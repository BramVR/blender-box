import base64
import copy
import errno
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import time
import unittest
from unittest import mock
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import onboarding_proof as proof
import proof_controller_dispatch as dispatch


SHA = "a" * 40
DRIVER = "b" * 40
EXECUTION = "gha_123_1"


def receipt(phase="settled", **changes):
    value = {"schema_version": 1, "execution_id": EXECUTION, "phase": phase,
             "closed": phase == "settled", "attempt": 1,
             "local_termination": "proven" if phase == "settled" else "unknown",
             "windows_cleanup": "proven" if phase == "settled" else "unknown",
             "proof_result": "fail" if phase == "settled" else "not-run"}
    value.update(changes)
    return value


def failed_report():
    outcomes = {name: {"status": "not-run", "code": "not-run"} for name in proof.REQUIRED}
    outcomes["preparation"] = {"status": "fail", "code": "proof-failed"}
    return {"schema_version": 1, "proof": "windows-onboarding-baseline", "candidate_sha": SHA,
            "driver_sha": DRIVER, "execution": "hosted", "status": "fail", "run": None,
            "cleanup": {name: True for name in proof.CLEANUP}, "outcomes": outcomes,
            "not_exercised": list(proof.WindowsProofHost.not_exercised), "artifacts": []}


def passing_report(image):
    outcomes = {name: {"status": "pass", "code": "proof-passed"} for name in proof.REQUIRED}
    return {"schema_version": 1, "proof": "windows-onboarding-baseline", "candidate_sha": SHA,
            "driver_sha": DRIVER, "execution": "hosted", "status": "pass",
            "run": {"run_id": "bbx_" + "1" * 32, "request_id": "req_" + "2" * 32,
                    "request_hash": "3" * 64, "session_id": "bss_" + "4" * 32},
            "cleanup": {name: True for name in proof.CLEANUP}, "outcomes": outcomes,
            "not_exercised": list(proof.WindowsProofHost.not_exercised),
            "artifacts": [
                {"path": "result/scenario-result.json", "type": "scenario-result", "size": 2,
                 "remote_sha256": "5" * 64, "local_sha256": "5" * 64,
                 "capture_method": None, "width": None, "height": None},
                {"path": "screenshots/viewport.png", "type": "viewport", "size": len(image),
                 "remote_sha256": dispatch.digest(image), "local_sha256": dispatch.digest(image),
                 "capture_method": "offscreen", "width": 2, "height": 2},
            ],
            "binaries": {"host_sha256": "6" * 64, "host_size": 1024,
                         "client_sha256": "7" * 64},
            "daemon_capabilities": list(proof.CAPABILITIES), "blender_version": "5.2.0"}


def png(width=2, height=2):
    def chunk(kind, content):
        return struct.pack(">I", len(content)) + kind + content + struct.pack(">I", zlib.crc32(kind + content))
    raw = (b"\x00" + b"\x00\x80\xff" * width) * height
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def collect_response(settled=None, request_sha=None, report=None, viewport=None):
    settled = settled or receipt()
    request_sha = request_sha or dispatch.run_identity(Args()).request_sha256
    outcome = {"schema_version": 2, "kind": "baseline-collect",
               "request": {"execution_id": EXECUTION, "request_sha256": request_sha,
                           "candidate_sha": SHA, "driver_sha": DRIVER, "variant": "baseline"},
               "baseline": {"record_sha256": "c" * 64, "report": report or failed_report()},
               "settlement": {"receipt": settled, "recovery": None}}
    raw = dispatch.canonical(outcome)
    files = [{"name": "outcome.json", "size": len(raw), "sha256": dispatch.digest(raw),
              "content_base64": base64.b64encode(raw).decode()}]
    if viewport is not None:
        files.append({"name": "viewport.png", "size": len(viewport), "sha256": dispatch.digest(viewport),
                      "content_base64": base64.b64encode(viewport).decode()})
    return {"schema_version": 1, "operation": "collect", "execution_id": EXECUTION, "files": files}


def wire(value, returncode=0):
    return dispatch.Exchange(returncode, dispatch.canonical(value), b"")


class Args:
    github_run_id = "123"
    github_run_attempt = "1"
    candidate_sha = SHA
    policy_driver_sha = DRIVER
    expires_at = "2099-01-01T00:00:00Z"


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def exchange(self, operation, request, timeout, cancel, record_process):
        self.calls.append((operation, request, timeout, cancel()))
        record_process({"schema_version": 1, "operation": operation, "pid": 100 + len(self.calls),
                        "parent_pid": 1, "argv_sha256": "d" * 64, "started_monotonic_ns": len(self.calls)})
        response = self.responses.pop(0)
        if callable(response):
            response = response()
        if isinstance(response, BaseException):
            raise response
        return response


class ManualClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class TrackingPipe:
    def __init__(self, source, *, read_error=False, read_prefix=b"", write_error=False):
        self.source = source
        self.read_error = read_error
        self.read_prefix = read_prefix
        self.write_error = write_error
        self.was_closed = False

    def read(self, size):
        if self.read_prefix:
            prefix, self.read_prefix = self.read_prefix[:size], self.read_prefix[size:]
            return prefix
        if self.read_error:
            raise OSError("injected-read-error")
        return self.source.read(size)

    def write(self, raw):
        if self.write_error:
            raise OSError("injected-write-error")
        return self.source.write(raw)

    def close(self):
        self.was_closed = True
        return self.source.close()


class DispatcherTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.identity = dispatch.run_identity(Args())

    def tearDown(self):
        self.temporary.cleanup()

    def runner(self, transport, name="first", publish=lambda _: None, budget=300, **kwargs):
        kwargs.setdefault("wait", lambda _: None)
        kwargs.setdefault("recovery_wait", kwargs["wait"])
        return dispatch.Dispatcher(transport, self.root / (name + "-state"), self.root / (name + "-public"),
                                   budget, publish_metadata=publish, **kwargs)

    def test_ambiguous_start_checks_status_then_retries_identical_canonical_bytes_once(self):
        responses = [dispatch.Exchange(None, b"", b"lost", "transport-timeout"),
                     wire({"schema_version": 1, "status": "error", "code": "execution-not-found"}, 1),
                     wire(receipt("running")), wire(receipt()), wire(collect_response())]
        transport = FakeTransport(responses)
        metadata = []

        def published(raw):
            metadata.append(json.loads(raw))
            self.assertTrue((self.root / "first-state/start.json").exists())
            self.assertEqual(transport.calls, [])

        result = self.runner(transport, publish=published).execute(self.identity, "run")
        starts = [raw for operation, raw, _, _ in transport.calls if operation == "start"]
        self.assertEqual(starts, [self.identity.start, self.identity.start])
        self.assertEqual([call[0] for call in transport.calls], ["start", "status", "start", "status", "collect"])
        self.assertEqual((result["status"], result["proof_result"], result["collection"]),
                         ("fail", "fail", "published"))
        self.assertEqual(metadata, [self.identity.metadata()])
        self.assertEqual((self.root / "first-state/start.json").read_bytes(), self.identity.start)
        self.assertEqual((self.root / "first-public/outcome.json").read_bytes(),
                         base64.b64decode(collect_response()["files"][0]["content_base64"]))

    def test_accepted_execution_publishes_observable_passing_outcome(self):
        image = png()
        settled = receipt(proof_result="pass")
        response = collect_response(settled=settled, report=passing_report(image), viewport=image)
        transport = FakeTransport([wire(receipt("accepted", attempt=0)), wire(settled), wire(response)])
        result = self.runner(transport, name="passing").execute(self.identity, "run")
        self.assertEqual([call[0] for call in transport.calls], ["start", "status", "collect"])
        self.assertEqual((result["status"], result["proof_result"], result["collection"]),
                         ("pass", "pass", "published"))
        outcome = json.loads((self.root / "passing-public/outcome.json").read_bytes())
        self.assertEqual(outcome["baseline"]["report"]["status"], "pass")

    def test_receipt_after_ambiguous_start_forbids_restart(self):
        transport = FakeTransport([dispatch.Exchange(None, b"", b"", "transport-timeout"),
                                   wire(receipt("running")),
                                   wire({"schema_version": 1, "status": "error",
                                         "code": "execution-not-found"}, 1),
                                   wire({"schema_version": 1, "status": "error",
                                         "code": "execution-not-found"}, 1),
                                   wire({"schema_version": 1, "status": "error",
                                         "code": "execution-not-found"}, 1)])
        with self.assertRaisesRegex(dispatch.DispatchError, "execution-not-found"):
            self.runner(transport).execute(self.identity, "run")
        self.assertEqual([call[0] for call in transport.calls],
                         ["start", "status", "status", "recover", "status"])

    def test_attempt_one_and_pre_transport_cancellation_are_mandatory(self):
        args = Args()
        args.github_run_attempt = "2"
        with self.assertRaisesRegex(dispatch.DispatchError, "hosted-authorization-invalid"):
            dispatch.run_identity(args)
        transport = FakeTransport([])
        metadata = []
        with self.assertRaisesRegex(dispatch.DispatchError, "dispatch-cancelled"):
            self.runner(transport, name="cancelled", publish=metadata.append,
                        cancel=lambda: True).execute(self.identity, "run")
        self.assertEqual(transport.calls, [])
        self.assertEqual(json.loads(metadata[0]), self.identity.metadata())

    def test_running_receipt_settles_on_cadenced_status_before_recovery(self):
        clock = ManualClock()
        waits = []

        def wait(seconds):
            waits.append(seconds)
            clock.advance(seconds)

        transport = FakeTransport([wire(receipt("running")), wire(receipt()), wire(collect_response())])
        result = self.runner(transport, name="natural", clock=clock, wait=wait).execute(self.identity, "run")
        self.assertEqual([call[0] for call in transport.calls], ["start", "status", "collect"])
        self.assertEqual(waits, [24])
        self.assertEqual(result["collection"], "published")

    def test_long_running_receipts_use_the_observation_budget_instead_of_burning_slots(self):
        clock = ManualClock()
        waits = []

        def wait(seconds):
            waits.append(seconds)
            clock.advance(seconds)

        responses = [wire(receipt("running")) for _ in range(6)]
        responses.extend((wire(receipt()), wire(collect_response())))
        transport = FakeTransport(responses)
        self.runner(transport, name="long", budget=900, clock=clock, wait=wait).execute(self.identity, "run")
        self.assertEqual([call[0] for call in transport.calls],
                         ["start", "status", "status", "status", "status", "status", "status", "collect"])
        self.assertNotIn("recover", [call[0] for call in transport.calls])
        self.assertGreater(sum(waits), 300)
        self.assertTrue(all(delay == 84 for delay in waits))

    def test_observation_budget_and_cancellation_reserve_recovery(self):
        for reason in ("budget", "cancel"):
            clock = ManualClock()
            cancelled = [False]

            def first():
                if reason == "budget":
                    clock.advance(80)
                else:
                    cancelled[0] = True
                return wire(receipt("running"))

            settled = receipt(attempt=2)
            response = collect_response(settled)
            outcome = json.loads(base64.b64decode(response["files"][0]["content_base64"]))
            outcome["settlement"]["recovery"] = {"attempt": 2, "record_sha256": "e" * 64,
                                                    "cleanup": {name: True for name in proof.CLEANUP}}
            raw = dispatch.canonical(outcome)
            response["files"][0].update(size=len(raw), sha256=dispatch.digest(raw),
                                        content_base64=base64.b64encode(raw).decode())
            transport = FakeTransport([first, wire(settled), wire(response)])
            result = dispatch.Dispatcher(transport, self.root / f"{reason}-state",
                                         self.root / f"{reason}-public", 100, clock=clock,
                                         wait=clock.advance, cancel=lambda: cancelled[0]).execute(self.identity, "run")
            self.assertEqual([call[0] for call in transport.calls], ["start", "recover", "collect"])
            self.assertEqual(result["cleanup"], "proven")

    def test_cancelled_start_reconciles_then_recovers_with_reserved_allowance(self):
        clock = ManualClock()
        settled = receipt(attempt=2)
        response = collect_response(settled)
        outcome = json.loads(base64.b64decode(response["files"][0]["content_base64"]))
        outcome["settlement"]["recovery"] = {"attempt": 2, "record_sha256": "e" * 64,
                                                "cleanup": {name: True for name in proof.CLEANUP}}
        raw = dispatch.canonical(outcome)
        response["files"][0].update(size=len(raw), sha256=dispatch.digest(raw),
                                    content_base64=base64.b64encode(raw).decode())
        transport = None

        def consume_cancelled_start():
            clock.advance(transport.calls[-1][2])
            return dispatch.Exchange(None, b"", b"cancelled", "transport-cancelled")

        def consume_reconciliation():
            clock.advance(transport.calls[-1][2])
            return wire(receipt("running"))

        transport = FakeTransport([
            consume_cancelled_start, consume_reconciliation, wire(settled), wire(response),
        ])
        result = self.runner(transport, name="cancelled-start", budget=100, clock=clock,
                             cancel=lambda: False).execute(self.identity, "run")
        self.assertEqual([call[0] for call in transport.calls], ["start", "status", "recover", "collect"])
        self.assertGreater(transport.calls[2][2], 0)
        self.assertEqual(result["cleanup"], "proven")

    def test_start_dispatch_error_reconciles_only_with_proven_local_cleanup(self):
        settled = receipt(attempt=2)
        response = collect_response(settled)
        outcome = json.loads(base64.b64decode(response["files"][0]["content_base64"]))
        outcome["settlement"]["recovery"] = {"attempt": 2, "record_sha256": "e" * 64,
                                                "cleanup": {name: True for name in proof.CLEANUP}}
        raw = dispatch.canonical(outcome)
        response["files"][0].update(size=len(raw), sha256=dispatch.digest(raw),
                                    content_base64=base64.b64encode(raw).decode())
        proven = FakeTransport([dispatch.DispatchError("injected", cleanup_proven=True),
                                wire(receipt("running")), wire(settled), wire(response)])
        self.runner(proven, name="proven-start-error").execute(self.identity, "run")
        self.assertEqual([call[0] for call in proven.calls], ["start", "status", "recover", "collect"])

        unproven = FakeTransport([dispatch.DispatchError("transport-cleanup-unproven")])
        with self.assertRaisesRegex(dispatch.DispatchError, "transport-cleanup-unproven"):
            self.runner(unproven, name="unproven-start-error").execute(self.identity, "run")
        self.assertEqual([call[0] for call in unproven.calls], ["start"])

    def test_malformed_mandatory_status_releases_recovery_reserve(self):
        clock = ManualClock()
        transport = None

        def consume_start():
            clock.advance(transport.calls[-1][2])
            return dispatch.Exchange(None, b"", b"timeout", "transport-timeout")

        def consume_reconciliation():
            clock.advance(transport.calls[-1][2])
            return dispatch.Exchange(0, b"{}", b"")

        settled = receipt(attempt=2)
        response = collect_response(settled)
        outcome = json.loads(base64.b64decode(response["files"][0]["content_base64"]))
        outcome["settlement"]["recovery"] = {"attempt": 2, "record_sha256": "e" * 64,
                                                "cleanup": {name: True for name in proof.CLEANUP}}
        raw = dispatch.canonical(outcome)
        response["files"][0].update(size=len(raw), sha256=dispatch.digest(raw),
                                    content_base64=base64.b64encode(raw).decode())
        transport = FakeTransport([consume_start, consume_reconciliation,
                                   wire(receipt("recovering", attempt=2)), wire(settled), wire(response)])
        result = self.runner(transport, name="malformed-reconciliation", budget=100,
                             clock=clock).execute(self.identity, "run")
        self.assertEqual([call[0] for call in transport.calls],
                         ["start", "status", "recover", "status", "collect"])
        self.assertGreater(transport.calls[3][2], 0)
        self.assertGreater(transport.calls[4][2], 0)
        self.assertEqual(result["collection"], "published")

    def test_cadence_wait_wakes_for_cancellation_and_recovers_original_execution(self):
        cancelled = [False]
        waits = []

        def wake(delay):
            waits.append(delay)
            cancelled[0] = True
            return True

        settled = receipt(attempt=2)
        response = collect_response(settled)
        outcome = json.loads(base64.b64decode(response["files"][0]["content_base64"]))
        outcome["settlement"]["recovery"] = {"attempt": 2, "record_sha256": "e" * 64,
                                                "cleanup": {name: True for name in proof.CLEANUP}}
        raw = dispatch.canonical(outcome)
        response["files"][0].update(size=len(raw), sha256=dispatch.digest(raw),
                                    content_base64=base64.b64encode(raw).decode())
        transport = FakeTransport([wire(receipt("running")), wire(settled), wire(response)])
        self.runner(transport, name="wake", wait=wake,
                    cancel=lambda: cancelled[0]).execute(self.identity, "run")
        self.assertEqual(len(waits), 1)
        self.assertEqual([call[0] for call in transport.calls], ["start", "recover", "collect"])
        for _, request, _, _ in transport.calls:
            self.assertEqual(dispatch.Dispatcher._identity_execution(request), EXECUTION)

    def test_malformed_observation_after_possible_acceptance_recovers_original_id(self):
        malformed = dispatch.Exchange(0, dispatch.canonical(receipt("running") | {"phase": []}), b"")
        settled = receipt(attempt=2)
        response = collect_response(settled)
        outcome = json.loads(base64.b64decode(response["files"][0]["content_base64"]))
        outcome["settlement"]["recovery"] = {"attempt": 2, "record_sha256": "e" * 64,
                                                "cleanup": {name: True for name in proof.CLEANUP}}
        raw = dispatch.canonical(outcome)
        response["files"][0].update(size=len(raw), sha256=dispatch.digest(raw),
                                    content_base64=base64.b64encode(raw).decode())
        transport = FakeTransport([dispatch.Exchange(None, b"", b"", "transport-timeout"),
                                   malformed, wire(settled), wire(response)])
        self.runner(transport, name="malformed").execute(self.identity, "run")
        self.assertEqual([call[0] for call in transport.calls], ["start", "status", "recover", "collect"])
        for _, request, _, _ in transport.calls:
            self.assertEqual(dispatch.Dispatcher._identity_execution(request), EXECUTION)

    def test_published_recovery_pins_support_fresh_recovery_without_start(self):
        metadata = []

        class Interrupted(Exception):
            pass

        def interrupt(raw):
            metadata.append(json.loads(raw))
            raise Interrupted()

        first = FakeTransport([])
        with self.assertRaises(Interrupted):
            self.runner(first, publish=interrupt).execute(self.identity, "run")
        self.assertEqual(first.calls, [])
        pins = metadata[0]
        recovered_identity = dispatch.Identity(pins["execution_id"], pins["candidate_sha"],
                                               pins["policy_driver_sha"], pins["request_sha256"], None)
        settled = receipt(attempt=2)
        recovery = {"attempt": 2, "record_sha256": "e" * 64,
                    "cleanup": {name: True for name in proof.CLEANUP}}
        response = collect_response(settled, pins["request_sha256"])
        outcome = json.loads(base64.b64decode(response["files"][0]["content_base64"]))
        outcome["settlement"]["recovery"] = recovery
        outcome_raw = dispatch.canonical(outcome)
        response["files"][0].update(size=len(outcome_raw), sha256=dispatch.digest(outcome_raw),
                                    content_base64=base64.b64encode(outcome_raw).decode())
        fresh = FakeTransport([wire(receipt("running")), wire(settled), wire(response)])
        result = self.runner(fresh, name="recover").execute(recovered_identity, "recover")
        self.assertEqual([call[0] for call in fresh.calls], ["status", "recover", "collect"])
        self.assertNotIn("start", [call[0] for call in fresh.calls])
        self.assertEqual(result["collection"], "published")
        self.assertEqual((result["status"], result["proof_result"]), ("fail", "fail"))

    def test_valid_unresolved_recovery_receipt_is_not_reissued(self):
        identity = dispatch.Identity(EXECUTION, SHA, DRIVER, self.identity.request_sha256, None)
        settled = receipt(attempt=2)
        response = collect_response(settled)
        outcome = json.loads(base64.b64decode(response["files"][0]["content_base64"]))
        outcome["settlement"]["recovery"] = {"attempt": 2, "record_sha256": "e" * 64,
                                                "cleanup": {name: True for name in proof.CLEANUP}}
        raw = dispatch.canonical(outcome)
        response["files"][0].update(size=len(raw), sha256=dispatch.digest(raw),
                                    content_base64=base64.b64encode(raw).decode())
        transport = FakeTransport([wire(receipt("running")), wire(receipt("unresolved", attempt=2)),
                                   wire(settled), wire(response)])
        self.runner(transport, name="one-recovery").execute(identity, "recover")
        self.assertEqual([call[0] for call in transport.calls], ["status", "recover", "status", "collect"])

    def test_recover_error_is_reobserved_once_without_reissuing_recovery(self):
        settled = receipt(attempt=2)
        response = collect_response(settled)
        outcome = json.loads(base64.b64decode(response["files"][0]["content_base64"]))
        outcome["settlement"]["recovery"] = {"attempt": 2, "record_sha256": "e" * 64,
                                                "cleanup": {name: True for name in proof.CLEANUP}}
        raw = dispatch.canonical(outcome)
        response["files"][0].update(size=len(raw), sha256=dispatch.digest(raw),
                                    content_base64=base64.b64encode(raw).decode())
        recover_error = wire({"schema_version": 1, "status": "error", "code": "native-unavailable"}, 1)
        transport = FakeTransport([wire(receipt("unresolved")), recover_error,
                                   wire(settled), wire(response)])
        self.runner(transport, name="recover-error").execute(self.identity, "run")
        self.assertEqual([call[0] for call in transport.calls], ["start", "recover", "status", "collect"])
        for _, request, _, _ in transport.calls:
            self.assertEqual(dispatch.Dispatcher._identity_execution(request), EXECUTION)
        exchanges = self.root / "recover-error-state/exchanges"
        self.assertEqual(json.loads((exchanges / "stdout-02.bin").read_bytes())["code"],
                         "native-unavailable")
        self.assertEqual(json.loads((exchanges / "stdout-03.bin").read_bytes())["phase"], "settled")

    def test_async_recovery_receipts_are_paced_and_leave_collection_capacity(self):
        clock = ManualClock()
        waits = []

        def exhaust_observation():
            clock.advance(840)
            return wire(receipt("running"))

        def recovery_wait(seconds):
            waits.append(seconds)
            clock.advance(seconds)

        settled = receipt(attempt=2)
        response = collect_response(settled)
        outcome = json.loads(base64.b64decode(response["files"][0]["content_base64"]))
        outcome["settlement"]["recovery"] = {"attempt": 2, "record_sha256": "e" * 64,
                                                "cleanup": {name: True for name in proof.CLEANUP}}
        raw = dispatch.canonical(outcome)
        response["files"][0].update(size=len(raw), sha256=dispatch.digest(raw),
                                    content_base64=base64.b64encode(raw).decode())
        responses = [wire(receipt("running")) for _ in range(10)] + [exhaust_observation]
        responses.extend([wire(receipt("recovering", attempt=2)) for _ in range(3)])
        responses.extend((wire(settled), wire(response)))
        transport = FakeTransport(responses)
        result = self.runner(transport, name="async-recovery", budget=900, clock=clock,
                             recovery_wait=recovery_wait).execute(self.identity, "run")
        self.assertEqual([call[0] for call in transport.calls],
                         ["start", *("status" for _ in range(10)), "recover",
                          "status", "status", "status", "collect"])
        self.assertEqual(waits, [15, 15, 15])
        self.assertEqual(clock.now, 885)
        self.assertEqual(transport.calls[-1][2], 15)
        self.assertEqual(result["collection"], "published")

    def test_cancelled_recovery_consumes_one_wake_then_spreads_remaining_budget(self):
        clock = ManualClock()
        cancelled = [False]
        wake_pending = [False]
        waits = []

        def cancel_after_acceptance():
            cancelled[0] = True
            wake_pending[0] = True
            return wire(receipt("running"))

        def recovery_wait(seconds):
            waits.append(seconds)
            if wake_pending[0]:
                wake_pending[0] = False
                return True
            clock.advance(seconds)
            return False

        settled = receipt(attempt=2)
        response = collect_response(settled)
        outcome = json.loads(base64.b64decode(response["files"][0]["content_base64"]))
        outcome["settlement"]["recovery"] = {"attempt": 2, "record_sha256": "e" * 64,
                                                "cleanup": {name: True for name in proof.CLEANUP}}
        raw = dispatch.canonical(outcome)
        response["files"][0].update(size=len(raw), sha256=dispatch.digest(raw),
                                    content_base64=base64.b64encode(raw).decode())
        transport = FakeTransport([cancel_after_acceptance]
                                  + [wire(receipt("recovering", attempt=2)) for _ in range(13)]
                                  + [wire(settled), wire(response)])
        result = self.runner(transport, name="cancelled-recovering", budget=100, clock=clock,
                             cancel=lambda: cancelled[0], recovery_wait=recovery_wait).execute(
                                 self.identity, "run")
        self.assertEqual([call[0] for call in transport.calls],
                         ["start", "recover", *("status" for _ in range(13)), "collect"])
        self.assertEqual(len(waits), 13)
        self.assertAlmostEqual(waits[0], 100 / 14)
        for delay in waits[1:]:
            self.assertAlmostEqual(delay, 100 / 13)
        self.assertAlmostEqual(clock.now, 12 * 100 / 13)
        self.assertAlmostEqual(transport.calls[-1][2], 100 / 13)
        self.assertEqual(result["collection"], "published")

    def test_cli_uses_signal_event_for_cadence_wait(self):
        args = ["run", "--github-run-id", "123", "--github-run-attempt", "1",
                "--candidate-sha", SHA, "--policy-driver-sha", DRIVER,
                "--expires-at", "2099-01-01T00:00:00Z", "--ssh-config", str(self.root / "config"),
                "--controller", "controller", "--state", str(self.root / "cli-state"),
                "--output", str(self.root / "cli-output"), "--budget-seconds", "300"]
        registered = {}
        original_signal = dispatch.signal.signal

        def register(chosen_signal, handler):
            if chosen_signal not in registered and callable(handler):
                registered[chosen_signal] = handler
            return original_signal(chosen_signal, handler)

        with mock.patch.object(dispatch, "SSHTransport"), mock.patch.object(dispatch, "Dispatcher") as runner, \
                mock.patch.object(dispatch, "emit"), mock.patch.object(dispatch.signal, "signal", side_effect=register):
            runner.return_value.execute.return_value = {"status": "fail"}
            self.assertEqual(dispatch.main(args), 1)
        wait = runner.call_args.kwargs["wait"]
        recovery_wait = runner.call_args.kwargs["recovery_wait"]
        cancel = runner.call_args.kwargs["cancel"]
        self.assertIs(wait.__self__, cancel.__self__)
        self.assertFalse(recovery_wait(0))
        registered[dispatch.signal.SIGTERM]()
        self.assertTrue(cancel())
        self.assertTrue(wait(0))
        self.assertTrue(recovery_wait(0))
        self.assertFalse(recovery_wait(0))

    def test_cleanup_unproven_exchange_is_persisted_before_fail_closed(self):
        transport = FakeTransport([
            dispatch.Exchange(None, b"partial-stdout", b"partial-stderr", "transport-cleanup-unproven")
        ])
        with self.assertRaisesRegex(dispatch.DispatchError, "transport-cleanup-unproven") as raised:
            self.runner(transport, name="cleanup-evidence").execute(self.identity, "run")
        self.assertFalse(raised.exception.cleanup_proven)
        self.assertEqual([call[0] for call in transport.calls], ["start"])
        exchanges = self.root / "cleanup-evidence-state/exchanges"
        self.assertEqual((exchanges / "stdout-01.bin").read_bytes(), b"partial-stdout")
        self.assertEqual((exchanges / "stderr-01.bin").read_bytes(), b"partial-stderr")
        record = json.loads((exchanges / "exchange-01.json").read_bytes())
        self.assertEqual(record["failure"], "transport-cleanup-unproven")

    def test_recovery_rejects_replacement_identity_and_mismatched_pins(self):
        identity = dispatch.Identity(EXECUTION, SHA, DRIVER, self.identity.request_sha256, None)
        replacement = receipt("running", execution_id="gha_999_1")
        with self.assertRaisesRegex(dispatch.DispatchError, "receipt-identity-changed"):
            self.runner(FakeTransport([wire(replacement)]), name="replacement").execute(identity, "recover")
        settled = receipt()
        wrong = collect_response(settled, "f" * 64)
        transport = FakeTransport([wire(settled), wire(wrong)])
        with self.assertRaisesRegex(dispatch.DispatchError, "outcome-identity-changed"):
            self.runner(transport, name="wrong-pin").execute(identity, "recover")
        self.assertEqual([call[0] for call in transport.calls], ["status", "collect"])

    def test_settled_failure_collect_record_missing_keeps_private_receipts(self):
        missing = wire({"schema_version": 1, "status": "error", "code": "collect-record-missing"}, 1)
        transport = FakeTransport([wire(receipt()), missing])
        result = self.runner(transport, name="missing").execute(
            dispatch.Identity(EXECUTION, SHA, DRIVER, self.identity.request_sha256, None), "recover")
        self.assertEqual((result["status"], result["collection"]), ("fail", "missing"))
        self.assertFalse((self.root / "missing-public").exists())
        records = self.root / "missing-state/exchanges"
        self.assertEqual(json.loads((records / "stdout-01.bin").read_bytes()), receipt())
        self.assertEqual(json.loads((records / "stdout-02.bin").read_bytes())["code"], "collect-record-missing")

    def test_strict_json_receipt_error_and_collect_schemas(self):
        bad_status = [b'{"schema_version":1,"schema_version":1}',
                      dispatch.canonical(receipt()) + b"{}",
                      dispatch.canonical(receipt() | {"phase": []}),
                      dispatch.canonical(receipt() | {"private": True})]
        for raw in bad_status:
            with self.subTest(raw=raw[:50]), self.assertRaises(dispatch.DispatchError):
                dispatch.parse_exchange(dispatch.Exchange(0, raw, b""), "status", EXECUTION)
        bad_errors = [{"schema_version": 1, "status": "error", "code": []},
                      {"schema_version": 1, "status": "error", "code": "bad", "private": True}]
        for value in bad_errors:
            with self.subTest(value=value), self.assertRaises(dispatch.DispatchError):
                dispatch.parse_exchange(wire(value, 1), "status", EXECUTION)
        invalid = collect_response()
        invalid["private"] = True
        transport = FakeTransport([wire(receipt()), wire(invalid)])
        with self.assertRaisesRegex(dispatch.DispatchError, "invalid-collect"):
            self.runner(transport, name="strict").execute(self.identity, "run")
        self.assertFalse((self.root / "strict-public").exists())

    def test_viewport_and_complete_envelope_validate_before_ordered_publication(self):
        image = png()
        report = failed_report()
        report["artifacts"] = [
            {"path": "result/scenario-result.json", "type": "scenario-result", "size": 2,
             "remote_sha256": "1" * 64, "local_sha256": "1" * 64,
             "capture_method": None, "width": None, "height": None},
            {"path": "screenshots/viewport.png", "type": "viewport", "size": len(image),
             "remote_sha256": dispatch.digest(image), "local_sha256": dispatch.digest(image),
             "capture_method": "offscreen", "width": 2, "height": 2},
        ]
        response = collect_response(report=report, viewport=image)
        transport = FakeTransport([wire(receipt()), wire(response)])
        order = []
        original = dispatch.write_file

        def observed(path, raw, **kwargs):
            if path.parent.name == "viewport-public":
                order.append(path.name)
            return original(path, raw, **kwargs)

        with mock.patch.object(dispatch, "write_file", side_effect=observed):
            self.runner(transport, name="viewport").execute(self.identity, "run")
        self.assertEqual(order, ["viewport.png", "outcome.json"])
        self.assertEqual((self.root / "viewport-public/viewport.png").read_bytes(), image)

        invalid = collect_response(report=report, viewport=image)
        invalid["files"][1]["sha256"] = "f" * 64
        with self.assertRaisesRegex(dispatch.DispatchError, "invalid-collect"):
            self.runner(FakeTransport([wire(receipt()), wire(invalid)]),
                        name="bad-viewport").execute(self.identity, "run")
        self.assertFalse((self.root / "bad-viewport-public").exists())

        private_report = failed_report()
        private_report["private"] = "secret"
        invalid = collect_response(report=private_report)
        with self.assertRaisesRegex(dispatch.DispatchError, "invalid-outcome"):
            self.runner(FakeTransport([wire(receipt()), wire(invalid)]),
                        name="bad-outcome").execute(self.identity, "run")
        self.assertFalse((self.root / "bad-outcome-public").exists())

    def test_declared_limits_fail_before_base64_decode(self):
        response = collect_response()
        response["files"][0]["size"] = dispatch.MAX_OUTCOME + 1
        with mock.patch.object(base64, "b64decode") as decode:
            with self.assertRaisesRegex(dispatch.DispatchError, "invalid-collect"):
                dispatch.validate_collect(response, self.identity, dispatch.Receipt.parse(receipt(), EXECUTION))
            decode.assert_not_called()
        with mock.patch.object(dispatch, "MAX_RESPONSE", 20):
            with self.assertRaises(dispatch.DispatchError):
                dispatch.parse_exchange(dispatch.Exchange(0, b"x" * 21, b""), "collect", EXECUTION)

    def test_collect_file_acceptance_matrix_never_publishes_invalid_responses(self):
        cases = {}
        duplicate = collect_response()
        duplicate["files"].append(copy.deepcopy(duplicate["files"][0]))
        cases["duplicate"] = duplicate
        unknown = collect_response()
        unknown["files"][0]["name"] = "private.json"
        cases["unknown"] = unknown
        bad_base64 = collect_response()
        bad_base64["files"][0]["content_base64"] = "!" * len(bad_base64["files"][0]["content_base64"])
        cases["bad-base64"] = bad_base64
        bad_hash = collect_response()
        bad_hash["files"][0]["sha256"] = "f" * 64
        cases["bad-hash"] = bad_hash
        oversized = collect_response()
        oversized["files"].append({"name": "viewport.png", "size": dispatch.MAX_VIEWPORT + 1,
                                    "sha256": "f" * 64, "content_base64": ""})
        cases["oversized-viewport"] = oversized
        for name, response in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(dispatch.DispatchError, "invalid-collect"):
                self.runner(FakeTransport([wire(receipt()), wire(response)]),
                            name="matrix-" + name).execute(self.identity, "run")
            self.assertFalse((self.root / ("matrix-" + name + "-public")).exists())

    def test_unconfirmed_recovery_retains_private_evidence_without_public_output(self):
        cancelled = [False]

        def accepted_then_cancelled():
            cancelled[0] = True
            return wire(receipt("running"))

        transport = FakeTransport([accepted_then_cancelled,
                                   dispatch.Exchange(None, b"", b"timeout", "transport-timeout"),
                                   wire({"schema_version": 1, "status": "error", "code": "native-unavailable"}, 1)])
        with self.assertRaisesRegex(dispatch.DispatchError, "native-unavailable"):
            self.runner(transport, name="unconfirmed", cancel=lambda: cancelled[0]).execute(self.identity, "run")
        self.assertEqual([call[0] for call in transport.calls], ["start", "recover", "status"])
        self.assertFalse((self.root / "unconfirmed-public").exists())
        private = self.root / "unconfirmed-state/exchanges"
        for number in range(1, 4):
            self.assertTrue((private / f"request-{number:02d}.json").is_file())
            self.assertTrue((private / f"process-{number:02d}.json").is_file())
            self.assertTrue((private / f"exchange-{number:02d}.json").is_file())

    def test_unsafe_output_destinations_fail_before_transport(self):
        existing = self.root / "existing"
        existing.mkdir()
        target = self.root / "target"
        target.mkdir()
        link = self.root / "link"
        link.symlink_to(target, target_is_directory=True)
        for output in (Path("relative"), existing, link / "public", self.root / "overlap-state/public"):
            transport = FakeTransport([])
            state = self.root / "overlap-state" if "overlap" in str(output) else self.root / (output.name + "-state")
            with self.subTest(output=output), self.assertRaises(dispatch.DispatchError):
                dispatch.Dispatcher(transport, state, output, 300).execute(self.identity, "run")
            self.assertEqual(transport.calls, [])

    def test_symlink_above_private_ancestor_rejects_state_and_output_before_transport(self):
        actual = self.root / "actual"
        actual.mkdir(mode=0o700)
        private = actual / "private"
        private.mkdir(mode=0o700)
        link = self.root / "ancestor-link"
        link.symlink_to(actual, target_is_directory=True)
        cases = [
            (link / "private/state", self.root / "safe-public"),
            (self.root / "safe-state", link / "private/public"),
        ]
        for index, (state, output) in enumerate(cases):
            transport = FakeTransport([])
            with self.subTest(index=index), self.assertRaises(dispatch.DispatchError):
                dispatch.Dispatcher(transport, state, output, 300).execute(self.identity, "run")
            self.assertEqual(transport.calls, [])


class SSHTransportTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.config = self.root / "ssh-config"
        self.config.write_text("Host controller\n")
        self.config.chmod(0o600)

    def tearDown(self):
        self.temporary.cleanup()

    def transport(self, source):
        processes = []

        def factory(_argv, **kwargs):
            process = subprocess.Popen([sys.executable, "-c", source], **kwargs)
            processes.append(process)
            return process

        return dispatch.SSHTransport(self.config, "controller", process_factory=factory), processes

    def test_fixed_argv_and_concurrent_output_overflow_stop_owned_process(self):
        source = "import os,time; os.write(1,b'x'*(2<<20)); os.write(2,b'y'*(128<<10)); time.sleep(10)"
        transport, processes = self.transport(source)
        records = []
        result = transport.exchange("status", b"{}", 5, lambda: False, records.append)
        self.assertEqual(result.failure, "transport-output-overflow")
        self.assertLessEqual(len(result.stdout), dispatch.MAX_OUTCOME + 1)
        self.assertLessEqual(len(result.stderr), dispatch.MAX_STDERR + 1)
        self.assertIsNotNone(processes[0].poll())
        self.assertEqual(records[0]["argv"], transport.argv)
        self.assertEqual((transport.argv[0], transport.argv[-1]), (dispatch.SSH, "controller"))
        self.assertNotIn("dispatch", transport.argv)
        for option in ("RemoteCommand=none", "PreferredAuthentications=publickey",
                       "PubkeyAuthentication=yes", "GSSAPIAuthentication=no",
                       "ConnectionAttempts=1", "UpdateHostKeys=no"):
            self.assertIn(option, transport.argv)

    def test_group_cleanup_polls_present_live_leader_until_zombie_before_reap(self):
        clock = ManualClock()
        transport = dispatch.SSHTransport(self.config, "controller", clock=clock)
        process = mock.Mock(pid=4242, returncode=None)
        observations = [
            subprocess.CompletedProcess([], 0, b"4242 4242 R\n4243 4242 Z\n", b""),
            subprocess.CompletedProcess([], 0, b"4242 4242 Z\n4243 4242 Z\n", b""),
        ]
        with mock.patch.object(dispatch.os, "killpg") as killpg, \
                mock.patch.object(dispatch.subprocess, "run", side_effect=observations) as observe, \
                mock.patch.object(dispatch.time, "sleep", side_effect=clock.advance) as sleep:
            transport._terminate_exact(process, 4242, 1)
        killpg.assert_called_once_with(4242, dispatch.signal.SIGKILL)
        self.assertEqual(observe.call_count, 2)
        sleep.assert_called_once_with(0.01)
        process.wait.assert_called_once()

    def test_timeout_stops_and_reaps_only_spawned_process_group(self):
        transport, processes = self.transport("import time; time.sleep(10)")
        records = []
        started = time.monotonic()
        result = transport.exchange("status", b"{}", 0.5, lambda: False, records.append)
        self.assertEqual(result.failure, "transport-timeout")
        self.assertLess(time.monotonic() - started, 3)
        self.assertIsNotNone(processes[0].poll())
        self.assertEqual(records[0]["pid"], processes[0].pid)
        self.assertEqual(records[0]["parent_pid"], os.getpid())

    def test_timeout_kills_owned_group_before_reap_and_does_not_touch_unrelated_group(self):
        ready = self.root / "child-ready"
        grandchild = ("import pathlib,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                      f"pathlib.Path({str(ready)!r}).write_text('ready'); time.sleep(10)")
        source = ("import pathlib,subprocess,sys,time; "
                  f"subprocess.Popen([sys.executable,'-c',{grandchild!r}],"
                  "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
                  f"marker=pathlib.Path({str(ready)!r}); "
                  "exec(\"while not marker.exists():\\n time.sleep(.001)\"); time.sleep(10)")
        transport, processes = self.transport(source)
        unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"],
                                     start_new_session=True)
        original_killpg = os.killpg
        kill_states = []

        def observed_killpg(process_group, chosen_signal):
            kill_states.append((process_group, chosen_signal, processes[0].returncode))
            return original_killpg(process_group, chosen_signal)

        try:
            with mock.patch.object(dispatch.os, "killpg", side_effect=observed_killpg):
                result = transport.exchange("status", b"{}", 2, ready.exists, lambda _: None)
            self.assertEqual(result.failure, "transport-cancelled")
            self.assertTrue(ready.exists())
            self.assertTrue(kill_states)
            self.assertTrue(all(process_group == processes[0].pid and returncode is None
                                for process_group, _, returncode in kill_states))
            self.assertIsNotNone(processes[0].poll())
            self.assertIsNone(unrelated.poll())
        finally:
            unrelated.terminate()
            unrelated.wait(timeout=2)

    def test_exited_leader_with_child_retaining_pipes_is_reaped_without_timeout(self):
        ready = self.root / "retained-pipe-child-ready"
        child = ("import pathlib,time; "
                 f"pathlib.Path({str(ready)!r}).write_text('ready'); time.sleep(10)")
        source = ("import pathlib,subprocess,sys,time; "
                  f"subprocess.Popen([sys.executable,'-c',{child!r}]); "
                  f"marker=pathlib.Path({str(ready)!r}); "
                  "exec(\"while not marker.exists():\\n time.sleep(.001)\")")
        transport, processes = self.transport(source)
        started = time.monotonic()
        result = transport.exchange("status", b"{}", 0.3, lambda: False, lambda _: None)
        self.assertIsNone(result.failure)
        self.assertTrue(ready.exists())
        self.assertLess(time.monotonic() - started, 3)
        self.assertIsNotNone(processes[0].poll())

    def test_exited_leader_terminates_ready_child_that_closed_output_pipes(self):
        ready = self.root / "closed-pipe-child-ready"
        gate = self.root / "closed-pipe-child-gate"
        os.mkfifo(gate, 0o600)
        child = ("import os,pathlib,time; "
                 f"fd=os.open({str(gate)!r},os.O_RDONLY|os.O_NONBLOCK); "
                 f"pathlib.Path({str(ready)!r}).write_text('ready'); time.sleep(10)")
        source = ("import pathlib,subprocess,sys,time; "
                  f"subprocess.Popen([sys.executable,'-c',{child!r}],"
                  "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
                  f"marker=pathlib.Path({str(ready)!r}); "
                  "exec(\"while not marker.exists():\\n time.sleep(.001)\"); print('{}')")
        transport, processes = self.transport(source)
        result = transport.exchange("status", b"{}", 2, lambda: False, lambda _: None)
        self.assertIsNone(result.failure)
        self.assertEqual(result.stdout.strip(), b"{}")
        self.assertIsNotNone(processes[0].poll())
        with self.assertRaises(OSError) as caught:
            os.open(gate, os.O_WRONLY | os.O_NONBLOCK)
        self.assertEqual(caught.exception.errno, errno.ENXIO)

    def test_injected_pipe_failures_close_every_pipe_and_reap_the_process(self):
        processes = []
        pipes = []

        def factory(_argv, **kwargs):
            process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"], **kwargs)
            process.stdin = TrackingPipe(process.stdin, write_error=True)
            process.stdout = TrackingPipe(process.stdout, read_error=True, read_prefix=b"captured-before-error")
            process.stderr = TrackingPipe(process.stderr)
            processes.append(process)
            pipes.extend((process.stdin, process.stdout, process.stderr))
            return process

        transport = dispatch.SSHTransport(self.config, "controller", process_factory=factory)
        result = transport.exchange("status", b"{}", 0.2, lambda: False, lambda _: None)
        self.assertEqual(result.failure, "transport-cleanup-unproven")
        self.assertEqual(result.stdout, b"captured-before-error")
        self.assertTrue(all(stream.was_closed for stream in pipes))
        self.assertIsNotNone(processes[0].poll())


if __name__ == "__main__":
    unittest.main()
