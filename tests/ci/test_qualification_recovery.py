from contextlib import contextmanager
from dataclasses import asdict, replace
from datetime import datetime, timezone
from pathlib import Path
import copy
import os
import time
import unittest
from unittest import mock

import test_proof_controller_native as fixtures
import test_qualification_contract as contract

native, model = fixtures.native, fixtures.model


@unittest.skipUnless(model.fcntl is not None, "POSIX native controller fixtures")
class QualificationRenewalTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.NativeLifecycleTests("run")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.base, self.files, self.ops = self.fixture.fixture, self.fixture.files, self.fixture.ops
        patch = mock.patch.object(native, "CONFIG", self.base.root)
        patch.start()
        self.addCleanup(patch.stop)
        value = fixtures.policy().value | {"expected_client_sha256": self.base.policy.expected_client_sha256}
        self.policy = native.NativePolicy.parse(model.proof.canonical(value))
        auth = contract.authorization() | {"policy_sha256": self.policy.digest,
            "installation_sha256": native.installation_digest(self.policy),
            "expected_client_sha256": self.policy.value["expected_client_sha256"],
            "cases": ["windows-baseline"], "launch_deadline_unix": 2000, "recovery_deadline_unix": 3000,
            "fixture_sha256": native.identity_digest("WindowsFixture", {name: self.policy.value["artifacts"][
                str(native.BASE / "tests/fixtures/onboarding-baseline" / name)] for name in ("payload.json", "scenario.py")})}
        first = native.QualificationAuthorization.parse(model.proof.canonical(auth))
        self.execution_id = first.execution_id("windows-baseline")
        self.request = fixtures.baseline.request(self.execution_id)
        self.root = self.base.control / self.execution_id
        self.job = model.Job(self.request, self.base.jobs / self.execution_id, self.base.checkout,
                             self.base.policy.expected_client_sha256, 1)
        original = self.files.read(self.base.operator)
        operator = model.document(original)
        ssh_raw = self.files.read(Path(operator["ssh_config"]))
        connection = model.ssh_connection(ssh_raw, operator["target"]["ssh_alias"])
        contents = {"original-operator.json": original, "original-ssh-config": ssh_raw,
                    "operator.json": model.proof.canonical(operator | {"ssh_config": str(self.job.root / "inputs/ssh-config")}),
                    "target.json": model.proof.canonical(operator["target"]),
                    "ssh-config": model.normalized_ssh(connection, self.job.root / "inputs"),
                    "key": self.files.read(Path(connection["identityfile"])),
                    "known_hosts": self.files.read(Path(connection["userknownhostsfile"]))}
        manifest = {"schema_version": 1, "files": {name: model.proof.digest(raw) for name, raw in contents.items()},
                    "candidate_checkout": str(self.base.checkout), "config": str(self.job.config),
                    "expected_client_sha256": self.job.expected_client_sha256}
        auth.update(operator_manifest_sha256=model.proof.digest(model.proof.canonical(manifest)),
                    target_sha256=model.proof.digest(contents["target.json"]))
        self.authority = native.QualificationAuthorization.parse(model.proof.canonical(auth))
        self.assertEqual(self.authority.execution_id("windows-baseline"), self.execution_id)
        self.context = native.WindowsQualification(self.authority, "windows-baseline")
        self.service = native.NativeService(self.policy, self.files, self.ops, self.context)
        self.controller = model.Controller(self.base.control, self.base.jobs, self.base.policy, self.service,
            clock=lambda: fixtures.baseline.NOW, files=self.files, admission=self.policy.admit, qualification=self.context)
        self.starts, self.releases = [], []
        self.ops.systemctl.side_effect = self.start
        self.ops.exchange.side_effect = self.release
        self.ops.stop.side_effect = self.stop
        self.ops.unit.side_effect = lambda: native.UnitState("inactive" if self.fixture.empty else "active",
            0 if self.fixture.empty else 300, self.receipt.invocation.invocation_id if hasattr(self, "receipt") else "", native.UNIT_CGROUP)
        self.ops.process.side_effect = lambda pid: (native.Process(300, 1, 3000, native.UNIT_CGROUP) if pid == 300 else
            native.Process(301, 300, 4001, self.receipt.invocation.cgroup))

    def start(self, operation):
        intent = native.Selector.parse(self.files.read(self.fixture.runtime / "pending.json")).intent
        self.starts.append(copy.deepcopy(intent))
        info = self.fixture.group.stat()
        inv = replace(fixtures.invocation(), execution_id=self.execution_id, request_digest=self.request.digest,
                      attempt=intent["attempt"], invocation_id=f"{intent['attempt']:032x}",
                      cgroup=native.UNIT_CGROUP + f"/attempt-{intent['attempt']:032x}")
        self.receipt = native.NativeReceipt(inv, 3000, info.st_dev, info.st_ino)
        self.files.publish(native.receipt_path(inv), model.proof.canonical(asdict(self.receipt)))
        self.fixture.empty = False

    def release(self, receipt, wire):
        self.releases.append(copy.deepcopy(wire))
        saved = model.document(self.files.read(self.root / f"authorization-{receipt.invocation.attempt:04d}.json"))
        self.assertEqual(saved, wire | {"native_receipt": asdict(receipt)})
        return {"schema_version": 1, "released": True, "invocation": asdict(receipt.invocation)}

    def stop(self, receipt):
        self.assertEqual(receipt, self.receipt)
        self.fixture.empty = True
        return True

    def original_run(self):
        state = self.controller.load(self.root)
        self.job = self.controller.job(self.root, state)
        self.job.config.mkdir(mode=0o700, parents=True)
        self.job.output.chmod(0o700)
        (self.job.output / "private").chmod(0o700)
        (self.job.config / "runs").mkdir(mode=0o700)
        self.fence = {"schema_version": 1, "run_id": "bbx_" + "a" * 32, "request_id": "req_" + "b" * 32,
                      "request_hash": "c" * 64, "deadline": "2026-09-06T17:25:00Z", "session_id": "bss_" + "d" * 32}
        claim = {key: value for key, value in self.fence.items() if key != "session_id"} | {"controller_id": "fixture", "task_name": "fixture"}
        journal = self.job.config / "runs" / (self.fence["run_id"] + ".json")
        record = {"schema_version": 1, "claim": claim, "target_fingerprint": "e" * 64}
        self.files.publish(journal, model.proof.canonical(record))
        self.files.publish(journal.with_suffix(".session.json"), model.proof.canonical(record |
            {"run_id": self.fence["run_id"], "session_id": self.fence["session_id"]}))
        self.files.publish(self.job.output / "private/run-journal.json", model.proof.canonical(
            {"schema_version": 1, "run_id": self.fence["run_id"]}))
        self.files.publish(self.job.output / "private/blender-box", b"client")
        self.files.publish(self.job.output / "private/target.json", self.files.read(self.job.root / "inputs/target.json"))
        return self.files.read(journal), self.files.read(journal.with_suffix(".session.json"))

    def renewal(self, digit):
        value = {"schema_version": 1, "kind": "qualification-cleanup", "authorization_id": "wq-" + digit * 32,
                 "original_authorization_sha256": self.authority.digest, "execution_id": self.execution_id,
                 "original_run_id": self.fence["run_id"], "original_session_id": self.fence["session_id"],
                 "original_request_sha256": self.fence["request_hash"], "original_run_deadline": self.fence["deadline"],
                 "inputs_sha256": self.job.inputs_digest, "policy_sha256": self.policy.digest,
                 "installation_sha256": native.installation_digest(self.policy), "recovery_deadline_unix": int(time.time()) + 3600}
        raw = model.proof.canonical(value) + b"\n"
        path = native.CONFIG / "qualification-cleanup"
        path.mkdir(mode=0o700, exist_ok=True)
        self.files.publish(path / (value["authorization_id"] + ".json"), raw)
        return native.CleanupAuthorization.parse(raw)

    def command(self, cleanup):
        return {"schema_version": 1, "operation": "recover", "execution_id": self.execution_id,
                "cleanup_authorization_id": cleanup.value["authorization_id"], "cleanup_authorization_sha256": cleanup.digest}

    def test_two_direct_renewals_recover_original_run_without_replaying_baseline(self):
        self.controller.dispatch(model.Command("start", self.execution_id, self.request))
        self.assertEqual(self.files.read(self.root / "inputs.json"), self.files.read(self.job.root / "inputs.json"))
        original = self.original_run()
        first = self.renewal("7")
        recovered = native.cleanup_qualification_command(self.command(first), self.policy, self.files, self.ops)
        self.assertEqual((recovered["phase"], recovered["attempt"]), ("recovering", 2))
        self.assertEqual(self.starts[-1]["cleanup_authorization_sha256"], first.digest)
        self.assertEqual(self.files.read(self.root / "cleanup-0002.json"), first.raw)
        self.fixture.empty = True
        second = self.renewal("8")
        recovered = native.cleanup_qualification_command(self.command(second), self.policy, self.files, self.ops)
        self.assertEqual((recovered["phase"], recovered["attempt"]), ("recovering", 3))
        self.assertEqual([item["mode"] for item in self.starts], ["baseline", "recover", "recover"])
        self.assertEqual([item["cleanup_authorization_sha256"] for item in self.starts], [None, first.digest, second.digest])
        state = self.controller.load(self.root)
        job = self.controller.job(self.root, state)
        commands, stopped = [], [False]
        fence = self.fence
        expected_config = str(job.config)
        class Commands:
            def __init__(self, private, cwd):
                self.private, self.env = private, {"PATH": "/usr/bin:/bin"}
            def json(self, args, **kwargs):
                commands.append(args[1])
                self.assert_original(args)
                if args[1] == "stop":
                    stopped[0] = True
                result = fence | {"state": "failed" if stopped[0] else "calling"}
                if stopped[0]:
                    result |= {"status": "settled", "cleanup": {key: True for key in model.proof.CLEANUP}}
                return result
            def assert_original(self, args):
                if self.env["BLENDER_BOX_CONFIG_DIR"] != expected_config or args[args.index("--run") + 1] != fence["run_id"]:
                    raise AssertionError("original Run changed")
        cleanup = model.ProofWorker(commands_factory=Commands).recover(job, state["recovery_inputs"])
        self.assertEqual(commands, ["status", "stop", "status"])
        self.assertTrue(all(cleanup.values()))
        journal = Path(state["recovery_inputs"]["journal"])
        self.assertEqual((self.files.read(journal), self.files.read(journal.with_suffix(".session.json"))), original)
        self.assertEqual(model.document(self.files.read(self.root / "origin.json")), self.context.origin)
        self.files.publish(self.root / "result-0003.json", model.proof.canonical({"schema_version": 1,
            "invocation": asdict(self.receipt.invocation), "mode": "recover", "result": cleanup}))
        self.fixture.empty = True
        completed = self.controller.dispatch(model.Command("status", self.execution_id))
        self.assertEqual((completed["phase"], completed["proof_result"], completed["windows_cleanup"]),
                         ("settled", "fail", "proven"))
        state = self.controller.load(self.root)
        for name in ("boot", "unit", "whole_empty", "supervisor_gone", "process", "group"):
            getattr(self.ops, name).side_effect = AssertionError("historical recovery queried live process authority")
        native.completed_windows_attempt(self.controller, self.root, state)
        for kind in ("intent", "native", "authorization", "result"):
            path = self.root / f"{kind}-0003.json"
            original = self.files.read(path)
            with self.subTest(kind=kind, change="missing recovery record"):
                path.unlink()
                with self.assertRaises((model.ControllerError, OSError)):
                    native.completed_windows_attempt(self.controller, self.root, state)
                self.files.publish(path, original)
        path = self.root / "result-0003.json"
        original = self.files.read(path)
        invalid = model.document(original)
        invalid["result"][model.proof.CLEANUP[0]] = False
        self.files.publish(path, model.proof.canonical(invalid), exclusive=False)
        with self.assertRaises(model.proof.ProofError):
            native.completed_windows_attempt(self.controller, self.root, state)
        self.files.publish(path, original, exclusive=False)
        native.windows_readiness(self.controller, self.context)
        readiness = model.document(self.files.read(self.root / "native-readiness.json"))
        self.assertIs(readiness["qualified"], False)
        self.assertEqual(readiness["cases"]["windows-baseline"]["status"], "fail")
        with self.assertRaises(model.ControllerError):
            self.policy.qualify(model.proof.canonical(readiness))
        with mock.patch.object(self.files, "publish", side_effect=AssertionError("unchanged status rewrote evidence")):
            self.assertEqual(native.windows_readiness(self.controller, self.context), completed)

    def test_previous_failed_start_without_native_receipt_can_advance(self):
        def failed(operation):
            self.start(operation)
            native.receipt_path(self.receipt.invocation).unlink()
            intent = self.starts[-1]
            failure = native.StartupFailure(intent, model.proof.digest(self.files.read(self.root / "intent-0001.json")),
                self.receipt.invocation.boot_id, self.receipt.invocation.invocation_id, 300, 3000,
                self.receipt.invocation.cgroup, 2, 3)
            self.files.publish(self.root / "startup-failure-0001.json", model.proof.canonical(asdict(failure)))
            self.fixture.empty = True
        self.ops.systemctl.side_effect = failed
        self.ops.process.side_effect = FileNotFoundError()
        with self.assertRaisesRegex(model.ControllerError, "native-start-unconfirmed"):
            self.controller.dispatch(model.Command("start", self.execution_id, self.request))
        self.assertEqual(self.controller.dispatch(model.Command("status", self.execution_id))["phase"], "settled")
        state = self.controller.load(self.root)
        self.assertIsNone(state["invocation"])
        authority = native.QualificationAuthorization.parse(model.proof.canonical(self.authority.value |
            {"authorization_id": "wq-" + "9" * 32, "cases": ["windows-crash-recover"]}))
        service = native.NativeService(self.policy, self.files, self.ops,
                                      native.WindowsQualification(authority, "windows-crash-recover"))
        with self.controller.locked():
            self.assertTrue(service.observe().empty)
        self.assertEqual(len(self.starts), 1)
        self.ops.exchange.assert_not_called()

    def test_new_single_case_authorization_advances_only_after_previous_settlement(self):
        self.controller.dispatch(model.Command("start", self.execution_id, self.request))
        old_root, old_controller = self.root, self.controller
        old_request, old_receipt = self.request, self.receipt
        value = self.authority.value | {"authorization_id": "wq-" + "9" * 32, "cases": ["windows-crash-recover"]}
        provisional = native.QualificationAuthorization.parse(model.proof.canonical(value))
        self.execution_id = provisional.execution_id("windows-crash-recover")
        self.request = fixtures.baseline.request(self.execution_id)
        self.root = self.base.control / self.execution_id
        self.job = model.Job(self.request, self.base.jobs / self.execution_id, self.base.checkout,
                             self.base.policy.expected_client_sha256, 1)
        contents = {name: self.files.read(old_root / "inputs" / name) for name in
            ("original-operator.json", "original-ssh-config", "operator.json", "target.json", "ssh-config", "key", "known_hosts")}
        connection = model.ssh_connection(contents["original-ssh-config"], model.document(contents["target.json"])["ssh_alias"])
        contents["operator.json"] = model.proof.canonical(model.document(contents["original-operator.json"]) |
                                                         {"ssh_config": str(self.job.root / "inputs/ssh-config")})
        contents["ssh-config"] = model.normalized_ssh(connection, self.job.root / "inputs")
        manifest = {"schema_version": 1, "files": {name: model.proof.digest(raw) for name, raw in contents.items()},
                    "candidate_checkout": str(self.base.checkout), "config": str(self.job.config),
                    "expected_client_sha256": self.job.expected_client_sha256}
        value["operator_manifest_sha256"] = model.proof.digest(model.proof.canonical(manifest))
        value["fixture_sha256"] = native.identity_digest("WindowsFixture", {name: self.policy.value["artifacts"][
            str(native.BASE / "tests/fixtures/qualification-windows-hold" / name)] for name in ("payload.json", "scenario.py")})
        self.context = native.WindowsQualification(native.QualificationAuthorization.parse(model.proof.canonical(value)), "windows-crash-recover")
        self.service = native.NativeService(self.policy, self.files, self.ops, self.context)
        self.controller = model.Controller(self.base.control, self.base.jobs, self.base.policy, self.service,
            clock=lambda: fixtures.baseline.NOW, files=self.files, admission=self.policy.admit, qualification=self.context)
        pending_path = self.fixture.runtime / "pending.json"
        original_pending = self.files.read(pending_path)
        with self.assertRaisesRegex(model.ControllerError, "fixture-unresolved"):
            self.controller.dispatch(model.Command("start", self.execution_id, self.request))
        self.assertEqual(self.files.read(pending_path), original_pending)
        self.assertEqual(len(self.starts), 1)
        self.files.publish(old_root / "result-0001.json", model.proof.canonical({"schema_version": 1,
            "invocation": asdict(old_receipt.invocation), "mode": "baseline", "result": {
                "execution": "hosted", "candidate_sha": old_request.candidate_sha, "driver_sha": old_request.driver_sha,
                "status": "pass", "cleanup": {key: True for key in model.proof.CLEANUP}}}))
        self.fixture.empty = True
        self.assertEqual(old_controller.dispatch(model.Command("status", old_request.execution_id))["phase"], "settled")
        origin_path = old_root / "origin.json"
        original_origin = self.files.read(origin_path)
        self.files.publish(origin_path, b"{}", exclusive=False)
        with self.assertRaises(model.ControllerError):
            self.controller.dispatch(model.Command("start", self.execution_id, self.request))
        self.assertEqual(self.files.read(pending_path), original_pending)
        self.files.publish(origin_path, original_origin, exclusive=False)
        self.ops.unit.return_value = native.UnitState("inactive", 0, "", native.UNIT_CGROUP)
        started = self.controller.dispatch(model.Command("start", self.execution_id, self.request))
        self.assertEqual((started["phase"], started["attempt"]), ("running", 1))
        self.assertEqual(len(self.starts), 2)
        self.assertNotEqual(self.files.read(pending_path), original_pending)
        self.assertEqual(model.document(self.files.read(self.root / "origin.json")), self.context.origin)

    def test_settled_pass_requires_matching_durable_attempt_without_live_queries(self):
        self.controller.dispatch(model.Command("start", self.execution_id, self.request))
        self.files.publish(self.root / "result-0001.json", model.proof.canonical({"schema_version": 1,
            "invocation": asdict(self.receipt.invocation), "mode": "baseline", "result": {
                "execution": "hosted", "candidate_sha": self.request.candidate_sha,
                "driver_sha": self.request.driver_sha, "status": "pass",
                "cleanup": {key: True for key in model.proof.CLEANUP}}}))
        self.fixture.empty = True
        completed = self.controller.dispatch(model.Command("status", self.execution_id))
        self.assertEqual((completed["phase"], completed["proof_result"]), ("settled", "pass"))
        for name in ("boot", "unit", "whole_empty", "supervisor_gone", "process", "group"):
            getattr(self.ops, name).side_effect = AssertionError("historical status queried live process authority")
        native.windows_readiness(self.controller, self.context)
        readiness = model.document(self.files.read(self.root / "native-readiness.json"))
        self.assertEqual(readiness["cases"][self.context.case]["status"], "pass")
        for kind in ("intent", "native", "authorization", "result"):
            path = self.root / f"{kind}-0001.json"
            original = self.files.read(path)
            with self.subTest(kind=kind, change="missing"):
                path.unlink()
                with self.assertRaises((model.ControllerError, OSError)):
                    native.windows_readiness(self.controller, self.context)
                self.files.publish(path, original)
            with self.subTest(kind=kind, change="mismatch"):
                value = model.document(original)
                if kind == "intent":
                    value["request_digest"] = "f" * 64
                elif kind == "native":
                    value["invocation"]["request_digest"] = "f" * 64
                elif kind == "authorization":
                    value["intent_sha256"] = "f" * 64
                else:
                    value["result"]["cleanup"][model.proof.CLEANUP[0]] = False
                self.files.publish(path, model.proof.canonical(value), exclusive=False)
                with self.assertRaises((model.ControllerError, model.proof.ProofError)):
                    native.windows_readiness(self.controller, self.context)
                self.files.publish(path, original, exclusive=False)
        with mock.patch.object(self.files, "publish", side_effect=AssertionError("historical status rewrote evidence")):
            native.windows_readiness(self.controller, self.context)

    def test_missing_qualification_origin_cannot_make_settled_execution_public(self):
        self.controller.dispatch(model.Command("start", self.execution_id, self.request))
        state = self.controller.load(self.root)
        state.update(phase="settled", closed=True, local_termination="proven", windows_cleanup="proven", proof_result="fail")
        self.controller.save(self.root, state)
        (self.root / "origin.json").unlink()
        public = model.Controller(self.base.control, self.base.jobs, self.base.policy, self.service, files=self.files)
        with mock.patch.object(self.files, "read", side_effect=AssertionError("public status read qualification records")):
            with self.assertRaisesRegex(model.ControllerError, "qualification-origin-forbidden"):
                public.dispatch(model.Command("status", self.execution_id))
        self.assertEqual(len(self.starts), 1)
        self.ops.stop.assert_not_called()

    def test_expired_status_checks_original_snapshot_without_live_operator_reads(self):
        self.controller.dispatch(model.Command("start", self.execution_id, self.request))
        original_read = self.files.read
        def retained_only(path, *args, **kwargs):
            if path == self.base.operator or path.name in ("dedicated-key",):
                raise AssertionError("live operator input read")
            return original_read(path, *args, **kwargs)
        with mock.patch.object(self.files, "read", side_effect=retained_only):
            native.validate_windows_qualification(self.context, self.policy, self.files, observe=True)
            self.files.publish(self.root / "inputs/target.json", b'{"schema_version":1}', exclusive=False)
            with self.assertRaisesRegex(model.ControllerError, "qualification-inputs-changed"):
                native.validate_windows_qualification(self.context, self.policy, self.files, observe=True)
        self.ops.stop.assert_not_called()


class RecoveryEvidenceTests(unittest.TestCase):
    def setUp(self):
        from contextlib import nullcontext
        from types import SimpleNamespace
        self.control = Path("/fixture-control")
        self.root = self.control / "fixture"
        records = {}
        self.files = SimpleNamespace(read=lambda path, *args: records[path], exists=lambda path: path in records,
            publish=lambda path, raw, **kwargs: records.__setitem__(path, raw))
        patch = mock.patch.object(native, "CONTROL", self.control)
        patch.start()
        self.addCleanup(patch.stop)
        self.original = native.NativeReceipt(fixtures.invocation(), 3000, 1, 2)
        self.final = replace(self.original, invocation=replace(self.original.invocation, boot_id="f" * 32))
        self.active = {"schema_version": 1, "checkpoint": {}, "native_receipt": asdict(self.original)}
        self.write("active-checkpoint.json", self.active)
        self.write("native-0002.json", asdict(self.final))
        self.write("result-0002.json", {"schema_version": 1, "result": "fixture-cleanup-proven"})
        self.write("intent-0002.json", {"fixture": "intent"})
        self.write("authorization-0002.json", {"fixture": "authorization"})
        patch = mock.patch.object(native, "completed_windows_attempt")
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(native.time, "time", return_value=2)
        self.clock = patch.start()
        self.addCleanup(patch.stop)
        self.record = {"schema_version": 1, "active_checkpoint_sha256": model.proof.digest(model.proof.canonical(self.active)),
                       "original_native_sha256": model.proof.digest(model.proof.canonical(asdict(self.original))),
                       "local_termination": "proven", "observed_at_unix": 1}
        self.context = SimpleNamespace(execution_id="fixture", case="windows-crash-recover", origin_digest="a" * 64,
            verify_origin=lambda files: None, authorization=SimpleNamespace(digest="b" * 64,
                value={"policy_sha256": "c" * 64, "installation_sha256": "d" * 64}))
        self.state = {"attempt": 2, "recovery_inputs": {}, "phase": "settled",
                      "local_termination": "proven", "windows_cleanup": "proven"}
        self.controller = SimpleNamespace(files=self.files, locked=nullcontext, load=lambda root: self.state,
                                         job=lambda root, state: None, receipt=lambda state: state)
        self.fence = model.proof.Fence.parse({"schema_version": 1, "run_id": "bbx_" + "a" * 32,
            "request_id": "req_" + "b" * 32, "request_hash": "c" * 64,
            "deadline": "2026-09-06T17:25:00Z", "session_id": "bss_" + "d" * 32})
        patch = mock.patch.object(native, "original_windows_fence", return_value=(self.fence, {}))
        patch.start()
        self.addCleanup(patch.stop)

    def write(self, name, value):
        self.files.publish(self.root / name, model.proof.canonical(value), exclusive=False)

    def test_readiness_accepts_only_exact_recovery_records(self):
        for case, name, reboot in (("windows-crash-recover", "interruption.json", False),
                                   ("windows-reboot-recover", "reboot-observation.json", True)):
            self.context.case = case
            record = self.record | ({"observed_boot_id": "f" * 32} if reboot else {})
            self.write(name, record)
            native.windows_readiness(self.controller, self.context)
            readiness = model.document(self.files.read(self.root / "native-readiness.json"))
            self.assertEqual(readiness["cases"][case]["status"], "pass")
            invalid = [[], record | {"extra": True}, record | {"schema_version": True},
                       record | {"observed_at_unix": 0}, record | {"observed_at_unix": -1},
                       record | {"observed_at_unix": True}, record | {"local_termination": "unknown"}]
            invalid += [{key: value for key, value in record.items() if key != field} for field in record]
            if reboot:
                invalid += [record | {"observed_boot_id": value} for value in (None, [], "F" * 32, "bad")]
            for value in invalid:
                with self.subTest(case=case, value=value):
                    self.write(name, value)
                    with self.assertRaises(model.ControllerError):
                        native.windows_readiness(self.controller, self.context)
            self.write(name, record)
            for active in ([], self.active | {"extra": True}, self.active | {"schema_version": True},
                           {key: value for key, value in self.active.items() if key != "checkpoint"}):
                with self.subTest(case=case, active=active):
                    self.write("active-checkpoint.json", active)
                    with self.assertRaises(model.ControllerError):
                        native.windows_readiness(self.controller, self.context)
            self.write("active-checkpoint.json", self.active)

    def test_retained_reboot_observation_rejects_malformed_records(self):
        record = self.record | {"observed_boot_id": "f" * 32}
        self.write("reboot-observation.json", record)
        ops = mock.Mock()
        native.observe_windows_reboot(self.context, self.files, ops)
        for value in ([], record | {"extra": True}, record | {"schema_version": True},
                      record | {"observed_at_unix": 0}, record | {"observed_at_unix": True},
                      record | {"local_termination": "unknown"}, record | {"observed_boot_id": []},
                      record | {"observed_boot_id": "F" * 32}):
            with self.subTest(value=value):
                self.write("reboot-observation.json", value)
                with self.assertRaises(model.ControllerError):
                    native.observe_windows_reboot(self.context, self.files, ops)
        self.write("active-checkpoint.json", self.active | {"extra": True})
        with self.assertRaises(model.ControllerError):
            native.observe_windows_reboot(self.context, self.files, ops)
        ops.boot.assert_not_called()
        ops.whole_empty.assert_not_called()

    def test_late_cleanup_cannot_upgrade_timely_interruption(self):
        self.write("interruption.json", self.record)
        deadline = datetime.fromisoformat(self.fence.deadline.replace("Z", "+00:00")).timestamp()
        self.clock.return_value = deadline
        native.windows_readiness(self.controller, self.context)
        readiness = model.document(self.files.read(self.root / "native-readiness.json"))
        self.assertEqual(readiness["cases"][self.context.case]["status"], "fail")
        completion = self.files.read(self.root / "recovery-completion.json")
        self.clock.return_value = deadline + 86400
        native.windows_readiness(self.controller, self.context)
        self.assertEqual(self.files.read(self.root / "recovery-completion.json"), completion)
        self.assertEqual(model.document(self.files.read(self.root / "native-readiness.json")), readiness)

    def test_timely_completion_survives_later_status_without_rewriting(self):
        self.write("interruption.json", self.record)
        native.windows_readiness(self.controller, self.context)
        readiness = model.document(self.files.read(self.root / "native-readiness.json"))
        self.assertEqual(readiness["cases"][self.context.case]["status"], "pass")
        self.clock.return_value = datetime.fromisoformat(self.fence.deadline.replace("Z", "+00:00")).timestamp() + 86400
        with mock.patch.object(self.files, "publish", side_effect=AssertionError("settled status rewrote evidence")):
            native.windows_readiness(self.controller, self.context)
        completion = model.document(self.files.read(self.root / "recovery-completion.json"))
        for bad in (completion | {"extra": True}, completion | {"attempt": True},
                    completion | {"observed_at_unix": 0}, completion | {"result_sha256": "f" * 64}):
            with self.subTest(completion=bad):
                self.write("recovery-completion.json", bad)
                with self.assertRaises(model.ControllerError):
                    native.windows_readiness(self.controller, self.context)
