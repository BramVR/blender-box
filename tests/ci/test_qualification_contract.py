from dataclasses import asdict, replace
from contextlib import redirect_stdout
import copy
import io
import json
import os
from types import SimpleNamespace
import unittest
from unittest import mock

import test_proof_controller_native as fixtures

native, model, worker = fixtures.native, fixtures.model, fixtures.worker


def linux():
    return {"schema_version": 1, "family": "linux-native-v1", "qualification_id": "q-" + "1" * 32,
            "policy_sha256": "2" * 64, "installation_sha256": "3" * 64,
            "deadline_unix": 2000, "case": "uid-confinement", "accepted_boot_id": "4" * 32}


def authorization():
    policy = fixtures.policy()
    return {"schema_version": 1, "family": "windows-controller-v1", "authorization_id": "wq-" + "1" * 32,
            "policy_sha256": policy.digest, "installation_sha256": native.installation_digest(policy),
            "candidate_sha": policy.value["candidate_sha"], "driver_sha": policy.value["driver_sha"],
            "fixture_sha256": "6" * 64, "operator_manifest_sha256": "7" * 64,
            "expected_client_sha256": policy.value["expected_client_sha256"], "expected_host_sha256": "8" * 64,
            "target_sha256": "9" * 64, "cases": ["windows-baseline"],
            "launch_deadline_unix": 2000, "recovery_deadline_unix": 3000, "max_attempts": 4}


class QualificationContractTests(unittest.TestCase):
    def test_startup_failure_rejects_nonobject_intents_at_boundary(self):
        receipt = native.StartupFailure(True, "a" * 64, "b" * 32, "c" * 32, 1, 2,
                                        native.UNIT_CGROUP + "/attempt-" + "d" * 32, 3, 4)
        for malformed in (True, None, 1, "intent", []):
            with self.assertRaises(model.ControllerError):
                native.StartupFailure.parse(asdict(receipt) | {"intent": malformed})

    def test_linux_hash_domains_and_three_way_selector_rejection(self):
        intent = native.LinuxIntent.parse(linux())
        self.assertEqual(len({intent.digest, intent.authorization_digest, intent.origin_digest}), 3)
        selected = native.Selector.create("linux-qualification", intent.value)
        self.assertEqual(native.Selector.parse(model.proof.canonical(selected.wire())), selected)
        operational = {"schema_version": 1, "execution_id": "unit", "attempt": 1, "request_digest": "a" * 64, "mode": "baseline"}
        for kind, value in (("operational", linux()), ("windows-qualification", linux()),
                            ("linux-qualification", operational), ("windows-qualification", operational)):
            with self.subTest(kind=kind), self.assertRaises(model.ControllerError):
                native.Selector.create(kind, value)
        with self.assertRaises(model.ControllerError):
            native.operational_pending(model.proof.canonical(selected.wire()))

    def test_exact_shapes_duplicate_keys_versions_boolean_numbers_and_size(self):
        start = {key: value for key, value in linux().items() if key != "accepted_boot_id"} | {"operation": "start"}
        native.parse_qualification_command(model.proof.canonical(start), "linux")
        mutations = [start | {"path": "/tmp/not-authority"}, start | {"deadline_unix": True}, start | {"schema_version": True},
                     start | {"case": ["uid-confinement"]}, start | {"qualification_id": "../unsafe"},
                     {key: value for key, value in start.items() if key != "policy_sha256"}]
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(model.ControllerError):
                native.parse_qualification_command(model.proof.canonical(value), "linux")
        for raw in (b'{"schema_version":1,"schema_version":1}', model.proof.canonical(start) + b'{}',
                    b' ' * native.QUALIFICATION_LIMIT + model.proof.canonical(start)):
            with self.assertRaises(model.ControllerError):
                native.parse_qualification_command(raw, "linux")
        selector = native.Selector.create("linux-qualification", linux()).wire()
        for value in (selector | {"schema_version": 1}, selector | {"schema_version": True}, selector | {"intent_sha256": "f" * 64}):
            with self.assertRaises(model.ControllerError):
                native.Selector.parse(model.proof.canonical(value))

    def test_authorization_file_hash_and_execution_identity_have_different_roles(self):
        raw = model.proof.canonical(authorization())
        first = native.QualificationAuthorization.parse(raw)
        second = native.QualificationAuthorization.parse(raw + b"\n")
        self.assertNotEqual(first.digest, second.digest)
        self.assertEqual(first.execution_id("windows-baseline"), second.execution_id("windows-baseline"))
        self.assertNotEqual(first.origin("windows-baseline"), second.origin("windows-baseline"))
        for cases in ([{}], [[]], [True], ["windows-baseline", "windows-baseline"],
                      ["windows-baseline", "windows-crash-recover"], []):
            with self.assertRaises(model.ControllerError):
                native.QualificationAuthorization.parse(model.proof.canonical(authorization() | {"cases": cases}))
        for field in ("max_attempts", "launch_deadline_unix", "recovery_deadline_unix"):
            with self.assertRaises(model.ControllerError):
                native.QualificationAuthorization.parse(model.proof.canonical(authorization() | {field: True}))

    def test_recovery_cases_admit_both_policy_variants_without_cross_variant_baselines(self):
        for variant in ("baseline", "named-target"):
            policy = native.NativePolicy.parse(model.proof.canonical(fixtures.policy().value | {"variant": variant}))
            value = authorization() | {"policy_sha256": policy.digest, "installation_sha256": native.installation_digest(policy),
                                      "cases": ["windows-crash-recover"]}
            approved = native.QualificationAuthorization.parse(model.proof.canonical(value))
            approved.validate(policy, native.installation_digest(policy), "windows-crash-recover", 1000, launch=True)
            wrong = "windows-baseline" if variant == "named-target" else "windows-named-target"
            approved = native.QualificationAuthorization.parse(model.proof.canonical(value | {"cases": [wrong]}))
            with self.assertRaises(model.ControllerError):
                approved.validate(policy, native.installation_digest(policy), wrong, 1000, launch=True)

    def test_root_operations_reject_real_or_effective_nonroot_before_stdin_or_files(self):
        for args in (["qualification"], ["qualify-windows"], ["qualification-cleanup"]):
            for uid, euid in ((1, 0), (0, 1), (1, 1)):
                stream = mock.Mock()
                with mock.patch.object(os, "getuid", return_value=uid, create=True), mock.patch.object(os, "geteuid", return_value=euid, create=True), \
                     mock.patch("sys.stdin", SimpleNamespace(buffer=stream)), mock.patch.object(native, "load_prepared") as load, \
                     redirect_stdout(io.StringIO()):
                    self.assertEqual(native.entrypoint(args), 1)
                stream.read.assert_not_called()
                load.assert_not_called()

    def test_operational_dispatch_never_accepts_qualification_document(self):
        start = {key: value for key, value in linux().items() if key != "accepted_boot_id"} | {"operation": "start"}
        with mock.patch("sys.stdin", SimpleNamespace(buffer=io.BytesIO(model.proof.canonical(start)))), \
             mock.patch.object(native, "load_runtime") as load, redirect_stdout(io.StringIO()):
            self.assertEqual(native.entrypoint(["dispatch"]), 1)
        load.assert_not_called()

    def test_linux_envelope_never_constructs_windows_request_or_admission(self):
        value = linux() | {"deadline_unix": 9999999999}
        intent = native.LinuxIntent.parse(value)
        owner = native.ProcessOwner(value["accepted_boot_id"], "a" * 32, native.UNIT_CGROUP + "/attempt-" + "b" * 32,
                                    11, 12, 13, 14, 15, 16)
        receipt = native.NativeFixtureReceipt(intent.digest, owner)
        envelope = {"schema_version": 1, "origin": "linux-qualification", "intent": value,
                    "intent_sha256": intent.digest, "native_receipt": asdict(receipt), "authorization_sha256": intent.authorization_digest}
        with mock.patch.object(model.ProofExecutionRequest, "parse", side_effect=AssertionError("Windows request")), \
             mock.patch.object(worker, "NativeAdmission", side_effect=AssertionError("Windows admission")), \
             mock.patch.object(worker, "WindowsQualificationAdmission", side_effect=AssertionError("Windows qualification")):
            self.assertEqual(worker.parse_linux_envelope(envelope), (intent, receipt))
        with self.assertRaises(model.ControllerError):
            worker.parse_envelope(envelope)

    def test_windows_intent_binds_direct_cleanup_digest_and_preserves_original_origin(self):
        approved = native.QualificationAuthorization.parse(model.proof.canonical(authorization()))
        context = native.WindowsQualification(approved, "windows-baseline")
        request = fixtures.baseline.request(context.execution_id)
        initial = context.intent(request, 1, "baseline")
        self.assertIsNone(initial["cleanup_authorization_sha256"])
        changed = initial | {"cleanup_authorization_sha256": "c" * 64}
        with self.assertRaises(model.ControllerError):
            native.parse_windows_intent(changed)
        recovered = changed | {"attempt": 2, "mode": "recover"}
        native.parse_windows_intent(recovered)
        self.assertEqual(recovered["origin_sha256"], initial["origin_sha256"])
        with self.assertRaises(model.ControllerError):
            native.parse_windows_intent(recovered | {"attempt": 5})


if __name__ == "__main__":
    unittest.main()

@unittest.skipUnless(model.fcntl is not None, "POSIX native controller fixtures")
class LinuxQualificationLifecycleTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from pathlib import Path
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name).resolve()
        self.control, self.jobs = root / "control", root / "jobs"
        self.control.mkdir(mode=0o700)
        self.jobs.mkdir(mode=0o700)
        patch = mock.patch.multiple(native, CONTROL=self.control, JOBS=self.jobs)
        patch.start()
        self.addCleanup(patch.stop)
        self.files = fixtures.store.LocalFiles()
        self.intent = native.LinuxIntent.parse(linux())
        self.intent.root.parent.mkdir(mode=0o700)
        self.intent.root.mkdir(mode=0o700)
        self.files.publish(self.intent.root / "intent.json", model.proof.canonical(self.intent.value))
        self.owner = native.ProcessOwner("4" * 32, "a" * 32, native.UNIT_CGROUP + "/attempt-" + "b" * 32,
                                         11, 12, 13, 14, 15, 16)
        self.ops = mock.Mock()
        self.ops.boot.return_value = "4" * 32
        self.ops.whole_empty.return_value = True
        self.ops.supervisor_gone.return_value = True
        self.ops.unit.return_value = native.UnitState("inactive", 0, "", "")

    def test_missing_native_receipt_never_means_no_work_started(self):
        value = native.linux_observe(self.intent, self.files, self.ops, stop=True)
        self.assertEqual(value["local_termination"], "unknown")
        self.assertFalse(self.files.exists(self.intent.root / "settled.json"))
        self.ops.stop.assert_not_called()

    def test_exact_failed_start_settles_reservation_without_authorizing_release(self):
        self.files.publish(self.intent.root / "startup-failure.json", model.proof.canonical({"schema_version": 1,
            "intent_sha256": self.intent.digest, "owner": asdict(self.owner), "child_cleanup": "proven"}))
        self.files.publish(self.intent.root / "start-command.json", model.proof.canonical({"schema_version": 1,
            "intent_sha256": self.intent.digest, "boot_id": self.owner.boot_id}))
        value = native.linux_observe(self.intent, self.files, self.ops)
        self.assertEqual((value["phase"], value["result"]), ("settled", "fail"))
        native.qualification_reservations_settled(self.files, self.intent.root.parent)
        self.ops.stop.assert_not_called()
        self.ops.exchange.assert_not_called()
        self.ops.reset_mock()
        self.ops.boot.side_effect = AssertionError("settled status must not observe a replacement service")
        self.ops.whole_empty.side_effect = AssertionError("settled status must not inspect replacement work")
        self.assertEqual(native.linux_observe(self.intent, self.files, self.ops), value)
        readiness = model.document(self.files.read(self.intent.root / "native-readiness.json"))
        self.assertIs(readiness["qualified"], False)
        with self.assertRaises(model.ControllerError):
            fixtures.policy().qualify(model.proof.canonical(readiness))

    def test_reboot_settlement_never_looks_up_or_signals_old_pids(self):
        receipt = native.NativeFixtureReceipt(self.intent.digest, self.owner)
        self.files.publish(self.intent.root / "native.json", model.proof.canonical(asdict(receipt)))
        self.ops.boot.return_value = "f" * 32
        self.ops.process.side_effect = AssertionError("old PID lookup")
        self.ops.stop.side_effect = AssertionError("old PID signal")
        value = native.linux_observe(self.intent, self.files, self.ops, stop=True)
        self.assertEqual((value["phase"], value["result"]), ("settled", "fail"))
        self.ops.process.assert_not_called()
        self.ops.supervisor_gone.assert_not_called()

    def test_result_without_authorization_refuses_and_preserves_reservation(self):
        receipt = native.NativeFixtureReceipt(self.intent.digest, self.owner)
        self.files.publish(self.intent.root / "native.json", model.proof.canonical(asdict(receipt)))
        self.files.publish(self.intent.root / "result.json", model.proof.canonical({"schema_version": 1}))
        with self.assertRaisesRegex(model.ControllerError, "qualification-result-conflict"):
            native.linux_observe(self.intent, self.files, self.ops)
        self.assertFalse(self.files.exists(self.intent.root / "settled.json"))

    def test_expired_start_cannot_replay_accepted_case(self):
        command = {key: value for key, value in linux().items() if key != "accepted_boot_id"} | {"operation": "start"}
        with self.assertRaisesRegex(model.ControllerError, "qualification-expired"):
            native.linux_qualification_command(command, fixtures.policy(), self.files, self.ops)
        self.ops.systemctl.assert_not_called()

    def test_noop_descendant_stop_cannot_pass_and_exact_stop_binds_live_child(self):
        from contextlib import contextmanager
        self.intent = native.LinuxIntent.parse(linux() | {"case": "descendant-stop"})
        self.files.publish(self.intent.root / "intent.json", model.proof.canonical(self.intent.value), exclusive=False)
        info = self.control.stat()
        self.owner = replace(self.owner, cgroup_device=info.st_dev, cgroup_inode=info.st_ino)
        receipt = native.NativeFixtureReceipt(self.intent.digest, self.owner)
        self.files.publish(self.intent.root / "native.json", model.proof.canonical(asdict(receipt)))
        self.files.publish(self.intent.root / "authorization.json", model.proof.canonical(
            native.linux_release(self.intent, receipt) | {"native_receipt": asdict(receipt)}))
        action_root = self.jobs / "qualification" / self.intent.value["qualification_id"]
        action_root.mkdir(parents=True, mode=0o700)
        action_root.parent.chmod(0o700)
        child = native.Process(17, self.owner.leader_pid, 18, self.owner.cgroup)
        self.files.publish(action_root / "action.json", model.proof.canonical({"schema_version": 1,
            "intent_sha256": self.intent.digest, "case": "descendant-stop", "observations": {"descendant": asdict(child)}}))
        empty, events = [False], []
        self.ops.whole_empty.side_effect = lambda: empty[0]
        self.ops.unit.side_effect = lambda: (native.UnitState("inactive", 0, "", "") if empty[0] else
                                             native.UnitState("active", self.owner.parent_pid, self.owner.invocation_id, native.UNIT_CGROUP))
        def process(pid):
            events.append(("process", pid))
            if pid == child.pid:
                return child
            if pid == self.owner.parent_pid:
                return native.Process(pid, 1, self.owner.supervisor_start, native.UNIT_CGROUP)
            return native.Process(pid, self.owner.parent_pid, self.owner.leader_start_ticks, self.owner.cgroup)
        @contextmanager
        def group(name):
            fd = os.open(self.control, os.O_RDONLY | os.O_DIRECTORY)
            try:
                yield fd
            finally:
                os.close(fd)
        self.ops.process.side_effect = process
        self.ops.group.side_effect = group
        self.ops.stop.return_value = True
        incomplete = native.linux_observe(self.intent, self.files, self.ops, stop=True)
        self.assertEqual(incomplete["local_termination"], "unknown")
        self.assertNotEqual(incomplete["result"], "pass")
        self.assertFalse(self.files.exists(self.intent.root / "descendant-stop-complete.json"))
        def exact_stop(observed):
            self.assertEqual(observed, receipt)
            self.assertEqual(events[-1], ("process", child.pid))
            self.assertTrue(self.files.exists(self.intent.root / "descendant-before-stop.json"))
            empty[0] = True
            return True
        self.ops.stop.side_effect = exact_stop
        complete = native.linux_observe(self.intent, self.files, self.ops, stop=True)
        self.assertEqual((complete["result"], complete["local_termination"]), ("pass", "proven"))
        self.assertTrue(self.files.exists(self.intent.root / "descendant-stop-complete.json"))
