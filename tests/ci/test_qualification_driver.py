from contextlib import ExitStack
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import runpy
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import test_onboarding_proof as baseline_tests


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import proof_controller_worker as worker

proof = baseline_tests.proof


class QualificationDriverTests(baseline_tests.ProofFixture):
    def execute_admitted(self, case=None, *, expected_host=None, admission_type=None, reject=False, variant=None):
        self.path.write_bytes(proof.canonical(self.config))
        self.path.chmod(0o600)
        authority_class = admission_type or (worker.WindowsQualificationAdmission if case else worker.NativeAdmission)
        authority = object.__new__(authority_class)
        self.request = replace(self.request, execution="hosted", driver_sha="b" * 40,
                               proof=variant or ("named-target" if case == "windows-named-target" else "baseline"))

        def admit(instance, request):
            self.assertIs(instance, authority)
            self.assertEqual(request, self.request)
            if reject:
                raise proof.ProofError("native-request-changed")
            if case:
                instance.case = case
                instance.expected_host_sha256 = expected_host or proof.digest(b"host")

        def factory(private, cwd):
            self.commands = baseline_tests.FakeCommands(private, cwd, self.config)
            return self.commands

        with ExitStack() as stack:
            stack.enter_context(mock.patch.dict(os.environ, GITHUB_RUN_ATTEMPT="1"))
            stack.enter_context(mock.patch.object(authority_class, "require_proof", admit))
            authority.require_proof = mock.Mock(side_effect=AssertionError("instance method must not authorize"))
            return proof.baseline(self.request, factory, native_authority=authority)

    def run_call(self):
        return next((call, options) for call, options in zip(self.commands.calls, self.commands.call_options)
                    if len(call) > 1 and call[1] == "run")

    def test_native_admission_keeps_baseline_fixture_and_budget(self):
        result = self.execute_admitted()
        self.assertEqual(result["status"], "pass")
        call, options = self.run_call()
        self.assertEqual(call[call.index("--payload") + 1], str(proof.FIXTURE / "payload.json"))
        self.assertEqual(call[call.index("--timeout") + 1], "20m")
        self.assertEqual(options["timeout"], 1320)

    def test_qualification_baseline_and_named_target_keep_existing_workflow(self):
        for case in ("windows-baseline", "windows-named-target"):
            with self.subTest(case=case):
                self.request = replace(self.request, output=self.root / case)
                result = self.execute_admitted(case)
                self.assertEqual(result["status"], "pass")
                call, options = self.run_call()
                self.assertEqual(call[call.index("--payload") + 1], str(proof.FIXTURE / "payload.json"))
                self.assertEqual(call[call.index("--timeout") + 1], "20m")
                self.assertEqual(options["timeout"], 1320)

    def test_recovery_cases_use_hold_and_never_pass_if_workload_returns(self):
        for case in ("windows-crash-recover", "windows-reboot-recover"):
            with self.subTest(case=case):
                self.request = replace(self.request, output=self.root / case)
                result = self.execute_admitted(case)
                call, options = self.run_call()
                self.assertEqual(call[call.index("--payload") + 1], str(proof.QUALIFICATION_HOLD_FIXTURE / "payload.json"))
                self.assertEqual(call[call.index("--timeout") + 1], "25m")
                self.assertEqual(options["timeout"], 1595)
                self.assertEqual(result["status"], "fail")
                self.assertEqual(result["outcomes"]["scenario"]["code"], "qualification-hold-returned")
                self.assertEqual(result["outcomes"]["cleanup"]["status"], "pass")

    def test_wrong_host_hash_refuses_before_setup_plan_or_transfer(self):
        result = self.execute_admitted("windows-crash-recover", expected_host="f" * 64)
        self.assertEqual(result["outcomes"]["preparation"]["code"], "host-artifact-mismatch")
        self.assertFalse(any(call[0] == "scp" or len(call) > 1 and call[1] in ("windows", "run")
                             for call in self.commands.calls))
        self.assertEqual(sum(call[:2] == ["go", "build"] for call in self.commands.calls), 2)

    def test_recovery_hold_preserves_enrolled_named_target_selection(self):
        result = self.execute_admitted("windows-crash-recover", variant="named-target")
        call, options = self.run_call()
        self.assertIn("--target-name", call)
        self.assertEqual(call[call.index("--payload") + 1], str(proof.QUALIFICATION_HOLD_FIXTURE / "payload.json"))
        self.assertEqual(options["timeout"], 1595)
        self.assertEqual(result["outcomes"]["scenario"]["code"], "qualification-hold-returned")

    def test_failed_consumption_or_unknown_case_makes_no_host_contact(self):
        for case, reject in (("windows-crash-recover", True), ("caller-custom-workload", False)):
            with self.subTest(case=case):
                self.request = replace(self.request, output=self.root / case)
                result = self.execute_admitted(case, reject=reject)
                self.assertEqual(result["status"], "fail")
                self.assertEqual(self.commands.calls, [])

    def test_subclass_cannot_supply_qualification_authority(self):
        class Impostor(worker.WindowsQualificationAdmission):
            pass

        result = self.execute_admitted("windows-crash-recover", admission_type=Impostor)
        self.assertEqual(result["outcomes"]["preparation"]["code"], "hosted-authorization-invalid")
        self.assertEqual(self.commands.calls, [])

    def test_local_driver_sha_does_not_select_hold(self):
        self.request = replace(self.request, driver_sha="b" * 40)
        self.assertEqual(self.execute()["status"], "pass")
        call, options = self.run_call()
        self.assertEqual(call[call.index("--payload") + 1], str(proof.FIXTURE / "payload.json"))
        self.assertEqual(options["timeout"], 1320)


class HoldFixtureTests(unittest.TestCase):
    def test_fixed_hold_timeout_fails_without_a_success_result(self):
        fixture = proof.QUALIFICATION_HOLD_FIXTURE
        payload = proof.document((fixture / "payload.json").read_bytes())
        self.assertEqual(payload["files"], [{"source": "scenario.py", "destination": "scenario.py"}])
        self.assertEqual(payload["scenario"]["read_timeout_seconds"], 1230)
        event = mock.Mock()
        bpy = SimpleNamespace(ops=mock.Mock(), context=SimpleNamespace(
            object=SimpleNamespace(), screen=SimpleNamespace(areas=[])))
        with mock.patch.dict(sys.modules, bpy=bpy), mock.patch("threading.Event", return_value=event) as create:
            with self.assertRaisesRegex(TimeoutError, "qualification-hold-timeout"):
                runpy.run_path(str(fixture / "scenario.py"))
        create.assert_called_once_with()
        event.wait.assert_called_once_with(1200)
        event.set.assert_not_called()
        self.assertEqual(bpy.context.object.name, "QualificationHoldCube")


class ActiveCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name).resolve()
        private = root / "baseline/private"
        self.job = SimpleNamespace(root=root, output=root / "baseline", config=private / "config",
                                   attempt_root=root / "attempts/0001", candidate_checkout=root,
                                   request=SimpleNamespace(execution_id="gha_123_1"), attempt=1,
                                   inputs_digest="a" * 64, expected_client_sha256=proof.digest(b"client"))
        for directory in (root / "baseline", private, self.job.config, self.job.config / "runs",
                          root / "inputs", root / "attempts", self.job.attempt_root):
            directory.mkdir(mode=0o700)
        self.record = dict(baseline_tests.run_record(), state="calling",
                           deadline=(datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat())
        claim = {key: self.record[key] for key in ("schema_version", "run_id", "request_id", "request_hash", "deadline")}
        claim.update(controller_id="test-controller", task_name="TestTask")
        self.claim = {"schema_version": 1, "claim": claim, "target_fingerprint": "b" * 64}
        self.pin = dict(self.claim, run_id=self.record["run_id"], session_id=self.record["session_id"])
        self.journal = self.job.config / "runs" / (self.record["run_id"] + ".json")
        self.pin_path = self.journal.with_suffix(".session.json")
        for path, content in ((private / "blender-box", b"client"), (private / "target.json", b"target"),
                              (root / "inputs/target.json", b"target"), (root / "inputs/ssh-config", b"Host test\n")):
            self.write(path, content)
        self.write(private / "run-journal.json", proof.canonical({"schema_version": 1, "run_id": self.record["run_id"]}))
        self.write(self.journal, proof.canonical(self.claim))
        self.write(self.pin_path, proof.canonical(self.pin))
        self.calls = []

    def write(self, path, raw):
        path.write_bytes(raw)
        path.chmod(0o600)

    def checkpoint(self, mutate=None, published=None):
        def factory(private, cwd):
            commands = proof.Commands(private, cwd)
            def status(args, **kwargs):
                self.calls.append((args, kwargs, commands.env.copy()))
                if mutate:
                    mutate()
                return self.record
            commands.json = status
            return commands

        def wait(path, predicate, timeout):
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 600)
            value = predicate()
            if value is None and published:
                published(path)
                value = predicate()
            if value is None:
                raise proof.ProofError("native-start-unconfirmed")
            return value

        with mock.patch.object(worker.native, "wait_file", wait), mock.patch.object(worker.model, "verify_worker_inputs"):
            return proof.active_qualification_checkpoint(self.job, factory)

    def test_checkpoint_uses_original_live_inputs_and_full_pinned_fence(self):
        result = self.checkpoint()
        self.assertEqual(result["claim_sha256"], proof.digest(self.journal.read_bytes()))
        self.assertEqual(result["session_pin_sha256"], proof.digest(self.pin_path.read_bytes()))
        self.assertEqual(result["session_id"], self.pin["session_id"])
        self.assertEqual(result["inputs_digest"], self.job.inputs_digest)
        args, _, env = self.calls[0]
        self.assertEqual(args[:2], [self.job.output / "private/blender-box", "status"])
        self.assertEqual(args[args.index("--target") + 1], self.job.output / "private/target.json")
        self.assertEqual(env["BLENDER_BOX_CONFIG_DIR"], str(self.job.config))

    def test_missing_pin_never_calls_status_or_reconstructs_pin(self):
        self.pin_path.rename(self.pin_path.with_suffix(".held"))
        with self.assertRaisesRegex(proof.ProofError, "native-start-unconfirmed"):
            self.checkpoint()
        self.assertEqual(self.calls, [])
        self.assertFalse(self.pin_path.exists())

    def test_marker_creation_waits_for_flushed_bytes(self):
        marker = self.job.output / "private/run-journal.json"
        raw = marker.read_bytes()
        self.write(marker, b"")
        def publish(path):
            self.assertEqual(path, marker)
            self.assertEqual(self.calls, [])
            self.write(marker, raw)
        result = self.checkpoint(published=publish)
        self.assertEqual(result["marker_sha256"], proof.digest(raw))

    def test_changed_client_never_calls_status(self):
        self.write(self.job.output / "private/blender-box", b"changed")
        with self.assertRaisesRegex(proof.ProofError, "client-artifact-mismatch"):
            self.checkpoint()
        self.assertEqual(self.calls, [])

    def test_root_cannot_invoke_candidate_checkpoint(self):
        with mock.patch.object(os, "geteuid", return_value=0):
            with self.assertRaisesRegex(proof.ProofError, "qualification-checkpoint-runner-required"):
                self.checkpoint()
        self.assertEqual(self.calls, [])

    def test_terminal_status_is_not_an_active_checkpoint(self):
        self.record["state"] = "complete"
        with self.assertRaisesRegex(proof.ProofError, "qualification-run-not-active"):
            self.checkpoint()

    def test_changed_session_is_not_an_active_checkpoint(self):
        self.record["session_id"] = "bss_" + "f" * 32
        with self.assertRaisesRegex(proof.ProofError, "qualification-run-not-active"):
            self.checkpoint()

    def test_insufficient_run_deadline_refuses_checkpoint(self):
        deadline = (datetime.now(timezone.utc) + timedelta(minutes=14)).isoformat()
        self.record["deadline"] = self.claim["claim"]["deadline"] = deadline
        self.write(self.journal, proof.canonical(self.claim))
        self.write(self.pin_path, proof.canonical(self.pin))
        with self.assertRaisesRegex(proof.ProofError, "qualification-checkpoint-deadline"):
            self.checkpoint()

    def test_pin_changed_during_status_refuses_checkpoint(self):
        with self.assertRaisesRegex(proof.ProofError, "qualification-checkpoint-authority-changed"):
            self.checkpoint(lambda: self.write(self.pin_path, proof.canonical(dict(self.pin, session_id="bss_" + "f" * 32))))


if __name__ == "__main__":
    unittest.main()
