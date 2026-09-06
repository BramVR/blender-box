import copy
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import test_onboarding_proof as baseline_tests

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("proof_controller", ROOT / "scripts/proof_controller.py")
controller = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = controller
spec.loader.exec_module(controller)
proof = controller.proof
SHA = "a" * 40
DRIVER = "b" * 40
NOW = datetime(2026, 9, 6, 17, 0, tzinfo=timezone.utc)


def request(execution_id="gha_123_1", **changes):
    value = {"schema_version": 1, "repository": "BramVR/blender-box", "candidate_sha": SHA,
             "driver_sha": DRIVER, "variant": "baseline", "execution_id": execution_id,
             "expires_at": "2026-09-06T18:00:00Z", **changes}
    return controller.ProofExecutionRequest.parse(value)


def command(operation="start", execution_id="gha_123_1", **changes):
    value = {"schema_version": 1, "operation": operation}
    value.update(request=asdict(request(execution_id, **changes))) if operation == "start" else value.update(execution_id=execution_id)
    return controller.parse_command(proof.canonical(value))


def private_file(path, content):
    path.write_bytes(content)
    path.chmod(0o600)


class Crash(BaseException):
    pass


class FakeService:
    def __init__(self, control):
        self.control = control
        self.boot = "1" * 32
        self.invocation = None
        self.empty = True
        self.starts, self.releases, self.stops = [], [], []
        self.before_stop = None
        self.pending = None
        self.completed = {}

    def observe(self):
        return controller.ServiceObservation(self.boot, self.invocation, self.empty)

    def start(self, accepted, attempt):
        control = self.control / accepted.execution_id
        intent = json.loads((control / f"intent-{attempt:04d}.json").read_bytes())
        state = json.loads((control / "execution.json").read_bytes())
        assert intent["request_digest"] == accepted.digest
        assert state["phase"] == "starting" and state["invocation"] is None
        assert not (control / f"authorization-{attempt:04d}.json").exists()
        self.starts.append((accepted, attempt))
        self.invocation = controller.Invocation(self.boot, f"{len(self.starts):032x}", "/fixture/proof", 123,
                                                100 + len(self.starts), 12, accepted.execution_id, attempt, accepted.digest)
        self.empty = False
        return self.invocation

    def release(self, invocation, authorization_path, job, mode, retained):
        authorization = json.loads(authorization_path.read_bytes())
        state = json.loads((authorization_path.parent / "execution.json").read_bytes())
        assert authorization["invocation"] == state["invocation"] == asdict(invocation)
        assert invocation == self.invocation
        self.releases.append(invocation)
        self.pending = (invocation, job, mode, retained)
        return True

    def complete(self, worker):
        invocation, job, mode, retained = self.pending
        self.pending = None
        with (self.control / "fixture.lock").open("rb") as lock:
            controller.fcntl.flock(lock, controller.fcntl.LOCK_EX | controller.fcntl.LOCK_NB)
            controller.fcntl.flock(lock, controller.fcntl.LOCK_UN)
        try:
            result = worker.baseline(job) if mode == "baseline" else worker.recover(job, retained)
            self.completed[invocation.invocation_id] = {"schema_version": 1, "invocation": asdict(invocation),
                                                       "mode": mode, "result": result}
        finally:
            self.empty = True

    def result(self, invocation):
        return self.completed.get(invocation.invocation_id)

    def stop_exact(self, expected):
        if self.before_stop is not None:
            self.before_stop(self)
        if expected != self.invocation:
            return False
        self.stops.append(expected)
        self.empty = True
        return True


class FakeCommands(baseline_tests.FakeCommands):
    def __init__(self, private, cwd, factory):
        super().__init__(private, cwd, factory.config, factory.fault if not factory.instances else None)
        self.factory = factory
        self.record = copy.deepcopy(factory.record)
        factory.instances.append(self)

    def run(self, args, **kwargs):
        self.sequence += 1
        private_file(self.private / f"command-{self.sequence:03d}.stdout", b"PRIVATE_LOG_SENTINEL")
        operation = str(args[1]) if len(args) > 1 else ""
        if operation in ("status", "stop") and self.fault is None:
            self.record = copy.deepcopy(self.factory.record)
        try:
            return super().run(args, **kwargs)
        finally:
            if operation == "run" and self.run_id:
                self.factory.record = copy.deepcopy(self.record)
                if self.factory.journals:
                    config = Path(self.env["BLENDER_BOX_CONFIG_DIR"])
                    config.mkdir(mode=0o700)
                    (config / "runs").mkdir(mode=0o700)
                    private_file(config / "runs" / (self.run_id + ".json"), b'{"schema_version":1,"test":"original-authority"}')
                if self.factory.worker_loss:
                    self.group_cleanup_known = False
                    raise Crash()


class CommandFactory:
    def __init__(self, config, fault=None, journals=True):
        self.config, self.fault, self.journals = config, fault, journals
        self.record = None
        self.instances = []
        self.worker_loss = False

    def __call__(self, private, cwd):
        return FakeCommands(private, cwd, self)


class WireAndCLITests(unittest.TestCase):
    def invoke(self, *args, raw=None):
        return subprocess.run([sys.executable, str(ROOT / "scripts/proof_controller.py"), *args],
                              input=raw, capture_output=True, timeout=10, check=False)

    def test_request_exact_keys_bounds_and_duplicates(self):
        valid = proof.canonical({"schema_version": 1, "operation": "start", "request": asdict(request())})
        self.assertEqual(controller.parse_command(valid).request, request())
        invalid = [b"x" * (controller.MAX_WIRE + 1), b"[]", valid.replace(b'"operation":', b'"extra":0,"operation":'),
                   valid.replace(b'"operation":', b'"operation":"stop","operation":'),
                   valid.replace(b'"schema_version":1', b'"schema_version":true'),
                   valid.replace(b'gha_123_1', b'../private'), valid.replace(b'baseline', b'arbitrary'),
                   b'{"schema_version":1,"nested":' + b'[' * 1500 + b']' * 1500 + b'}']
        for raw in invalid:
            with self.subTest(raw=raw[:90]), self.assertRaises(controller.ControllerError):
                controller.parse_command(raw)
        self.assertEqual(command("status").operation, "status")
        self.assertEqual(request(variant="named-target").variant, "named-target")

    def test_dispatch_never_reflects_input_or_starts_anything(self):
        valid = proof.canonical({"schema_version": 1, "operation": "start", "request": asdict(request())})
        result = self.invoke("dispatch", raw=valid)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout), {"schema_version": 1, "status": "error", "code": "native-adapter-unqualified"})
        self.assertEqual(result.stderr, b"")
        rejected = self.invoke("dispatch", raw=b'{"schema_version":1,"operation":"PRIVATE_KEY_SENTINEL"}')
        self.assertEqual(rejected.returncode, 1)
        self.assertNotIn(b"PRIVATE_KEY_SENTINEL", rejected.stdout + rejected.stderr)
        nested = self.invoke("dispatch", raw=b'{"schema_version":1,"nested":' + b'[' * 1500 + b']' * 1500 + b'}')
        self.assertEqual(nested.returncode, 1)
        self.assertEqual(nested.stderr, b"")

    def test_preview_deterministic_and_no_apply_or_fake_switch(self):
        first, second = self.invoke("bootstrap"), self.invoke("bootstrap")
        self.assertEqual(first.returncode, 0)
        self.assertEqual(first.stdout, second.stdout)
        preview = json.loads(first.stdout)
        self.assertFalse(preview["installable"])
        self.assertEqual(preview["status"], "unqualified")
        self.assertIn("native-helper-and-worker", preview["unknown_qualification"])
        self.assertIn("ExecStart=/usr/bin/false", preview["proposed_files"][0]["content"])
        for extra in ("--apply", "--fake", "--local"):
            self.assertNotEqual(self.invoke("bootstrap", extra).returncode, 0)
        self.assertEqual(self.invoke("--help").returncode, 0)

    @unittest.skipUnless(controller.fcntl is not None, "POSIX durable publication")
    def test_preview_fresh_output_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "proposal"
            result = self.invoke("bootstrap", "--output", str(path))
            self.assertEqual(result.returncode, 0, result.stderr)
            preview = json.loads(result.stdout)
            for file in preview["proposed_files"]:
                self.assertEqual((path / file["path"]).read_text(), file["content"])
                self.assertEqual((path / file["path"]).stat().st_mode & 0o777, 0o600)
            again = self.invoke("bootstrap", "--output", str(path))
            self.assertEqual(again.returncode, 1)
            self.assertEqual(len(list(path.iterdir())), 3)


@unittest.skipUnless(controller.fcntl is not None, "POSIX flock, nofollow and directory fsync")
class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.control, self.jobs = self.root / "control", self.root / "jobs"
        self.control.mkdir(mode=0o700)
        self.jobs.mkdir(mode=0o700)
        self.checkout = self.root / "checkout"
        self.checkout.mkdir(mode=0o700)
        self.config = baseline_tests.operator_config()
        self.operator = self.root / "operator.json"
        key, trust, ssh = self.root / "dedicated-key", self.root / "known_hosts", self.root / "ssh-config"
        private_file(key, b"PRIVATE_KEY_SENTINEL")
        private_file(trust, b"PRIVATE_TRUST_SENTINEL")
        private_file(ssh, (f'Host test-fixture\nHostName test.invalid\nUser test-user\nPort 22\n'
                           f'IdentityFile "{key}"\nUserKnownHostsFile "{trust}"\n').encode())
        self.config["ssh_config"] = str(ssh)
        private_file(self.operator, proof.canonical(self.config))
        self.policy = controller.Policy(SHA, DRIVER, self.checkout, self.operator, proof.digest(b"client"))
        self.service = FakeService(self.control)
        self.factory = CommandFactory(self.config)
        self.worker = controller.ProofWorker(self.factory, clock=lambda: NOW)
        self.env = mock.patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "1"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def reopen(self, clock=None):
        return controller.Controller(self.control, self.jobs, self.policy, self.service, self.worker, clock or (lambda: NOW))

    def state(self):
        return json.loads((self.control / "gha_123_1/execution.json").read_bytes())

    def fail_baseline(self):
        self.factory.fault = "cleanup-failed"
        result = self.baseline()
        self.assertEqual(result["proof_result"], "fail")
        self.assertEqual(result["windows_cleanup"], "unknown")
        self.assertEqual(result["phase"], "unresolved")
        return result

    def baseline(self):
        running = self.reopen().dispatch(command())
        self.assertEqual(running["phase"], "running")
        self.assertFalse(self.factory.instances)
        self.assertEqual(self.reopen().dispatch(command("status")), running)
        self.service.complete(self.worker)
        return self.reopen().dispatch(command("status"))

    def test_actual_baseline_hosted_private_retention_and_projection(self):
        result = self.baseline()
        self.assertEqual(result["phase"], "settled")
        self.assertEqual(result["proof_result"], "pass")
        self.assertEqual(result["local_termination"], "proven")
        self.assertEqual(result["windows_cleanup"], "proven")
        self.assertEqual(len(self.service.starts), 1)
        self.assertEqual(self.factory.instances[0].env["BLENDER_BOX_CONFIG_DIR"], str(self.jobs / "gha_123_1/baseline/private/config"))
        original = json.loads((self.jobs / "gha_123_1/baseline/public/outcome.json").read_bytes())
        self.assertEqual(original["execution"], "hosted")
        self.assertEqual(original["driver_sha"], DRIVER)
        public = proof.canonical(result)
        self.assertEqual(set(result), {"schema_version", *controller.PUBLIC_FIELDS})
        for planted in ("PRIVATE_KEY_SENTINEL", "PRIVATE_TRUST_SENTINEL", "PRIVATE_LOG_SENTINEL", "TEST-HOST", str(self.root)):
            self.assertNotIn(planted.encode(), public)
        self.assertEqual(self.reopen().dispatch(command("status")), result)

    def test_duplicate_conflict_closed_and_expired_do_not_relaunch(self):
        first = self.baseline()
        late = self.reopen(lambda: NOW + timedelta(days=1))
        self.assertEqual(late.dispatch(command()), first)
        self.assertEqual(late.dispatch(command("stop")), first)
        with self.assertRaisesRegex(controller.ControllerError, "execution-conflict"):
            late.dispatch(command(candidate_sha="c" * 40))
        with self.assertRaisesRegex(controller.ControllerError, "execution-expired"):
            late.dispatch(command(execution_id="other"))
        self.assertEqual(len(self.service.starts), 1)

    def test_guard_and_unknown_variant_before_service_and_proof(self):
        with mock.patch.object(self.service, "observe") as observe:
            with mock.patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "2"}):
                with self.assertRaisesRegex(controller.ControllerError, "hosted-authorization-invalid"):
                    self.reopen().dispatch(command())
            with self.assertRaisesRegex(controller.ControllerError, "variant-driver-unavailable"):
                self.reopen().dispatch(command(variant="named-target"))
            with self.assertRaisesRegex(controller.ControllerError, "request-not-authorized"):
                self.reopen().dispatch(command(driver_sha="c" * 40))
            self.policy = replace(self.policy, expected_client_sha256=None)
            with self.assertRaisesRegex(controller.ControllerError, "client-artifact-unavailable"):
                self.reopen().dispatch(command())
            observe.assert_not_called()
        self.assertFalse(self.service.starts or self.factory.instances)

    def test_wrong_built_client_never_runs_scenario_or_setup(self):
        self.policy = replace(self.policy, expected_client_sha256="f" * 64)
        result = self.baseline()
        self.assertEqual(result["proof_result"], "fail")
        self.assertFalse(any(call[1] in ("windows", "run") for call in self.factory.instances[0].calls))

    def test_worker_loss_after_run_marker_recovers_from_original_authority(self):
        self.reopen().dispatch(command())
        self.factory.worker_loss = True
        with self.assertRaises(Crash):
            self.service.complete(self.worker)
        interrupted = self.reopen().dispatch(command("status"))
        self.assertEqual(interrupted["proof_result"], "fail")
        self.assertIsNone(self.state()["recovery_inputs"])
        self.factory.record["state"] = "failed"
        self.factory.record["cleanup"] = {key: True for key in proof.CLEANUP}
        self.reopen().dispatch(command("recover"))
        self.service.complete(self.worker)
        result = self.reopen().dispatch(command("status"))
        self.assertEqual(result["phase"], "settled")
        self.assertEqual(result["proof_result"], "fail")
        self.assertEqual(result["attempt"], 2)
        self.assertEqual([call[1] for call in self.factory.instances[1].calls], ["status", "stop", "status"])
        self.assertEqual(sum(call[1] == "run" for commands in self.factory.instances for call in commands.calls), 1)

    def test_corrupt_settled_state_cannot_release_fixture(self):
        self.baseline()
        path = self.control / "gha_123_1/execution.json"
        original = path.read_bytes()
        for change in ({"closed": False}, {"local_termination": "unknown"}, {"windows_cleanup": "unknown"},
                       {"candidate_checkout": "relative"}, {"invocation": None}, {"proof_result": "not-run"}):
            with self.subTest(change=change):
                private_file(path, proof.canonical(dict(json.loads(original), **change)))
                with self.assertRaisesRegex(controller.ControllerError, "execution-state-unavailable"):
                    self.reopen().dispatch(command(execution_id="next"))
                self.assertEqual(len(self.service.starts), 1)
        private_file(path, original)

    def test_completed_report_with_live_service_does_not_release_fixture(self):
        self.reopen().dispatch(command())
        self.service.complete(self.worker)
        self.service.empty = False
        observed = self.reopen().dispatch(command("status"))
        self.assertEqual(observed["local_termination"], "unknown")
        with self.assertRaisesRegex(controller.ControllerError, "fixture-unresolved"):
            self.reopen().dispatch(command(execution_id="next"))
        self.assertEqual(len(self.service.starts), 1)

    def test_delayed_worker_cannot_launch_expired_scenario(self):
        self.reopen().dispatch(command())
        self.worker.clock = lambda: NOW + timedelta(days=1)
        with self.assertRaisesRegex(controller.ControllerError, "execution-expired"):
            self.service.complete(self.worker)
        self.assertFalse(self.factory.instances)

    def test_expiry_during_preparation_blocks_public_run(self):
        original = FakeCommands.run

        def expire_after_check(commands, args, **kwargs):
            result = original(commands, args, **kwargs)
            if [str(value) for value in args[1:3]] == ["windows", "check"]:
                self.worker.clock = lambda: NOW + timedelta(days=1)
            return result

        with mock.patch.object(FakeCommands, "run", expire_after_check):
            result = self.baseline()
        self.assertEqual(result["proof_result"], "fail")
        calls = self.factory.instances[0].calls
        self.assertTrue(any(call[1:3] == ["windows", "check"] for call in calls))
        self.assertFalse(any(call[1] == "run" for call in calls))

    def test_crash_boundaries_keep_admission_and_never_repeat_start(self):
        for boundary in ("intent", "identity", "authorization"):
            with self.subTest(boundary=boundary):
                execution_id = "crash_" + boundary
                original = controller.publish
                def crash(path, content, **kwargs):
                    value = json.loads(content) if path.suffix == ".json" else {}
                    hit = ((boundary == "intent" and path.name.startswith("intent-"))
                           or (boundary == "identity" and path.name == "execution.json" and value.get("invocation"))
                           or (boundary == "authorization" and path.name.startswith("authorization-")))
                    if hit:
                        raise Crash()
                    return original(path, content, **kwargs)
                with mock.patch.object(controller, "publish", side_effect=crash), self.assertRaises(Crash):
                    self.reopen().dispatch(command(execution_id=execution_id))
                starts = len(self.service.starts)
                observed = self.reopen().dispatch(command(execution_id=execution_id))
                self.assertIn(observed["phase"], ("starting", "running"))
                with self.assertRaises(controller.ControllerError):
                    self.reopen().dispatch(command(execution_id="new_" + boundary))
                self.assertEqual(len(self.service.starts), starts)
                self.assertFalse(self.service.releases or self.factory.instances)
                self.control = self.root / ("control_" + boundary)
                self.jobs = self.root / ("jobs_" + boundary)
                self.control.mkdir(mode=0o700)
                self.jobs.mkdir(mode=0o700)
                self.service = FakeService(self.control)

    def test_missing_state_blocks_admission(self):
        self.fail_baseline()
        (self.control / "gha_123_1/execution.json").unlink()
        with self.assertRaises(controller.ControllerError):
            self.reopen().dispatch(command(execution_id="new"))
        self.assertEqual(len(self.service.starts), 1)

    def test_fresh_recovery_logs_original_config_and_failure_preserved(self):
        self.fail_baseline()
        original_logs = {file.name: file.read_bytes() for file in (self.jobs / "gha_123_1/baseline/private").glob("command-*.stdout")}
        self.factory.record["state"] = "failed"
        self.factory.record["cleanup"] = {key: True for key in proof.CLEANUP}
        running = self.reopen(lambda: NOW + timedelta(days=1)).dispatch(command("recover"))
        self.assertEqual(running["phase"], "recovering")
        self.assertEqual(self.reopen().dispatch(command("recover")), running)
        self.assertEqual(len(self.service.starts), 2)
        self.service.complete(self.worker)
        result = self.reopen().dispatch(command("status"))
        self.assertEqual(result["phase"], "settled")
        self.assertEqual(result["proof_result"], "fail")
        self.assertEqual(result["windows_cleanup"], "proven")
        self.assertEqual(result["attempt"], 2)
        fresh = self.factory.instances[1]
        self.assertEqual([call[1] for call in fresh.calls], ["status", "stop", "status"])
        self.assertEqual(fresh.private, self.jobs / "gha_123_1/attempts/0002/commands")
        self.assertEqual(fresh.env["BLENDER_BOX_CONFIG_DIR"], self.factory.instances[0].env["BLENDER_BOX_CONFIG_DIR"])
        self.assertEqual(len(list(fresh.private.glob("command-*.stdout"))), 3)
        for name, content in original_logs.items():
            self.assertEqual((self.jobs / "gha_123_1/baseline/private" / name).read_bytes(), content)

    def test_changed_retained_trust_blocks_recovery_before_proof(self):
        self.fail_baseline()
        private_file(self.jobs / "gha_123_1/inputs/known_hosts", b"REPLACED")
        calls = len(self.factory.instances)
        with self.assertRaisesRegex(controller.ControllerError, "original-inputs-unavailable"):
            self.reopen().dispatch(command("recover"))
        self.assertEqual(len(self.factory.instances), calls)
        self.assertEqual(len(self.service.starts), 1)

    def test_reconciliation_cannot_adopt_replacement_run_locator(self):
        self.fail_baseline()
        retained = copy.deepcopy(self.state()["recovery_inputs"])
        replacement = "bbx_" + "f" * 32
        private = self.jobs / "gha_123_1/baseline/private"
        private_file(private / "run-journal.json", proof.canonical({"schema_version": 1, "run_id": replacement}))
        private_file(private / "config/runs" / (replacement + ".json"), b'{"schema_version":1,"test":"replacement"}')
        for operation in ("status", "recover"):
            with self.subTest(operation=operation), self.assertRaisesRegex(controller.ControllerError, "recovery-inputs-changed"):
                self.reopen().dispatch(command(operation))
            self.assertEqual(self.state()["recovery_inputs"], retained)
        self.assertEqual(len(self.factory.instances), 1)
        self.assertEqual(len(self.service.starts), 1)

    def test_first_reconciliation_binds_locator_to_completed_baseline_run(self):
        self.factory.fault = "cleanup-failed"
        self.reopen().dispatch(command())
        self.service.complete(self.worker)
        self.assertIsNone(self.state()["recovery_inputs"])
        replacement = "bbx_" + "f" * 32
        private = self.jobs / "gha_123_1/baseline/private"
        private_file(private / "run-journal.json", proof.canonical({"schema_version": 1, "run_id": replacement}))
        private_file(private / "config/runs" / (replacement + ".json"), b'{"schema_version":1,"test":"replacement"}')
        for operation in ("status", "recover"):
            with self.subTest(operation=operation), self.assertRaisesRegex(controller.ControllerError, "recovery-identity-changed"):
                self.reopen().dispatch(command(operation))
            self.assertIsNone(self.state()["recovery_inputs"])
        self.assertEqual(len(self.factory.instances), 1)
        self.assertEqual(len(self.service.starts), 1)

    def test_completed_baseline_cannot_adopt_locator_through_recovery_fallback(self):
        self.factory.fault = "cleanup-failed"
        self.reopen().dispatch(command())
        self.service.complete(self.worker)
        with mock.patch.object(self.worker, "recovery_inputs", side_effect=OSError("temporarily-unavailable")) as read:
            with self.assertRaisesRegex(controller.ControllerError, "retained-recovery-unavailable"):
                self.reopen().dispatch(command("recover"))
        self.assertEqual(read.call_count, 1)
        self.assertIsNone(self.state()["recovery_inputs"])
        self.assertEqual(len(self.service.starts), 1)

    def test_damaged_key_does_not_block_exact_local_stop(self):
        self.reopen().dispatch(command())
        expected = self.service.invocation
        private_file(self.jobs / "gha_123_1/inputs/key", b"DAMAGED")
        with self.assertRaisesRegex(controller.ControllerError, "original-inputs-unavailable"):
            self.reopen().dispatch(command("stop"))
        self.assertEqual(self.service.stops, [expected])
        self.assertEqual(self.state()["local_termination"], "proven")
        self.assertEqual(self.state()["windows_cleanup"], "unknown")
        self.assertEqual(self.state()["phase"], "unresolved")
        self.assertTrue(self.state()["closed"])
        self.assertFalse(self.factory.instances)

    def test_missing_manifest_does_not_block_exact_local_termination_for_recovery(self):
        self.reopen().dispatch(command())
        expected = self.service.invocation
        (self.control / "gha_123_1/inputs.json").unlink()
        with self.assertRaisesRegex(controller.ControllerError, "original-inputs-unavailable"):
            self.reopen().dispatch(command("recover"))
        self.assertEqual(self.service.stops, [expected])
        self.assertEqual(self.state()["local_termination"], "proven")
        self.assertEqual(self.state()["windows_cleanup"], "unknown")
        self.assertTrue(self.state()["closed"])
        self.assertFalse(self.factory.instances)

    def test_later_result_from_same_invocation_cannot_promote_failure(self):
        self.fail_baseline()
        completed = self.service.completed[self.service.invocation.invocation_id]
        completed["result"]["status"] = "pass"
        completed["result"]["cleanup"] = {key: True for key in proof.CLEANUP}
        result = self.reopen().dispatch(command("status"))
        self.assertEqual(result["proof_result"], "fail")
        self.assertEqual(result["windows_cleanup"], "proven")
        self.assertEqual(result["phase"], "settled")
        self.assertEqual(len(self.service.starts), 1)

    def test_changed_trust_after_release_blocks_delayed_worker(self):
        self.reopen().dispatch(command())
        private_file(self.jobs / "gha_123_1/inputs/key", b"REPLACED")
        with self.assertRaisesRegex(controller.ControllerError, "original-inputs-unavailable"):
            self.service.complete(self.worker)
        self.assertFalse(self.factory.instances)

    def test_live_operator_changes_do_not_redirect_recovery(self):
        self.fail_baseline()
        private_file(self.operator, b"changed")
        private_file(self.root / "known_hosts", b"changed")
        self.factory.record["state"] = "failed"
        self.factory.record["cleanup"] = {key: True for key in proof.CLEANUP}
        self.reopen().dispatch(command("stop"))
        self.service.complete(self.worker)
        self.assertEqual(self.reopen().dispatch(command("status"))["windows_cleanup"], "proven")

    def test_missing_journal_or_locator_and_client_change_make_zero_calls(self):
        self.fail_baseline()
        for name in ("run-journal.json", "blender-box", "config/runs/" + baseline_tests.RUN + ".json"):
            with self.subTest(name=name):
                path = self.jobs / "gha_123_1/baseline/private" / name
                content = path.read_bytes()
                path.unlink()
                with self.assertRaises((controller.ControllerError, OSError)):
                    self.reopen().dispatch(command("recover"))
                self.assertEqual(len(self.factory.instances), 1)
                private_file(path, content)
        private_file(self.jobs / "gha_123_1/baseline/private/blender-box", b"replacement")
        with self.assertRaisesRegex(controller.ControllerError, "client-artifact-mismatch"):
            self.reopen().dispatch(command("recover"))
        self.assertEqual(len(self.factory.instances), 1)

    def test_stale_same_boot_and_stop_race_send_zero_signals(self):
        self.fail_baseline()
        expected = self.service.invocation
        self.service.invocation = replace(expected, invocation_id="e" * 32)
        stops = len(self.service.stops)
        with self.assertRaisesRegex(controller.ControllerError, "service-identity-changed"):
            self.reopen().dispatch(command("stop"))
        self.assertEqual(len(self.service.stops), stops)
        self.service.invocation = expected
        self.service.empty = False
        self.service.before_stop = lambda service: setattr(service, "invocation", replace(expected, leader_start_ticks=999))
        with self.assertRaisesRegex(controller.ControllerError, "local-termination-unknown"):
            self.reopen().dispatch(command("stop"))
        self.assertEqual(len(self.service.stops), stops)

    def test_reboot_never_signals_recycled_pid(self):
        self.fail_baseline()
        self.service.boot = "2" * 32
        self.service.invocation = replace(self.service.invocation, boot_id=self.service.boot)
        self.service.empty = False
        stops = len(self.service.stops)
        with self.assertRaisesRegex(controller.ControllerError, "fixture-unresolved"):
            self.reopen().dispatch(command("recover"))
        self.assertEqual(len(self.service.stops), stops)

    def test_absent_product_journal_never_becomes_cleanup_authority(self):
        self.factory.journals = False
        self.fail_baseline()
        with self.assertRaisesRegex(controller.ControllerError, "retained-recovery-unavailable"):
            self.reopen().dispatch(command("recover"))
        self.assertEqual(len(self.factory.instances), 1)

    def test_input_mode_symlink_and_include_rejected_without_launch(self):
        content = (self.root / "ssh-config").read_bytes()
        for index, bad in enumerate((b'Include other\n', b'ProxyCommand private-command\n')):
            with self.subTest(bad=bad):
                control, jobs = self.root / f"control-invalid-{index}", self.root / f"jobs-invalid-{index}"
                control.mkdir(mode=0o700)
                jobs.mkdir(mode=0o700)
                service = FakeService(control)
                instance = controller.Controller(control, jobs, self.policy, service, self.worker, lambda: NOW)
                private_file(self.root / "ssh-config", content + bad)
                with self.assertRaisesRegex(controller.ControllerError, "ssh-config-not-self-contained"):
                    instance.dispatch(command())
                self.assertFalse(service.starts)
        path = self.root / "unsafe"
        path.symlink_to(self.operator)
        with self.assertRaises(controller.ControllerError):
            controller.read_private(path)
        self.operator.chmod(0o644)
        with self.assertRaisesRegex(controller.ControllerError, "private-file-invalid"):
            controller.read_private(self.operator)

    def test_exclusive_publication_and_fsync_failure_leave_admission_closed(self):
        path = self.control / "value"
        controller.publish(path, b"original")
        with self.assertRaises(FileExistsError):
            controller.publish(path, b"replacement")
        self.assertEqual(path.read_bytes(), b"original")
        path.unlink()
        with mock.patch.object(controller, "sync_directory", side_effect=OSError("fsync-unavailable")):
            with self.assertRaises(OSError):
                self.reopen().dispatch(command())
        with self.assertRaises(controller.ControllerError):
            self.reopen().dispatch(command(execution_id="other"))
        self.assertFalse(self.service.starts)


if __name__ == "__main__":
    unittest.main()
