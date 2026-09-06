from contextlib import redirect_stdout
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import socket
from types import SimpleNamespace
import unittest
from unittest import mock

import test_proof_controller as base
import test_proof_controller_native as fixtures

model, native, protocol, store = fixtures.model, fixtures.native, fixtures.worker, fixtures.store


class PublicAdoptionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.NativeLifecycleTests("run")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.case = self.fixture.fixture
        self.files = self.fixture.files
        self.ops = self.fixture.ops
        self.req = base.request(expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        value = fixtures.policy().value | {"expected_client_sha256": self.case.policy.expected_client_sha256}
        self.policy = native.NativePolicy.parse(model.proof.canonical(value))
        self.starts, self.releases, self.stops = 0, 0, 0
        self.crash = "identity"
        self.root = self.case.control / self.req.execution_id
        original_publish = self.files.publish
        def publish(path, content, **kwargs):
            if ((self.crash == "identity" and path.name == "execution.json" and model.document(content).get("invocation"))
                    or (self.crash == "issuer" and path.name == "start-command-0001.json")):
                self.crash = None
                raise base.Crash()
            return original_publish(path, content, **kwargs)
        self.files.publish = publish
        self.ops.systemctl.side_effect = self.start
        self.ops.stop.side_effect = self.stop
        self.ops.exchange.side_effect = self.release
        self.ops.process.side_effect = self.process
        patch = mock.patch.multiple(native, CONFIG=self.case.root)
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(native, "load_runtime", side_effect=self.load_runtime)
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(native, "LinuxOps", return_value=self.ops)
        patch.start()
        self.addCleanup(patch.stop)

    def load_runtime(self):
        self.policy.qualify(model.proof.canonical({"schema_version": 1, "qualified": True,
            "policy_sha256": self.policy.digest, "evidence": {key: "a" * 64 for key in native.QUALIFICATIONS}}))
        return self.policy, self.files

    def start(self, operation):
        self.assertEqual(operation, "start")
        self.starts += 1
        pending = native.parse_intent(self.files.read(self.fixture.runtime / "pending.json"))
        info = self.fixture.group.stat()
        inv = replace(fixtures.invocation(), request_digest=self.req.digest, attempt=pending["attempt"])
        self.receipt = native.NativeReceipt(inv, 3000, info.st_dev, info.st_ino)
        self.files.publish(native.receipt_path(inv), model.proof.canonical(asdict(self.receipt)))
        self.fixture.empty = False

    def process(self, pid):
        if pid == 300:
            return native.Process(300, 1, 3000, native.UNIT_CGROUP)
        return native.Process(301, 300, 4001, self.receipt.invocation.cgroup)

    def stop(self, receipt):
        self.assertEqual(receipt, self.receipt)
        saved = model.document(self.files.read(self.root / "execution.json"))
        self.assertEqual(saved["invocation"], asdict(receipt.invocation))
        self.assertTrue(saved["closed"])
        self.assertEqual(saved["phase"], "unresolved")
        self.stops += 1
        self.fixture.empty = True
        return True

    def release(self, *args):
        self.releases += 1
        raise AssertionError("adoption must not release")

    def dispatch(self, operation):
        wire = {"schema_version": 1, "operation": operation}
        wire.update(request=asdict(self.req)) if operation == "start" else wire.update(execution_id=self.req.execution_id)
        output = io.StringIO()
        with mock.patch("sys.stdin", SimpleNamespace(buffer=io.BytesIO(model.proof.canonical(wire)))), redirect_stdout(output):
            code = native.entrypoint(["dispatch"])
        return code, json.loads(output.getvalue())

    def stranded(self):
        with self.assertRaises(base.Crash):
            self.dispatch("start")
        self.original = self.files.read(native.receipt_path(self.receipt.invocation))
        self.assertIsNone(model.document(self.files.read(self.root / "execution.json"))["invocation"])

    def test_public_live_adoption_then_exact_stop_and_idempotent_status(self):
        self.stranded()
        code, first = self.dispatch("status")
        self.assertEqual((code, first["phase"], first["local_termination"]), (0, "unresolved", "unknown"))
        self.assertEqual(self.dispatch("status"), (0, first))
        code, final = self.dispatch("stop")
        self.assertEqual((code, final["phase"], final["proof_result"]), (0, "settled", "fail"))
        self.assertEqual(self.dispatch("recover"), (0, final))
        self.assertEqual((self.starts, self.releases, self.stops), (1, 0, 1))
        self.assertEqual(self.files.read(native.receipt_path(self.receipt.invocation)), self.original)

    def test_native_receipt_without_issuer_and_gone_or_reboot_adopts(self):
        self.crash = "issuer"
        self.stranded()
        self.assertFalse((self.root / "start-command-0001.json").exists())
        self.fixture.empty = True
        self.ops.boot.return_value = "f" * 32
        self.ops.process.side_effect = AssertionError("old boot PID must not be read")
        code, result = self.dispatch("status")
        self.assertEqual((code, result["phase"], result["windows_cleanup"]), (0, "settled", "proven"))
        self.assertEqual(self.stops, 0)

    def test_same_boot_gone_receipt_settles_without_signalling(self):
        self.stranded()
        self.fixture.empty = True
        self.assertEqual(self.dispatch("recover")[1]["phase"], "settled")
        self.assertEqual((self.stops, self.releases), (0, 0))

    def test_crash_after_adoption_save_rechecks_then_converges(self):
        self.stranded()
        self.fixture.empty = True
        original = self.files.publish
        fired = False
        def crash(path, content, **kwargs):
            nonlocal fired
            original(path, content, **kwargs)
            if not fired and path.name == "execution.json" and model.document(content)["phase"] == "unresolved":
                fired = True
                raise base.Crash()
        self.files.publish = crash
        with self.assertRaises(base.Crash):
            self.dispatch("status")
        self.assertEqual(self.dispatch("status")[1]["phase"], "settled")
        self.assertEqual((self.starts, self.stops, self.releases), (1, 0, 0))

    def test_conflicting_publication_prefix_refuses_without_adopting(self):
        self.stranded()
        for kind in ("authorization", "result", "unreleased", "startup-failure"):
            path = self.root / (kind + "-0001.json")
            self.files.publish(path, b'{"schema_version":1}')
            code, result = self.dispatch("stop")
            self.assertEqual((code, result["status"]), (1, "error"))
            self.assertIsNone(model.document(self.files.read(self.root / "execution.json"))["invocation"])
            path.unlink()
        self.assertEqual((self.stops, self.releases), (0, 0))

    def test_replacement_pending_worker_cgroup_and_queued_job_refuse(self):
        self.stranded()
        pending = self.fixture.runtime / "pending.json"
        original = self.files.read(pending)
        self.files.publish(pending, model.proof.canonical(dict(model.document(original), attempt=2)), exclusive=False)
        self.assertEqual(self.dispatch("stop")[0], 1)
        self.files.publish(pending, original, exclusive=False)
        self.ops.process.side_effect = lambda pid: replace(self.process(pid), start=9999) if pid == 301 else self.process(pid)
        self.assertEqual(self.dispatch("stop")[0], 1)
        self.ops.process.side_effect = self.process
        self.ops.unit.side_effect = lambda: native.UnitState("active", 300, "2" * 32, native.UNIT_CGROUP, 42)
        self.assertEqual(self.dispatch("stop")[0], 1)
        self.ops.unit.side_effect = lambda: native.UnitState("active", 300, "2" * 32, native.UNIT_CGROUP)
        wrong = replace(self.receipt, cgroup_inode=self.receipt.cgroup_inode + 1)
        self.files.publish(native.receipt_path(self.receipt.invocation), model.proof.canonical(asdict(wrong)), exclusive=False)
        self.assertEqual(self.dispatch("stop")[0], 1)
        self.assertEqual((self.stops, self.releases), (0, 0))


class ProtectedProofTests(unittest.TestCase):
    setUp = base.ControllerTests.setUp
    reopen = base.ControllerTests.reopen
    state = base.ControllerTests.state

    def test_named_target_selected_policy_runs_real_proof_flow(self):
        self.policy = replace(self.policy, variant="named-target")
        req = base.command(variant="named-target")
        self.reopen().dispatch(req)
        self.service.complete(self.worker)
        result = self.reopen().dispatch(base.command("status"))
        self.assertEqual((result["phase"], result["proof_result"]), ("settled", "pass"))
        outcome = model.document((self.jobs / "gha_123_1/baseline/public/outcome.json").read_bytes())
        self.assertEqual((outcome["execution"], outcome["proof"]), ("hosted", "windows-onboarding-named-target"))
        self.assertTrue(any(call[1:3] == ["targets", "import"] for call in self.factory.instances[0].calls))

    def test_adopted_recovery_retains_original_run_then_only_recovers_it(self):
        self.factory.fault = "cleanup-failed"
        base.ControllerTests.baseline(self)
        control = self.control / "gha_123_1"
        state = self.state()
        retained = dict(state["recovery_inputs"])
        original = {path: path.read_bytes() for path in (Path(retained["journal"]),
                    self.jobs / "gha_123_1/inputs/target.json", self.jobs / "gha_123_1/baseline/private/blender-box")}
        state.update(attempt=2, phase="starting", invocation=None, closed=True, local_termination="unknown")
        files = store.LocalFiles()
        files.publish(control / "execution.json", model.proof.canonical(state), exclusive=False)
        req = base.request()
        runtime = self.root / "runtime"
        runtime.mkdir(mode=0o700)
        group = self.root / "cgroup"
        group.mkdir()
        info = group.stat()
        current = {"inv": replace(fixtures.invocation(), attempt=2), "empty": True}
        intent = {"schema_version": 1, "execution_id": req.execution_id, "attempt": 2,
                  "request_digest": req.digest, "mode": "recover"}
        files.publish(control / "intent-0002.json", model.proof.canonical(intent))
        files.publish(runtime / "pending.json", model.proof.canonical(intent))
        def receipt():
            return native.NativeReceipt(current["inv"], 3000, info.st_dev, info.st_ino)
        files.publish(control / "native-0002.json", model.proof.canonical(asdict(receipt())))
        files.directory(self.jobs / "gha_123_1/attempts/0002", create=True)
        ops = mock.Mock()
        ops.boot.return_value = "1" * 32
        ops.whole_empty.side_effect = lambda: current["empty"]
        ops.supervisor_gone.return_value = True
        ops.unit.side_effect = lambda: native.UnitState("inactive" if current["empty"] else "active",
            0 if current["empty"] else 300, current["inv"].invocation_id, native.UNIT_CGROUP)
        @base.contextmanager
        def opened(name):
            fd = os.open(group, os.O_RDONLY | os.O_DIRECTORY)
            try:
                yield fd
            finally:
                os.close(fd)
        ops.group.side_effect = opened
        ops.process.side_effect = lambda pid: native.Process(300, 1, 3000, native.UNIT_CGROUP) if pid == 300 else native.Process(
            301, 300, 4001, current["inv"].cgroup)
        def start(operation):
            pending = native.parse_intent(files.read(runtime / "pending.json"))
            current.update(inv=replace(current["inv"], attempt=pending["attempt"]), empty=False)
            files.publish(native.receipt_path(current["inv"]), model.proof.canonical(asdict(receipt())))
        ops.systemctl.side_effect = start
        def exchange(bound, token):
            job = model.Controller(self.control, self.jobs, self.policy, None).job(control, self.state())
            self.assertEqual(protocol.parse_release(token, bound, files.read(control / "authorization-0003.json")), "recover")
            result = self.worker.recover(job, retained)
            files.publish(control / "result-0003.json", model.proof.canonical({"schema_version": 1,
                "invocation": asdict(bound.invocation), "mode": "recover", "result": result}))
            current["empty"] = True
            return {"schema_version": 1, "released": True, "invocation": asdict(bound.invocation)}
        ops.exchange.side_effect = exchange
        value = fixtures.policy().value | {"expected_client_sha256": self.policy.expected_client_sha256}
        policy = native.NativePolicy.parse(model.proof.canonical(value))
        def dispatch(operation):
            wire = model.proof.canonical({"schema_version": 1, "operation": operation, "execution_id": req.execution_id})
            output = io.StringIO()
            with mock.patch("sys.stdin", SimpleNamespace(buffer=io.BytesIO(wire))), redirect_stdout(output):
                code = native.entrypoint(["dispatch"])
            self.assertEqual(code, 0, output.getvalue())
            return json.loads(output.getvalue())
        self.factory.record["state"] = "failed"
        self.factory.record["cleanup"] = {key: True for key in model.proof.CLEANUP}
        with mock.patch.multiple(native, CONTROL=self.control, JOBS=self.jobs, CANDIDATE=self.checkout,
                                 CONFIG=self.root, RUNTIME=runtime), \
             mock.patch.object(native, "load_runtime", return_value=(policy, files)), \
             mock.patch.object(native, "LinuxOps", return_value=ops), \
             mock.patch.object(native, "wait_file", side_effect=lambda path, predicate, timeout: predicate()):
            adopted = dispatch("status")
            self.assertEqual((adopted["phase"], adopted["local_termination"], adopted["windows_cleanup"]),
                             ("unresolved", "proven", "unknown"))
            self.assertEqual(self.state()["recovery_inputs"], retained)
            self.assertEqual(dispatch("recover")["phase"], "recovering")
            self.assertEqual(dispatch("status")["phase"], "settled")
        self.assertEqual([call[1] for call in self.factory.instances[1].calls], ["status", "stop", "status"])
        self.assertEqual(sum(call[1] == "run" for commands in self.factory.instances for call in commands.calls), 1)
        self.assertEqual(self.state()["recovery_inputs"], retained)
        self.assertTrue(all(path.read_bytes() == content for path, content in original.items()))

    def test_forged_exact_authority_cannot_replace_validation_methods(self):
        self.reopen().dispatch(base.command())
        state = self.state()
        job = self.reopen().job(self.control / "gha_123_1", state)
        forged = object.__new__(protocol.NativeAdmission)
        forged.job, forged.mode, forged.gate = job, "baseline", None
        forged.receipt = native.NativeReceipt(fixtures.invocation(), 3000, 2, 3)
        forged.consume = lambda: None
        forged.check_process = lambda: None
        result = self.worker.baseline(job, native_authority=forged)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(self.factory.instances[0].calls, [])

    def test_wrong_peer_receiver_and_reused_gate_refuse(self):
        self.reopen().dispatch(base.command())
        job = self.reopen().job(self.control / "gha_123_1", self.state())
        for key, value in (("uid", 1902), ("pid", 302), ("peer", 302), ("start", 4002), ("boot", "f" * 32)):
            with self.subTest(key=key), base.native_gate(job, mutate=lambda env, obs: obs.update({key: value})) as (gate, wire, _):
                with self.assertRaises(model.ControllerError):
                    wire.NativeAdmission(gate)
        with base.native_gate(job) as (gate, wire, _):
            authority = wire.NativeAdmission(gate)
            self.assertFalse(gate.get_inheritable())
            request = model.proof.ProofRequest(job.request.candidate_sha, job.candidate_checkout,
                job.root / "inputs/operator.json", job.output, "hosted", job.request.driver_sha, job.request.variant)
            wire.NativeAdmission.require_proof(authority, request)
            self.assertEqual(gate.fileno(), -1)
            with self.assertRaises(model.ControllerError):
                wire.NativeAdmission.require_proof(authority, request)

    def test_socket_subclass_and_request_mismatch_cannot_authorize(self):
        self.reopen().dispatch(base.command())
        job = self.reopen().job(self.control / "gha_123_1", self.state())
        class ForgedSocket(socket.socket):
            def getsockopt(self, *args):
                return socket.SOCK_SEQPACKET
        forged = ForgedSocket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(forged.close)
        authority = object.__new__(protocol.NativeAdmission)
        authority.gate, authority.receipt = forged, native.NativeReceipt(fixtures.invocation(), 3000, 2, 3)
        with self.assertRaisesRegex(model.ControllerError, "native-peer-invalid"):
            protocol.NativeAdmission.check_process(forged, authority.receipt)
        with base.native_gate(job) as (gate, wire, _):
            authority = wire.NativeAdmission(gate)
            request = model.proof.ProofRequest(job.request.candidate_sha, job.candidate_checkout,
                job.root / "inputs/operator.json", job.output, "hosted", "f" * 40, job.request.variant)
            with self.assertRaisesRegex(model.ControllerError, "native-request-changed"):
                wire.NativeAdmission.require_proof(authority, request)
            self.assertEqual(gate.fileno(), -1)

    def test_consumed_root_packet_rejects_mutated_job_and_duplicate_descriptor(self):
        self.reopen().dispatch(base.command())
        job = self.reopen().job(self.control / "gha_123_1", self.state())
        with base.native_gate(job) as (gate, wire, _):
            authority = wire.NativeAdmission(gate)
            authority.job = replace(job, request=replace(job.request, driver_sha="f" * 40))
            outcome = self.worker.baseline(authority.job, native_authority=authority)
            self.assertEqual(outcome["status"], "fail")
            self.assertEqual(self.factory.instances[0].calls, [])
        with base.native_gate(job) as (gate, wire, observations):
            duplicate = socket.socket(fileno=os.dup(gate.fileno()))
            self.addCleanup(duplicate.close)
            observations["fds"].add(duplicate.fileno())
            first, second = wire.NativeAdmission(gate), wire.NativeAdmission(duplicate)
            request = model.proof.ProofRequest(job.request.candidate_sha, job.candidate_checkout,
                job.root / "inputs/operator.json", job.output, "hosted", job.request.driver_sha, job.request.variant)
            wire.NativeAdmission.require_proof(first, request)
            with self.assertRaises((BlockingIOError, model.ControllerError)):
                wire.NativeAdmission.require_proof(second, request)
            self.assertEqual(duplicate.fileno(), -1)
        with base.native_gate(job) as (gate, wire, _):
            with self.assertRaises(TypeError):
                wire.NativeAdmission(gate, {"job": "caller-chosen"})

    def test_valid_native_gate_cannot_authorize_linux_or_windows_subclass(self):
        import linux_blender_proof
        self.reopen().dispatch(base.command())
        job = self.reopen().job(self.control / "gha_123_1", self.state())
        class Substitute(model.proof.WindowsProofHost):
            pass
        for index, host in enumerate((linux_blender_proof.LinuxProofHost(), Substitute())):
            with base.native_gate(job) as (gate, wire, _):
                authority = wire.NativeAdmission(gate)
                request = model.proof.ProofRequest(job.request.candidate_sha, job.candidate_checkout,
                    job.root / "inputs/operator.json", self.root / ("host-refused-" + str(index)),
                    "hosted", job.request.driver_sha, job.request.variant)
                outcome = model.proof.baseline(request, self.factory, host, native_authority=authority)
                self.assertEqual(outcome["status"], "fail")
                self.assertEqual(self.factory.instances[-1].calls, [])



if __name__ == "__main__":
    unittest.main()
