import copy
from dataclasses import asdict, replace
import json
import unittest
import socket
import threading
from types import SimpleNamespace
from unittest import mock

import test_onboarding_proof as fixture
import test_proof_controller as baseline
import proof_installation as installation
import proof_controller_native as native

model, proof = baseline.controller, baseline.proof


@unittest.skipUnless(model.fcntl is not None, "POSIX private controller files")
class InstallationTests(unittest.TestCase):
    def setUp(self):
        self.base = baseline.ControllerTests()
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.config = fixture.installer_config(self.base.checkout)
        fixture.authorize_installer(self.config)
        self.config["ssh_config"] = self.base.config["ssh_config"]
        self.base.operator = self.base.checkout / "operator.json"
        baseline.private_file(self.base.operator, proof.canonical(self.config))
        (self.base.checkout / "manifest.json").chmod(0o600)
        self.base.policy = replace(self.base.policy, variant="host-install", operator_config=self.base.operator)
        self.controller = self.base.reopen()
        self.controller.dispatch(baseline.command(variant="host-install"))
        self.control = self.base.control / "gha_123_1"
        self.state = self.controller.load(self.control)
        self.job = self.controller.job(self.control, self.state)
        self.anchor = self.state["recovery_inputs"]
        self.records, self.mutations = [], []
        self.fault_stage = self.fault_boundary = self.host_fault = None
        self.commands = None
        self.checkpoints = self.channel()

    def latest(self):
        return installation.read_chain(self.control, self.job, self.anchor, self.controller.files)

    def exchange(self, frame):
        proposal = frame["record"]
        if proposal["stage"] == self.fault_stage and self.fault_boundary == "before-publish":
            raise baseline.Crash()
        ack = installation.publish_checkpoint(self.control, self.job, self.anchor, self.base.service.invocation,
                                             proposal, self.controller.files)
        self.records.append(copy.deepcopy(proposal))
        if proposal["stage"] == self.fault_stage and self.fault_boundary == "after-publish":
            raise baseline.Crash()
        if proposal["stage"] == self.fault_stage and self.fault_boundary == "wrong-ack":
            ack["sha256"] = "0" * 64
        return ack

    def channel(self):
        return installation.Checkpoints(self.job, self.anchor, self.latest(), self.base.service.invocation, self.exchange)

    def factory(self, private, cwd):
        owner = self
        if self.commands is not None:
            self.commands.private = private
            self.commands.sequence = 0
            self.commands.fault = self.host_fault
            return self.commands

        class Commands(fixture.FakeInstallCommands):
            def run(self, args, **kwargs):
                argv = [str(a) for a in args]
                operation = argv[1] if len(argv) > 1 else ""
                if argv[0] == "ssh" and b"$inputData.args" in kwargs.get("stdin", b""):
                    script = kwargs["stdin"].decode()
                    encoded = proof.re.search(r"FromBase64String\('([^']+)'\)", script).group(1)
                    remote = json.loads(proof.base64.b64decode(encoded))["args"]
                    operation = remote[1]
                    if "--apply" in remote:
                        latest = owner.latest()
                        wanted = {"install": ("install-released", "run-clean"), "remove": ("remove-released", "removed"),
                                  "stop": ("install-observed", "remove-observed")}[operation]
                        owner.assertIn(latest["stage"], wanted)
                        owner.assertEqual(latest["invocation"], asdict(owner.base.service.invocation))
                        owner.mutations.append((operation, latest["stage"], latest["sequence"]))
                        if latest["stage"] == owner.fault_stage and owner.fault_boundary == "before-send":
                            raise baseline.Crash()
                elif operation == "run":
                    owner.assertEqual(owner.latest()["stage"], "run-released")
                    owner.mutations.append(("run", "run-released", owner.latest()["sequence"]))
                elif operation == "stop":
                    owner.assertIn(owner.latest()["stage"], ("run-owned", "run-clean"))
                    owner.mutations.append(("run-stop", owner.latest()["stage"], owner.latest()["sequence"]))
                try:
                    result = super().run(args, **kwargs)
                    if owner.fault_boundary == "after-send" and owner.latest()["stage"] == owner.fault_stage:
                        if operation in ("install", "remove", "run"):
                            raise baseline.Crash()
                finally:
                    if operation == "run" and self.run_id and self.record:
                        owner.write_run(self.record)
                return result

        self.commands = Commands(private, cwd, self.config, self.host_fault)
        self.commands.operations_path = self.job.output / "private/installer-operations.json"
        return self.commands

    def write_run(self, record):
        self.job.config.mkdir(mode=0o700, exist_ok=True)
        (self.job.config / "runs").mkdir(mode=0o700, exist_ok=True)
        claim = {key: record[key] for key in ("schema_version", "run_id", "request_id", "deadline", "request_hash")}
        claim.update(controller_id="original-controller", task_name=self.config["installation"]["task_name"])
        fingerprint = installation.target_fingerprint((self.job.output / "private/target.json").read_bytes())
        journal = {"schema_version": 1, "claim": claim, "target_fingerprint": fingerprint}
        baseline.private_file(self.job.config / "runs" / (record["run_id"] + ".json"), proof.canonical(journal))
        if record.get("session_id"):
            baseline.private_file(self.job.config / "runs" / (record["run_id"] + ".session.json"), proof.canonical({
                **journal, "run_id": record["run_id"], "session_id": record["session_id"]}))

    def prove(self):
        worker = model.ProofWorker(self.factory, clock=lambda: baseline.NOW)
        retained = {"anchor": self.anchor, "latest": self.latest()}
        with baseline.native_gate(self.job, retained=retained) as (gate, protocol, _):
            authority = protocol.NativeAdmission(gate)
            authority.checkpoints = self.checkpoints
            result = worker.baseline(self.job, native_authority=authority)
        self.base.service.empty = True
        self.base.service.completed[self.base.service.invocation.invocation_id] = {
            "schema_version": 1, "invocation": asdict(self.base.service.invocation), "mode": "baseline", "result": result}
        return result

    def recover(self):
        self.base.service.empty = True
        self.base.service.completed.clear()
        self.controller.dispatch(baseline.command("recover"))
        self.state = self.controller.load(self.control)
        self.job = self.controller.job(self.control, self.state)
        self.checkpoints = self.channel()
        retained = {"anchor": self.anchor, "latest": self.latest()}
        result = model.ProofWorker(self.factory).recover(self.job, retained, checkpoints=self.checkpoints)
        self.base.service.empty = True
        self.base.service.completed[self.base.service.invocation.invocation_id] = {
            "schema_version": 1, "invocation": asdict(self.base.service.invocation), "mode": "recover", "result": result}
        return self.controller.dispatch(baseline.command("status"))

    def test_integrated_install_run_recovery_remove_and_public_receipt(self):
        result = self.prove()
        self.assertEqual(result["status"], "pass", result)
        self.assertEqual(self.latest()["stage"], "removed")
        self.assertEqual(self.commands.receipt.read_bytes(), b"removed tombstone")
        self.assertEqual(self.commands.remote_file(r"C:\ExistingFixture\precious.blend").read_bytes(), b"precious!")
        receipt = self.controller.dispatch(baseline.command("status"))
        self.assertEqual(receipt, {"schema_version": 1, "execution_id": "gha_123_1", "phase": "settled", "closed": True,
                                  "attempt": 1, "local_termination": "proven", "windows_cleanup": "proven", "proof_result": "pass"})
        self.assertLess(len(proof.canonical(receipt)), 512)
        self.assertLess(next(i for i, item in enumerate(self.mutations) if item[0] == "run-stop"),
                        next(i for i, item in enumerate(self.mutations) if item[0] == "remove"))

    def test_native_result_socket_checkpoints_and_final_result_are_distinct(self):
        import proof_controller_worker as protocol
        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(sender.close)
        self.addCleanup(receiver.close)
        for endpoint in (sender, receiver):
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 256 << 10)
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256 << 10)
            endpoint.settimeout(5)
        results, errors = [], []
        supervisor = protocol.Supervisor(SimpleNamespace(controller=self.base.policy), self.controller.files, None)
        def serve():
            try:
                results.append(supervisor.collect(SimpleNamespace(invocation=self.base.service.invocation), receiver))
            except BaseException as error:
                errors.append(error)
        def exchange(frame):
            sender.sendall(proof.canonical(frame))
            return protocol.receive(sender, model.MAX_WIRE, versions=(2,))
        self.checkpoints.exchange = exchange
        with mock.patch.multiple(native, CONTROL=self.base.control, JOBS=self.base.jobs):
            thread = threading.Thread(target=serve)
            thread.start()
            try:
                outcome = self.prove()
                sender.sendall(proof.canonical({"schema_version": 1, "result": {"status": outcome["status"]}}))
            finally:
                thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(outcome["status"], "pass", outcome)
        self.assertEqual(results, [{"schema_version": 1, "result": {"status": "pass"}}])
        self.assertEqual(self.latest()["stage"], "removed")
        self.assertEqual(self.commands.receipt.read_bytes(), b"removed tombstone")

    def test_original_private_inputs_rebound_without_fabricated_target(self):
        inputs = self.job.root / "inputs"
        self.assertFalse((inputs / "target.json").exists())
        retained = json.loads((inputs / "operator.json").read_bytes())
        self.assertEqual(retained["runtime"]["local_manifest"], str(inputs / "runtime-manifest.json"))
        self.assertEqual(retained["authorization"]["scope"], "host-install-run-remove")
        self.assertEqual((inputs / "original-operator.json").read_bytes(), self.base.operator.read_bytes())
        baseline.private_file(inputs / "runtime-manifest.json", b"replaced")
        with self.assertRaisesRegex(model.ControllerError, "original-inputs-unavailable"):
            model.verify_inputs(self.control, self.job, self.job.inputs_digest)

    def test_missing_marker_after_run_release_fences_installed_fixture(self):
        self.host_fault = "no-run-marker"
        result = self.prove()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(self.latest()["stage"], "run-released")
        with self.assertRaises(OSError):
            self.recover()
        self.assertTrue(self.commands.owned_runtime.exists())
        self.assertEqual(self.commands.removal_calls, 0)
        with self.assertRaisesRegex(model.ControllerError, "fixture-unresolved"):
            self.controller.dispatch(baseline.command(execution_id="gha_second", variant="host-install"))

    def test_lost_apply_response_pins_first_status_then_removes_without_reapply(self):
        self.host_fault = "lost-apply-response"
        result = self.prove()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(self.latest()["stage"], "removed", result)
        self.assertEqual(sum(item[0] == "install" for item in self.mutations), 1)
        receipt = self.controller.dispatch(baseline.command("status"))
        self.assertEqual((receipt["phase"], receipt["proof_result"]), ("settled", "fail"))

    def test_lost_exact_stop_reply_keeps_pin_and_reobserves(self):
        self.host_fault = "lost-stop-response"
        result = self.prove()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(self.latest()["stage"], "removed", result)
        stops = [item for item in self.mutations if item[0] == "stop"]
        self.assertEqual(len(stops), 1)
        self.assertEqual(stops[0][1], "install-observed")

    def test_reboot_and_local_termination_never_imply_windows_cleanup(self):
        self.fault_stage, self.fault_boundary = "install-released", "after-publish"
        with self.assertRaises(baseline.Crash):
            self.prove()
        self.base.service.boot = "9" * 32
        self.base.service.invocation = None
        self.base.service.empty = True
        receipt = self.controller.dispatch(baseline.command("status"))
        self.assertEqual((receipt["local_termination"], receipt["windows_cleanup"], receipt["phase"]),
                         ("proven", "unknown", "unresolved"))
        self.assertEqual(self.latest()["stage"], "install-released")
        self.assertFalse(self.commands.receipt.exists())

    def test_ack_loss_never_replays_uncertain_apply(self):
        self.fault_stage, self.fault_boundary = "install-released", "after-publish"
        with self.assertRaises(baseline.Crash):
            self.prove()
        self.assertTrue(self.checkpoints.broken)
        self.fault_stage = None
        with self.assertRaises(proof.ProofError):
            self.recover()
        self.assertEqual(self.latest()["stage"], "install-released")
        self.assertEqual(self.mutations, [])

    def test_fault_before_root_publication_can_close_only_after_fresh_absence(self):
        self.fault_stage, self.fault_boundary = "install-released", "before-publish"
        with self.assertRaises(baseline.Crash):
            self.prove()
        self.assertEqual(self.latest()["stage"], "bound")
        self.fault_stage = None
        receipt = self.recover()
        self.assertEqual((receipt["phase"], receipt["proof_result"], receipt["windows_cleanup"]), ("settled", "fail", "proven"))
        self.assertEqual(self.mutations, [])

    def test_malformed_duplicate_stale_and_changed_anchor_checkpoints_refuse(self):
        self.prove()
        last = self.records[-1]
        for bad in (last, {**last, "sequence": 0}, {**last, "private": "injection"},
                    {**last, "anchor_sha256": "0" * 64}, {**last, "schema_version": 1}):
            with self.subTest(keys=list(bad)), self.assertRaises(model.ControllerError):
                installation.publish_checkpoint(self.control, self.job, self.anchor, self.base.service.invocation,
                                                bad, self.controller.files)
        self.assertEqual(self.latest(), last)

    def test_altered_root_revision_and_mixed_schema_refuse(self):
        self.prove()
        path = self.control / "installation-0001.json"
        value = json.loads(path.read_bytes())
        value["data"]["intent"]["operation_id"] = "bbxo_" + "f" * 32
        baseline.private_file(path, proof.canonical(value))
        with self.assertRaises(model.ControllerError):
            self.controller.dispatch(baseline.command("status"))

    def test_response_loss_after_send_recovers_committed_install_and_remove(self):
        for stage in ("install-released", "remove-released", "run-released"):
            with self.subTest(stage=stage):
                other = InstallationTests()
                other.setUp()
                self.addCleanup(other.doCleanups)
                other.fault_stage, other.fault_boundary = stage, "after-send"
                with self.assertRaises(baseline.Crash):
                    other.prove()
                other.fault_stage = None
                before = [item[0] for item in other.mutations]
                receipt = other.recover()
                self.assertEqual((receipt["phase"], receipt["proof_result"]), ("settled", "fail"))
                self.assertEqual(sum(item[0] == "install" for item in other.mutations), before.count("install"))
                self.assertEqual(sum(item[0] == "run" for item in other.mutations), before.count("run"))
                if stage == "remove-released":
                    self.assertEqual(other.commands.removal_calls, 1)

    def test_apply_not_sent_after_ack_still_retains_uncertainty(self):
        for stage in ("install-released", "remove-released"):
            with self.subTest(stage=stage):
                other = InstallationTests()
                other.setUp()
                self.addCleanup(other.doCleanups)
                other.fault_stage, other.fault_boundary = stage, "before-send"
                with self.assertRaises(baseline.Crash):
                    other.prove()
                other.fault_stage = None
                with self.assertRaises(proof.ProofError):
                    other.recover()
                self.assertEqual(other.latest()["stage"], stage)
                self.assertEqual(other.commands.removal_calls, 0)

    def test_lost_run_reply_recovers_only_original_marker_journal_and_session(self):
        self.host_fault = "run-failed"
        result = self.prove()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(self.latest()["stage"], "removed", result)
        owned = next(item for item in self.records if item["stage"] == "run-owned")
        self.assertEqual(owned["data"]["run"]["run_id"], fixture.RUN)
        self.assertEqual(owned["data"]["run"]["session"]["record"]["session_id"], self.commands.record["session_id"])
        self.assertEqual(sum(item[0] == "run" for item in self.mutations), 1)

    def test_terminal_install_before_target_copy_recovers_without_reinstall(self):
        self.fault_stage, self.fault_boundary = "installed", "after-publish"
        with self.assertRaises(baseline.Crash):
            self.prove()
        self.assertFalse((self.job.output / "private/target.json").exists())
        self.fault_stage = None
        receipt = self.recover()
        self.assertEqual((receipt["phase"], receipt["proof_result"]), ("settled", "fail"))
        self.assertEqual(sum(item[0] == "install" for item in self.mutations), 1)
        self.assertEqual(self.commands.receipt.read_bytes(), b"removed tombstone")

    def test_changed_execution_pin_or_plan_never_stops_replacement(self):
        for field in ("token", "request_sha256", "deadline", "keeper", "worker", "plan"):
            with self.subTest(field=field):
                other = InstallationTests()
                other.setUp()
                self.addCleanup(other.doCleanups)
                other.fault_stage, other.fault_boundary = "install-observed", "after-publish"
                with self.assertRaises(baseline.Crash):
                    other.prove()
                result = other.commands.execution_results[other.anchor["operations"]["install"]]
                if field == "plan":
                    result["plan"]["plan_sha256"] = "9" * 64
                elif field in ("keeper", "worker"):
                    result["execution"][field]["created_filetime"] = "9999"
                else:
                    result["execution"][field] = {"token": "bbxe_" + "9" * 32,
                        "request_sha256": "9" * 64, "deadline": "2026-09-06T13:00:00Z"}[field]
                other.fault_stage = None
                with self.assertRaises((model.ControllerError, proof.ProofError)):
                    other.recover()
                self.assertEqual([item[0] for item in other.mutations], ["install"])
                self.assertTrue(other.commands.owned_runtime.exists())

    def test_changed_remove_plan_or_token_keeps_receipt_unresolved(self):
        for field in ("plan", "token"):
            with self.subTest(field=field):
                other = InstallationTests()
                other.setUp()
                self.addCleanup(other.doCleanups)
                other.fault_stage, other.fault_boundary = "remove-observed", "after-publish"
                with self.assertRaises(baseline.Crash):
                    other.prove()
                observed = other.commands.execution_results[other.anchor["operations"]["remove"]]
                if field == "plan":
                    observed["plan"]["plan_sha256"] = "9" * 64
                else:
                    observed["execution"]["token"] = "bbxe_" + "9" * 32
                other.fault_stage = None
                with self.assertRaises((model.ControllerError, proof.ProofError)):
                    other.recover()
                self.assertEqual(other.latest()["stage"], "remove-observed")
                self.assertEqual(other.commands.removal_calls, 1)
                self.assertEqual(other.controller.load(other.control)["windows_cleanup"], "unknown")

    def test_changed_original_run_inputs_prevent_stop_and_removal(self):
        for field in ("target", "client", "journal", "session"):
            with self.subTest(field=field):
                other = InstallationTests()
                other.setUp()
                self.addCleanup(other.doCleanups)
                other.fault_stage, other.fault_boundary = "run-owned", "after-publish"
                with self.assertRaises(baseline.Crash):
                    other.prove()
                root = other.job.output / "private"
                path = {"target": root / "target.json", "client": root / "blender-box",
                        "journal": other.job.config / "runs" / (fixture.RUN + ".json"),
                        "session": other.job.config / "runs" / (fixture.RUN + ".session.json")}[field]
                if field == "client":
                    baseline.private_file(path, b"different client")
                else:
                    record = json.loads(path.read_bytes())
                    if field == "target":
                        record["ssh_alias"] = "changed-host"
                    elif field == "journal":
                        record["claim"]["request_hash"] = "9" * 64
                    else:
                        record["session_id"] = "bss_" + "9" * 24
                    baseline.private_file(path, proof.canonical(record))
                other.fault_stage = None
                with self.assertRaises((model.ControllerError, proof.ProofError)):
                    other.recover()
                self.assertEqual([item[0] for item in other.mutations], ["install", "run"])
                self.assertTrue(other.commands.owned_runtime.exists())

    def test_root_publication_and_ack_fault_matrix(self):
        for stage in ("install-released", "install-observed", "run-released", "run-owned", "remove-released", "remove-observed"):
            for boundary in ("before-publish", "after-publish", "wrong-ack"):
                with self.subTest(stage=stage, boundary=boundary):
                    other = InstallationTests()
                    other.setUp()
                    self.addCleanup(other.doCleanups)
                    other.fault_stage, other.fault_boundary = stage, boundary
                    if boundary == "wrong-ack":
                        result = other.prove()
                        self.assertEqual(result["status"], "fail")
                    else:
                        with self.assertRaises(baseline.Crash):
                            other.prove()
                    committed = other.latest()
                    self.assertEqual(other.checkpoints.broken, True)
                    if boundary != "before-publish":
                        self.assertEqual(committed["stage"], stage)
                    if stage == "install-released":
                        self.assertFalse(other.commands.receipt.exists())
                    if stage == "run-released":
                        self.assertIsNone(other.commands.run_id)
                    if stage == "remove-released":
                        self.assertEqual(other.commands.removal_calls, 0)
                    other.base.service.empty = True
                    receipt = other.controller.dispatch(baseline.command("status"))
                    self.assertEqual(receipt["windows_cleanup"], "unknown")
                    with self.assertRaisesRegex(model.ControllerError, "fixture-unresolved"):
                        other.controller.dispatch(baseline.command(execution_id="gha_other", variant="host-install"))

    def test_lost_remove_reply_recovery_does_not_duplicate_remove_apply(self):
        self.host_fault = "lost-remove-response"
        result = self.prove()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(self.latest()["stage"], "removed")
        self.host_fault = None
        receipt = self.recover()
        self.assertEqual((receipt["phase"], receipt["proof_result"]), ("settled", "fail"))
        self.assertEqual(self.commands.removal_calls, 1)

    def test_unknown_installer_cleanup_never_authorizes_removal(self):
        for field in ("tree_cleanup", "task_mutation", "launcher_cleanup"):
            with self.subTest(field=field):
                other = InstallationTests()
                other.setUp()
                self.addCleanup(other.doCleanups)
                other.fault_stage, other.fault_boundary = "install-observed", "after-publish"
                with self.assertRaises(baseline.Crash):
                    other.prove()
                observed = other.commands.execution_results[other.anchor["operations"]["install"]]
                observed.update(state="unknown", completion="unknown")
                observed["execution"].update(state="unknown", fence_state="held")
                observed["execution"][field] = "unknown"
                other.fault_stage = None
                original = proof.installer_call
                statuses = []
                def bounded(commands, operator, operation, **kwargs):
                    if operation == "status":
                        statuses.append(operation)
                        if len(statuses) == 2:
                            raise proof.ProofError("installer-stop-unsettled")
                    return original(commands, operator, operation, **kwargs)
                with mock.patch.object(proof, "installer_call", side_effect=bounded):
                    with self.assertRaisesRegex(proof.ProofError, "installer-stop-unsettled"):
                        other.recover()
                self.assertEqual(other.latest()["stage"], "install-observed")
                self.assertEqual(other.latest()["data"]["observed"]["execution"][field], "unknown")
                self.assertEqual(other.commands.removal_calls, 0)
                self.assertEqual(other.controller.load(other.control)["windows_cleanup"], "unknown")

    def test_unreleased_native_attempt_still_needs_fresh_declared_absence(self):
        original = self.base.service.invocation
        self.base.service.empty = True
        self.base.service.inspect_attempt = lambda request, attempt, known: (
            model.BoundAttempt(original, "baseline", "gone", "withheld") if attempt == 1 else None)
        receipt = self.controller.dispatch(baseline.command("status"))
        self.assertEqual((receipt["phase"], receipt["local_termination"], receipt["windows_cleanup"]),
                         ("unresolved", "proven", "unknown"))
        self.assertIsNone(self.commands)
        receipt = self.recover()
        self.assertEqual((receipt["phase"], receipt["proof_result"], receipt["windows_cleanup"]), ("settled", "fail", "proven"))
        self.assertEqual(self.mutations, [])

    def test_partial_install_and_failed_run_cleanup_keep_owned_fixture(self):
        for fault, stage in (("apply-partial", "install-observed"), ("cleanup-failed", "run-owned")):
            with self.subTest(fault=fault):
                other = InstallationTests()
                other.setUp()
                self.addCleanup(other.doCleanups)
                other.host_fault = fault
                result = other.prove()
                self.assertEqual(result["status"], "fail")
                self.assertEqual(other.latest()["stage"], stage)
                receipt = other.controller.dispatch(baseline.command("status"))
                self.assertEqual(receipt["windows_cleanup"], "unknown")
                self.assertEqual(other.commands.removal_calls, 0)
                self.assertTrue(other.commands.owned_runtime.exists())

    def test_public_outcome_never_contains_private_settlement_observation(self):
        result = self.prove()
        self.assertIn("installation_settlement", result)
        public = (self.job.output / "public/outcome.json").read_bytes()
        self.assertNotIn(b"installation_settlement", public)
        self.assertNotIn(b"precious.blend", public)
        self.assertNotIn(b"request_sha256", public)



class InstallationPolicyTests(unittest.TestCase):
    def test_host_install_enrollment_requires_exact_private_pins_and_new_qualification(self):
        from test_proof_controller_native import spec
        value = dict(spec(), variant="host-install")
        with self.assertRaisesRegex(model.ControllerError, "native-enrollment-invalid"):
            native.validate_enrollment(value)
        value["installer_inputs"] = {key: "c" * 64 for key in native.INSTALL_INPUTS}
        native.validate_enrollment(value)
        del value["public_key"]
        value["artifacts"] = {path: "d" * 64 for path in native.artifact_paths()}
        policy = native.NativePolicy.parse(proof.canonical(value))
        old = {"schema_version": 1, "qualified": True, "policy_sha256": policy.digest,
               "evidence": {key: "e" * 64 for key in native.QUALIFICATIONS}}
        with self.assertRaisesRegex(model.ControllerError, "native-adapter-unqualified"):
            policy.qualify(proof.canonical(old))
        admitted = {"schema_version": 2, "scope": native.INSTALL_PREFLIGHT_SCOPE, "qualified": True,
                    "policy_sha256": policy.digest,
                    "evidence": {key: "e" * 64 for key in native.INSTALL_PREFLIGHT}}
        policy.qualify(proof.canonical(admitted))
        for change in ({"scope": "complete-installer-proof"}, {"policy_sha256": "f" * 64},
                       {"qualified": False}, {"evidence": {}},
                       {"evidence": {**admitted["evidence"], "installer-run-removal": "e" * 64}},
                       {"evidence": {**admitted["evidence"], "fixture-preflight": None}}):
            with self.subTest(change=change), self.assertRaisesRegex(model.ControllerError, "native-adapter-unqualified"):
                policy.qualify(proof.canonical(admitted | change))
        policy.admit(replace(baseline.command(variant="host-install"), installer_operator_sha256="c" * 64))
        with self.assertRaisesRegex(model.ControllerError, "variant-driver-unavailable"):
            policy.admit(baseline.command())

    @unittest.skipUnless(model.fcntl is not None, "POSIX private controller files")
    def test_enrollment_renders_host_install_as_unqualified_with_exact_artifacts(self):
        import tempfile
        from pathlib import Path
        from test_proof_controller_native import spec
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            value = dict(spec(), variant="host-install", installer_inputs={key: "c" * 64 for key in native.INSTALL_INPUTS})
            baseline.private_file(root / "spec.json", proof.canonical(value))
            manifest = native.render_enrollment(root / "spec.json", baseline.ROOT, root / "enrollment")
            resources = {item["path"]: item for item in manifest["resources"]}
            policy = native.NativePolicy.parse((root / "enrollment" / resources[str(native.CONFIG / "policy.json")]["source"]).read_bytes())
            raw = (root / "enrollment" / resources[str(native.CONFIG / "qualification.json")]["source"]).read_bytes()
            qualification = model.document(raw, version=2)
            self.assertEqual(qualification["qualified"], False)
            self.assertEqual(qualification["scope"], native.INSTALL_PREFLIGHT_SCOPE)
            self.assertEqual(set(qualification["evidence"]), set(native.INSTALL_PREFLIGHT))
            self.assertTrue(all(value is None for value in qualification["evidence"].values()))
            self.assertIn(str(native.BASE / "scripts/proof_installation.py"), policy.value["artifacts"])
            self.assertIn(str(native.CONFIG / "runtime-manifest.json"), manifest["operator_inputs"])
            with self.assertRaisesRegex(model.ControllerError, "native-adapter-unqualified"):
                policy.qualify(raw)

    def test_target_fingerprint_matches_frozen_product_contract(self):
        record = json.loads((baseline.ROOT / "internal/target/testdata/windows-compatibility.json").read_bytes())
        self.assertEqual(installation.target_fingerprint(proof.canonical(record["target"])), record["fingerprint"])
