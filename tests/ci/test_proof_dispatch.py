import base64
import copy
from dataclasses import asdict, replace
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import test_proof_controller as baseline
import test_proof_installation as installation_tests
import test_proof_controller_native as native_tests
import proof_dispatch as dispatch

model, proof = baseline.controller, baseline.proof


@unittest.skipUnless(model.fcntl is not None, "POSIX private controller files")
class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "dispatch"
        self.env = {"GITHUB_RUN_ATTEMPT": "1", "CANDIDATE_SHA": baseline.SHA, "DRIVER_SHA": baseline.DRIVER,
                    "PROOF_EXECUTION_ID": "gha_123_host_install", "INSTALL_CONTROLLER_KEY": "PRIVATE_KEY_SENTINEL",
                    "INSTALL_CONTROLLER_KNOWN_HOSTS": "PRIVATE_TRUST_SENTINEL",
                    "INSTALL_CONTROLLER_CONFIG": json.dumps({"schema_version": 1, "hostname": "controller.invalid",
                                                            "user": "proof-control", "port": 22}),
                    "INSTALL_OPERATOR_CONFIG": json.dumps({"schema_version": 1,
                        "authorization": {"candidate_sha": baseline.SHA, "scope": "host-install-run-remove", "launch": True},
                        "fixture": {"kind": "dedicated", "state": "absent"}})}

    def receipt(self, **changes):
        return {"schema_version": 1, "execution_id": "gha_123_host_install", "phase": "running", "closed": False,
                "attempt": 1, "local_termination": "unknown", "windows_cleanup": "unknown", "proof_result": "not-run", **changes}

    def test_exact_operator_digest_binds_start_to_qualified_controller_policy(self):
        dispatch.prepare(self.root, self.env)
        command = model.parse_command((self.root / "request.json").read_bytes())
        value = dict(native_tests.spec(), variant="host-install")
        value.pop("public_key")
        value.update(installer_inputs={key: "a" * 64 for key in native_tests.native.INSTALL_INPUTS},
                     artifacts={key: "b" * 64 for key in native_tests.native.artifact_paths()})
        value["installer_inputs"]["operator.json"] = proof.digest(self.env["INSTALL_OPERATOR_CONFIG"].encode())
        policy = native_tests.native.NativePolicy.parse(proof.canonical(value))
        policy.admit(command)
        for digest in (None, "0" * 64):
            with self.assertRaisesRegex(model.ControllerError, "request-not-authorized"):
                policy.admit(replace(command, installer_operator_sha256=digest))
        self.assertEqual((self.root / "operator.json").read_bytes(), self.env["INSTALL_OPERATOR_CONFIG"].encode())
        self.assertEqual((self.root / "key").stat().st_mode & 0o777, 0o600)

    @unittest.skipUnless(shutil.which("ssh"), "OpenSSH configuration parser")
    def test_generated_ssh_config_disables_commands_and_preserves_spaced_paths(self):
        self.root = self.root.parent / "dispatch inputs"
        dispatch.prepare(self.root, self.env)
        parsed = subprocess.run(["ssh", "-G", "-F", str(self.root / "ssh-config"), "-T", "--",
                                 "proof-controller", "dispatch"], capture_output=True, text=True, timeout=10)
        self.assertEqual(parsed.returncode, 0, parsed.stderr)
        options = dict(line.split(" ", 1) for line in parsed.stdout.splitlines())
        for key in ("remotecommand", "proxycommand", "proxyjump", "knownhostscommand"):
            self.assertNotIn(key, options)
        self.assertEqual(options["identityagent"], "none")
        self.assertEqual(options["certificatefile"], "none")
        self.assertEqual(options["identityfile"], str(self.root / "key"))
        self.assertEqual(options["userknownhostsfile"], str(self.root / "known_hosts"))

    @unittest.skipUnless(shutil.which("ssh-keygen"), "OpenSSH private key parser")
    def test_key_secret_without_final_newline_remains_usable(self):
        source = self.root.parent / "generated-key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(source)],
                       capture_output=True, check=True, timeout=10)
        expected = source.with_suffix(".pub").read_text().split()[:2]
        for newline in ("", "\n"):
            with self.subTest(newline=bool(newline)):
                self.root = self.root.parent / ("dispatch-newline" if newline else "dispatch-trimmed")
                self.env["INSTALL_CONTROLLER_KEY"] = source.read_text().rstrip("\r\n") + newline
                dispatch.prepare(self.root, self.env)
                parsed = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", str(self.root / "key")],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(parsed.returncode, 0, parsed.stderr)
                self.assertEqual(parsed.stdout.split()[:2], expected)
                self.assertEqual((self.root / "operator.json").read_bytes(), self.env["INSTALL_OPERATOR_CONFIG"].encode())

    def test_start_polls_same_execution_and_upload_projection_is_fixed(self):
        dispatch.prepare(self.root, self.env)
        received, now = [], [0]
        results = [self.receipt(), self.receipt(phase="settled", closed=True, local_termination="proven",
                                               windows_cleanup="proven", proof_result="pass")]
        class Commands:
            def run(self, args, **options):
                received.append((args, model.parse_command(options["stdin"])))
                return proof.canonical(results.pop(0))
        result = dispatch.dispatch(self.root, "start", commands=Commands(), clock=lambda: now[0],
                                   wait=lambda duration: now.__setitem__(0, now[0] + duration))
        self.assertEqual(result["phase"], "settled")
        self.assertEqual([command.operation for _, command in received], ["start", "status"])
        self.assertEqual({command.execution_id for _, command in received}, {"gha_123_host_install"})
        public = (self.root / "public/receipt.json").read_bytes()
        self.assertEqual(json.loads(public), result)
        self.assertNotIn(b"PRIVATE", public)
        self.assertNotIn(b"controller.invalid", public)

    def test_recovery_never_sends_start_or_replays_installation(self):
        dispatch.prepare(self.root, self.env)
        requests = []
        class Commands:
            def run(self, args, **options):
                requests.append(model.parse_command(options["stdin"]))
                return proof.canonical({"schema_version": 1, "execution_id": "gha_123_host_install", "phase": "unresolved",
                    "closed": True, "attempt": 2, "local_termination": "proven", "windows_cleanup": "unknown", "proof_result": "fail"})
        result = dispatch.dispatch(self.root, "recover", commands=Commands())
        self.assertEqual(result["phase"], "unresolved")
        self.assertEqual([command.operation for command in requests], ["recover"])

    def test_malformed_or_private_reply_is_not_published(self):
        dispatch.prepare(self.root, self.env)
        for bad in (self.receipt(private="PRIVATE_SECRET"), self.receipt(attempt=True), self.receipt(phase="settled"),
                    self.receipt(execution_id="different"), {"schema_version": 1, "status": "error", "code": "native-adapter-unqualified"}):
            class Commands:
                def run(self, args, **kwargs):
                    return proof.canonical(bad)
            with self.subTest(bad=bad), self.assertRaises(model.ControllerError):
                dispatch.dispatch(self.root, "start", commands=Commands())
            self.assertFalse((self.root / "public/receipt.json").exists())

    def test_unauthorized_rerun_or_wrong_grant_precedes_credential_files(self):
        for changes in ({"GITHUB_RUN_ATTEMPT": "2"}, {"CANDIDATE_SHA": "c" * 40}):
            with self.assertRaises(model.ControllerError):
                dispatch.prepare(self.root, self.env | changes)
            self.assertFalse(self.root.exists())


@unittest.skipUnless(model.fcntl is not None, "POSIX private controller files")
class CollectTests(unittest.TestCase):
    def setUp(self):
        self.fixture = installation_tests.InstallationTests("test_collect_projects_baseline_evidence_without_installer_settlement")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.prove()
        record = self.fixture.base.service.completed[self.fixture.base.service.invocation.invocation_id]
        baseline.private_file(self.fixture.control / "result-0001.json", proof.canonical(record))
        self.fixture.controller.dispatch(baseline.command("status"))
        self.response = self.fixture.base.reopen().dispatch(baseline.command("collect"))
        self.root = self.fixture.base.root / "dispatch"
        model.private_directory(self.root, create=True)
        model.private_directory(self.root / "public", create=True)
        model.publish(self.root / "request.json", proof.canonical({"schema_version": 1, "operation": "start",
                                                                   "request": asdict(self.fixture.job.request)}))

    def files(self, response=None):
        return {item["name"]: base64.b64decode(item["content_base64"]) for item in (response or self.response)["files"]}

    def rebuilt(self, change, viewport=None):
        files = self.files()
        envelope = json.loads(files["outcome.json"])
        change(envelope)
        files["outcome.json"] = proof.canonical(envelope)
        if viewport is not None:
            files["viewport.png"] = viewport
        return {**self.response, "files": [{"name": name, "size": len(content), "sha256": proof.digest(content),
                                            "content_base64": base64.b64encode(content).decode()}
                                           for name, content in files.items()]}

    def collect(self, response):
        sent = []

        class Commands:
            def run(self, args, **options):
                sent.append(model.parse_command(options["stdin"]))
                return proof.canonical(response)
        try:
            return dispatch.collect(self.root, commands=Commands())
        finally:
            self.assertEqual([(command.operation, command.execution_id) for command in sent], [("collect", "gha_123_1")])

    def test_settled_pass_publishes_exact_controller_outcome(self):
        self.assertTrue(self.collect(self.response))
        files = self.files()
        self.assertEqual((self.root / "public/outcome.json").read_bytes(), files["outcome.json"])
        self.assertEqual(json.loads(files["outcome.json"])["request"]["variant"], "host-install")
        self.assertNotIn(b"installation_settlement", files["outcome.json"])

    def test_viewport_must_match_the_reported_capture(self):
        image = baseline.baseline_tests.png(3, 2)

        def capture(envelope):
            artifact = next(item for item in envelope["baseline"]["report"]["artifacts"] if item["type"] == "viewport")
            artifact.update(size=len(image), local_sha256=proof.digest(image), remote_sha256=proof.digest(image), width=3, height=2)
        self.assertTrue(self.collect(self.rebuilt(capture, viewport=image)))
        self.assertEqual((self.root / "public/viewport.png").read_bytes(), image)
        (self.root / "public/viewport.png").unlink()
        (self.root / "public/outcome.json").unlink()
        with self.assertRaisesRegex(model.ControllerError, "collect-viewport-invalid"):
            self.collect(self.rebuilt(capture, viewport=baseline.baseline_tests.png(2, 2)))
        self.assertFalse((self.root / "public/viewport.png").exists())

    def test_failed_report_is_published_but_never_passes(self):
        def fail(envelope):
            envelope["baseline"]["report"]["status"] = "fail"
            envelope["baseline"]["report"]["outcomes"]["scenario"]["status"] = "fail"
        self.assertFalse(self.collect(self.rebuilt(fail)))
        self.assertEqual(json.loads((self.root / "public/outcome.json").read_bytes())["baseline"]["report"]["status"], "fail")

    def test_tampered_or_rebound_response_is_not_published(self):
        tampered = copy.deepcopy(self.response)
        tampered["files"][0]["sha256"] = "0" * 64
        rebound = self.rebuilt(lambda envelope: envelope["request"].update(execution_id="gha_other"))
        extra = {**self.response, "files": self.response["files"] + [{"name": "key", "size": 0, "sha256": proof.digest(b""),
                                                                      "content_base64": ""}]}
        missing = self.rebuilt(lambda envelope: envelope["baseline"]["report"]["outcomes"].pop("fixture-preserved"))
        for response in (tampered, rebound, extra, missing):
            with self.subTest(response=response["files"][0]["sha256"]), self.assertRaises(model.ControllerError):
                self.collect(response)
            self.assertFalse((self.root / "public/outcome.json").exists())
