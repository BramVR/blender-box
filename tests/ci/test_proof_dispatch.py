from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

import test_proof_controller as baseline
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
        self.assertIn(b'IdentityAgent "none"', (self.root / "ssh-config").read_bytes())
        self.assertEqual((self.root / "key").stat().st_mode & 0o777, 0o600)

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
