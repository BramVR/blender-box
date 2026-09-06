import copy
import importlib.util
import json
import os
import socket
from pathlib import Path
import struct
import sys
import tempfile
import threading
import unittest
from unittest import mock
import zlib


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("onboarding_proof", ROOT / "scripts/onboarding_proof.py")
proof = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = proof
spec.loader.exec_module(proof)
SHA = "a" * 40
RUN = "bbx_" + "a" * 32


def png(width=2, height=2, *, raw=None, compressed=None, depth=8, color=2, interlace=0, metadata=None):
    def chunk(kind, content):
        return struct.pack(">I", len(content)) + kind + content + struct.pack(">I", zlib.crc32(kind + content))
    if raw is None:
        raw = (b"\x00" + (b"\x00\x80\xff" if color == 2 else b"\x00\x80\xff\xff") * width) * height
    if compressed is None:
        compressed = zlib.compress(raw)
    ancillary = chunk(*metadata) if metadata else b""
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, depth, color, 0, 0, interlace))
            + ancillary + chunk(b"IDAT", compressed) + chunk(b"IEND", b""))


def run_record():
    return {"schema_version": 1, "run_id": RUN, "request_id": "req_" + "b" * 32,
            "request_hash": "c" * 64, "deadline": "2026-09-06T12:00:00+02:00",
            "session_id": "bss_" + "d" * 32, "state": "complete",
            "cleanup": {key: True for key in proof.CLEANUP}}


def write_bundle(root, record=None, result=None):
    record = copy.deepcopy(record or run_record())
    files = {"result/scenario-result.json": proof.canonical(result or proof.BASELINE_RESULT),
             "screenshots/viewport.png": png()}
    entries = []
    for path, content in files.items():
        file = root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(content)
        entry = {"path": path, "type": "viewport" if path.endswith("png") else "scenario-result",
                 "size": len(content), "sha256": proof.digest(content)}
        if entry["type"] == "viewport":
            entry.update(capture_method="offscreen", width=2, height=2)
        entries.append(entry)
    record["evidence"] = {"schema_version": 1, "files": entries}
    save_metadata(root, record)
    return record


def save_metadata(root, record):
    (root / "evidence.json").write_bytes(proof.canonical(record))
    (root / "manifest.json").write_bytes(proof.canonical(record["evidence"]))


def operator_config():
    return {"schema_version": 1, "target": {"schema_version": 1, "ssh_alias": "test-fixture",
            "ssh_user": "test-user", "interactive_user": "test-user", "work_root": "C:\\TestFixture",
            "task_name": "TestFixture", "host_executable": "C:\\TestFixture\\bin\\host.exe",
            "blender_executable": "C:\\Blender\\blender.exe", "session_broker_executable": "C:\\TestFixture\\daemon\\Scripts\\blendersessiond.exe"},
            "expected_host": {"hostname": "TEST-HOST", "windows_build": "19045", "blender_version": "4.5",
                              "identity_sid": "S-1-5-21-1234", "daemon_sha256": "e" * 64},
            "fixture": {"id": "test-fixture", "kind": "shared-existing", "state": "prepared"},
            "authorization": {"candidate_sha": SHA, "fixture_id": "test-fixture", "launch": True, "setup": None}}


def observation(config):
    expected = config["expected_host"]
    return {"schema_version": 1, **{k: v for k, v in expected.items() if k != "identity_sid"},
            "controller_sid": expected["identity_sid"], "console_sid": expected["identity_sid"],
            "configured_ssh_sid": expected["identity_sid"], "configured_interactive_sid": expected["identity_sid"],
            "host_sha256": proof.digest(b"host"), "blender_process_count": 0, "host_lock_present": False}


class AssertionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.record = write_bundle(self.root)

    def test_real_bundle_and_baseline(self):
        artifacts = proof.verify_bundle(self.root, self.record)
        proof.verify_baseline(self.root, artifacts)
        self.assertEqual(len(artifacts), 2)

    def test_duplicate_json_and_wrong_versions(self):
        for value in ('{"schema_version":1,"schema_version":1}', '{"schema_version":true}',
                      '{"schema_version":2}', '{"schema_version":1,"x":NaN}'):
            with self.subTest(value=value), self.assertRaises(proof.ProofError):
                proof.document(value)

    def test_missing_corrupt_unsafe_duplicate_and_changed_evidence(self):
        for mutation in ("missing", "hash", "unsafe", "duplicate", "capture", "dimensions", "identity", "size-bool", "metadata-sentinel"):
            with self.subTest(mutation=mutation):
                record = write_bundle(self.root)
                item = record["evidence"]["files"][1]
                if mutation == "missing":
                    (self.root / item["path"]).unlink()
                elif mutation == "hash":
                    item["sha256"] = "f" * 64
                elif mutation == "unsafe":
                    item["path"] = "../escape.png"
                elif mutation == "duplicate":
                    record["evidence"]["files"].append(copy.deepcopy(item))
                elif mutation == "capture":
                    item["capture_method"] = "desktop"
                elif mutation == "dimensions":
                    item["width"] = 99
                elif mutation == "identity":
                    record["session_id"] = "bss_" + "e" * 32
                elif mutation == "size-bool":
                    item["size"] = True
                elif mutation == "metadata-sentinel":
                    record["evidence"]["files"][0]["capture_method"] = "PRIVATE_SENTINEL"
                save_metadata(self.root, record)
                with self.assertRaises((proof.ProofError, OSError)):
                    proof.verify_bundle(self.root, self.record if mutation == "identity" else record)

    @unittest.skipIf(os.name == "nt", "Symlinks need Windows developer privileges")
    def test_symlink_artifact(self):
        image = self.root / "screenshots/viewport.png"
        image.rename(self.root / "elsewhere.png")
        image.symlink_to(self.root / "elsewhere.png")
        with self.assertRaises(proof.ProofError):
            proof.verify_bundle(self.root, self.record)

    def test_failed_scenario_does_not_become_integrity_failure(self):
        result = dict(proof.BASELINE_RESULT, status="fail")
        record = write_bundle(self.root, result=result)
        artifacts = proof.verify_bundle(self.root, record)
        with self.assertRaisesRegex(proof.ProofError, "baseline-scenario-failed"):
            proof.verify_baseline(self.root, artifacts)

    def test_png_encoding_and_stream(self):
        for image in (png(color=6), png(metadata=(b"sRGB", b"\x00")),
                      png(metadata=(b"gAMA", struct.pack(">I", 45455)))):
            proof.verify_png(image, 2, 2)
        for image in (png(compressed=b"not-zlib"), png(compressed=zlib.compress(b"x")[:-1]),
                      png(compressed=zlib.compress(b"x") + zlib.compress(b"y")),
                      png(raw=b"\x00" * 13), png(raw=b"\x00" * 15),
                      png(raw=b"\x05" + b"\x00" * 13), png(raw=b"\x00" * 100_000),
                      png(depth=16), png(color=3), png(interlace=1)):
            with self.subTest(size=len(image)), self.assertRaises(proof.ProofError):
                proof.verify_png(image, 2, 2)

    def test_png_private_metadata(self):
        for kind in (b"tEXt", b"iTXt", b"zTXt", b"eXIf", b"iCCP"):
            content = png(metadata=(kind, b"PRIVATE_METADATA_SENTINEL"))
            image = self.root / "screenshots/viewport.png"
            image.write_bytes(content)
            record = copy.deepcopy(self.record)
            record["evidence"]["files"][1].update(size=len(content), sha256=proof.digest(content))
            save_metadata(self.root, record)
            with self.subTest(kind=kind), self.assertRaisesRegex(proof.ProofError, "png-metadata-not-allowed"):
                proof.verify_bundle(self.root, record)

    def test_recovery_exact_fence_cleanup_state_and_manifest(self):
        before, after = copy.deepcopy(self.record), copy.deepcopy(self.record)
        stop = dict(self.record, status="settled")
        self.assertEqual(proof.verify_recovery(self.record, before, stop, after), self.record["cleanup"])
        for key, value in (("request_hash", "f" * 64), ("session_id", "bss_" + "f" * 32),
                           ("deadline", "2026-09-06T13:00:00+02:00"), ("state", "failed"),
                           ("evidence", {"schema_version": 1, "files": []}),
                           ("cleanup", {key: 1 for key in proof.CLEANUP})):
            with self.subTest(key=key), self.assertRaises(proof.ProofError):
                proof.verify_recovery(self.record, before, stop, dict(after, **{key: value}))

    def test_deadline_instant_and_nanos(self):
        run = dict(self.record, deadline="2026-09-06T12:00:00.123456789+02:00")
        recovered = dict(self.record, deadline="2026-09-06T10:00:00.123456789Z")
        proof.verify_recovery(run, recovered, dict(recovered, status="settled"), recovered)
        changed = dict(recovered, deadline="2026-09-06T10:00:00.123456788Z")
        with self.assertRaisesRegex(proof.ProofError, "recovery-identity-changed"):
            proof.verify_recovery(run, recovered, dict(recovered, status="settled"), changed)

    def test_recovery_session_must_settle(self):
        before = dict(self.record, state="starting", session_id="")
        stop = dict(before, status="settled")
        after = dict(self.record, state="failed")
        with self.assertRaisesRegex(proof.ProofError, "recovery-identity-changed"):
            proof.verify_recovery(before, before, stop, after)
        for state in ("starting", "running", "collecting", "settling"):
            with self.subTest(state=state), self.assertRaisesRegex(proof.ProofError, "recovery-not-settled"):
                proof.verify_recovery(self.record, self.record, dict(self.record, status="settled"),
                                      dict(self.record, state=state))

    def test_png_framing_crc_and_dimensions(self):
        for data, width in ((png()[:-1], 2), (png() + b"private", 2), (png(), True),
                            (png()[:40] + b"bad" + png()[43:], 2)):
            with self.subTest(width=width), self.assertRaises(proof.ProofError):
                proof.verify_png(data, width, 2)


class FakeCommands(proof.Commands):
    def __init__(self, private, cwd, config, fault=None):
        super().__init__(private, cwd)
        self.config, self.fault, self.calls = config, fault, []
        self.record = None
        self.targets = {}
        self.call_options = []
        self.replacements = 0
        self.imports = []

    def run(self, args, **kwargs):
        args = [str(a) for a in args]
        self.calls.append(args)
        self.call_options.append(kwargs)
        if args[:3] == ["git", "rev-parse", "HEAD"]:
            return (("f" * 40 if self.fault == "candidate" else SHA) + "\n").encode()
        if args[:2] == ["git", "status"]:
            return b""
        if args[:2] == ["go", "build"]:
            Path(args[args.index("-o") + 1]).write_bytes(b"host" if args[args.index("-o") + 1].endswith(".exe") else b"client")
            return b""
        if args[0] == "ssh":
            observed = observation(self.config)
            if self.fault == "wrong-host":
                observed["hostname"] = "WRONG-HOST"
            if self.fault in ("setup-unapproved", "setup-hash"):
                observed["host_sha256"] = "1" * 64
            if self.fault == "no-desktop":
                observed["console_sid"] = None
            return proof.canonical(observed)
        operation = args[1]
        if operation == "targets":
            action = args[2]
            name = args[3] if action != "list" else None
            if action == "import":
                if "--replace" in args:
                    self.replacements += 1
                    if self.fault == "restore-failed" and self.replacements == 2:
                        raise proof.ProofError("command-failed")
                source = Path(args[args.index("--file") + 1])
                imported = json.loads(source.read_bytes())
                self.imports.append(imported)
                self.targets[name] = proof.target_document(proof.windows_target(imported))
                if self.fault == "import-rewrites-source":
                    source.write_bytes(b"changed")
                return proof.canonical({"schema_version": 1, "name": name, "platform": "windows", "status": "imported"})
            if action == "show":
                if self.fault == "show-failed":
                    raise proof.ProofError("command-failed")
                return proof.canonical({"schema_version": 1, "name": name, "platform": "windows", "target": self.targets[name]})
            if action == "list":
                targets = [{"name": name, "platform": "windows"} for name in sorted(self.targets)]
                if self.fault == "list-empty" and targets:
                    targets = []
                return proof.canonical({"schema_version": 1, "targets": targets})
            if action == "forget":
                if self.fault == "forget-failed":
                    raise proof.ProofError("command-failed")
                del self.targets[name]
                return proof.canonical({"schema_version": 1, "name": name, "platform": "windows", "status": "forgotten"})
        if kwargs.get("expected_error"):
            self.assert_sentinel = self.targets[proof.PROOF_TARGET]
            if self.fault == "mismatch-transport":
                guard = Path(kwargs["env"]["PATH"].split(os.pathsep)[0])
                (guard / "attempts").write_text("ssh\n")
            if self.fault in ("mismatch-succeeded", "mismatch-wrong-error"):
                raise proof.ProofError("target-mismatch-not-rejected")
            if self.fault == "mismatch-interrupted":
                self.cancelled.set()
                raise proof.ProofError("interrupted")
            return b""
        if operation in ("status", "stop") and "--target-name" in args:
            original = proof.target_document(proof.windows_target(self.config["target"]))
            if self.targets[proof.PROOF_TARGET] != original:
                raise proof.ProofError("target-does-not-match")
        if operation == "windows":
            if args[2] == "setup":
                return proof.canonical({"schema_version": 1, "status": "plan", "applied": False,
                                        "host_sha256": "0" * 64 if self.fault == "setup-hash" else proof.digest(b"host"), "host_size": 4})
            return proof.canonical({"schema_version": 1, "status": "pass", "checks": [
                {"id": name, "required": True, "passed": True} for name in proof.CHECKS]})
        if operation == "run":
            self.marker(("RUN_ID=" + RUN).encode())
            self.early_report = json.loads((self.private.parent / "public/outcome.json").read_text())
            self.record = write_bundle(self.cwd / "artifacts/blender-box" / RUN)
            if self.fault in ("pre-session", "discovered-session"):
                self.record["state"] = "failed" if self.fault == "pre-session" else "starting"
                self.record.pop("session_id")
                self.record["cleanup"] = {key: False for key in proof.CLEANUP}
            if self.fault == "local-cleanup-unknown":
                self.group_cleanup_known = False
                raise proof.ProofError("command-cleanup-unknown")
            if self.fault in ("run-failed", "status-failed", "cleanup-failed", "pre-session", "discovered-session"):
                raise proof.ProofError("command-failed")
            return proof.canonical(self.record)
        if operation == "status":
            if self.fault == "status-failed":
                raise proof.ProofError("command-failed")
            record = copy.deepcopy(self.record)
            if self.fault == "cleanup-failed":
                record["cleanup"]["lock_released"] = False
            return proof.canonical(record)
        if operation == "stop":
            if self.fault in ("pre-session", "discovered-session"):
                self.record["state"] = "failed"
                self.record["cleanup"] = {key: True for key in proof.CLEANUP}
                if self.fault == "discovered-session":
                    self.record["session_id"] = "bss_" + "d" * 32
            if self.fault == "removed-evidence":
                (self.cwd / "artifacts/blender-box" / RUN / "screenshots/viewport.png").unlink()
            return proof.canonical(dict(self.record, status="settled"))
        raise AssertionError(args)


class ProofFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = operator_config()
        self.path = self.root / "operator.json"
        self.request = proof.ProofRequest(SHA, self.root, self.path, self.root / "output")

    def execute(self, fault=None):
        self.path.write_bytes(proof.canonical(self.config))
        self.path.chmod(0o600)
        def factory(private, cwd):
            self.commands = FakeCommands(private, cwd, self.config, fault)
            return self.commands
        return proof.baseline(self.request, factory)


class BaselineTests(ProofFixture):
    def test_hosted_proofs_refuse_before_contact_without_durable_recovery(self):
        for variant in ("baseline", "named-target"):
            with self.subTest(variant=variant), mock.patch.dict(os.environ, GITHUB_RUN_ATTEMPT="1"):
                self.request = proof.ProofRequest(SHA, self.root, self.path, self.root / variant,
                                                  execution="hosted", driver_sha="b" * 40, proof=variant)
                result = self.execute()
                self.assertEqual(result["status"], "fail")
                self.assertEqual(result["outcomes"]["preparation"]["code"], "hosted-recovery-retention-unavailable")
                self.assertEqual(self.commands.calls, [])
                self.assertIsNone(result["run"])
                self.assertIsNone(result["cleanup"])

    def test_complete_baseline_is_real_local_provenance_and_fixed_public_projection(self):
        result = self.execute()
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["execution"], "local")
        self.assertEqual(self.commands.early_report["status"], "fail")
        self.assertEqual(self.commands.early_report["run"], {"run_id": RUN})
        self.assertEqual(set(result["outcomes"]), set(proof.REQUIRED))
        self.assertEqual(list((self.request.output / "public").iterdir()), [self.request.output / "public/outcome.json"])
        public = (self.request.output / "public/outcome.json").read_text()
        for sentinel in ("TEST-HOST", "test-user", "TestFixture", "S-1-5-21-1234", str(self.root)):
            self.assertNotIn(sentinel, public)
        self.assertEqual(json.loads((self.request.output / "private/run-journal.json").read_text())["run_id"], RUN)

    def test_wrong_target_issue_20_refuses_every_mutation(self):
        result = self.execute("wrong-host")
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["outcomes"]["preparation"]["code"], "wrong-host-identity")
        self.assertEqual([call[0] for call in self.commands.calls], ["git", "git", "ssh"])
        self.assertIsNone(result["cleanup"])

    def test_candidate_rejected_before_ssh(self):
        self.assertEqual(self.execute("candidate")["status"], "fail")
        self.assertFalse(any(call[0] == "ssh" for call in self.commands.calls))

    def test_windows_controller_no_spawn(self):
        commands = proof.Commands(self.root, self.root)
        with mock.patch.object(proof.os, "name", "nt"), mock.patch.object(proof.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(proof.ProofError, "controller-platform-unsupported"):
                commands.run(["unused"])
        spawn.assert_not_called()

    def test_failure_before_session(self):
        result = self.execute("pre-session")
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["cleanup"], {key: True for key in proof.CLEANUP})
        self.assertEqual(result["outcomes"]["recovery"]["status"], "pass")
        self.assertEqual(result["outcomes"]["scenario"]["status"], "fail")

    def test_session_discovered_by_stop(self):
        result = self.execute("discovered-session")
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["cleanup"], {key: True for key in proof.CLEANUP})
        self.assertEqual(result["outcomes"]["recovery"]["status"], "pass")
        self.assertEqual(result["outcomes"]["scenario"]["status"], "fail")

    def test_missing_configuration_before_any_command(self):
        with mock.patch.object(proof.Commands, "run") as command:
            result = proof.baseline(self.request)
        command.assert_not_called()
        self.assertEqual(result["outcomes"]["preparation"]["code"], "operator-config-missing")

    def test_no_desktop_unapproved_setup_and_plan_mismatch(self):
        for fault in ("no-desktop", "setup-unapproved", "setup-hash"):
            with self.subTest(fault=fault):
                self.request = dataclasses_replace(self.request, output=self.root / fault)
                self.assertEqual(self.execute(fault)["status"], "fail")
                self.assertFalse(any("--apply" in call or call[1:2] == ["run"] for call in self.commands.calls))

    def test_failure_recovery_preserves_failure_and_attempts_stop_after_status_error(self):
        for fault in ("run-failed", "status-failed", "cleanup-failed", "removed-evidence"):
            with self.subTest(fault=fault):
                self.request = dataclasses_replace(self.request, output=self.root / fault)
                result = self.execute(fault)
                self.assertEqual(result["status"], "fail")
                self.assertEqual(result["run"]["run_id"], RUN)
                self.assertEqual([c[1] for c in self.commands.calls[-3:]], ["status", "stop", "status"])
                if fault == "run-failed":
                    self.assertEqual(result["cleanup"], {key: True for key in proof.CLEANUP})
                else:
                    self.assertIsNone(result["cleanup"])

    def test_unknown_local_cleanup_stops_recovery(self):
        result = self.execute("local-cleanup-unknown")
        self.assertEqual(result["status"], "fail")
        self.assertIsNone(result["cleanup"])
        self.assertEqual(result["run"], {"run_id": RUN})
        self.assertEqual(self.commands.calls[-1][1], "run")
        self.assertEqual(result["outcomes"]["recovery"]["code"], "command-cleanup-unknown")

    def test_viewport_requires_opt_in(self):
        self.config["publish_viewport"] = True
        self.assertEqual(self.execute()["status"], "pass")
        self.assertEqual((self.request.output / "public/viewport.png").read_bytes(), png())

    def test_setup_authorization_binds_target_candidate_prior_hash_and_scope(self):
        self.path.write_bytes(proof.canonical(self.config))
        self.path.chmod(0o600)
        operator = proof.Operator.load(self.path, SHA)
        auth = {"candidate_sha": SHA, "target_sha256": proof.digest(proof.canonical(operator.target)),
                "prior_host_sha256": None, "scope": "windows-setup-binary-task-acls"}
        operator.authorization["setup"] = auth
        proof.verify_setup_authorization(operator, SHA, None)
        for key in auth:
            bad = dict(auth, **{key: "wrong"})
            operator.authorization["setup"] = bad
            with self.subTest(key=key), self.assertRaises(proof.ProofError):
                proof.verify_setup_authorization(operator, SHA, None)


def dataclasses_replace(value, **changes):
    return proof.dataclasses.replace(value, **changes)


class NamedTargetTests(ProofFixture):
    def setUp(self):
        super().setUp()
        self.request = dataclasses_replace(self.request, proof="named-target")

    def test_named_target_complete_and_private(self):
        result = self.execute()
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["proof"], "windows-onboarding-named-target")
        self.assertEqual(set(result["outcomes"]), set(proof.REQUIRED + proof.NAMED_REQUIRED))
        config_dir = Path(self.commands.env["BLENDER_BOX_CONFIG_DIR"])
        self.assertTrue(config_dir.is_absolute())
        self.assertEqual(config_dir.parent, self.request.output / "private")
        product_calls = [call for call in self.commands.calls if call[0].endswith("blender-box")
                         and call[1:2] in (["run"], ["status"], ["stop"], ["windows"])]
        self.assertTrue(all("--target-name" in call and "--target" not in call for call in product_calls))
        negative = [(call[1], opts) for call, opts in zip(self.commands.calls, self.commands.call_options) if opts.get("expected_error")]
        self.assertEqual([op for op, _ in negative], ["status", "stop"])
        self.assertTrue(all(opts["expected_error"] == "target does not match original Run" for _, opts in negative))
        self.assertEqual(self.commands.assert_sentinel["windows"]["task_name"], self.config["target"]["task_name"])
        self.assertNotEqual(self.commands.assert_sentinel["ssh_alias"], self.config["target"]["ssh_alias"])
        self.assertEqual(self.commands.targets, {})
        public = (self.request.output / "public/outcome.json").read_text()
        for value in ("test-fixture", "test-user", "TestFixture", "TEST-HOST", "onboarding-mismatch", proof.PROOF_TARGET, str(self.root)):
            self.assertNotIn(value, public)

    def test_named_v2_operator_migrates_v1_import_and_preserves_raw_digest(self):
        self.config["target"] = proof.target_document(self.config["target"])
        self.assertEqual(self.execute()["status"], "pass")
        original = json.loads((self.request.output / "private/target.json").read_bytes())
        self.assertEqual(original, self.config["target"])
        first_import = next(call for call in self.commands.calls if call[1:3] == ["targets", "import"])
        self.assertNotIn("--replace", first_import)
        self.assertEqual(self.commands.imports[0]["schema_version"], 1)
        self.assertEqual(self.commands.imports[-1], self.config["target"])

    def test_named_false_success_and_interrupt_restore_before_cleanup(self):
        for fault in ("mismatch-succeeded", "mismatch-wrong-error", "mismatch-transport", "mismatch-interrupted"):
            with self.subTest(fault=fault):
                self.request = dataclasses_replace(self.request, output=self.root / fault)
                result = self.execute(fault)
                self.assertEqual(result["status"], "fail")
                self.assertEqual(result["outcomes"]["target-binding"]["status"], "fail")
                self.assertEqual(result["outcomes"]["target-restoration"]["status"], "pass")
                self.assertEqual(result["cleanup"], {key: True for key in proof.CLEANUP})
                calls = self.commands.calls
                restored = max(i for i, call in enumerate(calls) if call[1:3] == ["targets", "import"])
                stops = [i for i, call in enumerate(calls) if call[1:2] == ["stop"]]
                self.assertLess(stops[0], restored)
                self.assertGreater(stops[1], restored)
                if fault == "mismatch-transport":
                    self.assertEqual(result["outcomes"]["target-binding"]["code"], "target-mismatch-attempted-transport")

    def test_restore_failure_uses_original_file_and_never_passes(self):
        result = self.execute("restore-failed")
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["outcomes"]["target-restoration"]["code"], "target-restore-failed")
        self.assertEqual(result["cleanup"], {key: True for key in proof.CLEANUP})
        recovery = [call for call, opts in zip(self.commands.calls, self.commands.call_options)
                    if opts.get("recovery") and call[1:2] in (["status"], ["stop"])]
        self.assertEqual([call[1] for call in recovery], ["status", "stop", "status"])
        self.assertTrue(all("--target" in call and "--target-name" not in call for call in recovery))

    def test_catalog_and_forget_failures_cannot_pass(self):
        for fault in ("list-empty", "show-failed", "import-rewrites-source", "forget-failed"):
            with self.subTest(fault=fault):
                self.request = dataclasses_replace(self.request, output=self.root / fault)
                result = self.execute(fault)
                self.assertEqual(result["status"], "fail")
                key = "target-forget" if fault == "forget-failed" else "target-catalog"
                self.assertEqual(result["outcomes"][key]["status"], "fail")

    def test_named_missing_and_unsupported_configuration_stays_offline(self):
        with mock.patch.object(proof.Commands, "run") as command:
            result = proof.baseline(self.request)
        command.assert_not_called()
        self.assertEqual(result["status"], "fail")
        self.request = dataclasses_replace(self.request, output=self.root / "unsupported")
        self.config["target"] = dict(proof.target_document(self.config["target"]), platform="linux")
        result = self.execute()
        self.assertEqual(self.commands.calls, [])
        self.assertEqual(result["outcomes"]["preparation"]["code"], "operator-platform-unsupported")

    def test_unknown_cleanup_keeps_profile_and_run_handle(self):
        for fault in ("local-cleanup-unknown", "cleanup-failed"):
            with self.subTest(fault=fault):
                self.request = dataclasses_replace(self.request, output=self.root / fault)
                result = self.execute(fault)
                self.assertEqual(result["status"], "fail")
                self.assertIsNone(result["cleanup"])
                self.assertEqual(result["run"]["run_id"], RUN)
                self.assertIn(proof.PROOF_TARGET, self.commands.targets)
                self.assertFalse(any(call[1:3] == ["targets", "forget"] for call in self.commands.calls))
                self.assertEqual(result["outcomes"]["cleanup"]["code"], "cleanup-unknown")

    def test_failure_recovery_preserves_failure_and_attempts_stop_after_status_error(self):
        for fault in ("run-failed", "status-failed", "cleanup-failed", "removed-evidence"):
            with self.subTest(fault=fault):
                self.request = dataclasses_replace(self.request, output=self.root / fault)
                result = self.execute(fault)
                self.assertEqual(result["status"], "fail")
                recovered = [call[1] for call, opts in zip(self.commands.calls, self.commands.call_options)
                             if opts.get("recovery") and call[1:2] in (["status"], ["stop"])]
                self.assertEqual(recovered, ["status", "stop", "status"])
                if fault == "run-failed":
                    self.assertEqual(result["cleanup"], {key: True for key in proof.CLEANUP})
                else:
                    self.assertIsNone(result["cleanup"])


class OperatorTests(unittest.TestCase):
    def test_target_versions_reject_unknown_fields_types_and_platforms(self):
        v1 = operator_config()["target"]
        v2 = proof.target_document(v1)
        self.assertEqual(proof.windows_target(v2), v1)
        for target in (dict(v1, extra="x"), dict(v1, schema_version=True), dict(v2, platform="linux"),
                       dict(v2, windows=None), dict(v2, windows=dict(v2["windows"], extra="x")),
                       dict(v2, ssh_alias="bad alias"), dict(v2, schema_version=3)):
            with self.subTest(target=target), self.assertRaises(proof.ProofError):
                proof.windows_target(target)

    def test_v2_setup_digest_binds_supplied_document(self):
        raw = proof.target_document(operator_config()["target"])
        operator = proof.Operator(raw, {}, {}, {"setup": {"candidate_sha": SHA,
                                  "target_sha256": proof.digest(proof.canonical(raw)), "prior_host_sha256": None,
                                  "scope": "windows-setup-binary-task-acls"}}, None)
        proof.verify_setup_authorization(operator, SHA, None)
        operator.authorization["setup"]["target_sha256"] = proof.digest(proof.canonical(operator.windows))
        with self.assertRaisesRegex(proof.ProofError, "setup-not-authorized"):
            proof.verify_setup_authorization(operator, SHA, None)

    def test_hosted_credentials_use_trusted_v1_v2_normalization(self):
        for version in (1, 2):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temp:
                config = operator_config()
                config["fixture"] = {"id": "windows-onboarding-prepared-v1", "kind": "dedicated", "state": "prepared"}
                config["authorization"]["candidate_sha"] = "protected-environment-approval"
                if version == 2:
                    config["target"] = proof.target_document(config["target"])
                env = {"OPERATOR_CONFIG": json.dumps(config), "SSH_KEY": "PRIVATE_TEST_KEY",
                       "KNOWN_HOSTS": "TEST_KNOWN_HOST", "SSH_HOSTNAME": "test.invalid", "TS_CLIENT_ID": "test",
                       "TS_CLIENT_SECRET": "test", "CANDIDATE_SHA": SHA, "RUNNER_TEMP": temp}
                proof.prepare_hosted_credentials(env)
                root = Path(temp) / "onboarding-credentials"
                saved = json.loads((root / "operator.json").read_bytes())
                self.assertEqual(saved["target"], config["target"])
                self.assertEqual(saved["authorization"]["candidate_sha"], SHA)
                self.assertIn("Host test-fixture", (root / "config").read_text())
                self.assertIn('User "test-user"', (root / "config").read_text())
                self.assertIn("StrictHostKeyChecking yes", (root / "config").read_text())
        with self.assertRaisesRegex(proof.ProofError, "hosted-credential-missing"):
            proof.prepare_hosted_credentials({})


@unittest.skipIf(os.name != "posix", "Proof controller requires macOS or Linux")
class SubprocessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.commands = proof.Commands(self.root, self.root)

    def test_real_subprocess_json_and_private_stderr(self):
        raw = self.commands.run([sys.executable, "-c", 'import sys; print(\'{"schema_version":1}\'); print("PRIVATE_SENTINEL",file=sys.stderr)'])
        self.assertEqual(proof.document(raw), {"schema_version": 1})
        self.assertIn("PRIVATE_SENTINEL", (self.root / "command-001.stderr").read_text())

    def test_nonzero_plausible_json_and_bounded_output_and_timeout(self):
        cases = [('print(\'{"schema_version":1}\'); raise SystemExit(2)', {}, "command-failed"),
                 ('print("x" * 10000)', {"limit": 128}, "command-output-limit"),
                 ('import threading; threading.Event().wait(30)', {"timeout": .1}, "command-timeout")]
        for source, kwargs, code in cases:
            with self.subTest(code=code), self.assertRaisesRegex(proof.ProofError, code):
                self.commands.run([sys.executable, "-c", source], **kwargs)

    def test_negative_command_requires_nonzero_and_stable_error(self):
        expected = "target does not match original Run"
        for message, code, passes in ((expected, 1, True), (expected, 0, False), ("connection failed", 1, False)):
            source = f"import sys; print({message!r}, file=sys.stderr); raise SystemExit({code})"
            if passes:
                self.commands.run([sys.executable, "-c", source], expected_error=expected)
            else:
                with self.assertRaisesRegex(proof.ProofError, "target-mismatch-not-rejected"):
                    self.commands.run([sys.executable, "-c", source], expected_error=expected)

    def test_transport_tripwire_blocks_both_executables_even_with_correct_error(self):
        client = self.root / "client"
        client.write_text('#!/bin/sh\nssh ignored\nscp ignored\nprintf "%s\\n" "target does not match original Run" >&2\nexit 1\n')
        client.chmod(0o700)
        self.commands.run_id = RUN
        with self.assertRaisesRegex(proof.ProofError, "target-mismatch-attempted-transport"):
            proof.verify_target_mismatch(self.commands, client)
        self.assertEqual((self.root / "transport-tripwire/attempts").read_text().splitlines(), ["ssh", "scp", "ssh", "scp"])

    def test_named_cli_missing_config_returns_failed_private_free_result(self):
        output = self.root / "proof-output"
        result = proof.subprocess.run([sys.executable, str(ROOT / "scripts/onboarding_proof.py"), "named-target",
                                       "--candidate", SHA, "--candidate-checkout", str(self.root),
                                       "--operator-config", str(self.root / "PRIVATE_MISSING_CONFIG"),
                                       "--output", str(output)], capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"Windows onboarding named-target fail.\n")
        self.assertEqual(result.stderr, b"")
        report = json.loads((output / "public/outcome.json").read_bytes())
        self.assertEqual(report["outcomes"]["preparation"]["code"], "operator-config-missing")
        self.assertEqual(set(report["outcomes"]), set(proof.REQUIRED + proof.NAMED_REQUIRED))
        self.assertEqual(list((output / "private").iterdir()), [])
        self.assertNotIn("PRIVATE_MISSING_CONFIG", json.dumps(report))

    @unittest.skipIf(os.name == "nt", "POSIX SIGINT lifecycle")
    def test_cancel_reaps_child(self):
        server = socket.socket()
        self.addCleanup(server.close)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(5)
        port = server.getsockname()[1]
        receipt = self.root / "interrupt-receipt.json"
        child_source = 'import sys; print("ready",flush=True); assert sys.stdin.buffer.readline() == b"stop\\n"'
        source = f'''import json, pathlib, signal, socket, subprocess, sys
child = subprocess.Popen([sys.executable, "-c", {child_source!r}], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
assert child.stdout.readline() == b"ready\\n"
def interrupted(number, frame):
    child.communicate(b"stop\\n", timeout=3)
    pathlib.Path({str(receipt)!r}).write_text(json.dumps({{"signal": number, "child_exit": child.returncode, "child_pid": child.pid}}))
    raise SystemExit(0)
signal.signal(signal.SIGINT, interrupted)
print("RUN_ID={RUN}", file=sys.stderr, flush=True)
with socket.create_connection(("127.0.0.1", {port})) as connection:
    connection.sendall(b"ready")
    signal.pause()
'''
        results = []
        def run():
            try:
                self.commands.run([sys.executable, "-c", source], marker=True)
            except proof.ProofError as error:
                results.append(error.code)
        thread = threading.Thread(target=run)
        thread.start()
        try:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(5)
                self.assertEqual(connection.recv(5), b"ready")
                self.commands.cancelled.set()
                thread.join(5)
        finally:
            self.commands.cancelled.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results, ["interrupted"])
        saved = json.loads(receipt.read_text())
        self.assertEqual(saved["signal"], proof.signal.SIGINT)
        self.assertEqual(saved["child_exit"], 0)
        self.assertEqual(self.commands.run_id, RUN)

    def test_owned_orphan_group(self):
        server = socket.socket()
        self.addCleanup(server.close)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(5)
        port = server.getsockname()[1]
        child_source = f'''import json,os,signal,socket
signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
with socket.create_connection(("127.0.0.1", {port})) as connection:
    connection.sendall((json.dumps({{"pid": os.getpid(), "group": os.getpgrp()}}) + "\\n").encode())
    signal.pause()
'''
        source = f'import subprocess,sys; subprocess.Popen([sys.executable,"-c",{child_source!r}])'
        results = []
        def run():
            try:
                self.commands.run([sys.executable, "-c", source])
            except proof.ProofError as error:
                results.append(error.code)
        thread = threading.Thread(target=run)
        thread.start()
        try:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(10)
                with connection.makefile("rb") as stream:
                    child = json.loads(stream.readline())
                    owned = json.loads((self.root / "command-001.process.json").read_text())
                    self.assertEqual(child["group"], owned["process_group"])
                    self.assertNotEqual(child["pid"], owned["pid"])
                    self.assertEqual(stream.read(1), b"")
        finally:
            thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results, ["command-pipe-timeout"])
        self.assertTrue(self.commands.group_cleanup_known)

    def test_marker_is_durable_before_child_finishes(self):
        server = socket.socket()
        self.addCleanup(server.close)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(5)
        port = server.getsockname()[1]
        source = ('import sys,socket\n'
                  f'print("RUN_ID={RUN}",file=sys.stderr,flush=True)\n'
                  f'connection=socket.create_connection(("127.0.0.1",{port}))\n'
                  'connection.recv(1)\n'
                  'print(\'{"schema_version":1}\')\n')
        durable = threading.Event()
        published = []
        self.commands.on_run_id = published.append
        original_marker = self.commands.marker
        def marker(line):
            original_marker(line)
            durable.set()
        self.commands.marker = marker
        future = []
        thread = threading.Thread(target=lambda: future.append(self.commands.run([sys.executable, "-c", source], marker=True)))
        thread.start()
        connection, _ = server.accept()
        with connection:
            try:
                self.assertTrue(durable.wait(5))
                self.assertTrue(thread.is_alive())
                self.assertEqual(published, [RUN])
                self.assertEqual(json.loads((self.root / "run-journal.json").read_text())["run_id"], RUN)
            finally:
                connection.sendall(b"x")
                thread.join(5)
        self.assertTrue(future)

    def test_bad_markers(self):
        for marker in (f"RUN_ID={RUN}\nRUN_ID={RUN}", "RUN_ID=../unsafe"):
            self.commands = proof.Commands(self.root, self.root)
            self.commands.sequence = 100 if "unsafe" in marker else 0
            with self.subTest(marker=marker), self.assertRaisesRegex(proof.ProofError, "invalid-run-marker"):
                self.commands.run([sys.executable, "-c", f"import sys; print({marker!r},file=sys.stderr)"], marker=True)

    @unittest.skipIf(os.name == "nt", "POSIX hosted SSH shims")
    def test_ssh_shims_snapshot_config_and_enforce_strict_options(self):
        config = self.root / "operator-ssh"
        config.write_text("Host test-fixture\n  HostName fixture.invalid\n")
        config.chmod(0o600)
        proof.configure_ssh(self.commands, config)
        config.write_text("changed")
        self.assertIn("fixture.invalid", (self.root / "ssh-config").read_text())
        executable = self.root / "ssh-bin/ssh"
        self.assertTrue(executable.stat().st_mode & 0o100)
        body = executable.read_text()
        for required in ("BatchMode=yes", "StrictHostKeyChecking=yes", "ForwardAgent=no", "ClearAllForwardings=yes", "-F"):
            self.assertIn(required, body)


class WorkflowTests(unittest.TestCase):
    def test_named_job_requires_successful_baseline_and_reuses_trusted_boundaries(self):
        workflow = (ROOT / ".github/workflows/windows-onboarding-proof.yml").read_text()
        named = workflow.split("  named-target:\n", 1)[1]
        for value in ("needs: [candidate, authorize, baseline]", "environment: windows-onboarding-host",
                      "DRIVER_SHA: ${{ github.workflow_sha }}", "ref: ${{ github.workflow_sha }}",
                      "ref: ${{ needs.candidate.outputs.sha }}", "prepare_hosted_credentials(os.environ)",
                      "python3 driver/scripts/onboarding_proof.py named-target",
                      "onboarding-named-target-proof/public/outcome.json",
                      "name: windows-onboarding-named-target-${{ needs.candidate.outputs.sha }}",
                      '"$RUN_ATTEMPT" == 1', "tags: tag:blender-box-onboarding", "use-cache: false"):
            self.assertIn(value, named)
        self.assertNotIn('config["target"]["ssh_user"]', workflow)
        self.assertEqual(workflow.count("from onboarding_proof import ProofError, prepare_hosted_credentials"), 2)
        baseline_secrets = set(proof.re.findall(r"secrets\.([A-Z_]+)", workflow.split("  baseline:\n")[1].split("  named-target:\n")[0]))
        self.assertEqual(set(proof.re.findall(r"secrets\.([A-Z_]+)", named)), baseline_secrets)
        self.assertFalse(named.lstrip().startswith("if:"))

    def test_trusted_driver_authorization_and_public_upload_contract(self):
        workflow = (ROOT / ".github/workflows/windows-onboarding-proof.yml").read_text()
        for text in ("name: Windows onboarding proof", "name: baseline", "workflow_dispatch:",
                     "needs: [candidate, authorize]", "environment: windows-onboarding-approval",
                     "environment: windows-onboarding-host", "cancel-in-progress: false", "timeout-minutes: 75",
                     '"$RUN_ATTEMPT" == 1', '"$REQUEST_REF" == refs/heads/main', '"$REQUEST_ACTOR" == BramVR',
                     "ref: ${{ github.workflow_sha }}", "ref: ${{ needs.candidate.outputs.sha }}",
                     "python3 driver/scripts/onboarding_proof.py baseline", "--execution hosted", "persist-credentials: false",
                     "windows-onboarding-prepared-v1", "if-no-files-found: error", "prepare_hosted_credentials(os.environ)"):
            self.assertIn(text, workflow)
        for forbidden in ("pull_request:", "push:", "continue-on-error", "candidate/scripts/onboarding_proof.py",
                          "artifacts/**", "/private/", "~/.ssh", "$HOME", "StrictHostKeyChecking no"):
            self.assertNotIn(forbidden, workflow)
        upload = workflow.split("name: Upload allowlisted proof", 1)[1].split("name: Remove only", 1)[0]
        self.assertIn("/public/outcome.json", upload)
        self.assertIn("/public/viewport.png", upload)
        self.assertNotIn("*", upload)


if __name__ == "__main__":
    unittest.main()
