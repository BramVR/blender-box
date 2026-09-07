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
EXIF_RESOLUTION = (b"MM\x00*" + struct.pack(">IIIIIH", 24, 72, 1, 72, 1, 2)
                   + struct.pack(">HHIIHHIII", 282, 5, 1, 8, 283, 5, 1, 16, 0))


def png(width=2, height=2, *, raw=None, compressed=None, depth=8, color=2, interlace=0, metadata=None):
    def chunk(kind, content):
        return struct.pack(">I", len(content)) + kind + content + struct.pack(">I", zlib.crc32(kind + content))
    if raw is None:
        raw = (b"\x00" + (b"\x00\x80\xff" if color == 2 else b"\x00\x80\xff\xff") * width) * height
    if compressed is None:
        compressed = zlib.compress(raw)
    metadata = metadata if isinstance(metadata, list) else [metadata] if metadata else []
    ancillary = b"".join(chunk(*item) for item in metadata)
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

    def test_png_numeric_resolution(self):
        content = png(metadata=[(b"eXIf", EXIF_RESOLUTION), (b"oFFs", struct.pack(">iiB", 0, 0, 0))])
        before = proof.digest(content)
        proof.verify_png(content, 2, 2)
        self.assertEqual(proof.digest(content), before)


    def test_png_exif_rejects_other_data(self):
        cases = [EXIF_RESOLUTION + b"PRIVATE_METADATA_SENTINEL", EXIF_RESOLUTION[:-1],
                 b"II" + EXIF_RESOLUTION[2:], EXIF_RESOLUTION[:4] + struct.pack(">I", 26) + EXIF_RESOLUTION[8:],
                 EXIF_RESOLUTION[:26] + struct.pack(">H", 315) + EXIF_RESOLUTION[28:],
                 EXIF_RESOLUTION[:28] + struct.pack(">H", 2) + EXIF_RESOLUTION[30:],
                 EXIF_RESOLUTION[:30] + struct.pack(">I", 2) + EXIF_RESOLUTION[34:],
                 EXIF_RESOLUTION[:34] + struct.pack(">I", 16) + EXIF_RESOLUTION[38:],
                 EXIF_RESOLUTION[:12] + struct.pack(">I", 0) + EXIF_RESOLUTION[16:],
                 EXIF_RESOLUTION[:50] + struct.pack(">I", 8)]
        for exif in cases:
            with self.subTest(exif=exif.hex()), self.assertRaises(proof.ProofError):
                proof.verify_png(png(metadata=(b"eXIf", exif)), 2, 2)
        for offsets in (struct.pack(">iiB", 1, 0, 0), struct.pack(">iiB", 0, 0, 1), b"PRIVATE_METADATA_SENTINEL"):
            with self.subTest(offsets=offsets.hex()), self.assertRaises(proof.ProofError):
                proof.verify_png(png(metadata=(b"oFFs", offsets)), 2, 2)


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
        self.host_sha256 = "1" * 64 if fault in ("setup-unapproved", "setup-hash", "setup-approved") else proof.digest(b"host")

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
            observed["host_sha256"] = self.host_sha256
            if self.fault == "wrong-host":
                observed["hostname"] = "WRONG-HOST"
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
                applied = "--apply" in args
                if applied:
                    self.host_sha256 = proof.digest(b"host")
                return proof.canonical({"schema_version": 1, "status": "applied" if applied else "plan", "applied": applied,
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
                if fault in ("run-failed", "removed-evidence"):
                    self.assertEqual(result["cleanup"], {key: True for key in proof.CLEANUP})
                    self.assertEqual(result["outcomes"]["recovery"]["status"], "pass")
                    if fault == "removed-evidence":
                        self.assertEqual(result["outcomes"]["evidence"]["status"], "fail")
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

    def test_legacy_apply_grant_reports_refusal_without_bypassing_installer(self):
        self.config["authorization"]["setup"] = {"candidate_sha": SHA,
            "target_sha256": proof.digest(proof.canonical(self.config["target"])),
            "prior_host_sha256": "1" * 64, "scope": "windows-setup-binary-task-acls"}
        result = self.execute("setup-unapproved")
        self.assertEqual(result["outcomes"]["preparation"]["code"], "legacy-setup-unowned")
        self.assertFalse(any("--apply" in call for call in self.commands.calls))


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

    def test_named_legacy_apply_refusal_preserves_host(self):
        for version in (1, 2):
            with self.subTest(version=version):
                self.request = dataclasses_replace(self.request, output=self.root / f"setup-v{version}")
                self.config = operator_config()
                if version == 2:
                    self.config["target"] = proof.target_document(self.config["target"])
                self.config["authorization"]["setup"] = {
                    "candidate_sha": SHA, "target_sha256": proof.digest(proof.canonical(self.config["target"])),
                    "prior_host_sha256": "1" * 64, "scope": "windows-setup-binary-task-acls"}
                result = self.execute("setup-approved")
                self.assertEqual(result["status"], "fail")
                self.assertEqual(result["outcomes"]["preparation"]["code"], "legacy-setup-unowned")
                self.assertFalse(any("--apply" in call for call in self.commands.calls))
                self.assertEqual(self.commands.host_sha256, "1" * 64)

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
                if fault in ("run-failed", "removed-evidence"):
                    self.assertEqual(result["cleanup"], {key: True for key in proof.CLEANUP})
                    self.assertEqual(result["outcomes"]["recovery"]["status"], "pass")
                    if fault == "removed-evidence":
                        self.assertEqual(result["outcomes"]["evidence"]["status"], "fail")
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

    def test_post_spawn_failure(self):
        for fault in ("receipt", "reader-start", "writer-start", "observation"):
            with self.subTest(fault=fault), socket.socket() as server:
                private = self.root / fault
                private.mkdir()
                commands = proof.Commands(private, self.root)
                server.bind(("127.0.0.1", 0))
                server.listen(1)
                server.settimeout(5)
                port = server.getsockname()[1]
                child_source = 'import sys; print("ready",flush=True); assert sys.stdin.buffer.readline() == b"stop\\n"'
                source = f'''import json,signal,socket,subprocess,sys
child=subprocess.Popen([sys.executable,"-c",{child_source!r}],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
assert child.stdout.readline()==b"ready\\n"
with socket.create_connection(("127.0.0.1",{port})) as connection:
    def settle(number):
        child.communicate(b"stop\\n",timeout=3)
        connection.sendall((json.dumps({{"signal":number,"child_exit":child.returncode}})+"\\n").encode())
    def interrupted(number,frame):
        settle(number)
        raise SystemExit(0)
    signal.signal(signal.SIGINT,interrupted)
    print("RUN_ID={RUN}",file=sys.stderr,flush=True)
    connection.sendall(b"ready\\n")
    connection.recv(1)
    settle(None)
'''
                connections, leaders = [], []
                original_write = Path.write_bytes
                original_spawn = proof.subprocess.Popen
                original_start = threading.Thread.start
                original_observe = os.waitid
                starts = 0
                observed = False

                def ready():
                    connection, _ = server.accept()
                    connection.settimeout(2)
                    stream = connection.makefile("rb")
                    connections.append((connection, stream))
                    self.assertEqual(stream.readline(), b"ready\n")

                def write(path, content):
                    if fault == "receipt" and path.name.endswith(".process.json"):
                        ready()
                        raise OSError("injected-receipt")
                    return original_write(path, content)

                def spawn(*args, **kwargs):
                    process = original_spawn(*args, **kwargs)
                    if not leaders:
                        leaders.append(process)
                    return process

                def start(thread):
                    nonlocal starts
                    starts += 1
                    if (fault == "reader-start" and starts == 2) or (fault == "writer-start" and starts == 3):
                        ready()
                        raise RuntimeError("injected-" + fault)
                    return original_start(thread)

                def observe(*args):
                    nonlocal observed
                    if fault == "observation" and not observed:
                        observed = True
                        ready()
                        raise OSError("injected-observation")
                    return original_observe(*args)

                try:
                    with mock.patch.object(Path, "write_bytes", write), mock.patch.object(proof.subprocess, "Popen", spawn), \
                            mock.patch.object(threading.Thread, "start", start), mock.patch.object(os, "waitid", observe):
                        with self.assertRaisesRegex((OSError, RuntimeError), "injected-" + fault):
                            commands.run([sys.executable, "-c", source], marker=True,
                                         stdin=b"input" if fault == "writer-start" else None)
                    connection, stream = connections[0]
                    receipt = json.loads(stream.readline())
                    self.assertEqual(receipt, {"signal": proof.signal.SIGINT, "child_exit": 0})
                    self.assertEqual(stream.read(), b"")
                    self.assertTrue(commands.group_cleanup_known)
                    self.assertEqual(commands.process_identity["pid"], leaders[0].pid)
                    self.assertEqual(commands.process_identity["process_group"], leaders[0].pid)
                    self.assertEqual(leaders[0].returncode, 0)
                    self.assertEqual(commands.run_id, RUN)
                finally:
                    for connection, stream in connections:
                        try:
                            connection.sendall(b"x")
                        except OSError:
                            pass
                        stream.close()
                        connection.close()
                    for process in leaders:
                        process.wait(timeout=5)
                        for pipe in (process.stdout, process.stderr):
                            if pipe is not None and not pipe.closed:
                                pipe.close()


    def test_cleanup_grace(self):
        server = socket.socket()
        self.addCleanup(server.close)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(5)
        port = server.getsockname()[1]
        source = f'''import signal,socket
with socket.create_connection(("127.0.0.1", {port})) as connection:
    def interrupted(number, frame):
        connection.sendall(b"interrupted")
        connection.recv(1)
        raise SystemExit(0)
    signal.signal(signal.SIGINT, interrupted)
    connection.sendall(b"ready")
    signal.pause()
'''
        results = []
        def run():
            try:
                self.commands.json([sys.executable, "-c", source], cleanup_grace=0.05)
            except proof.ProofError as error:
                results.append(error.code)
        thread = threading.Thread(target=run)
        thread.start()
        connection, _ = server.accept()
        with connection:
            try:
                connection.settimeout(4)
                with connection.makefile("rb") as stream:
                    self.assertEqual(stream.read(5), b"ready")
                    self.commands.cancelled.set()
                    self.assertEqual(stream.read(11), b"interrupted")
                    self.assertEqual(stream.read(1), b"")
            finally:
                try:
                    connection.sendall(b"x")
                except OSError:
                    pass
                self.commands.cancelled.set()
                thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results, ["interrupted"])
        self.assertTrue(self.commands.group_cleanup_known)


    def test_real_subprocess_json_and_private_stderr(self):
        raw = self.commands.run([sys.executable, "-c", 'import sys; print(\'{"schema_version":1}\'); print("PRIVATE_SENTINEL",file=sys.stderr)'])
        self.assertEqual(proof.document(raw), {"schema_version": 1})
        self.assertIn("PRIVATE_SENTINEL", (self.root / "command-001.stderr").read_text())

    def test_streamed_input_round_trip_and_nonreading_child_timeout(self):
        content = ("C:\\Blender boîte\\\u2603\n" * 1000).encode("utf-8")
        result = self.commands.json([sys.executable, "-c",
                                    'import hashlib,json,sys; data=sys.stdin.buffer.read(); print(json.dumps({"schema_version":1,"sha256":hashlib.sha256(data).hexdigest()}))'],
                                    stdin=content)
        self.assertEqual(result["sha256"], proof.digest(content))
        self.assertEqual((self.root / "command-001.stdin").read_bytes(), content)
        with self.assertRaisesRegex(proof.ProofError, "command-timeout"):
            self.commands.run([sys.executable, "-c", "import threading; threading.Event().wait()"],
                              stdin=b"x" * (128 << 10), timeout=.1)
        self.assertTrue(self.commands.group_cleanup_known)
        sequence = self.commands.sequence
        with self.assertRaisesRegex(proof.ProofError, "command-input-limit"):
            self.commands.run([sys.executable, "-c", "raise AssertionError('must not spawn')"],
                              stdin=b"x" * ((128 << 10) + 1))
        self.assertEqual(self.commands.sequence, sequence)

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
    def test_installer_job_is_separate_serialized_and_blocked_before_host_credentials(self):
        workflow = (ROOT / ".github/workflows/windows-onboarding-proof.yml").read_text()
        installer = workflow.split("  host-install:\n", 1)[1]
        for value in ("name: host-install", "needs: [candidate, named-target]", "if: always() && needs.candidate.result == 'success'",
                      "environment: windows-onboarding-installer", "DRIVER_SHA: ${{ github.workflow_sha }}",
                      "ref: ${{ github.workflow_sha }}", "ONBOARDING_INSTALL_OPERATOR_CONFIG",
                      'value.get("authorization", {}).get("candidate_sha") != os.environ["CANDIDATE_SHA"]',
                      "python3 driver/scripts/onboarding_proof.py host-install", "--execution hosted --driver-sha",
                      "onboarding-host-install-proof/public/outcome.json"):
            self.assertIn(value, installer)
        for value in ("ONBOARDING_SSH", "ONBOARDING_TS", "tailscale/github-action", "prepare_hosted_credentials",
                      "protected-environment-approval", "candidate/scripts", "continue-on-error", "/private/", "*.json"):
            self.assertNotIn(value, installer)
        self.assertEqual(set(proof.re.findall(r"secrets\.([A-Z_]+)", installer)), {"ONBOARDING_INSTALL_OPERATOR_CONFIG"})
        self.assertIn("group: windows-onboarding-prepared-v1", workflow)

    def test_named_job_requires_successful_baseline_and_reuses_trusted_boundaries(self):
        workflow = (ROOT / ".github/workflows/windows-onboarding-proof.yml").read_text()
        named = workflow.split("  named-target:\n", 1)[1].split("  host-install:\n", 1)[0]
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


INSTALL_ID = "bbxi_" + "1" * 32


def installer_config(root):
    config = operator_config()
    installation = {"id": INSTALL_ID, "state_root": r"C:\TestFixture", "task_name": "DisposableInstallProof",
                    "blender": r"C:\Blender\blender.exe", "python": r"C:\Python\python.exe",
                    "target_out": r"C:\ProofExport\target.json"}
    manifest = {"schema_version": 1, "platform": "windows", "architecture": "amd64", "python_requires": ">=3.11,<4",
                "daemon_protocol": "blender-box-v1", "daemon_capabilities": ["typed-call-error-reason"], "artifacts": []}
    for role, name, content in (("host-executable", "host.exe", b"host"), ("daemon-launcher", "broker.exe", b"broker"),
                                ("daemon-wheel", "daemon.whl", b"wheel")):
        manifest["artifacts"].append({"role": role, "name": "C:\\Pinned\\" + name, "size": len(content),
                                      "sha256": proof.digest(content), "provenance": {"repository": "BramVR/blender-box",
                                      "source_commit": SHA, "patch_sha256": "2" * 64, "build_recipe_sha256": "3" * 64}})
    local = root / "manifest.json"
    raw = proof.canonical(manifest)
    local.write_bytes(raw)
    return {"schema_version": 1, "platform": "windows", "connection": {"ssh_alias": "test-fixture", "windows_user": "test-user"},
            "expected_host": dict(config["expected_host"], daemon_sha256=proof.digest(b"broker")),
            "fixture": {"id": "installer-dedicated-fixture", "kind": "dedicated", "state": "absent"},
            "installation": installation, "bootstrap": {"path": r"C:\Bootstrap\bootstrap.exe", "size": 9,
                                                         "sha256": proof.digest(b"bootstrap")},
            "runtime": {"local_manifest": str(local), "remote_manifest": {"path": r"C:\Pinned\manifest.json",
                                                                      "size": len(raw), "sha256": proof.digest(raw)}},
            "before_state": {"installation_absent": True, "task_absent": True, "target_absent": True,
                             "unrelated_files": [{"path": r"C:\ExistingFixture\precious.blend", "size": 9,
                                                  "sha256": proof.digest(b"precious!")}],
                             "unrelated_tasks": [{"name": "ExistingFixture", "xml_sha256": proof.digest(b"<task/>")}]}}


def authorize_installer(config):
    config["authorization"] = {"candidate_sha": SHA, "fixture_id": config["fixture"]["id"],
                               "installation_id": config["installation"]["id"],
                               "manifest_sha256": config["runtime"]["remote_manifest"]["sha256"],
                               "scope": "host-install-run-remove", "launch": True}
    for key, source in (("destination", "installation"), ("before_state", "before_state"), ("bootstrap", "bootstrap"),
                        ("connection", "connection"), ("expected_host", "expected_host")):
        config["authorization"][key + "_sha256"] = proof.digest(proof.canonical(config[source]))


class FakeInstallCommands(FakeCommands):
    def __init__(self, private, cwd, config, fault=None):
        super().__init__(private, cwd, config, fault)
        self.operator = proof.InstallOperator.load(cwd / "operator.json", SHA)
        self.remote = cwd / "remote"
        self.remote.mkdir()
        self.installer_actions = []
        self.execution_results = {}
        self.stopped_execution = None
        self.installation_state = "planned"
        self.removal_calls = 0
        for path, content in ((self.operator.bootstrap["path"], b"bootstrap"),
                              (self.operator.manifest_pin["path"], (cwd / "manifest.json").read_bytes()),
                              (r"C:\Pinned\host.exe", b"host"), (r"C:\Pinned\broker.exe", b"broker"),
                              (r"C:\Pinned\daemon.whl", b"wheel"),
                              (r"C:\ExistingFixture\precious.blend", b"precious!")):
            local = self.remote_file(path)
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(content)
        if fault == "bootstrap-pin":
            self.remote_file(self.operator.bootstrap["path"]).write_bytes(b"different")
        if fault == "artifact-pin":
            self.remote_file(r"C:\Pinned\daemon.whl").write_bytes(b"changed")
        self.unrelated_task = self.remote / "unrelated-task.xml"
        self.unrelated_task.write_bytes(b"<task/>")
        self.receipt = self.remote / "installation" / "receipt.json"
        self.owned_runtime = self.remote / "installation" / "runtime.bin"
        self.owned_task = self.remote / "owned-task.xml"
        if fault == "before-state":
            self.owned_task.write_bytes(b"unknown existing task")
        if fault == "cancel-before":
            self.cancelled.set()

    def remote_file(self, path):
        return self.remote.joinpath(*proof.PureWindowsPath(path).parts[1:])

    def run(self, args, **kwargs):
        proof.require(kwargs.get("recovery") or not self.cancelled.is_set(), "interrupted")
        args = [str(a) for a in args]
        if args[0] != "ssh":
            if args[1:2] == ["run"] and self.fault == "no-run-marker":
                self.calls.append(args)
                self.call_options.append(kwargs)
                raise proof.ProofError("command-failed")
            result = super().run(args, **kwargs)
            if args[1:2] == ["run"] and self.fault == "bad-evidence":
                (self.cwd / "artifacts/blender-box" / RUN / "screenshots/viewport.png").write_bytes(b"broken")
            return result
        self.sequence += 1
        self.calls.append(args)
        self.call_options.append(kwargs)
        proof.require(len(" ".join(args[args.index("--") + 2:])) < 8000, "windows-shell-command-limit")
        script = kwargs["stdin"].decode("utf-8")
        if "$inputData" not in script:
            observed = observation(self.config)
            if self.fault == "wrong-host":
                observed["hostname"] = "WRONG-HOST"
            return proof.canonical(observed)
        encoded = proof.re.search(r"FromBase64String\('([^']+)'\)", script).group(1)
        inputs = json.loads(proof.base64.b64decode(encoded))
        if "before" in inputs:
            files = []
            for pin in inputs["before"]["unrelated_files"]:
                content = self.remote_file(pin["path"]).read_bytes()
                files.append(dict(pin, size=len(content), sha256=proof.digest(content)))
            tasks = [dict(item, xml_sha256=proof.digest(self.unrelated_task.read_bytes()))
                     for item in inputs["before"]["unrelated_tasks"]]
            result = {"schema_version": 1, "installation_absent": not self.receipt.exists(),
                      "task_absent": not self.owned_task.exists(),
                      "target_absent": not self.remote_file(self.operator.installation["target_out"]).exists(),
                      "unrelated_files": files, "unrelated_tasks": tasks}
            if self.fault == "observation-extra":
                result["surprise"] = "PRIVATE"
            return proof.canonical(result)
        if "path" in inputs:
            raw = self.remote_file(inputs["path"]).read_bytes()
            if self.fault == "target-fetch":
                raw = proof.canonical(dict(json.loads(raw), ssh_alias="unexpected-host"))
            return proof.canonical({"schema_version": 1, "content": proof.base64.b64encode(raw).decode(),
                                    "sha256": proof.digest(raw)})
        for pin in inputs["pins"]:
            content = self.remote_file(pin["path"]).read_bytes()
            proof.require(len(content) == pin["size"] and proof.digest(content) == pin["sha256"], "command-failed")
        cli = inputs["args"]
        operation, apply = cli[1], "--apply" in cli
        self.installer_actions.append((operation, apply, kwargs.get("recovery", False)))
        if operation != "inspect":
            operation_id = cli[cli.index("--operation") + 1]
            journal = json.loads((self.private / "installer-operations.json").read_bytes())
            proof.require(journal["installation_id"] == INSTALL_ID
                          and operation_id in journal["operations"].values(),
                          "installer-operation-changed")
        if operation in ("status", "stop"):
            proof.require(operation_id in self.execution_results, "installer-execution-unknown")
            result = copy.deepcopy(self.execution_results[operation_id])
            if operation == "stop":
                token = cli[cli.index("--execution") + 1]
                proof.require(token == result["execution"]["token"], "installer-execution-changed")
                self.stopped_execution = token
                result["execution"]["cancel_requested"] = True
                result["execution"]["fence_state"] = "released"
                self.execution_results[operation_id] = copy.deepcopy(result)
            if self.fault in ("lost-active-response", "lost-stop-response", "execution-token-changed") and self.stopped_execution is None:
                result["state"] = "running"
                result["completion"] = "unknown"
                result["execution"].update(state="running", tree_cleanup="unknown", task_mutation="unknown", fence_state="held")
            if self.fault == "keeper-lost-response":
                result["state"] = "unknown"
                result["completion"] = "unknown"
                result["execution"].update(state="unknown", tree_cleanup="unknown", task_mutation="unknown", fence_state="held")
            if self.fault == "lost-stop-response" and operation == "stop":
                raise proof.ProofError("command-failed")
            if self.fault == "execution-token-changed" and self.stopped_execution:
                result["execution"]["token"] = "bbxe_" + "e" * 32
            return proof.canonical({"schema_version": 1, "exit_code": 0, "output": json.dumps(result)})
        if operation == "install" and apply:
            self.receipt.parent.mkdir(exist_ok=True)
            self.receipt.write_bytes(b"owned receipt")
            self.owned_runtime.write_bytes(b"owned runtime")
            self.owned_task.write_bytes(b"owned task")
            self.installation_state = "installed"
        if operation == "remove" and apply:
            self.removal_calls += 1
            if self.fault == "remove-failed":
                return proof.canonical({"schema_version": 1, "exit_code": 1,
                                        "output": '{"schema_version":1,"installation_id":"' + INSTALL_ID + '","state":"partial"}'})
            self.owned_task.unlink(missing_ok=True)
            self.owned_runtime.unlink(missing_ok=True)
            self.receipt.write_bytes(b"removed tombstone")
            self.installation_state = "removed"
            if self.fault == "unrelated-changed":
                self.remote_file(r"C:\ExistingFixture\precious.blend").write_bytes(b"changed!!")
        target = dict(self.operator.windows)
        runtime = proof.windows_path(self.operator.installation["state_root"]) / "installations" / INSTALL_ID / "runtime"
        target.update(host_executable=str(runtime / "blender-box.exe"), session_broker_executable=str(runtime / "blendersessiond.exe"))
        if self.fault == "target-result":
            target["ssh_alias"] = "unexpected-host"
        target = proof.target_document(target)
        if "--target-out" in cli and apply:
            path = self.remote_file(cli[cli.index("--target-out") + 1])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(proof.canonical(target))
        plan_hash = "4" * 64 if operation == "install" else "5" * 64
        def candidate(path):
            return {"path": path, "version": "3.12", "sha256": proof.digest(b"selected"), "identity": "test-volume:selected-id"}
        python = {"candidate": candidate(self.operator.installation["python"]), "home": r"C:\Python",
                  "template": candidate(r"C:\Python\Lib\venv\scripts\nt\python.exe"),
                  "dll": candidate(r"C:\Python\python312.dll"), "venv_source": candidate(r"C:\Python\Lib\venv\__init__.py")}
        files = [{"path": "runtime", "kind": "directory", "size": 0},
                 {"path": "runtime/blender-box.exe", "kind": "file", "size": 4, "sha256": proof.digest(b"host")},
                 {"path": "runtime/blendersessiond.exe", "kind": "file", "size": 6, "sha256": proof.digest(b"broker")}]
        result = {"schema_version": 1, "installation_id": INSTALL_ID, "state": self.installation_state, "completion": "known",
                  "inspection": {"owner_sid": self.operator.expected["identity_sid"], "root_identity": "test-volume:file-id",
                                 "blender_candidates": [candidate(self.operator.installation["blender"])], "python": python},
                  "plan": {"plan_sha256": plan_hash, "manifest_sha256": self.operator.manifest_sha256, "files": files},
                  "files": [dict(item, identity="test-volume:" + item["path"]) for item in files] if self.receipt.exists() else [],
                  "retained": [], "problems": [], "target_publication": {"status": "not-requested"}}
        if "--target-out" in cli:
            result["target_publication"] = {"status": "published" if apply else "not-published", "path": self.operator.installation["target_out"]}
        if "--installation" not in cli:
            result.pop("installation_id")
        if apply:
            root = proof.windows_path(self.operator.installation["state_root"])
            result["retained"] = [str(root), str(root / ".operation.lock"), str(root / ".launch.lock"), str(root / "runs"),
                                  str(root / "receipts"), str(root / "installations" / INSTALL_ID / "receipt.json")]
        if operation != "inspect":
            result["operation_id"] = cli[cli.index("--operation") + 1]
        if operation == "install":
            result["target"] = target
        if self.fault == "owner-changed":
            result["inspection"]["owner_sid"] = "S-1-5-21-9999"
        if self.fault == "identity-changed":
            result["installation_id"] = "bbxi_" + "9" * 32
        if self.fault == "unknown-state":
            result["state"] = "maybe-installed"
        if self.fault == "unknown-completion":
            result["completion"] = "unknown"
        if self.fault == "result-extra":
            result["surprise"] = "PRIVATE"
        if self.fault == "python-selection":
            result["inspection"]["python"]["candidate"]["path"] = r"C:\OtherPython\python.exe"
        if self.fault == "inventory-extra":
            result["plan"]["files"][0]["surprise"] = "PRIVATE"
        if self.fault == "inventory-missing":
            result["plan"]["files"] = []
        if self.fault == "plan-changed" and apply and operation == "install":
            result["plan"]["plan_sha256"] = "9" * 64
        if self.fault == "cancel-after-install" and apply and operation == "install":
            self.cancelled.set()
        if apply:
            result["execution"] = {"token": "bbxe_" + ("b" if operation == "install" else "c") * 32,
                                   "request_sha256": "d" * 64, "deadline": "2026-09-06T12:00:00Z",
                                   "state": "terminal", "process_state": "started", "fence_state": "released", "tree_cleanup": "known", "task_mutation": "settled",
                                   "cancel_requested": False, "keeper": {"pid": 101, "created_filetime": "1001"},
                                   "worker": {"pid": 102, "created_filetime": "1002"}}
            self.execution_results[operation_id] = copy.deepcopy(result)
        if self.fault == "apply-partial" and apply and operation == "install":
            result["state"] = "partial"
            result["problems"] = [{"code": "interrupted", "message": "PRIVATE FAILURE"}]
            self.execution_results[operation_id] = copy.deepcopy(result)
            return proof.canonical({"schema_version": 1, "exit_code": 1, "output": json.dumps(result)})
        if self.fault in ("lost-apply-response", "lost-active-response", "keeper-lost-response", "execution-token-changed", "lost-stop-response") and operation == "install" and apply:
            raise proof.ProofError("command-failed")
        if self.fault == "lost-remove-response" and operation == "remove" and apply and self.removal_calls == 1:
            raise proof.ProofError("command-failed")
        if self.fault == "publication-failed" and "--target-out" in cli and apply:
            result["target_publication"].update(status="failed", error="PRIVATE target export failure")
            self.execution_results[operation_id] = copy.deepcopy(result)
            return proof.canonical({"schema_version": 1, "exit_code": 1, "output": json.dumps(result)})
        return proof.canonical({"schema_version": 1, "exit_code": 0, "output": json.dumps(result)})


class InstallerRecoveryTests(unittest.TestCase):
    def observation(self, state="terminal", *, process_state=None, fence="released", **changes):
        process_state = process_state or ("unknown" if state == "unknown" else "started")
        execution = {"token": "bbxe_" + "b" * 32, "request_sha256": "d" * 64,
                     "deadline": "2026-09-06T12:00:00Z", "state": state, "process_state": process_state,
                     "fence_state": fence, "tree_cleanup": "known" if state == "terminal" else "unknown",
                     "task_mutation": "settled" if state == "terminal" else "unknown", "cancel_requested": False}
        if process_state != "unknown":
            execution["keeper"] = {"pid": 101, "created_filetime": "1001"}
        if process_state == "started":
            execution["worker"] = {"pid": 102, "created_filetime": "1002"}
        execution.update(changes)
        return {"state": "partial" if process_state == "not-started" else "installed" if state == "terminal" else state,
                "completion": "known" if state == "terminal" else "unknown", "execution": execution}

    def recover(self, responses, *, error=None, tick=0.1):
        pending = list(responses)
        now = [0.0]
        def wait(seconds):
            self.assertEqual(seconds, 0.1)
            now[0] += tick
        def call(commands, operator, operation, **kwargs):
            expected_operation, response = pending.pop(0)
            self.assertEqual(operation, expected_operation)
            self.assertEqual(kwargs["operation_id"], "bbxo_" + "a" * 32)
            self.assertTrue(kwargs["recovery"])
            self.assertTrue(kwargs["target_out"])
            if operation == "stop":
                self.assertTrue(kwargs["apply"])
                self.assertEqual(kwargs["execution_token"], "bbxe_" + "b" * 32)
            else:
                self.assertEqual(operation, "status")
                self.assertNotIn("apply", kwargs)
                self.assertEqual(kwargs["expected_plan"], "4" * 64)
            if isinstance(response, Exception):
                raise response
            return copy.deepcopy(response)
        with mock.patch.object(proof, "installer_call", side_effect=call), \
                mock.patch.object(proof.time, "monotonic", side_effect=lambda: now[0]), \
                mock.patch.object(proof.threading.Event, "wait", side_effect=wait):
            if error:
                with self.assertRaisesRegex(proof.ProofError, error):
                    proof.recover_installer(None, None, "bbxo_" + "a" * 32, "4" * 64, target_out=True)
                result = None
            else:
                result = proof.recover_installer(None, None, "bbxo_" + "a" * 32, "4" * 64, target_out=True)
        self.assertEqual(pending, [])
        return result

    def test_admission_unknown_can_publish_first_process_identities_and_settle(self):
        pending = self.observation("unknown", fence="held")
        terminal = self.observation()
        result = self.recover([("status", pending), ("stop", pending), ("status", terminal)])
        self.assertEqual(result, terminal)

    def test_admission_unknown_can_run_before_settling(self):
        pending = self.observation("unknown", fence="held")
        running = self.observation("running", fence="held", cancel_requested=True)
        terminal = self.observation()
        result = self.recover([("status", pending), ("stop", pending), ("status", running), ("status", terminal)])
        self.assertEqual(result, terminal)

    def test_first_observed_identity_is_pinned_for_later_status(self):
        pending = self.observation("unknown", fence="held")
        known = self.observation("running", fence="held")
        for role in ("keeper", "worker"):
            for change in ("replacement", "disappearance"):
                with self.subTest(role=role, change=change):
                    changed = copy.deepcopy(known)
                    if change == "replacement":
                        changed["execution"][role]["created_filetime"] = "2001"
                    else:
                        changed = copy.deepcopy(pending)
                    self.recover([("status", pending), ("stop", pending), ("status", known), ("status", changed)],
                                 error="installer-execution-changed")

    def test_known_process_state_cannot_regress_or_switch(self):
        for process_state in ("unknown", "not-started"):
            with self.subTest(process_state=process_state):
                running = self.observation("running", fence="held")
                changed = self.observation("unknown", process_state="started", fence="held")
                changed["execution"]["process_state"] = process_state
                if process_state == "not-started":
                    changed = self.observation(process_state="not-started")
                self.recover([("status", running), ("stop", running), ("status", changed)],
                             error="installer-execution-changed")

    def test_request_identity_and_deadline_cannot_change_during_admission(self):
        pending = self.observation("unknown", fence="held")
        for field, value in (("token", "bbxe_" + "e" * 32), ("request_sha256", "e" * 64),
                             ("deadline", "2026-09-06T12:00:01Z")):
            with self.subTest(field=field):
                changed = self.observation(**{field: value})
                self.recover([("status", pending), ("stop", pending), ("status", changed)],
                             error="installer-execution-changed")

    def test_process_state_is_pinned_when_it_first_becomes_known(self):
        pending = self.observation("unknown", fence="held")
        running = self.observation("running", fence="held")
        regressed = self.observation("unknown", process_state="started", fence="held")
        regressed["execution"]["process_state"] = "unknown"
        self.recover([("status", pending), ("stop", pending), ("status", running), ("status", regressed)],
                     error="installer-execution-changed")

    def test_terminal_held_after_cancellation_requires_fresh_stop_reconciliation(self):
        pending = self.observation("unknown", fence="held")
        held = self.observation(fence="held", cancel_requested=True)
        terminal = self.observation(cancel_requested=True)
        result = self.recover([("status", pending), ("stop", pending), ("status", held),
                               ("stop", terminal), ("status", terminal)])
        self.assertEqual(result, terminal)

    def test_lost_stop_replies_require_status_after_both_cancellation_and_reconciliation(self):
        pending = self.observation("unknown", fence="held")
        held = self.observation(fence="held", cancel_requested=True)
        terminal = self.observation(cancel_requested=True)
        lost = proof.ProofError("command-failed")
        result = self.recover([("status", pending), ("stop", lost), ("status", held),
                               ("stop", lost), ("status", terminal)])
        self.assertEqual(result, terminal)

    def test_no_start_terminal_still_requires_released_fence(self):
        pending = self.observation("unknown", fence="held")
        held = self.observation(process_state="not-started", fence="held")
        terminal = self.observation(process_state="not-started")
        result = self.recover([("status", pending), ("stop", pending), ("status", held),
                               ("stop", terminal), ("status", terminal)])
        self.assertEqual(result, terminal)

    def test_released_terminal_needs_no_stop(self):
        terminal = self.observation()
        self.assertEqual(self.recover([("status", terminal)]), terminal)

    def test_unknown_cleanup_or_task_and_keeper_loss_exhaust_budget_without_returning(self):
        for changes in ({}, {"tree_cleanup": "known"}, {"task_mutation": "settled"}):
            with self.subTest(changes=changes):
                unknown = self.observation("unknown", process_state="started", fence="held", **changes)
                self.recover([("status", unknown), ("stop", unknown), ("status", unknown)],
                             error="installer-stop-unsettled", tick=15)

    def test_pending_admission_exhausts_budget_without_returning(self):
        pending = self.observation("unknown", fence="held")
        self.recover([("status", pending), ("stop", pending), ("status", pending)],
                     error="installer-stop-unsettled", tick=15)

    def test_terminal_status_arriving_after_budget_cannot_authorize_removal(self):
        pending = self.observation("unknown", fence="held")
        terminal = self.observation()
        with mock.patch.object(proof, "installer_call", side_effect=[pending, pending, terminal]) as call, \
                mock.patch.object(proof.time, "monotonic", side_effect=[0, 0, 0, 15]), \
                mock.patch.object(proof.threading.Event, "wait") as wait:
            with self.assertRaisesRegex(proof.ProofError, "installer-stop-unsettled"):
                proof.recover_installer(None, None, "bbxo_" + "a" * 32, "4" * 64)
        self.assertEqual([item.args[2] for item in call.call_args_list], ["status", "stop", "status"])
        wait.assert_not_called()


class InstallerRecoveryDeadlineTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        config = installer_config(self.root)
        authorize_installer(config)
        operator_path = self.root / "operator.json"
        operator_path.write_bytes(proof.canonical(config))
        operator_path.chmod(0o600)
        private = self.root / "private"
        private.mkdir()
        self.commands = FakeInstallCommands(private, self.root, config)
        self.operator = self.commands.operator
        self.operation_id = "bbxo_" + "a" * 32
        (private / "installer-operations.json").write_bytes(proof.canonical({
            "installation_id": INSTALL_ID, "operations": {"install": self.operation_id}}))
        self.terminal = proof.installer_call(self.commands, self.operator, "install",
                                             operation_id=self.operation_id, apply=True)
        self.pending = copy.deepcopy(self.terminal)
        self.pending.update(state="unknown", completion="unknown")
        self.pending["execution"].update(state="unknown", process_state="unknown", fence_state="held",
                                         tree_cleanup="unknown", task_mutation="unknown")
        for role in ("keeper", "worker"):
            del self.pending["execution"][role]

    def recover(self, responses, *, error=None):
        pending = list(responses)
        now, calls = [100.0], []
        def run(args, **kwargs):
            script = kwargs["stdin"].decode()
            encoded = proof.re.search(r"FromBase64String\('([^']+)'\)", script).group(1)
            cli = json.loads(proof.base64.b64decode(encoded))["args"]
            operation, elapsed, response = pending.pop(0)
            self.assertEqual(args[0], "ssh")
            self.assertEqual(cli[1], operation)
            self.assertTrue(kwargs["recovery"])
            if operation == "stop":
                self.assertIn("--apply", cli)
                self.assertEqual(cli[cli.index("--execution") + 1], self.terminal["execution"]["token"])
            else:
                self.assertNotIn("--apply", cli)
            calls.append((operation, kwargs["timeout"]))
            self.commands.sequence += 1
            now[0] += elapsed
            if isinstance(response, Exception):
                raise response
            return proof.canonical({"schema_version": 1, "exit_code": 0, "output": json.dumps(response)})
        def wait(seconds):
            self.assertEqual(seconds, 0.1)
            now[0] += seconds
        with mock.patch.object(self.commands, "run", side_effect=run), \
                mock.patch.object(proof.time, "monotonic", side_effect=lambda: now[0]), \
                mock.patch.object(proof.threading.Event, "wait", side_effect=wait):
            if error:
                with self.assertRaisesRegex(proof.ProofError, error):
                    proof.recover_installer(self.commands, self.operator, self.operation_id, "4" * 64)
            else:
                result = proof.recover_installer(self.commands, self.operator, self.operation_id, "4" * 64)
                self.assertEqual(result, self.terminal)
        self.assertEqual(pending, [])
        return calls

    def test_slow_initial_status_consumes_shared_recovery_budget(self):
        calls = self.recover([("status", 12, self.pending), ("stop", 1, self.pending),
                              ("status", 1, self.terminal)])
        self.assertEqual(calls, [("status", 15), ("stop", 3), ("status", 2)])

    def test_initial_terminal_status_at_deadline_is_refused(self):
        calls = self.recover([("status", 15, self.terminal)], error="installer-stop-unsettled")
        self.assertEqual(calls, [("status", 15)])

    def test_lost_stop_reply_does_not_reset_next_status_timeout(self):
        calls = self.recover([("status", 2, self.pending), ("stop", 6, proof.ProofError("command-failed")),
                              ("status", 4, self.terminal)])
        self.assertEqual(calls, [("status", 15), ("stop", 13), ("status", 7)])

    def test_stop_exhausting_budget_does_not_spawn_another_status(self):
        calls = self.recover([("status", 14, self.pending), ("stop", 1, proof.ProofError("command-timeout"))],
                             error="installer-stop-unsettled")
        self.assertEqual(calls, [("status", 15), ("stop", 1)])

    def test_local_request_preparation_cannot_extend_or_restart_deadline(self):
        now = [100.0]
        canonical = proof.canonical
        def prepare(value):
            now[0] = 115.0
            return canonical(value)
        with mock.patch.object(proof, "canonical", side_effect=prepare), \
                mock.patch.object(proof.time, "monotonic", side_effect=lambda: now[0]), \
                mock.patch.object(self.commands, "run") as run:
            with self.assertRaisesRegex(proof.ProofError, "installer-stop-unsettled"):
                proof.installer_call(self.commands, self.operator, "status", operation_id=self.operation_id,
                                     recovery=True, recovery_deadline=115)
        run.assert_not_called()

    def test_nonrecovery_and_unbudgeted_call_timeouts_stay_unchanged(self):
        for recovery in (False, True):
            for operation in ("status", "stop", "inspect", "install", "remove"):
                with self.subTest(operation=operation, recovery=recovery), \
                        mock.patch.object(self.commands, "run", side_effect=proof.ProofError("command-timeout")) as run:
                    with self.assertRaisesRegex(proof.ProofError, "command-timeout"):
                        proof.installer_call(self.commands, self.operator, operation, operation_id=self.operation_id,
                                             apply=operation == "stop", recovery=recovery,
                                             execution_token=self.terminal["execution"]["token"] if operation == "stop" else None)
                    self.assertEqual(run.call_args.kwargs["timeout"], 45 if operation in ("status", "stop") else 360)
                    self.assertEqual(run.call_args.kwargs["recovery"], recovery)


class HostInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = installer_config(self.root)
        authorize_installer(self.config)
        self.path = self.root / "operator.json"
        self.request = proof.ProofRequest(SHA, self.root, self.path, self.root / "output", proof="host-install")

    def execute(self, fault=None):
        self.path.write_bytes(proof.canonical(self.config))
        self.path.chmod(0o600)
        def factory(private, cwd):
            self.commands = FakeInstallCommands(private, cwd, self.config, fault)
            return self.commands
        return proof.baseline(self.request, factory)

    def test_complete_branch_installs_uses_generated_target_settles_then_removes(self):
        result = self.execute()
        self.assertEqual(result["status"], "pass", result)
        self.assertEqual(set(result["outcomes"]), set(proof.REQUIRED + proof.INSTALL_REQUIRED))
        self.assertEqual(self.commands.installer_actions, [("inspect", False, False), ("install", False, False),
                         ("install", True, False), ("status", False, True), ("status", False, True), ("install", True, True), ("remove", False, True),
                         ("inspect", False, True), ("remove", True, True), ("status", False, True), ("remove", True, True)])
        self.assertEqual(result["installation"], {"installation_id": INSTALL_ID, "state": "removed"})
        operations = json.loads((self.commands.private / "installer-operations.json").read_bytes())["operations"]
        self.assertNotEqual(operations["install"], operations["remove"])
        self.assertEqual(self.commands.receipt.read_bytes(), b"removed tombstone")
        self.assertFalse(self.commands.owned_runtime.exists())
        self.assertEqual(self.commands.remote_file(r"C:\ExistingFixture\precious.blend").read_bytes(), b"precious!")
        calls = self.commands.calls
        last_status = max(i for i, call in enumerate(calls) if call[1:2] == ["status"])
        first_remove = min(i for i, call in enumerate(calls) if call[0] == "ssh"
                           and '"remove"' in proof.base64.b64decode(proof.re.search(r"FromBase64String\('([^']+)'\)",
                               self.commands.call_options[i]["stdin"].decode("utf-8")).group(1)).decode())
        self.assertLess(last_status, first_remove)
        selectors = [Path(call[call.index("--target") + 1]).read_bytes() for call in calls if "--target" in call]
        self.assertTrue(selectors and all(x == selectors[0] for x in selectors))
        self.assertEqual(json.loads(selectors[0])["windows"]["host_executable"],
                         str(proof.windows_path(self.config["installation"]["state_root"]) / "installations" / INSTALL_ID / "runtime" / "blender-box.exe"))
        self.assertFalse(any(call[0] == "scp" or call[1:3] == ["windows", "setup"] for call in calls))
        public = (self.request.output / "public/outcome.json").read_text()
        for private in ("TestFixture", "TEST-HOST", "test-user", "ExistingFixture", str(self.root)):
            self.assertNotIn(private, public)
        self.assertIn("installer-interruption", result["not_exercised"])

    def test_lost_apply_response_uses_fresh_status_before_removal(self):
        result = self.execute("lost-apply-response")
        self.assertIn(("status", False, True), self.commands.installer_actions)
        self.assertEqual(result["installation"]["state"], "removed", result)
        self.assertFalse(self.commands.owned_runtime.exists())

    def test_lost_active_response_stops_only_observed_execution(self):
        result = self.execute("lost-active-response")
        self.assertEqual(result["installation"]["state"], "removed", result)
        actions = self.commands.installer_actions
        stopped = actions.index(("stop", True, True))
        self.assertEqual(actions[stopped - 1], ("status", False, True))
        self.assertEqual(actions[stopped + 1], ("status", False, True))
        self.assertEqual(self.commands.stopped_execution, "bbxe_" + "b" * 32)

    def test_keeper_loss_retains_installation_and_never_replays_apply(self):
        with mock.patch.object(proof.time, "monotonic", side_effect=[0, 0, 16]), \
                mock.patch.object(proof.threading.Event, "wait"):
            result = self.execute("keeper-lost-response")
        self.assertEqual(result["installation"]["state"], "unknown")
        self.assertEqual(self.commands.removal_calls, 0)
        self.assertTrue(self.commands.owned_runtime.exists())
        self.assertEqual(self.commands.installer_actions.count(("install", True, False)), 1)
        self.assertNotIn(("install", True, True), self.commands.installer_actions)
        self.assertIn(("status", False, True), self.commands.installer_actions)

    def test_lost_remove_response_reobserves_cleanup_and_preserves_failure(self):
        result = self.execute("lost-remove-response")
        self.assertEqual(result["installation"]["state"], "removed", result)
        self.assertEqual(result["outcomes"]["remove-apply"], {"status": "fail", "code": "command-failed"})
        self.assertFalse(self.commands.owned_runtime.exists())
        actions = self.commands.installer_actions
        removal = actions.index(("remove", True, True))
        self.assertEqual(actions[removal + 1], ("status", False, True))

    def test_lost_stop_response_still_reobserves_exact_execution(self):
        result = self.execute("lost-stop-response")
        self.assertEqual(result["installation"]["state"], "removed", result)
        actions = self.commands.installer_actions
        stopped = actions.index(("stop", True, True))
        self.assertEqual(actions[stopped + 1], ("status", False, True))

    def test_changed_execution_after_stop_preserves_installation(self):
        result = self.execute("execution-token-changed")
        self.assertEqual(result["installation"]["state"], "unknown", result)
        self.assertEqual(self.commands.removal_calls, 0)
        self.assertTrue(self.commands.owned_runtime.exists())

    def test_manifest_hash_matches_actual_go_runtime_manifest_encoding(self):
        self.path.write_bytes(proof.canonical(self.config))
        self.path.chmod(0o600)
        operator = proof.InstallOperator.load(self.path, SHA)
        # Produced by json.Marshal(windowsinstall.RuntimeManifest), including escaped Python requirement operators.
        self.assertEqual(operator.manifest_sha256, "9e420a595e051c7d473f22092d0ffbc834f7e51cfcad66c37555f3836c31c498")
        self.assertNotEqual(operator.manifest_sha256, operator.manifest_pin["sha256"])

    def test_hosted_guard_has_no_config_or_command_access(self):
        self.request = dataclasses_replace(self.request, execution="hosted", driver_sha="b" * 40)
        with mock.patch.dict(os.environ, GITHUB_RUN_ATTEMPT="1"), mock.patch.object(proof.Commands, "run") as command:
            result = proof.baseline(self.request)
        command.assert_not_called()
        self.assertEqual(result["outcomes"]["preparation"]["code"], "hosted-recovery-retention-unavailable")

    def test_separate_authorization_never_contacts_host(self):
        for key in self.config["authorization"]:
            with self.subTest(key=key):
                config = copy.deepcopy(self.config)
                config["authorization"][key] = "wrong"
                self.path.write_bytes(proof.canonical(config))
                self.path.chmod(0o600)
                request = dataclasses_replace(self.request, output=self.root / key)
                with mock.patch.object(proof.Commands, "run") as command:
                    result = proof.baseline(request)
                command.assert_not_called()
                self.assertEqual(result["outcomes"]["preparation"]["code"], "installer-not-authorized")

    def test_existing_baseline_grant_cannot_authorize_install(self):
        self.path.write_bytes(proof.canonical(operator_config()))
        self.path.chmod(0o600)
        with mock.patch.object(proof.Commands, "run") as command:
            result = proof.baseline(self.request)
        command.assert_not_called()
        self.assertEqual(result["status"], "fail")

    def test_configuration_scope_and_manifest_rejected_offline(self):
        for fault in ("shared-fixture", "existing-fixture-id", "platform", "bootstrap-inside", "preserved-inside",
                      "target-equals-root", "target-under-root", "target-other-installation",
                      "unsafe-path", "manifest-hash", "manifest-role", "manifest-source", "extra-key"):
            with self.subTest(fault=fault):
                config = copy.deepcopy(self.config)
                if fault == "shared-fixture":
                    config["fixture"]["kind"] = "shared-existing"
                elif fault == "existing-fixture-id":
                    config["fixture"]["id"] = "windows-onboarding-prepared-v1"
                elif fault == "platform":
                    config["platform"] = "linux"
                elif fault in ("bootstrap-inside", "preserved-inside"):
                    path = str(proof.windows_path(config["installation"]["state_root"]) / "installations" / INSTALL_ID / "runtime" / "bad.exe")
                    if fault == "bootstrap-inside":
                        config["bootstrap"]["path"] = path
                    else:
                        config["before_state"]["unrelated_files"][0]["path"] = path
                elif fault in ("target-equals-root", "target-under-root", "target-other-installation"):
                    destination = proof.windows_path(config["installation"]["state_root"].swapcase())
                    if fault == "target-under-root":
                        destination /= "exported-target.json"
                    elif fault == "target-other-installation":
                        destination = destination / "installations" / ("bbxi_" + "b" * 32) / "target.json"
                    config["installation"]["target_out"] = str(destination)
                elif fault == "unsafe-path":
                    config["installation"]["state_root"] = r"C:\safe\..\other"
                elif fault == "manifest-hash":
                    config["runtime"]["remote_manifest"]["sha256"] = "0" * 64
                elif fault in ("manifest-role", "manifest-source"):
                    manifest = json.loads(Path(config["runtime"]["local_manifest"]).read_bytes())
                    if fault == "manifest-role":
                        manifest["artifacts"][0]["role"] = "daemon-wheel"
                    else:
                        manifest["artifacts"][0]["provenance"]["source_commit"] = "9" * 40
                    raw = proof.canonical(manifest)
                    local = self.root / (fault + ".json")
                    local.write_bytes(raw)
                    config["runtime"]["local_manifest"] = str(local)
                    config["runtime"]["remote_manifest"].update(size=len(raw), sha256=proof.digest(raw))
                else:
                    config["surprise"] = "PRIVATE"
                authorize_installer(config)
                self.path.write_bytes(proof.canonical(config))
                self.path.chmod(0o600)
                with mock.patch.object(proof.Commands, "run") as command:
                    result = proof.baseline(dataclasses_replace(self.request, output=self.root / fault))
                command.assert_not_called()
                self.assertEqual(result["status"], "fail")

    def test_unknown_preconditions_refuse_before_apply(self):
        for fault in ("wrong-host", "before-state", "observation-extra", "bootstrap-pin", "artifact-pin", "owner-changed",
                      "identity-changed", "unknown-state", "unknown-completion", "result-extra", "cancel-before",
                      "python-selection", "inventory-extra", "inventory-missing"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temp:
                self.root = Path(temp)
                self.config = installer_config(self.root)
                authorize_installer(self.config)
                self.path = self.root / "operator.json"
                self.request = dataclasses_replace(self.request, candidate_checkout=self.root, operator_config=self.path,
                                                   output=self.root / "output")
                result = self.execute(fault)
                self.assertEqual(result["status"], "fail", result)
                self.assertFalse(any(apply for _, apply, _ in self.commands.installer_actions))

    def test_generated_target_failure_removes_only_owned_install(self):
        for fault in ("target-result", "target-fetch", "cancel-after-install", "publication-failed"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temp:
                self.root = Path(temp)
                self.config = installer_config(self.root)
                authorize_installer(self.config)
                self.path = self.root / "operator.json"
                self.request = dataclasses_replace(self.request, candidate_checkout=self.root, operator_config=self.path,
                                                   output=self.root / "output")
                result = self.execute(fault)
                self.assertEqual(result["status"], "fail")
                self.assertFalse(any(call[1:2] == ["run"] for call in self.commands.calls))
                self.assertEqual(result["installation"]["state"], "removed", result)
                self.assertEqual(self.commands.removal_calls, 2)

    def test_unknown_run_or_install_preserves_receipt_and_runtime(self):
        for fault in ("status-failed", "cleanup-failed", "local-cleanup-unknown", "no-run-marker", "bad-evidence", "apply-partial", "plan-changed"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temp:
                self.root = Path(temp)
                self.config = installer_config(self.root)
                authorize_installer(self.config)
                self.path = self.root / "operator.json"
                self.request = dataclasses_replace(self.request, candidate_checkout=self.root, operator_config=self.path,
                                                   output=self.root / "output")
                result = self.execute(fault)
                self.assertEqual(result["status"], "fail")
                self.assertEqual(result["outcomes"]["remove-preview"]["code"], "installer-removal-not-settled")
                self.assertTrue(self.commands.receipt.exists())
                self.assertTrue(self.commands.owned_runtime.exists())
                self.assertEqual(self.commands.removal_calls, 0)
                self.assertTrue(list((self.request.output / "private").glob("installer-result-*.json")))

    def test_removal_and_preservation_failures_never_pass(self):
        for fault, stage in (("remove-failed", "remove-apply"), ("unrelated-changed", "fixture-preserved")):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temp:
                self.root = Path(temp)
                self.config = installer_config(self.root)
                authorize_installer(self.config)
                self.path = self.root / "operator.json"
                self.request = dataclasses_replace(self.request, candidate_checkout=self.root, operator_config=self.path,
                                                   output=self.root / "output")
                result = self.execute(fault)
                self.assertEqual(result["status"], "fail")
                self.assertEqual(result["outcomes"][stage]["status"], "fail")


if __name__ == "__main__":
    unittest.main()
