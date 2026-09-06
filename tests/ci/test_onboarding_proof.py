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

    def run(self, args, **kwargs):
        args = [str(a) for a in args]
        self.calls.append(args)
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


class BaselineTests(unittest.TestCase):
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
    def test_trusted_driver_authorization_and_public_upload_contract(self):
        workflow = (ROOT / ".github/workflows/windows-onboarding-proof.yml").read_text()
        for text in ("name: Windows onboarding proof", "name: baseline", "workflow_dispatch:",
                     "needs: [candidate, authorize]", "environment: windows-onboarding-approval",
                     "environment: windows-onboarding-host", "cancel-in-progress: false", "timeout-minutes: 75",
                     '"$RUN_ATTEMPT" == 1', '"$REQUEST_REF" == refs/heads/main', '"$REQUEST_ACTOR" == BramVR',
                     "ref: ${{ github.workflow_sha }}", "ref: ${{ needs.candidate.outputs.sha }}",
                     "python3 driver/scripts/onboarding_proof.py baseline", "--execution hosted", "persist-credentials: false",
                     "windows-onboarding-prepared-v1", "if-no-files-found: error", "StrictHostKeyChecking yes"):
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
