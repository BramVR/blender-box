from contextlib import contextmanager
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import errno
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

import test_proof_controller as baseline

model = baseline.controller
import proof_controller_native as native
import proof_controller_store as store
import proof_controller_worker as worker


def spec():
    return {"schema_version": 1, "control_uid": 1901, "control_gid": 1901, "runner_uid": 1902, "runner_gid": 1902,
            "candidate_sha": baseline.SHA, "driver_sha": baseline.DRIVER, "expected_client_sha256": "c" * 64,
            "public_key": "ssh-ed25519 " + base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 " + bytes(32)).decode(), "tool_sha256": {path: "d" * 64 for path in native.TOOLS}}


def policy():
    value = spec()
    del value["public_key"]
    value.update(variant="baseline", artifacts={path: "e" * 64 for path in native.artifact_paths()})
    return native.NativePolicy.parse(model.proof.canonical(value))


def invocation():
    return model.Invocation("1" * 32, "2" * 32, native.UNIT_CGROUP + "/attempt-" + "3" * 32,
                            301, 4001, 300, "gha_123_1", 1, baseline.request().digest)


def unit_bytes(active="active", pid=300, identity="2" * 32, cgroup=native.UNIT_CGROUP):
    return (f"Id={native.UNIT}\nLoadState=loaded\nActiveState={active}\nMainPID={pid}\n"
            f"InvocationID={identity}\nControlGroup={cgroup}\nJob=\n").encode()


def proc_bytes(pid=301, parent=300, start=4001):
    fields = ["S", str(parent)] + ["0"] * 17 + [str(start)] + ["0"] * 3
    return (str(pid) + " (a name ) with spaces) " + " ".join(fields) + "\n").encode()


def anchored(root, uid=None):
    cap = object.__new__(store.RootedFiles)
    cap.root, cap.uid, cap.gid = root, os.getuid() if uid is None else uid, os.getgid()
    cap.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    return cap


class NativeParsingTests(unittest.TestCase):
    def test_systemctl_argv_and_bounded_native_properties(self):
        run = mock.Mock(return_value=subprocess.CompletedProcess([], 0, unit_bytes(), b""))
        ops = native.LinuxOps(policy(), _run=run)
        self.assertEqual(ops.unit().main_pid, 300)
        self.assertEqual(run.call_args.args[0], ["/usr/bin/systemctl", "--no-pager", "--no-ask-password", "show", "--all",
                         "--property=" + ",".join(native.PROPERTIES), native.UNIT])
        self.assertEqual(run.call_args.kwargs["env"], {"PATH": "/usr/bin", "LANG": "C", "SYSTEMD_COLORS": "0"})
        ops.systemctl("start")
        self.assertEqual(run.call_args.args[0], ["/usr/bin/systemctl", "--no-pager", "--no-ask-password", "start", "--no-block", native.UNIT])
        with self.assertRaises(model.ControllerError):
            ops.systemctl("stop")
        for result in (subprocess.CompletedProcess([], 1, unit_bytes(), b"failure"),
                       subprocess.CompletedProcess([], 0, b"x" * 16385, b"")):
            run.return_value = result
            with self.assertRaises(model.ControllerError):
                ops.unit()

    def test_unit_parser_rejects_partial_duplicate_and_inconsistent_identity(self):
        self.assertEqual(native.parse_unit(unit_bytes("inactive", 0, "", "")).main_pid, 0)
        invalid = [unit_bytes() + b"MainPID=301\n", unit_bytes().replace(b"LoadState=loaded\n", b""),
                   unit_bytes().replace(b"MainPID=300", b"MainPID=-1"), unit_bytes("inactive"),
                   unit_bytes(cgroup="/another.service"), unit_bytes(identity="X" * 32),
                   unit_bytes() + b"Unknown=yes\n", b"x" * 16385]
        self.assertEqual(native.parse_unit(unit_bytes().replace(b"Job=\n", b"Job=42\n")).job_id, 42)
        invalid += [unit_bytes().replace(b"Job=\n", b""), unit_bytes().replace(b"Job=\n", b"Job=0\n")]
        for raw in invalid:
            with self.subTest(raw=raw[:30]), self.assertRaises(model.ControllerError):
                native.parse_unit(raw)

    def test_proc_names_with_spaces_and_parenthesis_pid_reuse(self):
        first = native.parse_process(301, proc_bytes(), b"0::/fixture\n")
        second = native.parse_process(301, proc_bytes(start=4002), b"0::/fixture\n")
        self.assertEqual((first.parent, first.start, first.cgroup), (300, 4001, "/fixture"))
        self.assertNotEqual(first, second)
        for raw, cgroup in ((b"301 nonsense", b"0::/fixture\n"), (proc_bytes(pid=302), b"0::/fixture\n"),
                            (proc_bytes(), b"0::/fixture\n0::/other\n"), (proc_bytes(), b"0::/a/../b\n")):
            with self.assertRaises(model.ControllerError):
                native.parse_process(301, raw, cgroup)
        with mock.patch.object(Path, "read_bytes", side_effect=[proc_bytes(), b"0::/fixture\n", proc_bytes(start=4002)]):
            with self.assertRaisesRegex(model.ControllerError, "native-process-changed"):
                native.LinuxOps(policy()).process(301)

    def test_boot_and_cgroup_events(self):
        self.assertEqual(native.boot_id(b"11111111-1111-1111-1111-111111111111\n"), "1" * 32)
        self.assertFalse(native.populated(b"populated 0\nfrozen 0\n"))
        self.assertTrue(native.populated(b"populated 1\n"))
        for raw in (b"populated 0\npopulated 1", b"populated 2", b"frozen 0"):
            with self.assertRaises(model.ControllerError):
                native.populated(raw)
        for raw in (b"1" * 32, b"11111111-1111-1111-1111-11111111111G"):
            with self.assertRaises(model.ControllerError):
                native.boot_id(raw)

    def test_native_receipt_only_accepts_unique_fixed_subtree(self):
        receipt = native.NativeReceipt(invocation(), 3000, 2, 3)
        self.assertEqual(native.NativeReceipt.parse(asdict(receipt)), receipt)
        for changes in ({"cgroup": native.UNIT_CGROUP}, {"cgroup": "/replacement/attempt-" + "3" * 32}):
            raw = asdict(receipt)
            raw["invocation"].update(changes)
            with self.assertRaises(model.ControllerError):
                native.NativeReceipt.parse(raw)


class NativeStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        ownership = mock.patch.object(os, "fchown")
        self.chown = ownership.start()
        self.addCleanup(ownership.stop)
        self.cap = anchored(self.root)
        self.addCleanup(self.cap.close)

    def test_actual_private_publication_owner_modes_atomic_replace_and_hardlinks(self):
        self.cap.directory(self.root / "job", create=True)
        path = self.root / "job/input"
        calls = []
        original_chown, original_fsync, original_link = os.fchown, os.fsync, os.link
        def chown(fd, uid, gid):
            calls.append(("owner", uid, gid))
            return original_chown(fd, uid, gid)
        def fsync(fd):
            calls.append(("fsync",))
            return original_fsync(fd)
        def link(*args, **kwargs):
            calls.append(("publish",))
            return original_link(*args, **kwargs)
        with mock.patch.object(os, "fchown", side_effect=chown), mock.patch.object(os, "fsync", side_effect=fsync), \
             mock.patch.object(os, "link", side_effect=link):
            self.cap.publish(path, b"original")
        self.assertEqual(calls[:3], [("owner", os.getuid(), os.getgid()), ("fsync",), ("publish",)])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.stat().st_uid, self.cap.uid)
        self.assertEqual(self.cap.read(path), b"original")
        with self.assertRaises(FileExistsError):
            self.cap.publish(path, b"collision")
        self.cap.publish(path, b"replacement", exclusive=False)
        self.assertEqual(self.cap.read(path), b"replacement")
        os.link(path, self.root / "alias")
        with self.assertRaises(model.ControllerError):
            self.cap.read(path)

    def test_exact_owner_capabilities_do_not_relax_other_uid(self):
        self.cap.publish(self.root / "record", b"owned")
        other = anchored(self.root, self.cap.uid + 1)
        self.addCleanup(other.close)
        with self.assertRaisesRegex(model.ControllerError, "private-directory-permissions"):
            other.read(self.root / "record")
        wrong_file = self.root / "record"
        actual_fstat = os.fstat
        def fstat(fd):
            result = actual_fstat(fd)
            if result.st_ino == wrong_file.stat().st_ino:
                fields = list(result)
                fields[4] = self.cap.uid + 2
                return os.stat_result(fields)
            return result
        with mock.patch.object(os, "fstat", side_effect=fstat):
            with self.assertRaisesRegex(model.ControllerError, "private-file-invalid"):
                self.cap.read(wrong_file)

    def test_symlink_ancestor_root_escape_size_and_replace_attacks(self):
        self.cap.directory(self.root / "job", create=True)
        self.cap.publish(self.root / "job/input", b"1234")
        (self.root / "alias").symlink_to(self.root / "job", target_is_directory=True)
        for path in (self.root / "alias/input", self.root / "../outside"):
            with self.assertRaises((model.ControllerError, OSError)):
                self.cap.read(path)
        with self.assertRaises(model.ControllerError):
            self.cap.read(self.root / "job/input", 3)
        (self.root / "job/link").symlink_to(self.root / "job/input")
        with self.assertRaises(OSError):
            self.cap.read(self.root / "job/link")
        fd = self.cap.fd
        moved = self.root / "moved"
        old = self.root / "job"
        old.rename(moved)
        old.symlink_to("/does-not-exist")
        self.assertTrue(os.fstat(fd))
        with self.assertRaises(OSError):
            self.cap.publish(old / "output", b"never")
        self.assertFalse((moved / "output").exists())


class StopOps(native.LinuxOps):
    def __init__(self, path):
        super().__init__(policy())
        self.path = path
        self.events = []
        self.boot_value = invocation().boot_id
        self.supervisor_dead = False
        self.unit_empty = False
        self.replace_before_kill = False
        self.group_populated = True
        self.replacement_killed = False

    def boot(self):
        return self.boot_value

    @contextmanager
    def group(self, name):
        self.events.append(("open", name))
        fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            yield fd
        finally:
            os.close(fd)

    def write_group(self, fd, name, data):
        self.events.append((name, os.fstat(fd).st_ino, data))
        self.group_populated = False
        if self.replace_before_kill:
            self.unit_empty = False

    def group_read(self, fd):
        return self.group_populated

    def wait_group_empty(self, fd, deadline):
        if self.group_populated:
            raise model.ControllerError("local-termination-unknown")

    def wait_supervisor(self, receipt, deadline):
        return self.supervisor_dead

    def supervisor_gone(self, receipt):
        return self.supervisor_dead

    def end_supervisor(self, receipt):
        self.events.append(("end-supervisor", receipt.invocation.parent_pid, receipt.supervisor_start))

    def whole_empty(self):
        return self.unit_empty


class NativeStopTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        path = Path(self.temp.name)
        self.ops = StopOps(path)
        info = path.stat()
        self.receipt = native.NativeReceipt(invocation(), 3000, info.st_dev, info.st_ino)

    def test_exact_attempt_killed_then_supervisor_and_whole_unit_required(self):
        self.ops.supervisor_dead = self.ops.unit_empty = True
        self.assertTrue(self.ops.stop(self.receipt))
        self.assertEqual(self.ops.events[0], ("open", invocation().cgroup))
        self.assertEqual(self.ops.events[1], ("cgroup.kill", self.receipt.cgroup_inode, b"1\n"))
        self.assertEqual(self.ops.events[2], ("end-supervisor", 300, 3000))

    def test_inode_mismatch_sends_zero_signals(self):
        with self.assertRaisesRegex(model.ControllerError, "native-cgroup-changed"):
            self.ops.stop(replace(self.receipt, cgroup_inode=self.receipt.cgroup_inode + 1))
        self.assertEqual(self.ops.events, [("open", invocation().cgroup)])

    def test_empty_child_alone_never_proves_service_exit(self):
        for supervisor, unit in ((False, True), (True, False)):
            self.ops.supervisor_dead, self.ops.unit_empty = supervisor, unit
            with mock.patch.object(native, "STOP_SECONDS", 0):
                self.assertFalse(self.ops.stop(self.receipt))

    def test_replacement_race_targets_old_inode_and_cannot_prove_empty(self):
        self.ops.supervisor_dead = True
        self.ops.replace_before_kill = True
        with mock.patch.object(native, "STOP_SECONDS", 0):
            self.assertFalse(self.ops.stop(self.receipt))
        self.assertEqual(self.ops.events[1][1], self.receipt.cgroup_inode)
        self.assertFalse(self.ops.replacement_killed)

    def test_reboot_has_zero_signals_even_when_empty_unknown(self):
        self.ops.boot_value = "9" * 32
        self.assertFalse(self.ops.stop(self.receipt))
        self.ops.unit_empty = True
        self.assertTrue(self.ops.stop(self.receipt))
        self.assertEqual(self.ops.events, [])

    def test_pidfd_rechecks_start_before_signalling(self):
        ops = native.LinuxOps(policy())
        first = native.Process(300, 1, 3000, native.UNIT_CGROUP)
        replacement = replace(first, start=3001)
        with mock.patch.object(ops, "process", side_effect=[first, replacement]), \
             mock.patch.object(os, "pidfd_open", return_value=99, create=True), \
             mock.patch.object(os, "close"), mock.patch.object(native.signal, "pidfd_send_signal", create=True) as signal_call:
            with self.assertRaisesRegex(model.ControllerError, "native-supervisor-changed"):
                ops.end_supervisor(self.receipt)
            signal_call.assert_not_called()


class NativeCLITests(unittest.TestCase):
    def invoke(self, script, *args, raw=None, env=None):
        return subprocess.run([sys.executable, str(baseline.ROOT / "scripts" / script), *args], input=raw,
                              capture_output=True, timeout=10, check=False, env=env)

    def test_actual_enrollment_manifest_hashes_modes_fixture_and_false_qualification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            enrollment = root / "spec.json"
            baseline.private_file(enrollment, model.proof.canonical(spec()))
            output = root / "preview"
            result = self.invoke("proof_controller.py", "bootstrap", "--enrollment", str(enrollment), "--output", str(output))
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads(result.stdout)
            self.assertFalse(manifest["installable"])
            resources = {entry["path"]: entry for entry in manifest["resources"]}
            for entry in resources.values():
                path = output / entry["source"]
                self.assertEqual(model.proof.digest(path.read_bytes()), entry["sha256"])
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(entry["uid"], 0)
            qualifier = json.loads((output / resources[str(native.CONFIG / "qualification.json")]["source"]).read_bytes())
            self.assertFalse(qualifier["qualified"])
            self.assertEqual(set(qualifier["evidence"]), set(native.QUALIFICATIONS))
            policy_raw = (output / resources[str(native.CONFIG / "policy.json")]["source"]).read_bytes()
            enrolled = native.NativePolicy.parse(policy_raw)
            self.assertEqual(qualifier["policy_sha256"], enrolled.digest)
            with self.assertRaisesRegex(model.ControllerError, "native-adapter-unqualified"):
                enrolled.qualify(model.proof.canonical(qualifier))
            self.assertIn("/usr/bin/scp", enrolled.value["tool_sha256"])
            self.assertEqual(len(enrolled.value["tool_sha256"]), 6)
            authorized_keys = resources["/etc/ssh/blender-box-proof-authorized_keys"]
            self.assertEqual((authorized_keys["uid"], authorized_keys["gid"], authorized_keys["mode"]), (0, 0, "0644"))
            self.assertEqual((output / authorized_keys["source"]).stat().st_mode & 0o777, 0o600)
            tmpfiles = resources[native.TMPFILES]
            self.assertEqual((output / tmpfiles["source"]).read_bytes(), b"d /run/blender-box-proof 0700 root root -\n")
            self.assertEqual((tmpfiles["uid"], tmpfiles["gid"], tmpfiles["mode"]), (0, 0, "0644"))
            self.assertEqual(enrolled.value["artifacts"][native.TMPFILES], tmpfiles["sha256"])
            default = json.loads(self.invoke("proof_controller.py", "bootstrap").stdout)
            defaults = {entry["path"]: entry for entry in default["resources"] if "path" in entry}
            for entry in manifest["resources"] + manifest["directories"]:
                if entry["path"] in defaults:
                    proposed = defaults[entry["path"]]
                    self.assertEqual(proposed["mode"], entry["mode"])
                    if entry["uid"] == 0:
                        self.assertEqual((proposed["owner"], proposed["uid"]), ("root", 0))
            for name in ("operator.json", "policy.json"):
                self.assertEqual(defaults[str(native.CONFIG / name)]["owner"], "root")
            for path in (native.HELPER, native.WORKER):
                self.assertTrue(defaults[str(path)]["available"])
            proposed_policy = json.loads(default["proposed_files"][2]["content"])
            self.assertEqual(proposed_policy["native_helper"], str(native.HELPER))
            self.assertEqual(proposed_policy["native_worker"], str(native.WORKER))
            self.assertFalse(proposed_policy["qualified"])
            self.assertIn("ExecStart=/usr/bin/false", default["proposed_files"][0]["content"])
            self.assertIn(str(native.BASE / "tests/fixtures/onboarding-baseline/scenario.py"), resources)
            unit = (output / resources["/etc/systemd/system/" + native.UNIT]["source"]).read_text()
            self.assertIn("User=root\n", unit)
            self.assertIn("KillMode=control-group\n", unit)
            self.assertNotIn("[Install]", unit)
            repeat = self.invoke("proof_controller.py", "bootstrap", "--enrollment", str(enrollment), "--output", str(output))
            self.assertEqual(repeat.returncode, 1)
            self.assertEqual(repeat.stderr, b"")

    def test_cli_bad_enrollment_and_qualification_never_expose_traceback_or_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "bad.json"
            baseline.private_file(path, b'{"schema_version":1,"secret":"PRIVATE_SENTINEL"}')
            result = self.invoke("proof_controller.py", "bootstrap", "--enrollment", str(path), "--output", str(path.parent / "out"))
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)["code"], "native-enrollment-invalid")
            self.assertEqual(result.stderr, b"")
            self.assertFalse((path.parent / "out").exists())
        raw = model.proof.canonical({"schema_version": 1, "operation": "status", "execution_id": "gha_123_1"})
        env = dict(os.environ, GITHUB_RUN_ATTEMPT="1", BLENDER_BOX_NATIVE_BACKEND="fake")
        result = self.invoke("proof_controller_native.py", "dispatch", raw=raw, env=env)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["code"], "native-adapter-unqualified")
        self.assertEqual(result.stderr, b"")
        for extra in ("--apply", "--fake", "--local", "--qualify"):
            result = self.invoke("proof_controller_native.py", "dispatch", extra, raw=raw)
            self.assertEqual(json.loads(result.stdout)["code"], "invalid-command")

    def test_scp_pin_and_tmpfiles_binding_are_required(self):
        without_scp = spec()
        del without_scp["tool_sha256"]["/usr/bin/scp"]
        with self.assertRaisesRegex(model.ControllerError, "native-enrollment-invalid"):
            native.validate_enrollment(without_scp)
        without_tmpfiles = dict(policy().value)
        without_tmpfiles["artifacts"] = {path: digest for path, digest in without_tmpfiles["artifacts"].items()
                                        if path != native.TMPFILES}
        with self.assertRaisesRegex(model.ControllerError, "native-policy-invalid"):
            native.NativePolicy.parse(model.proof.canonical(without_tmpfiles))

    def test_qualified_loader_checks_every_pinned_byte_before_capabilities(self):
        contents = {path: ("pinned " + path).encode() for path in native.artifact_paths()}
        tools = {path: ("tool " + path).encode() for path in native.TOOLS}
        value = dict(policy().value)
        value["artifacts"] = {path: model.proof.digest(raw) for path, raw in contents.items()}
        value["tool_sha256"] = {path: model.proof.digest(raw) for path, raw in tools.items()}
        raw_policy = model.proof.canonical(value)
        qualification = {"schema_version": 1, "qualified": True, "policy_sha256": model.proof.digest(raw_policy),
                         "evidence": {name: "f" * 64 for name in native.QUALIFICATIONS}}
        operator = baseline.baseline_tests.operator_config()
        operator["ssh_config"] = str(native.CONFIG / "ssh-config")
        ssh = (f"Host {operator['target']['ssh_alias']}\nHostName test.invalid\nUser test-user\nPort 22\n"
               f"IdentityFile {native.CONFIG}/key\nUserKnownHostsFile {native.CONFIG}/known_hosts\n").encode()
        contents.update({str(native.CONFIG / "policy.json"): raw_policy,
                         str(native.CONFIG / "qualification.json"): model.proof.canonical(qualification),
                         str(native.CONFIG / "operator.json"): model.proof.canonical(operator),
                         str(native.CONFIG / "ssh-config"): ssh, str(native.CONFIG / "key"): b"fake-key",
                         str(native.CONFIG / "known_hosts"): b"fake-trust"})
        from types import SimpleNamespace
        def attempt(changed=None):
            sources = dict(contents)
            executables = dict(tools)
            if changed in sources:
                sources[changed] = b"changed-source"
            if changed in executables:
                executables[changed] = b"changed-tool"
            with mock.patch.object(native, "protected_read", side_effect=lambda path, *args, **kwargs: sources[str(path)]), \
                 mock.patch.object(native, "tool_read", side_effect=lambda path: executables[str(path)]), \
                 mock.patch.object(model, "no_links"), \
                 mock.patch.object(Path, "stat", return_value=SimpleNamespace(st_uid=0, st_mode=0o40755)), \
                 mock.patch.object(native, "sys_platform_linux", return_value=True), \
                 mock.patch.object(os, "getuid", return_value=0), mock.patch.object(os, "geteuid", return_value=0), \
                 mock.patch.object(native, "RootedFiles") as capability:
                if changed is not None:
                    with self.assertRaisesRegex(model.ControllerError, "native-adapter-unqualified"):
                        native.load_runtime()
                    capability.assert_not_called()
                else:
                    loaded, files = native.load_runtime()
                    self.assertEqual(loaded.digest, model.proof.digest(raw_policy))
                    self.assertEqual(len(files.capabilities), 4)
                    self.assertEqual(capability.call_args_list, [mock.call(native.CONTROL, 0, 0),
                                     mock.call(native.JOBS, 1902, 1902), mock.call(native.CONFIG, 0, 0),
                                     mock.call(native.RUNTIME, 0, 0)])
        attempt()
        attempt(str(native.BASE / "scripts/proof_controller_worker.py"))
        attempt("/usr/bin/scp")

    def test_fixed_tool_symlink_resolves_with_root_owner_model_and_rejects_untrusted_link(self):
        from types import SimpleNamespace
        actual_lstat = Path.lstat
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root / "python-real"
            target.write_bytes(b"fixed-tool-bytes")
            target.chmod(0o755)
            link = root / "python"
            link.symlink_to("python-real")
            def info(path, *args, **kwargs):
                result = actual_lstat(path, *args, **kwargs)
                return SimpleNamespace(st_uid=0, st_mode=result.st_mode & ~0o022)
            with mock.patch.object(native, "TOOLS", (str(link),)), mock.patch.object(Path, "lstat", info), \
                 mock.patch.object(native, "protected_read", side_effect=lambda path: path.read_bytes()) as read:
                self.assertEqual(native.tool_read(link), b"fixed-tool-bytes")
                self.assertEqual(read.call_args.args[0], target)
                for owner, mode in ((1902, 0o120777), (0, 0o100777)):
                    def invalid(path, *args, **kwargs):
                        return SimpleNamespace(st_uid=owner, st_mode=mode) if path == link else info(path, *args, **kwargs)
                    with mock.patch.object(Path, "lstat", invalid):
                        with self.assertRaisesRegex(model.ControllerError, "native-source-untrusted"):
                            native.tool_read(link)

    def test_false_or_wrong_binding_refuses_before_any_native_mutation(self):
        chosen = policy()
        qualification = {"schema_version": 1, "qualified": False, "policy_sha256": chosen.digest,
                         "evidence": {key: "f" * 64 for key in native.QUALIFICATIONS}}
        for change in ({}, {"qualified": True, "policy_sha256": "0" * 64}, {"qualified": True, "evidence": {}}):
            raw = model.proof.canonical(qualification | change)
            with self.assertRaisesRegex(model.ControllerError, "native-adapter-unqualified"):
                chosen.qualify(raw)
        with mock.patch.object(native, "protected_read", side_effect=[model.proof.canonical(chosen.value),
                                  model.proof.canonical(qualification)]), \
             mock.patch.object(native, "RootedFiles") as files, mock.patch.object(native, "LinuxOps") as ops:
            with self.assertRaises(model.ControllerError):
                native.load_runtime()
            files.assert_not_called()
            ops.assert_not_called()


class WorkerProtocolTests(unittest.TestCase):
    def test_real_socket_gate_has_zero_work_before_authorized_envelope(self):
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        result_parent, result_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        for endpoint in (parent, child, result_parent, result_child):
            self.addCleanup(endpoint.close)
        fake = mock.Mock()
        fake.baseline.return_value = {"status": "pass"}
        errors = []
        def run():
            try:
                worker.run_worker(child, result_child, fake)
            except Exception as error:
                errors.append(error)
        thread = threading.Thread(target=run)
        thread.start()
        self.addCleanup(lambda: thread.join(1))
        self.assertEqual(worker.receive(result_parent, model.MAX_WIRE), {"schema_version": 1, "ready": True})
        fake.baseline.assert_not_called()
        expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        envelope = {"schema_version": 1, "request": asdict(baseline.request(expires_at=expires)), "attempt": 1,
                    "expected_client_sha256": "c" * 64, "inputs_digest": "d" * 64, "mode": "baseline", "retained": None}
        parent.sendall(model.proof.canonical(envelope))
        self.assertEqual(worker.receive(result_parent, model.MAX_FILE), {"schema_version": 1, "result": {"status": "pass"}})
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(fake.baseline.call_args.args[0].root, native.JOBS / "gha_123_1")

    def test_closed_expired_or_malformed_gate_cannot_run_proof(self):
        for raw in (b"", b"{}", model.proof.canonical({"schema_version": 1, "request": asdict(baseline.request()),
                    "attempt": 1, "expected_client_sha256": "c" * 64, "inputs_digest": "d" * 64,
                    "mode": "baseline", "retained": None})):
            gate = mock.Mock()
            gate.recvmsg.return_value = (raw, [], 0, None)
            fake = mock.Mock()
            with self.assertRaises(model.ControllerError):
                worker.run_worker(gate, mock.Mock(), fake)
            fake.baseline.assert_not_called()
            fake.recover.assert_not_called()

    def test_release_requires_exact_durable_authorization(self):
        receipt = native.NativeReceipt(invocation(), 3000, 2, 3)
        authorization = model.proof.canonical({"schema_version": 1, "invocation": asdict(invocation()), "mode": "baseline"})
        token = {"schema_version": 1, "operation": "release", "invocation": asdict(invocation()),
                 "authorization_sha256": model.proof.digest(authorization)}
        self.assertEqual(worker.parse_release(token, receipt, authorization), "baseline")
        for value in (token | {"authorization_sha256": "f" * 64}, token | {"operation": "exec"},
                      token | {"invocation": asdict(replace(invocation(), leader_start_ticks=4002))}):
            with self.assertRaises(model.ControllerError):
                worker.parse_release(value, receipt, authorization)

    def test_drop_closes_unrelated_fds_clears_groups_and_execs_only_protected_worker(self):
        chosen = policy()
        events = []
        def record(name):
            return lambda *args: events.append((name, args))
        libc = mock.Mock()
        libc.prctl.return_value = 0
        with mock.patch.object(worker.resource, "getrlimit", return_value=(100, 100)), \
             mock.patch.object(os, "closerange", side_effect=record("close")), \
             mock.patch.object(os, "setgroups", side_effect=record("groups")), \
             mock.patch.object(os, "setgid", side_effect=record("gid")), \
             mock.patch.object(os, "setuid", side_effect=record("uid")), \
             mock.patch.object(os, "getuid", return_value=1902), mock.patch.object(os, "geteuid", return_value=1902), \
             mock.patch.object(os, "getgroups", return_value=[]), mock.patch.object(worker.ctypes, "CDLL", return_value=libc), \
             mock.patch.object(os, "set_inheritable"), mock.patch.object(os, "chdir"), \
             mock.patch.object(os, "execve", side_effect=record("exec")):
            worker.drop_and_exec(chosen, 7, 9)
        self.assertEqual(events[:6], [("close", (0, 7)), ("close", (8, 9)), ("close", (10, 100)),
                                     ("groups", ([],)), ("gid", (1902,)), ("uid", (1902,))])
        executable, argv, env = events[-1][1]
        self.assertEqual(executable, "/usr/bin/python3")
        self.assertEqual(argv[1:3], ["-I", "-S"])
        self.assertIn(str(native.BASE / "scripts"), argv[4])
        self.assertNotIn(str(native.CANDIDATE), argv[4])
        self.assertEqual(argv[5:], ["run", "7", "9"])
        self.assertEqual(env, chosen.environment())
        self.assertNotIn("SSH_AUTH_SOCK", env)

    def test_peer_credential_and_pid_reuse_reject_before_release_bytes(self):
        receipt = native.NativeReceipt(invocation(), 3000, 2, 3)
        ops = native.LinuxOps(policy())
        for uid, pid, start in ((1902, 300, 3000), (0, 301, 3000), (0, 300, 3001)):
            connection = mock.MagicMock()
            connection.__enter__.return_value = connection
            import struct
            connection.getsockopt.return_value = struct.pack("3i", pid, uid, 0)
            with mock.patch.object(native.socket, "SO_PEERCRED", 17, create=True), \
                 mock.patch.object(native.socket, "socket", return_value=connection), \
                 mock.patch.object(ops, "process", return_value=native.Process(pid, 1, start, native.UNIT_CGROUP)):
                with self.assertRaisesRegex(model.ControllerError, "native-peer-invalid"):
                    ops.exchange(receipt, {"operation": "release"})
            connection.sendall.assert_not_called()


class NativeLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.fixture = baseline.ControllerTests("run")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.runtime = self.fixture.root / "runtime"
        self.runtime.mkdir(mode=0o700)
        patches = mock.patch.multiple(native, CONTROL=self.fixture.control, JOBS=self.fixture.jobs,
                                      CANDIDATE=self.fixture.checkout, RUNTIME=self.runtime)
        patches.start()
        self.addCleanup(patches.stop)
        self.files = store.LocalFiles()
        self.events = []
        self.completed = None
        self.empty = True
        self.receipt = None
        self.ops = mock.Mock()
        self.ops.boot.return_value = "1" * 32
        self.ops.whole_empty.side_effect = lambda: self.empty
        self.ops.supervisor_gone.return_value = True
        self.ops.process.return_value = native.Process(300, 1, 3000, native.UNIT_CGROUP)
        self.ops.systemctl.side_effect = self.start_native
        self.ops.unit.side_effect = lambda: native.UnitState("active", 300, "2" * 32, native.UNIT_CGROUP)
        self.ops.exchange.side_effect = self.release_native
        self.ops.stop.side_effect = self.stop_native
        self.native_service = native.NativeService(policy(), self.files, self.ops)
        def wait(path, predicate, timeout):
            result = predicate()
            if result is None:
                raise model.ControllerError("native-start-unconfirmed")
            return result
        watcher = mock.patch.object(native, "wait_file", side_effect=wait)
        watcher.start()
        self.addCleanup(watcher.stop)
        self.admission = mock.Mock()
        self.controller = model.Controller(self.fixture.control, self.fixture.jobs, self.fixture.policy,
                                           self.native_service, self.fixture.worker, lambda: baseline.NOW,
                                           files=self.files, admission=self.admission)

    def start_native(self, operation):
        self.assertEqual(operation, "start")
        pending = model.document(self.files.read(self.runtime / "pending.json"))
        root = self.fixture.control / pending["execution_id"]
        self.assertEqual(model.document(self.files.read(root / "execution.json"))["phase"], "starting")
        self.assertEqual(model.document(self.files.read(root / "intent-0001.json")), pending)
        self.assertFalse((root / "authorization-0001.json").exists())
        self.events.append("intent-before-start")
        self.receipt = native.NativeReceipt(invocation(), 3000, 2, 3)
        self.files.publish(native.receipt_path(invocation()), model.proof.canonical(asdict(self.receipt)))
        self.empty = False

    def release_native(self, receipt, token):
        root = self.fixture.control / receipt.invocation.execution_id
        state = model.document(self.files.read(root / "execution.json"))
        authorization = self.files.read(root / "authorization-0001.json")
        self.assertEqual(state["invocation"], asdict(receipt.invocation))
        self.assertEqual(worker.parse_release(token, receipt, authorization), "baseline")
        self.events.append("identity-authorization-before-release")
        return {"schema_version": 1, "released": True, "invocation": asdict(receipt.invocation)}

    def stop_native(self, receipt):
        self.assertEqual(receipt, self.receipt)
        self.empty = True
        return True

    def test_controller_native_intent_identity_authorization_result_and_recovery_reads(self):
        running = self.controller.dispatch(baseline.command())
        self.assertEqual(running["phase"], "running")
        self.assertEqual(self.events, ["intent-before-start", "identity-authorization-before-release"])
        self.assertEqual(self.controller.dispatch(baseline.command()), running)
        self.assertEqual(self.ops.systemctl.call_count, 1)
        control = self.fixture.control / "gha_123_1"
        state = self.controller.load(control)
        job = self.controller.job(control, state)
        result = self.fixture.worker.baseline(job)
        self.files.publish(control / "result-0001.json", model.proof.canonical({"schema_version": 1,
                           "invocation": asdict(invocation()), "mode": "baseline", "result": result}))
        self.assertEqual(self.controller.dispatch(baseline.command("status"))["phase"], "running")
        self.empty = True
        settled = self.controller.dispatch(baseline.command("status"))
        self.assertEqual(settled["phase"], "settled")
        self.assertEqual(settled["windows_cleanup"], "proven")
        retained = self.controller.load(control)["recovery_inputs"]
        self.assertTrue(retained["journal"].startswith(str(job.config / "runs")))
        self.assertEqual(retained, model.recovery_inputs(job, self.files))
        self.assertEqual(self.native_service.observe().invocation, invocation())

    def test_native_receipt_waits_through_real_two_link_publication(self):
        request = baseline.request()
        root = self.fixture.control / request.execution_id
        root.mkdir(mode=0o700)
        intent = {"schema_version": 1, "execution_id": request.execution_id, "attempt": 1,
                  "request_digest": request.digest, "mode": "baseline"}
        self.files.publish(root / "intent-0001.json", model.proof.canonical(intent))
        caps = [anchored(self.fixture.control), anchored(self.runtime)]
        for cap in caps:
            self.addCleanup(cap.close)
        files = store.FixtureFiles(*caps)
        receipt = native.NativeReceipt(invocation(), 3000, 2, 3)
        destination = native.receipt_path(invocation())
        temporary = root / ".publish-test"
        def publish_window(operation):
            self.assertEqual(operation, "start")
            self.files.publish(temporary, model.proof.canonical(asdict(receipt)))
            os.link(temporary, destination)
        self.ops.systemctl.side_effect = publish_window
        service = native.NativeService(policy(), files, self.ops)
        events = []
        def receive_events(path, ready, timeout):
            self.assertEqual(destination.stat().st_nlink, 2)
            with self.assertRaises(store.PendingPublication):
                files.read(path)
            events.append("created-two-links")
            self.assertIsNone(ready())
            self.assertIsNone(ready())
            temporary.unlink()
            events.append("deleted-temporary")
            self.assertEqual(destination.stat().st_nlink, 1)
            return ready()
        with mock.patch.object(os, "fchown"), mock.patch.object(native, "wait_file", side_effect=receive_events):
            self.assertEqual(service.start(request, 1), invocation())
        self.assertEqual(events, ["created-two-links", "deleted-temporary"])
        os.link(destination, temporary)
        with self.assertRaises(store.PendingPublication):
            service.receipt(invocation())
        destination.chmod(0o644)
        with self.assertRaisesRegex(model.ControllerError, "private-file-invalid"):
            files.read(destination)

    def failed_start(self):
        def failed(operation):
            self.start_native(operation)
            path = native.receipt_path(invocation())
            path.unlink()
            intent = native.parse_intent(self.files.read(self.runtime / "pending.json"))
            failure = native.StartupFailure(intent, model.proof.digest(self.files.read(native.attempt_path(intent, "intent"))),
                                            "1" * 32, "2" * 32, 300, 3000, invocation().cgroup, 2, 3)
            self.files.publish(native.attempt_path(intent, "startup-failure"), model.proof.canonical(asdict(failure)))
            self.empty = True
        self.ops.systemctl.side_effect = failed
        self.ops.unit.side_effect = lambda: native.UnitState("failed", 0, "2" * 32, native.UNIT_CGROUP)
        self.ops.process.side_effect = FileNotFoundError()
        with self.assertRaisesRegex(model.ControllerError, "native-start-unconfirmed"):
            self.controller.dispatch(baseline.command())
        return self.fixture.control / "gha_123_1"

    def test_failed_baseline_settles_without_invocation_and_admits_next_request(self):
        root = self.failed_start()
        settled = self.controller.dispatch(baseline.command("status"))
        self.assertEqual((settled["phase"], settled["proof_result"], settled["windows_cleanup"], settled["local_termination"]),
                         ("settled", "fail", "proven", "proven"))
        state = self.controller.load(root)
        self.assertIsNone(state["invocation"])
        self.assertIsNone(state["recovery_inputs"])
        before = self.ops.systemctl.call_count
        self.assertEqual(self.controller.dispatch(baseline.command()), settled)
        self.assertEqual(self.controller.dispatch(baseline.command("stop")), settled)
        self.assertEqual(self.ops.systemctl.call_count, before)
        self.ops.exchange.assert_not_called()
        self.ops.stop.assert_not_called()
        self.assertTrue(self.native_service.observe().empty)
        self.ops.systemctl.side_effect = model.ControllerError("next-start-reached")
        with self.assertRaisesRegex(model.ControllerError, "next-start-reached"):
            self.controller.dispatch(baseline.command(execution_id="next_attempt"))
        self.assertTrue((self.fixture.control / "next_attempt/request.json").exists())

    def test_failure_proof_crash_replay_and_fixture_lock_prevent_concurrent_release(self):
        root = self.failed_start()
        original = self.files.publish
        def crash(path, raw, **kwargs):
            if path == root / "execution.json" and model.document(raw)["phase"] == "settled":
                raise baseline.Crash()
            return original(path, raw, **kwargs)
        with mock.patch.object(self.files, "publish", side_effect=crash):
            with self.assertRaises(baseline.Crash):
                self.controller.dispatch(baseline.command("status"))
        self.assertTrue((root / "unreleased-0001.json").exists())
        with self.controller.locked():
            with self.assertRaisesRegex(model.ControllerError, "fixture-busy"):
                self.controller.dispatch(baseline.command("status"))
        self.assertEqual(self.controller.dispatch(baseline.command("status"))["phase"], "settled")
        with self.assertRaisesRegex(model.ControllerError, "attempt-unreleased"):
            self.native_service.release(invocation(), root / "authorization-0001.json", None, "baseline", None)
        with self.assertRaisesRegex(model.ControllerError, "attempt-unreleased"):
            worker.Supervisor(policy(), self.files, self.ops).serve()
        self.ops.exchange.assert_not_called()

    def test_every_no_launch_veto_preserves_unknown_without_signals(self):
        root = self.failed_start()
        failure_path = root / "startup-failure-0001.json"
        issuer_path = root / "start-command-0001.json"
        pending_path = self.runtime / "pending.json"
        intent_path = root / "intent-0001.json"
        request_path = root / "request.json"
        originals = {path: path.read_bytes() for path in (failure_path, issuer_path, pending_path, intent_path, request_path)}
        invalid_files = [root / "native-0001.json", root / "authorization-0001.json", root / "result-0001.json"]
        for path in invalid_files:
            self.files.publish(path, b"malformed-but-present")
            with self.assertRaises(model.ControllerError):
                self.controller.dispatch(baseline.command("status"))
            path.unlink()
        for path in (failure_path, issuer_path):
            path.unlink()
            self.assertEqual(self.controller.dispatch(baseline.command("status"))["local_termination"], "unknown")
            self.files.publish(path, originals[path])
        for path in (failure_path, issuer_path, pending_path, intent_path, request_path):
            self.files.publish(path, b"malformed", exclusive=False)
            with self.assertRaises(model.ControllerError):
                self.controller.dispatch(baseline.command("status"))
            self.files.publish(path, originals[path], exclusive=False)
        pending_path.unlink()
        with self.assertRaisesRegex(model.ControllerError, "fixture-unresolved"):
            self.controller.dispatch(baseline.command("status"))
        self.files.publish(pending_path, originals[pending_path])
        pending = model.document(originals[pending_path]) | {"execution_id": "replacement"}
        self.files.publish(pending_path, model.proof.canonical(pending), exclusive=False)
        with self.assertRaisesRegex(model.ControllerError, "fixture-unresolved"):
            self.controller.dispatch(baseline.command("status"))
        self.files.publish(pending_path, originals[pending_path], exclusive=False)
        for unit in (native.UnitState("active", 300, "2" * 32, native.UNIT_CGROUP),
                     native.UnitState("inactive", 0, "2" * 32, native.UNIT_CGROUP, 42),
                     native.UnitState("inactive", 0, "9" * 32, native.UNIT_CGROUP)):
            self.ops.unit.side_effect = lambda unit=unit: unit
            with self.assertRaisesRegex(model.ControllerError, "fixture-unresolved"):
                self.controller.dispatch(baseline.command("status"))
        self.ops.unit.side_effect = lambda: native.UnitState("failed", 0, "2" * 32, native.UNIT_CGROUP)
        self.empty = False
        with self.assertRaisesRegex(model.ControllerError, "fixture-unresolved"):
            self.controller.dispatch(baseline.command("status"))
        self.empty = True
        self.ops.process.side_effect = None
        self.ops.process.return_value = native.Process(300, 1, 3000, native.UNIT_CGROUP)
        with self.assertRaisesRegex(model.ControllerError, "fixture-unresolved"):
            self.controller.dispatch(baseline.command("status"))
        self.assertFalse((root / "unreleased-0001.json").exists())
        self.ops.exchange.assert_not_called()
        self.ops.stop.assert_not_called()

    def test_final_proof_recheck_vetoes_release_publication_event(self):
        root = self.failed_start()
        observations = []
        def snapshot():
            observations.append("unit")
            if len(observations) == 2:
                self.files.publish(root / "authorization-0001.json", b"publication-in-progress")
            return native.UnitState("inactive", 0, "2" * 32, native.UNIT_CGROUP)
        self.ops.unit.side_effect = snapshot
        with self.assertRaisesRegex(model.ControllerError, "unreleased-proof-invalid"):
            self.controller.dispatch(baseline.command("status"))
        self.assertEqual(observations, ["unit", "unit"])
        self.assertFalse((root / "unreleased-0001.json").exists())
        self.ops.exchange.assert_not_called()

    def test_reboot_proof_never_reads_old_pid_and_preserves_failed_recovery_inputs(self):
        root = self.failed_start()
        (self.runtime / "pending.json").unlink()
        self.ops.boot.return_value = "9" * 32
        self.ops.process.reset_mock()
        self.assertEqual(self.controller.dispatch(baseline.command("status"))["phase"], "settled")
        self.ops.process.assert_not_called()
        self.ops.stop.assert_not_called()
        state = self.controller.load(root)
        run_id = "bbx_" + "a" * 32
        state.update(phase="unresolved", attempt=2, local_termination="unknown", windows_cleanup="unknown",
                     recovery_inputs={"schema_version": 1, "run_id": run_id, "client_sha256": state["expected_client_sha256"],
                                      "target_sha256": "c" * 64, "journal": str(self.fixture.jobs / "gha_123_1/baseline/private/config/runs" / (run_id + ".json"))})
        self.controller.save(root, state)
        intent = {"schema_version": 1, "execution_id": "gha_123_1", "attempt": 2,
                  "request_digest": baseline.request().digest, "mode": "recover"}
        intent_raw = model.proof.canonical(intent)
        failure = native.StartupFailure(intent, model.proof.digest(intent_raw), "1" * 32, "2" * 32, 300, 3000,
                                        invocation().cgroup, 2, 3)
        for kind, record in (("intent", intent), ("startup-failure", asdict(failure)),
                             ("start-command", {"schema_version": 1, "boot_id": "1" * 32, "intent_sha256": model.proof.digest(intent_raw)})):
            self.files.publish(native.attempt_path(intent, kind), model.proof.canonical(record))
        retained = dict(state["recovery_inputs"])
        observed = self.controller.dispatch(baseline.command("status"))
        self.assertEqual((observed["phase"], observed["local_termination"], observed["windows_cleanup"]),
                         ("unresolved", "proven", "unknown"))
        self.assertEqual(self.controller.load(root)["recovery_inputs"], retained)
        self.ops.exchange.assert_not_called()
        self.ops.stop.assert_not_called()

    def test_expiry_and_native_admission_refuse_before_files_or_service(self):
        with self.assertRaisesRegex(model.ControllerError, "execution-expired"):
            self.controller.dispatch(baseline.command(expires_at="2026-09-06T16:00:00Z"))
        self.assertFalse((self.fixture.control / "gha_123_1").exists())
        self.ops.systemctl.assert_not_called()
        self.admission.side_effect = model.ControllerError("request-not-authorized")
        with self.assertRaisesRegex(model.ControllerError, "request-not-authorized"):
            self.controller.dispatch(baseline.command())
        self.ops.systemctl.assert_not_called()

    def test_source_preflight_executes_no_untrusted_module(self):
        sentinel = self.fixture.root / "imported"
        scripts = self.fixture.root / "unsafe/scripts"
        scripts.mkdir(parents=True)
        for name in ("proof_controller", "proof_controller_native", "proof_controller_store", "proof_controller_worker", "onboarding_proof"):
            (scripts / (name + ".py")).write_text("from pathlib import Path\nPath(" + repr(str(sentinel)) + ").touch()\n")
        with mock.patch.object(native, "BASE", scripts.parent):
            code = native.launcher_code("proof_controller_native")
        result = subprocess.run([sys.executable, "-I", "-S", "-c", code, "dispatch"], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["code"], "native-adapter-unqualified")
        self.assertEqual(result.stderr, b"")
        self.assertFalse(sentinel.exists())

    def test_actual_fake_systemctl_receives_fixed_argv_and_capture_is_bounded(self):
        executable = self.fixture.root / "fake-systemctl"
        record = self.fixture.root / "argv.json"
        executable.write_text("#!" + sys.executable + "\nimport json,sys\nfrom pathlib import Path\n"
                              + "Path(" + repr(str(record)) + ").write_text(json.dumps(sys.argv[1:]))\n"
                              + "sys.stdout.buffer.write(" + repr(unit_bytes()) + ")\n")
        executable.chmod(0o700)
        def run(argv, **kwargs):
            return native.bounded_command([str(executable)] + argv[1:], **kwargs)
        ops = native.LinuxOps(policy(), _run=run)
        self.assertEqual(ops.unit().main_pid, 300)
        self.assertEqual(json.loads(record.read_text()), ["--no-pager", "--no-ask-password", "show", "--all",
                         "--property=" + ",".join(native.PROPERTIES), native.UNIT])
        kwargs = dict(stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                      env={"PATH": "/usr/bin"}, timeout=3, check=False, close_fds=True)
        with self.assertRaisesRegex(model.ControllerError, "native-service-unavailable"):
            native.bounded_command([sys.executable, "-c", "import os; os.write(1,b'x'*20000)"], **kwargs)

    def test_membership_failure_closes_gate_and_reaps_owned_child_without_release(self):
        request = baseline.request()
        root = self.fixture.control / request.execution_id
        root.mkdir(mode=0o700)
        pending = {"schema_version": 1, "execution_id": request.execution_id, "attempt": 1,
                   "request_digest": request.digest, "mode": "baseline"}
        for path, value in ((self.runtime / "pending.json", pending), (root / "intent-0001.json", pending),
                            (root / "request.json", asdict(request))):
            self.files.publish(path, model.proof.canonical(value))
        parent_dir = self.fixture.root / "fake-cgroup"
        parent_dir.mkdir()
        @contextmanager
        def group(name):
            path = parent_dir if name == native.UNIT_CGROUP else parent_dir / name.rsplit("/", 1)[1]
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                yield fd
            finally:
                os.close(fd)
        ops = mock.Mock()
        ops.group.side_effect = group
        ops.unit.return_value = native.UnitState("active", os.getpid(), "2" * 32, native.UNIT_CGROUP)
        ops.process.return_value = native.Process(os.getpid(), 1, 123, native.UNIT_CGROUP)
        ops.boot.return_value = "1" * 32
        def write(fd, name, data):
            if name == "cgroup.procs":
                raise OSError("membership refused")
        ops.write_group.side_effect = write
        endpoints = [mock.Mock() for _ in range(4)]
        with mock.patch.object(worker.socket, "socketpair", side_effect=[tuple(endpoints[:2]), tuple(endpoints[2:])]), \
             mock.patch.object(os, "fork", return_value=456), mock.patch.object(worker, "reap_child") as reap:
            with self.assertRaisesRegex(OSError, "membership refused"):
                worker.Supervisor(policy(), self.files, ops).serve()
        for endpoint in endpoints:
            endpoint.close.assert_called()
            endpoint.sendall.assert_not_called()
        self.assertEqual(reap.call_args.args[0], 456)
        self.assertFalse((root / "native-0001.json").exists())
        self.assertEqual([call.args[1] for call in ops.write_group.call_args_list], ["cgroup.procs", "cgroup.kill"])
        failure_path = root / "startup-failure-0001.json"
        failure = native.StartupFailure.parse(model.document(self.files.read(failure_path)))
        self.assertEqual(failure.intent, pending)
        self.assertEqual(failure.supervisor_pid, os.getpid())
        self.assertEqual(failure.intent_sha256, model.proof.digest(self.files.read(root / "intent-0001.json")))
        failure_path.unlink()
        ops.wait_group_empty.side_effect = model.ControllerError("local-termination-unknown")
        with mock.patch.object(worker.socket, "socketpair", side_effect=[tuple(endpoints[:2]), tuple(endpoints[2:])]), \
             mock.patch.object(os, "fork", return_value=457), mock.patch.object(worker, "reap_child"):
            with self.assertRaisesRegex(model.ControllerError, "local-termination-unknown"):
                worker.Supervisor(policy(), self.files, ops).serve()
        self.assertFalse(failure_path.exists())



if __name__ == "__main__":
    unittest.main()
