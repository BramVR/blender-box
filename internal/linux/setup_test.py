import contextlib
import importlib.util
import io
import json
import os
import pathlib
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

bootstrap = None
if os.name != "nt":
    spec = importlib.util.spec_from_file_location("linux_setup", pathlib.Path(__file__).with_name("setup.py"))
    bootstrap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bootstrap)


@unittest.skipIf(bootstrap is None, "POSIX bootstrap helpers")
class SetupBoundaryTests(unittest.TestCase):
    def test_reused_complete_temporary_is_flushed_before_rename(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            destination = root / "host"
            temporary = pathlib.Path(str(destination) + ".linux-setup.tmp")
            temporary.write_bytes(b"binary")
            temporary.chmod(0o700)
            events = []
            fsync, replace = os.fsync, os.replace

            def flushed(fd):
                events.append(("fsync", os.fstat(fd).st_ino))
                return fsync(fd)

            def renamed(source, target):
                events.append(("replace", source))
                return replace(source, target)

            inode = temporary.stat().st_ino
            with mock.patch.object(bootstrap.os, "fsync", side_effect=flushed), mock.patch.object(bootstrap.os, "replace", side_effect=renamed):
                bootstrap.atomic_write(str(destination), b"binary", 0o700, os.getuid())
            self.assertEqual(destination.read_bytes(), b"binary")
            self.assertEqual(events[0], ("fsync", inode))
            self.assertEqual(events[1][0], "replace")
            self.assertEqual(events[2][0], "fsync")

    def test_partial_temporary_remains_for_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory).resolve() / "host"
            temporary = pathlib.Path(str(target) + ".linux-setup.tmp")
            temporary.write_bytes(b"part")
            temporary.chmod(0o700)
            with self.assertRaisesRegex(RuntimeError, "needs inspection"):
                bootstrap.atomic_write(str(target), b"complete binary", 0o700, os.getuid())
            self.assertFalse(target.exists())
            self.assertEqual(temporary.read_bytes(), b"part")

    def test_subprocess_output_is_bounded_while_running(self):
        with self.assertRaisesRegex(RuntimeError, "output exceeds bound"):
            bootstrap.run([sys.executable, "-I", "-S", "-c", "import os; data=b'x'*8192\nwhile True: os.write(1,data)"], {}, timeout=5)

    def test_subprocess_stdin_cannot_escape_deadline(self):
        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, "deadline exceeded"):
            bootstrap.run([sys.executable, "-I", "-S", "-c", "import threading; threading.Event().wait()"], {}, b"x" * 65536, timeout=0.2)
        self.assertLess(time.monotonic() - started, 3)

    def test_symlink_and_writable_parent_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            link = root / "link"
            link.symlink_to(root)
            with self.assertRaisesRegex(RuntimeError, "unsafe path type"):
                bootstrap.safe_path(str(link), os.getuid())
            parent = root / "shared"
            parent.mkdir(mode=0o777)
            parent.chmod(0o777)
            with self.assertRaisesRegex(RuntimeError, "unsafe path owner or mode"):
                bootstrap.safe_path(str(parent / "new"), os.getuid(), missing=True)


@unittest.skipIf(bootstrap is None, "POSIX setup application")
class SetupPublicationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.home = pathlib.Path(self.directory.name).resolve() / "home"
        self.home.mkdir(mode=0o700)
        self.root = self.home / "box"
        self.root.mkdir(mode=0o700)
        self.unit = self.home / ".config/systemd/user/blender-box.service"
        self.host = self.root / "bin/blender-box"
        self.active = False
        self.commands = []
        desktop = {"display": ":0", "xauthority": "/run/user/1000/gdm/Xauthority"}
        self.config = {"uid": 1000, "home": str(self.home), "work_root": str(self.root), "host_executable": str(self.host), "unit_name": "blender-box.service", "desktop": desktop}
        unit_bytes = ("[Unit]\nDescription=Blender Box owned Run launcher\n\n[Service]\n"
                      "Type=exec\nExitType=cgroup\nRemainAfterExit=no\nRestart=no\nKillMode=process\n"
                      "ExecStart=" + str(self.host) + " host run-request --state-root " + str(self.root) + "\n"
                      "Environment=HOME=" + str(self.home) + "\nEnvironment=DISPLAY=:0\n"
                      "Environment=XAUTHORITY=" + desktop["xauthority"] + "\n"
                      "Environment=XDG_RUNTIME_DIR=/run/user/1000\n"
                      "Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus\n")
        binary = b"fake owned host binary"
        self.plan = {"host_destination": str(self.host), "unit_destination": str(self.unit), "unit_name": "blender-box.service", "host_size": len(binary), "host_sha256": bootstrap.digest(binary), "unit_bytes": unit_bytes, "unit_sha256": bootstrap.digest(unit_bytes.encode())}
        self.document = {"config": self.config, "plan": self.plan, "binary": bootstrap.base64.b64encode(binary).decode()}
        native_uid, native_lstat, native_fstat = os.getuid(), os.lstat, os.fstat

        def stat_uid(info):
            values = list(info)
            if values[4] == native_uid:
                values[4] = 1000
            return os.stat_result(values)

        read_text = pathlib.Path.read_text

        def platform_text(path, *args, **kwargs):
            if str(path) == "/etc/os-release":
                return 'ID=ubuntu\nVERSION_ID="24.04"\n'
            return read_text(path, *args, **kwargs)

        patches = [mock.patch.object(bootstrap.sys, "platform", "linux"), mock.patch.object(bootstrap.sys, "version_info", (3, 12)),
                   mock.patch.object(bootstrap.os, "getuid", return_value=1000), mock.patch.object(bootstrap.os, "geteuid", return_value=1000),
                   mock.patch.object(bootstrap.os, "lstat", side_effect=lambda *a, **kw: stat_uid(native_lstat(*a, **kw))),
                   mock.patch.object(bootstrap.os, "fstat", side_effect=lambda *a, **kw: stat_uid(native_fstat(*a, **kw))),
                   mock.patch.object(bootstrap.pwd, "getpwuid", return_value=types.SimpleNamespace(pw_dir=str(self.home))),
                   mock.patch.object(pathlib.Path, "read_text", new=platform_text), mock.patch.object(bootstrap, "run", side_effect=self.external)]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def external(self, command, environment, input_data=None):
        self.commands.append(command)
        if command == ["/usr/bin/systemctl", "--version"]:
            return 0, b"systemd 255 (255.4)\n", b""
        if "show" in command:
            state = "active" if self.active else "inactive"
            return 0, ("LoadState=not-found\nActiveState=" + state + "\nFragmentPath=\nDropInPaths=\nNames=blender-box.service\n").encode(), b""
        if "daemon-reload" in command:
            self.assertEqual(bootstrap.digest(self.host.read_bytes()), self.plan["host_sha256"])
            self.assertEqual(bootstrap.digest(self.unit.read_bytes()), self.plan["unit_sha256"])
            return 0, b"", b""
        self.assertEqual(command, [str(self.host), "host", "linux-unit-check", "--state-root", str(self.root)])
        self.assertEqual(json.loads(input_data), self.config)
        return 0, b'{"schema_version":1,"status":"unit-verified"}', b""

    def apply(self):
        with contextlib.redirect_stdout(io.StringIO()):
            bootstrap.apply(self.document)

    def test_active_unit_and_host_lock_refuse_before_publication(self):
        self.active = True
        with self.assertRaisesRegex(RuntimeError, "must be inactive"):
            self.apply()
        self.assertFalse(self.host.exists())
        self.assertFalse((self.root / ".linux-setup.json").exists())
        self.active = False
        (self.root / "host-lock.json").write_text("{}")
        with self.assertRaisesRegex(RuntimeError, "Host Lock exists"):
            self.apply()
        self.assertFalse(self.unit.exists())

    def test_interrupted_binary_publication_retries_only_owned_artifacts(self):
        original = bootstrap.atomic_write

        def interrupt(path, *args):
            if path == str(self.unit):
                raise RuntimeError("injected after binary publication")
            return original(path, *args)

        with mock.patch.object(bootstrap, "atomic_write", side_effect=interrupt):
            with self.assertRaisesRegex(RuntimeError, "injected"):
                self.apply()
        receipt = json.loads((self.root / ".linux-setup.json").read_bytes())
        self.assertEqual(receipt["pending"]["host_sha256"], bootstrap.digest(self.host.read_bytes()))
        self.assertFalse(self.unit.exists())
        self.apply()
        receipt = json.loads((self.root / ".linux-setup.json").read_bytes())
        self.assertNotIn("pending", receipt)
        self.assertEqual(receipt["installed"]["unit_sha256"], bootstrap.digest(self.unit.read_bytes()))
        self.host.write_bytes(b"foreign modification")
        with self.assertRaisesRegex(RuntimeError, "artifact drifted"):
            self.apply()
        self.assertEqual(self.host.read_bytes(), b"foreign modification")

    def test_new_candidate_preserves_interrupted_installed_hash(self):
        original = bootstrap.atomic_write

        def fail_unit(path, *args):
            if path == str(self.unit):
                raise RuntimeError("first interruption")
            return original(path, *args)

        with mock.patch.object(bootstrap, "atomic_write", side_effect=fail_unit):
            with self.assertRaisesRegex(RuntimeError, "first interruption"):
                self.apply()
        first_hash = bootstrap.digest(self.host.read_bytes())
        second = b"replacement host candidate"
        self.document["binary"] = bootstrap.base64.b64encode(second).decode()
        self.plan["host_size"] = len(second)
        self.plan["host_sha256"] = bootstrap.digest(second)

        def fail_binary(path, *args):
            if path == str(self.host):
                raise RuntimeError("second interruption")
            return original(path, *args)

        with mock.patch.object(bootstrap, "atomic_write", side_effect=fail_binary):
            with self.assertRaisesRegex(RuntimeError, "second interruption"):
                self.apply()
        receipt = json.loads((self.root / ".linux-setup.json").read_bytes())
        self.assertEqual(receipt["installed"]["host_sha256"], first_hash)
        self.assertEqual(receipt["pending"]["host_sha256"], bootstrap.digest(second))
        self.apply()
        self.assertEqual(self.host.read_bytes(), second)

    def test_initial_complete_receipt_temporary_recovers(self):
        original = bootstrap.os.replace

        def interrupted(source, destination):
            if destination == str(self.root / ".linux-setup.json"):
                raise RuntimeError("initial receipt publication interrupted")
            return original(source, destination)

        with mock.patch.object(bootstrap.os, "replace", side_effect=interrupted):
            with self.assertRaisesRegex(RuntimeError, "initial receipt publication"):
                self.apply()
        self.assertFalse((self.root / ".linux-setup.json").exists())
        self.assertTrue((self.root / ".linux-setup.json.linux-setup.tmp").exists())
        self.apply()
        self.assertEqual(bootstrap.digest(self.host.read_bytes()), self.plan["host_sha256"])

    def interrupt_final_receipt(self):
        original = bootstrap.os.replace
        receipt = self.root / ".linux-setup.json"

        def interrupted(source, destination):
            if destination == str(receipt) and "pending" not in json.loads(pathlib.Path(source).read_bytes()):
                raise RuntimeError("final receipt publication interrupted")
            return original(source, destination)

        with mock.patch.object(bootstrap.os, "replace", side_effect=interrupted):
            with self.assertRaisesRegex(RuntimeError, "final receipt publication"):
                self.apply()
        temporary = self.root / ".linux-setup.json.linux-setup.tmp"
        prior = json.loads(receipt.read_bytes())
        final = json.loads(temporary.read_bytes())
        self.assertNotIn("pending", final)
        self.assertEqual(final["installed"], prior["pending"])
        self.assertEqual(final["installed"], {"host_sha256": bootstrap.digest(self.host.read_bytes()),
                                             "unit_sha256": bootstrap.digest(self.unit.read_bytes())})
        return receipt, temporary

    def change_candidate(self, binary):
        self.document["binary"] = bootstrap.base64.b64encode(binary).decode()
        self.plan["host_size"] = len(binary)
        self.plan["host_sha256"] = bootstrap.digest(binary)

    def check_complete_final_receipt_retry(self, next_candidate):
        receipt, temporary = self.interrupt_final_receipt()
        if next_candidate:
            self.change_candidate(b"next reviewed host candidate")
        self.apply()
        self.assertFalse(temporary.exists())
        final = json.loads(receipt.read_bytes())
        self.assertNotIn("pending", final)
        self.assertEqual(final["installed"]["host_sha256"], self.plan["host_sha256"])
        self.assertEqual(bootstrap.digest(self.host.read_bytes()), self.plan["host_sha256"])

    def test_complete_final_receipt_temporary_recovers_same_candidate(self):
        self.check_complete_final_receipt_retry(False)

    def test_complete_final_receipt_temporary_recovers_next_candidate(self):
        self.check_complete_final_receipt_retry(True)

    def test_final_receipt_temporary_refuses_tampering_without_mutation(self):
        receipt, temporary = self.interrupt_final_receipt()
        original_temporary = temporary.read_bytes()
        original_receipt = receipt.read_bytes()
        binary, unit = self.host.read_bytes(), self.unit.read_bytes()
        final = json.loads(original_temporary)
        changed_identity = dict(final, uid=1001)
        changed_hash = dict(final, installed=dict(final["installed"], host_sha256="0" * 64))
        for altered in (b"{", json.dumps(changed_identity).encode(), json.dumps(changed_hash).encode(),
                        json.dumps(dict(final, extra=True)).encode()):
            with self.subTest(altered=altered):
                temporary.write_bytes(altered)
                with self.assertRaises(RuntimeError):
                    self.apply()
                self.assertEqual(temporary.read_bytes(), altered)
                self.assertEqual(receipt.read_bytes(), original_receipt)
                self.assertEqual(self.host.read_bytes(), binary)
                self.assertEqual(self.unit.read_bytes(), unit)
        temporary.write_bytes(original_temporary)
        self.apply()

    def test_final_receipt_recovery_requires_both_artifacts_and_inactive_host(self):
        receipt, temporary = self.interrupt_final_receipt()
        original_temporary, original_receipt = temporary.read_bytes(), receipt.read_bytes()
        binary, unit = self.host.read_bytes(), self.unit.read_bytes()
        for fault in ("drift", "missing-unit", "active-unit", "host-lock", "temporary-mode"):
            with self.subTest(fault=fault):
                if fault == "drift":
                    self.host.write_bytes(b"foreign host modification")
                elif fault == "missing-unit":
                    self.unit.unlink()
                elif fault == "active-unit":
                    self.active = True
                elif fault == "host-lock":
                    (self.root / "host-lock.json").write_text("{}")
                else:
                    temporary.chmod(0o640)
                with self.assertRaises(RuntimeError):
                    self.apply()
                self.assertEqual(temporary.read_bytes(), original_temporary)
                self.assertEqual(receipt.read_bytes(), original_receipt)
                self.assertEqual(self.host.read_bytes(), b"foreign host modification" if fault == "drift" else binary)
                if fault == "missing-unit":
                    self.assertFalse(self.unit.exists())
                    self.unit.write_bytes(unit)
                    self.unit.chmod(0o600)
                else:
                    self.assertEqual(self.unit.read_bytes(), unit)
                self.host.write_bytes(binary)
                self.active = False
                if fault == "host-lock":
                    (self.root / "host-lock.json").unlink()
                temporary.chmod(0o600)
        self.apply()

    def test_completed_pending_temporary_requires_matching_candidate_retry(self):
        self.apply()
        receipt = self.root / ".linux-setup.json"
        previous = receipt.read_bytes()
        self.change_candidate(b"interrupted next host candidate")
        interrupted_document = self.document["binary"], dict(self.plan)
        original = bootstrap.os.replace

        def interrupted(source, destination):
            if destination == str(receipt):
                raise RuntimeError("pending receipt publication interrupted")
            return original(source, destination)

        with mock.patch.object(bootstrap.os, "replace", side_effect=interrupted):
            with self.assertRaisesRegex(RuntimeError, "pending receipt publication"):
                self.apply()
        temporary = self.root / ".linux-setup.json.linux-setup.tmp"
        interrupted_bytes = temporary.read_bytes()
        binary, unit = self.host.read_bytes(), self.unit.read_bytes()
        self.change_candidate(b"different next host candidate")
        with self.assertRaisesRegex(RuntimeError, "needs inspection"):
            self.apply()
        self.assertEqual(temporary.read_bytes(), interrupted_bytes)
        self.assertEqual(receipt.read_bytes(), previous)
        self.assertEqual(self.host.read_bytes(), binary)
        self.assertEqual(self.unit.read_bytes(), unit)
        self.document["binary"], self.plan = interrupted_document
        self.document["plan"] = self.plan
        self.apply()
        self.assertFalse(temporary.exists())
        self.assertEqual(bootstrap.digest(self.host.read_bytes()), self.plan["host_sha256"])

    def test_unrecognized_existing_unit_is_preserved(self):
        self.unit.parent.mkdir(parents=True, mode=0o700)
        self.unit.write_bytes(b"operator service")
        with self.assertRaisesRegex(RuntimeError, "unrecognized existing artifact"):
            self.apply()
        self.assertEqual(self.unit.read_bytes(), b"operator service")
        self.assertFalse(self.host.exists())


if __name__ == "__main__":
    unittest.main()
