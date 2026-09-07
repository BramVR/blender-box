import ctypes
from dataclasses import asdict
import os
from pathlib import Path
import select
import socket

import proof_controller as model
import proof_controller_native as native


def run_fixture(intent):
    model.require(type(intent) is native.LinuxIntent and os.getuid() == os.geteuid() != 0,
                  "qualification-admission-invalid")
    root = native.JOBS / "qualification" / intent.value["qualification_id"]
    case = intent.value["case"]
    observations = {"uid": os.getuid(), "euid": os.geteuid(), "gid": os.getgid(), "groups": os.getgroups(),
                    "no_new_privs": ctypes.CDLL(None, use_errno=True).prctl(39, 0, 0, 0, 0)}
    model.require(observations["groups"] == [] and observations["no_new_privs"] == 1, "qualification-confinement-failed")
    if case in ("uid-confinement", "network-local"):
        try:
            fd = os.open(native.CONTROL / "fixture.lock", os.O_RDONLY | os.O_NOFOLLOW)
        except PermissionError:
            observations["protected_control_denied"] = True
        else:
            os.close(fd)
            raise model.ControllerError("qualification-confinement-failed")
    elif case == "storage-lock":
        files = model.local_files()
        payload = b"blender-box qualification storage v1\n"
        files.publish(root / "storage.txt", payload)
        model.require(files.read(root / "storage.txt") == payload, "qualification-storage-failed")
        try:
            files.publish(root / "storage.txt", b"conflict\n")
        except (FileExistsError, model.ControllerError):
            pass
        else:
            raise model.ControllerError("qualification-storage-failed")
        with files.locked(root):
            try:
                with files.locked(root):
                    raise model.ControllerError("qualification-lock-failed")
            except model.ControllerError as error:
                model.require(error.code == "fixture-busy", "qualification-lock-failed")
        observations.update(storage_sha256=model.proof.digest(payload), lock_refused=True)
    elif case == "peer-rejection":
        from proof_controller_worker import NativeAdmission
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            owner = native.ProcessOwner(intent.value["accepted_boot_id"], "0" * 32,
                                        native.UNIT_CGROUP + "/attempt-" + "0" * 32,
                                        os.getpid(), 1, os.getppid(), 1, 1, 1)
            try:
                NativeAdmission.check_process(left, native.NativeFixtureReceipt(intent.digest, owner))
            except model.ControllerError as error:
                model.require(error.code == "native-peer-invalid", "qualification-peer-failed")
            else:
                raise model.ControllerError("qualification-peer-failed")
            observations["wrong_peer_refused"] = True
        finally:
            left.close()
            right.close()
    elif case == "descendant-stop":
        ready_read, ready_write = os.pipe()
        hold_read, hold_write = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(ready_read)
            os.close(hold_write)
            os.write(ready_write, b"R")
            os.close(ready_write)
            os.read(hold_read, 1)
            os._exit(0)
        os.close(ready_write)
        os.close(hold_read)
        model.require(os.read(ready_read, 1) == b"R", "qualification-descendant-failed")
        os.close(ready_read)
        child = native.LinuxOps(None).process(pid)
        model.require(child.parent == os.getpid(), "qualification-descendant-failed")
        observations["descendant"] = asdict(child)
        # Keep the owned descendant blocked until cgroup termination.
        os.set_inheritable(hold_write, False)
    elif case not in ("crash-after-release", "initiator-disconnect", "reboot-observation"):
        raise model.ControllerError("qualification-case-invalid")
    raw = model.proof.canonical({"schema_version": 1, "intent_sha256": intent.digest, "case": case,
                                "observations": observations})
    model.require(len(raw) <= 64 << 10, "qualification-evidence-limit")
    model.publish(root / "action.json", raw)
    if case in ("descendant-stop", "crash-after-release", "initiator-disconnect", "reboot-observation"):
        read_fd, write_fd = os.pipe()
        try:
            select.select([read_fd], [], [], max(0, intent.value["deadline_unix"] - __import__("time").time()))
        finally:
            os.close(read_fd)
            os.close(write_fd)
        raise model.ControllerError("qualification-fixture-timeout")
    return {"status": "partial" if case in ("initiator-disconnect", "reboot-observation", "network-local") else "pass",
            "case": case, "observations_sha256": model.proof.digest(raw)}
