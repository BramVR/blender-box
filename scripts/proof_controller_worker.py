from dataclasses import asdict
from datetime import datetime, timezone
import ctypes
import os
from pathlib import Path
import resource
import select
import socket
import stat
import signal
import struct
import sys
import time
import uuid

import proof_controller as model
import proof_controller_native as native


def receive(connection, limit):
    raw, _, flags, _ = connection.recvmsg(limit + 1)
    model.require(raw and len(raw) <= limit and not flags & socket.MSG_TRUNC, "native-message-invalid")
    return model.document(raw, limit)


def parse_release(value, receipt, authorization):
    model.require(isinstance(value, dict) and set(value) == {"schema_version", "operation", "invocation", "authorization_sha256"}
                  and value["schema_version"] == 1 and value["operation"] == "release"
                  and value["invocation"] == asdict(receipt.invocation)
                  and value["authorization_sha256"] == model.proof.digest(authorization), "native-authorization-invalid")
    record = model.document(authorization)
    model.require(set(record) == {"schema_version", "invocation", "mode"} and record["schema_version"] == 1
                  and record["invocation"] == asdict(receipt.invocation) and record["mode"] in ("baseline", "recover"),
                  "native-authorization-invalid")
    return record["mode"]


def worker_envelope(policy, files, receipt, mode):
    inv = receipt.invocation
    root = native.CONTROL / inv.execution_id
    controller = model.Controller(native.CONTROL, native.JOBS, policy.controller, None, files=files)
    state = controller.load(root)
    model.require(state["invocation"] == asdict(inv) and state["phase"] == ("running" if mode == "baseline" else "recovering"),
                  "native-authorization-invalid")
    job = controller.job(root, state)
    model.verify_inputs(root, job, state["inputs_digest"], files)
    if mode == "baseline":
        model.require(datetime.now(timezone.utc) < model.utc(job.request.expires_at), "execution-expired")
    return {"schema_version": 1, "request": asdict(job.request), "attempt": job.attempt,
            "expected_client_sha256": job.expected_client_sha256, "inputs_digest": job.inputs_digest,
            "mode": mode, "retained": state["recovery_inputs"]}


def parse_envelope(value):
    model.require(isinstance(value, dict) and set(value) == {"schema_version", "request", "attempt", "expected_client_sha256",
                  "inputs_digest", "mode", "retained"} and value["schema_version"] == 1
                  and type(value["attempt"]) is int and 0 < value["attempt"] <= 9999
                  and value["mode"] in ("baseline", "recover")
                  and model.proof.matches(model.proof.HASH, value["inputs_digest"])
                  and model.proof.matches(model.proof.HASH, value["expected_client_sha256"]), "native-message-invalid")
    request = model.ProofExecutionRequest.parse(value["request"])
    model.require(request.variant == "baseline", "variant-driver-unavailable")
    job = model.Job(request, native.JOBS / request.execution_id, native.CANDIDATE,
                    value["expected_client_sha256"], value["attempt"], value["inputs_digest"])
    return job, value["mode"], value["retained"]


def run_worker(gate, result, worker=None):
    gate.settimeout(native.STARTUP_SECONDS)
    result.sendall(b'{"schema_version":1,"ready":true}')
    envelope = receive(gate, model.MAX_FILE)
    job, mode, retained = parse_envelope(envelope)
    worker = worker or model.ProofWorker()
    model.require(mode != "baseline" or datetime.now(timezone.utc) < model.utc(job.request.expires_at), "execution-expired")
    completed = worker.baseline(job) if mode == "baseline" else worker.recover(job, retained)
    raw = model.proof.canonical({"schema_version": 1, "result": completed})
    model.require(len(raw) <= model.MAX_FILE, "native-result-invalid")
    result.sendall(raw)


def drop_and_exec(policy, gate_fd, result_fd):
    kept = {gate_fd, result_fd}
    maximum = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    model.require(maximum != resource.RLIM_INFINITY and maximum <= (1 << 20), "native-fd-limit-invalid")
    for low, high in zip([0] + [fd + 1 for fd in sorted(kept)], sorted(kept) + [int(maximum)]):
        os.closerange(low, high)
    os.setgroups([])
    os.setgid(policy.value["runner_gid"])
    os.setuid(policy.value["runner_uid"])
    model.require(os.getuid() == os.geteuid() == policy.value["runner_uid"] and os.getgroups() == [], "native-uid-drop-failed")
    libc = ctypes.CDLL(None, use_errno=True)
    model.require(libc.prctl(38, 1, 0, 0, 0) == 0, "native-uid-drop-failed")
    os.set_inheritable(gate_fd, True)
    os.set_inheritable(result_fd, True)
    os.chdir(native.BASE)
    command = ("import sys; sys.path.insert(0, " + repr(str(native.BASE / "scripts")) + "); "
               "from proof_controller_worker import main; raise SystemExit(main())")
    os.execve("/usr/bin/python3", ["/usr/bin/python3", "-I", "-S", "-c", command, "run", str(gate_fd), str(result_fd)],
              policy.environment())


def reap_child(pid, deadline):
    # An unreaped direct child cannot be replaced by a recycled PID.
    ended, _ = os.waitpid(pid, os.WNOHANG)
    if ended:
        return
    fd = os.pidfd_open(pid)
    try:
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not poller.poll(max(1, int(remaining * 1000))):
            signal.pidfd_send_signal(fd, signal.SIGKILL)
            model.require(poller.poll(5000), "local-termination-unknown")
        os.waitpid(pid, 0)
    finally:
        os.close(fd)


class Supervisor:
    def __init__(self, policy, files, ops):
        self.policy, self.files, self.ops = policy, files, ops

    def serve(self):
        pending = native.parse_intent(self.files.read(native.RUNTIME / "pending.json"))
        native.reject_unreleased(self.files, pending)
        root = native.CONTROL / pending["execution_id"]
        intent = self.files.read(root / f"intent-{pending['attempt']:04d}.json")
        model.require(model.document(intent) == pending, "native-intent-invalid")
        request = model.ProofExecutionRequest.parse(model.document(self.files.read(root / "request.json")))
        model.require(request.digest == pending["request_digest"], "native-intent-invalid")
        unit = self.ops.unit()
        supervisor = self.ops.process(os.getpid())
        model.require(unit.main_pid == os.getpid() and supervisor.cgroup == native.UNIT_CGROUP,
                      "native-supervisor-changed")
        boot = self.ops.boot()
        with self.ops.group(native.UNIT_CGROUP) as parent:
            leaf = "attempt-" + uuid.uuid4().hex
            os.mkdir(leaf, 0o700, dir_fd=parent)
        with self.ops.group(native.UNIT_CGROUP + "/" + leaf) as group:
            info = os.fstat(group)
            gate_parent, gate_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            result_parent, result_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            pid = os.fork()
            if pid == 0:
                try:
                    gate_parent.close()
                    result_parent.close()
                    gate_child.settimeout(native.STARTUP_SECONDS)
                    model.require(gate_child.recv(1) == b"S", "native-gate-closed")
                    drop_and_exec(self.policy, gate_child.fileno(), result_child.fileno())
                finally:
                    os._exit(1)
            failed = False
            try:
                gate_child.close()
                result_child.close()
                self.ops.write_group(group, "cgroup.procs", (str(pid) + "\n").encode())
                gate_parent.sendall(b"S")
                result_parent.settimeout(native.STARTUP_SECONDS)
                model.require(receive(result_parent, model.MAX_WIRE) == {"schema_version": 1, "ready": True},
                              "native-worker-unready")
                child = self.ops.process(pid)
                model.require(child.parent == os.getpid() and child.cgroup == native.UNIT_CGROUP + "/" + leaf,
                              "native-worker-changed")
                inv = model.Invocation(boot, unit.invocation_id, child.cgroup, pid, child.start, child.parent,
                                       request.execution_id, pending["attempt"], request.digest)
                receipt = native.NativeReceipt(inv, supervisor.start, info.st_dev, info.st_ino)
                self.release(receipt, gate_parent, pending["mode"])
                result_parent.settimeout(3 * 3600)
                completed = receive(result_parent, model.MAX_FILE)
                model.require(set(completed) == {"schema_version", "result"} and completed["schema_version"] == 1
                              and isinstance(completed["result"], dict), "native-result-invalid")
                self.files.publish(root / f"result-{inv.attempt:04d}.json", model.proof.canonical({"schema_version": 1,
                                   "invocation": asdict(inv), "mode": pending["mode"], "result": completed["result"]}))
            except Exception:
                failed = True
                raise
            finally:
                gate_parent.close()
                result_parent.close()
                deadline = time.monotonic() + native.STOP_SECONDS
                try:
                    self.ops.write_group(group, "cgroup.kill", b"1\n")
                    self.ops.wait_group_empty(group, deadline)
                finally:
                    reap_child(pid, deadline)
                if failed and not any(self.files.exists(native.attempt_path(pending, kind)) for kind in
                                      ("native", "authorization", "unreleased")):
                    failure = native.StartupFailure(pending, model.proof.digest(intent), boot, unit.invocation_id,
                                                    supervisor.pid, supervisor.start, native.UNIT_CGROUP + "/" + leaf,
                                                    info.st_dev, info.st_ino)
                    self.files.publish(native.attempt_path(pending, "startup-failure"), model.proof.canonical(asdict(failure)))

    def release(self, receipt, gate, expected_mode):
        native.reject_unreleased(self.files, {"execution_id": receipt.invocation.execution_id, "attempt": receipt.invocation.attempt})
        if native.SOCKET.exists() or native.SOCKET.is_symlink():
            info = native.SOCKET.lstat()
            model.require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1,
                          "native-peer-invalid")
            native.SOCKET.unlink()
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
            listener.bind(str(native.SOCKET))
            os.chmod(native.SOCKET, 0o600)
            listener.listen(1)
            self.files.publish(native.receipt_path(receipt.invocation), model.proof.canonical(asdict(receipt)))
            listener.settimeout(native.STARTUP_SECONDS)
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(native.STARTUP_SECONDS)
                _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                model.require(uid == 0, "native-peer-invalid")
                release = receive(connection, model.MAX_WIRE)
                inv = receipt.invocation
                authorization = self.files.read(native.CONTROL / inv.execution_id / f"authorization-{inv.attempt:04d}.json")
                mode = parse_release(release, receipt, authorization)
                model.require(mode == expected_mode and self.ops.boot() == inv.boot_id, "native-authorization-invalid")
                native.reject_unreleased(self.files, {"execution_id": inv.execution_id, "attempt": inv.attempt})
                envelope = worker_envelope(self.policy, self.files, receipt, mode)
                gate.sendall(model.proof.canonical(envelope))
                connection.sendall(model.proof.canonical({"schema_version": 1, "released": True, "invocation": asdict(inv)}))


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        if args == ["supervise"]:
            policy, files = native.load_runtime()
            os.umask(0o077)
            os.environ.clear()
            os.environ.update(policy.environment())
            Supervisor(policy, files, native.LinuxOps(policy)).serve()
            return 0
        model.require(len(args) == 3 and args[0] == "run" and all(value.isdigit() for value in args[1:])
                      and os.getuid() != 0 and os.getuid() == os.geteuid(), "invalid-command")
        with socket.socket(fileno=int(args[1])) as gate, socket.socket(fileno=int(args[2])) as result:
            run_worker(gate, result)
        return 0
    except (OSError, model.ControllerError, model.proof.ProofError):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
