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


def receive(connection, limit, flags=0):
    raw, _, flags, _ = connection.recvmsg(limit + 1, 0, flags)
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


def worker_envelope(policy, files, receipt, mode, qualification=None):
    inv = receipt.invocation
    root = native.CONTROL / inv.execution_id
    controller = model.Controller(native.CONTROL, native.JOBS, policy.controller, None, files=files, qualification=qualification)
    state = controller.load(root)
    model.require(state["invocation"] == asdict(inv) and state["phase"] == ("running" if mode == "baseline" else "recovering"),
                  "native-authorization-invalid")
    job = controller.job(root, state)
    policy.admit(model.Command("start", job.request.execution_id, job.request))
    model.verify_inputs(root, job, state["inputs_digest"], files)
    if qualification is not None:
        qualification.verify_origin(files)
        qualification.verify_inputs(files, job)
    else:
        model.require(not files.exists(root / "origin.json"), "qualification-origin-forbidden")
    if mode == "baseline":
        model.require(datetime.now(timezone.utc) < model.utc(job.request.expires_at), "execution-expired")
    return {"schema_version": 1, "envelope_version": 2, "native_receipt": asdict(receipt), "request": asdict(job.request), "attempt": job.attempt,
            "expected_client_sha256": job.expected_client_sha256, "inputs_digest": job.inputs_digest,
            "mode": mode, "retained": state["recovery_inputs"]}


def parse_envelope(value):
    model.require(isinstance(value, dict) and set(value) == {"schema_version", "request", "attempt", "expected_client_sha256",
                  "inputs_digest", "mode", "retained", "native_receipt", "envelope_version"} and value["schema_version"] == 1
                  and type(value["envelope_version"]) is int and value["envelope_version"] == 2
                  and type(value["attempt"]) is int and 0 < value["attempt"] <= 9999
                  and value["mode"] in ("baseline", "recover")
                  and model.proof.matches(model.proof.HASH, value["inputs_digest"])
                  and model.proof.matches(model.proof.HASH, value["expected_client_sha256"]), "native-message-invalid")
    request = model.ProofExecutionRequest.parse(value["request"])
    job = model.Job(request, native.JOBS / request.execution_id, native.CANDIDATE,
                    value["expected_client_sha256"], value["attempt"], value["inputs_digest"])
    receipt = native.NativeReceipt.parse(value["native_receipt"])
    inv = receipt.invocation
    model.require((inv.execution_id, inv.attempt, inv.request_digest) == (request.execution_id, job.attempt, request.digest)
                  and (value["mode"] == "baseline") == (job.attempt == 1), "native-message-invalid")
    return job, value["mode"], value["retained"], receipt


class NativeAdmission:
    def __init__(self, gate):
        model.require(type(gate) is socket.socket, "native-peer-invalid")
        self.gate = gate
        gate.set_inheritable(False)
        gate.settimeout(native.STARTUP_SECONDS)
        self.job, self.mode, self.retained, receipt = parse_envelope(receive(gate, model.MAX_FILE, socket.MSG_PEEK))
        NativeAdmission.check_process(gate, receipt)

    @staticmethod
    def check_process(gate, receipt):
        inv = receipt.owner
        model.require(type(gate) is socket.socket and gate.fileno() >= 0
                      and gate.family == socket.AF_UNIX
                      and gate.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET,
                      "native-peer-invalid")
        pid, uid, _ = struct.unpack("3i", gate.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        model.require(uid == 0 and pid == inv.parent_pid and os.getpid() == inv.leader_pid
                      and os.getppid() == inv.parent_pid and os.getuid() == os.geteuid() != 0,
                      "native-peer-invalid")
        ops = native.LinuxOps(None)
        model.require(ops.boot() == inv.boot_id, "native-process-changed")
        parent, child = ops.process(pid), ops.process(os.getpid())
        model.require(parent.start == inv.supervisor_start and parent.cgroup == native.UNIT_CGROUP
                      and (child.start, child.parent, child.cgroup) == (inv.leader_start_ticks, pid, inv.cgroup),
                      "native-process-changed")
        with ops.group(inv.cgroup) as fd:
            info = os.fstat(fd)
            model.require((info.st_dev, info.st_ino) == (inv.cgroup_device, inv.cgroup_inode),
                          "native-cgroup-changed")

    def consume(self):
        gate = self.gate
        try:
            model.require(type(gate) is socket.socket and gate.fileno() >= 0, "native-peer-invalid")
            gate.setblocking(False)
            job, mode, retained, receipt = parse_envelope(receive(gate, model.MAX_FILE, socket.MSG_DONTWAIT))
            NativeAdmission.check_process(gate, receipt)
            return job, mode, retained
        finally:
            if type(gate) is socket.socket:
                gate.close()
            self.gate = None

    def require_proof(self, request):
        job, mode, _ = NativeAdmission.consume(self)
        expected = model.proof.ProofRequest(job.request.candidate_sha, job.candidate_checkout,
            job.root / "inputs/operator.json", job.output, execution="hosted",
            driver_sha=job.request.driver_sha, proof=job.request.variant)
        model.require(mode == "baseline" and request == expected, "native-request-changed")
        model.verify_worker_inputs(job)


def parse_windows_envelope(value):
    native.exact(value, ("schema_version", "origin", "authorization_sha256", "origin_sha256", "case",
                         "operational_payload", "cleanup_authorization_sha256"))
    model.require(value["origin"] == "windows-qualification" and value["case"] in native.WINDOWS_CASES,
                  "native-message-invalid")
    native.hash_fields(value, ("authorization_sha256", "origin_sha256"))
    job, mode, retained, receipt = parse_envelope(value["operational_payload"])
    model.require(value["cleanup_authorization_sha256"] is None or
                  (mode == "recover" and model.proof.matches(model.proof.HASH, value["cleanup_authorization_sha256"])),
                  "native-message-invalid")
    raw = model.read_private(job.root / "qualification-authorization.json", native.QUALIFICATION_LIMIT)
    authority = native.QualificationAuthorization.parse(raw)
    model.require(authority.digest == value["authorization_sha256"]
                  and authority.execution_id(value["case"]) == job.request.execution_id
                  and native.identity_digest("WindowsQualificationOrigin", authority.origin(value["case"])) == value["origin_sha256"]
                  and (authority.value["candidate_sha"], authority.value["driver_sha"], authority.value["expected_client_sha256"]) ==
                      (job.request.candidate_sha, job.request.driver_sha, job.expected_client_sha256), "native-message-invalid")
    return job, mode, retained, receipt, authority


class WindowsQualificationAdmission:
    def __init__(self, gate):
        model.require(type(gate) is socket.socket, "native-peer-invalid")
        self.gate = gate
        gate.set_inheritable(False)
        gate.settimeout(native.STARTUP_SECONDS)
        value = receive(gate, model.MAX_FILE, socket.MSG_PEEK)
        self.job, self.mode, self.retained, receipt, authority = parse_windows_envelope(value)
        self.case, self.expected_host_sha256 = value["case"], authority.value["expected_host_sha256"]
        NativeAdmission.check_process(gate, receipt)

    def consume(self):
        gate = self.gate
        try:
            model.require(type(gate) is socket.socket and gate.fileno() >= 0, "native-peer-invalid")
            gate.setblocking(False)
            value = receive(gate, model.MAX_FILE, socket.MSG_DONTWAIT)
            job, mode, retained, receipt, authority = parse_windows_envelope(value)
            NativeAdmission.check_process(gate, receipt)
            model.require((job, mode, retained, value["case"]) == (self.job, self.mode, self.retained, self.case),
                          "native-request-changed")
            self.expected_host_sha256 = authority.value["expected_host_sha256"]
            return job, mode, retained
        finally:
            if type(gate) is socket.socket:
                gate.close()
            self.gate = None

    def require_proof(self, request):
        job, mode, _ = WindowsQualificationAdmission.consume(self)
        expected = model.proof.ProofRequest(job.request.candidate_sha, job.candidate_checkout,
                   job.root / "inputs/operator.json", job.output, execution="hosted",
                   driver_sha=job.request.driver_sha, proof=job.request.variant)
        model.require(mode == "baseline" and request == expected, "native-request-changed")
        model.verify_worker_inputs(job)


def parse_linux_envelope(value):
    native.exact(value, ("schema_version", "origin", "intent", "intent_sha256", "native_receipt", "authorization_sha256"))
    model.require(value["origin"] == "linux-qualification", "native-message-invalid")
    intent = native.LinuxIntent.parse(value["intent"])
    receipt = native.NativeFixtureReceipt.parse(value["native_receipt"])
    model.require(value["intent_sha256"] == receipt.intent_sha256 == intent.digest
                  and value["authorization_sha256"] == intent.authorization_digest
                  and receipt.owner.boot_id == intent.value["accepted_boot_id"]
                  and time.time() < intent.value["deadline_unix"], "native-message-invalid")
    return intent, receipt


class LinuxFixtureAdmission:
    def __init__(self, gate):
        model.require(type(gate) is socket.socket, "native-peer-invalid")
        self.gate = gate
        value = receive(gate, native.QUALIFICATION_LIMIT, socket.MSG_PEEK)
        self.intent, receipt = parse_linux_envelope(value)
        NativeAdmission.check_process(gate, receipt)

    def consume(self):
        try:
            intent, receipt = parse_linux_envelope(receive(self.gate, native.QUALIFICATION_LIMIT))
            NativeAdmission.check_process(self.gate, receipt)
            model.require(intent == self.intent, "native-request-changed")
            return intent
        finally:
            self.gate.close()
            self.gate = None



def run_worker(gate, result, worker=None):
    gate.set_inheritable(False)
    result.set_inheritable(False)
    gate.settimeout(native.STARTUP_SECONDS)
    result.sendall(b'{"schema_version":1,"ready":true}')
    message = receive(gate, model.MAX_FILE, socket.MSG_PEEK)
    origin = message.get("origin")
    if origin == "linux-qualification":
        authority = LinuxFixtureAdmission(gate)
        from proof_qualification_fixture import run_fixture
        completed = run_fixture(LinuxFixtureAdmission.consume(authority))
        result.sendall(model.proof.canonical({"schema_version": 1, "result": completed}))
        return
    authority = WindowsQualificationAdmission(gate) if origin == "windows-qualification" else NativeAdmission(gate)
    job, mode, retained = authority.job, authority.mode, authority.retained
    worker = worker or model.ProofWorker()
    model.require(mode != "baseline" or datetime.now(timezone.utc) < model.utc(job.request.expires_at), "execution-expired")
    if mode == "recover":
        job, mode, retained = type(authority).consume(authority)
        model.require(mode == "recover", "native-request-changed")
    if type(authority) is WindowsQualificationAdmission and mode == "baseline" and authority.case in (
            "windows-crash-recover", "windows-reboot-recover"):
        import threading
        def observe_active():
            try:
                record = model.proof.active_qualification_checkpoint(job, worker.commands_factory)
                model.publish(job.attempt_root / "active-checkpoint.json", model.proof.canonical(record))
            except Exception:
                model.publish(job.attempt_root / "active-failure.json", model.proof.canonical(
                    {"schema_version": 1, "status": "fail", "code": "active-checkpoint-unavailable"}))
        threading.Thread(target=observe_active, daemon=True).start()
    completed = worker.baseline(job, native_authority=authority) if mode == "baseline" else worker.recover(job, retained)
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
        self.selected = native.Selector.parse(self.files.read(native.RUNTIME / "pending.json"))
        pending = self.selected.intent
        self.context = None
        if self.selected.kind == "linux-qualification":
            self.context = native.LinuxIntent.parse(pending)
            root = self.context.root
            intent = self.files.read(root / "intent.json", native.QUALIFICATION_LIMIT)
            model.require(model.document(intent) == pending and not self.files.exists(root / "settled.json"),
                          "native-intent-invalid")
            request = None
        else:
            native.reject_unreleased(self.files, pending)
            root = native.CONTROL / pending["execution_id"]
            intent = self.files.read(root / f"intent-{pending['attempt']:04d}.json")
            model.require(model.document(intent) == pending, "native-intent-invalid")
            request = model.ProofExecutionRequest.parse(model.document(self.files.read(root / "request.json")))
            model.require(request.digest == pending["request_digest"], "native-intent-invalid")
            if self.selected.kind == "windows-qualification":
                self.context = native.qualification_context(self.files, pending)
            else:
                model.require(not self.files.exists(root / "origin.json"), "qualification-origin-forbidden")
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
            child = None
            try:
                gate_child.close()
                result_child.close()
                self.ops.write_group(group, "cgroup.procs", (str(pid) + "\n").encode())
                child = self.ops.process(pid)
                gate_parent.sendall(b"S")
                result_parent.settimeout(native.STARTUP_SECONDS)
                model.require(receive(result_parent, model.MAX_WIRE) == {"schema_version": 1, "ready": True},
                              "native-worker-unready")
                child = self.ops.process(pid)
                model.require(child.parent == os.getpid() and child.cgroup == native.UNIT_CGROUP + "/" + leaf,
                              "native-worker-changed")
                owner = native.ProcessOwner(boot, unit.invocation_id, child.cgroup, pid, child.start, child.parent,
                                            supervisor.start, info.st_dev, info.st_ino)
                if request is None:
                    receipt = native.NativeFixtureReceipt(self.context.digest, owner)
                    mode = None
                    result_path = root / "result.json"
                else:
                    inv = model.Invocation(boot, unit.invocation_id, child.cgroup, pid, child.start, child.parent,
                                           request.execution_id, pending["attempt"], request.digest)
                    receipt = native.NativeReceipt(inv, supervisor.start, info.st_dev, info.st_ino)
                    mode = pending["mode"]
                    result_path = root / f"result-{inv.attempt:04d}.json"
                self.release(receipt, gate_parent, mode)
                result_parent.settimeout(max(1, self.context.value["deadline_unix"] - time.time())
                                         if type(self.context) is native.LinuxIntent else 3 * 3600)
                completed = receive(result_parent, 64 << 10 if type(self.context) is native.LinuxIntent else model.MAX_FILE)
                model.require(set(completed) == {"schema_version", "result"} and completed["schema_version"] == 1
                              and isinstance(completed["result"], dict), "native-result-invalid")
                record = ({"schema_version": 1, "intent_sha256": self.context.digest,
                           "native_sha256": model.proof.digest(model.proof.canonical(asdict(receipt))), "result": completed["result"]}
                          if request is None else {"schema_version": 1, "invocation": asdict(inv),
                                                   "mode": mode, "result": completed["result"]})
                self.files.publish(result_path, model.proof.canonical(record))
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
                if failed:
                    if request is None:
                        if child is not None and not any(self.files.exists(root / (kind + ".json")) for kind in ("native", "authorization", "settled")):
                            self.files.publish(root / "startup-failure.json", model.proof.canonical({
                                "schema_version": 1, "intent_sha256": self.context.digest,
                                "owner": asdict(native.ProcessOwner(boot, unit.invocation_id, native.UNIT_CGROUP + "/" + leaf,
                                    pid, child.start, supervisor.pid, supervisor.start, info.st_dev, info.st_ino)),
                                "child_cleanup": "proven"}))
                    elif not any(self.files.exists(native.attempt_path(pending, kind)) for kind in
                                 ("native", "authorization", "unreleased")):
                        failure = native.StartupFailure(pending, model.proof.digest(intent), boot, unit.invocation_id,
                                                        supervisor.pid, supervisor.start, native.UNIT_CGROUP + "/" + leaf,
                                                        info.st_dev, info.st_ino)
                        self.files.publish(native.attempt_path(pending, "startup-failure"), model.proof.canonical(asdict(failure)))

    def release(self, receipt, gate, expected_mode):
        selected = getattr(self, "selected", None)
        if selected is None:
            pending = {"schema_version": 1, "execution_id": receipt.invocation.execution_id,
                       "attempt": receipt.invocation.attempt, "request_digest": receipt.invocation.request_digest,
                       "mode": expected_mode}
            selected = native.Selector.create("operational", pending)
            context = None
        else:
            context = self.context
        linux = selected.kind == "linux-qualification"
        root = context.root if linux else native.CONTROL / receipt.invocation.execution_id
        native_path = root / "native.json" if linux else native.receipt_path(receipt.invocation)
        if not linux:
            native.reject_unreleased(self.files, selected.intent)
        if native.SOCKET.exists() or native.SOCKET.is_symlink():
            info = native.SOCKET.lstat()
            model.require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1,
                          "native-peer-invalid")
            native.SOCKET.unlink()
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
            listener.bind(str(native.SOCKET))
            os.chmod(native.SOCKET, 0o600)
            listener.listen(1)
            self.files.publish(native_path, model.proof.canonical(asdict(receipt)))
            listener.settimeout(native.STARTUP_SECONDS)
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(native.STARTUP_SECONDS)
                _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                model.require(uid == 0, "native-peer-invalid")
                release = receive(connection, native.QUALIFICATION_LIMIT)
                current, policy, files, renewed = native.selected_runtime()
                model.require(current == selected and policy == self.policy and self.ops.boot() == receipt.owner.boot_id,
                              "native-authorization-invalid")
                unit = self.ops.unit()
                owner = receipt.owner
                model.require(unit.invocation_id == owner.invocation_id and unit.main_pid == owner.parent_pid,
                              "native-process-changed")
                parent, child = self.ops.process(owner.parent_pid), self.ops.process(owner.leader_pid)
                model.require(parent.start == owner.supervisor_start and parent.cgroup == native.UNIT_CGROUP
                              and (child.start, child.parent, child.cgroup) ==
                                  (owner.leader_start_ticks, owner.parent_pid, owner.cgroup), "native-process-changed")
                with self.ops.group(owner.cgroup) as group:
                    info = os.fstat(group)
                    model.require((info.st_dev, info.st_ino) == (owner.cgroup_device, owner.cgroup_inode), "native-cgroup-changed")
                if linux:
                    expected = native.linux_release(renewed, receipt)
                    authorization = files.read(root / "authorization.json", 64 << 10)
                    model.require(release == expected and model.document(authorization) == expected | {"native_receipt": asdict(receipt)}
                                  and not files.exists(root / "settled.json"), "native-authorization-invalid")
                    envelope = {"schema_version": 1, "origin": "linux-qualification", "intent": renewed.value,
                                "intent_sha256": renewed.digest, "native_receipt": asdict(receipt),
                                "authorization_sha256": renewed.authorization_digest}
                    reply = {"schema_version": 1, "released": True, "intent_sha256": renewed.digest}
                else:
                    inv = receipt.invocation
                    native.reject_unreleased(files, selected.intent)
                    authorization = files.read(root / f"authorization-{inv.attempt:04d}.json")
                    if renewed is None:
                        mode = parse_release(release, receipt, authorization)
                    else:
                        mode = selected.intent["mode"]
                        expected = renewed.release_record(files, receipt, mode)
                        model.require(release == expected and model.document(authorization) == expected | {"native_receipt": asdict(receipt)},
                                      "native-authorization-invalid")
                    model.require(mode == expected_mode, "native-authorization-invalid")
                    envelope = worker_envelope(policy, files, receipt, mode, qualification=renewed)
                    if renewed is not None:
                        envelope = {"schema_version": 1, "origin": "windows-qualification",
                                    "authorization_sha256": renewed.authorization.digest, "origin_sha256": renewed.origin_digest,
                                    "case": renewed.case, "operational_payload": envelope,
                                    "cleanup_authorization_sha256": None if renewed.cleanup is None else renewed.cleanup.digest}
                    reply = {"schema_version": 1, "released": True, "invocation": asdict(inv)}
                gate.sendall(model.proof.canonical(envelope))
                connection.sendall(model.proof.canonical(reply))


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        if args == ["supervise"]:
            _, policy, files, _ = native.selected_runtime()
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
