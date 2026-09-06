from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
import os
import base64
import ctypes
import selectors
from pathlib import Path
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import time
import uuid

import proof_controller as model
from proof_controller_store import FixtureFiles, PendingPublication, RootedFiles

BASE = Path("/usr/local/libexec/blender-box-proof")
CONFIG = Path("/etc/blender-box-proof")
CONTROL = Path("/var/lib/blender-box-proof/control")
JOBS = Path("/var/lib/blender-box-proof/jobs")
CANDIDATE = Path("/var/lib/blender-box-proof/candidate")
RUNTIME = Path("/run/blender-box-proof")
HELPER = Path("/usr/local/libexec/blender-box-proof-helper")
WORKER = Path("/usr/local/libexec/blender-box-proof-worker")
UNIT = "blender-box-proof.service"
TMPFILES = "/etc/tmpfiles.d/blender-box-proof.conf"
UNIT_CGROUP = "/system.slice/" + UNIT
CGROUP = Path("/sys/fs/cgroup")
SOCKET = RUNTIME / "supervisor.sock"
TOOLS = ("/usr/bin/python3", "/usr/bin/git", "/usr/bin/ssh", "/usr/local/go/bin/go", "/usr/bin/systemctl", "/usr/bin/scp")
SOURCES = ("scripts/proof_controller.py", "scripts/proof_controller_native.py", "scripts/proof_controller_store.py",
           "scripts/proof_controller_worker.py", "scripts/onboarding_proof.py",
           "tests/fixtures/onboarding-baseline/payload.json", "tests/fixtures/onboarding-baseline/scenario.py")
QUALIFICATIONS = ("separate-uids", "source-and-tool-confinement", "fsync-flock", "startup-gate", "peer-credentials",
                  "exact-cgroup-stop", "supervisor-crash-containment", "disconnect-reboot", "network-policy",
                  "original-journal-recovery", "owned-windows-fixture")
PROPERTIES = ("Id", "LoadState", "ActiveState", "MainPID", "InvocationID", "ControlGroup", "Job")
STARTUP_SECONDS = 30
STOP_SECONDS = 15


def bounded_text(raw, limit=16384):
    model.require(isinstance(raw, bytes) and 0 < len(raw) <= limit and b"\x00" not in raw, "native-response-invalid")
    try:
        return raw.decode("ascii")
    except UnicodeError as error:
        raise model.ControllerError("native-response-invalid") from error


def boot_id(raw):
    text = bounded_text(raw, 64).strip()
    model.require(model.proof.matches(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", text), "native-boot-invalid")
    return text.replace("-", "")


@dataclass(frozen=True)
class UnitState:
    active: str
    main_pid: int
    invocation_id: str
    cgroup: str
    job_id: int = 0


def parse_unit(raw):
    fields = {}
    for line in bounded_text(raw).splitlines():
        key, separator, value = line.partition("=")
        model.require(separator and key in PROPERTIES and key not in fields, "native-unit-invalid")
        fields[key] = value
    model.require(set(fields) == set(PROPERTIES) and fields["Id"] == UNIT and fields["LoadState"] == "loaded"
                  and fields["ActiveState"] in ("active", "activating", "deactivating", "inactive", "failed")
                  and model.proof.matches(r"0|[1-9][0-9]{0,9}", fields["MainPID"]), "native-unit-invalid")
    pid = int(fields["MainPID"])
    model.require(fields["ControlGroup"] in ("", UNIT_CGROUP)
                  and (fields["InvocationID"] == "" or model.proof.matches(r"[a-f0-9]{32}", fields["InvocationID"])),
                  "native-unit-invalid")
    model.require(not pid or (fields["ControlGroup"] == UNIT_CGROUP and fields["InvocationID"]), "native-unit-invalid")
    model.require(fields["ActiveState"] not in ("inactive", "failed") or pid == 0, "native-unit-invalid")
    model.require(fields["Job"] == "" or model.proof.matches(r"[1-9][0-9]{0,9}", fields["Job"]), "native-unit-invalid")
    return UnitState(fields["ActiveState"], pid, fields["InvocationID"], fields["ControlGroup"],
                     int(fields["Job"]) if fields["Job"] else 0)


@dataclass(frozen=True)
class Process:
    pid: int
    parent: int
    start: int
    cgroup: str


def parse_process(pid, raw, cgroup):
    text = bounded_text(raw)
    end = text.rfind(")")
    model.require(text.startswith(str(pid) + " (") and end > 0, "native-process-invalid")
    fields = text[end + 2:].split()
    model.require(len(fields) >= 20 and len(fields[0]) == 1
                  and fields[1].isdigit() and fields[19].isdigit(), "native-process-invalid")
    lines = bounded_text(cgroup).splitlines()
    model.require(len(lines) == 1 and lines[0].startswith("0::/"), "native-process-invalid")
    name = lines[0][3:]
    model.require(model.proof.matches(r"/[A-Za-z0-9_./-]{1,240}", name)
                  and all(part not in (".", "..") for part in name.split("/")[1:]), "native-process-invalid")
    return Process(pid, int(fields[1]), int(fields[19]), name)


def populated(raw):
    values = {}
    for line in bounded_text(raw, 4096).splitlines():
        fields = line.split()
        model.require(len(fields) == 2 and fields[0] not in values and fields[1] in ("0", "1"), "native-cgroup-invalid")
        values[fields[0]] = fields[1]
    model.require("populated" in values, "native-cgroup-invalid")
    return values["populated"] == "1"


@dataclass(frozen=True)
class NativeReceipt:
    invocation: model.Invocation
    supervisor_start: int
    cgroup_device: int
    cgroup_inode: int
    schema_version: int = 1

    @classmethod
    def parse(cls, value):
        model.require(isinstance(value, dict) and set(value) == set(cls.__dataclass_fields__)
                      and type(value["schema_version"]) is int and value["schema_version"] == 1, "native-receipt-invalid")
        invocation = model.Invocation.parse(value["invocation"])
        model.require(model.proof.matches(re.escape(UNIT_CGROUP) + r"/attempt-[a-f0-9]{32}", invocation.cgroup)
                      and all(type(value[k]) is int and value[k] > 0
                              for k in ("supervisor_start", "cgroup_device", "cgroup_inode")), "native-receipt-invalid")
        return cls(invocation, value["supervisor_start"], value["cgroup_device"], value["cgroup_inode"])


@dataclass(frozen=True)
class NativePolicy:
    value: dict
    digest: str

    @property
    def controller(self):
        return model.Policy(self.value["candidate_sha"], self.value["driver_sha"], CANDIDATE,
                            CONFIG / "operator.json", self.value["expected_client_sha256"], self.value["variant"])

    @classmethod
    def parse(cls, raw):
        value = model.document(raw)
        fields = {"schema_version", "control_uid", "control_gid", "runner_uid", "runner_gid", "candidate_sha",
                  "driver_sha", "expected_client_sha256", "tool_sha256", "artifacts", "variant"}
        model.require(set(value) == fields and value["schema_version"] == 1 and value["variant"] in ("baseline", "named-target"),
                      "native-policy-invalid")
        validate_enrollment({key: item for key, item in value.items() if key not in ("artifacts", "variant")}, _policy=True)
        model.require(isinstance(value["artifacts"], dict) and set(value["artifacts"]) == set(artifact_paths())
                      and all(model.proof.matches(model.proof.HASH, item) for item in value["artifacts"].values()),
                      "native-policy-invalid")
        return cls(value, model.proof.digest(raw))

    def qualify(self, raw):
        value = model.document(raw)
        model.require(set(value) == {"schema_version", "qualified", "policy_sha256", "evidence"}
                      and value["schema_version"] == 1 and value["qualified"] is True
                      and value["policy_sha256"] == self.digest and isinstance(value["evidence"], dict)
                      and set(value["evidence"]) == set(QUALIFICATIONS)
                      and all(model.proof.matches(model.proof.HASH, item) for item in value["evidence"].values()),
                      "native-adapter-unqualified")

    def admit(self, command):
        if command.request:
            request = command.request
            model.require(request.variant == self.value["variant"], "variant-driver-unavailable")
            model.require((request.candidate_sha, request.driver_sha) ==
                          (self.value["candidate_sha"], self.value["driver_sha"]), "request-not-authorized")

    def environment(self):
        return {"PATH": "/usr/bin:/usr/local/go/bin", "HOME": str(JOBS), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                "GITHUB_RUN_ATTEMPT": "1", "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory",
                "GIT_CONFIG_VALUE_0": str(CANDIDATE), "GOCACHE": str(JOBS / "go-cache"), "GOMODCACHE": str(JOBS / "go-mod")}


def artifact_paths():
    return [str(BASE / name) for name in SOURCES] + [str(HELPER), str(WORKER),
            "/etc/systemd/system/" + UNIT, "/etc/sudoers.d/blender-box-proof", "/etc/ssh/blender-box-proof-authorized_keys", TMPFILES]


def validate_enrollment(value, *, _policy=False):
    model.require(isinstance(value, dict) and set(value) - {"variant"} == {"schema_version", "control_uid", "control_gid", "runner_uid",
                  "runner_gid", "candidate_sha", "driver_sha", "expected_client_sha256", "tool_sha256"} | (set() if _policy else {"public_key"})
                  and type(value["schema_version"]) is int and value["schema_version"] == 1, "native-enrollment-invalid")
    model.require(all(type(value[k]) is int and 0 < value[k] < (1 << 31)
                      for k in ("control_uid", "control_gid", "runner_uid", "runner_gid"))
                  and value["control_uid"] != value["runner_uid"]
                  and all(model.proof.matches(model.proof.SHA, value[k]) for k in ("candidate_sha", "driver_sha"))
                  and model.proof.matches(model.proof.HASH, value["expected_client_sha256"])
                  and isinstance(value["tool_sha256"], dict) and set(value["tool_sha256"]) == set(TOOLS)
                  and all(model.proof.matches(model.proof.HASH, item) for item in value["tool_sha256"].values()),
                  "native-enrollment-invalid")
    model.require(value.get("variant", "baseline") in ("baseline", "named-target"), "native-enrollment-invalid")
    if _policy:
        return
    model.require(model.proof.matches(r"ssh-ed25519 [A-Za-z0-9+/]{68}", value["public_key"]), "native-enrollment-invalid")
    try:
        key = base64.b64decode(value["public_key"].split()[1], validate=True)
    except ValueError as error:
        raise model.ControllerError("native-enrollment-invalid") from error
    model.require(len(key) == 51 and key[:19] == b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 ", "native-enrollment-invalid")


def render_enrollment(spec, source, output):
    value = model.document(model.read_private(spec))
    validate_enrollment(value)
    def launcher(entry):
        code = launcher_code(entry)
        import shlex
        return "#!/bin/sh\nexec /usr/bin/python3 -I -S -c " + shlex.quote(code) + ' "$@"\n'
    helper = launcher("proof_controller_native")
    worker = launcher("proof_controller_worker")
    service = f"""[Unit]
Description=Blender Box fixed proof supervisor
[Service]
Type=exec
User=root
ExecStart={WORKER} supervise
Restart=no
KillMode=control-group
Delegate=yes
TimeoutStartSec=45
TimeoutStopSec=30
RuntimeMaxSec=3h
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths={CONTROL} {JOBS} {RUNTIME} {CANDIDATE}/artifacts /sys/fs/cgroup{UNIT_CGROUP}
UMask=0077
"""
    contents = {str(BASE / name): (source / name).read_bytes() for name in SOURCES}
    contents.update({str(HELPER): helper.encode(), str(WORKER): worker.encode(),
                     "/etc/systemd/system/" + UNIT: service.encode(),
                     TMPFILES: f"d {RUNTIME} 0700 root root -\n".encode(),
                     "/etc/sudoers.d/blender-box-proof":
                         f"Defaults!{HELPER} env_reset, !setenv\n#{value['control_uid']} ALL=(root) NOPASSWD: {HELPER} dispatch\n".encode(),
                     "/etc/ssh/blender-box-proof-authorized_keys":
                         f'restrict,command="/usr/bin/sudo -n {HELPER} dispatch" {value["public_key"]}\n'.encode()})
    policy = {key: item for key, item in value.items() if key != "public_key"}
    policy.update(variant=value.get("variant", "baseline"), artifacts={path: model.proof.digest(raw) for path, raw in contents.items()})
    policy_raw = model.proof.canonical(policy)
    contents[str(CONFIG / "policy.json")] = policy_raw
    contents[str(CONFIG / "qualification.json")] = model.proof.canonical({"schema_version": 1, "qualified": False,
                             "policy_sha256": model.proof.digest(policy_raw), "evidence": {key: None for key in QUALIFICATIONS}})
    model.private_directory(output, create=True)
    resources = []
    for index, (path, raw) in enumerate(sorted(contents.items())):
        name = f"resource-{index:02d}"
        model.publish(output / name, raw)
        mode = "0755" if path in (str(HELPER), str(WORKER)) else "0644"
        if path.startswith(str(CONFIG)):
            mode = "0600"
        if "/sudoers.d/" in path:
            mode = "0440"
        resources.append({"path": path, "source": name, "uid": 0, "gid": 0, "mode": mode,
                          "sha256": model.proof.digest(raw)})
    directories = [{"path": str(path), "uid": uid, "gid": gid, "mode": mode} for path, uid, gid, mode in
                   ((CONFIG, 0, 0, "0700"), (CONTROL, 0, 0, "0700"), (JOBS, value["runner_uid"], value["runner_gid"], "0700"),
                    (RUNTIME, 0, 0, "0700"), (BASE, 0, 0, "0755"), (CANDIDATE, 0, 0, "0755"),
                    (CANDIDATE / "artifacts", value["runner_uid"], value["runner_gid"], "0700"),
                    (JOBS / "go-cache", value["runner_uid"], value["runner_gid"], "0700"),
                    (JOBS / "go-mod", value["runner_uid"], value["runner_gid"], "0700"))]
    known_directories = {entry["path"] for entry in directories}
    for resource_path in contents:
        for parent in Path(resource_path).parents:
            if parent.is_relative_to(BASE) and str(parent) not in known_directories:
                directories.append({"path": str(parent), "uid": 0, "gid": 0, "mode": "0755"})
                known_directories.add(str(parent))
    directories.append({"path": "/var/lib/blender-box-proof", "uid": 0, "gid": 0, "mode": "0755"})
    manifest = {"schema_version": 1, "status": "unqualified", "installable": False, "resources": resources,
                "directories": directories, "missing_qualification": list(QUALIFICATIONS),
                "operator_inputs": [str(CONFIG / name) for name in ("operator.json", "ssh-config", "key", "known_hosts")],
                "policy_sha256": model.proof.digest(policy_raw)}
    model.publish(output / "manifest.json", model.proof.canonical(manifest))
    return manifest


def protected_read(path, limit=128 << 20, private=False):
    model.no_links(path)
    for parent in path.parents:
        info = parent.stat()
        model.require(info.st_uid == 0 and info.st_mode & 0o022 == 0, "native-source-untrusted")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        model.require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                      and info.st_mode & (0o077 if private else 0o022) == 0
                      and 0 < info.st_size <= limit, "native-source-untrusted")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        model.require(len(raw) == info.st_size and os.fstat(fd).st_mtime_ns == info.st_mtime_ns,
                      "native-source-untrusted")
        return raw
    finally:
        os.close(fd)


def tool_read(path):
    model.require(str(path) in TOOLS, "native-source-untrusted")
    pending, resolved, links = list(path.parts[1:]), Path("/"), 0
    while pending:
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            resolved = resolved.parent
            continue
        current = resolved / part
        info = current.lstat()
        model.require(info.st_uid == 0, "native-source-untrusted")
        if stat.S_ISLNK(info.st_mode):
            links += 1
            model.require(links <= 40, "native-source-untrusted")
            target = Path(os.readlink(current))
            if target.is_absolute():
                resolved = Path("/")
                pending = list(target.parts[1:]) + pending
            else:
                pending = list(target.parts) + pending
        else:
            model.require(info.st_mode & 0o022 == 0, "native-source-untrusted")
            resolved = current
    return protected_read(resolved)


def load_runtime():
    try:
        raw = protected_read(CONFIG / "policy.json", model.MAX_FILE, private=True)
        policy = NativePolicy.parse(raw)
        policy.qualify(protected_read(CONFIG / "qualification.json", model.MAX_FILE, private=True))
        for path, expected in policy.value["artifacts"].items():
            model.require(model.proof.digest(protected_read(Path(path))) == expected, "native-source-untrusted")
        for path, expected in policy.value["tool_sha256"].items():
            model.require(model.proof.digest(tool_read(Path(path))) == expected, "native-source-untrusted")
        model.no_links(CANDIDATE)
        for path in (CANDIDATE, *CANDIDATE.parents):
            info = path.stat()
            model.require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o022 == 0,
                          "native-source-untrusted")
        operator = model.document(protected_read(CONFIG / "operator.json", 64 << 10, private=True))
        model.require(operator.get("ssh_config") == str(CONFIG / "ssh-config"), "native-source-untrusted")
        connection = model.ssh_connection(protected_read(CONFIG / "ssh-config", 64 << 10, private=True),
                                          operator["target"]["ssh_alias"])
        model.require(connection["identityfile"] == str(CONFIG / "key")
                      and connection["userknownhostsfile"] == str(CONFIG / "known_hosts"), "native-source-untrusted")
        for name in ("key", "known_hosts"):
            protected_read(CONFIG / name, 64 << 10, private=True)
        model.require(sys_platform_linux() and os.getuid() == os.geteuid() == 0, "native-adapter-unqualified")
        files = FixtureFiles(RootedFiles(CONTROL, 0, 0),
                             RootedFiles(JOBS, policy.value["runner_uid"], policy.value["runner_gid"]),
                             RootedFiles(CONFIG, 0, 0), RootedFiles(RUNTIME, 0, 0))
        return policy, files
    except (OSError, model.ControllerError, KeyError, TypeError) as error:
        raise model.ControllerError("native-adapter-unqualified") from error


def sys_platform_linux():
    import sys
    return sys.platform == "linux"


def launcher_code(module):
    model.require(module in ("proof_controller_native", "proof_controller_worker"), "native-operation-invalid")
    paths = [str(BASE / name) for name in SOURCES if name.startswith("scripts/")]
    return ("import os,sys,stat\n"
            "from pathlib import Path\n"
            "try:\n"
            " for name in " + repr(paths) + ":\n"
            "  p=Path(name)\n"
            "  for item in (*p.parents,p):\n"
            "   st=item.lstat()\n"
            "   if st.st_uid!=0 or st.st_mode&0o022 or stat.S_ISLNK(st.st_mode): raise ValueError()\n"
            "  if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1: raise ValueError()\n"
            "except (OSError,ValueError):\n"
            " sys.stdout.write('{\"schema_version\":1,\"status\":\"error\",\"code\":\"native-adapter-unqualified\"}\\n')\n"
            " sys.exit(1)\n"
            "sys.path.insert(0," + repr(str(BASE / "scripts")) + ")\n"
            "from " + module + " import " + ("entrypoint" if module.endswith("native") else "main") + " as run\n"
            "raise SystemExit(run())\n")


def bounded_command(args, **kwargs):
    timeout = kwargs.pop("timeout")
    kwargs.pop("check")
    child = subprocess.Popen(args, **kwargs)
    chunks = {child.stdout: bytearray(), child.stderr: bytearray()}
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for stream in chunks:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                model.require(remaining > 0, "native-service-unavailable")
                for key, _ in selector.select(remaining):
                    data = os.read(key.fd, 16385)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    chunks[key.fileobj].extend(data)
                    model.require(len(chunks[key.fileobj]) <= 16384, "native-service-unavailable")
        code = child.wait(timeout=max(0.001, deadline - time.monotonic()))
        return subprocess.CompletedProcess(args, code, bytes(chunks[child.stdout]), bytes(chunks[child.stderr]))
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        child.stdout.close()
        child.stderr.close()


def wait_file(path, predicate, timeout):
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
    model.require(fd >= 0, "native-watch-unavailable")
    try:
        model.require(libc.inotify_add_watch(fd, os.fsencode(path.parent), 0x100 | 0x80 | 0x8 | 0x200) >= 0,
                      "native-watch-unavailable")
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        deadline = time.monotonic() + timeout
        while True:
            value = predicate()
            if value is not None:
                return value
            remaining = deadline - time.monotonic()
            model.require(remaining > 0 and poller.poll(max(1, int(remaining * 1000))), "native-start-unconfirmed")
            os.read(fd, 65536)
    finally:
        os.close(fd)


class LinuxOps:
    def __init__(self, policy, *, _run=bounded_command):
        self.policy, self._run = policy, _run

    def systemctl(self, operation):
        model.require(operation in ("show", "start"), "native-operation-invalid")
        args = ["/usr/bin/systemctl", "--no-pager", "--no-ask-password"]
        if operation == "show":
            args += ["show", "--all", "--property=" + ",".join(PROPERTIES), UNIT]
        else:
            args += ["start", "--no-block", UNIT]
        result = self._run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env={"PATH": "/usr/bin", "LANG": "C", "SYSTEMD_COLORS": "0"}, timeout=10, check=False,
                           close_fds=True)
        model.require(result.returncode == 0 and len(result.stdout) <= 16384 and len(result.stderr) <= 16384,
                      "native-service-unavailable")
        return result.stdout

    def unit(self):
        return parse_unit(self.systemctl("show"))

    def boot(self):
        return boot_id(Path("/proc/sys/kernel/random/boot_id").read_bytes())

    def process(self, pid):
        first = Path(f"/proc/{pid}/stat").read_bytes()
        group = Path(f"/proc/{pid}/cgroup").read_bytes()
        parsed = parse_process(pid, first, group)
        model.require(parsed == parse_process(pid, Path(f"/proc/{pid}/stat").read_bytes(), group), "native-process-changed")
        return parsed

    @contextmanager
    def group(self, name):
        model.require(name == UNIT_CGROUP or model.proof.matches(re.escape(UNIT_CGROUP) + r"/attempt-[a-f0-9]{32}", name),
                      "native-cgroup-invalid")
        fd = os.open(CGROUP, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in name.split("/")[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                info = os.fstat(fd)
                model.require(info.st_uid == 0 and info.st_mode & 0o022 == 0, "native-cgroup-invalid")
            yield fd
        finally:
            os.close(fd)

    def group_read(self, fd):
        child = os.open("cgroup.events", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            return populated(os.read(child, 4097))
        finally:
            os.close(child)

    def write_group(self, fd, name, data):
        model.require(name in ("cgroup.kill", "cgroup.procs"), "native-operation-invalid")
        child = os.open(name, os.O_WRONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            model.require(os.write(child, data) == len(data), "native-cgroup-invalid")
        finally:
            os.close(child)

    def whole_empty(self):
        unit = self.unit()
        if unit.main_pid or unit.job_id or unit.active not in ("inactive", "failed"):
            return False
        try:
            with self.group(UNIT_CGROUP) as fd:
                return not self.group_read(fd)
        except FileNotFoundError:
            return True

    def supervisor_gone(self, receipt):
        try:
            process = self.process(receipt.invocation.parent_pid)
        except FileNotFoundError:
            return True
        return process.start != receipt.supervisor_start

    def end_supervisor(self, receipt):
        if self.supervisor_gone(receipt):
            return
        fd = os.pidfd_open(receipt.invocation.parent_pid)
        try:
            current = self.process(receipt.invocation.parent_pid)
            model.require(current.start == receipt.supervisor_start and current.cgroup == UNIT_CGROUP,
                          "native-supervisor-changed")
            signal.pidfd_send_signal(fd, signal.SIGTERM)
        finally:
            os.close(fd)

    def wait_group_empty(self, fd, deadline):
        events = os.open("cgroup.events", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            poller = select.poll()
            poller.register(events, select.POLLPRI | select.POLLERR)
            while True:
                os.lseek(events, 0, os.SEEK_SET)
                if not populated(os.read(events, 4097)):
                    return
                remaining = deadline - time.monotonic()
                model.require(remaining > 0 and poller.poll(max(1, int(remaining * 1000))), "local-termination-unknown")
        finally:
            os.close(events)

    def wait_supervisor(self, receipt, deadline):
        if self.supervisor_gone(receipt):
            return True
        fd = os.pidfd_open(receipt.invocation.parent_pid)
        try:
            current = self.process(receipt.invocation.parent_pid)
            model.require(current.start == receipt.supervisor_start and current.cgroup == UNIT_CGROUP,
                          "native-supervisor-changed")
            poller = select.poll()
            poller.register(fd, select.POLLIN)
            remaining = deadline - time.monotonic()
            return bool(remaining > 0 and poller.poll(max(1, int(remaining * 1000))))
        finally:
            os.close(fd)

    def stop(self, receipt):
        if self.boot() != receipt.invocation.boot_id:
            return self.whole_empty()
        deadline = time.monotonic() + STOP_SECONDS
        with self.group(receipt.invocation.cgroup) as fd:
            info = os.fstat(fd)
            model.require((info.st_dev, info.st_ino) == (receipt.cgroup_device, receipt.cgroup_inode),
                          "native-cgroup-changed")
            self.write_group(fd, "cgroup.kill", b"1\n")
            self.wait_group_empty(fd, deadline)
        self.end_supervisor(receipt)
        if not self.wait_supervisor(receipt, deadline):
            return False
        try:
            with self.group(UNIT_CGROUP) as fd:
                self.wait_group_empty(fd, deadline)
        except FileNotFoundError:
            pass
        return self.supervisor_gone(receipt) and self.whole_empty()

    def exchange(self, receipt, request):
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
            connection.settimeout(STARTUP_SECONDS)
            connection.connect(str(SOCKET))
            pid, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            model.require(uid == 0 and pid == receipt.invocation.parent_pid
                          and self.process(pid).start == receipt.supervisor_start, "native-peer-invalid")
            connection.sendall(model.proof.canonical(request))
            return model.document(connection.recv(model.MAX_WIRE + 1), model.MAX_WIRE)


def parse_intent(raw):
    value = model.document(raw)
    model.require(set(value) == {"schema_version", "execution_id", "attempt", "request_digest", "mode"}
                  and model.proof.matches(model.EXECUTION_ID, value["execution_id"])
                  and type(value["attempt"]) is int and 0 < value["attempt"] <= 9999
                  and model.proof.matches(model.proof.HASH, value["request_digest"])
                  and value["mode"] in ("baseline", "recover"), "native-intent-invalid")
    return value


@dataclass(frozen=True)
class StartupFailure:
    intent: dict
    intent_sha256: str
    boot_id: str
    invocation_id: str
    supervisor_pid: int
    supervisor_start: int
    cgroup: str
    cgroup_device: int
    cgroup_inode: int
    schema_version: int = 1

    @classmethod
    def parse(cls, value):
        model.require(isinstance(value, dict) and set(value) == set(cls.__dataclass_fields__)
                      and type(value["schema_version"]) is int and value["schema_version"] == 1,
                      "startup-failure-invalid")
        parse_intent(model.proof.canonical(value["intent"]))
        model.require(model.proof.matches(model.proof.HASH, value["intent_sha256"])
                      and all(model.proof.matches(r"[a-f0-9]{32}", value[key]) for key in ("boot_id", "invocation_id"))
                      and all(type(value[key]) is int and value[key] > 0 for key in
                              ("supervisor_pid", "supervisor_start", "cgroup_device", "cgroup_inode"))
                      and model.proof.matches(re.escape(UNIT_CGROUP) + r"/attempt-[a-f0-9]{32}", value["cgroup"]),
                      "startup-failure-invalid")
        return cls(**value)


def attempt_path(intent, kind):
    return CONTROL / intent["execution_id"] / f"{kind}-{intent['attempt']:04d}.json"


def reject_unreleased(files, intent):
    model.require(not files.exists(attempt_path(intent, "unreleased")), "attempt-unreleased")


def receipt_path(invocation):
    return CONTROL / invocation.execution_id / f"native-{invocation.attempt:04d}.json"


class NativeService:
    def __init__(self, policy, files, ops):
        self.policy, self.files, self.ops = policy, files, ops

    def receipt(self, invocation):
        value = NativeReceipt.parse(model.document(self.files.read(receipt_path(invocation))))
        model.require(value.invocation == invocation, "native-receipt-invalid")
        return value

    def inspect_attempt(self, request, attempt, saved_invocation):
        identity = {"execution_id": request.execution_id, "attempt": attempt}
        path = attempt_path(identity, "native")
        if not self.files.exists(path):
            return None
        receipt = NativeReceipt.parse(model.document(self.files.read(path)))
        inv = receipt.invocation
        intent_raw = self.files.read(attempt_path(identity, "intent"))
        intent = parse_intent(intent_raw)
        model.require((inv.execution_id, inv.attempt, inv.request_digest) ==
                      (request.execution_id, attempt, request.digest)
                      and (saved_invocation is None or saved_invocation == inv)
                      and intent == {"schema_version": 1, **identity, "request_digest": request.digest,
                                     "mode": "baseline" if attempt == 1 else "recover"}, "native-attempt-invalid")
        original = model.ProofExecutionRequest.parse(model.document(self.files.read(CONTROL / request.execution_id / "request.json")))
        model.require(original == request, "native-attempt-invalid")
        self.policy.admit(model.Command("start", request.execution_id, request))
        issuer_path = attempt_path(identity, "start-command")
        if self.files.exists(issuer_path):
            model.require(model.document(self.files.read(issuer_path)) == {"schema_version": 1,
                          "intent_sha256": model.proof.digest(intent_raw), "boot_id": inv.boot_id}, "native-attempt-invalid")
        model.require(not any(self.files.exists(attempt_path(identity, kind)) for kind in
                              ("unreleased", "startup-failure")), "native-attempt-invalid")
        authorization = attempt_path(identity, "authorization")
        result = attempt_path(identity, "result")
        authorized, completed = self.files.exists(authorization), self.files.exists(result)
        model.require(saved_invocation is not None or not (authorized or completed), "native-publication-conflict")
        model.require(not completed or authorized, "native-publication-conflict")
        if authorized:
            model.require(model.document(self.files.read(authorization)) == {"schema_version": 1,
                          "invocation": asdict(inv), "mode": intent["mode"]}, "native-authorization-invalid")
        if completed:
            record = model.document(self.files.read(result))
            model.require(isinstance(record, dict) and set(record) == {"schema_version", "invocation", "mode", "result"}
                          and record["schema_version"] == 1 and record["invocation"] == asdict(inv)
                          and record["mode"] == intent["mode"], "proof-result-invalid")
        boot, unit = self.ops.boot(), self.ops.unit()
        pending_path = RUNTIME / "pending.json"
        pending = parse_intent(self.files.read(pending_path)) if self.files.exists(pending_path) else None
        model.require(pending is None or pending == intent, "fixture-unresolved")
        model.require(unit.job_id == 0 and unit.invocation_id in ("", inv.invocation_id), "service-identity-changed")
        empty = self.ops.whole_empty()
        if empty:
            model.require(unit.active in ("inactive", "failed") and unit.main_pid == 0
                          and (boot != inv.boot_id or self.ops.supervisor_gone(receipt)), "local-termination-unknown")
        else:
            model.require(boot == inv.boot_id and pending == intent and unit.main_pid == inv.parent_pid
                          and unit.invocation_id == inv.invocation_id, "service-identity-changed")
            supervisor = self.ops.process(inv.parent_pid)
            model.require(supervisor.start == receipt.supervisor_start and supervisor.cgroup == UNIT_CGROUP,
                          "native-supervisor-changed")
            try:
                child = self.ops.process(inv.leader_pid)
            except FileNotFoundError:
                pass
            else:
                model.require((child.start, child.parent, child.cgroup) == (inv.leader_start_ticks, inv.parent_pid, inv.cgroup),
                              "native-worker-changed")
            with self.ops.group(inv.cgroup) as fd:
                info = os.fstat(fd)
                model.require((info.st_dev, info.st_ino) == (receipt.cgroup_device, receipt.cgroup_inode), "native-cgroup-changed")
        if empty and boot == inv.boot_id:
            try:
                with self.ops.group(inv.cgroup) as fd:
                    info = os.fstat(fd)
                    model.require((info.st_dev, info.st_ino) == (receipt.cgroup_device, receipt.cgroup_inode),
                                  "native-cgroup-changed")
            except FileNotFoundError:
                pass
            model.require(self.ops.whole_empty() and self.ops.unit() == unit, "fixture-unresolved")
        model.require(self.ops.boot() == boot, "service-identity-changed")
        return model.BoundAttempt(inv, intent["mode"], "gone" if empty else "live",
                                  "result" if completed else "uncertain" if authorized else "withheld")

    def observe(self):
        boot = self.ops.boot()
        empty = self.ops.whole_empty()
        if not self.files.exists(RUNTIME / "pending.json"):
            return model.ServiceObservation(boot, None, empty)
        pending = parse_intent(self.files.read(RUNTIME / "pending.json"))
        path = CONTROL / pending["execution_id"] / f"native-{pending['attempt']:04d}.json"
        if not self.files.exists(path):
            request = model.ProofExecutionRequest.parse(model.document(self.files.read(CONTROL / pending["execution_id"] / "request.json")))
            proven = self.unreleased(request, pending["attempt"], fresh=True)
            return model.ServiceObservation(boot, None, bool(proven is not None and empty))
        receipt = NativeReceipt.parse(model.document(self.files.read(path)))
        inv = receipt.invocation
        if inv.boot_id != boot:
            return model.ServiceObservation(boot, None, empty)
        if not empty:
            unit = self.ops.unit()
            supervisor = self.ops.process(inv.parent_pid)
            model.require(supervisor.start == receipt.supervisor_start and supervisor.cgroup == UNIT_CGROUP
                          and unit.invocation_id == inv.invocation_id and unit.main_pid == inv.parent_pid,
                          "service-identity-changed")
        else:
            model.require(self.ops.supervisor_gone(receipt), "local-termination-unknown")
        return model.ServiceObservation(boot, inv, empty)

    def start(self, request, attempt):
        intent_path = CONTROL / request.execution_id / f"intent-{attempt:04d}.json"
        intent = parse_intent(self.files.read(intent_path))
        model.require(intent["request_digest"] == request.digest and intent["attempt"] == attempt
                      and intent["execution_id"] == request.execution_id and self.ops.whole_empty(), "fixture-unresolved")
        reject_unreleased(self.files, intent)
        self.files.publish(RUNTIME / "pending.json", model.proof.canonical(intent), exclusive=False)
        issuer_boot = self.ops.boot()
        self.ops.systemctl("start")
        self.files.publish(attempt_path(intent, "start-command"), model.proof.canonical({"schema_version": 1,
                           "intent_sha256": model.proof.digest(self.files.read(intent_path)), "boot_id": issuer_boot}))
        path = CONTROL / request.execution_id / f"native-{attempt:04d}.json"
        def ready():
            if not self.files.exists(path):
                return None
            try:
                raw = self.files.read(path)
            except PendingPublication:
                return None
            receipt = NativeReceipt.parse(model.document(raw))
            inv = receipt.invocation
            model.require(inv.request_digest == request.digest and inv.attempt == attempt
                          and inv.execution_id == request.execution_id and inv.boot_id == self.ops.boot(), "native-receipt-invalid")
            return inv
        return wait_file(path, ready, STARTUP_SECONDS)

    def release(self, invocation, authorization_path, job, mode, retained):
        model.require(authorization_path == CONTROL / invocation.execution_id / f"authorization-{invocation.attempt:04d}.json",
                      "native-authorization-invalid")
        reject_unreleased(self.files, {"execution_id": invocation.execution_id, "attempt": invocation.attempt})
        receipt = self.receipt(invocation)
        raw = self.files.read(authorization_path)
        response = self.ops.exchange(receipt, {"schema_version": 1, "operation": "release", "invocation": asdict(invocation),
                                             "authorization_sha256": model.proof.digest(raw)})
        return response == {"schema_version": 1, "released": True, "invocation": asdict(invocation)}

    def unreleased(self, request, attempt, *, fresh=False, publish=False):
        identity = {"execution_id": request.execution_id, "attempt": attempt}
        failure_path = attempt_path(identity, "startup-failure")
        issuer_path = attempt_path(identity, "start-command")
        if not self.files.exists(failure_path) or not self.files.exists(issuer_path):
            return None
        def evidence():
            intent_raw = self.files.read(attempt_path(identity, "intent"))
            intent = parse_intent(intent_raw)
            failure_raw = self.files.read(failure_path)
            failure = StartupFailure.parse(model.document(failure_raw))
            issuer = model.document(self.files.read(issuer_path))
            model.require(intent["execution_id"] == request.execution_id and intent["attempt"] == attempt
                          and intent["request_digest"] == request.digest and (intent["mode"] == "baseline") == (attempt == 1)
                          and failure.intent == intent and failure.intent_sha256 == model.proof.digest(intent_raw)
                          and issuer == {"schema_version": 1, "intent_sha256": failure.intent_sha256, "boot_id": failure.boot_id},
                          "unreleased-proof-invalid")
            original = model.ProofExecutionRequest.parse(model.document(self.files.read(CONTROL / request.execution_id / "request.json")))
            model.require(original == request, "unreleased-proof-invalid")
            model.require(not any(self.files.exists(attempt_path(identity, kind)) for kind in
                                  ("native", "authorization", "result")), "unreleased-proof-invalid")
            return intent, failure, model.proof.digest(failure_raw)
        intent, failure, failure_hash = evidence()
        proof_path = attempt_path(identity, "unreleased")
        existing = model.UnreleasedProof.parse(model.document(self.files.read(proof_path))) if self.files.exists(proof_path) else None
        def quiescent():
            boot = self.ops.boot()
            if self.files.exists(RUNTIME / "pending.json"):
                model.require(parse_intent(self.files.read(RUNTIME / "pending.json")) == intent, "fixture-unresolved")
            else:
                model.require(boot != failure.boot_id, "fixture-unresolved")
            unit = self.ops.unit()
            model.require(unit.active in ("inactive", "failed") and unit.main_pid == 0 and unit.job_id == 0
                          and unit.invocation_id in ("", failure.invocation_id) and self.ops.whole_empty(), "fixture-unresolved")
            if boot == failure.boot_id:
                try:
                    supervisor = self.ops.process(failure.supervisor_pid)
                except FileNotFoundError:
                    pass
                else:
                    model.require(supervisor.start != failure.supervisor_start, "fixture-unresolved")
            return boot
        observed_boot = quiescent() if fresh or publish else (existing.observed_boot if existing else failure.boot_id)
        result = model.UnreleasedProof(request.execution_id, attempt, request.digest, intent["mode"],
                                       failure.intent_sha256, failure_hash, observed_boot)
        if existing is not None:
            model.require(replace(existing, observed_boot=observed_boot) == result, "unreleased-proof-invalid")
            return existing
        if not publish:
            return None
        model.require(quiescent() == observed_boot and evidence() == (intent, failure, failure_hash), "fixture-unresolved")
        self.files.publish(proof_path, model.proof.canonical(asdict(result)))
        return result

    def result(self, invocation):
        self.receipt(invocation)
        path = CONTROL / invocation.execution_id / f"result-{invocation.attempt:04d}.json"
        return model.document(self.files.read(path)) if self.files.exists(path) else None

    def stop_exact(self, invocation):
        return self.ops.stop(self.receipt(invocation))


def entrypoint(argv=None):
    import sys
    args = sys.argv[1:] if argv is None else argv
    try:
        model.require(args == ["dispatch"], "invalid-command")
        command = model.parse_command(sys.stdin.buffer.read(model.MAX_WIRE + 1))
        policy, files = load_runtime()
        ops = LinuxOps(policy)
        controller = model.Controller(CONTROL, JOBS, policy.controller, NativeService(policy, files, ops),
                                      files=files, admission=policy.admit)
        result = controller.dispatch(command)
        print(model.proof.canonical(result).decode())
        return 0
    except (OSError, model.ControllerError, model.proof.ProofError, subprocess.SubprocessError) as error:
        code = error.code if isinstance(error, model.ControllerError) else "native-unavailable"
        print(model.proof.canonical({"schema_version": 1, "status": "error", "code": code}).decode())
        return 1


if __name__ == "__main__":
    raise SystemExit(entrypoint())
