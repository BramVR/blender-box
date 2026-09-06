#!/usr/bin/env python3
"""Opt-in prepared Windows proofs, through the public Blender Box CLI."""

import argparse
import base64
import dataclasses
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import stat
import struct
import subprocess
import threading
import time
import zlib


REQUIRED = ("preparation", "readiness", "scenario", "evidence", "recovery", "cleanup")
NAMED_REQUIRED = ("target-catalog", "target-binding", "target-restoration", "target-forget")
PROOF_TARGET = "onboarding-proof"
CLEANUP = ("session_stopped", "payload_removed", "run_root_removed", "lock_released")
CHECKS = {
    "host.windows", "host.console-user", "host.ssh-user", "host.limited-token-policy",
    "blender.executable", "daemon.executable", "host.executable", "work-root.access",
    "work-root.state-tree", "task.interactive",
}
CAPABILITIES = ("blender-box-v1", "typed-call-error-reason")
SHA = r"[0-9a-f]{40}"
HASH = r"[0-9a-f]{64}"
RUN_ID = r"bbx_[A-Za-z0-9_-]{16,64}"
FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/onboarding-baseline"
BASELINE_RESULT = {"schema_version": 1, "status": "pass", "object": "OnboardingCube",
                   "type": "MESH", "vertices": 8, "edges": 12, "faces": 6}


class ProofError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition, code):
    if not condition:
        raise ProofError(code)


def matches(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "invalid-json")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ProofError("invalid-json")))
    except (ValueError, UnicodeError) as error:
        raise ProofError("invalid-json") from error
    require(isinstance(value, dict), "invalid-json")
    require(type(value.get("schema_version")) is int and value["schema_version"] == 1,
            "invalid-schema")
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(content):
    return hashlib.sha256(content).hexdigest()


def read_regular(root, relative, limit=16 << 20):
    require(isinstance(relative, str) and len(relative) <= 240, "unsafe-evidence-path")
    parts = relative.split("/")
    require(all(re.fullmatch(r"[A-Za-z0-9_.-]+", p) and p not in (".", "..")
                and not p.endswith((".", " ")) for p in parts), "unsafe-evidence-path")
    require(not root.is_symlink(), "unsafe-evidence-path")
    path = root
    for part in parts:
        path = path / part
        require(not path.is_symlink(), "unsafe-evidence-path")
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit, "invalid-evidence-file")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        require(os.path.samestat(before, opened), "evidence-changed")
        content = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    require(len(content) == before.st_size and opened.st_mtime_ns == after.st_mtime_ns
            and os.path.samestat(after, path.stat()), "evidence-changed")
    return content


@dataclasses.dataclass(frozen=True)
class Fence:
    run_id: str
    request_id: str
    request_hash: str
    deadline: str
    session_id: str | None

    @classmethod
    def parse(cls, record, require_session=True):
        require(type(record.get("schema_version")) is int and record["schema_version"] == 1,
                "invalid-schema")
        patterns = {"run_id": RUN_ID, "request_id": r"req_[A-Za-z0-9_-]{16,64}",
                    "request_hash": HASH,
                    "deadline": r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)"}
        require(all(matches(pattern, record.get(key)) for key, pattern in patterns.items()),
                "invalid-fence")
        try:
            utc = datetime.datetime.fromisoformat(record["deadline"].replace("Z", "+00:00")).astimezone(datetime.timezone.utc)
        except ValueError as error:
            raise ProofError("invalid-fence") from error
        session = record.get("session_id")
        require(matches(r"bss_[A-Za-z0-9_-]{16,128}", session)
                or (not require_session and session in (None, "")), "invalid-fence")
        fraction = re.search(r"\.(\d{1,9})(?:Z|[+-])", record["deadline"])
        nanoseconds = (fraction.group(1) if fraction else "").ljust(9, "0")
        deadline = utc.strftime("%Y-%m-%dT%H:%M:%S") + "." + nanoseconds + "Z"
        return cls(record["run_id"], record["request_id"], record["request_hash"], deadline, session or None)


def verify_cleanup(record):
    value = record.get("cleanup")
    require(isinstance(value, dict) and set(value) == set(CLEANUP), "cleanup-unknown")
    require(all(value[key] is True for key in CLEANUP), "cleanup-unknown")
    return {key: True for key in CLEANUP}


def verify_recovery(run, before, stop, after):
    fence = Fence.parse(run, require_session=False)
    session = fence.session_id
    for record in (before, stop, after):
        observed = Fence.parse(record, require_session=False)
        require(dataclasses.replace(observed, session_id=None) == dataclasses.replace(fence, session_id=None),
                "recovery-identity-changed")
        require(session is None or observed.session_id == session, "recovery-identity-changed")
        session = observed.session_id
    require(Fence.parse(stop, require_session=False).session_id == Fence.parse(after, require_session=False).session_id,
            "recovery-identity-changed")
    require(stop.get("status") == "settled", "recovery-not-settled")
    require(after.get("state") in ("complete", "failed", "timed-out", "cleanup-failed"),
            "recovery-not-settled")
    if run.get("state") == "complete":
        for record in (before, after):
            require(record.get("state") == "complete" and record.get("evidence") == run.get("evidence"),
                    "recovery-record-changed")
            verify_cleanup(record)
    verify_cleanup(stop)
    return verify_cleanup(after)


@dataclasses.dataclass(frozen=True)
class VerifiedArtifact:
    path: str
    type: str
    size: int
    remote_sha256: str
    local_sha256: str
    capture_method: str | None = None
    width: int | None = None
    height: int | None = None


def verify_png(content, width, height):
    require(type(width) is int and type(height) is int and 0 < width <= 8192
            and 0 < height <= 8192 and len(content) <= 16 << 20, "invalid-png")
    require(content.startswith(b"\x89PNG\r\n\x1a\n"), "invalid-png")
    offset, kinds, compressed = 8, set(), bytearray()
    row_size = 0
    while offset < len(content):
        require(offset + 12 <= len(content), "invalid-png")
        size, kind = struct.unpack(">I4s", content[offset:offset + 8])
        end = offset + 12 + size
        require(end <= len(content), "invalid-png")
        data = content[offset + 8: end - 4]
        require(zlib.crc32(kind + data) == struct.unpack(">I", content[end - 4:end])[0],
                "invalid-png")
        require(kind in (b"IHDR", b"IDAT", b"IEND", b"sRGB", b"gAMA", b"cHRM", b"pHYs"),
                "png-metadata-not-allowed")
        if not kinds:
            require(kind == b"IHDR" and size == 13, "invalid-png")
            image_width, image_height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", data)
            require((image_width, image_height) == (width, height) and depth == 8 and color in (2, 6)
                    and compression == filtering == interlace == 0, "unsupported-png-encoding")
            row_size = width * (3 if color == 2 else 4) + 1
            require(row_size * height <= 64 << 20, "invalid-png")
        elif kind == b"IDAT":
            compressed.extend(data)
        elif kind == b"IEND":
            require(size == 0 and end == len(content) and b"IDAT" in kinds, "invalid-png")
        else:
            require(kind != b"IHDR" and kind not in kinds and b"IDAT" not in kinds, "invalid-png")
            if kind == b"sRGB":
                require(size == 1 and data[0] <= 3, "invalid-png")
            elif kind == b"gAMA":
                require(size == 4 and 0 < struct.unpack(">I", data)[0] <= 1_000_000, "invalid-png")
            elif kind == b"cHRM":
                require(size == 32, "invalid-png")
                values = struct.unpack(">8I", data)
                require(all(0 <= value <= 100_000 for value in values)
                        and all(0 < values[index] + values[index + 1] <= 100_000
                                for index in range(0, 8, 2)), "invalid-png")
            elif kind == b"pHYs":
                require(size == 9 and data[8] in (0, 1), "invalid-png")
                require(all(0 < value <= 1_000_000 for value in struct.unpack(">II", data[:8])), "invalid-png")
        kinds.add(kind)
        offset = end
    require(b"IEND" in kinds, "invalid-png")
    expected = row_size * height
    decoder = zlib.decompressobj()
    try:
        decoded = decoder.decompress(compressed, expected + 1)
    except zlib.error as error:
        raise ProofError("invalid-png") from error
    require(len(decoded) == expected and decoder.eof and not decoder.unused_data
            and not decoder.unconsumed_tail, "invalid-png")
    require(all(decoded[offset] <= 4 for offset in range(0, expected, row_size)), "invalid-png")


def verify_bundle(root, run):
    fence = Fence.parse(run)
    saved = document(read_regular(root, "evidence.json", 1 << 20))
    require(Fence.parse(saved) == fence, "evidence-identity-changed")
    require(saved == run, "evidence-record-changed")
    manifest = document(read_regular(root, "manifest.json", 1 << 20))
    require(manifest == run.get("evidence"), "evidence-manifest-changed")
    files = manifest.get("files")
    require(isinstance(files, list) and 1 <= len(files) <= 64, "invalid-evidence-manifest")
    seen, artifacts, total = set(), [], 0
    for item in files:
        require(isinstance(item, dict), "invalid-evidence-manifest")
        path, kind = item.get("path"), item.get("type")
        require(isinstance(path, str) and path.casefold() not in seen, "duplicate-evidence")
        seen.add(path.casefold())
        require(kind in ("scenario-result", "viewport"), "invalid-evidence-type")
        keys = {"path", "type", "size", "sha256"}
        if kind == "viewport":
            keys |= {"capture_method", "width", "height"}
        require(set(item) == keys, "invalid-evidence-manifest")
        require(type(item.get("size")) is int and 0 < item["size"] <= 16 << 20
                and matches(HASH, item.get("sha256")), "invalid-evidence-manifest")
        total += item["size"]
        require(total <= 64 << 20, "invalid-evidence-manifest")
        content = read_regular(root, path)
        require(len(content) == item["size"] and digest(content) == item["sha256"],
                "evidence-hash-mismatch")
        if kind == "viewport":
            require(item.get("capture_method") in ("offscreen", "window_grab"), "invalid-capture-provenance")
            verify_png(content, item.get("width"), item.get("height"))
        artifacts.append(VerifiedArtifact(path, kind, len(content), item["sha256"], digest(content),
                                         item.get("capture_method"), item.get("width"), item.get("height")))
    require(sum(a.type == "scenario-result" for a in artifacts) == 1
            and sum(a.type == "viewport" for a in artifacts) == 1, "missing-evidence")
    return tuple(artifacts)


def verify_baseline(root, artifacts):
    require({a.path for a in artifacts} == {"result/scenario-result.json", "screenshots/viewport.png"},
            "baseline-evidence-path")
    require(next(a for a in artifacts if a.type == "viewport").capture_method == "offscreen",
            "invalid-capture-provenance")
    result = document(read_regular(root, "result/scenario-result.json", 4096))
    require(canonical(result) == canonical(BASELINE_RESULT), "baseline-scenario-failed")


def verify_expected_host(expected, observed):
    require(type(observed.get("schema_version")) is int and observed["schema_version"] == 1,
            "invalid-schema")
    for key in ("hostname", "windows_build", "blender_version", "daemon_sha256"):
        require(observed.get(key) == expected[key], "wrong-host-identity")
    require(observed.get("controller_sid") == expected["identity_sid"]
            and observed.get("console_sid") == expected["identity_sid"]
            and observed.get("configured_ssh_sid") == expected["identity_sid"]
            and observed.get("configured_interactive_sid") == expected["identity_sid"], "wrong-host-identity")
    require(type(observed.get("blender_process_count")) is int
            and observed["blender_process_count"] == 0 and observed.get("host_lock_present") is False,
            "host-activity-unknown")
    require(observed.get("host_sha256") is None or matches(HASH, observed["host_sha256"]),
            "invalid-host-hash")


def verify_readiness(record):
    require(type(record.get("schema_version")) is int and record["schema_version"] == 1
            and record.get("status") == "pass", "readiness-failed")
    checks = record.get("checks")
    require(isinstance(checks, list), "readiness-failed")
    seen = set()
    for check in checks:
        require(isinstance(check, dict) and isinstance(check.get("id"), str)
                and check["id"] not in seen and type(check.get("required")) is bool
                and type(check.get("passed")) is bool, "readiness-failed")
        seen.add(check["id"])
        if check["id"] in CHECKS:
            require(check["required"] and check["passed"], "readiness-failed")
        if check["required"]:
            require(check["passed"], "readiness-failed")
    require(CHECKS <= seen, "readiness-failed")


def windows_target(target):
    require(isinstance(target, dict), "operator-config-invalid")
    keys = {"ssh_user", "work_root", "interactive_user", "task_name", "blender_executable",
            "session_broker_executable", "host_executable"}
    version = target.get("schema_version")
    require(type(version) is int, "operator-config-invalid")
    if version == 1:
        require(set(target) == keys | {"schema_version", "ssh_alias"}, "operator-config-invalid")
        view = dict(target)
    elif version == 2:
        require(target.get("platform") == "windows", "operator-platform-unsupported")
        require(set(target) == {"schema_version", "platform", "ssh_alias", "windows"}
                and isinstance(target["windows"], dict) and set(target["windows"]) == keys,
                "operator-config-invalid")
        view = {"schema_version": 1, "ssh_alias": target["ssh_alias"], **target["windows"]}
    else:
        raise ProofError("operator-config-invalid")
    require(all(isinstance(view[k], str) and view[k] for k in keys)
            and matches(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", view["ssh_alias"]), "operator-config-invalid")
    return view


def target_document(view):
    return {"schema_version": 2, "platform": "windows", "ssh_alias": view["ssh_alias"],
            "windows": {k: v for k, v in view.items() if k not in ("schema_version", "ssh_alias")}}


@dataclasses.dataclass(frozen=True)
class Operator:
    target: dict
    expected: dict
    fixture: dict
    authorization: dict
    ssh_config: Path | None
    publish_viewport: bool = False

    @property
    def windows(self):
        return windows_target(self.target)

    @classmethod
    def load(cls, path, candidate):
        require(path.is_file() and not path.is_symlink(), "operator-config-missing")
        require(os.name == "nt" or path.stat().st_mode & 0o077 == 0, "operator-config-permissions")
        data = document(read_regular(path.parent, path.name, 64 << 10))
        require(set(data) <= {"schema_version", "target", "expected_host", "fixture",
                              "authorization", "ssh_config", "publish_viewport"}, "operator-config-invalid")
        target, expected = data.get("target"), data.get("expected_host")
        fixture, auth = data.get("fixture"), data.get("authorization")
        require(all(isinstance(v, dict) for v in (target, expected, fixture, auth)), "operator-config-invalid")
        windows_target(target)
        require(set(expected) == {"hostname", "windows_build", "blender_version", "identity_sid", "daemon_sha256"}
                and matches(r"[A-Za-z0-9_.-]{1,128}", expected.get("hostname"))
                and matches(r"\d{4,6}", expected.get("windows_build"))
                and matches(r"\d+\.\d+(?:\.\d+)?", expected.get("blender_version"))
                and matches(r"S-1-\d+(?:-\d+)+", expected.get("identity_sid"))
                and matches(HASH, expected.get("daemon_sha256")), "operator-config-invalid")
        require(set(fixture) == {"id", "kind", "state"} and matches(r"[a-z0-9-]{1,64}", fixture.get("id"))
                and fixture.get("kind") in ("shared-existing", "dedicated") and fixture.get("state") == "prepared",
                "fixture-not-prepared")
        require(set(auth) == {"candidate_sha", "fixture_id", "launch", "setup"}
                and auth.get("candidate_sha") == candidate and auth.get("fixture_id") == fixture["id"]
                and auth.get("launch") is True, "launch-not-authorized")
        ssh_config = data.get("ssh_config")
        require(ssh_config is None or isinstance(ssh_config, str), "operator-config-invalid")
        require(type(data.get("publish_viewport", False)) is bool, "operator-config-invalid")
        return cls(target, expected, fixture, auth, Path(ssh_config) if ssh_config else None,
                   data.get("publish_viewport", False))


def verify_setup_authorization(operator, candidate, prior_hash):
    auth = operator.authorization["setup"]
    require(isinstance(auth, dict) and set(auth) == {"candidate_sha", "target_sha256", "prior_host_sha256", "scope"}
            and auth.get("candidate_sha") == candidate
            and auth.get("target_sha256") == digest(canonical(operator.target))
            and auth.get("prior_host_sha256") == prior_hash
            and auth.get("scope") == "windows-setup-binary-task-acls", "setup-not-authorized")


@dataclasses.dataclass(frozen=True)
class ProofRequest:
    candidate_sha: str
    candidate_checkout: Path
    operator_config: Path
    output: Path
    execution: str = "local"
    driver_sha: str | None = None
    proof: str = "baseline"


class Commands:
    def __init__(self, private, cwd):
        self.private, self.cwd = private, cwd
        self.env = dict(os.environ)
        self.sequence = 0
        self.cancelled = threading.Event()
        self.run_id = None
        self.marker_seen = False
        self.group_cleanup_known = True
        self.on_run_id = None

    def marker(self, line):
        if line.startswith(b"RUN_ID="):
            require(not self.marker_seen, "invalid-run-marker")
            self.marker_seen = True
            value = line[7:].decode("ascii", errors="replace")
            require(matches(RUN_ID, value), "invalid-run-marker")
            self.run_id = value
            journal = self.private / "run-journal.json"
            with journal.open("x", encoding="utf-8") as stream:
                json.dump({"schema_version": 1, "run_id": value}, stream)
                stream.flush()
                os.fsync(stream.fileno())
            if self.on_run_id is not None:
                self.on_run_id(value)

    def run(self, args, timeout=180, stdin=None, marker=False, env=None, recovery=False, limit=24 << 20,
            expected_error=None):
        require(os.name == "posix" and os.uname().sysname in ("Darwin", "Linux")
                and all(hasattr(os, name) for name in ("waitid", "WNOWAIT", "P_PID")),
                "controller-platform-unsupported")
        require(self.group_cleanup_known, "command-cleanup-unknown")
        require(recovery or not self.cancelled.is_set(), "interrupted")
        self.sequence += 1
        prefix = self.private / f"command-{self.sequence:03d}"
        process = subprocess.Popen([str(a) for a in args], cwd=self.cwd, env=env or self.env,
                                   stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        Path(str(prefix) + ".process.json").write_bytes(canonical({
            "pid": process.pid, "process_group": process.pid, "parent_pid": os.getpid(), "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "command": [str(a) for a in args], "task": "windows-onboarding-baseline"}))
        errors, outputs = [], {}
        readers_done = threading.Event()
        tick = threading.Event()

        def leader_exited():
            return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None

        def wait_owned(timeout):
            deadline = time.monotonic() + timeout
            while not leader_exited():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                tick.wait(min(0.05, remaining))
            return True

        def consume(name, pipe, maximum):
            content, pending = bytearray(), b""
            try:
                with Path(str(prefix) + "." + name).open("xb") as log:
                    while chunk := os.read(pipe.fileno(), 65536):
                        available = max(0, maximum - len(content))
                        log.write(chunk[:available])
                        content.extend(chunk[:available])
                        if len(chunk) > available:
                            if not errors:
                                errors.append(ProofError("command-output-limit"))
                        if marker and name == "stderr" and not errors:
                            pending += chunk
                            while b"\n" in pending:
                                line, pending = pending.split(b"\n", 1)
                                self.marker(line.rstrip(b"\r"))
                    if marker and name == "stderr" and pending and not errors:
                        self.marker(pending)
            except Exception as error:
                errors.append(error)
            finally:
                outputs[name] = bytes(content)
                pipe.close()
                if len(outputs) == 2:
                    readers_done.set()

        threads = [threading.Thread(target=consume, args=(name, pipe, maximum), daemon=True)
                   for name, pipe, maximum in (("stdout", process.stdout, limit), ("stderr", process.stderr, 64 << 10))]
        for thread in threads:
            thread.start()
        if stdin is not None:
            try:
                process.stdin.write(stdin)
                process.stdin.close()
            except BrokenPipeError:
                pass
        deadline = time.monotonic() + timeout
        failure = None
        while not leader_exited():
            if errors or time.monotonic() >= deadline or (self.cancelled.is_set() and not recovery):
                failure = errors[0] if errors else ProofError("interrupted" if self.cancelled.is_set() else "command-timeout")
                try:
                    os.kill(process.pid, signal.SIGINT)
                except OSError:
                    failure = ProofError("command-cleanup-unknown")
                    break
                # Run may settle twice and recover status, each with a 30-second deadline.
                wait_owned(95 if marker else 65 if recovery else 5)
                break
            tick.wait(0.05)
        if not readers_done.wait(2):
            failure = failure or ProofError("command-pipe-timeout")
        # WNOWAIT retains the task-owned group leader identity until all group signals finish.
        try:
            for signum in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(process.pid, signum)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    observation = subprocess.run(["/bin/ps", "-axo", "pid=,pgid=,stat="],
                                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                                 timeout=5, check=True)
                    require(len(observation.stdout) <= 1 << 20, "command-cleanup-unknown")
                    members = []
                    for line in observation.stdout.splitlines():
                        fields = line.split()
                        require(len(fields) == 3 and fields[0].isdigit() and fields[1].isdigit(),
                                "command-cleanup-unknown")
                        if int(fields[1]) == process.pid:
                            members.append((int(fields[0]), fields[2]))
                    require(any(pid == process.pid and state.startswith(b"Z") for pid, state in members)
                            and all(state.startswith(b"Z") for _, state in members), "command-cleanup-unknown")
                if signum == signal.SIGTERM:
                    wait_owned(5)
                    readers_done.wait(2)
            process.wait(timeout=5)
        except (OSError, subprocess.SubprocessError, ProofError) as error:
            self.group_cleanup_known = False
            if leader_exited():
                process.wait(timeout=5)
            raise ProofError("command-cleanup-unknown") from error
        for thread in threads:
            thread.join(timeout=2)
        if any(thread.is_alive() for thread in threads):
            self.group_cleanup_known = False
            raise ProofError("command-cleanup-unknown")
        if failure or errors:
            raise failure or errors[0]
        if expected_error is not None:
            require(process.returncode != 0 and expected_error.encode() in outputs["stderr"],
                    "target-mismatch-not-rejected")
        else:
            require(process.returncode == 0, "command-failed")
        return outputs["stdout"]

    def json(self, args, **kwargs):
        return document(self.run(args, **kwargs))


def configure_ssh(commands, config):
    if config is None:
        return
    require(os.name != "nt" and config.is_absolute() and config.is_file() and not config.is_symlink(),
            "ssh-config-invalid")
    source = read_regular(config.parent, config.name, 64 << 10)
    snapshot = commands.private / "ssh-config"
    snapshot.write_bytes(source)
    config = snapshot
    shim_root = commands.private / "ssh-bin"
    shim_root.mkdir(mode=0o700)
    for name in ("ssh", "scp"):
        executable = shutil.which(name, path=commands.env.get("PATH"))
        require(executable is not None and Path(executable).is_absolute(), "ssh-unavailable")
        shim = shim_root / name
        shim.write_text("#!/bin/sh\nexec " + shlex.quote(executable) + " -F " + shlex.quote(str(config))
                        + " -o BatchMode=yes -o StrictHostKeyChecking=yes -o ForwardAgent=no"
                        + " -o ClearAllForwardings=yes \"$@\"\n", encoding="utf-8")
        shim.chmod(0o700)
    commands.env["PATH"] = str(shim_root) + os.pathsep + commands.env.get("PATH", "")


def prepare_hosted_credentials(env):
    for key in ("OPERATOR_CONFIG", "SSH_KEY", "KNOWN_HOSTS", "SSH_HOSTNAME", "TS_CLIENT_ID", "TS_CLIENT_SECRET"):
        require(bool(env.get(key)), "hosted-credential-missing")
    config = document(env["OPERATOR_CONFIG"])
    require(config.get("fixture") == {"id": "windows-onboarding-prepared-v1", "kind": "dedicated", "state": "prepared"},
            "fixture-not-prepared")
    auth = config.get("authorization")
    require(isinstance(auth, dict) and auth.get("candidate_sha") == "protected-environment-approval"
            and matches(SHA, env.get("CANDIDATE_SHA")), "hosted-authorization-invalid")
    auth["candidate_sha"] = env["CANDIDATE_SHA"]
    target = windows_target(config.get("target"))
    alias, user, host = target["ssh_alias"], target["ssh_user"], env["SSH_HOSTNAME"]
    require(matches(r"[A-Za-z0-9_.:-]+", host) and matches(r"[A-Za-z0-9_.@\\-]+", user), "ssh-config-invalid")
    root = Path(env["RUNNER_TEMP"]) / "onboarding-credentials"
    require(root.is_absolute(), "ssh-config-invalid")
    root.mkdir(mode=0o700)
    (root / "key").write_text(env["SSH_KEY"])
    (root / "known_hosts").write_text(env["KNOWN_HOSTS"])
    ssh = root / "config"
    ssh.write_text(f'Host {alias}\n  HostName {host}\n  User "{user.replace(chr(92), chr(92)*2)}"\n'
                   f'  IdentityFile "{root}/key"\n  UserKnownHostsFile "{root}/known_hosts"\n'
                   '  IdentitiesOnly yes\n  BatchMode yes\n  StrictHostKeyChecking yes\n'
                   '  ForwardAgent no\n  ClearAllForwardings yes\n')
    config["ssh_config"] = str(ssh)
    (root / "operator.json").write_bytes(canonical(config))


def verify_catalog(commands, client, original):
    source = commands.private / "import-source.json"
    raw = canonical(original)
    source.write_bytes(raw)
    imported = commands.json([client, "targets", "import", PROOF_TARGET, "--file", source, "--json"])
    require(imported == {"schema_version": 1, "name": PROOF_TARGET, "platform": "windows", "status": "imported"},
            "target-import-mismatch")
    require(source.read_bytes() == raw, "target-source-rewritten")
    source.write_bytes(b"source changed after import\n")
    shown = commands.json([client, "targets", "show", PROOF_TARGET, "--json"])
    require(shown == {"schema_version": 1, "name": PROOF_TARGET, "platform": "windows",
                      "target": target_document(original)}, "target-copy-migration-mismatch")
    listed = commands.json([client, "targets", "list", "--json"])
    require(listed == {"schema_version": 1, "targets": [{"name": PROOF_TARGET, "platform": "windows"}]},
            "target-list-mismatch")


def verify_target_mismatch(commands, client):
    guard = commands.private / "transport-tripwire"
    guard.mkdir(mode=0o700)
    attempts = guard / "attempts"
    attempts.write_bytes(b"")
    for name in ("ssh", "scp"):
        shim = guard / name
        shim.write_text("#!/bin/sh\nprintf '%s\\n' " + shlex.quote(name) + " >> "
                        + shlex.quote(str(attempts)) + "\nexit 97\n")
        shim.chmod(0o700)
    env = dict(commands.env, PATH=str(guard) + os.pathsep + commands.env.get("PATH", ""))
    failures = []
    for operation in ("status", "stop"):
        try:
            commands.run([client, operation, "--target-name", PROOF_TARGET, "--run", commands.run_id,
                          "--timeout", "10s", "--json"], timeout=30, env=env,
                         expected_error="target does not match original Run")
        except Exception as error:
            failures.append(error)
    require(attempts.read_bytes() == b"", "target-mismatch-attempted-transport")
    if failures:
        raise failures[0]


def inspect_host(commands, target):
    encoded = base64.b64encode(canonical(target)).decode("ascii")
    script = r"""$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$config = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CONFIG__')) | ConvertFrom-Json
function Sid([string]$name) { ([Security.Principal.NTAccount]::new($name)).Translate([Security.Principal.SecurityIdentifier]).Value }
$os = Get-CimInstance Win32_OperatingSystem
$console = (Get-CimInstance Win32_ComputerSystem).UserName
$consoleSid = if ($console) { Sid $console } else { $null }
$blender = Get-Item -LiteralPath $config.blender_executable
$version = $blender.VersionInfo.ProductVersion
$hostHash = if (Test-Path -LiteralPath $config.host_executable) { (Get-FileHash -LiteralPath $config.host_executable -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
[ordered]@{schema_version=1; hostname=[Environment]::MachineName; windows_build=[string]$os.BuildNumber; blender_version=[string]$version; controller_sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; console_sid=$consoleSid; configured_ssh_sid=(Sid $config.ssh_user); configured_interactive_sid=(Sid $config.interactive_user); daemon_sha256=(Get-FileHash -LiteralPath $config.session_broker_executable -Algorithm SHA256).Hash.ToLowerInvariant(); host_sha256=$hostHash; blender_process_count=@(Get-CimInstance Win32_Process -Filter "Name = 'blender.exe'").Count; host_lock_present=[bool](Test-Path -LiteralPath ([IO.Path]::Combine($config.work_root,'host-lock.json')))} | ConvertTo-Json -Compress
""".replace("__CONFIG__", encoded)
    command = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return commands.json(["ssh", "-o", "RequestTTY=no", "-o", "RemoteCommand=none",
                          "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                          "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes", "--", target["ssh_alias"],
                          "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", command], timeout=120)


def write_outcome(public, report):
    temporary = public / "outcome.tmp"
    temporary.write_bytes(canonical(report) + b"\n")
    temporary.replace(public / "outcome.json")


def baseline(request, commands_factory=Commands):
    request.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    private, public = request.output / "private", request.output / "public"
    private.mkdir(mode=0o700)
    public.mkdir(mode=0o700)
    named = request.proof == "named-target"
    required = REQUIRED + NAMED_REQUIRED if named else REQUIRED
    report = {"schema_version": 1, "proof": "windows-onboarding-" + ("named-target" if named else "baseline"),
              "candidate_sha": request.candidate_sha if matches(SHA, request.candidate_sha) else None,
              "driver_sha": request.driver_sha if matches(SHA, request.driver_sha) else None,
              "execution": request.execution, "status": "fail", "run": None, "cleanup": None,
              "outcomes": {name: {"status": "not-run", "code": "not-run"} for name in required},
              "not_exercised": ["pairing", "fixture-reset", "kept-session-stop"], "artifacts": []}
    commands = commands_factory(private, request.candidate_checkout)
    commands.env["BLENDER_BOX_CONFIG_DIR"] = str((private / "config").absolute())
    def publish_run_id(run_id):
        report["run"] = {"run_id": run_id}
        write_outcome(public, report)
    commands.on_run_id = publish_run_id
    current, run, target_path, client = "preparation", None, private / "target.json", private / "blender-box"
    selector = ["--target", target_path]
    catalog_attempted, replacement_attempted = False, False
    old_signals = {}
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGINT, signal.SIGTERM):
            old_signals[sig] = signal.signal(sig, lambda *_: commands.cancelled.set())
    try:
        require(matches(SHA, request.candidate_sha) and request.execution in ("local", "hosted")
                and request.proof in ("baseline", "named-target"), "candidate-invalid")
        if request.execution == "hosted":
            require(matches(SHA, request.driver_sha) and os.environ.get("GITHUB_RUN_ATTEMPT") == "1", "hosted-authorization-invalid")
            raise ProofError("hosted-recovery-retention-unavailable")
        operator = Operator.load(request.operator_config, request.candidate_sha)
        require(commands.run(["git", "rev-parse", "HEAD"], timeout=30).decode().strip() == request.candidate_sha,
                "candidate-mismatch")
        require(not commands.run(["git", "status", "--porcelain", "--untracked-files=normal"], timeout=30).strip(),
                "candidate-dirty")
        target_path.write_bytes(canonical(operator.target))
        configure_ssh(commands, operator.ssh_config)
        observed = inspect_host(commands, operator.windows)
        verify_expected_host(operator.expected, observed)
        commands.run(["go", "build", "-trimpath", "-o", client, "./cmd/blender-box"], timeout=300)
        if named:
            current = "target-catalog"
            catalog_attempted = True
            verify_catalog(commands, client, operator.windows)
            selector = ["--target-name", PROOF_TARGET]
            report["outcomes"][current] = {"status": "pass", "code": "import-copy-migration-verified"}
            current = "preparation"
        host = private / "blender-box.exe"
        host_env = dict(commands.env, GOOS="windows", GOARCH="amd64", CGO_ENABLED="0")
        commands.run(["go", "build", "-trimpath", "-o", host, "./cmd/blender-box"], timeout=300, env=host_env)
        host_bytes = read_regular(private, host.name, 128 << 20)
        host_hash, host_size = digest(host_bytes), len(host_bytes)
        setup_args = [client, "windows", "setup", *selector, "--host-binary", host, "--json"]
        plan = commands.json(setup_args)
        require(plan.get("status") == "plan" and plan.get("applied") is False
                and plan.get("host_sha256") == host_hash and type(plan.get("host_size")) is int
                and plan["host_size"] == host_size, "setup-plan-mismatch")
        if observed["host_sha256"] != host_hash:
            verify_setup_authorization(operator, request.candidate_sha, observed["host_sha256"])
            applied = commands.json(setup_args + ["--apply"], timeout=300)
            require(applied.get("status") == "applied" and applied.get("applied") is True
                    and applied.get("host_sha256") == host_hash and type(applied.get("host_size")) is int
                    and applied["host_size"] == host_size, "setup-apply-mismatch")
        installed = inspect_host(commands, operator.windows)
        verify_expected_host(operator.expected, installed)
        require(installed["host_sha256"] == host_hash, "installed-host-mismatch")
        report["binaries"] = {"host_sha256": host_hash, "host_size": host_size,
                              "client_sha256": digest(read_regular(private, client.name, 128 << 20))}
        report["blender_version"] = operator.expected["blender_version"]
        report["outcomes"][current] = {"status": "pass", "code": "prepared-fixture-verified"}
        current = "readiness"
        verify_readiness(commands.json([client, "windows", "check", *selector, "--json"]))
        report["daemon_capabilities"] = list(CAPABILITIES)
        report["outcomes"][current] = {"status": "pass", "code": "windows-check-passed"}
        current = "scenario"
        run = commands.json([client, "run", *selector, "--payload", FIXTURE / "payload.json",
                             "--timeout", "20m", "--json"], timeout=1320, marker=True)
        fence = Fence.parse(run)
        require(commands.run_id == fence.run_id, "run-marker-mismatch")
        report["run"] = {key: getattr(fence, key) for key in ("run_id", "request_id", "request_hash", "session_id")}
        require(run.get("state") == "complete" and not run.get("error"), "scenario-run-failed")
        verify_cleanup(run)
        current = "evidence"
        bundle = request.candidate_checkout / "artifacts/blender-box" / fence.run_id
        artifacts = verify_bundle(bundle, run)
        verify_baseline(bundle, artifacts)
        report["outcomes"]["scenario"] = {"status": "pass", "code": "baseline-cube-passed"}
        report["outcomes"][current] = {"status": "pass", "code": "bundle-verified"}
        report["artifacts"] = [dataclasses.asdict(a) for a in artifacts]
        if operator.publish_viewport:
            viewport = read_regular(bundle, "screenshots/viewport.png")
            require(digest(viewport) == next(a.local_sha256 for a in artifacts if a.type == "viewport"),
                    "evidence-changed")
            (public / "viewport.png").write_bytes(viewport)
        if named:
            current = "target-binding"
            before = commands.json([client, "status", *selector, "--run", commands.run_id,
                                    "--timeout", "60s", "--json"], timeout=100)
            require(Fence.parse(before) == fence and before.get("state") == "complete"
                    and before.get("evidence") == run.get("evidence") and not before.get("error"),
                    "recovery-record-changed")
            verify_cleanup(before)
            sentinel = dict(operator.windows, ssh_alias="onboarding-mismatch"
                            if operator.windows["ssh_alias"] != "onboarding-mismatch" else "onboarding-mismatch-other")
            sentinel_path = private / "sentinel.json"
            sentinel_path.write_bytes(canonical(target_document(sentinel)))
            replacement_attempted = True
            replaced = commands.json([client, "targets", "import", PROOF_TARGET, "--file", sentinel_path,
                                      "--replace", "--json"])
            require(replaced == {"schema_version": 1, "name": PROOF_TARGET, "platform": "windows", "status": "imported"},
                    "target-replace-mismatch")
            shown = commands.json([client, "targets", "show", PROOF_TARGET, "--json"])
            require(shown == {"schema_version": 1, "name": PROOF_TARGET, "platform": "windows",
                              "target": target_document(sentinel)}, "target-replace-mismatch")
            verify_target_mismatch(commands, client)
            report["outcomes"][current] = {"status": "pass", "code": "status-stop-mismatch-offline"}
        current = "recovery"
    except Exception as error:
        code = error.code if isinstance(error, ProofError) else "proof-internal-error"
        report["outcomes"][current] = {"status": "fail", "code": code}
    finally:
        if named and catalog_attempted and commands.group_cleanup_known:
            try:
                if replacement_attempted:
                    restored = commands.json([client, "targets", "import", PROOF_TARGET, "--file", target_path,
                                              "--replace", "--json"], recovery=True)
                    require(restored == {"schema_version": 1, "name": PROOF_TARGET, "platform": "windows", "status": "imported"},
                            "target-restore-failed")
                shown = commands.json([client, "targets", "show", PROOF_TARGET, "--json"], recovery=True)
                require(shown == {"schema_version": 1, "name": PROOF_TARGET, "platform": "windows",
                                  "target": target_document(operator.windows)}, "target-restore-failed")
                selector = ["--target-name", PROOF_TARGET]
                report["outcomes"]["target-restoration"] = {"status": "pass", "code": "original-target-restored"}
            except Exception:
                selector = ["--target", target_path]
                report["outcomes"]["target-restoration"] = {"status": "fail", "code": "target-restore-failed"}
        if commands.run_id and commands.group_cleanup_known:
            recovered = []
            for operation in ("status", "stop", "status"):
                try:
                    record = commands.json([client, operation, *selector, "--run", commands.run_id,
                                            "--timeout", "60s", "--json"], timeout=100, recovery=True)
                    require(Fence.parse(record, require_session=False).run_id == commands.run_id, "recovery-identity-changed")
                    recovered.append(record)
                except Exception:
                    recovered.append(None)
            try:
                require(all(record is not None for record in recovered), "recovery-unavailable")
                cleanup = verify_recovery(run or recovered[0], *recovered)
                if run is not None and run.get("state") == "complete":
                    retained = request.candidate_checkout / "artifacts/blender-box" / commands.run_id
                    verify_baseline(retained, verify_bundle(retained, run))
                report["cleanup"] = cleanup
                report["outcomes"]["recovery"] = {"status": "pass", "code": "reconnect-exact-identity"}
                report["outcomes"]["cleanup"] = {"status": "pass", "code": "settled-and-reobserved"}
            except Exception as error:
                code = error.code if isinstance(error, ProofError) else "recovery-unavailable"
                report["outcomes"]["recovery"] = {"status": "fail", "code": code}
                report["outcomes"]["cleanup"] = {"status": "fail", "code": "cleanup-unknown"}
        if not commands.group_cleanup_known:
            report["outcomes"]["recovery"] = {"status": "fail", "code": "command-cleanup-unknown"}
            report["outcomes"]["cleanup"] = {"status": "fail", "code": "cleanup-unknown"}
        if named and catalog_attempted and commands.group_cleanup_known and (not commands.run_id or report["cleanup"]):
            try:
                forgotten = commands.json([client, "targets", "forget", PROOF_TARGET, "--json"], recovery=True)
                require(forgotten.get("status") == "forgotten" and forgotten.get("name") == PROOF_TARGET,
                        "target-forget-failed")
                require(commands.json([client, "targets", "list", "--json"], recovery=True)
                        == {"schema_version": 1, "targets": []}, "target-forget-failed")
                report["outcomes"]["target-forget"] = {"status": "pass", "code": "proof-profile-forgotten"}
            except Exception:
                report["outcomes"]["target-forget"] = {"status": "fail", "code": "target-forget-failed"}
        for sig, previous in old_signals.items():
            signal.signal(sig, previous)
        report["status"] = "pass" if all(report["outcomes"][name]["status"] == "pass" for name in required) else "fail"
        write_outcome(public, report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["baseline", "named-target"])
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--candidate-checkout", type=Path, required=True)
    parser.add_argument("--operator-config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execution", choices=["local", "hosted"], default="local")
    parser.add_argument("--driver-sha")
    args = parser.parse_args(argv)
    request = ProofRequest(args.candidate, args.candidate_checkout.resolve(), args.operator_config.resolve(),
                           args.output.absolute(), args.execution, args.driver_sha, args.command)
    try:
        report = baseline(request)
    except (OSError, ProofError):
        print("Proof output must be a fresh directory with an existing parent.")
        return 1
    print("Windows onboarding " + args.command + " " + report["status"] + ".")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
