#!/usr/bin/env python3
"""Run or recover one hosted baseline proof through the fixed SSH controller."""

import argparse
import base64
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import threading
import time

import onboarding_proof as proof
import proof_controller as controller


MAX_REQUEST = 4096
MAX_OUTCOME = 1 << 20
MAX_VIEWPORT = 16 << 20
MAX_RESPONSE = 24 << 20
MAX_STDERR = 64 << 10
MAX_EXCHANGES = 16
RECOVERY_EXCHANGES = 5
CALL_SECONDS = 60.0
STATUS_INTERVAL = 1.0
SSH = "/usr/bin/ssh"
PHASES = {"accepted", "starting", "running", "recovering", "unresolved", "settled"}


class DispatchError(Exception):
    def __init__(self, code, *, cleanup_proven=False):
        self.code = code
        self.cleanup_proven = cleanup_proven
        super().__init__(code)


def require(condition, code):
    if not condition:
        raise DispatchError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def document(raw, limit, code="invalid-response"):
    require(isinstance(raw, bytes) and 0 < len(raw) <= limit, code)

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, code)
            result[key] = value
        return result

    try:
        text = raw.decode("utf-8")
        decoder = json.JSONDecoder(object_pairs_hook=pairs,
                                   parse_constant=lambda _: (_ for _ in ()).throw(DispatchError(code)))
        value, end = decoder.raw_decode(text)
        require(text[end:].strip() == "", code)
        require(isinstance(value, dict), code)
        return value
    except (UnicodeError, ValueError, RecursionError) as error:
        raise DispatchError(code) from error


def safe_path(path, code, *, fresh=False):
    require(isinstance(path, Path) and path.is_absolute(), code)
    found_private_parent = False
    for part in (path, *path.parents):
        require(not part.is_symlink(), code)
        if part.exists():
            info = part.stat()
            if stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0:
                found_private_parent = True
    require(found_private_parent, code)
    if fresh:
        require(not path.exists() and path.parent.is_dir(), code)


def fresh_directory(path, code):
    safe_path(path, code, fresh=True)
    path.mkdir(mode=0o700)
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0, code)
    sync_directory(path.parent)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_file(path, raw, *, allow_empty=False):
    require(isinstance(raw, bytes) and (allow_empty or raw), "private-publication-invalid")
    safe_path(path, "unsafe-private-path")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    sync_directory(path.parent)


def validate_private_file(path):
    safe_path(path, "unsafe-ssh-config")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and info.st_mode & 0o077 == 0 and info.st_nlink == 1, "unsafe-ssh-config")
    finally:
        os.close(fd)


@dataclass(frozen=True)
class Identity:
    execution_id: str
    candidate_sha: str
    policy_driver_sha: str
    request_sha256: str
    start: bytes | None

    def metadata(self):
        return {"schema_version": 1, "kind": "baseline-recovery",
                "execution_id": self.execution_id, "request_sha256": self.request_sha256,
                "candidate_sha": self.candidate_sha, "policy_driver_sha": self.policy_driver_sha}


@dataclass(frozen=True)
class Receipt:
    execution_id: str
    phase: str
    closed: bool
    attempt: int
    local_termination: str
    windows_cleanup: str
    proof_result: str
    value: dict

    @classmethod
    def parse(cls, value, execution_id):
        fields = {"schema_version", *controller.PUBLIC_FIELDS}
        require(isinstance(value, dict) and set(value) == fields
                and type(value["schema_version"]) is int and value["schema_version"] == 1
                and isinstance(value["execution_id"], str)
                and isinstance(value["phase"], str) and value["phase"] in PHASES
                and type(value["closed"]) is bool
                and type(value["attempt"]) is int and 0 <= value["attempt"] <= 9999
                and value["local_termination"] in ("unknown", "proven")
                and value["windows_cleanup"] in ("unknown", "proven")
                and value["proof_result"] in ("not-run", "pass", "fail"), "invalid-receipt")
        require(value["execution_id"] == execution_id, "receipt-identity-changed")
        if value["phase"] == "settled":
            require(value["closed"] and value["attempt"] > 0
                    and value["local_termination"] == value["windows_cleanup"] == "proven"
                    and value["proof_result"] in ("pass", "fail"), "invalid-receipt")
        return cls(value["execution_id"], value["phase"], value["closed"], value["attempt"],
                   value["local_termination"], value["windows_cleanup"], value["proof_result"], value)


@dataclass(frozen=True)
class Exchange:
    returncode: int | None
    stdout: bytes
    stderr: bytes
    failure: str | None = None


@dataclass(frozen=True)
class ParsedExchange:
    receipt: Receipt | None = None
    error: str | None = None
    collect: dict | None = None
    ambiguous: bool = False
    failure: str | None = None


class Budget:
    def __init__(self, seconds, clock=time.monotonic):
        require(isinstance(seconds, (int, float)) and not isinstance(seconds, bool)
                and math.isfinite(seconds) and seconds > 0, "invalid-budget")
        self.clock = clock
        self.deadline = clock() + float(seconds)
        self.recovery_reserve = min(CALL_SECONDS, float(seconds) / 4.0)

    def remaining(self):
        return max(0.0, self.deadline - self.clock())

    def allowance(self, cleanup=False):
        remaining = self.remaining()
        if not cleanup:
            remaining = max(0.0, remaining - self.recovery_reserve)
        return min(CALL_SECONDS, remaining)

    def start_allowance(self):
        return min(CALL_SECONDS, max(0.0, self.remaining() - 2 * self.recovery_reserve))

    def reconciliation_allowance(self):
        return min(CALL_SECONDS, max(0.0, self.remaining() - self.recovery_reserve))

    def cleanup_allowance(self):
        return min(CALL_SECONDS, self.remaining() / 2.0)

    def observation_remaining(self):
        return max(0.0, self.remaining() - self.recovery_reserve)


class SSHTransport:
    def __init__(self, ssh_config, target, process_factory=subprocess.Popen, clock=time.monotonic):
        self.ssh_config = Path(ssh_config)
        self.target = target
        self.process_factory = process_factory
        self.clock = clock
        validate_private_file(self.ssh_config)
        require(proof.matches(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", target), "invalid-controller")
        self.argv = [SSH, "-F", str(self.ssh_config), "-T",
                     "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                     "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
                     "-o", "PreferredAuthentications=publickey", "-o", "PubkeyAuthentication=yes",
                     "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
                     "-o", "HostbasedAuthentication=no", "-o", "GSSAPIAuthentication=no",
                     "-o", "NumberOfPasswordPrompts=0", "-o", "ConnectionAttempts=1",
                     "-o", "UpdateHostKeys=no", "-o", "ForwardAgent=no",
                     "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no",
                     "-o", "ControlMaster=no", "-o", "ControlPath=none",
                     "-o", "ControlPersist=no", "-o", "ProxyCommand=none",
                     "-o", "ProxyJump=none", "-o", "KnownHostsCommand=none",
                     "-o", "CanonicalizeHostname=no", "-o", "RemoteCommand=none",
                     "-o", "RequestTTY=no", target]

    def exchange(self, operation, request, timeout, cancel, record_process):
        require(os.name == "posix" and os.uname().sysname in ("Darwin", "Linux")
                and all(hasattr(os, name) for name in ("waitid", "WNOWAIT", "P_PID")),
                "controller-platform-unsupported")
        require(0 < len(request) <= MAX_REQUEST and timeout > 0, "transport-budget-exhausted")
        stdout_limit = MAX_RESPONSE if operation == "collect" else MAX_OUTCOME
        started = self.clock()
        final_deadline = started + timeout
        operation_deadline = final_deadline - min(1.0, timeout / 4.0)
        process = self.process_factory(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, start_new_session=True, close_fds=True, bufsize=0)
        out, err = bytearray(), bytearray()
        overflow = threading.Event()
        reader_errors = []
        readers = []
        process_group = process.pid
        failure = None
        pending_error = None

        def drain(stream, target, limit):
            try:
                while True:
                    chunk = stream.read(64 << 10)
                    if not chunk:
                        return
                    target.extend(chunk[:limit + 1 - len(target)])
                    if len(target) > limit:
                        overflow.set()
                        return
            except (OSError, ValueError) as error:
                reader_errors.append(error)

        cleanup_errors = []
        try:
            try:
                process_group = os.getpgid(process.pid)
                require(process_group == process.pid, "transport-process-identity-changed")
                record_process({"schema_version": 1, "operation": operation, "pid": process.pid,
                                "process_group": process_group, "parent_pid": os.getpid(), "argv": self.argv,
                                "argv_sha256": digest(canonical(self.argv)),
                                "started_monotonic_ns": int(started * 1_000_000_000)})
                readers = [threading.Thread(target=drain, args=(process.stdout, out, stdout_limit), daemon=True),
                           threading.Thread(target=drain, args=(process.stderr, err, MAX_STDERR), daemon=True)]
                for reader in readers:
                    reader.start()
                try:
                    process.stdin.write(request)
                    process.stdin.close()
                except (BrokenPipeError, OSError):
                    failure = "transport-io"
                while failure is None:
                    if os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
                        break
                    if overflow.is_set():
                        failure = "transport-output-overflow"
                        break
                    if cancel():
                        failure = "transport-cancelled"
                        break
                    if self.clock() >= operation_deadline:
                        failure = "transport-timeout"
                        break
                    time.sleep(min(0.01, max(0.001, operation_deadline - self.clock())))
            except KeyboardInterrupt:
                failure = "transport-interrupted"
            except BaseException as error:
                pending_error = error
        finally:
            if process.returncode is None:
                try:
                    self._terminate_exact(process, process_group, final_deadline)
                except BaseException as error:
                    cleanup_errors.append(error)
            try:
                process.stdin.close()
            except BaseException as error:
                cleanup_errors.append(error)
            for reader in readers:
                try:
                    reader.join(timeout=max(0.0, final_deadline - self.clock()))
                except BaseException as error:
                    cleanup_errors.append(error)
            for stream in (process.stdout, process.stderr):
                try:
                    stream.close()
                except BaseException as error:
                    cleanup_errors.append(error)
            if any(reader.is_alive() for reader in readers) or reader_errors:
                cleanup_errors.append(DispatchError("transport-cleanup-unproven"))
        if cleanup_errors:
            return Exchange(process.returncode, bytes(out), bytes(err), "transport-cleanup-unproven")
        if isinstance(pending_error, DispatchError):
            raise DispatchError(pending_error.code, cleanup_proven=True) from pending_error
        if pending_error is not None:
            raise pending_error
        if overflow.is_set():
            failure = "transport-output-overflow"
        return Exchange(process.returncode, bytes(out), bytes(err), failure)

    def _terminate_exact(self, process, process_group, deadline):
        require(process.returncode is None and process_group == process.pid,
                "transport-process-identity-changed")
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass
        while not self._group_quiescent(process_group, deadline):
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise DispatchError("transport-cleanup-unproven")
            time.sleep(min(0.01, remaining))
        try:
            process.wait(timeout=max(0.001, deadline - self.clock()))
        except subprocess.TimeoutExpired as error:
            raise DispatchError("transport-cleanup-unproven") from error

    def _group_quiescent(self, process_group, deadline):
        try:
            observation = subprocess.run(["/bin/ps", "-axo", "pid=,pgid=,stat="],
                                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                         timeout=max(0.001, deadline - self.clock()), check=True)
        except (OSError, subprocess.SubprocessError) as error:
            raise DispatchError("transport-cleanup-unproven") from error
        require(len(observation.stdout) <= 1 << 20, "transport-cleanup-unproven")
        members = []
        for line in observation.stdout.splitlines():
            fields = line.split()
            require(len(fields) == 3 and fields[0].isdigit() and fields[1].isdigit(),
                    "transport-cleanup-unproven")
            if int(fields[1]) == process_group:
                members.append((int(fields[0]), fields[2]))
        leaders = [state for pid, state in members if pid == process_group]
        require(len(leaders) == 1, "transport-cleanup-unproven")
        return all(state.startswith(b"Z") for _, state in members)


def parse_exchange(exchange, operation, execution_id):
    if exchange.failure is not None or exchange.returncode is None or exchange.returncode == 255:
        return ParsedExchange(ambiguous=True, failure=exchange.failure or "transport-failure")
    limit = MAX_RESPONSE if operation == "collect" else MAX_OUTCOME
    try:
        value = document(exchange.stdout, limit)
        if operation == "collect" and exchange.returncode == 0:
            return ParsedExchange(collect=value)
        if exchange.returncode == 0:
            return ParsedExchange(receipt=Receipt.parse(value, execution_id))
        require(set(value) == {"schema_version", "status", "code"}
                and type(value["schema_version"]) is int and value["schema_version"] == 1
                and value["status"] == "error"
                and proof.matches(r"[a-z][a-z0-9-]{0,127}", value["code"]),
                "invalid-error-response")
        return ParsedExchange(error=value["code"])
    except DispatchError:
        if operation == "start":
            return ParsedExchange(ambiguous=True)
        raise


def validate_cleanup(value):
    require(isinstance(value, dict) and set(value) == set(proof.CLEANUP)
            and all(value[name] is True for name in proof.CLEANUP), "invalid-outcome")


def validate_outcome(raw, identity, settled, viewport):
    value = document(raw, MAX_OUTCOME, "invalid-outcome")
    require(set(value) == {"schema_version", "kind", "request", "baseline", "settlement"}
            and type(value["schema_version"]) is int and value["schema_version"] == 2
            and value["kind"] == "baseline-collect", "invalid-outcome")
    request = value["request"]
    require(isinstance(request, dict)
            and set(request) == {"execution_id", "request_sha256", "candidate_sha", "driver_sha", "variant"}
            and request == {"execution_id": identity.execution_id,
                            "request_sha256": identity.request_sha256,
                            "candidate_sha": identity.candidate_sha,
                            "driver_sha": identity.policy_driver_sha,
                            "variant": "baseline"}, "outcome-identity-changed")
    baseline = value["baseline"]
    require(isinstance(baseline, dict) and set(baseline) == {"record_sha256", "report"}
            and proof.matches(proof.HASH, baseline["record_sha256"]), "invalid-outcome")
    report = baseline["report"]
    binaries = report.get("binaries") if isinstance(report, dict) else None
    expected_client = binaries.get("client_sha256", "0" * 64) if isinstance(binaries, dict) else "0" * 64
    request_model = controller.ProofExecutionRequest(1, "BramVR/blender-box", identity.candidate_sha,
                                                     identity.policy_driver_sha, "baseline",
                                                     identity.execution_id, "2099-01-01T00:00:00Z")
    try:
        controller.baseline_report(report, request_model, expected_client)
    except (controller.ControllerError, proof.ProofError, AttributeError, TypeError, KeyError) as error:
        raise DispatchError("invalid-outcome") from error
    settlement = value["settlement"]
    require(isinstance(settlement, dict) and set(settlement) == {"receipt", "recovery"}, "invalid-outcome")
    outcome_receipt = Receipt.parse(settlement["receipt"], identity.execution_id)
    require(outcome_receipt.value == settled.value and report["status"] == settled.proof_result,
            "outcome-settlement-changed")
    recovery = settlement["recovery"]
    if recovery is not None:
        require(isinstance(recovery, dict) and set(recovery) == {"attempt", "record_sha256", "cleanup"}
                and type(recovery["attempt"]) is int and 1 < recovery["attempt"] <= 9999
                and proof.matches(proof.HASH, recovery["record_sha256"]),
                "invalid-outcome")
        validate_cleanup(recovery["cleanup"])
        require(recovery["attempt"] == settled.attempt, "outcome-settlement-changed")
    require((recovery is None) == (settled.attempt == 1), "outcome-settlement-changed")
    if recovery is None:
        validate_cleanup(report["cleanup"])
    viewport_artifact = next((item for item in report["artifacts"] if item["type"] == "viewport"), None)
    if viewport is not None:
        require(viewport_artifact is not None and len(viewport) == viewport_artifact["size"]
                and digest(viewport) == viewport_artifact["local_sha256"], "invalid-viewport")
        try:
            proof.verify_png(viewport, viewport_artifact["width"], viewport_artifact["height"])
        except proof.ProofError as error:
            raise DispatchError("invalid-viewport") from error
    return value


def validate_collect(value, identity, settled):
    require(isinstance(value, dict) and set(value) == {"schema_version", "operation", "execution_id", "files"}
            and type(value["schema_version"]) is int and value["schema_version"] == 1
            and value["operation"] == "collect" and value["execution_id"] == identity.execution_id
            and isinstance(value["files"], list) and 1 <= len(value["files"]) <= 2, "invalid-collect")
    files = {}
    for item in value["files"]:
        require(isinstance(item, dict) and set(item) == {"name", "size", "sha256", "content_base64"}
                and item["name"] in ("outcome.json", "viewport.png") and item["name"] not in files
                and type(item["size"]) is int and item["size"] > 0
                and item["size"] <= (MAX_OUTCOME if item["name"] == "outcome.json" else MAX_VIEWPORT)
                and proof.matches(proof.HASH, item["sha256"])
                and isinstance(item["content_base64"], str)
                and len(item["content_base64"]) == 4 * ((item["size"] + 2) // 3), "invalid-collect")
        try:
            raw = base64.b64decode(item["content_base64"], validate=True)
        except (ValueError, TypeError) as error:
            raise DispatchError("invalid-collect") from error
        require(len(raw) == item["size"] and digest(raw) == item["sha256"], "invalid-collect")
        files[item["name"]] = raw
    require("outcome.json" in files, "invalid-collect")
    outcome = validate_outcome(files["outcome.json"], identity, settled, files.get("viewport.png"))
    return files, outcome


class Dispatcher:
    def __init__(self, transport, state, output, budget_seconds, *, clock=time.monotonic,
                 cancel=lambda: False, wait=time.sleep, recovery_wait=time.sleep,
                 publish_metadata=lambda _: None):
        self.transport = transport
        self.state = Path(state)
        self.output = Path(output)
        self.budget = Budget(budget_seconds, clock)
        self.cancel = cancel
        self.wait = wait
        self.recovery_wait = recovery_wait
        self.publish_metadata = publish_metadata
        self.sequence = 0

    def execute(self, identity, mode):
        require(mode in ("run", "recover"), "invalid-mode")
        require(isinstance(identity, Identity)
                and proof.matches(controller.EXECUTION_ID, identity.execution_id)
                and proof.matches(proof.SHA, identity.candidate_sha)
                and proof.matches(proof.SHA, identity.policy_driver_sha)
                and proof.matches(proof.HASH, identity.request_sha256)
                and ((mode == "run") == (identity.start is not None)), "invalid-identity")
        if identity.start is not None:
            require(isinstance(identity.start, bytes) and 0 < len(identity.start) <= MAX_REQUEST,
                    "invalid-request")
            try:
                start_command = controller.parse_command(identity.start)
            except (controller.ControllerError, proof.ProofError) as error:
                raise DispatchError("invalid-identity") from error
            require(start_command.operation == "start" and start_command.request is not None
                    and start_command.execution_id == identity.execution_id
                    and start_command.request.candidate_sha == identity.candidate_sha
                    and start_command.request.driver_sha == identity.policy_driver_sha
                    and start_command.request.digest == identity.request_sha256
                    and identity.start == canonical({"schema_version": 1, "operation": "start",
                                                     "request": asdict(start_command.request)}), "invalid-identity")
        safe_path(self.output, "unsafe-output", fresh=True)
        safe_path(self.state, "unsafe-private-path", fresh=True)
        require(self.output != self.state and self.output not in self.state.parents
                and self.state not in self.output.parents, "unsafe-output")
        fresh_directory(self.state, "unsafe-private-path")
        (self.state / "exchanges").mkdir(mode=0o700)
        sync_directory(self.state)
        write_file(self.state / "identity.json", canonical(identity.metadata() | {"mode": mode}))
        if identity.start is not None:
            write_file(self.state / "start.json", identity.start)
        metadata = canonical(identity.metadata())
        self.publish_metadata(metadata)
        require(not self.cancel(), "dispatch-cancelled")
        action = "start" if mode == "run" else "status"
        starts = 0
        accepted = False
        recovery_sent = False
        settled = None
        potential_acceptance = False
        must_reconcile_start = False
        force_cleanup = False
        last_error = "dispatch-unresolved"
        while self.sequence < MAX_EXCHANGES:
            if settled is None and self.sequence >= MAX_EXCHANGES - 1:
                last_error = "dispatch-exchanges-exhausted"
                break
            cleanup = force_cleanup or self.cancel() or self.sequence >= MAX_EXCHANGES - RECOVERY_EXCHANGES
            if not cleanup and self.budget.allowance() <= 0:
                cleanup = True
            if settled is not None:
                action = "collect"
            elif cleanup and not must_reconcile_start and not recovery_sent \
                    and (accepted or potential_acceptance or mode == "recover"):
                action = "recover"
            elif cleanup and not must_reconcile_start and recovery_sent:
                action = "status"
            if action == "start":
                require(mode == "run" and not accepted and starts < 2 and identity.start is not None,
                        "restart-forbidden")
                request = identity.start
                starts += 1
                potential_acceptance = True
            else:
                request = canonical({"schema_version": 1, "operation": action,
                                     "execution_id": identity.execution_id})
            if action == "start":
                allowance = self.budget.start_allowance()
            elif action == "status" and must_reconcile_start:
                allowance = self.budget.reconciliation_allowance()
            elif action == "recover" or (action == "status" and recovery_sent):
                allowance = self.budget.cleanup_allowance()
            else:
                allowance = self.budget.allowance(cleanup=cleanup or action in ("recover", "collect"))
            if allowance <= 0:
                last_error = "dispatch-budget-exhausted"
                break
            try:
                parsed = self._exchange(action, request, allowance, cleanup)
            except DispatchError as error:
                if settled is not None:
                    raise
                if error.code == "receipt-identity-changed":
                    raise
                if error.code == "transport-cleanup-unproven" or not error.cleanup_proven:
                    raise
                if action == "start":
                    last_error = "invalid-response"
                    must_reconcile_start = True
                    force_cleanup = True
                    action = "status"
                    continue
                if action == "status" and must_reconcile_start:
                    must_reconcile_start = False
                if accepted or potential_acceptance or mode == "recover":
                    last_error = "invalid-response"
                    if action == "recover":
                        recovery_sent = True
                    action = "recover" if not recovery_sent else "status"
                    continue
                raise
            if parsed.ambiguous:
                last_error = "transport-ambiguous"
                if action == "start":
                    must_reconcile_start = True
                    force_cleanup = parsed.failure in ("transport-cancelled", "transport-interrupted")
                    action = "status"
                elif action == "recover":
                    recovery_sent = True
                    action = "status"
                elif action == "collect":
                    break
                elif must_reconcile_start:
                    must_reconcile_start = False
                continue
            if action == "status" and must_reconcile_start:
                must_reconcile_start = False
            if parsed.error is not None:
                last_error = parsed.error
                if action == "status" and parsed.error == "execution-not-found" and mode == "run" \
                        and not accepted and starts == 1 and not cleanup:
                    potential_acceptance = False
                    action = "start"
                    continue
                if action == "collect" and parsed.error == "collect-record-missing" \
                        and settled is not None and settled.proof_result == "fail":
                    return self._summary(identity, settled, "missing")
                if action == "recover":
                    recovery_sent = True
                    action = "status"
                    continue
                elif action == "status" and (accepted or potential_acceptance or mode == "recover") \
                        and not recovery_sent:
                    action = "recover"
                    continue
                break
            if parsed.collect is not None:
                require(settled is not None, "invalid-transition")
                files, outcome = validate_collect(parsed.collect, identity, settled)
                self._publish(files)
                report_status = outcome["baseline"]["report"]["status"]
                require(report_status == settled.proof_result, "outcome-settlement-changed")
                return self._summary(identity, settled, "published")
            receipt = parsed.receipt
            require(receipt is not None, "invalid-transition")
            accepted = True
            potential_acceptance = False
            if action == "recover":
                recovery_sent = True
            if receipt.phase == "settled":
                settled = receipt
                action = "collect"
            elif receipt.phase == "unresolved" and not recovery_sent:
                action = "recover"
            elif mode == "recover" and not recovery_sent:
                action = "recover"
            else:
                action = "status"
            if action == "status" and receipt.phase not in ("unresolved", "settled"):
                if recovery_sent:
                    remaining_slots = MAX_EXCHANGES - self.sequence
                    remaining = self.budget.remaining()
                    if remaining_slots > 1 and remaining > 0:
                        self.recovery_wait(remaining / remaining_slots)
                elif not self.cancel():
                    status_slots = MAX_EXCHANGES - RECOVERY_EXCHANGES - self.sequence
                    remaining = self.budget.observation_remaining()
                    if status_slots > 0 and remaining > 0:
                        self.wait(min(remaining, max(STATUS_INTERVAL, remaining / status_slots)))
        if settled is not None:
            return self._summary(identity, settled, "unavailable", code=last_error)
        raise DispatchError(last_error)

    def _exchange(self, operation, request, allowance, cleanup):
        self.sequence += 1
        number = self.sequence
        root = self.state / "exchanges"
        write_file(root / f"request-{number:02d}.json", request)

        def record_process(value):
            write_file(root / f"process-{number:02d}.json", canonical(value))

        exchange = self.transport.exchange(operation, request, allowance,
                                           (lambda: False) if cleanup else self.cancel, record_process)
        try:
            require(isinstance(exchange, Exchange) and len(exchange.stdout) <= (MAX_RESPONSE if operation == "collect" else MAX_OUTCOME) + 1
                    and len(exchange.stderr) <= MAX_STDERR + 1, "invalid-transport-result")
            write_file(root / f"stdout-{number:02d}.bin", exchange.stdout, allow_empty=True)
            write_file(root / f"stderr-{number:02d}.bin", exchange.stderr, allow_empty=True)
            record = {"schema_version": 1, "operation": operation, "returncode": exchange.returncode,
                      "failure": exchange.failure, "stdout_size": len(exchange.stdout),
                      "stdout_sha256": digest(exchange.stdout), "stderr_size": len(exchange.stderr),
                      "stderr_sha256": digest(exchange.stderr)}
            write_file(root / f"exchange-{number:02d}.json", canonical(record))
            if exchange.failure == "transport-cleanup-unproven":
                raise DispatchError(exchange.failure)
            return parse_exchange(exchange, operation, self._identity_execution(request))
        except DispatchError as error:
            if error.code == "transport-cleanup-unproven":
                raise
            raise DispatchError(error.code, cleanup_proven=True) from error

    @staticmethod
    def _identity_execution(request):
        try:
            value = document(request, MAX_REQUEST, "invalid-request")
            return value.get("execution_id", value.get("request", {}).get("execution_id"))
        except DispatchError:
            return ""

    def _publish(self, files):
        safe_path(self.output, "unsafe-output", fresh=True)
        fresh_directory(self.output, "unsafe-output")
        if "viewport.png" in files:
            write_file(self.output / "viewport.png", files["viewport.png"])
        write_file(self.output / "outcome.json", files["outcome.json"])

    @staticmethod
    def _summary(identity, settled, collection, code=None):
        value = {"schema_version": 1, "status": "pass" if settled.proof_result == "pass" and collection == "published" else "fail",
                 "execution_id": identity.execution_id, "request_sha256": identity.request_sha256,
                 "proof_result": settled.proof_result, "cleanup": "proven", "collection": collection}
        if code is not None:
            value["code"] = code
        return value


def run_identity(args):
    require(args.github_run_attempt == "1" and proof.matches(r"[1-9][0-9]{0,19}", args.github_run_id),
            "hosted-authorization-invalid")
    execution_id = f"gha_{args.github_run_id}_1"
    request = {"schema_version": 1, "repository": "BramVR/blender-box",
               "candidate_sha": args.candidate_sha, "driver_sha": args.policy_driver_sha,
               "variant": "baseline", "execution_id": execution_id, "expires_at": args.expires_at}
    try:
        parsed = controller.ProofExecutionRequest.parse(request)
    except controller.ControllerError as error:
        raise DispatchError(error.code) from error
    start = canonical({"schema_version": 1, "operation": "start", "request": request})
    return Identity(execution_id, args.candidate_sha, args.policy_driver_sha, parsed.digest, start)


def recover_identity(args):
    return Identity(args.execution_id, args.candidate_sha, args.policy_driver_sha, args.request_sha256, None)


def emit(raw):
    sys.stdout.buffer.write(raw + b"\n")
    sys.stdout.buffer.flush()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--candidate-sha", required=True)
    common.add_argument("--policy-driver-sha", required=True)
    common.add_argument("--ssh-config", type=Path, required=True)
    common.add_argument("--controller", required=True)
    common.add_argument("--state", type=Path, required=True)
    common.add_argument("--output", type=Path, required=True)
    common.add_argument("--budget-seconds", type=float, required=True)
    run = commands.add_parser("run", parents=[common])
    run.add_argument("--github-run-id", required=True)
    run.add_argument("--github-run-attempt", required=True)
    run.add_argument("--expires-at", required=True)
    recover = commands.add_parser("recover", parents=[common])
    recover.add_argument("--execution-id", required=True)
    recover.add_argument("--request-sha256", required=True)
    args = parser.parse_args(argv)
    identity = None
    cancelled = threading.Event()
    recovery_wakeup = threading.Event()
    previous_signals = {}

    def cancel(*_):
        cancelled.set()
        recovery_wakeup.set()

    def recovery_wait(timeout):
        interrupted = recovery_wakeup.wait(timeout)
        if interrupted:
            recovery_wakeup.clear()
        return interrupted

    try:
        for chosen_signal in (signal.SIGINT, signal.SIGTERM):
            previous_signals[chosen_signal] = signal.signal(chosen_signal, cancel)
        identity = run_identity(args) if args.mode == "run" else recover_identity(args)
        transport = SSHTransport(args.ssh_config, args.controller)
        result = Dispatcher(transport, args.state, args.output, args.budget_seconds,
                            cancel=cancelled.is_set, wait=cancelled.wait, recovery_wait=recovery_wait,
                            publish_metadata=emit).execute(identity, args.mode)
        emit(canonical(result))
        return 0 if result["status"] == "pass" else 1
    except (DispatchError, OSError, subprocess.SubprocessError) as error:
        code = error.code if isinstance(error, DispatchError) else "dispatcher-unavailable"
        value = {"schema_version": 1, "status": "error", "code": code}
        if identity is not None:
            value.update(execution_id=identity.execution_id, request_sha256=identity.request_sha256)
        emit(canonical(value))
        return 1
    finally:
        for chosen_signal, handler in previous_signals.items():
            signal.signal(chosen_signal, handler)


if __name__ == "__main__":
    raise SystemExit(main())
