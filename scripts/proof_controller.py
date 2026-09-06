#!/usr/bin/env python3
"""Render the unqualified controller proposal or validate a bounded dispatch request."""

import argparse
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import uuid

try:
    import fcntl
except ImportError:
    fcntl = None

import onboarding_proof as proof


MAX_WIRE = 4096
MAX_FILE = 1 << 20
EXECUTION_ID = r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}"
PHASES = {"accepted", "starting", "running", "recovering", "unresolved", "settled"}
PUBLIC_FIELDS = ("execution_id", "phase", "closed", "attempt", "local_termination",
                 "windows_cleanup", "proof_result")


class ControllerError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition, code):
    if not condition:
        raise ControllerError(code)


def document(raw, limit=MAX_FILE):
    require(isinstance(raw, bytes) and 0 < len(raw) <= limit, "invalid-document")
    try:
        return proof.document(raw)
    except (proof.ProofError, RecursionError) as error:
        raise ControllerError("invalid-document") from error


def utc(value):
    require(proof.matches(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value), "invalid-expiry")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise ControllerError("invalid-expiry") from error


@dataclass(frozen=True)
class ProofExecutionRequest:
    schema_version: int
    repository: str
    candidate_sha: str
    driver_sha: str
    variant: str
    execution_id: str
    expires_at: str

    @classmethod
    def parse(cls, value):
        require(isinstance(value, dict) and set(value) == set(cls.__dataclass_fields__), "invalid-request")
        require(type(value["schema_version"]) is int and value["schema_version"] == 1
                and value["repository"] == "BramVR/blender-box"
                and proof.matches(proof.SHA, value["candidate_sha"])
                and proof.matches(proof.SHA, value["driver_sha"])
                and value["variant"] in ("baseline", "named-target")
                and proof.matches(EXECUTION_ID, value["execution_id"]), "invalid-request")
        utc(value["expires_at"])
        return cls(**value)

    @property
    def digest(self):
        return proof.digest(proof.canonical(asdict(self)))


@dataclass(frozen=True)
class Command:
    operation: str
    execution_id: str
    request: ProofExecutionRequest | None = None


def parse_command(raw):
    value = document(raw, MAX_WIRE)
    operation = value.get("operation")
    if operation == "start":
        require(set(value) == {"schema_version", "operation", "request"}, "invalid-command")
        request = ProofExecutionRequest.parse(value["request"])
        return Command(operation, request.execution_id, request)
    require(operation in ("status", "recover", "stop")
            and set(value) == {"schema_version", "operation", "execution_id"}
            and proof.matches(EXECUTION_ID, value["execution_id"]), "invalid-command")
    return Command(operation, value["execution_id"])


def no_links(path):
    require(path.is_absolute(), "unsafe-private-path")
    for parent in reversed((path, *path.parents)):
        require(not parent.is_symlink(), "unsafe-private-path")


def private_directory(path, create=False):
    no_links(path)
    if create:
        path.mkdir(mode=0o700)
        sync_directory(path.parent)
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and info.st_mode & 0o077 == 0, "private-directory-permissions")


def read_private(path, limit=MAX_FILE):
    no_links(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and before.st_mode & 0o077 == 0 and before.st_nlink == 1
                and 0 < before.st_size <= limit, "private-file-invalid")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            content = stream.read(limit + 1)
        after = os.fstat(fd)
        require(len(content) == before.st_size and before.st_mtime_ns == after.st_mtime_ns
                and os.path.samestat(after, path.stat()), "private-file-changed")
        return content
    finally:
        os.close(fd)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def publish(path, content, exclusive=True, mode=0o600):
    private_directory(path.parent)
    no_links(path)
    temporary = path.parent / (".publish-" + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    try:
        if exclusive:
            os.link(temporary, path, follow_symlinks=False)
        else:
            os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    sync_directory(path.parent)


@dataclass(frozen=True)
class Invocation:
    boot_id: str
    invocation_id: str
    cgroup: str
    leader_pid: int
    leader_start_ticks: int
    parent_pid: int
    execution_id: str
    attempt: int
    request_digest: str

    @classmethod
    def parse(cls, value):
        require(isinstance(value, dict) and set(value) == set(cls.__dataclass_fields__), "invalid-invocation")
        require(all(proof.matches(r"[a-f0-9]{32}", value[k]) for k in ("boot_id", "invocation_id"))
                and proof.matches(r"/[A-Za-z0-9_./-]{1,240}", value["cgroup"])
                and ".." not in value["cgroup"].split("/")
                and all(type(value[k]) is int and value[k] > 0
                        for k in ("leader_pid", "leader_start_ticks", "parent_pid", "attempt"))
                and proof.matches(EXECUTION_ID, value["execution_id"])
                and proof.matches(proof.HASH, value["request_digest"]), "invalid-invocation")
        return cls(**value)


@dataclass(frozen=True)
class ServiceObservation:
    boot_id: str
    invocation: Invocation | None
    empty: bool


@dataclass(frozen=True)
class Policy:
    candidate_sha: str
    driver_sha: str
    candidate_checkout: Path
    operator_config: Path
    expected_client_sha256: str


@dataclass(frozen=True)
class Job:
    request: ProofExecutionRequest
    root: Path
    candidate_checkout: Path
    expected_client_sha256: str
    attempt: int
    inputs_digest: str | None = None

    @property
    def output(self):
        return self.root / "baseline"

    @property
    def config(self):
        return self.output / "private/config"

    @property
    def attempt_root(self):
        return self.root / "attempts" / f"{self.attempt:04d}"


SSH_KEYS = {"host", "hostname", "user", "port", "identityfile", "userknownhostsfile"}


def ssh_connection(raw, alias):
    try:
        text = raw.decode("utf-8")
        lines = [shlex.split(line, comments=True) for line in text.splitlines()]
    except (UnicodeError, ValueError) as error:
        raise ControllerError("ssh-config-not-self-contained") from error
    values = {}
    for tokens in filter(None, lines):
        require(len(tokens) == 2 and tokens[0].lower() in SSH_KEYS
                and tokens[0].lower() not in values, "ssh-config-not-self-contained")
        values[tokens[0].lower()] = tokens[1]
    require(set(values) == SSH_KEYS and values["host"] == alias
            and proof.matches(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}", values["hostname"])
            and proof.matches(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}", values["user"])
            and values["port"].isascii() and values["port"].isdigit()
            and 0 < int(values["port"]) <= 65535, "ssh-config-not-self-contained")
    return values


def normalized_ssh(connection, root):
    fixed = {"Host": connection["host"], "HostName": connection["hostname"], "User": connection["user"],
             "Port": str(int(connection["port"])), "IdentityFile": str(root / "key"),
             "UserKnownHostsFile": str(root / "known_hosts"), "GlobalKnownHostsFile": "/dev/null",
             "IdentityAgent": "none", "IdentitiesOnly": "yes", "CertificateFile": "none",
             "ProxyCommand": "none", "ProxyJump": "none", "KnownHostsCommand": "none",
             "CanonicalizeHostname": "no", "PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no",
             "HostbasedAuthentication": "no", "AddKeysToAgent": "no", "ControlMaster": "no",
             "ControlPath": "none", "ControlPersist": "no", "PermitLocalCommand": "no",
             "BatchMode": "yes", "StrictHostKeyChecking": "yes", "ForwardAgent": "no",
             "ClearAllForwardings": "yes", "RequestTTY": "no", "RemoteCommand": "none"}
    require(all('"' not in value and "\n" not in value and "\r" not in value and "%" not in value
                and "${" not in value and "\\" not in value for value in fixed.values()), "unsafe-private-path")
    return "".join(f'{key} "{value}"\n' for key, value in fixed.items()).encode()


def snapshot_inputs(control, job, policy):
    original = read_private(policy.operator_config, 64 << 10)
    value = document(original)
    inputs = control / "inputs"
    private_directory(inputs, create=True)
    publish(inputs / "original-operator.json", original)
    operator = proof.Operator.load(inputs / "original-operator.json", job.request.candidate_sha)
    require(operator.ssh_config is not None, "ssh-config-not-self-contained")
    source = read_private(operator.ssh_config, 64 << 10)
    connection = ssh_connection(source, operator.target["ssh_alias"])
    private_directory(job.root / "inputs", create=True)
    normalized = normalized_ssh(connection, job.root / "inputs")
    value["ssh_config"] = str(job.root / "inputs/ssh-config")
    files = {"original-operator.json": original, "original-ssh-config": source,
             "operator.json": proof.canonical(value), "target.json": proof.canonical(operator.target),
             "ssh-config": normalized, "key": read_private(Path(connection["identityfile"]), 64 << 10),
             "known_hosts": read_private(Path(connection["userknownhostsfile"]), 64 << 10)}
    manifest = {"schema_version": 1, "files": {name: proof.digest(content) for name, content in files.items()},
                "candidate_checkout": str(policy.candidate_checkout), "config": str(job.config),
                "expected_client_sha256": policy.expected_client_sha256}
    for name, content in files.items():
        if name != "original-operator.json":
            publish(inputs / name, content)
        publish(job.root / "inputs" / name, content)
    raw = proof.canonical(manifest)
    publish(control / "inputs.json", raw)
    publish(job.root / "inputs.json", raw)
    return proof.digest(raw)


def verify_inputs(control, job, expected):
    try:
        raw = read_private(control / "inputs.json")
        require(proof.digest(raw) == expected, "original-inputs-unavailable")
        require(read_private(job.root / "inputs.json") == raw, "original-inputs-unavailable")
        manifest = document(raw)
        require(set(manifest) == {"schema_version", "files", "candidate_checkout", "config", "expected_client_sha256"}
                and manifest["candidate_checkout"] == str(job.candidate_checkout)
                and manifest["config"] == str(job.config)
                and manifest["expected_client_sha256"] == job.expected_client_sha256
                and set(manifest["files"]) == {"original-operator.json", "original-ssh-config", "operator.json",
                                               "target.json", "ssh-config", "key", "known_hosts"},
                "original-inputs-unavailable")
        for name, expected_hash in manifest["files"].items():
            require(proof.digest(read_private(control / "inputs" / name)) == expected_hash
                    and proof.digest(read_private(job.root / "inputs" / name)) == expected_hash,
                    "original-inputs-unavailable")
    except (OSError, ControllerError, TypeError, KeyError) as error:
        raise ControllerError("original-inputs-unavailable") from error


def verify_worker_inputs(job):
    try:
        raw = read_private(job.root / "inputs.json")
        require(proof.digest(raw) == job.inputs_digest, "original-inputs-unavailable")
        manifest = document(raw)
        for name, expected in manifest["files"].items():
            require(proof.digest(read_private(job.root / "inputs" / name)) == expected, "original-inputs-unavailable")
    except (OSError, ControllerError, KeyError, TypeError) as error:
        raise ControllerError("original-inputs-unavailable") from error


class ProofWorker:
    def __init__(self, commands_factory=proof.Commands, clock=None):
        self.commands_factory = commands_factory
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def baseline(self, job):
        require(self.clock() < utc(job.request.expires_at), "execution-expired")
        verify_worker_inputs(job)
        request = proof.ProofRequest(job.request.candidate_sha, job.candidate_checkout,
                                     job.root / "inputs/operator.json", job.output,
                                     execution="hosted", driver_sha=job.request.driver_sha)

        def commands(private, cwd):
            result = self.commands_factory(private, cwd)
            result.env["BLENDER_BOX_CONFIG_DIR"] = str(job.config)
            original_json = result.json

            def checked_json(args, **kwargs):
                if Path(args[0]) == private / "blender-box":
                    require(proof.digest(read_private(private / "blender-box", 128 << 20))
                            == job.expected_client_sha256, "client-artifact-mismatch")
                    if len(args) > 1 and args[1] == "run":
                        require(self.clock() < utc(job.request.expires_at), "execution-expired")
                return original_json(args, **kwargs)

            result.json = checked_json
            return result
        previous = os.umask(0o077)
        try:
            return proof.baseline(request, commands)
        finally:
            os.umask(previous)

    def recovery_inputs(self, job):
        verify_worker_inputs(job)
        marker = document(read_private(job.output / "private/run-journal.json", 4096))
        require(set(marker) == {"schema_version", "run_id"} and proof.matches(proof.RUN_ID, marker["run_id"]),
                "run-locator-unavailable")
        journal = job.config / "runs" / (marker["run_id"] + ".json")
        read_private(journal, 16 << 10)
        session = journal.with_suffix(".session.json")
        if session.exists() or session.is_symlink():
            read_private(session, 16 << 10)
        client = read_private(job.output / "private/blender-box", 128 << 20)
        target = read_private(job.output / "private/target.json", 64 << 10)
        require(target == read_private(job.root / "inputs/target.json", 64 << 10), "original-inputs-unavailable")
        require(proof.digest(client) == job.expected_client_sha256, "client-artifact-mismatch")
        return {"schema_version": 1, "run_id": marker["run_id"], "client_sha256": proof.digest(client),
                "target_sha256": proof.digest(target), "journal": str(journal)}

    def recover(self, job, retained):
        current = self.recovery_inputs(job)
        require(current == retained, "recovery-inputs-changed")
        private_directory(job.attempt_root / "commands", create=True)
        commands = self.commands_factory(job.attempt_root / "commands", job.candidate_checkout)
        commands.env["BLENDER_BOX_CONFIG_DIR"] = str(job.config)
        proof.configure_ssh(commands, job.root / "inputs/ssh-config")
        recovered = []
        for operation in ("status", "stop", "status"):
            try:
                recovered.append(commands.json([job.output / "private/blender-box", operation, "--target",
                                                  job.root / "inputs/target.json", "--run", retained["run_id"],
                                                  "--timeout", "60s", "--json"], timeout=100, recovery=True))
            except Exception:
                recovered.append(None)
        require(all(record is not None for record in recovered), "recovery-unavailable")
        require(all(proof.Fence.parse(record, require_session=False).run_id == retained["run_id"]
                    for record in recovered), "recovery-identity-changed")
        return proof.verify_recovery(recovered[0], *recovered)


class Controller:
    def __init__(self, control_root, jobs_root, policy, service, worker=None, clock=None):
        self.control_root, self.jobs_root = control_root, jobs_root
        self.policy, self.service = policy, service
        self.worker = worker or ProofWorker()
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    @contextmanager
    def locked(self):
        require(fcntl is not None, "controller-platform-unsupported")
        private_directory(self.control_root)
        private_directory(self.jobs_root)
        lock = self.control_root / "fixture.lock"
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and info.st_mode & 0o077 == 0 and info.st_nlink == 1, "private-file-invalid")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        except BlockingIOError as error:
            raise ControllerError("fixture-busy") from error
        finally:
            os.close(fd)

    def dispatch(self, command):
        require(isinstance(command, Command) and proof.matches(EXECUTION_ID, command.execution_id)
                and command.operation in ("start", "status", "stop", "recover"), "invalid-command")
        with self.locked():
            control = self.control_root / command.execution_id
            if command.operation == "start":
                require(command.request is not None and command.request.execution_id == command.execution_id,
                        "invalid-command")
                if control.exists():
                    request = ProofExecutionRequest.parse(document(read_private(control / "request.json", MAX_WIRE)))
                    require(request == command.request, "execution-conflict")
                    return self.receipt(self.load(control))
                return self.start(control, command.request)
            require(control.exists(), "execution-not-found")
            state = self.load(control)
            if command.operation in ("recover", "stop") and state["phase"] != "settled":
                state = self.recover(control, state)
            elif command.operation == "status" and state["phase"] != "settled":
                state = self.reconcile(control, state)
            return self.receipt(state)

    @staticmethod
    def receipt(state):
        return {"schema_version": 1, **{name: state[name] for name in PUBLIC_FIELDS}}

    def load(self, control):
        try:
            state = document(read_private(control / "execution.json"))
            require(set(state) == {"schema_version", *PUBLIC_FIELDS, "request_digest", "inputs_digest", "invocation",
                                  "candidate_checkout", "expected_client_sha256", "recovery_inputs"}
                    and state["phase"] in PHASES and type(state["closed"]) is bool
                    and type(state["attempt"]) is int and 0 <= state["attempt"] <= 9999
                    and state["execution_id"] == control.name
                    and state["local_termination"] in ("unknown", "proven")
                    and state["windows_cleanup"] in ("unknown", "proven")
                    and state["proof_result"] in ("not-run", "pass", "fail")
                    and proof.matches(proof.HASH, state["expected_client_sha256"])
                    and isinstance(state["candidate_checkout"], str)
                    and Path(state["candidate_checkout"]).is_absolute()
                    and (state["inputs_digest"] is None or proof.matches(proof.HASH, state["inputs_digest"])),
                    "execution-state-invalid")
            request = ProofExecutionRequest.parse(document(read_private(control / "request.json", MAX_WIRE)))
            require(request.digest == state["request_digest"] and request.execution_id == control.name,
                    "execution-state-invalid")
            require(state["phase"] != "settled" or (state["closed"] and state["local_termination"] == "proven"
                    and state["windows_cleanup"] == "proven" and state["proof_result"] != "not-run"
                    and state["invocation"] is not None and state["inputs_digest"] is not None), "execution-state-invalid")
            require(state["phase"] not in ("running", "recovering") or state["invocation"] is not None,
                    "execution-state-invalid")
            require(state["phase"] != "accepted" or (state["attempt"] == 0 and state["invocation"] is None),
                    "execution-state-invalid")
            require(state["phase"] != "starting" or (state["attempt"] > 0 and state["invocation"] is None
                    and state["inputs_digest"] is not None), "execution-state-invalid")
            require(state["local_termination"] != "proven" or state["invocation"] is not None,
                    "execution-state-invalid")
            require(state["recovery_inputs"] is None or (isinstance(state["recovery_inputs"], dict)
                    and set(state["recovery_inputs"]) == {"schema_version", "run_id", "client_sha256", "target_sha256", "journal"}
                    and state["recovery_inputs"]["schema_version"] == 1
                    and proof.matches(proof.RUN_ID, state["recovery_inputs"]["run_id"])
                    and state["recovery_inputs"]["client_sha256"] == state["expected_client_sha256"]
                    and proof.matches(proof.HASH, state["recovery_inputs"]["target_sha256"])
                    and state["recovery_inputs"]["journal"] == str(self.jobs_root / request.execution_id
                        / "baseline/private/config/runs" / (state["recovery_inputs"]["run_id"] + ".json"))),
                    "execution-state-invalid")
            if state["invocation"] is not None:
                invocation = Invocation.parse(state["invocation"])
                require(invocation.execution_id == request.execution_id and invocation.attempt == state["attempt"]
                        and invocation.request_digest == request.digest, "execution-state-invalid")
            return state
        except (OSError, ControllerError, TypeError, KeyError) as error:
            raise ControllerError("execution-state-unavailable") from error

    def save(self, control, state):
        publish(control / "execution.json", proof.canonical(state), exclusive=False)

    def job(self, control, state):
        request = ProofExecutionRequest.parse(document(read_private(control / "request.json", MAX_WIRE)))
        return Job(request, self.jobs_root / request.execution_id, Path(state["candidate_checkout"]),
                   state["expected_client_sha256"], state["attempt"], state["inputs_digest"])

    def start(self, control, request):
        require(request.variant == "baseline", "variant-driver-unavailable")
        require((request.candidate_sha, request.driver_sha) == (self.policy.candidate_sha, self.policy.driver_sha),
                "request-not-authorized")
        require(proof.matches(proof.HASH, self.policy.expected_client_sha256), "client-artifact-unavailable")
        no_links(self.policy.candidate_checkout)
        require(self.clock() < utc(request.expires_at) <= self.clock() + timedelta(hours=2), "execution-expired")
        require(os.environ.get("GITHUB_RUN_ATTEMPT") == "1", "hosted-authorization-invalid")
        for entry in self.control_root.iterdir():
            if entry.name == "fixture.lock":
                continue
            require(entry.is_dir() and not entry.is_symlink() and proof.matches(EXECUTION_ID, entry.name),
                    "fixture-unresolved")
            require(self.load(entry)["phase"] == "settled", "fixture-unresolved")
        observation = self.observe()
        require(observation.empty, "fixture-unresolved")
        private_directory(control, create=True)
        publish(control / "request.json", proof.canonical(asdict(request)))
        state = {"schema_version": 1, "execution_id": request.execution_id, "phase": "accepted", "closed": False,
                 "attempt": 0, "request_digest": request.digest, "inputs_digest": None, "invocation": None,
                 "candidate_checkout": str(self.policy.candidate_checkout), "local_termination": "unknown",
                 "expected_client_sha256": self.policy.expected_client_sha256,
                 "windows_cleanup": "unknown", "proof_result": "not-run", "recovery_inputs": None}
        self.save(control, state)
        try:
            job = self.job(control, state)
            private_directory(job.root, create=True)
            private_directory(job.root / "attempts", create=True)
            state["inputs_digest"] = snapshot_inputs(control, job, self.policy)
            self.save(control, state)
            return self.receipt(self.launch(control, state, "baseline"))
        except Exception:
            state.update(phase="unresolved", closed=True)
            self.save(control, state)
            raise

    def observe(self):
        observed = self.service.observe()
        require(isinstance(observed, ServiceObservation) and type(observed.empty) is bool
                and proof.matches(r"[a-f0-9]{32}", observed.boot_id), "service-observation-invalid")
        if observed.invocation is not None:
            require(isinstance(observed.invocation, Invocation), "service-observation-invalid")
            invocation = Invocation.parse(asdict(observed.invocation))
            require(invocation.boot_id == observed.boot_id, "service-observation-invalid")
        return observed

    def terminate(self, state):
        require(state["invocation"] is not None, "service-identity-unavailable")
        expected = Invocation.parse(state["invocation"])
        observed = self.observe()
        if observed.boot_id != expected.boot_id:
            require(observed.empty and observed.invocation is None, "fixture-unresolved")
        else:
            require(observed.invocation == expected, "service-identity-changed")
            if not observed.empty:
                require(self.service.stop_exact(expected) is True, "local-termination-unknown")
                after = self.observe()
                require(after.boot_id == expected.boot_id and after.invocation == expected and after.empty,
                        "local-termination-unknown")
        state["local_termination"] = "proven"

    def recover(self, control, state):
        if state["phase"] == "recovering":
            state = self.reconcile(control, state)
            if state["phase"] in ("recovering", "settled"):
                return state
        state.update(closed=True)
        self.save(control, state)
        try:
            self.terminate(state)
            self.save(control, state)
            job = self.job(control, state)
            verify_inputs(control, job, state["inputs_digest"])
            state = self.reconcile(control, state)
            if state["phase"] == "settled":
                return state
            if state["recovery_inputs"] is None:
                require(self.service.result(Invocation.parse(state["invocation"])) is None, "retained-recovery-unavailable")
            retained = self.worker.recovery_inputs(job)
            require(state["recovery_inputs"] is None or retained == state["recovery_inputs"], "recovery-inputs-changed")
            state["recovery_inputs"] = retained
            self.save(control, state)
            return self.launch(control, state, "recover")
        except Exception:
            state.update(phase="unresolved", closed=True)
            self.save(control, state)
            raise

    def launch(self, control, state, mode):
        job = self.job(control, state)
        verify_inputs(control, job, state["inputs_digest"])
        if mode == "baseline":
            require(not state["closed"] and self.clock() < utc(job.request.expires_at), "execution-expired")
        require(state["attempt"] < 9999, "attempt-limit")
        state.update(attempt=state["attempt"] + 1, phase="starting", invocation=None, local_termination="unknown")
        self.save(control, state)
        job = replace(job, attempt=state["attempt"])
        private_directory(job.attempt_root, create=True)
        intent = {"schema_version": 1, "execution_id": job.request.execution_id, "attempt": job.attempt,
                  "request_digest": job.request.digest, "mode": mode}
        publish(control / f"intent-{job.attempt:04d}.json", proof.canonical(intent))
        invocation = self.service.start(job.request, job.attempt)
        invocation = Invocation.parse(asdict(invocation))
        require(invocation.execution_id == job.request.execution_id and invocation.attempt == job.attempt
                and invocation.request_digest == job.request.digest, "service-identity-changed")
        state.update(invocation=asdict(invocation), phase="running" if mode == "baseline" else "recovering")
        self.save(control, state)
        if mode == "baseline":
            require(self.clock() < utc(job.request.expires_at), "execution-expired")
        authorization = {"schema_version": 1, "invocation": asdict(invocation), "mode": mode}
        authorization_path = control / f"authorization-{job.attempt:04d}.json"
        publish(authorization_path, proof.canonical(authorization))
        verify_inputs(control, job, state["inputs_digest"])
        require(self.service.release(invocation, authorization_path, job, mode, state["recovery_inputs"]) is True,
                "service-release-unconfirmed")
        return state

    def reconcile(self, control, state):
        if state["invocation"] is None:
            return state
        invocation = Invocation.parse(state["invocation"])
        observed = self.observe()
        if observed.boot_id == invocation.boot_id:
            require(observed.invocation == invocation, "service-identity-changed")
        else:
            require(observed.empty and observed.invocation is None, "fixture-unresolved")
        if not observed.empty:
            return state
        job = self.job(control, state)
        verify_inputs(control, job, state["inputs_digest"])
        state["local_termination"] = "proven"
        state["closed"] = True
        completed = self.service.result(invocation)
        if completed is None:
            state.update(phase="unresolved", proof_result="fail")
            self.save(control, state)
            return state
        require(isinstance(completed, dict) and set(completed) == {"schema_version", "invocation", "mode", "result"}
                and completed["schema_version"] == 1 and completed["invocation"] == asdict(invocation)
                and completed["mode"] in ("baseline", "recover"), "proof-result-invalid")
        mode, result = completed["mode"], completed["result"]
        require((mode == "baseline") == (state["attempt"] == 1), "proof-result-invalid")
        if mode == "baseline":
            require(isinstance(result, dict) and result.get("execution") == "hosted"
                    and result.get("candidate_sha") == job.request.candidate_sha
                    and result.get("driver_sha") == job.request.driver_sha
                    and result.get("status") in ("pass", "fail"), "proof-result-invalid")
            if state["proof_result"] != "fail":
                state["proof_result"] = result["status"]
            try:
                proof.verify_cleanup(result)
                state["windows_cleanup"] = "proven"
            except proof.ProofError:
                pass
            try:
                retained = self.worker.recovery_inputs(job)
            except (OSError, ControllerError, proof.ProofError):
                pass
            else:
                require(state["recovery_inputs"] is None or retained == state["recovery_inputs"], "recovery-inputs-changed")
                run = result.get("run")
                require(isinstance(run, dict) and proof.matches(proof.RUN_ID, run.get("run_id"))
                        and retained["run_id"] == run["run_id"], "recovery-identity-changed")
                state["recovery_inputs"] = retained
        else:
            proof.verify_cleanup({"cleanup": result})
            state["windows_cleanup"] = "proven"
        state["closed"] = True
        self.save(control, state)
        state["phase"] = "settled" if state["windows_cleanup"] == "proven" else "unresolved"
        self.save(control, state)
        return state


def bootstrap_preview():
    service = """[Unit]
Description=Blender Box proof controller proposal
ConditionPathExists=/nonexistent/blender-box-proof-qualification
[Service]
Type=exec
User=blender-box-proof-runner
ExecStart=/usr/bin/false
Restart=no
KillMode=control-group
TimeoutStartSec=45min
TimeoutStopSec=2min
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/blender-box-proof/jobs
"""
    forced = 'restrict,command="/usr/bin/false" ssh-ed25519 REPLACE_ONLY_AFTER_QUALIFICATION\n'
    policy = {"schema_version": 1, "qualified": False, "control_uid": None, "runner_uid": None,
              "native_helper": None, "native_worker": None, "candidate_sha": None, "driver_sha": None,
              "expected_client_sha256": None,
              "proposed_privilege_rule": {"helper": "/usr/local/libexec/blender-box-proof-helper",
                                           "service": "blender-box-proof.service",
                                           "operations": ["start", "status", "recover", "stop"],
                                           "arbitrary_commands": False, "qualified": False}}
    return {"schema_version": 1, "status": "unqualified", "installable": False,
            "resources": [{"kind": "account", "name": "blender-box-proof-control", "uid": None, "password_login": "disabled"},
                          {"kind": "account", "name": "blender-box-proof-runner", "uid": None, "password_login": "disabled"},
                          {"path": "/var/lib/blender-box-proof/control", "mode": "0700", "owner": "blender-box-proof-control", "uid": None},
                          {"path": "/var/lib/blender-box-proof/jobs", "mode": "0700", "owner": "blender-box-proof-runner", "uid": None},
                          {"path": "/etc/systemd/system/blender-box-proof.service", "mode": "0644", "owner": "root", "uid": 0},
                          {"path": "/etc/blender-box-proof", "mode": "0700", "owner": "blender-box-proof-control", "uid": None},
                          {"path": "/etc/blender-box-proof/policy.json", "mode": "0600", "owner": "blender-box-proof-control", "uid": None},
                          {"path": "/etc/blender-box-proof/operator.json", "mode": "0600", "owner": "blender-box-proof-control", "uid": None},
                          {"path": "/etc/ssh/blender-box-proof-authorized_keys", "mode": "0600", "owner": "root", "uid": 0},
                          {"path": "/usr/local/libexec/blender-box-proof-helper", "mode": "0755", "owner": "root", "uid": 0, "available": False},
                          {"path": "/usr/local/libexec/blender-box-proof-worker", "mode": "0755", "owner": "root", "uid": 0, "available": False}],
            "unknown_qualification": ["control-and-runner-uids", "separate-uid-access", "filesystem-fsync-and-flock",
                                      "native-ownership-and-file-access-adapter",
                                      "native-helper-and-worker", "service-startup-gate", "exact-cgroup-termination",
                                      "dedicated-key-and-trust", "network-policy", "candidate-and-driver-policy",
                                      "expected-client-artifact-policy",
                                      "product-journal-recovery", "owned-windows-fixture-authorization"],
            "proposed_files": [{"path": "blender-box-proof.service.proposal", "mode": "0600", "content": service},
                               {"path": "authorized_keys.proposal", "mode": "0600", "content": forced},
                               {"path": "policy.json.proposal", "mode": "0600", "content": proof.canonical(policy).decode() + "\n"}]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    bootstrap = commands.add_parser("bootstrap", help="render non-installable proposals; never apply")
    bootstrap.add_argument("--output", type=Path, help="fresh directory for proposal files")
    commands.add_parser("dispatch", help="validate stdin; native adapter remains unqualified")
    args = parser.parse_args(argv)
    try:
        if args.command == "dispatch":
            parse_command(sys.stdin.buffer.read(MAX_WIRE + 1))
            raise ControllerError("native-adapter-unqualified")
        preview = bootstrap_preview()
        if args.output is not None:
            require(fcntl is not None, "controller-platform-unsupported")
            output = args.output.absolute()
            private_directory(output, create=True)
            for proposed in preview["proposed_files"]:
                publish(output / proposed["path"], proposed["content"].encode())
        print(proof.canonical(preview).decode())
        return 0
    except (ControllerError, OSError, proof.ProofError) as error:
        code = error.code if isinstance(error, ControllerError) else "controller-unavailable"
        print(proof.canonical({"schema_version": 1, "status": "error", "code": code}).decode())
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
