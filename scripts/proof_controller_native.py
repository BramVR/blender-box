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
           "scripts/proof_controller_worker.py", "scripts/onboarding_proof.py", "scripts/proof_qualification_fixture.py",
           "tests/fixtures/qualification-windows-hold/payload.json", "tests/fixtures/qualification-windows-hold/scenario.py",
           "tests/fixtures/onboarding-baseline/payload.json", "tests/fixtures/onboarding-baseline/scenario.py")
QUALIFICATIONS = ("separate-uids", "source-and-tool-confinement", "fsync-flock", "startup-gate", "peer-credentials",
                  "exact-cgroup-stop", "supervisor-crash-containment", "disconnect-reboot", "network-policy",
                  "original-journal-recovery", "owned-windows-fixture")
PROPERTIES = ("Id", "LoadState", "ActiveState", "MainPID", "InvocationID", "ControlGroup", "Job")
STARTUP_SECONDS = 30
STOP_SECONDS = 15


QUALIFICATION_LIMIT = 16 << 10
LINUX_CASES = ("uid-confinement", "storage-lock", "startup-withheld", "peer-rejection", "descendant-stop",
               "crash-before-release", "crash-after-release", "initiator-disconnect", "reboot-observation", "network-local")
WINDOWS_CASES = ("windows-baseline", "windows-named-target", "windows-crash-recover", "windows-reboot-recover")
QUALIFICATION_ID = r"q-[a-f0-9]{32}"
WINDOWS_AUTHORIZATION_ID = r"wq-[a-f0-9]{32}"


def identity_digest(name, value):
    import json
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return model.proof.digest(b"blender-box/qualification/v1/" + name.encode("ascii") + b"\0" + raw)


def exact(value, fields, code="qualification-document-invalid"):
    model.require(isinstance(value, dict) and set(value) == set(fields)
                  and type(value.get("schema_version")) is int and value["schema_version"] == 1, code)


def hash_fields(value, names):
    model.require(all(model.proof.matches(model.proof.HASH, value[name]) for name in names),
                  "qualification-binding-invalid")


@dataclass(frozen=True)
class LinuxIntent:
    value: dict

    @classmethod
    def parse(cls, value):
        exact(value, ("schema_version", "family", "qualification_id", "policy_sha256", "installation_sha256",
                      "deadline_unix", "case", "accepted_boot_id"))
        model.require(value["family"] == "linux-native-v1" and value["case"] in LINUX_CASES
                      and model.proof.matches(QUALIFICATION_ID, value["qualification_id"])
                      and type(value["deadline_unix"]) is int and value["deadline_unix"] > 0
                      and model.proof.matches(r"[a-f0-9]{32}", value["accepted_boot_id"]), "qualification-document-invalid")
        hash_fields(value, ("policy_sha256", "installation_sha256"))
        return cls(value)

    @property
    def digest(self):
        return identity_digest("LinuxIntent", self.value)

    @property
    def authorization_digest(self):
        return identity_digest("LinuxQualificationAuthorization", self.value)

    @property
    def origin_digest(self):
        return identity_digest("LinuxQualificationOrigin", self.value)

    @property
    def root(self):
        return CONTROL / "qualification" / self.value["qualification_id"]


@dataclass(frozen=True)
class QualificationAuthorization:
    value: dict
    digest: str
    raw: bytes

    @classmethod
    def parse(cls, raw):
        value = model.document(raw, QUALIFICATION_LIMIT)
        exact(value, ("schema_version", "family", "authorization_id", "policy_sha256", "installation_sha256",
                      "candidate_sha", "driver_sha", "fixture_sha256", "operator_manifest_sha256",
                      "expected_client_sha256", "expected_host_sha256", "target_sha256", "cases",
                      "launch_deadline_unix", "recovery_deadline_unix", "max_attempts"))
        model.require(value["family"] == "windows-controller-v1"
                      and model.proof.matches(WINDOWS_AUTHORIZATION_ID, value["authorization_id"])
                      and all(model.proof.matches(model.proof.SHA, value[key]) for key in ("candidate_sha", "driver_sha"))
                      and isinstance(value["cases"], list) and len(value["cases"]) == 1
                      and all(isinstance(case, str) for case in value["cases"])
                      and len(set(value["cases"])) == len(value["cases"])
                      and all(case in WINDOWS_CASES for case in value["cases"])
                      and type(value["max_attempts"]) is int and 1 <= value["max_attempts"] <= 4
                      and all(type(value[key]) is int and value[key] > 0 for key in
                              ("launch_deadline_unix", "recovery_deadline_unix"))
                      and value["launch_deadline_unix"] <= value["recovery_deadline_unix"],
                      "qualification-document-invalid")
        hash_fields(value, ("policy_sha256", "installation_sha256", "fixture_sha256", "operator_manifest_sha256",
                            "expected_client_sha256", "expected_host_sha256", "target_sha256"))
        return cls(value, model.proof.digest(raw), raw)

    def validate(self, policy, installation, case, now, *, launch):
        value = self.value
        model.require(case in value["cases"] and value["policy_sha256"] == policy.digest
                      and value["installation_sha256"] == installation
                      and (value["candidate_sha"], value["driver_sha"], value["expected_client_sha256"]) ==
                      (policy.value["candidate_sha"], policy.value["driver_sha"], policy.value["expected_client_sha256"])
                      and "windows-" + ("baseline" if policy.value["variant"] == "named-target" else "named-target") not in value["cases"], "qualification-binding-invalid")
        deadline = value["launch_deadline_unix" if launch else "recovery_deadline_unix"]
        model.require(now < deadline, "qualification-expired")
        if launch:
            model.require(value["launch_deadline_unix"] <= now + 7200
                          and value["recovery_deadline_unix"] <= now + 86400, "qualification-deadline-invalid")

    def execution_id(self, case):
        model.require(case in self.value["cases"], "qualification-case-invalid")
        return "wq-" + identity_digest("WindowsExecution", {"authorization_id": self.value["authorization_id"], "case": case})[:32]

    def origin(self, case):
        return {"schema_version": 1, "kind": "windows-qualification", "authorization_id": self.value["authorization_id"],
                "authorization_sha256": self.digest, "case": case}


@dataclass(frozen=True)
class CleanupAuthorization:
    value: dict
    digest: str
    raw: bytes

    @classmethod
    def parse(cls, raw):
        value = model.document(raw, QUALIFICATION_LIMIT)
        exact(value, ("schema_version", "kind", "authorization_id", "original_authorization_sha256", "execution_id",
                      "original_run_id", "original_session_id", "original_request_sha256", "original_run_deadline",
                      "inputs_sha256", "policy_sha256", "installation_sha256", "recovery_deadline_unix"))
        model.require(value["kind"] == "qualification-cleanup"
                      and model.proof.matches(WINDOWS_AUTHORIZATION_ID, value["authorization_id"])
                      and model.proof.matches(WINDOWS_AUTHORIZATION_ID, value["execution_id"])
                      and model.proof.matches(model.proof.RUN_ID, value["original_run_id"])
                      and model.proof.matches(r"bss_[A-Za-z0-9_-]{16,128}", value["original_session_id"])
                      and type(value["recovery_deadline_unix"]) is int and value["recovery_deadline_unix"] > 0,
                      "qualification-document-invalid")
        model.proof.Fence.parse({"schema_version": 1, "run_id": value["original_run_id"],
             "request_id": "req_" + "0" * 16, "request_hash": value["original_request_sha256"],
             "session_id": value["original_session_id"], "deadline": value["original_run_deadline"]})
        hash_fields(value, ("original_authorization_sha256", "original_request_sha256", "inputs_sha256",
                            "policy_sha256", "installation_sha256"))
        return cls(value, model.proof.digest(raw), raw)


def parse_qualification_command(raw, family):
    value = model.document(raw, QUALIFICATION_LIMIT)
    operation = value.get("operation")
    if family == "linux":
        if operation == "start":
            exact(value, ("schema_version", "operation", "family", "qualification_id", "policy_sha256",
                          "installation_sha256", "deadline_unix", "case"))
            LinuxIntent.parse({key: item for key, item in value.items() if key != "operation"} |
                              {"accepted_boot_id": "0" * 32})
        else:
            exact(value, ("schema_version", "operation", "qualification_id", "intent_sha256"))
            model.require(operation in ("status", "stop") and model.proof.matches(QUALIFICATION_ID, value["qualification_id"]),
                          "qualification-document-invalid")
            hash_fields(value, ("intent_sha256",))
    elif family == "windows":
        exact(value, ("schema_version", "operation", "authorization_id", "authorization_sha256", "case"))
        model.require(operation in ("start", "status", "stop", "recover") and value["case"] in WINDOWS_CASES
                      and model.proof.matches(WINDOWS_AUTHORIZATION_ID, value["authorization_id"]), "qualification-document-invalid")
        hash_fields(value, ("authorization_sha256",))
    else:
        model.require(family == "cleanup", "qualification-document-invalid")
        exact(value, ("schema_version", "operation", "execution_id", "cleanup_authorization_id", "cleanup_authorization_sha256"))
        model.require(operation in ("status", "stop", "recover")
                      and all(model.proof.matches(WINDOWS_AUTHORIZATION_ID, value[key]) for key in
                              ("execution_id", "cleanup_authorization_id")), "qualification-document-invalid")
        hash_fields(value, ("cleanup_authorization_sha256",))
    return value


def parse_windows_intent(value):
    extra = {"authorization_sha256", "origin_sha256", "case", "cleanup_authorization_sha256"}
    exact(value, {"schema_version", "execution_id", "attempt", "request_digest", "mode"} | extra)
    parse_intent(model.proof.canonical({key: item for key, item in value.items() if key not in extra}))
    hash_fields(value, ("authorization_sha256", "origin_sha256"))
    model.require(value["case"] in WINDOWS_CASES and value["attempt"] <= 4
                  and (value["cleanup_authorization_sha256"] is None or
                       (value["mode"] == "recover" and model.proof.matches(model.proof.HASH, value["cleanup_authorization_sha256"]))),
                  "qualification-document-invalid")
    return value


@dataclass(frozen=True)
class Selector:
    kind: str
    intent: dict
    intent_sha256: str

    @classmethod
    def create(cls, kind, intent):
        if kind == "linux-qualification":
            parsed = LinuxIntent.parse(intent)
            digest = parsed.digest
        elif kind == "windows-qualification":
            parse_windows_intent(intent)
            digest = identity_digest("WindowsIntent", intent)
        else:
            model.require(kind == "operational", "native-selector-invalid")
            parse_intent(model.proof.canonical(intent))
            digest = model.proof.digest(model.proof.canonical(intent))
        return cls(kind, intent, digest)

    def wire(self):
        return {"schema_version": 2, "kind": self.kind, "intent_sha256": self.intent_sha256, "intent": self.intent}

    @classmethod
    def parse(cls, raw):
        import json
        def pairs(items):
            result = {}
            for key, value in items:
                model.require(key not in result, "native-selector-invalid")
                result[key] = value
            return result
        model.require(isinstance(raw, bytes) and 0 < len(raw) <= QUALIFICATION_LIMIT, "native-selector-invalid")
        try:
            value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: model.require(False, "native-selector-invalid"))
        except (ValueError, UnicodeError, RecursionError) as error:
            raise model.ControllerError("native-selector-invalid") from error
        model.require(isinstance(value, dict) and set(value) == {"schema_version", "kind", "intent_sha256", "intent"}
                      and type(value["schema_version"]) is int and value["schema_version"] == 2, "native-selector-invalid")
        selected = cls.create(value["kind"], value["intent"])
        model.require(value == selected.wire(), "native-selector-invalid")
        return selected


def installation_digest(policy):
    return identity_digest("Installation", {"artifacts": policy.value["artifacts"], "tools": policy.value["tool_sha256"]})


@dataclass(frozen=True)
class WindowsQualification:
    authorization: QualificationAuthorization
    case: str
    cleanup: CleanupAuthorization | None = None

    @property
    def execution_id(self):
        return self.authorization.execution_id(self.case)

    @property
    def origin(self):
        return self.authorization.origin(self.case)

    @property
    def origin_digest(self):
        return identity_digest("WindowsQualificationOrigin", self.origin)

    def intent(self, request, attempt, mode):
        model.require(request.execution_id == self.execution_id and attempt <= self.authorization.value["max_attempts"],
                      "qualification-attempt-limit")
        return parse_windows_intent({"schema_version": 1, "execution_id": request.execution_id, "attempt": attempt,
                "request_digest": request.digest, "mode": mode, "authorization_sha256": self.authorization.digest,
                "origin_sha256": self.origin_digest, "case": self.case,
                "cleanup_authorization_sha256": None if self.cleanup is None else self.cleanup.digest})

    def verify_origin(self, files):
        model.require(model.document(files.read(CONTROL / self.execution_id / "origin.json", 64 << 10)) == self.origin,
                      "qualification-origin-changed")

    def verify_inputs(self, files, job):
        value = self.authorization.value
        root = CONTROL / self.execution_id
        manifest = files.read(root / "inputs.json", 64 << 10)
        model.require(model.proof.digest(manifest) == value["operator_manifest_sha256"]
                      and model.proof.digest(files.read(root / "inputs/target.json", 64 << 10)) == value["target_sha256"],
                      "qualification-inputs-changed")
        model.verify_inputs(root, job, job.inputs_digest, files)

    def release_record(self, files, receipt, mode):
        inv = receipt.invocation
        intent = self.intent(model.ProofExecutionRequest.parse(model.document(files.read(CONTROL / self.execution_id / "request.json"))),
                             inv.attempt, mode)
        return {"schema_version": 1, "operation": "qualification-release", "family": "windows-controller-v1",
                "intent_sha256": Selector.create("windows-qualification", intent).intent_sha256,
                "origin_sha256": self.origin_digest, "native_sha256": model.proof.digest(model.proof.canonical(asdict(receipt))),
                "authorization_sha256": self.authorization.digest,
                "cleanup_authorization_sha256": None if self.cleanup is None else self.cleanup.digest}


def qualification_context(files, intent):
    parse_windows_intent(intent)
    origin = model.document(files.read(CONTROL / intent["execution_id"] / "origin.json", 64 << 10))
    exact(origin, ("schema_version", "kind", "authorization_id", "authorization_sha256", "case"))
    model.require(origin["kind"] == "windows-qualification"
                  and model.proof.matches(WINDOWS_AUTHORIZATION_ID, origin["authorization_id"]), "qualification-origin-changed")
    authority = QualificationAuthorization.parse(files.read(CONTROL / intent["execution_id"] /
                                                            "qualification-authorization.json", QUALIFICATION_LIMIT))
    cleanup = None
    if intent["cleanup_authorization_sha256"] is not None:
        raw = files.read(CONTROL / intent["execution_id"] / f"cleanup-{intent['attempt']:04d}.json", QUALIFICATION_LIMIT)
        cleanup = CleanupAuthorization.parse(raw)
        model.require(cleanup.digest == intent["cleanup_authorization_sha256"], "qualification-cleanup-changed")
    context = WindowsQualification(authority, origin["case"], cleanup)
    model.require(context.execution_id == intent["execution_id"] and context.origin == origin
                  and context.origin_digest == intent["origin_sha256"] and authority.digest == intent["authorization_sha256"],
                  "qualification-origin-changed")
    return context


def qualification_count(files):
    count = len([entry for entry in files.entries(CONTROL) if entry.name.startswith("wq-")])
    root = CONTROL / "qualification"
    return count + (len(files.entries(root)) if files.exists(root) else 0)


def qualification_reservations_settled(files, root):
    files.directory(root)
    for entry in files.entries(root):
        model.require(model.proof.matches(QUALIFICATION_ID, entry.name), "fixture-unresolved")
        intent = LinuxIntent.parse(model.document(files.read(entry / "intent.json", QUALIFICATION_LIMIT)))
        model.require(intent.root == entry, "fixture-unresolved")
        record = model.document(files.read(entry / "settled.json", 64 << 10))
        model.require(record == {"schema_version": 1, "intent_sha256": intent.digest, "cleanup": "proven"},
                      "fixture-unresolved")


def validate_windows_qualification(context, policy, files, *, launch=False, observe=False):
    authority = context.authorization
    value = authority.value
    model.require(value["policy_sha256"] == policy.digest and value["installation_sha256"] == installation_digest(policy),
                  "qualification-binding-invalid")
    if not observe:
        if context.cleanup is None:
            authority.validate(policy, installation_digest(policy), context.case, int(time.time()), launch=launch)
        else:
            model.require(not launch, "qualification-cleanup-only")
            cleanup = context.cleanup.value
            model.require(cleanup["original_authorization_sha256"] == authority.digest
                          and cleanup["execution_id"] == context.execution_id
                          and cleanup["policy_sha256"] == policy.digest
                          and cleanup["installation_sha256"] == installation_digest(policy)
                          and time.time() < cleanup["recovery_deadline_unix"], "qualification-cleanup-changed")
    fixture = "qualification-windows-hold" if context.case in ("windows-crash-recover", "windows-reboot-recover") else "onboarding-baseline"
    hashes = {name: policy.value["artifacts"][str(BASE / "tests/fixtures" / fixture / name)]
              for name in ("payload.json", "scenario.py")}
    model.require(value["fixture_sha256"] == identity_digest("WindowsFixture", hashes), "qualification-fixture-changed")
    root = CONTROL / context.execution_id
    if files.exists(root):
        context.verify_origin(files)
        request = model.ProofExecutionRequest.parse(model.document(files.read(root / "request.json")))
        model.require(request.candidate_sha == value["candidate_sha"] and request.driver_sha == value["driver_sha"]
                      and request.variant == policy.value["variant"], "qualification-binding-invalid")
        controller = model.Controller(CONTROL, JOBS, policy.controller,
                                      NativeService(policy, files, LinuxOps(policy), context), files=files, qualification=context)
        state = controller.load(root)
        if state["inputs_digest"] is not None:
            context.verify_inputs(files, controller.job(root, state))
        if context.cleanup is not None:
            validate_cleanup(context, policy, files, controller.job(root, state), observe=observe)


def selected_runtime():
    model.require(os.getuid() == os.geteuid() == 0, "qualification-root-required")
    selected = Selector.parse(protected_read(RUNTIME / "pending.json", QUALIFICATION_LIMIT, private=True))
    if selected.kind == "operational":
        policy, files = load_runtime()
        context = None
    else:
        launching = selected.kind == "linux-qualification" or selected.intent["mode"] == "baseline"
        policy, files = load_prepared(launch=launching)
        if selected.kind == "windows-qualification":
            context = qualification_context(files, selected.intent)
            validate_windows_qualification(context, policy, files, launch=selected.intent["mode"] == "baseline")
        else:
            context = LinuxIntent.parse(selected.intent)
            model.require(context.value["policy_sha256"] == policy.digest
                          and context.value["installation_sha256"] == installation_digest(policy)
                          and context.value["accepted_boot_id"] == LinuxOps(policy).boot()
                          and time.time() < context.value["deadline_unix"], "qualification-expired")
    return selected, policy, files, context


def active_checkpoint_receipt(value):
    exact(value, ("schema_version", "checkpoint", "native_receipt"))
    return NativeReceipt.parse(value["native_receipt"])


def interruption_record(value, *, reboot):
    fields = ("schema_version", "active_checkpoint_sha256", "original_native_sha256",
              "observed_at_unix", "local_termination")
    exact(value, fields + (("observed_boot_id",) if reboot else ()))
    hash_fields(value, ("active_checkpoint_sha256", "original_native_sha256"))
    model.require(type(value["observed_at_unix"]) is int and value["observed_at_unix"] > 0
                  and value["local_termination"] == "proven", "qualification-interruption-invalid")
    if reboot:
        model.require(model.proof.matches(r"[a-f0-9]{32}", value["observed_boot_id"]),
                      "qualification-reboot-unobserved")
    return value


def completed_windows_attempt(controller, root, state):
    job = controller.job(root, state)
    durable = controller.service.durable_attempt(job.request, state["attempt"],
                                               model.Invocation.parse(state["invocation"]))
    model.require(durable is not None and durable[2] and durable[3] is not None,
                  "qualification-completion-missing")
    _, intent, _, record = durable
    result = record["result"]
    if state["attempt"] == 1:
        model.require(intent["mode"] == "baseline" and isinstance(result, dict)
                      and result.get("execution") == "hosted" and result.get("status") == "pass"
                      and result.get("candidate_sha") == job.request.candidate_sha
                      and result.get("driver_sha") == job.request.driver_sha, "proof-result-invalid")
        model.proof.verify_cleanup(result)
    else:
        model.require(intent["mode"] == "recover", "proof-result-invalid")
        model.proof.verify_cleanup({"cleanup": result})


def windows_readiness(controller, context):
    with controller.locked():
        root = CONTROL / context.execution_id
        context.verify_origin(controller.files)
        state = controller.load(root)
        records = ("execution.json", "request.json", "origin.json", "qualification-authorization.json", "inputs.json",
                   "active-checkpoint.json", "interruption.json", "reboot-observation.json", "recovery-completion.json")
        records += tuple(f"{kind}-{attempt:04d}.json" for attempt in range(1, state["attempt"] + 1)
                         for kind in ("intent", "native", "authorization", "result"))
        hashes = {name: model.proof.digest(controller.files.read(root / name, model.MAX_FILE))
                  for name in records if controller.files.exists(root / name)}
        evidence = {"schema_version": 1, "authorization_sha256": context.authorization.digest,
                    "origin_sha256": context.origin_digest, "files": hashes}
        if state["recovery_inputs"] is not None:
            fence, originals = original_windows_fence(controller.job(root, state), controller.files)
            evidence["original_run"] = asdict(fence) | originals
        case_status = "partial"
        if state["phase"] == "settled":
            if context.case in ("windows-baseline", "windows-named-target"):
                case_status = state["proof_result"]
                if case_status == "pass":
                    completed_windows_attempt(controller, root, state)
            elif state["attempt"] > 1 and state["local_termination"] == state["windows_cleanup"] == "proven":
                proof_name = "interruption.json" if context.case == "windows-crash-recover" else "reboot-observation.json"
                if proof_name in hashes and "active-checkpoint.json" in hashes and "original_run" in evidence:
                    interruption = interruption_record(model.document(controller.files.read(root / proof_name, 64 << 10)),
                                                       reboot=context.case == "windows-reboot-recover")
                    active = model.document(controller.files.read(root / "active-checkpoint.json", 64 << 10))
                    original = active_checkpoint_receipt(active)
                    final = NativeReceipt.parse(model.document(controller.files.read(root / f"native-{state['attempt']:04d}.json")))
                    valid = (interruption.get("active_checkpoint_sha256") == hashes["active-checkpoint.json"]
                             and interruption.get("original_native_sha256") == model.proof.digest(model.proof.canonical(asdict(original)))
                             and interruption["local_termination"] == "proven")
                    if context.case == "windows-reboot-recover":
                        valid = valid and original.owner.boot_id != final.owner.boot_id == interruption.get("observed_boot_id")
                    from datetime import datetime
                    deadline = datetime.fromisoformat(evidence["original_run"]["deadline"].replace("Z", "+00:00")).timestamp()
                    result_name = f"result-{state['attempt']:04d}.json"
                    if valid:
                        completed_windows_attempt(controller, root, state)
                        binding = {"schema_version": 1, "attempt": state["attempt"],
                                   "native_sha256": hashes[f"native-{state['attempt']:04d}.json"],
                                   "intent_sha256": hashes[f"intent-{state['attempt']:04d}.json"],
                                   "authorization_sha256": hashes[f"authorization-{state['attempt']:04d}.json"],
                                   "result_sha256": hashes[result_name],
                                   "original_run_sha256": model.proof.digest(model.proof.canonical(evidence["original_run"]))}
                        completion_path = root / "recovery-completion.json"
                        if not controller.files.exists(completion_path):
                            controller.files.publish(completion_path, model.proof.canonical(
                                binding | {"observed_at_unix": int(time.time())}))
                        completion_raw = controller.files.read(completion_path, 64 << 10)
                        completion = model.document(completion_raw)
                        exact(completion, (*binding, "observed_at_unix"))
                        model.require(type(completion["attempt"]) is int
                                      and all(completion[key] == value for key, value in binding.items())
                                      and type(completion["observed_at_unix"]) is int
                                      and completion["observed_at_unix"] > 0, "qualification-completion-invalid")
                        hashes["recovery-completion.json"] = model.proof.digest(completion_raw)
                        case_status = "pass" if interruption["observed_at_unix"] <= completion["observed_at_unix"] < deadline else "fail"
        raw = model.proof.canonical(evidence)
        model.require(len(raw) <= 64 << 10, "qualification-evidence-limit")
        readiness = {"schema_version": 1, "kind": "native-readiness", "qualified": False,
                     "policy_sha256": context.authorization.value["policy_sha256"],
                     "installation_sha256": context.authorization.value["installation_sha256"],
                     "authorization_sha256": context.authorization.digest,
                     "cases": {context.case: {"evidence_sha256": model.proof.digest(raw), "status": case_status}},
                     "unresolved": [] if case_status == "pass" else [context.case],
                     "cleanup": "proven" if state["local_termination"] == state["windows_cleanup"] == "proven" else "unknown"}
        for name, content in (("qualification-evidence.json", raw), ("native-readiness.json", model.proof.canonical(readiness))):
            path = root / name
            if not controller.files.exists(path) or controller.files.read(path, 64 << 10) != content:
                controller.files.publish(path, content, exclusive=False)
        return controller.receipt(state)


def observe_windows_reboot(context, files, ops):
    root = CONTROL / context.execution_id
    active_raw = files.read(root / "active-checkpoint.json", 64 << 10)
    active = model.document(active_raw)
    receipt = active_checkpoint_receipt(active)
    path = root / "reboot-observation.json"
    original_hash = model.proof.digest(model.proof.canonical(asdict(receipt)))
    if files.exists(path):
        observed = interruption_record(model.document(files.read(path, 64 << 10)), reboot=True)
        model.require(observed.get("original_native_sha256") == original_hash
                      and observed.get("active_checkpoint_sha256") == model.proof.digest(active_raw)
                      and observed.get("observed_boot_id") != receipt.owner.boot_id, "qualification-reboot-unobserved")
        return
    boot = ops.boot()
    model.require(boot != receipt.owner.boot_id and ops.whole_empty() and ops.boot() == boot, "qualification-reboot-unobserved")
    files.publish(path, model.proof.canonical({"schema_version": 1, "original_native_sha256": original_hash,
                  "active_checkpoint_sha256": model.proof.digest(active_raw), "observed_boot_id": boot,
                  "observed_at_unix": int(time.time()), "local_termination": "proven"}))


def qualification_dispatch(controller, operation, context):
    if operation != "stop":
        if operation == "recover" and context.case == "windows-reboot-recover":
            observe_windows_reboot(context, controller.files, controller.service.ops)
        controller.dispatch(model.Command(operation, context.execution_id))
        return windows_readiness(controller, context)
    root = CONTROL / context.execution_id
    with controller.locked():
        context.verify_origin(controller.files)
        state = controller.load(root)
        if state["phase"] == "settled":
            return controller.receipt(state)
        state = controller.reconcile(root, state)
        if state["phase"] != "settled":
            state.update(closed=True, phase="unresolved", proof_result="fail")
            controller.save(root, state)
            controller.terminate(state)
            controller.save(root, state)
            state = controller.reconcile(root, state)
        return controller.receipt(state)


def windows_qualification_command(command, policy, files, ops):
    execution_id = "wq-" + identity_digest("WindowsExecution", {"authorization_id": command["authorization_id"], "case": command["case"]})[:32]
    original = CONTROL / execution_id / "qualification-authorization.json"
    path = original if files.exists(original) else CONFIG / "qualification-authorizations" / (command["authorization_id"] + ".json")
    authority = QualificationAuthorization.parse(files.read(path, QUALIFICATION_LIMIT))
    model.require(authority.digest == command["authorization_sha256"], "qualification-authorization-changed")
    context = WindowsQualification(authority, command["case"])
    operation = command["operation"]
    validate_windows_qualification(context, policy, files, launch=operation == "start", observe=operation == "status")
    root = CONTROL / context.execution_id
    controller = model.Controller(CONTROL, JOBS, policy.controller, NativeService(policy, files, ops, context),
                                  files=files, admission=policy.admit, qualification=context)
    if operation == "start":
        if not files.exists(root):
            validate_windows_inputs()
        from datetime import datetime, timezone
        expires = datetime.fromtimestamp(authority.value["launch_deadline_unix"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        request = model.ProofExecutionRequest(1, "BramVR/blender-box", authority.value["candidate_sha"],
                  authority.value["driver_sha"], policy.value["variant"], context.execution_id, expires)
        existing = files.exists(root)
        response = controller.dispatch(model.Command("start", context.execution_id, request))
        if not existing and context.case in ("windows-crash-recover", "windows-reboot-recover"):
            path = JOBS / context.execution_id / "attempts/0001/active-checkpoint.json"
            wait_file(path, lambda: files.read(path, 64 << 10) if files.exists(path) else None, 700)
            accept_active_checkpoint(controller, context, files, ops)
        return windows_readiness(controller, context)
    response = qualification_dispatch(controller, operation, context)
    return windows_readiness(controller, context) if operation == "stop" else response


@dataclass(frozen=True)
class ProcessOwner:
    boot_id: str
    invocation_id: str
    cgroup: str
    leader_pid: int
    leader_start_ticks: int
    parent_pid: int
    supervisor_start: int
    cgroup_device: int
    cgroup_inode: int

    @classmethod
    def parse(cls, value):
        model.require(isinstance(value, dict) and set(value) == set(cls.__dataclass_fields__)
                      and all(model.proof.matches(r"[a-f0-9]{32}", value[key]) for key in ("boot_id", "invocation_id"))
                      and model.proof.matches(re.escape(UNIT_CGROUP) + r"/attempt-[a-f0-9]{32}", value["cgroup"])
                      and all(type(value[key]) is int and value[key] > 0 for key in
                              ("leader_pid", "leader_start_ticks", "parent_pid", "supervisor_start", "cgroup_device", "cgroup_inode")),
                      "native-owner-invalid")
        return cls(**value)


@dataclass(frozen=True)
class NativeFixtureReceipt:
    intent_sha256: str
    owner: ProcessOwner
    schema_version: int = 1

    @classmethod
    def parse(cls, value):
        exact(value, ("schema_version", "intent_sha256", "owner"))
        hash_fields(value, ("intent_sha256",))
        return cls(value["intent_sha256"], ProcessOwner.parse(value["owner"]))



def fixture_action(raw, intent, policy):
    value = model.document(raw, 64 << 10)
    exact(value, ("schema_version", "intent_sha256", "case", "observations"))
    model.require(value["intent_sha256"] == intent.digest and value["case"] == intent.value["case"]
                  and isinstance(value["observations"], dict), "qualification-evidence-changed")
    observed = value["observations"]
    model.require(all(type(observed.get(key)) is int for key in ("uid", "euid", "gid", "no_new_privs"))
                  and observed["uid"] == observed["euid"] == policy.value["runner_uid"]
                  and observed["gid"] == policy.value["runner_gid"] and observed["groups"] == []
                  and observed["no_new_privs"] == 1, "qualification-confinement-failed")
    return value


def crash_fixture(intent, receipt, files, ops):
    model.require(ops.boot() == intent.value["accepted_boot_id"] == receipt.owner.boot_id, "service-identity-changed")
    observed = linux_observe(intent, files, ops)
    model.require(observed["phase"] in ("starting", "released") and ops.boot() == receipt.owner.boot_id,
                  "native-process-changed")
    ops.end_supervisor(receipt)
    contained = False
    deadline = time.monotonic() + STOP_SECONDS
    try:
        if ops.wait_supervisor(receipt, deadline):
            try:
                with ops.group(UNIT_CGROUP) as group:
                    ops.wait_group_empty(group, deadline)
            except FileNotFoundError:
                pass
            contained = ops.whole_empty() and ops.supervisor_gone(receipt)
    except (OSError, model.ControllerError):
        pass
    files.publish(intent.root / "crash-containment.json", model.proof.canonical({"schema_version": 1,
                  "intent_sha256": intent.digest, "native_sha256": model.proof.digest(model.proof.canonical(asdict(receipt))),
                  "signal": "SIGTERM", "contained_before_cleanup": contained}))
    return linux_observe(intent, files, ops, stop=True)


def linux_release(intent, receipt):
    model.require(type(intent) is LinuxIntent and type(receipt) is NativeFixtureReceipt
                  and receipt.intent_sha256 == intent.digest, "qualification-binding-invalid")
    return {"schema_version": 1, "operation": "qualification-release", "family": "linux-native-v1",
            "intent_sha256": intent.digest, "origin_sha256": intent.origin_digest,
            "native_sha256": model.proof.digest(model.proof.canonical(asdict(receipt))),
            "authorization_sha256": intent.authorization_digest}


def settle_linux(intent, response, files):
    root = intent.root
    path = root / "case-outcome.json"
    if files.exists(path):
        original = model.document(files.read(path, 64 << 10))
        model.require({key: value for key, value in original.items() if key != "result"} ==
                      {key: value for key, value in response.items() if key != "result"}
                      and original["result"] in ("pass", "fail", "partial"), "qualification-evidence-changed")
        response = original
    else:
        files.publish(path, model.proof.canonical(response))
    readiness = {"schema_version": 1, "kind": "native-readiness", "qualified": False,
                 "policy_sha256": intent.value["policy_sha256"], "installation_sha256": intent.value["installation_sha256"],
                 "authorization_sha256": intent.authorization_digest,
                 "cases": {intent.value["case"]: {"evidence_sha256": model.proof.digest(files.read(path, 64 << 10)),
                                                   "status": response["result"]}},
                 "unresolved": [] if response["result"] == "pass" else [intent.value["case"]], "cleanup": "proven"}
    if not files.exists(root / "native-readiness.json"):
        files.publish(root / "native-readiness.json", model.proof.canonical(readiness))
    else:
        model.require(model.document(files.read(root / "native-readiness.json", 64 << 10)) == readiness, "qualification-evidence-changed")
    settled = {"schema_version": 1, "intent_sha256": intent.digest, "cleanup": "proven"}
    if not files.exists(root / "settled.json"):
        files.publish(root / "settled.json", model.proof.canonical(settled))
    else:
        model.require(model.document(files.read(root / "settled.json", 64 << 10)) == settled, "qualification-evidence-changed")
    return response


def linux_observe(intent, files, ops, *, stop=False):
    root = intent.root
    raw = files.read(root / "intent.json", QUALIFICATION_LIMIT)
    model.require(LinuxIntent.parse(model.document(raw)) == intent, "qualification-intent-changed")
    response = {"schema_version": 1, "qualification_id": intent.value["qualification_id"], "intent_sha256": intent.digest,
                "phase": "unresolved", "result": "pending", "local_termination": "unknown"}
    if files.exists(root / "settled.json"):
        settled = model.document(files.read(root / "settled.json", 64 << 10))
        model.require(settled == {"schema_version": 1, "intent_sha256": intent.digest, "cleanup": "proven"},
                      "qualification-evidence-changed")
        saved = model.document(files.read(root / "case-outcome.json", 64 << 10))
        model.require(set(saved) == set(response) and saved["qualification_id"] == response["qualification_id"]
                      and saved["intent_sha256"] == intent.digest and saved["phase"] == "settled"
                      and saved["local_termination"] == "proven" and saved["result"] in ("pass", "fail", "partial"),
                      "qualification-evidence-changed")
        return settle_linux(intent, saved, files)
    receipt = None
    native_path = root / "native.json"
    if files.exists(native_path):
        receipt = NativeFixtureReceipt.parse(model.document(files.read(native_path, 64 << 10)))
        model.require(receipt.intent_sha256 == intent.digest and receipt.owner.boot_id == intent.value["accepted_boot_id"],
                      "qualification-native-changed")
    release_path = root / "authorization.json"
    released = files.exists(release_path)
    if released:
        model.require(receipt is not None and model.document(files.read(release_path, 64 << 10)) ==
                      linux_release(intent, receipt) | {"native_receipt": asdict(receipt)}, "qualification-release-changed")
    result_path = root / "result.json"
    result = None
    if files.exists(result_path):
        model.require(released, "qualification-result-conflict")
        result = model.document(files.read(result_path, 64 << 10))
        exact(result, ("schema_version", "intent_sha256", "native_sha256", "result"))
        model.require(result["intent_sha256"] == intent.digest
                      and result["native_sha256"] == model.proof.digest(model.proof.canonical(asdict(receipt)))
                      and isinstance(result["result"], dict), "qualification-result-conflict")
    if receipt is None:
        if files.exists(root / "startup-failure.json") and files.exists(root / "start-command.json"):
            failure = model.document(files.read(root / "startup-failure.json", 64 << 10))
            exact(failure, ("schema_version", "intent_sha256", "owner", "child_cleanup"))
            owner = ProcessOwner.parse(failure["owner"])
            model.require(failure["intent_sha256"] == intent.digest and failure["child_cleanup"] == "proven"
                          and owner.boot_id == intent.value["accepted_boot_id"]
                          and model.document(files.read(root / "start-command.json")) ==
                              {"schema_version": 1, "intent_sha256": intent.digest, "boot_id": owner.boot_id}
                          and not released and ops.whole_empty(), "qualification-startup-unknown")
            response.update(local_termination="proven", result="fail", phase="settled")
            return settle_linux(intent, response, files)
        return response
    boot = ops.boot()
    if intent.value["case"] == "initiator-disconnect" and boot == receipt.owner.boot_id and not ops.whole_empty():
        if files.exists(root / "initiator.json"):
            helper = model.document(files.read(root / "initiator.json", 4096))
            exact(helper, ("schema_version", "boot_id", "pid", "start"))
            model.require(helper["boot_id"] == boot and type(helper["pid"]) is int and helper["pid"] > 0
                          and type(helper["start"]) is int and helper["start"] > 0, "qualification-initiator-invalid")
            try:
                gone = ops.process(helper["pid"]).start != helper["start"]
            except FileNotFoundError:
                gone = True
            if gone and not files.exists(root / "initiator-disconnected.json"):
                owner = receipt.owner
                child = ops.process(owner.leader_pid)
                model.require((child.start, child.parent, child.cgroup) == (owner.leader_start_ticks, owner.parent_pid, owner.cgroup),
                              "native-process-changed")
                files.publish(root / "initiator-disconnected.json", model.proof.canonical({"schema_version": 1,
                              "intent_sha256": intent.digest, "worker_survived": True}))
    descendant_stopped = False
    if stop and not ops.whole_empty():
        if intent.value["case"] == "descendant-stop" and boot == receipt.owner.boot_id:
            action = model.document(files.read(JOBS / "qualification" / intent.value["qualification_id"] / "action.json", 64 << 10))
            exact(action, ("schema_version", "intent_sha256", "case", "observations"))
            model.require(action["intent_sha256"] == intent.digest and action["case"] == "descendant-stop"
                          and isinstance(action["observations"], dict), "qualification-descendant-invalid")
            child = action["observations"].get("descendant")
            model.require(isinstance(child, dict) and set(child) == {"pid", "parent", "start", "cgroup"}
                          and all(type(child[key]) is int and child[key] > 0 for key in ("pid", "parent", "start"))
                          and child["parent"] == receipt.owner.leader_pid and child["cgroup"] == receipt.owner.cgroup,
                          "qualification-descendant-invalid")
            model.require(asdict(ops.process(child["pid"])) == child and ops.boot() == boot, "qualification-descendant-changed")
            witness = {"schema_version": 1, "intent_sha256": intent.digest,
                       "native_sha256": model.proof.digest(model.proof.canonical(asdict(receipt))), "descendant": child}
            path = root / "descendant-before-stop.json"
            if not files.exists(path):
                files.publish(path, model.proof.canonical(witness))
            else:
                model.require(model.document(files.read(path, 64 << 10)) == witness, "qualification-descendant-changed")
            model.require(asdict(ops.process(child["pid"])) == child and ops.boot() == boot, "qualification-descendant-changed")
            descendant_stopped = True
        model.require(ops.stop(receipt) is True, "local-termination-unknown")
    model.require(ops.boot() == boot, "service-identity-changed")
    if not ops.whole_empty():
        model.require(boot == receipt.owner.boot_id, "service-identity-changed")
        unit = ops.unit()
        owner = receipt.owner
        model.require(unit.invocation_id == owner.invocation_id and unit.main_pid == owner.parent_pid and unit.job_id == 0,
                      "service-identity-changed")
        supervisor = ops.process(owner.parent_pid)
        child = ops.process(owner.leader_pid)
        model.require(supervisor.start == owner.supervisor_start and supervisor.cgroup == UNIT_CGROUP
                      and (child.start, child.parent, child.cgroup) == (owner.leader_start_ticks, owner.parent_pid, owner.cgroup),
                      "native-process-changed")
        with ops.group(owner.cgroup) as group:
            info = os.fstat(group)
            model.require((info.st_dev, info.st_ino) == (owner.cgroup_device, owner.cgroup_inode), "native-cgroup-changed")
        model.require(ops.boot() == boot and ops.unit() == unit, "service-identity-changed")
        response["phase"] = "released" if released else "starting"
        return response
    unit = ops.unit()
    model.require(unit.active in ("inactive", "failed") and unit.main_pid == 0 and unit.job_id == 0
                  and ops.whole_empty() and ops.boot() == boot and ops.unit() == unit, "local-termination-unknown")
    if boot == receipt.owner.boot_id:
        model.require(ops.supervisor_gone(receipt), "local-termination-unknown")
    response.update(local_termination="proven", phase="settled", result="fail")
    if result is not None:
        data = result["result"]
        model.require(set(data) == {"status", "case", "observations_sha256"} and data["case"] == intent.value["case"]
                      and data["status"] in ("pass", "fail", "partial"), "qualification-result-conflict")
        action = files.read(JOBS / "qualification" / intent.value["qualification_id"] / "action.json", 64 << 10)
        model.require(model.proof.digest(action) == data["observations_sha256"], "qualification-evidence-changed")
        files.publish(root / "observations.json", action) if not files.exists(root / "observations.json") else None
        model.require(files.read(root / "observations.json", 64 << 10) == action, "qualification-evidence-changed")
        response["result"] = data["status"]
    elif intent.value["case"] == "startup-withheld" and not released:
        response["result"] = "pass"
    case = intent.value["case"]
    if case == "descendant-stop":
        path = root / "descendant-stop-complete.json"
        if descendant_stopped:
            completed = {"schema_version": 1, "intent_sha256": intent.digest,
                         "witness_sha256": model.proof.digest(files.read(root / "descendant-before-stop.json", 64 << 10)),
                         "local_termination": "proven"}
            if not files.exists(path):
                files.publish(path, model.proof.canonical(completed))
            else:
                model.require(model.document(files.read(path, 64 << 10)) == completed, "qualification-evidence-changed")
        response["result"] = "fail"
        if files.exists(path):
            completed = model.document(files.read(path, 64 << 10))
            model.require(completed == {"schema_version": 1, "intent_sha256": intent.digest,
                          "witness_sha256": model.proof.digest(files.read(root / "descendant-before-stop.json", 64 << 10)),
                          "local_termination": "proven"}, "qualification-evidence-changed")
            response["result"] = "pass"
    if case in ("crash-before-release", "crash-after-release") and files.exists(root / "crash-containment.json"):
        crash = model.document(files.read(root / "crash-containment.json", 4096))
        exact(crash, ("schema_version", "intent_sha256", "native_sha256", "signal", "contained_before_cleanup"))
        model.require(crash["intent_sha256"] == intent.digest and crash["signal"] == "SIGTERM"
                      and type(crash["contained_before_cleanup"]) is bool
                      and crash["native_sha256"] == model.proof.digest(model.proof.canonical(asdict(receipt))),
                      "qualification-evidence-changed")
        response["result"] = "pass" if crash["contained_before_cleanup"] else "fail"
    if case == "initiator-disconnect" and files.exists(root / "initiator-disconnected.json"):
        model.require(model.document(files.read(root / "initiator-disconnected.json")) ==
                      {"schema_version": 1, "intent_sha256": intent.digest, "worker_survived": True}, "qualification-evidence-changed")
        response["result"] = "pass"
    if boot != receipt.owner.boot_id:
        response["result"] = "fail"
        if case == "reboot-observation" and released and files.exists(root / "observations.json"):
            action = files.read(JOBS / "qualification" / intent.value["qualification_id"] / "action.json", 64 << 10)
            model.require(files.read(root / "observations.json", 64 << 10) == action, "qualification-evidence-changed")
            response["result"] = "pass"
    return settle_linux(intent, response, files)


def linux_qualification_command(command, policy, files, ops):
    operation = command["operation"]
    reservation_root = CONTROL / "qualification"
    with files.locked(CONTROL):
        files.directory(reservation_root, create=operation == "start" and not files.exists(reservation_root))
        root = reservation_root / command["qualification_id"]
        if operation != "start":
            intent = LinuxIntent.parse(model.document(files.read(root / "intent.json", QUALIFICATION_LIMIT)))
            model.require(intent.digest == command["intent_sha256"], "qualification-intent-changed")
            return linux_observe(intent, files, ops, stop=operation == "stop")
        model.require(time.time() < command["deadline_unix"] <= time.time() + 600, "qualification-expired")
        if files.exists(root):
            intent = LinuxIntent.parse(model.document(files.read(root / "intent.json", QUALIFICATION_LIMIT)))
            model.require({key: value for key, value in intent.value.items() if key != "accepted_boot_id"} ==
                          {key: value for key, value in command.items() if key != "operation"}, "qualification-intent-changed")
            return linux_observe(intent, files, ops)
        model.require(time.time() < command["deadline_unix"] <= time.time() + 600
                      and command["policy_sha256"] == policy.digest and command["installation_sha256"] == installation_digest(policy),
                      "qualification-binding-invalid")
        model.require(qualification_count(files) < 32, "qualification-capacity")
        qualification_reservations_settled(files, reservation_root)
        controller = model.Controller(CONTROL, JOBS, policy.controller, NativeService(policy, files, ops), files=files)
        for entry in files.entries(CONTROL):
            if entry.name in ("fixture.lock", "qualification"):
                continue
            model.require(model.proof.matches(model.EXECUTION_ID, entry.name) and controller.load(entry)["phase"] == "settled",
                          "fixture-unresolved")
        model.require(ops.whole_empty(), "fixture-unresolved")
        intent = LinuxIntent.parse({key: value for key, value in command.items() if key != "operation"} |
                                   {"accepted_boot_id": ops.boot()})
        files.directory(root, create=True)
        files.publish(root / "intent.json", model.proof.canonical(intent.value))
        files.directory(JOBS / "qualification", create=not files.exists(JOBS / "qualification"))
        files.directory(JOBS / "qualification" / command["qualification_id"], create=True)
        files.publish(RUNTIME / "pending.json", model.proof.canonical(Selector.create("linux-qualification", intent.value).wire()), exclusive=False)
        ops.systemctl("start")
        files.publish(root / "start-command.json", model.proof.canonical({"schema_version": 1, "intent_sha256": intent.digest,
                                                                          "boot_id": intent.value["accepted_boot_id"]}))
        def ready():
            if not files.exists(root / "native.json"):
                return None
            try:
                value = NativeFixtureReceipt.parse(model.document(files.read(root / "native.json", 64 << 10)))
            except PendingPublication:
                return None
            model.require(value.intent_sha256 == intent.digest and value.owner.boot_id == ops.boot(), "qualification-native-changed")
            return value
        receipt = wait_file(root / "native.json", ready, STARTUP_SECONDS)
        if intent.value["case"] in ("startup-withheld", "crash-before-release"):
            if intent.value["case"] == "crash-before-release":
                return crash_fixture(intent, receipt, files, ops)
            return linux_observe(intent, files, ops, stop=True)
        release = linux_release(intent, receipt)
        files.publish(root / "authorization.json", model.proof.canonical(release | {"native_receipt": asdict(receipt)}))
        model.require(ops.exchange(receipt, release) == {"schema_version": 1, "released": True, "intent_sha256": intent.digest},
                      "service-release-unconfirmed")
        if intent.value["case"] in ("descendant-stop", "crash-after-release"):
            path = JOBS / "qualification" / command["qualification_id"] / "action.json"
            action = wait_file(path, lambda: files.read(path, 64 << 10) if files.exists(path) else None, STARTUP_SECONDS)
            fixture_action(action, intent, policy)
            files.publish(root / "observations.json", action)
            if intent.value["case"] == "descendant-stop":
                return linux_observe(intent, files, ops, stop=True)
            return crash_fixture(intent, receipt, files, ops)
        if intent.value["case"] in ("initiator-disconnect", "reboot-observation"):
            path = JOBS / "qualification" / command["qualification_id"] / "action.json"
            action = wait_file(path, lambda: files.read(path, 64 << 10) if files.exists(path) else None, STARTUP_SECONDS)
            fixture_action(action, intent, policy)
            files.publish(root / "observations.json", action)
            helper = ops.process(os.getpid())
            files.publish(root / "initiator.json", model.proof.canonical({"schema_version": 1,
                          "boot_id": ops.boot(), "pid": helper.pid, "start": helper.start}))
        return linux_observe(intent, files, ops)


def original_windows_fence(job, files):
    marker_raw = files.read(job.output / "private/run-journal.json", 4096)
    marker = model.document(marker_raw)
    exact(marker, ("schema_version", "run_id"))
    model.require(model.proof.matches(model.proof.RUN_ID, marker["run_id"]), "run-locator-unavailable")
    journal = job.config / "runs" / (marker["run_id"] + ".json")
    claim_raw, pin_raw = files.read(journal, 16 << 10), files.read(journal.with_suffix(".session.json"), 16 << 10)
    record, pin = model.document(claim_raw), model.document(pin_raw)
    exact(record, ("schema_version", "claim", "target_fingerprint"))
    exact(pin, ("schema_version", "run_id", "claim", "target_fingerprint", "session_id"))
    exact(record["claim"], ("schema_version", "run_id", "request_id", "controller_id", "deadline", "request_hash", "task_name"))
    model.require(pin["claim"] == record["claim"] and pin["target_fingerprint"] == record["target_fingerprint"]
                  and pin["run_id"] == record["claim"]["run_id"] == marker["run_id"]
                  and model.proof.matches(model.proof.HASH, record["target_fingerprint"])
                  and all(isinstance(record["claim"][key], str) and record["claim"][key].strip()
                          for key in ("controller_id", "task_name")), "qualification-original-changed")
    fence = model.proof.Fence.parse(record["claim"] | {"session_id": pin["session_id"]})
    return fence, {"marker_sha256": model.proof.digest(marker_raw), "claim_sha256": model.proof.digest(claim_raw),
                   "session_pin_sha256": model.proof.digest(pin_raw)}


def accept_active_checkpoint(controller, context, files, ops):
    root = CONTROL / context.execution_id
    with controller.locked():
        state = controller.load(root)
        model.require(state["phase"] == "running" and state["attempt"] == 1, "qualification-run-not-active")
        job = controller.job(root, state)
        context.verify_inputs(files, job)
        checkpoint = model.document(files.read(job.attempt_root / "active-checkpoint.json", 64 << 10))
        exact(checkpoint, ("schema_version", "kind", "execution_id", "attempt", "inputs_digest", "run_id", "request_id",
                          "request_hash", "deadline", "session_id", "marker_sha256", "claim_sha256", "session_pin_sha256",
                          "client_sha256", "target_sha256", "status_sha256", "observed_at"))
        fence, hashes = original_windows_fence(job, files)
        public = model.document(files.read(job.attempt_root / "active-commands/command-001.stdout", 64 << 10))
        model.require(checkpoint["kind"] == "windows-active-checkpoint"
                      and checkpoint["execution_id"] == job.request.execution_id and checkpoint["attempt"] == 1
                      and checkpoint["inputs_digest"] == job.inputs_digest
                      and all(checkpoint[key] == value for key, value in hashes.items())
                      and checkpoint["client_sha256"] == job.expected_client_sha256
                      and checkpoint["target_sha256"] == context.authorization.value["target_sha256"]
                      and checkpoint["status_sha256"] == model.proof.digest(model.proof.canonical(public))
                      and model.proof.Fence.parse(checkpoint) == fence == model.proof.Fence.parse(public)
                      and public.get("state") in ("running", "calling") and not public.get("error"),
                      "qualification-run-not-active")
        from datetime import datetime, timezone
        remaining = (datetime.fromisoformat(fence.deadline.replace("Z", "+00:00")) - datetime.now(timezone.utc)).total_seconds()
        model.require(remaining >= 900, "qualification-checkpoint-deadline")
        bound = controller.bound_attempt(root, state)
        model.require(bound is not None and bound.process == "live" and bound.release == "uncertain"
                      and asdict(bound.invocation) == state["invocation"], "qualification-native-changed")
        retained = controller.worker.recovery_inputs(job)
        state["recovery_inputs"] = retained
        controller.save(root, state)
        record = {"schema_version": 1, "checkpoint": checkpoint, "native_receipt": asdict(controller.service.receipt(bound.invocation))}
        files.publish(root / "active-checkpoint.json", model.proof.canonical(record))
        if context.case == "windows-crash-recover":
            state.update(closed=True, proof_result="fail", phase="unresolved")
            controller.save(root, state)
            controller.terminate(state)
            controller.save(root, state)
            files.publish(root / "interruption.json", model.proof.canonical({"schema_version": 1,
                          "active_checkpoint_sha256": model.proof.digest(files.read(root / "active-checkpoint.json", 64 << 10)),
                          "original_native_sha256": model.proof.digest(model.proof.canonical(record["native_receipt"])),
                          "observed_at_unix": int(time.time()), "local_termination": "proven"}))
        return controller.receipt(state)


def validate_cleanup(context, policy, files, job, *, accept=False, observe=False):
    cleanup = context.cleanup
    model.require(type(cleanup) is CleanupAuthorization, "qualification-cleanup-invalid")
    fence, _ = original_windows_fence(job, files)
    value = cleanup.value
    model.require(value["original_authorization_sha256"] == context.authorization.digest
                  and value["execution_id"] == context.execution_id
                  and value["original_run_id"] == fence.run_id and value["original_session_id"] == fence.session_id
                  and value["original_request_sha256"] == fence.request_hash
                  and model.proof.Fence.parse({"schema_version": 1, "run_id": fence.run_id, "request_id": fence.request_id,
                       "request_hash": fence.request_hash, "session_id": fence.session_id,
                       "deadline": value["original_run_deadline"]}) == fence
                  and value["inputs_sha256"] == job.inputs_digest
                  and value["policy_sha256"] == policy.digest and value["installation_sha256"] == installation_digest(policy),
                  "qualification-cleanup-changed")
    context.verify_inputs(files, job)
    if not observe:
        model.require(time.time() < value["recovery_deadline_unix"], "qualification-expired")
    if accept:
        model.require(time.time() < value["recovery_deadline_unix"] <= time.time() + 86400, "qualification-deadline-invalid")


def cleanup_qualification_command(command, policy, files, ops):
    root = CONTROL / command["execution_id"]
    authority = QualificationAuthorization.parse(files.read(root / "qualification-authorization.json", QUALIFICATION_LIMIT))
    origin = model.document(files.read(root / "origin.json", QUALIFICATION_LIMIT))
    accepted = root / "cleanup-authorizations"
    retained_path = accepted / (command["cleanup_authorization_id"] + ".json")
    source = retained_path if files.exists(retained_path) else CONFIG / "qualification-cleanup" / (command["cleanup_authorization_id"] + ".json")
    cleanup = CleanupAuthorization.parse(files.read(source, QUALIFICATION_LIMIT))
    model.require(cleanup.digest == command["cleanup_authorization_sha256"]
                  and cleanup.value["authorization_id"] == command["cleanup_authorization_id"], "qualification-cleanup-changed")
    context = WindowsQualification(authority, origin["case"], cleanup)
    model.require(context.execution_id == command["execution_id"] and context.origin == origin, "qualification-origin-changed")
    controller = model.Controller(CONTROL, JOBS, policy.controller, NativeService(policy, files, ops, context),
                                  files=files, admission=policy.admit, qualification=context)
    with controller.locked():
        state = controller.load(root)
        validate_cleanup(context, policy, files, controller.job(root, state), accept=not files.exists(retained_path),
                         observe=command["operation"] == "status")
        if not files.exists(retained_path):
            files.directory(accepted, create=not files.exists(accepted))
            model.require(len(files.entries(accepted)) < 16, "qualification-capacity")
            files.publish(retained_path, cleanup.raw)
    response = qualification_dispatch(controller, command["operation"], context)
    return windows_readiness(controller, context) if command["operation"] == "stop" else response


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


    @property
    def owner(self):
        inv = self.invocation
        return ProcessOwner(inv.boot_id, inv.invocation_id, inv.cgroup, inv.leader_pid, inv.leader_start_ticks,
                            inv.parent_pid, self.supervisor_start, self.cgroup_device, self.cgroup_inode)


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
                   ((CONFIG, 0, 0, "0700"), (CONFIG / "qualification-authorizations", 0, 0, "0700"),
                    (CONFIG / "qualification-cleanup", 0, 0, "0700"), (CONTROL, 0, 0, "0700"), (JOBS, value["runner_uid"], value["runner_gid"], "0700"),
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


def load_prepared(*, windows=False, launch=False):
    model.require(sys_platform_linux() and os.getuid() == os.geteuid() == 0, "native-adapter-unqualified")
    raw = protected_read(CONFIG / "policy.json", model.MAX_FILE, private=True)
    policy = NativePolicy.parse(raw)
    achieved = model.document(protected_read(CONFIG / "qualification.json", model.MAX_FILE, private=True))
    exact(achieved, ("schema_version", "qualified", "policy_sha256", "evidence"), "native-adapter-unqualified")
    model.require(type(achieved["qualified"]) is bool and achieved["policy_sha256"] == policy.digest
                  and isinstance(achieved["evidence"], dict) and set(achieved["evidence"]) == set(QUALIFICATIONS),
                  "native-adapter-unqualified")
    if achieved["qualified"]:
        policy.qualify(model.proof.canonical(achieved))
        model.require(not launch, "qualification-already-achieved")
    else:
        model.require(all(item is None or model.proof.matches(model.proof.HASH, item)
                          for item in achieved["evidence"].values()), "native-adapter-unqualified")
    for path, expected in policy.value["artifacts"].items():
        model.require(model.proof.digest(protected_read(Path(path))) == expected, "native-source-untrusted")
    for path, expected in policy.value["tool_sha256"].items():
        model.require(model.proof.digest(tool_read(Path(path))) == expected, "native-source-untrusted")
    model.no_links(CANDIDATE)
    for path in (CANDIDATE, *CANDIDATE.parents):
        info = path.stat()
        model.require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o022 == 0,
                      "native-source-untrusted")
    if windows:
        validate_windows_inputs()
    files = FixtureFiles(RootedFiles(CONTROL, 0, 0),
                         RootedFiles(JOBS, policy.value["runner_uid"], policy.value["runner_gid"]),
                         RootedFiles(CONFIG, 0, 0), RootedFiles(RUNTIME, 0, 0))
    return policy, files


def validate_windows_inputs():
    operator = model.document(protected_read(CONFIG / "operator.json", 64 << 10, private=True))
    model.require(operator.get("ssh_config") == str(CONFIG / "ssh-config"), "native-source-untrusted")
    connection = model.ssh_connection(protected_read(CONFIG / "ssh-config", 64 << 10, private=True),
                                      operator["target"]["ssh_alias"])
    model.require(connection["identityfile"] == str(CONFIG / "key")
                  and connection["userknownhostsfile"] == str(CONFIG / "known_hosts"), "native-source-untrusted")
    for name in ("key", "known_hosts"):
        protected_read(CONFIG / name, 64 << 10, private=True)


def load_runtime():
    try:
        policy = NativePolicy.parse(protected_read(CONFIG / "policy.json", model.MAX_FILE, private=True))
        policy.qualify(protected_read(CONFIG / "qualification.json", model.MAX_FILE, private=True))
        prepared, files = load_prepared(windows=True)
        model.require(prepared == policy, "native-policy-changed")
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
            process = self.process(receipt.owner.parent_pid)
        except FileNotFoundError:
            return True
        return process.start != receipt.owner.supervisor_start

    def end_supervisor(self, receipt):
        if self.supervisor_gone(receipt):
            return
        fd = os.pidfd_open(receipt.owner.parent_pid)
        try:
            current = self.process(receipt.owner.parent_pid)
            model.require(current.start == receipt.owner.supervisor_start and current.cgroup == UNIT_CGROUP,
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
        fd = os.pidfd_open(receipt.owner.parent_pid)
        try:
            current = self.process(receipt.owner.parent_pid)
            model.require(current.start == receipt.owner.supervisor_start and current.cgroup == UNIT_CGROUP,
                          "native-supervisor-changed")
            poller = select.poll()
            poller.register(fd, select.POLLIN)
            remaining = deadline - time.monotonic()
            return bool(remaining > 0 and poller.poll(max(1, int(remaining * 1000))))
        finally:
            os.close(fd)

    def stop(self, receipt):
        if self.boot() != receipt.owner.boot_id:
            return self.whole_empty()
        deadline = time.monotonic() + STOP_SECONDS
        with self.group(receipt.owner.cgroup) as fd:
            info = os.fstat(fd)
            model.require((info.st_dev, info.st_ino) == (receipt.owner.cgroup_device, receipt.owner.cgroup_inode),
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
            model.require(uid == 0 and pid == receipt.owner.parent_pid
                          and self.process(pid).start == receipt.owner.supervisor_start, "native-peer-invalid")
            connection.sendall(model.proof.canonical(request))
            return model.document(connection.recv(model.MAX_WIRE + 1), model.MAX_WIRE)


def operational_pending(raw):
    selected = Selector.parse(raw)
    model.require(selected.kind == "operational", "native-selector-invalid")
    return selected.intent


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
                      and type(value["schema_version"]) is int and value["schema_version"] == 1
                      and isinstance(value["intent"], dict),
                      "startup-failure-invalid")
        if "authorization_sha256" in value["intent"]:
            parse_windows_intent(value["intent"])
        else:
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
    def __init__(self, policy, files, ops, qualification=None):
        self.policy, self.files, self.ops = policy, files, ops
        model.require(qualification is None or type(qualification) is WindowsQualification, "qualification-authority-invalid")
        self.qualification = qualification

    def intent(self, raw):
        if self.qualification is None:
            return parse_intent(raw)
        value = parse_windows_intent(model.document(raw))
        current = qualification_context(self.files, value)
        model.require(current.authorization == self.qualification.authorization and current.case == self.qualification.case,
                      "qualification-origin-changed")
        return value

    def pending(self, raw):
        selected = Selector.parse(raw)
        model.require(selected.kind == ("operational" if self.qualification is None else "windows-qualification"),
                      "native-selector-invalid")
        return self.intent(model.proof.canonical(selected.intent))

    def expected_intent(self, request, attempt):
        mode = "baseline" if attempt == 1 else "recover"
        if self.qualification is not None:
            return self.qualification.intent(request, attempt, mode)
        return {"schema_version": 1, "execution_id": request.execution_id, "attempt": attempt,
                "request_digest": request.digest, "mode": mode}

    def expected_authorization(self, receipt, mode):
        if self.qualification is not None:
            return self.qualification.release_record(self.files, receipt, mode) | {"native_receipt": asdict(receipt)}
        return {"schema_version": 1, "invocation": asdict(receipt.invocation), "mode": mode}

    def receipt(self, invocation):
        value = NativeReceipt.parse(model.document(self.files.read(receipt_path(invocation))))
        model.require(value.invocation == invocation, "native-receipt-invalid")
        return value

    def durable_attempt(self, request, attempt, saved_invocation):
        identity = {"execution_id": request.execution_id, "attempt": attempt}
        path = attempt_path(identity, "native")
        if not self.files.exists(path):
            return None
        receipt = NativeReceipt.parse(model.document(self.files.read(path)))
        inv = receipt.invocation
        intent_raw = self.files.read(attempt_path(identity, "intent"))
        intent = self.intent(intent_raw)
        model.require((inv.execution_id, inv.attempt, inv.request_digest) ==
                      (request.execution_id, attempt, request.digest)
                      and (saved_invocation is None or saved_invocation == inv)
                      and (intent == self.expected_intent(request, attempt) if self.qualification is None else
                           intent == qualification_context(self.files, intent).intent(request, attempt, intent["mode"])),
                      "native-attempt-invalid")
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
            model.require(model.document(self.files.read(authorization)) == (self.expected_authorization(receipt, intent["mode"]) if self.qualification is None else
                qualification_context(self.files, intent).release_record(self.files, receipt, intent["mode"]) | {"native_receipt": asdict(receipt)}), "native-authorization-invalid")
        if completed:
            record = model.document(self.files.read(result))
            model.require(isinstance(record, dict) and set(record) == {"schema_version", "invocation", "mode", "result"}
                          and type(record["schema_version"]) is int and record["schema_version"] == 1 and record["invocation"] == asdict(inv)
                          and record["mode"] == intent["mode"], "proof-result-invalid")
        return receipt, intent, authorized, record if completed else None

    def inspect_attempt(self, request, attempt, saved_invocation):
        durable = self.durable_attempt(request, attempt, saved_invocation)
        if durable is None:
            return None
        receipt, intent, authorized, record = durable
        inv, completed = receipt.invocation, record is not None
        boot, unit = self.ops.boot(), self.ops.unit()
        pending_path = RUNTIME / "pending.json"
        pending = self.pending(self.files.read(pending_path)) if self.files.exists(pending_path) else None
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
        raw = self.files.read(RUNTIME / "pending.json")
        selected = Selector.parse(raw)
        expected_kind = "operational" if self.qualification is None else "windows-qualification"
        if selected.kind != expected_kind:
            model.require(empty and self.ops.whole_empty(), "fixture-unresolved")
            return model.ServiceObservation(boot, None, True)
        if selected.kind == "windows-qualification":
            previous = qualification_context(self.files, selected.intent)
            if previous.authorization != self.qualification.authorization or previous.case != self.qualification.case:
                model.require(empty, "fixture-unresolved")
                historical = NativeService(self.policy, self.files, self.ops, previous)
                controller = model.Controller(CONTROL, JOBS, self.policy.controller, historical,
                                              files=self.files, qualification=previous)
                root = CONTROL / previous.execution_id
                state = controller.load(root)
                model.require(state["phase"] == "settled", "fixture-unresolved")
                job = controller.job(root, state)
                bound = historical.inspect_attempt(job.request, state["attempt"],
                    model.Invocation.parse(state["invocation"]) if state["invocation"] else None)
                if bound is None:
                    model.require(state["invocation"] is None
                                  and historical.unreleased(job.request, state["attempt"], fresh=True) is not None,
                                  "fixture-unresolved")
                else:
                    model.require(bound.process == "gone", "fixture-unresolved")
                model.require(self.ops.boot() == boot and self.ops.whole_empty(), "fixture-unresolved")
                return model.ServiceObservation(boot, None, True)
        pending = self.pending(raw)
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
        intent = self.intent(self.files.read(intent_path))
        model.require(intent["request_digest"] == request.digest and intent["attempt"] == attempt
                      and intent["execution_id"] == request.execution_id and self.ops.whole_empty(), "fixture-unresolved")
        reject_unreleased(self.files, intent)
        self.files.publish(RUNTIME / "pending.json", model.proof.canonical(Selector.create("operational" if self.qualification is None else "windows-qualification", intent).wire()), exclusive=False)
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
        release = {"schema_version": 1, "operation": "release", "invocation": asdict(invocation),
                   "authorization_sha256": model.proof.digest(raw)}
        if self.qualification is not None:
            release = self.qualification.release_record(self.files, receipt, mode)
            model.require(model.document(raw) == release | {"native_receipt": asdict(receipt)}, "native-authorization-invalid")
        response = self.ops.exchange(receipt, release)
        return response == {"schema_version": 1, "released": True, "invocation": asdict(invocation)}

    def unreleased(self, request, attempt, *, fresh=False, publish=False):
        identity = {"execution_id": request.execution_id, "attempt": attempt}
        failure_path = attempt_path(identity, "startup-failure")
        issuer_path = attempt_path(identity, "start-command")
        if not self.files.exists(failure_path) or not self.files.exists(issuer_path):
            return None
        def evidence():
            intent_raw = self.files.read(attempt_path(identity, "intent"))
            intent = self.intent(intent_raw)
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
                model.require(self.pending(self.files.read(RUNTIME / "pending.json")) == intent, "fixture-unresolved")
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
        if args in (["qualification"], ["qualify-windows"], ["qualification-cleanup"]):
            model.require(os.getuid() == os.geteuid() == 0, "qualification-root-required")
            family = {"qualification": "linux", "qualify-windows": "windows", "qualification-cleanup": "cleanup"}[args[0]]
            command = parse_qualification_command(sys.stdin.buffer.read(QUALIFICATION_LIMIT + 1), family)
            policy, files = load_prepared(launch=command["operation"] == "start")
            ops = LinuxOps(policy)
            result = (windows_qualification_command(command, policy, files, ops) if family == "windows" else
                      linux_qualification_command(command, policy, files, ops) if family == "linux" else
                      cleanup_qualification_command(command, policy, files, ops))
            print(model.proof.canonical(result).decode())
            return 0
        model.require(args == ["dispatch"], "invalid-command")
        command = model.parse_command(sys.stdin.buffer.read(model.MAX_WIRE + 1))
        policy, files = load_runtime()
        ops = LinuxOps(policy)
        controller = model.Controller(CONTROL, JOBS, policy.controller, NativeService(policy, files, ops),
                                      files=files, admission=policy.admit)
        result = controller.dispatch(command)
        raw = model.proof.canonical(result)
        if command.operation == "collect":
            model.require(len(raw) <= model.MAX_COLLECT_RESPONSE, "collect-response-too-large")
            sys.stdout.buffer.write(raw)
        else:
            print(raw.decode())
        return 0
    except (OSError, model.ControllerError, model.proof.ProofError, subprocess.SubprocessError, KeyError, TypeError, ValueError) as error:
        code = error.code if isinstance(error, model.ControllerError) else "native-unavailable"
        print(model.proof.canonical({"schema_version": 1, "status": "error", "code": code}).decode())
        return 1


if __name__ == "__main__":
    raise SystemExit(entrypoint())
