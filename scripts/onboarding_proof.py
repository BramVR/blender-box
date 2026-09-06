#!/usr/bin/env python3
"""Opt-in prepared Windows proofs, through the public Blender Box CLI."""

import argparse
import base64
import dataclasses
import datetime
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
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
INSTALL_REQUIRED = ("install-inspect", "install-preview", "install-apply", "install-target",
                    "install-repeat", "remove-preview", "remove-apply", "remove-repeat", "fixture-preserved")
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


def document(raw, version=1):
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
    require(type(value.get("schema_version")) is int and value["schema_version"] == version,
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
        require(kind in (b"IHDR", b"IDAT", b"IEND", b"sRGB", b"gAMA", b"cHRM", b"pHYs", b"eXIf", b"oFFs"),
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
            elif kind == b"eXIf":
                require(size == 54 and data[:8] == struct.pack(">2sHI", b"MM", 42, 24)
                        and data[24:26] == b"\x00\x02", "png-metadata-not-allowed")
                require(struct.unpack(">HHIIHHIII", data[26:]) == (282, 5, 1, 8, 283, 5, 1, 16, 0),
                        "png-metadata-not-allowed")
                require(all(0 < value <= 1_000_000 for value in struct.unpack(">IIII", data[8:24])),
                        "png-metadata-not-allowed")
            elif kind == b"oFFs":
                require(data == b"\x00" * 9, "png-metadata-not-allowed")
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


def verify_readiness(record, required_checks=CHECKS):
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
        if check["id"] in required_checks:
            require(check["required"] and check["passed"], "readiness-failed")
        if check["required"]:
            require(check["passed"], "readiness-failed")
    require(required_checks <= seen, "readiness-failed")


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


def windows_expected_host(expected):
    require(set(expected) == {"hostname", "windows_build", "blender_version", "identity_sid", "daemon_sha256"}
            and matches(r"[A-Za-z0-9_.-]{1,128}", expected.get("hostname"))
            and matches(r"\d{4,6}", expected.get("windows_build"))
            and matches(r"\d+\.\d+(?:\.\d+)?", expected.get("blender_version"))
            and matches(r"S-1-\d+(?:-\d+)+", expected.get("identity_sid"))
            and matches(HASH, expected.get("daemon_sha256")), "operator-config-invalid")


@dataclasses.dataclass(frozen=True)
class Operator:
    target: dict
    expected: dict
    fixture: dict
    authorization: dict
    ssh_config: Path | None
    publish_viewport: bool = False

    validate_target = staticmethod(windows_target)
    validate_expected = staticmethod(windows_expected_host)

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
        cls.validate_target(target)
        cls.validate_expected(expected)
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


def windows_path(value):
    require(isinstance(value, str) and len(value) <= 240 and re.fullmatch(r"[A-Za-z]:\\[^\x00-\x1f<>\"|?*]+", value)
            and all(p and p not in (".", "..") and not p.endswith((" ", ".")) and ":" not in p
                    and not re.fullmatch(r"(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])", p.split(".")[0])
                    for p in value[3:].split("\\")), "installer-path-invalid")
    return PureWindowsPath(value)


def pinned_file(value):
    require(isinstance(value, dict) and set(value) == {"path", "size", "sha256"}
            and type(value.get("size")) is int and 0 < value["size"] <= 64 << 20
            and matches(HASH, value.get("sha256")), "installer-pin-invalid")
    windows_path(value["path"])
    return value


@dataclasses.dataclass(frozen=True)
class InstallOperator:
    connection: dict
    expected: dict
    fixture: dict
    installation: dict
    bootstrap: dict
    manifest: dict
    raw_manifest: bytes
    manifest_pin: dict
    before: dict
    authorization: dict
    ssh_config: Path | None
    publish_viewport: bool

    @property
    def windows(self):
        artifacts = {item["role"]: item for item in self.manifest["artifacts"]}
        return {"schema_version": 1, "ssh_alias": self.connection["ssh_alias"],
                "ssh_user": self.connection["windows_user"], "interactive_user": self.connection["windows_user"],
                "work_root": self.installation["state_root"], "task_name": self.installation["task_name"],
                "host_executable": artifacts["host-executable"]["name"],
                "session_broker_executable": artifacts["daemon-launcher"]["name"],
                "blender_executable": self.installation["blender"]}

    @property
    def manifest_sha256(self):
        # Go hashes the typed manifest in declaration order, independent of source formatting.
        fields = ("schema_version", "platform", "architecture", "artifacts", "python_requires",
                  "daemon_protocol", "daemon_capabilities")
        ordered = {key: self.manifest[key] for key in fields}
        ordered["artifacts"] = [{**{key: item[key] for key in ("role", "name", "size", "sha256")},
                                 "provenance": {key: item["provenance"][key] for key in
                                                ("repository", "source_commit", "patch_sha256", "build_recipe_sha256")}}
                                for item in self.manifest["artifacts"]]
        encoded = json.dumps(ordered, separators=(",", ":"), ensure_ascii=False)
        for character in ("&", "<", ">", "\u2028", "\u2029"):
            encoded = encoded.replace(character, "\\u" + format(ord(character), "04x"))
        return digest(encoded.encode())

    @classmethod
    def load(cls, path, candidate):
        require(path.is_file() and not path.is_symlink(), "operator-config-missing")
        require(os.name == "nt" or path.stat().st_mode & 0o077 == 0, "operator-config-permissions")
        data = document(read_regular(path.parent, path.name, 64 << 10))
        require(set(data) <= {"schema_version", "platform", "connection", "expected_host", "fixture", "installation",
                              "bootstrap", "runtime", "before_state", "authorization", "ssh_config", "publish_viewport"}
                and data.get("platform") == "windows", "installer-config-invalid")
        connection, expected = data.get("connection"), data.get("expected_host")
        fixture, installation, runtime = data.get("fixture"), data.get("installation"), data.get("runtime")
        before, auth = data.get("before_state"), data.get("authorization")
        require(all(isinstance(v, dict) for v in (connection, expected, fixture, installation, runtime, before, auth)),
                "installer-config-invalid")
        require(set(connection) == {"ssh_alias", "windows_user"}
                and matches(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", connection.get("ssh_alias"))
                and matches(r"[A-Za-z0-9_.@\\-]{1,128}", connection.get("windows_user")), "installer-config-invalid")
        require(set(fixture) == {"id", "kind", "state"} and matches(r"[a-z0-9-]{1,64}", fixture.get("id"))
                and fixture.get("id") != "windows-onboarding-prepared-v1"
                and fixture.get("kind") == "dedicated" and fixture.get("state") == "absent", "installer-fixture-not-authorized")
        require(set(installation) == {"id", "state_root", "task_name", "blender", "python", "target_out"}
                and matches(r"bbxi_[a-f0-9]{32}", installation.get("id"))
                and matches(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", installation.get("task_name")), "installer-config-invalid")
        for key in ("state_root", "blender", "python", "target_out"):
            windows_path(installation[key])
        state_root, target_out = windows_path(installation["state_root"]), windows_path(installation["target_out"])
        require(target_out != state_root and state_root not in target_out.parents, "installer-scope-overlap")
        bootstrap = pinned_file(data.get("bootstrap"))
        require(set(runtime) == {"local_manifest", "remote_manifest"}
                and isinstance(runtime.get("local_manifest"), str), "installer-config-invalid")
        manifest_pin = pinned_file(runtime.get("remote_manifest"))
        local = Path(runtime["local_manifest"])
        require(local.is_absolute(), "installer-config-invalid")
        raw = read_regular(local.parent, local.name, 128 << 10)
        require(len(raw) == manifest_pin["size"] and digest(raw) == manifest_pin["sha256"], "installer-manifest-mismatch")
        manifest = document(raw)
        require(set(manifest) == {"schema_version", "platform", "architecture", "artifacts", "python_requires",
                                  "daemon_protocol", "daemon_capabilities"}
                and manifest.get("platform") == "windows" and manifest.get("architecture") == "amd64"
                and manifest.get("python_requires") == ">=3.11,<4" and manifest.get("daemon_protocol") == "blender-box-v1"
                and manifest.get("daemon_capabilities") == ["typed-call-error-reason"]
                and isinstance(manifest.get("artifacts"), list) and len(manifest["artifacts"]) == 3,
                "installer-manifest-invalid")
        roles, paths = set(), set()
        for item in manifest["artifacts"]:
            require(isinstance(item, dict) and set(item) == {"role", "name", "size", "sha256", "provenance"}
                    and item.get("role") in {"host-executable", "daemon-launcher", "daemon-wheel"}
                    and item["role"] not in roles, "installer-manifest-invalid")
            pinned_file({"path": item["name"], "size": item["size"], "sha256": item["sha256"]})
            require(item["name"].casefold() not in paths, "installer-manifest-invalid")
            roles.add(item["role"])
            paths.add(item["name"].casefold())
            source = item["provenance"]
            require(isinstance(source, dict) and set(source) == {"repository", "source_commit", "patch_sha256", "build_recipe_sha256"}
                    and matches(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", source.get("repository"))
                    and matches(SHA, source.get("source_commit")) and matches(HASH, source.get("patch_sha256"))
                    and matches(HASH, source.get("build_recipe_sha256")), "installer-provenance-invalid")
            if item["role"] != "daemon-wheel":
                require(source["source_commit"] == candidate and source["repository"] == "BramVR/blender-box",
                        "installer-candidate-mismatch")
        require(set(expected) == {"hostname", "windows_build", "blender_version", "identity_sid", "daemon_sha256"}
                and matches(r"[A-Za-z0-9_.-]{1,128}", expected.get("hostname"))
                and matches(r"\d{4,6}", expected.get("windows_build"))
                and matches(r"\d+\.\d+(?:\.\d+)?", expected.get("blender_version"))
                and matches(r"S-1-\d+(?:-\d+)+", expected.get("identity_sid"))
                and expected.get("daemon_sha256") == next(x["sha256"] for x in manifest["artifacts"] if x["role"] == "daemon-launcher"),
                "installer-config-invalid")
        require(set(before) == {"installation_absent", "task_absent", "target_absent", "unrelated_files", "unrelated_tasks"}
                and all(before.get(k) is True for k in ("installation_absent", "task_absent", "target_absent"))
                and isinstance(before.get("unrelated_files"), list) and 1 <= len(before["unrelated_files"]) <= 32
                and isinstance(before.get("unrelated_tasks"), list) and len(before["unrelated_tasks"]) <= 8,
                "installer-before-state-invalid")
        managed = windows_path(installation["state_root"]) / "installations" / installation["id"]
        external = [bootstrap["path"], manifest_pin["path"], installation["blender"], installation["python"],
                    installation["target_out"], *[x["name"] for x in manifest["artifacts"]]]
        for item in before["unrelated_files"]:
            external.append(pinned_file(item)["path"])
            require(windows_path(item["path"]) != windows_path(installation["target_out"]), "installer-scope-overlap")
        for path_value in external:
            value = windows_path(path_value)
            require(value != managed and managed not in value.parents and value not in managed.parents, "installer-scope-overlap")
        for item in before["unrelated_tasks"]:
            require(isinstance(item, dict) and set(item) == {"name", "xml_sha256"}
                    and matches(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", item.get("name"))
                    and item["name"].casefold() != installation["task_name"].casefold()
                    and matches(HASH, item.get("xml_sha256")), "installer-scope-overlap")
        expected_auth = {"candidate_sha": candidate, "fixture_id": fixture["id"], "installation_id": installation["id"],
                         "manifest_sha256": manifest_pin["sha256"], "destination_sha256": digest(canonical(installation)),
                         "before_state_sha256": digest(canonical(before)), "bootstrap_sha256": digest(canonical(bootstrap)),
                         "connection_sha256": digest(canonical(connection)), "expected_host_sha256": digest(canonical(expected)),
                         "scope": "host-install-run-remove", "launch": True}
        require(canonical(auth) == canonical(expected_auth), "installer-not-authorized")
        ssh = data.get("ssh_config")
        require(ssh is None or isinstance(ssh, str), "installer-config-invalid")
        require(type(data.get("publish_viewport", False)) is bool, "installer-config-invalid")
        return cls(connection, expected, fixture, installation, bootstrap, manifest, raw, manifest_pin, before, auth,
                   Path(ssh) if ssh else None, data.get("publish_viewport", False))


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
        self.task = "windows-onboarding-baseline"

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

    def run(self, args, timeout=180, stdin=None, marker=False, env=None, recovery=False, limit=24 << 20, cleanup_grace=5,
            expected_error=None):
        require(os.name == "posix" and os.uname().sysname in ("Darwin", "Linux")
                and all(hasattr(os, name) for name in ("waitid", "WNOWAIT", "P_PID")),
                "controller-platform-unsupported")
        require(self.group_cleanup_known, "command-cleanup-unknown")
        require(recovery or not self.cancelled.is_set(), "interrupted")
        require(stdin is None or isinstance(stdin, bytes) and len(stdin) <= 128 << 10, "command-input-limit")
        self.sequence += 1
        prefix = self.private / f"command-{self.sequence:03d}"
        if stdin is not None:
            Path(str(prefix) + ".stdin").write_bytes(stdin)
        identity = {"parent_pid": os.getpid(), "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "command": [str(a) for a in args], "task": self.task}
        errors, outputs, started_threads = [], {}, []
        readers_done = threading.Event()
        tick = threading.Event()
        failure = None

        def leader_exited():
            return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None

        def wait_owned(timeout):
            nonlocal failure
            deadline = time.monotonic() + timeout
            while True:
                try:
                    if leader_exited():
                        return True
                except ChildProcessError:
                    raise
                except OSError as error:
                    failure = failure or error
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                tick.wait(min(0.05, remaining))

        def consume(name, maximum):
            pipe = process.stderr if name == "stderr" else process.stdout
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

        threads = [threading.Thread(target=consume, args=(name, maximum), daemon=True)
                   for name, maximum in (("stderr", 64 << 10), ("stdout", limit))]

        def produce():
            try:
                with process.stdin:
                    process.stdin.write(stdin)
            except BrokenPipeError:
                pass
            except OSError as error:
                errors.append(error)

        def settle_process():
            nonlocal failure
            try:
                try:
                    exited = leader_exited()
                except ChildProcessError:
                    raise
                except OSError as error:
                    failure = failure or error
                    exited = False
                if not exited:
                    os.kill(process.pid, signal.SIGINT)
                    # Run may settle twice and recover status, each with a 30-second deadline.
                    wait_owned(95 if marker else 65 if recovery else cleanup_grace)
                if all(thread.ident is not None for thread in threads) and not readers_done.wait(2):
                    failure = failure or ProofError("command-pipe-timeout")
                # WNOWAIT retains the task-owned group leader identity until all group signals finish.
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
                        if all(thread.ident is not None for thread in threads):
                            readers_done.wait(2)
                process.wait(timeout=5)
            except BaseException as error:
                self.group_cleanup_known = False
                self.unsettled_process = process
                raise ProofError("command-cleanup-unknown") from error
            finally:
                for thread in started_threads:
                    if thread.ident is not None:
                        thread.join(timeout=2)
                if any(thread.is_alive() for thread in started_threads):
                    self.group_cleanup_known = False
                else:
                    for pipe in (process.stdin, process.stdout, process.stderr):
                        if pipe is not None and not pipe.closed:
                            try:
                                pipe.close()
                            except BrokenPipeError:
                                pass
            require(self.group_cleanup_known, "command-cleanup-unknown")

        process = subprocess.Popen(identity["command"], cwd=self.cwd, env=env or self.env,
                                   stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            identity.update(pid=process.pid, process_group=process.pid)
            self.process_identity = identity
            for thread in threads:
                started_threads.append(thread)
                thread.start()
            Path(str(prefix) + ".process.json").write_bytes(canonical(identity))
            if stdin is not None:
                writer = threading.Thread(target=produce, daemon=True)
                started_threads.append(writer)
                writer.start()
            deadline = time.monotonic() + timeout
            while not leader_exited():
                if errors or time.monotonic() >= deadline or (self.cancelled.is_set() and not recovery):
                    failure = errors[0] if errors else ProofError("interrupted" if self.cancelled.is_set() else "command-timeout")
                    break
                tick.wait(0.05)
        except BaseException as error:
            failure = error
        finally:
            settle_process()
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


def host_json(commands, alias, script, **kwargs):
    content = script.encode("utf-8")
    require(len(content) <= 128 << 10, "command-input-limit")
    bootstrap = "[Console]::InputEncoding=[Text.UTF8Encoding]::new($false);[Console]::In.ReadToEnd() | Invoke-Expression"
    command = base64.b64encode(bootstrap.encode("utf-16le")).decode("ascii")
    return commands.json(["ssh", "-o", "RequestTTY=no", "-o", "RemoteCommand=none",
                          "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                          "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes", "--", alias,
                          "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", command],
                         stdin=content, **kwargs)


INSTALL_SHELL = r"""$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$inputData = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__INPUT__')) | ConvertFrom-Json
function Regular([string]$path, [long]$maximum) {
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or $item.Length -lt 1 -or $item.Length -gt $maximum) { throw 'invalid regular file' }
    for ($ancestor = $item; $null -ne $ancestor; $ancestor = $ancestor.Parent) {
        if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse point' }
        if ($ancestor -is [IO.FileInfo]) { $ancestor = $ancestor.Directory; if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse point' } }
    }
    return $item
}
function Pin($pin) {
    $item = Regular $pin.path 67108864
    $stream = [IO.File]::Open($pin.path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $hash = [Security.Cryptography.SHA256]::Create()
        try { $hex = [BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-','').ToLowerInvariant() } finally { $hash.Dispose() }
        if ($stream.Length -ne $pin.size -or $hex -cne $pin.sha256) { throw 'pin mismatch' }
        return $stream
    } catch { $stream.Dispose(); throw }
}
"""


def installer_observation(commands, operator, *, recovery=False):
    inputs = {"installation": operator.installation, "before": operator.before}
    script = INSTALL_SHELL + r"""
$files = @($inputData.before.unrelated_files | ForEach-Object {
    $item = Regular $_.path 67108864
    [ordered]@{path=$_.path;size=$item.Length;sha256=(Get-FileHash -LiteralPath $_.path -Algorithm SHA256).Hash.ToLowerInvariant()}
})
$tasks = @($inputData.before.unrelated_tasks | ForEach-Object {
    $xml = Export-ScheduledTask -TaskName $_.name -TaskPath '\'
    $bytes = [Text.Encoding]::UTF8.GetBytes([string]$xml)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $hex = [BitConverter]::ToString($hash.ComputeHash($bytes)).Replace('-','').ToLowerInvariant() } finally { $hash.Dispose() }
    [ordered]@{name=$_.name;xml_sha256=$hex}
})
$installationPath = [IO.Path]::Combine($inputData.installation.state_root,'installations',$inputData.installation.id)
try { $task = @(Get-ScheduledTask -TaskName $inputData.installation.task_name -TaskPath '\' -ErrorAction Stop) }
catch { if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw }; $task = @() }
[ordered]@{schema_version=1;installation_absent=!(Test-Path -LiteralPath $installationPath);task_absent=($task.Count -eq 0);target_absent=!(Test-Path -LiteralPath $inputData.installation.target_out);unrelated_files=$files;unrelated_tasks=$tasks} | ConvertTo-Json -Depth 8 -Compress
"""
    value = host_json(commands, operator.connection["ssh_alias"],
                      script.replace("__INPUT__", base64.b64encode(canonical(inputs)).decode()), timeout=120, recovery=recovery)
    require(set(value) == set(operator.before) | {"schema_version"}
            and all(type(value[k]) is bool for k in ("installation_absent", "task_absent", "target_absent")),
            "installer-before-state-unknown")
    (commands.private / f"installer-observation-{commands.sequence:03d}.json").write_bytes(canonical(value))
    return {key: value[key] for key in operator.before}


def installer_call(commands, operator, operation, *, operation_id=None, apply=False, expected_plan=None, target_out=False,
                   recovery=False, fresh=False, execution_token=None, recovery_deadline=None):
    selected = operator.installation
    args = ["setup", operation, "--platform", "windows", "--state-root", selected["state_root"], "--json"]
    if not fresh:
        args += ["--installation", selected["id"]]
    if operation in ("inspect", "install"):
        args += ["--blender", selected["blender"], "--python", selected["python"]]
    if operation == "install":
        args += ["--runtime", operator.manifest_pin["path"], "--ssh-alias", operator.connection["ssh_alias"],
                 "--windows-user", operator.connection["windows_user"], "--task-name", selected["task_name"]]
    if operation != "inspect":
        require(matches(r"bbxo_[a-f0-9]{32}", operation_id), "installer-operation-invalid")
        args += ["--operation", operation_id]
    if apply:
        args += ["--apply"]
    if expected_plan and operation in ("install", "remove"):
        args += ["--expected-plan", expected_plan]
    if target_out and operation == "install":
        args += ["--target-out", selected["target_out"]]
    if execution_token is not None:
        require(operation == "stop" and matches(r"bbxe_[a-f0-9]{32}", execution_token), "installer-execution-invalid")
        args += ["--execution", execution_token]
    pins = [operator.bootstrap, operator.manifest_pin,
            *[{"path": a["name"], "size": a["size"], "sha256": a["sha256"]} for a in operator.manifest["artifacts"]]]
    if operation in ("status", "stop"):
        pins = [operator.bootstrap]
    inputs = {"bootstrap": operator.bootstrap["path"], "pins": pins, "args": args}
    script = INSTALL_SHELL + r"""
$leases = [Collections.Generic.List[IO.FileStream]]::new()
try {
    foreach ($pin in $inputData.pins) { $leases.Add((Pin $pin)) }
    $arguments = @($inputData.args | ForEach-Object { [string]$_ })
    $ErrorActionPreference = 'Continue'
    $outputText = (& $inputData.bootstrap @arguments | Out-String)
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    [ordered]@{schema_version=1;exit_code=$code;output=$outputText} | ConvertTo-Json -Depth 2 -Compress
} finally { foreach ($lease in $leases) { $lease.Dispose() } }
"""
    script = script.replace("__INPUT__", base64.b64encode(canonical(inputs)).decode())
    timeout = 45 if operation in ("status", "stop") else 360
    if recovery_deadline is not None:
        timeout = min(timeout, recovery_deadline - time.monotonic())
        require(timeout > 0, "installer-stop-unsettled")
    response = host_json(commands, operator.connection["ssh_alias"], script,
                         timeout=timeout, recovery=recovery, limit=3 << 20)
    require(set(response) == {"schema_version", "exit_code", "output"} and type(response["exit_code"]) is int
            and isinstance(response["output"], str), "installer-response-invalid")
    raw = response["output"].encode()
    (commands.private / f"installer-result-{commands.sequence:03d}.json").write_bytes(raw)
    value = document(raw)
    require(set(value) <= {"schema_version", "operation_id", "installation_id", "state", "completion", "plan", "inspection",
                          "files", "retained", "target", "problems", "target_publication", "execution"}
            and (value.get("installation_id") in (None, "") if fresh else value.get("installation_id") == selected["id"]),
            "installer-identity-changed")
    if operation != "inspect":
        require(value.get("operation_id") == operation_id, "installer-identity-changed")
    observing = operation in ("status", "stop")
    require(value.get("state") in {"planned", "prepared", "installed", "partial", "removing", "removed", "conflict", "running", "unknown"},
            "installer-state-unknown")
    require(value.get("completion") in ("known", "unknown") if observing else value.get("completion") == "known", "installer-state-unknown")
    if apply or observing:
        validate_installer_execution(value, terminal=not observing)
    else:
        require("execution" not in value, "installer-execution-invalid")
    publication = value.get("target_publication")
    require(isinstance(publication, dict) and set(publication) <= {"status", "path", "name", "error"},
            "installer-publication-invalid")
    if target_out:
        require(publication.get("status") in ("published", "failed", "not-published")
                and publication.get("path") == selected["target_out"] and "name" not in publication
                and (isinstance(publication.get("error"), str) if publication["status"] == "failed" else "error" not in publication),
                "installer-publication-invalid")
    else:
        require(publication == {"status": "not-requested"}, "installer-publication-invalid")
    publication_failed = target_out and publication["status"] == "failed" and value["state"] == "installed"
    problems = value.get("problems")
    require(isinstance(problems, list) and len(problems) <= 64
            and all(isinstance(p, dict) and set(p) == {"code", "message"}
                    and isinstance(p["code"], str) and isinstance(p["message"], str) for p in problems),
            "installer-problems-invalid")
    require(observing or problems == [] and (response["exit_code"] == 0 or publication_failed), "installer-operation-failed")
    root = windows_path(selected["state_root"])
    retained = [str(root), str(root / ".operation.lock"), str(root / ".launch.lock"), str(root / "runs"),
                str(root / "receipts"), str(root / "installations" / selected["id"] / "receipt.json")]
    require(value.get("retained") in ([], retained), "installer-retained-unknown")
    inspection = value.get("inspection")
    require(isinstance(inspection, dict) and set(inspection) <= {"owner_sid", "root_identity", "blender_candidates", "python"}
            and inspection.get("owner_sid") == operator.expected["identity_sid"], "installer-owner-changed")
    require(isinstance(inspection.get("root_identity"), str) and isinstance(inspection.get("blender_candidates"), list)
            and len(inspection["blender_candidates"]) <= 32, "installer-inspection-invalid")
    candidates = list(inspection["blender_candidates"])
    if "python" in inspection:
        python = inspection["python"]
        require(isinstance(python, dict) and set(python) == {"candidate", "home", "template", "dll", "venv_source"},
                "installer-inspection-invalid")
        windows_path(python["home"])
        candidates += [python[key] for key in ("candidate", "template", "dll", "venv_source")]
    for candidate in candidates:
        require(isinstance(candidate, dict) and set(candidate) == {"path", "version", "sha256", "identity"}
                and isinstance(candidate["version"], str) and matches(HASH, candidate["sha256"])
                and isinstance(candidate["identity"], str) and candidate["identity"], "installer-inspection-invalid")
        windows_path(candidate["path"])
    if operation in ("inspect", "install"):
        require(len(inspection["blender_candidates"]) == 1
                and inspection["blender_candidates"][0]["path"] == selected["blender"]
                and "python" in inspection and inspection["python"]["candidate"]["path"] == selected["python"],
                "installer-selection-changed")
    plan = value.get("plan")
    require(isinstance(plan, dict) and set(plan) <= {"plan_sha256", "manifest_sha256", "files"}, "installer-plan-invalid")
    if operation != "inspect":
        require(matches(HASH, plan.get("plan_sha256")), "installer-plan-invalid")
    if operation == "install":
        require(plan.get("manifest_sha256") == operator.manifest_sha256, "installer-manifest-mismatch")
    for inventory in (plan.get("files"), value.get("files")):
        require(isinstance(inventory, list) and len(inventory) <= 4096, "installer-inventory-invalid")
        seen = set()
        for item in inventory:
            require(isinstance(item, dict) and set(item) <= {"path", "kind", "size", "sha256", "identity"}
                    and isinstance(item.get("path"), str) and item.get("kind") in ("file", "directory")
                    and type(item.get("size")) is int and 0 <= item["size"] <= 128 << 20
                    and ("sha256" not in item or matches(HASH, item["sha256"]))
                    and ("identity" not in item or isinstance(item["identity"], str)), "installer-inventory-invalid")
            require(all(part and part not in (".", "..") and not part.endswith((" ", "."))
                        and all(ord(c) >= 32 and c not in '\\:<"|?*' for c in part) for part in item["path"].split("/"))
                    and item["path"].casefold() not in seen, "installer-inventory-invalid")
            require((item["kind"] == "file" and "sha256" in item)
                    or (item["kind"] == "directory" and item["size"] == 0 and "sha256" not in item), "installer-inventory-invalid")
            seen.add(item["path"].casefold())
    if operation == "install":
        inventory = {item["path"]: item for item in plan["files"]}
        for role, path in (("host-executable", "runtime/blender-box.exe"), ("daemon-launcher", "runtime/blendersessiond.exe")):
            artifact = next(item for item in operator.manifest["artifacts"] if item["role"] == role)
            require(inventory.get(path) == {"path": path, "kind": "file", "size": artifact["size"], "sha256": artifact["sha256"]},
                    "installer-inventory-mismatch")
        if apply:
            require([{key: v for key, v in item.items() if key != "identity"} for item in value["files"]] == plan["files"]
                    and all(item.get("identity") for item in value["files"]), "installer-inventory-mismatch")
    if expected_plan:
        require(plan.get("plan_sha256") == expected_plan, "installer-plan-changed")
    return value


def validate_installer_execution(result, *, terminal=False):
    execution = result.get("execution")
    require(isinstance(execution, dict) and set(execution) <= {"token", "request_sha256", "deadline", "state", "tree_cleanup",
                                                               "task_mutation", "cancel_requested", "keeper", "worker", "process_state", "fence_state"}
            and matches(r"bbxe_[a-f0-9]{32}", execution.get("token"))
            and matches(HASH, execution.get("request_sha256"))
            and execution.get("state") in {"running", "terminal", "unknown"}
            and execution.get("process_state") in {"started", "not-started", "unknown"}
            and execution.get("fence_state") in {"held", "released"}
            and execution.get("tree_cleanup") in {"known", "unknown"}
            and execution.get("task_mutation") in {"settled", "unknown"}
            and type(execution.get("cancel_requested")) is bool, "installer-execution-invalid")
    try:
        deadline = datetime.datetime.fromisoformat(execution["deadline"].replace("Z", "+00:00"))
        require(deadline.tzinfo is not None, "installer-execution-invalid")
    except (ValueError, KeyError, AttributeError, TypeError) as error:
        raise ProofError("installer-execution-invalid") from error
    for role in ("keeper", "worker"):
        if role not in execution:
            require(execution["state"] == "unknown" and execution["process_state"] == "unknown"
                    or role == "worker" and execution["process_state"] == "not-started", "installer-execution-invalid")
            continue
        identity = execution[role]
        require(isinstance(identity, dict) and set(identity) == {"pid", "created_filetime"}
                and type(identity["pid"]) is int and 0 < identity["pid"] <= 2**32 - 1
                and matches(r"[1-9][0-9]{0,19}", identity["created_filetime"]), "installer-execution-invalid")
    if execution["process_state"] == "not-started":
        require(execution["state"] == "terminal" and result["state"] == "partial" and "worker" not in execution,
                "installer-execution-invalid")
    if execution["state"] == "terminal" or terminal:
        require(execution["state"] == "terminal" and execution["tree_cleanup"] == "known"
                and execution["task_mutation"] == "settled" and result["completion"] == "known", "installer-state-unknown")
    if terminal:
        require(execution["fence_state"] == "released", "installer-state-unknown")
    return execution


def require_same_installer_execution(before, after):
    require(all(before.get(field) == after.get(field) for field in
                ("token", "request_sha256", "deadline")), "installer-execution-changed")
    require(all(role not in before or before[role] == after.get(role) for role in ("keeper", "worker")),
            "installer-execution-changed")
    require(before["process_state"] == "unknown" or before["process_state"] == after["process_state"],
            "installer-execution-changed")


def recover_installer(commands, operator, operation_id, expected_plan, *, target_out=False):
    deadline = time.monotonic() + 15
    observed = installer_call(commands, operator, "status", operation_id=operation_id, expected_plan=expected_plan,
                              target_out=target_out, recovery=True, recovery_deadline=deadline)
    require(time.monotonic() < deadline, "installer-stop-unsettled")
    execution = validate_installer_execution(observed)
    cancellation_attempted = False
    while execution["state"] != "terminal" or execution["fence_state"] != "released":
        require(time.monotonic() < deadline, "installer-stop-unsettled")
        if not cancellation_attempted or execution["state"] == "terminal" and execution["fence_state"] == "held":
            cancellation_attempted = True
            try:
                installer_call(commands, operator, "stop", operation_id=operation_id, apply=True,
                               execution_token=execution["token"], target_out=target_out, recovery=True,
                               recovery_deadline=deadline)
            except Exception:
                pass
        # The cancellation or fence release may have committed despite a lost response.
        observed = installer_call(commands, operator, "status", operation_id=operation_id, expected_plan=expected_plan,
                                  target_out=target_out, recovery=True, recovery_deadline=deadline)
        require(time.monotonic() < deadline, "installer-stop-unsettled")
        latest = validate_installer_execution(observed)
        require_same_installer_execution(execution, latest)
        execution = latest
        if execution["state"] != "terminal" or execution["fence_state"] != "released":
            threading.Event().wait(0.1)
    validate_installer_execution(observed, terminal=True)
    return observed


def installer_target(commands, operator, result, destination):
    target = result.get("target")
    actual = windows_target(target)
    require(target.get("schema_version") == 2, "installer-target-invalid")
    expected = operator.windows
    runtime = windows_path(operator.installation["state_root"]) / "installations" / operator.installation["id"] / "runtime"
    for key in ("ssh_alias", "ssh_user", "interactive_user", "work_root", "task_name", "blender_executable"):
        require(actual[key] == expected[key], "installer-target-changed")
    for key, filename in (("host_executable", "blender-box.exe"), ("session_broker_executable", "blendersessiond.exe")):
        require(windows_path(actual[key]) == runtime / filename, "installer-target-changed")
    inputs = {"path": operator.installation["target_out"]}
    script = INSTALL_SHELL + r"""
$item = Regular $inputData.path 65536
$raw = [IO.File]::ReadAllBytes($item.FullName)
[ordered]@{schema_version=1;content=[Convert]::ToBase64String($raw);sha256=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()} | ConvertTo-Json -Compress
"""
    response = host_json(commands, operator.connection["ssh_alias"],
                         script.replace("__INPUT__", base64.b64encode(canonical(inputs)).decode()), timeout=120, limit=128 << 10)
    require(set(response) == {"schema_version", "content", "sha256"} and isinstance(response.get("content"), str)
            and matches(HASH, response.get("sha256")), "installer-target-invalid")
    try:
        raw = base64.b64decode(response["content"], validate=True)
    except ValueError as error:
        raise ProofError("installer-target-invalid") from error
    require(0 < len(raw) <= 64 << 10 and digest(raw) == response["sha256"], "installer-target-invalid")
    require(document(raw, version=2) == target, "installer-target-changed")
    destination.write_bytes(raw)
    return actual


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
    return host_json(commands, target["ssh_alias"], script, timeout=120)


def write_outcome(public, report):
    temporary = public / "outcome.tmp"
    temporary.write_bytes(canonical(report) + b"\n")
    temporary.replace(public / "outcome.json")


class WindowsProofHost:
    platform = "windows"
    name = "windows-onboarding"
    host_filename = "blender-box.exe"
    proofs = ("baseline", "named-target", "host-install")
    not_exercised = ("pairing", "fixture-reset", "kept-session-stop")

    load_operator = staticmethod(Operator.load)
    verify_setup_authorization = staticmethod(verify_setup_authorization)
    verify_readiness = staticmethod(verify_readiness)

    def inspect(self, commands, operator):
        observed = inspect_host(commands, operator.windows)
        verify_expected_host(operator.expected, observed)
        return observed

    def verify_setup(self, record, operator, host_hash, host_size, applied, planned=None):
        require(record.get("status") == ("applied" if applied else "plan")
                and record.get("applied") is applied and record.get("host_sha256") == host_hash
                and type(record.get("host_size")) is int and record["host_size"] == host_size,
                "setup-apply-mismatch" if applied else "setup-plan-mismatch")

    def public_runtime(self, operator):
        return {"daemon_capabilities": list(CAPABILITIES), "blender_version": operator.expected["blender_version"]}


def baseline(request, commands_factory=Commands, host=None, *, native_authority=None):
    host = host or WindowsProofHost()
    request.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    private, public = request.output / "private", request.output / "public"
    private.mkdir(mode=0o700)
    public.mkdir(mode=0o700)
    named = request.proof == "named-target"
    installing = request.proof == "host-install"
    required = REQUIRED + (INSTALL_REQUIRED if installing else NAMED_REQUIRED if named else ())
    report = {"schema_version": 1, "proof": host.name + "-" + request.proof,
              "candidate_sha": request.candidate_sha if matches(SHA, request.candidate_sha) else None,
              "driver_sha": request.driver_sha if matches(SHA, request.driver_sha) else None,
              "execution": request.execution, "status": "fail", "run": None, "cleanup": None,
              "outcomes": {name: {"status": "not-run", "code": "not-run"} for name in required},
              "not_exercised": list(host.not_exercised), "artifacts": []}
    if installing:
        report["not_exercised"] += ["installer-interruption", "active-run-removal-refusal", "active-session-removal-refusal"]
    commands = commands_factory(private, request.candidate_checkout)
    commands.task = host.name + "-baseline"
    commands.env["BLENDER_BOX_CONFIG_DIR"] = str((private / "config").absolute())
    def publish_run_id(run_id):
        report["run"] = {"run_id": run_id}
        write_outcome(public, report)
    commands.on_run_id = publish_run_id
    current, run, target_path, client = "preparation", None, private / "target.json", private / "blender-box"
    selector = ["--target", target_path]
    catalog_attempted, replacement_attempted = False, False
    installation_owned, install_attempted, scenario_attempted = False, False, False
    original_observation = None
    old_signals = {}
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGINT, signal.SIGTERM):
            old_signals[sig] = signal.signal(sig, lambda *_: commands.cancelled.set())
    try:
        require(matches(SHA, request.candidate_sha) and request.execution in ("local", "hosted")
                and request.proof in host.proofs, "candidate-invalid")
        require(not installing or type(host) is WindowsProofHost, "candidate-invalid")
        if request.execution == "hosted":
            require(matches(SHA, request.driver_sha) and os.environ.get("GITHUB_RUN_ATTEMPT") == "1", "hosted-authorization-invalid")
            require(not installing and native_authority is not None, "hosted-recovery-retention-unavailable")
            from proof_controller_worker import NativeAdmission
            require(type(host) is WindowsProofHost and type(native_authority) is NativeAdmission,
                    "hosted-authorization-invalid")
            NativeAdmission.require_proof(native_authority, request)
        operator = (InstallOperator.load if installing else host.load_operator)(request.operator_config, request.candidate_sha)
        require(commands.run(["git", "rev-parse", "HEAD"], timeout=30).decode().strip() == request.candidate_sha,
                "candidate-mismatch")
        require(not commands.run(["git", "status", "--porcelain", "--untracked-files=normal"], timeout=30).strip(),
                "candidate-dirty")
        if not installing:
            target_path.write_bytes(canonical(operator.target))
        configure_ssh(commands, operator.ssh_config)
        observed = host.inspect(commands, operator)
        commands.run(["go", "build", "-trimpath", "-o", client, "./cmd/blender-box"], timeout=300)
        if named:
            current = "target-catalog"
            catalog_attempted = True
            verify_catalog(commands, client, operator.windows)
            selector = ["--target-name", PROOF_TARGET]
            report["outcomes"][current] = {"status": "pass", "code": "import-copy-migration-verified"}
            current = "preparation"
        if installing:
            operation_ids = {name: "bbxo_" + os.urandom(16).hex() for name in ("install", "remove")}
            with (private / "installer-operations.json").open("x") as stream:
                json.dump({"schema_version": 1, "installation_id": operator.installation["id"],
                           "operations": operation_ids}, stream)
                stream.flush()
                os.fsync(stream.fileno())
            (private / "installer-manifest.json").write_bytes(operator.raw_manifest)
            (private / "installer-scope.json").write_bytes(canonical({"installation": operator.installation,
                                                                       "bootstrap": operator.bootstrap,
                                                                       "before_state": operator.before,
                                                                       "connection": operator.connection,
                                                                       "expected_host": operator.expected,
                                                                       "manifest_pin": operator.manifest_pin,
                                                                       "authorization": operator.authorization}))
            report["installation"] = {"installation_id": operator.installation["id"], "state": "unobserved"}
            current = "install-inspect"
            original_observation = installer_observation(commands, operator)
            require(original_observation == operator.before, "installer-before-state-changed")
            inspected = installer_call(commands, operator, "inspect", fresh=True)
            require(inspected["state"] == "planned", "installer-inspect-mismatch")
            report["outcomes"][current] = {"status": "pass", "code": "dedicated-absent-fixture-verified"}
            current = "install-preview"
            plan = installer_call(commands, operator, "install", operation_id=operation_ids["install"], target_out=True)
            require(plan["state"] == "planned", "installer-preview-mismatch")
            require(installer_observation(commands, operator) == original_observation, "installer-preview-mutated")
            report["outcomes"][current] = {"status": "pass", "code": "install-preview-read-only"}
            current = "install-apply"
            install_attempted = True
            applied = installer_call(commands, operator, "install", operation_id=operation_ids["install"], apply=True,
                                     expected_plan=plan["plan"]["plan_sha256"], target_out=True)
            require(applied["state"] == "installed", "installer-apply-mismatch")
            observed_install = recover_installer(commands, operator, operation_ids["install"], plan["plan"]["plan_sha256"], target_out=True)
            require(observed_install.get("target") == applied.get("target")
                    , "installer-status-mismatch")
            require_same_installer_execution(applied["execution"], observed_install["execution"])
            installation_owned = True
            report["installation"]["state"] = "installed"
            report["outcomes"][current] = {"status": "pass", "code": "owned-runtime-installed"}
            current = "install-target"
            require(applied["target_publication"]["status"] == "published", "installer-target-publication-failed")
            installed_target = installer_target(commands, operator, applied, target_path)
            installed = inspect_host(commands, installed_target)
            verify_expected_host(operator.expected, installed)
            artifacts_by_role = {a["role"]: a for a in operator.manifest["artifacts"]}
            host_hash = artifacts_by_role["host-executable"]["sha256"]
            require(installed["host_sha256"] == host_hash, "installed-host-mismatch")
            report["outcomes"][current] = {"status": "pass", "code": "generated-target-verified"}
            report["binaries"] = {"host_sha256": host_hash, "host_size": artifacts_by_role["host-executable"]["size"],
                                  "client_sha256": digest(read_regular(private, client.name, 128 << 20))}
            current = "preparation"
        else:
            host_binary = private / host.host_filename
            host_env = dict(commands.env, GOOS=host.platform, GOARCH="amd64", CGO_ENABLED="0")
            commands.run(["go", "build", "-trimpath", "-o", host_binary, "./cmd/blender-box"], timeout=300, env=host_env)
            host_bytes = read_regular(private, host_binary.name, 128 << 20)
            host_hash, host_size = digest(host_bytes), len(host_bytes)
            setup_args = [client, host.platform, "setup", *selector, "--host-binary", host_binary, "--json"]
            plan = commands.json(setup_args)
            host.verify_setup(plan, operator, host_hash, host_size, False)
            if observed["host_sha256"] != host_hash:
                host.verify_setup_authorization(operator, request.candidate_sha, observed["host_sha256"])
                require(host.platform != "windows", "legacy-setup-unowned")
                applied = commands.json(setup_args + ["--apply"], timeout=300)
                host.verify_setup(applied, operator, host_hash, host_size, True, plan)
            installed = host.inspect(commands, operator)
            require(installed["host_sha256"] == host_hash, "installed-host-mismatch")
            report["binaries"] = {"host_sha256": host_hash, "host_size": host_size,
                                  "client_sha256": digest(read_regular(private, client.name, 128 << 20))}
        report["outcomes"][current] = {"status": "pass", "code": "prepared-fixture-verified"}
        current = "readiness"
        host.verify_readiness(commands.json([client, host.platform, "check", *selector, "--json"]))
        report.update(host.public_runtime(operator))
        report["outcomes"][current] = {"status": "pass", "code": host.platform + "-check-passed"}
        current = "scenario"
        scenario_attempted = True
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
                report["cleanup"] = cleanup
                report["outcomes"]["recovery"] = {"status": "pass", "code": "reconnect-exact-identity"}
                report["outcomes"]["cleanup"] = {"status": "pass", "code": "settled-and-reobserved"}
            except Exception as error:
                code = error.code if isinstance(error, ProofError) else "recovery-unavailable"
                report["outcomes"]["recovery"] = {"status": "fail", "code": code}
                report["outcomes"]["cleanup"] = {"status": "fail", "code": "cleanup-unknown"}
            else:
                if run is not None and run.get("state") == "complete":
                    try:
                        retained = request.candidate_checkout / "artifacts/blender-box" / commands.run_id
                        verify_baseline(retained, verify_bundle(retained, run))
                    except Exception as error:
                        code = error.code if isinstance(error, ProofError) else "retained-evidence-unavailable"
                        report["outcomes"]["evidence"] = {"status": "fail", "code": code}
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
        if installing and install_attempted:
            if commands.group_cleanup_known:
                try:
                    applied = recover_installer(commands, operator, operation_ids["install"], plan["plan"]["plan_sha256"], target_out=True)
                    installation_owned = applied["state"] == "installed"
                except Exception:
                    installation_owned = False
            if (installation_owned and commands.group_cleanup_known
                    and (not scenario_attempted or report["cleanup"] and report["outcomes"]["evidence"]["status"] != "fail")):
                repeat_install = scenario_attempted and not commands.cancelled.is_set()
                removal_stage = "install-repeat" if repeat_install else "remove-preview"
                try:
                    if repeat_install:
                        repeated = installer_call(commands, operator, "install", operation_id=operation_ids["install"], apply=True,
                                                  expected_plan=plan["plan"]["plan_sha256"], target_out=True, recovery=True)
                        require(repeated["state"] == "installed" and repeated.get("target") == applied.get("target")
                                and repeated.get("files") == applied.get("files"), "installer-repeat-mismatch")
                        report["outcomes"][removal_stage] = {"status": "pass", "code": "identical-install-repeated-after-run"}
                    removal_stage = "remove-preview"
                    preview = installer_call(commands, operator, "remove", operation_id=operation_ids["remove"], recovery=True)
                    require(preview["state"] == "installed", "installer-remove-preview-mismatch")
                    still_installed = installer_call(commands, operator, "inspect", recovery=True)
                    require(still_installed["state"] == "installed", "installer-remove-preview-mutated")
                    report["outcomes"][removal_stage] = {"status": "pass", "code": "remove-preview-read-only"}
                    removal_stage = "remove-apply"
                    removal_failure = None
                    removed = None
                    try:
                        removed = installer_call(commands, operator, "remove", operation_id=operation_ids["remove"], apply=True,
                                                 expected_plan=preview["plan"]["plan_sha256"], recovery=True)
                        require(removed["state"] == "removed", "installer-remove-mismatch")
                    except Exception as error:
                        removal_failure = error.code if isinstance(error, ProofError) else "installer-removal-unavailable"
                    observed_remove = recover_installer(commands, operator, operation_ids["remove"], preview["plan"]["plan_sha256"])
                    require(observed_remove["state"] == "removed", "installer-status-mismatch")
                    if removed is not None:
                        require_same_installer_execution(removed["execution"], observed_remove["execution"])
                    report["installation"]["state"] = "removed"
                    report["outcomes"][removal_stage] = {"status": "fail" if removal_failure else "pass",
                                                         "code": removal_failure or "owned-runtime-removed"}
                    removal_stage = "remove-repeat"
                    repeated = installer_call(commands, operator, "remove", operation_id=operation_ids["remove"], apply=True, recovery=True)
                    require(repeated["state"] == "removed", "installer-remove-repeat-mismatch")
                    report["outcomes"][removal_stage] = {"status": "pass", "code": "removed-tombstone-reobserved"}
                except Exception as error:
                    code = error.code if isinstance(error, ProofError) else "installer-removal-unavailable"
                    report["outcomes"][removal_stage] = {"status": "fail", "code": code}
                    report["installation"]["state"] = "unknown"
            else:
                report["outcomes"]["remove-preview"] = {"status": "fail", "code": "installer-removal-not-settled"}
                report["installation"]["state"] = "unknown"
        if installing and original_observation is not None and commands.group_cleanup_known:
            try:
                preserved = installer_observation(commands, operator, recovery=True)
                require(all(preserved[key] == original_observation[key] for key in ("unrelated_files", "unrelated_tasks")),
                        "installer-unrelated-fixture-changed")
                if report.get("installation", {}).get("state") == "removed":
                    require(preserved["task_absent"] is True and preserved["installation_absent"] is False,
                            "installer-removal-state-unknown")
                report["outcomes"]["fixture-preserved"] = {"status": "pass", "code": "declared-unrelated-fixture-preserved"}
            except Exception as error:
                code = error.code if isinstance(error, ProofError) else "installer-fixture-unknown"
                report["outcomes"]["fixture-preserved"] = {"status": "fail", "code": code}
        for sig, previous in old_signals.items():
            signal.signal(sig, previous)
        report["status"] = "pass" if all(report["outcomes"][name]["status"] == "pass" for name in required) else "fail"
        write_outcome(public, report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["baseline", "named-target", "host-install"])
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
