#!/usr/bin/env python3
"""Opt-in Linux Blender proof through the public Blender Box CLI."""

import argparse
from pathlib import Path, PurePosixPath
import shlex

import onboarding_proof as proof


DISTRIBUTION = "ubuntu-24.04-gnome-xorg"
PROVENANCE = "blendersessiond-6d40e403-posix-9a54bfb9"
BLENDER_VERSION = "5.2.0"
CHECKS = {"host.linux", "host.desktop", "daemon.runtime", "host.unit", "work-root.access", "blender.executable"}
SETUP_SCOPE = "linux-setup-binary-unit-state"
PREREQUISITES = (
    "Private durable original Run authority and Session-pin retention with a tested recovery procedure for hosted execution.",
    "An explicitly authorized Ubuntu 24.04 amd64 GNOME Xorg desktop with one local graphical login matching the SSH UID.",
    "Blender 5.2.0 and the externally provisioned reviewed daemon runtime; the uncorrected wheel is unsupported.",
    "Preverified SSH trust, prepared fixture, exact candidate authorization, and separate authorization for any setup apply.",
)


def absolute_path(value):
    proof.require(proof.matches(r"/[A-Za-z0-9._/-]{1,220}", value)
                  and str(PurePosixPath(value)) == value and not value.endswith("/")
                  and all(part not in ("", ".", "..") for part in value[1:].split("/")),
                  "operator-config-invalid")


def linux_target(target):
    proof.require(isinstance(target, dict), "operator-config-invalid")
    proof.require(target.get("platform") == "linux", "operator-platform-unsupported")
    proof.require(type(target.get("schema_version")) is int and target["schema_version"] == 2
                  and set(target) == {"schema_version", "platform", "ssh_alias", "linux"}
                  and proof.matches(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", target.get("ssh_alias")),
                  "operator-config-invalid")
    native = target["linux"]
    proof.require(isinstance(native, dict) and set(native) == {
        "distribution", "uid", "home", "work_root", "host_executable", "blender_executable", "unit_name", "desktop", "daemon"},
        "operator-config-invalid")
    proof.require(native["distribution"] == DISTRIBUTION, "linux-distribution-unsupported")
    proof.require(type(native["uid"]) is int and 1000 <= native["uid"] <= 60000,
                  "operator-config-invalid")
    for key in ("home", "work_root", "host_executable", "blender_executable"):
        absolute_path(native[key])
    proof.require(native["work_root"] != native["home"]
                  and not native["home"].startswith(native["work_root"] + "/")
                  and str(PurePosixPath(native["host_executable"]).parent) == native["work_root"] + "/bin"
                  and not native["blender_executable"].startswith(native["work_root"] + "/")
                  and proof.matches(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.service", native["unit_name"]),
                  "operator-config-invalid")
    desktop, daemon = native["desktop"], native["daemon"]
    proof.require(isinstance(desktop, dict) and set(desktop) == {"display", "xauthority"}
                  and proof.matches(r":[0-9]{1,2}", desktop["display"]), "linux-desktop-unsupported")
    absolute_path(desktop["xauthority"])
    proof.require(desktop["xauthority"] != native["work_root"]
                  and not desktop["xauthority"].startswith(native["work_root"] + "/"), "operator-config-invalid")
    proof.require(isinstance(daemon, dict)
                  and set(daemon) == {"venv_root", "python_executable", "provenance_id"}, "operator-config-invalid")
    absolute_path(daemon["venv_root"])
    absolute_path(daemon["python_executable"])
    proof.require(daemon["provenance_id"] == PROVENANCE, "linux-daemon-provenance-unavailable")
    proof.require(daemon["python_executable"] == daemon["venv_root"] + "/bin/python3"
                  and daemon["venv_root"] != native["work_root"]
                  and not daemon["venv_root"].startswith(native["work_root"] + "/")
                  and not native["work_root"].startswith(daemon["venv_root"] + "/"), "operator-config-invalid")
    return native


def expected_host(expected):
    proof.require(set(expected) == {"hostname", "distribution", "uid", "blender_version", "daemon_provenance_id"}
                  and proof.matches(r"[A-Za-z0-9_.-]{1,128}", expected.get("hostname"))
                  and expected.get("distribution") == DISTRIBUTION
                  and type(expected.get("uid")) is int and 1000 <= expected["uid"] <= 60000
                  and expected.get("blender_version") == BLENDER_VERSION
                  and expected.get("daemon_provenance_id") == PROVENANCE, "operator-config-invalid")


class LinuxOperator(proof.Operator):
    validate_target = staticmethod(linux_target)
    validate_expected = staticmethod(expected_host)

    @classmethod
    def load(cls, path, candidate):
        operator = super().load(path, candidate)
        proof.require(operator.target["linux"]["uid"] == operator.expected["uid"], "operator-config-invalid")
        return operator


INSPECT = r'''
import hashlib, json, os, pathlib, platform, pwd, shlex, stat, sys

def reject(code):
    print(json.dumps({"schema_version": 1, "status": "fail", "code": code}))
    raise SystemExit(0)

def binary_hash(name):
    path = pathlib.Path(name)
    for parent in (*reversed(path.parents), path):
        try:
            metadata = parent.lstat()
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid not in (0, os.getuid()) or metadata.st_mode & 0o022:
            reject("host-path-unsafe")
    if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= 128 << 20:
        reject("host-path-unsafe")
    result = hashlib.sha256()
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if not os.path.samestat(metadata, opened):
            reject("host-path-changed")
        count = 0
        while chunk := stream.read(65536):
            count += len(chunk)
            if count > 128 << 20:
                reject("host-path-changed")
            result.update(chunk)
        after = os.fstat(stream.fileno())
    if count != metadata.st_size or after.st_mtime_ns != opened.st_mtime_ns or not os.path.samestat(after, path.stat()):
        reject("host-path-changed")
    return result.hexdigest()

try:
    raw = sys.stdin.buffer.read((64 << 10) + 1)
    if len(raw) > 64 << 10:
        reject("operator-config-invalid")
    config = json.loads(raw)
    target, expected = config["target"]["linux"], config["expected"]
    if platform.system() != "Linux":
        reject("linux-platform-unsupported")
    if platform.node() != expected["hostname"] or os.getuid() != expected["uid"]:
        reject("wrong-host-identity")
    if pwd.getpwuid(os.getuid()).pw_dir != target["home"]:
        reject("wrong-host-identity")
    release = {}
    for line in pathlib.Path("/etc/os-release").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            parts = shlex.split(value)
            if len(parts) == 1:
                release[key] = parts[0]
    if release.get("ID") != "ubuntu" or release.get("VERSION_ID") != "24.04":
        reject("linux-distribution-unsupported")
    if platform.machine() != "x86_64":
        reject("linux-architecture-unsupported")
    count = 0
    entries = list(pathlib.Path("/proc").iterdir())
    if len(entries) > 100000:
        reject("host-activity-unknown")
    for entry in entries:
        if entry.name.isdigit():
            try:
                with (entry / "comm").open("rb") as stream:
                    name = stream.read(256).strip().lower()
            except FileNotFoundError:
                continue
            if name in (b"blender", b"blender-bin"):
                count += 1
    print(json.dumps({"schema_version": 1, "status": "pass", "hostname": platform.node(),
        "distribution": "ubuntu-24.04-gnome-xorg", "uid": os.getuid(), "architecture": platform.machine(),
        "home": pwd.getpwuid(os.getuid()).pw_dir, "blender_process_count": count,
        "host_lock_present": os.path.lexists(target["work_root"] + "/host-lock.json"),
        "host_sha256": binary_hash(target["host_executable"])}))
except (OSError, ValueError, KeyError, TypeError):
    reject("host-inspection-unavailable")
'''


def inspect_host(commands, operator):
    command = shlex.join(["/usr/bin/python3", "-I", "-B", "-S", "-c", INSPECT])
    return commands.json(["ssh", "-o", "RequestTTY=no", "-o", "RemoteCommand=none",
                          "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                          "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes", "--",
                          operator.target["ssh_alias"], command],
                         stdin=proof.canonical({"target": operator.target, "expected": operator.expected}),
                         timeout=120, limit=64 << 10)


def verify_expected_host(operator, observed):
    proof.require(observed.get("status") == "pass", "host-inspection-failed")
    for key in ("hostname", "distribution", "uid"):
        proof.require(type(observed.get(key)) is type(operator.expected[key])
                      and observed[key] == operator.expected[key], "wrong-host-identity")
    proof.require(observed.get("home") == operator.target["linux"]["home"], "wrong-host-identity")
    proof.require(observed.get("architecture") == "x86_64", "linux-architecture-unsupported")
    proof.require(type(observed.get("blender_process_count")) is int
                  and observed["blender_process_count"] == 0 and observed.get("host_lock_present") is False,
                  "host-activity-unknown")
    proof.require(observed.get("host_sha256") is None or proof.matches(proof.HASH, observed["host_sha256"]),
                  "invalid-host-hash")


class LinuxProofHost(proof.WindowsProofHost):
    platform = "linux"
    name = "linux-blender"
    host_filename = "blender-box-linux-amd64"
    proofs = ("baseline",)
    not_exercised = ("pairing", "fixture-reset", "deliberate-ssh-interruption", "desktop-logout", "service-crash")
    load_operator = staticmethod(LinuxOperator.load)

    def inspect(self, commands, operator):
        observed = inspect_host(commands, operator)
        verify_expected_host(operator, observed)
        return observed

    def verify_setup_authorization(self, operator, candidate, prior_hash):
        auth = operator.authorization["setup"]
        proof.require(isinstance(auth, dict)
                      and set(auth) == {"candidate_sha", "target_sha256", "prior_host_sha256", "scope"}
                      and auth.get("candidate_sha") == candidate
                      and auth.get("target_sha256") == proof.digest(proof.canonical(operator.target))
                      and auth.get("prior_host_sha256") == prior_hash
                      and auth.get("scope") == SETUP_SCOPE, "setup-not-authorized")

    def verify_setup(self, record, operator, host_hash, host_size, applied, planned=None):
        super().verify_setup(record, operator, host_hash, host_size, applied, planned)
        native = operator.target["linux"]
        unit = record.get("unit_bytes")
        code = "setup-apply-mismatch" if applied else "setup-plan-mismatch"
        proof.require(isinstance(unit, str) and 0 < len(unit.encode()) <= 64 << 10
                      and record.get("unit_sha256") == proof.digest(unit.encode())
                      and record.get("unit_name") == native["unit_name"]
                      and record.get("unit_destination") == native["home"] + "/.config/systemd/user/" + native["unit_name"]
                      and record.get("host_destination") == native["host_executable"]
                      and isinstance(record.get("prerequisites"), list)
                      and all(isinstance(item, str) and item for item in record["prerequisites"]), code)
        if applied:
            proof.require(all(record.get(key) == planned.get(key) for key in (
                "unit_bytes", "unit_sha256", "unit_name", "unit_destination", "host_destination")), code)

    def verify_readiness(self, record):
        proof.verify_readiness(record, CHECKS)
        proof.require(record.get("blender_version") == BLENDER_VERSION, "linux-blender-version-mismatch")

    def public_runtime(self, operator):
        return {"daemon_capabilities": list(proof.CAPABILITIES), "host_platform": "linux",
                "host_architecture": "amd64", "daemon_provenance_id": PROVENANCE,
                "blender_version": BLENDER_VERSION, "readiness_checks": sorted(CHECKS)}


def baseline(request, commands_factory=proof.Commands):
    report = proof.baseline(request, commands_factory, LinuxProofHost())
    if report["status"] != "pass":
        report["prerequisites"] = list(PREREQUISITES)
        proof.write_outcome(request.output / "public", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["baseline"])
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--candidate-checkout", type=Path, required=True)
    parser.add_argument("--operator-config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execution", choices=["local", "hosted"], default="local")
    parser.add_argument("--driver-sha")
    args = parser.parse_args(argv)
    request = proof.ProofRequest(args.candidate, args.candidate_checkout.absolute(), args.operator_config.absolute(),
                                 args.output.absolute(), args.execution, args.driver_sha, args.command)
    try:
        report = baseline(request)
    except (OSError, proof.ProofError):
        print("Proof output must be a fresh directory with an existing parent.")
        return 1
    failed = next((value["code"] for value in report["outcomes"].values() if value["status"] == "fail"), None)
    print("Linux Blender proof " + report["status"] + (" (" + failed + ")" if failed else "") + ".")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
