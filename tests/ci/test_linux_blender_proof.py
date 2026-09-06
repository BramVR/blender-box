import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).parent))
import test_onboarding_proof as shared

proof = shared.proof
sys.path.insert(0, str(ROOT / "scripts"))
import linux_blender_proof as linux

SHA = shared.SHA


def operator_config():
    return {"schema_version": 1, "target": {"schema_version": 2, "platform": "linux", "ssh_alias": "test-linux",
            "linux": {"distribution": linux.DISTRIBUTION, "uid": 1000, "home": "/home/test-user",
                      "work_root": "/home/test-user/box", "host_executable": "/home/test-user/box/bin/blender-box",
                      "blender_executable": "/opt/blender/blender", "unit_name": "test-blender-box.service",
                      "desktop": {"display": ":0", "xauthority": "/run/user/1000/gdm/Xauthority"},
                      "daemon": {"venv_root": "/home/test-user/daemon", "python_executable": "/home/test-user/daemon/bin/python3",
                                 "provenance_id": linux.PROVENANCE}}},
            "expected_host": {"hostname": "TEST-LINUX", "distribution": linux.DISTRIBUTION, "uid": 1000,
                              "blender_version": "5.2.0", "daemon_provenance_id": linux.PROVENANCE},
            "fixture": {"id": "test-linux", "kind": "shared-existing", "state": "prepared"},
            "authorization": {"candidate_sha": SHA, "fixture_id": "test-linux", "launch": True, "setup": None}}


def observation(config, host_hash=None):
    expected = config["expected_host"]
    return {"schema_version": 1, "status": "pass", "hostname": expected["hostname"],
            "distribution": expected["distribution"], "uid": expected["uid"], "architecture": "x86_64",
            "home": config["target"]["linux"]["home"], "blender_process_count": 0, "host_lock_present": False,
            "host_sha256": host_hash if host_hash is not None else proof.digest(b"host")}


def setup_record(config, applied=False):
    native = config["target"]["linux"]
    unit = "[Service]\nType=exec\nExitType=cgroup\nKillMode=process\n"
    return {"schema_version": 1, "status": "applied" if applied else "plan", "applied": applied,
            "host_sha256": proof.digest(b"host"), "host_size": 4,
            "host_destination": native["host_executable"], "unit_name": native["unit_name"],
            "unit_destination": native["home"] + "/.config/systemd/user/" + native["unit_name"],
            "unit_bytes": unit, "unit_sha256": proof.digest(unit.encode()),
            "prerequisites": ["External reviewed daemon runtime and supported desktop remain unverified by this plan."]}


class LinuxCommands(shared.FakeCommands):
    def __init__(self, private, cwd, config, fault=None):
        super().__init__(private, cwd, config, fault)
        self.host_hash = "1" * 64 if fault in ("setup", "setup-apply-hash", "setup-apply-unit") else proof.digest(b"host")

    def run(self, args, **kwargs):
        args = [str(arg) for arg in args]
        if args[:2] != ["go", "build"] and args[0] != "ssh" and args[1:2] != ["linux"]:
            return super().run(args, **kwargs)
        self.calls.append(args)
        self.call_options.append(kwargs)
        if args[:2] == ["go", "build"]:
            host = kwargs.get("env", {}).get("GOOS") == "linux"
            Path(args[args.index("-o") + 1]).write_bytes(b"host" if host else b"client")
            return b""
        if args[0] == "ssh":
            record = observation(self.config, self.host_hash)
            if self.fault == "wrong-host":
                record["hostname"] = "WRONG-HOST"
            if self.fault == "architecture":
                record["architecture"] = "aarch64"
            if self.fault == "active-blender":
                record["blender_process_count"] = 1
            if self.fault == "host-lock":
                record["host_lock_present"] = True
            return proof.canonical(record)
        if args[2] == "setup":
            applied = "--apply" in args
            record = setup_record(self.config, applied)
            if self.fault == "setup-hash" or self.fault == "setup-apply-hash" and applied:
                record["host_sha256"] = "0" * 64
            if self.fault == "setup-unit":
                record["unit_sha256"] = "0" * 64
            if self.fault == "setup-destination":
                record["unit_destination"] = "/home/someone-else/.config/systemd/user/foreign.service"
            if self.fault == "setup-apply-unit" and applied:
                record["unit_bytes"] += "Restart=always\n"
                record["unit_sha256"] = proof.digest(record["unit_bytes"].encode())
            if applied:
                self.host_hash = proof.digest(b"host")
            return proof.canonical(record)
        checks = [{"id": name, "required": True, "passed": True} for name in sorted(linux.CHECKS)]
        if self.fault in ("no-desktop", "daemon-runtime", "host-unit"):
            check_id = {"no-desktop": "host.desktop", "daemon-runtime": "daemon.runtime", "host-unit": "host.unit"}[self.fault]
            next(item for item in checks if item["id"] == check_id)["passed"] = False
        return proof.canonical({"schema_version": 1, "status": "pass", "checks": checks,
                                "blender_version": "4.5" if self.fault == "version" else "5.2.0"})


class LinuxProofTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = operator_config()
        self.path = self.root / "operator.json"
        self.request = proof.ProofRequest(SHA, self.root, self.path, self.root / "proof")

    def execute(self, fault=None):
        self.path.write_bytes(proof.canonical(self.config))
        self.path.chmod(0o600)
        def commands_factory(private, cwd):
            self.commands = LinuxCommands(private, cwd, self.config, fault)
            return self.commands
        return linux.baseline(self.request, commands_factory)

    def authorize_setup(self):
        self.config["authorization"]["setup"] = {
            "candidate_sha": SHA, "target_sha256": proof.digest(proof.canonical(self.config["target"])),
            "prior_host_sha256": "1" * 64, "scope": linux.SETUP_SCOPE}

    def test_local_fake_path_uses_linux_public_cli_and_shared_evidence_recovery(self):
        report = self.execute()
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["proof"], "linux-blender-baseline")
        self.assertEqual(report["host_platform"], "linux")
        self.assertEqual(report["daemon_provenance_id"], linux.PROVENANCE)
        self.assertEqual(report["readiness_checks"], sorted(linux.CHECKS))
        self.assertEqual(report["cleanup"], {key: True for key in proof.CLEANUP})
        self.assertEqual(set(report["outcomes"]), set(proof.REQUIRED))
        self.assertEqual([call[1] for call in self.commands.calls[-3:]], ["status", "stop", "status"])
        self.assertFalse(any(call[1:2] == ["windows"] for call in self.commands.calls))
        host_build = next(options for call, options in zip(self.commands.calls, self.commands.call_options)
                          if call[:2] == ["go", "build"] and options.get("env", {}).get("GOOS") == "linux")
        self.assertEqual(host_build["env"]["GOARCH"], "amd64")
        public = (self.request.output / "public/outcome.json").read_text()
        for private in ("TEST-LINUX", "test-user", "/opt/blender", "test-blender-box.service", str(self.root)):
            self.assertNotIn(private, public)
        self.assertEqual(len(list((self.request.output / "public").iterdir())), 1)
        self.assertEqual(self.commands.early_report["run"], {"run_id": shared.RUN})
        self.assertEqual(self.commands.task, "linux-blender-baseline")

    def test_hosted_refusal_precedes_operator_candidate_and_host_operations(self):
        self.request = proof.dataclasses.replace(self.request, execution="hosted", driver_sha="b" * 40)
        with mock.patch.dict(os.environ, GITHUB_RUN_ATTEMPT="1"), mock.patch.object(linux.LinuxOperator, "load") as load:
            report = self.execute()
        load.assert_not_called()
        self.assertEqual(self.commands.calls, [])
        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["outcomes"]["preparation"]["code"], "hosted-recovery-retention-unavailable")
        self.assertIsNone(report["run"])
        self.assertIsNone(report["cleanup"])
        self.assertEqual(list((self.request.output / "private").iterdir()), [])
        self.assertIn("Private durable", report["prerequisites"][0])

    def test_missing_config_and_windows_target_refuse_offline(self):
        with mock.patch.object(proof.Commands, "run") as command:
            report = linux.baseline(self.request)
        command.assert_not_called()
        self.assertEqual(report["outcomes"]["preparation"]["code"], "operator-config-missing")
        self.request = proof.dataclasses.replace(self.request, output=self.root / "wrong-platform")
        self.config["target"] = shared.operator_config()["target"]
        report = self.execute()
        self.assertEqual(self.commands.calls, [])
        self.assertEqual(report["outcomes"]["preparation"]["code"], "operator-platform-unsupported")

    def test_wrong_host_architecture_or_activity_prevents_setup_and_run(self):
        for fault in ("wrong-host", "architecture", "active-blender", "host-lock"):
            with self.subTest(fault=fault):
                self.request = proof.dataclasses.replace(self.request, output=self.root / fault)
                report = self.execute(fault)
                self.assertEqual(report["status"], "fail")
                self.assertEqual([call[0] for call in self.commands.calls], ["git", "git", "ssh"])
                self.assertIsNone(report["cleanup"])

    def test_readiness_rejects_desktop_runtime_unit_and_blender_version(self):
        for fault in ("no-desktop", "daemon-runtime", "host-unit", "version"):
            with self.subTest(fault=fault):
                self.request = proof.dataclasses.replace(self.request, output=self.root / fault)
                report = self.execute(fault)
                self.assertEqual(report["outcomes"]["readiness"]["status"], "fail")
                self.assertFalse(any(call[1:2] == ["run"] for call in self.commands.calls))
                self.assertNotIn("daemon_provenance_id", report)
                self.assertNotIn("blender_version", report)

    def test_setup_requires_exact_authorization_and_verified_plan(self):
        for fault in ("setup", "setup-hash", "setup-unit", "setup-destination"):
            with self.subTest(fault=fault):
                self.request = proof.dataclasses.replace(self.request, output=self.root / fault)
                report = self.execute(fault)
                self.assertEqual(report["status"], "fail")
                self.assertFalse(any("--apply" in call for call in self.commands.calls))
                self.assertFalse(any(call[1:2] == ["run"] for call in self.commands.calls))

    def test_authorized_setup_and_changed_apply_are_distinguished(self):
        self.authorize_setup()
        report = self.execute("setup")
        self.assertEqual(report["status"], "pass")
        self.assertEqual(sum("--apply" in call for call in self.commands.calls), 1)
        for fault in ("setup-apply-hash", "setup-apply-unit"):
            with self.subTest(fault=fault):
                self.request = proof.dataclasses.replace(self.request, output=self.root / fault)
                report = self.execute(fault)
                self.assertEqual(report["outcomes"]["preparation"]["code"], "setup-apply-mismatch")
                self.assertFalse(any(call[1:2] == ["run"] for call in self.commands.calls))

    def test_failed_run_retains_failure_and_uses_exact_shared_recovery(self):
        for fault in ("run-failed", "pre-session", "discovered-session", "status-failed", "cleanup-failed", "removed-evidence"):
            with self.subTest(fault=fault):
                self.request = proof.dataclasses.replace(self.request, output=self.root / fault)
                report = self.execute(fault)
                self.assertEqual(report["status"], "fail")
                self.assertEqual(report["run"]["run_id"], shared.RUN)
                self.assertEqual([call[1] for call in self.commands.calls[-3:]], ["status", "stop", "status"])
                if fault in ("run-failed", "pre-session", "discovered-session", "removed-evidence"):
                    self.assertEqual(report["cleanup"], {key: True for key in proof.CLEANUP})
                    if fault == "removed-evidence":
                        self.assertEqual(report["outcomes"]["recovery"]["status"], "pass")
                        self.assertEqual(report["outcomes"]["evidence"]["status"], "fail")
                else:
                    self.assertIsNone(report["cleanup"])

    def test_uncertain_local_process_cleanup_preserves_recovery_material(self):
        report = self.execute("local-cleanup-unknown")
        self.assertEqual(report["status"], "fail")
        self.assertIsNone(report["cleanup"])
        self.assertEqual(self.commands.calls[-1][1], "run")
        self.assertEqual(report["outcomes"]["recovery"]["code"], "command-cleanup-unknown")
        self.assertTrue((self.request.output / "private/target.json").is_file())
        self.assertTrue((self.request.output / "private/run-journal.json").is_file())

    def test_viewport_publishing_requires_explicit_permission(self):
        self.config["publish_viewport"] = True
        report = self.execute()
        self.assertEqual(report["status"], "pass")
        viewport = self.request.output / "public/viewport.png"
        artifact = next(item for item in report["artifacts"] if item["type"] == "viewport")
        self.assertEqual(proof.digest(viewport.read_bytes()), artifact["remote_sha256"])
        self.assertEqual({path.name for path in viewport.parent.iterdir()}, {"outcome.json", "viewport.png"})


class LinuxContractTests(unittest.TestCase):
    def test_target_rejects_unsupported_or_unsafe_configuration(self):
        target = operator_config()["target"]
        self.assertEqual(linux.linux_target(target), target["linux"])
        for key, value in (("uid", True), ("uid", 0), ("home", "/home/bad user"),
                           ("work_root", "/home/test-user/../other"), ("host_executable", "/tmp/host"),
                           ("unit_name", "foreign@unit.service"), ("distribution", "ubuntu-wayland")):
            with self.subTest(key=key), self.assertRaises(proof.ProofError):
                linux.linux_target(dict(target, linux=dict(target["linux"], **{key: value})))
        for mutation in (dict(target, windows={}), dict(target, schema_version=True), dict(target, ssh_alias="bad;echo"),
                         dict(target, linux=dict(target["linux"], desktop={"display": "localhost:0", "xauthority": "/tmp/xauth"})),
                         dict(target, linux=dict(target["linux"], daemon=dict(target["linux"]["daemon"], provenance_id="uncorrected-wheel")))):
            with self.subTest(target=mutation), self.assertRaises(proof.ProofError):
                linux.linux_target(mutation)

    def test_setup_authorization_binds_candidate_target_prior_hash_and_scope(self):
        config = operator_config()
        operator = linux.LinuxOperator(config["target"], config["expected_host"], config["fixture"],
                                       config["authorization"], None)
        auth = {"candidate_sha": SHA, "target_sha256": proof.digest(proof.canonical(config["target"])),
                "prior_host_sha256": None, "scope": linux.SETUP_SCOPE}
        operator.authorization["setup"] = auth
        linux.LinuxProofHost().verify_setup_authorization(operator, SHA, None)
        for key, value in (("candidate_sha", "f" * 40), ("target_sha256", "f" * 64),
                           ("prior_host_sha256", "f" * 64), ("scope", "windows-setup-binary-task-acls")):
            with self.subTest(key=key), self.assertRaisesRegex(proof.ProofError, "setup-not-authorized"):
                operator.authorization["setup"] = dict(auth, **{key: value})
                linux.LinuxProofHost().verify_setup_authorization(operator, SHA, None)

    def test_inspection_uses_quoted_fixed_program_and_bounded_json_stdin(self):
        config = operator_config()
        operator = linux.LinuxOperator(config["target"], config["expected_host"], config["fixture"],
                                       config["authorization"], None)
        commands = mock.Mock()
        linux.inspect_host(commands, operator)
        args, kwargs = commands.json.call_args
        remote = shlex.split(args[0][-1])
        self.assertEqual(remote, ["/usr/bin/python3", "-I", "-B", "-S", "-c", linux.INSPECT])
        self.assertEqual(json.loads(kwargs["stdin"]), {"target": config["target"], "expected": config["expected_host"]})
        self.assertEqual(kwargs["limit"], 64 << 10)
        self.assertEqual(kwargs["timeout"], 120)
        self.assertNotIn("--version", linux.INSPECT)
        compile(linux.INSPECT, "linux-proof-inspection", "exec")

    def test_linux_readiness_checks(self):
        record = {"schema_version": 1, "status": "pass", "blender_version": "5.2.0", "checks": [
            {"id": name, "passed": True, "required": True} for name in sorted(linux.CHECKS)]}
        linux.LinuxProofHost().verify_readiness(record)
        for omitted in linux.CHECKS:
            bad = dict(record, checks=[item for item in record["checks"] if item["id"] != omitted])
            with self.subTest(omitted=omitted), self.assertRaisesRegex(proof.ProofError, "readiness-failed"):
                linux.LinuxProofHost().verify_readiness(bad)

    def test_real_cli_hosted_preflight_retains_no_private_operator_data(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "proof"
            result = subprocess.run([sys.executable, str(ROOT / "scripts/linux_blender_proof.py"), "baseline",
                                     "--candidate", SHA, "--candidate-checkout", str(root / "MISSING-CANDIDATE"),
                                     "--operator-config", str(root / "PRIVATE_OPERATOR"), "--output", str(output),
                                     "--execution", "hosted", "--driver-sha", "b" * 40],
                                    env=dict(os.environ, GITHUB_RUN_ATTEMPT="1"), capture_output=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b"Linux Blender proof fail (hosted-recovery-retention-unavailable).\n")
            self.assertEqual(result.stderr, b"")
            public = (output / "public/outcome.json").read_text()
            self.assertNotIn("PRIVATE_OPERATOR", public)
            self.assertNotIn("MISSING-CANDIDATE", public)
            self.assertEqual(list((output / "private").iterdir()), [])
            self.assertFalse((root / "MISSING-CANDIDATE").exists())

    def test_workflow_has_no_candidate_checkout_credentials_or_host_bypass(self):
        workflow = (ROOT / ".github/workflows/linux-blender-proof.yml").read_text()
        for required in ("name: Linux Blender proof", "  linux-blender-proof:", "workflow_dispatch:",
                         "contents: read", "cancel-in-progress: false", "timeout-minutes:",
                         '"$REQUEST_REF" == refs/heads/main', '"$REQUEST_ACTOR" == BramVR', '"$RUN_ATTEMPT" == 1',
                         "ref: ${{ github.workflow_sha }}", "persist-credentials: false", "--execution hosted",
                         "python3 driver/scripts/linux_blender_proof.py baseline", "if-no-files-found: error"):
            self.assertIn(required, workflow)
        for forbidden in ("secrets.", "tailscale/", "pull_request:", "push:", "continue-on-error", "--execution local",
                          "path: candidate", "candidate/scripts/", "artifacts/**", "/private/", "self-hosted"):
            self.assertNotIn(forbidden, workflow)
        upload = workflow.split("name: Upload allowlisted proof outcome", 1)[1]
        self.assertIn("/public/outcome.json", upload)
        self.assertNotIn("*", upload)
        self.assertEqual(workflow.count("uses: actions/checkout@"), 1)


if __name__ == "__main__":
    unittest.main()
