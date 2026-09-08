import datetime
import json
import os
import pathlib
import re
import stat
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "windows-baseline-controller-proof.yml"
DISPATCHER_SHA = "2269a19e09680fde3cb02dbfa3ca83b5a93f63c6"
SHA = "a" * 40
POLICY_SHA = "b" * 40
REQUEST_SHA = "c" * 64


def shell_step(workflow, name):
    lines = workflow.splitlines()
    marker = f"      - name: {name}"
    start = lines.index(marker)
    run = lines.index("        run: |", start)
    stop = next((index for index in range(run + 1, len(lines))
                 if lines[index] and not lines[index].startswith("          ")), len(lines))
    return "\n".join(line[10:] if line.startswith("          ") else line
                     for line in lines[run + 1:stop]) + "\n"


def run_bash(source, *, cwd, env):
    return subprocess.run(["/bin/bash", "-c", source], cwd=cwd, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def outputs(path):
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, value = line.split("=", 1)
        values[key] = value
    return values


class ProofControllerWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.validate = shell_step(cls.workflow, "Validate public request before protected access")
        cls.authorize = shell_step(cls.workflow, "Bind approval to the validated request")
        cls.prepare = shell_step(cls.workflow, "Prepare fresh private controller connection")
        cls.dispatch = shell_step(cls.workflow, "Dispatch approved baseline request")
        cls.cleanup = shell_step(cls.workflow, "Remove only this runner's controller credentials")

    def validation_case(self, changes=None, *, resolved_candidate=SHA):
        case = tempfile.TemporaryDirectory()
        self.addCleanup(case.cleanup)
        root = pathlib.Path(case.name)
        fake_bin = root / "bin"
        fake_bin.mkdir()
        gh = fake_bin / "gh"
        gh.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "printf '%s\\n' \"$*\" >> \"$FAKE_GH_LOG\"\n"
            "case \"$*\" in\n"
            "  */commits/*) printf '%s\\n' \"$FAKE_RESOLVED_CANDIDATE\" ;;\n"
            "  *) printf '%s\\n' main ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        gh.chmod(0o700)
        output = root / "github-output"
        log = root / "gh-calls"
        log.write_text("", encoding="utf-8")
        env = dict(os.environ)
        env.update({
            "PATH": f"{fake_bin}:{env['PATH']}",
            "MODE": "run",
            "CANDIDATE_SHA": SHA,
            "POLICY_DRIVER_SHA": POLICY_SHA,
            "DISPATCHER_SHA": DISPATCHER_SHA,
            "ORIGINAL_EXECUTION_ID": "",
            "ORIGINAL_REQUEST_SHA256": "",
            "EVENT_NAME": "workflow_dispatch",
            "REQUEST_REPOSITORY": "BramVR/blender-box",
            "REQUEST_REF": "refs/heads/main",
            "REQUEST_ACTOR": "BramVR",
            "RUN_ATTEMPT": "1",
            "GH_TOKEN": "test-token",
            "GITHUB_OUTPUT": str(output),
            "FAKE_GH_LOG": str(log),
            "FAKE_RESOLVED_CANDIDATE": resolved_candidate,
        })
        env.update(changes or {})
        return run_bash(self.validate, cwd=root, env=env), output, log

    def test_invalid_public_requests_fail_in_the_unprotected_job(self):
        invalid = (
            {"REQUEST_ACTOR": "other"},
            {"REQUEST_REF": "refs/heads/topic"},
            {"RUN_ATTEMPT": "2"},
            {"MODE": "run", "ORIGINAL_EXECUTION_ID": "gha_123_1",
             "ORIGINAL_REQUEST_SHA256": REQUEST_SHA},
            {"MODE": "recover"},
            {"MODE": "unexpected"},
        )
        for changes in invalid:
            with self.subTest(changes=changes):
                result, output, _ = self.validation_case(changes)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())

        result, _, _ = self.validation_case(resolved_candidate="d" * 40)
        self.assertNotEqual(result.returncode, 0)

        request_job = self.workflow.split("  request:\n", 1)[1].split("  authorize:\n", 1)[0]
        self.assertNotIn("environment:", request_job)
        self.assertNotIn("secrets.", request_job)

    def test_valid_run_and_recovery_publish_the_exact_public_pins(self):
        result, output, _ = self.validation_case()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(outputs(output), {
            "mode": "run",
            "candidate_sha": SHA,
            "policy_driver_sha": POLICY_SHA,
            "dispatcher_sha": DISPATCHER_SHA,
            "execution_id": "",
            "request_sha256": "",
        })

        result, output, _ = self.validation_case({
            "MODE": "recover",
            "ORIGINAL_EXECUTION_ID": "gha_123_1",
            "ORIGINAL_REQUEST_SHA256": REQUEST_SHA,
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        recovery = outputs(output)
        self.assertEqual(recovery["execution_id"], "gha_123_1")
        self.assertEqual(recovery["request_sha256"], REQUEST_SHA)

    def test_approval_record_names_candidate_policy_dispatcher_and_recovery_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            summary = pathlib.Path(directory) / "summary"
            env = dict(os.environ)
            env.update({
                "MODE": "recover",
                "CANDIDATE_SHA": SHA,
                "POLICY_DRIVER_SHA": POLICY_SHA,
                "DISPATCHER_SHA": DISPATCHER_SHA,
                "ORIGINAL_EXECUTION_ID": "gha_123_1",
                "ORIGINAL_REQUEST_SHA256": REQUEST_SHA,
                "RUN_ATTEMPT": "1",
                "GITHUB_STEP_SUMMARY": str(summary),
            })
            result = run_bash(self.authorize, cwd=directory, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            record = summary.read_text(encoding="utf-8")
            for value in (SHA, POLICY_SHA, DISPATCHER_SHA, "gha_123_1", REQUEST_SHA):
                self.assertIn(value, record)

    def fake_dispatch_case(self, mode, *, exit_code=0):
        case = tempfile.TemporaryDirectory()
        self.addCleanup(case.cleanup)
        root = pathlib.Path(case.name)
        script = root / "driver" / "scripts" / "proof_controller_dispatch.py"
        script.parent.mkdir(parents=True)
        script.write_text(
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['FAKE_DISPATCH_LOG']).write_text(json.dumps(sys.argv[1:]))\n"
            "print(os.environ['FAKE_METADATA'], flush=True)\n"
            "print(os.environ['FAKE_RESULT'], flush=True)\n"
            "raise SystemExit(int(os.environ['FAKE_EXIT']))\n",
            encoding="utf-8",
        )
        fake_bin = root / "bin"
        fake_bin.mkdir()
        fake_date = fake_bin / "date"
        fake_date.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "if [ \"$*\" = '-u +%s' ]; then\n"
            "  printf '%s\\n' \"$FAKE_NOW\"\n"
            "else\n"
            "  printf '%s\\n' \"$FAKE_EXPIRY\"\n"
            "fi\n",
            encoding="utf-8",
        )
        fake_date.chmod(0o700)
        log = root / "dispatch.json"
        fake_now = 2_000_000_000
        fake_expiry = datetime.datetime.fromtimestamp(
            fake_now + 1200, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        env = dict(os.environ)
        env.update({
            "PATH": f"{fake_bin}:{env['PATH']}",
            "MODE": mode,
            "RUNNER_TEMP": str(root / "runner-temp"),
            "PRIVATE_NAME": "proof-controller-777-1",
            "GITHUB_RUN_ID": "777",
            "GITHUB_RUN_ATTEMPT": "1",
            "CANDIDATE_SHA": SHA,
            "POLICY_DRIVER_SHA": POLICY_SHA,
            "ORIGINAL_EXECUTION_ID": "gha_123_1",
            "ORIGINAL_REQUEST_SHA256": REQUEST_SHA,
            "FAKE_DISPATCH_LOG": str(log),
            "FAKE_METADATA": "original-public-recovery-metadata",
            "FAKE_RESULT": "final-dispatch-result",
            "FAKE_EXIT": str(exit_code),
            "FAKE_NOW": str(fake_now),
            "FAKE_EXPIRY": fake_expiry,
        })
        result = run_bash(self.dispatch, cwd=root, env=env)
        return result, json.loads(log.read_text(encoding="utf-8")), fake_expiry

    def test_run_and_recovery_execute_the_approved_arguments_in_the_foreground(self):
        result, argv, expected_expiry = self.fake_dispatch_case("run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "original-public-recovery-metadata\nfinal-dispatch-result\n")
        self.assertEqual(argv[0], "run")
        arguments = dict(zip(argv[1::2], argv[2::2]))
        self.assertEqual(arguments["--github-run-id"], "777")
        self.assertEqual(arguments["--github-run-attempt"], "1")
        self.assertEqual(arguments["--candidate-sha"], SHA)
        self.assertEqual(arguments["--policy-driver-sha"], POLICY_SHA)
        self.assertEqual(arguments["--budget-seconds"], "900")
        self.assertEqual(arguments["--expires-at"], expected_expiry)
        self.assertNotIn("--execution-id", arguments)

        result, argv, _ = self.fake_dispatch_case("recover")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(argv[0], "recover")
        arguments = dict(zip(argv[1::2], argv[2::2]))
        self.assertEqual(arguments["--execution-id"], "gha_123_1")
        self.assertEqual(arguments["--request-sha256"], REQUEST_SHA)
        self.assertEqual(arguments["--candidate-sha"], SHA)
        self.assertEqual(arguments["--policy-driver-sha"], POLICY_SHA)
        self.assertEqual(arguments["--budget-seconds"], "300")
        self.assertNotIn("--github-run-id", arguments)
        self.assertNotIn("--expires-at", arguments)

    def test_dispatcher_failure_is_the_dispatch_step_failure(self):
        result, _, _ = self.fake_dispatch_case("run", exit_code=23)
        self.assertEqual(result.returncode, 23)
        self.assertEqual(result.stdout, "original-public-recovery-metadata\nfinal-dispatch-result\n")

    def test_private_ssh_files_are_created_then_only_credentials_are_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            runner_temp = pathlib.Path(directory) / "runner"
            runner_temp.mkdir()
            env = dict(os.environ)
            env.update({
                "RUNNER_TEMP": str(runner_temp),
                "PRIVATE_NAME": "proof-controller-777-1",
                "GITHUB_RUN_ID": "777",
                "GITHUB_RUN_ATTEMPT": "1",
                "CONTROLLER_HOST": "controller.invalid",
                "CONTROLLER_PORT": "22",
                "CONTROLLER_USER": "proof-control",
                "CONTROLLER_SSH_KEY": "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----",
                "CONTROLLER_KNOWN_HOSTS": "controller.invalid ssh-ed25519 TEST",
            })
            prepared = run_bash(self.prepare, cwd=directory, env=env)
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            private_parent = runner_temp / env["PRIVATE_NAME"]
            ssh_root = private_parent / "ssh"
            self.assertEqual(stat.S_IMODE(private_parent.stat().st_mode), 0o700)
            for name in ("key", "known_hosts", "config"):
                self.assertEqual(stat.S_IMODE((ssh_root / name).stat().st_mode), 0o600)
            self.assertFalse((private_parent / "private").exists())
            self.assertFalse((private_parent / "public").exists())

            (private_parent / "private").mkdir()
            (private_parent / "private" / "identity.json").write_text("private", encoding="utf-8")
            (private_parent / "public").mkdir()
            (private_parent / "public" / "outcome.json").write_text("public", encoding="utf-8")
            cleaned = run_bash(self.cleanup, cwd=directory, env=env)
            self.assertEqual(cleaned.returncode, 0, cleaned.stderr)
            self.assertFalse(ssh_root.exists())
            self.assertEqual((private_parent / "private" / "identity.json").read_text(), "private")
            self.assertEqual((private_parent / "public" / "outcome.json").read_text(), "public")

    def test_protected_job_order_source_pin_and_publication_allowlist(self):
        self.assertIn("environment: windows-onboarding-approval", self.workflow)
        self.assertIn("environment: windows-onboarding-controller", self.workflow)
        self.assertIn("group: windows-onboarding-prepared-v1", self.workflow)
        self.assertIn("cancel-in-progress: false", self.workflow)
        self.assertRegex(self.workflow, rf"ref: {DISPATCHER_SHA}\n\s+path: driver\n\s+persist-credentials: false")
        verification = '[[ "$(git -C driver rev-parse HEAD)" == "$DISPATCHER_SHA" ]]'
        self.assertLess(self.workflow.index(verification), self.workflow.index("secrets.PROOF_CONTROLLER_SSH_KEY"))
        action_refs = re.findall(r"uses: [^@\s]+@([^\s]+)", self.workflow)
        self.assertTrue(action_refs)
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{40}", value) for value in action_refs))

        upload = self.workflow.split("      - name: Upload allowlisted controller proof\n", 1)[1].split(
            "      - name: Remove only this runner's controller credentials\n", 1)[0]
        paths = re.findall(r"^\s+\$\{\{ runner\.temp \}\}(/[^\n]+)$", upload, re.MULTILINE)
        self.assertEqual(paths, [
            "/proof-controller-${{ github.run_id }}-${{ github.run_attempt }}/public/outcome.json",
            "/proof-controller-${{ github.run_id }}-${{ github.run_attempt }}/public/viewport.png",
        ])
        self.assertEqual(self.workflow.count("if: ${{ always() }}"), 3)
        for forbidden in ("path: candidate", "onboarding_proof.py", "ONBOARDING_OPERATOR_CONFIG", "rm -rf"):
            self.assertNotIn(forbidden, self.workflow)


if __name__ == "__main__":
    unittest.main()
