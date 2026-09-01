import os
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
SECURITY_WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"
CI_SCRIPT = ROOT / "scripts" / "ci"
DEPENDABOT = ROOT / ".github" / "dependabot.yml"


class CIContractTests(unittest.TestCase):
    def test_pull_requests_and_main_run_least_privilege_ci(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        required_fragments = (
            "pull_request:",
            "push:",
            "branches: [main]",
            "permissions:\n  contents: read",
            "cancel-in-progress: true",
            "timeout-minutes:",
            "name: Check",
            "name: Test",
            "name: Windows",
            "name: macOS",
            "runs-on: ubuntu-latest",
            "runs-on: windows-latest",
            "runs-on: macos-latest",
        )
        for fragment in required_fragments:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, workflow)

    def test_every_ci_job_uses_the_repository_gate(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertEqual(workflow.count("./scripts/ci check"), 1)
        self.assertEqual(workflow.count("./scripts/ci test"), 1)
        self.assertEqual(workflow.count("./scripts/ci all"), 2)

    @unittest.skipIf(os.name == "nt", "Windows does not expose Git executable bits")
    def test_repository_gate_is_executable_on_posix(self) -> None:
        self.assertTrue(CI_SCRIPT.stat().st_mode & 0o111)

    def test_actions_are_pinned_and_dependabot_updates_them(self) -> None:
        workflows = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted((ROOT / ".github" / "workflows").glob("*.yml"))
        )
        action_refs = re.findall(r"uses: [^@\s]+@([^\s]+)", workflows)

        self.assertGreaterEqual(len(action_refs), 3)
        for action_ref in action_refs:
            with self.subTest(action_ref=action_ref):
                self.assertRegex(action_ref, r"^[0-9a-f]{40}$")

        dependabot = DEPENDABOT.read_text(encoding="utf-8")
        self.assertIn('package-ecosystem: "github-actions"', dependabot)
        self.assertIn("interval: weekly", dependabot)

    def test_pull_requests_scan_changed_content_for_secrets(self) -> None:
        workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("pull_request:", workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("name: Secrets", workflow)
        self.assertIn("trufflesecurity/trufflehog@", workflow)
        self.assertIn("--results=verified,unknown", workflow)


if __name__ == "__main__":
    unittest.main()
