import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
CI_SCRIPT = ROOT / "scripts" / "ci"


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
            "runs-on: ubuntu-latest",
            "runs-on: windows-latest",
        )
        for fragment in required_fragments:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, workflow)

    def test_every_ci_job_uses_the_repository_gate(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertEqual(workflow.count("./scripts/ci check"), 1)
        self.assertEqual(workflow.count("./scripts/ci test"), 1)
        self.assertEqual(workflow.count("./scripts/ci all"), 1)

    def test_repository_gate_is_executable_and_its_check_passes(self) -> None:
        self.assertTrue(CI_SCRIPT.stat().st_mode & 0o111)
        result = subprocess.run(
            [str(CI_SCRIPT), "check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
