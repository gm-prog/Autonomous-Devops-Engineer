import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from application.services.remediation_validation_runner import (
    RemediationValidationRunner,
    UnknownValidationProfileError,
    ValidationStep,
    ValidationWorkspaceMutationError,
)
from application.services.remediation_workspace_service import RemediationWorkspace

SOURCE_SHA = "a" * 40


def make_workspace():
    root = Path(tempfile.mkdtemp(prefix="devops-remediation-validation-"))
    repo = root / "repository"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Validation Test"], cwd=repo, check=True)
    target = repo / "service.py"
    target.write_text("print('old')\n", encoding="utf-8")
    subprocess.run(["git", "add", "service.py"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "fixture"], cwd=repo, check=True)
    target.write_text("print('new')\n", encoding="utf-8")
    return root, RemediationWorkspace(
        path=str(repo), cleanup_path=str(root), repository_slug="owner/repo",
        source_sha=SOURCE_SHA, base_branch="main",
        branch_name="automation/remediation/inc-1/proposal-1",
    )


def profile(command: str) -> dict[str, tuple[ValidationStep, ...]]:
    return {"test": (ValidationStep(
        name="test-step", working_directory=".",
        argv=("python", "-c", command), timeout_seconds=5, max_output_bytes=4096,
    ),)}


class RemediationValidationRunnerTests(unittest.TestCase):
    def test_unknown_profile_is_rejected(self):
        root, workspace = make_workspace()
        try:
            with self.assertRaises(UnknownValidationProfileError):
                RemediationValidationRunner(profile("print('ok')")).validate(workspace, "unknown", "service.py")
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_fixed_profile_passes_when_command_succeeds(self):
        root, workspace = make_workspace()
        try:
            result = RemediationValidationRunner(profile("print('ok')")).validate(workspace, "test", "service.py")
            self.assertTrue(result.passed)
            self.assertEqual(result.steps[0].exit_code, 0)
            self.assertFalse(result.steps[0].timed_out)
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_nonzero_command_fails_validation(self):
        root, workspace = make_workspace()
        try:
            result = RemediationValidationRunner(profile("raise SystemExit(3)")).validate(workspace, "test", "service.py")
            self.assertFalse(result.passed)
            self.assertEqual(result.steps[0].exit_code, 3)
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_workspace_mutation_is_rejected(self):
        root, workspace = make_workspace()
        try:
            with self.assertRaises(ValidationWorkspaceMutationError):
                RemediationValidationRunner(profile(
                    "from pathlib import Path; Path('unexpected.txt').write_text('mutation')"
                )).validate(workspace, "test", "service.py")
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_timeout_is_reported_and_process_does_not_pass(self):
        root, workspace = make_workspace()
        try:
            result = RemediationValidationRunner({
                "test": (ValidationStep(
                    name="timeout", working_directory=".",
                    argv=("python", "-c", "import time; time.sleep(10)"),
                    timeout_seconds=0.2, max_output_bytes=4096,
                ),)
            }).validate(workspace, "test", "service.py")
            self.assertFalse(result.passed)
            self.assertTrue(result.steps[0].timed_out)
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_secret_environment_is_not_forwarded(self):
        root, workspace = make_workspace()
        try:
            os.environ["UNIT_TEST_SECRET_TOKEN"] = "should-not-forward"
            result = RemediationValidationRunner(profile(
                "import os; print(os.getenv('UNIT_TEST_SECRET_TOKEN', 'missing'))"
            )).validate(workspace, "test", "service.py")
            self.assertTrue(result.passed)
            self.assertIn("missing", result.steps[0].stdout)
            self.assertNotIn("should-not-forward", result.steps[0].stdout)
        finally:
            os.environ.pop("UNIT_TEST_SECRET_TOKEN", None)
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_profile_rejects_non_python_executable(self):
        with self.assertRaises(ValueError):
            RemediationValidationRunner({"bad": (ValidationStep(
                name="bad", working_directory=".",
                argv=("sh", "-c", "echo unsafe"),
            ),)})


if __name__ == "__main__":
    unittest.main()
