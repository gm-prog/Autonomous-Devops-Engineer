import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from incident_service.application.services.remediation_commit_service import (
    CommitSourceMismatchError,
    CommitWorkspaceDirtyError,
    RemediationCommitService,
)
from incident_service.application.services.remediation_workspace_service import (
    RemediationWorkspace,
    RemediationWorkspaceService,
    UnsafeRemediationBranchError,
)


class RemediationCommitServiceTests(unittest.TestCase):
    def _workspace(self, content="old()\n"):
        root = Path(tempfile.mkdtemp(prefix="devops-remediation-commit-"))
        repo = root / "repository"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Remediation Test"], cwd=repo, check=True)
        target = repo / "src" / "service.py"
        target.parent.mkdir()
        target.write_text(content, encoding="utf-8")
        subprocess.run(["git", "add", "--", "src/service.py"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "fixture"], cwd=repo, check=True)
        source_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo, check=True,
            capture_output=True, text=True,
        ).stdout.strip()
        branch = RemediationWorkspaceService.build_branch_name("inc-1", "proposal-1")
        subprocess.run(["git", "checkout", "-q", "-b", branch], cwd=repo, check=True)
        target.write_text("new()\n", encoding="utf-8")
        return root, RemediationWorkspace(
            path=str(repo),
            cleanup_path=str(root),
            repository_slug="owner/repo",
            source_sha=source_sha,
            base_branch="main",
            branch_name=branch,
        )

    def tearDown(self):
        for root in getattr(self, "_roots", []):
            shutil.rmtree(root, ignore_errors=True)

    def setUp(self):
        self._roots = []

    def test_creates_single_target_commit_with_pinned_parent(self):
        root, workspace = self._workspace()
        self._roots.append(root)

        result = RemediationCommitService().create(
            workspace, "src/service.py", "inc-1", "proposal-1"
        )

        self.assertEqual(result.parent_sha, workspace.source_sha)
        self.assertEqual(result.target_filepath, "src/service.py")
        self.assertEqual(result.commit_message, "chore(remediation): incident inc-1 proposal proposal-1")

        parent = subprocess.run(
            ["git", "rev-parse", "HEAD^"], cwd=workspace.path,
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        self.assertEqual(parent, workspace.source_sha)

        status = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=workspace.path, check=True, capture_output=True, text=True,
        ).stdout.strip()
        self.assertEqual(status, "")

        changed = subprocess.run(
            ["git", "show", "--format=", "--name-status", result.commit_sha],
            cwd=workspace.path, check=True, capture_output=True, text=True,
        ).stdout.splitlines()
        self.assertEqual(changed, ["M\tsrc/service.py"])

    def test_source_sha_mismatch_is_rejected_before_staging(self):
        root, workspace = self._workspace()
        self._roots.append(root)
        workspace = RemediationWorkspace(**{
            **workspace.__dict__, "source_sha": "a" * 40
        })

        with self.assertRaises(CommitSourceMismatchError):
            RemediationCommitService().create(
                workspace, "src/service.py", "inc-1", "proposal-1"
            )

    def test_dirty_workspace_is_rejected(self):
        root, workspace = self._workspace()
        self._roots.append(root)
        Path(workspace.path, "extra.txt").write_text("unexpected\n", encoding="utf-8")

        with self.assertRaises(CommitWorkspaceDirtyError):
            RemediationCommitService().create(
                workspace, "src/service.py", "inc-1", "proposal-1"
            )

    def test_non_deterministic_branch_is_rejected(self):
        root, workspace = self._workspace()
        self._roots.append(root)
        workspace = RemediationWorkspace(**{
            **workspace.__dict__, "branch_name": "feature/user-controlled"
        })

        with self.assertRaises(UnsafeRemediationBranchError):
            RemediationCommitService().create(
                workspace, "src/service.py", "inc-1", "proposal-1"
            )

    def test_target_path_traversal_is_rejected(self):
        root, workspace = self._workspace()
        self._roots.append(root)

        with self.assertRaises(Exception):
            RemediationCommitService().create(
                workspace, "../service.py", "inc-1", "proposal-1"
            )


if __name__ == "__main__":
    unittest.main()
