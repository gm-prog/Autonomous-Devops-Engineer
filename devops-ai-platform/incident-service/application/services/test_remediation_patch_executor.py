import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from application.services.remediation_patch_executor import (
    PatchApplicationRejectedError,
    PatchPostconditionError,
    PatchSourceMismatchError,
    PatchWorkspaceDirtyError,
    RemediationPatchExecutor,
)
from application.services.remediation_workspace_service import RemediationWorkspace
from domain.entities.hotfix_proposal import HotfixProposal


SOURCE_SHA = "a" * 40
PATCH = """--- a/src/service.py
+++ b/src/service.py
@@ -1 +1 @@
-old()
+new()
"""


class RemediationPatchExecutorTests(unittest.TestCase):
    def _create_workspace(self, content="old()\n"):
        root = Path(tempfile.mkdtemp(prefix="devops-remediation-"))
        repo = root / "repository"
        repo.mkdir()

        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=repo,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Remediation Test"],
            cwd=repo,
            check=True,
        )
        target = repo / "src" / "service.py"
        target.parent.mkdir(parents=True)
        target.write_text(content, encoding="utf-8")
        subprocess.run(["git", "add", "src/service.py"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "fixture"], cwd=repo, check=True)

        return root, RemediationWorkspace(
            path=str(repo),
            cleanup_path=str(root),
            repository_slug="owner/repo",
            source_sha=SOURCE_SHA,
            base_branch="main",
            branch_name="automation/remediation/inc-1/proposal-1",
        )

    def _proposal(self, source_sha=SOURCE_SHA, patch=PATCH):
        proposal = HotfixProposal(
            id="proposal-1",
            target_filepath="src/service.py",
            diff_patch_payload=patch,
            source_sha=source_sha,
        )
        proposal.apply_verification_pass()
        return proposal

    def test_applies_verified_patch_and_changes_only_target(self):
        root, workspace = self._create_workspace()
        try:
            proposal = self._proposal()
            result = RemediationPatchExecutor().apply(workspace, proposal)

            self.assertEqual(result.source_sha, SOURCE_SHA)
            self.assertEqual(result.target_filepath, "src/service.py")
            self.assertEqual(result.changed_paths, ("src/service.py",))
            self.assertEqual(
                Path(workspace.path, "src/service.py").read_text(encoding="utf-8"),
                "new()\n",
            )
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_source_sha_mismatch_is_rejected_before_git_mutation(self):
        root, workspace = self._create_workspace()
        try:
            proposal = self._proposal(source_sha="b" * 40)
            with self.assertRaises(PatchSourceMismatchError):
                RemediationPatchExecutor().apply(workspace, proposal)
            self.assertEqual(
                Path(workspace.path, "src/service.py").read_text(encoding="utf-8"),
                "old()\n",
            )
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_unverified_proposal_is_rejected(self):
        root, workspace = self._create_workspace()
        try:
            proposal = HotfixProposal(
                "proposal-1",
                "src/service.py",
                PATCH,
                source_sha=SOURCE_SHA,
            )
            with self.assertRaises(PatchSourceMismatchError):
                RemediationPatchExecutor().apply(workspace, proposal)
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_dirty_workspace_is_rejected(self):
        root, workspace = self._create_workspace()
        try:
            Path(workspace.path, "src/service.py").write_text("already changed\n", encoding="utf-8")
            with self.assertRaises(PatchWorkspaceDirtyError):
                RemediationPatchExecutor().apply(workspace, self._proposal())
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_multi_file_patch_is_rejected_by_proposal_verifier(self):
        root, workspace = self._create_workspace()
        try:
            patch = PATCH + """--- a/src/other.py
+++ b/src/other.py
@@ -1 +1 @@
-old()
+new()
"""
            with self.assertRaises(PatchSourceMismatchError):
                RemediationPatchExecutor().apply(
                    workspace,
                    self._proposal(patch=patch),
                )
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_invalid_patch_is_rejected_without_partial_change(self):
        root, workspace = self._create_workspace()
        try:
            proposal = self._proposal(
                patch="""--- a/src/service.py
+++ b/src/service.py
@@ -100 +100 @@
-missing()
+new()
"""
            )
            with self.assertRaises(PatchApplicationRejectedError):
                RemediationPatchExecutor().apply(workspace, proposal)
            self.assertEqual(
                Path(workspace.path, "src/service.py").read_text(encoding="utf-8"),
                "old()\n",
            )
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

    def test_postcondition_rejects_unexpected_extra_change(self):
        root, workspace = self._create_workspace()
        try:
            proposal = self._proposal()
            Path(workspace.path, "README.md").write_text("unexpected\n", encoding="utf-8")
            with self.assertRaises(PatchWorkspaceDirtyError):
                RemediationPatchExecutor().apply(workspace, proposal)
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
