import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from application.services.remediation_workspace_service import (
    InvalidSourceRevisionError,
    RemediationWorkspaceService,
    UnsafeRemediationBranchError,
)


class RemediationWorkspaceServiceTests(unittest.TestCase):
    def test_invalid_source_sha_is_rejected_before_git(self):
        service = RemediationWorkspaceService()

        with patch.object(service, "_run_git") as git:
            with self.assertRaises(InvalidSourceRevisionError):
                service.prepare(
                    "owner/repo",
                    "not-a-sha",
                    "incident-1",
                    "proposal-1",
                )

        git.assert_not_called()

    def test_branch_name_is_deterministic_sanitized_and_bounded(self):
        branch = RemediationWorkspaceService.build_branch_name(
            " incident/1 ; rm -rf / ",
            "proposal:with spaces and " + ("x" * 80),
        )

        self.assertTrue(branch.startswith("automation/remediation/"))
        self.assertNotIn(" ", branch)
        self.assertNotIn(";", branch)
        self.assertNotIn("..", branch)
        self.assertLessEqual(len(branch), 120)

    def test_protected_head_branch_is_rejected(self):
        service = RemediationWorkspaceService()

        with self.assertRaises(UnsafeRemediationBranchError):
            service.validate_head_branch("main", "main")

        with self.assertRaises(UnsafeRemediationBranchError):
            service.validate_head_branch("production", "main")

    def test_prepare_pins_checkout_and_creates_controlled_branch(self):
        service = RemediationWorkspaceService()

        def fake_git(args, cwd=None):
            command = list(args)
            if command[:3] == ["git", "rev-parse", "HEAD"]:
                return Mock(stdout="a" * 40 + "\n")
            return Mock(stdout="")

        with patch.object(service, "_run_git", side_effect=fake_git) as git:
            workspace = service.prepare(
                "owner/repo",
                "A" * 40,
                "inc-1",
                "proposal-1",
                base_branch="main",
            )

        self.assertEqual(workspace.source_sha, "a" * 40)
        self.assertEqual(workspace.base_branch, "main")
        self.assertEqual(
            workspace.branch_name,
            "automation/remediation/inc-1/proposal-1",
        )
        calls = [call.args[0] for call in git.call_args_list]
        self.assertIn(
            ["git", "fetch", "--no-tags", "origin", "a" * 40],
            calls,
        )
        self.assertIn(
            ["git", "checkout", "--detach", "a" * 40],
            calls,
        )
        self.assertIn(
            ["git", "switch", "--create", "automation/remediation/inc-1/proposal-1"],
            calls,
        )

        service.cleanup(workspace)
        self.assertFalse(Path(workspace.cleanup_path).exists())

    def test_workspace_cleanup_is_idempotent_and_isolated(self):
        service = RemediationWorkspaceService()
        root = Path(tempfile.mkdtemp(prefix=service.workspace_prefix))
        (root / "marker.txt").write_text("only this workspace", encoding="utf-8")
        service._active_workspaces.add(root.resolve())

        workspace = type("Workspace", (), {"cleanup_path": str(root)})()
        service.cleanup(workspace)
        service.cleanup(workspace)

        self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
