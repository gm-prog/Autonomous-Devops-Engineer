import unittest
from unittest.mock import Mock

from application.services.remediation_orchestration_service import RemediationOrchestrationService
from application.services.remediation_workspace_service import RemediationWorkspace
from domain.entities.hotfix_proposal import HotfixProposal


class RemediationOrchestrationServiceTests(unittest.TestCase):
    def setUp(self):
        self.workspace_service = Mock()
        self.workspace_service.prepare.return_value = RemediationWorkspace(
            path="/tmp/workspace",
            cleanup_path="/tmp/workspace-root",
            repository_slug="owner/repo",
            source_sha="a" * 40,
            base_branch="main",
            branch_name="automation/remediation/inc-1/proposal-1",
        )
        self.patch_executor = Mock()
        self.patch_executor.apply.return_value = Mock(
            target_filepath="src/service.py"
        )
        self.validation_runner = Mock()
        self.validation_runner.validate.return_value = Mock(
            passed=True,
            source_sha="a" * 40,
        )
        self.commit_service = Mock()
        self.commit_service.create.return_value = Mock(
            parent_sha="a" * 40,
            commit_sha="b" * 40,
            branch_name="automation/remediation/inc-1/proposal-1",
            target_filepath="src/service.py",
        )
        self.github = Mock()
        self.github.create_branch_from_commit.return_value = (
            "https://github.com/owner/repo/tree/automation/remediation/inc-1/proposal-1"
        )
        self.github.create_pull_request.return_value = (
            "https://github.com/owner/repo/pull/42"
        )
        self.service = RemediationOrchestrationService(
            self.workspace_service,
            self.patch_executor,
            self.validation_runner,
            self.commit_service,
            self.github,
        )

    def test_full_flow_is_strictly_ordered_and_cleans_workspace(self):
        proposal = HotfixProposal(
            id="proposal-1",
            target_filepath="src/service.py",
            diff_patch_payload="--- a/src/service.py\n+++ b/src/service.py\n@@ -1 +1 @@\n-old\n+new\n",
            is_verified=True,
            source_sha="a" * 40,
        )

        result = self.service.execute(
            incident_id="inc-1",
            proposal=proposal,
            repository_slug="owner/repo",
        )

        self.assertEqual(result.commit_sha, "b" * 40)
        self.assertEqual(result.pull_request_url, "https://github.com/owner/repo/pull/42")
        self.patch_executor.apply.assert_called_once()
        self.validation_runner.validate.assert_called_once()
        self.commit_service.create.assert_called_once()
        self.github.create_branch_from_commit.assert_called_once()
        self.github.create_pull_request.assert_called_once()
        self.workspace_service.cleanup.assert_called_once()

    def test_failed_validation_never_commits_or_publishes(self):
        self.validation_runner.validate.return_value = Mock(
            passed=False,
            source_sha="a" * 40,
        )
        proposal = HotfixProposal(
            id="proposal-1",
            target_filepath="src/service.py",
            diff_patch_payload="patch",
            is_verified=True,
            source_sha="a" * 40,
        )

        with self.assertRaises(RuntimeError):
            self.service.execute("inc-1", proposal, "owner/repo")

        self.commit_service.create.assert_not_called()
        self.github.create_branch_from_commit.assert_not_called()
        self.github.create_pull_request.assert_not_called()
        self.workspace_service.cleanup.assert_called_once()

    def test_invalid_proposal_never_prepares_workspace(self):
        proposal = HotfixProposal(
            id="proposal-1",
            target_filepath="src/service.py",
            diff_patch_payload="patch",
            is_verified=False,
            source_sha="a" * 40,
        )

        with self.assertRaises(ValueError):
            self.service.execute("inc-1", proposal, "owner/repo")

        self.workspace_service.prepare.assert_not_called()


if __name__ == "__main__":
    unittest.main()
