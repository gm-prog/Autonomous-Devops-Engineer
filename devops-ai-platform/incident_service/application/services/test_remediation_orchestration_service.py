import unittest
from unittest.mock import Mock

from incident_service.application.failures import (
    ExistingPullRequestConflict,
    RemoteBranchConflict,
    RemoteReconciliationFailed,
)
from incident_service.application.services.remediation_orchestration_service import (
    RemediationOrchestrationService,
)
from incident_service.application.services.remediation_workspace_service import (
    RemediationWorkspace,
)
from incident_service.domain.entities.hotfix_proposal import HotfixProposal
from incident_service.infrastructure.source_provider.github_pr_client import (
    ExistingPullRequest,
    PullRequestLookupFailedException,
)


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
        # Phase 6.2.1: discovery always runs before POST /pulls
        self.github.find_existing_pull_requests.return_value = []
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


class PullRequestReconciliationTests(unittest.TestCase):
    """Phase 6.2.1: PR discovery/reconciliation policy (§40/§44)."""

    BRANCH = "automation/remediation/inc-1/proposal-1"
    HASH = "c" * 64

    def setUp(self):
        self.workspace_service = Mock()
        self.workspace_service.prepare.return_value = RemediationWorkspace(
            path="/tmp/workspace",
            cleanup_path="/tmp/workspace-root",
            repository_slug="owner/repo",
            source_sha="a" * 40,
            base_branch="main",
            branch_name=self.BRANCH,
        )
        self.patch_executor = Mock()
        self.patch_executor.apply.return_value = Mock(target_filepath="src/service.py")
        self.validation_runner = Mock()
        self.validation_runner.validate.return_value = Mock(
            passed=True, source_sha="a" * 40
        )
        self.commit_service = Mock()
        self.commit_service.create.return_value = Mock(
            parent_sha="a" * 40,
            commit_sha="b" * 40,
            branch_name=self.BRANCH,
            target_filepath="src/service.py",
        )
        self.github = Mock()
        self.github.create_branch_from_commit.return_value = (
            "https://github.com/owner/repo/tree/" + self.BRANCH
        )
        self.github.create_pull_request.return_value = (
            "https://github.com/owner/repo/pull/42"
        )
        self.github.find_existing_pull_requests.return_value = []
        self.service = RemediationOrchestrationService(
            self.workspace_service,
            self.patch_executor,
            self.validation_runner,
            self.commit_service,
            self.github,
        )
        self.proposal = HotfixProposal(
            id="proposal-1",
            target_filepath="src/service.py",
            diff_patch_payload=(
                "--- a/src/service.py\n+++ b/src/service.py\n"
                "@@ -1 +1 @@\n-old\n+new\n"
            ),
            is_verified=True,
            source_sha="a" * 40,
        )
        self.proposal.proposal_hash = self.HASH
        self.proposal.commit_sha = "b" * 40
        self.proposal.branch_name = self.BRANCH

    def _run(self, stage_callback=None):
        return self.service.execute(
            incident_id="inc-1",
            proposal=self.proposal,
            repository_slug="owner/repo",
            stage_callback=stage_callback,
        )

    @staticmethod
    def _pull(
        *,
        state="open",
        merged=False,
        head_ref="automation/remediation/inc-1/proposal-1",
        base_ref="main",
        body="Proposal hash: " + "c" * 64,
        number=7,
    ):
        return ExistingPullRequest(
            number=number,
            url=f"https://github.com/owner/repo/pull/{number}",
            state=state,
            draft=True,
            merged=merged,
            head_ref=head_ref,
            base_ref=base_ref,
            body=body,
        )

    # --- reuse / conflict matrix -----------------------------------------
    def test_single_open_corroborated_pr_is_reused_without_post(self):
        self.github.find_existing_pull_requests.return_value = [self._pull()]
        result = self._run()
        self.assertEqual(result.pull_request_url, "https://github.com/owner/repo/pull/7")
        self.github.create_pull_request.assert_not_called()

    def test_merged_pr_fails_closed_without_second_post(self):
        self.github.find_existing_pull_requests.return_value = [
            self._pull(state="closed", merged=True)
        ]
        with self.assertRaises(ExistingPullRequestConflict):
            self._run()
        self.github.create_pull_request.assert_not_called()

    def test_closed_unmerged_pr_fails_closed(self):
        self.github.find_existing_pull_requests.return_value = [
            self._pull(state="closed")
        ]
        with self.assertRaises(ExistingPullRequestConflict):
            self._run()
        self.github.create_pull_request.assert_not_called()

    def test_multiple_matching_prs_fail_closed(self):
        self.github.find_existing_pull_requests.return_value = [
            self._pull(number=7),
            self._pull(number=8),
        ]
        with self.assertRaises(ExistingPullRequestConflict):
            self._run()
        self.github.create_pull_request.assert_not_called()

    def test_body_hash_mismatch_fails_closed_corroboration_only(self):
        self.github.find_existing_pull_requests.return_value = [
            self._pull(body="Proposal hash: deadbeef")
        ]
        with self.assertRaises(ExistingPullRequestConflict):
            self._run()
        self.github.create_pull_request.assert_not_called()

    def test_unexpected_discovery_result_fails_closed(self):
        self.github.find_existing_pull_requests.return_value = {"oops": True}
        with self.assertRaises(RemoteReconciliationFailed):
            self._run()
        self.github.create_pull_request.assert_not_called()

    def test_discovery_transport_failure_maps_to_reconciliation_failed(self):
        self.github.find_existing_pull_requests.side_effect = (
            PullRequestLookupFailedException("boom")
        )
        with self.assertRaises(RemoteReconciliationFailed):
            self._run()
        self.github.create_pull_request.assert_not_called()

    # --- ordering / stage events -------------------------------------------
    def test_discovery_stage_precedes_creation_and_create_posts_once(self):
        seen = []
        stages = []

        def callback(stage, metadata):
            stages.append(stage)

        self._run(stage_callback=callback)
        self.assertIn("pr.discovery", stages)
        self.assertIn("pr.created", stages)
        self.assertLess(
            stages.index("pr.discovery"), stages.index("pr.created")
        )
        self.assertEqual(stages.count("pr.created"), 1)
        self.github.find_existing_pull_requests.assert_called_once()
        self.github.create_pull_request.assert_called_once()

    def test_discovery_identity_is_exact_deterministic_head_and_base(self):
        self._run()
        kwargs = self.github.find_existing_pull_requests.call_args.kwargs
        self.assertEqual(kwargs["repo_slug"], "owner/repo")
        self.assertEqual(kwargs["head"], self.BRANCH)
        self.assertEqual(kwargs["base"], "main")

    # --- resume path (reconcile_and_create_pr) ------------------------------
    def _reconcile(self, stage_callback=None):
        return self.service.reconcile_and_create_pr(
            incident_id="inc-1",
            proposal=self.proposal,
            repository_slug="owner/repo",
            stage_callback=stage_callback,
        )

    def test_resume_with_matching_remote_reuses_remote_branch(self):
        self.workspace_service.inspect_remote_branch.return_value = "b" * 40
        self.github.find_existing_pull_requests.return_value = [self._pull()]
        url = self._reconcile()
        self.assertEqual(url, "https://github.com/owner/repo/pull/7")
        self.workspace_service.prepare.assert_not_called()
        self.commit_service.create.assert_not_called()
        self.github.create_pull_request.assert_not_called()

    def test_resume_with_missing_remote_fails_closed(self):
        self.workspace_service.inspect_remote_branch.return_value = None
        with self.assertRaises(RemoteReconciliationFailed):
            self._reconcile()
        self.github.find_existing_pull_requests.assert_not_called()
        self.github.create_pull_request.assert_not_called()

    def test_resume_with_moved_remote_fails_closed_without_force(self):
        self.workspace_service.inspect_remote_branch.return_value = "f" * 40
        with self.assertRaises(RemoteBranchConflict):
            self._reconcile()
        self.github.find_existing_pull_requests.assert_not_called()
        self.github.create_pull_request.assert_not_called()

    def test_resume_discovers_before_creating_when_no_pr_exists(self):
        self.workspace_service.inspect_remote_branch.return_value = "b" * 40
        stages = []
        url = self._reconcile(
            stage_callback=lambda stage, metadata: stages.append(stage)
        )
        self.assertTrue(url.endswith("/pull/42"))
        self.assertIn("pr.discovery", stages)
        self.assertIn("pr.created", stages)
        self.github.create_pull_request.assert_called_once()
