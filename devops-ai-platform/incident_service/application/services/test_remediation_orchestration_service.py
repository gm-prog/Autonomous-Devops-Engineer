import unittest
from unittest.mock import Mock

from incident_service.application.failures import (
    ExistingPullRequestConflict,
    RemoteBranchConflict,
    RemoteReconciliationFailed,
)
from incident_service.application.services.remediation_orchestration_service import (
    RemediationOrchestrationService,
    RemediationStageGuardError,
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
        # Phase 6.2.1: discovery always runs before POST /pulls; after a
        # create, discovery returns the created PR so post-create exact
        # identity verification (6.2.1B) can succeed
        self.github.find_existing_pull_requests.return_value = []
        self._install_create_aware_discovery()
        self.service = RemediationOrchestrationService(
            self.workspace_service,
            self.patch_executor,
            self.validation_runner,
            self.commit_service,
            self.github,
        )

    def _created_pull_payload(self):
        return ExistingPullRequest(
            number=42,
            url="https://github.com/owner/repo/pull/42",
            state="open",
            draft=True,
            merged=False,
            head_ref="automation/remediation/inc-1/proposal-1",
            base_ref="main",
            body="Proposal hash: n/a",
            head_sha="b" * 40,
            head_repository="owner/repo",
        )

    def _install_create_aware_discovery(self):
        """[] until a PR has been created; then the created PR itself."""
        def _discovery(**kwargs):
            if self.github.create_pull_request.call_count == 0:
                return []
            return [self._created_pull_payload()]

        self.github.find_existing_pull_requests.side_effect = _discovery

    def test_full_flow_is_strictly_ordered_and_cleans_workspace(self):
        proposal = HotfixProposal(
            id="proposal-1",
            target_filepath="src/service.py",
            diff_patch_payload="--- a/src/service.py\n+++ b/src/service.py\n@@ -1 +1 @@\n-old\n+new\n",
            is_verified=True,
            source_sha="a" * 40,
        )
        proposal.repository = "owner/repo"

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


class PreSideEffectGuardBoundaryTests(unittest.TestCase):
    """Phase 6.2.1B Goal B: ownership loss BEFORE a side effect means the
    side-effecting function is NEVER invoked (not merely a later
    callback failure)."""

    # boundary name -> the mock whose method must not be called
    BOUNDARIES = (
        ("workspace.prepare", "workspace_service.prepare"),
        ("patch.apply", "patch_executor.apply"),
        ("validation.run", "validation_runner.validate"),
        ("commit.create", "commit_service.create"),
        ("remote.publish", "workspace_service.publish_branch"),
        ("remote.branch.create", "github.create_branch_from_commit"),
        ("pr.discovery", "github.find_existing_pull_requests"),
        ("pr.create", "github.create_pull_request"),
    )

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
            passed=True, source_sha="a" * 40
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
            "https://github.com/owner/repo/tree/automation/remediation"
        )
        self.github.create_pull_request.return_value = (
            "https://github.com/owner/repo/pull/42"
        )

        def _discovery(**kwargs):
            if self.github.create_pull_request.call_count == 0:
                return []
            return [
                ExistingPullRequest(
                    number=42,
                    url="https://github.com/owner/repo/pull/42",
                    state="open",
                    draft=True,
                    merged=False,
                    head_ref="automation/remediation/inc-1/proposal-1",
                    base_ref="main",
                    body="",
                    head_sha="b" * 40,
                    head_repository="owner/repo",
                )
            ]

        self.github.find_existing_pull_requests.side_effect = _discovery
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
            repository="owner/repo",
        )

    @staticmethod
    def _guard_failing_at(target):
        seen = []

        def guard(operation):
            seen.append(operation)
            if operation == target:
                raise RemediationStageGuardError(
                    f"lease lost before {operation}"
                )

        return guard, seen

    def test_ownership_loss_blocks_every_side_effect_boundary(self):
        for target, mock_path in self.BOUNDARIES:
            with self.subTest(target=target):
                # fresh mocks per iteration
                self.setUp()
                guard, seen = self._guard_failing_at(target)
                with self.assertRaises(RemediationStageGuardError):
                    self.service.execute(
                        incident_id="inc-1",
                        proposal=self.proposal,
                        repository_slug="owner/repo",
                        before_side_effect=guard,
                    )
                # the guarded side-effecting operation never ran
                mock = self
                for attr in mock_path.split("."):
                    mock = getattr(mock, attr)
                mock.assert_not_called()
                # earlier boundaries DID run (guard is checked in order)
                self.assertIn(target, seen)
                # nothing after the failed boundary ran
                for later, later_path in self.BOUNDARIES[
                    [b for b, _ in self.BOUNDARIES].index(target) + 1:
                ]:
                    later_mock = self
                    for attr in later_path.split("."):
                        later_mock = getattr(later_mock, attr)
                    later_mock.assert_not_called()

    def test_guard_runs_for_every_boundary_in_order_on_success(self):
        guard, seen = self._guard_failing_at("__never__")
        self.service.execute(
            incident_id="inc-1",
            proposal=self.proposal,
            repository_slug="owner/repo",
            before_side_effect=guard,
        )
        self.assertEqual(
            seen, [name for name, _ in self.BOUNDARIES]
        )

    def test_resume_path_guard_blocks_remote_inspect(self):
        self.proposal.commit_sha = "b" * 40
        self.proposal.branch_name = "automation/remediation/inc-1/proposal-1"
        self.workspace_service.inspect_remote_branch.return_value = "b" * 40
        guard, _seen = self._guard_failing_at("remote.inspect")
        with self.assertRaises(RemediationStageGuardError):
            self.service.reconcile_and_create_pr(
                incident_id="inc-1",
                proposal=self.proposal,
                repository_slug="owner/repo",
                before_side_effect=guard,
            )
        self.workspace_service.inspect_remote_branch.assert_not_called()
        self.github.find_existing_pull_requests.assert_not_called()
        self.github.create_pull_request.assert_not_called()

    def test_resume_path_guard_blocks_before_pr_discovery(self):
        self.proposal.commit_sha = "b" * 40
        self.proposal.branch_name = "automation/remediation/inc-1/proposal-1"
        self.workspace_service.inspect_remote_branch.return_value = "b" * 40
        guard, seen = self._guard_failing_at("pr.discovery")
        with self.assertRaises(RemediationStageGuardError):
            self.service.reconcile_and_create_pr(
                incident_id="inc-1",
                proposal=self.proposal,
                repository_slug="owner/repo",
                before_side_effect=guard,
            )
        self.assertEqual(
            seen,
            ["remote.inspect", "remote.branch.create", "pr.discovery"],
        )
        self.github.find_existing_pull_requests.assert_not_called()
        self.github.create_pull_request.assert_not_called()

    def test_store_uncertainty_blocks_side_effect(self):
        def guard(operation):
            raise RemediationStageGuardError(
                "durable claim store unavailable; cannot authorize"
            )

        with self.assertRaises(RemediationStageGuardError):
            self.service.execute(
                incident_id="inc-1",
                proposal=self.proposal,
                repository_slug="owner/repo",
                before_side_effect=guard,
            )
        # nothing side-effecting ever ran
        self.workspace_service.prepare.assert_not_called()
        self.patch_executor.apply.assert_not_called()
        self.github.create_pull_request.assert_not_called()


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
        self.proposal.repository = "owner/repo"

    def _created_pull_payload(self):
        return ExistingPullRequest(
            number=42,
            url="https://github.com/owner/repo/pull/42",
            state="open",
            draft=True,
            merged=False,
            head_ref=self.BRANCH,
            base_ref="main",
            body=f"Proposal hash: {self.HASH}",
            head_sha="b" * 40,
            head_repository="owner/repo",
        )

    def _maybe_install_create_aware_discovery(self):
        """Install verification-aware discovery only when the test uses
        the default empty result (fixed overrides + error side_effects
        are left untouched)."""
        mock = self.github.find_existing_pull_requests
        if mock.side_effect is not None:
            return  # explicit transport/error behavior
        if mock.return_value != []:
            return  # explicit fixed discovery payload

        def _discovery(**kwargs):
            if self.github.create_pull_request.call_count == 0:
                return []
            return [self._created_pull_payload()]

        mock.side_effect = _discovery

    def _run(self, stage_callback=None):
        self._maybe_install_create_aware_discovery()
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
        head_sha="b" * 40,          # == proposal.commit_sha
        head_repository="owner/repo",  # == proposal.repository
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
            head_sha=head_sha,
            head_repository=head_repository,
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

    def test_exact_repository_branch_sha_base_reuses_pr(self):
        self.github.find_existing_pull_requests.return_value = [
            self._pull(
                head_sha="b" * 40,
                head_repository="owner/repo",
                base_ref="main",
            )
        ]
        result = self._run()
        self.assertEqual(
            result.pull_request_url, "https://github.com/owner/repo/pull/7"
        )
        self.github.create_pull_request.assert_not_called()

    def test_wrong_head_sha_fails_closed_no_second_pr(self):
        # persisted/executed commit = b*40, remote PR head = f*40
        self.github.find_existing_pull_requests.return_value = [
            self._pull(head_sha="f" * 40)
        ]
        with self.assertRaises(ExistingPullRequestConflict):
            self._run()
        self.github.create_pull_request.assert_not_called()

    def test_wrong_head_repository_fails_closed(self):
        # same branch name + body, but the PR head lives in another repo
        self.github.find_existing_pull_requests.return_value = [
            self._pull(head_repository="attacker/fork")
        ]
        with self.assertRaises(ExistingPullRequestConflict):
            self._run()
        self.github.create_pull_request.assert_not_called()

    def test_missing_head_repository_fails_closed(self):
        # deleted fork / absent head repository identity
        self.github.find_existing_pull_requests.return_value = [
            self._pull(head_repository="")
        ]
        with self.assertRaises(ExistingPullRequestConflict):
            self._run()
        self.github.create_pull_request.assert_not_called()

    def test_wrong_base_fails_closed(self):
        self.github.find_existing_pull_requests.return_value = [
            self._pull(base_ref="production")
        ]
        with self.assertRaises(ExistingPullRequestConflict):
            self._run()
        self.github.create_pull_request.assert_not_called()

    def test_body_hash_alone_never_authorizes_reuse(self):
        # perfect proposal-hash body but wrong commit identity -> conflict
        self.github.find_existing_pull_requests.return_value = [
            self._pull(body=f"Proposal hash: {self.HASH}", head_sha="f" * 40)
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
        # discovery runs before create AND again for post-create
        # identity verification (Phase 6.2.1B)
        self.assertEqual(
            self.github.find_existing_pull_requests.call_count, 2
        )
        self.github.create_pull_request.assert_called_once()

    def test_discovery_identity_is_exact_deterministic_head_and_base(self):
        self._run()
        calls = self.github.find_existing_pull_requests.call_args_list
        self.assertGreaterEqual(len(calls), 1)
        kwargs = calls[0].kwargs
        self.assertEqual(kwargs["repo_slug"], "owner/repo")
        self.assertEqual(kwargs["head"], self.BRANCH)
        self.assertEqual(kwargs["base"], "main")

    # --- post-create exact identity verification (6.2.1B) -------------------
    def test_new_pr_exact_identity_is_accepted(self):
        result = self._run()
        self.assertTrue(result.pull_request_url.endswith("/pull/42"))
        # discovery ran pre-create AND for post-create verification
        self.assertEqual(
            self.github.find_existing_pull_requests.call_count, 2
        )
        self.github.create_pull_request.assert_called_once()

    def _verification_payload(self, **overrides):
        fields = dict(
            number=42,
            url="https://github.com/owner/repo/pull/42",
            state="open",
            draft=True,
            merged=False,
            head_ref=self.BRANCH,
            base_ref="main",
            body=f"Proposal hash: {self.HASH}",
            head_sha="b" * 40,
            head_repository="owner/repo",
        )
        fields.update(overrides)
        return ExistingPullRequest(**fields)

    def _run_with_verification_payload(self, payload):
        # first call must be empty to reach create; second is the
        # verification discovery result (list of matches)
        self.github.find_existing_pull_requests.side_effect = [
            [],
            [payload],
        ]

    def test_new_pr_wrong_head_sha_rejected_without_second_create(self):
        self._run_with_verification_payload(
            self._verification_payload(head_sha="f" * 40)
        )
        with self.assertRaises(ExistingPullRequestConflict):
            self._run()
        self.github.create_pull_request.assert_called_once()

    def test_new_pr_wrong_head_repository_rejected(self):
        self._run_with_verification_payload(
            self._verification_payload(head_repository="attacker/fork")
        )
        with self.assertRaises(ExistingPullRequestConflict):
            self._run()
        self.github.create_pull_request.assert_called_once()

    def test_new_pr_wrong_base_rejected(self):
        self._run_with_verification_payload(
            self._verification_payload(base_ref="production")
        )
        with self.assertRaises(ExistingPullRequestConflict):
            self._run()
        self.github.create_pull_request.assert_called_once()

    def test_new_pr_closed_or_merged_rejected(self):
        self._run_with_verification_payload(
            self._verification_payload(state="closed", merged=True)
        )
        with self.assertRaises(ExistingPullRequestConflict):
            self._run()
        self.github.create_pull_request.assert_called_once()

    def test_multiple_discovered_matching_prs_rejected(self):
        """Phase 6.2.1C: the deterministic head/base pair must resolve
        to exactly ONE PR — a duplicate masquerading next to the created
        URL never authorizes."""
        created = self._verification_payload()  # url .../pull/42
        duplicate = self._verification_payload(
            number=43, url="https://github.com/owner/repo/pull/43"
        )
        self.github.find_existing_pull_requests.side_effect = [
            [],
            [created, duplicate],
        ]
        with self.assertRaises(ExistingPullRequestConflict):
            self._run()
        self.github.create_pull_request.assert_called_once()

    def test_created_pr_not_draft_rejected(self):
        payload = self._verification_payload(draft=False)
        self._run_with_verification_payload(payload)
        with self.assertRaises(ExistingPullRequestConflict) as ctx:
            self._run()
        self.assertIn("draft", str(ctx.exception))
        self.github.create_pull_request.assert_called_once()

    def test_new_pr_created_url_not_discoverable_rejected(self):
        self.github.find_existing_pull_requests.side_effect = [
            [],
            [],  # verification finds nothing matching
        ]
        with self.assertRaises(ExistingPullRequestConflict):
            self._run()
        self.github.create_pull_request.assert_called_once()

    def test_malformed_verification_discovery_fails_closed(self):
        self.github.find_existing_pull_requests.side_effect = [
            [],
            PullRequestLookupFailedException("malformed payload"),
        ]
        with self.assertRaises(RemoteReconciliationFailed):
            self._run()
        self.github.create_pull_request.assert_called_once()

    # --- resume path (reconcile_and_create_pr) ------------------------------
    def _reconcile(self, stage_callback=None):
        self._maybe_install_create_aware_discovery()
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
