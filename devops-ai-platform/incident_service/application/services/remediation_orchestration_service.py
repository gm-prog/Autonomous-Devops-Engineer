import logging
import os
from dataclasses import dataclass
from typing import Any

from incident_service.application.services.remediation_commit_service import RemediationCommitResult
from incident_service.application.services.remediation_patch_executor import RemediationPatchExecutionResult
from incident_service.application.services.remediation_validation_runner import RemediationValidationResult
from incident_service.application.services.remediation_workspace_service import (
    RemediationWorkspaceError,
    RemediationWorkspaceService,
)
from incident_service.application.failures import (
    ExistingPullRequestConflict,
    RemoteBranchConflict,
    RemoteReconciliationFailed,
)
from incident_service.infrastructure.source_provider.github_pr_client import (
    PullRequestLookupFailedException,
    RepositoryNotFoundException,
)
from incident_service.domain.entities.hotfix_proposal import HotfixProposal


class RemediationStageGuardError(RuntimeError):
    """Execution lease/stage guard tripped — abort the running orchestration.

    Unlike ordinary observers (whose failures never change control flow),
    this signal means the caller lost durable ownership and must stop
    performing side effects.
    """


def _make_notifier(stage_callback):
    """Build an observer that swallows ordinary errors but propagates the
    stage guard (ownership) exception."""

    def notify(stage: str, **metadata) -> None:
        if stage_callback is None:
            return
        try:
            stage_callback(stage, metadata)
        except RemediationStageGuardError:
            raise
        except Exception:  # observers must not change control flow
            logging.getLogger("RemediationOrchestration").warning(
                "stage observer failed for stage=%s", stage, exc_info=True
            )

    return notify


class RemediationOrchestrationError(RuntimeError):
    """Raised when a remediation cannot safely reach publication."""


def _summarize_validation_steps(validation_result) -> list:
    """Observer-safe step summary: never raise on odd/mock-shaped results."""
    try:
        steps = validation_result.steps
    except AttributeError:
        return []
    summary = []
    try:
        iterator = iter(steps)
    except TypeError:
        return []
    for step in iterator:
        try:
            summary.append({"name": step.name, "passed": step.passed})
        except (AttributeError, TypeError):
            continue
    return summary


@dataclass(frozen=True)
class RemediationOrchestrationResult:
    proposal_id: str
    incident_id: str
    source_sha: str
    branch_name: str
    commit_sha: str
    pull_request_url: str
    patch_result: RemediationPatchExecutionResult
    validation_result: RemediationValidationResult
    commit_result: RemediationCommitResult


class RemediationOrchestrationService:
    """Executes the complete safe remediation path from verified patch to draft PR."""

    def __init__(
        self,
        workspace_service: Any,
        patch_executor: Any,
        validation_runner: Any,
        commit_service: Any,
        github_client: Any,
        github_oauth_token: str | None = None,
    ):
        self.workspace_service = workspace_service or RemediationWorkspaceService()
        self.patch_executor = patch_executor
        self.validation_runner = validation_runner
        self.commit_service = commit_service
        self.github = github_client
        self.github_oauth_token = (
            github_oauth_token
            if github_oauth_token is not None
            else os.getenv("GITHUB_OAUTH_TOKEN", "")
        )

        required = (
            self.patch_executor,
            self.validation_runner,
            self.commit_service,
            self.github,
        )
        if any(service is None for service in required):
            raise ValueError(
                "patch_executor, validation_runner, commit_service, and github_client are required"
            )

    def execute(
        self,
        incident_id: str,
        proposal: HotfixProposal,
        repository_slug: str,
        base_branch: str = "main",
        validation_profile: str = "incident_service",
        pr_title: str | None = None,
        pr_body: str | None = None,
        prepared_workspace: Any | None = None,
        stage_callback: Any | None = None,
    ) -> RemediationOrchestrationResult:
        """Run workspace → patch → validation → commit → publish → draft PR.

        ``stage_callback`` (optional, Phase 6.2) receives
        ``(stage_name, metadata_dict)`` at each completed stage so the
        caller can emit structured lifecycle logs/audit evidence. It is a
        pure observer: callback errors never alter execution flow, and
        omitting it preserves prior behaviour exactly.
        """

        notify = _make_notifier(stage_callback)

        if not proposal.is_verified:
            raise ValueError("remediation proposal must be verified before orchestration")
        if not proposal.source_sha:
            raise ValueError("remediation proposal requires an immutable source SHA")

        workspace = prepared_workspace or self.workspace_service.prepare(
            repository_slug=repository_slug,
            source_sha=proposal.source_sha,
            incident_id=incident_id,
            proposal_id=proposal.id,
            base_branch=base_branch,
        )
        notify(
            "workspace.created",
            branch=workspace.branch_name,
            source_sha=workspace.source_sha,
        )

        try:
            patch_result = self.patch_executor.apply(workspace, proposal)
            try:
                changed_paths = [
                    str(item) for item in patch_result.changed_paths
                ]
            except TypeError:  # observer must never break execution
                changed_paths = []
            notify(
                "patch.applied",
                target_filepath=patch_result.target_filepath,
                changed_paths=changed_paths,
            )

            notify("validation.started", profile=validation_profile)
            validation_result = self.validation_runner.validate(
                workspace=workspace,
                profile=validation_profile,
                target_filepath=proposal.target_filepath,
            )
            notify(
                "validation.completed",
                profile=validation_profile,
                passed=bool(validation_result.passed),
                steps=_summarize_validation_steps(validation_result),
            )
            if not validation_result.passed:
                raise RemediationOrchestrationError(
                    "remediation validation failed; refusing commit and publication"
                )
            if validation_result.source_sha.lower() != proposal.source_sha.lower():
                raise RemediationOrchestrationError(
                    "validation source SHA does not match the proposal source SHA"
                )

            commit_result = self.commit_service.create(
                workspace=workspace,
                target_filepath=proposal.target_filepath,
                incident_id=incident_id,
                proposal_id=proposal.id,
            )
            notify(
                "commit.created",
                commit_sha=commit_result.commit_sha,
                parent_sha=commit_result.parent_sha,
                branch=commit_result.branch_name,
            )

            if commit_result.parent_sha != proposal.source_sha.lower():
                raise RemediationOrchestrationError(
                    "remediation commit parent does not match the pinned source SHA"
                )
            if commit_result.target_filepath != patch_result.target_filepath:
                raise RemediationOrchestrationError(
                    "remediation commit target differs from the applied patch target"
                )

            # Transfer the verified local commit to GitHub before any REST
            # ref/PR operation: a commit SHA only exists on the remote after
            # it has been pushed (GitHub cannot create a ref to an object it
            # has never received).
            try:
                self.workspace_service.publish_branch(
                    workspace=workspace,
                    oauth_token=self.github_oauth_token,
                )
            except (RemoteBranchConflict, RemoteReconciliationFailed):
                raise
            except RemediationWorkspaceError as exc:
                raise RemediationOrchestrationError(
                    "remediation commit could not be published to the remote repository"
                ) from exc

            # publish_branch pushes AND verifies the remote ref at the
            # verified commit before this point (§12 ordering).
            notify(
                "remote.published",
                branch=commit_result.branch_name,
                commit_sha=commit_result.commit_sha,
            )
            notify(
                "remote.verified",
                branch=commit_result.branch_name,
                commit_sha=commit_result.commit_sha,
                verified=True,
            )

            self.github.create_branch_from_commit(
                repo_slug=repository_slug,
                branch=commit_result.branch_name,
                commit_sha=commit_result.commit_sha,
                expected_parent_sha=commit_result.parent_sha,
            )

            pull_request_url = self._resolve_draft_pr(
                notify=notify,
                repository_slug=repository_slug,
                branch=commit_result.branch_name,
                base_branch=base_branch,
                incident_id=incident_id,
                proposal=proposal,
                commit_sha=commit_result.commit_sha,
                pr_title=pr_title,
                pr_body=pr_body,
            )

            proposal.pull_request_url = pull_request_url

            return RemediationOrchestrationResult(
                proposal_id=proposal.id,
                incident_id=incident_id,
                source_sha=proposal.source_sha.lower(),
                branch_name=commit_result.branch_name,
                commit_sha=commit_result.commit_sha,
                pull_request_url=pull_request_url,
                patch_result=patch_result,
                validation_result=validation_result,
                commit_result=commit_result,
            )
        finally:
            self.workspace_service.cleanup(workspace)

    def reconcile_and_create_pr(
        self,
        *,
        incident_id: str,
        proposal: HotfixProposal,
        repository_slug: str,
        base_branch: str = "main",
        pr_title: str | None = None,
        pr_body: str | None = None,
        stage_callback: Any | None = None,
    ) -> str:
        """Resume path (Phase 6.2.1): converge to the draft PR without
        repeating workspace/patch/validation/commit.

        Preconditions are durable state (persisted commit + branch cursor).
        The method re-inspects the real remote before trusting it:
          remote == persisted commit  -> resume PR reconciliation
          remote absent               -> fail closed (state vanished)
          remote != persisted commit  -> fail closed (never overwrite)
        """
        notify = _make_notifier(stage_callback)
        if not proposal.is_verified:
            raise ValueError("remediation proposal must be verified before orchestration")
        commit_sha = (proposal.commit_sha or "").strip().lower()
        branch = (proposal.branch_name or "").strip()
        if not commit_sha or not branch:
            raise RemoteReconciliationFailed(
                "durable execution state does not record a published commit"
            )

        remote_sha = self.workspace_service.inspect_remote_branch(
            repository_slug, branch, self.github_oauth_token
        )
        if remote_sha is None:
            raise RemoteReconciliationFailed(
                "expected remediation branch is missing on the remote"
            )
        if remote_sha != commit_sha:
            raise RemoteBranchConflict(
                "remote remediation branch moved away from the persisted commit"
            )
        notify(
            "remote.published",
            branch=branch,
            commit_sha=commit_sha,
            recovered=True,
        )
        notify(
            "remote.verified",
            branch=branch,
            commit_sha=commit_sha,
            verified=True,
            recovered=True,
        )

        self.github.create_branch_from_commit(
            repo_slug=repository_slug,
            branch=branch,
            commit_sha=commit_sha,
            expected_parent_sha=proposal.source_sha.lower(),
        )

        pull_request_url = self._resolve_draft_pr(
            notify=notify,
            repository_slug=repository_slug,
            branch=branch,
            base_branch=base_branch,
            incident_id=incident_id,
            proposal=proposal,
            commit_sha=commit_sha,
            pr_title=pr_title,
            pr_body=pr_body,
        )
        proposal.pull_request_url = pull_request_url
        return pull_request_url

    def _resolve_draft_pr(
        self,
        *,
        notify,
        repository_slug: str,
        branch: str,
        base_branch: str,
        incident_id: str,
        proposal: HotfixProposal,
        commit_sha: str,
        pr_title: str | None,
        pr_body: str | None,
    ) -> str:
        """Reconcile-then-create: discovery ALWAYS precedes POST /pulls."""
        try:
            matches = self.github.find_existing_pull_requests(
                repo_slug=repository_slug,
                head=branch,
                base=base_branch,
            )
        except (PullRequestLookupFailedException, RepositoryNotFoundException) as exc:
            # discovery infrastructure failures are reconciliation failures
            # (typed -> 502), never authorization to create blindly
            raise RemoteReconciliationFailed(
                "could not reconcile existing pull requests before creation"
            ) from exc
        notify(
            "pr.discovery",
            branch=branch,
            base=base_branch,
            matches=len(matches) if isinstance(matches, list) else None,
        )
        if isinstance(matches, list) and not matches:
            url = self.github.create_pull_request(
                repo_slug=repository_slug,
                branch=branch,
                title=pr_title
                or f"Automated remediation for incident {incident_id}",
                body=pr_body
                or self._default_pr_body(
                    incident_id=incident_id,
                    proposal=proposal,
                    commit_sha=commit_sha,
                    branch=branch,
                ),
                draft=True,
                base=base_branch,
            )
            notify(
                "pr.created",
                pull_request_url=url,
                branch=branch,
                commit_sha=commit_sha,
            )
            return url

        url = self._evaluate_existing_pr(
            matches,
            proposal=proposal,
            incident_id=incident_id,
            branch=branch,
            base=base_branch,
            commit_sha=commit_sha,
        )
        notify(
            "pr.reconciled",
            pull_request_url=url,
            branch=branch,
            base=base_branch,
            commit_sha=commit_sha,
        )
        return url

    @staticmethod
    def _evaluate_existing_pr(
        matches,
        *,
        proposal: HotfixProposal,
        incident_id: str,
        branch: str,
        base: str,
        commit_sha: str,
    ) -> str:
        """Explicit policy for discovered PRs (§16/§40/§6.2.1A). Fail
        closed on anything that is not exactly one open PR whose head
        points at THE commit this execution produced:

            head repository == proposal.repository (exact, not branch name)
            head ref       == deterministic branch
            head SHA       == persisted/executed commit SHA
            base ref       == allowed base branch
            open + not merged
            body proposal-hash corroboration

        PR body text is untrusted data — corroboration only;
        authorization comes from persisted approval state. Body content
        is never used to derive commit identity."""
        if not isinstance(matches, list):
            raise RemoteReconciliationFailed(
                "PR discovery returned an unexpected result"
            )
        if len(matches) > 1:
            raise ExistingPullRequestConflict(
                "multiple pull requests match the deterministic remediation "
                "head/base pair"
            )
        pull = matches[0]
        if getattr(pull, "merged", False) or getattr(pull, "state", "") != "open":
            raise ExistingPullRequestConflict(
                "an existing pull request for the remediation branch is "
                "merged or closed; refusing to open another"
            )
        if getattr(pull, "head_ref", None) != branch or getattr(
            pull, "base_ref", None
        ) != base:
            raise ExistingPullRequestConflict(
                "existing pull request does not match the deterministic "
                "remediation identity"
            )
        # exact remote head identity: repository + executed commit SHA
        expected_sha = (commit_sha or "").strip().lower()
        actual_sha = (getattr(pull, "head_sha", "") or "").strip().lower()
        if not expected_sha or actual_sha != expected_sha:
            raise ExistingPullRequestConflict(
                "existing pull request head commit does not match the "
                "executed remediation commit"
            )
        expected_repo = (proposal.repository or "").strip().lower()
        actual_head_repo = (
            getattr(pull, "head_repository", "") or ""
        ).strip().lower()
        if not expected_repo or actual_head_repo != expected_repo:
            raise ExistingPullRequestConflict(
                "existing pull request head repository does not match the "
                "proposal repository"
            )
        body = getattr(pull, "body", "") or ""
        expected_hash = (proposal.proposal_hash or "n/a").strip()
        found_hash = None
        for line in body.splitlines():
            if line.strip().lower().startswith("proposal hash:"):
                found_hash = line.split(":", 1)[1].strip()
                break
        if found_hash is None or found_hash != expected_hash:
            raise ExistingPullRequestConflict(
                "existing pull request does not corroborate the persisted "
                "proposal hash"
            )
        return getattr(pull, "url", "") or ""

    @staticmethod
    def _default_pr_body(
        incident_id: str,
        proposal: HotfixProposal,
        commit_sha: str,
        branch: str,
    ) -> str:
        return (
            f"Incident: {incident_id}\n"
            f"Proposal: {proposal.id}\n"
            f"Proposal hash: {proposal.proposal_hash or 'n/a'}\n"
            f"Risk class: {proposal.risk_class or 'n/a'}\n"
            f"Target: {proposal.target_filepath}\n"
            f"Source SHA: {proposal.source_sha}\n"
            f"Remediation Commit: {commit_sha}\n"
            f"Branch: {branch}\n\n"
            "Generated remediation awaiting human review. "
            "Do not merge without CI review. No deployment is performed "
            "by this automation."
        )
