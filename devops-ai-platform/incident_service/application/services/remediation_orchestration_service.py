from dataclasses import dataclass
from typing import Any

from application.services.remediation_commit_service import RemediationCommitResult
from application.services.remediation_patch_executor import RemediationPatchExecutionResult
from application.services.remediation_validation_runner import RemediationValidationResult
from application.services.remediation_workspace_service import RemediationWorkspaceService
from domain.entities.hotfix_proposal import HotfixProposal


class RemediationOrchestrationError(RuntimeError):
    """Raised when a remediation cannot safely reach publication."""


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
    ):
        self.workspace_service = workspace_service or RemediationWorkspaceService()
        self.patch_executor = patch_executor
        self.validation_runner = validation_runner
        self.commit_service = commit_service
        self.github = github_client

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
    ) -> RemediationOrchestrationResult:
        if not proposal.is_verified:
            raise ValueError("remediation proposal must be verified before orchestration")
        if not proposal.source_sha:
            raise ValueError("remediation proposal requires an immutable source SHA")

        workspace = self.workspace_service.prepare(
            repository_slug=repository_slug,
            source_sha=proposal.source_sha,
            incident_id=incident_id,
            proposal_id=proposal.id,
            base_branch=base_branch,
        )

        try:
            patch_result = self.patch_executor.apply(workspace, proposal)

            validation_result = self.validation_runner.validate(
                workspace=workspace,
                profile=validation_profile,
                target_filepath=proposal.target_filepath,
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

            if commit_result.parent_sha != proposal.source_sha.lower():
                raise RemediationOrchestrationError(
                    "remediation commit parent does not match the pinned source SHA"
                )
            if commit_result.target_filepath != patch_result.target_filepath:
                raise RemediationOrchestrationError(
                    "remediation commit target differs from the applied patch target"
                )

            self.github.create_branch_from_commit(
                repo_slug=repository_slug,
                branch=commit_result.branch_name,
                commit_sha=commit_result.commit_sha,
                expected_parent_sha=commit_result.parent_sha,
            )

            pull_request_url = self.github.create_pull_request(
                repo_slug=repository_slug,
                branch=commit_result.branch_name,
                title=pr_title or f"Automated remediation for incident {incident_id}",
                body=pr_body or self._default_pr_body(
                    incident_id=incident_id,
                    proposal=proposal,
                    commit_result=commit_result,
                ),
                draft=True,
                base=base_branch,
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

    @staticmethod
    def _default_pr_body(
        incident_id: str,
        proposal: HotfixProposal,
        commit_result: RemediationCommitResult,
    ) -> str:
        return (
            f"Incident: {incident_id}\n"
            f"Proposal: {proposal.id}\n"
            f"Target: {proposal.target_filepath}\n"
            f"Source SHA: {proposal.source_sha}\n"
            f"Remediation Commit: {commit_result.commit_sha}\n"
            f"Branch: {commit_result.branch_name}\n\n"
            "Generated remediation. Review CI and human approval before merge."
        )
