from typing import Any, Optional
import logging
import uuid
import re

from domain.entities.hotfix_proposal import HotfixProposal
from domain.repository_interface import IncidentRepositoryPort
from application.services.hotfix_validation_service import HotfixValidationService

logger = logging.getLogger("ApplyAutomatedFixCommandHandler")

_SOURCE_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


class ApplyAutomatedFixCommand:
    def __init__(
        self,
        incident_id: str,
        target_file: str,
        raw_patch: str,
        confidence_score: float = 0.85,
        repository_slug: Optional[str] = None,
        source_branch: Optional[str] = None,
        source_sha: Optional[str] = None,
        base_branch: str = "main",
        pr_title: Optional[str] = None,
        pr_body: Optional[str] = None,
    ):
        self.incident_id = incident_id
        self.target_file = target_file
        self.raw_patch = raw_patch
        self.confidence_score = confidence_score
        self.repository_slug = repository_slug
        self.source_branch = source_branch
        self.source_sha = source_sha
        self.base_branch = base_branch
        self.pr_title = pr_title
        self.pr_body = pr_body


class ApplyAutomatedFixCommandHandler:
    """Validates a patch and creates a bounded draft PR; it never directly mutates production."""

    def __init__(
        self,
        persistence: IncidentRepositoryPort,
        github_client: Any = None,
        validation_service: Any = None,
    ):
        self.repo = persistence
        self.github = github_client
        self.validator = validation_service or HotfixValidationService()

    def handle(self, cmd: ApplyAutomatedFixCommand) -> bool:
        incident = self.repo.get_incident_by_id(cmd.incident_id)
        if not incident:
            logger.error("Cannot apply fix; incident %s does not exist.", cmd.incident_id)
            return False

        proposal = HotfixProposal(
            id=str(uuid.uuid4()),
            target_filepath=cmd.target_file,
            diff_patch_payload=cmd.raw_patch,
        )

        is_safe, violations = self.validator.validate_patch(
            proposal,
            cmd.confidence_score,
        )
        if not is_safe:
            logger.warning(
                "Rejecting remediation %s due to guardrails: %s",
                proposal.id,
                violations,
            )
            return False

        if not proposal.apply_verification_pass():
            logger.warning(
                "Rejecting remediation %s because its patch structure could not be verified.",
                proposal.id,
            )
            return False

        if not cmd.source_sha or not _SOURCE_SHA_PATTERN.fullmatch(cmd.source_sha.strip()):
            logger.warning(
                "Rejecting remediation %s because an immutable source SHA is required.",
                proposal.id,
            )
            return False
        proposal.source_sha = cmd.source_sha.strip().lower()

        # No GitHub client means the proposal can be inspected but must not be
        # reported as submitted. This preserves a safe dry-run boundary.
        if self.github is None:
            logger.info(
                "Remediation %s verified locally; GitHub submission is disabled.",
                proposal.id,
            )
            return False

        if not cmd.repository_slug or not cmd.source_branch:
            logger.warning(
                "Remediation %s requires repository_slug and source_branch for PR creation.",
                proposal.id,
            )
            return False

        try:
            proposal.pull_request_url = self.github.create_pull_request(
                repo_slug=cmd.repository_slug,
                branch=cmd.source_branch,
                title=cmd.pr_title or f"Automated remediation for incident {incident.id}",
                body=cmd.pr_body or (
                    f"Incident: {incident.id}\n"
                    f"Proposal: {proposal.id}\n"
                    f"Target: {proposal.target_filepath}\n"
                    f"Source SHA: {proposal.source_sha}\n\n"
                    "Generated remediation. Review CI and human approval before merge."
                ),
                draft=True,
                base=cmd.base_branch,
            )
        except Exception:
            logger.exception("GitHub rejected remediation proposal %s.", proposal.id)
            return False

        incident.attach_remediation_proposal(proposal)
        self.repo.save_incident(incident)
        logger.info(
            "Created draft remediation PR %s for incident %s.",
            proposal.pull_request_url,
            incident.id,
        )
        return True
