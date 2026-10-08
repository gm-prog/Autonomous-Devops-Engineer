from typing import Any
import uuid
import logging
from ...domain.entities.hotfix_proposal import HotfixProposal
from ...domain.repository_interface import IncidentRepositoryPort
from ..services.hotfix_validation_service import HotfixValidationService

logger = logging.getLogger("ApplyAutomatedFixCommandHandler")

class ApplyAutomatedFixCommand:
    def __init__(self, incident_id: str, target_file: str, raw_patch: str, confidence_score: float = 0.85):
        self.incident_id = incident_id
        self.target_file = target_file
        self.raw_patch = raw_patch
        self.confidence_score = confidence_score

class ApplyAutomatedFixCommandHandler:
    """Takes generated patch, runs guardrail safety validations, compiles confirmation checks, and submits PRs."""
    def __init__(self, persistence: IncidentRepositoryPort, github_client_mock: Any = None, validation_service: Any = None):
        self.repo = persistence
        self.git = github_client_mock
        self.validator = validation_service or HotfixValidationService()

    def handle(self, cmd: ApplyAutomatedFixCommand) -> bool:
        incident = self.repo.get_incident_by_id(cmd.incident_id)
        if not incident:
            logger.error(f"Cannot apply fix; Incident with ID {cmd.incident_id} does not exist.")
            return False

        proposal = HotfixProposal(
            id=str(uuid.uuid4()),
            target_filepath=cmd.target_file,
            diff_patch_payload=cmd.raw_patch
        )

        # 1. Apply safety policies checking for refactoring, size, and file vulnerabilities
        is_safe, violations = self.validator.validate_patch(proposal, cmd.confidence_score)
        if not is_safe:
            logger.warning(f"Aborting automatic fix deployment due to security/risk guardrails: {violations}")
            return False

        # 2. Record the claimed sanity/compiler pass (Phase 8.7-D.1):
        #    PLACEHOLDER — no checks are actually executed, so the proposal
        #    remains unverified and this flow does NOT attach it as a
        #    verified patch. A verified attachment requires real checks
        #    (see HotfixProposal.mark_verified).
        proposal.record_claimed_verification()
        if proposal.is_verified:
            incident.attach_verified_patch(proposal)
            self.repo.save_incident(incident)
            logger.info(f"Successfully committed verified remediation draft {proposal.id} to Domain Aggregate and local caching databases.")
            return True

        logger.warning(
            f"Remediation draft {proposal.id} has a claimed-but-not-executed "
            f"verification; it is not attached as a verified patch."
        )
        return False

