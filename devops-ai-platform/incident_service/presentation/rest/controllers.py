from typing import Any, Dict, List

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from incident_service.application.dependencies import get_incident_repository
from incident_service.application.failures import (
    IncidentNotFound,
    InvalidRcaResult,
    ProposalPersistenceFailed,
    RcaGenerationFailed,
    TargetBindingFailed,
)
from incident_service.domain.repository_interface import IncidentRepositoryPort
from incident_service.domain.entities.incident_evidence import IncidentEvidence
from incident_service.domain.entities.hotfix_proposal import HotfixProposal
from incident_service.infrastructure.agent.rca_client import RcaAgentClient, RcaAgentUnavailable
from incident_service.application.services.proposal_generation_service import (
    ProposalGenerationService,
)
from incident_service.application.services.rca_evidence_pack import RcaEvidencePackBuilder
from incident_service.application.services.hotfix_validation_service import HotfixValidationService
from incident_service.application.services.remediation_commit_service import RemediationCommitService
from incident_service.application.services.remediation_orchestration_service import (
    RemediationOrchestrationError,
    RemediationOrchestrationService,
)
from incident_service.application.services.remediation_patch_executor import RemediationPatchExecutor
from incident_service.application.services.remediation_validation_runner import RemediationValidationRunner
from incident_service.application.services.remediation_workspace_service import RemediationWorkspaceService
from incident_service.application.services.remediation_target_binding import (
    RemediationTargetBindingError,
    authorize_remediation_target,
)
from incident_service.infrastructure.source_provider.github_pr_client import GitHubPRClient



router = APIRouter(prefix="/incidents", tags=["Active Incidents Controller"])

class RemediationRequest(BaseModel):
    target_filepath: str = Field(min_length=1, max_length=256)
    patch: str = Field(min_length=1, max_length=262144)
    source_sha: str = Field(pattern=r"^[0-9a-fA-F]{40}$")
    repository_slug: str
    base_branch: str = Field(default="main", min_length=1, max_length=120)
    validation_profile: str = Field(default="incident_service", min_length=1, max_length=64)
    confidence_score: float = Field(default=0.85, ge=0.0, le=1.0)
    pr_title: str | None = Field(default=None, max_length=256)
    pr_body: str | None = Field(default=None, max_length=8192)

    @field_validator("repository_slug")
    @classmethod
    def _canonical_repository_slug(cls, value: str) -> str:
        # pydantic's Rust regex lacks lookahead; enforce the strong canonical
        # form (rejects bare names and dot-only segments) with Python re.
        import re as _re
        strong = (
            r"(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+"
            r"/(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+"
        )
        if not _re.fullmatch(strong, value):
            raise ValueError(
                "repository_slug must be canonical owner/repository "
                "(alphanumeric segments; bare names and path tricks rejected)"
            )
        return value


def get_remediation_orchestrator() -> RemediationOrchestrationService:
    return RemediationOrchestrationService(
        workspace_service=RemediationWorkspaceService(),
        patch_executor=RemediationPatchExecutor(),
        validation_runner=RemediationValidationRunner(),
        commit_service=RemediationCommitService(),
        github_client=GitHubPRClient(),
    )


def _serialize_incident(incident) -> Dict[str, Any]:
    return {
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "context": incident.context,
        "created_at": incident.created_at.isoformat(),
        "evidence": [
            {
                "id": evidence.id,
                "kind": evidence.kind,
                "source": evidence.source,
                "observed_at": evidence.observed_at.isoformat(),
                "payload": dict(evidence.payload),
            }
            for evidence in incident.evidence
        ],
        "patch_proposals": [
            {
                "id": proposal.id,
                "incident_id": proposal.incident_id,
                "target_filepath": proposal.target_filepath,
                "is_verified": proposal.is_verified,
                "generated_at": proposal.generated_at.isoformat(),
                "repository": proposal.repository,
                "source_sha": proposal.source_sha,
                "evidence_refs": list(proposal.evidence_refs),
                "validation_plan": list(proposal.validation_plan),
                "risk_class": proposal.risk_class,
                "proposal_hash": proposal.proposal_hash,
                "status": proposal.status,
                "blocked_reason": proposal.blocked_reason,
            }
            for proposal in incident.patch_proposals
        ],
    }


@router.get("", response_model=List[Dict[str, Any]])
def list_current_anomalies(
    repository: IncidentRepositoryPort = Depends(get_incident_repository),
):
    """Returns persisted incidents that are not in a terminal state."""
    return [_serialize_incident(item) for item in repository.get_active_incidents()]


@router.get("/{incident_id}", response_model=Dict[str, Any])
def get_incident(
    incident_id: str,
    repository: IncidentRepositoryPort = Depends(get_incident_repository),
):
    incident = repository.get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _serialize_incident(incident)


@router.get("/{incident_id}/rca/evidence", response_model=Dict[str, Any])
def get_rca_evidence_pack(
    incident_id: str,
    repository: IncidentRepositoryPort = Depends(get_incident_repository),
):
    """Returns the deterministic evidence package consumed by future RCA agents."""
    try:
        return RcaEvidencePackBuilder(repository).build(incident_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/{incident_id}/rca", response_model=Dict[str, Any])
def investigate_root_cause(
    incident_id: str,
    repository: IncidentRepositoryPort = Depends(get_incident_repository),
):
    """Build evidence, invoke the RCA agent, then persist the validated RCA."""
    try:
        pack = RcaEvidencePackBuilder(repository).build(incident_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    try:
        result = RcaAgentClient().analyze(pack)
    except (RcaAgentUnavailable, ValueError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    valid_ids = {item["evidence_id"] for item in pack["evidence"]["timeline"]}
    cited_ids = result.get("supporting_evidence_ids", [])
    if not isinstance(cited_ids, list) or not all(item in valid_ids for item in cited_ids):
        raise HTTPException(status_code=502, detail="RCA agent returned invalid evidence references")

    incident = repository.get_incident_by_id(incident_id.strip())
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.attach_evidence(IncidentEvidence(
        id=f"rca-{incident.id}",
        kind="rca_result",
        source="agent-service",
        payload=result,
    ))
    incident.move_to_triage()
    incident.mark_root_cause_found()
    repository.save_incident(incident)

    return {
        "incident_id": incident.id,
        "status": incident.status,
        "rca": result,
        "evidence_pack_version": pack["pack_version"],
    }

@router.post("/{incident_id}/remediation", response_model=Dict[str, Any])
def create_remediation(
    incident_id: str,
    request: RemediationRequest,
    repository: IncidentRepositoryPort = Depends(get_incident_repository),
):
    incident = repository.get_incident_by_id(incident_id.strip())
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Authorization boundary: the requested repository + source SHA must be
    # provably bound to this incident's own deployment evidence, otherwise the
    # endpoint is an arbitrary GitHub write primitive (403 before any work).
    try:
        authorize_remediation_target(
            incident=incident,
            repository_slug=request.repository_slug,
            source_sha=request.source_sha,
        )
    except RemediationTargetBindingError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    proposal = HotfixProposal(
        id=f"remediation-{incident.id}",
        target_filepath=request.target_filepath,
        diff_patch_payload=request.patch,
        source_sha=request.source_sha.strip().lower(),
    )
    safe, violations = HotfixValidationService().validate_patch(
        proposal,
        request.confidence_score,
    )
    if not safe or not proposal.apply_verification_pass():
        raise HTTPException(
            status_code=422,
            detail={"message": "remediation patch failed safety validation", "violations": violations},
        )

    # Construct the remediation pipeline only now: authorization and patch
    # safety have passed, so an unauthorized request never instantiates the
    # orchestrator (no workspace, no GitHub client, nothing to publish).
    orchestrator = get_remediation_orchestrator()

    try:
        result = orchestrator.execute(
            incident_id=incident.id,
            proposal=proposal,
            repository_slug=request.repository_slug,
            base_branch=request.base_branch,
            validation_profile=request.validation_profile,
            pr_title=request.pr_title,
            pr_body=request.pr_body,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RemediationOrchestrationError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    incident.attach_remediation_proposal(proposal)
    repository.save_incident(incident)
    return {
        "incident_id": result.incident_id,
        "proposal_id": result.proposal_id,
        "status": incident.status,
        "source_sha": result.source_sha,
        "branch": result.branch_name,
        "commit_sha": result.commit_sha,
        "pull_request_url": result.pull_request_url,
        "validation": {
            "passed": result.validation_result.passed,
            "steps": [
                {"name": step.name, "passed": step.passed, "exit_code": step.exit_code}
                for step in result.validation_result.steps
            ],
        },
    }


# --------------------------------------------------------------------------
# Phase 6.1: incident → evidence → RCA → structured remediation proposal
# --------------------------------------------------------------------------

logger = logging.getLogger("IncidentProposalController")


def get_proposal_generation_service() -> ProposalGenerationService:
    """Proposal pipeline bound to the shared incident repository."""
    return ProposalGenerationService(repository=get_incident_repository())


def _serialize_proposal(proposal: HotfixProposal) -> Dict[str, Any]:
    return proposal.to_dict()


@router.post("/{incident_id}/proposal", response_model=Dict[str, Any])
def generate_remediation_proposal(
    incident_id: str,
    service: ProposalGenerationService = Depends(get_proposal_generation_service),
):
    """Evidence-grounded proposal generation — proposal-only (§22).

    Runs the full pipeline (trusted target → RCA → deterministic
    validation → canonical hash → persistence). Never executes remediation:
    no workspace, no git, no GitHub, no deploy. Returns HTTP 200 for both
    a ``PROPOSED`` and a ``BLOCKED`` outcome (the pipeline itself ran);
    blocked payloads carry a machine-readable ``blocked_reason`` and are
    persisted, never executable (§7/§20).
    """
    try:
        return service.generate(incident_id)
    except IncidentNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except InvalidRcaResult as exc:
        # schema-constrained AI output failed validation → fail closed (§11)
        raise HTTPException(
            status_code=422,
            detail=f"RCA result failed schema validation: {exc}",
        ) from exc
    except RcaGenerationFailed as exc:
        raise HTTPException(
            status_code=503,
            detail="RCA provider is unavailable; try again later",
        ) from exc
    except TargetBindingFailed as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ProposalPersistenceFailed as exc:
        raise HTTPException(
            status_code=503,
            detail="Proposal could not be persisted",
        ) from exc


@router.get("/{incident_id}/proposal", response_model=Dict[str, Any])
def get_remediation_proposal(
    incident_id: str,
    repository: IncidentRepositoryPort = Depends(get_incident_repository),
):
    """Read-only view of the incident's persisted proposal (§27)."""
    incident = repository.get_incident_by_id(incident_id.strip())
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    if not incident.patch_proposals:
        raise HTTPException(
            status_code=404,
            detail="No remediation proposal exists for this incident",
        )
    proposal = incident.patch_proposals[-1]
    return {
        "incident_id": incident.id,
        "incident_status": incident.status,
        "proposal": _serialize_proposal(proposal),
    }
