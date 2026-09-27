"""Deterministic proposal approval (Phase 6.2 §5/§6).

Approval is the authorization boundary between "AI proposed" and "the
platform executes". It binds an authenticated operator identity
(``approved_by`` — stamped by the gateway from the verified JWT subject)
to exactly one canonical proposal hash, after re-verifying:

* the proposal exists and is in an approvable state;
* its canonical hash is reproducible from persisted state and matches
  the caller's claim (tamper → fail closed);
* the risk class is inside the deliberately small approval policy set;
* the proposal is fresh (generation → approval inside the TTL);
* the authoritative deployment target still matches the proposal's
  trusted repository/SHA (no retargeting, ever).

Confidence is never consulted for authorization. Successful approval
persists status ``APPROVED`` + ``approved_by``/``approved_at``/
``approval_hash`` on the existing aggregate.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Dict, Optional

from incident_service.application.failures import (
    ApprovalPolicyError,
    ProposalNotFoundError,
    ProposalStaleError,
    TargetRevalidationError,
)
from incident_service.domain.repository_interface import IncidentRepositoryPort
from incident_service.application.services.proposal_execution_policy import (
    APPROVABLE_RISK_CLASSES,
    find_proposal,
    is_fresh,
    load_proposal_ttl_seconds,
    log_stage,
    utcnow,
    verify_proposal_integrity,
)
from incident_service.application.services.remediation_target_binding import (
    resolve_authoritative_deployment_target,
)


class ProposalApprovalService:
    def __init__(
        self,
        repository: IncidentRepositoryPort,
        ttl_seconds: Optional[float] = None,
        now: Callable[[], datetime] = utcnow,
    ):
        self.repository = repository
        self.ttl_seconds = (
            load_proposal_ttl_seconds() if ttl_seconds is None else ttl_seconds
        )
        self.now = now

    def approve(
        self,
        *,
        incident_id: str,
        proposal_id: str,
        proposal_hash: str,
        approved_by: str,
    ) -> Dict[str, Any]:
        incident = self.repository.get_incident_by_id(incident_id.strip())
        if incident is None:
            raise ProposalNotFoundError(f"Incident '{incident_id}' not found")

        proposal = find_proposal(incident, proposal_id)
        approver = (approved_by or "").strip()
        if not approver:
            raise ApprovalPolicyError("approved_by identity is required")

        # Idempotent re-approval of the SAME approved hash (§21): return
        # the existing approval instead of mutating audit history.
        if proposal.status == "APPROVED":
            verify_proposal_integrity(incident, proposal, proposal_hash)
            log_stage(
                "approval.accepted",
                incident_id=incident.id,
                proposal_id=proposal.id,
                proposal_hash=proposal.proposal_hash,
                approved_by=proposal.approved_by,
                idempotent=True,
            )
            return {
                "incident_id": incident.id,
                "proposal": proposal.to_dict(),
                "idempotent": True,
            }

        # State gate first so blocked/proposed-in-flight proposals report
        # their real reason rather than an integrity error.
        if proposal.status == "BLOCKED":
            raise ApprovalPolicyError(
                f"proposal is BLOCKED ({proposal.blocked_reason or 'unknown'}) "
                "and cannot be approved"
            )
        if proposal.status != "PROPOSED":
            raise ApprovalPolicyError(
                f"proposal status {proposal.status} is not approvable"
            )
        if proposal.risk_class not in APPROVABLE_RISK_CLASSES:
            raise ApprovalPolicyError(
                f"risk class {proposal.risk_class} is outside the bounded "
                "approval policy (LOW/MEDIUM only)"
            )

        # Hash binding: reproducible canonical hash == stored == claim.
        verify_proposal_integrity(incident, proposal, proposal_hash)

        # Freshness: generation → approval within TTL (§9).
        now = self.now()
        if not is_fresh(proposal.generated_at, self.ttl_seconds, now):
            raise ProposalStaleError(
                "proposal is older than the approval freshness contract"
            )

        # Target eligibility re-checked at approval time (§6): the
        # authoritative deployment record must still equal the proposal's
        # trusted binding. Never retarget to a newer deployment.
        target = resolve_authoritative_deployment_target(incident)
        if target is None:
            raise TargetRevalidationError(
                "no authoritative deployment evidence for this incident"
            )
        if (
            target["repository_name"] != proposal.repository
            or target["source_sha"] != (proposal.source_sha or "").lower()
        ):
            raise TargetRevalidationError(
                "authoritative deployment target no longer matches the "
                "proposal binding; a fresh evidence-grounded proposal is required"
            )

        proposal.status = "APPROVED"
        proposal.approved_by = approver
        proposal.approved_at = now
        proposal.approval_hash = proposal.proposal_hash
        self.repository.save_incident(incident)

        log_stage(
            "approval.accepted",
            incident_id=incident.id,
            proposal_id=proposal.id,
            proposal_hash=proposal.proposal_hash,
            approved_by=approver,
            risk_class=proposal.risk_class,
            target_repository=proposal.repository,
            source_sha=proposal.source_sha,
        )
        return {
            "incident_id": incident.id,
            "proposal": proposal.to_dict(),
            "idempotent": False,
        }
