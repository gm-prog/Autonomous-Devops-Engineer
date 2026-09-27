"""Deterministic proposal policy shared by approval and execution (§6/§5).

Authority model: the persisted proposal + canonical hash are the contract;
approval binds an authenticated operator identity to one exact hash, and
execution re-verifies the same contract plus fresh authoritative target
evidence immediately before any side effect.

Nothing here consults AI confidence for authorization, and no caller
supplied repository/SHA is ever accepted.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from incident_service.application.failures import (
    ProposalIntegrityError,
    ProposalNotFoundError,
)
from incident_service.domain.entities.hotfix_proposal import HotfixProposal
from incident_service.application.services.proposal_generation_service import (
    compute_proposal_hash,
)

logger = logging.getLogger("ProposalExecutionPolicy")

#: Freshness contract (Phase 6.2 §9): approval must happen within this
#: many seconds of proposal generation, and execution within this many
#: seconds of approval. No scheduler — the smallest explicit TTL.
PROPOSAL_TTL_ENV = "REMEDIATION_PROPOSAL_TTL_SECONDS"
DEFAULT_PROPOSAL_TTL_SECONDS = 86400.0  # 24h

#: Deliberately small approval-eligible risk class set (§6): HIGH/BLOCKED
#: proposals are out of scope for this bounded policy slice.
APPROVABLE_RISK_CLASSES = frozenset({"LOW", "MEDIUM"})

#: Deterministic execution identity: same proposal + same approved hash →
#: same execution id, across retries (§21).
EXECUTION_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "devops.ai/remediation-execution"
)


def load_proposal_ttl_seconds() -> float:
    """Fail fast on malformed TTL configuration (repo env convention)."""
    raw = os.getenv(PROPOSAL_TTL_ENV, "").strip()
    if not raw:
        return DEFAULT_PROPOSAL_TTL_SECONDS
    ttl = float(raw)
    if ttl <= 0:
        raise ValueError(f"{PROPOSAL_TTL_ENV} must be a positive number")
    return ttl


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def find_proposal(incident, proposal_id: str) -> HotfixProposal:
    for proposal in incident.patch_proposals:
        if proposal.id == proposal_id:
            return proposal
    raise ProposalNotFoundError(
        f"Proposal '{proposal_id}' does not exist on incident '{incident.id}'"
    )


def rca_root_cause(incident) -> Optional[str]:
    """Persisted RCA for this incident (Phase 6.1 evidence), if any."""
    rca_evidence_id = f"rca-{incident.id}"
    for item in incident.evidence:
        if item.id == rca_evidence_id and item.kind == "rca_result":
            payload = dict(item.payload or {})
            value = payload.get("root_cause")
            return str(value) if value is not None else None
    return None


def recompute_proposal_hash(incident, proposal: HotfixProposal) -> str:
    """Canonical hash from persisted state only (§5: hash reproducible).

    ``root_cause`` comes from the persisted RCA evidence — the same source
    Phase 6.1 hashed at generation time. Missing RCA on an approved-shaped
    proposal means the hash cannot be reproduced → caller fails closed.
    """
    root_cause = rca_root_cause(incident)
    if root_cause is None and proposal.status not in {"BLOCKED"}:
        # Phase 6.1 only hashed empty root_cause for pre-RCA blocked
        # proposals; anything else without RCA evidence is unreproducible.
        if proposal.proposal_hash:
            raise ProposalIntegrityError(
                "proposal hash cannot be reproduced: RCA evidence is missing"
            )
        root_cause = ""
    if root_cause is None:
        root_cause = ""
    return compute_proposal_hash(
        incident_id=proposal.incident_id or incident.id,
        root_cause=root_cause,
        evidence_refs=proposal.evidence_refs,
        repository=proposal.repository,
        source_sha=proposal.source_sha or "",
        file_paths=[proposal.target_filepath] if proposal.target_filepath else [],
        patch=proposal.diff_patch_payload,
        validation_plan=proposal.validation_plan,
        risk_class=proposal.risk_class,
    )


def verify_proposal_integrity(
    incident,
    proposal: HotfixProposal,
    claimed_hash: str,
) -> None:
    """stored hash must equal both the recomputed canonical hash and the
    caller's claim — any divergence fails closed (§5)."""
    if not proposal.proposal_hash:
        raise ProposalIntegrityError("proposal has no canonical hash")
    recomputed = recompute_proposal_hash(incident, proposal)
    if not hmac.compare_digest(recomputed, proposal.proposal_hash):
        raise ProposalIntegrityError(
            "persisted proposal does not match its canonical hash "
            "(proposal was modified after generation)"
        )
    claim = (claimed_hash or "").strip().lower()
    if not claim:
        raise ProposalIntegrityError("proposal_hash is required")
    if not hmac.compare_digest(claim, proposal.proposal_hash):
        raise ProposalIntegrityError(
            "supplied proposal_hash does not match the persisted proposal"
        )
    if proposal.approval_hash and not hmac.compare_digest(
        proposal.approval_hash, proposal.proposal_hash
    ):
        raise ProposalIntegrityError(
            "approval is bound to a different proposal hash"
        )


def execution_id_for(proposal_id: str, proposal_hash: str) -> str:
    return str(
        uuid.uuid5(EXECUTION_NAMESPACE, f"{proposal_id}:{proposal_hash}")
    )


def is_fresh(moment: Optional[datetime], ttl_seconds: float, now: datetime) -> bool:
    if moment is None:
        return False
    observed = moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)
    age = (now - observed).total_seconds()
    return 0 <= age <= ttl_seconds


def _log(event: str, **fields) -> None:
    logger.info(json.dumps({"event": event, **fields}))


def log_stage(stage: str, **fields) -> None:
    """Structured execution lifecycle event (§29): ids/hashes/status only."""
    _log(f"remediation.{stage}", **fields)
