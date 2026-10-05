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


# ---------------------------------------------------------------------- #
# Phase 6.2.1: durable lease coordination + persisted stage vocabulary
# ---------------------------------------------------------------------- #

#: Durable lease contract: how long one owner may hold an execution
#: before another worker may reclaim it. Config (not hardcoded) because
#: the value is operationally dangerous to guess.
LEASE_SECONDS_ENV = "REMEDIATION_EXECUTION_LEASE_SECONDS"
DEFAULT_LEASE_SECONDS = 600.0  # 10 minutes

#: Bounded, externally-meaningful persisted stage vocabulary. A stage is
#: only persisted AFTER the boundary it names has actually been verified.
EXECUTION_STAGES: tuple = (
    "CLAIMED",
    "WORKSPACE_CREATED",
    "PATCH_APPLIED",
    "VALIDATION_STARTED",
    "VALIDATION_PASSED",
    "COMMIT_CREATED",
    "REMOTE_PUBLISHED",
    "REMOTE_VERIFIED",
    "PR_DISCOVERY",
    "PR_CREATED",
    "COMPLETED",
    "FAILED",
)

_STAGE_INDEX = {name: index for index, name in enumerate(EXECUTION_STAGES)}

#: Durable cursor stages from which recovery may resume by reconciling
#: remote state instead of redoing workspace/patch/validation/commit.
RESUMABLE_STAGES = frozenset(
    {"COMMIT_CREATED", "REMOTE_PUBLISHED", "REMOTE_VERIFIED", "PR_DISCOVERY"}
)

#: orchestrator notify name → persisted stage
_NOTIFY_TO_STAGE = {
    "workspace.created": "WORKSPACE_CREATED",
    "patch.applied": "PATCH_APPLIED",
    "validation.started": "VALIDATION_STARTED",
    "validation.completed": "VALIDATION_PASSED",
    "commit.created": "COMMIT_CREATED",
    "remote.published": "REMOTE_PUBLISHED",
    "remote.verified": "REMOTE_VERIFIED",
    "pr.discovery": "PR_DISCOVERY",
    "pr.created": "PR_CREATED",
    "pr.reconciled": "PR_CREATED",
}


def load_lease_seconds() -> float:
    """Fail fast on malformed lease configuration (repo env convention)."""
    raw = os.getenv(LEASE_SECONDS_ENV, "").strip()
    if not raw:
        return DEFAULT_LEASE_SECONDS
    lease = float(raw)
    if lease <= 0:
        raise ValueError(f"{LEASE_SECONDS_ENV} must be a positive number")
    return lease


#: Optional heartbeat interval override (Phase 6.2.1A). When unset the
#: interval is derived from the lease duration so that renewals happen
#: well before expiry (interval < lease/2 by construction).
HEARTBEAT_SECONDS_ENV = "REMEDIATION_EXECUTION_HEARTBEAT_SECONDS"


def load_heartbeat_seconds(lease_seconds: float) -> float:
    """Resolve the active-lease heartbeat interval for one execution.

    Derived default: ``lease_seconds / 3`` — strictly below the required
    ``lease / 2`` ceiling, leaving at least two renewal opportunities
    inside one lease window. An explicit override must be a positive
    finite number strictly below ``lease / 2``; anything else fails
    fast (never silently coerced).
    """
    if lease_seconds <= 0:
        raise ValueError("lease duration must be positive")
    ceiling = lease_seconds / 2.0
    raw = os.getenv(HEARTBEAT_SECONDS_ENV, "").strip()
    if not raw:
        return lease_seconds / 3.0
    interval = float(raw)
    if interval <= 0 or interval != interval or interval == float("inf"):
        raise ValueError(f"{HEARTBEAT_SECONDS_ENV} must be a positive number")
    if interval >= ceiling:
        raise ValueError(
            f"{HEARTBEAT_SECONDS_ENV} must be less than half the lease "
            f"duration ({ceiling})"
        )
    return interval


def new_lease_owner() -> str:
    """Process-derived owner identity — never caller-supplied."""
    import socket
    import uuid as _uuid

    host = socket.gethostname() or "unknown-host"
    return f"{host}:{os.getpid()}:{_uuid.uuid4().hex[:12]}"


def stage_for_notify(notify_stage: str) -> Optional[str]:
    """Map an orchestrator stage callback name to the durable vocabulary.

    Callers must still gate on result metadata (e.g. a FAILED validation
    must not persist VALIDATION_PASSED — the failure path persists FAILED).
    """
    return _NOTIFY_TO_STAGE.get(notify_stage)


def validate_stage_transition(current: str, new: str) -> None:
    """Enforce the bounded forward-only stage machine (§36).

    Allowed: forward movement inside EXECUTION_STAGES, and FAILED from
    any executed state. Backward/jumping transitions raise — recovery
    resets go through the atomic claim, never through progress writes.
    """
    if new == "FAILED":
        if current not in {"", "FAILED"} and current not in _STAGE_INDEX:
            raise ValueError(f"unknown current stage: {current!r}")
        return
    if new == "CLAIMED":
        # claim-time (re)start: always allowed via the claim path
        return
    if new not in _STAGE_INDEX:
        raise ValueError(f"unknown execution stage: {new!r}")
    if current == "FAILED":
        raise ValueError("failed execution must be re-claimed, not progressed")
    if current and current != new:
        current_index = _STAGE_INDEX.get(current)
        if current_index is None:
            raise ValueError(f"unknown current stage: {current!r}")
        if _STAGE_INDEX[new] <= current_index:
            raise ValueError(
                f"stage transition {current} -> {new} violates ordering"
            )
    if current == "COMPLETED":
        raise ValueError("completed execution cannot progress further")
