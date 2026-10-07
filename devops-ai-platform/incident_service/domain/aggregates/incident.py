from typing import List, Mapping
from datetime import datetime, timezone

from ..entities.hotfix_proposal import HotfixProposal
from ..events import OutOfBoundsIncidentLoggedEvent
from ..entities.incident_evidence import IncidentEvidence


class IncidentAggregate:
    """
    Incident Aggregate Root.
    Encapsulates all lifecycle state for an operational incident,
    including structured evidence, RCA completion, and remediation proposals.
    """

    def __init__(self, id: str, title: str, severity: str, context_details: str, version: int = 0):
        self.id = id
        self.title = title
        self.severity = severity
        self.context = context_details
        # Phase 8.1: durable optimistic-concurrency revision. 0 = new
        # (never persisted); every successful save advances it exactly
        # once. Hydration overwrites this with the persisted value —
        # the database is the authority for aggregate freshness.
        self.version = int(version)
        self.created_at = datetime.now(timezone.utc)
        self.status = "Raised"
        self.patch_proposals: List[HotfixProposal] = []
        self.evidence: List[IncidentEvidence] = []
        self.domain_events = [
            OutOfBoundsIncidentLoggedEvent(
                aggregate_id=self.id,
                payload={"severity": self.severity, "reason": self.title},
            )
        ]

    def move_to_triage(self):
        """Raised → Triage. Idempotent only for an already-present Triage
        state; every other source state is rejected (never coerced)."""
        if self.status == "Triage":
            return
        if self.status != "Raised":
            raise ValueError(
                f"Cannot move incident to Triage from state {self.status!r}"
            )
        self.status = "Triage"

    def begin_investigation(self):
        """Triage → Investigating (the explicit required intermediate
        transition of the canonical lifecycle)."""
        if self.status == "Investigating":
            return
        if self.status != "Triage":
            raise ValueError(
                f"Cannot begin investigation from state {self.status!r} "
                "(requires Triage)"
            )
        self.status = "Investigating"

    def mark_root_cause_found(self):
        """Investigating → RootCauseFound. Investigating must be entered
        explicitly first — Triage may not skip straight to RootCauseFound."""
        if self.status == "RootCauseFound":
            return
        if self.status != "Investigating":
            raise ValueError(
                f"Cannot mark root cause found from incident state {self.status!r} "
                "(requires Investigating)"
            )
        self.status = "RootCauseFound"

    def mark_remediation_pr_created(self):
        """RemediationProposed → RemediationPRCreated, persisted exactly
        when a real PR has been persisted for the approved proposal."""
        if self.status == "RemediationPRCreated":
            return
        if self.status != "RemediationProposed":
            raise ValueError(
                f"Cannot mark remediation PR created from state {self.status!r} "
                "(requires RemediationProposed)"
            )
        self.status = "RemediationPRCreated"

    def attach_evidence(self, evidence: IncidentEvidence):
        if not evidence.id.strip():
            raise ValueError("evidence id must not be empty")
        if any(item.id == evidence.id for item in self.evidence):
            return
        self.evidence.append(evidence)

    # Phase 8.2 (Task B): the former unguarded `attach_remediation_proposal`
    # escape hatch (append + promote with no lifecycle/identity policy) was
    # REMOVED. The only production proposal-attach APIs are
    # `upsert_remediation_proposal` and `attach_blocked_proposal`, both of
    # which enforce the Phase 8 lifecycle guards below.

    def upsert_remediation_proposal(self, proposal: HotfixProposal):
        """Idempotent proposal attach (§4): a deterministic proposal id
        replaces any previous instance instead of accumulating duplicates.

        Lifecycle guard (Phase 8 §4/§35): regeneration may refresh a
        BLOCKED or PROPOSED proposal, but must never reset an approved,
        executing, failed, or published proposal back to PROPOSED — that
        would permit a second approval/execution cycle for the same
        identity and destroy the durable PR record.
        """
        if not proposal.is_verified:
            raise ValueError("remediation proposal must pass deterministic patch verification")
        if self.status not in {"RootCauseFound", "RemediationProposed"}:
            raise ValueError(
                f"Cannot attach executable proposal from incident state "
                f"{self.status!r} (requires RootCauseFound — no skipped "
                "intermediate transitions)"
            )
        existing = next(
            (item for item in self.patch_proposals if item.id == proposal.id),
            None,
        )
        if existing is not None and existing.status in {
            "APPROVED",
            "EXECUTING",
            "PR_CREATED",
            "EXECUTION_FAILED",
        }:
            raise ValueError(
                f"proposal {proposal.id} is {existing.status}; regeneration "
                "cannot reset an approved/executing/published proposal to "
                f"{proposal.status}"
            )
        self.patch_proposals = [
            item for item in self.patch_proposals if item.id != proposal.id
        ]
        self.patch_proposals.append(proposal)
        self.status = "RemediationProposed"

    def attach_blocked_proposal(self, proposal: HotfixProposal):
        """Persist a BLOCKED (non-executable) proposal without promoting
        the incident: status must not suggest an executable proposal (§20).

        Same Phase 8 lifecycle guard as ``upsert_remediation_proposal``:
        a BLOCKED regeneration may never replace an approved, executing,
        failed, or published proposal record.
        """
        if proposal.status != "BLOCKED":
            raise ValueError("blocked proposal must carry status BLOCKED")
        existing = next(
            (item for item in self.patch_proposals if item.id == proposal.id),
            None,
        )
        if existing is not None and existing.status in {
            "APPROVED",
            "EXECUTING",
            "PR_CREATED",
            "EXECUTION_FAILED",
        }:
            raise ValueError(
                f"proposal {proposal.id} is {existing.status}; a BLOCKED "
                "regeneration cannot replace an approved/executing/published "
                "proposal"
            )
        self.patch_proposals = [
            item for item in self.patch_proposals if item.id != proposal.id
        ]
        self.patch_proposals.append(proposal)

    def attach_verified_patch(self, proposal: HotfixProposal):
        if proposal.is_verified:
            self.patch_proposals.append(proposal)
            self.status = "RemediationVerified"
