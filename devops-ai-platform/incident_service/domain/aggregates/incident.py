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

    def __init__(self, id: str, title: str, severity: str, context_details: str):
        self.id = id
        self.title = title
        self.severity = severity
        self.context = context_details
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
        if self.status == "Raised":
            self.status = "Triage"

    def mark_root_cause_found(self):
        if self.status not in {"Triage", "Investigating"}:
            raise ValueError(
                f"Cannot mark root cause found from incident state {self.status!r}"
            )
        self.status = "RootCauseFound"

    def attach_evidence(self, evidence: IncidentEvidence):
        if not evidence.id.strip():
            raise ValueError("evidence id must not be empty")
        if any(item.id == evidence.id for item in self.evidence):
            return
        self.evidence.append(evidence)

    def attach_remediation_proposal(self, proposal: HotfixProposal):
        if not proposal.is_verified:
            raise ValueError("remediation proposal must pass deterministic patch verification")
        self.patch_proposals.append(proposal)
        self.status = "RemediationProposed"

    def upsert_remediation_proposal(self, proposal: HotfixProposal):
        """Idempotent proposal attach (§4): a deterministic proposal id
        replaces any previous instance instead of accumulating duplicates."""
        if not proposal.is_verified:
            raise ValueError("remediation proposal must pass deterministic patch verification")
        self.patch_proposals = [
            item for item in self.patch_proposals if item.id != proposal.id
        ]
        self.patch_proposals.append(proposal)
        self.status = "RemediationProposed"

    def attach_blocked_proposal(self, proposal: HotfixProposal):
        """Persist a BLOCKED (non-executable) proposal without promoting
        the incident: status must not suggest an executable proposal (§20)."""
        if proposal.status != "BLOCKED":
            raise ValueError("blocked proposal must carry status BLOCKED")
        self.patch_proposals = [
            item for item in self.patch_proposals if item.id != proposal.id
        ]
        self.patch_proposals.append(proposal)

    def approve_remediation_proposal(
        self,
        proposal_id: str,
        approved_by: str,
        expected_hash: str,
    ):
        """Approve exactly one persisted proposal, bound to its current hash."""
        proposal = next(
            (item for item in self.patch_proposals if item.id == proposal_id),
            None,
        )
        if proposal is None:
            raise ValueError("remediation proposal not found")
        if proposal.status != "PROPOSED":
            raise ValueError(f"proposal state {proposal.status!r} cannot be approved")
        if not proposal.is_verified:
            raise ValueError("only a verified proposal can be approved")
        if proposal.proposal_hash != expected_hash:
            raise ValueError("proposal hash does not match the persisted proposal")
        if not approved_by.strip():
            raise ValueError("approved_by must not be empty")
        proposal.approved_by = approved_by.strip()
        proposal.approved_at = datetime.now(timezone.utc)
        proposal.status = "APPROVED"

    def mark_remediation_pr_created(self, proposal_id: str, pull_request_url: str):
        """Record successful guarded publication of a remediation PR."""
        proposal = next(
            (item for item in self.patch_proposals if item.id == proposal_id),
            None,
        )
        if proposal is None:
            raise ValueError("remediation proposal not found")
        if proposal.status != "APPROVED":
            raise ValueError("only an approved proposal can become PR_CREATED")
        if not isinstance(pull_request_url, str) or not pull_request_url.startswith("https://github.com/"):
            raise ValueError("pull_request_url must be a GitHub HTTPS URL")
        proposal.pull_request_url = pull_request_url
        proposal.status = "PR_CREATED"
        self.status = "RemediationPRCreated"

    def attach_verified_patch(self, proposal: HotfixProposal):
        if proposal.is_verified:
            self.patch_proposals.append(proposal)
            self.status = "RemediationVerified"
