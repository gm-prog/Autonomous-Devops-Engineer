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

    def attach_verified_patch(self, proposal: HotfixProposal):
        if proposal.is_verified:
            self.patch_proposals.append(proposal)
            self.status = "RemediationVerified"
