from typing import List
from datetime import datetime, timezone

from ..entities.hotfix_proposal import HotfixProposal
from ..events import OutOfBoundsIncidentLoggedEvent
from ..entities.incident_evidence import IncidentEvidence


class IncidentAggregate:
    """
    Incident Aggregate Root.
    Encapsulates life states of operational alerts, auto-triage workflows,
    and references back to autonomous patch plans.
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

    def attach_evidence(self, evidence: IncidentEvidence):
        if not evidence.id.strip():
            raise ValueError("evidence id must not be empty")
        if any(item.id == evidence.id for item in self.evidence):
            return
        self.evidence.append(evidence)

    def attach_verified_patch(self, proposal: HotfixProposal):
        if proposal.is_verified:
            self.patch_proposals.append(proposal)
            self.status = "RemediationVerified"
