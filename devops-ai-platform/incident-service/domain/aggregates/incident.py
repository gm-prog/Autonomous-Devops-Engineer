from typing import List, Optional
from datetime import datetime
from ..entities.hotfix_proposal import HotfixProposal
from ...shared_kernel.domain.events import OutOfBoundsIncidentLoggedEvent

class IncidentAggregate:
    """
    Incident Aggregate Root.
    Encapsulates life states of operational alerts, auto-triage workflows,
    and references back to autonomous patch plans.
    """
    def __init__(self, id: str, title: str, severity: str, context_details: str):
        self.id = id
        self.title = title
        self.severity = severity # Low, Medium, High, Critical
        self.context = context_details
        self.created_at = datetime.utcnow()
        self.status = "Raised" # Raised, Triage, RemediationVerified, Resolved
        self.patch_proposals: List[HotfixProposal] = []
        self.domain_events = []

        self.domain_events.append(OutOfBoundsIncidentLoggedEvent(
            aggregate_id=self.id,
            payload={"severity": self.severity, "reason": self.title}
        ))

    def move_to_triage(self):
        if self.status == "Raised":
            self.status = "Triage"

    def attach_verified_patch(self, proposal: HotfixProposal):
        if proposal.is_verified:
            self.patch_proposals.append(proposal)
            self.status = "RemediationVerified"
