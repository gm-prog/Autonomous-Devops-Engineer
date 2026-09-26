import uuid
from typing import List, Optional

from incident_service.domain.entities.incident_evidence import IncidentEvidence

from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.domain.repository_interface import IncidentRepositoryPort


class IngestWebhookAlertCommand:
    def __init__(self, raw_source: str, alert_name: str, severity: str, details: str, evidence: Optional[List[IncidentEvidence]] = None):
        if not raw_source.strip():
            raise ValueError("raw_source must not be empty")
        if not alert_name.strip():
            raise ValueError("alert_name must not be empty")
        if not details.strip():
            raise ValueError("details must not be empty")

        self.raw_source = raw_source.strip()
        self.alert_name = alert_name.strip()
        self.severity = severity.strip().upper() or "HIGH"
        self.details = details.strip()
        self.evidence = list(evidence or [])


class IngestWebhookAlertCommandHandler:
    """Turns external alert-shaped commands into incident aggregates."""

    def __init__(self, persistence: IncidentRepositoryPort):
        self.repo = persistence

    def handle(self, cmd: IngestWebhookAlertCommand) -> str:
        incident_id = str(uuid.uuid4())
        incident = IncidentAggregate(
            id=incident_id,
            title=f"[{cmd.raw_source.upper()}] {cmd.alert_name}",
            severity=cmd.severity,
            context_details=cmd.details,
        )
        for evidence in cmd.evidence:
            incident.attach_evidence(evidence)
        incident.move_to_triage()
        self.repo.save_incident(incident)
        return incident.id
