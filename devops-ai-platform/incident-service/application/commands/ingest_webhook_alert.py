import uuid

from ...domain.aggregates.incident import IncidentAggregate
from ...domain.repository_interface import IncidentRepositoryPort


class IngestWebhookAlertCommand:
    def __init__(self, raw_source: str, alert_name: str, severity: str, details: str):
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


class IngestWebhookAlertCommandHandler:
    """Turns external alert-shaped commands into persisted incident aggregates."""

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
        incident.move_to_triage()
        self.repo.save_incident(incident)
        return incident.id
