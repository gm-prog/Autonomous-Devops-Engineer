import uuid
from ...domain.aggregates.incident import IncidentAggregate
from ...domain.repository_interface import IncidentRepositoryPort

class IngestWebhookAlertCommand:
    def __init__(self, raw_source: str, alert_name: str, severity: str, details: str):
        self.raw_source = raw_source
        self.alert_name = alert_name
        self.severity = severity
        self.details = details

class IngestWebhookAlertCommandHandler:
    """Ingests Sentry or Prometheus alerting payload models, spinning up an incident aggregate to log details."""
    def __init__(self, persistence: IncidentRepositoryPort):
        self.repo = persistence

    def handle(self, cmd: IngestWebhookAlertCommand) -> str:
        incident_id = str(uuid.uuid4())
        
        # Instantiate aggregate matching incident schema
        incident = IncidentAggregate(
            id=incident_id,
            title=f"[{cmd.raw_source.upper()}] {cmd.alert_name}",
            severity=cmd.severity,
            context_details=cmd.details
        )
        
        # Trigger triage phase
        incident.move_to_triage()
        
        self.repo.save_incident(incident)
        return incident.id
