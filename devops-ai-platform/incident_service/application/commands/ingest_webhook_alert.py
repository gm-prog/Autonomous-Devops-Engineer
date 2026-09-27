import json
import logging
import uuid
from typing import List, Optional

from incident_service.domain.entities.incident_evidence import IncidentEvidence

from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.domain.repository_interface import IncidentRepositoryPort

logger = logging.getLogger("IngestWebhookAlert")

# Deterministic namespace for event_id-derived ids (§4 idempotency): the
# same event_id always maps to the same incident/evidence identity, so
# stream redeliveries can never mint uncontrolled duplicates.
INCIDENT_EVENT_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "devops.ai/incident-event"
)


def deterministic_incident_id(event_id: str) -> str:
    """Stable incident id derived from a producer-assigned event id."""
    return str(uuid.uuid5(INCIDENT_EVENT_NAMESPACE, f"incident:{event_id}"))


def deterministic_evidence_id(event_id: str) -> str:
    """Stable evidence id derived from a producer-assigned event id."""
    return str(uuid.uuid5(INCIDENT_EVENT_NAMESPACE, f"evidence:{event_id}"))


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
        # §4 idempotency: when evidence carries a producer event_id, the
        # incident id is derived from it — a redelivered event returns the
        # existing incident instead of creating a duplicate.
        event_id = ""
        for evidence in cmd.evidence:
            candidate = str((evidence.payload or {}).get("event_id") or "").strip()
            if candidate:
                event_id = candidate
                break

        if event_id:
            incident_id = deterministic_incident_id(event_id)
            existing = self.repo.get_incident_by_id(incident_id)
            if existing is not None:
                logger.info(
                    json.dumps(
                        {
                            "event": "incident.duplicate_ignored",
                            "incident_id": existing.id,
                            "event_id": event_id,
                            "correlation_id": event_id,
                        }
                    )
                )
                return existing.id
        else:
            incident_id = str(uuid.uuid4())

        incident = IncidentAggregate(
            id=incident_id,
            title=f"[{cmd.raw_source.upper()}] {cmd.alert_name}",
            severity=cmd.severity,
            context_details=cmd.details,
        )
        for evidence in cmd.evidence:
            incident.attach_evidence(evidence)
            logger.info(
                json.dumps(
                    {
                        "event": "evidence.attached",
                        "incident_id": incident.id,
                        "evidence_id": evidence.id,
                        "evidence_kind": evidence.kind,
                        "event_id": event_id or None,
                        "correlation_id": event_id or incident.id,
                    }
                )
            )
        incident.move_to_triage()
        self.repo.save_incident(incident)
        logger.info(
            json.dumps(
                {
                    "event": "incident.created",
                    "incident_id": incident.id,
                    "event_id": event_id or None,
                    "correlation_id": event_id or incident.id,
                    "evidence_ids": [item.id for item in incident.evidence],
                }
            )
        )
        return incident.id
