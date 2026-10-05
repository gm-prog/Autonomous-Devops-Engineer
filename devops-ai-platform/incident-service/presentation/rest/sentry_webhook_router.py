from fastapi import APIRouter, Depends, Header, HTTPException, status

from application.commands.ingest_webhook_alert import (
    IngestWebhookAlertCommand,
    IngestWebhookAlertCommandHandler,
)
from application.dependencies import get_incident_repository
from domain.repository_interface import IncidentRepositoryPort


router = APIRouter(prefix="/alerts/webhooks", tags=["Webhook Alerting Receiver"])


def get_triage_handler(
    repository: IncidentRepositoryPort = Depends(get_incident_repository),
) -> IngestWebhookAlertCommandHandler:
    return IngestWebhookAlertCommandHandler(repository)


@router.post("/sentry", status_code=status.HTTP_202_ACCEPTED)
def receive_sentry_webhook(
    payload: dict,
    x_sentry_signature: str | None = Header(default=None),
    handler: IngestWebhookAlertCommandHandler = Depends(get_triage_handler),
):
    """Receives JSON webhook alerts and persists the resulting incident."""
    if x_sentry_signature is None and not payload:
        raise HTTPException(status_code=400, detail="Invalid sentry payload signature.")

    issue_data = payload.get("data", {}).get("issue", {})
    alert_name = issue_data.get("title", "Unhandled RuntimeError Exception")
    details = (
        "Sentry exception trigger. Project context: "
        f"{issue_data.get('metadata', {}).get('value', 'Stacktrace blocked.')}"
    )

    cmd = IngestWebhookAlertCommand(
        raw_source="sentry",
        alert_name=alert_name,
        severity="High" if "null" not in details else "Medium",
        details=details,
    )

    incident_id = handler.handle(cmd)
    return {
        "status": "ACCEPTED",
        "registered_incident_id": incident_id,
        "automated_triage_initiated": True,
    }
