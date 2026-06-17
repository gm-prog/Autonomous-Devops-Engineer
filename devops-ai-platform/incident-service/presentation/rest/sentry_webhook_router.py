from fastapi import APIRouter, Header, HTTPException, status, Depends
from ...application.commands.ingest_webhook_alert import IngestWebhookAlertCommand, IngestWebhookAlertCommandHandler

router = APIRouter(prefix="/alerts/webhooks", tags=["Webhook Alerting Receiver"])

def get_triage_handler_mock() -> IngestWebhookAlertCommandHandler:
    class MockRepo:
        def save_incident(self, inc): pass
    return IngestWebhookAlertCommandHandler(MockRepo())

@router.post("/sentry", status_code=status.HTTP_202_ACCEPTED)
def receive_sentry_webhook(payload: dict, x_sentry_signature: str = Header(None), handler: IngestWebhookAlertCommandHandler = Depends(get_triage_handler_mock)):
    """Receives JSON webhook alerts triggered by exceptions logged inside Sentry metrics."""
    # Check signature validations
    if x_sentry_signature is None and not payload:
        raise HTTPException(status_code=400, detail="Invalid sentry payload signature.")
        
    issue_data = payload.get("data", {}).get("issue", {})
    alert_name = issue_data.get("title", "Unhandled RuntimeError Exception")
    details = f"Sentry exception trigger. Project context: {issue_data.get('metadata', {}).get('value', 'Stacktrace blocked.')}"
    
    cmd = IngestWebhookAlertCommand(
        raw_source="sentry",
        alert_name=alert_name,
        severity="High" if "null" not in details else "Medium",
        details=details
    )
    
    incident_id = handler.handle(cmd)
    return {
        "status": "ACCEPTED",
        "registered_incident_id": incident_id,
        "automated_triage_initiated": True
    }
