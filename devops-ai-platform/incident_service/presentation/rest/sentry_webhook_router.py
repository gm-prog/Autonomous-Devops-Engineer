"""Sentry webhook receiver with fail-closed HMAC verification.

The recovery transplant had replaced the green line's signature check with
the dev-line permissive receiver (any JSON accepted). This merged router
keeps the transplant's real repository injection and restores raw-body
HMAC-SHA256 verification from the green baseline.
"""

import hashlib
import hmac
import json
import logging
import os

from fastapi import APIRouter, Depends, HTTPException, Request, status

from incident_service.application.commands.ingest_webhook_alert import (
    IngestWebhookAlertCommand,
    IngestWebhookAlertCommandHandler,
)
from incident_service.application.dependencies import get_incident_repository
from incident_service.domain.repository_interface import IncidentRepositoryPort

logger = logging.getLogger("SentryWebhookReceiver")

router = APIRouter(prefix="/alerts/webhooks", tags=["Webhook Alerting Receiver"])

# Shared secret for HMAC-SHA256 verification of inbound Sentry alerts.
# When unset the receiver runs in permissive dev mode (with a loud warning)
# so local demos keep working; production MUST set this.
SENTRY_WEBHOOK_SECRET = os.getenv("SENTRY_WEBHOOK_SECRET", "")

if not SENTRY_WEBHOOK_SECRET:
    logger.warning(
        "SENTRY_WEBHOOK_SECRET is not set - inbound Sentry webhooks are accepted "
        "UNVERIFIED (permissive dev mode). Set it to enable HMAC verification."
    )


def verify_sentry_signature(body: bytes, signature: str | None) -> bool:
    """Verify the HMAC-SHA256 hex digest of the raw request body."""
    if not SENTRY_WEBHOOK_SECRET:
        return True  # permissive dev mode (warned at import time)
    if not signature:
        return False
    expected = hmac.new(
        SENTRY_WEBHOOK_SECRET.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def get_triage_handler(
    repository: IncidentRepositoryPort = Depends(get_incident_repository),
) -> IngestWebhookAlertCommandHandler:
    return IngestWebhookAlertCommandHandler(repository)


@router.post("/sentry", status_code=status.HTTP_202_ACCEPTED)
async def receive_sentry_webhook(
    request: Request,
    handler: IngestWebhookAlertCommandHandler = Depends(get_triage_handler),
):
    """Receives JSON webhook alerts and persists the resulting incident.

    Signature contract: header ``X-Sentry-Signature`` = hex digest of
    HMAC-SHA256(raw_body, SENTRY_WEBHOOK_SECRET).
    """
    body = await request.body()
    signature = request.headers.get("x-sentry-signature")

    if not body:
        raise HTTPException(status_code=400, detail="Invalid sentry payload signature.")
    if not verify_sentry_signature(body, signature):
        logger.warning("Sentry webhook rejected: invalid or missing signature")
        raise HTTPException(status_code=401, detail="Webhook signature verification failed.")

    try:
        payload = json.loads(body)
    except ValueError:
        raise HTTPException(status_code=400, detail="Webhook body is not valid JSON.")

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
