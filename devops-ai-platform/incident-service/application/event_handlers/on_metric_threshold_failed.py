import logging
from typing import Any, Mapping

from application.commands.ingest_webhook_alert import (
    IngestWebhookAlertCommand,
    IngestWebhookAlertCommandHandler,
)

logger = logging.getLogger("OnMetricThresholdFailed")


class OnMetricThresholdFailedHandler:
    """Maps the public monitoring event payload into incident ingestion."""

    def __init__(self, triage_handler: IngestWebhookAlertCommandHandler):
        self.triage = triage_handler

    def handle(self, event: Mapping[str, Any]) -> str:
        aggregate_id = str(event.get("aggregate_id", "")).strip()
        payload = event.get("payload") or {}
        if not aggregate_id:
            raise ValueError("monitoring event aggregate_id is required")
        if not isinstance(payload, Mapping):
            raise ValueError("monitoring event payload must be an object")

        breaches = payload.get("breaches") or []
        if not isinstance(breaches, list):
            raise ValueError("monitoring event breaches must be a list")

        primary = breaches[0] if breaches and isinstance(breaches[0], Mapping) else {}

        metric = primary.get("metric", "unknown")
        value = primary.get("value", "N/A")
        threshold = primary.get("threshold", "N/A")
        operator = primary.get("operator", ">=")
        severity = str(
            primary.get("severity")
            or payload.get("severity")
            or "high"
        ).upper()

        command = IngestWebhookAlertCommand(
            raw_source="prometheus-alert",
            alert_name=f"{metric}-threshold-breached",
            severity=severity,
            details=(
                f"Service={aggregate_id}; "
                f"metric={metric}; value={value}; "
                f"threshold={operator} {threshold}; "
                f"breach_count={payload.get('breach_count', len(breaches))}"
            ),
        )

        logger.warning(
            "Threshold breach mapped to incident ingestion: service=%s metric=%s severity=%s",
            aggregate_id,
            metric,
            severity,
        )
        return self.triage.handle(command)
