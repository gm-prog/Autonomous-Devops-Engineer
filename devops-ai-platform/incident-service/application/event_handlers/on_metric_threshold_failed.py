import logging
from typing import Any

from ....monitoring_service.domain.events import ThreatThresholdExceededEvent
from ..commands.ingest_webhook_alert import (
    IngestWebhookAlertCommand,
    IngestWebhookAlertCommandHandler,
)

logger = logging.getLogger("OnMetricThresholdFailed")


class OnMetricThresholdFailedHandler:
    """Maps a monitoring threshold event into the incident ingestion command."""

    def __init__(self, triage_handler: IngestWebhookAlertCommandHandler):
        self.triage = triage_handler

    def handle(self, event: ThreatThresholdExceededEvent) -> str:
        breaches = list(event.payload.get("breaches", []))
        primary = breaches[0] if breaches else {}

        metric = primary.get("metric", "unknown")
        value = primary.get("value", "N/A")
        threshold = primary.get("threshold", "N/A")
        operator = primary.get("operator", ">=")
        severity = str(
            primary.get("severity")
            or event.payload.get("severity")
            or "high"
        ).upper()

        cmd = IngestWebhookAlertCommand(
            raw_source="prometheus-alert",
            alert_name=f"{metric}-threshold-breached",
            severity=severity,
            details=(
                f"Service={event.aggregate_id}; "
                f"metric={metric}; value={value}; "
                f"threshold={operator} {threshold}; "
                f"breach_count={event.payload.get('breach_count', len(breaches))}"
            ),
        )

        logger.warning(
            "[EVENT] Threshold breach mapped to incident ingestion: "
            "service=%s metric=%s severity=%s",
            event.aggregate_id,
            metric,
            severity,
        )
        return self.triage.handle(cmd)
