import json
import logging
from datetime import datetime, timezone
from typing import Any, Mapping

from incident_service.domain.entities.incident_evidence import IncidentEvidence

from incident_service.application.commands.ingest_webhook_alert import (
    IngestWebhookAlertCommand,
    IngestWebhookAlertCommandHandler,
    deterministic_evidence_id,
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

        observed_at = _parse_timestamp(event.get("timestamp"))
        event_id = str(event.get("event_id", ""))

        # §4 idempotency: the evidence id derives from the producer's
        # event_id, so a redelivered event maps onto the SAME evidence
        # entry (attach_evidence skips ids it already holds).
        evidence_kwargs = {}
        if event_id.strip():
            evidence_kwargs["id"] = deterministic_evidence_id(event_id)

        evidence = IncidentEvidence(
            kind="threshold_breach",
            source="monitoring-service",
            observed_at=observed_at,
            payload={
                "event_id": event_id,
                "event_type": str(event.get("event_type", "ThreatThresholdExceededEvent")),
                "service": aggregate_id,
                "metric": metric,
                "value": value,
                "threshold": threshold,
                "operator": operator,
                "severity": severity,
                "breach_count": payload.get("breach_count", len(breaches)),
                "breaches": breaches,
                "metrics": payload.get("metrics") or {},
            },
            **evidence_kwargs,
        )

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
            evidence=[evidence],
        )

        logger.warning(
            "Threshold breach mapped to incident ingestion: service=%s metric=%s severity=%s",
            aggregate_id,
            metric,
            severity,
        )
        incident_id = self.triage.handle(command)
        return incident_id


def _parse_timestamp(value: Any) -> datetime:
    raw = str(value or "").strip()
    if raw:
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            logger.warning("Invalid monitoring event timestamp=%r; using ingestion time", raw)
    return datetime.now(timezone.utc)
