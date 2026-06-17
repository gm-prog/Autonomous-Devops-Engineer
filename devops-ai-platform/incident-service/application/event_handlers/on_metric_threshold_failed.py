import logging
from ....shared_kernel.domain.events import ThreatThresholdExceededEvent
from ..commands.ingest_webhook_alert import IngestWebhookAlertCommand, IngestWebhookAlertCommandHandler

logger = logging.getLogger("OnMetricThresholdFailed")

class OnMetricThresholdFailedHandler:
    """Consumes load limit breach events to raise automated incident workflows."""
    def __init__(self, triage_handler: IngestWebhookAlertCommandHandler):
        self.triage = triage_handler

    def handle(self, event: ThreatThresholdExceededEvent):
        logger.warning(f"[AMQP] Threat limit breached event received from Service scope {event.aggregate_id}.")
        cmd = IngestWebhookAlertCommand(
            raw_source="prometheus-alert",
            alert_name="NodeMemorySaturationAlarm",
            severity="High",
            details=f"Usage metric: {event.payload.get('average', 'N/A')}"
        )
        self.triage.handle(cmd)
