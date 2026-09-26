from incident_service.application.commands.ingest_webhook_alert import IngestWebhookAlertCommandHandler
from incident_service.application.dependencies import get_incident_repository
from incident_service.application.event_handlers.on_metric_threshold_failed import (
    OnMetricThresholdFailedHandler,
)
from incident_service.infrastructure.messaging.redis_incident_consumer import RedisIncidentEventConsumer


def main():
    repository = get_incident_repository()
    triage_handler = IngestWebhookAlertCommandHandler(repository)
    event_handler = OnMetricThresholdFailedHandler(triage_handler)
    consumer = RedisIncidentEventConsumer(event_handler)
    consumer.run_forever()


if __name__ == "__main__":
    main()
