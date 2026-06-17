import json
import logging
from typing import Any
from ...shared_kernel.domain.events import DomainEvent

logger = logging.getLogger("SharedMessagingBus")

class DomainEventPublisher:
    """
    Publish model domain events across our boundaries towards active RabbitMQ/Kafka brokers.
    """
    def __init__(self, broker_url: str = "redis://redis:6379/0"):
        self.broker_url = broker_url

    def publish(self, event: DomainEvent):
        payload_data = json.dumps(event.to_dict())
        logger.info(f"[PUBLISH_EVENT] Type: {event.__class__.__name__} -> Aggregate: {event.aggregate_id}")
        logger.debug(f"Event payload: {payload_data}")
        # In actual production code, this routes directly into an active amqp connection
        return True
