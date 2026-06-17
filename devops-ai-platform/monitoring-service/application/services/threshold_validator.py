import logging
from ...domain.aggregates.metric_stream import MetricStreamAggregate
from ....shared_kernel.domain.events import ThreatThresholdExceededEvent

logger = logging.getLogger("ThresholdValidator")

class ThresholdValidator:
    """Evaluates telemetry values to trigger failover or escalation flows."""
    def __init__(self, danger_percentage: float = 90.0):
        self.danger_limit = danger_percentage

    def evaluate_stream(self, stream: MetricStreamAggregate) -> bool:
        avg = stream.current_load_average()
        if avg > self.danger_limit:
            logger.warning(f"[ALARM] Alert! Danger threshold breached for service '{stream.service_id}'. Value: '{avg}'")
            # In live event microservices we dispatch events:
            # event = ThreatThresholdExceededEvent(aggregate_id=stream.service_id, payload={"average": avg})
            # message_publisher.publish(event)
            return True
        return False
