import logging
from typing import Optional

from ...domain.aggregates.metric_stream import MetricStreamAggregate
from shared_kernel.domain.events import ThreatThresholdExceededEvent

logger = logging.getLogger("ThresholdValidator")

class ThresholdValidator:
    """Evaluates telemetry values to trigger failover or escalation flows.

    When a ``publisher`` is provided (Phase 6.1 wiring), a breach emits a
    ``ThreatThresholdExceededEvent`` onto the shared event bus — the exact
    event type the incident consumer consumes — so the monitoring →
    incident chain has a real producer. Without a publisher the validator
    keeps its original observe-and-return behaviour (tests and callers
    without Redis stay deterministic).
    """
    def __init__(self, danger_percentage: float = 90.0, publisher: Optional[object] = None):
        self.danger_limit = danger_percentage
        self.publisher = publisher

    def evaluate_stream(self, stream: MetricStreamAggregate) -> bool:
        avg = stream.current_load_average()
        if avg > self.danger_limit:
            logger.warning(f"[ALARM] Alert! Danger threshold breached for service '{stream.service_id}'. Value: '{avg}'")
            self._publish_breach(stream, avg)
            return True
        return False

    def _publish_breach(self, stream: MetricStreamAggregate, avg: float) -> None:
        if self.publisher is None:
            return
        event = ThreatThresholdExceededEvent(
            aggregate_id=stream.service_id,
            payload={
                "service": stream.service_id,
                "metric": stream.metric_name,
                "average": avg,
                "threshold": self.danger_limit,
                "breach_count": 1,
                "severity": "high",
                "breaches": [
                    {
                        "metric": stream.metric_name,
                        "value": avg,
                        "threshold": self.danger_limit,
                        "operator": ">",
                        "severity": "high",
                    }
                ],
            },
        )
        self.publisher.publish(event)
