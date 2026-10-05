import json
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

    ``context`` optionally carries observation metadata; only the
    pre-existing envelope key ``metrics`` is passed through into the event
    payload (the incident consumer already reads it). Nothing in the
    context is ever interpreted as an instruction — it stays data.
    """
    def __init__(self, danger_percentage: float = 90.0, publisher: Optional[object] = None):
        self.danger_limit = danger_percentage
        self.publisher = publisher

    def evaluate_stream(
        self,
        stream: MetricStreamAggregate,
        context: Optional[dict] = None,
    ) -> bool:
        avg = stream.current_load_average()
        if avg > self.danger_limit:
            logger.warning(f"[ALARM] Alert! Danger threshold breached for service '{stream.service_id}'. Value: '{avg}'")
            self._publish_breach(stream, avg, context)
            return True
        return False

    def _publish_breach(
        self,
        stream: MetricStreamAggregate,
        avg: float,
        context: Optional[dict] = None,
    ) -> None:
        if self.publisher is None:
            return
        payload = {
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
        }
        # passthrough of an envelope key the consumer already understands
        if isinstance(context, dict) and isinstance(context.get("metrics"), dict):
            payload["metrics"] = context["metrics"]

        event = ThreatThresholdExceededEvent(
            aggregate_id=stream.service_id,
            payload=payload,
        )
        self.publisher.publish(event)
        # structured lifecycle marker (§observability): ids/status/numbers only
        logger.info(
            json.dumps(
                {
                    "event": "monitoring.threshold_exceeded",
                    "event_id": event.event_id,
                    "service": stream.service_id,
                    "metric": stream.metric_name,
                    "value": avg,
                    "threshold": self.danger_limit,
                    "correlation_id": event.event_id,
                }
            )
        )
