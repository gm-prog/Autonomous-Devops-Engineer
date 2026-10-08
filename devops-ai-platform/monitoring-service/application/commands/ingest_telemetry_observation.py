"""Telemetry observation ingestion — application layer (Phase 8.7-C).

Pipeline (only ever reached AFTER machine authentication has passed):

    TelemetryObservation (authenticated payload)
        -> MetricStreamAggregate.record_value
        -> ThresholdValidator.evaluate_stream
        -> ThreatThresholdExceededEvent (only on breach)
        -> publisher.publish (Redis / event bus -> incident ingestion)

Rejected telemetry never reaches this layer: the presentation boundary
enforces HMAC producer authentication before any domain state is touched, so
a rejected request can produce no datapoint and no downstream incident.
"""

from __future__ import annotations

import logging
from typing import Dict, Optional

from ....shared_kernel.domain.events import ThreatThresholdExceededEvent
from ...domain.aggregates.metric_stream import MetricStreamAggregate
from ...domain.value_objects.metric_unit import MetricUnit
from ...security.telemetry_auth import NonceStore  # noqa: F401  (re-export for DI)
from ..services.threshold_validator import ThresholdValidator

logger = logging.getLogger("IngestTelemetryObservation")

# Default unit catalog for the platform's primary telemetry metrics.
KNOWN_METRIC_UNITS: Dict[str, MetricUnit] = {
    "percent": MetricUnit(symbol="%", description="Percentage (0-100)"),
    "ms": MetricUnit(symbol="ms", description="Milliseconds"),
    "mib": MetricUnit(symbol="MiB", description="Mebibytes"),
    "rps": MetricUnit(symbol="rps", description="Requests per second"),
    "count": MetricUnit(symbol="", description="Raw count"),
}

DEFAULT_DANGER_PERCENTAGE = 90.0


class MetricStreamRegistry:
    """Process-local registry of active metric streams (bounded)."""

    def __init__(self, max_streams: int = 256):
        self._streams: Dict[tuple, MetricStreamAggregate] = {}
        self._max_streams = max_streams

    def get_or_create(self, service_id: str, metric_name: str,
                      unit: MetricUnit) -> MetricStreamAggregate:
        key = (service_id, metric_name)
        stream = self._streams.get(key)
        if stream is None:
            if len(self._streams) >= self._max_streams:
                # Evict the oldest inserted stream (insertion order).
                self._streams.pop(next(iter(self._streams)))
            stream = MetricStreamAggregate(service_id=service_id,
                                           metric_name=metric_name,
                                           unit=unit)
            self._streams[key] = stream
        return stream


class IngestTelemetryObservationCommand:
    """A single authenticated telemetry observation from a trusted producer."""

    def __init__(self, service_id: str, metric_name: str, value: float,
                 unit: str = "percent", producer_id: str = "unknown-producer"):
        self.service_id = service_id
        self.metric_name = metric_name
        self.value = value
        self.unit = unit
        self.producer_id = producer_id


class IngestTelemetryObservationCommandHandler:
    """Applies an authenticated observation to the monitoring pipeline."""

    def __init__(self, registry: Optional[MetricStreamRegistry] = None,
                 validator: Optional[ThresholdValidator] = None,
                 publisher=None):
        self.registry = registry or MetricStreamRegistry()
        self.validator = validator or ThresholdValidator(danger_percentage=DEFAULT_DANGER_PERCENTAGE)
        self.publisher = publisher  # DomainEventPublisher (or compatible)

    def handle(self, cmd: IngestTelemetryObservationCommand) -> Dict:
        unit = KNOWN_METRIC_UNITS.get(cmd.unit.lower(),
                                      KNOWN_METRIC_UNITS["count"])
        stream = self.registry.get_or_create(cmd.service_id, cmd.metric_name, unit)
        stream.record_value(float(cmd.value))

        breached = self.validator.evaluate_stream(stream)
        event: Optional[ThreatThresholdExceededEvent] = None
        if breached:
            event = ThreatThresholdExceededEvent(
                aggregate_id=cmd.service_id,
                payload={
                    "service_id": cmd.service_id,
                    "metric_name": cmd.metric_name,
                    "average": stream.current_load_average(),
                    "danger_limit": self.validator.danger_limit,
                    "unit": unit.symbol or "count",
                    "producer_id": cmd.producer_id,
                },
            )
            if self.publisher is not None:
                self.publisher.publish(event)
            else:
                logger.warning(
                    "Threshold breached for %s but no publisher is wired; event held.",
                    cmd.service_id,
                )

        return {
            "service_id": cmd.service_id,
            "metric_name": cmd.metric_name,
            "recorded_value": float(cmd.value),
            "current_average": stream.current_load_average(),
            "threshold_breached": breached,
            "event": event,
        }
