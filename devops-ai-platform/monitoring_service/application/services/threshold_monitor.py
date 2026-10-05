"""Application service receiving monitoring threshold observations (Phase 6.1).

Presentation layers (internal HTTP ingestion) delegate here — this class
only turns an observation into the existing domain stream and hands it to
the already-composed :class:`ThresholdValidator`, which owns evaluation,
typed-event construction and publishing. No business logic lives in the
entrypoint; no business logic is duplicated here.

``metrics`` is an optional context passthrough (labels/deployment hints)
that travels into the event payload key the incident consumer already
reads (``payload.metrics``) — no new envelope fields are invented, and
anything carried is treated purely as data.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from monitoring_service.domain.aggregates.metric_stream import MetricStreamAggregate
from monitoring_service.domain.value_objects.metric_unit import MetricUnit


class ThresholdMonitor:
    """Observe → evaluate → (publish on breach) via the existing validator."""

    def __init__(self, validator):
        self.validator = validator

    def observe(
        self,
        *,
        service_id: str,
        metric_name: str,
        value: float,
        unit: Optional[str] = None,
        metrics: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        stream = MetricStreamAggregate(
            service_id=service_id,
            metric_name=metric_name,
            unit=MetricUnit(symbol=unit or "%", description=unit or "percent"),
        )
        stream.record_value(float(value))
        context = {"metrics": metrics} if metrics else None
        breached = self.validator.evaluate_stream(stream, context=context)
        return {
            "breached": bool(breached),
            "published": bool(breached),
            "service": service_id,
            "metric": metric_name,
            "value": float(value),
            "threshold": self.validator.danger_limit,
        }
