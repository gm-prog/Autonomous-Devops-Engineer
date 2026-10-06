"""Internal telemetry ingestion (Phase 6.1 runtime input surface).

Completes the gateway dispatch contract: ``POST /v1/gateway/dispatch/
monitoring`` forwards to ``http://monitoring-service:8040/api/internal``
with the envelope ``{"payload": <observation>, "forwarded_by": <jwt sub>}``
— this router receives exactly that shape. The route validates input and
delegates to the composed :class:`ThresholdMonitor`; evaluation, typed
event construction and publishing live in the application layer.

External text in observation fields (service names, metric labels,
``metrics`` context) is untrusted data only: it is bounded by the schema,
carried verbatim into the event payload, and never interpreted as an
instruction or command by this service.
"""

import math
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from monitoring_service.application.dependencies import get_threshold_monitor
from monitoring_service.application.services.threshold_monitor import (
    ThresholdMonitor,
)

router = APIRouter(prefix="/api/internal", tags=["Internal Telemetry"])


def _sanitize(obj: Any) -> Any:
    """Replace non-finite floats with their string form so malformed input
    serializes into a clean 422 body (raw NaN/Infinity in error echoes
    crash Starlette's JSON encoder)."""
    if isinstance(obj, float) and not math.isfinite(obj):
        return str(obj)
    if isinstance(obj, dict):
        return {key: _sanitize(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [_sanitize(item) for item in obj]
    return obj


def register_validation_exception_handler(app) -> None:
    """422 body sanitizer for malformed observations (presentation wiring)."""

    async def sanitized_request_validation(
        request, exc: RequestValidationError
    ):
        return JSONResponse(
            status_code=422,
            content={"detail": _sanitize(exc.errors())},
        )

    app.add_exception_handler(RequestValidationError, sanitized_request_validation)


class TelemetryObservation(BaseModel):
    """One monitoring observation (service/workload + metric reading)."""

    service: str = Field(min_length=1, max_length=200)
    metric: str = Field(min_length=1, max_length=200)
    value: float = Field(allow_inf_nan=False)
    unit: Optional[str] = Field(default=None, max_length=32)
    metrics: Optional[Dict[str, Any]] = None


class DispatchEnvelope(BaseModel):
    """Envelope produced by the gateway's generic dispatch proxy."""

    payload: TelemetryObservation
    forwarded_by: Optional[str] = Field(default=None, max_length=200)


@router.post("", response_model=Dict[str, Any])
def observe_telemetry(
    envelope: DispatchEnvelope,
    monitor: ThresholdMonitor = Depends(get_threshold_monitor),
):
    """Evaluate one observation; breaches publish through the event bus."""
    observation = envelope.payload
    try:
        return monitor.observe(
            service_id=observation.service,
            metric_name=observation.metric,
            value=observation.value,
            unit=observation.unit,
            metrics=observation.metrics,
        )
    except Exception as exc:  # event bus unavailable → explicit failure
        raise HTTPException(
            status_code=503,
            detail="Monitoring event bus is unavailable; observation not published",
        ) from exc
