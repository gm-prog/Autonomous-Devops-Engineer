"""Machine-authenticated telemetry ingestion boundary (Phase 8.7-C).

Endpoint
========

    POST /api/internal/telemetry/observations

This is the ONLY accepted path for telemetry ingestion into the monitoring
service, and it accepts **machine credentials only**:

* Authentication is an HMAC-SHA256 shared-secret envelope
  (``X-Telemetry-Signature`` / ``X-Telemetry-Timestamp`` / ``X-Telemetry-Nonce``)
  verified against ``TELEMETRY_HMAC_SECRET``.
* Human JWTs are NOT an accepted credential on this boundary.  A bearer
  token (Developer, operator, DevOpsLead, ClusterAdmin — any role) provides
  no telemetry producer authority here; presenting one is simply a missing
  HMAC envelope and is rejected.
* If ``TELEMETRY_HMAC_SECRET`` is not configured the endpoint fails closed
  (503) for every request.
* Rejected requests produce NO downstream side effect: no metric datapoint
  is recorded and no threshold event is published.  Authentication runs
  before any domain state is touched.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ...application.commands.ingest_telemetry_observation import (
    IngestTelemetryObservationCommand,
    IngestTelemetryObservationCommandHandler,
)
from ...security.telemetry_auth import (
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    NonceStore,
    TelemetryAuthenticationError,
    verify_telemetry_signature,
)

logger = logging.getLogger("TelemetryRouter")

router = APIRouter(prefix="/api/internal/telemetry", tags=["Trusted Telemetry Ingestion"])

# Producer secret is resolved per-app at startup (fail closed when absent).
TELEMETRY_SECRET_ENV = "TELEMETRY_HMAC_SECRET"

_nonce_store = NonceStore()


class TelemetryObservationPayload(BaseModel):
    """Typed telemetry observation body (no free-form relay surface)."""

    service_id: str = Field(min_length=1, max_length=200)
    metric_name: str = Field(min_length=1, max_length=200)
    value: float = Field(ge=-1e9, le=1e9)
    unit: str = Field(default="percent", max_length=16)
    producer_id: str = Field(default="unknown-producer", max_length=200)


def get_producer_secret() -> Optional[str]:
    """The configured trusted-producer secret (None -> ingestion disabled)."""
    return os.getenv(TELEMETRY_SECRET_ENV) or None


async def authenticate_trusted_producer(request: Request) -> str:
    """Dependency: verify the HMAC producer envelope before any payload use.

    Returns the producer_id once authenticated.  Raises HTTPException on any
    failure; the request body is never parsed by the handler on rejection.
    """
    secret = get_producer_secret()
    raw_body = await request.body()
    try:
        verify_telemetry_signature(
            secret=secret,
            method=request.method,
            path=request.url.path,
            raw_body=raw_body,
            signature_header=request.headers.get(HEADER_SIGNATURE),
            timestamp_header=request.headers.get(HEADER_TIMESTAMP),
            nonce_header=request.headers.get(HEADER_NONCE),
            nonce_store=_nonce_store,
        )
    except TelemetryAuthenticationError as exc:
        # Log the failure without secret material or body content.
        logger.warning("Rejected unauthenticated telemetry request: %s", exc.reason)
        raise HTTPException(status_code=exc.status_code, detail=exc.reason) from exc
    return "hmac-producer"


def build_ingest_handler(publisher=None, registry=None, validator=None) -> IngestTelemetryObservationCommandHandler:
    """Factory for dependency injection (tests wire spies here)."""
    from ...application.commands.ingest_telemetry_observation import (
        MetricStreamRegistry,
    )

    return IngestTelemetryObservationCommandHandler(
        registry=registry or MetricStreamRegistry(),
        validator=validator,
        publisher=publisher,
    )


@router.post("/observations")
def ingest_telemetry_observation(
    payload: TelemetryObservationPayload,
    producer: str = Depends(authenticate_trusted_producer),
    handler: IngestTelemetryObservationCommandHandler = Depends(build_ingest_handler),
):
    """Ingest one telemetry observation from a trusted, HMAC-authenticated producer."""
    cmd = IngestTelemetryObservationCommand(
        service_id=payload.service_id,
        metric_name=payload.metric_name,
        value=payload.value,
        unit=payload.unit,
        producer_id=payload.producer_id,
    )
    result = handler.handle(cmd)
    return {
        "status": "ACCEPTED",
        "authenticated_as": producer,
        "service_id": result["service_id"],
        "metric_name": result["metric_name"],
        "current_average": result["current_average"],
        "threshold_breached": result["threshold_breached"],
        "event_id": result["event"].event_id if result["event"] else None,
    }
