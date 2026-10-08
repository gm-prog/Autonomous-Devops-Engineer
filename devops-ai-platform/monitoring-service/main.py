"""Monitoring service application factory (Phase 8.7-C).

Exposes the machine-authenticated telemetry ingestion boundary:

    POST /api/internal/telemetry/observations

Fail-closed: when ``TELEMETRY_HMAC_SECRET`` is not configured, ingestion
is disabled for every request (503) — the monitoring service never accepts
unsigned telemetry and never accepts human-JWT telemetry.

Run:

    uvicorn monitoring_service.main:app --host 0.0.0.0 --port 8040
"""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI

from .presentation.rest.telemetry_router import (
    TELEMETRY_SECRET_ENV,
    build_ingest_handler,
    router as telemetry_router,
)

logger = logging.getLogger("MonitoringMain")


def create_app(publisher=None, registry=None, validator=None) -> FastAPI:
    """Build the monitoring service app with injectable pipeline components.

    ``publisher`` is the event bus (e.g. shared-kernel
    ``DomainEventPublisher``) receiving ``ThreatThresholdExceededEvent``.
    """
    app = FastAPI(
        title="Monitoring Service",
        version="8.7-C",
        description="Telemetry ingestion for trusted producers only "
                    "(HMAC-SHA256 machine authentication).",
    )

    if not os.getenv(TELEMETRY_SECRET_ENV):
        logger.warning(
            "TELEMETRY_HMAC_SECRET is not configured: telemetry ingestion is "
            "DISABLED (fail closed). Configure the secret to enable the "
            "trusted producer boundary."
        )

    handler = build_ingest_handler(publisher=publisher, registry=registry,
                                   validator=validator)
    app.dependency_overrides[build_ingest_handler] = lambda: handler
    app.state.telemetry_handler = handler

    app.include_router(telemetry_router)
    return app


app = create_app()
