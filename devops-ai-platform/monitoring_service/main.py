"""Bootable entrypoint for the monitoring bounded context (port 8040).

Composition root only (Phase 6.1): configuration + dependency assembly
live in ``application.dependencies``; this module wires routers and
delegates. ``POST /api/internal`` receives monitoring observations
(the target of the gateway's generic ``dispatch/monitoring`` proxy),
which the composed ``ThresholdMonitor`` evaluates through the existing
``ThresholdValidator`` — breaches publish ``ThreatThresholdExceededEvent``
onto ``devops:events`` for the incident consumer.
"""

import logging

from fastapi import FastAPI

from .presentation.sockets.ws_metrics_emitter import router as telemetry_router
from .presentation.rest.telemetry_controller import (
    register_validation_exception_handler,
    router as ingest_router,
)

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="DevOps.AI Monitoring Service", version="1.0.0")
register_validation_exception_handler(app)
app.include_router(telemetry_router)
app.include_router(ingest_router)


@app.get("/health")
def health():
    return {"status": "healthy", "service": "monitoring-service"}
