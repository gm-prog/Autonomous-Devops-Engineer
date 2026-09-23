"""Bootable entrypoint for the monitoring bounded context (port 8040)."""

import logging

from fastapi import FastAPI

from .presentation.sockets.ws_metrics_emitter import router as telemetry_router

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="DevOps.AI Monitoring Service", version="1.0.0")
app.include_router(telemetry_router)


@app.get("/health")
def health():
    return {"status": "healthy", "service": "monitoring-service"}
