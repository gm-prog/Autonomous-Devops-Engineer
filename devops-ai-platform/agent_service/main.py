"""Bootable entrypoint for the agent swarm bounded context (port 8020)."""

import logging

from fastapi import FastAPI

from .presentation.rest.rca_controller import router as rca_router
from .presentation.rest.stream_controller import router as agent_streams_router

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="DevOps.AI Agent Service", version="1.0.0")
app.include_router(agent_streams_router)
# Phase 8.4 §5: the internal RCA boundary the incident service calls
# (POST /api/internal/analyze-rca) — private-network only.
app.include_router(rca_router)


@app.get("/health")
def health():
    return {"status": "healthy", "service": "agent-service"}
