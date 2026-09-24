"""Bootable entrypoint for the agent swarm bounded context (port 8020)."""

import logging

from fastapi import FastAPI

from .presentation.rest.stream_controller import router as agent_streams_router

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="DevOps.AI Agent Service", version="1.0.0")
app.include_router(agent_streams_router)


@app.get("/health")
def health():
    return {"status": "healthy", "service": "agent-service"}
