"""
Bootable entrypoint for the DevOps.AI Operator Platform gateway.

Run locally (from the devops-ai-platform/ directory):

    uvicorn api_gateway.main:app --host 0.0.0.0 --port 8000

Auth: mint a dev token with

    python -m api_gateway.core.auth devops-operator DevOpsLead

then call e.g.

    curl -H "Authorization: Bearer <token>" http://localhost:8000/v1/gateway/metrics
"""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .core.auth import GatewaySettings  # noqa: F401  (emits dev-secret warning)
from .routers.gateway_router import router as gateway_router

logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="DevOps.AI Operator Platform Gateway",
    description=(
        "BFF gateway in front of the autonomous DevOps platform services "
        "(repo / agent / deployment / monitoring / incident)."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    # wildcard origin + credentials is an invalid Fetch-spec combination;
    # browser clients are not part of this platform yet
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(gateway_router)


@app.get("/health")
def health():
    """Liveness probe for the gateway container."""
    return {"status": "healthy", "service": "api-gateway"}


@app.get("/")
def root():
    return {
        "service": "DevOps.AI Operator Platform Gateway",
        "docs": "/docs",
        "health": "/health",
        "auth": "Bearer HS256 JWT (mint with: python -m api_gateway.core.auth <sub> [roles...])",
    }
