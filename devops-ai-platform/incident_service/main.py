"""Bootable entrypoint for the incident bounded context (port 8050).

Sentry webhook ingestion verifies an HMAC-SHA256 signature over the raw
request body when ``SENTRY_WEBHOOK_SECRET`` is configured (see
``presentation/rest/sentry_webhook_router.py``).
"""

import logging

from fastapi import FastAPI

from .presentation.rest.controllers import router as incidents_router
from .presentation.rest.sentry_webhook_router import router as webhooks_router

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="DevOps.AI Incident Service", version="1.0.0")
app.include_router(incidents_router)
app.include_router(webhooks_router)


@app.get("/health")
def health():
    return {"status": "healthy", "service": "incident-service"}
