"""Bootable entrypoint for the repository bounded context (port 8010)."""

import logging

from fastapi import FastAPI

from .presentation.rest.controllers import router as repositories_router

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="DevOps.AI Repo Service", version="1.0.0")
app.include_router(repositories_router)


@app.get("/health")
def health():
    return {"status": "healthy", "service": "repo-service"}
