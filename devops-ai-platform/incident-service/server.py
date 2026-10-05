from fastapi import FastAPI

from presentation.rest.controllers import router as incidents_router
from presentation.rest.sentry_webhook_router import router as sentry_router


app = FastAPI(title="DevOps.AI Incident Service")

app.include_router(incidents_router, prefix="/api/internal")
app.include_router(sentry_router, prefix="/api/internal")


@app.get("/health")
def health():
    return {"status": "ok", "service": "incident-service"}
