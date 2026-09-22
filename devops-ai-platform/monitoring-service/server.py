import os

from fastapi import FastAPI, HTTPException, Query

from application.queries.get_live_metrics import (
    GetLiveMetricsQuery,
    GetLiveMetricsQueryHandler,
)
from infrastructure.prometheus.scraper_client import PrometheusScraperClient


app = FastAPI(
    title="DevOps.AI Monitoring Service",
    version="1.1.0",
)

handler = GetLiveMetricsQueryHandler(
    PrometheusScraperClient(
        endpoint=os.getenv("PROMETHEUS_URL", "http://prometheus:9090"),
        timeout_seconds=float(os.getenv("PROMETHEUS_TIMEOUT_SECONDS", "5")),
    )
)


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "monitoring-service",
        "prometheus_url": os.getenv("PROMETHEUS_URL", "http://prometheus:9090"),
    }


@app.get("/api/internal/metrics/live")
def get_live_metrics(
    service: str = Query(..., min_length=1, max_length=255),
):
    try:
        return handler.handle(GetLiveMetricsQuery(service))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
