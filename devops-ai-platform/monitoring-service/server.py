import os

from fastapi import FastAPI, HTTPException, Query

from application.queries.get_live_metrics import (
    GetLiveMetricsQuery,
    GetLiveMetricsQueryHandler,
)
from application.services.threshold_evaluator import ThresholdEvaluator
from infrastructure.prometheus.scraper_client import PrometheusScraperClient


app = FastAPI(
    title="DevOps.AI Monitoring Service",
    version="1.2.0",
)

handler = GetLiveMetricsQueryHandler(
    PrometheusScraperClient(
        endpoint=os.getenv("PROMETHEUS_URL", "http://prometheus:9090"),
        timeout_seconds=float(os.getenv("PROMETHEUS_TIMEOUT_SECONDS", "5")),
    )
)
threshold_evaluator = ThresholdEvaluator()


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


@app.get("/api/internal/alerts/evaluate")
def evaluate_alerts(
    service: str = Query(..., min_length=1, max_length=255),
):
    try:
        metrics = handler.handle(GetLiveMetricsQuery(service))
        if metrics["status"] == "UNAVAILABLE":
            return {
                "status": "UNAVAILABLE",
                "service_id": service,
                "metrics": metrics,
                "evaluation": {
                    "status": "UNAVAILABLE",
                    "breaches": [],
                    "severity": None,
                    "breach_count": 0,
                },
            }

        evaluation = threshold_evaluator.evaluate(metrics)
        return {
            "status": evaluation["status"],
            "service_id": service,
            "metrics": metrics,
            "evaluation": evaluation,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
