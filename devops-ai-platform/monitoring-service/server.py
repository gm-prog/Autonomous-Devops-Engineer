import os

from fastapi import FastAPI, HTTPException, Query

from application.queries.get_live_metrics import (
    GetLiveMetricsQuery,
    GetLiveMetricsQueryHandler,
)
from application.services.threshold_event_service import create_threshold_event
from application.services.threshold_evaluator import ThresholdEvaluator
from infrastructure.messaging.redis_event_publisher import RedisStreamEventPublisher
from infrastructure.prometheus.scraper_client import PrometheusScraperClient


app = FastAPI(
    title="DevOps.AI Monitoring Service",
    version="1.4.0",
)

handler = GetLiveMetricsQueryHandler(
    PrometheusScraperClient(
        endpoint=os.getenv("PROMETHEUS_URL", "http://prometheus:9090"),
        timeout_seconds=float(os.getenv("PROMETHEUS_TIMEOUT_SECONDS", "5")),
    )
)
threshold_evaluator = ThresholdEvaluator()
event_publisher = RedisStreamEventPublisher()


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "monitoring-service",
        "prometheus_url": os.getenv("PROMETHEUS_URL", "http://prometheus:9090"),
        "event_stream": os.getenv("EVENT_BUS_STREAM", "devops:events"),
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
                "event": None,
                "event_delivery": None,
            }

        evaluation = threshold_evaluator.evaluate(metrics)
        event = create_threshold_event(service, metrics, evaluation)

        if event is None:
            return {
                "status": evaluation["status"],
                "service_id": service,
                "metrics": metrics,
                "evaluation": evaluation,
                "event": None,
                "event_delivery": None,
            }

        try:
            message_id = event_publisher.publish(event)
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail=f"Threshold event delivery failed: {type(exc).__name__}",
            ) from exc

        return {
            "status": evaluation["status"],
            "service_id": service,
            "metrics": metrics,
            "evaluation": evaluation,
            "event": event.to_dict(),
            "event_delivery": {
                "status": "PUBLISHED",
                "stream": event_publisher.stream_name,
                "message_id": message_id,
            },
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
