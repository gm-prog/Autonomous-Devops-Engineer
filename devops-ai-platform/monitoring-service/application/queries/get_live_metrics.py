from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from infrastructure.prometheus.scraper_client import (
    PrometheusScraperClient,
    PrometheusScraperError,
)


class GetLiveMetricsQuery:
    def __init__(self, target_service: str):
        if not target_service.strip():
            raise ValueError("target_service must not be empty")
        self.target_service = target_service.strip()


class GetLiveMetricsQueryHandler:
    """Read live service telemetry from Prometheus and normalize it for the API/UI."""

    def __init__(self, prometheus: PrometheusScraperClient | None = None):
        self.prometheus = prometheus or PrometheusScraperClient()

    def _query(self, expression: str) -> float:
        payload = self.prometheus.query_instant_metric(expression)
        results = payload.get("data", {}).get("result", [])
        if not results:
            raise PrometheusScraperError("Prometheus returned no samples for a required metric")
        first = results[0]
        raw_value = first.get("value")
        if not isinstance(raw_value, list) or len(raw_value) < 2:
            raise PrometheusScraperError("Prometheus returned an invalid instant-vector sample")
        try:
            return float(raw_value[1])
        except (TypeError, ValueError) as exc:
            raise PrometheusScraperError("Prometheus returned a non-numeric metric value") from exc

    @staticmethod
    def _queries(service: str) -> Dict[str, str]:
        safe = service.replace("\\", "\\\\").replace('"', '\\\"')
        return {
            "latency_ms": (
                f'1000 * histogram_quantile(0.95, '
                f'sum(rate(http_request_duration_seconds_bucket{{service="{safe}"}}[5m])) by (le))'
            ),
            "cpu_percent": (
                f'avg(100 * (1 - rate(process_cpu_seconds_total{{service="{safe}"}}[5m]))) * 100'
            ),
            "memory_usage_mib": (
                f'sum(process_resident_memory_bytes{{service="{safe}"}}) / 1024 / 1024'
            ),
            "rps": f'sum(rate(http_requests_total{{service="{safe}"}}[5m]))',
        }

    def handle(self, q: GetLiveMetricsQuery) -> Dict[str, Any]:
        queries = self._queries(q.target_service)
        metrics: Dict[str, float] = {}
        errors: Dict[str, str] = {}

        for name, expression in queries.items():
            try:
                metrics[name] = self._query(expression)
            except PrometheusScraperError as exc:
                errors[name] = str(exc)

        now = datetime.now(timezone.utc).isoformat()
        timeline = [
            {
                "index": 0,
                "value": metrics["latency_ms"],
                "timestamp": now,
            }
        ] if "latency_ms" in metrics else []

        result: Dict[str, Any] = {
            "service_id": q.target_service,
            "source": "prometheus",
            "timestamp": now,
            "latency_ms": metrics.get("latency_ms"),
            "cpu_percent": metrics.get("cpu_percent"),
            "memory_usage_mib": metrics.get("memory_usage_mib"),
            "rps": metrics.get("rps"),
            "timeline_data": timeline,
            "metrics_available": len(metrics),
            "metric_errors": errors,
        }

        if len(errors) == len(queries):
            result["status"] = "UNAVAILABLE"
        elif errors:
            result["status"] = "DEGRADED"
        else:
            result["status"] = "LIVE"

        return result
