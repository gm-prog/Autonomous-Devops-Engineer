from __future__ import annotations

import json
import logging
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

logger = logging.getLogger("PrometheusScraper")


class PrometheusScraperError(RuntimeError):
    """Base error raised when a Prometheus query cannot be completed."""


class PrometheusScraperClient:
    """Small, dependency-free adapter for the Prometheus HTTP API."""

    def __init__(self, endpoint: str = "http://prometheus:9090", timeout_seconds: float = 5.0):
        if not endpoint.strip():
            raise ValueError("Prometheus endpoint must not be empty")
        if timeout_seconds <= 0:
            raise ValueError("Prometheus timeout must be greater than zero")

        self.endpoint = endpoint.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def query_instant_metric(self, prom_statement: str) -> dict[str, Any]:
        """Execute an instant PromQL query through Prometheus /api/v1/query."""
        if not prom_statement.strip():
            raise ValueError("PromQL statement must not be empty")

        endpoint = self._normalize_endpoint(self.endpoint)
        url = f"{endpoint}/api/v1/query?{urlencode({'query': prom_statement})}"

        logger.info("Issuing PromQL query to Prometheus endpoint: %s", endpoint)

        request = Request(
            url,
            headers={"Accept": "application/json"},
            method="GET",
        )

        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                status_code = getattr(response, "status", None)
                if status_code is None:
                    status_code = response.getcode()
                if status_code < 200 or status_code >= 300:
                    raise PrometheusScraperError(
                        f"Prometheus returned unexpected HTTP status {status_code}"
                    )
                raw_body = response.read()
        except HTTPError as exc:
            raise PrometheusScraperError(
                f"Prometheus HTTP request failed with status {exc.code}"
            ) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise PrometheusScraperError(
                "Unable to reach Prometheus"
            ) from exc

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PrometheusScraperError("Prometheus returned invalid JSON") from exc

        if not isinstance(payload, dict):
            raise PrometheusScraperError("Prometheus response must be a JSON object")

        if payload.get("status") != "success":
            error_type = payload.get("errorType", "unknown")
            error_message = payload.get("error", "Prometheus query failed")
            raise PrometheusScraperError(
                f"Prometheus query failed ({error_type}): {error_message}"
            )

        return payload

    @staticmethod
    def _normalize_endpoint(endpoint: str) -> str:
        """Accept both 'prometheus:9090' and fully-qualified HTTP URLs."""
        parsed = urlsplit(endpoint if "://" in endpoint else f"http://{endpoint}")
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Prometheus endpoint must use http or https")
        if not parsed.netloc:
            raise ValueError("Prometheus endpoint must include a host")
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"
