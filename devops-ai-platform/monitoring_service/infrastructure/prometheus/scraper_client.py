import http.client
import json
import logging
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Tuple
from urllib.parse import urlencode

logger = logging.getLogger("PrometheusScraper")

# --- Phase 6.5 bounded range-query contract (fixed constants; never caller-tuned) ---
QUERY_TIMEOUT_SECONDS = 5.0
MAX_RANGE_DAYS = 31
MAX_RANGE_POINTS = 500
MAX_RESPONSE_SAMPLES = 10_000

#: Predefined query templates — the only PromQL this client will ever run
#: (Phase 6.5: no arbitrary user-supplied PromQL). Each template groups by
#: the authoritative release-identity labels so attribution survives
#: aggregation: ``deployment_id`` (exact deployment run id) and
#: ``source_sha`` (exact 40-hex source SHA). Both metric names are backed
#: by real telemetry in this repository: ``devops_api_requests_total`` is
#: instrumented in backend/app/main.py and scraped via
#: monitoring/prometheus.yml; ``process_cpu_seconds_total`` is exposed by
#: the default prometheus_client process collector on every scrape target.
_RANGE_TEMPLATES: Dict[str, str] = {
    "request_rate": (
        "sum by (job, deployment_id, source_sha) "
        "(rate(devops_api_requests_total[5m]))"
    ),
    "cpu_saturation": (
        "avg by (job, deployment_id, source_sha) "
        "(rate(process_cpu_seconds_total[2m]))"
    ),
}


class PrometheusQueryError(Exception):
    """Base fail-closed signal for the bounded range query."""


class PrometheusUnavailableError(PrometheusQueryError):
    """Prometheus unreachable, timed out, or answered non-200."""


class PrometheusMalformedResponseError(PrometheusQueryError):
    """Response body violates the expected matrix envelope."""


class PrometheusUnsupportedError(PrometheusQueryError):
    """Unknown template name or a result type this client does not model."""


@dataclass(frozen=True)
class RangeSample:
    """One (unix timestamp, value) point of a range series."""

    timestamp: float
    value: float


@dataclass(frozen=True)
class RangeSeries:
    """Typed series: identity-bearing labels + bounded sample tuple."""

    labels: Dict[str, str]
    samples: Tuple[RangeSample, ...]


@dataclass(frozen=True)
class RangeQueryResult:
    """Deterministic typed result of one predefined range query."""

    template: str
    query: str
    start: float
    end: float
    step_seconds: int
    series: Tuple[RangeSeries, ...]


def _unix(value: datetime) -> float:
    """Aware/naive (naive = UTC) datetime -> unix seconds."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).timestamp()


class PrometheusScraperClient:
    """Interfaces with the physical Prometheus HTTP API to query active container groups."""
    def __init__(self, endpoint: str = "prometheus:9090"):
        self.endpoint = endpoint

    def query_instant_metric(self, prom_statement: str) -> dict:
        logger.info(f"Issuing immediate PromQL string: {prom_statement} to endpoint: {self.endpoint}")
        # Returns typical Prometheus JSON matrix response payloads
        return {
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [
                    {
                        "metric": {"__name__": "http_requests_total", "job": "api-gateway"},
                        "value": [1781722858, "124.5"]
                    }
                ]
            }
        }

    # ---- Phase 6.5: bounded, read-only, template-only range query ---- #

    @staticmethod
    def template_names() -> Tuple[str, ...]:
        """The complete fixed template catalog (no other queries exist)."""
        return tuple(_RANGE_TEMPLATES)

    @staticmethod
    def compute_step_seconds(start: datetime, end: datetime) -> int:
        """Deterministic step: cover the window with <= MAX_RANGE_POINTS,
        never below 60s, always a whole number of minutes."""
        span = max(_unix(end) - _unix(start), 1.0)
        step = max(60, math.ceil(span / MAX_RANGE_POINTS))
        return ((step + 59) // 60) * 60

    def query_range_metric(
        self, template_name: str, start: datetime, end: datetime
    ) -> RangeQueryResult:
        """Run one predefined template over a bounded window.

        Fail-closed: fixed timeout, bounded lookback and sample count,
        unsupported template/result types and malformed bodies raise —
        never partial or fabricated data. Read-only GET.
        """
        if template_name not in _RANGE_TEMPLATES:
            raise PrometheusUnsupportedError(
                f"unknown query template '{template_name}'"
            )
        start_unix = _unix(start)
        end_unix = _unix(end)
        if end_unix <= start_unix:
            raise PrometheusQueryError("range query window must be non-empty")
        if (end_unix - start_unix) > MAX_RANGE_DAYS * 86400:
            raise PrometheusQueryError(
                f"range query window exceeds {MAX_RANGE_DAYS} days"
            )
        step_seconds = self.compute_step_seconds(start, end)
        query = _RANGE_TEMPLATES[template_name]
        params = urlencode(
            {
                "query": query,
                "start": f"{start_unix:.3f}",
                "end": f"{end_unix:.3f}",
                "step": str(step_seconds),
            }
        )
        body = self._get(f"/api/v1/query_range?{params}")
        return self._parse_matrix(
            template_name=template_name,
            query=query,
            start=start_unix,
            end=end_unix,
            step_seconds=step_seconds,
            body=body,
        )

    def _get(self, path: str) -> bytes:
        """GET against the configured endpoint with the fixed timeout."""
        host, _, port_text = self.endpoint.partition(":")
        port = int(port_text) if port_text.isdigit() else 80
        connection = http.client.HTTPConnection(
            host, port, timeout=QUERY_TIMEOUT_SECONDS
        )
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            if response.status != 200:
                raise PrometheusUnavailableError(
                    f"Prometheus answered HTTP {response.status}"
                )
            return response.read()
        except PrometheusUnavailableError:
            raise
        except (OSError, http.client.HTTPException) as exc:
            raise PrometheusUnavailableError(
                f"Prometheus unreachable: {exc.__class__.__name__}"
            ) from exc
        finally:
            connection.close()

    @staticmethod
    def _parse_matrix(
        *,
        template_name: str,
        query: str,
        start: float,
        end: float,
        step_seconds: int,
        body: bytes,
    ) -> RangeQueryResult:
        try:
            payload = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise PrometheusMalformedResponseError(
                "Prometheus response is not valid JSON"
            ) from exc
        if not isinstance(payload, dict) or payload.get("status") != "success":
            raise PrometheusMalformedResponseError(
                "Prometheus response envelope must be status=success"
            )
        data = payload.get("data")
        if not isinstance(data, dict):
            raise PrometheusMalformedResponseError("missing data object")
        result_type = data.get("resultType")
        if result_type != "matrix":
            raise PrometheusUnsupportedError(
                f"unsupported resultType '{result_type}'"
            )
        result = data.get("result")
        if not isinstance(result, list):
            raise PrometheusMalformedResponseError("result must be a list")

        series_list = []
        sample_total = 0
        for entry in result:
            if not isinstance(entry, dict):
                raise PrometheusMalformedResponseError("series must be an object")
            raw_labels = entry.get("metric")
            if not isinstance(raw_labels, dict):
                raise PrometheusMalformedResponseError("series metric must be an object")
            labels = {str(key): str(value) for key, value in raw_labels.items()}
            raw_values = entry.get("values")
            if not isinstance(raw_values, list):
                raise PrometheusMalformedResponseError("series values must be a list")
            samples = []
            for point in raw_values:
                if not isinstance(point, (list, tuple)) or len(point) != 2:
                    raise PrometheusMalformedResponseError("sample must be [ts, value]")
                try:
                    timestamp = float(point[0])
                    value = float(point[1])
                except (TypeError, ValueError) as exc:
                    raise PrometheusMalformedResponseError(
                        "sample fields must be numeric"
                    ) from exc
                if not (math.isfinite(timestamp) and math.isfinite(value)):
                    raise PrometheusMalformedResponseError(
                        "sample fields must be finite"
                    )
                sample_total += 1
                if sample_total > MAX_RESPONSE_SAMPLES:
                    raise PrometheusMalformedResponseError(
                        f"response exceeds {MAX_RESPONSE_SAMPLES} samples"
                    )
                samples.append(RangeSample(timestamp=timestamp, value=value))
            series_list.append(
                RangeSeries(labels=labels, samples=tuple(samples))
            )
        return RangeQueryResult(
            template=template_name,
            query=query,
            start=start,
            end=end,
            step_seconds=step_seconds,
            series=tuple(series_list),
        )
