import unittest

from infrastructure.prometheus.scraper_client import PrometheusScraperError
from application.queries.get_live_metrics import GetLiveMetricsQuery, GetLiveMetricsQueryHandler


class FakePrometheus:
    def __init__(self, failures=None):
        self.failures = set(failures or [])
        self.queries = []

    def query_instant_metric(self, expression):
        self.queries.append(expression)
        for name, marker in {
            "latency_ms": "histogram_quantile",
            "cpu_percent": "process_cpu_seconds_total",
            "memory_usage_mib": "process_resident_memory_bytes",
            "rps": "http_requests_total",
        }.items():
            if marker in expression:
                if name in self.failures:
                    raise PrometheusScraperError(f"{name} unavailable")
                values = {
                    "latency_ms": "128.5",
                    "cpu_percent": "42.0",
                    "memory_usage_mib": "256.25",
                    "rps": "18.5",
                }
                return {
                    "status": "success",
                    "data": {
                        "resultType": "vector",
                        "result": [{"metric": {"service": "api"}, "value": [1727000000.0, values[name]]}],
                    },
                }
        raise AssertionError("unexpected PromQL expression")


class LiveMetricsHandlerTests(unittest.TestCase):
    def test_handler_normalizes_live_prometheus_values(self):
        prometheus = FakePrometheus()
        result = GetLiveMetricsQueryHandler(prometheus).handle(
            GetLiveMetricsQuery("api")
        )

        self.assertEqual(result["status"], "LIVE")
        self.assertEqual(result["source"], "prometheus")
        self.assertEqual(result["latency_ms"], 128.5)
        self.assertEqual(result["cpu_percent"], 42.0)
        self.assertEqual(result["memory_usage_mib"], 256.25)
        self.assertEqual(result["rps"], 18.5)
        self.assertEqual(result["metrics_available"], 4)
        self.assertEqual(result["metric_errors"], {})
        self.assertEqual(len(prometheus.queries), 4)

    def test_handler_survives_partial_metric_failure(self):
        result = GetLiveMetricsQueryHandler(
            FakePrometheus(failures={"rps"})
        ).handle(GetLiveMetricsQuery("api"))

        self.assertEqual(result["status"], "DEGRADED")
        self.assertEqual(result["metrics_available"], 3)
        self.assertIn("rps", result["metric_errors"])

    def test_handler_reports_total_prometheus_failure(self):
        result = GetLiveMetricsQueryHandler(
            FakePrometheus(failures={"latency_ms", "cpu_percent", "memory_usage_mib", "rps"})
        ).handle(GetLiveMetricsQuery("api"))

        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertEqual(result["metrics_available"], 0)
        self.assertEqual(len(result["metric_errors"]), 4)

    def test_empty_service_is_rejected(self):
        with self.assertRaises(ValueError):
            GetLiveMetricsQuery(" ")
