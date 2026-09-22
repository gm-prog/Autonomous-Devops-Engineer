import unittest

from application.services.threshold_event_service import create_threshold_event


class ThresholdEventServiceTests(unittest.TestCase):
    def test_no_event_is_created_when_metrics_are_ok(self):
        event = create_threshold_event(
            "gateway",
            {"cpu_percent": 40.0},
            {"status": "OK", "breaches": [], "severity": None, "breach_count": 0},
        )

        self.assertIsNone(event)

    def test_breach_creates_serializable_domain_event(self):
        event = create_threshold_event(
            "gateway",
            {
                "cpu_percent": 95.0,
                "latency_ms": 1200.0,
                "memory_usage_mib": 512.0,
                "rps": 12.0,
            },
            {
                "status": "BREACHED",
                "severity": "critical",
                "breach_count": 1,
                "breaches": [
                    {
                        "metric": "cpu_percent",
                        "value": 95.0,
                        "threshold": 90.0,
                        "operator": ">=",
                        "severity": "critical",
                    }
                ],
            },
        )

        payload = event.to_dict()

        self.assertEqual(payload["event_type"], "ThreatThresholdExceededEvent")
        self.assertEqual(payload["aggregate_id"], "gateway")
        self.assertEqual(payload["payload"]["severity"], "critical")
        self.assertEqual(payload["payload"]["breaches"][0]["metric"], "cpu_percent")
        self.assertTrue(payload["event_id"])
        self.assertTrue(payload["timestamp"])

    def test_event_contains_only_normalized_metric_fields(self):
        event = create_threshold_event(
            "gateway",
            {"cpu_percent": 95.0, "internal_secret": "do-not-export"},
            {
                "status": "BREACHED",
                "severity": "critical",
                "breach_count": 1,
                "breaches": [],
            },
        )

        self.assertNotIn("internal_secret", event.to_dict()["payload"]["metrics"])


if __name__ == "__main__":
    unittest.main()
