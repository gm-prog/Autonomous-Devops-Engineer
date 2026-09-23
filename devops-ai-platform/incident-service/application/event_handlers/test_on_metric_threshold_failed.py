import unittest

from application.commands.ingest_webhook_alert import IngestWebhookAlertCommandHandler
from application.event_handlers.on_metric_threshold_failed import (
    OnMetricThresholdFailedHandler,
)


class FakeIncidentRepository:
    def __init__(self):
        self.saved = []

    def save_incident(self, incident):
        self.saved.append(incident)

    def get_incident_by_id(self, incident_id):
        return None

    def get_active_incidents(self):
        return []


class OnMetricThresholdFailedHandlerTests(unittest.TestCase):
    def test_threshold_event_becomes_triage_incident(self):
        repository = FakeIncidentRepository()
        handler = OnMetricThresholdFailedHandler(
            IngestWebhookAlertCommandHandler(repository)
        )

        event = {
            "event_id": "event-1",
            "aggregate_id": "gateway",
            "event_type": "ThreatThresholdExceededEvent",
            "timestamp": "2026-09-23T00:00:00+00:00",
            "payload": {
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
                "metrics": {"cpu_percent": 95.0},
            },
        }

        incident_id = handler.handle(event)

        self.assertEqual(len(repository.saved), 1)
        incident = repository.saved[0]
        self.assertEqual(incident.id, incident_id)
        self.assertEqual(
            incident.title,
            "[PROMETHEUS-ALERT] cpu_percent-threshold-breached",
        )
        self.assertEqual(incident.severity, "CRITICAL")
        self.assertEqual(incident.status, "Triage")
        self.assertIn("value=95.0", incident.context)
        self.assertEqual(
            incident.domain_events[0].to_dict()["event_type"],
            "OutOfBoundsIncidentLoggedEvent",
        )

    def test_sparse_event_uses_safe_defaults(self):
        repository = FakeIncidentRepository()
        handler = OnMetricThresholdFailedHandler(
            IngestWebhookAlertCommandHandler(repository)
        )

        handler.handle({
            "aggregate_id": "api",
            "payload": {"severity": "high", "breach_count": 1, "breaches": []},
        })

        incident = repository.saved[0]
        self.assertEqual(
            incident.title,
            "[PROMETHEUS-ALERT] unknown-threshold-breached",
        )
        self.assertEqual(incident.severity, "HIGH")
        self.assertIn("metric=unknown", incident.context)

    def test_missing_aggregate_id_is_rejected(self):
        repository = FakeIncidentRepository()
        handler = OnMetricThresholdFailedHandler(
            IngestWebhookAlertCommandHandler(repository)
        )

        with self.assertRaises(ValueError):
            handler.handle({"payload": {}})


if __name__ == "__main__":
    unittest.main()
