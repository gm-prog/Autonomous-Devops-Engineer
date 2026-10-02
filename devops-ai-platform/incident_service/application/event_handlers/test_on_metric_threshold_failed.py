import unittest

from incident_service.application.commands.ingest_webhook_alert import IngestWebhookAlertCommandHandler
from incident_service.application.event_handlers.on_metric_threshold_failed import (
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
        self.assertEqual(len(incident.evidence), 1)
        self.assertEqual(incident.evidence[0].kind, "threshold_breach")
        self.assertEqual(incident.evidence[0].source, "monitoring-service")
        self.assertEqual(incident.evidence[0].payload["metric"], "cpu_percent")
        self.assertEqual(incident.evidence[0].payload["value"], 95.0)
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



    def test_redelivered_event_is_idempotent(self):
        class StatefulRepo:
            def __init__(self):
                self.store = {}
                self.saved = []

            def save_incident(self, incident):
                self.store[incident.id] = incident
                self.saved.append(incident)

            def get_incident_by_id(self, incident_id):
                return self.store.get(incident_id)

            def get_active_incidents(self):
                return list(self.store.values())

        def build_event(event_id):
            return {
                "event_id": event_id,
                "aggregate_id": "gateway",
                "event_type": "ThreatThresholdExceededEvent",
                "timestamp": "2026-09-23T00:00:00+00:00",
                "payload": {
                    "breaches": [
                        {
                            "metric": "cpu_percent",
                            "value": 95.0,
                            "threshold": 90.0,
                            "operator": ">=",
                            "severity": "high",
                        }
                    ]
                },
            }

        repository = StatefulRepo()
        handler = OnMetricThresholdFailedHandler(
            IngestWebhookAlertCommandHandler(repository)
        )

        first = handler.handle(build_event("evt-redeliver"))
        second = handler.handle(build_event("evt-redeliver"))

        self.assertEqual(first, second)
        self.assertEqual(len(repository.store), 1)
        self.assertEqual(len(repository.saved), 1)
        incident = repository.store[first]
        # deterministic evidence id → attach_evidence never duplicates (§4)
        self.assertEqual(len(incident.evidence), 1)
        self.assertEqual(
            incident.evidence[0].payload["event_id"], "evt-redeliver"
        )

    def test_evidence_id_is_stable_across_fresh_repositories(self):
        def handle_once(event_id):
            repository = FakeIncidentRepository()
            handler = OnMetricThresholdFailedHandler(
                IngestWebhookAlertCommandHandler(repository)
            )
            event = {
                "event_id": event_id,
                "aggregate_id": "gateway",
                "payload": {
                    "breaches": [
                        {
                            "metric": "cpu_percent",
                            "value": 95.0,
                            "threshold": 90.0,
                            "operator": ">=",
                            "severity": "high",
                        }
                    ]
                },
            }
            incident_id = handler.handle(event)
            incident = repository.saved[0]
            return incident_id, incident.evidence[0].id

        id_a, evidence_a = handle_once("evt-stable")
        id_b, evidence_b = handle_once("evt-stable")
        id_c, evidence_c = handle_once("evt-other")
        self.assertEqual(id_a, id_b)
        self.assertEqual(evidence_a, evidence_b)
        self.assertNotEqual(id_a, id_c)
        self.assertNotEqual(evidence_a, evidence_c)


if __name__ == "__main__":
    unittest.main()
