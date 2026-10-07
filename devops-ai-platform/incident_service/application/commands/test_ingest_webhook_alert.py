"""Event-id idempotency for incident ingestion (§4)."""

import unittest

from incident_service.application.commands.ingest_webhook_alert import (
    IngestWebhookAlertCommand,
    IngestWebhookAlertCommandHandler,
    deterministic_evidence_id,
    deterministic_incident_id,
)
from incident_service.domain.entities.incident_evidence import IncidentEvidence


class FakeRepo:
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


def command_for_event(event_id, evidence_id=None, metric="cpu"):
    evidence = IncidentEvidence(
        id=evidence_id or "random-evidence-id",
        kind="threshold_breach",
        source="monitoring-service",
        payload={"event_id": event_id, "metric": metric},
    )
    return IngestWebhookAlertCommand(
        raw_source="prometheus-alert",
        alert_name=f"{metric}-threshold-breached",
        severity="HIGH",
        details="service=api metric=cpu",
        evidence=[evidence],
    )


class IngestIdempotencyTests(unittest.TestCase):
    def test_same_event_id_maps_to_same_incident(self):
        first = deterministic_incident_id("evt-42")
        second = deterministic_incident_id("evt-42")
        other = deterministic_incident_id("evt-43")
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        self.assertEqual(
            deterministic_evidence_id("evt-42"),
            deterministic_evidence_id("evt-42"),
        )

    def test_redelivered_event_does_not_duplicate_incident(self):
        repo = FakeRepo()
        handler = IngestWebhookAlertCommandHandler(repo)

        first_id = handler.handle(command_for_event("evt-42"))
        second_id = handler.handle(command_for_event("evt-42", metric="memory"))

        self.assertEqual(first_id, second_id)
        self.assertEqual(len(repo.store), 1)
        self.assertEqual(len(repo.saved), 1)

    def test_distinct_event_ids_create_distinct_incidents(self):
        repo = FakeRepo()
        handler = IngestWebhookAlertCommandHandler(repo)
        id_a = handler.handle(command_for_event("evt-a"))
        id_b = handler.handle(command_for_event("evt-b"))
        self.assertNotEqual(id_a, id_b)
        self.assertEqual(len(repo.store), 2)

    def test_events_without_event_id_keep_legacy_behaviour(self):
        repo = FakeRepo()
        handler = IngestWebhookAlertCommandHandler(repo)
        id_a = handler.handle(command_for_event(""))
        id_b = handler.handle(command_for_event(""))
        self.assertNotEqual(id_a, id_b)
        self.assertEqual(len(repo.store), 2)


if __name__ == "__main__":
    unittest.main()
