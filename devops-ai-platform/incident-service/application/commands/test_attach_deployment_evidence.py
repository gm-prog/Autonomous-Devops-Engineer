import unittest

from application.commands.attach_deployment_evidence import (
    AttachDeploymentEvidenceCommand,
    AttachDeploymentEvidenceCommandHandler,
)
from domain.aggregates.incident import IncidentAggregate
from domain.entities.incident_evidence import IncidentEvidence


class FakeRepository:
    def __init__(self, incident=None):
        self.incident = incident
        self.saved = []

    def save_incident(self, incident):
        self.incident = incident
        self.saved.append(incident)

    def get_incident_by_id(self, incident_id):
        return self.incident if self.incident and self.incident.id == incident_id else None

    def get_active_incidents(self):
        return [self.incident] if self.incident else []


class FakeCollector:
    def collect(self, deployment_run_id):
        return IncidentEvidence(
            id="deployment-evidence-1",
            kind="deployment_run",
            source="deployment-service",
            payload={
                "deployment_run_id": deployment_run_id,
                "state": "DEPLOYED",
                "artifact_hash": "a" * 64,
            },
        )


class AttachDeploymentEvidenceTests(unittest.TestCase):
    def test_attaches_deployment_evidence_to_existing_incident(self):
        incident = IncidentAggregate("inc-1", "Checkout incident", "HIGH", "5xx spike")
        repository = FakeRepository(incident)
        handler = AttachDeploymentEvidenceCommandHandler(repository, FakeCollector())

        evidence = handler.handle(
            AttachDeploymentEvidenceCommand("inc-1", "run_123")
        )

        self.assertEqual(evidence.kind, "deployment_run")
        self.assertEqual(repository.incident.evidence[0].payload["deployment_run_id"], "run_123")
        self.assertEqual(len(repository.saved), 1)

    def test_missing_incident_is_rejected(self):
        handler = AttachDeploymentEvidenceCommandHandler(FakeRepository(), FakeCollector())

        with self.assertRaises(LookupError):
            handler.handle(AttachDeploymentEvidenceCommand("missing", "run_123"))


if __name__ == "__main__":
    unittest.main()