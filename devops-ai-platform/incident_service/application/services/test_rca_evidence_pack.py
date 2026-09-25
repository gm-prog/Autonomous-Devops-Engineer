import unittest
from datetime import datetime, timezone

from incident_service.application.services.rca_evidence_pack import RcaEvidencePackBuilder
from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.domain.entities.incident_evidence import IncidentEvidence


class FakeRepository:
    def __init__(self, incident=None):
        self.incident = incident

    def save_incident(self, incident):
        self.incident = incident

    def get_incident_by_id(self, incident_id):
        return self.incident if self.incident and self.incident.id == incident_id else None

    def get_active_incidents(self):
        return [self.incident] if self.incident else []


class RcaEvidencePackBuilderTests(unittest.TestCase):
    def test_builds_deterministic_pack_from_persisted_evidence(self):
        incident = IncidentAggregate(
            "inc-1",
            "Gateway CPU breach",
            "CRITICAL",
            "CPU threshold exceeded",
        )

        incident.attach_evidence(
            IncidentEvidence(
                id="deployment-1",
                kind="deployment_run",
                source="deployment-service",
                observed_at=datetime(2026, 9, 23, 10, 0, tzinfo=timezone.utc),
                payload={
                    "deployment_run_id": "run-123",
                    "repository_name": "gateway",
                    "state": "DEPLOYED",
                    "artifact_hash": "a" * 64,
                    "plan_hash": "b" * 64,
                    "health_check_status": "PASS",
                    "rollback_status": "NOT_TRIGGERED",
                },
            )
        )
        incident.attach_evidence(
            IncidentEvidence(
                id="threshold-1",
                kind="threshold_breach",
                source="monitoring-service",
                observed_at=datetime(2026, 9, 23, 10, 5, tzinfo=timezone.utc),
                payload={
                    "service": "gateway",
                    "metric": "cpu_percent",
                    "value": 95.0,
                    "threshold": 90.0,
                    "operator": ">=",
                    "severity": "critical",
                    "breach_count": 1,
                },
            )
        )

        pack = RcaEvidencePackBuilder(FakeRepository(incident)).build("inc-1")

        self.assertEqual(pack["pack_version"], "1.0")
        self.assertEqual(pack["evidence"]["count"], 2)
        self.assertEqual(
            [x["evidence_id"] for x in pack["evidence"]["timeline"]],
            ["deployment-1", "threshold-1"],
        )
        self.assertEqual(
            pack["signals"]["threshold_breaches"][0]["metric"],
            "cpu_percent",
        )
        self.assertEqual(
            pack["signals"]["deployment_runs"][0]["deployment_run_id"],
            "run-123",
        )
        self.assertEqual(pack["evidence"]["sources"]["monitoring-service"], 1)
        self.assertEqual(pack["evidence"]["sources"]["deployment-service"], 1)

    def test_missing_incident_is_rejected(self):
        with self.assertRaises(LookupError):
            RcaEvidencePackBuilder(FakeRepository()).build("missing")

    def test_empty_id_is_rejected(self):
        with self.assertRaises(ValueError):
            RcaEvidencePackBuilder(FakeRepository()).build(" ")


if __name__ == "__main__":
    unittest.main()
