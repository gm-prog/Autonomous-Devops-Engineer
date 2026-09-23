import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from application.dependencies import get_incident_repository
from domain.aggregates.incident import IncidentAggregate
from domain.entities.incident_evidence import IncidentEvidence
from infrastructure.database.postgres_incident_repo import PostgresIncidentRepositoryAdapter
from presentation.rest.controllers import investigate_root_cause


class RcaOrchestrationTests(unittest.TestCase):
    def test_rca_result_is_persisted_as_evidence_and_advances_state(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = PostgresIncidentRepositoryAdapter(
                f"sqlite:///{os.path.join(temp_dir, "incidents.db")}"
            )
            incident = IncidentAggregate("inc-rca", "CPU breach", "CRITICAL", "gateway CPU")
            incident.move_to_triage()
            incident.attach_evidence(IncidentEvidence(
                id="threshold-1",
                kind="threshold_breach",
                source="monitoring-service",
                payload={"metric": "cpu_percent", "value": 95.0, "threshold": 90.0},
            ))
            repository.save_incident(incident)

            with patch("presentation.rest.controllers.RcaAgentClient") as client_cls:
                client_cls.return_value.analyze.return_value = {
                    "root_cause": "CPU threshold exceeded with deployment evidence present",
                    "confidence": 0.72,
                    "supporting_evidence_ids": ["threshold-1"],
                    "contributing_factors": [],
                    "recommended_next_actions": ["inspect the deployment timeline"],
                }
                result = investigate_root_cause("inc-rca", repository)

            self.assertEqual(result["status"], "RootCauseFound")
            restored = repository.get_incident_by_id("inc-rca")
            self.assertEqual(restored.status, "RootCauseFound")
            rca = next(item for item in restored.evidence if item.kind == "rca_result")
            self.assertEqual(rca.payload["supporting_evidence_ids"], ["threshold-1"])

    def test_rca_agent_cannot_introduce_unknown_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = PostgresIncidentRepositoryAdapter(
                f"sqlite:///{os.path.join(temp_dir, "incidents.db")}"
            )
            incident = IncidentAggregate("inc-invalid", "CPU breach", "HIGH", "gateway CPU")
            incident.move_to_triage()
            incident.attach_evidence(IncidentEvidence(
                id="threshold-1",
                kind="threshold_breach",
                source="monitoring-service",
                payload={"metric": "cpu_percent", "value": 95.0},
            ))
            repository.save_incident(incident)

            with patch("presentation.rest.controllers.RcaAgentClient") as client_cls:
                client_cls.return_value.analyze.return_value = {
                    "root_cause": "unsupported",
                    "confidence": 0.2,
                    "supporting_evidence_ids": ["not-in-pack"],
                    "contributing_factors": [],
                    "recommended_next_actions": [],
                }
                with self.assertRaises(HTTPException) as context:
                    investigate_root_cause("inc-invalid", repository)

            self.assertEqual(context.exception.status_code, 502)
            restored = repository.get_incident_by_id("inc-invalid")
            self.assertEqual([item.kind for item in restored.evidence], ["threshold_breach"])


if __name__ == "__main__":
    unittest.main()
