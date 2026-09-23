import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from domain.aggregates.incident import IncidentAggregate
from domain.entities.incident_evidence import IncidentEvidence
from infrastructure.database.postgres_incident_repo import PostgresIncidentRepositoryAdapter
from presentation.rest.controllers import router
from fastapi import FastAPI


class RcaOrchestrationTests(unittest.TestCase):
    def test_rca_result_is_persisted_as_evidence_and_advances_state(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = PostgresIncidentRepositoryAdapter(
                f"sqlite:///{os.path.join(temp_dir, 'incidents.db')}"
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

            app = FastAPI()
            app.include_router(router, prefix="/api/internal")

            with patch("presentation.rest.controllers.get_incident_repository", return_value=repository), \
                 patch("presentation.rest.controllers.RcaAgentClient") as client_cls:
                client_cls.return_value.analyze.return_value = {
                    "root_cause": "CPU threshold exceeded with deployment evidence present",
                    "confidence": 0.72,
                    "supporting_evidence_ids": ["threshold-1"],
                    "contributing_factors": [],
                    "recommended_next_actions": ["inspect the deployment timeline"],
                }
                # Dependency override is required because FastAPI resolves Depends by callable identity.
                app.dependency_overrides = {}
                from application.dependencies import get_incident_repository
                app.dependency_overrides[get_incident_repository] = lambda: repository
                response = TestClient(app).post("/api/internal/incidents/inc-rca/rca")

            self.assertEqual(response.status_code, 200, response.text)
            payload = response.json()
            self.assertEqual(payload["status"], "RootCauseFound")

            restored = repository.get_incident_by_id("inc-rca")
            self.assertEqual(restored.status, "RootCauseFound")
            rca = next(item for item in restored.evidence if item.kind == "rca_result")
            self.assertEqual(rca.payload["supporting_evidence_ids"], ["threshold-1"])


if __name__ == "__main__":
    unittest.main()
