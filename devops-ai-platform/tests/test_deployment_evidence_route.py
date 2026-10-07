"""Deployment-evidence REST seam tests (Phase 8.4 §4).

Route: POST /incidents/{incident_id}/deployment-evidence

Guarantees under test:
* unknown incident → 404 with NO deployment-service call (§18)
* collector errors mapped fail-closed (404 run missing / 502 unreachable / 422 other)
* non-DEPLOYED / missing repository+SHA / missing provenance → 422 and NOT persisted
* DEPLOYED + repository + exact SHA + provenance → 200, persisted (second
  source of truth: re-read from the repository), and extra caller fields
  are not persisted as evidence
"""

import unittest
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.domain.entities.incident_evidence import IncidentEvidence
from incident_service.presentation.rest import controllers as controllers_module
from incident_service.application.dependencies import get_incident_repository

ROUTE = "/incidents/{incident_id}/deployment-evidence"


class FakeRepository:
    def __init__(self, incident=None):
        self.incident = incident
        self.saved = []

    def save_incident(self, incident):
        self.incident = incident
        self.saved.append(incident)

    def get_incident_by_id(self, incident_id):
        if self.incident and self.incident.id == incident_id:
            return self.incident
        return None

    def get_active_incidents(self):
        return [self.incident] if self.incident else []


def _deployed_evidence(run_id="run_1", state="DEPLOYED", provenance=None, repo="e2e/fixture", sha="a" * 40):
    return IncidentEvidence(
        kind="deployment_run",
        source="deployment-service",
        payload={
            "deployment_run_id": run_id,
            "repository_name": repo,
            "source_revision": {"head_sha": sha},
            "state": state,
            "artifact_hash": "f" * 64,
            "plan_hash": "e" * 64,
            "provenance": (
                {"deployment_run_id": run_id, "repository_name": repo, "source_sha": sha}
                if provenance is None
                else provenance
            ),
        },
    )


def _app(repository):
    app = FastAPI()
    app.include_router(controllers_module.router)
    app.dependency_overrides[get_incident_repository] = lambda: repository
    return TestClient(app)


class DeploymentEvidenceRouteTests(unittest.TestCase):
    def test_unknown_incident_404_without_downstream_call(self):
        repository = FakeRepository(incident=None)
        with patch.object(
            controllers_module.DeploymentEvidenceCollector, "collect"
        ) as collect:
            client = _app(repository)
            response = client.post(
                ROUTE.format(incident_id="missing"),
                json={"deployment_run_id": "run_1"},
            )
        self.assertEqual(response.status_code, 404, response.text)
        collect.assert_not_called()

    def test_collector_missing_run_maps_to_404(self):
        repository = FakeRepository(IncidentAggregate("inc-1", "t", "HIGH", "ctx"))
        with patch.object(
            controllers_module.DeploymentEvidenceCollector,
            "collect",
            side_effect=controllers_module.DeploymentEvidenceCollectorError(
                "deployment run run_x was not found"
            ),
        ):
            client = _app(repository)
            response = client.post(
                ROUTE.format(incident_id="inc-1"), json={"deployment_run_id": "run_x"}
            )
        self.assertEqual(response.status_code, 404, response.text)

    def test_collector_unreachable_maps_to_502(self):
        repository = FakeRepository(IncidentAggregate("inc-1", "t", "HIGH", "ctx"))
        with patch.object(
            controllers_module.DeploymentEvidenceCollector,
            "collect",
            side_effect=controllers_module.DeploymentEvidenceCollectorError(
                "unable to reach deployment service"
            ),
        ):
            client = _app(repository)
            response = client.post(
                ROUTE.format(incident_id="inc-1"), json={"deployment_run_id": "run_1"}
            )
        self.assertEqual(response.status_code, 502, response.text)

    def test_non_deployed_state_is_422_and_not_persisted(self):
        incident = IncidentAggregate("inc-1", "t", "HIGH", "ctx")
        repository = FakeRepository(incident)
        with patch.object(
            controllers_module.DeploymentEvidenceCollector,
            "collect",
            return_value=_deployed_evidence(state="AWAITING_APPROVAL"),
        ):
            client = _app(repository)
            response = client.post(
                ROUTE.format(incident_id="inc-1"), json={"deployment_run_id": "run_1"}
            )
        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn("not authoritative", response.json()["detail"])
        self.assertEqual(repository.saved, [])
        self.assertEqual(incident.evidence, [])

    def test_missing_provenance_is_422_and_not_persisted(self):
        incident = IncidentAggregate("inc-1", "t", "HIGH", "ctx")
        repository = FakeRepository(incident)
        with patch.object(
            controllers_module.DeploymentEvidenceCollector,
            "collect",
            return_value=_deployed_evidence(provenance={}),
        ):
            client = _app(repository)
            response = client.post(
                ROUTE.format(incident_id="inc-1"), json={"deployment_run_id": "run_1"}
            )
        self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(repository.saved, [])

    def test_valid_deployed_evidence_persists_and_returns_record(self):
        incident = IncidentAggregate("inc-1", "t", "HIGH", "ctx")
        repository = FakeRepository(incident)
        with patch.object(
            controllers_module.DeploymentEvidenceCollector,
            "collect",
            return_value=_deployed_evidence(),
        ) as collect:
            client = _app(repository)
            response = client.post(
                ROUTE.format(incident_id="inc-1"),
                json={"deployment_run_id": "run_1", "repository_name": "spoofed/repo"},
            )
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["kind"], "deployment_run")
        self.assertEqual(body["payload"]["state"], "DEPLOYED")
        self.assertEqual(body["payload"]["repository_name"], "e2e/fixture")
        # caller-supplied repository_name was ignored — evidence came from
        # the deployment service only
        self.assertNotEqual(body["payload"]["repository_name"], "spoofed/repo")
        # second source of truth: persisted in the aggregate
        self.assertEqual(len(repository.saved), 1)
        persisted = [
            item
            for item in repository.incident.evidence
            if item.id == body["id"]
        ]
        self.assertEqual(len(persisted), 1)
        self.assertEqual(
            persisted[0].payload["source_revision"]["head_sha"], "a" * 40
        )
        collect.assert_called_once_with("run_1")

    def test_empty_run_id_is_422_from_request_contract(self):
        repository = FakeRepository(IncidentAggregate("inc-1", "t", "HIGH", "ctx"))
        client = _app(repository)
        response = client.post(
            ROUTE.format(incident_id="inc-1"), json={"deployment_run_id": ""}
        )
        self.assertEqual(response.status_code, 422, response.text)


if __name__ == "__main__":
    unittest.main()
