"""Phase 6.1 proposal endpoints: typed failure → HTTP mapping (§25/§27).

Route registration (POST/GET ``/incidents/{id}/proposal``) is exercised
end-to-end over TestClient in ``tests/test_proposal_pipeline_e2e.py``;
this module pins the controller contract itself.
"""

import os
import tempfile
import unittest

from fastapi import HTTPException

from incident_service.application.failures import InvalidRcaResult
from incident_service.application.services.proposal_generation_service import (
    ProposalGenerationService,
)
from incident_service.application.services.rca_analyzer import RcaAnalyzerPort
from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.domain.entities.incident_evidence import IncidentEvidence
from incident_service.infrastructure.database.postgres_incident_repo import (
    PostgresIncidentRepositoryAdapter,
)
from incident_service.presentation.rest.controllers import (
    generate_remediation_proposal,
    get_remediation_proposal,
)

GOOD_RESULT = {
    "root_cause": "cpu saturation after rollout",
    "confidence": 0.93,
    "evidence_refs": ["evt-1"],
    "remediation_draft": {
        "target_file": "app/worker.py",
        "patch": (
            "--- a/app/worker.py\n"
            "+++ b/app/worker.py\n"
            "@@ -1 +1 @@\n"
            "-run()\n"
            "+run_safely()\n"
        ),
        "validation_plan": ["pytest -q"],
    },
}


class FakeAnalyzer(RcaAnalyzerPort):
    def __init__(self, result):
        self.result = result

    def analyze(self, evidence_pack):
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class BrokenPersistenceRepo:
    """Delegates reads to a real repo but fails on save."""

    def __init__(self, inner):
        self.inner = inner

    def save_incident(self, incident):
        raise RuntimeError("disk full")

    def get_incident_by_id(self, incident_id):
        return self.inner.get_incident_by_id(incident_id)

    def get_active_incidents(self):
        return self.inner.get_active_incidents()


def _trusted_deployment_evidence():
    """DEPLOYED record with genuine provenance (Stage-5 binding gates)."""
    from shared_kernel.domain.provenance import build_provenance_record

    payload = {
        "deployment_run_id": "run-1",
        "repository_name": "acme/checkout",
        "source_revision": {"head_sha": "a" * 40, "commits": []},
        "state": "DEPLOYED",
        "artifact_hash": "c" * 64,
        "plan_hash": "d" * 64,
    }
    payload["provenance"] = build_provenance_record(
        repository_name=payload["repository_name"],
        source_sha="a" * 40,
        artifact_hash=payload["artifact_hash"],
        plan_hash=payload["plan_hash"],
        deployment_run_id="run-1",
        state="DEPLOYED",
        verification_method="test-source-verifier",
    )
    return IncidentEvidence(
        id="deploy-1",
        kind="deployment_run",
        source="deployment-service",
        payload=payload,
    )


class ProposalEndpointTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.repository = PostgresIncidentRepositoryAdapter(
            f"sqlite:///{os.path.join(self._temp.name, 'incidents.db')}"
        )
        self.incident = IncidentAggregate(
            "inc-ep-1", "cpu breach", "HIGH", "gateway cpu"
        )
        self.incident.move_to_triage()
        self.incident.attach_evidence(
            IncidentEvidence(
                id="evt-1",
                kind="threshold_breach",
                source="monitoring-service",
                payload={"metric": "cpu_percent"},
            )
        )
        self.incident.attach_evidence(_trusted_deployment_evidence())
        self.repository.save_incident(self.incident)

    def tearDown(self):
        self._temp.cleanup()

    def _service(self, result=GOOD_RESULT, repository=None):
        return ProposalGenerationService(
            repository=repository or self.repository,
            analyzer=FakeAnalyzer(result),
        )

    def test_unknown_incident_returns_404_on_generate_and_get(self):
        with self.assertRaises(HTTPException) as ctx:
            generate_remediation_proposal("missing", self._service())
        self.assertEqual(ctx.exception.status_code, 404)

        with self.assertRaises(HTTPException) as ctx:
            get_remediation_proposal("missing", self.repository)
        self.assertEqual(ctx.exception.status_code, 404)

    def test_get_without_proposal_returns_404(self):
        with self.assertRaises(HTTPException) as ctx:
            get_remediation_proposal("inc-ep-1", self.repository)
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertIn("No remediation proposal", ctx.exception.detail)

    def test_generate_success_returns_proposal_body(self):
        body = generate_remediation_proposal("inc-ep-1", self._service())
        self.assertEqual(body["incident_id"], "inc-ep-1")
        self.assertEqual(body["incident_status"], "RemediationProposed")
        self.assertEqual(body["proposal"]["status"], "PROPOSED")

        fetched = get_remediation_proposal("inc-ep-1", self.repository)
        self.assertEqual(
            fetched["proposal"]["proposal_hash"],
            body["proposal"]["proposal_hash"],
        )

    def test_malformed_rca_returns_422_fail_closed(self):
        with self.assertRaises(HTTPException) as ctx:
            generate_remediation_proposal(
                "inc-ep-1",
                self._service(result={**GOOD_RESULT, "confidence": 9}),
            )
        self.assertEqual(ctx.exception.status_code, 422)
        self.assertIn("schema validation", ctx.exception.detail)
        # nothing persisted
        restored = self.repository.get_incident_by_id("inc-ep-1")
        self.assertEqual(restored.patch_proposals, [])

    def test_provider_outage_returns_503(self):
        with self.assertRaises(HTTPException) as ctx:
            generate_remediation_proposal(
                "inc-ep-1", self._service(result=RuntimeError("down"))
            )
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertIn("unavailable", ctx.exception.detail)

    def test_persistence_failure_returns_503(self):
        broken = BrokenPersistenceRepo(self.repository)
        with self.assertRaises(HTTPException) as ctx:
            generate_remediation_proposal("inc-ep-1", self._service(repository=broken))
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertIn("persisted", ctx.exception.detail)


if __name__ == "__main__":
    unittest.main()
