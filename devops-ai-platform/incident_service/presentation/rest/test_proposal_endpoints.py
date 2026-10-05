"""Phase 6.1 proposal endpoints: typed failure → HTTP mapping (§25/§27).

Route registration (POST/GET ``/incidents/{id}/proposal``) is exercised
end-to-end over TestClient in ``tests/test_proposal_pipeline_e2e.py``;
this module pins the controller contract itself.
"""

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

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


class ActiveIncidentListSerializationTests(unittest.TestCase):
    """Phase 6.2.1B Goal C: GET /incidents (list endpoint) reflects
    per-proposal durable claim state after the projection fix."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        url = f"sqlite:///{os.path.join(self._temp.name, 'list.db')}"
        self.repository = PostgresIncidentRepositoryAdapter(url)

        incident = IncidentAggregate("inc-list", "cpu", "HIGH", "ctx")
        incident.move_to_triage()
        incident.begin_investigation()
        incident.mark_root_cause_found()
        from incident_service.domain.entities.hotfix_proposal import (
            HotfixProposal,
        )

        for pid, patch_file in (("p-x", "app/x.py"), ("p-y", "app/y.py")):
            patch = (
                f"--- a/{patch_file}\n+++ b/{patch_file}\n"
                "@@ -1 +1 @@\n-old()\n+new()\n"
            )
            proposal = HotfixProposal(
                id=pid,
                incident_id="inc-list",
                target_filepath=patch_file,
                diff_patch_payload=patch,
                source_sha="a" * 40,
                repository="acme/checkout",
                status="APPROVED",
                validation_plan=["pytest -q"],
            )
            assert proposal.apply_verification_pass()
            proposal.proposal_hash = ("1" * 64) if pid == "p-x" else ("2" * 64)
            proposal.approved_by = "alice-operator"
            proposal.approval_hash = proposal.proposal_hash
            proposal.approved_at = datetime.now(timezone.utc)
            incident.upsert_remediation_proposal(proposal)
        self.repository.save_incident(incident)

        # p-x: claimed, COMMIT_CREATED + durable commit (attempt 2)
        from sqlalchemy import update as sa_update

        from incident_service.infrastructure.database.postgres_incident_repo import (
            execution_claims_table,
        )

        for index in range(2):
            now = datetime.now(timezone.utc)
            reason, _ = self.repository.claim_execution_lease(
                "inc-list", "p-x", "1" * 64,
                owner="worker-x", now=now, lease_seconds=600.0,
            )
            assert reason == "claimed", reason
            # expire between claims only; final claim stays live
            if index < 1:
                with self.repository.engine.begin() as connection:
                    connection.execute(
                        sa_update(execution_claims_table)
                        .where(
                            execution_claims_table.c.incident_id == "inc-list"
                        )
                        .values(
                            lease_expires_at=datetime.now(timezone.utc)
                            - timedelta(seconds=1)
                        )
                    )
        for stage in (
            "WORKSPACE_CREATED", "PATCH_APPLIED", "VALIDATION_STARTED",
            "VALIDATION_PASSED", "COMMIT_CREATED",
        ):
            assert self.repository.persist_execution_progress(
                "inc-list", "p-x", "worker-x",
                stage=stage,
                now=datetime.now(timezone.utc),
                lease_seconds=600.0,
                commit_sha="e" * 40 if stage == "COMMIT_CREATED" else None,
                branch_name=(
                    "automation/remediation/inc-list/p-x"
                    if stage == "COMMIT_CREATED"
                    else None
                ),
            ), stage
        # p-y: no claim

    def test_list_endpoint_serializes_durable_per_proposal_state(self):
        from incident_service.presentation.rest.controllers import (
            list_current_anomalies,
        )

        body = list_current_anomalies(repository=self.repository)
        target = [item for item in body if item["id"] == "inc-list"]
        self.assertEqual(len(target), 1)
        proposals = {item["id"]: item for item in target[0]["patch_proposals"]}
        self.assertEqual(set(proposals), {"p-x", "p-y"})

        x, y = proposals["p-x"], proposals["p-y"]
        # x reflects ITS claim: attempt 2, durable commit/branch
        self.assertEqual(x["execution_attempts"], 2)
        self.assertEqual(x["commit_sha"], "e" * 40)
        self.assertEqual(x["branch_name"], "automation/remediation/inc-list/p-x")
        self.assertTrue(x["execution_id"])
        # y has no claim: JSON view preserved, nothing inherited from x
        self.assertEqual(y["execution_attempts"], 0)
        self.assertEqual(y["commit_sha"], "")
        self.assertEqual(y["branch_name"], "")
        self.assertEqual(y["execution_id"], "")


if __name__ == "__main__":
    unittest.main()
