"""Deterministic E2E: monitoring event → evidence → RCA → proposal (§23).

Chain exercised over real HTTP (TestClient), real ingestion, real sqlite
persistence and the real collector command — only the RCA provider and
external infrastructure are deterministic fakes:

    ThreatThresholdExceededEvent (event_id)
        → incident ingestion (event-id idempotent)
        → deployment evidence attached through the real command handler
           (fixture carries genuine platform provenance, DEPLOYED state,
           canonical repository, full 40-hex SHA, run id, artifact/plan
           hashes)
        → POST /incidents/{id}/proposal (schema-validated RCA,
           deterministic validation + risk + hash)
        → GET  /incidents/{id}/proposal after a FRESH repository reload
           (persistence round-trip, §19)

plus the blocked outcome (no deployment evidence → BLOCKED, provider not
called) and the §22 no-side-effect spies at transport level.
"""

import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from shared_kernel.domain.provenance import build_provenance_record, verify_provenance_record

from incident_service.application.commands.attach_deployment_evidence import (
    AttachDeploymentEvidenceCommandHandler,
    AttachDeploymentEvidenceCommand,
)
from incident_service.application.commands.ingest_webhook_alert import (
    IngestWebhookAlertCommandHandler,
    deterministic_evidence_id,
    deterministic_incident_id,
)
from incident_service.application.event_handlers.on_metric_threshold_failed import (
    OnMetricThresholdFailedHandler,
)
from incident_service.application.services.proposal_generation_service import (
    BLOCKED_MISSING_TARGET,
    ProposalGenerationService,
)
from incident_service.application.services.rca_analyzer import RcaAnalyzerPort
from incident_service.domain.entities.incident_evidence import IncidentEvidence
from incident_service.infrastructure.database.postgres_incident_repo import (
    PostgresIncidentRepositoryAdapter,
)
from incident_service.infrastructure.deployment.deployment_evidence_collector import (
    DeploymentEvidenceCollector,
)
from incident_service.infrastructure.source_provider.github_pr_client import (
    GitHubPRClient,
)
from incident_service.application.services.remediation_orchestration_service import (
    RemediationOrchestrationService,
)
from incident_service.presentation.rest import controllers as controllers_module
from incident_service.main import app as incident_app

EVENT_ID = "evt-e2e-001"
REPOSITORY_NAME = "acme/checkout"
HEAD_SHA = "a" * 40

RCA_RESULT = {
    "root_cause": "connection pool leak after deployment of run-e2e-1",
    "confidence": 0.95,
    "contributing_factors": [],
    "evidence_refs": [],  # filled per-test with real evidence ids
    "uncertainty": [],
    "methodology": "deterministic-e2e",
    "remediation_draft": {
        "target_file": "app/pool.py",
        "patch": (
            "--- a/app/pool.py\n"
            "+++ b/app/pool.py\n"
            "@@ -1 +1 @@\n"
            "-close_pool()\n"
            "+close_pool_gracefully()\n"
        ),
        "validation_plan": ["run unit tests", "run integration tests"],
        "risk_class": None,
    },
}

THRESHOLD_EVENT = {
    "event_id": EVENT_ID,
    "aggregate_id": "gateway",
    "event_type": "ThreatThresholdExceededEvent",
    "timestamp": "2026-09-27T08:00:00+00:00",
    "payload": {
        "severity": "high",
        "breach_count": 3,
        "breaches": [
            {
                "metric": "cpu_percent",
                "value": 97.2,
                "threshold": 90.0,
                "operator": ">=",
                "severity": "high",
            }
        ],
        "metrics": {"cpu_percent": 97.2},
    },
}


class FakeAnalyzer(RcaAnalyzerPort):
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def analyze(self, evidence_pack):
        self.calls += 1
        return self.result


class StaticDeploymentEvidenceCollector(DeploymentEvidenceCollector):
    """Collector contract with a fixture record instead of live HTTP."""

    def __init__(self, evidence):
        self.evidence = evidence

    def collect(self, deployment_run_id):
        return self.evidence


def deployment_run_fixture(evidence_id="deploy-e2e-1", run_id="run-e2e-1"):
    payload = {
        "deployment_run_id": run_id,
        "repository_id": 42,
        "repository_name": REPOSITORY_NAME,
        "source_revision": {"head_sha": HEAD_SHA, "commits": []},
        "state": "DEPLOYED",
        "artifact_hash": "c" * 64,
        "plan_hash": "d" * 64,
    }
    payload["provenance"] = build_provenance_record(
        repository_name=REPOSITORY_NAME,
        source_sha=HEAD_SHA,
        artifact_hash=payload["artifact_hash"],
        plan_hash=payload["plan_hash"],
        deployment_run_id=run_id,
        state="DEPLOYED",
        verification_method="test-source-verifier",
    )
    return IncidentEvidence(
        id=evidence_id,
        kind="deployment_run",
        source="deployment-service",
        payload=payload,
    )


class ProposalPipelineE2ETests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.db_url = f"sqlite:///{os.path.join(self._temp.name, 'incidents.db')}"
        self.repository = PostgresIncidentRepositoryAdapter(self.db_url)

        # real monitoring event → real ingestion (event-id idempotent)
        self.handler = OnMetricThresholdFailedHandler(
            IngestWebhookAlertCommandHandler(self.repository)
        )
        self.incident_id = self.handler.handle(dict(THRESHOLD_EVENT))

        # deployment evidence through the REAL attach command handler
        collector = StaticDeploymentEvidenceCollector(deployment_run_fixture())
        AttachDeploymentEvidenceCommandHandler(
            self.repository, collector
        ).handle(
            AttachDeploymentEvidenceCommand(
                incident_id=self.incident_id,
                deployment_run_id="run-e2e-1",
            )
        )

        threshold_id = deterministic_evidence_id(EVENT_ID)
        self.analyzer = FakeAnalyzer(
            {
                **RCA_RESULT,
                "evidence_refs": [threshold_id, "deploy-e2e-1"],
            }
        )
        self.service = ProposalGenerationService(
            repository=self.repository, analyzer=self.analyzer
        )
        self._install_overrides(self.repository, self.service)
        self.client = TestClient(incident_app)

    def tearDown(self):
        incident_app.dependency_overrides.clear()
        self._temp.cleanup()

    @staticmethod
    def _install_overrides(repository, service):
        incident_app.dependency_overrides[
            controllers_module.get_incident_repository
        ] = lambda: repository
        incident_app.dependency_overrides[
            controllers_module.get_proposal_generation_service
        ] = lambda: service

    # ------------------------------------------------------------------ #
    def test_full_pipeline_produces_and_reloads_proposal(self):
        # provenance on the attached record is genuine (Stage-5 gates) —
        # verify raises ProvenanceError if anything is off
        incident = self.repository.get_incident_by_id(self.incident_id)
        deployment = next(
            item for item in incident.evidence if item.kind == "deployment_run"
        )
        verify_provenance_record(deployment.payload["provenance"])

        with patch.object(
            RemediationOrchestrationService, "execute"
        ) as orchestrator_spy, patch(
            "incident_service.infrastructure.source_provider."
            "github_pr_client.GitHubPRClient.__init__"
        ) as github_spy, patch(
            "subprocess.run"
        ) as subprocess_run:
            response = self.client.post(
                f"/incidents/{self.incident_id}/proposal"
            )

        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["proposal"]["status"], "PROPOSED")
        self.assertEqual(body["incident_status"], "RemediationProposed")
        # §23: target identity equals the trusted record, same object
        self.assertEqual(body["target"]["repository_name"], REPOSITORY_NAME)
        self.assertEqual(body["target"]["source_sha"], HEAD_SHA)
        self.assertEqual(body["target"]["evidence_id"], "deploy-e2e-1")
        self.assertEqual(body["proposal"]["repository"], REPOSITORY_NAME)
        self.assertEqual(body["proposal"]["source_sha"], HEAD_SHA)
        self.assertEqual(body["proposal"]["risk_class"], "LOW")
        self.assertRegex(body["proposal"]["proposal_hash"], r"^[0-9a-f]{64}$")

        # §22: proposal produced while every execution path stayed untouched
        orchestrator_spy.assert_not_called()
        github_spy.assert_not_called()
        subprocess_run.assert_not_called()

        # §19: a FRESH repository instance reloads every field byte-identical
        fresh = PostgresIncidentRepositoryAdapter(self.db_url)
        self._install_overrides(fresh, ProposalGenerationService(
            repository=fresh, analyzer=self.analyzer
        ))
        fetched = self.client.get(f"/incidents/{self.incident_id}/proposal")
        self.assertEqual(fetched.status_code, 200, fetched.text)
        reloaded = fetched.json()
        self.assertEqual(
            reloaded["proposal"]["proposal_hash"],
            body["proposal"]["proposal_hash"],
        )
        self.assertEqual(reloaded["proposal"]["validation_plan"],
                         body["proposal"]["validation_plan"])
        self.assertEqual(reloaded["proposal"]["evidence_refs"],
                         body["proposal"]["evidence_refs"])
        self.assertEqual(reloaded["proposal"]["status"], "PROPOSED")
        self.assertEqual(reloaded["incident_status"], "RemediationProposed")

        # regeneration stays idempotent (§4): one proposal, same hash
        again = self.client.post(f"/incidents/{self.incident_id}/proposal")
        self.assertEqual(again.status_code, 200)
        self.assertEqual(
            again.json()["proposal"]["proposal_hash"],
            body["proposal"]["proposal_hash"],
        )
        restored = fresh.get_incident_by_id(self.incident_id)
        self.assertEqual(len(restored.patch_proposals), 1)

    def test_duplicate_event_delivery_keeps_single_incident(self):
        second = self.handler.handle(dict(THRESHOLD_EVENT))
        self.assertEqual(second, self.incident_id)
        self.assertEqual(
            second, deterministic_incident_id(EVENT_ID)
        )
        restored = self.repository.get_incident_by_id(self.incident_id)
        threshold = [
            item for item in restored.evidence if item.kind == "threshold_breach"
        ]
        self.assertEqual(len(threshold), 1)

    def test_missing_deployment_evidence_blocks_without_provider(self):
        incident_id = self.handler.handle(
            {
                **THRESHOLD_EVENT,
                "event_id": "evt-e2e-no-deploy",
            }
        )
        calls_before = self.analyzer.calls

        response = self.client.post(f"/incidents/{incident_id}/proposal")

        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["proposal"]["status"], "BLOCKED")
        self.assertEqual(
            body["proposal"]["blocked_reason"], BLOCKED_MISSING_TARGET
        )
        self.assertEqual(body["proposal"]["repository"], "")
        self.assertEqual(body["proposal"]["source_sha"], "")
        self.assertEqual(self.analyzer.calls, calls_before)
        self.assertEqual(body["incident_status"], "Triage")

        fetched = self.client.get(f"/incidents/{incident_id}/proposal")
        self.assertEqual(fetched.status_code, 200)
        self.assertEqual(fetched.json()["proposal"]["status"], "BLOCKED")

    def test_unknown_incident_404_and_no_proposal_404(self):
        missing = self.client.post("/incidents/inc-does-not-exist/proposal")
        self.assertEqual(missing.status_code, 404)
        no_proposal = self.client.get("/incidents/inc-does-not-exist/proposal")
        self.assertEqual(no_proposal.status_code, 404)

        incident_id = self.handler.handle(
            {**THRESHOLD_EVENT, "event_id": "evt-e2e-empty"}
        )
        empty = self.client.get(f"/incidents/{incident_id}/proposal")
        self.assertEqual(empty.status_code, 404)
        self.assertIn("No remediation proposal", empty.json()["detail"])


if __name__ == "__main__":
    unittest.main()
