import os
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock

from incident_service.application.services.proposal_execution_service import (
    ProposalApprovalError,
    ProposalExecutionError,
    ProposalExecutionService,
)
from incident_service.application.services.proposal_generation_service import (
    compute_proposal_hash,
)
from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.domain.entities.hotfix_proposal import HotfixProposal
from incident_service.domain.entities.incident_evidence import IncidentEvidence
from incident_service.infrastructure.database.postgres_incident_repo import (
    PostgresIncidentRepositoryAdapter,
)
from shared_kernel.domain.provenance import build_provenance_record


REPOSITORY = "acme/checkout"
SOURCE_SHA = "a" * 40
PROPOSAL_ID = "proposal-inc-7"
INCIDENT_ID = "inc-7"


def trusted_deployment():
    payload = {
        "deployment_run_id": "run-7",
        "repository_name": REPOSITORY,
        "source_revision": {"head_sha": SOURCE_SHA, "commits": []},
        "state": "DEPLOYED",
        "artifact_hash": "c" * 64,
        "plan_hash": "d" * 64,
    }
    payload["provenance"] = build_provenance_record(
        repository_name=REPOSITORY,
        source_sha=SOURCE_SHA,
        artifact_hash=payload["artifact_hash"],
        plan_hash=payload["plan_hash"],
        deployment_run_id="run-7",
        state="DEPLOYED",
        verification_method="test-source-verifier",
    )
    return IncidentEvidence(
        id="deploy-7",
        kind="deployment_run",
        source="deployment-service",
        observed_at=datetime(2026, 9, 27, tzinfo=timezone.utc),
        payload=payload,
    )


def build_test_incident():
    incident = IncidentAggregate(INCIDENT_ID, "CPU breach", "HIGH", "gateway CPU")
    incident.move_to_triage()

    threshold = IncidentEvidence(
        id="threshold-7",
        kind="threshold_breach",
        source="monitoring-service",
        observed_at=datetime(2026, 9, 27, tzinfo=timezone.utc),
        payload={"metric": "cpu_percent", "value": 97.0},
    )
    incident.attach_evidence(threshold)
    incident.attach_evidence(trusted_deployment())

    rca_payload = {
        "schema": "devops.incident.rca/1",
        "rca_id": "rca-inc-7",
        "incident_id": INCIDENT_ID,
        "root_cause": "connection pool leak",
        "confidence": 0.95,
        "contributing_factors": [],
        "evidence_refs": ["threshold-7", "deploy-7"],
        "supporting_evidence_ids": ["threshold-7", "deploy-7"],
        "uncertainty": [],
        "methodology": "deterministic-test",
        "generated_at": "2026-09-27T10:00:00+00:00",
    }
    incident.attach_evidence(
        IncidentEvidence(
            id="rca-inc-7",
            kind="rca_result",
            source="agent-service",
            observed_at=datetime(2026, 9, 27, 10, tzinfo=timezone.utc),
            payload=rca_payload,
        )
    )

    patch = (
        "--- a/app/pool.py\n"
        "+++ b/app/pool.py\n"
        "@@ -1 +1 @@\n"
        "-close_pool()\n"
        "+close_pool_gracefully()\n"
    )
    proposal = HotfixProposal(
        id=PROPOSAL_ID,
        incident_id=INCIDENT_ID,
        target_filepath="app/pool.py",
        diff_patch_payload=patch,
        is_verified=False,
        source_sha=SOURCE_SHA,
        repository=REPOSITORY,
        evidence_refs=["threshold-7", "deploy-7"],
        validation_plan=["run unit tests"],
        risk_class="LOW",
        proposal_hash="",
        status="PROPOSED",
    )
    proposal.apply_verification_pass()
    proposal.proposal_hash = compute_proposal_hash(
        incident_id=INCIDENT_ID,
        root_cause="connection pool leak",
        evidence_refs=proposal.evidence_refs,
        repository=REPOSITORY,
        source_sha=SOURCE_SHA,
        file_paths=["app/pool.py"],
        patch=proposal.diff_patch_payload,
        validation_plan=proposal.validation_plan,
        risk_class="LOW",
    )
    incident.upsert_remediation_proposal(proposal)
    return incident


class FakeRepository(PostgresIncidentRepositoryAdapter):
    pass


class ProposalExecutionServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repository = FakeRepository(
            f"sqlite:///{os.path.join(self.temp.name, 'incidents.db')}"
        )
        self.incident = build_test_incident()
        self.repository.save_incident(self.incident)
        self.factory_calls = 0

        def factory():
            self.factory_calls += 1
            return self.orchestrator

        self.orchestrator = MagicMock()
        self.orchestration_result = MagicMock()
        self.orchestration_result.pull_request_url = (
            "https://github.com/acme/checkout/pull/77"
        )
        self.orchestrator.execute.return_value = self.orchestration_result

        self.service = ProposalExecutionService(
            repository=self.repository,
            orchestrator_factory=factory,
        )

    def tearDown(self):
        self.temp.cleanup()

    def _hash(self):
        return self.repository.get_incident_by_id(INCIDENT_ID).patch_proposals[0].proposal_hash

    def test_execution_requires_approval(self):
        with self.assertRaises(ProposalExecutionError):
            self.service.execute(
                incident_id=INCIDENT_ID,
                proposal_id=PROPOSAL_ID,
                proposal_hash=self._hash(),
            )
        self.assertEqual(self.factory_calls, 0)
        self.orchestrator.execute.assert_not_called()

    def test_wrong_hash_cannot_approve(self):
        with self.assertRaises(ProposalApprovalError):
            self.service.approve(
                incident_id=INCIDENT_ID,
                proposal_id=PROPOSAL_ID,
                proposal_hash="b" * 64,
                approved_by="alice",
            )
        self.assertEqual(self.factory_calls, 0)

    def test_approval_is_hash_bound_and_persisted(self):
        result = self.service.approve(
            incident_id=INCIDENT_ID,
            proposal_id=PROPOSAL_ID,
            proposal_hash=self._hash(),
            approved_by="alice",
        )
        self.assertEqual(result.proposal.status, "APPROVED")
        self.assertEqual(result.proposal.approved_by, "alice")
        self.assertIsNotNone(result.proposal.approved_at)

        reloaded = self.repository.get_incident_by_id(INCIDENT_ID)
        proposal = reloaded.patch_proposals[0]
        self.assertEqual(proposal.status, "APPROVED")
        self.assertEqual(proposal.approved_by, "alice")
        self.assertEqual(proposal.proposal_hash, self._hash())

    def test_execution_revalidates_and_creates_pr(self):
        digest = self._hash()
        self.service.approve(
            incident_id=INCIDENT_ID,
            proposal_id=PROPOSAL_ID,
            proposal_hash=digest,
            approved_by="alice",
        )

        result = self.service.execute(
            incident_id=INCIDENT_ID,
            proposal_id=PROPOSAL_ID,
            proposal_hash=digest,
        )

        self.assertFalse(result.reused_existing_pr)
        self.assertEqual(result.proposal.status, "PR_CREATED")
        self.assertEqual(
            result.proposal.pull_request_url,
            "https://github.com/acme/checkout/pull/77",
        )
        self.assertEqual(self.factory_calls, 1)
        self.orchestrator.execute.assert_called_once()
        call = self.orchestrator.execute.call_args.kwargs
        self.assertEqual(call["repository_slug"], REPOSITORY)
        self.assertEqual(call["proposal"].proposal_hash, digest)

        restored = self.repository.get_incident_by_id(INCIDENT_ID)
        self.assertEqual(restored.status, "RemediationPRCreated")
        self.assertEqual(restored.patch_proposals[0].status, "PR_CREATED")

    def test_retry_after_pr_creation_is_idempotent(self):
        digest = self._hash()
        self.service.approve(
            incident_id=INCIDENT_ID,
            proposal_id=PROPOSAL_ID,
            proposal_hash=digest,
            approved_by="alice",
        )
        first = self.service.execute(
            incident_id=INCIDENT_ID,
            proposal_id=PROPOSAL_ID,
            proposal_hash=digest,
        )
        second = self.service.execute(
            incident_id=INCIDENT_ID,
            proposal_id=PROPOSAL_ID,
            proposal_hash=digest,
        )

        self.assertFalse(first.reused_existing_pr)
        self.assertTrue(second.reused_existing_pr)
        self.assertEqual(self.factory_calls, 1)
        self.orchestrator.execute.assert_called_once()

    def test_proposal_tampering_blocks_before_orchestrator(self):
        digest = self._hash()
        self.service.approve(
            incident_id=INCIDENT_ID,
            proposal_id=PROPOSAL_ID,
            proposal_hash=digest,
            approved_by="alice",
        )
        tampered = self.repository.get_incident_by_id(INCIDENT_ID)
        tampered.patch_proposals[0].diff_patch_payload += "# tampered"
        self.repository.save_incident(tampered)

        with self.assertRaises(ProposalExecutionError):
            self.service.execute(
                incident_id=INCIDENT_ID,
                proposal_id=PROPOSAL_ID,
                proposal_hash=digest,
            )
        self.assertEqual(self.factory_calls, 0)
        self.orchestrator.execute.assert_not_called()
