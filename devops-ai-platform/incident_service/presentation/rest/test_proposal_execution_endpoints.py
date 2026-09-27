"""Phase 6.2 controller contract: proposal approve/execute HTTP mapping.

Direct controller calls with injected services pin the typed-failure →
HTTP status map (§25), plus one full-chain wiring test where the endpoint
builds the REAL approval + execution services (orchestration stubbed) —
proving the composition path end-to-end at the controller layer.
"""

import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from incident_service.application.failures import (
    ApprovalPolicyError,
    ProposalAlreadyExecutingError,
    ProposalExecutionFailedError,
    ProposalIntegrityError,
    ProposalNotApprovedError,
    ProposalNotFoundError,
    ProposalPatchPolicyError,
    ProposalStaleError,
    RemediationValidationFailedError,
    TargetRevalidationError,
)
from incident_service.application.services.remediation_orchestration_service import (
    RemediationOrchestrationError,
)
from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.domain.entities.incident_evidence import IncidentEvidence
from incident_service.infrastructure.database.postgres_incident_repo import (
    PostgresIncidentRepositoryAdapter,
)
from incident_service.presentation.rest.controllers import (
    ProposalApprovalRequest,
    ProposalExecutionRequest,
    approve_proposal,
    execute_proposal,
    get_proposal_execution_service,
)

HASH = "a" * 64


class _FailingApprovalService:
    def __init__(self, error):
        self.error = error

    def approve(self, **kwargs):
        raise self.error


class _FailingExecutionService:
    def __init__(self, error):
        self.error = error

    def execute(self, **kwargs):
        raise self.error


class ApprovalEndpointMappingTests(unittest.TestCase):
    def _call(self, error=None, body=None):
        request = body or ProposalApprovalRequest(
            proposal_id="proposal-inc-1", proposal_hash=HASH, approved_by="op"
        )
        service = (
            _FailingApprovalService(error)
            if error is not None
            else SimpleNamespace(approve=lambda **kw: {"ok": True, **kw})
        )
        return approve_proposal("inc-1", request, service=service)

    def test_success_passthrough(self):
        result = self._call()
        self.assertTrue(result["ok"])
        self.assertEqual(result["approved_by"], "op")

    def test_failure_status_map(self):
        cases = (
            (ProposalNotFoundError("nope"), 404),
            (ApprovalPolicyError("risk class HIGH not approvable"), 403),
            (TargetRevalidationError("target drift"), 403),
            (ProposalStaleError("ttl exceeded"), 409),
            (ProposalIntegrityError("hash mismatch"), 422),
        )
        for error, expected in cases:
            with self.subTest(error=type(error).__name__):
                with self.assertRaises(HTTPException) as ctx:
                    self._call(error=error)
                self.assertEqual(ctx.exception.status_code, expected)


class ExecutionEndpointMappingTests(unittest.TestCase):
    def _call(self, error=None):
        request = ProposalExecutionRequest(
            proposal_id="proposal-inc-1", proposal_hash=HASH, requested_by="op"
        )
        service = (
            _FailingExecutionService(error)
            if error is not None
            else SimpleNamespace(execute=lambda **kw: {"status": "PR_CREATED", **kw})
        )
        return execute_proposal("inc-1", request, service=service)

    def test_success_passthrough(self):
        result = self._call()
        self.assertEqual(result["status"], "PR_CREATED")

    def test_failure_status_map(self):
        cases = (
            (ProposalNotFoundError("nope"), 404),
            (ProposalIntegrityError("hash mismatch"), 422),
            (ProposalPatchPolicyError("forbidden path"), 422),
            (ProposalNotApprovedError("status PROPOSED"), 409),
            (ProposalAlreadyExecutingError("in flight"), 409),
            (ProposalStaleError("approval expired"), 409),
            (ApprovalPolicyError("policy"), 403),
            (TargetRevalidationError("drift"), 403),
            (RemediationValidationFailedError("validation failed"), 422),
            # patch-stage execution failure is deterministic → 422
            (ProposalExecutionFailedError("git apply refused", stage="patch"), 422),
            # GitHub/remote failure → 502, auditable stage in detail
            (ProposalExecutionFailedError("create failed", stage="pr"), 502),
            # untyped leak-through (defense in depth) → 502
            (RemediationOrchestrationError("workspace blowup"), 502),
        )
        for error, expected in cases:
            with self.subTest(error=type(error).__name__, expected=expected):
                with self.assertRaises(HTTPException) as ctx:
                    self._call(error=error)
                self.assertEqual(ctx.exception.status_code, expected)

    def test_execution_failure_detail_carries_stage(self):
        with self.assertRaises(HTTPException) as ctx:
            self._call(error=ProposalExecutionFailedError("boom", stage="pr"))
        self.assertIn("stage 'pr'", ctx.exception.detail)

    def test_request_schema_rejects_short_hash(self):
        with self.assertRaises(Exception) as ctx:
            ProposalExecutionRequest(
                proposal_id="p", proposal_hash="deadbeef", requested_by="x"
            )
        # pydantic validation error, never reaches the service
        self.assertNotIsInstance(ctx.exception, HTTPException)


class FullChainWiringTests(unittest.TestCase):
    """Controller → real approval + real execution services (orchestrator stub)."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.repository = PostgresIncidentRepositoryAdapter(
            f"sqlite:///{os.path.join(self._temp.name, 'incidents.db')}"
        )
        self.incident = IncidentAggregate("inc-wire-1", "cpu", "HIGH", "gw")
        self.incident.move_to_triage()
        self.incident.attach_evidence(
            IncidentEvidence(
                id="evt-1",
                kind="threshold_breach",
                source="monitoring-service",
                payload={},
            )
        )
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
        self.incident.attach_evidence(
            IncidentEvidence(
                id="deploy-1",
                kind="deployment_run",
                source="deployment-service",
                payload=payload,
            )
        )
        self.repository.save_incident(self.incident)

        from incident_service.application.services.proposal_generation_service import (
            ProposalGenerationService,
        )
        from incident_service.application.services.rca_analyzer import RcaAnalyzerPort

        class FakeAnalyzer(RcaAnalyzerPort):
            def analyze(self, pack):
                return {
                    "root_cause": "cpu saturation",
                    "confidence": 0.93,
                    "evidence_refs": ["evt-1"],
                    "remediation_draft": {
                        "target_file": "app/worker.py",
                        "risk_class": "low",
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

        body = ProposalGenerationService(
            repository=self.repository, analyzer=FakeAnalyzer()
        ).generate("inc-wire-1")
        self.proposal_id = body["proposal"]["id"]
        self.proposal_hash = body["proposal"]["proposal_hash"]

    def tearDown(self):
        self._temp.cleanup()

    def test_approve_then_execute_through_controllers(self):
        from incident_service.application.services.proposal_approval_service import (
            ProposalApprovalService,
        )
        from incident_service.application.services.proposal_execution_service import (
            ProposalExecutionService,
        )

        approval_service = ProposalApprovalService(
            repository=self.repository, ttl_seconds=3600.0
        )
        approved = approve_proposal(
            "inc-wire-1",
            ProposalApprovalRequest(
                proposal_id=self.proposal_id,
                proposal_hash=self.proposal_hash,
                approved_by="alice-operator",
            ),
            service=approval_service,
        )
        self.assertEqual(approved["proposal"]["status"], "APPROVED")

        def orchestrator_factory():
            def execute(incident_id, proposal, repository_slug,
                        validation_profile, stage_callback=None):
                if stage_callback:
                    stage_callback("workspace.created", {"workspace": "ws"})
                    stage_callback(
                        "pr.created",
                        {"pull_request_url": "https://github.example/pull/9"},
                    )
                return SimpleNamespace(
                    proposal_id=proposal.id,
                    incident_id=incident_id,
                    source_sha=proposal.source_sha,
                    branch_name="automation/remediation/x/y",
                    commit_sha="e" * 40,
                    pull_request_url="https://github.example/pull/9",
                    validation_result=SimpleNamespace(
                        passed=True,
                        steps=(SimpleNamespace(name="unit", passed=True),),
                    ),
                )

            return SimpleNamespace(execute=execute)

        execution_service = ProposalExecutionService(
            repository=self.repository,
            orchestrator_factory=orchestrator_factory,
            ttl_seconds=3600.0,
        )
        executed = execute_proposal(
            "inc-wire-1",
            ProposalExecutionRequest(
                proposal_id=self.proposal_id,
                proposal_hash=self.proposal_hash,
                requested_by="alice-operator",
            ),
            service=execution_service,
        )
        self.assertEqual(executed["status"], "PR_CREATED")
        self.assertEqual(
            executed["proposal"]["pull_request_url"],
            "https://github.example/pull/9",
        )

        # persisted after controller return (fresh reload)
        restored = self.repository.get_incident_by_id("inc-wire-1")
        self.assertEqual(restored.patch_proposals[0].status, "PR_CREATED")

    def test_provider_functions_are_overridable_dependencies(self):
        # the endpoints depend on module-level providers (FastAPI override seam)
        import incident_service.presentation.rest.controllers as controllers_module

        self.assertTrue(
            hasattr(controllers_module, "get_proposal_approval_service")
        )
        self.assertTrue(
            hasattr(controllers_module, "get_proposal_execution_service")
        )
        # default provider builds a real execution service bound to the
        # same orchestrator factory as the legacy remediation path
        from incident_service.application.dependencies import (
            get_incident_repository,
        )

        try:
            with patch.dict(
                os.environ,
                {
                    "INCIDENT_DATABASE_URL": (
                        f"sqlite:///{self._temp.name}/provider.db"
                    )
                },
            ):
                service = get_proposal_execution_service()
        finally:
            # the repository provider is lru_cached — do not leak the
            # temp instance into other tests in the same process
            get_incident_repository.cache_clear()
        self.assertEqual(service.validation_profile, "incident_service")
        self.assertIs(
            service.orchestrator_factory,
            controllers_module.get_remediation_orchestrator,
        )


if __name__ == "__main__":
    unittest.main()
