"""Unit/integration tests: controlled proposal execution (Phase 6.2 §2/§15/§21/§23).

The real approval + execution services run against a persisted sqlite
incident; only the heavyweight orchestration (workspace → git → PR) is a
recording stub, so policy, lifecycle, idempotency, failure classification,
audit evidence and concurrency semantics are all exercised for real.
"""

import os
import tempfile
import threading
import unittest
from types import SimpleNamespace

from incident_service.application.failures import (
    ProposalExecutionFailedError,
    ProposalIntegrityError,
    ProposalNotApprovedError,
    ProposalStaleError,
    RemediationValidationFailedError,
    TargetRevalidationError,
)
from incident_service.application.services.proposal_approval_service import (
    ProposalApprovalService,
)
from incident_service.application.services.proposal_execution_policy import (
    execution_id_for,
)
from incident_service.application.services.proposal_execution_service import (
    EXECUTION_EVIDENCE_KIND,
    ProposalExecutionService,
)
from incident_service.application.services.proposal_generation_service import (
    ProposalGenerationService,
)
from incident_service.application.services.rca_analyzer import RcaAnalyzerPort
from incident_service.application.services.remediation_orchestration_service import (
    RemediationOrchestrationError,
)
from incident_service.application.services.remediation_patch_executor import (
    PatchApplicationRejectedError,
)
from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.domain.entities.incident_evidence import IncidentEvidence
from incident_service.infrastructure.database.postgres_incident_repo import (
    PostgresIncidentRepositoryAdapter,
)
from incident_service.infrastructure.source_provider.github_pr_client import (
    PRCreationFailedException,
)

GOOD_RESULT = {
    "root_cause": "cpu saturation after rollout",
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


class FakeAnalyzer(RcaAnalyzerPort):
    def analyze(self, evidence_pack):
        return GOOD_RESULT


def _deployment_evidence(sha: str = "a" * 40) -> IncidentEvidence:
    from shared_kernel.domain.provenance import build_provenance_record

    payload = {
        "deployment_run_id": "run-1",
        "repository_name": "acme/checkout",
        "source_revision": {"head_sha": sha, "commits": []},
        "state": "DEPLOYED",
        "artifact_hash": "c" * 64,
        "plan_hash": "d" * 64,
    }
    payload["provenance"] = build_provenance_record(
        repository_name=payload["repository_name"],
        source_sha=sha,
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


class RecordingOrchestrator:
    """Stands in for RemediationOrchestrationService.execute exactly.

    On error, fails at the stage that error represents: before
    ``pr.created`` for GitHub failures, before ``patch.applied`` for patch
    rejections, before ``commit.created`` for validation failures.
    """

    _RAISE_BEFORE = {
        PRCreationFailedException: "pr.created",
        PatchApplicationRejectedError: "patch.applied",
        RemediationOrchestrationError: "commit.created",
    }

    def __init__(self, calls, error=None, delay=0.0):
        self.calls = calls
        self.error = error
        self.delay = delay

    def execute(self, incident_id, proposal, repository_slug, validation_profile,
                stage_callback=None, before_side_effect=None):
        self.calls.append(
            {
                "incident_id": incident_id,
                "proposal_id": proposal.id,
                "repository_slug": repository_slug,
                "validation_profile": validation_profile,
            }
        )
        if self.delay:
            threading.Event().wait(self.delay)
        raise_before = self._RAISE_BEFORE.get(
            type(self.error), "commit.created"
        )
        stages = (
            ("workspace.created", {"workspace": "ws-abc"}),
            ("patch.applied", {"target_filepath": proposal.target_filepath}),
            ("validation.started", {"profile": validation_profile}),
            (
                "validation.completed",
                {"passed": True, "steps": ["incident-service-unit-tests"]},
            ),
            (
                "commit.created",
                {"commit_sha": "e" * 40, "branch": "automation/remediation/x/y"},
            ),
            (
                "pr.created",
                {"pull_request_url": "https://github.example/acme/checkout/pull/1"},
            ),
        )
        for stage, metadata in stages:
            if self.error is not None and stage == raise_before:
                raise self.error
            if stage_callback is not None:
                stage_callback(stage, dict(metadata))
        if self.error is not None:
            raise self.error
        return SimpleNamespace(
            proposal_id=proposal.id,
            incident_id=incident_id,
            source_sha=proposal.source_sha,
            branch_name=f"automation/remediation/{incident_id}/{proposal.id}",
            commit_sha="e" * 40,
            pull_request_url="https://github.example/acme/checkout/pull/1",
            patch_result=SimpleNamespace(applied=True),
            validation_result=SimpleNamespace(
                passed=True,
                steps=(SimpleNamespace(name="incident-service-unit-tests",
                                        passed=True),),
            ),
            commit_result=SimpleNamespace(commit_sha="e" * 40),
        )


class ExecutionServiceTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.repository = PostgresIncidentRepositoryAdapter(
            f"sqlite:///{os.path.join(self._temp.name, 'incidents.db')}"
        )
        self.incident = IncidentAggregate("inc-ex-1", "cpu breach", "HIGH", "gw")
        self.incident.move_to_triage()
        self.incident.attach_evidence(
            IncidentEvidence(
                id="evt-1",
                kind="threshold_breach",
                source="monitoring-service",
                payload={"metric": "cpu_percent"},
            )
        )
        self.incident.attach_evidence(_deployment_evidence())
        self.repository.save_incident(self.incident)

        generated = ProposalGenerationService(
            repository=self.repository, analyzer=FakeAnalyzer()
        ).generate("inc-ex-1")
        self.proposal_id = generated["proposal"]["id"]
        self.proposal_hash = generated["proposal"]["proposal_hash"]

        self.calls = []
        self.factory_calls = []
        self.pending_error = None

        def factory():
            orchestrator = RecordingOrchestrator(
                self.calls, error=self.pending_error
            )
            self.factory_calls.append(orchestrator)
            return orchestrator

        self.factory = factory

    def tearDown(self):
        self._temp.cleanup()

    def _approve(self, ttl=3600.0):
        return ProposalApprovalService(
            repository=self.repository, ttl_seconds=ttl
        ).approve(
            incident_id="inc-ex-1",
            proposal_id=self.proposal_id,
            proposal_hash=self.proposal_hash,
            approved_by="alice-operator",
        )

    def _service(self, ttl=3600.0):
        return ProposalExecutionService(
            repository=self.repository,
            orchestrator_factory=self.factory,
            ttl_seconds=ttl,
            validation_profile="incident_service",
        )

    def _execute(self, service=None, requested_by="alice-operator"):
        return (service or self._service()).execute(
            incident_id="inc-ex-1",
            proposal_id=self.proposal_id,
            proposal_hash=self.proposal_hash,
            requested_by=requested_by,
        )

    def _proposal(self):
        return self.repository.get_incident_by_id("inc-ex-1").patch_proposals[0]

    def _exec_evidence(self):
        incident = self.repository.get_incident_by_id("inc-ex-1")
        return [e for e in incident.evidence if e.kind == EXECUTION_EVIDENCE_KIND]

    # --- success path ---------------------------------------------------
    def test_approved_execution_reaches_pr_created_with_audit_evidence(self):
        self._approve()
        body = self._execute(requested_by="alice-operator")

        self.assertEqual(body["status"], "PR_CREATED")
        self.assertFalse(body["idempotent"])
        proposal = self._proposal()
        self.assertEqual(proposal.status, "PR_CREATED")
        self.assertEqual(proposal.commit_sha, "e" * 40)
        self.assertEqual(
            proposal.branch_name,
            f"automation/remediation/inc-ex-1/{self.proposal_id}",
        )
        self.assertTrue(proposal.pull_request_url)

        # deterministic execution identity (§21)
        self.assertEqual(
            proposal.execution_id,
            execution_id_for(self.proposal_id, self.proposal_hash),
        )

        # orchestration received trusted inputs only
        call = self.calls[0]
        self.assertEqual(call["repository_slug"], "acme/checkout")
        self.assertEqual(call["validation_profile"], "incident_service")
        self.assertEqual(call["incident_id"], "inc-ex-1")

        # evidence: machine readable, no secrets, stages recorded
        evidence = self._exec_evidence()
        self.assertEqual(len(evidence), 1)
        payload = evidence[0].payload
        self.assertEqual(payload["status"], "PR_CREATED")
        self.assertEqual(payload["execution_id"], proposal.execution_id)
        self.assertEqual(payload["attempt"], 1)
        self.assertEqual(payload["repository"], "acme/checkout")
        self.assertEqual(payload["source_sha"], "a" * 40)
        self.assertEqual(payload["approved_by"], "alice-operator")
        self.assertEqual(payload["requested_by"], "alice-operator")
        self.assertEqual(payload["pull_request_url"], proposal.pull_request_url)
        stage_names = [entry["stage"] for entry in payload["stages"]]
        self.assertIn("workspace.created", stage_names)
        self.assertIn("pr.created", stage_names)
        self.assertEqual(payload["validation"]["profile"], "incident_service")

    def test_caller_interface_never_accepts_repository_or_sha(self):
        import inspect

        params = inspect.signature(self._service().execute).parameters
        for forbidden in ("repository", "repository_slug", "source_sha",
                          "branch", "workspace", "commands"):
            self.assertNotIn(forbidden, params)

    def test_repeat_after_success_reconciles_same_pr(self):
        self._approve()
        first = self._execute()
        second = self._execute()
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        self.assertEqual(first["execution_id"], second["execution_id"])
        # orchestrator ran exactly once — no second PR attempt
        self.assertEqual(len(self.factory_calls), 1)
        self.assertEqual(len(self.calls), 1)
        # still exactly one execution evidence record
        self.assertEqual(len(self._exec_evidence()), 1)
        self.assertEqual(self._proposal().execution_attempts, 1)

    # --- pre-side-effect gates -----------------------------------------
    def test_unapproved_proposal_cannot_execute(self):
        with self.assertRaises(ProposalNotApprovedError):
            self._execute()
        self.assertEqual(self.factory_calls, [])
        self.assertEqual(self._proposal().status, "PROPOSED")

    def test_tampered_proposal_rejected_before_side_effects(self):
        self._approve()
        incident = self.repository.get_incident_by_id("inc-ex-1")
        incident.patch_proposals[0].diff_patch_payload += "\n# evil\n"
        self.repository.save_incident(incident)
        with self.assertRaises(ProposalIntegrityError):
            self._execute()
        self.assertEqual(self.factory_calls, [])
        self.assertEqual(self._proposal().status, "APPROVED")

    def test_stale_approval_rejected_before_side_effects(self):
        self._approve()
        with self.assertRaises(ProposalStaleError):
            self._execute(service=self._service(ttl=0.0))
        self.assertEqual(self.factory_calls, [])
        self.assertEqual(self._proposal().status, "APPROVED")

    def test_forbidden_path_tamper_detected_before_side_effects(self):
        self._approve()
        incident = self.repository.get_incident_by_id("inc-ex-1")
        incident.patch_proposals[0].target_filepath = "../../etc/passwd"
        self.repository.save_incident(incident)
        with self.assertRaises(ProposalIntegrityError):
            self._execute()
        self.assertEqual(self.factory_calls, [])
        self.assertEqual(self._proposal().status, "APPROVED")

    def test_deployment_drift_after_approval_aborts_without_retarget(self):
        self._approve()
        incident = self.repository.get_incident_by_id("inc-ex-1")
        incident.evidence = [
            item for item in incident.evidence if item.id != "deploy-1"
        ]
        incident.attach_evidence(_deployment_evidence(sha="b" * 40))
        self.repository.save_incident(incident)
        with self.assertRaises(TargetRevalidationError):
            self._execute()
        self.assertEqual(self.factory_calls, [])
        proposal = self._proposal()
        self.assertEqual(proposal.status, "APPROVED")
        self.assertEqual(proposal.source_sha, "a" * 40)  # never retargeted

    # --- failure matrix --------------------------------------------------
    def test_validation_failure_records_execution_failed_without_pr(self):
        self._approve()
        self.pending_error = RemediationOrchestrationError(
            "remediation validation failed; refusing commit and publication"
        )
        with self.assertRaises(RemediationValidationFailedError):
            self._execute()
        proposal = self._proposal()
        self.assertEqual(proposal.status, "EXECUTION_FAILED")
        self.assertEqual(proposal.last_failure_stage, "validation.completed")
        self.assertFalse(proposal.pull_request_url)
        evidence = self._exec_evidence()
        self.assertEqual(evidence[0].payload["status"], "EXECUTION_FAILED")

    def test_github_failure_is_auditable_execution_failed(self):
        self._approve()
        self.pending_error = PRCreationFailedException("create_pull_request down")
        with self.assertRaises(ProposalExecutionFailedError) as ctx:
            self._execute()
        self.assertEqual(ctx.exception.stage, "pr")
        proposal = self._proposal()
        self.assertEqual(proposal.status, "EXECUTION_FAILED")
        self.assertEqual(proposal.last_failure_stage, "pr")
        payload = self._exec_evidence()[0].payload
        self.assertEqual(payload["failure_type"], "PRCreationFailedException")
        self.assertFalse(proposal.pull_request_url)

    def test_patch_rejection_classified_as_patch_stage(self):
        self._approve()
        self.pending_error = PatchApplicationRejectedError("git apply refused")
        with self.assertRaises(ProposalExecutionFailedError) as ctx:
            self._execute()
        self.assertEqual(ctx.exception.stage, "patch")
        self.assertEqual(self._proposal().status, "EXECUTION_FAILED")

    def test_failure_reason_is_redacted(self):
        self._approve()
        self.pending_error = RuntimeError(
            "push failed with Authorization: Bearer sk-abc123secret"
        )
        with self.assertRaises(ProposalExecutionFailedError):
            self._execute()
        proposal = self._proposal()
        self.assertNotIn("sk-abc123secret", proposal.last_failure_reason)
        self.assertIn("[REDACTED]", proposal.last_failure_reason)

    def test_retry_after_failure_can_succeed(self):
        self._approve()
        self.pending_error = RemediationOrchestrationError(
            "remediation validation failed; refusing commit and publication"
        )
        with self.assertRaises(RemediationValidationFailedError):
            self._execute()

        self.pending_error = None  # transient cause gone
        body = self._execute()
        self.assertEqual(body["status"], "PR_CREATED")
        proposal = self._proposal()
        self.assertEqual(proposal.execution_attempts, 2)
        self.assertEqual(proposal.execution_id,
                         execution_id_for(self.proposal_id, self.proposal_hash))
        attempts = sorted(
            e.payload["attempt"] for e in self._exec_evidence()
        )
        self.assertEqual(attempts, [1, 2])

    # --- concurrency domain invariant ------------------------------------
    def test_two_concurrent_executions_yield_one_execution_identity(self):
        self._approve()
        self.calls.clear()

        def factory():
            orchestrator = RecordingOrchestrator(self.calls, delay=0.15)
            self.factory_calls.append(orchestrator)
            return orchestrator

        service = ProposalExecutionService(
            repository=self.repository,
            orchestrator_factory=factory,
            ttl_seconds=3600.0,
            validation_profile="incident_service",
        )
        results, errors = [], []

        def worker():
            try:
                results.append(self._execute(service=service))
            except Exception as exc:  # noqa: BLE001 - recorded for asserts
                errors.append(exc)

        t1 = threading.Thread(target=worker)
        t2 = threading.Thread(target=worker)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        # one orchestrator run — the loser reconciles the stored PR (§21/§26)
        self.assertEqual(len(self.calls), 1)
        execution_ids = {result["execution_id"] for result in results}
        self.assertEqual(len(execution_ids), 1)
        statuses = {result["status"] for result in results}
        self.assertEqual(statuses, {"PR_CREATED"})
        self.assertEqual(self._proposal().status, "PR_CREATED")
        self.assertEqual(len(self._exec_evidence()), 1)


if __name__ == "__main__":
    unittest.main()
