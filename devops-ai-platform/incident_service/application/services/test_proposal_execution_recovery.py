"""Phase 6.2.1: recovery semantics of ProposalExecutionService.

Crashed durable states are built against the REAL adapter (claim +
progress writes), then recovery is driven through the real service with a
recording orchestrator and a deterministic remote inspector — proving that
recovery reconciles instead of blindly replaying side effects.
"""

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from incident_service.application.failures import (
    ExecutionLeaseUnavailable,
    ProposalIntegrityError,
    ProposalStaleError,
    RemoteBranchConflict,
    RemoteReconciliationFailed,
    TargetRevalidationError,
)
from incident_service.application.services.proposal_execution_service import (
    EXECUTION_EVIDENCE_KIND,
    ProposalExecutionService,
)
from incident_service.application.services.test_proposal_lease_coordination import (
    _seed_incident,
)
from incident_service.infrastructure.database.postgres_incident_repo import (
    PostgresIncidentRepositoryAdapter,
    execution_claims_table,
)
from sqlalchemy import update as sa_update

BRANCH = "automation/remediation/inc-lease-1/proposal-inc-lease-1"
COMMIT = "e" * 40


class FakeInspector:
    def __init__(self):
        self.result = None  # sha | None
        self.error = None
        self.calls = []

    def inspect_remote_branch(self, repository_slug, branch, oauth_token=""):
        self.calls.append((repository_slug, branch))
        if self.error is not None:
            raise self.error
        return self.result


class RecordingOrchestrator:
    def __init__(self, calls, error=None, commit_sha=COMMIT):
        self.calls = calls
        self.error = error
        self.commit_sha = commit_sha

    def execute(self, *, incident_id, proposal, repository_slug,
                validation_profile, stage_callback=None):
        self.calls.append(("execute", proposal.execution_stage))
        if stage_callback:
            stage_callback("workspace.created", {"workspace": "ws"})
        if self.error is not None:
            # crash early: before any commit/remote boundary
            raise self.error
        if stage_callback:
            stage_callback("commit.created", {
                "commit_sha": self.commit_sha,
                "branch": BRANCH,
            })
        if stage_callback:
            stage_callback("remote.published", {"branch": BRANCH})
            stage_callback("remote.verified", {"branch": BRANCH, "verified": True})
            stage_callback("pr.discovery", {"matches": 0})
            stage_callback("pr.created", {
                "pull_request_url": "https://github.example/pull/1",
            })
        return _Result(self.commit_sha)

    def reconcile_and_create_pr(self, *, incident_id, proposal, repository_slug,
                                stage_callback=None, **kwargs):
        self.calls.append(("reconcile", proposal.execution_stage))
        if stage_callback:
            stage_callback("remote.published", {"branch": BRANCH, "recovered": True})
            stage_callback("remote.verified", {"branch": BRANCH, "verified": True})
            stage_callback("pr.discovery", {"matches": 0})
            stage_callback("pr.reconciled", {
                "pull_request_url": "https://github.example/pull/9",
            })
        return "https://github.example/pull/9"


class _Result:
    def __init__(self, commit_sha):
        self.commit_sha = commit_sha
        self.branch_name = BRANCH
        self.pull_request_url = "https://github.example/pull/1"
        self.validation_result = None


class ExecutionRecoveryTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        url = f"sqlite:///{os.path.join(self._temp.name, 'rec.db')}"
        self.repository = PostgresIncidentRepositoryAdapter(url)
        seed, self.proposal_hash = _seed_incident()
        self.repository.save_incident(seed)
        self.inspector = FakeInspector()
        self.calls = []
        self.pending_error = None
        self.commit_sha = COMMIT

        def factory():
            return RecordingOrchestrator(
                self.calls, error=self.pending_error, commit_sha=self.commit_sha
            )

        self.factory = factory
        self.service = self._service()

    def _service(self, ttl=3600.0, lease=600.0):
        return ProposalExecutionService(
            repository=self.repository,
            orchestrator_factory=self.factory,
            ttl_seconds=ttl,
            lease_seconds=lease,
            lease_owner="worker-recovery",
            remote_inspector=self.inspector,
        )

    def _execute(self, service=None):
        return (service or self.service).execute(
            incident_id="inc-lease-1",
            proposal_id="proposal-inc-lease-1",
            proposal_hash=self.proposal_hash,
            requested_by="alice-operator",
        )

    def _proposal(self):
        return self.repository.get_incident_by_id(
            "inc-lease-1"
        ).patch_proposals[0]

    def _claim(self):
        return self.repository.get_execution_claim(
            "inc-lease-1", "proposal-inc-lease-1"
        ) or {}

    def _evidence(self, kind=EXECUTION_EVIDENCE_KIND):
        incident = self.repository.get_incident_by_id("inc-lease-1")
        return [e for e in incident.evidence if e.kind == kind]

    # --- durable crashed-state builders ---------------------------------
    def _crash_at(self, stage, commit_sha=COMMIT, branch=BRANCH, owner="dead-worker"):
        """Simulate a worker that claimed, progressed, and died."""
        now = datetime.now(timezone.utc)
        reason, incident = self.repository.claim_execution_lease(
            "inc-lease-1",
            "proposal-inc-lease-1",
            self.proposal_hash,
            owner=owner,
            now=now,
            lease_seconds=600.0,
        )
        assert reason == "claimed", reason
        updates = {}
        if commit_sha:
            updates["commit_sha"] = commit_sha
        if branch:
            updates["branch_name"] = branch
        # stages must be persisted in order — replay up to `stage`
        order = [
            "CLAIMED",
            "WORKSPACE_CREATED",
            "PATCH_APPLIED",
            "VALIDATION_STARTED",
            "VALIDATION_PASSED",
            "COMMIT_CREATED",
            "REMOTE_PUBLISHED",
            "REMOTE_VERIFIED",
            "PR_DISCOVERY",
        ]
        target_index = order.index(stage)
        for name in order[: target_index + 1]:
            kwargs = dict(updates) if name == "COMMIT_CREATED" else {}
            ok = self.repository.persist_execution_progress(
                "inc-lease-1",
                "proposal-inc-lease-1",
                owner,
                stage=name,
                now=now,
                lease_seconds=600.0,
                **kwargs,
            )
            assert ok, name
        # expire the lease: the worker is dead
        with self.repository.engine.begin() as connection:
            connection.execute(
                sa_update(execution_claims_table)
                .where(
                    execution_claims_table.c.incident_id == "inc-lease-1"
                )
                .values(
                    lease_expires_at=now - timedelta(seconds=10_000)
                )
            )

    # --- scenario B: crash after EXECUTING --------------------------------
    def test_crash_after_executing_is_recoverable(self):
        self.pending_error = RuntimeError("worker crashed mid-run")
        with self.assertRaises(Exception):
            self._execute()
        proposal = self._proposal()
        self.assertEqual(proposal.status, "EXECUTION_FAILED")
        claim = self._claim()
        self.assertEqual(claim["state"], "FREE", "failure must release the lease")
        self.assertEqual(claim["stage"], "FAILED")

        self.pending_error = None
        body = self._execute()
        self.assertEqual(body["status"], "PR_CREATED")
        self.assertEqual(self._proposal().execution_attempts, 2)
        self.assertEqual(
            [c[0] for c in self.calls].count("execute"), 2
        )

    # --- scenario C/D: crash after commit (+push) --------------------------
    def test_resume_reconciles_remote_and_skips_workspace(self):
        self._crash_at("COMMIT_CREATED")
        self.inspector.result = COMMIT  # remote holds the persisted commit

        body = self._execute()
        self.assertEqual(body["status"], "PR_CREATED")
        methods = [c[0] for c in self.calls]
        self.assertIn("reconcile", methods)
        self.assertNotIn("execute", methods, "resume must not redo the workspace")
        proposal = self._proposal()
        self.assertEqual(proposal.commit_sha, COMMIT)  # stable commit identity
        self.assertEqual(proposal.execution_attempts, 2)
        self.assertTrue(proposal.pull_request_url.endswith("/pull/9"))
        # recovery events were emitted
        # (structured logs are asserted via evidence durable stage)
        self.assertEqual(self._claim()["stage"], "COMPLETED")

    def test_commit_never_published_restarts_safely(self):
        self._crash_at("COMMIT_CREATED")
        self.inspector.result = None  # push never happened

        self.commit_sha = "f" * 40  # a fresh workspace commit on restart
        body = self._execute()
        self.assertEqual(body["status"], "PR_CREATED")
        methods = [c[0] for c in self.calls]
        self.assertIn("execute", methods)
        self.assertNotIn("reconcile", methods)
        self.assertEqual(self._proposal().commit_sha, "f" * 40)

    def test_vanished_remote_branch_fails_closed_with_durable_record(self):
        self._crash_at("REMOTE_PUBLISHED")
        self.inspector.result = None

        with self.assertRaises(RemoteReconciliationFailed):
            self._execute()
        self.assertEqual(self.calls, [], "no orchestrator side effects")
        proposal = self._proposal()
        self.assertEqual(proposal.status, "EXECUTION_FAILED")
        self.assertEqual(proposal.last_failure_stage, "reconciliation")
        conflicts = [
            e
            for e in self._evidence()
            if e.payload.get("status") == "RECONCILIATION_CONFLICT"
        ]
        self.assertEqual(len(conflicts), 1)

    def test_wrong_remote_sha_fails_closed_no_retarget(self):
        self._crash_at("COMMIT_CREATED")
        self.inspector.result = "b" * 40  # unexpected remote commit

        with self.assertRaises(RemoteBranchConflict):
            self._execute()
        self.assertEqual(self.calls, [])
        proposal = self._proposal()
        self.assertEqual(proposal.status, "EXECUTION_FAILED")
        self.assertEqual(proposal.commit_sha, COMMIT, "persisted commit kept")
        conflicts = [
            e
            for e in self._evidence()
            if e.payload.get("status") == "RECONCILIATION_CONFLICT"
        ]
        self.assertEqual(len(conflicts), 1)

    def test_inspection_error_fails_closed(self):
        self._crash_at("REMOTE_PUBLISHED")
        self.inspector.error = RemoteReconciliationFailed("network unreachable")
        with self.assertRaises(RemoteReconciliationFailed):
            self._execute()
        self.assertEqual(self.calls, [])

    # --- revalidation gates during recovery --------------------------------
    def test_stale_approval_blocks_recovery(self):
        self._crash_at("COMMIT_CREATED")
        self.inspector.result = COMMIT
        service = self._service(ttl=0.0)
        with self.assertRaises(ProposalStaleError):
            self._execute(service=service)
        self.assertEqual(self.calls, [])
        self.assertEqual(self._claim()["attempt"], 1, "no new claim")

    def test_tampered_proposal_blocks_recovery_before_inspection(self):
        self._crash_at("COMMIT_CREATED")
        self.inspector.result = COMMIT
        incident = self.repository.get_incident_by_id("inc-lease-1")
        incident.patch_proposals[0].diff_patch_payload += "\n# evil\n"
        self.repository.save_incident(incident)

        with self.assertRaises(ProposalIntegrityError):
            self._execute()
        self.assertEqual(self.inspector.calls, [], "no remote inspection")
        self.assertEqual(self.calls, [])

    def test_deployment_drift_blocks_recovery_without_new_claim(self):
        self._crash_at("COMMIT_CREATED")
        self.inspector.result = COMMIT
        incident = self.repository.get_incident_by_id("inc-lease-1")
        incident.evidence = [
            item for item in incident.evidence if item.id != "deploy-1"
        ]
        from incident_service.application.services.test_proposal_approval_service import (
            _deployment_evidence,
        )

        incident.attach_evidence(_deployment_evidence(sha="b" * 40))
        self.repository.save_incident(incident)

        with self.assertRaises(TargetRevalidationError):
            self._execute()
        self.assertEqual(self._claim()["attempt"], 1)
        self.assertEqual(self.calls, [])

    # --- lease lost mid-run -------------------------------------------------
    def test_lost_lease_mid_run_fails_loud_without_clobbering(self):
        stolen = {"done": False}

        class StealingOrchestrator:
            def execute(orch_self, *, incident_id, proposal, repository_slug,
                        validation_profile, stage_callback=None):
                stage_callback("workspace.created", {"workspace": "ws"})
                if not stolen["done"]:
                    stolen["done"] = True
                    # another worker takes over the lease (simulated theft)
                    with self.repository.engine.begin() as connection:
                        connection.execute(
                            sa_update(execution_claims_table)
                            .where(
                                execution_claims_table.c.incident_id
                                == "inc-lease-1"
                            )
                            .values(lease_owner="thief-worker")
                        )
                # next durable stage write must detect ownership loss
                stage_callback("patch.applied", {"target_filepath": "app/w.py"})
                raise AssertionError("guard should have aborted execution")

        self.factory = lambda: StealingOrchestrator()
        service = self._service()

        with self.assertRaises(ExecutionLeaseUnavailable):
            self._execute(service=service)
        claim = self._claim()
        self.assertEqual(claim["lease_owner"], "thief-worker")
        self.assertEqual(claim["state"], "LEASED")
        # our failed attempt must NOT have written anything over the takeover
        self.assertEqual(self._proposal().status, "EXECUTING")

    # --- reconciliation conflict retry stays deterministic ------------------
    def test_conflict_retry_repeats_same_fail_closed_decision(self):
        self._crash_at("COMMIT_CREATED")
        self.inspector.result = "b" * 40
        with self.assertRaises(RemoteBranchConflict):
            self._execute()
        with self.assertRaises(RemoteBranchConflict):
            self._execute()
        conflicts = [
            e
            for e in self._evidence()
            if e.payload.get("status") == "RECONCILIATION_CONFLICT"
        ]
        # deterministic: the same conflict state yields the same durable
        # record (evidence ids are execution-scoped, not request-scoped)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(self._proposal().status, "EXECUTION_FAILED")
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
