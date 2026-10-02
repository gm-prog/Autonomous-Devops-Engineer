"""Phase 6.2.1A: active lease liveness (heartbeat) tests.

Real SQLite claim store, real CAS renewal, injected tiny intervals —
proving a worker keeps its lease during long bounded operations, detects
owner loss/store uncertainty, refuses the next side-effecting stage, and
never leaks heartbeat threads.
"""

import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from incident_service.application.failures import ExecutionLeaseUnavailable
from incident_service.application.services.proposal_execution_policy import (
    HEARTBEAT_SECONDS_ENV,
    load_heartbeat_seconds,
)
from incident_service.application.services.proposal_execution_service import (
    ProposalExecutionService,
)
from incident_service.application.services.remediation_orchestration_service import (
    RemediationStageGuardError,
)
from incident_service.application.services.test_proposal_lease_coordination import (
    _seed_incident,
)
from incident_service.infrastructure.database.postgres_incident_repo import (
    PostgresIncidentRepositoryAdapter,
    execution_claims_table,
)
from sqlalchemy import update as sa_update

INCIDENT_ID = "inc-lease-1"
PROPOSAL_ID = "proposal-inc-lease-1"
BRANCH = "automation/remediation/inc-lease-1/proposal-inc-lease-1"


class _Result:
    def __init__(self, commit_sha):
        self.commit_sha = commit_sha
        self.branch_name = BRANCH
        self.pull_request_url = "https://github.com/owner/repo/pull/1"
        self.validation_result = None


class CountingRepository(PostgresIncidentRepositoryAdapter):
    """Adapter that records renewals and can simulate store outages."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.renew_calls = 0
        self.renew_error = None
        # Test-only synchronization: a long-operation test can require
        # N successful renewals AFTER a named operation boundary without
        # relying on scheduler-sensitive wall-clock sleeps.
        self.renew_target = 0
        self.renewed_event = threading.Event()
        self.renew_gate = None
        self.renewals_after_gate = 0

    def renew_execution_lease(self, incident_id, proposal_id, owner, *,
                              now, lease_seconds):
        if self.renew_error is not None:
            raise self.renew_error
        self.renew_calls += 1
        renewed = super().renew_execution_lease(
            incident_id, proposal_id, owner,
            now=now, lease_seconds=lease_seconds,
        )
        if renewed and (
            self.renew_gate is None or self.renew_gate.is_set()
        ):
            self.renewals_after_gate += 1
            if (
                self.renew_target > 0
                and self.renewals_after_gate >= self.renew_target
            ):
                self.renewed_event.set()
        return renewed

            incident_id, proposal_id, owner,
            now=now, lease_seconds=lease_seconds,
        )


def _full_sequence(orchestrator, stages, *, hold_seconds=0.0,
                   hold_after="validation.started", hold_event=None,
                   hold_started=None, notify_guard=None):
    """Replay the real stage sequence, optionally holding one boundary."""
    order = [
        ("workspace.created", {"workspace": "ws"}),
        ("patch.applied", {"target_filepath": "app/w.py"}),
        ("validation.started", {"profile": "e2e"}),
        ("validation.completed", {"profile": "e2e", "passed": True, "steps": []}),
        ("commit.created", {"commit_sha": "e" * 40, "branch": BRANCH}),
        ("remote.published", {"branch": BRANCH}),
        ("remote.verified", {"branch": BRANCH, "verified": True}),
        ("pr.discovery", {"matches": 0}),
        ("pr.created", {"pull_request_url": "https://github.com/owner/repo/pull/1"}),
    ]
    for name, metadata in order:
        if notify_guard is not None:
            notify_guard(name)
        orchestrator.stage_callback(name, dict(metadata))
        stages.append(name)
        if name == hold_after:
            # The boundary is persisted first. Signal its start, then keep
            # the operation open until the heartbeat has actually completed
            # the required renewals. This proves liveness without a fixed
            # sleep whose outcome depends on host scheduling.
            if hold_started is not None:
                hold_started.set()
            if hold_event is not None:
                if not hold_event.wait(timeout=5.0):
                    raise AssertionError(
                        "heartbeat did not complete the required renewals "
                        "while the bounded operation was held"
                    )
            elif hold_seconds:
                time.sleep(hold_seconds)


class _Orchestrator:
    def __init__(self, *, hold_seconds=0.0, hold_after="validation.started",
                 hold_event=None, hold_started=None):
        self.stage_callback = None
        self.stages = []
        self.hold_seconds = hold_seconds
        self.hold_after = hold_after
        self.hold_event = hold_event
        self.hold_started = hold_started

    def execute(self, *, incident_id, proposal, repository_slug,
                validation_profile, stage_callback=None,
                before_side_effect=None):
        self.stage_callback = stage_callback
        _full_sequence(
            self, self.stages,
            hold_seconds=self.hold_seconds,
            hold_after=self.hold_after,
            hold_event=self.hold_event,
            hold_started=self.hold_started,
        )
        return _Result("e" * 40)

    def reconcile_and_create_pr(self, **kwargs):
        raise AssertionError("not used in liveness tests")


class HeartbeatIntervalPolicyTests(unittest.TestCase):
    def test_derived_default_is_below_lease_half(self):
        with patch.dict(os.environ, {HEARTBEAT_SECONDS_ENV: ""}):
            self.assertEqual(load_heartbeat_seconds(600.0), 200.0)
            self.assertLess(load_heartbeat_seconds(600.0), 600.0 / 2)

    def test_env_override_must_stay_below_lease_half(self):
        with patch.dict(os.environ, {HEARTBEAT_SECONDS_ENV: "10"}):
            self.assertEqual(load_heartbeat_seconds(600.0), 10.0)
        with patch.dict(os.environ, {HEARTBEAT_SECONDS_ENV: "300"}):
            with self.assertRaises(ValueError):
                load_heartbeat_seconds(600.0)
        with patch.dict(os.environ, {HEARTBEAT_SECONDS_ENV: "0"}):
            with self.assertRaises(ValueError):
                load_heartbeat_seconds(600.0)
        with patch.dict(os.environ, {HEARTBEAT_SECONDS_ENV: "nan"}):
            with self.assertRaises(ValueError):
                load_heartbeat_seconds(600.0)

    def test_invalid_lease_fails_fast(self):
        with self.assertRaises(ValueError):
            load_heartbeat_seconds(0.0)

    def test_service_rejects_invalid_explicit_interval(self):
        with self.assertRaises(ValueError):
            ProposalExecutionService(
                repository=object(),
                orchestrator_factory=lambda: None,
                lease_seconds=10.0,
                heartbeat_interval=5.0,  # == lease/2, not below
            )
        with self.assertRaises(ValueError):
            ProposalExecutionService(
                repository=object(),
                orchestrator_factory=lambda: None,
                lease_seconds=10.0,
                heartbeat_interval=-1.0,
            )


class RenewalPrimitiveTests(unittest.TestCase):
    """CAS semantics of the durable renewal itself."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        url = f"sqlite:///{os.path.join(self._temp.name, 'r.db')}"
        self.repository = PostgresIncidentRepositoryAdapter(url)
        seed, self.proposal_hash = _seed_incident()
        self.repository.save_incident(seed)
        now = datetime.now(timezone.utc)
        reason, _ = self.repository.claim_execution_lease(
            INCIDENT_ID, PROPOSAL_ID, self.proposal_hash,
            owner="worker-a", now=now, lease_seconds=600.0,
        )
        self.assertEqual(reason, "claimed")
        self.now = now

    def _renew(self, owner="worker-a", proposal_id=PROPOSAL_ID):
        return self.repository.renew_execution_lease(
            INCIDENT_ID, proposal_id, owner,
            now=datetime.now(timezone.utc), lease_seconds=600.0,
        )

    def test_owner_can_renew_and_expiry_moves_forward(self):
        claim = self.repository.get_execution_claim(INCIDENT_ID, PROPOSAL_ID)
        before = claim["lease_expires_at"]
        self.assertTrue(self._renew())
        claim = self.repository.get_execution_claim(INCIDENT_ID, PROPOSAL_ID)
        self.assertGreater(claim["lease_expires_at"], before)

    def test_wrong_owner_cannot_renew(self):
        self.assertFalse(self._renew(owner="worker-b"))

    def test_unknown_proposal_cannot_renew(self):
        self.assertFalse(self._renew(proposal_id="proposal-ghost"))

    def test_completed_claim_is_never_resurrected(self):
        self.assertTrue(
            self.repository.finish_execution_lease(
                INCIDENT_ID, PROPOSAL_ID, "worker-a",
                status="EXECUTION_FAILED", stage="FAILED",
                now=datetime.now(timezone.utc),
            )
        )
        self.assertFalse(self._renew())  # state is FREE now
        claim = self.repository.get_execution_claim(INCIDENT_ID, PROPOSAL_ID)
        self.assertEqual(claim["state"], "FREE")


class ActiveHeartbeatTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.db_path = os.path.join(self._temp.name, "hb.db")
        self.repository = CountingRepository(f"sqlite:///{self.db_path}")
        seed, self.proposal_hash = _seed_incident()
        self.repository.save_incident(seed)
        self.orchestrator = _Orchestrator()

    def _service(self, owner="worker-a", repository=None, interval=0.02,
                 orchestrator=None):
        return ProposalExecutionService(
            repository=repository or self.repository,
            orchestrator_factory=lambda: orchestrator or self.orchestrator,
            ttl_seconds=3600.0,
            lease_seconds=600.0,
            lease_owner=owner,
            heartbeat_interval=interval,
        )

    def _execute(self, service):
        return service.execute(
            incident_id=INCIDENT_ID,
            proposal_id=PROPOSAL_ID,
            proposal_hash=self.proposal_hash,
            requested_by="alice-operator",
        )

    def _proposal(self, repository=None):
        return (repository or self.repository).get_incident_by_id(
            INCIDENT_ID
        ).patch_proposals[0]

    def test_long_operation_keeps_lease_alive_and_completes(self):
        # Synchronize on TWO successful heartbeat renewals after the
        # validation.started boundary; never depend on a wall-clock sleep.
        hold_started = threading.Event()
        self.repository.renew_gate = hold_started
        self.repository.renew_target = 2
        self.orchestrator = _Orchestrator(
            hold_after="validation.started",
            hold_event=self.repository.renewed_event,
            hold_started=hold_started,
        )
        service = self._service()
        body = self._execute(service)

        self.assertEqual(body["status"], "PR_CREATED")
        self.assertGreaterEqual(self.repository.renew_calls, 2)
        claim = self.repository.get_execution_claim(
            INCIDENT_ID, PROPOSAL_ID
        )
        self.assertEqual(claim["state"], "FREE")
        self.assertEqual(claim["stage"], "COMPLETED")
        self.assertEqual(self._proposal().status, "PR_CREATED")

    def test_long_validation_phase_renews_lease(self):
        # The operation remains open until the heartbeat has demonstrably
        # renewed the durable lease twice AFTER validation begins.
        hold_started = threading.Event()
        self.repository.renew_gate = hold_started
        self.repository.renew_target = 2
        orchestrator = _Orchestrator(
            hold_after="validation.started",
            hold_event=self.repository.renewed_event,
            hold_started=hold_started,
        )
        service = self._service(orchestrator=orchestrator)
        body = self._execute(service)
        self.assertEqual(body["status"], "PR_CREATED")
        self.assertGreaterEqual(self.repository.renew_calls, 2)
        self.assertIn("validation.completed", orchestrator.stages)

    def test_owner_loss_stops_before_next_side_effect_and_cannot_finish(self):
        holder = {}
        stolen = {"done": False}
        test = self

        class Scenario:
            def execute(self, *, incident_id, proposal, repository_slug,
                        validation_profile, stage_callback=None,
                        before_side_effect=None):
                stage_callback("workspace.created", {"workspace": "ws"})
                if not stolen["done"]:
                    stolen["done"] = True
                    # expire worker A's lease and let worker B take over
                    # (independent adapter instance = independent service)
                    now = datetime.now(timezone.utc)
                    with test.repository.engine.begin() as connection:
                        connection.execute(
                            sa_update(execution_claims_table)
                            .where(
                                execution_claims_table.c.incident_id
                                == INCIDENT_ID
                            )
                            .values(lease_expires_at=now)
                        )
                    repo_b = PostgresIncidentRepositoryAdapter(
                        f"sqlite:///{test.db_path}"
                    )
                    # retry until B wins (a concurrent renewal may extend)
                    for _ in range(50):
                        reason, _ = repo_b.claim_execution_lease(
                            INCIDENT_ID, PROPOSAL_ID, test.proposal_hash,
                            owner="worker-b",
                            now=datetime.now(timezone.utc),
                            lease_seconds=600.0,
                        )
                        if reason == "claimed":
                            break
                        with test.repository.engine.begin() as connection:
                            connection.execute(
                                sa_update(execution_claims_table)
                                .where(
                                    execution_claims_table.c.incident_id
                                    == INCIDENT_ID
                                )
                                .values(lease_expires_at=datetime.now(timezone.utc))
                            )
                        time.sleep(0.01)
                    else:
                        raise AssertionError("worker B never acquired the lease")
                # heartbeat must observe the ownership loss promptly
                if not holder["service"]._heartbeat.lost.wait(timeout=5.0):
                    raise AssertionError("heartbeat never detected lease loss")
                # the next side-effecting stage must be refused
                try:
                    stage_callback(
                        "patch.applied", {"target_filepath": "app/w.py"}
                    )
                except RemediationStageGuardError:
                    test.guard_observed = True
                    raise
                raise AssertionError("stage guard did not fire after lease loss")

        self.guard_observed = False
        service_a = self._service(
            owner="worker-a", interval=0.05, orchestrator=Scenario()
        )
        holder["service"] = service_a
        with self.assertRaises(ExecutionLeaseUnavailable):
            self._execute(service_a)
        self.assertTrue(self.guard_observed)

        # worker B owns the durable claim; worker A could not clobber it
        repo_b = PostgresIncidentRepositoryAdapter(f"sqlite:///{self.db_path}")
        claim = repo_b.get_execution_claim(INCIDENT_ID, PROPOSAL_ID)
        self.assertEqual(claim["lease_owner"], "worker-b")
        self.assertEqual(claim["state"], "LEASED")
        self.assertEqual(claim["attempt"], 2)
        proposal = self._proposal()
        self.assertEqual(proposal.status, "EXECUTING")  # A's finish rejected
        self.assertEqual(proposal.lease_owner, "worker-b")

    def test_store_unavailable_fails_closed(self):
        from incident_service.application.failures import (
            ProposalExecutionFailedError,
        )

        self.repository.renew_error = RuntimeError("claim store offline")
        boundaries = []
        reasons = []

        class Scenario:
            def execute(self, *, incident_id, proposal, repository_slug,
                        validation_profile, stage_callback=None,
                        before_side_effect=None):
                stage_callback("workspace.created", {"workspace": "ws"})
                boundaries.append("workspace.created")
                if not service._heartbeat.lost.wait(timeout=5.0):
                    raise AssertionError("heartbeat never flagged outage")
                reasons.append(service._heartbeat.loss_reason)
                stage_callback("patch.applied", {"target_filepath": "app/w.py"})
                boundaries.append("patch.applied")  # must never be reached
                raise AssertionError("unreachable")

        service = self._service(orchestrator=Scenario())
        with self.assertRaises(ProposalExecutionFailedError):
            self._execute(service)
        # uncertainty must fail closed: no next side-effecting stage
        self.assertNotIn("patch.applied", boundaries)
        self.assertEqual(reasons, ["store_unavailable"])
        # owner-gated finish still worked (store outage was heartbeat-only)
        claim = self.repository.get_execution_claim(INCIDENT_ID, PROPOSAL_ID)
        self.assertEqual(claim["state"], "FREE")
        self.assertEqual(self._proposal().status, "EXECUTION_FAILED")

    def test_success_and_failure_paths_leave_no_heartbeat_threads(self):
        # failure path first (fresh APPROVED proposal)
        class Boom:
            def execute(self, *, incident_id, proposal, repository_slug,
                        validation_profile, stage_callback=None,
                        before_side_effect=None):
                stage_callback("workspace.created", {"workspace": "ws"})
                raise RuntimeError("boom")

        failing = self._service(orchestrator=Boom())
        with self.assertRaises(Exception):
            self._execute(failing)
        self.assertIsNone(failing._heartbeat)

        # success path (retry after EXECUTION_FAILED)
        succeeding = self._service(orchestrator=_Orchestrator())
        body = self._execute(succeeding)
        self.assertEqual(body["status"], "PR_CREATED")
        self.assertIsNone(succeeding._heartbeat)

        # repeated runs must not accumulate workers
        for _ in range(3):
            replay = self._service(orchestrator=_Orchestrator())
            # PR_CREATED -> idempotent reconcile path starts no heartbeat
            body = self._execute(replay)
            self.assertEqual(body["status"], "PR_CREATED")
            self.assertIsNone(replay._heartbeat)

        leaked = [
            t for t in threading.enumerate()
            if t.name.startswith("remediation-heartbeat:")
            and t.is_alive()
        ]
        self.assertEqual(leaked, [], "heartbeat threads must not outlive runs")


class PreSideEffectAuthorizationTests(unittest.TestCase):
    """Phase 6.2.1B Goal B: assert_execution_lease_live semantics on a
    real durable store + service-to-orchestrator wiring."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.db_path = os.path.join(self._temp.name, "guard.db")
        self.repository = CountingRepository(f"sqlite:///{self.db_path}")
        seed, self.proposal_hash = _seed_incident()
        self.repository.save_incident(seed)
        self.now = datetime.now(timezone.utc)
        reason, _ = self.repository.claim_execution_lease(
            INCIDENT_ID, PROPOSAL_ID, self.proposal_hash,
            owner="worker-a", now=self.now, lease_seconds=600.0,
        )
        assert reason == "claimed", reason

    def _service(self, owner="worker-a", repository=None, orchestrator=None):
        return ProposalExecutionService(
            repository=repository or self.repository,
            orchestrator_factory=lambda: orchestrator or _Orchestrator(),
            ttl_seconds=3600.0,
            lease_seconds=600.0,
            lease_owner=owner,
            heartbeat_interval=0.02,
        )

    def test_live_lease_authorizes_the_next_side_effect(self):
        service = self._service()
        service.assert_execution_lease_live(INCIDENT_ID, PROPOSAL_ID)

    def test_owner_mismatch_fails_closed(self):
        service = self._service(owner="worker-b")
        with self.assertRaises(RemediationStageGuardError):
            service.assert_execution_lease_live(INCIDENT_ID, PROPOSAL_ID)

    def test_expired_lease_fails_closed(self):
        with self.repository.engine.begin() as connection:
            connection.execute(
                sa_update(execution_claims_table)
                .where(execution_claims_table.c.incident_id == INCIDENT_ID)
                .values(lease_expires_at=self.now)
            )
        service = self._service()
        with self.assertRaises(RemediationStageGuardError):
            service.assert_execution_lease_live(INCIDENT_ID, PROPOSAL_ID)

    def test_released_claim_fails_closed(self):
        self.assertTrue(
            self.repository.finish_execution_lease(
                INCIDENT_ID, PROPOSAL_ID, "worker-a",
                status="EXECUTION_FAILED", stage="FAILED",
                now=datetime.now(timezone.utc),
            )
        )
        service = self._service()
        with self.assertRaises(RemediationStageGuardError):
            service.assert_execution_lease_live(INCIDENT_ID, PROPOSAL_ID)

    def test_missing_claim_fails_closed(self):
        service = self._service()
        with self.assertRaises(RemediationStageGuardError):
            service.assert_execution_lease_live(INCIDENT_ID, "proposal-ghost")

    def test_heartbeat_loss_fails_closed_immediately(self):
        import threading as _threading

        service = self._service()
        fake = type("H", (), {})()
        fake.lost = _threading.Event()
        fake.lost.set()
        fake.loss_reason = "owner_lost"
        with self.assertRaises(RemediationStageGuardError):
            service.assert_execution_lease_live(
                INCIDENT_ID, PROPOSAL_ID, heartbeat=fake
            )

    def test_store_uncertainty_fails_closed(self):
        service = self._service()

        class BrokenRepo:
            def get_execution_claim(self, incident_id, proposal_id):
                raise RuntimeError("database offline")

            def get_incident_by_id(self, incident_id):
                return self.wrapped.get_incident_by_id(incident_id)

        broken = BrokenRepo()
        broken.wrapped = self.repository
        service = ProposalExecutionService(
            repository=broken,
            orchestrator_factory=lambda: _Orchestrator(),
            ttl_seconds=3600.0,
            lease_seconds=600.0,
            lease_owner="worker-a",
            heartbeat_interval=0.02,
        )
        with self.assertRaises(RemediationStageGuardError):
            service.assert_execution_lease_live(INCIDENT_ID, PROPOSAL_ID)

    def test_service_passes_guard_and_lost_lease_blocks_side_effect(self):
        """End-to-end wiring: service injects before_side_effect; after a
        steal, the guard refuses and the fake side effect never runs."""
        # release the setUp claim so the SERVICE claims its own lease
        # (the wiring under test starts from a normal claim)
        self.assertTrue(
            self.repository.finish_execution_lease(
                INCIDENT_ID, PROPOSAL_ID, "worker-a",
                status="EXECUTION_FAILED", stage="FAILED",
                now=datetime.now(timezone.utc),
            )
        )
        holder = {}
        stolen = {"done": False}
        side_effect_ran = []
        test = self

        class Scenario:
            def execute(self, *, incident_id, proposal, repository_slug,
                        validation_profile, stage_callback=None,
                        before_side_effect=None):
                assert before_side_effect is not None, (
                    "service must inject the pre-side-effect guard"
                )
                stage_callback("workspace.created", {"workspace": "ws"})
                if not stolen["done"]:
                    stolen["done"] = True
                    with test.repository.engine.begin() as connection:
                        connection.execute(
                            sa_update(execution_claims_table)
                            .where(
                                execution_claims_table.c.incident_id
                                == INCIDENT_ID
                            )
                            .values(
                                lease_expires_at=datetime.now(timezone.utc)
                            )
                        )
                    repo_b = PostgresIncidentRepositoryAdapter(
                        f"sqlite:///{test.db_path}"
                    )
                    reason, _ = repo_b.claim_execution_lease(
                        INCIDENT_ID, PROPOSAL_ID, test.proposal_hash,
                        owner="worker-b",
                        now=datetime.now(timezone.utc),
                        lease_seconds=600.0,
                    )
                    assert reason == "claimed", reason
                # THE pre-side-effect boundary: must refuse now
                before_side_effect("patch.apply")
                side_effect_ran.append("patch.apply")  # must never run
                raise AssertionError("side effect ran after lease loss")

        service = self._service(orchestrator=Scenario())
        holder["service"] = service
        with self.assertRaises(
            (RemediationStageGuardError, Exception)
        ) as ctx:
            service.execute(
                incident_id=INCIDENT_ID,
                proposal_id=PROPOSAL_ID,
                proposal_hash=self.proposal_hash,
                requested_by="alice-operator",
            )
        self.assertNotIsInstance(ctx.exception, AssertionError)
        self.assertEqual(side_effect_ran, [], "side effect must not run")
        claim = self.repository.get_execution_claim(
            INCIDENT_ID, PROPOSAL_ID
        )
        self.assertEqual(claim["lease_owner"], "worker-b")


if __name__ == "__main__":
    unittest.main()
