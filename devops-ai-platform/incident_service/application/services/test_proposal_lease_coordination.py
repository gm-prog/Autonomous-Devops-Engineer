"""Phase 6.2.1: durable execution lease tested at the persistence boundary.

Everything here runs against the REAL adapter and REAL SQLite file
(two independent adapter instances on the same database) — no fake
dict, no mocked repository. This is the layer that must hold the
single-owner invariant across processes/replicas.
"""

import os
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from incident_service.application.failures import (
    ExecutionLeaseUnavailable,
    ProposalNotFoundError,
)
from incident_service.application.services.proposal_execution_policy import (
    DEFAULT_LEASE_SECONDS,
    EXECUTION_STAGES,
    RESUMABLE_STAGES,
    load_lease_seconds,
    new_lease_owner,
    validate_stage_transition,
)
from incident_service.application.services.proposal_execution_service import (
    ProposalExecutionService,
)
from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.domain.entities.hotfix_proposal import HotfixProposal
from incident_service.infrastructure.database.postgres_incident_repo import (
    PostgresIncidentRepositoryAdapter,
    execution_claims_table,
)
from sqlalchemy import update as sa_update

PATCH = (
    "--- a/app/w.py\n"
    "+++ b/app/w.py\n"
    "@@ -1 +1 @@\n"
    "-run()\n"
    "+run_safely()\n"
)


def _seed_incident():
    from shared_kernel.domain.provenance import build_provenance_record

    from incident_service.domain.entities.incident_evidence import IncidentEvidence

    incident = IncidentAggregate("inc-lease-1", "cpu", "HIGH", "ctx")
    incident.move_to_triage()
    incident.attach_evidence(
        IncidentEvidence(
            id="evt-1",
            kind="threshold_breach",
            source="monitoring-service",
            payload={"metric": "cpu_percent"},
        )
    )
    # RCA evidence so canonical hash recompute + confidence gates pass
    incident.attach_evidence(
        IncidentEvidence(
            id="rca-inc-lease-1",
            kind="rca_result",
            source="agent-service",
            payload={
                "rca_id": "rca-inc-lease-1",
                "incident_id": "inc-lease-1",
                "root_cause": "cpu saturation after rollout",
                "confidence": 0.93,
                "evidence_refs": ["evt-1"],
            },
        )
    )
    payload = {
        "deployment_run_id": "run-lease-1",
        "repository_name": "acme/checkout",
        "source_revision": {"head_sha": "a" * 40, "commits": []},
        "state": "DEPLOYED",
        "artifact_hash": "c" * 64,
        "plan_hash": "d" * 64,
    }
    payload["provenance"] = build_provenance_record(
        repository_name="acme/checkout",
        source_sha="a" * 40,
        artifact_hash=payload["artifact_hash"],
        plan_hash=payload["plan_hash"],
        deployment_run_id="run-lease-1",
        state="DEPLOYED",
        verification_method="test-source-verifier",
    )
    incident.attach_evidence(
        IncidentEvidence(
            id="deploy-1",
            kind="deployment_run",
            source="deployment-service",
            payload=payload,
        )
    )
    proposal = HotfixProposal(
        id="proposal-inc-lease-1",
        incident_id="inc-lease-1",
        target_filepath="app/w.py",
        diff_patch_payload=PATCH,
        source_sha="a" * 40,
        repository="acme/checkout",
        status="APPROVED",
        validation_plan=["pytest -q"],
    )
    assert proposal.apply_verification_pass()
    from incident_service.application.services.proposal_execution_policy import (
        recompute_proposal_hash,
    )

    # real canonical hash over persisted state (integrity gate is real)
    proposal.proposal_hash = recompute_proposal_hash(incident, proposal)
    proposal.approved_by = "alice-operator"
    proposal.approval_hash = proposal.proposal_hash
    proposal.approved_at = datetime.now(timezone.utc)
    incident.upsert_remediation_proposal(proposal)
    return incident, proposal.proposal_hash


class DurableLeasePersistenceTests(unittest.TestCase):
    """Two independent adapter instances == two service replicas."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        url = f"sqlite:///{os.path.join(self._temp.name, 'lease.db')}"
        # two separate adapters (= separate engine/pools) on ONE database
        self.replica_a = PostgresIncidentRepositoryAdapter(url)
        self.replica_b = PostgresIncidentRepositoryAdapter(url)
        self.incident_seed, self.proposal_hash = _seed_incident()
        self.replica_a.save_incident(self.incident_seed)
        self.now = datetime.now(timezone.utc)

    def _claim(self, adapter, owner, now=None, lease=600.0):
        return adapter.claim_execution_lease(
            "inc-lease-1",
            "proposal-inc-lease-1",
            self.proposal_hash,
            owner=owner,
            now=now or self.now,
            lease_seconds=lease,
        )

    # --- claim semantics -------------------------------------------------
    def test_first_claim_succeeds_and_flips_lifecycle_atomically(self):
        reason, incident = self._claim(self.replica_a, "worker-a")
        self.assertEqual(reason, "claimed")
        proposal = incident.patch_proposals[0]
        self.assertEqual(proposal.status, "EXECUTING")
        self.assertEqual(proposal.execution_attempts, 1)
        self.assertEqual(proposal.execution_stage, "CLAIMED")
        self.assertEqual(proposal.lease_owner, "worker-a")
        claim = self.replica_a.get_execution_claim(
            "inc-lease-1", "proposal-inc-lease-1"
        )
        self.assertEqual(claim["state"], "LEASED")
        self.assertEqual(claim["lease_owner"], "worker-a")

    def test_second_independent_claim_is_rejected(self):
        self.assertEqual(self._claim(self.replica_a, "worker-a")[0], "claimed")
        # different replica, same database → rejected by the store
        self.assertEqual(self._claim(self.replica_b, "worker-b")[0], "lease_active")

    def test_active_lease_cannot_be_stolen_even_by_same_owner_field(self):
        self._claim(self.replica_a, "worker-a")
        # reclaim attempt before expiry → rejected
        reason, _ = self._claim(self.replica_b, "worker-a-replica2")
        self.assertEqual(reason, "lease_active")

    def test_expired_lease_is_reclaimable_and_keeps_resumable_cursor(self):
        self._claim(self.replica_a, "worker-a")
        ok = self.replica_a.persist_execution_progress(
            "inc-lease-1",
            "proposal-inc-lease-1",
            "worker-a",
            stage="COMMIT_CREATED",
            now=self.now,
            lease_seconds=600,
            commit_sha="c" * 40,
            branch_name="automation/remediation/inc-lease-1/proposal-inc-lease-1",
        )
        self.assertTrue(ok)
        self._expire_lease()

        reason, incident = self._claim(self.replica_b, "worker-b")
        self.assertEqual(reason, "claimed")
        proposal = incident.patch_proposals[0]
        self.assertEqual(proposal.execution_attempts, 2)
        self.assertEqual(proposal.execution_stage, "COMMIT_CREATED")  # cursor kept
        self.assertEqual(proposal.lease_owner, "worker-b")

    def test_expired_lease_with_non_resumable_cursor_restarts(self):
        self._claim(self.replica_a, "worker-a")
        self.replica_a.persist_execution_progress(
            "inc-lease-1",
            "proposal-inc-lease-1",
            "worker-a",
            stage="PATCH_APPLIED",
            now=self.now,
            lease_seconds=600,
        )
        self._expire_lease()
        reason, incident = self._claim(self.replica_b, "worker-b")
        self.assertEqual(reason, "claimed")
        self.assertEqual(incident.patch_proposals[0].execution_stage, "CLAIMED")

    def test_claims_reject_bad_status_and_hash(self):
        self.assertEqual(
            self._claim(self.replica_a, "a", now=self.now)[0], "claimed"
        )
        self.replica_a.finish_execution_lease(
            "inc-lease-1",
            "proposal-inc-lease-1",
            "a",
            status="PR_CREATED",
            stage="COMPLETED",
            now=self.now,
        )
        # after completion: no new claim
        self.assertEqual(
            self._claim(self.replica_b, "b")[0], "status_not_executable"
        )
        # missing incident / proposal
        self.assertEqual(
            PostgresIncidentRepositoryAdapter.claim_execution_lease(
                self.replica_a,
                "nope",
                "proposal-inc-lease-1",
                self.proposal_hash,
                owner="x",
                now=self.now,
                lease_seconds=600,
            )[0],
            "no_incident",
        )
        self.assertEqual(
            self.replica_a.claim_execution_lease(
                "inc-lease-1",
                "proposal-other",
                self.proposal_hash,
                owner="x",
                now=self.now,
                lease_seconds=600,
            )[0],
            "proposal_missing",
        )
        self.assertEqual(
            self.replica_a.claim_execution_lease(
                "inc-lease-1",
                "proposal-inc-lease-1",
                "f" * 64,
                owner="x",
                now=self.now,
                lease_seconds=600,
            )[0],
            "hash_mismatch",
        )

    def test_proposal_not_approved_status_rejected(self):
        incident = self.replica_a.get_incident_by_id("inc-lease-1")
        incident.patch_proposals[0].status = "PROPOSED"
        self.replica_a.save_incident(incident)
        self.assertEqual(
            self._claim(self.replica_a, "worker-a")[0], "status_not_executable"
        )

    # --- owner-gated progress + finish ----------------------------------
    def test_progress_requires_live_owner(self):
        self._claim(self.replica_a, "worker-a")
        self.assertFalse(
            self.replica_b.persist_execution_progress(
                "inc-lease-1",
                "proposal-inc-lease-1",
                "worker-b",
                stage="WORKSPACE_CREATED",
                now=self.now,
                lease_seconds=600,
            )
        )
        self.assertTrue(
            self.replica_a.persist_execution_progress(
                "inc-lease-1",
                "proposal-inc-lease-1",
                "worker-a",
                stage="WORKSPACE_CREATED",
                now=self.now,
                lease_seconds=600,
            )
        )

    def test_stage_ordering_is_enforced(self):
        self._claim(self.replica_a, "worker-a")
        self.replica_a.persist_execution_progress(
            "inc-lease-1",
            "proposal-inc-lease-1",
            "worker-a",
            stage="COMMIT_CREATED",
            now=self.now,
            lease_seconds=600,
        )
        with self.assertRaises(ValueError):
            self.replica_a.persist_execution_progress(
                "inc-lease-1",
                "proposal-inc-lease-1",
                "worker-a",
                stage="PATCH_APPLIED",  # backward — rejected
                now=self.now,
                lease_seconds=600,
            )

    def test_progress_renews_lease_expiry(self):
        self._claim(self.replica_a, "worker-a", lease=60.0)
        before = self.replica_a.get_execution_claim(
            "inc-lease-1", "proposal-inc-lease-1"
        )["lease_expires_at"]
        later = self.now + timedelta(seconds=30)
        self.replica_a.persist_execution_progress(
            "inc-lease-1",
            "proposal-inc-lease-1",
            "worker-a",
            stage="WORKSPACE_CREATED",
            now=later,
            lease_seconds=600.0,
        )
        after = self.replica_a.get_execution_claim(
            "inc-lease-1", "proposal-inc-lease-1"
        )["lease_expires_at"]
        if after.tzinfo is None:
            after = after.replace(tzinfo=timezone.utc)
        if before.tzinfo is None:
            before = before.replace(tzinfo=timezone.utc)
        self.assertGreater(after, before)

    def test_finish_is_owner_gated_and_releases_atomically(self):
        self._claim(self.replica_a, "worker-a")
        self.assertFalse(
            self.replica_b.finish_execution_lease(
                "inc-lease-1",
                "proposal-inc-lease-1",
                "worker-b",
                status="PR_CREATED",
                stage="COMPLETED",
                now=self.now,
            )
        )
        self.assertTrue(
            self.replica_a.finish_execution_lease(
                "inc-lease-1",
                "proposal-inc-lease-1",
                "worker-a",
                status="PR_CREATED",
                stage="COMPLETED",
                now=self.now,
                updates={"pull_request_url": "https://github.example/pull/1"},
            )
        )
        incident = self.replica_b.get_incident_by_id("inc-lease-1")
        self.assertEqual(incident.patch_proposals[0].status, "PR_CREATED")
        claim = self.replica_a.get_execution_claim(
            "inc-lease-1", "proposal-inc-lease-1"
        )
        self.assertEqual(claim["state"], "FREE")
        self.assertIsNone(claim["lease_owner"])
        # stale second finish by original owner → rejected
        self.assertFalse(
            self.replica_a.finish_execution_lease(
                "inc-lease-1",
                "proposal-inc-lease-1",
                "worker-a",
                status="EXECUTION_FAILED",
                stage="FAILED",
                now=self.now,
            )
        )

    def test_attempt_increments_only_on_claim(self):
        self._claim(self.replica_a, "worker-a")
        claim = self.replica_a.get_execution_claim(
            "inc-lease-1", "proposal-inc-lease-1"
        )
        self.assertEqual(claim["attempt"], 1)
        self.replica_a.persist_execution_progress(
            "inc-lease-1",
            "proposal-inc-lease-1",
            "worker-a",
            stage="WORKSPACE_CREATED",
            now=self.now,
            lease_seconds=600,
        )
        self.replica_a.persist_execution_progress(
            "inc-lease-1",
            "proposal-inc-lease-1",
            "worker-a",
            stage="PATCH_APPLIED",
            now=self.now,
            lease_seconds=600,
        )
        claim = self.replica_a.get_execution_claim(
            "inc-lease-1", "proposal-inc-lease-1"
        )
        self.assertEqual(claim["attempt"], 1, "progress must not bump attempts")

    # --- true concurrent CAS race ---------------------------------------
    def test_concurrent_claims_yield_exactly_one_owner(self):
        outcomes = []
        barrier = threading.Barrier(2)

        def racer(adapter, owner):
            barrier.wait()
            reason, _ = adapter.claim_execution_lease(
                "inc-lease-1",
                "proposal-inc-lease-1",
                self.proposal_hash,
                owner=owner,
                now=self.now,
                lease_seconds=600.0,
            )
            outcomes.append(reason)

        threads = [
            threading.Thread(target=racer, args=(self.replica_a, "worker-a")),
            threading.Thread(target=racer, args=(self.replica_b, "worker-b")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertEqual(len(outcomes), 2)
        self.assertEqual(outcomes.count("claimed"), 1, outcomes)
        claim = self.replica_a.get_execution_claim(
            "inc-lease-1", "proposal-inc-lease-1"
        )
        self.assertEqual(claim["attempt"], 1, "loser must not own or increment")

    # --- service-level independent instances (scenario I) ---------------
    def test_two_service_instances_cannot_both_execute(self):
        services = []

        def make_service(blocker, started):
            def factory():
                class Blocking:
                    def execute(self, **kwargs):
                        started.set()
                        blocker.wait(timeout=10)
                        raise RuntimeError("stop after observing contention")

                return Blocking()

            service = ProposalExecutionService(
                repository=self.replica_a,
                orchestrator_factory=factory,
                ttl_seconds=3600.0,
                lease_seconds=600.0,
                lease_owner=f"worker-{len(services)}",
            )
            services.append(service)
            return service, started

        release = threading.Event()
        started_a = threading.Event()
        service_a, started_a = make_service(release, started_a)
        # service B uses a SEPARATE adapter instance on the same database
        service_b = ProposalExecutionService(
            repository=self.replica_b,
            orchestrator_factory=lambda: (_ for _ in ()).throw(
                AssertionError("B must never reach the orchestrator")
            ),
            ttl_seconds=3600.0,
            lease_seconds=600.0,
            lease_owner="worker-b",
        )

        results = {}

        def run_a():
            try:
                service_a.execute(
                    incident_id="inc-lease-1",
                    proposal_id="proposal-inc-lease-1",
                    proposal_hash=self.proposal_hash,
                )
            except Exception as exc:  # injected post-claim stop
                results["a"] = exc

        thread_a = threading.Thread(target=run_a)
        thread_a.start()
        self.assertTrue(started_a.wait(timeout=10), "A never reached execution")

        # B is a different instance with its OWN process-local lock:
        # only the durable store (read via replica B's adapter) can reject
        # it here — the state-based precheck reads the claim row from DB.
        from incident_service.application.failures import (
            ProposalAlreadyExecutingError,
        )

        with self.assertRaises(
            (ExecutionLeaseUnavailable, ProposalAlreadyExecutingError)
        ):
            service_b.execute(
                incident_id="inc-lease-1",
                proposal_id="proposal-inc-lease-1",
                proposal_hash=self.proposal_hash,
            )
        claim = self.replica_b.get_execution_claim(
            "inc-lease-1", "proposal-inc-lease-1"
        )
        self.assertEqual(claim["lease_owner"], "worker-0")

        release.set()
        thread_a.join(timeout=10)
        self.assertFalse(thread_a.is_alive())

    def test_execute_interface_has_no_owner_or_target_parameters(self):
        import inspect

        params = inspect.signature(
            ProposalExecutionService.execute
        ).parameters
        for forbidden in (
            "repository",
            "repository_slug",
            "source_sha",
            "branch",
            "workspace",
            "commands",
            "owner",
            "lease_owner",
        ):
            self.assertNotIn(forbidden, params)

    def test_lease_owner_identity_is_process_derived(self):
        owner = new_lease_owner()
        host, pid, suffix = owner.split(":", 2)
        self.assertTrue(host)
        self.assertEqual(pid, str(os.getpid()))
        self.assertEqual(len(suffix), 12)

    # --- configuration ----------------------------------------------------
    def test_lease_seconds_config_fail_fast(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("REMEDIATION_EXECUTION_LEASE_SECONDS", None)
            self.assertEqual(load_lease_seconds(), DEFAULT_LEASE_SECONDS)
        with patch.dict(
            os.environ, {"REMEDIATION_EXECUTION_LEASE_SECONDS": "120"}
        ):
            self.assertEqual(load_lease_seconds(), 120.0)
        for bad in ("0", "-5", "abc"):
            with self.subTest(bad=bad), patch.dict(
                os.environ, {"REMEDIATION_EXECUTION_LEASE_SECONDS": bad}
            ):
                with self.assertRaises(ValueError):
                    load_lease_seconds()

    def test_stage_vocabulary_and_transitions(self):
        self.assertIn("CLAIMED", EXECUTION_STAGES)
        self.assertIn("COMPLETED", EXECUTION_STAGES)
        self.assertTrue(RESUMABLE_STAGES.issubset(set(EXECUTION_STAGES)))
        validate_stage_transition("CLAIMED", "WORKSPACE_CREATED")
        validate_stage_transition("COMMIT_CREATED", "REMOTE_PUBLISHED")
        validate_stage_transition("COMMIT_CREATED", "FAILED")
        validate_stage_transition("PR_DISCOVERY", "COMPLETED")
        with self.assertRaises(ValueError):
            validate_stage_transition("PATCH_APPLIED", "WORKSPACE_CREATED")
        with self.assertRaises(ValueError):
            validate_stage_transition("COMPLETED", "PR_CREATED")
        with self.assertRaises(ValueError):
            validate_stage_transition("CLAIMED", "EXOTIC_STAGE")

    # --- helpers -----------------------------------------------------------
    def _expire_lease(self):
        past = self.now - timedelta(seconds=10_000)
        with self.replica_a.engine.begin() as connection:
            connection.execute(
                sa_update(execution_claims_table)
                .where(
                    execution_claims_table.c.incident_id == "inc-lease-1"
                )
                .values(lease_expires_at=past)
            )


class MissingCoordinationRepositoryTests(unittest.TestCase):
    def test_service_fails_closed_without_durable_store(self):
        class MinimalRepo:
            def get_incident_by_id(self, incident_id):
                return None

        service = ProposalExecutionService(
            repository=MinimalRepo(),
            orchestrator_factory=lambda: None,
            ttl_seconds=60,
        )
        with self.assertRaises(ProposalNotFoundError):
            service.execute(
                incident_id="missing",
                proposal_id="p",
                proposal_hash="a" * 64,
            )
        # any repository lacking durable coordination methods must be
        # rejected the moment ownership would be required
        with self.assertRaises(ExecutionLeaseUnavailable):
            service._coordination("claim_execution_lease")


class StrictLeaseExpiryTests(unittest.TestCase):
    """Phase 6.2.1B Goal A: an expired lease is never authoritative, even
    while state == LEASED and lease_owner still matches."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        url = f"sqlite:///{os.path.join(self._temp.name, 'exp.db')}"
        self.repository = PostgresIncidentRepositoryAdapter(url)
        seed, self.proposal_hash = _seed_incident()
        self.repository.save_incident(seed)
        self.now = datetime.now(timezone.utc)
        reason, _ = self.repository.claim_execution_lease(
            "inc-lease-1",
            "proposal-inc-lease-1",
            self.proposal_hash,
            owner="worker-a",
            now=self.now,
            lease_seconds=600.0,
        )
        assert reason == "claimed", reason

    def _expire(self):
        """Expire worker A's lease in place (state/owner untouched)."""
        with self.repository.engine.begin() as connection:
            connection.execute(
                sa_update(execution_claims_table)
                .where(
                    execution_claims_table.c.incident_id == "inc-lease-1"
                )
                .values(
                    lease_expires_at=self.now - timedelta(seconds=1)
                )
            )

    def _claim(self):
        return self.repository.get_execution_claim(
            "inc-lease-1", "proposal-inc-lease-1"
        )

    def _renew(self, owner="worker-a"):
        return self.repository.renew_execution_lease(
            "inc-lease-1",
            "proposal-inc-lease-1",
            owner,
            now=datetime.now(timezone.utc),
            lease_seconds=600.0,
        )

    def _progress(self, owner="worker-a", stage="WORKSPACE_CREATED"):
        return self.repository.persist_execution_progress(
            "inc-lease-1",
            "proposal-inc-lease-1",
            owner,
            stage=stage,
            now=datetime.now(timezone.utc),
            lease_seconds=600.0,
        )

    def _finish(self, owner="worker-a"):
        return self.repository.finish_execution_lease(
            "inc-lease-1",
            "proposal-inc-lease-1",
            owner,
            status="PR_CREATED",
            stage="COMPLETED",
            now=datetime.now(timezone.utc),
        )

    def test_expired_lease_cannot_renew(self):
        self._expire()
        self.assertFalse(self._renew())
        claim = self._claim()
        # expiry untouched — the expired owner gained nothing
        expires = claim["lease_expires_at"]
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        self.assertLess(expires, self.now)
        self.assertEqual(claim["lease_owner"], "worker-a")
        self.assertEqual(claim["state"], "LEASED")

    def test_expired_lease_cannot_persist_progress(self):
        self._expire()
        self.assertFalse(self._progress())
        self.assertEqual(self._claim()["stage"], "CLAIMED")

    def test_expired_lease_cannot_finish(self):
        self._expire()
        self.assertFalse(self._finish())
        claim = self._claim()
        self.assertEqual(claim["state"], "LEASED")  # never released
        proposal = self.repository.get_incident_by_id(
            "inc-lease-1"
        ).patch_proposals[0]
        self.assertEqual(proposal.status, "EXECUTING")  # no terminal write

    def test_valid_lease_owner_can_renew_persist_finish(self):
        # same owner, unexpired lease — all three operations succeed
        self.assertTrue(self._renew())
        self.assertTrue(self._progress(stage="WORKSPACE_CREATED"))
        self.assertTrue(
            self.repository.persist_execution_progress(
                "inc-lease-1",
                "proposal-inc-lease-1",
                "worker-a",
                stage="PATCH_APPLIED",
                now=datetime.now(timezone.utc),
                lease_seconds=600.0,
            )
        )
        self.assertTrue(self._finish())
        claim = self._claim()
        self.assertEqual(claim["state"], "FREE")
        self.assertEqual(claim["stage"], "COMPLETED")

    def test_stale_owner_cannot_clobber_new_owner_after_reclaim(self):
        # worker A expires, worker B reclaims and progresses
        self._expire()
        now_b = datetime.now(timezone.utc)
        reason, _ = self.repository.claim_execution_lease(
            "inc-lease-1",
            "proposal-inc-lease-1",
            self.proposal_hash,
            owner="worker-b",
            now=now_b,
            lease_seconds=600.0,
        )
        self.assertEqual(reason, "claimed")
        self.assertTrue(
            self.repository.persist_execution_progress(
                "inc-lease-1",
                "proposal-inc-lease-1",
                "worker-b",
                stage="WORKSPACE_CREATED",
                now=now_b,
                lease_seconds=600.0,
            )
        )
        state_after_b = self._claim()
        self.assertEqual(state_after_b["lease_owner"], "worker-b")
        self.assertEqual(state_after_b["attempt"], 2)

        # stale worker A: every mutating operation is refused
        self.assertFalse(self._renew(owner="worker-a"))
        self.assertFalse(self._progress(owner="worker-a"))
        self.assertFalse(self._finish(owner="worker-a"))

        # worker B's durable state is byte-for-byte unchanged
        state_final = self._claim()
        for key in (
            "lease_owner",
            "state",
            "stage",
            "attempt",
            "lease_expires_at",
            "lease_acquired_at",
        ):
            self.assertEqual(state_final[key], state_after_b[key], key)


class FinishStaleWriterAtomicityTests(unittest.TestCase):
    """Phase 6.2.1C Goal A: when finish's final claim CAS affects 0
    rows, the ENTIRE finish transaction must roll back — a stale worker
    must never commit terminal proposal state (status/stage/commit/
    branch/PR URL/failure fields/evidence) after its lease was replaced.

    Deterministic interleaving (event barriers, no timing sleeps):

        A claim read (live, passes read-check)
            ↓
        PAUSE A at its proposals UPDATE (before any write lock)
            ↓
        B replaces the lease + B persists its own durable state
            ↓
        RESUME A → A proposals CAS matches → A claim CAS = 0 rows
            ↓
        finish raises _CoordinationRace → transaction ROLLS BACK
            ↓
        B's claim + proposal + evidence state byte-identical
    """

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        url = f"sqlite:///{os.path.join(self._temp.name, 'finish.db')}"
        self.repository = PostgresIncidentRepositoryAdapter(url)
        self.engine = self.repository.engine
        seed, self.proposal_hash = _seed_incident()
        self.repository.save_incident(seed)
        self.now = datetime.now(timezone.utc)
        reason, _ = self.repository.claim_execution_lease(
            "inc-lease-1",
            "proposal-inc-lease-1",
            self.proposal_hash,
            owner="worker-a",
            now=self.now,
            lease_seconds=600.0,
        )
        assert reason == "claimed", reason

    @staticmethod
    def _proposal_state(repository, incident_id, proposal_id):
        incident = repository.get_incident_by_id(incident_id)
        proposal = next(
            item for item in incident.patch_proposals
            if item.id == proposal_id
        )
        return {
            "status": proposal.status,
            "execution_stage": proposal.execution_stage,
            "execution_attempts": proposal.execution_attempts,
            "commit_sha": proposal.commit_sha,
            "branch_name": proposal.branch_name,
            "pull_request_url": proposal.pull_request_url,
            "last_failure_stage": proposal.last_failure_stage,
            "last_failure_reason": proposal.last_failure_reason,
        }

    def test_stale_finish_rolls_back_terminal_and_evidence_writes(self):
        from sqlalchemy import event, select as sa_select

        from incident_service.domain.entities.incident_evidence import (
            IncidentEvidence,
        )
        from incident_service.infrastructure.database.postgres_incident_repo import (
            _CoordinationRace,
            evidence_table,
        )

        a_ident = [None]
        paused = threading.Event()
        release = threading.Event()
        pause_hits = [0]

        def _pause_before_a_proposals(
            conn, cursor, statement, parameters, context, executemany
        ):
            # only A's finish touches incidents; A's thread is the only
            # thread inside finish, and pause exactly once
            if (
                a_ident[0] is not None
                and threading.get_ident() == a_ident[0]
                and statement.lstrip().upper().startswith("UPDATE")
                and "incidents" in statement
                and pause_hits[0] == 0
            ):
                pause_hits[0] += 1
                paused.set()
                if not release.wait(timeout=10):
                    raise RuntimeError("test never released paused finish")

        event.listen(
            self.engine, "before_cursor_execute", _pause_before_a_proposals
        )
        self.addCleanup(
            event.remove,
            self.engine,
            "before_cursor_execute",
            _pause_before_a_proposals,
        )

        evidence = IncidentEvidence(
            id="ev-stale-finish",
            kind="execution_log",
            source="stale-worker-a",
            observed_at=datetime.now(timezone.utc),
            payload={"attempt": 1},
        )
        outcome = {}

        def _run_stale_finish():
            a_ident[0] = threading.get_ident()
            try:
                outcome["ret"] = self.repository.finish_execution_lease(
                    "inc-lease-1",
                    "proposal-inc-lease-1",
                    "worker-a",
                    status="EXECUTION_FAILED",
                    stage="WORKSPACE_CREATED",
                    now=datetime.now(timezone.utc),
                    updates={
                        "commit_sha": "a" * 40,
                        "branch_name": "automation/remediation/stale-a",
                        "pull_request_url":
                            "https://github.com/owner/repo/pull/999",
                        "last_failure_stage": "workspace.created",
                        "last_failure_reason": "boom",
                    },
                    evidence=evidence,
                )
            except BaseException as exc:  # noqa: BLE001 — record anything
                outcome["exc"] = exc

        worker_a = threading.Thread(target=_run_stale_finish)
        worker_a.start()
        self.assertTrue(
            paused.wait(timeout=10),
            "worker A never reached the finish write window",
        )
        # A has read its OWN live claim (read-check passed). B now
        # replaces the lease and persists its own durable state.
        now_b = datetime.now(timezone.utc)
        with self.engine.begin() as connection:
            connection.execute(
                sa_update(execution_claims_table)
                .where(
                    execution_claims_table.c.incident_id == "inc-lease-1"
                )
                .values(
                    state="LEASED",
                    lease_owner="worker-b",
                    lease_acquired_at=now_b,
                    lease_expires_at=now_b + timedelta(seconds=600),
                    last_heartbeat_at=now_b,
                    completed_at=None,
                    attempt=2,
                    stage="CLAIMED",
                )
            )
        self.assertTrue(
            self.repository.persist_execution_progress(
                "inc-lease-1",
                "proposal-inc-lease-1",
                "worker-b",
                stage="WORKSPACE_CREATED",
                now=datetime.now(timezone.utc),
                lease_seconds=600.0,
                commit_sha="b" * 40,
                branch_name="automation/remediation/inc-lease-1/proposal-1",
            ),
            "worker B must be able to persist while A is paused",
        )
        # snapshots AFTER B's state — A must leave every one intact
        claim_before = self.repository.get_execution_claim(
            "inc-lease-1", "proposal-inc-lease-1"
        )
        proposal_before = self._proposal_state(
            self.repository, "inc-lease-1", "proposal-inc-lease-1"
        )
        with self.engine.connect() as connection:
            evidence_ids_before = sorted(
                row[0]
                for row in connection.execute(
                    sa_select(evidence_table.c.id).where(
                        evidence_table.c.incident_id == "inc-lease-1"
                    )
                )
            )

        release.set()
        worker_a.join(timeout=10)
        self.assertFalse(worker_a.is_alive(), "stale finish deadlocked")

        # (1) A never finished successfully: it raised, not returned
        self.assertNotIn("ret", outcome)
        self.assertIn("exc", outcome)
        self.assertIsInstance(outcome["exc"], _CoordinationRace)

        # (2) A cannot release B's lease; B's claim state byte-identical
        claim_after = self.repository.get_execution_claim(
            "inc-lease-1", "proposal-inc-lease-1"
        )
        for key in (
            "lease_owner",
            "state",
            "attempt",
            "stage",
            "lease_expires_at",
            "lease_acquired_at",
            "last_heartbeat_at",
            "completed_at",
            "commit_sha",
            "branch_name",
            "last_failure_stage",
            "last_failure_reason",
        ):
            self.assertEqual(claim_after[key], claim_before[key], key)

        # (3) terminal proposal state was NOT written by A (rollback)
        proposal_after = self._proposal_state(
            self.repository, "inc-lease-1", "proposal-inc-lease-1"
        )
        self.assertEqual(proposal_after, proposal_before)
        self.assertEqual(proposal_after["status"], "EXECUTING")
        # commit/branch shown are B's (claim overlay), never A's stale
        # mirrors or terminal failure fields
        self.assertEqual(proposal_after["commit_sha"], "b" * 40)
        self.assertEqual(
            proposal_after["branch_name"],
            "automation/remediation/inc-lease-1/proposal-1",
        )
        self.assertFalse(proposal_after["pull_request_url"])
        self.assertFalse(proposal_after["last_failure_stage"])

        # (4) A's evidence was never attached (rollback demonstrable)
        with self.engine.connect() as connection:
            evidence_ids_after = sorted(
                row[0]
                for row in connection.execute(
                    sa_select(evidence_table.c.id).where(
                        evidence_table.c.incident_id == "inc-lease-1"
                    )
                )
            )
        self.assertEqual(evidence_ids_after, evidence_ids_before)
        self.assertNotIn("ev-stale-finish", evidence_ids_after)


class MultiProposalClaimProjectionTests(unittest.TestCase):
    """Phase 6.2.1A: one incident, many proposals — claims project
    independently by proposal_id; no proposal inherits another's state."""

    PROPOSALS = ("p-a", "p-b", "p-c", "p-d", "p-e")

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        url = f"sqlite:///{os.path.join(self._temp.name, 'multi.db')}"
        self.repository = PostgresIncidentRepositoryAdapter(url)
        self.now = datetime.now(timezone.utc)

        incident = IncidentAggregate("inc-multi", "cpu", "HIGH", "ctx")
        incident.move_to_triage()
        for pid in self.PROPOSALS:
            per_proposal_patch = (
                f"--- a/app/{pid}.py\n"
                f"+++ b/app/{pid}.py\n"
                "@@ -1 +1 @@\n"
                "-old()\n"
                "+new()\n"
            )
            proposal = HotfixProposal(
                id=pid,
                incident_id="inc-multi",
                target_filepath=f"app/{pid}.py",
                diff_patch_payload=per_proposal_patch,
                source_sha="a" * 40,
                repository="acme/checkout",
                status="APPROVED",
                validation_plan=["pytest -q"],
            )
            assert proposal.apply_verification_pass()
            proposal.proposal_hash = (hashes := {p: (str(i) * 64) for i, p
                                                 in enumerate(self.PROPOSALS)})[pid]
            proposal.approved_by = "alice-operator"
            proposal.approval_hash = proposal.proposal_hash
            proposal.approved_at = datetime.now(timezone.utc)
            incident.upsert_remediation_proposal(proposal)
        self.hashes = hashes
        self.repository.save_incident(incident)

    def _claim(self, pid, owner, stage, *, commit=None, finish=None):
        """claim -> progress(stage) -> optional finish; return reason."""
        p_hash = self.hashes[pid]
        reason, _ = self.repository.claim_execution_lease(
            "inc-multi", pid, p_hash,
            owner=owner, now=self.now, lease_seconds=600.0,
        )
        assert reason == "claimed", (pid, reason)
        self.repository.persist_execution_progress(
            "inc-multi", pid, owner,
            stage=stage, now=self.now, lease_seconds=600.0,
            commit_sha=commit,
            branch_name=f"automation/remediation/inc-multi/{pid}" if commit else None,
        )
        if finish is not None:
            status, final_stage, updates = finish
            ok = self.repository.finish_execution_lease(
                "inc-multi", pid, owner,
                status=status, stage=final_stage, now=self.now,
                updates=updates,
            )
            assert ok, (pid, final_stage)
        return reason

    def _spec_seed(self):
        """Fresh incident with p-a (attempt 2, COMMIT_CREATED, worker-a),
        p-b (attempt 4, PR_CREATED, worker-b), p-c (no claim)."""
        incident = IncidentAggregate("inc-active", "cpu", "HIGH", "ctx")
        incident.move_to_triage()
        hashes = {}
        for pid in ("p-a", "p-b", "p-c"):
            patch = (
                f"--- a/app/{pid}.py\n+++ b/app/{pid}.py\n"
                "@@ -1 +1 @@\n-old()\n+new()\n"
            )
            proposal = HotfixProposal(
                id=pid,
                incident_id="inc-active",
                target_filepath=f"app/{pid}.py",
                diff_patch_payload=patch,
                source_sha="a" * 40,
                repository="acme/checkout",
                status="APPROVED",
                validation_plan=["pytest -q"],
            )
            assert proposal.apply_verification_pass()
            proposal.proposal_hash = (str(len(hashes) + 1) * 64)
            hashes[pid] = proposal.proposal_hash
            proposal.approved_by = "alice-operator"
            proposal.approval_hash = proposal.proposal_hash
            proposal.approved_at = datetime.now(timezone.utc)
            incident.upsert_remediation_proposal(proposal)
        return incident, hashes

    @staticmethod
    def _stage_chain(repository, incident_id, pid, owner, stages, commit=None):
        for stage in stages:
            ok = repository.persist_execution_progress(
                incident_id,
                pid,
                owner,
                stage=stage,
                now=datetime.now(timezone.utc),
                lease_seconds=600.0,
                commit_sha=commit
                if stage == "COMMIT_CREATED" and commit
                else None,
                branch_name=(
                    f"automation/remediation/{incident_id}/{pid}"
                    if stage == "COMMIT_CREATED" and commit
                    else None
                ),
            )
            assert ok, (pid, stage)

    def _reclaim_to(self, repository, incident_id, pid, p_hash, owner,
                    attempts):
        for index in range(attempts):
            now = datetime.now(timezone.utc)
            reason, _ = repository.claim_execution_lease(
                incident_id, pid, p_hash,
                owner=owner, now=now, lease_seconds=600.0,
            )
            assert reason == "claimed", (pid, index, reason)
            # expire BETWEEN claims only; the final claim stays live
            # so subsequent stage persists are authorized
            if index < attempts - 1:
                with repository.engine.begin() as connection:
                    connection.execute(
                        sa_update(execution_claims_table)
                        .where(
                            execution_claims_table.c.incident_id == incident_id
                        )
                        .values(
                            lease_expires_at=datetime.now(timezone.utc)
                            - timedelta(seconds=1)
                        )
                    )

    def test_get_active_incidents_projects_claims_per_proposal(self):
        incident, hashes = self._spec_seed()
        self.repository.save_incident(incident)

        # p-a: attempt 2, stage COMMIT_CREATED, worker-a, durable commit
        self._reclaim_to(
            self.repository, "inc-active", "p-a", hashes["p-a"],
            "worker-a", attempts=2,
        )
        self._stage_chain(
            self.repository, "inc-active", "p-a", "worker-a",
            ["WORKSPACE_CREATED", "PATCH_APPLIED", "VALIDATION_STARTED",
             "VALIDATION_PASSED", "COMMIT_CREATED"],
            commit="e" * 40,
        )
        # p-b: attempt 4, stage PR_CREATED, worker-b
        self._reclaim_to(
            self.repository, "inc-active", "p-b", hashes["p-b"],
            "worker-b", attempts=4,
        )
        self._stage_chain(
            self.repository, "inc-active", "p-b", "worker-b",
            ["WORKSPACE_CREATED", "PATCH_APPLIED", "VALIDATION_STARTED",
             "VALIDATION_PASSED", "COMMIT_CREATED", "REMOTE_PUBLISHED",
             "REMOTE_VERIFIED", "PR_DISCOVERY", "PR_CREATED"],
            commit="f" * 40,
        )
        # p-c: no claim row at all

        active = [
            item
            for item in self.repository.get_active_incidents()
            if item.id == "inc-active"
        ]
        self.assertEqual(len(active), 1)
        by_id = {item.id: item for item in active[0].patch_proposals}
        a, b, c = by_id["p-a"], by_id["p-b"], by_id["p-c"]

        # A gets only A's claim state
        self.assertEqual(a.execution_stage, "COMMIT_CREATED")
        self.assertEqual(a.execution_attempts, 2)
        self.assertEqual(a.lease_owner, "worker-a")
        self.assertEqual(a.commit_sha, "e" * 40)
        self.assertTrue(a.branch_name.endswith("/p-a"))
        # B gets only B's claim state
        self.assertEqual(b.execution_stage, "PR_CREATED")
        self.assertEqual(b.execution_attempts, 4)
        self.assertEqual(b.lease_owner, "worker-b")
        self.assertEqual(b.commit_sha, "f" * 40)
        self.assertTrue(b.branch_name.endswith("/p-b"))
        self.assertNotEqual(a.execution_id, b.execution_id)
        # C preserves its JSON coordination view (no claim projected)
        self.assertEqual(c.execution_stage, "")
        self.assertEqual(c.execution_attempts, 0)
        self.assertFalse(c.lease_owner)
        self.assertFalse(c.commit_sha)
        # cross-contamination impossible
        self.assertNotEqual(a.lease_owner, b.lease_owner)
        self.assertNotEqual(a.commit_sha, b.commit_sha)

    def test_claims_project_independently_across_proposals(self):
        # p-a: active lease at COMMIT_CREATED with durable commit
        self._claim("p-a", "worker-1", "COMMIT_CREATED", commit="e" * 40)
        # p-b: active lease at VALIDATION_PASSED (different owner)
        self._claim("p-b", "worker-2", "VALIDATION_PASSED")
        # p-c: no claim at all
        # p-d: completed claim (FREE, PR_CREATED)
        self._claim(
            "p-d", "worker-3", "PR_DISCOVERY",
            commit="f" * 40,
            finish=(
                "PR_CREATED", "COMPLETED",
                {"pull_request_url": "https://github.example/pull/9"},
            ),
        )
        # p-e: failed recoverable claim (FREE, FAILED cursor)
        self._claim(
            "p-e", "worker-4", "CLAIMED",
            finish=(
                "EXECUTION_FAILED", "FAILED",
                {"last_failure_stage": "validation"},
            ),
        )

        incident = self.repository.get_incident_by_id("inc-multi")
        by_id = {item.id: item for item in incident.patch_proposals}
        self.assertEqual(set(by_id), set(self.PROPOSALS))

        a, b, c, d, e = (by_id[p] for p in self.PROPOSALS)

        # active independent leases
        self.assertEqual(a.execution_stage, "COMMIT_CREATED")
        self.assertEqual(a.execution_attempts, 1)
        self.assertEqual(a.lease_owner, "worker-1")
        self.assertEqual(a.commit_sha, "e" * 40)
        self.assertTrue(a.branch_name.endswith("/p-a"))

        self.assertEqual(b.execution_stage, "VALIDATION_PASSED")
        self.assertEqual(b.execution_attempts, 1)
        self.assertEqual(b.lease_owner, "worker-2")
        self.assertFalse(b.commit_sha)  # did NOT inherit p-a's commit
        self.assertNotEqual(a.execution_id, b.execution_id)

        # no claim -> untouched JSON view
        self.assertEqual(c.execution_stage, "")
        self.assertEqual(c.execution_attempts, 0)
        self.assertFalse(c.lease_owner)

        # completed claim -> its own PR identity, lease released
        self.assertEqual(d.status, "PR_CREATED")
        self.assertEqual(d.execution_stage, "COMPLETED")
        self.assertEqual(d.lease_owner, "")
        self.assertEqual(d.commit_sha, "f" * 40)
        self.assertTrue(d.pull_request_url.endswith("/pull/9"))

        # failed claim -> recoverable, its own failure fields
        self.assertEqual(e.status, "EXECUTION_FAILED")
        self.assertEqual(e.execution_stage, "FAILED")
        self.assertEqual(e.last_failure_stage, "validation")
        self.assertEqual(e.lease_owner, "")

        # durable rows survive reload as stored (5 rows, keyed correctly)
        rows = {
            row["proposal_id"]: row
            for row in self.repository.get_execution_claims_for_incident(
                "inc-multi"
            )
        }
        self.assertEqual(set(rows), {"p-a", "p-b", "p-d", "p-e"})
        self.assertEqual(rows["p-a"]["stage"], "COMMIT_CREATED")
        self.assertEqual(rows["p-b"]["stage"], "VALIDATION_PASSED")
        self.assertEqual(rows["p-d"]["state"], "FREE")
        self.assertEqual(rows["p-e"]["last_failure_stage"], "validation")


if __name__ == "__main__":
    unittest.main()
