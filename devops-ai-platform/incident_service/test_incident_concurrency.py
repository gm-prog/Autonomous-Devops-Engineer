"""Phase 8.1 — durable aggregate concurrency control (Invariant B).

Covers §7 (stale regeneration), §8 (stale-write matrix), §10 (approval
race), §11 (regeneration vs execution race), §12 (RCA vs approval race),
§17/§18 (REAL threads + Barrier, no sleeps), §19 (stale reload), §23
(migration idempotency + data preservation) and §37 (stale version across
restart).

Backend guarantee (documented honestly):

    The correctness gate is the SQL predicate
    ``UPDATE devops_incidents SET version=version+1
     WHERE id=:id AND version=:expected`` with a rowcount check inside
    the write transaction. That predicate is evaluated *by the database*
    on every backend. On SQLite the file lock serializes writers, so a
    concurrent thread's UPDATE matches either the version it observed or
    zero rows. PostgreSQL provides the same guarantee via row-level
    locking/MVCC. Nothing here relies on timestamps, UUIDs or client
    side comparison.

Threads synchronize on a ``threading.Barrier`` before their first write;
there are no timing sleeps anywhere in this module.
"""

import json
import os
import tempfile
import threading
import unittest
import uuid
from datetime import datetime, timezone

from sqlalchemy import text

from incident_service.application.failures import IncidentConcurrencyConflict
from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.domain.entities.hotfix_proposal import HotfixProposal
from incident_service.infrastructure.database.postgres_incident_repo import (
    PostgresIncidentRepositoryAdapter,
)
from incident_service.presentation.rest.controllers import (
    RemediationRequest,
    create_remediation,
)
from incident_service.presentation.rest.test_remediation_authorization import (
    _deployment_evidence,
)

SOURCE_SHA = "a" * 40


def promote_to_root_cause_found(
    incident,
    root_cause="connection pool exhaustion under peak load",
):
    """Local fixture copy: canonical incident chain + schema-valid RCA
    evidence (the proposal-intake precondition). Kept self-contained so
    this module does not depend on presentation-test refactors."""
    from incident_service.application.services.proposal_generation_service import (
        incident_service_evidence_from_rca,
    )
    from incident_service.domain.entities.root_cause_analysis import (
        RootCauseAnalysis,
    )

    if incident.status == "Raised":
        incident.move_to_triage()
    if incident.status == "Triage":
        incident.begin_investigation()
    if incident.status == "Investigating":
        incident.mark_root_cause_found()
    incident.attach_evidence(
        incident_service_evidence_from_rca(
            RootCauseAnalysis(
                id=f"rca-{incident.id}",
                incident_id=incident.id,
                root_cause=root_cause,
                confidence=0.9,
                evidence_refs=[item.id for item in incident.evidence],
            )
        )
    )
    return incident

PATCH = """--- a/src/service.py
+++ b/src/service.py
@@ -1 +1 @@
-old()
+new()
"""


def _utcnow():
    return datetime.now(timezone.utc)


class _ConcurrencyFixture(unittest.TestCase):
    """Fresh temp-file SQLite database per test + promoted incident."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db_path = os.path.join(self._tmp.name, "c81.db")
        self.repository = PostgresIncidentRepositoryAdapter(
            f"sqlite:///{self.db_path}"
        )
        self.incident_seq = 0

    def _seed(self, status_chain=True):
        """Create + persist an incident whose chain reached
        RootCauseFound with deployment + RCA evidence (proposal-ready)."""
        self.incident_seq += 1
        iid = f"inc-c81-{uuid.uuid4().hex[:10]}"
        incident = IncidentAggregate(iid, "pool exhaustion", "HIGH", "gateway")
        incident.attach_evidence(_deployment_evidence(evidence_id=f"dep-{iid}"))
        promote_to_root_cause_found(incident)
        self.repository.save_incident(incident)
        return self.repository.get_incident_by_id(iid)

    def _shim(self, incident):
        """Legacy request → PROPOSED proposal through the Phase 8.1
        compatibility shim (validated, persisted, zero execution)."""
        result = create_remediation(
            incident.id,
            RemediationRequest(
                target_filepath="src/service.py",
                patch=PATCH,
                source_sha=SOURCE_SHA,
                repository_slug="acme/checkout",
            ),
            self.repository,
        )
        assert result["status"] == "PROPOSED", result
        return result

    def _run_threads(self, *targets):
        """Start all workers synchronized on one Barrier; join with a
        bounded timeout (not a timing sleep — the barrier does the
        synchronizing). Returns [(label, outcome), ...]."""
        barrier = threading.Barrier(len(targets))
        results = []

        def wrap(label, fn):
            barrier.wait()
            try:
                results.append((label, fn()))
            except IncidentConcurrencyConflict as exc:
                results.append((label, exc))
            except Exception as exc:  # noqa: BLE001 — surfaced in asserts
                results.append((label, exc))

        threads = [
            threading.Thread(target=wrap, args=(label, fn))
            for label, fn in targets
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
            self.assertFalse(thread.is_alive(), "worker thread hung")
        return results


class VersionLifecycleTests(_ConcurrencyFixture):
    """Creation=0, +1 exactly once per successful update, reload."""

    def test_creation_persists_version_zero_and_updates_increment(self):
        incident = self._seed()
        self.assertEqual(incident.version, 0)  # creation = 0

        incident = self.repository.get_incident_by_id(incident.id)
        incident.attach_evidence(
            _deployment_evidence(evidence_id=f"dep2-{incident.id}")
        )
        self.repository.save_incident(incident)
        self.assertEqual(
            self.repository.get_incident_by_id(incident.id).version, 1
        )

        incident = self.repository.get_incident_by_id(incident.id)
        incident.attach_evidence(
            _deployment_evidence(evidence_id=f"dep3-{incident.id}")
        )
        self.repository.save_incident(incident)
        self.assertEqual(
            self.repository.get_incident_by_id(incident.id).version, 2
        )

    def test_reload_returns_latest_version_and_state(self):
        # §19: reload is authoritative — no stale shadow state.
        incident = self._seed()
        first = self.repository.get_incident_by_id(incident.id)
        first.attach_evidence(
            _deployment_evidence(evidence_id=f"rel-{first.id}")
        )
        self.repository.save_incident(first)

        reloaded = self.repository.get_incident_by_id(incident.id)
        self.assertEqual(reloaded.version, first.version)
        self.assertEqual(reloaded.status, first.status)
        self.assertEqual(len(reloaded.evidence), len(first.evidence))

    def test_stale_version_across_restart(self):
        # §37: version survives a process restart (new adapter instance,
        # new engine, same durable file); the pre-restart in-memory copy
        # is stale and its write is rejected.
        incident = self._seed()
        pre_restart = self.repository.get_incident_by_id(incident.id)

        restarted = PostgresIncidentRepositoryAdapter(
            f"sqlite:///{self.db_path}"
        )
        current = restarted.get_incident_by_id(incident.id)
        self.assertEqual(current.version, pre_restart.version)

        # post-restart writer advances the aggregate...
        current.attach_evidence(
            _deployment_evidence(evidence_id=f"post-{current.id}")
        )
        restarted.save_incident(current)

        # ...the pre-restart copy must be rejected, not resurrected.
        version_after_post_restart_write = current.version
        pre_restart.attach_evidence(
            _deployment_evidence(evidence_id=f"ghost-{pre_restart.id}")
        )
        with self.assertRaises(IncidentConcurrencyConflict):
            self.repository.save_incident(pre_restart)
        final = restarted.get_incident_by_id(incident.id)
        self.assertEqual(final.version, version_after_post_restart_write)
        self.assertNotIn(
            "ghost-" + pre_restart.id, [item.id for item in final.evidence]
        )


class StaleWriteMatrixTests(_ConcurrencyFixture):
    """§8: stale RCA/approval/PR_CREATED-shaped writers, failed
    transactions leave no partial writes, two readers one writer."""

    def test_stale_lifecycle_write_is_rejected_state_preserved(self):
        incident = self._seed()  # RootCauseFound, version 0
        stale = self.repository.get_incident_by_id(incident.id)
        writer = self.repository.get_incident_by_id(incident.id)

        writer.attach_evidence(
            _deployment_evidence(evidence_id=f"lc-{writer.id}")
        )
        self.repository.save_incident(writer)
        self.assertEqual(
            self.repository.get_incident_by_id(incident.id).version, 1
        )

        # stale writer holds the old snapshot; its write must reject with
        # a typed conflict carrying the incident id + expected version.
        stale_version_before = stale.version
        stale.attach_evidence(
            _deployment_evidence(evidence_id=f"lc-stale-{stale.id}")
        )
        with self.assertRaises(IncidentConcurrencyConflict) as ctx:
            self.repository.save_incident(stale)
        self.assertEqual(stale.version, stale_version_before)
        self.assertIn(incident.id, str(ctx.exception))
        self.assertIn("stale aggregate version", str(ctx.exception))

        final = self.repository.get_incident_by_id(incident.id)
        self.assertEqual(final.version, 1)
        self.assertEqual(final.status, "RootCauseFound")
        self.assertNotIn(
            f"lc-stale-{stale.id}", [item.id for item in final.evidence]
        )

    def test_stale_write_leaves_no_partial_evidence_writes(self):
        incident = self._seed()
        stale = self.repository.get_incident_by_id(incident.id)

        writer = self.repository.get_incident_by_id(incident.id)
        writer.attach_evidence(
            _deployment_evidence(evidence_id=f"adv-{writer.id}")
        )
        self.repository.save_incident(writer)

        # baseline AFTER the winning write — the stale attempt must not
        # add anything on top of it (rollback drops the whole save).
        evidence_before = sorted(
            item.id
            for item in self.repository.get_incident_by_id(incident.id).evidence
        )

        # the stale save carries an in-memory evidence attachment — the
        # rollback must drop it entirely (no partial write).
        stale.attach_evidence(
            _deployment_evidence(evidence_id=f"partial-{stale.id}")
        )
        with self.assertRaises(IncidentConcurrencyConflict):
            self.repository.save_incident(stale)

        final = self.repository.get_incident_by_id(incident.id)
        self.assertEqual(
            sorted(item.id for item in final.evidence), evidence_before
        )
        self.assertNotIn(
            f"partial-{stale.id}", [item.id for item in final.evidence]
        )

    def test_two_readers_one_writer(self):
        incident = self._seed()
        reader_a = self.repository.get_incident_by_id(incident.id)
        reader_b = self.repository.get_incident_by_id(incident.id)
        writer = self.repository.get_incident_by_id(incident.id)

        writer.attach_evidence(
            _deployment_evidence(evidence_id=f"w-{writer.id}")
        )
        self.repository.save_incident(writer)

        stale_a_version = reader_a.version
        reader_a.attach_evidence(
            _deployment_evidence(evidence_id=f"a-{reader_a.id}")
        )
        with self.assertRaises(IncidentConcurrencyConflict):
            self.repository.save_incident(reader_a)
        self.assertEqual(reader_a.version, stale_a_version)

        reader_b.attach_evidence(
            _deployment_evidence(evidence_id=f"b-{reader_b.id}")
        )
        with self.assertRaises(IncidentConcurrencyConflict):
            self.repository.save_incident(reader_b)

        final = self.repository.get_incident_by_id(incident.id)
        ids = [item.id for item in final.evidence]
        self.assertIn(f"w-{writer.id}", ids)
        self.assertNotIn(f"a-{reader_a.id}", ids)
        self.assertNotIn(f"b-{reader_b.id}", ids)


class StaleRegenerationTests(_ConcurrencyFixture):
    """§7: B approves at N+1 while A holds a stale snapshot; the stale
    save must 409-style reject and the persisted APPROVED state stays."""

    def test_stale_regeneration_cannot_clobber_approved_proposal(self):
        incident = self._seed()
        result = self._shim(incident)
        proposal_id = result["proposal_id"]
        proposal_hash = result["proposal_hash"]

        # A's snapshot: PROPOSED proposal, taken before approval.
        stale = self.repository.get_incident_by_id(incident.id)

        # B approves → durable version advances (CAS save inside).
        from incident_service.application.services.proposal_approval_service import (
            ProposalApprovalService,
        )

        ProposalApprovalService(self.repository).approve(
            incident_id=incident.id,
            proposal_id=proposal_id,
            proposal_hash=proposal_hash,
            approved_by="operator-b",
        )
        approved = self.repository.get_incident_by_id(incident.id)
        self.assertEqual(approved.patch_proposals[0].status, "APPROVED")

        # A's stale snapshot tries to write its regenerated proposal state.
        stale.patch_proposals[0].status = "PROPOSED"
        with self.assertRaises(IncidentConcurrencyConflict):
            self.repository.save_incident(stale)

        final = self.repository.get_incident_by_id(incident.id)
        self.assertEqual(final.patch_proposals[0].status, "APPROVED")
        self.assertEqual(final.patch_proposals[0].approved_by, "operator-b")
        self.assertEqual(final.version, approved.version)

    def test_generation_save_propagates_conflict_not_wrapped_failure(self):
        # The generation pipeline must surface IncidentConcurrencyConflict
        # (→ REST 409) rather than burying it as a persistence failure.
        incident = self._seed()
        self._shim(incident)
        stale = self.repository.get_incident_by_id(incident.id)

        writer = self.repository.get_incident_by_id(incident.id)
        writer.attach_evidence(
            _deployment_evidence(evidence_id=f"adv-{writer.id}")
        )
        self.repository.save_incident(writer)  # version +1

        from incident_service.application.services.proposal_generation_service import (
            ProposalGenerationService,
        )

        with self.assertRaises(IncidentConcurrencyConflict):
            ProposalGenerationService(self.repository)._save(stale)


class ApprovalAndRaceTests(_ConcurrencyFixture):
    """§10 (approval race) + §12 (RCA-shaped write vs approval)."""

    def test_concurrent_approvals_preserve_single_approved_state(self):
        # §10: two operators approve the same proposal concurrently.
        # Policy-preserving outcomes: the second call either observes
        # APPROVED (idempotent-same) or loses the CAS and surfaces a
        # typed conflict. Either way: exactly one durable approval.
        incident = self._seed()
        result = self._shim(incident)
        payload = dict(
            incident_id=incident.id,
            proposal_id=result["proposal_id"],
            proposal_hash=result["proposal_hash"],
            approved_by="operator-1",
        )

        from incident_service.application.services.proposal_approval_service import (
            ProposalApprovalService,
        )

        def approve_call():
            return ProposalApprovalService(self.repository).approve(**payload)

        outcomes = self._run_threads(
            ("op-a", approve_call), ("op-b", approve_call)
        )

        for label, outcome in outcomes:
            if isinstance(outcome, IncidentConcurrencyConflict):
                continue  # policy-preserving loser
            self.assertIsInstance(
                outcome,
                dict,
                f"{label}: unexpected outcome {outcome!r}",
            )

        final = self.repository.get_incident_by_id(incident.id)
        self.assertEqual(final.patch_proposals[0].status, "APPROVED")
        self.assertEqual(
            sorted(item.id for item in final.patch_proposals),
            [result["proposal_id"]],
        )

    def test_rca_shaped_stale_write_vs_approval(self):
        # §12: a stale root-cause update racing a successful approval —
        # approval wins the CAS; the RCA-shaped write is rejected and
        # cannot regress the proposal or incident state.
        incident = self._seed()
        result = self._shim(incident)
        stale = self.repository.get_incident_by_id(incident.id)

        from incident_service.application.services.proposal_approval_service import (
            ProposalApprovalService,
        )

        ProposalApprovalService(self.repository).approve(
            incident_id=incident.id,
            proposal_id=result["proposal_id"],
            proposal_hash=result["proposal_hash"],
            approved_by="operator-c",
        )
        approved_status = self.repository.get_incident_by_id(incident.id).status

        # stale RCA-shaped write: the pre-approval snapshot tries to
        # regress the lifecycle state after the approval landed.
        stale.status = "Investigating"
        with self.assertRaises(IncidentConcurrencyConflict):
            self.repository.save_incident(stale)

        final = self.repository.get_incident_by_id(incident.id)
        self.assertEqual(final.status, approved_status)
        self.assertEqual(final.patch_proposals[0].status, "APPROVED")


class RegenerationVsExecutionRaceTests(_ConcurrencyFixture):
    """§11: winner lifecycle durable in both interleavings; the terminal
    execution transaction remains one atomic unit (Invariants C+D)."""

    def _approved_incident(self):
        incident = self._seed()
        result = self._shim(incident)
        from incident_service.application.services.proposal_approval_service import (
            ProposalApprovalService,
        )

        ProposalApprovalService(self.repository).approve(
            incident_id=incident.id,
            proposal_id=result["proposal_id"],
            proposal_hash=result["proposal_hash"],
            approved_by="operator-x",
        )
        return incident.id, result

    def test_execution_finish_first_then_stale_regen_rejected(self):
        iid, result = self._approved_incident()
        stale = self.repository.get_incident_by_id(iid)  # pre-execution view

        reason, _ = self.repository.claim_execution_lease(
            iid,
            result["proposal_id"],
            result["proposal_hash"],
            owner="worker-a",
            now=_utcnow(),
            lease_seconds=600.0,
        )
        self.assertEqual(reason, "claimed")

        finished = self.repository.finish_execution_lease(
            iid,
            result["proposal_id"],
            "worker-a",
            status="PR_CREATED",
            stage="COMPLETED",
            now=_utcnow(),
            updates={
                "commit_sha": "c" * 40,
                "branch_name": "c81/fix",
                "pull_request_url": "https://github.com/acme/checkout/pull/7",
            },
            promote_incident_pr_created=True,
        )
        self.assertTrue(finished)

        # stale regeneration now attempts to overwrite the terminal state
        stale.patch_proposals[0].status = "PROPOSED"
        with self.assertRaises(IncidentConcurrencyConflict):
            self.repository.save_incident(stale)

        final = self.repository.get_incident_by_id(iid)
        self.assertEqual(final.status, "RemediationPRCreated")
        self.assertEqual(final.patch_proposals[0].status, "PR_CREATED")
        self.assertEqual(
            final.patch_proposals[0].pull_request_url,
            "https://github.com/acme/checkout/pull/7",
        )

        # §8: claim cursor released inside the same terminal transaction.
        with self.repository.engine.connect() as connection:
            claim = connection.execute(
                text(
                    "SELECT state, lease_owner FROM devops_execution_claims"
                    " WHERE incident_id = :iid"
                ),
                {"iid": iid},
            ).mappings().one()
        self.assertEqual(claim["state"], "FREE")
        self.assertIsNone(claim["lease_owner"])

    def test_regeneration_wins_then_execution_finish_lands_atomically(self):
        # Interleaving: claim happens, THEN a proposal regeneration
        # overwrites the proposal JSON (version +1), THEN execution lands
        # its terminal write. The terminal transaction must stay ONE unit
        # (Invariants C+D): either it fully applies — status PR_CREATED,
        # claim FREE, version +1 exactly once — or it writes nothing.
        # Regeneration's write remains durable in the version history; the
        # claim/lease machinery is never corrupted by the interleave.
        iid, result = self._approved_incident()

        reason, _ = self.repository.claim_execution_lease(
            iid,
            result["proposal_id"],
            result["proposal_hash"],
            owner="worker-b",
            now=_utcnow(),
            lease_seconds=600.0,
        )
        self.assertEqual(reason, "claimed")
        version_at_claim = self.repository.get_incident_by_id(iid).version

        # regeneration lands first (fresh snapshot, new proposal body)
        fresh = self.repository.get_incident_by_id(iid)
        fresh.patch_proposals[0].status = "PROPOSED"
        fresh.patch_proposals[0].proposal_hash = "f" * 64
        self.repository.save_incident(fresh)
        after_regen = self.repository.get_incident_by_id(iid)
        self.assertEqual(after_regen.version, version_at_claim + 1)

        finished = self.repository.finish_execution_lease(
            iid,
            result["proposal_id"],
            "worker-b",
            status="PR_CREATED",
            stage="COMPLETED",
            now=_utcnow(),
            updates={"pull_request_url": "https://github.com/acme/checkout/pull/9"},
            promote_incident_pr_created=True,
        )
        self.assertTrue(finished)

        final = self.repository.get_incident_by_id(iid)
        # terminal write landed atomically: incident promoted, proposal
        # terminal, claim released — all three in one transaction.
        self.assertEqual(final.status, "RemediationPRCreated")
        self.assertEqual(final.patch_proposals[0].status, "PR_CREATED")
        self.assertEqual(
            final.patch_proposals[0].pull_request_url,
            "https://github.com/acme/checkout/pull/9",
        )
        self.assertEqual(
            final.version, after_regen.version + 1
        )  # exactly one +1 for the terminal write
        with self.repository.engine.connect() as connection:
            claim_state = connection.execute(
                text(
                    "SELECT state FROM devops_execution_claims"
                    " WHERE incident_id = :iid"
                ),
                {"iid": iid},
            ).scalar_one()
        self.assertEqual(claim_state, "FREE")


class RealThreadRaceTests(_ConcurrencyFixture):
    """§17/§18: real concurrent writers (threads + Barrier, no sleeps)."""

    def test_two_concurrent_legacy_remediation_calls_one_proposal(self):
        # §21: two simultaneous legacy intake calls → one logical
        # proposal, zero execution side effects. Outcomes are either both
        # 200 (second observed the committed proposal) or one typed
        # conflict — never two proposals, never an orchestrator.
        import threading
        from unittest.mock import MagicMock, patch

        from fastapi import HTTPException

        from incident_service.presentation.rest import controllers as controllers_module

        incident = self._seed()
        barrier = threading.Barrier(2)
        outcomes = {}

        def call(label):
            barrier.wait()
            with patch.object(
                controllers_module,
                "get_remediation_orchestrator",
                return_value=MagicMock(),
            ) as provider:
                try:
                    outcome = create_remediation(
                        incident.id,
                        RemediationRequest(
                            target_filepath="src/service.py",
                            patch=PATCH,
                            source_sha=SOURCE_SHA,
                            repository_slug="acme/checkout",
                        ),
                        self.repository,
                    )
                except (IncidentConcurrencyConflict, HTTPException) as exc:
                    outcome = exc
                self.assertFalse(
                    provider.called, "shim must never construct orchestrator"
                )
            outcomes[label] = outcome

        threads = [
            threading.Thread(target=call, args=("a",)),
            threading.Thread(target=call, args=("b",)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
            self.assertFalse(thread.is_alive())

        self.assertEqual(sorted(outcomes), ["a", "b"])
        successes = [
            outcome
            for outcome in outcomes.values()
            if not isinstance(outcome, BaseException)
        ]
        for outcome in outcomes.values():
            if isinstance(outcome, BaseException):
                self.assertIsInstance(
                    outcome, (IncidentConcurrencyConflict, HTTPException)
                )
        self.assertGreaterEqual(len(successes), 1)

        final = self.repository.get_incident_by_id(incident.id)
        self.assertEqual(len(final.patch_proposals), 1)
        self.assertEqual(final.patch_proposals[0].status, "PROPOSED")
        self.assertEqual(final.patch_proposals[0].pull_request_url, None)
        # both successful callers converge on the same logical identity
        for outcome in successes:
            self.assertEqual(outcome["proposal_id"], "proposal-" + incident.id)
            self.assertEqual(outcome["status"], "PROPOSED")

    def test_four_concurrent_saves_one_winner(self):
        incident = self._seed()
        snapshots = [
            self.repository.get_incident_by_id(incident.id) for _ in range(4)
        ]

        def writer(snapshot, evidence_id):
            def run():
                snapshot.attach_evidence(
                    _deployment_evidence(evidence_id=evidence_id)
                )
                return self.repository.save_incident(snapshot)

            return run

        targets = [
            (f"thread-{i}", writer(snapshot, f"race-{i}-{incident.id}"))
            for i, snapshot in enumerate(snapshots)
        ]
        outcomes = self._run_threads(*targets)

        winners = [
            label
            for label, outcome in outcomes
            if not isinstance(outcome, BaseException)
        ]
        losers = [
            (label, outcome)
            for label, outcome in outcomes
            if isinstance(outcome, IncidentConcurrencyConflict)
        ]
        others = [
            (label, outcome)
            for label, outcome in outcomes
            if isinstance(outcome, BaseException)
            and not isinstance(outcome, IncidentConcurrencyConflict)
        ]
        self.assertEqual(others, [], f"unexpected failures: {others}")
        self.assertEqual(len(winners), 1, f"winners={winners} all={outcomes}")
        self.assertEqual(len(losers), 3)

        final = self.repository.get_incident_by_id(incident.id)
        self.assertEqual(final.version, 1)  # creation 0 → exactly one +1
        ids = [item.id for item in final.evidence]
        winner_label = winners[0]
        winner_index = int(winner_label.split("-")[1])
        self.assertIn(f"race-{winner_index}-{incident.id}", ids)
        for index in range(4):
            if index != winner_index:
                self.assertNotIn(f"race-{index}-{incident.id}", ids)

    def test_concurrent_stale_reloads_cannot_both_commit(self):
        # §18: two readers reload the same version, then race their
        # writes — at most one may commit.
        incident = self._seed()
        reader_x = self.repository.get_incident_by_id(incident.id)
        reader_y = self.repository.get_incident_by_id(incident.id)
        self.assertEqual(reader_x.version, reader_y.version)
        barrier = threading.Barrier(2)
        outcomes = []

        def race(snapshot, evidence_id):
            def run():
                barrier.wait()
                snapshot.attach_evidence(
                    _deployment_evidence(evidence_id=evidence_id)
                )
                try:
                    self.repository.save_incident(snapshot)
                    outcomes.append("committed")
                except IncidentConcurrencyConflict:
                    outcomes.append("conflict")

            return run

        threads = [
            threading.Thread(
                target=race(reader_x, f"x-{incident.id}")
            ),
            threading.Thread(
                target=race(reader_y, f"y-{incident.id}")
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
            self.assertFalse(thread.is_alive())

        self.assertEqual(outcomes.count("committed"), 1, outcomes)
        self.assertEqual(outcomes.count("conflict"), 1, outcomes)


class MigrationTests(_ConcurrencyFixture):
    """§23: idempotent schema evolution — fresh + legacy + rerun, with
    proposals/evidence/claims preserved. Never drop/recreate tables.

    This class needs a PRISTINE file for the legacy-upgrade case, so the
    adapter is created inside each test, not in setUp."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db_path = os.path.join(self._tmp.name, "migration.db")
        self.repository = None
        self.incident_seq = 0

    def _adapter(self):
        self.repository = PostgresIncidentRepositoryAdapter(
            f"sqlite:///{self.db_path}"
        )
        return self.repository

    def test_fresh_database_has_version_column_default_zero(self):
        self._adapter()
        incident = self._seed()
        self.assertEqual(incident.version, 0)
        with self.repository.engine.connect() as connection:
            rows = connection.execute(
                text("PRAGMA table_info(devops_incidents)")
            ).fetchall()
        columns = {row[1]: row for row in rows}
        self.assertIn("version", columns)
        info = columns["version"]
        self.assertEqual(str(info[2]).upper(), "INTEGER")
        self.assertEqual(info[3], 1)  # NOT NULL
        self.assertEqual(str(info[4]).strip("'"), "0")  # DEFAULT 0
        with self.repository.engine.connect() as connection:
            value = connection.execute(
                text("SELECT version FROM devops_incidents WHERE id = :id"),
                {"id": incident.id},
            ).scalar_one()
        self.assertEqual(value, 0)

    def test_legacy_database_upgraded_in_place_data_preserved_rerun_safe(self):
        from sqlalchemy import create_engine

        legacy_engine = create_engine(f"sqlite:///{self.db_path}")
        with legacy_engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TABLE devops_incidents ("
                    " id VARCHAR(64) NOT NULL PRIMARY KEY,"
                    " title VARCHAR(255) NOT NULL,"
                    " severity VARCHAR(32) NOT NULL,"
                    " context TEXT NOT NULL,"
                    " status VARCHAR(64) NOT NULL,"
                    " created_at DATETIME NOT NULL,"
                    " patch_proposals TEXT NOT NULL DEFAULT '[]')"
                )
            )
            connection.execute(
                text(
                    "CREATE TABLE devops_incident_evidence ("
                    " id VARCHAR(64) NOT NULL PRIMARY KEY,"
                    " incident_id VARCHAR(64) NOT NULL,"
                    " kind VARCHAR(64) NOT NULL,"
                    " source VARCHAR(128) NOT NULL,"
                    " observed_at DATETIME NOT NULL,"
                    " payload TEXT NOT NULL)"
                )
            )
            connection.execute(
                text(
                    "CREATE TABLE devops_execution_claims ("
                    " incident_id VARCHAR(64) NOT NULL,"
                    " proposal_id VARCHAR(200) NOT NULL,"
                    " proposal_hash VARCHAR(64) NOT NULL,"
                    " execution_id VARCHAR(64) NOT NULL,"
                    " attempt INTEGER NOT NULL DEFAULT 0,"
                    " state VARCHAR(16) NOT NULL DEFAULT 'FREE',"
                    " lease_owner VARCHAR(160),"
                    " lease_acquired_at DATETIME,"
                    " lease_expires_at DATETIME,"
                    " last_heartbeat_at DATETIME,"
                    " completed_at DATETIME,"
                    " stage VARCHAR(32) NOT NULL DEFAULT '',"
                    " commit_sha VARCHAR(40),"
                    " branch_name VARCHAR(255),"
                    " pull_request_url TEXT,"
                    " last_failure_stage VARCHAR(32),"
                    " last_failure_reason TEXT,"
                    " PRIMARY KEY (incident_id, proposal_id))"
                )
            )
            legacy_proposal = HotfixProposal(
                id="proposal-legacy-1",
                incident_id="legacy-1",
                target_filepath="src/service.py",
                diff_patch_payload=PATCH,
                status="APPROVED",
                approved_by="operator-legacy",
                proposal_hash="e" * 64,
                repository="acme/checkout",
                source_sha=SOURCE_SHA,
            )
            connection.execute(
                text(
                    "INSERT INTO devops_incidents"
                    " (id, title, severity, context, status, created_at,"
                    "  patch_proposals)"
                    " VALUES (:id, :title, :severity, :context, :status,"
                    "  :created_at, :props)"
                ),
                {
                    "id": "legacy-1",
                    "title": "legacy incident",
                    "severity": "HIGH",
                    "context": "gw",
                    "status": "RemediationProposed",
                    "created_at": datetime.now(timezone.utc),
                    "props": json.dumps([legacy_proposal.to_dict()]),
                },
            )
            connection.execute(
                text(
                    "INSERT INTO devops_incident_evidence"
                    " (id, incident_id, kind, source, observed_at, payload)"
                    " VALUES ('legacy-ev-1', 'legacy-1', 'deployment_run',"
                    "  'deployment-service', :obs, :payload)"
                ),
                {
                    "obs": datetime.now(timezone.utc),
                    "payload": json.dumps({"kept": True}),
                },
            )
            connection.execute(
                text(
                    "INSERT INTO devops_execution_claims"
                    " (incident_id, proposal_id, proposal_hash,"
                    "  execution_id, attempt, state, stage)"
                    " VALUES ('legacy-1', 'proposal-legacy-1', :h,"
                    "  'exec-1', 1, 'FREE', 'COMPLETED')"
                ),
                {"h": "e" * 64},
            )
        legacy_engine.dispose()

        # Upgrade happens HERE: adapter init (create_all + ALTER ADD).
        repo = PostgresIncidentRepositoryAdapter(f"sqlite:///{self.db_path}")

        # version column added, legacy row still fully readable
        reloaded = repo.get_incident_by_id("legacy-1")
        self.assertIsNotNone(reloaded)
        self.assertEqual(reloaded.version, 0)
        self.assertEqual(len(reloaded.patch_proposals), 1)
        self.assertEqual(reloaded.patch_proposals[0].status, "APPROVED")
        self.assertEqual(len(reloaded.evidence), 1)

        # every other table's data preserved verbatim
        with repo.engine.connect() as connection:
            evidence_count = connection.execute(
                text("SELECT COUNT(*) FROM devops_incident_evidence")
            ).scalar_one()
            claim_hash = connection.execute(
                text(
                    "SELECT proposal_hash FROM devops_execution_claims"
                    " WHERE incident_id = 'legacy-1'"
                )
            ).scalar_one()
            version_rows = connection.execute(
                text(
                    "SELECT COUNT(*) FROM pragma_table_info"
                    "('devops_incidents') WHERE name = 'version'"
                )
            ).scalar_one()
        self.assertEqual(evidence_count, 1)
        self.assertEqual(claim_hash, "e" * 64)
        self.assertEqual(version_rows, 1)

        # the upgraded row accepts CAS writes (evidence-level update —
        # never drop/recreate, just the versioned aggregate path)
        reloaded.attach_evidence(
            _deployment_evidence(evidence_id=f"upgraded-{reloaded.id}")
        )
        repo.save_incident(reloaded)
        self.assertEqual(
            repo.get_incident_by_id("legacy-1").version, 1
        )

        # rerun (second adapter over the same file) is a no-op: no drop,
        # no duplicate column, data intact.
        rerun = PostgresIncidentRepositoryAdapter(f"sqlite:///{self.db_path}")
        again = rerun.get_incident_by_id("legacy-1")
        self.assertEqual(again.version, 1)
        self.assertEqual(len(again.patch_proposals), 1)
        with rerun.engine.connect() as connection:
            version_rows = connection.execute(
                text(
                    "SELECT COUNT(*) FROM pragma_table_info"
                    "('devops_incidents') WHERE name = 'version'"
                )
            ).scalar_one()
            evidence_count = connection.execute(
                text("SELECT COUNT(*) FROM devops_incident_evidence")
            ).scalar_one()
        self.assertEqual(version_rows, 1)
        # 1 legacy row + the post-upgrade CAS write's evidence — no drops,
        # no duplicates from the idempotent rerun.
        self.assertEqual(evidence_count, 2)

    def test_rerun_on_fresh_database_is_idempotent(self):
        first = self._adapter()
        incident = self._seed()
        second = PostgresIncidentRepositoryAdapter(f"sqlite:///{self.db_path}")
        self.assertEqual(
            second.get_incident_by_id(incident.id).version, incident.version
        )
        with second.engine.connect() as connection:
            version_rows = connection.execute(
                text(
                    "SELECT COUNT(*) FROM pragma_table_info"
                    "('devops_incidents') WHERE name = 'version'"
                )
            ).scalar_one()
        self.assertEqual(version_rows, 1)


if __name__ == "__main__":
    unittest.main()
