"""Phase 6.6.2 — durable progressive-release rollout stage state tests.

Covers the full §11 matrix: creation, promotion sequence, illegal
transitions, decision handling, identity/staleness binding, concurrent
convergence, restart recovery, and the strict no-side-effects boundary
(no Kubernetes, no deployment execution, no GitHub, no traffic).
"""

import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from incident_service.application.services.progressive_release_gate_service import (
    GATE_EVALUATION_TTL_SECONDS,
    ProgressiveReleaseGateService,
)
from incident_service.application.services.progressive_rollout_stage_service import (
    InvalidRolloutStageRequest,
    ProgressiveRolloutStageService,
    RolloutStageConflict,
)
from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.infrastructure.database.postgres_incident_repo import (
    PostgresIncidentRepositoryAdapter,
)
from incident_service.presentation.rest.test_remediation_authorization import (
    _deployment_evidence,
)
from monitoring_service.infrastructure.prometheus.scraper_client import (
    PrometheusUnavailableError,
    RangeQueryResult,
    RangeSample,
    RangeSeries,
)

UTC = timezone.utc
START = datetime(2026, 9, 1, tzinfo=UTC)
END = datetime(2026, 9, 8, tzinfo=UTC)
SHA = "a" * 40
RUN_ID = "run-rollout-1"
OTHER_RUN_ID = "run-rollout-2"


class FakePrometheus:
    def __init__(self, cpu=0.30, request=10.0, error=None, deployment_id=RUN_ID):
        self.cpu = cpu
        self.request = request
        self.error = error
        self.deployment_id = deployment_id
        self.calls = []

    def query_range_metric(self, template_name, start, end):
        self.calls.append(template_name)
        if self.error is not None:
            raise self.error
        value = self.request if template_name == "request_rate" else self.cpu
        return RangeQueryResult(
            template=template_name,
            query="fixed-test-query",
            start=start.timestamp(),
            end=end.timestamp(),
            step_seconds=60,
            series=(
                RangeSeries(
                    labels={"deployment_id": self.deployment_id},
                    samples=tuple(
                        RangeSample(
                            timestamp=START.timestamp() + 3600 + i * 600,
                            value=value,
                        )
                        for i in range(6)
                    ),
                ),
            ),
        )


class RolloutStageStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db_path = os.path.join(self.temp.name, "rollout.db")
        self.repository = PostgresIncidentRepositoryAdapter(
            f"sqlite:///{self.db_path}"
        )
        self.now = datetime(2026, 9, 8, 12, tzinfo=UTC)
        for run_id in (RUN_ID, OTHER_RUN_ID):
            incident = IncidentAggregate(
                id=f"inc-{run_id}",
                title="[release] rollout stage",
                severity="HIGH",
                context_details="progressive rollout stage fixture",
            )
            incident.created_at = START + timedelta(hours=1)
            incident.status = "Fixed"
            incident.evidence.append(
                _deployment_evidence(
                    run_id=run_id,
                    evidence_id=f"evidence-{run_id}",
                    head_sha=SHA,
                    kind_extra={
                        "health_check_status": "PASS",
                        "source_sha": SHA,
                    },
                )
            )
            self.repository.save_incident(incident)

    # ------------------------------------------------------------- helpers

    def _service(self, repository=None, now=None):
        moment = now if now is not None else self.now
        return ProgressiveRolloutStageService(
            repository or self.repository, now_factory=lambda: moment
        )

    def _evaluate(
        self,
        target=5,
        *,
        cpu=0.30,
        error=None,
        run_id=RUN_ID,
        repository=None,
        now=None,
        baseline=True,
    ):
        moment = now if now is not None else self.now
        repo = repository or self.repository
        return ProgressiveReleaseGateService(
            repo,
            FakePrometheus(cpu=cpu, error=error, deployment_id=run_id),
            now_factory=lambda: moment,
        ).evaluate(
            run_id,
            START,
            END,
            target,
            baseline_deployment_run_id=(
                run_id if (baseline and target > 5) else None
            ),
        )

    def _transition(self, expected, target, evaluation, *, repository=None, now=None):
        return self._service(repository, now).transition(
            deployment_run_id=RUN_ID,
            expected_percentage=expected,
            target_percentage=target,
            evaluation_id=evaluation["evaluation_id"],
            source_sha=evaluation["source_sha"],
        )

    def _bootstrap(self):
        evaluation = self._evaluate(5)
        return self._transition(0, 5, evaluation)

    def _advance_clock(self, seconds=60):
        self.now = self.now + timedelta(seconds=seconds)

    # ------------------------------------------------- state creation (A)

    def test_new_deployment_creates_active_5(self):
        stage = self._bootstrap()
        self.assertEqual(stage["state"], "ACTIVE")
        self.assertEqual(stage["current_percentage"], 5)
        self.assertEqual(stage["previous_percentage"], 0)
        self.assertEqual(stage["deployment_run_id"], RUN_ID)
        self.assertEqual(stage["source_sha"], SHA)
        self.assertEqual(stage["last_gate_decision"], "PROMOTE")
        self.assertTrue(stage["stage_state_id"].startswith("rst_"))
        # read round-trip
        read_back = self._service().read(RUN_ID)
        self.assertEqual(read_back, stage)

    def test_creation_requires_presented_fresh_promote_evaluation(self):
        # missing stage + non-zero expected → 404 (fail closed)
        evaluation = self._evaluate(5)
        with self.assertRaises(LookupError):
            self._service().transition(
                RUN_ID, 5, 25, evaluation["evaluation_id"], SHA
            )
        # unknown evaluation id → 404
        with self.assertRaises(LookupError):
            self._service().transition(RUN_ID, 0, 5, "no-such-eval", SHA)
        # creation can only start at 5% (fresh PROMOTE targeting 25)
        with self.assertRaises(RolloutStageConflict):
            self._transition(0, 25, self._evaluate(25))
        # nothing was created by the rejected attempts
        with self.assertRaises(LookupError):
            self._service().read(RUN_ID)

    # -------------------------------------------------- promotion (B, C)

    def test_full_promotion_sequence_5_25_50_100_then_completed(self):
        self._bootstrap()
        for step, (expected, target) in enumerate(
            ((5, 25), (25, 50), (50, 100))
        ):
            self._advance_clock(60)
            evaluation = self._evaluate(target)
            stage = self._transition(expected, target, evaluation)
            self.assertEqual(stage["state"], "ACTIVE")
            self.assertEqual(stage["current_percentage"], target)
            self.assertEqual(stage["previous_percentage"], expected)
        # completion confirmation at 100% with a fresh evaluation
        self._advance_clock(GATE_EVALUATION_TTL_SECONDS + 60)
        completion = self._evaluate(100)
        stage = self._transition(100, 100, completion)
        self.assertEqual(stage["state"], "COMPLETED")
        self.assertEqual(stage["current_percentage"], 100)
        # terminal: no resurrection
        self._advance_clock(60)
        with self.assertRaises(RolloutStageConflict):
            self._transition(100, 100, self._evaluate(100))

    def test_skip_5_to_50_is_rejected(self):
        self._bootstrap()
        with self.assertRaises(RolloutStageConflict):
            self._transition(5, 50, self._evaluate(50))

    def test_regression_25_to_5_is_rejected(self):
        self._bootstrap()
        self._advance_clock(60)
        self._transition(5, 25, self._evaluate(25))
        self._advance_clock(60)
        with self.assertRaises(RolloutStageConflict):
            self._transition(25, 5, self._evaluate(5))
        stage = self._service().read(RUN_ID)
        self.assertEqual(stage["current_percentage"], 25)
        self.assertEqual(stage["state"], "ACTIVE")

    def test_reverse_100_to_50_is_rejected(self):
        self._bootstrap()
        for expected, target in ((5, 25), (25, 50), (50, 100)):
            self._advance_clock(60)
            self._transition(expected, target, self._evaluate(target))
        self._advance_clock(60)
        with self.assertRaises(RolloutStageConflict):
            self._transition(100, 50, self._evaluate(50))

    def test_aborted_stage_cannot_be_revived(self):
        self._bootstrap()
        self._advance_clock(60)
        aborted = self._transition(5, 5, self._evaluate(5, cpu=0.95))
        self.assertEqual(aborted["state"], "ABORTED")
        self._advance_clock(60)
        with self.assertRaises(RolloutStageConflict):
            self._transition(5, 25, self._evaluate(25))
        stage = self._service().read(RUN_ID)
        self.assertEqual(stage["state"], "ABORTED")

    def test_completed_stage_cannot_be_revived(self):
        self._bootstrap()
        for expected, target in ((5, 25), (25, 50), (50, 100)):
            self._advance_clock(60)
            self._transition(expected, target, self._evaluate(target))
        self._advance_clock(GATE_EVALUATION_TTL_SECONDS + 60)
        self._transition(100, 100, self._evaluate(100))
        self._advance_clock(60)
        with self.assertRaises(RolloutStageConflict):
            self._transition(100, 100, self._evaluate(100))

    # ------------------------------------------------ decision handling (D)

    def test_pause_decision_pauses_without_changing_percentages(self):
        self._bootstrap()
        self._advance_clock(60)
        self._transition(5, 25, self._evaluate(25))
        self._advance_clock(60)
        paused = self._transition(25, 25, self._evaluate(25, cpu=0.75))
        self.assertEqual(paused["state"], "PAUSED")
        self.assertEqual(paused["current_percentage"], 25)
        self.assertEqual(paused["previous_percentage"], 5)
        self.assertEqual(paused["last_gate_decision"], "PAUSE")

    def test_abort_decision_aborts_from_active(self):
        self._bootstrap()
        self._advance_clock(60)
        stage = self._transition(5, 5, self._evaluate(5, cpu=0.95))
        self.assertEqual(stage["state"], "ABORTED")
        self.assertEqual(stage["last_gate_decision"], "ABORT")

    def test_inconclusive_never_advances_the_rollout(self):
        self._bootstrap()
        before = self._service().read(RUN_ID)
        self._advance_clock(60)
        inconclusive = self._evaluate(25, error=PrometheusUnavailableError("refused"))
        self.assertEqual(inconclusive["gate_decision"], "INCONCLUSIVE")
        with self.assertRaises(RolloutStageConflict):
            self._transition(5, 25, inconclusive)
        after = self._service().read(RUN_ID)
        self.assertEqual(after, before)  # unchanged, including evaluation id
        self.assertEqual(after["state"], "ACTIVE")
        self.assertEqual(after["current_percentage"], 5)

    def test_paused_plus_pause_stays_paused(self):
        self._bootstrap()
        self._advance_clock(60)
        self._transition(5, 5, self._evaluate(5, cpu=0.75))
        self._advance_clock(60)
        again = self._transition(5, 5, self._evaluate(5, cpu=0.75))
        self.assertEqual(again["state"], "PAUSED")
        self.assertEqual(again["current_percentage"], 5)

    def test_paused_plus_fresh_promote_advances_to_next_stage(self):
        self._bootstrap()
        self._advance_clock(60)
        self._transition(5, 5, self._evaluate(5, cpu=0.75))
        self.assertEqual(self._service().read(RUN_ID)["state"], "PAUSED")
        self._advance_clock(60)
        resumed = self._transition(5, 25, self._evaluate(25))
        self.assertEqual(resumed["state"], "ACTIVE")
        self.assertEqual(resumed["current_percentage"], 25)
        self.assertEqual(resumed["previous_percentage"], 5)

    def test_abort_from_paused_is_terminal(self):
        self._bootstrap()
        self._advance_clock(60)
        self._transition(5, 5, self._evaluate(5, cpu=0.75))
        self._advance_clock(60)
        stage = self._transition(5, 5, self._evaluate(5, cpu=0.95))
        self.assertEqual(stage["state"], "ABORTED")

    # ------------------------------------------ identity / staleness (E)

    def test_evaluation_from_another_deployment_is_rejected(self):
        self._bootstrap()
        self._advance_clock(60)
        foreign = self._evaluate(25, run_id=OTHER_RUN_ID)
        self.assertEqual(foreign["deployment_run_id"], OTHER_RUN_ID)
        with self.assertRaises(RolloutStageConflict):
            self._transition(5, 25, foreign)
        stage = self._service().read(RUN_ID)
        self.assertEqual(stage["current_percentage"], 5)

    def test_wrong_source_sha_is_rejected(self):
        self._bootstrap()
        self._advance_clock(60)
        evaluation = self._evaluate(25)
        with self.assertRaises(RolloutStageConflict):
            self._service().transition(
                RUN_ID, 5, 25, evaluation["evaluation_id"], "b" * 40
            )
        # malformed SHA fails closed at validation (422 semantics)
        with self.assertRaises(InvalidRolloutStageRequest):
            self._service().transition(
                RUN_ID, 5, 25, evaluation["evaluation_id"], SHA.upper()
            )
        with self.assertRaises(InvalidRolloutStageRequest):
            self._service().transition(
                RUN_ID, 5, 25, evaluation["evaluation_id"], "abc"
            )

    def test_unknown_evaluation_id_fails_closed(self):
        self._bootstrap()
        with self.assertRaises(LookupError):
            self._transition(5, 25, {"evaluation_id": "missing", "source_sha": SHA})

    def test_stale_evaluation_is_rejected(self):
        self._bootstrap()
        evaluation = self._evaluate(25)
        later = self.now + timedelta(seconds=GATE_EVALUATION_TTL_SECONDS + 1)
        with self.assertRaises(RolloutStageConflict):
            self._transition(5, 25, evaluation, now=later)
        # and the newest evaluation is NOT silently substituted
        stage = self._service().read(RUN_ID)
        self.assertEqual(stage["current_percentage"], 5)

    def test_target_mismatch_with_presented_evaluation_is_rejected(self):
        self._bootstrap()
        evaluation = self._evaluate(25)
        with self.assertRaises(RolloutStageConflict):
            self._service().transition(
                RUN_ID, 5, 50, evaluation["evaluation_id"], SHA
            )

    def test_foreign_policy_version_is_rejected(self):
        self._bootstrap()
        self.repository.save_progressive_release_gate_evaluation(
            {
                "evaluation_id": "eval-foreign-policy",
                "deployment_run_id": RUN_ID,
                "source_sha": SHA,
                "repository_name": "acme/checkout",
                "target_percentage": 5,
                "observation_start": START,
                "observation_end": END,
                "baseline_deployment_run_id": None,
                "baseline_source_sha": None,
                "health_decision": "HEALTHY",
                "gate_decision": "PROMOTE",
                "reasons": [],
                "live_assessment": {"decision": "HEALTHY"},
                "policy_version": "6.6.0",
                "request_fingerprint": "f" * 64,
                "assessment_fingerprint": "e" * 64,
                "observed_at": self.now,
                "expires_at": self.now
                + timedelta(seconds=GATE_EVALUATION_TTL_SECONDS),
            }
        )
        with self.assertRaises(RolloutStageConflict):
            self._service().transition(
                RUN_ID, 5, 5, "eval-foreign-policy", SHA
            )

    # ------------------------------------------------- concurrency (F)

    def test_two_adapters_converge_on_single_25_stage(self):
        self._bootstrap()
        evaluation = self._evaluate(25)
        worker_a = PostgresIncidentRepositoryAdapter(f"sqlite:///{self.db_path}")
        worker_b = PostgresIncidentRepositoryAdapter(f"sqlite:///{self.db_path}")

        first = self._service(worker_a).transition(
            RUN_ID, 5, 25, evaluation["evaluation_id"], SHA
        )
        second = self._service(worker_b).transition(
            RUN_ID, 5, 25, evaluation["evaluation_id"], SHA
        )
        # one durable 25% stage; both workers converge on it
        self.assertEqual(first["current_percentage"], 25)
        self.assertEqual(second["current_percentage"], 25)
        self.assertEqual(second["state"], "ACTIVE")
        self.assertEqual(
            second["last_gate_evaluation_id"], evaluation["evaluation_id"]
        )
        rows = worker_a.get_progressive_rollout_stage(RUN_ID)
        self.assertEqual(rows["current_percentage"], 25)
        self.assertEqual(
            self.repository.get_progressive_rollout_stage(RUN_ID)[
                "current_percentage"
            ],
            25,
        )

    def test_concurrent_stale_worker_with_old_evaluation_fails_closed(self):
        self._bootstrap()
        evaluation_25 = self._evaluate(25)
        worker_a = PostgresIncidentRepositoryAdapter(f"sqlite:///{self.db_path}")
        worker_b = PostgresIncidentRepositoryAdapter(f"sqlite:///{self.db_path}")
        self._service(worker_a).transition(
            RUN_ID, 5, 25, evaluation_25["evaluation_id"], SHA
        )
        # worker B still believes it is at 5% and presents the OLD eval
        old_eval = self._evaluate(5)  # old-stage evaluation, still fresh
        with self.assertRaises(RolloutStageConflict):
            self._service(worker_b).transition(
                RUN_ID, 5, 5, old_eval["evaluation_id"], SHA
            )
        stage = self.repository.get_progressive_rollout_stage(RUN_ID)
        self.assertEqual(stage["current_percentage"], 25)  # no regression

    def test_repository_cas_update_miss_returns_none_and_keeps_row(self):
        self._bootstrap()
        unchanged = self.repository.update_progressive_rollout_stage(
            RUN_ID,
            expected_current_percentage=99,  # stale expectation
            expected_state="ACTIVE",
            changes={"current_percentage": 100, "updated_at": self.now},
        )
        self.assertIsNone(unchanged)
        row = self.repository.get_progressive_rollout_stage(RUN_ID)
        self.assertEqual(row["current_percentage"], 5)

    # --------------------------------------------------- recovery (G)

    def test_restart_reconstructs_state_from_persistence(self):
        self._bootstrap()
        self._advance_clock(60)
        expected = self._transition(5, 25, self._evaluate(25))

        # destroy every in-memory object; reload from durable storage
        del self.repository
        reloaded = PostgresIncidentRepositoryAdapter(f"sqlite:///{self.db_path}")
        service = ProgressiveRolloutStageService(reloaded)
        state = service.read(RUN_ID)
        self.assertEqual(state, expected)
        self.assertEqual(state["current_percentage"], 25)
        self.assertEqual(state["state"], "ACTIVE")
        self.assertEqual(
            state["stage_state_id"], expected["stage_state_id"]
        )

        # missing durable state fails closed (fresh run id, no inference)
        with self.assertRaises(LookupError):
            ProgressiveRolloutStageService(reloaded).read("run-never-seen")
        self.repository = reloaded

    # ------------------------------------------- no side effects (H)

    def test_transition_has_no_execution_side_effects(self):
        self._bootstrap()
        incident_before = self.repository.get_incident_by_id("inc-" + RUN_ID)
        status_before = incident_before.status
        evidence_before = [
            dict(item.payload) for item in incident_before.evidence
        ]

        self._advance_clock(60)
        with patch.object(subprocess, "run") as run_mock, patch.object(
            subprocess, "Popen"
        ) as popen_mock:
            stage = self._transition(5, 25, self._evaluate(25))

        self.assertEqual(stage["current_percentage"], 25)
        run_mock.assert_not_called()      # no kubectl / terraform / git / gh
        popen_mock.assert_not_called()
        # no traffic-shifting adapter exists anywhere in the process
        self.assertFalse(
            [name for name in sys.modules if name.startswith("traffic")]
        )
        # incident/durable evidence untouched (control state only)
        incident_after = self.repository.get_incident_by_id("inc-" + RUN_ID)
        self.assertEqual(incident_after.status, status_before)
        self.assertEqual(
            [dict(item.payload) for item in incident_after.evidence],
            evidence_before,
        )

    def test_evaluate_never_creates_or_mutates_stage_state(self):
        # gate evaluation with PROMOTE must not create the stage
        self._evaluate(5)
        with self.assertRaises(LookupError):
            self._service().read(RUN_ID)
        # ... and must not mutate it afterwards either
        created = self._bootstrap()
        self._advance_clock(60)
        self._evaluate(25)
        self._evaluate(25, cpu=0.95)
        self.assertEqual(self._service().read(RUN_ID), created)

    # ------------------------------------------------ validation (I)

    def test_malformed_transition_inputs_fail_closed(self):
        self._bootstrap()
        evaluation = self._evaluate(25)
        cases = (
            dict(expected_percentage=True),        # bool is not an int here
            dict(expected_percentage="5"),
            dict(target_percentage=10),            # not in the sequence
            dict(target_percentage=0),             # 0 only for creation
            dict(evaluation_id=""),
            dict(source_sha="A" * 40),             # uppercase rejected
        )
        for override in cases:
            with self.subTest(override=sorted(override)):
                kwargs = dict(
                    deployment_run_id=RUN_ID,
                    expected_percentage=5,
                    target_percentage=25,
                    evaluation_id=evaluation["evaluation_id"],
                    source_sha=SHA,
                )
                kwargs.update(override)
                with self.assertRaises(InvalidRolloutStageRequest):
                    self._service().transition(**kwargs)


if __name__ == "__main__":
    unittest.main()
