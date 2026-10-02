"""Phase 6.7.1 — traffic-control boundary + rollout-plan preflight tests.

Covers the §10 matrix: identity binding, evaluation freshness/policy,
stage progression, observed-traffic states, all five preflight statuses,
and strict no-side-effects (no Kubernetes/provider/deployment/rollout-
stage mutation on any path).
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
    ProgressiveRolloutStageService,
)
from incident_service.application.services.rollout_plan_service import (
    OBSERVED_CONFLICT,
    OBSERVED_DIFFERS_FROM_DESIRED,
    OBSERVED_KNOWN,
    OBSERVED_MATCHES_DESIRED,
    OBSERVED_UNKNOWN,
    PREFLIGHT_BLOCKED,
    PREFLIGHT_CONFLICT,
    PREFLIGHT_INCONCLUSIVE,
    PREFLIGHT_NO_OP,
    PREFLIGHT_READY,
    InvalidRolloutPlanRequest,
    ObservedTrafficState,
    RolloutPlanConflict,
    RolloutPlanService,
    TrafficControllerPort,
    TrafficProviderUnavailable,
    UnavailableTrafficController,
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
RUN_ID = "run-plan-1"
OTHER_RUN_ID = "run-plan-2"


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


def _observed(
    percentage,
    *,
    status=OBSERVED_KNOWN,
    stable="svc-stable",
    canary="svc-canary",
    run_id=RUN_ID,
    source_sha=SHA,
    provider="test-weighted-router",
):
    return ObservedTrafficState(
        provider=provider,
        observed_status=status,
        observed_percentage=percentage,
        stable_identity=stable,
        canary_identity=canary,
        deployment_run_id=run_id,
        source_sha=source_sha,
        observation_timestamp=datetime(2026, 9, 8, 12, tzinfo=UTC),
        observation_source="provider-inspection",
        detail="fixture",
    )


class ScriptedTrafficController:
    """Deterministic test double AT THE PORT BOUNDARY (not shipped as a
    production provider): inspection returns a scripted observation and
    plan() only records the intent it was handed — it mutates nothing."""

    def __init__(self, observed=None, error=None):
        self.observed = observed
        self.error = error
        self.inspect_calls = []
        self.plan_calls = []

    def inspect(self, deployment_run_id, source_sha):
        self.inspect_calls.append((deployment_run_id, source_sha))
        if self.error is not None:
            raise self.error
        return self.observed

    def plan(self, intent):
        self.plan_calls.append(intent)
        return {
            "provider": self.observed.provider if self.observed else "none",
            "intent_id": intent.intent_id,
            "actions": [],  # rendering only — no mutation instructions executed here
        }


class RolloutPlanServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db_path = os.path.join(self.temp.name, "plan.db")
        self.repository = PostgresIncidentRepositoryAdapter(
            f"sqlite:///{self.db_path}"
        )
        self.now = datetime(2026, 9, 8, 12, tzinfo=UTC)
        for run_id in (RUN_ID, OTHER_RUN_ID):
            incident = IncidentAggregate(
                id=f"inc-{run_id}",
                title="[release] rollout plan",
                severity="HIGH",
                context_details="rollout plan fixture",
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

    def _evaluate(self, target=5, *, cpu=0.30, error=None, run_id=RUN_ID, now=None):
        moment = now if now is not None else self.now
        return ProgressiveReleaseGateService(
            self.repository,
            FakePrometheus(cpu=cpu, error=error, deployment_id=run_id),
            now_factory=lambda: moment,
        ).evaluate(
            run_id,
            START,
            END,
            target,
            baseline_deployment_run_id=(
                run_id if target > 5 else None
            ),
        )

    def _stage_service(self):
        return ProgressiveRolloutStageService(
            self.repository, now_factory=lambda: self.now
        )

    def _bootstrap(self):
        evaluation = self._evaluate(5)
        return self._stage_service().transition(
            RUN_ID, 0, 5, evaluation["evaluation_id"], SHA
        )

    def _promote_to(self, current_stage_target):
        """Advance the durable stage to ``current_stage_target``."""
        self.now = self.now + timedelta(seconds=60)
        evaluation = self._evaluate(current_stage_target)
        expected = {25: 5, 50: 25, 100: 50}[current_stage_target]
        return self._stage_service().transition(
            RUN_ID,
            expected,
            current_stage_target,
            evaluation["evaluation_id"],
            SHA,
        )

    def _plan(self, evaluation, requested, controller=None, *, now=None, run_id=RUN_ID):
        moment = now if now is not None else self.now
        service = RolloutPlanService(
            self.repository,
            controller=controller,
            now_factory=lambda: moment,
        )
        return service.plan(
            deployment_run_id=run_id,
            evaluation_id=evaluation["evaluation_id"],
            requested_percentage=requested,
            source_sha=evaluation["source_sha"]
            if evaluation.get("source_sha") == SHA
            else SHA,
        )

    def _plan_by_id(self, evaluation_id, requested, controller=None, *, sha=SHA, run_id=RUN_ID, now=None):
        moment = now if now is not None else self.now
        return RolloutPlanService(
            self.repository,
            controller=controller,
            now_factory=lambda: moment,
        ).plan(
            deployment_run_id=run_id,
            evaluation_id=evaluation_id,
            requested_percentage=requested,
            source_sha=sha,
        )

    def _ready_controller(self, percentage=5):
        return ScriptedTrafficController(
            observed=_observed(percentage)
        )

    # ---------------------------------------------------- identity matrix

    def test_fresh_promote_with_proven_observation_is_ready(self):
        self._bootstrap()
        evaluation = self._evaluate(25)
        controller = self._ready_controller(percentage=5)
        result = self._plan(evaluation, 25, controller)
        self.assertEqual(result["preflight_status"], PREFLIGHT_READY)
        self.assertEqual(result["observed_status"], OBSERVED_DIFFERS_FROM_DESIRED)
        self.assertTrue(result["target_identity"]["proven"])
        self.assertEqual(result["target_identity"]["stable"], "svc-stable")
        self.assertEqual(result["target_identity"]["canary"], "svc-canary")
        self.assertEqual(result["intent"]["stable_target"], "svc-stable")
        self.assertEqual(controller.inspect_calls, [(RUN_ID, SHA)])
        self.assertEqual(len(controller.plan_calls), 1)
        self.assertEqual(
            controller.plan_calls[0].requested_percentage, 25
        )

    def test_unknown_deployment_run_is_404(self):
        with self.assertRaises(LookupError):
            self._plan_by_id(
                "eval-x", 5, self._ready_controller(), run_id="run-never-seen"
            )

    def test_wrong_deployment_evaluation_is_rejected(self):
        self._bootstrap()
        foreign = self._evaluate(5, run_id=OTHER_RUN_ID)
        with self.assertRaises(RolloutPlanConflict):
            self._plan_by_id(foreign["evaluation_id"], 5, self._ready_controller())

    def test_wrong_source_sha_is_rejected(self):
        self._bootstrap()
        evaluation = self._evaluate(25)
        with self.assertRaises(RolloutPlanConflict):
            self._plan_by_id(
                evaluation["evaluation_id"], 25, self._ready_controller(), sha="b" * 40
            )
        with self.assertRaises(InvalidRolloutPlanRequest):
            self._plan_by_id(
                evaluation["evaluation_id"], 25, self._ready_controller(), sha=SHA.upper()
            )

    def test_missing_rollout_state_is_404(self):
        # evaluation exists, stage does not → fail closed before planning
        evaluation = self._evaluate(5)
        with self.assertRaises(LookupError):
            self._plan_by_id(
                evaluation["evaluation_id"], 5, self._ready_controller()
            )

    def test_terminal_rollout_is_rejected(self):
        self._bootstrap()
        self._promote_to(25)
        self.now = self.now + timedelta(seconds=60)
        aborted = self._stage_service().transition(
            RUN_ID,
            25,
            25,
            self._evaluate(25, cpu=0.95)["evaluation_id"],
            SHA,
        )
        self.assertEqual(aborted["state"], "ABORTED")
        evaluation = self._evaluate(50)
        with self.assertRaises(RolloutPlanConflict):
            self._plan_by_id(
                evaluation["evaluation_id"], 50, self._ready_controller()
            )

    # ------------------------------------------------- evaluation matrix

    def test_stale_evaluation_is_rejected(self):
        self._bootstrap()
        evaluation = self._evaluate(25)
        later = self.now + timedelta(seconds=GATE_EVALUATION_TTL_SECONDS + 1)
        with self.assertRaises(RolloutPlanConflict):
            self._plan_by_id(
                evaluation["evaluation_id"],
                25,
                self._ready_controller(),
                now=later,
            )

    def test_unknown_evaluation_id_is_404(self):
        self._bootstrap()
        with self.assertRaises(LookupError):
            self._plan_by_id("missing-eval", 25, self._ready_controller())

    def test_wrong_target_percentage_is_rejected(self):
        self._bootstrap()
        evaluation = self._evaluate(25)
        with self.assertRaises(RolloutPlanConflict):
            self._plan_by_id(
                evaluation["evaluation_id"], 5, self._ready_controller()
            )

    def test_foreign_policy_version_is_rejected(self):
        self._bootstrap()
        self.repository.save_progressive_release_gate_evaluation(
            {
                "evaluation_id": "eval-foreign-plan",
                "deployment_run_id": RUN_ID,
                "source_sha": SHA,
                "repository_name": "acme/checkout",
                "target_percentage": 25,
                "observation_start": START,
                "observation_end": END,
                "baseline_deployment_run_id": RUN_ID,
                "baseline_source_sha": SHA,
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
        with self.assertRaises(RolloutPlanConflict):
            self._plan_by_id("eval-foreign-plan", 25, self._ready_controller())

    def test_pause_decision_blocks_the_plan(self):
        self._bootstrap()
        evaluation = self._evaluate(5, cpu=0.75)
        result = self._plan(evaluation, 5, self._ready_controller(percentage=5))
        self.assertEqual(result["preflight_status"], PREFLIGHT_BLOCKED)
        self.assertTrue(
            any("PAUSE" in reason for reason in result["reasons"]),
            result["reasons"],
        )

    def test_abort_decision_blocks_the_plan(self):
        self._bootstrap()
        evaluation = self._evaluate(5, cpu=0.95)
        result = self._plan(evaluation, 5, self._ready_controller(percentage=5))
        self.assertEqual(result["preflight_status"], PREFLIGHT_BLOCKED)

    def test_inconclusive_decision_blocks_the_plan(self):
        self._bootstrap()
        evaluation = self._evaluate(
            25, error=PrometheusUnavailableError("refused")
        )
        result = self._plan(evaluation, 25, self._ready_controller(percentage=5))
        self.assertEqual(result["preflight_status"], PREFLIGHT_BLOCKED)
        self.assertEqual(evaluation["gate_decision"], "INCONCLUSIVE")

    # --------------------------------------------- stage progression

    def test_stage_progression_5_25_50_100_plans(self):
        self._bootstrap()
        for requested in (25, 50, 100):
            with self.subTest(requested=requested):
                self.now = self.now + timedelta(seconds=60)
                evaluation = self._evaluate(requested)
                result = self._plan(
                    evaluation, requested, self._ready_controller(percentage=5)
                )
                self.assertEqual(result["preflight_status"], PREFLIGHT_READY)
                self._stage_service().transition(
                    RUN_ID,
                    {25: 5, 50: 25, 100: 50}[requested],
                    requested,
                    evaluation["evaluation_id"],
                    SHA,
                )

    def test_skipped_stage_is_rejected(self):
        self._bootstrap()
        evaluation = self._evaluate(50)
        with self.assertRaises(RolloutPlanConflict):
            self._plan_by_id(
                evaluation["evaluation_id"], 50, self._ready_controller()
            )

    def test_reversed_stage_is_rejected(self):
        self._bootstrap()
        self._promote_to(25)
        evaluation = self._evaluate(5)
        with self.assertRaises(RolloutPlanConflict):
            self._plan_by_id(
                evaluation["evaluation_id"], 5, self._ready_controller()
            )

    # ------------------------------------------------ traffic states

    def test_unavailable_provider_is_inconclusive(self):
        self._bootstrap()
        evaluation = self._evaluate(25)
        # default controller: deliberately unavailable, never fake
        result = self._plan(evaluation, 25, None)
        self.assertEqual(result["preflight_status"], PREFLIGHT_INCONCLUSIVE)
        self.assertEqual(result["observed_traffic"]["observed_status"], OBSERVED_UNKNOWN)
        self.assertEqual(result["observed_traffic"]["provider"], "unavailable")
        with self.assertRaises(TrafficProviderUnavailable):
            UnavailableTrafficController().inspect(RUN_ID, SHA)
        with self.assertRaises(TrafficProviderUnavailable):
            UnavailableTrafficController().plan(None)

    def test_unknown_observation_is_inconclusive(self):
        self._bootstrap()
        evaluation = self._evaluate(25)
        controller = ScriptedTrafficController(
            observed=_observed(None, status=OBSERVED_UNKNOWN, stable=None, canary=None)
        )
        result = self._plan(evaluation, 25, controller)
        self.assertEqual(result["preflight_status"], PREFLIGHT_INCONCLUSIVE)
        self.assertEqual(result["observed_status"], OBSERVED_UNKNOWN)

    def test_observed_already_desired_is_no_op_at_completion(self):
        # Forward NO_OP would require observed traffic beyond the durable
        # stage (a conflict); the legitimate NO_OP is completion where
        # observed == requested == stage == 100.
        self._bootstrap()
        for target in (25, 50, 100):
            self.now = self.now + timedelta(seconds=60)
            evaluation = self._evaluate(target)
            self._stage_service().transition(
                RUN_ID,
                {25: 5, 50: 25, 100: 50}[target],
                target,
                evaluation["evaluation_id"],
                SHA,
            )
        self.now = self.now + timedelta(seconds=GATE_EVALUATION_TTL_SECONDS + 60)
        completion = self._evaluate(100)
        controller = ScriptedTrafficController(observed=_observed(100))
        result = self._plan(completion, 100, controller)
        self.assertEqual(result["observed_status"], OBSERVED_MATCHES_DESIRED)
        self.assertEqual(result["preflight_status"], PREFLIGHT_NO_OP)
        self.assertEqual(controller.plan_calls, [])  # no plan needed

    def test_observed_differs_and_targets_unproven_is_blocked(self):
        self._bootstrap()
        evaluation = self._evaluate(25)
        controller = ScriptedTrafficController(
            observed=_observed(5, stable=None, canary=None)
        )
        result = self._plan(evaluation, 25, controller)
        self.assertEqual(result["preflight_status"], PREFLIGHT_BLOCKED)
        self.assertFalse(result["target_identity"]["proven"])
        self.assertTrue(
            any("traffic_targets_unproven" in r for r in result["reasons"]),
            result["reasons"],
        )
        self.assertEqual(controller.plan_calls, [])

    def test_conflicting_observed_identity_is_conflict(self):
        self._bootstrap()
        evaluation = self._evaluate(25)
        controller = ScriptedTrafficController(
            observed=_observed(5, run_id=OTHER_RUN_ID)
        )
        result = self._plan(evaluation, 25, controller)
        self.assertEqual(result["preflight_status"], PREFLIGHT_CONFLICT)
        self.assertEqual(result["observed_status"], OBSERVED_CONFLICT)

        sha_controller = ScriptedTrafficController(
            observed=_observed(5, source_sha="b" * 40)
        )
        result = self._plan(evaluation, 25, sha_controller)
        self.assertEqual(result["preflight_status"], PREFLIGHT_CONFLICT)

    def test_observed_beyond_authorized_stage_is_conflict(self):
        self._bootstrap()  # durable stage authorizes 5%
        evaluation = self._evaluate(25)
        controller = ScriptedTrafficController(observed=_observed(50))
        result = self._plan(evaluation, 25, controller)
        self.assertEqual(result["observed_status"], OBSERVED_CONFLICT)
        self.assertEqual(result["preflight_status"], PREFLIGHT_CONFLICT)

    # -------------------------------------------------- determinism

    def test_intent_and_status_are_deterministic(self):
        self._bootstrap()
        evaluation = self._evaluate(25)
        first = self._plan(evaluation, 25, self._ready_controller(5))
        second = self._plan(evaluation, 25, self._ready_controller(5))
        self.assertEqual(first["intent"]["intent_id"], second["intent"]["intent_id"])
        self.assertEqual(first["preflight_status"], second["preflight_status"])
        self.assertEqual(first["observed_traffic"], second["observed_traffic"])

    # --------------------------------------------- no side effects

    def test_every_plan_path_is_side_effect_free(self):
        self._bootstrap()
        evaluation = self._evaluate(25)
        stage_before = self.repository.get_progressive_rollout_stage(RUN_ID)
        evaluations_before = list(
            self.repository.get_progressive_release_gate_evaluations(RUN_ID)
        )
        incident_before = self.repository.get_incident_by_id("inc-" + RUN_ID)
        evidence_before = [dict(i.payload) for i in incident_before.evidence]

        controller = self._ready_controller(5)
        with patch.object(subprocess, "run") as run_mock, patch.object(
            subprocess, "Popen"
        ) as popen_mock:
            result = self._plan(evaluation, 25, controller)

        self.assertEqual(result["preflight_status"], PREFLIGHT_READY)
        run_mock.assert_not_called()  # no kubectl / terraform / git / gh
        popen_mock.assert_not_called()
        self.assertFalse(
            [name for name in sys.modules if name.startswith("traffic")]
        )
        # durable rollout stage unchanged (plan must never advance it)
        self.assertEqual(
            self.repository.get_progressive_rollout_stage(RUN_ID), stage_before
        )
        self.assertEqual(
            self.repository.get_progressive_release_gate_evaluations(RUN_ID),
            evaluations_before,
        )
        incident_after = self.repository.get_incident_by_id("inc-" + RUN_ID)
        self.assertEqual(
            [dict(i.payload) for i in incident_after.evidence], evidence_before
        )

    def test_port_exposes_no_mutation_surface(self):
        members = set(dir(TrafficControllerPort))
        for forbidden in ("apply", "mutate", "execute", "write", "push"):
            self.assertNotIn(forbidden, members)
        for cls in (UnavailableTrafficController, ScriptedTrafficController):
            self.assertFalse(
                [
                    name
                    for name in dir(cls)
                    if name in {"apply", "mutate", "execute", "write", "push"}
                ],
                cls,
            )

    def test_blocked_and_inconclusive_paths_also_leave_stage_untouched(self):
        self._bootstrap()
        stage_before = self.repository.get_progressive_rollout_stage(RUN_ID)
        pause_eval = self._evaluate(5, cpu=0.75)
        self._plan(pause_eval, 5, self._ready_controller(5))
        promote_eval = self._evaluate(25)
        self._plan(promote_eval, 25, None)  # unavailable provider
        self.assertEqual(
            self.repository.get_progressive_rollout_stage(RUN_ID), stage_before
        )


if __name__ == "__main__":
    unittest.main()
