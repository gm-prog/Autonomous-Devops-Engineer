"""Phase 8.7-A — controlled traffic-mutation boundary tests.

Covers: request construction from the repository's existing
``TrafficIntent`` (including one integration test against the REAL
``RolloutPlanService``), strict validation, the deterministic digest,
result verification semantics, the fail-closed default provider, the
exact public surface of the port, and the execution-boundary proof that
the module cannot mutate anything.

The last two groups are structural (AST-based) rather than declarative:
a promise in a docstring is not a control.
"""

import ast
import inspect
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from incident_service.application.services.progressive_release_gate_service import (
    GATE_POLICY_VERSION,
)
from incident_service.application.services.rollout_plan_service import (
    PREFLIGHT_READY,
    OBSERVED_KNOWN,
    ObservedTrafficState,
    RolloutPlanService,
    TrafficControllerPort,
    TrafficIntent,
)
from incident_service.application.services.traffic_mutation_boundary import (
    FORBIDDEN_PORT_MEMBERS,
    OP_APPLY,
    OP_ROLLBACK,
    TRAFFIC_MUTATION_OPERATIONS,
    TRAFFIC_MUTATION_REQUEST_VERSION,
    InvalidTrafficMutationRequest,
    TrafficMutationError,
    TrafficMutationPort,
    TrafficMutationProviderUnavailable,
    TrafficMutationRequest,
    TrafficMutationResult,
    UNAVAILABLE_PROVIDER,
    UnavailableTrafficMutationProvider,
    is_traffic_mutation_port,
)

UTC = timezone.utc
SHA = "a" * 40
RUN_ID = "run-8-7-a"
GATE_EVAL_ID = "gate-eval-1"
INTENT_ID = "ti_0123456789abcdef01234567"
STABLE = "svc-stable"
CANARY = "svc-canary"
OBSERVED_AT = datetime(2026, 10, 8, 9, 30, tzinfo=UTC)

MODULE_PATH = Path(
    "incident_service/application/services/traffic_mutation_boundary.py"
)


def _intent(
    *,
    current=5,
    requested=25,
    stable=STABLE,
    canary=CANARY,
    source_sha=SHA,
    run_id=RUN_ID,
    gate_evaluation_id=GATE_EVAL_ID,
    intent_id=INTENT_ID,
):
    return TrafficIntent(
        intent_id=intent_id,
        deployment_run_id=run_id,
        source_sha=source_sha,
        gate_evaluation_id=gate_evaluation_id,
        stable_target=stable,
        canary_target=canary,
        current_percentage=current,
        requested_percentage=requested,
        created_at=OBSERVED_AT,
        evaluated_at=OBSERVED_AT,
    )


def _request(**overrides):
    kwargs = {
        "deployment_run_id": RUN_ID,
        "source_sha": SHA,
        "gate_evaluation_id": GATE_EVAL_ID,
        "intent_id": INTENT_ID,
        "stable_target": STABLE,
        "canary_target": CANARY,
        "expected_current_percentage": 5,
        "requested_percentage": 25,
        "observed_percentage": 5,
        "observed_at": OBSERVED_AT,
    }
    kwargs.update(overrides)
    return TrafficMutationRequest(**kwargs)


class RecordingMutationProvider:
    """A test double AT the port boundary (never shipped).

    It records the requests it is handed and returns a result the test
    scripted. It calls nothing and mutates nothing; the point of the
    double is to prove what the boundary hands a provider, not to
    simulate traffic.
    """

    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.apply_calls = []
        self.rollback_calls = []

    def apply(self, request):
        self.apply_calls.append(request)
        if self.error is not None:
            raise self.error
        return self.result

    def rollback(self, request):
        self.rollback_calls.append(request)
        if self.error is not None:
            raise self.error
        return self.result


# ---------------------------------------------------------------- request


class TrafficMutationRequestTests(unittest.TestCase):
    def test_valid_intent_produces_a_valid_request(self):
        request = TrafficMutationRequest.from_traffic_intent(
            _intent(), observed_percentage=5, observed_at=OBSERVED_AT
        )
        self.assertEqual(request.deployment_run_id, RUN_ID)
        self.assertEqual(request.source_sha, SHA)
        self.assertEqual(request.gate_evaluation_id, GATE_EVAL_ID)
        self.assertEqual(request.intent_id, INTENT_ID)
        self.assertEqual(request.stable_target, STABLE)
        self.assertEqual(request.canary_target, CANARY)
        self.assertEqual(request.expected_current_percentage, 5)
        self.assertEqual(request.requested_percentage, 25)
        self.assertEqual(request.observed_percentage, 5)
        self.assertEqual(request.observed_at, OBSERVED_AT)

    def test_request_is_immutable(self):
        request = _request()
        with self.assertRaises(Exception):
            request.requested_percentage = 50  # type: ignore[misc]

    def test_request_preserves_the_intent_identity_exactly(self):
        """No second identity scheme: the ids come from the intent."""
        intent = _intent()
        request = TrafficMutationRequest.from_traffic_intent(
            intent, observed_percentage=5, observed_at=OBSERVED_AT
        )
        self.assertEqual(request.intent_id, intent.intent_id)
        self.assertEqual(request.deployment_run_id, intent.deployment_run_id)
        self.assertEqual(request.source_sha, intent.source_sha)
        self.assertEqual(
            request.gate_evaluation_id, intent.gate_evaluation_id
        )
        self.assertEqual(
            request.expected_current_percentage, intent.current_percentage
        )
        self.assertEqual(
            request.requested_percentage, intent.requested_percentage
        )

    def test_observed_state_and_timestamp_are_carried(self):
        """The provider boundary must see what was observed, and when."""
        request = _request(
            observed_at=datetime(2026, 10, 8, 11, 45, 30, tzinfo=UTC)
        )
        self.assertEqual(request.observed_percentage, 5)
        self.assertEqual(
            request.observed_at,
            datetime(2026, 10, 8, 11, 45, 30, tzinfo=UTC),
        )

    def test_naive_timestamp_is_normalised_to_utc(self):
        request = _request(
            observed_at=datetime(2026, 10, 8, 9, 30)
        )
        self.assertEqual(request.observed_at.tzinfo, UTC)
        self.assertEqual(request.observed_at, OBSERVED_AT)

    def test_non_datetime_observation_is_rejected(self):
        with self.assertRaises(InvalidTrafficMutationRequest):
            _request(observed_at="2026-10-08T09:30:00Z")

    def test_intent_without_proven_targets_cannot_produce_a_request(self):
        """The plan service leaves targets None until observation
        proves them; an unproven target is not a target."""
        for stable, canary in (
            (None, CANARY),
            (STABLE, None),
            (None, None),
            ("   ", CANARY),
            (STABLE, ""),
        ):
            with self.subTest(stable=stable, canary=canary):
                with self.assertRaises(InvalidTrafficMutationRequest):
                    TrafficMutationRequest.from_traffic_intent(
                        _intent(stable=stable, canary=canary),
                        observed_percentage=5,
                        observed_at=OBSERVED_AT,
                    )

    def test_from_traffic_intent_rejects_a_lookalike_object(self):
        class NotAnIntent:
            intent_id = INTENT_ID
            stable_target = STABLE
            canary_target = CANARY

        with self.assertRaises(InvalidTrafficMutationRequest):
            TrafficMutationRequest.from_traffic_intent(
                NotAnIntent(), observed_percentage=5, observed_at=OBSERVED_AT
            )


class TrafficMutationDigestTests(unittest.TestCase):
    def test_digest_is_a_sha256_hex_string(self):
        digest = _request().digest()
        self.assertEqual(len(digest), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in digest))

    def test_digest_is_deterministic(self):
        self.assertEqual(_request().digest(), _request().digest())

    def test_equivalent_requests_produce_the_same_digest(self):
        """Same authority, different construction route, same digest."""
        from_intent = TrafficMutationRequest.from_traffic_intent(
            _intent(), observed_percentage=5, observed_at=OBSERVED_AT
        )
        direct = _request()
        via_utc_offset = _request(
            observed_at=datetime(2026, 10, 8, 15, 0, tzinfo=timezone(
                timedelta(hours=5, minutes=30)))
        )
        # 15:00+05:30 is 09:30 UTC -- the same instant the other two use.
        self.assertEqual(from_intent.digest(), direct.digest())
        self.assertEqual(direct.digest(), via_utc_offset.digest())

    def test_changing_any_identity_critical_field_changes_the_digest(self):
        base = _request()
        mutations = {
            "deployment_run_id": {"deployment_run_id": "run-other"},
            "source_sha": {"source_sha": "b" * 40},
            "gate_evaluation_id": {"gate_evaluation_id": "gate-eval-2"},
            "intent_id": {"intent_id": "ti_ffffffffffffffffffffffff"},
            "stable_target": {"stable_target": "svc-stable-2"},
            "canary_target": {"canary_target": "svc-canary-2"},
            # expected/observed move together: they must be equal.
            "expected_current_percentage": {
                "expected_current_percentage": 25,
                "observed_percentage": 25,
                "requested_percentage": 50,
            },
            "requested_percentage": {"requested_percentage": 50},
            "observed_percentage": {
                "expected_current_percentage": 25,
                "observed_percentage": 25,
                "requested_percentage": 50,
            },
            "observed_at": {
                "observed_at": OBSERVED_AT + timedelta(seconds=1)
            },
        }
        self.assertEqual(
            set(mutations),
            set(base.to_dict()),
            "every field of the canonical payload must be covered",
        )
        for field, override in mutations.items():
            with self.subTest(field=field):
                self.assertNotEqual(
                    base.digest(),
                    _request(**override).digest(),
                    f"changing {field} must change the request digest",
                )

    def test_digest_does_not_depend_on_field_insertion_order(self):
        """Canonicalisation, not dict iteration order, decides."""
        request = _request()
        payload = request.to_dict()
        reordered = {
            key: payload[key] for key in reversed(list(payload))
        }
        self.assertEqual(list(payload), list(request.to_dict()))
        self.assertEqual(list(reversed(list(reordered))), list(payload))

    def test_to_dict_is_json_serialisable_and_versioned(self):
        import json

        payload = _request().to_dict()
        self.assertEqual(
            json.loads(json.dumps(payload)),
            payload,
        )
        self.assertEqual(TRAFFIC_MUTATION_REQUEST_VERSION, "traffic-mutation-request-v1")

    def test_digest_carries_no_implicit_clock(self):
        """Two requests built a second apart digest identically when the
        observation is the same: nothing is generated during hashing."""
        first = _request()
        second = _request()
        self.assertEqual(first.digest(), second.digest())


class TrafficMutationValidationTests(unittest.TestCase):
    def test_missing_stable_target_is_rejected(self):
        for value in ("", "   ", None, 0):
            with self.subTest(value=value):
                with self.assertRaises(InvalidTrafficMutationRequest):
                    _request(stable_target=value)

    def test_missing_canary_target_is_rejected(self):
        for value in ("", "   ", None, 0):
            with self.subTest(value=value):
                with self.assertRaises(InvalidTrafficMutationRequest):
                    _request(canary_target=value)

    def test_missing_run_id_is_rejected(self):
        with self.assertRaises(InvalidTrafficMutationRequest):
            _request(deployment_run_id="")

    def test_missing_gate_evaluation_id_is_rejected(self):
        with self.assertRaises(InvalidTrafficMutationRequest):
            _request(gate_evaluation_id="")

    def test_missing_intent_id_is_rejected(self):
        with self.assertRaises(InvalidTrafficMutationRequest):
            _request(intent_id="")

    def test_over_long_identifier_is_rejected(self):
        with self.assertRaises(InvalidTrafficMutationRequest):
            _request(intent_id="i" * 129)

    def test_malformed_source_sha_is_rejected(self):
        for value in ("z" * 40, "g" * 40, "a" * 39 + "-", "not-a-sha"):
            with self.subTest(value=value):
                with self.assertRaises(InvalidTrafficMutationRequest):
                    _request(source_sha=value)

    def test_uppercase_source_sha_is_rejected(self):
        with self.assertRaises(InvalidTrafficMutationRequest):
            _request(source_sha="A" * 40)
        # 39 lowercase + one uppercase is still mixed case
        with self.assertRaises(InvalidTrafficMutationRequest):
            _request(source_sha="a" * 39 + "B")

    def test_incorrect_source_sha_length_is_rejected(self):
        for value in ("a" * 39, "a" * 41, ""):
            with self.subTest(length=len(value)):
                with self.assertRaises(InvalidTrafficMutationRequest):
                    _request(source_sha=value)

    def test_percentage_outside_bounds_is_rejected(self):
        for field, value in (
            ("expected_current_percentage", -1),
            ("expected_current_percentage", 101),
            ("requested_percentage", 101),
            ("requested_percentage", 1000),
            ("observed_percentage", -5),
        ):
            with self.subTest(field=field, value=value):
                override = {field: value}
                if field == "observed_percentage":
                    override["expected_current_percentage"] = value
                with self.assertRaises(InvalidTrafficMutationRequest):
                    _request(**override)

    def test_boolean_percentage_is_rejected(self):
        """bool is an int subclass; a percentage is never a boolean."""
        with self.assertRaises(InvalidTrafficMutationRequest):
            _request(expected_current_percentage=True, observed_percentage=True)
        with self.assertRaises(InvalidTrafficMutationRequest):
            _request(requested_percentage=True)
        with self.assertRaises(InvalidTrafficMutationRequest):
            _request(requested_percentage=False)

    def test_non_integer_percentage_is_rejected(self):
        for value in (25.0, "25", None):
            with self.subTest(value=value):
                with self.assertRaises(InvalidTrafficMutationRequest):
                    _request(requested_percentage=value)

    def test_observed_percentage_must_match_the_expected_state(self):
        """A valid requested target is not a substitute for observation."""
        for observed in (0, 4, 6, 25, 50, 100):
            with self.subTest(observed=observed):
                with self.assertRaises(InvalidTrafficMutationRequest):
                    _request(observed_percentage=observed)

    def test_no_op_request_is_rejected(self):
        with self.assertRaises(InvalidTrafficMutationRequest):
            _request(requested_percentage=5)
        with self.assertRaises(InvalidTrafficMutationRequest):
            TrafficMutationRequest.from_traffic_intent(
                _intent(current=5, requested=5),
                observed_percentage=5,
                observed_at=OBSERVED_AT,
            )

    def test_backward_apply_is_rejected(self):
        """Rollback is a separate operation, not a negative apply."""
        with self.assertRaises(InvalidTrafficMutationRequest):
            _request(
                expected_current_percentage=50,
                observed_percentage=50,
                requested_percentage=25,
            )
        with self.assertRaises(InvalidTrafficMutationRequest):
            TrafficMutationRequest.from_traffic_intent(
                _intent(current=50, requested=5),
                observed_percentage=50,
                observed_at=OBSERVED_AT,
            )


# ----------------------------------------------------------------- result


class TrafficMutationResultTests(unittest.TestCase):
    def test_unverified_result_is_representable_and_preserved(self):
        result = TrafficMutationResult(
            provider="some-provider",
            request_digest=_request().digest(),
            operation=OP_APPLY,
            remote_percentage=None,
            verified=False,
            detail="provider call returned, remote state not confirmed",
        )
        self.assertFalse(result.verified)
        self.assertIsNone(result.remote_percentage)
        self.assertFalse(result.to_dict()["verified"])

    def test_verified_result_requires_an_explicit_flag(self):
        signature = inspect.signature(TrafficMutationResult)
        self.assertNotIn(
            "verified",
            {
                name: parameter
                for name, parameter in signature.parameters.items()
                if parameter.default is not inspect.Parameter.empty
            },
            "verified must be explicit, never defaulted",
        )

    def test_verified_false_is_not_converted_to_success(self):
        result = TrafficMutationResult(
            provider="some-provider",
            request_digest=_request().digest(),
            operation=OP_APPLY,
            remote_percentage=25,
            verified=False,
            external_operation_id="op-1",
            detail="remote reports 25 but could not be re-observed",
        )
        self.assertEqual(result.remote_percentage, 25)
        self.assertFalse(result.verified)

    def test_fully_verified_result_is_expressible(self):
        result = TrafficMutationResult(
            provider="some-provider",
            request_digest=_request().digest(),
            operation=OP_APPLY,
            remote_percentage=25,
            verified=True,
            external_operation_id="op-2",
        )
        self.assertTrue(result.verified)
        self.assertEqual(result.remote_percentage, 25)

    def test_invalid_operation_is_rejected(self):
        for operation in ("SET", "apply", "", "MUTATE", None, 1):
            with self.subTest(operation=operation):
                with self.assertRaises(InvalidTrafficMutationRequest):
                    TrafficMutationResult(
                        provider="some-provider",
                        request_digest=_request().digest(),
                        operation=operation,
                        remote_percentage=25,
                        verified=False,
                    )

    def test_both_operations_are_accepted(self):
        for operation in TRAFFIC_MUTATION_OPERATIONS:
            with self.subTest(operation=operation):
                TrafficMutationResult(
                    provider="some-provider",
                    request_digest=_request().digest(),
                    operation=operation,
                    remote_percentage=None,
                    verified=False,
                )
        self.assertEqual(set(TRAFFIC_MUTATION_OPERATIONS), {OP_APPLY, OP_ROLLBACK})

    def test_non_boolean_verified_is_rejected(self):
        for value in ("false", 0, 1, None):
            with self.subTest(value=value):
                with self.assertRaises(InvalidTrafficMutationRequest):
                    TrafficMutationResult(
                        provider="some-provider",
                        request_digest=_request().digest(),
                        operation=OP_APPLY,
                        remote_percentage=25,
                        verified=value,
                    )

    def test_out_of_range_remote_percentage_is_rejected(self):
        with self.assertRaises(InvalidTrafficMutationRequest):
            TrafficMutationResult(
                provider="some-provider",
                request_digest=_request().digest(),
                operation=OP_APPLY,
                remote_percentage=101,
                verified=True,
            )

    def test_blank_provider_or_digest_is_rejected(self):
        with self.assertRaises(InvalidTrafficMutationRequest):
            TrafficMutationResult(
                provider="",
                request_digest=_request().digest(),
                operation=OP_APPLY,
                remote_percentage=25,
                verified=False,
            )
        for digest in ("", "not-a-digest", "a" * 63, "A" * 64, "z" * 64):
            with self.subTest(digest=digest[:12]):
                with self.assertRaises(InvalidTrafficMutationRequest):
                    TrafficMutationResult(
                        provider="some-provider",
                        request_digest=digest,
                        operation=OP_APPLY,
                        remote_percentage=25,
                        verified=False,
                    )

    def test_verification_without_an_observed_percentage_is_rejected(self):
        """verified=True is a claim about an observed remote state; a
        claim with no observed value proves nothing."""
        with self.assertRaises(InvalidTrafficMutationRequest):
            TrafficMutationResult(
                provider="some-provider",
                request_digest=_request().digest(),
                operation=OP_APPLY,
                remote_percentage=None,
                verified=True,
            )

    def test_a_verified_result_cannot_be_attributed_to_the_unavailable_provider(self):
        with self.assertRaises(InvalidTrafficMutationRequest):
            TrafficMutationResult(
                provider=UNAVAILABLE_PROVIDER,
                request_digest=_request().digest(),
                operation=OP_APPLY,
                remote_percentage=25,
                verified=True,
            )
        # …but an honest unverified result from it is expressible.
        result = TrafficMutationResult(
            provider=UNAVAILABLE_PROVIDER,
            request_digest=_request().digest(),
            operation=OP_APPLY,
            remote_percentage=None,
            verified=False,
        )
        self.assertFalse(result.verified)

    def test_result_digest_correlates_with_the_request(self):
        """A result can only be tied to one exact request."""
        first = _request()
        second = _request(requested_percentage=50)
        result = TrafficMutationResult(
            provider="some-provider",
            request_digest=first.digest(),
            operation=OP_APPLY,
            remote_percentage=25,
            verified=True,
        )
        self.assertEqual(result.request_digest, first.digest())
        self.assertNotEqual(result.request_digest, second.digest())

    def test_over_long_detail_is_rejected(self):
        with self.assertRaises(InvalidTrafficMutationRequest):
            TrafficMutationResult(
                provider="some-provider",
                request_digest=_request().digest(),
                operation=OP_APPLY,
                remote_percentage=25,
                verified=False,
                detail="d" * 513,
            )


# ------------------------------------------------- provider / port surface


class UnavailableProviderTests(unittest.TestCase):
    def test_default_apply_fails_closed(self):
        with self.assertRaises(TrafficMutationProviderUnavailable):
            UnavailableTrafficMutationProvider().apply(_request())

    def test_default_rollback_fails_closed(self):
        with self.assertRaises(TrafficMutationProviderUnavailable):
            UnavailableTrafficMutationProvider().rollback(_request())

    def test_unavailable_error_is_a_traffic_mutation_error(self):
        self.assertTrue(
            issubclass(TrafficMutationProviderUnavailable, TrafficMutationError)
        )
        self.assertTrue(
            issubclass(TrafficMutationProviderUnavailable, RuntimeError)
        )

    def test_default_provider_never_returns_a_result(self):
        """Fail-closed means RAISING: there is no value to mistake for
        success, and no local state is written and renamed 'traffic'."""
        provider = UnavailableTrafficMutationProvider()
        for method in (provider.apply, provider.rollback):
            with self.subTest(method=method.__name__):
                try:
                    returned = method(_request())
                except TrafficMutationProviderUnavailable:
                    returned = "raised"
                self.assertEqual(
                    returned,
                    "raised",
                    "the default provider must raise, never return",
                )

    def test_default_provider_holds_no_mutable_state(self):
        provider = UnavailableTrafficMutationProvider()
        self.assertEqual(
            [name for name in vars(provider)],
            [],
            "a fail-closed provider has nothing to mutate",
        )

    def test_a_request_that_cannot_be_trusted_never_reaches_a_provider(self):
        provider = RecordingMutationProvider()
        with self.assertRaises(InvalidTrafficMutationRequest):
            TrafficMutationRequest.from_traffic_intent(
                _intent(stable=None),
                observed_percentage=5,
                observed_at=OBSERVED_AT,
            )
        request = _request()
        with self.assertRaises(InvalidTrafficMutationRequest):
            TrafficMutationRequest(**{**request.to_dict(),
                                      "observed_percentage": 4})
        self.assertEqual(provider.apply_calls, [])

    def test_the_boundary_hands_a_provider_the_request_unchanged(self):
        provider = RecordingMutationProvider(
            result=TrafficMutationResult(
                provider="recording",
                request_digest=_request().digest(),
                operation=OP_APPLY,
                remote_percentage=None,
                verified=False,
            )
        )
        request = _request()
        provider.apply(request)
        self.assertEqual(provider.apply_calls, [request])
        self.assertEqual(provider.apply_calls[0].digest(), request.digest())


class TrafficMutationPortTests(unittest.TestCase):
    def test_port_exposes_exactly_apply_and_rollback(self):
        members = {
            name
            for name in dir(TrafficMutationPort)
            if not name.startswith("_")
        }
        self.assertEqual(members, {"apply", "rollback"})

    def test_port_has_no_forbidden_mutation_or_planning_members(self):
        for member in FORBIDDEN_PORT_MEMBERS:
            with self.subTest(member=member):
                self.assertFalse(hasattr(TrafficMutationPort, member))

    def test_default_provider_satisfies_the_port(self):
        self.assertIsInstance(
            UnavailableTrafficMutationProvider(), TrafficMutationPort
        )
        self.assertTrue(
            is_traffic_mutation_port(UnavailableTrafficMutationProvider())
        )

    def test_structural_witness_rejects_a_broadened_surface(self):
        class BroadenedProvider:
            def apply(self, request):  # pragma: no cover - never called
                raise AssertionError

            def rollback(self, request):  # pragma: no cover
                raise AssertionError

            def mutate(self, request):  # pragma: no cover
                raise AssertionError

        class IncompleteProvider:
            def apply(self, request):  # pragma: no cover
                raise AssertionError

        self.assertFalse(is_traffic_mutation_port(BroadenedProvider()))
        self.assertFalse(is_traffic_mutation_port(IncompleteProvider()))
        self.assertTrue(is_traffic_mutation_port(RecordingMutationProvider()))

    def test_planning_port_was_not_turned_into_a_mutation_interface(self):
        """Phase 6.7.1's port stays inspect/plan only — phase 8.7-A is a
        SEPARATE boundary, not a widening of the planning one."""
        members = {
            name
            for name in dir(TrafficControllerPort)
            if not name.startswith("_")
        }
        self.assertEqual(members, {"inspect", "plan"})
        for member in ("apply", "rollback"):
            with self.subTest(member=member):
                self.assertFalse(hasattr(TrafficControllerPort, member))


# ---------------------------------------------------- integration / evidence


class RolloutPlanIntegrationTests(unittest.TestCase):
    """The REAL RolloutPlanService produces the intent this boundary
    consumes. Nothing here re-derives identity."""

    class _StageRepository:
        def __init__(self, stage, evaluation):
            self._stage = stage
            self._evaluation = evaluation

        def get_progressive_rollout_stage(self, deployment_run_id):
            return dict(self._stage)

        def get_progressive_release_gate_evaluation(self, evaluation_id):
            return dict(self._evaluation)

        def get_progressive_release_gate_evaluations(self, deployment_run_id):
            return [dict(self._evaluation)]

    def _plan(self):
        now = datetime(2026, 10, 8, 9, 0, tzinfo=UTC)
        stage = {
            "stage_state_id": "stage-1",
            "deployment_run_id": RUN_ID,
            "source_sha": SHA,
            "repository": "gm-prog/Autonomous-Devops-Engineer",
            "state": "ACTIVE",
            "current_percentage": 5,
            "previous_percentage": 0,
        }
        evaluation = {
            "evaluation_id": GATE_EVAL_ID,
            "deployment_run_id": RUN_ID,
            "source_sha": SHA,
            "target_percentage": 25,
            "gate_decision": "PROMOTE",
            "health_decision": "HEALTHY",
            "policy_version": GATE_POLICY_VERSION,
            "observed_at": now,
            "expires_at": now + timedelta(hours=1),
        }
        controller = RecordingMutationProvider()
        controller.inspect_calls = []  # not part of the mutation port

        class _ReadOnlyController:
            """inspect/plan only, exactly like TrafficControllerPort."""

            def __init__(self):
                self.inspect_calls = []
                self.plan_calls = []

            def inspect(self, deployment_run_id, source_sha):
                self.inspect_calls.append((deployment_run_id, source_sha))
                return ObservedTrafficState(
                    provider="test-weighted-router",
                    observed_status=OBSERVED_KNOWN,
                    observed_percentage=5,
                    stable_identity=STABLE,
                    canary_identity=CANARY,
                    deployment_run_id=RUN_ID,
                    source_sha=SHA,
                    observation_timestamp=now,
                    observation_source="provider-inspection",
                    detail="fixture",
                )

            def plan(self, intent):
                self.plan_calls.append(intent.intent_id)
                return {"provider": "test-weighted-router", "rendered": True}

        service = RolloutPlanService(
            repository=self._StageRepository(stage, evaluation),
            controller=_ReadOnlyController(),
            now_factory=lambda: now,
        )
        return service.plan(RUN_ID, GATE_EVAL_ID, 25, SHA), service

    def test_a_real_ready_preflight_yields_a_mutation_request(self):
        planned, _ = self._plan()
        self.assertEqual(planned["preflight_status"], PREFLIGHT_READY)
        published = planned["intent"]
        intent = TrafficIntent(
            intent_id=published["intent_id"],
            deployment_run_id=published["deployment_run_id"],
            source_sha=published["source_sha"],
            gate_evaluation_id=published["gate_evaluation_id"],
            stable_target=published["stable_target"],
            canary_target=published["canary_target"],
            current_percentage=published["current_percentage"],
            requested_percentage=published["requested_percentage"],
            created_at=datetime.fromisoformat(published["created_at"]),
            evaluated_at=datetime.fromisoformat(published["evaluated_at"]),
        )
        request = TrafficMutationRequest.from_traffic_intent(
            intent, observed_percentage=5, observed_at=OBSERVED_AT
        )
        self.assertEqual(request.intent_id, published["intent_id"])
        self.assertEqual(request.deployment_run_id, RUN_ID)
        self.assertEqual(request.source_sha, SHA)
        self.assertEqual(request.gate_evaluation_id, GATE_EVAL_ID)
        self.assertEqual(request.stable_target, STABLE)
        self.assertEqual(request.canary_target, CANARY)
        self.assertEqual(request.expected_current_percentage, 5)
        self.assertEqual(request.requested_percentage, 25)
        # The intent id is the plan service's own, not the fixture's: it
        # hashes run+SHA+current+requested, so the boundary is provably
        # consuming the service's identity rather than minting its own.
        self.assertTrue(published["intent_id"].startswith("ti_"))
        self.assertEqual(len(published["intent_id"]), 27)
        self.assertNotEqual(published["intent_id"], INTENT_ID)
        # …and it is the same request the boundary would digest directly.
        self.assertEqual(
            request.digest(),
            _request(intent_id=published["intent_id"]).digest(),
        )

    def test_ready_preflight_did_not_mutate_anything(self):
        """READY is not evidence that traffic changed."""
        planned, service = self._plan()
        self.assertEqual(planned["preflight_status"], PREFLIGHT_READY)
        self.assertFalse(hasattr(service.controller, "apply"))
        self.assertFalse(hasattr(service.controller, "rollback"))
        self.assertEqual(planned["observed_traffic"]["observed_percentage"], 5)


# ------------------------------------------------- execution-boundary proof


def _module_tree():
    return ast.parse(MODULE_PATH.read_text(encoding="utf-8"))


class ExecutionBoundarySourceTests(unittest.TestCase):
    """The module must be unable to mutate anything, structurally."""

    #: Modules whose presence would mean a real execution mechanism
    #: could be reached from this boundary.
    FORBIDDEN_IMPORTS = {
        "subprocess",
        "requests",
        "httpx",
        "aiohttp",
        "urllib",
        "urllib2",
        "http",
        "socket",
        "boto3",
        "botocore",
        "google",
        "azure",
        "kubernetes",
        "docker",
        "paramiko",
        "shlex",
        "pty",
        "ctypes",
        "os",
    }

    #: Callables that would execute or fetch something.
    FORBIDDEN_CALLS = {
        "open",
        "eval",
        "exec",
        "compile",
        "__import__",
        "system",
        "popen",
        "run",
        "call",
        "check_call",
        "check_output",
        "urlopen",
        "request",
        "get",
        "post",
        "put",
        "patch",
    }

    def test_module_imports_no_execution_or_network_mechanism(self):
        tree = _module_tree()
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported.add(node.module.split(".")[0])
        offenders = sorted(imported & self.FORBIDDEN_IMPORTS)
        self.assertEqual(
            offenders,
            [],
            f"execution/network modules must not be reachable: {offenders}",
        )

    def test_module_calls_no_execution_or_network_function(self):
        tree = _module_tree()
        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            else:
                continue
            if name in self.FORBIDDEN_CALLS:
                # `validate_*` style helpers are ours; exact-name matches
                # only, so nothing here is a false positive today.
                offenders.append(name)
        self.assertEqual(
            sorted(set(offenders)),
            [],
            f"no execution/network call may exist in the boundary: {offenders}",
        )

    def test_module_has_no_attribute_chain_into_a_forbidden_module(self):
        tree = _module_tree()
        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute):
                continue
            parts = []
            current = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            chain = ".".join(reversed(parts))
            root = chain.split(".")[0]
            if root in self.FORBIDDEN_IMPORTS:
                offenders.append(chain)
        self.assertEqual(offenders, [], f"no foreign mechanism: {offenders}")

    def test_no_traffic_mutation_implementation_is_hidden_in_the_module(self):
        """Only the fail-closed default provider may exist: no shipped
        provider may carry a mutation mechanism behind the interface."""
        tree = _module_tree()
        # "Providers" are exactly the classes that implement the mutation
        # surface -- not every class whose name contains the word.
        providers = []
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            methods = {
                item.name
                for item in node.body
                if isinstance(item, ast.FunctionDef)
            }
            if {"apply", "rollback"} <= methods:
                providers.append(node)
        self.assertEqual(
            [node.name for node in providers],
            ["TrafficMutationPort", "UnavailableTrafficMutationProvider"],
            "the only provider shipped in 8.7-A is the fail-closed default",
        )

        protocol, default = providers
        # The protocol declares the surface and implements nothing.
        for method in protocol.body:
            if not isinstance(method, ast.FunctionDef):
                continue
            with self.subTest(protocol_method=method.name):
                self.assertEqual(len(method.body), 1)
                self.assertIsInstance(method.body[0], ast.Expr)
                self.assertIsInstance(method.body[0].value, ast.Constant)
                self.assertIs(
                    method.body[0].value.value, Ellipsis,
                    "the protocol declares the surface and implements nothing",
                )

        # The default provider raises and returns nothing.
        for method in default.body:
            if not isinstance(method, ast.FunctionDef):
                continue
            with self.subTest(method=method.name):
                raises = [
                    node
                    for node in ast.walk(method)
                    if isinstance(node, ast.Raise)
                ]
                returns = [
                    node
                    for node in ast.walk(method)
                    if isinstance(node, ast.Return) and node.value is not None
                ]
                self.assertTrue(raises, f"{method.name} must raise")
                self.assertEqual(
                    returns, [], f"{method.name} must not return a result"
                )

    def test_module_does_not_reach_into_infrastructure_or_other_services(self):
        """Provider-neutral: no database, no Kubernetes/cloud client, no
        deployment-service coupling."""
        tree = _module_tree()
        modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module)
        expected = {
            "incident_service.application.services.rollout_plan_service"
        }
        internal = {m for m in modules
                    if m.startswith(("incident_service.", "deployment_service."))
                    or m == "deployment_service"}
        self.assertEqual(
            internal,
            expected,
            "the boundary may bind to the rollout intent and nothing else",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
