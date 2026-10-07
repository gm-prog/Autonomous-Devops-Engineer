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
    expected_verified_percentage,
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
    """The result is bound to ONE request, and verification is a claim
    about that request's requested percentage and nothing else."""

    def _result(self, request=None, **overrides):
        kwargs = {
            "provider": "some-provider",
            "operation": OP_APPLY,
            "remote_percentage": None,
            "verified": False,
        }
        kwargs.update(overrides)
        return TrafficMutationResult.from_request(request or _request(), **kwargs)

    # ---- binding -----------------------------------------------------

    def test_result_created_from_a_request_carries_that_request_digest(self):
        request = _request()
        result = self._result(request)
        self.assertEqual(result.request_digest, request.digest())
        self.assertIs(result.request, request)

    def test_both_construction_paths_bind_identically(self):
        request = _request()
        direct = TrafficMutationResult(
            request=request, provider="some-provider", operation=OP_APPLY,
            remote_percentage=25, verified=True,
        )
        factory = TrafficMutationResult.from_request(
            request, provider="some-provider", operation=OP_APPLY,
            remote_percentage=25, verified=True,
        )
        self.assertEqual(direct, factory)
        self.assertEqual(direct.request_digest, factory.request_digest)
        self.assertEqual(direct.to_dict(), factory.to_dict())

    def test_no_construction_path_accepts_a_freestanding_digest(self):
        """The Finding-A attack — request A plus request B's digest — is
        unrepresentable, not merely rejected: there is no parameter for
        a digest to arrive through."""
        for constructor in (
            TrafficMutationResult,
            TrafficMutationResult.from_request,
        ):
            parameters = set(inspect.signature(constructor).parameters)
            self.assertNotIn(
                "request_digest", parameters,
                f"{constructor} must not take a supplied digest",
            )
            self.assertIn("request", parameters)

        with self.assertRaises(TypeError):
            TrafficMutationResult(
                request=_request(),
                provider="some-provider",
                operation=OP_APPLY,
                remote_percentage=25,
                verified=True,
                request_digest=_request(requested_percentage=50).digest(),
            )
        with self.assertRaises(TypeError):
            TrafficMutationResult.from_request(
                _request(),
                provider="some-provider",
                operation=OP_APPLY,
                remote_percentage=25,
                verified=True,
                request_digest="a" * 64,
            )

    def test_a_result_cannot_be_bound_to_request_a_while_answering_b(self):
        request_a = _request()
        request_b = _request(requested_percentage=50)
        result_b = self._result(
            request_b, remote_percentage=50, verified=True
        )
        self.assertEqual(result_b.request_digest, request_b.digest())
        self.assertNotEqual(result_b.request_digest, request_a.digest())
        # No attribute assignment can re-point the binding.
        with self.assertRaises(Exception):
            result_b.request = request_a  # type: ignore[misc]

    def test_the_bound_request_must_be_a_real_request(self):
        with self.assertRaises(InvalidTrafficMutationRequest):
            TrafficMutationResult(
                request=_request().digest(),  # a bare digest is not a request
                provider="some-provider",
                operation=OP_APPLY,
                remote_percentage=None,
                verified=False,
            )
        with self.assertRaises(InvalidTrafficMutationRequest):
            TrafficMutationResult(
                request=None,
                provider="some-provider",
                operation=OP_APPLY,
                remote_percentage=None,
                verified=False,
            )

    def test_result_digest_tracks_every_identity_critical_request_field(self):
        base = _request()
        base_digest = self._result(base).request_digest
        self.assertEqual(base_digest, base.digest())
        for field, override in (
            ("deployment_run_id", {"deployment_run_id": "run-other"}),
            ("source_sha", {"source_sha": "b" * 40}),
            ("gate_evaluation_id", {"gate_evaluation_id": "gate-eval-2"}),
            ("intent_id", {"intent_id": "ti_ffffffffffffffffffffffff"}),
            ("stable_target", {"stable_target": "svc-stable-2"}),
            ("canary_target", {"canary_target": "svc-canary-2"}),
            ("expected_current_percentage",
             {"expected_current_percentage": 25, "observed_percentage": 25,
              "requested_percentage": 50}),
            ("requested_percentage",
             {"expected_current_percentage": 25, "observed_percentage": 25,
              "requested_percentage": 50}),
            ("observed_percentage",
             {"expected_current_percentage": 25, "observed_percentage": 25,
              "requested_percentage": 50}),
            ("observed_at", {"observed_at": OBSERVED_AT
                             + timedelta(seconds=1)}),
        ):
            with self.subTest(field=field):
                other = _request(**override)
                self.assertNotEqual(
                    self._result(other).request_digest, base_digest
                )
                self.assertEqual(
                    self._result(other).request_digest, other.digest()
                )

    def test_same_request_same_result_digest_different_request_different(self):
        first = self._result(_request())
        same = self._result(_request())
        other = self._result(_request(requested_percentage=50))
        self.assertEqual(first.request_digest, same.request_digest)
        self.assertNotEqual(first.request_digest, other.request_digest)

    # ---- verification semantics --------------------------------------

    def test_unverified_result_without_an_observation_is_valid(self):
        result = self._result(remote_percentage=None, verified=False)
        self.assertFalse(result.verified)
        self.assertIsNone(result.remote_percentage)
        self.assertEqual(result.request_digest, _request().digest())

    def test_unverified_result_may_still_report_an_observation(self):
        """Finding C: an informative but unproven observation stays
        representable — including the requested value itself."""
        for remote in (0, 5, 25, 50, 100):
            with self.subTest(remote=remote):
                result = self._result(
                    remote_percentage=remote, verified=False
                )
                self.assertEqual(result.remote_percentage, remote)
                self.assertFalse(result.verified)
                self.assertEqual(
                    result.request_digest, _request().digest()
                )

    def test_verified_without_an_observation_is_rejected(self):
        with self.assertRaises(InvalidTrafficMutationRequest):
            self._result(remote_percentage=None, verified=True)

    def test_verified_with_a_different_remote_percentage_is_rejected(self):
        """Finding B: verified=True means the requested state was
        observed — not some other state."""
        for remote in (0, 5, 24, 26, 50, 100):
            with self.subTest(remote=remote):
                with self.assertRaises(InvalidTrafficMutationRequest):
                    self._result(remote_percentage=remote, verified=True)

    def test_verified_with_the_requested_percentage_is_valid(self):
        request = _request()
        result = self._result(
            request, remote_percentage=request.requested_percentage,
            verified=True, external_operation_id="op-1",
        )
        self.assertTrue(result.verified)
        self.assertEqual(
            result.remote_percentage, request.requested_percentage
        )
        self.assertEqual(result.request_digest, request.digest())

    def test_verification_is_per_request_not_global(self):
        """25 verifies request A (asked for 25) and not request B (asked
        for 50), even though the observation is identical."""
        request_a = _request()
        request_b = _request(
            expected_current_percentage=25, observed_percentage=25,
            requested_percentage=50,
        )
        self.assertTrue(self._result(
            request_a, remote_percentage=25, verified=True).verified)
        with self.assertRaises(InvalidTrafficMutationRequest):
            self._result(request_b, remote_percentage=25, verified=True)
        self.assertFalse(self._result(
            request_b, remote_percentage=25, verified=False).verified)

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

    def test_invalid_operation_is_rejected(self):
        for operation in ("SET", "apply", "", "MUTATE", None, 1):
            with self.subTest(operation=operation):
                with self.assertRaises(InvalidTrafficMutationRequest):
                    self._result(operation=operation)

    def test_both_operations_are_accepted(self):
        for operation in TRAFFIC_MUTATION_OPERATIONS:
            with self.subTest(operation=operation):
                self.assertFalse(
                    self._result(operation=operation).verified
                )
        self.assertEqual(
            set(TRAFFIC_MUTATION_OPERATIONS), {OP_APPLY, OP_ROLLBACK}
        )

    def test_non_boolean_verified_is_rejected(self):
        for value in ("false", 0, 1, None):
            with self.subTest(value=value):
                with self.assertRaises(InvalidTrafficMutationRequest):
                    self._result(verified=value)

    def test_out_of_range_remote_percentage_is_rejected(self):
        for value in (-1, 101, 1000):
            with self.subTest(value=value):
                with self.assertRaises(InvalidTrafficMutationRequest):
                    self._result(remote_percentage=value, verified=False)

    def test_boolean_remote_percentage_is_rejected(self):
        with self.assertRaises(InvalidTrafficMutationRequest):
            self._result(remote_percentage=True, verified=False)

    def test_blank_provider_is_rejected(self):
        for provider in ("", "   ", None):
            with self.subTest(provider=provider):
                with self.assertRaises(InvalidTrafficMutationRequest):
                    self._result(provider=provider)

    def test_a_verified_result_cannot_be_attributed_to_the_unavailable_provider(self):
        with self.assertRaises(InvalidTrafficMutationRequest):
            self._result(
                provider=UNAVAILABLE_PROVIDER, remote_percentage=25,
                verified=True,
            )
        # …but an honest unverified result from it is expressible.
        result = self._result(
            provider=UNAVAILABLE_PROVIDER, remote_percentage=None,
            verified=False,
        )
        self.assertFalse(result.verified)

    def test_over_long_detail_is_rejected(self):
        with self.assertRaises(InvalidTrafficMutationRequest):
            self._result(detail="d" * 513)

    def test_audit_representation_exposes_the_required_fields(self):
        request = _request()
        result = self._result(
            request, remote_percentage=25, verified=True,
            external_operation_id="op-9", detail="observed 25% remote",
        )
        payload = result.to_dict()
        self.assertEqual(
            set(payload),
            {
                "provider", "request_digest", "operation",
                "remote_percentage", "expected_verified_percentage",
                "verified", "external_operation_id", "detail",
            },
        )
        self.assertEqual(payload["request_digest"], request.digest())
        self.assertEqual(len(payload["request_digest"]), 64)
        self.assertEqual(payload["verified"], True)
        self.assertEqual(payload["remote_percentage"], 25)
        # The record states what the verified claim was measured against.
        self.assertEqual(payload["expected_verified_percentage"], 25)
        import json
        self.assertEqual(json.loads(json.dumps(payload)), payload)

    def test_audit_representation_records_the_rollback_target(self):
        request = _request()  # 5 -> 25
        applied = self._result(
            request, operation=OP_APPLY, remote_percentage=25, verified=True
        )
        rolled = self._result(
            request, operation=OP_ROLLBACK, remote_percentage=5, verified=True
        )
        self.assertEqual(applied.to_dict()["expected_verified_percentage"], 25)
        self.assertEqual(rolled.to_dict()["expected_verified_percentage"], 5)
        self.assertNotEqual(
            applied.to_dict()["expected_verified_percentage"],
            rolled.to_dict()["expected_verified_percentage"],
        )
        # Both are bound to the same exact forward request.
        self.assertEqual(
            applied.to_dict()["request_digest"],
            rolled.to_dict()["request_digest"],
        )


class TrafficMutationOperationMatrixTests(unittest.TestCase):
    """The operation matrix, driven through the real classes.

    A request describes one forward transition (5 -> 25) and both
    operations complete that same request — APPLY from the near end,
    ROLLBACK from the far end:

        Forward request: 5% -> 25%
        APPLY    verified -> remote 25%
        ROLLBACK verified -> remote  5%

    Nothing here re-implements the contract in a test helper: every row
    builds an actual TrafficMutationResult bound to an actual
    TrafficMutationRequest and observes whether construction is allowed.
    """

    #: (operation, remote_percentage, verified, may_be_constructed)
    MATRIX = (
        # APPLY: verified only at the requested percentage.
        (OP_APPLY, 25, True, True),
        (OP_APPLY, 5, True, False),
        (OP_APPLY, 50, True, False),
        (OP_APPLY, 100, True, False),
        (OP_APPLY, 24, True, False),
        (OP_APPLY, 26, True, False),
        (OP_APPLY, None, True, False),
        # ROLLBACK: verified only at the state the transition started from.
        (OP_ROLLBACK, 5, True, True),
        (OP_ROLLBACK, 25, True, False),
        (OP_ROLLBACK, 50, True, False),
        (OP_ROLLBACK, 100, True, False),
        (OP_ROLLBACK, 0, True, False),
        (OP_ROLLBACK, None, True, False),
        # Unverified: any observed value, or none, for either operation.
        (OP_APPLY, None, False, True),
        (OP_APPLY, 0, False, True),
        (OP_APPLY, 5, False, True),
        (OP_APPLY, 25, False, True),
        (OP_APPLY, 50, False, True),
        (OP_ROLLBACK, None, False, True),
        (OP_ROLLBACK, 0, False, True),
        (OP_ROLLBACK, 5, False, True),
        (OP_ROLLBACK, 25, False, True),
        (OP_ROLLBACK, 50, False, True),
    )

    def test_operation_matrix(self):
        request = _request()  # 5 -> 25
        self.assertEqual(request.expected_current_percentage, 5)
        self.assertEqual(request.requested_percentage, 25)
        for operation, remote, verified, allowed in self.MATRIX:
            with self.subTest(operation=operation, remote=remote,
                              verified=verified):
                if allowed:
                    result = TrafficMutationResult.from_request(
                        request, provider="matrix-provider",
                        operation=operation, remote_percentage=remote,
                        verified=verified,
                    )
                    self.assertEqual(result.operation, operation)
                    self.assertEqual(result.remote_percentage, remote)
                    self.assertEqual(result.verified, verified)
                    self.assertIs(result.request, request)
                    self.assertEqual(result.request_digest, request.digest())
                else:
                    with self.assertRaises(InvalidTrafficMutationRequest):
                        TrafficMutationResult.from_request(
                            request, provider="matrix-provider",
                            operation=operation, remote_percentage=remote,
                            verified=verified,
                        )

    def test_matrix_rows_are_independently_meaningful(self):
        """Guard against a matrix that silently stops testing anything:
        each operation must have at least one accepted and one rejected
        verified row, and unverified rows must never be rejected."""
        for operation in TRAFFIC_MUTATION_OPERATIONS:
            verified_rows = [
                row for row in self.MATRIX
                if row[0] == operation and row[2] is True
            ]
            self.assertTrue(
                any(row[3] for row in verified_rows),
                f"{operation} has no accepted verified row",
            )
            self.assertTrue(
                any(not row[3] for row in verified_rows),
                f"{operation} has no rejected verified row",
            )
            self.assertTrue(
                all(row[3] for row in self.MATRIX
                    if row[0] == operation and row[2] is False),
                f"an unverified {operation} row was rejected",
            )

    def test_verified_rollback_can_be_represented(self):
        """The audit finding: before this correction, an honestly
        verified rollback was IMPOSSIBLE to express. It is now
        expressible, and it carries proof of what it observed."""
        request = _request()  # 5 -> 25
        result = TrafficMutationResult.from_request(
            request, provider="some-provider", operation=OP_ROLLBACK,
            remote_percentage=request.expected_current_percentage,
            verified=True, external_operation_id="op-rollback-1",
            detail="remote rejoined the 5% state",
        )
        self.assertTrue(result.verified)
        self.assertEqual(result.remote_percentage, 5)
        self.assertEqual(result.expected_verified_percentage, 5)
        self.assertEqual(result.operation, OP_ROLLBACK)
        self.assertEqual(
            result.request_digest, request.digest(),
            "the verified rollback is bound to the same exact request",
        )
        # …and the same request still refuses the wrong observation.
        with self.assertRaises(InvalidTrafficMutationRequest):
            TrafficMutationResult.from_request(
                request, provider="some-provider", operation=OP_ROLLBACK,
                remote_percentage=25, verified=True,
            )

    def test_apply_and_rollback_share_one_request_and_one_digest(self):
        request = _request()
        applied = TrafficMutationResult.from_request(
            request, provider="some-provider", operation=OP_APPLY,
            remote_percentage=25, verified=True,
        )
        rolled = TrafficMutationResult.from_request(
            request, provider="some-provider", operation=OP_ROLLBACK,
            remote_percentage=5, verified=True,
        )
        self.assertIs(applied.request, rolled.request)
        self.assertEqual(applied.request_digest, rolled.request_digest)
        self.assertEqual(applied.request_digest, request.digest())
        self.assertNotEqual(applied.operation, rolled.operation)
        self.assertNotEqual(
            applied.expected_verified_percentage,
            rolled.expected_verified_percentage,
        )

    def test_rollback_verification_target_is_derived_not_supplied(self):
        """No path lets a caller name its own rollback target: the target
        is a property of the bound request, and neither construction
        path has a parameter for it."""
        for constructor in (
            TrafficMutationResult,
            TrafficMutationResult.from_request,
        ):
            parameters = set(inspect.signature(constructor).parameters)
            for forbidden in (
                "request_digest", "rollback_target", "target_percentage",
                "expected_percentage",
            ):
                with self.subTest(constructor=constructor,
                                  parameter=forbidden):
                    self.assertNotIn(forbidden, parameters)
        with self.assertRaises(TypeError):
            TrafficMutationResult.from_request(
                _request(), provider="some-provider", operation=OP_ROLLBACK,
                remote_percentage=5, verified=True,
                rollback_target=5,
            )

    def test_the_derived_target_tracks_a_different_request(self):
        """A request for 25 -> 50 moves both ends of the matrix."""
        request = _request(
            expected_current_percentage=25, observed_percentage=25,
            requested_percentage=50,
        )
        applied = TrafficMutationResult.from_request(
            request, provider="some-provider", operation=OP_APPLY,
            remote_percentage=50, verified=True,
        )
        rolled = TrafficMutationResult.from_request(
            request, provider="some-provider", operation=OP_ROLLBACK,
            remote_percentage=25, verified=True,
        )
        self.assertEqual(applied.expected_verified_percentage, 50)
        self.assertEqual(rolled.expected_verified_percentage, 25)
        for operation, remote in ((OP_APPLY, 25), (OP_ROLLBACK, 50)):
            with self.subTest(operation=operation, remote=remote):
                with self.assertRaises(InvalidTrafficMutationRequest):
                    TrafficMutationResult.from_request(
                        request, provider="some-provider",
                        operation=operation, remote_percentage=remote,
                        verified=True,
                    )

    def test_unverified_rollback_may_report_any_observed_state(self):
        """An honest "we looked, and it is not where we expected" result
        stays representable for rollback too."""
        request = _request()
        for remote in (None, 5, 25, 50):
            with self.subTest(remote=remote):
                result = TrafficMutationResult.from_request(
                    request, provider="some-provider", operation=OP_ROLLBACK,
                    remote_percentage=remote, verified=False,
                )
                self.assertFalse(result.verified)
                self.assertEqual(result.remote_percentage, remote)


class ExpectedVerifiedPercentageTests(unittest.TestCase):
    """The operation-aware target is one explicit, reusable concept."""

    def test_apply_targets_the_requested_percentage(self):
        self.assertEqual(
            expected_verified_percentage(OP_APPLY, _request()), 25
        )

    def test_rollback_targets_the_expected_current_percentage(self):
        self.assertEqual(
            expected_verified_percentage(OP_ROLLBACK, _request()), 5
        )

    def test_target_is_read_from_the_request_alone(self):
        request = _request(
            expected_current_percentage=50, observed_percentage=50,
            requested_percentage=100,
        )
        self.assertEqual(expected_verified_percentage(OP_APPLY, request), 100)
        self.assertEqual(
            expected_verified_percentage(OP_ROLLBACK, request), 50
        )

    def test_invalid_operation_has_no_target(self):
        for operation in ("SET", "apply", "", "MUTATE", None, 1):
            with self.subTest(operation=operation):
                with self.assertRaises(InvalidTrafficMutationRequest):
                    expected_verified_percentage(operation, _request())

    def test_the_operation_vocabulary_stays_two_valued(self):
        self.assertEqual(
            set(TRAFFIC_MUTATION_OPERATIONS), {OP_APPLY, OP_ROLLBACK}
        )
        for operation in TRAFFIC_MUTATION_OPERATIONS:
            with self.subTest(operation=operation):
                self.assertIn(
                    expected_verified_percentage(operation, _request()),
                    (5, 25),
                )

    def test_result_property_agrees_with_the_function(self):
        request = _request()
        for operation in TRAFFIC_MUTATION_OPERATIONS:
            with self.subTest(operation=operation):
                result = TrafficMutationResult.from_request(
                    request, provider="some-provider", operation=operation,
                    remote_percentage=None, verified=False,
                )
                self.assertEqual(
                    result.expected_verified_percentage,
                    expected_verified_percentage(operation, request),
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
        request = _request()
        provider = RecordingMutationProvider(
            result=TrafficMutationResult.from_request(
                request,
                provider="recording",
                operation=OP_APPLY,
                remote_percentage=None,
                verified=False,
            )
        )
        result = provider.apply(request)
        self.assertEqual(provider.apply_calls, [request])
        self.assertEqual(provider.apply_calls[0].digest(), request.digest())
        # The provider's answer is bound to the same exact request.
        self.assertIs(result.request, provider.apply_calls[0])
        self.assertEqual(result.request_digest, request.digest())


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

        class NonCallableSurface:
            apply = 5

            def rollback(self, request):  # pragma: no cover
                raise AssertionError

        self.assertFalse(is_traffic_mutation_port(BroadenedProvider()))
        self.assertFalse(is_traffic_mutation_port(IncompleteProvider()))
        self.assertFalse(is_traffic_mutation_port(NonCallableSurface()))
        self.assertTrue(is_traffic_mutation_port(RecordingMutationProvider()))

    def test_structural_witness_rejects_every_forbidden_verb(self):
        for verb in FORBIDDEN_PORT_MEMBERS:
            with self.subTest(verb=verb):
                broadened = type(
                    "Broadened",
                    (),
                    {
                        "apply": lambda self, request: None,
                        "rollback": lambda self, request: None,
                        verb: lambda self, *args: None,
                    },
                )
                self.assertFalse(is_traffic_mutation_port(broadened()))

    def test_structural_witness_claim_is_exactly_what_it_proves(self):
        """The helper rejects extra public CALLABLES. It says nothing
        about non-callable public data, and does not claim to — the
        default provider's own ``provider_name`` is such an attribute."""
        class WithPublicData:
            provider_name = "a-provider"

            def apply(self, request):  # pragma: no cover - never called
                raise AssertionError

            def rollback(self, request):  # pragma: no cover
                raise AssertionError

        self.assertTrue(is_traffic_mutation_port(WithPublicData()))
        self.assertEqual(
            UnavailableTrafficMutationProvider.provider_name,
            UNAVAILABLE_PROVIDER,
        )
        self.assertTrue(
            is_traffic_mutation_port(UnavailableTrafficMutationProvider()),
            "the default provider's public data attribute is not mechanism",
        )

    def test_reachability_and_the_structural_witness_agree_by_default(self):
        provider = UnavailableTrafficMutationProvider()
        self.assertIsInstance(provider, TrafficMutationPort)
        self.assertTrue(is_traffic_mutation_port(provider))
        self.assertFalse(isinstance(object(), TrafficMutationPort))

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
