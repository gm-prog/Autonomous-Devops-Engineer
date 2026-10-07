
"""Phase 8.7-A traffic-mutation boundary tests.

These tests prove the boundary can be introduced without opening a write path:
the default provider always fails closed, the request is tightly bound to one
TrafficIntent, rollback is distinct from forward promotion, and no
provider-specific execution surface is accepted.
"""

import ast
import os
import unittest
from datetime import datetime, timezone

from incident_service.application.services.rollout_plan_service import TrafficIntent
from incident_service.application.services.traffic_mutation_boundary import (
    InvalidTrafficMutationRequest,
    TrafficMutationPort,
    TrafficMutationProviderUnavailable,
    TrafficMutationResult,
    UnavailableTrafficMutationProvider,
    mutation_request_from_intent,
)


UTC = timezone.utc
NOW = datetime(2026, 10, 7, 18, 0, tzinfo=UTC)
SHA = "a" * 40


def _intent(**overrides):
    values = {
        "intent_id": "ti_test",
        "deployment_run_id": "run-1",
        "source_sha": SHA,
        "gate_evaluation_id": "eval-1",
        "stable_target": "svc-stable",
        "canary_target": "svc-canary",
        "current_percentage": 5,
        "requested_percentage": 25,
        "created_at": NOW,
        "evaluated_at": NOW,
    }
    values.update(overrides)
    return TrafficIntent(**values)


class TrafficMutationRequestTests(unittest.TestCase):
    def test_exact_intent_round_trips_with_stable_digest(self):
        intent = _intent()
        first = mutation_request_from_intent(intent, observed_percentage=5, observed_at=NOW)
        second = mutation_request_from_intent(intent, observed_percentage=5, observed_at=NOW)
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(first.digest(), second.digest())
        self.assertEqual(first.requested_percentage, 25)
        self.assertEqual(first.expected_current_percentage, 5)

    def test_targets_are_required_and_must_come_from_the_intent(self):
        with self.assertRaises(InvalidTrafficMutationRequest):
            mutation_request_from_intent(_intent(stable_target=None), observed_percentage=5, observed_at=NOW)
        with self.assertRaises(InvalidTrafficMutationRequest):
            mutation_request_from_intent(_intent(canary_target=""), observed_percentage=5, observed_at=NOW)

    def test_observed_state_must_match_expected_current_state(self):
        with self.assertRaises(InvalidTrafficMutationRequest):
            mutation_request_from_intent(_intent(), observed_percentage=25, observed_at=NOW)

    def test_forward_mutation_never_uses_a_lower_target(self):
        with self.assertRaises(InvalidTrafficMutationRequest):
            mutation_request_from_intent(_intent(requested_percentage=0), observed_percentage=5, observed_at=NOW)

    def test_noop_mutation_is_rejected_by_the_write_contract(self):
        with self.assertRaises(InvalidTrafficMutationRequest):
            mutation_request_from_intent(_intent(requested_percentage=5), observed_percentage=5, observed_at=NOW)

    def test_source_sha_is_canonical_and_lowercase(self):
        with self.assertRaises(InvalidTrafficMutationRequest):
            mutation_request_from_intent(_intent(source_sha=SHA.upper()), observed_percentage=5, observed_at=NOW)
        with self.assertRaises(InvalidTrafficMutationRequest):
            mutation_request_from_intent(_intent(source_sha="short"), observed_percentage=5, observed_at=NOW)


class DefaultProviderTests(unittest.TestCase):
    def setUp(self):
        self.provider = UnavailableTrafficMutationProvider()
        self.request = mutation_request_from_intent(_intent(), observed_percentage=5, observed_at=NOW)

    def test_apply_fails_closed(self):
        with self.assertRaises(TrafficMutationProviderUnavailable):
            self.provider.apply(self.request)

    def test_rollback_fails_closed(self):
        with self.assertRaises(TrafficMutationProviderUnavailable):
            self.provider.rollback(self.request)


class ResultContractTests(unittest.TestCase):
    def test_result_is_explicitly_unverified_until_remote_state_is_checked(self):
        result = TrafficMutationResult(
            provider="fixture",
            request_digest="b" * 64,
            operation="APPLY",
            remote_percentage=25,
            verified=False,
            external_operation_id="op-1",
        )
        self.assertFalse(result.verified)

    def test_invalid_operation_is_rejected(self):
        with self.assertRaises(InvalidTrafficMutationRequest):
            TrafficMutationResult(
                provider="fixture",
                request_digest="b" * 64,
                operation="EXECUTE",
                remote_percentage=25,
                verified=False,
                external_operation_id=None,
            )


class StructuralBoundaryTests(unittest.TestCase):
    def test_protocol_exposes_only_apply_and_rollback_writes(self):
        public = {name for name in dir(TrafficMutationPort) if not name.startswith("_")}
        self.assertEqual(public, {"apply", "rollback"})
        self.assertNotIn("kubectl", public)
        self.assertNotIn("subprocess", public)

    def test_boundary_module_has_no_process_or_http_write_imports(self):
        path = os.path.join(os.path.dirname(__file__), "traffic_mutation_boundary.py")
        with open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=path)
        forbidden_modules = {"subprocess", "requests", "httpx", "boto3", "google.cloud", "kubernetes"}
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertTrue(forbidden_modules.isdisjoint(imported), imported)


if __name__ == "__main__":
    unittest.main()
