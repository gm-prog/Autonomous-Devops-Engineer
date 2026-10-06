"""Agent-service RCA boundary tests (Phase 8.4 §5/§6, 8.4.1 §19).

Proves the exact contract ``RcaAgentClient`` calls:
POST /api/internal/analyze-rca — deterministic mode returns a
schema-valid result citing only real pack ids and carrying the
fixture-owned remediation draft (validated through the incident
service's own ``parse_rca_result``), and every non-E2E configuration
fails closed with 503 (never a silent substitution).

Phase 8.4.1 §19: the deterministic conclusion is conditional on real
evidence semantics — a pack without the validated checkout-service
breach (wrong service, wrong metric, missing/non-breaching numbers,
missing signals, ambiguous signals) must return 422.
"""

import copy
import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from agent_service.main import app
from agent_service.application.deterministic_rca import (
    DETERMINISTIC_ROOT_CAUSE,
    E2E_PATCHED_SERVICE_NAME,
    E2E_TARGET_FILE,
)
from incident_service.application.services.rca_analyzer import (
    InvalidRcaResult,
    parse_rca_result,
)

client = TestClient(app)

ENDPOINT = "/api/internal/analyze-rca"

# Real-shaped pack mirroring RcaEvidencePackBuilder.build() output for
# the single controlled staging scenario (§6): checkout-service /
# cpu_percent observed 97.0 against the configured danger limit 90.0.
_PACK = {
    "pack_version": "1.0",
    "incident": {
        "id": "inc-e2e-1",
        "title": "checkout-service cpu breach",
        "severity": "HIGH",
        "status": "Investigating",
        "created_at": "2026-10-06T00:00:00+00:00",
    },
    "evidence": {
        "count": 2,
        "sources": {"monitoring-service": 1, "deployment-service": 1},
        "kinds": {"threshold_breach": 1, "deployment_run": 1},
        "timeline": [
            {
                "evidence_id": "ev-threshold-1",
                "kind": "threshold_breach",
                "source": "monitoring-service",
                "observed_at": "2026-10-06T00:00:01+00:00",
            },
            {
                "evidence_id": "ev-deployment-2",
                "kind": "deployment_run",
                "source": "deployment-service",
                "observed_at": "2026-10-06T00:00:02+00:00",
            },
        ],
    },
    "signals": {
        "threshold_breaches": [
            {
                "evidence_id": "ev-threshold-1",
                "observed_at": "2026-10-06T00:00:01+00:00",
                "service": "checkout-service",
                "metric": "cpu_percent",
                "value": 97.0,
                "threshold": 90.0,
                "operator": ">",
                "severity": "HIGH",
                "breach_count": 1,
            }
        ],
        "deployment_runs": [
            {
                "evidence_id": "ev-deployment-2",
                "observed_at": "2026-10-06T00:00:02+00:00",
                "deployment_run_id": "run-e2e-1",
                "repository_id": 42,
                "repository_name": "acme/checkout",
                "source_revision": {"head_sha": "a" * 40, "commits": []},
                "state": "DEPLOYED",
            }
        ],
    },
}

VALID_IDS = {"ev-threshold-1", "ev-deployment-2"}


def _pack_with(**signal_overrides):
    pack = copy.deepcopy(_PACK)
    signal = pack["signals"]["threshold_breaches"][0]
    signal.update(signal_overrides)
    return pack


def _post(pack, env="true"):
    with patch.dict(os.environ, {"E2E_DETERMINISTIC_RCA": env}):
        return client.post(ENDPOINT, json={"evidence_pack": pack})


class AnalyzeRcaContractTests(unittest.TestCase):
    def test_request_requires_evidence_pack_object(self):
        response = client.post(ENDPOINT, json={})
        self.assertEqual(response.status_code, 422, response.text)

        response = client.post(ENDPOINT, json={"evidence_pack": ["not", "an", "object"]})
        self.assertEqual(response.status_code, 422, response.text)

    def test_fails_closed_outside_e2e_deterministic_mode(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("E2E_DETERMINISTIC_RCA", None)
            response = client.post(ENDPOINT, json={"evidence_pack": _PACK})

        self.assertEqual(response.status_code, 503, response.text)
        self.assertIn("no RCA provider configured", response.json()["detail"])

        # explicit opt-out value is equally fail-closed (Suite G)
        response = _post(_PACK, env="false")
        self.assertEqual(response.status_code, 503, response.text)

    def test_deterministic_mode_returns_schema_valid_rca_with_actionable_draft(self):
        response = _post(_PACK)
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()

        # Schema validation through the incident service's canonical parser.
        rca, draft = parse_rca_result(
            result,
            incident_id="inc-e2e-1",
            valid_evidence_ids=VALID_IDS,
        )
        self.assertEqual(rca.root_cause, DETERMINISTIC_ROOT_CAUSE)
        self.assertEqual(rca.evidence_refs, ["ev-threshold-1", "ev-deployment-2"])
        self.assertEqual(
            result["supporting_evidence_ids"], result["evidence_refs"]
        )
        self.assertGreaterEqual(rca.confidence, 0.0)
        self.assertLessEqual(rca.confidence, 1.0)

        # Phase 8.4.1: actionable, fixture-owned remediation draft
        self.assertIsNotNone(draft)
        self.assertEqual(draft["target_file"], E2E_TARGET_FILE)
        self.assertEqual(draft["risk_class"], "LOW")
        self.assertTrue(draft["validation_plan"])
        self.assertIn("--- a/src/service_config.py", draft["patch"])
        self.assertIn(
            f'+SERVICE_NAME = "{E2E_PATCHED_SERVICE_NAME}"', draft["patch"]
        )

        # Foreign citations are impossible: every ref is a pack id, and
        # the parser rejects the result for ids outside the incident.
        self.assertTrue(set(result["evidence_refs"]) <= VALID_IDS)
        with self.assertRaises(InvalidRcaResult):
            parse_rca_result(
                result,
                incident_id="inc-e2e-1",
                valid_evidence_ids={"only-this-one"},
            )

    def test_invalid_pack_shapes_are_rejected_not_guessed(self):
        cases = [
            {"incident_id": "x"},  # no evidence/signals keys
            {"evidence": {"timeline": []}},  # empty timeline
            {"evidence": {"timeline": [{"kind": "threshold"}]}},  # missing id
            {**_PACK, "signals": {}},  # signals not an object
            {**_PACK, "signals": {"threshold_breaches": []}},  # no breaches
            {**_PACK, "signals": None},  # signals null
        ]
        for pack in cases:
            with self.subTest(pack=list(pack)[:2]):
                response = _post(pack)
                self.assertEqual(response.status_code, 422, response.text)

    def test_response_contains_no_secret_material(self):
        response = _post(_PACK)
        body = response.text
        for marker in ("Bearer ", "ghp_", "PRIVATE KEY", "password", "JWT_SECRET"):
            self.assertNotIn(marker, body)


class SemanticBreachValidationTests(unittest.TestCase):
    """Suite A (§19): the conclusion is conditional on breach semantics."""

    def _assert_rejected(self, pack, note=""):
        response = _post(pack)
        self.assertEqual(
            response.status_code, 422, f"{note}: {response.status_code} {response.text}"
        )

    def test_non_breach_value_equal_to_threshold_fails_closed(self):
        self._assert_rejected(_pack_with(value=90.0), "equal")

    def test_non_breach_value_below_threshold_fails_closed(self):
        self._assert_rejected(_pack_with(value=85.0), "below")

    def test_wrong_service_fails_closed(self):
        self._assert_rejected(_pack_with(service="billing-service"), "service")

    def test_wrong_metric_fails_closed(self):
        self._assert_rejected(_pack_with(metric="memory_percent"), "metric")

    def test_missing_numeric_value_fails_closed(self):
        self._assert_rejected(_pack_with(value="N/A"), "value-str")
        self._assert_rejected(_pack_with(value=None), "value-none")

    def test_missing_or_unusable_threshold_fails_closed(self):
        self._assert_rejected(_pack_with(threshold="N/A"), "threshold")
        self._assert_rejected(_pack_with(threshold=None), "threshold-none")

    def test_missing_signals_structure_fails_closed(self):
        pack = copy.deepcopy(_PACK)
        del pack["signals"]
        self._assert_rejected(pack, "signals-missing")

        pack = copy.deepcopy(_PACK)
        del pack["signals"]["threshold_breaches"]
        self._assert_rejected(pack, "breaches-missing")

    def test_missing_timeline_fails_closed(self):
        pack = copy.deepcopy(_PACK)
        del pack["evidence"]["timeline"]
        self._assert_rejected(pack, "timeline-missing")

    def test_empty_ids_fail_closed(self):
        pack = copy.deepcopy(_PACK)
        pack["evidence"]["timeline"][0]["evidence_id"] = " "
        self._assert_rejected(pack, "empty-id")

    def test_signal_id_outside_timeline_fails_closed(self):
        self._assert_rejected(
            _pack_with(evidence_id="ev-from-another-incident"), "foreign-signal-id"
        )

    def test_ambiguous_scenario_signals_fail_closed(self):
        pack = copy.deepcopy(_PACK)
        duplicate = copy.deepcopy(pack["signals"]["threshold_breaches"][0])
        duplicate["evidence_id"] = "ev-threshold-dup"
        pack["signals"]["threshold_breaches"].append(duplicate)
        pack["evidence"]["timeline"].append(
            {
                "evidence_id": "ev-threshold-dup",
                "kind": "threshold_breach",
                "source": "monitoring-service",
                "observed_at": "2026-10-06T00:00:03+00:00",
            }
        )
        self._assert_rejected(pack, "ambiguous")

    def test_foreign_citation_cannot_appear_in_result(self):
        response = _post(_PACK)
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertTrue(result["evidence_refs"])
        self.assertTrue(set(result["evidence_refs"]) <= set(
            item["evidence_id"] for item in _PACK["evidence"]["timeline"]
        ))
        # a caller-supplied citation field outside evidence_pack is ignored
        with patch.dict(os.environ, {"E2E_DETERMINISTIC_RCA": "true"}):
            response = client.post(
                ENDPOINT,
                json={
                    "evidence_pack": _PACK,
                    "evidence_refs": ["ev-made-up-99"],
                },
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn("ev-made-up-99", response.text)


if __name__ == "__main__":
    unittest.main()
