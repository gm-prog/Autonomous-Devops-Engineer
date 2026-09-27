"""Schema-constrained RCA provider output (§11) — fail-closed matrix."""

import unittest

from incident_service.application.failures import InvalidRcaResult
from incident_service.application.services.rca_analyzer import (
    parse_rca_result,
)

VALID = {
    "root_cause": "connection leak introduced by deployment run-7",
    "confidence": 0.91,
    "contributing_factors": ["elevated pool wait time"],
    "evidence_refs": ["evt-1", "deploy-1"],
    "uncertainty": ["rollout overlap window unobserved"],
    "methodology": "timeline diffing",
}
VALID_IDS = {"evt-1", "deploy-1"}


def _parse(result, valid_ids=None):
    return parse_rca_result(
        result,
        incident_id="inc-1",
        valid_evidence_ids=set(valid_ids if valid_ids is not None else VALID_IDS),
    )


class RcaSchemaTests(unittest.TestCase):
    def test_valid_result_parses_into_typed_rca(self):
        rca, draft = _parse(dict(VALID))
        self.assertEqual(rca.incident_id, "inc-1")
        self.assertEqual(rca.root_cause, VALID["root_cause"])
        self.assertAlmostEqual(rca.confidence, 0.91)
        self.assertEqual(rca.evidence_refs, ["evt-1", "deploy-1"])
        self.assertEqual(rca.methodology, "timeline diffing")
        self.assertIsNone(draft)
        payload = rca.to_payload()
        self.assertEqual(payload["evidence_refs"], ["evt-1", "deploy-1"])
        # legacy alias carries the same list
        self.assertEqual(payload["supporting_evidence_ids"], ["evt-1", "deploy-1"])

    def test_legacy_alias_supporting_evidence_ids_is_accepted(self):
        legacy = dict(VALID)
        legacy.pop("evidence_refs")
        legacy["supporting_evidence_ids"] = ["evt-1"]
        rca, _ = _parse(legacy)
        self.assertEqual(rca.evidence_refs, ["evt-1"])

    def test_missing_methodology_gets_honest_default(self):
        legacy = dict(VALID)
        legacy.pop("methodology")
        rca, _ = _parse(legacy)
        self.assertIn("methodology not stated", rca.methodology)

    def test_malformed_results_are_rejected(self):
        cases = [
            "not-a-dict",
            {**VALID, "root_cause": 42},
            {**VALID, "root_cause": ""},
            {**VALID, "confidence": "high"},
            {**VALID, "confidence": 1.5},
            {**VALID, "confidence": -0.1},
            {**VALID, "confidence": True},
            {**VALID, "contributing_factors": "many"},
            {**VALID, "evidence_refs": []},
            {**VALID, "evidence_refs": ["evt-1", "ghost"]},
            {**VALID, "evidence_refs": None},
            {**VALID, "uncertainty": [1]},
            {**VALID, "root_cause": "x" * 5000},
        ]
        for result in cases:
            with self.subTest(value=str(result)[:80]):
                with self.assertRaises(InvalidRcaResult):
                    _parse(dict(result) if isinstance(result, dict) else result)

        with self.assertRaises(InvalidRcaResult) as ctx:
            _parse({**VALID, "confidence": 1.5})
        self.assertIn("[0, 1]", str(ctx.exception))

    def test_evidence_reference_must_exist_on_incident(self):
        with self.assertRaises(InvalidRcaResult) as ctx:
            _parse({**VALID, "evidence_refs": ["evt-1", "other-incident-ev"]})
        self.assertIn("do not belong", str(ctx.exception))

    def test_draft_parsing_happy_and_fail_closed(self):
        draft = {
            "target_file": "app/pool.py",
            "patch": "--- a/app/pool.py\n+++ b/app/pool.py\n@@ -1 +1 @@\n-a\n+b\n",
            "validation_plan": ["pytest -q"],
        }
        rca, parsed = _parse({**VALID, "remediation_draft": draft})
        self.assertEqual(parsed["target_file"], "app/pool.py")
        self.assertIsNone(parsed["risk_class"])

        bad_cases = [
            {**draft, "target_file": ""},
            {**draft, "patch": ""},
            {**draft, "validation_plan": []},
            {**draft, "repository": "evil/repo"},          # §14 smuggle attempt
            {**draft, "source_sha": "f" * 40},             # §14 smuggle attempt
            {**draft, "approved_by": "attacker"},          # §14 smuggle attempt
            {**draft, "risk_class": "CRITICAL"},
            "not-a-dict",
        ]
        for bad in bad_cases:
            with self.subTest(bad=str(bad)[:80]):
                with self.assertRaises(InvalidRcaResult):
                    _parse({**VALID, "remediation_draft": bad})


if __name__ == "__main__":
    unittest.main()
