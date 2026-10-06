"""Agent-service RCA boundary tests (Phase 8.4 §5/§6).

Proves the exact contract ``RcaAgentClient`` calls:
POST /api/internal/analyze-rca — deterministic mode returns a
schema-valid result citing only real pack ids (validated through the
incident service's own ``parse_rca_result``), and every non-E2E
configuration fails closed with 503 (never a silent substitution).
"""

import unittest

from fastapi.testclient import TestClient

from agent_service.main import app
from agent_service.application.deterministic_rca import DETERMINISTIC_ROOT_CAUSE
from incident_service.application.services.rca_analyzer import (
    InvalidRcaResult,
    parse_rca_result,
)

client = TestClient(app)

ENDPOINT = "/api/internal/analyze-rca"

_PACK = {
    "incident_id": "inc-e2e-1",
    "evidence": {
        "timeline": [
            {"evidence_id": "ev-threshold-1", "kind": "threshold"},
            {"evidence_id": "ev-deployment-2", "kind": "deployment_run"},
        ],
    },
}


class AnalyzeRcaContractTests(unittest.TestCase):
    def test_request_requires_evidence_pack_object(self):
        response = client.post(ENDPOINT, json={})
        self.assertEqual(response.status_code, 422, response.text)

        response = client.post(ENDPOINT, json={"evidence_pack": ["not", "an", "object"]})
        self.assertEqual(response.status_code, 422, response.text)

    def test_fails_closed_outside_e2e_deterministic_mode(self):
        import os
        from unittest.mock import patch

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("E2E_DETERMINISTIC_RCA", None)
            response = client.post(ENDPOINT, json={"evidence_pack": _PACK})
        self.assertEqual(response.status_code, 503, response.text)
        self.assertIn("no RCA provider configured", response.json()["detail"])

    def test_deterministic_mode_returns_schema_valid_rca_citing_real_pack_ids(self):
        import os
        from unittest.mock import patch

        with patch.dict(os.environ, {"E2E_DETERMINISTIC_RCA": "true"}):
            response = client.post(ENDPOINT, json={"evidence_pack": _PACK})
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()

        # Schema validation through the incident service's canonical parser.
        rca, draft = parse_rca_result(
            result,
            incident_id="inc-e2e-1",
            valid_evidence_ids={"ev-threshold-1", "ev-deployment-2"},
        )
        self.assertIsNone(draft)
        self.assertEqual(rca.root_cause, DETERMINISTIC_ROOT_CAUSE)
        self.assertEqual(rca.evidence_refs, ["ev-threshold-1", "ev-deployment-2"])
        self.assertEqual(
            result["supporting_evidence_ids"], result["evidence_refs"]
        )
        self.assertGreaterEqual(rca.confidence, 0.0)
        self.assertLessEqual(rca.confidence, 1.0)

        # Foreign citations are impossible: parser must reject if ids don't exist.
        with self.assertRaises(InvalidRcaResult):
            parse_rca_result(
                result,
                incident_id="inc-e2e-1",
                valid_evidence_ids={"only-this-one"},
            )

    def test_invalid_pack_shapes_are_rejected_not_guessed(self):
        import os
        from unittest.mock import patch

        cases = [
            {"incident_id": "x"},  # no evidence key
            {"evidence": {"timeline": []}},  # empty timeline
            {"evidence": {"timeline": [{"kind": "threshold"}]}},  # missing id
        ]
        with patch.dict(os.environ, {"E2E_DETERMINISTIC_RCA": "true"}):
            for pack in cases:
                with self.subTest(pack=pack):
                    response = client.post(ENDPOINT, json={"evidence_pack": pack})
                    self.assertEqual(response.status_code, 422, response.text)

    def test_response_contains_no_secret_material(self):
        import os
        from unittest.mock import patch

        with patch.dict(os.environ, {"E2E_DETERMINISTIC_RCA": "true"}):
            response = client.post(ENDPOINT, json={"evidence_pack": _PACK})
        body = response.text
        for marker in ("Bearer ", "ghp_", "PRIVATE KEY", "password", "JWT_SECRET"):
            self.assertNotIn(marker, body)
