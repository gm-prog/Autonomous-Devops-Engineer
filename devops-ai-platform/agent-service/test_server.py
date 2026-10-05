import json
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from server import RcaRequest, analyze_rca


class FakeLLM:
    def generate_remediation(self, prompt, system_instruction):
        return json.dumps(
            {
                "root_cause": "Latency breach coincides with failed deployment health checks.",
                "confidence": 0.8,
                "supporting_evidence_ids": ["ev-1"],
                "contributing_factors": ["deployment health check failure"],
                "recommended_next_actions": ["inspect the failed deployment"],
            }
        )


class RcaEndpointTests(unittest.TestCase):
    def test_rca_requires_evidence_grounded_ids(self):
        pack = {
            "incident": {"id": "inc-1"},
            "evidence": {
                "timeline": [
                    {
                        "evidence_id": "ev-1",
                        "kind": "threshold_breach",
                        "source": "monitoring-service",
                        "observed_at": "2026-09-23T10:00:00+00:00",
                    }
                ]
            },
        }

        with patch("server.llm", FakeLLM()):
            body = analyze_rca(RcaRequest(evidence_pack=pack))

        self.assertEqual(body["supporting_evidence_ids"], ["ev-1"])
        self.assertEqual(body["confidence"], 0.8)

    def test_rca_rejects_unknown_supporting_evidence(self):
        pack = {
            "incident": {"id": "inc-1"},
            "evidence": {"timeline": [{"evidence_id": "ev-1"}]},
        }

        class InvalidLLM(FakeLLM):
            def generate_remediation(self, prompt, system_instruction):
                result = json.loads(super().generate_remediation(prompt, system_instruction))
                result["supporting_evidence_ids"] = ["not-in-pack"]
                return json.dumps(result)

        with patch("server.llm", InvalidLLM()):
            with self.assertRaises(HTTPException) as context:
                analyze_rca(RcaRequest(evidence_pack=pack))

        self.assertEqual(context.exception.status_code, 502)


if __name__ == "__main__":
    unittest.main()
