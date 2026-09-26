"""Contract test for GET /api/internal/deployments/{run_id}.

The incident-service evidence collector reads this endpoint to turn a
deployment run into incident evidence (repository identity + immutable source
revision), which is what the remediation target binding later enforces. The
record must come from the real deployment run store - never be synthesized.
"""

import unittest

from deployment_service import main as deployment_main


class _FakeRunStore:
    """Deterministic stand-in for RedisPipelineStore (same get() contract)."""

    def __init__(self):
        self.runs = {}

    def get(self, run_id):
        return self.runs.get(run_id)


class InternalDeploymentApiTests(unittest.TestCase):
    def setUp(self):
        self.store = _FakeRunStore()
        self._original_store = deployment_main.engine.store
        deployment_main.engine.store = self.store
        self.addCleanup(self._restore)

    def _restore(self):
        deployment_main.engine.store = self._original_store

    def test_known_run_returns_full_evidence_payload(self):
        from fastapi.testclient import TestClient

        self.store.runs["run-42"] = {
            "id": "run-42",
            "repository_id": 7,
            "repository_name": "acme/checkout",
            "source_revision": {"head_sha": "a" * 40, "commits": []},
            "state": "DEPLOYED",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:05:00Z",
        }

        resp = TestClient(deployment_main.app).get(
            "/api/internal/deployments/run-42"
        )

        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["id"], "run-42")
        self.assertEqual(body["repository_name"], "acme/checkout")
        # exact 40-hex source revision: what incident binding validates against
        self.assertEqual(body["source_revision"]["head_sha"], "a" * 40)
        self.assertEqual(body["state"], "DEPLOYED")

    def test_unknown_run_is_404_not_synthesized(self):
        from fastapi.testclient import TestClient

        resp = TestClient(deployment_main.app).get(
            "/api/internal/deployments/run-missing"
        )
        self.assertEqual(resp.status_code, 404)

    def test_collector_payload_shape_matches_normalized_evidence(self):
        """The endpoint payload must contain every field the incident
        collector normalizes into deployment_run evidence."""
        from incident_service.infrastructure.deployment.deployment_evidence_collector import (
            DeploymentEvidenceCollector,
        )
        from unittest.mock import patch, MagicMock

        payload = {
            "id": "run-7",
            "repository_id": 7,
            "repository_name": "acme/checkout",
            "source_revision": {"head_sha": "b" * 40, "commits": []},
            "state": "DEPLOYED",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:05:00Z",
            "artifact_hash": "c" * 64,
            "plan_hash": "d" * 64,
            "approval": {"approved_by": "ops", "approved_at": "2026-01-01T00:01:00Z"},
            "health_check": {"status": "PASS"},
            "rollback": {"status": "NOT_REQUIRED"},
            "error": None,
        }

        response = MagicMock()
        response.__enter__ = lambda s: response
        response.__exit__ = lambda s, *a: False
        response.getcode.return_value = 200
        import json as _json
        response.read.return_value = _json.dumps(payload).encode("utf-8")

        with patch(
            "incident_service.infrastructure.deployment."
            "deployment_evidence_collector.urlopen",
            return_value=response,
        ) as urlopen:
            evidence = DeploymentEvidenceCollector(
                base_url="http://deployment-service:8030"
            ).collect("run-7")

        self.assertEqual(evidence.kind, "deployment_run")
        self.assertEqual(evidence.payload["repository_name"], "acme/checkout")
        self.assertEqual(evidence.payload["source_revision"]["head_sha"], "b" * 40)
        requested_url = urlopen.call_args[0][0].full_url
        self.assertEqual(
            requested_url,
            "http://deployment-service:8030/api/internal/deployments/run-7",
        )


if __name__ == "__main__":
    unittest.main()
