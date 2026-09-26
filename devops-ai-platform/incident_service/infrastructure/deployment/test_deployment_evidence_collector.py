import io
import json
import unittest
from unittest.mock import patch

from incident_service.infrastructure.deployment.deployment_evidence_collector import (
    DeploymentEvidenceCollector,
    DeploymentEvidenceCollectorError,
)


class FakeResponse:
    def __init__(self, payload, status=200):
        self.payload = json.dumps(payload).encode("utf-8")
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def getcode(self):
        return self.status

    def read(self):
        return self.payload


class DeploymentEvidenceCollectorTests(unittest.TestCase):
    @patch("incident_service.infrastructure.deployment.deployment_evidence_collector.urlopen")
    def test_collects_bounded_deployment_metadata(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse({
            "id": "run_123",
            "repository_id": 7,
            "repository_name": "checkout-api",
            "source_revision": {"head_sha": "abc123", "commits": [], "summary": {"commit_count": 0, "files_changed": 0, "additions": 0, "deletions": 0}},
            "state": "DEPLOYED",
            "created_at": "2026-09-23T10:00:00+00:00",
            "updated_at": "2026-09-23T10:05:00+00:00",
            "artifact_hash": "a" * 64,
            "plan_hash": "b" * 64,
            "approval": {"approved_by": "operator", "approved_at": "2026-09-23T10:02:00+00:00"},
            "health_check": {"status": "PASS"},
            "rollback": {"status": "PASS"},
            "error": None,
            "logs": ["this must not be persisted"],
            "terraform_plan": {"stdout": "sensitive command output"},
        })

        evidence = DeploymentEvidenceCollector("http://deployment-service:8030").collect("run_123")

        self.assertEqual(evidence.kind, "deployment_run")
        self.assertEqual(evidence.payload["state"], "DEPLOYED")
        self.assertEqual(evidence.payload["health_check_status"], "PASS")
        self.assertEqual(evidence.payload["source_revision"]["head_sha"], "abc123")
        self.assertNotIn("logs", evidence.payload)
        self.assertNotIn("terraform_plan", evidence.payload)
        self.assertEqual(mock_urlopen.call_args.kwargs["timeout"], 5.0)

    @patch("incident_service.infrastructure.deployment.deployment_evidence_collector.urlopen")
    def test_not_found_is_normalized(self, mock_urlopen):
        from urllib.error import HTTPError
        mock_urlopen.side_effect = HTTPError(
            "http://deployment-service:8030/api/internal/deployments/run_missing",
            404,
            "not found",
            {},
            io.BytesIO(b""),
        )

        with self.assertRaises(DeploymentEvidenceCollectorError):
            DeploymentEvidenceCollector().collect("run_missing")


if __name__ == "__main__":
    unittest.main()