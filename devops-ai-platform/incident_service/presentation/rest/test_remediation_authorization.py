"""Authorization boundary for the public remediation endpoint (§21).

Proves the incident → repository → source-revision binding: a caller cannot
use ``POST /incidents/{id}/remediation`` as an arbitrary GitHub write
primitive by pairing a legitimate incident with an unrelated repository or
a fabricated source SHA.
"""

import unittest
from unittest.mock import MagicMock

from ...domain.aggregates.incident import IncidentAggregate
from ...domain.entities.incident_evidence import IncidentEvidence
from ...infrastructure.database.postgres_incident_repo import (
    PostgresIncidentRepositoryAdapter,
)
from .controllers import RemediationRequest, create_remediation

import os
import tempfile

SOURCE_SHA = "a" * 40
OTHER_SHA = "b" * 40

PATCH = """--- a/src/service.py
+++ b/src/service.py
@@ -1 +1 @@
-old()
+new()
"""


def _deployment_evidence(name="acme/checkout", head_sha=SOURCE_SHA, kind_extra=None):
    payload = {
        "deployment_run_id": "run-1",
        "repository_id": 42,
        "repository_name": name,
        "source_revision": {"head_sha": head_sha, "commits": []},
        "state": "DEPLOYED",
    }
    if kind_extra:
        payload.update(kind_extra)
    return IncidentEvidence(
        id="deploy-1",
        kind="deployment_run",
        source="deployment-service",
        payload=payload,
    )


def _incident(incident_id="inc-bind", with_deployment=True):
    incident = IncidentAggregate(incident_id, "Checkout 5xx", "HIGH", "gateway")
    incident.move_to_triage()
    if with_deployment:
        incident.attach_evidence(_deployment_evidence())
    return incident


def _request(slug="acme/checkout", sha=SOURCE_SHA):
    return RemediationRequest(
        target_filepath="src/service.py",
        patch=PATCH,
        source_sha=sha,
        repository_slug=slug,
    )


def _orchestrator_spy():
    spy = MagicMock()
    spy.execute.return_value = MagicMock(
        incident_id="inc-bind",
        proposal_id="remediation-inc-bind",
        source_sha=SOURCE_SHA,
        branch_name="automation/remediation/inc-bind/remediation-inc-bind",
        commit_sha="c" * 40,
        pull_request_url="https://github.com/acme/checkout/pull/1",
        validation_result=MagicMock(passed=True, steps=[]),
    )
    return spy


class FakeRepository:
    def __init__(self, incidents):
        self.by_id = {i.id: i for i in incidents}
        self.saved = []

    def get_incident_by_id(self, incident_id):
        return self.by_id.get(incident_id)

    def get_active_incidents(self):
        return list(self.by_id.values())

    def save_incident(self, incident):
        self.saved.append(incident)


class RemediationAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repository = PostgresIncidentRepositoryAdapter(
            f"sqlite:///{os.path.join(self._tmp.name, 'incidents.db')}"
        )
        self.addCleanup(self._tmp.cleanup)

    def test_valid_incident_repository_sha_binding_is_allowed(self):
        incident = _incident()
        self.repository.save_incident(incident)
        spy = _orchestrator_spy()

        result = create_remediation(
            incident.id, _request(), self.repository, spy
        )

        spy.execute.assert_called_once()
        self.assertEqual(result["pull_request_url"],
                         "https://github.com/acme/checkout/pull/1")
        # proposal persisted on the bound incident
        restored = self.repository.get_incident_by_id(incident.id)
        self.assertEqual(len(restored.patch_proposals), 1)

    def test_unknown_incident_is_not_found(self):
        from fastapi import HTTPException

        spy = _orchestrator_spy()
        with self.assertRaises(HTTPException) as ctx:
            create_remediation("inc-missing", _request(), self.repository, spy)
        self.assertEqual(ctx.exception.status_code, 404)
        spy.execute.assert_not_called()

    def test_unrelated_repository_is_rejected(self):
        from fastapi import HTTPException

        self.repository.save_incident(_incident())
        spy = _orchestrator_spy()

        with self.assertRaises(HTTPException) as ctx:
            create_remediation(
                "inc-bind",
                _request(slug="evil/checkout"),
                self.repository,
                spy,
            )

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("repository", str(ctx.exception.detail).lower())
        spy.execute.assert_not_called()

    def test_unrelated_source_sha_is_rejected(self):
        from fastapi import HTTPException

        self.repository.save_incident(_incident())
        spy = _orchestrator_spy()

        with self.assertRaises(HTTPException) as ctx:
            create_remediation(
                "inc-bind",
                _request(sha=OTHER_SHA),
                self.repository,
                spy,
            )

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("source revision", str(ctx.exception.detail).lower())
        spy.execute.assert_not_called()

    def test_incident_without_deployment_evidence_is_rejected(self):
        from fastapi import HTTPException

        self.repository.save_incident(_incident(with_deployment=False))
        spy = _orchestrator_spy()

        with self.assertRaises(HTTPException) as ctx:
            create_remediation("inc-bind", _request(), self.repository, spy)

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("binding", str(ctx.exception.detail).lower())
        spy.execute.assert_not_called()

    def test_bare_repository_name_in_evidence_binds_by_segment(self):
        """Evidence with a bare repository_name still binds owner/name slugs."""
        incident = _incident()
        # overwrite evidence with bare name (as produced by the collector
        # when only repository_name is available)
        incident.evidence = [
            IncidentEvidence(
                id="deploy-bare",
                kind="deployment_run",
                source="deployment-service",
                payload={
                    "repository_name": "checkout",
                    "source_revision": {"head_sha": SOURCE_SHA},
                },
            )
        ]
        self.repository.save_incident(incident)
        spy = _orchestrator_spy()

        result = create_remediation(
            "inc-bind", _request(slug="acme/checkout"), self.repository, spy
        )
        spy.execute.assert_called_once()
        self.assertEqual(result["incident_id"], "inc-bind")


if __name__ == "__main__":
    unittest.main()
