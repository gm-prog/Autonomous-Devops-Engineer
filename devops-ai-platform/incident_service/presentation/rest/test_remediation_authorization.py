"""Authorization boundary for the public remediation endpoint (§21/§36).

Security invariant under test::

    authorized(request)  ⇔  ∃ ONE deployment_run evidence record E with
        canonical_repository(E) == request.repository_slug
        AND canonical_source_sha(E) == request.source_sha

``TargetBindingUnitTests`` exercises the binding function directly;
``RemediationAuthorizationTests`` exercises the HTTP handler, proving that
unauthorized requests never even construct the remediation orchestrator
(provider not invoked) and therefore never execute or publish anything.
"""

import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from ...domain.aggregates.incident import IncidentAggregate
from ...domain.entities.incident_evidence import IncidentEvidence
from ...application.services.remediation_target_binding import (
    RemediationTargetBindingError,
    authorize_remediation_target,
)
from ...infrastructure.database.postgres_incident_repo import (
    PostgresIncidentRepositoryAdapter,
)
from . import controllers as controllers_module
from .controllers import RemediationRequest, create_remediation

SOURCE_SHA = "a" * 40
OTHER_SHA = "b" * 40

PATCH = """--- a/src/service.py
+++ b/src/service.py
@@ -1 +1 @@
-old()
+new()
"""


def _deployment_evidence(
    name="acme/checkout", head_sha=SOURCE_SHA, evidence_id="deploy-1", kind_extra=None
):
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
        id=evidence_id,
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



class TargetBindingUnitTests(unittest.TestCase):
    """Direct unit tests for the same-record pair invariant (§24)."""

    def _incident_with(self, *evidence):
        incident = IncidentAggregate("inc-unit", "t", "HIGH", "gw")
        incident.move_to_triage()
        for item in evidence:
            incident.attach_evidence(item)
        return incident

    def test_exact_pair_in_one_record_is_authorized(self):
        incident = self._incident_with(_deployment_evidence())
        authorize_remediation_target(incident, "acme/checkout", SOURCE_SHA)

    def test_repository_mismatch_is_rejected(self):
        incident = self._incident_with(_deployment_evidence())
        with self.assertRaises(RemediationTargetBindingError):
            authorize_remediation_target(incident, "evil/checkout", SOURCE_SHA)

    def test_source_sha_mismatch_is_rejected(self):
        incident = self._incident_with(_deployment_evidence())
        with self.assertRaises(RemediationTargetBindingError):
            authorize_remediation_target(incident, "acme/checkout", OTHER_SHA)

    def test_cross_evidence_mixing_is_rejected(self):
        """CRITICAL: repository from deployment B + SHA from deployment A
        must never authorize, even though both values exist in evidence."""
        incident = self._incident_with(
            _deployment_evidence(
                name="acme/payment", head_sha=SOURCE_SHA, evidence_id="deploy-a"
            ),
            _deployment_evidence(
                name="evil/checkout", head_sha=OTHER_SHA, evidence_id="deploy-b"
            ),
        )
        with self.assertRaises(RemediationTargetBindingError):
            authorize_remediation_target(incident, "evil/checkout", SOURCE_SHA)

    def test_multiple_deployments_with_valid_exact_pair_is_authorized(self):
        incident = self._incident_with(
            _deployment_evidence(
                name="acme/payment", head_sha=SOURCE_SHA, evidence_id="deploy-a"
            ),
            _deployment_evidence(
                name="evil/checkout", head_sha=OTHER_SHA, evidence_id="deploy-b"
            ),
        )
        authorize_remediation_target(incident, "evil/checkout", OTHER_SHA)

    def test_bare_repository_name_is_not_an_identity(self):
        incident = self._incident_with(
            _deployment_evidence(name="checkout", evidence_id="deploy-bare")
        )
        with self.assertRaises(RemediationTargetBindingError):
            authorize_remediation_target(incident, "acme/checkout", SOURCE_SHA)

    def test_bare_repository_slug_request_is_rejected(self):
        incident = self._incident_with(_deployment_evidence())
        with self.assertRaises(RemediationTargetBindingError):
            authorize_remediation_target(incident, "checkout", SOURCE_SHA)

    def test_path_trick_repository_slug_request_is_rejected(self):
        incident = self._incident_with(_deployment_evidence())
        for bad in ("../checkout", "acme/../checkout", "a/b/c", "https://github.com/a/b"):
            with self.assertRaises(RemediationTargetBindingError, msg=bad):
                authorize_remediation_target(incident, bad, SOURCE_SHA)

    def test_malformed_repository_identity_in_evidence_fails_closed(self):
        for bad in ("", "a/b/c", "acme/checkout.git?x", None, 42):
            incident = self._incident_with(
                _deployment_evidence(name=bad, evidence_id=f"deploy-{id(bad)}")
            )
            with self.assertRaises(
                RemediationTargetBindingError, msg=f"repo={bad!r}"
            ):
                authorize_remediation_target(incident, "acme/checkout", SOURCE_SHA)

    def test_malformed_request_source_sha_is_rejected(self):
        incident = self._incident_with(_deployment_evidence())
        for bad in (
            "abc",
            "main",
            "refs/heads/main",
            "",
            None,
            "a" * 41,
            "a" * 39,
            "z" * 40,  # non-hex
            12345,
        ):
            with self.assertRaises(
                RemediationTargetBindingError, msg=f"sha={bad!r}"
            ):
                authorize_remediation_target(incident, "acme/checkout", bad)

    def test_malformed_evidence_source_sha_fails_closed(self):
        for bad in ("abc", "main", "refs/heads/main", "", None, "a" * 41, "z" * 40, 7):
            incident = self._incident_with(
                _deployment_evidence(
                    head_sha=bad, evidence_id=f"deploy-sha-{id(bad)}"
                )
            )
            with self.assertRaises(
                RemediationTargetBindingError, msg=f"evidence sha={bad!r}"
            ):
                authorize_remediation_target(incident, "acme/checkout", SOURCE_SHA)

    def test_only_deployed_state_is_authoritative(self):
        """A successful deployment authorizes; every lesser/failed state does
        not (§8 deployment-provenance invariant)."""
        for bad_state in (
            "AWAITING_APPROVAL",
            "DRY_RUN_PASSED",
            "DRY_RUNNING",
            "APPROVED",
            "DEPLOYING",
            "DEPLOYMENT_FAILED",
            "ROLLED_BACK",
            "VALIDATION_FAILED",
        ):
            incident = self._incident_with(
                IncidentEvidence(
                    id=f"deploy-state-{bad_state}",
                    kind="deployment_run",
                    source="deployment-service",
                    payload={
                        "repository_name": "acme/checkout",
                        "source_revision": {"head_sha": SOURCE_SHA},
                        "state": bad_state,
                    },
                )
            )
            with self.assertRaises(
                RemediationTargetBindingError, msg=f"state={bad_state}"
            ):
                authorize_remediation_target(incident, "acme/checkout", SOURCE_SHA)

    def test_missing_or_malformed_state_is_not_authoritative(self):
        # Policy: exact match on the domain enum value only - no trimming,
        # no case folding. Anything else is non-authoritative (fail closed).
        for state in (None, "", "deployed", " DEPLOYED", "DEPLOYED ", 42, "DEPLOYED_FAILED"):
            incident = self._incident_with(
                IncidentEvidence(
                    id=f"deploy-state-{id(state)}",
                    kind="deployment_run",
                    source="deployment-service",
                    payload={
                        "repository_name": "acme/checkout",
                        "source_revision": {"head_sha": SOURCE_SHA},
                        "state": state,
                    },
                )
            )
            with self.assertRaises(
                RemediationTargetBindingError, msg=f"state={state!r}"
            ):
                authorize_remediation_target(incident, "acme/checkout", SOURCE_SHA)

    def test_failed_deployment_cannot_authorize_while_deployed_run_exists(self):
        """State gate is per record: a DEPLOYED record with a DIFFERENT pair
        must not rescue a failed record's pair."""
        failed = IncidentEvidence(
            id="deploy-failed",
            kind="deployment_run",
            source="deployment-service",
            payload={
                "repository_name": "acme/checkout",
                "source_revision": {"head_sha": SOURCE_SHA},
                "state": "DEPLOYMENT_FAILED",
            },
        )
        deployed = self._incident_with(
            failed,
            _deployment_evidence(
                name="acme/checkout", head_sha=OTHER_SHA, evidence_id="deploy-ok"
            ),
        )
        # the failed run's pair is unusable
        with self.assertRaises(RemediationTargetBindingError):
            authorize_remediation_target(deployed, "acme/checkout", SOURCE_SHA)
        # the deployed run's pair still works
        authorize_remediation_target(deployed, "acme/checkout", OTHER_SHA)

    def test_no_deployment_evidence_is_rejected(self):
        incident = IncidentAggregate("inc-none", "t", "HIGH", "gw")
        incident.move_to_triage()
        with self.assertRaises(RemediationTargetBindingError) as ctx:
            authorize_remediation_target(incident, "acme/checkout", SOURCE_SHA)
        self.assertIn("no deployment evidence", str(ctx.exception))

    def test_request_sha_case_normalizes_to_evidence(self):
        incident = self._incident_with(_deployment_evidence(head_sha=SOURCE_SHA))
        authorize_remediation_target(incident, "acme/checkout", SOURCE_SHA.upper())

    def test_repository_identity_is_case_sensitive(self):
        """No case folding on repository slugs (§16): different case = different
        identity = rejected."""
        incident = self._incident_with(_deployment_evidence(name="acme/Checkout"))
        with self.assertRaises(RemediationTargetBindingError):
            authorize_remediation_target(incident, "acme/checkout", SOURCE_SHA)


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
    """Controller-level tests: 403 + the orchestrator provider is never
    invoked for unauthorized requests (construction avoided, §17/§18)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repository = PostgresIncidentRepositoryAdapter(
            f"sqlite:///{os.path.join(self._tmp.name, 'incidents.db')}"
        )
        self.addCleanup(self._tmp.cleanup)

    def _call_with_spy(self, incident_id, request):
        """Invoke the handler with the orchestrator provider patched so tests
        can assert construction (provider call) and execution separately."""
        spy = _orchestrator_spy()
        with patch.object(
            controllers_module,
            "get_remediation_orchestrator",
            return_value=spy,
        ) as provider:
            try:
                result = create_remediation(incident_id, request, self.repository)
            except Exception as exc:
                return spy, provider, exc
            return spy, provider, result

    def test_valid_exact_pair_authorizes_and_executes(self):
        incident = _incident()
        self.repository.save_incident(incident)

        spy, provider, result = self._call_with_spy(incident.id, _request())

        self.assertNotIsInstance(result, Exception)
        provider.assert_called_once()
        spy.execute.assert_called_once()
        self.assertEqual(
            result["pull_request_url"], "https://github.com/acme/checkout/pull/1"
        )
        restored = self.repository.get_incident_by_id(incident.id)
        self.assertEqual(len(restored.patch_proposals), 1)

    def test_unknown_incident_is_not_found(self):
        spy, provider, exc = self._call_with_spy("inc-missing", _request())
        from fastapi import HTTPException

        self.assertIsInstance(exc, HTTPException)
        self.assertEqual(exc.status_code, 404)
        provider.assert_not_called()
        spy.execute.assert_not_called()

    def test_unrelated_repository_is_rejected(self):
        from fastapi import HTTPException

        self.repository.save_incident(_incident())

        spy, provider, exc = self._call_with_spy(
            "inc-bind", _request(slug="evil/checkout")
        )

        self.assertIsInstance(exc, HTTPException)
        self.assertEqual(exc.status_code, 403)
        provider.assert_not_called()
        spy.execute.assert_not_called()

    def test_unrelated_source_sha_is_rejected(self):
        from fastapi import HTTPException

        self.repository.save_incident(_incident())

        spy, provider, exc = self._call_with_spy(
            "inc-bind", _request(sha=OTHER_SHA)
        )

        self.assertIsInstance(exc, HTTPException)
        self.assertEqual(exc.status_code, 403)
        provider.assert_not_called()
        spy.execute.assert_not_called()

    def test_cross_evidence_mixing_attack_is_rejected(self):
        """CRITICAL (§10): two deployments must not be cross-combinable.

        Evidence A: acme/payment + AAAAA...
        Evidence B: evil/checkout + BBBBB...
        Request:     evil/checkout + AAAAA...  → 403, nothing constructed.
        """
        from fastapi import HTTPException

        incident = _incident(with_deployment=False)
        incident.attach_evidence(
            _deployment_evidence(
                name="acme/payment", head_sha=SOURCE_SHA, evidence_id="deploy-a"
            )
        )
        incident.attach_evidence(
            _deployment_evidence(
                name="evil/checkout", head_sha=OTHER_SHA, evidence_id="deploy-b"
            )
        )
        self.repository.save_incident(incident)

        spy, provider, exc = self._call_with_spy(
            "inc-bind", _request(slug="evil/checkout", sha=SOURCE_SHA)
        )

        self.assertIsInstance(exc, HTTPException)
        self.assertEqual(exc.status_code, 403)
        provider.assert_not_called()
        spy.execute.assert_not_called()

    def test_bare_repository_name_in_evidence_is_rejected(self):
        """Evidence repository_name='checkout' must NOT authorize
        repository_slug='acme/checkout' (no segment matching, no upgrade)."""
        from fastapi import HTTPException

        incident = _incident(with_deployment=False)
        incident.attach_evidence(
            IncidentEvidence(
                id="deploy-bare",
                kind="deployment_run",
                source="deployment-service",
                payload={
                    "repository_name": "checkout",
                    "source_revision": {"head_sha": SOURCE_SHA},
                    "state": "DEPLOYED",
                },
            )
        )
        self.repository.save_incident(incident)

        spy, provider, exc = self._call_with_spy(
            "inc-bind", _request(slug="acme/checkout")
        )

        self.assertIsInstance(exc, HTTPException)
        self.assertEqual(exc.status_code, 403)
        provider.assert_not_called()
        spy.execute.assert_not_called()

    def test_malformed_repository_identity_in_evidence_fails_closed(self):
        from fastapi import HTTPException

        incident = _incident(with_deployment=False)
        incident.attach_evidence(
            IncidentEvidence(
                id="deploy-malformed",
                kind="deployment_run",
                source="deployment-service",
                payload={
                    "repository_name": "a/b/c",
                    "source_revision": {"head_sha": SOURCE_SHA},
                    "state": "DEPLOYED",
                },
            )
        )
        self.repository.save_incident(incident)

        spy, provider, exc = self._call_with_spy("inc-bind", _request())

        self.assertIsInstance(exc, HTTPException)
        self.assertEqual(exc.status_code, 403)
        provider.assert_not_called()
        spy.execute.assert_not_called()

    def test_incident_without_deployment_evidence_is_rejected(self):
        from fastapi import HTTPException

        self.repository.save_incident(_incident(with_deployment=False))

        spy, provider, exc = self._call_with_spy("inc-bind", _request())

        self.assertIsInstance(exc, HTTPException)
        self.assertEqual(exc.status_code, 403)
        self.assertIn("no deployment evidence", str(exc.detail))
        provider.assert_not_called()
        spy.execute.assert_not_called()

    def test_multiple_deployments_with_valid_exact_pair_is_authorized(self):
        incident = _incident(with_deployment=False)
        incident.attach_evidence(
            _deployment_evidence(
                name="acme/payment", head_sha=SOURCE_SHA, evidence_id="deploy-a"
            )
        )
        incident.attach_evidence(
            _deployment_evidence(
                name="evil/checkout", head_sha=OTHER_SHA, evidence_id="deploy-b"
            )
        )
        self.repository.save_incident(incident)

        spy, provider, result = self._call_with_spy(
            "inc-bind", _request(slug="evil/checkout", sha=OTHER_SHA)
        )

        self.assertNotIsInstance(result, Exception)
        provider.assert_called_once()
        spy.execute.assert_called_once()

    def test_non_deployed_evidence_cannot_reach_orchestrator(self):
        from fastapi import HTTPException

        incident = _incident(with_deployment=False)
        incident.attach_evidence(
            IncidentEvidence(
                id="deploy-awaiting",
                kind="deployment_run",
                source="deployment-service",
                payload={
                    "repository_name": "acme/checkout",
                    "source_revision": {"head_sha": SOURCE_SHA},
                    "state": "AWAITING_APPROVAL",
                },
            )
        )
        self.repository.save_incident(incident)

        spy, provider, exc = self._call_with_spy("inc-bind", _request())

        self.assertIsInstance(exc, HTTPException)
        self.assertEqual(exc.status_code, 403)
        provider.assert_not_called()
        spy.execute.assert_not_called()

    def test_uppercase_requested_sha_is_normalized(self):
        incident = _incident()
        self.repository.save_incident(incident)

        spy, provider, result = self._call_with_spy(
            "inc-bind", _request(sha=SOURCE_SHA.upper())
        )

        self.assertNotIsInstance(result, Exception)
        provider.assert_called_once()
        spy.execute.assert_called_once()


if __name__ == "__main__":
    unittest.main()
