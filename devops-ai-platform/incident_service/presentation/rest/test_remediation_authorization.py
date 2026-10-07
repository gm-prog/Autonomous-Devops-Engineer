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
from shared_kernel.domain.provenance import (
    ProvenanceError,
    build_provenance_record,
    compute_provenance_hash,
)

SOURCE_SHA = "a" * 40
OTHER_SHA = "b" * 40

PATCH = """--- a/src/service.py
+++ b/src/service.py
@@ -1 +1 @@
-old()
+new()
"""


def _deployment_evidence(
    name="acme/checkout",
    head_sha=SOURCE_SHA,
    evidence_id="deploy-1",
    kind_extra=None,
    run_id="run-1",
):
    payload = {
        "deployment_run_id": run_id,
        "repository_id": 42,
        "repository_name": name,
        "source_revision": {"head_sha": head_sha, "commits": []},
        "state": "DEPLOYED",
        "artifact_hash": "c" * 64,
        "plan_hash": "d" * 64,
    }
    if kind_extra:
        payload.update(kind_extra)
    try:
        # fixtures carry genuine platform provenance (Stage 5) so that tests
        # keep proving the property they claim; malformed-identity fixtures
        # cannot build one and stay unprovenanced (fail closed, as in prod).
        payload["provenance"] = build_provenance_record(
            repository_name=payload["repository_name"],
            source_sha=str(payload["source_revision"].get("head_sha") or ""),
            artifact_hash=str(payload.get("artifact_hash") or ""),
            plan_hash=str(payload.get("plan_hash") or ""),
            deployment_run_id=str(payload["deployment_run_id"]),
            state=str(payload["state"]),
            verification_method="test-source-verifier",
        )
    except ProvenanceError:
        pass
    return IncidentEvidence(
        id=evidence_id,
        kind="deployment_run",
        source="deployment-service",
        payload=payload,
    )


def promote_to_root_cause_found(
    incident,
    root_cause="connection pool exhaustion under peak load",
):
    """Drive the canonical incident chain and persist a schema-valid RCA
    record — the Phase 8/8.1 precondition for any proposal intake
    (the compatibility shim never invents an RCA itself)."""
    from ...application.services.proposal_generation_service import (
        incident_service_evidence_from_rca,
    )
    from ...domain.entities.root_cause_analysis import RootCauseAnalysis

    if incident.status == "Raised":
        incident.move_to_triage()
    if incident.status == "Triage":
        incident.begin_investigation()
    if incident.status == "Investigating":
        incident.mark_root_cause_found()
    incident.attach_evidence(
        incident_service_evidence_from_rca(
            RootCauseAnalysis(
                id=f"rca-{incident.id}",
                incident_id=incident.id,
                root_cause=root_cause,
                confidence=0.9,
                evidence_refs=[item.id for item in incident.evidence],
            )
        )
    )
    return incident


def _incident(incident_id="inc-bind", with_deployment=True):
    incident = IncidentAggregate(incident_id, "Checkout 5xx", "HIGH", "gateway")
    if with_deployment:
        incident.attach_evidence(_deployment_evidence())
    promote_to_root_cause_found(incident)
    return incident


def _request(slug="acme/checkout", sha=SOURCE_SHA, patch=PATCH):
    return RemediationRequest(
        target_filepath="src/service.py",
        patch=patch,
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

    # ---------------- Stage 5: provenance gate ----------------

    def test_deployed_record_without_provenance_is_rejected(self):
        """A DEPLOYED record lacking the platform provenance record fails
        closed: plausible repository + SHA alone never authorizes."""
        payload = {
            "deployment_run_id": "run-noprov",
            "repository_name": "acme/checkout",
            "source_revision": {"head_sha": SOURCE_SHA},
            "state": "DEPLOYED",
        }
        incident = self._incident_with(
            IncidentEvidence(
                id="deploy-no-provenance",
                kind="deployment_run",
                source="deployment-service",
                payload=payload,
            )
        )
        with self.assertRaises(RemediationTargetBindingError) as ctx:
            authorize_remediation_target(incident, "acme/checkout", SOURCE_SHA)
        self.assertIn("provenance", str(ctx.exception))

    def test_tampered_provenance_is_rejected(self):
        evidence = _deployment_evidence()
        # alter an identity field without being able to hide it: the
        # provenance_hash no longer recomputes
        evidence.payload["provenance"]["artifact_hash"] = "e" * 64
        incident = self._incident_with(evidence)
        with self.assertRaises(RemediationTargetBindingError) as ctx:
            authorize_remediation_target(incident, "acme/checkout", SOURCE_SHA)
        self.assertIn("provenance", str(ctx.exception))

    def test_provenance_grafted_from_another_record_is_rejected(self):
        """Provenance from deployment B grafted onto record A (hash intact!)
        is caught by the identity cross-check: it describes another run."""
        record_a = _deployment_evidence(
            name="acme/checkout",
            head_sha=SOURCE_SHA,
            evidence_id="deploy-a",
            run_id="run-a",
        )
        record_b = _deployment_evidence(
            name="acme/checkout",
            head_sha=SOURCE_SHA,
            evidence_id="deploy-b",
            run_id="run-b",
        )
        # both records prove the same pair, but B's provenance carries B's
        # run id: it must not corroborate record A.
        record_a.payload["provenance"] = record_b.payload["provenance"]
        incident = self._incident_with(record_a)
        with self.assertRaises(RemediationTargetBindingError) as ctx:
            authorize_remediation_target(incident, "acme/checkout", SOURCE_SHA)
        self.assertIn("provenance", str(ctx.exception))

    def test_provenance_state_mismatch_is_rejected(self):
        """Valid-hash provenance recorded for AWAITING_APPROVAL never
        corroborates a payload claiming DEPLOYED (state participates in the
        hashed identity and is cross-checked against the record)."""
        evidence = _deployment_evidence()
        stale = build_provenance_record(
            repository_name="acme/checkout",
            source_sha=SOURCE_SHA,
            artifact_hash="c" * 64,
            plan_hash="d" * 64,
            deployment_run_id="run-1",
            state="AWAITING_APPROVAL",
            verification_method="test-source-verifier",
        )
        evidence.payload["provenance"] = stale
        incident = self._incident_with(evidence)
        with self.assertRaises(RemediationTargetBindingError) as ctx:
            authorize_remediation_target(incident, "acme/checkout", SOURCE_SHA)
        self.assertIn("provenance", str(ctx.exception))

    def test_unverified_source_method_never_authorizes(self):
        """Even a perfectly re-hashed record with verification_method
        'unverified' is rejected: provenance must record an independent
        source verification."""
        evidence = _deployment_evidence()
        unverified = dict(evidence.payload["provenance"])
        unverified["verification_method"] = "unverified"
        unverified["provenance_hash"] = compute_provenance_hash(unverified)
        evidence.payload["provenance"] = unverified
        incident = self._incident_with(evidence)
        with self.assertRaises(RemediationTargetBindingError) as ctx:
            authorize_remediation_target(incident, "acme/checkout", SOURCE_SHA)
        self.assertIn("provenance", str(ctx.exception))

    def test_provenance_from_a_different_pair_does_not_authorize(self):
        """Cross-evidence attack extended to provenance: the incident holds
        B's (repoB, shaB) record whose provenance is valid, but a request
        for (repoB, shaA) still never authorizes — provenance cannot bridge
        different records."""
        incident = self._incident_with(
            _deployment_evidence(
                name="evil/checkout", head_sha=OTHER_SHA, evidence_id="deploy-b"
            )
        )
        with self.assertRaises(RemediationTargetBindingError):
            authorize_remediation_target(incident, "evil/checkout", SOURCE_SHA)


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

    def test_valid_exact_pair_produces_proposed_shim_without_execution(self):
        """Phase 8.1 §3.8 Test 1: legacy request → PROPOSED only.

        200 + persisted PROPOSED proposal + incident RemediationProposed,
        and the orchestrator provider is NEVER constructed (zero Git /
        GitHub / PR side effects).
        """
        incident = _incident()
        self.repository.save_incident(incident)

        spy, provider, result = self._call_with_spy(incident.id, _request())

        self.assertNotIsInstance(result, Exception)
        provider.assert_not_called()
        spy.execute.assert_not_called()
        self.assertEqual(result["status"], "PROPOSED")
        self.assertEqual(result["incident_status"], "RemediationProposed")
        self.assertTrue(result["compatibility_shim"])
        self.assertFalse(result["executed"])
        self.assertNotIn("pull_request_url", result)
        self.assertNotIn("commit_sha", result)
        self.assertNotIn("branch", result)
        # trusted identity comes from evidence, not the request
        self.assertEqual(result["repository"], "acme/checkout")
        self.assertEqual(result["source_sha"], SOURCE_SHA)
        restored = self.repository.get_incident_by_id(incident.id)
        self.assertEqual(restored.status, "RemediationProposed")
        self.assertEqual(len(restored.patch_proposals), 1)
        self.assertEqual(restored.patch_proposals[0].status, "PROPOSED")

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
        provider.assert_not_called()
        spy.execute.assert_not_called()
        self.assertEqual(result["status"], "PROPOSED")
        self.assertEqual(result["repository"], "evil/checkout")
        self.assertEqual(result["source_sha"], OTHER_SHA)

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
        provider.assert_not_called()
        spy.execute.assert_not_called()
        self.assertEqual(result["status"], "PROPOSED")
        self.assertEqual(result["source_sha"], SOURCE_SHA)

    def test_deployed_evidence_without_provenance_never_reaches_orchestrator(
        self,
    ):
        """Controller-level Stage 5 gate: correct pair + DEPLOYED state but
        no platform provenance record → 403, orchestrator never constructed."""
        from fastapi import HTTPException

        incident = _incident(with_deployment=False)
        incident.attach_evidence(
            IncidentEvidence(
                id="deploy-no-provenance",
                kind="deployment_run",
                source="deployment-service",
                payload={
                    "deployment_run_id": "run-x",
                    "repository_name": "acme/checkout",
                    "source_revision": {"head_sha": SOURCE_SHA},
                    "state": "DEPLOYED",
                    "artifact_hash": "c" * 64,
                    "plan_hash": "d" * 64,
                },
            )
        )
        self.repository.save_incident(incident)

        spy, provider, exc = self._call_with_spy("inc-bind", _request())

        self.assertIsInstance(exc, HTTPException)
        self.assertEqual(exc.status_code, 403)
        self.assertIn("provenance", str(exc.detail))
        provider.assert_not_called()
        spy.execute.assert_not_called()


UNSAFE_MULTI_FILE_PATCH = """--- a/src/service.py
+++ b/src/service.py
@@ -1 +1 @@
-old()
+new()
--- a/src/other.py
+++ b/src/other.py
@@ -1 +1 @@
-old()
+new()
"""


class RemediationShimCompatibilityTests(unittest.TestCase):
    """Phase 8.1 §3.8/§35/§36 — the legacy route is proposal intake ONLY.

    Every test proves the route cannot construct an orchestrator, cannot
    publish, cannot approve itself, and cannot be tricked into execution
    via legacy compatibility fields.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repository = PostgresIncidentRepositoryAdapter(
            f"sqlite:///{os.path.join(self._tmp.name, 'shim.db')}"
        )
        self.addCleanup(self._tmp.cleanup)
        self.incident = _incident()
        self.repository.save_incident(self.incident)

    def _call(self, request=None):
        spy = MagicMock()
        with patch.object(
            controllers_module,
            "get_remediation_orchestrator",
            return_value=spy,
        ) as provider:
            try:
                result = create_remediation(
                    self.incident.id, request or _request(), self.repository
                )
            except Exception as exc:
                return spy, provider, exc
            return spy, provider, result

    # ---- Test 2: invalid target -------------------------------------
    def test_invalid_target_is_403_with_zero_orchestrator_construction(self):
        from fastapi import HTTPException

        spy, provider, exc = self._call(_request(slug="evil/checkout"))
        self.assertIsInstance(exc, HTTPException)
        self.assertEqual(exc.status_code, 403)
        provider.assert_not_called()
        spy.execute.assert_not_called()

    # ---- Test 3: unsafe patch ---------------------------------------
    def test_unsafe_patch_is_422_blocked_persisted_no_execution(self):
        from fastapi import HTTPException

        spy, provider, exc = self._call(_request(patch=UNSAFE_MULTI_FILE_PATCH))
        self.assertIsInstance(exc, HTTPException)
        self.assertEqual(exc.status_code, 422)
        self.assertEqual(exc.detail["status"], "BLOCKED")
        provider.assert_not_called()
        spy.execute.assert_not_called()
        restored = self.repository.get_incident_by_id(self.incident.id)
        self.assertEqual(restored.status, "RootCauseFound")  # never promoted
        self.assertEqual(restored.patch_proposals[0].status, "BLOCKED")
        self.assertEqual(
            restored.patch_proposals[0].blocked_reason, "PATCH_VALIDATION_FAILED"
        )

    # ---- Test 4: shim → approval ------------------------------------
    def test_shim_then_canonical_approval(self):
        from .controllers import ProposalApprovalRequest, approve_proposal
        from ...application.services.proposal_approval_service import (
            ProposalApprovalService,
        )

        spy, provider, result = self._call()
        self.assertEqual(result["status"], "PROPOSED")

        approved = approve_proposal(
            self.incident.id,
            ProposalApprovalRequest(
                proposal_id=result["proposal_id"],
                proposal_hash=result["proposal_hash"],
                approved_by="alice-operator",
            ),
            service=ProposalApprovalService(self.repository),
        )
        self.assertEqual(approved["proposal"]["status"], "APPROVED")
        restored = self.repository.get_incident_by_id(self.incident.id)
        self.assertEqual(restored.patch_proposals[0].status, "APPROVED")
        provider.assert_not_called()
        spy.execute.assert_not_called()

    # ---- Test 6: direct hidden bypass attempt ------------------------
    def test_shim_never_invokes_orchestration_execute(self):
        with patch.object(
            controllers_module.RemediationOrchestrationService, "execute"
        ) as class_execute:
            spy, provider, result = self._call()
        self.assertEqual(result["status"], "PROPOSED")
        class_execute.assert_not_called()
        provider.assert_not_called()

    # ---- §35: the shim cannot approve -------------------------------
    def test_shim_cannot_self_approve(self):
        spy, provider, result = self._call()
        self.assertEqual(result["status"], "PROPOSED")
        restored = self.repository.get_incident_by_id(self.incident.id)
        proposal = restored.patch_proposals[0]
        self.assertEqual(proposal.status, "PROPOSED")
        self.assertEqual(proposal.approved_by, "")
        self.assertEqual(proposal.approval_hash, "")
        provider.assert_not_called()
        spy.execute.assert_not_called()

    # ---- §36: legacy execution parameters are not authorization ------
    def test_legacy_execution_fields_do_not_execute(self):
        request = RemediationRequest(
            target_filepath="src/service.py",
            patch=PATCH,
            source_sha=SOURCE_SHA,
            repository_slug="acme/checkout",
            base_branch="production",  # hostile: not even allowlisted
            pr_title="fix",
            pr_body="approved",
            validation_profile="incident_service",
        )
        spy, provider, result = self._call(request)
        self.assertNotIsInstance(result, Exception)
        self.assertEqual(result["status"], "PROPOSED")
        self.assertFalse(result["executed"])
        provider.assert_not_called()
        spy.execute.assert_not_called()
        restored = self.repository.get_incident_by_id(self.incident.id)
        self.assertEqual(restored.patch_proposals[0].status, "PROPOSED")

    # ---- repeated shim is idempotent on one logical proposal ----------
    def test_repeated_shim_converges_on_one_logical_proposal(self):
        first = self._call()[2]
        second = self._call()[2]
        self.assertEqual(first["proposal_id"], second["proposal_id"])
        self.assertEqual(first["proposal_hash"], second["proposal_hash"])
        restored = self.repository.get_incident_by_id(self.incident.id)
        self.assertEqual(len(restored.patch_proposals), 1)
        self.assertEqual(restored.patch_proposals[0].status, "PROPOSED")

    # ---- readiness precondition --------------------------------------
    def test_triage_incident_cannot_receive_shim_proposal(self):
        from fastapi import HTTPException

        incident = IncidentAggregate("inc-triage-only", "t", "HIGH", "gw")
        incident.move_to_triage()
        incident.attach_evidence(_deployment_evidence(evidence_id="deploy-triage"))
        self.repository.save_incident(incident)
        with patch.object(
            controllers_module, "get_remediation_orchestrator", return_value=MagicMock()
        ) as provider:
            with self.assertRaises(HTTPException) as ctx:
                create_remediation(incident.id, _request(), self.repository)
        self.assertEqual(ctx.exception.status_code, 409)
        provider.assert_not_called()


if __name__ == "__main__":
    unittest.main()
