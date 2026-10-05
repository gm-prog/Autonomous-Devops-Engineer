"""Full control-plane trust chain through the gateway (Stage 5 §E/§O).

    authenticated JWT → gateway control-plane route (function authz +
    identity stamping) → real deployment handlers → real state machine →
    persisted provenance → REAL evidence collector → incident remediation
    (evidence provenance binding) → orchestrator

Process boundaries are substituted exactly like the other platform E2Es:
terraform/kubectl/Redis and GitHub source verification use deterministic
fakes, the collector's ``urlopen`` is routed into the deployment
TestClient, and the gateway's downstream ``requests.post`` is routed into
the deployment/incident TestClients. Everything else — auth, role gates,
identity stamping, HTTP handlers, state machine, persistence objects,
collector normalization, binding — is the real code.

Rejection matrix (each asserts the security reason, not just a 4xx):
unauthenticated (401), wrong role (403, downstream never contacted),
unverified source (422, no run persisted), wrong SHA / wrong repository /
cross-evidence (403, orchestrator never constructed), non-DEPLOYED
evidence (403), unknown incident (404).
"""

import json
import os
import unittest
import uuid
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from api_gateway.core.auth import GatewaySettings, mint_token
from deployment_service.main import app as deployment_app
from deployment_service.tests.test_deployment_engine import (
    VALID_PAYLOAD,
    FakeHealth,
    FakeKubectl,
    FakeSourceVerifier,
    FakeStore,
    FakeTerraform,
    FakeValidator,
)
from incident_service.application.dependencies import get_incident_repository
from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.infrastructure.deployment.deployment_evidence_collector import (
    DeploymentEvidenceCollector,
)
from incident_service.presentation.rest import controllers as controllers_module

SHA_A = "a" * 40
SHA_B = "b" * 40

DRY_RUN = "/v1/deployments/dry-run"
APPROVE = "/v1/deployments/{run_id}/approve"
EXECUTE = "/v1/deployments/{run_id}/execute"
REMEDIATION = "/v1/incidents/{incident_id}/remediation"

REMEDIATION_BODY = {
    "target_filepath": "src/service.py",
    "patch": (
        "--- a/src/service.py\n+++ b/src/service.py\n@@ -1 +1 @@\n-old()\n+new()\n"
    ),
}


def _authed(token):
    return {"Authorization": f"Bearer {token}"}


def _operator_token(subject="alice-operator"):
    return mint_token(
        subject, roles=["DevOpsLead"], secret=GatewaySettings.JWT_SECRET
    )


def _ordinary_token(subject="bob-developer"):
    return mint_token(
        subject, roles=["Developer"], secret=GatewaySettings.JWT_SECRET
    )


class _RoutedResponse:
    """urlopen-compatible response backed by the deployment TestClient."""

    def __init__(self, status, body):
        self._status, self._body = status, body

    def getcode(self):
        return self._status

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _route_urlopen_to_test_client(client):
    def _router(request, timeout=None):
        path = "/" + request.full_url.split("/", 3)[3]
        response = client.get(path)
        return _RoutedResponse(response.status_code, response.content)

    return _router


class _RelayedResponse:
    """requests.Response-compatible wrapper around a TestClient response."""

    def __init__(self, response):
        self.status_code = response.status_code
        self.text = response.text

    def json(self):
        return json.loads(self.text)


def _orchestrator_spy():
    spy = MagicMock()
    spy.execute.return_value = MagicMock(
        incident_id="inc-cp",
        proposal_id="remediation-inc-cp",
        source_sha=SHA_A,
        branch_name="automation/remediation/inc-cp/remediation-inc-cp",
        commit_sha="c" * 40,
        pull_request_url="https://github.com/acme/checkout/pull/4242",
        validation_result=MagicMock(passed=True, steps=[]),
    )
    return spy


class ControlPlaneEndToEndTests(unittest.TestCase):
    def setUp(self):
        import deployment_service.main as deployment_main

        self.deployment_client = TestClient(deployment_app)
        self.incident_client = TestClient(
            __import__(
                "incident_service.main", fromlist=["app"]
            ).app
        )
        self.gateway_client = TestClient(
            __import__("api_gateway.main", fromlist=["app"]).app
        )
        self.store = FakeStore()
        self._originals = {
            name: getattr(deployment_main.engine, name)
            for name in (
                "store",
                "validator",
                "terraform",
                "kubectl",
                "health_checker",
                "source_verifier",
            )
        }
        deployment_main.engine.store = self.store
        deployment_main.engine.validator = FakeValidator()
        deployment_main.engine.terraform = FakeTerraform()
        deployment_main.engine.kubectl = FakeKubectl()
        deployment_main.engine.health_checker = FakeHealth()
        deployment_main.engine.source_verifier = FakeSourceVerifier()
        self.addCleanup(self._restore)

        # gateway → downstream transport: routed into the real TestClients
        self.forwarded = []
        patcher = patch(
            "api_gateway.routers.control_plane.requests.post",
            side_effect=self._forward_router,
        )
        self.forward_mock = patcher.start()
        self.addCleanup(patcher.stop)

        self.repository = get_incident_repository()
        self.incident_seq = 0

    def _restore(self):
        import deployment_service.main as deployment_main

        for name, value in self._originals.items():
            setattr(deployment_main.engine, name, value)

    def _forward_router(self, url, json=None, timeout=None):
        self.forwarded.append({"url": url, "json": json})
        path = "/" + url.split("/", 3)[3]
        if url.startswith("http://incident-service"):
            return _RelayedResponse(self.incident_client.post(path, json=json))
        return _RelayedResponse(self.deployment_client.post(path, json=json))

    # ---------- helpers ----------

    def _new_incident(self, title="Checkout 5xx"):
        self.incident_seq += 1
        incident_id = f"inc-cp-{uuid.uuid4().hex[:10]}"
        incident = IncidentAggregate(incident_id, title, "HIGH", "gateway")
        from incident_service.presentation.rest.test_remediation_authorization import (
            promote_to_root_cause_found,
        )

        # canonical precondition for any proposal intake (Phase 8/8.1)
        return promote_to_root_cause_found(incident)

    def _deploy_via_gateway(
        self, repository_name="acme/checkout", head_sha=SHA_A, token=None
    ):
        """dry-run → approve → execute entirely through the gateway."""
        token = token or _operator_token()
        body = dict(VALID_PAYLOAD)
        body.update(
            repository_name=repository_name,
            requested_by="mallory-claimed-identity",
            source_revision=dict(
                VALID_PAYLOAD["source_revision"], head_sha=head_sha
            ),
        )
        dry = self.gateway_client.post(DRY_RUN, json=body, headers=_authed(token))
        self.assertEqual(dry.status_code, 200, dry.text)
        run = dry.json()

        approval = self.gateway_client.post(
            APPROVE.format(run_id=run["id"]),
            json={
                "approved_by": "mallory-claimed-identity",
                "artifact_hash": run["artifact_hash"],
                "plan_hash": run["plan_hash"],
            },
            headers=_authed(token),
        )
        self.assertEqual(approval.status_code, 200, approval.text)

        with patch.dict(os.environ, {"DEPLOYMENT_EXECUTION_ENABLED": "true"}):
            execute = self.gateway_client.post(
                EXECUTE.format(run_id=run["id"]),
                json={
                    "artifact_hash": run["artifact_hash"],
                    "plan_hash": run["plan_hash"],
                    "dockerfile": body["dockerfile"],
                    "k8s_yaml": body["k8s_yaml"],
                    "terraform_tf": body["terraform_tf"],
                    "pipeline_yaml": body["pipeline_yaml"],
                },
                headers=_authed(token),
            )
        self.assertEqual(execute.status_code, 200, execute.text)
        self.assertEqual(execute.json()["state"], "DEPLOYED")
        return execute.json()

    def _collect_evidence(self, run_id):
        router = _route_urlopen_to_test_client(self.deployment_client)
        with patch(
            "incident_service.infrastructure.deployment."
            "deployment_evidence_collector.urlopen",
            side_effect=router,
        ):
            return DeploymentEvidenceCollector(
                base_url="http://deployment-service:8030"
            ).collect(run_id)

    def _incident_with_evidence(self, *run_ids):
        incident = self._new_incident()
        for run_id in run_ids:
            incident.attach_evidence(self._collect_evidence(run_id))
        self.repository.save_incident(incident)
        return incident

    def _remediate_via_gateway(self, incident_id, body, token=None):
        token = token or _operator_token()
        spy = _orchestrator_spy()
        with patch.object(
            controllers_module, "get_remediation_orchestrator", return_value=spy
        ) as provider:
            response = self.gateway_client.post(
                REMEDIATION.format(incident_id=incident_id),
                json=body,
                headers=_authed(token),
            )
        return spy, provider, response

    # ---------- positive chain ----------

    def test_full_chain_operator_dry_run_approve_execute_shim_stops_at_proposal(self):
        token = _operator_token()

        # 1) dry-run: identity stamped from JWT, never from the body
        body = dict(VALID_PAYLOAD)
        body.update(
            repository_name="acme/checkout",
            requested_by="mallory-claimed-identity",
            source_revision=dict(VALID_PAYLOAD["source_revision"], head_sha=SHA_A),
        )
        dry = self.gateway_client.post(DRY_RUN, json=body, headers=_authed(token))
        self.assertEqual(dry.status_code, 200, dry.text)
        run = dry.json()
        self.assertEqual(run["requested_by"], "alice-operator")
        self.assertEqual(run["state"], "AWAITING_APPROVAL")

        # provenance + independent source verification are on the record
        from shared_kernel.domain.provenance import verify_provenance_record

        verify_provenance_record(run["provenance"])
        self.assertEqual(run["provenance"]["state"], "AWAITING_APPROVAL")
        self.assertEqual(
            run["source_verification"]["method"], FakeSourceVerifier.METHOD
        )

        # 2) approve: approved_by stamped from JWT, not from the body
        approval = self.gateway_client.post(
            APPROVE.format(run_id=run["id"]),
            json={
                "approved_by": "mallory-claimed-identity",
                "artifact_hash": run["artifact_hash"],
                "plan_hash": run["plan_hash"],
            },
            headers=_authed(token),
        )
        self.assertEqual(approval.status_code, 200, approval.text)
        self.assertEqual(
            approval.json()["approval"]["approved_by"], "alice-operator"
        )
        self.assertEqual(approval.json()["state"], "APPROVED")

        # 3) execute → DEPLOYED with state-derived provenance
        with patch.dict(os.environ, {"DEPLOYMENT_EXECUTION_ENABLED": "true"}):
            execute = self.gateway_client.post(
                EXECUTE.format(run_id=run["id"]),
                json={
                    "artifact_hash": run["artifact_hash"],
                    "plan_hash": run["plan_hash"],
                    "dockerfile": body["dockerfile"],
                    "k8s_yaml": body["k8s_yaml"],
                    "terraform_tf": body["terraform_tf"],
                    "pipeline_yaml": body["pipeline_yaml"],
                },
                headers=_authed(token),
            )
        self.assertEqual(execute.status_code, 200, execute.text)
        deployed = execute.json()
        self.assertEqual(deployed["state"], "DEPLOYED")
        verify_provenance_record(deployed["provenance"])
        self.assertEqual(deployed["provenance"]["state"], "DEPLOYED")
        self.assertNotEqual(
            deployed["provenance"]["provenance_hash"],
            run["provenance"]["provenance_hash"],
        )

        # 4) evidence → incident (REAL collector over the live endpoint)
        incident = self._incident_with_evidence(deployed["id"])

        # 5) legacy /remediation through the gateway → compatibility shim:
        #    binding passes, but the route STOPS at PROPOSED. No
        #    orchestrator, no PR (Phase 8.1 §42).
        spy, provider, response = self._remediate_via_gateway(
            incident.id,
            {**REMEDIATION_BODY, "source_sha": SHA_A, "repository_slug": "acme/checkout"},
            token=token,
        )
        self.assertEqual(response.status_code, 200, response.text)
        provider.assert_not_called()
        spy.execute.assert_not_called()
        body_json = response.json()
        self.assertEqual(body_json["status"], "PROPOSED")
        self.assertTrue(body_json["compatibility_shim"])
        self.assertFalse(body_json["executed"])
        self.assertNotIn("pull_request_url", body_json)

    # ---------- authentication / role matrix ----------

    def test_unauthenticated_requests_rejected_and_downstream_untouched(self):
        seen_before = len(self.forwarded)
        for route in (DRY_RUN, APPROVE, EXECUTE, REMEDIATION):
            with self.subTest(route=route):
                resp = self.gateway_client.post(route, json={})
                self.assertIn(resp.status_code, (401, 403))
        self.assertEqual(len(self.forwarded), seen_before)

    def test_ordinary_user_cannot_mutate_and_downstream_is_never_called(self):
        seen_before = len(self.forwarded)
        ordinary = _ordinary_token()
        for route in (APPROVE, EXECUTE, REMEDIATION):
            with self.subTest(route=route):
                resp = self.gateway_client.post(
                    route, json={}, headers=_authed(ordinary)
                )
                self.assertEqual(resp.status_code, 403, resp.text)
                self.assertIn("operator role", resp.json()["detail"])
        self.assertEqual(len(self.forwarded), seen_before)

    def test_unverified_source_revision_is_422_and_no_run_exists(self):
        import deployment_service.main as deployment_main

        deployment_main.engine.source_verifier = FakeSourceVerifier(
            accepted_pairs=set()
        )
        token = _operator_token()
        body = dict(VALID_PAYLOAD)
        body.update(
            repository_name="acme/checkout",
            source_revision=dict(
                VALID_PAYLOAD["source_revision"], head_sha="f" * 40
            ),
        )
        resp = self.gateway_client.post(DRY_RUN, json=body, headers=_authed(token))
        self.assertEqual(resp.status_code, 422, resp.text)
        self.assertIn("not found", resp.json()["detail"])
        self.assertEqual(len(self.store.data), 0)

    # ---------- remediation rejection matrix ----------

    def test_wrong_source_sha_is_403_orchestrator_not_constructed(self):
        deployed = self._deploy_via_gateway("acme/checkout", SHA_A)
        incident = self._incident_with_evidence(deployed["id"])

        spy, provider, response = self._remediate_via_gateway(
            incident.id,
            {**REMEDIATION_BODY, "source_sha": SHA_B, "repository_slug": "acme/checkout"},
        )
        self.assertEqual(response.status_code, 403, response.text)
        self.assertIn("pair does not occur", response.json()["detail"])
        provider.assert_not_called()
        spy.execute.assert_not_called()

    def test_wrong_repository_is_403_orchestrator_not_constructed(self):
        deployed = self._deploy_via_gateway("acme/checkout", SHA_A)
        incident = self._incident_with_evidence(deployed["id"])

        spy, provider, response = self._remediate_via_gateway(
            incident.id,
            {**REMEDIATION_BODY, "source_sha": SHA_A, "repository_slug": "evil/checkout"},
        )
        self.assertEqual(response.status_code, 403, response.text)
        provider.assert_not_called()
        spy.execute.assert_not_called()

    def test_cross_evidence_mixing_is_403(self):
        run_a = self._deploy_via_gateway("acme/payment", SHA_A)
        run_b = self._deploy_via_gateway("evil/checkout", SHA_B)
        incident = self._incident_with_evidence(run_a["id"], run_b["id"])

        # repository from B + SHA from A → 403, nothing constructed
        spy, provider, response = self._remediate_via_gateway(
            incident.id,
            {**REMEDIATION_BODY, "source_sha": SHA_A, "repository_slug": "evil/checkout"},
        )
        self.assertEqual(response.status_code, 403, response.text)
        provider.assert_not_called()
        spy.execute.assert_not_called()

        # each record's own pair still works through the gateway
        spy2, provider2, response2 = self._remediate_via_gateway(
            incident.id,
            {**REMEDIATION_BODY, "source_sha": SHA_B, "repository_slug": "evil/checkout"},
        )
        self.assertEqual(response2.status_code, 200, response2.text)
        provider2.assert_not_called()
        spy2.execute.assert_not_called()
        self.assertEqual(response2.json()["status"], "PROPOSED")
        self.assertTrue(response2.json()["compatibility_shim"])

    def test_non_deployed_evidence_is_403(self):
        # dry-run only: state stays AWAITING_APPROVAL, provenance proves it
        token = _operator_token()
        body = dict(VALID_PAYLOAD)
        body.update(
            repository_name="acme/checkout",
            source_revision=dict(VALID_PAYLOAD["source_revision"], head_sha=SHA_A),
        )
        dry = self.gateway_client.post(DRY_RUN, json=body, headers=_authed(token))
        self.assertEqual(dry.status_code, 200, dry.text)
        run = dry.json()
        self.assertEqual(run["state"], "AWAITING_APPROVAL")

        incident = self._incident_with_evidence(run["id"])
        spy, provider, response = self._remediate_via_gateway(
            incident.id,
            {**REMEDIATION_BODY, "source_sha": SHA_A, "repository_slug": "acme/checkout"},
        )
        self.assertEqual(response.status_code, 403, response.text)
        self.assertIn("state=DEPLOYED", response.json()["detail"])
        provider.assert_not_called()
        spy.execute.assert_not_called()

    def test_unknown_incident_remediation_is_404(self):
        spy, provider, response = self._remediate_via_gateway(
            "inc-does-not-exist",
            {**REMEDIATION_BODY, "source_sha": SHA_A, "repository_slug": "acme/checkout"},
        )
        self.assertEqual(response.status_code, 404, response.text)
        provider.assert_not_called()
        spy.execute.assert_not_called()

    def test_unknown_deployment_run_approve_is_rejected(self):
        """Relayed verbatim from the deployment service: an unknown run is
        rejected by the engine (409 with 'not found'), never fabricated."""
        token = _operator_token()
        resp = self.gateway_client.post(
            APPROVE.format(run_id="run-missing"),
            json={"artifact_hash": "a" * 64, "plan_hash": "b" * 64},
            headers=_authed(token),
        )
        self.assertEqual(resp.status_code, 409, resp.text)
        self.assertIn("not found", resp.json()["detail"])


if __name__ == "__main__":
    unittest.main()
