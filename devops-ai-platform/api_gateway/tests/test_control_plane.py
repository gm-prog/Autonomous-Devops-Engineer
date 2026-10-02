"""Control-plane authorization tests (Stage 5 §E/§F/§N).

Proves, at the gateway boundary and before any downstream call:

* no/invalid/expired/wrong-key JWT → 401 on every control-plane route;
* ordinary (non-operator) roles → 403 on approve/execute/remediation, and
  the downstream is NEVER contacted (no existence probing);
* dry-run is open to any authenticated user (requests are inert until an
  operator approves);
* ``requested_by`` / ``approved_by`` are overwritten with the JWT ``sub`` —
  caller-supplied identity strings are discarded;
* downstream status/body are relayed faithfully (404 for unknown ids,
  409 for state-machine rejections) and an unreachable downstream → 502.
"""

import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from api_gateway.core.auth import GatewaySettings, mint_token
from api_gateway.main import app

client = TestClient(app)

DRY_RUN = "/v1/deployments/dry-run"
APPROVE = "/v1/deployments/run-42/approve"
EXECUTE = "/v1/deployments/run-42/execute"
REMEDIATION = "/v1/incidents/inc-42/remediation"
CONTROL_PLANE_ROUTES = (DRY_RUN, APPROVE, EXECUTE, REMEDIATION)
MUTATING_ROUTES = (APPROVE, EXECUTE, REMEDIATION)

CONTROL_PLANE = "api_gateway.routers.control_plane"


def _authed(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _operator(subject="alice-operator"):
    return mint_token(subject, roles=["DevOpsLead"], secret=GatewaySettings.JWT_SECRET)


def _downstream(status_code=200, body=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body if body is not None else {"ok": True}
    resp.text = "..."
    return resp


def _post_mock():
    return patch(f"{CONTROL_PLANE}.requests.post")


class ControlPlaneAuthenticationTests(unittest.TestCase):
    def test_unauthenticated_requests_are_rejected_before_forwarding(self):
        for route in CONTROL_PLANE_ROUTES:
            with self.subTest(route=route), _post_mock() as post:
                resp = client.post(route, json={})
                self.assertIn(resp.status_code, (401, 403))
                post.assert_not_called()

    def test_malformed_token_rejected_before_forwarding(self):
        for route in CONTROL_PLANE_ROUTES:
            with self.subTest(route=route), _post_mock() as post:
                resp = client.post(
                    route,
                    json={},
                    headers=_authed("not-a-jwt"),
                )
                self.assertIn(resp.status_code, (401, 403))
                post.assert_not_called()

    def test_wrong_key_and_expired_tokens_rejected(self):
        wrong_key = mint_token("mallory", secret="some-other-key")
        expired = mint_token(
            "mallory", secret=GatewaySettings.JWT_SECRET, ttl_seconds=-1
        )
        for token, why in ((wrong_key, "wrong-key"), (expired, "expired")):
            with self.subTest(why=why), _post_mock() as post:
                resp = client.post(APPROVE, json={}, headers=_authed(token))
                self.assertIn(resp.status_code, (401, 403))
                post.assert_not_called()


class ControlPlaneRoleAuthorizationTests(unittest.TestCase):
    def test_ordinary_user_cannot_approve_execute_or_remediate(self):
        ordinary = mint_token("bob-developer", roles=["Developer"])
        for route in MUTATING_ROUTES:
            with self.subTest(route=route), _post_mock() as post:
                resp = client.post(route, json={}, headers=_authed(ordinary))
                self.assertEqual(resp.status_code, 403, resp.text)
                self.assertIn("operator role", resp.json()["detail"])
                post.assert_not_called()  # nothing even reaches the network

    def test_roleless_token_is_not_an_operator(self):
        roleless = mint_token("nobody", roles=[])
        with _post_mock() as post:
            resp = client.post(APPROVE, json={}, headers=_authed(roleless))
        self.assertEqual(resp.status_code, 403)
        post.assert_not_called()

    def test_every_documented_operator_role_is_accepted(self):
        for role in ("operator", "DevOpsLead", "ClusterAdmin"):
            with self.subTest(role=role), _post_mock() as post:
                post.return_value = _downstream()
                token = mint_token("op", roles=[role])
                resp = client.post(APPROVE, json={}, headers=_authed(token))
                self.assertEqual(resp.status_code, 200, resp.text)
                post.assert_called_once()

    def test_dry_run_is_open_to_any_authenticated_user(self):
        ordinary = mint_token("bob-developer", roles=["Developer"])
        with _post_mock() as post:
            post.return_value = _downstream()
            resp = client.post(
                DRY_RUN,
                json={"repository_name": "acme/checkout"},
                headers=_authed(ordinary),
            )
        self.assertEqual(resp.status_code, 200, resp.text)
        post.assert_called_once()


class ControlPlaneIdentityTests(unittest.TestCase):
    def test_requested_by_is_stamped_from_the_jwt_subject(self):
        token = mint_token("alice-operator", roles=["DevOpsLead"])
        with _post_mock() as post:
            post.return_value = _downstream()
            resp = client.post(
                DRY_RUN,
                json={"repository_name": "acme/checkout", "requested_by": "mallory"},
                headers=_authed(token),
            )
        self.assertEqual(resp.status_code, 200, resp.text)
        forwarded = post.call_args.kwargs["json"]
        self.assertEqual(forwarded["requested_by"], "alice-operator")
        self.assertEqual(forwarded["repository_name"], "acme/checkout")

    def test_approved_by_is_stamped_from_the_jwt_subject(self):
        token = mint_token("alice-operator", roles=["DevOpsLead"])
        with _post_mock() as post:
            post.return_value = _downstream()
            resp = client.post(
                APPROVE,
                json={"approved_by": "mallory", "artifact_hash": "a" * 64},
                headers=_authed(token),
            )
        self.assertEqual(resp.status_code, 200, resp.text)
        forwarded = post.call_args.kwargs["json"]
        self.assertEqual(forwarded["approved_by"], "alice-operator")
        self.assertNotEqual(forwarded["approved_by"], "mallory")


class ControlPlaneRelayTests(unittest.TestCase):
    def test_downstream_statuses_are_relayed_faithfully(self):
        token = _operator()
        for status, body in (
            (404, {"detail": "Deployment run not found"}),
            (409, {"detail": "Only an APPROVED deployment can execute."}),
            (422, {"detail": "requested source revision was not found"}),
        ):
            with self.subTest(status=status), _post_mock() as post:
                post.return_value = _downstream(status, body)
                resp = client.post(EXECUTE, json={}, headers=_authed(token))
                self.assertEqual(resp.status_code, status)
                self.assertEqual(resp.json(), body)

    def test_unreachable_downstream_is_502(self):
        import requests as requests_lib

        token = _operator()
        with _post_mock() as post:
            post.side_effect = requests_lib.ConnectionError("refused")
            resp = client.post(REMEDIATION, json={}, headers=_authed(token))
        self.assertEqual(resp.status_code, 502)
        self.assertIn("unreachable", resp.json()["detail"])

    def test_internal_prefix_still_404_at_the_gateway(self):
        """Knowing /api/internal/* grants nothing: control-plane auth is on
        named /v1 routes, not on path prefixes."""
        token = _operator()
        resp = client.post(
            "/api/internal/deployments/dry-run", json={}, headers=_authed(token)
        )
        self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()


PROPOSAL_GET = "/v1/incidents/inc-42/proposal"


def _get_mock():
    return patch(f"{CONTROL_PLANE}.requests.get")


class ProposalReadRouteTests(unittest.TestCase):
    """Phase 6.1 §27: proposal read endpoint is authenticated + authorized."""

    def test_unauthenticated_get_is_rejected_before_forwarding(self):
        with _get_mock() as get:
            resp = client.get(PROPOSAL_GET)
        self.assertEqual(resp.status_code, 401)
        get.assert_not_called()

    def test_ordinary_user_cannot_read_proposals(self):
        token = mint_token(
            "bob", roles=["Developer"], secret=GatewaySettings.JWT_SECRET
        )
        with _get_mock() as get:
            resp = client.get(PROPOSAL_GET, headers=_authed(token))
        self.assertEqual(resp.status_code, 403)
        get.assert_not_called()

    def test_operator_get_is_forwarded_and_relayed(self):
        body = {
            "incident_id": "inc-42",
            "proposal": {"status": "PROPOSED", "proposal_hash": "a" * 64},
        }
        token = _operator()
        with _get_mock() as get:
            get.return_value = _downstream(200, body)
            resp = client.get(PROPOSAL_GET, headers=_authed(token))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), body)
        target = get.call_args.args[0]
        self.assertEqual(
            target, "http://incident-service:8050/incidents/inc-42/proposal"
        )
        get.assert_called_once()

    def test_downstream_404_is_relayed(self):
        token = _operator()
        with _get_mock() as get:
            get.return_value = _downstream(
                404, {"detail": "No remediation proposal exists for this incident"}
            )
            resp = client.get(PROPOSAL_GET, headers=_authed(token))
        self.assertEqual(resp.status_code, 404)
        self.assertIn("No remediation proposal", resp.json()["detail"])

    def test_unreachable_downstream_is_502(self):
        import requests as _requests

        token = _operator()
        with _get_mock() as get:
            get.side_effect = _requests.ConnectionError("refused")
            resp = client.get(PROPOSAL_GET, headers=_authed(token))
        self.assertEqual(resp.status_code, 502)

    def test_internal_prefix_still_404_at_the_gateway(self):
        token = _operator()
        with _get_mock() as get:
            resp = client.get(
                "/api/internal/incidents/inc-42/proposal", headers=_authed(token)
            )
        self.assertEqual(resp.status_code, 404)
        get.assert_not_called()


# ---------------------------------------------------------------------------
# Phase 6.2: proposal approval / execution control-plane routes (§6/§21)
# ---------------------------------------------------------------------------

PROPOSAL_APPROVE = "/v1/incidents/inc-42/proposal/approve"
PROPOSAL_EXECUTE = "/v1/incidents/inc-42/proposal/execute"
PROPOSAL_ACTION_ROUTES = (PROPOSAL_APPROVE, PROPOSAL_EXECUTE)

_PROPOSAL_BODY = {
    "proposal_id": "proposal-inc-42",
    "proposal_hash": "a" * 64,
    "approved_by": "mallory",
    "requested_by": "mallory",
}


class ProposalExecutionRouteTests(unittest.TestCase):
    """Proposal approve/execute require JWT + operator role at the gateway
    and always stamp the verified identity over caller-supplied fields."""

    def test_unauthenticated_requests_are_rejected_before_forwarding(self):
        for route in PROPOSAL_ACTION_ROUTES:
            with self.subTest(route=route), _post_mock() as post:
                resp = client.post(route, json=_PROPOSAL_BODY)
                self.assertIn(resp.status_code, (401, 403))
                post.assert_not_called()

    def test_ordinary_user_cannot_approve_or_execute_proposals(self):
        ordinary = mint_token("bob-developer", roles=["Developer"])
        for route in PROPOSAL_ACTION_ROUTES:
            with self.subTest(route=route), _post_mock() as post:
                resp = client.post(
                    route, json=_PROPOSAL_BODY, headers=_authed(ordinary)
                )
                self.assertEqual(resp.status_code, 403, resp.text)
                self.assertIn("operator role", resp.json()["detail"])
                post.assert_not_called()

    def test_operator_identity_is_stamped_over_request_strings(self):
        token = mint_token("alice-operator", roles=["DevOpsLead"])
        for route, field in (
            (PROPOSAL_APPROVE, "approved_by"),
            (PROPOSAL_EXECUTE, "requested_by"),
        ):
            with self.subTest(route=route), _post_mock() as post:
                post.return_value = _downstream()
                resp = client.post(
                    route, json=_PROPOSAL_BODY, headers=_authed(token)
                )
                self.assertEqual(resp.status_code, 200, resp.text)
                forwarded = post.call_args.kwargs["json"]
                self.assertEqual(forwarded[field], "alice-operator")
                self.assertNotEqual(forwarded[field], "mallory")
                # trusted inputs preserved verbatim
                self.assertEqual(forwarded["proposal_id"], "proposal-inc-42")
                self.assertEqual(forwarded["proposal_hash"], "a" * 64)
                # forwarded to the incident service proposal endpoints
                self.assertTrue(
                    post.call_args.args[0].endswith(
                        f"/incidents/inc-42/proposal/{route.rsplit('/', 1)[-1]}"
                    ),
                    post.call_args.args[0],
                )

    def test_all_documented_operator_roles_are_accepted(self):
        for role in ("operator", "DevOpsLead", "ClusterAdmin"):
            for route in PROPOSAL_ACTION_ROUTES:
                with self.subTest(role=role, route=route), _post_mock() as post:
                    post.return_value = _downstream()
                    token = mint_token("op", roles=[role])
                    resp = client.post(
                        route, json=_PROPOSAL_BODY, headers=_authed(token)
                    )
                    self.assertEqual(resp.status_code, 200, resp.text)

    def test_downstream_statuses_are_relayed(self):
        token = _operator()
        for status, body in (
            (409, {"detail": "proposal status PROPOSED cannot execute"}),
            (422, {"detail": "supplied proposal_hash does not match"}),
            (403, {"detail": "authoritative deployment target no longer matches"}),
        ):
            with self.subTest(status=status), _post_mock() as post:
                post.return_value = _downstream(status, body)
                resp = client.post(
                    PROPOSAL_EXECUTE, json=_PROPOSAL_BODY, headers=_authed(token)
                )
                self.assertEqual(resp.status_code, status)
                self.assertEqual(resp.json(), body)

    def test_unreachable_downstream_is_502(self):
        import requests as requests_lib

        token = _operator()
        with _post_mock() as post:
            post.side_effect = requests_lib.ConnectionError("refused")
            resp = client.post(
                PROPOSAL_EXECUTE, json=_PROPOSAL_BODY, headers=_authed(token)
            )
        self.assertEqual(resp.status_code, 502)
        self.assertIn("unreachable", resp.json()["detail"])

    def test_internal_prefix_grants_nothing(self):
        token = _operator()
        for path in (
            "/api/internal/incidents/inc-42/proposal/approve",
            "/api/internal/incidents/inc-42/proposal/execute",
        ):
            with self.subTest(path=path), _post_mock() as post:
                resp = client.post(
                    path, json=_PROPOSAL_BODY, headers=_authed(token)
                )
                self.assertEqual(resp.status_code, 404)
                post.assert_not_called()


# --------------------------------------------------------------------------- #
# Phase 6.3: operational analytics summary (authenticated, read-only forward)
# --------------------------------------------------------------------------- #

ANALYTICS_GET = (
    "/v1/analytics/summary"
    "?start=2026-09-01T00%3A00%3A00Z&end=2026-09-08T00%3A00%3A00Z"
)
ANALYTICS_DOWNSTREAM = (
    "http://incident-service:8050/incidents/analytics/summary"
    "?start=2026-09-01T00%3A00%3A00Z&end=2026-09-08T00%3A00%3A00Z"
)


class AnalyticsSummaryRouteTests(unittest.TestCase):
    """Phase 6.3: gateway authentication + verbatim GET forward.

    Analytics aggregates are read-only and expose no patch content, so
    any authenticated user may read them (``verify_token`` only) — unlike
    the proposal read route which requires an operator role.
    """

    def test_unauthenticated_get_is_rejected_before_forwarding(self):
        with _get_mock() as get:
            resp = client.get(ANALYTICS_GET)
        self.assertEqual(resp.status_code, 401)
        get.assert_not_called()

    def test_malformed_token_is_rejected_before_forwarding(self):
        with _get_mock() as get:
            resp = client.get(ANALYTICS_GET, headers=_authed("not-a-jwt"))
        self.assertEqual(resp.status_code, 401)
        get.assert_not_called()

    def test_any_authenticated_user_may_read_aggregates(self):
        token = mint_token("bob-developer", roles=["Developer"])
        body = {"window": {"timezone": "UTC"}, "incidents": {"total": 3}}
        with _get_mock() as get:
            get.return_value = _downstream(200, body)
            resp = client.get(ANALYTICS_GET, headers=_authed(token))
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json(), body)
        self.assertEqual(get.call_args.args[0], ANALYTICS_DOWNSTREAM)
        get.assert_called_once()

    def test_operator_get_is_forwarded_and_relayed(self):
        token = _operator()
        body = {"incidents": {"total": 0}, "unsupported": []}
        with _get_mock() as get:
            get.return_value = _downstream(200, body)
            resp = client.get(ANALYTICS_GET, headers=_authed(token))
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json(), body)
        get.assert_called_once()

    def test_downstream_window_rejection_is_relayed(self):
        token = mint_token("bob-developer", roles=["Developer"])
        with _get_mock() as get:
            get.return_value = _downstream(
                422, {"detail": "window must not exceed 31 days"}
            )
            resp = client.get(ANALYTICS_GET, headers=_authed(token))
        self.assertEqual(resp.status_code, 422)
        self.assertIn("31 days", resp.json()["detail"])

    def test_unreachable_downstream_is_502(self):
        import requests as requests_lib

        token = mint_token("bob-developer", roles=["Developer"])
        with _get_mock() as get:
            get.side_effect = requests_lib.ConnectionError("refused")
            resp = client.get(ANALYTICS_GET, headers=_authed(token))
        self.assertEqual(resp.status_code, 502)

    def test_internal_prefix_grants_nothing(self):
        token = mint_token("bob-developer", roles=["Developer"])
        with _get_mock() as get:
            resp = client.get(
                "/api/internal/analytics/summary?start=x&end=y",
                headers=_authed(token),
            )
        self.assertEqual(resp.status_code, 404)
        get.assert_not_called()


# --------------------------------------------------------------------------- #
# Phase 6.4: change-intelligence release health (authenticated, read-only)
# --------------------------------------------------------------------------- #

CHANGES_HEALTH_GET = (
    "/v1/changes/run-9/health"
    "?start=2026-09-01T00%3A00%3A00Z&end=2026-09-08T00%3A00%3A00Z"
)
CHANGES_HEALTH_DOWNSTREAM = (
    "http://incident-service:8050/changes/run-9/health"
    "?start=2026-09-01T00%3A00%3A00Z&end=2026-09-08T00%3A00%3A00Z"
)


class ChangeHealthRouteTests(unittest.TestCase):
    """Phase 6.4: gateway authentication + verbatim GET forward.

    Read-only assessment (no patch content): any authenticated user may
    read it, mirroring the analytics summary route.
    """

    def test_unauthenticated_get_is_rejected_before_forwarding(self):
        with _get_mock() as get:
            resp = client.get(CHANGES_HEALTH_GET)
        self.assertEqual(resp.status_code, 401)
        get.assert_not_called()

    def test_malformed_token_is_rejected_before_forwarding(self):
        with _get_mock() as get:
            resp = client.get(CHANGES_HEALTH_GET, headers=_authed("not-a-jwt"))
        self.assertEqual(resp.status_code, 401)
        get.assert_not_called()

    def test_any_authenticated_user_may_read_the_assessment(self):
        token = mint_token("bob-developer", roles=["Developer"])
        body = {"decision": "HEALTHY", "reasons": ["all_required_evidence_healthy"]}
        with _get_mock() as get:
            get.return_value = _downstream(200, body)
            resp = client.get(CHANGES_HEALTH_GET, headers=_authed(token))
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json(), body)
        self.assertEqual(get.call_args.args[0], CHANGES_HEALTH_DOWNSTREAM)
        get.assert_called_once()

    def test_downstream_unknown_deployment_404_is_relayed(self):
        token = mint_token("bob-developer", roles=["Developer"])
        with _get_mock() as get:
            get.return_value = _downstream(
                404, {"detail": "no deployment-run evidence for 'run-9' within the observation window"}
            )
            resp = client.get(CHANGES_HEALTH_GET, headers=_authed(token))
        self.assertEqual(resp.status_code, 404)
        self.assertIn("no deployment-run evidence", resp.json()["detail"])

    def test_downstream_window_rejection_422_is_relayed(self):
        token = _operator()
        with _get_mock() as get:
            get.return_value = _downstream(
                422, {"detail": "window must not exceed 31 days"}
            )
            resp = client.get(CHANGES_HEALTH_GET, headers=_authed(token))
        self.assertEqual(resp.status_code, 422)
        self.assertIn("31 days", resp.json()["detail"])

    def test_unreachable_downstream_is_502(self):
        import requests as requests_lib

        token = mint_token("bob-developer", roles=["Developer"])
        with _get_mock() as get:
            get.side_effect = requests_lib.ConnectionError("refused")
            resp = client.get(CHANGES_HEALTH_GET, headers=_authed(token))
        self.assertEqual(resp.status_code, 502)

    def test_internal_prefix_grants_nothing(self):
        token = mint_token("bob-developer", roles=["Developer"])
        with _get_mock() as get:
            resp = client.get(
                "/api/internal/changes/run-9/health?start=x&end=y",
                headers=_authed(token),
            )
        self.assertEqual(resp.status_code, 404)
        get.assert_not_called()


# --------------------------------------------------------------------------- #
# Phase 6.5: change-aware live release verification (authenticated, read-only)
# --------------------------------------------------------------------------- #

CHANGES_LIVE_GET = (
    "/v1/changes/run-9/live-health"
    "?start=2026-09-01T00%3A00%3A00Z&end=2026-09-08T00%3A00%3A00Z"
)
CHANGES_LIVE_DOWNSTREAM = (
    "http://incident-service:8050/changes/run-9/live-health"
    "?start=2026-09-01T00%3A00%3A00Z&end=2026-09-08T00%3A00%3A00Z"
)
CHANGES_LIVE_BASELINE_GET = CHANGES_LIVE_GET + "&baseline_deployment_run_id=run-8"
CHANGES_LIVE_BASELINE_DOWNSTREAM = CHANGES_LIVE_DOWNSTREAM + (
    "&baseline_deployment_run_id=run-8"
)


class ChangeLiveHealthRouteTests(unittest.TestCase):
    """Phase 6.5: gateway authentication + verbatim GET forward.

    Read-only combined durable + live assessment (no patch content):
    any authenticated user may read it, mirroring the health route.
    """

    def test_unauthenticated_get_is_rejected_before_forwarding(self):
        with _get_mock() as get:
            resp = client.get(CHANGES_LIVE_GET)
        self.assertEqual(resp.status_code, 401)
        get.assert_not_called()

    def test_malformed_token_is_rejected_before_forwarding(self):
        with _get_mock() as get:
            resp = client.get(CHANGES_LIVE_GET, headers=_authed("not-a-jwt"))
        self.assertEqual(resp.status_code, 401)
        get.assert_not_called()

    def test_any_authenticated_user_may_read_the_assessment(self):
        token = mint_token("bob-developer", roles=["Developer"])
        body = {
            "durable_assessment": {"decision": "HEALTHY"},
            "live_assessment": {"decision": "INCONCLUSIVE", "reasons": []},
        }
        with _get_mock() as get:
            get.return_value = _downstream(200, body)
            resp = client.get(CHANGES_LIVE_GET, headers=_authed(token))
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json(), body)
        self.assertEqual(get.call_args.args[0], CHANGES_LIVE_DOWNSTREAM)
        get.assert_called_once()

    def test_baseline_parameter_is_forwarded_verbatim(self):
        token = mint_token("bob-developer", roles=["Developer"])
        with _get_mock() as get:
            get.return_value = _downstream(200, {"live_assessment": {}})
            resp = client.get(
                CHANGES_LIVE_BASELINE_GET, headers=_authed(token)
            )
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(get.call_args.args[0], CHANGES_LIVE_BASELINE_DOWNSTREAM)

    def test_downstream_unknown_deployment_404_is_relayed(self):
        token = mint_token("bob-developer", roles=["Developer"])
        with _get_mock() as get:
            get.return_value = _downstream(
                404, {"detail": "no deployment-run evidence for 'run-9' within the observation window"}
            )
            resp = client.get(CHANGES_LIVE_GET, headers=_authed(token))
        self.assertEqual(resp.status_code, 404)
        self.assertIn("no deployment-run evidence", resp.json()["detail"])

    def test_downstream_window_rejection_422_is_relayed(self):
        token = _operator()
        with _get_mock() as get:
            get.return_value = _downstream(
                422, {"detail": "window must not exceed 31 days"}
            )
            resp = client.get(CHANGES_LIVE_GET, headers=_authed(token))
        self.assertEqual(resp.status_code, 422)
        self.assertIn("31 days", resp.json()["detail"])

    def test_unreachable_downstream_is_502(self):
        import requests as requests_lib

        token = mint_token("bob-developer", roles=["Developer"])
        with _get_mock() as get:
            get.side_effect = requests_lib.ConnectionError("refused")
            resp = client.get(CHANGES_LIVE_GET, headers=_authed(token))
        self.assertEqual(resp.status_code, 502)

    def test_internal_prefix_grants_nothing(self):
        token = mint_token("bob-developer", roles=["Developer"])
        with _get_mock() as get:
            resp = client.get(
                "/api/internal/changes/run-9/live-health?start=x&end=y",
                headers=_authed(token),
            )
        self.assertEqual(resp.status_code, 404)
        get.assert_not_called()


# --------------------------------------------------------------------------- #
# Phase 6.6.1: durable gate-analysis history (authenticated, read-only GET)
# --------------------------------------------------------------------------- #

GATE_HISTORY_GET = "/v1/changes/run-gate-1/gate/history?limit=25"
GATE_HISTORY_DOWNSTREAM = (
    "http://incident-service:8050/changes/run-gate-1/gate/history?limit=25"
)


class GateHistoryRouteTests(unittest.TestCase):
    def test_unauthenticated_history_is_rejected_before_forwarding(self):
        with _get_mock() as get:
            resp = client.get(GATE_HISTORY_GET)
        self.assertEqual(resp.status_code, 401)
        get.assert_not_called()

    def test_authenticated_history_is_forwarded_verbatim(self):
        token = mint_token("bob-developer", roles=["Developer"])
        body = {
            "deployment_run_id": "run-gate-1",
            "count": 1,
            "evaluations": [{"evaluation_id": "eval-1", "fresh": True}],
            "policy_version": "6.6.1",
        }
        with _get_mock() as get:
            get.return_value = _downstream(200, body)
            resp = client.get(GATE_HISTORY_GET, headers=_authed(token))
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json(), body)
        self.assertEqual(get.call_args.args[0], GATE_HISTORY_DOWNSTREAM)
        get.assert_called_once()

    def test_history_downstream_errors_are_relayed(self):
        token = mint_token("bob-developer", roles=["Developer"])
        with _get_mock() as get:
            get.return_value = _downstream(
                422, {"detail": "limit must be an integer between 1 and 100"}
            )
            resp = client.get(GATE_HISTORY_GET, headers=_authed(token))
        self.assertEqual(resp.status_code, 422)
        self.assertEqual(resp.json()["detail"], "limit must be an integer between 1 and 100")

    def test_history_is_read_only_get(self):
        token = mint_token("bob-developer", roles=["Developer"])
        with _get_mock() as get:
            get.return_value = _downstream(200, {"count": 0, "evaluations": []})
            resp = client.get(GATE_HISTORY_GET, headers=_authed(token))
        self.assertEqual(resp.status_code, 200)
        get.assert_called_once()


# --------------------------------------------------------------------------- #
# Phase 6.6.2: durable rollout-stage state (authenticated read + operator
# transition; forward/relay only — the gateway performs no rollout itself)
# --------------------------------------------------------------------------- #

ROLLOUT_STATE_GET = "/v1/changes/run-rollout-1/rollout-state"
ROLLOUT_STATE_DOWNSTREAM = (
    "http://incident-service:8050/changes/run-rollout-1/rollout-state"
)
ROLLOUT_TRANSITION = "/v1/changes/run-rollout-1/rollout-state/transition"
ROLLOUT_TRANSITION_DOWNSTREAM = (
    "http://incident-service:8050/changes/run-rollout-1/"
    "rollout-state/transition"
)


class RolloutStateRouteTests(unittest.TestCase):
    def test_unauthenticated_read_is_rejected_before_forwarding(self):
        with _get_mock() as get:
            resp = client.get(ROLLOUT_STATE_GET)
        self.assertEqual(resp.status_code, 401)
        get.assert_not_called()

    def test_authenticated_read_is_forwarded_verbatim(self):
        token = mint_token("bob-developer", roles=["Developer"])
        body = {
            "stage_state_id": "rst_x",
            "deployment_run_id": "run-rollout-1",
            "source_sha": "a" * 40,
            "repository": "acme/checkout",
            "current_percentage": 25,
            "previous_percentage": 5,
            "state": "ACTIVE",
            "last_gate_evaluation_id": "eval-1",
            "last_gate_decision": "PROMOTE",
            "observation_start": "2026-09-01T00:00:00+00:00",
            "observation_end": "2026-09-08T00:00:00+00:00",
            "updated_at": "2026-09-08T12:00:00+00:00",
        }
        with _get_mock() as get:
            get.return_value = _downstream(200, body)
            resp = client.get(ROLLOUT_STATE_GET, headers=_authed(token))
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json(), body)
        self.assertEqual(get.call_args.args[0], ROLLOUT_STATE_DOWNSTREAM)
        get.assert_called_once()

    def test_read_missing_state_is_relayed_as_404(self):
        token = mint_token("bob-developer", roles=["Developer"])
        with _get_mock() as get:
            get.return_value = _downstream(
                404, {"detail": "rollout state not found"}
            )
            resp = client.get(ROLLOUT_STATE_GET, headers=_authed(token))
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.json()["detail"], "rollout state not found")

    def test_unauthenticated_transition_is_rejected_before_forwarding(self):
        with _post_mock() as post:
            resp = client.post(ROLLOUT_TRANSITION, json={})
        self.assertEqual(resp.status_code, 401)
        post.assert_not_called()

    def test_non_operator_cannot_transition_before_forwarding(self):
        token = mint_token("bob-developer", roles=["Developer"])
        with _post_mock() as post:
            resp = client.post(
                ROLLOUT_TRANSITION,
                json={"expected_percentage": 5},
                headers=_authed(token),
            )
        self.assertEqual(resp.status_code, 403)
        self.assertIn("operator role", resp.json()["detail"])
        post.assert_not_called()  # no existence probing downstream

    def test_operator_transition_is_forwarded_verbatim(self):
        payload = {
            "expected_percentage": 5,
            "target_percentage": 25,
            "evaluation_id": "eval-1",
            "source_sha": "a" * 40,
        }
        body = {
            "deployment_run_id": "run-rollout-1",
            "current_percentage": 25,
            "previous_percentage": 5,
            "state": "ACTIVE",
        }
        with _post_mock() as post:
            post.return_value = _downstream(200, body)
            resp = client.post(
                ROLLOUT_TRANSITION,
                json=payload,
                headers=_authed(_operator()),
            )
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json(), body)
        self.assertEqual(
            post.call_args.args[0], ROLLOUT_TRANSITION_DOWNSTREAM
        )
        self.assertEqual(post.call_args.kwargs["json"], payload)
        post.assert_called_once()

    def test_downstream_conflicts_and_validation_errors_are_relayed(self):
        for status, detail in (
            (409, "expected_percentage does not match the durable stage"),
            (422, "target_percentage must be one of: 5, 25, 50, 100"),
            (404, "gate evaluation not found"),
        ):
            with self.subTest(status=status), _post_mock() as post:
                post.return_value = _downstream(status, {"detail": detail})
                resp = client.post(
                    ROLLOUT_TRANSITION,
                    json={
                        "expected_percentage": 5,
                        "target_percentage": 25,
                        "evaluation_id": "eval-1",
                        "source_sha": "a" * 40,
                    },
                    headers=_authed(_operator()),
                )
            self.assertEqual(resp.status_code, status)
            self.assertEqual(resp.json()["detail"], detail)
