"""Gateway seams for the Phase 8.4 staging golden path (§3).

Covers the five newly added control-plane routes:

* GET  /v1/incidents                       (authenticated, read-only)
* GET  /v1/incidents/{id}                  (authenticated, read-only)
* POST /v1/incidents/{id}/deployment-evidence (operator)
* POST /v1/incidents/{id}/rca              (operator)
* POST /v1/incidents/{id}/proposal         (operator, generation)

Security contract: 401 without/with malformed JWT, 403 for non-operator
on every mutating route (downstream never contacted), faithful relay of
downstream 404/502 — matching the existing control-plane test matrix.
"""

import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from api_gateway.core.auth import GatewaySettings, mint_token
from api_gateway.main import app

CONTROL_PLANE = "api_gateway.routers.control_plane"

client = TestClient(app)

LIST_INCIDENTS = "/v1/incidents"
GET_INCIDENT = "/v1/incidents/{incident_id}"
EVIDENCE = "/v1/incidents/{incident_id}/deployment-evidence"
RCA = "/v1/incidents/{incident_id}/rca"
PROPOSAL = "/v1/incidents/{incident_id}/proposal"

READ_ROUTES = (LIST_INCIDENTS, GET_INCIDENT)
MUTATING_ROUTES = (EVIDENCE, RCA, PROPOSAL)


def _authed(token):
    return {"Authorization": f"Bearer {token}"}


def _operator(subject="alice-operator"):
    return mint_token(subject, roles=["DevOpsLead"], secret=GatewaySettings.JWT_SECRET)


def _ordinary(subject="bob-developer"):
    return mint_token(subject, roles=["Developer"], secret=GatewaySettings.JWT_SECRET)


def _fill(route):
    return route.format(incident_id="inc-123")


class IncidentSeamAuthTests(unittest.TestCase):
    def test_unauthenticated_requests_rejected_before_forwarding(self):
        for route in READ_ROUTES + MUTATING_ROUTES:
            with self.subTest(route=route), patch(
                f"{CONTROL_PLANE}.requests.post"
            ) as post, patch(f"{CONTROL_PLANE}.requests.get") as get:
                response = client.get(_fill(route)) if route in READ_ROUTES else client.post(_fill(route), json={})
                self.assertEqual(response.status_code, 401, response.text)
                post.assert_not_called()
                get.assert_not_called()

    def test_malformed_token_rejected(self):
        for route in READ_ROUTES + MUTATING_ROUTES:
            with self.subTest(route=route):
                kwargs = (
                    {}
                    if route in READ_ROUTES
                    else {"json": {}}
                )
                method = client.get if route in READ_ROUTES else client.post
                response = method(
                    _fill(route), headers=_authed("not-a-jwt"), **kwargs
                )
                self.assertEqual(response.status_code, 401, response.text)

    def test_non_operator_blocked_on_mutating_seams_without_downstream_call(self):
        for route in MUTATING_ROUTES:
            with self.subTest(route=route), patch(
                f"{CONTROL_PLANE}.requests.post"
            ) as post:
                response = client.post(
                    _fill(route),
                    headers=_authed(_ordinary()),
                    json={"deployment_run_id": "run_1"},
                )
                self.assertEqual(response.status_code, 403, response.text)
                post.assert_not_called()

    def test_read_routes_allowed_for_ordinary_authenticated_user(self):
        for route in READ_ROUTES:
            with self.subTest(route=route), patch(
                f"{CONTROL_PLANE}.requests.get", return_value=_FakeResponse(200, [])
            ):
                response = client.get(_fill(route), headers=_authed(_ordinary()))
                self.assertEqual(response.status_code, 200, response.text)


class _FakeResponse:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body

    def json(self):
        return self._body

    @property
    def text(self):
        return str(self._body)


class IncidentSeamForwardingTests(unittest.TestCase):
    def test_operator_mutating_routes_forward_to_incident_service(self):
        for route in MUTATING_ROUTES:
            with self.subTest(route=route), patch(
                f"{CONTROL_PLANE}.requests.post",
                return_value=_FakeResponse(200, {"ok": True}),
            ) as post:
                response = client.post(
                    _fill(route),
                    headers=_authed(_operator()),
                    json={"deployment_run_id": "run_1"},
                )
                self.assertEqual(response.status_code, 200, response.text)
                target = post.call_args.kwargs.get("url") or post.call_args.args[0]
                self.assertIn("/incidents/inc-123", target)
                self.assertTrue(
                    target.endswith(route.format(incident_id="inc-123").split("/v1", 1)[1])
                    or route.split("{")[0] in target
                )

    def test_downstream_404_is_relayed_faithfully(self):
        with patch(
            f"{CONTROL_PLANE}.requests.get",
            return_value=_FakeResponse(404, {"detail": "Incident not found"}),
        ):
            response = client.get(
                _fill(GET_INCIDENT), headers=_authed(_operator())
            )
            self.assertEqual(response.status_code, 404)
            self.assertEqual(response.json().get("detail"), "Incident not found")

    def test_unreachable_downstream_is_502_not_success(self):
        import requests as requests_lib

        with patch(
            f"{CONTROL_PLANE}.requests.post",
            side_effect=requests_lib.ConnectionError("refused"),
        ):
            response = client.post(
                _fill(RCA), headers=_authed(_operator()), json={}
            )
            self.assertEqual(response.status_code, 502, response.text)

    def test_evidence_payload_is_forwarded_without_identity_trusting(self):
        with patch(
            f"{CONTROL_PLANE}.requests.post",
            return_value=_FakeResponse(200, {"ok": True}),
        ) as post:
            response = client.post(
                _fill(EVIDENCE),
                headers=_authed(_operator()),
                json={"deployment_run_id": "run_9"},
            )
            self.assertEqual(response.status_code, 200, response.text)
            forwarded = post.call_args.kwargs.get("json") or post.call_args.args[1]
            self.assertEqual(forwarded, {"deployment_run_id": "run_9"})
