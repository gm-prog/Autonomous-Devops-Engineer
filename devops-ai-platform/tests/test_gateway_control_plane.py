"""Phase 8.7-C — Defect A acceptance tests: the gateway is NOT a telemetry
trust boundary and NOT a generic internal-service tunnel.

Acceptance criteria covered:

* Test 1 — an ordinary authenticated user (Developer) cannot inject telemetry.
* Test 2 — operator roles (operator / DevOpsLead / ClusterAdmin) cannot
  impersonate the telemetry producer through the gateway either.
* Test 6 — the generic dispatch surface cannot be used as an arbitrary
  privileged internal-service tunnel (structural + behavioral).
* Cross-system authorization matrix (gateway control-plane columns):
    unauthenticated / Developer / ordinary user / operator
    vs proposal approval and proposal execution.
"""

from __future__ import annotations

import pytest

from conftest import make_token

DISPATCH_PATHS = (
    "/v1/gateway/dispatch/monitoring",
    "/v1/gateway/dispatch/repo",
    "/v1/gateway/dispatch/agent",
    "/v1/gateway/dispatch/deployment",
    "/v1/gateway/dispatch/incident",
    "/v1/gateway/dispatch",
)

TELEMETRY_PAYLOAD = {
    "service_id": "spring-gateway",
    "metric_name": "cpu_percent",
    "value": 99.5,
    "unit": "percent",
}


class FakeDownstream:
    """Records every downstream call the gateway attempts to make."""

    def __init__(self):
        self.calls: list = []

    def call(self, method, url, json_body, authorizing_identity):
        self.calls.append({"method": method, "url": url,
                           "body": json_body, "identity": authorizing_identity})
        return {"status": "DOWNSTREAM_OK"}


# ---------------------------------------------------------------------------
# Generic dispatch surface: structurally and behaviorally unavailable
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", DISPATCH_PATHS)
@pytest.mark.parametrize(
    "token",
    [
        make_token("dev-1", ["Developer"]),
        make_token("op-1", ["operator"]),
        make_token("lead-1", ["DevOpsLead"]),
        make_token("admin-1", ["ClusterAdmin"]),
        None,  # unauthenticated
    ],
    ids=["developer", "operator", "devops-lead", "cluster-admin", "anonymous"],
)
def test_generic_dispatch_is_unavailable_for_every_actor(gateway_client, path, token):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    resp = gateway_client.post(path, json=TELEMETRY_PAYLOAD, headers=headers)
    # The route must not exist at all: no 200, no 403/401 passthrough, no
    # forwarding.  FastAPI answers unmatched paths with 404.
    assert resp.status_code in (404, 405), f"{path} with {headers} -> {resp.status_code}"
    assert "monitoring-service" not in resp.text


def test_openapi_surface_contains_no_dispatch_or_monitoring_route(gateway_client):
    spec = gateway_client.get("/openapi.json").json()
    paths = list(spec["paths"].keys())
    for path in paths:
        assert "dispatch" not in path.lower(), f"dispatch route restored: {path}"
    # No gateway route may target the monitoring service.
    assert not any("monitoring" in p.lower() for p in paths)
    assert "/v1/gateway/metrics" in paths  # existing surface preserved


def test_routing_table_excludes_monitoring():
    from platform_pkg.api_gateway.routers import gateway_router

    assert "monitoring" not in gateway_router.SERVICES
    assert set(gateway_router.SERVICES) == {"repo", "agent", "deployment", "incident"}


# ---------------------------------------------------------------------------
# Typed control-plane operations: proposal approval / execution
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "roles,expected",
    [
        (["Developer"], 403),
        (["Viewer"], 403),
        (["user"], 403),
        (["operator"], 200),
        (["DevOpsLead"], 200),
        (["ClusterAdmin"], 200),
        (["Developer", "operator"], 200),  # operator among roles grants
    ],
    ids=["developer", "viewer", "ordinary", "operator", "devops-lead",
         "cluster-admin", "developer-plus-operator"],
)
def test_proposal_approval_role_matrix(gateway_client, gateway_app, roles, expected):
    from platform_pkg.api_gateway.routers.gateway_router import get_downstream_transport

    transport = FakeDownstream()
    gateway_app.dependency_overrides[get_downstream_transport] = lambda: transport
    token = make_token("actor", roles)
    resp = gateway_client.post(
        "/v1/gateway/incidents/inc_1/proposals/pr_9/approve",
        json={"expected_state": "PendingApproval", "approver_note": "approved"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == expected
    if expected == 200:
        assert len(transport.calls) == 1
        call = transport.calls[0]
        assert call["url"].startswith("http://incident-service:8050/api/internal/incidents/inc_1/proposals/pr_9/approve")
        # Only the typed payload is forwarded — no arbitrary relay.
        assert set(call["body"]) == {"expected_state", "approver_note", "authorizing_identity"}
    else:
        assert transport.calls == []


def test_proposal_execution_role_matrix(gateway_client, gateway_app):
    from platform_pkg.api_gateway.routers.gateway_router import get_downstream_transport

    transport = FakeDownstream()
    gateway_app.dependency_overrides[get_downstream_transport] = lambda: transport

    dev = make_token("dev-1", ["Developer"])
    resp = gateway_client.post(
        "/v1/gateway/incidents/inc_1/proposals/pr_9/execute",
        json={}, headers={"Authorization": f"Bearer {dev}"},
    )
    assert resp.status_code == 403
    assert transport.calls == []

    op = make_token("op-1", ["operator"])
    resp = gateway_client.post(
        "/v1/gateway/incidents/inc_1/proposals/pr_9/execute",
        json={"expected_state": "Approved"},
        headers={"Authorization": f"Bearer {op}"},
    )
    assert resp.status_code == 200
    assert len(transport.calls) == 1


def test_control_plane_requires_typed_payload(gateway_client, gateway_app):
    from platform_pkg.api_gateway.routers.gateway_router import get_downstream_transport

    transport = FakeDownstream()
    gateway_app.dependency_overrides[get_downstream_transport] = lambda: transport
    op = make_token("op-1", ["operator"])
    # Wrong field type on the typed model -> rejected before forwarding.
    resp = gateway_client.post(
        "/v1/gateway/incidents/inc_1/proposals/pr_9/approve",
        json={"expected_state": 12345},
        headers={"Authorization": f"Bearer {op}"},
    )
    assert resp.status_code == 422
    assert transport.calls == []


def test_unauthenticated_control_plane_denied(gateway_client, gateway_app):
    from platform_pkg.api_gateway.routers.gateway_router import get_downstream_transport

    transport = FakeDownstream()
    gateway_app.dependency_overrides[get_downstream_transport] = lambda: transport
    resp = gateway_client.post(
        "/v1/gateway/incidents/inc_1/proposals/pr_9/approve", json={}
    )
    assert resp.status_code == 401
    assert transport.calls == []

    resp = gateway_client.get("/v1/gateway/metrics")
    assert resp.status_code == 401


def test_invalid_or_forged_tokens_denied(gateway_client):
    # A token signed with the wrong secret (forged) must be rejected.
    forged = make_token("attacker", ["ClusterAdmin"], secret="not-the-gateway-secret")
    resp = gateway_client.get(
        "/v1/gateway/metrics", headers={"Authorization": f"Bearer {forged}"}
    )
    assert resp.status_code == 401

    resp = gateway_client.get(
        "/v1/gateway/metrics", headers={"Authorization": "Bearer garbage-token-12345"}
    )
    assert resp.status_code == 401

    # The retired mock magic token must no longer authenticate.
    resp = gateway_client.get(
        "/v1/gateway/metrics", headers={"Authorization": "Bearer mock-devops-admin-token-1842"}
    )
    assert resp.status_code == 401


def test_app_verifies_with_its_own_startup_secret():
    """Each app instance authenticates with exactly the secret it started
    with — a token valid for another gateway process is rejected here."""
    from fastapi.testclient import TestClient

    from platform_pkg.api_gateway.main import create_app

    app_secret = "another-startup-secret-0123456789"
    app = create_app(env={"JWT_SECRET": app_secret, "APP_ENV": "production",
                            "ANALYSIS_RATE_LIMIT_SINGLE_INSTANCE_PRODUCTION": "true"})
    foreign = make_token("ops-1", ["operator"])  # signed with conftest secret
    with TestClient(app) as client:
        resp = client.get("/v1/gateway/metrics",
                          headers={"Authorization": f"Bearer {foreign}"})
        assert resp.status_code == 401
    own = make_token("ops-1", ["operator"], secret=app_secret)
    with TestClient(app) as client:
        resp = client.get("/v1/gateway/metrics",
                          headers={"Authorization": f"Bearer {own}"})
        assert resp.status_code == 200


def test_metrics_endpoint_still_available_to_ordinary_users(gateway_client):
    dev = make_token("dev-1", ["Developer"])
    resp = gateway_client.get("/v1/gateway/metrics", headers={"Authorization": f"Bearer {dev}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["gateway_status"] == "ONLINE"
    assert "monitoring" not in body["route_mapping_matrix"]


# ---------------------------------------------------------------------------
# Operator roles can NEVER be used to reach monitoring telemetry
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("roles", [["operator"], ["DevOpsLead"], ["ClusterAdmin"]])
def test_operator_jwt_cannot_reach_monitoring_through_gateway(gateway_client, roles):
    token = make_token("op-1", roles)
    # The old tunnel shape is gone, and no other route may forward telemetry.
    for path in DISPATCH_PATHS:
        resp = gateway_client.post(path, json=TELEMETRY_PAYLOAD,
                                   headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code in (404, 405)
    # No route on the gateway targets the monitoring service at all.
    spec = gateway_client.get("/openapi.json").json()
    assert not any("monitoring" in p.lower() for p in spec["paths"])
