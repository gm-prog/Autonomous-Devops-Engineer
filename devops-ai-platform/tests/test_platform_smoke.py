"""
Boot-level smoke tests for the operator platform.

Verifies that every service app is importable, serves its endpoints, and
enforces its security contracts (JWT on the gateway, HMAC on Sentry
webhooks) — the regressions that made the platform "not runnable" in the
original AI Studio export.
"""
import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

JWT_SECRET = "pytest-secret-not-for-production"
SENTRY_SECRET = "pytest-sentry-shared-secret"


@pytest.fixture(scope="module")
def gateway_client():
    from api_gateway.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def admin_token():
    from api_gateway.core.auth import mint_token
    return mint_token("devops-operator", ["DevOpsLead", "ClusterAdmin"])


# --- shared kernel -----------------------------------------------------------

def test_shared_kernel_events():
    from shared_kernel.domain.events import RepositoryImportedEvent
    event = RepositoryImportedEvent("agg-1", {"repo": "x"})
    assert event.to_dict()["event_type"] == "RepositoryImportedEvent"


def test_shared_kernel_value_objects_validate():
    from shared_kernel.domain.value_objects import RepoUrl
    with pytest.raises(ValueError):
        RepoUrl("not-a-git-url")
    assert RepoUrl("https://github.com/org/repo.git").value.endswith(".git")


def test_shared_kernel_publisher():
    from shared_kernel.domain.events import DomainEvent
    from shared_kernel.infrastructure.messaging import DomainEventPublisher
    assert DomainEventPublisher().publish(DomainEvent("agg-1")) is True


# --- api gateway: JWT auth ----------------------------------------------------

def test_gateway_health(gateway_client):
    assert gateway_client.get("/health").status_code == 200


def test_gateway_metrics_rejects_missing_token(gateway_client):
    assert gateway_client.get("/v1/gateway/metrics").status_code == 401


def test_gateway_metrics_rejects_forged_token(gateway_client):
    r = gateway_client.get(
        "/v1/gateway/metrics",
        headers={"Authorization": "Bearer forged.token.signature"},
    )
    assert r.status_code == 401


def test_gateway_metrics_accepts_signed_token(gateway_client, admin_token):
    r = gateway_client.get(
        "/v1/gateway/metrics",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200
    assert r.json()["authorizing_identity"] == "devops-operator"


def test_gateway_dispatch_unknown_service_404(gateway_client, admin_token):
    r = gateway_client.post(
        "/v1/gateway/dispatch/unknown",
        json={"x": 1},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 404


def test_gateway_dispatch_unreachable_downstream_502(gateway_client, admin_token):
    # repo-service host does not resolve in CI: dispatch must honestly report
    # the failure (502), not fabricate a PROXY_PASSTHROUGH success.
    r = gateway_client.post(
        "/v1/gateway/dispatch/repo",
        json={"x": 1},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 502


def test_jwt_expiry_enforced():
    from api_gateway.core.auth import decode_and_verify, mint_token
    expired = mint_token("sub", ["Developer"], secret=JWT_SECRET, ttl_seconds=-10)
    with pytest.raises(ValueError):
        decode_and_verify(expired, JWT_SECRET)


# --- repo service ---------------------------------------------------------------

def test_repo_service_import_repository():
    from repo_service.main import app
    with TestClient(app) as c:
        assert c.get("/health").status_code == 200
        r = c.post(
            "/repositories",
            json={"name": "smoke-svc", "url": "https://github.com/example/smoke-svc.git"},
        )
        assert r.status_code == 201
        assert r.json()["status"] == "Imported"


# --- agent service (SSE) ----------------------------------------------------------

def test_agent_service_sse_stream():
    from agent_service.main import app
    with TestClient(app) as c:
        with c.stream("GET", "/agent/streams/task-42") as r:
            assert r.status_code == 200
            events = sum(1 for line in r.iter_lines() if line.startswith("event:"))
    assert events >= 2


# --- monitoring service (WebSocket) -------------------------------------------------

def test_monitoring_service_websocket():
    from monitoring_service.main import app
    with TestClient(app) as c:
        with c.websocket_connect("/ws/telemetry/socket/c-1") as ws:
            msg = json.loads(ws.receive_text())
    assert "active_connections" in msg


# --- incident service (Sentry HMAC) ---------------------------------------------------

def _signed(payload: bytes, secret: str = SENTRY_SECRET) -> str:
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def test_incident_service_endpoints():
    from incident_service.main import app
    with TestClient(app) as c:
        assert c.get("/health").status_code == 200
        assert c.get("/incidents").status_code == 200


def test_sentry_webhook_rejects_missing_signature():
    from incident_service.main import app
    with TestClient(app) as c:
        r = c.post("/alerts/webhooks/sentry", json={"data": {"issue": {}}})
        assert r.status_code == 401


def test_sentry_webhook_rejects_bad_signature():
    from incident_service.main import app
    with TestClient(app) as c:
        payload = json.dumps({"data": {"issue": {"title": "x"}}}).encode()
        r = c.post(
            "/alerts/webhooks/sentry",
            content=payload,
            headers={"Content-Type": "application/json", "X-Sentry-Signature": "deadbeef"},
        )
        assert r.status_code == 401


def test_sentry_webhook_accepts_valid_signature():
    from incident_service.main import app
    with TestClient(app) as c:
        payload = json.dumps(
            {"data": {"issue": {"title": "HikariPool saturation", "metadata": {"value": "pool"}}}}
        ).encode()
        r = c.post(
            "/alerts/webhooks/sentry",
            content=payload,
            headers={"Content-Type": "application/json",
                     "X-Sentry-Signature": _signed(payload)},
        )
        assert r.status_code == 202
        assert r.json()["automated_triage_initiated"] is True


# --- deployment service ---------------------------------------------------------------

def test_deployment_service_command_layer():
    from deployment_service.application.commands.execute_deployment import (
        ExecuteDeploymentCommand,
    )
    assert len(ExecuteDeploymentCommand("p-1", "ops@example.com", "k").get_idempotency_hash()) == 64


def test_deployment_service_celery_task_registered():
    from deployment_service.infrastructure.celery.tasks import celery_app, execute_iac_deployment
    assert "tasks.execute_iac_deployment" in celery_app.tasks


# --- github client: no more fabricated PR urls ---------------------------------------------

def test_github_client_refuses_fake_pr_without_token(monkeypatch):
    monkeypatch.delenv("GITHUB_OAUTH_TOKEN", raising=False)
    from incident_service.infrastructure.source_provider.github_pr_client import (
        GitHubPRClient,
        InvalidGitHubTokenException,
    )
    client = GitHubPRClient(oauth_token="")
    with pytest.raises(InvalidGitHubTokenException):
        client.create_pull_request("org/repo", "hotfix/x", "t", "b")
