"""Phase 8.7-C — Defect A acceptance tests: telemetry trust boundary.

The monitoring service's telemetry ingestion is machine-authenticated
(HMAC-SHA256 shared secret).  Human JWTs — of ANY role, including operator —
are not a telemetry producer credential.

Acceptance criteria covered:

* Test 1 — an ordinary authenticated user (Developer) cannot inject telemetry.
* Test 2 — operator roles cannot impersonate the telemetry producer.
* Test 3 — unauthorized telemetry produces no downstream side effect
  (ThresholdValidator, publisher, event bus, incident ingestion all spied).
* Test 4 — the trusted producer path works end to end:
  observation -> stream -> threshold -> event -> incident ingestion.
* Test 5 — replay/tampering protection (valid sig, altered body, altered
  signature, missing signature, replayed nonce, stale timestamp, wrong
  secret, missing configured secret fails closed).
"""

from __future__ import annotations

import json
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from platform_pkg.monitoring.security.telemetry_auth import (
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    make_signed_headers,
)
from conftest import TEST_TELEMETRY_SECRET, make_token

INGEST_PATH = "/api/internal/telemetry/observations"


def _body(**overrides) -> bytes:
    payload = {
        "service_id": "spring-gateway",
        "metric_name": "cpu_percent",
        "value": 42.0,
        "unit": "percent",
        "producer_id": "prometheus-scraper",
    }
    payload.update(overrides)
    return json.dumps(payload).encode("utf-8")


def _signed_headers(body: bytes, secret: str = TEST_TELEMETRY_SECRET, path: str = INGEST_PATH,
                    now: float | None = None, nonce: str | None = None) -> dict:
    headers = make_signed_headers(secret, "POST", path, body, now=now, nonce=nonce)
    headers["content-type"] = "application/json"
    return headers


@pytest.fixture
def telemetry_env(monkeypatch):
    monkeypatch.setenv("TELEMETRY_HMAC_SECRET", TEST_TELEMETRY_SECRET)


@pytest.fixture
def monitoring_app(recording_publisher, counting_validator):
    from platform_pkg.monitoring.main import create_app

    app = create_app(publisher=recording_publisher, validator=counting_validator)
    app.state.counting_validator = counting_validator
    app.state.telemetry_publisher = recording_publisher
    return app


@pytest.fixture
def monitoring_client(monitoring_app):
    with TestClient(monitoring_app) as client:
        yield client


# ---------------------------------------------------------------------------
# Test 4 — trusted producer path works, end to end
# ---------------------------------------------------------------------------


def test_trusted_producer_ingestion_accepted(monitoring_client, monitoring_app,
                                             telemetry_env):
    body = _body(value=55.0)
    resp = monitoring_client.post(INGEST_PATH, content=body,
                                  headers=_signed_headers(body))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "ACCEPTED"
    assert data["authenticated_as"] == "hmac-producer"
    assert data["threshold_breached"] is False
    assert data["event_id"] is None


def test_trusted_producer_breach_flows_through_full_pipeline(
    monitoring_app, monitoring_client, recording_publisher, counting_validator,
    recording_incident_repo, telemetry_env,
):
    """observation -> stream -> ThresholdValidator -> event -> incident."""
    from platform_pkg.incident.application.commands.ingest_webhook_alert import (
        IngestWebhookAlertCommandHandler,
    )
    from platform_pkg.incident.application.event_handlers.on_metric_threshold_failed import (
        OnMetricThresholdFailedHandler,
    )
    from platform_pkg.shared_kernel.domain.events import ThreatThresholdExceededEvent

    publisher = recording_publisher
    validator = counting_validator
    body = _body(value=99.0)  # above the 90% danger limit
    resp = monitoring_client.post(INGEST_PATH, content=body,
                                  headers=_signed_headers(body))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["threshold_breached"] is True
    assert data["event_id"]

    # The event bus received exactly one threshold event with the breach data.
    assert len(publisher.threat_events) == 1
    event = publisher.threat_events[0]
    assert isinstance(event, ThreatThresholdExceededEvent)
    assert event.aggregate_id == "spring-gateway"
    assert event.payload["average"] == pytest.approx(99.0)
    assert event.payload["producer_id"] == "prometheus-scraper"

    # The validator was actually consulted (real pipeline, not a shortcut).
    assert validator.calls == 1

    # Incident ingestion consumes the event and creates a triaged incident.
    triage = IngestWebhookAlertCommandHandler(recording_incident_repo)
    handler = OnMetricThresholdFailedHandler(triage)
    handler.handle(event)
    assert len(recording_incident_repo.saved) == 1
    incident = recording_incident_repo.saved[0]
    assert incident.severity == "High"
    assert incident.status == "Triage"
    assert event.event_id == publisher.threat_events[0].event_id


# ---------------------------------------------------------------------------
# Tests 1 & 2 — human JWTs (any role) cannot ingest telemetry
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "roles",
    [
        ["Developer"],
        ["operator"],
        ["DevOpsLead"],
        ["ClusterAdmin"],
        ["Developer", "operator", "DevOpsLead", "ClusterAdmin"],
    ],
    ids=["developer", "operator", "devops-lead", "cluster-admin", "all-roles"],
)
def test_human_jwt_cannot_ingest_telemetry(monitoring_client, monitoring_app,
                                           telemetry_env, roles):
    token = make_token("attacker-" + roles[0], roles)
    body = _body(value=99.9)  # would manufacture a breach if accepted
    resp = monitoring_client.post(
        INGEST_PATH,
        content=body,
        headers={"Authorization": f"Bearer {token}"},
    )
    # No HMAC envelope -> rejected.  A bearer JWT is simply not a credential
    # this boundary accepts.
    assert resp.status_code == 401, f"{roles} -> {resp.status_code}"
    _assert_no_side_effects(monitoring_app)


def test_unauthenticated_ingestion_denied(monitoring_client, monitoring_app,
                                          telemetry_env):
    body = _body(value=99.9)
    resp = monitoring_client.post(INGEST_PATH, content=body)
    assert resp.status_code == 401
    _assert_no_side_effects(monitoring_app)


def _assert_no_side_effects(monitoring_app):
    """Test 3: rejected requests must produce NO downstream side effect.

    Spies verified: metric stream registry (no datapoints), ThresholdValidator
    (never consulted), event publisher / bus (no events).  Since no event is
    published, the incident ingestion handler cannot be triggered either.
    """
    handler = monitoring_app.state.telemetry_handler
    # No metric stream was ever created/recorded.
    assert handler.registry._streams == {}
    # The validator was never consulted.
    validator = monitoring_app.state.counting_validator
    assert validator.calls == 0
    # No event was published to the bus / Redis.
    publisher = monitoring_app.state.telemetry_publisher
    assert publisher.events == []


# ---------------------------------------------------------------------------
# Test 5 — replay / tampering protection
# ---------------------------------------------------------------------------


def test_valid_signature_succeeds(monitoring_client, monitoring_app, telemetry_env):
    body = _body()
    resp = monitoring_client.post(INGEST_PATH, content=body,
                                  headers=_signed_headers(body))
    assert resp.status_code == 200


def test_altered_body_fails(monitoring_client, monitoring_app, telemetry_env):
    body = _body(value=10.0)
    headers = _signed_headers(body)
    tampered = _body(value=99.9)  # attacker raises the value after signing
    resp = monitoring_client.post(INGEST_PATH, content=tampered, headers=headers)
    assert resp.status_code == 401
    _assert_no_side_effects(monitoring_app)


def test_altered_signature_fails(monitoring_client, monitoring_app, telemetry_env):
    body = _body()
    headers = _signed_headers(body)
    sig = headers[HEADER_SIGNATURE]
    flipped = ("0" if sig[7] == "1" else "1") + sig[8:]
    headers[HEADER_SIGNATURE] = f"sha256={flipped}"
    resp = monitoring_client.post(INGEST_PATH, content=body, headers=headers)
    assert resp.status_code == 401
    _assert_no_side_effects(monitoring_app)


def test_missing_signature_fails(monitoring_client, monitoring_app, telemetry_env):
    body = _body()
    headers = _signed_headers(body)
    del headers[HEADER_SIGNATURE]
    resp = monitoring_client.post(INGEST_PATH, content=body, headers=headers)
    assert resp.status_code == 401

    headers = _signed_headers(body)
    del headers[HEADER_TIMESTAMP]
    resp = monitoring_client.post(INGEST_PATH, content=body, headers=headers)
    assert resp.status_code == 401

    headers = _signed_headers(body)
    del headers[HEADER_NONCE]
    resp = monitoring_client.post(INGEST_PATH, content=body, headers=headers)
    assert resp.status_code == 401


def test_replayed_request_fails(monitoring_client, monitoring_app, telemetry_env):
    body = _body()
    nonce = "replay-probe-" + uuid.uuid4().hex
    first = monitoring_client.post(INGEST_PATH, content=body,
                                   headers=_signed_headers(body, nonce=nonce))
    assert first.status_code == 200
    # Exact replay (same signature, timestamp, nonce) must be rejected.
    second = monitoring_client.post(INGEST_PATH, content=body,
                                    headers=_signed_headers(body, nonce=nonce))
    assert second.status_code == 401
    assert "replay" in second.json()["detail"].lower() or "nonce" in second.json()["detail"].lower()


def test_stale_timestamp_fails(monitoring_client, monitoring_app, telemetry_env):
    body = _body()
    stale = time.time() - 3600  # an hour old: outside the skew window
    resp = monitoring_client.post(
        INGEST_PATH, content=body, headers=_signed_headers(body, now=stale)
    )
    assert resp.status_code == 401
    _assert_no_side_effects(monitoring_app)


def test_wrong_secret_fails(monitoring_client, monitoring_app, telemetry_env):
    body = _body()
    headers = _signed_headers(body, secret="a-different-producer-secret")
    resp = monitoring_client.post(INGEST_PATH, content=body, headers=headers)
    assert resp.status_code == 401
    _assert_no_side_effects(monitoring_app)


def test_missing_configured_secret_fails_closed(monitoring_app, monkeypatch,
                                                telemetry_env):
    """No TELEMETRY_HMAC_SECRET configured -> ingestion disabled for ALL,
    including a correctly signed request (503, not 200, not 401-fallback)."""
    monkeypatch.delenv("TELEMETRY_HMAC_SECRET", raising=False)
    with TestClient(monitoring_app) as client:
        body = _body()
        headers = _signed_headers(body, secret=TEST_TELEMETRY_SECRET)
        resp = client.post(INGEST_PATH, content=body, headers=headers)
        assert resp.status_code == 503
        _assert_no_side_effects(monitoring_app)


def test_hmac_binding_covers_method_and_path(monitoring_app, telemetry_env):
    """A signature valid for one path must not replay onto another path."""
    from platform_pkg.monitoring.main import create_app as make_app

    app = make_app()
    with TestClient(app) as client:
        body = _body()
        headers = make_signed_headers(
            TEST_TELEMETRY_SECRET, "POST", "/api/internal/telemetry/other", body
        )
        resp = client.post(INGEST_PATH, content=body, headers=headers)
        assert resp.status_code == 401
        assert app.state.telemetry_handler.registry._streams == {}
