"""Phase 8.7-D — verified server-side Gemini analysis path.

Contract coverage (mandatory list, section 5):

Gateway (typed route ``POST /api/v1/repository/analyze``):
  * unauthenticated request rejected (401)
  * insufficient role rejected (403)
  * valid JWT accepted (typed relay, 200)
  * malformed payload rejected (422: oversized / missing / bad URL)
  * client-supplied Gemini key rejected (extra="forbid" -> 422)
  * downstream failure mapping (429/502/503/504)
  * no user-controlled downstream service/path (fixed constants)

Agent-service internal boundary (``/api/internal/repository/analyze``):
  * missing server Gemini secret fails closed (503, no fabricated result)
  * successful (fake) Gemini response parsed correctly (200, typed)
  * malformed provider response -> 502 (never a fabricated blueprint)

GeminiCallerAdapter hardening (injectable transport, fake provider):
  * provider 401/403 -> GeminiAuthException, NO retry
  * provider 429 -> bounded retries then GeminiRateLimitException
  * provider 5xx -> bounded retries then GeminiUpstreamException
  * timeout -> bounded retries then GeminiTimeoutException
  * malformed 200 -> GeminiMalformedResponseException, NO retry
  * circuit breaker: opens after threshold, fast-rejects, recovers
  * budget exhaustion blocks calls (no HTTP call)
  * missing key -> fail closed, no fake "success" (both entry points)
  * credential never appears in URLs, exception text, or logs

Android side is covered by the static contract tests in
``test_android_secret_guards.py`` (no provider secret; Bearer-JWT
authentication required for the typed call; offline default; honest
failure) and by the adversarial mutations M5/M8-M12.
"""

from __future__ import annotations

import json
import os
import time

import pytest
import requests
from fastapi.testclient import TestClient

from conftest import TEST_GW_SECRET, make_token

ANALYSIS_PATH = "/api/v1/repository/analyze"
INTERNAL_PATH = "/api/internal/repository/analyze"

GOOD_BODY = {
    "repo_name": "fastapi-probe",
    "repo_url": "https://github.com/acme/fastapi-probe.git",
    "framework": "FastAPI",
    "technology": "Python 3.12",
}

GOOD_ASSETS = {
    "dockerfile": "FROM python:3.12-slim",
    "k8s_yaml": "apiVersion: apps/v1\nkind: Deployment",
    "terraform_tf": 'provider "aws" {}',
    "pipeline_yaml": "name: CI",
    "report": "Detected FastAPI service.",
}


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeGeminiResponse:
    def __init__(self, status: int, payload):
        self.status_code = status
        self._payload = payload
        self.text = json.dumps(payload) if payload is not None else ""

    def json(self):
        if self._payload is None:
            raise ValueError("no JSON body")
        return self._payload

    def raise_for_status(self):
        pass


def _gemini_http(status: int, payload=None) -> "FakeGeminiResponse":
    return FakeGeminiResponse(status, payload)


class FakeLLM:
    """A controllable RemoteLLMInterface fake for the agent boundary."""

    def __init__(self, response: object = None, exc: Exception | None = None):
        self.response = response
        self.exc = exc
        self.calls = 0

    def generate_remediation(self, prompt: str, system_instruction: str) -> str:
        self.calls += 1
        if self.exc is not None:
            raise self.exc
        if isinstance(self.response, str):
            return self.response
        return json.dumps(self.response or GOOD_ASSETS)

    def generate_iac_blueprint(self, tech_metadata: dict) -> dict:
        raise NotImplementedError("not used by this path")


class FakeGatewayTransport:
    """Stand-in for the gateway's downstream transport (agent-service)."""

    def __init__(self, payload: dict | None = None, exc: Exception | None = None):
        self.payload = payload or {
            "status": "ANALYSIS_COMPLETE",
            "source": "server_gemini",
            "analysis": dict(GOOD_ASSETS),
        }
        self.exc = exc
        self.calls = []

    def call(self, method: str, url: str, json_body: dict, identity: str) -> dict:
        self.calls.append({"method": method, "url": url, "body": json_body, "identity": identity})
        if self.exc is not None:
            raise self.exc
        return self.payload


def _downstream_http_error(status: int) -> requests.HTTPError:
    resp = requests.Response()
    resp.status_code = status
    resp._content = b"{}"
    return requests.HTTPError(response=resp)


@pytest.fixture(autouse=True)
def agent_internal_token(monkeypatch):
    monkeypatch.setenv("AGENT_INTERNAL_TOKEN", "test-agent-internal-token-0123456789abcdef0123456789abcdef")


def _agent_app(llm=None, config=None):
    from platform_pkg.agent.main import create_app

    return create_app(llm_engine=llm, config=config)


def _single_replica_test_config():
    """Explicit single-replica test deployment config.

    Phase 8.7-D.1-CORRECTION-2 (P1-B): an EMPTY/MISSING APP_ENV is no
    longer a recognized development environment, so the default
    (local-store) adapter must not be resolved from the test process
    environment implicitly.  These tests are single-replica deployments
    and therefore opt in with an EXPLICIT config — the same documented
    single-instance mechanism the production code requires."""
    from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

    return gc.GeminiRuntimeConfig(max_retries=1, backoff_base_seconds=0.001)


def _gateway_app():
    from platform_pkg.api_gateway.main import create_app

    return create_app(env={"JWT_SECRET": TEST_GW_SECRET, "APP_ENV": "production",
        "ANALYSIS_RATE_LIMIT_SINGLE_INSTANCE_PRODUCTION": "true"})


# ---------------------------------------------------------------------------
# Gateway: authentication & authorization
# ---------------------------------------------------------------------------


class TestGatewayAnalysisAuth:
    def test_unauthenticated_request_rejected(self):
        client = TestClient(_gateway_app())
        resp = client.post(ANALYSIS_PATH, json=GOOD_BODY)
        assert resp.status_code == 401

    def test_insufficient_role_rejected(self):
        client = TestClient(_gateway_app())
        viewer = make_token("viewer-1", ["Viewer"])
        resp = client.post(
            ANALYSIS_PATH, json=GOOD_BODY,
            headers={"Authorization": f"Bearer {viewer}"},
        )
        assert resp.status_code == 403

    def test_expired_token_rejected(self):
        client = TestClient(_gateway_app())
        expired = make_token("dev-1", ["Developer"], ttl=-10)
        resp = client.post(
            ANALYSIS_PATH, json=GOOD_BODY,
            headers={"Authorization": f"Bearer {expired}"},
        )
        assert resp.status_code == 401

    @pytest.mark.parametrize("roles", [["Developer"], ["operator"], ["DevOpsLead"]])
    def test_valid_jwt_accepted_and_relayed_typed(self, roles):
        app = _gateway_app()
        transport = FakeGatewayTransport()
        from platform_pkg.api_gateway.routers.analysis_router import (
            get_downstream_transport,
        )

        app.dependency_overrides[get_downstream_transport] = lambda: transport
        token = make_token("dev-1", roles)
        with TestClient(app) as client:
            resp = client.post(
                ANALYSIS_PATH, json=GOOD_BODY,
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["source"] == "server_gemini"
        assert body["analysis"] == GOOD_ASSETS
        # Exactly one fixed downstream call to the fixed constant path.
        assert len(transport.calls) == 1
        call = transport.calls[0]
        assert call["url"] == "http://agent-service:8020/api/internal/repository/analyze"
        assert call["identity"] == "dev-1"
        assert call["body"] == GOOD_BODY

    def test_client_supplied_gemini_key_rejected(self):
        """A provider key field is structurally impossible (extra=forbid)."""
        client = TestClient(_gateway_app())
        token = make_token("dev-1", ["Developer"])
        payload = dict(GOOD_BODY)
        payload["gemini_api_key"] = "AIzaFAKE-should-never-be-accepted"
        resp = client.post(
            ANALYSIS_PATH, json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 422

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda b: b.__setitem__("repo_name", "x" * 500),
            lambda b: b.pop("technology"),
            lambda b: b.__setitem__("repo_url", "not-a-url"),
            lambda b: b.__setitem__("framework", ""),
        ],
    )
    def test_malformed_payload_rejected(self, mutate):
        client = TestClient(_gateway_app())
        token = make_token("dev-1", ["Developer"])
        payload = dict(GOOD_BODY)
        mutate(payload)
        resp = client.post(
            ANALYSIS_PATH, json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 422

    @pytest.mark.parametrize("status,expected", [(429, 429), (502, 502), (503, 503), (504, 504)])
    def test_downstream_failure_mapping(self, status, expected):
        app = _gateway_app()
        transport = FakeGatewayTransport(exc=_downstream_http_error(status))
        from platform_pkg.api_gateway.routers.analysis_router import (
            get_downstream_transport,
        )

        app.dependency_overrides[get_downstream_transport] = lambda: transport
        token = make_token("dev-1", ["Developer"])
        with TestClient(app) as client:
            resp = client.post(
                ANALYSIS_PATH, json=GOOD_BODY,
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == expected

    def test_downstream_connection_failure_maps_to_502(self):
        app = _gateway_app()
        transport = FakeGatewayTransport(exc=requests.ConnectionError("no route"))
        from platform_pkg.api_gateway.routers.analysis_router import (
            get_downstream_transport,
        )

        app.dependency_overrides[get_downstream_transport] = lambda: transport
        token = make_token("dev-1", ["Developer"])
        with TestClient(app) as client:
            resp = client.post(
                ANALYSIS_PATH, json=GOOD_BODY,
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == 502

    def test_response_contains_no_credential_material(self):
        app = _gateway_app()
        transport = FakeGatewayTransport()
        from platform_pkg.api_gateway.routers.analysis_router import (
            get_downstream_transport,
        )

        app.dependency_overrides[get_downstream_transport] = lambda: transport
        token = make_token("dev-1", ["Developer"])
        with TestClient(app) as client:
            resp = client.post(
                ANALYSIS_PATH, json=GOOD_BODY,
                headers={"Authorization": f"Bearer {token}"},
            )
        text = resp.text.lower()
        assert "gemini_api_key" not in text
        assert "aiza" not in text
        assert "x-goog-api-key" not in text


# ---------------------------------------------------------------------------
# Agent-service internal boundary
# ---------------------------------------------------------------------------


class TestAgentAnalysisBoundary:
    def test_missing_server_gemini_secret_fails_closed(self, monkeypatch):
        """No server key => 503, and NEVER a fabricated analysis."""
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        with TestClient(_agent_app(config=_single_replica_test_config())) as client:
            resp = client.post(INTERNAL_PATH, json=GOOD_BODY, headers={"X-Gateway-Identity": "agent-test", "X-Agent-Internal-Token": "test-agent-internal-token-0123456789abcdef0123456789abcdef"})
        assert resp.status_code == 503
        assert "analysis" not in resp.json()

    def test_successful_response_parsed_typed(self):
        fake = FakeLLM(response=GOOD_ASSETS)
        with TestClient(_agent_app(llm=fake)) as client:
            resp = client.post(INTERNAL_PATH, json=GOOD_BODY, headers={"X-Gateway-Identity": "agent-test", "X-Agent-Internal-Token": "test-agent-internal-token-0123456789abcdef0123456789abcdef"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ANALYSIS_COMPLETE"
        assert body["source"] == "server_gemini"
        assert body["analysis"] == GOOD_ASSETS
        assert fake.calls == 1

    @pytest.mark.parametrize(
        "bad",
        [
            "garbage, not json",
            json.dumps({"dockerfile": "D"}),  # missing fields
            json.dumps({k: "" for k in GOOD_ASSETS}),  # empty values
            json.dumps(list(GOOD_ASSETS.values())),  # not an object
        ],
    )
    def test_malformed_provider_response_never_fabricated(self, bad):
        fake = FakeLLM(response=bad)
        with TestClient(_agent_app(llm=fake)) as client:
            resp = client.post(
                INTERNAL_PATH,
                json=GOOD_BODY,
                headers={
                    "X-Gateway-Identity": "agent-test",
                    "X-Agent-Internal-Token": "test-agent-internal-token-0123456789abcdef0123456789abcdef",
                },
            )
        assert resp.status_code == 502
        assert "analysis" not in resp.json()

    def test_internal_boundary_rejects_client_supplied_key_field(self):
        fake = FakeLLM()
        payload = dict(GOOD_BODY)
        payload["gemini_api_key"] = "AIzaFAKE"
        with TestClient(_agent_app(llm=fake)) as client:
            resp = client.post(INTERNAL_PATH, json=payload, headers={"X-Gateway-Identity": "agent-test", "X-Agent-Internal-Token": "test-agent-internal-token-0123456789abcdef0123456789abcdef"})
        assert resp.status_code == 422
        assert fake.calls == 0  # no provider interaction at all

    def test_internal_boundary_rejects_missing_token(self):
        fake = FakeLLM(response=GOOD_ASSETS)
        with TestClient(_agent_app(llm=fake)) as client:
            resp = client.post(
                INTERNAL_PATH,
                json=GOOD_BODY,
                headers={"X-Gateway-Identity": "agent-test"},
            )
        assert resp.status_code == 401
        assert fake.calls == 0

    def test_internal_boundary_rejects_invalid_token(self):
        fake = FakeLLM(response=GOOD_ASSETS)
        with TestClient(_agent_app(llm=fake)) as client:
            resp = client.post(
                INTERNAL_PATH,
                json=GOOD_BODY,
                headers={
                    "X-Gateway-Identity": "agent-test",
                    "X-Agent-Internal-Token": "wrong-token",
                },
            )
        assert resp.status_code == 401
        assert fake.calls == 0

    def test_invalid_input_422(self):
        fake = FakeLLM()
        payload = dict(GOOD_BODY)
        payload["repo_url"] = "no-scheme"
        with TestClient(_agent_app(llm=fake)) as client:
            resp = client.post(INTERNAL_PATH, json=payload, headers={"X-Gateway-Identity": "agent-test", "X-Agent-Internal-Token": "test-agent-internal-token-0123456789abcdef0123456789abcdef"})
        assert resp.status_code == 422
        assert fake.calls == 0


# ---------------------------------------------------------------------------
# GeminiCallerAdapter hardening
# ---------------------------------------------------------------------------


def _caller(transport=None, **kw):
    from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

    # Explicit single-replica config: never resolves the store from the
    # test process environment (P1-B fail-closed classification).
    defaults = dict(
        api_key="test-server-key",
        config=gc.GeminiRuntimeConfig(),
        max_retries=3,
        backoff_base_seconds=0.01,
        timeout_seconds=5.0,
    )
    defaults.update(kw)
    if transport is not None:
        defaults["transport"] = transport
    return gc.GeminiCallerAdapter(**defaults)


def _http_transport(status: int, payload=None, record: list | None = None,
                    exc: Exception | None = None):
    def t(payload_body):
        if record is not None:
            record.append(status)
        if exc is not None:
            raise exc
        return _gemini_http(status, payload)
    return t


GOOD_PROVIDER_PAYLOAD = {
    "candidates": [{"content": {"parts": [{"text": "provider-text"}]}}],
    "usageMetadata": {"promptTokenCount": 100, "candidatesTokenCount": 50},
}


class TestGeminiCallerResilience:
    def test_missing_key_fails_closed_no_fake_success(self):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        calls = []
        caller = _caller(transport=_http_transport(200, GOOD_PROVIDER_PAYLOAD, calls), api_key="")
        with pytest.raises(gc.GeminiServiceUnavailableException):
            caller.generate_remediation("p", "s")
        with pytest.raises(gc.GeminiServiceUnavailableException):
            caller.generate_iac_blueprint({"lang": "python"})
        assert calls == []  # no HTTP call, no fabricated output

    def test_provider_401_auth_failure_no_retry(self):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        calls = []
        caller = _caller(transport=_http_transport(401, record=calls))
        with pytest.raises(gc.GeminiAuthException):
            caller.generate_remediation("p", "s")
        assert calls == [401]  # exactly one attempt

    def test_provider_403_auth_failure_no_retry(self):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        calls = []
        caller = _caller(transport=_http_transport(403, record=calls))
        with pytest.raises(gc.GeminiAuthException):
            caller.generate_remediation("p", "s")
        assert calls == [403]

    def test_provider_429_bounded_retry_then_rate_limit(self):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        calls = []
        caller = _caller(transport=_http_transport(429, record=calls), max_retries=3)
        with pytest.raises(gc.GeminiRateLimitException):
            caller.generate_remediation("p", "s")
        assert calls == [429, 429, 429]  # bounded, not infinite

    def test_provider_5xx_bounded_retry_then_upstream(self):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        calls = []
        caller = _caller(transport=_http_transport(503, record=calls), max_retries=3)
        with pytest.raises(gc.GeminiUpstreamException):
            caller.generate_remediation("p", "s")
        assert calls == [503, 503, 503]

    def test_timeout_bounded_retry_then_timeout_error(self):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        calls = []

        def t(_):
            calls.append("timeout")
            raise requests.Timeout()

        caller = _caller(transport=t, max_retries=2)
        with pytest.raises(gc.GeminiTimeoutException):
            caller.generate_remediation("p", "s")
        assert calls == ["timeout", "timeout"]

    def test_malformed_200_no_retry_typed_error(self):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        calls = []
        caller = _caller(
            transport=_http_transport(200, {"candidates": []}, record=calls),
            max_retries=3,
        )
        with pytest.raises(gc.GeminiMalformedResponseException):
            caller.generate_remediation("p", "s")
        assert calls == [200]  # malformed is permanent: no retry

    def test_success_returns_text_and_records_budget(self):
        calls = []
        caller = _caller(transport=_http_transport(200, GOOD_PROVIDER_PAYLOAD, record=calls))
        out = caller.generate_remediation("p", "s")
        assert out == "provider-text"
        assert calls == [200]
        assert caller.budget_service.accumulated_spend > 0

    def test_circuit_breaker_opens_and_recovers(self):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        now = [1000.0]
        caller = _caller(
            transport=_http_transport(500, record=[]),
            max_retries=1,
            backoff_base_seconds=0.01,
        )
        caller._time_fn = lambda: now[0]
        for _ in range(5):
            with pytest.raises(gc.GeminiUpstreamException):
                caller.generate_remediation("p", "s")
        assert caller.cb_state == "OPEN"
        # Fast reject while open (no HTTP call):
        calls = []
        caller._transport = _http_transport(500, record=calls)
        with pytest.raises(gc.GeminiServiceUnavailableException):
            caller.generate_remediation("p", "s")
        assert calls == []
        # After cooldown: half-open probe; success closes the circuit.
        now[0] += 61
        caller._transport = _http_transport(200, GOOD_PROVIDER_PAYLOAD)
        assert caller.generate_remediation("p", "s") == "provider-text"
        assert caller.cb_state == "CLOSED"

    def test_budget_exhaustion_blocks_calls(self):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        calls = []
        caller = _caller(
            transport=_http_transport(200, GOOD_PROVIDER_PAYLOAD, record=calls),
            monthly_budget_usd=0.0,
        )
        with pytest.raises(gc.BudgetExceededException):
            caller.generate_remediation("p", "s")
        assert calls == []  # blocked before any HTTP call

    def test_credential_never_in_url_or_exception_text(self, caplog):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        seen = {}
        caller = _caller(api_key="SUPER-SECRET-XYZ")
        orig_post = gc.requests.post

        def spy(url, **kw):
            seen["url"] = url
            seen["headers"] = kw.get("headers")
            raise requests.Timeout()

        gc.requests.post = spy
        try:
            with caplog.at_level("DEBUG"):
                with pytest.raises(gc.GeminiTimeoutException):
                    caller.generate_remediation("p", "s")
        finally:
            gc.requests.post = orig_post
        assert "SUPER-SECRET-XYZ" not in seen["url"]
        assert seen["headers"].get("x-goog-api-key") == "SUPER-SECRET-XYZ"
        assert "SUPER-SECRET-XYZ" not in caplog.text


# ---------------------------------------------------------------------------
# End-to-end (fake provider): gateway -> agent -> caller -> parsed response
# ---------------------------------------------------------------------------


class TestEndToEndFakeProvider:
    """Full path with a fake provider transport: proves the typed relay,
    the auth chain, and the parsing — WITHOUT any real Gemini call (there is
    no credential in this environment; a genuine provider call is reported
    as NOT executed)."""

    def test_full_path_with_fake_provider(self):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc
        from platform_pkg.agent.main import create_app as agent_create_app
        from platform_pkg.api_gateway.main import create_app as gateway_create_app
        from platform_pkg.api_gateway.routers.analysis_router import (
            get_downstream_transport,
        )
        from platform_pkg.agent.presentation.rest.analysis_router import (
            get_analysis_handler,
        )
        from platform_pkg.agent.application.commands.analyze_repository import (
            AnalyzeRepositoryCommandHandler,
        )

        inner_text = json.dumps(GOOD_ASSETS)
        provider_payload = {
            "candidates": [{"content": {"parts": [{"text": inner_text}]}}],
            "usageMetadata": {"promptTokenCount": 300, "candidatesTokenCount": 900},
        }

        agent_app = agent_create_app(config=_single_replica_test_config())
        # Wire the production caller with a fake provider transport:
        caller = gc.GeminiCallerAdapter(
            api_key="server-side-test-key",
            config=_single_replica_test_config(),
            transport=lambda _p: _gemini_http(200, provider_payload),
            backoff_base_seconds=0.01,
        )
        agent_app.dependency_overrides[get_analysis_handler] = (
            lambda: AnalyzeRepositoryCommandHandler(caller)
        )

        # Bridge the gateway to the agent app in-process (fixed path,
        # identity propagation preserved).
        agent_client = TestClient(agent_app)

        class AgentBridgeTransport:
            def call(self, method, url, json_body, identity):
                resp = agent_client.post(
                    url, json=json_body,
                    headers={
                        "X-Gateway-Identity": identity,
                        "X-Agent-Internal-Token": "test-agent-internal-token-0123456789abcdef0123456789abcdef",
                    },
                )
                if resp.status_code != 200:
                    raise _downstream_http_error(resp.status_code)
                return resp.json()

        gateway_app = _gateway_app()
        gateway_app.dependency_overrides[get_downstream_transport] = AgentBridgeTransport

        token = make_token("dev-e2e", ["Developer"])
        with TestClient(gateway_app) as client:
            resp = client.post(
                ANALYSIS_PATH, json=GOOD_BODY,
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["source"] == "server_gemini"
        assert body["analysis"] == GOOD_ASSETS
        assert "server-side-test-key" not in resp.text


# ---------------------------------------------------------------------------
# Positive lifecycle: ONE shared handler/adapter per process (D1 P0-1)
# ---------------------------------------------------------------------------


class _FailingProviderTransport:
    """Provider transport that always answers a transient 500."""

    def __init__(self):
        self.calls = 0

    def __call__(self, payload):
        self.calls += 1
        return _gemini_http(500, None)


def _production_agent_app(**config_kwargs):
    from platform_pkg.agent.main import create_app
    from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

    return create_app(config=gc.GeminiRuntimeConfig(max_retries=1, **config_kwargs))


class TestSharedAnalysisHandlerLifecycle:
    def test_two_requests_resolve_the_same_handler_instance(self):
        from starlette.requests import Request

        from platform_pkg.agent.presentation.rest import analysis_router

        app = _production_agent_app()
        scope = {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"",
            "server": ("testserver", 80),
            "client": ("testclient", 123),
            "app": app,
        }
        handler_1 = analysis_router.get_analysis_handler(Request(scope))
        handler_2 = analysis_router.get_analysis_handler(Request(scope))
        assert handler_1 is handler_2 is app.state.analysis_handler, (
            "the analysis handler must be the single application-lifetime "
            "instance shared across requests"
        )

    def test_provider_state_persists_across_separate_requests(self, monkeypatch):
        """Five failing SEPARATE requests open the shared circuit; the next
        request fails fast (503) WITHOUT any provider contact until the
        cooldown elapses, then a half-open probe can recover the circuit."""
        monkeypatch.setenv("GEMINI_API_KEY", "lifecycle-test-key-not-a-real-credential")
        app = _production_agent_app()
        adapter = app.state.analysis_handler.llm
        transport = _FailingProviderTransport()
        adapter._transport = transport

        clock = {"now": 1_000_000.0}
        adapter._time_fn = lambda: clock["now"]

        hdrs = {
            "X-Gateway-Identity": "lifecycle",
            "X-Agent-Internal-Token": "test-agent-internal-token-0123456789abcdef0123456789abcdef",
        }
        with TestClient(app) as client:
            # Five independent HTTP requests, each through the router.
            for _ in range(5):
                resp = client.post(INTERNAL_PATH, json=GOOD_BODY, headers=hdrs)
                assert resp.status_code == 502
            assert transport.calls == 5

            # Circuit OPEN: the sixth request fails fast with NO provider call.
            blocked = client.post(INTERNAL_PATH, json=GOOD_BODY, headers=hdrs)
            assert blocked.status_code == 503
            assert transport.calls == 5, "circuit-open request must not contact the provider"

            # Still inside the cooldown: no provider contact.
            clock["now"] += 10
            still_blocked = client.post(INTERNAL_PATH, json=GOOD_BODY, headers=hdrs)
            assert still_blocked.status_code == 503
            assert transport.calls == 5

            # Cooldown elapsed: half-open probe is allowed; a SUCCESS recovers
            # the circuit (state lived across all of these requests).
            clock["now"] += 55
            adapter._transport = lambda payload: _gemini_http(200, {
                "candidates": [{"content": {"parts": [{"text": json.dumps(GOOD_ASSETS)}]}}],
            })
            recovered = client.post(INTERNAL_PATH, json=GOOD_BODY, headers=hdrs)
            assert recovered.status_code == 200
            assert recovered.json()["analysis"] == GOOD_ASSETS

            # And the recovered state persists: a normal request succeeds.
            again = client.post(INTERNAL_PATH, json=GOOD_BODY, headers=hdrs)
            assert again.status_code == 200


class _SuccessProviderTransport:
    """Provider transport that always answers a valid 200.

    ``delay`` (seconds) keeps the probe in flight long enough that the
    concurrent racers deterministically observe the HALF-OPEN state.
    """

    def __init__(self, delay: float = 0.0):
        self.calls = 0
        self.delay = delay

    def __call__(self, payload):
        self.calls += 1
        if self.delay:
            time.sleep(self.delay)
        return _gemini_http(200, {
            "candidates": [{"content": {"parts": [{"text": json.dumps(GOOD_ASSETS)}]}}],
        })


class TestHalfOpenSingleProbe:
    """Phase 8.7-D.1-CORRECTION: at most ONE provider probe in half-open.

    After the cooldown expires, concurrent callers must NOT all become
    provider probes: the first acquires the single-probe lease; the rest
    fail fast until the probe settles.
    """

    def _open_circuit(self, adapter, transport, clock, n_failures: int = 5):
        from platform_pkg.agent.infrastructure.llm.gemini_caller import (
            GeminiUpstreamException,
        )

        adapter._transport = transport
        for _ in range(n_failures):
            with pytest.raises(GeminiUpstreamException):
                adapter.generate_remediation("p", "s")
        assert adapter.cb_state == "OPEN"

    def _fire_concurrent(self, adapter, n: int = 20):
        import threading

        from platform_pkg.agent.infrastructure.llm.gemini_caller import (
            GeminiServiceUnavailableException,
            GeminiUpstreamException,
        )

        barrier = threading.Barrier(n)
        outcomes: list = []
        lock = threading.Lock()

        def worker():
            barrier.wait()
            try:
                adapter.generate_remediation("p", "s")
                with lock:
                    outcomes.append("success")
            except GeminiServiceUnavailableException:
                with lock:
                    outcomes.append("fast-reject")
            except GeminiUpstreamException:
                with lock:
                    outcomes.append("probe-failed")

        threads = [threading.Thread(target=worker) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return outcomes

    def test_exactly_one_probe_when_probe_fails(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "halfopen-test-key-not-a-real-credential")
        from platform_pkg.agent.infrastructure.llm.gemini_caller import (
            GeminiServiceUnavailableException,
        )

        app = _production_agent_app()
        adapter = app.state.analysis_handler.llm
        clock = {"now": 1_000_000.0}
        adapter._time_fn = lambda: clock["now"]
        failing = _FailingProviderTransport()
        self._open_circuit(adapter, failing, clock)
        assert failing.calls == 5

        # Cooldown elapses; 20 concurrent requests race for recovery.
        clock["now"] += 61
        outcomes = self._fire_concurrent(adapter)

        assert failing.calls == 6, (
            "exactly ONE half-open probe may contact the provider; "
            f"got {failing.calls - 5} probe calls"
        )
        assert outcomes.count("fast-reject") == 19
        assert outcomes.count("probe-failed") == 1
        assert outcomes.count("success") == 0
        # The failed probe re-opens the circuit: the next call fails fast
        # WITHOUT any provider contact.
        assert adapter.cb_state == "OPEN"
        with pytest.raises(GeminiServiceUnavailableException):
            adapter.generate_remediation("p", "s")
        assert failing.calls == 6

    def test_exactly_one_probe_when_probe_recovers(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "halfopen-test-key-not-a-real-credential")

        app = _production_agent_app()
        adapter = app.state.analysis_handler.llm
        clock = {"now": 2_000_000.0}
        adapter._time_fn = lambda: clock["now"]
        self._open_circuit(adapter, _FailingProviderTransport(), clock)

        # Cooldown elapses and the provider is healthy again: the single
        # probe succeeds, the circuit CLOSES, and the other 19 concurrent
        # calls fail fast — they never become extra probes.  The probe
        # transport is deliberately delayed so all racers observe
        # HALF-OPEN before it settles.
        clock["now"] += 61
        ok = _SuccessProviderTransport(delay=0.05)
        adapter._transport = ok
        outcomes = self._fire_concurrent(adapter)

        assert ok.calls == 1, "recovery is a single probe"
        assert outcomes.count("success") == 1
        assert outcomes.count("fast-reject") == 19
        assert adapter.cb_state == "CLOSED"
        # Recovered state: a normal call succeeds with no extra probing.
        text = adapter.generate_remediation("p", "s")
        assert json.loads(text) == GOOD_ASSETS
        assert ok.calls == 2


# ---------------------------------------------------------------------------
# Phase 8.7-D.1-CORRECTION-2 (P1-A): probe-lease settlement for PRE-provider
# failures — A1 (missing key), A2 (budget store down), A3 (budget ceiling),
# A6 (20-concurrent pre-provider failure must not wedge HALF-OPEN).
# A4 (provider failure -> OPEN) and A5 (recovery -> CLOSED) are the two
# tests above them in TestHalfOpenSingleProbe.
# ---------------------------------------------------------------------------


class _FailingBudgetLedger:
    """Budget ledger double whose reserve() fails BEFORE provider contact
    (budget store unavailable / budget ceiling)."""

    def __init__(self, exc: Exception):
        self._exc = exc

    def reserve(self, max_cost_usd: float):
        raise self._exc

    def finalize(self, reservation, actual_cost_usd):  # pragma: no cover
        raise AssertionError("finalize must not run when reserve() failed")

    @property
    def accumulated_spend(self):
        return 0.0


def _direct_probe_adapter(**kwargs):
    """A GeminiCallerAdapter built with an EXPLICIT single-replica config
    (no from_env) so the probe-lifecycle tests are independent of the
    process environment; transport/clock are injected like everywhere else."""
    from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

    return gc.GeminiCallerAdapter(
        config=gc.GeminiRuntimeConfig(max_retries=1, backoff_base_seconds=0.001),
        **kwargs,
    )


class _HalfOpenProbeBase:
    """Shared driver for the pre-provider settlement tests (A1–A3)."""

    def _open_circuit(self, adapter, transport, clock, n_failures: int = 5):
        from platform_pkg.agent.infrastructure.llm.gemini_caller import (
            GeminiUpstreamException,
        )

        adapter._transport = transport
        for _ in range(n_failures):
            with pytest.raises(GeminiUpstreamException):
                adapter.generate_remediation("p", "s")
        assert adapter.cb_state == "OPEN"

    def _assert_settled_open_with_fresh_cooldown(self, adapter, clock, recover=None):
        """The probe lease must have settled to OPEN (never a permanent
        HALF-OPEN) with a fresh cooldown: an immediate call fails fast with
        no provider contact, and the circuit can still recover afterwards.
        ``recover`` (optional) may repair whatever the test broke for the
        recovery probe (e.g. restore the credential)."""
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        assert adapter.cb_state == "OPEN", (
            "pre-provider failure must settle the probe lease to OPEN with "
            f"a fresh cooldown — the circuit must never remain {adapter.cb_state}"
        )
        transport_calls_before = adapter._transport.calls
        with pytest.raises(gc.GeminiServiceUnavailableException):
            adapter.generate_remediation("p", "s")
        assert adapter._transport.calls == transport_calls_before, (
            "a settled OPEN circuit must fail fast without provider contact"
        )
        # The settled state must not be a dead end: after the fresh
        # cooldown the single probe can recover the circuit.  (A healthy
        # budget service is restored first — the A2/A3 pre-provider fault
        # is what is under test, not the ledger itself.)
        clock["now"] += 61
        adapter.budget_service = gc.build_budget_ledger(adapter.config)
        adapter._transport = _SuccessProviderTransport()
        if recover is not None:
            recover(adapter)
        assert json.loads(adapter.generate_remediation("p", "s")) == GOOD_ASSETS
        assert adapter.cb_state == "CLOSED"


class TestProbeLeaseSettlesOnPreProviderFailure(_HalfOpenProbeBase):
    """A pre-provider exception after acquiring the half-open lease must
    settle the lease (OPEN + fresh cooldown) — the audit defect P1-A left
    the circuit HALF-OPEN forever on exactly these paths."""

    def test_a1_probe_lease_settles_when_api_key_missing(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        # Circuit opens while configured; the key is lost afterwards
        # (mid-flight credential loss), so the next admitted call fails
        # pre-provider while holding the half-open lease.
        adapter = _direct_probe_adapter(
            api_key="a1-test-key-not-a-real-credential"
        )
        clock = {"now": 3_000_000.0}
        adapter._time_fn = lambda: clock["now"]
        self._open_circuit(adapter, _FailingProviderTransport(), clock)
        adapter.api_key = ""

        clock["now"] += 61  # cooldown elapsed -> this call takes the lease
        with pytest.raises(gc.GeminiServiceUnavailableException):
            adapter.generate_remediation("p", "s")
        self._assert_settled_open_with_fresh_cooldown(
            adapter, clock,
            recover=lambda a: setattr(a, "api_key", "a1-restored-key-not-a-real-credential"),
        )

    def test_a2_probe_lease_settles_when_budget_store_unavailable(self):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        adapter = _direct_probe_adapter(
            api_key="a2-test-key-not-a-real-credential"
        )
        clock = {"now": 4_000_000.0}
        adapter._time_fn = lambda: clock["now"]
        self._open_circuit(adapter, _FailingProviderTransport(), clock)

        clock["now"] += 61
        adapter.budget_service = _FailingBudgetLedger(
            gc.BudgetStoreUnavailableException("budget store connection refused")
        )
        with pytest.raises(gc.BudgetStoreUnavailableException):
            adapter.generate_remediation("p", "s")
        self._assert_settled_open_with_fresh_cooldown(adapter, clock)

    def test_a3_probe_lease_settles_when_budget_ceiling_exceeded(self):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        adapter = _direct_probe_adapter(
            api_key="a3-test-key-not-a-real-credential"
        )
        clock = {"now": 4_500_000.0}
        adapter._time_fn = lambda: clock["now"]
        self._open_circuit(adapter, _FailingProviderTransport(), clock)

        clock["now"] += 61
        adapter.budget_service = _FailingBudgetLedger(
            gc.BudgetExceededException("monthly budget ceiling exceeded")
        )
        with pytest.raises(gc.BudgetExceededException):
            adapter.generate_remediation("p", "s")
        self._assert_settled_open_with_fresh_cooldown(adapter, clock)

    def test_a6_twenty_concurrent_pre_provider_failure_no_permanent_half_open(
        self, monkeypatch
    ):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        import threading

        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc
        from platform_pkg.agent.infrastructure.llm.gemini_caller import (
            GeminiServiceUnavailableException,
        )

        # Circuit opens while configured; the key is lost afterwards so
        # that EVERY admitted call in the race fails pre-provider.
        adapter = _direct_probe_adapter(
            api_key="a6-test-key-not-a-real-credential"
        )
        clock = {"now": 5_000_000.0}
        adapter._time_fn = lambda: clock["now"]
        self._open_circuit(adapter, _FailingProviderTransport(), clock)
        adapter.api_key = ""

        clock["now"] += 61  # all 20 racers race right after the cooldown
        barrier = threading.Barrier(20)
        outcomes: list = []
        lock = threading.Lock()

        def worker():
            barrier.wait()
            try:
                adapter.generate_remediation("p", "s")
                with lock:
                    outcomes.append("success")
            except GeminiServiceUnavailableException:
                with lock:
                    outcomes.append("fast-reject")
            except Exception:
                with lock:
                    outcomes.append("other")

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # The lease holder fails pre-provider; the 19 racers fail fast on
        # the in-flight lease.  THE DEFECT: without settlement this leaves
        # the breaker HALF-OPEN forever and every future call fails fast
        # indefinitely — the circuit can never probe again.
        assert len(outcomes) == 20
        assert outcomes.count("success") == 0
        assert adapter.cb_state == "OPEN", (
            "a concurrent pre-provider failure must not leave the circuit "
            f"permanently HALF-OPEN (got {adapter.cb_state})"
        )
        # Fresh cooldown: immediate call fails fast, no provider contact...
        with pytest.raises(GeminiServiceUnavailableException):
            adapter.generate_remediation("p", "s")
        # ...and recovery is still possible once configured (no dead
        # state): the budget service was never touched (the key check runs
        # before reserve), so only the credential changes.
        clock["now"] += 61
        adapter.api_key = "a6-recovery-key-not-a-real-credential"
        adapter._transport = _SuccessProviderTransport()
        assert json.loads(adapter.generate_remediation("p", "s")) == GOOD_ASSETS
        assert adapter.cb_state == "CLOSED"


# ---------------------------------------------------------------------------
# Phase 8.7-D.1-CORRECTION-3 — Finding A: half-open probe = exactly ONE
# provider attempt (no retry after a transient failure)
# ---------------------------------------------------------------------------


class _QueueTransport:
    """Transport that replays a scripted queue of outcomes (responses or
    exceptions) and counts every call — the attempts under test."""

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    def __call__(self, payload):
        self.calls += 1
        item = self.outcomes.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _probe_adapter_with_retries(transport, clock, **config_kwargs):
    from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

    kwargs = dict(max_retries=3, backoff_base_seconds=0.001)
    kwargs.update(config_kwargs)
    return gc.GeminiCallerAdapter(
        api_key="c3-a-test-key-not-a-real-credential",
        config=gc.GeminiRuntimeConfig(**kwargs),
        transport=transport,
        time_fn=lambda: clock["now"],
    )


class TestHalfOpenProbeNeverRetries:
    """The half-open probe lease gets EXACTLY ONE provider attempt.

    A probe's purpose is to test the provider: a timeout, connection
    error, 429, 5xx, or malformed response re-opens the circuit with a
    fresh cooldown.  Retrying inside the probe would (1) multiply the
    blast radius of a flapping upstream and (2) let the "single probe"
    contract quietly become a retry storm.  Closed-circuit calls keep
    their configured bounded retry budget unchanged.
    """

    def test_probe_transient_503_makes_exactly_one_transport_call(self):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        transport = _QueueTransport(
            [_gemini_http(503, None)] * 6 + [_gemini_http(503, None)]
        )
        clock = {"now": 9_000_000.0}
        adapter = _probe_adapter_with_retries(transport, clock)

        # Trip the circuit OPEN (3 attempts x 2 calls = 6 failures >= 5).
        for _ in range(2):
            with pytest.raises(
                (gc.GeminiUpstreamException, gc.GeminiTimeoutException)
            ):
                adapter.generate_remediation("p", "s")
        assert adapter.cb_state == "OPEN"
        assert transport.calls == 6

        # Cooldown elapsed: this caller takes the half-open lease.  The
        # probe fails on a transient 503 — and must make EXACTLY ONE
        # provider attempt despite max_retries=3.
        clock["now"] += 61
        before = transport.calls
        with pytest.raises(gc.GeminiUpstreamException):
            adapter.generate_remediation("p", "s")
        assert transport.calls - before == 1, (
            f"the half-open probe made {transport.calls - before} provider "
            "attempts; it must make exactly ONE"
        )
        # Fresh cooldown with a fresh failure count.
        assert adapter.cb_state == "OPEN"
        assert adapter.cb_failures == 1

        # A second caller while the circuit is open again is rejected
        # fast with ZERO provider contact.
        before = transport.calls
        with pytest.raises(gc.GeminiServiceUnavailableException):
            adapter.generate_remediation("p", "s")
        assert transport.calls == before

        # The next cooldown: a healthy one-attempt probe closes it.
        clock["now"] += 61
        transport.outcomes = [_http_200_ok()]
        before = transport.calls
        adapter.generate_remediation("p", "s")
        assert transport.calls - before == 1
        assert adapter.cb_state == "CLOSED"
        assert adapter.cb_failures == 0

    def test_probe_timeout_and_connection_error_also_single_attempt(self):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        for exc_cls in (requests.Timeout, requests.ConnectionError):
            transport = _QueueTransport(
                [exc_cls("failing")] * 6 + [exc_cls("failing")]
            )
            clock = {"now": 9_100_000.0}
            adapter = _probe_adapter_with_retries(transport, clock)
            for _ in range(2):
                with pytest.raises(
                    (gc.GeminiUpstreamException, gc.GeminiTimeoutException)
                ):
                    adapter.generate_remediation("p", "s")
            clock["now"] += 61
            before = transport.calls
            with pytest.raises(
                gc.GeminiTimeoutException
                if exc_cls is requests.Timeout
                else gc.GeminiUpstreamException
            ):
                adapter.generate_remediation("p", "s")
            assert transport.calls - before == 1, (
                f"a probe that failed with {exc_cls.__name__} must make "
                "exactly ONE provider attempt"
            )
            assert adapter.cb_state == "OPEN"

    def test_closed_circuit_call_keeps_configured_retry_budget(self):
        # The bounded retry policy for CLOSED-circuit calls is untouched:
        # transient 503 then 200 => two attempts, success.
        transport = _QueueTransport([_gemini_http(503, None), _http_200_ok()])
        clock = {"now": 9_200_000.0}
        adapter = _probe_adapter_with_retries(transport, clock)
        assert json.loads(adapter.generate_remediation("p", "s")) == GOOD_ASSETS
        assert transport.calls == 2
        assert adapter.cb_state == "CLOSED"


def _http_200_ok():
    return _gemini_http(200, {
        "candidates": [{
            "content": {"parts": [{"text": json.dumps(GOOD_ASSETS)}]}
        }],
        "usageMetadata": {"promptTokenCount": 100, "candidatesTokenCount": 50},
    })


# ---------------------------------------------------------------------------
# Phase 8.7-D.1-CORRECTION-3 — Finding B: non-finite floats are rejected
# on EVERY construction path and fail closed before provider contact
# ---------------------------------------------------------------------------


class TestFiniteConfigValidation:
    @pytest.mark.parametrize("raw", ["nan", "NaN", "NAN", "inf", "Infinity",
                                     "-inf", "+inf", "inf ", "  inf", "1e999"])
    @pytest.mark.parametrize("field", [
        "GEMINI_MONTHLY_BUDGET_USD",
        "GEMINI_INPUT_COST_PER_MILLION_USD",
        "GEMINI_OUTPUT_COST_PER_MILLION_USD",
        "GEMINI_TIMEOUT_SECONDS",
        "GEMINI_BACKOFF_BASE_SECONDS",
    ])
    def test_env_parsing_rejects_non_finite(self, raw, field):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        env = {"GEMINI_API_KEY": "b1-test-key-not-a-real-credential",
               "APP_ENV": "test", field: raw}
        with pytest.raises(ValueError, match="finite"):
            gc.GeminiRuntimeConfig.from_env(env)

    @pytest.mark.parametrize("field,value", [
        ("monthly_budget_usd", float("nan")),
        ("monthly_budget_usd", float("inf")),
        ("monthly_budget_usd", float("-inf")),
        ("input_cost_per_million", float("nan")),
        ("input_cost_per_million", float("inf")),
        ("output_cost_per_million", float("nan")),
        ("output_cost_per_million", float("inf")),
        ("timeout_seconds", float("nan")),
        ("timeout_seconds", float("-inf")),
        ("backoff_base_seconds", float("nan")),
        ("backoff_base_seconds", float("inf")),
    ])
    def test_direct_constructor_rejects_non_finite(self, field, value):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        with pytest.raises(ValueError, match="finite"):
            gc.GeminiRuntimeConfig(**{field: value})

    def test_documented_range_semantics(self):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        # Zero budget is LEGAL: it means "no calls this period" — every
        # reservation is rejected immediately (fail closed), never
        # "unlimited".
        cfg = gc.GeminiRuntimeConfig(monthly_budget_usd=0.0)
        assert cfg.monthly_budget_usd == 0.0
        # Zero backoff is legal (deliberately used by tests).
        assert gc.GeminiRuntimeConfig(backoff_base_seconds=0.0).backoff_base_seconds == 0.0
        # Zero RATES are NOT legal: they would silently disable cost
        # accounting while calls still happen.
        for field in ("input_cost_per_million", "output_cost_per_million"):
            with pytest.raises(ValueError):
                gc.GeminiRuntimeConfig(**{field: 0.0})
        with pytest.raises(ValueError):
            gc.GeminiRuntimeConfig(timeout_seconds=0.0)
        for field in ("max_output_tokens", "estimated_prompt_tokens", "max_retries"):
            with pytest.raises(ValueError):
                gc.GeminiRuntimeConfig(**{field: 0})

    def test_invalid_config_fails_closed_before_any_provider_contact(self):
        # The defect: float("inf") budget parsed fine, and
        # "committed + reserved + amount > inf" is False for finite
        # amounts — the ceiling silently disabled.  Now construction
        # itself refuses the value, so no adapter, no transport, no
        # reservation can ever exist with it.
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        with pytest.raises(ValueError):
            gc.GeminiRuntimeConfig.from_env({
                "GEMINI_API_KEY": "b2-test-key-not-a-real-credential",
                "APP_ENV": "test",
                "GEMINI_MONTHLY_BUDGET_USD": "inf",
            })
        # The finite default config still works end-to-end.
        cfg = gc.GeminiRuntimeConfig.from_env({
            "GEMINI_API_KEY": "b3-test-key-not-a-real-credential",
            "APP_ENV": "test",
        })
        assert cfg.monthly_budget_usd == 150.0

    def test_ledger_constructors_reject_non_finite_identically(self):
        """Local and real-Redis-backed ledgers fail closed the same way —
        even when built directly (defense in depth below the config)."""
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        for bad in (float("nan"), float("inf"), float("-inf")):
            with pytest.raises(ValueError, match="finite"):
                gc.InProcessBudgetLedger(bad, 1.5, 7.5)
            with pytest.raises(ValueError, match="finite"):
                gc.InProcessBudgetLedger(100.0, bad, 7.5)
            with pytest.raises(ValueError, match="finite"):
                gc.InProcessBudgetLedger(100.0, 1.5, bad)
        with pytest.raises(ValueError, match="finite"):
            gc.RedisBudgetLedger(float("nan"), "redis://localhost:6399/0")


# ---------------------------------------------------------------------------
# Phase 8.7-D.1-CORRECTION-3 — Finding C: hard input bounds at the single
# _generate_text choke point, before reservation and provider contact
# ---------------------------------------------------------------------------


class TestInputBounds:
    def _bounded_adapter(self, **config_kwargs):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        kwargs = dict(max_retries=3, backoff_base_seconds=0.001)
        kwargs.update(config_kwargs)
        cfg = gc.GeminiRuntimeConfig(**kwargs)
        ledger = gc.InProcessBudgetLedger(
            cfg.monthly_budget_usd, cfg.input_cost_per_million, cfg.output_cost_per_million
        )
        transport = _QueueTransport([])
        adapter = gc.GeminiCallerAdapter(
            api_key="c-test-key-not-a-real-credential",
            config=cfg, budget_ledger=ledger, transport=transport,
        )
        return adapter, ledger, transport

    def test_oversized_prompt_rejected_before_reservation_and_transport(self):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        adapter, ledger, transport = self._bounded_adapter()
        oversized = "x" * (gc.MAX_PROMPT_CHARS + 1)
        with pytest.raises(gc.GeminiInputBoundException):
            adapter.generate_remediation(oversized, "system")
        assert transport.calls == 0, "no provider contact for oversized input"
        assert ledger.accumulated_spend == 0.0
        assert ledger._reserved == 0.0, "no reservation may be created"

    def test_oversized_system_instruction_rejected_before_transport(self):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        adapter, ledger, transport = self._bounded_adapter()
        with pytest.raises(gc.GeminiInputBoundException):
            adapter.generate_remediation("prompt", "s" * (gc.MAX_SYSTEM_INSTRUCTION_CHARS + 1))
        assert transport.calls == 0
        assert ledger._reserved == 0.0

    def test_max_legal_repository_analysis_fields_fit_within_bounds(self):
        """The authenticated analysis contract's maximum legal fields
        (name 120 / URL 2048 / framework 200 / technology 200, built by the
        gateway-validated handler prompt) must fit under the hard bound —
        the bound protects the budget, not the product."""
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        prompt = (
            "Analyze repository:\n"
            f"- name: {'n' * 120}\n"
            f"- url: {'u' * 2048}\n"
            f"- framework: {'f' * 200}\n"
            f"- technology: {'t' * 200}\n"
            "Produce the strict five-field JSON payload."
        )
        assert len(prompt) < gc.MAX_PROMPT_CHARS
        adapter, ledger, transport = self._bounded_adapter()
        transport.outcomes = [_http_200_ok()]
        assert json.loads(adapter.generate_remediation(prompt, "s")) == GOOD_ASSETS
        assert transport.calls == 1

    def test_unicode_input_reserved_by_utf8_byte_bound(self):
        """Adversarial multibyte input: the reservation must use the UTF-8
        BYTE bound (an upper bound on BPE input tokens), not the char
        count.  A failing call commits the full reservation, so the
        committed spend proves which bound was used."""
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        adapter, ledger, transport = self._bounded_adapter(
            estimated_prompt_tokens=1  # the legacy estimate must NOT lower it
        )
        prompt = "é" * 3000  # 3000 chars, 6000 UTF-8 bytes
        transport.outcomes = [_gemini_http(503, None)] * 3
        with pytest.raises(gc.GeminiUpstreamException):
            adapter.generate_remediation(prompt, "s")
        expected_input_tokens = adapter._estimated_input_tokens(prompt, "s")
        assert expected_input_tokens == (
            len(prompt.encode("utf-8")) + len("s".encode("utf-8"))
            + gc._INPUT_FRAMING_OVERHEAD_TOKENS
        ), "the allowance must be the UTF-8 byte bound + framing"
        worst = (
            expected_input_tokens * adapter.config.input_cost_per_million
            + adapter.config.max_output_tokens * adapter.config.output_cost_per_million
        ) / 1_000_000
        assert abs(ledger.accumulated_spend - 3 * worst) < 1e-9, (
            "the reservation must be the UTF-8 byte bound, not the char "
            f"count nor the tiny legacy estimate (got {ledger.accumulated_spend})"
        )

    def test_too_small_legacy_estimate_cannot_lower_the_safe_bound(self):
        """GEMINI_ESTIMATED_PROMPT_TOKENS is a FLOOR only: setting it to 1
        must not shrink the per-request allowance below the documented
        byte bound."""
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        adapter, _, _ = self._bounded_adapter(estimated_prompt_tokens=1)
        est = adapter._estimated_input_tokens("hello", "")
        assert est >= len("hello".encode("utf-8")) + gc._INPUT_FRAMING_OVERHEAD_TOKENS
        # And a large configured value still acts as a floor upward.
        adapter_hi, _, _ = self._bounded_adapter(estimated_prompt_tokens=999_999)
        assert adapter_hi._estimated_input_tokens("hello", "") == 999_999

    def test_oversized_tech_metadata_rejected_before_transport(self):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        adapter, ledger, transport = self._bounded_adapter()
        metadata = {"big": "y" * (gc.MAX_TECH_METADATA_SERIALIZED_CHARS + 100)}
        with pytest.raises(gc.GeminiInputBoundException):
            adapter.generate_iac_blueprint(metadata)
        assert transport.calls == 0
        assert ledger._reserved == 0.0

    def test_non_scalar_tech_metadata_values_rejected(self):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        adapter, _, transport = self._bounded_adapter()
        for bad_value in (["a", "b"], {"nested": 1}, object()):
            with pytest.raises(gc.GeminiInputBoundException):
                adapter.generate_iac_blueprint({"k": bad_value})
        with pytest.raises(gc.GeminiInputBoundException):
            adapter.generate_iac_blueprint({"k": float("nan")})
        with pytest.raises(gc.GeminiInputBoundException):
            adapter.generate_iac_blueprint({})
        assert transport.calls == 0

    def test_legal_scalar_metadata_accepted_and_bounded(self):
        adapter, _, transport = self._bounded_adapter()
        transport.outcomes = [_http_200_ok()]
        result = adapter.generate_iac_blueprint({"python": "3.12", "workers": 4,
                                                 "ratio": 1.5, "ha": True})
        assert result == GOOD_ASSETS
        assert transport.calls == 1

    def test_oversized_individual_metadata_value_rejected_before_serialization(self):
        """A single value above the per-value cap is rejected by the
        preflight BEFORE json.dumps() — provider and budget ledger
        untouched."""
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        adapter, ledger, transport = self._bounded_adapter()
        oversized_value = "x" * (gc.MAX_TECH_METADATA_STRING_VALUE_CHARS + 1)
        with pytest.raises(gc.GeminiInputBoundException):
            adapter.generate_iac_blueprint({"notes": oversized_value})
        assert transport.calls == 0, "no provider contact for oversized metadata"
        assert ledger.accumulated_spend == 0.0, "no cost committed"
        assert ledger._reserved == 0.0, "no reservation may be created"

    def test_aggregate_metadata_preflight_rejects_before_serialization(self):
        """Each value is well under the per-value cap, but the aggregate
        serialized size exceeds the bound: the preflight must reject
        BEFORE json.dumps() allocates the serialized form."""
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        adapter, ledger, transport = self._bounded_adapter()
        n_items = 60
        value_len = 130  # per item: 8 (key) + 132 (value) + 3 = 143 chars
        metadata = {f"key-{i:02d}": "a" * value_len for i in range(n_items)}
        # Sanity: the per-item caps must NOT be the trigger here — only
        # the aggregate preflight may reject this input.
        assert value_len <= gc.MAX_TECH_METADATA_STRING_VALUE_CHARS
        assert n_items <= gc.MAX_TECH_METADATA_ITEMS
        assert 2 + n_items * (8 + value_len + 2 + 3) > gc.MAX_TECH_METADATA_SERIALIZED_CHARS
        with pytest.raises(gc.GeminiInputBoundException):
            adapter.generate_iac_blueprint(metadata)
        assert transport.calls == 0, "no provider contact for oversized metadata"
        assert ledger.accumulated_spend == 0.0, "no cost committed"
        assert ledger._reserved == 0.0, "no reservation may be created"

    def test_huge_int_metadata_value_rejected_before_serialization(self):
        """An integer with more digits than the bound is rejected by the
        preflight (a 31-digit int would serialize to 31+ characters)."""
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        adapter, ledger, transport = self._bounded_adapter()
        assert len(str(10 ** 30)) > gc.MAX_TECH_METADATA_INT_DIGITS
        with pytest.raises(gc.GeminiInputBoundException):
            adapter.generate_iac_blueprint({"huge": 10 ** 30})
        assert transport.calls == 0, "no provider contact for oversized metadata"
        assert ledger.accumulated_spend == 0.0, "no cost committed"
        assert ledger._reserved == 0.0, "no reservation may be created"


# ---------------------------------------------------------------------------
# Phase 8.7-D.1-CORRECTION-3 — Finding D: retry-chain cost reconciliation —
# committed = sum(known usage) + worst-case allowance per attempt with
# unknown cost.  Never undercount; capped at the reservation.
# ---------------------------------------------------------------------------


def _reconcile_adapter(outcomes, **config_kwargs):
    from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

    kwargs = dict(max_retries=3, backoff_base_seconds=0.001)
    kwargs.update(config_kwargs)
    cfg = gc.GeminiRuntimeConfig(**kwargs)
    ledger = gc.InProcessBudgetLedger(
        cfg.monthly_budget_usd, cfg.input_cost_per_million, cfg.output_cost_per_million
    )
    transport = _QueueTransport(outcomes)
    adapter = gc.GeminiCallerAdapter(
        api_key="d-test-key-not-a-real-credential",
        config=cfg, budget_ledger=ledger, transport=transport,
    )
    return adapter, ledger, transport


def _per_attempt_usd(adapter, input_tokens):
    return (
        input_tokens * adapter.config.input_cost_per_million
        + adapter.config.max_output_tokens * adapter.config.output_cost_per_million
    ) / 1_000_000


def _usage_usd(usage, cfg):
    prompt = usage.get("promptTokenCount", 0)
    cached = usage.get("cachedContentTokenCount", 0)
    cand = usage.get("candidatesTokenCount", 0)
    thoughts = usage.get("thoughtsTokenCount", 0)
    return ((prompt + cached) * cfg.input_cost_per_million
            + (cand + thoughts) * cfg.output_cost_per_million) / 1_000_000


def _gemini_http_usage(usage):
    return _gemini_http(200, {
        "candidates": [{
            "content": {"parts": [{"text": json.dumps(GOOD_ASSETS)}]}
        }],
        "usageMetadata": usage,
    })


class TestRetryChainCostReconciliation:
    PROMPT, SYSTEM = "p", "s"

    def _input_tokens(self, adapter):
        return adapter._estimated_input_tokens(self.PROMPT, self.SYSTEM)

    def test_a_success_with_usage_commits_the_actual_cost(self):
        adapter, ledger, transport = _reconcile_adapter(
            [_gemini_http_usage({"promptTokenCount": 100, "candidatesTokenCount": 50})]
        )
        assert json.loads(adapter.generate_remediation(self.PROMPT, self.SYSTEM)) == GOOD_ASSETS
        assert transport.calls == 1
        expected = _usage_usd({"promptTokenCount": 100, "candidatesTokenCount": 50},
                              adapter.config)
        assert abs(ledger.accumulated_spend - expected) < 1e-12
        assert ledger._reserved == 0.0

    def test_b_timeout_then_success_commits_worst_case_plus_actual(self):
        adapter, ledger, transport = _reconcile_adapter(
            [requests.Timeout("slow"),
             _gemini_http_usage({"promptTokenCount": 100, "candidatesTokenCount": 50})]
        )
        adapter.generate_remediation(self.PROMPT, self.SYSTEM)
        assert transport.calls == 2
        worst = _per_attempt_usd(adapter, self._input_tokens(adapter))
        known = _usage_usd({"promptTokenCount": 100, "candidatesTokenCount": 50},
                           adapter.config)
        # committed = 1x unknown-attempt allowance + actual usage — the
        # timed-out attempt is NOT free.
        assert abs(ledger.accumulated_spend - (worst + known)) < 1e-12
        # And it is within the reservation (3x worst).
        assert ledger.accumulated_spend <= 3 * worst + 1e-12

    def test_c_503_then_success_commits_worst_case_plus_actual(self):
        adapter, ledger, transport = _reconcile_adapter(
            [_gemini_http(503, None),
             _gemini_http_usage({"promptTokenCount": 200, "candidatesTokenCount": 10})]
        )
        adapter.generate_remediation(self.PROMPT, self.SYSTEM)
        assert transport.calls == 2
        worst = _per_attempt_usd(adapter, self._input_tokens(adapter))
        known = _usage_usd({"promptTokenCount": 200, "candidatesTokenCount": 10},
                           adapter.config)
        assert abs(ledger.accumulated_spend - (worst + known)) < 1e-12

    def test_d_success_with_missing_usage_metadata_counts_worst_case(self):
        # A 200 whose body has NO usageMetadata at all.
        no_usage = _gemini_http(200, {
            "candidates": [{"content": {"parts": [{"text": json.dumps(GOOD_ASSETS)}]}}],
        })
        adapter, ledger, transport = _reconcile_adapter([no_usage])
        adapter.generate_remediation(self.PROMPT, self.SYSTEM)
        worst = _per_attempt_usd(adapter, self._input_tokens(adapter))
        # Missing metadata => the (single) attempt's cost is unknown =>
        # the full worst-case allowance is committed.
        assert abs(ledger.accumulated_spend - worst) < 1e-12

    def test_e_total_failure_commits_the_full_reservation(self):
        from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

        adapter, ledger, transport = _reconcile_adapter(
            [_gemini_http(503, None)] * 3
        )
        with pytest.raises(gc.GeminiUpstreamException):
            adapter.generate_remediation(self.PROMPT, self.SYSTEM)
        assert transport.calls == 3
        worst = _per_attempt_usd(adapter, self._input_tokens(adapter))
        assert abs(ledger.accumulated_spend - 3 * worst) < 1e-12
        assert ledger._reserved == 0.0

    def test_f_known_usage_dimensions_aggregated(self):
        """cachedContentTokenCount and thoughtsTokenCount are billed (at
        the input / output rates respectively) — reliable usage is
        aggregated, not ignored."""
        usage = {"promptTokenCount": 100, "cachedContentTokenCount": 40,
                 "candidatesTokenCount": 50, "thoughtsTokenCount": 10}
        adapter, ledger, transport = _reconcile_adapter([_gemini_http_usage(usage)])
        adapter.generate_remediation(self.PROMPT, self.SYSTEM)
        assert abs(ledger.accumulated_spend - _usage_usd(usage, adapter.config)) < 1e-12

    def test_total_token_only_metadata_billed_at_higher_rate(self):
        adapter, ledger, _ = _reconcile_adapter(
            [_gemini_http_usage({"totalTokenCount": 1000})]
        )
        adapter.generate_remediation(self.PROMPT, self.SYSTEM)
        higher = max(adapter.config.input_cost_per_million,
                     adapter.config.output_cost_per_million)
        assert abs(ledger.accumulated_spend - 1000 * higher / 1_000_000) < 1e-12

    def test_committed_never_exceeds_the_reservation(self):
        """Invariant: even if the provider reports usage far above the
        allowance, this reservation commits at most what it reserved."""
        usage = {"promptTokenCount": 10_000_000, "candidatesTokenCount": 10_000_000}
        adapter, ledger, _ = _reconcile_adapter([_gemini_http_usage(usage)])
        adapter.generate_remediation(self.PROMPT, self.SYSTEM)
        worst = _per_attempt_usd(adapter, self._input_tokens(adapter))
        expected = min(_usage_usd(usage, adapter.config), 3 * worst)
        assert abs(ledger.accumulated_spend - expected) < 1e-9
        assert expected < _usage_usd(usage, adapter.config), (
            "the oversized usage must actually exercise the reservation cap"
        )
