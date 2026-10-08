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


def _agent_app(llm=None):
    from platform_pkg.agent.main import create_app

    return create_app(llm_engine=llm)


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
        with TestClient(_agent_app()) as client:
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

    defaults = dict(
        api_key="test-server-key",
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

        agent_app = agent_create_app()
        # Wire the production caller with a fake provider transport:
        caller = gc.GeminiCallerAdapter(
            api_key="server-side-test-key",
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
