"""Phase 8.7-D.1 — analysis route rate limiting (P0-3) end-to-end tests.

Covers the mandated semantics on the REAL gateway app (test client, fake
downstream transport — no provider contact):

* same-user burst is limited with 429 + Retry-After;
* cross-identity isolation (one user's burst must not limit another user);
* per-IP backstop (distinct identities from one source IP);
* fixed-window expiry (injected clock);
* malformed identity fails closed (never allowed, never keyed blindly);
* Redis store down / misconfigured -> fail closed 503 (never unlimited);
* authentication precedes limiting (unauthenticated bursts consume no quota);
* concurrency: the in-process ledger cannot admit more than the limit;
* configuration: safe production defaults + invalid configs rejected.

The shared-Redis limiter is exercised against a REAL Redis in
``test_redis_integration.py`` (CI job ``redis-integration``).
"""

from __future__ import annotations

import threading

import pytest
from fastapi.testclient import TestClient

from conftest import TEST_GW_SECRET, make_token

ANALYZE_PATH = "/api/v1/repository/analyze"
ANALYSIS_BODY = {
    "repo_name": "rl-target",
    "repo_url": "https://github.com/org/rl-target.git",
    "framework": "FastAPI",
    "technology": "Python 3.12",
}


class _FakeAnalysisTransport:
    def call(self, method, url, json_body, identity):
        return {
            "status": "ANALYSIS_COMPLETE",
            "source": "server_gemini",
            "analysis": {
                "dockerfile": "D",
                "k8s_yaml": "K",
                "terraform_tf": "T",
                "pipeline_yaml": "P",
                "report": "R",
            },
        }


def _gateway_app(env_extra: dict):
    from platform_pkg.api_gateway.main import create_app
    from platform_pkg.api_gateway import routers

    env = {"JWT_SECRET": TEST_GW_SECRET, "APP_ENV": "production",
            "ANALYSIS_RATE_LIMIT_SINGLE_INSTANCE_PRODUCTION": "true"}
    env.update(env_extra)
    app = create_app(env=env)
    analysis_router = routers.analysis_router
    app.dependency_overrides[analysis_router.get_downstream_transport] = (
        _FakeAnalysisTransport
    )
    return app


def _post(client: TestClient, token: str, body: dict = None):
    return client.post(
        ANALYZE_PATH,
        json=body or ANALYSIS_BODY,
        headers={"Authorization": f"Bearer {token}"},
    )


# ---------------------------------------------------------------------------
# Burst / isolation / backstop on the real gateway app
# ---------------------------------------------------------------------------


def test_same_user_burst_limited_with_retry_after():
    app = _gateway_app(
        {
            "ANALYSIS_RATE_LIMIT_STORE": "local",
            "ANALYSIS_RATE_LIMIT_PER_IDENTITY_PER_MINUTE": "2",
        }
    )
    token = make_token("burst-user", ["Developer"])
    with TestClient(app) as client:
        assert _post(client, token).status_code == 200
        assert _post(client, token).status_code == 200
        limited = _post(client, token)
    assert limited.status_code == 429
    retry_after = limited.headers.get("Retry-After")
    assert retry_after is not None and 1 <= int(retry_after) <= 60


def test_cross_identity_isolation():
    app = _gateway_app(
        {
            "ANALYSIS_RATE_LIMIT_STORE": "local",
            "ANALYSIS_RATE_LIMIT_PER_IDENTITY_PER_MINUTE": "2",
        }
    )
    user_a = make_token("user-a", ["Developer"])
    user_b = make_token("user-b", ["Developer"])
    with TestClient(app) as client:
        assert _post(client, user_a).status_code == 200
        assert _post(client, user_a).status_code == 200
        assert _post(client, user_a).status_code == 429
        # user-b is a different identity: not limited by user-a's burst.
        assert _post(client, user_b).status_code == 200


def test_per_ip_backstop_limits_distinct_identities():
    app = _gateway_app(
        {
            "ANALYSIS_RATE_LIMIT_STORE": "local",
            "ANALYSIS_RATE_LIMIT_PER_IDENTITY_PER_MINUTE": "30",
            "ANALYSIS_RATE_LIMIT_PER_IP_PER_MINUTE": "3",
        }
    )
    tokens = [make_token(f"funnel-{i}", ["Developer"]) for i in range(4)]
    with TestClient(app) as client:
        codes = [_post(client, t).status_code for t in tokens[:3]]
        fourth = _post(client, tokens[3])
    assert codes == [200, 200, 200]
    # Fourth DISTINCT identity from the same source IP: the IP backstop.
    assert fourth.status_code == 429


def test_unauthenticated_burst_consumes_no_quota():
    app = _gateway_app(
        {
            "ANALYSIS_RATE_LIMIT_STORE": "local",
            "ANALYSIS_RATE_LIMIT_PER_IDENTITY_PER_MINUTE": "2",
        }
    )
    token = make_token("quota-user", ["Developer"])
    with TestClient(app) as client:
        # Unauthenticated hammering: rejected by auth BEFORE the limiter.
        for _ in range(6):
            assert client.post(ANALYZE_PATH, json=ANALYSIS_BODY).status_code == 401
        # The authenticated user still has the full quota.
        assert _post(client, token).status_code == 200
        assert _post(client, token).status_code == 200
        assert _post(client, token).status_code == 429


def test_store_down_fails_closed_503():
    # Nothing listens on this port: the shared store is unreachable.
    app = _gateway_app(
        {
            "ANALYSIS_RATE_LIMIT_STORE": "redis",
            "REDIS_URL": "redis://127.0.0.1:59999/0",
        }
    )
    token = make_token("down-store-user", ["Developer"])
    with TestClient(app) as client:
        resp = _post(client, token)
    # Fail closed: never an unlimited pass, never a fake success.
    assert resp.status_code == 503


def test_malformed_identity_fails_closed():
    # An empty sub cannot exist behind the real auth dependency, so test the
    # limiter boundary directly: it must refuse to key on a blank identity.
    from platform_pkg.api_gateway.core.analysis_rate_limit import (
        LocalAnalysisRateLimiter,
        RateLimitStoreUnavailable,
    )

    limiter = LocalAnalysisRateLimiter(
        limit_per_identity_per_minute=10, limit_per_ip_per_minute=10
    )
    for bad in ("", "   "):
        with pytest.raises(RateLimitStoreUnavailable):
            limiter.check(bad, "127.0.0.1")


# ---------------------------------------------------------------------------
# Unit level: window expiry, concurrency, configuration
# ---------------------------------------------------------------------------


def test_fixed_window_expiry_with_injected_clock():
    from platform_pkg.api_gateway.core.analysis_rate_limit import (
        LocalAnalysisRateLimiter,
    )

    clock = {"now": 1_000.0}
    limiter = LocalAnalysisRateLimiter(
        limit_per_identity_per_minute=2,
        limit_per_ip_per_minute=10,
        window_seconds=60,
        time_fn=lambda: clock["now"],
    )
    assert limiter.check("u", "ip").allowed
    assert limiter.check("u", "ip").allowed
    denied = limiter.check("u", "ip")
    assert not denied.allowed
    assert denied.retry_after_seconds >= 1
    # After the window elapses the identity has quota again.
    clock["now"] += 61
    assert limiter.check("u", "ip").allowed


def test_concurrent_requests_cannot_exceed_limit():
    from platform_pkg.api_gateway.core.analysis_rate_limit import (
        LocalAnalysisRateLimiter,
    )

    limiter = LocalAnalysisRateLimiter(
        limit_per_identity_per_minute=5, limit_per_ip_per_minute=1000
    )
    results: list[bool] = []
    lock = threading.Lock()

    def worker():
        decision = limiter.check("hammer", "10.0.0.1")
        with lock:
            results.append(decision.allowed)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(results) == 5, "concurrent checks admitted more than the limit"


def test_production_defaults_are_safe():
    from platform_pkg.api_gateway.core.analysis_rate_limit import (
        load_analysis_rate_limit_settings,
    )

    settings = load_analysis_rate_limit_settings({})
    assert settings["limit_per_identity_per_minute"] == 30
    assert settings["limit_per_ip_per_minute"] == 120
    assert settings["window_seconds"] == 60
    # Without a redis URL the explicit single-instance mode is chosen —
    # documented and logged, never a silent multi-replica assumption.
    assert settings["store"] == "local"


def test_invalid_rate_limit_configuration_rejected():
    from platform_pkg.api_gateway.core.analysis_rate_limit import (
        AnalysisRateLimitConfigurationError,
        load_analysis_rate_limit_settings,
    )

    with pytest.raises(AnalysisRateLimitConfigurationError):
        load_analysis_rate_limit_settings(
            {"ANALYSIS_RATE_LIMIT_PER_IDENTITY_PER_MINUTE": "0"}
        )
    with pytest.raises(AnalysisRateLimitConfigurationError):
        load_analysis_rate_limit_settings(
            {"ANALYSIS_RATE_LIMIT_STORE": "memcached"}
        )
    with pytest.raises(AnalysisRateLimitConfigurationError):
        load_analysis_rate_limit_settings({"ANALYSIS_RATE_LIMIT_STORE": "redis"})


def test_forwarded_headers_are_never_trusted():
    """The limiter keys on the TCP peer only: a spoofed X-Forwarded-For
    must not change the source-IP dimension at all."""
    from platform_pkg.api_gateway.core.analysis_rate_limit import (
        LocalAnalysisRateLimiter,
    )

    app = _gateway_app(
        {
            "ANALYSIS_RATE_LIMIT_STORE": "local",
            "ANALYSIS_RATE_LIMIT_PER_IDENTITY_PER_MINUTE": "100",
            "ANALYSIS_RATE_LIMIT_PER_IP_PER_MINUTE": "2",
        }
    )
    with TestClient(app) as client:
        token = make_token("spoof-user", ["Developer"])
        # Requests from the SAME peer with different hostile headers:
        # the peer count (2) is what matters, never the header.
        r1 = client.post(
            ANALYZE_PATH, json=ANALYSIS_BODY,
            headers={"Authorization": f"Bearer {token}",
                     "X-Forwarded-For": "1.1.1.1, 2.2.2.2"},
        )
        r2 = client.post(
            ANALYZE_PATH, json=ANALYSIS_BODY,
            headers={"Authorization": f"Bearer {token}",
                     "X-Forwarded-For": "9.9.9.9"},
        )
        r3 = client.post(
            ANALYZE_PATH, json=ANALYSIS_BODY,
            headers={"Authorization": f"Bearer {token}",
                     "X-Forwarded-For": "7.7.7.7"},
        )
    assert r1.status_code == 200
    assert r2.status_code == 200
    # Same peer again (yet another spoofed header) -> IP backstop applies.
    assert r3.status_code == 429
    # Structural proof the spoofed values were never read: the app's
    # limiter contains exactly ONE ip counter key (the real peer).
    limiter = app.state.analysis_rate_limiter
    assert isinstance(limiter, LocalAnalysisRateLimiter)
    assert list(limiter._ip_counts.keys()) == ["testclient"]


# ---------------------------------------------------------------------------
# Production posture: shared Redis state is REQUIRED (D1-CORRECTION §10)
# ---------------------------------------------------------------------------


class TestProductionSharedStateRequirement:
    """staging/production must fail closed when the shared (Redis) state
    that preserves the security limits is missing — for BOTH the gateway
    rate limiter and the agent budget ledger. Development/test may use the
    explicit in-process mode. A documented single-replica staging/production
    deployment opts in via the exact-value flag."""

    def test_development_without_redis_uses_local(self):
        from platform_pkg.api_gateway.core.analysis_rate_limit import (
            load_analysis_rate_limit_settings,
        )

        for app_env in ("development", "test", ""):
            settings = load_analysis_rate_limit_settings({"APP_ENV": app_env})
            assert settings["store"] == "local"

    def test_staging_and_production_without_redis_fail_closed(self):
        from platform_pkg.api_gateway.core.analysis_rate_limit import (
            AnalysisRateLimitConfigurationError,
            load_analysis_rate_limit_settings,
        )

        for app_env in ("staging", "production"):
            with pytest.raises(AnalysisRateLimitConfigurationError):
                load_analysis_rate_limit_settings({"APP_ENV": app_env})
            # Even an explicitly local store is refused without the flag:
            with pytest.raises(AnalysisRateLimitConfigurationError):
                load_analysis_rate_limit_settings(
                    {"APP_ENV": app_env, "ANALYSIS_RATE_LIMIT_STORE": "local"}
                )

    def test_production_explicit_single_instance_flag_is_allowed(self):
        from platform_pkg.api_gateway.core.analysis_rate_limit import (
            load_analysis_rate_limit_settings,
        )

        settings = load_analysis_rate_limit_settings(
            {
                "APP_ENV": "production",
                "ANALYSIS_RATE_LIMIT_SINGLE_INSTANCE_PRODUCTION": "true",
            }
        )
        assert settings["store"] == "local"

    def test_single_instance_flag_requires_the_exact_value(self):
        from platform_pkg.api_gateway.core.analysis_rate_limit import (
            AnalysisRateLimitConfigurationError,
            load_analysis_rate_limit_settings,
        )

        for bad in ("True", "yes", "1", "TRUE"):  # (surrounding whitespace is tolerated)
            with pytest.raises(AnalysisRateLimitConfigurationError):
                load_analysis_rate_limit_settings(
                    {
                        "APP_ENV": "production",
                        "ANALYSIS_RATE_LIMIT_SINGLE_INSTANCE_PRODUCTION": bad,
                    }
                )

    def test_production_with_redis_uses_the_shared_store(self):
        from platform_pkg.api_gateway.core.analysis_rate_limit import (
            load_analysis_rate_limit_settings,
        )

        settings = load_analysis_rate_limit_settings(
            {"APP_ENV": "production", "REDIS_URL": "redis://gw:6379/0"}
        )
        assert settings["store"] == "redis"

    # -- agent-side budget ledger -----------------------------------------

    def test_agent_development_without_redis_uses_local(self):
        from platform_pkg.agent.infrastructure.llm.gemini_caller import (
            GeminiRuntimeConfig,
        )

        for app_env in ("development", "test", ""):
            cfg = GeminiRuntimeConfig.from_env({"APP_ENV": app_env})
            assert cfg.budget_store == "local"

    def test_agent_staging_and_production_without_redis_fail_closed(self):
        from platform_pkg.agent.infrastructure.llm.gemini_caller import (
            GeminiRuntimeConfig,
        )

        for app_env in ("staging", "production"):
            with pytest.raises(ValueError):
                GeminiRuntimeConfig.from_env({"APP_ENV": app_env})
            with pytest.raises(ValueError):
                GeminiRuntimeConfig.from_env(
                    {"APP_ENV": app_env, "GEMINI_BUDGET_STORE": "local"}
                )

    def test_agent_production_explicit_single_instance_flag_is_allowed(self):
        from platform_pkg.agent.infrastructure.llm.gemini_caller import (
            GeminiRuntimeConfig,
        )

        cfg = GeminiRuntimeConfig.from_env(
            {
                "APP_ENV": "production",
                "GEMINI_BUDGET_SINGLE_INSTANCE_PRODUCTION": "true",
            }
        )
        assert cfg.budget_store == "local"

    def test_agent_production_with_redis_uses_the_shared_store(self):
        from platform_pkg.agent.infrastructure.llm.gemini_caller import (
            GeminiRuntimeConfig,
        )

        cfg = GeminiRuntimeConfig.from_env(
            {
                "APP_ENV": "production",
                "GEMINI_BUDGET_STORE": "redis",
                "REDIS_URL": "redis://agent:6379/0",
            }
        )
        assert cfg.budget_store == "redis"
        assert cfg.redis_url == "redis://agent:6379/0"

    def test_production_gateway_app_refuses_local_limiter_at_startup(self):
        # The startup path itself must fail closed (not just the loader):
        # a production gateway without Redis cannot boot.
        from platform_pkg.api_gateway.main import create_app
        from platform_pkg.api_gateway.core.analysis_rate_limit import (
            AnalysisRateLimitConfigurationError,
        )

        with pytest.raises(AnalysisRateLimitConfigurationError) as excinfo:
            create_app(env={"JWT_SECRET": TEST_GW_SECRET, "APP_ENV": "production"})
        assert "Redis" in str(excinfo.value)
