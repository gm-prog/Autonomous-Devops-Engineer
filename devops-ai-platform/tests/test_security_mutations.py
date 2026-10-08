"""Phase 8.7-C — adversarial mutation / bypass tests (section 13).

A green security suite proves nothing on its own.  Each test here
deliberately WEAKENS one control on an isolated copy of the repository and
proves two things:

1. the structural guard detects the weakened source (the guard turns red), and
2. with the control weakened, the attack that the security property forbids
   actually succeeds against the mutated code — i.e., the behavioral security
   tests would turn red too.

Mutations:

M1. Telemetry: restore the generic user-facing dispatcher into the gateway.
M2. Telemetry: disable producer authentication on the ingestion boundary.
M3. Android:   reintroduce BuildConfig.GEMINI_API_KEY on the request path.
M4. JWT:       restore the hard-coded fallback as the production default.
M5. Android:   reintroduce the fictitious remote Gemini execution path
               (unauthenticated backend request to an endpoint that does not
               exist in this branch) — the false "authenticated backend
               exists" regression.
"""

from __future__ import annotations

import importlib
import shutil
import sys
import types
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import security_guards.android_guard as android_guard
import security_guards.gateway_guard as gateway_guard
import security_guards.jwt_guard as jwt_guard
from conftest import REPO_ROOT, TEST_GW_SECRET, make_token

INGEST_PATH = "/api/internal/telemetry/observations"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def mutated_repo(tmp_path):
    """An isolated copy of the real repository (mutations never touch the
    working tree)."""
    dst = tmp_path / "repo"
    shutil.copytree(
        REPO_ROOT, dst, ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__")
    )
    return dst


def _register_mutated_tree(repo_root: Path, top_name: str) -> str:
    """Register a synthetic platform root over the mutated tree so the
    mutated production modules import exactly as they do in production."""
    top = types.ModuleType(top_name)
    top.__path__ = []
    sys.modules[top_name] = top
    for sub, rel in (
        ("api_gateway", "api-gateway"),
        ("monitoring", "monitoring-service"),
        ("shared_kernel", "shared-kernel"),
    ):
        subpkg = types.ModuleType(f"{top_name}.{sub}")
        subpkg.__path__ = [str(repo_root / "devops-ai-platform" / rel)]
        sys.modules[f"{top_name}.{sub}"] = subpkg
    return top_name


# ---------------------------------------------------------------------------
# M1 — restore the generic dispatcher (user JWT impersonates producer)
# ---------------------------------------------------------------------------

LEGACY_DISPATCH_ROUTE = '''

@router.post("/dispatch/{service_name}")
def dispatch_service_proxy(service_name: str, payload: dict, request: Request, user: dict = Depends(verify_token)):
    if service_name not in SERVICES:
        raise HTTPException(status_code=404, detail="Target microservice not reachable or registered in BFF catalog.")
    target_url = f"{SERVICES[service_name]}/api/internal"
    return {
        "status": "PROXY_PASSTHROUGH",
        "forwarded_to": target_url,
        "authorizing_identity": user["sub"],
        "payload_relayed": payload
    }
'''


def _apply_dispatch_mutation(repo: Path) -> None:
    router_path = repo / "devops-ai-platform/api-gateway/routers/gateway_router.py"
    src = router_path.read_text(encoding="utf-8")
    # Re-add monitoring to the routing table...
    src = src.replace(
        '    "incident": "http://incident-service:8050",\n}',
        '    "incident": "http://incident-service:8050",\n'
        '    "monitoring": "http://monitoring-service:8040",\n}',
        1,
    )
    # ...and restore the arbitrary-payload dispatcher.
    src += LEGACY_DISPATCH_ROUTE
    router_path.write_text(src, encoding="utf-8")


def test_mutation_m1_dispatch_restoration_detected(mutated_repo):
    _apply_dispatch_mutation(mutated_repo)

    # (1) Structural guard turns red.
    violations = gateway_guard.check_gateway(mutated_repo)
    assert violations, "guard stayed green after the dispatcher was restored"
    joined = "\n".join(violations)
    assert "dispatch" in joined.lower()
    assert "monitoring" in joined.lower()

    # (2) Behavioral: with the control weakened, an ordinary Developer JWT can
    #     impersonate the telemetry producer through the gateway.
    top = _register_mutated_tree(mutated_repo, "mut_m1")
    main = importlib.import_module(f"{top}.api_gateway.main")
    app = main.create_app(env={"JWT_SECRET": TEST_GW_SECRET, "APP_ENV": "production"})
    dev_token = make_token("dev-attacker", ["Developer"])
    with TestClient(app) as client:
        resp = client.post(
            "/v1/gateway/dispatch/monitoring",
            json={"service_id": "spring-gateway", "metric_name": "cpu", "value": 99.5},
            headers={"Authorization": f"Bearer {dev_token}"},
        )
        # The attack SUCCEEDS against the weakened control: the user's
        # arbitrary payload is relayed toward monitoring's internal endpoint.
        assert resp.status_code == 200
        assert resp.json()["status"] == "PROXY_PASSTHROUGH"
        assert "monitoring-service:8040/api/internal" in resp.json()["forwarded_to"]


# ---------------------------------------------------------------------------
# M2 — disable producer authentication on the telemetry boundary
# ---------------------------------------------------------------------------


def _apply_producer_auth_bypass(repo: Path) -> None:
    router_path = (
        repo / "devops-ai-platform/monitoring-service/presentation/rest/telemetry_router.py"
    )
    src = router_path.read_text(encoding="utf-8")
    # Weaken the control: skip HMAC verification entirely.
    weakened = src.replace(
        "    secret = get_producer_secret()",
        "    if True:  # MUTATION: producer auth disabled\n        return \"hmac-producer\"",
        1,
    )
    assert weakened != src, "mutation target not found in telemetry router"
    router_path.write_text(weakened, encoding="utf-8")


def test_mutation_m2_producer_auth_bypass_detected(mutated_repo):
    _apply_producer_auth_bypass(mutated_repo)

    # (1) Structural guard turns red (G5: no HMAC enforcement left).
    violations = gateway_guard.check_gateway(mutated_repo)
    assert violations, "guard stayed green after producer auth was disabled"
    assert any("HMAC" in v for v in violations)

    # (2) Behavioral: unsigned telemetry (and a Developer JWT) now ingests and
    #     can manufacture a threshold event.
    import json
    import os

    top = _register_mutated_tree(mutated_repo, "mut_m2")
    main = importlib.import_module(f"{top}.monitoring.main")

    published: list = []

    class _SpyPublisher:
        def publish(self, event):
            published.append(event)
            return True

    os.environ["TELEMETRY_HMAC_SECRET"] = "irrelevant-now"
    try:
        app = main.create_app(publisher=_SpyPublisher())
        with TestClient(app) as client:
            body = json.dumps(
                {"service_id": "spring-gateway", "metric_name": "cpu_percent",
                 "value": 99.9, "unit": "percent"}
            ).encode()
            # No auth headers at all:
            resp = client.post(INGEST_PATH, content=body,
                               headers={"content-type": "application/json"})
            assert resp.status_code == 200
            assert resp.json()["threshold_breached"] is True
            # ...and with a Developer JWT (human impersonating producer):
            dev_token = make_token("dev-attacker", ["Developer"])
            resp2 = client.post(
                INGEST_PATH, content=body,
                headers={"Authorization": f"Bearer {dev_token}",
                         "content-type": "application/json"},
            )
            assert resp2.status_code == 200
            # The event bus received fabricated threshold events:
            assert len(published) >= 1
    finally:
        os.environ.pop("TELEMETRY_HMAC_SECRET", None)


# ---------------------------------------------------------------------------
# M3 — reintroduce BuildConfig.GEMINI_API_KEY in the Android app
# ---------------------------------------------------------------------------

ANDROID_MUTATION_LINES = """
    // legacy direct-call path (regression probe)
    val legacyApiKey = BuildConfig.GEMINI_API_KEY
    val legacyGeminiUrl = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent?key=$legacyApiKey"
"""


def _apply_android_secret_mutation(repo: Path) -> None:
    kt = repo / "app/src/main/java/com/example/data/GeminiClient.kt"
    src = kt.read_text(encoding="utf-8")
    src = src.replace(
        "object GeminiClient {\n",
        "object GeminiClient {\n" + ANDROID_MUTATION_LINES,
        1,
    )
    kt.write_text(src, encoding="utf-8")


def test_mutation_m3_android_secret_reintroduction_detected(mutated_repo):
    _apply_android_secret_mutation(mutated_repo)

    violations = android_guard.check_android(mutated_repo)
    assert violations, "guard stayed green after the bundled Gemini key returned"
    joined = "\n".join(violations)
    assert "BuildConfig" in joined
    assert "key" in joined.lower()


# ---------------------------------------------------------------------------
# M4 — restore the hard-coded JWT fallback as the production default
# ---------------------------------------------------------------------------

JWT_FALLBACK_LINE = '    JWT_SECRET: str = os.getenv("JWT_SECRET", "super-secret-devops-platform-signature-token")\n'


def _apply_jwt_fallback_mutation(repo: Path) -> None:
    config_path = repo / "devops-ai-platform/api-gateway/config/__init__.py"
    src = config_path.read_text(encoding="utf-8")
    src = src.replace(
        "    RATE_LIMIT_MAX_REQUESTS: int = int(os.getenv(\"RATE_LIMIT_MAX_REQUESTS\", 100))  # per minute",
        JWT_FALLBACK_LINE
        + "    RATE_LIMIT_MAX_REQUESTS: int = int(os.getenv(\"RATE_LIMIT_MAX_REQUESTS\", 100))  # per minute",
        1,
    )
    assert "JWT_SECRET: str" in src, "mutation target not found in gateway config"
    config_path.write_text(src, encoding="utf-8")


def test_mutation_m4_jwt_fallback_restoration_detected(mutated_repo):
    _apply_jwt_fallback_mutation(mutated_repo)

    # (1) Structural guard turns red (bundled fallback restored).
    violations = jwt_guard.check_jwt(mutated_repo)
    assert violations, "guard stayed green after the hard-coded fallback returned"
    assert any("fallback" in v.lower() for v in violations)

    # (2) Behavioral: the production default is a usable signing secret again —
    #     a misconfigured process silently signs/verifies with the bundled
    #     value instead of failing closed.
    import jwt as pyjwt
    import os

    # Import the mutated config with JWT_SECRET absent from the process
    # environment so the class default (the restored bundled fallback) is
    # what gets evaluated.
    saved_secret = os.environ.pop("JWT_SECRET", None)
    try:
        top = _register_mutated_tree(mutated_repo, "mut_m4")
        config_mod = importlib.import_module(f"{top}.api_gateway.config")
    finally:
        if saved_secret is not None:
            os.environ["JWT_SECRET"] = saved_secret

    assert hasattr(config_mod.GatewaySettings, "JWT_SECRET")
    assert (
        config_mod.GatewaySettings.JWT_SECRET
        == jwt_guard.LEGACY_SECRET_VALUE
    ), "the production default must never be a bundled secret"
    # A token signed with that bundled default verifies against it — exactly
    # the unsafe property the fail-closed contract forbids.
    token = pyjwt.encode(
        {"sub": "victim", "roles": ["ClusterAdmin"], "iat": 0, "exp": 9999999999},
        config_mod.GatewaySettings.JWT_SECRET,
        algorithm="HS256",
    )
    claims = pyjwt.decode(
        token, config_mod.GatewaySettings.JWT_SECRET, algorithms=["HS256"]
    )
    assert claims["roles"] == ["ClusterAdmin"]


# ---------------------------------------------------------------------------
# M5 — reintroduce the fictitious remote Gemini execution path
# ---------------------------------------------------------------------------

_FICTITIOUS_REMOTE_BACKEND_METHOD = '''

    /**
     * Fictitious remote analysis (regression probe): unauthenticated request
     * to an endpoint that does not exist in this branch.
     */
    suspend fun queryRemoteAnalysis(
        baseUrlStr: String,
        repoName: String,
        repoUrl: String,
        framework: String,
        technology: String
    ): DevOpsAnalysisResult? {
        val cleanUrl = baseUrlStr.trim().removeSuffix("/")
        val endpoint = "$cleanUrl/api/v1/repository/analyze"
        val request = okhttp3.Request.Builder()
            .url(endpoint)
            .post(okhttp3.RequestBody.create(null, "{}".toByteArray()))
            .build()
        client.newCall(request).execute().use { response ->
            return null
        }
    }
'''


def _apply_fictitious_remote_mutation(repo: Path) -> None:
    """Reintroduce the pre-correction shape: GeminiClient delegates analysis
    to an unauthenticated backend client that targets an endpoint no
    implemented, authenticated backend serves in this branch."""
    backend_client = repo / "app/src/main/java/com/example/data/BackendGatewayClient.kt"
    src = backend_client.read_text(encoding="utf-8")
    # Insert the fictitious remote-analysis method before the object's end.
    src = src.rstrip()
    assert src.endswith("}")
    src = src[:-1].rstrip() + "\n" + _FICTITIOUS_REMOTE_BACKEND_METHOD.strip("\n") + "\n}\n"
    backend_client.write_text(src, encoding="utf-8")

    gemini = repo / "app/src/main/java/com/example/data/GeminiClient.kt"
    src = gemini.read_text(encoding="utf-8")
    old_sig = """    fun analyzeRepository(
        repoName: String,
        repoUrl: String,
        framework: String,
        technology: String
    ): DevOpsAnalysisResult {
        return generateSimulatedAssets(repoName, technology, framework)
    }"""
    new_sig = """    fun analyzeRepository(
        repoName: String,
        repoUrl: String,
        framework: String,
        technology: String,
        backendBaseUrl: String? = null
    ): DevOpsAnalysisResult {
        if (backendBaseUrl != null) {
            return BackendGatewayClient.queryRemoteAnalysis(
                baseUrlStr = backendBaseUrl,
                repoName = repoName,
                repoUrl = repoUrl,
                framework = framework,
                technology = technology
            ) ?: generateSimulatedAssets(repoName, technology, framework)
        }
        return generateSimulatedAssets(repoName, technology, framework)
    }"""
    assert old_sig in src, "mutation target not found in GeminiClient.kt"
    src = src.replace(old_sig, new_sig, 1)
    gemini.write_text(src, encoding="utf-8")


def test_mutation_m5_fictitious_remote_path_detected(mutated_repo):
    from test_android_secret_guards import check_offline_only_contract

    _apply_fictitious_remote_mutation(mutated_repo)

    violations = check_offline_only_contract(mutated_repo)
    assert violations, (
        "contract test stayed green after the fictitious unauthenticated "
        "remote analysis path was reintroduced"
    )
    joined = "\n".join(violations)
    assert "queryRemoteAnalysis" in joined
    assert "backendBaseUrl" in joined
    assert "/api/v1/repository/analyze" in joined
    assert "BackendGatewayClient" in joined
    for v in violations:
        print("  violation:", v)
