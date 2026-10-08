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
M6. Android:   reintroduce stale live-Gemini UI claims (the UI again says it
               compiles live blueprints via Gemini AI and presents the
               simulator as a "Gemini Resilient API Cockpit") — the false
               "live Gemini telemetry" regression.
M7. Docs:      reintroduce the stale roadmap architecture claim (pinging/
               configuring the gateway makes the repository generator route
               analysis to the remote server instead of simulation) — the
               false "remote analysis transport" documentation regression.

Phase 8.7-D mutations:

M8. Gateway:   disable the analysis role gate (a Viewer JWT can trigger
               provider-backed analysis).
M9. Gateway:   accept a client-supplied Gemini key field on the analysis
               schema and forward it to the backend.
M10. Caller:   missing server Gemini key fails OPEN (fabricated "simulated"
               response instead of a typed failure).
M11. Caller:   provider 401/403 is swallowed and answered with a fabricated
               "simulated" success.
M12. Caller:   the budget ceiling is bypassed (exhausted budget still
               places provider calls).

Phase 8.7-D.1 mutations:

M13. Agent:    restore PER-REQUEST Gemini adapter construction (circuit-
               breaker and budget state reset on every request).
M14. Gateway:  remove the analysis route's rate-limiting dependency
               (unlimited provider-bound analysis).
M15. Android:  re-enable bearer-JWT transport to arbitrary cleartext
               endpoints (disable the URL transport policy).
M16. Caller:   reintroduce the NON-ATOMIC budget check-then-act (TOCTOU
               race) — concurrent reservations race past the ceiling.
M17. Runtime:  remove the canonical agent-service build from the D1
               compose stack (runtime verification must turn red).
M18. Caller:   revert the model to the deprecated gemini-3.5-flash and
               drop the maxOutputTokens bound from the provider payload.
"""

from __future__ import annotations

import importlib
import shutil
import sys
import time
import types
from pathlib import Path

import re

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
        ("agent", "agent-service"),
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
    app = main.create_app(env={"JWT_SECRET": TEST_GW_SECRET, "APP_ENV": "production",
        "ANALYSIS_RATE_LIMIT_SINGLE_INSTANCE_PRODUCTION": "true"})
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
    from test_android_secret_guards import check_analysis_transport_contract

    _apply_fictitious_remote_mutation(mutated_repo)

    violations = check_analysis_transport_contract(mutated_repo)
    assert violations, (
        "contract test stayed green after the fictitious unauthenticated "
        "remote analysis path was reintroduced"
    )
    joined = "\n".join(violations)
    # The unauthenticated client method itself is the regression:
    assert "queryRemoteAnalysis" in joined
    for v in violations:
        print("  violation:", v)


# ---------------------------------------------------------------------------
# M6 — reintroduce stale live-Gemini UI claims
# ---------------------------------------------------------------------------


def _apply_stale_ui_mutation(repo: Path) -> None:
    """Reintroduce the pre-correction UI wording: live-Gemini blueprint
    claims and the unqualified "Gemini Resilient API Cockpit" title that
    presents local simulation as live provider telemetry."""
    main_activity = repo / "app/src/main/java/com/example/MainActivity.kt"
    src = main_activity.read_text(encoding="utf-8")

    old_copy = "Register repository parameters to generate offline DevOps blueprints by default; authenticated live backend analysis can be enabled in Settings."
    old_title = '"AI Simulation & Resilience Cockpit"'
    assert old_copy in src, "mutation target (blueprint copy) not found"
    assert old_title in src, "mutation target (cockpit title) not found"

    src = src.replace(
        old_copy,
        "Register code parameters to compile live blueprints via Gemini AI.",
        1,
    )
    src = src.replace(old_title, '"Gemini Resilient API Cockpit"', 1)
    main_activity.write_text(src, encoding="utf-8")


def test_mutation_m6_stale_live_gemini_ui_detected(mutated_repo):
    from test_android_secret_guards import check_ui_truthfulness

    _apply_stale_ui_mutation(mutated_repo)

    violations = check_ui_truthfulness(mutated_repo)
    assert violations, (
        "UI truthfulness contract stayed green after stale live-Gemini "
        "claims were reintroduced"
    )
    joined = "\n".join(violations)
    assert "live blueprints via gemini" in joined
    assert "gemini resilient api cockpit" in joined
    for v in violations:
        print("  violation:", v)


# ---------------------------------------------------------------------------
# M7 — reintroduce the stale roadmap remote-analysis claim
# ---------------------------------------------------------------------------


def _apply_stale_roadmap_mutation(repo: Path) -> None:
    """Take the corrected roadmap and reintroduce the pre-correction claim:
    toggling/pinging the gateway makes the repository generator route
    analyze tasks to the remote server instead of simulation."""
    roadmap = repo / "VS_CODE_AND_VERCEL_ROADMAP.md"
    src = roadmap.read_text(encoding="utf-8")

    honest = (
        "6.  **The probe is diagnostics.** The result only indicates whether the"
        "\n    configured endpoint is reachable. Reaching `CONNECTED` alone does not"
        "\n    switch analysis: without a gateway JWT the live path stays off and"
        "\n    repository analysis remains offline and deterministic (source badge"
        "\n    `OFFLINE_SIM`)."
    )
    assert honest in src, "mutation target not found in roadmap"

    # Reintroduce the pre-correction claim: the probe alone makes the
    # repository generator route analyze tasks to the remote server
    # instead of the on-device engine.
    stale = (
        "6.  **Connect to Remote Backend**: as soon as the probe receives a"
        "\n    successful handshake, the repository generator will route analyze"
        "\n    tasks directly to your remote edge server instead of using"
        "\n    simulation!"
    )
    src = src.replace(honest, stale, 1)
    roadmap.write_text(src, encoding="utf-8")


def test_mutation_m7_stale_roadmap_claim_detected(mutated_repo):
    from test_android_secret_guards import check_roadmap_truthfulness

    _apply_stale_roadmap_mutation(mutated_repo)

    violations = check_roadmap_truthfulness(mutated_repo)
    assert violations, (
        "roadmap truthfulness contract stayed green after the stale "
        "remote-analysis claim was reintroduced"
    )
    joined = "\n".join(violations)
    assert "route analyze tasks directly to your remote edge server" in joined
    assert "instead of using simulation" in joined
    assert "connect to remote backend" in joined
    for v in violations:
        print("  violation:", v)


# ---------------------------------------------------------------------------
# M8 — disable the analysis role gate (insufficient role triggers analysis)
# ---------------------------------------------------------------------------


def _apply_role_gate_bypass(repo: Path) -> None:
    auth_path = repo / "devops-ai-platform/api-gateway/core/auth.py"
    src = auth_path.read_text(encoding="utf-8")
    target = "    if not (set(user.get(\"roles\", [])) & ANALYSIS_ROLES):"
    assert target in src, "M8 target not found in require_analysis_role"
    src = src.replace(target, "    if False:  # MUTATION: analysis role gate disabled", 1)
    auth_path.write_text(src, encoding="utf-8")


def _assert_analysis_role_gate_intact(repo: Path) -> None:
    """Structural guard: the analysis route must keep its role gate, and the
    gate must actually check ANALYSIS_ROLES."""
    router_src = (repo / "devops-ai-platform/api-gateway/routers/analysis_router.py").read_text(encoding="utf-8")
    assert "Depends(require_analysis_role)" in router_src, (
        "analysis route lost its role-authorization gate"
    )
    auth_src = (repo / "devops-ai-platform/api-gateway/core/auth.py").read_text(encoding="utf-8")
    gate = auth_src.split("def require_analysis_role", 1)[1]
    assert "ANALYSIS_ROLES" in gate and "raise HTTPException" in gate, (
        "require_analysis_role no longer enforces ANALYSIS_ROLES"
    )


def test_mutation_m8_analysis_role_gate_bypass_detected(mutated_repo):
    # (1) Structural guard holds on the unmutated repo.
    _assert_analysis_role_gate_intact(REPO_ROOT)
    _apply_role_gate_bypass(mutated_repo)
    # The mutated gate is structurally broken:
    auth_src = (mutated_repo / "devops-ai-platform/api-gateway/core/auth.py").read_text(encoding="utf-8")
    gate = auth_src.split("def require_analysis_role", 1)[1]
    assert "ANALYSIS_ROLES" not in gate.split("if False", 1)[1].split("def ", 1)[0], (
        "guard stayed green after the role gate was disabled"
    )

    # (2) Behavioral: a read-only Viewer JWT can now trigger provider-backed
    #     analysis against the weakened control.
    top = _register_mutated_tree(mutated_repo, "mut_m8")
    main = importlib.import_module(f"{top}.api_gateway.main")
    app = main.create_app(env={"JWT_SECRET": TEST_GW_SECRET, "APP_ENV": "production",
        "ANALYSIS_RATE_LIMIT_SINGLE_INSTANCE_PRODUCTION": "true"})

    class _FakeTransport:
        def call(self, method, url, json_body, identity):
            return {"status": "ANALYSIS_COMPLETE", "source": "server_gemini",
                    "analysis": {"dockerfile": "D", "k8s_yaml": "K", "terraform_tf": "T",
                                  "pipeline_yaml": "P", "report": "R"}}

    analysis_router = importlib.import_module(f"{top}.api_gateway.routers.analysis_router")
    app.dependency_overrides[analysis_router.get_downstream_transport] = _FakeTransport

    viewer_token = make_token("viewer-attacker", ["Viewer"])
    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/repository/analyze",
            json={"repo_name": "x", "repo_url": "https://github.com/o/r.git",
                  "framework": "FastAPI", "technology": "Python 3.12"},
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
    # The attack SUCCEEDS against the weakened control:
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# M9 — accept a client-supplied Gemini key on the analysis schema
# ---------------------------------------------------------------------------


def _apply_client_key_field(repo: Path) -> None:
    router_path = repo / "devops-ai-platform/api-gateway/routers/analysis_router.py"
    src = router_path.read_text(encoding="utf-8")
    target = "    technology: str = Field(min_length=1, max_length=200)"
    assert target in src, "M9 target not found in gateway analysis schema"
    src = src.replace(
        target,
        target + "\n    gemini_api_key: str = \"\"  # MUTATION: client-supplied provider key",
        1,
    )
    # extra="forbid" would reject the field: the mutation weakens the contract.
    src = src.replace('model_config = ConfigDict(extra="forbid")',
                      'model_config = ConfigDict(extra="ignore")', 1)
    router_path.write_text(src, encoding="utf-8")


def _assert_analysis_schema_rejects_key_fields(repo: Path) -> None:
    """Structural guard: neither analysis schema may accept a provider key
    field, and both must forbid extra fields."""
    for rel in ("devops-ai-platform/api-gateway/routers/analysis_router.py",
                "devops-ai-platform/agent-service/presentation/rest/analysis_router.py"):
        src = (repo / rel).read_text(encoding="utf-8")
        assert not re.search(r"^\s*gemini_?api_?key\s*:", src, re.M), (
            f"{rel}: analysis schema accepts a provider key field"
        )
        assert 'extra="forbid"' in src, f"{rel}: schema must forbid extra fields"


def test_mutation_m9_client_supplied_gemini_key_detected(mutated_repo):
    # (1) Structural guard holds on the unmutated repo.
    _assert_analysis_schema_rejects_key_fields(REPO_ROOT)
    _apply_client_key_field(mutated_repo)
    # The mutated schema is structurally broken:
    src = (mutated_repo / "devops-ai-platform/api-gateway/routers/analysis_router.py").read_text(encoding="utf-8")
    assert "gemini_api_key" in src
    assert 'model_config = ConfigDict(extra="forbid")' not in src, (
        "guard stayed green after the extra-forbid contract was weakened"
    )

    # (2) Behavioral: the client can now smuggle a provider key to the
    #     backend through the weakened contract.
    top = _register_mutated_tree(mutated_repo, "mut_m9")
    main = importlib.import_module(f"{top}.api_gateway.main")
    app = main.create_app(env={"JWT_SECRET": TEST_GW_SECRET, "APP_ENV": "production",
        "ANALYSIS_RATE_LIMIT_SINGLE_INSTANCE_PRODUCTION": "true"})

    forwarded: list = []

    class _FakeTransport:
        def call(self, method, url, json_body, identity):
            forwarded.append(json_body)
            return {"status": "ANALYSIS_COMPLETE", "source": "server_gemini",
                    "analysis": {"dockerfile": "D", "k8s_yaml": "K", "terraform_tf": "T",
                                  "pipeline_yaml": "P", "report": "R"}}

    analysis_router = importlib.import_module(f"{top}.api_gateway.routers.analysis_router")
    app.dependency_overrides[analysis_router.get_downstream_transport] = _FakeTransport

    dev_token = make_token("dev-attacker", ["Developer"])
    payload = {"repo_name": "x", "repo_url": "https://github.com/o/r.git",
               "framework": "FastAPI", "technology": "Python 3.12",
               "gemini_api_key": "AIzaCLIENT-SMUGGLED-KEY"}
    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/repository/analyze", json=payload,
            headers={"Authorization": f"Bearer {dev_token}"},
        )
    # The attack SUCCEEDS: the client-supplied key is accepted and forwarded.
    assert resp.status_code == 200
    assert forwarded and forwarded[0].get("gemini_api_key") == "AIzaCLIENT-SMUGGLED-KEY"


# ---------------------------------------------------------------------------
# M10 — missing server Gemini key fails OPEN (fabricated success)
# ---------------------------------------------------------------------------


def _apply_missing_key_fail_open(repo: Path) -> None:
    caller_path = repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py"
    src = caller_path.read_text(encoding="utf-8")
    # Weaken: _generate_text fabricates a response when the key is missing —
    # the guard line is injected right before the fail-closed assertion call
    # (inside _generate_text, the only place both calls are adjacent).
    target = "        self._check_circuit()\n        self._assert_provider_configured()"
    assert target in src, "M10 target not found in gemini_caller"
    src = src.replace(
        target,
        "        self._check_circuit()\n"
        "        if not self.api_key:  # MUTATION: fail open\n"
        '            return "SIMULATED GEMINI RESPONSE (offline bypass)"\n'
        "        self._assert_provider_configured()",
        1,
    )
    caller_path.write_text(src, encoding="utf-8")


def _assert_missing_key_fails_closed(repo: Path) -> None:
    """Structural guard: the no-key branch must raise, never return."""
    src = (repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py").read_text(encoding="utf-8")
    fn = src.split("def _assert_provider_configured", 1)[1].split("def ", 1)[0]
    assert "if not self.api_key" in fn, "no-key check missing from the caller"
    branch = fn.split("if not self.api_key", 1)[1]
    assert "raise GeminiServiceUnavailableException" in branch, (
        "the no-key branch must raise (fail closed), not fabricate a response"
    )
    assert "SIMULATED GEMINI RESPONSE" not in src, (
        "fabricated-response fallback present in the Gemini caller"
    )


def test_mutation_m10_missing_secret_fail_open_detected(mutated_repo):
    # (1) Structural guard holds on the unmutated repo.
    _assert_missing_key_fails_closed(REPO_ROOT)
    _apply_missing_key_fail_open(mutated_repo)
    # The mutated caller is structurally broken (fabricated fallback present):
    mut_src = (mutated_repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py").read_text(encoding="utf-8")
    assert "SIMULATED GEMINI RESPONSE" in mut_src, (
        "guard stayed green after the fail-open fallback was introduced"
    )

    # (2) Behavioral: without the server key the weakened caller fabricates a
    #     fake "Gemini answered" success instead of failing closed.
    top = _register_mutated_tree(mutated_repo, "mut_m10")
    gc = importlib.import_module(f"{top}.agent.infrastructure.llm.gemini_caller")
    caller = gc.GeminiCallerAdapter(api_key="")
    result = caller.generate_remediation("prompt", "system")
    assert isinstance(result, str) and "SIMULATED" in result, (
        "expected the weakened control to fabricate a fake success"
    )


# ---------------------------------------------------------------------------
# M11 — swallow provider auth failure, answer with fabricated success
# ---------------------------------------------------------------------------


def _apply_swallow_auth_failure(repo: Path) -> None:
    caller_path = repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py"
    src = caller_path.read_text(encoding="utf-8")
    old = "            if status in _AUTH_STATUS_CODES:\n                self._register_failure()\n                raise GeminiAuthException("
    assert old in src, "M11 target not found in gemini_caller"
    src = src.replace(
        old,
        "            if status in _AUTH_STATUS_CODES:\n"
        "                self._register_failure()\n"
        '                return "SIMULATED GEMINI RESPONSE (provider error swallowed)"  # MUTATION\n'
        "                raise GeminiAuthException(",
        1,
    )
    caller_path.write_text(src, encoding="utf-8")


def _assert_auth_failure_raises(repo: Path) -> None:
    """Structural guard: the provider-auth branch must raise, with no early
    return before it."""
    src = (repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py").read_text(encoding="utf-8")
    branch = src.split("if status in _AUTH_STATUS_CODES:", 1)[1].split(
        "if status in _TRANSIENT_STATUS_CODES:", 1
    )[0]
    assert "raise GeminiAuthException" in branch, "auth branch must raise GeminiAuthException"
    assert "return " not in branch, "auth branch must not return a fabricated result"


def test_mutation_m11_fake_gemini_success_detected(mutated_repo):
    # (1) Structural guard holds on the unmutated repo.
    _assert_auth_failure_raises(REPO_ROOT)
    _apply_swallow_auth_failure(mutated_repo)
    # The mutated branch is structurally broken:
    src = (mutated_repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py").read_text(encoding="utf-8")
    branch = src.split("if status in _AUTH_STATUS_CODES:", 1)[1].split(
        "if status in _TRANSIENT_STATUS_CODES:", 1
    )[0]
    assert "return " in branch, "guard stayed green after the auth swallow was added"

    # (2) Behavioral: a provider 401 now yields a fabricated success.
    top = _register_mutated_tree(mutated_repo, "mut_m11")
    gc = importlib.import_module(f"{top}.agent.infrastructure.llm.gemini_caller")

    class _Resp401:
        status_code = 401
        text = ""

        def json(self):
            raise ValueError("no body")

    def _t401(_payload):
        return _Resp401()

    caller = gc.GeminiCallerAdapter(api_key="server-key", transport=_t401,
                                    max_retries=3, backoff_base_seconds=0.01)
    result = caller.generate_remediation("p", "s")
    assert isinstance(result, str) and "SIMULATED" in result, (
        "expected the weakened control to fake a Gemini success on 401"
    )


# ---------------------------------------------------------------------------
# M12 — bypass the budget ceiling
# ---------------------------------------------------------------------------


def _apply_budget_bypass(repo: Path) -> None:
    caller_path = repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py"
    src = caller_path.read_text(encoding="utf-8")
    old = "            if self._committed + self._reserved + max_cost_usd > self.monthly_budget + _FLOAT_EPS:"
    assert old in src, "M12 target not found in InProcessBudgetLedger.reserve"
    src = src.replace(
        old,
        "            if False:  # MUTATION: budget ceiling bypassed",
        1,
    )
    caller_path.write_text(src, encoding="utf-8")


def _assert_budget_enforced(repo: Path) -> None:
    """Structural guard: the atomic reservation must compare the combined
    committed + reserved + new amount against the ceiling before allowing
    the reservation (no bypass, no GET-then-SET race)."""
    src = (repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py").read_text(encoding="utf-8")
    fn = src.split("class InProcessBudgetLedger", 1)[1].split("class RedisBudgetLedger", 1)[0]
    reserve = fn.split("def reserve", 1)[1].split("def finalize", 1)[0]
    assert "self._committed + self._reserved + max_cost_usd > self.monthly_budget" in reserve, (
        "reserve() no longer compares committed + reserved + amount "
        "against the ceiling atomically"
    )
    assert "self._reserved += max_cost_usd" in reserve, (
        "reserve() no longer commits the reserved amount"
    )


def test_mutation_m12_budget_bypass_detected(mutated_repo):
    # (1) Structural guard holds on the unmutated repo.
    _assert_budget_enforced(REPO_ROOT)
    _apply_budget_bypass(mutated_repo)
    # The mutated budget check is structurally broken:
    src = (mutated_repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py").read_text(encoding="utf-8")
    fn = src.split("class InProcessBudgetLedger", 1)[1].split("class RedisBudgetLedger", 1)[0]
    reserve = fn.split("def reserve", 1)[1].split("def finalize", 1)[0]
    assert "self._committed + self._reserved + max_cost_usd > self.monthly_budget" not in reserve, (
        "guard stayed green after the budget ceiling was bypassed"
    )

    # (2) Behavioral: an exhausted budget still places a provider call.
    top = _register_mutated_tree(mutated_repo, "mut_m12")
    gc = importlib.import_module(f"{top}.agent.infrastructure.llm.gemini_caller")

    class _Resp200:
        status_code = 200
        text = "{}"

        def json(self):
            return {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}

    calls: list = []

    def _t(payload):
        calls.append(1)
        return _Resp200()

    caller = gc.GeminiCallerAdapter(api_key="server-key", transport=_t,
                                    monthly_budget_usd=0.0, max_retries=1,
                                    backoff_base_seconds=0.01)
    result = caller.generate_remediation("p", "s")
    assert result == "ok" and calls == [1], (
        "expected the weakened control to call the provider despite the "
        "exhausted budget"
    )


# ---------------------------------------------------------------------------
# M13 — restore PER-REQUEST Gemini adapter construction (state reset)
# ---------------------------------------------------------------------------


def _apply_per_request_adapter(repo: Path) -> None:
    router_path = repo / "devops-ai-platform/agent-service/presentation/rest/analysis_router.py"
    src = router_path.read_text(encoding="utf-8")
    # Weaken: rebuild the handler (and its GeminiCallerAdapter) on EVERY
    # request instead of resolving the application-lifetime shared handler.
    target = (
        "    handler = getattr(request.app.state, \"analysis_handler\", None)\n"
        "    if handler is None:  # defensive: mis-assembled app -> fail closed, never build ad hoc\n"
        "        raise HTTPException(\n"
        "            status_code=503,\n"
        "            detail=\"Agent analysis handler is not initialized (application lifecycle not run).\",\n"
        "        )\n"
        "    return handler"
    )
    assert target in src, "M13 target not found in agent analysis router"
    src = src.replace(
        target,
        "    # MUTATION: per-request adapter construction (state resets every call)\n"
        "    return AnalyzeRepositoryCommandHandler(GeminiCallerAdapter())",
        1,
    )
    # The router no longer imports the adapter; the mutation re-adds it.
    src = src.replace(
        "    GeminiUpstreamException,\n)",
        "    GeminiUpstreamException,\n    GeminiCallerAdapter,\n)",
        1,
    )
    router_path.write_text(src, encoding="utf-8")


def _assert_shared_analysis_handler_intact(repo: Path) -> None:
    """Structural guard: the route must resolve the SHARED app-lifetime
    handler and must never construct an adapter per request."""
    src = (repo / "devops-ai-platform/agent-service/presentation/rest/analysis_router.py").read_text(encoding="utf-8")
    fn = src.split("def get_analysis_handler", 1)[1].split("\ndef ", 1)[0]
    assert "app.state" in fn and "analysis_handler" in fn, (
        "get_analysis_handler no longer resolves the shared app.state handler"
    )
    assert "GeminiCallerAdapter(" not in fn, (
        "get_analysis_handler constructs an adapter per request"
    )


def test_mutation_m13_per_request_adapter_state_reset_detected(mutated_repo, monkeypatch):
    # (1) Structural guard holds on the unmutated repo.
    _assert_shared_analysis_handler_intact(REPO_ROOT)
    _apply_per_request_adapter(mutated_repo)
    mut_src = (mutated_repo / "devops-ai-platform/agent-service/presentation/rest/analysis_router.py").read_text(encoding="utf-8")
    fn = mut_src.split("def get_analysis_handler", 1)[1].split("\ndef ", 1)[0]
    assert "GeminiCallerAdapter(" in fn, (
        "guard stayed green after per-request adapter construction was introduced"
    )

    # (2) Behavioral: circuit-breaker state must persist ACROSS separate
    #     requests through the shared handler.  Five failing requests open
    #     the shared circuit; the sixth request then fails fast WITHOUT any
    #     provider contact.  With per-request adapters the state resets and
    #     the sixth request still reaches the provider.
    import importlib

    monkeypatch.setenv("AGENT_INTERNAL_TOKEN", "test-agent-internal-token-0123456789abcdef0123456789abcdef")
    monkeypatch.setenv("GEMINI_API_KEY", "m13-test-key-not-a-real-credential")
    monkeypatch.setenv("GEMINI_MAX_RETRIES", "1")
    monkeypatch.setenv("GEMINI_BACKOFF_BASE_SECONDS", "0.001")

    hdrs = {
        "X-Gateway-Identity": "m13-shared-state",
        "X-Agent-Internal-Token": "test-agent-internal-token-0123456789abcdef0123456789abcdef",
    }
    body = {"repo_name": "m13", "repo_url": "https://github.com/o/r.git",
            "framework": "FastAPI", "technology": "Python 3.12"}

    class _Resp500:
        status_code = 500
        text = "transient upstream error"

        def json(self):
            raise ValueError("no body")

    # --- unmutated: failures accumulate on the SHARED adapter.
    from platform_pkg.agent.main import create_app
    from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

    app = create_app(config=gc.GeminiRuntimeConfig(max_retries=1, backoff_base_seconds=0.001))
    app.state.analysis_handler.llm._transport = lambda payload: _Resp500()
    with TestClient(app) as client:
        codes = [client.post("/api/internal/repository/analyze", json=body, headers=hdrs).status_code
                 for _ in range(5)]
        sixth = client.post("/api/internal/repository/analyze", json=body, headers=hdrs)
    assert codes == [502] * 5
    assert sixth.status_code == 503, (
        "shared circuit-breaker state was NOT persisted across requests: "
        "expected fail-fast 503 after 5 failures"
    )

    # --- mutated: each request rebuilds the adapter; the circuit never
    #     opens, so the sixth request still contacts the provider (502).
    top = _register_mutated_tree(mutated_repo, "mut_m13")
    m_main = importlib.import_module(f"{top}.agent.main")
    m_gc = importlib.import_module(f"{top}.agent.infrastructure.llm.gemini_caller")
    calls: list = []

    def _fake_post(url, json=None, headers=None, timeout=None):
        calls.append(1)
        return _Resp500()

    monkeypatch.setattr(m_gc.requests, "post", _fake_post)
    mapp = m_main.create_app(config=m_gc.GeminiRuntimeConfig(max_retries=1, backoff_base_seconds=0.001))
    with TestClient(mapp) as client:
        codes = [client.post("/api/internal/repository/analyze", json=body, headers=hdrs).status_code
                 for _ in range(5)]
        sixth = client.post("/api/internal/repository/analyze", json=body, headers=hdrs)
    assert codes == [502] * 5
    assert sixth.status_code == 502, (
        "expected the weakened control to keep contacting the provider per "
        "request (circuit state resets)"
    )
    assert len(calls) >= 6, (
        "expected the weakened control to make provider calls on every request"
    )


# ---------------------------------------------------------------------------
# M14 — remove the analysis route's rate limiting
# ---------------------------------------------------------------------------


def _apply_rate_limit_removal(repo: Path) -> None:
    router_path = repo / "devops-ai-platform/api-gateway/routers/analysis_router.py"
    src = router_path.read_text(encoding="utf-8")
    target = "    _rate_limited: None = Depends(require_analysis_rate_limit),"
    assert target in src, "M14 target not found in gateway analysis route"
    src = src.replace(target, "    # MUTATION: analysis rate limiting removed", 1)
    router_path.write_text(src, encoding="utf-8")


def _assert_analysis_rate_limit_intact(repo: Path) -> None:
    """Structural guard: the analysis route keeps its limiter dependency."""
    src = (repo / "devops-ai-platform/api-gateway/routers/analysis_router.py").read_text(encoding="utf-8")
    route = src.split('@router.post("/api/v1/repository/analyze")', 1)[1].split("):", 1)[1]
    sig = src.split("def analyze_repository", 1)[1].split("):", 1)[0]
    assert "Depends(require_analysis_rate_limit)" in sig, (
        "the analysis route lost its rate-limiting dependency"
    )


def test_mutation_m14_analysis_rate_limit_removal_detected(mutated_repo):
    # (1) Structural guard holds on the unmutated repo.
    _assert_analysis_rate_limit_intact(REPO_ROOT)
    _apply_rate_limit_removal(mutated_repo)
    mut_src = (mutated_repo / "devops-ai-platform/api-gateway/routers/analysis_router.py").read_text(encoding="utf-8")
    sig = mut_src.split("def analyze_repository", 1)[1].split("):", 1)[0]
    assert "Depends(require_analysis_rate_limit)" not in sig, (
        "guard stayed green after the rate limiting was removed"
    )

    # (2) Behavioral: the same burst that the intact control limits with
    #     429 is now allowed UNLIMITED against the weakened control.
    top = _register_mutated_tree(mutated_repo, "mut_m14")
    main = importlib.import_module(f"{top}.api_gateway.main")
    analysis_router = importlib.import_module(f"{top}.api_gateway.routers.analysis_router")
    app = main.create_app(env={
        "JWT_SECRET": TEST_GW_SECRET,
        "APP_ENV": "production",
        "ANALYSIS_RATE_LIMIT_STORE": "local",
        "ANALYSIS_RATE_LIMIT_PER_IDENTITY_PER_MINUTE": "2",
        "ANALYSIS_RATE_LIMIT_SINGLE_INSTANCE_PRODUCTION": "true",
    })

    class _FakeTransport:
        def call(self, method, url, json_body, identity):
            return {"status": "ANALYSIS_COMPLETE", "source": "server_gemini",
                    "analysis": {"dockerfile": "D", "k8s_yaml": "K", "terraform_tf": "T",
                                  "pipeline_yaml": "P", "report": "R"}}

    app.dependency_overrides[analysis_router.get_downstream_transport] = _FakeTransport
    token = make_token("m14-burst", ["Developer"])
    with TestClient(app) as client:
        codes = [
            client.post("/api/v1/repository/analyze", json={
                "repo_name": "x", "repo_url": "https://github.com/o/r.git",
                "framework": "FastAPI", "technology": "Python 3.12",
            }, headers={"Authorization": f"Bearer {token}"}).status_code
            for _ in range(5)
        ]
    # The attack SUCCEEDS: 5 requests, no 429 anywhere.
    assert codes == [200] * 5, (
        "expected the weakened control to allow an unlimited burst"
    )

    # Baseline: the INTACT control limits the same burst.
    from platform_pkg.api_gateway.main import create_app as real_create_app
    from platform_pkg.api_gateway import routers as real_routers
    real_app = real_create_app(env={
        "JWT_SECRET": TEST_GW_SECRET,
        "APP_ENV": "production",
        "ANALYSIS_RATE_LIMIT_STORE": "local",
        "ANALYSIS_RATE_LIMIT_PER_IDENTITY_PER_MINUTE": "2",
        "ANALYSIS_RATE_LIMIT_SINGLE_INSTANCE_PRODUCTION": "true",
    })
    real_app.dependency_overrides[
        real_routers.analysis_router.get_downstream_transport
    ] = _FakeTransport
    with TestClient(real_app) as client:
        codes = [
            client.post("/api/v1/repository/analyze", json={
                "repo_name": "x", "repo_url": "https://github.com/o/r.git",
                "framework": "FastAPI", "technology": "Python 3.12",
            }, headers={"Authorization": f"Bearer {token}"}).status_code
            for _ in range(5)
        ]
    assert codes[:2] == [200, 200] and 429 in codes[2:], (
        "intact control must limit the burst with 429"
    )


# ---------------------------------------------------------------------------
# M15 — re-enable bearer-JWT transport to arbitrary cleartext endpoints
# ---------------------------------------------------------------------------


def _apply_android_transport_bypass(repo: Path) -> None:
    client_path = repo / "app/src/main/java/com/example/data/BackendGatewayClient.kt"
    src = client_path.read_text(encoding="utf-8")
    target = "        val urlPolicyError = validateAnalysisUrl(cleanUrl)\n"
    assert target in src, "M15 target not found in BackendGatewayClient.kt"
    src = src.replace(
        target,
        "        val urlPolicyError: String? = null  // MUTATION: transport policy disabled\n",
        1,
    )
    client_path.write_text(src, encoding="utf-8")


def test_mutation_m15_cleartext_bearer_transport_detected(mutated_repo):
    # (1) Structural guard (A8) holds on the unmutated repo.
    assert android_guard.check_analysis_transport_policy(REPO_ROOT) == [], (
        "baseline: the unmutated Android transport policy must be intact"
    )
    _apply_android_transport_bypass(mutated_repo)
    # The A8 guard must turn red on the weakened source:
    violations = android_guard.check_analysis_transport_policy(mutated_repo)
    assert violations, (
        "guard stayed green after the URL transport policy was disabled "
        "(bearer JWTs could be sent to arbitrary cleartext endpoints)"
    )
    # And the weakened client no longer calls the policy at all:
    mut_src = (mutated_repo / "app/src/main/java/com/example/data/BackendGatewayClient.kt").read_text(encoding="utf-8")
    assert "validateAnalysisUrl(cleanUrl)" not in mut_src, (
        "expected the policy call to be gone in the mutated client"
    )
    # The Kotlin unit tests (app/src/test/.../AnalysisUrlPolicyTest.kt) run
    # in the CI Gradle job and fail there: the mutation breaks the
    # https-only / debug-local contract that those tests assert.


# ---------------------------------------------------------------------------
# M16 — reintroduce the NON-ATOMIC budget check-then-act (TOCTOU race)
# ---------------------------------------------------------------------------


def _apply_budget_toctou(repo: Path) -> None:
    caller_path = repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py"
    src = caller_path.read_text(encoding="utf-8")
    target = (
        "        with self._lock:\n"
        "            self._roll_period_if_needed()\n"
        "            if self._committed + self._reserved + max_cost_usd > self.monthly_budget + _FLOAT_EPS:\n"
        "                logger.warning(\n"
        "                    \"[COST_MONITORING] Budget reservation of $%.6f rejected: \"\n"
        "                    \"ceiling $%.2f (committed $%.6f, reserved $%.6f).\",\n"
        "                    max_cost_usd, self.monthly_budget, self._committed, self._reserved,\n"
        "                )\n"
        "                raise BudgetExceededException(\n"
        "                    \"Application AI budget ceiling reached; the call was \"\n"
        "                    \"blocked before contacting the provider.\"\n"
        "                )\n"
        "            self._reserved += max_cost_usd"
    )
    assert target in src, "M16 target not found in InProcessBudgetLedger.reserve"
    src = src.replace(
        target,
        "        # MUTATION: NON-ATOMIC check-then-act (TOCTOU race): the\n"
        "        # ceiling check runs OUTSIDE the lock, then the commit\n"
        "        # happens under it.\n"
        "        self._roll_period_if_needed()\n"
        "        if self._committed + self._reserved + max_cost_usd > self.monthly_budget + _FLOAT_EPS:\n"
        "            raise BudgetExceededException(\n"
        "                \"Application AI budget ceiling reached; the call was \"\n"
        "                \"blocked before contacting the provider.\"\n"
        "            )\n"
        "        time.sleep(0.005)  # widen the race window (mutation hook)\n"
        "        with self._lock:\n"
        "            self._reserved += max_cost_usd",
        1,
    )
    caller_path.write_text(src, encoding="utf-8")


def _assert_budget_reserve_atomic(repo: Path) -> None:
    """Structural guard: the ceiling check must run INSIDE the lock."""
    src = (repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py").read_text(encoding="utf-8")
    ledger = src.split("class InProcessBudgetLedger", 1)[1].split("class RedisBudgetLedger", 1)[0]
    reserve = ledger.split("def reserve", 1)[1].split("def finalize", 1)[0]
    check_idx = reserve.index("self._committed + self._reserved + max_cost_usd")
    lock_idx = reserve.index("with self._lock")
    assert lock_idx < check_idx, (
        "the budget ceiling check no longer runs inside the lock (TOCTOU race)"
    )


def _race_reserve(ledger, n_threads: int, amount: float):
    """Fire n concurrent reservations; return (allowed, rejected)."""
    import threading

    from platform_pkg.agent.infrastructure.llm.gemini_caller import (
        BudgetExceededException,
    )

    barrier = threading.Barrier(n_threads)
    allowed, rejected = [], []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        try:
            res = ledger.reserve(amount)
            with lock:
                allowed.append(res)
        except BudgetExceededException:
            with lock:
                rejected.append(1)

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return allowed, rejected


def test_mutation_m16_non_atomic_budget_race_detected(mutated_repo):
    # (1) Structural guard holds on the unmutated repo.
    _assert_budget_reserve_atomic(REPO_ROOT)
    _apply_budget_toctou(mutated_repo)
    mut_src = (mutated_repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py").read_text(encoding="utf-8")
    reserve = mut_src.split("class InProcessBudgetLedger", 1)[1].split("class RedisBudgetLedger", 1)[0]
    reserve = reserve.split("def reserve", 1)[1].split("def finalize", 1)[0]
    check_idx = reserve.index("self._committed + self._reserved + max_cost_usd")
    lock_idx = reserve.index("with self._lock")
    assert check_idx < lock_idx, (
        "guard stayed green after the ceiling check was moved outside the lock"
    )

    # (2) Behavioral: concurrent reservations must never race past the
    #     ceiling.  Ceiling 10.0 with 6.0 reservations: the ATOMIC ledger
    #     admits exactly one.
    from platform_pkg.agent.infrastructure.llm.gemini_caller import (
        InProcessBudgetLedger,
    )

    intact = InProcessBudgetLedger(10.0, 1.5, 7.5)
    allowed, rejected = _race_reserve(intact, 4, 6.0)
    assert len(allowed) == 1 and len(rejected) == 3, (
        "intact atomic ledger must admit exactly one 6.0 reservation "
        "against a 10.0 ceiling"
    )

    # The WEAKENED TOCTOU ledger admits all four: the ceiling is blown.
    top = _register_mutated_tree(mutated_repo, "mut_m16")
    m_gc = importlib.import_module(f"{top}.agent.infrastructure.llm.gemini_caller")
    weakened = m_gc.InProcessBudgetLedger(10.0, 1.5, 7.5)
    allowed, rejected = _race_reserve(weakened, 4, 6.0)
    assert len(allowed) > 1, (
        "expected the weakened control to let concurrent reservations race "
        "past the ceiling"
    )
    total = len(allowed) * 6.0
    assert total > 10.0, (
        f"weakened ledger double-spent: {total} reserved against a 10.0 ceiling"
    )


# ---------------------------------------------------------------------------
# M17 — remove the canonical agent build from the D1 runtime
# ---------------------------------------------------------------------------


def _apply_agent_build_removal(repo: Path) -> None:
    import yaml

    compose_path = repo / "devops-ai-platform/docker-compose.yml"
    spec = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    assert "agent-service" in spec["services"], "M17 target not found in compose"
    del spec["services"]["agent-service"]
    compose_path.write_text(
        yaml.safe_dump(spec, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )


def _assert_runtime_contract_intact(repo: Path) -> None:
    from security_guards.runtime_guard import check_runtime_contract

    assert check_runtime_contract(repo) == [], (
        "baseline: the canonical D1 runtime contract must hold"
    )


def test_mutation_m17_agent_build_removal_detected(mutated_repo):
    # (1) Structural guard holds on the unmutated repo.
    _assert_runtime_contract_intact(REPO_ROOT)
    _apply_agent_build_removal(mutated_repo)
    # The runtime guard must turn red: the canonical stack no longer
    # declares the internal analysis boundary (and CI would no longer
    # build/boot the full path).
    from security_guards.runtime_guard import check_runtime_contract

    violations = check_runtime_contract(mutated_repo)
    assert any("agent-service" in v for v in violations), (
        "guard stayed green after the agent-service was removed from the "
        "canonical compose stack"
    )


# ---------------------------------------------------------------------------
# M18 — revert to the deprecated Gemini model + drop the output bound
# ---------------------------------------------------------------------------


def _apply_deprecated_model_revert(repo: Path) -> None:
    caller_path = repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py"
    src = caller_path.read_text(encoding="utf-8")
    target = 'DEFAULT_GEMINI_MODEL = "gemini-3.8-flash"'
    assert target in src, "M18 target not found in gemini_caller"
    src = src.replace(target, 'DEFAULT_GEMINI_MODEL = "gemini-3.5-flash"', 1)
    bound = '                "maxOutputTokens": int(self.config.max_output_tokens),\n'
    assert bound in src, "M18 maxOutputTokens target not found in gemini_caller"
    src = src.replace(bound, "                # MUTATION: output bound removed\n", 1)
    caller_path.write_text(src, encoding="utf-8")


def _assert_current_model_contract_intact(repo: Path) -> None:
    """Structural guard: the configured model is the current stable
    gemini-3.8-flash and the payload keeps the explicit output bound."""
    src = (repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py").read_text(encoding="utf-8")
    assert 'DEFAULT_GEMINI_MODEL = "gemini-3.8-flash"' in src, (
        "the default model is not the current stable gemini-3.8-flash"
    )
    assert '= "gemini-3.5-flash"' not in src, (
        "the deprecated gemini-3.5-flash is present as a model default"
    )
    payload = src.split("def _build_payload", 1)[1].split("\n    def ", 1)[0]
    assert '"maxOutputTokens"' in payload, (
        "the provider payload lost its explicit maxOutputTokens bound"
    )


def test_mutation_m18_deprecated_model_revert_detected(mutated_repo):
    # (1) Structural guard holds on the unmutated repo.
    _assert_current_model_contract_intact(REPO_ROOT)
    _apply_deprecated_model_revert(mutated_repo)
    mut_src = (mutated_repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py").read_text(encoding="utf-8")
    assert 'DEFAULT_GEMINI_MODEL = "gemini-3.5-flash"' in mut_src and (
        '"maxOutputTokens"' not in mut_src.split("def _build_payload", 1)[1].split("\n    def ", 1)[0]
    ), "expected the deprecated model and the missing output bound in the mutation"

    # (2) Behavioral: the weakened default configuration is observably
    #     different — the adapter resolves the deprecated model and its
    #     payload no longer carries the output bound.
    top = _register_mutated_tree(mutated_repo, "mut_m18")
    m_gc = importlib.import_module(f"{top}.agent.infrastructure.llm.gemini_caller")
    caller = m_gc.GeminiCallerAdapter(api_key="m18-test-key-not-a-real-credential")
    assert caller.model_name == "gemini-3.5-flash", (
        "expected the weakened control to revert to the deprecated model"
    )
    payload = caller._build_payload("prompt", "system")
    gen_cfg = payload.get("generationConfig", {})
    assert "maxOutputTokens" not in gen_cfg, (
        "expected the weakened control to drop the output bound"
    )
    # And the INTACT default still carries both properties:
    from platform_pkg.agent.infrastructure.llm.gemini_caller import (
        GeminiCallerAdapter as IntactAdapter,
    )

    intact = IntactAdapter(api_key="m18-test-key-not-a-real-credential")
    assert intact.model_name == "gemini-3.8-flash"
    intact_cfg = intact._build_payload("prompt", "system").get("generationConfig", {})
    assert "maxOutputTokens" in intact_cfg


# ---------------------------------------------------------------------------
# M19 — make the Redis finalize accounting non-idempotent (duplicate
#        finalization double-counts)
# ---------------------------------------------------------------------------


def _apply_finalize_idempotency_removal(repo: Path) -> None:
    caller_path = repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py"
    src = caller_path.read_text(encoding="utf-8")
    target = (
        "if redis.call('EXISTS', claim_key) == 1 then\n"
        "  return 0\n"
        "end\n"
        "redis.call('SET', claim_key, '1', 'EX', ttl)\n"
    )
    assert target in src, "M19 target not found in the Redis finalize script"
    src = src.replace(
        target,
        "-- MUTATION: exactly-once claim removed; duplicate finalizations "
        "re-apply the accounting\n",
        1,
    )
    caller_path.write_text(src, encoding="utf-8")


def _assert_finalize_is_idempotent(repo: Path) -> None:
    """Structural guard: the Redis finalize script must keep its atomic
    exactly-once claim (period-scoped claim key, checked-and-set inside
    the atomic script)."""
    src = (repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py").read_text(encoding="utf-8")
    script = src.split("_FINALIZE_LUA = ", 1)[1].split('"""', 1)[1].split('"""', 1)[0]
    assert "EXISTS', claim_key" in script, (
        "the Redis finalize script lost its duplicate check"
    )
    assert "SET', claim_key, '1'" in script, (
        "the Redis finalize script lost its atomic claim"
    )
    # The release must use the supported floating-point primitive
    # (INCRBYFLOAT with a negative delta) — Redis has no DECRBYFLOAT.
    assert "DECRBYFLOAT" not in script, (
        "the finalize script references a nonexistent Redis command"
    )
    assert "INCRBYFLOAT', reserved_key, -reserved_amount" in script, (
        "the reservation release must use INCRBYFLOAT with a negative delta"
    )


def test_mutation_m19_finalize_idempotency_removal_detected(mutated_repo):
    # (1) Structural guard holds on the unmutated repo.
    _assert_finalize_is_idempotent(REPO_ROOT)
    _apply_finalize_idempotency_removal(mutated_repo)
    mut_src = (mutated_repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py").read_text(encoding="utf-8")
    script = mut_src.split("_FINALIZE_LUA = ", 1)[1].split('"""', 1)[1].split('"""', 1)[0]
    assert "EXISTS', claim_key" not in script, (
        "guard stayed green after the exactly-once claim was removed"
    )
    # Behavioral proof of the WEAKENED script against a REAL Redis, when
    # one is available (CI redis-integration environment).  Locally the
    # structural detection above is the CI-enforced red.
    import os

    if os.environ.get("REDIS_URL", "").strip():
        top = _register_mutated_tree(mutated_repo, "mut_m19")
        m_gc = importlib.import_module(
            f"{top}.agent.infrastructure.llm.gemini_caller"
        )
        ledger = m_gc.RedisBudgetLedger(
            monthly_budget_usd=10.0, redis_url=os.environ["REDIS_URL"]
        )
        ledger._client.flushdb()
        res = ledger.reserve(4.0)
        ledger.finalize(res, 2.0)
        ledger.finalize(res, 2.0)  # duplicate
        spend = ledger.accumulated_spend
        ledger._client.flushdb()
        ledger.close()
        assert spend == pytest.approx(4.0), (
            "expected the weakened control to double-count a duplicate "
            f"finalization (got committed {spend})"
        )


# ---------------------------------------------------------------------------
# M20 — bypass the production shared-Redis requirement
# ---------------------------------------------------------------------------


def _apply_production_requirement_bypass(repo: Path) -> None:
    limiter_path = repo / "devops-ai-platform/api-gateway/core/analysis_rate_limit.py"
    src = limiter_path.read_text(encoding="utf-8")
    target = "        and app_env in _PRODUCTION_ENVS\n"
    assert target in src, "M20 target not found in load_analysis_rate_limit_settings"
    src = src.replace(
        target,
        "        and app_env in frozenset()  # MUTATION: production shared-state requirement bypassed\n",
        1,
    )
    limiter_path.write_text(src, encoding="utf-8")


def _assert_production_requires_shared_store(repo: Path) -> None:
    """Structural guard: staging/production must be forced onto the shared
    store (with the explicit single-replica opt-out)."""
    src = (repo / "devops-ai-platform/api-gateway/core/analysis_rate_limit.py").read_text(encoding="utf-8")
    assert "app_env in _PRODUCTION_ENVS" in src, (
        "the production shared-store requirement is missing"
    )
    assert "ANALYSIS_RATE_LIMIT_SINGLE_INSTANCE_PRODUCTION" in src, (
        "the documented single-replica opt-out flag is missing"
    )


def test_mutation_m20_production_requirement_bypass_detected(mutated_repo):
    # (1) Structural guard holds on the unmutated repo.
    _assert_production_requires_shared_store(REPO_ROOT)
    _apply_production_requirement_bypass(mutated_repo)
    mut_src = (mutated_repo / "devops-ai-platform/api-gateway/core/analysis_rate_limit.py").read_text(encoding="utf-8")
    assert "app_env in _PRODUCTION_ENVS" not in mut_src, (
        "guard stayed green after the production requirement was bypassed"
    )

    # (2) Behavioral: the INTACT loader refuses a production gateway with
    #     no shared store; the WEAKENED loader silently downgrades it to
    #     the single-instance limiter (limits multiply per replica).
    from platform_pkg.api_gateway.core.analysis_rate_limit import (
        AnalysisRateLimitConfigurationError,
        load_analysis_rate_limit_settings as intact_load,
    )

    with pytest.raises(AnalysisRateLimitConfigurationError):
        intact_load({"APP_ENV": "production"})

    top = _register_mutated_tree(mutated_repo, "mut_m20")
    m_arl = importlib.import_module(
        f"{top}.api_gateway.core.analysis_rate_limit"
    )
    settings = m_arl.load_analysis_rate_limit_settings({"APP_ENV": "production"})
    assert settings["store"] == "local", (
        "expected the weakened control to silently run the in-process "
        "limiter in production mode"
    )


# ---------------------------------------------------------------------------
# M21 — half-open circuit permits multiple concurrent probes
# ---------------------------------------------------------------------------


def _apply_multiple_half_open_probes(repo: Path) -> None:
    caller_path = repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py"
    src = caller_path.read_text(encoding="utf-8")
    target = '            if self.cb_state == "HALF-OPEN":\n'
    assert target in src, "M21 target not found in _check_circuit"
    src = src.replace(
        target,
        '            if self.cb_state == "NEVER":  # MUTATION: half-open allows unlimited concurrent probes\n',
        1,
    )
    caller_path.write_text(src, encoding="utf-8")


def _assert_single_half_open_probe(repo: Path) -> None:
    """Structural guard: while a half-open probe is in flight, concurrent
    callers must be rejected fast (no second probe)."""
    src = (repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py").read_text(encoding="utf-8")
    fn = src.split("def _check_circuit", 1)[1].split("\n    def ", 1)[0]
    assert 'if self.cb_state == "HALF-OPEN":' in fn, (
        "_check_circuit lost the HALF-OPEN fast-fail branch"
    )
    branch = fn.split('if self.cb_state == "HALF-OPEN":', 1)[1]
    assert "raise GeminiServiceUnavailableException" in branch, (
        "the HALF-OPEN branch must reject concurrent callers"
    )


class _M21CountingTransport:
    """Failing transport that holds the provider window open long enough
    for every racer to observe the half-open state."""

    def __init__(self):
        self.calls = 0

    def __call__(self, payload):
        self.calls += 1
        time.sleep(0.05)

        class _Resp500:
            status_code = 500
            text = "transient"

            def json(self):
                raise ValueError("no body")

        return _Resp500()


def _m21_open_circuit_then_race(adapter, n_racers: int):
    import threading

    clock = {"now": 5_000_000.0}
    adapter._time_fn = lambda: clock["now"]
    for _ in range(5):
        try:
            adapter.generate_remediation("p", "s")  # five failing attempts
        except Exception:
            pass
    assert adapter.cb_state == "OPEN"
    clock["now"] += 61  # cooldown elapses

    barrier = threading.Barrier(n_racers)

    def worker():
        barrier.wait()
        try:
            adapter.generate_remediation("p", "s")
        except Exception:
            pass

    threads = [threading.Thread(target=worker) for _ in range(n_racers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return adapter.cb_state


def test_mutation_m21_multiple_half_open_probes_detected(mutated_repo, monkeypatch):
    # (1) Structural guard holds on the unmutated repo.
    _assert_single_half_open_probe(REPO_ROOT)
    _apply_multiple_half_open_probes(mutated_repo)
    mut_src = (mutated_repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py").read_text(encoding="utf-8")
    fn = mut_src.split("def _check_circuit", 1)[1].split("\n    def ", 1)[0]
    assert 'if self.cb_state == "HALF-OPEN":' not in fn, (
        "guard stayed green after the half-open fast-fail was removed"
    )

    # (2) Behavioral: after the cooldown, 8 concurrent callers must permit
    #     exactly ONE provider probe (5 opening failures + 1 probe = 6).
    monkeypatch.setenv("GEMINI_API_KEY", "m21-test-key-not-a-real-credential")
    from platform_pkg.agent.infrastructure.llm import gemini_caller as gc

    intact_cfg = gc.GeminiRuntimeConfig(max_retries=1, backoff_base_seconds=0.001)
    intact_t = _M21CountingTransport()
    intact = gc.GeminiCallerAdapter(config=intact_cfg, transport=intact_t)
    _m21_open_circuit_then_race(intact, 8)
    assert intact_t.calls == 6, (
        "intact breaker: 5 opening failures + exactly ONE half-open probe"
    )

    top = _register_mutated_tree(mutated_repo, "mut_m21")
    m_gc = importlib.import_module(f"{top}.agent.infrastructure.llm.gemini_caller")
    mutated_t = _M21CountingTransport()
    mutated = m_gc.GeminiCallerAdapter(
        config=m_gc.GeminiRuntimeConfig(max_retries=1, backoff_base_seconds=0.001),
        transport=mutated_t,
    )
    _m21_open_circuit_then_race(mutated, 8)
    assert mutated_t.calls >= 7, (
        "expected the weakened control to let MULTIPLE concurrent callers "
        f"become provider probes (got {mutated_t.calls - 5} probes)"
    )
