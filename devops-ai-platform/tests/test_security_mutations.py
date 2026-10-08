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
"""

from __future__ import annotations

import importlib
import shutil
import sys
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
    app = main.create_app(env={"JWT_SECRET": TEST_GW_SECRET, "APP_ENV": "production"})

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
    app = main.create_app(env={"JWT_SECRET": TEST_GW_SECRET, "APP_ENV": "production"})

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
    # Weaken: _generate_text fabricates a response when the key is missing
    # (the first _precall_gates() call site is inside _generate_text).
    old_check = "        self._precall_gates()"
    assert old_check in src, "M10 target not found in gemini_caller"
    src = src.replace(
        old_check,
        "        if not self.api_key:  # MUTATION: fail open\n"
        '            return "SIMULATED GEMINI RESPONSE (offline bypass)"\n'
        + old_check,
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
    old = "        return self.accumulated_spend < self.monthly_budget"
    assert old in src, "M12 target not found in GeminiBudgetService.check_budget"
    src = src.replace(old, "        return True  # MUTATION: budget ceiling bypassed", 1)
    caller_path.write_text(src, encoding="utf-8")


def _assert_budget_enforced(repo: Path) -> None:
    """Structural guard: check_budget must compare spend against the ceiling."""
    src = (repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py").read_text(encoding="utf-8")
    fn = src.split("def check_budget", 1)[1].split("def ", 1)[0]
    assert "self.accumulated_spend < self.monthly_budget" in fn, (
        "check_budget no longer compares spend against the ceiling"
    )


def test_mutation_m12_budget_bypass_detected(mutated_repo):
    # (1) Structural guard holds on the unmutated repo.
    _assert_budget_enforced(REPO_ROOT)
    _apply_budget_bypass(mutated_repo)
    # The mutated budget check is structurally broken:
    src = (mutated_repo / "devops-ai-platform/agent-service/infrastructure/llm/gemini_caller.py").read_text(encoding="utf-8")
    fn = src.split("def check_budget", 1)[1].split("def ", 1)[0]
    assert "self.accumulated_spend < self.monthly_budget" not in fn, (
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
