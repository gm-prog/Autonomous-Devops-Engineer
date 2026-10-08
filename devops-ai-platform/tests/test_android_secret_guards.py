"""Phase 8.7-C — Defect B acceptance tests: no APK-bundled Gemini secret.

Acceptance criteria covered:

* Test 1 — no production Kotlin source references BuildConfig.GEMINI_API_KEY
  for actual network authorization.
* Test 2 — no Gemini API URL contains a runtime API key parameter sourced
  from an APK-bundled secret.
* Test 3 — no secret relocated into string resources, renamed BuildConfig
  fields, manifest, assets, raw resources, source literals, or
  SharedPreferences defaults.
* Test 4 — the app can still function without a Gemini key (the non-secret
  offline template path is the unconditional fallback).
* Test 5 — the backend/gateway path, when configured, carries the AI request
  server-side.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import security_guards.android_guard as android_guard
from conftest import REPO_ROOT

APP_SRC = REPO_ROOT / "app" / "src" / "main"
GEMINI_CLIENT = APP_SRC / "java" / "com" / "example" / "data" / "GeminiClient.kt"
REPOSITORY = APP_SRC / "java" / "com" / "example" / "data" / "DevOpsRepository.kt"
BACKEND_CLIENT = APP_SRC / "java" / "com" / "example" / "data" / "BackendGatewayClient.kt"
MANIFEST = APP_SRC / "AndroidManifest.xml"
STRINGS = APP_SRC / "res" / "values" / "strings.xml"
ENV_EXAMPLE = REPO_ROOT / ".env.example"
GRADLE = REPO_ROOT / "app" / "build.gradle.kts"


def _main_kotlin_sources():
    return sorted(APP_SRC.rglob("*.kt"))


# ---------------------------------------------------------------------------
# Test 1 — no BuildConfig.GEMINI_API_KEY in production Kotlin source
# ---------------------------------------------------------------------------


def test_no_buildconfig_gemini_key_in_production_source():
    for src in _main_kotlin_sources():
        violations = android_guard.check_android_source(
            src.read_text(encoding="utf-8"), label=src.name
        )
        buildconfig_violations = [v for v in violations if "BuildConfig" in v]
        assert buildconfig_violations == [], f"{src.name}: {buildconfig_violations}"
    # Explicitly: the exact retired field is gone from every main source.
    for src in _main_kotlin_sources():
        code = android_guard._strip_kotlin_comments(src.read_text(encoding="utf-8"))
        assert "GEMINI_API_KEY" not in code, f"{src.name} still references GEMINI_API_KEY"


def test_guard_reports_clean_repository():
    violations = android_guard.check_android(REPO_ROOT)
    assert violations == [], "\n".join(violations)


# ---------------------------------------------------------------------------
# Test 2 — no Gemini URL with a runtime key parameter
# ---------------------------------------------------------------------------


def test_no_gemini_url_with_bundled_key():
    for src in _main_kotlin_sources():
        code = android_guard._strip_kotlin_comments(src.read_text(encoding="utf-8"))
        assert not android_guard._RE_GEMINI_URL_KEY.search(code), src.name
        assert not android_guard._RE_GEMINI_URL_INTERPOLATED_KEY.search(code), src.name
        # No direct call to the Gemini endpoint at all in the app:
        assert "generativelanguage.googleapis.com" not in code, (
            f"{src.name}: direct Gemini endpoint call — AI must be carried "
            "server-side by the authenticated backend"
        )


# ---------------------------------------------------------------------------
# Test 3 — no secret relocation into any APK-readable storage
# ---------------------------------------------------------------------------


def test_no_secret_relocated_into_app_storage():
    # string resources / manifest / assets
    for path in (STRINGS, MANIFEST):
        text = path.read_text(encoding="utf-8")
        assert "GEMINI" not in text.upper(), (
            f"{path.name}: Gemini key token in APK-readable resources"
        )
        assert not android_guard._RE_GEMINI_KEY_TOKEN.search(text), path.name
        assert not android_guard._RE_GOOGLE_KEY_LITERAL.search(text), path.name
    for asset in (APP_SRC / "assets").rglob("*") if (APP_SRC / "assets").is_dir() else []:
        if asset.is_file() and asset.suffix in (".xml", ".txt", ".json", ".md"):
            assert not android_guard._RE_GEMINI_KEY_TOKEN.search(asset.read_text()), asset

    # renamed BuildConfig field: any BuildConfig.GEMINI* is a violation
    for src in _main_kotlin_sources():
        code = android_guard._strip_kotlin_comments(src.read_text(encoding="utf-8"))
        assert not re.search(r"BuildConfig\s*\.\s*GEMINI", code, re.IGNORECASE), src.name

    # source literals: no real Google/Gemini key anywhere in main sources
    for src in _main_kotlin_sources():
        assert not android_guard._RE_GOOGLE_KEY_LITERAL.search(
            src.read_text(encoding="utf-8")
        ), f"{src.name}: API key literal"

    # SharedPreferences defaults: no secret-named key seeded with a literal
    for src in _main_kotlin_sources():
        code = android_guard._strip_kotlin_comments(src.read_text(encoding="utf-8"))
        for m in android_guard._RE_PREFS_SECRET_DEFAULT.finditer(code):
            assert not android_guard._SECRET_NAME_RE.search(m.group(1)), (
                f"{src.name}: {m.group(0)[:60]}..."
            )

    # committed env template: no key assignment (it would regenerate
    # BuildConfig.GEMINI_API_KEY through the Secrets plugin)
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("#"):
            continue
        assert not re.match(r"\s*GEMINI_API_KEY\s*=", line), line

    # committed env template: must not carry the stale remote-backend claim
    # and must state the 8.7-D truth (offline by default; the authenticated
    # server-side path is implemented; no provider key in the app).  The
    # template content lives in comment lines, so strip the comment markers
    # before normalizing (line wraps would otherwise split phrases).
    env_norm = re.sub(
        r"\s+", " ", re.sub(r"(?m)^\s*#\s*", " ", ENV_EXAMPLE.read_text(encoding="utf-8"))
    ).lower()
    for stale_claim in (
        "authenticated platform backend",
        "calls gemini server-side",
        "sends analysis requests to the",
    ):
        assert stale_claim not in env_norm, (
            f".env.example: stale remote-backend claim still present: "
            f"{stale_claim!r}"
        )
    for truth_marker in (
        "offline by default",
        "implemented on this branch",
        "bearer",
        "no provider key",
    ):
        assert truth_marker in env_norm, (
            f".env.example: required truth missing: {truth_marker!r} — the "
            "template must state that Android analysis is offline by "
            "default, that the authenticated server-side Gemini path is "
            "implemented on this branch (Phase 8.7-D), and that the app "
            "holds no provider key"
        )

    # gradle: no buildConfigField for a gemini key
    gradle_text = GRADLE.read_text(encoding="utf-8")
    assert not android_guard._RE_GRADLE_GEMINI.search(gradle_text)
    assert "GEMINI_API_KEY" not in gradle_text


# ---------------------------------------------------------------------------
# Test 4 — the app functions via the non-secret offline path
# ---------------------------------------------------------------------------


def test_offline_analysis_path_is_unconditional():
    """Repository analysis ALWAYS runs the offline template engine —
    deterministic, non-secret, no credential, no network call.

    (Behavioral execution of the Kotlin path lives in
    app/src/test/.../GeminiClientSecretPolicyTest.kt and runs under
    `gradle test`; here the contract is verified structurally.)
    """
    client_src = GEMINI_CLIENT.read_text(encoding="utf-8")
    code = android_guard._strip_kotlin_comments(client_src)

    # The offline engine exists and is what analyzeRepository returns.
    assert "fun generateSimulatedAssets" in code
    assert "fun analyzeRepository" in code
    analyze_body = code.split("fun analyzeRepository", 1)[1]
    assert "generateSimulatedAssets(" in analyze_body
    # No remote selection of any kind inside the analysis path.
    assert "backendBaseUrl" not in code
    assert "isRemoteAnalysisConfigured" not in code
    assert "BackendGatewayClient" not in code, (
        "the analysis engine must not depend on a remote backend client"
    )
    # No key presence concept remains (no isApiKeyPresent / BuildConfig read).
    assert "isApiKeyPresent" not in code
    assert "BuildConfig" not in code

    # The repository layer calls the offline engine without remote selection.
    repo_code = android_guard._strip_kotlin_comments(REPOSITORY.read_text(encoding="utf-8"))
    assert "GeminiClient.analyzeRepository" in repo_code
    assert "isRemote" not in repo_code
    assert "remoteUrl" not in repo_code
    assert "queryRemoteAnalysis" not in repo_code


# ---------------------------------------------------------------------------
# Test 5 — the analysis transport contract (Phase 8.7-D)
# ---------------------------------------------------------------------------

# The pre-8.7-D client method for the UNAUTHENTICATED analyze endpoint.
# It must never come back: the endpoint now exists for real, is JWT-
# authorized on the gateway, and is reached only through the typed,
# authenticated client below.
_FORBIDDEN_APP_TOKENS = ("queryRemoteAnalysis", "GEMINI_API_KEY",
                         "generativelanguage.googleapis.com")


def check_analysis_transport_contract(repo_root: Path) -> list:
    """Structural checker for the Phase 8.7-D Android analysis contract.

    Returns a list of violation strings (empty == contract holds).  The
    contract:

    1. the old unauthenticated remote-analysis client
       (``queryRemoteAnalysis``) is absent;
    2. if the app calls the typed analyze endpoint, the request is
       Bearer-JWT authenticated with a VARIABLE token (a static token
       literal or an empty bearer is a violation);
    3. no provider secret anywhere in the app (GEMINI_API_KEY, direct
       provider URL);
    4. the offline engine remains the explicit default (GeminiClient stays
       pure; the repository uses it and does not synthesize assets itself);
    5. the UI distinguishes LIVE_BACKEND from OFFLINE_SIM truthfully and a
       failed live attempt is surfaced as a failure, never as a success.

    Used by the contract tests and by the adversarial mutation tests (M5
    and friends must turn the suite red when the unauthenticated path or a
    provider secret is reintroduced).
    """
    violations: list = []
    app_src = Path(repo_root) / "app" / "src" / "main"
    for kt in sorted(app_src.rglob("*.kt")):
        rel = kt.name
        code = android_guard._strip_kotlin_comments(kt.read_text(encoding="utf-8"))
        for token in _FORBIDDEN_APP_TOKENS:
            if token in code:
                violations.append(
                    f"{rel}: '{token}' present — the old unauthenticated "
                    "remote path / provider secret must not reappear"
                )
        # A remote analyze call is only legitimate when Bearer-authenticated
        # with a variable token.
        if "/api/v1/repository/analyze" in code:
            authed = re.search(
                r'addHeader\s*\(\s*["\']Authorization["\']\s*,\s*["\']Bearer\s+\$[A-Za-z_]',
                code,
            )
            if not authed:
                violations.append(
                    f"{rel}: typed analyze endpoint called WITHOUT a "
                    "Bearer-JWT Authorization header — the pre-8.7-D "
                    "unauthenticated design must not be restored"
                )
            # No static token literals: the token must be a variable.
            for m in re.finditer(r'Bearer\s+([^"]*)"', code):
                literal = m.group(1).strip()
                if literal and "$" not in literal:
                    violations.append(
                        f"{rel}: static bearer token literal — the gateway "
                        "JWT must come from user configuration, never a "
                        "hard-coded credential"
                    )
    # GeminiClient must remain the pure offline engine.
    gemini = app_src / "java" / "com" / "example" / "data" / "GeminiClient.kt"
    if gemini.is_file():
        gcode = android_guard._strip_kotlin_comments(gemini.read_text(encoding="utf-8"))
        if "BackendGatewayClient" in gcode:
            violations.append(
                "GeminiClient.kt: depends on BackendGatewayClient — the "
                "offline analysis engine must not call remote backends"
            )
        if "generateSimulatedAssets" not in gcode or "fun analyzeRepository" not in gcode:
            violations.append(
                "GeminiClient.kt: offline engine or analyzeRepository entry "
                "point missing — the offline default must remain"
            )
    # The repository layer: offline default, honest live failure.
    repo = app_src / "java" / "com" / "example" / "data" / "DevOpsRepository.kt"
    if repo.is_file():
        rcode = android_guard._strip_kotlin_comments(repo.read_text(encoding="utf-8"))
        if "generateSimulatedAssets" in rcode:
            violations.append(
                "DevOpsRepository.kt: synthesizes simulated assets directly "
                "— a live failure must never masquerade as offline content"
            )
        if not all(state in rcode for state in
                   ("LIVE_BACKEND", "OFFLINE_SIM", "LIVE_FAILED", "OFFLINE_FAILED")):
            violations.append(
                "DevOpsRepository.kt: analysis-source reporting missing — "
                "live success / offline / live failure / offline failure "
                "must be distinguishable"
            )
        if '"Failed"' not in rcode:
            violations.append(
                "DevOpsRepository.kt: failed analyses are not marked "
                "Failed — honest failure reporting is required"
            )
    # The UI flow must distinguish the modes truthfully: all three states
    # (live success / offline default / live failure) must exist in the UI
    # layer (header badge source + analysis-source reporting), and the
    # header must render the state from the ViewModel.
    main = app_src / "java" / "com" / "example" / "MainActivity.kt"
    viewmodel = app_src / "java" / "com" / "example" / "ui" / "DevOpsViewModel.kt"
    if main.is_file() and viewmodel.is_file():
        ui_code = android_guard._strip_kotlin_comments(main.read_text(encoding="utf-8"))
        vm_code = android_guard._strip_kotlin_comments(viewmodel.read_text(encoding="utf-8"))
        # The badge renders the repository's state string verbatim; the
        # three rendered states must be explicitly handled in the UI layer,
        # and the fourth (OFFLINE_FAILED) must exist in the repository
        # (checked above) so a local engine failure can never be labeled
        # as a live failure.
        for mode in ('"LIVE_BACKEND"', '"OFFLINE_SIM"', '"LIVE_FAILED"'):
            if mode not in ui_code and mode not in vm_code:
                violations.append(
                    f"UI layer: {mode} state missing — the UI must "
                    "truthfully distinguish live/offline/failed analysis"
                )
        if "analysisMode" not in ui_code or "analysisSource" not in vm_code:
            violations.append(
                "UI layer: the header badge must render the analysis source "
                "from the ViewModel (LIVE_BACKEND / OFFLINE_SIM / LIVE_FAILED)"
            )
    return violations


def test_analysis_transport_contract():
    violations = check_analysis_transport_contract(REPO_ROOT)
    assert violations == [], "\n".join(violations)
    # Explicitly: the removed unauthenticated client method is gone...
    backend_code = android_guard._strip_kotlin_comments(BACKEND_CLIENT.read_text(encoding="utf-8"))
    assert "queryRemoteAnalysis" not in backend_code
    # ...and the typed endpoint call is Bearer-authenticated.
    assert re.search(
        r'addHeader\s*\(\s*["\']Authorization["\']\s*,\s*["\']Bearer\s+\$[A-Za-z_]',
        backend_code,
    ), "the analyze request must carry a Bearer JWT from a variable"


# ---------------------------------------------------------------------------
# Test 6 — app authentication is real JWT bearer, never fake/static
# ---------------------------------------------------------------------------


def test_remote_analysis_authentication_is_real_bearer_jwt():
    for kt in _main_kotlin_sources():
        code = android_guard._strip_kotlin_comments(kt.read_text(encoding="utf-8"))
        assert "GEMINI_API_KEY" not in code, f"{kt.name}: provider secret reference"
        assert "BuildConfig" not in code or "BuildConfig.GEMINI" not in code, (
            f"{kt.name}: BuildConfig provider reference"
        )
        # Any bearer construction must use a variable token — never a
        # static literal and never an empty credential.
        for m in re.finditer(r'Bearer\s+([^"]*)"', code):
            literal = m.group(1).strip()
            assert not (literal and "$" not in literal), (
                f"{kt.name}: static bearer token literal — no hard-coded "
                "credentials may be presented as real authentication"
            )
            assert literal != "", f"{kt.name}: empty bearer credential"
    # The token flows from user configuration (Settings) into the request.
    viewmodel = android_guard._strip_kotlin_comments(
        (REPO_ROOT / "app/src/main/java/com/example/ui/DevOpsViewModel.kt").read_text(encoding="utf-8")
    )
    assert "gatewayJwtToken" in viewmodel, (
        "the gateway JWT must come from user-supplied settings, not a "
        "hard-coded value"
    )


# ---------------------------------------------------------------------------
# Test 7 — documentation matches the actual branch
# ---------------------------------------------------------------------------


def test_documentation_states_the_offline_truth():
    """The current docs must state the truthful 8.7-D contract — offline by
    default, an implemented authenticated server-side path, and an honest
    verification status — and must not overclaim production verification
    or describe any fake/placeholder backend."""
    readme = re.sub(r"[*`\s]+", " ", (REPO_ROOT / "README.md").read_text(encoding="utf-8")).lower()
    security_md = re.sub(r"[*`\s]+", " ", (REPO_ROOT / "devops-ai-platform" / "SECURITY.md").read_text(encoding="utf-8")).lower()

    for doc in (readme, security_md):
        # Android apps cannot keep a reusable provider secret confidential.
        assert "cannot keep a reusable provider secret" in doc, (
            "documentation must state that Android apps cannot keep a "
            "reusable provider secret confidential"
        )
        # The Android path is offline / non-secret (the default).
        assert "offline" in doc
        # The authenticated server-side path is documented as implemented
        # on this branch (Phase 8.7-D).
        assert "implemented" in doc and "8.7-d" in doc, (
            "documentation must state that the authenticated server-side "
            "Gemini analysis path is implemented on this branch (Phase 8.7-D)"
        )
        # Verification status is stated honestly: the path has NOT been
        # exercised against the real Gemini API in production.
        assert "not been exercised against the real gemini api" in doc, (
            "documentation must not claim production verification — it "
            "must state that the path has not been exercised against the "
            "real Gemini API in a production deployment"
        )
        # No claim of a fictitious/placeholder backend carrying Gemini.
        for bad_claim in (
            "authenticated platform backend",
            "server-side by the authenticated backend",
            "authenticated backend, which calls gemini",
            "carries the ai request server-side",
        ):
            assert bad_claim not in doc, (
                f"documentation must not make the false claim: {bad_claim!r}"
            )

    # The retired BuildConfig-based instructions must not remain in the
    # current README.
    assert "BuildConfig.GEMINI_API_KEY" not in readme


# ---------------------------------------------------------------------------
# Phase 8.7-C.2 — UI truthfulness: the UI must not misrepresent the
# offline/simulated AI path as live Gemini functionality
# ---------------------------------------------------------------------------

MAIN_ACTIVITY = REPO_ROOT / "app" / "src" / "main" / "java" / "com" / "example" / "MainActivity.kt"

# Phrases that would falsely present local simulation as live provider
# telemetry or claim an unverified capability. The authenticated live
# analysis path is implemented in Phase 8.7-D, so generic "live Gemini"
# wording is not forbidden unless it mislabels the local cockpit/UI.  Matched case-insensitively against whitespace-
# normalized production source (comments included: a phrase like "Gemini
# Live analysis" describing current functionality is a regression anywhere
# in production source).
_FORBIDDEN_LIVE_GEMINI_PHRASES = (
    "compile live blueprints",
    "live blueprints via gemini",
    "gemini resilient api cockpit",
    "realtime safety constraints",
)

# Honest language the UI must carry instead (semantic markers, whitespace-
# insensitive).
_REQUIRED_TRUTHFUL_MARKERS = (
    "offline devops blueprints",
    "ai simulation & resilience cockpit",
    "not live gemini telemetry",
    "simulated api rate load",
    "simulated token cost",
    "simulated circuit state",
    "analyze (offline ai)",
)


def _normalized_main_activity() -> str:
    return re.sub(r"\s+", " ", MAIN_ACTIVITY.read_text(encoding="utf-8")).lower()


def check_ui_truthfulness(repo_root: Path) -> list:
    """Semantic contract checker for Android UI truthfulness (Phase 8.7-C.2).

    Returns a list of violation strings (empty == contract holds).  The
    contract: no production Android source claims live/current Gemini
    analysis, live blueprints, or a live Gemini API cockpit; the offline
    analysis path and the AI resilience cockpit are explicitly labeled as
    offline/simulated.  Used by the contract tests and by mutation M6.
    """
    violations: list = []
    main_activity = Path(repo_root) / "app" / "src" / "main" / "java" / "com" / "example" / "MainActivity.kt"
    if not main_activity.is_file():
        return ["MainActivity.kt: missing — UI truthfulness contract cannot be verified"]
    norm = re.sub(r"\s+", " ", main_activity.read_text(encoding="utf-8")).lower()

    for phrase in _FORBIDDEN_LIVE_GEMINI_PHRASES:
        if phrase in norm:
            violations.append(
                f"MainActivity.kt: stale live-Gemini claim present: {phrase!r} — "
                "this branch has no verified live Gemini integration"
            )
    for marker in _REQUIRED_TRUTHFUL_MARKERS:
        if marker not in norm:
            violations.append(
                f"MainActivity.kt: required truthful language missing: {marker!r} — "
                "the UI must label the offline/simulated behavior explicitly"
            )
    # Metric labels must be simulation-qualified, never bare provider labels.
    for bare_label in ("\"api rate load\"", "\"token cost\""):
        if re.search(r"text\(\s*" + re.escape(bare_label), norm):
            violations.append(
                f"MainActivity.kt: unqualified metric label {bare_label} — "
                "simulated metrics must be labeled as simulated"
            )
    return violations


def test_no_stale_live_gemini_ui_claims():
    norm = _normalized_main_activity()
    for phrase in _FORBIDDEN_LIVE_GEMINI_PHRASES:
        assert phrase not in norm, (
            f"stale live-Gemini UI claim still present: {phrase!r}"
        )


def test_ai_cockpit_and_analysis_labeled_as_simulation():
    violations = check_ui_truthfulness(REPO_ROOT)
    assert violations == [], "\n".join(violations)


# ---------------------------------------------------------------------------
# Phase 8.7-C.3 — documentation truthfulness: the roadmap must not claim
# that the gateway probe enables remote repository analysis
# ---------------------------------------------------------------------------

ROADMAP = REPO_ROOT / "VS_CODE_AND_VERCEL_ROADMAP.md"

# Stale claims that would describe the gateway as a remote-analysis
# transport (the pre-correction roadmap wording).
_FORBIDDEN_ROADMAP_CLAIMS = (
    "route analyze tasks directly to your remote edge server",
    "instead of using simulation",
    "connect to remote backend",
)

# Semantic markers the roadmap must carry (Phase 8.7-D truth):
# offline-by-default analysis, diagnostics-only probe, gateway does not
# route deployments, the implemented authenticated live path, the
# not-yet-production-verified boundary, and the server-side credential
# boundary.
_REQUIRED_ROADMAP_MARKERS = (
    "offline",
    "diagnostics-only",
    "does not route",
    "repository analysis",
    "not verified on this branch",
    "server-side only",
    "bearer",
    "jwt",
)


def _normalized_roadmap() -> str:
    return re.sub(r"\s+", " ", ROADMAP.read_text(encoding="utf-8")).lower()


def check_roadmap_truthfulness(repo_root: Path) -> list:
    """Semantic contract checker for the deployment roadmap (Phase 8.7-C.3).

    Returns a list of violation strings (empty == contract holds).  The
    contract: the roadmap never claims that pinging the gateway alone routes
    repository analysis to a remote server, and it explicitly states the
    offline-by-default architecture, the diagnostics-only probe, the
    implemented authenticated live path (Bearer-JWT, role-gated), the
    not-yet-production-verified boundary, and the server-side Gemini
    credential boundary.  Used by the contract test and by M7.
    """
    violations: list = []
    roadmap = Path(repo_root) / "VS_CODE_AND_VERCEL_ROADMAP.md"
    if not roadmap.is_file():
        return ["VS_CODE_AND_VERCEL_ROADMAP.md: missing — roadmap truthfulness contract cannot be verified"]
    norm = re.sub(r"\s+", " ", roadmap.read_text(encoding="utf-8")).lower()

    for phrase in _FORBIDDEN_ROADMAP_CLAIMS:
        if phrase in norm:
            violations.append(
                f"VS_CODE_AND_VERCEL_ROADMAP.md: stale remote-analysis claim "
                f"present: {phrase!r} — on this branch the gateway is "
                "diagnostics-only and never routes repository analysis"
            )
    for marker in _REQUIRED_ROADMAP_MARKERS:
        if marker not in norm:
            violations.append(
                f"VS_CODE_AND_VERCEL_ROADMAP.md: required architecture "
                f"language missing: {marker!r} — the roadmap must state the "
                "current offline/diagnostics-only/future-boundary truth"
            )
    return violations


def test_roadmap_matches_offline_architecture():
    violations = check_roadmap_truthfulness(REPO_ROOT)
    assert violations == [], "\n".join(violations)
