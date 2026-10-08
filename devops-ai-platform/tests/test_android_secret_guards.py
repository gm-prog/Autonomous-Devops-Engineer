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
# Test 5 — no fictitious remote-analysis path exists
# ---------------------------------------------------------------------------


def check_offline_only_contract(repo_root: Path) -> list:
    """Structural checker for the truthful Phase 8.7-C.1 Android contract.

    Returns a list of violation strings (empty == contract holds).  The
    contract: the app contains no remote repository-analysis client, no
    client for an unimplemented analyze endpoint, no fake client-side
    authentication, and no BuildConfig provider secret.  Used by the
    contract tests and by the adversarial mutation tests (must turn red when
    the fictitious remote path is reintroduced).
    """
    violations: list = []
    app_src = Path(repo_root) / "app" / "src" / "main"
    for kt in sorted(app_src.rglob("*.kt")):
        rel = kt.name
        code = android_guard._strip_kotlin_comments(kt.read_text(encoding="utf-8"))
        if "queryRemoteAnalysis" in code:
            violations.append(
                f"{rel}: remote-analysis client method 'queryRemoteAnalysis' "
                "present — this branch has no implemented, authenticated "
                "analysis backend"
            )
        if "backendBaseUrl" in code:
            violations.append(
                f"{rel}: analysis path selects a remote backend URL "
                "(parameter 'backendBaseUrl') — repository analysis must be "
                "offline-only on this branch"
            )
        if "/api/v1/repository/analyze" in code:
            violations.append(
                f"{rel}: request to the unimplemented /api/v1/repository/analyze "
                "endpoint — fictitious remote analysis path"
            )
        if re.search(r'addHeader\s*\(\s*["\']\s*Authorization', code) or re.search(
            r'["\']\s*Bearer', code
        ):
            violations.append(
                f"{rel}: client-side authentication header construction — "
                "no fake/placeholder auth may be introduced"
            )
    # GeminiClient specifically must not reference the backend client.
    gemini = app_src / "java" / "com" / "example" / "data" / "GeminiClient.kt"
    if gemini.is_file():
        gcode = android_guard._strip_kotlin_comments(gemini.read_text(encoding="utf-8"))
        if "BackendGatewayClient" in gcode:
            violations.append(
                "GeminiClient.kt: depends on BackendGatewayClient — the "
                "offline analysis engine must not call remote backends"
            )
    return violations


def test_no_fictitious_remote_analysis_path():
    violations = check_offline_only_contract(REPO_ROOT)
    assert violations == [], "\n".join(violations)
    # Explicitly: the removed client method and its endpoint are gone.
    backend_code = android_guard._strip_kotlin_comments(BACKEND_CLIENT.read_text(encoding="utf-8"))
    assert "queryRemoteAnalysis" not in backend_code
    assert "/api/v1/repository/analyze" not in backend_code


# ---------------------------------------------------------------------------
# Test 6 — no fake authentication mechanism is introduced
# ---------------------------------------------------------------------------


def test_no_fake_authentication_in_app():
    for kt in _main_kotlin_sources():
        code = android_guard._strip_kotlin_comments(kt.read_text(encoding="utf-8"))
        assert not re.search(r'addHeader\s*\(\s*["\']\s*Authorization', code), kt.name
        assert not re.search(r'["\']\s*Bearer', code), (
            f"{kt.name}: Bearer-token construction — no fake client-side "
            "authentication may be presented as real security"
        )
        assert "GEMINI_API_KEY" not in code, f"{kt.name}: provider secret reference"


# ---------------------------------------------------------------------------
# Test 7 — documentation matches the actual branch
# ---------------------------------------------------------------------------


def test_documentation_states_the_offline_truth():
    """The current docs must state the truthful contract AND must not claim
    a verified authenticated backend path that does not exist."""
    readme = re.sub(r"[*`\s]+", " ", (REPO_ROOT / "README.md").read_text(encoding="utf-8")).lower()
    security_md = re.sub(r"[*`\s]+", " ", (REPO_ROOT / "devops-ai-platform" / "SECURITY.md").read_text(encoding="utf-8")).lower()

    for doc in (readme, security_md):
        # Android apps cannot keep a reusable provider secret confidential.
        assert "cannot keep a reusable provider secret" in doc, (
            "documentation must state that Android apps cannot keep a "
            "reusable provider secret confidential"
        )
        # The branch does not expose a verified live Gemini backend for the app.
        assert "does not" in doc and "verified live gemini backend integration" in doc, (
            "documentation must state that this branch does not expose a "
            "verified live Gemini backend integration"
        )
        # The Android path is offline / non-secret.
        assert "offline" in doc
        # No false claim of an authenticated backend carrying Gemini.
        # (The docs may state, as a FUTURE condition, that a remote path
        # requires a real implemented authenticated backend; they must not
        # claim such a path currently exists.)
        for bad_claim in (
            "authenticated platform backend",
            "server-side by the authenticated backend",
            "authenticated backend, which calls gemini",
            "carries the ai request server-side",
            "/api/v1/repository/analyze",
        ):
            assert bad_claim not in doc, (
                f"documentation must not make the false current claim: {bad_claim!r}"
            )

    # The retired BuildConfig-based instructions must not remain in the
    # current README.
    assert "BuildConfig.GEMINI_API_KEY" not in readme
