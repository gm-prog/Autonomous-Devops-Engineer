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
# Test 4 — the app functions without a Gemini key (non-secret fallback)
# ---------------------------------------------------------------------------


def test_offline_fallback_path_is_unconditional():
    """Without a backend the app uses the offline template engine — a
    truthful non-secret fallback, no credential involved.

    (Behavioral execution of the Kotlin path lives in
    app/src/test/.../GeminiClientSecretPolicyTest.kt and runs under
    `gradle test`; here the guard verifies the structure statically.)
    """
    client_src = GEMINI_CLIENT.read_text(encoding="utf-8")
    code = android_guard._strip_kotlin_comments(client_src)

    # The offline engine still exists and is the final, unconditional return.
    assert "fun generateSimulatedAssets" in code
    assert code.count("generateSimulatedAssets(") >= 2  # definition + call sites
    # analyzeRepository returns the offline result when no backend is set:
    assert re.search(
        r"fun\s+analyzeRepository\([^)]*backendBaseUrl", code, re.DOTALL
    ), "analyzeRepository must take the (non-secret) backend base URL"
    # No key presence concept remains (no isApiKeyPresent / BuildConfig read).
    assert "isApiKeyPresent" not in code
    assert "BuildConfig" not in code


def test_repository_wires_remote_path_and_offline_fallback():
    repo_src = REPOSITORY.read_text(encoding="utf-8")
    code = android_guard._strip_kotlin_comments(repo_src)
    # Analysis goes through GeminiClient with the backend URL only when the
    # user configured a remote gateway (non-secret config in prefs).
    assert "backendBaseUrl = if (isRemote) remoteUrl else null" in code
    # The old direct-call fallback branch is gone.
    assert "Live Gemini API Analysis" not in code


# ---------------------------------------------------------------------------
# Test 5 — the backend path carries the AI request server-side
# ---------------------------------------------------------------------------


def test_backend_path_carries_ai_request_server_side():
    client_src = android_guard._strip_kotlin_comments(GEMINI_CLIENT.read_text(encoding="utf-8"))
    backend_src = BACKEND_CLIENT.read_text(encoding="utf-8")

    # When a backend URL is configured, the client delegates to the
    # authenticated backend (server-side Gemini).
    assert "BackendGatewayClient.queryRemoteAnalysis" in client_src
    assert "baseUrlStr = backendBaseUrl" in client_src
    # The backend endpoint the app calls:
    assert "/api/v1/repository/analyze" in backend_src
    # The app sends only non-secret repository metadata to the backend.
    payload_block = client_src.split("queryRemoteAnalysis", 1)[1]
    for field in ("repoName", "repoUrl", "framework", "technology"):
        assert field in payload_block
    # And no secret ever crosses the app -> backend boundary.
    assert "apiKey" not in client_src.lower()
    assert "API_KEY" not in client_src


def test_documentation_states_the_secret_model():
    """Acceptance test 6 (documentation): the docs must not claim the
    opposite of the corrected trust model."""
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    security_md = (REPO_ROOT / "devops-ai-platform" / "SECURITY.md").read_text(encoding="utf-8")
    for doc in (readme, security_md):
        assert "cannot keep" in doc.lower() or "cannot keep a reusable" in doc.lower(), (
            "documentation must state that Android apps cannot keep a "
            "reusable provider secret confidential"
        )
    # The retired BuildConfig-based instructions must not remain in the
    # current README.
    assert "BuildConfig.GEMINI_API_KEY" not in readme
