"""Structural guard: no APK-bundled Gemini provider secret (Phase 8.7-C).

Android-distributed applications cannot keep a reusable provider secret
confidential — anything compiled into (or shipped with) the artifact is
recoverable.  The app therefore must never carry ``GEMINI_API_KEY`` (or any
renamed Gemini credential) on any code or configuration path.

Security properties enforced on the ACTUAL source:

A1. No ``BuildConfig.GEMINI*`` reference in production Kotlin source
    (covers the original field and any rename inside BuildConfig).
A2. No Gemini API URL carrying a runtime ``key=`` API-key parameter in
    production Kotlin source.
A3. No SharedPreferences (or similar) default seeding a Gemini/API-key/
    secret/token value from a source literal.
A4. No ``GEMINI_API_KEY=`` assignment in committed ``.env`` / ``.env.example``.
A5. No ``GEMINI_API_KEY`` token or ``key=`` Gemini URL in AndroidManifest,
    string resources, assets, or raw resources.
A6. No real Google/Gemini API key literal (``AIza...``) anywhere in app
    production sources or resources.
A7. No ``buildConfigField`` generating a Gemini key into BuildConfig.

The checker operates on source text, so mutation tests can feed weakened
variants and must observe violations.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Union

APP_REL = Path("app")

# A1 — BuildConfig Gemini field (original or renamed).
_RE_BUILDCONFIG_GEMINI = re.compile(r"BuildConfig\s*\.\s*GEMINI", re.IGNORECASE)

# A2 — Gemini endpoint URL with a runtime key parameter.
_RE_GEMINI_URL_KEY = re.compile(
    r"(generativelanguage\.googleapis\.com|gemini[a-z0-9.-]*\.googleapis\.com)[^\n]*[?&]key=",
    re.IGNORECASE,
)
# ...or a generic construction of a Gemini URL where a key variable is
# interpolated into the query string.
_RE_GEMINI_URL_INTERPOLATED_KEY = re.compile(
    r"(generativelanguage\.googleapis\.com[^\n]*?key\s*=\s*[\$\{])",
    re.IGNORECASE,
)

# A3 — SharedPreferences default seeding a secret-looking value.
#   putString("...key|secret|token...", "<literal>")
#   getString("...key|secret|token...", "<literal>")
_RE_PREFS_SECRET_DEFAULT = re.compile(
    r"\.(?:put|get)String\s*\(\s*[\"']((?:(?![\"']).)*(?:key|secret|token|credential)[^\"']*)[\"']\s*,\s*[\"']([^\"']{8,})[\"']",
    re.IGNORECASE,
)

# A4 — env file assignment.
_RE_ENV_GEMINI = re.compile(r"^\s*GEMINI_API_KEY\s*=", re.IGNORECASE | re.MULTILINE)

# A5 — manifest / resources / assets token.
_RE_GEMINI_KEY_TOKEN = re.compile(r"GEMINI[_-]?API[_-]?KEY", re.IGNORECASE)

# A6 — real Google/Gemini key literal (39-char AIza-prefixed base64url).
_RE_GOOGLE_KEY_LITERAL = re.compile(r"AIza[0-9A-Za-z_-]{35}")

# A7 — gradle buildConfigField for a gemini key.
_RE_GRADLE_GEMINI = re.compile(
    r"buildConfigField\s*\([^)]*GEMINI", re.IGNORECASE | re.DOTALL
)

_SECRET_NAME_RE = re.compile(r"(key|secret|token|credential)", re.IGNORECASE)

def _strip_kotlin_comments(source: str) -> str:
    """Remove Kotlin // and /* */ comments, respecting string literals.

    A small state scanner: comments are stripped only outside of string and
    character literals, so URL strings like "http://..." survive.  String
    interpolation bodies are treated as string content (an accepted
    approximation for guard purposes).
    """
    out: List[str] = []
    i = 0
    n = len(source)
    NORMAL, LINE, BLOCK, STR, TSTR, CHR = range(6)
    state = NORMAL
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if state == NORMAL:
            if ch == "/" and nxt == "/":
                state = LINE
                i += 2
                continue
            if ch == "/" and nxt == "*":
                state = BLOCK
                i += 2
                continue
            if source.startswith('"""', i):
                state = TSTR
                out.append('"""')
                i += 3
                continue
            if ch == '"':
                state = STR
                out.append(ch)
                i += 1
                continue
            if ch == "'":
                state = CHR
                out.append(ch)
                i += 1
                continue
            out.append(ch)
            i += 1
            continue
        if state == LINE:
            if ch == "\n":
                state = NORMAL
                out.append(ch)
            i += 1
            continue
        if state == BLOCK:
            if ch == "*" and nxt == "/":
                state = NORMAL
                i += 2
                continue
            if ch == "\n":
                out.append(ch)
            i += 1
            continue
        if state == TSTR:
            if source.startswith('"""', i):
                out.append('"""')
                state = NORMAL
                i += 3
                continue
            out.append(ch)
            i += 1
            continue
        if state == STR:
            if ch == "\\":
                out.append(source[i:i + 2])
                i += 2
                continue
            if ch == '"':
                state = NORMAL
            out.append(ch)
            i += 1
            continue
        if state == CHR:
            if ch == "\\":
                out.append(source[i:i + 2])
                i += 2
                continue
            if ch == "'":
                state = NORMAL
            out.append(ch)
            i += 1
            continue
    return "".join(out)


def _iter_app_kotlin_files(app_dir: Path) -> List[Path]:
    main_src = app_dir / "src" / "main"
    if not main_src.is_dir():
        return []
    return sorted(main_src.rglob("*.kt"))


_TEXT_RESOURCE_SUFFIXES = {".xml", ".txt", ".json", ".pro", ".md", ".png",
                          ".jpg", ".jpeg", ".webp"}


def _iter_app_resource_files(app_dir: Path) -> List[Path]:
    main_src = app_dir / "src" / "main"
    if not main_src.is_dir():
        return []
    files: List[Path] = []
    manifest = main_src / "AndroidManifest.xml"
    if manifest.is_file():
        files.append(manifest)
    for pat in ("res/**/*", "assets/**/*"):
        files.extend(sorted(main_src.glob(pat)))
    return [f for f in files if f.suffix.lower() in _TEXT_RESOURCE_SUFFIXES]


def check_android_source(source: str, label: str = "kotlin source") -> List[str]:
    """A1 + A2 + A3 + A6 on one production Kotlin source text.

    Code-pattern checks (A1/A2/A3) run on comment-stripped source so that
    documentation of the prohibition cannot mask or trip code checks; the
    key-literal check (A6) runs on the raw source because a secret in ANY
    source text is a repository leak.
    """
    violations: List[str] = []
    code = _strip_kotlin_comments(source)

    for match in _RE_BUILDCONFIG_GEMINI.finditer(code):
        violations.append(
            f"{label}: BuildConfig Gemini secret reference restored: "
            f"{match.group(0)!r} — APK-bundled provider secrets are not allowed"
        )

    for match in _RE_GEMINI_URL_KEY.finditer(code):
        violations.append(
            f"{label}: Gemini API URL carries a runtime key parameter: "
            f"{match.group(0)[:80]!r} — AI requests must be carried "
            "server-side by the authenticated backend"
        )

    for match in _RE_GEMINI_URL_INTERPOLATED_KEY.finditer(code):
        violations.append(
            f"{label}: Gemini API URL interpolates a key into the query "
            f"string: {match.group(0)[:80]!r}"
        )

    for match in _RE_PREFS_SECRET_DEFAULT.finditer(code):
        key_name = match.group(1)
        if _SECRET_NAME_RE.search(key_name):
            violations.append(
                f"{label}: SharedPreferences seeds a secret-looking value for "
                f"key {key_name!r} from a source literal"
            )

    for match in _RE_GOOGLE_KEY_LITERAL.finditer(source):
        violations.append(
            f"{label}: real Google/Gemini API key literal found in source: "
            f"{match.group(0)[:8]}..."
        )

    return violations


def check_android(repo_root: Union[str, Path]) -> List[str]:
    """Run the Android secret guard over the actual repository."""
    repo_root = Path(repo_root)
    violations: List[str] = []
    app_dir = repo_root / APP_REL
    if not app_dir.is_dir():
        violations.append(f"android guard: app directory not found: {app_dir}")
        return violations

    # A1/A2/A3/A6 — production Kotlin sources.
    for py in _iter_app_kotlin_files(app_dir):
        rel = py.relative_to(repo_root).as_posix()
        violations.extend(check_android_source(py.read_text(encoding="utf-8"), label=rel))

    # A5 — manifest / resources / assets.
    for res in _iter_app_resource_files(app_dir):
        rel = res.relative_to(repo_root).as_posix()
        try:
            text = res.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        if _RE_GEMINI_KEY_TOKEN.search(text) or _RE_GEMINI_URL_KEY.search(text):
            violations.append(
                f"android guard: Gemini key token or key-parameter URL in {rel}"
            )
        if _RE_GOOGLE_KEY_LITERAL.search(text):
            violations.append(f"android guard: API key literal in {rel}")

    # A4 — committed env files.
    for env_name in (".env", ".env.example"):
        env_path = repo_root / env_name
        if env_path.is_file():
            text = env_path.read_text(encoding="utf-8", errors="ignore")
            for line in text.splitlines():
                if line.lstrip().startswith("#"):
                    continue
                if _RE_ENV_GEMINI.search(line):
                    violations.append(
                        f"android guard: {env_name} assigns GEMINI_API_KEY — the "
                        "key belongs server-side, never in the app's BuildConfig"
                    )

    # A7 — gradle buildConfigField.
    gradle_files = list(app_dir.glob("build.gradle.kts")) + list(
        app_dir.glob("build.gradle")
    )
    for gradle in gradle_files:
        rel = gradle.relative_to(repo_root).as_posix()
        text = gradle.read_text(encoding="utf-8", errors="ignore")
        if _RE_GRADLE_GEMINI.search(text):
            violations.append(
                f"android guard: {rel} generates a Gemini key BuildConfig field"
            )
        if _RE_BUILDCONFIG_GEMINI.search(text):
            violations.append(f"android guard: {rel} references a Gemini BuildConfig field")

    return violations
