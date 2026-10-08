"""Structural guard: JWT fail-closed configuration (Phase 8.7-C).

Security properties enforced on the ACTUAL source:

J1. No bundled JWT signing secret fallback: no ``os.getenv("JWT_SECRET",
    <literal>)`` / ``os.environ.get("JWT_SECRET", <literal>)`` (or dict
    ``.get`` with a literal default) anywhere in gateway production code.
J2. No hard-coded signing secret in code: ``jwt.encode``/``jwt.decode`` are
    never called with a string-literal secret argument.
J3. The legacy predictable secret value is quarantined: it may appear only
    in (a) its explicit test-reference constant definition in
    ``api-gateway/config/__init__.py`` and (b) the security test-suite /
    documentation — never anywhere else in the repository.
J4. The development fallback is explicitly gated: the development fallback
    secret is referenced only inside a conditional that tests the explicit
    development switch (``APP_ENV == development``), never unconditionally.

The checker operates on source text/AST, so mutation tests can feed weakened
variants and must observe violations.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import List, Union

GATEWAY_PKG_REL = Path("devops-ai-platform/api-gateway")
CONFIG_REL = Path("devops-ai-platform/api-gateway/config/__init__.py")

LEGACY_SECRET_VALUE = "super-secret-devops-platform-signature-token"

# The legacy value is permitted ONLY in these relative locations (its
# test-reference definition + the guard's own reference constant +
# documentation/test-suite references).  Everywhere else it is a violation.
_LEGACY_ALLOWED_REL_PREFIXES = (
    "devops-ai-platform/api-gateway/config/__init__.py",
    "devops-ai-platform/security_guards/",
    "devops-ai-platform/tests/",
    "devops-ai-platform/SECURITY.md",
    "CHANGELOG.md",
    "README.md",
)

# Environment variable names considered "the JWT secret".
_JWT_SECRET_NAMES = {"JWT_SECRET"}

_DEV_ENV_VALUES = {"development", '"development"', "'development'"}


def _iter_gateway_py_files(repo_root: Path) -> List[Path]:
    base = repo_root / GATEWAY_PKG_REL
    if not base.is_dir():
        return []
    return sorted(base.rglob("*.py"))


def check_jwt_source(source: str, label: str = "gateway module") -> List[str]:
    """J1 + J2 on one gateway production source text."""
    violations: List[str] = []
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [f"{label}: source is not parseable Python ({exc})"]

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func

        # J1 — any lookup of the JWT secret with a non-empty literal default:
        #   os.getenv("JWT_SECRET", "...") / os.environ.get("JWT_SECRET", "...")
        #   env.get("JWT_SECRET", "...")   (mapping-style)
        if isinstance(func, ast.Attribute) and func.attr in ("get", "getenv"):
            if node.args:
                try:
                    key = ast.literal_eval(node.args[0])
                except (ValueError, TypeError, SyntaxError):
                    key = None
                if key in _JWT_SECRET_NAMES and len(node.args) >= 2:
                    default = node.args[1]
                    # A non-empty literal default is a usable bundled secret.
                    # (None / "" are "no value" sentinels, not secrets.)
                    if isinstance(default, ast.Constant) and isinstance(
                        default.value, str
                    ) and default.value != "":
                        violations.append(
                            f"{label}: bundled JWT_SECRET fallback restored — "
                            "a literal default for the JWT signing secret "
                            "defeats the fail-closed contract"
                        )

        # J2 — jwt.encode/decode with a string-literal secret
        if isinstance(func, ast.Attribute) and func.attr in ("encode", "decode", "sign", "verify"):
            base = func.value
            is_jwt_call = isinstance(base, ast.Name) and base.id in ("jwt", "pyjwt")
            if is_jwt_call and len(node.args) >= 2:
                secret = node.args[1]
                if isinstance(secret, ast.Constant) and isinstance(secret.value, str):
                    violations.append(
                        f"{label}: hard-coded JWT signing secret literal passed "
                        f"to {func.attr}() — signing must use the validated "
                        "environment-resolved secret"
                    )

    return violations


def check_jwt(repo_root: Union[str, Path]) -> List[str]:
    """Run the JWT structural guard over the actual repository."""
    repo_root = Path(repo_root)
    violations: List[str] = []

    # J1 + J2 across all gateway production modules.
    for py in _iter_gateway_py_files(repo_root):
        rel = py.relative_to(repo_root).as_posix()
        violations.extend(check_jwt_source(py.read_text(encoding="utf-8"), label=rel))

    # J3 — legacy predictable secret quarantined.
    for py in repo_root.rglob("*.py"):
        rel = py.relative_to(repo_root).as_posix()
        if rel.startswith(".git"):
            continue
        text = py.read_text(encoding="utf-8", errors="ignore")
        if LEGACY_SECRET_VALUE in text:
            allowed = any(rel.startswith(pfx) for pfx in _LEGACY_ALLOWED_REL_PREFIXES)
            if not allowed:
                violations.append(
                    f"jwt guard: legacy predictable signing secret value appears "
                    f"in {rel} — it must stay quarantined to its test-reference "
                    "definition and documentation"
                )

    # J4 — development fallback gated by the explicit development switch.
    config_path = repo_root / CONFIG_REL
    if config_path.is_file():
        violations.extend(_check_dev_fallback_gate(config_path.read_text(encoding="utf-8")))
    else:
        violations.append(f"jwt guard: gateway config module missing: {CONFIG_REL}")

    return violations


def _check_dev_fallback_gate(config_source: str) -> List[str]:
    """J4: the dev fallback secret is only referenced inside the explicit
    APP_ENV=development conditional."""
    violations: List[str] = []
    try:
        tree = ast.parse(config_source)
    except SyntaxError:
        return violations  # parseability covered by check_jwt_source

    # Collect all READ (Load) references to DEV_FALLBACK_JWT_SECRET — the
    # constant definition itself (Store) is allowed.
    fallback_refs = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and node.id == "DEV_FALLBACK_JWT_SECRET"
        and isinstance(node.ctx, ast.Load)
    ]
    if not fallback_refs:
        return violations  # no dev fallback kept at all — acceptable

    # Find every If node whose test references the development switch.
    gated_regions = []

    class _Collector(ast.NodeVisitor):
        def visit_If(self, node: ast.If):
            test_src = ast.unparse(node.test)
            if any(v in test_src for v in ("DEVELOPMENT_ENV_VALUE", "development")):
                gated_regions.append(node)
            self.generic_visit(node)

    _Collector().visit(tree)

    for ref in fallback_refs:
        line = ref.lineno
        in_gate = any(
            gate.lineno <= line <= getattr(gate, "end_lineno", gate.lineno)
            for gate in gated_regions
        )
        if not in_gate:
            violations.append(
                f"jwt guard: development fallback secret referenced at line "
                f"{line} outside the explicit APP_ENV=development conditional — "
                "the fallback must be unreachable except in unmistakable "
                "development mode"
            )
    return violations
