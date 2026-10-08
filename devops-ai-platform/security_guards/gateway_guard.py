"""Structural guard: gateway telemetry trust & dispatch surface (Phase 8.7-C).

Security properties enforced on the ACTUAL source:

G1. No generic user-facing dispatch route exists
    (no route path containing "dispatch" on any gateway router).
G2. The gateway routing table does not expose the monitoring service to any
    user-facing route (no "monitoring" key in ``SERVICES``).
G3. No route handler forwards to an arbitrary downstream target: no direct
    outbound HTTP call inside a route handler whose URL is derived from a
    route path parameter (service selection or internal path).
G3b. No route handler selects a downstream service via a mapping lookup
    (``SERVICES[<route_param>]``) — service selection must be code constants.
G4. No user-facing gateway route references a monitoring-service target in
    CODE (telemetry ingestion is NOT part of the gateway surface).
G5. The monitoring telemetry ingestion boundary is machine-authenticated:
    it does NOT accept user-JWT dependencies (verify_token /
    require_operator / HTTPBearer) and DOES enforce the HMAC producer
    verification.

The checker operates on source text/AST, so mutation tests can feed weakened
variants and must observe violations.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import List, Union

GATEWAY_ROUTERS_REL = Path("devops-ai-platform/api-gateway/routers")
MONITORING_TELEMETRY_ROUTER_REL = Path(
    "devops-ai-platform/monitoring-service/presentation/rest/telemetry_router.py"
)

_MONITORING_TARGET_RE = re.compile(r"monitoring[-_]service", re.IGNORECASE)
_JWT_DEP_TOKENS = ("verify_token", "require_operator", "security_bearer", "HTTPBearer")
_HMAC_TOKEN = "verify_telemetry_signature"


def _decorator_route_paths(node: ast.AST) -> List[str]:
    paths: List[str] = []
    for dec in node.decorator_list:
        func = dec.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            path_arg = dec.args[0] if dec.args else (
                dec.keywords[0].value if dec.keywords else None
            )
            if path_arg is None:
                continue
            try:
                literal = ast.literal_eval(path_arg)
            except (ValueError, TypeError, SyntaxError):
                literal = ast.unparse(path_arg)
            paths.append(str(literal))
    return paths


def _route_handler_names(tree: ast.Module) -> set:
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for path in _decorator_route_paths(node):
                names.add(node.name)
    return names


def _services_dict_keys(tree: ast.Module) -> List[str]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in (
                    "SERVICES", "SERVICE_ROUTES", "ROUTE_MAP"
                ):
                    if isinstance(node.value, ast.Dict):
                        keys = []
                        for k in node.value.keys:
                            try:
                                keys.append(ast.literal_eval(k))
                            except (ValueError, TypeError, SyntaxError):
                                keys.append(None)
                        return keys
    return []


def _is_http_call(func: ast.AST) -> bool:
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return (
            func.value.id in ("requests", "httpx", "session", "client", "transport")
            and func.attr in ("request", "post", "get", "put", "delete", "patch", "call")
        )
    return False


def _url_arg(call: ast.Call):
    url_arg = call.args[0] if call.args else None
    for kw in call.keywords:
        if kw.arg == "url":
            url_arg = kw.value
    return url_arg


def check_gateway_source(source: str, label: str = "gateway router") -> List[str]:
    """Structural checks on one gateway router source text."""
    violations: List[str] = []
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [f"{label}: source is not parseable Python ({exc})"]

    # G1 — no generic dispatch routes.
    for path in _all_route_paths(tree):
        if "dispatch" in path.lower():
            violations.append(
                f"{label}: generic dispatch route restored: {path!r} "
                "(the arbitrary-payload dispatcher must stay removed)"
            )

    # G2 — monitoring must not be in the routing table.
    keys = _services_dict_keys(tree)
    if "monitoring" in [str(k) for k in keys]:
        violations.append(
            f"{label}: routing table exposes 'monitoring' to user-facing routes"
        )

    # G3 / G3b — no route handler tunnels user input into downstream URLs.
    handler_names = _route_handler_names(tree)
    for node in ast.walk(tree):
        if not (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name in handler_names
        ):
            continue
        if _handler_forwards_url_from_route_param(node):
            violations.append(
                f"{label}: route handler {node.name!r} forwards to a downstream "
                "target derived from a route path parameter (arbitrary-service "
                "or arbitrary-internal-path tunnel)"
            )
        if _handler_selects_service_from_route_param(node):
            violations.append(
                f"{label}: route handler {node.name!r} selects the downstream "
                "service from a route path parameter (arbitrary downstream "
                "service tunnel)"
            )

    # G4 — no monitoring-service target in gateway ROUTER CODE (docstrings and
    # comments are ignored; code references only).
    try:
        code_only = ast.unparse(_strip_docstrings(tree))
    except Exception:
        code_only = source
    if _MONITORING_TARGET_RE.search(code_only):
        violations.append(
            f"{label}: a monitoring-service target reference exists in "
            "user-facing router code (telemetry is machine-authenticated on "
            "the monitoring service, not routed through the gateway)"
        )

    return violations


def _strip_docstrings(tree: ast.Module) -> ast.Module:
    """Remove docstring statements so code-only analysis ignores prose."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(
                body[0].value, ast.Constant
            ) and isinstance(body[0].value.value, str):
                node.body = body[1:]
    return tree


def _all_route_paths(tree: ast.Module) -> List[str]:
    paths: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            paths.extend(_decorator_route_paths(node))
    return paths


def _handler_forwards_url_from_route_param(node: ast.FunctionDef) -> bool:
    """True if the handler body makes an outbound HTTP call whose URL is
    derived from a route path parameter."""
    param_names = {a.arg for a in node.args.args} - {"self", "request"}
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call) or not _is_http_call(sub.func):
            continue
        url_arg = _url_arg(sub)
        if url_arg is None:
            continue
        if isinstance(url_arg, ast.JoinedStr):
            for part in url_arg.values:
                if isinstance(part, ast.FormattedValue):
                    v = part.value
                    if isinstance(v, ast.Name) and v.id in param_names:
                        return True
                    if isinstance(v, ast.Subscript):
                        idx = v.slice
                        if isinstance(idx, ast.Name) and idx.id in param_names:
                            return True
        elif isinstance(url_arg, ast.Name) and url_arg.id in param_names:
            return True
    return False


def _handler_selects_service_from_route_param(node: ast.FunctionDef) -> bool:
    """G3b: ``base = SERVICES[service_name]`` style selection where the
    subscript key is a route path parameter."""
    param_names = {a.arg for a in node.args.args} - {"self", "request"}
    for sub in ast.walk(node):
        if isinstance(sub, ast.Assign):
            for target in sub.targets:
                if (
                    isinstance(sub.value, ast.Subscript)
                    and isinstance(sub.value.value, ast.Name)
                    and sub.value.value.id in ("SERVICES", "SERVICE_ROUTES", "ROUTE_MAP")
                    and isinstance(sub.value.slice, ast.Name)
                    and sub.value.slice.id in param_names
                ):
                    return True
    return False


def check_gateway(repo_root: Union[str, Path]) -> List[str]:
    """Run the gateway structural guard over the actual repository."""
    repo_root = Path(repo_root)
    violations: List[str] = []

    routers_dir = repo_root / GATEWAY_ROUTERS_REL
    if not routers_dir.is_dir():
        violations.append(f"gateway guard: routers directory not found: {routers_dir}")
        return violations

    for py in sorted(routers_dir.glob("*.py")):
        violations.extend(check_gateway_source(py.read_text(encoding="utf-8"), label=py.name))

    # G5 — telemetry boundary is machine-authenticated (no user-JWT deps).
    telemetry_router = repo_root / MONITORING_TELEMETRY_ROUTER_REL
    if not telemetry_router.is_file():
        violations.append(
            f"gateway guard: telemetry ingestion boundary missing: "
            f"{MONITORING_TELEMETRY_ROUTER_REL}"
        )
    else:
        src = telemetry_router.read_text(encoding="utf-8")
        for token in _JWT_DEP_TOKENS:
            if token in src:
                violations.append(
                    f"gateway guard: telemetry ingestion boundary references "
                    f"user-JWT mechanism {token!r} — human JWTs must never be a "
                    "telemetry producer credential"
                )
        if _HMAC_TOKEN not in src:
            violations.append(
                "gateway guard: telemetry ingestion boundary does not enforce "
                "the HMAC producer verification (verify_telemetry_signature)"
            )
        violations.extend(_check_authentication_not_short_circuited(src))

    return violations


def _check_authentication_not_short_circuited(src: str) -> List[str]:
    """The producer-auth dependency must actually run the HMAC verification.

    Detects the "disable producer auth" weakening: an early return (or other
    exit) inside the auth function that precedes the HMAC verification call
    makes the check dead code.
    """
    violations: List[str] = []
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return violations

    verify_call_lines = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == _HMAC_TOKEN
    ]
    if not verify_call_lines:
        return violations  # covered by the token check above

    for node in ast.walk(tree):
        if not (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "authenticate_trusted_producer"
        ):
            continue
        min_call_line = min(verify_call_lines)
        for sub in ast.walk(node):
            if isinstance(sub, ast.Return) and sub.lineno < min_call_line:
                violations.append(
                    "gateway guard: telemetry producer authentication "
                    "short-circuits (returns before) the HMAC verification — "
                    "producer auth is effectively disabled"
                )
                break

    return violations
