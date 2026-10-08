"""Phase 8.7-C structural security guards.

These guards inspect the ACTUAL repository source (AST where meaningful,
targeted text scans otherwise) to prevent reintroduction of the three
corrected weaknesses:

* ``gateway_guard``  — no generic user-facing dispatch into internal services,
  no user-facing route into the monitoring service, no arbitrary internal
  path construction.
* ``jwt_guard``      — no hard-coded/fallback JWT signing secret usable in
  production; legacy predictable secret quarantined to its test reference.
* ``android_guard``  — no APK-bundled Gemini provider secret on any code or
  configuration path.

Run standalone (CI job ``structural-guards``):

    PYTHONPATH=devops-ai-platform python -m security_guards

Each guard exposes ``check_repo(repo_root) -> list[str]`` (violations) and
source-level ``check_*`` helpers used directly by the pytest mutation tests.
"""

from .android_guard import check_android as android_check
from .gateway_guard import check_gateway as gateway_check
from .jwt_guard import check_jwt as jwt_check

ALL_GUARDS = {
    "gateway-telemetry-trust": gateway_check,
    "android-gemini-secret": android_check,
    "jwt-fail-closed": jwt_check,
}

__all__ = [
    "ALL_GUARDS",
    "android_check",
    "gateway_check",
    "jwt_check",
]
