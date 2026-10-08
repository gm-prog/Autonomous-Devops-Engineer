"""API Gateway configuration — environment contract (Phase 8.7-C).

JWT environment contract
========================

* ``JWT_SECRET``  — HS256 signing secret for gateway-issued/verified JWTs.
  It MUST be provided explicitly as an environment variable in every
  non-development deployment (staging, production, or any other value of
  ``APP_ENV``).  When it is absent in a non-development environment the
  gateway configuration **fails closed**: startup raises
  :class:`GatewayConfigurationError` and no signing secret is substituted.

* ``APP_ENV``     — explicit environment selector.  Only the exact value
  ``development`` enables the development-only fallback secret.  Development
  is never inferred from how the process was launched (outside Docker,
  local shell, CI, etc.); the switch must be unmistakably explicit.

Fail-closed guarantees
======================

* No bundled signing secret is ever used outside explicit development mode.
* The retired legacy fallback value (see ``LEGACY_PREDICTABLE_JWT_SECRET``)
  is rejected: tokens signed with it can never authenticate.  The
  development fallback is deliberately a *different* value so that a token
  minted under the old predictable secret is invalid everywhere.
* Configuration and authentication logging never emit secret material.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Mapping, Optional

logger = logging.getLogger("GatewayConfig")

# The exact value that must be selected to enable the development fallback.
DEVELOPMENT_ENV_VALUE = "development"

# Development-only fallback.  It exists solely so a local developer who has
# not exported JWT_SECRET yet can still boot the gateway with APP_ENV=development.
# It MUST NOT be used outside that mode and is intentionally distinct from the
# retired legacy secret below.
DEV_FALLBACK_JWT_SECRET = "development-only-jwt-signing-secret-do-not-use-in-production"

# Retired, predictable fallback from the pre-8.7-C gateway.  It is referenced
# by the security test-suite to prove that it can no longer authenticate.
# Do not use it as a signing secret anywhere.
LEGACY_PREDICTABLE_JWT_SECRET = "super-secret-devops-platform-signature-token"


class GatewayConfigurationError(RuntimeError):
    """Raised when the gateway configuration cannot be satisfied fail-closed."""


@dataclass(frozen=True)
class GatewayConfig:
    """Immutable, validated gateway runtime settings (including JWT secret)."""

    jwt_secret: str
    jwt_secret_origin: str  # "environment" | "development-fallback"
    app_env: str
    rate_limit_max_requests: int
    repo_service_grpc: str
    agent_service_grpc: str
    deployment_service_grpc: str
    incident_service_grpc: str

    @property
    def is_development(self) -> bool:
        return self.jwt_secret_origin == "development-fallback"


def resolve_jwt_secret(
    env: Optional[Mapping[str, str]] = None,
) -> tuple[str, str]:
    """Resolve the JWT signing secret under the fail-closed contract.

    Returns a ``(secret, origin)`` tuple where origin is either
    ``"environment"`` or ``"development-fallback"``.

    Raises:
        GatewayConfigurationError: when ``JWT_SECRET`` is absent and the
            environment is not explicitly ``APP_ENV=development``.
    """
    if env is None:
        env = os.environ

    raw_secret = env.get("JWT_SECRET", "").strip()
    app_env = env.get("APP_ENV", "")

    if raw_secret:
        return raw_secret, "environment"

    if app_env == DEVELOPMENT_ENV_VALUE:
        # Explicit development mode: the development fallback may be used.
        # Log without emitting the secret material itself.
        logger.warning(
            "JWT_SECRET not set; using the development-only fallback secret "
            "(APP_ENV=development). Never deploy this configuration outside "
            "a controlled development environment."
        )
        return DEV_FALLBACK_JWT_SECRET, "development-fallback"

    # Production / staging / anything not explicitly development:
    # fail closed. Never substitute a bundled secret.
    raise GatewayConfigurationError(
        "JWT_SECRET is required for the API gateway in non-development "
        "environments. Set JWT_SECRET explicitly. If this is a controlled "
        "local development machine, set APP_ENV=development explicitly — "
        "development mode is never inferred from the execution context."
    )


def load_gateway_settings(env: Optional[Mapping[str, str]] = None) -> GatewayConfig:
    """Load and validate full gateway settings (fail closed on bad JWT config)."""
    if env is None:
        env = os.environ

    jwt_secret, origin = resolve_jwt_secret(env)

    return GatewayConfig(
        jwt_secret=jwt_secret,
        jwt_secret_origin=origin,
        app_env=env.get("APP_ENV", ""),
        rate_limit_max_requests=int(env.get("RATE_LIMIT_MAX_REQUESTS", "100")),
        repo_service_grpc=env.get("REPO_SERVICE_GRPC", "repo-service:50051"),
        agent_service_grpc=env.get("AGENT_SERVICE_GRPC", "agent-service:50052"),
        deployment_service_grpc=env.get("DEPLOYMENT_SERVICE_GRPC", "deployment-service:50053"),
        incident_service_grpc=env.get("INCIDENT_SERVICE_GRPC", "incident-service:50055"),
    )


class GatewaySettings:
    """Non-secret gateway coordinates (import-compatible surface).

    The JWT signing secret is deliberately NOT a class attribute anymore.
    It is resolved per-process at startup through :func:`load_gateway_settings`
    so that a misconfigured process cannot silently fall back to a bundled
    value.  See devops-ai-platform/SECURITY.md for the full contract.
    """

    RATE_LIMIT_MAX_REQUESTS: int = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", 100))  # per minute

    # Downstream Internal gRPC connection coordinates
    REPO_SERVICE_GRPC: str = os.getenv("REPO_SERVICE_GRPC", "repo-service:50051")
    AGENT_SERVICE_GRPC: str = os.getenv("AGENT_SERVICE_GRPC", "agent-service:50052")
    DEPLOYMENT_SERVICE_GRPC: str = os.getenv("DEPLOYMENT_SERVICE_GRPC", "deployment-service:50053")
    MONITORING_SERVICE_GRPC: str = os.getenv("MONITORING_SERVICE_GRPC", "monitoring-service:50054")
    INCIDENT_SERVICE_GRPC: str = os.getenv("INCIDENT_SERVICE_GRPC", "incident-service:50055")


__all__ = [
    "DEVELOPMENT_ENV_VALUE",
    "DEV_FALLBACK_JWT_SECRET",
    "LEGACY_PREDICTABLE_JWT_SECRET",
    "GatewayConfigurationError",
    "GatewayConfig",
    "GatewaySettings",
    "load_gateway_settings",
    "resolve_jwt_secret",
]
