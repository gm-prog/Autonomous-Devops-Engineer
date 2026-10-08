"""Gateway JWT authentication and control-plane role authorization (Phase 8.7-C).

Authentication model
====================

* The gateway verifies **signed HS256 JWTs** with the process JWT secret
  resolved at startup by ``config.load_gateway_settings`` (fail closed when
  ``JWT_SECRET`` is absent outside explicit ``APP_ENV=development``).
* There is no token literal, magic string, or length-based mock acceptance.
  A request is authenticated only if its bearer token is a valid, unexpired
  HS256 JWT signed by the configured secret and carries ``sub`` + ``roles``.

Authorization model
===================

* :func:`verify_token` — authenticates any valid JWT (returns claims).
* :func:`require_operator` — control-plane gate: only operator roles
  (``operator``, ``DevOpsLead``, ``ClusterAdmin``) may invoke privileged
  control-plane operations (e.g. hotfix proposal approval/execution).

Telemetry provenance
====================

Human JWTs (of any role, including operator) are NEVER an accepted
authentication mechanism for monitoring telemetry ingestion.  Telemetry is
ingested only through the machine-authenticated (HMAC) producer boundary of
the monitoring service.  See ``monitoring-service/security/telemetry_auth.py``
and devops-ai-platform/SECURITY.md.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

import jwt
from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..config import GatewayConfig, GatewaySettings, load_gateway_settings

logger = logging.getLogger("GatewayAuth")

security_bearer = HTTPBearer(auto_error=False)

# Operator-role authorization for the control plane (existing platform
# operator roles, plus the lowercase ``operator`` alias used by the
# cross-system authorization matrix).
OPERATOR_ROLES = frozenset({"operator", "DevOpsLead", "ClusterAdmin"})

# Roles that are explicitly NOT operator roles (ordinary end users).
ORDINARY_ROLES = frozenset({"Developer", "Viewer", "user"})

_DEFAULT_TOKEN_TTL_SECONDS = 3600

# Config bound by the app factory (create_app) for dependency overrides;
# falls back to process-environment resolution (fail closed) when the router
# is mounted outside the factory.
_active_config: Optional[GatewayConfig] = None


def set_active_config(config: GatewayConfig) -> None:
    """Bind a validated config (called by the application factory)."""
    global _active_config
    _active_config = config


def get_gateway_config() -> GatewayConfig:
    """Resolve the validated gateway configuration (fail closed if misconfigured).

    Any authentication attempt in a misconfigured process fails closed with a
    503 instead of falling back to any bundled secret.
    """
    global _active_config
    if _active_config is None:
        try:
            _active_config = load_gateway_settings()
        except Exception:  # GatewayConfigurationError
            # Never log the exception text if it could carry secret material —
            # the configuration error text is static, but we keep this explicit.
            logger.error("Gateway JWT configuration is invalid; failing closed.")
            raise HTTPException(
                status_code=503,
                detail="Gateway authentication is unavailable: JWT configuration "
                "error. Refusing to fall back to any built-in signing secret.",
            )
    return _active_config


def decode_and_validate_token(token: str, config: GatewayConfig) -> Dict[str, Any]:
    """Core HS256 verification against an explicit validated config.

    Raises HTTPException(401) on any failure: malformed token, wrong
    algorithm, bad signature (including tokens signed with the retired
    legacy secret), expired token, or missing required claims.
    """
    try:
        claims: Dict[str, Any] = jwt.decode(
            token,
            config.jwt_secret,
            algorithms=["HS256"],
            options={"require": ["sub", "exp", "roles"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail="Invalid token: expired.") from exc
    except jwt.InvalidTokenError as exc:
        # Covers bad signature, wrong algorithm, malformed payload, missing
        # required claims.  Log without the token material.
        logger.warning("Rejected invalid JWT: %s", type(exc).__name__)
        raise HTTPException(
            status_code=401, detail="Invalid token signature or claims."
        ) from exc

    sub = claims.get("sub")
    roles = claims.get("roles")
    if not isinstance(sub, str) or not sub:
        raise HTTPException(status_code=401, detail="Invalid token: empty subject.")
    if not isinstance(roles, list) or not roles:
        raise HTTPException(status_code=401, detail="Invalid token: missing roles claim.")

    return {"sub": sub, "roles": [str(r) for r in roles]}


def verify_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
) -> Dict[str, Any]:
    """Verify incoming HS256 JWT signatures validating client identity credentials."""
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=401, detail="Not authenticated: bearer token missing."
        )
    return decode_and_validate_token(credentials.credentials, get_gateway_config())


def make_bound_verify_token(config: GatewayConfig):
    """Build a verify_token bound to a specific validated app config.

    Used by the application factory so each app instance authenticates with
    exactly the secret it was started with.
    """

    def _bound_verify_token(
        credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
    ) -> Dict[str, Any]:
        if credentials is None or not credentials.credentials:
            raise HTTPException(
                status_code=401, detail="Not authenticated: bearer token missing."
            )
        return decode_and_validate_token(credentials.credentials, config)

    return _bound_verify_token


def require_operator(user: Dict[str, Any] = Depends(verify_token)) -> Dict[str, Any]:
    """Control-plane authorization gate: operator roles only."""
    if not (set(user.get("roles", [])) & OPERATOR_ROLES):
        raise HTTPException(
            status_code=403,
            detail="Forbidden: operator role required for this control-plane operation.",
        )
    return user


def create_access_token(
    subject: str,
    roles: List[str],
    secret: str,
    ttl_seconds: int = _DEFAULT_TOKEN_TTL_SECONDS,
) -> str:
    """Issue an HS256 JWT signed with ``secret``.

    Used by trusted token mints (service tooling, tests, operator consoles).
    The secret itself is never logged.
    """
    now = int(time.time())
    payload = {"sub": subject, "roles": list(roles), "iat": now, "exp": now + ttl_seconds}
    return jwt.encode(payload, secret, algorithm="HS256")


class GatewayRateLimiter:
    """Simple Sliding-window memory rate limiter safeguarding downstream microservices."""

    def __init__(self):
        self.history: Dict[str, List[float]] = {}
        self.limit = GatewaySettings.RATE_LIMIT_MAX_REQUESTS

    def is_rate_limited(self, client_ip: str) -> bool:
        now = time.time()
        requests = self.history.get(client_ip, [])
        # Filter requests in the last 60 seconds
        requests = [req for req in requests if now - req < 60]
        self.history[client_ip] = requests

        if len(requests) >= self.limit:
            return True

        self.history[client_ip].append(now)
        return False
