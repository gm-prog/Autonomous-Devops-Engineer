"""Deployment API authentication and authorization (Phase 8.8A Correction-1, F2).

Authentication model
====================
Two verified credential mechanisms — nothing else is accepted:

* **HS256 JWT** — the SAME contract the api-gateway enforces
  (``api-gateway/core/auth.py``): signed with the process ``JWT_SECRET``,
  algorithms restricted to HS256, required claims ``sub`` + ``exp`` +
  ``roles``, subject must be a non-empty string, roles a non-empty list.
  A request is authenticated only if its bearer token is a valid,
  unexpired JWT signed by the configured secret. There is no token
  literal, no magic string, no length-based mock acceptance and no
  bundled fallback secret: with ``JWT_SECRET`` absent or invalid the
  service fails closed (503), mirroring the gateway.

* **Internal service token** — ``AGENT_INTERNAL_TOKEN`` (the same
  environment variable the gateway/agent hop already uses), sent in the
  ``X-Internal-Token`` header, compared with
  :func:`hmac.compare_digest` (constant-time). It authenticates as the
  fixed service principal ``deployment-service-principal`` with the
  ``service`` role — never as a caller-supplied identity, and never as
  an approver.

Authorization model
===================
Roles, in line with the existing platform role model
(``OPERATOR_ROLES`` in the gateway):

===========  ==========================================================
Operation    Accepted identities
===========  ==========================================================
dry-run      operator roles (human JWT) or the service principal
read         operator roles, or the creator of the run, or the
             service principal for runs it created
approve      operator roles (human JWT) ONLY — the approver identity is
             the verified ``sub`` of the token; caller-supplied
             approver text is ignored
dispatch     operator roles or the service principal
===========  ==========================================================

Network segmentation (internal d1 network, no host ports) is defence in
depth, not a substitute: every sensitive route authenticates and
authorizes even when reachable.

Fail-closed behaviour
=====================
* no/invalid/expired/wrongly-signed token  → 401
* authenticated but missing the role        → 403
* auth configuration absent/invalid         → 503 (never a fallback
  secret, never a permissive default)
* execution-enabled mode WITHOUT the required auth configuration is
  refused at startup (see :func:`validate_execution_config`).
"""
from __future__ import annotations

import hmac
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import jwt
from fastapi import Header, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger("DeploymentAuth")

security_bearer = HTTPBearer(auto_error=False)

#: The existing platform operator roles (identical to the gateway's
#: control-plane set — one role model, not a parallel weaker one).
OPERATOR_ROLES = frozenset({"operator", "DevOpsLead", "ClusterAdmin"})

#: The role of the internal service principal.
SERVICE_ROLE = "service"

#: Fixed identity of the internal service principal. It is derived from
#: the verified token, never from any request field or header.
SERVICE_PRINCIPAL = "deployment-service-principal"

#: Minimum accepted length for the shared internal token (mirrors the
#: gateway's "too short" refusal — a short token is a misconfiguration,
#: not a valid credential).
_MIN_INTERNAL_TOKEN_LENGTH = 16


class DeploymentAuthenticationConfigError(RuntimeError):
    """The deployment auth configuration is absent or unusable."""


@dataclass(frozen=True)
class Identity:
    """A verified caller identity. Never built from request fields."""

    subject: str
    roles: tuple
    kind: str  # "human" | "service"

    @property
    def is_operator(self) -> bool:
        return bool(set(self.roles) & OPERATOR_ROLES)

    @property
    def is_service(self) -> bool:
        return self.kind == "service"


# ---------------------------------------------------------------------------
# Configuration resolution (fail closed)
# ---------------------------------------------------------------------------


def _jwt_secret() -> str:
    secret = os.getenv("JWT_SECRET", "").strip()
    if not secret:
        raise DeploymentAuthenticationConfigError(
            "JWT_SECRET is absent; the deployment API refuses to "
            "authenticate with a fallback secret."
        )
    return secret


def _internal_token() -> str:
    token = os.getenv("AGENT_INTERNAL_TOKEN", "").strip()
    if not token:
        raise DeploymentAuthenticationConfigError(
            "AGENT_INTERNAL_TOKEN is absent; the service-principal "
            "boundary is unavailable."
        )
    if len(token) < _MIN_INTERNAL_TOKEN_LENGTH:
        raise DeploymentAuthenticationConfigError(
            "AGENT_INTERNAL_TOKEN is too short to be a valid credential; "
            "refusing to treat a short token as authentication."
        )
    return token


def _http_503() -> HTTPException:
    # Static detail: the exception text can vary and must not be
    # reflected to callers (it could carry configuration detail).
    return HTTPException(
        status_code=503,
        detail="Deployment authentication is unavailable: configuration "
               "error. Refusing to fall back to any built-in credential.",
    )


# ---------------------------------------------------------------------------
# Core verification
# ---------------------------------------------------------------------------


def decode_and_validate_token(token: str) -> Identity:
    """Verify one bearer JWT under the process contract.

    Raises HTTPException(401) on any failure: malformed token, wrong
    algorithm, bad signature, expired token, missing required claims.
    Raises DeploymentAuthenticationConfigError (mapped to 503 by the
    dependency) when the process cannot authenticate at all.
    """
    secret = _jwt_secret()
    try:
        claims: Dict[str, Any] = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            options={"require": ["sub", "exp", "roles"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail="Invalid token: expired.") from exc
    except jwt.InvalidTokenError as exc:
        # Covers bad signature, wrong algorithm (incl. ``alg:none``),
        # malformed payload, missing required claims. Log without the
        # token material.
        logger.warning("Rejected invalid deployment JWT: %s", type(exc).__name__)
        raise HTTPException(
            status_code=401, detail="Invalid token signature or claims."
        ) from exc

    sub = claims.get("sub")
    roles = claims.get("roles")
    if not isinstance(sub, str) or not sub.strip():
        raise HTTPException(status_code=401, detail="Invalid token: empty subject.")
    if not isinstance(roles, list) or not roles:
        raise HTTPException(status_code=401, detail="Invalid token: missing roles claim.")
    return Identity(subject=sub.strip(), roles=tuple(str(r) for r in roles), kind="human")


def verify_service_token(provided: str) -> Identity:
    """Verify the internal service token (constant-time comparison)."""
    expected = _internal_token()
    if not provided or not hmac.compare_digest(provided.encode(), expected.encode()):
        raise HTTPException(
            status_code=401, detail="Not authenticated: invalid internal token."
        )
    return Identity(
        subject=SERVICE_PRINCIPAL, roles=(SERVICE_ROLE,), kind="service"
    )


def verify_caller(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
    internal_token: Optional[str] = None,
) -> Identity:
    """Authenticate ONE caller via bearer JWT or the internal token.

    Bearer JWT wins when present (a request must not mix the two
    mechanisms: a bearer token invalidates any internal-token claim,
    and vice versa).
    """
    has_bearer = credentials is not None and bool(credentials.credentials)
    has_internal = bool(internal_token)
    if has_bearer and has_internal:
        # Mixed mechanisms are a confused-deputy smell: authenticate
        # via the bearer JWT only (the internal token is ignored).
        return decode_and_validate_token(credentials.credentials)
    if has_bearer:
        return decode_and_validate_token(credentials.credentials)
    if has_internal:
        return verify_service_token(internal_token)
    raise HTTPException(
        status_code=401, detail="Not authenticated: bearer token missing."
    )


def _enforce(identity: Identity, *, operation: str, allow_service: bool) -> Identity:
    if identity.is_service and not allow_service:
        raise HTTPException(
            status_code=403,
            detail=f"Forbidden: the service principal may not {operation}.",
        )
    if not identity.is_service and not identity.is_operator:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: operator role required for this deployment operation.",
        )
    return identity


def require_dry_run_caller(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
    internal_token: Optional[str] = Header(None, alias="X-Internal-Token"),
) -> Identity:
    """Dry run: operator roles or the service principal."""
    identity = _require_authenticated(credentials, internal_token)
    return _enforce(identity, operation="create deployment dry runs", allow_service=True)


def require_read_caller(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
    internal_token: Optional[str] = Header(None, alias="X-Internal-Token"),
) -> Identity:
    """Run inspection: operator roles or the creating principal."""
    return _require_authenticated(credentials, internal_token)


def require_approver(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
    internal_token: Optional[str] = Header(None, alias="X-Internal-Token"),
) -> Identity:
    """Plan approval: HUMAN operator roles only — never the service
    principal, never caller-supplied identity."""
    identity = _require_authenticated(credentials, internal_token)
    return _enforce(identity, operation="approve a deployment plan", allow_service=False)


def require_dispatch_caller(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
    internal_token: Optional[str] = Header(None, alias="X-Internal-Token"),
) -> Identity:
    """Execution dispatch: operator roles or the service principal."""
    identity = _require_authenticated(credentials, internal_token)
    return _enforce(identity, operation="dispatch deployment execution", allow_service=True)


def _require_authenticated(
    credentials: Optional[HTTPAuthorizationCredentials], internal_token: Optional[str]
) -> Identity:
    try:
        return verify_caller(credentials, internal_token)
    except DeploymentAuthenticationConfigError:
        logger.error("Deployment auth configuration is invalid; failing closed.")
        raise _http_503() from None


def assert_run_visible(identity: Identity, created_by: Optional[str]) -> None:
    """Run-inspection visibility: operators see platform runs; the
    service principal and other humans see only runs they created.

    An unknown ``created_by`` (runs minted before this field existed)
    is treated as service-created: only the service principal and
    operators may read it — never an arbitrary human subject.
    """
    if identity.is_operator:
        return
    if identity.is_service:
        if created_by in (SERVICE_PRINCIPAL, None):
            return
        raise HTTPException(status_code=403, detail="Forbidden: run not visible to this principal.")
    if created_by == identity.subject:
        return
    raise HTTPException(status_code=403, detail="Forbidden: run not visible to this principal.")


# ---------------------------------------------------------------------------
# Startup validation (B.7)
# ---------------------------------------------------------------------------


def validate_execution_config() -> None:
    """Refuse to start in execution-enabled mode without the required
    auth configuration. Called from the application factory.

    Raises DeploymentAuthenticationConfigError with a static message.
    """
    if os.getenv("DEPLOYMENT_EXECUTION_ENABLED", "false").strip().lower() != "true":
        return
    # Execution mode requires BOTH credentials: dispatch may come from
    # the service principal and approval requires a verifiable human
    # JWT. Either missing ⇒ the process must not come up.
    _jwt_secret()
    _internal_token()


def create_access_token(
    subject: str, roles: List[str], secret: str, ttl_seconds: int = 3600
) -> str:
    """Issue an HS256 JWT signed with ``secret``.

    Used by trusted token mints (the E2E harness, tests, operator
    consoles) — the same helper the gateway uses, so one token format
    crosses the platform. The secret is never logged.
    """
    now = int(time.time())
    payload = {"sub": subject, "roles": list(roles), "iat": now, "exp": now + ttl_seconds}
    return jwt.encode(payload, secret, algorithm="HS256")
