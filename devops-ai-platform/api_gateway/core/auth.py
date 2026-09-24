"""
Real HS256 JWT authentication for the operator platform gateway.

The previous implementation accepted ANY token of length >= 10 as a valid
identity (and a hardcoded literal as admin) — authorization was an illusion.
This module verifies proper signed tokens instead:

* tokens are signed with the `JWT_SECRET` environment variable (the secret
  that was declared in config but never actually used);
* tokens carry `sub`, `roles`, `iat` and `exp` claims;
* expired or badly signed tokens are rejected with 401.

Dev workflow: mint a token with

    python -m api_gateway.core.auth <subject> [Role1 Role2 ...]

and pass it as `Authorization: Bearer <token>`.

Only stdlib crypto (hmac/hashlib/base64/json) is used — no extra dependency.
"""

import base64
import hashlib
import hmac
import json
import logging
import sys
import time

from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..config import GatewaySettings

logger = logging.getLogger("GatewayAuth")

security_bearer = HTTPBearer()

_TOKEN_TTL_SECONDS = 3600


# ---------------------------------------------------------------------------
# HS256 primitives (stdlib only)
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _sign(header_b64: str, payload_b64: str, secret: str) -> str:
    digest = hmac.new(
        secret.encode("utf-8"),
        f"{header_b64}.{payload_b64}".encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return _b64url_encode(digest)


def mint_token(
    subject: str,
    roles: list[str] | None = None,
    secret: str | None = None,
    ttl_seconds: int = _TOKEN_TTL_SECONDS,
) -> str:
    """Create a signed HS256 JWT. Used by the dev CLI and by tests."""
    secret = secret or GatewaySettings.JWT_SECRET
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": subject,
        "roles": roles or ["Developer"],
        "iat": now,
        "exp": now + ttl_seconds,
    }
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{h}.{p}.{_sign(h, p, secret)}"


def decode_and_verify(token: str, secret: str) -> dict:
    """Verify signature + expiry. Raises ValueError on any failure."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed token structure")
    header_b64, payload_b64, signature = parts

    expected = _sign(header_b64, payload_b64, secret)
    if not hmac.compare_digest(signature, expected):
        raise ValueError("token signature verification failed")

    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except (ValueError, TypeError) as exc:
        raise ValueError("token payload is not valid JSON") from exc

    if int(payload.get("exp", 0)) < int(time.time()):
        raise ValueError("token expired")
    return payload


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------

def verify_token(
    credentials: HTTPAuthorizationCredentials = Security(security_bearer),
) -> dict:
    """Verifies the incoming JWT signature and returns the identity claims."""
    token = credentials.credentials
    try:
        payload = decode_and_verify(token, GatewaySettings.JWT_SECRET)
    except ValueError as exc:
        logger.warning("JWT rejected: %s", exc)
        raise HTTPException(status_code=401, detail="Invalid or expired token signature")
    return {"sub": payload.get("sub", "unknown"), "roles": payload.get("roles", [])}


# ---------------------------------------------------------------------------
# Bounded sliding-window rate limiter
# ---------------------------------------------------------------------------

class GatewayRateLimiter:
    """Sliding-window in-memory rate limiter safeguarding downstream services.

    The history dict is pruned once it exceeds `_MAX_TRACKED_CLIENTS` so a
    flood of distinct client IPs cannot grow it without bound.
    """

    _MAX_TRACKED_CLIENTS = 10_000
    _WINDOW_SECONDS = 60

    def __init__(self):
        self.history: dict[str, list[float]] = {}

    def _prune_stale(self, now: float) -> None:
        if len(self.history) <= self._MAX_TRACKED_CLIENTS:
            return
        stale = [
            ip
            for ip, requests in self.history.items()
            if not requests or now - requests[-1] > self._WINDOW_SECONDS
        ]
        for ip in stale:
            del self.history[ip]

    def is_rate_limited(self, client_ip: str) -> bool:
        now = time.time()
        self._prune_stale(now)

        requests = [
            t for t in self.history.get(client_ip, [])
            if now - t < self._WINDOW_SECONDS
        ]
        self.history[client_ip] = requests

        if len(requests) >= GatewaySettings.RATE_LIMIT_MAX_REQUESTS:
            return True

        requests.append(now)
        return False


if __name__ == "__main__":
    # Dev token minter:
    #   python -m api_gateway.core.auth devops-operator DevOpsLead ClusterAdmin
    if len(sys.argv) < 2:
        print("usage: python -m api_gateway.core.auth <subject> [Role1 Role2 ...]")
        print(f"example: python -m api_gateway.core.auth devops-operator DevOpsLead")
        sys.exit(1)
    subject = sys.argv[1]
    roles = sys.argv[2:] or ["Developer"]
    if not GatewaySettings.JWT_SECRET:
        print("error: JWT_SECRET is not set", file=sys.stderr)
        sys.exit(1)
    print(mint_token(subject, roles))
