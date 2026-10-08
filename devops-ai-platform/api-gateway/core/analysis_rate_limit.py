"""Route-specific rate limiting for the expensive analysis route (D1 P0-3).

Trust model
===========

* **Primary identity**: the authenticated JWT ``sub`` (already verified by
  ``require_analysis_role`` before this limiter runs).
* **Second dimension**: the source IP — used ONLY as the direct TCP peer
  (``request.client.host``).  Spoofable forwarded headers (``X-Forwarded-For``
  etc.) are NEVER read; behind a trusted proxy, deploy that proxy in front
  and let it terminate the connection (the peer is then the proxy).
* **Shared state**: the Redis ledger (atomic Lua script) makes the limit
  effective across multiple gateway replicas.  The in-process ledger is an
  EXPLICIT single-instance mode (documented, never a silent default in
  multi-replica deployments).
* **Fail closed**: if the shared (Redis) store is unreachable the endpoint
  returns a stable 503 — protection is never silently disabled for this
  expensive route.
* **Production posture** (Phase 8.7-D.1-CORRECTION): `APP_ENV=staging` /
  `APP_ENV=production` REQUIRE the shared Redis store; startup fails closed
  when a production-mode gateway would run the in-process limiter (whose
  limits multiply per replica). A documented single-replica deployment opts
  in EXPLICITLY via
  `ANALYSIS_RATE_LIMIT_SINGLE_INSTANCE_PRODUCTION=true` (exact value; it
  cannot be enabled by accident).

Semantics
=========

Fixed-window counters (atomic ``INCR``/``EXPIRE`` in one Lua invocation —
no GET-then-INCR race):

* per-identity limit: ``ANALYSIS_RATE_LIMIT_PER_IDENTITY_PER_MINUTE``
  (safe production default 30/min);
* per-source-IP limit: ``ANALYSIS_RATE_LIMIT_PER_IP_PER_MINUTE``
  (safe production default 120/min — a loose backstop so one IP cannot
  funnel unlimited identities).

A request is allowed only while BOTH counters are under their limits.
When limited, the route returns ``429`` with a ``Retry-After`` header set
to the window's remaining seconds.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Callable, Mapping, Optional, Protocol

logger = logging.getLogger("AnalysisRateLimiter")


class RateLimitStoreUnavailable(Exception):
    """The rate-limit store (Redis) is unreachable.  The caller must fail
    closed (503), never proceed unprotected."""


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: Optional[int] = None


class AnalysisRateLimiter(Protocol):
    def check(self, identity: str, source_ip: str) -> RateLimitDecision: ...

    def close(self) -> None: ...


# ---------------------------------------------------------------------------
# In-process ledger — EXPLICIT single-instance mode
# ---------------------------------------------------------------------------


class LocalAnalysisRateLimiter:
    """Lock-protected fixed-window counters for a SINGLE gateway process.

    Deployment contract: effective only per process.  A horizontally scaled
    gateway MUST use ``ANALYSIS_RATE_LIMIT_STORE=redis`` so all replicas
    share one counter; this mode is for single-instance deployments and
    tests, and it says so loudly at construction.
    """

    def __init__(
        self,
        limit_per_identity_per_minute: int,
        limit_per_ip_per_minute: int,
        window_seconds: int = 60,
        time_fn: Callable[[], float] = time.time,
    ):
        self.limit_identity = max(1, int(limit_per_identity_per_minute))
        self.limit_ip = max(1, int(limit_per_ip_per_minute))
        self.window_seconds = max(1, int(window_seconds))
        self._time_fn = time_fn
        self._lock = threading.Lock()
        self._identity_counts: dict[str, tuple[float, int]] = {}
        self._ip_counts: dict[str, tuple[float, int]] = {}
        logger.warning(
            "[RATE_LIMIT] In-process analysis rate limiter active (SINGLE "
            "INSTANCE contract): per-identity=%d/min, per-IP=%d/min. "
            "Multi-replica deployments must use ANALYSIS_RATE_LIMIT_STORE=redis.",
            self.limit_identity, self.limit_ip,
        )

    def _bucket(self, store: dict, key: str, limit: int) -> tuple[int, int]:
        """Return (count, remaining_seconds); increments atomically under
        the shared lock (fixed window)."""
        now = self._time_fn()
        start, count = store.get(key, (0.0, 0))
        if now - start >= self.window_seconds:
            start, count = now, 0
        count += 1
        store[key] = (start, count)
        remaining = max(0, int(self.window_seconds - (now - start)))
        return count, remaining

    def check(self, identity: str, source_ip: str) -> RateLimitDecision:
        if not identity or not identity.strip():
            # Malformed/absent identity: fail closed (never allow anonymous
            # analysis, never key on an untrusted value).
            raise RateLimitStoreUnavailable(
                "Analysis rate limiting requires a valid authenticated identity."
            )
        with self._lock:
            id_count, id_remaining = self._bucket(self._identity_counts, identity, self.limit_identity)
            ip_count, ip_remaining = self._bucket(self._ip_counts, source_ip or "unknown", self.limit_ip)
        if id_count > self.limit_identity:
            return RateLimitDecision(allowed=False, retry_after_seconds=max(1, id_remaining))
        if ip_count > self.limit_ip:
            return RateLimitDecision(allowed=False, retry_after_seconds=max(1, ip_remaining))
        return RateLimitDecision(allowed=True)

    def close(self) -> None:
        with self._lock:
            self._identity_counts.clear()
            self._ip_counts.clear()


# ---------------------------------------------------------------------------
# Redis ledger — shared across replicas (atomic Lua)
# ---------------------------------------------------------------------------

_CHECK_LUA = """
local id_key = KEYS[1]
local ip_key = KEYS[2]
local id_limit = tonumber(ARGV[1])
local ip_limit = tonumber(ARGV[2])
local window = tonumber(ARGV[3])
local id_count = tonumber(redis.call('GET', id_key) or '0')
local ip_count = tonumber(redis.call('GET', ip_key) or '0')
if id_count >= id_limit or ip_count >= ip_limit then
  local id_ttl = redis.call('TTL', id_key)
  local ip_ttl = redis.call('TTL', ip_key)
  local ttl = id_ttl > ip_ttl and id_ttl or ip_ttl
  if ttl < 0 then ttl = window end
  return {0, ttl}
end
id_count = redis.call('INCR', id_key)
ip_count = redis.call('INCR', ip_key)
if id_count == 1 then redis.call('EXPIRE', id_key, window) end
if ip_count == 1 then redis.call('EXPIRE', ip_key, window) end
return {1, 0}
"""


class RedisAnalysisRateLimiter:
    """Shared fixed-window rate limiter (atomic Redis Lua script).

    One script invocation checks AND increments both counters, so concurrent
    replicas cannot bypass the limit.  Any Redis failure raises
    ``RateLimitStoreUnavailable`` — the route maps that to a fail-closed
    503 (protection is never silently disabled).
    """

    def __init__(
        self,
        redis_url: str,
        limit_per_identity_per_minute: int,
        limit_per_ip_per_minute: int,
        window_seconds: int = 60,
        key_prefix: str = "devops:analysis:ratelimit",
    ):
        try:
            import redis  # noqa: F401
        except ImportError as exc:  # pragma: no cover - environment guard
            raise RateLimitStoreUnavailable(
                "The 'redis' package is required for ANALYSIS_RATE_LIMIT_STORE=redis."
            ) from exc
        self.limit_identity = max(1, int(limit_per_identity_per_minute))
        self.limit_ip = max(1, int(limit_per_ip_per_minute))
        self.window_seconds = max(1, int(window_seconds))
        self._key_prefix = key_prefix
        self._client = redis.Redis.from_url(
            redis_url, socket_connect_timeout=2, socket_timeout=2
        )
        self._script = self._client.register_script(_CHECK_LUA)

    def check(self, identity: str, source_ip: str) -> RateLimitDecision:
        if not identity or not identity.strip():
            raise RateLimitStoreUnavailable(
                "Analysis rate limiting requires a valid authenticated identity."
            )
        id_key = f"{self._key_prefix}:identity:{identity}"
        ip_key = f"{self._key_prefix}:ip:{source_ip or 'unknown'}"
        try:
            allowed, ttl = self._script(
                keys=[id_key, ip_key],
                args=[
                    str(self.limit_identity),
                    str(self.limit_ip),
                    str(self.window_seconds),
                ],
            )
        except RateLimitStoreUnavailable:
            raise
        except Exception as exc:
            raise RateLimitStoreUnavailable(
                "The shared rate-limit store (Redis) is unreachable."
            ) from exc
        if not allowed:
            return RateLimitDecision(
                allowed=False, retry_after_seconds=max(1, int(ttl or self.window_seconds))
            )
        return RateLimitDecision(allowed=True)

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # pragma: no cover - best effort
            pass


# ---------------------------------------------------------------------------
# Configuration + factory
# ---------------------------------------------------------------------------

DEFAULT_LIMIT_PER_IDENTITY_PER_MINUTE = 30
DEFAULT_LIMIT_PER_IP_PER_MINUTE = 120

# Environments that MUST run the shared (Redis) limiter: with a per-process
# limiter, N replicas would each allow their own quota and the effective
# limit would silently multiply by the replica count.
_PRODUCTION_ENVS = frozenset({"staging", "production"})
# Explicit, accidental-usage-proof opt-out for a DOCUMENTED single-replica
# staging/production deployment: must be exactly "true".
_SINGLE_INSTANCE_FLAG = "ANALYSIS_RATE_LIMIT_SINGLE_INSTANCE_PRODUCTION"


class AnalysisRateLimitConfigurationError(RuntimeError):
    """The rate-limit configuration is invalid (fail closed)."""


def load_analysis_rate_limit_settings(env: Optional[Mapping[str, str]] = None) -> dict:
    e: Mapping[str, str] = os.environ if env is None else env

    def _int(name: str, default: int) -> int:
        raw = (e.get(name) or "").strip()
        if not raw:
            return default
        value = int(raw)
        if value < 1:
            raise AnalysisRateLimitConfigurationError(f"{name} must be >= 1.")
        return value

    store = (e.get("ANALYSIS_RATE_LIMIT_STORE") or "").strip().lower()
    redis_url = (e.get("REDIS_URL") or "").strip()

    if store == "local":
        effective = "local"
    elif store == "redis":
        if not redis_url:
            raise AnalysisRateLimitConfigurationError(
                "ANALYSIS_RATE_LIMIT_STORE=redis requires REDIS_URL to be set."
            )
        effective = "redis"
    elif store:
        raise AnalysisRateLimitConfigurationError(
            "ANALYSIS_RATE_LIMIT_STORE must be 'local' or 'redis'."
        )
    else:
        # Default: shared (redis) when a redis URL is configured; otherwise
        # the explicit single-instance mode (documented, logged).
        effective = "redis" if redis_url else "local"

    # Phase 8.7-D.1-CORRECTION: staging/production MUST use the shared
    # store. Failing closed here (at startup) instead of silently running
    # an in-process limiter whose limits multiply per replica.
    app_env = (e.get("APP_ENV") or "").strip().lower()
    if (
        effective == "local"
        and app_env in _PRODUCTION_ENVS
        and (e.get(_SINGLE_INSTANCE_FLAG) or "").strip() != "true"
    ):
        raise AnalysisRateLimitConfigurationError(
            f"APP_ENV={app_env} requires the shared Redis analysis rate-limit "
            f"store (ANALYSIS_RATE_LIMIT_STORE=redis + REDIS_URL): the "
            f"in-process limiter is single-instance and its limits multiply "
            f"across replicas. For a documented single-replica deployment set "
            f"{_SINGLE_INSTANCE_FLAG}=true explicitly."
        )

    return {
        "store": effective,
        "redis_url": redis_url or None,
        "limit_per_identity_per_minute": _int(
            "ANALYSIS_RATE_LIMIT_PER_IDENTITY_PER_MINUTE",
            DEFAULT_LIMIT_PER_IDENTITY_PER_MINUTE,
        ),
        "limit_per_ip_per_minute": _int(
            "ANALYSIS_RATE_LIMIT_PER_IP_PER_MINUTE",
            DEFAULT_LIMIT_PER_IP_PER_MINUTE,
        ),
        "window_seconds": _int("ANALYSIS_RATE_LIMIT_WINDOW_SECONDS", 60),
    }


def build_analysis_rate_limiter(
    env: Optional[Mapping[str, str]] = None,
) -> AnalysisRateLimiter:
    """Construct the limiter selected by the environment configuration."""
    settings = load_analysis_rate_limit_settings(env)
    if settings["store"] == "redis":
        return RedisAnalysisRateLimiter(
            redis_url=settings["redis_url"],
            limit_per_identity_per_minute=settings["limit_per_identity_per_minute"],
            limit_per_ip_per_minute=settings["limit_per_ip_per_minute"],
            window_seconds=settings["window_seconds"],
        )
    return LocalAnalysisRateLimiter(
        limit_per_identity_per_minute=settings["limit_per_identity_per_minute"],
        limit_per_ip_per_minute=settings["limit_per_ip_per_minute"],
        window_seconds=settings["window_seconds"],
    )
