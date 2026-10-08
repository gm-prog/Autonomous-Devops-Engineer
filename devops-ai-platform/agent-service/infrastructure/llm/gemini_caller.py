"""Server-side Gemini provider client (Phase 8.7-D hardened, Phase 8.7-D.1).

Security / resilience contract
==============================

* **Single configuration source**: every tunable (model, budget, pricing,
  token bounds, retries, store selection) comes from ``GeminiRuntimeConfig``
  (environment-backed).  The historical split defaults between
  ``GeminiBudgetService`` and the adapter are removed — there is exactly one
  default per setting, defined once below (D1 P0-1).
* **Fail closed**: when ``GEMINI_API_KEY`` is absent from the server
  environment, every generation call RAISES ``GeminiServiceUnavailableException``.
  There is no simulator fallback and no fake "success" that pretends Gemini
  answered.
* **Credential handling**: the key is read only from the server environment
  (``GEMINI_API_KEY``) and is sent exclusively via the ``x-goog-api-key``
  header — never in the URL — so it cannot leak into exception text, logs,
  or access traces.
* **Bounded + structured provider contract** (D1 P0-6):
  - the model is the currently supported stable ``gemini-3.8-flash``
    (overridable via ``GEMINI_MODEL``); the deprecated ``gemini-3.5-flash``
    is no longer the default;
  - an explicit ``maxOutputTokens`` bound gives the application a real
    provider-side output ceiling (not only post-response character checks);
  - ``responseMimeType: "application/json"`` + a strict ``responseSchema``
    request the structured five-field payload (defense in depth — the
    application's strict parse remains the authority);
  - bounded request timeout, bounded retries with exponential backoff,
    retries only for transient failures (429/5xx/timeout/connection);
    provider auth failures (401/403) and malformed responses fail fast.
* **Concurrency-safe AI budget** (D1 P0-2): before contacting the provider
  the caller atomically RESERVES a conservative worst-case cost (bounded
  output tokens x attempts); if the reservation would exceed the monthly
  ceiling the call is rejected BEFORE any provider contact.  After the
  response the actual cost from ``usageMetadata`` reconciles the
  reservation; missing usage metadata keeps the full reservation
  (never undercount).  Reservations are atomic per ledger: the in-process
  ledger is lock-protected (single-process contract), the Redis ledger
  uses atomic Lua scripts (shared across replicas).  This is an
  **application safety budget**, not a Google billing hard cap — Google
  project/account spend controls are separate and documented in
  SECURITY.md.
* **Circuit breaker**: after a threshold of consecutive failures the
  circuit opens and calls fail fast until the cooldown elapses (half-open
  probe).  State lives on the shared application-lifetime adapter (see
  ``main.create_app``), never per request.
* **Structured extraction**: a 200 response that is not well-formed
  (missing candidates / parts / text) raises ``GeminiMalformedResponseException``.

Error taxonomy (callers may branch on these precisely):

* ``GeminiAuthException``                — provider rejected credentials (401/403).
* ``GeminiRateLimitException``           — upstream rate limit (429) after retries.
* ``GeminiTimeoutException``             — upstream did not answer in time.
* ``GeminiUpstreamException``            — upstream 5xx / network failure.
* ``GeminiMalformedResponseException``   — 200 response without usable content.
* ``GeminiServiceUnavailableException``  — missing key (fail closed), circuit open.
* ``BudgetExceededException``            — application AI budget ceiling reached.
* ``BudgetStoreUnavailableException``    — the shared budget store (Redis) is
                                           unreachable; the call is blocked
                                           (fail closed, never free of limits).
"""

from __future__ import annotations

import json
import logging
import os
import time
import threading
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Mapping, Optional, Protocol

import requests

from ...domain.analysis_payload import (
    ANALYSIS_ASSET_FIELDS,
    MalformedAnalysisResponseError,
    parse_strict_asset_payload,
)
from ...domain.remote_llm_interface import RemoteLLMInterface

logger = logging.getLogger("GeminiCallerAdapter")


# ---------------------------------------------------------------------------
# Resilience exceptions (typed; no credential material in any message)
# ---------------------------------------------------------------------------


class GeminiServiceUnavailableException(Exception):
    """Fail-closed: provider cannot/should not be called (missing key,
    circuit open, infrastructure unavailable)."""


class GeminiRateLimitException(Exception):
    """Upstream rate limit persisted beyond the bounded retry budget."""


class GeminiAuthException(Exception):
    """The provider rejected the server-side credential (401/403)."""


class GeminiTimeoutException(Exception):
    """The provider did not answer within the bounded timeout."""


class GeminiUpstreamException(Exception):
    """Upstream provider failure (5xx or network-level error)."""


class GeminiMalformedResponseException(Exception):
    """The provider answered 200 but the payload is not usable content."""


class BudgetExceededException(Exception):
    """The application AI budget ceiling has been reached; calls are blocked.

    This is an application-level safety budget, NOT a Google billing hard
    cap (Google project/account spend controls are separate).
    """


class BudgetStoreUnavailableException(Exception):
    """The shared budget store is unreachable; the call is blocked rather
    than proceeding without a spend limit (fail closed)."""


# ---------------------------------------------------------------------------
# Runtime configuration — the SINGLE source of defaults (D1 P0-1)
# ---------------------------------------------------------------------------

# Model selection (D1 P0-6): ``gemini-3.8-flash`` is the newest stable 3.x
# Flash model in Google's Gemini API documentation — released 2026-09-02,
# "no shutdown date announced", and the recommended replacement for several
# scheduled-for-shutdown models.  Source (accessed 2026-10-08):
#   https://ai.google.dev/gemini-api/docs/deprecations
#   https://ai.google.dev/gemini-api/docs/models/gemini-3.8-flash
# The previously used ``gemini-3.5-flash`` is retired from the default.
DEFAULT_GEMINI_MODEL = "gemini-3.8-flash"

# Pricing for the safety budget, per 1M tokens in USD, for
# ``gemini-3.8-flash`` Standard (paid tier), source (accessed 2026-10-08):
#   https://ai.google.dev/gemini-api/docs/pricing
#   input  $0.75 through 2026-12-31, then $1.50 from 2027-01-01
#   output $3.75 through 2026-12-31, then $7.50 from 2027-01-01
# The defaults below use the POST-promo (permanent) rates: a safety budget
# must err on the conservative side — overestimating cost blocks earlier,
# underestimating it would allow real overspend.
DEFAULT_INPUT_COST_PER_MILLION = 1.50
DEFAULT_OUTPUT_COST_PER_MILLION = 7.50

# Application safety budget ceiling (USD) per UTC calendar month.
DEFAULT_MONTHLY_BUDGET_USD = 150.0

# Provider-side output ceiling (tokens).  Also the bounded maximum output
# allowance used for budget reservations (D1 P0-2).
DEFAULT_MAX_OUTPUT_TOKENS = 16_384

# Conservative input estimate (tokens) used for reservations.
DEFAULT_ESTIMATED_PROMPT_TOKENS = 220

# Tolerance for float accounting comparisons (USD).
_FLOAT_EPS = 1e-9

# Phase 8.7-D.1-CORRECTION-2 (P1-B): the ONLY APP_ENV values that may use
# the in-process (single-process) budget ledger.  Every other value —
# staging, production, empty, missing, or unexpected — is treated as
# NON-DEVELOPMENT and requires the shared Redis ledger (fail closed),
# mirroring the gateway's analysis-rate-limit classification exactly.
_LOCAL_STATE_ENVS = frozenset({"development", "test"})


@dataclass(frozen=True)
class GeminiRuntimeConfig:
    """All Gemini runtime tunables in one immutable configuration.

    Every environment variable maps to exactly one field; every field has
    exactly one default.  There is no second place where a default can
    disagree (the D1 P0-1 defect: 100.0 vs 150.0 budget defaults).
    """

    model_name: str = DEFAULT_GEMINI_MODEL
    monthly_budget_usd: float = DEFAULT_MONTHLY_BUDGET_USD
    input_cost_per_million: float = DEFAULT_INPUT_COST_PER_MILLION
    output_cost_per_million: float = DEFAULT_OUTPUT_COST_PER_MILLION
    max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS
    estimated_prompt_tokens: int = DEFAULT_ESTIMATED_PROMPT_TOKENS
    timeout_seconds: float = 20.0
    max_retries: int = 3
    backoff_base_seconds: float = 0.5
    # "local" = in-process ledger (single-process deployment contract);
    # "redis" = shared ledger across replicas (requires redis_url).
    budget_store: str = "local"
    redis_url: Optional[str] = None

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "GeminiRuntimeConfig":
        e: Mapping[str, str] = os.environ if env is None else env

        def _float(name: str, default: float) -> float:
            raw = (e.get(name) or "").strip()
            if not raw:
                return default
            value = float(raw)
            if value < 0:
                raise ValueError(f"{name} must be >= 0 (got {raw!r}).")
            return value

        def _int(name: str, default: int) -> int:
            raw = (e.get(name) or "").strip()
            if not raw:
                return default
            value = int(raw)
            if value < 1:
                raise ValueError(f"{name} must be >= 1 (got {raw!r}).")
            return value

        store = (e.get("GEMINI_BUDGET_STORE") or "local").strip().lower()
        if store not in ("local", "redis"):
            raise ValueError(
                f"GEMINI_BUDGET_STORE must be 'local' or 'redis' (got {store!r})."
            )
        redis_url = (e.get("REDIS_URL") or "").strip() or None
        if store == "redis" and not redis_url:
            raise ValueError(
                "GEMINI_BUDGET_STORE=redis requires REDIS_URL to be set."
            )
        # Phase 8.7-D.1-CORRECTION (extended by 8.7-D.1-CORRECTION-2, P1-B):
        # the in-process budget ledger may only be used in the explicitly
        # recognized development environments (development/test).  staging,
        # production, an EMPTY APP_ENV, a MISSING APP_ENV, and any
        # UNEXPECTED value are all treated as NON-DEVELOPMENT: with N agent
        # replicas an in-process ledger silently multiplies the effective
        # budget by N, so startup fails closed unless a documented
        # single-replica deployment opts in EXPLICITLY (exact value, not
        # accidental).
        app_env = (e.get("APP_ENV") or "").strip().lower()
        if (
            store == "local"
            and app_env not in _LOCAL_STATE_ENVS
            and (e.get("GEMINI_BUDGET_SINGLE_INSTANCE_PRODUCTION") or "").strip()
            != "true"
        ):
            raise ValueError(
                f"APP_ENV={app_env!r} is not a recognized development "
                f"environment ({sorted(_LOCAL_STATE_ENVS)}); it requires the "
                f"shared Redis budget ledger (GEMINI_BUDGET_STORE=redis + "
                f"REDIS_URL): the in-process ledger is single-process and "
                f"the effective budget multiplies across replicas. Empty, "
                f"missing, or unexpected APP_ENV values are deliberately "
                f"treated as non-development (fail closed). For a documented "
                f"single-replica deployment set "
                f"GEMINI_BUDGET_SINGLE_INSTANCE_PRODUCTION=true explicitly."
            )

        return cls(
            model_name=(e.get("GEMINI_MODEL") or "").strip() or DEFAULT_GEMINI_MODEL,
            monthly_budget_usd=_float("GEMINI_MONTHLY_BUDGET_USD", DEFAULT_MONTHLY_BUDGET_USD),
            input_cost_per_million=_float(
                "GEMINI_INPUT_COST_PER_MILLION_USD", DEFAULT_INPUT_COST_PER_MILLION
            ),
            output_cost_per_million=_float(
                "GEMINI_OUTPUT_COST_PER_MILLION_USD", DEFAULT_OUTPUT_COST_PER_MILLION
            ),
            max_output_tokens=_int("GEMINI_MAX_OUTPUT_TOKENS", DEFAULT_MAX_OUTPUT_TOKENS),
            estimated_prompt_tokens=_int(
                "GEMINI_ESTIMATED_PROMPT_TOKENS", DEFAULT_ESTIMATED_PROMPT_TOKENS
            ),
            timeout_seconds=_float("GEMINI_TIMEOUT_SECONDS", 20.0),
            max_retries=_int("GEMINI_MAX_RETRIES", 3),
            backoff_base_seconds=_float("GEMINI_BACKOFF_BASE_SECONDS", 0.5),
            budget_store=store,
            redis_url=redis_url,
        )


# ---------------------------------------------------------------------------
# Budget ledger — atomic reservation model (D1 P0-2)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BudgetReservation:
    """An atomic, conservative reservation against the monthly ceiling."""

    reservation_id: str
    period_key: str  # UTC calendar month, e.g. "2026-10"
    reserved_usd: float


def utc_period_key(now: datetime) -> str:
    """Explicit accounting period: UTC calendar month (YYYY-MM)."""
    return now.strftime("%Y-%m")


class BudgetLedger(Protocol):
    """Concurrency-safe monthly safety budget.

    ``reserve`` atomically commits a worst-case amount BEFORE provider
    contact and raises ``BudgetExceededException`` when the ceiling would
    be exceeded; ``finalize`` reconciles the actual cost afterwards.

    Finalization is IDEMPOTENT while the finalization claim is retained:
    each reservation is accounted for at most once for as long as its
    claim is held.  ``finalize`` returns ``True`` when this call applied
    the accounting and ``False`` when the reservation was already
    finalized within the retention window (duplicate / retried call —
    the accounting is unchanged).  On the shared store the claim is a
    Redis claim key with a 45-day TTL — longer than one UTC calendar
    billing period — so it outlives every period the reservation can
    belong to and holds across replicas; after expiry a redelivered
    finalize can at most touch the already-expired period's counters,
    never the current period's budget.  The in-process ledger retains
    its claims for the process lifetime.
    """

    def reserve(self, max_cost_usd: float) -> BudgetReservation: ...

    def finalize(
        self, reservation: BudgetReservation, actual_cost_usd: Optional[float]
    ) -> bool: ...

    @property
    def accumulated_spend(self) -> float: ...


class InProcessBudgetLedger:
    """Lock-protected calendar-month budget for a SINGLE process.

    Deployment contract: with ``budget_store="local"`` the ceiling is
    per-process; running multiple agent replicas without a shared store
    multiplies the effective budget by the replica count.  Use
    ``GEMINI_BUDGET_STORE=redis`` (with ``REDIS_URL``) for a ceiling that
    is shared across replicas.  This is documented, not hidden: the
    configuration rejects an ambiguous "global" assumption.
    """

    # How long the current period's keys/states may outlive the period.
    def __init__(
        self,
        monthly_budget_usd: float,
        input_cost_per_million: float,
        output_cost_per_million: float,
        now_fn: Optional[Callable[[], datetime]] = None,
    ):
        self.monthly_budget = float(monthly_budget_usd)
        self.input_cost_per_million = float(input_cost_per_million)
        self.output_cost_per_million = float(output_cost_per_million)
        self._now_fn = now_fn or (lambda: datetime.now(timezone.utc))
        self._lock = threading.Lock()
        self._period_key = utc_period_key(self._now_fn())
        self._committed = 0.0
        self._reserved = 0.0
        # Exactly-once finalization claim.  For the SINGLE-process ledger a
        # process-local claim set is the correct mechanism (there is only
        # one process); the shared Redis ledger uses a Redis claim key
        # instead (see RedisBudgetLedger).
        self._finalized_ids: set[str] = set()

    # -- period handling ---------------------------------------------------

    def _roll_period_if_needed(self) -> None:
        current = utc_period_key(self._now_fn())
        if current != self._period_key:
            logger.info(
                "[COST_MONITORING] Budget period rolled %s -> %s; spend "
                "counters reset.", self._period_key, current,
            )
            self._period_key = current
            self._committed = 0.0
            self._reserved = 0.0

    def _cost_usd(self, prompt_tokens: int, completion_tokens: int) -> float:
        return (
            prompt_tokens * self.input_cost_per_million
            + completion_tokens * self.output_cost_per_million
        ) / 1_000_000

    # -- BudgetLedger --------------------------------------------------------

    def reserve(self, max_cost_usd: float) -> BudgetReservation:
        """Atomically reserve a worst-case cost against the ceiling.

        Raises ``BudgetExceededException`` when committed + reserved +
        ``max_cost_usd`` would exceed the monthly ceiling — the rejection
        happens BEFORE any provider contact.
        """
        if max_cost_usd <= 0:
            raise ValueError("max_cost_usd must be positive.")
        with self._lock:
            self._roll_period_if_needed()
            if self._committed + self._reserved + max_cost_usd > self.monthly_budget + _FLOAT_EPS:
                logger.warning(
                    "[COST_MONITORING] Budget reservation of $%.6f rejected: "
                    "ceiling $%.2f (committed $%.6f, reserved $%.6f).",
                    max_cost_usd, self.monthly_budget, self._committed, self._reserved,
                )
                raise BudgetExceededException(
                    "Application AI budget ceiling reached; the call was "
                    "blocked before contacting the provider."
                )
            self._reserved += max_cost_usd
            return BudgetReservation(
                reservation_id=str(uuid.uuid4()),
                period_key=self._period_key,
                reserved_usd=float(max_cost_usd),
            )

    def finalize(
        self, reservation: BudgetReservation, actual_cost_usd: Optional[float]
    ) -> bool:
        """Reconcile a reservation with the actual cost (exactly once for
        the process lifetime).

        * actual present  -> committed += actual (the reservation is
          released; the actual — never an estimate — is what counts);
        * actual missing  -> the FULL reservation counts (conservative:
          never undercount);
        * period rolled while in flight -> the reservation is void against
          the new period; the actual (if any) is counted against the
          current period so spend is never lost;
        * duplicate finalize -> ignored (returns False, accounting
          unchanged) — the claim is held in this process's memory for the
          process lifetime, which is the correct mechanism for a
          single-process ledger.
        """
        with self._lock:
            if reservation.reservation_id in self._finalized_ids:
                logger.info(
                    "[COST_MONITORING] Duplicate finalization of reservation "
                    "%s ignored (exactly-once claim); accounting unchanged.",
                    reservation.reservation_id,
                )
                return False
            self._finalized_ids.add(reservation.reservation_id)
            self._roll_period_if_needed()
            if reservation.period_key == self._period_key:
                self._reserved = max(0.0, self._reserved - reservation.reserved_usd)
                counted = (
                    reservation.reserved_usd
                    if actual_cost_usd is None
                    else float(actual_cost_usd)
                )
                self._committed += counted
            elif actual_cost_usd is not None:
                self._committed += float(actual_cost_usd)
            logger.info(
                "[COST_MONITORING] Finalized reservation %s: counted $%.6f. "
                "Committed $%.6f / ceiling $%.2f (period %s).",
                reservation.reservation_id,
                self._committed if reservation.period_key == self._period_key else 0.0,
                self._committed, self.monthly_budget, self._period_key,
            )
            return True

    @property
    def accumulated_spend(self) -> float:
        """Committed spend for the current period (finalized calls only)."""
        with self._lock:
            self._roll_period_if_needed()
            return self._committed


class RedisBudgetLedger:
    """Shared calendar-month budget backed by Redis (atomic Lua scripts).

    Keys are period-scoped (``devops:gemini:budget:{period}:committed`` /
    ``:reserved``): a new UTC month naturally starts from zero.  The
    reserve and finalize operations are single atomic Redis script
    invocations, so concurrent replicas cannot double-spend the same
    remaining budget.

    Finalization is EXACTLY ONCE WHILE THE CLAIM IS RETAINED (Phase
    8.7-D.1-CORRECTION; retention stated explicitly in Phase
    8.7-D.1-CORRECTION-2): each reservation has a period-scoped claim key
    (``…:{period}:finalized:{reservation_id}``) with a 45-day TTL — longer
    than one UTC calendar billing period — and the atomic finalize script
    checks-and-sets it, so a duplicate or concurrent finalize of the same
    reservation within the retention window is ignored instead of
    double-releasing the reservation or double-committing the cost.  The
    claim outlives every period the reservation can belong to; after
    expiry a redelivered finalize can at most touch the already-expired
    period's counters, never the current period's budget.  The
    reservation is released with a negative ``INCRBYFLOAT`` (Redis has no
    DECRBYFLOAT command).
    """

    _RESERVE_LUA = """
local committed_key = KEYS[1]
local reserved_key = KEYS[2]
local ceiling = tonumber(ARGV[1])
local amount = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local committed = tonumber(redis.call('GET', committed_key) or '0')
local reserved = tonumber(redis.call('GET', reserved_key) or '0')
if committed + reserved + amount > ceiling + 0.000000001 then
  return 0
end
redis.call('INCRBYFLOAT', reserved_key, amount)
redis.call('EXPIRE', reserved_key, ttl)
return 1
"""

    # Exactly-once finalization (Phase 8.7-D.1-CORRECTION).
    #
    # * The reservation is released with a NEGATIVE INCRBYFLOAT — Redis has
    #   no DECRBYFLOAT command; INCRBYFLOAT with a negative delta is the
    #   supported floating-point decrement primitive.
    # * KEYS[3] is a per-reservation claim key (period-scoped, TTL-bounded).
    #   Redis executes the WHOLE script atomically, so the EXISTS-check +
    #   SET claim is an atomic claim: of N duplicate or concurrent
    #   finalizations of the same reservation_id, exactly ONE acquires the
    #   claim and mutates the accounting; the rest return 0 and change
    #   nothing. This is safe across replicas (the claim lives in Redis,
    #   never in process memory).
    _FINALIZE_LUA = """
local committed_key = KEYS[1]
local reserved_key = KEYS[2]
local claim_key = KEYS[3]
local reserved_amount = tonumber(ARGV[1])
local actual = ARGV[2]
local ttl = tonumber(ARGV[3])
if redis.call('EXISTS', claim_key) == 1 then
  return 0
end
redis.call('SET', claim_key, '1', 'EX', ttl)
redis.call('INCRBYFLOAT', reserved_key, -reserved_amount)
local remaining = tonumber(redis.call('GET', reserved_key) or '0')
if remaining < 0 then
  redis.call('SET', reserved_key, '0')
else
  redis.call('EXPIRE', reserved_key, ttl)
end
if actual == '' then
  actual = tostring(reserved_amount)
end
redis.call('INCRBYFLOAT', committed_key, actual)
redis.call('EXPIRE', committed_key, ttl)
return 1
"""

    # Period keys are cleaned up well after the month ends.
    _KEY_TTL_SECONDS = 45 * 24 * 3600
    _KEY_PREFIX = "devops:gemini:budget"

    def __init__(self, monthly_budget_usd: float, redis_url: str):
        try:
            import redis  # noqa: F401
        except ImportError as exc:  # pragma: no cover - environment guard
            raise BudgetStoreUnavailableException(
                "The 'redis' package is required for GEMINI_BUDGET_STORE=redis."
            ) from exc
        self.monthly_budget = float(monthly_budget_usd)
        self._client = redis.Redis.from_url(
            redis_url, socket_connect_timeout=3, socket_timeout=3
        )
        self._reserve_script = self._client.register_script(self._RESERVE_LUA)
        self._finalize_script = self._client.register_script(self._FINALIZE_LUA)

    def _keys(self, period_key: str):
        return [
            f"{self._KEY_PREFIX}:{period_key}:committed",
            f"{self._KEY_PREFIX}:{period_key}:reserved",
        ]

    @staticmethod
    def _period_key() -> str:
        return utc_period_key(datetime.now(timezone.utc))

    def _call(self, script: Callable, keys: list, args: list):
        try:
            return script(keys=keys, args=args)
        except BudgetStoreUnavailableException:
            raise
        except Exception as exc:
            raise BudgetStoreUnavailableException(
                "The shared budget store (Redis) is unreachable; the call "
                "is blocked rather than proceeding without a spend limit."
            ) from exc

    def reserve(self, max_cost_usd: float) -> BudgetReservation:
        if max_cost_usd <= 0:
            raise ValueError("max_cost_usd must be positive.")
        period = self._period_key()
        ok = self._call(
            self._reserve_script,
            self._keys(period),
            [repr(self.monthly_budget), repr(float(max_cost_usd)), str(self._KEY_TTL_SECONDS)],
        )
        if not ok:
            raise BudgetExceededException(
                "Application AI budget ceiling reached (shared store); the "
                "call was blocked before contacting the provider."
            )
        return BudgetReservation(
            reservation_id=str(uuid.uuid4()),
            period_key=period,
            reserved_usd=float(max_cost_usd),
        )

    def finalize(
        self, reservation: BudgetReservation, actual_cost_usd: Optional[float]
    ) -> bool:
        """Idempotently release the reservation and commit the actual cost.

        Returns ``True`` when this call applied the accounting and
        ``False`` when the reservation was ALREADY finalized (duplicate /
        retried finalize — no double release, no double commit).
        """
        actual = "" if actual_cost_usd is None else repr(float(actual_cost_usd))
        committed_key, reserved_key = self._keys(reservation.period_key)
        claim_key = f"{self._KEY_PREFIX}:{reservation.period_key}:finalized:{reservation.reservation_id}"
        applied = self._call(
            self._finalize_script,
            [committed_key, reserved_key, claim_key],
            [repr(reservation.reserved_usd), actual, str(self._KEY_TTL_SECONDS)],
        )
        if not applied:
            logger.info(
                "[COST_MONITORING] Duplicate finalization of reservation %s "
                "ignored (exactly-once claim); accounting unchanged.",
                reservation.reservation_id,
            )
        return bool(applied)

    @property
    def accumulated_spend(self) -> float:
        period = self._period_key()
        try:
            raw = self._client.get(f"{self._KEY_PREFIX}:{period}:committed")
        except Exception:
            return 0.0
        try:
            return float(raw) if raw else 0.0
        except (TypeError, ValueError):
            return 0.0

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # pragma: no cover - best effort
            pass


def build_budget_ledger(config: GeminiRuntimeConfig) -> BudgetLedger:
    """Construct the ledger selected by the (single-source) config."""
    if config.budget_store == "redis":
        return RedisBudgetLedger(config.monthly_budget_usd, config.redis_url)
    return InProcessBudgetLedger(
        monthly_budget_usd=config.monthly_budget_usd,
        input_cost_per_million=config.input_cost_per_million,
        output_cost_per_million=config.output_cost_per_million,
    )


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


# HTTP status codes that are transient (safe to retry, bounded).
_TRANSIENT_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
# HTTP status codes that are permanent provider-auth failures (never retry).
_AUTH_STATUS_CODES = frozenset({401, 403})


class GeminiCallerAdapter(RemoteLLMInterface):
    """Resilient, fail-closed Gemini API client.

    Application-lifetime object: one instance is created per agent
    application (see ``agent-service/main.py``) and shared across requests,
    so circuit-breaker and budget state persist for the life of the process.
    The HTTP transport and clocks are injectable for tests.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        config: Optional[GeminiRuntimeConfig] = None,
        *,
        monthly_budget_usd: Optional[float] = None,
        max_retries: Optional[int] = None,
        backoff_base_seconds: Optional[float] = None,
        timeout_seconds: Optional[float] = None,
        model_name: Optional[str] = None,
        transport: Optional[Callable[..., requests.Response]] = None,
        time_fn: Callable[[], float] = time.time,
        now_fn: Optional[Callable[[], datetime]] = None,
        budget_ledger: Optional[BudgetLedger] = None,
    ):
        # Server environment (via the single-source config) is the ONLY
        # credential source.  The narrow keyword overrides exist so tests
        # (and the pre-D1 call sites) can pin a single tunable without
        # constructing a full config; every DEFAULT still lives exactly
        # once in GeminiRuntimeConfig.
        self.api_key = api_key if api_key is not None else os.getenv("GEMINI_API_KEY", "")
        base = config if config is not None else GeminiRuntimeConfig.from_env()
        overrides: Dict[str, Any] = {}
        if monthly_budget_usd is not None:
            overrides["monthly_budget_usd"] = monthly_budget_usd
        if max_retries is not None:
            overrides["max_retries"] = max_retries
        if backoff_base_seconds is not None:
            overrides["backoff_base_seconds"] = backoff_base_seconds
        if timeout_seconds is not None:
            overrides["timeout_seconds"] = timeout_seconds
        if model_name is not None:
            overrides["model_name"] = model_name
        self.config = replace(base, **overrides) if overrides else base

        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models"
        self.model_name = self.config.model_name
        self.timeout_seconds = float(self.config.timeout_seconds)
        self.max_retries = max(1, int(self.config.max_retries))
        self.backoff_base_seconds = float(self.config.backoff_base_seconds)

        self.budget_service: BudgetLedger = budget_ledger or build_budget_ledger(self.config)
        self._transport = transport  # injectable; defaults to requests.post
        self._time_fn = time_fn
        self._now_fn = now_fn

        # Circuit breaker states: CLOSED, OPEN, HALF-OPEN.
        #
        # HALF-OPEN is a single-probe lease (Phase 8.7-D.1-CORRECTION,
        # settlement contract hardening in 8.7-D.1-CORRECTION-2):
        # when the cooldown expires, the FIRST caller atomically acquires
        # the probe lease and becomes the only provider probe; every other
        # concurrent caller sees HALF-OPEN and fails fast instead of
        # becoming an additional probe.
        #
        # SETTLEMENT CONTRACT — the lease is always settled through
        # exactly one exception-safe finalization path in
        # _generate_text() (a single try/finally-style except handler
        # wrapping the ENTIRE post-lease section, not a per-branch
        # remember-to-settle discipline):
        #   * provider success  -> CLOSED      (_register_success)
        #   * provider failure  -> OPEN        (_register_failure)
        #   * PRE-provider failure (missing key, budget store unavailable,
        #     budget ceiling) -> OPEN with a FRESH cooldown
        #     (_settle_failed_probe) — never CLOSED, so an unconfigured
        #     or exhausted deployment cannot stream unlimited doomed
        #     probes; never an unsettled HALF-OPEN, so the circuit cannot
        #     wedge with every caller failing fast forever.
        self.cb_state = "CLOSED"
        self.cb_failures = 0
        self.cb_max_failures = 5
        self.cb_cooldown_seconds = 60.0
        self.cb_last_failure_time = 0.0
        self._state_lock = threading.Lock()

    # -- circuit breaker ----------------------------------------------------

    def _check_circuit(self) -> bool:
        """Admission check. Returns True ONLY when this caller acquired the
        single half-open probe lease (and is therefore responsible for
        settling it via the finalization path in _generate_text).
        Raises for every rejected call (OPEN cooldown, probe in flight)."""
        with self._state_lock:
            if self.cb_state == "OPEN":
                if self._time_fn() - self.cb_last_failure_time > self.cb_cooldown_seconds:
                    # Cooldown elapsed: this caller acquires the SINGLE
                    # half-open probe lease and proceeds as the probe.
                    # The lease MUST be settled by _generate_text's
                    # finalization path — see the SETTLEMENT CONTRACT in
                    # the constructor.
                    self.cb_state = "HALF-OPEN"
                    logger.info(
                        "[CIRCUIT_BREAKER] Cooldown elapsed; single half-open "
                        "probe armed."
                    )
                    return True
                logger.warning("[CIRCUIT_BREAKER] Circuit OPEN; rejecting call fast.")
                raise GeminiServiceUnavailableException(
                    "Gemini circuit breaker is OPEN; calls are rejected until cooldown."
                )
            if self.cb_state == "HALF-OPEN":
                # A probe is already in flight: no second probe is
                # permitted, so concurrent callers fail fast.
                logger.warning(
                    "[CIRCUIT_BREAKER] HALF-OPEN probe in flight; rejecting "
                    "call fast."
                )
                raise GeminiServiceUnavailableException(
                    "Gemini circuit breaker is recovering (a single probe is "
                    "in flight); calls are rejected until it settles."
                )
            # CLOSED: proceed (no lease held).
            return False

    def _settle_failed_probe(self) -> None:
        """Idempotent pre-provider failure settlement for the half-open
        probe lease (Phase 8.7-D.1-CORRECTION-2).

        Called from _generate_text's single finalization path when the
        probe fails BEFORE provider contact (missing GEMINI_API_KEY,
        budget store unavailable, budget ceiling).  Re-opens the circuit
        with a FRESH cooldown — never CLOSED (an unconfigured/exhausted
        deployment must not stream unlimited doomed probes) and never an
        unsettled HALF-OPEN (which would wedge every caller failing fast
        forever).

        No-op when the probe was already settled by _register_success /
        _register_failure — settlement is exactly-once either way, and
        both transitions happen under the same state lock."""
        with self._state_lock:
            if self.cb_state != "HALF-OPEN":
                return
            logger.critical(
                "[CIRCUIT_BREAKER] Pre-provider failure during half-open "
                "probe; re-opening circuit with a fresh cooldown."
            )
            self.cb_state = "OPEN"
            self.cb_failures = 1
            self.cb_last_failure_time = self._time_fn()

    def _register_failure(self) -> None:
        with self._state_lock:
            self.cb_failures += 1
            self.cb_last_failure_time = self._time_fn()
            if self.cb_state == "HALF-OPEN":
                # The single probe failed: re-open the circuit
                # immediately so the cooldown runs again before the next
                # probe is permitted.
                logger.critical(
                    "[CIRCUIT_BREAKER] Half-open probe FAILED; re-opening "
                    "circuit."
                )
                self.cb_state = "OPEN"
                self.cb_failures = 1
            elif self.cb_failures >= self.cb_max_failures:
                logger.critical(
                    "[CIRCUIT_BREAKER] %d consecutive failures; tripping circuit OPEN.",
                    self.cb_failures,
                )
                self.cb_state = "OPEN"

    def _register_success(self) -> None:
        with self._state_lock:
            self.cb_failures = 0
            self.cb_state = "CLOSED"

    # -- preconditions (fail closed) ----------------------------------------

    def _assert_provider_configured(self) -> None:
        """Fail closed: never answer a generation call without the key."""
        if not self.api_key:
            logger.error(
                "[FAIL_CLOSED] GEMINI_API_KEY is not configured in the server "
                "environment. Refusing to fabricate a provider response."
            )
            raise GeminiServiceUnavailableException(
                "Server-side Gemini is not configured (GEMINI_API_KEY absent); "
                "failing closed instead of fabricating a response."
            )

    # -- budget reservation (D1 P0-2) ----------------------------------------

    def _max_estimated_cost_usd(self) -> float:
        """Conservative worst-case cost of one generation call.

        Covers the bounded retry budget: every attempt can cost up to
        (estimated prompt + max output tokens).  Reserving the worst case
        guarantees concurrent callers can never commit more than the
        ceiling, and reconciliation with real usage corrects downward.
        """
        cfg = self.config
        per_attempt = (
            cfg.estimated_prompt_tokens * cfg.input_cost_per_million
            + cfg.max_output_tokens * cfg.output_cost_per_million
        ) / 1_000_000
        return per_attempt * self.max_retries

    @staticmethod
    def _cost_from_usage(data: Dict[str, Any], cfg: GeminiRuntimeConfig) -> Optional[float]:
        """Actual cost from provider ``usageMetadata``, or None when the
        metadata is absent (the caller then keeps the full reservation —
        conservative, never undercount)."""
        usage = data.get("usageMetadata") if isinstance(data, dict) else None
        if isinstance(usage, dict):
            prompt_tokens = int(usage.get("promptTokenCount") or 0)
            completion_tokens = int(usage.get("candidatesTokenCount") or 0)
            if prompt_tokens or completion_tokens:
                return (
                    prompt_tokens * cfg.input_cost_per_million
                    + completion_tokens * cfg.output_cost_per_million
                ) / 1_000_000
        return None

    # -- core generation -----------------------------------------------------

    def _build_payload(self, prompt: str, system_instruction: str) -> Dict[str, Any]:
        """The structured, bounded provider request contract (D1 P0-6).

        * ``maxOutputTokens``: a real provider-side output ceiling.
        * ``responseMimeType``/``responseSchema``: explicit JSON output in
          the exact five-field shape (defense in depth — the strict
          application parse remains the authority).
        """
        schema_properties = {field: {"type": "STRING"} for field in ANALYSIS_ASSET_FIELDS}
        return {
            "contents": [{"parts": [{"text": prompt}]}],
            "systemInstruction": {"parts": [{"text": system_instruction}]},
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": {
                    "type": "OBJECT",
                    "properties": schema_properties,
                    "required": list(ANALYSIS_ASSET_FIELDS),
                    "propertyOrdering": list(ANALYSIS_ASSET_FIELDS),
                },
                "maxOutputTokens": int(self.config.max_output_tokens),
            },
        }

    def _post(self, payload: Dict[str, Any]) -> requests.Response:
        if self._transport is not None:
            return self._transport(payload)
        return requests.post(
            f"{self.base_url}/{self.model_name}:generateContent",
            json=payload,
            headers={"x-goog-api-key": self.api_key},
            timeout=self.timeout_seconds,
        )

    @staticmethod
    def _extract_text(data: Dict[str, Any]) -> str:
        """Strict, typed extraction of the provider text.

        Raises GeminiMalformedResponseException on any structural surprise
        (no candidates, empty parts, non-string text).
        """
        candidates = data.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise GeminiMalformedResponseException(
                "Gemini response contained no candidates (possibly safety-blocked)."
            )
        content = candidates[0].get("content") if isinstance(candidates[0], dict) else None
        parts = content.get("parts") if isinstance(content, dict) else None
        if not isinstance(parts, list) or not parts:
            raise GeminiMalformedResponseException("Gemini response contained no content parts.")
        first = parts[0]
        text = first.get("text") if isinstance(first, dict) else None
        if not isinstance(text, str) or not text.strip():
            raise GeminiMalformedResponseException("Gemini response part had no usable text.")
        return text

    def _generate_text(self, prompt: str, system_instruction: str) -> str:
        """Bounded, retrying, circuit-protected, budget-reserving text
        generation (real calls only — fail closed when unconfigured).

        HALF-OPEN probe-lease lifecycle (Phase 8.7-D.1-CORRECTION-2):
        when _check_circuit hands us the single probe lease, the ENTIRE
        post-lease section (precondition checks, budget reservation,
        provider contact) is wrapped in ONE exception-safe finalization
        path.  Whatever fails — a pre-provider precondition, the budget
        store, the budget ceiling, or the provider itself — settles the
        lease exactly once: success closes the circuit, any failure re-
        opens it with a fresh cooldown.  No per-branch remember-to-settle
        discipline exists that an exception could bypass."""
        probing = self._check_circuit()
        try:
            self._assert_provider_configured()

            # Atomic worst-case reservation BEFORE any provider contact.
            reservation = self.budget_service.reserve(self._max_estimated_cost_usd())
            try:
                return self._generate_text_with_reservation(prompt, system_instruction, reservation)
            except Exception:
                # Any failure path keeps the FULL reservation (conservative).
                # The provider-side failure itself is already registered
                # (and the lease settled) by _generate_text_with_reservation.
                self.budget_service.finalize(reservation, None)
                raise
        except Exception:
            # Single finalization path: settle the probe lease exactly once
            # if we hold it and it is still unsettled.  No-op when the
            # provider call already settled it (_register_success /
            # _register_failure) — and a no-op entirely when we were not
            # the probe (CLOSED admission).
            if probing:
                self._settle_failed_probe()
            raise

    def _generate_text_with_reservation(
        self, prompt: str, system_instruction: str, reservation: BudgetReservation
    ) -> str:
        payload = self._build_payload(prompt, system_instruction)
        backoff_delay = self.backoff_base_seconds
        for attempt in range(1, self.max_retries + 1):
            try:
                response = self._post(payload)
            except requests.Timeout as exc:
                self._register_failure()
                if attempt == self.max_retries:
                    logger.error("[GEMINI] Timeout after %d attempts.", attempt)
                    raise GeminiTimeoutException(
                        "Gemini provider did not answer within the bounded timeout."
                    ) from exc
                logger.warning("[GEMINI] Attempt %d timed out; backing off %.1fs.", attempt, backoff_delay)
                time.sleep(backoff_delay)
                backoff_delay *= 2.0
                continue
            except requests.ConnectionError as exc:
                self._register_failure()
                if attempt == self.max_retries:
                    raise GeminiUpstreamException(
                        "Network-level failure reaching the Gemini provider."
                    ) from exc
                logger.warning("[GEMINI] Attempt %d connection failed; backing off %.1fs.", attempt, backoff_delay)
                time.sleep(backoff_delay)
                backoff_delay *= 2.0
                continue
            except requests.RequestException as exc:
                # Any other requests-level failure: treat as transient.
                self._register_failure()
                if attempt == self.max_retries:
                    raise GeminiUpstreamException(
                        "Transport failure reaching the Gemini provider."
                    ) from exc
                logger.warning("[GEMINI] Attempt %d transport error; backing off %.1fs.", attempt, backoff_delay)
                time.sleep(backoff_delay)
                backoff_delay *= 2.0
                continue

            status = response.status_code

            # Permanent provider-auth failure: never retry, never leak the key.
            if status in _AUTH_STATUS_CODES:
                self._register_failure()
                raise GeminiAuthException(
                    "Gemini provider rejected the server-side credential (HTTP %d)." % status
                )

            # Transient statuses: bounded retry with backoff.
            if status in _TRANSIENT_STATUS_CODES:
                self._register_failure()
                if attempt == self.max_retries:
                    if status == 429:
                        raise GeminiRateLimitException(
                            "Gemini provider rate limit persisted (HTTP 429) after bounded retries."
                        )
                    raise GeminiUpstreamException(
                        "Gemini provider upstream error (HTTP %d) after bounded retries." % status
                    )
                logger.warning("[GEMINI] HTTP %d on attempt %d; backing off %.1fs.", status, attempt, backoff_delay)
                time.sleep(backoff_delay)
                backoff_delay *= 2.0
                continue

            if status != 200:
                # Non-2xx that is neither auth nor a known transient: fail now.
                self._register_failure()
                raise GeminiUpstreamException(
                    "Gemini provider returned an unexpected status (HTTP %d)." % status
                )

            try:
                data = response.json()
            except ValueError as exc:
                self._register_failure()
                raise GeminiMalformedResponseException(
                    "Gemini provider response was not valid JSON."
                ) from exc

            text = self._extract_text(data)

            # Success: reconcile the reservation with real usage (or keep
            # the full reservation when usage metadata is absent).
            self.budget_service.finalize(
                reservation, self._cost_from_usage(data, self.config)
            )
            self._register_success()
            return text

        # Unreachable (the loop either returns or raises), but be explicit.
        self._register_failure()
        raise GeminiServiceUnavailableException(
            "Gemini generation did not complete within the bounded retry budget."
        )

    # -- RemoteLLMInterface ----------------------------------------------------

    def generate_remediation(self, prompt: str, system_instruction: str) -> str:
        """Real provider text generation.  Fail closed when unconfigured."""
        return self._generate_text(prompt, system_instruction)

    def generate_iac_blueprint(self, tech_metadata: Dict[str, Any]) -> Dict[str, str]:
        """Real provider blueprint generation.

        Uses the SAME strict five-field parse/validate contract as the
        repository-analysis path (``parse_strict_asset_payload``) — there is
        no alternate lenient parser in the codebase (D1 P0-6).
        """
        tech_lines = ", ".join(f"{k}: {v}" for k, v in sorted(tech_metadata.items()))
        prompt = (
            f"Technology metadata: {tech_lines}\n"
            "Generate production DevOps blueprints. Respond with ONLY a JSON "
            'object of the form {"dockerfile": "...", "k8s_yaml": "...", '
            '"terraform_tf": "...", "pipeline_yaml": "...", "report": "..."}. '
            "No markdown fences, no commentary, no extra fields."
        )
        system_instruction = (
            "You are a senior DevOps platform architect. You emit strictly "
            "validated JSON only."
        )
        raw = self._generate_text(prompt, system_instruction)
        return parse_strict_asset_payload(raw).to_dict()
