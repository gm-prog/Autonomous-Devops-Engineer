"""Server-side Gemini provider client (Phase 8.7-D hardened).

Security / resilience contract
==============================

* **Fail closed**: when ``GEMINI_API_KEY`` is absent from the server
  environment, every generation call RAISES ``GeminiServiceUnavailableException``.
  There is no simulator fallback and no fake "success" that pretends Gemini
  answered (the pre-8.7-D ``[OFFLINE_BYPASS]`` behavior is removed).
* **Credential handling**: the key is read only from the server environment
  (``GEMINI_API_KEY``) and is sent exclusively via the ``x-goog-api-key``
  header — never in the URL — so it cannot leak into exception text, logs,
  or access traces.
* **Bounded**: bounded request timeout, bounded retry attempts with
  exponential backoff.
* **Retries only transient failures**: 429, 5xx, timeouts, and connection
  errors are retried.  Provider authentication failures (401/403) and
  malformed responses fail immediately — retrying them cannot help.
* **Circuit breaker**: after a threshold of consecutive failures the circuit
  opens and calls fail fast until a cooldown elapses (half-open probe).
* **Budget ceiling**: platform spend is accumulated per process and calls
  are blocked when the monthly ceiling is exhausted.
* **Structured extraction**: a 200 response that is not well-formed
  (missing candidates / parts / text) raises ``GeminiMalformedResponseException``
  instead of crashing with an untyped KeyError or returning partial data.

Error taxonomy (callers may branch on these precisely):

* ``GeminiAuthException``              — provider rejected credentials (401/403).
* ``GeminiRateLimitException``         — upstream rate limit (429) after retries.
* ``GeminiTimeoutException``           — upstream did not answer in time.
* ``GeminiUpstreamException``          — upstream 5xx / network failure.
* ``GeminiMalformedResponseException`` — 200 response without usable content.
* ``GeminiServiceUnavailableException``— missing key (fail closed), circuit
                                        open, or infrastructure unavailable.
* ``BudgetExceededException``          — platform spend ceiling reached.
"""

from __future__ import annotations

import json
import logging
import os
import time
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import requests

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
    """The platform AI spend ceiling has been reached; calls are blocked."""


# ---------------------------------------------------------------------------
# Budget service
# ---------------------------------------------------------------------------


class GeminiBudgetService:
    """Per-process calendar-month AI spend ceiling (USD).

    This is a local safety guard, not a provider-account/global billing limit.
    Horizontally scaled replicas require a shared budget store for a global
    ceiling.
    """

    # Gemini 3.5 Flash Standard pricing (per 1M tokens).
    INPUT_COST_PER_MILLION = 1.50
    OUTPUT_COST_PER_MILLION = 9.00

    def __init__(self, monthly_budget_usd: float = 100.0):
        self.monthly_budget = float(monthly_budget_usd)
        self.accumulated_spend = 0.0
        self._lock = threading.Lock()
        self._period_key = self._current_period_key()

    @staticmethod
    def _current_period_key() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m")

    def _roll_period_if_needed(self) -> None:
        current = self._current_period_key()
        if current != self._period_key:
            self._period_key = current
            self.accumulated_spend = 0.0

    def check_budget(self) -> bool:
        with self._lock:
            self._roll_period_if_needed()
            return self.accumulated_spend < self.monthly_budget

    def warn_if_low(self) -> None:
        self._roll_period_if_needed()
        remaining = self.monthly_budget - self.accumulated_spend
        if remaining < 10.0:
            logger.warning(
                "[COST_MONITORING] Gemini API monthly budget is critically low: "
                "$%.2f remaining.", remaining
            )

    def record_cost(self, prompt_tokens: int, completion_tokens: int) -> None:
        with self._lock:
            self._record_cost_locked(prompt_tokens, completion_tokens)

    def _record_cost_locked(self, prompt_tokens: int, completion_tokens: int) -> None:
        self._roll_period_if_needed()
        cost = (
            prompt_tokens * self.INPUT_COST_PER_MILLION / 1_000_000
        ) + (completion_tokens * self.OUTPUT_COST_PER_MILLION / 1_000_000)
        self.accumulated_spend += cost
        logger.info(
            "[COST_MONITORING] Recorded cost: $%.6f. Total spend: $%.6f "
            "(ceiling $%.2f).", cost, self.accumulated_spend, self.monthly_budget
        )


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


# HTTP status codes that are transient (safe to retry, bounded).
_TRANSIENT_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
# HTTP status codes that are permanent provider-auth failures (never retry).
_AUTH_STATUS_CODES = frozenset({401, 403})

# Default conservative token estimate used only when the provider omits
# usageMetadata; the real usage is preferred whenever present.
_DEFAULT_ESTIMATED_PROMPT_TOKENS = 220
_DEFAULT_ESTIMATED_COMPLETION_TOKENS = 400


class GeminiCallerAdapter(RemoteLLMInterface):
    """Resilient, fail-closed Gemini API client.

    All resilience behavior (circuit breaker, bounded retries with
    exponential backoff, budget ceiling, structured extraction) is enforced
    here, on the server side.  The HTTP layer is injectable for testing;
    production uses ``requests.post`` with a bounded timeout.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        monthly_budget_usd: float = 150.0,
        timeout_seconds: float = 20.0,
        max_retries: int = 3,
        backoff_base_seconds: float = 0.5,
        model_name: str = "gemini-3.5-flash",
        transport: Optional[Callable[..., requests.Response]] = None,
        time_fn: Callable[[], float] = time.time,
    ):
        # Server environment is the ONLY credential source.
        self.api_key = api_key if api_key is not None else os.getenv("GEMINI_API_KEY", "")
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models"
        self.model_name = model_name
        self.timeout_seconds = float(timeout_seconds)
        self.max_retries = max(1, int(max_retries))
        self.backoff_base_seconds = float(backoff_base_seconds)
        self.budget_service = GeminiBudgetService(monthly_budget_usd)
        self._transport = transport  # injectable; defaults to requests.post
        self._time_fn = time_fn

        # Circuit breaker states: CLOSED, OPEN, HALF-OPEN.
        self.cb_state = "CLOSED"
        self.cb_failures = 0
        self.cb_max_failures = 5
        self.cb_cooldown_seconds = 60.0
        self.cb_last_failure_time = 0.0
        self._state_lock = threading.Lock()
        self._generation_lock = threading.Lock()

    # -- circuit breaker ----------------------------------------------------

    def _check_circuit(self) -> None:
        with self._state_lock:
            self._check_circuit_locked()

    def _check_circuit_locked(self) -> None:
        if self.cb_state == "OPEN":
            if self._time_fn() - self.cb_last_failure_time > self.cb_cooldown_seconds:
                logger.info("[CIRCUIT_BREAKER] Cooldown elapsed. Half-open probe armed.")
                self.cb_state = "HALF-OPEN"
            else:
                logger.warning("[CIRCUIT_BREAKER] Circuit OPEN; rejecting call fast.")
                raise GeminiServiceUnavailableException(
                    "Gemini circuit breaker is OPEN; calls are rejected until cooldown."
                )

    def _register_failure(self) -> None:
        with self._state_lock:
            self.cb_failures += 1
            self.cb_last_failure_time = self._time_fn()
            if self.cb_failures >= self.cb_max_failures:
                logger.critical(
                    "[CIRCUIT_BREAKER] %d consecutive failures; tripping circuit OPEN.",
                    self.cb_failures,
                )
                self.cb_state = "OPEN"

    def _register_success(self) -> None:
        with self._state_lock:
            self.cb_failures = 0
            self.cb_state = "CLOSED"

    # -- circuit breaker legacy body removed --
    def _register_failure_legacy_removed(self) -> None:
        return

    def _register_success_legacy_removed(self) -> None:
        return

    def _old_failure_body_removed(self) -> None:
        return

    def _unused_placeholder(self) -> None:
        return

    def _remove_this_method(self) -> None:
        return

    def _removed(self) -> None:
        return

    def _noop(self) -> None:
        return

    def _placeholder(self) -> None:
        return


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

    def _precall_gates(self) -> None:
        self._check_circuit()
        if not self.budget_service.check_budget():
            raise BudgetExceededException(
                "Platform AI consumption budget has been capped; calls are blocked."
            )
        self._assert_provider_configured()

    # -- core generation -----------------------------------------------------

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

    def _record_usage(self, data: Dict[str, Any]) -> None:
        usage = data.get("usageMetadata") if isinstance(data, dict) else None
        if isinstance(usage, dict):
            prompt_tokens = int(usage.get("promptTokenCount") or 0)
            completion_tokens = int(usage.get("candidatesTokenCount") or 0)
            if prompt_tokens or completion_tokens:
                self.budget_service.record_cost(prompt_tokens, completion_tokens)
                self.budget_service.warn_if_low()
                return
        # Conservative fallback estimate when the provider omits usage data.
        self.budget_service.record_cost(
            _DEFAULT_ESTIMATED_PROMPT_TOKENS, _DEFAULT_ESTIMATED_COMPLETION_TOKENS
        )
        self.budget_service.warn_if_low()

    def _generate_text(self, prompt: str, system_instruction: str) -> str:
        """Bounded, retrying, circuit-protected text generation (real calls
        only — fail closed when unconfigured)."""
        with self._generation_lock:
            return self._generate_text_locked(prompt, system_instruction)

    def _generate_text_locked(self, prompt: str, system_instruction: str) -> str:
        self._precall_gates()

        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "systemInstruction": {"parts": [{"text": system_instruction}]},
        }

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

            self._register_success()
            self._record_usage(data)
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
        """Real provider blueprint generation with strict JSON extraction.

        Fail closed when unconfigured; malformed provider JSON raises
        ``GeminiMalformedResponseException`` — it never returns a fabricated
        blueprint.
        """
        tech_lines = ", ".join(f"{k}: {v}" for k, v in sorted(tech_metadata.items()))
        prompt = (
            f"Technology metadata: {tech_lines}\n"
            "Generate production DevOps blueprints. Respond with ONLY a JSON "
            'object of the form {"dockerfile": "...", "k8s_yaml": "...", '
            '"terraform_tf": "...", "pipeline_yaml": "...", "report": "..."}. '
            "No markdown fences, no commentary."
        )
        system_instruction = (
            "You are a senior DevOps platform architect. You emit strictly "
            "validated JSON only."
        )
        raw = self._generate_text(prompt, system_instruction)
        return _parse_strict_json_object(raw)


def _parse_strict_json_object(raw: str) -> Dict[str, str]:
    """Parse a provider response into a strict string->string object.

    Strips an accidental markdown fence, then requires a JSON object whose
    values are all non-empty strings.  Raises GeminiMalformedResponseException
    otherwise.
    """
    text = raw.strip()
    if text.startswith("```"):
        # Tolerate a single accidental fence pair; nothing else is forgiven.
        lines = text.splitlines()
        if len(lines) >= 2 and lines[0].startswith("```"):
            if lines[-1].strip().startswith("```"):
                text = "\n".join(lines[1:-1]).strip()
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise GeminiMalformedResponseException(
            "Provider response was not a JSON object."
        ) from exc
    if not isinstance(data, dict) or not data:
        raise GeminiMalformedResponseException("Provider JSON was not a non-empty object.")
    for key, value in data.items():
        if not isinstance(value, str) or not value.strip():
            raise GeminiMalformedResponseException(
                f"Provider JSON field {key!r} is not a non-empty string."
            )
    return {str(k): str(v) for k, v in data.items()}
