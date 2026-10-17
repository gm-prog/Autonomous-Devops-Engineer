"""Phase 8.7-D.1-CORRECTION-3 structural guard — Gemini caller resilience
contract (Findings A–D).

Inspects the ACTUAL source of ``agent-service/infrastructure/llm/
gemini_caller.py`` and fails (exits non-zero in CI) when any of the
corrected weaknesses is reintroduced:

* **A — half-open single probe**: the half-open probe lease must get
  exactly ONE provider attempt.  ``_generate_text`` computes an EXPLICIT
  ``allowed_attempts`` (1 for the probe, ``max_retries`` when closed) and
  passes it through; the attempt loop must iterate over
  ``allowed_attempts`` — never re-infer ``self.max_retries`` per
  iteration (mutation M25).
* **B — finite configuration**: NaN/+-inf must be rejected for every
  float field at construction — in ``GeminiRuntimeConfig.__post_init__``
  (covers ``from_env`` AND direct construction), in the ``from_env``
  ``_float`` parser, and in the shared ledger-validation helper that both
  ledger constructors use (mutation M26).
* **C — hard input bounds**: every path through ``_generate_text`` is
  bounded at the single choke point BEFORE reservation/provider contact;
  the per-request input allowance is ``max(per-request byte bound,
  configured estimate)`` so the operator can never lower the safe bound;
  ``generate_iac_blueprint`` metadata is bounded by accepted scalar types
  + serialized size (mutation M27).
* **D — retry-chain cost reconciliation**: the reservation finalizes
  from the explicit per-attempt billing evidence — known usage + the
  worst-case allowance for every attempt with unknown cost — capped at
  the reservation.  A mutation that finalizes only the final attempt's
  usage undercounts timed-out/5xx attempts (mutation M28).

Run standalone with the other guards:

    PYTHONPATH=devops-ai-platform python -m security_guards
"""

from __future__ import annotations

from pathlib import Path
from typing import List

PLATFORM = "devops-ai-platform"
CALLER_REL = f"{PLATFORM}/agent-service/infrastructure/llm/gemini_caller.py"


def _section(src: str, start_marker: str, end_marker: str) -> str:
    """The source text between two markers ('' when either is missing)."""
    i = src.find(start_marker)
    if i < 0:
        return ""
    j = src.find(end_marker, i + len(start_marker))
    return src[i:j] if j > i else src[i:]


def check_gemini_contract(repo_root: Path) -> List[str]:
    """Source-level contract check; returns violation strings (empty = ok)."""
    caller = repo_root / CALLER_REL
    if not caller.exists():
        return [f"missing {CALLER_REL}"]
    src = caller.read_text(encoding="utf-8")
    v: List[str] = []

    # ------------------------------------------------------------------ A
    gen = _section(src, "def _generate_text(", "\n    def _generate_text_with_reservation(")
    if "allowed_attempts = 1 if probing else self.max_retries" not in gen:
        v.append("A: _generate_text must compute an explicit "
                 "allowed_attempts = 1 if probing else self.max_retries "
                 "(half-open probe = exactly one provider attempt)")
    if "self._max_estimated_cost_usd(input_tokens, allowed_attempts)" not in gen:
        v.append("A: the reservation must be sized with the explicit "
                 "(input_tokens, allowed_attempts) pair, not implicit "
                 "config/breaker state")
    loop_fn = _section(
        src, "def _generate_text_with_reservation(", "\n    # -- RemoteLLMInterface"
    )
    if "for attempt in range(1, allowed_attempts + 1):" not in loop_fn:
        v.append("A: the attempt loop must iterate over the explicit "
                 "allowed_attempts count")
    if "for attempt in range(1, self.max_retries + 1):" in src:
        v.append("A: the attempt loop must never re-infer self.max_retries "
                 "per iteration (a probe would expand into a retry storm)")
    if "if attempt == self.max_retries:" in loop_fn:
        v.append("A: the final-attempt checks must key off the explicit "
                 "allowed_attempts, not self.max_retries")

    # ------------------------------------------------------------------ B
    post_init = _section(src, "def __post_init__(self)", "def from_env(")
    if "math.isfinite" not in post_init:
        v.append("B: GeminiRuntimeConfig.__post_init__ must reject "
                 "non-finite values with math.isfinite (covers both "
                 "from_env and direct construction)")
    if "if not math.isfinite(value):" not in src:
        v.append("B: the from_env float parser must reject non-finite "
                 "values with a math.isfinite check")
    if "if not math.isfinite(v) or v < 0:" not in src:
        v.append("B: the shared ledger-validation helper "
                 "_require_finite_non_negative must reject NaN/+-inf")
    inproc = _section(src, "class InProcessBudgetLedger:", "class RedisBudgetLedger:")
    if "self.monthly_budget = _require_finite_non_negative(" not in inproc:
        v.append("B: InProcessBudgetLedger must validate its accounting "
                 "parameters at construction (fail closed)")
    redis_fn = _section(src, "class RedisBudgetLedger:", "class GeminiCallerAdapter(")
    if "self.monthly_budget = _require_finite_non_negative(" not in redis_fn:
        v.append("B: RedisBudgetLedger must validate its accounting "
                 "parameters at construction (fail closed)")

    # ------------------------------------------------------------------ C
    if "self._validate_input_bounds(prompt, system_instruction)" not in gen:
        v.append("C: _generate_text must call _validate_input_bounds on "
                 "every input path")
    if gen.find("self._validate_input_bounds(prompt, system_instruction)") > \
            gen.find("probing = self._check_circuit()"):
        v.append("C: the input bound check must run BEFORE circuit state "
                 "is read, reservation, and provider contact")
    validate_fn = _section(src, "def _validate_input_bounds(", "def _estimated_input_tokens(")
    for bound in ("MAX_PROMPT_CHARS", "MAX_SYSTEM_INSTRUCTION_CHARS",
                  "GeminiInputBoundException"):
        if bound not in validate_fn:
            v.append(f"C: _validate_input_bounds must enforce {bound}")
    est_fn = _section(src, "def _estimated_input_tokens(", "def _cost_from_usage(")
    if "return max(byte_bound, int(self.config.estimated_prompt_tokens))" not in est_fn:
        v.append("C: the per-request input allowance must be max(byte "
                 "bound, configured estimate) — the estimate is a floor "
                 "only and can never lower the per-request safe bound")
    iac_fn = _section(src, "def generate_iac_blueprint(", "def _generate_text(")
    if "MAX_TECH_METADATA_SERIALIZED_CHARS" not in iac_fn:
        v.append("C: generate_iac_blueprint must bound tech_metadata by "
                 "serialized size")
    if "isinstance(v, (str, int, float))" not in iac_fn:
        v.append("C: generate_iac_blueprint must accept only scalar "
                 "metadata values (no implicit str() of arbitrary objects)")

    # ------------------------------------------------------------------ D
    if "attempts: List[Optional[float]] = []" not in loop_fn:
        v.append("D: the attempt loop must keep an explicit per-attempt "
                 "billing-evidence list (no hidden globals)")
    if "unknown_attempts = sum(1 for c in attempts if c is None)" not in loop_fn:
        v.append("D: finalization must count every attempt with unknown "
                 "cost (timeouts/5xx/missing metadata are never free)")
    if "total_cost = min(total_cost, reservation.reserved_usd)" not in loop_fn:
        v.append("D: the committed amount for a reservation must be capped "
                 "at what that reservation held")
    if "self.budget_service.finalize(reservation, total_cost)" not in loop_fn:
        v.append("D: the reservation must finalize with the reconciled "
                 "retry-chain total, not only the final attempt's usage")
    if loop_fn.count("attempts.append(None)") < 5:
        v.append("D: every failed provider attempt (timeout, connection, "
                 "transport, auth, 5xx/429, unexpected status, malformed) "
                 "must record its unknown cost in the evidence list")
    return v


def check_gemini(repo_root: Path) -> List[str]:
    """Guard entry point (registered in ALL_GUARDS)."""
    return check_gemini_contract(repo_root)
