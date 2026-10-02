"""Phase 6.6.2 — durable progressive-release rollout stage state.

Separates two concerns that must never be conflated:

* ``ProgressiveReleaseGateService.evaluate`` answers "what does the
  current evidence say?" (read-only analysis, Phase 6.6/6.6.1).
* ``ProgressiveRolloutStageService`` answers "what rollout stage has
  the control plane durably reached?" — a deterministic, fail-closed
  state machine over one durable record per deployment.

Fixed stage sequence: 5% → 25% → 50% → 100%. State vocabulary:
``ACTIVE``, ``PAUSED``, ``ABORTED``, ``COMPLETED`` (terminal:
``ABORTED``, ``COMPLETED``).

A stored gate evaluation is informational; it only drives a transition
when the caller presents the exact evaluation id and it satisfies
freshness, identity, target, policy-version and stage preconditions.
``PROMOTE`` never mutates the stage by itself — only an explicit
transition request (bound to that evaluation) does.

This phase changes ONLY durable rollout state: no traffic shifting,
no Kubernetes mutation, no rollback, no approval, no deployment
execution, no GitHub action. State is reconstructed from persistence
on every call (no in-memory authority); concurrency converges through
an atomic compare-and-set on the durable record.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional, Tuple

from incident_service.application.services.progressive_release_gate_service import (
    ALLOWED_EXPOSURE_PERCENTAGES,
    GATE_POLICY_VERSION,
)

#: Fixed progressive stage sequence (5% → 25% → 50% → 100%).
ROLLOUT_STAGE_SEQUENCE: Tuple[int, ...] = ALLOWED_EXPOSURE_PERCENTAGES

#: Legal next exposure per current exposure; 100% completes instead.
NEXT_PERCENTAGE: Dict[int, int] = {
    5: 25,
    25: 50,
    50: 100,
}

#: Expected percentage that bootstraps a brand-new rollout stage.
INITIAL_PERCENTAGE = 0


class RolloutStageState(str, Enum):
    """Small explicit vocabulary for the durable rollout stage."""

    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    ABORTED = "ABORTED"
    COMPLETED = "COMPLETED"


TERMINAL_STAGE_STATES = frozenset(
    {RolloutStageState.ABORTED.value, RolloutStageState.COMPLETED.value}
)


class InvalidRolloutStageRequest(ValueError):
    """Malformed transition/read input (maps to HTTP 422)."""


class RolloutStageConflict(RuntimeError):
    """Illegal, stale or conflicting transition (maps to HTTP 409)."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _stage_state_id(deployment_run_id: str, source_sha: str) -> str:
    """Deterministic record identity bound to the authoritative pair."""
    digest = hashlib.sha256(
        f"{deployment_run_id}:{source_sha}".encode("utf-8")
    ).hexdigest()
    return f"rst_{digest[:24]}"


def _validate_percentage(value: Any, *, allow_zero: bool, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise InvalidRolloutStageRequest(f"{field} must be an integer")
    allowed = (
        (INITIAL_PERCENTAGE,) + ROLLOUT_STAGE_SEQUENCE
        if allow_zero
        else ROLLOUT_STAGE_SEQUENCE
    )
    if value not in allowed:
        allowed_text = ", ".join(str(item) for item in allowed)
        raise InvalidRolloutStageRequest(
            f"{field} must be one of: {allowed_text}"
        )
    return value


def _validate_non_empty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidRolloutStageRequest(f"{field} must be a non-empty string")
    if len(value) > 128:
        raise InvalidRolloutStageRequest(f"{field} must be at most 128 characters")
    return value


def _validate_source_sha(value: Any) -> str:
    if not isinstance(value, str):
        raise InvalidRolloutStageRequest("source_sha must be a string")
    if len(value) != 40 or any(char not in "0123456789abcdef" for char in value):
        raise InvalidRolloutStageRequest(
            "source_sha must be the exact 40-character lowercase hex SHA"
        )
    return value


class ProgressiveRolloutStageService:
    """Deterministic durable rollout-stage state machine (read/transition)."""

    def __init__(self, repository, *, now_factory=None):
        self.repository = repository
        self.now_factory = now_factory or (lambda: datetime.now(timezone.utc))

    # ---------------------------------------------------------------- read

    def read(self, deployment_run_id: str) -> Dict[str, Any]:
        """Bounded durable lookup; missing state fails closed (404)."""
        _validate_non_empty_string(deployment_run_id, "deployment_run_id")
        stage = self.repository.get_progressive_rollout_stage(deployment_run_id)
        if stage is None:
            raise LookupError("rollout state not found")
        return self._to_dict(stage)

    # ----------------------------------------------------------- transition

    def transition(
        self,
        deployment_run_id: str,
        expected_percentage: Any,
        target_percentage: Any,
        evaluation_id: Any,
        source_sha: Any,
    ) -> Dict[str, Any]:
        """Apply one explicit stage-transition command bound to the exact
        gate evaluation presented by the caller.

        Fail-closed for: malformed input (422), missing stage/evaluation
        (404), and every illegal/stale/conflicting transition (409).
        """
        _validate_non_empty_string(deployment_run_id, "deployment_run_id")
        expected = _validate_percentage(
            expected_percentage, allow_zero=True, field="expected_percentage"
        )
        target = _validate_percentage(
            target_percentage, allow_zero=False, field="target_percentage"
        )
        evaluation_id = _validate_non_empty_string(
            evaluation_id, "evaluation_id"
        )
        source_sha = _validate_source_sha(source_sha)
        now = _utc(self.now_factory())

        stage = self.repository.get_progressive_rollout_stage(deployment_run_id)

        if stage is None:
            # Bootstrap: the only legal creation is (no state) → ACTIVE 5%.
            if expected != INITIAL_PERCENTAGE:
                raise LookupError("rollout state not found")
            evaluation = self._load_evaluation(
                deployment_run_id, evaluation_id, target, source_sha, now
            )
            if evaluation["gate_decision"] != "PROMOTE":
                raise RolloutStageConflict(
                    "a new rollout stage can only be created from a fresh "
                    "PROMOTE evaluation"
                )
            if target != ROLLOUT_STAGE_SEQUENCE[0]:
                raise RolloutStageConflict(
                    "a new rollout stage must start at "
                    f"{ROLLOUT_STAGE_SEQUENCE[0]}%"
                )
            created = self._insert_stage(
                deployment_run_id, source_sha, evaluation, target, now
            )
            return self._to_dict(created)

        # ---- existing durable stage
        state = str(stage["state"])
        current = int(stage["current_percentage"])
        if state in TERMINAL_STAGE_STATES:
            raise RolloutStageConflict(
                f"rollout is terminal ({state}); no further transitions"
            )
        if str(stage["source_sha"]) != source_sha:
            raise RolloutStageConflict(
                "source_sha does not match the durable rollout stage"
            )

        evaluation = self._load_evaluation(
            deployment_run_id, evaluation_id, target, source_sha, now
        )
        decision = str(evaluation["gate_decision"])
        if decision == "INCONCLUSIVE":
            raise RolloutStageConflict(
                "gate decision INCONCLUSIVE cannot drive a stage transition; "
                "rollout state is unchanged"
            )

        # Idempotent convergence: if this exact evaluation already produced
        # the current durable outcome (a racing worker applied it first),
        # return the single converged record — no duplicate transition, no
        # stage regression, no conflicting failure.
        if self._already_applied(stage, evaluation, decision, target):
            return self._to_dict(stage)

        if current != expected:
            raise RolloutStageConflict(
                "expected_percentage does not match the durable stage "
                "(stale or concurrent transition)"
            )

        new_state, new_percentage, new_previous = self._resolve_transition(
            state,
            current,
            int(stage["previous_percentage"]),
            decision,
            target,
        )
        changes = {
            "state": new_state,
            "current_percentage": new_percentage,
            "previous_percentage": new_previous,
            "last_gate_evaluation_id": str(evaluation["evaluation_id"]),
            "last_gate_decision": decision,
            "observation_start": _utc(evaluation["observation_start"]),
            "observation_end": _utc(evaluation["observation_end"]),
            "updated_at": now,
        }
        updated = self.repository.update_progressive_rollout_stage(
            deployment_run_id,
            expected_current_percentage=current,
            expected_state=state,
            changes=changes,
        )
        if updated is None:
            # Atomic CAS lost: converge deterministically. If another
            # worker already applied THIS exact transition, return the
            # single durable outcome (no duplicate, no regression);
            # otherwise fail closed as a conflicting transition.
            current_row = self.repository.get_progressive_rollout_stage(
                deployment_run_id
            )
            if current_row is not None and self._already_applied(
                current_row, evaluation, decision, target
            ):
                return self._to_dict(current_row)
            raise RolloutStageConflict(
                "rollout state changed concurrently; transition rejected"
            )
        return self._to_dict(updated)

    # ------------------------------------------------------------ internals

    def _resolve_transition(
        self,
        state: str,
        current: int,
        previous: int,
        decision: str,
        target: int,
    ) -> Tuple[str, int, int]:
        """Central deterministic state-machine decision (pure).

        Returns ``(new_state, new_current, new_previous)``; percentages
        change only on promotion (``previous := current``).
        """
        if decision == "PROMOTE":
            if state not in (
                RolloutStageState.ACTIVE.value,
                RolloutStageState.PAUSED.value,
            ):
                raise RolloutStageConflict(
                    f"PROMOTE cannot advance a {state} rollout"
                )
            if current == ROLLOUT_STAGE_SEQUENCE[-1]:
                # Already at maximum exposure: the only legal "next"
                # outcome is a completion confirmation at 100%.
                if target != ROLLOUT_STAGE_SEQUENCE[-1]:
                    raise RolloutStageConflict(
                        "rollout already at 100%; only a fresh PROMOTE "
                        "evaluation targeting 100% can complete it"
                    )
                return (RolloutStageState.COMPLETED.value, current, previous)
            expected_next = NEXT_PERCENTAGE[current]
            if target != expected_next:
                raise RolloutStageConflict(
                    f"target_percentage must be exactly {expected_next} "
                    f"(never skip or reverse stages)"
                )
            return (RolloutStageState.ACTIVE.value, target, current)
        if decision == "PAUSE":
            if state not in (
                RolloutStageState.ACTIVE.value,
                RolloutStageState.PAUSED.value,
            ):
                raise RolloutStageConflict(
                    f"PAUSE cannot apply to a {state} rollout"
                )
            if target != current:
                raise RolloutStageConflict(
                    "PAUSE must target the current exposure percentage"
                )
            # Percentages are untouched: INCONCLUSIVE ≠ PAUSED ≠ ABORTED,
            # and PAUSED + PAUSE simply stays PAUSED.
            return (RolloutStageState.PAUSED.value, current, previous)
        if decision == "ABORT":
            if state not in (
                RolloutStageState.ACTIVE.value,
                RolloutStageState.PAUSED.value,
            ):
                raise RolloutStageConflict(
                    f"ABORT cannot apply to a {state} rollout"
                )
            if target != current:
                raise RolloutStageConflict(
                    "ABORT must target the current exposure percentage"
                )
            return (RolloutStageState.ABORTED.value, current, previous)
        raise RolloutStageConflict(
            f"gate decision {decision!r} cannot drive a stage transition"
        )

    def _already_applied(
        self,
        stage: Dict[str, Any],
        evaluation: Dict[str, Any],
        decision: str,
        target: int,
    ) -> bool:
        """True when THIS evaluation already produced the current durable
        outcome (concurrent-worker replay is a deterministic no-op)."""
        if str(stage["last_gate_evaluation_id"]) != str(
            evaluation["evaluation_id"]
        ):
            return False
        state = str(stage["state"])
        current = int(stage["current_percentage"])
        if decision == "PROMOTE":
            return current == target and state == RolloutStageState.ACTIVE.value
        if decision == "PAUSE":
            return (
                state == RolloutStageState.PAUSED.value
                and current == target
            )
        return False

    def _load_evaluation(
        self,
        deployment_run_id: str,
        evaluation_id: str,
        target: int,
        source_sha: str,
        now: datetime,
    ) -> Dict[str, Any]:
        """Fetch the exact presented evaluation and enforce staleness and
        identity binding — never substitute the newest evaluation."""
        evaluation = self.repository.get_progressive_release_gate_evaluation(
            evaluation_id
        )
        if evaluation is None:
            raise LookupError("gate evaluation not found")
        if str(evaluation["deployment_run_id"]) != deployment_run_id:
            raise RolloutStageConflict(
                "evaluation belongs to a different deployment"
            )
        if str(evaluation["source_sha"]).lower() != source_sha:
            raise RolloutStageConflict(
                "evaluation source_sha does not match the transition request"
            )
        if int(evaluation["target_percentage"]) != target:
            raise RolloutStageConflict(
                "target_percentage does not match the presented evaluation"
            )
        if str(evaluation["policy_version"]) != GATE_POLICY_VERSION:
            raise RolloutStageConflict(
                "evaluation policy version is not current"
            )
        if _utc(evaluation["expires_at"]) <= now:
            raise RolloutStageConflict(
                "presented evaluation is stale (expired); refusing transition"
            )
        return evaluation

    def _insert_stage(
        self,
        deployment_run_id: str,
        source_sha: str,
        evaluation: Dict[str, Any],
        target: int,
        now: datetime,
    ) -> Dict[str, Any]:
        stage = {
            "stage_state_id": _stage_state_id(deployment_run_id, source_sha),
            "deployment_run_id": deployment_run_id,
            "source_sha": source_sha,
            "repository": str(evaluation.get("repository_name") or ""),
            "current_percentage": target,
            "previous_percentage": INITIAL_PERCENTAGE,
            "state": RolloutStageState.ACTIVE.value,
            "last_gate_evaluation_id": str(evaluation["evaluation_id"]),
            "last_gate_decision": str(evaluation["gate_decision"]),
            "observation_start": _utc(evaluation["observation_start"]),
            "observation_end": _utc(evaluation["observation_end"]),
            "updated_at": now,
        }
        try:
            return self.repository.insert_progressive_rollout_stage(stage)
        except ValueError:
            # Another worker bootstrapped concurrently: converge on the
            # single durable row when it is THIS transition's outcome.
            current_row = self.repository.get_progressive_rollout_stage(
                deployment_run_id
            )
            if (
                current_row is not None
                and int(current_row["current_percentage"]) == target
                and str(current_row["state"])
                == RolloutStageState.ACTIVE.value
                and str(current_row["last_gate_evaluation_id"])
                == str(evaluation["evaluation_id"])
            ):
                return current_row
            raise RolloutStageConflict(
                "rollout state was created concurrently with a different "
                "transition; rejected"
            )

    @staticmethod
    def _to_dict(stage: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "stage_state_id": str(stage["stage_state_id"]),
            "deployment_run_id": str(stage["deployment_run_id"]),
            "source_sha": str(stage["source_sha"]),
            "repository": str(stage.get("repository") or ""),
            "current_percentage": int(stage["current_percentage"]),
            "previous_percentage": int(stage["previous_percentage"]),
            "state": str(stage["state"]),
            "last_gate_evaluation_id": str(stage["last_gate_evaluation_id"]),
            "last_gate_decision": str(stage["last_gate_decision"]),
            "observation_start": _utc(stage["observation_start"]).isoformat(),
            "observation_end": _utc(stage["observation_end"]).isoformat(),
            "updated_at": _utc(stage["updated_at"]).isoformat(),
        }


__all__ = [
    "INITIAL_PERCENTAGE",
    "InvalidRolloutStageRequest",
    "NEXT_PERCENTAGE",
    "ROLLOUT_STAGE_SEQUENCE",
    "ProgressiveRolloutStageService",
    "RolloutStageConflict",
    "RolloutStageState",
    "TERMINAL_STAGE_STATES",
]
