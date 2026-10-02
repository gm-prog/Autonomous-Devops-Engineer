"""Phase 6.7.1 — traffic-control boundary + deterministic rollout intent.

Plan + preflight ONLY. This module contains no mutation path of any
kind: no kubectl, no subprocess, no Kubernetes/traffic-provider write,
no HTTP PATCH/PUT. ``plan != apply`` by construction — the future
mutation lives behind a separate ``TrafficMutationPort`` in a later
phase; here the port exposes exactly ``inspect()`` (observe) and
``plan()`` (deterministic, provider-neutral rendering of intent).

Chosen traffic mechanism (documented honestly): the repository deploys
no concrete traffic-split mechanism — ``k8s/deployment.yaml`` defines a
single plain ``Service`` (``devops-gateway-loadbalancer`` selecting
``app: devops-gateway``), there is no Ingress/HTTPRoute/Gateway/
service-mesh resource, no weight field anywhere, the kubectl runner has
no traffic operations, and canary/blue-green/mesh are documented as
unsupported. Per the selection rule we therefore ship a provider-neutral
port with a deliberately *unavailable* default provider (never a fake
production provider) and a deterministic plan model. Stable/canary
targets are proven only from trusted runtime observation when a real
provider exists; the repository proves no split topology today, so
target-dependent planning fails closed with ``BLOCKED`` /
``traffic_targets_unproven`` rather than inventing names.

Separation of concerns (Argo-style): the gate asks "is the evidence
good enough?", the rollout-stage service asks "what stage are we
durably at?", this service asks "HOW WOULD traffic be changed to reach
that stage?" — and answers with a preflight status only.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Protocol, Tuple

from incident_service.application.services.progressive_release_gate_service import (
    GATE_POLICY_VERSION,
)
from incident_service.application.services.progressive_rollout_stage_service import (
    NEXT_PERCENTAGE,
    ROLLOUT_STAGE_SEQUENCE,
    TERMINAL_STAGE_STATES,
)

#: Observed traffic state vocabulary (§6).
OBSERVED_UNKNOWN = "UNKNOWN"
OBSERVED_KNOWN = "KNOWN"
OBSERVED_MATCHES_DESIRED = "MATCHES_DESIRED"
OBSERVED_DIFFERS_FROM_DESIRED = "DIFFERS_FROM_DESIRED"
OBSERVED_CONFLICT = "CONFLICT"

#: Preflight status vocabulary (§7). READY never means "mutation
#: succeeded" — no mutation exists in this phase.
PREFLIGHT_READY = "READY"
PREFLIGHT_NO_OP = "NO_OP"
PREFLIGHT_BLOCKED = "BLOCKED"
PREFLIGHT_CONFLICT = "CONFLICT"
PREFLIGHT_INCONCLUSIVE = "INCONCLUSIVE"

UNAVAILABLE_PROVIDER = "unavailable"


class TrafficProviderUnavailable(RuntimeError):
    """No traffic provider can answer inspection (fail closed)."""


class InvalidRolloutPlanRequest(ValueError):
    """Malformed plan request (maps to HTTP 422)."""


class RolloutPlanConflict(RuntimeError):
    """Plan request conflicts with durable truth (maps to HTTP 409)."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _validate_non_empty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidRolloutPlanRequest(f"{field} must be a non-empty string")
    if len(value) > 128:
        raise InvalidRolloutPlanRequest(
            f"{field} must be at most 128 characters"
        )
    return value


def _validate_requested_percentage(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise InvalidRolloutPlanRequest(
            "requested_percentage must be an integer"
        )
    if value not in ROLLOUT_STAGE_SEQUENCE:
        allowed = ", ".join(str(item) for item in ROLLOUT_STAGE_SEQUENCE)
        raise InvalidRolloutPlanRequest(
            f"requested_percentage must be one of: {allowed}"
        )
    return value


def _validate_source_sha(value: Any) -> str:
    if not isinstance(value, str):
        raise InvalidRolloutPlanRequest("source_sha must be a string")
    if len(value) != 40 or any(char not in "0123456789abcdef" for char in value):
        raise InvalidRolloutPlanRequest(
            "source_sha must be the exact 40-character lowercase hex SHA"
        )
    return value


@dataclass(frozen=True)
class ObservedTrafficState:
    """Bounded structured facts about observed traffic (§11) — never a
    fabricated metric and never a raw provider payload."""

    provider: str
    observed_status: str  # UNKNOWN | KNOWN | CONFLICT (raw provider truth)
    observed_percentage: Optional[int]
    stable_identity: Optional[str]
    canary_identity: Optional[str]
    deployment_run_id: Optional[str]
    source_sha: Optional[str]
    observation_timestamp: Optional[datetime]
    observation_source: str
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "observed_status": self.observed_status,
            "observed_percentage": self.observed_percentage,
            "stable_identity": self.stable_identity,
            "canary_identity": self.canary_identity,
            "deployment_run_id": self.deployment_run_id,
            "source_sha": self.source_sha,
            "observation_timestamp": (
                _utc(self.observation_timestamp).isoformat()
                if self.observation_timestamp is not None
                else None
            ),
            "observation_source": self.observation_source,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class TrafficIntent:
    """Deterministic desired-traffic intent derived ONLY from the
    authoritative rollout stage + the exact gate evaluation presented."""

    intent_id: str
    deployment_run_id: str
    source_sha: str
    gate_evaluation_id: str
    stable_target: Optional[str]
    canary_target: Optional[str]
    current_percentage: int
    requested_percentage: int
    created_at: datetime
    evaluated_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "intent_id": self.intent_id,
            "deployment_run_id": self.deployment_run_id,
            "source_sha": self.source_sha,
            "gate_evaluation_id": self.gate_evaluation_id,
            "stable_target": self.stable_target,
            "canary_target": self.canary_target,
            "current_percentage": self.current_percentage,
            "requested_percentage": self.requested_percentage,
            "created_at": _utc(self.created_at).isoformat(),
            "evaluated_at": _utc(self.evaluated_at).isoformat(),
        }


class TrafficControllerPort(Protocol):
    """Provider-neutral traffic-control boundary (§4).

    Only observation and deterministic plan rendering — deliberately no
    ``apply``/``mutate``/``execute`` member, so nothing in 6.7.1 can
    reach production traffic through this port. The future mutation
    belongs to a separate ``TrafficMutationPort`` (Phase 6.7.2+).
    """

    def inspect(
        self, deployment_run_id: str, source_sha: str
    ) -> ObservedTrafficState: ...

    def plan(self, intent: TrafficIntent) -> Dict[str, Any]: ...


class UnavailableTrafficController:
    """Default production provider: deliberately unavailable.

    The repository ships no traffic mechanism, and a fake provider is
    forbidden — every inspection fails closed so preflight reports
    INCONCLUSIVE instead of inventing observed state.
    """

    def inspect(
        self, deployment_run_id: str, source_sha: str
    ) -> ObservedTrafficState:
        raise TrafficProviderUnavailable(
            "no traffic provider is configured for this deployment"
        )

    def plan(self, intent: TrafficIntent) -> Dict[str, Any]:
        raise TrafficProviderUnavailable(
            "no traffic provider is configured for this deployment"
        )


class RolloutPlanService:
    """Deterministic read-only preflight over durable rollout state,
    the exact gate evaluation, and (when available) provider inspection."""

    def __init__(self, repository, controller=None, *, now_factory=None):
        self.repository = repository
        self.controller = controller or UnavailableTrafficController()
        self.now_factory = now_factory or (lambda: datetime.now(timezone.utc))

    def plan(
        self,
        deployment_run_id: Any,
        evaluation_id: Any,
        requested_percentage: Any,
        source_sha: Any,
    ) -> Dict[str, Any]:
        deployment_run_id = _validate_non_empty_string(
            deployment_run_id, "deployment_run_id"
        )
        evaluation_id = _validate_non_empty_string(
            evaluation_id, "evaluation_id"
        )
        requested = _validate_requested_percentage(requested_percentage)
        source_sha = _validate_source_sha(source_sha)
        now = _utc(self.now_factory())

        # ---- authoritative durable rollout stage (read-only)
        stage = self.repository.get_progressive_rollout_stage(deployment_run_id)
        if stage is None:
            raise LookupError("rollout state not found")
        state = str(stage["state"])
        current = int(stage["current_percentage"])
        if state in TERMINAL_STAGE_STATES:
            raise RolloutPlanConflict(
                f"rollout is terminal ({state}); no traffic plan applies"
            )
        if str(stage["source_sha"]) != source_sha:
            raise RolloutPlanConflict(
                "source_sha does not match the durable rollout stage"
            )

        # ---- exact presented gate evaluation (never substituted)
        evaluation = self.repository.get_progressive_release_gate_evaluation(
            evaluation_id
        )
        if evaluation is None:
            raise LookupError("gate evaluation not found")
        if str(evaluation["deployment_run_id"]) != deployment_run_id:
            raise RolloutPlanConflict(
                "evaluation belongs to a different deployment"
            )
        if str(evaluation["source_sha"]).lower() != source_sha:
            raise RolloutPlanConflict(
                "evaluation source_sha does not match the request"
            )
        if int(evaluation["target_percentage"]) != requested:
            raise RolloutPlanConflict(
                "requested_percentage does not match the presented evaluation"
            )
        if str(evaluation["policy_version"]) != GATE_POLICY_VERSION:
            raise RolloutPlanConflict(
                "evaluation policy version is not current"
            )
        if _utc(evaluation["expires_at"]) <= now:
            raise RolloutPlanConflict(
                "presented evaluation is stale (refusing to plan)"
            )

        # ---- stage legality (fail closed; never advances the stage)
        # PROMOTE plans forward only: 5 → 25 → 50 → 100 (no skips/
        # reversals). PAUSE/ABORT/INCONCLUSIVE decisions may only plan
        # at the current durable percentage — a different requested
        # percentage is a conflict, and none of them ever advances
        # the stage either.
        decision = str(evaluation["gate_decision"])
        if decision == "PROMOTE":
            if current == ROLLOUT_STAGE_SEQUENCE[-1]:
                if requested != ROLLOUT_STAGE_SEQUENCE[-1]:
                    raise RolloutPlanConflict(
                        "rollout already at 100%; only a plan targeting 100% "
                        "applies (completion confirmation)"
                    )
            else:
                expected_next = NEXT_PERCENTAGE[current]
                if requested != expected_next:
                    raise RolloutPlanConflict(
                        f"requested_percentage must be exactly {expected_next} "
                        f"(never skip or reverse stages)"
                    )
        elif requested != current:
            raise RolloutPlanConflict(
                f"{decision} decisions may only plan at the current "
                f"durable percentage ({current}); requested_percentage="
                f"{requested} does not match the rollout stage"
            )

        intent = TrafficIntent(
            intent_id=self._intent_id(
                deployment_run_id,
                source_sha,
                current,
                requested,
            ),
            deployment_run_id=deployment_run_id,
            source_sha=source_sha,
            gate_evaluation_id=evaluation_id,
            stable_target=None,  # proven only from trusted observation
            canary_target=None,  # the repository proves no split today
            current_percentage=current,
            requested_percentage=requested,
            created_at=now,
            evaluated_at=now,
        )

        # ---- provider inspection (never fabricates; fail closed)
        reasons = []
        try:
            raw = self.controller.inspect(deployment_run_id, source_sha)
        except TrafficProviderUnavailable as exc:
            raw = ObservedTrafficState(
                provider=UNAVAILABLE_PROVIDER,
                observed_status=OBSERVED_UNKNOWN,
                observed_percentage=None,
                stable_identity=None,
                canary_identity=None,
                deployment_run_id=None,
                source_sha=None,
                observation_timestamp=None,
                observation_source="none",
                detail=str(exc),
            )
        observed_status, observed_reasons = self._classify(raw, stage, requested)
        reasons.extend(observed_reasons)

        # ---- deterministic status resolution (policy first)
        if decision != "PROMOTE":
            reasons.insert(
                0,
                f"gate decision {decision} cannot drive a forward "
                "traffic plan; rollout state unchanged",
            )
        provider_plan: Optional[Dict[str, Any]] = None
        if decision != "PROMOTE":
            status = PREFLIGHT_BLOCKED
        elif observed_status == OBSERVED_CONFLICT:
            status = PREFLIGHT_CONFLICT
        elif observed_status == OBSERVED_UNKNOWN:
            status = PREFLIGHT_INCONCLUSIVE
            reasons.append(
                "observed traffic state cannot be established reliably"
            )
        elif observed_status == OBSERVED_MATCHES_DESIRED:
            status = PREFLIGHT_NO_OP
            reasons.append(
                "observed traffic already equals the requested target; "
                "a future mutation would be a deterministic no-op"
            )
        else:  # DIFFERS_FROM_DESIRED
            stable = raw.stable_identity
            canary = raw.canary_identity
            if not isinstance(stable, str) or not stable.strip() or not isinstance(
                canary, str
            ) or not canary.strip():
                status = PREFLIGHT_BLOCKED
                reasons.append(
                    "traffic_targets_unproven: stable/canary identities "
                    "must come from trusted runtime observation; this "
                    "repository proves no split topology"
                )
            else:
                # trusted observation proves the targets — bind the intent
                intent = TrafficIntent(
                    intent_id=intent.intent_id,
                    deployment_run_id=intent.deployment_run_id,
                    source_sha=intent.source_sha,
                    gate_evaluation_id=intent.gate_evaluation_id,
                    stable_target=stable,
                    canary_target=canary,
                    current_percentage=intent.current_percentage,
                    requested_percentage=intent.requested_percentage,
                    created_at=intent.created_at,
                    evaluated_at=intent.evaluated_at,
                )
                status = PREFLIGHT_READY
                reasons.append(
                    "identity, stage and evaluation are valid; observed "
                    "traffic differs from the requested target"
                )
                provider_plan = self.controller.plan(intent)

        evaluation_out = {
            "evaluation_id": str(evaluation["evaluation_id"]),
            "gate_decision": str(evaluation["gate_decision"]),
            "health_decision": str(evaluation["health_decision"]),
            "target_percentage": int(evaluation["target_percentage"]),
            "policy_version": str(evaluation["policy_version"]),
            "observed_at": _utc(evaluation["observed_at"]).isoformat(),
            "expires_at": _utc(evaluation["expires_at"]).isoformat(),
            "fresh": True,  # staleness already rejected above
        }
        return {
            "rollout": {
                "stage_state_id": str(stage["stage_state_id"]),
                "deployment_run_id": deployment_run_id,
                "source_sha": source_sha,
                "repository": str(stage.get("repository") or ""),
                "state": state,
                "current_percentage": current,
                "previous_percentage": int(stage["previous_percentage"]),
            },
            "evaluation": evaluation_out,
            "requested_percentage": requested,
            "intent": intent.to_dict(),
            "target_identity": {
                "stable": intent.stable_target,
                "canary": intent.canary_target,
                "proven": intent.stable_target is not None
                and intent.canary_target is not None,
            },
            "observed_traffic": raw.to_dict(),
            "observed_status": observed_status,
            "preflight_status": status,
            "reasons": reasons,
            "provider_plan": provider_plan,
        }

    @staticmethod
    def _intent_id(
        deployment_run_id: str,
        source_sha: str,
        current: int,
        requested: int,
    ) -> str:
        """Deterministic identity of the DESIRED traffic state.

        Only the four contract inputs take part — ``deployment_run_id``,
        ``source_sha``, ``current_percentage``, ``requested_percentage``.
        Never ``stage_state_id``, ``evaluation_id``, timestamps, display
        names, branches, PR titles, k8s names, image tags, or provider/
        observation output: the id identifies the desired rollout state,
        not a particular gate-evaluation instance. Two independent fresh
        evaluations of the same desired state therefore yield the same
        intent id.
        """
        canonical = f"{deployment_run_id}:{source_sha}:{current}:{requested}"
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return f"ti_{digest[:24]}"

    @staticmethod
    def _classify(
        raw: ObservedTrafficState,
        stage: Dict[str, Any],
        requested: int,
    ) -> Tuple[str, list]:
        """Map raw provider truth onto the §6 vocabulary — no guessing,
        no provider-semantics conversion beyond exact comparison."""
        reasons = []
        if raw.observed_status == OBSERVED_CONFLICT:
            reasons.append(
                "provider reported a conflicting traffic state: "
                + (raw.detail or "unspecified conflict")
            )
            return OBSERVED_CONFLICT, reasons
        # identity binding, when the provider exposes it (§5)
        observed_run = raw.deployment_run_id
        if isinstance(observed_run, str) and observed_run and observed_run != str(
            stage["deployment_run_id"]
        ):
            reasons.append(
                "observed traffic is bound to a different deployment"
            )
            return OBSERVED_CONFLICT, reasons
        observed_sha = raw.source_sha
        if isinstance(observed_sha, str) and observed_sha and observed_sha != str(
            stage["source_sha"]
        ):
            reasons.append(
                "observed traffic is bound to a different source revision"
            )
            return OBSERVED_CONFLICT, reasons
        if raw.observed_status == OBSERVED_UNKNOWN:
            reasons.append("provider observation is UNKNOWN")
            return OBSERVED_UNKNOWN, reasons
        if raw.observed_status != OBSERVED_KNOWN:
            reasons.append(
                f"provider returned unsupported observation status "
                f"{raw.observed_status!r}"
            )
            return OBSERVED_UNKNOWN, reasons
        if not isinstance(raw.observed_percentage, int) or isinstance(
            raw.observed_percentage, bool
        ):
            reasons.append(
                "provider reported KNOWN without an integer percentage"
            )
            return OBSERVED_UNKNOWN, reasons
        observed_percentage = raw.observed_percentage
        if observed_percentage < 0 or observed_percentage > 100:
            reasons.append("provider percentage outside 0-100 bounds")
            return OBSERVED_CONFLICT, reasons
        if observed_percentage > int(stage["current_percentage"]):
            # observed traffic beyond what the durable stage authorizes
            reasons.append(
                "observed traffic exceeds the durable stage's authorized "
                "exposure"
            )
            return OBSERVED_CONFLICT, reasons
        if observed_percentage == requested:
            return OBSERVED_MATCHES_DESIRED, reasons
        return OBSERVED_DIFFERS_FROM_DESIRED, reasons


__all__ = [
    "OBSERVED_CONFLICT",
    "OBSERVED_DIFFERS_FROM_DESIRED",
    "OBSERVED_KNOWN",
    "OBSERVED_MATCHES_DESIRED",
    "OBSERVED_UNKNOWN",
    "PREFLIGHT_BLOCKED",
    "PREFLIGHT_CONFLICT",
    "PREFLIGHT_INCONCLUSIVE",
    "PREFLIGHT_NO_OP",
    "PREFLIGHT_READY",
    "InvalidRolloutPlanRequest",
    "ObservedTrafficState",
    "RolloutPlanConflict",
    "RolloutPlanService",
    "TrafficControllerPort",
    "TrafficIntent",
    "TrafficProviderUnavailable",
    "UnavailableTrafficController",
]
