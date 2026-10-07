"""Phase 8.7-A — controlled traffic-mutation execution boundary.

This module defines the future mutation contract without implementing a
provider. Phase 6.7.1 remains plan/preflight-only. A concrete provider may
only be introduced after the repository has a real weighted-traffic topology
and an end-to-end proof of the provider remote-state semantics.

The contract is intentionally narrow:
* the mutation request is derived from one exact TrafficIntent;
* deployment/source/evaluation/intent identity is immutable and bound together;
* the expected pre-mutation percentage is carried for optimistic remote-state
  verification;
* provider-specific command strings, manifests, URLs, credentials and shell
  fragments are not accepted by the contract;
* the shipped default provider always fails closed because no real traffic
  provider is configured in the repository today.

Nothing in this module invokes kubectl, subprocess, HTTP writes, or a cloud SDK.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Protocol, Tuple, runtime_checkable

from incident_service.application.services.rollout_plan_service import TrafficIntent


class TrafficMutationError(RuntimeError):
    """Base failure for a traffic mutation attempt."""


class TrafficMutationProviderUnavailable(TrafficMutationError):
    """No concrete weighted-traffic provider is configured."""


class InvalidTrafficMutationRequest(ValueError):
    """The mutation request violates the provider-independent contract."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _validate_non_empty(value: Any, field: str, limit: int = 128) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidTrafficMutationRequest(f"{field} must be a non-empty string")
    value = value.strip()
    if len(value) > limit:
        raise InvalidTrafficMutationRequest(
            f"{field} must be at most {limit} characters"
        )
    return value


def _validate_source_sha(value: Any) -> str:
    if not isinstance(value, str):
        raise InvalidTrafficMutationRequest("source_sha must be a string")
    value = value.strip()
    if len(value) != 40 or any(char not in "0123456789abcdef" for char in value):
        raise InvalidTrafficMutationRequest(
            "source_sha must be the exact 40-character lowercase hex SHA"
        )
    return value


def _validate_percentage(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise InvalidTrafficMutationRequest(f"{field} must be an integer")
    if not 0 <= value <= 100:
        raise InvalidTrafficMutationRequest(f"{field} must be between 0 and 100")
    return value


def _canonical_payload(value: Dict[str, Any]) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=lambda item: (
            _utc(item).isoformat() if isinstance(item, datetime) else str(item)
        ),
    )


def _digest(value: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_payload(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TrafficMutationRequest:
    """Exact provider-independent mutation input.

    The request contains facts already established by the rollout-plan
    boundary plus the observed state that the provider must re-check before
    changing remote traffic. It deliberately contains no provider-specific
    command or credential material.
    """

    deployment_run_id: str
    source_sha: str
    gate_evaluation_id: str
    intent_id: str
    stable_target: str
    canary_target: str
    expected_current_percentage: int
    requested_percentage: int
    observed_percentage: int
    observed_at: datetime

    @classmethod
    def from_intent(cls, intent: TrafficIntent, *, observed_percentage: int, observed_at: datetime) -> "TrafficMutationRequest":
        deployment_run_id = _validate_non_empty(intent.deployment_run_id, "deployment_run_id")
        source_sha = _validate_source_sha(intent.source_sha)
        gate_evaluation_id = _validate_non_empty(intent.gate_evaluation_id, "gate_evaluation_id")
        intent_id = _validate_non_empty(intent.intent_id, "intent_id")
        stable_target = _validate_non_empty(intent.stable_target, "stable_target")
        canary_target = _validate_non_empty(intent.canary_target, "canary_target")
        expected_current = _validate_percentage(intent.current_percentage, "expected_current_percentage")
        requested = _validate_percentage(intent.requested_percentage, "requested_percentage")
        observed = _validate_percentage(observed_percentage, "observed_percentage")
        if observed != expected_current:
            raise InvalidTrafficMutationRequest(
                "observed_percentage must exactly equal the intent current_percentage before mutation"
            )
        if requested == expected_current:
            raise InvalidTrafficMutationRequest(
                "requested_percentage must differ from current exposure"
            )
        if requested < expected_current:
            raise InvalidTrafficMutationRequest(
                "traffic mutation cannot reduce exposure; rollback uses a separate control path"
            )
        return cls(
            deployment_run_id=deployment_run_id,
            source_sha=source_sha,
            gate_evaluation_id=gate_evaluation_id,
            intent_id=intent_id,
            stable_target=stable_target,
            canary_target=canary_target,
            expected_current_percentage=expected_current,
            requested_percentage=requested,
            observed_percentage=observed,
            observed_at=_utc(observed_at),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "deployment_run_id": self.deployment_run_id,
            "source_sha": self.source_sha,
            "gate_evaluation_id": self.gate_evaluation_id,
            "intent_id": self.intent_id,
            "stable_target": self.stable_target,
            "canary_target": self.canary_target,
            "expected_current_percentage": self.expected_current_percentage,
            "requested_percentage": self.requested_percentage,
            "observed_percentage": self.observed_percentage,
            "observed_at": _utc(self.observed_at).isoformat(),
        }

    def digest(self) -> str:
        """Stable integrity digest for durable evidence and idempotency binding."""
        return _digest(self.to_dict())


@dataclass(frozen=True)
class TrafficMutationResult:
    """Provider result model.

    A successful result is still only truthful after the caller performs
    post-mutation remote inspection and confirms the requested state.
    The provider cannot self-declare the rollout complete.
    """

    provider: str
    request_digest: str
    operation: str
    remote_percentage: Optional[int]
    verified: bool
    external_operation_id: Optional[str]
    detail: str = ""

    def __post_init__(self) -> None:
        _validate_non_empty(self.provider, "provider")
        _validate_non_empty(self.request_digest, "request_digest", 128)
        if self.operation not in {"APPLY", "ROLLBACK"}:
            raise InvalidTrafficMutationRequest("operation must be APPLY or ROLLBACK")
        if self.remote_percentage is not None:
            _validate_percentage(self.remote_percentage, "remote_percentage")
        if self.external_operation_id is not None:
            _validate_non_empty(self.external_operation_id, "external_operation_id", 256)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "request_digest": self.request_digest,
            "operation": self.operation,
            "remote_percentage": self.remote_percentage,
            "verified": self.verified,
            "external_operation_id": self.external_operation_id,
            "detail": self.detail,
        }


@runtime_checkable
class TrafficMutationPort(Protocol):
    """Minimal write boundary for a real weighted-traffic provider.

    Implementations must verify the request expected current state and the
    bound stable/canary identities against the provider before changing
    traffic. They must not treat the return from the write API as proof of
    the final remote state; the orchestration layer performs authoritative
    post-mutation inspection.
    """

    def apply(self, request: TrafficMutationRequest) -> TrafficMutationResult:
        """Move traffic from expected current exposure to requested exposure."""
        ...

    def rollback(self, request: TrafficMutationRequest) -> TrafficMutationResult:
        """Restore the request expected current exposure."""
        ...


class UnavailableTrafficMutationProvider:
    """Deliberately unavailable default.

    The checked-in repository has no real weighted traffic mechanism, so a
    fake provider would create a false capability. Both writes therefore
    fail closed until a concrete provider is deliberately introduced.
    """

    provider_name = "unavailable"

    def apply(self, request: TrafficMutationRequest) -> TrafficMutationResult:
        raise TrafficMutationProviderUnavailable(
            "no concrete weighted-traffic provider is configured"
        )

    def rollback(self, request: TrafficMutationRequest) -> TrafficMutationResult:
        raise TrafficMutationProviderUnavailable(
            "no concrete weighted-traffic provider is configured"
        )


def mutation_request_from_intent(intent: TrafficIntent, *, observed_percentage: int, observed_at: datetime) -> TrafficMutationRequest:
    """Build the only supported mutation command shape from an exact intent."""
    return TrafficMutationRequest.from_intent(
        intent, observed_percentage=observed_percentage, observed_at=observed_at
    )


__all__: Tuple[str, ...] = (
    "TrafficMutationError",
    "TrafficMutationProviderUnavailable",
    "InvalidTrafficMutationRequest",
    "TrafficMutationRequest",
    "TrafficMutationResult",
    "TrafficMutationPort",
    "UnavailableTrafficMutationProvider",
    "mutation_request_from_intent",
)
