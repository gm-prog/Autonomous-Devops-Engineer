"""Phase 8.7-A — controlled traffic-mutation boundary (contract only).

Phase 6.7.1 answers "HOW WOULD traffic change to reach this stage?" and
is deliberately read-only: ``TrafficControllerPort`` exposes exactly
``inspect()`` and ``plan()``, and ``RolloutPlanService`` returns a
preflight status. This module is the separate boundary that a real
mutation would eventually cross, and it ships the contract for that
crossing — nothing more:

    gate evaluation -> rollout stage state -> traffic planning
        -> traffic mutation (this boundary)

What is here
------------
* :class:`TrafficMutationRequest` — the complete authority a provider
  would need: the exact deployment run, source revision, gate
  evaluation, rollout intent, the trusted stable and canary targets,
  the expected current percentage, the requested next percentage, the
  percentage actually OBSERVED immediately before the mutation, and the
  observation timestamp. Validated at construction time.
* :func:`TrafficMutationRequest.from_traffic_intent` — builds a request
  from the repository's existing ``TrafficIntent``, preserving its
  identity (intent id, run, SHA, gate evaluation, targets) and binding
  it to the freshly observed state. There is no second identity scheme.
* :meth:`TrafficMutationRequest.digest` / :meth:`TrafficMutationRequest.to_dict`
  — a deterministic SHA-256 over a canonical, stable-order payload, for
  auditability, idempotency and evidence correlation.
* :class:`TrafficMutationResult` — the outcome vocabulary, in which
  "the call returned", "the provider accepted it" and "the remote state
  is now verified at the requested percentage" are three different
  things and are never collapsed into one.
* :class:`TrafficMutationPort` — exactly ``apply()`` and ``rollback()``.
* :class:`UnavailableTrafficMutationProvider` — the default provider,
  which raises :class:`TrafficMutationProviderUnavailable` and never
  returns a fake success.

What is deliberately NOT here
-----------------------------
No kubectl, no subprocess, no Kubernetes/cloud/service-mesh client, no
HTTP, no DNS or load-balancer call, no shell. The repository's
checked-in topology is a single plain ``Service`` selecting one
``Deployment`` with a rolling update strategy, an HPA and a ConfigMap
(``k8s/deployment.yaml``) — it does not establish a weighted
stable/canary routing mechanism, so there is nothing honest to mutate
yet and the default stays fail-closed. Phase 8.7-B is the phase in
which a real provider may be added, and only once the prerequisites
recorded in ``docs/PHASE-8.7-A-TRAFFIC-MUTATION-BOUNDARY.md`` hold.

A ``READY`` preflight from Phase 6.7.1 is not evidence that traffic
changed; a mutation is only proven by a verified remote observation
after the fact.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Protocol, Tuple, runtime_checkable

from incident_service.application.services.rollout_plan_service import (
    TrafficIntent,
)

#: Canonical payload version for the request digest.
TRAFFIC_MUTATION_REQUEST_VERSION = "traffic-mutation-request-v1"

#: Operation vocabulary for :class:`TrafficMutationResult`.
OP_APPLY = "APPLY"
OP_ROLLBACK = "ROLLBACK"
TRAFFIC_MUTATION_OPERATIONS: Tuple[str, ...] = (OP_APPLY, OP_ROLLBACK)

#: Result ``provider`` value used when no provider acted at all (the
#: fail-closed default). A result carrying it can never be ``verified``.
UNAVAILABLE_PROVIDER = "unavailable"

#: Bounds on the identifier strings a request carries.
MAX_IDENTIFIER_LENGTH = 128
MAX_DETAIL_LENGTH = 512


class TrafficMutationError(RuntimeError):
    """Base failure for the traffic-mutation boundary."""


class InvalidTrafficMutationRequest(ValueError):
    """A mutation request that is malformed, unbound or stale.

    Raised at construction time, so a provider is never handed a
    request whose authority cannot be established.
    """


class TrafficMutationProviderUnavailable(TrafficMutationError):
    """No traffic provider can mutate (the default, fail-closed case).

    This is raised, never returned as a result: a provider that cannot
    act must not produce an object that looks like an outcome.
    """


# --------------------------------------------------------------------------
# validation helpers (host-side, provider-neutral)
# --------------------------------------------------------------------------


def _utc(value: datetime) -> datetime:
    """Normalise a timestamp to timezone-aware UTC."""
    if not isinstance(value, datetime):
        raise InvalidTrafficMutationRequest("observed_at must be a datetime")
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def validate_identifier(value: Any, field: str) -> str:
    """A non-empty, bounded string. No trimming, no coercion, no guess."""
    if not isinstance(value, str) or not value.strip():
        raise InvalidTrafficMutationRequest(f"{field} must be a non-empty string")
    if len(value) > MAX_IDENTIFIER_LENGTH:
        raise InvalidTrafficMutationRequest(
            f"{field} must be at most {MAX_IDENTIFIER_LENGTH} characters"
        )
    return value


def validate_source_sha(value: Any) -> str:
    """Exactly 40 lowercase hex characters. Mixed case is rejected."""
    if not isinstance(value, str):
        raise InvalidTrafficMutationRequest("source_sha must be a string")
    if len(value) != 40:
        raise InvalidTrafficMutationRequest(
            "source_sha must be exactly 40 characters"
        )
    if any(char not in "0123456789abcdef" for char in value):
        raise InvalidTrafficMutationRequest(
            "source_sha must be lowercase hexadecimal"
        )
    return value


def validate_request_digest(value: Any) -> str:
    """A request digest is one of *our* digests: 64 lowercase hex.

    The field exists so a result can be correlated with the exact
    request it answers; a truncated or invented value cannot correlate
    with anything and is refused.
    """
    if not isinstance(value, str):
        raise InvalidTrafficMutationRequest("request_digest must be a string")
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise InvalidTrafficMutationRequest(
            "request_digest must be a 64-character lowercase sha256 hex digest"
        )
    return value


def validate_percentage(value: Any, field: str) -> int:
    """An honest integer in ``[0, 100]``.

    ``bool`` is a subclass of ``int`` in Python, so ``True`` would
    otherwise pass as ``1``. A percentage is never a boolean.
    """
    if isinstance(value, bool):
        raise InvalidTrafficMutationRequest(
            f"{field} must be an integer, not a boolean"
        )
    if not isinstance(value, int):
        raise InvalidTrafficMutationRequest(f"{field} must be an integer")
    if value < 0 or value > 100:
        raise InvalidTrafficMutationRequest(
            f"{field} must be within [0, 100]"
        )
    return value


# --------------------------------------------------------------------------
# the request
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class TrafficMutationRequest:
    """The complete, self-contained authority for one traffic mutation.

    Every identity-critical value travels with the request, so a
    provider never has to look up, derive or guess anything — and a
    request that a provider cannot fully justify is refused before the
    provider sees it.
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

    def __post_init__(self) -> None:
        # ---- required identities -------------------------------------
        validate_identifier(self.deployment_run_id, "deployment_run_id")
        validate_identifier(self.gate_evaluation_id, "gate_evaluation_id")
        validate_identifier(self.intent_id, "intent_id")
        validate_identifier(self.stable_target, "stable_target")
        validate_identifier(self.canary_target, "canary_target")
        validate_source_sha(self.source_sha)

        # ---- exposure arithmetic -------------------------------------
        expected = validate_percentage(
            self.expected_current_percentage, "expected_current_percentage"
        )
        requested = validate_percentage(
            self.requested_percentage, "requested_percentage"
        )
        observed = validate_percentage(
            self.observed_percentage, "observed_percentage"
        )

        # The provider boundary must know what was ACTUALLY observed
        # immediately before the mutation. A valid requested target is
        # not a substitute for that observation.
        if observed != expected:
            raise InvalidTrafficMutationRequest(
                "observed_percentage must equal expected_current_percentage "
                f"(observed={observed}, expected={expected}); the observed "
                "state is what is mutated from, and it must match the state "
                "the intent was built on"
            )

        # A mutation request is an actual forward transition.
        if requested == expected:
            raise InvalidTrafficMutationRequest(
                f"requested_percentage must differ from "
                f"expected_current_percentage ({expected}); a no-op is not "
                "a mutation"
            )

        # Rollback is a separate operation and must never be smuggled
        # through apply() as a negative step.
        if requested < expected:
            raise InvalidTrafficMutationRequest(
                f"requested_percentage ({requested}) must not be lower than "
                f"expected_current_percentage ({expected}); a backward move "
                "is a rollback and must be requested as one"
            )

        object.__setattr__(self, "observed_at", _utc(self.observed_at))

    # ---- construction from the existing intent -----------------------

    @classmethod
    def from_traffic_intent(
        cls,
        intent: TrafficIntent,
        *,
        observed_percentage: int,
        observed_at: datetime,
    ) -> "TrafficMutationRequest":
        """Build a request from the repository's existing rollout intent.

        The intent's identity is preserved exactly: ``intent_id``,
        ``deployment_run_id``, ``source_sha`` and ``gate_evaluation_id``
        are copied, and the requested percentage is the intent's
        ``requested_percentage``. What the intent cannot carry — the
        percentage observed immediately before the mutation and when —
        is supplied by the caller and then validated against the
        intent's own ``current_percentage``: if the observed state does
        not match what the intent was built on, the request is refused.

        ``TrafficIntent`` leaves both targets ``None`` until trusted
        observation proves them (the repository proves no split
        topology today); such an intent cannot produce a mutation
        request, because nobody would be given a target to mutate.
        """
        if not isinstance(intent, TrafficIntent):
            raise InvalidTrafficMutationRequest(
                "intent must be a TrafficIntent from the rollout plan service"
            )
        stable = intent.stable_target
        canary = intent.canary_target
        if not isinstance(stable, str) or not stable.strip():
            raise InvalidTrafficMutationRequest(
                "stable_target must be proven by trusted observation before "
                "a mutation can be requested"
            )
        if not isinstance(canary, str) or not canary.strip():
            raise InvalidTrafficMutationRequest(
                "canary_target must be proven by trusted observation before "
                "a mutation can be requested"
            )
        return cls(
            deployment_run_id=intent.deployment_run_id,
            source_sha=intent.source_sha,
            gate_evaluation_id=intent.gate_evaluation_id,
            intent_id=intent.intent_id,
            stable_target=stable,
            canary_target=canary,
            expected_current_percentage=intent.current_percentage,
            requested_percentage=intent.requested_percentage,
            observed_percentage=observed_percentage,
            observed_at=observed_at,
        )

    # ---- canonical representation and digest -------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Canonical field order, JSON-safe values, no implicit clock."""
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
        """Deterministic SHA-256 over the complete canonical payload.

        Every identity-critical field participates, so a change to any
        of them changes the digest. The field order is fixed here rather
        than taken from dict insertion order, the encoding is explicit,
        and nothing (no clock, no memory address, no random value) is
        generated while hashing — two equivalent requests always digest
        to the same value.
        """
        payload = self.to_dict()
        blob = json.dumps(
            {"version": TRAFFIC_MUTATION_REQUEST_VERSION, **payload},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# the result
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class TrafficMutationResult:
    """What a provider reports afterwards — with verification kept honest.

    ``verified`` is the only field that claims the remote state is now
    the requested one. A provider call that returned, a provider that
    accepted the request, and a remote state that actually changed are
    three different facts; ``verified=False`` is a normal, representable
    outcome and is never rewritten into success.
    """

    provider: str
    request_digest: str
    operation: str
    remote_percentage: Optional[int]
    verified: bool
    external_operation_id: Optional[str] = None
    detail: str = ""

    def __post_init__(self) -> None:
        validate_identifier(self.provider, "provider")
        validate_request_digest(self.request_digest)
        if self.operation not in TRAFFIC_MUTATION_OPERATIONS:
            allowed = ", ".join(TRAFFIC_MUTATION_OPERATIONS)
            raise InvalidTrafficMutationRequest(
                f"operation must be one of: {allowed}"
            )
        if not isinstance(self.verified, bool):
            raise InvalidTrafficMutationRequest("verified must be a boolean")
        if self.remote_percentage is not None:
            validate_percentage(self.remote_percentage, "remote_percentage")
        # Verification means the remote state was actually observed at the
        # requested percentage. Claiming it without stating the observed
        # value would be a claim about nothing.
        if self.verified and self.remote_percentage is None:
            raise InvalidTrafficMutationRequest(
                "verified=True requires the observed remote_percentage; a "
                "verification with no observed value proves nothing"
            )
        # The unavailable provider raises rather than returning, so a
        # result attributed to it that also claims verification is a
        # contradiction by construction.
        if self.verified and self.provider == UNAVAILABLE_PROVIDER:
            raise InvalidTrafficMutationRequest(
                "the unavailable provider cannot have verified anything"
            )
        if self.external_operation_id is not None:
            validate_identifier(
                self.external_operation_id, "external_operation_id"
            )
        if not isinstance(self.detail, str):
            raise InvalidTrafficMutationRequest("detail must be a string")
        if len(self.detail) > MAX_DETAIL_LENGTH:
            raise InvalidTrafficMutationRequest(
                f"detail must be at most {MAX_DETAIL_LENGTH} characters"
            )

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


# --------------------------------------------------------------------------
# the port
# --------------------------------------------------------------------------


@runtime_checkable
class TrafficMutationPort(Protocol):
    """Provider-neutral mutation boundary: exactly ``apply``/``rollback``.

    Deliberately NOT here: ``inspect``/``plan`` (that is
    ``TrafficControllerPort``, Phase 6.7.1, and stays separate),
    ``execute``/``mutate``/``apply_percentage`` (open-ended execution
    verbs), and any provider-specific member (Kubernetes, mesh, cloud).
    A small surface is the point: every future provider must be
    auditable against this list and nothing else.

    ``rollback(request)`` undoes the approved forward transition
    described by ``request`` — it is not handed a separately-shaped
    "backward" request, because a request can only ever describe a
    forward move (``requested > observed``). Reversing it is a distinct
    operation with its own authorisation, which is exactly why it is a
    distinct member and never a negative ``apply``.
    """

    def apply(self, request: TrafficMutationRequest) -> TrafficMutationResult: ...

    def rollback(
        self, request: TrafficMutationRequest
    ) -> TrafficMutationResult: ...


#: Members no mutation provider may add to this boundary.
FORBIDDEN_PORT_MEMBERS: Tuple[str, ...] = (
    "inspect",
    "plan",
    "execute",
    "mutate",
    "apply_percentage",
)


class UnavailableTrafficMutationProvider:
    """The default provider: it refuses, loudly, and simulates nothing.

    This is not a stub that pretends to succeed, and not a provider that
    writes a local percentage and calls it a traffic change. It raises,
    so a caller cannot mistake "nothing happened" for "traffic moved".
    """

    provider_name = UNAVAILABLE_PROVIDER

    def apply(self, request: TrafficMutationRequest) -> TrafficMutationResult:
        raise TrafficMutationProviderUnavailable(
            "no traffic-mutation provider is configured; the repository "
            "does not establish a weighted stable/canary topology, so "
            "traffic cannot be mutated (fail closed)"
        )

    def rollback(
        self, request: TrafficMutationRequest
    ) -> TrafficMutationResult:
        raise TrafficMutationProviderUnavailable(
            "no traffic-mutation provider is configured; rollback of a "
            "traffic mutation is unavailable (fail closed)"
        )


#: Structural witness that an object satisfies the boundary contract.
def is_traffic_mutation_port(candidate: Any) -> bool:
    """True only when ``candidate`` exposes exactly the port contract.

    The check is member-based rather than isinstance-based so it also
    rejects a candidate that has grown extra mutation verbs
    (``execute``, ``mutate``, ``apply_percentage``, ...) — broadening the
    surface is the failure mode this boundary exists to prevent.
    """
    if not callable(getattr(candidate, "apply", None)):
        return False
    if not callable(getattr(candidate, "rollback", None)):
        return False
    return not any(
        hasattr(candidate, member) for member in FORBIDDEN_PORT_MEMBERS
    )


#: Public surface of this module (import * must stay explicit).
__all__ = [
    "FORBIDDEN_PORT_MEMBERS",
    "InvalidTrafficMutationRequest",
    "MAX_DETAIL_LENGTH",
    "MAX_IDENTIFIER_LENGTH",
    "OP_APPLY",
    "OP_ROLLBACK",
    "TRAFFIC_MUTATION_OPERATIONS",
    "TRAFFIC_MUTATION_REQUEST_VERSION",
    "TrafficMutationError",
    "TrafficMutationPort",
    "TrafficMutationProviderUnavailable",
    "TrafficMutationRequest",
    "TrafficMutationResult",
    "UNAVAILABLE_PROVIDER",
    "UnavailableTrafficMutationProvider",
    "is_traffic_mutation_port",
    "validate_identifier",
    "validate_request_digest",
    "validate_percentage",
    "validate_source_sha",
]
