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
  "the call returned", "the provider reported a value", "the provider
  accepted it" and "the remote state is now verified" are four
  different things and are never collapsed into one. A result carries
  the :class:`TrafficMutationRequest` it answers and derives
  ``request_digest`` from it, so request A can never be paired with
  request B's digest; and verification is operation-aware, because both
  operations complete the same forward request — ``APPLY`` is verified
  by the requested percentage and ``ROLLBACK`` by the percentage the
  transition started from (:func:`expected_verified_percentage`).
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


def expected_verified_percentage(
    operation: str, request: "TrafficMutationRequest"
) -> int:
    """The ONE remote observation that can verify ``operation``.

    A request describes a forward transition, and both operations are
    verified against that same request — they simply complete it from
    opposite ends:

    * ``APPLY`` moves the forward transition, so it is verified by
      observing the request's ``requested_percentage``;
    * ``ROLLBACK`` undoes that transition, so it is verified by
      observing the request's ``expected_current_percentage``.

    Deriving the rollback target from the bound request is the point:
    there is no second request shape and no caller-supplied rollback
    target, so a rollback cannot be verified against a state the
    approved transition never defined.
    """
    if operation == OP_APPLY:
        return request.requested_percentage
    if operation == OP_ROLLBACK:
        return request.expected_current_percentage
    allowed = ", ".join(TRAFFIC_MUTATION_OPERATIONS)
    raise InvalidTrafficMutationRequest(
        f"operation must be one of: {allowed}"
    )


@dataclass(frozen=True)
class TrafficMutationResult:
    """What a provider reports afterwards — bound to the exact request.

    A result does not carry a digest the caller supplies; it carries the
    :class:`TrafficMutationRequest` it answers, and
    :attr:`request_digest` is DERIVED from that request. There is
    therefore no construction path that can pair request A with request
    B's digest, and no path that can pair them by accident: the pairing
    is structural, not conventional.

    ``verified`` is the only field that claims the post-operation remote
    state, and which state that is depends on the operation. Both
    operations complete the SAME forward request, from opposite ends:

    * ``APPLY`` moves the forward transition, so it is verified only
      when ``remote_percentage == request.requested_percentage``;
    * ``ROLLBACK`` undoes it, so it is verified only when
      ``remote_percentage == request.expected_current_percentage``.

    A provider call that returned, a provider that reported a value, a
    provider that accepted the request, and a remote state that actually
    changed remain four different facts:

    * ``verified=False`` with ``remote_percentage=None`` — nothing was
      observed (or the observation is unavailable);
    * ``verified=False`` with a percentage — the provider reported a
      value, and it is recorded, but it was not proven to the standard a
      verified claim requires (true for either operation);
    * ``verified=True`` — the remote observation equals
      :attr:`expected_verified_percentage` for this exact request and
      operation.

    ``verified=False`` is a normal, representable outcome and is never
    rewritten into success.
    """

    request: TrafficMutationRequest
    provider: str
    operation: str
    remote_percentage: Optional[int]
    verified: bool
    external_operation_id: Optional[str] = None
    detail: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.request, TrafficMutationRequest):
            raise InvalidTrafficMutationRequest(
                "request must be the TrafficMutationRequest this result "
                "answers; a result is bound to a request, never to a "
                "freestanding digest"
            )
        validate_identifier(self.provider, "provider")
        if self.operation not in TRAFFIC_MUTATION_OPERATIONS:
            allowed = ", ".join(TRAFFIC_MUTATION_OPERATIONS)
            raise InvalidTrafficMutationRequest(
                f"operation must be one of: {allowed}"
            )
        if not isinstance(self.verified, bool):
            raise InvalidTrafficMutationRequest("verified must be a boolean")
        if self.remote_percentage is not None:
            validate_percentage(self.remote_percentage, "remote_percentage")
        # Verification is a claim about ONE exact remote state, and which
        # state that is depends on the operation: an APPLY is verified by
        # the requested percentage, a ROLLBACK by the percentage the
        # forward transition started from. Either way it is derived from
        # the bound request; an observation of anything else cannot
        # verify this operation, whatever the provider reported.
        if self.verified and self.remote_percentage is None:
            raise InvalidTrafficMutationRequest(
                "verified=True requires the observed remote_percentage; a "
                "verification with no observed value proves nothing"
            )
        if self.verified and self.remote_percentage != self.expected_verified_percentage:
            raise InvalidTrafficMutationRequest(
                "verified=True requires remote_percentage to equal the "
                f"remote state this {self.operation} completes "
                f"(remote={self.remote_percentage}, "
                f"expected={self.expected_verified_percentage}); an "
                "observation of a different state verifies nothing about "
                "this request"
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

    # ---- binding -----------------------------------------------------

    @property
    def request_digest(self) -> str:
        """The digest of the bound request — derived, never supplied."""
        return self.request.digest()

    @property
    def expected_verified_percentage(self) -> int:
        """The remote state that alone verifies this operation.

        ``APPLY`` -> the request's ``requested_percentage``;
        ``ROLLBACK`` -> the request's ``expected_current_percentage``.
        Derived from the bound request, never supplied by a caller.
        """
        return expected_verified_percentage(self.operation, self.request)

    @classmethod
    def from_request(
        cls,
        request: TrafficMutationRequest,
        *,
        provider: str,
        operation: str,
        remote_percentage: Optional[int],
        verified: bool,
        external_operation_id: Optional[str] = None,
        detail: str = "",
    ) -> "TrafficMutationResult":
        """The documented construction path: bind a result to a request.

        There is deliberately no ``request_digest`` parameter to pass: a
        provider returning an outcome states which request it answers,
        and the digest follows from that.
        """
        return cls(
            request=request,
            provider=provider,
            operation=operation,
            remote_percentage=remote_percentage,
            verified=verified,
            external_operation_id=external_operation_id,
            detail=detail,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialisable audit record; the derived fields are derived.

        ``request_digest`` is the digest of the bound request and
        ``expected_verified_percentage`` is the state this operation
        would have had to observe — both are recorded so a reader can
        see what the ``verified`` claim was measured against without
        recomputing it from the request.
        """
        return {
            "provider": self.provider,
            "request_digest": self.request_digest,
            "operation": self.operation,
            "remote_percentage": self.remote_percentage,
            "expected_verified_percentage": self.expected_verified_percentage,
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

    ``FORBIDDEN_PORT_MEMBERS`` names the widening this surface must
    never grow; the structural tests assert the protocol exposes exactly
    these two members.

    ``rollback(request)`` undoes the approved forward transition
    described by ``request`` — it is not handed a separately-shaped
    "backward" request, because a request can only ever describe a
    forward move (``requested > observed``). Reversing it is a distinct
    operation with its own authorisation, which is exactly why it is a
    distinct member and never a negative ``apply``. A verified rollback
    observes the request's ``expected_current_percentage``; a verified
    apply observes its ``requested_percentage``.
    """

    def apply(self, request: TrafficMutationRequest) -> TrafficMutationResult: ...

    def rollback(
        self, request: TrafficMutationRequest
    ) -> TrafficMutationResult: ...


#: The vocabulary of widening this boundary exists to prevent: verbs a
#: mutation provider must never grow alongside ``apply``/``rollback``.
#: The authoritative statement of the surface is ``TrafficMutationPort``
#: itself (exactly ``apply`` and ``rollback``), asserted structurally in
#: the tests; this tuple names the class of addition that would break it.
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


#: Structural witness for the MECHANISM surface of a candidate provider.
def is_traffic_mutation_port(candidate: Any) -> bool:
    """True when ``candidate`` offers exactly the port's callable surface.

    What this proves, precisely:

    * ``apply`` and ``rollback`` exist and are callable; and
    * no OTHER public name on the candidate is callable.

    What it does not prove, and does not claim: anything about
    non-callable public attributes (``provider_name`` is data, not
    mechanism), nor that the candidate may not have private helpers.
    Broadening the mechanism surface — growing ``execute``, ``mutate``,
    ``apply_percentage`` or a provider-specific verb — is what this
    rejects, and that is the failure mode this boundary exists to
    prevent.

    ``TrafficMutationPort`` remains the authoritative interface; a
    caller that only needs reachability can use ``isinstance`` against
    it (it is runtime-checkable). This helper adds the negative check
    that reachability alone cannot make.
    """
    if not callable(getattr(candidate, "apply", None)):
        return False
    if not callable(getattr(candidate, "rollback", None)):
        return False
    public_callables = {
        name
        for name in dir(candidate)
        if not name.startswith("_")
        and callable(getattr(candidate, name, None))
    }
    return not (public_callables - {"apply", "rollback"})


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
    "expected_verified_percentage",
    "is_traffic_mutation_port",
    "validate_identifier",
    "validate_percentage",
    "validate_source_sha",
]
