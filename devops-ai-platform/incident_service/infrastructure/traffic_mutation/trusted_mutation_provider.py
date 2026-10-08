"""Phase 8.7-B.2 — the trusted traffic mutation provider.

This is the first production-shaped capability in the repository that is
allowed to change traffic. Its whole design is the answer to one question:
*how do we make an incorrect, stale, ambiguous, duplicated, unauthorized or
unverifiable request unable to become a successful mutation?*

The lifecycle it implements, in order, with no skipping:

    approved TrafficMutationRequest (exact authority, derived digest)
                │
                ▼
    execution claim  ────────── duplicate / concurrent attempt ──► REFUSE
                │
                ▼
    fresh B.1 observation  ──── UNKNOWN / CONFLICT / wrong target /
                │               stale current state / unbound  ──► REFUSE
                ▼  KNOWN + trusted identity + controller authority
    exact authorized mutation (one bounded CAS write)
                │
                ▼
    fresh B.1 observation  ──── wrong state / unavailable ────────► VERIFIED=False
                │  remote == the state this operation completes
                ▼
    TrafficMutationResult(verified=True) + durable evidence record

Design decisions an auditor will ask about, stated where they are made:

**One interpretation of the topology.** The provider never re-implements
what B.1 already interprets. Track identity, endpoint disjointness,
configured share, controller acceptance and the binding rule all come from
:class:`~incident_service.infrastructure.traffic.gateway_api_observer.KubernetesTrafficObserver`.
The provider adds exactly two things on top: a stricter *authority* rule
(see below), and the write itself.

**Controller authority is required, and it is stricter than observation.**
B.1's hardening already makes an observation ``KNOWN`` only when the
controller reports ``Accepted=True``. For *mutation authority* this provider
additionally requires ``ResolvedRefs=True`` and
``controller observedGeneration == route metadata.generation`` at the
precondition. The freshness relationship therefore is: the controller must
have observed the *exact current* generation of the route the provider is
about to change. A route that is still reconciling, or one whose status
predates its spec, is not authority to write — the provider refuses rather
than guessing. (The postcondition deliberately does *not* require the
controller to have caught up with the write; it requires the *spec* — what
the provider actually changed — to be observed exactly, and separates the
controller facts into the evidence.)

**The write is a compare-and-set, not a read-then-write.** The patch carries
RFC 6902 ``test`` operations on the route's ``resourceVersion`` *and* on each
weight it is about to replace, so the API server rejects the entire write if
the route moved between the observation and the mutation. A lost race is
therefore an API-server rejection with a two-valued classification, never a
stale write. There is no client-side lock pretending to be a transaction.

**Exactly one bounded attempt, ever.** No retry loop exists. An accepted
write and a failed write are both followed by a fresh observation; a write
whose answer was lost is classified ``unknown`` and resolved *only* by
observing the remote state. "Patch again" is never a response to an unknown
outcome, because the first patch may have landed.

**Verification is a remote-state claim, not a causality claim.**
``verified=True`` means exactly what the frozen Phase 8.7-A contract says:
the fresh post-mutation observation equals the state this operation
completes (``APPLY`` → ``request.requested_percentage``, ``ROLLBACK`` →
``request.expected_current_percentage``). Whether *this* call is what
produced that state is a separate, separately recorded fact
(``causality`` in the evidence): a write the API server refused, followed by
a remote state that matches the target, is reported ``verified=False`` —
the provider does not claim a mutation it did not perform.

**Classification precedence is explicit.** When more than one statement is
true of the same outcome, the record says which one it reports, and the
remaining facts stay in their own fields rather than being merged:

1. the post-state cannot be observed → ``unverified:postcondition-not-established``;
2. the post-state equals the target → verified (or the "another actor got
   there, not this write" refusal);
3. the post-state still equals the pre-state →
   ``failed:write-did-not-change-the-state`` (with the attempt's own outcome —
   including a server rejection — recorded beside it);
4. the post-state is a third state → ``refused:conflict``, even when this
   write was also rejected by the server, because the *state* is what an
   operator has to reconcile. ``causality`` still reports what this write
   did, so the refusal never hides it.

**Refusals are results, not silence.** A refusal returns
``verified=False`` with a bounded reason and a machine-readable evidence
record; nothing is swallowed and nothing is upgraded. Only a malformed
*request object* raises (the request is validated at construction, so the
provider never sees one it cannot justify).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional, Protocol, Sequence, Tuple

from incident_service.application.services.traffic_mutation_boundary import (
    OP_APPLY,
    OP_ROLLBACK,
    TRAFFIC_MUTATION_OPERATIONS,
    InvalidTrafficMutationRequest,
    TrafficMutationRequest,
    TrafficMutationResult,
    expected_verified_percentage,
    validate_percentage,
)
from incident_service.infrastructure.traffic.gateway_api_observer import (
    OBSERVED_KNOWN,
    TrafficObservation,
)
from incident_service.infrastructure.traffic_mutation.kubernetes_mutation_client import (
    ATTEMPT_ACCEPTED,
    ATTEMPT_REJECTED,
    ATTEMPT_UNKNOWN,
    BackendWeightChange,
    KubernetesMutationClient,
    MutationAttempt,
    MutationWriteError,
    WeightMutation,
)
from incident_service.infrastructure.traffic.kubernetes_read_client import (
    redact,
)

#: Provider identity recorded on every result and every evidence record.
PROVIDER_NAME = "trusted-kubernetes-gateway-api"

#: Evidence schema and version: a record is self-describing, so an auditor
#: reading a sealed artifact knows exactly what shape it is looking at.
EVIDENCE_SCHEMA = "traffic-mutation-evidence-v1"

#: The exact percentage→weight mapping this provider writes. Percentage is
#: what the request authorizes; weights are what the route stores; the
#: mapping is exact integer arithmetic because every integer percentage in
#: ``[0, 100]`` is representable over a denominator of 100. There is no
#: rounding step anywhere, and no pair whose ratio differs from the
#: authorized percentage can be produced.
WEIGHT_DENOMINATOR = 100

#: Classification vocabulary for evidence. Every record carries exactly one.
CLASSIFICATION_VERIFIED = "verified:write-accepted-and-observed"
CLASSIFICATION_VERIFIED_UNKNOWN_ATTEMPT = "verified:remote-state-after-unknown-attempt"
CLASSIFICATION_REPLAY = "already-applied:idempotent-replay"
CLASSIFICATION_ALREADY_APPLIED = "already-applied:unattributed"
CLASSIFICATION_REFUSED_CLAIM = "refused:concurrent-claim"
CLASSIFICATION_REFUSED_OBSERVATION = "refused:observation-unavailable"
CLASSIFICATION_REFUSED_AUTHORITY = "refused:authority"
CLASSIFICATION_REFUSED_PRECONDITION = "refused:precondition"
CLASSIFICATION_REFUSED_CONFLICT = "refused:conflict"
CLASSIFICATION_REFUSED_ATTEMPT = "refused:write-refused-by-server"
CLASSIFICATION_FAILED_ATTEMPT = "failed:write-did-not-change-the-state"
CLASSIFICATION_UNVERIFIED = "unverified:postcondition-not-established"

#: Causality vocabulary: what the evidence may and may not claim about who
#: produced the observed post-state.
CAUSALITY_WRITE_ACCEPTED = "this-write-accepted-and-observed"
CAUSALITY_UNKNOWN_ATTEMPT = "observed-desired-after-unknown-attempt"
CAUSALITY_NO_ATTEMPT = "no-attempt-in-this-call"
CAUSALITY_ATTEMPT_REFUSED = "this-write-refused-by-server"
CAUSALITY_NOT_APPLIED = "this-write-did-not-change-the-state"

#: How old the observation a request carries may be before the provider
#: refuses to act on it. The provider takes its own fresh observation
#: regardless — this bound is about the *request's* provenance: a request
#: built on a stale observation is a stale decision, even if the topology
#: now happens to look convenient.
DEFAULT_MAX_REQUEST_AGE_SECONDS = 300

#: Tolerance for a request whose carried observation is slightly ahead of
#: this process's clock. Beyond this, time is not a fact the provider can
#: trust, and it refuses rather than guessing which clock is right.
DEFAULT_MAX_CLOCK_SKEW_SECONDS = 60

#: Bounds on evidence text, mirroring the read adapter's discipline.
MAX_REASON_LENGTH = 400
MAX_FINDINGS_IN_EVIDENCE = 4


# --------------------------------------------------------------------------
# exact percentage ↔ weight mapping
# --------------------------------------------------------------------------


def percentage_to_weights(percentage: Any) -> Tuple[int, int]:
    """The exact ``(stable_weight, canary_weight)`` pair for a percentage.

    Gateway API weights are proportional, so the pair must *represent* the
    authorized percentage exactly. Over the denominator this provider writes
    (100) that is possible for every integer percentage, and the mapping is
    therefore integer arithmetic with no rounding:

        percentage 5   -> (95, 5)
        percentage 25  -> (75, 25)
        percentage 100 -> (0, 100)
        percentage 0   -> (100, 0)

    A percentage that is not an integer in ``[0, 100]`` is refused here, and
    a pair whose ratio is not exactly the percentage can be neither produced
    nor written (the client validates the pair, and the observer re-derives
    the percentage from the live weights after the write).
    """
    value = validate_percentage(percentage, "percentage")
    return (WEIGHT_DENOMINATOR - value, value)


def percentage_from_weights(stable_weight: int, canary_weight: int) -> int:
    """The exact integer percentage two weights represent, or refuse.

    The inverse of :func:`percentage_to_weights`, and the same rule the read
    adapter applies to live weights: a pair that does not sum to the
    denominator, or that is not an integer pair, has no exact percentage —
    and an inexact share is never rounded into one.
    """
    for label, value in (("stable_weight", stable_weight),
                         ("canary_weight", canary_weight)):
        if not isinstance(value, int) or isinstance(value, bool):
            raise InvalidTrafficMutationRequest(f"{label} must be an integer")
        if value < 0:
            raise InvalidTrafficMutationRequest(f"{label} must not be negative")
    if stable_weight + canary_weight != WEIGHT_DENOMINATOR:
        raise InvalidTrafficMutationRequest(
            f"weights {stable_weight}/{canary_weight} do not sum to "
            f"{WEIGHT_DENOMINATOR}, so they do not represent one percentage"
        )
    return canary_weight


# --------------------------------------------------------------------------
# concurrency / idempotency registry
# --------------------------------------------------------------------------


class MutationClaimConflict(RuntimeError):
    """Another attempt for the same request digest and operation is in flight.

    Raised before any cluster access: a concurrent duplicate is refused at
    the claim, never by racing it into the topology. The conflicting claim's
    id travels with the exception so the refusal can name it in evidence
    instead of merely asserting that somebody else was there.
    """

    def __init__(self, detail: str, *, claim_id: Optional[str] = None) -> None:
        super().__init__(detail)
        self.claim_id = claim_id


class MutationAttemptRegistry(Protocol):
    """Owner of the digest-scoped single-flight/idempotency record.

    The repository's durable ``execution_claims`` mechanism belongs to
    incident/proposal execution (``claim_execution_lease(incident_id,
    proposal_id, …)``): it is keyed by an incident aggregate and a proposal
    hash, and a traffic mutation has neither. Rather than bend that table
    into a meaning it does not have, B.2 takes a registry through this port:
    the default is in-memory and process-local, and a durable implementation
    can be injected where the control plane has a store. What the registry
    provides is single-flight and replay recognition; the *authoritative*
    race guard is the write's own compare-and-set (§ design above), which
    holds across processes, replicas and actors.
    """

    def claim(self, request_digest: str, operation: str, now: datetime) -> Mapping[str, Any]:
        """Take ownership of one attempt, or raise :class:`MutationClaimConflict`."""

    def finish(
        self,
        claim: Mapping[str, Any],
        *,
        state: str,
        verified: bool,
        detail: str,
        now: datetime,
    ) -> None:
        """Record the terminal state of one attempt."""

    def completed(self, request_digest: str, operation: str) -> Optional[Mapping[str, Any]]:
        """The completed record for this digest/operation, if one exists."""


@dataclass
class InMemoryMutationAttemptRegistry:
    """Process-local claim/replay registry (the default).

    Bounded by construction: it keeps one record per (digest, operation),
    never a log, and a claim that is never finished expires after
    ``claim_ttl_seconds`` so a crashed attempt cannot wedge the digest
    forever. Losing the process loses the records — which is exactly why
    every refusal and completion is also written into the provider's
    evidence, and why verification never depends on a registry record.
    """

    claim_ttl_seconds: float = 120.0
    _records: Dict[Tuple[str, str], Dict[str, Any]] = field(default_factory=dict)
    #: Completed *verified* attempts, kept separately from the live claim so
    #: that taking a new claim can never erase the memory a duplicate request
    #: is recognised by. Bounded by (digest, operation) pairs, like the claims.
    _completed: Dict[Tuple[str, str], Dict[str, Any]] = field(default_factory=dict)
    _sequence: int = 0

    def claim(self, request_digest: str, operation: str, now: datetime) -> Mapping[str, Any]:
        if not isinstance(request_digest, str) or len(request_digest) != 64:
            raise MutationClaimConflict("a claim requires the request's 64-character digest")
        if operation not in TRAFFIC_MUTATION_OPERATIONS:
            raise MutationClaimConflict(f"unknown operation {operation!r}")
        key = (request_digest, operation)
        existing = self._records.get(key)
        if existing is not None and existing["state"] == "in-flight":
            if _utc(existing["expires_at"]) > _utc(now):
                raise MutationClaimConflict(
                    f"another {operation} attempt for this request is in flight "
                    f"(claim {existing['claim_id']})",
                    claim_id=str(existing["claim_id"]),
                )
        self._sequence += 1
        claimed_at = _utc(now)
        claim = {
            "claim_id": f"clm_{request_digest[:16]}_{self._sequence}",
            "request_digest": request_digest,
            "operation": operation,
            "state": "in-flight",
            "claimed_at": claimed_at,
            "expires_at": claimed_at + timedelta(seconds=self.claim_ttl_seconds),
            "verified": False,
            "detail": "",
        }
        self._records[key] = claim
        return dict(claim)

    def finish(
        self,
        claim: Mapping[str, Any],
        *,
        state: str,
        verified: bool,
        detail: str,
        now: datetime,
    ) -> None:
        key = (str(claim.get("request_digest")), str(claim.get("operation")))
        record = self._records.get(key)
        if record is None or record.get("claim_id") != claim.get("claim_id"):
            # A finish from an expired/replaced claim must not overwrite the
            # owner's terminal state; the evidence record still carries it.
            return
        record["state"] = str(state)
        record["verified"] = bool(verified)
        record["detail"] = redact(detail, limit=200)
        record["finished_at"] = _utc(now)
        if verified:
            # Only a verified completion is remembered as "this provider
            # performed this mutation". A refusal leaves no such claim.
            self._completed[key] = dict(record)

    def completed(self, request_digest: str, operation: str) -> Optional[Mapping[str, Any]]:
        record = self._completed.get((request_digest, operation))
        return dict(record) if record is not None else None


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise MutationWriteError("a timestamp is required")
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


# --------------------------------------------------------------------------
# the provider
# --------------------------------------------------------------------------


class TrustedTrafficMutationProvider:
    """Implements :class:`TrafficMutationPort` against one weighted route.

    The provider is an *executor of authority*, never a creator of it: it
    accepts an already-validated :class:`TrafficMutationRequest`, and every
    identity it acts on (run, source revision, targets, current percentage)
    is re-derived from a fresh trusted observation and compared against that
    request. It never fills in a missing field, never updates the request,
    and never decides on its own that a transition would be reasonable.

    Its public callable surface is exactly ``apply``/``rollback`` (asserted
    by the tests), so it cannot be widened into a generic executor without
    failing the port contract.
    """

    provider_name = PROVIDER_NAME

    def __init__(
        self,
        *,
        read_client: Any,
        observer: Any,
        mutation_client: Optional[KubernetesMutationClient] = None,
        route_name: str,
        namespace: str,
        app_label: str,
        expected_deployment_run_id: Optional[str] = None,
        expected_source_sha: Optional[str] = None,
        registry: Optional[MutationAttemptRegistry] = None,
        now_factory: Optional[Any] = None,
        max_request_age_seconds: int = DEFAULT_MAX_REQUEST_AGE_SECONDS,
        max_clock_skew_seconds: int = DEFAULT_MAX_CLOCK_SKEW_SECONDS,
    ) -> None:
        if read_client is None:
            raise MutationWriteError("a read client is required (B.1 is the authority)")
        if observer is None:
            raise MutationWriteError(
                "the B.1 observer is required: there is one authoritative "
                "interpretation of live topology, and this provider uses it"
            )
        if mutation_client is None:
            raise MutationWriteError(
                "a mutation client is required; this provider does not build "
                "kubectl invocations itself"
            )
        self._read_client = read_client
        self._observer = observer
        self._mutation_client = mutation_client
        self._route_name = _require_name(route_name, "route_name")
        self._namespace = _require_name(namespace, "namespace")
        self._app_label = app_label
        self._expected_run = expected_deployment_run_id or None
        self._expected_sha = expected_source_sha or None
        self._registry = registry or InMemoryMutationAttemptRegistry()
        self._now_factory = now_factory or (lambda: datetime.now(timezone.utc))
        for label, value in (("max_request_age_seconds", max_request_age_seconds),
                             ("max_clock_skew_seconds", max_clock_skew_seconds)):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise MutationWriteError(f"{label} must be a non-negative integer")
        if max_request_age_seconds == 0 or max_request_age_seconds > 86_400:
            raise MutationWriteError(
                "max_request_age_seconds must be within [1, 86400]: a request "
                "that never expires is not a fresh precondition"
            )
        self._max_request_age = max_request_age_seconds
        self._max_clock_skew = max_clock_skew_seconds
        self._records: List[Dict[str, Any]] = []

    # ------------------------------------------------------- read-only data

    @property
    def records(self) -> Tuple[Dict[str, Any], ...]:
        """The machine-readable evidence records this provider has produced.

        Deliberately data, not a method: the port contract requires the
        provider's callable surface to be exactly ``apply``/``rollback``.
        """
        return tuple(self._records)

    @property
    def mutation_attempts(self) -> int:
        """Bounded write attempts performed through the client."""
        return int(getattr(self._mutation_client, "attempts", 0))

    # ---------------------------------------------------------- the port

    def apply(self, request: TrafficMutationRequest) -> TrafficMutationResult:
        """Move the approved forward transition (``expected → requested``)."""
        return self._operate(OP_APPLY, request)

    def rollback(self, request: TrafficMutationRequest) -> TrafficMutationResult:
        """Undo the approved forward transition (``requested → expected``).

        The rollback target is *derived* from the bound request, never
        supplied: a rollback cannot be pointed at a state the approved
        transition never defined, and a backwards move cannot be smuggled
        through ``apply`` (the request contract refuses that shape).
        """
        return self._operate(OP_ROLLBACK, request)

    # ---------------------------------------------------------- internals

    def _operate(
        self, operation: str, request: TrafficMutationRequest
    ) -> TrafficMutationResult:
        started = _utc(self._now_factory())
        if operation not in TRAFFIC_MUTATION_OPERATIONS:
            raise InvalidTrafficMutationRequest(
                f"operation must be one of: {', '.join(TRAFFIC_MUTATION_OPERATIONS)}"
            )
        if not isinstance(request, TrafficMutationRequest):
            # The only raise: a caller that is not even holding a validated
            # request has no authority to be refused over.
            raise InvalidTrafficMutationRequest(
                "the provider executes a validated TrafficMutationRequest; "
                f"got {type(request).__name__}"
            )

        digest = request.digest()
        target_percentage = expected_verified_percentage(operation, request)

        # ---- 1. claim: duplicate/concurrent attempts stop here, before
        #         any cluster access at all.
        try:
            claim = self._registry.claim(digest, operation, started)
        except MutationClaimConflict as exc:
            return self._refuse(
                operation, request, digest, claim=None,
                evidence_claim={
                    "claim_id": exc.claim_id,
                    "state": "held-by-another-attempt",
                },
                classification=CLASSIFICATION_REFUSED_CLAIM,
                reason=f"a concurrent attempt for this request is already in "
                       f"flight: {exc}",
                detail_extra={"target_percentage": target_percentage,
                              "expected_current_percentage":
                                  request.expected_current_percentage},
            )

        # ---- 2. fresh trusted observation (the request's own observed value
        #         is NOT the precondition).
        try:
            pre = self._observe(request)
        except Exception as exc:  # noqa: BLE001 - fail closed, never silently
            return self._refuse(
                operation, request, digest, claim=claim,
                classification=CLASSIFICATION_REFUSED_OBSERVATION,
                reason=f"the live topology could not be observed: "
                       f"{type(exc).__name__}: {redact(exc)}",
                detail_extra={"target_percentage": target_percentage},
            )

        authority_problems = self._authority_problems(request, pre, started)
        if authority_problems:
            return self._refuse(
                operation, request, digest, claim=claim, pre=pre,
                classification=CLASSIFICATION_REFUSED_AUTHORITY,
                reason="mutation authority is not established: "
                       + " | ".join(authority_problems[:3]),
                remote_percentage=pre.observation.observed_percentage,
                detail_extra={"target_percentage": target_percentage,
                              "pre_percentage":
                                  pre.observation.observed_percentage},
            )

        live_percentage = int(pre.observation.observed_percentage)
        precondition_problems = self._precondition_problems(
            operation, request, live_percentage
        )
        if precondition_problems:
            # Two different situations reach this branch, and they are
            # reported differently because they mean different things:
            #   * the live state is already the state this operation
            #     completes → a duplicate/already-applied attempt;
            #   * anything else → stale or contradictory, refused.
            # "Already at the target" is an APPLY-shaped statement: it says a
            # forward transition this provider may or may not have performed
            # is already in effect. A ROLLBACK that finds the pre-transition
            # state live is simply a rollback with nothing to undo, and is
            # reported as the precondition refusal it is.
            if operation == OP_APPLY and live_percentage == target_percentage:
                return self._already_applied(
                    operation, request, digest, claim, pre, target_percentage
                )
            return self._refuse(
                operation, request, digest, claim=claim, pre=pre,
                classification=CLASSIFICATION_REFUSED_PRECONDITION,
                reason="the live traffic state is not the state this operation "
                       "is authorized from: " + " | ".join(precondition_problems),
                remote_percentage=live_percentage,
                detail_extra={"target_percentage": target_percentage,
                              "expected_current_percentage":
                                  request.expected_current_percentage,
                              "requested_percentage": request.requested_percentage},
            )

        # ---- 3. the exact authorized transition, derived from the request.
        try:
            mutation = self._build_mutation(
                request, pre, operation=operation, target_percentage=target_percentage
            )
        except Exception as exc:  # noqa: BLE001 - a construction failure is a refusal
            return self._refuse(
                operation, request, digest, claim=claim, pre=pre,
                classification=CLASSIFICATION_REFUSED_CONFLICT,
                reason=f"the authorized transition could not be constructed "
                       f"exactly: {type(exc).__name__}: {redact(exc)}",
                remote_percentage=live_percentage,
            )

        # ---- 4. exactly ONE bounded attempt.
        attempts_before = self.mutation_attempts
        try:
            attempt = self._mutation_client.apply_weight_mutation(mutation)
        except Exception as exc:  # noqa: BLE001 - no write, no proof, refusal
            return self._refuse(
                operation, request, digest, claim=claim, pre=pre,
                classification=CLASSIFICATION_REFUSED_OBSERVATION,
                reason=f"the write could not be performed: "
                       f"{type(exc).__name__}: {redact(exc)}",
                remote_percentage=live_percentage,
                mutation=mutation,
            )
        attempts_made = self.mutation_attempts - attempts_before
        if attempts_made != 1:
            # A client that thinks it may retry is exactly what B.2 forbids.
            return self._refuse(
                operation, request, digest, claim=claim, pre=pre,
                classification=CLASSIFICATION_REFUSED_OBSERVATION,
                reason=f"the client performed {attempts_made} write attempts for one "
                       f"authorized transition; exactly one attempt is allowed",
                remote_percentage=live_percentage,
                mutation=mutation, attempt=attempt,
            )

        # ---- 5. fresh post-mutation observation: the only thing that can
        #         verify anything.
        try:
            post = self._observe(request)
        except Exception as exc:  # noqa: BLE001 - unknown outcome, no claim
            return self._refuse(
                operation, request, digest, claim=claim, pre=pre,
                classification=CLASSIFICATION_UNVERIFIED,
                reason=f"the mutation was attempted but the resulting state "
                       f"could not be observed: {type(exc).__name__}: "
                       f"{redact(exc)}; nothing is claimed",
                remote_percentage=None, mutation=mutation, attempt=attempt,
            )

        # ---- 6. classify the truth, never the hope.
        return self._classify_outcome(
            operation, request, digest, claim, pre, post, attempt, mutation,
            target_percentage=target_percentage,
        )

    # ------------------------------------------------------- observation

    def _observe(self, request: TrafficMutationRequest) -> TrafficObservation:
        """One fresh, structured observation through the B.1 adapter.

        A fresh call every time: there is no cache here, and the tests prove
        that a caching observer cannot fake a successful verification.
        """
        record = self._observer.inspect_detailed(
            request.deployment_run_id, request.source_sha
        )
        if not isinstance(record, TrafficObservation):
            raise MutationWriteError(
                "the observer must return the structured TrafficObservation: a "
                "weaker summary would lose the facts this provider verifies"
            )
        return record

    def _authority_problems(
        self,
        request: TrafficMutationRequest,
        pre: TrafficObservation,
        now: datetime,
    ) -> List[str]:
        """Everything that must hold *before* a write, in one place.

        The precondition/authority split is deliberate: authority is about
        *who and what* (trusted identity, controller acceptance, the route),
        the precondition is about *where the transition starts*.
        """
        problems: List[str] = []
        observation = pre.observation

        # The request's own provenance has an age. A decision built on an
        # observation from long ago is not the decision this provider is
        # being asked to execute, however convenient the live state looks.
        observed_at = _utc(request.observed_at)
        age_seconds = (now - observed_at).total_seconds()
        if age_seconds > self._max_request_age:
            problems.append(
                f"the request was built on an observation "
                f"{int(age_seconds)}s old, beyond the "
                f"{self._max_request_age}s freshness bound"
            )
        if -age_seconds > self._max_clock_skew:
            problems.append(
                f"the request's observation is {int(-age_seconds)}s in the "
                f"future, beyond the {self._max_clock_skew}s clock-skew "
                f"tolerance"
            )

        if observation.observed_status != OBSERVED_KNOWN:
            problems.append(
                f"the live topology is not KNOWN (status="
                f"{observation.observed_status}): "
                + "; ".join(text for _severity, text in pre.findings[:2] or
                            (("", observation.detail),))
            )
        if not pre.binding_established:
            problems.append(
                f"the observation is not attributable to this deployment/source "
                f"(binding={pre.binding}); a request-carried identity is not "
                f"enough"
            )
        if observation.deployment_run_id != request.deployment_run_id:
            problems.append(
                "the observed deployment run does not match the request"
            )
        if observation.source_sha != request.source_sha:
            problems.append("the observed source revision does not match the request")

        if self._expected_run and self._expected_run != request.deployment_run_id:
            problems.append(
                "the request's deployment run is not the host-owned configured one"
            )
        if self._expected_sha and self._expected_sha != request.source_sha:
            problems.append(
                "the request's source revision is not the host-owned configured one"
            )

        # The port-visible identities and the structured target facts are two
        # independent renderings of the same live truth. Both are checked: a
        # provider that trusted only one of them would accept an observation
        # whose two halves disagree, which is exactly the ambiguity this phase
        # must refuse.
        if observation.stable_identity != request.stable_target:
            problems.append(
                f"the observed stable identity is {observation.stable_identity!r}, "
                f"not the requested {request.stable_target!r}"
            )
        if observation.canary_identity != request.canary_target:
            problems.append(
                f"the observed canary identity is {observation.canary_identity!r}, "
                f"not the requested {request.canary_target!r}"
            )

        targets = pre.targets or {}
        stable = targets.get("stable")
        canary = targets.get("canary")
        if stable is None or canary is None:
            problems.append("the observation does not prove both stable and canary targets")
        else:
            if stable.identity != request.stable_target:
                problems.append(
                    f"the live stable target is {stable.identity!r}, not the "
                    f"requested {request.stable_target!r}"
                )
            if canary.identity != request.canary_target:
                problems.append(
                    f"the live canary target is {canary.identity!r}, not the "
                    f"requested {request.canary_target!r}"
                )
            if (observation.stable_identity is not None
                    and stable.identity != observation.stable_identity):
                problems.append(
                    "the observation is internally inconsistent: its reported "
                    f"stable identity ({observation.stable_identity!r}) differs "
                    f"from its stable target facts ({stable.identity!r})"
                )
            if (observation.canary_identity is not None
                    and canary.identity != observation.canary_identity):
                problems.append(
                    "the observation is internally inconsistent: its reported "
                    f"canary identity ({observation.canary_identity!r}) differs "
                    f"from its canary target facts ({canary.identity!r})"
                )
        if pre.endpoints_disjoint is not True:
            problems.append(
                "the two tracks do not resolve to disjoint endpoint sets, so the "
                "split is not observable traffic"
            )

        route = pre.route
        if route is None:
            problems.append("the observation carries no route facts")
            return problems
        if route.name != self._route_name or route.namespace != self._namespace:
            problems.append(
                f"the observed route is {route.namespace}/{route.name}, not the "
                f"host-owned target {self._namespace}/{self._route_name}"
            )
        if route.accepted is not True:
            problems.append("the controller has not reported Accepted=True")
        if route.resolved_refs is not True:
            problems.append("the controller has not resolved every backendRef")
        if (
            route.controller_observed_generation is None
            or route.generation is None
            or route.controller_observed_generation != route.generation
        ):
            problems.append(
                "controller observedGeneration "
                f"({route.controller_observed_generation}) does not equal the route "
                f"generation ({route.generation}); mutation authority requires the "
                f"controller to have observed the exact generation being changed"
            )
        configured = pre.configured_percentage
        if configured is None or configured != observation.observed_percentage:
            problems.append(
                "the observed percentage is not the exact configured share of the "
                "live weights"
            )
        return problems

    def _precondition_problems(
        self, operation: str, request: TrafficMutationRequest, live_percentage: int
    ) -> List[str]:
        """Where the authorized transition must start, per operation."""
        if operation == OP_APPLY:
            expected = request.expected_current_percentage
            if live_percentage != expected:
                return [
                    f"the request authorizes {expected}% -> "
                    f"{request.requested_percentage}%, but the live canary share is "
                    f"{live_percentage}%"
                ]
            return []
        # ROLLBACK undoes a transition that actually happened: it may only
        # start from the state the approved forward transition completes to.
        reached = request.requested_percentage
        if live_percentage != reached:
            return [
                f"the forward transition {request.expected_current_percentage}% -> "
                f"{request.requested_percentage}% has not been observed as reached; "
                f"the live canary share is {live_percentage}%, so there is nothing "
                f"to roll back"
            ]
        return []

    def _build_mutation(
        self,
        request: TrafficMutationRequest,
        pre: TrafficObservation,
        *,
        operation: str,
        target_percentage: int,
    ) -> WeightMutation:
        """Construct the one authorized change from trusted values only.

        The backend *names* and their *current weights* come from the
        observer's trusted interpretation; the on-disk layout (which index
        each name sits at) comes from a read of the same route, and every
        element is cross-checked. Nothing here is taken from the request
        except the authorized percentage.
        """
        route = pre.route
        backends = dict(route.backends or {})
        weights = dict(route.weights or {})
        if set(backends) != {"stable", "canary"} or set(weights) != {"stable", "canary"}:
            raise MutationWriteError(
                "the observation does not bind exactly two tracks to two backends"
            )
        stable_name = backends["stable"]
        canary_name = backends["canary"]
        stable_weight, canary_weight = percentage_to_weights(target_percentage)

        document = self._read_client.get_http_route(self._route_name, self._namespace)
        if not isinstance(document, Mapping):
            raise MutationWriteError("the route document could not be read")
        metadata = document.get("metadata") or {}
        resource_version = metadata.get("resourceVersion")
        layout = _backend_layout(document)
        if layout is None:
            raise MutationWriteError(
                "the route does not declare exactly one weighted rule with exactly "
                "two backendRefs, so no exact index-based patch exists"
            )
        by_name = {entry["name"]: entry for entry in layout}
        if set(by_name) != {stable_name, canary_name}:
            raise MutationWriteError(
                f"the route's backendRefs {sorted(by_name)} do not match the "
                f"observed targets {sorted([stable_name, canary_name])}"
            )
        if by_name[stable_name]["weight"] != weights["stable"]:
            raise MutationWriteError(
                "the route's stable weight and the trusted observation disagree"
            )
        if by_name[canary_name]["weight"] != weights["canary"]:
            raise MutationWriteError(
                "the route's canary weight and the trusted observation disagree"
            )
        # `operation` participates so a rollback can never be built from an
        # apply-shaped target by accident: the caller already derived
        # `target_percentage` from the operation, and this is the assertion
        # that the two agree.
        if target_percentage != expected_verified_percentage(operation, request):
            raise InvalidTrafficMutationRequest(
                "the mutation target is not the state this operation completes"
            )
        return WeightMutation(
            route_name=self._route_name,
            namespace=self._namespace,
            resource_version=str(resource_version),
            changes=(
                BackendWeightChange(
                    index=by_name[stable_name]["index"],
                    name=stable_name,
                    expected_weight=by_name[stable_name]["weight"],
                    new_weight=stable_weight,
                ),
                BackendWeightChange(
                    index=by_name[canary_name]["index"],
                    name=canary_name,
                    expected_weight=by_name[canary_name]["weight"],
                    new_weight=canary_weight,
                ),
            ),
        )

    # ------------------------------------------------------- classification

    def _classify_outcome(
        self,
        operation: str,
        request: TrafficMutationRequest,
        digest: str,
        claim: Mapping[str, Any],
        pre: TrafficObservation,
        post: TrafficObservation,
        attempt: MutationAttempt,
        mutation: WeightMutation,
        *,
        target_percentage: int,
    ) -> TrafficMutationResult:
        """Turn the post-write remote state into the truth, and only that.

        The order of the branches is the priority order of honesty:

        1. no trustworthy post-observation → unverified, nothing claimed;
        2. the remote state is an unrelated third state → conflict refusal;
        3. the remote state is still the pre state → the write did not
           change anything;
        4. the remote state is the target state → verified, *if* this call
           either had a write accepted or had an unknown outcome. A
           definitively refused write followed by a matching state is not
           this call's achievement, and is reported as a refusal.
        """
        post_percentage = post.observation.observed_percentage
        pre_percentage = pre.observation.observed_percentage
        if post.observation.observed_status != OBSERVED_KNOWN or post_percentage is None:
            return self._refuse(
                operation, request, digest, claim=claim, pre=pre, post=post,
                classification=CLASSIFICATION_UNVERIFIED,
                reason=f"the write was attempted and the resulting state is not a "
                       f"trustworthy observation (status="
                       f"{post.observation.observed_status}); nothing is claimed",
                remote_percentage=None, mutation=mutation, attempt=attempt,
            )

        if post_percentage == target_percentage:
            if not self._generation_progressed(pre, post, attempt):
                return self._refuse(
                    operation, request, digest, claim=claim, pre=pre, post=post,
                    classification=CLASSIFICATION_UNVERIFIED,
                    reason="the remote state matches the target, but the route's "
                           "generation does not show the change; refusing to claim "
                           "a verification the resource does not support",
                    remote_percentage=post_percentage, mutation=mutation,
                    attempt=attempt,
                )
            if attempt.state == ATTEMPT_REJECTED:
                return self._refuse(
                    operation, request, digest, claim=claim, pre=pre, post=post,
                    classification=CLASSIFICATION_REFUSED_ATTEMPT,
                    reason="the API server refused this write and the route is now "
                           "at the requested state: the state was reached by another "
                           "actor, not by this operation; nothing is claimed",
                    remote_percentage=post_percentage, mutation=mutation,
                    attempt=attempt,
                )
            if attempt.state == ATTEMPT_UNKNOWN:
                return self._verified(
                    operation, request, digest, claim=claim, pre=pre, post=post,
                    mutation=mutation, attempt=attempt,
                    classification=CLASSIFICATION_VERIFIED_UNKNOWN_ATTEMPT,
                    causality=CAUSALITY_UNKNOWN_ATTEMPT,
                    reason="the write's answer was lost, but a fresh observation "
                           "shows the route at the requested state; the mutation is "
                           "complete (the attempt's own outcome is recorded "
                           "separately)",
                )
            return self._verified(
                operation, request, digest, claim=claim, pre=pre, post=post,
                mutation=mutation, attempt=attempt,
                classification=CLASSIFICATION_VERIFIED,
                causality=CAUSALITY_WRITE_ACCEPTED,
                reason="the write was accepted by the API server and a fresh "
                       "observation shows the route at the state this operation "
                       "completes",
            )

        if post_percentage == pre_percentage:
            return self._refuse(
                operation, request, digest, claim=claim, pre=pre, post=post,
                classification=CLASSIFICATION_FAILED_ATTEMPT,
                reason=f"the write is not visible in the route: the canary share is "
                       f"still {post_percentage}% (attempt="
                       f"{attempt.state}: {attempt.detail})",
                remote_percentage=post_percentage, mutation=mutation, attempt=attempt,
            )

        return self._refuse(
            operation, request, digest, claim=claim, pre=pre, post=post,
            classification=CLASSIFICATION_REFUSED_CONFLICT,
            reason=f"the route is now at {post_percentage}%, which is neither the "
                   f"state this operation started from ({pre_percentage}%) nor the "
                   f"state it completes ({target_percentage}%); refusing",
            remote_percentage=post_percentage, mutation=mutation, attempt=attempt,
        )

    @staticmethod
    def _generation_progressed(
        pre: TrafficObservation, post: TrafficObservation, attempt: MutationAttempt
    ) -> bool:
        """Did the resource actually change?

        An accepted write must bump the route's generation; anything else
        means the observation and the write cannot both be true, and the
        provider refuses to claim verification over an inconsistency. An
        unknown attempt may legitimately have landed or not, so a strictly
        greater generation is not required there — but a *lower* one is
        always a contradiction.
        """
        pre_generation = (pre.route.generation if pre.route else None)
        post_generation = (post.route.generation if post.route else None)
        if pre_generation is None or post_generation is None:
            return False
        if post_generation < pre_generation:
            return False
        if attempt.state == ATTEMPT_ACCEPTED and post_generation <= pre_generation:
            return False
        return True

    def _already_applied(
        self,
        operation: str,
        request: TrafficMutationRequest,
        digest: str,
        claim: Mapping[str, Any],
        pre: TrafficObservation,
        target_percentage: int,
    ) -> TrafficMutationResult:
        """A request whose target is already the live state.

        Two shapes, deliberately separated:

        * **idempotent replay** — this provider recorded completing exactly
          this digest/operation before, and a *fresh* observation still
          shows the target state. Nothing is written and nothing new is
          claimed; the result states the remote truth, and the evidence
          records that zero attempts were made in this call;
        * **unattributed** — the live state matches the target, but no
          record of this provider performing it exists. The state could have
          been produced by another process, another replica, a rollback, or
          an operator. Returned as a refusal: the provider will not claim
          credit for a mutation it cannot account for.
        """
        previous = self._registry.completed(digest, operation)
        if previous is not None and bool(previous.get("verified")):
            result = TrafficMutationResult.from_request(
                request,
                provider=PROVIDER_NAME,
                operation=operation,
                remote_percentage=target_percentage,
                verified=True,
                external_operation_id=None,
                detail=redact(
                    f"idempotent replay of {operation} for request digest "
                    f"{digest[:16]}: this provider already completed this exact "
                    f"request and the live state still equals the requested "
                    f"percentage; no mutation was attempted in this call",
                    limit=MAX_REASON_LENGTH,
                ),
            )
            self._record(
                operation, request, digest, claim,
                classification=CLASSIFICATION_REPLAY,
                causality=CAUSALITY_NO_ATTEMPT,
                verified=True,
                reason=result.detail,
                pre=pre,
                remote_percentage=target_percentage,
                attempts=0,
                target_percentage=target_percentage,
                extra={"previous_claim_id": str(previous.get("claim_id"))},
            )
            self._finish(claim, state="replayed", verified=True,
                         detail=result.detail)
            return result

        return self._refuse(
            operation, request, digest, claim=claim, pre=pre,
            classification=CLASSIFICATION_ALREADY_APPLIED,
            reason=f"the live state already equals the percentage this {operation} "
                   f"completes ({target_percentage}%), but this provider has no "
                   f"record of performing the transition; refusing to claim a "
                   f"mutation it did not make (no attempt was made)",
            remote_percentage=target_percentage,
            detail_extra={"target_percentage": target_percentage,
                          "attempts": 0},
        )

    # ---------------------------------------------------------- result paths

    def _verified(
        self,
        operation: str,
        request: TrafficMutationRequest,
        digest: str,
        *,
        claim: Mapping[str, Any],
        pre: TrafficObservation,
        post: TrafficObservation,
        mutation: WeightMutation,
        attempt: MutationAttempt,
        classification: str,
        causality: str,
        reason: str,
    ) -> TrafficMutationResult:
        detail = redact(reason, limit=MAX_REASON_LENGTH)
        result = TrafficMutationResult.from_request(
            request,
            provider=PROVIDER_NAME,
            operation=operation,
            remote_percentage=post.observation.observed_percentage,
            verified=True,
            external_operation_id=attempt.external_operation_id,
            detail=detail,
        )
        self._record(
            operation, request, digest, claim,
            classification=classification, causality=causality, verified=True,
            reason=detail, pre=pre, post=post, mutation=mutation, attempt=attempt,
            remote_percentage=post.observation.observed_percentage,
            attempts=1, target_percentage=result.expected_verified_percentage,
        )
        self._finish(claim, state="verified", verified=True, detail=detail)
        return result

    def _refuse(
        self,
        operation: str,
        request: TrafficMutationRequest,
        digest: str,
        *,
        classification: str,
        reason: str,
        claim: Optional[Mapping[str, Any]] = None,
        evidence_claim: Optional[Mapping[str, Any]] = None,
        pre: Optional[TrafficObservation] = None,
        post: Optional[TrafficObservation] = None,
        mutation: Optional[WeightMutation] = None,
        attempt: Optional[MutationAttempt] = None,
        remote_percentage: Optional[int] = None,
        detail_extra: Optional[Mapping[str, Any]] = None,
    ) -> TrafficMutationResult:
        """A truthful non-success: nothing verified, reason recorded."""
        detail = redact(reason, limit=MAX_REASON_LENGTH)
        result = TrafficMutationResult.from_request(
            request,
            provider=PROVIDER_NAME,
            operation=operation,
            remote_percentage=remote_percentage,
            verified=False,
            external_operation_id=None,
            detail=detail,
        )
        self._record(
            operation, request, digest,
            evidence_claim if evidence_claim is not None else claim,
            classification=classification,
            causality=(
                CAUSALITY_ATTEMPT_REFUSED if attempt is not None
                and attempt.state == ATTEMPT_REJECTED
                else CAUSALITY_NOT_APPLIED if attempt is not None
                else CAUSALITY_NO_ATTEMPT
            ),
            verified=False, reason=detail, pre=pre, post=post, mutation=mutation,
            attempt=attempt, remote_percentage=remote_percentage,
            attempts=1 if attempt is not None else 0,
            target_percentage=result.expected_verified_percentage,
            extra=detail_extra,
        )
        self._finish(claim, state="refused", verified=False, detail=detail)
        return result

    def _finish(
        self,
        claim: Optional[Mapping[str, Any]],
        *,
        state: str,
        verified: bool,
        detail: str,
    ) -> None:
        if claim is None:
            return
        try:
            self._registry.finish(
                claim, state=state, verified=verified, detail=detail,
                now=_utc(self._now_factory()),
            )
        except Exception:  # noqa: BLE001 - a registry failure never changes the
            # truth of the result the caller is about to receive; the evidence
            # record already carries the terminal state.
            return

    # -------------------------------------------------------------- evidence

    def _record(
        self,
        operation: str,
        request: TrafficMutationRequest,
        digest: str,
        claim: Optional[Mapping[str, Any]],
        *,
        classification: str,
        causality: str,
        verified: bool,
        reason: str,
        pre: Optional[TrafficObservation] = None,
        post: Optional[TrafficObservation] = None,
        mutation: Optional[WeightMutation] = None,
        attempt: Optional[MutationAttempt] = None,
        remote_percentage: Optional[int] = None,
        attempts: int = 0,
        target_percentage: Optional[int] = None,
        extra: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """One machine-readable record of one attempt of one operation.

        The record keeps *attempted*, *accepted by the client*, *reported by
        the command*, *observed remotely* and *verified* as separate facts —
        they are never collapsed into one success boolean.
        """
        record: Dict[str, Any] = {
            "schema": EVIDENCE_SCHEMA,
            "provider": PROVIDER_NAME,
            "operation": operation,
            "classification": classification,
            "causality": causality,
            "verified": bool(verified),
            "request": request.to_dict(),
            "request_digest": digest,
            "concurrency": {
                "registry": type(self._registry).__name__,
                "claim_id": (claim or {}).get("claim_id"),
                "claim_state": (claim or {}).get("state"),
                "replay": classification == CLASSIFICATION_REPLAY,
                "attempts": attempts,
            },
            "target_percentage": target_percentage,
            "remote_percentage": remote_percentage,
            "reason": reason,
            "pre": _observation_summary(pre),
            "mutation": mutation.to_dict() if mutation is not None else None,
            "attempt": attempt.to_dict() if attempt is not None else None,
            "post": _observation_summary(post),
            "verification": {
                "expected_percentage": target_percentage,
                "observed_percentage": (
                    post.observation.observed_percentage if post is not None
                    and post.observation.observed_status == OBSERVED_KNOWN else None
                ),
                "verified": bool(verified),
                "reason": reason,
            },
        }
        if extra:
            record["detail"] = {
                key: (value if isinstance(value, (int, bool)) or value is None
                      else redact(value, limit=200))
                for key, value in extra.items()
            }
        self._records.append(record)
        return record


def _require_name(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MutationWriteError(f"{field} must be a non-empty string")
    return value


def _backend_layout(document: Mapping[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """The two backendRefs of the single weighted rule, with their indexes.

    Returns ``None`` for any layout this provider cannot write exactly —
    more than one weighted rule, more than two backends, duplicate names or
    a malformed weight. The provider refuses on ``None``; it never guesses
    which backend a change was meant for.
    """
    spec = document.get("spec") or {}
    rules = [rule for rule in spec.get("rules") or [] if (rule or {}).get("backendRefs")]
    if len(rules) != 1:
        return None
    refs = rules[0].get("backendRefs") or []
    if len(refs) != 2:
        return None
    layout: List[Dict[str, Any]] = []
    seen = set()
    for index, ref in enumerate(refs):
        if not isinstance(ref, Mapping):
            return None
        name = ref.get("name")
        weight = ref.get("weight")
        if not isinstance(name, str) or not name or name in seen:
            return None
        if not isinstance(weight, int) or isinstance(weight, bool) or weight < 0:
            return None
        seen.add(name)
        layout.append({"index": index, "name": name, "weight": weight})
    return layout


def _observation_summary(record: Optional[TrafficObservation]) -> Optional[Dict[str, Any]]:
    """A bounded, structured summary of one observation for the evidence.

    Structured facts (identities, percentages, generations, controller
    conditions) are kept exact; free text is bounded and redacted exactly as
    the read adapter bounds it; secrets have no path into this structure at
    all because nothing here reads a credential or a kubeconfig.
    """
    if record is None:
        return None
    observation = record.observation
    route = record.route
    targets = record.targets or {}
    return {
        "status": observation.observed_status,
        "percentage": observation.observed_percentage,
        "configured_percentage": record.configured_percentage,
        "configured_fraction": (
            list(record.configured_fraction) if record.configured_fraction else None
        ),
        "stable_identity": observation.stable_identity,
        "canary_identity": observation.canary_identity,
        "binding": record.binding,
        "binding_established": record.binding_established,
        "endpoints_disjoint": record.endpoints_disjoint,
        "collected_at": (
            _utc(record.collected_at).isoformat() if record.collected_at else None
        ),
        "route": None if route is None else {
            "name": route.name,
            "namespace": route.namespace,
            "generation": route.generation,
            "weights": dict(route.weights) if route.weights else None,
            "backends": dict(route.backends) if route.backends else None,
            "controller_observed_generation": route.controller_observed_generation,
        },
        "controller": None if route is None else {
            "accepted": route.accepted,
            "resolved_refs": route.resolved_refs,
        },
        "targets": {
            track: {
                "identity": facts.identity,
                "service": facts.service,
                "ready_endpoints": len(facts.ready_endpoints),
                "workload": facts.workload,
            }
            for track, facts in sorted(targets.items())
        },
        "findings": [
            {"severity": severity, "text": redact(text, limit=240)}
            for severity, text in record.findings[:MAX_FINDINGS_IN_EVIDENCE]
        ],
    }


def evidence_to_json(records: Sequence[Mapping[str, Any]]) -> str:
    """Deterministic JSON for the sealed evidence artifact.

    Stable separators, sorted keys and one trailing newline (the repository's
    sealing convention), so the digest of the artifact is reproducible from
    the same records.
    """
    return json.dumps(list(records), indent=2, sort_keys=True) + "\n"


__all__ = [
    "CAUSALITY_ATTEMPT_REFUSED",
    "CAUSALITY_NO_ATTEMPT",
    "CAUSALITY_NOT_APPLIED",
    "CAUSALITY_UNKNOWN_ATTEMPT",
    "CAUSALITY_WRITE_ACCEPTED",
    "CLASSIFICATION_ALREADY_APPLIED",
    "CLASSIFICATION_FAILED_ATTEMPT",
    "CLASSIFICATION_REFUSED_ATTEMPT",
    "CLASSIFICATION_REFUSED_AUTHORITY",
    "CLASSIFICATION_REFUSED_CLAIM",
    "CLASSIFICATION_REFUSED_CONFLICT",
    "CLASSIFICATION_REFUSED_OBSERVATION",
    "CLASSIFICATION_REFUSED_PRECONDITION",
    "CLASSIFICATION_REPLAY",
    "CLASSIFICATION_UNVERIFIED",
    "CLASSIFICATION_VERIFIED",
    "CLASSIFICATION_VERIFIED_UNKNOWN_ATTEMPT",
    "EVIDENCE_SCHEMA",
    "InMemoryMutationAttemptRegistry",
    "MutationAttemptRegistry",
    "MutationClaimConflict",
    "PROVIDER_NAME",
    "TrustedTrafficMutationProvider",
    "WEIGHT_DENOMINATOR",
    "evidence_to_json",
    "percentage_from_weights",
    "percentage_to_weights",
]
