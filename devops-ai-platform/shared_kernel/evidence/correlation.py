"""Deterministic operational correlation engine (Phase 8.4.2-G.1).

No model, no heuristic, no randomness, no wall-clock reads. Given the same
observations, the same policy version and the same incident, this engine
produces byte-identical output — including evidence ids, relationship set,
relationship ordering and pack hash — regardless of the order in which the
observations were ingested.

Correlation precedence (§21), strongest first::

    1. exact incident / request / trace identity
    2. deployment identity
    3. service + environment identity
    4. repository + commit relationship
    5. temporal proximity            (always labelled temporal, never causal)

Exactly one *anchor* edge is emitted per item: the highest-precedence rule
that applies. Lower-precedence rules do not add duplicate edges, so the
relationship set is a function of the evidence, not of evaluation order.

What this engine will never do
------------------------------
* infer ``CAUSED_BY`` from "it happened just before" — temporal edges are
  emitted as ``PRECEDED``/``CORRELATES_WITH`` with ``temporal=True``;
* merge ``checkout@production`` with ``checkout@staging`` because the
  service names match (§20 R7);
* drop a contradictory observation to make the graph tidy (§22);
* mutate an observation to mark it stale (§23) — freshness is reported
  separately, alongside the untouched item.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .model import (
    CorrelationKey,
    CorrelationKeyType,
    EvidenceError,
    EvidenceErrorCode,
    EvidenceItem,
    EvidencePack,
    EvidenceRelationship,
    EvidenceStatus,
    ObservationType,
    RelationshipType,
    DEFAULT_LIMITS,
    EvidenceLimits,
)

__all__ = [
    "CorrelationPolicy",
    "DEFAULT_POLICY",
    "OperationalCorrelationEngine",
    "CORRELATION_POLICY_VERSION",
]

#: Bump this when correlation *semantics* change, so historical packs stay
#: interpretable and a re-run difference is visible rather than silent (§25).
CORRELATION_POLICY_VERSION = "devops.correlation-policy/1"

# Rule identifiers, surfaced on every relationship for auditability.
RULE_INCIDENT_BINDING = "R1-incident-binding"
RULE_TRACE_BINDING = "R2-trace-binding"
RULE_DEPLOYMENT_BINDING = "R3-deployment-binding"
RULE_SERVICE_BINDING = "R4-service-environment-binding"
RULE_REPOSITORY_BINDING = "R5-repository-commit-binding"
RULE_TEMPORAL_PROXIMITY = "R6-temporal-proximity"
RULE_DEPLOYMENT_GROUPING = "R3a-deployment-grouping"
RULE_CONFLICT_DETECTION = "C1-deployment-identity-conflict"

#: Precedence order; index 0 is strongest.
_PRECEDENCE = (
    RULE_INCIDENT_BINDING,
    RULE_TRACE_BINDING,
    RULE_DEPLOYMENT_BINDING,
    RULE_SERVICE_BINDING,
    RULE_REPOSITORY_BINDING,
    RULE_TEMPORAL_PROXIMITY,
)


@dataclass(frozen=True)
class CorrelationPolicy:
    """Explicit, versioned correlation parameters.

    Window semantics are stated rather than implied: the temporal window is
    ``[anchor - before, anchor + after]`` and is **inclusive at both
    endpoints**. ``clock_skew_tolerance`` is the margin within which two
    timestamps are treated as concurrent, so a 200 ms difference between
    two hosts never becomes an ordering claim.
    """

    version: str = CORRELATION_POLICY_VERSION
    temporal_window_before: timedelta = timedelta(minutes=30)
    temporal_window_after: timedelta = timedelta(minutes=15)
    clock_skew_tolerance: timedelta = timedelta(seconds=2)
    stale_after: timedelta = timedelta(minutes=15)
    #: Upper bound on pairwise linking inside one index bucket, so a huge
    #: bucket cannot produce a quadratic relationship explosion (§48).
    max_bucket_pairs: int = 10_000
    limits: EvidenceLimits = DEFAULT_LIMITS

    def window_contains(self, anchor: datetime, observed_at: datetime) -> bool:
        """Inclusive membership test for the temporal window."""
        return (
            anchor - self.temporal_window_before
            <= observed_at
            <= anchor + self.temporal_window_after
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "temporal_window_before_seconds": self.temporal_window_before.total_seconds(),
            "temporal_window_after_seconds": self.temporal_window_after.total_seconds(),
            "clock_skew_tolerance_seconds": self.clock_skew_tolerance.total_seconds(),
            "stale_after_seconds": self.stale_after.total_seconds(),
            "window_semantics": "inclusive[anchor-before, anchor+after]",
        }


DEFAULT_POLICY = CorrelationPolicy()


def _key_values(item: EvidenceItem, key_type: CorrelationKeyType) -> Tuple[str, ...]:
    return tuple(
        sorted(
            key.value for key in item.correlation_keys if key.key_type is key_type
        )
    )


def _first_key(item: EvidenceItem, key_type: CorrelationKeyType) -> Optional[str]:
    values = _key_values(item, key_type)
    return values[0] if values else None


class OperationalCorrelationEngine:
    """Builds an :class:`EvidencePack` from an incident and its evidence."""

    def __init__(self, policy: CorrelationPolicy = DEFAULT_POLICY) -> None:
        if not isinstance(policy, CorrelationPolicy):
            raise EvidenceError(
                EvidenceErrorCode.CORRELATION_POLICY_UNSUPPORTED,
                "policy must be a CorrelationPolicy",
            )
        self.policy = policy

    # -- public API ---------------------------------------------------

    def correlate(
        self,
        *,
        incident_id: str,
        evidence_items: Iterable[EvidenceItem],
        generated_at: datetime,
        reference_time: Optional[datetime] = None,
    ) -> EvidencePack:
        """Correlate ``evidence_items`` for ``incident_id``.

        ``generated_at`` is recorded but deliberately excluded from the
        pack hash, so a replay performed later reproduces the same hash.
        ``reference_time`` is the instant freshness is judged against; it
        defaults to the anchor incident's ``observed_at`` so that freshness
        is a property of the evidence, not of when the code happened to run.
        """
        items = self._deduplicate(evidence_items)
        if len(items) > self.policy.limits.max_items_per_pack:
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_TOO_LARGE,
                f"{len(items)} items exceeds the per-pack limit of "
                f"{self.policy.limits.max_items_per_pack}",
                incident_id=incident_id,
            )

        anchor = self._anchor(items, incident_id)
        anchor_time = (
            anchor.observed_at
            if anchor is not None
            else min((item.observed_at for item in items), default=generated_at)
        )
        effective_reference = reference_time or anchor_time

        relationships: List[EvidenceRelationship] = []
        bindings: Dict[str, str] = {}

        if anchor is not None:
            for item in items:
                if item.evidence_id == anchor.evidence_id:
                    continue
                rule = self._strongest_rule(anchor, item, anchor_time, incident_id)
                if rule is None:
                    continue
                bindings[item.evidence_id] = rule
                relationships.append(self._edge(anchor, item, rule, anchor_time))

        relationships.extend(self._deployment_grouping(items))
        conflicts = self._detect_conflicts(items)
        relationships.extend(conflict.relationship for conflict in conflicts)

        relationships = self._normalize_relationships(relationships)
        if len(relationships) > self.policy.limits.max_relationships_per_pack:
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_TOO_LARGE,
                f"{len(relationships)} relationships exceed the per-pack limit "
                f"of {self.policy.limits.max_relationships_per_pack}",
                incident_id=incident_id,
            )

        summary = self._summarize(
            items=items,
            anchor=anchor,
            bindings=bindings,
            conflicts=conflicts,
            reference_time=effective_reference,
        )

        return EvidencePack(
            incident_id=incident_id,
            generated_at=generated_at,
            evidence_items=items,
            relationships=relationships,
            correlation_policy_version=self.policy.version,
            summary=summary,
        )

    # -- internals ----------------------------------------------------

    @staticmethod
    def _deduplicate(evidence_items: Iterable[EvidenceItem]) -> Tuple[EvidenceItem, ...]:
        """Collapse re-ingested observations and impose a stable order.

        Identical observations share an ``evidence_id`` by construction, so
        duplicates disappear here; ordering by id makes the output
        independent of ingestion order.
        """
        unique: Dict[str, EvidenceItem] = {}
        for item in evidence_items:
            if not isinstance(item, EvidenceItem):
                raise EvidenceError(
                    EvidenceErrorCode.INVALID_EVIDENCE,
                    "correlation input must contain EvidenceItem instances",
                )
            unique.setdefault(item.evidence_id, item)
        return tuple(sorted(unique.values(), key=lambda i: i.evidence_id))

    @staticmethod
    def _anchor(
        items: Sequence[EvidenceItem], incident_id: str
    ) -> Optional[EvidenceItem]:
        candidates = [
            item
            for item in items
            if item.observation_type is ObservationType.INCIDENT
            and item.incident_id == incident_id
        ]
        # deterministic choice when a source emits several incident records
        return sorted(candidates, key=lambda i: i.evidence_id)[0] if candidates else None

    def _strongest_rule(
        self,
        anchor: EvidenceItem,
        item: EvidenceItem,
        anchor_time: datetime,
        incident_id: str,
    ) -> Optional[str]:
        """Return the highest-precedence rule binding ``item`` to the anchor."""
        # R7 environment binding is a *gate*, not a rule: cross-environment
        # evidence never correlates on weaker-than-exact identity.
        same_environment = (
            anchor.environment is None
            or item.environment is None
            or anchor.environment == item.environment
        )

        if item.incident_id == incident_id:
            return RULE_INCIDENT_BINDING

        anchor_traces = set(_key_values(anchor, CorrelationKeyType.TRACE_ID))
        if anchor_traces and anchor_traces & set(
            _key_values(item, CorrelationKeyType.TRACE_ID)
        ):
            return RULE_TRACE_BINDING

        anchor_requests = set(_key_values(anchor, CorrelationKeyType.REQUEST_ID))
        if anchor_requests and anchor_requests & set(
            _key_values(item, CorrelationKeyType.REQUEST_ID)
        ):
            return RULE_TRACE_BINDING

        anchor_deployments = set(_key_values(anchor, CorrelationKeyType.DEPLOYMENT_ID))
        item_deployments = set(_key_values(item, CorrelationKeyType.DEPLOYMENT_ID))
        if anchor_deployments and anchor_deployments & item_deployments:
            return RULE_DEPLOYMENT_BINDING

        if not same_environment:
            # Weaker rules below all key on service/repo/time, which would
            # otherwise merge staging into production.
            return None

        if (
            anchor.service_identity is not None
            and item.service_identity is not None
            and anchor.service_identity.scope == item.service_identity.scope
        ):
            return RULE_SERVICE_BINDING

        anchor_repo = _first_key(anchor, CorrelationKeyType.REPOSITORY)
        item_repo = _first_key(item, CorrelationKeyType.REPOSITORY)
        anchor_commit = _first_key(anchor, CorrelationKeyType.COMMIT_SHA)
        item_commit = _first_key(item, CorrelationKeyType.COMMIT_SHA)
        if (
            anchor_repo is not None
            and anchor_repo == item_repo
            and anchor_commit is not None
            and anchor_commit == item_commit
        ):
            return RULE_REPOSITORY_BINDING

        if self.policy.window_contains(anchor_time, item.observed_at):
            return RULE_TEMPORAL_PROXIMITY

        return None

    def _edge(
        self,
        anchor: EvidenceItem,
        item: EvidenceItem,
        rule: str,
        anchor_time: datetime,
    ) -> EvidenceRelationship:
        temporal = rule == RULE_TEMPORAL_PROXIMITY
        if item.observation_type is ObservationType.DEPLOYMENT and not temporal:
            relationship_type = RelationshipType.DEPLOYED_AS
            basis = "incident is bound to the deployment identity it ran under"
        elif temporal:
            delta = anchor_time - item.observed_at
            if delta > self.policy.clock_skew_tolerance:
                relationship_type = RelationshipType.PRECEDED
                basis = (
                    "observed inside the configured temporal window before the "
                    "incident; ordering only, no causal claim"
                )
            else:
                relationship_type = RelationshipType.CORRELATES_WITH
                basis = (
                    "observed inside the configured temporal window; within "
                    "clock-skew tolerance, so no ordering is claimed"
                )
        else:
            relationship_type = RelationshipType.CORRELATES_WITH
            basis = f"bound by {rule}"
        return EvidenceRelationship(
            source_evidence_id=anchor.evidence_id,
            target_evidence_id=item.evidence_id,
            relationship_type=relationship_type,
            basis=basis,
            rule_id=rule,
            temporal=temporal,
        )

    def _deployment_grouping(
        self, items: Sequence[EvidenceItem]
    ) -> List[EvidenceRelationship]:
        """Link telemetry to the deployment it was produced under.

        Uses a keyed index rather than an all-pairs scan, and only links
        *non-deployment* items to *deployment* items, so the edge count is
        bounded by ``len(telemetry) x len(deployments in that bucket)``.
        """
        by_deployment: Dict[str, List[EvidenceItem]] = defaultdict(list)
        for item in items:
            for value in _key_values(item, CorrelationKeyType.DEPLOYMENT_ID):
                by_deployment[value].append(item)

        edges: List[EvidenceRelationship] = []
        emitted = 0
        for deployment_id in sorted(by_deployment):
            bucket = sorted(by_deployment[deployment_id], key=lambda i: i.evidence_id)
            deployments = [
                item
                for item in bucket
                if item.observation_type is ObservationType.DEPLOYMENT
            ]
            others = [
                item
                for item in bucket
                # Incidents bind to a deployment through R3 (DEPLOYED_AS);
                # re-linking them here would duplicate that edge with a
                # weaker label.
                if item.observation_type
                not in (ObservationType.DEPLOYMENT, ObservationType.INCIDENT)
            ]
            for deployment in deployments:
                for other in others:
                    if emitted >= self.policy.max_bucket_pairs:
                        return edges
                    if other.environment and deployment.environment:
                        if other.environment != deployment.environment:
                            continue
                    edges.append(
                        EvidenceRelationship(
                            source_evidence_id=other.evidence_id,
                            target_evidence_id=deployment.evidence_id,
                            relationship_type=RelationshipType.GENERATED_BY,
                            basis=(
                                f"observation carries deployment_id={deployment_id}"
                            ),
                            rule_id=RULE_DEPLOYMENT_GROUPING,
                            temporal=False,
                        )
                    )
                    emitted += 1
        return edges

    def _detect_conflicts(
        self, items: Sequence[EvidenceItem]
    ) -> List["_Conflict"]:
        """Find contradictory claims about the same deployment identity (§22).

        Two sources asserting different ``source_sha`` for one
        ``deployment_id`` is a contradiction. Both observations stay in the
        pack; the disagreement is represented, not resolved.
        """
        by_deployment: Dict[str, List[EvidenceItem]] = defaultdict(list)
        for item in items:
            identity = item.deployment_identity
            if identity is not None and identity.source_sha:
                by_deployment[identity.deployment_id].append(item)

        conflicts: List[_Conflict] = []
        for deployment_id in sorted(by_deployment):
            bucket = sorted(by_deployment[deployment_id], key=lambda i: i.evidence_id)
            claims: Dict[str, List[EvidenceItem]] = defaultdict(list)
            for item in bucket:
                claims[item.deployment_identity.source_sha].append(item)
            if len(claims) < 2:
                continue
            shas = sorted(claims)
            for index, left_sha in enumerate(shas):
                for right_sha in shas[index + 1:]:
                    for left in claims[left_sha]:
                        for right in claims[right_sha]:
                            conflicts.append(
                                _Conflict(
                                    deployment_id=deployment_id,
                                    field="source_sha",
                                    left=left,
                                    right=right,
                                    left_value=left_sha,
                                    right_value=right_sha,
                                    relationship=EvidenceRelationship(
                                        source_evidence_id=left.evidence_id,
                                        target_evidence_id=right.evidence_id,
                                        relationship_type=RelationshipType.CONTRADICTS,
                                        basis=(
                                            f"deployment {deployment_id} source_sha "
                                            f"{left_sha} vs {right_sha}"
                                        ),
                                        rule_id=RULE_CONFLICT_DETECTION,
                                        temporal=False,
                                    ),
                                )
                            )
        return conflicts

    @staticmethod
    def _normalize_relationships(
        relationships: Iterable[EvidenceRelationship],
    ) -> Tuple[EvidenceRelationship, ...]:
        unique = {rel.sort_key: rel for rel in relationships}
        return tuple(unique[key] for key in sorted(unique))

    def _summarize(
        self,
        *,
        items: Sequence[EvidenceItem],
        anchor: Optional[EvidenceItem],
        bindings: Mapping[str, str],
        conflicts: Sequence["_Conflict"],
        reference_time: datetime,
    ) -> Dict[str, Any]:
        """Derived, non-authoritative view of the pack.

        Freshness is reported here rather than written onto the items, so
        the original observation is never mutated to say "stale" (§23).
        """
        freshness = {}
        for item in items:
            age = reference_time - item.observed_at
            freshness[item.evidence_id] = (
                "STALE" if age > self.policy.stale_after else "FRESH"
            )

        counts: Dict[str, int] = defaultdict(int)
        for item in items:
            counts[item.observation_type.value] += 1

        status_counts: Dict[str, int] = defaultdict(int)
        for item in items:
            status_counts[item.status.value] += 1

        return {
            "pack_status": "CONFLICTING" if conflicts else "COHERENT",
            "anchor_evidence_id": anchor.evidence_id if anchor is not None else None,
            "item_count": len(items),
            "observation_type_counts": dict(sorted(counts.items())),
            "status_counts": dict(sorted(status_counts.items())),
            "binding_rules": dict(sorted(bindings.items())),
            "freshness": dict(sorted(freshness.items())),
            "stale_evidence_ids": sorted(
                evidence_id
                for evidence_id, state in freshness.items()
                if state == "STALE"
            ),
            "conflicts": [conflict.to_dict() for conflict in conflicts],
            "policy": self.policy.to_dict(),
            "environments": sorted(
                {item.environment for item in items if item.environment}
            ),
            "notes": (
                "Temporal relationships express ordering or co-occurrence only. "
                "No causal claim is derived from temporal proximity."
            ),
        }


@dataclass(frozen=True)
class _Conflict:
    """An internal record of two contradictory observations."""

    deployment_id: str
    field: str
    left: EvidenceItem
    right: EvidenceItem
    left_value: str
    right_value: str
    relationship: EvidenceRelationship

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": "DEPLOYMENT_IDENTITY_CONFLICT",
            "deployment_id": self.deployment_id,
            "field": self.field,
            "claims": [
                {
                    "evidence_id": self.left.evidence_id,
                    "source": self.left.source_type.value,
                    "value": self.left_value,
                },
                {
                    "evidence_id": self.right.evidence_id,
                    "source": self.right.source_type.value,
                    "value": self.right_value,
                },
            ],
            "resolution": "NONE - both observations are preserved",
        }
