"""Phase 8.7-B.1 — read-only Kubernetes/Gateway API traffic observer.

Phase 8.7-B.0 proved that a real Envoy Gateway honours the weighted
``HTTPRoute`` in the ``ares-traffic`` topology. This module makes that
traffic state *observable* through the provider-neutral boundary the
repository already has (``TrafficControllerPort`` in
``rollout_plan_service``): it reads the live cluster and translates
trusted observations into :class:`ObservedTrafficState`.

    Kubernetes Gateway API
            │  (read-only, closed operation set)
            ▼
    gateway_api_observer  ──►  ObservedTrafficState
                                  │
                                  ▼
                        TrafficControllerPort.inspect()
                                  │
                                  ▼
                        RolloutPlanService (planning only)

What this module observes, from live resources only:

* the committed ``HTTPRoute``'s backendRefs and their weights
  (``configured`` traffic state — a direct read, never an inference);
* what the controller says about that route (``controller`` state);
* which Services back the route, which ready endpoints they resolve to,
  which workloads own those pods and that the two endpoint sets are
  disjoint (``observed`` target identity).

What it deliberately does not do:

* it never mutates anything. The only Kubernetes verbs reachable are the
  reads in :mod:`kubernetes_read_client`; ``plan()`` is a pure renderer
  with no cluster access at all, so it cannot write either;
* it never turns unavailable information into an answer. Missing route,
  missing Service, missing/empty EndpointSlices, unreadable API, a
  malformed weight, a zero denominator or a share that is not an exact
  integer percentage all fail closed to ``UNKNOWN`` with the reason;
* it never downgrades a contradiction to ``UNKNOWN``: contradictory
  cluster truth (duplicate backend names, two backends claiming the same
  track, stable and canary resolving to the same workload identity, an
  endpoint the Service does not select, a controller that rejects a
  route whose targets are healthy) is ``CONFLICT``;
* it never fabricates deployment/source identity. See the binding rule
  on :class:`KubernetesTrafficObserver`.

``observed_percentage`` is the **effective configured share derived from
the observed route weights** — ``canary / (stable + canary) * 100`` — and
not a sampled request percentage. Phase 8.7-B.0's sampling proved that
real requests follow the weights; B.1 proves what the configuration is
and which workloads it points at. The two claims stay separate in the
record returned by :meth:`KubernetesTrafficObserver.inspect_detailed`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from incident_service.application.services.rollout_plan_service import (
    OBSERVED_CONFLICT,
    OBSERVED_KNOWN,
    OBSERVED_UNKNOWN,
    ObservedTrafficState,
)
from incident_service.infrastructure.traffic.kubernetes_read_client import (
    KubernetesReadError,
    KubernetesResourceNotFound,
    redact,
)

#: Deterministic provider identity (§17): no runtime data, no timestamps.
PROVIDER_NAME = "kubernetes-gateway-api"

#: What an observation is a read *of* (§16). It is a direct read of the
#: live HTTPRoute plus the Services, EndpointSlices, Pods and Deployments
#: behind it — not a sampled measurement and not a manifest re-read.
OBSERVATION_SOURCE = "kubernetes-gateway-api"

#: The observed topology's identity (Phase 8.7-B.0). Names, not
#: percentages: nothing here encodes a traffic split.
DEFAULT_NAMESPACE = "ares-traffic"
DEFAULT_ROUTE = "ares-route"
DEFAULT_APP_LABEL = "ares-traffic"
TRACK_LABEL_KEY = "track"
APP_LABEL_KEY = "app"
TRACKS: Tuple[str, str] = ("stable", "canary")

#: The repository's release-identity carrier (Phase 6.5.2,
#: ``deployment_service/.../release_identity_injection.py``). Recorded as
#: observed evidence when a workload carries it; see the binding rule for
#: why it does not by itself establish the binding. Kept as literals so
#: the incident service does not import from another service; the B.1
#: test suite asserts they stay identical to the deployment service's.
DEPLOYMENT_ID_ENV = "DEVOPS_DEPLOYMENT_ID"
SOURCE_SHA_ENV = "DEVOPS_SOURCE_SHA"

#: Binding bases reported in the record (§14).
BINDING_CONFIGURED = "configured-attestation"
BINDING_UNBOUND = "unbound"
BINDING_MISMATCH = "request-vs-configured-mismatch"

#: Findings are classified, not merged: a conflict always wins over an
#: unavailable fact, so a contradiction can never be downgraded.
_CONFLICT = "conflict"
_UNAVAILABLE = "unavailable"

_MAX_FINDINGS = 6


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _label_map(document: Mapping[str, Any]) -> Mapping[str, Any]:
    metadata = document.get("metadata") or {}
    labels = metadata.get("labels")
    return labels if isinstance(labels, dict) else {}


def _identity(document: Mapping[str, Any]) -> Optional[str]:
    metadata = document.get("metadata") or {}
    value = metadata.get("uid")
    return value if isinstance(value, str) and value else None


def _selector_matches(selector: Mapping[str, Any], labels: Mapping[str, Any]) -> bool:
    """Kubernetes label-selector semantics for the equality case.

    ``matchLabels``/plain selectors are equality maps; a Service whose
    selector is not a subset of a pod's labels does not select that pod.
    """
    return all(labels.get(key) == value for key, value in selector.items())


def _endpoint_ready(endpoint: Mapping[str, Any]) -> bool:
    """EndpointSlice readiness, per the API contract.

    ``conditions.ready`` is optional: a nil value means "unknown" and
    Kubernetes documents that consumers should interpret it as ready,
    while an explicit ``false`` means not ready.
    """
    conditions = endpoint.get("conditions") or {}
    return conditions.get("ready") is not False


@dataclass(frozen=True)
class RouteFacts:
    """Directly observed ``HTTPRoute`` facts (configured + controller)."""

    name: str
    namespace: str
    generation: Optional[int] = None
    weights: Optional[Mapping[str, int]] = None
    backends: Optional[Mapping[str, str]] = None
    accepted: Optional[bool] = None
    resolved_refs: Optional[bool] = None
    controller_observed_generation: Optional[int] = None
    rules_with_backends: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "namespace": self.namespace,
            "generation": self.generation,
            "configured_weights": dict(self.weights) if self.weights else None,
            "backend_services": dict(self.backends) if self.backends else None,
            "rules_with_backend_refs": self.rules_with_backends,
        }


@dataclass(frozen=True)
class TargetFacts:
    """What one track's Service actually resolves to, live."""

    track: str
    service: str
    namespace: str = DEFAULT_NAMESPACE
    service_uid: Optional[str] = None
    selector: Mapping[str, Any] = field(default_factory=dict)
    ready_endpoints: Tuple[str, ...] = ()
    not_ready_endpoints: Tuple[str, ...] = ()
    ready_endpoint_uids: Tuple[str, ...] = ()
    workload: Optional[str] = None
    workload_images: Tuple[str, ...] = ()
    identity_carrier: Mapping[str, str] = field(default_factory=dict)

    @property
    def identity(self) -> str:
        """Deterministic, non-ephemeral target identity.

        The mutation-relevant target of a Gateway API weighted route is
        its ``backendRef`` — the Service. Pod names and UIDs are recorded
        as *evidence* in the record but are deliberately not part of the
        identity, because they change whenever a pod is rescheduled and
        would make two otherwise identical observations differ.
        """
        return f"{self.namespace}/service/{self.service}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "track": self.track,
            "identity": self.identity,
            "namespace": self.namespace,
            "service": self.service,
            "service_uid": self.service_uid,
            "selector": dict(self.selector),
            "ready_endpoints": list(self.ready_endpoints),
            "ready_endpoint_uids": list(self.ready_endpoint_uids),
            "not_ready_endpoints": list(self.not_ready_endpoints),
            "workload": self.workload,
            "workload_images": list(self.workload_images),
            "identity_carrier": dict(self.identity_carrier),
        }


@dataclass(frozen=True)
class TrafficObservation:
    """The full, structured result of one observation.

    ``observation`` is the port-visible truth. The remaining fields keep
    the three evidence classes apart (Phase 8.7-B.0's rule): what the
    route *declares*, what the *controller* says, and what the live
    *workloads* are. They are never merged into one synthetic fact.
    """

    observation: ObservedTrafficState
    route: Optional[RouteFacts]
    targets: Mapping[str, TargetFacts]
    endpoints_disjoint: Optional[bool]
    shared_endpoints: Tuple[str, ...]
    binding: str
    binding_established: bool
    findings: Tuple[Tuple[str, str], ...]
    collected_at: datetime
    configured_percentage: Optional[int] = None
    configured_fraction: Optional[Tuple[int, int]] = None
    client_config: Mapping[str, Any] = field(default_factory=dict)

    @property
    def status(self) -> str:
        return self.observation.observed_status

    def checks(self) -> List[Dict[str, Any]]:
        """Machine-readable checks for the live E2E evidence.

        Each entry mirrors (but never replaces) the structured facts:
        the driver records both, so a check can never contradict the
        evidence it summarises.
        """
        rows: List[Dict[str, Any]] = []

        def row(name: str, requested: str, observed: str, ok: bool) -> None:
            rows.append({"check": name, "requested": requested,
                         "observed": observed, "status": "PASS" if ok else "FAIL"})

        status = self.status
        row("observation:status-known",
            "the live cluster yields a complete, trustworthy observation",
            f"status={status} findings={[text for _, text in self.findings][:2]}",
            status == OBSERVED_KNOWN)
        row("observation:percentage-exact",
            "the observed share is the exact integer percentage of the live weights",
            (f"observed_percentage={self.observation.observed_percentage} "
             f"configured_fraction={self.configured_fraction} "
             f"configured_percentage={self.configured_percentage}"),
            (self.observation.observed_percentage is None
             and status != OBSERVED_KNOWN)
            or self.observation.observed_percentage == self.configured_percentage)
        row("observation:no-fabrication",
            "no percentage, identity or binding is reported for a non-KNOWN state",
            (f"status={status} percentage={self.observation.observed_percentage} "
             f"stable={self.observation.stable_identity} "
             f"canary={self.observation.canary_identity} "
             f"run={self.observation.deployment_run_id} sha={self.observation.source_sha}"),
            status == OBSERVED_KNOWN
            or (self.observation.observed_percentage is None
                and self.observation.stable_identity is None
                and self.observation.canary_identity is None
                and self.observation.deployment_run_id is None
                and self.observation.source_sha is None))
        row("observation:timestamp",
            "the observation carries a timezone-aware UTC timestamp",
            str(self.observation.observation_timestamp),
            self.observation.observation_timestamp is not None
            and self.observation.observation_timestamp.tzinfo is not None
            and self.observation.observation_timestamp.utcoffset()
            == timezone.utc.utcoffset(None))
        row("observation:provider-stable",
            "the provider and source identities are deterministic constants",
            f"provider={self.observation.provider} source={self.observation.observation_source}",
            self.observation.provider == PROVIDER_NAME
            and self.observation.observation_source == OBSERVATION_SOURCE)
        row("observation:binding-established",
            "the observation is attributable to the requested deployment/source",
            f"basis={self.binding} established={self.binding_established} "
            f"run={self.observation.deployment_run_id} sha={self.observation.source_sha}",
            self.binding_established == (status == OBSERVED_KNOWN))
        if self.targets:
            stable = self.targets.get("stable")
            canary = self.targets.get("canary")
            row("observation:targets-proven",
                "both tracks resolve to live ready endpoints",
                (f"stable={list(stable.ready_endpoints) if stable else None} "
                 f"canary={list(canary.ready_endpoints) if canary else None}"),
                bool(stable and canary and stable.ready_endpoints
                     and canary.ready_endpoints))
            row("observation:endpoints-disjoint",
                "the two Services resolve to different pods",
                (f"disjoint={self.endpoints_disjoint} "
                 f"shared={list(self.shared_endpoints)}"),
                self.endpoints_disjoint is True)
        return rows

    def to_dict(self) -> Dict[str, Any]:
        stable = self.targets.get("stable")
        canary = self.targets.get("canary")
        return {
            "provider": self.observation.provider,
            "observation_source": self.observation.observation_source,
            "status": self.observation.observed_status,
            "configured": {
                "route": self.route.to_dict() if self.route else None,
                "weights": dict(self.route.weights) if self.route and self.route.weights else None,
                "canary_fraction": (
                    {"numerator": self.configured_fraction[0],
                     "denominator": self.configured_fraction[1]}
                    if self.configured_fraction else None
                ),
                "canary_percentage": self.configured_percentage,
                "note": ("observed_percentage is the effective configured share "
                         "derived from these live weights; it is not a sampled "
                         "request percentage"),
            },
            "controller": {
                "accepted": self.route.accepted if self.route else None,
                "resolved_refs": self.route.resolved_refs if self.route else None,
                "observed_generation": (
                    self.route.controller_observed_generation if self.route else None),
                "route_generation": self.route.generation if self.route else None,
            },
            "observed": {
                "percentage": self.observation.observed_percentage,
                "stable": stable.to_dict() if stable else None,
                "canary": canary.to_dict() if canary else None,
                "endpoints_disjoint": self.endpoints_disjoint,
                "shared_endpoints": list(self.shared_endpoints),
            },
            "binding": {
                "rule": ("the observation is attributed to the request only when the "
                         "request matches the observer's host-owned configured binding, "
                         "or when the live workload carries the repository's release "
                         "identity carrier and it matches"),
                "basis": self.binding,
                "established": self.binding_established,
                "deployment_run_id": self.observation.deployment_run_id,
                "source_sha": self.observation.source_sha,
            },
            "findings": [{"severity": severity, "text": text}
                         for severity, text in self.findings],
            "observation_timestamp": (
                _utc(self.collected_at).isoformat() if self.collected_at else None),
            "detail": self.observation.detail,
            "client": dict(self.client_config),
        }


class KubernetesTrafficObserver:
    """Read-only observation provider for a Gateway API weighted route.

    Binding rule (§14), stated once and applied mechanically:

    1. The observer carries a *host-owned* expected binding
       (``expected_deployment_run_id`` / ``expected_source_sha``) taken
       from trusted application configuration — never from the request.
    2. ``inspect(run, sha)`` reports the binding only when the request
       matches that configuration. The values in the returned
       ``ObservedTrafficState`` are therefore **attestation against
       configuration**, never a claim derived from the workloads: the
       B.0 workloads carry no release identity, and inventing one (for
       example mapping an image tag to a SHA) is forbidden.
    3. A request that contradicts the configured binding is ``CONFLICT``
       — not a silent ``UNKNOWN`` — because the cluster cannot refute the
       caller's claim, and a shadow "unknown" would hide the mismatch.
    4. An observer with no configured binding reports ``UNKNOWN``: it
       cannot answer "why is this observation yours?".
    5. When a workload *does* carry the repository's release-identity
       carrier, it is recorded under ``observed`` as evidence. B.1 does
       not use it to establish the binding: a progressive topology
       legitimately runs two revisions at once, and a per-track carrier
       rule belongs to the phase that introduces trusted mutation.
    """

    def __init__(
        self,
        client: Any,
        *,
        route_name: str = DEFAULT_ROUTE,
        namespace: str = DEFAULT_NAMESPACE,
        app_label: str = DEFAULT_APP_LABEL,
        expected_deployment_run_id: Optional[str] = None,
        expected_source_sha: Optional[str] = None,
        now_factory: Optional[Any] = None,
    ) -> None:
        if client is None:
            raise ValueError("a read client is required")
        self._client = client
        self._route_name = route_name
        self._namespace = namespace
        self._app_label = app_label
        self._expected_run = expected_deployment_run_id or None
        self._expected_sha = expected_source_sha or None
        self._now_factory = now_factory or (lambda: datetime.now(timezone.utc))

    # ---------------------------------------------------------- properties

    @property
    def provider_name(self) -> str:
        return PROVIDER_NAME

    @property
    def observation_source(self) -> str:
        return OBSERVATION_SOURCE

    # ------------------------------------------------------ read-only port

    def inspect(self, deployment_run_id: str, source_sha: str) -> ObservedTrafficState:
        """``TrafficControllerPort.inspect`` — observe, never mutate."""
        return self.inspect_detailed(deployment_run_id, source_sha).observation

    def plan(self, intent: Any) -> Dict[str, Any]:
        """``TrafficControllerPort.plan`` — a pure renderer (no cluster access).

        Phase 6.7.1's contract is "plan != apply", and this provider keeps
        it literally: ``plan`` reads nothing, writes nothing and has no
        client reference in its body, so it *cannot* change traffic. It
        renders the desired change a future, separately-authorized
        mutation phase would need to perform.
        """
        return {
            "provider": PROVIDER_NAME,
            "read_only": True,
            "mutates": False,
            "intent_id": getattr(intent, "intent_id", None),
            "deployment_run_id": getattr(intent, "deployment_run_id", None),
            "source_sha": getattr(intent, "source_sha", None),
            "stable_target": getattr(intent, "stable_target", None),
            "canary_target": getattr(intent, "canary_target", None),
            "current_percentage": getattr(intent, "current_percentage", None),
            "requested_percentage": getattr(intent, "requested_percentage", None),
            "note": ("rendered by a read-only observation provider: this phase "
                     "cannot apply, patch or roll back anything"),
        }

    # ----------------------------------------------------------- inspection

    def inspect_detailed(
        self, deployment_run_id: Any, source_sha: Any
    ) -> TrafficObservation:
        collected_at = _utc(self._now_factory())
        findings: List[Tuple[str, str]] = []

        requested, problem = self._validated_binding_inputs(
            deployment_run_id, source_sha
        )
        binding = BINDING_UNBOUND
        binding_established = False
        if problem:
            findings.append((_UNAVAILABLE, problem))
        elif self._expected_run is None and self._expected_sha is None:
            findings.append((
                _UNAVAILABLE,
                "this observer has no configured deployment/source binding, so the "
                "observation cannot be attributed to a deployment run",
            ))
        else:
            mismatches = []
            if self._expected_run is not None and requested[0] != self._expected_run:
                mismatches.append("deployment_run_id")
            if self._expected_sha is not None and requested[1] != self._expected_sha:
                mismatches.append("source_sha")
            if mismatches:
                binding = BINDING_MISMATCH
                findings.append((
                    _CONFLICT,
                    "the requested " + "/".join(mismatches) + " does not match the "
                    "observer's configured binding for this topology",
                ))
            else:
                binding = BINDING_CONFIGURED
                binding_established = True

        route_facts, targets, disjoint, shared, cluster_findings = self._observe_topology()
        findings.extend(cluster_findings)

        weights = route_facts.weights if route_facts else None
        fraction: Optional[Tuple[int, int]] = None
        configured_percentage: Optional[int] = None
        if weights is not None and "stable" in weights and "canary" in weights:
            stable_weight = weights["stable"]
            canary_weight = weights["canary"]
            total = stable_weight + canary_weight
            if total <= 0:
                findings.append((
                    _UNAVAILABLE,
                    f"the route declares a zero total weight ({stable_weight}+"
                    f"{canary_weight}); no share can be derived",
                ))
            else:
                fraction = (canary_weight, total)
                if (canary_weight * 100) % total == 0:
                    configured_percentage = (canary_weight * 100) // total
                else:
                    findings.append((
                        _UNAVAILABLE,
                        f"the canary share {canary_weight}/{total} is not an exact "
                        f"integer percentage; B.1 reports no rounded value",
                    ))

        status = self._resolve_status(findings)
        known = status == OBSERVED_KNOWN
        stable_facts = targets.get("stable")
        canary_facts = targets.get("canary")
        observation = ObservedTrafficState(
            provider=PROVIDER_NAME,
            observed_status=status,
            observed_percentage=configured_percentage if known else None,
            stable_identity=(stable_facts.identity if known and stable_facts else None),
            canary_identity=(canary_facts.identity if known and canary_facts else None),
            deployment_run_id=(requested[0] if known and binding_established and requested
                               else None),
            source_sha=(requested[1] if known and binding_established and requested
                        else None),
            observation_timestamp=collected_at,
            observation_source=OBSERVATION_SOURCE,
            detail=self._detail(status, route_facts, weights, configured_percentage,
                                findings),
        )
        return TrafficObservation(
            observation=observation,
            route=route_facts,
            targets=targets,
            endpoints_disjoint=disjoint,
            shared_endpoints=shared,
            binding=binding,
            binding_established=binding_established,
            findings=tuple(findings[:_MAX_FINDINGS]),
            collected_at=collected_at,
            configured_percentage=configured_percentage,
            configured_fraction=fraction,
            client_config=self._client_config(),
        )

    # ------------------------------------------------------------- internals

    @staticmethod
    def _validated_binding_inputs(
        deployment_run_id: Any, source_sha: Any
    ) -> Tuple[Optional[Tuple[str, str]], Optional[str]]:
        """Validate the caller's binding request (fail closed, never raise)."""
        if not isinstance(deployment_run_id, str) or not deployment_run_id.strip():
            return None, "deployment_run_id must be a non-empty string"
        if len(deployment_run_id) > 128:
            return None, "deployment_run_id must be at most 128 characters"
        if not isinstance(source_sha, str) or len(source_sha) != 40 or any(
            character not in "0123456789abcdef" for character in source_sha
        ):
            return None, "source_sha must be the exact 40-character lowercase hex SHA"
        return (deployment_run_id, source_sha), None

    @staticmethod
    def _resolve_status(findings: Sequence[Tuple[str, str]]) -> str:
        if any(severity == _CONFLICT for severity, _ in findings):
            return OBSERVED_CONFLICT
        if findings:
            return OBSERVED_UNKNOWN
        return OBSERVED_KNOWN

    def _client_config(self) -> Dict[str, Any]:
        config = getattr(self._client, "config", None)
        if config is not None and hasattr(config, "to_dict"):
            return dict(config.to_dict())
        return {}

    def _observe_topology(self):
        """Read the live topology; returns facts plus classified findings."""
        findings: List[Tuple[str, str]] = []
        route_facts: Optional[RouteFacts] = None
        targets: Dict[str, TargetFacts] = {}
        disjoint: Optional[bool] = None
        shared: Tuple[str, ...] = ()

        try:
            route = self._client.get_http_route(self._route_name, self._namespace)
        except KubernetesResourceNotFound as exc:
            findings.append((
                _UNAVAILABLE,
                f"the observed route {self._namespace}/{self._route_name} does not "
                f"exist: "
                f"{redact(exc)}",
            ))
            return None, targets, None, (), findings
        except KubernetesReadError as exc:
            findings.append((
                _UNAVAILABLE,
                f"the observed route could not be read: {redact(exc)}",
            ))
            return None, targets, None, (), findings

        route_facts = self._route_facts(route)
        refs, ref_findings = self._backend_refs(route)
        findings.extend(ref_findings)
        if refs is None:
            return route_facts, targets, disjoint, shared, findings

        # ---- resolve every backendRef to a live Service and to its track.
        # The track comes from the Service's own live label — never from
        # the request, never from a name convention: identity must be
        # observed, and an ambiguous identity is a conflict, not a guess.
        resolved: Dict[str, Tuple[str, Mapping[str, Any]]] = {}
        weights: Dict[str, int] = {}
        for service_name, weight in refs:
            try:
                service = self._client.get_service(service_name, self._namespace)
            except KubernetesResourceNotFound as exc:
                findings.append((
                    _UNAVAILABLE,
                    f"backend Service {self._namespace}/{service_name} does not "
                    f"exist: {redact(exc)}",
                ))
                continue
            except KubernetesReadError as exc:
                findings.append((
                    _UNAVAILABLE,
                    f"Service {service_name} read failed: {redact(exc)}",
                ))
                continue
            labels = _label_map(service)
            track = labels.get(TRACK_LABEL_KEY)
            if track not in TRACKS:
                findings.append((
                    _CONFLICT,
                    f"backend Service {service_name} declares "
                    f"{TRACK_LABEL_KEY}={track!r}; the track identity of a backend "
                    f"must be one of {list(TRACKS)}",
                ))
                continue
            if labels.get(APP_LABEL_KEY) != self._app_label:
                findings.append((
                    _CONFLICT,
                    f"backend Service {service_name} declares "
                    f"{APP_LABEL_KEY}={labels.get(APP_LABEL_KEY)!r}, not "
                    f"{self._app_label!r}; it is not part of the observed topology",
                ))
                continue
            if track in resolved:
                findings.append((
                    _CONFLICT,
                    f"two backendRefs resolve to the same {track!r} track "
                    f"({resolved[track][0]} and {service_name}); the target identity "
                    f"is ambiguous",
                ))
                continue
            resolved[track] = (service_name, service)
            weights[track] = weight

        route_facts = RouteFacts(
            name=route_facts.name,
            namespace=route_facts.namespace,
            generation=route_facts.generation,
            weights=weights or None,
            backends={track: name for track, (name, _) in resolved.items()} or None,
            accepted=route_facts.accepted,
            resolved_refs=route_facts.resolved_refs,
            controller_observed_generation=route_facts.controller_observed_generation,
            rules_with_backends=route_facts.rules_with_backends,
        )

        if route_facts.resolved_refs is False and len(resolved) == len(refs):
            findings.append((
                _CONFLICT,
                "the controller reports ResolvedRefs=False while every referenced "
                "backend exists; controller and observed configuration disagree",
            ))

        pods_by_name: Optional[Dict[str, Mapping[str, Any]]] = None
        deployments: Optional[List[Mapping[str, Any]]] = None

        for track in TRACKS:
            resolved_service = resolved.get(track)
            if resolved_service is None:
                continue
            service_name, service = resolved_service
            selector = ((service.get("spec") or {}).get("selector") or {})
            try:
                slices = self._client.list_endpoint_slices(self._namespace, service_name)
            except KubernetesReadError as exc:
                findings.append((
                    _UNAVAILABLE,
                    f"EndpointSlices for {service_name} are unavailable: {redact(exc)}",
                ))
                continue

            ready: List[Tuple[str, Optional[str]]] = []
            not_ready: List[str] = []
            identity_problem = False
            for slice_document in slices:
                for endpoint in slice_document.get("endpoints") or []:
                    target = endpoint.get("targetRef") or {}
                    name = target.get("name")
                    kind = target.get("kind")
                    target_namespace = target.get("namespace") or self._namespace
                    if kind != "Pod" or not isinstance(name, str) or not name:
                        identity_problem = True
                        continue
                    if target_namespace != self._namespace:
                        identity_problem = True
                        continue
                    if _endpoint_ready(endpoint):
                        ready.append((name, endpoint.get("targetRef", {}).get("uid")))
                    else:
                        not_ready.append(name)
            if identity_problem:
                findings.append((
                    _UNAVAILABLE,
                    f"an endpoint behind {service_name} has no Pod targetRef, so its "
                    f"workload identity cannot be established",
                ))
            if not ready:
                findings.append((
                    _UNAVAILABLE,
                    f"Service {service_name} has no ready endpoints (EndpointSlices="
                    f"{len(slices)})",
                ))

            if pods_by_name is None:
                pods_by_name = {}
                try:
                    for pod in self._client.list_pods(self._namespace, self._app_label):
                        pod_name = ((pod.get("metadata") or {}).get("name"))
                        if isinstance(pod_name, str):
                            pods_by_name[pod_name] = pod
                except KubernetesReadError as exc:
                    findings.append((
                        _UNAVAILABLE,
                        f"pod listing is unavailable: {redact(exc)}",
                    ))
            if deployments is None:
                deployments = []
                try:
                    deployments = list(
                        self._client.list_deployments(self._namespace, self._app_label)
                    )
                except KubernetesReadError as exc:
                    findings.append((
                        _UNAVAILABLE,
                        f"deployment listing is unavailable: {redact(exc)}",
                    ))

            workloads: List[str] = []
            images: List[str] = []
            carrier: Dict[str, str] = {}
            for name, _uid in ready:
                pod = pods_by_name.get(name)
                if pod is None:
                    findings.append((
                        _UNAVAILABLE,
                        f"ready endpoint {name} of {service_name} is not visible in the "
                        f"pod listing, so its identity cannot be established",
                    ))
                    continue
                labels = _label_map(pod)
                if not _selector_matches(selector, labels):
                    findings.append((
                        _CONFLICT,
                        f"ready endpoint {name} of {service_name} is not selected by "
                        f"that Service's selector",
                    ))
                    continue
                if labels.get(TRACK_LABEL_KEY) != track:
                    findings.append((
                        _CONFLICT,
                        f"ready endpoint {name} behind the {track} Service carries "
                        f"{TRACK_LABEL_KEY}={labels.get(TRACK_LABEL_KEY)!r}",
                    ))
                    continue
                matching = [workload for workload in deployments
                            if _selector_matches(
                                ((workload.get("spec") or {}).get("selector") or {})
                                .get("matchLabels") or {}, labels)]
                if len(matching) > 1:
                    findings.append((
                        _CONFLICT,
                        f"pod {name} is matched by {len(matching)} Deployments "
                        f"({sorted((w.get('metadata') or {}).get('name') for w in matching)}); "
                        f"the workload identity is ambiguous",
                    ))
                elif matching:
                    workload_name = ((matching[0].get("metadata") or {}).get("name"))
                    if isinstance(workload_name, str):
                        workloads.append(workload_name)
                    for container in (((matching[0].get("spec") or {}).get("template") or {})
                                      .get("spec") or {}).get("containers") or []:
                        image = container.get("image")
                        if isinstance(image, str):
                            images.append(image)
                        for entry in container.get("env") or []:
                            key = entry.get("name")
                            value = entry.get("value")
                            if key in (DEPLOYMENT_ID_ENV, SOURCE_SHA_ENV) and isinstance(
                                value, str
                            ):
                                carrier[key] = value

            targets[track] = TargetFacts(
                track=track,
                service=service_name,
                namespace=self._namespace,
                service_uid=_identity(service),
                selector=dict(selector),
                ready_endpoints=tuple(sorted(name for name, _ in ready)),
                not_ready_endpoints=tuple(sorted(not_ready)),
                ready_endpoint_uids=tuple(
                    sorted(uid for _, uid in ready if isinstance(uid, str))
                ),
                workload=(sorted(set(workloads))[0] if len(set(workloads)) == 1
                          and workloads else None),
                workload_images=tuple(sorted(set(images))[:2]),
                identity_carrier=dict(sorted(carrier.items())),
            )

        stable, canary = targets.get("stable"), targets.get("canary")
        if stable and canary:
            stable_ids = set(stable.ready_endpoint_uids) | set(stable.ready_endpoints)
            canary_ids = set(canary.ready_endpoint_uids) | set(canary.ready_endpoints)
            shared = tuple(sorted(stable_ids & canary_ids))
            disjoint = not shared
            if shared:
                findings.append((
                    _CONFLICT,
                    f"stable and canary resolve to the same workload identity: "
                    f"{list(shared)}",
                ))
            if stable.workload and stable.workload == canary.workload:
                findings.append((
                    _CONFLICT,
                    f"both Services resolve into the same Deployment "
                    f"({stable.workload})",
                ))
        return route_facts, targets, disjoint, shared, findings

    @staticmethod
    def _route_facts(route: Mapping[str, Any]) -> RouteFacts:
        metadata = route.get("metadata") or {}
        spec = route.get("spec") or {}
        rules = [rule for rule in spec.get("rules") or []
                 if (rule or {}).get("backendRefs")]
        parents = ((route.get("status") or {}).get("parents") or [])
        conditions: Sequence[Mapping[str, Any]] = ()
        for parent in parents:
            if parent.get("conditions"):
                conditions = parent.get("conditions") or ()
                break
        by_type = {condition.get("type"): condition for condition in conditions
                   if isinstance(condition, dict)}
        accepted = by_type.get("Accepted", {}).get("status")
        resolved = by_type.get("ResolvedRefs", {}).get("status")
        generations = [condition.get("observedGeneration")
                       for condition in conditions
                       if isinstance(condition, dict)
                       and isinstance(condition.get("observedGeneration"), int)]
        return RouteFacts(
            name=str(metadata.get("name") or ""),
            namespace=str(metadata.get("namespace") or ""),
            generation=(metadata.get("generation")
                        if isinstance(metadata.get("generation"), int) else None),
            accepted=(accepted == "True" if accepted is not None else None),
            resolved_refs=(resolved == "True" if resolved is not None else None),
            controller_observed_generation=(max(generations) if generations else None),
            rules_with_backends=len(rules),
        )

    @staticmethod
    def _backend_refs(route: Mapping[str, Any]):
        """Extract the two required backendRefs, or explain why not.

        Fail-closed rules (documented in the phase doc): a route must
        declare exactly one rule with backendRefs and exactly two
        distinct backends, and each weight must be a non-negative
        integer. Anything else is reported, never coerced: a malformed
        weight becomes an UNKNOWN observation, not a guessed percentage.
        """
        findings: List[Tuple[str, str]] = []
        spec = route.get("spec") or {}
        rules = [rule for rule in spec.get("rules") or []
                 if (rule or {}).get("backendRefs")]
        if len(rules) != 1:
            findings.append((
                _CONFLICT,
                f"the route declares {len(rules)} rules with backendRefs; a single "
                f"weighted rule is required to derive one traffic share",
            ))
            return None, findings
        refs = rules[0].get("backendRefs") or []
        if len(refs) != 2:
            findings.append((
                _CONFLICT,
                f"the route declares {len(refs)} backendRefs; exactly one stable and "
                f"one canary backend are required",
            ))
            return None, findings
        names = [(ref or {}).get("name") for ref in refs]
        if len(set(names)) != len(names):
            findings.append((
                _CONFLICT,
                f"the route declares duplicate backendRef names {names}",
            ))
            return None, findings
        extracted: List[Tuple[str, int]] = []
        for ref in refs:
            name = (ref or {}).get("name")
            if not isinstance(name, str) or not name.strip():
                findings.append((
                    _UNAVAILABLE,
                    "a backendRef has no usable name, so its target cannot be observed",
                ))
                return None, findings
            weight = (ref or {}).get("weight")
            if not isinstance(weight, int) or isinstance(weight, bool):
                findings.append((
                    _UNAVAILABLE,
                    f"backendRef {name!r} has a malformed weight {weight!r} (expected a "
                    f"non-negative integer); no percentage is inferred from it",
                ))
                return None, findings
            if weight < 0:
                findings.append((
                    _UNAVAILABLE,
                    f"backendRef {name!r} has a negative weight {weight}",
                ))
                return None, findings
            extracted.append((name, weight))
        return extracted, findings

    @staticmethod
    def _detail(
        status: str,
        route: Optional[RouteFacts],
        weights: Optional[Mapping[str, int]],
        percentage: Optional[int],
        findings: Sequence[Tuple[str, str]],
    ) -> str:
        route_text = f"{route.namespace}/{route.name}" if route else "<no route>"
        text = (
            f"status={status} route={route_text} weights={dict(weights) if weights else None} "
            f"observed_canary_percentage={percentage}"
        )
        if findings:
            text += " findings=" + " | ".join(f"[{severity}] {message}"
                                              for severity, message in findings[:3])
        return redact(text, limit=400)


__all__ = [
    "APP_LABEL_KEY",
    "BINDING_CONFIGURED",
    "BINDING_MISMATCH",
    "BINDING_UNBOUND",
    "DEFAULT_APP_LABEL",
    "DEFAULT_NAMESPACE",
    "DEFAULT_ROUTE",
    "DEPLOYMENT_ID_ENV",
    "KubernetesTrafficObserver",
    "OBSERVATION_SOURCE",
    "PROVIDER_NAME",
    "RouteFacts",
    "SOURCE_SHA_ENV",
    "TRACKS",
    "TRACK_LABEL_KEY",
    "TargetFacts",
    "TrafficObservation",
]
