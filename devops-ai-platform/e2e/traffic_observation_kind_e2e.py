#!/usr/bin/env python3
"""Phase 8.7-B.1 — the read-only traffic observation adapter, proven live.

WHAT THIS PROVES
    The application's traffic observation provider
    (``incident_service/infrastructure/traffic/gateway_api_observer.py``,
    driven through the existing provider-neutral
    ``TrafficControllerPort``) reports the *real* state of a live
    Kubernetes Gateway API topology:

    * which two Services the weighted route points at, and with which
      proportional weights (the configured state, read back from the API
      server — never from a manifest on disk);
    * which ready endpoints those Services resolve to, and that the two
      endpoint sets are disjoint (the target identity);
    * when it must refuse to answer: an unavailable read, a malformed
      weight, a zero denominator, a non-integral share and contradictory
      cluster truth are reported as UNKNOWN / CONFLICT with the reason,
      never as a fabricated percentage.

    The live states are established by the same machinery Phase 8.7-B.0
    proved (this driver reuses that driver's helpers verbatim: preflight,
    pinned-stack checks, fixture render/apply, readiness gates, weight
    patching, sampling). What changes is who reads the result: here the
    *application code* reads the cluster, and its answer is compared
    against an independent ``kubectl`` read taken by this driver.

WHAT THIS DRIVER IS NOT
    * It is NOT a traffic-mutation capability. The application still has
      no way to change traffic: the observation provider exposes reads
      only, and ``plan()`` is a pure renderer with no cluster access at
      all. The only thing that mutates the route is this driver's
      ``kubectl patch``, inside a disposable Kind cluster, to create proof
      states — exactly as in Phase 8.7-B.0. The Phase 8.7-A mutation
      boundary is never imported or called.
    * It is NOT a request-sampling proof. Phase 8.7-B.0's job measures
      real HTTP responses; this driver *observes configuration*. Its
      ``observed_percentage`` is the effective configured share derived
      from the observed route weights, and the evidence keeps that
      distinct from the sampled measurement it cross-checks against
      (``observation:live-traffic-agrees``).

FAIL CLOSED
    Every wait has an explicit deadline, and the driver stops instead of
    asserting a traffic claim it did not verify. The adapter is exercised
    with a fresh read client for every observation, so a stale answer
    cannot pass: the states are patch/observe pairs, and each is
    cross-checked against the driver's own independent read.

Usage:
    python e2e/traffic_observation_kind_e2e.py \\
        --cluster ares-observation-e2e \\
        --stable-image ares-observation-stable:local \\
        --canary-image ares-observation-canary:local \\
        --sampler-image ares-observation-sampler:local \\
        --deployment-run-id "$GITHUB_RUN_ID" \\
        --expected-commit "$GITHUB_SHA" \\
        --destroy-cluster \\
        --evidence e2e-evidence/traffic-observation-e2e.json
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from e2e import traffic_topology_kind_e2e as topology_driver  # noqa: E402
from e2e.evidence_provenance import provenance, seal  # noqa: E402
from e2e.traffic_topology import (  # noqa: E402
    GATEWAY,
    HTTP_ROUTE,
    NAMESPACE,
    SERVICE,
    TOPOLOGY_DIR,
    load_documents,
    verify_documents,
)
from incident_service.application.services.rollout_plan_service import (  # noqa: E402
    OBSERVED_CONFLICT,
    OBSERVED_KNOWN,
    OBSERVED_UNKNOWN,
)
from incident_service.infrastructure.traffic.gateway_api_observer import (  # noqa: E402
    BINDING_CONFIGURED,
    BINDING_MISMATCH,
    BINDING_UNBOUND,
    OBSERVATION_SOURCE,
    PROVIDER_NAME,
    KubernetesTrafficObserver,
)
from incident_service.infrastructure.traffic.kubernetes_read_client import (  # noqa: E402
    OPERATION_RESOURCES,
    KubectlReadClient,
    ReadOperation,
    TrafficReadConfig,
)

notice = topology_driver.notice
record = topology_driver.record

#: A Service name that can never exist in the fixture (used to put the
#: live route into an unavailable state on purpose).
MISSING_BACKEND = "ares-backend-that-does-not-exist"

#: Requests used for the supplementary traffic cross-check at the
#: committed state. B.0 owns the traffic proof; this is a triangulation
#: against it with the same tolerance method, one state, one budget.
CROSS_CHECK_SAMPLES = 500

OBSERVATIONS: List[Dict[str, Any]] = []
READ_ONLY: Dict[str, Any] = {}


# ------------------------------------------------------------------ target


class ObservationTarget:
    """Host-owned configuration for the adapter, taken from the fixture.

    The adapter must never learn *what to observe* from the cluster or
    from the caller: the namespace, route name and app label come from
    the committed fixture in the repository, and this driver confirms the
    live cluster actually matches them.
    """

    def __init__(self, namespace: str, route_name: str, app_label: str) -> None:
        self.namespace = namespace
        self.route_name = route_name
        self.app_label = app_label

    @classmethod
    def from_fixture(cls, documents: Sequence[Mapping[str, Any]]) -> "ObservationTarget":
        """Route name, namespace and app label, read off the fixture.

        The fixture spans more than one namespace on purpose (the Envoy
        data plane lives in ``envoy-gateway-system``), so the topology's
        namespace is the one the *route* declares — and every workload
        must agree with it, or the configuration is ambiguous and the
        driver refuses to guess.
        """
        routes = [doc for doc in documents if doc.get("kind") == "HTTPRoute"]
        if len(routes) != 1:
            raise RuntimeError(
                f"the fixture declares {len(routes)} routes "
                f"{[doc.get('metadata', {}).get('name') for doc in routes]}; exactly "
                f"one weighted route defines what the observer targets")
        route = routes[0]
        namespace = str((route.get("metadata") or {}).get("namespace") or "")
        workloads = {str((doc.get("metadata") or {}).get("namespace") or "")
                     for doc in documents if doc.get("kind") in ("Service", "Deployment")}
        labels = {((doc.get("metadata") or {}).get("labels") or {}).get("app")
                  for doc in documents if doc.get("kind") in ("Service", "Deployment")}
        labels.discard(None)
        if not namespace or workloads != {namespace} or len(labels) != 1:
            raise RuntimeError(
                f"the fixture declares route namespace={namespace!r} "
                f"workload namespaces={sorted(workloads)} "
                f"app_labels={sorted(labels)}; one namespace and one app label are "
                f"required to configure the observer")
        return cls(namespace, str((route.get("metadata") or {}).get("name")), labels.pop())

    def matches_module_constants(self) -> bool:
        return (self.namespace == NAMESPACE and self.route_name == HTTP_ROUTE)

    def to_dict(self) -> Dict[str, Any]:
        return {"namespace": self.namespace, "route": self.route_name,
                "app_label": self.app_label,
                "source": "committed fixture (k8s/progressive), not live cluster "
                          "state and not the request"}


# ------------------------------------------------------------- observation


def read_config(target: ObservationTarget, args: argparse.Namespace) -> TrafficReadConfig:
    """Frozen, host-owned client configuration for one observation run."""
    return TrafficReadConfig(
        namespace=target.namespace,
        app_label=target.app_label,
        context=f"kind-{args.cluster}",
        timeout_seconds=int(args.observe_timeout),
    )


def observe(
    target: ObservationTarget,
    args: argparse.Namespace,
    *,
    expected_run: Optional[str],
    expected_sha: Optional[str],
    request_run: Optional[str],
    request_sha: Optional[str],
):
    """One live observation through the real application provider.

    A fresh client is constructed for every call: the adapter holds no
    cache, and a state change between two observations must be visible.
    """
    client = KubectlReadClient(read_config(target, args))
    observer = KubernetesTrafficObserver(
        client,
        route_name=target.route_name,
        namespace=target.namespace,
        app_label=target.app_label,
        expected_deployment_run_id=expected_run,
        expected_source_sha=expected_sha,
    )
    return observer.inspect_detailed(request_run, request_sha)


def summarise(record_) -> Dict[str, Any]:
    """The adapter's own JSON record, plus the two fields the checks read."""
    payload = record_.to_dict()
    payload["targets"] = {track: facts.to_dict()
                          for track, facts in sorted(record_.targets.items())}
    return payload


def check_row(name: str, requested: str, observed: str, ok: bool) -> bool:
    return record(f"observation:{name}", requested, observed, ok)


# ------------------------------------------------------------------ states


def wait_generation(cluster: str, target: ObservationTarget, name: str,
                    previous_generation: Any,
                    expected_refs: Optional[Sequence[str]] = None,
                    expect_resolved_false: bool = False,
                    timeout: float = 120.0) -> bool:
    """Wait until the API server shows the patched generation.

    A generation bump is the honest "the cluster has the new spec" signal;
    it does not assume anything about how the controller reacts.
    """
    def probe() -> Tuple[bool, str]:
        route = topology_driver.read_route(cluster)
        metadata = route.get("metadata") or {}
        generation = metadata.get("generation")
        refs = [ref.get("name") for ref in
                ((route.get("spec") or {}).get("rules") or [{}])[0].get("backendRefs") or []]
        parent = topology_driver.route_parent_status(route)
        conditions = parent.get("conditions")
        resolved = topology_driver.condition_status(conditions, "ResolvedRefs")
        observed = topology_driver.condition_observed_generations(conditions)
        ok = generation != previous_generation
        if expected_refs is not None:
            ok = ok and sorted(refs) == sorted(expected_refs)
        if expect_resolved_false:
            ok = ok and resolved == "False" and observed == [generation]
        return ok, (f"generation={generation} (was {previous_generation}) "
                    f"backendRefs={refs} resolvedRefs={resolved} "
                    f"observedGenerations={observed}")

    return topology_driver.wait_or_fail(
        f"observation:{name}:controller-saw-the-change", probe,
        "the API server serves the patched spec before the adapter is asked",
        timeout, cluster,
        (("get", "-n", target.namespace, "httproute", target.route_name, "-o", "yaml"),))


def observation_state(target: ObservationTarget, args: argparse.Namespace, state: Mapping[str, Any],
                      *, expected_run: str, expected_sha: str) -> bool:
    """Patch a live state (when the state asks for it), observe, cross-check."""
    cluster = args.cluster
    name = str(state["name"])
    weights = state.get("patch")
    ok = True

    if weights:
        topology_driver.patch_route_weights(cluster, weights)
        if not topology_driver.wait_or_fail(
            f"observation:{name}:controller-accepted",
            topology_driver.route_probe(cluster, weights),
            f"the controller accepted the live route at weights {dict(weights)}",
            args.readiness_timeout, cluster,
            (("get", "-n", target.namespace, "httproute", target.route_name, "-o", "yaml"),),
        ):
            return False

    # The driver's OWN read: an independent path (topology_driver.kubectl_json)
    # that shares no code with the adapter being tested.
    route = topology_driver.read_route(cluster)
    independent_weights = topology_driver.configured_weight_map(route)
    independent_refs = {ref["name"]: ref["weight"]
                        for ref in topology_driver.configured_backend_refs(route)}

    observation = observe(target, args, expected_run=expected_run,
                          expected_sha=expected_sha, request_run=expected_run,
                          request_sha=expected_sha)
    payload = summarise(observation)

    expected_status = str(state["expected_status"])
    expected_percentage = state["expected_percentage"]
    ok &= check_row(f"{name}:status",
                    f"an available topology is observed as {expected_status}",
                    f"status={observation.observation.observed_status} "
                    f"findings={list(observation.findings)}",
                    observation.observation.observed_status == expected_status)
    ok &= check_row(f"{name}:percentage",
                    f"the observed canary share is the configured proportion "
                    f"({expected_percentage}%)",
                    f"percentage={observation.observation.observed_percentage} "
                    f"configured_weights={independent_weights}",
                    observation.observation.observed_percentage == expected_percentage)

    adapter_weights = dict(payload["configured"]["weights"] or {})
    adapter_names = {track: facts.service for track, facts in observation.targets.items()}
    total = sum(independent_weights.values())
    derived = ({track: round(independent_weights[track] * 100 / total)
                for track in ("stable", "canary")} if total else {})
    ok &= check_row(f"{name}:configured-cross-check",
                    "the adapter's configured weights and share equal an independent "
                    "kubectl read of the same live route",
                    f"adapter_weights={adapter_weights} independent_weights="
                    f"{independent_weights} adapter_percentage="
                    f"{observation.observation.observed_percentage} derived="
                    f"{derived.get('canary')} backend_refs={independent_refs}",
                    adapter_weights == independent_weights
                    and adapter_names == {track: SERVICE[track]
                                          for track in ("stable", "canary")}
                    and observation.observation.observed_percentage
                    == derived.get("canary")
                    and payload["configured"]["canary_percentage"]
                    == derived.get("canary"))

    endpoints = {track: sorted(facts.ready_endpoints)
                 for track, facts in observation.targets.items()}
    independent_endpoints = {track: sorted(
        endpoint["target"] for endpoint in
        topology_driver.service_endpoints(cluster, SERVICE[track]))
        for track in ("stable", "canary")}
    ok &= check_row(f"{name}:identity-cross-check",
                    "the adapter's ready endpoints and their disjointness equal an "
                    "independent kubectl read of both Services",
                    f"adapter={endpoints} independent={independent_endpoints} "
                    f"disjoint={observation.endpoints_disjoint}",
                    endpoints == independent_endpoints
                    and bool(endpoints.get("stable")) and bool(endpoints.get("canary"))
                    and observation.endpoints_disjoint is True)

    OBSERVATIONS.append({
        "state": name,
        "description": state["description"],
        "kind": "KNOWN",
        "target_weights": dict(weights) if weights else None,
        "independent_configured_weights": independent_weights,
        "independent_backend_refs": independent_refs,
        "independent_endpoints": independent_endpoints,
        "adapter": payload,
        "expected": {"status": expected_status, "percentage": expected_percentage},
        "verdict": "PASS" if ok else "FAIL",
    })
    return ok


def unavailable_state(target: ObservationTarget, args: argparse.Namespace,
                      state: Mapping[str, Any], *, expected_run: str,
                      expected_sha: str) -> bool:
    """A live state the adapter must refuse to answer about.

    Two variants, both created by this driver in the disposable cluster:
    a backendRef naming a Service that does not exist, and an all-zero
    weight pair (no share exists). The adapter must report UNKNOWN with
    no percentage — for both — and the driver must not have to trust it:
    the independent read shows the unavailable condition is really there.
    """
    cluster = args.cluster
    name = str(state["name"])
    route = topology_driver.read_route(cluster)
    previous_generation = (route.get("metadata") or {}).get("generation")
    ok = True

    if state["kind"] == "missing-backend":
        if not patch_backend_ref_name(cluster, target, SERVICE["canary"], MISSING_BACKEND):
            return check_row(f"{name}:patched",
                             "the live route is pointed at a Service that does not exist",
                             "the driver could not patch the backendRef", False)
        # The controller must SEE the change; a controller that reports
        # ResolvedRefs=False is the expected, healthy reaction to it.
        ok &= wait_generation(cluster, target, name, previous_generation,
                              expected_refs=[SERVICE["stable"], MISSING_BACKEND],
                              expect_resolved_false=True)
        independent_note = (f"backendRefs now name {MISSING_BACKEND}, which does not "
                            f"exist in {target.namespace}")
    else:  # zero-weights
        if not patch_backend_ref_name(cluster, target, MISSING_BACKEND, SERVICE["canary"]):
            return check_row(f"{name}:patched",
                             "the live route is restored before the zero-weight state",
                             "the driver could not restore the backendRef", False)
        topology_driver.patch_route_weights(cluster, {"stable": 0, "canary": 0})
        ok &= wait_generation(cluster, target, name, previous_generation,
                              expected_refs=[SERVICE["stable"], SERVICE["canary"]])
        independent_note = "both backendRefs carry weight 0, so no share exists"

    route = topology_driver.read_route(cluster)
    # A name- and share-agnostic independent read: in these states a
    # committed backend name is *supposed* to be wrong and the weights may
    # sum to zero, so neither the committed-name map nor the proportional
    # -share helper may be used here.
    independent_refs = {str(ref.get("name")): ref.get("weight")
                        for ref in (((route.get("spec") or {}).get("rules") or [{}])[0]
                                    .get("backendRefs") or [])}
    observation = observe(target, args, expected_run=expected_run,
                          expected_sha=expected_sha, request_run=expected_run,
                          request_sha=expected_sha)
    payload = summarise(observation)
    findings = list(observation.findings)

    ok &= check_row(f"{name}:refused",
                    f"the adapter reports UNKNOWN for {'a missing backend' if state['kind'] == 'missing-backend' else 'an all-zero weight pair'}, "
                    f"never a percentage",
                    f"status={observation.observation.observed_status} "
                    f"percentage={observation.observation.observed_percentage} "
                    f"findings={findings} independent_backend_refs={independent_refs} "
                    f"({independent_note})",
                    observation.observation.observed_status == OBSERVED_UNKNOWN
                    and observation.observation.observed_percentage is None
                    and observation.observation.stable_identity is None
                    and observation.observation.canary_identity is None)
    ok &= check_row(f"{name}:no-fabrication",
                    "nothing about the unavailable state is invented: no identity, "
                    "no run, no sha, no percentage",
                    f"stable={observation.observation.stable_identity} "
                    f"canary={observation.observation.canary_identity} "
                    f"run={observation.observation.deployment_run_id} "
                    f"sha={observation.observation.source_sha} "
                    f"detail={observation.observation.detail}",
                    observation.observation.deployment_run_id is None
                    and observation.observation.source_sha is None)

    OBSERVATIONS.append({
        "state": name,
        "description": state["description"],
        "kind": "UNAVAILABLE",
        "independent_backend_refs": independent_refs,
        "independent_note": independent_note,
        "adapter": payload,
        "expected": {"status": OBSERVED_UNKNOWN, "percentage": None},
        "verdict": "PASS" if ok else "FAIL",
    })
    return ok


def binding_states(target: ObservationTarget, args: argparse.Namespace, *,
                   expected_run: str, expected_sha: str) -> bool:
    """§14: the binding is attestation against host-owned configuration.

    Two states, both with a healthy cluster underneath:
    * the request claims a different source SHA than the configured one →
      CONFLICT (a shadow UNKNOWN would hide the mismatch);
    * the observer has no configured binding at all → UNKNOWN, and the
      identity the request carried is NOT echoed back as an observation.
    """
    ok = True
    route = topology_driver.read_route(args.cluster)
    weights = topology_driver.configured_weight_map(route)

    mismatch = observe(target, args, expected_run=expected_run,
                       expected_sha=expected_sha, request_run=expected_run,
                       request_sha="0" * 40)
    mismatch_payload = summarise(mismatch)
    ok &= check_row("binding-mismatch:conflict",
                    "a request whose source_sha contradicts the configured binding "
                    "is CONFLICT, not a silent UNKNOWN",
                    f"status={mismatch.observation.observed_status} "
                    f"basis={mismatch.binding} "
                    f"configured_sha={expected_sha[:12]} requested_sha={'0' * 12} "
                    f"findings={list(mismatch.findings)}",
                    mismatch.observation.observed_status == OBSERVED_CONFLICT
                    and mismatch.binding == BINDING_MISMATCH
                    and mismatch.observation.observed_percentage is None)
    ok &= check_row("binding-mismatch:no-echoed-identity",
                    "the observation reports no deployment run or source sha of its "
                    "own while the request is contradicted",
                    f"run={mismatch.observation.deployment_run_id} "
                    f"sha={mismatch.observation.source_sha} "
                    f"percentage={mismatch.observation.observed_percentage}",
                    mismatch.observation.deployment_run_id is None
                    and mismatch.observation.source_sha is None)

    unbound = observe(target, args, expected_run=None, expected_sha=None,
                      request_run=expected_run, request_sha=expected_sha)
    unbound_payload = summarise(unbound)
    ok &= check_row("unbound:unknown",
                    "an observer with no host-owned binding reports UNKNOWN instead of "
                    "trusting the identity the request carried",
                    f"status={unbound.observation.observed_status} "
                    f"basis={unbound.binding} requested_run={expected_run} "
                    f"requested_sha={expected_sha[:12]} "
                    f"findings={list(unbound.findings)}",
                    unbound.observation.observed_status == OBSERVED_UNKNOWN
                    and unbound.binding == BINDING_UNBOUND
                    and unbound.observation.observed_percentage is None)
    ok &= check_row("unbound:request-identity-not-echoed",
                    "the request's identity is not turned into an observation: a "
                    "request-carried value is never trusted",
                    f"reported_run={unbound.observation.deployment_run_id} "
                    f"reported_sha={unbound.observation.source_sha} "
                    f"expected_run={expected_run} expected_sha={expected_sha[:12]}",
                    unbound.observation.deployment_run_id is None
                    and unbound.observation.source_sha is None)

    healthy = observe(target, args, expected_run=expected_run,
                      expected_sha=expected_sha, request_run=expected_run,
                      request_sha=expected_sha)
    healthy_payload = summarise(healthy)
    ok &= check_row("binding:attested-when-it-matches",
                    "with host-owned configuration matching the request, the binding "
                    "is established and reported as attestation against configuration",
                    f"status={healthy.observation.observed_status} "
                    f"basis={healthy.binding} run={healthy.observation.deployment_run_id} "
                    f"provider={healthy.observation.provider}",
                    healthy.observation.observed_status == OBSERVED_KNOWN
                    and healthy.binding == BINDING_CONFIGURED
                    and healthy.observation.deployment_run_id == expected_run
                    and healthy.observation.source_sha == expected_sha
                    and healthy.observation.provider == PROVIDER_NAME
                    and healthy.observation.observation_source == OBSERVATION_SOURCE
                    and healthy.observation.observed_percentage is not None)

    OBSERVATIONS.append({"state": "binding-mismatch", "kind": "BINDING",
                         "target_weights": weights, "adapter": mismatch_payload,
                         "expected": {"status": OBSERVED_CONFLICT, "percentage": None},
                         "verdict": "PASS" if ok else "FAIL"})
    OBSERVATIONS.append({"state": "unbound", "kind": "BINDING",
                         "target_weights": weights, "adapter": unbound_payload,
                         "expected": {"status": OBSERVED_UNKNOWN, "percentage": None},
                         "verdict": "PASS" if ok else "FAIL"})
    OBSERVATIONS.append({"state": "binding-attested", "kind": "BINDING",
                         "target_weights": weights, "adapter": healthy_payload,
                         "expected": {"status": OBSERVED_KNOWN, "percentage": 5},
                         "verdict": "PASS" if ok else "FAIL"})
    return ok


def read_only_proof(target: ObservationTarget, args: argparse.Namespace, *,
                    expected_run: str, expected_sha: str) -> bool:
    """Observing must not change the cluster, and must not be able to.

    The live half: the route's resourceVersion and generation are unchanged
    across a batch of observations that includes both accepted and refused
    ones. The static half is unit-tested (only ``get`` is reachable).
    """
    cluster = args.cluster
    before = topology_driver.read_route(cluster)
    observations = [
        observe(target, args, expected_run=expected_run, expected_sha=expected_sha,
                request_run=expected_run, request_sha=expected_sha),
        observe(target, args, expected_run=expected_run, expected_sha=expected_sha,
                request_run=expected_run, request_sha="1" * 40),
        observe(target, args, expected_run=None, expected_sha=None,
                request_run=expected_run, request_sha=expected_sha),
    ]
    after = topology_driver.read_route(cluster)
    before_meta = before.get("metadata") or {}
    after_meta = after.get("metadata") or {}
    unchanged = (before_meta.get("resourceVersion") == after_meta.get("resourceVersion")
                 and before_meta.get("generation") == after_meta.get("generation"))
    READ_ONLY.update({
        "resource_version_before": before_meta.get("resourceVersion"),
        "resource_version_after": after_meta.get("resourceVersion"),
        "generation_before": before_meta.get("generation"),
        "generation_after": after_meta.get("generation"),
        "observations_in_the_batch": len(observations),
        "route_unchanged": bool(unchanged),
    })
    return check_row("read-only:no-cluster-write",
                     "a batch of observations (accepted, contradicted and unbound) "
                     "leaves the route's resourceVersion and generation untouched",
                     f"resourceVersion={before_meta.get('resourceVersion')} -> "
                     f"{after_meta.get('resourceVersion')} "
                     f"generation={before_meta.get('generation')} -> "
                     f"{after_meta.get('generation')} batch={len(observations)}",
                     unchanged)


def patch_backend_ref_name(cluster: str, target: ObservationTarget, current_name: str,
                           new_name: str) -> bool:
    """Driver-only mutation: repoint one backendRef at another Service name.

    The caller states which name it is replacing, so the restore step is
    explicit about the state the driver itself created — and a patch that
    does not match what the driver expects fails instead of silently
    editing the wrong backendRef.
    """
    route = topology_driver.read_route(cluster)
    refs = ((route.get("spec") or {}).get("rules") or [{}])[0].get("backendRefs") or []
    indexes = [index for index, ref in enumerate(refs) if ref.get("name") == current_name]
    if len(indexes) != 1:
        return False
    payload = json.dumps([{"op": "replace",
                           "path": f"/spec/rules/0/backendRefs/{indexes[0]}/name",
                           "value": new_name}])
    out = topology_driver.kubectl(cluster, "-n", target.namespace, "patch", "httproute",
                                  target.route_name, "--type=json", "-p", payload)
    return out.returncode == 0


def traffic_cross_check(target: ObservationTarget, args: argparse.Namespace, workdir: Path, *,
                        expected_run: str, expected_sha: str) -> bool:
    """Supplementary triangulation: the adapter's number vs real requests.

    Phase 8.7-B.0 owns the traffic proof and its tolerance method; this
    reuses that method for one state (the committed one) so the artifact
    ties the adapter's *configured* reading to the *observed* behaviour
    of the data plane without conflating them.
    """
    cluster = args.cluster
    observation = observe(target, args, expected_run=expected_run,
                          expected_sha=expected_sha, request_run=expected_run,
                          request_sha=expected_sha)
    adapter_percentage = observation.observation.observed_percentage
    if observation.observation.observed_status != OBSERVED_KNOWN or adapter_percentage is None:
        return check_row("live-traffic-agrees",
                         "real requests through the data plane agree with the "
                         "adapter's configured reading",
                         f"the adapter did not report a KNOWN share: "
                         f"status={observation.observation.observed_status}",
                         False)
    try:
        payload = topology_driver.run_sampler(
            cluster, workdir, args.sampler_image,
            topology_driver.DATA_PLANE["cluster_url"], CROSS_CHECK_SAMPLES,
            "ares-sampler-observation-cross-check")
    except Exception as exc:  # noqa: BLE001
        return check_row("live-traffic-agrees",
                         "real requests through the data plane agree with the "
                         "adapter's configured reading",
                         f"{type(exc).__name__}: {str(exc)[:400]}", False)

    total = int(payload["total"])
    canary = int(payload["canary"])
    clean = (total == CROSS_CHECK_SAMPLES and int(payload["errors"]) == 0
             and int(payload["other"]) == 0
             and int(payload["body_disagreements"]) == 0)
    expected_share = adapter_percentage / 100.0
    within, detail = topology_driver.share_within_tolerance(canary, total, expected_share)
    CROSS_CHECK = {
        "adapter_percentage": adapter_percentage,
        "samples": total,
        "stable": payload["stable"],
        "canary": canary,
        "canary_share": canary / total if total else None,
        "statuses": payload["statuses"],
        "tolerance": detail,
        "discrimination": topology_driver.discrimination_note(
            expected_share, total, expected_share + 0.05),
        "note": ("the traffic measurement belongs to Phase 8.7-B.0; this is a "
                 "triangulation of the adapter's configured reading against real "
                 "responses, using the same 4-sigma acceptance method"),
    }
    READ_ONLY["traffic_cross_check"] = CROSS_CHECK
    return check_row("live-traffic-agrees",
                     f"real requests through the data plane are consistent with the "
                     f"adapter's configured reading ({adapter_percentage}% canary) "
                     f"at {topology_driver.SIGMA:.0f} sigma",
                     f"total={total} stable={payload['stable']} canary={canary} "
                     f"errors={payload['errors']} unattributed={payload['other']} "
                     f"body_disagreements={payload['body_disagreements']} | {detail} | "
                     f"clean={clean}",
                     clean and within)


def distinguishability() -> bool:
    """The observed states must be distinguishable from one another."""
    by_state = {row["state"]: row for row in OBSERVATIONS}
    percentages = {}
    for name in ("committed-95-5", "all-stable-100-0", "all-canary-0-100",
                 "restored-95-5"):
        row = by_state.get(name)
        if row is None:
            return record("observation:states-distinguishable",
                          "the observed shares separate the live states from each other",
                          f"state {name!r} was never observed", False)
        percentages[name] = row["adapter"]["observed"]["percentage"]
    distinct = sorted(set(percentages.values()))
    return check_row("states-distinguishable",
                     "the adapter's observed shares distinguish the three live states "
                     "(and re-reading after a change is not a cached answer)",
                     f"per_state={percentages} distinct={distinct}",
                     percentages["committed-95-5"] == 5
                     and percentages["all-stable-100-0"] == 0
                     and percentages["all-canary-0-100"] == 100
                     and percentages["restored-95-5"] == 5
                     and distinct == [0, 5, 100])


# -------------------------------------------------------------------- run


def run(args: argparse.Namespace, workdir: Path) -> bool:
    cluster = args.cluster
    expected_run = args.deployment_run_id
    expected_sha = args.expected_commit
    ok = topology_driver.preflight_commit(args)
    pins_ok, versions = topology_driver.preflight_pins(args)
    ok &= pins_ok
    if not ok:
        record("harness:stopped", "the driver stops before touching the cluster when "
                                  "its preconditions fail", "preconditions failed", False)
        return False

    try:
        documents = load_documents(TOPOLOGY_DIR)
        violations = verify_documents(documents)
    except Exception as exc:  # noqa: BLE001
        documents, violations = [], [f"{type(exc).__name__}: {exc}"]
    ok &= record("topology:fixture-valid",
                 "the committed fixture is the declared minimal weighted topology",
                 f"documents={len(documents)} violations={violations}", not violations)
    if not ok:
        return False

    try:
        target = ObservationTarget.from_fixture(documents)
    except Exception as exc:  # noqa: BLE001
        record("observation:configuration-from-fixture",
               "the observer's host-owned configuration comes from the committed "
               "fixture", f"{type(exc).__name__}: {exc}", False)
        return False
    READ_ONLY["client_configuration"] = read_config(target, args).to_dict()
    ok &= record("observation:configuration-from-fixture",
                 "the observer is configured from the committed fixture — not from "
                 "live cluster state and not from the request",
                 f"namespace={target.namespace} route={target.route_name} "
                 f"app_label={target.app_label} "
                 f"matches_module_constants={target.matches_module_constants()}",
                 target.matches_module_constants() and bool(target.app_label))
    if not ok:
        return False

    alive = topology_driver.sh(["docker", "inspect", "-f", "{{.State.Running}}",
                                f"{cluster}-control-plane"])
    ok &= record("cluster:kind-is-live", "a real Kind control plane is running",
                 f"container={cluster}-control-plane running={alive.stdout.strip()!r}",
                 alive.stdout.strip() == "true")
    server_version = json.loads(
        topology_driver.kubectl_raw(cluster, "get", "--raw=/version"))
    ok &= record("cluster:server-version", "the cluster reports its real version",
                 f"server={server_version.get('gitVersion')}",
                 bool(server_version.get("gitVersion")))
    if not ok:
        return False

    for key, image in (("stable", args.stable_image), ("canary", args.canary_image),
                       ("sampler", args.sampler_image)):
        inspected = topology_driver.sh(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image])
        topology_driver.IMAGE_IDENTITIES[key] = (
            inspected.stdout.strip().splitlines() or [""])[0]
    identities = topology_driver.IMAGE_IDENTITIES
    ok &= record("build:distinct-workload-images",
                 "stable and canary are genuinely different images, not one image "
                 "serving both tracks",
                 f"stable={identities['stable'][:23]} canary={identities['canary'][:23]} "
                 f"sampler={identities['sampler'][:23]}",
                 bool(identities["stable"] and identities["canary"])
                 and identities["stable"] != identities["canary"])
    if not ok:
        return False

    ok &= topology_driver.check_gateway_api_crds(cluster, versions.get("Gateway API", ""))
    ok &= topology_driver.check_envoy_gateway_controller(
        cluster, versions.get("Envoy Gateway", ""), args.readiness_timeout)
    if not ok:
        record("stack:identified", "the controller stack is the pinned one before any "
                                   "topology is applied", "stack identification failed",
               False)
        return False

    try:
        topology_driver.render_fixture(workdir / "rendered",
                                       {"stable": args.stable_image,
                                        "canary": args.canary_image})
        applied = topology_driver.apply_fixture(cluster, workdir / "rendered",
                                                "topology fixture")
    except Exception as exc:  # noqa: BLE001
        record("topology:applied", "the topology was applied to the cluster",
               f"{type(exc).__name__}: {exc}"[:1000], False)
        return False
    ok &= record("topology:applied", "the topology was applied to the cluster",
                 f"{len(applied.splitlines())} object line(s) reported by kubectl apply",
                 True)

    if not topology_driver.core_readiness(cluster, args):
        record("harness:stopped", "no observation is trusted until the controller and "
                                  "the data plane report ready", "readiness failed", False)
        return False

    stable_endpoints = topology_driver.service_endpoints(cluster, SERVICE["stable"])
    canary_endpoints = topology_driver.service_endpoints(cluster, SERVICE["canary"])
    stable_addresses = {row["address"] for row in stable_endpoints}
    canary_addresses = {row["address"] for row in canary_endpoints}
    stable_targets = {row["target"] for row in stable_endpoints}
    canary_targets = {row["target"] for row in canary_endpoints}
    ok &= record("topology:endpoint-sets-disjoint",
                 "the two Services resolve to different pods (observed from the "
                 "cluster, not from the selectors)",
                 f"stable={sorted(stable_targets)} {sorted(stable_addresses)} | "
                 f"canary={sorted(canary_targets)} {sorted(canary_addresses)}",
                 bool(stable_addresses) and bool(canary_addresses)
                 and stable_addresses.isdisjoint(canary_addresses)
                 and stable_targets.isdisjoint(canary_targets))
    if not ok:
        return False

    notice(f"observing through the application provider: "
           f"provider={PROVIDER_NAME} namespace={target.namespace} "
           f"route={target.route_name} context=kind-{cluster}")

    # ---- the four available states, starting with the committed one.
    for state in (
        {"name": "committed-95-5", "kind": "KNOWN",
         "description": "the committed initial state (first progressive stage)",
         "patch": None, "expected_status": OBSERVED_KNOWN, "expected_percentage": 5},
        {"name": "all-stable-100-0", "kind": "KNOWN",
         "description": "canary weight 0 — the adapter must report 0%, not 'unknown'",
         "patch": {"stable": 100, "canary": 0},
         "expected_status": OBSERVED_KNOWN, "expected_percentage": 0},
        {"name": "all-canary-0-100", "kind": "KNOWN",
         "description": "stable weight 0 — the reverse direction",
         "patch": {"stable": 0, "canary": 100},
         "expected_status": OBSERVED_KNOWN, "expected_percentage": 100},
    ):
        if not observation_state(target, args, state, expected_run=expected_run,
                                 expected_sha=expected_sha):
            return False

    # ---- the two unavailable states, both created live by this driver.
    for state in (
        {"name": "negative-missing-backend", "kind": "missing-backend",
         "description": "the live route names a backend Service that does not exist"},
        {"name": "negative-zero-weights", "kind": "zero-weights",
         "description": "both backendRefs carry weight 0, so no share exists"},
    ):
        if not unavailable_state(target, args, state, expected_run=expected_run,
                                 expected_sha=expected_sha):
            return False

    # ---- restore the committed state and observe it again (no caching).
    restore = {"name": "restored-95-5", "kind": "KNOWN",
               "description": "the committed state restored after the negative states "
                              "— the same adapter, a fresh read",
               "patch": {"stable": 95, "canary": 5},
               "expected_status": OBSERVED_KNOWN, "expected_percentage": 5}
    if not observation_state(target, args, restore, expected_run=expected_run,
                             expected_sha=expected_sha):
        return False

    ok &= binding_states(target, args, expected_run=expected_run,
                         expected_sha=expected_sha)
    ok &= read_only_proof(target, args, expected_run=expected_run,
                          expected_sha=expected_sha)
    ok &= traffic_cross_check(target, args, workdir, expected_run=expected_run,
                              expected_sha=expected_sha)
    ok &= distinguishability()
    return ok


# --------------------------------------------------------------- evidence


def build_evidence(args: argparse.Namespace) -> Dict[str, Any]:
    passed = sum(1 for row in topology_driver.RESULTS if row["status"] == "PASS")
    total = len(topology_driver.RESULTS)
    return {
        "suite": "phase-8.7-B.1-traffic-observation-adapter",
        "proves": ("the application's read-only traffic observation provider reports "
                   "the live configuration, target identity and binding of a real "
                   "Kubernetes Gateway API topology, and refuses to answer when the "
                   "cluster cannot support an answer"),
        "is_not": [
            "a traffic-mutation capability: the Phase 8.7-A boundary is untouched and "
            "the application still cannot change traffic — plan() is a pure renderer",
            "a request-sampling proof: that is Phase 8.7-B.0's job; this artifact's "
            "observed_percentage is the configured share derived from the observed "
            "route weights, cross-checked against real responses but never conflated "
            "with them",
            "a production configuration: the topology is applied only to a disposable "
            "Kind cluster",
        ],
        "adapter": {
            "provider": PROVIDER_NAME,
            "observation_source": OBSERVATION_SOURCE,
            "module": "incident_service/infrastructure/traffic/gateway_api_observer.py",
            "read_client": ("incident_service/infrastructure/traffic/"
                            "kubernetes_read_client.py"),
            "read_operations": [operation.value for operation in ReadOperation],
            "read_resources": {operation.value: OPERATION_RESOURCES[operation]
                               for operation in ReadOperation},
            "verbs": ["get"],
            "port": ("TrafficControllerPort.inspect/plan; plan() performs no cluster "
                     "access at all"),
            "configuration": READ_ONLY.get("client_configuration", {}),
            "binding_rule": ("host-owned expected run/sha; a matching request is "
                             "attested as configured-attestation, a contradicting one "
                             "is CONFLICT (request-vs-configured-mismatch), and an "
                             "observer without a configured binding is UNKNOWN — a "
                             "request-carried identity is never trusted"),
        },
        "commit_under_test": args.expected_commit,
        "deployment_run_id": args.deployment_run_id,
        "stack": dict(topology_driver.STACK_INFO),
        "topology": {
            "namespace": NAMESPACE,
            "gateway": GATEWAY,
            "route": HTTP_ROUTE,
            "chain": ("GatewayClass -> Gateway -> HTTPRoute(weighted backendRefs) -> "
                      "Service ares-stable|ares-canary -> Deployment ares-stable|ares-canary"),
            "data_plane": dict(topology_driver.DATA_PLANE),
            "distinct_workload_images": dict(topology_driver.IMAGE_IDENTITIES),
        },
        "observations": OBSERVATIONS,
        "read_only": READ_ONLY,
        "safety": {
            "application_can_mutate_traffic": False,
            "provider_operations": ["inspect", "plan"],
            "provider_has_write_method": False,
            "proof_state_mutation": {
                "mechanism": ("kubectl patch of the HTTPRoute, executed by this E2E "
                              "driver for proof states only"),
                "location": "disposable Kind cluster created for this job",
                "application_capability": False,
                "imports_traffic_mutation_boundary": False,
            },
            "production_topology_untouched": ("k8s/deployment.yaml is unaffected; the "
                                              "reserved overlay is never referenced "
                                              "from it"),
        },
        "checks": topology_driver.RESULTS,
        "diagnostics": topology_driver.DIAGNOSTICS,
        "passed": passed,
        "total": total,
        "failing_checks": [row["check"] for row in topology_driver.RESULTS
                           if row["status"] != "PASS"],
        "provenance": provenance(),
        "teardown": {
            "driver_deletes_cluster": bool(args.destroy_cluster),
            "workflow_fallback": "kind delete cluster runs with if: always()",
            "workdir_kept": bool(args.keep_workdir),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Phase 8.7-B.1 read-only traffic observation E2E")
    parser.add_argument("--cluster", default="ares-observation-e2e")
    parser.add_argument("--stable-image", required=True)
    parser.add_argument("--canary-image", required=True)
    parser.add_argument("--sampler-image", required=True)
    parser.add_argument("--expected-commit", default="")
    parser.add_argument("--deployment-run-id",
                        default=os.environ.get("GITHUB_RUN_ID", "") or "local-observation")
    parser.add_argument("--gateway-api-version", default="v1.4.1")
    parser.add_argument("--envoy-gateway-version", default="v1.6.7")
    parser.add_argument("--readiness-timeout", type=float, default=240.0)
    parser.add_argument("--observe-timeout", type=int, default=30,
                        help="per-read kubectl --request-timeout, in seconds")
    parser.add_argument("--evidence",
                        default="e2e-evidence/traffic-observation-e2e.json")
    parser.add_argument("--destroy-cluster", action="store_true",
                        help="delete the Kind cluster after sealing evidence")
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="ares-traffic-observation-"))
    notice(f"workdir {workdir}")
    try:
        try:
            run(args, workdir)
        except Exception as exc:  # noqa: BLE001
            import traceback
            record("harness:completed", "the driver reached the end of the sequence",
                   f"{type(exc).__name__}: {str(exc)[:600]}", False)
            notice("traceback:\n" + traceback.format_exc()[-3000:])
    finally:
        if not args.keep_workdir:
            shutil.rmtree(workdir, ignore_errors=True)

    out = Path(args.evidence)
    if not out.is_absolute():
        out = Path.cwd() / out
    evidence = build_evidence(args)
    sealed = seal(evidence, out)
    notice(f"evidence sealed: {out} sha256={sealed.get('artifact_sha256', '')}")

    if args.destroy_cluster:
        deleted = topology_driver.sh(
            ["kind", "delete", "cluster", "--name", args.cluster], timeout=600)
        notice(f"cluster {args.cluster} deleted (rc={deleted.returncode})")

    passed = evidence["passed"]
    total = evidence["total"]
    notice(f"{passed}/{total} checks PASS")
    for row in OBSERVATIONS:
        observed = row["adapter"]["observed"]
        notice(f"  {row['state']}: status={row['adapter']['status']} "
               f"percentage={observed['percentage']} "
               f"stable={observed['stable'] if observed['stable'] is None else observed['stable']['identity']} "
               f"[{row['verdict']}]")

    print(f"::notice title=8.7-B.1::read-only traffic observation E2E {passed}/{total} "
          f"checks PASS, {total - passed} FAIL; evidence={out}")
    if passed != total:
        for row in topology_driver.RESULTS:
            if row["status"] == "PASS":
                continue
            message = (f"requested={row['requested'][:160]} "
                       f"observed={row['observed'][:1200]}")
            for line in message.splitlines() or [""]:
                print(f"::error title=8.7-B.1 FAIL {row['check']}::{line}")
    else:
        import base64
        import gzip
        packed = base64.b64encode(gzip.compress(json.dumps(
            topology_driver.RESULTS, separators=(",", ":")).encode())).decode()
        for index in range(0, len(packed), 900):
            print(f"::notice title=8.7-B.1 results {index // 900}::"
                  f"{packed[index:index + 900]}")
    return 0 if passed == total and total > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
