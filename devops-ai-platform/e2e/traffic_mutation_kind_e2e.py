#!/usr/bin/env python3
"""Phase 8.7-B.2 — the trusted traffic mutation provider, proven live.

WHAT THIS PROVES
    The application's traffic-mutation provider
    (``incident_service/infrastructure/traffic_mutation/``) really changes
    the live routing of a disposable Kind cluster running the pinned
    Gateway API + Envoy Gateway stack, and really refuses to change it when
    the contract does not hold:

    * ``apply()`` moves the authorized forward transition
      (95/5 -> 75/25 for a 5% -> 25% request) through **one** bounded
      write, and the new state is verified by a *fresh* observation
      through the Phase 8.7-B.1 adapter — not by the write's exit status;
    * ``rollback()`` moves it back to the request's own derived target
      (75/25 -> 95/5) and is verified the same way;
    * both moves are confirmed three ways: the driver's independent
      ``kubectl`` read of the route, the observation provider, and real
      HTTP traffic sampled through the Envoy data plane (statistically,
      with the Phase 8.7-B.0 method — never as an exact percentage);
    * every refusal is proven *and* the route is proven unchanged
      (resourceVersion + weights read back from the API server), for stale
      preconditions, wrong target identity, unresolved refs, an ambiguous
      layout, zero weights, an unattributed already-applied state, a lost
      compare-and-set race and a concurrent competitor.

WHAT THIS DRIVER IS NOT
    * It is not a production rollout. The cluster is disposable Kind, the
      topology is the reserved ``k8s/progressive`` fixture, and the
      evidence says so.
    * The *driver* still owns proof-state mutation (its ``kubectl patch``
      calls put the cluster into the states the negatives need). That is
      harness control, recorded separately in the evidence; the APPLY and
      ROLLBACK under test are performed by the application provider, and
      the driver asserts that from the provider's own evidence records
      (``attempts == 1`` per operation, ``causality ==
      this-write-accepted-and-observed``) rather than from its own writes.
    * It does not fabricate authority. The request under test is built by
      ``TrafficMutationRequest.from_traffic_intent`` from a
      ``TrafficIntent`` the driver presents *and* from a live observation:
      the intent is harness-presented approval (in production the rollout
      plan/gate services own it), while the targets and the current
      percentage come from the cluster. No identifier is invented by the
      provider, and the provider never mutates the request.

Usage:
    python e2e/traffic_mutation_kind_e2e.py \\
        --cluster ares-mutation-e2e \\
        --stable-image ares-mutation-stable:local \\
        --canary-image ares-mutation-canary:local \\
        --sampler-image ares-mutation-sampler:local \\
        --deployment-run-id "$GITHUB_RUN_ID" \\
        --expected-commit "$GITHUB_SHA" \\
        --destroy-cluster \\
        --evidence traffic-mutation-e2e.json
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
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
    OBSERVED_KNOWN,
    TrafficIntent,
)
from incident_service.application.services.traffic_mutation_boundary import (  # noqa: E402
    OP_APPLY,
    OP_ROLLBACK,
    TrafficMutationRequest,
)
from incident_service.infrastructure.traffic.gateway_api_observer import (  # noqa: E402
    KubernetesTrafficObserver,
)
from incident_service.infrastructure.traffic.kubernetes_read_client import (  # noqa: E402
    KubectlReadClient,
    TrafficReadConfig,
)
from incident_service.infrastructure.traffic_mutation.kubernetes_mutation_client import (  # noqa: E402,E501
    MUTATING_VERBS,
    TrafficWriteConfig,
)
from incident_service.infrastructure.traffic_mutation.trusted_mutation_provider import (  # noqa: E402,E501
    PROVIDER_NAME,
    TrustedTrafficMutationProvider,
    percentage_to_weights,
)

notice = topology_driver.notice
record = topology_driver.record

APP_LABEL = "ares-traffic"

#: Samples per data-plane cross-check. B.0 owns the traffic proof; this
#: re-uses its sampler and its 4-sigma acceptance method at the two states
#: the provider itself created.
CROSS_CHECK_SAMPLES = 500

MUTATIONS: List[Dict[str, Any]] = []
OBSERVATIONS: List[Dict[str, Any]] = []
REFUSALS: List[Dict[str, Any]] = []
DRIVER_STATE_CHANGES: List[Dict[str, Any]] = []
CONCURRENCY: List[Dict[str, Any]] = []
SAFETY: Dict[str, Any] = {}


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


# ------------------------------------------------------------------ stack


class FreshReadClient:
    """The B.1 read client, constructed fresh for every read.

    Phase 8.7-B.1 proved that a freshly constructed client cannot serve a
    cached answer. The mutation provider holds one object, so this adapter
    builds a new ``KubectlReadClient`` per call: the *operations and their
    validation* are still the read client's own, and the E2E additionally
    compares the provider's pre/post observations against its own reads.
    """

    def __init__(self, config: TrafficReadConfig) -> None:
        self._config = config
        self.reads = 0

    def _fresh(self) -> KubectlReadClient:
        self.reads += 1
        return KubectlReadClient(self._config)

    def get_http_route(self, name: str, namespace: str) -> Dict[str, Any]:
        return self._fresh().get_http_route(name, namespace)

    def get_service(self, name: str, namespace: str) -> Dict[str, Any]:
        return self._fresh().get_service(name, namespace)

    def list_endpoint_slices(self, namespace: str, service_name: str) -> List[Dict[str, Any]]:
        return self._fresh().list_endpoint_slices(namespace, service_name)

    def list_pods(self, namespace: str, app_label: str) -> List[Dict[str, Any]]:
        return self._fresh().list_pods(namespace, app_label)

    def list_deployments(self, namespace: str, app_label: str) -> List[Dict[str, Any]]:
        return self._fresh().list_deployments(namespace, app_label)


class ApplicationStack:
    """The real application objects under test, wired to the live cluster."""

    def __init__(self, args: argparse.Namespace, *, runner: Any = None,
                 registry: Any = None) -> None:
        context = f"kind-{args.cluster}"
        self.read_config = TrafficReadConfig(
            namespace=NAMESPACE, app_label=APP_LABEL, context=context,
            kubectl="kubectl", timeout_seconds=args.observe_timeout,
        )
        self.read_client = FreshReadClient(self.read_config)
        self.observer = KubernetesTrafficObserver(
            self.read_client,
            route_name=HTTP_ROUTE,
            namespace=NAMESPACE,
            app_label=APP_LABEL,
            expected_deployment_run_id=args.deployment_run_id,
            expected_source_sha=args.expected_commit,
        )
        self.mutation_client = _mutation_client(args, runner=runner)
        self.expected_run = args.deployment_run_id
        self.expected_sha = args.expected_commit
        self.provider = TrustedTrafficMutationProvider(
            read_client=self.read_client,
            observer=self.observer,
            mutation_client=self.mutation_client,
            route_name=HTTP_ROUTE,
            namespace=NAMESPACE,
            app_label=APP_LABEL,
            expected_deployment_run_id=args.deployment_run_id,
            expected_source_sha=args.expected_commit,
            registry=registry,
        )

    def observe(self):
        return self.observer.inspect_detailed(self.expected_run, self.expected_sha)


def _mutation_client(args: argparse.Namespace, *, runner: Any = None):
    from incident_service.infrastructure.traffic_mutation.kubernetes_mutation_client import (  # noqa: E402,E501
        KubernetesMutationClient,
    )

    config = TrafficWriteConfig(
        namespace=NAMESPACE, context=f"kind-{args.cluster}", kubectl="kubectl",
        timeout_seconds=args.mutation_timeout,
    )
    return KubernetesMutationClient(config, runner=runner) if runner is not None \
        else KubernetesMutationClient(config)


class RacingRunner:
    """The real ``subprocess.run``, plus one competing writer.

    Before the provider's own write reaches the API server, another actor
    commits a different state. This is the only way to create that
    divergence deterministically without racing the provider's internals:
    the write the provider built was conditioned on the state it observed,
    and the API server must now refuse it. The *client's* argv, patch,
    classification and attempt counting are the shipped ones; only the
    competing write is injected, and it is recorded as such.
    """

    def __init__(self, cluster: str, competing_weights: Mapping[str, int]) -> None:
        self.cluster = cluster
        self.competing_weights = dict(competing_weights)
        self.calls = 0
        self.applied: Optional[str] = None

    def __call__(self, argv: Any, **kwargs: Any) -> Any:
        self.calls += 1
        if self.calls == 1:
            topology_driver.patch_route_weights(self.cluster, self.competing_weights)
            self.applied = json.dumps(self.competing_weights, sort_keys=True)
        return subprocess.run(argv, **kwargs)


# --------------------------------------------------------------- cluster


def raw_backend_refs(route: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """The route's backendRefs exactly as the API server serves them.

    Deliberately *not* ``configured_backend_refs``: that helper derives a
    proportional share and refuses a zero denominator, while this driver
    must be able to read a route that carries no share at all (the
    zero-weight refusal case is exactly that state).
    """
    rules = (route.get("spec") or {}).get("rules") or [{}]
    return [dict(ref) for ref in ((rules[0] or {}).get("backendRefs") or [])]


def driver_view(cluster: str) -> Dict[str, Any]:
    """The driver's own independent read of the route (never the adapter's)."""
    route = topology_driver.read_route(cluster)
    metadata = route.get("metadata") or {}
    refs = raw_backend_refs(route)
    parent = topology_driver.route_parent_status(route)
    conditions = parent.get("conditions")
    return {
        "weights": {ref["name"]: ref["weight"] for ref in refs},
        "backend_refs": refs,
        "generation": metadata.get("generation"),
        "resource_version": metadata.get("resourceVersion"),
        "accepted": topology_driver.condition_status(conditions, "Accepted"),
        "resolved_refs": topology_driver.condition_status(conditions, "ResolvedRefs"),
        "observed_generations": topology_driver.condition_observed_generations(conditions),
        "rules_with_backend_refs": len([
            rule for rule in (route.get("spec") or {}).get("rules") or []
            if (rule or {}).get("backendRefs")
        ]),
    }


def driver_patch(cluster: str, label: str, weights: Mapping[str, int]) -> Dict[str, Any]:
    """A proof-state change made by the harness — recorded as harness control."""
    before = driver_view(cluster)
    topology_driver.patch_route_weights(cluster, weights)
    after = driver_view(cluster)
    row = {
        "label": label,
        "requested_weights": dict(weights),
        "before": before,
        "after": after,
        "actor": "E2E driver (harness control, not the application)",
    }
    DRIVER_STATE_CHANGES.append(row)
    return row


# ------------------------------------------------------------- requests


def build_request(args: argparse.Namespace, stack: ApplicationStack, *,
                  requested: int, nonce: str,
                  stable_target: Optional[str] = None,
                  canary_target: Optional[str] = None,
                  authorized_from: Optional[int] = None) -> Tuple[Any, Dict[str, Any]]:
    """Build the request from a live observation plus a presented intent.

    The intent is harness-presented approval: the repository's own
    ``TrafficIntent`` shape, produced here because the gate/rollout
    evaluation services that own it in production are out of scope for a
    traffic-mutation E2E. Everything the provider *acts* on — the targets,
    the current percentage and the observation time — comes from the live
    cluster through the B.1 adapter.

    ``authorized_from`` overrides *only* the percentage the intent claims to
    be authorized from (the stale-precondition case needs a request that was
    honest when it was approved and is stale now). The targets still come
    from the live observation, and the provider still performs its own fresh
    observation — it is never handed this number as truth.
    """
    observed = stack.observe()
    if observed.observation.observed_status != OBSERVED_KNOWN:
        raise RuntimeError(
            f"the live topology is not observable: {observed.observation.detail}"
        )
    targets = observed.targets or {}
    stable = stable_target or targets["stable"].identity
    canary = canary_target or targets["canary"].identity
    live = observed.observation.observed_percentage
    approved_from = live if authorized_from is None else int(authorized_from)
    intent_id = "ti_" + hashlib.sha256(
        f"{args.deployment_run_id}:{args.expected_commit}:{approved_from}:"
        f"{requested}:{nonce}".encode()
    ).hexdigest()[:24]
    gate_evaluation_id = "gate-" + hashlib.sha256(
        f"{args.deployment_run_id}:{requested}:{nonce}".encode()
    ).hexdigest()[:24]
    intent = TrafficIntent(
        intent_id=intent_id,
        deployment_run_id=args.deployment_run_id,
        source_sha=args.expected_commit,
        gate_evaluation_id=gate_evaluation_id,
        stable_target=stable,
        canary_target=canary,
        current_percentage=int(approved_from),
        requested_percentage=int(requested),
        created_at=_now(),
        evaluated_at=_now(),
    )
    request = TrafficMutationRequest.from_traffic_intent(
        intent, observed_percentage=int(approved_from), observed_at=_now()
    )
    context = {
        "intent": intent.to_dict(),
        "authority": ("harness-presented approval (TrafficIntent) + live observation; "
                      "the provider neither creates nor rewrites it"),
        "live_percentage": live,
        "authorized_from": approved_from,
        "targets_from_observation": {"stable": stable, "canary": canary},
        "request_digest": request.digest(),
    }
    return request, context


# -------------------------------------------------------------- checks


_cluster_holder: Dict[str, str] = {}


def provider_operation(stack: ApplicationStack, operation: str, request: Any, *,
                       label: str, expected_percentage: int) -> bool:
    """Run one APPLY/ROLLBACK through the application provider and verify it."""
    cluster = _cluster_holder["cluster"]
    before_driver = driver_view(cluster)
    before_attempts = stack.provider.mutation_attempts
    function = stack.provider.apply if operation == OP_APPLY else stack.provider.rollback
    result = function(request)
    attempts = stack.provider.mutation_attempts - before_attempts
    after_driver = driver_view(cluster)
    post = stack.observe()
    records = [dict(row) for row in stack.provider.records]
    latest = records[-1] if records else {}
    expected_weights = dict(zip(
        (SERVICE["stable"], SERVICE["canary"]),
        percentage_to_weights(expected_percentage),
    ))
    row = {
        "label": label,
        "operation": operation,
        "request_digest": request.digest(),
        "expected_verified_percentage": result.expected_verified_percentage,
        "verified": result.verified,
        "remote_percentage": result.remote_percentage,
        "detail": result.detail,
        "attempts_in_this_call": attempts,
        "write_attempted": attempts == 1,
        "driver_read_before": before_driver,
        "driver_read_after": after_driver,
        "expected_weights": expected_weights,
        "observation_after": {
            "status": post.observation.observed_status,
            "percentage": post.observation.observed_percentage,
            "stable": post.observation.stable_identity,
            "canary": post.observation.canary_identity,
        },
        "classification": latest.get("classification"),
        "causality": latest.get("causality"),
        "record": latest,
        "performed_by": ("application provider "
                         "(incident_service/infrastructure/traffic_mutation)"),
    }
    MUTATIONS.append(row)
    ok = record(
        f"mutation:{label}",
        f"the application provider performs ONE bounded write for the "
        f"{operation} and verifies it at {expected_percentage}%",
        (f"verified={result.verified} remote={result.remote_percentage} "
         f"attempts={attempts} weights_before="
         f"{ {k: v for k, v in before_driver['weights'].items()} } "
         f"weights_after={after_driver['weights']} "
         f"resource_version {before_driver['resource_version']} -> "
         f"{after_driver['resource_version']} "
         f"observation={post.observation.observed_status}/"
         f"{post.observation.observed_percentage} classification="
         f"{latest.get('classification')} causality={latest.get('causality')} "
         f"detail={result.detail[:200]}"),
        result.verified
        and attempts == 1
        and result.remote_percentage == expected_percentage
        and after_driver["weights"] == expected_weights
        and post.observation.observed_status == OBSERVED_KNOWN
        and post.observation.observed_percentage == expected_percentage
        and before_driver["resource_version"] != after_driver["resource_version"]
        and after_driver["generation"] > before_driver["generation"],
    )
    return ok


def data_plane_cross_check(args: argparse.Namespace, workdir: Path, *,
                           expected_percentage: int, label: str) -> bool:
    """Real requests through the data plane agree with the new configuration."""
    expected_share = expected_percentage / 100.0
    try:
        payload = topology_driver.run_sampler(
            args.cluster, workdir, args.sampler_image,
            topology_driver.DATA_PLANE["cluster_url"], CROSS_CHECK_SAMPLES,
            f"ares-sampler-mutation-{label}")
    except Exception as exc:  # noqa: BLE001
        return record(f"data-plane:{label}",
                      "real requests follow the provider's new weights",
                      f"{type(exc).__name__}: {str(exc)[:400]}", False)
    total = int(payload["total"])
    canary = int(payload["canary"])
    clean = (total == CROSS_CHECK_SAMPLES and int(payload["errors"]) == 0
             and int(payload["other"]) == 0
             and int(payload["body_disagreements"]) == 0)
    within, detail = topology_driver.share_within_tolerance(canary, total, expected_share)
    row = {
        "label": label,
        "expected_percentage": expected_percentage,
        "samples": total,
        "stable": payload["stable"],
        "canary": canary,
        "canary_share": canary / total if total else None,
        "statuses": payload["statuses"],
        "tolerance": detail,
        "within_tolerance": bool(within),
        "clean": bool(clean),
        "note": ("a statistical measurement, never an exact percentage; Phase "
                 "8.7-B.0 owns the traffic proof, this triangulates it at the "
                 "state the provider itself wrote"),
    }
    OBSERVATIONS.append({"kind": "data-plane", **row})
    return record(
        f"data-plane:{label}",
        f"real requests through the Envoy data plane are consistent with "
        f"{expected_percentage}% canary at {topology_driver.SIGMA:.0f} sigma",
        f"total={total} stable={payload['stable']} canary={canary} "
        f"errors={payload['errors']} unattributed={payload['other']} "
        f"body_disagreements={payload['body_disagreements']} | {detail} | "
        f"clean={clean}",
        clean and within,
    )


def refusal_case(name: str, stack: ApplicationStack, request: Any, *,
                 expect_classification: Sequence[str],
                 expectation: str,
                 observer_guard=None) -> bool:
    """A refusal must be proven AND the route must be proven unchanged."""
    cluster = _cluster_holder["cluster"]
    before = driver_view(cluster)
    attempts_before = stack.provider.mutation_attempts
    result = stack.provider.apply(request)
    attempts = stack.provider.mutation_attempts - attempts_before
    after = driver_view(cluster)
    latest = dict(stack.provider.records[-1]) if stack.provider.records else {}
    unchanged = (
        before["weights"] == after["weights"]
        and before["resource_version"] == after["resource_version"]
        and attempts == 0
    )
    guard_ok = True if observer_guard is None else bool(observer_guard())
    row = {
        "case": name,
        "expectation": expectation,
        "verified": result.verified,
        "attempts": attempts,
        "detail": result.detail,
        "classification": latest.get("classification"),
        "causality": latest.get("causality"),
        "weights_before": before["weights"],
        "weights_after": after["weights"],
        "resource_version_before": before["resource_version"],
        "resource_version_after": after["resource_version"],
        "route_unchanged": unchanged,
        "danger_present": guard_ok,
        "record": latest,
    }
    REFUSALS.append(row)
    return record(
        f"refusal:{name}",
        expectation,
        (f"verified={result.verified} attempts={attempts} "
         f"classification={latest.get('classification')} "
         f"weights={before['weights']}->{after['weights']} "
         f"resourceVersion {before['resource_version']}->"
         f"{after['resource_version']} danger_present={guard_ok} "
         f"detail={result.detail[:260]}"),
        (not result.verified)
        and unchanged
        and latest.get("classification") in set(expect_classification)
        and guard_ok,
    )


# ------------------------------------------------------------------ run


def run(args: argparse.Namespace, workdir: Path) -> bool:
    cluster = args.cluster
    _cluster_holder["cluster"] = cluster
    ok = topology_driver.preflight_commit(args)
    pins_ok, versions = topology_driver.preflight_pins(args)
    ok &= pins_ok
    if not ok:
        record("harness:stopped", "the driver stops before touching the cluster "
                                  "when its preconditions fail",
               "preconditions failed", False)
        return False

    try:
        documents = load_documents(TOPOLOGY_DIR)
        violations = verify_documents(documents)
    except Exception as exc:  # noqa: BLE001
        documents, violations = [], [f"{type(exc).__name__}: {exc}"]
    ok &= record("topology:fixture-valid",
                 "the committed fixture is the declared minimal weighted topology",
                 f"documents={len(documents)} violations={violations}",
                 not violations)
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
                                   "topology is applied",
               "stack identification failed", False)
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
        record("harness:stopped", "nothing is mutated until the controller and the "
                                  "data plane report ready", "readiness failed", False)
        return False

    # ---- the application stack under test.
    stack = ApplicationStack(args)
    live = stack.observe()
    SAFETY.update({
        "provider_module": ("incident_service/infrastructure/traffic_mutation/"
                            "trusted_mutation_provider.py"),
        "client_module": ("incident_service/infrastructure/traffic_mutation/"
                          "kubernetes_mutation_client.py"),
        "observation_module": ("incident_service/infrastructure/traffic/"
                               "gateway_api_observer.py"),
        "provider_name": PROVIDER_NAME,
        "mutating_verbs": sorted(MUTATING_VERBS),
        "mutation_resource": "httproute",
        "writes": "exactly the two backendRef weights of the authorized route",
        "attempts_per_operation": 1,
        "verification": ("a fresh B.1 observation of the route after the write; a "
                         "write's exit status is never verification"),
        "production_topology_untouched": ("k8s/deployment.yaml is unaffected; the "
                                          "reserved k8s/progressive fixture is applied "
                                          "only to a disposable Kind cluster"),
        "driver_role": ("the driver still patches the route to create proof states; "
                        "every such change is recorded under driver_state_changes and "
                        "no APPLY/ROLLBACK under test is performed by the driver"),
    })
    ok &= record(
        "stack:application-provider-observes-live-topology",
        "the application's real provider reports the committed 95/5 state",
        (f"status={live.observation.observed_status} "
         f"percentage={live.observation.observed_percentage} "
         f"stable={live.observation.stable_identity} "
         f"canary={live.observation.canary_identity} "
         f"route={live.route.name} generation={live.route.generation} "
         f"observedGeneration={live.route.controller_observed_generation} "
         f"accepted={live.route.accepted} resolvedRefs={live.route.resolved_refs}"),
        live.observation.observed_status == OBSERVED_KNOWN
        and live.observation.observed_percentage == 5
        and live.route.accepted is True
        and live.route.resolved_refs is True
        and live.route.controller_observed_generation == live.route.generation,
    )
    if not ok:
        return False

    # ---- golden path: 5% -> 25% through the provider, then roll back.
    request, context = build_request(args, stack, requested=25, nonce="apply")
    ok &= record("request:built-from-live-observation-and-presented-intent",
                 "the request carries the live observation's targets and the "
                 "presented approval's identity; the provider rewrites nothing",
                 json.dumps(context, sort_keys=True)[:900],
                 live.observation.stable_identity == request.stable_target
                 and live.observation.canary_identity == request.canary_target
                 and request.expected_current_percentage == 5
                 and request.requested_percentage == 25)
    ok &= provider_operation(stack, OP_APPLY, request, label="apply-5-to-25",
                             expected_percentage=25)
    ok &= data_plane_cross_check(args, workdir, expected_percentage=25, label="after-apply")

    # a duplicate of the same request is a replay: no write, no credit claimed
    before_replay = driver_view(cluster)
    attempts_before = stack.provider.mutation_attempts
    replay = stack.provider.apply(request)
    after_replay = driver_view(cluster)
    replay_record = dict(stack.provider.records[-1])
    ok &= record(
        "idempotency:duplicate-apply-is-a-replay",
        "re-presenting the identical request writes nothing and claims nothing new",
        (f"verified={replay.verified} attempts={stack.provider.mutation_attempts - attempts_before} "
         f"classification={replay_record.get('classification')} "
         f"resourceVersion {before_replay['resource_version']}->"
         f"{after_replay['resource_version']} "
         f"causality={replay_record.get('causality')}"),
        replay.verified
        and stack.provider.mutation_attempts - attempts_before == 0
        and replay_record.get("classification") == "already-applied:idempotent-replay"
        and replay_record.get("causality") == "no-attempt-in-this-call"
        and before_replay["resource_version"] == after_replay["resource_version"],
    )

    # an unattributed already-applied state never becomes a success claim
    fresh = ApplicationStack(args)
    ok &= refusal_case(
        "already-applied-without-a-record", fresh, request,
        expect_classification=("already-applied:unattributed",),
        expectation=("a live state that equals the target, with no record of this "
                     "provider performing it, is refused (never claimed) and the "
                     "route is not written"),
    )

    # ROLLBACK completes the SAME approved forward transition from the other end:
    # it may only start from the state that transition reached, and it is verified
    # at the transition's own derived target (5%), never at a caller-supplied one.
    ok &= provider_operation(stack, OP_ROLLBACK, request,
                             label="rollback-25-to-5", expected_percentage=5)
    ok &= data_plane_cross_check(args, workdir, expected_percentage=5, label="after-rollback")

    # ---- refusals, each with the danger proven present and the route proven
    #      unchanged.
    driver_patch(cluster, "proof-state-50-50", {"stable": 50, "canary": 50})
    stale_request, stale_context = build_request(
        args, stack, requested=25, nonce="stale", authorized_from=5)
    ok &= refusal_case(
        "stale-precondition", stack, stale_request,
        expect_classification=("refused:precondition", "already-applied:unattributed"),
        expectation=("a request authorized from 5% presented while the route is live "
                     "at 50% is refused with no write and no route change "
                     f"(request authorized from {stale_context['authorized_from']}%, "
                     f"live {stale_context['live_percentage']}%)"),
        observer_guard=lambda: driver_view(cluster)["weights"] == {SERVICE["stable"]: 50,
                                                                  SERVICE["canary"]: 50},
    )
    driver_patch(cluster, "restore-95-5", {"stable": 95, "canary": 5})

    wrong_target_request, _ = build_request(
        args, stack, requested=25, nonce="wrong-target",
        stable_target=f"{NAMESPACE}/service/ares-backend-that-does-not-exist",
    )
    ok &= refusal_case(
        "wrong-target-identity", stack, wrong_target_request,
        expect_classification=("refused:authority",),
        expectation=("a request naming a target the live topology does not have is "
                     "refused as a security-boundary failure, and nothing is written"),
        observer_guard=lambda: "ares-backend-that-does-not-exist"
        not in json.dumps(driver_view(cluster)["backend_refs"]),
    )

    driver_patch(cluster, "restore-95-5-before-refs", {"stable": 95, "canary": 5})
    patch_backend_ref_name(cluster, SERVICE["canary"],
                           "ares-backend-that-does-not-exist")
    try:
        ok &= refusal_case(
            "unresolved-refs", stack, _build_request_soft(args, stack, requested=25,
                                                          nonce="unresolved"),
            expect_classification=("refused:authority", "refused:observation-unavailable"),
            expectation=("a route whose backend the controller cannot resolve is never "
                         "mutated, and the route is unchanged"),
            observer_guard=lambda: (
                stack.observe().route is not None
                and stack.observe().route.resolved_refs is not True
            ),
        )
    finally:
        patch_backend_ref_name(cluster, "ares-backend-that-does-not-exist",
                               SERVICE["canary"])
    wait_for_route(cluster, {"stable": 95, "canary": 5}, timeout=180)

    # ambiguous layout: a second weighted rule
    add_rule_payload = json.dumps([
        {"op": "add", "path": "/spec/rules/-",
         "value": {"matches": [{"path": {"type": "PathPrefix", "value": "/other"}}],
                   "backendRefs": [{"name": SERVICE["stable"], "port": 8080,
                                    "weight": 100}]}},
    ])
    out = topology_driver.kubectl(cluster, "-n", NAMESPACE, "patch", "httproute",
                                  HTTP_ROUTE, "--type=json", "-p", add_rule_payload)
    if out.returncode != 0:
        record("refusal:ambiguous-layout", "the harness created a second weighted rule",
               f"kubectl patch failed: {out.stderr[-300:]}", False)
        return False
    try:
        ok &= refusal_case(
            "ambiguous-layout", stack, _build_request_soft(args, stack,
                                                           requested=25,
                                                           nonce="ambiguous"),
            expect_classification=("refused:authority", "refused:observation-unavailable"),
            expectation=("a route carrying two weighted rules is ambiguous and is never "
                         "mutated; the route is unchanged"),
            observer_guard=lambda: driver_view(cluster)["rules_with_backend_refs"] == 2,
        )
    finally:
        remove_rule_payload = json.dumps([{"op": "remove", "path": "/spec/rules/1"}])
        topology_driver.kubectl(cluster, "-n", NAMESPACE, "patch", "httproute",
                                HTTP_ROUTE, "--type=json", "-p", remove_rule_payload)
    wait_for_route(cluster, {"stable": 95, "canary": 5}, timeout=180)

    driver_patch(cluster, "proof-state-zero-weights", {"stable": 0, "canary": 0})
    try:
        ok &= refusal_case(
            "zero-weights", stack, _build_request_soft(args, stack, requested=25,
                                                       nonce="zero-weights"),
            expect_classification=("refused:authority", "refused:observation-unavailable"),
            expectation=("all-zero weights carry no share at all, so no percentage can "
                         "be authorized and nothing is written"),
            observer_guard=lambda: driver_view(cluster)["weights"]
            == {SERVICE["stable"]: 0, SERVICE["canary"]: 0},
        )
    finally:
        driver_patch(cluster, "restore-95-5-after-zero", {"stable": 95, "canary": 5})
    wait_for_route(cluster, {"stable": 95, "canary": 5}, timeout=180)

    # ---- the compare-and-set: another actor writes first.
    race_request, _ = build_request(args, stack, requested=25, nonce="race")
    racing = RacingRunner(cluster, {"stable": 40, "canary": 60})
    racing_stack = ApplicationStack(args, runner=racing)
    before_race = driver_view(cluster)
    racing_result = racing_stack.provider.apply(race_request)
    after_race = driver_view(cluster)
    race_record = dict(racing_stack.provider.records[-1])
    ok &= record(
        "cas:lost-race-is-refused-not-overwritten",
        "when another actor changes the route between the observation and the write, "
        "the API server refuses the whole patch (RFC 6902 tests) and the other "
        "actor's state survives",
        (f"verified={racing_result.verified} "
         f"classification={race_record.get('classification')} "
         f"attempt_state={(race_record.get('attempt') or {}).get('state')} "
         f"causality={race_record.get('causality')} "
         f"weights={before_race['weights']}->{after_race['weights']} "
         f"resourceVersion {before_race['resource_version']}->"
         f"{after_race['resource_version']} detail={racing_result.detail[:220]}"),
        (not racing_result.verified)
        and after_race["weights"] == {SERVICE["stable"]: 40, SERVICE["canary"]: 60}
        and (race_record.get("attempt") or {}).get("state") == "rejected"
        and race_record.get("causality") == "this-write-refused-by-server"
        and racing.calls == 1,
    )
    driver_patch(cluster, "restore-95-5-after-race", {"stable": 95, "canary": 5})
    wait_for_route(cluster, {"stable": 95, "canary": 5}, timeout=180)

    # ---- two competitors, one winner.
    competing_request, _ = build_request(args, stack, requested=25, nonce="competing")
    outcomes: List[Dict[str, Any]] = []
    lock = threading.Lock()

    def compete(index: int) -> None:
        competitor = ApplicationStack(args)
        result = competitor.provider.apply(competing_request)
        with lock:
            outcomes.append({
                "competitor": index,
                "verified": result.verified,
                "attempts": competitor.provider.mutation_attempts,
                "classification": (dict(competitor.provider.records[-1]).get("classification")
                                   if competitor.provider.records else None),
                "detail": result.detail[:220],
            })

    before_competing = driver_view(cluster)
    threads = [threading.Thread(target=compete, args=(index,)) for index in (1, 2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=args.mutation_timeout + 60)
    after_competing = driver_view(cluster)
    winners = [row for row in outcomes if row["verified"]]
    CONCURRENCY.append({
        "case": "competing-applies",
        "outcomes": outcomes,
        "weights_before": before_competing["weights"],
        "weights_after": after_competing["weights"],
    })
    ok &= record(
        "concurrency:competing-applies-one-winner",
        "two providers racing the identical request leave exactly one verified "
        "mutation and the route at the requested state",
        (f"outcomes={json.dumps(outcomes, sort_keys=True)[:700]} "
         f"weights={before_competing['weights']}->{after_competing['weights']}"),
        len(outcomes) == 2
        and len(winners) == 1
        and after_competing["weights"] == {SERVICE["stable"]: 75, SERVICE["canary"]: 25},
    )
    driver_patch(cluster, "restore-95-5-final", {"stable": 95, "canary": 5})
    wait_for_route(cluster, {"stable": 95, "canary": 5}, timeout=180)

    final = stack.observe()
    ok &= record(
        "final:committed-state-restored-through-the-provider-path",
        "the cluster is back in the committed 95/5 state and the application's "
        "observation agrees (no cached answer)",
        (f"status={final.observation.observed_status} "
         f"percentage={final.observation.observed_percentage} "
         f"driver={driver_view(cluster)['weights']}"),
        final.observation.observed_status == OBSERVED_KNOWN
        and final.observation.observed_percentage == 5
        and driver_view(cluster)["weights"] == {SERVICE["stable"]: 95,
                                               SERVICE["canary"]: 5},
    )

    # every refusal recorded must have been a real refusal of a real hazard
    ok &= record(
        "refusals:all-proven-with-an-unchanged-route",
        "every refusal case reached the provider, was refused, and left the route's "
        "weights and resourceVersion untouched",
        f"cases={[row['case'] for row in REFUSALS]} "
        f"all_unchanged={all(row['route_unchanged'] for row in REFUSALS)} "
        f"all_danger_present={all(row['danger_present'] for row in REFUSALS)}",
        bool(REFUSALS)
        and all(row["route_unchanged"] for row in REFUSALS)
        and all(row["danger_present"] for row in REFUSALS),
    )
    return ok


def patch_backend_ref_name(cluster: str, current_name: str, new_name: str) -> None:
    """Point one backendRef at a different Service (harness control only)."""
    route = topology_driver.read_route(cluster)
    refs = ((route.get("spec") or {}).get("rules") or [{}])[0].get("backendRefs") or []
    for index, ref in enumerate(refs):
        if ref.get("name") == current_name:
            payload = json.dumps([{"op": "replace",
                                   "path": f"/spec/rules/0/backendRefs/{index}/name",
                                   "value": new_name}])
            out = topology_driver.kubectl(cluster, "-n", NAMESPACE, "patch",
                                          "httproute", HTTP_ROUTE, "--type=json",
                                          "-p", payload)
            if out.returncode != 0:
                raise RuntimeError(f"patching backendRef name failed: {out.stderr[-300:]}")
            return
    raise RuntimeError(f"no backendRef named {current_name!r}")


def wait_for_route(cluster: str, weights: Mapping[str, int],
                   timeout: float = 120.0) -> bool:
    """Wait until the controller has accepted the proof state again.

    ``configured_weight_map`` is keyed by *track* (the B.0 reader's
    vocabulary); the driver's own reads are keyed by the backendRef's
    Service name, so the two vocabularies are kept apart here.
    """
    target = {track: value for track, value in weights.items()}
    topology_driver.wait_or_fail(
        f"state:{json.dumps(target, sort_keys=True)}:controller-accepted",
        topology_driver.route_probe(cluster, target),
        f"the controller accepted generation with weights {target}",
        timeout, cluster,
        (("get", "-n", NAMESPACE, "httproute", HTTP_ROUTE, "-o", "yaml"),),
    )
    return True


def _build_request_soft(args: argparse.Namespace, stack: ApplicationStack, *,
                        requested: int, nonce: str):
    """A request for a refusal case, where the live state may not be KNOWN.

    The request's identity still comes from a real observation when the
    topology is observable; when it is not (the ambiguous/zero-weight
    states), the refusal must come from the *provider's own fresh
    observation*, so the request is built from the last known-good
    observation of the committed topology and the provider is the one that
    discovers the hazard.
    """
    try:
        request, _ = build_request(args, stack, requested=requested, nonce=nonce)
        return request
    except Exception:
        stable = f"{NAMESPACE}/service/{SERVICE['stable']}"
        canary = f"{NAMESPACE}/service/{SERVICE['canary']}"
        intent = TrafficIntent(
            intent_id="ti_" + hashlib.sha256(f"{args.deployment_run_id}:{nonce}".encode()
                                             ).hexdigest()[:24],
            deployment_run_id=args.deployment_run_id,
            source_sha=args.expected_commit,
            gate_evaluation_id="gate-" + hashlib.sha256(nonce.encode()).hexdigest()[:24],
            stable_target=stable, canary_target=canary,
            current_percentage=5, requested_percentage=requested,
            created_at=_now(), evaluated_at=_now(),
        )
        return TrafficMutationRequest.from_traffic_intent(
            intent, observed_percentage=5, observed_at=_now())


# --------------------------------------------------------------- evidence


def build_evidence(args: argparse.Namespace) -> Dict[str, Any]:
    passed = sum(1 for row in topology_driver.RESULTS if row["status"] == "PASS")
    total = len(topology_driver.RESULTS)
    return {
        "suite": "phase-8.7-B.2-trusted-traffic-mutation-provider",
        "proves": (
            "the application performs a real, bounded, verified traffic mutation on "
            "a live Kubernetes Gateway API topology, and refuses every request whose "
            "authority, precondition or target it cannot prove"),
        "is_not": [
            "a production rollout: the cluster is disposable Kind and the topology is "
            "the reserved k8s/progressive fixture",
            "a claim that traffic is safe to shift: the evidence proves the mechanism "
            "and its refusals, not the operational decision to move traffic",
            "a substitute for the unit-level safety probes, which is where the "
            "refusal matrix and the source-mutation controls live",
        ],
        "provider": {
            "name": PROVIDER_NAME,
            "module": SAFETY.get("provider_module"),
            "client_module": SAFETY.get("client_module"),
            "observation_module": SAFETY.get("observation_module"),
            "operations": [OP_APPLY, OP_ROLLBACK],
            "mutating_verbs": SAFETY.get("mutating_verbs"),
            "mutation_resource": SAFETY.get("mutation_resource"),
            "writes": SAFETY.get("writes"),
            "attempts_per_operation": SAFETY.get("attempts_per_operation"),
            "verification": SAFETY.get("verification"),
            "weight_mapping": {
                "denominator": 100,
                "mapping": {str(value): list(percentage_to_weights(value))
                            for value in (0, 5, 25, 50, 100)},
                "note": ("canary percentage p maps to stable 100-p / canary p by "
                         "exact integer arithmetic; the route stores weights, the "
                         "request authorizes a percentage"),
            },
        },
        "commit_under_test": args.expected_commit,
        "deployment_run_id": args.deployment_run_id,
        "stack": dict(topology_driver.STACK_INFO),
        "topology": {
            "namespace": NAMESPACE,
            "gateway": GATEWAY,
            "route": HTTP_ROUTE,
            "data_plane": dict(topology_driver.DATA_PLANE),
            "distinct_workload_images": dict(topology_driver.IMAGE_IDENTITIES),
        },
        "mutations": MUTATIONS,
        "provider_records": {
            "note": ("the provider's own machine-readable evidence records, as "
                     "produced by the live run (one per operation, including the "
                     "duplicate replay and the refusals)"),
            "records": [row["record"] for row in MUTATIONS if row.get("record")],
            "refusal_records": [row["record"] for row in REFUSALS if row.get("record")],
        },
        "refusals": REFUSALS,
        "driver_state_changes": DRIVER_STATE_CHANGES,
        "data_plane_observations": OBSERVATIONS,
        "concurrency": CONCURRENCY,
        "safety": dict(SAFETY),
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
        description="Phase 8.7-B.2 trusted traffic mutation E2E")
    parser.add_argument("--cluster", default="ares-mutation-e2e")
    parser.add_argument("--stable-image", required=True)
    parser.add_argument("--canary-image", required=True)
    parser.add_argument("--sampler-image", required=True)
    parser.add_argument("--expected-commit", default="")
    parser.add_argument("--deployment-run-id",
                        default=os.environ.get("GITHUB_RUN_ID", "") or "local-mutation")
    parser.add_argument("--gateway-api-version", default="v1.4.1")
    parser.add_argument("--envoy-gateway-version", default="v1.6.7")
    parser.add_argument("--readiness-timeout", type=float, default=240.0)
    parser.add_argument("--observe-timeout", type=int, default=30,
                        help="per-read kubectl --request-timeout, in seconds")
    parser.add_argument("--mutation-timeout", type=int, default=30,
                        help="per-write kubectl --request-timeout, in seconds")
    parser.add_argument("--evidence", default="e2e-evidence/traffic-mutation-e2e.json")
    parser.add_argument("--destroy-cluster", action="store_true")
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="ares-traffic-mutation-"))
    notice(f"workdir {workdir}")
    completed = False
    try:
        try:
            run(args, workdir)
            completed = True
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
    evidence["harness_completed"] = completed
    sealed = seal(evidence, out)
    notice(f"evidence sealed: {out} sha256={sealed.get('artifact_sha256', '')}")

    if args.destroy_cluster:
        deleted = topology_driver.sh(
            ["kind", "delete", "cluster", "--name", args.cluster], timeout=600)
        notice(f"cluster {args.cluster} deleted (rc={deleted.returncode})")

    passed = evidence["passed"]
    total = evidence["total"]
    notice(f"{passed}/{total} checks PASS")
    for row in MUTATIONS:
        notice(f"  {row['label']}: verified={row['verified']} "
               f"attempts={row['attempts_in_this_call']} "
               f"weights={row['driver_read_after']['weights']}")
    for row in REFUSALS:
        notice(f"  refusal {row['case']}: classification={row['classification']} "
               f"unchanged={row['route_unchanged']}")

    print(f"::notice title=8.7-B.2::trusted traffic mutation E2E {passed}/{total} "
          f"checks PASS, {total - passed} FAIL; evidence={out}")
    if passed != total:
        for row in topology_driver.RESULTS:
            if row["status"] == "PASS":
                continue
            message = (f"requested={row['requested'][:160]} "
                       f"observed={row['observed'][:1200]}")
            for line in message.splitlines() or [""]:
                print(f"::error title=8.7-B.2 FAIL {row['check']}::{line}")
    else:
        import base64
        import gzip
        packed = base64.b64encode(gzip.compress(json.dumps(
            topology_driver.RESULTS, separators=(",", ":")).encode())).decode()
        for index in range(0, len(packed), 900):
            print(f"::notice title=8.7-B.2 results {index // 900}::"
                  f"{packed[index:index + 900]}")
    return 0 if passed == total and total > 0 and completed else 1


if __name__ == "__main__":
    sys.exit(main())
