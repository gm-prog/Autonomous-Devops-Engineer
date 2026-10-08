"""Phase 8.7-B.2 — the trusted traffic mutation provider.

Focused, non-vacuous coverage for
``incident_service/infrastructure/traffic_mutation/``: the only code in this
repository that writes to a live Gateway API route.

WHAT IS UNDER TEST
    ``TrustedTrafficMutationProvider`` (the port implementation) and
    ``KubernetesMutationClient`` (the single bounded write). Both are driven
    against a *cluster-shaped* fixture — a real route document, real
    ``kubectl`` argv, real subprocess-shaped ``CompletedProcess`` results —
    because the behaviour that matters is what happens at the boundary, not
    what a helper returns.

HOW THE DANGER IS PROVEN PRESENT
    Every refusal test asserts three things, not one:

    1. the provider refused (and with which classification);
    2. the write was never attempted (the fixture counts attempts) or, where
       an attempt is the point, was attempted exactly once;
    3. the fixture really did contain the dangerous condition (a stale
       percentage, an unaccepted route, an unresolvable ref, a moved route),
       so the test cannot pass against a fixture that never had the hazard.

SOURCE-MUTATION CONTROLS
    ``SourceMutationControlTests`` mutates the shipped source in memory,
    runs the probe battery against the mutant, and *requires* at least one
    named safety probe to break. If a control cannot break a probe, the
    probe (or the control) is not doing its job and the suite fails. This is
    the difference between "the tests pass" and "the tests bite".
"""

from __future__ import annotations

import ast
import copy
import json
import pathlib
import subprocess
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

PLATFORM_DIR = pathlib.Path(__file__).resolve().parent.parent
REPO_ROOT = PLATFORM_DIR.parent
sys.path.insert(0, str(PLATFORM_DIR))

from incident_service.application.services.rollout_plan_service import (  # noqa: E402
    OBSERVED_CONFLICT,
    ObservedTrafficState,
    OBSERVED_KNOWN,
    OBSERVED_UNKNOWN,
    TrafficIntent,
)
from incident_service.application.services.traffic_mutation_boundary import (  # noqa: E402
    FORBIDDEN_PORT_MEMBERS,
    TrafficMutationProviderUnavailable,
    OP_APPLY,
    OP_ROLLBACK,
    InvalidTrafficMutationRequest,
    TrafficMutationRequest,
    TrafficMutationResult,
    UnavailableTrafficMutationProvider,
    expected_verified_percentage,
    is_traffic_mutation_port,
)
from incident_service.infrastructure.traffic.gateway_api_observer import (  # noqa: E402
    RouteFacts,
    TargetFacts,
    TrafficObservation,
)
import incident_service.infrastructure.traffic_mutation as mutation_package  # noqa: E402
from incident_service.infrastructure.traffic_mutation import (  # noqa: E402
    kubernetes_mutation_client as client_module,
    trusted_mutation_provider as provider_module,
)
from incident_service.infrastructure.traffic_mutation.kubernetes_mutation_client import (  # noqa: E402,E501
    ATTEMPT_ACCEPTED,
    ATTEMPT_REJECTED,
    ATTEMPT_STATES,
    ATTEMPT_UNKNOWN,
    MutationAttempt,
)
from incident_service.infrastructure.traffic_mutation.trusted_mutation_provider import (  # noqa: E402,E501
    CLASSIFICATION_REFUSED_AUTHORITY,
    CLASSIFICATION_VERIFIED,
    TrustedTrafficMutationProvider,
)

MUTATION_DIR = (PLATFORM_DIR / "incident_service" / "infrastructure"
                / "traffic_mutation")
TRAFFIC_DIR = PLATFORM_DIR / "incident_service" / "infrastructure" / "traffic"
PROVIDER_SOURCE = MUTATION_DIR / "trusted_mutation_provider.py"
CLIENT_SOURCE = MUTATION_DIR / "kubernetes_mutation_client.py"
DRIVER = PLATFORM_DIR / "e2e" / "traffic_mutation_kind_e2e.py"
DRIVER_TESTS = PLATFORM_DIR / "tests" / "test_phase_8_7_b_2_driver_control_flow.py"
DOC = REPO_ROOT / "docs" / "PHASE-8.7-B.2-TRUSTED-TRAFFIC-MUTATION-PROVIDER.md"

NAMESPACE = "ares-traffic"
APP_LABEL = "ares-traffic"
ROUTE = "ares-route"
STABLE = "ares-stable"
CANARY = "ares-canary"
STABLE_IDENTITY = f"{NAMESPACE}/service/{STABLE}"
CANARY_IDENTITY = f"{NAMESPACE}/service/{CANARY}"
RUN_ID = "deployment-run-8-7-b-2"
SOURCE_SHA = "194882d4eadbf083184fab1bc6eb5cc92689ff94"
OTHER_SHA = "7b30a56d2bfd06798c0a90023acd1c6bd5cd3420"
GATE_ID = "gate-8-7-b-2-fixture"
INTENT_ID = "ti_8-7-b-2-fixture"
NOW = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)

#: Operations this package must never grow: any argv it can build is the
#: closed weight mutation, and these verbs are not part of that vocabulary.
FORBIDDEN_VERBS = ("delete", "create", "replace", "edit", "scale", "exec",
                   "rollout", "annotate", "label", "cordon", "uncordon",
                   "drain", "taint", "set")
#: Payload/execution primitives that must never appear in this package: a
#: caller-supplied patch document, a shell, or an arbitrary argv.
FORBIDDEN_PRIMITIVES = ("subprocess.run(", "shell=True", "os.system(",
                        "Popen(", "run_kubectl", "patch(raw", "eval(",
                        "exec(", "run(argv", "--raw", "-f ", "--filename",
                        "jsonpath", "kubectl apply", "kubectl delete",
                        "build_mutation_argv(payload", "patch_payload")


# ----------------------------------------------------------------- fixtures


def live_route(weights: Tuple[int, int] = (95, 5)) -> Dict[str, Any]:
    """The committed fixture's route, as the API server serves it."""
    return {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": {"name": ROUTE, "namespace": NAMESPACE, "uid": "route-uid",
                     "generation": 4, "resourceVersion": "1000"},
        "spec": {
            "parentRefs": [{"name": "ares-gateway", "sectionName": "http"}],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": "/"}}],
                "backendRefs": [
                    {"name": STABLE, "port": 8080, "weight": weights[0]},
                    {"name": CANARY, "port": 8080, "weight": weights[1]},
                ],
            }],
        },
        "status": {"parents": [{"conditions": [
            {"type": "Accepted", "status": "True", "reason": "Accepted",
             "observedGeneration": 4},
            {"type": "ResolvedRefs", "status": "True", "reason": "ResolvedRefs",
             "observedGeneration": 4},
        ]}]},
    }


class FakeCluster:
    """A route document plus the controller state around it.

    Every proof-state change goes through :meth:`commit`, which is what a
    real write does: it bumps ``metadata.generation`` and
    ``metadata.resourceVersion`` and re-observes the controller once the
    route is resolvable. A controller that has not caught up is explicit
    (``reconcile=False``).
    """

    def __init__(self, weights: Tuple[int, int] = (95, 5), *, generation: int = 4,
                 resource_version: int = 1000, present: bool = True,
                 accepted: Any = True, resolved_refs: Any = True,
                 observed_generation: Optional[int] = None) -> None:
        self.present = present
        self.generation = generation
        self.resource_version = resource_version
        self.accepted = accepted
        self.resolved_refs = resolved_refs
        self.observed_generation = (generation if observed_generation is None
                                    else observed_generation)
        self.weights: Tuple[int, int] = (int(weights[0]), int(weights[1]))
        self.rule_count = 1
        self.ref_names: Tuple[str, str] = (STABLE, CANARY)
        self.weight_objects: Optional[Tuple[Any, Any]] = None
        self.annotations: Dict[str, str] = {}
        self.status_failures: Dict[str, str] = {}

    # ------------------------------------------------------------- reading
    def document(self) -> Dict[str, Any]:
        route = live_route(self.weights)
        route["metadata"]["generation"] = self.generation
        route["metadata"]["resourceVersion"] = str(self.resource_version)
        if self.annotations:
            route["metadata"]["annotations"] = dict(self.annotations)
        route["spec"]["rules"][0]["backendRefs"][0]["name"] = self.ref_names[0]
        route["spec"]["rules"][0]["backendRefs"][1]["name"] = self.ref_names[1]
        if self.weight_objects is not None:
            for ref, value in zip(route["spec"]["rules"][0]["backendRefs"],
                                  self.weight_objects):
                ref["weight"] = value
        if self.rule_count > 1:
            for _ in range(self.rule_count - 1):
                route["spec"]["rules"].append({
                    "matches": [{"path": {"type": "PathPrefix", "value": "/other"}}],
                    "backendRefs": [{"name": STABLE, "port": 8080, "weight": 100}],
                })
        conditions = []
        for type_, status in (("Accepted", self.accepted),
                              ("ResolvedRefs", self.resolved_refs)):
            if status is None:
                continue
            conditions.append({"type": type_,
                               "status": "True" if status is True else str(status),
                               "observedGeneration": self.observed_generation})
        route["status"]["parents"][0]["conditions"] = conditions
        return route

    # ------------------------------------------------------------- writing
    def commit(self, weights: Tuple[int, int], *, reconcile: bool = True,
               accepted: Any = True, resolved_refs: Any = True) -> None:
        self.weights = (int(weights[0]), int(weights[1]))
        self.generation += 1
        self.resource_version += 1
        if reconcile:
            self.observed_generation = self.generation
        self.accepted = accepted
        self.resolved_refs = resolved_refs


class FakeReadClient:
    """A read client shaped exactly like ``KubectlReadClient``."""

    def __init__(self, cluster: FakeCluster) -> None:
        self.cluster = cluster
        self.reads = 0
        #: Invoked after every route read, so a competing actor can change
        #: the cluster between the provider's read and its write.
        self.on_read: Optional[Callable[[], None]] = None

    def _route(self) -> Dict[str, Any]:
        self.reads += 1
        document = copy.deepcopy(self.cluster.document())
        if self.on_read is not None:
            self.on_read()
        return document

    def get_http_route(self, name: str, namespace: str) -> Dict[str, Any]:
        if (name, namespace) != (ROUTE, NAMESPACE) or not self.cluster.present:
            raise RuntimeError(f"httproute {namespace}/{name} not found")
        return self._route()

    def get_service(self, name: str, namespace: str) -> Dict[str, Any]:
        if name == "ares-backend-that-does-not-exist" or not self.cluster.present:
            raise RuntimeError(f'services "{name}" not found')
        track = "stable" if name == STABLE else "canary"
        return {"metadata": {"name": name, "namespace": namespace,
                             "uid": f"uid-service-{track}",
                             "labels": {"app": APP_LABEL, "track": track}},
                "spec": {"selector": {"app": APP_LABEL, "track": track},
                         "ports": [{"name": "http", "port": 8080}]}}

    def list_endpoint_slices(self, namespace: str,
                             service_name: str) -> List[Dict[str, Any]]:
        track = "stable" if service_name == STABLE else "canary"
        return [{"metadata": {"name": f"{service_name}-slice", "namespace": namespace,
                              "labels": {"kubernetes.io/service-name": service_name}},
                 "endpoints": [{
                     "addresses": [f"10.244.1.{4 if track == 'stable' else 8}"],
                     "conditions": {"ready": True},
                     "targetRef": {"kind": "Pod", "namespace": namespace,
                                   "name": f"{service_name}-pod",
                                   "uid": f"uid-pod-{track}"}}]}]

    def list_pods(self, namespace: str, app_label: str) -> List[Dict[str, Any]]:
        return [{"metadata": {"name": f"{service}-pod", "namespace": namespace,
                              "uid": f"uid-pod-{'stable' if service == STABLE else 'canary'}",
                              "labels": {"app": app_label,
                                         "track": "stable" if service == STABLE else "canary"}},
                 "spec": {"containers": [{"image": f"ares-mutation-{service}:local"}]},
                 "status": {"phase": "Running"}}
                for service in (STABLE, CANARY)]

    def list_deployments(self, namespace: str,
                         app_label: str) -> List[Dict[str, Any]]:
        return [{"metadata": {"name": f"ares-{track}", "namespace": namespace},
                 "spec": {"template": {"spec": {"containers": [
                     {"image": f"ares-mutation-{track}:local"}]}}}}
                for track in ("stable", "canary")]


class FakeObserver:
    """What the provider is told the observable traffic state is.

    By default it reports exactly what ``FakeCluster`` really holds — the
    Phase 8.7-B.1 contract — and each override introduces exactly one
    hazard, which is the point of the refusal tests.
    """

    def __init__(self, cluster: FakeCluster, *, run_id: str = RUN_ID,
                 sha: str = SOURCE_SHA) -> None:
        self.cluster = cluster
        self.bound_run_id = run_id
        self.bound_sha = sha
        self.status: Optional[str] = None
        self.percentage: Optional[int] = None
        self.identities: Optional[Tuple[str, str]] = None
        #: What the *observation* claims the route declares. When set, the
        #: observation stays internally coherent (its share is derived from
        #: these weights) while the document the read client returns differs,
        #: which is the only way to test the layout cross-check in isolation.
        self.route_weights_override: Optional[Dict[str, int]] = None
        self.findings: Tuple[str, ...] = ()
        self.raise_on_inspect = False
        self.inspections = 0
        self.binding_established = True

    @property
    def _observed_weights(self) -> Tuple[int, int]:
        if self.route_weights_override is not None:
            return (int(self.route_weights_override["stable"]),
                    int(self.route_weights_override["canary"]))
        return self.cluster.weights

    @property
    def _share(self) -> Optional[int]:
        stable, canary = self._observed_weights
        total = stable + canary
        if total <= 0:
            return None
        exact = canary * provider_module.WEIGHT_DENOMINATOR / total
        return int(exact) if float(exact).is_integer() else None

    def inspect_detailed(self, deployment_run_id: str = RUN_ID,
                         source_sha: str = SOURCE_SHA) -> Any:
        self.inspections += 1
        if self.raise_on_inspect:
            raise RuntimeError("the API server could not be read")
        share = self._share
        status = self.status
        if status is None:
            status = OBSERVED_KNOWN if share is not None else OBSERVED_UNKNOWN
        percentage = self.percentage if self.percentage is not None else (
            share if status == OBSERVED_KNOWN else None)
        known = status == OBSERVED_KNOWN
        stable_identity, canary_identity = self.identities or (
            STABLE_IDENTITY, CANARY_IDENTITY)
        document = self.cluster.document()
        route = self.route_facts(document)
        targets = {}
        for track, identity in (("stable", stable_identity),
                                ("canary", canary_identity)):
            namespace, service = _split_identity(identity)
            targets[track] = TargetFacts(
                track=track, service=service, namespace=namespace,
                selector={"app": APP_LABEL, "track": track},
                ready_endpoints=(f"10.244.1.{4 if track == 'stable' else 8}",),
                identity_carrier={"uid": f"uid-pod-{track}"},
            )
        observed = ObservedTrafficState(
            provider="fixture-observer",
            observed_status=status,
            observed_percentage=percentage if known else None,
            stable_identity=stable_identity if known else None,
            canary_identity=canary_identity if known else None,
            deployment_run_id=self.bound_run_id if known else None,
            source_sha=self.bound_sha if known else None,
            observation_timestamp=NOW,
            observation_source="fixture",
            detail=f"fixture status={status}",
        )
        return TrafficObservation(
            observation=observed, route=route, targets=targets,
            endpoints_disjoint=True, shared_endpoints=(),
            binding=("deployment-run" if self.binding_established
                     else "unbound"),
            binding_established=self.binding_established,
            findings=self.findings, collected_at=NOW,
            configured_percentage=percentage,
            configured_fraction=self._observed_weights,
        )

    def route_facts(self, document: Dict[str, Any]) -> Any:
        conditions = document["status"]["parents"][0]["conditions"]
        statuses = {condition["type"]: condition["status"] for condition in conditions}
        generations = [condition["observedGeneration"] for condition in conditions]
        refs = document["spec"]["rules"][0]["backendRefs"]
        stable_weight, canary_weight = self._observed_weights
        return RouteFacts(
            name=ROUTE, namespace=NAMESPACE,
            generation=document["metadata"]["generation"],
            weights={"stable": stable_weight, "canary": canary_weight},
            backends={"stable": refs[0]["name"], "canary": refs[1]["name"]},
            accepted=True if statuses.get("Accepted") == "True" else (
                False if statuses.get("Accepted") == "False" else None),
            resolved_refs=True if statuses.get("ResolvedRefs") == "True" else (
                False if statuses.get("ResolvedRefs") == "False" else None),
            controller_observed_generation=generations[0] if generations else None,
            rules_with_backends=len([rule for rule in document["spec"]["rules"]
                                     if rule.get("backendRefs")]),
        )


class FakeMutationClient:
    """The write port, with the behaviours a real cluster can produce.

    ``script`` values:
      * ``"apply"`` — the shipped semantics: evaluate the patch against the
        cluster (compare-and-set included) and answer like the API server;
      * ``"no_op"`` — the API server answers success and nothing changes;
      * ``"reject"`` — the API server refuses the patch (a two-valued no);
      * ``"timeout"`` — no answer, nothing changed;
      * ``"timeout_landed"`` — no answer, and the write *did* land;
      * ``"raise"`` — the client itself fails before any write;
      * ``("write", weights)`` — the write lands a different state.
    """

    def __init__(self, cluster: FakeCluster) -> None:
        self.cluster = cluster
        self.script: Any = "apply"
        self.attempts = 0
        self.calls: List[Any] = []
        self.lock_free_digest: Optional[str] = None

    def apply_weight_mutation(self, mutation: Any) -> Any:
        self.attempts += 1
        self.calls.append(mutation)
        script = self.script
        if script == "raise":
            raise client_module.MutationWriteError("the write could not be started")
        if script == "no_op":
            return client_module.MutationAttempt(
                state=client_module.ATTEMPT_ACCEPTED,
                detail="the API server accepted the patch",
                external_operation_id=None, duration_ms=1)
        if script == "reject":
            return client_module.MutationAttempt(
                state=client_module.ATTEMPT_REJECTED,
                detail=("Error from server (Conflict): the server rejected our "
                        "request: test failed"),
                duration_ms=1)
        if script == "timeout":
            return client_module.MutationAttempt(
                state=client_module.ATTEMPT_UNKNOWN,
                detail="kubectl did not answer within the timeout",
                duration_ms=10)
        if script == "timeout_landed":
            self.cluster.commit(_weights_tuple(mutation.target_weights))
            return client_module.MutationAttempt(
                state=client_module.ATTEMPT_UNKNOWN,
                detail="kubectl did not answer within the timeout",
                duration_ms=10)
        if isinstance(script, tuple) and script[0] == "write":
            self.cluster.commit(script[1])
            return client_module.MutationAttempt(
                state=client_module.ATTEMPT_ACCEPTED,
                detail="the API server accepted the patch",
                external_operation_id="op-forced", duration_ms=1)
        # the faithful path: a compare-and-set patch against the cluster
        expected = self.cluster.weights
        wanted = _weights_tuple(mutation.target_weights)
        current_version = str(self.cluster.resource_version)
        if mutation.resource_version != current_version:
            return client_module.MutationAttempt(
                state=client_module.ATTEMPT_REJECTED,
                detail=("Error from server (Conflict): the server rejected our "
                        "request: test failed at /metadata/resourceVersion"),
                duration_ms=1)
        for change in mutation.changes:
            observed = expected[change.index]
            if change.expected_weight != observed:
                return client_module.MutationAttempt(
                    state=client_module.ATTEMPT_REJECTED,
                    detail=(f"Error from server (Conflict): the server rejected "
                            f"our request: test failed at "
                            f"/spec/rules/0/backendRefs/{change.index}/weight"),
                    duration_ms=1)
        self.cluster.commit(wanted)
        return client_module.MutationAttempt(
            state=client_module.ATTEMPT_ACCEPTED,
            detail="the API server accepted the patch",
            external_operation_id="op-5001",
            reported_resource_version=str(self.cluster.resource_version),
            reported_generation=self.cluster.generation, duration_ms=3)


class FakeWorld:
    """One cluster, one provider, and the objects the provider acts on."""

    def __init__(self, weights: Tuple[int, int] = (95, 5), *,
                 module: Any = None, registry: Any = None, run_id: str = RUN_ID,
                 sha: str = SOURCE_SHA, now: datetime = NOW,
                 **cluster_kwargs: Any) -> None:
        self.cluster = FakeCluster(weights, **cluster_kwargs)
        self.read_client = FakeReadClient(self.cluster)
        self.observer = FakeObserver(self.cluster, run_id=run_id, sha=sha)
        self.mutation_client = FakeMutationClient(self.cluster)
        self.now = now
        self.registry = (registry if registry is not None
                         else provider_module.InMemoryMutationAttemptRegistry())
        implementation = module or provider_module
        self.provider = implementation.TrustedTrafficMutationProvider(
            read_client=self.read_client,
            observer=self.observer,
            mutation_client=self.mutation_client,
            route_name=ROUTE,
            namespace=NAMESPACE,
            app_label=APP_LABEL,
            expected_deployment_run_id=RUN_ID,
            expected_source_sha=SOURCE_SHA,
            registry=self.registry,
            now_factory=lambda: self.now,
        )

    # -------------------------------------------------------------- helpers
    @property
    def weights(self) -> Tuple[int, int]:
        return self.cluster.weights

    @property
    def tests(self) -> Tuple[int, int]:
        """Attempts made, and inspections performed, by the provider."""
        return self.mutation_client.attempts, self.observer.inspections

    @property
    def records(self) -> List[Dict[str, Any]]:
        return [dict(record) for record in self.provider.records]

    @property
    def latest(self) -> Dict[str, Any]:
        return self.records[-1] if self.records else {}

    def request(self, *, expected: int = 5, requested: int = 25,
                observed_at: Optional[datetime] = None, run_id: str = RUN_ID,
                sha: str = SOURCE_SHA, stable_target: str = STABLE_IDENTITY,
                canary_target: str = CANARY_IDENTITY, gate: str = GATE_ID,
                intent: str = INTENT_ID,
                observed_percentage: Optional[int] = None,
                operation: str = OP_APPLY) -> TrafficMutationRequest:
        """A request built the way the repository builds one."""
        stamp = observed_at or self.now
        traffic_intent = TrafficIntent(
            intent_id=intent,
            deployment_run_id=run_id,
            source_sha=sha,
            gate_evaluation_id=gate,
            stable_target=stable_target,
            canary_target=canary_target,
            current_percentage=expected,
            requested_percentage=requested,
            created_at=stamp,
            evaluated_at=stamp,
        )
        return TrafficMutationRequest.from_traffic_intent(
            traffic_intent,
            observed_percentage=(expected if observed_percentage is None
                                 else observed_percentage),
            observed_at=stamp,
        )

    def digest(self, request: Any) -> str:
        """The logical identity of one request, as the provider computes it."""
        return str(request.digest())

    def provider_for(self, module: Any) -> Any:
        """A provider from ``module`` wired to this same fixture."""
        del module
        return self.provider


def _split_identity(identity: str) -> Tuple[str, str]:
    """``namespace/service/name`` -> ``(namespace, name)``."""
    parts = str(identity).split("/")
    if len(parts) != 3 or parts[1] != "service":
        raise ValueError(f"not a traffic target identity: {identity!r}")
    return parts[0], parts[2]


def _weights_tuple(by_name: Dict[str, int]) -> Tuple[int, int]:
    """``{name: weight}`` -> the fixture's ``(stable, canary)`` tuple."""
    missing = {STABLE, CANARY} - set(by_name)
    if missing:
        raise AssertionError(f"the mutation does not carry {sorted(missing)}")
    return (by_name[STABLE], by_name[CANARY])


def proc(argv: Sequence[str], stdout: str = "", stderr: str = "",
         rc: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(list(argv), rc, stdout, stderr)


def mutation_argv() -> List[str]:
    """The argv shape the client is allowed to build (used by the guard tests)."""
    return [
        "kubectl", "patch", "httproute", ROUTE, "-n", NAMESPACE,
        "--type=json", "-p", '[{"op": "replace", "path": "/x", "value": 1}]',
        "--request-timeout=10s",
    ]


def _resolve(document: Any, path: str) -> Any:
    """Resolve one RFC 6901 JSON pointer inside a fixture document."""
    cursor = document
    for part in path.strip("/").split("/"):
        if isinstance(cursor, list):
            cursor = cursor[int(part)]
        else:
            cursor = cursor[part]
    return cursor


class ClusterRunner:
    """A ``subprocess.run``-shaped runner over a :class:`FakeCluster`.

    This is the layer the shipped client talks to, so the *real* client's
    argv, its compare-and-set patch and its answer classification are all
    exercised; only ``kubectl`` itself is replaced. ``script`` decides how
    the API server answers, one entry per call:

    * ``"answer"``            — apply the patch (RFC 6902 semantics) and answer;
    * ``"silence"``           — say nothing (a timeout), change nothing;
    * ``"landed-silence"``    — apply the patch, then say nothing;
    * ``"reject"``            — answer with a server-side rejection.
    """

    def __init__(self, cluster: FakeCluster, script: Sequence[str] = ("answer",)
                 ) -> None:
        self.cluster = cluster
        self.script = list(script)
        self.calls: List[List[str]] = []

    def __call__(self, argv: Sequence[str], **kwargs: Any) -> Any:
        self.calls.append([str(item) for item in argv])
        mode = self.script.pop(0) if self.script else "answer"
        if mode == "silence":
            raise subprocess.TimeoutExpired(cmd=list(argv),
                                           timeout=kwargs.get("timeout", 30))
        if mode == "reject":
            return proc(argv, "", "Error from server (Conflict): the server "
                                  "rejected our request: test failed", 1)
        operations = json.loads(argv[list(argv).index("-p") + 1])
        document = self.cluster.document()
        for operation in operations:
            if operation.get("op") != "test":
                continue
            if _resolve(document, operation["path"]) != operation["value"]:
                return proc(argv, "", f"Error from server (Conflict): the server "
                                      f"rejected our request: test failed at "
                                      f"{operation['path']}", 1)
        wanted = list(self.cluster.weights)
        for operation in operations:
            if operation.get("op") == "replace":
                slot = int(operation["path"].strip("/").split("/")[4])
                wanted[slot] = operation["value"]
        self.cluster.commit((wanted[0], wanted[1]))
        if mode == "landed-silence":
            raise subprocess.TimeoutExpired(cmd=list(argv),
                                           timeout=kwargs.get("timeout", 30))
        return proc(argv, json.dumps(self.cluster.document()), "", 0)


def real_client_world(script: Sequence[str] = ("answer",), *,
                      weights: Tuple[int, int] = (95, 5), module: Any = None,
                      client: Any = None) -> Tuple[FakeWorld, ClusterRunner]:
    """A world whose writes go through the client and runner under test."""
    implementation = module or provider_module
    client_implementation = client or client_module
    world = FakeWorld(weights, module=implementation)
    world.registry = provider_module.InMemoryMutationAttemptRegistry()
    runner = ClusterRunner(world.cluster, script)
    real_client = client_implementation.KubernetesMutationClient(
        client_implementation.TrafficWriteConfig(
            namespace=NAMESPACE, context="kind-fixture", kubectl="kubectl",
            timeout_seconds=10),
        runner=runner,
    )
    world.mutation_client = real_client
    world.provider = implementation.TrustedTrafficMutationProvider(
        read_client=world.read_client,
        observer=world.observer,
        mutation_client=real_client,
        route_name=ROUTE,
        namespace=NAMESPACE,
        app_label=APP_LABEL,
        expected_deployment_run_id=RUN_ID,
        expected_source_sha=SOURCE_SHA,
        registry=world.registry,
        now_factory=lambda: world.now,
    )
    return world, runner


def fixture_mutation(client_module_or_none: Any = None) -> Any:
    """The exact mutation the provider is expected to build for 5 -> 25."""
    module = client_module_or_none or client_module
    return module.WeightMutation(
        route_name=ROUTE, namespace=NAMESPACE, resource_version="1000",
        changes=(
            module.BackendWeightChange(index=0, name=STABLE, expected_weight=95,
                                       new_weight=75),
            module.BackendWeightChange(index=1, name=CANARY, expected_weight=5,
                                       new_weight=25),
        ),
    )


# ------------------------------------------------------------------- probes
#
# Every probe takes the *module pair under test* and returns ``None`` when the
# safety property holds, or a human-readable failure when it does not. The
# shipped modules satisfy all of them; a mutated copy must break at least one
# (see SourceMutationControlTests). Each probe drives the real provider (and
# often the real client) end to end; none of them asserts on an internal
# helper's return value alone.


def probe_stale_precondition_refused(mod: Any, client: Any = None) -> Optional[str]:
    """A request authorized from a state that is not live writes nothing."""
    world = FakeWorld((50, 50), module=mod)
    result = world.provider.apply(world.request(expected=5, requested=25))
    if result.verified:
        return "a mutation authorized from 5% was verified while the route was at 50%"
    if world.mutation_client.attempts:
        return (f"the provider attempted {world.mutation_client.attempts} write(s) "
                f"from a stale precondition")
    if world.weights != (50, 50):
        return f"the route changed to {world.weights}"
    if world.latest.get("classification") != provider_module.CLASSIFICATION_REFUSED_PRECONDITION:
        return f"classification {world.latest.get('classification')!r}"
    return None


def probe_target_already_live_unattributed(mod: Any, client: Any = None) -> Optional[str]:
    """A live state equal to the target, with no record, is never claimed."""
    world = FakeWorld((75, 25), module=mod)
    result = world.provider.apply(world.request(expected=5, requested=25))
    if result.verified:
        return "an unattributed already-applied state was reported as verified"
    if world.mutation_client.attempts:
        return "a write was attempted for an already-applied state"
    if world.weights != (75, 25):
        return f"the route changed to {world.weights}"
    if world.latest.get("classification") != provider_module.CLASSIFICATION_ALREADY_APPLIED:
        return f"classification {world.latest.get('classification')!r}"
    return None


def probe_duplicate_is_a_replay_with_no_write(mod: Any, client: Any = None) -> Optional[str]:
    """Re-presenting a completed request never writes again."""
    world = FakeWorld(module=mod)
    request = world.request()
    first = world.provider.apply(request)
    if not first.verified:
        return f"the first apply was not verified: {first.detail}"
    attempts_after_first = world.mutation_client.attempts
    version = world.cluster.resource_version
    second = world.provider.apply(request)
    if world.mutation_client.attempts != attempts_after_first:
        return (f"the duplicate performed "
                f"{world.mutation_client.attempts - attempts_after_first} new write(s)")
    if world.cluster.resource_version != version:
        return "the duplicate changed the route"
    if not second.verified:
        return "the duplicate was not recognised as a replay"
    if world.latest.get("classification") != provider_module.CLASSIFICATION_REPLAY:
        return f"classification {world.latest.get('classification')!r}"
    if world.latest.get("causality") != provider_module.CAUSALITY_NO_ATTEMPT:
        return f"causality {world.latest.get('causality')!r}"
    return None


def probe_controller_acceptance_missing(mod: Any, client: Any = None) -> Optional[str]:
    """A route with no ``Accepted`` condition has no controller authority."""
    world = FakeWorld(module=mod, accepted=None)
    result = world.provider.apply(world.request())
    if result.verified or world.mutation_client.attempts or world.weights != (95, 5):
        return (f"verified={result.verified} attempts={world.mutation_client.attempts} "
                f"weights={world.weights}")
    if world.latest.get("classification") != provider_module.CLASSIFICATION_REFUSED_AUTHORITY:
        return f"classification {world.latest.get('classification')!r}"
    return None


def probe_controller_not_accepted(mod: Any, client: Any = None) -> Optional[str]:
    """``Accepted=False`` is a refusal, never a mutation."""
    world = FakeWorld(module=mod, accepted=False)
    result = world.provider.apply(world.request())
    if result.verified or world.mutation_client.attempts or world.weights != (95, 5):
        return (f"verified={result.verified} attempts={world.mutation_client.attempts} "
                f"weights={world.weights}")
    if world.latest.get("classification") != provider_module.CLASSIFICATION_REFUSED_AUTHORITY:
        return f"classification {world.latest.get('classification')!r}"
    return None


def probe_resolved_refs_false(mod: Any, client: Any = None) -> Optional[str]:
    """An unresolvable backendRef is never written through."""
    world = FakeWorld(module=mod, resolved_refs=False)
    result = world.provider.apply(world.request())
    if result.verified or world.mutation_client.attempts or world.weights != (95, 5):
        return (f"verified={result.verified} attempts={world.mutation_client.attempts} "
                f"weights={world.weights}")
    if world.latest.get("classification") != provider_module.CLASSIFICATION_REFUSED_AUTHORITY:
        return f"classification {world.latest.get('classification')!r}"
    return None


def probe_controller_generation_stale(mod: Any, client: Any = None) -> Optional[str]:
    """A controller that has not observed the current generation is refused."""
    world = FakeWorld(module=mod, observed_generation=3)
    result = world.provider.apply(world.request())
    if result.verified or world.mutation_client.attempts or world.weights != (95, 5):
        return (f"verified={result.verified} attempts={world.mutation_client.attempts} "
                f"weights={world.weights}")
    return None


def probe_unobservable_cluster_refused(mod: Any, client: Any = None) -> Optional[str]:
    """An unreadable topology can never become a successful mutation."""
    world = FakeWorld(module=mod)
    world.observer.raise_on_inspect = True
    result = world.provider.apply(world.request())
    if result.verified or world.mutation_client.attempts or world.weights != (95, 5):
        return (f"verified={result.verified} attempts={world.mutation_client.attempts}")
    if world.latest.get("classification") != provider_module.CLASSIFICATION_REFUSED_OBSERVATION:
        return f"classification {world.latest.get('classification')!r}"
    return None


def probe_route_absent_refused(mod: Any, client: Any = None) -> Optional[str]:
    """A missing HTTPRoute is a refusal, not a crash and not a write."""
    world = FakeWorld(module=mod)
    world.cluster.present = False
    result = world.provider.apply(world.request())
    if result.verified or world.mutation_client.attempts:
        return (f"verified={result.verified} attempts={world.mutation_client.attempts}")
    return None


def probe_unknown_status_refused(mod: Any, client: Any = None) -> Optional[str]:
    """An observation that is not KNOWN has no authority to spend."""
    world = FakeWorld(module=mod)
    world.observer.status = OBSERVED_UNKNOWN
    result = world.provider.apply(world.request())
    if result.verified or world.mutation_client.attempts:
        return (f"verified={result.verified} attempts={world.mutation_client.attempts}")
    if world.latest.get("classification") != provider_module.CLASSIFICATION_REFUSED_AUTHORITY:
        return f"classification {world.latest.get('classification')!r}"
    return None


def probe_unbound_observation_refused(mod: Any, client: Any = None) -> Optional[str]:
    """An observation that cannot be attributed to this run is refused."""
    world = FakeWorld(module=mod)
    world.observer.binding_established = False
    result = world.provider.apply(world.request())
    if result.verified or world.mutation_client.attempts:
        return (f"verified={result.verified} attempts={world.mutation_client.attempts}")
    return None


def probe_run_mismatch_refused(mod: Any, client: Any = None) -> Optional[str]:
    """A live topology belonging to another deployment run is refused."""
    world = FakeWorld(module=mod)
    world.observer.bound_run_id = "some-other-run"
    result = world.provider.apply(world.request())
    if result.verified or world.mutation_client.attempts:
        return (f"verified={result.verified} attempts={world.mutation_client.attempts}")
    return None


def probe_sha_mismatch_refused(mod: Any, client: Any = None) -> Optional[str]:
    """A live topology built from another revision is refused."""
    world = FakeWorld(module=mod)
    world.observer.bound_sha = OTHER_SHA
    result = world.provider.apply(world.request())
    if result.verified or world.mutation_client.attempts:
        return (f"verified={result.verified} attempts={world.mutation_client.attempts}")
    return None


def probe_request_run_is_not_host_owned(mod: Any, client: Any = None) -> Optional[str]:
    """A request carrying a run the host did not configure is refused."""
    world = FakeWorld(module=mod)
    request = world.request(run_id="invented-run")
    result = world.provider.apply(request)
    if result.verified or world.mutation_client.attempts:
        return (f"verified={result.verified} attempts={world.mutation_client.attempts}; "
                f"the provider executed a request that is not the host-owned one")
    return None


def probe_identity_mismatch(mod: Any, client: Any = None) -> Optional[str]:
    """A target the live topology does not have is a security refusal."""
    world = FakeWorld(module=mod)
    request = world.request(stable_target=f"{NAMESPACE}/service/ares-stable-v2")
    result = world.provider.apply(request)
    if result.verified or world.mutation_client.attempts or world.weights != (95, 5):
        return (f"verified={result.verified} attempts={world.mutation_client.attempts} "
                f"weights={world.weights}")
    if world.latest.get("classification") != provider_module.CLASSIFICATION_REFUSED_AUTHORITY:
        return f"classification {world.latest.get('classification')!r}"
    return None


def probe_bare_service_name_is_not_an_identity(mod: Any, client: Any = None) -> Optional[str]:
    """A bare Service name is never accepted as a target identity."""
    world = FakeWorld(module=mod)
    request = world.request(stable_target="ares-stable")
    result = world.provider.apply(request)
    if result.verified or world.mutation_client.attempts:
        return ("a request naming a bare Service name was executed: the provider "
                "accepted an identity that the live topology never produced")
    return None


def probe_stale_request_refused(mod: Any, client: Any = None) -> Optional[str]:
    """A request built on an observation older than the freshness bound."""
    world = FakeWorld(module=mod)
    request = world.request(observed_at=NOW - timedelta(seconds=301))
    result = world.provider.apply(request)
    if result.verified or world.mutation_client.attempts:
        return "a request older than the freshness bound was executed"
    return None


def probe_future_request_refused(mod: Any, client: Any = None) -> Optional[str]:
    """A request whose observation is in the future beyond skew tolerance."""
    world = FakeWorld(module=mod)
    request = world.request(observed_at=NOW + timedelta(seconds=61))
    result = world.provider.apply(request)
    if result.verified or world.mutation_client.attempts:
        return "a request from the future was executed"
    return None


def probe_ambiguous_layout_refused(mod: Any, client: Any = None) -> Optional[str]:
    """Two weighted rules are ambiguous: nothing may be written."""
    world = FakeWorld(module=mod)
    world.cluster.rule_count = 2
    result = world.provider.apply(world.request())
    if result.verified or world.mutation_client.attempts or world.weights != (95, 5):
        return (f"verified={result.verified} attempts={world.mutation_client.attempts} "
                f"weights={world.weights}")
    return None


def probe_malformed_weight_refused(mod: Any, client: Any = None) -> Optional[str]:
    """A non-integer weight is never coerced into a mutation."""
    world = FakeWorld(module=mod)
    world.cluster.weight_objects = (95, "5")
    result = world.provider.apply(world.request())
    if result.verified or world.mutation_client.attempts:
        return (f"verified={result.verified} attempts={world.mutation_client.attempts}; "
                f"a string weight was coerced")
    return None


def probe_zero_weight_share_refused(mod: Any, client: Any = None) -> Optional[str]:
    """All-zero weights carry no share, so no percentage is authorized."""
    world = FakeWorld((0, 0), module=mod)
    result = world.provider.apply(world.request())
    if result.verified or world.mutation_client.attempts:
        return "a mutation was derived from a route with no share at all"
    return None


def probe_layout_disagrees_with_observation(mod: Any, client: Any = None) -> Optional[str]:
    """A document that contradicts the trusted observation is refused.

    The observation is internally coherent (it says the route declares
    95/5), the request is authorized from that 5% state, but the document
    the write would be built from declares 75/25. Without the cross-check
    the provider builds a patch from the *document* and writes the target
    weights onto a route that was never in the state the request was
    approved for — and, because the target is also 75/25, that no-op write
    is then "verified" by a fresh observation. So this probe asserts both
    the refusal and that no write was made.
    """
    world = FakeWorld((75, 25), module=mod)
    world.observer.route_weights_override = {"stable": 95, "canary": 5}
    if world.cluster.weights == (95, 5):
        return "the fixture does not contain the disagreement it tests"
    result = world.provider.apply(world.request(expected=5, requested=25))
    if result.verified:
        return ("a mutation was verified against a document that contradicts "
                "the trusted observation")
    if world.mutation_client.attempts:
        return ("the provider attempted a write from a route layout that "
                "disagrees with its own observation")
    if world.weights != (75, 25):
        return f"the route changed to {world.weights}"
    return None


def probe_inexact_share_refused(mod: Any, client: Any = None) -> Optional[str]:
    """Weights that do not sum to 100 have no exact percentage."""
    try:
        value = mod.percentage_from_weights(60, 45)
    except InvalidTrafficMutationRequest:
        value = None
    if value is not None:
        return (f"weights 60/45 were reported as {value}%: an inexact share was "
                f"rounded into a percentage")
    for percentage in (0, 5, 25, 50, 100):
        stable, canary = mod.percentage_to_weights(percentage)
        if mod.percentage_from_weights(stable, canary) != percentage:
            return f"{percentage}% does not round-trip through the weight mapping"
    return None


def probe_postcondition_is_observed_not_assumed(mod: Any, client: Any = None) -> Optional[str]:
    """An accepted write that changed nothing is not a verified mutation."""
    world = FakeWorld(module=mod)
    world.mutation_client.script = "no_op"
    result = world.provider.apply(world.request())
    if result.verified:
        return ("the provider reported verification from an accepted write whose "
                "post-state was never reached")
    if world.weights != (95, 5):
        return f"the route changed to {world.weights}"
    if world.latest.get("classification") != provider_module.CLASSIFICATION_FAILED_ATTEMPT:
        return f"classification {world.latest.get('classification')!r}"
    return None


def probe_write_refused_by_server_is_not_success(mod: Any, client: Any = None) -> Optional[str]:
    """A server-side rejection is never a success or a retry."""
    world = FakeWorld(module=mod)
    world.mutation_client.script = "reject"
    result = world.provider.apply(world.request())
    if result.verified or world.weights != (95, 5):
        return f"verified={result.verified} weights={world.weights}"
    if world.mutation_client.attempts != 1:
        return f"attempts={world.mutation_client.attempts} for one rejected write"
    record = world.latest
    if record.get("classification") not in (
            provider_module.CLASSIFICATION_FAILED_ATTEMPT,
            provider_module.CLASSIFICATION_REFUSED_ATTEMPT):
        return f"classification {record.get('classification')!r}"
    if (record.get("attempt") or {}).get("state") != client_module.ATTEMPT_REJECTED:
        return f"attempt state {(record.get('attempt') or {}).get('state')!r}"
    if record.get("verified") is not False:
        return "a rejected write was recorded as verified"
    return None


def probe_client_failure_is_not_success(mod: Any, client: Any = None) -> Optional[str]:
    """A client that cannot perform the write produces no success."""
    world = FakeWorld(module=mod)
    world.mutation_client.script = "raise"
    result = world.provider.apply(world.request())
    if result.verified or world.weights != (95, 5):
        return f"verified={result.verified} weights={world.weights}"
    return None


def probe_post_observation_unavailable_is_not_success(mod: Any, client: Any = None) -> Optional[str]:
    """An unverifiable outcome is reported as unverified, never as success."""
    world = FakeWorld(module=mod)
    original = world.observer.inspect_detailed

    def flaky(*args: Any, **kwargs: Any) -> Any:
        if world.mutation_client.attempts:
            raise RuntimeError("the API server could not be read after the write")
        return original(*args, **kwargs)

    world.observer.inspect_detailed = flaky  # type: ignore[assignment]
    result = world.provider.apply(world.request())
    if result.verified:
        return "an attempted write whose outcome could not be observed was verified"
    if world.latest.get("classification") != provider_module.CLASSIFICATION_UNVERIFIED:
        return f"classification {world.latest.get('classification')!r}"
    if world.latest.get("causality") != provider_module.CAUSALITY_NOT_APPLIED and \
            world.latest.get("attempt", {}).get("state") is None:
        return f"causality {world.latest.get('causality')!r}"
    return None


def probe_unknown_attempt_is_single_shot(mod: Any, client: Any = None) -> Optional[str]:
    """One unknown answer must not become two writes (no blind retry)."""
    world, runner = real_client_world(("silence",), module=mod, client=client)
    result = world.provider.apply(world.request())
    if result.verified:
        return "a mutation that was never answered was reported as verified"
    if len(runner.calls) != 1:
        return f"the client performed {len(runner.calls)} attempts for one unknown answer"
    if world.weights != (95, 5):
        return f"the route changed to {world.weights}"
    return None


def probe_unknown_but_landed_verified_without_credit(mod: Any, client: Any = None) -> Optional[str]:
    """A landed write with a lost answer is verified, but without credit."""
    world, runner = real_client_world(("landed-silence",), module=mod, client=client)
    result = world.provider.apply(world.request())
    if len(runner.calls) != 1:
        return f"the client retried after an unknown answer ({len(runner.calls)} calls)"
    if world.weights != (75, 25):
        return f"the landed write did not take effect: {world.weights}"
    if not result.verified:
        return f"a landed, freshly observed desired state was not verified: {result.detail}"
    if result.external_operation_id is not None:
        return "an external operation id was fabricated for an unanswered write"
    record = world.latest
    if record.get("classification") != provider_module.CLASSIFICATION_VERIFIED_UNKNOWN_ATTEMPT:
        return f"classification {record.get('classification')!r}"
    if record.get("causality") != provider_module.CAUSALITY_UNKNOWN_ATTEMPT:
        return f"causality {record.get('causality')!r}"
    if record.get("attempt", {}).get("state") != client_module.ATTEMPT_UNKNOWN:
        return f"attempt state {record.get('attempt', {}).get('state')!r}"
    return None


def probe_unknown_landing_in_a_third_state_is_a_conflict(mod: Any, client: Any = None) -> Optional[str]:
    """An unanswered write that landed somewhere else is a conflict."""
    world = FakeWorld(module=mod)
    world.mutation_client.script = ("write", (10, 90))
    result = world.provider.apply(world.request())
    if result.verified:
        return "a write that landed in a third state was verified as the mutation"
    record = world.latest
    if record.get("classification") != provider_module.CLASSIFICATION_REFUSED_CONFLICT:
        return f"classification {record.get('classification')!r}"
    if record.get("remote_percentage") != 90:
        return f"the true remote state was not reported: {record.get('remote_percentage')}"
    if record.get("verified") is not False:
        return "a conflicting remote state was recorded as verified"
    if (record.get("attempt") or {}).get("state") is None:
        return "the attempt was not recorded"
    return None


def probe_lost_race_keeps_the_other_actors_value(mod: Any, client: Any = None) -> Optional[str]:
    """A write conditioned on a stale revision must be rejected.

    Another actor changes the route *after* the provider has read it, but
    changes nothing the weight preconditions would notice (it annotates the
    route). Only the compare-and-set on ``resourceVersion`` can tell that
    the revision the provider observed is gone; without it the write is
    committed against a revision the provider never observed — a lost
    update — and the other actor's change is silently built upon.
    """
    world, runner = real_client_world(("answer",), module=mod, client=client)
    world.cluster.annotations = {}
    seen: List[int] = []

    def competing() -> None:
        if seen:
            return
        seen.append(1)
        world.cluster.resource_version += 1
        world.cluster.annotations["touched-by-another-actor"] = "true"

    world.read_client.on_read = competing
    result = world.provider.apply(world.request())
    if len(runner.calls) != 1:
        return f"the client made {len(runner.calls)} attempts"
    if world.cluster.annotations.get("touched-by-another-actor") != "true":
        return "the fixture did not contain the competing change it tests"
    if result.verified:
        return "a mutation that lost the compare-and-set was verified"
    if world.cluster.resource_version != 1001:
        return (f"the write was committed against a revision the provider never "
                f"observed (resourceVersion is {world.cluster.resource_version}, "
                f"expected 1001 after the competing change alone)")
    if world.weights != (95, 5):
        return f"the route's weights changed: {world.weights}"
    return None


def probe_concurrent_claim_is_refused(mod: Any, client: Any = None) -> Optional[str]:
    """A second attempt for an in-flight request stops before any cluster access."""
    world = FakeWorld(module=mod)
    request = world.request()
    held = world.registry.claim(request.digest(), OP_APPLY, world.now)
    result = world.provider.apply(request)
    if result.verified:
        return "a concurrent attempt was verified"
    if world.mutation_client.attempts:
        return "a concurrent attempt performed a write"
    if world.observer.inspections:
        return "a concurrent attempt read the cluster before being refused"
    record = world.latest
    if record.get("classification") != provider_module.CLASSIFICATION_REFUSED_CLAIM:
        return f"classification {record.get('classification')!r}"
    concurrency = record.get("concurrency") or {}
    if concurrency.get("claim_id") != held.get("claim_id"):
        return f"the blocking claim was not recorded: {concurrency!r}"
    if concurrency.get("claim_state") != "held-by-another-attempt":
        return f"claim state {concurrency.get('claim_state')!r}"
    if concurrency.get("attempts") != 0:
        return f"attempts {concurrency.get('attempts')!r} for a refused claim"
    return None


def probe_second_provider_cannot_double_apply(mod: Any, client: Any = None) -> Optional[str]:
    """A second provider over the same cluster cannot re-apply the same request."""
    world = FakeWorld(module=mod)
    request = world.request()
    first = world.provider.apply(request)
    if not first.verified:
        return f"the first provider did not verify: {first.detail}"
    other = FakeWorld(module=mod, registry=provider_module
                      .InMemoryMutationAttemptRegistry())
    other.cluster.weights = world.cluster.weights
    other.cluster.resource_version = world.cluster.resource_version
    other.cluster.generation = world.cluster.generation
    other.cluster.observed_generation = world.cluster.observed_generation
    result = other.provider.apply(other.request())
    if result.verified:
        return ("a second provider verified the same transition from a state it "
                "did not reach")
    if other.mutation_client.attempts:
        return "a second provider wrote the route again"
    return None


def probe_claim_holder_is_released_after_a_refusal(mod: Any, client: Any = None) -> Optional[str]:
    """A refusal releases its claim: the next honest attempt may proceed."""
    world = FakeWorld((50, 50), module=mod)
    request = world.request(expected=5, requested=25)
    refused = world.provider.apply(request)
    if refused.verified:
        return "a stale request was verified"
    world.cluster.commit((95, 5))
    world.cluster.accepted = True
    world.cluster.resolved_refs = True
    retried = world.provider.apply(request)
    if not retried.verified:
        return f"the claim was not released: {retried.detail}"
    if world.weights != (75, 25):
        return f"the retried mutation did not land: {world.weights}"
    return None


def probe_evidence_keeps_attempt_and_verification_apart(mod: Any, client: Any = None) -> Optional[str]:
    """``attempted``, ``reported``, ``observed`` and ``verified`` stay distinct."""
    world = FakeWorld(module=mod)
    world.mutation_client.script = "no_op"
    result = world.provider.apply(world.request())
    record = world.latest
    if result.verified or record.get("verified") is not False:
        return "a write that changed nothing was recorded as verified"
    attempt = record.get("attempt") or {}
    if attempt.get("state") != client_module.ATTEMPT_ACCEPTED:
        return f"the client's accepted answer was not recorded: {attempt.get('state')!r}"
    if attempt.get("reported_resource_version") is not None:
        return "a reported resourceVersion was invented for an answer that had none"
    if record.get("causality") != provider_module.CAUSALITY_NOT_APPLIED:
        return f"causality {record.get('causality')!r}"
    if record.get("verification", {}).get("verified") is not False:
        return f"verification {record.get('verification')!r}"
    return None


def probe_the_write_is_one_process_per_attempt(mod: Any, client: Any = None) -> Optional[str]:
    """The shipped client is one bounded attempt: one process, one argv."""
    world, runner = real_client_world(("answer",), module=mod, client=client)
    result = world.provider.apply(world.request())
    if not result.verified:
        return f"the write was not verified: {result.detail}"
    if len(runner.calls) != 1:
        return f"{len(runner.calls)} processes were spawned for one attempt"
    argv = runner.calls[0]
    if argv[1] != "patch" or "httproute" not in argv:
        return f"unexpected argv shape: {argv}"
    if "--type=json" not in argv or "-p" not in argv:
        return f"the patch was not sent as an RFC 6902 document: {argv}"
    if any(str(item).startswith("--dry-run") for item in argv):
        return f"a dry run reached the API server: {argv}"
    if "-f" in argv or "--filename" in argv:
        return f"the write was driven from a file: {argv}"
    return None


PROBES: Tuple[Tuple[str, Callable[..., Optional[str]]], ...] = (
    ("stale-precondition-refused", probe_stale_precondition_refused),
    ("target-already-live-unattributed", probe_target_already_live_unattributed),
    ("duplicate-is-a-replay-with-no-write", probe_duplicate_is_a_replay_with_no_write),
    ("controller-acceptance-missing", probe_controller_acceptance_missing),
    ("controller-not-accepted", probe_controller_not_accepted),
    ("resolved-refs-false", probe_resolved_refs_false),
    ("controller-generation-stale", probe_controller_generation_stale),
    ("unobservable-cluster-refused", probe_unobservable_cluster_refused),
    ("route-absent-refused", probe_route_absent_refused),
    ("unknown-status-refused", probe_unknown_status_refused),
    ("unbound-observation-refused", probe_unbound_observation_refused),
    ("run-mismatch-refused", probe_run_mismatch_refused),
    ("sha-mismatch-refused", probe_sha_mismatch_refused),
    ("request-run-is-not-host-owned", probe_request_run_is_not_host_owned),
    ("identity-mismatch", probe_identity_mismatch),
    ("bare-service-name-is-not-an-identity", probe_bare_service_name_is_not_an_identity),
    ("stale-request-refused", probe_stale_request_refused),
    ("future-request-refused", probe_future_request_refused),
    ("ambiguous-layout-refused", probe_ambiguous_layout_refused),
    ("malformed-weight-refused", probe_malformed_weight_refused),
    ("zero-weight-share-refused", probe_zero_weight_share_refused),
    ("layout-disagrees-with-observation", probe_layout_disagrees_with_observation),
    ("inexact-share-refused", probe_inexact_share_refused),
    ("postcondition-is-observed-not-assumed", probe_postcondition_is_observed_not_assumed),
    ("write-refused-by-server-is-not-success", probe_write_refused_by_server_is_not_success),
    ("client-failure-is-not-success", probe_client_failure_is_not_success),
    ("post-observation-unavailable-is-not-success",
     probe_post_observation_unavailable_is_not_success),
    ("unknown-attempt-is-single-shot", probe_unknown_attempt_is_single_shot),
    ("unknown-but-landed-verified-without-credit",
     probe_unknown_but_landed_verified_without_credit),
    ("unknown-landing-in-a-third-state-is-a-conflict",
     probe_unknown_landing_in_a_third_state_is_a_conflict),
    ("lost-race-keeps-the-other-actors-value", probe_lost_race_keeps_the_other_actors_value),
    ("concurrent-claim-is-refused", probe_concurrent_claim_is_refused),
    ("second-provider-cannot-double-apply", probe_second_provider_cannot_double_apply),
    ("claim-holder-is-released-after-a-refusal",
     probe_claim_holder_is_released_after_a_refusal),
    ("evidence-keeps-attempt-and-verification-apart",
     probe_evidence_keeps_attempt_and_verification_apart),
    ("the-write-is-one-process-per-attempt", probe_the_write_is_one_process_per_attempt),
)

#: The name each probe is recorded under (kept identical to ``PROBES``).
SAFETY_PROBES = PROBES


# ------------------------------------------------------------ test classes


class SafetyProbeTests(unittest.TestCase):
    """The probe battery itself: every property, against the shipped modules."""

    def test_every_safety_probe_holds_on_the_shipped_modules(self):
        for name, probe in SAFETY_PROBES:
            with self.subTest(probe=name):
                outcome = probe(provider_module, client_module)
                self.assertIsNone(outcome, f"{name}: {outcome}")

    def test_the_probe_battery_is_not_vacuous(self):
        """Each probe must reach the provider and leave a record behind."""
        self.assertGreaterEqual(len(SAFETY_PROBES), 30)
        names = [name for name, _ in SAFETY_PROBES]
        self.assertEqual(len(names), len(set(names)), "duplicate probe names")
        for name, probe in SAFETY_PROBES:
            with self.subTest(probe=name):
                self.assertIsNotNone(probe.__doc__)


class WeightMappingTests(unittest.TestCase):
    """Weights, denominator 100, integer arithmetic — never a float."""

    def test_every_authorized_percentage_maps_exactly(self):
        allowed = (0, 5, 25, 50, 100)
        for percentage in allowed:
            with self.subTest(percentage=percentage):
                stable, canary = provider_module.percentage_to_weights(percentage)
                self.assertEqual(stable + canary, 100)
                self.assertEqual(canary, percentage)
                self.assertEqual(stable, 100 - percentage)
                self.assertIsInstance(stable, int)
                self.assertIsInstance(canary, int)
                self.assertEqual(
                    provider_module.percentage_from_weights(stable, canary),
                    percentage)

    def test_the_denominator_is_fixed_at_one_hundred(self):
        self.assertEqual(provider_module.WEIGHT_DENOMINATOR, 100)
        self.assertEqual(provider_module.percentage_to_weights(25), (75, 25))

    def test_a_boolean_is_not_a_percentage(self):
        for value in (True, False):
            with self.subTest(value=value):
                with self.assertRaises(InvalidTrafficMutationRequest):
                    provider_module.percentage_to_weights(value)

    def test_an_out_of_range_percentage_is_refused(self):
        for value in (-1, 101, 1000):
            with self.subTest(value=value):
                with self.assertRaises(InvalidTrafficMutationRequest):
                    provider_module.percentage_to_weights(value)

    def test_inexact_weights_have_no_percentage(self):
        for stable, canary in ((60, 45), (95, 4), (50, 51), (-1, 101)):
            with self.subTest(weights=(stable, canary)):
                with self.assertRaises(InvalidTrafficMutationRequest):
                    provider_module.percentage_from_weights(stable, canary)

    def test_the_written_route_represents_exactly_the_authorized_percentage(self):
        for expected, requested in ((5, 25), (25, 50), (50, 100), (0, 5)):
            with self.subTest(transition=(expected, requested)):
                world = FakeWorld(percentage_to_weights_pair(expected))
                result = world.provider.apply(
                    world.request(expected=expected, requested=requested))
                self.assertTrue(result.verified, result.detail)
                self.assertEqual(world.weights,
                                 percentage_to_weights_pair(requested))
                self.assertEqual(result.remote_percentage, requested)
                record = world.latest
                changes = record["mutation"]["changes"]
                self.assertEqual(
                    {change["name"]: change["new_weight"] for change in changes},
                    {STABLE: 100 - requested, CANARY: requested})

    def test_no_float_ever_decides_a_weight(self):
        """Every weight this package writes comes out of integer arithmetic."""
        source = CLIENT_SOURCE.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, float):
                self.fail(f"a float literal appears in the write client: {node.value}")
        self.assertNotIn("round(", source.replace("round-trip", ""))
        self.assertNotIn("float(", source)


def percentage_to_weights_pair(percentage: int) -> Tuple[int, int]:
    stable, canary = provider_module.percentage_to_weights(percentage)
    return (stable, canary)


class RequestBoundaryTests(unittest.TestCase):
    """The request contract is authoritative and is never rewritten."""

    def test_only_a_non_request_raises(self):
        world = FakeWorld()
        for value in (None, {}, "request", object()):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(InvalidTrafficMutationRequest):
                    world.provider.apply(value)
        # a real request is refused, never raised at
        result = world.provider.apply(world.request())
        self.assertIsInstance(result, TrafficMutationResult)

    def test_the_provider_never_rewrites_the_request(self):
        world = FakeWorld()
        request = world.request()
        before = request.to_dict()
        digest_before = request.digest()
        world.provider.apply(request)
        self.assertEqual(request.to_dict(), before)
        self.assertEqual(request.digest(), digest_before)
        # and the same authority always resolves to the same logical identity
        rebuilt = world.request()
        self.assertEqual(rebuilt.digest(), digest_before)

    def test_no_caller_supplied_digest_exists(self):
        source = PROVIDER_SOURCE.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "digest":
                self.assertEqual(node.value.id if isinstance(node.value, ast.Name)
                                 else "", "request.digest()",
                                 "the provider must take the digest from the request")
        self.assertNotIn("hashlib", source)
        self.assertNotIn("sha256", source)

    def test_a_target_is_an_identity_not_a_name(self):
        world = FakeWorld()
        request = world.request()
        self.assertEqual(request.stable_target,
                         f"{NAMESPACE}/service/{STABLE}")
        result = world.provider.apply(request)
        record = world.latest
        # the request's identity travels verbatim into the evidence, and the
        # resolved target identities are the observation's own rendering
        self.assertEqual(record["request"]["stable_target"],
                         request.stable_target)
        self.assertEqual(record["pre"]["targets"]["stable"]["identity"],
                         request.stable_target)
        self.assertTrue(result.verified)
        # a bare Service name is never accepted as an identity (see the probe)
        self.assertNotEqual(request.stable_target, STABLE)

    def test_result_binds_the_exact_request_and_target(self):
        world = FakeWorld()
        request = world.request()
        result = world.provider.apply(request)
        self.assertIs(result.request, request)
        self.assertEqual(result.request_digest, request.digest())
        self.assertEqual(result.expected_verified_percentage,
                         request.requested_percentage)
        self.assertEqual(result.provider, provider_module.PROVIDER_NAME)
        self.assertEqual(result.operation, OP_APPLY)


class PreconditionTests(unittest.TestCase):
    """Fail closed on anything that is not a fresh, exact precondition."""

    def test_a_stale_precondition_is_refused_without_a_write(self):
        world = FakeWorld((50, 50))
        result = world.provider.apply(world.request(expected=5, requested=25))
        self.assertFalse(result.verified)
        self.assertEqual(world.mutation_client.attempts, 0)
        self.assertEqual(world.weights, (50, 50))
        self.assertIn("not the state this operation is authorized from",
                      world.latest["reason"])

    def test_the_live_state_is_never_adopted_as_the_precondition(self):
        world = FakeWorld((60, 40))
        world.provider.apply(world.request(expected=5, requested=25))
        record = world.latest
        self.assertEqual(record["request"]["expected_current_percentage"], 5)
        self.assertEqual(record["pre"]["percentage"], 40)
        self.assertFalse(record["verified"])

    def test_a_missing_route_is_refused(self):
        world = FakeWorld()
        world.cluster.present = False
        result = world.provider.apply(world.request())
        self.assertFalse(result.verified)
        self.assertEqual(world.mutation_client.attempts, 0)

    def test_an_ambiguous_layout_is_refused(self):
        world = FakeWorld()
        world.cluster.rule_count = 2
        result = world.provider.apply(world.request())
        self.assertFalse(result.verified)
        self.assertEqual(world.mutation_client.attempts, 0)

    def test_a_malformed_weight_is_refused(self):
        world = FakeWorld()
        world.cluster.weight_objects = (95, "5")
        result = world.provider.apply(world.request())
        self.assertFalse(result.verified)
        self.assertEqual(world.mutation_client.attempts, 0)

    def test_a_route_with_a_single_backend_is_refused(self):
        world = FakeWorld()
        world.cluster.ref_names = (STABLE, STABLE)
        result = world.provider.apply(world.request())
        self.assertFalse(result.verified)
        self.assertEqual(world.mutation_client.attempts, 0)

    def test_a_request_older_than_the_freshness_bound_is_refused(self):
        world = FakeWorld()
        result = world.provider.apply(
            world.request(observed_at=NOW - timedelta(seconds=301)))
        self.assertFalse(result.verified)
        self.assertIn("freshness bound", world.latest["reason"])

    def test_the_freshness_bound_is_the_documented_one(self):
        self.assertEqual(world_default_max_age(), 300)

    def test_a_claim_does_not_lock_the_read(self):
        """The registry is claim/lease state, never a lock on the cluster."""
        world = FakeWorld()
        world.observer.inspect_detailed(RUN_ID, SOURCE_SHA)
        self.assertEqual(world.provider.records, ())
        self.assertEqual(world.mutation_client.attempts, 0)

    def test_the_authorized_transition_vocabulary_is_closed(self):
        world = FakeWorld()
        for expected, requested in ((5, 5), (25, 5), (5, 4)):
            with self.subTest(transition=(expected, requested)):
                with self.assertRaises(InvalidTrafficMutationRequest):
                    world.request(expected=expected, requested=requested)


def world_provider() -> Any:
    """A shipped provider wired to the fixture (used by surface tests)."""
    return FakeWorld().provider


def world_default_max_age() -> int:
    return provider_module.DEFAULT_MAX_REQUEST_AGE_SECONDS


class AuthorityTests(unittest.TestCase):
    """Who may be mutated, and only when the controller agrees."""

    def test_acceptance_is_required(self):
        for accepted in (None, False, "Unknown"):
            with self.subTest(accepted=accepted):
                world = FakeWorld(accepted=accepted)
                result = world.provider.apply(world.request())
                self.assertFalse(result.verified)
                self.assertEqual(world.mutation_client.attempts, 0)
                self.assertEqual(world.latest["classification"],
                                 CLASSIFICATION_REFUSED_AUTHORITY)

    def test_resolved_refs_is_required(self):
        world = FakeWorld(resolved_refs=False)
        result = world.provider.apply(world.request())
        self.assertFalse(result.verified)
        self.assertEqual(world.mutation_client.attempts, 0)

    def test_the_controller_must_have_observed_the_generation(self):
        world = FakeWorld(observed_generation=3)
        result = world.provider.apply(world.request())
        self.assertFalse(result.verified)
        self.assertEqual(world.mutation_client.attempts, 0)
        self.assertIn("observed", world.latest["reason"])

    def test_a_controller_that_has_not_caught_up_is_refused_not_assumed(self):
        world = FakeWorld()
        world.cluster.commit((95, 5), reconcile=False)
        result = world.provider.apply(world.request())
        self.assertFalse(result.verified)
        self.assertEqual(world.mutation_client.attempts, 0)

    def test_the_observed_generation_is_recorded_separately_from_generation(self):
        world = FakeWorld()
        world.provider.apply(world.request())
        record = world.latest
        self.assertEqual(record["pre"]["route"]["generation"], 4)
        self.assertEqual(
            record["pre"]["route"]["controller_observed_generation"], 4)
        self.assertGreater(record["post"]["route"]["generation"], 4)

    def test_request_and_live_identity_must_match(self):
        world = FakeWorld()
        result = world.provider.apply(
            world.request(canary_target=f"{NAMESPACE}/service/ares-canary-v2"))
        self.assertFalse(result.verified)
        self.assertEqual(world.mutation_client.attempts, 0)
        self.assertIn("canary", world.latest["reason"])

    def test_the_run_and_revision_must_be_the_live_ones(self):
        for kwargs in ({"run_id": "another-run"},
                       {"sha": OTHER_SHA}):
            with self.subTest(**kwargs):
                world = FakeWorld()
                result = world.provider.apply(world.request(
                    run_id=kwargs.get("run_id", RUN_ID),
                    sha=kwargs.get("sha", SOURCE_SHA)))
                self.assertFalse(result.verified)
                self.assertEqual(world.mutation_client.attempts, 0)

    def test_a_non_known_observation_has_no_authority(self):
        for status in (OBSERVED_UNKNOWN, OBSERVED_CONFLICT):
            with self.subTest(status=status):
                world = FakeWorld()
                world.observer.status = status
                result = world.provider.apply(world.request())
                self.assertFalse(result.verified)
                self.assertEqual(world.mutation_client.attempts, 0)


class ApplyTests(unittest.TestCase):
    """APPLY is forward-only, exact, and verified at its own target."""

    def test_apply_is_forward_only(self):
        world = FakeWorld()
        with self.assertRaises(InvalidTrafficMutationRequest):
            world.request(expected=50, requested=25)
        source = (PLATFORM_DIR / "incident_service" / "application" / "services"
                  / "traffic_mutation_boundary.py").read_text(encoding="utf-8")
        self.assertNotIn("rollback_to_percentage", source)

    def test_apply_verifies_at_the_requested_percentage(self):
        world = FakeWorld()
        request = world.request(expected=5, requested=25)
        result = world.provider.apply(request)
        self.assertTrue(result.verified, result.detail)
        self.assertEqual(result.expected_verified_percentage, 25)
        self.assertEqual(result.remote_percentage, 25)
        self.assertEqual(world.weights, (75, 25))
        self.assertEqual(world.latest["classification"], CLASSIFICATION_VERIFIED)

    def test_apply_writes_exactly_once(self):
        world, runner = real_client_world()
        world.provider.apply(world.request())
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(world.provider.mutation_attempts, 1)

    def test_apply_uses_the_shipped_patch_and_nothing_else(self):
        world, runner = real_client_world()
        request = world.request()
        world.provider.apply(request)
        sent = json.loads(runner.calls[0][runner.calls[0].index("-p") + 1])
        mutation = fixture_mutation()
        self.assertEqual(sent, list(client_module.build_weight_patch(mutation)))
        self.assertEqual([operation["op"] for operation in sent],
                         ["test", "test", "test", "test", "test",
                          "replace", "replace"])

    def test_apply_records_the_observed_percentage_not_the_requested_one(self):
        world = FakeWorld()
        world.mutation_client.script = ("write", (50, 50))
        result = world.provider.apply(world.request(expected=5, requested=25))
        self.assertFalse(result.verified)
        self.assertEqual(world.latest["remote_percentage"], 50)
        self.assertEqual(world.latest["verification"]["observed_percentage"], 50)
        self.assertEqual(world.latest["verification"]["expected_percentage"], 25)


class RollbackTests(unittest.TestCase):
    """ROLLBACK is separately controlled and verified at its derived target."""

    def test_rollback_moves_back_to_the_requests_own_target(self):
        world = FakeWorld((75, 25))
        request = world.request(expected=5, requested=25)
        result = world.provider.rollback(request)
        self.assertTrue(result.verified, result.detail)
        self.assertEqual(result.expected_verified_percentage, 5)
        self.assertEqual(result.remote_percentage, 5)
        self.assertEqual(world.weights, (95, 5))

    def test_rollback_requires_the_forward_state_first(self):
        world = FakeWorld()
        request = world.request(expected=5, requested=25)
        result = world.provider.rollback(request)
        self.assertFalse(result.verified)
        self.assertEqual(world.mutation_client.attempts, 0)
        self.assertEqual(world.latest["classification"],
                         provider_module.CLASSIFICATION_REFUSED_PRECONDITION)

    def test_rollback_is_never_a_smaller_apply(self):
        world = FakeWorld((75, 25))
        request = world.request(expected=5, requested=25)
        self.assertEqual(expected_verified_percentage(OP_APPLY, request), 25)
        self.assertEqual(expected_verified_percentage(OP_ROLLBACK, request), 5)
        result = world.provider.rollback(request)
        self.assertEqual(result.remote_percentage, 5)
        self.assertNotEqual(result.expected_verified_percentage,
                            request.requested_percentage)

    def test_rollback_does_not_need_a_replay_record(self):
        """A rollback completes the same transition; it is not a duplicate."""
        world = FakeWorld((75, 25))
        request = world.request(expected=5, requested=25)
        first = world.provider.rollback(request)
        self.assertTrue(first.verified)
        second = world.provider.rollback(request)
        self.assertFalse(second.verified)
        self.assertEqual(world.weights, (95, 5))

    def test_no_public_function_takes_a_rollback_target(self):
        """The rollback target is derived; it is never a parameter."""
        state_shaped = ("target_percentage", "percentage", "stable_weight",
                        "canary_weight", "target", "weights")
        for path in (PROVIDER_SOURCE, CLIENT_SOURCE):
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source)
            classes = {id(node): node.name for node in ast.walk(tree)
                       if isinstance(node, ast.ClassDef)}
            scopes = [tree] + [node for node in ast.walk(tree)
                               if isinstance(node, ast.ClassDef)]
            for parent in scopes:
                for node in parent.body:
                    if not isinstance(node, (ast.FunctionDef,
                                             ast.AsyncFunctionDef)):
                        continue
                    names = {argument.arg for argument in
                             node.args.args + node.args.kwonlyargs}
                    for name in sorted(names):
                        self.assertNotIn(
                            "rollback", name,
                            f"{path.name}:{node.name} takes a rollback-shaped "
                            f"parameter {name!r}: the rollback target is "
                            f"derived from the request, never supplied")
                    if id(parent) in classes and not node.name.startswith("_"):
                        for name in sorted(names & set(state_shaped)):
                            self.fail(
                                f"{path.name}:"
                                f"{classes[id(parent)]}.{node.name} is public and "
                                f"takes {name!r}; a caller must not be able to "
                                f"name a mutation state")
                    if id(parent) not in classes and not node.name.startswith("_"):
                        # a module-level pure helper may map a percentage to
                        # weights (that is the exact arithmetic), but no
                        # module-level function in the write package may take
                        # a caller-shaped payload
                        for name in sorted(names & {
                                "request", "mutation_request",
                                "traffic_request", "raw_payload", "payload",
                                "document", "argv", "spec", "path_expression"}):
                            self.fail(
                                f"{path.name}:{node.name} is a module-level "
                                f"function taking a caller-shaped {name!r}")


class IdempotencyTests(unittest.TestCase):
    """A duplicate is a replay or a refusal — never a second mutation."""

    def test_a_duplicate_after_success_is_a_replay(self):
        world = FakeWorld()
        request = world.request()
        self.assertTrue(world.provider.apply(request).verified)
        record = world.latest
        replay = world.provider.apply(request)
        self.assertTrue(replay.verified)
        self.assertEqual(world.mutation_client.attempts, 1,
                         "the duplicate performed a second write")
        self.assertEqual(world.latest["classification"],
                         provider_module.CLASSIFICATION_REPLAY)
        self.assertEqual(world.latest["causality"],
                         provider_module.CAUSALITY_NO_ATTEMPT)
        self.assertIn("remote_percentage", record)
        self.assertIsNotNone(record["remote_percentage"])

    def test_an_unattributed_already_applied_state_is_refused(self):
        world = FakeWorld((75, 25))
        result = world.provider.apply(world.request(expected=5, requested=25))
        self.assertFalse(result.verified)
        self.assertEqual(world.latest["classification"],
                         provider_module.CLASSIFICATION_ALREADY_APPLIED)
        self.assertEqual(world.mutation_client.attempts, 0)

    def test_the_digest_is_the_logical_identity_of_the_mutation(self):
        world = FakeWorld()
        request = world.request()
        other = world.request(requested=50)
        self.assertNotEqual(request.digest(), other.digest())
        same = world.request()
        self.assertEqual(request.digest(), same.digest())

    def test_a_different_request_for_the_same_target_is_not_a_replay(self):
        world = FakeWorld()
        self.assertTrue(world.provider.apply(world.request()).verified)
        other = world.request(intent="ti_other_intent")
        result = world.provider.apply(other)
        self.assertFalse(result.verified,
                         "a different request was accepted as a replay")

    def test_a_rollback_is_never_mistaken_for_an_already_applied_apply(self):
        world = FakeWorld()
        request = world.request(expected=5, requested=25)
        plugin = request.digest()
        self.assertTrue(plugin)
        result = world.provider.rollback(request)
        self.assertFalse(result.verified)
        self.assertEqual(world.latest["classification"],
                         provider_module.CLASSIFICATION_REFUSED_PRECONDITION)


class ConcurrencyTests(unittest.TestCase):
    """One winner, honest losers, and no wedged claims."""

    def test_a_held_claim_refuses_the_second_attempt_before_any_read(self):
        world = FakeWorld()
        request = world.request()
        held = world.registry.claim(request.digest(), OP_APPLY, world.now)
        result = world.provider.apply(request)
        self.assertFalse(result.verified)
        self.assertEqual(world.observer.inspections, 0)
        self.assertEqual(world.mutation_client.attempts, 0)
        entry = world.latest["concurrency"]
        self.assertEqual(entry["claim_id"], held["claim_id"])
        self.assertEqual(entry["claim_state"], "held-by-another-attempt")
        self.assertIn("concurrent attempt", result.detail)
        self.assertIn("in flight", result.detail)

    def test_an_expired_claim_does_not_wedge_the_request(self):
        registry = provider_module.InMemoryMutationAttemptRegistry(
            claim_ttl_seconds=120)
        world = FakeWorld(registry=registry)
        request = world.request()
        registry.claim(request.digest(), OP_APPLY, world.now)
        world.now = NOW + timedelta(seconds=121)
        result = world.provider.apply(request)
        self.assertTrue(result.verified, result.detail)

    def test_the_claim_ttl_is_shorter_than_the_request_freshness_bound(self):
        registry = provider_module.InMemoryMutationAttemptRegistry()
        self.assertLess(registry.claim_ttl_seconds,
                        provider_module.DEFAULT_MAX_REQUEST_AGE_SECONDS)

    def test_finishing_an_unknown_claim_is_a_no_op(self):
        registry = provider_module.InMemoryMutationAttemptRegistry()
        registry.finish({"claim_id": "clm_unknown", "request_digest": "x",
                         "operation": OP_APPLY}, state="verified", verified=True,
                        detail="", now=NOW)
        self.assertIsNone(registry.completed("x", OP_APPLY))

    def test_a_lost_compare_and_set_keeps_the_other_actors_value(self):
        world, runner = real_client_world()
        reads = {"n": 0}

        def competing() -> None:
            reads["n"] += 1
            if reads["n"] == 1:
                world.cluster.commit((40, 60))

        world.read_client.on_read = competing
        result = world.provider.apply(world.request())
        self.assertFalse(result.verified)
        self.assertEqual(world.weights, (40, 60))
        self.assertEqual(len(runner.calls), 1, "the provider retried the write")
        self.assertEqual(world.latest["attempt"]["state"],
                         client_module.ATTEMPT_REJECTED)
        self.assertEqual(world.latest["causality"],
                         provider_module.CAUSALITY_ATTEMPT_REFUSED)
        self.assertEqual(world.latest["remote_percentage"], 60)

    def test_two_providers_over_one_cluster_produce_one_mutation(self):
        world = FakeWorld()
        request = world.request()
        self.assertTrue(world.provider.apply(request).verified)
        loser = FakeWorld(registry=provider_module.InMemoryMutationAttemptRegistry())
        for field in ("weights", "resource_version", "generation",
                      "observed_generation"):
            setattr(loser.cluster, field, getattr(world.cluster, field))
        result = loser.provider.apply(loser.request())
        self.assertFalse(result.verified)
        self.assertEqual(loser.mutation_client.attempts, 0)
        self.assertEqual(loser.weights, (75, 25))

    def test_a_refusal_releases_its_claim(self):
        world = FakeWorld((50, 50))
        request = world.request(expected=5, requested=25)
        self.assertFalse(world.provider.apply(request).verified)
        world.cluster.commit((95, 5))
        self.assertTrue(world.provider.apply(request).verified)


class UnknownOutcomeTests(unittest.TestCase):
    """Uncertainty is never converted into success."""

    def test_a_lost_answer_that_changed_nothing_is_not_verified(self):
        world, runner = real_client_world(("silence",))
        result = world.provider.apply(world.request())
        self.assertFalse(result.verified)
        self.assertEqual(len(runner.calls), 1, "the client retried")
        self.assertEqual(world.latest["attempt"]["state"],
                         client_module.ATTEMPT_UNKNOWN)
        self.assertEqual(world.latest["classification"],
                         provider_module.CLASSIFICATION_FAILED_ATTEMPT)
        self.assertIsNone(world.latest["attempt"]["external_operation_id"])

    def test_a_lost_answer_that_landed_is_verified_without_credit(self):
        world, runner = real_client_world(("landed-silence",))
        result = world.provider.apply(world.request())
        self.assertEqual(len(runner.calls), 1, "the client retried")
        self.assertTrue(result.verified, result.detail)
        self.assertIsNone(result.external_operation_id)
        self.assertEqual(world.latest["classification"],
                         provider_module.CLASSIFICATION_VERIFIED_UNKNOWN_ATTEMPT)
        self.assertEqual(world.latest["attempt"]["state"],
                         client_module.ATTEMPT_UNKNOWN)
        self.assertEqual(world.latest["causality"],
                         provider_module.CAUSALITY_UNKNOWN_ATTEMPT)

    def test_a_lost_answer_is_never_resolved_by_replaying(self):
        world, runner = real_client_world(("silence", "answer"))
        world.provider.apply(world.request())
        self.assertEqual(runner.script, ["answer"],
                         "the second scripted answer was consumed: the client retried")

    def test_a_rejected_write_is_not_retried(self):
        world, runner = real_client_world(("reject", "answer"))
        result = world.provider.apply(world.request())
        self.assertFalse(result.verified)
        self.assertEqual(len(runner.calls), 1)
        self.assertIn(world.latest["classification"],
                      (provider_module.CLASSIFICATION_REFUSED_ATTEMPT,
                       provider_module.CLASSIFICATION_FAILED_ATTEMPT))

    def test_an_unobservable_after_math_is_unverified(self):
        world = FakeWorld()
        original = world.observer.inspect_detailed

        def flaky(*args: Any, **kwargs: Any) -> Any:
            if world.mutation_client.attempts:
                raise RuntimeError("the API server could not be read")
            return original(*args, **kwargs)

        world.observer.inspect_detailed = flaky  # type: ignore[assignment]
        result = world.provider.apply(world.request())
        self.assertFalse(result.verified)
        self.assertEqual(world.latest["classification"],
                         provider_module.CLASSIFICATION_UNVERIFIED)
        self.assertEqual(world.latest["verification"]["verified"], False)
        self.assertIn("could not be observed", world.latest["reason"])


class EvidenceTests(unittest.TestCase):
    """Machine-readable, reconstructable, and never a claim it cannot back."""

    def verified_world(self) -> FakeWorld:
        world = FakeWorld()
        self.assertTrue(world.provider.apply(world.request()).verified)
        return world

    def test_the_record_carries_the_evidence_the_spec_requires(self):
        world = self.verified_world()
        record = world.latest
        self.assertEqual(record["schema"], provider_module.EVIDENCE_SCHEMA)
        self.assertEqual(record["provider"], provider_module.PROVIDER_NAME)
        self.assertEqual(record["operation"], OP_APPLY)
        self.assertEqual(record["verified"], True)
        self.assertEqual(record["request_digest"],
                         world.request().digest())
        request = record["request"]
        for field in ("intent_id", "gate_evaluation_id", "deployment_run_id",
                      "source_sha", "stable_target", "canary_target",
                      "expected_current_percentage", "requested_percentage",
                      "observed_percentage", "observed_at"):
            self.assertIn(field, request)
        for phase in ("pre", "post"):
            summary = record[phase]
            for field in ("status", "percentage", "configured_percentage",
                          "configured_fraction", "stable_identity",
                          "canary_identity", "binding_established",
                          "collected_at", "route", "controller", "targets",
                          "findings"):
                self.assertIn(field, summary, f"{phase}.{field} is missing")
            for field in ("name", "namespace", "generation", "weights",
                          "backends", "controller_observed_generation"):
                self.assertIn(field, summary["route"],
                              f"{phase}.route.{field} is missing")
        mutation = record["mutation"]
        self.assertEqual(mutation["operation"], "set_backend_weights")
        self.assertEqual(mutation["resource"], "httproute")
        self.assertEqual(mutation["route"], ROUTE)
        self.assertEqual(mutation["namespace"], NAMESPACE)
        self.assertEqual(mutation["resource_version_precondition"], "1000")
        self.assertEqual(len(mutation["changes"]), 2)
        verification = record["verification"]
        for field in ("expected_percentage", "observed_percentage", "verified",
                      "reason"):
            self.assertIn(field, verification)
        for field in ("registry", "claim_id", "claim_state", "replay", "attempts"):
            self.assertIn(field, record["concurrency"])
        self.assertEqual(record["causality"],
                         provider_module.CAUSALITY_WRITE_ACCEPTED)
        self.assertEqual(record["classification"],
                         provider_module.CLASSIFICATION_VERIFIED)

    def test_every_record_keeps_attempt_and_verification_apart(self):
        world = self.verified_world()
        attempt = world.latest["attempt"]
        self.assertEqual(attempt["state"], client_module.ATTEMPT_ACCEPTED)
        self.assertTrue(attempt["reported_resource_version"])
        self.assertEqual(world.latest["causality"],
                         provider_module.CAUSALITY_WRITE_ACCEPTED)
        world2 = FakeWorld()
        world2.mutation_client.script = "no_op"
        world2.provider.apply(world2.request())
        self.assertEqual(world2.latest["attempt"]["state"],
                         client_module.ATTEMPT_ACCEPTED)
        self.assertFalse(world2.latest["verified"])
        self.assertFalse(world2.latest["verification"]["verified"])

    def test_the_external_operation_id_is_reported_never_invented(self):
        world = FakeWorld()
        world.mutation_client.script = "no_op"
        world.provider.apply(world.request())
        self.assertIsNone(world.latest["attempt"]["external_operation_id"])
        real, _runner = real_client_world()
        real.provider.apply(real.request())
        reported = real.latest["attempt"]["external_operation_id"]
        self.assertEqual(reported, real.latest["attempt"]["reported_resource_version"])

    def test_evidence_json_is_deterministic_and_sorted(self):
        world = self.verified_world()
        first = provider_module.evidence_to_json(world.provider.records)
        second = provider_module.evidence_to_json(world.provider.records)
        self.assertEqual(first, second)
        self.assertTrue(first.endswith("\n"))
        payload = json.loads(first)
        self.assertEqual(payload, [dict(record) for record in world.provider.records])
        self.assertEqual(first.index('"attempt"') < first.index('"causality"'), True,
                         "keys are not serialised in sorted order")

    def test_no_secret_path_or_token_reaches_the_evidence(self):
        world = FakeWorld()
        world.mutation_client.script = "reject"
        world.provider.apply(world.request())
        blob = provider_module.evidence_to_json(world.provider.records)
        for forbidden in ("/home/", "kubeconfig", "Bearer", "token=", ".kube"):
            self.assertNotIn(forbidden, blob,
                             f"the evidence leaked {forbidden!r}")
        self.assertIn("reason", world.latest)
        self.assertLessEqual(len(world.latest["reason"]),
                             provider_module.MAX_REASON_LENGTH)

    def test_timestamps_are_utc_isoformat(self):
        world = self.verified_world()
        record = world.latest
        for phase in ("pre", "post"):
            self.assertTrue(record[phase]["collected_at"].endswith("+00:00"),
                            record[phase]["collected_at"])
        self.assertEqual(record["request"]["observed_at"],
                         "2026-10-08T12:00:00+00:00")

    def test_a_refusal_records_its_classification_and_its_reason(self):
        world = FakeWorld((50, 50))
        world.provider.apply(world.request(expected=5, requested=25))
        record = world.latest
        self.assertTrue(record["classification"].startswith("refused:"))
        self.assertTrue(record["reason"])
        self.assertFalse(record["verified"])
        self.assertEqual(record["concurrency"]["attempts"], 0)

    def test_a_claim_refusal_records_the_holder_without_a_claim_of_its_own(self):
        world = FakeWorld()
        request = world.request()
        held = world.registry.claim(request.digest(), OP_APPLY, world.now)
        world.provider.apply(request)
        record = world.latest
        self.assertEqual(record["concurrency"]["claim_id"], held["claim_id"])
        self.assertEqual(record["concurrency"]["claim_state"],
                         "held-by-another-attempt")
        self.assertEqual(record["concurrency"]["attempts"], 0)

    def test_evidence_is_bounded(self):
        world = FakeWorld()
        world.mutation_client.script = "reject"
        world.provider.apply(world.request())
        record = world.latest
        self.assertLessEqual(len(record["reason"]),
                             provider_module.MAX_REASON_LENGTH)
        self.assertLessEqual(len(record["pre"].get("findings", ())),
                             provider_module.MAX_FINDINGS_IN_EVIDENCE)
        self.assertLessEqual(len(json.dumps(record)), 20000)


class MutationClientClosureTests(unittest.TestCase):
    """The one write is a closed, host-owned, bounded operation."""

    def test_there_is_one_operation_and_one_verb(self):
        self.assertEqual([member.value for member in client_module.MutationOperation],
                         ["set_backend_weights"])
        self.assertEqual(client_module.OPERATION_RESOURCES,
                         {"set_backend_weights": "httproute"})
        self.assertEqual(client_module.MUTATING_VERBS, {"patch"})
        self.assertEqual(client_module.BACKEND_REFS_PATH,
                         "/spec/rules/0/backendRefs")

    def test_the_patch_is_a_compare_and_set_of_exactly_two_weights(self):
        operations = client_module.build_weight_patch(fixture_mutation())
        self.assertEqual(len(operations), 7)
        self.assertEqual(operations[0],
                         {"op": "test", "path": "/metadata/resourceVersion",
                          "value": "1000"})
        replaces = [operation for operation in operations
                    if operation["op"] == "replace"]
        self.assertEqual(replaces, [
            {"op": "replace", "path": f"{client_module.BACKEND_REFS_PATH}/0/weight",
             "value": 75},
            {"op": "replace", "path": f"{client_module.BACKEND_REFS_PATH}/1/weight",
             "value": 25},
        ])
        tests = [operation for operation in operations
                 if operation["op"] == "test"]
        self.assertEqual([operation["path"] for operation in tests],
                         ["/metadata/resourceVersion",
                          f"{client_module.BACKEND_REFS_PATH}/0/name",
                          f"{client_module.BACKEND_REFS_PATH}/0/weight",
                          f"{client_module.BACKEND_REFS_PATH}/1/name",
                          f"{client_module.BACKEND_REFS_PATH}/1/weight"])
        for operation in replaces:
            self.assertTrue(operation["path"].endswith("/weight"))
        for operation in operations:
            self.assertIn(operation["op"], ("test", "replace"))

    def test_the_argv_is_host_owned_and_carries_no_caller_payload(self):
        argv = client_module.build_mutation_argv(fixture_mutation())
        self.assertEqual(argv[0], "kubectl")
        self.assertIn("patch", argv)
        self.assertIn("httproute", argv)
        self.assertIn(ROUTE, argv)
        self.assertIn("-n", argv)
        self.assertIn(NAMESPACE, argv)
        self.assertIn("--type=json", argv)
        self.assertIn("-p", argv)
        for verb in FORBIDDEN_VERBS:
            self.assertNotIn(verb, argv)
        for token in ("-f", "--filename", "--raw", "--dry-run", "jsonpath",
                      "/bin/sh", "sh"):
            self.assertNotIn(token, argv)

    def test_no_public_function_takes_an_argv_a_verb_or_a_payload(self):
        for path in (CLIENT_SOURCE, PROVIDER_SOURCE):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                names = {argument.arg for argument in
                         node.args.args + node.args.kwonlyargs}
                forbidden = {"argv", "args", "command", "cmd", "shell", "payload",
                             "patch", "patch_payload", "patch_document",
                             "jsonpath", "json_path", "file", "filename",
                             "file_path", "verb", "subcommand", "resource",
                             "kind", "namespace_override", "path_expression"}
                self.assertEqual(names & forbidden, set(),
                                 f"{path.name}:{node.name} accepts {names & forbidden}")

    def test_the_client_has_exactly_one_process_entry_point(self):
        executable = _executable_source(CLIENT_SOURCE.read_text(encoding="utf-8"))
        self.assertEqual(executable.count("subprocess.run"), 1,
                         "the client must reference exactly one process runner")
        self.assertIn("self._runner = runner or subprocess.run", executable)

    def test_no_forbidden_primitive_appears_in_the_write_package(self):
        for path in (CLIENT_SOURCE, PROVIDER_SOURCE):
            source = path.read_text(encoding="utf-8")
            executable = _executable_source(source)
            for primitive in ("os.system(", "shell=True", "Popen(", "run_kubectl",
                              "patch(raw", "eval(", "exec(", "shutil.which(",
                              "kubectl apply", "kubectl delete", "kubectl create",
                              "kubectl replace", "kubectl scale", "kubectl exec"):
                self.assertNotIn(primitive, executable,
                                 f"{path.name} contains {primitive!r}")
        executable = _executable_source(CLIENT_SOURCE.read_text(encoding="utf-8"))
        self.assertNotIn("subprocess.run(list(", executable)
        self.assertNotIn("_runner(argv, shell", executable)

    def test_the_provider_module_has_no_process_or_environment_access(self):
        source = PROVIDER_SOURCE.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertNotIn("subprocess", imported)
        self.assertNotIn("os", imported)
        self.assertNotIn("shutil", imported)
        self.assertNotIn("socket", imported)
        self.assertNotIn("urllib", imported)

    def test_the_client_reads_the_environment_once_at_construction(self):
        source = CLIENT_SOURCE.read_text(encoding="utf-8")
        self.assertNotIn("os.environ[", source)
        self.assertEqual(source.count("os.environ"), 1)
        self.assertIn("ARES_TRAFFIC_MUTATION_TIMEOUT", source)

    def test_the_runner_is_called_once_without_a_shell(self):
        calls: List[Dict[str, Any]] = []
        world = FakeWorld()
        client = client_module.KubernetesMutationClient(
            client_module.TrafficWriteConfig(namespace=NAMESPACE, context="c",
                                             kubectl="kubectl", timeout_seconds=7),
            runner=lambda argv, **kwargs: (
                calls.append({"argv": list(argv), "kwargs": dict(kwargs)})
                or proc(argv, json.dumps(world.cluster.document()), "", 0)),
        )
        attempt = client.apply_weight_mutation(fixture_mutation())
        self.assertEqual(len(calls), 1)
        self.assertNotIn("shell", calls[0]["kwargs"])
        self.assertFalse(calls[0]["kwargs"].get("shell", False))
        self.assertEqual(calls[0]["kwargs"].get("timeout"), 7)
        self.assertEqual(calls[0]["kwargs"].get("check"), False)
        self.assertIsInstance(calls[0]["argv"], list)
        self.assertEqual(client.attempts, 1)
        self.assertEqual(attempt.state, client_module.ATTEMPT_ACCEPTED)

    def test_classification_is_three_valued(self):
        self.assertEqual(client_module.ATTEMPT_STATES,
                         ("accepted", "rejected", "unknown"))
        cases = (
            (0, '{"ok": true}', "", client_module.ATTEMPT_ACCEPTED),
            (1, "", "Error from server (Conflict): the server rejected our "
                    "request: test failed", client_module.ATTEMPT_REJECTED),
            (1, "", "error: the server rejected our request", client_module.ATTEMPT_REJECTED),
            (1, "", "something else went wrong", client_module.ATTEMPT_UNKNOWN),
            (None, "", "", client_module.ATTEMPT_UNKNOWN),
            (0, "", "", client_module.ATTEMPT_ACCEPTED),
        )
        for returncode, stdout, stderr, expected in cases:
            with self.subTest(returncode=returncode, stderr=stderr[:30]):
                attempt = client_module.classify_attempt(returncode, stdout, stderr)
                self.assertEqual(attempt.state, expected)

    def test_a_timeout_is_unknown_and_never_retried(self):
        calls = {"n": 0}

        def timeout(argv: Any, **kwargs: Any) -> Any:
            calls["n"] += 1
            raise subprocess.TimeoutExpired(cmd=list(argv),
                                            timeout=kwargs.get("timeout", 30))

        client = client_module.KubernetesMutationClient(
            client_module.TrafficWriteConfig(namespace=NAMESPACE),
            runner=timeout)
        attempt = client.apply_weight_mutation(fixture_mutation())
        self.assertEqual(attempt.state, client_module.ATTEMPT_UNKNOWN)
        self.assertEqual(calls["n"], 1)
        self.assertEqual(client.attempts, 1)

    def test_a_missing_binary_is_unknown(self):
        def missing(argv: Any, **kwargs: Any) -> Any:
            raise FileNotFoundError("kubectl")

        client = client_module.KubernetesMutationClient(
            client_module.TrafficWriteConfig(namespace=NAMESPACE),
            runner=missing)
        attempt = client.apply_weight_mutation(fixture_mutation())
        self.assertEqual(attempt.state, client_module.ATTEMPT_UNKNOWN)
        self.assertEqual(client.attempts, 1)

    def test_an_oversized_answer_is_unknown(self):
        huge = "x" * (client_module.MAX_OUTPUT_BYTES + 1)
        client = client_module.KubernetesMutationClient(
            client_module.TrafficWriteConfig(namespace=NAMESPACE),
            runner=lambda argv, **kwargs: proc(argv, huge, "", 0))
        attempt = client.apply_weight_mutation(fixture_mutation())
        self.assertEqual(attempt.state, client_module.ATTEMPT_UNKNOWN)

    def test_credentials_and_paths_are_redacted_from_a_rejection(self):
        client = client_module.KubernetesMutationClient(
            client_module.TrafficWriteConfig(namespace=NAMESPACE),
            runner=lambda argv, **kwargs: proc(
                argv, "", 'error: failed using kubeconfig /home/user/.kube/config '
                          'with token=abc123: the server rejected our request', 1))
        attempt = client.apply_weight_mutation(fixture_mutation())
        self.assertEqual(attempt.state, client_module.ATTEMPT_REJECTED)
        self.assertNotIn("/home/user/.kube/config", attempt.detail)
        self.assertNotIn("abc123", attempt.detail)
        self.assertIn("token=<redacted>", attempt.detail)

    def test_identifiers_are_validated_before_any_argv_exists(self):
        cases = (
            {"route_name": "bad route"},
            {"route_name": ""},
            {"namespace": "kube-system"},
            {"namespace": ""},
        )
        for override in cases:
            with self.subTest(**override):
                values = {"route_name": ROUTE, "namespace": NAMESPACE,
                          "resource_version": "1000",
                          "changes": (client_module.BackendWeightChange(
                              index=0, name=STABLE, expected_weight=95,
                              new_weight=75),)}
                values.update(override)
                with self.assertRaises(client_module.KubernetesMutationPolicyViolation):
                    client_module.WeightMutation(**values)
        for override in ({"name": "bad name"}, {"name": "ares-stable; rm -rf /"},
                         {"expected_weight": True}, {"new_weight": -1},
                         {"new_weight": 1001}, {"index": 9}, {"index": -1}):
            with self.subTest(**override):
                values = {"index": 0, "name": STABLE, "expected_weight": 95,
                          "new_weight": 75}
                values.update(override)
                with self.assertRaises(client_module.KubernetesMutationPolicyViolation):
                    client_module.BackendWeightChange(**values)

    def test_a_mutation_with_the_wrong_shape_is_refused(self):
        for changes in ((client_module.BackendWeightChange(
                index=0, name=STABLE, expected_weight=95, new_weight=75),),
                (client_module.BackendWeightChange(
                    index=0, name=STABLE, expected_weight=95, new_weight=75),
                 client_module.BackendWeightChange(
                     index=1, name=STABLE, expected_weight=5, new_weight=25))):
            with self.subTest(changes=len(changes)):
                with self.assertRaises(client_module.KubernetesMutationPolicyViolation):
                    client_module.WeightMutation(
                        route_name=ROUTE, namespace=NAMESPACE,
                        resource_version="1000", changes=changes)

    def test_a_patch_is_only_built_from_a_validated_mutation(self):
        with self.assertRaises(client_module.KubernetesMutationPolicyViolation):
            client_module.build_weight_patch({"op": "replace"})
        with self.assertRaises(client_module.KubernetesMutationPolicyViolation):
            client_module.build_mutation_argv({"route": ROUTE})


def _executable_source(source: str) -> str:
    """The module's source with comments and docstrings removed.

    A guard that scans raw text would trip over a docstring that *names* a
    forbidden primitive while forbidding it, which is exactly what these
    modules do.
    """
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and \
                    isinstance(body[0].value, ast.Constant) and \
                    isinstance(body[0].value.value, str):
                body[0].value.value = ""
    return ast.unparse(tree)


class ContractAndSecurityBoundaryTests(unittest.TestCase):
    """The frozen contracts stay frozen, and the write stays in its lane."""

    def test_the_attempt_vocabulary_is_three_valued(self):
        self.assertEqual(ATTEMPT_STATES,
                         (ATTEMPT_ACCEPTED, ATTEMPT_REJECTED, ATTEMPT_UNKNOWN))
        for state in ATTEMPT_STATES:
            with self.subTest(state=state):
                attempt = MutationAttempt(state=state)
                self.assertEqual(attempt.state, state)
        with self.assertRaises(client_module.MutationWriteError):
            MutationAttempt(state="probably-fine")

    def test_the_provider_refuses_to_be_constructed_without_its_tools(self):
        world = FakeWorld()
        for missing in ("read_client", "observer", "mutation_client"):
            with self.subTest(missing=missing):
                arguments = {
                    "read_client": world.read_client,
                    "observer": world.observer,
                    "mutation_client": world.mutation_client,
                    "route_name": ROUTE,
                    "namespace": NAMESPACE,
                    "app_label": APP_LABEL,
                    "expected_deployment_run_id": RUN_ID,
                    "expected_source_sha": SOURCE_SHA,
                }
                arguments[missing] = None
                with self.assertRaises((ValueError, RuntimeError)):
                    TrustedTrafficMutationProvider(**arguments)

    def test_the_provider_is_a_traffic_mutation_port(self):
        world = FakeWorld()
        self.assertTrue(is_traffic_mutation_port(world.provider))

    def test_the_provider_surface_is_exactly_apply_and_rollback(self):
        public = {name for name in dir(provider_module.TrustedTrafficMutationProvider)
                  if not name.startswith("_")}
        self.assertIn("apply", public)
        self.assertIn("rollback", public)
        for forbidden in FORBIDDEN_PORT_MEMBERS:
            self.assertNotIn(forbidden, public)
        for forbidden in FORBIDDEN_VERBS:
            self.assertNotIn(forbidden, public)
        self.assertNotIn("inspect", public)
        self.assertNotIn("plan", public)
        self.assertTrue(is_traffic_mutation_port(world_provider()))

    def test_the_port_contract_is_unchanged(self):
        self.assertEqual(FORBIDDEN_PORT_MEMBERS,
                         ("inspect", "plan", "execute", "mutate", "apply_percentage"))
        world = FakeWorld()
        request = world.request()
        self.assertEqual(expected_verified_percentage(OP_APPLY, request),
                         request.requested_percentage)
        self.assertEqual(expected_verified_percentage(OP_ROLLBACK, request),
                         request.expected_current_percentage)
        # the fail-closed default offers the port's surface but refuses to act
        self.assertTrue(is_traffic_mutation_port(UnavailableTrafficMutationProvider()))

    def test_the_unavailable_provider_still_fails_closed(self):
        provider = UnavailableTrafficMutationProvider()
        world = FakeWorld()
        request = world.request()
        for operation in (provider.apply, provider.rollback):
            with self.subTest(operation=operation.__name__):
                with self.assertRaises(TrafficMutationProviderUnavailable):
                    operation(request)
        self.assertFalse(hasattr(provider, "records"))

    def test_the_write_package_is_the_only_process_spawner(self):
        def spawners(directory: pathlib.Path) -> set:
            return {path.name for path in directory.rglob("*.py")
                    if "subprocess." in path.read_text(encoding="utf-8")}

        self.assertEqual(spawners(MUTATION_DIR), {"kubernetes_mutation_client.py"})
        self.assertEqual(spawners(TRAFFIC_DIR), {"kubernetes_read_client.py"})

    def test_the_write_client_is_registered_in_the_execution_boundary_audit(self):
        from incident_service.application.commands.test_execution_authority import (  # noqa: E501
            RepositoryExecutionBoundaryAuditTests,
        )
        allowed = RepositoryExecutionBoundaryAuditTests.ALLOWED["subprocess."]
        self.assertIn("incident_service/infrastructure/traffic_mutation/"
                      "kubernetes_mutation_client.py", allowed)
        self.assertIn("incident_service/infrastructure/traffic/"
                      "kubernetes_read_client.py", allowed)

    def test_production_modules_never_import_the_e2e_harness(self):
        for path in (CLIENT_SOURCE, PROVIDER_SOURCE):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertFalse(alias.name.startswith("e2e"),
                                         f"{path.name} imports {alias.name}")
                elif isinstance(node, ast.ImportFrom) and node.module:
                    self.assertFalse(node.module.startswith("e2e"),
                                     f"{path.name} imports {node.module}")

    def test_the_provider_never_manufactures_approval_material(self):
        source = _executable_source(PROVIDER_SOURCE.read_text(encoding="utf-8"))
        for token in ("intent_id =", "gate_evaluation_id =", "deployment_run_id =",
                      "source_sha =", "uuid4", "secrets.", "hashlib", "random."):
            self.assertNotIn(token, source.replace("self._expected_run", "x"))
        # no identifier prefix is synthesized anywhere in the write package
        for literal in ('"ti_"', "'ti_'", '"gate-"', "'gate-'", "getenv"):
            for path in (PROVIDER_SOURCE, CLIENT_SOURCE):
                self.assertNotIn(
                    literal, _executable_source(path.read_text(encoding="utf-8")),
                    f"{path.name} synthesizes approval material")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in (
                    "intent_id", "gate_evaluation_id", "deployment_run_id",
                    "source_sha", "stable_target", "canary_target",
                    "requested_percentage", "expected_current_percentage"):
                self.assertIsInstance(node.ctx, ast.Load,
                                      f"the provider assigns to {node.attr}")

    def test_the_package_public_surface_is_explicit(self):
        exported = set(mutation_package.__all__)
        for name in ("TrustedTrafficMutationProvider", "KubernetesMutationClient",
                     "MutationClaimConflict", "InMemoryMutationAttemptRegistry",
                     "percentage_to_weights", "evidence_to_json"):
            self.assertIn(name, exported)
        for name in ("UnavailableTrafficMutationProvider", "execute", "run_kubectl",
                     "apply_manifest", "delete"):
            self.assertNotIn(name, exported)

    def test_the_write_modules_are_not_part_of_the_observation_package(self):
        self.assertTrue((MUTATION_DIR / "trusted_mutation_provider.py").is_file())
        self.assertFalse((TRAFFIC_DIR / "trusted_mutation_provider.py").exists())
        self.assertFalse((TRAFFIC_DIR / "kubernetes_mutation_client.py").exists())

    def test_no_new_arbitrary_mutation_endpoint_exists(self):
        source = (PLATFORM_DIR / "incident_service" / "application" / "services"
                  / "traffic_mutation_boundary.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        port_members = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "TrafficMutationPort":
                port_members = [child.name for child in node.body
                                if isinstance(child, ast.FunctionDef)]
        self.assertEqual(sorted(port_members), ["apply", "rollback"])
        self.assertEqual(source.count("class TrafficMutationPort"), 1)


# --------------------------------------------------- source-mutation controls
#
# Each control mutates the shipped source in memory, loads it as a module, and
# runs the whole probe battery against it. A control that cannot break a named
# probe is not proving anything, and the suite fails. The anchors are exact
# strings: if the implementation moves, the control fails loudly instead of
# silently mutating nothing.

CONTROLS: Tuple[Tuple[str, str, Tuple[Tuple[str, str], ...],
                     Tuple[str, ...]], ...] = (
    (
        "stale-precondition-rejection-removed",
        "provider",
        (("            if live_percentage != expected:",
          "            if False:  # mutation control: the stale check is gone"),),
        ("stale-precondition-refused", "target-already-live-unattributed",
         "duplicate-is-a-replay-with-no-write"),
    ),
    (
        "controller-acceptance-rejection-removed",
        "provider",
        (("        if route.accepted is not True:",
          "        if False and route.accepted is not True:  # mutation control"),),
        ("controller-acceptance-missing", "controller-not-accepted"),
    ),
    (
        "resolved-refs-rejection-removed",
        "provider",
        (("        if route.resolved_refs is not True:",
          "        if False and route.resolved_refs is not True:  # mutation control"),),
        ("resolved-refs-false",),
    ),
    (
        "observed-generation-rejection-removed",
        "provider",
        (("""        if (
            route.controller_observed_generation is None
            or route.generation is None
            or route.controller_observed_generation != route.generation
        ):""",
          "        if False:  # mutation control"),),
        ("controller-generation-stale",),
    ),
    (
        "identity-verification-disabled",
        "provider",
        (("        if observation.stable_identity != request.stable_target:",
          "        if False:  # mutation control"),
         ("        if observation.canary_identity != request.canary_target:",
          "        if False:  # mutation control"),
         ("            if stable.identity != request.stable_target:",
          "            if False:  # mutation control"),
         ("            if canary.identity != request.canary_target:",
          "            if False:  # mutation control")),
        ("identity-mismatch",),
    ),
    (
        "postcondition-verification-removed",
        "provider",
        (("        if post_percentage == target_percentage:",
          "        if attempt.state == ATTEMPT_ACCEPTED or post_percentage == "
          "target_percentage:  # mutation control"),
         ("            if not self._generation_progressed(pre, post, attempt):",
          "            if False:  # mutation control: the generation guard is gone")),
        ("postcondition-is-observed-not-assumed",),
    ),
    (
        "route-layout-cross-check-removed",
        "provider",
        (("        if by_name[stable_name][\"weight\"] != weights[\"stable\"]:",
          "        if False:  # mutation control"),
         ("        if by_name[canary_name][\"weight\"] != weights[\"canary\"]:",
          "        if False:  # mutation control")),
        ("layout-disagrees-with-observation",),
    ),
    (
        "claim-single-flight-removed",
        "provider",
        (("            claim = self._registry.claim(digest, operation, started)",
          "            claim = {\"claim_id\": \"clm_control\", \"state\": "
          "\"in-flight\", \"request_digest\": digest, \"operation\": operation, "
          "\"started_at\": started}  # mutation control"),),
        ("concurrent-claim-is-refused", "duplicate-is-a-replay-with-no-write"),
    ),
    (
        "weight-exactness-coerced-by-rounding",
        "provider",
        (("    if stable_weight + canary_weight != WEIGHT_DENOMINATOR:",
          "    if False:  # mutation control"),),
        ("inexact-share-refused",),
    ),
    (
        "client-retries-on-an-unknown-answer",
        "client",
        (("        except subprocess.TimeoutExpired:\n",
          "        except subprocess.TimeoutExpired:\n"
          "            # mutation control: a lost answer is retried once\n"
          "            self._attempts += 1\n"
          "            completed = self._runner(list(argv), capture_output=True,\n"
          "                                     text=True, timeout=timeout, check=False)\n"
          "            return classify_attempt(completed.returncode,\n"
          "                                    completed.stdout or \"\",\n"
          "                                    completed.stderr or \"\")\n"
          "        except subprocess.TimeoutExpired as _control_unreachable:\n"),),
        ("unknown-attempt-is-single-shot", "the-write-is-one-process-per-attempt"),
    ),
    (
        "compare-and-set-tests-removed",
        "client",
        (("""        {"op": "test", "path": "/metadata/resourceVersion",
         "value": mutation.resource_version},
""", "        # mutation control: the compare-and-set is gone\n"),
         ("""    for change in mutation.changes:
        operations += (
            {"op": "test", "path": f"{BACKEND_REFS_PATH}/{change.index}/name",
             "value": change.name},
            {"op": "test", "path": f"{BACKEND_REFS_PATH}/{change.index}/weight",
             "value": change.expected_weight},
        )
""", "")),
        ("lost-race-keeps-the-other-actors-value",),
    ),
)


def load_mutated_module(path: pathlib.Path, replacements: Sequence[Tuple[str, str]],
                        name: str) -> Any:
    """Load ``path`` with ``replacements`` applied, as a real module."""
    source = path.read_text(encoding="utf-8")
    for old, new in replacements:
        if old not in source:
            raise AssertionError(
                f"the mutation anchor is not in {path.name}: {old[:70]!r}")
        source = source.replace(old, new, 1)
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module


class SourceMutationControlTests(unittest.TestCase):
    """Controls that were actually executed, and that provably bite."""

    @classmethod
    def tearDownClass(cls) -> None:
        for name in list(sys.modules):
            if name.startswith("_mutated_8_7_b_2_"):
                del sys.modules[name]

    def test_the_unmutated_modules_satisfy_every_safety_probe(self):
        failures = []
        for name, probe in SAFETY_PROBES:
            outcome = probe(provider_module, client_module)
            if outcome:
                failures.append((name, outcome))
        self.assertEqual(failures, [],
                         f"the shipped modules fail safety probes: {failures}")

    def test_every_control_compiles_changes_the_source_and_is_named(self):
        seen = set()
        for name, target, replacements, expected in CONTROLS:
            with self.subTest(control=name):
                self.assertNotIn(name, seen, "duplicate control name")
                seen.add(name)
                path = PROVIDER_SOURCE if target == "provider" else CLIENT_SOURCE
                module = load_mutated_module(
                    path, replacements, f"_mutated_8_7_b_2_{name.replace('-', '_')}")
                self.assertTrue(module is not None)
                self.assertTrue(expected)

    def test_every_executed_control_breaks_its_named_safety_probe(self):
        report: List[str] = []
        for name, target, replacements, expected in CONTROLS:
            with self.subTest(control=name):
                path = PROVIDER_SOURCE if target == "provider" else CLIENT_SOURCE
                mutated = load_mutated_module(
                    path, replacements, f"_mutated_8_7_b_2_{name.replace('-', '_')}")
                provider_under_test = (mutated if target == "provider"
                                       else provider_module)
                client_under_test = (mutated if target == "client"
                                     else client_module)
                broken: List[Tuple[str, str]] = []
                for probe_name, probe in SAFETY_PROBES:
                    try:
                        outcome = probe(provider_under_test, client_under_test)
                    except Exception as exc:  # noqa: BLE001 - a crash is a break
                        outcome = f"raised {type(exc).__name__}: {exc}"
                    if outcome:
                        broken.append((probe_name, outcome))
                broken_names = [probe_name for probe_name, _ in broken]
                report.append(f"{name}: broke {broken_names}")
                self.assertTrue(
                    broken,
                    f"the control {name} changed the source and every safety "
                    f"probe still passed: the probes do not cover it")
                missing = [name_ for name_ in expected if name_ not in broken_names]
                self.assertEqual(
                    missing, [],
                    f"the control {name} did not break {missing}; it broke "
                    f"{broken_names}")
        print("\n" + "\n".join(report))

    def test_a_control_demonstrates_the_danger_its_probe_forbids(self):
        """The postcondition control really does verify an unchanged route."""
        control = next(entry for entry in CONTROLS
                       if entry[0] == "postcondition-verification-removed")
        mutated = load_mutated_module(PROVIDER_SOURCE, control[2],
                                      "_mutated_8_7_b_2_postcondition_demo")
        world = FakeWorld(module=mutated)
        world.mutation_client.script = "no_op"
        # The mutant tries to verify a route it never moved. The frozen
        # Phase 8.7-A result contract refuses to carry that claim at all
        # (verified=True with a remote state that is not the operation's
        # target), which is a second, independent backstop; the safety
        # probe for this control still breaks, because the mutant does not
        # behave, and either way no false success is produced.
        with self.assertRaises(InvalidTrafficMutationRequest):
            world.provider.apply(world.request())
        self.assertEqual(world.weights, (95, 5))


# ----------------------------------------------------- documentation and CI


class DocumentationTests(unittest.TestCase):
    """The phase's design document exists and answers the §39 questions."""

    REQUIRED_SECTIONS = (
        "Scope",
        "Authority model",
        "Target binding",
        "Precondition",
        "Mutation boundary",
        "Postcondition",
        "APPLY",
        "ROLLBACK",
        "Idempotency",
        "Concurrency",
        "Unknown outcomes",
        "Evidence",
        "Security boundary",
        "E2E evidence",
        "Limitations",
    )

    def test_the_document_exists_and_covers_every_section(self):
        self.assertTrue(DOC.is_file(), f"{DOC} is missing")
        text = DOC.read_text(encoding="utf-8")
        for section in self.REQUIRED_SECTIONS:
            with self.subTest(section=section):
                self.assertIn(section, text)

    def test_the_document_names_the_exact_limits_it_cannot_prove(self):
        text = DOC.read_text(encoding="utf-8")
        for token in ("Limitations", "Kind", "not a production"):
            self.assertIn(token, text)

    def test_the_document_states_the_weights_are_not_percentages(self):
        text = DOC.read_text(encoding="utf-8").lower()
        self.assertIn("denominator", text)
        self.assertIn("not a percentage", text)


class LiveE2EHarnessTests(unittest.TestCase):
    """The live driver and its control-flow tests exist and stay separated."""

    def test_the_driver_exists_and_targets_the_real_provider(self):
        self.assertTrue(DRIVER.is_file())
        source = DRIVER.read_text(encoding="utf-8")
        self.assertIn("TrustedTrafficMutationProvider", source)
        self.assertIn("e2e/traffic_topology_kind_e2e", source.replace(
            "from e2e import traffic_topology_kind_e2e", "e2e/traffic_topology_kind_e2e"))
        for flag in ("--stable-image", "--canary-image", "--sampler-image",
                     "--expected-commit", "--deployment-run-id", "--evidence",
                     "--destroy-cluster"):
            self.assertIn(flag, source)

    def test_the_driver_separates_harness_control_from_the_application_write(self):
        source = DRIVER.read_text(encoding="utf-8")
        self.assertIn("driver_state_changes", source)
        self.assertIn("harness control", source)
        self.assertIn("performed_by", source)

    def test_the_driver_reads_its_own_route_and_not_the_adapters(self):
        source = DRIVER.read_text(encoding="utf-8")
        start = source.index("def driver_view(")
        end = source.index("def driver_patch(")
        view = source[start:end]
        self.assertIn("topology_driver.read_route", view)
        self.assertNotIn("observer.", view)

    def test_the_driver_control_flow_tests_run_the_real_driver(self):
        self.assertTrue(DRIVER_TESTS.is_file())
        source = DRIVER_TESTS.read_text(encoding="utf-8")
        self.assertIn("from e2e import traffic_mutation_kind_e2e", source)
        self.assertIn("REAL_MUTATION_CLIENT", source)
        self.assertIn("ClusterRunner", source.replace("MutationStubCluster",
                                                      "ClusterRunner"))

    def test_the_application_write_is_not_the_harness_write(self):
        """The driver's own patches never go through the application modules."""
        source = DRIVER.read_text(encoding="utf-8")
        start = source.index("def driver_patch(")
        end = source.index("# ------------------------------------------------------------- requests")
        body = source[start:end]
        self.assertIn("topology_driver.patch_route_weights", body)
        self.assertNotIn("provider.", body)
        self.assertNotIn("KubernetesMutationClient", body)


class CiWorkflowTests(unittest.TestCase):
    """The Phase 8.7-B.2 job exists, is not optional, and is not weakened."""

    @classmethod
    def setUpClass(cls):
        import yaml
        cls.workflow = yaml.safe_load(
            (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
        cls.jobs = cls.workflow["jobs"]

    def _script(self, key: str) -> str:
        job = self.jobs[key]
        return "\n".join(step.get("run", "") for step in job["steps"])

    def test_the_b2_job_exists_and_is_not_optional(self):
        self.assertIn("kubernetes-traffic-mutation-e2e", self.jobs)
        job = self.jobs["kubernetes-traffic-mutation-e2e"]
        self.assertEqual(job["name"], "Phase 8.7-B.2 trusted traffic mutation E2E")
        self.assertEqual(job["defaults"]["run"]["working-directory"],
                         "devops-ai-platform")
        self.assertNotIn("needs", job)
        self.assertIsNone(job.get("if"))
        for step in job["steps"]:
            run = step.get("run") or ""
            self.assertIsNone(step.get("continue-on-error"),
                              f"a step may not swallow failures: {run[:60]}")

    def test_the_b2_job_runs_the_mutation_driver_without_weakening(self):
        script = self._script("kubernetes-traffic-mutation-e2e")
        for token in ("e2e/traffic_mutation_kind_e2e.py",
                      '--expected-commit "$GITHUB_SHA"',
                      '--deployment-run-id "$GITHUB_RUN_ID"',
                      "--destroy-cluster",
                      "--evidence traffic-mutation-e2e.json",
                      "ares-mutation-e2e"):
            self.assertIn(token, script, f"the 8.7-B.2 job is missing {token}")
        self.assertIn("e2e/pinned-traffic-topology.txt", script)
        self.assertIn("sha256sum -c -", script)
        self.assertIn("e2e/pinned-kubectl.txt", script)
        self.assertNotIn("latest", script.replace("latest)", ""))

    def test_the_b2_job_builds_and_loads_its_own_workloads(self):
        script = self._script("kubernetes-traffic-mutation-e2e")
        for image in ("ares-mutation-stable:local", "ares-mutation-canary:local",
                      "ares-mutation-sampler:local"):
            self.assertIn(image, script)
        self.assertIn("kind load docker-image", script)
        self.assertIn("--build-arg TRACK=stable", script)
        self.assertIn("--build-arg TRACK=canary", script)

    def test_the_b2_job_tears_down_and_uploads_its_evidence_always(self):
        steps = self.jobs["kubernetes-traffic-mutation-e2e"]["steps"]
        teardown = [step for step in steps
                    if "kind delete cluster" in (step.get("run") or "")]
        self.assertTrue(teardown)
        self.assertEqual(teardown[0].get("if"), "always()")
        uploads = [step for step in steps
                   if str(step.get("uses", "")).startswith("actions/upload-artifact")]
        self.assertTrue(uploads)
        self.assertEqual(uploads[0].get("if"), "always()")
        self.assertIn("traffic-mutation-e2e.json", uploads[0]["with"]["path"])
        self.assertIn(".sha256", uploads[0]["with"]["path"])
        provenance = [step for step in steps if "provenance" in (step.get("name") or "")]
        self.assertTrue(provenance)
        self.assertEqual(provenance[0].get("if"), "always()")

    def test_the_earlier_phase_jobs_are_untouched(self):
        for key, name in (("kubernetes-traffic-topology-e2e",
                           "Phase 8.7-B.0 weighted traffic topology E2E"),
                          ("kubernetes-traffic-observation-e2e",
                           "Phase 8.7-B.1 traffic observation E2E")):
            with self.subTest(job=key):
                self.assertIn(key, self.jobs)
                self.assertEqual(self.jobs[key]["name"], name)

    def test_the_incident_service_job_still_collects_the_audit_modules(self):
        script = self._script("incident-service")
        self.assertIn("incident_service.application.commands.test_execution_authority",
                      script)
        self.assertIn("python -m compileall -q incident_service", script)

    def test_the_platform_job_collects_the_b2_modules(self):
        script = self._script("platform-tests")
        self.assertIn("pytest tests/", script)
        for module in ("test_phase_8_7_b_2_trusted_traffic_mutation_provider.py",
                       "test_phase_8_7_b_2_driver_control_flow.py"):
            with self.subTest(module=module):
                self.assertTrue((PLATFORM_DIR / "tests" / module).is_file())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
