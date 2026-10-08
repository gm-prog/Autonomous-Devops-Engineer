"""Phase 8.7-B.1 — read-only Kubernetes traffic observation adapter.

Focused coverage for the provider in
``incident_service/infrastructure/traffic``. The tests are deliberately
behavioural: they drive the observer with live-shaped Kubernetes
documents (the Phase 8.7-B.0 topology) and assert what the *adapter*
returns, not what a helper happens to compute.

Every safety-critical assertion is paired with evidence that the test
actually bites: the fixture is inspected to prove it really contains the
condition under test (a shared endpoint UID, a weight whose type is a
string, a healthy topology for the fail-closed case), so a test cannot
pass by being vacuous.

Three source-mutation controls were executed against this module and the
driver's control-flow module, each on the real implementation and then
reverted:

1. shared-identity detection removed from the observer -> 1 failure, the
   shared-backend conflict test;
2. weights silently coerced (``int(weight)``) instead of refused -> 3
   failures (malformed weight, string weight, non-integral share);
3. ``_resolve_status`` upgraded refusals to ``KNOWN`` -> 4 failures, all
   of the fail-closed paths;

with the implementation restored, both modules pass: 91 tests and 54
subtests.
"""

from __future__ import annotations

import ast
import copy
import json
import pathlib
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

PLATFORM_DIR = pathlib.Path(__file__).resolve().parent.parent
REPO_ROOT = PLATFORM_DIR.parent
sys.path.insert(0, str(PLATFORM_DIR))

from incident_service.application.services.rollout_plan_service import (  # noqa: E402
    GATE_POLICY_VERSION,
    OBSERVED_CONFLICT,
    OBSERVED_KNOWN,
    OBSERVED_UNKNOWN,
    PREFLIGHT_READY,
    RolloutPlanService,
)
from incident_service.infrastructure.traffic import (  # noqa: E402
    gateway_api_observer as observer_module,
    kubernetes_read_client as read_module,
)

TRAFFIC_DIR = PLATFORM_DIR / "incident_service" / "infrastructure" / "traffic"
READ_CLIENT = TRAFFIC_DIR / "kubernetes_read_client.py"
OBSERVER = TRAFFIC_DIR / "gateway_api_observer.py"
DRIVER = PLATFORM_DIR / "e2e" / "traffic_observation_kind_e2e.py"
DOC = REPO_ROOT / "docs" / "PHASE-8.7-B.1-TRAFFIC-OBSERVATION-ADAPTER.md"

RUN_ID = "deployment-run-8-7-b-1"
SOURCE_SHA = "941c71e5353050f5ad991c85d29f318bde8bf952"
NOW = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)

#: Members a read-only observation provider must never grow.
FORBIDDEN_PROVIDER_MEMBERS = ("apply", "rollback", "mutate", "execute",
                              "patch", "replace", "delete", "create", "scale")
#: Subcommands that must never appear in any argv this package can build.
FORBIDDEN_SUBCOMMANDS = ("apply", "patch", "replace", "delete", "create",
                         "edit", "scale", "exec", "rollout", "annotate",
                         "label", "set", "drain", "cordon", "uncordon", "taint")


# ----------------------------------------------------------------- fixtures


def live_documents(weights: tuple = (95, 5)) -> Dict[str, Any]:
    """A live-shaped snapshot of the Phase 8.7-B.0 topology.

    Shapes mirror what the API server actually returns for the committed
    fixture: one weighted HTTPRoute, two Services labelled with their
    track, one EndpointSlice per Service with ready Pod targetRefs, the
    pods behind them, and the two Deployments.
    """
    route = {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": {"name": "ares-route", "namespace": "ares-traffic",
                     "generation": 4, "uid": "route-uid"},
        "spec": {
            "parentRefs": [{"name": "ares-gateway", "sectionName": "http"}],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": "/"}}],
                "backendRefs": [
                    {"name": "ares-stable", "port": 80, "weight": weights[0]},
                    {"name": "ares-canary", "port": 80, "weight": weights[1]},
                ],
            }],
        },
        "status": {"parents": [{"conditions": [
            {"type": "Accepted", "status": "True", "observedGeneration": 4},
            {"type": "ResolvedRefs", "status": "True", "observedGeneration": 4},
        ]}]},
    }
    services: Dict[str, Any] = {}
    slices: Dict[str, Any] = {}
    pods: Dict[str, Any] = {}
    deployments: Dict[str, Any] = {}
    for track in ("stable", "canary"):
        name = f"ares-{track}"
        services[name] = {
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": name, "namespace": "ares-traffic",
                         "uid": f"uid-service-{track}",
                         "labels": {"app": "ares-traffic", "track": track}},
            "spec": {"type": "ClusterIP",
                     "selector": {"app": "ares-traffic", "track": track},
                     "ports": [{"name": "http", "port": 80, "targetPort": "http"}]},
        }
        endpoints = []
        for index in range(2):
            pod = f"{name}-6bd676c8f9-{track[:2]}{index}"
            endpoints.append({
                "addresses": [f"10.244.1.{index + 4}"],
                "conditions": {"ready": True},
                "targetRef": {"kind": "Pod", "name": pod, "namespace": "ares-traffic",
                              "uid": f"uid-pod-{track}-{index}"},
            })
            pods[pod] = {
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": pod, "namespace": "ares-traffic",
                             "uid": f"uid-pod-{track}-{index}",
                             "labels": {"app": "ares-traffic", "track": track,
                                        "pod-template-hash": "6bd676c8f9"}},
                "spec": {"containers": [{
                    "name": "workload", "image": f"ares-traffic-{track}:local",
                    "env": [{"name": "ARES_TRACK", "value": track}]}]},
            }
        slices[name] = {
            "apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice",
            "metadata": {"name": f"{name}-abcde", "namespace": "ares-traffic",
                         "labels": {read_module.SERVICE_NAME_LABEL: name}},
            "endpoints": endpoints,
        }
        deployments[name] = {
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": name, "namespace": "ares-traffic",
                         "uid": f"uid-deployment-{track}"},
            "spec": {"selector": {"matchLabels": {"app": "ares-traffic", "track": track}},
                     "template": {
                         "metadata": {"labels": {"app": "ares-traffic", "track": track}},
                         "spec": {"containers": [{
                             "name": "workload", "image": f"ares-traffic-{track}:local",
                             "env": [{"name": "ARES_TRACK", "value": track}]}]}}},
        }
    return {"route": route, "services": services, "slices": slices, "pods": pods,
            "deployments": deployments}


class FakeReadClient:
    """Serves live-shaped documents; per-resource failures are injectable."""

    def __init__(self, world: Optional[Dict[str, Any]] = None) -> None:
        self.world = world if world is not None else live_documents()
        self.config = read_module.TrafficReadConfig()
        self.calls: List[tuple] = []
        self.service_errors: Dict[str, Exception] = {}
        self.raise_on: Dict[str, Exception] = {}

    def get_http_route(self, name: str, namespace: str) -> Dict[str, Any]:
        self.calls.append(("http_route", name, namespace))
        if "http_route" in self.raise_on:
            raise self.raise_on["http_route"]
        route = self.world.get("route")
        if route is None:
            raise read_module.KubernetesResourceNotFound(
                f"http_route: {namespace}/{name} not found")
        return copy.deepcopy(route)

    def get_service(self, name: str, namespace: str) -> Dict[str, Any]:
        self.calls.append(("service", name, namespace))
        if name in self.service_errors:
            raise self.service_errors[name]
        if "service" in self.raise_on:
            raise self.raise_on["service"]
        service = self.world["services"].get(name)
        if service is None:
            raise read_module.KubernetesResourceNotFound(
                f"service: {namespace}/{name} not found")
        return copy.deepcopy(service)

    def list_endpoint_slices(self, namespace: str, service_name: str) -> List[Dict[str, Any]]:
        self.calls.append(("endpoint_slices", service_name, namespace))
        if "endpoint_slices" in self.raise_on:
            raise self.raise_on["endpoint_slices"]
        return copy.deepcopy([self.world["slices"][service_name]]
                             if service_name in self.world["slices"] else [])

    def list_pods(self, namespace: str, app_label: str) -> List[Dict[str, Any]]:
        self.calls.append(("pods", app_label, namespace))
        if "pods" in self.raise_on:
            raise self.raise_on["pods"]
        return copy.deepcopy(list(self.world["pods"].values()))

    def list_deployments(self, namespace: str, app_label: str) -> List[Dict[str, Any]]:
        self.calls.append(("deployments", app_label, namespace))
        if "deployments" in self.raise_on:
            raise self.raise_on["deployments"]
        return copy.deepcopy(list(self.world["deployments"].values()))


def observer_for(world: Optional[Dict[str, Any]] = None, **kwargs: Any):
    """A bound observer (the production-shaped configuration)."""
    kwargs.setdefault("expected_deployment_run_id", RUN_ID)
    kwargs.setdefault("expected_source_sha", SOURCE_SHA)
    kwargs.setdefault("now_factory", lambda: NOW)
    client = kwargs.pop("client", None) or FakeReadClient(world)
    return observer_module.KubernetesTrafficObserver(client, **kwargs), client


def observe(world: Optional[Dict[str, Any]] = None, **kwargs: Any):
    observer, _client = observer_for(world, **kwargs)
    return observer.inspect_detailed(RUN_ID, SOURCE_SHA)


# ------------------------------------------------------------- read policy


class ReadPolicyTests(unittest.TestCase):
    """The Kubernetes read surface is closed and read-only by construction."""

    def test_only_get_is_reachable_for_every_operation(self):
        for operation in read_module.ReadOperation:
            with self.subTest(operation=operation.value):
                argv = read_module.build_read_argv(
                    operation, namespace="ares-traffic", name="ares-route",
                    service_name="ares-stable", app_label="ares-traffic",
                    context="kind-ares-observation-e2e")
                self.assertEqual(argv[1], "get")
                self.assertEqual(argv[0], "kubectl")
                self.assertIn("--context", argv)
                self.assertEqual(argv[-2:], ("-o", "json"))
                for forbidden in FORBIDDEN_SUBCOMMANDS:
                    self.assertNotIn(forbidden, argv)

    def test_the_operation_set_is_exactly_the_five_reads(self):
        self.assertEqual(
            {operation.value for operation in read_module.ReadOperation},
            {"http_route", "service", "endpoint_slices", "pods", "deployments"})
        self.assertEqual(read_module.READ_VERBS, frozenset({"get"}))
        self.assertTrue(
            read_module.FORBIDDEN_SUBCOMMANDS.issuperset(FORBIDDEN_SUBCOMMANDS))

    def test_names_and_labels_are_validated_not_trusted(self):
        for bad in ("Ares-Stable", "ares_stable", "ares-stable;rm -rf /",
                    "--namespace=kube-system", "", None, "ares--stable-", "a" * 64):
            with self.subTest(bad=bad):
                with self.assertRaises(read_module.KubernetesReadPolicyViolation):
                    read_module.build_read_argv(
                        read_module.ReadOperation.HTTP_ROUTE,
                        namespace="ares-traffic", name=bad)

    def test_reserved_namespaces_are_refused(self):
        for namespace in sorted(read_module.RESERVED_NAMESPACES):
            with self.subTest(namespace=namespace):
                with self.assertRaises(read_module.KubernetesReadPolicyViolation):
                    read_module.build_read_argv(
                        read_module.ReadOperation.PODS, namespace=namespace,
                        app_label="ares-traffic")

    def test_an_unknown_operation_cannot_be_smuggled_in(self):
        with self.assertRaises(read_module.KubernetesReadPolicyViolation):
            read_module.build_read_argv("delete", namespace="ares-traffic",
                                        name="ares-route")

    def test_redaction_bounds_and_hides_credential_shapes(self):
        text = "error: Bearer abcdef0123456789 token=deadbeef " + "x" * 900
        redacted = read_module.redact(text)
        self.assertLessEqual(len(redacted), 241)
        self.assertNotIn("abcdef0123456789", redacted)
        self.assertNotIn("deadbeef", redacted)
        self.assertNotIn("\n", read_module.redact("two\nlines"))


class KubectlReadClientTests(unittest.TestCase):
    """The concrete client: bounded output, strict parsing, fail closed."""

    def _client(self, completed):
        def runner(argv, **kwargs):
            runner.argv = tuple(argv)
            runner.kwargs = kwargs
            return completed
        runner.argv = ()
        return read_module.KubectlReadClient(
            read_module.TrafficReadConfig(namespace="ares-traffic", timeout_seconds=7),
            runner=runner), runner

    def test_a_successful_read_is_parsed_and_versioned_by_the_api_server(self):
        payload = json.dumps({"kind": "HTTPRoute", "metadata": {"name": "ares-route"}})
        client, runner = self._client(
            subprocess.CompletedProcess([], 0, payload, ""))
        document = client.get_http_route("ares-route", "ares-traffic")
        self.assertEqual(document["kind"], "HTTPRoute")
        self.assertEqual(runner.argv[1], "get")
        self.assertIn("--request-timeout=7s", runner.argv)
        self.assertFalse(runner.kwargs["check"])

    def test_a_nonzero_exit_is_a_read_error_with_bounded_text(self):
        client, _ = self._client(subprocess.CompletedProcess(
            [], 1, "", "Error from server: " + "boom " * 500))
        with self.assertRaises(read_module.KubernetesReadError) as caught:
            client.get_service("ares-stable", "ares-traffic")
        self.assertLessEqual(len(str(caught.exception)), 400)

    def test_a_not_found_is_distinguishable_from_a_failure(self):
        client, _ = self._client(subprocess.CompletedProcess(
            [], 1, "", 'Error from server (NotFound): services "ares-canary" not found'))
        with self.assertRaises(read_module.KubernetesResourceNotFound):
            client.get_service("ares-canary", "ares-traffic")

    def test_a_timeout_propagates_as_a_read_timeout(self):
        def runner(argv, **kwargs):
            raise subprocess.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout", 1))
        client = read_module.KubectlReadClient(
            read_module.TrafficReadConfig(namespace="ares-traffic"), runner=runner)
        with self.assertRaises(read_module.KubernetesReadTimeout):
            client.get_http_route("ares-route", "ares-traffic")

    def test_invalid_json_is_refused_rather_than_guessed(self):
        client, _ = self._client(subprocess.CompletedProcess([], 0, "not json", ""))
        with self.assertRaises(read_module.KubernetesReadError):
            client.list_pods("ares-traffic", "ares-traffic")

    def test_oversized_output_is_refused(self):
        client, _ = self._client(subprocess.CompletedProcess(
            [], 0, "x" * (read_module.MAX_OUTPUT_BYTES + 1), ""))
        with self.assertRaises(read_module.KubernetesReadError):
            client.list_deployments("ares-traffic", "ares-traffic")

    def test_a_list_response_without_items_is_refused(self):
        client, _ = self._client(subprocess.CompletedProcess([], 0, "{}", ""))
        with self.assertRaises(read_module.KubernetesReadError):
            client.list_endpoint_slices("ares-traffic", "ares-stable")

    def test_the_client_refuses_a_reserved_namespace_configuration(self):
        with self.assertRaises(read_module.KubernetesReadPolicyViolation):
            read_module.KubectlReadClient(
                read_module.TrafficReadConfig(namespace="kube-system"))

    def test_configuration_is_snapshotted_from_the_environment(self):
        config = read_module.TrafficReadConfig.from_environment({
            "ARES_TRAFFIC_NAMESPACE": "ares-traffic",
            "ARES_TRAFFIC_KUBE_CONTEXT": "kind-ares-observation-e2e",
            "ARES_TRAFFIC_OBSERVE_TIMEOUT": "12",
            "ARES_TRAFFIC_KUBECONFIG": "/run/secrets/kubeconfig",
        })
        self.assertEqual(config.context, "kind-ares-observation-e2e")
        self.assertEqual(config.timeout_seconds, 12)
        self.assertTrue(config.to_dict()["kubeconfig_configured"])
        self.assertNotIn("/run/secrets/kubeconfig",
                         json.dumps(config.to_dict()))


# ------------------------------------------------------------ observations


class HealthyObservationTests(unittest.TestCase):
    """A healthy topology yields KNOWN with the exact configured share."""

    def test_committed_95_5_is_observed_as_5_percent(self):
        record = observe()
        observation = record.observation
        self.assertEqual(observation.observed_status, OBSERVED_KNOWN)
        self.assertEqual(observation.observed_percentage, 5)
        self.assertEqual(observation.provider, "kubernetes-gateway-api")
        self.assertEqual(observation.observation_source, "kubernetes-gateway-api")
        self.assertEqual(observation.stable_identity, "ares-traffic/service/ares-stable")
        self.assertEqual(observation.canary_identity, "ares-traffic/service/ares-canary")
        self.assertEqual(observation.deployment_run_id, RUN_ID)
        self.assertEqual(observation.source_sha, SOURCE_SHA)
        self.assertEqual(record.configured_fraction, (5, 100))
        self.assertIs(record.endpoints_disjoint, True)
        self.assertEqual(list(record.shared_endpoints), [])
        self.assertEqual(record.binding, observer_module.BINDING_CONFIGURED)
        self.assertEqual(record.findings, ())

    def test_the_weight_ratio_is_the_share_not_the_weight(self):
        # 25/75 is a proportional weight pair: canary is 75%, never 75/2.
        for weights, expected in (((95, 5), 5), ((100, 0), 0), ((0, 100), 100),
                                  ((25, 75), 75), ((50, 50), 50), ((1, 9), 90),
                                  ((3, 1), 25)):
            with self.subTest(weights=weights):
                record = observe(live_documents(weights=weights))
                self.assertEqual(record.observation.observed_status, OBSERVED_KNOWN)
                self.assertEqual(record.observation.observed_percentage, expected)

    def test_a_zero_weight_backend_is_observed_as_zero_not_missing(self):
        record = observe(live_documents(weights=(100, 0)))
        self.assertEqual(record.observation.observed_percentage, 0)
        self.assertEqual(record.targets["canary"].ready_endpoints,
                         ("ares-canary-6bd676c8f9-ca0", "ares-canary-6bd676c8f9-ca1"))

    def test_identity_evidence_comes_from_the_live_resources(self):
        record = observe()
        stable = record.targets["stable"]
        canary = record.targets["canary"]
        self.assertEqual(stable.workload, "ares-stable")
        self.assertEqual(canary.workload, "ares-canary")
        self.assertEqual(stable.ready_endpoints,
                         ("ares-stable-6bd676c8f9-st0", "ares-stable-6bd676c8f9-st1"))
        self.assertTrue(set(stable.ready_endpoint_uids).isdisjoint(
            canary.ready_endpoint_uids))
        self.assertEqual(stable.service_uid, "uid-service-stable")
        self.assertEqual(canary.workload_images,
                         ("ares-traffic-canary:local",))

    def test_the_track_identity_is_read_from_the_service_not_assumed(self):
        # Relabel the whole world consistently: the Service named
        # `ares-stable` now declares track=canary and its pods agree. The
        # weights must follow the live labels, so the 95-weight backend is
        # now the canary one — a name-convention adapter would answer 5.
        world = live_documents(weights=(95, 5))
        for name, track in (("ares-stable", "canary"), ("ares-canary", "stable")):
            world["services"][name]["metadata"]["labels"]["track"] = track
            world["services"][name]["spec"]["selector"]["track"] = track
            world["deployments"][name]["spec"]["selector"]["matchLabels"]["track"] = track
            world["deployments"][name]["spec"]["template"]["metadata"]["labels"][
                "track"] = track
            for pod in world["pods"].values():
                if pod["metadata"]["name"].startswith(name):
                    pod["metadata"]["labels"]["track"] = track
        self.assertEqual(
            world["services"]["ares-stable"]["metadata"]["labels"]["track"], "canary")
        record = observe(world)
        self.assertEqual(record.observation.observed_status, OBSERVED_KNOWN)
        self.assertEqual(record.observation.observed_percentage, 95)
        self.assertEqual(record.observation.stable_identity,
                         "ares-traffic/service/ares-canary")
        self.assertEqual(record.observation.canary_identity,
                         "ares-traffic/service/ares-stable")

    def test_the_timestamp_is_timezone_aware_utc(self):
        observation = observe().observation
        self.assertEqual(observation.observation_timestamp, NOW)
        self.assertIsNotNone(observation.observation_timestamp.tzinfo)
        self.assertEqual(observation.observation_timestamp.utcoffset(), timedelta(0))

    def test_the_controller_block_is_recorded_separately_from_the_rest(self):
        payload = observe().to_dict()
        self.assertEqual(payload["controller"], {
            "accepted": True, "resolved_refs": True, "observed_generation": 4,
            "route_generation": 4})
        self.assertEqual(payload["configured"]["canary_percentage"], 5)
        self.assertEqual(payload["observed"]["percentage"], 5)
        self.assertIn("not a sampled request percentage",
                      payload["configured"]["note"])

    def test_controller_explicit_rejection_is_never_known(self):
        world = live_documents()
        world["route"]["status"]["parents"][0]["conditions"][0]["status"] = "False"
        record = observe(world)
        self.assertEqual(record.observation.observed_status, OBSERVED_UNKNOWN)
        self.assertIsNone(record.observation.observed_percentage)
        self.assertTrue(
            any("Accepted=False" in text for _severity, text in record.findings),
            record.findings,
        )

    def test_missing_controller_acceptance_status_is_never_known(self):
        world = live_documents()
        world["route"]["status"]["parents"][0]["conditions"] = [
            condition for condition in
            world["route"]["status"]["parents"][0]["conditions"]
            if condition["type"] != "Accepted"
        ]
        record = observe(world)
        self.assertEqual(record.observation.observed_status, OBSERVED_UNKNOWN)
        self.assertIsNone(record.observation.observed_percentage)
        self.assertTrue(
            any("Accepted=True" in text for _severity, text in record.findings),
            record.findings,
        )

    def test_a_route_still_reconciling_is_recorded_not_hidden(self):
        world = live_documents()
        world["route"]["metadata"]["generation"] = 5
        record = observe(world)
        self.assertEqual(record.observation.observed_status, OBSERVED_KNOWN)
        self.assertEqual(record.to_dict()["controller"]["observed_generation"], 4)
        self.assertEqual(record.to_dict()["controller"]["route_generation"], 5)


class FailClosedTests(unittest.TestCase):
    """Unavailable information is never turned into an answer."""

    def _assert_unknown(self, record, expected_text):
        self.assertEqual(record.observation.observed_status, OBSERVED_UNKNOWN)
        self.assertIsNone(record.observation.observed_percentage)
        self.assertIsNone(record.observation.stable_identity)
        self.assertIsNone(record.observation.canary_identity)
        self.assertIsNone(record.observation.deployment_run_id)
        self.assertIsNone(record.observation.source_sha)
        self.assertTrue(
            any(expected_text in text for _severity, text in record.findings),
            f"{expected_text!r} not in {record.findings}")

    def test_missing_route(self):
        world = live_documents()
        world["route"] = None
        self._assert_unknown(observe(world), "does not exist")

    def test_missing_service(self):
        world = live_documents()
        del world["services"]["ares-canary"]
        self._assert_unknown(observe(world), "ares-canary")

    def test_missing_endpoint_slices(self):
        world = live_documents()
        del world["slices"]["ares-canary"]
        self._assert_unknown(observe(world), "no ready endpoints")

    def test_endpoints_that_are_not_ready(self):
        world = live_documents()
        for endpoint in world["slices"]["ares-canary"]["endpoints"]:
            endpoint["conditions"]["ready"] = False
        self._assert_unknown(observe(world), "no ready endpoints")

    def test_an_endpoint_without_a_pod_target_reference(self):
        world = live_documents()
        world["slices"]["ares-stable"]["endpoints"][0].pop("targetRef")
        # The topology is otherwise healthy, so the only reason for the
        # refusal is the unprovable endpoint identity.
        self.assertEqual(len(world["slices"]["ares-stable"]["endpoints"]), 2)
        self._assert_unknown(observe(world), "no Pod targetRef")

    def test_a_ready_endpoint_missing_from_the_pod_listing(self):
        world = live_documents()
        del world["pods"]["ares-stable-6bd676c8f9-st0"]
        self._assert_unknown(observe(world), "not visible in the pod listing")

    def test_the_api_server_is_unavailable(self):
        observer, client = observer_for()
        client.raise_on["http_route"] = read_module.KubernetesReadError(
            "connection refused")
        record = observer.inspect_detailed(RUN_ID, SOURCE_SHA)
        self._assert_unknown(record, "route could not be read")

    def test_every_resource_read_can_fail_closed(self):
        for resource in ("http_route", "service", "endpoint_slices", "pods",
                         "deployments"):
            with self.subTest(resource=resource):
                observer, client = observer_for()
                client.raise_on[resource] = read_module.KubernetesReadError("boom")
                record = observer.inspect_detailed(RUN_ID, SOURCE_SHA)
                self.assertEqual(record.observation.observed_status, OBSERVED_UNKNOWN)
                self.assertIsNone(record.observation.observed_percentage)

    def test_malformed_weights_are_never_normalised(self):
        for weight in ("5", True, None, 5.0, -5, [5]):
            with self.subTest(weight=weight):
                world = live_documents()
                world["route"]["spec"]["rules"][0]["backendRefs"][1]["weight"] = weight
                # Prove the fixture really carries the malformed value, so
                # "no percentage" cannot be an accident of a valid route.
                self.assertEqual(
                    world["route"]["spec"]["rules"][0]["backendRefs"][1]["weight"],
                    weight)
                if isinstance(weight, int) and not isinstance(weight, bool) and weight >= 0:
                    self.skipTest("not a malformed weight")
                record = observe(world)
                self.assertEqual(record.observation.observed_status, OBSERVED_UNKNOWN)
                self.assertIsNone(record.observation.observed_percentage)

    def test_a_string_weight_that_would_coerce_to_five_is_refused(self):
        world = live_documents()
        world["route"]["spec"]["rules"][0]["backendRefs"][1]["weight"] = "5"
        # The coercion a weaker implementation would perform is possible…
        self.assertEqual(int("5"), 5)
        # …and it is exactly what this adapter refuses to do.
        record = observe(world)
        self.assertEqual(record.observation.observed_status, OBSERVED_UNKNOWN)
        self.assertIsNone(record.observation.observed_percentage)
        self.assertEqual(record.configured_percentage, None)

    def test_a_zero_total_weight_has_no_share(self):
        self._assert_unknown(observe(live_documents(weights=(0, 0))),
                             "zero total weight")

    def test_a_non_integral_share_is_not_rounded(self):
        record = observe(live_documents(weights=(1, 2)))
        self._assert_unknown(record, "not an exact integer percentage")
        self.assertEqual(record.configured_fraction, (2, 3))
        # 2/3 is 66.666…%: a rounded 67 would be a fabricated observation.
        self.assertNotEqual(record.observation.observed_percentage, 67)

    def test_a_backend_ref_without_a_name(self):
        world = live_documents()
        world["route"]["spec"]["rules"][0]["backendRefs"][0]["name"] = ""
        self.assertEqual(
            world["route"]["spec"]["rules"][0]["backendRefs"][0]["name"], "")
        self._assert_unknown(observe(world), "no usable name")

    def test_a_single_backend_route_is_not_a_two_track_observation(self):
        world = live_documents()
        del world["route"]["spec"]["rules"][0]["backendRefs"][1]
        record = observe(world)
        self.assertEqual(record.observation.observed_status, OBSERVED_CONFLICT)
        self.assertIsNone(record.observation.observed_percentage)


class ConflictTests(unittest.TestCase):
    """Contradictory cluster truth is CONFLICT, never a quiet UNKNOWN."""

    def _assert_conflict(self, record, expected_text):
        self.assertEqual(record.observation.observed_status, OBSERVED_CONFLICT)
        self.assertIsNone(record.observation.observed_percentage)
        self.assertTrue(
            any(expected_text in text for _severity, text in record.findings),
            f"{expected_text!r} not in {record.findings}")

    def test_shared_backend_identity_is_a_conflict(self):
        world = live_documents()
        world["slices"]["ares-canary"]["endpoints"] = copy.deepcopy(
            world["slices"]["ares-stable"]["endpoints"])
        # Non-vacuous: the two Services really do resolve to the same pods.
        stable_uids = {endpoint["targetRef"]["uid"]
                       for endpoint in world["slices"]["ares-stable"]["endpoints"]}
        canary_uids = {endpoint["targetRef"]["uid"]
                       for endpoint in world["slices"]["ares-canary"]["endpoints"]}
        self.assertEqual(stable_uids, canary_uids)
        record = observe(world)
        self._assert_conflict(record, "same workload identity")
        self.assertIs(record.endpoints_disjoint, False)
        self.assertTrue(record.shared_endpoints)

    def test_both_services_resolving_into_one_deployment_is_a_conflict(self):
        world = live_documents()
        world["deployments"]["ares-canary"]["spec"]["selector"]["matchLabels"] = {
            "app": "ares-traffic", "track": "stable"}
        record = observe(world)
        # Two honest consequences of one contradiction: the stable pods are
        # now matched by two Deployments, or both tracks resolve into one.
        self.assertEqual(record.observation.observed_status, OBSERVED_CONFLICT)
        self.assertTrue(any("Deployment" in text for _severity, text in record.findings),
                        record.findings)

    def test_duplicate_backend_ref_names_are_a_conflict(self):
        world = live_documents()
        first = dict(world["route"]["spec"]["rules"][0]["backendRefs"][0])
        world["route"]["spec"]["rules"][0]["backendRefs"] = [dict(first), dict(first)]
        self.assertEqual(
            world["route"]["spec"]["rules"][0]["backendRefs"][0]["name"],
            world["route"]["spec"]["rules"][0]["backendRefs"][1]["name"])
        self._assert_conflict(observe(world), "duplicate backendRef names")

    def test_two_backends_claiming_the_same_track_are_a_conflict(self):
        world = live_documents()
        world["services"]["ares-canary"]["metadata"]["labels"]["track"] = "stable"
        self._assert_conflict(observe(world), "same 'stable' track")

    def test_a_backend_without_a_track_identity_is_a_conflict(self):
        world = live_documents()
        world["services"]["ares-stable"]["metadata"]["labels"].pop("track")
        self.assertNotIn("track", world["services"]["ares-stable"]["metadata"]["labels"])
        self._assert_conflict(observe(world), "track")

    def test_a_backend_from_another_topology_is_a_conflict(self):
        world = live_documents()
        world["services"]["ares-canary"]["metadata"]["labels"]["app"] = "something-else"
        self._assert_conflict(observe(world), "not part of the observed topology")

    def test_an_endpoint_the_service_does_not_select_is_a_conflict(self):
        world = live_documents()
        world["pods"]["ares-stable-6bd676c8f9-st0"]["metadata"]["labels"]["app"] = "other"
        record = observe(world)
        self._assert_conflict(record, "is not selected by that Service's selector")

    def test_an_endpoint_carrying_the_wrong_track_is_a_conflict(self):
        world = live_documents()
        pod = world["pods"]["ares-stable-6bd676c8f9-st0"]
        pod["metadata"]["labels"]["track"] = "canary"
        record = observe(world)
        # Either the selector or the track rule must catch this; the label
        # the pod carries contradicts the track it is served under.
        self.assertEqual(record.observation.observed_status, OBSERVED_CONFLICT)
        self.assertIsNone(record.observation.observed_percentage)

    def test_an_ambiguous_workload_identity_is_a_conflict(self):
        world = live_documents()
        world["deployments"]["third"] = copy.deepcopy(world["deployments"]["ares-stable"])
        world["deployments"]["third"]["metadata"]["name"] = "third"
        record = observe(world)
        self._assert_conflict(record, "matched by 2 Deployments")

    def test_a_controller_contradiction_is_a_conflict(self):
        world = live_documents()
        for condition in world["route"]["status"]["parents"][0]["conditions"]:
            if condition["type"] == "ResolvedRefs":
                condition["status"] = "False"
        record = observe(world)
        self._assert_conflict(record, "controller and observed configuration disagree")

    def test_more_than_two_backends_is_a_conflict(self):
        world = live_documents()
        refs = world["route"]["spec"]["rules"][0]["backendRefs"]
        refs.append({"name": "ares-third", "port": 80, "weight": 1})
        self._assert_conflict(observe(world), "exactly one stable and one canary")

    def test_two_weighted_rules_are_a_conflict(self):
        world = live_documents()
        rule = world["route"]["spec"]["rules"][0]
        world["route"]["spec"]["rules"].append(copy.deepcopy(rule))
        self.assertEqual(len(world["route"]["spec"]["rules"]), 2)
        self._assert_conflict(observe(world), "single weighted rule")

    def test_a_conflict_is_never_downgraded_to_unknown(self):
        world = live_documents()
        # A contradictory *and* unavailable topology at once.
        world["services"]["ares-canary"]["metadata"]["labels"]["track"] = "stable"
        del world["slices"]["ares-stable"]
        record = observe(world)
        self.assertEqual(record.observation.observed_status, OBSERVED_CONFLICT)


class BindingTests(unittest.TestCase):
    """§14: no fabricated deployment/source identity."""

    def test_a_matching_request_is_attested_against_configuration(self):
        record = observe()
        self.assertEqual(record.binding, observer_module.BINDING_CONFIGURED)
        self.assertTrue(record.binding_established)
        self.assertEqual(record.observation.deployment_run_id, RUN_ID)
        self.assertEqual(record.observation.source_sha, SOURCE_SHA)

    def test_a_different_source_sha_is_a_conflict(self):
        observer, _ = observer_for()
        record = observer.inspect_detailed(RUN_ID, "b" * 40)
        self.assertEqual(record.observation.observed_status, OBSERVED_CONFLICT)
        self.assertEqual(record.binding, observer_module.BINDING_MISMATCH)
        self.assertIsNone(record.observation.source_sha)

    def test_a_different_deployment_run_is_a_conflict(self):
        observer, _ = observer_for()
        record = observer.inspect_detailed("another-run", SOURCE_SHA)
        self.assertEqual(record.observation.observed_status, OBSERVED_CONFLICT)
        self.assertIn("deployment_run_id",
                      " ".join(text for _s, text in record.findings))
        self.assertIsNone(record.observation.deployment_run_id)

    def test_an_unbound_observer_reports_unknown_without_echoing(self):
        world = live_documents()
        client = FakeReadClient(world)
        observer = observer_module.KubernetesTrafficObserver(
            client, now_factory=lambda: NOW)
        record = observer.inspect_detailed(RUN_ID, SOURCE_SHA)
        self.assertEqual(record.observation.observed_status, OBSERVED_UNKNOWN)
        self.assertEqual(record.binding, observer_module.BINDING_UNBOUND)
        self.assertIsNone(record.observation.deployment_run_id)
        self.assertIsNone(record.observation.source_sha)
        self.assertTrue(any("no configured deployment/source binding" in text
                            for _severity, text in record.findings))

    def test_a_malformed_binding_request_fails_closed(self):
        observer, _ = observer_for()
        for run_id, sha in ((None, SOURCE_SHA), ("", SOURCE_SHA), (RUN_ID, "short"),
                            (RUN_ID, SOURCE_SHA.upper())):
            with self.subTest(run_id=run_id, sha=sha):
                record = observer.inspect_detailed(run_id, sha)
                self.assertEqual(record.observation.observed_status, OBSERVED_UNKNOWN)
                self.assertIsNone(record.observation.observed_percentage)

    def test_the_configured_binding_is_not_derived_from_the_cluster(self):
        # The live topology carries no release identity at all: if the
        # adapter echoed the request, an observation with no configured
        # binding would still report the requested values. It does not.
        world = live_documents()
        self.assertNotIn("DEVOPS_SOURCE_SHA", json.dumps(world))
        observer = observer_module.KubernetesTrafficObserver(
            FakeReadClient(world), now_factory=lambda: NOW)
        record = observer.inspect_detailed(RUN_ID, SOURCE_SHA)
        self.assertIsNone(record.observation.deployment_run_id)

    def test_an_identity_carrier_is_recorded_as_evidence(self):
        world = live_documents()
        for track in ("stable", "canary"):
            deployment = world["deployments"][f"ares-{track}"]
            container = deployment["spec"]["template"]["spec"]["containers"][0]
            container["env"] += [
                {"name": observer_module.DEPLOYMENT_ID_ENV, "value": RUN_ID},
                {"name": observer_module.SOURCE_SHA_ENV, "value": SOURCE_SHA},
            ]
        record = observe(world)
        self.assertEqual(record.targets["canary"].identity_carrier,
                         {"DEVOPS_DEPLOYMENT_ID": RUN_ID,
                          "DEVOPS_SOURCE_SHA": SOURCE_SHA})
        # Recorded, and documented as not establishing the binding by itself.
        payload = record.to_dict()
        self.assertEqual(payload["observed"]["canary"]["identity_carrier"],
                         {"DEVOPS_DEPLOYMENT_ID": RUN_ID,
                          "DEVOPS_SOURCE_SHA": SOURCE_SHA})
        self.assertEqual(payload["binding"]["basis"], observer_module.BINDING_CONFIGURED)

    def test_the_carrier_constants_match_the_deployment_service_contract(self):
        """The duplicated literals must not drift from the real carrier."""
        paths = sorted((PLATFORM_DIR / "deployment_service").rglob(
            "release_identity_injection.py"))
        self.assertTrue(paths, "the Phase 6.5.2 carrier module is missing")
        source = paths[0].read_text(encoding="utf-8")
        self.assertIn('DEPLOYMENT_ID_ENV = "DEVOPS_DEPLOYMENT_ID"', source)
        self.assertIn('SOURCE_SHA_ENV = "DEVOPS_SOURCE_SHA"', source)
        self.assertEqual(observer_module.DEPLOYMENT_ID_ENV, "DEVOPS_DEPLOYMENT_ID")
        self.assertEqual(observer_module.SOURCE_SHA_ENV, "DEVOPS_SOURCE_SHA")


# ---------------------------------------------------------- port contract


class PortContractTests(unittest.TestCase):
    """The adapter is a read-only TrafficControllerPort implementation."""

    def test_the_provider_exposes_inspect_and_plan_and_nothing_mutating(self):
        provider = observer_module.KubernetesTrafficObserver(FakeReadClient())
        self.assertTrue(callable(provider.inspect))
        self.assertTrue(callable(provider.plan))
        for member in FORBIDDEN_PROVIDER_MEMBERS:
            self.assertFalse(hasattr(provider, member),
                             f"{member} must not exist on a read-only observer")

    def test_plan_is_a_pure_renderer_with_no_cluster_access(self):
        world = live_documents()
        client = FakeReadClient(world)

        class ExplodingClient:
            def __getattr__(self, item):
                raise AssertionError("plan() must not read the cluster")

        observer = observer_module.KubernetesTrafficObserver(ExplodingClient())
        intent = FakeIntent()
        plan = observer.plan(intent)
        self.assertTrue(plan["read_only"])
        self.assertFalse(plan["mutates"])
        self.assertEqual(plan["current_percentage"], 5)
        self.assertEqual(plan["requested_percentage"], 25)
        self.assertEqual(client.calls, [])
        source = _method_source(OBSERVER, "plan")
        for token in ("self._client", "subprocess", "kubectl"):
            self.assertNotIn(token, source,
                             "plan() must not touch the cluster at all")

    def test_inspect_and_inspect_detailed_agree(self):
        observer, _ = observer_for()
        self.assertEqual(observer.inspect(RUN_ID, SOURCE_SHA),
                         observer.inspect_detailed(RUN_ID, SOURCE_SHA).observation)

    def test_the_observation_feeds_the_existing_planning_service(self):
        """RolloutPlanService.inspect → observer → READY (Phase 6.7.1 path)."""
        observer, _ = observer_for()
        service = RolloutPlanService(_StageRepository(), controller=observer,
                                     now_factory=lambda: NOW)
        plan = service.plan(RUN_ID, "gate-eval-1", 25, SOURCE_SHA)
        self.assertEqual(plan["preflight_status"], PREFLIGHT_READY)
        self.assertEqual(plan["observed_status"], "DIFFERS_FROM_DESIRED")
        self.assertEqual(plan["observed_traffic"]["observed_percentage"], 5)
        self.assertEqual(plan["target_identity"],
                         {"stable": "ares-traffic/service/ares-stable",
                          "canary": "ares-traffic/service/ares-canary",
                          "proven": True})
        self.assertTrue(plan["provider_plan"]["read_only"])
        self.assertFalse(plan["provider_plan"]["mutates"])

    def test_the_planning_service_stays_inconclusive_when_observation_fails(self):
        observer = observer_module.KubernetesTrafficObserver(
            FakeReadClient(live_documents()), expected_deployment_run_id=RUN_ID,
            expected_source_sha=SOURCE_SHA, now_factory=lambda: NOW)
        service = RolloutPlanService(_StageRepository(), controller=observer,
                                     now_factory=lambda: NOW)
        plan = service.plan(RUN_ID, "gate-eval-1", 25, SOURCE_SHA)
        self.assertEqual(plan["preflight_status"], "READY")
        broken = observer_module.KubernetesTrafficObserver(
            FakeReadClient({**live_documents(), "route": None}),
            expected_deployment_run_id=RUN_ID, expected_source_sha=SOURCE_SHA,
            now_factory=lambda: NOW)
        plan = RolloutPlanService(_StageRepository(), controller=broken,
                                  now_factory=lambda: NOW).plan(
            RUN_ID, "gate-eval-1", 25, SOURCE_SHA)
        self.assertEqual(plan["preflight_status"], "INCONCLUSIVE")
        self.assertIsNone(plan["target_identity"]["stable"])


class FakeIntent:
    intent_id = "ti_test"
    deployment_run_id = RUN_ID
    source_sha = SOURCE_SHA
    stable_target = "ares-traffic/service/ares-stable"
    canary_target = "ares-traffic/service/ares-canary"
    current_percentage = 5
    requested_percentage = 25


class _StageRepository:
    """Minimal durable state for the planning-service integration test."""

    def get_progressive_rollout_stage(self, deployment_run_id):
        return {"stage_state_id": "stage-1", "deployment_run_id": RUN_ID,
                "source_sha": SOURCE_SHA, "repository": "gm-prog/Autonomous-Devops-Engineer",
                "state": "ACTIVE", "current_percentage": 5, "previous_percentage": 0}

    def get_progressive_release_gate_evaluation(self, evaluation_id):
        return {"evaluation_id": "gate-eval-1", "deployment_run_id": RUN_ID,
                "source_sha": SOURCE_SHA, "target_percentage": 25,
                "gate_decision": "PROMOTE", "health_decision": "HEALTHY",
                "policy_version": GATE_POLICY_VERSION,
                "observed_at": NOW, "expires_at": NOW + timedelta(hours=1)}


# ------------------------------------------------------------ read-only


def _executable_source(path: pathlib.Path) -> str:
    """Source without docstrings/comments — a guard must not match prose."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(
                body[0].value, ast.Constant
            ) and isinstance(body[0].value.value, str):
                node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


def _method_source(path: pathlib.Path, name: str) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.unparse(node)
    raise AssertionError(f"{name} not found in {path}")


class ReadOnlyGuardTests(unittest.TestCase):
    """Static proof that nothing in the package can write to Kubernetes."""

    def _string_constants_outside_deny_lists(self, path: pathlib.Path):
        """Every string literal that is not part of a policy deny-list.

        The read policy must *name* the verbs it refuses (that is the
        point of the deny-list); what must never happen is a write verb
        appearing anywhere else, in the collection of strings this
        function returns.
        """
        tree = ast.parse(path.read_text(encoding="utf-8"))
        allowed = set()
        deny_list_names = {"FORBIDDEN_SUBCOMMANDS", "READ_VERBS"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets = [target.id for target in node.targets
                           if isinstance(target, ast.Name)]
                if deny_list_names & set(targets):
                    for literal in ast.walk(node.value):
                        if isinstance(literal, ast.Constant):
                            allowed.add(literal.value)
        literals = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value not in allowed:
                    literals.append(node.value)
        return literals

    def test_no_mutating_subcommand_appears_outside_the_deny_list(self):
        for path in (READ_CLIENT, OBSERVER):
            literals = self._string_constants_outside_deny_lists(path)
            for verb in FORBIDDEN_SUBCOMMANDS:
                self.assertNotIn(verb, literals,
                                 f"{path.name} uses the {verb!r} subcommand")

    def test_the_deny_list_itself_is_present_and_complete(self):
        self.assertTrue(
            read_module.FORBIDDEN_SUBCOMMANDS.issuperset(FORBIDDEN_SUBCOMMANDS),
            "the read policy must refuse every mutating subcommand")

    def test_no_patch_apply_or_delete_call_site_exists(self):
        offenders = []
        for path in (READ_CLIENT, OBSERVER):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = ast.unparse(node.func)
                    # e.g. `kubectl ... patch`-style argv construction or a
                    # Kubernetes client's write method.
                    rendered = ast.unparse(node)
                    if any(f'"{verb}"' in rendered and "get" not in rendered
                           for verb in ("patch", "apply", "delete", "replace")):
                        offenders.append(f"{path.name}: {name}")
        self.assertEqual(offenders, [],
                         "the observation package must contain no write call site")

    def test_the_read_client_is_registered_in_the_execution_boundary_audit(self):
        """The incident service audits every production file that spawns a
        process: a new one must be recorded in the table with its reason,
        which is exactly what CI's incident-service job enforces.
        """
        import importlib
        module = importlib.import_module(
            "incident_service.application.commands.test_execution_authority")
        allowed = module.RepositoryExecutionBoundaryAuditTests.ALLOWED["subprocess."]
        self.assertIn(
            "incident_service/infrastructure/traffic/kubernetes_read_client.py",
            allowed,
            "the new process-spawning module must be registered in the "
            "execution-boundary audit table")
        spawning = {path.name for path in TRAFFIC_DIR.rglob("*.py")
                    if "subprocess." in path.read_text(encoding="utf-8")}
        self.assertEqual(spawning, {"kubernetes_read_client.py"},
                         "only the read client may spawn a process")

    def test_the_read_client_spawns_only_built_argvs(self):
        source = _executable_source(READ_CLIENT)
        self.assertIn("build_read_argv", source)
        # The single process spawn is the injected runner; no shell, no
        # arbitrary command string.
        self.assertNotIn("shell=True", source)
        self.assertNotIn("os.system", source)
        self.assertNotIn("Popen", source)
        self.assertNotIn("--raw", source)

    def test_the_observer_never_imports_the_mutation_boundary(self):
        source = OBSERVER.read_text(encoding="utf-8")
        self.assertNotIn("traffic_mutation_boundary", source)
        self.assertNotIn("TrafficMutationPort", source)
        self.assertNotIn("TrafficMutationRequest", source)
        self.assertNotIn("subprocess", _executable_source(OBSERVER))

    def test_the_provider_has_no_write_capability_by_construction(self):
        provider = observer_module.KubernetesTrafficObserver(FakeReadClient())
        self.assertEqual(
            sorted(name for name in dir(provider) if not name.startswith("_")),
            ["inspect", "inspect_detailed", "observation_source", "plan",
             "provider_name"])
        for member in FORBIDDEN_PROVIDER_MEMBERS:
            self.assertFalse(hasattr(observer_module.KubernetesTrafficObserver, member))


# --------------------------------------------------------------- evidence


class EvidenceShapeTests(unittest.TestCase):
    """The record keeps configured / controller / observed apart."""

    def test_evidence_separates_the_three_truth_classes(self):
        payload = observe().to_dict()
        self.assertEqual(sorted(payload), [
            "binding", "client", "configured", "controller", "detail", "findings",
            "observation_source", "observation_timestamp", "observed", "provider",
            "status"])
        self.assertEqual(payload["configured"]["weights"],
                         {"stable": 95, "canary": 5})
        self.assertEqual(payload["observed"]["canary"]["ready_endpoints"],
                         ["ares-canary-6bd676c8f9-ca0", "ares-canary-6bd676c8f9-ca1"])
        self.assertEqual(payload["observed"]["stable"]["identity"],
                         "ares-traffic/service/ares-stable")
        self.assertTrue(payload["observed"]["endpoints_disjoint"])

    def test_evidence_is_json_serialisable_and_bounded(self):
        payload = observe().to_dict()
        encoded = json.dumps(payload)
        self.assertLess(len(encoded), 20000)
        self.assertLessEqual(len(payload["detail"]), 400)

    def test_no_secret_material_reaches_the_evidence(self):
        observer, client = observer_for()
        client.raise_on["http_route"] = read_module.KubernetesReadError(
            "auth failed Bearer super-secret-token /home/runner/.kube/config")
        payload = observer.inspect_detailed(RUN_ID, SOURCE_SHA).to_dict()
        encoded = json.dumps(payload)
        self.assertNotIn("super-secret-token", encoded)
        self.assertNotIn("/home/runner", encoded)
        self.assertIn("route could not be read", encoded)
        # The reason is still visible; the material is not.
        self.assertIn("<redacted>", encoded)

    def test_the_checks_block_mirrors_the_facts(self):
        checks = {row["check"]: row for row in observe().checks()}
        self.assertEqual(checks["observation:status-known"]["status"], "PASS")
        self.assertEqual(checks["observation:endpoints-disjoint"]["status"], "PASS")
        self.assertEqual(checks["observation:binding-established"]["status"], "PASS")
        failing = {row["check"]: row for row in
                   observe(live_documents(), expected_source_sha="c" * 40).checks()}
        self.assertEqual(failing["observation:status-known"]["status"], "FAIL")
        self.assertEqual(failing["observation:no-fabrication"]["status"], "PASS")

    def test_unavailable_observations_report_no_targets(self):
        payload = observe({**live_documents(), "route": None}).to_dict()
        self.assertIsNone(payload["observed"]["percentage"])
        self.assertIsNone(payload["observed"]["stable"])
        self.assertIsNone(payload["observed"]["canary"])


class NonVacuousControlTests(unittest.TestCase):
    """Each safety rule is paired with a control that shows it bites."""

    def test_the_shared_identity_fixture_really_shares_and_a_permissive_rule_fails(self):
        world = live_documents()
        world["slices"]["ares-canary"]["endpoints"] = copy.deepcopy(
            world["slices"]["ares-stable"]["endpoints"])
        stable_uids = {endpoint["targetRef"]["uid"]
                       for endpoint in world["slices"]["ares-stable"]["endpoints"]}
        canary_uids = {endpoint["targetRef"]["uid"]
                       for endpoint in world["slices"]["ares-canary"]["endpoints"]}
        self.assertTrue(stable_uids & canary_uids)

        def permissive_rule(stable: set, canary: set) -> bool:
            """What a weaker adapter would do: only require non-emptiness."""
            return bool(stable) and bool(canary)

        self.assertTrue(permissive_rule(stable_uids, canary_uids),
                        "the control must show the weaker rule wrongly accepts")
        self.assertEqual(observe(world).observation.observed_status, OBSERVED_CONFLICT)

    def test_the_malformed_weight_fixture_really_needs_the_type_check(self):
        raw = "5"
        self.assertEqual(int(raw), 5)  # coercion is possible and refused
        world = live_documents()
        world["route"]["spec"]["rules"][0]["backendRefs"][1]["weight"] = raw
        self.assertIsInstance(
            world["route"]["spec"]["rules"][0]["backendRefs"][1]["weight"], str)
        record = observe(world)
        self.assertEqual(record.observation.observed_status, OBSERVED_UNKNOWN)
        self.assertIsNone(record.observation.observed_percentage)

    def test_the_unavailable_fixture_is_otherwise_healthy(self):
        healthy = observe()
        self.assertEqual(healthy.observation.observed_status, OBSERVED_KNOWN)
        broken = observe({**live_documents(), "route": None})
        self.assertEqual(broken.observation.observed_status, OBSERVED_UNKNOWN)
        # Same weights, same services, same endpoints: only the read failed.
        self.assertIsNone(broken.observation.observed_percentage)

    def test_every_failure_case_differs_from_the_healthy_baseline(self):
        baseline = observe()
        self.assertEqual(baseline.observation.observed_status, OBSERVED_KNOWN)
        world = live_documents()
        world["slices"]["ares-canary"]["endpoints"] = copy.deepcopy(
            world["slices"]["ares-stable"]["endpoints"])
        self.assertNotEqual(observe(world).observation.observed_status,
                            baseline.observation.observed_status)


class CiWorkflowTests(unittest.TestCase):
    """The dedicated job exists and the Phase 8.7-B.0 job is not weakened."""

    @classmethod
    def setUpClass(cls):
        import yaml
        cls.workflow = yaml.safe_load(
            (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
        cls.jobs = cls.workflow["jobs"]

    def _script(self, key: str) -> str:
        job = self.jobs[key]
        return "\n".join(step.get("run", "") for step in job["steps"])

    def test_both_phase_jobs_exist_and_neither_was_removed(self):
        for key, name in (("kubernetes-traffic-topology-e2e",
                           "Phase 8.7-B.0 weighted traffic topology E2E"),
                          ("kubernetes-traffic-observation-e2e",
                           "Phase 8.7-B.1 traffic observation E2E")):
            with self.subTest(job=key):
                self.assertIn(key, self.jobs)
                self.assertEqual(self.jobs[key]["name"], name)
                self.assertEqual(self.jobs[key]["defaults"]["run"]
                                 ["working-directory"], "devops-ai-platform")

    def test_the_b1_job_runs_the_observation_driver_without_weakening(self):
        script = self._script("kubernetes-traffic-observation-e2e")
        for token in ("e2e/traffic_observation_kind_e2e.py",
                      '--expected-commit "$GITHUB_SHA"',
                      '--deployment-run-id "$GITHUB_RUN_ID"',
                      "--destroy-cluster",
                      "--evidence traffic-observation-e2e.json",
                      "ares-observation-e2e"):
            self.assertIn(token, script, f"the 8.7-B.1 job is missing {token}")
        # The pinned stack is installed from the committed digests, not a tag.
        self.assertIn("e2e/pinned-traffic-topology.txt", script)
        self.assertIn("sha256sum -c -", script)
        self.assertNotIn("latest", script.replace("latest)", ""))

    def test_the_b1_job_tears_down_and_uploads_its_evidence_always(self):
        steps = self.jobs["kubernetes-traffic-observation-e2e"]["steps"]
        teardown = [step for step in steps
                    if "kind delete cluster" in (step.get("run") or "")]
        self.assertTrue(teardown)
        self.assertEqual(teardown[0].get("if"), "always()")
        uploads = [step for step in steps
                   if str(step.get("uses", "")).startswith("actions/upload-artifact")]
        self.assertTrue(uploads)
        self.assertEqual(uploads[0].get("if"), "always()")
        self.assertIn("traffic-observation-e2e.json", uploads[0]["with"]["path"])

    def test_the_b0_job_still_runs_its_own_driver(self):
        script = self._script("kubernetes-traffic-topology-e2e")
        for token in ("e2e/traffic_topology_kind_e2e.py",
                      '--expected-commit "$GITHUB_SHA"',
                      "--evidence traffic-topology-e2e.json"):
            self.assertIn(token, script)
        self.assertNotIn("traffic_observation_kind_e2e.py", script)


class LiveE2EDriverTests(unittest.TestCase):
    """The live Kind driver exists, observes through the real provider and
    is itself read-only towards the cluster it inspects."""

    def test_the_driver_exists_and_drives_the_real_provider(self):
        self.assertTrue(DRIVER.exists(), "the live observation E2E driver is missing")
        source = DRIVER.read_text(encoding="utf-8")
        self.assertIn("KubernetesTrafficObserver", source)
        self.assertIn("KubectlReadClient", source)
        for token in ("read-only", "--destroy-cluster"):
            self.assertIn(token, source)

    def test_the_driver_never_mutates_the_route_through_the_provider(self):
        """Proof-state patching goes through B.0's kubectl helper, never
        through the application provider: the provider has no write API."""
        source = _executable_source(DRIVER)
        self.assertIn("topology_driver.patch_route_weights", source)
        self.assertIn("patch_backend_ref_name", source)
        for forbidden in ("observer.patch", "observer.apply", "observer.rollback",
                          "provider.patch", "provider.apply"):
            self.assertNotIn(forbidden, source)
        # The only observer method the driver calls is the read-only one.
        self.assertIn("KubernetesTrafficObserver(", source)
        self.assertIn("inspect_detailed", source)
        self.assertNotIn("TrafficMutation", source)

    def test_the_driver_records_the_live_states_the_negative_and_binding(self):
        """The live states, the two negatives and both binding states, each
        recorded as a check through the shared ``observation:`` prefix."""
        source = DRIVER.read_text(encoding="utf-8")
        for token in ("committed-95-5", "all-stable-100-0", "all-canary-0-100",
                      "negative-missing-backend", "negative-zero-weights",
                      "restored-95-5", "binding-mismatch", "unbound",
                      "live-traffic-agrees", "states-distinguishable",
                      "read-only:no-cluster-write"):
            self.assertIn(token, source, f"missing live state {token}")
        self.assertIn('record(f"observation:{name}', source)

    def test_the_documentation_exists_with_the_required_sections(self):
        self.assertTrue(DOC.exists(), "docs/PHASE-8.7-B.1-... is missing")
        text = DOC.read_text(encoding="utf-8")
        for heading in ("Objective", "Architecture", "Read-only", "percentage",
                        "identity", "binding", "UNKNOWN", "CONFLICT",
                        "configured", "production", "limitations",
                        "does not mutate"):
            self.assertIn(heading, text, f"documentation is missing {heading!r}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
