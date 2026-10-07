"""Driver-stage control flow, exercised against a stub cluster.

Phase 8.7-B.1's E2E driver cannot run in this test process (no cluster,
no container runtime), and that blind spot is exactly where Phase 8.7-B.0
lost its first two CI runs. So this module runs the *real* driver —
``e2e/traffic_observation_kind_e2e.py`` — with only the process layer
faked: a stub cluster answers every ``kubectl`` invocation, keeps the
route's weights in memory, bumps its generation and recomputes
``ResolvedRefs`` the way a controller would.

Everything above that layer is real code:

* the Phase 8.7-B.0 helpers the driver reuses (fixture render/apply,
  readiness gates, weight patching, ``read_route``/``service_endpoints``
  reads, the sampler contract);
* the application's own read client, including its argv construction,
  validation, parsing and bounds — the fake replaces the process, not the
  client;
* the application's observer, which therefore sees the same stub cluster
  through its real code path.

Two hostile controls prove the checks bite: a caching observer (answers
with the first state forever) and an unreachable cluster must both turn
the run red. A driver that cannot fail is not evidence.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import Any, Dict, List, Optional, Sequence, Tuple
from unittest import mock

PLATFORM_DIR = pathlib.Path(__file__).resolve().parent.parent
REPO_ROOT = PLATFORM_DIR.parent
sys.path.insert(0, str(PLATFORM_DIR))

from e2e import traffic_observation_kind_e2e as adapter_driver  # noqa: E402
from e2e import traffic_topology_kind_e2e as topology_driver  # noqa: E402
from incident_service.infrastructure.traffic import (  # noqa: E402
    kubernetes_read_client,
)

#: The genuine client, captured before any patching: the harness replaces
#: the *process* it spawns, never the client itself.
REAL_CLIENT = kubernetes_read_client.KubectlReadClient

HEAD = subprocess.run(["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
                      capture_output=True, text=True).stdout.strip()
REAL_RUN = subprocess.run


class StubCluster:
    """A tiny Kubernetes API server, spoken over ``kubectl`` argv."""

    def __init__(self, world: Optional[Dict[str, Any]] = None) -> None:
        self.world = world if world is not None else live_world()
        self.calls: List[Tuple[str, ...]] = []
        self.service_failures: Dict[str, str] = {}
        self.generation = 4
        self.resource_version = 1000

    # ------------------------------------------------------------- state
    @property
    def route(self) -> Dict[str, Any]:
        return self.world["route"]

    def refs(self) -> List[Dict[str, Any]]:
        return ((self.route.get("spec") or {}).get("rules") or [{}])[0].get("backendRefs") or []

    def touch(self) -> None:
        """A write bumps generation/resourceVersion and re-resolves refs."""
        self.generation += 1
        self.resource_version += 1
        self.route["metadata"]["generation"] = self.generation
        self.route["metadata"]["resourceVersion"] = str(self.resource_version)
        resolved = all(ref.get("name") in self.world["services"] for ref in self.refs())
        self.route["status"] = {"parents": [{
            "parentRef": {"name": "ares-gateway", "sectionName": "http"},
            "conditions": [
                {"type": "Accepted", "status": "True", "reason": "Accepted",
                 "observedGeneration": self.generation},
                {"type": "ResolvedRefs", "status": "True" if resolved else "False",
                 "reason": "ResolvedRefs" if resolved else "BackendNotFound",
                 "observedGeneration": self.generation},
            ]}]}

    def patch_route(self, payload: str) -> None:
        for operation in json.loads(payload):
            path = operation["path"]
            parts = [part for part in path.strip("/").split("/")]
            cursor: Any = self.route
            for part in parts[:-1]:
                cursor = cursor[int(part)] if isinstance(cursor, list) else cursor[part]
            last = parts[-1]
            if operation["op"] in ("replace", "add"):
                if isinstance(cursor, list):
                    cursor[int(last)] = operation["value"]
                else:
                    cursor[last] = operation["value"]
            else:  # pragma: no cover - the driver only replaces
                raise AssertionError(f"unsupported patch op {operation['op']}")
        self.touch()

    def set_weights(self, weights: Dict[str, int]) -> None:
        for ref in self.refs():
            for track, service in (("stable", "ares-stable"), ("canary", "ares-canary")):
                if ref.get("name") == service and track in weights:
                    ref["weight"] = weights[track]

    # --------------------------------------------------------------- argv
    def __call__(self, argv: Sequence[str], timeout: int = 300, **kwargs: Any):
        """Serve one process: the B.0 driver's ``sh`` and the read client's
        injected runner both call this, so both see one cluster."""
        argv = [str(item) for item in argv]
        self.calls.append(tuple(argv))
        if argv[0] == "git":
            return REAL_RUN(argv, capture_output=True, text=True, timeout=timeout)
        if argv[0] == "docker":
            return proc(argv, self._docker(argv), "", 0)
        if argv[0] == "kind":
            return proc(argv, "", "", 0)
        if argv[0] == "kubectl":
            return self._kubectl(argv)
        return proc(argv, "", f"unsupported command {argv[0]}", 1)

    def _docker(self, argv: Sequence[str]) -> str:
        if "inspect" in argv and "{{.State.Running}}" in argv:
            return "true\n"
        if "image" in argv and "inspect" in argv:
            digest = hashlib.sha256(str(argv[-1]).encode()).hexdigest()
            return f"sha256:{digest}\n"
        return ""

    def _kubectl(self, argv: Sequence[str]) -> subprocess.CompletedProcess:
        namespace = "default"
        selector: Optional[str] = None
        raw: Optional[str] = None
        patch_payload: Optional[str] = None
        positional: List[str] = []
        tokens = argv[1:]
        if tokens[:1] == ["--context"]:
            tokens = tokens[2:]
        position = 0
        while position < len(tokens):
            token = tokens[position]
            if token in ("-n", "--namespace"):
                namespace = tokens[position + 1]
                position += 2
            elif token == "-l":
                selector = tokens[position + 1]
                position += 2
            elif token.startswith("--raw="):
                raw = token.split("=", 1)[1]
                position += 1
            elif token in ("-o", "--output"):
                position += 2
            elif token.startswith("--request-timeout") or token.startswith("--tail"):
                position += 1
            elif token == "--context":
                position += 2
            elif token in ("--type=json", "--wait=true", "--ignore-not-found=true", "-A"):
                position += 1
            elif token in ("-p", "--patch"):
                patch_payload = tokens[position + 1]
                position += 2
            elif token in ("-f", "--filename"):
                position += 2
            else:
                positional.append(token)
                position += 1

        if raw is not None:
            if raw == "/version":
                return proc(argv, json.dumps({"major": "1", "minor": "31",
                                              "gitVersion": "v1.31.4"}), "", 0)
            return proc(argv, "{}", "", 0)
        if not positional:
            return proc(argv, "", "no verb", 1)
        verb = positional[0]
        resource = positional[1] if len(positional) > 1 else ""
        name = positional[2] if len(positional) > 2 else None

        if verb == "get":
            return self._get(argv, namespace, resource, name, selector)
        if verb == "patch":
            if resource != "httproute" or patch_payload is None:
                return proc(argv, "", f"unsupported patch {positional}", 1)
            self.patch_route(patch_payload)
            return proc(argv, json.dumps(self.route), "", 0)
        if verb == "apply":
            return proc(argv, f"{resource or 'object'}/applied created", "", 0)
        if verb in ("delete", "logs"):
            return proc(argv, "", "", 0)
        return proc(argv, "", f"unsupported verb {verb}", 1)

    def _get(self, argv: Sequence[str], namespace: str, resource: str,
             name: Optional[str], selector: Optional[str]):
        if resource == "httproute":
            if name is not None and name != self.route["metadata"]["name"]:
                return proc(argv, "", f'Error from server (NotFound): httproutes '
                                      f'"{name}" not found', 1)
            return proc(argv, json.dumps(copy.deepcopy(self.route)), "", 0)
        if resource in ("service", "services"):
            if name is None:
                return proc(argv, json.dumps({"items": list(self.world["services"].values())}),
                            "", 0)
            if name in self.service_failures:
                return proc(argv, "", f"Error from server: {self.service_failures[name]}", 1)
            service = self.world["services"].get(name)
            if service is None:
                return proc(argv, "", f'Error from server (NotFound): services "{name}" '
                                      f'not found', 1)
            return proc(argv, json.dumps(copy.deepcopy(service)), "", 0)
        if resource == "endpointslice":
            key = None
            if selector and "=" in selector:
                key = selector.split("=", 1)[1]
            if key is None:
                return proc(argv, json.dumps({"items": list(self.world["slices"].values())}),
                            "", 0)
            sliced = [self.world["slices"][key]] if key in self.world["slices"] else []
            return proc(argv, json.dumps({"items": copy.deepcopy(sliced)}), "", 0)
        if resource in ("pods", "pod"):
            return proc(argv, json.dumps({"items": copy.deepcopy(
                list(self.world["pods"].values()))}), "", 0)
        if resource in ("deployments", "deployment"):
            if name is not None:
                deployment = self.world["deployments"].get(name)
                if deployment is None:
                    return proc(argv, "", f'Error from server (NotFound): deployments '
                                          f'"{name}" not found', 1)
                return proc(argv, json.dumps(copy.deepcopy(deployment)), "", 0)
            return proc(argv, json.dumps({"items": copy.deepcopy(
                list(self.world["deployments"].values()))}), "", 0)
        if resource == "gatewayclass":
            return proc(argv, json.dumps({}), "", 0)
        if resource == "gateway":
            return proc(argv, json.dumps({}), "", 0)
        return proc(argv, "", f"unsupported resource {resource}", 1)


def proc(argv, stdout: str, stderr: str, rc: int) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(list(argv), rc, stdout, stderr)


def live_world(weights: Tuple[int, int] = (95, 5)) -> Dict[str, Any]:
    """Live-shaped documents, as the API server would return them.

    Built from the *committed* topology's labels so the observer's own
    rules (app label, track label, selector agreement) are what decides
    whether the fixture is observable at all.
    """
    route = {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": {"name": "ares-route", "namespace": "ares-traffic",
                     "generation": 4, "resourceVersion": "1000", "uid": "route-uid"},
        "spec": {"parentRefs": [{"name": "ares-gateway", "sectionName": "http"}],
                 "rules": [{
                     "matches": [{"path": {"type": "PathPrefix", "value": "/"}}],
                     "backendRefs": [
                         {"name": "ares-stable", "port": 8080, "weight": weights[0]},
                         {"name": "ares-canary", "port": 8080, "weight": weights[1]},
                     ]}]},
        "status": {"parents": [{
            "parentRef": {"name": "ares-gateway", "sectionName": "http"},
            "conditions": [
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
                     "ports": [{"name": "http", "port": 8080, "targetPort": "http"}]},
        }
        endpoints = []
        for index in range(2):
            pod = f"{name}-6bd676c8f9-{track[:2]}{index}"
            octet = index + 4 if track == "stable" else index + 8
            endpoints.append({
                "addresses": [f"10.244.1.{octet}"],
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
                         "labels": {"kubernetes.io/service-name": name}},
            "endpoints": endpoints,
        }
        deployments[name] = {
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": name, "namespace": "ares-traffic",
                         "uid": f"uid-deployment-{track}",
                         "labels": {"app": "ares-traffic", "track": track}},
            "spec": {"selector": {"matchLabels": {"app": "ares-traffic", "track": track}},
                     "template": {"metadata": {
                         "labels": {"app": "ares-traffic", "track": track}},
                         "spec": {"containers": [{
                             "name": "workload", "image": f"ares-traffic-{track}:local",
                             "env": [{"name": "ARES_TRACK", "value": track}]}]}}},
        }
    return {"route": route, "services": services, "slices": slices, "pods": pods,
            "deployments": deployments}


def driver_args(**overrides: Any) -> argparse.Namespace:
    values = {
        "cluster": "ares-observation-e2e",
        "stable_image": "ares-observation-stable:local",
        "canary_image": "ares-observation-canary:local",
        "sampler_image": "ares-observation-sampler:local",
        "expected_commit": HEAD,
        "deployment_run_id": "stub-run-1",
        "gateway_api_version": "v1.4.1",
        "envoy_gateway_version": "v1.6.7",
        "readiness_timeout": 30.0,
        "observe_timeout": 30,
        "evidence": "e2e-evidence/traffic-observation-e2e.json",
        "destroy_cluster": False,
        "keep_workdir": True,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class DriverHarness:
    """Runs the real driver with only the process layer replaced."""

    def __init__(self, cluster: Optional[StubCluster] = None, **args_overrides: Any) -> None:
        self.cluster = cluster or StubCluster()
        self.args = driver_args(**args_overrides)
        self.workdir = pathlib.Path(tempfile.mkdtemp(prefix="ares-observation-stub-"))

    def __enter__(self) -> "DriverHarness":
        self._saved = {
            "sh": topology_driver.sh,
            "check_gateway_api_crds": topology_driver.check_gateway_api_crds,
            "check_envoy_gateway_controller":
                topology_driver.check_envoy_gateway_controller,
            "core_readiness": topology_driver.core_readiness,
            "run_sampler": topology_driver.run_sampler,
            "client": adapter_driver.KubectlReadClient,
            "results": list(topology_driver.RESULTS),
            "diagnostics": dict(topology_driver.DIAGNOSTICS),
            "stack": dict(topology_driver.STACK_INFO),
            "images": dict(topology_driver.IMAGE_IDENTITIES),
            "data_plane": dict(topology_driver.DATA_PLANE),
            "observations": list(adapter_driver.OBSERVATIONS),
            "read_only": dict(adapter_driver.READ_ONLY),
        }
        topology_driver.RESULTS.clear()
        topology_driver.DIAGNOSTICS.clear()
        topology_driver.STACK_INFO.clear()
        topology_driver.IMAGE_IDENTITIES.clear()
        topology_driver.DATA_PLANE.clear()
        adapter_driver.OBSERVATIONS.clear()
        adapter_driver.READ_ONLY.clear()
        self._patches = [
            mock.patch.object(topology_driver, "sh", self.cluster),
            mock.patch.object(topology_driver, "check_gateway_api_crds",
                              lambda *a, **k: True),
            mock.patch.object(topology_driver, "check_envoy_gateway_controller",
                              lambda *a, **k: True),
            mock.patch.object(topology_driver, "core_readiness", self._core_readiness),
            mock.patch.object(topology_driver, "run_sampler", self._run_sampler),
            mock.patch.object(adapter_driver, "KubectlReadClient", self._client),
        ]
        for patch in self._patches:
            patch.start()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        for patch in reversed(self._patches):
            patch.stop()
        topology_driver.RESULTS[:] = self._saved["results"]
        topology_driver.DIAGNOSTICS.clear()
        topology_driver.DIAGNOSTICS.update(self._saved["diagnostics"])
        topology_driver.STACK_INFO.clear()
        topology_driver.STACK_INFO.update(self._saved["stack"])
        topology_driver.IMAGE_IDENTITIES.clear()
        topology_driver.IMAGE_IDENTITIES.update(self._saved["images"])
        topology_driver.DATA_PLANE.clear()
        topology_driver.DATA_PLANE.update(self._saved["data_plane"])
        adapter_driver.OBSERVATIONS[:] = self._saved["observations"]
        adapter_driver.READ_ONLY.clear()
        adapter_driver.READ_ONLY.update(self._saved["read_only"])
        shutil.rmtree(self.workdir, ignore_errors=True)

    # ----------------------------------------------------------- seams
    def _core_readiness(self, cluster: str, args: argparse.Namespace) -> bool:
        topology_driver.DATA_PLANE.clear()
        topology_driver.DATA_PLANE.update({
            "name": "ares-data-plane", "namespace": "envoy-gateway-system", "port": 8080,
            "cluster_url": ("http://ares-data-plane.envoy-gateway-system.svc.cluster"
                            ".local:8080/")})
        return topology_driver.record(
            "readiness:stub", "the stub cluster reports ready",
            "data plane simulated", True)

    def _run_sampler(self, cluster: str, workdir: pathlib.Path, sampler_image: str,
                     url: str, count: int, name: str, timeout: int = 420) -> Dict[str, Any]:
        weights = topology_driver.configured_weight_map(self.cluster.route)
        total = sum(weights.values())
        canary_share = weights["canary"] / total if total else 0.0
        canary = round(count * canary_share)
        return {"total": count, "stable": count - canary, "canary": canary, "errors": 0,
                "other": 0, "body_disagreements": 0, "statuses": {"200": count},
                "instances": {"ares-data-plane": count}, "elapsed_ms": 12}

    def _client(self, config, *, runner=None):
        return REAL_CLIENT(config, runner=self.cluster)

    def run(self) -> bool:
        return adapter_driver.run(self.args, self.workdir)

    def checks(self) -> Dict[str, str]:
        return {row["check"]: row["status"] for row in topology_driver.RESULTS}


class DriverControlFlowTests(unittest.TestCase):
    """The real driver, a stub cluster, and two hostile controls."""

    def test_a_healthy_stub_cluster_runs_the_whole_driver_green(self):
        with DriverHarness() as harness:
            ok = harness.run()
            checks = harness.checks()
            evidence = adapter_driver.build_evidence(harness.args)
            observed = {row["state"]: row["adapter"]["observed"]["percentage"]
                        for row in adapter_driver.OBSERVATIONS}

        self.assertTrue(ok, [name for name, status in checks.items()
                             if status != "PASS"])
        self.assertEqual(evidence["failing_checks"], [])
        self.assertGreater(evidence["total"], 0)
        self.assertEqual(evidence["passed"], evidence["total"])
        self.assertEqual(observed["committed-95-5"], 5)
        self.assertEqual(observed["all-stable-100-0"], 0)
        self.assertEqual(observed["all-canary-0-100"], 100)
        self.assertEqual(observed["restored-95-5"], 5)
        self.assertIsNone(observed["negative-missing-backend"])
        self.assertIsNone(observed["negative-zero-weights"])
        self.assertIsNone(observed["binding-mismatch"])
        self.assertIsNone(observed["unbound"])
        for name in (
            "observation:committed-95-5:status",
            "observation:committed-95-5:percentage",
            "observation:all-stable-100-0:percentage",
            "observation:all-canary-0-100:percentage",
            "observation:negative-missing-backend:refused",
            "observation:negative-zero-weights:refused",
            "observation:restored-95-5:status",
            "observation:binding-mismatch:conflict",
            "observation:unbound:unknown",
            "observation:read-only:no-cluster-write",
            "observation:live-traffic-agrees",
            "observation:states-distinguishable",
        ):
            with self.subTest(check=name):
                self.assertIn(name, checks)
                self.assertEqual(checks[name], "PASS")

    def test_a_caching_observer_turns_the_run_red(self):
        """A provider that answers with its first observation must fail.

        This is the control for ``states-distinguishable``: an adapter that
        reads once and repeats itself would report 5% for the 0/100 state,
        and the driver must notice.
        """
        real_observe = adapter_driver.observe
        cache: Dict[Any, Any] = {}

        def cached(target, args, **kwargs):
            key = (kwargs.get("expected_run"), kwargs.get("expected_sha"))
            if key not in cache:
                cache[key] = real_observe(target, args, **kwargs)
            return cache[key]

        with DriverHarness() as harness:
            with mock.patch.object(adapter_driver, "observe", cached):
                ok = harness.run()
            checks = harness.checks()
            evidence = adapter_driver.build_evidence(harness.args)

        self.assertFalse(ok)
        self.assertTrue(evidence["failing_checks"])
        # The driver stops at the first state it cannot verify, so the
        # states-distinguishable roll-up is never reached: the cached
        # answer is caught by the per-state checks themselves.
        self.assertEqual(checks["observation:all-stable-100-0:percentage"], "FAIL")
        self.assertEqual(
            checks["observation:all-stable-100-0:configured-cross-check"], "FAIL")
        # Fail-fast, by design: the driver stops at the first live state it
        # cannot verify rather than continuing to assert on a stale answer.
        self.assertNotIn("observation:all-canary-0-100:percentage", checks)
        self.assertNotIn("observation:restored-95-5:status", checks)

    def test_an_unavailable_read_turns_the_run_red(self):
        """Every independent view of the cluster stays healthy; only the
        adapter's own read of one Service fails. The run must go red,
        because the adapter refuses to report a share it could not read.
        """
        cluster = StubCluster()
        cluster.service_failures["ares-canary"] = (
            "the server is currently unable to handle the request")
        with DriverHarness(cluster) as harness:
            ok = harness.run()
            checks = harness.checks()
            evidence = adapter_driver.build_evidence(harness.args)

        self.assertFalse(ok)
        self.assertEqual(checks["topology:endpoint-sets-disjoint"], "PASS")
        self.assertEqual(checks["observation:committed-95-5:status"], "FAIL")
        self.assertEqual(checks["observation:committed-95-5:percentage"], "FAIL")
        self.assertTrue(evidence["failing_checks"])

    def test_the_driver_stops_before_the_cluster_when_the_checkout_is_wrong(self):
        # The production wait retries for two minutes; the same predicate,
        # evaluated once, is what this test needs.
        def once(expected: str, timeout: float = 120.0) -> Tuple[bool, str]:
            return HEAD == expected, f"HEAD={HEAD!r} expected={expected!r}"

        with DriverHarness(expected_commit="0" * 40) as harness:
            with mock.patch.object(topology_driver, "wait_for_expected_commit", once):
                ok = harness.run()
            checks = harness.checks()

        self.assertFalse(ok)
        self.assertEqual(checks["preflight:checkout-matches-commit"], "FAIL")
        self.assertNotIn("observation:committed-95-5:status", checks)

    def test_the_stub_cluster_only_ever_sees_read_verbs_from_the_adapter(self):
        """The adapter's argv is a read; the driver's own patch is separate."""
        captured: List[Tuple[str, ...]] = []

        def runner(argv, **kwargs):
            captured.append(tuple(argv))
            return subprocess.CompletedProcess(
                list(argv), 0, json.dumps({"kind": "Object", "metadata": {},
                                           "items": []}), "")

        client = kubernetes_read_client.KubectlReadClient(
            kubernetes_read_client.TrafficReadConfig(
                namespace="ares-traffic", app_label="ares-traffic",
                context="kind-ares-observation-e2e", timeout_seconds=30), runner=runner)
        client.get_http_route("ares-route", "ares-traffic")
        client.get_service("ares-stable", "ares-traffic")
        client.list_endpoint_slices("ares-traffic", "ares-stable")
        client.list_pods("ares-traffic", "ares-traffic")
        client.list_deployments("ares-traffic", "ares-traffic")
        self.assertEqual(captured and {argv[1] for argv in captured}, {"get"})
        self.assertIn("--context", captured[0])
        self.assertEqual(
            [index for index, token in enumerate(captured[0]) if token == "-o"],
            [len(captured[0]) - 3])


if __name__ == "__main__":
    unittest.main(verbosity=2)
