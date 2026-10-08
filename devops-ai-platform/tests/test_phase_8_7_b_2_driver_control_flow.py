"""Phase 8.7-B.2 driver-stage control flow, exercised against a stub cluster.

The live mutation E2E cannot run in this test process (no container runtime,
no cluster), and an E2E driver that has never been executed is exactly where
the earlier phases lost CI runs. So this module runs the *real* driver —
``e2e/traffic_mutation_kind_e2e.py`` — with only the process layer faked:

* the stub cluster from Phase 8.7-B.1's control-flow harness answers every
  ``kubectl`` invocation (its reads, its ``get`` shapes and its controller
  status), extended here with full RFC 6902 patch semantics so the
  provider's compare-and-set is genuinely evaluated: ``test`` operations
  are checked before anything is written, a failed test refuses the whole
  patch with a server-style conflict, a committed write bumps generation
  and resourceVersion, and ``remove``/``add /-`` work;
* the application's own read client, observer, mutation client, provider
  and request construction are the real ones. Only the process layer — the
  ``subprocess.run`` that both the read runner and the write runner call —
  is replaced by the stub cluster, so the *argv* the shipped client builds
  is exactly what the stub API server sees.

Hostile controls make the driver falsifiable: a client that never writes
but reports success, a read path that cannot see the change, a patch
builder without its compare-and-set, a data-plane sample that contradicts
the written weights, and a client that writes twice must each turn the run
red. A driver that cannot fail is not evidence.
"""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import Any, Dict, List, Optional, Sequence
from unittest import mock

PLATFORM_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PLATFORM_DIR))
sys.path.insert(0, str(PLATFORM_DIR / "tests"))

# The B.1 control-flow harness owns the stub cluster: reusing it keeps one
# stub world for both drivers instead of two that can drift apart.
import test_phase_8_7_b_1_driver_control_flow as b1_harness  # noqa: E402
from e2e import traffic_topology_kind_e2e as topology_driver  # noqa: E402
from e2e import traffic_mutation_kind_e2e as mutation_driver  # noqa: E402
from incident_service.infrastructure.traffic import (  # noqa: E402
    kubernetes_read_client,
)
from incident_service.infrastructure.traffic_mutation import (  # noqa: E402
    kubernetes_mutation_client,
)

REAL_CLIENT = kubernetes_read_client.KubectlReadClient
REAL_MUTATION_CLIENT = kubernetes_mutation_client.KubernetesMutationClient
REAL_BUILD_PATCH = kubernetes_mutation_client.build_weight_patch


class StubPatchRejected(Exception):
    """The stub API server refused the whole patch (a two-valued no)."""


def _resolve(document: Any, path: str) -> Any:
    cursor = document
    for part in path.strip("/").split("/"):
        if isinstance(cursor, list):
            index = len(cursor) - 1 if part == "-" else int(part)
            cursor = cursor[index]
        else:
            cursor = cursor[part]
    return cursor


def provider_writes(cluster) -> "List[Any]":
    """The writes that really came from the shipped client.

    A write is recognised by the *closed* patch the shipped builder
    produces: one ``test`` on the route's resourceVersion plus two
    ``test``/``replace`` pairs on the backendRef weights. The harness's own
    proof-state patches have a different shape, so they cannot be mistaken
    for the application's write.
    """
    writes = []
    for call in cluster.calls:
        if "-p" not in call:
            continue
        payload = call[call.index("-p") + 1]
        try:
            operations = json.loads(payload)
        except (TypeError, ValueError):
            continue
        if not isinstance(operations, list):
            continue
        cas = [operation for operation in operations
               if operation.get("op") == "test"
               and operation.get("path") == "/metadata/resourceVersion"]
        replaces = [operation for operation in operations
                    if operation.get("op") == "replace"
                    and str(operation.get("path", "")).endswith("/weight")]
        if len(cas) == 1 and len(replaces) == 2 and len(operations) == 7:
            writes.append(operations)
    return writes


def write_signature(operations) -> "tuple":
    """(resourceVersion tested, weights written) for one provider write."""
    tested = next((operation["value"] for operation in operations
                   if operation.get("op") == "test"
                   and operation.get("path") == "/metadata/resourceVersion"), None)
    written = tuple(operation["value"] for operation in operations
                    if operation.get("op") == "replace")
    return (tested, written)


def signature_counts(cluster) -> Dict[Any, int]:
    counts: Dict[Any, int] = {}
    for operations in provider_writes(cluster):
        key = write_signature(operations)
        counts[key] = counts.get(key, 0) + 1
    return counts

class MutationStubCluster(b1_harness.StubCluster):
    """The B.1 stub cluster plus real JSON-patch semantics."""

    def patch_route(self, payload: str) -> None:
        operations = json.loads(payload)
        # every `test` first: the API server refuses the entire patch if any
        # of them fails, which is what makes the provider's CAS real
        for operation in operations:
            if operation.get("op") == "test":
                if _resolve(self.route, operation["path"]) != operation["value"]:
                    raise StubPatchRejected(
                        f"test failed at {operation['path']}")
        for operation in operations:
            op = operation.get("op")
            if op == "replace":
                parts = operation["path"].strip("/").split("/")
                parent: Any = self.route
                for part in parts[:-1]:
                    parent = parent[int(part)] if isinstance(parent, list) else parent[part]
                last = parts[-1]
                if isinstance(parent, list):
                    parent[int(last)] = operation["value"]
                else:
                    parent[last] = operation["value"]
            elif op == "add":
                parts = operation["path"].strip("/").split("/")
                parent: Any = self.route
                for part in parts[:-1]:
                    parent = parent[int(part)] if isinstance(parent, list) else parent[part]
                last = parts[-1]
                if isinstance(parent, list):
                    if last == "-":
                        parent.append(operation["value"])
                    else:
                        parent.insert(int(last), operation["value"])
                else:
                    parent[last] = operation["value"]
            elif op == "remove":
                parts = operation["path"].strip("/").split("/")
                parent: Any = self.route
                for part in parts[:-1]:
                    parent = parent[int(part)] if isinstance(parent, list) else parent[part]
                last = parts[-1]
                if isinstance(parent, list):
                    parent.pop(int(last))
                else:
                    del parent[last]
            elif op == "test":
                continue
            else:  # pragma: no cover - defensive
                raise AssertionError(f"unsupported patch op {op}")
        self.touch()

    def _kubectl(self, argv: Sequence[str]) -> subprocess.CompletedProcess:
        try:
            return super()._kubectl(argv)
        except StubPatchRejected as exc:
            return b1_harness.proc(
                list(argv), "",
                f"Error from server (Conflict): the server rejected our request: {exc}",
                1,
            )


class DriverHarness:
    """Runs the real mutation driver with only the process layer replaced."""

    def __init__(self, cluster: Optional[MutationStubCluster] = None, *,
                 runner_factory=None, read_client_factory=None,
                 sampler=None, **args_overrides: Any) -> None:
        self.cluster = cluster or MutationStubCluster()
        self.args = b1_harness.driver_args(
            cluster="ares-mutation-e2e", deployment_run_id="stub-mutation-run",
            mutation_timeout=30,
            evidence="e2e-evidence/traffic-mutation-e2e.json", **args_overrides)
        self.workdir = pathlib.Path(tempfile.mkdtemp(prefix="ares-mutation-stub-"))
        self._runner_factory = runner_factory
        self._read_client_factory = read_client_factory
        self._sampler = sampler

    # -------------------------------------------------------------- seams

    def _client(self, config, *, runner=None):
        return REAL_CLIENT(config, runner=self.cluster)

    def _mutation_client(self, args, *, runner=None):
        if self._runner_factory is not None:
            return self._runner_factory(self.cluster, args)
        # the driver's own runner (the racing one) is kept — it is what the
        # driver is testing — and only the process it calls is the stub; when
        # the driver passes no runner at all, the real client gets the stub
        runner = runner or (lambda argv, **kwargs: self.cluster(
            list(argv), timeout=kwargs.get("timeout", 300)))
        return REAL_MUTATION_CLIENT(
            mutation_driver.TrafficWriteConfig(
                namespace=mutation_driver.NAMESPACE, context="kind-stub",
                kubectl="kubectl", timeout_seconds=args.mutation_timeout),
            runner=runner,
        )

    def _core_readiness(self, cluster: str, args: argparse.Namespace) -> bool:
        topology_driver.DATA_PLANE.clear()
        topology_driver.DATA_PLANE.update({
            "name": "ares-data-plane", "namespace": "envoy-gateway-system", "port": 8080,
            "cluster_url": ("http://ares-data-plane.envoy-gateway-system.svc.cluster"
                            ".local:8080/")})
        return topology_driver.record(
            "readiness:stub", "the stub cluster reports ready", "simulated", True)

    def _run_sampler(self, cluster: str, workdir: pathlib.Path, sampler_image: str,
                     url: str, count: int, name: str, timeout: int = 420):
        if self._sampler is not None:
            return self._sampler(self.cluster, count)
        weights = topology_driver.configured_weight_map(self.cluster.route)
        total = sum(weights.values())
        canary_share = weights["canary"] / total if total else 0.0
        canary = round(count * canary_share)
        return {"total": count, "stable": count - canary, "canary": canary,
                "errors": 0, "other": 0, "body_disagreements": 0,
                "statuses": {"200": count}, "instances": {"ares-data-plane": count},
                "elapsed_ms": 12}

    def __enter__(self) -> "DriverHarness":
        self._saved = {
            "sh": topology_driver.sh,
            "check_gateway_api_crds": topology_driver.check_gateway_api_crds,
            "check_envoy_gateway_controller":
                topology_driver.check_envoy_gateway_controller,
            "core_readiness": topology_driver.core_readiness,
            "run_sampler": topology_driver.run_sampler,
            "results": list(topology_driver.RESULTS),
            "diagnostics": dict(topology_driver.DIAGNOSTICS),
            "stack": dict(topology_driver.STACK_INFO),
            "images": dict(topology_driver.IMAGE_IDENTITIES),
            "data_plane": dict(topology_driver.DATA_PLANE),
            "mutations": list(mutation_driver.MUTATIONS),
            "observations": list(mutation_driver.OBSERVATIONS),
            "refusals": list(mutation_driver.REFUSALS),
            "state_changes": list(mutation_driver.DRIVER_STATE_CHANGES),
            "concurrency": list(mutation_driver.CONCURRENCY),
            "safety": dict(mutation_driver.SAFETY),
        }
        topology_driver.RESULTS.clear()
        topology_driver.DIAGNOSTICS.clear()
        topology_driver.STACK_INFO["cluster"] = "stub"
        topology_driver.IMAGE_IDENTITIES.clear()
        topology_driver.DATA_PLANE.clear()
        mutation_driver.MUTATIONS.clear()
        mutation_driver.OBSERVATIONS.clear()
        mutation_driver.REFUSALS.clear()
        mutation_driver.DRIVER_STATE_CHANGES.clear()
        mutation_driver.CONCURRENCY.clear()
        mutation_driver.SAFETY.clear()
        self._patches = [
            mock.patch.object(topology_driver, "sh", self.cluster),
            mock.patch.object(topology_driver, "check_gateway_api_crds",
                              lambda *a, **k: True),
            mock.patch.object(topology_driver, "check_envoy_gateway_controller",
                              lambda *a, **k: True),
            mock.patch.object(topology_driver, "core_readiness", self._core_readiness),
            mock.patch.object(topology_driver, "run_sampler", self._run_sampler),
            mock.patch.object(mutation_driver, "KubectlReadClient",
                              self._read_client_factory or self._client),
            mock.patch.object(mutation_driver, "_mutation_client", self._mutation_client),
            mock.patch.object(mutation_driver, "subprocess", self._subprocess),
        ]
        for patch in self._patches:
            patch.start()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        for patch in reversed(self._patches):
            patch.stop()
        topology_driver.RESULTS[:] = self._saved["results"]
        for name, key in (("DIAGNOSTICS", "diagnostics"), ("STACK_INFO", "stack"),
                          ("IMAGE_IDENTITIES", "images"), ("DATA_PLANE", "data_plane")):
            mapping = getattr(topology_driver, name)
            mapping.clear()
            mapping.update(self._saved[key])
        mutation_driver.MUTATIONS[:] = self._saved["mutations"]
        mutation_driver.OBSERVATIONS[:] = self._saved["observations"]
        mutation_driver.REFUSALS[:] = self._saved["refusals"]
        mutation_driver.DRIVER_STATE_CHANGES[:] = self._saved["state_changes"]
        mutation_driver.CONCURRENCY[:] = self._saved["concurrency"]
        mutation_driver.SAFETY.clear()
        mutation_driver.SAFETY.update(self._saved["safety"])
        shutil.rmtree(self.workdir, ignore_errors=True)

    # -------------------------------------------------------------- process

    @property
    def _subprocess(self):
        """``subprocess`` as the driver sees it: the stub cluster, no exec."""
        cluster = self.cluster

        class Stdlib:
            TimeoutExpired = subprocess.TimeoutExpired
            CalledProcessError = subprocess.CalledProcessError
            CompletedProcess = subprocess.CompletedProcess

            @staticmethod
            def run(argv, **kwargs):
                return cluster(list(argv), timeout=kwargs.get("timeout", 300))

        return Stdlib()

    # ------------------------------------------------------------ running

    def run(self) -> bool:
        return mutation_driver.run(self.args, self.workdir)

    def checks(self) -> Dict[str, str]:
        return {row["check"]: row["status"] for row in topology_driver.RESULTS}


class DriverControlFlowTests(unittest.TestCase):
    """The real driver, a stub cluster, and hostile controls."""

    def test_a_healthy_stub_cluster_runs_the_whole_driver_green(self):
        with DriverHarness() as harness:
            ok = harness.run()
            checks = harness.checks()
            failures = {name: status for name, status in checks.items()
                        if status != "PASS"}
            self.assertTrue(
                ok,
                f"the driver failed against a healthy stub cluster: {failures}",
            )
            self.assertGreater(len(checks), 10)
            # the two operations under test really went through the provider
            self.assertEqual(
                [row["operation"] for row in mutation_driver.MUTATIONS],
                ["APPLY", "ROLLBACK"],
            )
            for row in mutation_driver.MUTATIONS:
                self.assertTrue(row["verified"], row["detail"])
                self.assertEqual(row["attempts_in_this_call"], 1)
                self.assertEqual(
                    row["driver_read_after"]["weights"],
                    row["expected_weights"],
                    f"{row['label']}: the route does not carry the "
                    f"authorized mapping",
                )
            # the refusals really refused, with the route untouched
            for row in mutation_driver.REFUSALS:
                self.assertFalse(row["verified"])
                self.assertTrue(row["route_unchanged"], row)
                self.assertTrue(row["danger_present"], row)
            # the provider wrote the route; the driver did not (for the
            # operations under test): every driver-side change is recorded
            self.assertTrue(mutation_driver.DRIVER_STATE_CHANGES)

    def test_the_stub_cluster_saw_exactly_two_writes_from_the_provider(self):
        with DriverHarness() as harness:
            ok = harness.run()
            self.assertTrue(ok)
            writes = provider_writes(harness.cluster)
            # four writes come from the shipped client, and each one is a
            # distinct, single attempt: the APPLY, the ROLLBACK, the write
            # that deliberately loses the compare-and-set race, and the
            # winning competitor's write. No write is ever repeated.
            self.assertEqual(
                len(writes), 4,
                f"expected exactly four application writes, saw {len(writes)}")
            counts = signature_counts(harness.cluster)
            self.assertEqual(
                max(counts.values()), 1,
                f"the same write (resourceVersion + weights) was sent more "
                f"than once: {counts}")
            # the closed vocabulary: patch httproute, --type=json, no file,
            # no dry run, and only weight fields are replaced
            for call in harness.cluster.calls:
                if "--type=json" in call:
                    self.assertIn("httproute", call)
                    self.assertNotIn("-f", call)
                    self.assertNotIn("--dry-run=server", call)
            for operations in writes:
                for operation in operations:
                    self.assertIn(operation["op"], ("test", "replace"))
                    if operation["op"] == "replace":
                        self.assertTrue(
                            str(operation["path"]).endswith("/weight"),
                            f"a write touched something other than a weight: "
                            f"{operation['path']}")

    # ------------------------------------------------- hostile controls

    def _runner_that_never_writes(self, cluster, args):
        class NeverWrites(REAL_MUTATION_CLIENT):
            def __init__(self):
                super().__init__(
                    mutation_driver.TrafficWriteConfig(
                        namespace=mutation_driver.NAMESPACE, context="kind-stub",
                        kubectl="kubectl", timeout_seconds=args.mutation_timeout),
                    runner=self._pretend,
                )

            def _pretend(self, argv, **kwargs):
                # a client that believes its own exit code: the API server
                # answered 0 and returned the *old* document
                return subprocess.CompletedProcess(
                    list(argv), 0, json.dumps(copy.deepcopy(cluster.route)), "")

        return NeverWrites()

    def test_a_write_that_never_happens_turns_the_run_red(self):
        with DriverHarness(runner_factory=self._runner_that_never_writes) as harness:
            ok = harness.run()
            self.assertFalse(ok, "the driver accepted a write that never landed")
            self.assertEqual(
                harness.checks().get("mutation:apply-5-to-25"), "FAIL")

    def test_an_observer_that_cannot_see_the_change_turns_the_run_red(self):
        frozen: Dict[str, Any] = {"route": None}

        class FrozenReads(REAL_CLIENT):
            """A real client whose route read is frozen at one moment."""

            def get_http_route(self, name, namespace):
                if frozen["route"] is None:
                    frozen["route"] = copy.deepcopy(
                        harness_ref["cluster"].route)
                return copy.deepcopy(frozen["route"])

        harness_ref: Dict[str, Any] = {}
        with DriverHarness(read_client_factory=lambda config, runner=None:
                           FrozenReads(config, runner=harness_ref["cluster"])) as harness:
            harness_ref["cluster"] = harness.cluster
            ok = harness.run()
            self.assertFalse(ok, "the driver verified a change it could not observe")
            self.assertEqual(harness.checks().get("mutation:apply-5-to-25"), "FAIL")

    def test_a_patch_without_its_compare_and_set_is_caught_by_the_driver(self):
        def without_tests(mutation):
            return tuple(operation for operation in REAL_BUILD_PATCH(mutation)
                         if operation.get("op") != "test")

        with mock.patch.object(kubernetes_mutation_client, "build_weight_patch",
                               without_tests):
            with DriverHarness() as harness:
                ok = harness.run()
                self.assertFalse(
                    ok, "the driver accepted a lost race it should have detected")
                self.assertEqual(
                    harness.checks().get("cas:lost-race-is-refused-not-overwritten"),
                    "FAIL")

    def test_a_data_plane_that_disagrees_turns_the_run_red(self):
        def all_canary(cluster, count):
            return {"total": count, "stable": 0, "canary": count, "errors": 0,
                    "other": 0, "body_disagreements": 0,
                    "statuses": {"200": count}, "instances": {"ares-data-plane": count},
                    "elapsed_ms": 9}

        with DriverHarness(sampler=all_canary) as harness:
            ok = harness.run()
            self.assertFalse(ok, "the driver accepted a contradicting data plane")
            self.assertEqual(harness.checks().get("data-plane:after-apply"), "FAIL")

    def test_a_client_that_writes_twice_turns_the_run_red(self):
        def double_writer(cluster, args):
            class DoubleWriter(REAL_MUTATION_CLIENT):
                def __init__(self):
                    super().__init__(
                        mutation_driver.TrafficWriteConfig(
                            namespace=mutation_driver.NAMESPACE, context="kind-stub",
                            kubectl="kubectl", timeout_seconds=args.mutation_timeout),
                        runner=lambda argv, **kwargs: cluster(
                            list(argv), timeout=kwargs.get("timeout", 300)),
                    )

                def apply_weight_mutation(self, mutation):
                    first = super().apply_weight_mutation(mutation)
                    if first.accepted:
                        # a second write for one logical mutation: the
                        # provider must count two attempts and refuse
                        super().apply_weight_mutation(mutation)
                    return first

            return DoubleWriter()

        with DriverHarness(runner_factory=double_writer) as harness:
            ok = harness.run()
            self.assertFalse(ok, "the driver accepted two writes for one operation")
            self.assertEqual(
                harness.checks().get("mutation:apply-5-to-25"), "FAIL")
            self.assertTrue(
                any("write attempts" in row["detail"]
                    for row in mutation_driver.MUTATIONS), 
                "the refusal does not name the second attempt")
            counts = signature_counts(harness.cluster)
            self.assertTrue(counts, "no provider write reached the stub server")
            # this client writes twice for *every* operation it is given, so
            # every signature really did arrive twice
            self.assertEqual(
                set(counts.values()), {2},
                f"the duplicate write never reached the stub server: {counts}")
            self.assertIn(
                (75, 25), [written for _, written in counts],
                "the APPLY's own write is missing from the duplicates")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
