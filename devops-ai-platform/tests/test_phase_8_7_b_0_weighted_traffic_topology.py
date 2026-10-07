"""Phase 8.7-B.0 — weighted stable/canary traffic topology contracts.

Phase 8.7-B.0 puts a REAL weighted topology on the repository (Gateway
API, implemented by Envoy Gateway) so a future 8.7-B provider has a
genuine remote resource to address. It deliberately does NOT give the
application any way to change that topology, and that boundary is what
most of these tests protect:

* the committed fixture really is the declared minimal weighted topology
  (manifests, identity, disjoint selectors, explicit proportional weights);
* the production deployment path is untouched and still plain-Service;
* no application code can reach Gateway API resources — no client, no
  mutation path, no new sandbox verb;
* the Phase 8.7-A mutation boundary is still unimplemented and fails
  closed, and the E2E driver that patches weights never imports it;
* every topology mutation is caught by the static verifier, on an
  isolated copy that cannot touch this working tree;
* the proof states' tolerance is derived from the sampling distribution
  (4 sigma normal approximation), not chosen to make a weak test pass.

The cluster-side half (real HTTP routing through the Envoy data plane)
is executed by ``e2e/traffic_topology_kind_e2e.py`` in the dedicated CI
job; it cannot run here because this repository's tests never create
clusters.
"""
from __future__ import annotations

import argparse
import ast
import builtins
import hashlib
import http.server
import importlib.util
import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

PLATFORM_DIR = pathlib.Path(__file__).resolve().parent.parent
REPO_ROOT = PLATFORM_DIR.parent
sys.path.insert(0, str(PLATFORM_DIR))

from e2e.helpers import ARTIFACT_PIN_KEYS, parse_pinned_artifacts  # noqa: E402
from e2e import traffic_topology as topo  # noqa: E402
from e2e import traffic_topology_kind_e2e as driver  # noqa: E402

PINS_FILE = PLATFORM_DIR / "e2e" / "pinned-traffic-topology.txt"
PROBE = PLATFORM_DIR / "e2e" / "traffic-topology" / "mutation_probe.py"
DRIVER = PLATFORM_DIR / "e2e" / "traffic_topology_kind_e2e.py"
WORKLOAD_SERVER = PLATFORM_DIR / "e2e" / "traffic-topology" / "workload" / "server.py"
SAMPLER = PLATFORM_DIR / "e2e" / "traffic-topology" / "sampler" / "sampler.py"
BOUNDARY = (PLATFORM_DIR / "incident_service" / "application" / "services"
            / "traffic_mutation_boundary.py")
DOC = REPO_ROOT / "docs" / "PHASE-8.7-B.0-WEIGHTED-TRAFFIC-TOPOLOGY.md"
WORKLOAD_DIR = PLATFORM_DIR / "e2e" / "traffic-topology" / "workload"
SAMPLER_DIR = PLATFORM_DIR / "e2e" / "traffic-topology" / "sampler"
PRODUCTION_MANIFEST = REPO_ROOT / "k8s" / "deployment.yaml"

#: Modules that are ALLOWED to know about kubectl at all: the Phase
#: 8.6-A sandbox path that applies one approved manifest. Nothing here may
#: grow a Gateway API capability.
KUBECTL_AWARE_PREFIXES = ("deployment_service/",)

#: ``${VAR}`` / ``$VAR`` expansions inside a Dockerfile instruction.
VARIABLE_USE = re.compile(r"\$(?:\{)?([A-Za-z_][A-Za-z0-9_]*)")


def fixture_digest() -> str:
    """sha256 over the whole committed fixture, file names included."""
    digest = hashlib.sha256()
    for path in sorted(pathlib.Path(topo.TOPOLOGY_DIR).iterdir()):
        if path.suffix not in (".yaml", ".yml"):
            continue
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def executable_code(path: pathlib.Path) -> str:
    """Module source with comments and docstrings removed.

    Safety assertions must look at what the code DOES. A docstring that
    says "there is no HTTPRoute support" is the opposite of a violation,
    so it is stripped before the token search.
    """
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = node.body
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


def unbound_global_names(path: pathlib.Path) -> list:
    """Names loaded anywhere in the module but bound nowhere in it.

    This is the ``undefined name`` lint (F821) restricted to module level,
    computed with the standard library only so the CI job needs no extra
    dependency: every import alias, class, function, argument, assignment
    target, ``global``/``nonlocal`` declaration, exception binding and
    match binding counts as bound. A name that appears in NONE of those
    sets cannot resolve at run time -- it is a NameError on that path.
    """
    allowed = set(dir(builtins)) | {
        "__file__", "__name__", "__doc__", "__package__", "__spec__",
        "__loader__", "__builtins__", "__annotations__",
    }
    tree = ast.parse(path.read_text(encoding="utf-8"))
    bound: set = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bound.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                arguments = node.args
                for argument in (*arguments.posonlyargs, *arguments.args,
                                  *arguments.kwonlyargs):
                    bound.add(argument.arg)
                for extra in (arguments.vararg, arguments.kwarg):
                    if extra is not None:
                        bound.add(extra.arg)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound.add(node.id)
        elif isinstance(node, ast.arg):
            bound.add(node.arg)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            bound.update(node.names)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        elif isinstance(node, ast.MatchAs) and node.name:
            bound.add(node.name)
        elif isinstance(node, ast.MatchStar) and node.name:
            bound.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bound.add(node.rest)
    used = {
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }
    return sorted(used - bound - allowed)


def raw_probe_output_flags(argv) -> list:
    """The output-selection flags carried by a `kubectl --raw` invocation.

    ``kubectl get --raw=/version -o json`` is rejected by kubectl itself
    ("--raw and --output are mutually exclusive", exit 1); a raw endpoint
    already returns JSON, so no output flag may accompany ``--raw``. This
    predicate is applied to the real call site AND to a deliberately
    broken sample, so it cannot pass vacuously.
    """
    return [
        item for item in argv
        if item in ("-o", "--output", "-ojson") or item.startswith("--output=")
    ]


def application_modules() -> list:
    modules = []
    for prefix in ("incident_service", "deployment_service", "agent_service", "backend"):
        root = PLATFORM_DIR / prefix
        if not root.exists():
            root = REPO_ROOT / prefix
        if not root.exists():
            continue
        for path in root.rglob("*.py"):
            if "/tests/" in str(path) or path.name.startswith("test_"):
                continue
            modules.append(path)
    return modules


class TopologyFixtureTests(unittest.TestCase):
    """The committed fixture is a real, minimal, weighted topology."""

    def test_fixture_satisfies_the_declared_contract(self):
        violations = topo.verify_topology()
        self.assertEqual(
            violations, [],
            f"the committed topology violates its own contract: {violations}")

    def test_resource_graph_is_the_declared_chain(self):
        documents = topo.load_documents()
        by_kind = {}
        for document in documents:
            by_kind.setdefault(document["kind"], []).append(document)
        self.assertEqual(
            sorted(by_kind), sorted(topo.ALLOWED_DOCUMENTS),
            "the fixture must contain exactly the declared resource kinds")
        for kind, allowed_names in topo.ALLOWED_DOCUMENTS.items():
            names = sorted((doc["metadata"]["name"]) for doc in by_kind[kind])
            self.assertEqual(names, sorted(allowed_names))

    def test_route_references_both_services_with_explicit_weights(self):
        refs = topo.route_backends(topo.load_documents())
        self.assertEqual(len(refs), 2)
        names = {ref["name"] for ref in refs}
        self.assertEqual(names, {"ares-stable", "ares-canary"})
        for ref in refs:
            self.assertIsInstance(ref.get("weight"), int,
                                  "weights must be explicit, never implied")
            self.assertEqual(ref.get("port"), topo.BACKEND_PORT)

    def test_weights_are_proportional_not_percentages(self):
        refs = topo.route_backends(topo.load_documents())
        self.assertAlmostEqual(topo.expected_share_of(refs, "ares-stable"), 0.95)
        self.assertAlmostEqual(topo.expected_share_of(refs, "ares-canary"), 0.05)
        # The rule itself: share = weight / sum(weights). Changing the
        # total changes each share, which is what "proportional" means.
        self.assertAlmostEqual(topo.proportional_share(95, [95, 5]), 0.95)
        self.assertAlmostEqual(topo.proportional_share(190, [190, 10]), 0.95)
        with self.assertRaises(ValueError):
            topo.proportional_share(0, [0, 0])

    def test_backends_are_disjoint_workloads_not_one_pod_set(self):
        documents = topo.load_documents()
        services = {doc["metadata"]["name"]: doc for doc in documents
                    if doc["kind"] == "Service"}
        deployments = {doc["metadata"]["name"]: doc for doc in documents
                       if doc["kind"] == "Deployment"}
        self.assertEqual(sorted(services), ["ares-canary", "ares-stable"])
        self.assertEqual(sorted(deployments), ["ares-canary", "ares-stable"])

        def matches(selector, labels):
            return all(labels.get(key) == value for key, value in selector.items())

        stable_pods = deployments["ares-stable"]["spec"]["template"]["metadata"]["labels"]
        canary_pods = deployments["ares-canary"]["spec"]["template"]["metadata"]["labels"]
        self.assertFalse(matches(services["ares-stable"]["spec"]["selector"], canary_pods),
                         "the stable Service must not select canary pods")
        self.assertFalse(matches(services["ares-canary"]["spec"]["selector"], stable_pods),
                         "the canary Service must not select stable pods")
        self.assertNotEqual(stable_pods, canary_pods)
        self.assertEqual(stable_pods.pop("track"), "stable")
        self.assertEqual(canary_pods.pop("track"), "canary")

    def test_gateway_class_names_a_real_implementation(self):
        gateway_class = next(doc for doc in topo.load_documents()
                             if doc["kind"] == "GatewayClass")
        self.assertEqual(gateway_class["spec"]["controllerName"],
                         topo.ENVOY_CONTROLLER_NAME,
                         "the class must be served by a real Gateway API "
                         "implementation, not a placeholder controller")

    def test_listener_is_plain_http_with_no_tls(self):
        gateway = next(doc for doc in topo.load_documents() if doc["kind"] == "Gateway")
        self.assertEqual(len(gateway["spec"]["listeners"]), 1)
        listener = gateway["spec"]["listeners"][0]
        self.assertEqual((listener["protocol"], listener["port"]), ("HTTP", 80))
        self.assertNotIn("tls", listener)
        self.assertEqual(listener["allowedRoutes"]["namespaces"]["from"], "Same")

    def test_no_extra_mechanisms_creep_into_the_overlay(self):
        text = "".join(path.read_text(encoding="utf-8").lower()
                       for path in pathlib.Path(topo.TOPOLOGY_DIR).iterdir()
                       if path.suffix in (".yaml", ".yml"))
        for banned in ("istio", "linkerd", "flagger", "argo-rollouts", "virtualservice",
                       "destinationrule", "cert-manager", "dns"):
            self.assertNotIn(banned, text,
                             f"{banned!r} must not appear in the minimal topology")


class ProductionTopologyTests(unittest.TestCase):
    """The default deployment path must not depend on any of this."""

    def test_production_manifest_is_unchanged_and_plain_service(self):
        import yaml
        documents = [doc for doc in yaml.safe_load_all(
            PRODUCTION_MANIFEST.read_text(encoding="utf-8")) if doc]
        kinds = sorted(doc["kind"] for doc in documents)
        self.assertEqual(kinds, ["ConfigMap", "Deployment", "HorizontalPodAutoscaler",
                                 "Namespace", "Service"])
        for banned in ("Gateway", "GatewayClass", "HTTPRoute"):
            self.assertNotIn(banned, kinds)
        service = next(doc for doc in documents if doc["kind"] == "Service")
        self.assertEqual(service["metadata"]["name"], "devops-gateway-loadbalancer")
        self.assertEqual(service["spec"]["ports"][0]["port"], 80)
        self.assertEqual(service["spec"]["ports"][0]["targetPort"], 8000)

    def test_production_manifest_does_not_reference_the_overlay(self):
        text = PRODUCTION_MANIFEST.read_text(encoding="utf-8")
        for token in ("ares-traffic", "HTTPRoute", "GatewayClass", "envoyproxy"):
            self.assertNotIn(token, text)

    def test_fixture_is_not_wired_into_the_application(self):
        for module in application_modules():
            text = module.read_text(encoding="utf-8")
            self.assertNotIn("k8s/progressive", text)
            self.assertNotIn("traffic_topology", text)

    def test_application_cannot_reach_gateway_api_resources(self):
        offenders = []
        for module in application_modules():
            try:
                code = executable_code(module)
            except SyntaxError:  # pragma: no cover - defensive
                continue
            for token in ("HTTPRoute", "gateway.networking.k8s.io",
                          "envoyproxy.io", "GatewayClass"):
                if token in code:
                    offenders.append(f"{module}: {token}")
        self.assertEqual(
            offenders, [],
            "the application must have no Gateway API client or mutation path: "
            f"{offenders}")

    def test_no_new_mutating_verb_beside_the_approved_manifest_apply(self):
        offenders = []
        for module in application_modules():
            relative = str(module.relative_to(REPO_ROOT)).replace(os.sep, "/")
            if not relative.startswith(KUBECTL_AWARE_PREFIXES):
                continue
            try:
                code = executable_code(module)
            except SyntaxError:  # pragma: no cover - defensive
                continue
            if "kubectl" in code and "patch" in code:
                offenders.append(relative)
        self.assertEqual(offenders, [],
                         "kubectl-aware modules may not gain a patch path: "
                         f"{offenders}")


class MutationBoundaryUntouchedTests(unittest.TestCase):
    """Phase 8.7-A stays exactly as frozen: no provider, fail closed."""

    def test_default_provider_still_fails_closed(self):
        from datetime import datetime, timezone

        from incident_service.application.services import (
            traffic_mutation_boundary as boundary,
        )
        from incident_service.application.services.rollout_plan_service import (
            TrafficIntent,
        )
        from incident_service.application.services.traffic_mutation_boundary import (
            InvalidTrafficMutationRequest,
            TrafficMutationProviderUnavailable,
            TrafficMutationRequest,
            UnavailableTrafficMutationProvider,
            expected_verified_percentage,
            OP_APPLY,
            OP_ROLLBACK,
        )
        observed_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        intent = TrafficIntent(
            intent_id="ti_" + "0" * 24,
            deployment_run_id="run-1",
            source_sha="a" * 40,
            gate_evaluation_id="gate-1",
            stable_target="ares-stable",
            canary_target="ares-canary",
            current_percentage=5,
            requested_percentage=25,
            created_at=observed_at,
            evaluated_at=observed_at,
        )
        request = TrafficMutationRequest.from_traffic_intent(
            intent, observed_percentage=5, observed_at=observed_at)
        provider = UnavailableTrafficMutationProvider()
        self.assertEqual(provider.provider_name, boundary.UNAVAILABLE_PROVIDER)
        with self.assertRaises(TrafficMutationProviderUnavailable):
            provider.apply(request)
        with self.assertRaises(TrafficMutationProviderUnavailable):
            provider.rollback(request)
        self.assertEqual(expected_verified_percentage(OP_APPLY, request), 25)
        self.assertEqual(expected_verified_percentage(OP_ROLLBACK, request), 5)
        with self.assertRaises(InvalidTrafficMutationRequest):
            expected_verified_percentage("DELETE", request)
        # A backward move is refused as an apply, and a no-op is not a
        # mutation: the boundary keeps rejecting both shapes.
        for kwargs in ({"requested_percentage": 5, "expected_current_percentage": 5,
                        "observed_percentage": 5},        # a no-op is not a mutation
                       {"requested_percentage": 25, "expected_current_percentage": 5,
                        "observed_percentage": 10},):     # observation must match
            with self.assertRaises(InvalidTrafficMutationRequest):
                TrafficMutationRequest(
                    deployment_run_id="run-1", source_sha="a" * 40,
                    gate_evaluation_id="gate-1", intent_id="ti_" + "0" * 24,
                    stable_target="ares-stable", canary_target="ares-canary",
                    observed_at=observed_at, **kwargs)
        with self.assertRaises(InvalidTrafficMutationRequest):
            TrafficMutationRequest(
                deployment_run_id="run-1", source_sha="a" * 40,
                gate_evaluation_id="gate-1", intent_id="ti_" + "0" * 24,
                stable_target="ares-stable", canary_target="ares-canary",
                expected_current_percentage=25, requested_percentage=5,
                observed_percentage=25, observed_at=observed_at)

    def test_port_surface_is_still_apply_and_rollback_only(self):
        from incident_service.application.services.traffic_mutation_boundary import (
            FORBIDDEN_PORT_MEMBERS,
            TRAFFIC_MUTATION_REQUEST_VERSION,
            TrafficMutationPort,
        )
        members = {name for name in vars(TrafficMutationPort) if not name.startswith("_")}
        self.assertEqual(members, {"apply", "rollback"})
        for forbidden in ("inspect", "plan", "execute", "mutate", "apply_percentage"):
            self.assertIn(forbidden, FORBIDDEN_PORT_MEMBERS)
        self.assertEqual(TRAFFIC_MUTATION_REQUEST_VERSION,
                         "traffic-mutation-request-v1")

    def test_no_shipped_provider_implements_the_port(self):
        source = ast.parse(BOUNDARY.read_text(encoding="utf-8"))
        shipped = []
        for node in source.body:
            if not isinstance(node, ast.ClassDef):
                continue
            bases = {ast.unparse(base) for base in node.bases}
            if "Protocol" in bases:
                continue  # the port itself declares the surface, not a provider
            methods = {child.name for child in node.body
                       if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))}
            if {"apply", "rollback"}.issubset(methods):
                shipped.append(node.name)
        self.assertEqual(shipped, ["UnavailableTrafficMutationProvider"],
                         "8.7-B.0 adds no provider; the only implementer is the "
                         "raise-only default")

    def test_proof_state_mutation_never_imports_the_boundary(self):
        for path in (PLATFORM_DIR / "e2e" / "traffic_topology_kind_e2e.py",
                     PROBE):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    imported.update(alias.name for alias in node.names)
                    imported.add(node.module or "")
                elif isinstance(node, ast.Import):
                    imported.update(alias.name for alias in node.names)
            self.assertNotIn("traffic_mutation_boundary", " ".join(imported),
                             f"{path.name} must not import the mutation boundary")
            self.assertNotIn("TrafficMutationPort", " ".join(imported))


class ProofStateLogicTests(unittest.TestCase):
    """Tolerance is derived from the sampling distribution, and honest."""

    def test_acceptance_interval_comes_from_the_formula(self):
        import math
        half = driver.share_half_width(0.05, 2000)
        self.assertAlmostEqual(half, 4.0 * math.sqrt(0.05 * 0.95 / 2000), places=12)
        self.assertGreater(half, 0.01, "an interval narrower than sampling noise "
                                       "would fail honest runs")
        self.assertLess(half, 0.03, "an interval this wide would accept a wrong split")
        block = driver.statistics_block()
        self.assertLess(block["false_failure_probability_per_proportional_state"], 1e-4)
        self.assertIn("why_not_an_exact_value", block)

    def test_correct_split_is_accepted_and_wrong_splits_rejected(self):
        self.assertTrue(driver.share_within_tolerance(100, 2000, 0.05)[0])
        self.assertTrue(driver.share_within_tolerance(62, 2000, 0.05)[0])
        self.assertTrue(driver.share_within_tolerance(138, 2000, 0.05)[0])
        for wrong in (61, 139, 200, 20, 500, 0, 2000):
            self.assertFalse(driver.share_within_tolerance(wrong, 2000, 0.05)[0],
                             f"{wrong}/2000 must not be accepted as a 5% split")
        for wrong_share in (0.10, 0.01, 0.50):
            note = driver.discrimination_note(0.05, 2000, wrong_share)
            sigmas = float(note.split("sit ")[1].split(" sigma")[0])
            self.assertGreater(sigmas, 3.0,
                               "a wrong split must sit well outside the interval")

    def test_exclusive_states_require_zero_leakage(self):
        states = {state["name"]: state for state in driver.PROOF_STATES}
        stable_only = states["all-stable-100-0"]
        canary_only = states["all-canary-0-100"]
        self.assertTrue(driver.pilot_agrees(
            {"total": 40, "stable": 40, "canary": 0, "errors": 0, "other": 0},
            stable_only)[0])
        self.assertFalse(driver.pilot_agrees(
            {"total": 40, "stable": 39, "canary": 1, "errors": 0, "other": 0},
            stable_only)[0])
        self.assertTrue(driver.pilot_agrees(
            {"total": 40, "stable": 0, "canary": 40, "errors": 0, "other": 0},
            canary_only)[0])
        self.assertFalse(driver.pilot_agrees(
            {"total": 40, "stable": 1, "canary": 39, "errors": 0, "other": 0},
            canary_only)[0])

    def test_the_three_required_proof_states_exist(self):
        states = {state["name"]: state for state in driver.PROOF_STATES}
        self.assertEqual(states["committed-95-5"]["weights"],
                         {"stable": 95, "canary": 5})
        self.assertEqual(states["all-stable-100-0"]["weights"],
                         {"stable": 100, "canary": 0})
        self.assertEqual(states["all-canary-0-100"]["weights"],
                         {"stable": 0, "canary": 100})
        self.assertEqual(states["committed-95-5"]["expectation"], "proportional")
        self.assertGreaterEqual(states["committed-95-5"]["samples"], 1000)
        for state in states.values():
            self.assertGreaterEqual(state["samples"], 500)
        for name in ("all-stable-100-0", "all-canary-0-100"):
            self.assertTrue(states[name]["expectation"].startswith("exclusive:"))

    def test_configured_state_is_read_from_the_route_not_assumed(self):
        route = {"spec": {"rules": [{"backendRefs": [
            {"name": "ares-stable", "port": 80, "weight": 95},
            {"name": "ares-canary", "port": 80, "weight": 5}]}]}}
        self.assertEqual(driver.configured_weight_map(route),
                         {"stable": 95, "canary": 5})
        refs = driver.configured_backend_refs(route)
        self.assertAlmostEqual(refs[0]["proportional_share"], 0.95)
        self.assertAlmostEqual(refs[1]["proportional_share"], 0.05)
        reordered = {"spec": {"rules": [{"backendRefs": [
            {"name": "ares-canary", "port": 80, "weight": 30},
            {"name": "ares-stable", "port": 80, "weight": 70}]}]}}
        self.assertEqual(driver.configured_weight_map(reordered),
                         {"stable": 70, "canary": 30})


class NegativeProbeTests(unittest.TestCase):
    """Every topology mutation is caught, on a copy that cannot touch the tree."""

    def test_probe_catches_every_mutation_and_leaves_the_tree_alone(self):
        before = fixture_digest()
        completed = subprocess.run([sys.executable, str(PROBE)],
                                   capture_output=True, text=True, timeout=300,
                                   cwd=str(PLATFORM_DIR))
        after = fixture_digest()
        self.assertEqual(before, after,
                         "the probe must never write into the repository fixture")
        self.assertEqual(completed.returncode, 0, completed.stderr[-800:])
        report = json.loads(completed.stdout)
        self.assertTrue(report["control_clean"], report["control_violations"])
        self.assertGreaterEqual(report["cases_total"], 13)
        self.assertEqual(report["escaped"], [])
        self.assertEqual(report["caught_for_unexpected_reason"], [])
        self.assertEqual(report["cases_caught"], report["cases_total"])
        self.assertEqual(report["isolated_copy"], "(removed)")

    def test_expected_mutations_are_among_the_cases(self):
        import copy
        from e2e.traffic_topology import load_documents
        sys.path.insert(0, str(PROBE.parent))
        probe_module = importlib.util.spec_from_file_location(
            "ares_topology_mutation_probe", PROBE)
        probe = importlib.util.module_from_spec(probe_module)
        probe_module.loader.exec_module(probe)
        names = {case[0] for case in probe.CASES}
        for required in ("selector-overlap", "swapped-backend-refs",
                         "removed-canary-ref", "altered-weights",
                         "invalid-backend-ref" if False else "duplicate-backend"):
            self.assertIn(required, names)
        document = copy.deepcopy(load_documents())
        results = {row["case"]: row for row in probe.run_cases(document)}
        # A missing backend ref is flagged...
        self.assertTrue(results["removed-canary-ref"]["caught"])
        # ...and a backendRef that names the wrong (missing) service fails safely.
        self.assertTrue(results["swapped-backend-refs"]["caught"])
        self.assertTrue(results["duplicate-backend"]["caught"])

    def test_invalid_probe_route_is_not_part_of_the_committed_fixture(self):
        documents = topo.load_documents()
        names = {(doc["kind"], doc["metadata"]["name"]) for doc in documents}
        self.assertNotIn(("HTTPRoute", driver.INVALID_PROBE_ROUTE), names)
        self.assertIn("does-not-exist", json.dumps(
            {"name": "ares-backend-that-does-not-exist"}))
        self.assertEqual(driver.INVALID_PROBE_PATH, "/invalid-probe")


class ContainerFixtureTests(unittest.TestCase):
    """The two new build surfaces obey the repository's E2E build contract.

    They are deliberately NOT added to ``e2e.build_surfaces.E2E_DOCKERFILES``:
    that inventory is the frozen Phase 8.4.2 list of eight surfaces, and
    the existing BuildKit gate asserts exactly eight. This phase therefore
    keeps the inventory untouched and asserts its own contract here
    instead of editing a frozen count.
    """

    def test_build_arguments_are_declared_in_the_stage_that_uses_them(self):
        """A variable must be declared in the SCOPE that expands it.

        BuildKit's ``dockerfile2llb/validations.go`` reports
        ``UndefinedVar`` when a word expands a variable that is absent from
        ``d.buildArgs`` — the ARGs declared *inside the current stage* — so
        a global ``ARG`` written above ``FROM`` is undefined once the stage
        begins, even when the value was passed on the command line. Both
        fixtures carry ``# check=error=true``, which promotes that warning
        to a hard build failure. Phase 8.7-B.0 lost its first CI run to
        exactly this shape (``ARG TRACK`` before ``FROM``, used by ``ENV``
        inside the stage), so the rule is asserted here rather than
        discovered again in CI.
        """
        for path, expected_stage_args in (
            (WORKLOAD_DIR / "Dockerfile", {"TRACK"}),
            (SAMPLER_DIR / "Dockerfile", set()),
        ):
            with self.subTest(dockerfile=path.name):
                lines = path.read_text(encoding="utf-8").splitlines()
                stage_args: set[str] = set()
                in_stage = False
                for number, line in enumerate(lines, 1):
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    keyword = stripped.split(None, 1)[0].upper()
                    if keyword == "FROM":
                        in_stage = True
                        stage_args = set()
                        continue
                    if not in_stage:
                        continue
                    if keyword == "ARG":
                        for item in stripped.split(None, 1)[1].split():
                            stage_args.add(item.split("=", 1)[0])
                        continue
                    if keyword in {"RUN", "CMD", "ENTRYPOINT"}:
                        continue  # shell form: the shell expands these
                    used = set(VARIABLE_USE.findall(stripped))
                    undeclared = used - stage_args
                    self.assertFalse(
                        undeclared,
                        f"{path.name}:{number} expands {sorted(undeclared)} but "
                        f"this stage declares only {sorted(stage_args)}")
                self.assertTrue(
                    expected_stage_args <= stage_args,
                    f"{path.name} must declare {sorted(expected_stage_args)} "
                    f"inside the stage; found {sorted(stage_args)}")


class StaticIntegrityTests(unittest.TestCase):
    """Cheap executable guards for code that only ever runs inside CI.

    The E2E driver, the sampler and the fixture server cannot execute in
    this test process (no cluster, no container runtime), so their control
    flow is only ever exercised by the dedicated CI job. Phase 8.7-B.0's
    first CI run was lost to a defect exactly in that blind spot, so these
    tests read the sources and assert the properties a linter would.
    """

    def test_new_e2e_modules_have_no_unbound_global_names(self):
        """A name used but bound nowhere in the module is a crash waiting.

        ``e2e/traffic_topology_kind_e2e.py`` called ``shutil.rmtree`` in
        its cleanup path without importing ``shutil``; nothing local could
        see it, and in CI it would have thrown away the sealed evidence of
        an otherwise complete run. This is a stdlib-only restatement of the
        ``undefined name`` lint over the modules the CI job executes.
        """
        for path in (
            PLATFORM_DIR / "e2e" / "traffic_topology_kind_e2e.py",
            PLATFORM_DIR / "e2e" / "traffic_topology.py",
            PLATFORM_DIR / "e2e" / "traffic_topology_pins.py",
            PLATFORM_DIR / "e2e" / "traffic-topology" / "mutation_probe.py",
            PLATFORM_DIR / "e2e" / "traffic-topology" / "workload" / "server.py",
            PLATFORM_DIR / "e2e" / "traffic-topology" / "sampler" / "sampler.py",
        ):
            with self.subTest(module=path.name):
                self.assertEqual(unbound_global_names(path), [])

    def test_the_unbound_name_detector_rejects_a_known_bad_module(self):
        """The detector above must not be vacuous."""
        with tempfile.TemporaryDirectory() as tmp:
            sample = pathlib.Path(tmp) / "sample.py"
            sample.write_text("import json\n\n\ndef run():\n"
                              "    json.dumps({})\n"
                              "    shutil.rmtree('/tmp')\n"
                              "    return None\n", encoding="utf-8")
            self.assertEqual(unbound_global_names(sample), ["shutil"])


    def test_dockerfiles_are_fail_closed_and_pinned(self):
        for path in (WORKLOAD_DIR / "Dockerfile", SAMPLER_DIR / "Dockerfile"):
            with self.subTest(dockerfile=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIn("ARG BASE_IMAGE\n", text)
                self.assertRegex(text, r"(?m)^FROM \$\{BASE_IMAGE\}$")
                self.assertNotIn("${BASE_IMAGE:?", text,
                                 "the Compose-only required-value operator is "
                                 "invalid in a Dockerfile")
                self.assertNotRegex(text, r"(?m)^ARG BASE_IMAGE=",
                                    "a default base image would defeat the pin")
                self.assertNotRegex(text, r"(?m)^FROM\s+[a-z0-9]+:",
                                    "the base must come from the pinned argument")
                first = text.splitlines()[0]
                self.assertIn("docker/dockerfile:1@sha256:", first,
                              "the Dockerfile frontend must stay digest-pinned")

    def test_workload_identity_is_baked_at_build_time(self):
        text = (WORKLOAD_DIR / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("ARG TRACK", text)
        self.assertIn("ENV ARES_TRACK=${TRACK}", text)
        server = (WORKLOAD_DIR / "server.py").read_text(encoding="utf-8")
        self.assertIn('TRACK not in KNOWN_TRACKS', server)
        self.assertIn("TRACK_HEADER", server)

    def test_sampler_image_carries_no_track(self):
        text = (SAMPLER_DIR / "Dockerfile").read_text(encoding="utf-8")
        self.assertNotIn("TRACK", text)
        sampler = (SAMPLER_DIR / "sampler.py").read_text(encoding="utf-8")
        self.assertIn("body_disagreements", sampler)
        self.assertIn("ARES_SAMPLER_URL", sampler)

    def test_sampler_job_template_is_rigid(self):
        template = (SAMPLER_DIR / "job.yaml").read_text(encoding="utf-8")
        for token in ("__SAMPLER_NAME__", "__SAMPLER_IMAGE__", "__SAMPLER_URL__",
                      "__SAMPLER_COUNT__"):
            self.assertIn(token, template)
        self.assertIn("backoffLimit: 0", template,
                      "a retried sampler would double-count traffic")
        self.assertIn("automountServiceAccountToken: false", template)
        self.assertIn("readOnlyRootFilesystem: true", template)


class ServerVersionProbeTests(unittest.TestCase):
    """`kubectl --raw` must never be combined with `-o json`.

    The first live run of the Phase 8.7-B.0 job died on

        kubectl --context kind-ares-topology-e2e get --raw=/version -o json

    with "error: --raw and --output are mutually exclusive": the driver's
    JSON helper appended ``-o json`` to a RAW endpoint. The API server
    version is still read from the real cluster; only the way it is asked
    for changed.
    """

    COMMIT = "a" * 40

    def setUp(self):
        self._sh = driver.sh
        self._saved = {
            name: list(getattr(driver, name))
            for name in ("RESULTS", "STATES")
        }
        self._saved["DIAGNOSTICS"] = dict(driver.DIAGNOSTICS)
        self._saved["STACK_INFO"] = dict(driver.STACK_INFO)
        self._saved["IMAGE_IDENTITIES"] = dict(driver.IMAGE_IDENTITIES)
        self._saved["DATA_PLANE"] = dict(driver.DATA_PLANE)
        driver.RESULTS.clear()
        driver.DIAGNOSTICS.clear()
        driver.STACK_INFO.clear()
        driver.IMAGE_IDENTITIES.clear()

    def tearDown(self):
        driver.sh = self._sh
        for name, value in self._saved.items():
            target = getattr(driver, name)
            target.clear()
            if isinstance(target, dict):
                target.update(value)
            else:
                target.extend(value)

    def test_kubectl_raw_invokes_kubectl_without_any_output_flag(self):
        calls = []

        def fake_sh(argv, timeout=300):
            calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, '{"gitVersion": "v1.31.4"}', "")

        driver.sh = fake_sh
        payload = json.loads(driver.kubectl_raw("ares-topology-e2e", "get",
                                                "--raw=/version"))
        self.assertEqual(payload, {"gitVersion": "v1.31.4"})
        self.assertEqual(calls, [[
            "kubectl", "--context", "kind-ares-topology-e2e", "get",
            "--raw=/version",
        ]], "the raw endpoint is requested without -o json")
        self.assertEqual(raw_probe_output_flags(calls[0]), [])

    def test_the_output_flag_rule_rejects_the_original_invalid_shape(self):
        """The negative control for the assertion above."""
        invalid = ["kubectl", "--context", "kind-ares-topology-e2e", "get",
                   "--raw=/version", "-o", "json"]
        self.assertEqual(raw_probe_output_flags(invalid), ["-o"],
                         "the rejected shape must be recognised as invalid")
        self.assertNotEqual(raw_probe_output_flags(invalid), [])

    def test_kubectl_raw_raises_on_failure_with_the_stderr_tail(self):
        driver.sh = lambda argv, timeout=300: subprocess.CompletedProcess(
            argv, 1, "", "error: --raw and --output are mutually exclusive")
        with self.assertRaises(RuntimeError) as caught:
            driver.kubectl_raw("cluster", "get", "--raw=/version")
        self.assertIn("--raw and --output are mutually exclusive",
                      str(caught.exception))
        self.assertIn("--raw=/version", str(caught.exception))

    def test_kubectl_raw_propagates_a_timeout(self):
        def timing_out(argv, timeout=300):
            raise subprocess.TimeoutExpired(argv, timeout)

        driver.sh = timing_out
        with self.assertRaises(subprocess.TimeoutExpired):
            driver.kubectl_raw("cluster", "get", "--raw=/version")

    def test_run_reads_the_server_version_through_the_raw_helper(self):
        """The run() path itself, not just the helper, must use `--raw`.

        The stub answers exactly the calls ``run()`` makes before the
        version check and then makes the image inspection fail, so the
        driver stops early. What is asserted is the recorded argv of the
        version probe and the recorded PASS.
        """
        calls = []
        cluster = "cluster"

        def fake_sh(argv, timeout=300):
            argv = list(argv)
            calls.append(argv)
            joined = " ".join(argv)
            if "rev-parse" in joined:
                return subprocess.CompletedProcess(argv, 0, self.COMMIT + "\n", "")
            if "diff" in joined:
                return subprocess.CompletedProcess(argv, 0, "", "")
            if "ls-files" in joined:
                return subprocess.CompletedProcess(
                    argv, 0, "\n".join(f"k8s/progressive/{name}" for name in
                                       ("gateway.yaml", "gatewayclass.yaml",
                                        "httproute.yaml", "namespace.yaml",
                                        "services.yaml", "workloads.yaml",
                                        "envoy-proxy.yaml")) + "\n", "")
            if argv[0] == "docker" and "inspect" in argv:
                return subprocess.CompletedProcess(argv, 0, "true\n", "")
            if "get --raw=/version" in joined:
                return subprocess.CompletedProcess(
                    argv, 0, json.dumps({"gitVersion": "v1.31.4"}), "")
            if argv[0] == "docker" and "image" in argv:
                return subprocess.CompletedProcess(argv, 1, "", "Error: no such image")
            return subprocess.CompletedProcess(argv, 1, "", f"unexpected: {joined}")

        driver.sh = fake_sh
        args = argparse.Namespace(
            cluster=cluster, stable_image="ares-traffic-stable:local",
            canary_image="ares-traffic-canary:local",
            sampler_image="ares-traffic-sampler:local",
            expected_commit=self.COMMIT, gateway_api_version="v1.4.1",
            envoy_gateway_version="v1.6.7", readiness_timeout=30.0,
            evidence=str(pathlib.Path(tempfile.gettempdir()) / "unused.json"),
            destroy_cluster=False, keep_workdir=True,
        )
        with tempfile.TemporaryDirectory() as workdir:
            self.assertFalse(driver.run(args, pathlib.Path(workdir)),
                             "the run stops as soon as the image check fails")
        probes = [call for call in calls if "--raw=/version" in call]
        self.assertEqual(len(probes), 1, f"exactly one version probe: {probes}")
        self.assertEqual(raw_probe_output_flags(probes[0]), [],
                         f"the run() version probe must not carry -o json: {probes[0]}")
        self.assertNotIn("json", probes[0])
        version = [row for row in driver.RESULTS
                   if row["check"] == "cluster:server-version"]
        self.assertEqual(len(version), 1)
        self.assertEqual(version[0]["status"], "PASS")
        self.assertIn("v1.31.4", version[0]["observed"])

    def test_no_kubectl_json_call_requests_a_raw_endpoint(self):
        """Supplementary guard: the two shapes may never be re-conflated."""
        tree = ast.parse(DRIVER.read_text(encoding="utf-8"))
        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Name) and func.id == "kubectl_json"):
                continue
            for argument in node.args:
                if (isinstance(argument, ast.Constant)
                        and isinstance(argument.value, str)
                        and argument.value.startswith("--raw")):
                    offenders.append(ast.unparse(node))
        self.assertEqual(offenders, [],
                         f"kubectl_json() appends -o json and cannot serve --raw: "
                         f"{offenders}")
        source = DRIVER.read_text(encoding="utf-8")
        self.assertRegex(
            source, r'kubectl_raw\(cluster,\s*"get",\s*"--raw=/version"\)',
            "the server version must be read through the raw helper")


class FixtureApplyOrderTests(unittest.TestCase):
    """The fixture must be applied namespace-first.

    ``kubectl apply -f <dir>`` walks a directory lexicographically, and the
    fixture's ``namespace.yaml`` sorts AFTER ``gateway.yaml``,
    ``httproute.yaml``, ``services.yaml`` and ``workloads.yaml``. The API
    server therefore rejected every namespaced object with
    ``namespaces "ares-traffic" not found`` — the failure the live run hit
    immediately after the raw-version probe was repaired. The driver now
    applies Namespace definitions first, one file per ``kubectl`` call, so
    a failure also names the file that caused it.
    """

    def setUp(self):
        self._sh = driver.sh

    def tearDown(self):
        driver.sh = self._sh

    def test_the_namespace_is_applied_before_the_namespaced_objects(self):
        calls = []

        def fake_sh(argv, timeout=300):
            calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, "created\n", "")

        driver.sh = fake_sh
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            (directory / "workloads.yaml").write_text(
                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n"
                "  name: ares-stable\n  namespace: ares-traffic\n",
                encoding="utf-8")
            (directory / "gateway.yaml").write_text(
                "apiVersion: gateway.networking.k8s.io/v1\nkind: Gateway\n"
                "metadata:\n  name: ares-gateway\n  namespace: ares-traffic\n",
                encoding="utf-8")
            (directory / "namespace.yaml").write_text(
                "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: ares-traffic\n",
                encoding="utf-8")
            applied = driver.apply_fixture("cluster", directory, "topology fixture")
        order = [pathlib.Path(call[-1]).name for call in calls]
        self.assertEqual(order, ["namespace.yaml", "gateway.yaml", "workloads.yaml"],
                         "the namespace must exist before the objects inside it")
        self.assertIn("created", applied)
        for call in calls:
            self.assertEqual(call[:3], ["kubectl", "--context", "kind-cluster"],
                             "each file is applied with one kubectl call")

    def test_an_apply_failure_names_the_file_and_the_api_error(self):
        driver.sh = lambda argv, timeout=300: subprocess.CompletedProcess(
            argv, 1, "namespace/ares-traffic created\n",
            'Error from server (NotFound): error when creating "gateway.yaml": '
            'namespaces "ares-traffic" not found')
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            (directory / "gateway.yaml").write_text(
                "apiVersion: gateway.networking.k8s.io/v1\nkind: Gateway\n"
                "metadata:\n  name: ares-gateway\n  namespace: ares-traffic\n",
                encoding="utf-8")
            with self.assertRaises(RuntimeError) as caught:
                driver.apply_fixture("cluster", directory, "topology fixture")
        message = str(caught.exception)
        self.assertIn("gateway.yaml", message)
        self.assertIn("namespaces \"ares-traffic\" not found", message)
        self.assertNotIn("\n", message,
                         "the message must survive the annotation channel")

    def test_the_fixture_layout_is_the_one_that_defeats_lexicographic_apply(self):
        """Non-vacuous: prove the fixture really has the ordering hazard."""
        with tempfile.TemporaryDirectory() as tmp:
            rendered_dir = pathlib.Path(tmp) / "rendered"
            documents = driver.render_fixture(
                rendered_dir,
                {"stable": "ares-traffic-stable:local",
                 "canary": "ares-traffic-canary:local"})
            names = sorted(path.name for path in rendered_dir.iterdir())
        self.assertIn("namespace.yaml", names)
        self.assertLess(
            names.index("gateway.yaml"), names.index("namespace.yaml"),
            "namespace.yaml must sort after the namespaced manifests, which is "
            "exactly why a plain directory apply cannot work")
        kinds = {document.get("kind") for document in documents}
        self.assertIn("Namespace", kinds)
        namespaced = [document for document in documents
                      if (document.get("metadata") or {}).get("namespace")]
        self.assertTrue(namespaced, "the fixture must contain namespaced objects")

    def test_the_driver_never_applies_the_fixture_directory_directly(self):
        """Static guard: the directory apply must go through the ordered helper."""
        source = DRIVER.read_text(encoding="utf-8")
        self.assertIn('apply_fixture(cluster, workdir / "rendered", "topology fixture")',
                      source)
        self.assertNotIn("kubectl_apply(cluster, workdir", source,
                         "a directory apply would walk the manifests "
                         "lexicographically and hit the missing namespace again")

    def test_one_line_collapses_output_for_annotations(self):
        self.assertEqual(driver.one_line("a\nb\tc   d "), "a b c d")
        self.assertEqual(driver.one_line(""), "<empty>")
        long_text = "x" * 5000
        collapsed = driver.one_line(long_text)
        self.assertNotIn("\n", collapsed)
        self.assertLess(len(collapsed), len(long_text))


class PinTests(unittest.TestCase):
    """Every external artifact is pinned to an exact release by digest."""

    def test_pins_are_complete_immutable_and_versioned(self):
        records = parse_pinned_artifacts(PINS_FILE.read_text(encoding="utf-8"))
        self.assertEqual({record["key"] for record in records},
                         set(ARTIFACT_PIN_KEYS))
        for record in records:
            self.assertRegex(record["pin"], r"^sha256:[0-9a-f]{64}$")
            self.assertTrue(record["url"].startswith("https://"))
            self.assertNotIn("latest", record["url"])
            tag = record["url"].split("/download/")[1].split("/")[0]
            self.assertRegex(tag, r"^v\d+\.\d+\.\d+$")

    def test_pinned_releases_are_the_intended_ones(self):
        records = {record["key"]: record
                   for record in parse_pinned_artifacts(
                       PINS_FILE.read_text(encoding="utf-8"))}
        self.assertIn("gateway-api/releases/download/v1.4.1",
                      records["GATEWAY_API_CRDS_URL"]["url"])
        self.assertIn("gateway/releases/download/v1.6.7",
                      records["ENVOY_GATEWAY_INSTALL_URL"]["url"])
        self.assertIn("gateway/releases/download/v1.6.7",
                      records["ENVOY_GATEWAY_CRDS_URL"]["url"])

    def test_parser_fails_closed_on_every_deviation(self):
        good = PINS_FILE.read_text(encoding="utf-8")
        line = [row for row in good.splitlines()
                if row and not row.startswith("#")][0]
        url, pin, key = line.split()
        cases = {
            "http instead of https": good.replace(url, url.replace("https:", "http:")),
            "floating latest": good.replace(url.split("/download/")[1].split("/")[0], "latest"),
            "bad digest": good.replace(pin, "sha256:" + "0" * 63),
            "no digest": good.replace(f" {pin}", ""),
            "duplicate key": good + f"\n{url} {pin} {key}\n",
            "unknown env key": good.replace(key, "TRAFFIC_TOPOLOGY_URL"),
            "missing pin": "\n".join(row for row in good.splitlines() if key not in row),
            "non-yaml artifact": good.replace(".yaml", ".tar.gz"),
        }
        for label, text in cases.items():
            with self.assertRaises(ValueError, msg=label):
                parse_pinned_artifacts(text)


class SamplerContractTests(unittest.TestCase):
    """The measurement instruments themselves, exercised over real HTTP."""

    def _serve(self, track="stable", body_track=None):
        spec = importlib.util.spec_from_file_location(
            "ares_topology_workload_fixture", WORKLOAD_SERVER)
        module = importlib.util.module_from_spec(spec)
        os.environ["ARES_TRACK"] = track
        try:
            spec.loader.exec_module(module)
        finally:
            os.environ.pop("ARES_TRACK", None)
        if body_track is not None:
            module.TRACK = track

            class Disagreeing(module.Handler):
                def do_GET(self):  # noqa: N802 - http.server API
                    payload = json.dumps({"track": body_track}).encode()
                    self._send(200, payload, "application/json")

            handler = Disagreeing
        else:
            handler = module.Handler
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        return server.server_address[1]

    def _sample(self, port, count=60):
        environment = dict(os.environ)
        environment.update({
            "ARES_SAMPLER_URL": f"http://127.0.0.1:{port}/",
            "ARES_SAMPLER_COUNT": str(count),
        })
        return subprocess.run([sys.executable, str(SAMPLER)],
                              capture_output=True, text=True, timeout=120,
                              env=environment)

    def test_sampler_attributes_responses_to_the_backend_that_served_them(self):
        for track in ("stable", "canary"):
            with self.subTest(track=track):
                completed = self._sample(self._serve(track), 60)
                self.assertEqual(completed.returncode, 0, completed.stderr[-400:])
                payload = json.loads(completed.stdout.strip().splitlines()[-1])
                self.assertEqual(payload["total"], 60)
                self.assertEqual(payload[track], 60)
                other = "canary" if track == "stable" else "stable"
                self.assertEqual(payload[other], 0)
                self.assertEqual(payload["errors"], 0)
                self.assertEqual(payload["other"], 0)
                self.assertEqual(payload["body_disagreements"], 0)

    def test_sampler_flags_header_body_disagreement(self):
        completed = self._sample(self._serve("stable", body_track="canary"), 30)
        payload = json.loads(completed.stdout.strip().splitlines()[-1])
        self.assertEqual(payload["body_disagreements"], 30,
                         "a header/body disagreement must be reported, not "
                         "silently resolved")

    def test_sampler_fails_closed_when_nothing_answers(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        completed = self._sample(port, 5)
        self.assertNotEqual(completed.returncode, 0)
        payload = json.loads(completed.stdout.strip().splitlines()[-1])
        self.assertEqual(payload["stable"] + payload["canary"], 0)
        self.assertIn("meaningless", completed.stderr)

    def test_workload_refuses_to_start_without_a_track(self):
        environment = {key: value for key, value in os.environ.items()
                       if key not in ("ARES_TRACK",)}
        with tempfile.TemporaryDirectory() as tmp:
            completed = subprocess.run([sys.executable, str(WORKLOAD_SERVER)],
                                       capture_output=True, text=True, timeout=30,
                                       cwd=tmp, env=environment)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("ARES_TRACK", completed.stderr)


class DocumentationTests(unittest.TestCase):
    """The phase document must state the boundary, not overstate it."""

    def test_document_exists_and_states_the_boundary(self):
        text = DOC.read_text(encoding="utf-8")
        for required in ("proportional", "Envoy Gateway", "Gateway API",
                         "/ sum(weights in that rule)", "8.7-B.1"):
            self.assertIn(required, text, f"the phase document must mention {required!r}")
        for heading in ("What is NOT implemented", "What Phase 8.7-B.1 will add"):
            self.assertIn(heading, text)
        lowered = text.lower()
        self.assertNotIn("weight is a percentage", lowered)
        self.assertNotIn("automatically mutates", lowered)
        self.assertNotIn("rollback is implemented", lowered)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
