"""Negative (mutation) probe for the Phase 8.7-B.0 topology contract.

Purpose: prove the routing proof actually DEPENDS on the topology, by
tampering with the manifests and requiring the verifier to reject each
tampered variant. A probe that only ever ran against a good fixture would
prove nothing.

Isolation guarantee: every mutation is applied to a byte-for-byte COPY of
``k8s/progressive/`` inside a fresh ``tempfile.mkdtemp()`` directory. The
repository working tree is opened read-only and is never written to, so
running this probe cannot change the developer's branch or dirty the
checkout. (The copy is also kept on disk after the run when ``--keep`` is
passed, purely to make a failure inspectable.)

Exit code is 0 only when the control fixture verifies clean AND every
single mutation is caught. Any escaped mutation is printed with its
violation-free result and exits 1.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import shutil
import sys
import tempfile
from typing import Any, Callable, Dict, List, Mapping, Sequence

# <platform>/e2e/traffic-topology/<this file> -> put <platform> on sys.path
_PLATFORM_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _PLATFORM_DIR)

import yaml  # noqa: E402

from e2e.traffic_topology import (  # noqa: E402
    DEPLOYMENT,
    GATEWAY,
    HTTP_ROUTE,
    SERVICE,
    TOPOLOGY_DIR,
    load_documents,
    verify_documents,
)

Mutation = Callable[[List[Dict[str, Any]]], None]


def _doc(documents: Sequence[Mapping[str, Any]], kind: str, name: str) -> Mapping[str, Any]:
    for document in documents:
        if document.get("kind") == kind and (document.get("metadata") or {}).get("name") == name:
            return document
    raise AssertionError(f"fixture is missing {kind}/{name}")


def _rule(documents: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    route = _doc(documents, "HTTPRoute", HTTP_ROUTE)
    return route["spec"]["rules"][0]


# --- the mutations ---------------------------------------------------------


def selector_overlap(documents: List[Dict[str, Any]]) -> None:
    """Stable Service loses its `track` key and starts selecting both."""
    service = _doc(documents, "Service", SERVICE["stable"])
    service["spec"]["selector"].pop("track")


def swapped_backend_refs(documents: List[Dict[str, Any]]) -> None:
    refs = _rule(documents)["backendRefs"]
    refs[0]["name"], refs[1]["name"] = refs[1]["name"], refs[0]["name"]


def removed_canary_ref(documents: List[Dict[str, Any]]) -> None:
    refs = _rule(documents)["backendRefs"]
    refs[:] = [ref for ref in refs if ref["name"] != SERVICE["canary"]]


def altered_weights(documents: List[Dict[str, Any]]) -> None:
    for ref in _rule(documents)["backendRefs"]:
        ref["weight"] = 90 if ref["name"] == SERVICE["stable"] else 10


def zero_weight_sum(documents: List[Dict[str, Any]]) -> None:
    for ref in _rule(documents)["backendRefs"]:
        ref["weight"] = 0


def missing_weight_field(documents: List[Dict[str, Any]]) -> None:
    for ref in _rule(documents)["backendRefs"]:
        if ref["name"] == SERVICE["canary"]:
            ref.pop("weight")


def duplicate_backend(documents: List[Dict[str, Any]]) -> None:
    refs = _rule(documents)["backendRefs"]
    refs[1]["name"] = refs[0]["name"]


def tls_listener(documents: List[Dict[str, Any]]) -> None:
    gateway = _doc(documents, "Gateway", GATEWAY)
    listener = gateway["spec"]["listeners"][0]
    listener["protocol"] = "HTTPS"
    listener["tls"] = {"mode": "Terminate", "certificateRefs": [{"name": "self-signed"}]}


def extra_service_port(documents: List[Dict[str, Any]]) -> None:
    service = _doc(documents, "Service", SERVICE["canary"])
    service["spec"]["ports"].append({"name": "metrics", "port": 9090, "targetPort": 8080})


def floating_image_tag(documents: List[Dict[str, Any]]) -> None:
    deployment = _doc(documents, "Deployment", DEPLOYMENT["stable"])
    deployment["spec"]["template"]["spec"]["containers"][0]["image"] = "devops-registry/ares-stable:latest"


def track_env_mismatch(documents: List[Dict[str, Any]]) -> None:
    deployment = _doc(documents, "Deployment", DEPLOYMENT["canary"])
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    for item in container["env"]:
        if item["name"] == "ARES_TRACK":
            item["value"] = "stable"


def extra_route(documents: List[Dict[str, Any]]) -> None:
    rogue = copy.deepcopy(_doc(documents, "HTTPRoute", HTTP_ROUTE))
    rogue["metadata"]["name"] = "ares-route-shadow"
    documents.append(rogue)


def controller_swap(documents: List[Dict[str, Any]]) -> None:
    """The class stops being Envoy Gateway — i.e. no real implementation."""
    gateway_class = _doc(documents, "GatewayClass", "ares-gatewayclass")
    gateway_class["spec"]["controllerName"] = "example.com/not-a-real-controller"


CASES: Sequence[tuple] = (
    ("selector-overlap", selector_overlap, "also select"),
    ("swapped-backend-refs", swapped_backend_refs, "initial weights"),
    ("removed-canary-ref", removed_canary_ref, "two backends"),
    ("altered-weights", altered_weights, "initial weights"),
    ("zero-weight-sum", zero_weight_sum, "positive weight sum"),
    ("missing-weight-field", missing_weight_field, "explicit integer weight"),
    ("duplicate-backend", duplicate_backend, "DISTINCT services"),
    ("tls-listener", tls_listener, "must not terminate TLS"),
    ("extra-service-port", extra_service_port, "exactly one port"),
    ("floating-image-tag", floating_image_tag, "immutable reference"),
    ("track-env-mismatch", track_env_mismatch, "ARES_TRACK=canary"),
    ("extra-route", extra_route, "unexpected HTTPRoute name"),
    ("controller-swap", controller_swap, "controllerName"),
)


def run_cases(documents: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Run every mutation against a deep copy; return per-case results."""
    results: List[Dict[str, Any]] = []
    for name, mutate, needle in CASES:
        mutated = copy.deepcopy(list(documents))
        mutate(mutated)
        # Round-trip through YAML so a mutation cannot get lost or be
        # "caught" for a serialisation artefact rather than its content.
        serialized = yaml.safe_dump_all(mutated, sort_keys=True)
        reloaded = list(yaml.safe_load_all(serialized))
        violations = verify_documents(reloaded)
        caught = bool(violations)
        matched = any(needle in violation for violation in violations)
        results.append(
            {
                "case": name,
                "caught": caught,
                "caught_for_expected_reason": matched,
                "expected_reason": needle,
                "violations": violations,
            }
        )
    return results


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", default=TOPOLOGY_DIR)
    parser.add_argument("--keep", action="store_true", help="keep the isolated copy")
    args = parser.parse_args(argv)

    workdir = tempfile.mkdtemp(prefix="ares-topology-probe-")
    isolated = os.path.join(workdir, "progressive")
    shutil.copytree(args.fixture, isolated)

    try:
        documents = load_documents(isolated)
        control_violations = verify_documents(documents)
        results = run_cases(documents)
    finally:
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)

    escaped = [r["case"] for r in results if not r["caught"]]
    wrong_reason = [r["case"] for r in results if r["caught"] and not r["caught_for_expected_reason"]]
    report = {
        "schema": "ares.traffic-topology.mutation-probe/1",
        "fixture": args.fixture,
        "isolated_copy": isolated if args.keep else "(removed)",
        "control_clean": not control_violations,
        "control_violations": control_violations,
        "cases_total": len(results),
        "cases_caught": len(results) - len(escaped),
        "escaped": escaped,
        "caught_for_unexpected_reason": wrong_reason,
        "results": results,
    }
    print(json.dumps(report, indent=2, sort_keys=True))

    if control_violations:
        print("::error::control fixture is not clean; the probe is meaningless", file=sys.stderr)
        return 1
    if escaped:
        print(f"::error::mutations escaped the verifier: {escaped}", file=sys.stderr)
        return 1
    if wrong_reason:
        print(f"::error::caught for an unexpected reason: {wrong_reason}", file=sys.stderr)
        return 1
    print(
        f"all {len(results)} topology mutations caught by the static verifier",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
