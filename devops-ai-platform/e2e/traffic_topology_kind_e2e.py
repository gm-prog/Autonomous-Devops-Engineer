#!/usr/bin/env python3
"""Phase 8.7-B.0 — the weighted stable/canary routing proof.

WHAT THIS PROVES
    A real Kubernetes Gateway API topology, implemented by a real Envoy
    Gateway, genuinely splits live HTTP traffic between two independently
    addressable workloads:

        GatewayClass -> Gateway -> HTTPRoute(weighted backendRefs)
                                    -> Service ares-stable -> Deployment ares-stable
                                    -> Service ares-canary -> Deployment ares-canary

    Three proof states are established by patching the HTTPRoute weights
    and each is measured with real HTTP requests that traverse the real
    Envoy data plane. Which backend served a request is read from the
    response itself (``X-Ares-Track`` header, cross-checked against the
    JSON body), never inferred from a manifest.

THREE STATES ARE KEPT APART, ALWAYS
    ``configured``  what the HTTPRoute actually says (read back from the
                    cluster API server),
    ``controller``  what the Gateway API controller reports about it
                    (generation, Accepted, ResolvedRefs, Programmed),
    ``observed``    what the requests actually did.
    A route that says 5% is not evidence that 5% was observed; nothing
    here ever collapses one of those into another.

WEIGHT SEMANTICS
    Gateway API ``weight`` is PROPORTIONAL: a backend's share of the rule
    is weight / sum(weights). 95/5 therefore means 95/100 = 95%, and this
    driver only ever reports shares computed that way.

WHAT THIS DRIVER IS NOT
    * It is NOT an application capability. The only thing that mutates
      the route is this driver's ``kubectl patch``, inside a disposable
      cluster, for proof states. The Phase 8.7-A mutation boundary
      (``TrafficMutationPort`` / ``UnavailableTrafficMutationProvider``)
      is never imported, called or bypassed: the application still has no
      way to change traffic, and this file adds none.
    * It builds no routing of its own: no python router, no fake weighted
      service, no label trickery, one pod set per track.

FAIL CLOSED
    Every wait has an explicit deadline. On timeout the driver collects
    cluster diagnostics, records FAIL, and does NOT proceed to traffic
    assertions — a manifest that merely applied is never reported as
    working routing. Sampling starts only after the controller accepted
    the new generation AND a bounded pilot confirms the data plane
    converged.

Usage:
    python e2e/traffic_topology_kind_e2e.py \\
        --cluster ares-topology-e2e \\
        --stable-image ares-traffic-stable:local \\
        --canary-image ares-traffic-canary:local \\
        --sampler-image ares-traffic-sampler:local \\
        --expected-commit "$GITHUB_SHA" \\
        --evidence e2e-evidence/traffic-topology-e2e.json
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import subprocess  # noqa: S404 - E2E driver: orchestrates kind/kubectl
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

from e2e.evidence_provenance import provenance, seal  # noqa: E402
from e2e.helpers import parse_pinned_artifacts  # noqa: E402
from e2e.readiness import (  # noqa: E402
    ReadinessTimeout,
    collect_diagnostics,
    wait_until,
)
from e2e.traffic_topology import (  # noqa: E402
    BACKEND_PORT,
    DEPLOYMENT,
    GATEWAY,
    GATEWAY_CLASS,
    HTTP_ROUTE,
    NAMESPACE,
    SERVICE,
    TOPOLOGY_DIR,
    expected_share_of,
    load_documents,
    leftover_placeholders,
    verify_documents,
)

ENVOY_NAMESPACE = "envoy-gateway-system"
TRACK_HEADER = "X-Ares-Track"
PINS_FILE = ROOT / "e2e" / "pinned-traffic-topology.txt"
SAMPLER_JOB_TEMPLATE = ROOT / "e2e" / "traffic-topology" / "sampler" / "job.yaml"
TRACK_SERVICE = {track: SERVICE[track] for track in ("stable", "canary")}
TRACK_DEPLOYMENT = {track: DEPLOYMENT[track] for track in ("stable", "canary")}
INVALID_PROBE_PATH = "/invalid-probe"
INVALID_PROBE_ROUTE = "ares-route-invalid-probe"

#: The sampler container's request budget for the bounded convergence
#: pilot. The pilot decides only "has the data plane caught up", never a
#: tolerance: the statistical acceptance is applied to the full sample.
PILOT_SAMPLES = 40

RESULTS: List[Dict[str, Any]] = []
DIAGNOSTICS: Dict[str, str] = {}
STACK_INFO: Dict[str, Any] = {}
STATES: List[Dict[str, Any]] = []
IMAGE_IDENTITIES: Dict[str, str] = {}

#: Two-sided normal approximation to Binomial(n, p). 4 sigma keeps the
#: probability of failing a HEALTHY route at ~6.3e-5 per state while still
#: rejecting a materially wrong split with probability ~1.
SIGMA = 4.0


def notice(message: str) -> None:
    print(f"[8.7-B] {message}", flush=True)


def record(name: str, requested: str, observed: str, ok: bool) -> bool:
    RESULTS.append({"check": name, "requested": requested,
                    "observed": observed, "status": "PASS" if ok else "FAIL"})
    print(f"  [{'PASS' if ok else 'FAIL'}] {name} :: observed={observed}", flush=True)
    return ok


def sh(argv: Sequence[str], timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout)


def kubectl(cluster: str, *args: str, timeout: int = 180) -> subprocess.CompletedProcess:
    return sh(["kubectl", "--context", f"kind-{cluster}", *args], timeout=timeout)


def kubectl_json(cluster: str, *args: str, timeout: int = 180) -> Any:
    out = sh(["kubectl", "--context", f"kind-{cluster}", *args, "-o", "json"],
             timeout=timeout)
    if out.returncode != 0:
        raise RuntimeError(f"kubectl {' '.join(args)} failed: {out.stderr[-300:]}")
    return json.loads(out.stdout)


def kubectl_raw(cluster: str, *args: str, timeout: int = 180) -> str:
    """Ask kubectl for a RAW endpoint and return its bytes untouched.

    ``-o json`` is not merely unnecessary here, it is invalid: kubectl
    rejects ``--raw`` combined with ``--output`` ("--raw and --output are
    mutually exclusive", exit 1). Raw endpoints return JSON themselves, so
    the caller parses the string. Keeping this separate from
    ``kubectl_json`` makes the intent explicit and stops the two shapes
    from being conflated again.
    """
    out = sh(["kubectl", "--context", f"kind-{cluster}", *args], timeout=timeout)
    if out.returncode != 0:
        raise RuntimeError(f"kubectl {' '.join(args)} failed: {out.stderr[-300:]}")
    return out.stdout


def kubectl_apply(cluster: str, path: Path, what: str) -> str:
    out = kubectl(cluster, "apply", "-f", str(path))
    if out.returncode != 0:
        raise RuntimeError(f"{what} failed: {(out.stdout + out.stderr)[-800:]}")
    return out.stdout.strip()


def wait_or_fail(name: str, probe, requested: str, timeout: float, cluster: str,
                 diagnostic_args: Sequence[Sequence[str]]) -> bool:
    """Bounded readiness wait; on timeout collect diagnostics, FAIL, return False
    so the caller stops before making any traffic claim."""
    try:
        result = wait_until(name, probe, timeout=timeout, interval=2.0)
    except ReadinessTimeout as exc:
        bundle = collect_diagnostics(
            [["kubectl", "--context", f"kind-{cluster}", *args] for args in diagnostic_args]
        )
        DIAGNOSTICS[name] = bundle
        notice(f"readiness timeout — {name}\n{bundle}")
        return record(name, requested, f"TIMEOUT after {timeout:.0f}s: {exc}", False)
    return record(name, requested, f"passed after {result['attempts']} probe(s)", True)


# ---------------------------------------------------------------- statistics


def share_half_width(share: float, samples: int, sigma: float = SIGMA) -> float:
    """Half-width of the acceptance interval for an observed share."""
    if samples <= 0:
        raise ValueError("samples must be positive")
    return sigma * math.sqrt(share * (1.0 - share) / samples)


def share_within_tolerance(observed: int, samples: int, expected: float,
                           sigma: float = SIGMA) -> Tuple[bool, str]:
    """Is the observed count consistent with ``expected`` at ``sigma``?"""
    half_width = share_half_width(expected, samples, sigma)
    observed_share = observed / samples
    within = abs(observed_share - expected) <= half_width
    return within, (
        f"observed {observed}/{samples} = {observed_share:.4%}; accepted "
        f"{expected:.4%} ± {half_width:.4%} ({sigma:.0f} sigma, normal approximation)"
    )


def discrimination_note(expected: float, samples: int, wrong: float,
                        sigma: float = SIGMA) -> str:
    """How far a materially WRONG split sits from the acceptance interval."""
    half_width = share_half_width(expected, samples, sigma)
    wrong_sd = math.sqrt(wrong * (1.0 - wrong) / samples)
    if not wrong_sd:
        return "degenerate"
    sigmas = (abs(wrong - expected) - half_width) / wrong_sd
    return (f"a true split of {wrong:.0%} would sit {sigmas:.1f} sigma outside the "
            f"accepted interval ({abs(wrong - expected):.4%} away vs half-width "
            f"{half_width:.4%})")


#: The proof states, in measurement order. The COMMITTED state is measured
#: first so the artefact the repository ships is the first thing validated;
#: the two exclusivity states follow, which is also what shows the weights
#: (and not luck) drive the split.
PROOF_STATES: Sequence[Dict[str, Any]] = (
    {
        "name": "committed-95-5",
        "description": "the committed initial state (first progressive stage)",
        "weights": {"stable": 95, "canary": 5},
        "samples": 2000,
        "expectation": "proportional",
    },
    {
        "name": "all-stable-100-0",
        "description": "canary weight 0 — Envoy Gateway skips zero-weight backends",
        "weights": {"stable": 100, "canary": 0},
        "samples": 500,
        "expectation": "exclusive:stable",
    },
    {
        "name": "all-canary-0-100",
        "description": "stable weight 0 — the reverse direction",
        "weights": {"stable": 0, "canary": 100},
        "samples": 500,
        "expectation": "exclusive:canary",
    },
)


def pilot_agrees(payload: Mapping[str, Any], state: Mapping[str, Any]) -> Tuple[bool, str]:
    """Bounded convergence predicate: has the DATA PLANE caught up?"""
    total = int(payload.get("total") or 0)
    stable = int(payload.get("stable") or 0)
    canary = int(payload.get("canary") or 0)
    problems = int(payload.get("errors") or 0) + int(payload.get("other") or 0)
    expectation = state["expectation"]
    if total <= 0:
        return False, "pilot returned no responses"
    if expectation == "exclusive:stable":
        ok = stable == total and canary == 0
    elif expectation == "exclusive:canary":
        ok = canary == total and stable == 0
    else:
        # 95/5: the pilot must only rule out the previous exclusive state;
        # the real tolerance is applied to the full sample, never here.
        ok = stable >= total * 0.5
    return ok, (f"pilot total={total} stable={stable} canary={canary} "
                f"unattributed_or_errors={problems}")


# ------------------------------------------------------------ cluster reading


def condition_status(conditions: Optional[Sequence[Mapping[str, Any]]],
                     type_: str) -> Optional[str]:
    for condition in conditions or []:
        if condition.get("type") == type_:
            return str(condition.get("status"))
    return None


def condition_observed_generations(conditions: Optional[Sequence[Mapping[str, Any]]]) -> List[Any]:
    return sorted({c.get("observedGeneration") for c in (conditions or [])},
                  key=lambda value: str(value))


def configured_backend_refs(route: Mapping[str, Any]) -> List[Dict[str, Any]]:
    refs = ((route.get("spec") or {}).get("rules") or [{}])[0].get("backendRefs") or []
    return [
        {
            "name": ref.get("name"),
            "port": ref.get("port"),
            "weight": int(ref.get("weight", 1)),
            "proportional_share": expected_share_of(refs, ref.get("name")),
        }
        for ref in refs
    ]


def configured_weight_map(route: Mapping[str, Any]) -> Dict[str, int]:
    refs = ((route.get("spec") or {}).get("rules") or [{}])[0].get("backendRefs") or []
    by_name = {ref.get("name"): int(ref.get("weight", 1)) for ref in refs}
    return {track: by_name[SERVICE[track]] for track in ("stable", "canary")}


def route_parent_status(route: Mapping[str, Any]) -> Mapping[str, Any]:
    parents = ((route.get("status") or {}).get("parents") or [])
    for parent in parents:
        if (parent.get("parentRef") or {}).get("name") == GATEWAY:
            return parent
    return parents[0] if parents else {}


def read_route(cluster: str) -> Mapping[str, Any]:
    return kubectl_json(cluster, "-n", NAMESPACE, "get", "httproute", HTTP_ROUTE)


def service_endpoints(cluster: str, service: str) -> List[Dict[str, str]]:
    data = kubectl_json(cluster, "-n", NAMESPACE, "get", "endpointslice",
                        "-l", f"kubernetes.io/service-name={service}")
    endpoints: List[Dict[str, str]] = []
    for item in data.get("items", []):
        slices = item.get("endpoints") or []
        for endpoint in slices:
            conditions = endpoint.get("conditions") or {}
            if conditions.get("ready") is False or conditions.get("terminating") is True:
                continue
            for address in endpoint.get("addresses") or []:
                endpoints.append({
                    "address": address,
                    "target": str((endpoint.get("targetRef") or {}).get("name", "")),
                })
    return endpoints


def discover_data_plane(cluster: str) -> Dict[str, Any]:
    data = kubectl_json(cluster, "get", "service", "-A", "-l",
                        f"gateway.envoyproxy.io/owning-gateway-name={GATEWAY}")
    for item in data.get("items", []):
        labels = (item.get("metadata") or {}).get("labels") or {}
        if labels.get("gateway.envoyproxy.io/owning-gateway-namespace") != NAMESPACE:
            continue
        ports = (item.get("spec") or {}).get("ports") or []
        chosen = next((port for port in ports if port.get("port") == BACKEND_PORT),
                      ports[0] if ports else None)
        if chosen is None:
            continue
        name = (item.get("metadata") or {}).get("name")
        namespace = (item.get("metadata") or {}).get("namespace")
        return {
            "name": name,
            "namespace": namespace,
            "port": int(chosen.get("port")),
            "labels": labels,
            "cluster_url": f"http://{name}.{namespace}.svc.cluster.local:{int(chosen.get('port'))}/",
        }
    raise RuntimeError(
        "Envoy Gateway data-plane Service not found for the ares-gateway topology; "
        "the controller never programmed a data plane")


# ------------------------------------------------------------- sampler driver


def render_sampler_job(name: str, image: str, url: str, count: int, path: Path) -> Path:
    text = SAMPLER_JOB_TEMPLATE.read_text(encoding="utf-8")
    for token, value in (("__SAMPLER_NAME__", name), ("__SAMPLER_IMAGE__", image),
                         ("__SAMPLER_URL__", url), ("__SAMPLER_COUNT__", str(count))):
        text = text.replace(token, value)
    document = yaml.safe_load(text)
    leftovers = leftover_placeholders(document)
    if leftovers:
        raise RuntimeError(f"sampler job template has unresolved tokens: {leftovers}")
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def wait_for_sampler_job(cluster: str, name: str, timeout: int) -> Tuple[bool, str]:
    deadline = time.monotonic() + timeout
    history: List[str] = []
    while time.monotonic() < deadline:
        try:
            job = kubectl_json(cluster, "-n", NAMESPACE, "get", "job", name)
        except RuntimeError as exc:
            history.append(f"wait: {exc}"[:200])
            time.sleep(2)
            continue
        status = job.get("status") or {}
        if status.get("succeeded"):
            return True, f"succeeded={status.get('succeeded')}"
        if status.get("failed"):
            return False, f"job failed: status={json.dumps(status, sort_keys=True)[:400]}"
        history.append(f"wait: active={status.get('active')} conditions="
                       f"{[(c.get('type'), c.get('status')) for c in status.get('conditions') or []]}"[:220])
        time.sleep(2)
    return False, f"TIMEOUT after {timeout}s; last: {history[-3:]}"


def run_sampler(cluster: str, workdir: Path, sampler_image: str, url: str,
                count: int, name: str, timeout: int = 420) -> Dict[str, Any]:
    """Run one in-cluster sampler Job and return its parsed JSON report.

    Fails closed: an unparseable or missing report raises rather than
    returning an empty measurement.
    """
    job_path = render_sampler_job(name, sampler_image, url, count, workdir / f"{name}.yaml")
    kubectl_apply(cluster, job_path, f"sampler job {name}")
    succeeded, detail = wait_for_sampler_job(cluster, name, timeout)
    logs = kubectl(cluster, "-n", NAMESPACE, "logs", f"job/{name}", "--tail=200")
    kubectl(cluster, "-n", NAMESPACE, "delete", "job", name, "--wait=true",
            "--ignore-not-found=true", timeout=120)
    if not succeeded:
        raise RuntimeError(f"sampler {name} did not complete: {detail}; logs: "
                           f"{(logs.stdout + logs.stderr)[-800:]}")
    payload: Optional[Dict[str, Any]] = None
    for line in reversed((logs.stdout or "").splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                payload = json.loads(line)
                break
            except ValueError:
                continue
    if payload is None:
        raise RuntimeError(f"sampler {name} produced no JSON report; logs: "
                           f"{(logs.stdout + logs.stderr)[-800:]}")
    return payload


# ------------------------------------------------------------- fixture render


def render_fixture(destination: Path, images: Mapping[str, str]) -> List[Dict[str, Any]]:
    """Substitute the two image tokens and re-verify the rendered documents.

    The rendered copy is written OUTSIDE the repository (a temp directory),
    so the working tree that produced it stays byte-identical to the
    commit under test.
    """
    destination.mkdir(parents=True, exist_ok=True)
    documents: List[Dict[str, Any]] = []
    for name in sorted(os.listdir(TOPOLOGY_DIR)):
        if not name.endswith((".yaml", ".yml")):
            continue
        text = (Path(TOPOLOGY_DIR) / name).read_text(encoding="utf-8")
        text = text.replace("__STABLE_IMAGE__", images["stable"])
        text = text.replace("__CANARY_IMAGE__", images["canary"])
        (destination / name).write_text(text, encoding="utf-8")
        documents.extend(yaml.safe_load_all(text))
    leftovers = leftover_placeholders(documents)
    if leftovers:
        raise RuntimeError(f"rendered fixture still contains tokens: {leftovers}")
    violations = verify_documents(documents)
    if violations:
        raise RuntimeError(f"rendered fixture violates the topology contract: {violations}")
    return documents


# --------------------------------------------------------------- preflight


def git(*args: str) -> subprocess.CompletedProcess:
    return sh(["git", "-C", str(ROOT.parent), *args])


def wait_for_expected_commit(expected: str, timeout: float = 120.0) -> Tuple[bool, str]:
    deadline = time.monotonic() + timeout
    head = ""
    while time.monotonic() < deadline:
        head = git("rev-parse", "HEAD").stdout.strip()
        if head == expected:
            return True, head
        time.sleep(3)
    return False, f"HEAD={head!r} expected={expected!r}"


def preflight_commit(args: argparse.Namespace) -> bool:
    if not args.expected_commit:
        return record(
            "preflight:expected-commit-provided",
            "the driver must be told which commit it is proving",
            "no --expected-commit was given",
            False,
        )
    ok = True
    matched, detail = wait_for_expected_commit(args.expected_commit)
    ok &= record("preflight:checkout-matches-commit",
                 f"git HEAD == {args.expected_commit[:12]} (retried, not sampled once)",
                 detail, matched)
    diff = git("diff", "--quiet", "HEAD", "--", "k8s/progressive")
    ok &= record("preflight:fixture-unmodified",
                 "the manifests about to be applied are the committed ones",
                 f"git diff HEAD -- k8s/progressive rc={diff.returncode}",
                 diff.returncode == 0)
    tracked = git("ls-files", "k8s/progressive").stdout.split()
    ok &= record("preflight:fixture-tracked",
                 "the fixture is committed, not a local artefact",
                 f"tracked_files={len(tracked)}", len(tracked) >= 7)
    return ok


def preflight_pins(args: argparse.Namespace) -> Tuple[bool, Dict[str, str]]:
    """Parse the committed artifact pins and check the expected versions."""
    try:
        records = parse_pinned_artifacts(PINS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        record("stack:pins-valid",
               "the external stack artifacts are pinned by digest in the repository",
               f"{type(exc).__name__}: {exc}", False)
        return False, {}
    by_key = {record_["key"]: record_ for record_ in records}
    STACK_INFO["pins_file"] = str(PINS_FILE.relative_to(ROOT.parent))
    STACK_INFO["pins"] = [
        {"key": record_["key"], "url": record_["url"], "sha256": record_["pin"]}
        for record_ in sorted(records, key=lambda item: item["key"])
    ]
    versions: Dict[str, str] = {}
    problems: List[str] = []
    for key, expected, label in (
        ("GATEWAY_API_CRDS_URL", args.gateway_api_version, "Gateway API"),
        ("ENVOY_GATEWAY_INSTALL_URL", args.envoy_gateway_version, "Envoy Gateway"),
    ):
        url = by_key[key]["url"]
        parts = url.split("/")
        tag = parts[parts.index("download") + 1] if "download" in parts else ""
        versions[label] = tag
        if tag != expected:
            problems.append(f"{label} pin is {tag!r}, expected {expected!r}")
        if expected in ("latest", ""):
            problems.append(f"{label} must not float")
    STACK_INFO["pinned_versions"] = dict(versions)
    ok = record("stack:pins-valid",
                "Gateway API CRDs and Envoy Gateway are pinned to explicit "
                "releases with committed sha256 digests (no 'latest')",
                f"gateway_api={versions.get('Gateway API')} "
                f"envoy_gateway={versions.get('Envoy Gateway')} "
                f"pins={len(records)} problems={problems}",
                not problems)
    return ok, versions


# ------------------------------------------------------- installed stack


def check_gateway_api_crds(cluster: str, version: str) -> bool:
    crd = kubectl_json(cluster, "get", "crd",
                       "httproutes.gateway.networking.k8s.io")
    annotations = (crd.get("metadata") or {}).get("annotations") or {}
    bundle = annotations.get("gateway.networking.k8s.io/bundle-version", "")
    STACK_INFO["observed_gateway_api_crd_bundle_version"] = bundle
    STACK_INFO["observed_gateway_api_crd_channel"] = annotations.get(
        "gateway.networking.k8s.io/channel", "")
    return record("stack:gateway-api-crds-installed",
                  f"the installed HTTPRoute CRD comes from the pinned Gateway API {version}",
                  f"bundle-version={bundle!r} "
                  f"channel={annotations.get('gateway.networking.k8s.io/channel')!r}",
                  bundle == version)


def check_envoy_gateway_controller(cluster: str, version: str, timeout: float) -> bool:
    def probe() -> Tuple[bool, str]:
        deployment = kubectl_json(cluster, "-n", ENVOY_NAMESPACE,
                                  "get", "deployment", "envoy-gateway")
        metadata = deployment.get("metadata") or {}
        status = deployment.get("status") or {}
        spec_replicas = (deployment.get("spec") or {}).get("replicas", 1)
        images = [container.get("image") for container in
                  ((deployment.get("spec") or {}).get("template") or {}).get(
                      "spec", {}).get("containers", [])]
        available = status.get("availableReplicas")
        ready = (status.get("observedGeneration") == metadata.get("generation")
                 and available == spec_replicas and spec_replicas)
        tagged = any(f":{version}" in str(image) for image in images)
        if ready and tagged:
            STACK_INFO["observed_envoy_gateway_images"] = images
        return bool(ready and tagged), (
            f"images={images} available={available}/{spec_replicas} "
            f"observedGeneration={status.get('observedGeneration')} "
            f"generation={metadata.get('generation')} expected_tag={version}")
    return wait_or_fail("readiness:envoy-gateway-controller",
                        probe,
                        f"the pinned Envoy Gateway {version} controller is Ready",
                        timeout, cluster,
                        [("get", "-n", ENVOY_NAMESPACE, "deployments,pods", "-o", "wide"),
                         ("logs", "-n", ENVOY_NAMESPACE, "deployment/envoy-gateway",
                          "--tail=80")])


# ---------------------------------------------------------- core readiness


def probe_gatewayclass(cluster: str):
    def probe() -> Tuple[bool, str]:
        obj = kubectl_json(cluster, "get", "gatewayclass", GATEWAY_CLASS)
        metadata = obj.get("metadata") or {}
        conditions = (obj.get("status") or {}).get("conditions")
        accepted = condition_status(conditions, "Accepted")
        generations = condition_observed_generations(conditions)
        return (accepted == "True" and generations == [metadata.get("generation")],
                f"accepted={accepted} generation={metadata.get('generation')} "
                f"observedGenerations={generations}")
    return probe


def probe_gateway(cluster: str):
    def probe() -> Tuple[bool, str]:
        obj = kubectl_json(cluster, "-n", NAMESPACE, "get", "gateway", GATEWAY)
        metadata = obj.get("metadata") or {}
        status = obj.get("status") or {}
        conditions = status.get("conditions")
        accepted = condition_status(conditions, "Accepted")
        programmed = condition_status(conditions, "Programmed")
        generations = condition_observed_generations(conditions)
        listeners = status.get("listeners") or []
        return (accepted == "True" and programmed == "True"
                and generations == [metadata.get("generation")] and len(listeners) == 1,
                f"accepted={accepted} programmed={programmed} "
                f"generation={metadata.get('generation')} "
                f"observedGenerations={generations} listeners={len(listeners)}")
    return probe


def route_probe(cluster: str, expected_weights: Optional[Mapping[str, int]] = None):
    def probe() -> Tuple[bool, str]:
        route = read_route(cluster)
        metadata = route.get("metadata") or {}
        parent = route_parent_status(route)
        conditions = parent.get("conditions")
        statuses = {type_: condition_status(conditions, type_)
                    for type_ in ("Accepted", "ResolvedRefs")}
        generations = condition_observed_generations(conditions)
        weights = configured_weight_map(route)
        ok = (all(value == "True" for value in statuses.values())
              and generations == [metadata.get("generation")])
        detail = (f"generation={metadata.get('generation')} "
                  f"observedGenerations={generations} conditions={statuses} "
                  f"configured_weights={weights}")
        if ok and expected_weights is not None:
            ok = weights == dict(expected_weights)
            detail += f" expected={dict(expected_weights)}"
        return ok, detail
    return probe


def probe_deployments(cluster: str):
    def probe() -> Tuple[bool, str]:
        details: List[str] = []
        ok = True
        for track in ("stable", "canary"):
            deployment = kubectl_json(cluster, "-n", NAMESPACE, "get",
                                      "deployment", TRACK_DEPLOYMENT[track])
            metadata = deployment.get("metadata") or {}
            status = deployment.get("status") or {}
            spec_replicas = (deployment.get("spec") or {}).get("replicas", 1)
            ready = (status.get("observedGeneration") == metadata.get("generation")
                     and status.get("availableReplicas") == spec_replicas
                     and bool(spec_replicas))
            ok &= bool(ready)
            details.append(f"{track}: available={status.get('availableReplicas')}/"
                           f"{spec_replicas} generation={metadata.get('generation')} "
                           f"observedGeneration={status.get('observedGeneration')}")
        return ok, "; ".join(details)
    return probe


def probe_backend_endpoints(cluster: str):
    def probe() -> Tuple[bool, str]:
        stable = service_endpoints(cluster, SERVICE["stable"])
        canary = service_endpoints(cluster, SERVICE["canary"])
        ok = bool(stable) and bool(canary)
        return ok, (f"stable_endpoints={len(stable)} canary_endpoints={len(canary)}")
    return probe


DATA_PLANE: Dict[str, Any] = {}


def probe_data_plane(cluster: str):
    def probe() -> Tuple[bool, str]:
        try:
            data_plane = discover_data_plane(cluster)
        except RuntimeError as exc:
            return False, str(exc)
        pods = kubectl_json(cluster, "-n", data_plane["namespace"], "get", "pods",
                            "-l", f"gateway.envoyproxy.io/owning-gateway-name={GATEWAY}")
        ready = total = 0
        for pod in pods.get("items", []):
            total += 1
            for condition in (pod.get("status") or {}).get("conditions") or []:
                if condition.get("type") == "Ready" and condition.get("status") == "True":
                    ready += 1
        ok = total >= 1 and ready == total
        if ok:
            DATA_PLANE.clear()
            DATA_PLANE.update(data_plane)
        return ok, (f"service={data_plane['name']} namespace={data_plane['namespace']} "
                    f"port={data_plane['port']} pods_ready={ready}/{total}")
    return probe


def core_readiness(cluster: str, args: argparse.Namespace) -> bool:
    diag = (
        ("get", "gatewayclass", GATEWAY_CLASS, "-o", "yaml"),
        ("get", "-n", NAMESPACE, "gateway", GATEWAY, "-o", "yaml"),
        ("get", "-n", NAMESPACE, "httproute", HTTP_ROUTE, "-o", "yaml"),
        ("get", "-n", NAMESPACE, "deployments,pods,services", "-o", "wide"),
        ("get", "-n", NAMESPACE, "endpointslice", "-o", "wide"),
        ("get", "-n", NAMESPACE, "events", "--sort-by=.lastTimestamp"),
        ("get", "-n", ENVOY_NAMESPACE, "pods,services,deployments", "-o", "wide"),
        ("logs", "-n", ENVOY_NAMESPACE, "deployment/envoy-gateway", "--tail=120"),
    )
    timeout = args.readiness_timeout
    ok = True
    ok &= wait_or_fail("readiness:gatewayclass-accepted", probe_gatewayclass(cluster),
                       "the GatewayClass is accepted by its controller",
                       90, cluster, diag)
    ok &= wait_or_fail("readiness:gateway-programmed", probe_gateway(cluster),
                       "the Gateway is Accepted and Programmed with one listener",
                       timeout, cluster, diag)
    ok &= wait_or_fail("readiness:httproute-accepted",
                       route_probe(cluster, {"stable": 95, "canary": 5}),
                       "the HTTPRoute is Accepted with ResolvedRefs at the committed weights",
                       timeout, cluster, diag)
    ok &= wait_or_fail("readiness:deployments-available", probe_deployments(cluster),
                       "both workloads have all replicas available",
                       timeout, cluster, diag)
    ok &= wait_or_fail("readiness:backend-endpoints", probe_backend_endpoints(cluster),
                       "both backend Services have ready endpoints",
                       timeout, cluster, diag)
    ok &= wait_or_fail("readiness:data-plane-ready", probe_data_plane(cluster),
                       "the Envoy data plane exists and its pods are Ready",
                       timeout, cluster, diag)
    return ok


# ------------------------------------------------------------- proof states


def patch_route_weights(cluster: str, target: Mapping[str, int]) -> None:
    """Test-infrastructure-only mutation of the proof state.

    This is the E2E driver, not the application: the commit keeps the
    application's traffic-mutation boundary unimplemented and untouched.
    """
    route = read_route(cluster)
    refs = ((route.get("spec") or {}).get("rules") or [{}])[0].get("backendRefs") or []
    operations = []
    for index, ref in enumerate(refs):
        name = ref.get("name")
        for track, weight in target.items():
            if name == SERVICE[track]:
                operations.append({
                    "op": "replace",
                    "path": f"/spec/rules/0/backendRefs/{index}/weight",
                    "value": int(weight),
                })
    if len(operations) != len(target):
        raise RuntimeError(
            f"cannot patch weights {dict(target)}: route backendRefs are "
            f"{[ref.get('name') for ref in refs]}")
    payload = json.dumps(operations)
    out = kubectl(cluster, "-n", NAMESPACE, "patch", "httproute", HTTP_ROUTE,
                  "--type=json", "-p", payload)
    if out.returncode != 0:
        raise RuntimeError(f"patching HTTPRoute weights failed: {out.stderr[-400:]}")


def establish_state(cluster: str, workdir: Path, args: argparse.Namespace,
                    state: Mapping[str, Any]) -> bool:
    name = state["name"]
    target = dict(state["weights"])
    samples = int(state["samples"])
    diag = (
        ("get", "-n", NAMESPACE, "httproute", HTTP_ROUTE, "-o", "yaml"),
        ("get", "-n", NAMESPACE, "pods,endpointslice", "-o", "wide"),
        ("get", "-n", NAMESPACE, "events", "--sort-by=.lastTimestamp"),
        ("logs", "-n", ENVOY_NAMESPACE, "deployment/envoy-gateway", "--tail=80"),
    )
    patch_route_weights(cluster, target)

    if not wait_or_fail(
        f"state:{name}:controller-accepted",
        route_probe(cluster, target),
        f"the controller accepted generation with configured weights {target}",
        120, cluster, diag,
    ):
        return False

    route = read_route(cluster)
    gateway = kubectl_json(cluster, "-n", NAMESPACE, "get", "gateway", GATEWAY)
    parent = route_parent_status(route)
    conditions = parent.get("conditions")
    configured = {
        "source": "HTTPRoute spec read back from the cluster API server",
        "route_generation": (route.get("metadata") or {}).get("generation"),
        "backend_refs": configured_backend_refs(route),
        "proportional_share_of_stable": next(
            ref["proportional_share"] for ref in configured_backend_refs(route)
            if ref["name"] == SERVICE["stable"]),
    }
    controller = {
        "source": "Gateway API controller status, not a manifest",
        "observed_generations": condition_observed_generations(conditions),
        "accepted": condition_status(conditions, "Accepted"),
        "resolved_refs": condition_status(conditions, "ResolvedRefs"),
        "reasons": {condition.get("type"): condition.get("reason")
                    for condition in conditions or []},
        "gateway_programmed": condition_status(
            (gateway.get("status") or {}).get("conditions"), "Programmed"),
    }

    url = DATA_PLANE["cluster_url"]
    pilot = run_sampler(cluster, workdir, args.sampler_image, url, PILOT_SAMPLES,
                        f"ares-sampler-pilot-{name}")
    converged, note = pilot_agrees(pilot, state)
    record(f"state:{name}:data-plane-converged",
           "a bounded pilot shows the data plane serves the newly configured state "
           "(no traffic is measured until it does)",
           note, converged)
    if not converged:
        return False

    payload = run_sampler(cluster, workdir, args.sampler_image, url, samples,
                          f"ares-sampler-{name}")
    total = int(payload["total"])
    stable = int(payload["stable"])
    canary = int(payload["canary"])
    clean = (total == samples and int(payload["errors"]) == 0
             and int(payload["other"]) == 0
             and int(payload["body_disagreements"]) == 0)
    record(f"state:{name}:measurement-complete",
           f"{samples} real HTTP responses through the Envoy data plane, every one "
           f"attributable (header cross-checked against body)",
           f"total={total} stable={stable} canary={canary} "
           f"errors={payload['errors']} unattributed={payload['other']} "
           f"body_disagreements={payload['body_disagreements']}",
           clean)
    if not clean:
        return False

    expectation = str(state["expectation"])
    if expectation == "proportional":
        expected_share = configured["proportional_share_of_stable"]
        within, detail = share_within_tolerance(canary, samples, 1.0 - expected_share)
        both_seen = stable > 0 and canary > 0
        ok = within and both_seen
        record(f"state:{name}:distribution",
               f"canary share of {samples} responses within "
               f"{1.0 - expected_share:.4%} ± {share_half_width(1.0 - expected_share, samples):.4%} "
               f"({SIGMA:.0f} sigma) — never an exact value",
               f"{detail}; both_backends_observed={both_seen} "
               f"({discrimination_note(1.0 - expected_share, samples, 0.10)})",
               ok)
    else:
        expected_track = expectation.split(":", 1)[1]
        winner = stable if expected_track == "stable" else canary
        loser = canary if expected_track == "stable" else stable
        ok = winner == samples and loser == 0
        record(f"state:{name}:distribution",
               f"all {samples} responses come from the {expected_track} backend "
               f"(the other backend has weight 0 and must never be selected)",
               f"{expected_track}={winner} other_backend={loser} "
               f"(0-weight backends are skipped by the implementation; a single "
               f"leak is a hard failure, not jitter)",
               ok)

    STATES.append({
        "state": name,
        "description": state["description"],
        "target_weights": target,
        "configured": configured,
        "controller": controller,
        "observed": {
            "source": "real HTTP responses through the Envoy data plane",
            "samples": samples,
            "stable": stable,
            "canary": canary,
            "canary_share": canary / samples,
            "stable_share": stable / samples,
            "statuses": payload["statuses"],
            "instances": payload["instances"],
            "errors": payload["errors"],
            "unattributed": payload["other"],
            "body_disagreements": payload["body_disagreements"],
            "elapsed_ms": payload["elapsed_ms"],
        },
        "pilot": {"samples": PILOT_SAMPLES, "stable": pilot["stable"],
                  "canary": pilot["canary"], "note": note},
        "verdict": "PASS" if RESULTS[-1]["status"] == "PASS" else "FAIL",
    })
    return bool(RESULTS[-1]["status"] == "PASS")


# ----------------------------------------------------------- negative probe


def negative_probe(cluster: str, workdir: Path, args: argparse.Namespace) -> bool:
    """An HTTPRoute whose backendRef names a Service that does not exist.

    The controller must FLAG it (ResolvedRefs=False) and requests matching
    it must not be silently served by a healthy backend — i.e. an invalid
    backend fails visibly instead of falling back.
    """
    manifest = {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": {
            "name": INVALID_PROBE_ROUTE,
            "namespace": NAMESPACE,
            "labels": {"ares.dev/phase": "8.7-B.0", "ares.dev/kinds": "negative-probe"},
        },
        "spec": {
            "parentRefs": [{"name": GATEWAY, "sectionName": "http"}],
            "rules": [
                {
                    "matches": [{"path": {"type": "PathPrefix", "value": INVALID_PROBE_PATH}}],
                    "backendRefs": [{
                        "name": "ares-backend-that-does-not-exist",
                        "port": BACKEND_PORT,
                        "weight": 1,
                    }],
                }
            ],
        },
    }
    path = workdir / "invalid-probe-route.yaml"
    path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    kubectl_apply(cluster, path, "invalid-backend probe route")

    def probe() -> Tuple[bool, str]:
        route = kubectl_json(cluster, "-n", NAMESPACE, "get", "httproute",
                             INVALID_PROBE_ROUTE)
        parent = route_parent_status(route)
        conditions = parent.get("conditions")
        resolved = condition_status(conditions, "ResolvedRefs")
        accepted = condition_status(conditions, "Accepted")
        reason = next((condition.get("reason") for condition in conditions or []
                       if condition.get("type") == "ResolvedRefs"), "")
        return resolved == "False", (f"accepted={accepted} resolvedRefs={resolved} "
                                     f"reason={reason!r}")

    diag = (("get", "-n", NAMESPACE, "httproute", INVALID_PROBE_ROUTE, "-o", "yaml"),
            ("get", "-n", NAMESPACE, "services",),
            ("get", "-n", NAMESPACE, "events", "--sort-by=.lastTimestamp"))
    ok = wait_or_fail("negative:invalid-backend-flagged", probe,
                      "a backendRef naming a missing Service is flagged by the "
                      "controller instead of being silently accepted",
                      90, cluster, diag)

    if ok:
        attempts: List[str] = []
        served = -1
        payload: Dict[str, Any] = {}
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            payload = run_sampler(cluster, workdir, args.sampler_image,
                                  DATA_PLANE["cluster_url"] + INVALID_PROBE_PATH.lstrip("/"),
                                  5, "ares-sampler-invalid-probe")
            served = int(payload["stable"]) + int(payload["canary"])
            attempts.append(f"statuses={payload['statuses']} served={served}")
            if served == 0:
                break
            time.sleep(3)
        ok &= record("negative:invalid-backend-not-silently-served",
                     "requests matching the invalid route are NOT answered by "
                     "another healthy backend",
                     f"statuses={payload.get('statuses')} served_by_a_backend={served} "
                     f"others={payload.get('other')} attempts={attempts}",
                     served == 0)

    sh(["kubectl", "--context", f"kind-{cluster}", "-n", NAMESPACE, "delete",
        "httproute", INVALID_PROBE_ROUTE, "--ignore-not-found=true", "--wait=true"])
    return ok


# ------------------------------------------------------------------- run


def run(args: argparse.Namespace, workdir: Path) -> bool:
    cluster = args.cluster
    ok = preflight_commit(args)
    pins_ok, versions = preflight_pins(args)
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
                 f"documents={len(documents)} violations={violations}",
                 not violations)
    if not ok:
        return False

    alive = sh(["docker", "inspect", "-f", "{{.State.Running}}",
                f"{cluster}-control-plane"])
    ok &= record("cluster:kind-is-live", "a real Kind control plane is running",
                 f"container={cluster}-control-plane "
                 f"running={alive.stdout.strip()!r}", alive.stdout.strip() == "true")
    # The API server version comes from the raw endpoint: `kubectl get
    # --raw=/version` already returns JSON, and passing -o json alongside
    # --raw is rejected by kubectl itself.
    server_version = json.loads(kubectl_raw(cluster, "get", "--raw=/version"))
    ok &= record("cluster:server-version", "the cluster reports its real version",
                 f"server={server_version.get('gitVersion')}", bool(server_version.get("gitVersion")))
    if not ok:
        return False

    for key, image in (("stable", args.stable_image), ("canary", args.canary_image),
                       ("sampler", args.sampler_image)):
        inspected = sh(["docker", "image", "inspect", "--format", "{{.Id}}", image])
        IMAGE_IDENTITIES[key] = (inspected.stdout.strip().splitlines() or [""])[0]
    ok &= record("build:distinct-workload-images",
                 "stable and canary are genuinely different images, not one image "
                 "serving both tracks",
                 f"stable={IMAGE_IDENTITIES['stable'][:23]} "
                 f"canary={IMAGE_IDENTITIES['canary'][:23]} "
                 f"sampler={IMAGE_IDENTITIES['sampler'][:23]}",
                 bool(IMAGE_IDENTITIES["stable"] and IMAGE_IDENTITIES["canary"])
                 and IMAGE_IDENTITIES["stable"] != IMAGE_IDENTITIES["canary"])
    if not ok:
        return False

    ok &= check_gateway_api_crds(cluster, versions.get("Gateway API", ""))
    ok &= check_envoy_gateway_controller(cluster, versions.get("Envoy Gateway", ""),
                                         args.readiness_timeout)
    if not ok:
        record("stack:identified", "the controller stack is the pinned one before any "
                                   "topology is applied", "stack identification failed", False)
        return False

    try:
        render_fixture(workdir / "rendered",
                       {"stable": args.stable_image, "canary": args.canary_image})
    except Exception as exc:  # noqa: BLE001
        ok &= record("topology:rendered", "the images are substituted into the fixture",
                     f"{type(exc).__name__}: {exc}", False)
        return False
    ok &= record("topology:rendered",
                 "the fixture with the two local images substituted still satisfies "
                 "the topology contract",
                 f"rendered into {workdir / 'rendered'} (outside the repository)", True)

    applied = kubectl_apply(cluster, workdir / "rendered", "topology fixture")
    ok &= record("topology:applied", "the topology was applied to the cluster",
                 f"{len(applied.splitlines())} object line(s) reported by kubectl apply", True)

    if not core_readiness(cluster, args):
        record("harness:stopped", "no traffic is measured until the controller and the "
                                  "data plane report ready", "readiness failed", False)
        return False

    stable_endpoints = service_endpoints(cluster, SERVICE["stable"])
    canary_endpoints = service_endpoints(cluster, SERVICE["canary"])
    stable_addresses = {endpoint["address"] for endpoint in stable_endpoints}
    canary_addresses = {endpoint["address"] for endpoint in canary_endpoints}
    stable_targets = {endpoint["target"] for endpoint in stable_endpoints}
    canary_targets = {endpoint["target"] for endpoint in canary_endpoints}
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

    notice(f"data plane: {DATA_PLANE['cluster_url']}")

    for state in PROOF_STATES:
        if not establish_state(cluster, workdir, args, state):
            record(f"state:{state['name']}:verdict", "the state is proven by real "
                                                     "requests", "aborted", False)
            return False

    patch_route_weights(cluster, {"stable": 95, "canary": 5})
    restored = wait_or_fail("state:restored-committed-weights",
                            route_probe(cluster, {"stable": 95, "canary": 5}),
                            "the cluster is left in the committed initial state (95/5)",
                            120, cluster,
                            (("get", "-n", NAMESPACE, "httproute", HTTP_ROUTE, "-o", "yaml"),))
    ok &= restored

    ok &= negative_probe(cluster, workdir, args)
    return ok


# --------------------------------------------------------------- evidence


def statistics_block() -> Dict[str, Any]:
    share = 0.05
    samples = 2000
    half_width = share_half_width(share, samples)
    phi4 = 0.5 * (1.0 + math.erf(SIGMA / math.sqrt(2.0)))
    return {
        "method": ("two-sided normal approximation to the Binomial(n, p) sampling "
                   "distribution of the observed backend counts"),
        "sigma": SIGMA,
        "false_failure_probability_per_proportional_state": 2.0 * (1.0 - phi4),
        "why_not_an_exact_value": (
            "The data plane picks a backend per request, so the observed count is "
            "Binomial(n, p), not a fixed number. Asserting an exact 5.000000% would "
            "fail on essentially every honest run; the accepted band is derived "
            "from the sampling distribution instead of chosen to make the test pass."),
        "proportional_state": {
            "samples": samples,
            "expected_canary_share": share,
            "accepted_interval": [share - half_width, share + half_width],
            "rationale": (f"{SIGMA:.0f} sigma on n={samples}: tight enough to reject a "
                          f"wrong split, loose enough not to fail a correct one"),
        },
        "exclusive_states": {
            "samples": 500,
            "rule": "the backend with weight 0 must never be selected",
            "rationale": ("weight-0 backendRefs are skipped by Envoy Gateway's "
                          "translator (internal/gatewayapi/route.go, v1.6.7), so any "
                          "leak is a real routing defect rather than sampling noise"),
        },
        "discrimination": [
            discrimination_note(share, samples, 0.10),
            discrimination_note(share, samples, 0.01),
            discrimination_note(share, samples, 0.50),
        ],
    }


def build_evidence(args: argparse.Namespace, workdir: Path) -> Dict[str, Any]:
    passed = sum(1 for row in RESULTS if row["status"] == "PASS")
    total = len(RESULTS)
    return {
        "suite": "phase-8.7-B.0-weighted-traffic-topology",
        "proves": ("a real Kubernetes Gateway API topology implemented by a real "
                   "Envoy Gateway routes real HTTP requests between two independent "
                   "workloads according to explicit proportional weights"),
        "is_not": [
            "an application traffic-mutation capability: the Phase 8.7-A boundary is "
            "unimplemented and untouched, and the application cannot change traffic",
            "a production ingress configuration: the reserved overlay is applied only "
            "to a disposable Kind cluster",
            "evidence that canary releases are automated: nothing promotes, pauses, "
            "aborts or rolls back",
        ],
        "weight_semantics": {
            "rule": "share(backend) = weight / sum(weights in the rule)",
            "committed_initial_state": {
                "weights": {"stable": 95, "canary": 5},
                "proportional_shares": {"stable": 0.95, "canary": 0.05},
            },
            "note": "Gateway API `weight` is proportional; it is never itself a percentage",
        },
        "commit_under_test": args.expected_commit,
        "stack": dict(STACK_INFO),
        "topology": {
            "namespace": NAMESPACE,
            "chain": ("GatewayClass -> Gateway -> HTTPRoute(weighted backendRefs) -> "
                      "Service ares-stable|ares-canary -> Deployment ares-stable|ares-canary"),
            "data_plane": dict(DATA_PLANE),
            "distinct_workload_images": dict(IMAGE_IDENTITIES),
            "workload_identity": "baked into the image (ARES_TRACK) and reported on "
                                 "every response as the X-Ares-Track header",
        },
        "statistics": statistics_block(),
        "states": STATES,
        "safety": {
            "application_can_mutate_traffic": False,
            "proof_state_mutation": {
                "mechanism": "kubectl patch of the HTTPRoute, executed by this E2E "
                             "driver for proof states only",
                "location": "disposable Kind cluster created for this job",
                "application_capability": False,
                "imports_traffic_mutation_boundary": False,
            },
            "production_topology_untouched": "k8s/deployment.yaml is unaffected; this "
                                             "overlay is never referenced from it",
        },
        "checks": RESULTS,
        "diagnostics": DIAGNOSTICS,
        "passed": passed,
        "total": total,
        "failing_checks": [row["check"] for row in RESULTS if row["status"] != "PASS"],
        "provenance": provenance(),
        "teardown": {
            "driver_deletes_cluster": bool(args.destroy_cluster),
            "workflow_fallback": "kind delete cluster runs with if: always()",
            "workdir_kept": bool(args.keep_workdir),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 8.7-B.0 weighted traffic "
                                                 "topology E2E")
    parser.add_argument("--cluster", default="ares-topology-e2e")
    parser.add_argument("--stable-image", required=True)
    parser.add_argument("--canary-image", required=True)
    parser.add_argument("--sampler-image", required=True)
    parser.add_argument("--expected-commit", default="")
    parser.add_argument("--gateway-api-version", default="v1.4.1")
    parser.add_argument("--envoy-gateway-version", default="v1.6.7")
    parser.add_argument("--readiness-timeout", type=float, default=240.0)
    parser.add_argument("--evidence",
                        default="e2e-evidence/traffic-topology-e2e.json")
    parser.add_argument("--destroy-cluster", action="store_true",
                        help="delete the Kind cluster after sealing evidence")
    parser.add_argument("--keep-workdir", action="store_true")
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="ares-traffic-topology-"))
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
    evidence = build_evidence(args, workdir)
    record_ = seal(evidence, out)
    notice(f"evidence sealed: {out} sha256={record_.get('artifact_sha256', '')}")

    if args.destroy_cluster:
        deleted = sh(["kind", "delete", "cluster", "--name", args.cluster], timeout=600)
        notice(f"cluster {args.cluster} deleted (rc={deleted.returncode})")

    passed = evidence["passed"]
    total = evidence["total"]
    notice(f"{passed}/{total} checks PASS")
    for state in STATES:
        observed = state["observed"]
        notice(f"  {state['state']}: configured={state['target_weights']} "
               f"observed stable={observed['stable']} canary={observed['canary']} "
               f"({observed['canary_share']:.4%} canary) [{state['verdict']}]")

    print(f"::notice title=8.7-B.0::weighted traffic topology E2E {passed}/{total} "
          f"checks PASS, {total - passed} FAIL; evidence={out}")
    if passed != total:
        for row in RESULTS:
            if row["status"] == "PASS":
                continue
            print(f"::error title=8.7-B.0 FAIL {row['check']}::"
                  f"requested={row['requested'][:120]} "
                  f"observed={row['observed'][:300]}")
    else:
        import base64
        import gzip
        packed = base64.b64encode(gzip.compress(
            json.dumps(RESULTS, separators=(",", ":")).encode())).decode()
        for index in range(0, len(packed), 900):
            print(f"::notice title=8.7-B.0 results {index // 900}::"
                  f"{packed[index:index + 900]}")
    return 0 if passed == total and total > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
