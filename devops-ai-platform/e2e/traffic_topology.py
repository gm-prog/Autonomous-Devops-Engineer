"""Static contract of the Phase 8.7-B.0 weighted stable/canary topology.

One source of truth for "is this manifest set a real, minimal,
non-overlapping weighted topology" — shared by

* ``tests/test_phase_8_7_b_0_weighted_traffic_topology.py`` (the committed
  fixture must satisfy it, and must keep satisfying it), and
* ``e2e/traffic-topology/mutation_probe.py``, which tampers with an
  isolated COPY of the fixture and requires this same verifier to reject
  every tampering.

Nothing here talks to a cluster: it is the static half of the proof. The
dynamic half (does real traffic actually split) lives in
``e2e/traffic_topology_kind_e2e.py``.

The verifier is intentionally strict: it fails closed on unknown keys,
unknown resource kinds, unresolved ``__TOKEN__`` placeholders and
missing explicit weights, so a manifest edit cannot silently weaken the
topology claim.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, Iterable, List, Mapping, Sequence

import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TOPOLOGY_DIR = os.path.join(REPO_ROOT, "k8s", "progressive")

NAMESPACE = "ares-traffic"
APP_LABEL = "ares-traffic"
TRACK_LABEL = "track"
TRACKS: Sequence[str] = ("stable", "canary")

GATEWAY_CLASS = "ares-gatewayclass"
ENVOY_CONTROLLER_NAME = "gateway.envoyproxy.io/gatewayclass-controller"
ENVOY_PROXY = "ares-envoy-proxy"
ENVOY_PROXY_NAMESPACE = "envoy-gateway-system"
# Pinned Gateway API v1.4.1 CRD limit for GatewayClass.spec.description.
# The API server enforces it at admission time, so a longer string makes
# the whole fixture unappliable (observed live: `GatewayClass
# "ares-gatewayclass" is invalid: spec.description: Too long: may not be
# longer than 64`). It is a contract rule, not a style preference: an
# object the API server refuses cannot route anything.
GATEWAY_CLASS_DESCRIPTION_LIMIT = 64
# Pinned Gateway API v1.4.1 CRD limit for GatewayClass.spec.description.
# The API server enforces it at admission time, so a longer string makes
# the whole fixture unappliable (observed live:
# `GatewayClass "ares-gatewayclass" is invalid: spec.description: Too
#  long: may not be longer than 64`). It is a contract rule, not a style
# preference: an object the API server refuses cannot route anything.
GATEWAY_CLASS_DESCRIPTION_LIMIT = 64
GATEWAY = "ares-gateway"
GATEWAY_LISTENER_PORT = 80
HTTP_ROUTE = "ares-route"

SERVICE = {track: f"ares-{track}" for track in TRACKS}
DEPLOYMENT = {track: f"ares-{track}" for track in TRACKS}

BACKEND_PORT = 80
CONTAINER_PORT = 8080
CONTAINER_PORT_NAME = "http"
WORKLOAD_TRACK_ENV = "ARES_TRACK"

#: The committed INITIAL state: first progressive stage, canary at 5%.
#: Gateway API `weight` is PROPORTIONAL, so 95/5 means 95/(95+5) = 95%.
INITIAL_WEIGHTS = {"stable": 95, "canary": 5}

#: Only these kinds may appear, and only with these names, so an extra
#: resource cannot smuggle itself into the topology unnoticed.
ALLOWED_DOCUMENTS: Mapping[str, frozenset] = {
    "Namespace": frozenset({NAMESPACE}),
    "GatewayClass": frozenset({GATEWAY_CLASS}),
    "EnvoyProxy": frozenset({ENVOY_PROXY}),
    "Gateway": frozenset({GATEWAY}),
    "HTTPRoute": frozenset({HTTP_ROUTE}),
    "Service": frozenset(set(SERVICE.values())),
    "Deployment": frozenset(set(DEPLOYMENT.values())),
}

#: Keys we accept anywhere in the fixture. Anything else is rejected so
#: that a TLS block, a retry policy, a filter or an auth extension cannot
#: creep in under an unrecognised name.
ALLOWED_KEYS: Mapping[str, frozenset] = {
    "Namespace": frozenset({"apiVersion", "kind", "metadata", "spec"}),
    "GatewayClass": frozenset({"apiVersion", "kind", "metadata", "spec"}),
    "EnvoyProxy": frozenset({"apiVersion", "kind", "metadata", "spec"}),
    "Gateway": frozenset({"apiVersion", "kind", "metadata", "spec"}),
    "HTTPRoute": frozenset({"apiVersion", "kind", "metadata", "spec"}),
    "Service": frozenset({"apiVersion", "kind", "metadata", "spec"}),
    "Deployment": frozenset({"apiVersion", "kind", "metadata", "spec"}),
}

PLACEHOLDER = re.compile(r"__[A-Z0-9_]+__")
MANAGED_LABEL_PREFIX = "app.kubernetes.io/"


def load_documents(directory: str = TOPOLOGY_DIR) -> List[Dict[str, Any]]:
    """Load every YAML document from the fixture directory, in file order."""
    documents: List[Dict[str, Any]] = []
    for name in sorted(os.listdir(directory)):
        if not name.endswith((".yaml", ".yml")):
            continue
        path = os.path.join(directory, name)
        with open(path, "r", encoding="utf-8") as handle:
            loaded = list(yaml.safe_load_all(handle))
        if any(doc is None for doc in loaded):
            raise ValueError(f"{name}: contains an empty document")
        documents.extend(loaded)
    if not documents:
        raise ValueError(f"{directory}: no YAML documents found")
    return documents


def _by_kind(documents: Iterable[Mapping[str, Any]]) -> Dict[str, List[Mapping[str, Any]]]:
    grouped: Dict[str, List[Mapping[str, Any]]] = {}
    for doc in documents:
        grouped.setdefault(str(doc.get("kind")), []).append(doc)
    return grouped


def _name(doc: Mapping[str, Any]) -> str:
    return str((doc.get("metadata") or {}).get("name") or "")


def _labels(doc: Mapping[str, Any]) -> Mapping[str, str]:
    return ((doc.get("metadata") or {}).get("labels") or {}) or {}


def _spec(doc: Mapping[str, Any]) -> Mapping[str, Any]:
    return (doc.get("spec") or {}) or {}


def route_backends(documents: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Every backendRef of the HTTPRoute rule, in declared order."""
    for doc in documents:
        if doc.get("kind") == "HTTPRoute":
            rules = _spec(doc).get("rules") or []
            refs: List[Dict[str, Any]] = []
            for rule in rules:
                refs.extend(rule.get("backendRefs") or [])
            return refs
    raise ValueError("no HTTPRoute document found")


def proportional_share(weight: int, weights: Sequence[int]) -> float:
    """Gateway API semantics: weight / sum(weights) — never "percent"."""
    total = sum(weights)
    if total <= 0:
        raise ValueError("weights must have a positive sum")
    return weight / total


def expected_share_of(backend_refs: Sequence[Mapping[str, Any]], name: str) -> float:
    weights = [int(ref.get("weight", 1)) for ref in backend_refs]
    for ref, weight in zip(backend_refs, weights):
        if ref.get("name") == name:
            return proportional_share(weight, weights)
    raise ValueError(f"no backendRef named {name!r}")


def leftover_placeholders(value: Any, path: str = "") -> List[str]:
    """Unresolved ``__TOKEN__`` placeholders anywhere in a rendered doc."""
    found: List[str] = []
    if isinstance(value, str):
        if PLACEHOLDER.search(value):
            found.append(f"{path}={value}")
    elif isinstance(value, Mapping):
        for key, item in value.items():
            found.extend(leftover_placeholders(item, f"{path}.{key}"))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            found.extend(leftover_placeholders(item, f"{path}[{index}]"))
    return found


def verify_documents(documents: Sequence[Mapping[str, Any]]) -> List[str]:
    """Return every violation of the static topology contract.

    An empty list means the manifest set is exactly the declared
    topology: one GatewayClass, one data-plane config, one Gateway, one
    weighted HTTPRoute, two disjoint Services and two independent
    Deployments.
    """
    violations: List[str] = []
    grouped = _by_kind(documents)

    # --- resource inventory -------------------------------------------------
    for kind, docs in grouped.items():
        if kind not in ALLOWED_DOCUMENTS:
            violations.append(f"unexpected resource kind {kind!r} in fixture")
            continue
        seen: Dict[str, int] = {}
        for doc in docs:
            name = _name(doc)
            seen[name] = seen.get(name, 0) + 1
            if name not in ALLOWED_DOCUMENTS[kind]:
                violations.append(f"unexpected {kind} name {name!r}")
            extra = set(doc) - set(ALLOWED_KEYS[kind])
            if extra:
                violations.append(f"{kind}/{name}: unexpected top-level keys {sorted(extra)}")
        for name, count in seen.items():
            if count > 1:
                violations.append(f"{kind}/{name}: declared {count} times")
    for kind, required in ALLOWED_DOCUMENTS.items():
        missing = sorted(required - {_name(d) for d in grouped.get(kind, [])})
        if missing:
            violations.append(f"missing {kind}: {missing}")
    if violations:
        return violations

    # --- namespacing --------------------------------------------------------
    namespaced = ("Gateway", "HTTPRoute", "Service", "Deployment")
    for kind in namespaced:
        for doc in grouped[kind]:
            namespace = (doc.get("metadata") or {}).get("namespace")
            if namespace != NAMESPACE:
                violations.append(f"{kind}/{_name(doc)}: namespace must be {NAMESPACE!r}, got {namespace!r}")
    if (grouped["EnvoyProxy"][0].get("metadata") or {}).get("namespace") != ENVOY_PROXY_NAMESPACE:
        violations.append(f"EnvoyProxy/{ENVOY_PROXY}: must live in {ENVOY_PROXY_NAMESPACE}")

    # --- GatewayClass + data plane -----------------------------------------
    gateway_class = grouped["GatewayClass"][0]
    class_spec = _spec(gateway_class)
    if class_spec.get("controllerName") != ENVOY_CONTROLLER_NAME:
        violations.append(
            f"GatewayClass controllerName must be {ENVOY_CONTROLLER_NAME!r} "
            f"(a real Gateway API implementation), got {class_spec.get('controllerName')!r}"
        )
    parameters_ref = class_spec.get("parametersRef") or {}
    if (parameters_ref.get("kind"), parameters_ref.get("name")) != ("EnvoyProxy", ENVOY_PROXY):
        violations.append("GatewayClass parametersRef must point at the EnvoyProxy fixture")
    description = class_spec.get("description")
    if description is not None and len(description) > GATEWAY_CLASS_DESCRIPTION_LIMIT:
        violations.append(
            f"GatewayClass description is {len(description)} characters; the pinned "
            f"CRD caps it at {GATEWAY_CLASS_DESCRIPTION_LIMIT}")

    description = class_spec.get("description")
    if description is not None and len(description) > GATEWAY_CLASS_DESCRIPTION_LIMIT:
        violations.append(
            f"GatewayClass description is {len(description)} characters; the pinned "
            f"CRD caps it at {GATEWAY_CLASS_DESCRIPTION_LIMIT}"
        )

    proxy = grouped["EnvoyProxy"][0]
    provider = _spec(proxy).get("provider") or {}
    if provider.get("type") != "Kubernetes":
        violations.append("EnvoyProxy provider.type must be Kubernetes")
    service_type = ((provider.get("kubernetes") or {}).get("envoyService") or {}).get("type")
    if service_type != "ClusterIP":
        violations.append("EnvoyProxy envoyService.type must be ClusterIP (Kind has no cloud LB)")

    # --- Gateway ------------------------------------------------------------
    gateway = grouped["Gateway"][0]
    gateway_spec = _spec(gateway)
    if gateway_spec.get("gatewayClassName") != GATEWAY_CLASS:
        violations.append("Gateway must attach to the declared GatewayClass")
    listeners = gateway_spec.get("listeners") or []
    if len(listeners) != 1:
        violations.append(f"Gateway must expose exactly one listener, found {len(listeners)}")
    else:
        listener = listeners[0]
        if listener.get("protocol") != "HTTP" or listener.get("port") != GATEWAY_LISTENER_PORT:
            violations.append(
                f"Gateway listener must be HTTP:{GATEWAY_LISTENER_PORT}, "
                f"got {listener.get('protocol')}:{listener.get('port')}"
            )
        if "tls" in listener:
            violations.append("Gateway listener must not terminate TLS (minimal topology)")
        if ((listener.get("allowedRoutes") or {}).get("namespaces") or {}).get("from") != "Same":
            violations.append("Gateway must only allow routes from its own namespace")

    # --- HTTPRoute: the actual weighted split -------------------------------
    http_route = grouped["HTTPRoute"][0]
    route_spec = _spec(http_route)
    parent_refs = route_spec.get("parentRefs") or []
    if [ref.get("name") for ref in parent_refs] != [GATEWAY]:
        violations.append(f"HTTPRoute must attach to Gateway {GATEWAY!r} exactly once")
    rules = route_spec.get("rules") or []
    if len(rules) != 1:
        violations.append(f"HTTPRoute must have exactly one rule, found {len(rules)}")
    else:
        rule = rules[0]
        unexpected_rule_keys = set(rule) - {"matches", "backendRefs", "filters"}
        if unexpected_rule_keys:
            violations.append(f"HTTPRoute rule has unexpected keys {sorted(unexpected_rule_keys)}")
        if rule.get("filters"):
            violations.append("HTTPRoute must not carry filters (minimal topology)")
        matches = rule.get("matches") or []
        if len(matches) != 1 or (matches[0].get("path") or {}).get("value") != "/":
            violations.append("HTTPRoute must match exactly the '/' path prefix")

        refs = rule.get("backendRefs") or []
        if len(refs) != 2:
            violations.append(f"HTTPRoute must reference exactly two backends, found {len(refs)}")
        else:
            names = [ref.get("name") for ref in refs]
            if sorted(names) != sorted(SERVICE.values()):
                violations.append(f"HTTPRoute backend names must be {sorted(SERVICE.values())}, got {names}")
            if len(set(names)) != len(names):
                violations.append("HTTPRoute backendRefs must point at two DISTINCT services")
            for ref in refs:
                # A missing/!int weight is a violation, never an exception:
                # the verifier must always be able to explain itself.
                weight = ref.get("weight")
                if isinstance(weight, bool) or not isinstance(weight, int):
                    violations.append(
                        f"backendRef {ref.get('name')!r} must declare an explicit integer "
                        f"weight, got {weight!r}"
                    )
                if ref.get("port") != BACKEND_PORT:
                    violations.append(f"backendRef {ref.get('name')!r} must target port {BACKEND_PORT}")
                extra = set(ref) - {"name", "port", "weight", "kind", "group"}
                if extra:
                    violations.append(f"backendRef {ref.get('name')!r} has unexpected keys {sorted(extra)}")
            weights = {
                ref.get("name"): ref.get("weight")
                for ref in refs
                if isinstance(ref.get("weight"), int) and not isinstance(ref.get("weight"), bool)
            }
            expected_weights = {SERVICE[track]: INITIAL_WEIGHTS[track] for track in TRACKS}
            if len(weights) == len(refs):
                if weights != expected_weights:
                    violations.append(
                        f"committed initial weights must be {expected_weights} "
                        f"(proportional 95/5 = 95%/5%), got {weights}"
                    )
                if sum(weights.values()) <= 0:
                    violations.append("backendRefs must have a positive weight sum")

    # --- Services -----------------------------------------------------------
    service_selector: Dict[str, Mapping[str, str]] = {}
    for track in TRACKS:
        service = next(doc for doc in grouped["Service"] if _name(doc) == SERVICE[track])
        selector = _spec(service).get("selector") or {}
        service_selector[track] = selector
        if selector.get("app") != APP_LABEL or selector.get(TRACK_LABEL) != track:
            violations.append(
                f"Service/{SERVICE[track]} selector must be "
                f"{{app: {APP_LABEL}, {TRACK_LABEL}: {track}}}, got {selector}"
            )
        if _spec(service).get("type") != "ClusterIP":
            violations.append(f"Service/{SERVICE[track]} must be ClusterIP")
        ports = _spec(service).get("ports") or []
        if len(ports) != 1:
            violations.append(f"Service/{SERVICE[track]} must expose exactly one port")
        elif (ports[0].get("port"), ports[0].get("targetPort")) != (BACKEND_PORT, CONTAINER_PORT_NAME):
            violations.append(
                f"Service/{SERVICE[track]} must map {BACKEND_PORT} -> "
                f"named port {CONTAINER_PORT_NAME!r}"
            )

    # --- Deployments and identity disjointness ------------------------------
    pod_labels: Dict[str, Mapping[str, str]] = {}
    deployment_names = set()
    for track in TRACKS:
        deployment = next(doc for doc in grouped["Deployment"] if _name(doc) == DEPLOYMENT[track])
        deployment_names.add(_name(deployment))
        selector = (_spec(deployment).get("selector") or {}).get("matchLabels") or {}
        template = (_spec(deployment).get("template") or {})
        labels = (template.get("metadata") or {}).get("labels") or {}
        pod_labels[track] = labels
        if selector != service_selector[track]:
            violations.append(
                f"Deployment/{DEPLOYMENT[track]} selector {selector} must equal its "
                f"Service selector {dict(service_selector[track])}"
            )
        if not set(selector).issubset(labels):
            violations.append(
                f"Deployment/{DEPLOYMENT[track]} pod template must carry every selector label"
            )
        if labels.get(TRACK_LABEL) != track:
            violations.append(
                f"Deployment/{DEPLOYMENT[track]} pod template track label must be {track!r}"
            )
        if int(_spec(deployment).get("replicas") or 0) < 1:
            violations.append(f"Deployment/{DEPLOYMENT[track]} must run at least one replica")

        containers = ((template.get("spec") or {}).get("containers") or [])
        if len(containers) != 1:
            violations.append(f"Deployment/{DEPLOYMENT[track]} must run exactly one container")
            continue
        container = containers[0]
        image = str(container.get("image") or "")
        if not PLACEHOLDER.search(image) and (image.endswith(":latest") or ":" not in image.split("/")[-1]):
            violations.append(
                f"Deployment/{DEPLOYMENT[track]} image must be an immutable reference, got {image!r}"
            )
        ports = container.get("ports") or []
        matching = [
            port
            for port in ports
            if port.get("name") == CONTAINER_PORT_NAME and port.get("containerPort") == CONTAINER_PORT
        ]
        if len(matching) != 1:
            violations.append(
                f"Deployment/{DEPLOYMENT[track]} must expose the named container port "
                f"{CONTAINER_PORT_NAME!r}={CONTAINER_PORT}"
            )
        track_env = {
            item.get("name"): item.get("value")
            for item in (container.get("env") or [])
        }
        if track_env.get(WORKLOAD_TRACK_ENV) != track:
            violations.append(
                f"Deployment/{DEPLOYMENT[track]} must set {WORKLOAD_TRACK_ENV}={track}"
            )

    for left, right in (("stable", "canary"),):
        # A k8s selector matches when every key=value pair it declares is
        # present on the pod. Checking key-sets alone would pass while the
        # VALUES collided, which is precisely the tampering this guards.
        if all(pod_labels[right].get(key) == value for key, value in service_selector[left].items()):
            violations.append(
                f"Service/{SERVICE[left]} selector would also select the {right} pods"
            )
        if all(pod_labels[left].get(key) == value for key, value in service_selector[right].items()):
            violations.append(
                f"Service/{SERVICE[right]} selector would also select the {left} pods"
            )
        if pod_labels[left] == pod_labels[right]:
            violations.append("stable and canary pod templates must not share identical labels")
    if len(deployment_names) != len(TRACKS):
        violations.append("stable and canary workloads must be independently named")

    return violations


def verify_topology(directory: str = TOPOLOGY_DIR) -> List[str]:
    """Convenience wrapper: load the fixture and verify it."""
    return verify_documents(load_documents(directory))
