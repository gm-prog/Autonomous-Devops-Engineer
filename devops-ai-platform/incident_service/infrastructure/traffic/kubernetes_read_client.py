"""Phase 8.7-B.1 — read-only Kubernetes client for traffic observation.

This module is the *only* place in the incident service that talks to a
Kubernetes API server, and it can only read. It mirrors the execution
policy of ``deployment_service/application/services/kubectl_sandbox.py``
(Phase 8.6-A), with the write half removed:

* a closed set of **read** operations (:class:`ReadOperation`) and a
  module-level argv builder — there is deliberately no ``run(argv)`` or
  ``run_kubectl(command)`` entry point, so a caller cannot turn the
  observer into an arbitrary Kubernetes CLI;
* every variable element (namespace, resource name, service name, app
  label, context) is validated as a Kubernetes name/label before it
  reaches the argv, so no value can smuggle a flag or a subcommand;
* the resource and verb are host-owned constants: ``get`` and only
  ``get``, with a fixed resource per operation. No ``apply``, ``patch``,
  ``replace``, ``delete``, ``create``, ``edit``, ``exec``, ``rollout`` or
  ``--raw`` is reachable — not by argument, not by configuration;
* output is bounded and parsed strictly, and failure text is bounded and
  redacted before it can reach ``ObservedTrafficState.detail``.

Configuration is a frozen snapshot taken once at construction
(:meth:`TrafficReadConfig.from_environment`), so one observation can
never be built from configuration that changed half-way through it —
the same rule Phase 8.6-A applied to the deployment path.

Not-in-scope, deliberately: this client does not know what traffic means.
It returns raw resource documents; interpreting them is the observer's
job (``gateway_api_observer``). Keeping the two apart is what makes the
observer testable without a cluster and the client auditable on its own.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

#: Kubernetes names (RFC 1123 subdomain labels) and label values.
_DNS_1123 = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
_LABEL_VALUE = re.compile(r"^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$")
#: kubeconfig context names may contain dots, colons, slashes and @.
_CONTEXT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@:/-]{0,253}$")

#: System namespaces are never a traffic-observation target. Defence in
#: depth: the namespace is host-owned configuration, and this makes even
#: a misconfiguration fail closed instead of reading cluster plumbing.
RESERVED_NAMESPACES = frozenset(
    {"kube-system", "kube-public", "kube-node-lease", "default",
     "local-path-storage"}
)

#: The only verbs this client can emit. A read-only client that could
#: also write would not be a read-only client.
READ_VERBS = frozenset({"get"})

#: Subcommands that must never be reachable through this module.
FORBIDDEN_SUBCOMMANDS = frozenset(
    {"apply", "patch", "replace", "delete", "deletecollection", "create",
     "edit", "scale", "annotate", "label", "set", "exec", "cp", "attach",
     "port-forward", "proxy", "plugin", "drain", "cordon", "uncordon",
     "taint", "run", "expose", "autoscale", "certificate", "auth",
     "config", "rollout", "debug", "top"}
)

#: Bounded output: a response larger than this is refused rather than
#: truncated into a half-parsed document.
MAX_OUTPUT_BYTES = 262144

#: Label keys used to select resources. Host-owned: callers can supply
#: the *values* (validated), never the keys.
SERVICE_NAME_LABEL = "kubernetes.io/service-name"
APP_LABEL_KEY = "app"

DEFAULT_OBSERVE_TIMEOUT = 30


class KubernetesReadError(RuntimeError):
    """A read could not be performed or its answer cannot be trusted."""


class KubernetesReadPolicyViolation(KubernetesReadError):
    """A caller tried to leave the closed read policy."""


class KubernetesReadTimeout(KubernetesReadError):
    """The read did not finish inside its budget (fail closed)."""


class KubernetesResourceNotFound(KubernetesReadError):
    """The API server answered that the resource does not exist.

    Kept distinct from other read failures because "absent" and
    "unavailable" are different observations (both fail closed, but for
    different reasons, and the caller reports which one it saw).
    """


class ReadOperation(str, Enum):
    """The closed set of Kubernetes reads traffic observation may perform."""

    HTTP_ROUTE = "http_route"
    SERVICE = "service"
    ENDPOINT_SLICES = "endpoint_slices"
    PODS = "pods"
    DEPLOYMENTS = "deployments"


#: The resource each operation reads. Fixed here, never passed in.
OPERATION_RESOURCES: Dict[ReadOperation, str] = {
    ReadOperation.HTTP_ROUTE: "httproute",
    ReadOperation.SERVICE: "service",
    ReadOperation.ENDPOINT_SLICES: "endpointslice",
    ReadOperation.PODS: "pods",
    ReadOperation.DEPLOYMENTS: "deployments",
}

#: Wall-clock budget per operation, in seconds. Reads are short by
#: design: observation never waits for convergence (that is the
#: controller's job, and B.0 already proved it happens).
OPERATION_TIMEOUTS: Dict[ReadOperation, int] = {
    ReadOperation.HTTP_ROUTE: DEFAULT_OBSERVE_TIMEOUT,
    ReadOperation.SERVICE: DEFAULT_OBSERVE_TIMEOUT,
    ReadOperation.ENDPOINT_SLICES: DEFAULT_OBSERVE_TIMEOUT,
    ReadOperation.PODS: DEFAULT_OBSERVE_TIMEOUT,
    ReadOperation.DEPLOYMENTS: DEFAULT_OBSERVE_TIMEOUT,
}


def _validate_name(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DNS_1123.match(value):
        raise KubernetesReadPolicyViolation(
            f"{field} {value!r} is not a valid Kubernetes name"
        )
    if len(value) > 63:
        raise KubernetesReadPolicyViolation(
            f"{field} is {len(value)} characters; Kubernetes names are "
            f"limited to 63 and an over-long value indicates injection"
        )
    return value


def _validate_label_value(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _LABEL_VALUE.match(value):
        raise KubernetesReadPolicyViolation(
            f"{field} {value!r} is not a valid Kubernetes label value"
        )
    if len(value) > 63:
        raise KubernetesReadPolicyViolation(f"{field} is longer than 63 characters")
    return value


def _validate_context(value: Any) -> str:
    if value in (None, ""):
        return ""
    if not isinstance(value, str) or not _CONTEXT_NAME.match(value):
        raise KubernetesReadPolicyViolation(
            f"kubeconfig context {value!r} is not a valid context name"
        )
    return value


def _validate_path(value: Any, field: str) -> str:
    if value in (None, ""):
        return ""
    if not isinstance(value, str) or "\n" in value or "\x00" in value:
        raise KubernetesReadPolicyViolation(f"{field} is not a usable path")
    return value


def build_read_argv(
    operation: ReadOperation,
    *,
    namespace: str,
    name: Optional[str] = None,
    service_name: Optional[str] = None,
    app_label: Optional[str] = None,
    context: str = "",
    kubeconfig: str = "",
    request_timeout: Optional[int] = None,
    kubectl: str = "kubectl",
) -> Tuple[str, ...]:
    """Build the exact argv for one read.

    Every element is host-owned or validated here. The verb is always
    ``get``; the resource comes from :data:`OPERATION_RESOURCES`; the
    optional ``-l`` selector key is a module constant. There is no
    parameter through which a caller could supply a verb, a flag or a
    resource of their choosing.
    """
    if not isinstance(operation, ReadOperation):
        raise KubernetesReadPolicyViolation(
            f"unknown read operation {operation!r}; the operation set is closed"
        )
    if not isinstance(kubectl, str) or not kubectl or any(
        character.isspace() for character in kubectl
    ):
        raise KubernetesReadPolicyViolation(f"kubectl binary {kubectl!r} is not usable")
    _validate_name(namespace, "namespace")
    if namespace in RESERVED_NAMESPACES:
        raise KubernetesReadPolicyViolation(
            f"namespace {namespace!r} is a reserved system namespace and is "
            f"never a traffic-observation target"
        )

    argv: List[str] = [kubectl, "get", OPERATION_RESOURCES[operation]]
    context = _validate_context(context)
    if context:
        argv += ["--context", context]
    kubeconfig = _validate_path(kubeconfig, "kubeconfig")
    if kubeconfig:
        argv += ["--kubeconfig", kubeconfig]

    if operation in (ReadOperation.HTTP_ROUTE, ReadOperation.SERVICE):
        argv.append(_validate_name(name, f"{operation.value} name"))
    elif operation is ReadOperation.ENDPOINT_SLICES:
        argv += ["-l", f"{SERVICE_NAME_LABEL}={_validate_name(service_name, 'service name')}"]
    else:  # PODS / DEPLOYMENTS
        argv += ["-l", f"{APP_LABEL_KEY}={_validate_label_value(app_label, 'app label')}"]

    argv += ["-n", namespace, "-o", "json"]
    if request_timeout is not None:
        if not isinstance(request_timeout, int) or isinstance(request_timeout, bool):
            raise KubernetesReadPolicyViolation("request_timeout must be an integer")
        if request_timeout < 1 or request_timeout > 300:
            raise KubernetesReadPolicyViolation(
                "request_timeout must be between 1 and 300 seconds"
            )
        argv += [f"--request-timeout={request_timeout}s"]

    for element in argv:
        if element in FORBIDDEN_SUBCOMMANDS:
            raise KubernetesReadPolicyViolation(
                f"{element!r} is a mutating subcommand and is never reachable"
            )
    if argv[1] not in READ_VERBS:
        raise KubernetesReadPolicyViolation(
            f"verb {argv[1]!r} is not a read verb; only {sorted(READ_VERBS)} may run"
        )
    return tuple(argv)


@dataclass(frozen=True)
class TrafficReadConfig:
    """Frozen, host-owned configuration for one observation client."""

    namespace: str = "ares-traffic"
    app_label: str = "ares-traffic"
    context: str = ""
    kubeconfig: str = ""
    kubectl: str = "kubectl"
    timeout_seconds: int = DEFAULT_OBSERVE_TIMEOUT

    @classmethod
    def from_environment(cls, environ: Optional[Dict[str, str]] = None) -> "TrafficReadConfig":
        """Snapshot configuration once, at construction.

        The client never reads the environment again, so a single
        observation cannot mix two configurations.
        """
        source = os.environ if environ is None else environ
        timeout_raw = (source.get("ARES_TRAFFIC_OBSERVE_TIMEOUT") or "").strip()
        try:
            timeout = int(timeout_raw) if timeout_raw else DEFAULT_OBSERVE_TIMEOUT
        except ValueError:
            timeout = DEFAULT_OBSERVE_TIMEOUT
        return cls(
            namespace=(source.get("ARES_TRAFFIC_NAMESPACE") or "ares-traffic").strip(),
            app_label=(source.get("ARES_TRAFFIC_APP_LABEL") or "ares-traffic").strip(),
            context=(source.get("ARES_TRAFFIC_KUBE_CONTEXT") or "").strip(),
            kubeconfig=(source.get("ARES_TRAFFIC_KUBECONFIG") or "").strip(),
            kubectl=(source.get("ARES_TRAFFIC_KUBECTL") or "kubectl").strip(),
            timeout_seconds=timeout,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Host-owned configuration, without credentials.

        ``kubeconfig`` is reported as a boolean because a filesystem path
        is environment detail an evidence artifact does not need.
        """
        return {
            "namespace": self.namespace,
            "app_label": self.app_label,
            "context": self.context,
            "kubeconfig_configured": bool(self.kubeconfig),
            "kubectl": self.kubectl,
            "timeout_seconds": self.timeout_seconds,
        }


def redact(text: Any, limit: int = 240) -> str:
    """Bound and redact command output before it reaches any caller.

    Failure text from a CLI can contain paths, server URLs and (on some
    misconfigurations) credential material. Only a bounded, single-line
    form is ever surfaced, and obvious credential shapes are removed.
    """
    if text is None:
        return ""
    collapsed = " ".join(str(text).split())
    collapsed = re.sub(
        r"(?i)\b(bearer|token|password|secret|client-key)\b\s*[:=]?\s*\S+",
        r"\1=<redacted>",
        collapsed,
    )
    # Cluster-configuration paths are environment detail: a failure text
    # never needs to name where a kubeconfig lives.
    collapsed = re.sub(r"/(?:[\w.-]+/)+[\w.-]+", "<path>", collapsed)
    if len(collapsed) > limit:
        collapsed = f"{collapsed[:limit]}…"
    return collapsed


class KubectlReadClient:
    """Concrete read client: fixed read operations, no arbitrary argv.

    ``runner`` is injectable so tests can exercise the whole client
    (validation, parsing, bounds, redaction) without a cluster; it is
    the single place a process is spawned.
    """

    def __init__(
        self,
        config: Optional[TrafficReadConfig] = None,
        *,
        runner: Optional[Callable[..., Any]] = None,
    ) -> None:
        self._config = config or TrafficReadConfig()
        self._runner = runner or subprocess.run
        _validate_name(self._config.namespace, "namespace")
        _validate_label_value(self._config.app_label, "app label")
        if self._config.namespace in RESERVED_NAMESPACES:
            raise KubernetesReadPolicyViolation(
                f"namespace {self._config.namespace!r} is reserved"
            )
        if not isinstance(self._config.timeout_seconds, int) or isinstance(
            self._config.timeout_seconds, bool
        ) or not (1 <= self._config.timeout_seconds <= 300):
            raise KubernetesReadPolicyViolation(
                "timeout_seconds must be an integer between 1 and 300"
            )

    # ------------------------------------------------------------- config

    @property
    def config(self) -> TrafficReadConfig:
        return self._config

    def _argv(self, operation: ReadOperation, namespace: str, **kwargs: Any) -> Tuple[str, ...]:
        """Build this client's argv for one read, with its own bounds."""
        return build_read_argv(
            operation,
            namespace=namespace,
            context=self._config.context,
            kubeconfig=self._config.kubeconfig,
            kubectl=self._config.kubectl,
            request_timeout=min(OPERATION_TIMEOUTS[operation],
                                self._config.timeout_seconds),
            **kwargs,
        )

    # -------------------------------------------------------- read surface

    def get_http_route(self, name: str, namespace: str) -> Dict[str, Any]:
        return self._read_object(ReadOperation.HTTP_ROUTE, namespace, name=name)

    def get_service(self, name: str, namespace: str) -> Dict[str, Any]:
        return self._read_object(ReadOperation.SERVICE, namespace, name=name)

    def list_endpoint_slices(self, namespace: str, service_name: str) -> List[Dict[str, Any]]:
        document = self._read(
            self._argv(ReadOperation.ENDPOINT_SLICES, namespace,
                       service_name=service_name),
            ReadOperation.ENDPOINT_SLICES,
        )
        return _items(document, ReadOperation.ENDPOINT_SLICES)

    def list_pods(self, namespace: str, app_label: str) -> List[Dict[str, Any]]:
        document = self._read(
            self._argv(ReadOperation.PODS, namespace, app_label=app_label),
            ReadOperation.PODS,
        )
        return _items(document, ReadOperation.PODS)

    def list_deployments(self, namespace: str, app_label: str) -> List[Dict[str, Any]]:
        document = self._read(
            self._argv(ReadOperation.DEPLOYMENTS, namespace, app_label=app_label),
            ReadOperation.DEPLOYMENTS,
        )
        return _items(document, ReadOperation.DEPLOYMENTS)

    # -------------------------------------------------------------- internals

    def _read_object(self, operation: ReadOperation, namespace: str, *, name: str):
        document = self._read(self._argv(operation, namespace, name=name), operation)
        if not isinstance(document, dict) or "kind" not in document:
            raise KubernetesReadError(
                f"{operation.value}: the API server did not return a resource object"
            )
        return document

    def _read(self, argv: Sequence[str], operation: ReadOperation) -> Any:
        timeout = OPERATION_TIMEOUTS[operation]
        try:
            completed = self._runner(list(argv), capture_output=True, text=True,
                                     timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:  # pragma: no cover - timing dependent
            raise KubernetesReadTimeout(
                f"{operation.value} timed out after {timeout}s"
            ) from exc
        except FileNotFoundError as exc:  # pragma: no cover - environment dependent
            raise KubernetesReadError(
                f"{operation.value}: kubectl {self._config.kubectl!r} is not available"
            ) from exc
        except OSError as exc:  # pragma: no cover - environment dependent
            raise KubernetesReadError(
                f"{operation.value}: kubectl could not run: {redact(exc)}"
            ) from exc

        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        if len(stdout) > MAX_OUTPUT_BYTES or len(stderr) > MAX_OUTPUT_BYTES:
            raise KubernetesReadError(
                f"{operation.value}: response exceeded {MAX_OUTPUT_BYTES} bytes"
            )
        if completed.returncode != 0:
            if "NotFound" in stderr:
                raise KubernetesResourceNotFound(
                    f"{operation.value}: {redact(stderr)}"
                )
            raise KubernetesReadError(
                f"{operation.value} failed (rc={completed.returncode}): {redact(stderr)}"
            )
        try:
            return json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise KubernetesReadError(
                f"{operation.value}: response is not JSON ({redact(exc)})"
            ) from exc


def _items(document: Any, operation: ReadOperation) -> List[Dict[str, Any]]:
    if not isinstance(document, dict):
        raise KubernetesReadError(f"{operation.value}: expected a list response")
    items = document.get("items")
    if not isinstance(items, list):
        raise KubernetesReadError(f"{operation.value}: response has no item list")
    for item in items:
        if not isinstance(item, dict):
            raise KubernetesReadError(f"{operation.value}: malformed item in response")
    return items


__all__ = [
    "APP_LABEL_KEY",
    "DEFAULT_OBSERVE_TIMEOUT",
    "FORBIDDEN_SUBCOMMANDS",
    "KubernetesReadError",
    "KubernetesReadPolicyViolation",
    "KubernetesReadTimeout",
    "KubernetesResourceNotFound",
    "KubectlReadClient",
    "MAX_OUTPUT_BYTES",
    "OPERATION_RESOURCES",
    "OPERATION_TIMEOUTS",
    "READ_VERBS",
    "RESERVED_NAMESPACES",
    "ReadOperation",
    "SERVICE_NAME_LABEL",
    "TrafficReadConfig",
    "build_read_argv",
    "redact",
]
