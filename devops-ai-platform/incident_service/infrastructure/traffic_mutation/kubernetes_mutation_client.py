"""Phase 8.7-B.2 — closed Kubernetes write client for authorized traffic mutations.

This module is the *only* new place in the incident service that can change
a Kubernetes resource, and it can change exactly one thing: the
``backendRef`` weights of the single weighted route the Phase 8.7-B.0
topology defines. It is the write-side counterpart of
:mod:`kubernetes_read_client`, and it is deliberately as narrow:

* **one** operation (:class:`MutationOperation.SET_BACKEND_WEIGHTS`), with a
  host-owned mutating verb (``patch``) and a host-owned resource
  (``httproute``) — there is no ``run(argv)``, no ``run_kubectl(command)``,
  no shell, no arbitrary file, no arbitrary resource kind and no caller
  payload anywhere in this module;
* the JSON patch document is **built here** from typed values
  (:class:`WeightMutation` / :class:`BackendWeightChange`). No public
  function in this module accepts a patch document, a path expression or a
  command string, so a caller cannot inject a mutation the provider did not
  authorize;
* every variable element (namespace, route name, backend names, context,
  kubeconfig, kubectl binary, request timeout) is validated with the *same*
  validators the read client uses — one source of truth for Kubernetes
  identifier validation, imported rather than re-implemented;
* the patch is a **compare-and-set**: it carries an RFC 6902 ``test`` on the
  route's ``metadata.resourceVersion`` and on each weight it is about to
  replace, so the API server itself rejects the whole patch if the route
  moved between the observation and the write. The write path therefore does
  not depend on a client-side lock, and a lost race cannot silently apply a
  stale decision;
* the outcome is three-valued (:data:`ATTEMPT_ACCEPTED`,
  :data:`ATTEMPT_REJECTED`, :data:`ATTEMPT_UNKNOWN`). A successful exit
  status is *not* verification: it means the API server accepted the write,
  and nothing more. A timeout, a killed process or a lost response is
  ``UNKNOWN`` — never a reason to replay the write.

Failure text is bounded and redacted exactly as on the read side, so a
kubeconfig path or a credential-shaped token cannot leak into evidence.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

#: One source of truth for Kubernetes identifier validation. The write path
#: deliberately imports the read client's validators instead of re-implementing
#: them: a second copy of "what is a valid namespace/name/context" would be a
#: second, weaker interpretation of the same rule, and the first thing an
#: attacker would find is whichever copy is more permissive. The private names
#: are stable within this package pair and are asserted by the B.2 tests.
from incident_service.infrastructure.traffic.kubernetes_read_client import (
    RESERVED_NAMESPACES,
    KubernetesReadPolicyViolation,
    TrafficReadConfig,
    _validate_context,
    _validate_path,
    redact,
)

#: Wall-clock budget for one bounded write attempt, in seconds. A write is
#: short: it either lands or it does not, and an unknown outcome is resolved
#: by re-observing, never by waiting longer or by replaying.
DEFAULT_MUTATION_TIMEOUT = 30

#: Largest response this client will accept from one write attempt.
MAX_OUTPUT_BYTES = 256 * 1024

#: The ONLY mutating verb this module can emit. The verb is host-owned: no
#: parameter of any public function can supply it.
MUTATING_VERBS = frozenset({"patch"})

#: Subcommands that must never appear in any argv this module can build.
#: ``patch`` is the one authorized mutating verb and is deliberately absent
#: from this list; everything else that could change cluster state is here.
FORBIDDEN_SUBCOMMANDS = frozenset({
    "apply", "create", "replace", "delete", "edit", "scale", "set",
    "annotate", "label", "cordon", "uncordon", "drain", "taint", "exec",
    "cp", "port-forward", "proxy", "rollout", "expose", "run", "cp",
    "auth", "config", "certificate", "top", "attach", "debug",
})

#: Outcome vocabulary of one bounded mutation attempt.
ATTEMPT_ACCEPTED = "accepted"
ATTEMPT_REJECTED = "rejected"
ATTEMPT_UNKNOWN = "unknown"
ATTEMPT_STATES: Tuple[str, ...] = (ATTEMPT_ACCEPTED, ATTEMPT_REJECTED, ATTEMPT_UNKNOWN)

#: Bound on the resourceVersion string the patch compares against.
MAX_RESOURCE_VERSION_LENGTH = 64

#: Largest weight this client will write. Weights are proportional
#: integers; the provider only ever writes pairs that sum to 100, and this
#: bound keeps a malformed caller value out of the patch whatever it is.
MAX_WEIGHT = 1000


class MutationWriteError(RuntimeError):
    """A write that could not even be attempted."""


class KubernetesMutationPolicyViolation(MutationWriteError):
    """A value that must never reach the argv of a write."""


def _checked_name(value: Any, field: str) -> str:
    """The read client's name validator, in this package's error vocabulary.

    The rule is shared (one interpretation of a Kubernetes name); only the
    exception type is local, so a caller of the write path catches the write
    package's own policy violation.
    """
    from incident_service.infrastructure.traffic.kubernetes_read_client import (
        _validate_name,
    )

    try:
        return _validate_name(value, field)
    except KubernetesReadPolicyViolation as exc:
        raise KubernetesMutationPolicyViolation(str(exc)) from exc


def _checked_context(value: Any) -> str:
    try:
        return _validate_context(value)
    except KubernetesReadPolicyViolation as exc:
        raise KubernetesMutationPolicyViolation(str(exc)) from exc


def _checked_path(value: Any, field: str) -> str:
    try:
        return _validate_path(value, field)
    except KubernetesReadPolicyViolation as exc:
        raise KubernetesMutationPolicyViolation(str(exc)) from exc


class MutationOperation(str, Enum):
    """The closed mutation vocabulary — exactly one operation.

    An enum with one member is not a placeholder: it is the mechanical
    statement that this client cannot express any other change, and the
    structural tests assert that the enum has exactly this member.
    """

    SET_BACKEND_WEIGHTS = "set_backend_weights"


#: The resource the one operation writes. Fixed here, never passed in.
OPERATION_RESOURCES: Dict[MutationOperation, str] = {
    MutationOperation.SET_BACKEND_WEIGHTS: "httproute",
}

#: The one JSON-patch location prefix this module can write inside.
BACKEND_REFS_PATH = "/spec/rules/0/backendRefs"


@dataclass(frozen=True)
class BackendWeightChange:
    """One authorized weight change inside the single weighted rule.

    ``index``/``name``/``expected_weight`` are preconditions carried *inside*
    the patch (RFC 6902 ``test`` operations), so the API server rejects the
    whole write if the backend it names is no longer at that slot with that
    weight. ``new_weight`` is the only value this client changes.
    """

    index: int
    name: str
    expected_weight: int
    new_weight: int

    def __post_init__(self) -> None:
        if not isinstance(self.index, int) or isinstance(self.index, bool):
            raise KubernetesMutationPolicyViolation("change index must be an integer")
        if self.index < 0 or self.index > 8:
            raise KubernetesMutationPolicyViolation(
                "change index must be within [0, 8]; a weighted rule has two slots"
            )
        _checked_name(self.name, "backend name")
        for field, value in (("expected_weight", self.expected_weight),
                             ("new_weight", self.new_weight)):
            if not isinstance(value, int) or isinstance(value, bool):
                raise KubernetesMutationPolicyViolation(f"{field} must be an integer")
            if value < 0 or value > MAX_WEIGHT:
                raise KubernetesMutationPolicyViolation(
                    f"{field} must be within [0, {MAX_WEIGHT}]"
                )


@dataclass(frozen=True)
class WeightMutation:
    """The complete, typed description of the one authorized change.

    A provider builds this from its own trusted observation; the client
    turns it into the exact argv below. There is no path through this class
    that expresses a different resource, a different verb, a different rule
    index or a free-form payload.
    """

    route_name: str
    namespace: str
    resource_version: str
    changes: Tuple[BackendWeightChange, ...]

    def __post_init__(self) -> None:
        _checked_name(self.route_name, "route name")
        _checked_name(self.namespace, "namespace")
        if self.namespace in RESERVED_NAMESPACES:
            raise KubernetesMutationPolicyViolation(
                f"namespace {self.namespace!r} is reserved and is never a "
                f"traffic-mutation target"
            )
        resource_version = self.resource_version
        if (
            not isinstance(resource_version, str)
            or not resource_version
            or len(resource_version) > MAX_RESOURCE_VERSION_LENGTH
            or any(character.isspace() or not character.isprintable()
                   for character in resource_version)
        ):
            raise KubernetesMutationPolicyViolation(
                "resource_version must be a bounded, printable string: it is the "
                "compare-and-set token the write is conditioned on"
            )
        changes = tuple(self.changes)
        if len(changes) != 2:
            raise KubernetesMutationPolicyViolation(
                "a weighted route has exactly two backends to change"
            )
        if len({change.index for change in changes}) != 2:
            raise KubernetesMutationPolicyViolation("change indexes must be distinct")
        if len({change.name for change in changes}) != 2:
            raise KubernetesMutationPolicyViolation("change backend names must be distinct")
        for change in changes:
            if not isinstance(change, BackendWeightChange):
                raise KubernetesMutationPolicyViolation(
                    "changes must be BackendWeightChange values"
                )
        object.__setattr__(self, "changes", changes)

    @property
    def target_weights(self) -> Dict[str, int]:
        """The weights this mutation will write, keyed by backend name."""
        return {change.name: change.new_weight for change in self.changes}

    def to_dict(self) -> Dict[str, Any]:
        """Audit description of the mutation — never a command string."""
        return {
            "operation": MutationOperation.SET_BACKEND_WEIGHTS.value,
            "resource": OPERATION_RESOURCES[MutationOperation.SET_BACKEND_WEIGHTS],
            "route": self.route_name,
            "namespace": self.namespace,
            "backend_refs_path": BACKEND_REFS_PATH,
            "resource_version_precondition": self.resource_version,
            "changes": [
                {
                    "index": change.index,
                    "name": change.name,
                    "expected_weight": change.expected_weight,
                    "new_weight": change.new_weight,
                }
                for change in self.changes
            ],
        }


@dataclass(frozen=True)
class TrafficWriteConfig:
    """Frozen, host-owned configuration for one write client.

    Same shape and same snapshot discipline as the read client's
    configuration: the environment is read once, at construction, so a
    single mutation cannot be built from configuration that changed
    half-way through it.
    """

    namespace: str = "ares-traffic"
    context: str = ""
    kubeconfig: str = ""
    kubectl: str = "kubectl"
    timeout_seconds: int = DEFAULT_MUTATION_TIMEOUT

    @classmethod
    def from_environment(
        cls, environ: Optional[Mapping[str, str]] = None
    ) -> "TrafficWriteConfig":
        source = os.environ if environ is None else environ
        read = TrafficReadConfig.from_environment(source)
        timeout_raw = (source.get("ARES_TRAFFIC_MUTATION_TIMEOUT") or "").strip()
        try:
            timeout = int(timeout_raw) if timeout_raw else DEFAULT_MUTATION_TIMEOUT
        except ValueError:
            timeout = DEFAULT_MUTATION_TIMEOUT
        return cls(
            namespace=read.namespace,
            context=read.context,
            kubeconfig=read.kubeconfig,
            kubectl=read.kubectl,
            timeout_seconds=timeout,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Host-owned configuration, without credentials or paths."""
        return {
            "namespace": self.namespace,
            "context": self.context,
            "kubeconfig_configured": bool(self.kubeconfig),
            "kubectl": self.kubectl,
            "timeout_seconds": self.timeout_seconds,
        }


def build_weight_patch(mutation: WeightMutation) -> Tuple[Dict[str, Any], ...]:
    """Build the RFC 6902 patch for one :class:`WeightMutation`.

    The document is built entirely from typed values:

    * a ``test`` on ``/metadata/resourceVersion`` — the compare-and-set that
      makes a lost race an API-server rejection instead of a stale write;
    * a ``test`` on each backend's name *and* current weight — so a patch
      built against a different route layout is rejected rather than applied
      to the wrong slot;
    * exactly two ``replace`` operations, on the weight fields only.
    """
    if not isinstance(mutation, WeightMutation):
        raise KubernetesMutationPolicyViolation(
            "a weight patch is built from a validated WeightMutation"
        )
    operations: Tuple[Dict[str, Any], ...] = (
        {"op": "test", "path": "/metadata/resourceVersion",
         "value": mutation.resource_version},
    )
    for change in mutation.changes:
        operations += (
            {"op": "test", "path": f"{BACKEND_REFS_PATH}/{change.index}/name",
             "value": change.name},
            {"op": "test", "path": f"{BACKEND_REFS_PATH}/{change.index}/weight",
             "value": change.expected_weight},
        )
    for change in mutation.changes:
        operations += (
            {"op": "replace", "path": f"{BACKEND_REFS_PATH}/{change.index}/weight",
             "value": change.new_weight},
        )
    return operations


def build_mutation_argv(
    mutation: WeightMutation,
    *,
    context: str = "",
    kubeconfig: str = "",
    request_timeout: Optional[int] = None,
    kubectl: str = "kubectl",
) -> Tuple[str, ...]:
    """Build the exact argv for the one authorized write.

    Every element is host-owned or validated here: the verb comes from
    :data:`MUTATING_VERBS`, the resource from :data:`OPERATION_RESOURCES`,
    and the payload is produced by :func:`build_weight_patch` from the typed
    mutation. There is no parameter through which a caller could supply a
    verb, a flag, a resource, a path or a payload of their choosing.
    """
    if not isinstance(mutation, WeightMutation):
        raise KubernetesMutationPolicyViolation(
            "mutation must be a validated WeightMutation"
        )
    if not isinstance(kubectl, str) or not kubectl or any(
        character.isspace() for character in kubectl
    ):
        raise KubernetesMutationPolicyViolation(f"kubectl binary {kubectl!r} is not usable")

    argv = [
        kubectl,
        "patch",
        OPERATION_RESOURCES[MutationOperation.SET_BACKEND_WEIGHTS],
    ]
    context = _checked_context(context)
    if context:
        argv += ["--context", context]
    kubeconfig = _checked_path(kubeconfig, "kubeconfig")
    if kubeconfig:
        argv += ["--kubeconfig", kubeconfig]
    argv.append(mutation.route_name)
    argv += ["-n", mutation.namespace, "--type=json", "-p",
             json.dumps(list(build_weight_patch(mutation)), separators=(",", ":"))]
    if request_timeout is not None:
        if not isinstance(request_timeout, int) or isinstance(request_timeout, bool):
            raise KubernetesMutationPolicyViolation("request_timeout must be an integer")
        if request_timeout < 1 or request_timeout > 300:
            raise KubernetesMutationPolicyViolation(
                "request_timeout must be between 1 and 300 seconds"
            )
        argv.append(f"--request-timeout={request_timeout}s")

    for element in argv:
        if element in FORBIDDEN_SUBCOMMANDS:
            raise KubernetesMutationPolicyViolation(
                f"{element!r} is a subcommand this client must never reach"
            )
    if argv[1] not in MUTATING_VERBS:
        raise KubernetesMutationPolicyViolation(
            f"verb {argv[1]!r} is not an authorized mutation verb; only "
            f"{sorted(MUTATING_VERBS)} may run"
        )
    return tuple(argv)


@dataclass(frozen=True)
class MutationAttempt:
    """The outcome of exactly one bounded write attempt.

    ``state`` is three-valued on purpose: a write whose answer was lost is
    ``unknown``, and the caller's only honest response to ``unknown`` is to
    re-observe the remote state — never to replay the write.
    """

    state: str
    detail: str = ""
    external_operation_id: Optional[str] = None
    reported_resource_version: Optional[str] = None
    reported_generation: Optional[int] = None
    duration_ms: int = 0

    def __post_init__(self) -> None:
        if self.state not in ATTEMPT_STATES:
            raise MutationWriteError(f"unknown attempt state {self.state!r}")

    @property
    def accepted(self) -> bool:
        """The API server accepted the write — not that it is verified."""
        return self.state == ATTEMPT_ACCEPTED

    @property
    def unknown(self) -> bool:
        return self.state == ATTEMPT_UNKNOWN

    @property
    def rejected(self) -> bool:
        return self.state == ATTEMPT_REJECTED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state,
            "detail": self.detail,
            "external_operation_id": self.external_operation_id,
            "reported_resource_version": self.reported_resource_version,
            "reported_generation": self.reported_generation,
            "duration_ms": self.duration_ms,
        }


#: Markers that mean the API server answered the write and refused it. This
#: is what makes ``rejected`` distinguishable from ``unknown``: an answer
#: from the server proves the write did not land, while a missing answer
#: proves nothing at all.
_SERVER_ANSWER_MARKERS = (
    "error from server",
    "the server rejected",
    "is invalid:",
    "does not match the provided",
    "test failed",
)


def classify_attempt(returncode: int, stdout: str, stderr: str) -> MutationAttempt:
    """Classify one finished process into the three-valued outcome.

    * exit 0 → the API server accepted the write (:data:`ATTEMPT_ACCEPTED`);
    * a non-zero exit where the API server *answered* → the write was
      refused and definitively did not land (:data:`ATTEMPT_REJECTED`);
    * anything else (connection failure, lost response, unparseable output)
      → :data:`ATTEMPT_UNKNOWN`, because nothing proves whether the write
      landed.
    """
    text = f"{stdout}\n{stderr}".lower()
    answered = any(marker in text for marker in _SERVER_ANSWER_MARKERS)
    reported = _reported_identity(stdout)
    if returncode == 0:
        return MutationAttempt(
            state=ATTEMPT_ACCEPTED,
            detail=redact(stderr or ""),
            external_operation_id=reported.get("resource_version"),
            reported_resource_version=reported.get("resource_version"),
            reported_generation=reported.get("generation"),
        )
    if answered:
        return MutationAttempt(
            state=ATTEMPT_REJECTED,
            detail=redact(stderr or stdout),
        )
    return MutationAttempt(
        state=ATTEMPT_UNKNOWN,
        detail=redact(stderr or stdout),
    )


def _reported_identity(stdout: str) -> Dict[str, Any]:
    """The resourceVersion/generation the API server reported back, if any.

    These are real values reported by the server; nothing here is invented,
    and a missing answer yields no fields rather than a placeholder.
    """
    try:
        document = json.loads(stdout or "")
    except (ValueError, TypeError):
        return {}
    if not isinstance(document, dict):
        return {}
    metadata = document.get("metadata") or {}
    resource_version = metadata.get("resourceVersion")
    generation = metadata.get("generation")
    result: Dict[str, Any] = {}
    if isinstance(resource_version, str) and resource_version:
        result["resource_version"] = resource_version
    if isinstance(generation, int) and not isinstance(generation, bool):
        result["generation"] = generation
    return result


class KubernetesMutationClient:
    """Concrete write client: one typed mutation, no arbitrary argv.

    ``runner`` is injectable so tests can exercise the whole client
    (validation, patch construction, classification, bounds, redaction)
    without a cluster; it is the single place a process is spawned.
    """

    def __init__(
        self,
        config: Optional[TrafficWriteConfig] = None,
        *,
        runner: Optional[Callable[..., Any]] = None,
    ) -> None:
        self._config = config or TrafficWriteConfig()
        self._runner = runner or subprocess.run
        _checked_name(self._config.namespace, "namespace")
        if self._config.namespace in RESERVED_NAMESPACES:
            raise KubernetesMutationPolicyViolation(
                f"namespace {self._config.namespace!r} is reserved"
            )
        if not isinstance(self._config.timeout_seconds, int) or isinstance(
            self._config.timeout_seconds, bool
        ) or not (1 <= self._config.timeout_seconds <= 300):
            raise KubernetesMutationPolicyViolation(
                "timeout_seconds must be an integer between 1 and 300"
            )
        self._attempts = 0

    # ------------------------------------------------------------- config

    @property
    def config(self) -> TrafficWriteConfig:
        return self._config

    @property
    def attempts(self) -> int:
        """How many bounded write attempts this client has performed."""
        return self._attempts

    # -------------------------------------------------------- write surface

    def apply_weight_mutation(self, mutation: WeightMutation) -> MutationAttempt:
        """Perform ONE bounded write attempt and classify its outcome.

        The operation is the only one that exists: setting the two
        ``backendRef`` weights of the authorized route, conditioned on the
        resourceVersion and weights the caller observed. This method never
        retries. A timeout, a killed process or an unparseable answer is
        returned as :data:`ATTEMPT_UNKNOWN` for the caller to resolve by
        re-observing the remote state.
        """
        if not isinstance(mutation, WeightMutation):
            raise KubernetesMutationPolicyViolation(
                "mutation must be a validated WeightMutation"
            )
        argv = build_mutation_argv(
            mutation,
            context=self._config.context,
            kubeconfig=self._config.kubeconfig,
            request_timeout=self._config.timeout_seconds,
            kubectl=self._config.kubectl,
        )
        timeout = self._config.timeout_seconds
        self._attempts += 1
        try:
            completed = self._runner(
                list(argv),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            # The write may or may not have landed. That is exactly the
            # unknown case, and it is never resolved by trying again here.
            return MutationAttempt(
                state=ATTEMPT_UNKNOWN,
                detail=f"the write did not answer within {timeout}s; the outcome "
                       f"is unknown",
            )
        except FileNotFoundError:
            return MutationAttempt(
                state=ATTEMPT_UNKNOWN,
                detail=f"kubectl {self._config.kubectl!r} is not available, so the "
                       f"write could not be proven to have happened",
            )
        except OSError as exc:
            return MutationAttempt(
                state=ATTEMPT_UNKNOWN,
                detail=f"the write could not be completed: {redact(exc)}",
            )

        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        if len(stdout) > MAX_OUTPUT_BYTES or len(stderr) > MAX_OUTPUT_BYTES:
            return MutationAttempt(
                state=ATTEMPT_UNKNOWN,
                detail=f"the write answered with more than {MAX_OUTPUT_BYTES} bytes",
            )
        return classify_attempt(completed.returncode, stdout, stderr)


__all__ = [
    "ATTEMPT_ACCEPTED",
    "ATTEMPT_REJECTED",
    "ATTEMPT_STATES",
    "ATTEMPT_UNKNOWN",
    "BACKEND_REFS_PATH",
    "BackendWeightChange",
    "DEFAULT_MUTATION_TIMEOUT",
    "FORBIDDEN_SUBCOMMANDS",
    "KubernetesMutationClient",
    "KubernetesMutationPolicyViolation",
    "MAX_OUTPUT_BYTES",
    "MAX_WEIGHT",
    "MUTATING_VERBS",
    "MutationAttempt",
    "MutationOperation",
    "MutationWriteError",
    "OPERATION_RESOURCES",
    "TrafficWriteConfig",
    "WeightMutation",
    "build_mutation_argv",
    "build_weight_patch",
    "classify_attempt",
]
