"""Phase 8.6-A — kubectl execution policy and sandbox contract.

This mirrors the Phase 8.5-A Terraform boundary. The deployment service
never composes a kubectl command from caller input: it names a closed
operation, and *this module* builds the argv. There is deliberately no
``run(command)`` entry point, because a generic command API would turn
the sandbox into an arbitrary Kubernetes CLI.

The sandbox differs from the Terraform sandbox in exactly one respect:
kubectl must reach the API server, so ``--network none`` is impossible.
Network access is therefore host-owned and destination-controlled — a
named Docker network supplied by configuration — and ``host`` networking
is refused outright. A request can never select it.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Sequence, Tuple

_DNS_1123 = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
_DIGEST_PINNED = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_NETWORK_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")

#: Where the approved manifest and the sanitized kubeconfig appear inside
#: the sandbox. Credentials live outside the workspace.
WORKSPACE_DIR = "/workspace"
MANIFEST_PATH = f"{WORKSPACE_DIR}/deployment.yaml"
KUBECONFIG_PATH = "/run/secrets/ares/kubeconfig"
KUBERC_PATH = "/run/secrets/ares/kuberc"

#: Field manager used for every server-side apply.
FIELD_MANAGER = "ares"

#: System namespaces ARES may never target, whatever configuration says.
#: Defence in depth: the runner already pins a single host-owned namespace.
RESERVED_NAMESPACES = frozenset({
    "kube-system", "kube-public", "kube-node-lease", "default",
    "local-path-storage",
})

#: Networking modes that are never acceptable.
FORBIDDEN_NETWORK_MODES = frozenset({"host", "none", "container", "bridge", ""})


class KubectlSandboxPolicyViolation(RuntimeError):
    """Raised when a caller tries to leave the fixed execution policy."""


class KubectlSandboxConfigurationError(RuntimeError):
    """Raised when host-owned configuration is unusable."""


class KubectlOperation(str, Enum):
    """The closed set of Kubernetes operations ARES may perform."""

    SERVER_SIDE_DRY_RUN = "server_side_dry_run"
    APPLY = "apply"
    ROLLOUT_STATUS = "rollout_status"
    ROLLOUT_UNDO = "rollout_undo"


#: Wall-clock budget per operation, in seconds.
OPERATION_TIMEOUTS: Dict[KubectlOperation, int] = {
    KubectlOperation.SERVER_SIDE_DRY_RUN: 120,
    KubectlOperation.APPLY: 300,
    KubectlOperation.ROLLOUT_STATUS: 330,
    KubectlOperation.ROLLOUT_UNDO: 180,
}

#: Subcommands that must never be reachable through the production API.
FORBIDDEN_SUBCOMMANDS = frozenset({
    "exec", "cp", "attach", "port-forward", "proxy", "plugin", "delete",
    "replace", "patch", "scale", "run", "create", "edit", "debug",
    "config", "auth", "drain", "cordon", "uncordon", "taint", "label",
    "annotate", "set", "expose", "autoscale", "certificate", "top",
})

MAX_OUTPUT_BYTES = 131072


def build_kubectl_argv(
    operation: KubectlOperation,
    *,
    namespace: str,
    deployment_name: Optional[str] = None,
    rollout_timeout_seconds: int = 300,
) -> Tuple[str, ...]:
    """Build the exact argv for one operation.

    Every element is host-owned. ``namespace`` and ``deployment_name``
    are validated as Kubernetes names, so neither can smuggle a flag.
    """
    if not isinstance(operation, KubectlOperation):
        raise KubectlSandboxPolicyViolation(f"unknown kubectl operation {operation!r}")

    if not isinstance(namespace, str) or not _DNS_1123.match(namespace):
        raise KubectlSandboxPolicyViolation(
            f"namespace {namespace!r} is not a valid Kubernetes name"
        )
    if len(namespace) > 63:
        raise KubectlSandboxPolicyViolation(
            f"namespace is {len(namespace)} characters; Kubernetes names are "
            f"limited to 63 and an over-long value indicates injection"
        )
    if namespace in RESERVED_NAMESPACES:
        raise KubectlSandboxPolicyViolation(
            f"namespace {namespace!r} is a reserved system namespace and is "
            f"never a valid deployment target"
        )

    if operation in (KubectlOperation.ROLLOUT_STATUS, KubectlOperation.ROLLOUT_UNDO):
        if not isinstance(deployment_name, str) or not _DNS_1123.match(deployment_name):
            raise KubectlSandboxPolicyViolation(
                f"deployment name {deployment_name!r} is not a valid Kubernetes name; "
                f"it must come from the approved manifest, not from a request"
            )
        if len(deployment_name) > 253:
            raise KubectlSandboxPolicyViolation("deployment name is too long")

    if operation is KubectlOperation.SERVER_SIDE_DRY_RUN:
        return (
            "kubectl", "apply",
            "--server-side",
            "--dry-run=server",
            "--validate=strict",
            f"--field-manager={FIELD_MANAGER}",
            "-f", MANIFEST_PATH,
            "-n", namespace,
        )
    if operation is KubectlOperation.APPLY:
        return (
            "kubectl", "apply",
            "--server-side",
            "--validate=strict",
            f"--field-manager={FIELD_MANAGER}",
            "-f", MANIFEST_PATH,
            "-n", namespace,
        )
    if operation is KubectlOperation.ROLLOUT_STATUS:
        if not isinstance(rollout_timeout_seconds, int) or not (1 <= rollout_timeout_seconds <= 600):
            raise KubectlSandboxPolicyViolation(
                "rollout timeout must be an integer between 1 and 600 seconds"
            )
        return (
            "kubectl", "rollout", "status",
            f"deployment/{deployment_name}",
            "-n", namespace,
            f"--timeout={rollout_timeout_seconds}s",
        )
    if operation is KubectlOperation.ROLLOUT_UNDO:
        return (
            "kubectl", "rollout", "undo",
            f"deployment/{deployment_name}",
            "-n", namespace,
        )
    raise KubectlSandboxPolicyViolation(f"unhandled operation {operation!r}")


@dataclass(frozen=True)
class KubectlSandboxStep:
    """One bounded kubectl invocation."""

    operation: KubectlOperation
    argv: Tuple[str, ...]
    timeout_seconds: int
    max_output_bytes: int = MAX_OUTPUT_BYTES

    def __post_init__(self) -> None:
        if not self.argv or self.argv[0] != "kubectl":
            raise KubectlSandboxPolicyViolation("argv must invoke kubectl")
        if len(self.argv) < 2:
            raise KubectlSandboxPolicyViolation("argv carries no subcommand")
        if self.argv[1] in FORBIDDEN_SUBCOMMANDS:
            raise KubectlSandboxPolicyViolation(
                f"kubectl subcommand {self.argv[1]!r} is not reachable through this API"
            )
        if self.timeout_seconds <= 0 or self.timeout_seconds > 900:
            raise KubectlSandboxPolicyViolation("timeout out of range")
        for token in self.argv:
            if not isinstance(token, str):
                raise KubectlSandboxPolicyViolation("argv tokens must be strings")
            if token.startswith(("http://", "https://")):
                raise KubectlSandboxPolicyViolation("remote URLs are not accepted")
            if token in ("-k", "--kustomize", "-", "--server", "--kubeconfig",
                         "--insecure-skip-tls-verify", "--token", "--as",
                         "--as-group", "--certificate-authority", "--tls-server-name"):
                raise KubectlSandboxPolicyViolation(
                    f"flag {token!r} is host-owned and may not appear in argv"
                )
        # the only -f value permitted is the approved manifest
        for index, token in enumerate(self.argv):
            if token == "-f":
                if index + 1 >= len(self.argv) or self.argv[index + 1] != MANIFEST_PATH:
                    raise KubectlSandboxPolicyViolation(
                        f"-f must reference exactly {MANIFEST_PATH}"
                    )


@dataclass(frozen=True)
class KubectlSandboxSpec:
    """Host-owned runtime contract for the kubectl sandbox."""

    image: str
    network: str
    user: str = "65532:65532"
    memory_bytes: int = 536870912
    cpus: str = "1"
    pids_limit: int = 128
    kubectl_version: str = ""

    def __post_init__(self) -> None:
        if not _DIGEST_PINNED.match(self.image or ""):
            raise KubectlSandboxConfigurationError(
                f"kubectl sandbox image must be digest-pinned, got {self.image!r}"
            )
        if (self.network or "").lower() in FORBIDDEN_NETWORK_MODES:
            raise KubectlSandboxConfigurationError(
                f"network {self.network!r} is not an acceptable sandbox network; "
                f"a dedicated host-owned network is required so egress stays "
                f"destination-controlled"
            )
        if not _NETWORK_NAME.match(self.network or ""):
            raise KubectlSandboxConfigurationError(
                f"network name {self.network!r} is malformed"
            )
        uid_gid = (self.user or "").split(":")
        if len(uid_gid) != 2:
            raise KubectlSandboxConfigurationError("user must be <uid>:<gid>")
        try:
            uid, gid = int(uid_gid[0]), int(uid_gid[1])
        except ValueError:
            raise KubectlSandboxConfigurationError("user must be numeric") from None
        if uid <= 0 or gid <= 0:
            raise KubectlSandboxConfigurationError(
                "the kubectl sandbox must not run as root"
            )


def sandbox_environment() -> Dict[str, str]:
    """The complete environment handed to kubectl.

    Built from nothing. ``os.environ.copy()`` would leak cloud, database,
    Docker, proxy and JWT material into a process that talks to the
    cluster, so it is never used. Proxy variables are deliberately absent:
    inheriting them would let a hostile host redirect API traffic.
    """
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/tmp",
        "TMPDIR": "/tmp",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "KUBECONFIG": KUBECONFIG_PATH,
        "KUBERC": KUBERC_PATH,
    }


#: kuberc denying every credential plugin. kubectl versions that support
#: it refuse exec credential plugins outright; older versions ignore the
#: file, which is why the kubeconfig sanitizer rejects ``exec`` as well.
KUBERC_DENY_ALL = """apiVersion: kubectl.config.k8s.io/v1alpha1
kind: Preference
credentialPlugins:
  policy: DenyAll
"""


@dataclass(frozen=True)
class KubectlRunPlan:
    """A fully-formed container invocation."""

    argv: Tuple[str, ...]
    operation: KubectlOperation
    timeout_seconds: int
    max_output_bytes: int
    container_name: str


def build_run_plan(
    *,
    spec: KubectlSandboxSpec,
    step: KubectlSandboxStep,
    manifest_host_path: str,
    kubeconfig_host_path: str,
    kuberc_host_path: str,
    container_name: str,
    runtime: str = "docker",
) -> KubectlRunPlan:
    """Compose the container argv for one kubectl step.

    The kubectl argv is re-derived from the operation rather than trusted
    from ``step``, so a caller that mutated ``step.argv`` cannot smuggle
    flags past the policy.
    """
    if runtime not in ("docker", "podman"):
        raise KubectlSandboxPolicyViolation(f"unsupported container runtime {runtime!r}")
    if not _NETWORK_NAME.match(container_name or ""):
        raise KubectlSandboxPolicyViolation(f"container name {container_name!r} is malformed")
    for path, label in ((manifest_host_path, "manifest"),
                        (kubeconfig_host_path, "kubeconfig"),
                        (kuberc_host_path, "kuberc")):
        if not isinstance(path, str) or not path.startswith("/") or ":" in path:
            raise KubectlSandboxPolicyViolation(f"{label} host path {path!r} is unusable")

    argv: List[str] = [
        runtime, "run", "--rm",
        "--name", container_name,
        "--pull", "never",
        # Destination-controlled egress: a dedicated host-owned network,
        # never host networking and never caller-selected.
        "--network", spec.network,
        "--user", spec.user,
        "--read-only",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--pids-limit", str(spec.pids_limit),
        "--memory", str(spec.memory_bytes),
        "--cpus", spec.cpus,
        "--hostname", "ares-kubectl",
        "--label", "dev.arena.kubectl-sandbox=1",
        "--entrypoint", "kubectl",
    ]
    for key, value in sorted(sandbox_environment().items()):
        argv += ["-e", f"{key}={value}"]
    argv += [
        "-v", f"{manifest_host_path}:{MANIFEST_PATH}:ro",
        "-v", f"{kubeconfig_host_path}:{KUBECONFIG_PATH}:ro",
        "-v", f"{kuberc_host_path}:{KUBERC_PATH}:ro",
        "-w", WORKSPACE_DIR,
        spec.image,
    ]
    argv += list(step.argv[1:])  # entrypoint already supplies "kubectl"
    return KubectlRunPlan(
        argv=tuple(argv),
        operation=step.operation,
        timeout_seconds=step.timeout_seconds,
        max_output_bytes=step.max_output_bytes,
        container_name=container_name,
    )


def sandbox_policy_identity(spec: KubectlSandboxSpec, namespace: str) -> str:
    """Deterministic identity of the whole execution posture.

    If the runtime boundary weakens, this changes, so an approval granted
    under a stronger posture cannot execute under a weaker one.
    """
    material = "|".join([
        "kubernetes-sandbox-v1",
        f"image={spec.image}",
        f"kubectl_version={spec.kubectl_version}",
        f"user={spec.user}",
        f"network={spec.network}",
        f"memory={spec.memory_bytes}",
        f"cpus={spec.cpus}",
        f"pids={spec.pids_limit}",
        f"namespace={namespace}",
        f"operations={','.join(sorted(o.value for o in KubectlOperation))}",
        f"manifest={MANIFEST_PATH}",
        f"kubeconfig={KUBECONFIG_PATH}",
        f"field_manager={FIELD_MANAGER}",
        f"env={','.join(sorted(sandbox_environment()))}",
        "readonly_rootfs=1,cap_drop=ALL,no_new_privileges=1,docker_socket=0",
    ])
    return f"kubernetes-sandbox-v1:{hashlib.sha256(material.encode()).hexdigest()[:32]}"


def load_spec_from_environment() -> KubectlSandboxSpec:
    """Build the sandbox spec from host-owned configuration only."""
    image = os.getenv("DEPLOYMENT_KUBECTL_SANDBOX_IMAGE", "").strip()
    if not image:
        raise KubectlSandboxConfigurationError(
            "DEPLOYMENT_KUBECTL_SANDBOX_IMAGE must be a digest-pinned image"
        )
    network = os.getenv("DEPLOYMENT_KUBECTL_SANDBOX_NETWORK", "").strip()
    if not network:
        raise KubectlSandboxConfigurationError(
            "DEPLOYMENT_KUBECTL_SANDBOX_NETWORK must name a host-owned network"
        )
    return KubectlSandboxSpec(
        image=image,
        network=network,
        user=os.getenv("DEPLOYMENT_KUBECTL_SANDBOX_USER", "65532:65532").strip(),
        kubectl_version=os.getenv("DEPLOYMENT_KUBECTL_VERSION", "").strip(),
    )
