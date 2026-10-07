"""Phase 8.6-A corrective — the authoritative Kubernetes execution identity.

Approval must mean:

    I approve this exact artifact, against this exact execution target,
    under this exact policy.

Before this module, approval bound the artifact but not the target: the
runner sanitized whatever kubeconfig it was given without checking that
the endpoint was the one approval was granted against. A syntactically
valid kubeconfig pointing at a different cluster was accepted.

This module is the single place that derives that identity. It is
composed from values that are *all* host-owned, and it is derived twice:
once when approval is prepared, and again immediately before any
mutation. If the two disagree, execution is refused before kubectl runs.

No credential value is part of the identity -- only the non-secret
profile name, the endpoint, and a fingerprint of the CA bundle.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

IDENTITY_VERSION = "kubernetes-execution-identity-v1"


class KubernetesExecutionIdentityError(ValueError):
    """Raised when the execution target cannot be identified or has moved."""


@dataclass(frozen=True)
class KubernetesExecutionIdentity:
    """Everything an approval is bound to, besides the artifact itself."""

    namespace: str
    api_server: str
    ca_fingerprint_sha256: str
    credential_profile_id: str
    manifest_policy_identity: str
    sandbox_policy_identity: str
    network_identity: str
    #: Identity of the workload-identity policy (deployment SA, allowed
    #: workload SA, automount posture). A relaxation must not be able to
    #: inherit a stricter policy's approval.
    workload_identity_policy: str = ""

    def digest(self) -> str:
        material = "|".join([
            IDENTITY_VERSION,
            f"namespace={self.namespace}",
            f"api_server={self.api_server}",
            f"ca={self.ca_fingerprint_sha256}",
            f"credential_profile={self.credential_profile_id}",
            f"manifest_policy={self.manifest_policy_identity}",
            f"sandbox_policy={self.sandbox_policy_identity}",
            f"network={self.network_identity}",
            f"workload_identity={self.workload_identity_policy}",
        ])
        return hashlib.sha256(material.encode()).hexdigest()

    def to_dict_fields(self) -> Dict[str, str]:
        """The constructor kwargs, for building a deliberately stale copy."""
        return {
            "namespace": self.namespace,
            "api_server": self.api_server,
            "ca_fingerprint_sha256": self.ca_fingerprint_sha256,
            "credential_profile_id": self.credential_profile_id,
            "manifest_policy_identity": self.manifest_policy_identity,
            "sandbox_policy_identity": self.sandbox_policy_identity,
            "network_identity": self.network_identity,
            "workload_identity_policy": self.workload_identity_policy,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Evidence-safe view. Contains no credential material."""
        return {
            "identity_version": IDENTITY_VERSION,
            "namespace": self.namespace,
            "api_server": self.api_server,
            "ca_fingerprint_sha256": self.ca_fingerprint_sha256,
            "credential_profile_id": self.credential_profile_id,
            "manifest_policy_identity": self.manifest_policy_identity,
            "sandbox_policy_identity": self.sandbox_policy_identity,
            "network_identity": self.network_identity,
            "workload_identity_policy": self.workload_identity_policy,
            "execution_identity": self.digest(),
        }

    def differences(self, other: "KubernetesExecutionIdentity") -> Dict[str, str]:
        """Field-level diff, so a refusal can say exactly what moved."""
        changed: Dict[str, str] = {}
        for field in ("namespace", "api_server", "ca_fingerprint_sha256",
                      "credential_profile_id", "manifest_policy_identity",
                      "sandbox_policy_identity", "network_identity",
                      "workload_identity_policy"):
            mine, theirs = getattr(self, field), getattr(other, field)
            if mine != theirs:
                changed[field] = f"approved={mine!r} observed={theirs!r}"
        return changed


@dataclass(frozen=True)
class KubernetesExecutionConfig:
    """An immutable snapshot of host-owned Kubernetes execution config.

    Workstream C. Previously each value was read with ``os.getenv``
    independently, whenever the code happened to need it. That is a
    time-of-check/time-of-use gap: the namespace could be read before
    approval and the endpoint after it, with nothing guaranteeing the
    two described the same world.

    The snapshot is taken ONCE and carried for the whole run, so every
    decision in that run is made against the same configuration. It
    holds identities only -- never a token, key or kubeconfig body.
    """

    namespace: str
    kubeconfig_path: str
    credential_profile_id: str
    expected_api_server: str
    expected_ca_fingerprint: str
    sandbox_network: str
    sandbox_network_identity: str
    container_runtime: str
    #: The ONLY destinations the sandbox may reach. Host-owned, read in
    #: the same single pass as everything else so an execution cannot
    #: validate membership against a set that changed after approval.
    sandbox_peers: Tuple[str, ...] = ()
    #: Where the adapter stages manifests and credentials. When the
    #: control plane itself runs in a container this MUST be a path the
    #: daemon also sees at the same absolute location, or the sandbox's
    #: bind mounts resolve to nothing.
    staging_root: str = ""

    @classmethod
    def from_environment(cls) -> "KubernetesExecutionConfig":
        """Read every host-owned value in a single pass."""
        return cls(
            namespace=(os.getenv("DEPLOYMENT_KUBERNETES_NAMESPACE", "").strip()
                       or "devops-production-namespace"),
            kubeconfig_path=os.getenv("DEPLOYMENT_KUBECONFIG_PATH", "").strip(),
            credential_profile_id=(os.getenv("DEPLOYMENT_K8S_CREDENTIAL_PROFILE",
                                             "").strip() or "default"),
            expected_api_server=os.getenv("DEPLOYMENT_K8S_API_SERVER", "").strip(),
            expected_ca_fingerprint=os.getenv("DEPLOYMENT_K8S_CA_FINGERPRINT",
                                              "").strip().lower(),
            sandbox_network=os.getenv("DEPLOYMENT_KUBECTL_SANDBOX_NETWORK", "").strip(),
            # A bare name is not an identity: a network can be deleted
            # and rebuilt wider under the same name. This canonical
            # digest, published by whoever created the isolated network,
            # detects that.
            sandbox_network_identity=os.getenv(
                "DEPLOYMENT_K8S_SANDBOX_NETWORK_IDENTITY", "").strip(),
            container_runtime=(os.getenv("DEPLOYMENT_CONTAINER_RUNTIME", "").strip()
                               or "docker"),
            # A canonical set: sorted and de-duplicated, so a repeated
            # name cannot change the identity or the membership check.
            sandbox_peers=tuple(sorted({
                peer.strip()
                for peer in os.getenv("DEPLOYMENT_K8S_SANDBOX_PEERS", "").split(",")
                if peer.strip()
            })),
            staging_root=os.getenv("DEPLOYMENT_KUBECTL_STAGING_ROOT", "").strip(),
        )

    @property
    def network_identity(self) -> str:
        """Prefer the canonical identity; fall back to the bare name."""
        return self.sandbox_network_identity or self.sandbox_network

    def to_dict(self) -> Dict[str, str]:
        return {
            "namespace": self.namespace,
            "credential_profile_id": self.credential_profile_id,
            "expected_api_server": self.expected_api_server,
            "expected_ca_fingerprint": self.expected_ca_fingerprint,
            "sandbox_network": self.sandbox_network,
            "sandbox_network_identity": self.sandbox_network_identity,
            "container_runtime": self.container_runtime,
            "sandbox_peers": list(self.sandbox_peers),
            "staging_root": self.staging_root,
        }

    def digest(self) -> str:
        blob = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()


def expected_api_server() -> Optional[str]:
    """The host-owned API endpoint, if one is configured.

    When this is set, a kubeconfig naming any other endpoint is refused
    outright -- that is what makes the cluster part of the approval
    rather than part of the input.
    """
    value = os.getenv("DEPLOYMENT_K8S_API_SERVER", "").strip()
    return value or None


def expected_ca_fingerprint() -> Optional[str]:
    value = os.getenv("DEPLOYMENT_K8S_CA_FINGERPRINT", "").strip().lower()
    return value or None


def verify_binding(
    approved: Optional[KubernetesExecutionIdentity],
    observed: KubernetesExecutionIdentity,
) -> None:
    """Fail closed when the execution target is not the approved one.

    Called immediately before a mutation, never after one.
    """
    if approved is None:
        raise KubernetesExecutionIdentityError(
            "no approved Kubernetes execution identity is bound to this run; "
            "refusing to mutate the cluster"
        )
    if approved.digest() != observed.digest():
        changed = approved.differences(observed) or {
            "digest": f"approved={approved.digest()} observed={observed.digest()}"
        }
        detail = "; ".join(f"{k}: {v}" for k, v in sorted(changed.items()))
        raise KubernetesExecutionIdentityError(
            f"the Kubernetes execution target changed after approval ({detail}); "
            f"refusing to execute"
        )
