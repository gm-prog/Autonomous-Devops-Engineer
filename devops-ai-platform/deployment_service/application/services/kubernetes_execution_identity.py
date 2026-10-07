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
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

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
        ])
        return hashlib.sha256(material.encode()).hexdigest()

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
            "execution_identity": self.digest(),
        }

    def differences(self, other: "KubernetesExecutionIdentity") -> Dict[str, str]:
        """Field-level diff, so a refusal can say exactly what moved."""
        changed: Dict[str, str] = {}
        for field in ("namespace", "api_server", "ca_fingerprint_sha256",
                      "credential_profile_id", "manifest_policy_identity",
                      "sandbox_policy_identity", "network_identity"):
            mine, theirs = getattr(self, field), getattr(other, field)
            if mine != theirs:
                changed[field] = f"approved={mine!r} observed={theirs!r}"
        return changed


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
