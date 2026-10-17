"""Phase 8.6-A — kubeconfig trust boundary.

A kubeconfig is not inert data. Kubernetes credential ``exec`` plugins
run an external binary chosen by the file, so a kubeconfig is a
code-execution surface. ``proxy-url`` can silently redirect API traffic,
and ``insecure-skip-tls-verify`` removes server authentication.

This module therefore never forwards an operator file into the sandbox.
It parses the supplied kubeconfig, rejects every dangerous construct and
**rebuilds** a minimal one containing exactly one cluster, one user, one
context and one namespace, with inline credentials only. Anything it does
not understand is refused rather than passed through.

It also derives a non-secret *cluster identity* — the normalised API
endpoint plus a SHA-256 fingerprint of the CA bundle — so an approval can
be bound to the cluster it was granted against. No credential value is
returned, logged or hashed into any identity.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import yaml

#: Keys that may never appear on a user entry: each is an execution,
#: redirection or weak-authentication surface.
FORBIDDEN_USER_KEYS: Tuple[str, ...] = (
    "exec",            # arbitrary external binary execution
    "auth-provider",   # legacy plugin execution surface
    "username",        # basic auth
    "password",
    "act-as",          # impersonation
    "act-as-groups",
    "act-as-uid",
    "as",
    "as-groups",
    "as-uid",
)

#: Keys that may never appear on a cluster entry.
FORBIDDEN_CLUSTER_KEYS: Tuple[str, ...] = (
    "insecure-skip-tls-verify",
    "proxy-url",
    "tls-server-name",
    "disable-compression",
)

#: Credential forms the sandbox accepts, all inline.
ALLOWED_USER_CREDENTIALS: Tuple[str, ...] = (
    "token",
    "client-certificate-data",
    "client-key-data",
)

_PEM_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----")


class KubeconfigPolicyError(ValueError):
    """Raised when a kubeconfig violates the trust boundary."""


@dataclass(frozen=True)
class ClusterIdentity:
    """Non-secret identity of the Kubernetes control plane."""

    server: str
    ca_fingerprint_sha256: str
    namespace: str

    def identity(self) -> str:
        material = f"{self.server}|{self.ca_fingerprint_sha256}|{self.namespace}"
        return hashlib.sha256(material.encode()).hexdigest()

    def to_dict(self) -> Dict[str, str]:
        return {
            "server": self.server,
            "ca_fingerprint_sha256": self.ca_fingerprint_sha256,
            "namespace": self.namespace,
            "cluster_identity": self.identity(),
        }


@dataclass(frozen=True)
class SanitizedKubeconfig:
    """A rebuilt, minimal kubeconfig plus its non-secret identity."""

    content: str
    cluster_identity: ClusterIdentity
    credential_profile_id: str
    credential_kind: str
    warnings: List[str] = field(default_factory=list)

    def to_evidence(self) -> Dict[str, Any]:
        """Evidence-safe view. Never includes the credential itself."""
        return {
            "credential_profile_id": self.credential_profile_id,
            "credential_kind": self.credential_kind,
            **self.cluster_identity.to_dict(),
        }


def _normalise_server(server: Any) -> str:
    if not isinstance(server, str) or not server.strip():
        raise KubeconfigPolicyError("cluster.server is missing")
    server = server.strip()
    parsed = urlparse(server)
    if parsed.scheme != "https":
        raise KubeconfigPolicyError(
            f"cluster.server must use https, got {parsed.scheme or 'no scheme'!r}"
        )
    if not parsed.hostname:
        raise KubeconfigPolicyError("cluster.server has no host")
    if parsed.path not in ("", "/"):
        raise KubeconfigPolicyError("cluster.server must not carry a path")
    if parsed.username or parsed.password:
        raise KubeconfigPolicyError("cluster.server must not embed credentials")
    port = parsed.port or 443
    return f"https://{parsed.hostname.lower()}:{port}"


def _ca_fingerprint(cluster: Dict[str, Any]) -> Tuple[str, str]:
    """Return (inline base64 CA, sha256 fingerprint of the raw bytes)."""
    if cluster.get("certificate-authority"):
        raise KubeconfigPolicyError(
            "cluster.certificate-authority references an external file path; "
            "only inline certificate-authority-data is accepted"
        )
    data = cluster.get("certificate-authority-data")
    if not data:
        raise KubeconfigPolicyError(
            "cluster.certificate-authority-data is required; the sandbox will not "
            "trust an unauthenticated API server"
        )
    if not isinstance(data, str):
        raise KubeconfigPolicyError("cluster.certificate-authority-data must be a string")
    try:
        raw = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise KubeconfigPolicyError(
            f"cluster.certificate-authority-data is not valid base64: {exc}"
        ) from None
    if not _PEM_CERT.search(raw):
        raise KubeconfigPolicyError(
            "cluster.certificate-authority-data does not contain a PEM certificate"
        )
    return data, hashlib.sha256(raw).hexdigest()


def _select(entries: Any, name: str, label: str) -> Dict[str, Any]:
    if not isinstance(entries, list):
        raise KubeconfigPolicyError(f"kubeconfig has no {label} list")
    matches = [e for e in entries
               if isinstance(e, dict) and e.get("name") == name]
    if not matches:
        raise KubeconfigPolicyError(f"kubeconfig has no {label} named {name!r}")
    if len(matches) > 1:
        raise KubeconfigPolicyError(f"kubeconfig has duplicate {label} named {name!r}")
    body = matches[0].get(label[:-1] if label.endswith("s") else label)
    if body is None:
        body = matches[0].get("cluster") or matches[0].get("user") or matches[0].get("context")
    if not isinstance(body, dict):
        raise KubeconfigPolicyError(f"{label} {name!r} has no body")
    return body


def sanitize_kubeconfig(
    raw_kubeconfig: str,
    expected_namespace: str,
    credential_profile_id: str = "ares-k8s-deployer-v1",
    expected_server: Optional[str] = None,
) -> SanitizedKubeconfig:
    """Validate an operator kubeconfig and rebuild a minimal, safe one.

    Raises :class:`KubeconfigPolicyError` on anything that could execute
    code, redirect traffic or weaken server authentication.
    """
    if not raw_kubeconfig or not raw_kubeconfig.strip():
        raise KubeconfigPolicyError("kubeconfig is empty")

    try:
        doc = yaml.safe_load(raw_kubeconfig)
    except yaml.YAMLError as exc:
        raise KubeconfigPolicyError(f"kubeconfig is not valid YAML: {exc}") from None
    if not isinstance(doc, dict):
        raise KubeconfigPolicyError("kubeconfig is not a mapping")

    if doc.get("kind") not in (None, "Config"):
        raise KubeconfigPolicyError(f"unexpected kubeconfig kind {doc.get('kind')!r}")

    # Reject global preferences that could carry plugin configuration.
    preferences = doc.get("preferences") or {}
    if isinstance(preferences, dict) and preferences:
        raise KubeconfigPolicyError(
            "kubeconfig declares preferences; the sandbox accepts no client preferences"
        )

    context_name = doc.get("current-context")
    if not isinstance(context_name, str) or not context_name.strip():
        raise KubeconfigPolicyError("kubeconfig has no current-context")
    context = _select(doc.get("contexts"), context_name.strip(), "contexts")

    cluster_name = context.get("cluster")
    user_name = context.get("user")
    if not isinstance(cluster_name, str) or not cluster_name:
        raise KubeconfigPolicyError("current context selects no cluster")
    if not isinstance(user_name, str) or not user_name:
        raise KubeconfigPolicyError("current context selects no user")

    cluster = _select(doc.get("clusters"), cluster_name, "clusters")
    user = _select(doc.get("users"), user_name, "users")

    # --- cluster -------------------------------------------------------
    for key in FORBIDDEN_CLUSTER_KEYS:
        if key in cluster:
            raise KubeconfigPolicyError(
                f"cluster entry sets {key!r}, which the sandbox never accepts"
            )
    server = _normalise_server(cluster.get("server"))
    if expected_server is not None and server != _normalise_server(expected_server):
        raise KubeconfigPolicyError(
            f"cluster.server {server!r} does not match the host-owned endpoint"
        )
    ca_data, ca_fingerprint = _ca_fingerprint(cluster)

    # --- user ----------------------------------------------------------
    for key in FORBIDDEN_USER_KEYS:
        if key in user:
            raise KubeconfigPolicyError(
                f"user entry sets {key!r}, which the sandbox never accepts "
                f"(credential plugins and impersonation are denied)"
            )
    for key in ("client-certificate", "client-key", "tokenFile"):
        if user.get(key):
            raise KubeconfigPolicyError(
                f"user entry sets {key!r}, which references an external path; "
                f"only inline credentials are accepted"
            )

    present = [k for k in ALLOWED_USER_CREDENTIALS if user.get(k)]
    unknown = [k for k in user.keys() if k not in ALLOWED_USER_CREDENTIALS]
    if unknown:
        raise KubeconfigPolicyError(
            f"user entry carries unsupported keys {sorted(unknown)!r}; the sandbox "
            f"accepts only {list(ALLOWED_USER_CREDENTIALS)}"
        )
    if not present:
        raise KubeconfigPolicyError("user entry carries no supported credential")

    if "token" in present:
        if len(present) > 1:
            raise KubeconfigPolicyError("user entry mixes token and certificate credentials")
        credential_kind = "token"
        safe_user: Dict[str, Any] = {"token": user["token"]}
    else:
        if set(present) != {"client-certificate-data", "client-key-data"}:
            raise KubeconfigPolicyError(
                "client certificate authentication requires both "
                "client-certificate-data and client-key-data"
            )
        credential_kind = "client-certificate"
        safe_user = {
            "client-certificate-data": user["client-certificate-data"],
            "client-key-data": user["client-key-data"],
        }

    # --- namespace -------------------------------------------------------
    declared_ns = context.get("namespace")
    if declared_ns is not None and str(declared_ns).strip() != expected_namespace:
        raise KubeconfigPolicyError(
            f"kubeconfig context namespace {declared_ns!r} does not match the "
            f"host-owned execution namespace {expected_namespace!r}"
        )

    rebuilt = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{
            "name": "ares-cluster",
            "cluster": {"server": server, "certificate-authority-data": ca_data},
        }],
        "users": [{"name": "ares-deployer", "user": safe_user}],
        "contexts": [{
            "name": "ares",
            "context": {
                "cluster": "ares-cluster",
                "user": "ares-deployer",
                "namespace": expected_namespace,
            },
        }],
        "current-context": "ares",
    }

    return SanitizedKubeconfig(
        content=yaml.safe_dump(rebuilt, sort_keys=True, default_flow_style=False),
        cluster_identity=ClusterIdentity(
            server=server,
            ca_fingerprint_sha256=ca_fingerprint,
            namespace=expected_namespace,
        ),
        credential_profile_id=credential_profile_id,
        credential_kind=credential_kind,
    )
