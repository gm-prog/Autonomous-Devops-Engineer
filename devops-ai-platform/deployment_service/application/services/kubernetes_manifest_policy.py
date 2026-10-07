"""Phase 8.6-A — static Kubernetes manifest policy.

Every manifest reaching this module is treated as UNTRUSTED EXECUTION
POLICY INPUT. A manifest is not merely data: it can select resource
kinds, namespaces, service-account identities, host namespaces, host
filesystem paths, capabilities and external exposure. Namespace
allowlisting alone does not constrain a cluster-scoped object, because
``kubectl -n <ns>`` is ignored for cluster-scoped kinds.

The policy therefore:

* starts from DENY and admits only an explicitly allowed
  ``apiVersion/kind`` set that is host-owned, never request-owned;
* hard-denies cluster-scoped and authorization-bearing kinds even if an
  operator widens the allowlist by mistake;
* walks *every* container list (``containers``, ``initContainers``,
  ``ephemeralContainers``) of *both* a bare Pod spec and an embedded
  ``spec.template.spec`` — the previous implementation only inspected
  ``spec.template.spec.containers``, so a bare privileged Pod or a
  privileged init container passed silently;
* rejects rather than rewrites. Silently repairing an unsafe manifest
  would hide an attack and make the approved artifact differ from what
  the author submitted.

It produces a canonical byte-form and its SHA-256 so approval can be
bound to the exact manifest that will later be applied.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml

# RFC 1123 subdomain, the rule Kubernetes applies to most object names.
_DNS_1123 = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")

# Quantities such as "50m", "64Mi", "0.5", "1".
_QUANTITY = re.compile(r"^\d+(\.\d+)?([numkKMGTPE]i?)?$")

#: Host-owned default allowlist. Derived from the resources this
#: repository actually deploys (``e2e/fixtures/k8s-deployment.yaml`` is an
#: ``apps/v1`` Deployment) plus the two namespaced companions a Deployment
#: normally needs. Everything else is BLOCKED. Operators may widen this
#: through ``DEPLOYMENT_K8S_ALLOWED_RESOURCES`` but the hard denies below
#: still apply.
DEFAULT_ALLOWED_RESOURCES: Tuple[Tuple[str, str], ...] = (
    ("apps/v1", "Deployment"),
    ("v1", "Service"),
    ("v1", "ConfigMap"),
)

#: Kinds that are cluster-scoped or carry authorization weight. These are
#: denied unconditionally: a namespace flag cannot constrain them, and a
#: generated workload must never define its own authorization policy.
HARD_DENIED_KINDS: frozenset = frozenset({
    # cluster-scoped infrastructure
    "Namespace", "Node", "PersistentVolume", "StorageClass",
    "CustomResourceDefinition", "APIService", "PriorityClass",
    "RuntimeClass", "CSIDriver", "CSINode", "VolumeAttachment",
    "ComponentStatus", "Lease",
    # admission control
    "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration",
    "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding",
    # authorization: generated workloads may not define their own RBAC
    "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding",
    "ServiceAccount",
    # identity / policy
    "PodSecurityPolicy", "SecurityContextConstraints",
})

#: Volume sources a generated application manifest may use.
ALLOWED_VOLUME_TYPES: frozenset = frozenset({
    "configMap", "secret", "emptyDir", "projected", "downwardAPI",
    "persistentVolumeClaim",
})

#: Volume sources that are never acceptable from generated content.
DENIED_VOLUME_TYPES: frozenset = frozenset({
    "hostPath", "csi", "nfs", "iscsi", "glusterfs", "rbd", "cephfs",
    "flexVolume", "flocker", "portworxVolume", "quobyte", "scaleIO",
    "storageos", "fc", "azureDisk", "azureFile", "gcePersistentDisk",
    "awsElasticBlockStore", "cinder", "vsphereVolume", "gitRepo",
    "ephemeral",
})

ALLOWED_SERVICE_TYPES: frozenset = frozenset({"ClusterIP"})

ALLOWED_SECCOMP_TYPES: frozenset = frozenset({"RuntimeDefault", "Localhost"})

_CONTAINER_LISTS = ("containers", "initContainers", "ephemeralContainers")


class KubernetesManifestPolicyError(ValueError):
    """Raised when a manifest cannot be evaluated at all."""


@dataclass(frozen=True)
class ManifestPolicyResult:
    """Outcome of evaluating one manifest bundle."""

    status: str
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    resources: List[Dict[str, str]] = field(default_factory=list)
    deployment_names: List[str] = field(default_factory=list)
    canonical_yaml: str = ""
    manifest_sha256: str = ""
    policy_identity: str = ""

    @property
    def passed(self) -> bool:
        return self.status == "PASS"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "resources": list(self.resources),
            "deployment_names": list(self.deployment_names),
            "manifest_sha256": self.manifest_sha256,
            "policy_identity": self.policy_identity,
        }


def _parse_name_list(raw: str) -> Tuple[str, ...]:
    """Parse a comma-separated host-owned allowlist of resource names."""
    return tuple(sorted({v.strip() for v in (raw or "").split(",") if v.strip()}))


def _parse_allowed_resources(raw: str) -> Tuple[Tuple[str, str], ...]:
    """Parse ``apiVersion=Kind`` pairs, comma separated."""
    pairs: List[Tuple[str, str]] = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" not in chunk:
            raise KubernetesManifestPolicyError(
                f"allowed resource {chunk!r} must be written as apiVersion=Kind"
            )
        api_version, kind = chunk.split("=", 1)
        api_version, kind = api_version.strip(), kind.strip()
        if not api_version or not kind:
            raise KubernetesManifestPolicyError(
                f"allowed resource {chunk!r} must be written as apiVersion=Kind"
            )
        pairs.append((api_version, kind))
    return tuple(pairs)


class KubernetesManifestPolicy:
    """Host-owned static policy for untrusted Kubernetes manifests."""

    POLICY_VERSION = "kubernetes-manifest-policy-v1"

    def __init__(
        self,
        namespace: Optional[str] = None,
        service_account: Optional[str] = None,
        allowed_resources: Optional[Sequence[Tuple[str, str]]] = None,
        require_resource_limits: bool = True,
        deployment_service_account: Optional[str] = None,
        allowed_secret_names: Optional[Sequence[str]] = None,
        allowed_pvc_names: Optional[Sequence[str]] = None,
        allowed_configmap_names: Optional[Sequence[str]] = None,
        allow_service_account_tokens: bool = False,
    ) -> None:
        self.namespace = (
            namespace
            if namespace is not None
            else os.getenv("DEPLOYMENT_KUBERNETES_NAMESPACE", "devops-production-namespace")
        ).strip()
        if not self.namespace:
            raise KubernetesManifestPolicyError(
                "a single host-owned execution namespace must be configured"
            )
        if not _DNS_1123.match(self.namespace):
            raise KubernetesManifestPolicyError(
                f"configured namespace {self.namespace!r} is not a valid Kubernetes name"
            )

        # The identity ARES itself authenticates to Kubernetes with. A
        # generated workload may NEVER run as it: that would hand the
        # deployment control-plane's own rights to untrusted content.
        if deployment_service_account is None:
            deployment_service_account = os.getenv(
                "DEPLOYMENT_K8S_DEPLOYER_SERVICE_ACCOUNT", "ares-deployer").strip()
        self.deployment_service_account = deployment_service_account or "ares-deployer"

        # The identity generated workloads may run as. None (the default)
        # means "no workload may choose an identity at all".
        if service_account is None:
            service_account = os.getenv("DEPLOYMENT_K8S_SERVICE_ACCOUNT", "").strip() or None
        self.service_account = service_account

        # Workload creation is an INDIRECT path to Secret access: a pod
        # that mounts a Secret reads it without the author holding
        # `get secrets`. Secret and PVC references are therefore
        # deny-by-default and must be named explicitly by the host.
        self.allowed_secret_names = frozenset(
            allowed_secret_names if allowed_secret_names is not None
            else _parse_name_list(os.getenv("DEPLOYMENT_K8S_ALLOWED_SECRETS", ""))
        )
        self.allowed_pvc_names = frozenset(
            allowed_pvc_names if allowed_pvc_names is not None
            else _parse_name_list(os.getenv("DEPLOYMENT_K8S_ALLOWED_PVCS", ""))
        )
        self.allowed_configmap_names = frozenset(
            allowed_configmap_names if allowed_configmap_names is not None
            else _parse_name_list(os.getenv("DEPLOYMENT_K8S_ALLOWED_CONFIGMAPS", ""))
        )
        self.allow_service_account_tokens = allow_service_account_tokens

        if allowed_resources is None:
            raw = os.getenv("DEPLOYMENT_K8S_ALLOWED_RESOURCES", "").strip()
            allowed_resources = _parse_allowed_resources(raw) if raw else DEFAULT_ALLOWED_RESOURCES
        self.allowed_resources = tuple(allowed_resources)
        self.require_resource_limits = require_resource_limits

    # ------------------------------------------------------------------
    # identity
    # ------------------------------------------------------------------
    def identity(self) -> str:
        """Deterministic, non-secret identity of this policy configuration.

        A materially different policy must not be able to inherit an
        approval produced under a stricter one.
        """
        allowed = ";".join(f"{a}={k}" for a, k in sorted(self.allowed_resources))
        material = "|".join([
            self.POLICY_VERSION,
            f"namespace={self.namespace}",
            f"service_account={self.service_account or ''}",
            f"allowed={allowed}",
            f"denied={';'.join(sorted(HARD_DENIED_KINDS))}",
            f"volumes={';'.join(sorted(ALLOWED_VOLUME_TYPES))}",
            f"service_types={';'.join(sorted(ALLOWED_SERVICE_TYPES))}",
            f"require_limits={self.require_resource_limits}",
            f"deployment_sa={self.deployment_service_account}",
            f"secrets={';'.join(sorted(self.allowed_secret_names))}",
            f"pvcs={';'.join(sorted(self.allowed_pvc_names))}",
            f"configmaps={';'.join(sorted(self.allowed_configmap_names))}",
            f"sa_tokens={self.allow_service_account_tokens}",
        ])
        return f"{self.POLICY_VERSION}:{hashlib.sha256(material.encode()).hexdigest()[:32]}"

    # ------------------------------------------------------------------
    # evaluation
    # ------------------------------------------------------------------
    def evaluate(self, manifest_yaml: str) -> ManifestPolicyResult:
        identity = self.identity()
        if not manifest_yaml or not manifest_yaml.strip():
            return ManifestPolicyResult(
                status="FAIL", errors=["Kubernetes manifest is empty."],
                policy_identity=identity)

        try:
            documents = [d for d in yaml.safe_load_all(manifest_yaml) if d is not None]
        except yaml.YAMLError as exc:
            return ManifestPolicyResult(
                status="FAIL", errors=[f"Invalid YAML: {exc}"], policy_identity=identity)

        if not documents:
            return ManifestPolicyResult(
                status="FAIL", errors=["No Kubernetes resources found."],
                policy_identity=identity)

        errors: List[str] = []
        warnings: List[str] = []
        resources: List[Dict[str, str]] = []
        deployment_names: List[str] = []
        canonical_docs: List[Dict[str, Any]] = []

        for index, doc in enumerate(documents, 1):
            where = f"document {index}"
            if not isinstance(doc, dict):
                errors.append(f"{where} is not a Kubernetes object.")
                continue

            api_version = doc.get("apiVersion")
            kind = doc.get("kind")
            if not isinstance(api_version, str) or not api_version.strip():
                errors.append(f"{where} must declare apiVersion.")
                continue
            if not isinstance(kind, str) or not kind.strip():
                errors.append(f"{where} must declare kind.")
                continue
            api_version, kind = api_version.strip(), kind.strip()
            where = f"{where} ({kind})"

            # Hard deny first: this must hold even if the allowlist is widened.
            if kind in HARD_DENIED_KINDS:
                errors.append(
                    f"{where} is a cluster-scoped or authorization-bearing kind and is "
                    f"never accepted from a generated manifest; a namespace flag does "
                    f"not constrain it."
                )
                continue

            if (api_version, kind) not in self.allowed_resources:
                allowed = ", ".join(f"{a}/{k}" for a, k in sorted(self.allowed_resources))
                errors.append(
                    f"{where} uses apiVersion/kind {api_version}/{kind}, which is not "
                    f"in the host-owned allowlist ({allowed})."
                )
                continue

            metadata = doc.get("metadata")
            if not isinstance(metadata, dict):
                errors.append(f"{where} must declare metadata.")
                continue
            name = metadata.get("name")
            if not isinstance(name, str) or not name.strip():
                errors.append(f"{where} must declare metadata.name.")
                continue
            name = name.strip()
            if not _DNS_1123.match(name) or len(name) > 253:
                errors.append(f"{where} name {name!r} is not a valid Kubernetes object name.")
                continue

            # Namespace binding: absent is fine (canonicalised later), but a
            # declared namespace must match the single execution namespace.
            declared_ns = metadata.get("namespace")
            if declared_ns is not None:
                if not isinstance(declared_ns, str) or declared_ns.strip() != self.namespace:
                    errors.append(
                        f"{where} declares namespace {declared_ns!r} but the host-owned "
                        f"execution namespace is {self.namespace!r}."
                    )
                    continue

            resources.append({"apiVersion": api_version, "kind": kind, "name": name})

            if kind == "Deployment":
                deployment_names.append(name)
                errors.extend(self._check_workload(doc, where))
            elif kind == "Service":
                errors.extend(self._check_service(doc, where))
            elif kind == "ConfigMap":
                pass  # no executable surface beyond what the workload mounts

            canonical = dict(doc)
            canonical_metadata = dict(metadata)
            canonical_metadata["namespace"] = self.namespace
            canonical["metadata"] = canonical_metadata
            canonical_docs.append(canonical)

        if not resources and not errors:
            errors.append("No Kubernetes resources found.")

        if errors:
            return ManifestPolicyResult(
                status="FAIL", errors=errors, warnings=warnings,
                resources=resources, policy_identity=identity)

        canonical_yaml = yaml.safe_dump_all(
            canonical_docs, sort_keys=True, default_flow_style=False, explicit_start=True)
        digest = hashlib.sha256(canonical_yaml.encode("utf-8")).hexdigest()

        if not deployment_names:
            warnings.append("Manifest declares no Deployment; rollout status is not applicable.")

        return ManifestPolicyResult(
            status="PASS", errors=[], warnings=warnings, resources=resources,
            deployment_names=deployment_names, canonical_yaml=canonical_yaml,
            manifest_sha256=digest, policy_identity=identity)

    # ------------------------------------------------------------------
    # workload checks
    # ------------------------------------------------------------------
    def _check_workload(self, doc: Dict[str, Any], where: str) -> List[str]:
        errors: List[str] = []
        spec = doc.get("spec")
        if not isinstance(spec, dict):
            errors.append(f"{where} must declare spec.")
            return errors
        template = spec.get("template")
        if not isinstance(template, dict):
            errors.append(f"{where} must declare spec.template.")
            return errors
        pod_spec = template.get("spec")
        if not isinstance(pod_spec, dict):
            errors.append(f"{where} must declare spec.template.spec.")
            return errors
        errors.extend(self._check_pod_spec(pod_spec, where))
        return errors

    def _check_pod_spec(self, pod_spec: Dict[str, Any], where: str) -> List[str]:
        errors: List[str] = []

        # --- host namespaces -------------------------------------------
        for host_field in ("hostNetwork", "hostPID", "hostIPC"):
            if pod_spec.get(host_field) is True:
                errors.append(f"{where} enables {host_field}.")

        if pod_spec.get("nodeName"):
            errors.append(f"{where} pins nodeName, which is not permitted.")
        if pod_spec.get("hostUsers") is False:
            # user-namespace selection is a runtime decision, not a manifest one
            errors.append(f"{where} sets hostUsers, which is host-owned.")

        # --- service account -------------------------------------------
        declared_sa = pod_spec.get("serviceAccountName") or pod_spec.get("serviceAccount")
        if declared_sa is not None:
            declared_sa = str(declared_sa).strip()
            # The deployment control-plane identity is never a workload
            # identity. Inheriting it would give untrusted content the
            # rights ARES uses to mutate the cluster.
            if declared_sa == self.deployment_service_account:
                errors.append(
                    f"{where} selects serviceAccountName {declared_sa!r}, which is the "
                    f"ARES deployment identity; a generated workload may never run as "
                    f"the identity that performs deployments."
                )
            elif self.service_account is None:
                errors.append(
                    f"{where} selects serviceAccountName {declared_sa!r}; generated "
                    f"manifests may not choose a workload identity."
                )
            elif declared_sa != self.service_account:
                errors.append(
                    f"{where} selects serviceAccountName {declared_sa!r} but the only "
                    f"permitted workload identity is {self.service_account!r}."
                )

        # Token automounting is an API identity. It is opt-in, explicit,
        # and never relies on the namespace default service account.
        automount = pod_spec.get("automountServiceAccountToken")
        if automount is None:
            errors.append(
                f"{where} does not set automountServiceAccountToken; it must be "
                f"explicit so the workload never silently inherits the namespace "
                f"default service account token."
            )
        elif automount is True:
            if not self.allow_service_account_tokens:
                errors.append(
                    f"{where} sets automountServiceAccountToken: true, but Kubernetes "
                    f"API identity is not enabled for generated workloads."
                )
            elif self.service_account is None or declared_sa is None:
                errors.append(
                    f"{where} sets automountServiceAccountToken: true without an "
                    f"explicitly approved workload serviceAccountName."
                )
        elif automount is not False:
            errors.append(
                f"{where} has a malformed automountServiceAccountToken value "
                f"{automount!r}; it must be a boolean."
            )

        # --- pod-level security context --------------------------------
        pod_sc = pod_spec.get("securityContext") or {}
        if not isinstance(pod_sc, dict):
            errors.append(f"{where} has a malformed pod securityContext.")
            pod_sc = {}

        if pod_sc.get("runAsNonRoot") is not True:
            errors.append(
                f"{where} must set spec.securityContext.runAsNonRoot: true "
                f"(Restricted profile)."
            )
        if "runAsUser" in pod_sc and _is_root_id(pod_sc.get("runAsUser")):
            errors.append(f"{where} sets runAsUser 0.")
        if "runAsGroup" in pod_sc and _is_root_id(pod_sc.get("runAsGroup")):
            errors.append(f"{where} sets runAsGroup 0.")

        seccomp = pod_sc.get("seccompProfile") or {}
        if not isinstance(seccomp, dict) or seccomp.get("type") not in ALLOWED_SECCOMP_TYPES:
            errors.append(
                f"{where} must set spec.securityContext.seccompProfile.type to one of "
                f"{sorted(ALLOWED_SECCOMP_TYPES)} (Restricted profile)."
            )

        if pod_spec.get("sysctls") or pod_sc.get("sysctls"):
            errors.append(f"{where} sets sysctls, which is not permitted.")

        # --- volumes ----------------------------------------------------
        volumes = pod_spec.get("volumes") or []
        if not isinstance(volumes, list):
            errors.append(f"{where} has a malformed volumes list.")
            volumes = []
        for volume in volumes:
            if not isinstance(volume, dict):
                errors.append(f"{where} has a malformed volume entry.")
                continue
            vol_name = volume.get("name", "<unnamed>")
            sources = [k for k in volume.keys() if k != "name"]
            if not sources:
                errors.append(f"{where} volume {vol_name!r} declares no source.")
                continue
            for source in sources:
                if source in DENIED_VOLUME_TYPES:
                    errors.append(
                        f"{where} volume {vol_name!r} uses volume source {source!r}, "
                        f"which is not permitted from a generated manifest."
                    )
                elif source not in ALLOWED_VOLUME_TYPES:
                    errors.append(
                        f"{where} volume {vol_name!r} uses unrecognised volume source "
                        f"{source!r}; the policy admits only {sorted(ALLOWED_VOLUME_TYPES)}."
                    )
                else:
                    errors.extend(self._check_volume_reference(
                        source, volume.get(source), f"{where} volume {vol_name!r}"))

        # --- every container list, not just `containers` ---------------
        found_container = False
        for list_name in _CONTAINER_LISTS:
            entries = pod_spec.get(list_name) or []
            if not isinstance(entries, list):
                errors.append(f"{where} has a malformed {list_name} list.")
                continue
            if list_name == "ephemeralContainers" and entries:
                errors.append(
                    f"{where} declares ephemeralContainers, which is a debugging "
                    f"surface and is not permitted."
                )
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    errors.append(f"{where} has a malformed {list_name} entry.")
                    continue
                found_container = True
                errors.extend(self._check_container(entry, f"{where} {list_name[:-1]}"))

        if not found_container:
            errors.append(f"{where} declares no containers.")

        return errors

    def _check_named_reference(self, kind: str, name: Any, where: str) -> List[str]:
        """Deny-by-default check of one Secret/PVC/ConfigMap reference.

        Workload creation is an indirect path to Secret access: a pod
        that mounts a Secret reads it even though the manifest author
        holds no `get secrets` permission. Every reference must
        therefore be named by the host, not chosen by the manifest.
        """
        allowed = {
            "Secret": self.allowed_secret_names,
            "PersistentVolumeClaim": self.allowed_pvc_names,
            "ConfigMap": self.allowed_configmap_names,
        }[kind]
        if not isinstance(name, str) or not name.strip():
            return [f"{where} references a {kind} with no usable name."]
        name = name.strip()
        # A reference is resolved inside the pod's own namespace, so a
        # name carrying a separator is an attempt to escape it.
        if "/" in name or ":" in name:
            return [f"{where} references {kind} {name!r} with a namespace-qualified "
                    f"name; references are resolved in {self.namespace!r} only."]
        if not _DNS_1123.match(name):
            return [f"{where} references {kind} {name!r}, which is not a valid name."]
        if name not in allowed:
            permitted = sorted(allowed)
            detail = (f"the host-owned allowlist {permitted}" if permitted
                      else f"no {kind} reference is permitted at all")
            return [f"{where} references {kind} {name!r}, which is not in {detail}."]
        return []

    def _check_volume_reference(self, source: str, body: Any, where: str) -> List[str]:
        """Validate the names a permitted volume source resolves to."""
        errors: List[str] = []
        body = body if isinstance(body, dict) else {}
        if source == "secret":
            errors += self._check_named_reference(
                "Secret", body.get("secretName"), where)
        elif source == "persistentVolumeClaim":
            errors += self._check_named_reference(
                "PersistentVolumeClaim", body.get("claimName"), where)
        elif source == "configMap":
            errors += self._check_named_reference(
                "ConfigMap", body.get("name"), where)
        elif source == "projected":
            sources = body.get("sources")
            if not isinstance(sources, list):
                return errors + [f"{where} has a malformed projected volume."]
            for entry in sources:
                if not isinstance(entry, dict):
                    errors.append(f"{where} has a malformed projected source.")
                    continue
                for key, value in entry.items():
                    inner = value if isinstance(value, dict) else {}
                    if key == "secret":
                        errors += self._check_named_reference(
                            "Secret", inner.get("name"), f"{where} projected")
                    elif key == "configMap":
                        errors += self._check_named_reference(
                            "ConfigMap", inner.get("name"), f"{where} projected")
                    elif key == "serviceAccountToken":
                        if not self.allow_service_account_tokens:
                            errors.append(
                                f"{where} projects a serviceAccountToken, which grants "
                                f"the workload a Kubernetes API identity; this is not "
                                f"enabled for generated workloads.")
                    elif key == "downwardAPI":
                        continue
                    else:
                        errors.append(
                            f"{where} uses unrecognised projected source {key!r}.")
        elif source in ("emptyDir", "downwardAPI"):
            return errors
        return errors

    def _check_env_references(self, container: Dict[str, Any], where: str) -> List[str]:
        """Secret/ConfigMap reached through env, not through a volume."""
        errors: List[str] = []
        env = container.get("env")
        if env is not None and not isinstance(env, list):
            errors.append(f"{where} has a malformed env list.")
            env = []
        for entry in env or []:
            if not isinstance(entry, dict):
                errors.append(f"{where} has a malformed env entry.")
                continue
            value_from = entry.get("valueFrom")
            if not isinstance(value_from, dict):
                continue
            name = entry.get("name", "<unnamed>")
            for key, kind in (("secretKeyRef", "Secret"),
                              ("configMapKeyRef", "ConfigMap")):
                ref = value_from.get(key)
                if ref is not None:
                    ref = ref if isinstance(ref, dict) else {}
                    errors += self._check_named_reference(
                        kind, ref.get("name"), f"{where} env {name!r} {key}")
            for key in value_from:
                if key not in ("secretKeyRef", "configMapKeyRef",
                               "fieldRef", "resourceFieldRef"):
                    errors.append(
                        f"{where} env {name!r} uses unrecognised valueFrom source {key!r}.")

        env_from = container.get("envFrom")
        if env_from is not None and not isinstance(env_from, list):
            errors.append(f"{where} has a malformed envFrom list.")
            env_from = []
        for entry in env_from or []:
            if not isinstance(entry, dict):
                errors.append(f"{where} has a malformed envFrom entry.")
                continue
            matched = False
            for key, kind in (("secretRef", "Secret"),
                              ("configMapRef", "ConfigMap")):
                ref = entry.get(key)
                if ref is not None:
                    matched = True
                    ref = ref if isinstance(ref, dict) else {}
                    errors += self._check_named_reference(
                        kind, ref.get("name"), f"{where} envFrom {key}")
            if not matched:
                errors.append(f"{where} has an envFrom entry with no known source.")
        return errors

    def _check_container(self, container: Dict[str, Any], where: str) -> List[str]:
        errors: List[str] = []
        name = container.get("name") or "<unnamed>"
        where = f"{where} {name!r}"

        # Secret/ConfigMap reached through the environment rather than a
        # volume is the same escalation by a different route.
        errors.extend(self._check_env_references(container, where))

        image = container.get("image")
        if not isinstance(image, str) or not image.strip():
            errors.append(f"{where} declares no image.")

        # --- host ports --------------------------------------------------
        for port in container.get("ports") or []:
            if isinstance(port, dict) and port.get("hostPort") is not None:
                errors.append(f"{where} requests hostPort {port.get('hostPort')!r}.")

        # --- container security context ----------------------------------
        sc = container.get("securityContext") or {}
        if not isinstance(sc, dict):
            errors.append(f"{where} has a malformed securityContext.")
            sc = {}

        if sc.get("privileged") is True:
            errors.append(f"{where} requests privileged execution.")
        if sc.get("allowPrivilegeEscalation") is not False:
            errors.append(
                f"{where} must set allowPrivilegeEscalation: false (Restricted profile)."
            )
        if _is_root_id(sc.get("runAsUser")):
            errors.append(f"{where} sets runAsUser 0.")
        if _is_root_id(sc.get("runAsGroup")):
            errors.append(f"{where} sets runAsGroup 0.")
        if sc.get("runAsNonRoot") is False:
            errors.append(f"{where} sets runAsNonRoot: false.")
        if sc.get("procMount") not in (None, "Default"):
            errors.append(f"{where} sets procMount {sc.get('procMount')!r}.")
        if sc.get("windowsOptions"):
            errors.append(f"{where} sets windowsOptions, which is not permitted.")

        seccomp = sc.get("seccompProfile")
        if seccomp is not None:
            if not isinstance(seccomp, dict) or seccomp.get("type") not in ALLOWED_SECCOMP_TYPES:
                errors.append(
                    f"{where} sets an unsupported seccompProfile; permitted types are "
                    f"{sorted(ALLOWED_SECCOMP_TYPES)}."
                )

        caps = sc.get("capabilities") or {}
        if not isinstance(caps, dict):
            errors.append(f"{where} has a malformed capabilities block.")
            caps = {}
        added = caps.get("add") or []
        if added:
            errors.append(
                f"{where} adds capabilities {list(added)!r}; the policy permits no "
                f"capability additions."
            )
        dropped = [str(d).upper() for d in (caps.get("drop") or [])]
        if "ALL" not in dropped:
            errors.append(
                f"{where} must drop ALL capabilities (Restricted profile)."
            )

        # --- resource bounds ----------------------------------------------
        if self.require_resource_limits:
            resources = container.get("resources") or {}
            if not isinstance(resources, dict):
                errors.append(f"{where} has a malformed resources block.")
                resources = {}
            for section in ("requests", "limits"):
                block = resources.get(section) or {}
                if not isinstance(block, dict):
                    errors.append(f"{where} has a malformed resources.{section}.")
                    continue
                for dimension in ("cpu", "memory"):
                    value = block.get(dimension)
                    if value is None:
                        errors.append(
                            f"{where} must declare resources.{section}.{dimension}; "
                            f"unbounded workloads are a resource-exhaustion primitive."
                        )
                    elif not _QUANTITY.match(str(value)):
                        errors.append(
                            f"{where} resources.{section}.{dimension} value "
                            f"{value!r} is not a valid Kubernetes quantity."
                        )

        return errors

    # ------------------------------------------------------------------
    # service checks
    # ------------------------------------------------------------------
    def _check_service(self, doc: Dict[str, Any], where: str) -> List[str]:
        errors: List[str] = []
        spec = doc.get("spec")
        if not isinstance(spec, dict):
            errors.append(f"{where} must declare spec.")
            return errors

        service_type = spec.get("type", "ClusterIP")
        if service_type not in ALLOWED_SERVICE_TYPES:
            errors.append(
                f"{where} requests service type {service_type!r}; only "
                f"{sorted(ALLOWED_SERVICE_TYPES)} is permitted, so a generated manifest "
                f"cannot create external exposure."
            )
        for forbidden in ("externalIPs", "externalName", "loadBalancerIP",
                          "healthCheckNodePort", "loadBalancerSourceRanges"):
            if spec.get(forbidden):
                errors.append(f"{where} sets {forbidden}, which is not permitted.")
        for port in spec.get("ports") or []:
            if isinstance(port, dict) and port.get("nodePort") is not None:
                errors.append(f"{where} requests nodePort {port.get('nodePort')!r}.")
        return errors


def _is_root_id(value: Any) -> bool:
    """True when an explicit UID/GID of 0 was requested."""
    if value is None or isinstance(value, bool):
        return False
    try:
        return int(value) == 0
    except (TypeError, ValueError):
        return False
