"""Kubernetes execution authority.

Phase 8.6-A moved kubectl execution off the host. This service no longer
spawns a process of any kind: it validates the manifest against the
host-owned policy, sanitizes the kubeconfig, names a closed operation,
and hands a bounded step to a :class:`KubernetesSandboxPort`
implementation. The container adapter behind that port is the only code
that launches a process, and it launches the container runtime, never
``kubectl`` and never a shell.

There is deliberately no method that accepts a command, a flag, a server
URL, a kubeconfig path or a filename. Those are all host-owned.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional, Protocol

from deployment_service.application.services.kubeconfig_policy import (
    KubeconfigPolicyError,
    SanitizedKubeconfig,
    sanitize_kubeconfig,
)
from deployment_service.application.services.kubectl_sandbox import (
    OPERATION_TIMEOUTS,
    KubectlOperation,
    KubectlSandboxConfigurationError,
    KubectlSandboxPolicyViolation,
    KubectlSandboxStep,
    build_kubectl_argv,
    load_spec_from_environment,
)
from deployment_service.application.services.kubernetes_execution_identity import (
    KubernetesExecutionIdentity,
    KubernetesExecutionIdentityError,
    expected_api_server,
    KubernetesExecutionConfig,
    expected_ca_fingerprint,
    verify_binding,
)
from deployment_service.application.services.kubernetes_manifest_policy import (
    KubernetesManifestPolicy,
)

DEFAULT_NAMESPACE = "devops-production-namespace"


class KubernetesSandboxPort(Protocol):
    """Port the runner uses to execute a bounded kubectl step."""

    def execute(
        self,
        step: KubectlSandboxStep,
        *,
        manifest_yaml: str,
        kubeconfig_yaml: str,
        namespace: str,
    ) -> Any:
        ...

    def policy_identity(self, namespace: str) -> str:
        ...


class KubectlRunnerService:
    """Policy-bound Kubernetes runner. Executes only inside the sandbox."""

    def __init__(self, sandbox: Optional[KubernetesSandboxPort] = None,
                 config: Optional[KubernetesExecutionConfig] = None) -> None:
        self._sandbox = sandbox
        # Workstream C: one immutable snapshot for the whole run. Every
        # decision below reads THIS object, never the environment, so
        # configuration cannot drift between check and use.
        self._config = config or KubernetesExecutionConfig.from_environment()
        self._manifest_policy = KubernetesManifestPolicy(
            namespace=self._config.namespace)

    # ---------------------------------------------------------------- config

    def namespace(self) -> str:
        """The single host-owned execution namespace, from the snapshot."""
        return self._config.namespace

    def _check_namespace(self, namespace: Optional[str]) -> Optional[Dict[str, Any]]:
        """Reject any namespace that is not the host-owned one."""
        owned = self.namespace()
        if namespace is not None and namespace != owned:
            return self._blocked(
                f"Namespace {namespace!r} is not the host-owned execution namespace "
                f"{owned!r}; cross-namespace execution is refused."
            )
        return None

    @staticmethod
    def _blocked(reason: str) -> Dict[str, Any]:
        return {
            "status": "BLOCKED",
            "stderr": reason,
            "stdout": "",
            "cluster_access": False,
            "sandboxed": True,
        }

    # ------------------------------------------------------------ credentials

    def _kubeconfig(self) -> SanitizedKubeconfig:
        path = self._config.kubeconfig_path
        if not path:
            raise KubeconfigPolicyError(
                "DEPLOYMENT_KUBECONFIG_PATH must be explicitly configured for "
                "cluster execution."
            )
        try:
            raw = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise KubeconfigPolicyError(f"kubeconfig is unreadable: {exc}") from None
        sanitized = sanitize_kubeconfig(
            raw,
            expected_namespace=self.namespace(),
            credential_profile_id=self._config.credential_profile_id,
            # The host-owned endpoint. Without this the runner would
            # accept any syntactically valid https cluster, which makes
            # the approved target a suggestion rather than a binding.
            expected_server=self._config.expected_api_server or None,
        )
        pinned_ca = self._config.expected_ca_fingerprint
        if pinned_ca and sanitized.cluster_identity.ca_fingerprint_sha256 != pinned_ca:
            raise KubeconfigPolicyError(
                "the cluster CA does not match the host-owned fingerprint; "
                "refusing to trust this control plane"
            )
        return sanitized

    def _resolve_sandbox(self) -> KubernetesSandboxPort:
        if self._sandbox is not None:
            return self._sandbox
        from deployment_service.infrastructure.sandbox.container_kubectl_sandbox import (
            ContainerKubectlSandbox,
        )
        sandbox = ContainerKubectlSandbox(
            load_spec_from_environment(),
            runtime=self._config.container_runtime,
            staging_root=self._config.staging_root or None,
            # Workstream C: the approved network identity and the
            # approved destination set come from the ONE immutable
            # snapshot this runner was built with -- not from a second
            # environment read at execution time.
            approved_network_identity=self._config.sandbox_network_identity or None,
            approved_peers=self._config.sandbox_peers,
        )
        self._sandbox = sandbox
        return sandbox

    # ---------------------------------------------------------- identity

    def execution_identity(
        self, kubeconfig: Optional[SanitizedKubeconfig] = None
    ) -> KubernetesExecutionIdentity:
        """Derive the full execution identity from host-owned state only."""
        kubeconfig = kubeconfig or self._kubeconfig()
        namespace = self.namespace()
        try:
            sandbox_identity = self._resolve_sandbox().policy_identity(namespace)
        except KubectlSandboxConfigurationError as exc:
            raise KubernetesExecutionIdentityError(
                f"sandbox policy identity is unavailable: {exc}") from None
        return KubernetesExecutionIdentity(
            namespace=namespace,
            api_server=kubeconfig.cluster_identity.server,
            ca_fingerprint_sha256=kubeconfig.cluster_identity.ca_fingerprint_sha256,
            credential_profile_id=kubeconfig.credential_profile_id,
            manifest_policy_identity=self._manifest_policy.identity(),
            sandbox_policy_identity=sandbox_identity,
            network_identity=self._config.network_identity,
            workload_identity_policy=self._manifest_policy.workload_identity_policy(),
        )

    # --------------------------------------------------------------- manifest

    def _approved_manifest(self, manifest_path: str) -> tuple:
        """Validate the manifest and return its canonical, approved form."""
        try:
            raw = Path(manifest_path).read_text(encoding="utf-8")
        except OSError as exc:
            return None, self._blocked(f"manifest is unreadable: {exc}")
        result = self._manifest_policy.evaluate(raw)
        if not result.passed:
            return None, {
                "status": "BLOCKED",
                "stdout": "",
                "stderr": "manifest policy rejected the manifest:\n" + "\n".join(result.errors),
                "cluster_access": False,
                "sandboxed": True,
                "manifest_policy": result.to_dict(),
            }
        return result, None

    # -------------------------------------------------------------- execution

    #: Operations that change cluster state. These may only run against
    #: the exact target the approval was granted for.
    MUTATING_OPERATIONS = (KubectlOperation.APPLY, KubectlOperation.ROLLOUT_UNDO)

    def _execute(
        self,
        operation: KubectlOperation,
        *,
        manifest_yaml: str,
        deployment_name: Optional[str] = None,
        rollout_timeout_seconds: int = 300,
        extra: Optional[Dict[str, Any]] = None,
        approved_identity: Optional[KubernetesExecutionIdentity] = None,
    ) -> Dict[str, Any]:
        namespace = self.namespace()
        try:
            kubeconfig = self._kubeconfig()
        except KubeconfigPolicyError as exc:
            return self._blocked(str(exc))

        # Re-derive the execution target from host-owned state and
        # compare it with what was approved. This happens BEFORE the
        # sandbox is touched, so a moved cluster never receives a call.
        try:
            observed_identity = self.execution_identity(kubeconfig)
            if operation in self.MUTATING_OPERATIONS:
                verify_binding(approved_identity, observed_identity)
            elif approved_identity is not None:
                verify_binding(approved_identity, observed_identity)
        except KubernetesExecutionIdentityError as exc:
            return self._blocked(str(exc))

        try:
            argv = build_kubectl_argv(
                operation,
                namespace=namespace,
                deployment_name=deployment_name,
                rollout_timeout_seconds=rollout_timeout_seconds,
            )
            step = KubectlSandboxStep(
                operation=operation,
                argv=argv,
                timeout_seconds=OPERATION_TIMEOUTS[operation],
            )
        except KubectlSandboxPolicyViolation as exc:
            return self._blocked(f"command policy refused the operation: {exc}")

        try:
            sandbox = self._resolve_sandbox()
        except KubectlSandboxConfigurationError as exc:
            return self._blocked(f"sandbox is not configured: {exc}")

        try:
            result = sandbox.execute(
                step,
                manifest_yaml=manifest_yaml,
                kubeconfig_yaml=kubeconfig.content,
                namespace=namespace,
            )
        except (KubectlSandboxPolicyViolation, KubectlSandboxConfigurationError) as exc:
            return self._blocked(f"sandbox refused the step: {exc}")

        timed_out = bool(getattr(result, "timed_out", False))
        exit_code = int(getattr(result, "exit_code", 1))
        payload: Dict[str, Any] = {
            "status": "TIMEOUT" if timed_out else ("PASS" if exit_code == 0 else "FAIL"),
            "exit_code": exit_code,
            "operation": operation.value,
            "stdout": getattr(result, "stdout", ""),
            "stderr": getattr(result, "stderr", ""),
            "cluster_access": True,
            "sandboxed": True,
            "namespace": namespace,
            "truncated": bool(getattr(result, "truncated", False)),
            "sandbox_policy_identity": getattr(result, "policy_identity", ""),
            "credential_profile": kubeconfig.to_evidence(),
            "execution_identity": observed_identity.to_dict(),
        }
        if extra:
            payload.update(extra)
        return payload

    # ----------------------------------------------------------------- public

    def dry_run(self, manifest_path: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Server-side dry run against the real cluster.

        Fails closed. There is no client-side fallback: a client dry run
        proves nothing about admission, RBAC or schema on the target
        cluster, so reporting it as a pass would be a false result.
        """
        blocked = self._check_namespace(namespace)
        if blocked:
            return blocked
        approved, error = self._approved_manifest(manifest_path)
        if error:
            return error
        return self._execute(
            KubectlOperation.SERVER_SIDE_DRY_RUN,
            manifest_yaml=approved.canonical_yaml,
            extra={
                "manifest_sha256": approved.manifest_sha256,
                "manifest_policy_identity": approved.policy_identity,
                "validation_mode": "server-side-dry-run",
            },
        )

    def apply(self, manifest_path: str, namespace: Optional[str] = None,
              approved_identity: Optional[KubernetesExecutionIdentity] = None) -> Dict[str, Any]:
        blocked = self._check_namespace(namespace)
        if blocked:
            return blocked
        approved, error = self._approved_manifest(manifest_path)
        if error:
            return error
        return self._execute(
            KubectlOperation.APPLY,
            approved_identity=approved_identity,
            manifest_yaml=approved.canonical_yaml,
            extra={
                "manifest_sha256": approved.manifest_sha256,
                "manifest_policy_identity": approved.policy_identity,
                "applied_resources": approved.resources,
            },
        )

    def rollout_status(
        self,
        deployment_name: str,
        namespace: Optional[str] = None,
        timeout_seconds: int = 300,
    ) -> Dict[str, Any]:
        blocked = self._check_namespace(namespace)
        if blocked:
            return blocked
        return self._execute(
            KubectlOperation.ROLLOUT_STATUS,
            manifest_yaml="",
            deployment_name=deployment_name,
            rollout_timeout_seconds=timeout_seconds,
        )

    def rollout_undo(
        self,
        deployment_name: str,
        namespace: Optional[str] = None,
        approved_identity: Optional[KubernetesExecutionIdentity] = None,
    ) -> Dict[str, Any]:
        blocked = self._check_namespace(namespace)
        if blocked:
            return blocked
        return self._execute(
            KubectlOperation.ROLLOUT_UNDO,
            approved_identity=approved_identity,
            manifest_yaml="",
            deployment_name=deployment_name,
        )
