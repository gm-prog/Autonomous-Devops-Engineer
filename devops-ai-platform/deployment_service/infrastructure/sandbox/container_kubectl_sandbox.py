"""Phase 8.6-A — trusted host-side adapter that runs kubectl in a container.

This is the only module permitted to spawn a process for Kubernetes work.
It launches the container runtime — never ``kubectl`` itself, and never a
shell. The argv it executes is built by
:mod:`deployment_service.application.services.kubectl_sandbox` from a
closed operation enum, so no untrusted value reaches the command line.

The credential and manifest material is written to a host staging
directory owned by this adapter, mounted read-only, and removed when the
step completes.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess  # noqa: S404 - trusted adapter; see module docstring
import tempfile
import uuid
from dataclasses import dataclass
from typing import Optional

from deployment_service.application.services.kubectl_sandbox import (
    KUBERC_DENY_ALL,
    KubectlOperation,
    KubectlSandboxPolicyViolation,
    KubectlSandboxSpec,
    KubectlSandboxStep,
    build_run_plan,
    sandbox_policy_identity,
)

_SECRET_MARKERS = (
    "client-key-data", "client-certificate-data", "token:",
    "-----BEGIN", "certificate-authority-data", "Authorization:",
    "Bearer ",
)


@dataclass(frozen=True)
class KubectlSandboxResult:
    """Outcome of one sandboxed kubectl step."""

    operation: KubectlOperation
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool
    policy_identity: str
    container_argv: tuple

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


def _redact(text: str) -> str:
    """Drop any line that could carry credential material.

    Server-side errors can echo request bodies, so output is filtered
    before it is ever stored or logged.
    """
    kept = []
    for line in text.splitlines():
        if any(marker in line for marker in _SECRET_MARKERS):
            kept.append("[redacted: credential-bearing line removed]")
        else:
            kept.append(line)
    return "\n".join(kept)


def _bounded(raw: bytes, limit: int) -> tuple:
    if len(raw) <= limit:
        return raw.decode("utf-8", "replace"), False
    return raw[:limit].decode("utf-8", "replace") + "\n[output truncated]", True


class ContainerKubectlSandbox:
    """Runs one kubectl operation inside a locked-down container."""

    def __init__(
        self,
        spec: KubectlSandboxSpec,
        *,
        runtime: str = "docker",
        staging_root: Optional[str] = None,
    ) -> None:
        self._spec = spec
        if runtime not in ("docker", "podman"):
            raise KubectlSandboxPolicyViolation(f"unsupported runtime {runtime!r}")
        self._runtime = runtime
        self._staging_root = staging_root or tempfile.gettempdir()

    @property
    def spec(self) -> KubectlSandboxSpec:
        return self._spec

    def policy_identity(self, namespace: str) -> str:
        return sandbox_policy_identity(self._spec, namespace)

    def execute(
        self,
        step: KubectlSandboxStep,
        *,
        manifest_yaml: str,
        kubeconfig_yaml: str,
        namespace: str,
    ) -> KubectlSandboxResult:
        """Stage inputs, run the container, and return bounded output."""
        staging = tempfile.mkdtemp(prefix="ares-k8s-", dir=self._staging_root)
        try:
            os.chmod(staging, stat.S_IRWXU)
            manifest_path = os.path.join(staging, "deployment.yaml")
            kubeconfig_path = os.path.join(staging, "kubeconfig")
            kuberc_path = os.path.join(staging, "kuberc")

            self._write(manifest_path, manifest_yaml, 0o444)
            self._write(kubeconfig_path, kubeconfig_yaml, 0o400)
            self._write(kuberc_path, KUBERC_DENY_ALL, 0o444)
            # The sandbox runs as a non-root uid, so the mounted files must
            # be world-readable to that uid. Mode 0o444 is read-only for
            # everyone; the kubeconfig is handled below.
            os.chmod(kubeconfig_path, 0o444)
            os.chmod(staging, 0o711)

            plan = build_run_plan(
                spec=self._spec,
                step=step,
                manifest_host_path=manifest_path,
                kubeconfig_host_path=kubeconfig_path,
                kuberc_host_path=kuberc_path,
                container_name=f"ares-kubectl-{uuid.uuid4().hex[:12]}",
                runtime=self._runtime,
            )

            timed_out = False
            try:
                completed = subprocess.run(  # noqa: S603 - fixed host-built argv
                    list(plan.argv),
                    capture_output=True,
                    timeout=plan.timeout_seconds,
                    env=self._runtime_env(),
                    check=False,
                )
                stdout_raw, stderr_raw = completed.stdout, completed.stderr
                exit_code = completed.returncode
            except subprocess.TimeoutExpired as exc:
                timed_out = True
                stdout_raw = exc.stdout or b""
                stderr_raw = (exc.stderr or b"") + b"\n[sandbox wall-clock timeout]"
                exit_code = 124
                self._force_remove(plan.container_name)

            stdout, trunc_out = _bounded(stdout_raw, plan.max_output_bytes)
            stderr, trunc_err = _bounded(stderr_raw, plan.max_output_bytes)
            return KubectlSandboxResult(
                operation=plan.operation,
                exit_code=exit_code,
                stdout=_redact(stdout),
                stderr=_redact(stderr),
                timed_out=timed_out,
                truncated=trunc_out or trunc_err,
                policy_identity=self.policy_identity(namespace),
                container_argv=plan.argv,
            )
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    @staticmethod
    def _write(path: str, content: str, mode: int) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "w") as handle:
            handle.write(content)
        os.chmod(path, mode)

    def _runtime_env(self) -> dict:
        """Environment for the *container runtime* client.

        Explicitly constructed. ``os.environ.copy()`` is never used: it
        would hand cloud, database and proxy variables to the runtime and,
        through it, potentially to the sandbox.
        """
        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": os.getenv("HOME", "/tmp"),
        }
        docker_host = os.getenv("DOCKER_HOST")
        if docker_host:
            env["DOCKER_HOST"] = docker_host
        return env

    def _force_remove(self, container_name: str) -> None:
        try:
            subprocess.run(  # noqa: S603 - fixed host-built argv
                [self._runtime, "rm", "-f", container_name],
                capture_output=True,
                timeout=30,
                env=self._runtime_env(),
                check=False,
            )
        except Exception:  # pragma: no cover - best-effort cleanup
            pass
