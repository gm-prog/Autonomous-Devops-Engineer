"""Phase 8.6-A — trusted host-side adapter that runs kubectl in a container.

This is the only module permitted to spawn a process for Kubernetes work.
It launches the container runtime — never ``kubectl`` itself, and never a
shell. The argv it executes is built by
:mod:`deployment_service.application.services.kubectl_sandbox` from a
closed operation enum, so no untrusted value reaches the command line.

Staging contract (Phase 8.8A Correction-1, F4)
==============================================
Credential and manifest material is written to a PRIVATE host staging
root (mode 0700) and removed when the step completes:

* the staging root must be private: mode 0700 and owned by the worker
  identity (or usable by a root worker); a pre-existing
  attacker-controlled path, a symlink, or a world-traversable root is
  refused, never adopted;
* the staged kubeconfig is chowned to the sandbox uid:gid from the
  host-owned spec and chmod 0600 — readable by exactly the sandbox
  identity and by nobody else (world-readable 0444 was the defect this
  closes); a chown that cannot be performed aborts the step — there is
  no less-strict fallback;
* the manifest is staged the same way (0600, sandbox-owned);
* files are created exclusively (O_EXCL) and verified regular
  (lstat) after write; symlinks and unexpected file types are refused;
* cleanup cannot follow symlinks and only removes entries inside the
  per-run directory the adapter created.

Network contract (F3): the destination network is validated BEFORE any
staged material is written, and a missing/empty/invalid peer set is a
hard policy error — the adapter never "validates nothing".
"""
from __future__ import annotations

import os
import stat
import subprocess  # noqa: S404 - trusted adapter; see module docstring
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Optional

from deployment_service.application.services.kubectl_sandbox import (
    KUBERC_DENY_ALL,
    KubectlOperation,
    KubectlSandboxConfigurationError,
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

_STAGING_ROOT_DIR_MODE = 0o700
_CREDENTIAL_MODE = 0o600


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
    cancelled: bool = False

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.cancelled


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
        verify_network: bool = True,
    ) -> None:
        self._spec = spec
        if runtime not in ("docker", "podman"):
            raise KubectlSandboxPolicyViolation(f"unsupported runtime {runtime!r}")
        self._runtime = runtime
        self._staging_root = staging_root or None
        self._verify_network = verify_network
        # The network identity captured at approval, if the host
        # published one. A mismatch at execution time is fatal.
        self._approved_network_digest = os.getenv(
            "DEPLOYMENT_K8S_SANDBOX_NETWORK_IDENTITY", "").strip() or None
        self._sandbox_uid, self._sandbox_gid = self._parse_sandbox_user()

    def _parse_sandbox_user(self) -> tuple:
        parts = (self._spec.user or "").split(":")
        if len(parts) != 2:
            raise KubectlSandboxConfigurationError("sandbox user must be <uid>:<gid>")
        try:
            return int(parts[0]), int(parts[1])
        except ValueError:
            raise KubectlSandboxConfigurationError("sandbox user must be numeric") from None

    @property
    def spec(self) -> KubectlSandboxSpec:
        return self._spec

    # ------------------------------------------------------------------
    # F3 — destination network validation (fail closed, before staging)
    # ------------------------------------------------------------------

    def _validate_network(self) -> None:
        """Fail closed unless the destination network is still as approved.

        A missing or empty peer configuration is a POLICY ERROR here:
        validating nothing would let the sandbox run against an
        unproven network (the fail-open path this correction removes).
        """
        if not self._verify_network:
            raise KubectlSandboxConfigurationError(
                "network verification cannot be disabled for the kubectl "
                "sandbox; an unverified network is never treated as safe"
            )
        from deployment_service.infrastructure.sandbox.kubernetes_sandbox_network import (
            KubernetesSandboxNetworkError,
            approved_peers_from_environment,
            validate_network,
        )
        try:
            peers = approved_peers_from_environment()
            validate_network(
                self._spec.network,
                approved_identity=None,
                approved_peers=peers,
                approved_digest=self._approved_network_digest,
                runtime=self._runtime,
            )
        except KubernetesSandboxNetworkError as exc:
            raise KubectlSandboxConfigurationError(
                f"the sandbox network could not be verified: {exc}") from None

    # ------------------------------------------------------------------
    # F4 — private staging
    # ------------------------------------------------------------------

    def _staging_base(self) -> str:
        """Resolve (and verify) the private staging root.

        A configured root must already be a private directory (0700,
        not a symlink, owned by the worker or usable by root). Without
        configuration the adapter creates a worker-private root under
        the system temp dir — it never adopts a pre-existing path with
        a different owner or a permissive mode.
        """
        euid = os.geteuid() if hasattr(os, "geteuid") else 0
        if self._staging_root:
            root = self._staging_root
            if os.path.islink(root):
                raise KubectlSandboxConfigurationError(
                    "the staging root is a symlink; refusing to stage "
                    "credentials through a path the adapter does not own"
                )
            if not os.path.isdir(root):
                raise KubectlSandboxConfigurationError(
                    "the configured staging root does not exist or is not a "
                    "directory; refusing to create credential material next "
                    "to an unexpected path"
                )
            st = os.lstat(root)
            if stat.S_IMODE(st.st_mode) & 0o077:
                raise KubectlSandboxConfigurationError(
                    "the staging root is accessible to users other than its "
                    "owner (mode must be 0700); refusing to stage credentials"
                )
            if st.st_uid not in (euid, 0) and euid != 0:
                raise KubectlSandboxConfigurationError(
                    "the staging root is owned by another identity; refusing "
                    "to stage credentials into a directory the worker does "
                    "not control"
                )
            return root
        base = os.path.join(tempfile.gettempdir(), f"ares-k8s-staging-{euid}")
        if os.path.lexists(base):
            if os.path.islink(base) or not os.path.isdir(base):
                raise KubectlSandboxConfigurationError(
                    "the staging base path exists and is not a directory; "
                    "refusing to adopt an unexpected path"
                )
            st = os.lstat(base)
            if st.st_uid != euid or stat.S_IMODE(st.st_mode) != _STAGING_ROOT_DIR_MODE:
                raise KubectlSandboxConfigurationError(
                    "the staging base exists with an unexpected owner or "
                    "mode; refusing to adopt a path the worker did not create"
                )
            return base
        try:
            os.mkdir(base, _STAGING_ROOT_DIR_MODE)
            os.chmod(base, _STAGING_ROOT_DIR_MODE)
        except FileExistsError as exc:
            raise KubectlSandboxConfigurationError(
                "the staging base could not be created exclusively; another "
                "identity got there first — refusing"
            ) from None
        return base

    def _write_private(self, path: str, content: str) -> None:
        """Create one staged file: exclusive, regular, sandbox-owned,
        0600. Any deviation aborts the step (no 0444 fallback)."""
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _CREDENTIAL_MODE)
        except FileExistsError as exc:
            # A pre-planted file or symlink at a staged path (including
            # a symlink race) is an attack or a collision: refuse, never
            # overwrite.
            raise KubectlSandboxConfigurationError(
                "a staged credential path already exists (file or "
                "symlink); refusing to write credential material over an "
                "unexpected path"
            ) from exc
        try:
            with os.fdopen(fd, "w") as handle:
                handle.write(content)
        except Exception:
            try:
                os.unlink(path)
            except OSError:
                pass
            raise
        # Ownership: exactly the sandbox identity. A worker that cannot
        # chown cannot produce a correctly-scoped credential — fail
        # closed instead of widening the mode.
        try:
            os.chown(path, self._sandbox_uid, self._sandbox_gid)
        except (OSError, PermissionError) as exc:
            raise KubectlSandboxConfigurationError(
                f"the staged credential cannot be owned by the sandbox "
                f"identity {self._sandbox_uid}:{self._sandbox_gid} "
                f"({type(exc).__name__}); refusing to run kubectl with a "
                "credential whose scope cannot be proven"
            ) from None
        os.chmod(path, _CREDENTIAL_MODE)
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise KubectlSandboxConfigurationError(
                "the staged file is not a regular file; refusing to mount it"
            )

    @staticmethod
    def _safe_remove_tree(path: str) -> None:
        """Remove the per-run staging directory without following
        symlinks and only inside the directory the adapter created."""
        if not path or os.path.islink(path) or not os.path.isdir(path):
            return
        for name in os.listdir(path):
            child = os.path.join(path, name)
            if os.path.islink(child):
                os.unlink(child)
            elif os.path.isdir(child):
                ContainerKubectlSandbox._safe_remove_tree(child)
                try:
                    os.rmdir(child)
                except OSError:
                    pass
            else:
                try:
                    os.unlink(child)
                except OSError:
                    pass
        try:
            os.rmdir(path)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # execution
    # ------------------------------------------------------------------

    def execute(
        self,
        step: KubectlSandboxStep,
        *,
        manifest_yaml: str,
        kubeconfig_yaml: str,
        namespace: str,
        cancel_event: Optional[threading.Event] = None,
    ) -> KubectlSandboxResult:
        """Validate, stage inputs, run the container, and return bounded
        output. On cancellation (lost lease) the runtime process is
        killed and the container removed — a bounded cancel, not a
        silent continuation."""
        # F3: the network is proven BEFORE any credential material is
        # staged or the container is started.
        self._validate_network()

        base = self._staging_base()
        staging = _make_run_dir(base)
        try:
            manifest_path = os.path.join(staging, "deployment.yaml")
            self._write_private(manifest_path, manifest_yaml)
            kubeconfig_path = os.path.join(staging, "kubeconfig")
            self._write_private(kubeconfig_path, kubeconfig_yaml)
            kuberc_path = os.path.join(staging, "kuberc")
            self._write_private(kuberc_path, KUBERC_DENY_ALL)

            # F3: re-validate immediately before launch as well — the
            # window between the first check and now is milliseconds,
            # but a rebuilt network or a new co-tenant in that window
            # must still be caught.
            self._validate_network()

            plan = build_run_plan(
                spec=self._spec,
                step=step,
                manifest_host_path=manifest_path,
                kubeconfig_host_path=kubeconfig_path,
                kuberc_host_path=kuberc_path,
                container_name=f"ares-kubectl-{uuid.uuid4().hex[:12]}",
                runtime=self._runtime,
            )

            return self._run_container(plan, step, namespace, cancel_event)
        finally:
            self._safe_remove_tree(staging)

    def _run_container(self, plan, step, namespace: str, cancel_event) -> KubectlSandboxResult:
        timed_out = False
        cancelled = False
        try:
            process = subprocess.Popen(  # noqa: S603 - fixed host-built argv
                list(plan.argv),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                env=self._runtime_env(),
            )
            deadline = time.monotonic() + plan.timeout_seconds
            poll_interval = 0.25
            while process.poll() is None:
                if cancel_event is not None and cancel_event.is_set():
                    cancelled = True
                    _kill_process(process)
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    _kill_process(process)
                    break
                try:
                    process.wait(timeout=poll_interval)
                except subprocess.TimeoutExpired:
                    continue
            stdout_raw = process.stdout.read() if process.stdout else b""
            stderr_raw = process.stderr.read() if process.stderr else b""
            exit_code = process.returncode if process.returncode is not None else 1
            if timed_out:
                exit_code = 124
                stderr_raw = (stderr_raw or b"") + b"\n[sandbox wall-clock timeout]"
            if cancelled:
                exit_code = exit_code or 130
                stderr_raw = (stderr_raw or b"") + b"\n[sandbox cancelled: execution lease lost]"
            if timed_out or cancelled:
                self._force_remove(plan.container_name)
        except FileNotFoundError as exc:
            raise KubectlSandboxConfigurationError(
                f"the container runtime {self._runtime!r} is not available; "
                "the sandbox cannot run and will not fall back to the host"
            ) from None
        except Exception:
            self._force_remove(plan.container_name)
            raise

        stdout, trunc_out = _bounded(stdout_raw, plan.max_output_bytes)
        stderr, trunc_err = _bounded(stderr_raw, plan.max_output_bytes)
        return KubectlSandboxResult(
            operation=step.operation,
            exit_code=exit_code,
            stdout=_redact(stdout),
            stderr=_redact(stderr),
            timed_out=timed_out,
            truncated=trunc_out or trunc_err,
            policy_identity=self.policy_identity(namespace),
            container_argv=plan.argv,
            cancelled=cancelled,
        )

    def policy_identity(self, namespace: str) -> str:
        return sandbox_policy_identity(self._spec, namespace)

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


def _make_run_dir(base: str) -> str:
    staging = tempfile.mkdtemp(prefix="ares-k8s-", dir=base)
    os.chmod(staging, _STAGING_ROOT_DIR_MODE)
    st = os.lstat(staging)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise KubectlSandboxConfigurationError(
            "the per-run staging directory is not a real directory; refusing"
        )
    return staging


def _kill_process(process: subprocess.Popen) -> None:
    try:
        process.kill()
    except OSError:
        pass
    try:
        process.wait(timeout=10)
    except Exception:  # noqa: BLE001
        pass
