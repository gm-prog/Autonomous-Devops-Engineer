"""Phase 8.5-A — container-backed Terraform execution sandbox.

Runs ONE fixed Terraform operation inside a short-lived, tightly
constrained container:

- digest-pinned image, ``--pull never`` (hermetic; no floating tags)
- ``--network none`` (there is no per-request network switch)
- non-root ``--user``, ``--read-only`` rootfs, tmpfs ``/tmp``
- ``--cap-drop ALL``, ``--security-opt no-new-privileges:true``
- ``--pids-limit`` / ``--memory`` / ``--cpus`` bounded, wall-clock timeout
- exactly one bind mount: the ephemeral workspace at ``/workspace``
- environment built from the policy allowlist; credential VALUES are
  passed through the docker CLI's own environment, never through argv
- ``--rm`` plus unconditional best-effort ``docker rm -f`` on every exit
  path (success, failure, timeout, startup error)

The docker CLI is invoked by this TRUSTED orchestration component on the
host. The Docker socket is never mounted into the sandbox, so the
untrusted Terraform workload has no path to the daemon.

No fallback: if the docker CLI or daemon is unavailable, execution raises
a typed fail-closed error and Terraform does not run at all.
"""

import os
import signal
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from deployment_service.application.services.terraform_sandbox import (
    sandbox_runtime_identity,
    SANDBOX_IMAGE_VAR,
    TerraformSandboxConfigurationError,
    TerraformSandboxOutcome,
    TerraformSandboxResultError,
    TerraformSandboxSpec,
    TerraformSandboxStep,
    TerraformSandboxUnavailableError,
    build_run_plan,
    new_container_name,
    sandbox_policy_identity,
    validate_runtime_spec,
)

_DAEMON_ERROR_MARKERS = (
    "cannot connect to the docker daemon",
    "is the docker daemon running",
    "error during connect",
    "no such file or directory",  # missing docker socket / binary
)
_IMAGE_ERROR_MARKERS = (
    "unable to find image",
    "no such image",
    "image not known",
    "pull access denied",
    "manifest unknown",
)
_DOCKER_CLI_ERROR_MARKERS = (
    "docker:",
    "error response from daemon",
    "unable to prepare",
)

_SANDBOX_TERRAFORM_VERSION_VAR = "DEPLOYMENT_TERRAFORM_SANDBOX_VERSION"


@dataclass(frozen=True)
class _CliResult:
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool = False


class ContainerTerraformSandbox:
    """TerraformSandboxPort implemented with short-lived containers."""

    def __init__(
        self,
        *,
        image: str,
        user: str | None = None,
        network_mode: str = "none",
        terraform_version: str = "",
        cli_runner=None,
    ):
        """``cli_runner(argv, timeout, env) -> _CliResult`` is a test seam
        for deterministic unit tests; production uses the real docker CLI.
        """
        self._spec = TerraformSandboxSpec(
            image=(image or "").strip(),
            user=user if user is not None else f"{os.getuid()}:{os.getgid()}",
            network_mode=network_mode,
            terraform_version=(terraform_version or "").strip(),
        )
        self._cli_runner = cli_runner

    @classmethod
    def from_environment(cls) -> "ContainerTerraformSandbox":
        """Production wiring: configuration is host-owned, via env vars.

        Missing configuration is stored as-is and fails closed at
        execution time with a typed configuration error — it never
        enables a host fallback.
        """
        return cls(
            image=os.environ.get(SANDBOX_IMAGE_VAR, ""),
            # Phase 8.5-A corrective: the runtime identity and the
            # workspace owner are resolved by ONE helper so they cannot
            # drift apart and leave Terraform unable to write (or, far
            # worse, tempt someone to "fix" it by running as root).
            user="%d:%d" % sandbox_runtime_identity(),
            network_mode="none",
            terraform_version=os.environ.get(
                _SANDBOX_TERRAFORM_VERSION_VAR, ""
            ),
        )

    # --- evidence ------------------------------------------------------

    def describe(self) -> Mapping[str, str]:
        """Safe, deterministic runtime identity for execution evidence.

        Contains no credentials, no environment dump and no plan content.
        """
        try:
            identity = sandbox_policy_identity(self._spec)
        except Exception:  # pragma: no cover - identity is pure
            identity = ""
        return {
            "sandbox_policy_identity": identity,
            "sandbox_image": self._spec.image,
            "sandbox_user": self._spec.user,
            "sandbox_network_mode": self._spec.network_mode,
            "terraform_version": self._spec.terraform_version,
            "execution_mode": "container",
        }

    # --- execution -----------------------------------------------------

    def execute(
        self, step: TerraformSandboxStep, workspace_path: Path
    ) -> TerraformSandboxOutcome:
        validate_runtime_spec(self._spec)

        container_name = new_container_name(step.operation.value)
        plan = build_run_plan(
            spec=self._spec,
            step=step,
            workspace_path=Path(workspace_path),
            container_name=container_name,
        )

        # Credential VALUES travel in the CLI process environment only.
        cli_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        for key in ("DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
            if key in os.environ:
                cli_env[key] = os.environ[key]
        missing = [
            key for key in plan.credential_env_keys if key not in os.environ
        ]
        if missing:
            raise TerraformSandboxConfigurationError(
                "configured credential environment variables are not "
                f"present on the host: {sorted(missing)}"
            )
        for key in plan.credential_env_keys:
            cli_env[key] = os.environ[key]

        try:
            result = self._run_cli(
                plan.cli_argv, plan.wall_timeout_seconds, cli_env
            )
        except FileNotFoundError as exc:
            raise TerraformSandboxUnavailableError(
                "terraform sandbox runtime is unavailable: docker CLI not "
                "found; terraform will not run on the host"
            ) from exc
        except OSError as exc:
            raise TerraformSandboxUnavailableError(
                f"terraform sandbox runtime could not be started: {exc}"
            ) from exc
        finally:
            self._destroy_container(container_name)

        limit = step.max_output_bytes
        if result.timed_out:
            return TerraformSandboxOutcome(
                operation=step.operation,
                exit_code=-int(signal.SIGKILL),
                stdout=result.stdout[:limit].decode("utf-8", errors="replace"),
                stderr=result.stderr[:limit].decode("utf-8", errors="replace"),
                timed_out=True,
                output_truncated=(
                    len(result.stdout) > limit or len(result.stderr) > limit
                ),
            )

        if result.exit_code is None or not isinstance(result.exit_code, int):
            raise TerraformSandboxResultError(
                "terraform sandbox returned a malformed result; failing closed"
            )

        stderr_text = result.stderr.decode("utf-8", errors="replace")
        lowered = stderr_text.lower()
        if result.exit_code in (125, 126, 127):
            if any(m in lowered for m in _DAEMON_ERROR_MARKERS):
                raise TerraformSandboxUnavailableError(
                    "terraform sandbox runtime is unreachable; terraform "
                    "will not run on the host"
                )
            if any(m in lowered for m in _IMAGE_ERROR_MARKERS):
                raise TerraformSandboxConfigurationError(
                    "terraform sandbox image is not present locally and "
                    "--pull never forbids fetching it; failing closed"
                )
            if any(m in lowered for m in _DOCKER_CLI_ERROR_MARKERS):
                raise TerraformSandboxResultError(
                    "terraform sandbox runtime refused the request; "
                    "failing closed"
                )

        return TerraformSandboxOutcome(
            operation=step.operation,
            exit_code=result.exit_code,
            stdout=result.stdout[:limit].decode("utf-8", errors="replace"),
            stderr=stderr_text[:limit],
            output_truncated=(
                len(result.stdout) > limit or len(result.stderr) > limit
            ),
            timed_out=False,
        )

    # --- docker CLI plumbing -------------------------------------------

    def _run_cli(self, argv, timeout: float, env: Mapping[str, str]):
        if self._cli_runner is not None:
            return self._cli_runner(tuple(argv), timeout, dict(env))
        return self._default_cli_runner(tuple(argv), timeout, dict(env))

    def _destroy_container(self, container_name: str) -> None:
        """Unconditional best-effort cleanup on every exit path."""
        try:
            self._run_cli(
                ("docker", "rm", "-f", container_name),
                15.0,
                {"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            )
        except Exception:
            pass

    @classmethod
    def _default_cli_runner(cls, argv, timeout: float, env) -> _CliResult:
        process = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=dict(env),
            start_new_session=True,
        )

        stdout_buffer = bytearray()
        stderr_buffer = bytearray()
        limit = 4 * 1024 * 1024
        readers = [
            threading.Thread(
                target=cls._drain,
                args=(process.stdout, stdout_buffer, limit),
                daemon=True,
            ),
            threading.Thread(
                target=cls._drain,
                args=(process.stderr, stderr_buffer, limit),
                daemon=True,
            ),
        ]
        for reader in readers:
            reader.start()

        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            cls._kill(process)

        for reader in readers:
            reader.join(timeout=2.0)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()

        return _CliResult(
            process.returncode,
            bytes(stdout_buffer),
            bytes(stderr_buffer),
            timed_out=timed_out,
        )

    @staticmethod
    def _kill(process: subprocess.Popen) -> None:
        """Terminate the whole process group, then the process itself."""
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
        if process.poll() is None:
            process.kill()

    @staticmethod
    def _drain(stream, buffer: bytearray, limit: int) -> None:
        if stream is None:
            return
        while True:
            chunk = stream.read(8192)
            if not chunk:
                break
            remaining = limit - len(buffer)
            if remaining > 0:
                buffer.extend(chunk[:remaining])
