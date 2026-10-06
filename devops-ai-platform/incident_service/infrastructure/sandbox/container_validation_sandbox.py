"""Container-backed validation sandbox (Phase 6.2.2).

Executes one fixed validation step inside a short-lived, tightly
constrained container:

- digest-pinned image, ``--pull never`` (hermetic; no floating tags)
- ``--network none`` (no per-request network switch exists)
- non-root ``--user``, ``--read-only`` rootfs, tmpfs ``/tmp``
- ``--cap-drop ALL``, ``--security-opt no-new-privileges:true``
- restrictive seccomp when a profile is configured; docker's default
  seccomp profile otherwise (``seccomp=unconfined`` is forbidden by policy)
- ``--pids-limit`` / ``--memory`` / ``--cpus`` bounded, wall-clock timeout
- exactly one bind mount: the ephemeral workspace at ``/workspace``
- environment built exclusively from the policy allowlist — host
  variables (tokens, DB/Redis URLs, JWT secrets) are never forwarded
- ``--rm`` + unconditional best-effort ``docker rm -f`` cleanup on every
  exit path (success, timeout, failure, startup error)

No fallback: if the docker CLI or daemon is unavailable, execution raises
a typed fail-closed error — the workload never runs on the host.
"""

import os
import signal
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path

from incident_service.application.services.remediation_validation_runner import (
    ValidationSandboxConfigurationError,
    ValidationSandboxResultError,
    ValidationSandboxUnavailableError,
)
from incident_service.application.services.validation_sandbox import (
    SandboxRunPlan,
    SandboxStepOutcome,
    SandboxStepSpec,
    SandboxRuntimeSpec,
    build_run_plan,
    new_container_name,
    validate_runtime_spec,
)

_DAEMON_ERROR_MARKERS = (
    "cannot connect to the docker daemon",
    "is the docker daemon running",
    "error during connect",
    "no such file or directory",  # missing docker socket / binary
)
_DOCKER_CLI_ERROR_MARKERS = (
    "docker:",
    "error response from daemon",
    "unable to prepare",
)


@dataclass(frozen=True)
class _CliResult:
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool = False


class ContainerValidationSandbox:
    """ValidationSandboxPort implemented with short-lived containers."""

    def __init__(
        self,
        *,
        image: str,
        user: str | None = None,
        network_mode: str = "none",
        seccomp_profile: str | None = None,
        cli_runner=None,
    ):
        """``cli_runner(argv, timeout) -> _CliResult`` is a test seam for
        deterministic unit tests; production uses the real docker CLI."""
        self._runtime = SandboxRuntimeSpec(
            image=(image or "").strip(),
            user=user if user is not None else f"{os.getuid()}:{os.getgid()}",
            network_mode=network_mode,
            seccomp_profile=seccomp_profile,
        )
        self._cli_runner = cli_runner

    @classmethod
    def from_environment(cls) -> "ContainerValidationSandbox":
        """Production wiring: configuration comes from explicit env vars.

        Missing configuration is stored as-is and fails closed at
        execution time (typed configuration error) — it never enables a
        host fallback.
        """
        return cls(
            image=os.environ.get("REMEDIATION_SANDBOX_IMAGE", ""),
            user=(
                f"{os.getuid()}:{os.getgid()}"
                if os.getuid() != 0
                else "65534:65534"
            ),
            network_mode="none",
            seccomp_profile=(
                os.environ.get("REMEDIATION_SANDBOX_SECCOMP_PROFILE") or None
            ),
        )

    def execute(
        self, step: SandboxStepSpec, workspace_path: Path
    ) -> SandboxStepOutcome:
        try:
            validate_runtime_spec(self._runtime)
        except ValueError as exc:
            raise ValidationSandboxConfigurationError(str(exc)) from exc

        container_name = new_container_name(step.name)
        try:
            plan = build_run_plan(
                spec=self._runtime,
                step=step,
                workspace_path=Path(workspace_path),
                container_name=container_name,
            )
        except ValueError as exc:
            raise ValidationSandboxConfigurationError(str(exc)) from exc

        if self._runtime.seccomp_profile is not None and not Path(
            self._runtime.seccomp_profile
        ).is_file():
            raise ValidationSandboxConfigurationError(
                "configured seccomp profile does not exist"
            )

        try:
            result = self._run_cli(plan.cli_argv, plan.wall_timeout_seconds)
        except FileNotFoundError as exc:
            raise ValidationSandboxUnavailableError(
                "sandbox runtime is unavailable: docker CLI not found; "
                "remediation validation will not run on the host"
            ) from exc
        except OSError as exc:
            raise ValidationSandboxUnavailableError(
                f"sandbox runtime could not be started: {exc}"
            ) from exc
        finally:
            self._destroy_container(container_name)

        if result.timed_out:
            stdout = result.stdout[: step.max_output_bytes]
            stderr = result.stderr[: step.max_output_bytes]
            return SandboxStepOutcome(
                exit_code=-int(signal.SIGKILL),
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
                timed_out=True,
                output_truncated=len(result.stdout) > step.max_output_bytes
                or len(result.stderr) > step.max_output_bytes,
            )

        if result.exit_code is None or not isinstance(result.exit_code, int):
            raise ValidationSandboxResultError(
                "sandbox returned a malformed result; failing closed"
            )

        stderr_text = result.stderr.decode("utf-8", errors="replace")
        exit_code = result.exit_code
        if exit_code in (125, 126, 127) and any(
            marker in stderr_text.lower()
            for marker in _DAEMON_ERROR_MARKERS + _DOCKER_CLI_ERROR_MARKERS
        ):
            if any(m in stderr_text.lower() for m in _DAEMON_ERROR_MARKERS):
                raise ValidationSandboxUnavailableError(
                    "sandbox runtime is unreachable; remediation validation "
                    "will not run on the host"
                )
            raise ValidationSandboxResultError(
                "sandbox runtime refused the request; failing closed"
            )

        stdout_text = result.stdout[: step.max_output_bytes].decode(
            "utf-8", errors="replace"
        )
        stderr_text = stderr_text[: step.max_output_bytes]
        truncated = (
            len(result.stdout) > step.max_output_bytes
            or len(result.stderr) > step.max_output_bytes
        )
        return SandboxStepOutcome(
            exit_code=exit_code,
            stdout=stdout_text,
            stderr=stderr_text,
            timed_out=False,
            output_truncated=truncated,
        )

    # --- docker CLI plumbing -------------------------------------------

    def _run_cli(self, argv, timeout: float) -> _CliResult:
        if self._cli_runner is not None:
            return self._cli_runner(tuple(argv), timeout)
        return self._default_cli_runner(tuple(argv), timeout)

    def _destroy_container(self, container_name: str) -> None:
        """Unconditional best-effort cleanup on every exit path."""
        try:
            self._run_cli(("docker", "rm", "-f", container_name), 15.0)
        except (OSError, ValueError, ValidationSandboxConfigurationError):
            pass

    @classmethod
    def _default_cli_runner(cls, argv, timeout: float) -> _CliResult:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        }
        # Optional daemon location stays host-side (orchestration only);
        # it is never forwarded into the container itself.
        for key in ("DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
            if key in os.environ:
                env[key] = os.environ[key]

        try:
            process = subprocess.Popen(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                env=env,
                start_new_session=True,
            )
        except FileNotFoundError:
            raise
        except OSError:
            raise

        stdout_buffer = bytearray()
        stderr_buffer = bytearray()
        stdout_truncated = [False]
        stderr_truncated = [False]
        limit = 4 * 1024 * 1024

        readers = [
            threading.Thread(
                target=cls._drain,
                args=(process.stdout, stdout_buffer, stdout_truncated, limit),
                daemon=True,
            ),
            threading.Thread(
                target=cls._drain,
                args=(process.stderr, stderr_buffer, stderr_truncated, limit),
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
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()

        exit_code = process.returncode
        return _CliResult(
            exit_code if exit_code is not None else None,
            bytes(stdout_buffer),
            bytes(stderr_buffer),
            timed_out=timed_out,
        )

    @staticmethod
    def _kill(process: subprocess.Popen) -> None:
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
    def _drain(stream, buffer: bytearray, truncated: list[bool], limit: int) -> None:
        if stream is None:
            return
        while True:
            chunk = stream.read(8192)
            if not chunk:
                break
            remaining = limit - len(buffer)
            if remaining > 0:
                buffer.extend(chunk[:remaining])
            if len(chunk) > max(remaining, 0):
                truncated[0] = True
