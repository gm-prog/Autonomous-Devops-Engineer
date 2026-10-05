"""Explicit development / unit-test seam for validation execution.

Phase 6.2.2 critical invariant: production remediation execution has NO
host fallback. ``RemediationValidationRunner`` requires an explicitly
injected ``ValidationSandboxPort``; the production wiring in
``presentation.rest.controllers`` injects the container sandbox. This
module remains only so focused tests can exercise profile policy,
workspace-state checks and result mapping without a container runtime.
It executes on the host by construction — never wire it into a running
control plane.
"""

import os
import re
import signal
import subprocess
import threading
from pathlib import Path

from incident_service.application.services.remediation_validation_runner import (
    ValidationRunnerError,
)
from incident_service.application.services.validation_sandbox import (
    SANDBOX_MAX_RUNTIME_SECONDS,
    SandboxStepOutcome,
    SandboxStepSpec,
    is_safe_working_directory,
)

_SECRET_ENV_PATTERN = re.compile(
    r"(TOKEN|PASSWORD|SECRET|PRIVATE_KEY|API_KEY|CREDENTIAL)",
    re.IGNORECASE,
)


class LocalProcessValidationExecutor:
    """In-process (host) execution of fixed validation steps.

    Development/unit-test only. Inherits the same policy bounds as the
    sandbox path: policy-owned python executable, shell=False, bounded
    output, wall-clock timeout, resource rlimits, secret-filtered env.
    """

    explicit_host_seam = True

    def execute(
        self, step: SandboxStepSpec, workspace_path: Path
    ) -> SandboxStepOutcome:
        if not self.explicit_host_seam:
            raise ValidationRunnerError("host execution seam was not armed")
        if not is_safe_working_directory(step.working_directory):
            raise ValidationRunnerError(
                "validation working directory must be a safe workspace-relative path"
            )

        root = Path(workspace_path).resolve()
        relative = Path(step.working_directory or ".")
        cwd = (root / relative).resolve()
        try:
            cwd.relative_to(root)
        except ValueError as exc:
            raise ValidationRunnerError(
                "validation working directory escaped the remediation workspace"
            ) from exc
        if not cwd.is_dir():
            raise ValidationRunnerError(
                "validation working directory does not exist: "
                f"{step.working_directory}"
            )

        try:
            process = subprocess.Popen(
                list(step.argv),
                cwd=str(cwd),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                env=self._sanitized_environment(),
                start_new_session=True,
                preexec_fn=self._resource_limiter,
            )
        except OSError as exc:
            raise ValidationRunnerError(
                f"could not start validation step {step.name}"
            ) from exc

        stdout_buffer = bytearray()
        stderr_buffer = bytearray()
        stdout_truncated = [False]
        stderr_truncated = [False]

        readers = [
            threading.Thread(
                target=self._drain_stream,
                args=(
                    process.stdout,
                    stdout_buffer,
                    stdout_truncated,
                    step.max_output_bytes,
                ),
                daemon=True,
            ),
            threading.Thread(
                target=self._drain_stream,
                args=(
                    process.stderr,
                    stderr_buffer,
                    stderr_truncated,
                    step.max_output_bytes,
                ),
                daemon=True,
            ),
        ]
        for reader in readers:
            reader.start()

        timed_out = False
        try:
            process.wait(timeout=step.timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._terminate_process_group(process)

        for reader in readers:
            reader.join(timeout=2.0)

        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()

        exit_code = (
            process.returncode
            if process.returncode is not None
            else -signal.SIGKILL
        )
        return SandboxStepOutcome(
            exit_code=exit_code,
            stdout=bytes(stdout_buffer).decode("utf-8", errors="replace"),
            stderr=bytes(stderr_buffer).decode("utf-8", errors="replace"),
            timed_out=timed_out,
            output_truncated=stdout_truncated[0] or stderr_truncated[0],
        )

    @staticmethod
    def _sanitized_environment() -> dict[str, str]:
        """Legacy denylist sanitization for the test seam (host git/python).

        The production container sandbox does NOT use this: it builds its
        environment solely from SANDBOX_ENV_ALLOWLIST constants.
        """
        sanitized: dict[str, str] = {}
        for key, value in os.environ.items():
            if _SECRET_ENV_PATTERN.search(key):
                continue
            if key in {
                "GIT_SSH_COMMAND",
                "GIT_CONFIG_GLOBAL",
                "GIT_CONFIG_SYSTEM",
                "GIT_ASKPASS",
                "SSH_AUTH_SOCK",
                "PYTHONPATH",
                "VIRTUAL_ENV",
            }:
                continue
            sanitized[key] = value
        sanitized.update(
            {
                "CI": "true",
                "GIT_TERMINAL_PROMPT": "0",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            }
        )
        return sanitized

    @staticmethod
    def _resource_limiter() -> None:
        try:
            import resource

            cpu_seconds = max(int(SANDBOX_MAX_RUNTIME_SECONDS) - 60, 30)
            resource.setrlimit(
                resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1)
            )
            resource.setrlimit(
                resource.RLIMIT_AS,
                (768 * 1024 * 1024, 768 * 1024 * 1024),
            )
            resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        except (ImportError, OSError, ValueError):
            pass

    @staticmethod
    def _terminate_process_group(process: subprocess.Popen) -> None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
        finally:
            if process.poll() is None:
                process.kill()

    @staticmethod
    def _drain_stream(
        stream, buffer: bytearray, truncated: list[bool], limit: int
    ) -> None:
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
