import logging
import os
import re
import signal
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Mapping, Sequence

from incident_service.application.services.remediation_patch_executor import (
    PatchPostconditionError,
)
from incident_service.application.services.remediation_workspace_service import RemediationWorkspace

logger = logging.getLogger("RemediationValidationRunner")

MAX_RUNTIME_SECONDS = 180.0
MAX_OUTPUT_BYTES = 128 * 1024
MAX_CPU_SECONDS = 120
MAX_ADDRESS_SPACE_BYTES = 768 * 1024 * 1024
MAX_OPEN_FILES = 256

_SECRET_ENV_PATTERN = re.compile(
    r"(TOKEN|PASSWORD|SECRET|PRIVATE_KEY|API_KEY|CREDENTIAL)",
    re.IGNORECASE,
)


class ValidationRunnerError(RuntimeError):
    """Base error for bounded remediation validation."""


class UnknownValidationProfileError(ValidationRunnerError):
    """The requested profile is not owned by the validation policy."""


class ValidationWorkspaceMutationError(ValidationRunnerError):
    """Validation changed files outside the expected remediation target."""


@dataclass(frozen=True)
class ValidationStep:
    """A platform-owned, fixed validation command."""

    name: str
    working_directory: str
    argv: tuple[str, ...]
    timeout_seconds: float = MAX_RUNTIME_SECONDS
    max_output_bytes: int = MAX_OUTPUT_BYTES


@dataclass(frozen=True)
class ValidationStepResult:
    name: str
    passed: bool
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    output_truncated: bool


@dataclass(frozen=True)
class RemediationValidationResult:
    profile: str
    passed: bool
    steps: tuple[ValidationStepResult, ...]
    source_sha: str
    target_filepath: str


_DEFAULT_PROFILES: Dict[str, tuple[ValidationStep, ...]] = {
    "incident_service": (
        ValidationStep(
            name="incident-service-unit-tests",
            # Arena package layout: run from the platform root so every module
            # imports as `incident_service.*` (the old hyphenated flat-layout
            # working directory no longer exists).
            working_directory="devops-ai-platform",
            argv=(
                "python",
                "-m",
                "unittest",
                "incident_service.infrastructure.database.test_postgres_incident_repo",
                "incident_service.application.event_handlers.test_on_metric_threshold_failed",
                "incident_service.application.commands.test_attach_deployment_evidence",
                "incident_service.infrastructure.deployment.test_deployment_evidence_collector",
                "incident_service.application.services.test_rca_evidence_pack",
                "incident_service.presentation.rest.test_rca_orchestration",
                "incident_service.application.commands.test_apply_automated_fix",
                "incident_service.infrastructure.source_provider.test_github_pr_client",
                "incident_service.application.services.test_remediation_workspace_service",
                "incident_service.application.services.test_remediation_workspace_push",
                "incident_service.application.services.test_remediation_patch_executor",
                "incident_service.application.services.test_remediation_validation_runner",
                "incident_service.application.services.test_remediation_commit_service",
                "incident_service.application.services.test_remediation_orchestration_service",
                "incident_service.infrastructure.messaging.test_redis_incident_consumer",
            ),
            timeout_seconds=MAX_RUNTIME_SECONDS,
            max_output_bytes=MAX_OUTPUT_BYTES,
        ),
    ),
}


class RemediationValidationRunner:
    """Runs only fixed platform validation profiles inside an isolated workspace."""

    def __init__(
        self,
        profiles: Mapping[str, Sequence[ValidationStep]] | None = None,
    ):
        selected = profiles or _DEFAULT_PROFILES
        if not selected:
            raise ValueError("at least one validation profile is required")

        self._profiles = {
            name: tuple(steps)
            for name, steps in selected.items()
        }

        for profile_name, steps in self._profiles.items():
            if not profile_name or not steps:
                raise ValueError("validation profiles must have non-empty names and steps")
            self._validate_steps(steps)

    def validate(
        self,
        workspace: RemediationWorkspace,
        profile: str,
        target_filepath: str,
    ) -> RemediationValidationResult:
        steps = self._profiles.get(profile)
        if steps is None:
            raise UnknownValidationProfileError(
                f"validation profile is not allowlisted: {profile}"
            )

        target = self._normalize_target(target_filepath)
        self._assert_expected_workspace_state(workspace, target)

        results = []
        for step in steps:
            result = self._run_step(workspace, step)
            results.append(result)

            if not result.passed:
                return RemediationValidationResult(
                    profile=profile,
                    passed=False,
                    steps=tuple(results),
                    source_sha=workspace.source_sha,
                    target_filepath=target,
                )

            self._assert_expected_workspace_state(workspace, target)

        return RemediationValidationResult(
            profile=profile,
            passed=True,
            steps=tuple(results),
            source_sha=workspace.source_sha,
            target_filepath=target,
        )

    @staticmethod
    def _normalize_target(target_filepath: str) -> str:
        target = target_filepath.replace("\\", "/").strip()
        if not target or target.startswith("/"):
            raise ValidationRunnerError("validation target filepath is unsafe")
        if any(part in {"", ".", ".."} for part in target.split("/")):
            raise ValidationRunnerError(
                "validation target filepath contains unsafe path segments"
            )
        return target

    def _assert_expected_workspace_state(
        self,
        workspace: RemediationWorkspace,
        target: str,
    ) -> None:
        workspace_path = Path(workspace.path).resolve()
        if not workspace_path.is_dir():
            raise ValidationRunnerError("validation workspace does not exist")

        status = self._run_fixed_git(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            workspace_path,
        )
        entries = [line for line in status.stdout.splitlines() if line.strip()]

        if len(entries) != 1:
            raise ValidationWorkspaceMutationError(
                "validation workspace must contain exactly the expected remediation change"
            )

        entry = entries[0]
        if len(entry) < 4 or entry[:2] != " M" or entry[3:] != target:
            raise ValidationWorkspaceMutationError(
                "validation changed an unexpected path or file state"
            )

    def _run_step(
        self,
        workspace: RemediationWorkspace,
        step: ValidationStep,
    ) -> ValidationStepResult:
        cwd = self._resolve_working_directory(workspace, step.working_directory)

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
                args=(process.stdout, stdout_buffer, stdout_truncated, step.max_output_bytes),
                daemon=True,
            ),
            threading.Thread(
                target=self._drain_stream,
                args=(process.stderr, stderr_buffer, stderr_truncated, step.max_output_bytes),
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

        exit_code = process.returncode if process.returncode is not None else -signal.SIGKILL
        output_truncated = stdout_truncated[0] or stderr_truncated[0]

        stdout = bytes(stdout_buffer).decode("utf-8", errors="replace")
        stderr = bytes(stderr_buffer).decode("utf-8", errors="replace")

        passed = (
            not timed_out
            and exit_code == 0
            and not output_truncated
        )

        if output_truncated:
            stderr = (
                f"{stderr}\n[validation rejected: output exceeded "
                f"{step.max_output_bytes} bytes]"
            )

        if timed_out:
            stderr = (
                f"{stderr}\n[validation rejected: step exceeded "
                f"{step.timeout_seconds:.1f}s timeout]"
            )

        return ValidationStepResult(
            name=step.name,
            passed=passed,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            output_truncated=output_truncated,
        )

    @staticmethod
    def _resolve_working_directory(
        workspace: RemediationWorkspace,
        relative_directory: str,
    ) -> Path:
        relative = Path(relative_directory)
        if relative.is_absolute() or any(
            part in {"", ".", ".."} for part in relative.parts
        ):
            raise ValidationRunnerError(
                "validation working directory must be a safe workspace-relative path"
            )

        root = Path(workspace.path).resolve()
        resolved = (root / relative).resolve()

        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise ValidationRunnerError(
                "validation working directory escaped the remediation workspace"
            ) from exc

        if not resolved.is_dir():
            raise ValidationRunnerError(
                f"validation working directory does not exist: {relative_directory}"
            )
        return resolved

    @staticmethod
    def _sanitized_environment() -> dict[str, str]:
        sanitized = {}
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

            resource.setrlimit(
                resource.RLIMIT_CPU,
                (MAX_CPU_SECONDS, MAX_CPU_SECONDS + 1),
            )
            resource.setrlimit(
                resource.RLIMIT_AS,
                (MAX_ADDRESS_SPACE_BYTES, MAX_ADDRESS_SPACE_BYTES),
            )
            resource.setrlimit(
                resource.RLIMIT_NOFILE,
                (MAX_OPEN_FILES, MAX_OPEN_FILES),
            )
        except (ImportError, OSError, ValueError):
            logger.warning("OS resource limits are unavailable on this platform")

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
        stream: Iterable[bytes] | None,
        buffer: bytearray,
        truncated: list[bool],
        limit: int,
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

    @staticmethod
    def _validate_steps(steps: Sequence[ValidationStep]) -> None:
        for step in steps:
            if not step.name.strip():
                raise ValueError("validation step name must not be empty")
            if not step.argv or step.argv[0] != "python":
                raise ValueError(
                    "validation steps may only use the policy-owned Python executable"
                )
            if step.timeout_seconds <= 0 or step.timeout_seconds > MAX_RUNTIME_SECONDS:
                raise ValueError(
                    f"validation step timeout must be in (0, {MAX_RUNTIME_SECONDS}]"
                )
            if step.max_output_bytes <= 0 or step.max_output_bytes > MAX_OUTPUT_BYTES:
                raise ValueError(
                    f"validation output limit must be in (0, {MAX_OUTPUT_BYTES}]"
                )

    @staticmethod
    def _run_fixed_git(
        args: list[str],
        cwd: Path,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            args,
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=True,
            shell=False,
            env=RemediationValidationRunner._sanitized_environment(),
            timeout=10,
        )
