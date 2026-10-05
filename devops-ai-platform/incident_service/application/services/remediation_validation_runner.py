"""Bounded remediation validation behind an explicit sandbox boundary.

Phase 6.2.2: profile policy, workspace-state checks and result mapping
stay host-owned; the actual workload execution is delegated to an
explicitly injected ``ValidationSandboxPort``. Production wiring uses the
container sandbox (``infrastructure.sandbox.container_validation_sandbox``);
there is deliberately NO default sandbox and NO host-execution fallback —
``sandbox`` is a required constructor argument and every sandbox failure
is typed and fail-closed.
"""

import hashlib
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Mapping, Sequence

from incident_service.application.services.remediation_workspace_service import (
    RemediationWorkspace,
)
from incident_service.application.services.validation_sandbox import (
    SANDBOX_MAX_OUTPUT_BYTES,
    SANDBOX_MAX_RUNTIME_SECONDS,
    SandboxStepSpec,
    is_safe_working_directory,
)

if TYPE_CHECKING:
    from incident_service.application.services.validation_sandbox import (
        ValidationSandboxPort,
    )

logger = __import__("logging").getLogger("RemediationValidationRunner")

# Single source of truth lives in validation_sandbox policy module.
MAX_RUNTIME_SECONDS = SANDBOX_MAX_RUNTIME_SECONDS
MAX_OUTPUT_BYTES = SANDBOX_MAX_OUTPUT_BYTES

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


class ValidationSandboxUnavailableError(ValidationRunnerError):
    """The sandbox runtime could not be reached; workload never ran."""


class ValidationSandboxConfigurationError(ValidationRunnerError):
    """Sandbox runtime configuration violated policy; workload never ran."""


class ValidationSandboxResultError(ValidationRunnerError):
    """Sandbox result could not be trusted; treated as a failure."""


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


_DEFAULT_PROFILES: Mapping[str, tuple[ValidationStep, ...]] = {
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
                "incident_service.presentation.rest.test_remediation_authorization",
                "incident_service.application.services.test_proposal_approval_service",
                "incident_service.application.services.test_proposal_execution_service",
                "incident_service.presentation.rest.test_proposal_execution_endpoints",
            ),
            timeout_seconds=MAX_RUNTIME_SECONDS,
            max_output_bytes=MAX_OUTPUT_BYTES,
        ),
    ),
}


class RemediationValidationRunner:
    """Runs only fixed platform validation profiles inside a sandbox.

    The runner never executes the workload itself: every step is handed
    to the injected ``ValidationSandboxPort``. There is no fallback —
    construction without a sandbox raises, and sandbox failures surface
    as typed ``ValidationSandbox*`` errors instead of host execution.
    """

    def __init__(
        self,
        *,
        sandbox: "ValidationSandboxPort",
        profiles: Mapping[str, Sequence[ValidationStep]] | None = None,
    ):
        if sandbox is None:
            raise ValueError(
                "validation sandbox is required; host execution fallback is "
                "forbidden (Phase 6.2.2)"
            )
        if not hasattr(sandbox, "execute") or not callable(
            getattr(sandbox, "execute")
        ):
            raise ValueError(
                "validation sandbox must provide execute(step, workspace_path)"
            )
        self._sandbox = sandbox

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

    @property
    def sandbox(self) -> "ValidationSandboxPort":
        """The injected execution boundary (never the host implicitly)."""
        return self._sandbox

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
            # Defense in depth (6.2.2 corrective pass): capture the
            # approved target's exact bytes and the Git state around
            # THIS sandbox execution, and require byte-for-byte
            # equality afterwards — a zero exit code alone never
            # authorizes a changed workspace. The comparison is
            # before-sandbox == after-sandbox (the target already
            # contains the approved remediation patch at this point).
            integrity_before = self._integrity_snapshot(workspace, target)
            result = self._run_step(workspace, step)
            integrity_after = self._integrity_snapshot(workspace, target)
            if integrity_after != integrity_before:
                raise ValidationWorkspaceMutationError(
                    "sandbox validation modified the approved target or "
                    "Git state around the validation step"
                )
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

    def _integrity_snapshot(
        self,
        workspace: RemediationWorkspace,
        target: str,
    ) -> dict:
        """Deterministic integrity snapshot taken immediately before and
        after each sandboxed step.

        Captures: the approved target's SHA-256 over its exact bytes,
        HEAD, the target's staged and working-tree diff state, and the
        digests of .git/HEAD, .git/index and .git/config. Any difference
        between the before/after snapshots fails validation closed.
        All Git reads use --no-optional-locks so the snapshot itself
        never rewrites .git/index (self-observation must be stable).
        """
        root = Path(workspace.path).resolve()
        target_path = (root / target).resolve()
        try:
            target_path.relative_to(root)
        except ValueError as exc:
            raise ValidationRunnerError(
                "approved target escaped the remediation workspace"
            ) from exc
        if not target_path.is_file():
            raise ValidationRunnerError(
                "approved target is missing around sandbox execution"
            )

        snapshot = {
            "target_sha256": hashlib.sha256(
                target_path.read_bytes()
            ).hexdigest(),
        }
        try:
            snapshot["head"] = self._run_fixed_git(
                ["git", "rev-parse", "HEAD"], root, read_only=True
            ).stdout.strip()
            snapshot["target_staged"] = self._run_fixed_git(
                ["git", "diff", "--cached", "--binary", "--", target],
                root,
                read_only=True,
            ).stdout
            snapshot["target_worktree"] = self._run_fixed_git(
                ["git", "diff", "--binary", "--", target],
                root,
                read_only=True,
            ).stdout
        except subprocess.CalledProcessError as exc:
            raise ValidationRunnerError(
                "could not capture Git integrity state around sandbox execution"
            ) from exc

        for name, key in (
            ("HEAD", "git_head"),
            ("index", "git_index"),
            ("config", "git_config"),
        ):
            snapshot[key] = self._file_digest(self._git_metadata_path(root, name))
        return snapshot

    @staticmethod
    def _git_metadata_path(root: Path, name: str) -> Path | None:
        git_dir = root / ".git"
        if git_dir.is_dir():
            candidate = git_dir / name
            return candidate if candidate.is_file() else None
        if git_dir.is_file():
            # gitfile pointer ("gitdir: <path>") — resolve the real dir
            pointer = git_dir.read_text(encoding="utf-8", errors="replace")
            if pointer.startswith("gitdir:"):
                real = Path(pointer.split(":", 1)[1].strip())
                if not real.is_absolute():
                    real = (root / real).resolve()
                candidate = real / name
                return candidate if candidate.is_file() else None
        return None

    @staticmethod
    def _file_digest(path: Path | None):
        if path is None or not path.is_file():
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()

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

        # read-only observation: --no-optional-locks so the CHECK itself
        # never writes .git/index (validation must be observationally
        # side-effect-free on Git metadata)
        status = self._run_fixed_git(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            workspace_path,
            read_only=True,
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
        # Host-side safety validation happens BEFORE any sandbox launch.
        relative = self._safe_working_directory(workspace, step)
        workspace_path = Path(workspace.path).resolve()

        spec = SandboxStepSpec(
            name=step.name,
            argv=tuple(step.argv),
            working_directory=relative,
            timeout_seconds=float(step.timeout_seconds),
            max_output_bytes=int(step.max_output_bytes),
        )
        outcome = self._sandbox.execute(spec, workspace_path)

        passed = (
            not outcome.timed_out
            and outcome.exit_code == 0
            and not outcome.output_truncated
        )

        stderr = outcome.stderr
        if outcome.output_truncated:
            stderr = (
                f"{stderr}\n[validation rejected: output exceeded "
                f"{step.max_output_bytes} bytes]"
            )
        if outcome.timed_out:
            stderr = (
                f"{stderr}\n[validation rejected: step exceeded "
                f"{step.timeout_seconds:.1f}s timeout]"
            )

        return ValidationStepResult(
            name=step.name,
            passed=passed,
            exit_code=outcome.exit_code,
            stdout=outcome.stdout,
            stderr=stderr,
            timed_out=outcome.timed_out,
            output_truncated=outcome.output_truncated,
        )

    @classmethod
    def _safe_working_directory(
        cls,
        workspace: RemediationWorkspace,
        step: ValidationStep,
    ) -> str:
        relative = str(step.working_directory).replace("\\", "/").strip()
        if not is_safe_working_directory(relative):
            raise ValidationRunnerError(
                "validation working directory must be a safe workspace-relative path"
            )

        root = Path(workspace.path).resolve()
        resolved = (root / (relative or ".")).resolve()

        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise ValidationRunnerError(
                "validation working directory escaped the remediation workspace"
            ) from exc

        if not resolved.is_dir():
            raise ValidationRunnerError(
                f"validation working directory does not exist: {step.working_directory}"
            )
        return relative if relative else "."

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
    def _run_fixed_git(
        args: list[str],
        cwd: Path,
        *,
        read_only: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        command = list(args)
        if read_only and command and command[0] == "git":
            # never refresh/write the index while observing it
            command = [command[0], "--no-optional-locks", *command[1:]]
        return subprocess.run(
            command,
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=True,
            shell=False,
            env=RemediationValidationRunner._sanitized_environment(),
            timeout=10,
        )

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
            if (
                step.max_output_bytes <= 0
                or step.max_output_bytes > MAX_OUTPUT_BYTES
            ):
                raise ValueError(
                    "validation output limit must be in "
                    f"(0, {MAX_OUTPUT_BYTES}]"
                )
