"""Phase 6.2.2 — remediation validation sandbox policy (pure configuration).

Repository content (patched files, test/build scripts, project config,
filenames) is UNTRUSTED: it may influence its own test inputs only. It can
never redefine the executable, argv, resource limits, network mode, mounts,
environment, credentials, or any other property of the execution sandbox.
Those are host-owned policy, expressed here as pure, unit-testable
configuration builders. The real remediation workspace is bound
READ-ONLY at /workspace (the writable area is tmpfs /tmp only); the
host additionally verifies before/after target and Git-state integrity
around every sandboxed step.

Critical invariant: there is NO host/in-process fallback behind this
module. Every failure to build or run a sandboxed step is a typed,
fail-closed error handled by the execution classification that already
exists. Nothing in this module executes commands.
"""

from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Protocol, Sequence, runtime_checkable

# --- policy-owned resource bounds (single source of truth) -----------------

SANDBOX_MAX_RUNTIME_SECONDS = 180.0
SANDBOX_MAX_OUTPUT_BYTES = 128 * 1024
SANDBOX_WALL_GRACE_SECONDS = 10.0
SANDBOX_MEMORY_BYTES = 768 * 1024 * 1024
SANDBOX_CPUS = "2"
SANDBOX_PIDS_LIMIT = 256

SANDBOX_WORKSPACE_MOUNT = "/workspace"

# Network is disabled unless this policy module itself is changed — there
# is no per-request or repository-controlled network switch. A fixed
# validation profile that genuinely needs the network must be granted an
# exception here, explicitly and reviewably (validated + tested).
SANDBOX_ALLOWED_NETWORK_MODES = frozenset({"none"})

# Explicit environment ALLOWLIST: values are constants, never derived from
# the host process environment. Host secrets can only leak in if they are
# added to this mapping by a reviewed policy change.
SANDBOX_ENV_ALLOWLIST: Mapping[str, str] = MappingProxyType(
    {
        "PATH": "/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/tmp",
        "LANG": "C.UTF-8",
        "CI": "true",
        "GIT_TERMINAL_PROMPT": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
    }
)

_CONTAINER_NAME_PATTERN = r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$"
# Strongest verifiable image identity: content-addressed digest reference.
# Floating tags (":latest", bare tags) are rejected; the environment must
# be provisioned with a digest (resolved e.g. via `docker pull` +
# `docker image inspect --format '{{index .RepoDigests 0}}'`).
_IMAGE_DIGEST_PATTERN = r"^[^@\s]+@sha256:[0-9a-f]{64}$"


class SandboxPolicyViolation(ValueError):
    """A step/spec violates sandbox execution policy (fail closed)."""


@dataclass(frozen=True)
class SandboxStepSpec:
    """A single fixed validation step, as owned by host profile policy."""

    name: str
    argv: tuple[str, ...]
    working_directory: str  # workspace-relative (".", "dir", "a/b")
    timeout_seconds: float
    max_output_bytes: int


@dataclass(frozen=True)
class SandboxStepOutcome:
    """Bounded, untrusted result of one sandboxed step."""

    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    output_truncated: bool


@dataclass(frozen=True)
class SandboxRuntimeSpec:
    """Per-sandbox identity/isolation configuration.

    ``image`` must be a digest-pinned reference (``name@sha256:<64 hex>``).
    ``network_mode`` defaults to, and is only allowed to be, "none".
    """

    image: str
    user: str
    network_mode: str = "none"
    seccomp_profile: str | None = None


@dataclass(frozen=True)
class SandboxRunPlan:
    """Fully generated runtime configuration — the test surface for
    isolation properties (mounts, network, privileges, env, limits)."""

    container_name: str
    cli_argv: tuple[str, ...]
    env: Mapping[str, str]
    mounts: tuple[str, ...]  # exactly one bind, always ":ro" (workspace)
    working_directory: str  # container path
    wall_timeout_seconds: float


@runtime_checkable
class ValidationSandboxPort(Protocol):
    """The single execution seam for remediation validation workloads."""

    def execute(
        self, step: SandboxStepSpec, workspace_path: Path
    ) -> SandboxStepOutcome: ...


def validate_runtime_spec(spec: SandboxRuntimeSpec) -> None:
    """Reject any runtime configuration that weakens the sandbox."""
    import re

    image = (spec.image or "").strip()
    if not image:
        raise SandboxPolicyViolation(
            "sandbox image is not configured (digest-pinned image required)"
        )
    if ":latest" in image:
        raise SandboxPolicyViolation("floating image tags are forbidden")
    if not re.fullmatch(_IMAGE_DIGEST_PATTERN, image):
        raise SandboxPolicyViolation(
            "sandbox image must be pinned by digest (name@sha256:<hex>)"
        )

    if spec.network_mode not in SANDBOX_ALLOWED_NETWORK_MODES:
        raise SandboxPolicyViolation(
            "sandbox networking must be one of "
            f"{sorted(SANDBOX_ALLOWED_NETWORK_MODES)}; profile exceptions "
            "require an explicit policy change in validation_sandbox.py"
        )

    user = (spec.user or "").strip()
    uid_text = user.split(":", 1)[0]
    try:
        uid = int(uid_text)
    except ValueError as exc:
        raise SandboxPolicyViolation("sandbox user must be uid[:gid]") from exc
    if uid == 0:
        raise SandboxPolicyViolation("sandbox must run as a non-root user")

    if spec.seccomp_profile is not None:
        profile_path = str(spec.seccomp_profile)
        if not profile_path.endswith(".json"):
            raise SandboxPolicyViolation(
                "seccomp profile must be a JSON profile path"
            )
        if "unconfined" in profile_path:
            raise SandboxPolicyViolation("seccomp may never be unconfined")


def build_run_plan(
    *,
    spec: SandboxRuntimeSpec,
    step: SandboxStepSpec,
    workspace_path: Path,
    container_name: str,
) -> SandboxRunPlan:
    """Build the complete runtime plan for one sandboxed step.

    Pure: no filesystem access, no command execution. Raises
    SandboxPolicyViolation on anything that would exceed policy — defense
    in depth on top of profile construction (repository content and API
    request data never reach this function's inputs directly).
    """
    import re

    validate_runtime_spec(spec)

    if not isinstance(container_name, str) or not re.fullmatch(
        _CONTAINER_NAME_PATTERN, container_name
    ):
        raise SandboxPolicyViolation("invalid sandbox container name")

    if not step.argv or any(not isinstance(arg, str) for arg in step.argv):
        raise SandboxPolicyViolation("sandbox argv must be non-empty strings")
    if step.argv[0] != "python":
        raise SandboxPolicyViolation(
            "sandbox steps may only use the policy-owned python executable"
        )
    if not (0 < step.timeout_seconds <= SANDBOX_MAX_RUNTIME_SECONDS):
        raise SandboxPolicyViolation(
            f"sandbox step timeout must be in (0, {SANDBOX_MAX_RUNTIME_SECONDS}]"
        )
    if not (0 < step.max_output_bytes <= SANDBOX_MAX_OUTPUT_BYTES):
        raise SandboxPolicyViolation(
            "sandbox step output limit must be within policy bounds"
        )

    working_directory = str(step.working_directory or "").strip()
    if working_directory in {"", "."}:
        container_workdir = SANDBOX_WORKSPACE_MOUNT
    else:
        parts = working_directory.replace("\\", "/").split("/")
        if (
            working_directory.startswith("/")
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise SandboxPolicyViolation(
                "sandbox working directory must be a safe relative path"
            )
        container_workdir = (
            f"{SANDBOX_WORKSPACE_MOUNT}/{working_directory}"
        )

    workspace = Path(workspace_path)
    if not workspace.is_absolute():
        raise SandboxPolicyViolation(
            "sandbox workspace mount source must be an absolute path"
        )

    # Exactly one host bind: the ephemeral per-attempt workspace, and it
    # is READ-ONLY — the untrusted validation workload may observe the
    # real remediation Git workspace (including .git, which lives inside
    # the same mount) but can never write the working tree or Git
    # metadata through it. No host root, home, credential directories,
    # docker socket, /proc, /sys, or any other sensitive path is ever
    # mounted, and no separate Git-metadata mount exists.
    mounts = (f"{workspace}:{SANDBOX_WORKSPACE_MOUNT}:ro",)

    env = dict(SANDBOX_ENV_ALLOWLIST)

    cli_argv: list[str] = [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "--pull",
        "never",
        "--network",
        spec.network_mode,
        "--user",
        spec.user,
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=64m",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
    ]
    if spec.seccomp_profile is not None:
        cli_argv += ["--security-opt", f"seccomp={spec.seccomp_profile}"]
    cli_argv += [
        "--pids-limit",
        str(SANDBOX_PIDS_LIMIT),
        "--memory",
        str(SANDBOX_MEMORY_BYTES),
        "--cpus",
        SANDBOX_CPUS,
        "--hostname",
        container_name,
        "--label",
        "dev.arena.remediation-sandbox=1",
    ]
    for key, value in sorted(env.items()):
        cli_argv += ["-e", f"{key}={value}"]
    cli_argv += ["-v", mounts[0], "-w", container_workdir, spec.image]
    cli_argv += list(step.argv)

    return SandboxRunPlan(
        container_name=container_name,
        cli_argv=tuple(cli_argv),
        env=MappingProxyType(env),
        mounts=mounts,
        working_directory=container_workdir,
        wall_timeout_seconds=(
            float(step.timeout_seconds) + SANDBOX_WALL_GRACE_SECONDS
        ),
    )


def new_container_name(attempt_hint: str = "") -> str:
    """Unique, cross-attempt container identity (no trust reuse)."""
    import re
    import uuid

    hint = re.sub(r"[^a-zA-Z0-9_.-]", "", str(attempt_hint))[:16]
    suffix = uuid.uuid4().hex[:12]
    base = f"remed-sbx-{hint}" if hint else "remed-sbx"
    return f"{base}-{suffix}"[:128]


def is_safe_working_directory(relative: str) -> bool:
    """Shared relative-path policy for workspace-relative directories."""
    value = str(relative or "").replace("\\", "/").strip()
    if value in {"", "."}:
        return True
    if value.startswith("/"):
        return False
    return all(part not in {"", ".", ".."} for part in value.split("/"))
