"""Phase 8.5-A — Terraform execution trust boundary (pure policy).

Terraform supplied to the deployment service is UNTRUSTED EXECUTABLE
INPUT. Terraform is plugin-based: providers and provisioners are
executable programs that Terraform discovers and runs during ``init`` and
``plan``, so static text validation (``local-exec`` / ``remote-exec`` /
``external`` rejection in ``IaCValidator``) is early rejection only — it
is NOT the execution boundary. The execution boundary is this policy plus
the sandbox runtime that enforces it.

Untrusted content may influence the Terraform configuration it is planning
and nothing else. It can never choose the image, UID/GID, network mode,
mounts, capabilities, runtime flags, resource limits, environment,
credentials, executable or argv. Those are host-owned decisions, expressed
here as pure, unit-testable configuration builders. Nothing in this module
executes anything.

Deliberate differences from the remediation validation sandbox
(``incident_service``), which this is modelled on but does not import —
bounded contexts stay decoupled:

* the workspace bind is READ-WRITE, because ``terraform init`` writes
  ``.terraform/`` and ``terraform plan -out`` writes the saved plan. It is
  an ephemeral, host-created directory holding content the caller already
  supplied, so write access grants the workload nothing it did not bring.
* argv[0] is the policy-owned ``terraform`` binary, never ``python``.

Critical invariant: there is NO host fallback behind this module. Every
failure to build or run a sandboxed operation is a typed, fail-closed
error. "Sandbox unavailable" never means "run Terraform on the host".
"""

import hashlib
import json
import os
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Protocol, runtime_checkable

# --- policy identity -------------------------------------------------------

# Bump when the security posture changes materially. The full identity is
# a deterministic fingerprint (see ``sandbox_policy_identity``) so that the
# same artifact planned under a different trust boundary cannot silently
# reuse an earlier approval identity.
TERRAFORM_SANDBOX_POLICY_VERSION = "terraform-sandbox-v1"

# --- policy-owned resource bounds (single source of truth) -----------------

SANDBOX_MAX_RUNTIME_SECONDS = 600.0
SANDBOX_MAX_OUTPUT_BYTES = 128 * 1024
SANDBOX_WALL_GRACE_SECONDS = 10.0
SANDBOX_MEMORY_BYTES = 1024 * 1024 * 1024
SANDBOX_CPUS = "2"
SANDBOX_PIDS_LIMIT = 256
SANDBOX_TMPFS_SIZE = "64m"

SANDBOX_WORKSPACE_MOUNT = "/workspace"

# Network is disabled unless this policy module itself is changed. There is
# deliberately no per-request, per-repository or environment-variable
# network switch: untrusted Terraform must not be able to turn networking
# on, and neither must an API caller. A future provider-distribution
# profile needs an explicit, reviewed policy change here.
SANDBOX_ALLOWED_NETWORK_MODES = frozenset({"none"})

# Explicit environment ALLOWLIST with CONSTANT values — never derived from
# the host process environment. Host secrets (JWT secret, database and
# Redis URLs, GitHub tokens, docker config) cannot leak in unless a
# reviewed policy change adds them here.
SANDBOX_ENV_ALLOWLIST: Mapping[str, str] = MappingProxyType(
    {
        "PATH": "/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/tmp",
        "TMPDIR": "/tmp",
        "LANG": "C.UTF-8",
        "TF_IN_AUTOMATION": "1",
        "TF_INPUT": "0",
        "TF_CLI_ARGS": "-no-color",
        "CHECKPOINT_DISABLE": "1",
        "AWS_EC2_METADATA_DISABLED": "true",
    }
)

# Credential NAMES that execution profiles may forward. Values are never
# placed in argv: the adapter passes ``-e NAME`` (name only) and supplies
# the value through the docker CLI process environment.
SANDBOX_CREDENTIAL_ENV_KEYS_VAR = "DEPLOYMENT_CREDENTIAL_ENV_KEYS"
_CREDENTIAL_NAME_PATTERN = r"^[A-Z][A-Z0-9_]{0,63}$"
# Never forwardable, even if someone lists them in the allowlist variable.
SANDBOX_FORBIDDEN_ENV_KEYS = frozenset(
    {
        "PATH", "HOME", "TMPDIR", "LD_PRELOAD", "LD_LIBRARY_PATH",
        "JWT_SECRET", "E2E_JWT_SECRET", "DATABASE_URL", "REDIS_URL",
        "GITHUB_TOKEN", "GITHUB_OAUTH_TOKEN", "E2E_FIXTURE_GITHUB_TOKEN",
        "DOCKER_HOST", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY",
        "DOCKER_CONFIG", "SSH_AUTH_SOCK",
    }
)

_CONTAINER_NAME_PATTERN = r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$"
# Strongest verifiable image identity: content-addressed digest reference.
_IMAGE_DIGEST_PATTERN = r"^[^@\s]+@sha256:[0-9a-f]{64}$"
# Saved plan / workspace-relative file names assembled by trusted code.
_RELATIVE_FILE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"

SANDBOX_IMAGE_VAR = "DEPLOYMENT_TERRAFORM_SANDBOX_IMAGE"
SANDBOX_UID_VAR = "DEPLOYMENT_TERRAFORM_SANDBOX_UID"
SANDBOX_GID_VAR = "DEPLOYMENT_TERRAFORM_SANDBOX_GID"

#: Phase 8.5-A corrective, Workstream C. The sandbox must run as a real
#: non-root identity AND must be able to write the workspace the control
#: plane created for it. Those two requirements meet here, in ONE place,
#: so the runtime user and the workspace owner can never drift apart.
#:
#: Distroless-style "nonroot" UID. Only used when the control plane is
#: root and therefore able to hand ownership over deliberately.
DEFAULT_SANDBOX_UID = 65532
DEFAULT_SANDBOX_GID = 65532
SANDBOX_WORKSPACE_ROOT_VAR = "DEPLOYMENT_WORKSPACE_ROOT"


# --- typed, fail-closed errors --------------------------------------------


class TerraformSandboxError(Exception):
    """Base class: every one of these means Terraform did NOT run."""

    code = "SANDBOX_EXECUTION_FAILED"


class TerraformSandboxPolicyViolation(TerraformSandboxError, ValueError):
    """A spec/step/request would weaken the sandbox (fail closed)."""

    code = "SANDBOX_POLICY_VIOLATION"


class TerraformSandboxConfigurationError(TerraformSandboxError, ValueError):
    """The sandbox is misconfigured (missing/floating image, bad root)."""

    code = "SANDBOX_CONFIGURATION_ERROR"


class TerraformSandboxUnavailableError(TerraformSandboxError):
    """The sandbox runtime cannot be reached. NEVER a host fallback."""

    code = "SANDBOX_UNAVAILABLE"


class TerraformSandboxResultError(TerraformSandboxError):
    """The sandbox returned something malformed; refuse to interpret it."""

    code = "SANDBOX_RESULT_INVALID"


# --- operations: fixed, policy-owned command templates --------------------


class TerraformOperation(str, Enum):
    """The complete set of Terraform operations this boundary permits.

    There is no generic "run this command" operation, and no shell: a free
    string can never become argv.
    """

    FORMAT = "FORMAT"
    INIT = "INIT"
    VALIDATE = "VALIDATE"
    PLAN = "PLAN"
    APPLY = "APPLY"


TERRAFORM_BINARY = "terraform"

# Per-operation wall-clock budgets (seconds), host-owned.
OPERATION_TIMEOUTS: Mapping[TerraformOperation, float] = MappingProxyType(
    {
        TerraformOperation.FORMAT: 60.0,
        TerraformOperation.INIT: 180.0,
        TerraformOperation.VALIDATE: 120.0,
        TerraformOperation.PLAN: 240.0,
        TerraformOperation.APPLY: 600.0,
    }
)


def build_terraform_argv(
    operation: TerraformOperation,
    *,
    execution: bool = False,
    plan_file: str | None = None,
) -> tuple[str, ...]:
    """Assemble the exact argv for one allowed operation.

    This is the ONLY place a Terraform command line is constructed. The
    caller chooses an operation from a closed enum and, at most, a
    workspace-relative plan file name validated against a strict pattern —
    never a path, never a flag, never a free string.
    """
    if not isinstance(operation, TerraformOperation):
        raise TerraformSandboxPolicyViolation(
            "terraform operation must be a TerraformOperation member"
        )

    relative_plan: str | None = None
    if plan_file is not None:
        relative_plan = str(plan_file)
        if not re.fullmatch(_RELATIVE_FILE_PATTERN, relative_plan):
            raise TerraformSandboxPolicyViolation(
                "saved plan file must be a simple workspace-relative name"
            )

    if operation is TerraformOperation.FORMAT:
        return (TERRAFORM_BINARY, "fmt", "-check", "-diff")

    if operation is TerraformOperation.INIT:
        argv = [TERRAFORM_BINARY, "init", "-input=false", "-no-color"]
        if not execution:
            argv.insert(2, "-backend=false")
        return tuple(argv)

    if operation is TerraformOperation.VALIDATE:
        return (TERRAFORM_BINARY, "validate", "-no-color")

    if operation is TerraformOperation.PLAN:
        argv = [
            TERRAFORM_BINARY,
            "plan",
            "-input=false",
            "-lock=true" if execution else "-lock=false",
            "-no-color",
        ]
        if not execution:
            argv.insert(2, "-refresh=false")
        if relative_plan is not None:
            argv.extend(["-out", relative_plan])
        return tuple(argv)

    # APPLY: only ever the exact saved plan, never a re-planned apply.
    if relative_plan is None:
        raise TerraformSandboxPolicyViolation(
            "terraform apply requires the exact saved plan file"
        )
    return (
        TERRAFORM_BINARY,
        "apply",
        "-input=false",
        "-no-color",
        relative_plan,
    )


# --- value objects ---------------------------------------------------------


@dataclass(frozen=True)
class TerraformSandboxStep:
    """One fixed Terraform operation, as owned by host policy."""

    operation: TerraformOperation
    argv: tuple[str, ...]
    timeout_seconds: float
    max_output_bytes: int = SANDBOX_MAX_OUTPUT_BYTES
    credential_env_keys: tuple[str, ...] = ()


@dataclass(frozen=True)
class TerraformSandboxOutcome:
    """Bounded, untrusted result of one sandboxed operation."""

    operation: TerraformOperation
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    output_truncated: bool


@dataclass(frozen=True)
class TerraformSandboxSpec:
    """Per-sandbox identity/isolation configuration (host-owned)."""

    image: str
    user: str
    network_mode: str = "none"
    terraform_version: str = ""


@dataclass(frozen=True)
class TerraformSandboxRunPlan:
    """Fully generated runtime configuration.

    This is the unit-test surface for every isolation property: mounts,
    network, privileges, limits and environment are all assertable without
    a container runtime.
    """

    container_name: str
    cli_argv: tuple[str, ...]
    env: Mapping[str, str]
    credential_env_keys: tuple[str, ...]
    mounts: tuple[str, ...]
    working_directory: str
    wall_timeout_seconds: float
    policy_identity: str


@runtime_checkable
class TerraformSandboxPort(Protocol):
    """The single execution seam for Terraform workloads."""

    def execute(
        self, step: TerraformSandboxStep, workspace_path: Path
    ) -> TerraformSandboxOutcome: ...

    def describe(self) -> Mapping[str, str]: ...


# --- validation ------------------------------------------------------------


def validate_runtime_spec(spec: TerraformSandboxSpec) -> None:
    """Reject any runtime configuration that weakens the sandbox."""
    image = (spec.image or "").strip()
    if not image:
        raise TerraformSandboxConfigurationError(
            f"terraform sandbox image is not configured ({SANDBOX_IMAGE_VAR}); "
            "a digest-pinned image is required"
        )
    if ":latest" in image:
        raise TerraformSandboxConfigurationError(
            "floating image tags are forbidden for the terraform sandbox"
        )
    if not re.fullmatch(_IMAGE_DIGEST_PATTERN, image):
        raise TerraformSandboxConfigurationError(
            "terraform sandbox image must be pinned by digest "
            "(name@sha256:<64 hex>)"
        )

    if spec.network_mode not in SANDBOX_ALLOWED_NETWORK_MODES:
        raise TerraformSandboxPolicyViolation(
            "terraform sandbox networking must be one of "
            f"{sorted(SANDBOX_ALLOWED_NETWORK_MODES)}; enabling the network "
            "requires an explicit policy change in terraform_sandbox.py"
        )

    user = (spec.user or "").strip()
    uid_text = user.split(":", 1)[0]
    try:
        uid = int(uid_text)
    except ValueError as exc:
        raise TerraformSandboxPolicyViolation(
            "terraform sandbox user must be uid[:gid]"
        ) from exc
    if uid == 0:
        raise TerraformSandboxPolicyViolation(
            "terraform sandbox must run as a non-root user"
        )


def resolve_credential_env_keys() -> tuple[str, ...]:
    """Credential NAMES an execution profile may forward into the sandbox.

    Names come from host configuration, never from an API request or from
    Terraform content. Anything malformed or on the forbidden list is
    dropped rather than forwarded.
    """
    raw = os.environ.get(SANDBOX_CREDENTIAL_ENV_KEYS_VAR, "")
    keys = []
    for name in raw.split(","):
        candidate = name.strip()
        if not candidate:
            continue
        if not re.fullmatch(_CREDENTIAL_NAME_PATTERN, candidate):
            continue
        if candidate in SANDBOX_FORBIDDEN_ENV_KEYS:
            continue
        if candidate in SANDBOX_ENV_ALLOWLIST:
            continue
        keys.append(candidate)
    return tuple(sorted(dict.fromkeys(keys)))


def validate_workspace(workspace_path: Path) -> Path:
    """Confine the bind source to a real directory under the exec root.

    Rejects relative paths, traversal and symlink escape. When
    ``DEPLOYMENT_WORKSPACE_ROOT`` is configured the workspace must resolve
    beneath it; with it unset (pure unit contexts) the absolute-and-exists
    rule still applies. There is never a fallback to another host path.
    """
    workspace = Path(workspace_path)
    if not workspace.is_absolute():
        raise TerraformSandboxPolicyViolation(
            "terraform sandbox workspace must be an absolute path"
        )
    if ".." in workspace.parts:
        raise TerraformSandboxPolicyViolation(
            "terraform sandbox workspace must not contain '..'"
        )
    if not workspace.is_dir():
        raise TerraformSandboxPolicyViolation(
            "terraform sandbox workspace does not exist (fail-closed; "
            "no host fallback)"
        )

    # Resolve symlinks before the containment check: a symlink inside the
    # root that points outside it must not escape confinement.
    resolved = workspace.resolve()
    configured_root = os.environ.get(SANDBOX_WORKSPACE_ROOT_VAR, "").strip()
    if configured_root:
        root = Path(configured_root)
        if not root.is_absolute():
            raise TerraformSandboxConfigurationError(
                f"{SANDBOX_WORKSPACE_ROOT_VAR} must be an absolute path"
            )
        if not root.is_dir():
            raise TerraformSandboxConfigurationError(
                f"{SANDBOX_WORKSPACE_ROOT_VAR} does not exist"
            )
        if not resolved.is_relative_to(root.resolve()):
            raise TerraformSandboxPolicyViolation(
                "terraform sandbox workspace must be beneath "
                f"{SANDBOX_WORKSPACE_ROOT_VAR} (fail-closed)"
            )
    return resolved


def sandbox_policy_identity(spec: TerraformSandboxSpec) -> str:
    """Deterministic fingerprint of the whole security posture.

    Covers image digest, identity, network, capability/rootfs policy,
    resource limits, output bound and the allowed operation set. Contains
    no timestamps and no random values, so it is stable for a given
    posture and changes the moment the posture does.
    """
    material = {
        "policy_version": TERRAFORM_SANDBOX_POLICY_VERSION,
        "image": (spec.image or "").strip(),
        "user": (spec.user or "").strip(),
        "network_mode": spec.network_mode,
        "terraform_version": spec.terraform_version or "",
        "read_only_rootfs": True,
        "cap_drop": ["ALL"],
        "no_new_privileges": True,
        "privileged": False,
        "docker_socket": False,
        "tmpfs": {"/tmp": SANDBOX_TMPFS_SIZE},
        "pids_limit": SANDBOX_PIDS_LIMIT,
        "memory_bytes": SANDBOX_MEMORY_BYTES,
        "cpus": SANDBOX_CPUS,
        "max_output_bytes": SANDBOX_MAX_OUTPUT_BYTES,
        "max_runtime_seconds": SANDBOX_MAX_RUNTIME_SECONDS,
        "workspace_mount": SANDBOX_WORKSPACE_MOUNT,
        "allowed_operations": sorted(op.value for op in TerraformOperation),
        "env_allowlist": sorted(SANDBOX_ENV_ALLOWLIST),
    }
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return f"{TERRAFORM_SANDBOX_POLICY_VERSION}:{digest[:32]}"


def build_run_plan(
    *,
    spec: TerraformSandboxSpec,
    step: TerraformSandboxStep,
    workspace_path: Path,
    container_name: str,
) -> TerraformSandboxRunPlan:
    """Build the complete runtime plan for one sandboxed operation.

    Raises ``TerraformSandboxPolicyViolation`` on anything exceeding
    policy. Pure apart from the workspace existence/containment check.
    """
    validate_runtime_spec(spec)

    if not isinstance(container_name, str) or not re.fullmatch(
        _CONTAINER_NAME_PATTERN, container_name
    ):
        raise TerraformSandboxPolicyViolation("invalid sandbox container name")

    if not isinstance(step.operation, TerraformOperation):
        raise TerraformSandboxPolicyViolation(
            "sandbox step operation must be a TerraformOperation member"
        )
    if not step.argv or any(not isinstance(arg, str) for arg in step.argv):
        raise TerraformSandboxPolicyViolation(
            "sandbox argv must be non-empty strings"
        )
    if step.argv[0] != TERRAFORM_BINARY:
        raise TerraformSandboxPolicyViolation(
            "sandbox steps may only run the policy-owned terraform binary"
        )
    # argv must be exactly what policy would have produced for this
    # operation: a caller cannot smuggle extra flags past the template.
    if step.argv != build_terraform_argv(
        step.operation,
        execution=_infers_execution(step.argv),
        plan_file=_plan_file_of(step.argv),
    ):
        raise TerraformSandboxPolicyViolation(
            "sandbox argv does not match the policy template for "
            f"{step.operation.value}"
        )

    budget = OPERATION_TIMEOUTS[step.operation]
    if not (0 < step.timeout_seconds <= budget):
        raise TerraformSandboxPolicyViolation(
            f"{step.operation.value} timeout must be in (0, {budget}]"
        )
    if not (0 < step.max_output_bytes <= SANDBOX_MAX_OUTPUT_BYTES):
        raise TerraformSandboxPolicyViolation(
            "sandbox output limit must be within policy bounds"
        )

    credential_keys = tuple(step.credential_env_keys or ())
    for key in credential_keys:
        if not re.fullmatch(_CREDENTIAL_NAME_PATTERN, key):
            raise TerraformSandboxPolicyViolation(
                "credential environment names must be upper-case identifiers"
            )
        if key in SANDBOX_FORBIDDEN_ENV_KEYS or key in SANDBOX_ENV_ALLOWLIST:
            raise TerraformSandboxPolicyViolation(
                f"environment variable {key} may never be forwarded"
            )

    workspace = validate_workspace(workspace_path)

    # Exactly one host bind: the ephemeral per-run workspace. Read-write,
    # because init/plan must write into it. No host root, home, SSH,
    # credential directory, /proc, /sys, and above all no docker socket.
    mounts = (f"{workspace}:{SANDBOX_WORKSPACE_MOUNT}:rw",)

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
        f"/tmp:rw,nosuid,nodev,size={SANDBOX_TMPFS_SIZE}",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        str(SANDBOX_PIDS_LIMIT),
        "--memory",
        str(SANDBOX_MEMORY_BYTES),
        "--cpus",
        SANDBOX_CPUS,
        "--hostname",
        container_name,
        "--label",
        "dev.arena.terraform-sandbox=1",
        "--entrypoint",
        TERRAFORM_BINARY,
    ]
    for key, value in sorted(env.items()):
        cli_argv += ["-e", f"{key}={value}"]
    # Credential VALUES never enter argv: only the name is passed, and the
    # adapter supplies the value through the docker CLI's own environment.
    for key in credential_keys:
        cli_argv += ["-e", key]
    cli_argv += ["-v", mounts[0], "-w", SANDBOX_WORKSPACE_MOUNT, spec.image]
    # argv[0] is the entrypoint; pass only the arguments after it.
    cli_argv += list(step.argv[1:])

    return TerraformSandboxRunPlan(
        container_name=container_name,
        cli_argv=tuple(cli_argv),
        env=MappingProxyType(env),
        credential_env_keys=credential_keys,
        mounts=mounts,
        working_directory=SANDBOX_WORKSPACE_MOUNT,
        wall_timeout_seconds=(
            float(step.timeout_seconds) + SANDBOX_WALL_GRACE_SECONDS
        ),
        policy_identity=sandbox_policy_identity(spec),
    )


def _infers_execution(argv: tuple[str, ...]) -> bool:
    """Recover the execution flag from argv for template re-derivation."""
    if "init" in argv:
        return "-backend=false" not in argv
    if "plan" in argv:
        return "-lock=true" in argv
    return True


def _plan_file_of(argv: tuple[str, ...]) -> str | None:
    if "-out" in argv:
        index = argv.index("-out")
        if index + 1 < len(argv):
            return argv[index + 1]
        return None
    if argv[:2] == (TERRAFORM_BINARY, "apply"):
        return argv[-1]
    return None


def new_container_name(hint: str = "") -> str:
    """Unique container identity — no trust is ever reused across runs."""
    import uuid

    cleaned = re.sub(r"[^a-zA-Z0-9_.-]", "", str(hint))[:16].lower()
    suffix = uuid.uuid4().hex[:12]
    base = f"tf-sbx-{cleaned}" if cleaned else "tf-sbx"
    return f"{base}-{suffix}"[:128]


# ---------------------------------------------------------------------
# Phase 8.5-A corrective — runtime identity and credential profile
# ---------------------------------------------------------------------


def sandbox_runtime_identity() -> tuple[int, int]:
    """Resolve the (uid, gid) the Terraform container must run as.

    Two cases, and neither of them is root:

    * The control plane is itself non-root. It cannot ``chown`` anything,
      so the sandbox reuses the control plane's own identity and the
      workspace it creates is writable by construction.
    * The control plane is root. It can hand ownership over explicitly,
      so the sandbox uses a dedicated unprivileged identity and the
      workspace is chowned to it.

    A configured UID/GID of 0 is refused outright: there is no
    configuration path to a root Terraform container.
    """
    def _configured(var: str, fallback: int) -> int:
        raw = os.environ.get(var, "").strip()
        if not raw:
            return fallback
        try:
            value = int(raw)
        except ValueError as exc:
            raise TerraformSandboxConfigurationError(
                f"{var} must be an integer id, got {raw!r}"
            ) from exc
        if value <= 0:
            raise TerraformSandboxConfigurationError(
                f"{var} must be a non-root id, got {value}"
            )
        return value

    current_uid = os.getuid()
    current_gid = os.getgid()
    if current_uid != 0:
        # Non-root control plane: match it, unless explicitly overridden.
        return (
            _configured(SANDBOX_UID_VAR, current_uid),
            _configured(SANDBOX_GID_VAR, current_gid),
        )
    return (
        _configured(SANDBOX_UID_VAR, DEFAULT_SANDBOX_UID),
        _configured(SANDBOX_GID_VAR, DEFAULT_SANDBOX_GID),
    )


#: Stable, non-secret identity of the "no credentials at all" profile.
CREDENTIALS_DISABLED_PROFILE = "credentials-disabled"


def credential_profile_identity() -> str:
    """Non-secret identity of the credential context for this execution.

    This exists so that approval can bind *which* credential context was
    in force without ever touching a secret value. Only the NAMES are
    hashed -- never values, never a hash of a value, because a hash of a
    low-entropy secret is itself a disclosure risk.

    A profile change after approval (credentials switched on, or a
    different credential set configured) changes this identity and is
    therefore rejected at execution time.
    """
    keys = resolve_credential_env_keys()
    if not keys:
        return CREDENTIALS_DISABLED_PROFILE
    digest = hashlib.sha256(
        json.dumps(sorted(keys), separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"credential-names:{digest[:32]}"
