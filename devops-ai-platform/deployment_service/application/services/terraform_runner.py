"""Terraform runner — Phase 8.5-A execution trust boundary.

This service orchestrates Terraform but DOES NOT EXECUTE IT. Every
operation is handed to a sandbox port that runs it inside an isolated,
host-policy-owned runtime. There is deliberately no ``subprocess`` import
in this module and no host fallback anywhere in it: if the sandbox cannot
run, Terraform does not run, and the operation is reported BLOCKED.

Untrusted Terraform content can influence only the configuration being
planned. It can never choose the executable, argv, image, user, network,
mounts, limits, environment or credentials.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from deployment_service.application.services.plan_artifact import (
    PLAN_FILENAME,
    PlanArtifactError,
    hash_plan_artifact,
)

from deployment_service.application.services.terraform_sandbox import (
    OPERATION_TIMEOUTS,
    SANDBOX_MAX_OUTPUT_BYTES,
    TerraformOperation,
    TerraformSandboxError,
    TerraformSandboxPolicyViolation,
    TerraformSandboxStep,
    build_terraform_argv,
    resolve_credential_env_keys,
)

# Statuses the deployment engine already understands. Anything that is not
# exactly "PASS" is a fail-closed outcome for the caller.
STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_TIMEOUT = "TIMEOUT"
STATUS_BLOCKED = "BLOCKED"


class TerraformRunnerService:
    """Run fixed Terraform operations through the sandbox boundary."""

    def __init__(self, sandbox=None):
        """``sandbox`` is the single execution seam.

        Production wiring resolves the container sandbox lazily so that
        importing this module never requires a container runtime; unit
        tests inject a deterministic fake.
        """
        self._sandbox = sandbox

    # --- single operation ----------------------------------------------

    def _execute(
        self,
        operation: TerraformOperation,
        iac_dir: str,
        *,
        execution: bool,
        plan_file: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run exactly one policy-owned Terraform operation."""
        sandbox = self._sandbox if self._sandbox is not None else _default_sandbox()
        try:
            argv = build_terraform_argv(
                operation, execution=execution, plan_file=plan_file
            )
            step = TerraformSandboxStep(
                operation=operation,
                argv=argv,
                timeout_seconds=OPERATION_TIMEOUTS[operation],
                max_output_bytes=SANDBOX_MAX_OUTPUT_BYTES,
                credential_env_keys=(
                    resolve_credential_env_keys() if execution else ()
                ),
            )
            outcome = sandbox.execute(step, Path(iac_dir))
        except TerraformSandboxError as exc:
            # Sandbox configuration / policy / availability / result
            # problems are ALL fail-closed. Terraform did not execute.
            return {
                "status": STATUS_BLOCKED,
                "operation": operation.value,
                "error_code": getattr(exc, "code", "SANDBOX_EXECUTION_FAILED"),
                "error": str(exc),
                "stdout": "",
                "stderr": "",
                "executed": False,
            }

        if outcome.timed_out:
            return {
                "status": STATUS_TIMEOUT,
                "operation": operation.value,
                "error_code": "SANDBOX_TIMEOUT",
                "exit_code": outcome.exit_code,
                "stdout": outcome.stdout,
                "stderr": outcome.stderr,
                "output_truncated": outcome.output_truncated,
                "executed": True,
            }

        return {
            "status": STATUS_PASS if outcome.exit_code == 0 else STATUS_FAIL,
            "operation": operation.value,
            "exit_code": outcome.exit_code,
            "stdout": outcome.stdout,
            "stderr": outcome.stderr,
            "output_truncated": outcome.output_truncated,
            "executed": True,
        }

    # --- plan ------------------------------------------------------------

    def run_plan(
        self,
        iac_dir: str,
        execution: bool = False,
        plan_output_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """fmt -> init -> validate -> plan, all inside the sandbox.

        The dry-run path is sandboxed exactly like the execution path:
        provider plugins can be invoked during ``init``/``plan``, so
        leaving dry-run on the host would leave the boundary open.
        """
        plan_file: Optional[str] = None
        if plan_output_path:
            try:
                plan_file = _workspace_relative_name(iac_dir, plan_output_path)
            except TerraformSandboxPolicyViolation as exc:
                blocked = {
                    "status": STATUS_BLOCKED,
                    "operation": TerraformOperation.PLAN.value,
                    "error_code": exc.code,
                    "error": str(exc),
                    "stdout": "",
                    "stderr": "",
                    "executed": False,
                }
                return {
                    "status": STATUS_BLOCKED,
                    "steps": [blocked],
                    "plan": blocked,
                    "plan_file_hash": "",
                    "execution": execution,
                    "sandbox": self.describe_sandbox(),
                }

        steps: List[Dict[str, Any]] = []
        for operation, uses_plan_file in (
            (TerraformOperation.FORMAT, False),
            (TerraformOperation.INIT, False),
            (TerraformOperation.VALIDATE, False),
            (TerraformOperation.PLAN, True),
        ):
            result = self._execute(
                operation,
                iac_dir,
                execution=execution,
                plan_file=plan_file if uses_plan_file else None,
            )
            steps.append(result)
            if result["status"] != STATUS_PASS:
                # Stop at the first failure: never run a later Terraform
                # stage on top of a stage that did not succeed.
                break

        statuses = [step["status"] for step in steps]
        if all(value == STATUS_PASS for value in statuses):
            status = STATUS_PASS
        elif STATUS_BLOCKED in statuses:
            status = STATUS_BLOCKED
        elif STATUS_TIMEOUT in statuses:
            status = STATUS_TIMEOUT
        else:
            status = STATUS_FAIL

        plan_file_hash = ""
        if status == STATUS_PASS and plan_output_path:
            # The saved plan was written by untrusted Terraform inside a
            # workspace it controls, so the host may only touch it through
            # the proven-safe artifact guard (symlink/confinement checks).
            try:
                plan_file_hash = hash_plan_artifact(iac_dir, plan_output_path)
            except PlanArtifactError as exc:
                status = STATUS_BLOCKED
                steps.append(
                    {
                        "status": STATUS_BLOCKED,
                        "operation": TerraformOperation.PLAN.value,
                        "error_code": exc.code,
                        "error": str(exc),
                        "executed": False,
                    }
                )

        return {
            "status": status,
            "steps": steps,
            "plan": steps[-1],
            "plan_file_hash": plan_file_hash,
            "execution": execution,
            "sandbox": self.describe_sandbox(),
        }

    # --- apply -----------------------------------------------------------

    def apply_plan(
        self,
        iac_dir: str,
        plan_output_path: str,
        expected_plan_file_hash: str = "",
    ) -> Dict[str, Any]:
        """Apply EXACTLY the saved plan, after re-verifying its bytes.

        The plan is never regenerated here and the caller cannot point
        this at an alternate plan path outside the workspace.
        """
        try:
            plan_file = _workspace_relative_name(iac_dir, plan_output_path)
        except TerraformSandboxPolicyViolation as exc:
            return {
                "status": STATUS_BLOCKED,
                "operation": TerraformOperation.APPLY.value,
                "error_code": exc.code,
                "error": str(exc),
                "executed": False,
                "sandbox": self.describe_sandbox(),
            }

        if not expected_plan_file_hash:
            # Phase 8.5-A corrective: applying without a hash to compare
            # against would make the approval binding unprovable. There is
            # no "unverified apply" mode.
            return {
                "status": STATUS_BLOCKED,
                "operation": TerraformOperation.APPLY.value,
                "error_code": "PLAN_ARTIFACT_UNVERIFIED",
                "error": "refusing to apply a plan with no approved hash "
                "to verify it against",
                "executed": False,
                "sandbox": self.describe_sandbox(),
            }

        try:
            actual_hash = hash_plan_artifact(iac_dir, plan_output_path)
        except PlanArtifactError as exc:
            return {
                "status": STATUS_BLOCKED,
                "operation": TerraformOperation.APPLY.value,
                "error_code": exc.code,
                "error": str(exc),
                "executed": False,
                "sandbox": self.describe_sandbox(),
            }

        if actual_hash != expected_plan_file_hash:
            # The approved plan artifact changed between plan and apply.
            return {
                "status": STATUS_BLOCKED,
                "operation": TerraformOperation.APPLY.value,
                "error_code": "PLAN_ARTIFACT_MISMATCH",
                "error": "saved terraform plan does not match the hash "
                "recorded at plan time; refusing to apply",
                "executed": False,
                "plan_file_hash": actual_hash,
                "sandbox": self.describe_sandbox(),
            }

        result = self._execute(
            TerraformOperation.APPLY,
            iac_dir,
            execution=True,
            plan_file=plan_file,
        )
        result["plan_file_hash"] = actual_hash
        result["sandbox"] = self.describe_sandbox()
        return result

    # --- post-approval preparation ---------------------------------------

    def initialize(self, iac_dir: str) -> Dict[str, Any]:
        """Run ONLY ``terraform init`` (no plan) in an existing workspace.

        Phase 8.5-A corrective, Workstream D: the execution path must be
        able to make a recovered approval workspace usable again without
        producing a new plan. ``init`` cannot create or alter a plan, so
        it cannot change what is about to be applied.
        """
        result = self._execute(
            TerraformOperation.INIT, iac_dir, execution=True
        )
        result["sandbox"] = self.describe_sandbox()
        return result

    # --- evidence ---------------------------------------------------------

    def describe_sandbox(self) -> Dict[str, str]:
        """Safe runtime identity for deployment evidence (no secrets)."""
        sandbox = self._sandbox
        if sandbox is None:
            try:
                sandbox = _default_sandbox()
            except Exception:
                return {"execution_mode": "unavailable"}
        describe = getattr(sandbox, "describe", None)
        if describe is None:
            return {"execution_mode": "unknown"}
        try:
            return dict(describe())
        except Exception:
            return {"execution_mode": "unknown"}


def _default_sandbox():
    """Resolve the production sandbox adapter lazily."""
    from deployment_service.infrastructure.sandbox.container_terraform_sandbox import (  # noqa: E501
        ContainerTerraformSandbox,
    )

    return ContainerTerraformSandbox.from_environment()


def _workspace_relative_name(iac_dir: str, plan_output_path: str) -> str:
    """Confine the saved plan to a simple name inside the workspace.

    The container sees the workspace at a fixed mount point, so the host
    path is meaningless inside it. Anything that is not a direct child of
    the working directory is rejected rather than rewritten.
    """
    directory = Path(iac_dir)
    candidate = Path(plan_output_path)
    if not candidate.is_absolute():
        candidate = directory / candidate
    try:
        relative = candidate.relative_to(directory)
    except ValueError as exc:
        raise TerraformSandboxPolicyViolation(
            "saved terraform plan must live inside the execution workspace"
        ) from exc
    if len(relative.parts) != 1:
        raise TerraformSandboxPolicyViolation(
            "saved terraform plan must be a direct child of the workspace"
        )
    return relative.parts[0]
