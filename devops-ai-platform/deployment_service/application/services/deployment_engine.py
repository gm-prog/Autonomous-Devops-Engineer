
import hashlib
import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List

import yaml

from deployment_service.application.services.health_check_service import HealthCheckService
from deployment_service.application.services.iac_validator import IaCValidator
from deployment_service.application.services.kubectl_runner import KubectlRunnerService
from deployment_service.application.services.release_identity_injection import (
    inject_release_identity,
)
from deployment_service.application.services.source_verification import (
    GitHubSourceVerifier,
)
from deployment_service.application.services.plan_artifact import (
    PLAN_FILENAME,
    PlanArtifactError,
    hash_plan_artifact,
)
from deployment_service.application.services.terraform_runner import TerraformRunnerService
from deployment_service.application.services.terraform_sandbox import (
    credential_profile_identity,
    sandbox_runtime_identity,
)
from deployment_service.domain.entities.deployment_run import DeploymentRun
from deployment_service.domain.value_objects.deployment_state import DeploymentState
from deployment_service.infrastructure.persistence.redis_pipeline_store import RedisPipelineStore


class DeploymentActionError(RuntimeError):
    pass


#: States after which an approved plan can never legitimately be applied.
_TERMINAL_STATES = frozenset(
    {
        DeploymentState.DEPLOYED,
        DeploymentState.DEPLOYMENT_FAILED,
        DeploymentState.ROLLED_BACK,
        DeploymentState.ROLLBACK_FAILED,
    }
)


class DeploymentEngine:
    def __init__(self, store=None, validator=None, terraform=None, kubectl=None, health_checker=None, source_verifier=None):
        self.store = store or RedisPipelineStore()
        self.validator = validator or IaCValidator()
        self.terraform = terraform or TerraformRunnerService()
        self.kubectl = kubectl or KubectlRunnerService()
        self.health_checker = health_checker or HealthCheckService()
        # Independent source-revision verification (Stage 5): the default is
        # the real GitHub-backed verifier; tests inject deterministic fakes.
        self.source_verifier = source_verifier or GitHubSourceVerifier()

    @staticmethod
    def _validated_source_revision(value: Any) -> Dict[str, Any]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise DeploymentActionError("source_revision must be an object")
        head_sha = value.get("head_sha", "")
        commits = value.get("commits", [])
        summary = value.get("summary", {})
        if head_sha and (not isinstance(head_sha, str) or len(head_sha) > 64):
            raise DeploymentActionError("source_revision.head_sha is invalid")
        if not isinstance(commits, list) or len(commits) > 5:
            raise DeploymentActionError("source_revision.commits is invalid")
        if not isinstance(summary, dict):
            raise DeploymentActionError("source_revision.summary is invalid")
        return {
            "head_sha": head_sha,
            "commits": commits[:5],
            "summary": {
                "commit_count": int(summary.get("commit_count", 0)),
                "files_changed": int(summary.get("files_changed", 0)),
                "additions": int(summary.get("additions", 0)),
                "deletions": int(summary.get("deletions", 0)),
            },
        }

    @staticmethod
    def _effective_payload(payload: Dict[str, Any], deployment_id: Any, source_sha: Any) -> Dict[str, Any]:
        """Canonical deployment payload (Phase 6.5.2 corrective).

        Returns a copy of the caller payload whose ``k8s_yaml`` is bound to
        the authoritative release identity taken from THIS run's persisted
        record (``run.id`` + ``source_revision.head_sha``) — never from the
        caller. Pure and deterministic: the same inputs always produce the
        same bytes, so validation, dry-run, ``artifact_hash``, approval and
        execution all reference one single artifact representation. An
        unusable identity injects nothing (fail closed — the original
        ``k8s_yaml`` passes through unchanged, never fabricated).
        """
        effective = dict(payload)
        original = payload.get("k8s_yaml", "")
        if isinstance(original, str):
            effective["k8s_yaml"], _ = inject_release_identity(
                original, deployment_id, source_sha
            )
        return effective

    @staticmethod
    def _artifact_hash(payload: Dict[str, Any]) -> str:
        bundle = {k: payload.get(k, "") for k in ("dockerfile", "k8s_yaml", "terraform_tf", "pipeline_yaml")}
        # Which components were declared is part of artifact identity.
        bundle["components"] = list(payload.get("components") or [])
        return hashlib.sha256(json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    @staticmethod
    def _plan_hash(artifact_hash: str, terraform_result: Dict[str, Any], kubernetes_result: Dict[str, Any], source_revision: Dict[str, Any] | None = None, repository_name: str | None = None) -> str:
        material = {
            "artifact_hash": artifact_hash,
            # repository identity participates in plan identity: identical
            # artifacts deployed from two different repositories must not
            # share a plan hash.
            "repository_name": repository_name or "",
            "source_revision": source_revision or {},
            "terraform": {"status": terraform_result.get("status"), "stdout": terraform_result.get("plan", {}).get("stdout", "")},
            # Phase 8.5-A: the execution trust boundary is part of plan
            # identity. The same artifact planned under a materially
            # different sandbox policy must not silently reuse an earlier
            # approval identity.
            "sandbox_policy_identity": (terraform_result.get("sandbox") or {}).get("sandbox_policy_identity", ""),
            # Phase 8.5-A corrective, Workstream D. The approval must bind
            # the EXACT plan artifact, not a description of it. Without
            # this, approving "plan A" and applying a freshly generated
            # "plan B" would produce the same identity.
            "plan_file_hash": terraform_result.get("plan_file_hash", ""),
            # Workstream F: which credential context was in force. Names
            # only -- never values (see credential_profile_identity).
            "credential_profile_id": terraform_result.get("credential_profile_id", ""),
            "kubernetes": {"status": kubernetes_result.get("status"), "stdout": kubernetes_result.get("stdout", "")},
            # Phase 8.6-A corrective, Workstream B. Approval must bind the
            # execution TARGET as well as the artifact: endpoint, CA,
            # namespace, credential profile, manifest policy, sandbox
            # policy and network. Without this an approval granted
            # against one cluster could execute against another.
            "kubernetes_execution_identity": (
                kubernetes_result.get("execution_identity") or {}
            ).get("execution_identity", ""),
        }
        return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    @staticmethod
    def _kubernetes_is_declared(payload) -> bool:
        """True when the deployment actually has a Kubernetes component.

        Phase 8.6-A: the Kubernetes dry run is now a SERVER-side dry run
        against the real cluster, so it cannot be performed without one.
        A payload that declares no manifest performs no Kubernetes
        operation at all, so there is nothing to validate and nothing to
        execute -- that is "not applicable", not "allowed through".

        This is deliberately keyed on the manifest text, which is part of
        the artifact hash. A run approved with no Kubernetes component
        therefore cannot later acquire one: injecting a manifest changes
        the artifact hash and invalidates the approval.
        """
        components = payload.get("components")
        if components is not None:
            # An explicit selection is authoritative. Contradictory
            # payloads (manifest supplied but Kubernetes not requested)
            # are rejected by IaCValidator before reaching here.
            return "kubernetes" in components
        return bool(str(payload.get("k8s_yaml", "") or "").strip())

    @staticmethod
    def _approved_kubernetes_identity(run):
        """Rebuild the approval-bound Kubernetes execution identity.

        Returns None when the run carries none, which makes the runner
        refuse to mutate -- fail closed rather than fall back.
        """
        from deployment_service.application.services.kubernetes_execution_identity import (
            KubernetesExecutionIdentity,
        )
        stored = (run.execution or {}).get("kubernetes_execution_identity") or {}
        required = ("namespace", "api_server", "ca_fingerprint_sha256",
                    "credential_profile_id", "manifest_policy_identity",
                    "sandbox_policy_identity")
        if not all(stored.get(k) for k in required):
            return None
        return KubernetesExecutionIdentity(
            namespace=stored["namespace"],
            api_server=stored["api_server"],
            ca_fingerprint_sha256=stored["ca_fingerprint_sha256"],
            credential_profile_id=stored["credential_profile_id"],
            manifest_policy_identity=stored["manifest_policy_identity"],
            sandbox_policy_identity=stored["sandbox_policy_identity"],
            network_identity=stored.get("network_identity", ""),
        )

    @staticmethod
    def _terraform_is_declared(payload) -> bool:
        """True when the deployment actually has a Terraform component.

        The mirror of _kubernetes_is_declared. Component selection was
        introduced for Kubernetes but the Terraform leg still planned
        unconditionally, so a deployment that declared no Terraform was
        sent to the Terraform sandbox anyway and BLOCKED on a sandbox
        it was never meant to use. Not applicable is not the same as
        blocked, and neither is the same as allowed through.
        """
        components = payload.get("components")
        if components is not None:
            return "terraform" in components
        return bool(str(payload.get("terraform_tf", "") or "").strip())

    @staticmethod
    def _terraform_not_applicable() -> Dict[str, Any]:
        return {
            "status": "NOT_APPLICABLE",
            "terraform_applicable": False,
            "steps": [],
            "reason": "terraform is not a requested component",
        }

    @staticmethod
    def _kubernetes_not_applicable() -> Dict[str, Any]:
        return {
            "status": "SKIPPED",
            "stdout": "",
            "stderr": "Kubernetes is not a declared component of this "
                      "deployment; no Kubernetes operation is performed, "
                      "attempted, or claimed.",
            # Explicit and machine-checkable. A consumer must be able to
            # tell "no Kubernetes work was requested" apart from
            # "Kubernetes work was requested and succeeded" without
            # interpreting prose.
            "kubernetes_applicable": False,
            "cluster_access": False,
            "sandboxed": True,
        }

    @staticmethod
    def _deployment_names(k8s_yaml: str) -> List[str]:
        try:
            documents = [doc for doc in yaml.safe_load_all(k8s_yaml) if isinstance(doc, dict)]
        except yaml.YAMLError:
            return []
        names = []
        for document in documents:
            if document.get("kind") == "Deployment":
                name = (document.get("metadata") or {}).get("name")
                if isinstance(name, str) and name.strip():
                    names.append(name.strip())
        return list(dict.fromkeys(names))

    @staticmethod
    def _write_iac(payload: Dict[str, Any], temp_dir: str) -> Dict[str, str]:
        paths = {
            "terraform": str(Path(temp_dir, "main.tf")),
            "kubernetes": str(Path(temp_dir, "deployment.yaml")),
            "dockerfile": str(Path(temp_dir, "Dockerfile")),
            "pipeline": str(Path(temp_dir, "ci.yml")),
            "terraform_plan": str(Path(temp_dir, "terraform.tfplan")),
        }
        Path(paths["terraform"]).write_text(payload.get("terraform_tf", ""), encoding="utf-8")
        Path(paths["kubernetes"]).write_text(payload.get("k8s_yaml", ""), encoding="utf-8")
        Path(paths["dockerfile"]).write_text(payload.get("dockerfile", ""), encoding="utf-8")
        Path(paths["pipeline"]).write_text(payload.get("pipeline_yaml", ""), encoding="utf-8")
        return paths

    @staticmethod
    def _new_workspace(prefix: str) -> str:
        """Create the ephemeral execution workspace.

        When DEPLOYMENT_WORKSPACE_ROOT is configured, the workspace is
        created BENEATH it so the sandbox's containment check can succeed;
        the sandbox independently re-verifies containment and fails closed
        if the directory is anywhere else.
        """
        root = os.getenv("DEPLOYMENT_WORKSPACE_ROOT", "").strip()
        if root:
            Path(root).mkdir(parents=True, exist_ok=True)
            return tempfile.mkdtemp(prefix=prefix, dir=root)
        return tempfile.mkdtemp(prefix=prefix)

    @staticmethod
    def _approval_workspace(run_id: str) -> str:
        """Create the PERSISTENT workspace that holds the approved plan.

        Phase 8.5-A corrective, Workstreams B and C.

        This directory outlives the dry-run on purpose: it is the only
        place the exact approved plan exists, and execution applies that
        artifact rather than regenerating one. It must therefore be:

        * beneath the configured workspace root, so it is visible at the
          SAME absolute path to the container runtime (a path that exists
          only inside the control-plane container cannot be bind-mounted);
        * owned by the identity the sandbox runs as, so a non-root
          Terraform can write ``.terraform/`` and the saved plan;
        * group-traversable at most -- never world-readable, because a
          saved plan describes private infrastructure.
        """
        root = os.getenv("DEPLOYMENT_WORKSPACE_ROOT", "").strip()
        base = Path(root) if root else Path(tempfile.gettempdir())
        base.mkdir(parents=True, exist_ok=True)
        workspace = base / f"approved-{run_id}"
        workspace.mkdir(parents=True, exist_ok=False)
        # 0o2770: owner+group rwx, setgid so Terraform-created files stay
        # in the shared group; nothing for "other". Explicitly NOT 0o777.
        os.chmod(workspace, 0o2770)
        uid, gid = sandbox_runtime_identity()
        if os.getuid() == 0 and (uid, gid) != (os.getuid(), os.getgid()):
            # Only a root control plane can, and must, hand ownership to
            # the unprivileged sandbox identity.
            os.chown(workspace, uid, gid)
        return str(workspace)

    @staticmethod
    def _discard_approval_workspace(run_id: str) -> None:
        """Remove a persisted approval workspace once it can never apply."""
        root = os.getenv("DEPLOYMENT_WORKSPACE_ROOT", "").strip()
        base = Path(root) if root else Path(tempfile.gettempdir())
        shutil.rmtree(base / f"approved-{run_id}", ignore_errors=True)

    def create_dry_run(self, payload: Dict[str, Any]) -> DeploymentRun:
        source_revision = self._validated_source_revision(payload.get("source_revision"))
        # Independent source verification happens FIRST: if the exact
        # requested revision cannot be confirmed against the canonical
        # repository, SourceVerificationError propagates and NO run is ever
        # persisted (fail closed; see main.py for the HTTP mapping).
        source_verification = self.source_verifier.verify(
            payload["repository_name"], source_revision.get("head_sha", "")
        )
        run = DeploymentRun(
            id=f"run_{uuid.uuid4().hex[:12]}",
            repository_id=int(payload["repository_id"]),
            repository_name=payload["repository_name"],
            requested_by=payload.get("requested_by"),
            source_revision=source_revision,
        )
        run.source_verification = dict(source_verification)
        # Phase 6.5.2 corrective — canonical effective payload: the caller
        # payload with k8s_yaml bound to THIS run's authoritative identity.
        # Everything below (validation, dry-run, artifact/plan hashes)
        # references this single artifact representation, so the approved
        # artifact already contains the runtime identity and no mutation is
        # ever needed after the approval boundary.
        effective_payload = self._effective_payload(
            payload, run.id, run.source_revision.get("head_sha", "")
        )
        run.move(DeploymentState.VALIDATING)
        run.add_log("VALIDATING: static IaC safety and syntax checks started.")
        run.validation = self.validator.validate(effective_payload.get("dockerfile", ""), effective_payload.get("k8s_yaml", ""), effective_payload.get("terraform_tf", ""), effective_payload.get("pipeline_yaml", ""), effective_payload.get("components"))
        if run.validation["status"] == "FAIL":
            run.move(DeploymentState.VALIDATION_FAILED)
            run.add_log("VALIDATION_FAILED: blocking IaC checks detected.")
            self.store.save(run)
            return run

        run.move(DeploymentState.VALIDATED)
        run.move(DeploymentState.DRY_RUNNING)
        run.add_log("DRY_RUNNING: executing local Terraform plan and Kubernetes client-side dry-run.")
        self.store.save(run)

        # Phase 8.5-A corrective: the dry-run plan IS the plan that will
        # be applied, so it is produced into a persistent, correctly-owned
        # workspace and saved to disk. Nothing re-plans after this point.
        temp_dir = self._approval_workspace(run.id)
        try:
            paths = self._write_iac(effective_payload, temp_dir)
            run.terraform_plan = (
                self.terraform.run_plan(
                    temp_dir,
                    execution=False,
                    plan_output_path=paths["terraform_plan"],
                )
                if self._terraform_is_declared(effective_payload)
                else self._terraform_not_applicable()
            )
            run.terraform_plan["credential_profile_id"] = credential_profile_identity()
            run.terraform_plan["approval_workspace"] = temp_dir
            run.kubernetes_dry_run = (
                self.kubectl.dry_run(paths["kubernetes"])
                if self._kubernetes_is_declared(effective_payload)
                else self._kubernetes_not_applicable()
            )
            # The identity the approval is granted against. Persisted on
            # the run so execution can prove it has not moved.
            run.execution["kubernetes_execution_identity"] = (
                run.kubernetes_dry_run.get("execution_identity") or {}
            )
            run.artifact_hash = self._artifact_hash(effective_payload)
            run.plan_hash = self._plan_hash(run.artifact_hash, run.terraform_plan, run.kubernetes_dry_run, run.source_revision, run.repository_name)
            if run.terraform_plan["status"] == "PASS" and \
                    run.kubernetes_dry_run["status"] in ("PASS", "SKIPPED"):
                run.move(DeploymentState.DRY_RUN_PASSED)
                run.move(DeploymentState.AWAITING_APPROVAL)
                run.add_log("AWAITING_APPROVAL: exact artifact and dry-run hashes are bound to this run.")
            else:
                run.move(DeploymentState.DRY_RUN_FAILED)
                run.add_log(f"DRY_RUN_FAILED: Terraform={run.terraform_plan['status']}; Kubernetes={run.kubernetes_dry_run['status']}.")
            self.store.save(run)
            return run
        except Exception as exc:
            run.move(DeploymentState.DRY_RUN_FAILED, error=type(exc).__name__)
            run.add_log(f"DRY_RUN_FAILED: {type(exc).__name__}.")
            self.store.save(run)
            return run
        finally:
            # Keep the workspace only while it can still be executed; a
            # run that never reached AWAITING_APPROVAL has no approved
            # plan to protect, so its saved plan is destroyed immediately.
            if run.state != DeploymentState.AWAITING_APPROVAL:
                self._discard_approval_workspace(run.id)

    def approve(self, run_id: str, approved_by: str, artifact_hash: str, plan_hash: str) -> DeploymentRun:
        payload = self.store.get(run_id)
        if not payload:
            raise DeploymentActionError("Deployment run not found.")
        run = DeploymentRun.from_dict(payload)
        if run.state != DeploymentState.AWAITING_APPROVAL:
            raise DeploymentActionError("Only an AWAITING_APPROVAL run can be approved.")
        if not approved_by.strip():
            raise DeploymentActionError("approved_by is required.")
        if artifact_hash != run.artifact_hash or plan_hash != run.plan_hash:
            raise DeploymentActionError("Approval hashes do not match the immutable dry-run snapshot.")
        from datetime import datetime, timezone
        run.approval = {
            "requested_by": run.requested_by,
            "approved_by": approved_by.strip(),
            "approved_at": datetime.now(timezone.utc).isoformat(),
            "artifact_hash": artifact_hash,
            "plan_hash": plan_hash,
        }
        run.move(DeploymentState.APPROVED)
        run.add_log(f"APPROVED: deployment approved by {approved_by.strip()} for artifact {artifact_hash[:12]}.")
        self.store.save(run)
        return run

    @staticmethod
    def _blocked_terraform(error):
        """Wrap a refusal reason as a BLOCKED terraform result (or pass None)."""
        if error is None:
            return None
        return {
            "status": "BLOCKED",
            "error": error,
            "executed": False,
            "replanned_after_approval": False,
            "plan_source": "approved",
        }

    def _verify_approved_plan_recoverable(
        self, workspace, approved_hash, approved_profile=""
    ):
        """Return a refusal reason, or None when the approved plan is intact.

        Checked before anything is applied, and deliberately strict: a
        missing or altered approval workspace means the approved plan no
        longer exists, which is a reason to stop, never a reason to make
        a new one.
        """
        if not approved_hash:
            return (
                "The approval record carries no saved plan hash, so the "
                "approved plan cannot be proven."
            )
        if not workspace:
            return "The approved plan workspace is not recorded on this run."
        if not Path(workspace).is_dir():
            return (
                "The approved plan workspace no longer exists; re-run the "
                "dry run to obtain a fresh approval."
            )
        try:
            actual = hash_plan_artifact(workspace, str(Path(workspace, PLAN_FILENAME)))
        except PlanArtifactError as exc:
            return f"The approved plan artifact is unusable: {exc}"
        if actual != approved_hash:
            return (
                "The saved Terraform plan no longer matches the approved "
                "plan hash; refusing to apply a plan that was not approved."
            )
        # Workstream F: the credential context in force at execution must
        # be the one that was approved. Switching credentials on (or
        # changing the credential set) after approval materially changes
        # what the apply can reach, so it is rejected rather than merged.
        current_profile = credential_profile_identity()
        if approved_profile and approved_profile != current_profile:
            return (
                "The credential profile changed after approval "
                f"(approved {approved_profile!r}, now {current_profile!r}); "
                "refusing to execute under a different credential context."
            )
        return None

    def _require_execution_enabled(self) -> None:
        if os.getenv("DEPLOYMENT_EXECUTION_ENABLED", "false").lower() != "true":
            raise DeploymentActionError("Real deployment execution is disabled. Set DEPLOYMENT_EXECUTION_ENABLED=true only after explicit runtime credentials are provisioned.")

    def _rollback(self, run, temp_dir, namespace, deployment_names, previous_good_terraform_tf):
        run.move(DeploymentState.ROLLBACK_PENDING)
        run.add_log("ROLLBACK_PENDING: attempting deterministic rollback.")
        results = []
        for name in deployment_names:
            results.append({"component": f"kubernetes:{name}", "result": self.kubectl.rollout_undo(
                name, namespace,
                approved_identity=self._approved_kubernetes_identity(run))})

        if run.execution.get("terraform_applied"):
            if not previous_good_terraform_tf.strip():
                results.append({"component": "terraform", "result": {"status": "BLOCKED", "error": "No previous known-good Terraform configuration was supplied."}})
            else:
                rollback_dir = Path(temp_dir, "rollback")
                rollback_dir.mkdir(parents=True, exist_ok=True)
                previous_path = rollback_dir / "main.tf"
                previous_path.write_text(previous_good_terraform_tf, encoding="utf-8")
                plan_path = rollback_dir / "rollback.tfplan"
                plan = self.terraform.run_plan(str(rollback_dir), execution=True, plan_output_path=str(plan_path))
                results.append({
                    "component": "terraform",
                    "result": plan if plan.get("status") != "PASS" else self.terraform.apply_plan(
                        str(rollback_dir),
                        str(plan_path),
                        expected_plan_file_hash=plan.get("plan_file_hash", ""),
                    ),
                })

        failed = [r for r in results if (r.get("result") or {}).get("status") != "PASS"]
        run.rollback = {"status": "PASS" if not failed else "FAIL", "components": results}
        if failed:
            run.move(DeploymentState.ROLLBACK_FAILED)
            run.add_log("ROLLBACK_FAILED: one or more components could not be restored.")
        else:
            run.move(DeploymentState.ROLLED_BACK)
            run.add_log("ROLLED_BACK: all rollback components reported success.")
        self.store.save(run)
        return run

    def execute(self, run_id: str, payload: Dict[str, Any], artifact_hash: str, plan_hash: str, namespace="devops-production-namespace", healthcheck_url="", previous_good_terraform_tf=""):
        self._require_execution_enabled()
        stored = self.store.get(run_id)
        if not stored:
            raise DeploymentActionError("Deployment run not found.")
        run = DeploymentRun.from_dict(stored)
        if run.state != DeploymentState.APPROVED:
            raise DeploymentActionError("Only an APPROVED deployment can execute.")
        if run.approval.get("artifact_hash") != artifact_hash or run.approval.get("plan_hash") != plan_hash:
            raise DeploymentActionError("Execution hashes do not match the approval record.")
        # Phase 6.5.2 corrective — deterministically derive the SAME
        # effective payload (caller artifacts + THIS run's authoritative
        # identity) and compare its hash to the approved artifact hash.
        # One artifact representation crosses the approval boundary: this
        # exact payload is written to disk and applied without any
        # post-approval mutation.
        effective_payload = self._effective_payload(
            payload, run.id, run.source_revision.get("head_sha", "")
        )
        if self._artifact_hash(effective_payload) != artifact_hash:
            raise DeploymentActionError("Submitted artifacts do not match the immutable approved artifact hash.")
        if not self.store.acquire_lock(run.id):
            raise DeploymentActionError("Deployment is already executing.")

        # The Kubernetes manifest still needs an ephemeral workspace, but
        # Terraform does NOT: it reuses the exact approval workspace that
        # already holds the approved plan.
        temp_dir = self._new_workspace(f"devops-exec-{run.id}-")
        approved = run.terraform_plan or {}
        approved_plan_hash = approved.get("plan_file_hash", "")
        tf_workspace = approved.get("approval_workspace", "")
        deployment_names = self._deployment_names(effective_payload.get("k8s_yaml", ""))
        try:
            run.move(DeploymentState.DEPLOYING)
            run.add_log("DEPLOYING: starting controlled Terraform and Kubernetes execution.")
            paths = self._write_iac(effective_payload, temp_dir)

            # ---- Phase 8.5-A corrective, Workstream D ----------------
            # Execution applies the EXACT artifact that was approved. It
            # does not re-plan: a second plan could legitimately differ
            # from the approved one (drift, provider behaviour, time) and
            # the approval would then be meaningless.
            blocked = self._blocked_terraform(
                self._verify_approved_plan_recoverable(
                    tf_workspace,
                    approved_plan_hash,
                    approved.get("credential_profile_id", ""),
                )
            )
            if blocked is None:
                init = self.terraform.initialize(tf_workspace)
                run.execution["terraform_init"] = init
                blocked = (
                    None
                    if init.get("status") == "PASS"
                    else self._blocked_terraform(
                        "Terraform initialization of the approved workspace "
                        f"failed ({init.get('status')})."
                    )
                )
            if blocked is not None:
                run.execution["terraform_plan"] = blocked
                run.error = blocked["error"]
                run.move(DeploymentState.DEPLOYMENT_FAILED)
                run.add_log(
                    "DEPLOYMENT_FAILED: the approved Terraform plan could not "
                    "be recovered and verified; nothing was applied."
                )
                self.store.save(run)
                return run

            # Contract-preserving evidence: the plan recorded against the
            # execution IS the approved plan, explicitly marked as not
            # regenerated so an auditor can tell the difference.
            terraform_plan = dict(approved)
            terraform_plan["replanned_after_approval"] = False
            terraform_plan["plan_source"] = "approved"
            run.execution["terraform_plan"] = terraform_plan
            run.execution["approved_plan_hash"] = approved_plan_hash

            terraform_apply = self.terraform.apply_plan(
                tf_workspace,
                str(Path(tf_workspace, PLAN_FILENAME)),
                expected_plan_file_hash=approved_plan_hash,
            )
            run.execution["applied_plan_hash"] = terraform_apply.get(
                "plan_file_hash", ""
            )
            run.execution["terraform_apply"] = terraform_apply
            run.execution["terraform_applied"] = terraform_apply.get("status") == "PASS"
            if not run.execution["terraform_applied"]:
                run.error = "Terraform apply failed."
                run.move(DeploymentState.DEPLOYMENT_FAILED)
                return self._rollback(run, temp_dir, namespace, deployment_names, previous_good_terraform_tf)

            # Phase 6.5.2 corrective — the manifest file written above IS
            # the approved artifact (identity already bound in
            # create_dry_run); apply it byte-for-byte with no further
            # mutation after the hash check.
            approved_k8s_identity = self._approved_kubernetes_identity(run)
            kubernetes_apply = (
                self.kubectl.apply(paths["kubernetes"], namespace,
                                   approved_identity=approved_k8s_identity)
                if self._kubernetes_is_declared(effective_payload)
                else self._kubernetes_not_applicable()
            )
            run.execution["kubernetes_apply"] = kubernetes_apply
            run.execution["kubernetes_applied"] = kubernetes_apply.get("status") in ("PASS", "SKIPPED")
            if not run.execution["kubernetes_applied"]:
                run.error = "Kubernetes apply failed."
                run.move(DeploymentState.DEPLOYMENT_FAILED)
                return self._rollback(run, temp_dir, namespace, deployment_names, previous_good_terraform_tf)

            run.move(DeploymentState.HEALTH_CHECKING)
            run.add_log("HEALTH_CHECKING: verifying rollout and optional HTTP readiness.")
            run.health_check = self.health_checker.check(self.kubectl, deployment_names, namespace, healthcheck_url)
            if run.health_check.get("status") != "PASS":
                run.error = "Post-deployment health verification failed."
                run.move(DeploymentState.DEPLOYMENT_FAILED)
                return self._rollback(run, temp_dir, namespace, deployment_names, previous_good_terraform_tf)

            run.move(DeploymentState.DEPLOYED)
            run.add_log("DEPLOYED: execution and deterministic health verification succeeded.")
            self.store.save(run)
            return run
        except Exception as exc:
            run.error = type(exc).__name__
            if run.state in {DeploymentState.DEPLOYING, DeploymentState.HEALTH_CHECKING}:
                run.move(DeploymentState.DEPLOYMENT_FAILED)
            if run.execution.get("terraform_applied") or run.execution.get("kubernetes_applied"):
                return self._rollback(run, temp_dir, namespace, deployment_names, previous_good_terraform_tf)
            self.store.save(run)
            return run
        finally:
            self.store.release_lock(run.id)
            shutil.rmtree(temp_dir, ignore_errors=True)
            # A saved plan is sensitive and single-use: once the run has
            # reached a terminal state it can never be applied again, so
            # the approval workspace is destroyed.
            if run.state in _TERMINAL_STATES:
                self._discard_approval_workspace(run.id)
