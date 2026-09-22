
import hashlib
import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List

import yaml

from application.services.health_check_service import HealthCheckService
from application.services.iac_validator import IaCValidator
from application.services.kubectl_runner import KubectlRunnerService
from application.services.terraform_runner import TerraformRunnerService
from domain.entities.deployment_run import DeploymentRun
from domain.value_objects.deployment_state import DeploymentState
from infrastructure.persistence.redis_pipeline_store import RedisPipelineStore


class DeploymentActionError(RuntimeError):
    pass


class DeploymentEngine:
    def __init__(self, store=None, validator=None, terraform=None, kubectl=None, health_checker=None):
        self.store = store or RedisPipelineStore()
        self.validator = validator or IaCValidator()
        self.terraform = terraform or TerraformRunnerService()
        self.kubectl = kubectl or KubectlRunnerService()
        self.health_checker = health_checker or HealthCheckService()

    @staticmethod
    def _artifact_hash(payload: Dict[str, Any]) -> str:
        bundle = {k: payload.get(k, "") for k in ("dockerfile", "k8s_yaml", "terraform_tf", "pipeline_yaml")}
        return hashlib.sha256(json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    @staticmethod
    def _plan_hash(artifact_hash: str, terraform_result: Dict[str, Any], kubernetes_result: Dict[str, Any]) -> str:
        material = {
            "artifact_hash": artifact_hash,
            "terraform": {"status": terraform_result.get("status"), "stdout": terraform_result.get("plan", {}).get("stdout", "")},
            "kubernetes": {"status": kubernetes_result.get("status"), "stdout": kubernetes_result.get("stdout", "")},
        }
        return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

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

    def create_dry_run(self, payload: Dict[str, Any]) -> DeploymentRun:
        run = DeploymentRun(
            id=f"run_{uuid.uuid4().hex[:12]}",
            repository_id=int(payload["repository_id"]),
            repository_name=payload["repository_name"],
            requested_by=payload.get("requested_by"),
        )
        run.move(DeploymentState.VALIDATING)
        run.add_log("VALIDATING: static IaC safety and syntax checks started.")
        run.validation = self.validator.validate(payload.get("dockerfile", ""), payload.get("k8s_yaml", ""), payload.get("terraform_tf", ""), payload.get("pipeline_yaml", ""))
        if run.validation["status"] == "FAIL":
            run.move(DeploymentState.VALIDATION_FAILED)
            run.add_log("VALIDATION_FAILED: blocking IaC checks detected.")
            self.store.save(run)
            return run

        run.move(DeploymentState.VALIDATED)
        run.move(DeploymentState.DRY_RUNNING)
        run.add_log("DRY_RUNNING: executing local Terraform plan and Kubernetes client-side dry-run.")
        self.store.save(run)

        temp_dir = tempfile.mkdtemp(prefix=f"devops-deploy-{run.id}-")
        try:
            paths = self._write_iac(payload, temp_dir)
            run.terraform_plan = self.terraform.run_plan(temp_dir, execution=False)
            run.kubernetes_dry_run = self.kubectl.dry_run(paths["kubernetes"])
            run.artifact_hash = self._artifact_hash(payload)
            run.plan_hash = self._plan_hash(run.artifact_hash, run.terraform_plan, run.kubernetes_dry_run)
            if run.terraform_plan["status"] == "PASS" and run.kubernetes_dry_run["status"] == "PASS":
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
            shutil.rmtree(temp_dir, ignore_errors=True)

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

    def _require_execution_enabled(self) -> None:
        if os.getenv("DEPLOYMENT_EXECUTION_ENABLED", "false").lower() != "true":
            raise DeploymentActionError("Real deployment execution is disabled. Set DEPLOYMENT_EXECUTION_ENABLED=true only after explicit runtime credentials are provisioned.")

    def _rollback(self, run, temp_dir, namespace, deployment_names, previous_good_terraform_tf):
        run.move(DeploymentState.ROLLBACK_PENDING)
        run.add_log("ROLLBACK_PENDING: attempting deterministic rollback.")
        results = []
        for name in deployment_names:
            results.append({"component": f"kubernetes:{name}", "result": self.kubectl.rollout_undo(name, namespace)})

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
                    "result": plan if plan.get("status") != "PASS" else self.terraform.apply_plan(str(rollback_dir), str(plan_path)),
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
        if self._artifact_hash(payload) != artifact_hash:
            raise DeploymentActionError("Submitted artifacts do not match the immutable approved artifact hash.")
        if not self.store.acquire_lock(run.id):
            raise DeploymentActionError("Deployment is already executing.")

        temp_dir = tempfile.mkdtemp(prefix=f"devops-exec-{run.id}-")
        deployment_names = self._deployment_names(payload.get("k8s_yaml", ""))
        try:
            run.move(DeploymentState.DEPLOYING)
            run.add_log("DEPLOYING: starting controlled Terraform and Kubernetes execution.")
            paths = self._write_iac(payload, temp_dir)
            terraform_plan = self.terraform.run_plan(temp_dir, execution=True, plan_output_path=paths["terraform_plan"])
            run.execution["terraform_plan"] = terraform_plan
            if terraform_plan.get("status") != "PASS":
                run.error = "Terraform execution plan failed."
                run.move(DeploymentState.DEPLOYMENT_FAILED)
                return self._rollback(run, temp_dir, namespace, deployment_names, previous_good_terraform_tf)

            terraform_apply = self.terraform.apply_plan(temp_dir, paths["terraform_plan"])
            run.execution["terraform_apply"] = terraform_apply
            run.execution["terraform_applied"] = terraform_apply.get("status") == "PASS"
            if not run.execution["terraform_applied"]:
                run.error = "Terraform apply failed."
                run.move(DeploymentState.DEPLOYMENT_FAILED)
                return self._rollback(run, temp_dir, namespace, deployment_names, previous_good_terraform_tf)

            kubernetes_apply = self.kubectl.apply(paths["kubernetes"], namespace)
            run.execution["kubernetes_apply"] = kubernetes_apply
            run.execution["kubernetes_applied"] = kubernetes_apply.get("status") == "PASS"
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
