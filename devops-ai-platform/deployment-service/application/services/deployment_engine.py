
import shutil
import tempfile
import uuid
from pathlib import Path

from application.services.iac_validator import IaCValidator
from application.services.terraform_runner import TerraformRunnerService
from application.services.kubectl_runner import KubectlRunnerService
from domain.entities.deployment_run import DeploymentRun
from domain.value_objects.deployment_state import DeploymentState
from infrastructure.persistence.redis_pipeline_store import RedisPipelineStore

class DeploymentEngine:
    def __init__(self, store=None, validator=None, terraform=None, kubectl=None):
        self.store = store or RedisPipelineStore()
        self.validator = validator or IaCValidator()
        self.terraform = terraform or TerraformRunnerService()
        self.kubectl = kubectl or KubectlRunnerService()

    def create_dry_run(self, payload: dict) -> DeploymentRun:
        run = DeploymentRun(
            id=f"run_{uuid.uuid4().hex[:12]}",
            repository_id=int(payload["repository_id"]),
            repository_name=payload["repository_name"],
        )
        self.store.save(run)
        run.move(DeploymentState.VALIDATING)
        run.add_log("VALIDATING: static IaC safety and syntax checks started.")
        run.validation = self.validator.validate(
            payload.get("dockerfile", ""),
            payload.get("k8s_yaml", ""),
            payload.get("terraform_tf", ""),
            payload.get("pipeline_yaml", ""),
        )
        if run.validation["status"] == "FAIL":
            run.move(DeploymentState.VALIDATION_FAILED)
            run.add_log("VALIDATION_FAILED: blocking IaC checks detected.")
            self.store.save(run)
            return run

        run.move(DeploymentState.VALIDATED)
        run.add_log("VALIDATED: static IaC checks passed.")
        run.move(DeploymentState.DRY_RUNNING)
        run.add_log("DRY_RUNNING: executing real Terraform plan and Kubernetes client-side dry-run.")

        temp_dir = tempfile.mkdtemp(prefix=f"devops-deploy-{run.id}-")
        try:
            Path(temp_dir, "main.tf").write_text(payload.get("terraform_tf", ""), encoding="utf-8")
            Path(temp_dir, "deployment.yaml").write_text(payload.get("k8s_yaml", ""), encoding="utf-8")
            Path(temp_dir, "Dockerfile").write_text(payload.get("dockerfile", ""), encoding="utf-8")
            Path(temp_dir, "ci.yml").write_text(payload.get("pipeline_yaml", ""), encoding="utf-8")

            run.terraform_plan = self.terraform.run_plan(temp_dir)
            run.kubernetes_dry_run = self.kubectl.dry_run(str(Path(temp_dir, "deployment.yaml")))
            terraform_status = run.terraform_plan["status"]
            k8s_status = run.kubernetes_dry_run["status"]

            if terraform_status == "PASS" and k8s_status == "PASS":
                run.move(DeploymentState.DRY_RUN_PASSED)
                run.add_log("DRY_RUN_PASSED: Terraform plan and Kubernetes dry-run succeeded.")
            else:
                run.move(DeploymentState.DRY_RUN_FAILED)
                run.add_log(f"DRY_RUN_FAILED: Terraform={terraform_status}; Kubernetes={k8s_status}.")
            self.store.save(run)
            return run
        except Exception as exc:
            run.move(DeploymentState.DRY_RUN_FAILED, error=type(exc).__name__)
            run.add_log(f"DRY_RUN_FAILED: {type(exc).__name__}.")
            self.store.save(run)
            return run
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
