
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from application.services.deployment_engine import DeploymentEngine
from domain.value_objects.deployment_state import DeploymentState

app = FastAPI(title="DevOps.AI Deployment Engine", version="1.0.0")
engine = DeploymentEngine()

class DryRunRequest(BaseModel):
    repository_id: int
    repository_name: str
    dockerfile: str
    k8s_yaml: str
    terraform_tf: str
    pipeline_yaml: str

@app.get("/health")
def health():
    return {"status": "healthy", "service": "deployment-service"}

@app.post("/api/internal/deployments/dry-run")
def dry_run(request: DryRunRequest):
    run = engine.create_dry_run(request.model_dump())
    return {
        "run_id": run.id,
        "repository_id": run.repository_id,
        "repository_name": run.repository_name,
        "state": run.state.value,
        "validation": run.validation,
        "terraform_plan": run.terraform_plan,
        "kubernetes_dry_run": run.kubernetes_dry_run,
        "logs": run.logs,
        "error": run.error,
    }

@app.get("/api/internal/deployments/{run_id}")
def get_run(run_id: str):
    payload = engine.store.get(run_id)
    if not payload:
        raise HTTPException(status_code=404, detail="Deployment run not found")
    return payload

@app.post("/api/internal/deployments/{run_id}/approve")
def approve(run_id: str):
    payload = engine.store.get(run_id)
    if not payload:
        raise HTTPException(status_code=404, detail="Deployment run not found")
    if payload["state"] != DeploymentState.DRY_RUN_PASSED.value:
        raise HTTPException(status_code=409, detail="Only a successful dry-run can be approved.")
    return {
        "run_id": run_id,
        "state": "APPROVAL_RECORDED",
        "message": "Approval recorded. Real apply remains disabled in Deployment Engine v1.",
    }
