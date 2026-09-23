
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from application.services.deployment_engine import DeploymentActionError, DeploymentEngine

app = FastAPI(title="DevOps.AI Deployment Engine", version="2.0.0")
engine = DeploymentEngine()


class DryRunRequest(BaseModel):
    repository_id: int
    repository_name: str
    requested_by: str = ""
    dockerfile: str
    k8s_yaml: str
    terraform_tf: str
    pipeline_yaml: str


class ApprovalRequest(BaseModel):
    approved_by: str = Field(min_length=1)
    artifact_hash: str = Field(min_length=64, max_length=64)
    plan_hash: str = Field(min_length=64, max_length=64)


class ExecuteRequest(BaseModel):
    artifact_hash: str = Field(min_length=64, max_length=64)
    plan_hash: str = Field(min_length=64, max_length=64)
    namespace: str = "devops-production-namespace"
    healthcheck_url: str = ""
    previous_good_terraform_tf: str = ""
    dockerfile: str
    k8s_yaml: str
    terraform_tf: str
    pipeline_yaml: str


@app.get("/health")
def health():
    return {"status": "healthy", "service": "deployment-service", "version": "2.0.0",
            "execution_enabled": __import__("os").getenv("DEPLOYMENT_EXECUTION_ENABLED", "false").lower() == "true"}


@app.post("/api/internal/deployments/dry-run")
def dry_run(request: DryRunRequest):
    return engine.create_dry_run(request.model_dump()).to_dict()


@app.get("/api/internal/deployments/{run_id}")
def get_run(run_id: str):
    payload = engine.store.get(run_id)
    if not payload:
        raise HTTPException(status_code=404, detail="Deployment run not found")
    return payload


@app.post("/api/internal/deployments/{run_id}/approve")
def approve(run_id: str, request: ApprovalRequest):
    try:
        return engine.approve(run_id, request.approved_by, request.artifact_hash, request.plan_hash).to_dict()
    except DeploymentActionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/internal/deployments/{run_id}/execute")
def execute(run_id: str, request: ExecuteRequest):
    try:
        return engine.execute(run_id, request.model_dump(), request.artifact_hash, request.plan_hash, request.namespace, request.healthcheck_url, request.previous_good_terraform_tf).to_dict()
    except DeploymentActionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
