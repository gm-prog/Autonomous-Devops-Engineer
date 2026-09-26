
import re

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator

from deployment_service.application.services.deployment_engine import DeploymentActionError, DeploymentEngine

app = FastAPI(title="DevOps.AI Deployment Engine", version="2.0.0")
engine = DeploymentEngine()

# Canonical identities accepted at the deployment HTTP boundary. The exact
# same semantics are enforced later by remediation target binding, so a
# request that could never authorize remediation is rejected up front.
_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
STRONG_SLUG_PATTERN = (
    r"(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+"
    r"/(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+"
)
_SLUG_PATTERN = re.compile(r"^(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+/(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+$")  # python-re (lookahead ok)


class SourceRevision(BaseModel):
    """Exact immutable source revision being deployed.

    The HTTP contract is strict on purpose: no branch names, no tags, no
    short SHAs, no alternate mutable fields. Unknown keys inside
    ``source_revision`` are dropped (never persisted), so the engine can
    only ever see this declared contract.
    """

    head_sha: str = Field(pattern=r"^[0-9a-fA-F]{40}$")
    commits: list = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)

    @field_validator("head_sha", mode="before")
    @classmethod
    def _normalize_head_sha(cls, value):
        # strip surrounding whitespace (permitted by the binding contract)
        # and persist the canonical lowercase form end-to-end.
        if isinstance(value, str):
            return value.strip().lower()
        return value


class DryRunRequest(BaseModel):
    repository_id: int
    # canonical owner/repository identity - bare names and dot-only segments
    # rejected here (pydantic's regex has no lookahead, so this is a validator)
    repository_name: str
    requested_by: str = ""
    dockerfile: str
    k8s_yaml: str
    terraform_tf: str
    pipeline_yaml: str
    # required: the deployment must identify the exact revision deployed
    source_revision: SourceRevision

    @field_validator("repository_name")
    @classmethod
    def _canonical_repository_name(cls, value: str) -> str:
        if not re.fullmatch(STRONG_SLUG_PATTERN, value):
            raise ValueError(
                "repository_name must be canonical owner/repository "
                "(alphanumeric segments; bare names and path tricks rejected)"
            )
        return value


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
    # model_dump() carries the validated canonical source_revision straight
    # into the engine - no inference, no alternate fields, lowercase SHA.
    payload = request.model_dump()
    assert _SHA_PATTERN.fullmatch(payload["source_revision"]["head_sha"])
    assert _SLUG_PATTERN.fullmatch(payload["repository_name"])
    return engine.create_dry_run(payload).to_dict()


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
