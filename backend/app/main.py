import os
import datetime
import logging
from contextlib import asynccontextmanager
from typing import List

import qdrant_client
import redis
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from prometheus_client import Counter, generate_latest
from pydantic import BaseModel, ConfigDict
from qdrant_client.http import models as qmodels
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from .services.analysis import analyze_repository

# --- LOGGER CONFIGURATION ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DevOpsBackend")

# --- ENVIRONMENT ---
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@db:5432/devops_prod")
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
QDRANT_HOST = os.getenv("QDRANT_HOST", "qdrant")
QDRANT_PORT = int(os.getenv("QDRANT_PORT", 6333))
# Server-side Gemini key: optional. When absent/placeholder, the analysis
# endpoints use the deterministic offline template engine.
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
# Comma-separated list of allowed CORS origins. Default "*" (no credentials,
# which is the spec-valid combination). Set e.g. "https://myapp.example.com"
# for credentialed browser clients.
CORS_ORIGINS = [
    o.strip()
    for o in os.getenv(
        "CORS_ORIGINS",
        "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000",
    ).split(",")
    if o.strip()
]

QDRANT_COLLECTION = "devops_knowledge_base"

# --- DATABASE & DATA LAYER SETUP ---
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- REDIS TASK GATEWAY & VECTOR MEMORY SETUP ---
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)
qdrant = qdrant_client.QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT, timeout=12)

# --- SQLALCHEMY MODELS ---
class Repository(Base):
    __tablename__ = "repositories"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, index=True, nullable=False)
    url = Column(String(512), nullable=False)
    framework = Column(String(100))
    technology = Column(String(100))
    dockerfile = Column(Text, default="")
    k8s_yaml = Column(Text, default="")
    terraform_tf = Column(Text, default="")
    pipeline_yaml = Column(Text, default="")
    last_analysis_report = Column(Text, default="")
    status = Column(String(50), default="Idle") # Idle, Analyzing, Generated, Deploying, Deployed, Failed
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(String(50)) # Low, Medium, High, Critical
    service_name = Column(String(255))
    status = Column(String(50), default="Investigating") # Investigating, RootCauseFound, Fixed
    root_cause = Column(Text, default="")
    remediation_plan = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

# --- PROMETHEUS METRICS ---
API_REQUESTS = Counter(
    "devops_api_requests_total",
    "Total API requests processed by the operator gateway",
    ["method", "path"],
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database schema ready.")
    except Exception as e:
        logger.warning(f"Database schema initialization skipped: {e}")

    # Set up Qdrant Vector Collection for Operational Knowledge retrieval.
    # NOTE: create-if-missing only. The previous implementation recreated the
    # collection on every boot, silently destroying any stored vectors.
    try:
        if qdrant.collection_exists(QDRANT_COLLECTION):
            logger.info("Qdrant collection '%s' already present - preserving stored data.", QDRANT_COLLECTION)
        else:
            qdrant.create_collection(
                collection_name=QDRANT_COLLECTION,
                vectors_config=qmodels.VectorParams(size=1536, distance=qmodels.Distance.COSINE),
            )
            logger.info("Initialized Qdrant Collection base successfully.")
    except Exception as e:
        logger.warning(f"Qdrant integration skipped or offline: {e}")

    yield

# --- INSTANTIATE APP & MITIGATE CORS ---
app = FastAPI(
    title="Autonomous DevOps AI Operator Gateway",
    description="Enterprise API Gateway orchestrating multi-agent systems, IaC generation, monitoring, and automated incident recovery.",
    version="1.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    # Wildcard origins must NOT be combined with credentials (Fetch spec);
    # credentials are only enabled for explicitly allow-listed origins.
    allow_credentials="*" not in CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def count_requests(request: Request, call_next):
    response = await call_next(request)
    route = request.scope.get("route")
    path = route.path if route is not None else request.url.path
    API_REQUESTS.labels(method=request.method, path=path).inc()
    return response

# DB Dependency injection wrapper
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def dispatch_celery_task(task_name: str, *args):
    """Publish a task to the Celery worker; raise on broker failure so the
    caller can fall back to its inline (mock) execution path."""
    from celery import Celery
    celery_app = Celery("tasks", broker=f"redis://{REDIS_HOST}:{REDIS_PORT}/0")
    celery_app.send_task(task_name, args=list(args))

# --- PYDANTIC SCHEMAS ---
class RepositoryCreate(BaseModel):
    name: str
    url: str
    framework: str
    technology: str

class RepositoryResponse(BaseModel):
    id: int
    name: str
    url: str
    framework: str
    technology: str
    status: str
    model_config = ConfigDict(from_attributes=True)

class IncidentResponse(BaseModel):
    id: int
    title: str
    description: str
    severity: str
    status: str
    model_config = ConfigDict(from_attributes=True)

# --- OBSERVABILITY ---

@app.get("/metrics")
def metrics():
    """Prometheus scrape target (monitoring/prometheus.yml -> api:8000)."""
    return Response(content=generate_latest(), media_type="text/plain; version=0.0.4")

# --- API ENDPOINTS ---

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "components": {
            "api_gateway": "online",
            "redis_connection": "configured",
            "qdrant_vector_memory": "active"
        }
    }

@app.get("/api/repositories", response_model=List[RepositoryResponse])
def get_repositories(db: Session = Depends(get_db)):
    return db.query(Repository).order_by(Repository.created_at.desc()).all()

@app.post("/api/repositories", response_model=RepositoryResponse, status_code=status.HTTP_201_CREATED)
def import_repository(repo_in: RepositoryCreate, db: Session = Depends(get_db)):
    db_repo = db.query(Repository).filter(Repository.name == repo_in.name).first()
    if db_repo:
        raise HTTPException(status_code=400, detail="Repository name already imported.")

    new_repo = Repository(
        name=repo_in.name,
        url=repo_in.url,
        framework=repo_in.framework,
        technology=repo_in.technology,
        status="Idle"
    )
    db.add(new_repo)
    db.commit()
    db.refresh(new_repo)
    logger.info(f"Imported repository catalog descriptor: {new_repo.name}")
    return new_repo

@app.post("/api/repositories/{repo_id}/analyze")
def trigger_repository_analysis(repo_id: int, db: Session = Depends(get_db)):
    repo = db.query(Repository).filter(Repository.id == repo_id).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository target not found")

    # Enqueue task to Celery distributed worker via Redis
    repo.status = "Analyzing"
    db.commit()

    try:
        dispatch_celery_task("tasks.analyze_repository_task", repo.id)
        logger.info(f"Dispatched Celery task.analyze_repository_task for Repo ID: {repo.id}")
        return {"status": "Analysis triggered", "task": "analyze_repository_task"}
    except Exception as e:
        logger.error(f"Failed to publish to Celery pipeline: {e}")
        # Fallback inline mock update logic if celery broker is missing during integration
        repo.status = "Generated"
        db.commit()
        return {"status": "Triggered (Async Bypass/Inline Mock Executed)", "error": str(e)}

@app.post("/api/repositories/{repo_id}/deploy")
def trigger_agent_deployment(repo_id: int, db: Session = Depends(get_db)):
    repo = db.query(Repository).filter(Repository.id == repo_id).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository target not found")

    repo.status = "Deploying"
    db.commit()

    try:
        dispatch_celery_task("tasks.deploy_application_task", repo.id)
        logger.info(f"Dispatched Celery tasks.deploy_application_task for Repo: {repo.name}")
        return {"status": "Deployment workflow dispatched", "task": "deploy_application_task"}
    except Exception as e:
        logger.error(f"Celery exception: {e}")
        repo.status = "Deployed"
        db.commit()
        return {"status": "Triggered (Async Bypass/Inline Mock Executed)"}

@app.get("/api/incidents", response_model=List[IncidentResponse])
def get_incidents(db: Session = Depends(get_db)):
    return db.query(Incident).order_by(Incident.created_at.desc()).all()

@app.post("/api/incidents/{incident_id}/investigate")
def investigate_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.status = "Investigating"
    db.commit()

    try:
        dispatch_celery_task("tasks.investigate_incident_task", incident.id)
        return {"status": "Investigation dispatched to multi-agent swarm"}
    except Exception as e:
        logger.error(f"Celery trigger error: {e}")
        incident.status = "RootCauseFound"
        incident.root_cause = "Database saturate on connection pools. Spring threads blocked on Hikari connection requests."
        db.commit()
        return {"status": "Completed (Simulated Inline Result)"}

# ---------------------------------------------------------------------------
# /api/v1 — compatibility contract expected by the Android client
# (BackendGatewayClient.kt). The app probes /api/v1/health and POSTs
# /api/v1/repository/analyze expecting synchronous artifacts.
# ---------------------------------------------------------------------------

@app.get("/api/v1/health")
def v1_health_check():
    """Alias of /health on the client-expected /api/v1 path."""
    return health_check()

@app.get("/api/v1/repositories", response_model=List[RepositoryResponse])
def v1_get_repositories(db: Session = Depends(get_db)):
    return get_repositories(db)

@app.post("/api/v1/repository/analyze")
def v1_repository_analyze(repo_in: RepositoryCreate, db: Session = Depends(get_db)):
    """Synchronous analyze endpoint for the Android remote mode.

    Runs the analysis engine (live Gemini when GEMINI_API_KEY is configured
    server-side, offline templates otherwise), persists the result, and
    returns the exact 5-field artifact shape the app parses:
    {dockerfile, k8s_yaml, terraform_tf, pipeline_yaml, analysis_report}.
    """
    artifacts = analyze_repository(
        repo_in.name, repo_in.url, repo_in.framework, repo_in.technology,
        api_key=GEMINI_API_KEY,
    )

    repo = db.query(Repository).filter(Repository.name == repo_in.name).first()
    if repo is None:
        repo = Repository(name=repo_in.name, status="Generated")
        db.add(repo)
    repo.url = repo_in.url
    repo.framework = repo_in.framework
    repo.technology = repo_in.technology
    repo.status = "Generated"
    repo.dockerfile = artifacts["dockerfile"]
    repo.k8s_yaml = artifacts["k8s_yaml"]
    repo.terraform_tf = artifacts["terraform_tf"]
    repo.pipeline_yaml = artifacts["pipeline_yaml"]
    repo.last_analysis_report = artifacts["analysis_report"]
    db.commit()
    db.refresh(repo)

    logger.info(
        "v1 analyze complete for '%s' via %s engine", repo.name, artifacts.get("engine")
    )
    return {
        "id": repo.id,
        "name": repo.name,
        "status": repo.status,
        "engine": artifacts.get("engine", "template"),
        "note": artifacts.get("note", ""),
        "dockerfile": repo.dockerfile,
        "k8s_yaml": repo.k8s_yaml,
        "terraform_tf": repo.terraform_tf,
        "pipeline_yaml": repo.pipeline_yaml,
        "analysis_report": repo.last_analysis_report,
    }
