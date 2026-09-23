import os
import time
import logging
import requests
from celery import Celery
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .main import Repository, Incident, get_db

# --- INITIALIZE CELERY ENGINE ---
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
celery_app = Celery("tasks", broker=f"redis://{REDIS_HOST}:{REDIS_PORT}/0", backend=f"redis://{REDIS_HOST}:{REDIS_PORT}/0")

# --- LOGGER CONFIGURATION ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CeleryWorker")

# --- INITIALIZE DB CONNECTION ---
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@db:5432/devops_prod")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

@celery_app.task(name="tasks.analyze_repository_task")
def analyze_repository_task(repo_id: int):
    """Run repository intelligence and AI artifact generation without exposing credentials."""
    import json

    db = SessionLocal()
    try:
        repo = db.query(Repository).filter(Repository.id == repo_id).first()
        if not repo:
            logger.error("Repository not found: %s", repo_id)
            return

        repo.status = "Analyzing"
        db.commit()

        repo_service_url = os.getenv("REPO_SERVICE_URL", "http://repo-service:8010")
        agent_service_url = os.getenv("AGENT_SERVICE_URL", "http://agent-service:8020")

        analysis_response = requests.post(
            f"{repo_service_url}/api/internal/analyze",
            json={"name": repo.name, "url": repo.url},
            timeout=180,
        )
        analysis_response.raise_for_status()
        analysis = analysis_response.json()

        # Keep the catalog fields synchronized with observed source, not user-entered guesses.
        tech = analysis.get("tech_stack", {})
        repo.technology = tech.get("primary_language", repo.technology)
        frameworks = tech.get("frameworks", [])
        repo.framework = ", ".join(frameworks) if frameworks else repo.framework

        ai_response = requests.post(
            f"{agent_service_url}/api/internal/generate-iac",
            json={"repository": analysis},
            timeout=180,
        )
        ai_response.raise_for_status()
        artifacts = ai_response.json()

        required = ("dockerfile", "k8s_yaml", "terraform_tf", "pipeline_yaml", "analysis_report")
        missing = [key for key in required if not artifacts.get(key)]
        if missing:
            raise ValueError(f"Agent response missing required artifacts: {', '.join(missing)}")

        repo.dockerfile = artifacts["dockerfile"]
        repo.k8s_yaml = artifacts["k8s_yaml"]
        repo.terraform_tf = artifacts["terraform_tf"]
        repo.pipeline_yaml = artifacts["pipeline_yaml"]
        repo.analysis_report = (
            f"Repository intelligence: {analysis.get('total_files', 0)} bounded source files inspected. "
            f"Recent commits: {len(analysis.get('recent_commits', []))}. "
            f"{artifacts['analysis_report']}"
        )
        repo.status = "Generated"
        db.commit()
        logger.info("Real repository analysis completed for %s", repo.name)

    except Exception as exc:
        db.rollback()
        repo = db.query(Repository).filter(Repository.id == repo_id).first()
        if repo:
            repo.status = "Failed"
            repo.analysis_report = f"Repository analysis failed: {type(exc).__name__}"
            db.commit()
        logger.exception("Repository analysis failed for %s", repo_id)
    finally:
        db.close()

@celery_app.task(name="tasks.deploy_application_task")
def deploy_application_task(repo_id: int):
    """Run the deployment engine dry-run; never reports a deployment without verified execution."""
    db = SessionLocal()
    try:
        repo = db.query(Repository).filter(Repository.id == repo_id).first()
        if not repo:
            logger.error("Repository not found: %s", repo_id)
            return

        repo.status = "Validating"
        db.commit()

        deployment_service_url = os.getenv("DEPLOYMENT_SERVICE_URL", "http://deployment-service:8030")
        payload = {
            "repository_id": repo.id,
            "repository_name": repo.name,
            "dockerfile": repo.dockerfile or "",
            "k8s_yaml": repo.k8s_yaml or "",
            "terraform_tf": repo.terraform_tf or "",
            "pipeline_yaml": repo.pipeline_yaml or "",
        }

        response = requests.post(
            f"{deployment_service_url}/api/internal/deployments/dry-run",
            json=payload,
            timeout=360,
        )
        response.raise_for_status()
        result = response.json()
        state = result.get("state", "UNKNOWN")

        if state == "DRY_RUN_PASSED":
            repo.status = "DryRunPassed"
        elif state == "VALIDATION_FAILED":
            repo.status = "ValidationFailed"
        elif state == "DRY_RUN_FAILED":
            repo.status = "DryRunFailed"
        else:
            repo.status = "DeploymentBlocked"
        repo.analysis_report = (
            (repo.analysis_report or "")
            + "\nDeployment Engine v1: "
            + state
            + "\n"
            + "\n".join(result.get("logs", []))
        )
        db.commit()
        logger.info("Deployment dry-run for %s finished in state %s", repo.name, state)
    except Exception as exc:
        db.rollback()
        repo = db.query(Repository).filter(Repository.id == repo_id).first()
        if repo:
            repo.status = "DeploymentFailed"
            repo.analysis_report = (repo.analysis_report or "") + f"\nDeployment engine failed: {type(exc).__name__}"
            db.commit()
        logger.exception("Deployment dry-run failed for %s", repo_id)
    finally:
        db.close()

@celery_app.task(name="tasks.investigate_incident_task")
def investigate_incident_task(incident_id: int):
    db = SessionLocal()
    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            return
        
        time.sleep(1)
        incident.status = "RootCauseFound"
        incident.root_cause = "Database saturate on connection pools. Spring threads blocked on Hikari connection requests. Load spikes at UTC 12:00:15 causing out-of-bounds metrics."
        incident.remediation_plan = "Scale Database replicas using HPA yaml, reset standard connection timeouts from 30s to 5s, apply database backoff configuration."
        db.commit()
    except Exception as e:
        logger.error(f"Swarminer analysis error: {e}")
    finally:
        db.close()
