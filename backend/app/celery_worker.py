import os
import time
import logging
from celery import Celery
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .main import Repository, Incident, get_db
from .services.analysis import generate_templates

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
    logger.info(f"Starting async Repository Analysis task for ID: {repo_id}")
    db = SessionLocal()
    try:
        repo = db.query(Repository).filter(Repository.id == repo_id).first()
        if not repo:
            logger.error(f"Repository not found in DB: Error ID {repo_id}")
            return
        
        # Simulated 5-second intense source analysis
        time.sleep(1)
        # Deterministic offline templates (shared with the sync /api/v1 engine)
        artifacts = generate_templates(repo.name, repo.framework, repo.technology)
        repo.dockerfile = artifacts["dockerfile"]
        repo.k8s_yaml = artifacts["k8s_yaml"]
        repo.terraform_tf = artifacts["terraform_tf"]
        repo.pipeline_yaml = artifacts["pipeline_yaml"]
        repo.last_analysis_report = artifacts["analysis_report"]
        repo.status = "Generated"
        db.commit()
        logger.info(f"Asynchronous code-gen completed successfully for {repo.name}")
        
    except Exception as e:
        logger.error(f"Error during repository evaluation task: {e}")
    finally:
        db.close()

@celery_app.task(name="tasks.deploy_application_task")
def deploy_application_task(repo_id: int):
    logger.info(f"Starting async Infrastructure deployment for Repository ID: {repo_id}")
    db = SessionLocal()
    try:
        repo = db.query(Repository).filter(Repository.id == repo_id).first()
        if not repo:
            return
        
        # Simulate deployment stage ticks with logs
        stages = [
            "Initiating connection to AWS Kubernetes Cluster control-plane VPC...",
            "Validating Terraform secrets configuration variables...",
            "Applying Terraform state blueprints to provision target infrastructure...",
            "Pushing compiled application container stages to cloud registry...",
            "Scheduling replica sets in EKS cluster namespace...",
            "Attaching target group metrics register nodes to Prometheus endpoint...",
            "Running network verification endpoint calls for stable handshake...",
            "SUCCESS: Autonomous Deployment Completed!"
        ]
        
        for stage in stages:
            logger.info(f"[{repo.name}] {stage}")
            time.sleep(0.5)

        repo.status = "Deployed"
        db.commit()
    except Exception as e:
        logger.error(f"Deployment runner error: {e}")
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
