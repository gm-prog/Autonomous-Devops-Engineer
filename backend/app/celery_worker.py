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
    logger.info(f"Starting async Repository Analysis task for ID: {repo_id}")
    db = SessionLocal()
    try:
        repo = db.query(Repository).filter(Repository.id == repo_id).first()
        if not repo:
            logger.error(f"Repository not found in DB: Error ID {repo_id}")
            return
        
        # Simulated 5-second intense source analysis
        time.sleep(1)
        repo.dockerfile = f"""# Multi-Stage Build Pipeline targetting {repo.framework} 
FROM python:3.12-alpine as builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt --target /dependencies

FROM python:3.12-alpine
WORKDIR /app
COPY --from=builder /dependencies /usr/local/lib/python3.12/site-packages
COPY . .
EXPOSE 8080
USER 10001
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
"""
        
        repo.k8s_yaml = f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: {repo.name}-deployment
  labels:
    app: {repo.name}
spec:
  replicas: 3
  selector:
    matchLabels:
      app: {repo.name}
  template:
    metadata:
      labels:
        app: {repo.name}
    spec:
      containers:
      - name: app
        image: devops-registry/{repo.name}:latest
        ports:
        - containerPort: 8080
        resources:
          limits:
            cpu: "500m"
            memory: "512Mi"
          requests:
            cpu: "200m"
            memory: "256Mi"
"""
        
        repo.terraform_tf = f"""module "ecs_service" {{
  source  = "terraform-aws-modules/ecs/aws"
  version = "~> 5.0"

  name = "{repo.name}-cluster"

  fargate_capacity_providers = {{
    FARGATE = {{
      default_capacity_provider_strategy = {{
        weight = 100
      }}
    }}
  }}
}}
"""
        
        repo.pipeline_yaml = f"""name: CI/CD Pipeline
on: [push]
jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Set up Qemu
      uses: docker/setup-qemu-action@v2
    - name: Push Container
      run: |
        docker build -t devops-registry/{repo.name}:latest .
        docker push devops-registry/{repo.name}:v1.0.0
"""
        
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
