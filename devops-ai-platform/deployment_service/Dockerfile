# DevOps.AI Operator Platform - Deployment Service (Celery worker)
# Build context: devops-ai-platform/  (see docker-compose.yml)
FROM python:3.11-slim

WORKDIR /app

# Phase 8.8A: the sanctioned hash-pinned runtime lock — no broad
# requirements.txt, no unpinned transitive resolution at build time.
COPY requirements-runtime.txt /app/requirements-runtime.txt
RUN pip install --no-cache-dir --require-hashes -r requirements-runtime.txt

COPY . /app

# The celery app lives in the deployment_service package
CMD ["celery", "-A", "deployment_service.infrastructure.celery.tasks.celery_app", "worker", "--loglevel=info"]
