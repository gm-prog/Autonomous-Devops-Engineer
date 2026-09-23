# DevOps.AI Operator Platform - Deployment Service (Celery worker)
# Build context: devops-ai-platform/  (see docker-compose.yml)
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

# The celery app lives in the deployment_service package
CMD ["celery", "-A", "deployment_service.infrastructure.celery.tasks.celery_app", "worker", "--loglevel=info"]
