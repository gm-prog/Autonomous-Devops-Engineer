# DevOps.AI Operator Platform - repo_service
# Build context: devops-ai-platform/  (see docker-compose.yml)
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

EXPOSE 8010

CMD ["uvicorn", "repo_service.main:app", "--host", "0.0.0.0", "--port", "8010"]
