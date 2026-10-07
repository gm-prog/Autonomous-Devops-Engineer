# DevOps.AI Operator Platform - agent_service
# Build context: devops-ai-platform/  (see docker-compose.yml)
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

EXPOSE 8020

CMD ["uvicorn", "agent_service.main:app", "--host", "0.0.0.0", "--port", "8020"]
