# DevOps.AI Operator Platform - incident_service
# Build context: devops-ai-platform/  (see docker-compose.yml)
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

EXPOSE 8050

CMD ["uvicorn", "incident_service.main:app", "--host", "0.0.0.0", "--port", "8050"]
