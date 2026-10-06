# DevOps.AI Operator Platform - API Gateway
# Build context: devops-ai-platform/  (see docker-compose.yml)
FROM python:3.11-slim

WORKDIR /app

# Install dependencies first for better layer caching
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the whole platform tree (services are sibling packages)
COPY . /app

EXPOSE 8000

CMD ["uvicorn", "api_gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
