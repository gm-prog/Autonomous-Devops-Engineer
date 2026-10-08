# Phase 8.7-D.1: immutable base image (digest resolved 2026-10-08 from the
# official python 3.11-slim manifest — see docker-compose.yml header).
FROM python:3.11-slim@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Repository directory uses a hyphen; copy it into a valid Python package name.
COPY agent-service /app/agent_service

ENV PYTHONUNBUFFERED=1
EXPOSE 8020

CMD ["uvicorn", "agent_service.main:app", "--host", "0.0.0.0", "--port", "8020"]
