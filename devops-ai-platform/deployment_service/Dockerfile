# DevOps.AI Operator Platform - Deployment Service
# Build context: devops-ai-platform/  (see docker-compose.yml)
#
# Phase 8.8A Correction-1 (F1): this image is the single canonical
# deployment runtime. It serves the declared HTTP contract (uvicorn on
# 8030) as its default entrypoint; the Celery worker runs THE SAME image
# with a different `command:` override (docker-compose.yml,
# deployment-worker), so API and worker share one pinned, tested image
# definition and one hash-pinned dependency lock.
#
# Phase 8.8A Correction-1 (F6): the base is pinned to the exact digest
# the repository already approves (e2e/pinned-images.txt,
# E2E_PYTHON_BASE_IMAGE — observed 2026-10-06 against the official
# registry.hub.docker.com manifest, identical to the digest the
# gateway/agent D1 images use, and re-pulled by every CI build).
# Floating tag references are rejected by
# scripts/assert_deployment_base_images.py.
FROM python:3.11-slim@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce

WORKDIR /app

# Phase 8.8A: the sanctioned hash-pinned runtime lock — no broad
# requirements.txt, no unpinned transitive resolution at build time.
COPY requirements-runtime.txt /app/requirements-runtime.txt
RUN pip install --no-cache-dir --require-hashes -r requirements-runtime.txt

COPY . /app

EXPOSE 8030

# The deployment API serves the declared contract on 8030. It holds no
# Docker daemon access and no sandbox authority: it validates, persists
# durable run records and enqueues execution; the worker entrypoint
# (selected by the compose `command:` override on deployment-worker)
# owns sandbox execution under a fenced Redis lease.
CMD ["uvicorn", "deployment_service.main:app", "--host", "0.0.0.0", "--port", "8030"]
