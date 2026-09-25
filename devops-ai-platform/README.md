# DevOps.AI Operator Platform (DDD)

The bounded-context microservices platform for the DevOps.AI autonomous
DevOps engine.

## What runs today

As of this development round, **every service in this directory is importable
and has a bootable entrypoint** (verified by the `tests/` smoke suite, run in
CI):

| Service | Package | Entrypoint | Exposes |
|---|---|---|---|
| BFF Gateway | `api_gateway` | `api_gateway.main:app` :8000 | `POST /v1/gateway/dispatch/{service}`, `GET /v1/gateway/metrics` (HS256 JWT), `/health` |
| Repo context | `repo_service` | `repo_service.main:app` :8010 | `POST /repositories`, `/health` |
| Agent swarm | `agent_service` | `agent_service.main:app` :8020 | `GET /agent/streams/{task_id}` (SSE), `/health` |
| Deployment | `deployment_service` | Celery worker | task `tasks.execute_iac_deployment` (Redis broker) |
| Monitoring | `monitoring_service` | `monitoring_service.main:app` :8040 | `WS /ws/telemetry/socket/{client_id}`, `/health` |
| Incident | `incident_service` | `incident_service.main:app` :8050 | `GET /incidents`, `POST /alerts/webhooks/sentry` (HMAC), `/health` |
| Reporting | `reporting_service` | (library) | weekly audit-report queries + "PDF" engine |
| Shared kernel | `shared_kernel` | (library) | domain events, value objects, event publisher, metrics |

## Run the full stack

```bash
# 1. infrastructure + all services (Docker required)
docker-compose up -d --build

# 2. mint a gateway token and exercise the BFF
export TOKEN=$(python -m api_gateway.core.auth devops-operator DevOpsLead)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/v1/gateway/metrics
```

## Run without Docker (single service)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# from this directory, any service:
uvicorn api_gateway.main:app --port 8000
uvicorn repo_service.main:app --port 8010
uvicorn agent_service.main:app --port 8020
uvicorn monitoring_service.main:app --port 8040
uvicorn incident_service.main:app --port 8050

# deployment service is a Celery worker:
celery -A deployment_service.infrastructure.celery.tasks.celery_app worker --loglevel=info
```

## Security model

* **Gateway auth** — real HS256 JWT verified with `JWT_SECRET`
  (`api_gateway/core/auth.py`). The old "any token ≥ 10 chars is a
  Developer" mock is gone. Mint dev tokens with
  `python -m api_gateway.core.auth <subject> [roles...]`. If `JWT_SECRET` is
  unset, a committed development fallback is used **and a warning is logged**
  — set a real secret before exposing the gateway.
* **Sentry webhooks** — `incident-service` verifies an HMAC-SHA256 signature
  of the raw body (`X-Sentry-Signature`) when `SENTRY_WEBHOOK_SECRET` is set.
  Without the secret it runs in permissive dev mode (loud warning).
* **GitHub PR client** — refuses to fabricate PR URLs: a missing
  `GITHUB_OAUTH_TOKEN` now raises instead of "succeeding".

## Remediation runtime & deployment evidence contract

The incident bounded context ships the full remediation path
(`incident_service` package, package-mode entrypoint
`uvicorn incident_service.main:app`):

```
POST /incidents/{id}/remediation          (binding-gated, see below)
  -> isolated workspace @ pinned 40-hex source SHA
  -> bounded patch (`git apply --check`) -> bounded validation profiles
  -> deterministic commit (parent == pinned SHA)
  -> git push automation/remediation/* (http.extraHeader credentials)
  -> remote SHA verification (ls-remote) -> GitHub REST branch + DRAFT PR
  -> real html_url; every boundary fails closed
```

**Target binding:** the endpoint first proves the requested
`repository_slug` + `source_sha` appear in the incident's own
`deployment_run` evidence (403 + orchestrator never invoked otherwise).

**Deployment evidence contract** (`GET /api/internal/deployments/{run_id}`
on `deployment-service:8030`, served by `deployment_service.main:app`):

| Field | Meaning |
|---|---|
| `id` | deployment run id |
| `repository_id`, `repository_name` | repository identity (`owner/repo`) |
| `source_revision.head_sha` | full 40-hex revision deployed |
| `state`, `created_at`, `updated_at`, `artifact_hash`, `plan_hash`, `approval`, `health_check`, `rollback`, `error` | bounded run metadata |

Records are produced by `POST /api/internal/deployments/dry-run` (then
approve/execute) and persisted in the run store; unknown run ids return
**404** - responses are never synthesized. `incident-service` reads this
endpoint through `DeploymentEvidenceCollector` (`DEPLOYMENT_SERVICE_URL`)
when attaching evidence.

## Known limits (honest)

* The `dispatch` route forwards to service hostnames
  (`repo-service:8010`, …) that only exist **inside the compose network**.
  Run a single service locally without compose and dispatches will 502 —
  that is truthful behaviour, not a bug.
* The `deployment` dispatch target has no HTTP layer (it is a Celery worker);
  it will 502 until an HTTP surface is added.
* gRPC surfaces (ports 50051–50055) are still sketch: `grpcio` is installed,
  service impls exist, but **no `.proto` files and no registered servers**
  were in the original export — left as-is.
* Postgres adapters are still mostly stubs (see each
  `infrastructure/persistence/` module); the services run on in-memory mocks
  by design until real adapters are wired.
* `gemini-3.5-flash` / `gemini-3.1-pro-preview` model ids are unverified
  upstream; the Gemini caller fails soft into templates/offline bypass.

## Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

Covers: JWT sign/verify/reject/expiry, gateway 401/404/502 contracts,
Sentry HMAC accept/reject, SSE + WebSocket endpoints, repo import,
shared-kernel VOs/events, Celery task registration, GitHub no-fake-PR guard.
