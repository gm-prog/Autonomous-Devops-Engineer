# DevOps.AI Operator Platform (DDD)

The bounded-context microservices platform for the DevOps.AI autonomous
DevOps engine.

## What runs today

As of this development round, **every service in this directory is importable
and has a bootable entrypoint** (verified by the `tests/` smoke suite, run in
CI):

| Service | Package | Entrypoint | Exposes |
|---|---|---|---|
| BFF Gateway | `api_gateway` | `api_gateway.main:app` :8000 | `POST /v1/gateway/dispatch/{service}`, `GET /v1/gateway/metrics`, control plane `POST /v1/deployments/dry-run`, `/v1/deployments/{id}/approve`, `/execute`, `/v1/incidents/{id}/remediation` (HS256 JWT), `/health` |
| Repo context | `repo_service` | `repo_service.main:app` :8010 | `POST /repositories`, `/health` |
| Agent swarm | `agent_service` | `agent_service.main:app` :8020 | `GET /agent/streams/{task_id}` (SSE), `/health` |
| Deployment | `deployment_service` | Celery worker | task `tasks.execute_iac_deployment` (Redis broker) |
| Monitoring | `monitoring_service` | `monitoring_service.main:app` :8040 | `WS /ws/telemetry/socket/{client_id}`, `/health` |
| Incident | `incident_service` | `incident_service.main:app` :8050 | `GET /incidents`, `POST /incidents/{id}/remediation` (provenance-bound), `POST /alerts/webhooks/sentry` (HMAC, fail-closed), `/health` |
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
* **Control plane** — deployments and remediation are driven through named
  gateway routes (`/v1/deployments/*`, `/v1/incidents/{id}/remediation`),
  not by proxying guessed `/api/internal/*` paths (which 404 at the
  gateway). Every route requires a valid JWT; `approve`, `execute` and
  `remediation` additionally require an operator role
  (`operator`, `DevOpsLead`, `ClusterAdmin`) else **403 before any
  downstream call**. The gateway stamps `requested_by` / `approved_by`
  from the JWT `sub` — caller-supplied identity strings are overwritten.
  The product is intentionally **single-operator**: any operator may act
  on any run/incident id (no per-user tenancy is claimed or invented);
  ids must exist downstream (404/409 relayed), deployments are guarded by
  the state machine + hash binding, and remediation by evidence binding.
* **Sentry webhooks** — `incident-service` verifies an HMAC-SHA256
  signature of the raw body (`X-Sentry-Signature`) with a constant-time
  compare. **Fail closed:** if `SENTRY_WEBHOOK_SECRET` is unset the
  endpoint rejects every request with **HTTP 503** until configured —
  there is no permissive mode, and `verify_sentry_signature` itself
  returns False without a secret.
* **Deployment provenance** — see "Deployment provenance & source
  verification" below: remediation authorization requires a DEPLOYED run
  whose platform provenance record verifies (hash + identity + source
  verification), not a plausible repository name + SHA.
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
| `source_verification` | independent source check attestation (`method`, `verified_at`, remote commit id); never contains credentials |
| `provenance` | canonical-JSON-hashed provenance record (see below), re-derived on every save |
| `state`, `created_at`, `updated_at`, `artifact_hash`, `plan_hash`, `approval`, `health_check`, `rollback`, `error` | bounded run metadata |

Records are produced by `POST /api/internal/deployments/dry-run` (then
approve/execute) and persisted in the run store; unknown run ids return
**404** - responses are never synthesized. `incident-service` reads this
endpoint through `DeploymentEvidenceCollector` (`DEPLOYMENT_SERVICE_URL`)
when attaching evidence.

## Deployment provenance & source verification (Stage 5)

The trust chain from request to remediation is:

```
caller picks repo + exact SHA
  → HTTP boundary: canonical owner/repo + full 40-hex only
  → server-side source verification: GitHub commits API confirms that exact
    SHA exists in that exact repository (Bearer token from env, header-only;
    404 → 422, provider trouble → 503 — both fail closed, no run persisted)
  → artifact identity: sha256 of the submitted IaC; plan identity binds
    artifact + repo + source revision + tool outputs
  → approval (hash-bound) → execute (re-checks hashes) → state=DEPLOYED
  → evidence collector copies the run, including its provenance record
  → remediation binding: ONE DEPLOYED evidence record whose provenance
    verifies AND whose (repo, SHA) equals the requested target
  → orchestrator constructed only after that gate passes
```

**Provenance record** (`shared_kernel/domain/provenance.py`, schema
`devops.deployment-provenance/1`): `repository_name`, `source_sha`,
`artifact_hash`, `plan_hash`, `deployment_run_id`, `state`,
`verification_method`, `artifact_source_derivation`, plus
`provenance_hash` = SHA-256 over the canonical JSON (sorted keys, compact
separators) of all other fields. It is **re-derived from the run's own
persisted fields on every save** — never read back from requests or
storage, so no HTTP field can rewrite it. Remediation binding recomputes
the hash and cross-checks every identity field against the evidence
record; `verification_method: "unverified"`, tampering, grafting from
another record, or a state mismatch all fail closed.

**What the platform claims — and what it deliberately does not:**

* *Source-verified:* the exact revision's existence in the canonical
  repository is confirmed server-side before any run exists.
* *Artifact-identity-verified:* the submitted IaC bundle is content-hashed
  and that hash is bound through plan → approval → execution.
* *Artifact-to-source derivation:* **not established**
  (`artifact_source_derivation: "not-established"`). The platform does not
  deterministically generate artifacts from the verified source tree, and
  the builder/verifier refuse to record or accept a stronger claim.
  Nothing here should be described as "cryptographic source-to-artifact
  provenance".
* The provenance hash is **unkeyed integrity, not a signature**: it
  detects tampering and cross-record grafting, while authenticity rests
  on the network/gateway boundary below.

## Network & authentication trust boundary

* **External boundary = API gateway only.** `docker-compose.yml` publishes a
  host port for `api-gateway` (8000) and for **nothing else** - incident,
  deployment, repo, agent, monitoring and the data stores have no host
  publication and are reachable exclusively over the private compose network
  (service-name DNS). Direct external requests to internal services are
  therefore impossible in the production topology; guessing `/api/internal/*`
  grants nothing (a URL prefix is not authorization).
* **Authentication** happens at the gateway (HS256 JWT, `JWT_SECRET` is
  fail-fast `${JWT_SECRET:?}` in compose). Internal service-to-service calls
  stay inside the trusted private network - no second token system, no
  secrets in source.
* **Development:** `docker-compose.dev.yml` is an explicit, opt-in override
  that re-publishes internal ports for local debugging:
  `docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d`
* **Layered authorization:** even in-network callers must pass the
  remediation target binding (canonical repository + exact 40-hex SHA in one
  *DEPLOYED* evidence record of the same incident, with valid provenance)
  before the remediation orchestrator is even constructed.
* **Internal request trust model (no second token system):**
  * *Identity source* — only the gateway authenticates callers (HS256 JWT,
    `sub` + `roles` claims); it stamps `requested_by`/`approved_by` from
    `sub` before forwarding. Downstream HTTP APIs trust the private network
    (single-operator deployment), which is why host publication of
    internals is forbidden by the compose contract above.
  * *Credential lifecycle* — gateway JWT secret lives in the `JWT_SECRET`
    env (fail-fast `${JWT_SECRET:?}` in compose); tokens carry a 1-hour
    `exp`; rotation = set a new secret and restart the gateway (old tokens
    die immediately). GitHub verification uses `GITHUB_OAUTH_TOKEN`
    (header-only, optional for public repos).
  * *Failure behavior* — invalid/expired/bad-signature JWT → 401; wrong
    role → 403 (before any network call); downstream unreachable → 502;
    downstream answers relayed verbatim (404/409/422/403); Sentry
    webhooks without a configured secret → 503.
  * *Replay* — bearer tokens are time-boxed (1 h) but not nonce-tracked;
    short TTL is the accepted trade-off for this single-operator product.
  * *Logging* — rejected tokens are logged by reason only (never the
    secret, never the token); webhook rejections log no payload.
  * *Tests* — `api_gateway/tests/test_control_plane.py`,
    `tests/test_control_plane_e2e.py`, `tests/test_platform_smoke.py`,
    `tests/test_compose_network_boundary.py`.

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
* **SSH host-key verification** — `repo_service`'s git SSH helper disables
  `StrictHostKeyChecking`, which weakens first-contact host identity for
  *that* service's own clones. The remediation publication path does **not**
  use it (HTTPS clone + `ls-remote` SHA verification instead), so this is a
  separate, unmitigated risk in `repo_service`, recorded here rather than
  silently expanded into the remediation trust chain.
* **Validation-runner sandbox** — the remediation validation runner bounds
  commands with `shell=False`, fixed profiles, timeouts and env
  sanitation, but it executes in-process on the incident-service host, not
  in a container/gVisor sandbox. Untrusted patch content is still checked
  (`git apply --check` + path rules); full isolation remains open work.
* **Two stacks exist** — the repository-root `docker-compose.yml` is the
  broad *development* stack (Postgres/Redis/Qdrant/gateway/Prometheus/
  Grafana + backend services with several host ports for local debugging).
  The **platform** topology described above is
  `devops-ai-platform/docker-compose.yml` (gateway-only host publication)
  with `docker-compose.dev.yml` as the explicit opt-in for internal ports.
  Do not confuse the two when reasoning about the trust boundary.
* **Governance (not a code fix)** — the `main` branch currently has no
  GitHub branch protection (verified via the API). Restricting direct
  pushes, requiring PR reviews and enforcing status checks is a repository
  *settings* action; it is recorded as a recommendation and intentionally
  not changed from code.

## Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

Covers: JWT sign/verify/reject/expiry, gateway 401/404/502 contracts,
control-plane role matrix + identity stamping + full E2E chain,
Sentry HMAC accept/reject/unset-secret (503), provenance hash contract
(tamper/graft/unverified/over-claim), source-verification fail-closed
matrix, remediation binding attacks, SSE + WebSocket endpoints, repo
import, shared-kernel VOs/events, Celery task registration,
GitHub no-fake-PR guard.
