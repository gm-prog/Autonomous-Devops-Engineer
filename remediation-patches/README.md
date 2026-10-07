# Remediation patches for `dev/remediation-pr-orchestration-v1`

Drop-in patches for the scoped fixes from the forensic audit of this branch,
plus follow-on development (gateway wiring, CORS). Every patch was generated
against, and verified on, commit
**`9b85d91848178a09a7b861db64d050d951ee6f72`** (branch tip at authoring time).

## Apply

```bash
git fetch origin
git checkout dev/remediation-pr-orchestration-v1   # must be at 9b85d918 (or a descendant)
git status                                          # clean tree required

git apply 01-celery-json-import.patch
git apply 02-android-preset-seeding.patch
git apply 03-remediation-github-publication.patch
git apply 04-api-gateway-real-jwt.patch
git apply 05-backend-root-metrics.patch
git apply 06-compose-env-gaps.patch
git apply 07-api-gateway-wiring.patch
git apply 08-backend-cors-allowlist.patch
```

`git apply --check <patch>` is safe to run first. The patches are
independent (no overlapping hunks) and were verified to apply in **any
order** (forward 01→08 and reverse 08→01 both clean) — each maps 1:1 to an
audit finding or development item, which keeps review easy.

> If your branch has moved past `9b85d918` and a patch no longer applies
> cleanly, apply with `git apply --3way` or rebase the hunk by hand — the
> anchor context in the diff identifies exactly what should be changed.

**Dependency note:** patches **04 + 07 pair up** — 04 makes the auth code
real, 07 makes the service bootable. Each applies alone; the gateway only
*runs* once both are in.

## What each patch does

### 01 — `01-celery-json-import.patch` (backend)
**Audit finding:** `celery_worker.py` used `json` (line ~115) without a
module-level import; the only import was function-local inside a *different*
function → `NameError` whenever the repository-intelligence Celery task ran.

**Fix:** module-level `import json`; removed the function-local duplicate.

**Files:** `backend/app/celery_worker.py`

### 02 — `02-android-preset-seeding.patch` (Android)
**Audit finding:** `setupPresetsIfEmpty()` gated on
`getRepoByPredicate { true } == null` — a private helper that **always
returned null** — so the 3 preset repos + 2 preset incidents were
re-inserted on every app launch (unbounded DB growth). The correct query,
`dao.getRepositoryCount()`, existed but was never used.

**Fix:** gate on `dao.getRepositoryCount() == 0`; deleted the dead
`getRepoByPredicate` helper. Added a pure-JVM regression test (fake DAO —
the project has no Robolectric dependency, so no Android framework is
required) that proves seeding is idempotent and skipped for a used database.

**Files:** `app/src/main/java/com/example/data/DevOpsRepository.kt`,
`app/src/test/java/com/example/DevOpsRepositorySeedingTest.kt` (new)

### 03 — `03-remediation-github-publication.patch` (incident-service)
**Audit finding:** the remediation pipeline committed locally, then called
`create_branch_from_commit()` against a SHA **that GitHub had never
received** — the flow could never complete end-to-end. (The existing code
fails closed at `GET /repos/{repo}/commits/{sha}` → 404 → raise; the missing
step is transferring the commit object over the wire.)

**Fix:** a new `publish_branch(workspace, oauth_token)` step on the
workspace service, invoked by the orchestrator **after** the commit
checks and **before** any REST ref/PR operation:

1. `git rev-parse HEAD` and validate it is the full 40-char verified SHA;
2. `git push --no-tags origin HEAD:refs/heads/<remediation-branch>` with the
   token passed **only** via `GIT_CONFIG_COUNT/KEY_0/VALUE_0`
   (`http.extraHeader`) — never in the URL or argv, never echoed to logs;
3. `git ls-remote` verify the remote ref points at exactly that SHA before
   `create_branch_from_commit` / `create_pull_request` may proceed.

The GitHub REST client is unchanged: its existing
"ref already exists at same SHA → idempotent success" path now carries the
re-run case. Missing/blank token → fail-closed
(`RemediationRemotePublishError` → `RemediationOrchestrationError`) with no
stderr leakage.

**Files:** `remediation_workspace_service.py` (+`publish_branch`,
+`RemediationRemotePublishError`), `remediation_orchestration_service.py`
(+`github_oauth_token` ctor param, publish step in `execute()`),
`controllers.py` (DI wiring from `GITHUB_OAUTH_TOKEN`),
`test_remediation_orchestration_service.py` (order proof:
commit → publish → branch → PR; failure-stops tests),
`test_remediation_workspace_push.py` (new: 5 tests), `.github/workflows/ci.yml`
(the incident-service unittest list gains the new test module).

### 04 — `04-api-gateway-real-jwt.patch` (api-gateway)
**Audit finding:** `core/auth.py` accepted **any** string of length ≥ 10 as a
valid identity (plus a hardcoded literal as "admin"); `JWT_SECRET` was
declared in config but never used. Authorization was an illusion.

**Fix:** real HS256 JWT verification using stdlib crypto only
(`hmac`/`hashlib`/`base64`/`json` — no new dependency): signature check with
constant-time compare, `exp` enforcement, `sub`/`roles` claims, 401 on any
failure. `verify_token` and `GatewayRateLimiter` keep their names so the
router is untouched. Imports normalized to the repo's top-level convention
(`from config import ...`, matching how `incident-service` boots). Dev token
minter (from `devops-ai-platform/api-gateway/`):
`python -m core.auth <subject> [Role1 Role2 ...]`. The config keeps its
dev fallback secret but now **logs a warning** when it is in use.

**Files:** `devops-ai-platform/api-gateway/core/auth.py`,
`devops-ai-platform/api-gateway/config/__init__.py`

### 05 — `05-backend-root-metrics.patch` (backend)
**Audit finding:** the root API (port 8000, the one
`monitoring/prometheus.yml` scrapes) exposed no `/metrics`;
`prometheus-client` was not even a declared dependency.

**Fix:** Prometheus Counter (`devops_api_requests_total{method,path}`,
routed paths only) + middleware + `GET /metrics` endpoint;
`prometheus-client>=0.17.0` added to `requirements.txt`.
Bonus (same file): the Qdrant startup block was
`recreate_collection` on **every** boot, destroying stored vectors — now
create-if-missing (`collection_exists` first).

**Files:** `backend/app/main.py`, `backend/requirements.txt`

### 06 — `06-compose-env-gaps.patch` (compose)
**Audit finding:** `incident-service` and `incident-event-worker` never
received `AGENT_SERVICE_URL`, so the RCA adapter was unreachable under
default compose; and nothing provided `GITHUB_OAUTH_TOKEN` for remediation
publication.

**Fix:** `AGENT_SERVICE_URL=http://agent-service:8020` on both services;
`GITHUB_OAUTH_TOKEN=${GITHUB_OAUTH_TOKEN:-}` on `incident-service`
(secret-safe: empty default → pipeline fails closed; set it via your
`.env`, never commit it).

**Files:** `docker-compose.yml`

### 07 — `07-api-gateway-wiring.patch` (api-gateway) — *development*
**Gap:** the gateway was orphaned on this branch — `routers/`, `core/`,
`config/` existed but there was **no entrypoint, no Dockerfile, no
requirements, no tests, no CI job**. Worse,
`devops-ai-platform/docker-compose.yml` (the file CI's compose job
validates) already declares an `api-gateway` service whose
`dockerfile: ./api-gateway/Dockerfile` **did not exist** — `docker compose
config` passes anyway because it never checks Dockerfile presence. The
router also used package-relative imports (`..core.auth`) that cannot
resolve from the hyphenated directory.

**Fix:** make the reserved slot real —
- `main.py`: FastAPI entrypoint (`uvicorn main:app`), mounts the gateway
  router, public `/health`;
- `Dockerfile` (context = `devops-ai-platform/`, matching the compose
  declaration), `requirements.txt`;
- `routers/gateway_router.py`: top-level import
  (`from core.auth import ...`) per repo convention;
- platform compose: `JWT_SECRET` + `RATE_LIMIT_MAX_REQUESTS` env for the
  `api-gateway` service (safe `${VAR:-dev-default}` so an empty host var
  cannot silently disable verification);
- `tests/test_gateway.py` (new, 9 tests): health, 401/403 paths, valid
  token, tampered/expired/garbage tokens, **the old
  `mock-devops-admin-token-1842` backdoor rejected**, dispatch 404 +
  passthrough identity echo;
- CI: new `api-gateway` job (compileall + `python -m unittest
  tests.test_gateway`) — the auth fix from 04 is now continuously verified,
  not just once.

**Files:** `devops-ai-platform/api-gateway/{main.py,Dockerfile,
requirements.txt,routers/gateway_router.py,tests/}` (new/modified),
`devops-ai-platform/docker-compose.yml`, `.github/workflows/ci.yml`

### 08 — `08-backend-cors-allowlist.patch` (backend) — *development*
**Audit finding:** backend CORS was `allow_origins=["*"]` **together with
`allow_credentials=True`** — browsers reject that combination, and if it
ever "worked" it would let any site drive the API with the user's
credentials.

**Fix:** explicit origin allowlist read from `ALLOW_ORIGINS`
(comma-separated), defaulting to local dev origins
(`localhost:3000`, `localhost:5173`, `127.0.0.1:3000`). Root compose
passes `${ALLOW_ORIGINS:-...}` through so production origins are a `.env`
change, not a code change. Disallowed origins receive no
`Access-Control-Allow-Origin` header.

**Files:** `backend/app/main.py`, `docker-compose.yml`

## Verified before delivery

Applied all eight to a detached worktree at `9b85d918` and ran:

| Check | Result |
|---|---|
| `git apply` forward (01→08) **and reverse (08→01)** from repo root | clean both ways; exactly the 21 intended files touched |
| incident-service CI list (14 modules incl. new `test_remediation_workspace_push`) | **64 tests OK** |
| monitoring-service CI list (4 modules) | 20 tests OK |
| deployment-service `pytest -q` | 11 passed |
| agent-service `unittest test_server` | 2 OK |
| **api-gateway compileall + `tests.test_gateway`** (the new CI job's commands) | **9 tests OK** (incl. legacy backdoor token rejected) |
| backend `compileall`; `/metrics` 200 (prometheus content-type, per-path counter increments); `/health` 200 | OK |
| backend CORS: allowed origins echoed (GET + preflight), disallowed origin gets no ACAO header | OK |
| gateway minter CLI round-trip (`python -m core.auth` → `decode_and_verify`) | OK; dev-fallback warning fires when `JWT_SECRET` unset |
| root compose YAML (13 services; `AGENT_SERVICE_URL`, `GITHUB_OAUTH_TOKEN`, `ALLOW_ORIGINS` present) | OK |
| platform compose YAML (`api-gateway` service + env; referenced Dockerfile now exists) | OK |
| Kotlin: brace/paren/bracket balance on touched file; no dangling `getRepoByPredicate` reference | OK |

Not runnable in the authoring sandbox (no JVM): `gradle test` for patch 02 —
the test is dependency-safe by construction (only `junit` +
`kotlinx-coroutines` + the app's own classes, all already declared).

## Suggested follow-up commands (your machine)

```bash
# CI-equivalent checks, from repo root:
docker compose -f devops-ai-platform/docker-compose.yml config   # what the compose job runs
cd devops-ai-platform/incident-service && PYTHONPATH=. python -m unittest <14-module list from .github/workflows/ci.yml>
cd devops-ai-platform/api-gateway && PYTHONPATH=. python -m pip install -r requirements.txt httpx && python -m unittest tests.test_gateway -v
gradle test                                                        # Android
docker compose up --build api-gateway                              # boot the gateway (platform compose)
```

## Known limitations / not included (needs product decisions)

- **Client-side Gemini API key** in the Android app — moving it behind the
  backend is an architecture change, not a drop-in patch.
- **RAG/vector pipeline quality** — out of scope for the scoped fix set.
- **SSH host-key handling** in remediation git operations — the current
  flows use HTTPS only.
- **Android ↔ platform unification** (two divergent repo models) — a
  design decision, not a patch.
- **Dispatch is still a passthrough stub** — `/v1/gateway/dispatch/*`
  echoes identity + payload instead of proxying the HTTP call downstream;
  wiring real HTTPX/gRPC forwarding is product work (the auth, routing
  table, and rate limit around it are now real).
- **Port overlap:** root compose maps backend `api` to host `8000`, and
  the pre-existing platform-compose declaration maps `api-gateway` to host
  `8000` too (their file, preserved as-is). The two stacks are fine
  separately; run both at once only after remapping one host port.
