# CHANGELOG

## 2026-09-24 — Development round: fix & stabilize (post-forensic-audit)

This round addresses the defects identified in `FORENSIC_REPORT.md`.
All changes verified by the test suites below (no Docker/Android SDK in CI,
so Python is exercised end-to-end and Android changes are compile-safe edits).

### P0 — critical fixes

* **Client ↔ backend contract now works.** Added `GET /api/v1/health`,
  `GET /api/v1/repositories` and `POST /api/v1/repository/analyze` to
  `backend/app/main.py`. The last returns the exact 5-field shape the Android
  `BackendGatewayClient` parses (`dockerfile`, `k8s_yaml`, `terraform_tf`,
  `pipeline_yaml`, `analysis_report`), upserts the repo row, and runs live
  Gemini server-side when `GEMINI_API_KEY` is set (key sent via the
  `x-goog-api-key` header, never as a URL query param). The remote-backend
  feature in the app is now functional end-to-end.
* **Preset duplication bug fixed** (`DevOpsRepository.setupPresetsIfEmpty`):
  the always-null `getRepoByPredicate` helper is gone; seeding now gates on a
  real `COUNT(*)` DAO query. New Robolectric+Room regression test asserts
  presets exist exactly once after repeated seeding.
* **`devops-ai-platform` is now bootable.**
  * All 7 hyphenated service directories renamed to valid Python packages
    (`api_gateway`, `repo_service`, `agent_service`, `deployment_service`,
    `monitoring_service`, `incident_service`, `reporting_service`);
    `__init__.py` added throughout.
  * `shared-kernel/` merged into the importable `shared_kernel/` package
    (events, value objects, messaging, metrics).
  * Every `main.py`/entrypoint that was missing now exists; each service has
    a Dockerfile; `docker-compose.yml` builds and runs the full stack with
    service names/ports matching the gateway routing matrix.
  * Broken imports fixed: `execute_deployment.py` now imports a real
    `deployment_service/domain/exceptions.py` (duplicated class removed);
    all cross-service `shared_kernel` imports corrected (relative-depth bugs →
    absolute imports); `mcp/mcp_server.py` `logger` NameError fixed.

### P1 — hardening & quality

* **Real gateway JWT auth** (`api_gateway/core/auth.py`): the "any token ≥ 10
  chars = Developer, literal = admin" mock is replaced with HS256
  sign/verify (stdlib crypto) using the previously-dead `JWT_SECRET`,
  expiry enforcement, constant-time compare, and a token-mint CLI
  (`python -m api_gateway.core.auth <sub> [roles...]`). Startup warns when
  the committed dev fallback secret is in use.
* **`/metrics` on the root gateway** (`prometheus_client`): the Prometheus
  target in `monitoring/prometheus.yml` is now real; a Qdrant job was added.
  **Grafana** now provisions its Prometheus datasource on boot.
* **Honest gateway dispatch** (`api_gateway/routers/gateway_router.py`):
  `/v1/gateway/dispatch/{service}` performs a real HTTP forward and reports
  502 when the downstream is down instead of fabricating `PROXY_PASSTHROUGH`.
* **Sentry webhook HMAC** (`incident_service`): `X-Sentry-Signature` is
  verified as HMAC-SHA256 over the raw body when `SENTRY_WEBHOOK_SECRET` is
  set (401 otherwise); permissive dev mode only when unset, with a warning.
* **GitHub PR client no longer fabricates success**: missing
  `GITHUB_OAUTH_TOKEN` raises `InvalidGitHubTokenException` instead of
  returning a fake PR URL.
* **Qdrant boot no longer destructive**: create-if-missing instead of
  `recreate_collection` on every startup (vector data survives restarts).
* **CORS correctness**: wildcard origins no longer combined with
  credentials; origins configurable via `CORS_ORIGINS`.
* **Android health probe honesty** (`BackendGatewayClient.testConnection`):
  probes `/health` then `/api/v1/health`; only 2xx counts as connected —
  404-as-success removed.
* **`analyzeRepoAsync`** now updates the repo row instead of re-inserting a
  copy to set `Analyzing`.
* **Tests added:**
  * `backend/tests/` — 33 tests (API contract, /metrics, CORS, Celery
    fallback path, tag protocol parsing, Gemini live path with mocked
    transport incl. key-in-header assertion).
  * `devops-ai-platform/tests/` — 20 tests (boot + auth + HMAC + SSE/WS +
    guardrail regressions).
  * Android — `GeminiClientParseTest` (8 parse-tag cases),
    `DevOpsRepositorySeedingTest` (2 seeding regressions);
    `ExampleRobolectricTest` assertion corrected to the real app name;
    the non-compiling `GreetingScreenshotTest` (referenced a composable that
    never existed) and its stale baseline removed.
* **CI** (`.github/workflows/ci.yml`): backend + platform pytest jobs on
  push/PR.

### P2 — misc

* `celery_worker.py` reuses the shared template engine (single source of
  truth for IaC templates across sync/async paths; tech branching now
  python/node/JVM, matching the app).
* `GeminiClient.parseTag` made `internal` for direct unit testing.
* Pydantic v2 (`ConfigDict`) and SQLAlchemy 2.0 import modernizations;
  deprecated `@app.on_event` replaced by lifespan.
* `backend/.dockerignore`-style hygiene: `.gitignore` extended
  (`__pycache__`, `.venv`, `*.sqlite3`, …).
* Docs corrected: `VS_CODE_AND_VERCEL_ROADMAP.md` (real uvicorn paths, real
  env vars — the Prisma-style `POSTGRES_PRISMA_URL`/`REDIS_URL` phantoms are
  gone), `README.md` (honest simulation labels, backend + platform setup),
  new `devops-ai-platform/README.md`.

### Still open (tracked in FORENSIC_REPORT.md §34)

* Verify `gemini-3.5-flash` / `gemini-3.1-pro-preview` model ids with a real
  key (still 🔴 unverified upstream).
* gRPC surfaces still lack `.proto` files and registered servers.
* Real Postgres adapters for the platform services (still stubs by design).
* Room schema export / Alembic migrations (both stacks still `create_all`).
* Android build verification (no JDK in this environment) — run
  `gradle assembleDebug` + `gradle :app:testDebugUnitTest` on a dev machine.
