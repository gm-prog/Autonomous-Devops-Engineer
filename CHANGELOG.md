# CHANGELOG

## 2026-09-27 — Phase 6.2.1A: lease liveness & remote identity integrity (corrective hardening)

Closes three review gaps on the completed 6.2.1 implementation; no
architecture change, pipeline unchanged (approved proposal → controlled
remediation → draft PR).

* **Active lease liveness** — new owner-CAS renewal primitive
  `renew_execution_lease` (stage-neutral, exact claim, never resurrects
  or extends foreign leases; no schema change) plus a worker-owned
  heartbeat thread active for exactly one execution attempt. Interval =
  `REMEDIATION_EXECUTION_HEARTBEAT_SECONDS` or derived `lease/3`
  (always positive and `< lease/2`, fail-fast validation). Lease loss
  or claim-store uncertainty is detected immediately and the next
  side-effecting stage is refused (stage guard); persistence/finish
  paths convert store unavailability to typed fail-closed errors. A
  worker that lost its lease cannot clobber the new owner's state; an
  in-flight external operation is never "cancelled" — only the next
  stage is blocked, recovery runs through the existing reconciliation
  path. Heartbeats are stopped and joined on every exit path (no thread
  leaks).
* **Exact PR identity** — `ExistingPullRequest` exposes `head_sha` +
  `head_repository`; reuse now requires exact repository + head branch +
  head commit SHA + allowed base + open/unmerged, with the proposal
  hash in the body remaining corroboration only. Wrong head SHA, wrong
  or absent head repository, wrong base, merged/closed, multiple
  matches, or body-only agreement → `ExistingPullRequestConflict`,
  fail closed (no second PR / overwrite / force-push / retarget).
  Malformed head identity in API payloads → typed discovery failure.
* **Multi-proposal claim projection** — incident reload fetches ALL
  claim rows per incident and maps them by `proposal_id`; proposals with
  no claim keep their JSON view; independent stage/attempt/lease/
  commit/branch/PR per proposal proven on real SQLite (active, completed,
  failed and claim-less proposals side by side). Added read helper
  `get_execution_claims_for_incident`.
* **Tests:** new `test_proposal_lease_liveness` (13 — interval policy
  fail-fast, renewal CAS semantics, long-operation/long-validation
  renewal on real store, owner-loss stops next stage + cannot finish,
  store-outage fails closed, no heartbeat-thread leaks); multi-proposal
  projection (1); client exact-identity + malformed-head tests (+3);
  orchestration wrong-SHA/wrong-repo/wrong-base/body-only-never-reuses
  tests (+6); §29-D recovery E2E — PR created remotely with lost
  response, worker B reuses the exact PR with zero second creates (+1).
  Full battery: backend 38, platform 137+78 subtests, gateway 34+36
  subtests, incident **27 modules Ran 255 OK**.
* **Honest limitations:** PostgreSQL CAS still not exercised in CI
  (SQLite real-persistence only); in-flight operations cannot be
  cancelled after lease loss; no hardened sandbox (Phase 6.2.2); no
  exactly-once across DB+Git+GitHub.

## 2026-09-27 — Phase 6.2.1: durable execution coordination & remote reconciliation

Hardens the Phase 6.2 executor (same architecture, no new stack): one
logical proposal execution now converges to one logical remediation
result under duplicate, interrupted and ambiguous requests.

* **Durable execution lease** — new `devops_execution_claims` table
  (same database, explicit schema, reload round-trip tested) holding
  `execution_id, attempt, lease_owner, lease_acquired_at,
  lease_expires_at, current_stage, state, commit/branch/pr mirrors`.
  Atomic claim guarantees at most one live lease per
  `(incident_id, proposal_id, proposal_hash)` **across independent
  service instances** (verified with two adapters over real SQLite,
  including a threaded CAS race). TTL from
  `REMEDIATION_EXECUTION_LEASE_SECONDS` (default 600.0, positive,
  fail-fast, tz-aware); fresh leases can never be stolen; progress
  writes renew expiry; `attempt` increments only on a real ownership
  claim. Lease owner is process-derived — the execute API still accepts
  only `{proposal_id, proposal_hash}` (+ authenticated operator),
  never owner/repository/target.
* **Bounded durable stage vocabulary** — `CLAIMED → WORKSPACE_CREATED →
  PATCH_APPLIED → VALIDATION_STARTED → VALIDATION_PASSED → COMMIT_CREATED
  → REMOTE_PUBLISHED → REMOTE_VERIFIED → PR_DISCOVERY → PR_CREATED →
  COMPLETED|FAILED`, each transition a short owner-gated transaction
  (never held across external ops). Losing the lease mid-run aborts the
  orchestrator (`RemediationStageGuardError`) without clobbering the
  new owner's state.
* **Crash recovery reconciles reality first** — expired lease reclaim
  re-runs integrity/freshness/patch/target gates, then inspects durable
  cursor + `ls-remote` SHA before choosing RESUME (remote == persisted
  commit → skip workspace, converge PR) or a deterministic FULL
  restart; missing/vanished or mismatched remotes fail closed with
  durable `RECONCILIATION_CONFLICT` evidence — never retarget, never
  force-push.
* **Mandatory PR reconciliation** — new
  `GitHubPRClient.find_existing_pull_request(s)` (auth, slug/base
  validation, bounded timeouts, distinct 401/403/404/429/5xx typed
  outcomes, no token leakage, typed `ExistingPullRequest` results) runs
  before every create: 0 → create, 1 open exact-identity match → reuse,
  merged/closed/multiple/mismatched-corroboration →
  `ExistingPullRequestConflict` fail closed. head/base/repository are
  the identity; PR body metadata is corroboration only — remote state
  is never authorization. Branch publication reconciles the same way
  (absent → push, equal → idempotent, unequal → conflict).
* **Failure/HTTP map:** new typed `ExecutionLeaseUnavailable`,
  `RemoteBranchConflict`, `ExistingPullRequestConflict` → 409;
  `RemoteReconciliationFailed` → 502 (`ExecutionLeaseExpired`,
  `ExecutionRecoveryConflict` remain reserved vocabulary). Active
  lease → 409 (no parallel execution); retry-after-success returns the
  existing result without incrementing attempts; unrecoverable
  conflicts stay `EXECUTION_FAILED` until operator action.
* **Observability:** `remediation.lease.acquired|rejected|expired`,
  `recovery.started|reconciled`, `remote.branch.reconciled`,
  `pr.discovery|reconciled|created`, `execution.completed|failed` —
  observer failures never change semantics. Per-attempt evidence
  (`exec-{id}-a{attempt}`) carries stage, status, repo, SHAs, lease
  owner and redacted reason; conflict evidence
  (`exec-{id}-recon-a{n}`) persists pre-lease reconciliation failures.
* **Tests (all green locally):** durable lease coordination (19 —
  two-instance claims, expiry reclaim, owner-gated finish, thread CAS
  race, stage guard, vocabulary, fail-closed store), service recovery
  (11 — crash/RESUME/FULL/vanished/wrong-SHA, stale/tampered/drift
  gates, lease theft mid-run), discovery client (21 — typed status
  matrix, filters, token-free messages), orchestration reconciliation
  (16 — reuse/merged/multiple/body-hash, resume re-inspect), §44
  recovery E2E with bare git + deterministic fake GitHub HTTP
  (worker A push → crash → worker B converges to exactly 1 commit /
  1 branch / 1 PR; PR-response timeout retry; wrong-SHA fail-closed;
  merged-PR no-second-PR), plus the full proposal battery —
  156 passed / 29 subtests. CI incident job: 26 modules (+2).
* **Honest limitations:** TTL lease ≠ distributed consensus (no
  exactly-once claim across DB+Git+GitHub — at-least-once +
  deterministic idempotency + fail-closed reconciliation only);
  PostgreSQL DDL mirrors SQLite but is not exercised in CI; hostile
  remote history beyond branch SHA/PR identity fails closed to an
  operator; workspace+subprocess still not a hardened sandbox.

## 2026-09-27 — Phase 6.2: controlled remediation execution (proposal → approval → validated patch → draft PR)

Completes the bounded vertical slice: an evidence-grounded, persisted
proposal can now be approved by an authenticated operator and executed
by deterministic code up to a **draft GitHub PR** — and nothing else.
No merge, no approve of the PR itself, no deploy/canary/rollback, no
authorization escalation, no multi-agent or model-supplied commands.

* **Approval (`POST /incidents/{id}/proposal/approve`).** Deterministic
  policy only: proposal exists, status approvable (`BLOCKED` never),
  canonical hash reproducible from persisted state and equal to both the
  stored and caller-claimed hash, risk class within the bounded
  `LOW`/`MEDIUM` set, generation → approval inside
  `REMEDIATION_PROPOSAL_TTL_SECONDS` (default 86400), and the
  authoritative deployment target still matching the proposal's trusted
  repository/SHA. `approved_by` is stamped from the verified JWT subject
  at the gateway (`/v1/incidents/{id}/proposal/approve`, operator role);
  AI confidence is never consulted for authorization. Approval persists
  `APPROVED` + `approved_by/approved_at/approval_hash` on the existing
  aggregate (idempotent for the same hash).
* **Execution (`POST /incidents/{id}/proposal/execute`, operator).**
  Pre-flight re-verifies integrity, approval freshness (TTL), patch
  policy and the authoritative target (mismatch → abort, never
  retarget), persists `EXECUTING` with a deterministic
  `uuid5(proposal_id:proposal_hash)` execution id, then runs the
  existing orchestration stack unchanged (SHA-pinned isolated workspace →
  bounded `git apply --check` → fixed validation profile → deterministic
  commit with parent == pinned SHA → push `automation/remediation/*` →
  remote SHA verification → **draft** PR). Success persists
  `PR_CREATED` + commit/branch/PR identity and attaches machine-readable
  `remediation_execution` evidence (`exec-{id}-a{attempt}`); failure
  persists `EXECUTION_FAILED` with stage + redacted reason and allows
  retry. Repeat execution reconciles the stored PR (same identity, no
  second push).
* **Lifecycle fields (additive):** `approved_by`, `approved_at`,
  `approval_hash`, `execution_id`, `executed_at`, `commit_sha`,
  `branch_name`, `execution_attempts`, `last_failure_stage`,
  `last_failure_reason`, plus statuses `APPROVED/EXECUTING/PR_CREATED/
  EXECUTION_FAILED` — restored on reload through the existing
  postgres/sqlite adapter; no schema/table changes.
* **Typed failures + HTTP map:** 404 not found / 422 integrity, patch
  policy, validation-failed / 409 not-approved, executing, stale /
  403 approval-policy, target-revalidation / 502 GitHub-remote failure.
* **Heredity fixes found while wiring the chain:** deterministic
  committer identity for remediation commits (a cloned workspace has no
  `user.name/user.email`; fixed non-impersonating
  `devops-ai-remediation@noreply.invalid`, env-overridable) and a
  composition-time remote-URL seam on the workspace service (production
  default still the fixed GitHub URL; tests inject a local bare origin).
* **Observability:** structured `remediation.*` logs for approval,
  target revalidation, execution start/stage/complete/fail/reconcile.
* **Tests:** approval policy matrix, execution gates + failure matrix
  (unapproved, wrong hash, tampered patch/path, deployment drift, stale,
  validation failure, GitHub failure, patch rejection, redaction, retry,
  duplicate reconcile, concurrency invariant, injection-as-data),
  controller mapping, gateway operator routes, and a real-git E2E
  (persisted proposal → approval → execution → bare-origin push → draft
  PR). CI incident job: 24 modules.
* **Honest limitations:** process-local locks (not distributed),
  workspace+subprocess ≠ hardened sandbox, crashed `EXECUTING` needs
  manual recovery, non-fast-forward push retries fail closed.

## 2026-09-27 — Phase 6.1 live vertical slice: monitoring runtime wiring

Closes the last runtime gap of the monitoring → proposal chain (proposal
remains proposal-only; nothing executes).

* **Monitoring composition root** — `monitoring_service` now composes the
  real producer at runtime: `application/dependencies.build_threshold_monitor()`
  (env `MONITORING_DANGER_LIMIT`, fail-fast config) → `RedisStreamPublisher`
  (`EVENT_BUS_REDIS_URL` / `EVENT_BUS_STREAM`) → existing
  `ThresholdValidator`; the entrypoint only wires routers/delegates.
* **Runtime input** — `POST /api/internal` on the monitoring app (the
  gateway `dispatch/monitoring` target, envelope
  `{"payload": <observation>, "forwarded_by": <jwt sub>}`) validates
  observations (bounded fields, finite floats — malformed → 422 with a
  sanitized error body) and delegates to the composed monitor; breaches
  publish `ThreatThresholdExceededEvent`, non-breaches publish nothing;
  event-bus failure → explicit 503 (never silent).
* **Producer/consumer envelope fix** — `RedisStreamPublisher` now XADDs
  the field set `RedisIncidentEventConsumer._deserialize` actually reads
  (`event_id`, `event_type`, `aggregate_id`, `timestamp`, `payload` as
  JSON string). Previously the single `data` field would have been
  acknowledged and dropped — the live chain could never connect.
* **Observability** — structured `monitoring.threshold_exceeded` marker
  (event_id/service/metric/value/threshold/correlation id; ids+numbers
  only). Optional observation `metrics` context passes through the
  pre-existing `payload.metrics` envelope key the incident handler
  already reads — no new schema fields.
* **Compose** — monitoring-service gains event-bus env + `depends_on:
  redis` (still no host ports; gateway-only publication preserved).
* **Tests** — producer test updated to the consumer envelope + real
  deserializer round-trip; new `tests/test_monitoring_runtime_slice.py`:
  composition/config unit tests, ingestion contract (publish, no-breach,
  malformed 422, bus 503, prompt-injection-as-data), and the vertical
  slice `monitoring input → event → consumer → incident (duplicate-event
  idempotent) → deployment evidence → RCA → persisted proposal` with
  no-side-effect spies across the whole chain.

## 2026-09-27 — Phase 6.1: incident → evidence → RCA → structured remediation proposal

Proposal-only pipeline inside `devops-ai-platform/incident_service` (no
execution of any kind — no clone/modify/commit/push/branch/PR, no deploy,
no remediation engine, no approval).

* **Producer wiring:** `ThresholdValidator` can publish
  `ThreatThresholdExceededEvent` via the new shared
  `RedisStreamPublisher` (`devops:events`) — the exact type the incident
  consumer already dispatches.
* **Idempotent ingestion:** incident and threshold-evidence ids derive
  from the producer `event_id` (uuid5); redeliveries return the existing
  incident without duplicates; proposal regeneration upserts one record.
* **Typed RCA:** `RootCauseAnalysis` domain object persisted as
  `kind="rca_result"` evidence; `RcaAnalyzerPort` (agent-service adapter,
  deterministic fakes in tests); `parse_rca_result` schema fail-closed
  (bounded types/lengths, confidence in [0,1], evidence refs must exist
  on the incident; legacy `supporting_evidence_ids` alias supported).
* **Trusted target binding:** `resolve_authoritative_deployment_target`
  reuses the Stage-5 gates (DEPLOYED, one-record canonical repo + 40-hex
  SHA, valid provenance); no trustworthy target → persisted
  `BLOCKED/MISSING_DEPLOYED_TARGET_EVIDENCE` proposal with empty identity
  fields — nothing fabricated.
* **Proposal generation:** AI may propose file/patch/plan/risk only;
  target-path policy + `HotfixProposal.apply_verification_pass()` +
  `HotfixValidationService` decide pass/fail (single-file policy kept);
  deterministic `LOW|MEDIUM|HIGH|BLOCKED` risk classifier; SHA-256
  canonical proposal hash over the fixed §18 field set; every §12 field
  survives repository reload; success → incident `RemediationProposed`.
* **API:** `POST/GET /incidents/{id}/proposal` (typed failures: 404/422/
  503) + gateway `GET /v1/incidents/{id}/proposal` (JWT + operator role).
* **Observability:** structured single-line JSON logs (`incident.created`,
  `evidence.attached`, `rca.started/completed/failed`,
  `proposal.generated/validated/blocked`) with correlation ids; no
  secrets, tokens or full AI outputs logged.
* **Tests:** incident suite grows 17 → 21 modules (140 tests), platform
  `tests/` gains the producer + full pipeline E2E; gateway read-route
  auth matrix added. Full local battery: 323 tests + 91 subtests green;
  §22 no-side-effect spies assert GitHub client/git/branch/PR/deploy/
  remediation-engine paths are never invoked while the proposal is still
  produced and persisted.

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
