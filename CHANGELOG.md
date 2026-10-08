# Changelog

All notable changes to this project are documented in this file.

## [8.7-D.1-CORRECTION-2] — Final Hardening After Independent Adversarial Audit (2026-10-08)

Final hardening pass for Phase 8.7-D.1, driven by an independent
adversarial audit of the green-CI state (`eb90a88`). No feature
expansion, no architectural rewrite; the green CI was treated as
evidence, not approval. All new controls carry a structural guard plus a
behavioral failure test, and removal is proven adversarial by the new
mutations M22–M24 (isolated repository copies).

### P1-A — circuit breaker can wedge permanently HALF-OPEN (fixed)

A pre-provider exception raised after acquiring the half-open probe lease
(missing `GEMINI_API_KEY`, budget store unavailable, budget ceiling
exceeded) left the circuit `HALF-OPEN` forever: every subsequent call
failed fast and no probe was ever permitted again. The lease now settles
through **one exception-safe finalization path** in
`GeminiCallerAdapter._generate_text` (single `try/except` around the
entire post-admission section — no per-branch remember-to-settle
discipline): success → `CLOSED`; provider failure → `OPEN`; pre-provider
failure → `OPEN` with a **fresh cooldown** via the new idempotent
`_settle_failed_probe()` (deliberately not `CLOSED`, so an unconfigured
or exhausted deployment cannot stream unlimited doomed probes). Coverage:
A1–A6 in `tests/test_gemini_analysis_path.py` (including a 20-concurrent
pre-provider failure that must not leave a permanent `HALF-OPEN`);
adversarial proof **M22** (settlement bypass wedges the circuit: ten
fresh cooldowns + restored credential + healthy provider, and the
weakened circuit still never probes again).

### P1-B — empty/missing/unknown `APP_ENV` must not resolve to local state (fixed)

The in-process (single-instance) rate limiter and budget ledger were
reachable with an EMPTY, MISSING, or UNEXPECTED `APP_ENV` — an
unidentified environment silently got single-replica state. The
classification is now fail-closed in **both**
`load_analysis_rate_limit_settings` (gateway) and
`GeminiRuntimeConfig.from_env` (agent): only the explicitly recognized
`development` and `test` values may use local state; everything else
(staging, production, empty, missing, unexpected) is treated as
NON-DEVELOPMENT and requires the shared Redis stores, with the documented
exact-value single-instance flags as the only explicit opt-out. The full
environment matrix (development / test / staging / production / empty /
missing / unexpected, each ± Redis) is covered by
`TestAppEnvClassificationMatrix`; tests asserting unset-env = safe local
were updated, not weakened. Adversarial proof **M23** (admitting `""` to
the local-state set in either service makes the empty/missing `APP_ENV`
silently resolve to local state — guard turns red). The test process
itself now declares `APP_ENV=test` explicitly in `tests/conftest.py`
(development mode enabled by exact value, never inferred).

### P1-C — real-Redis CI gate was not fail-closed (fixed)

The `redis-integration` job set `REDIS_URL` but never
`REDIS_INTEGRATION_REQUIRED=true`, so a missing/unreachable store would
degrade the mandatory gate into **silent skips** (green CI, zero Redis
tests executed). Both live-store steps now set the flag, and the
`d1-runtime-contract` structural guard checks the contract on every run:
every step executing the real-Redis suite must set `REDIS_URL` **and**
`REDIS_INTEGRATION_REQUIRED=true`. Adversarial proof **M24** (removing the
flag from an isolated CI copy turns the guard red, and the fixture's
fail-closed resolution is behaviorally demonstrated: no flag → silent
skip; flag → hard failure).

### P2 — exactly-once wording (corrected)

The finalization guarantee is now stated truthfully: **exactly-once per
reservation while the finalization claim is retained**. The retention
window is documented explicitly (SECURITY.md §6.2 and
`gemini_caller.py`): the claim key carries a 45-day TTL — longer than one
UTC calendar billing period — so the claim outlives every period it can
belong to; after expiry, a redelivered finalize can at most touch the
already-expired period's counters, never the current period's budget.

### P2 — truthful Gradle verification (fixed)

The in-step `gradle --version` showed the runner's preinstalled Gradle
(`$GITHUB_PATH` takes effect only in later steps), misrepresenting the
toolchain. The `android-unit-tests` job now runs the **pinned executable
by absolute path** — `/opt/gradle/gradle-9.3.1/bin/gradle` — for the
version check, `:app:testDebugUnitTest`, and `:app:assembleDebug`, and
prints the resolved executable path in the test step, so the log proves
the exact toolchain that executed.

### P2 — deprecation warnings (fixed, no global suppression)

* `MainActivity.kt`: `Icons.Filled.List` and `Icons.Filled.ArrowForward`
  (both deprecated) replaced with the auto-mirrored equivalents
  (`Icons.AutoMirrored.Filled.List` / `Icons.AutoMirrored.Filled.ArrowForward`),
  which mirror correctly in RTL layouts.
* The `StarletteDeprecationWarning` ("Using `httpx` with
  `starlette.testclient` is deprecated; install `httpx2`") is resolved by
  EXACTLY pinning the last pre-starlette-1.0 generation in
  `requirements-test.txt`: `fastapi==0.128.8`, `starlette==0.52.1`,
  `anyio==4.12.1` (anyio 4.15+ would reintroduce a different TestClient
  deprecation via the `anyio.abc.BlockingPortal` alias — 4.13/4.14
  verified clean, 4.15 emits the warning), `httpx==0.28.1`.
  The full suite now runs with zero deprecation warnings from the test
  client stack; nothing is globally suppressed.

### Retained (verified, not modified in behavior)

JWT fail-closed environment contract, role-based authorization, telemetry
machine-auth (HMAC envelope), no generic dispatch, server-side-only
Gemini credential (no Android secret), typed analysis route,
gateway→agent internal auth, HTTPS bearer-JWT transport, Redis rate
limiting + budget ledger, `maxOutputTokens` output bound, strict
five-field validation, circuit breaker with single half-open probe
(M21), truthful failure mapping, canonical digest-pinned compose stack,
and mutations M1–M21 (M10's injection point was re-targeted to the
restructured `_generate_text`; M20's target re-targeted to the
fail-closed classification — intent unchanged, both still turn CI red).

## [8.7-D.1-CORRECTION] — Verified CI-Failure Remediation (2026-10-08)

Correction pass for the verified CI failures of the 8.7-D.1 release commit
(`64ce8e5`). Scope: restore the D.1 contract; no new features, no
architectural rewrites. All fixes were reproduced and verified locally
(including against a real Redis 7.2.5 server built from source) before
commit; the GitHub Actions evidence for this commit is the authority for
the Docker/Android/CI claims.

### Fixed

* **Redis budget finalize (broken command + duplicate accounting).** The
  finalize script referenced the nonexistent `DECRBYFLOAT` command (real
  Redis: "Unknown Redis command called from script"), which made every
  finalize fail with `BudgetStoreUnavailableException`. The reservation
  release now uses `INCRBYFLOAT <reserved_key> -<amount>`. Finalize is also
  **exactly-once per reservation**: an atomic, period-scoped claim key
  (`devops:gemini:budget:{period}:finalized:{reservation_id}`) is
  check-and-set inside the finalize script itself, so duplicate
  finalizations (retries, concurrent duplicate handling, cross-replica)
  cannot double-subtract the reserved pool or double-count committed
  spend. `finalize()` now returns whether the accounting was applied. The
  in-process ledger enforces the same contract. The finalize script was
  verified against a real Redis 7.2.5 server.
* **Android compile failure.** `MainActivity.kt:242` used an invalid
  `when` arm (`"OFFLINE_SIM", else -> …`); the offline-simulation state
  now has its own branch and the `else` maps unknown states to the safe
  offline/non-success color — never the live/success color.
* **Android error-detail leakage.** Transport failures now surface the
  stable user-facing string "Unable to reach the analysis gateway." and
  malformed-URL rejections "Gateway URL is malformed."; the raw exception
  message (which can embed URL/host/socket/DNS details) is never surfaced
  or logged (at most the exception class name). Regression test added to
  `AnalysisUrlPolicyTest.kt`. `app/build.gradle.kts` enables
  `isReturnDefaultValues` so the unit tests can exercise `Log`.
* **Test dependency contract.** `devops-ai-platform/requirements-test.txt`
  is the single authoritative dependency contract for `tests/` and
  `security_guards/` (adds `redis`, `pyyaml`, FastAPI test client, JWT,
  requests, pytest). Every Python CI job installs only that file — the
  per-job `pip install … pyyaml` / `… redis` extras that masked
  `ModuleNotFoundError` failures are removed.
* **Compose smoke tested the wrong role.** The boot smoke minted an
  `Administrator` token (a 403 role), so the missing-`GEMINI_API_KEY` →
  503 property was never exercised. The smoke now mints a
  `Developer`-role token (an authorized role) and proves the exact
  sequence: valid JWT → valid role → rate limiter → gateway → agent → key
  absent → exactly 503 (never 200 / fabricated).

### Added

* **Production shared-state requirement (fail closed).** When `APP_ENV` is
  `staging` or `production`, the agent and gateway refuse to start unless
  the shared Redis store backs both the budget ledger and the analysis
  rate limiter. The only exception is the explicit single-replica mode via
  the exact-value (case-sensitive) flags
  `GEMINI_BUDGET_SINGLE_INSTANCE_PRODUCTION=true` /
  `ANALYSIS_RATE_LIMIT_SINGLE_INSTANCE_PRODUCTION=true`. `dev` keeps the
  in-process stores. Tests cover both sides (production+shared passes,
  production+in-process fails, flag variants rejected, dev+local passes,
  `create_app` startup fails closed).
* **Single half-open probe lease.** After the cooldown, exactly one
  concurrent caller performs the atomic `OPEN → HALF-OPEN` transition and
  probes the provider; all other concurrent callers fast-fail (503, no
  provider contact). A failed probe re-opens the circuit immediately; a
  successful probe closes it. Barrier test: N concurrent racers after the
  cooldown produce exactly one provider call.
* **Real-Redis integration suite (8 properties).** Shared rate limiter,
  shared budget, concurrent reservations respecting the ceiling, finalize
  semantics, missing-usage full-reservation retention, calendar-month
  rollover, duplicate-finalize once-only (sequential and 8-thread
  concurrent), and store-outage fail-closed — all run against a
  digest-pinned real Redis (no fakeredis); skipped locally, hard-required
  in the CI `redis-integration` job.
* **Adversarial mutations M19–M21.** M19: exactly-once finalize claim
  removed from the Redis script (structural guard; the behavioral proof —
  the weakened script double-counts on a real Redis — runs in the
  real-Redis CI job). M20: production shared-state requirement bypassed.
  M21: half-open single-probe lease removed (20-call race). M1–M18 are
  unchanged.
* **Canonical compose production posture.** The agent service in
  `devops-ai-platform/docker-compose.yml` now runs with
  `APP_ENV=production` (both stores on shared Redis), satisfying the new
  contract by construction.

### Verified

* Real Redis 7.2.5 (built from source locally; digest-pinned image in
  CI): all 8 integration properties green, including concurrent
  duplicate-finalize once-only and the M19 behavioral proof.
* All Python suites, structural guards, and the 21-test mutation suite
  green locally; Android verified with the real Gradle toolchain and the
  compose stack verified by the CI runtime job (build, boot, health,
  host-port non-exposure, exact-503 smoke) — per-run evidence is the
  GitHub Actions artifacts for this commit. No production-verification
  claim is made for the provider path.

## [8.7-D.1] — Production Security & Runtime Hardening (2026-10-08)

Audit-driven release blockers corrected on the server-side analysis path,
the Android transport, and the canonical runtime. No behavior is claimed
production-verified: the provider path has not been exercised against the
real Gemini API, and the compose boot smoke runs without provider
credentials to verify the truthful fail-closed behavior.

### Added

* **Single shared analysis handler per process (P0-1).** The agent-service
  now constructs exactly one analysis handler in `create_app` and shares it
  via `app.state.analysis_handler`; the internal route resolves the shared
  instance (no per-request adapter construction). `GeminiRuntimeConfig` is
  the single configuration source for all Gemini tunables (one env var, one
  default each — the 150 vs 100 budget default conflict is eliminated).
* **Atomic pre-invocation budget reservation (P0-2).** Worst-case cost
  (retries × bounded tokens × documented prices) is reserved atomically
  against the UTC calendar-month ceiling before any provider contact;
  rejected reservations block the call before the provider is contacted.
  Reconciliation uses provider `usageMetadata` when present and keeps the
  FULL reservation when it is missing (never undercount). `local` store =
  explicit single-process contract; `GEMINI_BUDGET_STORE=redis` = shared
  atomic ledger (Lua) across replicas; an unreachable store fails closed
  (503). The budget is an application safety budget, NOT a Google billing
  cap (documented in SECURITY.md 6.2).
* **Route-specific rate limiting on the analysis route (P0-3).** Fixed
  60-second window: 30/min per JWT `sub` and 120/min per direct-TCP-peer IP
  (forwarded headers are never read), env-configurable, atomic counters
  (Redis Lua or explicit in-process single-instance mode), 429 +
  `Retry-After`, authentication before limiting, and fail-closed 503 when
  the limiter/store is missing or unreachable.
* **Android cleartext transport policy (P0-4).**
  `validateAnalysisUrl(rawUrl, debugBuild = BuildConfig.DEBUG)` rejects any
  URL that is not `https://`; `http://` is permitted only for the
  local-emulator hosts (`10.0.2.2`, `localhost`, `127.0.0.1`) and only in
  debug builds. Unsafe/malformed URLs are rejected before the request is
  constructed (typed failure, nothing sent); the policy runs before the
  `Authorization: Bearer` header is attached. The Network Security
  Configuration now permits no cleartext in the main config and local hosts
  only in the debug overlay; the manifest wires the NSC.
  `AnalysisUrlPolicyTest.kt` (6 offline JUnit tests) covers HTTPS
  success, arbitrary-HTTP rejection, debug-local allowance,
  production-build local rejection, malformed URLs, and the request-level
  pre-send failure.
* **Canonical D1 compose stack (P0-5).** New
  `devops-ai-platform/docker-compose.yml`: `api-gateway` (host 8000) +
  `agent-service` (8020, never host-exposed) + `redis` (never host-exposed),
  digest-pinned images (`redis:7.2-alpine@sha256:29e8589c…`,
  `python:3.11-slim@sha256:0dd364ba…`, resolved 2026-10-08), healthchecks,
  required `${JWT_SECRET:?}` / `${AGENT_INTERNAL_TOKEN:?}`, optional
  `GEMINI_API_KEY` (empty → agent fails closed 503). The previous stack is
  quarantined in `docker-compose.legacy.yml` with its hardcoded
  `POSTGRES_PASSWORD` removed. Both service Dockerfiles pin the digest
  base image.
* **CI: real Android Gradle job, compose runtime job, real-Redis job.**
  `android-unit-tests` (JDK 17 + Android SDK + Gradle 9.3.1, pinned to the
  AGP 9.1.1 documented minimum): unit tests incl. the new policy tests +
  `assembleDebug`. `compose-runtime`: `docker compose config`, image
  builds for both services, boot smoke (readiness, gateway→agent over the
  compose network, agent port not host-exposed, authenticated analysis
  without provider credentials → truthful 503), log artifacts.
  `redis-integration`: real-Redis tests for the shared budget ledger and
  shared rate limiter (hard-fails in CI without `REDIS_URL`). All action
  pins upgraded to current non-deprecated majors (checkout@v7,
  setup-python@v7, setup-java@v6, upload-artifact@v7,
  android-actions/setup-android@v4) — no Node deprecation warnings.
* **Structural runtime guard + mutations M13–M18.** New
  `d1-runtime-contract` guard (canonical services, existing Dockerfiles,
  digest pins, host-port policy, CI builds both images, legacy password
  removed). New adversarial mutations: M13 per-request adapter
  construction, M14 analysis rate limiting removed, M15 cleartext bearer
  transport re-enabled, M16 non-atomic budget check-then-act, M17 agent
  build removed from the canonical runtime, M18 deprecated model / removed
  output bound — each proven to turn the suite red.
* **Current, bounded provider contract (P0-6).** Default model
  **`gemini-3.8-flash`** (verified 2026-10-08 against the official Gemini
  API deprecations, model, and pricing pages; `GEMINI_MODEL` override
  remains). Cost defaults use the post-promotion rates from the official
  pricing page fetched 2026-10-08 (input $1.50 / 1M, output $7.50 / 1M),
  documented in `gemini_caller.py`. The provider request is bounded and
  structured: `application/json` + five-field schema + explicit
  `maxOutputTokens`; all LLM paths keep the same strict validation and the
  bounded timeout/retry + typed error mapping.

### Changed

* **Truthfulness corrections (P1).** `github_pr_client.create_pull_request`
  raises when credentials are missing or the API omits `html_url` (no
  fabricated PR URL); `mark_pr_ready_for_review` performs the correct
  GitHub operation (`PUT …/pulls/{n}` with `draft: false`) and raises on
  missing credentials or non-success (never success for a no-op); the
  `apply_verification_pass` placeholder is renamed
  `record_claimed_verification` (records a claim, runs no checks, leaves
  the proposal unverified — the apply-automated-fix flow no longer treats
  it as verified); the git SSH client verifies host keys against an
  operator-managed `known_hosts` (`DEVOPS_SSH_KNOWN_HOSTS_PATH`) and is
  refused without it (`StrictHostKeyChecking=no` /
  `UserKnownHostsFile=/dev/null` removed); dataclass timestamp defaults use
  `default_factory`.
* `SECURITY.md` updated normatively for the D.1 controls (single shared
  handler, budget reservation/reconciliation and the explicit
  "not a Google billing cap" distinction, rate-limit semantics and
  defaults, model/pricing citation, transport policy, canonical compose
  stack, truthfulness corrections, new guard and mutations).

## [8.7-D] — Verified Server-Side Gemini Integration (2026-10-08)

### Added

* **Authenticated, typed, role-gated repository-analysis endpoint.**
  `POST /api/v1/repository/analyze` on the api-gateway: JWT required
  (401 otherwise), role-gated to Developer / operator / DevOpsLead
  (403 otherwise), strict Pydantic schemas that validate repository
  name/URL/framework/technology, reject malformed or oversized input
  (422), and forbid extra fields — a client-supplied `gemini_api_key`
  (or any provider key) is rejected, never forwarded, never accepted.
  The gateway forwards a typed internal call
  (`POST /api/internal/repository/analyze` on the agent-service) with
  the verified identity; no generic dispatch was restored.
* **Agent-service analysis command + Gemini integration.** New
  `application/commands/analyze_repository.py` and
  `presentation/rest/analysis_router.py` wired through the existing
  agent-service boundary with DI around `RemoteLLMInterface` /
  `GeminiCallerAdapter`. The Gemini credential is read only from the
  agent-service server environment.
* **Hardened `GeminiCallerAdapter`** (`infrastructure/llm/gemini_caller.py`):
  fails closed when `GEMINI_API_KEY` is absent (503, no fabricated
  response); bounded timeout and bounded retries (transient failures
  only); circuit breaker with half-open recovery; monthly USD budget
  ceiling; structured/validated response extraction; typed exceptions
  distinguishing provider auth failure (401/403), rate limit (429),
  timeout, upstream failure, and malformed response; the credential
  never appears in URLs, exceptions, responses, or logs.
* **Android live analysis path (opt-in, JWT-only).** `analyzeRepoAsync`
  now runs the live path only when the operator has configured the
  gateway URL + platform-issued gateway JWT and the probe reports
  CONNECTED; the client sends a typed analysis request with
  `Authorization: Bearer <JWT>` only (no provider key). Results are
  surfaced truthfully as `LIVE_BACKEND` / `OFFLINE_SIM` / `LIVE_FAILED`
  / `OFFLINE_FAILED` in a header badge; a failed live attempt is never
  substituted by a fake "successful Gemini" result, and the offline
  engine remains the default when live analysis is off or the backend
  is unavailable.
* **Tests:** new `tests/test_gemini_analysis_path.py` (gateway authz /
  422 / downstream mapping / no credential leak; agent boundary
  fail-closed / typed / malformed; caller resilience units; e2e
  fake-provider path) and five new mutations: M8 (role-gate bypass),
  M9 (client-supplied key field), M10 (missing-key fail-open),
  M11 (provider 401 swallowed into fabricated success), M12 (budget
  bypass). M5/M7 re-anchored to the new transport contract.

### Changed

* **Documentation re-anchored to the new truth** (SECURITY.md §2,
  README, VS_CODE_AND_VERCEL_ROADMAP.md, `.env.example`): analysis is
  offline by default; the authenticated server-side path is implemented
  on this branch (JWT + role-gated, server-side key, fail-closed); the
  live path has **not** been exercised against the real Gemini API in a
  production deployment on this branch, and no production-verification
  claim is made.

### Verification status (honest)

* Backend path verified by the automated gateway / agent / caller /
  Android test suites in this environment (see CI).
* **No genuine end-to-end call against the real Gemini API was executed**
  on this branch (no provider credential is configured in the test or CI
  environment). This entry does not claim production verification.

## [8.7-C.3] — Roadmap & Documentation Truthfulness Reconciliation (2026-10-08)

### Corrected

* **Root cause:** `VS_CODE_AND_VERCEL_ROADMAP.md` still told developers that
  toggling "Connect to Remote Backend" and pinging the gateway made "the
  repository generator route analyze tasks directly to your remote edge
  server instead of using simulation" — a flow that does not exist on this
  branch.
* **Fix (documentation-only, no implementation change):**
  * Added a "Current Branch Architecture" statement: Android repository
    analysis is offline and deterministic; the configured gateway URL is
    diagnostics-only and does not route repository analysis, Gemini
    requests, deployments, or execution through the remote server.
  * Separated the two independent flows (on-device analysis vs gateway
    reachability probe) and marked Step 1/Step 2 as backend-infrastructure
    documentation (running/deploying the backend is not proof that Android
    consumes it for analysis).
  * "Step 3: Connecting Your Android App" rewritten as "Android Gateway
    Diagnostics": probe result is reachability status only; repository
    analysis remains offline.
  * `GEMINI_API_KEY` instructions explicitly marked server-side only —
    never in the APK, `BuildConfig`, resources, preferences, or source
    literals.
  * Future backend integration (authenticated Android → typed endpoint →
    analysis service → server-side Gemini) explicitly labeled **future /
    not implemented on this branch**; the existing cockpit is documented as
    local simulation, not provider telemetry.
* **Tests:** new roadmap truthfulness contract (stale remote-analysis
  claims forbidden; offline/diagnostics-only/future-boundary language
  required) plus mutation M7, which reintroduces the stale claim and proves
  the guard detects it. No security control changed.

## [8.7-C.2] — Android UI Truthfulness & Offline Gemini Contract (2026-10-08)

### Corrected

* **Root cause:** residual UI language still implied live Gemini
  functionality even though the analysis path is offline/simulated on this
  branch.
* **Fix (labeling only — no architecture change):**
  * Repository registration copy: "compile live blueprints via Gemini AI"
    → "generate offline DevOps blueprints (on-device simulation — no live
    Gemini calls on this branch)".
  * Analysis button relabeled `Analyze (Offline AI)`; analysis action
    comment updated; report box renamed to "AI Discovery Report (Offline)".
  * "Gemini Resilient API Cockpit" (locally simulated metrics) renamed to
    "AI Simulation & Resilience Cockpit" (`GeminiApiCockpit` →
    `AiSimulationCockpit`); subtitle and metric labels now explicitly
    state "Simulated API Rate Load", "Simulated Token Cost", "Simulated
    Circuit State" / "not live Gemini telemetry". Simulation functionality
    retained, honestly labeled.
  * Gateway settings copy no longer claims the app routes deployments,
    alerts, or code reviews to a remote server; the probe is labeled
    diagnostics-only.
* **Tests:** new UI truthfulness contract tests (stale live-Gemini phrases
  forbidden; explicit offline/simulation language required; simulated
  metric labels required) plus mutation M6, which reintroduces the stale
  claims and proves the guard detects them. No security control changed.

## [8.7-C.1] — Android Remote-Analysis Contract Correction (2026-10-08)

### Corrected

* **Root cause:** Phase 8.7-C removed the Android provider secret correctly,
  but `GeminiClient.kt` then routed analysis through
  `BackendGatewayClient.queryRemoteAnalysis()` — an **unauthenticated**
  request to `/api/v1/repository/analyze`, an endpoint that is not
  implemented (nor authenticated) anywhere in this branch. The code and the
  current documentation therefore claimed an authenticated server-side
  Gemini path that did not exist.
* **Fix (offline-only, truthful contract):**
  * `GeminiClient.analyzeRepository` is now offline-only: no
    `backendBaseUrl` parameter, no network call, no provider credential —
    it always runs the deterministic non-secret template engine.
  * Removed `BackendGatewayClient.queryRemoteAnalysis()` (client for the
    fictitious endpoint); the baseline `testConnection` reachability
    diagnostic is retained and is now clearly labeled diagnostics-only.
  * `DevOpsRepository.analyzeRepoAsync` no longer selects a remote path;
    the ViewModel passes no remote selection; the header badge always
    reflects the offline engine (`OFFLINE_SIM`) instead of claiming live AI.
  * `SECURITY.md` / `README.md` now state exactly: this branch does not
    expose a verified live Gemini backend integration for the app; Android
    uses the non-secret offline analysis path; server-side Gemini
    integration belongs to a later backend integration phase.
* **Tests/guards:** the Android contract tests now verify the offline-only
  truth (no fictitious remote path, no fake client-side authentication,
  documentation makes no false backend claim); a new mutation test proves
  reintroducing the fictitious unauthenticated remote path turns the suite
  red. No telemetry/JWT/gateway changes.

## [8.7-C] — Security Integrity Corrections (2026-10-08)

### Fixed

#### 1. Telemetry trust no longer depends on ordinary user JWTs
* **Root cause:** `POST /v1/gateway/dispatch/{service_name}` accepted any
  authenticated JWT and forwarded arbitrary JSON to
  `{service}/api/internal`, including the monitoring service. An ordinary
  authenticated user could submit fabricated telemetry and manufacture a
  threshold-breach incident.
* **Fix:**
  * Removed the generic user-facing dispatcher from the API gateway. The
    gateway now exposes only explicitly typed control-plane operations
    (`/v1/gateway/metrics`, incident proposal approve/execute) with a fixed
    routing table that no longer contains the monitoring service.
  * Added a dedicated machine-authenticated telemetry ingestion boundary on
    the monitoring service: `POST /api/internal/telemetry/observations` with
    an HMAC-SHA256 envelope (`X-Telemetry-Signature`, `X-Telemetry-Timestamp`,
    `X-Telemetry-Nonce`) verified against `TELEMETRY_HMAC_SECRET`.
    Authentication runs before any domain state is touched; rejected
    requests record no datapoint and publish no event. No producer secret
    configured → ingestion disabled (503, fail closed).
  * Wired the authenticated observation through the existing pipeline:
    `MetricStreamAggregate` → `ThresholdValidator` →
    `ThreatThresholdExceededEvent` → `DomainEventPublisher` → incident
    ingestion.

#### 2. Android Gemini secret removed from the APK trust model
* **Root cause:** `GeminiClient.kt` read `BuildConfig.GEMINI_API_KEY`
  (generated from `.env.example` via the Secrets Gradle Plugin) and placed it
  in the Gemini request URL — recoverable from any distributed APK.
* **Fix:**
  * Removed all `BuildConfig.GEMINI_API_KEY` usage from the request path.
    When a platform backend URL is configured, the AI request is carried
    server-side by the authenticated backend
    (`POST {backend}/api/v1/repository/analyze`); the Gemini key stays
    server-side. Without a backend (or on failure) the app uses the existing
    non-secret offline template engine — a truthful fallback, not a bundled
    credential.
  * Removed `GEMINI_API_KEY` from `.env.example` so the field is no longer
    generated into the app's BuildConfig.
  * Updated the UI status badge to reflect remote-AI configuration
    (`REMOTE_AI` / `OFFLINE_SIM`) instead of an API-key presence state.

#### 3. JWT fallback secret fails closed outside explicit development
* **Root cause:** `GatewaySettings.JWT_SECRET` fell back to the hard-coded,
  predictable `super-secret-devops-platform-signature-token`, so a directly
  executed gateway outside a controlled environment silently used a bundled
  signing secret. Token "verification" was also a mock (any string ≥ 10
  chars accepted as a Developer).
* **Fix:**
  * `JWT_SECRET` is now resolved by a fail-closed configuration loader:
    absent outside explicit `APP_ENV=development` → startup raises
    `GatewayConfigurationError` and the gateway does not boot. No bundled
    secret is substituted in production/staging.
  * The development-only fallback is a distinct, clearly labeled value used
    only behind the exact `APP_ENV=development` switch. The retired legacy
    value is quarantined to a test-reference constant and can no longer
    authenticate any token.
  * Real signed HS256 JWT verification (`sub`, `roles`, `exp` required);
    the magic-token mock acceptance and the magic admin token were removed.
    Logs never emit secret material.

### Added

* `devops-ai-platform/tests/` — focused security suites (JWT fail-closed
  contract, gateway control-plane authorization matrix, telemetry HMAC trust
  boundary with replay/tamper/no-side-effect proofs, Android static secret
  guards) plus adversarial mutation/bypass tests proving each guard turns
  red when its control is weakened.
* `devops-ai-platform/security_guards/` — structural guards over the actual
  repository source (gateway dispatch/telemetry surface, Android secret
  surface, JWT configuration surface), runnable standalone
  (`PYTHONPATH=. python -m security_guards`).
* `devops-ai-platform/SECURITY.md` — normative current security model.
* `app/src/test/java/com/example/GeminiClientSecretPolicyTest.kt` — unit
  tests for the keyless client path (run under `gradle test`).
* `.github/workflows/ci.yml` — mandatory CI jobs: focused security suites,
  structural guards (fails on missing security evidence).

### Documentation

* `README.md` — corrected setup (no app-side Gemini key), security model
  section.
* `devops-ai-platform/SECURITY.md` — new normative security model.
