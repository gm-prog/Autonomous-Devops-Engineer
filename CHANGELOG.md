# Changelog

All notable changes to this project are documented in this file.

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
