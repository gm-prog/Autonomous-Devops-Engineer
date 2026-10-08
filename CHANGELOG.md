# Changelog

All notable changes to this project are documented in this file.

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
