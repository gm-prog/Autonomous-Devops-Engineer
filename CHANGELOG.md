# Changelog

All notable changes to this project are documented in this file.

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
