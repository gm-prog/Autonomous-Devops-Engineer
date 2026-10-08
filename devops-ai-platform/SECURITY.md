# Security Model — Autonomous DevOps AI Platform (Phase 8.7-C)

This document describes the **current** trust model of the platform after the
Phase 8.7-C security integrity corrections. It is normative for the gateway,
monitoring, and Android client. Historical phase reports may describe earlier
states; where they disagree, this document and the code are authoritative.

---

## 1. Telemetry trust: human auth ≠ telemetry provenance

**Telemetry provenance and operator authorization are separate trust
domains.** Human authentication (JWT, any role — including `operator`,
`DevOpsLead`, `ClusterAdmin`) is NEVER a telemetry producer credential.

### 1.1 What was removed

The API gateway's generic dispatcher,
`POST /v1/gateway/dispatch/{service_name}`, forwarded an arbitrary
authenticated user's arbitrary JSON payload to an arbitrary
`{service}/api/internal` target — including the monitoring service. An
ordinary authenticated user could therefore submit fabricated monitoring
data and manufacture a threshold-breach incident. **That route no longer
exists** (structurally unavailable, enforced by the structural guards and
covered by behavioral tests).

### 1.2 The machine-authenticated ingestion boundary

Telemetry is ingested only through:

```
POST /api/internal/telemetry/observations   (monitoring-service)
```

with an HMAC-SHA256 shared-secret envelope:

| Header                 | Value                                    |
| ---------------------- | ---------------------------------------- |
| `X-Telemetry-Signature`| `sha256=<hmac-hex>` over the canonical message |
| `X-Telemetry-Timestamp`| Unix epoch seconds at signing time       |
| `X-Telemetry-Nonce`    | unique random string (single-use)        |

Canonical message: `METHOD\nPATH\nTIMESTAMP\nNONCE\nsha256hex(raw_body)\n`.

The producer secret is configured server-side via **`TELEMETRY_HMAC_SECRET`**.

Fail-closed guarantees:

* `TELEMETRY_HMAC_SECRET` absent → ingestion is **disabled** (503) for every
  request; no telemetry is recorded.
* Missing/malformed headers, signature mismatch, stale timestamp (beyond
  ±300 s skew window), or replayed nonce → rejected (401) **before** any
  domain state is touched: rejected requests record no datapoint and publish
  no event, so they cannot produce incidents.
* Comparison is constant-time; nonces are single-use within the replay window.
* No secret material is logged.

Authorized pipeline (only after authentication passes):

```
TelemetryObservation
  → MetricStreamAggregate.record_value
  → ThresholdValidator.evaluate_stream
  → ThreatThresholdExceededEvent (breach only)
  → DomainEventPublisher (Redis / event bus)
  → incident-service ingestion (OnMetricThresholdFailedHandler)
```

### 1.3 Gateway surface

The gateway exposes only **explicitly typed, function-specific** control-plane
operations:

* `GET /v1/gateway/metrics` — gateway self-telemetry (read).
* `POST /v1/gateway/incidents/{id}/proposals/{id}/approve` — operator role.
* `POST /v1/gateway/incidents/{id}/proposals/{id}/execute` — operator role.

No route on the gateway targets the monitoring service, and no route accepts
a user-chosen downstream service, internal path, or untyped relay payload.

---

## 2. Android client: no device-side provider secrets

**Android-distributed applications cannot keep a reusable provider secret
confidential.** Any credential shipped inside an APK — BuildConfig, string
resources, assets, SharedPreferences defaults, obfuscated or base64-wrapped
constants — is recoverable by anyone who can decompile the artifact.

Consequences for this app:

* The app **does not treat provider API credentials as device-side secrets**.
* `GEMINI_API_KEY` is no longer injected into the app (removed from
  `.env.example`; `BuildConfig.GEMINI_API_KEY` no longer exists or is used).
* AI analysis is carried **server-side**: the app sends non-secret repository
  metadata to the authenticated platform backend
  (`POST {backend}/api/v1/repository/analyze`), which calls Gemini with the
  key kept server-side.
* With no backend configured — or when the backend is unreachable — the app
  falls back to the non-secret offline template engine. A missing remote AI
  credential results in a **truthful non-secret fallback**, never a bundled
  credential.
* The app may know: an endpoint URL, non-secret configuration. It must never
  ship a reusable privileged Gemini secret.

Regression protection: the `android-gemini-secret` structural guard (and the
`android-secret-guards` CI job) fails the build if a Gemini secret reappears
in production Kotlin source, resources, manifest, assets, gradle
`buildConfigField`, committed env files, or SharedPreferences defaults.

---

## 3. Gateway JWT: fail-closed environment contract

Production and staging **require an explicit `JWT_SECRET` and fail closed
when it is absent.** The retired predictable fallback
(`super-secret-devops-platform-signature-token`) is quarantined to a
test-reference constant and can no longer authenticate any token — a token
signed with it is rejected in every mode.

| Environment variable | Contract |
| -------------------- | -------- |
| `JWT_SECRET` | HS256 signing secret. Required in all non-development deployments. Never logged. |
| `APP_ENV` | Explicit environment selector. Only the exact value `development` enables the development-only fallback secret. Development is never inferred from the execution context (outside Docker, local shell, etc.). |

Behavior:

* `JWT_SECRET` absent + `APP_ENV != development` (or unset) → **startup fails
  closed** (`GatewayConfigurationError`); no bundled secret is substituted.
* `JWT_SECRET` absent + `APP_ENV=development` → a clearly labeled
  development-only fallback is used and logged (without the secret value).
* Tokens are verified as signed HS256 JWTs with required `sub`, `roles`,
  `exp` claims. There is no token-literal or length-based mock acceptance.
* Rotating `JWT_SECRET` immediately invalidates previously issued tokens.
* Configuration and authentication logs never emit secret material.

Operator role authorization (`operator`, `DevOpsLead`, `ClusterAdmin`) gates
privileged control-plane operations. It is an **authorization** property and
grants no telemetry producer authority.

---

## 4. Structural guards

`devops-ai-platform/security_guards/` inspects the **actual repository
source** (AST where meaningful) so these weaknesses cannot silently return:

* `gateway-telemetry-trust` — no generic dispatch route, no monitoring target
  in the user-facing routing table, no user-input-derived downstream URL,
  telemetry boundary machine-authenticated (no user-JWT dependency).
* `android-gemini-secret` — no `BuildConfig.GEMINI*`, no Gemini URL with a
  runtime key parameter, no relocated secret (resources/manifest/assets/
  gradle/env/SharedPreferences defaults), no `AIza…` key literals.
* `jwt-fail-closed` — no bundled `JWT_SECRET` fallback, no hard-coded signing
  secret, legacy secret quarantined, development fallback gated behind the
  explicit switch.

Run locally:

```bash
cd devops-ai-platform
PYTHONPATH=. python -m security_guards
```

CI runs these guards as a **mandatory job** (`structural-guards`); a failed
invariant fails CI. Mutation/bypass tests
(`tests/test_security_mutations.py`) prove each guard turns red when the
corresponding control is weakened.

---

## 5. Security test-suite

```bash
cd devops-ai-platform
pip install -r requirements-test.txt
python -m pytest tests/ -v
```

Covers: JWT fail-closed contract, gateway control-plane authorization matrix,
telemetry HMAC trust boundary (valid/altered/replayed/unsigned),
no-side-effect-on-rejection with spies on validator/publisher/incident
ingestion, trusted producer end-to-end pipeline, Android static secret
guards, and adversarial mutations.

---

## 6. Known limitations (honest)

* The gateway's typed control-plane forwards are synchronous HTTP; in this
  codebase state they relay typed payloads to the incident service's internal
  API and surface downstream availability errors (502).
* Telemetry nonce state is process-local; a horizontally scaled deployment
  must share the nonce store (e.g. Redis) to keep replay protection global.
* The Android Gradle unit tests for the client path
  (`app/src/test/java/com/example/GeminiClientSecretPolicyTest.kt`) run under
  `gradle test` on machines with a JDK/Android SDK; CI enforces the Android
  secret property through the static guards, which do not require a JDK.
* mTLS between producer and monitoring service is not yet deployed; the HMAC
  envelope is the current machine-authentication mechanism and assumes
  network-level segregation of `/api/internal` endpoints.
