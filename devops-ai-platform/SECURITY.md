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

## 2. Android client: no device-side provider secrets; authenticated server-side analysis (offline by default)

**Android-distributed applications cannot keep a reusable provider secret
confidential.** Any credential shipped inside an APK — BuildConfig, string
resources, assets, SharedPreferences defaults, obfuscated or base64-wrapped
constants — is recoverable by anyone who can decompile the artifact.

What this branch does and does not do (truthful contract for this branch):

* **No device-side provider secret, ever.** The app **does not treat provider
  API credentials as device-side secrets**. `GEMINI_API_KEY` is no longer
  injected into the app (removed from `.env.example`; `BuildConfig.GEMINI_API_KEY`
  no longer exists or is used).
* **Two explicit analysis paths (implemented in Phase 8.7-D).** Repository analysis runs either on the
  **non-secret offline path** (deterministic template engine — the default,
  no network round-trip, no credential) or on the **authenticated server-side
  Gemini path**: the Android client sends a typed analysis request to
  `POST /api/v1/repository/analyze` carrying only a
  `Authorization: Bearer <JWT>` header; the api-gateway verifies the JWT and
  the caller's role (Developer, operator, DevOpsLead), then forwards a
  typed internal call to the agent-service, which invokes Gemini using
  `GEMINI_API_KEY` read **from the agent-service server environment**.
  Provider credentials belong **server-side** — that is valid server-side
  code and is not reachable from the APK. The gateway-to-agent hop is a
  separate trust boundary authenticated by `AGENT_INTERNAL_TOKEN`; the agent
  rejects internal analysis requests without that credential before invoking
  Gemini. The gateway URL in Settings is a
  configuration the user provides; the reachability check stays diagnostics-only.
* **Authenticated and role-gated, fail-closed end to end.** The analyze
  endpoint rejects unauthenticated requests (401), insufficient roles (403),
  and malformed or oversized payloads (422). A **client-supplied provider key
  is rejected** (the request schema is strict: `extra="forbid"`; there is no
  `gemini_api_key` field). The agent-service **fails closed** when
  `GEMINI_API_KEY` is absent (503, no fabricated response), applies bounded
  timeout/retry, a circuit breaker, and a monthly budget ceiling, and never
  echoes the credential in responses or logs.
* **No silent fabrication on the client.** If the backend is unavailable,
  the live path is not configured, or the server reports failure, the app
  records a **typed, truthful failure** (`LIVE_FAILED` with the reason) — it
  never falls back to a fake "successful Gemini" result, and the analysis
  screen displays an explicit source badge distinguishing `OFFLINE_SIM`
  (local simulation) from `LIVE_BACKEND` (server-side provider result).
* **Honest verification status.** The path above is implemented and verified
  by the automated gateway/agent/Android test suites on this branch. It has
  **not** been exercised against the real Gemini API in a production
  deployment on this branch; no production-verification claim is made.

Regression protection: the `android-gemini-secret` structural guard (and the
`android-secret-guards` CI job) fails the build if a Gemini secret reappears
in production Kotlin source, resources, manifest, assets, gradle
`buildConfigField`, committed env files, or SharedPreferences defaults. The
Android contract tests additionally fail if the analysis transport contract
is violated: a call to `/api/v1/repository/analyze` without a Bearer-JWT
Authorization header, the reintroduction of `queryRemoteAnalysis`, any
provider-secret literal in production code, or the absence of the truthful
`OFFLINE_SIM` / `LIVE_BACKEND` / `LIVE_FAILED` state handling.

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


### 2.1 Server-to-server analysis boundary

The public gateway JWT authenticates the end user; it is not reused as the agent-service network credential. The gateway sends the authenticated identity for audit purposes plus `X-Agent-Internal-Token` to the fixed agent-service analysis endpoint. The agent compares that shared secret constant-time and rejects missing/invalid credentials before any LLM call.
