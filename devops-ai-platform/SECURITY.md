# Security Model — Autonomous DevOps AI Platform (Phases 8.7-C / 8.7-D / 8.7-D.1 / 8.7-D.1-CORRECTION / 8.7-D.1-CORRECTION-2 / 8.7-D.1-CORRECTION-3)

This document describes the **current** trust model of the platform after the
Phase 8.7-C security integrity corrections, the Phase 8.7-D.1 production
security & runtime hardening, the Phase 8.7-D.1-CORRECTION fixes
(idempotent Redis budget finalize, production shared-state requirements,
single-probe half-open circuit recovery, and the verified real-Redis test
suite), and the Phase 8.7-D.1-CORRECTION-3 corrections (single-probe
provider-attempt budget, non-finite config rejection, hard input bounds at
the generation choke point, retry-chain cost reconciliation, one
hash-pinned compatible dependency set, and the Android redirect /
origin-trust contract — §6.9). It is normative for the gateway, monitoring,
agent-service, and Android client. Historical phase reports may describe
earlier states; where they disagree, this document and the code are
authoritative.

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
* **The bearer JWT never travels over cleartext (Phase 8.7-D.1).** Before a
  request is constructed, `validateAnalysisUrl` enforces the transport policy:
  `https://` is the only permitted scheme for live URLs; `http://` is allowed
  ONLY for the local-emulator loopback hosts (`10.0.2.2`, `localhost`,
  `127.0.0.1`) AND only in debug builds (explicit `BuildConfig.DEBUG` gating,
  injectable for tests — a production build rejects the local exception).
  Unsafe or malformed URLs are rejected **before** the request is built, with
  a typed `AnalysisOutcome.Failure`; the policy runs before the
  `Authorization: Bearer` header is attached, so a rejected URL sends
  nothing. The Network Security Configuration is updated to match: the main
  config permits **no** cleartext, and the debug overlay permits cleartext
  only for those local hosts. `testConnection` remains diagnostics-only.
* **No silent fabrication on the client.** If the backend is unavailable,
  the live path is not configured, or the server reports failure, the app
  records a **typed, truthful failure** (`LIVE_FAILED` with the reason) — it
  never falls back to a fake "successful Gemini" result, and the analysis
  screen displays an explicit source badge distinguishing `OFFLINE_SIM`
  (local simulation) from `LIVE_BACKEND` (server-side provider result).
* **No backend-detail leakage in user-facing errors (Phase
  8.7-D.1-CORRECTION).** Failure reasons shown to the user are stable,
  pre-authored strings ("Unable to reach the analysis gateway." for
  transport failures; "Gateway URL is malformed." for URL-policy
  rejections). The raw exception message — which can embed the gateway
  URL, host, port, socket, or DNS details — is never surfaced in the UI or
  logs; at most the exception's class name is logged. A regression test in
  `AnalysisUrlPolicyTest` asserts that no exception-derived text reaches
  the user-facing failure string, and the UI renders unknown states as the
  safe offline/non-success color, never as live/success.
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
  gradle/env/SharedPreferences defaults), no `AIza…` key literals, and (A8,
  Phase 8.7-D.1) the analysis transport policy is intact: the URL policy is
  invoked before the Authorization header is attached, the policy keeps
  https-only with the debug-local exception, the main Network Security
  Configuration permits no cleartext, the manifest wires the NSC, and the
  debug overlay is restricted to local hosts. Since Phase
  8.7-D.1-CORRECTION-3 (Finding F) the guard also enforces the redirect +
  trust policy: the JWT-bearing client must set `followRedirects(false)`
  and `followSslRedirects(false)`, no 3xx-follow or `Location` reading may
  exist on the authenticated path, the URL policy must reject userinfo /
  query / fragment, the trust gate (`TrustedGatewayOrigin.isApproved`)
  must guard the bearer request, and the ViewModel must require the origin
  trust for live analysis without persisting the JWT.
* `gemini-resilience-contract` (Phase 8.7-D.1-CORRECTION-3) — the Gemini
  caller resilience contract in `agent-service/infrastructure/llm/
  gemini_caller.py`: the half-open probe gets an explicit
  `allowed_attempts = 1 if probing else self.max_retries` passed to an
  attempt loop that iterates `allowed_attempts` (never re-inferring
  `self.max_retries`); NaN/±inf are rejected for every float field in
  `GeminiRuntimeConfig.__post_init__`, the `from_env` float parser, and
  the shared ledger validation used by both ledgers; every input path is
  bound at the single `_generate_text` choke point before reservation /
  provider contact with the configured estimate acting as a FLOOR only;
  the reservation finalizes from the explicit per-attempt billing evidence
  (known usage + worst-case allowance per unknown attempt, capped at the
  reservation).
* `dependency-parity-contract` (Phase 8.7-D.1-CORRECTION-3, Finding E) —
  ONE compatible, hash-pinned dependency set: the container
  (`requirements-runtime.txt`) and every CI test job
  (`requirements-test.txt`) must share identical pinned versions for every
  shared package, both locks must be `pip-compile --generate-hashes`
  generated with per-package sha256 hashes, both service Dockerfiles must
  install the runtime lock with `pip install --require-hashes`, all five
  CI Python install paths must use `--require-hashes`, and the retired
  broad `requirements.txt` must not reappear.
* `jwt-fail-closed` — no bundled `JWT_SECRET` fallback, no hard-coded signing
  secret, legacy secret quarantined, development fallback gated behind the
  explicit switch.
* `d1-runtime-contract` (Phase 8.7-D.1; extended by 8.7-D.1-CORRECTION-2) —
  the canonical compose stack declares gateway + agent + redis with
  existing Dockerfiles, digest-pinned third-party images, no host-exposed
  ports except gateway 8000, CI builds both service images, the
  quarantined legacy stack carries no hardcoded database password, and
  (P1-C) the `redis-integration` CI job's live-store steps are FAIL-CLOSED:
  every step that executes the real-Redis suite must set both `REDIS_URL`
  and `REDIS_INTEGRATION_REQUIRED=true`, so a missing store is a hard test
  failure, never a silent skip that turns the mandatory gate green with
  zero Redis tests executed (removal is detected by mutation M24).

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
guards, the Gemini analysis lifecycle (shared handler across requests,
circuit persistence with fail-fast until cooldown, budget reservation and
reconciliation, structured-output contract, fail-closed missing key), the
analysis rate limiter (burst, cross-identity isolation, IP backstop,
spoofed-header immunity, window expiry, concurrency, fail-closed store
failure), and adversarial mutations M1–M18.

CI additionally runs the Android unit tests and debug build with a real
Gradle toolchain (`android-unit-tests` job), the real-Redis integration
tests for the shared budget ledger and rate limiter (`redis-integration`
job), and the canonical compose config/build/boot smoke (`compose-runtime`
job).

---

## 6. Analysis runtime hardening (Phase 8.7-D.1)

### 6.1 Single shared analysis handler per process (P0-1)

The agent-service builds **exactly one** `AnalyzeRepositoryCommandHandler`
per application instance, in `create_app`, and stores it on
`app.state.analysis_handler`. The internal route resolves that shared
instance (never a per-request construction), so the single
`GeminiCallerAdapter` — its circuit breaker, budget ledger, and retry state —
persists for the life of the process. `GeminiRuntimeConfig` is the **single
configuration source**: every tunable (model, budget, costs, retries,
timeout, budget store) has exactly one env var and exactly one default, so
two places can no longer disagree (the 150 vs 100 budget defect).

### 6.2 Atomic budget reservation (P0-2; math updated in 8.7-D.1-CORRECTION-3)

Before any provider contact, the adapter **atomically reserves the
conservative worst-case cost** of the call —
**(worst-case per-attempt cost) × (allowed attempts)**, where the
per-attempt cost = (per-request input allowance × input price +
`maxOutputTokens` × output price) and the allowed attempt count is the
**explicit** value computed once per call: **1 for a half-open probe**,
`max_retries` for a closed-circuit call (Finding A; the probe may not
retry). The per-request input allowance is the documented UTF-8 byte bound
+ framing, with `GEMINI_ESTIMATED_PROMPT_TOKENS` as a **floor only**
(Finding C; §6.9.3). If the reservation would exceed the
**application-level monthly (UTC calendar-month) ceiling**, the call is
rejected with a typed `BudgetExceededException` **before** the provider is
contacted.

After the call, the reservation is reconciled from the **whole retry
chain** (Finding D; §6.9.4): known usage → real cost; every attempt with
unknown/missing usage (timeout, 5xx, absent metadata) → the worst-case
per-attempt allowance (never free); total failure → the full reservation;
the committed amount for a reservation never exceeds what it held. This is
an **application-level safety budget, NOT a Google billing cap** — the
allowance is a conservative estimate, not a billing guarantee.

**Finalize is exactly-once per reservation while the finalization claim is
retained.** The ledger's finalize step returns a boolean: the accounting
is applied at most once per `reservation_id` for as long as its claim is
retained. On the shared store this is enforced atomically *inside the
Redis script* — a period-scoped claim key
(`devops:gemini:budget:{period}:finalized:{reservation_id}`) is checked
and set in the same atomic operation as the reservation release, so
duplicate finalization calls (client retries, crash/restart redelivery,
concurrent duplicate handling) **cannot double-subtract the reserved pool
or double-count committed spend**, and the guarantee holds across
replicas. **Retention window (Phase 8.7-D.1-CORRECTION-2, stated
explicitly):** the claim key carries a **45-day TTL** — longer than one
UTC calendar billing period — so the claim outlives every period it can
belong to, and any duplicate finalization within the billing window is
guaranteed to be rejected. After the claim expires (≥ 45 days after
finalization), a redelivered finalize can at most re-create counters of
the ALREADY-EXPIRED period (whose keys are also gone or irrelevant) — it
can never affect the current period's budget, because the claim key is
scoped to the reservation's original period. The release itself uses
`INCRBYFLOAT reserved -amount` (Redis has no `DECRBYFLOAT`; the script was
verified against a real Redis 7.2.5 server). The in-process ledger
enforces the same once-per-reservation contract with a lock-protected set
retained for the process lifetime.

* `GEMINI_BUDGET_STORE=local` (default): lock-protected in-process ledger —
  an **explicit single-process deployment contract**; the ceiling is per
  process and N replicas multiply it by N. **Refused at startup when
  `APP_ENV` is `staging` or `production`** (see the shared-state contract
  below); allowed for `dev`/local development.
* `GEMINI_BUDGET_STORE=redis` (+ `REDIS_URL`): shared ledger (atomic Lua
  scripts, period-scoped keys, 45-day TTL) — one ceiling across replicas.
  An unreachable store **fails closed** (503) — the call is blocked rather
  than run unlimited.

**This budget is an application safety budget, NOT a Google billing cap.**
It bounds how much *this application* may spend per month against its
ceiling; it does not limit what Google bills for the underlying API key.
Google-side spend controls (billing budget alerts, key-level restrictions,
IAM) are a separate operator responsibility on the provider account and are
not enforced by this platform.

**Production shared-state contract (Phase 8.7-D.1-CORRECTION; environment
classification extended by Phase 8.7-D.1-CORRECTION-2, P1-B).** The
in-process (single-instance) stores may only be used in the **explicitly
recognized development environments `development` and `test`**. Every
other `APP_ENV` value — `staging`, `production`, an **empty** string, a
**missing** variable, or any **unexpected** value — is treated as
**NON-DEVELOPMENT**, and the process **refuses to start** (fail-closed
configuration error) unless the shared Redis store backs **both** the
budget ledger (`GEMINI_BUDGET_STORE=redis` + `REDIS_URL`) and the
analysis rate limiter (see 6.4). An environment that cannot be positively
identified as a development environment must never silently fall back to
single-instance state — an unset `APP_ENV` is therefore NOT a safe local
default; it is a configuration error. The only documented exception is an
explicit single-replica mode, enabled only by setting the exact value
`true` (case-sensitive; surrounding whitespace is stripped) of
`GEMINI_BUDGET_SINGLE_INSTANCE_PRODUCTION` and/or
`ANALYSIS_RATE_LIMIT_SINGLE_INSTANCE_PRODUCTION` — the flag cannot be
tripped accidentally (`True`, `TRUE`, `yes`, `1`, … are all rejected).
`development`/`test` deployments keep the in-process stores. The canonical
compose stack runs the agent with `APP_ENV=production` and both stores on
shared Redis, satisfying the contract by construction. The classification
is enforced in BOTH `GeminiRuntimeConfig.from_env` (agent budget ledger)
and `load_analysis_rate_limit_settings` (gateway rate limiter), with the
full environment matrix (development / test / staging / production /
empty / missing / unexpected, each ± Redis) covered by
`TestAppEnvClassificationMatrix` in `tests/test_analysis_rate_limiting.py`.

### 6.3 Current, bounded provider contract (P0-6)

The default model is **`gemini-3.8-flash`** (stable; verified 2026-10-08
against the official Gemini API deprecations, model, and pricing pages —
`gemini-3.5-flash` is no longer the configured model). The provider request
is a bounded structured-output call: `application/json` response MIME type,
the five-field response schema, and an explicit `maxOutputTokens` ceiling.
Cost defaults use the **post-promotion** pricing from the official pricing
page fetched 2026-10-08 (input $1.50 / 1M, output $7.50 / 1M — conservative
relative to the 2026 promotional rates); the source and date are recorded in
`gemini_caller.py` and are operator-configurable. All LLM paths parse and
validate the five-field contract strictly; there is no lenient alternate
parse. Bounded timeout/retry with typed error mapping is preserved.

### 6.4 Route-specific rate limiting on the analysis route (P0-3)

`POST /api/v1/repository/analyze` is rate limited **before any provider
call**:

| Setting | Env var | Default |
| ------- | ------- | ------- |
| Per-JWT-sub limit | `ANALYSIS_RATE_LIMIT_PER_IDENTITY_PER_MINUTE` | 30/min |
| Per-source-IP backstop | `ANALYSIS_RATE_LIMIT_PER_IP_PER_MINUTE` | 120/min |
| Window (fixed) | `ANALYSIS_RATE_LIMIT_WINDOW_SECONDS` | 60 s |
| Store | `ANALYSIS_RATE_LIMIT_STORE` | `redis` when `REDIS_URL` set, else explicit `local` |

* Primary key: the authenticated JWT `sub`; second dimension: the **direct
  TCP peer** (`request.client.host`) — forwarded headers are never read.
* Counters are atomic (Redis Lua script; in-process lock otherwise).
* Limited requests get **429 + `Retry-After`** (window's remaining seconds).
* Authentication precedes limiting: unauthenticated bursts consume no quota.
* Fail closed: a missing limiter or an unreachable/misconfigured shared
  store blocks the route with **503** — protection is never silently
  disabled for this expensive route.

### 6.5 Canonical D1 compose stack (P0-5)

`devops-ai-platform/docker-compose.yml` is the **canonical** D1 runtime:
`api-gateway` (host 8000, JWT-authenticated control plane) + `agent-service`
(8020, **never host-exposed**, reached only through the gateway) + `redis`
(never host-exposed; shared rate-limit and budget state). Base/third-party
images are pinned to immutable digests (recorded in the compose header,
resolved 2026-10-08). `JWT_SECRET` and `AGENT_INTERNAL_TOKEN` are required
(fail closed via `${VAR:?}`); the agent runs with `APP_ENV=production`, so
the production shared-state contract (6.2) is active in the canonical stack
and satisfied by the shared Redis service. `GEMINI_API_KEY` is optional and
its absence makes the agent fail closed (503) — the CI boot smoke verifies
exactly that (with a correctly role-authorized token, so the 503 is proven
to come from the missing key, not from authorization).
The older broad stack is **quarantined** in `docker-compose.legacy.yml`
(do not use for the D1 path) with its hardcoded database password removed.
CI builds both service images, boots the stack, and checks readiness,
gateway→agent connectivity over the compose network, and the agent port's
non-exposure on the host.

### 6.6 Truthfulness corrections (P1)

* `github_pr_client.create_pull_request` **raises** when credentials are
  missing (no fabricated PR URL) and when the API omits `html_url`.
* `mark_pr_ready_for_review` performs the correct GitHub operation
  (`PUT /repos/{slug}/pulls/{number}` with `draft: false`) and **raises** on
  missing credentials or non-success — it never reports success for a no-op.
* The hotfix `apply_verification_pass` placeholder was renamed
  `record_claimed_verification`: it records that a verification pass was
  *claimed* without running any check, and **leaves the proposal
  unverified**; the apply-automated-fix flow no longer attaches it as a
  verified patch (real verification requires actually executing the checks).
* The git SSH client no longer ships `StrictHostKeyChecking=no` +
  `UserKnownHostsFile=/dev/null`: clones verify host keys against an
  operator-managed `known_hosts` file (`DEVOPS_SSH_KNOWN_HOSTS_PATH`) and are
  **refused** when it is not configured (no trust-on-first-use).
* Dataclass timestamp defaults use `default_factory` (no import-time
  frozen timestamps).

### 6.7 Guard + mutation coverage for the D.1 controls

The `d1-runtime-contract` structural guard enforces 6.5 (canonical services
declared, existing Dockerfiles, digest-pinned redis, no unneeded host ports,
CI builds both images, legacy password removed). Adversarial mutations prove
each D.1 control turns red when weakened: **M13** per-request adapter
construction (shared circuit/budget state lost), **M14** analysis rate
limiting removed, **M15** cleartext bearer transport re-enabled, **M16**
non-atomic budget check-then-act (concurrent double-spend), **M17** agent
build removed from the canonical runtime, **M18** deprecated model / removed
output bound, **M19** exactly-once finalize claim removed from the Redis
finalize script (structural guard in the security job; behavioral proof —
the weakened script double-counts a duplicate finalization — runs in the
real-Redis integration job), **M20** non-development shared-state
requirement bypassed (staging/production/empty/missing/unexpected
`APP_ENV` + in-process stores silently allowed), **M21** half-open
single-probe lease removed (multiple concurrent probes), **M22** pre-
provider probe-lease settlement bypassed (circuit wedges `HALF-OPEN`
forever), **M23** empty/missing `APP_ENV` admitted to single-instance
local state in either the gateway or the agent classification, **M24**
`REDIS_INTEGRATION_REQUIRED=true` removed from the CI redis-integration
job (the mandatory real-Redis gate degrades into silent skips — detected
structurally by the `d1-runtime-contract` guard AND behaviorally by the
fixture's fail-closed resolution).

### 6.8 Single half-open probe lease (circuit recovery, Phase 8.7-D.1-CORRECTION; lease settlement hardened in Phase 8.7-D.1-CORRECTION-2)

The provider circuit breaker uses three states — `CLOSED`, `OPEN`,
`HALF-OPEN` — under a single state lock, so the recovery transition is
atomic. When `OPEN` and the cooldown has elapsed, **exactly one** in-flight
caller performs the `OPEN → HALF-OPEN` transition and is the sole probe;
the `HALF-OPEN` state itself *is* the probe lease — any other concurrent
caller that observes it is rejected immediately (503, no provider contact)
instead of becoming a second probe. If the probe fails, the circuit re-opens
to `OPEN` immediately (failure counter reset to 1, full cooldown runs
again); if it succeeds, the breaker returns to `CLOSED` (failure counter
reset). The barrier test proves the property: N concurrent callers released
after the cooldown produce exactly **one** provider call and N−1 fast
failures, and a recovering probe closes the circuit. Removal is proven
adversarial by M21 (the weakened breaker lets all N racers probe).

**Probe-lease settlement contract (Phase 8.7-D.1-CORRECTION-2, P1-A).**
The lease is settled through exactly **one exception-safe finalization
path** in `_generate_text`: the entire post-admission section (precondition
checks, budget reservation, provider contact) is wrapped in a single
`try/except` that settles the lease on ANY failure — there is no
per-branch remember-to-settle discipline that an exception could bypass.
The outcomes:

* provider **success** → `CLOSED` (`_register_success`);
* provider **failure** → `OPEN` with a fresh cooldown (`_register_failure`);
* **pre-provider** failure — missing `GEMINI_API_KEY`, budget store
  unavailable, budget ceiling exceeded → `OPEN` with a **fresh cooldown**
  (`_settle_failed_probe`). Deliberately **not** `CLOSED`: an
  unconfigured or budget-exhausted deployment must not stream unlimited
  doomed probes; and never an unsettled `HALF-OPEN`, which would wedge
  every future call into a permanent fast-fail with no probe ever
  permitted again.

Settlement is idempotent: `_settle_failed_probe` is a no-op when the probe
was already settled by `_register_success`/`_register_failure` (both
transitions run under the same state lock), so the lease settles exactly
once. Coverage: A1 (missing key), A2 (budget store down), A3 (budget
ceiling), A4 (provider failure → OPEN), A5 (recovery → CLOSED), A6
(20-concurrent pre-provider failure leaves no permanent `HALF-OPEN`) — in
`tests/test_gemini_analysis_path.py`. The bypass is proven adversarial by
**M22** (with the settlement call removed, a pre-provider failure wedges
the circuit `HALF-OPEN`: ten fresh cooldowns pass, the credential is
restored and the provider is healthy, and the circuit still never probes
again).

### 6.9 Phase 8.7-D.1-CORRECTION-3 (Findings A–F)

The independent audit of `7b8e050` found six concrete weaknesses. All six
are corrected below; each has regression tests, a permanent structural
guard, and an adversarial mutation (M25–M30) that proves CI turns red when
the control is removed or weakened.

#### 6.9.1 Finding A — the half-open probe makes EXACTLY ONE provider attempt

Before: the attempt loop iterated `range(1, self.max_retries + 1)` and
consulted mutable state per iteration, so a half-open probe (whose only
purpose is to test the provider) inherited the full retry budget — a
flapping upstream got a retry storm during circuit recovery, and the
"single probe" contract was not actually single.

Now, in `_generate_text`:

* the allowed attempt count is computed **once** per call —
  `allowed_attempts = 1 if probing else self.max_retries` — and passed
  **explicitly** into `_generate_text_with_reservation(prompt, system,
  reservation, allowed_attempts, input_tokens)`. The loop iterates
  `range(1, allowed_attempts + 1)` and its final-attempt checks key off
  `allowed_attempts`; it never re-infers `self.max_retries` or reads the
  breaker state per iteration;
* a probe that fails (timeout, connection error, 429, 5xx, malformed)
  makes exactly **one** transport call, re-opens the circuit to `OPEN`
  with a **fresh cooldown** (failure counter reset to 1), and the second
  caller is rejected until the next cooldown;
* a healthy one-attempt probe closes the circuit; a pre-provider failure
  (missing key, budget store down, ceiling) settles the lease exactly as
  in CORRECTION-2 (zero provider calls, no permanent `HALF-OPEN`);
* CLOSED-circuit calls keep their configured bounded retry budget
  unchanged (transient failure then success = two attempts).

The reservation is sized from the same explicit count (see 6.9.3/6.9.4).
Mutation **M25** (loop re-infers `self.max_retries` — the probe makes 3
transport calls instead of 1) is detected by the
`gemini-resilience-contract` guard.

#### 6.9.2 Finding B — non-finite floats are rejected on every construction path

Before: `from_env` parsed `float(raw)` and checked only `< 0` — `float("inf")`
passed (and `committed + reserved + amount > inf` is `False` for every
finite amount, silently **disabling the ceiling**), and `float("nan")`
passed both because `nan < 0` is `False` and because NaN comparisons
defeat every accounting check. Direct `GeminiRuntimeConfig(...)`
construction had no validation at all.

Now:

* `GeminiRuntimeConfig.__post_init__` runs for **both** `from_env`
  (which constructs `cls(...)`) and direct construction: every float field
  (`monthly_budget_usd`, `input_cost_per_million`,
  `output_cost_per_million`, `timeout_seconds`,
  `backoff_base_seconds`) must be `math.isfinite`;
* the `from_env` float parser rejects non-finite values with the same
  message before the dataclass is built;
* both ledger constructors validate their accounting parameters at
  construction through the shared `_require_finite_non_negative` helper
  (defense in depth below the config — even a directly-built ledger fails
  closed identically on local and Redis stores).

Documented range semantics (all fail closed, no permissive fallback):

| field | legal range | meaning at the edge |
|---|---|---|
| `monthly_budget_usd` | finite, ≥ 0 | **0 = "no calls this period"** — every reservation is rejected immediately; it never means "unlimited" |
| `input_cost_per_million` / `output_cost_per_million` | finite, **> 0** | a zero rate would silently disable cost accounting while calls still happen |
| `timeout_seconds` | finite, > 0 | a provider call needs a positive timeout |
| `backoff_base_seconds` | finite, ≥ 0 | 0 = no wait between attempts (test use, documented) |
| `max_output_tokens` / `estimated_prompt_tokens` / `max_retries` | int ≥ 1 | — |

Invalid configuration is rejected at construction — **before any provider
contact**. Mutation **M26** (finiteness removal in all three layers: an
`inf` budget is accepted and any reservation passes the now-disabled
ceiling check) is detected by the `gemini-resilience-contract` guard.

#### 6.9.3 Finding C — hard input bounds at the single generation choke point

Before: `generate_remediation`/`generate_iac_blueprint`/`_generate_text`
accepted unbounded input (the agent-task path takes an unbounded
`cmd.raw_prompt`; the IaC path stringified arbitrary metadata with no
bound), while the reservation used only the configured
`GEMINI_ESTIMATED_PROMPT_TOKENS` (default 220) — an operator could set it
to 1 and reserve ~zero for a multibyte prompt, so concurrent callers could
drive committed spend past the ceiling the estimate was supposed to bound.

Now (call-surface audit: the only production caller is
`analyze_repository.py:60` with gateway-validated fields — name ≤ 120, URL
≤ 2048, framework ≤ 200, technology ≤ 200 — plus a fixed template; the
agent-task path is wired only through unwired AMQP scaffolding;
`generate_iac_blueprint` has zero production callers, but is bounded too):

* **`_generate_text` is the single choke point.** Every path through it
  first calls `_validate_input_bounds(prompt, system_instruction)`:
  `prompt ≤ MAX_PROMPT_CHARS (16 000)` and
  `system_instruction ≤ MAX_SYSTEM_INSTRUCTION_CHARS (4 000)`. Oversized
  input raises `GeminiInputBoundException` **before** circuit state is
  read, **before** any reservation, and **before** any provider contact —
  budget state stays untouched.
* **Per-request input allowance.** The reservation uses
  `_estimated_input_tokens(prompt, system_instruction)` =
  `len((prompt + system).encode("utf-8")) + 64` framing overhead.
  Justified bound: the Gemini tokenizer is BPE over UTF-8 bytes and every
  token encodes ≥ 1 input byte, so the byte count is an **upper bound** on
  input tokens. This is a **reservation allowance, NOT a provider billing
  guarantee** (see §7).
* **`GEMINI_ESTIMATED_PROMPT_TOKENS` is a FLOOR only.** The effective
  allowance is `max(per-request byte bound, configured estimate)` — an
  operator can never lower the per-request safe bound by setting it small
  (the setting is retained for compatibility, not removed, so all existing
  references stay valid).
* **`generate_iac_blueprint` metadata** is bounded before serialization:
  accepted value types are exactly the scalars `str` / `int` / finite
  `float` / `bool` (no implicit `str()` of arbitrary objects), keys ≤ 128
  chars, and the sorted JSON serialization must fit
  `MAX_TECH_METADATA_SERIALIZED_CHARS (8 000)` — the resulting prompt is
  then inside `MAX_PROMPT_CHARS` by construction and re-validated at the
  choke point.
* `countTokens` is **not** used: the documented byte bound + framing
  already over-estimates, and a fail-closed countTokens round-trip would
  add an unbounded provider dependency for no safety gain.

Mutation **M27** (bound check removed — an oversized prompt reaches the
provider; estimate floor dropped — a tiny estimate under-reserves
multibyte input by an order of magnitude) is detected by the
`gemini-resilience-contract` guard.

#### 6.9.4 Finding D — retry-chain cost reconciliation (no undercount)

Before: the reservation was finalized with **only the final attempt's**
`usageMetadata` cost — every preceding timeout/5xx attempt was silently
**free**, so the committed spend under-counted real provider work
(a timed-out request can still consume billable upstream work), letting
concurrent callers push committed spend past the ceiling.

Now the attempt loop keeps an **explicit per-attempt billing-evidence
list** (`attempts: List[Optional[float]]`, no hidden globals): every
failed attempt appends `None` (unknown cost), a successful attempt appends
its actual cost from `_cost_from_usage`. On success the reservation
finalizes with

```
committed = sum(known usage) + (unknown attempts) × worst-case per-attempt
committed = min(committed, reservation)
```

— i.e. known usage where reliable, and a conservative **worst-case
allowance for every attempt whose cost is unknown** (timeouts, 5xx,
missing metadata — never free). Total failure keeps the **full
reservation** (the previous fallback). Invariant: a reservation never
commits more than it held, and committed ≥ known billable + allowances.

`_cost_from_usage` now inspects the official `usageMetadata` beyond
prompt/candidates: `cachedContentTokenCount` (billed at the **full** input
rate — conservative, real cache reads price lower),
`thoughtsTokenCount`/`thoughtSummariesTokenCount` (output rate), and a
`totalTokenCount`-only fallback billed at the **higher** configured rate.

Regression coverage: (a) success with usage → actual cost committed;
(b) timeout→success; (c) 503→success (both commit worst-case + actual);
(d) 200 with **missing** metadata → worst-case allowance; (e) total
failure → full reservation; (f) cached/thoughts dimensions aggregated;
(g) duplicate finalize remains exactly-once on local **and** real Redis
(existing integration tests). Mutation **M28** (finalization reverts to
the final attempt's usage only — the timeout is silently free) is detected
by the `gemini-resilience-contract` guard.

#### 6.9.5 Finding E — one compatible, hash-pinned dependency set

Before: CI installed `requirements-test.txt` (pinned fastapi 0.128.8 /
starlette 0.52.1 / anyio 4.12.1 for the test-client stack) while the
containers installed broad `>=` ranges from `requirements.txt` — live CI
proved the container resolved fastapi **0.143.0** / starlette **1.7.0** /
anyio **4.15.1**: security was tested on one dependency set and shipped on
another.

Now:

* **`requirements-runtime.in` / `requirements-test.in`** are the declared
  sources; the **full transitive locks** `requirements-runtime.txt` /
  `requirements-test.txt` are generated with `pip-compile
  --generate-hashes` on Python 3.11 (documented update procedure in the
  `.in` headers — no ad-hoc `pip freeze`).
* The deliberately chosen set is the **last verified generation**:
  fastapi 0.128.8 / starlette 0.52.1 (starlette 1.x deprecates the
  httpx-based TestClient the security suite is built on) and anyio 4.12.1
  (4.15+ deprecates the `BlockingPortal` alias starlette 0.52's
  testclient imports), with pydantic 2.14.1 / redis 8.1.0 / requests
  2.34.2 / PyJWT 2.15.1 shared exactly. The **container is deliberately
  held on the verified generation** — one compatible set, not two drifting
  worlds; the container never runs an untested framework version.
* **Every runtime dependency is kept** (13 direct deps; no silent
  slimming); the lock resolves the full closure with sha256 hashes.
* Both service **Dockerfiles** install ONLY `requirements-runtime.txt`
  with `pip install --no-cache-dir --require-hashes` (a missing hash or a
  drifted pin is a hard build failure).
* **All five CI Python jobs** install ONLY `requirements-test.txt` with
  `pip install --require-hashes` (cache-dependency-path stays
  `requirements-test.txt`); the retired broad `requirements.txt` is
  deleted.
* The **`dependency-parity-contract` guard** fails CI on any version
  disagreement between the two locks for the shared packages, a
  non-pip-compiled/unhashed lock, a missing direct dependency, a
  Dockerfile without `--require-hashes`, or a CI install without
  `--require-hashes`.

Verification (local, pre-push): a **fresh** clean venv installs
`requirements-runtime.txt` with `--require-hashes` (all 13 direct deps
import; `pip check` clean) and a **second fresh** venv installs
`requirements-test.txt` with `--require-hashes` (full security suite +
real Redis + all guards green). The CI `compose-runtime` job builds both
images from the exact locks and boots them. Mutation **M29** (runtime
lock re-pinned to starlette 1.7.0 ≠ test lock; Dockerfile drops
`--require-hashes`) is detected by the `dependency-parity-contract`
guard.

#### 6.9.6 Finding F — Android: no redirect-following, no unconfirmed-origin token transfer

Before: the single shared `OkHttpClient` used OkHttp's **default**
`followRedirects(true)`, so a 3xx on the JWT-bearing analysis call would
have moved the bearer token to whatever `Location` header the gateway
sent (host/scheme/port/endpoint). `validateAnalysisUrl` also accepted
`user:pass@host`, query strings, and fragments, making the "exact URL
used" ambiguous. There was no operator confirmation of the exact
destination.

Now, in `app/src/main/java/com/example/data/BackendGatewayClient.kt`
(+ `DevOpsViewModel` / `MainActivity`):

* **Dedicated authenticated client.** The JWT-bearing call runs on
  `authenticatedHttpClient` — a separate `OkHttpClient` built with
  `.followRedirects(false)` **and** `.followSslRedirects(false)` (even
  http→https "safe" redirects are off). The credential-free diagnostics
  client (`testConnection`) is a separate instance whose default behavior
  can never carry a token.
* **3xx = safe explicit failure.** The authenticated path answers any
  300–399 with a typed failure ("…redirects are never followed…"); the
  `Location` header is never followed, logged, or surfaced — same-origin
  or cross-origin alike.
* **URL canonicalization before token handling.** `validateAnalysisUrl`
  additionally rejects userinfo, query strings, and fragments; the
  destination is exactly `scheme://host[:port][/base-path]` + the fixed
  analysis route (legitimate base paths preserved).
* **Explicit origin trust, bound to the normalized origin.**
  `GatewayOrigin(scheme, host, port)` (host lower-cased, effective port)
  is parsed with the pure `parseGatewayOrigin`. `TrustedGatewayOrigin`
  (in-memory only, like the JWT — never persisted; fresh process =
  untrusted) requires an explicit Settings confirmation
  ("Confirm & trust this gateway origin") **before** any
  `Authorization: Bearer` request is constructed; an untrusted origin
  yields a typed failure with **zero network calls**. Changing any part
  of the (scheme, host, port) triple invalidates the approval
  automatically (`updateApiUrl` re-checks; the UI shows the trusted
  canonical origin with a revoke control). `isLiveAnalysisEnabled`
  requires the trust, so live analysis stays OFF until confirmed.
* **Honest scope.** The confirmation protects against a wrong or
  accidental endpoint choice — it is **NOT cryptographic server
  identity**; TLS certificate validation still governs the connection
  (no permissive trust managers, no disabled checks anywhere).

Kotlin coverage (`GatewayOriginTrustTest` + extended
`AnalysisUrlPolicyTest`, offline seam, no real network): client
isolation + redirect policy, 302/307 explicit failures (Location never
surfaced), userinfo/query/fragment rejection, origin normalization and
binding, untrusted origin = zero calls, trusted origin = exactly one call
with the bearer header, approval cleared on origin change, transport
exception detail contract (now on the authenticated seam). The
`android-gemini-secret` guard enforces the structural contract. Mutation
**M30** (redirect following restored on the JWT-bearing client; trust gate
bypassed) is detected by the guard.

---

## 7. Known limitations (honest)

* The gateway's typed control-plane forwards are synchronous HTTP; in this
  codebase state they relay typed payloads to the incident service's internal
  API and surface downstream availability errors (502).
* Telemetry nonce state is process-local; a horizontally scaled deployment
  must share the nonce store (e.g. Redis) to keep replay protection global.
* The Android unit tests (including `GeminiClientSecretPolicyTest.kt` and
  the Phase 8.7-D.1 `AnalysisUrlPolicyTest.kt`) run under a real Gradle
  toolchain in the `android-unit-tests` CI job (JDK 21, AGP 9.1.1,
  Gradle 9.3.1 — the job verifies the pinned executable by absolute path,
  `/opt/gradle/gradle-9.3.1/bin/gradle`, for the version check, the test
  run, and the `assembleDebug` build, so the log proves the exact
  toolchain that executed) and locally via
  `gradle :app:testDebugUnitTest` on machines with a JDK/Android SDK; the
  Python static guards additionally hold on any machine without a JDK.
* mTLS between producer and monitoring service is not yet deployed; the HMAC
  envelope is the current machine-authentication mechanism and assumes
  network-level segregation of `/api/internal` endpoints.
* The in-process budget ledger and in-process rate limiter are explicitly
  single-process. For `APP_ENV` of `staging`/`production`, a configuration
  that resolves either one of them to the in-process store is **refused at
  startup** (fail-closed); a multi-replica deployment MUST set
  `GEMINI_BUDGET_STORE=redis` / `ANALYSIS_RATE_LIMIT_STORE=redis` (shared
  Redis), and the only exception is the explicit, exact-value
  single-instance flags documented in 6.2. The application budget is a
  safety budget for THIS application and is not a Google billing cap (see
  6.2).
* Nothing on this branch has been exercised against the real Gemini API in a
  production deployment: no production-verification or "production-ready"
  claim is made for the provider path. The compose boot smoke runs WITHOUT
  provider credentials and verifies the truthful fail-closed behavior.


### 2.1 Server-to-server analysis boundary

The public gateway JWT authenticates the end user; it is not reused as the agent-service network credential. The gateway sends the authenticated identity for audit purposes plus `X-Agent-Internal-Token` to the fixed agent-service analysis endpoint. The agent compares that shared secret constant-time and rejects missing/invalid credentials before any LLM call.
