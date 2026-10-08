# DevOps.AI - Autonomous Multi-Agent DevOps Engineer Clients

DevOps.AI is a high-fidelity, enterprise-grade Android client application built as an intelligent Virtual DevOps Engineer workstation. Crafted with Kotlin, Jetpack Compose, and modern Material 3 design systems, the platform orchestrates autonomous multi-agents to analyze code repositories, model Infrastructure-as-Code (IaC), deploy applications, observe metrics, and apply hotfixes autonomously.

---

## 🎨 System Highlights & Features

### 1. Repository Analyzer & Pipeline Workflows
* **Autonomous Discovery:** Analyze any imported Git repository using the on-device, non-secret template analysis engine to discover technology stacks, frameworks, and architecture blocks. (Live server-side Gemini is a later backend integration phase — see Security Model.)
* **11-Stage Deployment Engine:** A comprehensive simulated operator workspace with real-time terminal trace logs visualizing deep tasks including:
  * Security scanning & vulnerability auditing (Bandit/npm audit)
  * Multi-stage production container compiling (Dockerfile)
  * Infrastructure configuration authoring (AWS Terraform Subnets/VPC/IAM)
  * CI/CD deployment logic generation (GitHub Actions CI/CD)
  * Pod scheduling and load boundary setup (Kubernetes Deployment/HPA)
  * Direct Prometheus monitoring scrape register

### 2. Multi-Agent Topology Architect
* **Topology Diagrams:** Dynamic vector visualizations modeling AWS Gateway, private EKS/ECS subnet structures, and scaling pod setups.
* **Syntax Blueprint Inspector:** High-contrast inspector with tab-based panels highlighting:
  * Highly optimized, non-root execute Dockerfiles
  * Clustered, limits-gated Kubernetes Deployment configurations
  * Best-practice modular Terraform setups
  * Complete secret-safe GitHub Actions CD workflow configs

### 3. Incident Investigation & Auto-Patches
* **Anomalous Log Investigator:** Track active incident rooms, including database pool saturation spikes or over-privileged AWS credential calls.
* **Root-Cause Telemetry:** Drill down into active agent investigation logs, tracing thread dumps, Sentry exceptions, and memory states.
* **One-Click Auto-Fix:** Dispatches virtual agents to generate code patches, run verification passes, and output automated Pull Requests (e.g., `PR-XXXX`) to resolve issues.

### 4. Interactive Grafana-style Observability
* **Real-time Heartbeat Canvas:** Sine-wave driven network transaction simulators tracking live load averages.
* **Interactive Metric Cards:** Dynamic status panels reflecting system nodes, latency metrics, active incident levels, and resource averages.

---

## 🛡️ Security Model (Phase 8.7-C)

The platform is built on explicit trust boundaries. The full normative
description lives in [`devops-ai-platform/SECURITY.md`](devops-ai-platform/SECURITY.md);
the essentials:

### Telemetry
* **Human authentication and telemetry provenance are separate trust
  domains.** A JWT (any role, including operator) can never impersonate a
  monitoring telemetry producer.
* Telemetry is ingested only through the monitoring service's
  **machine-authenticated** boundary
  (`POST /api/internal/telemetry/observations`, HMAC-SHA256
  `X-Telemetry-Signature` / `-Timestamp` / `-Nonce`, secret
  `TELEMETRY_HMAC_SECRET`). Rejected or unsigned telemetry produces no metric
  datapoint, no threshold event, and no incident.
* The API gateway's former generic dispatcher
  (`POST /v1/gateway/dispatch/{service_name}`) has been **removed**; the
  gateway exposes only typed control-plane operations, and none of them
  target the monitoring service.

### Android
* **The application does not treat provider API credentials as
  device-side secrets.** Android-distributed applications cannot keep a
  reusable provider secret confidential — anything compiled into the APK is
  recoverable.
* `GEMINI_API_KEY` is no longer injected into the app
  (`BuildConfig.GEMINI_API_KEY` does not exist and is prohibited). Provider
  credentials belong server-side only.
* **Repository analysis has two explicit, truthfully labeled paths**
  (Phase 8.7-D).
  The default is the non-secret offline template engine (deterministic
  local assets, no provider credential, no network round-trip). When the
  user has configured a gateway, a live analysis is sent as a typed request
  to `POST /api/v1/repository/analyze` with an
  `Authorization: Bearer <JWT>` header only; the gateway verifies the JWT
  and role (Developer / operator / DevOpsLead) and forwards it to the
  agent-service, which calls Gemini using `GEMINI_API_KEY` from its own
  server environment. The app never holds or transmits a provider key, and
  the request schema rejects any client-supplied key field.
* **Failures are typed, never fabricated.** If the backend is unavailable
  or reports failure, the app shows an explicit `LIVE_FAILED` state with the
  reason — it never falls back to a fake "successful Gemini" result. The
  analysis screen displays a source badge distinguishing `OFFLINE_SIM`
  (local simulation) from `LIVE_BACKEND` (server-side provider result).
* CI runs static guards that fail the build if a Gemini secret reappears in
  the app's code, resources, manifest, assets, gradle config, or env files,
  and if the analysis transport contract is violated (unauthenticated
  analyze call, `queryRemoteAnalysis` reintroduction, or missing
  live/offline/failed state handling).
* **Verification status (honest).** The live path is implemented and
  covered by the automated gateway / agent / Android test suites on this
  branch. It has not been exercised against the real Gemini API in a
  production deployment on this branch, and no production-verification
  claim is made.

### Gateway JWT
* **Production requires an explicit `JWT_SECRET` and fails closed when it is
  absent.** No bundled signing secret is ever substituted in
  production/staging.
* A development-only fallback exists **only** behind the unmistakable explicit
  switch `APP_ENV=development` (never inferred from how the process was
  launched). The retired predictable fallback
  `super-secret-devops-platform-signature-token` is quarantined to a
  test-reference constant and can no longer authenticate any token.

---

## 🛠️ Technology Stack & Architecture

DevOps.AI is engineered under rigorous industry standards:

* **Language:** Kotlin 100%
* **UI toolkit:** Jetpack Compose (Material Design 3, dynamic gradients, responsive viewports)
* **API Layer:** Gateway reachability diagnostics (non-secret URL probe); repository analysis runs on-device via the offline template engine by default, or via the authenticated, role-gated server-side Gemini analysis endpoint when a gateway is configured
* **Local Persistence:** Secure Room Database persistent state cache (RepoEntity, IncidentEntity, DeploymentLogEntity)
* **Thread Safety:** Structured Kotlin Coroutines & Flow streams for background calculations
* **Signings & Builds:** Gradle Kotlin DSL (`build.gradle.kts`) structured via standard custom plugins

---

## 🚀 Setting Up the Application

To build and experience DevOps.AI as a fully functional platform:

1. **No API key is required in the app — none is bundled.**
   * Repository analysis runs the app's **offline template engine** by
     default (deterministic, non-secret, on-device). No Gemini credential is
     needed in the app, the workspace, or any client `.env`.
   * Live server-side Gemini analysis is available on this branch through
     the authenticated, role-gated gateway endpoint
     (`POST /api/v1/repository/analyze` with `Authorization: Bearer <JWT>`).
     It only works when the platform's `agent-service` is deployed and its
     server environment provides `GEMINI_API_KEY`; the Android app never
     holds or sends a provider key, and a live failure is surfaced as an
     explicit `LIVE_FAILED` state — never as a fabricated success.
   * *The app's Settings screen offers a gateway reachability probe
     (diagnostics only) for a user-configured URL.*

2. **Run and Compile:**
   Using Gradle:
   ```bash
   gradle assembleDebug
   ```

3. **Deploy or Export:**
   * Export the workspace as a unified APK/AAB or push the source code directly to GitHub using your AI Studio profile integrations.

### Platform (server-side) environment

* `AGENT_INTERNAL_TOKEN` — server-only shared credential for the fixed gateway → agent-service analysis hop. It is never sent to Android and must be at least 32 characters.

The `devops-ai-platform` services follow the contract in
[`devops-ai-platform/SECURITY.md`](devops-ai-platform/SECURITY.md):

* `JWT_SECRET` — **required** for the API gateway outside explicit
  development; startup fails closed when absent.
* `APP_ENV` — explicit environment selector; only the exact value
  `development` enables the development-only JWT fallback.
* `TELEMETRY_HMAC_SECRET` — trusted telemetry producer secret; ingestion is
  disabled (fail closed) when unset.
* `GEMINI_API_KEY` — server-side only (read by the `agent-service`'s
  Gemini caller for the authenticated analysis path); never consumed by
  the Android app, which authenticates with JWTs only. The agent-service
  fails closed when the key is absent and applies timeout/retry,
  circuit-breaker, and monthly budget limits to provider calls.

### Security checks

```bash
cd devops-ai-platform
pip install -r requirements-test.txt
python -m pytest tests/ -v                 # focused security suites
PYTHONPATH=. python -m security_guards     # structural guards
```

Both are mandatory in CI (see `.github/workflows/ci.yml`).
