# 🚀 DevOps.AI - VS Code & Vercel Deployment Guide + Product Roadmap

Welcome to the **DevOps.AI Operator Platform** engineering roadmap. This document provides step-by-step blueprints on how to launch the DDD python services in **VS Code**, host them on **Vercel**, and use the **Android Client App**'s gateway diagnostics — along with a clear strategic upgrade roadmap.

---

## 🏗️ Current Branch Architecture (read this first)

> **On the current branch, Android repository analysis is offline and deterministic BY DEFAULT. When the operator explicitly enables live analysis (gateway URL + gateway JWT + successful reachability probe), analysis is sent as a typed, authenticated request to the gateway's `POST /api/v1/repository/analyze` endpoint (Bearer-JWT, role-gated) and the agent-service calls Gemini with its own server-side key. The gateway does not route deployments or execution; the APK never contains a Gemini provider credential.**

Two separate, independent flows exist today:

**Flow A — Repository analysis (offline by default; opt-in authenticated live):**

```text
Android repository registration
        ↓
live analysis enabled? (operator toggle + JWT + probe OK)
        ├─ no  → offline deterministic on-device template engine
        │          ↓
        │        local DevOps blueprint generation (source: OFFLINE_SIM)
        └─ yes → POST /api/v1/repository/analyze  (Authorization: Bearer <JWT>)
                   ↓  (gateway: JWT + role check → agent-service)
                 server-side Gemini call (GEMINI_API_KEY in agent-service env)
                   ↓
                 validated analysis response (source: LIVE_BACKEND)
                 failure → truthful LIVE_FAILED, never a fabricated success
```

**Flow B — Gateway connectivity (diagnostics only):**

```text
Android gateway URL
        ↓
reachability probe
        ↓
diagnostic connectivity status
```

Live analysis is an **explicit operator choice**, not a side effect of
reachability: the Settings screen keeps the diagnostics-only probe separate
from the live-analysis toggle (which additionally requires the gateway JWT).
The Android app contains no Gemini provider credential (no
`BuildConfig.GEMINI_API_KEY`, no embedded key). Server-side Gemini
credentials are **server-side only** and must never be placed in the Android
APK, `BuildConfig`, Android resources, Android preferences, or Android source
literals.

---

## 🛠️ Step 1: Running the Platform on VS Code

To run and debug the entire DevOps Multi-Agent Platform locally on your computer inside VS Code, follow these instructions:

> **Scope note:** this section documents how to run the *Python backend
> infrastructure locally*. Android analysis is offline by default; to use the
> opt-in live path against a locally run backend, the gateway, the
> agent-service (with `GEMINI_API_KEY` set in its environment), and the
> Android app must all be configured as described in Step 3 (see Current
> Branch Architecture).

### 1. Prerequisites & VS Code Extensions
Ensure you have **Python 3.11+**, **Docker Desktop**, and **Android Studio / Command Line Tools** installed. Then install the following VS Code extensions:
*   `ms-python.python` (Python language support)
*   `ms-azuretools.vscode-docker` (Docker container visibility)
*   `vscjava.vscode-java-pack` & `fwcd.kotlin` (Optional: for inspection of Kotlin files)

### 2. Multi-Container Infrastructure Bootstrapper
DevOps.AI is offline-first but includes Postgres, Redis, and Qdrant backend requirements. 
Open your terminal in VS Code and spin up the backend dependencies:
```bash
# Start your databases, caches and brokers in the background
docker-compose up -d
```
This launches:
*   **PostgreSQL** (`localhost:5432`) - Stores repository settings and telemetry alerts.
*   **Redis** (`localhost:6379`) - Celery message broker for background deployments.
*   **Qdrant** (`localhost:6333`) - Vector store for Incident Root Cause Retrieval-Augmented Generation (RAG).

### 3. Setting Up the FastAPI Backend Service
Navigate to the backend folder inside VS Code:
```bash
cd devops-ai-platform

# Create python virtual environment
python -m venv venv

# Activate virtual environment
# On Mac/Linux:
source venv/bin/activate
# On Windows:
.\venv\Scripts\activate

# Install all workspace dependencies
pip install -r requirements.txt
```

Create a `.env` file inside `devops-ai-platform/` using the template `.env.example`:
```env
POSTGRES_PRISMA_URL="postgresql://postgres:postgres@localhost:5432/devops_db"
REDIS_URL="redis://localhost:6379/0"
GEMINI_API_KEY="your_actual_gemini_api_key_here"
QDRANT_HOST="localhost"
QDRANT_PORT=6333
```

> **Credential boundary:** `GEMINI_API_KEY` is **server-side only**. It is
> read by the server-side Gemini caller in the Python platform. It must
> never be copied into the Android project — not into `BuildConfig`,
> resources, preferences, source literals, or any APK artifact. The Android
> app does not consume a Gemini key and cannot.

Next, run the main FastAPI server:
```bash
uvicorn api-gateway.main:app --host 0.0.0.0 --port 8000 --reload
```
You can now open `http://localhost:8000/docs` in your browser to inspect the Swagger/OpenAPI interactive API gateway!

---

## 🌐 Step 2: Deploying Live to Vercel

FastAPI apps deploy beautifully to Vercel's serverless edge. Since the database, Redis broker, and Qdrant Vector store are persistent stateful systems, you cannot run them inside Vercel's ephemeral serverless containers directly. You should use **managed serverless database providers** and point your Vercel deployment variables to them!

> **Scope note:** this section documents *deploying backend
> infrastructure*. The authenticated Android live-analysis integration is
> implemented on this branch; deploying the backend (with `GEMINI_API_KEY`
> set for the agent-service) and pointing the app's live-analysis
> configuration at the deployed gateway is what makes the live path
> available against that deployment. It has **not** been exercised against
> the real Gemini API in a production deployment on this branch (see the
> Current vs Future boundary in Step 4).

### 1. Provision Hosted Services
*   **Database**: Set up a serverless PostgreSQL database on **Vercel Postgres (Neon)** or **Supabase**.
*   **Message Broker**: Set up a serverless Redis cluster on **Upstash Redis** (which allows webhooks for execution).
*   **Vector Database**: Set up a free cloud instance on **Qdrant Cloud** (using their API keys).

### 2. Configure Vercel Routing (`vercel.json`)
Create a file named `vercel.json` in the root of the backend folder to manage edge request rewrites to WSGI/ASGI servers:
```json
{
  "version": 2,
  "builds": [
    {
      "src": "api-gateway/main.py",
      "use": "@vercel/python"
    }
  ],
  "routes": [
    {
      "src": "/(.*)",
      "dest": "api-gateway/main.py"
    }
  ]
}
```

### 3. Deploy via Vercel CLI
Run the following commands in the terminal inside VS Code:
```bash
# Install Vercel CLI globally if you haven't yet
npm install -g vercel

# Log in and link your project
vercel login
vercel link

# Push environment variables securely to Vercel
vercel env add POSTGRES_PRISMA_URL "your_production_postgres_uri"
vercel env add REDIS_URL "your_production_upstash_redis_uri"
vercel env add GEMINI_API_KEY "your_gemini_key"
vercel env add QDRANT_HOST "your_qdrant_cloud_host"

# Trigger a production build deployment
vercel --prod
```
Vercel will output a live url (e.g. `https://devops-ai-platform.vercel.app`). Copy this link!

> **Credential boundary:** `GEMINI_API_KEY` is a **server-side only**
> environment variable for the deployed platform. It is never delivered to,
> embedded in, or consumed by the Android application.

---

## 📱 Step 3: Android Gateway Diagnostics

The Android app's gateway configuration is a **reachability diagnostic
only**. It is not a repository-analysis transport, not a Gemini transport,
not a deployment execution bridge, and not an authenticated Android →
backend execution channel.

1.  Launch the **DevOps.AI** Android App.
2.  Tap the **Settings (Gear Icon)** in the top bar.
3.  Open the **Gateway Reachability Probe** section (toggle it on).
4.  Configure the **Base Gateway Endpoint URL**:
    *   **Local Developer/Emulator Loopback**: If running FastAPI locally in VS Code, input `http://10.0.2.2:8000` (this maps the host's localhost inside the emulator).
    *   **Deployed backend**: If you deployed the backend (Step 2), you may input that URL (e.g., `https://devops-ai-platform.vercel.app`) to test reachability.
5.  Tap **Ping Endpoint**: the status pill shows **CONNECTED** when the
    endpoint responds, or **UNREACHABLE** otherwise.
6.  **The probe is diagnostics.** The result only indicates whether the
    configured endpoint is reachable. Reaching `CONNECTED` alone does not
    switch analysis: without a gateway JWT the live path stays off and
    repository analysis remains offline and deterministic (source badge
    `OFFLINE_SIM`).
7.  **Opt-in live analysis (authenticated).** Under the same
    **Live Backend Analysis & Gateway Probe** toggle, also paste the
    platform-issued **gateway JWT** (never a Gemini key). Live analysis is
    active only when *all* of these hold: the toggle is on, the gateway URL
    is set, the JWT is non-blank, and the probe reports `CONNECTED`. While
    active, "Analyze" sends a typed request with
    `Authorization: Bearer <JWT>` to
    `POST /api/v1/repository/analyze`; the gateway verifies the JWT and the
    caller's role (Developer / operator / DevOpsLead) and forwards it to the
    agent-service, which calls Gemini with its own server-side key.
8.  **Truthful results.** A successful live analysis is badged
    `LIVE_BACKEND`. A failed live attempt is surfaced as `LIVE_FAILED` with
    the reason — the app never falls back to a fake "successful Gemini"
    result, and the on-device engine is never presented as a live result.
    Deployments and execution are never routed through the gateway.

---

## 🗺️ Step 4: Product Roadmap & Future Upgrades

To take this platform to a commercial enterprise-grade product, these are the recommended upgrades:

### 1. Swarm State Machine Monitor
*   **Feature**: Integrate a real-time visualization of the collaborative agent swarm executing a deployment.
*   **UI Asset**: A network nodes card plotting the four specialized agents: **Repo-Expert**, **IaC-Builder**, **Audit-Inspector**, and **Hotfix-Validator**.
*   **Behavior**: When triggering a deployment, nodes light up or trigger pulsing animations to indicate which agent is compiling, testing, or checking permissions.

### 2. Human-In-The-Loop Authorization
*   **Feature**: Prevent automated agents from deploying files or merging PRs directly without strict operator verification.
*   **UI Asset**: A Slack-style alerting feed inside the "Incident Response Page" of the Android app. 
*   **Behavior**: When a fix is compiled, the operator receives a notification. They can view a side-by-side Git Diff visualizer of the code patch and swipe right to **Authorize & Merge Draft PR** securely, or reject it with custom text input.

### 3. API Budget and Circuit-Breaker Visualizer
*   **Feature**: Full telemetry monitor for Gemini API budgets ($ USD) and rate limits to block malicious token consumption.
*   **UI Asset**: Two curved gauge indicators for input/output token counters and estimated USD cost spent. 
*   **Behavior**: If the Gemini API experiences throttling or budget issues, visual indicator warnings flash amber and display the Circuit Breaker status (*CLOSED, OPEN, HALF-OPEN*) along with dynamic diagnostic rules, mirroring the resilient patterns implemented in `gemini_caller.py`.
*   **Phase boundary**: the Android UI currently demonstrates these concepts
    using **local simulation** (the "AI Simulation & Resilience
    Cockpit"). The server-side Gemini integration now exists (phase
    8.7-D), but this branch does not surface provider telemetry to the app
    — the cockpit still does **not** receive actual Gemini provider
    telemetry.

### 🧭 Current vs Future: Backend Integration Boundary

**Current branch (implemented in phase 8.7-D)**

*   Android repository analysis is offline/deterministic by default.
*   No Gemini provider credential is bundled in the APK (no
    `BuildConfig.GEMINI_API_KEY`; the Settings field accepts a gateway JWT
    only).
*   The authenticated Android → gateway → agent-service → Gemini analysis
    flow is implemented: a typed `POST /api/v1/repository/analyze`
    endpoint, JWT + role gating (Developer / operator / DevOpsLead),
    strict schemas that reject client-supplied key fields, and a
    server-side Gemini caller with fail-closed secret handling, bounded
    timeout/retry, a circuit breaker, and a monthly budget ceiling.
*   The gateway probe stays diagnostics-only; live analysis additionally
    requires the explicit JWT plus a successful probe.
*   A failed live attempt is surfaced as `LIVE_FAILED` with the reason —
    the app never presents a fabricated "successful Gemini" result.

```text
Android (gateway JWT only — no provider key)
  ↓
authenticated API request (Authorization: Bearer <JWT>)
  ↓
API Gateway / typed analysis endpoint (JWT + role check)
  ↓
analysis/agent service
  ↓
server-side Gemini credentials (GEMINI_API_KEY in service env)
  ↓
Gemini
  ↓
validated analysis response (source: LIVE_BACKEND)
  ↓
Android
```

**Future / not verified on this branch**

*   A genuine end-to-end run against the real Gemini API in a production
    deployment. The flow is covered by automated gateway / agent / Android
    test suites on this branch; no production-verification claim is made.
*   Real provider telemetry surfaced in the Android resilience cockpit
    (the cockpit remains a local simulation — see the phase boundary in
    the "API Budget and Circuit-Breaker Visualizer" item).
*   Deploying the backend infrastructure (Steps 1–2) alone does not make
    the live path available: without `GEMINI_API_KEY` in the agent-service
    environment, the service fails closed (HTTP 503) instead of
    fabricating a response.
the backend infrastructure (Steps 1–2) alone does not create it.
