# 🚀 DevOps.AI - VS Code & Vercel Deployment Guide + Product Roadmap

Welcome to the **DevOps.AI Operator Platform** engineering roadmap. This document provides step-by-step blueprints on how to launch the DDD python services in **VS Code**, host them on **Vercel**, and use the **Android Client App**'s gateway diagnostics — along with a clear strategic upgrade roadmap.

---

## 🏗️ Current Branch Architecture (read this first)

> **On the current branch, Android repository analysis is offline and deterministic. The configured gateway URL is diagnostics-only and does not route repository analysis, Gemini requests, deployments, or execution through the remote server.**

Two separate, independent flows exist today:

**Flow A — Repository analysis (on-device):**

```text
Android repository registration
        ↓
offline deterministic repository analysis
        ↓
local DevOps blueprint generation
```

**Flow B — Gateway connectivity (diagnostics only):**

```text
Android gateway URL
        ↓
reachability probe
        ↓
diagnostic connectivity status
```

Enabling or pinging the gateway (Flow B) **never** switches repository analysis (Flow A)
to a remote service. The Android app contains no Gemini provider credential
(no `BuildConfig.GEMINI_API_KEY`, no embedded key), and no
Android → backend → Gemini repository-analysis path is implemented on this
branch. Server-side Gemini credentials are **server-side only** and must
never be placed in the Android APK, `BuildConfig`, Android resources,
Android preferences, or Android source literals.

---

## 🛠️ Step 1: Running the Platform on VS Code

To run and debug the entire DevOps Multi-Agent Platform locally on your computer inside VS Code, follow these instructions:

> **Scope note:** this section documents how to run the *Python backend
> infrastructure locally*. Running these services does **not** mean the
> Android client currently uses them for repository analysis — on this
> branch Android analysis is offline (see Current Branch Architecture).

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
> infrastructure*. Deploying the backend does **not** create a verified
> Android live-analysis integration: on this branch the Android app does
> not send repository analysis to the deployed URL, and no future
> integration exists yet (see the Current vs Future boundary in Step 4).

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
6.  **That is the entire effect.** The result only indicates whether the
    configured endpoint is reachable. **Repository analysis remains
    offline and deterministic on this branch** — no analysis task, Gemini
    request, deployment, or execution is routed through the gateway.

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
    Cockpit"). Real provider telemetry requires the future server-side
    Gemini integration below — the current cockpit does **not** receive
    actual Gemini provider telemetry.

### 🧭 Current vs Future: Backend Integration Boundary

**Current branch**

*   Android repository analysis is offline/deterministic.
*   No Gemini provider credential is bundled in the APK.
*   Gateway configuration is diagnostics-only (reachability probe).
*   No verified Android → backend → Gemini repository-analysis flow exists.

**Future backend integration — *future / not implemented on this branch***

A future phase may introduce:

```text
Android
  ↓
authenticated API request
  ↓
API Gateway / typed analysis endpoint
  ↓
analysis/agent service
  ↓
server-side Gemini credentials
  ↓
Gemini
  ↓
validated analysis response
  ↓
Android
```

That future flow must be explicitly implemented — a real authenticated API
contract **and** its implementation on this branch — before any
documentation, UI, or test may describe it as current behavior. Deploying
the backend infrastructure (Steps 1–2) alone does not create it.
