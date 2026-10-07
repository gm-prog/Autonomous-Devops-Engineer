# 🚀 DevOps.AI - VS Code & Vercel Deployment Guide + Product Roadmap

Welcome to the **DevOps.AI Operator Platform** engineering roadmap. This document provides step-by-step blueprints on how to launch the DDD python services in **VS Code**, host them live on **Vercel**, and connect your **Android Client App** along with a clear strategic upgrade roadmap.

> **Updated (2026-09):** the run instructions below were rewritten to match the
> actual code. The previous revision referenced `uvicorn api-gateway.main:app`
> (a file that never existed) and Prisma-style env vars
> (`POSTGRES_PRISMA_URL`, `REDIS_URL`) that no code in this repo reads
> (the stack uses SQLAlchemy, not Prisma).

---

## 🛠️ Step 1: Running the Platform on VS Code

To run and debug the entire DevOps Multi-Agent Platform locally on your computer inside VS Code, follow these instructions:

### 1. Prerequisites & VS Code Extensions
Ensure you have **Python 3.11+**, **Docker Desktop**, and **Android Studio / Command Line Tools** installed. Then install the following VS Code extensions:
*   `ms-python.python` (Python language support)
*   `ms-azuretools.vscode-docker` (Docker container visibility)
*   `vscjava.vscode-java-pack` & `fwcd.kotlin` (Optional: for inspection of Kotlin files)

### 2. Multi-Container Infrastructure Bootstrapper
DevOps.AI is offline-first but includes Postgres, Redis, and Qdrant backend requirements. 
Open your terminal in VS Code and spin up the backend dependencies:
```bash
# Root stack (used by the Android app's remote mode + observability):
docker-compose up -d

# OR the full DDD platform stack (all 7 services + infra):
cd devops-ai-platform && docker-compose up -d --build
```
This launches:
*   **PostgreSQL** (`localhost:5432`) - Stores repository settings and telemetry alerts.
*   **Redis** (`localhost:6379`) - Celery message broker for background deployments.
*   **Qdrant** (`localhost:6333`) - Vector store for Incident Root Cause Retrieval-Augmented Generation (RAG).
*   Root stack also: **Prometheus** (`:9090`, scrapes `api:8000/metrics`) and **Grafana** (`:3000`, Prometheus datasource auto-provisioned).

### 3. Setting Up the FastAPI Backend Service

#### Option A — the root "Operator Gateway" (what the Android app talks to)
```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```
Endpoints: `/health`, `/api/repositories`, `/api/v1/repository/analyze` (the
contract the Android app uses), `/metrics`. Set `GEMINI_API_KEY` in the
environment to make the analyze endpoint use live Gemini instead of the
offline template engine.

#### Option B — the DDD platform services
```bash
cd devops-ai-platform

# Create python virtual environment
python -m venv venv
# Activate:  source venv/bin/activate   (Linux/Mac)
#            venv\Scripts\activate      (Windows)
pip install -r requirements.txt
```

The platform reads these environment variables (no Prisma — it uses SQLAlchemy):
```bash
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/devops_prod"
export REDIS_HOST="localhost"
export REDIS_PORT=6379
export QDRANT_HOST="localhost"
export QDRANT_PORT=6333
export GEMINI_API_KEY="your_actual_gemini_api_key_here"   # optional
export JWT_SECRET="a-strong-random-string"                # gateway auth
export SENTRY_WEBHOOK_SECRET="another-strong-string"      # optional, incident svc
```

Run any service (from the `devops-ai-platform/` directory):
```bash
uvicorn api_gateway.main:app      --host 0.0.0.0 --port 8000   # BFF gateway (JWT-protected)
uvicorn repo_service.main:app     --host 0.0.0.0 --port 8010   # repository context
uvicorn agent_service.main:app    --host 0.0.0.0 --port 8020   # agent SSE streams
uvicorn monitoring_service.main:app --host 0.0.0.0 --port 8040 # WS telemetry
uvicorn incident_service.main:app --host 0.0.0.0 --port 8050   # incidents + Sentry webhook
celery -A deployment_service.infrastructure.celery.tasks.celery_app worker --loglevel=info
```

The gateway enforces **HS256 JWT auth** (the old "any 10+ character token"
mock is gone). Mint a development token:
```bash
python -m api_gateway.core.auth devops-operator DevOpsLead
# → eyJhbGciOiJIUzI1NiIs...
curl -H "Authorization: Bearer <token>" http://localhost:8000/v1/gateway/metrics
```

You can now open `http://localhost:8000/docs` in your browser to inspect the Swagger/OpenAPI interactive API gateway!

---

## 🌐 Step 2: Deploying Live to Vercel

FastAPI apps deploy beautifully on Vercel's serverless edge. Since the database, Redis broker, and Qdrant Vector store are persistent stateful systems, you cannot run them inside Vercel's ephemeral serverless containers directly. You should use **managed serverless database providers** and point your Vercel deployment variables to them!

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
      "src": "app/main.py",
      "use": "@vercel/python"
    }
  ],
  "routes": [
    {
      "src": "/(.*)",
      "dest": "app/main.py"
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

# Push environment variables securely to Vercel (names match the code):
vercel env add DATABASE_URL "your_production_postgres_uri"
vercel env add REDIS_HOST "your_production_upstash_redis_host"
vercel env add REDIS_PORT "6379"
vercel env add GEMINI_API_KEY "your_gemini_key"
vercel env add QDRANT_HOST "your_qdrant_cloud_host"

# Trigger a production build deployment
vercel --prod
```
Vercel will output a live url (e.g. `https://devops-ai-platform.vercel.app`). Copy this link!

---

## 📱 Step 3: Connecting Your Android App

1.  Launch the **DevOps.AI** Android App.
2.  Tap the **Settings (Gear Icon)** in the top bar.
3.  Toggle **Connect to Remote Backend** -> **On**.
4.  Configure the **Base Gateway Endpoint URL**:
    *   **Local Developer/Emulator Loopback**: If running FastAPI locally in VS Code, input `http://10.0.2.2:8000` (this maps the host's localhost inside the emulator).
    *   **Live Cloud Server**: If deployed to Vercel, input your URL (e.g., `https://devops-ai-platform.vercel.app`).
5.  Tap **Ping Endpoint**: the pill now only reports **CONNECTED** on a genuine
    `200` from the gateway's `/health` or `/api/v1/health` — a reachable but
    wrong host (404) correctly shows **OFFLINE**. When connected, **Analyze
    (AI)** routes `POST /api/v1/repository/analyze` to the server, which
    returns the full artifact set synchronously (live Gemini when the server
    has `GEMINI_API_KEY`, offline templates otherwise).

---

## 🗺️ Step 4: Product Roadmap & Future Upgrades

To take this platform to a commercial enterprise-grade product, these are the recommended upgrades:

### 1. Swarm State Machine Monitor — *implemented as UI simulation*
*   **Feature**: Integrate a real-time visualization of the collaborative agent swarm executing a deployment.
*   **UI Asset**: A network nodes card plotting the four specialized agents: **Repo-Expert**, **IaC-Builder**, **Audit-Inspector**, and **Hotfix-Validator**.
*   **Behavior**: When triggering a deployment, nodes light up or trigger pulsing animations to indicate which agent is compiling, testing, or checking permissions.
*   **Status**: Present in the Android Hub tab as a *visual simulation*. The next step is driving the node states from real deployment events (Celery task lifecycle / SSE).

### 2. Human-In-The-Loop Authorization
*   **Feature**: Prevent automated agents from deploying files or merging PRs directly without strict operator verification.
*   **UI Asset**: A Slack-style alerting feed inside the "Incident Response Page" of the Android app. 
*   **Behavior**: When a fix is compiled, the operator receives a notification. They can view a side-by-side Git Diff visualizer of the code patch and swipe right to **Authorize & Merge Draft PR** securely, or reject it with custom text input.
*   **Status**: Swipe-to-merge gate exists in the app (simulated PR). The Slack-style feed is not yet built.

### 3. API Budget and Circuit-Breaker Visualizer — *implemented as UI simulation*
*   **Feature**: Full telemetry monitor for Gemini API budgets ($ USD) and rate limits to block malicious token consumption.
*   **UI Asset**: Two curved gauge indicators for input/output token counters and estimated USD cost spent.
*   **Behavior**: If the Gemini API experiences throttling or budget issues, visual indicator warnings flash amber and display the Circuit Breaker status (*CLOSED, OPEN, HALF-OPEN*) along with dynamic diagnostic rules, mirroring the resilient patterns implemented in `gemini_caller.py`.
*   **Status**: Present in the Android Hub tab as a *visual simulation*. `gemini_caller.py` already contains a real breaker + budget guard for the platform side; the next step is surfacing its state over the gateway's `/metrics`.
