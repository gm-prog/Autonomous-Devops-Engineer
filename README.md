# DevOps.AI - Autonomous Multi-Agent DevOps Engineer Clients

DevOps.AI is a high-fidelity, enterprise-grade Android client application built as an intelligent Virtual DevOps Engineer workstation. Crafted with Kotlin, Jetpack Compose, and modern Material 3 design systems, the platform orchestrates autonomous multi-agents to analyze code repositories, model Infrastructure-as-Code (IaC), deploy applications, observe metrics, and apply hotfixes autonomously.

---

## 🎨 System Highlights & Features

### 1. Repository Analyzer & Pipeline Workflows
* **Autonomous Discovery:** Analyze any imported Git repository instantly using **Gemini** (on-device REST call, or via the operator gateway when the backend is enabled) to discover technology stacks, frameworks, and architecture blocks. Without an API key, a high-quality offline template engine takes over.
* **11-Stage Deployment Engine:** A comprehensive *simulated* operator workspace with real-time terminal trace logs visualizing deep tasks including:
  * Security scanning & vulnerability auditing (simulated Bandit/npm audit trace)
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

## 🛠️ Technology Stack & Architecture

DevOps.AI is engineered under rigorous industry standards:

* **Language:** Kotlin 100%
* **UI toolkit:** Jetpack Compose (Material Design 3, dynamic gradients, responsive viewports)
* **API Layer:** Direct REST client calls to the Gemini API (on-device), or the FastAPI Operator Gateway when "Remote Backend" is enabled in Settings
* **Local Persistence:** Room Database (RepoEntity, IncidentEntity, DeploymentLogEntity)
* **Thread Safety:** Structured Kotlin Coroutines & Flow streams for background calculations
* **Signings & Builds:** Gradle Kotlin DSL (`build.gradle.kts`) structured via standard custom plugins

The repository also contains two Python layers:

* **`backend/`** — the "Operator Gateway" the Android app can connect to (FastAPI + Celery + PostgreSQL + Redis + Qdrant). Exposes `/api/v1/repository/analyze` (the app's remote contract), `/metrics` for Prometheus, and graceful offline templates when no Gemini key is configured server-side.
* **`devops-ai-platform/`** — the DDD bounded-context microservices (gateway, repo, agent, deployment, monitoring, incident, reporting + shared kernel). Every service now boots (see `devops-ai-platform/README.md`).

---

## 🚀 Setting Up the Application

To build and experience DevOps.AI as a fully functional platform:

1. **Configure your Gemini API Key (optional):**
   * Enter your API credentials inside the Google AI Studio **Secrets Panel**.
   * The app will inject it at runtime using `BuildConfig.GEMINI_API_KEY`.
   * *If no key is configured, the application gracefully activates its high-quality Offline Pre-simulation Engine so you can inspect beautiful templates instantly.*
   * For **remote mode**, prefer setting `GEMINI_API_KEY` on the *backend* instead (`export GEMINI_API_KEY=...` before `docker-compose up`) — the server then performs the live AI call and the key does not ship in the APK.

2. **Build the Android app:**
   Using Gradle (no wrapper is committed; a local Gradle + JDK installation is required):
   ```bash
   gradle assembleDebug
   ```

3. **Optional: run the backend stack + observability:**
   ```bash
   docker-compose up -d
   # API on :8000, Prometheus on :9090, Grafana on :3000 (datasource pre-provisioned)
   ```
   Then in the app: **Settings ⚙ → Remote Backend ON → `http://10.0.2.2:8000` → Ping Endpoint**.

4. **Optional: run the DDD platform:** see [`devops-ai-platform/README.md`](devops-ai-platform/README.md).

5. **Tests:**
   ```bash
   cd backend && pip install -r requirements-dev.txt && python -m pytest tests/
   cd devops-ai-platform && pip install -r requirements.txt pytest && python -m pytest tests/
   ```

6. **Deploy or Export:**
   * Export the workspace as a unified APK/AAB or push the source code directly to GitHub using your AI Studio profile integrations.
