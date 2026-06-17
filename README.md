# DevOps.AI - Autonomous Multi-Agent DevOps Engineer Clients

DevOps.AI is a high-fidelity, enterprise-grade Android client application built as an intelligent Virtual DevOps Engineer workstation. Crafted with Kotlin, Jetpack Compose, and modern Material 3 design systems, the platform orchestrates autonomous multi-agents to analyze code repositories, model Infrastructure-as-Code (IaC), deploy applications, observe metrics, and apply hotfixes autonomously.

---

## 🎨 System Highlights & Features

### 1. Repository Analyzer & Pipeline Workflows
* **Autonomous Discovery:** Analyze any imported Git repository instantly using server-side **Gemini 3.5 Flash** models to discover technology stacks, frameworks, and architecture blocks.
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

## 🛠️ Technology Stack & Architecture

DevOps.AI is engineered under rigorous industry standards:

* **Language:** Kotlin 100%
* **UI toolkit:** Jetpack Compose (Material Design 3, dynamic gradients, responsive viewports)
* **API Layer:** Direct REST client calls mapping Gemini API endpoints
* **Local Persistence:** Secure Room Database persistent state cache (RepoEntity, IncidentEntity, DeploymentLogEntity)
* **Thread Safety:** Structured Kotlin Coroutines & Flow streams for background calculations
* **Signings & Builds:** Gradle Kotlin DSL (`build.gradle.kts`) structured via standard custom plugins

---

## 🚀 Setting Up the Application

To build and experience DevOps.AI as a fully functional platform:

1. **Configure your Gemini API Key:**
   * Enter your API credentials inside the Google AI Studio **Secrets Panel**.
   * The app will inject it at runtime using `BuildConfig.GEMINI_API_KEY`.
   * *If no key is configured, the application gracefully activates its high-quality Offline Pre-simulation Engine so you can inspect beautiful templates instantly.*

2. **Run and Compiles:**
   Using Gradle:
   ```bash
   gradle assembleDebug
   ```

3. **Deploy or Export:**
   * Export the workspace as a unified APK/AAB or push the source code directly to GitHub using your AI Studio profile integrations.
