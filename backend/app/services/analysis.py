"""
Repository analysis engine for the DevOps.AI Operator Gateway.

This module is the single source of truth for IaC generation on the server:

* ``generate_templates``  - deterministic, offline tech-stack templates
  (mirrors the Android client's Offline Pre-simulation Engine so that remote
  and on-device mode produce equivalent artifacts).
* ``call_gemini``         - live Google Gemini REST call (v1beta) using the
  same tag-delimited output protocol as the Android client
  (``<DOCKERFILE>`` / ``<KUBERNETES>`` / ``<TERRAFORM>`` / ``<CICD>`` / ``<REPORT>``).
* ``analyze_repository``  - orchestrator: live Gemini when a key is
  configured, graceful template fallback otherwise.

The Gemini API key is a SERVER-side secret (environment variable). It is
never embedded in the Android client for remote mode.
"""

import logging
import os
import re
from typing import Dict, Optional

import requests

logger = logging.getLogger("DevOpsAnalysis")

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash")
GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

#: Sentinel value that the AI Studio build pipeline writes when no key was
#: configured. Treated as "absent" so we never send it to Google.
_PLACEHOLDER_KEY = "MY_GEMINI_API_KEY"


def _is_usable_key(api_key: Optional[str]) -> bool:
    return bool(api_key) and api_key != _PLACEHOLDER_KEY


def parse_tag(text: str, tag: str) -> str:
    """Extract the payload between ``<TAG>`` and ``</TAG>``.

    Mirrors ``GeminiClient.parseTag`` on the Android side:
    * missing/malformed tags yield an empty string (never an exception);
    * stray markdown code fences inside the payload are stripped.
    """
    open_tag = f"<{tag}>"
    close_tag = f"</{tag}>"
    start = text.find(open_tag)
    end = text.find(close_tag)
    if start != -1 and end != -1 and end > start:
        content = text[start + len(open_tag):end]
        # Strip any leading/trailing markdown codegen markers (```yaml etc.)
        content = re.sub(r"^```[a-zA-Z]*\n", "", content)
        content = re.sub(r"\n```$", "", content)
        return content.strip()
    return ""


def parse_gemini_response(text: str) -> Dict[str, str]:
    """Parse the 5-tag AI output protocol into a flat artifact dict."""
    return {
        "dockerfile": parse_tag(text, "DOCKERFILE"),
        "k8s_yaml": parse_tag(text, "KUBERNETES"),
        "terraform_tf": parse_tag(text, "TERRAFORM"),
        "pipeline_yaml": parse_tag(text, "CICD"),
        "analysis_report": parse_tag(text, "REPORT")
        or "Successfully generated secure deployment structures.",
    }


# ---------------------------------------------------------------------------
# Offline templates (ported 1:1 from the Android client's
# GeminiClient.generateSimulatedAssets so both modes stay consistent)
# ---------------------------------------------------------------------------

def _tpl(template: str, name: str) -> str:
    return template.replace("@@NAME@@", name)


_PYTHON_DOCKERFILE = """\
# Multi-stage build for Python microservice
FROM python:3.12-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends build-essential gcc
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.12-slim AS runner
WORKDIR /app
# Copy installed packages using non-root user
COPY --from=builder /root/.local /home/appuser/.local
COPY . .

# Set security boundaries (non-root execution)
RUN useradd -u 8888 appuser && chown -R appuser:appuser /app
USER appuser
ENV PATH=/home/appuser/.local/bin:$PATH

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \\
  CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
"""

_PYTHON_K8S = """\
# Enterprise Kubernetes Config for FastAPI Microservice
apiVersion: apps/v1
kind: Deployment
metadata:
  name: @@NAME@@-deployment
  labels:
    app: @@NAME@@
    tier: backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: @@NAME@@
  template:
    metadata:
      labels:
        app: @@NAME@@
    spec:
      containers:
      - name: @@NAME@@-container
        image: 555555555555.dkr.ecr.us-east-1.amazonaws.com/@@NAME@@:latest
        ports:
        - containerPort: 8000
        resources:
          limits:
            cpu: "500m"
            memory: "512Mi"
          requests:
            cpu: "200m"
            memory: "256Mi"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 15
          periodSeconds: 20
---
apiVersion: v1
kind: Service
metadata:
  name: @@NAME@@-service
spec:
  type: ClusterIP
  ports:
  - port: 80
    targetPort: 8000
  selector:
    app: @@NAME@@
"""

_PYTHON_TF = """\
# Terraform AWS Module definition
provider "aws" {
  region = "us-east-1"
}

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  name   = "@@NAME@@-vpc"
  cidr   = "10.0.0.0/16"

  azs             = ["us-east-1a", "us-east-1b"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]
  enable_nat_gateway = true
  single_nat_gateway  = true
}

resource "aws_security_group" "@@NAME@@-sg" {
  vpc_id = module.vpc.vpc_id
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

_PYTHON_PIPELINE = """\
# GitHub Actions CI/CD Pipeline
name: CI/CD Pipeline
on:
  push:
    branches: [ main ]
jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Setup Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.12'
    - name: Run Sec-Scan
      run: |
        pip install bandit
        bandit -r ./app
    - name: Build and Push ECR
      run: |
        docker build -t ecr-registry/@@NAME@@:latest .
"""

_PYTHON_REPORT = (
    "Discovered FastAPI web application pattern. Setup provisions a secure VPC, a "
    "three-replica cluster architecture optimized using multi-stage light images and "
    "secure, non-privileged execution boundaries."
)

_NODE_DOCKERFILE = """\
# Multi-stage construction for Node.js / React micro-frontend
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package*.json ./
RUN npm ci --only=production

# Avoid execution under root context
USER node
EXPOSE 3000
CMD ["npm", "run", "start:prod"]
"""

_NODE_K8S = """\
# Kubernetes Deployment Manifest
apiVersion: apps/v1
kind: Deployment
metadata:
  name: @@NAME@@-frontend
  labels:
    app: @@NAME@@
spec:
  replicas: 2
  selector:
    matchLabels:
      app: @@NAME@@
  template:
    metadata:
      labels:
        app: @@NAME@@
    spec:
      containers:
      - name: @@NAME@@
        image: node-registry/@@NAME@@:v2.0
        resources:
          limits:
            cpu: "400m"
            memory: "256Mi"
          requests:
            cpu: "100m"
            memory: "128Mi"
---
apiVersion: v1
kind: Service
metadata:
  name: @@NAME@@-service
spec:
  type: LoadBalancer
  ports:
  - port: 80
    targetPort: 3000
  selector:
    app: @@NAME@@
"""

_NODE_TF = """\
# S3 Bucket and CloudFront distribution for Static assets
resource "aws_s3_bucket" "static_bucket" {
  bucket = "@@NAME@@-frontend-bucket"
}

resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name = aws_s3_bucket.static_bucket.bucket_regional_domain_name
    origin_id   = "s3_origin"
  }
  enabled             = true
  default_root_object = "index.html"
  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "s3_origin"
    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }
    viewer_protocol_policy = "redirect-to-https"
  }
  viewer_certificate {
    cloudfront_default_certificate = true
  }
  restrictions {
    geo_restriction { restriction_type = "none" }
  }
}
"""

_NODE_PIPELINE = """\
# Node.js Static Deploy CD
name: Deploy Web App
on:
  push:
    branches: [ production ]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - run: npm ci
    - run: npm run build
    - name: Linter & Security Audit
      run: |
        npm run lint
        npm audit --audit-level=high
    - name: Deploy to S3
      run: aws s3 sync ./dist s3://@@NAME@@-frontend-bucket --delete
"""

_NODE_REPORT = (
    "Identified statically compilable frontend node workspace. Provisioned a highly "
    "performant, serverless CDN static hosting profile with S3 cloud storage layered "
    "with secure SSL-CloudFront caching boundaries."
)

_JVM_DOCKERFILE = """\
# Enterprise JVM Container Setup
FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /workspace
COPY gradle gradle
COPY gradlew build.gradle settings.gradle ./
COPY src src
RUN ./gradlew build -x test

FROM eclipse-temurin:21-jre-alpine AS runner
WORKDIR /app
COPY --from=build /workspace/build/libs/*.jar app.jar

# Restrict JVM process capabilities
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
"""

_JVM_K8S = """\
# Enterprise Multi-service Manifests
apiVersion: apps/v1
kind: Deployment
metadata:
  name: @@NAME@@-node
spec:
  replicas: 4
  selector:
    matchLabels:
      app: @@NAME@@
  template:
    metadata:
      labels:
        app: @@NAME@@
    spec:
      containers:
      - name: service
        image: 123456789.dkr.ecr.us-east-1.amazonaws.com/@@NAME@@:latest
        resources:
          limits:
            cpu: "1.5"
            memory: "2Gi"
          requests:
            cpu: "500m"
            memory: "1Gi"
---
apiVersion: v1
kind: Service
metadata:
  name: @@NAME@@-lb
spec:
  type: ClusterIP
  ports:
  - port: 8080
  selector:
    app: @@NAME@@
"""

_JVM_TF = """\
# Terraform Kubernetes EKS Cluster setup
module "eks" {
  source          = "terraform-aws-modules/eks/aws"
  version         = "~> 20.0"
  cluster_name    = "@@NAME@@-kubernetes"
  cluster_version = "1.30"
  vpc_id          = "vpc-xxxxxxxx"
  subnet_ids      = ["subnet-xxxx", "subnet-yyyy"]
  eks_managed_node_groups = {
    primary = {
      min_size     = 3
      max_size     = 10
      desired_size = 5
      instance_types = ["t3.medium"]
    }
  }
}
"""

_JVM_PIPELINE = """\
# Compile testing build pipeline
name: Kotlin Gradle CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-java@v4
      with:
        distribution: 'temurin'
        java-version: '21'
    - run: ./gradlew test
    - run: ./gradlew jacocoTestReport
"""

_JVM_REPORT = (
    "Identified robust enterprise JVM deployment footprint. Provisioned a dynamic "
    "Kubernetes topology managed by Amazon EKS with robust metrics tracking, "
    "horizontal scheduling properties, and strict resource gates."
)


def generate_templates(
    repo_name: str, framework: str, technology: str
) -> Dict[str, str]:
    """Deterministic offline IaC templates, branched on detected technology.

    Same branch keys as the Android client: python/fastapi/django,
    node/react/javascript/next, and a JVM fallback for everything else.
    """
    name = (repo_name or "app").strip().lower().replace(" ", "-") or "app"
    tech = (technology or "").lower()
    frame = (framework or "").lower()

    if any(k in tech for k in ("python", "fastapi", "django")) or any(
        k in frame for k in ("python", "fastapi", "django")
    ):
        return {
            "dockerfile": _PYTHON_DOCKERFILE,
            "k8s_yaml": _tpl(_PYTHON_K8S, name),
            "terraform_tf": _tpl(_PYTHON_TF, name),
            "pipeline_yaml": _tpl(_PYTHON_PIPELINE, name),
            "analysis_report": _PYTHON_REPORT,
        }
    if any(k in tech for k in ("node", "react", "javascript", "next", "typescript")) or any(
        k in frame for k in ("node", "react", "next", "vue", "svelte")
    ):
        return {
            "dockerfile": _NODE_DOCKERFILE,
            "k8s_yaml": _tpl(_NODE_K8S, name),
            "terraform_tf": _tpl(_NODE_TF, name),
            "pipeline_yaml": _tpl(_NODE_PIPELINE, name),
            "analysis_report": _NODE_REPORT,
        }
    return {
        "dockerfile": _JVM_DOCKERFILE,
        "k8s_yaml": _tpl(_JVM_K8S, name),
        "terraform_tf": _tpl(_JVM_TF, name),
        "pipeline_yaml": _JVM_PIPELINE,
        "analysis_report": _JVM_REPORT,
    }


# ---------------------------------------------------------------------------
# Live Gemini integration
# ---------------------------------------------------------------------------

def _build_prompt(repo_name: str, repo_url: str, framework: str, technology: str) -> str:
    return f"""You are DevOpsAI, a virtual DevOps engineer capable of analyzing repositories and generating production-ready infrastructure configurations.

Analyze the following repository description:
- Name: {repo_name}
- URL/Description: {repo_url}
- Main Tech Stack: {technology}
- Main Framework: {framework}

Please provide a production-grade, highly secure setup for this configuration. Generate exactly 4 clean DevOps configurations and a short architectural report.
Return them enclosed in specific markup tags so they can be parsed programmatically:

<DOCKERFILE>
[Add the optimized production Dockerfile content here. Include multi-stage builds, non-root users, security practices, and clean labels.]
</DOCKERFILE>

<KUBERNETES>
[Add production-grade Kubernetes YAML manifests including Deployment, Service, and HorizontalPodAutoscaler. Explicit CPU/Memory resources must be defined.]
</KUBERNETES>

<TERRAFORM>
[Add excellent, production-grade Terraform files defining an AWS VPC, Security Group, and container-running host/service like AWS ECS or EKS.]
</TERRAFORM>

<CICD>
[Add a complete GitHub Actions CI/CD pipeline in YAML configuring security scanning, Docker build, and deployment steps.]
</CICD>

<REPORT>
[Write a highly professional 150-word Repository Analysis and Architectural Discovery Report explaining your secure choices.]
</REPORT>

Ensure there is NO extra text outside these tags. Do not wrap code blocks inside standard ``` markdown code blocks inside the tags, just write the raw files inside the XML style tags."""


def call_gemini(
    repo_name: str,
    repo_url: str,
    framework: str,
    technology: str,
    api_key: str,
    model: str = GEMINI_MODEL,
    timeout: int = 60,
) -> Optional[Dict[str, str]]:
    """Synchronous Gemini generateContent call. Returns parsed artifacts or None.

    The API key is sent via the ``x-goog-api-key`` header (never as a URL
    query parameter) so it cannot leak into proxy/CDN access logs.
    """
    url = GEMINI_ENDPOINT.format(model=model)
    headers = {"x-goog-api-key": api_key, "Content-Type": "application/json"}
    body = {
        "contents": [
            {"parts": [{"text": _build_prompt(repo_name, repo_url, framework, technology)}]}
        ],
        "systemInstruction": {
            "parts": [
                {
                    "text": (
                        "You are an expert enterprise-grade AI DevOps engineer "
                        "specializing in Docker, K8s, AWS, AWS Terraform, "
                        "security scanning, and GitHub Actions."
                    )
                }
            ]
        },
    }

    try:
        resp = requests.post(url, json=body, headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        logger.warning("Gemini transport failure: %s", exc)
        return None

    if resp.status_code != 200:
        logger.warning("Gemini returned HTTP %s", resp.status_code)
        return None

    try:
        data = resp.json()
    except ValueError:
        logger.warning("Gemini returned non-JSON payload")
        return None

    text = (
        (data.get("candidates") or [{}])[0]
        .get("content", {})
        .get("parts", [{}])[0]
        .get("text", "")
        or ""
    )
    if not text:
        logger.warning("Gemini response contained no text parts")
        return None

    artifacts = parse_gemini_response(text)
    if not artifacts["dockerfile"]:
        # Model did not honor the tag protocol - treat as unusable.
        logger.warning("Gemini output missing required tags; falling back to templates")
        return None
    return artifacts


def analyze_repository(
    repo_name: str,
    repo_url: str,
    framework: str,
    technology: str,
    api_key: Optional[str] = None,
) -> Dict[str, str]:
    """Orchestrator: live Gemini when a real key is configured, else templates.

    Returns the 5 artifact fields plus an ``engine`` label (``gemini`` or
    ``template``) and, when a fallback occurred, a human-readable ``note``.
    """
    if _is_usable_key(api_key):
        artifacts = call_gemini(repo_name, repo_url, framework, technology, api_key)
        if artifacts is not None:
            artifacts["engine"] = "gemini"
            return artifacts
        logger.info("Gemini unavailable - activating offline template engine for %s", repo_name)
        note = "Gemini call failed or returned unparseable output; offline template engine activated."
    else:
        note = "No server-side GEMINI_API_KEY configured; offline template engine activated."

    artifacts = generate_templates(repo_name, framework, technology)
    artifacts["engine"] = "template"
    artifacts["note"] = note
    return artifacts
