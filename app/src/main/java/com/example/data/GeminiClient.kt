package com.example.data

/**
 * Repository-analysis engine (Phase 8.7-C.1 — offline-only, truthful contract).
 *
 * SECURITY MODEL — read this before adding a "quick key" or "quick backend":
 *
 * Android-distributed applications CANNOT keep a reusable provider secret
 * confidential. Any credential shipped inside an APK (BuildConfig, string
 * resources, assets, SharedPreferences defaults, obfuscated or base64-wrapped
 * constants) is recoverable by anyone who can decompile the artifact.
 * Embedding GEMINI_API_KEY in the app is therefore a credential leak, not a
 * configuration option.
 *
 * TRUTHFUL BEHAVIOR ON THIS BRANCH:
 *
 * This class is the deterministic offline engine. The Android app also has a
 * separate authenticated server-side analysis path in BackendGatewayClient;
 * that path carries only a platform JWT and keeps GEMINI_API_KEY server-side.
 *
 * The live path must remain in the dedicated authenticated gateway client:
 *
 *  * do not add a `?key=` request path or any BuildConfig provider secret;
 *  * do not add fake/placeholder authentication headers presented as real
 *    security;
 *  * keep this class network-free and non-secret.
 *
 * The CI job `android-secret-guards` fails the build if a Gemini secret or a
 * fictitious remote analysis path reappears.
 */
object GeminiClient {

    /**
     * Analyzes a repository for DevOps asset generation.
     *
     * Offline-only on this branch: deterministic template engine, no provider
     * credential, no network call. See the object-level security model note.
     */
    fun analyzeRepository(
        repoName: String,
        repoUrl: String,
        framework: String,
        technology: String
    ): DevOpsAnalysisResult {
        return generateSimulatedAssets(repoName, technology, framework)
    }

    /**
     * Offline template engine. Pure, non-secret, deterministic fallback used
     * for ALL repository analysis on this branch.
     */
    fun generateSimulatedAssets(
        repoName: String,
        technology: String,
        framework: String
    ): DevOpsAnalysisResult {
        val techLower = technology.lowercase()
        return when {
            techLower.contains("python") || techLower.contains("fastapi") || techLower.contains("django") -> {
                DevOpsAnalysisResult(
                    dockerfile = """
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
                        ENV PATH=/home/appuser/.local/bin:${'$'}PATH
                        
                        EXPOSE 8000
                        HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
                          CMD curl -f http://localhost:8000/health || exit 1
                        
                        CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
                    """.trimIndent(),
                    k8sYaml = """
                        # Enterprise Kubernetes Config for FastAPI Microservice
                        apiVersion: apps/v1
                        kind: Deployment
                        metadata:
                          name: $repoName-deployment
                          labels:
                            app: $repoName
                            tier: backend
                        spec:
                          replicas: 3
                          selector:
                            matchLabels:
                              app: $repoName
                          template:
                            metadata:
                              labels:
                                app: $repoName
                            spec:
                              containers:
                              - name: $repoName-container
                                image: 555555555555.dkr.ecr.us-east-1.amazonaws.com/$repoName:latest
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
                          name: $repoName-service
                        spec:
                          type: ClusterIP
                          ports:
                          - port: 80
                            targetPort: 8000
                          selector:
                            app: $repoName
                    """.trimIndent(),
                    terraformTf = """
                        # Terraform AWS Module definition
                        provider "aws" {
                          region = "us-east-1"
                        }
                        
                        module "vpc" {
                          source = "terraform-aws-modules/vpc/aws"
                          name   = "$repoName-vpc"
                          cidr   = "10.0.0.0/16"
                          
                          azs             = ["us-east-1a", "us-east-1b"]
                          private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
                          public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]
                          enable_nat_gateway = true
                          single_nat_gateway  = true
                        }
                        
                        resource "aws_security_group" "$repoName-sg" {
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
                    """.trimIndent(),
                    pipelineYaml = """
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
                                docker build -t ecr-registry/$repoName:latest .
                    """.trimIndent(),
                    report = "Discovered FastAPI web application pattern. Setup provisions a secure VPC, a three-replica cluster architecture optimized using multi-stage light images and secure, non-privileged executing boundaries."
                )
            }
            techLower.contains("node") || techLower.contains("react") || techLower.contains("javascript") || techLower.contains("next") -> {
                DevOpsAnalysisResult(
                    dockerfile = """
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
                    """.trimIndent(),
                    k8sYaml = """
                        # Kubernetes Deployment Manifest
                        apiVersion: apps/v1
                        kind: Deployment
                        metadata:
                          name: $repoName-frontend
                          labels:
                            app: $repoName
                        spec:
                          replicas: 2
                          selector:
                            matchLabels:
                              app: $repoName
                          template:
                            metadata:
                              labels:
                                app: $repoName
                            spec:
                              containers:
                              - name: $repoName
                                image: node-registry/$repoName:v2.0
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
                          name: $repoName-service
                        spec:
                          type: LoadBalancer
                          ports:
                          - port: 80
                            targetPort: 3000
                          selector:
                            app: $repoName
                    """.trimIndent(),
                    terraformTf = """
                        # S3 Bucket and CloudFront distribution for Static assets
                        resource "aws_s3_bucket" "static_bucket" {
                          bucket = "$repoName-frontend-bucket"
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
                    """.trimIndent(),
                    pipelineYaml = """
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
                              run: aws s3 sync ./dist s3://$repoName-frontend-bucket --delete
                    """.trimIndent(),
                    report = "Identified statically compileable frontend node workspace. Provisioned a highly performant, serverless CDN static hosting profile with S3 cloud storage layered with secure SSL-CloudFront caching boundaries."
                )
            }
            else -> {
                // Java / general fallback
                DevOpsAnalysisResult(
                    dockerfile = """
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
                    """.trimIndent(),
                    k8sYaml = """
                        # Enterprise Multi-service Manifests
                        apiVersion: apps/v1
                        kind: Deployment
                        metadata:
                          name: $repoName-node
                        spec:
                          replicas: 4
                          selector:
                            matchLabels:
                              app: $repoName
                          template:
                            metadata:
                              labels:
                                app: $repoName
                            spec:
                              containers:
                              - name: service
                                image: 123456789.dkr.ecr.us-east-1.amazonaws.com/$repoName:latest
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
                          name: $repoName-lb
                        spec:
                          type: ClusterIP
                          ports:
                          - port: 8080
                            targetPort: 8080
                          selector:
                            app: $repoName
                    """.trimIndent(),
                    terraformTf = """
                        # Terraform Kubernetes EKS Cluster setup
                        module "eks" {
                          source          = "terraform-aws-modules/eks/aws"
                          version         = "~> 20.0"
                          cluster_name    = "$repoName-kubernetes"
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
                    """.trimIndent(),
                    pipelineYaml = """
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
                    """.trimIndent(),
                    report = "Identified robust enterprise JVM deployment footprint. Provisioned a dynamic Kubernetes topology managed by Amazon EKS with robust metrics tracking, horizontal scheduling properties, and strict resource gates."
                )
            }
        }
    }
}

data class DevOpsAnalysisResult(
    val dockerfile: String,
    val k8sYaml: String,
    val terraformTf: String,
    val pipelineYaml: String,
    val report: String
)
