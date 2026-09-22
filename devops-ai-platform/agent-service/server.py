import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from infrastructure.llm.gemini_caller import GeminiCallerAdapter

app = FastAPI(title="DevOps.AI Agent Service", version="1.0.0")
llm = GeminiCallerAdapter(monthly_budget_usd=float(os.getenv("GEMINI_MONTHLY_BUDGET_USD", "100")))

class IaCRequest(BaseModel):
    repository: dict

@app.get("/health")
def health():
    return {"status": "healthy", "service": "agent-service"}

@app.post("/api/internal/generate-iac")
def generate_iac(request: IaCRequest):
    repository = request.repository
    tech = repository.get("tech_stack", {})
    files = repository.get("files", [])
    compact_files = [
        {"path": item["path"], "language": item["language"], "content": item["content"][:12000]}
        for item in files[:40]
    ]
    prompt = f"""
Analyze this software repository as a senior DevOps architect.

Repository: {repository.get("name")}
Primary language: {tech.get("primary_language")}
Frameworks: {tech.get("frameworks")}
Dockerfile exists: {tech.get("has_dockerfile")}
Kubernetes manifests exist: {tech.get("has_k8s_manifests")}

Source excerpts:
{compact_files}

Return production-oriented deployment artifacts. The response MUST be valid JSON with exactly:
{{
  "dockerfile": "...",
  "k8s_yaml": "...",
  "terraform_tf": "...",
  "pipeline_yaml": "...",
  "analysis_report": "..."
}}

Do not include Markdown fences around the JSON. Do not invent application ports when they can be inferred from source. Prefer least-privilege, non-root containers, health checks, bounded resources, and immutable image tags.
"""
    try:
        raw = llm.generate_remediation(
            prompt,
            "You are a senior DevOps architect. Produce conservative, reviewable infrastructure artifacts."
        )
        import json
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[1].rsplit("```", 1)[0].strip()
        return json.loads(cleaned)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="AI artifact generation failed") from exc
