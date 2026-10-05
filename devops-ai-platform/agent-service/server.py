import json
import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from infrastructure.llm.gemini_caller import GeminiCallerAdapter

app = FastAPI(title="DevOps.AI Agent Service", version="1.0.0")
llm = GeminiCallerAdapter(monthly_budget_usd=float(os.getenv("GEMINI_MONTHLY_BUDGET_USD", "100")))

class IaCRequest(BaseModel):
    repository: dict


class RcaRequest(BaseModel):
    evidence_pack: dict

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
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("\n", 1)[1].rsplit("```", 1)[0].strip()
        return json.loads(cleaned)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="AI artifact generation failed") from exc

@app.post("/api/internal/analyze-rca")
def analyze_rca(request: RcaRequest):
    pack = request.evidence_pack
    prompt = f"""
You are the RCA investigator for an autonomous DevOps platform.

Use ONLY the supplied incident evidence pack. Do not invent logs, deployments,
code changes, infrastructure facts, or causal links that are not supported by
the evidence.

Return ONLY valid JSON with exactly these keys:
{{
  "root_cause": "concise evidence-grounded root cause",
  "confidence": 0.0,
  "supporting_evidence_ids": ["..."],
  "contributing_factors": ["..."],
  "recommended_next_actions": ["..."]
}}

Rules:
- confidence must be a number from 0.0 to 1.0.
- supporting_evidence_ids must reference IDs present in the evidence pack.
- If evidence is insufficient, say so explicitly in root_cause and use a lower confidence.
- recommended_next_actions are suggestions only; do not claim a fix was executed.

Evidence pack:
{json.dumps(pack, separators=(",", ":"))}
"""
    try:
        raw = llm.generate_remediation(
            prompt,
            "You are a cautious SRE root-cause analyst. Reason only from supplied evidence and return strict JSON.",
        )
        result = _parse_json_object(raw)
        _validate_rca_result(result, pack)
        return result
    except Exception as exc:
        raise HTTPException(status_code=502, detail="RCA analysis failed") from exc


def _parse_json_object(raw: str) -> dict:
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[1].rsplit("```", 1)[0].strip()
    value = json.loads(cleaned)
    if not isinstance(value, dict):
        raise ValueError("AI response must be a JSON object")
    return value


def _validate_rca_result(result: dict, pack: dict) -> None:
    required = {
        "root_cause",
        "confidence",
        "supporting_evidence_ids",
        "contributing_factors",
        "recommended_next_actions",
    }
    if set(result) != required:
        raise ValueError("RCA response schema mismatch")
    confidence = result["confidence"]
    if not isinstance(confidence, (int, float)) or not 0.0 <= float(confidence) <= 1.0:
        raise ValueError("RCA confidence must be between 0.0 and 1.0")
    valid_ids = {
        item.get("evidence_id")
        for item in pack.get("evidence", {}).get("timeline", [])
    }
    evidence_ids = result["supporting_evidence_ids"]
    if not isinstance(evidence_ids, list) or not all(item in valid_ids for item in evidence_ids):
        raise ValueError("RCA supporting evidence IDs are invalid")
