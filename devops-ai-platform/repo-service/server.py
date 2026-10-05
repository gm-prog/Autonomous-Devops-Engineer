from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl

from repository_analyzer import RepositoryAnalyzer

app = FastAPI(
    title="DevOps.AI Repository Intelligence Service",
    version="1.0.0",
)

analyzer = RepositoryAnalyzer()

class RepositoryAnalyzeRequest(BaseModel):
    name: str
    url: HttpUrl

@app.get("/health")
def health():
    return {"status": "healthy", "service": "repo-service"}

@app.post("/api/internal/analyze")
def analyze_repository(request: RepositoryAnalyzeRequest):
    try:
        return analyzer.analyze(str(request.url), request.name)
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Repository analysis failed: {type(exc).__name__}",
        ) from exc
