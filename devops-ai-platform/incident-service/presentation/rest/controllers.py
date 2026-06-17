from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any

router = APIRouter(prefix="/incidents", tags=["Active Incidents Controller"])

@router.get("", response_model=List[Dict[str, Any]])
def list_current_anomalies():
    """Fetches high priority incident rooms active in our cluster systems."""
    return [
        {
            "id": "inc_778120",
            "title": "[SENTRY] HikariPool Connection saturation thread lock",
            "severity": "CRITICAL",
            "status": "Triage",
            "created_at": "2026-06-17T12:00:15Z"
        },
        {
            "id": "inc_778121",
            "title": "[PROM-ALERT] AWS ECS Node 03 Disk Space Saturation > 92%",
            "severity": "HIGH",
            "status": "Resolved",
            "created_at": "2026-06-17T08:12:00Z"
        }
    ]
