"""Phase 6.4 — change intelligence read API (authenticated at gateway).

One small read-only endpoint: ``GET /changes/{deployment_run_id}/health?start&end``.
No SQL and no rules in the handler — the application service owns window
validation, correlation and the deterministic rule evaluator; the
repository owns persistence reads. This surface can never mutate
anything (no rollback, approval, or deployment action exists here).
"""

from datetime import datetime
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query

from incident_service.application.dependencies import get_incident_repository
from incident_service.application.services.change_intelligence_service import (
    ChangeIntelligenceService,
)
from incident_service.application.services.operational_analytics_service import (
    InvalidAnalyticsWindowError,
)
from incident_service.domain.repository_interface import IncidentRepositoryPort

router = APIRouter(prefix="/changes", tags=["Change Intelligence"])


@router.get("/{deployment_run_id}/health", response_model=Dict[str, Any])
def get_change_health(
    deployment_run_id: str,
    start: datetime = Query(
        ..., description="Observation window start, ISO 8601 (naive = UTC)"
    ),
    end: datetime = Query(
        ..., description="Observation window end, ISO 8601 (naive = UTC)"
    ),
    repository: IncidentRepositoryPort = Depends(get_incident_repository),
):
    """Evidence-backed release-health assessment (HEALTHY/DEGRADED/FAILED/
    INCONCLUSIVE) for one deployment/change over a bounded observation
    window. Read-only; correlation is association, not causal proof.
    """
    try:
        return ChangeIntelligenceService(repository).assess(
            deployment_run_id=deployment_run_id, start=start, end=end
        )
    except InvalidAnalyticsWindowError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
