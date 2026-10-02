"""Phase 6.4 — change intelligence read API (authenticated at gateway).

Small read-only endpoints: ``GET /changes/{deployment_run_id}/health?start&end``
(durable evidence, Phase 6.4) and
``GET /changes/{deployment_run_id}/live-health?start&end`` (combined
durable + attributable live telemetry, Phase 6.5). No SQL and no rules
in the handlers — the application services own window validation,
correlation, telemetry attribution and the deterministic rule
evaluators; the repository owns persistence reads. These surfaces can
never mutate anything (no rollback, approval, or deployment action
exists here). Telemetry failures never surface as HTTP errors: they are
fail-closed data-quality gaps inside a 200 response
(``decision=INCONCLUSIVE``).
"""

from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from incident_service.application.dependencies import (
    get_incident_repository,
    get_live_prometheus_client,
)
from incident_service.application.services.change_intelligence_service import (
    ChangeIntelligenceService,
)
from incident_service.application.services.live_release_verification_service import (
    LiveReleaseVerificationService,
)
from incident_service.application.services.progressive_release_gate_service import (
    InvalidProgressiveReleaseGateRequest,
    ProgressiveReleaseGateService,
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


@router.get("/{deployment_run_id}/live-health", response_model=Dict[str, Any])
def get_change_live_health(
    deployment_run_id: str,
    start: datetime = Query(
        ..., description="Verification window start, ISO 8601 (naive = UTC)"
    ),
    end: datetime = Query(
        ..., description="Verification window end, ISO 8601 (naive = UTC)"
    ),
    baseline_deployment_run_id: Optional[str] = Query(
        None,
        description=(
            "Optional explicit baseline release: its deployment run id must "
            "resolve to durable evidence inside the same window or the "
            "assessment reports invalid_baseline"
        ),
    ),
    repository: IncidentRepositoryPort = Depends(get_incident_repository),
    prometheus=Depends(get_live_prometheus_client),
):
    """Combined read model: the unchanged Phase 6.4 durable assessment plus
    the Phase 6.5 live telemetry assessment (HEALTHY/DEGRADED/FAILED/
    INCONCLUSIVE) for telemetry attributable to this exact release.
    Read-only; window validation → 422, unknown run → 404, telemetry
    unavailable/malformed/unattributable → 200 with INCONCLUSIVE.
    """
    try:
        return LiveReleaseVerificationService(repository, prometheus).verify(
            deployment_run_id=deployment_run_id,
            start=start,
            end=end,
            baseline_deployment_run_id=baseline_deployment_run_id,
        )
    except InvalidAnalyticsWindowError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{deployment_run_id}/gate", response_model=Dict[str, Any])
def get_change_release_gate(
    deployment_run_id: str,
    start: datetime = Query(
        ..., description="Verification window start, ISO 8601 (naive = UTC)"
    ),
    end: datetime = Query(
        ..., description="Verification window end, ISO 8601 (naive = UTC)"
    ),
    target_percentage: int = Query(
        ..., description="Requested progressive exposure: 5, 25, 50, or 100"
    ),
    baseline_deployment_run_id: Optional[str] = Query(
        None,
        description=(
            "Explicit baseline release required for exposure above 5%; "
            "its identity must remain attributable by Phase 6.5."
        ),
    ),
    repository: IncidentRepositoryPort = Depends(get_incident_repository),
    prometheus=Depends(get_live_prometheus_client),
):
    """Read-only Phase 6.6 progressive-release gate.

    No rollout, traffic shift, approval, or rollback occurs here. The service
    maps the Phase 6.5 evidence decision to PROMOTE/PAUSE/ABORT/INCONCLUSIVE.
    """
    try:
        return ProgressiveReleaseGateService(repository, prometheus).evaluate(
            deployment_run_id=deployment_run_id,
            start=start,
            end=end,
            target_percentage=target_percentage,
            baseline_deployment_run_id=baseline_deployment_run_id,
        )
    except InvalidAnalyticsWindowError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except InvalidProgressiveReleaseGateRequest as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
