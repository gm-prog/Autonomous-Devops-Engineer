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
from pydantic import BaseModel

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
from incident_service.application.services.progressive_rollout_stage_service import (
    InvalidRolloutStageRequest,
    ProgressiveRolloutStageService,
    RolloutStageConflict,
)
from incident_service.application.services.rollout_plan_service import (
    InvalidRolloutPlanRequest,
    RolloutPlanConflict,
    RolloutPlanService,
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


@router.get("/{deployment_run_id}/gate/history", response_model=Dict[str, Any])
def get_change_release_gate_history(
    deployment_run_id: str,
    limit: int = Query(50, description="Maximum persisted evaluations to return (1-100)"),
    repository: IncidentRepositoryPort = Depends(get_incident_repository),
):
    """Return durable gate-analysis history; stale rows are informational only."""
    try:
        return ProgressiveReleaseGateService(repository, prometheus=None).history(
            deployment_run_id=deployment_run_id, limit=limit
        )
    except InvalidProgressiveReleaseGateRequest as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/{deployment_run_id}/rollout-state", response_model=Dict[str, Any])
def get_change_rollout_state(
    deployment_run_id: str,
    repository: IncidentRepositoryPort = Depends(get_incident_repository),
):
    """Phase 6.6.2 — durable progressive-rollout stage state (read-only).

    Bounded lookup of the single authoritative stage record; a missing
    record fails closed (404) and is never inferred from telemetry,
    timestamps or history.
    """
    try:
        return ProgressiveRolloutStageService(repository).read(deployment_run_id)
    except InvalidRolloutStageRequest as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


class RolloutStageTransitionRequest(BaseModel):
    """Minimum control inputs for a stage transition. Identity fields
    (deployment run id from the path, authoritative repository and
    source SHA server-side, evaluation contents) are never accepted
    from the caller beyond this exact binding."""

    expected_percentage: int
    target_percentage: int
    evaluation_id: str
    source_sha: str


@router.post(
    "/{deployment_run_id}/rollout-state/transition",
    response_model=Dict[str, Any],
)
def post_change_rollout_state_transition(
    deployment_run_id: str,
    request: RolloutStageTransitionRequest,
    repository: IncidentRepositoryPort = Depends(get_incident_repository),
):
    """Phase 6.6.2 — explicit stage-transition command.

    Changes ONLY the durable rollout-stage record (5% → 25% → 50% →
    100%, PAUSE/ABORT, terminal states). The transition is bound to the
    exact fresh gate evaluation id presented by the caller. No traffic
    shifting, Kubernetes mutation, rollback, approval, or deployment
    execution occurs here. Malformed input → 422, missing stage or
    evaluation → 404, illegal/stale/conflicting transition → 409.
    """
    try:
        return ProgressiveRolloutStageService(repository).transition(
            deployment_run_id=deployment_run_id,
            expected_percentage=request.expected_percentage,
            target_percentage=request.target_percentage,
            evaluation_id=request.evaluation_id,
            source_sha=request.source_sha,
        )
    except InvalidRolloutStageRequest as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RolloutStageConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{deployment_run_id}/rollout-plan", response_model=Dict[str, Any])
def get_change_rollout_plan(
    deployment_run_id: str,
    evaluation_id: str = Query(
        ..., description="Exact fresh gate-evaluation id the plan is bound to"
    ),
    requested_percentage: int = Query(
        ..., description="Requested next exposure: 5, 25, 50, or 100"
    ),
    source_sha: str = Query(
        ..., description="Exact authoritative 40-hex lowercase source SHA"
    ),
    repository: IncidentRepositoryPort = Depends(get_incident_repository),
):
    """Phase 6.7.1 — read-only traffic preflight (plan ONLY).

    Returns rollout identity, durable stage, the exact fresh gate
    evaluation, observed traffic state, requested target, preflight
    status (READY/NO_OP/BLOCKED/CONFLICT/INCONCLUSIVE) and reasons.
    This endpoint never mutates traffic: no kubectl, no provider write,
    no rollout-stage change. Missing state/evaluation → 404, conflicts →
    409, malformed input → 422.
    """
    try:
        return RolloutPlanService(repository).plan(
            deployment_run_id=deployment_run_id,
            evaluation_id=evaluation_id,
            requested_percentage=requested_percentage,
            source_sha=source_sha,
        )
    except InvalidRolloutPlanRequest as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RolloutPlanConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
