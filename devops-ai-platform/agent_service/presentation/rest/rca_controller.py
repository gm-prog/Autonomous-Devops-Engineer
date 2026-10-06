"""Internal RCA contract endpoint (Phase 8.4 §5).

``POST /api/internal/analyze-rca`` is the exact boundary the incident
service's ``RcaAgentClient`` already calls. It is an internal
service-to-service route: the compose topology does not publish the
agent service to the host, so it is reachable only on the private
service network (covered by the platform compose boundary test).

Contract:

* request body: ``{"evidence_pack": {...}}``
* response: schema-valid RCA JSON (``root_cause``, ``confidence``,
  ``evidence_refs`` citing only ids present in the pack, ...)
* ``E2E_DETERMINISTIC_RCA=true`` → deterministic adapter (staging/E2E)
* any other configuration → 503 fail-closed (no provider configured;
  the deterministic adapter is never silently substituted)
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, HTTPException

from ...application.deterministic_rca import (
    deterministic_analyze,
    deterministic_rca_enabled,
)

router = APIRouter(prefix="/api/internal", tags=["Internal RCA"])


@router.post("/analyze-rca")
def analyze_rca(payload: Dict[str, Any]):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="request body must be a JSON object")

    evidence_pack = payload.get("evidence_pack")
    if not isinstance(evidence_pack, dict):
        raise HTTPException(
            status_code=422,
            detail="evidence_pack object is required",
        )

    if not deterministic_rca_enabled():
        # Fail closed: no production RCA provider is configured on this
        # boundary. E2E must opt in explicitly via E2E_DETERMINISTIC_RCA.
        raise HTTPException(
            status_code=503,
            detail="no RCA provider configured (E2E_DETERMINISTIC_RCA not enabled)",
        )

    try:
        return deterministic_analyze(evidence_pack)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
