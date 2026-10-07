"""Read-only operational evidence plane (Phase 8.4.2-G.1, §28/§29).

Three authenticated reads over the deterministic evidence substrate:

    GET /v1/incidents/{incident_id}/evidence
    GET /v1/evidence-packs/{evidence_pack_id}
    GET /v1/evidence/{evidence_id}

**There is intentionally no write surface here.** Historical evidence is
never replaced or deleted through the API: a correction is a new
observation produced by an adapter, which hashes differently and therefore
receives a new id. ``POST``/``PUT``/``PATCH``/``DELETE`` are simply not
registered, so they return 405 rather than being "protected by a role".

Authorization reuses the platform's existing gateway identity
(``verify_token`` → HS256 JWT). No new auth mechanism is introduced and no
endpoint is public. Evidence payloads can contain untrusted text from logs,
commit messages and Kubernetes labels; this plane returns them as inert
JSON data and never interprets them (§33).
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request

from shared_kernel.evidence import (
    EvidenceError,
    EvidenceErrorCode,
    EvidenceRepository,
    InMemoryEvidenceRepository,
)

from ..core.auth import verify_token
from .gateway_router import _rate_limit_or_429

logger = logging.getLogger("EvidencePlane")

router = APIRouter(prefix="/v1", tags=["Operational Evidence"])

#: Process-local repository. Replaced in tests (and by a future persistent
#: adapter) through ``app.dependency_overrides[get_evidence_repository]``.
_repository: EvidenceRepository = InMemoryEvidenceRepository()


def get_evidence_repository() -> EvidenceRepository:
    """Dependency seam for the evidence repository port."""
    return _repository


#: Predictable domain failures map to precise HTTP codes — never a generic
#: 500 and never a raw exception string (§37).
_STATUS_BY_CODE = {
    EvidenceErrorCode.EVIDENCE_NOT_FOUND: 404,
    EvidenceErrorCode.PACK_NOT_FOUND: 404,
    EvidenceErrorCode.INVALID_EVIDENCE: 422,
    EvidenceErrorCode.INVALID_PROVENANCE: 422,
    EvidenceErrorCode.INVALID_CORRELATION_KEY: 422,
    EvidenceErrorCode.INVALID_IDENTITY: 422,
    EvidenceErrorCode.EVIDENCE_TOO_LARGE: 413,
    EvidenceErrorCode.SCHEMA_VERSION_UNSUPPORTED: 409,
    EvidenceErrorCode.CORRELATION_POLICY_UNSUPPORTED: 409,
    EvidenceErrorCode.CONFLICTING_EVIDENCE: 409,
    EvidenceErrorCode.STALE_EVIDENCE: 409,
    EvidenceErrorCode.IMMUTABLE_EVIDENCE: 409,
}


def _raise_http(error: EvidenceError) -> None:
    status = _STATUS_BY_CODE.get(error.code, 422)
    logger.info("evidence request rejected: %s", error.code.value)
    raise HTTPException(status_code=status, detail=error.to_dict())


@router.get("/incidents/{incident_id}/evidence")
def read_incident_evidence(
    incident_id: str,
    request: Request,
    user: dict = Depends(verify_token),
    repository: EvidenceRepository = Depends(get_evidence_repository),
):
    """All stored evidence items bound to an incident, plus its packs."""
    _rate_limit_or_429(request)
    try:
        items = repository.list_items_for_incident(incident_id)
        packs = repository.list_packs_for_incident(incident_id)
    except EvidenceError as error:
        _raise_http(error)
    return {
        "incident_id": incident_id,
        "evidence_items": [item.to_dict() for item in items],
        "evidence_pack_ids": [pack.evidence_pack_id for pack in packs],
        "item_count": len(items),
    }


@router.get("/evidence-packs/{evidence_pack_id}")
def read_evidence_pack(
    evidence_pack_id: str,
    request: Request,
    user: dict = Depends(verify_token),
    repository: EvidenceRepository = Depends(get_evidence_repository),
):
    """A finalized, immutable evidence pack including its integrity block."""
    _rate_limit_or_429(request)
    try:
        pack = repository.get_pack(evidence_pack_id)
    except EvidenceError as error:
        _raise_http(error)
    return pack.to_dict()


@router.get("/evidence/{evidence_id}")
def read_evidence_item(
    evidence_id: str,
    request: Request,
    user: dict = Depends(verify_token),
    repository: EvidenceRepository = Depends(get_evidence_repository),
):
    """A single normalized observation with its full provenance."""
    _rate_limit_or_429(request)
    try:
        item = repository.get_item(evidence_id)
    except EvidenceError as error:
        _raise_http(error)
    return item.to_dict()
