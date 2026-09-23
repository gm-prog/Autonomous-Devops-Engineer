from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException

from application.dependencies import get_incident_repository
from domain.repository_interface import IncidentRepositoryPort
from application.services.rca_evidence_pack import RcaEvidencePackBuilder


router = APIRouter(prefix="/incidents", tags=["Active Incidents Controller"])


def _serialize_incident(incident) -> Dict[str, Any]:
    return {
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "context": incident.context,
        "created_at": incident.created_at.isoformat(),
        "evidence": [
            {
                "id": evidence.id,
                "kind": evidence.kind,
                "source": evidence.source,
                "observed_at": evidence.observed_at.isoformat(),
                "payload": dict(evidence.payload),
            }
            for evidence in incident.evidence
        ],
        "patch_proposals": [
            {
                "id": proposal.id,
                "target_filepath": proposal.target_filepath,
                "is_verified": proposal.is_verified,
                "generated_at": proposal.generated_at.isoformat(),
            }
            for proposal in incident.patch_proposals
        ],
    }


@router.get("", response_model=List[Dict[str, Any]])
def list_current_anomalies(
    repository: IncidentRepositoryPort = Depends(get_incident_repository),
):
    """Returns persisted incidents that are not in a terminal state."""
    return [_serialize_incident(item) for item in repository.get_active_incidents()]


@router.get("/{incident_id}", response_model=Dict[str, Any])
def get_incident(
    incident_id: str,
    repository: IncidentRepositoryPort = Depends(get_incident_repository),
):
    incident = repository.get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _serialize_incident(incident)


@router.get("/{incident_id}/rca/evidence", response_model=Dict[str, Any])
def get_rca_evidence_pack(
    incident_id: str,
    repository: IncidentRepositoryPort = Depends(get_incident_repository),
):
    """Returns the deterministic evidence package consumed by future RCA agents."""
    try:
        return RcaEvidencePackBuilder(repository).build(incident_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
