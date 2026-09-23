from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException

from application.dependencies import get_incident_repository
from domain.repository_interface import IncidentRepositoryPort
from domain.entities.incident_evidence import IncidentEvidence
from infrastructure.agent.rca_client import RcaAgentClient, RcaAgentUnavailable
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


@router.post("/{incident_id}/rca", response_model=Dict[str, Any])
def investigate_root_cause(
    incident_id: str,
    repository: IncidentRepositoryPort = Depends(get_incident_repository),
):
    """Build evidence, invoke the RCA agent, then persist the validated RCA."""
    try:
        pack = RcaEvidencePackBuilder(repository).build(incident_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    try:
        result = RcaAgentClient().analyze(pack)
    except (RcaAgentUnavailable, ValueError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    valid_ids = {item["evidence_id"] for item in pack["evidence"]["timeline"]}
    cited_ids = result.get("supporting_evidence_ids", [])
    if not isinstance(cited_ids, list) or not all(item in valid_ids for item in cited_ids):
        raise HTTPException(status_code=502, detail="RCA agent returned invalid evidence references")

    incident = repository.get_incident_by_id(incident_id.strip())
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.attach_evidence(IncidentEvidence(
        id=f"rca-{incident.id}",
        kind="rca_result",
        source="agent-service",
        payload=result,
    ))
    incident.move_to_triage()
    incident.mark_root_cause_found()
    repository.save_incident(incident)

    return {
        "incident_id": incident.id,
        "status": incident.status,
        "rca": result,
        "evidence_pack_version": pack["pack_version"],
    }
