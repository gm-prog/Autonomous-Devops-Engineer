from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List

from domain.repository_interface import IncidentRepositoryPort


class RcaEvidencePackBuilder:
    """Builds a deterministic evidence package for future RCA agents."""

    def __init__(self, repository: IncidentRepositoryPort):
        self.repository = repository

    def build(self, incident_id: str) -> Dict[str, Any]:
        normalized_id = incident_id.strip()
        if not normalized_id:
            raise ValueError("incident_id must not be empty")

        incident = self.repository.get_incident_by_id(normalized_id)
        if incident is None:
            raise LookupError("Incident not found")

        evidence = sorted(
            incident.evidence,
            key=lambda item: (item.observed_at, item.id),
        )

        sources = Counter(item.source for item in evidence)
        kinds = Counter(item.kind for item in evidence)

        threshold_breaches: List[Dict[str, Any]] = []
        deployment_runs: List[Dict[str, Any]] = []

        for item in evidence:
            payload = dict(item.payload)

            if item.kind == "threshold_breach":
                threshold_breaches.append(
                    {
                        "evidence_id": item.id,
                        "observed_at": item.observed_at.isoformat(),
                        "service": payload.get("service"),
                        "metric": payload.get("metric"),
                        "value": payload.get("value"),
                        "threshold": payload.get("threshold"),
                        "operator": payload.get("operator"),
                        "severity": payload.get("severity"),
                        "breach_count": payload.get("breach_count"),
                    }
                )

            elif item.kind == "deployment_run":
                deployment_runs.append(
                    {
                        "evidence_id": item.id,
                        "observed_at": item.observed_at.isoformat(),
                        "deployment_run_id": payload.get("deployment_run_id"),
                        "repository_id": payload.get("repository_id"),
                        "repository_name": payload.get("repository_name"),
                        "source_revision": payload.get("source_revision") or {},
                        "state": payload.get("state"),
                        "created_at": payload.get("created_at"),
                        "updated_at": payload.get("updated_at"),
                        "artifact_hash": payload.get("artifact_hash"),
                        "plan_hash": payload.get("plan_hash"),
                        "health_check_status": payload.get("health_check_status"),
                        "rollback_status": payload.get("rollback_status"),
                        "error": payload.get("error"),
                    }
                )

        timeline = [
            {
                "evidence_id": item.id,
                "kind": item.kind,
                "source": item.source,
                "observed_at": item.observed_at.isoformat(),
            }
            for item in evidence
        ]

        return {
            "pack_version": "1.0",
            "incident": {
                "id": incident.id,
                "title": incident.title,
                "severity": incident.severity,
                "status": incident.status,
                "created_at": incident.created_at.isoformat(),
            },
            "evidence": {
                "count": len(evidence),
                "sources": dict(sources),
                "kinds": dict(kinds),
                "timeline": timeline,
            },
            "signals": {
                "threshold_breaches": threshold_breaches,
                "deployment_runs": deployment_runs,
            },
        }
