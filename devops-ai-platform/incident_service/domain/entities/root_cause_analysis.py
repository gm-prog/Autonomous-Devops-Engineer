"""Typed Root Cause Analysis result (Phase 6.1).

The RCA is a first-class domain object: every conclusion carries an
explicit confidence, the evidence ids it is grounded on, the
uncertainties the provider stated, and the methodology used. It is
persisted as ``kind="rca_result"`` incident evidence (existing
convention), so it survives reload without a schema change.

``to_payload()`` emits both ``evidence_refs`` (canonical field) and
``supporting_evidence_ids`` (legacy alias kept for backward-compatible
readers of the original agent RCA shape).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List

RCA_EVIDENCE_KIND = "rca_result"
RCA_PAYLOAD_SCHEMA = "devops.incident.rca/1"


@dataclass
class RootCauseAnalysis:
    """Evidence-grounded RCA conclusion for one incident."""

    id: str
    incident_id: str
    root_cause: str
    confidence: float
    contributing_factors: List[str] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    uncertainty: List[str] = field(default_factory=list)
    methodology: str = ""
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def to_payload(self) -> Dict[str, Any]:
        """Persisted representation (stored as incident evidence)."""
        return {
            "schema": RCA_PAYLOAD_SCHEMA,
            "rca_id": self.id,
            "incident_id": self.incident_id,
            "root_cause": self.root_cause,
            "confidence": self.confidence,
            "contributing_factors": list(self.contributing_factors),
            "evidence_refs": list(self.evidence_refs),
            # legacy alias: same list, original agent-field name
            "supporting_evidence_ids": list(self.evidence_refs),
            "uncertainty": list(self.uncertainty),
            "methodology": self.methodology,
            "generated_at": self.generated_at.isoformat(),
        }

    @classmethod
    def from_payload(cls, payload: Dict[str, Any]) -> "RootCauseAnalysis":
        """Rebuild from persisted evidence payload (best-effort structural
        read; validation already ran before persistence)."""
        generated_at = datetime.now(timezone.utc)
        raw_generated = payload.get("generated_at")
        if isinstance(raw_generated, str) and raw_generated:
            try:
                parsed = datetime.fromisoformat(raw_generated.replace("Z", "+00:00"))
                generated_at = (
                    parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
                )
            except ValueError:
                pass
        refs = payload.get("evidence_refs") or payload.get(
            "supporting_evidence_ids"
        ) or []
        return cls(
            id=str(payload.get("rca_id") or payload.get("id") or ""),
            incident_id=str(payload.get("incident_id") or ""),
            root_cause=str(payload.get("root_cause") or ""),
            confidence=float(payload.get("confidence") or 0.0),
            contributing_factors=[
                str(item) for item in payload.get("contributing_factors") or []
            ],
            evidence_refs=[str(item) for item in refs],
            uncertainty=[str(item) for item in payload.get("uncertainty") or []],
            methodology=str(payload.get("methodology") or ""),
            generated_at=generated_at,
        )
