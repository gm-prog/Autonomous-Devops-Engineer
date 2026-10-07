"""Application-level RCA provider abstraction and schema validation (§10/§11).

``RcaAnalyzerPort`` is the ONLY place an AI/LLM is plugged into the
incident aggregate — the aggregate itself never talks to a provider.
``AgentServiceRcaAnalyzer`` adapts the existing ``RcaAgentClient`` HTTP
boundary (agent-service); tests inject deterministic fakes through the
same port.

Every provider response is schema-constrained by ``parse_rca_result``:
types, confidence bounds, list/string lengths and — critically —
``evidence_refs`` must exist on THIS incident (§9). Malformed output
raises :class:`InvalidRcaResult` and never becomes operational input.

An optional ``remediation_draft`` block lets the provider propose the
patch content (§14) — but never the trusted repository, source SHA or
authorization identity: those come only from deployment evidence.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set, Tuple

from incident_service.domain.entities.root_cause_analysis import (
    RootCauseAnalysis,
)
from incident_service.application.failures import InvalidRcaResult

logger = logging.getLogger("RcaAnalyzer")

_MAX_STRING = 4000
_MAX_LIST = 50
_MAX_LIST_STRING = 500

#: keys accepted inside the provider's optional remediation draft.
#: Deliberately excludes repository/source_sha/identity fields (§14).
DRAFT_KEYS = {"target_file", "patch", "validation_plan", "risk_class"}
_RISK_CLASSES = {"LOW", "MEDIUM", "HIGH"}


class RcaAnalyzerPort(ABC):
    """Provider boundary: evidence pack in, raw structured RCA out."""

    @abstractmethod
    def analyze(self, evidence_pack: Dict[str, Any]) -> Dict[str, Any]:
        """Return a structured RCA result mapping (see parse_rca_result)."""


class AgentServiceRcaAnalyzer(RcaAnalyzerPort):
    """Production adapter over the existing agent-service HTTP client."""

    def __init__(self, client=None):
        # client=None → construct lazily so import/config errors surface
        # at call time (typed as RcaGenerationFailed by the orchestrator).
        self._client = client

    @property
    def client(self):
        if self._client is None:
            from incident_service.infrastructure.agent.rca_client import (
                RcaAgentClient,
            )

            self._client = RcaAgentClient()
        return self._client

    def analyze(self, evidence_pack: Dict[str, Any]) -> Dict[str, Any]:
        return self.client.analyze(evidence_pack)


def _bounded_string(value: Any, field: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise InvalidRcaResult(f"RCA field '{field}' must be a string")
    text = value.strip()
    if not text and not allow_empty:
        raise InvalidRcaResult(f"RCA field '{field}' must not be empty")
    if len(text) > _MAX_STRING:
        raise InvalidRcaResult(f"RCA field '{field}' exceeds {_MAX_STRING} chars")
    return text


def _bounded_string_list(value: Any, field: str, *, required: bool) -> List[str]:
    if value is None:
        if required:
            raise InvalidRcaResult(f"RCA field '{field}' is required")
        return []
    if not isinstance(value, list):
        raise InvalidRcaResult(f"RCA field '{field}' must be a list of strings")
    if len(value) > _MAX_LIST:
        raise InvalidRcaResult(f"RCA field '{field}' exceeds {_MAX_LIST} items")
    items: List[str] = []
    for item in value:
        text = _bounded_string(item, field)
        if len(text) > _MAX_LIST_STRING:
            raise InvalidRcaResult(
                f"RCA field '{field}' items exceed {_MAX_LIST_STRING} chars"
            )
        items.append(text)
    return items


def parse_rca_result(
    result: Any,
    *,
    incident_id: str,
    valid_evidence_ids: Set[str],
) -> Tuple[RootCauseAnalysis, Optional[Dict[str, Any]]]:
    """Validate raw provider output into a typed RCA (+ optional draft).

    Returns ``(RootCauseAnalysis, remediation_draft_or_None)``.
    Raises :class:`InvalidRcaResult` on any schema violation — including
    dangling or foreign evidence references (fail closed).
    """
    if not isinstance(result, dict):
        raise InvalidRcaResult("RCA provider result must be a JSON object")

    root_cause = _bounded_string(result.get("root_cause"), "root_cause")

    confidence = result.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise InvalidRcaResult("RCA 'confidence' must be a number")
    confidence = float(confidence)
    if not 0.0 <= confidence <= 1.0:
        raise InvalidRcaResult("RCA 'confidence' must be within [0, 1]")

    contributing = _bounded_string_list(
        result.get("contributing_factors"), "contributing_factors", required=False
    )

    # legacy alias supported: original agent shape used supporting_evidence_ids
    raw_refs = result.get("evidence_refs")
    if raw_refs is None:
        raw_refs = result.get("supporting_evidence_ids")
    refs = _bounded_string_list(raw_refs, "evidence_refs", required=True)
    if not refs:
        raise InvalidRcaResult("RCA must cite at least one evidence reference")
    unknown = [ref for ref in refs if ref not in valid_evidence_ids]
    if unknown:
        # dangling or foreign references are rejected outright
        raise InvalidRcaResult(
            "RCA cites evidence references that do not belong to this incident"
        )

    uncertainty = _bounded_string_list(
        result.get("uncertainty"), "uncertainty", required=False
    )

    raw_methodology = result.get("methodology")
    if raw_methodology is None:
        # honest default: record which provider produced the analysis
        methodology = "agent-service-analysis (methodology not stated)"
    else:
        methodology = _bounded_string(raw_methodology, "methodology")

    rca = RootCauseAnalysis(
        id=f"rca-{incident_id}",
        incident_id=incident_id,
        root_cause=root_cause,
        confidence=confidence,
        contributing_factors=contributing,
        evidence_refs=refs,
        uncertainty=uncertainty,
        methodology=methodology,
    )

    draft: Optional[Dict[str, Any]] = None
    if "remediation_draft" in result and result["remediation_draft"] is not None:
        draft = _parse_draft(result["remediation_draft"])
    return rca, draft


def _parse_draft(raw: Any) -> Dict[str, Any]:
    """Validate the provider's optional remediation draft (fail closed)."""
    if not isinstance(raw, dict):
        raise InvalidRcaResult("remediation_draft must be a JSON object")
    unknown = set(raw) - DRAFT_KEYS
    if unknown:
        # providers may not smuggle repository/SHA/identity decisions (§14)
        raise InvalidRcaResult(
            f"remediation_draft contains unsupported fields: {sorted(unknown)}"
        )
    target_file = _bounded_string(raw.get("target_file"), "remediation_draft.target_file")
    patch = raw.get("patch")
    if not isinstance(patch, str) or not patch.strip():
        raise InvalidRcaResult("remediation_draft.patch must be a non-empty string")
    if len(patch) > 262144:
        raise InvalidRcaResult("remediation_draft.patch exceeds size limit")
    validation_plan = _bounded_string_list(
        raw.get("validation_plan"),
        "remediation_draft.validation_plan",
        required=True,
    )
    if not validation_plan:
        raise InvalidRcaResult(
            "remediation_draft.validation_plan must contain at least one step"
        )
    risk = raw.get("risk_class")
    if risk is None:
        risk_normalized = None
    else:
        if not isinstance(risk, str) or risk.upper() not in _RISK_CLASSES:
            raise InvalidRcaResult(
                "remediation_draft.risk_class must be LOW, MEDIUM or HIGH"
            )
        risk_normalized = risk.upper()
    return {
        "target_file": target_file,
        "patch": patch,
        "validation_plan": validation_plan,
        "risk_class": risk_normalized,
    }
