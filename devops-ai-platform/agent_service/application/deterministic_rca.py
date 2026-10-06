"""Deterministic RCA adapter for staging/E2E runs (Phase 8.4 §6).

Activated ONLY when ``E2E_DETERMINISTIC_RCA=true`` is set in the agent
service environment. Outside that mode the RCA endpoint fails closed
(no provider is configured) — the deterministic adapter is never
silently substituted for a production provider.

The adapter still executes inside the agent-service process, consumes
the real evidence pack built by the incident service, and returns a
schema-valid RCA result whose evidence citations are drawn exclusively
from the pack's own timeline ids (dangling or foreign citations are
impossible by construction).
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

DETERMINISTIC_RCA_ENV = "E2E_DETERMINISTIC_RCA"

# Fixed, known conclusion for the synthetic staging scenario — the E2E
# report asserts against this exact string.
DETERMINISTIC_ROOT_CAUSE = (
    "E2E deterministic root cause: monitored checkout-service metric "
    "exceeded the configured danger threshold"
)

_MAX_CITED_EVIDENCE_IDS = 10


def deterministic_rca_enabled(env: Dict[str, str] | None = None) -> bool:
    source = os.environ if env is None else env
    return str(source.get(DETERMINISTIC_RCA_ENV, "")).strip().lower() in {
        "1",
        "true",
        "yes",
    }


def _timeline_evidence_ids(evidence_pack: Dict[str, Any]) -> List[str]:
    evidence = evidence_pack.get("evidence")
    if not isinstance(evidence, dict):
        raise ValueError("evidence_pack.evidence must be an object")
    timeline = evidence.get("timeline")
    if not isinstance(timeline, list):
        raise ValueError("evidence_pack.evidence.timeline must be a list")
    ids: List[str] = []
    for item in timeline:
        if not isinstance(item, dict):
            raise ValueError("evidence_pack timeline entries must be objects")
        evidence_id = str(item.get("evidence_id") or "").strip()
        if not evidence_id:
            raise ValueError("evidence_pack timeline entries require evidence_id")
        if evidence_id not in ids:
            ids.append(evidence_id)
    if not ids:
        raise ValueError("evidence_pack timeline contains no evidence ids")
    return ids


def deterministic_analyze(evidence_pack: Any) -> Dict[str, Any]:
    """Produce a schema-valid RCA result grounded in the actual pack."""
    if not isinstance(evidence_pack, dict):
        raise ValueError("evidence_pack must be an object")

    cited = _timeline_evidence_ids(evidence_pack)[:_MAX_CITED_EVIDENCE_IDS]

    return {
        "root_cause": DETERMINISTIC_ROOT_CAUSE,
        "confidence": 1.0,
        "evidence_refs": list(cited),
        # legacy alias emitted alongside the canonical field
        "supporting_evidence_ids": list(cited),
        "contributing_factors": [
            "deterministic E2E RCA adapter (E2E_DETERMINISTIC_RCA=true)"
        ],
        "uncertainty": [],
        "methodology": "e2e-deterministic-adapter/1",
    }
