"""Deterministic RCA adapter for staging/E2E runs (Phase 8.4 §6, 8.4.1).

Activated ONLY when ``E2E_DETERMINISTIC_RCA=true`` is set in the agent
service environment. Outside that mode the RCA endpoint fails closed
(no provider is configured) — the deterministic adapter is never
silently substituted for a production provider.

Three information classes stay strictly separated (Phase 8.4.1 §4):

* authoritative deployment identity (repository / source SHA / hashes)
  is NEVER produced here — it flows only from deployment evidence
  through the target-binding step of proposal generation;
* evidence-derived facts are validated from the real evidence pack
  built by the incident service (:func:`validate_e2e_signal`) — the
  conclusion is returned ONLY after the pack proves the synthetic
  breach semantics (service, metric, numeric value > threshold);
* fixture-owned remediation intent is a fixed, code-owned constant
  (:data:`E2E_TARGET_FILE` / :data:`DETERMINISTIC_PATCH` / ...) that
  the incoming request can never influence.

Citations are drawn exclusively from the pack's own timeline ids
(dangling or foreign citations are impossible by construction).
"""

from __future__ import annotations

import json
import logging
import math
import os
from typing import Any, Dict, List

logger = logging.getLogger("DeterministicRca")

DETERMINISTIC_RCA_ENV = "E2E_DETERMINISTIC_RCA"

# Fixed, known conclusion for the synthetic staging scenario — the E2E
# report asserts against this exact string. Returned ONLY after
# validate_e2e_signal() has proven the breach from the evidence pack.
DETERMINISTIC_ROOT_CAUSE = (
    "E2E deterministic root cause: monitored checkout-service metric "
    "exceeded the configured danger threshold"
)

# --------------------------------------------------------------------------
# Synthetic scenario contract (Phase 8.4.1 §6) — exactly one controlled
# staging incident: service `checkout-service`, metric `cpu_percent`,
# breached against the monitoring service's configured danger limit
# (MONITORING_DANGER_LIMIT, default 90.0, operator ">"). The numeric
# threshold is read from the evidence pack — the real monitoring path is
# its single source of truth; this adapter never duplicates the config.
# --------------------------------------------------------------------------
E2E_SCENARIO_SERVICE = "checkout-service"
E2E_SCENARIO_METRIC = "cpu_percent"

# --------------------------------------------------------------------------
# Fixture-owned remediation intent (Phase 8.4.1 §10–§12) — code-owned,
# deterministic, single-file. The disposable fixture repository's
# src/service_config.py initially reads SERVICE_NAME = "checkout-service"
# (tests/fixtures/e2e_fixture_repo/); the patch makes exactly one
# reviewable change. Repository/SHA/branch/command authority is NEVER
# accepted from the request or from this adapter.
# --------------------------------------------------------------------------
E2E_TARGET_FILE = "src/service_config.py"
E2E_FIXTURE_INITIAL_SERVICE_NAME = "checkout-service"
E2E_PATCHED_SERVICE_NAME = "checkout-service-remediated"

DETERMINISTIC_PATCH = (
    "--- a/src/service_config.py\n"
    "+++ b/src/service_config.py\n"
    "@@ -1 +1 @@\n"
    f"-SERVICE_NAME = \"{E2E_FIXTURE_INITIAL_SERVICE_NAME}\"\n"
    f"+SERVICE_NAME = \"{E2E_PATCHED_SERVICE_NAME}\"\n"
)

# Human-readable, fixed validation intent recorded on the proposal. The
# executable assertion is policy-owned by the incident service's
# `e2e_fixture` validation profile — validation_plan entries are
# metadata, never commands.
DETERMINISTIC_VALIDATION_PLAN = [
    (
        "e2e-fixture-target-assertion: src/service_config.py exists and "
        "SERVICE_NAME == 'checkout-service-remediated'"
    ),
]

DETERMINISTIC_RISK_CLASS = "LOW"

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


def _finite_float(value: Any, field: str) -> float:
    """Parse a numeric evidence field, fail closed on anything unusable."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError(f"evidence {field} must be numeric")
    if isinstance(value, str):
        try:
            parsed = float(value.strip())
        except ValueError as exc:
            raise ValueError(f"evidence {field} must be numeric") from exc
    else:
        parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"evidence {field} must be finite")
    return parsed


def validate_e2e_signal(evidence_pack: Dict[str, Any]) -> Dict[str, Any]:
    """Fail-closed semantic inspection of the real evidence pack (§7).

    Proves the synthetic breach BEFORE any conclusion is returned:
    structure, timeline ids, exactly one ``checkout-service`` /
    ``cpu_percent`` monitoring signal, numeric observed value and
    configured danger threshold, and ``observed_value > threshold``.
    Every failure raises ``ValueError`` (→ 422 at the RCA boundary).
    """
    if not isinstance(evidence_pack, dict):
        raise ValueError("evidence_pack must be an object")

    timeline_ids = _timeline_evidence_ids(evidence_pack)

    signals = evidence_pack.get("signals")
    if not isinstance(signals, dict):
        raise ValueError("evidence_pack.signals must be an object")
    breaches = signals.get("threshold_breaches")
    if not isinstance(breaches, list) or not breaches:
        raise ValueError("evidence_pack.signals.threshold_breaches must be a non-empty list")

    matches: List[Dict[str, Any]] = []
    for entry in breaches:
        if not isinstance(entry, dict):
            raise ValueError("threshold_breach entries must be objects")
        evidence_id = str(entry.get("evidence_id") or "").strip()
        if not evidence_id:
            raise ValueError("threshold_breach entries require evidence_id")
        if evidence_id not in timeline_ids:
            raise ValueError(
                "threshold_breach evidence_id must belong to the pack timeline"
            )
        if (
            entry.get("service") == E2E_SCENARIO_SERVICE
            and entry.get("metric") == E2E_SCENARIO_METRIC
        ):
            matches.append(entry)

    if not matches:
        raise ValueError(
            "evidence pack does not contain the expected checkout-service "
            "cpu_percent monitoring signal"
        )
    if len(matches) > 1:
        # ambiguity fails closed — the staging scenario is exactly one
        # controlled breach (duplicate/redelivered events dedupe to one
        # evidence id upstream).
        raise ValueError("evidence pack contains ambiguous scenario signals")

    signal = matches[0]
    # Operator semantics belong to the scenario contract (§47): the
    # monitoring producer emits ">"; a contradictory operator (e.g. "<")
    # can never justify the deterministic conclusion even when the raw
    # numbers happen to satisfy value > threshold.
    operator = signal.get("operator")
    if not isinstance(operator, str) or operator.strip() != ">":
        raise ValueError(
            "evidence operator does not match the scenario breach direction"
        )
    value = _finite_float(signal.get("value"), "observed value")
    threshold = _finite_float(signal.get("threshold"), "danger threshold")

    # the conclusion may only be claimed when the numeric relationship
    # actually holds — a presence-only ThreatThresholdExceededEvent is
    # not enough (§7).
    if not value > threshold:
        raise ValueError(
            "observed value does not exceed the configured danger threshold"
        )

    return {
        "evidence_id": signal["evidence_id"],
        "service": E2E_SCENARIO_SERVICE,
        "metric": E2E_SCENARIO_METRIC,
        "value": value,
        "threshold": threshold,
    }


def deterministic_analyze(evidence_pack: Any) -> Dict[str, Any]:
    """Produce a schema-valid RCA + bounded remediation draft, grounded
    in the actual pack. The root cause and draft are returned only after
    semantic validation succeeds (§9)."""
    if not isinstance(evidence_pack, dict):
        raise ValueError("evidence_pack must be an object")

    # 1. semantic validation first — no conclusion without proof
    signal = validate_e2e_signal(evidence_pack)

    # 2. citations: pack timeline ids only, signal always cited
    timeline_ids = _timeline_evidence_ids(evidence_pack)
    ordered = [signal["evidence_id"]] + [
        evidence_id
        for evidence_id in timeline_ids
        if evidence_id != signal["evidence_id"]
    ]
    cited = ordered[:_MAX_CITED_EVIDENCE_IDS]

    result = {
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
        # fixture-owned intent only — never repository/SHA/branch/command
        "remediation_draft": {
            "target_file": E2E_TARGET_FILE,
            "patch": DETERMINISTIC_PATCH,
            "validation_plan": list(DETERMINISTIC_VALIDATION_PLAN),
            "risk_class": DETERMINISTIC_RISK_CLASS,
        },
    }

    # structured, bounded log (§29): ids/counts/validated identities only —
    # never the patch, the full pack, tokens or request payload.
    logger.info(
        json.dumps(
            {
                "event": "e2e_deterministic_rca.completed",
                "incident_id": str(
                    (evidence_pack.get("incident") or {}).get("id", "")
                )[:64],
                "evidence_count": len(timeline_ids),
                "validated_service": signal["service"],
                "validated_metric": signal["metric"],
                "evidence_ref_count": len(cited),
            }
        )
    )
    return result
