"""Phase 6.4 — change intelligence & release verification foundation (read-only).

Connects a known deployment/change to authoritative operational evidence
and produces a deterministic release-health assessment — the decision /
evidence foundation between Phase 6.3 (understand) and Phase 6.5
(control). This module NEVER mutates anything: no rollback, no approval,
no traffic shifting, no remediation.

**Change ↔ incident correlation (not causation).** A link exists only on
durable identifiers, never on timestamp proximity:

1. ``deployment_run_id`` — an incident's ``kind="deployment_run"``
   evidence payload records the exact deployment run id (strong basis);
2. ``repository_source_sha`` — exact ``repository_name`` + exact deployed
   ``source_revision.head_sha`` matching the authoritative record for
   that run (supporting basis, weaker; never invented when the exact-id
   record is absent).

The authoritative record for a run = the latest exact-id evidence record
by ``(observed_at, evidence_id)`` (same deterministic winner rule as
``resolve_authoritative_deployment_target``). Linked incidents are
*associated* / *observed after* the deployment in the evidence — this is
a correlation/attribution record, NOT proof that the deployment caused
the incident.

**Observation window.** Reuses the Phase 6.3 contract verbatim: caller-
supplied UTC half-open ``[start, end)``, at most 31 days, validated by
the same service validator (single authority, no drift). The window
selects the incident cohort; deployment-run evidence attached to those
in-window incidents defines what this assessment can know (cohort
semantics — child evidence is analyzed for in-window incidents even when
the child timestamp itself falls outside the window).

**Signals** (durable sources only — the authoritative record's payload
fields captured by the deployment evidence collector, plus in-cohort
incident/proposal records): deployment ``state`` (deployment state-machine
vocabulary), ``health_check_status`` (PASS/FAIL/BLOCKED/TIMEOUT),
``rollback_status`` (PASS/FAIL), platform ``provenance`` validity
(``_provenance_satisfies_record`` — reused from remediation binding,
never reimplemented), target SHA / repository identity, linked-incident
counts/severity, and durable proposal outcomes
(``EXECUTION_FAILED``) for linked incidents.

**Decision rules** (explicit, typed, bounded, evaluated in fixed
declaration order — precedence FAILED > DEGRADED > INCONCLUSIVE >
HEALTHY; identical persisted inputs + identical window ⇒ identical
JSON):

* FAILED — any of: authoritative state in
  {VALIDATION_FAILED, DRY_RUN_FAILED, DEPLOYMENT_FAILED, ROLLBACK_FAILED}
  → ``deployment_state_failed``; health check ``FAIL`` →
  ``deployment_health_check_failed``; rollback ``FAIL`` →
  ``deployment_rollback_failed``.
* DEGRADED (only when no FAILED rule fired) — state in
  {ROLLBACK_PENDING, ROLLED_BACK} → ``deployment_state_degraded``;
  ≥1 linked incident whose durable status is NOT terminal
  (the same {Fixed, Resolved} terminal vocabulary as active-incident
  reads) → ``linked_unresolved_incidents``; ≥1 linked incident with a
  durable ``EXECUTION_FAILED`` proposal → ``linked_remediation_failed``.
  Terminal-status linked incidents still count in the impact record but
  do not by themselves indicate ongoing deterioration (otherwise every
  known change — whose record necessarily lives on an incident — could
  never be HEALTHY).
* INCONCLUSIVE (only when neither FAILED nor DEGRADED fired) — required
  evidence missing/untrustworthy: ``target_sha_missing``,
  ``repository_missing``, ``deployment_state_missing``,
  ``deployment_state_unrecognized``, ``deployment_state_nonterminal``,
  ``health_check_missing``, ``health_check_unavailable`` (BLOCKED,
  TIMEOUT or unknown value), ``rollback_status_unrecognized``,
  ``provenance_missing``, ``provenance_invalid``. Missing evidence is
  never HEALTHY; malformed evidence is never FAILED without an
  independent authoritative failure field.
* HEALTHY — none of the above fired: state DEPLOYED, health PASS,
  valid provenance describing THIS record, identity complete, rollback
  absent-or-PASS, no unresolved linked incident and no failed linked
  remediation (reason ``all_required_evidence_healthy``).

Failed-deploy records carry provenance whose ``state`` gate is DEPLOYED
only — ``provenance_invalid`` may therefore be recorded on non-DEPLOYED
records; it is a data-quality fact for the signal, not a tamper claim,
and never drives FAILED by itself (§10: malformed ≠ FAILED).

**Data quality.** Every response carries the full fixed reason
vocabulary with counts (zero unless fired) — same no-fabrication
philosophy as Phase 6.3. **Unsupported** (explicitly out of scope:
never attempted here): live Prometheus queries, ML/LLM decisions,
probabilistic scoring, causal proof, canary/rollout control, automatic
rollback, deployment mutation of any kind.
"""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from incident_service.application.services.operational_analytics_service import (
    InvalidAnalyticsWindowError,
    OperationalAnalyticsService,
    _aware_utc,  # shared UTC-normalization helper (single authority)
)
from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.domain.repository_interface import IncidentRepositoryPort
from incident_service.application.services.remediation_target_binding import (
    _provenance_satisfies_record,  # reused identity guarantee (Stage 5)
)

# Evidence kind written by the deployment evidence collector.
DEPLOYMENT_EVIDENCE_KIND = "deployment_run"

# Deployment state vocabulary — copied verbatim from
# deployment_service/domain/value_objects/deployment_state.py (bounded
# context: the incident context references the vocabulary as strings,
# exactly as the evidence collector stores it; no cross-context import).
_SUCCESS_STATE = "DEPLOYED"
_FAILED_STATES = frozenset(
    {"VALIDATION_FAILED", "DRY_RUN_FAILED", "DEPLOYMENT_FAILED", "ROLLBACK_FAILED"}
)
_DEGRADED_STATES = frozenset({"ROLLBACK_PENDING", "ROLLED_BACK"})
_NONTERMINAL_STATES = frozenset(
    {
        "CREATED",
        "VALIDATING",
        "VALIDATED",
        "DRY_RUNNING",
        "DRY_RUN_PASSED",
        "AWAITING_APPROVAL",
        "APPROVED",
        "DEPLOYING",
        "HEALTH_CHECKING",
    }
)
_KNOWN_STATES = (
    _FAILED_STATES | _DEGRADED_STATES | _NONTERMINAL_STATES | {_SUCCESS_STATE}
)

# Health-check vocabulary (deployment_service health_check_service).
_HEALTH_FAIL = "FAIL"
_HEALTH_GREEN = "PASS"
_HEALTH_UNAVAILABLE = frozenset({"BLOCKED", "TIMEOUT"})
# Rollback vocabulary (deployment_service deployment_engine).
_ROLLBACK_GREEN = "PASS"
_ROLLBACK_FAIL = "FAIL"

# Fixed data-quality reason vocabulary — every counter always present.
_DQ_REASONS: Tuple[Tuple[str, str], ...] = (
    ("correlation", "deployment_evidence_malformed"),
    ("signals", "target_sha_missing"),
    ("signals", "repository_missing"),
    ("signals", "deployment_state_missing"),
    ("signals", "deployment_state_unrecognized"),
    ("signals", "deployment_state_nonterminal"),
    ("signals", "health_check_missing"),
    ("signals", "health_check_unavailable"),
    ("signals", "rollback_status_unrecognized"),
    ("signals", "provenance_missing"),
    ("signals", "provenance_invalid"),
)

# Fired-gap tokens, evaluated for INCONCLUSIVE in this fixed order.
_GAP_ORDER: Tuple[str, ...] = tuple(
    reason for scope, reason in _DQ_REASONS if scope == "signals"
)

_FAILED_STATE_REASON = "deployment_state_failed"
_FAILED_HEALTH_REASON = "deployment_health_check_failed"
_FAILED_ROLLBACK_REASON = "deployment_rollback_failed"
_DEGRADED_STATE_REASON = "deployment_state_degraded"
_DEGRADED_INCIDENTS_REASON = "linked_unresolved_incidents"
_DEGRADED_REMEDIATION_REASON = "linked_remediation_failed"
_HEALTHY_REASON = "all_required_evidence_healthy"

# Terminal incident statuses — same vocabulary the active-incident read
# filters out (get_active_incidents excludes {Fixed, Resolved}).
_TERMINAL_INCIDENT_STATUSES = frozenset({"Fixed", "Resolved"})

_FAILED_ORDER: Tuple[str, ...] = (
    _FAILED_STATE_REASON,
    _FAILED_HEALTH_REASON,
    _FAILED_ROLLBACK_REASON,
)
_DEGRADED_ORDER: Tuple[str, ...] = (
    _DEGRADED_STATE_REASON,
    _DEGRADED_INCIDENTS_REASON,
    _DEGRADED_REMEDIATION_REASON,
)

_LINK_BASIS_RUN_ID = "deployment_run_id"
_LINK_BASIS_REPO_SHA = "repository_source_sha"

# Incident severity scale used for ``highest_incident_severity``.
# Unknown severities rank below the known scale, ordered alphabetically.
_SEVERITY_RANK: Tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


class ReleaseDecision(str, Enum):
    """The four allowed release-health decisions (no other values)."""

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


def _dq_key(scope: str, reason: str) -> str:
    return f"{scope}:{reason}"


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _severity_key(severity: str) -> Tuple[int, str]:
    rank = _SEVERITY_RANK.index(severity) if severity in _SEVERITY_RANK else len(_SEVERITY_RANK)
    return (rank, severity)


@dataclass(frozen=True)
class ChangeIncidentLink:
    """One incident linked to the change on durable identifiers only."""

    incident_id: str
    severity: str
    status: str
    created_at: str
    link_basis: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "incident_id": self.incident_id,
            "severity": self.severity,
            "status": self.status,
            "created_at": self.created_at,
            "link_basis": self.link_basis,
        }


@dataclass(frozen=True)
class ChangeImpact:
    """Deliverable A — evidence-backed change/outcome correlation record."""

    deployment_run_id: str
    repository_name: Optional[str]
    source_sha: Optional[str]
    artifact_hash: Optional[str]
    plan_hash: Optional[str]
    linked_incidents: Tuple[ChangeIncidentLink, ...]
    incident_count: int
    highest_incident_severity: Optional[str]
    first_incident_at: Optional[str]
    assessment_window: Dict[str, str]
    link_basis: str
    data_quality: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "deployment_run_id": self.deployment_run_id,
            "repository_name": self.repository_name,
            "source_sha": self.source_sha,
            "artifact_hash": self.artifact_hash,
            "plan_hash": self.plan_hash,
            "linked_incidents": [item.to_dict() for item in self.linked_incidents],
            "incident_count": self.incident_count,
            "highest_incident_severity": self.highest_incident_severity,
            "first_incident_at": self.first_incident_at,
            "assessment_window": dict(self.assessment_window),
            "link_basis": self.link_basis,
            "data_quality": {
                "exclusions": [dict(item) for item in self.data_quality["exclusions"]]
            },
        }


@dataclass(frozen=True)
class Signals:
    """Deterministic signal set consumed by the rule evaluator."""

    deployment_state: Optional[str]
    health_check_status: Optional[str]
    rollback_status: Optional[str]
    provenance_valid: Optional[bool]
    target_sha: Optional[str]
    repository_name: Optional[str]
    linked_incident_count: int
    linked_unresolved_count: int
    highest_incident_severity: Optional[str]
    linked_remediation_failed_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "deployment_state": self.deployment_state,
            "health_check_status": self.health_check_status,
            "rollback_status": self.rollback_status,
            "provenance_valid": self.provenance_valid,
            "target_sha": self.target_sha,
            "repository_name": self.repository_name,
            "linked_incident_count": self.linked_incident_count,
            "linked_unresolved_count": self.linked_unresolved_count,
            "highest_incident_severity": self.highest_incident_severity,
            "linked_remediation_failed_count": self.linked_remediation_failed_count,
        }


@dataclass(frozen=True)
class ReleaseHealthAssessment:
    """Deliverable B — typed, read-only release-health assessment."""

    deployment_run_id: str
    target_sha: Optional[str]
    observation_window: Dict[str, str]
    change_impact: ChangeImpact
    signals: Signals
    decision: ReleaseDecision
    reasons: Tuple[str, ...]
    data_quality: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "deployment_run_id": self.deployment_run_id,
            "target_sha": self.target_sha,
            "observation_window": dict(self.observation_window),
            "change_impact": self.change_impact.to_dict(),
            "signals": self.signals.to_dict(),
            "decision": self.decision.value,
            "reasons": list(self.reasons),
            "data_quality": {
                "incidents_considered": self.data_quality["incidents_considered"],
                "exclusions": [
                    dict(item) for item in self.data_quality["exclusions"]
                ],
            },
        }


class ChangeIntelligenceService:
    """Window-validated, read-only change correlation + health rules."""

    def __init__(self, repository: IncidentRepositoryPort) -> None:
        self._repository = repository

    def assess(
        self, *, deployment_run_id: str, start: datetime, end: datetime
    ) -> Dict[str, Any]:
        run_id = _text(deployment_run_id)
        if not run_id:
            raise LookupError("deployment_run_id must not be empty")
        # Single window authority: reuse the Phase 6.3 validator verbatim
        # (UTC, half-open [start, end), <= 31 days).
        window_start, window_end = OperationalAnalyticsService._validate_window(
            start, end
        )
        window = {
            "start": window_start.isoformat(),
            "end": window_end.isoformat(),
            "timezone": "UTC",
            "max_days": 31,
        }

        # ONE bounded read (incident window query + one bulk evidence
        # query — no per-incident or per-record query loop).
        incidents = self._repository.list_incidents_in_window(
            window_start, window_end
        )

        exclusions: Counter = Counter()
        impact, authoritative, linked = self._correlate(
            run_id, incidents, window, exclusions
        )
        if authoritative is None:
            raise LookupError(
                f"no deployment-run evidence for '{run_id}' within the "
                "observation window"
            )

        signals, fired_gaps, fired_failed, fired_degraded = self._observe(
            authoritative, linked, incidents, exclusions
        )
        decision, reasons = _evaluate(fired_failed, fired_degraded, fired_gaps)

        exclusion_rows = [
            {
                "scope": scope,
                "reason": reason,
                "count": int(exclusions.get(_dq_key(scope, reason), 0)),
            }
            for scope, reason in _DQ_REASONS
        ]
        correlation_rows = [
            dict(item) for item in exclusion_rows if item["scope"] == "correlation"
        ]
        # Phase 6.3-shaped data-quality block: incidents_considered +
        # fixed exclusion vocabulary (always fully present).
        data_quality = {
            "incidents_considered": len(incidents),
            "exclusions": exclusion_rows,
        }
        assessment = ReleaseHealthAssessment(
            deployment_run_id=run_id,
            target_sha=signals.target_sha,
            observation_window=window,
            change_impact=ChangeImpact(
                deployment_run_id=run_id,
                repository_name=signals.repository_name,
                source_sha=signals.target_sha,
                artifact_hash=authoritative.get("artifact_hash")
                if isinstance(authoritative.get("artifact_hash"), str)
                else None,
                plan_hash=authoritative.get("plan_hash")
                if isinstance(authoritative.get("plan_hash"), str)
                else None,
                linked_incidents=linked,
                incident_count=len(linked),
                highest_incident_severity=signals.highest_incident_severity,
                first_incident_at=linked[0].created_at if linked else None,
                assessment_window=window,
                link_basis=_LINK_BASIS_RUN_ID,
                data_quality={"exclusions": correlation_rows},
            ),
            signals=signals,
            decision=decision,
            reasons=reasons,
            data_quality=data_quality,
        )
        return assessment.to_dict()

    # ------------------------------------------------------------------ #
    # Correlation (Deliverable A)
    # ------------------------------------------------------------------ #
    def _correlate(
        self,
        run_id: str,
        incidents: Sequence[IncidentAggregate],
        window: Dict[str, str],
        exclusions: Counter,
    ) -> Tuple[ChangeImpact, Optional[Dict[str, Any]], Tuple[ChangeIncidentLink, ...]]:
        """Return (placeholder impact, authoritative record, linked links).

        The full ``ChangeImpact`` needs signal fields, so it is assembled
        in ``assess`` — this helper only resolves identity + links.
        """
        # Pass 1 — exact deployment_run_id records (strong basis).
        candidates: List[Tuple[Tuple[Any, ...], Dict[str, Any]]] = []
        for incident in incidents:
            for item in incident.evidence:
                if item.kind != DEPLOYMENT_EVIDENCE_KIND:
                    continue
                payload = item.payload
                if not isinstance(payload, Mapping):
                    exclusions[_dq_key("correlation", "deployment_evidence_malformed")] += 1
                    continue
                if _text(payload.get("deployment_run_id")) == "":
                    exclusions[_dq_key("correlation", "deployment_evidence_malformed")] += 1
                    continue
                if _text(payload.get("deployment_run_id")) == run_id:
                    candidates.append(
                        ((_aware_utc(item.observed_at), str(item.id)), dict(payload))
                    )
        if not candidates:
            return (
                ChangeImpact(
                    deployment_run_id=run_id,
                    repository_name=None,
                    source_sha=None,
                    artifact_hash=None,
                    plan_hash=None,
                    linked_incidents=(),
                    incident_count=0,
                    highest_incident_severity=None,
                    first_incident_at=None,
                    assessment_window=window,
                    link_basis=_LINK_BASIS_RUN_ID,
                    data_quality={"exclusions": []},
                ),
                None,
                (),
            )

        # Deterministic winner: latest by (observed_at, evidence_id) —
        # the same rule as resolve_authoritative_deployment_target.
        _, authoritative = max(candidates, key=lambda entry: entry[0])

        authoritative_repo = _text(authoritative.get("repository_name"))
        authoritative_sha = ""
        revision = authoritative.get("source_revision")
        if isinstance(revision, Mapping):
            authoritative_sha = _text(revision.get("head_sha"))

        # Pass 2 — link incidents on exact identifiers only.
        links: List[Tuple[str, ChangeIncidentLink]] = []
        for incident in incidents:
            basis: Optional[str] = None
            for item in incident.evidence:
                if item.kind != DEPLOYMENT_EVIDENCE_KIND:
                    continue
                payload = item.payload
                if not isinstance(payload, Mapping):
                    continue  # malformed already counted in pass 1
                if _text(payload.get("deployment_run_id")) == run_id:
                    basis = _LINK_BASIS_RUN_ID
                    break
                if authoritative_repo and authoritative_sha:
                    candidate_repo = _text(payload.get("repository_name"))
                    candidate_sha = ""
                    candidate_revision = payload.get("source_revision")
                    if isinstance(candidate_revision, Mapping):
                        candidate_sha = _text(candidate_revision.get("head_sha"))
                    if (
                        candidate_repo == authoritative_repo
                        and candidate_sha == authoritative_sha
                    ):
                        basis = _LINK_BASIS_REPO_SHA  # supporting, weaker
            if basis is None:
                continue
            links.append(
                (
                    str(incident.id),
                    ChangeIncidentLink(
                        incident_id=str(incident.id),
                        severity=str(incident.severity),
                        status=str(incident.status),
                        created_at=_aware_utc(incident.created_at).isoformat(),
                        link_basis=basis,
                    ),
                )
            )
        links.sort(key=lambda entry: (entry[1].created_at, entry[0]))
        linked = tuple(link for _, link in links)
        return (None, authoritative, linked)  # impact assembled in assess

    # ------------------------------------------------------------------ #
    # Signal extraction + rule inputs (Deliverable B)
    # ------------------------------------------------------------------ #
    @staticmethod
    def _observe(
        authoritative: Mapping[str, Any],
        linked: Tuple[ChangeIncidentLink, ...],
        incidents: Sequence[IncidentAggregate],
        exclusions: Counter,
    ) -> Tuple[Signals, Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]:
        fired_gaps: Counter = Counter()
        fired_failed: List[str] = []
        fired_degraded: List[str] = []

        def gap(reason: str) -> None:
            fired_gaps[reason] += 1
            exclusions[_dq_key("signals", reason)] += 1

        # identity
        revision = authoritative.get("source_revision")
        target_sha = (
            _text(revision.get("head_sha")) if isinstance(revision, Mapping) else ""
        )
        if not target_sha:
            gap("target_sha_missing")
        repository_name = _text(authoritative.get("repository_name"))
        if not repository_name:
            gap("repository_missing")

        # deployment state
        state = authoritative.get("state")
        state_text = _text(state) if state is not None else ""
        if state is None or state_text == "":
            gap("deployment_state_missing")
        elif state_text not in _KNOWN_STATES:
            gap("deployment_state_unrecognized")
        elif state_text in _FAILED_STATES:
            fired_failed.append(_FAILED_STATE_REASON)
        elif state_text in _DEGRADED_STATES:
            fired_degraded.append(_DEGRADED_STATE_REASON)
        elif state_text in _NONTERMINAL_STATES:
            gap("deployment_state_nonterminal")

        # health check
        health = authoritative.get("health_check_status")
        health_text = _text(health) if health is not None else ""
        if health is None or health_text == "":
            gap("health_check_missing")
        elif health_text == _HEALTH_FAIL:
            fired_failed.append(_FAILED_HEALTH_REASON)
        elif health_text != _HEALTH_GREEN:
            # BLOCKED / TIMEOUT / unknown values: no trustworthy check.
            gap("health_check_unavailable")

        # rollback
        rollback = authoritative.get("rollback_status")
        rollback_text = _text(rollback) if rollback is not None else ""
        if rollback_text and rollback_text not in {_ROLLBACK_GREEN, _ROLLBACK_FAIL}:
            gap("rollback_status_unrecognized")
        elif rollback_text == _ROLLBACK_FAIL:
            fired_failed.append(_FAILED_ROLLBACK_REASON)

        # provenance validity (reused Stage-5 identity guarantee)
        provenance = authoritative.get("provenance")
        if provenance is None:
            provenance_valid: Optional[bool] = None
            gap("provenance_missing")
        else:
            provenance_valid = bool(_provenance_satisfies_record(dict(authoritative)))
            if not provenance_valid:
                gap("provenance_invalid")

        # linked incidents + durable remediation outcomes (cohort records)
        linked_ids = {link.incident_id for link in linked}
        unresolved = sum(
            1
            for link in linked
            if link.status not in _TERMINAL_INCIDENT_STATUSES
        )
        if unresolved:
            fired_degraded.append(_DEGRADED_INCIDENTS_REASON)
        failed_remediation = 0
        for incident in incidents:
            if str(incident.id) not in linked_ids:
                continue
            if any(
                str(proposal.status) == "EXECUTION_FAILED"
                for proposal in incident.patch_proposals
            ):
                failed_remediation += 1
        if failed_remediation:
            fired_degraded.append(_DEGRADED_REMEDIATION_REASON)

        highest: Optional[str] = None
        if linked:
            highest = min(
                (link.severity for link in linked), key=_severity_key
            )

        signals = Signals(
            deployment_state=state_text or None,
            health_check_status=health_text or None,
            rollback_status=rollback_text or None,
            provenance_valid=provenance_valid,
            target_sha=target_sha or None,
            repository_name=repository_name or None,
            linked_incident_count=len(linked),
            linked_unresolved_count=unresolved,
            highest_incident_severity=highest,
            linked_remediation_failed_count=failed_remediation,
        )
        # Fixed-order token lists (rule declaration order ⇒ deterministic).
        failed_tuple = tuple(token for token in _FAILED_ORDER if token in fired_failed)
        degraded_tuple = tuple(
            token for token in _DEGRADED_ORDER if token in fired_degraded
        )
        gap_tuple = tuple(token for token in _GAP_ORDER if token in fired_gaps)
        return signals, gap_tuple, failed_tuple, degraded_tuple


def _evaluate(
    fired_failed: Tuple[str, ...],
    fired_degraded: Tuple[str, ...],
    fired_gaps: Tuple[str, ...],
) -> Tuple[ReleaseDecision, Tuple[str, ...]]:
    """Fixed precedence: FAILED > DEGRADED > INCONCLUSIVE > HEALTHY.

    Order-independent: results depend only on which rule sets fired.
    """
    if fired_failed:
        return ReleaseDecision.FAILED, fired_failed
    if fired_degraded:
        return ReleaseDecision.DEGRADED, fired_degraded
    if fired_gaps:
        return ReleaseDecision.INCONCLUSIVE, fired_gaps
    return ReleaseDecision.HEALTHY, (_HEALTHY_REASON,)


__all__ = [
    "ChangeImpact",
    "ChangeIncidentLink",
    "ChangeIntelligenceService",
    "DEPLOYMENT_EVIDENCE_KIND",
    "InvalidAnalyticsWindowError",
    "ReleaseDecision",
    "ReleaseHealthAssessment",
    "Signals",
]
