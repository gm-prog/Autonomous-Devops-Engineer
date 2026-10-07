"""Incident → Evidence → RCA → Structured Remediation Proposal (Phase 6.1).

``ProposalGenerationService.generate`` is the complete proposal-only
pipeline. It NEVER executes anything: no workspace, no git, no GitHub, no
deployment, no remediation engine — the only writes are the incident
aggregate's own persistence (RCA evidence + proposal), exactly as §22
requires.

Pipeline (deterministic order):

1. load incident (typed :class:`IncidentNotFound`);
2. resolve the actionable target from THIS incident's persisted deployment
   evidence through :func:`resolve_authoritative_deployment_target`
   (Stage-5 gates: state DEPLOYED, canonical repo + full 40-hex SHA in one
   record, valid provenance). No trustworthy target → BLOCKED proposal with
   ``MISSING_DEPLOYED_TARGET_EVIDENCE`` — nothing is fabricated (§7);
3. build the evidence pack and run the RCA provider through
   :class:`RcaAnalyzerPort`; the typed result is schema-validated
   fail-closed (:func:`parse_rca_result`) and persisted as
   ``kind="rca_result"`` evidence;
4. turn the provider's optional remediation draft into a
   :class:`HotfixProposal`; target-path policy, single-file unified-diff
   verification (``apply_verification_pass``) and the deterministic
   ``HotfixValidationService`` rules decide pass/fail (§15);
5. classify risk deterministically (:func:`classify_proposal_risk`,
   §17), compute the canonical :func:`compute_proposal_hash` (§18) and
   persist the proposal (§19) — success upserts a verified proposal and
   moves the incident to ``RemediationProposed`` (§20); any policy or
   validation failure persists a non-executable ``BLOCKED`` proposal.

Structured single-line JSON logs (``rca.started`` / ``rca.completed`` /
``proposal.generated`` / ``proposal.validated`` / ``proposal.blocked``)
carry incident/correlation ids but never tokens, headers or full AI
outputs (§25/§26).
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, Sequence

from incident_service.application.failures import (
    IncidentNotFound,
    InvalidRcaResult,
    ProposalLifecycleConflict,
    ProposalPersistenceFailed,
    RcaGenerationFailed,
)
from incident_service.domain.entities.hotfix_proposal import HotfixProposal
from incident_service.domain.entities.root_cause_analysis import (
    RCA_EVIDENCE_KIND,
    RootCauseAnalysis,
)
from incident_service.domain.repository_interface import IncidentRepositoryPort
from incident_service.application.services.hotfix_validation_service import (
    HotfixValidationService,
)
from incident_service.application.services.rca_analyzer import (
    RcaAnalyzerPort,
    AgentServiceRcaAnalyzer,
    parse_rca_result,
)
from incident_service.application.services.rca_evidence_pack import (
    RcaEvidencePackBuilder,
)
from incident_service.application.services.remediation_target_binding import (
    resolve_authoritative_deployment_target,
)

logger = logging.getLogger("ProposalGeneration")

# Blocked reasons (stable machine-readable vocabulary, §7).
BLOCKED_MISSING_TARGET = "MISSING_DEPLOYED_TARGET_EVIDENCE"
BLOCKED_NO_DRAFT = "NO_ACTIONABLE_DRAFT"
BLOCKED_PATH_REJECTED = "TARGET_PATH_REJECTED"
BLOCKED_VALIDATION_FAILED = "PATCH_VALIDATION_FAILED"

_RISK_LEVELS = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def _log(event: str, **fields: Any) -> None:
    """Single-line structured log (existing telemetry style: greppable JSON)."""
    logger.info(json.dumps({"event": event, **fields}))


def classify_proposal_risk(
    *,
    confidence: float,
    uncertainty: Sequence[str],
    contributing_factors: Sequence[str],
    incident_severity: str,
    ai_suggested: Optional[str],
    validation_ok: bool,
    violations: Sequence[str] = (),
) -> str:
    """Deterministic risk classification (§17): LOW / MEDIUM / HIGH / BLOCKED.

    Derived only from proposal + evidence metadata — never from prose, and
    the result is metadata that can never trigger execution on its own.
    """
    if not validation_ok or violations:
        return "BLOCKED"
    level = 0
    if confidence < 0.90:
        level = max(level, 1)
    if uncertainty or contributing_factors:
        level = max(level, 1)
    if str(incident_severity or "").upper() == "CRITICAL":
        level = max(level, 2)
    if ai_suggested is not None:
        suggested = str(ai_suggested).upper()
        if suggested in _RISK_LEVELS:
            # an AI-proposed class only ever floors the deterministic score
            level = max(level, _RISK_LEVELS[suggested])
    return ("LOW", "MEDIUM", "HIGH")[level]


def compute_proposal_hash(
    *,
    incident_id: str,
    root_cause: str,
    evidence_refs: Sequence[str],
    repository: str,
    source_sha: str,
    file_paths: Sequence[str],
    patch: str,
    validation_plan: Sequence[str],
    risk_class: str,
) -> str:
    """Canonical proposal hash (§18).

    SHA-256 over a fixed-field canonical JSON document (sorted keys,
    compact separators, ASCII escaping) — dictionary order, timestamps and
    other volatile data never influence the digest.
    """
    canonical = json.dumps(
        {
            "incident_id": incident_id,
            "root_cause": root_cause,
            "evidence_refs": list(evidence_refs),
            "repository": repository,
            "source_sha": source_sha,
            "file_paths": list(file_paths),
            "patch": patch,
            "validation_plan": list(validation_plan),
            "risk_class": risk_class,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _proposal_id(incident_id: str) -> str:
    return f"proposal-{incident_id}"


class ProposalGenerationService:
    """Orchestrates evidence → RCA → structured proposal without side effects."""

    def __init__(
        self,
        repository: IncidentRepositoryPort,
        analyzer: Optional[RcaAnalyzerPort] = None,
        validation_service: Optional[HotfixValidationService] = None,
        pack_builder: Optional[RcaEvidencePackBuilder] = None,
    ):
        self.repository = repository
        self.analyzer = analyzer or AgentServiceRcaAnalyzer()
        self.validation = validation_service or HotfixValidationService()
        self.pack_builder = pack_builder or RcaEvidencePackBuilder(repository)

    # ------------------------------------------------------------------ #
    # public pipeline
    # ------------------------------------------------------------------ #
    def generate(self, incident_id: str) -> Dict[str, Any]:
        incident = self.repository.get_incident_by_id(incident_id.strip())
        if incident is None:
            raise IncidentNotFound(f"Incident '{incident_id}' not found")

        correlation = incident.id

        # Step 1: trusted target from THIS incident's deployment evidence.
        target = resolve_authoritative_deployment_target(incident)
        if target is None:
            proposal = self._persist_blocked(
                incident, BLOCKED_MISSING_TARGET, correlation
            )
            return {
                "incident_id": incident.id,
                "incident_status": incident.status,
                "proposal": proposal.to_dict(),
                "target": None,
                "rca": None,
            }

        # Step 2: evidence pack + schema-validated RCA.
        pack = self.pack_builder.build(incident.id)
        _log(
            "rca.started",
            incident_id=incident.id,
            correlation_id=correlation,
            evidence_count=len(incident.evidence),
        )
        try:
            raw_result = self.analyzer.analyze(pack)
            rca, draft = parse_rca_result(
                raw_result,
                incident_id=incident.id,
                valid_evidence_ids={item.id for item in incident.evidence},
            )
        except IncidentNotFound:
            raise
        except InvalidRcaResult:
            # schema fail-closed → typed 422, never reclassified as outage
            _log(
                "rca.failed",
                incident_id=incident.id,
                correlation_id=correlation,
                failure="InvalidRcaResult",
            )
            raise
        except RcaGenerationFailed:
            raise
        except Exception as exc:  # provider/config/network failures → typed
            _log(
                "rca.failed",
                incident_id=incident.id,
                correlation_id=correlation,
                failure=type(exc).__name__,
            )
            raise RcaGenerationFailed(
                "RCA provider could not produce a result"
            ) from exc

        _log(
            "rca.completed",
            incident_id=incident.id,
            correlation_id=correlation,
            confidence=rca.confidence,
            evidence_ref_count=len(rca.evidence_refs),
        )
        self._attach_rca(incident, rca)

        # Step 3: proposal draft → deterministic validation.
        if not draft:
            proposal = self._persist_blocked(
                incident,
                BLOCKED_NO_DRAFT,
                correlation,
                rca=rca,
                target=target,
            )
            return self._result(incident, proposal, target, rca)

        path = draft["target_file"].replace("\\", "/")
        if path.startswith("/") or ".." in path.split("/"):
            proposal = self._persist_blocked(
                incident,
                BLOCKED_PATH_REJECTED,
                correlation,
                rca=rca,
                target=target,
                draft=draft,
                detail={"target_filepath": draft["target_file"]},
            )
            return self._result(incident, proposal, target, rca)

        proposal = HotfixProposal(
            id=_proposal_id(incident.id),
            incident_id=incident.id,
            target_filepath=draft["target_file"],
            diff_patch_payload=draft["patch"],
            source_sha=target["source_sha"],
            repository=target["repository_name"],
            evidence_refs=list(rca.evidence_refs),
            validation_plan=list(draft["validation_plan"]),
        )

        path_ok = proposal.apply_verification_pass()
        safe, violations = self.validation.validate_patch(
            proposal, rca.confidence
        )
        validation_ok = bool(path_ok and safe)
        if not validation_ok:
            all_violations = list(violations)
            if not path_ok:
                all_violations.append(
                    "single-file unified diff verification failed "
                    "(multi-file, mismatched or malformed patch)"
                )
            proposal.is_verified = False
            proposal.status = "BLOCKED"
            proposal.blocked_reason = BLOCKED_VALIDATION_FAILED
            proposal.risk_class = classify_proposal_risk(
                confidence=rca.confidence,
                uncertainty=rca.uncertainty,
                contributing_factors=rca.contributing_factors,
                incident_severity=incident.severity,
                ai_suggested=draft.get("risk_class"),
                validation_ok=False,
                violations=all_violations,
            )
            proposal.proposal_hash = self._hash(proposal, rca)
            try:
                incident.attach_blocked_proposal(proposal)
            except ValueError as exc:
                raise ProposalLifecycleConflict(str(exc)) from exc
            self._save(incident)
            _log(
                "proposal.blocked",
                incident_id=incident.id,
                correlation_id=correlation,
                proposal_id=proposal.id,
                blocked_reason=BLOCKED_VALIDATION_FAILED,
                violation_count=len(all_violations),
            )
            result = self._result(incident, proposal, target, rca)
            result["validation_violations"] = all_violations
            return result

        # Step 4: deterministic risk + canonical hash + persistence.
        proposal.status = "PROPOSED"
        proposal.blocked_reason = ""
        proposal.risk_class = classify_proposal_risk(
            confidence=rca.confidence,
            uncertainty=rca.uncertainty,
            contributing_factors=rca.contributing_factors,
            incident_severity=incident.severity,
            ai_suggested=draft.get("risk_class"),
            validation_ok=True,
        )
        proposal.proposal_hash = self._hash(proposal, rca)

        # RCA evidence exists → the incident must reach RootCauseFound
        # through the explicit canonical chain before an executable
        # proposal may attach (Phase 8 §4). Idempotent when the caller
        # already ran /rca (evidence dedup + guarded no-op transitions).
        self._attach_rca(incident, rca)
        try:
            incident.upsert_remediation_proposal(proposal)
        except ValueError as exc:
            raise ProposalLifecycleConflict(str(exc)) from exc
        self._save(incident)
        _log(
            "proposal.generated",
            incident_id=incident.id,
            correlation_id=correlation,
            proposal_id=proposal.id,
            risk_class=proposal.risk_class,
            proposal_hash=proposal.proposal_hash,
        )
        _log(
            "proposal.validated",
            incident_id=incident.id,
            correlation_id=correlation,
            proposal_id=proposal.id,
            validation_rules=len(self.validation.rules),
        )
        return self._result(incident, proposal, target, rca)


    def _save(self, incident) -> None:
        """Persistence failure → typed §25 error (never a silent drop).
        Concurrency conflicts are THEIR OWN truth (Phase 8.1): a stale
        writer must surface as a 409 conflict, not a generic 503."""
        from incident_service.application.failures import (
            IncidentConcurrencyConflict,
        )

        try:
            self.repository.save_incident(incident)
        except IncidentConcurrencyConflict as exc:
            # bounded ids only — structured truth for the losing writer
            _log(
                "proposal.regeneration_conflict",
                incident_id=str(getattr(incident, "id", ""))[:64],
                expected_version=int(getattr(incident, "version", 0)),
            )
            raise
        except Exception as exc:
            raise ProposalPersistenceFailed(
                "proposal could not be persisted"
            ) from exc

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _hash(proposal: HotfixProposal, rca: RootCauseAnalysis) -> str:
        return compute_proposal_hash(
            incident_id=proposal.incident_id,
            root_cause=rca.root_cause,
            evidence_refs=rca.evidence_refs,
            repository=proposal.repository,
            source_sha=proposal.source_sha or "",
            file_paths=[proposal.target_filepath] if proposal.target_filepath else [],
            patch=proposal.diff_patch_payload,
            validation_plan=proposal.validation_plan,
            risk_class=proposal.risk_class,
        )

    def _attach_rca(self, incident, rca: RootCauseAnalysis) -> None:
        evidence = incident_service_evidence_from_rca(rca)
        incident.attach_evidence(evidence)
        # Explicit canonical chain (Phase 8 §4): each promotion is its own
        # guarded domain transition — no skipped intermediates, no silent
        # coercion, idempotent when already reached.
        if incident.status == "Raised":
            incident.move_to_triage()
        if incident.status == "Triage":
            incident.begin_investigation()
        if incident.status == "Investigating":
            incident.mark_root_cause_found()

    def _persist_blocked(
        self,
        incident,
        reason: str,
        correlation: str,
        *,
        rca: Optional[RootCauseAnalysis] = None,
        target: Optional[Dict[str, Any]] = None,
        draft: Optional[Dict[str, Any]] = None,
        detail: Optional[Dict[str, Any]] = None,
    ) -> HotfixProposal:
        """Persist a non-executable BLOCKED proposal (§7/§20)."""
        proposal = HotfixProposal(
            id=_proposal_id(incident.id),
            incident_id=incident.id,
            target_filepath=(draft or {}).get("target_file", ""),
            diff_patch_payload=(draft or {}).get("patch", ""),
            # trusted values only — absent target means empty, never invented
            source_sha=(target or {}).get("source_sha", ""),
            repository=(target or {}).get("repository_name", ""),
            evidence_refs=list(rca.evidence_refs) if rca else [],
            validation_plan=list((draft or {}).get("validation_plan", [])),
            risk_class="BLOCKED",
            status="BLOCKED",
            blocked_reason=reason,
        )
        proposal.is_verified = False
        # Blocked proposals are hashed too (§18 fields, honest empty RCA
        # parts when the pipeline stopped before analysis).
        proposal.proposal_hash = compute_proposal_hash(
            incident_id=proposal.incident_id,
            root_cause=rca.root_cause if rca else "",
            evidence_refs=list(rca.evidence_refs) if rca else [],
            repository=proposal.repository,
            source_sha=proposal.source_sha,
            file_paths=[proposal.target_filepath] if proposal.target_filepath else [],
            patch=proposal.diff_patch_payload,
            validation_plan=proposal.validation_plan,
            risk_class="BLOCKED",
        )
        try:
            incident.attach_blocked_proposal(proposal)
        except ValueError as exc:
            raise ProposalLifecycleConflict(str(exc)) from exc
        self._save(incident)
        _log(
            "proposal.blocked",
            incident_id=incident.id,
            correlation_id=correlation,
            proposal_id=proposal.id,
            blocked_reason=reason,
            **(detail or {}),
        )
        return proposal

    @staticmethod
    def _result(incident, proposal, target, rca) -> Dict[str, Any]:
        return {
            "incident_id": incident.id,
            "incident_status": incident.status,
            "proposal": proposal.to_dict(),
            "target": target,
            "rca": rca.to_payload() if rca else None,
        }


def incident_service_evidence_from_rca(rca: RootCauseAnalysis):
    """Typed RCA → persisted ``kind="rca_result"`` evidence (§19)."""
    from incident_service.domain.entities.incident_evidence import IncidentEvidence

    return IncidentEvidence(
        id=rca.id,
        kind=RCA_EVIDENCE_KIND,
        source="agent-service",
        observed_at=rca.generated_at,
        payload=rca.to_payload(),
    )
