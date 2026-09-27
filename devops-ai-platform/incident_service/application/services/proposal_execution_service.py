"""Controlled remediation execution of an approved proposal (Phase 6.2 §2).

Chain enforced here, in order, ALL before any repository side effect:

    load persisted proposal → canonical hash re-verified (stored + claim)
    → status/precondition gate → approval freshness (TTL)
    → deterministic patch policy re-validated against persisted content
    → authoritative target re-resolution (still DEPLOYED, same repo+SHA —
      never retarget to a newer deployment)
    → EXECUTING transition persisted (idempotent execution id)
    → existing RemediationOrchestrationService
        (isolated workspace → bounded patch → fixed validation profile →
         deterministic commit → remote verification → draft PR)
    → PR_CREATED persisted + execution evidence attached

Failure at any stage persists EXECUTION_FAILED + evidence for audit and
allows retry; PR_CREATED returns/reconciles the stored PR instead of
creating a second one. Concurrency is guarded by a process-local lock
PLUS the persisted status precondition — this storage layer does not
provide distributed locking (documented limitation, not claimed).
"""

from __future__ import annotations

import logging
import os
import re
import threading
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from incident_service.application.failures import (
    ApprovalPolicyError,
    ProposalAlreadyExecutingError,
    ProposalExecutionFailedError,
    ProposalIntegrityError,
    ProposalNotApprovedError,
    ProposalNotFoundError,
    ProposalPatchPolicyError,
    ProposalStaleError,
    RemediationValidationFailedError,
    TargetRevalidationError,
)
from incident_service.domain.entities.incident_evidence import IncidentEvidence
from incident_service.domain.repository_interface import IncidentRepositoryPort
from incident_service.application.services.hotfix_validation_service import (
    HotfixValidationService,
)
from incident_service.application.services.proposal_execution_policy import (
    execution_id_for,
    find_proposal,
    is_fresh,
    load_proposal_ttl_seconds,
    log_stage,
    rca_root_cause,
    utcnow,
    verify_proposal_integrity,
)
from incident_service.application.services.remediation_orchestration_service import (
    RemediationOrchestrationError,
)
from incident_service.application.services.remediation_target_binding import (
    resolve_authoritative_deployment_target,
)

logger = logging.getLogger("ProposalExecution")

EXECUTION_EVIDENCE_KIND = "remediation_execution"
VALIDATION_PROFILE_ENV = "REMEDIATION_VALIDATION_PROFILE"
DEFAULT_VALIDATION_PROFILE = "incident_service"

_LOCKS: Dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()

_SENSITIVE_PATTERNS = (
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE),
    re.compile(r"ghp_[A-Za-z0-9]+"),
    re.compile(r"github_pat_[A-Za-z0-9_]+"),
)


def _proposal_lock(key: str) -> threading.Lock:
    with _LOCKS_GUARD:
        if key not in _LOCKS:
            _LOCKS[key] = threading.Lock()
        return _LOCKS[key]


def _safe_reason(exc: BaseException) -> str:
    """Truncated, credential-redacted failure reason for audit evidence."""
    reason = str(exc) or exc.__class__.__name__
    for pattern in _SENSITIVE_PATTERNS:
        reason = pattern.sub("[REDACTED]", reason)
    return reason[:300]


def load_validation_profile() -> str:
    return os.getenv(VALIDATION_PROFILE_ENV, "").strip() or (
        DEFAULT_VALIDATION_PROFILE
    )


class ProposalExecutionService:
    def __init__(
        self,
        repository: IncidentRepositoryPort,
        orchestrator_factory: Callable[[], Any],
        ttl_seconds: Optional[float] = None,
        now: Callable[[], datetime] = utcnow,
        validation_profile: Optional[str] = None,
        validation_service: Optional[HotfixValidationService] = None,
    ):
        self.repository = repository
        self.orchestrator_factory = orchestrator_factory
        self.ttl_seconds = (
            load_proposal_ttl_seconds() if ttl_seconds is None else ttl_seconds
        )
        self.now = now
        self.validation_profile = (
            validation_profile
            if validation_profile is not None
            else load_validation_profile()
        )
        self.validation = validation_service or HotfixValidationService()

    # ------------------------------------------------------------------ #
    def execute(
        self,
        *,
        incident_id: str,
        proposal_id: str,
        proposal_hash: str,
        requested_by: str = "",
    ) -> Dict[str, Any]:
        incident = self.repository.get_incident_by_id(incident_id.strip())
        if incident is None:
            raise ProposalNotFoundError(f"Incident '{incident_id}' not found")

        lock = _proposal_lock(f"{incident.id}:{proposal_id}")
        with lock:
            # Re-read under the lock: state may have advanced while waiting.
            incident = self.repository.get_incident_by_id(incident.id)
            if incident is None:
                raise ProposalNotFoundError(f"Incident '{incident_id}' not found")
            proposal = find_proposal(incident, proposal_id)

            # Never-approved states fail fast on authorization (§5/§15):
            # nothing to verify a claim against yet, nothing may execute.
            if proposal.status in {"PROPOSED", "BLOCKED"}:
                raise ProposalNotApprovedError(
                    f"proposal status {proposal.status} cannot execute without "
                    "a valid approval"
                )

            # §5 hash binding — stored == reproducible == caller claim.
            verify_proposal_integrity(incident, proposal, proposal_hash)

            if proposal.status == "PR_CREATED":
                return self._reconcile(incident, proposal)

            self._assert_execution_preconditions(proposal)

            # §12 deterministic patch policy re-validated on persisted
            # content (a persisted proposal is trusted only as far as the
            # validator says it is valid).
            self._revalidate_patch_policy(incident, proposal)

            # §8 mandatory target revalidation immediately before side
            # effects — fail closed, never retarget.
            target = resolve_authoritative_deployment_target(incident)
            if target is None:
                raise TargetRevalidationError(
                    "no authoritative deployment evidence remains for this incident"
                )
            if (
                target["repository_name"] != proposal.repository
                or target["source_sha"] != (proposal.source_sha or "").lower()
            ):
                raise TargetRevalidationError(
                    "authoritative deployment target no longer matches the "
                    "approved proposal; execution aborted (no retargeting)"
                )
            log_stage(
                "target.revalidated",
                incident_id=incident.id,
                proposal_id=proposal.id,
                proposal_hash=proposal.proposal_hash,
                target_repository=target["repository_name"],
                source_sha=target["source_sha"],
                evidence_id=target["evidence_id"],
            )

            # EXECUTING transition persisted BEFORE side effects.
            proposal.execution_id = (
                proposal.execution_id
                or execution_id_for(proposal.id, proposal.proposal_hash)
            )
            proposal.execution_attempts = int(proposal.execution_attempts or 0) + 1
            proposal.status = "EXECUTING"
            proposal.executed_at = self.now()
            proposal.last_failure_stage = ""
            proposal.last_failure_reason = ""
            self.repository.save_incident(incident)
            attempt = proposal.execution_attempts
            log_stage(
                "execution.started",
                incident_id=incident.id,
                proposal_id=proposal.id,
                proposal_hash=proposal.proposal_hash,
                execution_id=proposal.execution_id,
                attempt=attempt,
                requested_by=requested_by or None,
                target_repository=proposal.repository,
                source_sha=proposal.source_sha,
            )

            stages: List[Tuple[str, Dict[str, Any]]] = []

            def stage_callback(stage: str, metadata: Dict[str, Any]) -> None:
                stages.append((stage, dict(metadata)))
                log_stage(
                    stage,
                    incident_id=incident.id,
                    proposal_id=proposal.id,
                    proposal_hash=proposal.proposal_hash,
                    execution_id=proposal.execution_id,
                    **{
                        key: value
                        for key, value in metadata.items()
                        if key != "stdout"
                    },
                )

            orchestrator = self.orchestrator_factory()
            try:
                result = orchestrator.execute(
                    incident_id=incident.id,
                    proposal=proposal,
                    repository_slug=proposal.repository,
                    validation_profile=self.validation_profile,
                    stage_callback=stage_callback,
                )
            except Exception as exc:
                typed = self._classify_failure(exc, stages)
                # §15/§23: failure stops here AND is persisted as audit
                # evidence — no commit/PR is claimed, retry stays possible.
                self._execution_failure(
                    incident, proposal, typed, stages, attempt,
                    requested_by, cause=exc,
                )
                raise typed from exc

            return self._persist_success(
                incident, proposal, result, stages, requested_by, attempt
            )

    # ------------------------------------------------------------------ #
    def _assert_execution_preconditions(self, proposal) -> None:
        if proposal.status == "APPROVED" or proposal.status == "EXECUTION_FAILED":
            pass  # retryable / executable
        elif proposal.status == "EXECUTING":
            raise ProposalAlreadyExecutingError(
                "proposal execution is already in flight or was interrupted; "
                "reconcile before retrying"
            )
        elif proposal.status in {"PROPOSED", "BLOCKED"}:
            raise ProposalNotApprovedError(
                f"proposal status {proposal.status} cannot execute without "
                "a valid approval"
            )
        else:
            raise ProposalNotApprovedError(
                f"proposal status {proposal.status} is not executable"
            )

        if not proposal.approved_by or not proposal.approval_hash:
            raise ProposalNotApprovedError("proposal carries no approval record")

        now = self.now()
        if not is_fresh(proposal.approved_at, self.ttl_seconds, now):
            raise ProposalStaleError(
                "approval is older than the execution freshness contract"
            )

    def _revalidate_patch_policy(self, incident, proposal) -> None:
        if not proposal.apply_verification_pass():
            raise ProposalPatchPolicyError(
                "persisted patch failed single-file unified-diff verification"
            )
        # Confidence is re-read from persisted RCA evidence (fail closed
        # when unavailable); it gates validation rules only — it is never
        # an authorization signal.
        root_cause = rca_root_cause(incident)
        if root_cause is None:
            raise ProposalPatchPolicyError(
                "persisted RCA evidence is unavailable for revalidation"
            )
        confidence = self._rca_confidence(incident)
        if confidence is None:
            raise ProposalPatchPolicyError(
                "RCA confidence evidence is unavailable for revalidation"
            )
        safe, violations = self.validation.validate_patch(proposal, confidence)
        if not safe:
            raise ProposalPatchPolicyError(
                "persisted patch failed deterministic policy: "
                + "; ".join(str(item) for item in violations)
            )

    @staticmethod
    def _rca_confidence(incident) -> Optional[float]:
        for item in incident.evidence:
            if item.id == f"rca-{incident.id}" and item.kind == "rca_result":
                try:
                    value = float(dict(item.payload or {}).get("confidence"))
                except (TypeError, ValueError):
                    return None
                if 0.0 <= value <= 1.0:
                    return value
                return None
        return None

    @staticmethod
    def _classify_failure(
        exc: BaseException,
        stages: List[Tuple[str, Dict[str, Any]]],
    ) -> BaseException:
        """Map an orchestration failure onto a typed, auditable error."""
        if isinstance(
            exc,
            (
                ProposalPatchPolicyError,
                ProposalStaleError,
                TargetRevalidationError,
                ProposalIntegrityError,
                ProposalNotApprovedError,
                ApprovalPolicyError,
            ),
        ):
            return exc
        if isinstance(exc, RemediationOrchestrationError) and (
            "validation failed" in str(exc) or "source SHA" in str(exc)
        ):
            return RemediationValidationFailedError(str(exc))

        name = exc.__class__.__name__
        if "Patch" in name:
            stage = "patch"
        elif "Validation" in name:
            stage = "validation"
        elif "Commit" in name:
            stage = "commit"
        elif "Publish" in name:
            stage = "publish"
        elif "GitHub" in name or "PullRequest" in name or name.startswith("PR"):
            stage = "pr"
        else:
            stage = stages[-1][0] if stages else "workspace"

        if isinstance(exc, (RemediationOrchestrationError, ValueError)):
            return ProposalExecutionFailedError(str(exc), stage=stage)
        # foreign/unexpected errors: redacted message, class recorded too
        return ProposalExecutionFailedError(_safe_reason(exc), stage=stage)

    # persistence helpers ------------------------------------------------ #
    def _persist_success(
        self, incident, proposal, result, stages, requested_by, attempt
    ) -> Dict[str, Any]:
        proposal.status = "PR_CREATED"
        proposal.commit_sha = result.commit_sha
        proposal.branch_name = result.branch_name
        proposal.pull_request_url = result.pull_request_url
        proposal.last_failure_stage = ""
        proposal.last_failure_reason = ""

        validation_meta = {
            "profile": self.validation_profile,
            "passed": bool(result.validation_result.passed),
            "steps": [
                {"name": step.name, "passed": step.passed}
                for step in result.validation_result.steps
            ],
        }
        evidence = self._execution_evidence(
            incident=incident,
            proposal=proposal,
            attempt=attempt,
            status="PR_CREATED",
            stages=stages,
            requested_by=requested_by,
            extra={
                "commit_sha": result.commit_sha,
                "branch_name": result.branch_name,
                "pull_request_url": result.pull_request_url,
                "validation": validation_meta,
            },
        )
        incident.attach_evidence(evidence)
        self.repository.save_incident(incident)
        log_stage(
            "execution.completed",
            incident_id=incident.id,
            proposal_id=proposal.id,
            proposal_hash=proposal.proposal_hash,
            execution_id=proposal.execution_id,
            commit_sha=result.commit_sha,
            pull_request_url=result.pull_request_url,
        )
        return {
            "incident_id": incident.id,
            "proposal": proposal.to_dict(),
            "execution_id": proposal.execution_id,
            "status": "PR_CREATED",
            "idempotent": False,
        }

    def _execution_failure(
        self, incident, proposal, exc, stages, attempt, requested_by, cause=None
    ) -> None:
        stage = getattr(exc, "stage", None) or (
            stages[-1][0] if stages else "workspace"
        )
        original = cause if cause is not None else exc
        proposal.status = "EXECUTION_FAILED"
        proposal.last_failure_stage = str(stage)
        proposal.last_failure_reason = _safe_reason(exc)
        evidence = self._execution_evidence(
            incident=incident,
            proposal=proposal,
            attempt=attempt,
            status="EXECUTION_FAILED",
            stages=stages,
            requested_by=requested_by,
            extra={
                "failed_stage": str(stage),
                "failure_type": original.__class__.__name__,
                "failure_reason": proposal.last_failure_reason,
            },
        )
        incident.attach_evidence(evidence)
        self.repository.save_incident(incident)
        log_stage(
            "execution.failed",
            incident_id=incident.id,
            proposal_id=proposal.id,
            proposal_hash=proposal.proposal_hash,
            execution_id=proposal.execution_id,
            failed_stage=str(stage),
            failure_type=exc.__class__.__name__,
            attempt=attempt,
        )

    @staticmethod
    def _execution_evidence(
        *, incident, proposal, attempt, status, stages, requested_by, extra
    ) -> IncidentEvidence:
        payload = {
            "schema": "devops.remediation.execution/1",
            "execution_id": proposal.execution_id,
            "attempt": attempt,
            "status": status,
            "incident_id": incident.id,
            "proposal_id": proposal.id,
            "proposal_hash": proposal.proposal_hash,
            "repository": proposal.repository,
            "source_sha": proposal.source_sha,
            "risk_class": proposal.risk_class,
            "approved_by": proposal.approved_by,
            "approved_at": (
                proposal.approved_at.isoformat() if proposal.approved_at else None
            ),
            "requested_by": requested_by or None,
            "stages": [
                {"stage": stage, "metadata": metadata}
                for stage, metadata in stages
            ],
            **extra,
        }
        return IncidentEvidence(
            id=f"exec-{proposal.execution_id}-a{attempt}",
            kind=EXECUTION_EVIDENCE_KIND,
            source="remediation-control-plane",
            payload=payload,
        )

    def _reconcile(self, incident, proposal) -> Dict[str, Any]:
        log_stage(
            "execution.reconciled",
            incident_id=incident.id,
            proposal_id=proposal.id,
            proposal_hash=proposal.proposal_hash,
            execution_id=proposal.execution_id,
            pull_request_url=proposal.pull_request_url,
        )
        return {
            "incident_id": incident.id,
            "proposal": proposal.to_dict(),
            "execution_id": proposal.execution_id,
            "status": "PR_CREATED",
            "idempotent": True,
        }
