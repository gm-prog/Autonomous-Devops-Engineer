"""Controlled remediation execution with durable coordination (Phase 6.2/6.2.1).

Pre-side-effect gates (every attempt, including recovery):

    load persisted proposal → canonical hash re-verified (stored + claim +
    approval binding) → status/lease gate → approval freshness (TTL)
    → deterministic patch policy re-check → authoritative target
    re-resolution (never retarget) → remote inspection when a durable
    resume cursor exists → ATOMIC durable lease claim (storage CAS —
    the process-local lock is only a performance optimization)
    → bounded side effects through RemediationOrchestrationService with
    durable stage persistence at every verified boundary
    → PR_CREATED persisted atomically with lease release + evidence.

Recovery never blindly repeats external mutations: a resumable durable
cursor (commit_sha + stage >= COMMIT_CREATED) is reconciled against the
real remote before deciding resume-vs-restart, and draft PR creation is
always preceded by PR discovery. Model: at-least-once attempts +
deterministic idempotency + reconciliation + fail-closed conflicts —
never claimed as exactly-once.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from incident_service.application.failures import (
    ApprovalPolicyError,
    ExecutionLeaseUnavailable,
    ExistingPullRequestConflict,
    ProposalAlreadyExecutingError,
    ProposalExecutionFailedError,
    ProposalIntegrityError,
    ProposalNotApprovedError,
    ProposalNotFoundError,
    ProposalPatchPolicyError,
    ProposalStaleError,
    RemoteBranchConflict,
    RemoteReconciliationFailed,
    RemediationValidationFailedError,
    TargetRevalidationError,
)
from incident_service.domain.entities.incident_evidence import IncidentEvidence
from incident_service.domain.repository_interface import IncidentRepositoryPort
from incident_service.application.services.hotfix_validation_service import (
    HotfixValidationService,
)
from incident_service.application.services.proposal_execution_policy import (
    RESUMABLE_STAGES,
    execution_id_for,
    find_proposal,
    is_fresh,
    load_heartbeat_seconds,
    load_lease_seconds,
    load_proposal_ttl_seconds,
    log_stage,
    new_lease_owner,
    rca_root_cause,
    stage_for_notify,
    utcnow,
    verify_proposal_integrity,
)
from incident_service.application.services.remediation_orchestration_service import (
    RemediationOrchestrationError,
    RemediationStageGuardError,
)
from incident_service.application.services.remediation_target_binding import (
    resolve_authoritative_deployment_target,
)
from incident_service.application.services.remediation_workspace_service import (
    RemediationWorkspaceService,
)

logger = logging.getLogger("ProposalExecution")

EXECUTION_EVIDENCE_KIND = "remediation_execution"
VALIDATION_PROFILE_ENV = "REMEDIATION_VALIDATION_PROFILE"
DEFAULT_VALIDATION_PROFILE = "incident_service"

_SENSITIVE_PATTERNS = (
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE),
    re.compile(r"ghp_[A-Za-z0-9]+"),
    re.compile(r"github_pat_[A-Za-z0-9_]+"),
)

#: typed failures that must pass through classification unchanged
_PASSTHROUGH_FAILURES = (
    ApprovalPolicyError,
    ExecutionLeaseUnavailable,
    ExistingPullRequestConflict,
    ProposalIntegrityError,
    ProposalNotApprovedError,
    ProposalPatchPolicyError,
    ProposalStaleError,
    RemoteBranchConflict,
    RemoteReconciliationFailed,
    TargetRevalidationError,
)


def _safe_reason(exc: BaseException) -> str:
    """Truncated, credential-redacted failure reason for audit evidence."""
    reason = str(exc) or exc.__class__.__name__
    for pattern in _SENSITIVE_PATTERNS:
        reason = pattern.sub("[REDACTED]", reason)
    return reason[:300]


class _LeaseHeartbeat:
    """Worker-owned liveness for one active execution attempt (§6.2.1A).

    While a bounded external operation runs (clone/push/validation/REST),
    the heartbeat periodically renews the durable lease through the
    owner-CAS primitive. Outcomes are explicit:

    * renewal succeeds -> execution continues;
    * renewal reports the owner no longer holds the claim -> ownership
      is marked lost, the loop stops, and the next stage persist is
      refused (RemediationStageGuardError) BEFORE any further side
      effect;
    * the claim store is unreachable -> same fail-closed treatment —
      uncertainty never grants new authority.

    This is NOT distributed cancellation: an already-running git/HTTP
    operation finishes; only the *next* destructive stage is blocked.
    The thread is daemon, joined deterministically by stop(), and never
    outlives the execution attempt it serves.
    """

    def __init__(self, *, renew, interval, fields, name):
        self._renew = renew
        self.interval = interval
        self._fields = fields
        self._stop = threading.Event()
        self.lost = threading.Event()
        self.loss_reason = ""
        self.renewals = 0
        self._thread: Optional[threading.Thread] = None
        self._name = name

    def start(self) -> None:
        thread = threading.Thread(target=self._run, name=self._name, daemon=True)
        self._thread = thread
        thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=5.0)

    def is_alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                renewed = self._renew()
            except Exception as exc:  # store unavailable -> fail closed
                self._mark_lost("store_unavailable", exc)
                return
            if not renewed:
                # CAS miss: another owner, released, or completed claim
                self._mark_lost("owner_lost", None)
                return
            self.renewals += 1
            log_stage(
                "lease.renewed",
                renewals=self.renewals,
                **self._fields,
            )

    def _mark_lost(self, reason: str, exc: Optional[BaseException]) -> None:
        self.loss_reason = reason
        self.lost.set()
        log_stage(
            "lease.rejected",
            reason=f"heartbeat_{reason}",
            error=exc.__class__.__name__ if exc is not None else None,
            **self._fields,
        )


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
        lease_seconds: Optional[float] = None,
        lease_owner: Optional[str] = None,
        remote_inspector: Optional[Any] = None,
        heartbeat_interval: Optional[float] = None,
    ):
        self.repository = repository
        self.orchestrator_factory = orchestrator_factory
        self.ttl_seconds = (
            load_proposal_ttl_seconds() if ttl_seconds is None else ttl_seconds
        )
        self.lease_seconds = (
            load_lease_seconds() if lease_seconds is None else lease_seconds
        )
        # active-lease liveness policy: env/derived interval, or an
        # explicit value (tests/composition) — always positive and
        # strictly below lease/2, fail fast otherwise
        if heartbeat_interval is None:
            self.heartbeat_interval = load_heartbeat_seconds(self.lease_seconds)
        else:
            explicit = float(heartbeat_interval)
            if explicit <= 0 or explicit != explicit or explicit == float("inf"):
                raise ValueError("heartbeat_interval must be a positive number")
            if explicit >= self.lease_seconds / 2.0:
                raise ValueError(
                    "heartbeat_interval must be less than half the lease duration"
                )
            self.heartbeat_interval = explicit
        self.now = now
        self.validation_profile = (
            validation_profile
            if validation_profile is not None
            else load_validation_profile()
        )
        self.validation = validation_service or HotfixValidationService()
        # never caller-supplied: process-derived identity (§9)
        self.lease_owner = lease_owner or new_lease_owner()
        self.remote_inspector = remote_inspector or RemediationWorkspaceService()
        # performance optimization ONLY — the durable claim is the
        # source of truth for ownership (§7)
        self._locks: Dict[str, threading.Lock] = {}
        # active heartbeat for the in-flight attempt (diagnostics/tests)
        self._heartbeat: Optional[_LeaseHeartbeat] = None

    # ------------------------------------------------------------------ #
    def _proposal_lock(self, key: str) -> threading.Lock:
        if key not in self._locks:
            self._locks[key] = threading.Lock()
        return self._locks[key]

    def _coordination(self, method_name: str) -> Callable[..., Any]:
        method = getattr(self.repository, method_name, None)
        if method is None:
            raise ExecutionLeaseUnavailable(
                "incident repository lacks durable execution coordination"
            )
        return method

    def assert_execution_lease_live(
        self,
        incident_id: str,
        proposal_id: str,
        *,
        heartbeat: Optional["_LeaseHeartbeat"] = None,
    ) -> None:
        """Pre-side-effect authorization (Phase 6.2.1B, single source of
        truth).

        Succeeds only when, AT THIS INSTANT, the durable control plane
        reports this worker owns a live (state LEASED, owner match,
        unexpired) claim and the heartbeat has not flagged loss. It does
        NOT make the subsequent external Git/GitHub operation
        transactionally atomic with the lease — defense in depth remains
        pre-side-effect guard + heartbeat + owner-gated stage persistence
        + remote reconciliation + fail closed. Store uncertainty raises
        (fail closed) — never treated as authorization.
        """
        active_heartbeat = heartbeat if heartbeat is not None else self._heartbeat
        if active_heartbeat is not None and active_heartbeat.lost.is_set():
            raise RemediationStageGuardError(
                "execution lease lost ("
                f"{active_heartbeat.loss_reason or 'unknown'}) before a "
                "side effect"
            )
        try:
            claim = self._coordination("get_execution_claim")(
                incident_id, proposal_id
            )
        except ExecutionLeaseUnavailable:
            raise
        except Exception as exc:
            raise RemediationStageGuardError(
                "durable claim store unavailable; cannot authorize the "
                "next side effect"
            ) from exc
        if not claim:
            raise RemediationStageGuardError(
                "execution claim missing; cannot authorize the next side effect"
            )
        if str(claim.get("state") or "") != "LEASED":
            raise RemediationStageGuardError(
                "execution claim is not leased; cannot authorize the next "
                "side effect"
            )
        if str(claim.get("lease_owner") or "") != self.lease_owner:
            raise RemediationStageGuardError(
                "execution lease is owned by another worker; cannot "
                "authorize the next side effect"
            )
        expires = claim.get("lease_expires_at")
        if expires is None:
            raise RemediationStageGuardError(
                "execution lease has no expiry; cannot authorize the next "
                "side effect"
            )
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires <= self.now():
            raise RemediationStageGuardError(
                "execution lease expired; cannot authorize the next side effect"
            )

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

        lock = self._proposal_lock(f"{incident.id}:{proposal_id}")
        with lock:
            incident = self.repository.get_incident_by_id(incident.id)
            if incident is None:
                raise ProposalNotFoundError(f"Incident '{incident_id}' not found")
            proposal = find_proposal(incident, proposal_id)

            # §5 hash binding — stored == reproducible == caller claim.
            verify_proposal_integrity(incident, proposal, proposal_hash)

            if proposal.status == "PR_CREATED":
                return self._reconcile(incident, proposal)

            if proposal.status in {"PROPOSED", "BLOCKED"}:
                raise ProposalNotApprovedError(
                    f"proposal status {proposal.status} cannot execute without "
                    "a valid approval"
                )

            self._assert_execution_preconditions(proposal)
            self._revalidate_patch_policy(incident, proposal)
            self._revalidate_target(incident, proposal)

            claim = self._coordination("get_execution_claim")(
                incident.id, proposal.id
            ) or {}
            recovery = bool(
                claim
                and (
                    proposal.status == "EXECUTING"
                    or proposal.execution_stage in RESUMABLE_STAGES
                )
            )
            if recovery:
                log_stage(
                    "recovery.started",
                    incident_id=incident.id,
                    proposal_id=proposal.id,
                    proposal_hash=proposal.proposal_hash,
                    attempt=int(claim.get("attempt") or 0),
                    durable_stage=str(
                        proposal.execution_stage
                        or claim.get("stage")
                        or "unknown"
                    ),
                )

            try:
                mode, resume_stage = self._decide_mode(proposal, claim)
            except (RemoteBranchConflict, RemoteReconciliationFailed) as exc:
                # durable reconciliation failure (§10): record it before
                # propagating; never retarget, never silently continue.
                self._record_reconciliation_conflict(
                    incident, proposal, claim, exc
                )
                raise

            reason, claimed_incident = self._coordination(
                "claim_execution_lease"
            )(
                incident.id,
                proposal.id,
                proposal.proposal_hash,
                owner=self.lease_owner,
                now=self.now(),
                lease_seconds=self.lease_seconds,
            )
            if reason == "lease_active":
                log_stage(
                    "lease.rejected",
                    incident_id=incident.id,
                    proposal_id=proposal.id,
                    proposal_hash=proposal.proposal_hash,
                    owner=self.lease_owner,
                )
                raise ExecutionLeaseUnavailable(
                    "another live owner holds the execution lease for this proposal"
                )
            if reason == "raced":
                raise ExecutionLeaseUnavailable(
                    "execution claim lost a concurrent write race; retry"
                )
            if reason in {"no_incident", "proposal_missing"}:
                raise ProposalNotFoundError(
                    f"Proposal '{proposal_id}' does not exist on incident "
                    f"'{incident_id}'"
                )
            if reason == "hash_mismatch":
                raise ProposalIntegrityError(
                    "execution claim rejected: proposal hash does not match"
                )
            if reason == "status_not_executable":
                fresh = self.repository.get_incident_by_id(incident.id)
                fresh_proposal = (
                    find_proposal(fresh, proposal_id) if fresh else None
                )
                if fresh_proposal is not None and (
                    fresh_proposal.status == "PR_CREATED"
                ):
                    verify_proposal_integrity(fresh, fresh_proposal, proposal_hash)
                    return self._reconcile(fresh, fresh_proposal)
                raise ProposalNotApprovedError(
                    "proposal state changed before the execution lease "
                    "could be acquired"
                )
            if reason != "claimed" or claimed_incident is None:
                raise ExecutionLeaseUnavailable(
                    f"execution lease could not be acquired ({reason})"
                )

            proposal = find_proposal(claimed_incident, proposal_id)
            attempt = int(proposal.execution_attempts or 0)
            log_stage(
                "lease.acquired",
                incident_id=incident.id,
                proposal_id=proposal.id,
                proposal_hash=proposal.proposal_hash,
                execution_id=proposal.execution_id
                or execution_id_for(proposal.id, proposal.proposal_hash),
                attempt=attempt,
                owner=self.lease_owner,
                mode=mode,
                durable_stage=proposal.execution_stage,
                requested_by=requested_by or None,
            )
            if mode == "FULL" and proposal.execution_stage not in {"CLAIMED"}:
                # durable cursor cannot resume (e.g. remote absent) —
                # restart from a clean CLAIMED state before side effects.
                self._coordination("persist_execution_progress")(
                    incident.id,
                    proposal.id,
                    self.lease_owner,
                    stage="CLAIMED",
                    now=self.now(),
                    lease_seconds=self.lease_seconds,
                )
                proposal.execution_stage = "CLAIMED"
            log_stage(
                "execution.started",
                incident_id=incident.id,
                proposal_id=proposal.id,
                proposal_hash=proposal.proposal_hash,
                execution_id=proposal.execution_id,
                attempt=attempt,
                mode=mode,
                requested_by=requested_by or None,
                target_repository=proposal.repository,
                source_sha=proposal.source_sha,
            )

            stages: List[Tuple[str, Dict[str, Any]]] = []

            orchestrator = self.orchestrator_factory()

            # §6.2.1A active lease liveness: renew the durable lease while
            # bounded external work runs; stop deterministically on every
            # exit path (no orphan threads).
            heartbeat = _LeaseHeartbeat(
                renew=lambda: self._coordination("renew_execution_lease")(
                    incident.id,
                    proposal.id,
                    self.lease_owner,
                    now=self.now(),
                    lease_seconds=self.lease_seconds,
                ),
                interval=self.heartbeat_interval,
                fields={
                    "incident_id": incident.id,
                    "proposal_id": proposal.id,
                    "proposal_hash": proposal.proposal_hash,
                    "execution_id": proposal.execution_id,
                    "attempt": attempt,
                    "owner": self.lease_owner,
                    "interval_seconds": self.heartbeat_interval,
                },
                name=(
                    f"remediation-heartbeat:{incident.id}:{proposal.id}"
                ),
            )
            self._heartbeat = heartbeat

            def stage_callback(stage_name: str, metadata: Dict[str, Any]) -> None:
                self._persist_stage(
                    incident=incident,
                    proposal=proposal,
                    stage_name=stage_name,
                    metadata=metadata,
                    stages=stages,
                    heartbeat=heartbeat,
                )

            def before_side_effect(operation: str) -> None:
                # runs on the execution worker thread (never the
                # heartbeat thread): durable live-ownership check
                # immediately before each side effect
                self.assert_execution_lease_live(
                    incident.id,
                    proposal.id,
                    heartbeat=heartbeat,
                )

            try:
                try:
                    heartbeat.start()
                except Exception as exc:
                    # no side effects yet: surface typed; the durable
                    # lease expires by TTL and recovery reconciles.
                    raise ExecutionLeaseUnavailable(
                        "execution lease heartbeat could not be started"
                    ) from exc
                try:
                    if mode == "RESUME":
                        url = orchestrator.reconcile_and_create_pr(
                            incident_id=incident.id,
                            proposal=proposal,
                            repository_slug=proposal.repository,
                            stage_callback=stage_callback,
                            before_side_effect=before_side_effect,
                        )
                        result = _ResumeResult(
                            commit_sha=proposal.commit_sha,
                            branch_name=proposal.branch_name,
                            pull_request_url=url,
                        )
                    else:
                        result = orchestrator.execute(
                            incident_id=incident.id,
                            proposal=proposal,
                            repository_slug=proposal.repository,
                            validation_profile=self.validation_profile,
                            stage_callback=stage_callback,
                            before_side_effect=before_side_effect,
                        )
                except Exception as exc:
                    heartbeat.stop()
                    typed = self._classify_failure(exc, stages)
                    self._execution_failure(
                        incident, proposal, typed, stages, attempt,
                        requested_by, cause=exc,
                    )
                    raise typed from exc
                # stop BEFORE finishing so renewal can never race the
                # owner-gated release transaction
                heartbeat.stop()
                return self._persist_success(
                    incident, proposal, result, stages, requested_by,
                    attempt, mode
                )
            finally:
                heartbeat.stop()
                if self._heartbeat is heartbeat:
                    self._heartbeat = None

    def _record_reconciliation_conflict(
        self, incident, proposal, claim, exc
    ) -> None:
        """Persist a pre-lease reconciliation failure on the aggregate.

        Only used when no live owner exists (the lease is absent/expired
        — checked before this point), so the aggregate write cannot clobber
        a live execution.
        """
        attempt = int(claim.get("attempt") or proposal.execution_attempts or 0)
        execution_id = proposal.execution_id or execution_id_for(
            proposal.id, proposal.proposal_hash
        )
        reason = _safe_reason(exc)
        proposal.status = "EXECUTION_FAILED"
        proposal.last_failure_stage = "reconciliation"
        proposal.last_failure_reason = reason
        evidence = IncidentEvidence(
            id=f"exec-{execution_id}-recon-a{attempt}",
            kind=EXECUTION_EVIDENCE_KIND,
            source="remediation-control-plane",
            payload={
                "schema": "devops.remediation.execution/2",
                "execution_id": execution_id,
                "attempt": attempt,
                "status": "RECONCILIATION_CONFLICT",
                "incident_id": incident.id,
                "proposal_id": proposal.id,
                "proposal_hash": proposal.proposal_hash,
                "repository": proposal.repository,
                "source_sha": proposal.source_sha,
                "durable_stage": proposal.execution_stage,
                "failure_type": exc.__class__.__name__,
                "failure_reason": reason,
            },
        )
        incident.attach_evidence(evidence)
        self.repository.save_incident(incident)
        log_stage(
            "execution.failed",
            incident_id=incident.id,
            proposal_id=proposal.id,
            proposal_hash=proposal.proposal_hash,
            execution_id=execution_id,
            failed_stage="reconciliation",
            failure_type=exc.__class__.__name__,
            attempt=attempt,
        )

    # ------------------------------------------------------------------ #
    def _decide_mode(self, proposal, claim: Dict[str, Any]) -> Tuple[str, str]:
        """Resume only when durable cursor AND real remote agree (§13/§15)."""
        stage = str(claim.get("stage") or proposal.execution_stage or "")
        commit_sha = str(claim.get("commit_sha") or "").strip().lower()
        branch = str(
            claim.get("branch_name") or proposal.branch_name or ""
        ).strip()
        if stage not in RESUMABLE_STAGES or not commit_sha or not branch:
            return ("FULL", stage)

        remote_sha = self.remote_inspector.inspect_remote_branch(
            proposal.repository, branch, os.getenv("GITHUB_OAUTH_TOKEN", "")
        )
        if remote_sha == commit_sha:
            log_stage(
                "recovery.reconciled",
                incident_id=proposal.incident_id,
                proposal_id=proposal.id,
                proposal_hash=proposal.proposal_hash,
                durable_stage=stage,
                commit_sha=commit_sha,
                branch=branch,
                remote_sha=remote_sha,
            )
            log_stage(
                "remote.branch.reconciled",
                incident_id=proposal.incident_id,
                proposal_id=proposal.id,
                branch=branch,
                remote_sha=remote_sha,
                outcome="expected_commit",
            )
            return ("RESUME", stage)
        if remote_sha is None and stage == "COMMIT_CREATED":
            # commit was never published — safe to rebuild from source
            return ("FULL", stage)
        if remote_sha is None:
            raise RemoteReconciliationFailed(
                "persisted execution state expects a published remediation "
                "branch, but the remote branch is missing"
            )
        raise RemoteBranchConflict(
            "remote remediation branch exists at an unexpected commit; "
            "recovery refuses to overwrite or retarget it"
        )

    def _persist_stage(
        self, *, incident, proposal, stage_name, metadata, stages,
        heartbeat: Optional[_LeaseHeartbeat] = None,
    ) -> None:
        stages.append((stage_name, dict(metadata)))
        # §6.2.1A lease-expiry safety rule: a worker that has already
        # observed lease loss (owner CAS miss or store uncertainty) must
        # not begin the next side-effecting stage.
        if heartbeat is not None and heartbeat.lost.is_set():
            raise RemediationStageGuardError(
                "execution lease lost ("
                f"{heartbeat.loss_reason or 'unknown'}) before persisting "
                f"stage {stage_name}"
            )
        log_stage(
            stage_name,
            incident_id=incident.id,
            proposal_id=proposal.id,
            proposal_hash=proposal.proposal_hash,
            execution_id=proposal.execution_id,
            **{k: v for k, v in metadata.items() if k != "stdout"},
        )
        stage = stage_for_notify(stage_name)
        if stage is None:
            return
        if stage_name == "validation.completed" and not metadata.get("passed"):
            return  # failure path persists FAILED; never claim VALIDATION_PASSED
        updates: Dict[str, Any] = {}
        if stage_name == "commit.created":
            commit_sha = str(metadata.get("commit_sha") or "").strip()
            branch = str(metadata.get("branch") or "").strip()
            if commit_sha:
                updates["commit_sha"] = commit_sha
            if branch:
                updates["branch_name"] = branch
        if stage_name in {"pr.created", "pr.reconciled"}:
            url = str(metadata.get("pull_request_url") or "")
            if url:
                updates["pull_request_url"] = url
        try:
            ok = self._coordination("persist_execution_progress")(
                incident.id,
                proposal.id,
                self.lease_owner,
                stage=stage,
                now=self.now(),
                lease_seconds=self.lease_seconds,
                commit_sha=updates.get("commit_sha"),
                branch_name=updates.get("branch_name"),
            )
        except ValueError:
            raise  # stage-order contract violation — surface honestly
        except Exception as exc:
            # §6.2.1A: if the claim store is unreachable we cannot prove
            # ownership — fail closed, never continue on uncertainty.
            raise RemediationStageGuardError(
                "durable claim store unavailable while verifying execution "
                "ownership"
            ) from exc
        if not ok:
            raise RemediationStageGuardError(
                "execution lease lost while persisting stage progress"
            )
        proposal.execution_stage = stage
        if "commit_sha" in updates and updates["commit_sha"]:
            proposal.commit_sha = updates["commit_sha"]
        if "branch_name" in updates and updates["branch_name"]:
            proposal.branch_name = updates["branch_name"]

    def _assert_execution_preconditions(self, proposal) -> None:
        if proposal.status in {"APPROVED", "EXECUTION_FAILED"}:
            pass  # retryable / executable
        elif proposal.status == "EXECUTING":
            claim = self._coordination("get_execution_claim")(
                proposal.incident_id, proposal.id
            )
            owner = str((claim or {}).get("lease_owner") or "")
            expires = (claim or {}).get("lease_expires_at")
            now = self.now()
            if claim and str(claim.get("state")) == "LEASED" and owner:
                observed = expires if expires is not None else now
                if observed.tzinfo is None:
                    from datetime import timezone as _tz

                    observed = observed.replace(tzinfo=_tz.utc)
                if observed > now:
                    raise ProposalAlreadyExecutingError(
                        "proposal execution is already in flight under an "
                        "active durable lease"
                    )
                log_stage(
                    "lease.expired",
                    proposal_id=proposal.id,
                    proposal_hash=proposal.proposal_hash,
                    previous_owner=owner,
                    expired_at=observed.isoformat(),
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
        if rca_root_cause(incident) is None:
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

    def _revalidate_target(self, incident, proposal) -> None:
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

    def _classify_failure(
        self,
        exc: BaseException,
        stages: List[Tuple[str, Dict[str, Any]]],
    ) -> BaseException:
        """Map an orchestration failure onto a typed, auditable error."""
        if isinstance(exc, _PASSTHROUGH_FAILURES):
            return exc
        if isinstance(exc, RemediationStageGuardError):
            return ProposalExecutionFailedError(
                str(exc),
                stage=stages[-1][0] if stages else "workspace",
            )
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
        return ProposalExecutionFailedError(_safe_reason(exc), stage=stage)

    # persistence helpers ------------------------------------------------ #
    def _persist_success(
        self, incident, proposal, result, stages, requested_by, attempt, mode
    ) -> Dict[str, Any]:
        execution_id = proposal.execution_id or execution_id_for(
            proposal.id, proposal.proposal_hash
        )
        payload_extra = {
            "commit_sha": result.commit_sha,
            "branch_name": result.branch_name,
            "pull_request_url": result.pull_request_url,
            "mode": mode,
            "validation": {
                **self._validation_summary(result),
                "profile": self.validation_profile,
            },
        }
        evidence = self._execution_evidence(
            incident=incident,
            proposal=proposal,
            attempt=attempt,
            status="PR_CREATED",
            stages=stages,
            requested_by=requested_by,
            extra=payload_extra,
            execution_id=execution_id,
        )
        updates = {
            "commit_sha": result.commit_sha,
            "branch_name": result.branch_name,
            "pull_request_url": result.pull_request_url,
        }
        try:
            finished = self._coordination("finish_execution_lease")(
                incident.id,
                proposal.id,
                self.lease_owner,
                status="PR_CREATED",
                stage="COMPLETED",
                now=self.now(),
                updates=updates,
                evidence=evidence,
            )
        except ExecutionLeaseUnavailable:
            raise
        except Exception as exc:
            raise ExecutionLeaseUnavailable(
                "durable claim store unavailable; the completed execution "
                "could not be persisted"
            ) from exc
        if not finished:
            raise ExecutionLeaseUnavailable(
                "execution lease was lost before completion could be persisted; "
                "reconcile by retrying the execution request"
            )
        proposal.status = "PR_CREATED"
        proposal.execution_stage = "COMPLETED"
        proposal.commit_sha = result.commit_sha
        proposal.branch_name = result.branch_name
        proposal.pull_request_url = result.pull_request_url
        proposal.lease_owner = ""
        proposal.lease_acquired_at = None
        proposal.lease_expires_at = None
        proposal.last_heartbeat_at = None
        log_stage(
            "execution.completed",
            incident_id=incident.id,
            proposal_id=proposal.id,
            proposal_hash=proposal.proposal_hash,
            execution_id=execution_id,
            attempt=attempt,
            commit_sha=result.commit_sha,
            pull_request_url=result.pull_request_url,
        )
        return {
            "incident_id": incident.id,
            "proposal": proposal.to_dict(),
            "execution_id": execution_id,
            "status": "PR_CREATED",
            "idempotent": False,
        }

    def _execution_failure(
        self, incident, proposal, exc, stages, attempt, requested_by,
        cause=None,
    ) -> None:
        stage = getattr(exc, "stage", None) or (
            stages[-1][0] if stages else "workspace"
        )
        original = cause if cause is not None else exc
        reason = _safe_reason(exc)
        execution_id = proposal.execution_id or execution_id_for(
            proposal.id, proposal.proposal_hash
        )

        # durable cursor: keep a resumable stage so recovery can reconcile
        # remote state; otherwise mark the attempt FAILED.
        claim = self._coordination("get_execution_claim")(
            incident.id, proposal.id
        ) or {}
        cursor = str(claim.get("stage") or proposal.execution_stage or "")
        durable_stage = cursor if cursor in RESUMABLE_STAGES else "FAILED"

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
                "failure_reason": reason,
                "durable_stage": durable_stage,
                "lease_owner": self.lease_owner,
            },
            execution_id=execution_id,
        )
        try:
            finished = self._coordination("finish_execution_lease")(
                incident.id,
                proposal.id,
                self.lease_owner,
                status="EXECUTION_FAILED",
                stage=durable_stage,
                now=self.now(),
                updates={
                    "last_failure_stage": str(stage),
                    "last_failure_reason": reason,
                },
                evidence=evidence,
            )
        except ExecutionLeaseUnavailable:
            raise
        except Exception as exc:
            # store unavailable: outcome unknown locally — fail closed
            # with a typed error; the durable lease expires and recovery
            # reconciles through the normal path.
            raise ExecutionLeaseUnavailable(
                "durable claim store unavailable; the execution failure "
                "could not be persisted"
            ) from exc
        if not finished:
            # ownership is gone — never clobber the new owner's state
            log_stage(
                "lease.rejected",
                incident_id=incident.id,
                proposal_id=proposal.id,
                proposal_hash=proposal.proposal_hash,
                reason="finish_rejected_owner_lost",
            )
            raise ExecutionLeaseUnavailable(
                "execution lease was lost during the failed attempt; the "
                "failure could not be persisted under this owner"
            ) from exc
        proposal.status = "EXECUTION_FAILED"
        proposal.execution_stage = durable_stage
        proposal.last_failure_stage = str(stage)
        proposal.last_failure_reason = reason
        proposal.lease_owner = ""
        proposal.lease_acquired_at = None
        proposal.lease_expires_at = None
        proposal.last_heartbeat_at = None
        log_stage(
            "execution.failed",
            incident_id=incident.id,
            proposal_id=proposal.id,
            proposal_hash=proposal.proposal_hash,
            execution_id=execution_id,
            failed_stage=str(stage),
            failure_type=exc.__class__.__name__,
            attempt=attempt,
        )

    @staticmethod
    def _validation_summary(result) -> Dict[str, Any]:
        validation_result = getattr(result, "validation_result", None)
        if validation_result is None:
            return {"recovered": True}
        try:
            steps = [
                {"name": step.name, "passed": step.passed}
                for step in validation_result.steps
            ]
        except (AttributeError, TypeError):
            steps = []
        return {
            "passed": bool(getattr(validation_result, "passed", False)),
            "steps": steps,
        }

    @staticmethod
    def _execution_evidence(
        *, incident, proposal, attempt, status, stages, requested_by, extra,
        execution_id,
    ) -> IncidentEvidence:
        payload = {
            "schema": "devops.remediation.execution/2",
            "execution_id": execution_id,
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
            "durable_stage": proposal.execution_stage,
            "lease_owner": proposal.lease_owner or None,
            "stages": [
                {"stage": stage, "metadata": metadata}
                for stage, metadata in stages
            ],
            **extra,
        }
        return IncidentEvidence(
            id=f"exec-{execution_id}-a{attempt}",
            kind=EXECUTION_EVIDENCE_KIND,
            source="remediation-control-plane",
            payload=payload,
        )

    def _reconcile(self, incident, proposal) -> Dict[str, Any]:
        execution_id = proposal.execution_id or execution_id_for(
            proposal.id, proposal.proposal_hash
        )
        log_stage(
            "execution.reconciled",
            incident_id=incident.id,
            proposal_id=proposal.id,
            proposal_hash=proposal.proposal_hash,
            execution_id=execution_id,
            pull_request_url=proposal.pull_request_url,
        )
        return {
            "incident_id": incident.id,
            "proposal": proposal.to_dict(),
            "execution_id": execution_id,
            "status": "PR_CREATED",
            "idempotent": True,
        }


class _ResumeResult:
    """Result shim for the resume path (no patch/validation this attempt)."""

    def __init__(self, *, commit_sha, branch_name, pull_request_url):
        self.commit_sha = commit_sha
        self.branch_name = branch_name
        self.pull_request_url = pull_request_url
        self.validation_result = None
