"""DevOps.AI Deployment Engine — internal API (Phase 8.8A Correction-1).

Runtime topology (F1/F7)
========================
This module is the deployment **API**. It runs uvicorn on 8030 as the
default image entrypoint; the Celery worker runs the SAME image with a
different entrypoint (docker-compose.yml, deployment-worker).

The API validates requests, authenticates and authorizes the caller
(see deployment_auth), persists durable run records in Redis and
enqueues execution tasks. It **never executes sandboxes itself** and
holds no Docker daemon access. The worker owns execution under a
fenced, renewable Redis lease; delivery is at-least-once and the worker
is idempotent, so a redelivered or duplicate task never double-applies.

Execution contract (F7, audit P1-2 + follow-up rounds A–D)
==========================================================
POST .../execute is a DISPATCH, not an execution. The API never
conflates "the broker accepted the task", "the broker never received
it", and "we do not know which":

* 200 ``dispatched: true`` — the durable run moved to
  EXECUTION_REQUESTED (atomic revision-claim) AND the publish
  completed AND the PUBLISHED outcome was durably journaled.
* 200 ``dispatched: "unknown"`` — the dispatch CANNOT be proven to
  have stayed off the broker per its DURABLE ATTEMPT JOURNAL (each
  attempt is journaled PUBLISHING before the send, then PUBLISHED /
  PRE_SEND_FAILED / AMBIGUOUS; a crashed API or a worker fence can
  never erase it): the task MAY be queued and executing, so the run
  is NEVER reverted; it stays EXECUTION_REQUESTED, explicitly
  ambiguous, and the caller may poll or idempotently re-POST the same
  request (same stable task id; the worker absorbs duplicates).
* 503 — EVERY journaled attempt for this dispatch is terminal
  PRE_SEND_FAILED (each a clean connection refusal before any publish
  bytes, checked atomically server-side): the run is atomically
  reverted to APPROVED and nothing was executed.

Concurrency: every durable write to the run document atomically
ADVANCES a monotonic ``revision`` counter; the concurrency-sensitive
dispatch writes (the APPROVED -> EXECUTION_REQUESTED claim, re-dispatch
updates, reverts, outcome bookkeeping) are Lua compare-and-set on it,
so a losing concurrent request publishes nothing and a stale dispatch
write is refused. Unconditional saves (single-writer phases, worker
state advances) also advance the counter, invalidating any dispatch
claim based on an earlier read. Delivery is at-least-once; the worker
is idempotent.
"""

import logging
import re
import time
import uuid
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from deployment_service.application.services import deployment_auth
from deployment_service.application.services.deployment_auth import (
    Identity,
    require_approver,
    require_dispatch_caller,
    require_dry_run_caller,
    require_read_caller,
    validate_execution_config,
)
from deployment_service.application.services.deployment_engine import (
    DeploymentActionError,
    DeploymentEngine,
)
from deployment_service.application.services.source_verification import (
    SourceVerificationError,
)

logger = logging.getLogger("DeploymentAPI")

# Canonical identities accepted at the deployment HTTP boundary. The exact
# same semantics are enforced later by remediation target binding, so a
# request that could never authorize remediation is rejected up front.
_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
STRONG_SLUG_PATTERN = (
    r"(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+"
    r"/(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+"
)
_SLUG_PATTERN = re.compile(r"^(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+/(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+$")  # python-re (lookahead ok)


class SourceRevision(BaseModel):
    """Exact immutable source revision being deployed.

    The HTTP contract is strict on purpose: no branch names, no tags, no
    short SHAs, no alternate mutable fields. Unknown keys inside
    ``source_revision`` are dropped (never persisted), so the engine can
    only ever see this declared contract.
    """

    head_sha: str = Field(pattern=r"^[0-9a-fA-F]{40}$")
    commits: list = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)

    @field_validator("head_sha", mode="before")
    @classmethod
    def _normalize_head_sha(cls, value):
        # strip surrounding whitespace (permitted by the binding contract)
        # and persist the canonical lowercase form end-to-end.
        if isinstance(value, str):
            return value.strip().lower()
        return value


#: The components a deployment may declare. A component that is not
#: requested is NOT APPLICABLE: no validation, no plan, no execution and
#: no sandbox invocation. That is distinct from a requested component
#: that failed, which is always an error.
KNOWN_COMPONENTS = ("dockerfile", "kubernetes", "terraform", "pipeline")


def _validate_components(value: List[str]) -> List[str]:
    if not value:
        raise ValueError("at least one component must be requested")
    unknown = sorted(set(value) - set(KNOWN_COMPONENTS))
    if unknown:
        raise ValueError(f"unknown component(s): {unknown}")
    if len(set(value)) != len(value):
        raise ValueError("components must not repeat")
    # canonical order, so the same selection always hashes identically
    return [c for c in KNOWN_COMPONENTS if c in value]


class DryRunRequest(BaseModel):
    repository_id: int
    # canonical owner/repository identity - bare names and dot-only segments
    # rejected here (pydantic's regex has no lookahead, so this is a validator)
    repository_name: str
    requested_by: str = ""
    dockerfile: str
    k8s_yaml: str
    terraform_tf: str
    pipeline_yaml: str
    # required: the deployment must identify the exact revision deployed
    source_revision: SourceRevision
    #: Which components this deployment declares. Defaults to all
    #: four, so existing callers are unaffected.
    components: List[str] = list(KNOWN_COMPONENTS)

    @field_validator("components")
    @classmethod
    def _components(cls, value: List[str]) -> List[str]:
        return _validate_components(value)

    @field_validator("repository_name")
    @classmethod
    def _canonical_repository_name(cls, value: str):
        if not re.fullmatch(STRONG_SLUG_PATTERN, value):
            raise ValueError(
                "repository_name must be canonical owner/repository "
                "(alphanumeric segments; bare names and path tricks rejected)"
            )
        return value


class ApprovalRequest(BaseModel):
    """Hash-bound approval request (Phase 8.8A Correction-1, F2).

    There is deliberately NO ``approved_by`` field: the approver
    identity is the verified ``sub`` of the caller's operator JWT. A
    legacy client that still posts ``approved_by`` has the field
    ignored — it can never override the authenticated subject.
    """

    artifact_hash: str = Field(min_length=64, max_length=64)
    plan_hash: str = Field(min_length=64, max_length=64)


class ExecuteRequest(BaseModel):
    artifact_hash: str = Field(min_length=64, max_length=64)
    plan_hash: str = Field(min_length=64, max_length=64)
    namespace: str = "devops-production-namespace"
    healthcheck_url: str = ""
    previous_good_terraform_tf: str = ""
    dockerfile: str
    k8s_yaml: str
    terraform_tf: str
    pipeline_yaml: str
    #: Which components this deployment declares. Defaults to all
    #: four, so existing callers are unaffected.
    components: List[str] = list(KNOWN_COMPONENTS)

    @field_validator("components")
    @classmethod
    def _components(cls, value: List[str]) -> List[str]:
        return _validate_components(value)


# Independent audit (P1-2, follow-up Blocker D): bounded publish
# retries and a CONSERVATIVE failure classification. A failed publish is
# AMBIGUOUS by default — the broker may have accepted the message and
# the producer lost the reply (a timeout after send, a mid-command
# disconnect, a broker that accepts and then dies). The ONLY failure
# class that proves the message was never accepted is a clean TCP-level
# REFUSAL of the connection itself: no publish bytes could have reached
# the broker. A later reachability ping can NEVER prove historical
# non-acceptance, so no probe gates a revert: only all-attempts-pre-send
# justifies reverting to APPROVED; any ambiguous attempt keeps the run
# in EXECUTION_REQUESTED for idempotent re-dispatch.
_PUBLISH_ATTEMPTS = 3
_PUBLISH_RETRY_DELAY_SECONDS = 0.5

#: Exception-chain signatures of a clean connection REFUSAL (pre-send).
#: Anything not matching — timeouts, mid-command resets, protocol errors,
#: unknown errors — is ambiguous by default.
_PRE_SEND_REFUSED_RE = re.compile(
    r"connection refused|failed to establish a connection|error \d+ connecting",
    re.IGNORECASE,
)


def _publish_failure_is_pre_send(exc: BaseException) -> bool:
    """True only if the exception chain PROVES the publish was never
    sent (Blocker D): no timeout anywhere in the cause/context chain,
    and a connection-refused signature (a ConnectionRefusedError, or an
    OSError naming a refused connection at connect time). Any doubt —
    an unexplainable error type or message — returns False (ambiguous),
    because an ambiguous send must never be reverted to APPROVED."""
    nodes: "List[BaseException]" = []
    current: "Optional[BaseException]" = exc
    seen = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        nodes.append(current)
        current = current.__cause__ or current.__context__
    for node in nodes:
        if isinstance(node, TimeoutError):
            return False
        if "timeout" in f"{type(node).__name__}: {node}".lower():
            return False
    for node in nodes:
        if isinstance(node, ConnectionRefusedError):
            return True
        if isinstance(node, OSError) and _PRE_SEND_REFUSED_RE.search(
            f"{type(node).__name__}: {node}"
        ):
            return True
    return False


def create_app() -> FastAPI:
    """Application factory.

    Execution-enabled mode is validated at startup (B.7): a process may
    not serve execution dispatch without the required auth
    configuration — it refuses to start instead.
    """
    validate_execution_config()
    application = FastAPI(title="DevOps.AI Deployment Engine", version="2.0.0")
    application.state.engine = DeploymentEngine()

    @application.get("/health")
    def health():
        """Readiness for the declared contract, not mere process
        liveness: the API answers AND its broker dependency (dry-run
        persistence + execution dispatch) is reachable. A down broker
        is a degraded service: 503, never a success-shaped 200."""
        engine: DeploymentEngine = application.state.engine
        payload = {
            "status": "healthy",
            "service": "deployment-service",
            "version": "2.0.0",
            "execution_enabled": engine.execution_enabled(),
        }
        try:
            engine.store.ping()
            payload["redis"] = "ok"
        except Exception:  # noqa: BLE001 — the check itself must not crash
            payload["status"] = "degraded"
            payload["redis"] = "unreachable"
            return JSONResponse(status_code=503, content=payload)
        return payload

    @application.post("/api/internal/deployments/dry-run")
    def dry_run(
        request: DryRunRequest,
        identity: Identity = Depends(require_dry_run_caller),
    ):
        engine: DeploymentEngine = application.state.engine
        # model_dump() carries the validated canonical source_revision
        # straight into the engine - no inference, no alternate fields,
        # lowercase SHA.
        payload = request.model_dump()
        assert _SHA_PATTERN.fullmatch(payload["source_revision"]["head_sha"])
        assert _SLUG_PATTERN.fullmatch(payload["repository_name"])
        # The creating principal is the VERIFIED identity (F2): it is
        # never taken from a request field.
        payload["created_by"] = identity.subject
        try:
            # The engine independently verifies the requested revision
            # against the authoritative repository before any run
            # record exists.
            return engine.create_dry_run(payload).to_dict()
        except SourceVerificationError as exc:
            # not_found → 422 (the input cannot be confirmed), anything
            # the provider could not answer → 503. Both fail closed: no
            # run, no plan, no provenance.
            status = 422 if exc.reason == "not_found" else 503
            raise HTTPException(status_code=status, detail=exc.public_message) from exc

    @application.get("/api/internal/deployments/{run_id}")
    def get_run(
        run_id: str,
        identity: Identity = Depends(require_read_caller),
    ):
        engine: DeploymentEngine = application.state.engine
        payload = engine.store.get(run_id)
        if not payload:
            raise HTTPException(status_code=404, detail="Deployment run not found")
        # Run-inspection visibility (F2): a principal only sees runs it
        # created; operators see platform runs. Never another caller's
        # ids, artifacts, logs or approval records.
        deployment_auth.assert_run_visible(identity, payload.get("created_by"))
        return payload

    @application.post("/api/internal/deployments/{run_id}/approve")
    def approve(
        run_id: str,
        request: ApprovalRequest,
        identity: Identity = Depends(require_approver),
    ):
        engine: DeploymentEngine = application.state.engine
        try:
            # The approver is the authenticated subject — the verified
            # ``sub`` of the operator JWT. Caller-supplied approver text
            # (a legacy ``approved_by`` field) is structurally ignored.
            return engine.approve(
                run_id, identity.subject, request.artifact_hash, request.plan_hash
            ).to_dict()
        except DeploymentActionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @application.post("/api/internal/deployments/{run_id}/execute")
    def execute(
        run_id: str,
        request: ExecuteRequest,
        identity: Identity = Depends(require_dispatch_caller),
    ):
        """DISPATCH an approved run to the worker (F7; audit P1-2 +
        follow-up rounds A–D).

        Tri-state truthful contract — the API never conflates "the
        broker accepted the task", "the broker never received it", and
        "we do not know which":

        * 200 ``dispatched: true`` — the run claimed EXECUTION_REQUESTED
          (atomic revision-claim), the publish completed, and the
          PUBLISHED outcome is durably journaled (every attempt is
          journaled PUBLISHING before the send; the audit trail cannot
          be erased by a crash or by a worker's active fence).
        * 200 ``dispatched: "unknown"`` — the DURABLE ATTEMPT JOURNAL
          cannot prove that every attempt stayed off the broker (any
          PUBLISHING/AMBIGUOUS/PUBLISHED entry — from this call or an
          earlier one — blocks a revert, and a later clean refusal on a
          retry does not erase an earlier ambiguous or successful
          publish). The task MAY be queued and executing, so the run
          is NEVER reverted; it stays EXECUTION_REQUESTED, explicitly
          ambiguous, and re-POSTing the SAME request idempotently
          re-publishes the SAME stable task id, which the worker's
          lease + terminal-state check absorb.
        * 503 — EVERY journaled attempt for this dispatch is terminal
          PRE_SEND_FAILED (checked atomically server-side with state +
          dispatch + revision + fence): the run is atomically reverted
          to APPROVED and the API truthfully reports that nothing was
          executed.

        Duplicate handling: a run in EXECUTION_REQUESTED is re-delivered
        only when the dispatch is ambiguous, stale, or has an
        unresolved journaled attempt; otherwise the fresh duplicate is
        refused with 409 (exactly-once dispatch on the normal path).
        Concurrent initial dispatches race an atomic revision-claim:
        exactly one wins and publishes; the loser's claim is refused
        and it publishes nothing.
        """
        engine: DeploymentEngine = application.state.engine
        try:
            run = engine.prepare_dispatch(
                run_id,
                request.model_dump(),
                request.artifact_hash,
                request.plan_hash,
                namespace=request.namespace,
                healthcheck_url=request.healthcheck_url,
                previous_good_terraform_tf=request.previous_good_terraform_tf,
            )
        except DeploymentActionError as exc:
            # A run already in EXECUTION_REQUESTED may be a re-dispatch
            # request for an ambiguous/stale dispatch — let the engine
            # decide (it refuses when the dispatch is fresh).
            if "EXECUTION_REQUESTED" in str(exc):
                try:
                    run = engine.redeliver_dispatch(
                        run_id, request.artifact_hash, request.plan_hash
                    )
                except DeploymentActionError as re_exc:
                    raise HTTPException(status_code=409, detail=str(re_exc)) from re_exc
            else:
                raise HTTPException(status_code=409, detail=str(exc)) from exc

        dispatch = (run.execution or {}).get("dispatch") or {}
        task_id = dispatch.get("task_id")
        dispatch_id = dispatch.get("dispatch_id")
        if not task_id or not dispatch_id:
            # Cannot happen for a run prepared by this API; refuse to
            # publish a task whose durable identity we cannot prove.
            raise HTTPException(
                status_code=500,
                detail="Internal dispatch error: the run has no durable "
                       "dispatch identity; no task was enqueued.",
            )

        store = engine.store
        publish_errors: "List[Exception]" = []
        publish_succeeded = False
        for _attempt in range(_PUBLISH_ATTEMPTS):
            attempt_id = uuid.uuid4().hex
            # Independent audit (P1-2, third round): the attempt is
            # journaled PUBLISHING durably BEFORE the send — a crashed
            # API, a worker fence blocking the run-document history
            # write, or a retry can never make the audit trail
            # disappear. If the journal write fails, the attempt is NOT
            # sent: an untracked publish must not be made.
            if not store.journal_dispatch_attempt(
                run_id, dispatch_id, attempt_id,
                store.ATTEMPT_PUBLISHING,
            ):
                break
            try:
                from deployment_service.infrastructure.celery import tasks as deployment_tasks

                # The SAME stable task_id on every attempt: a retry after
                # an ambiguous failure publishes a duplicate message that
                # the worker's idempotency absorbs — at-least-once, never
                # double-executed.
                deployment_tasks.execute_iac_deployment.apply_async(
                    kwargs={
                        "run_id": run_id,
                        "artifact_hash": request.artifact_hash,
                        "plan_hash": request.plan_hash,
                        "namespace": request.namespace,
                        "healthcheck_url": request.healthcheck_url,
                        "previous_good_terraform_tf": request.previous_good_terraform_tf,
                        "dockerfile": request.dockerfile,
                        "k8s_yaml": request.k8s_yaml,
                        "terraform_tf": request.terraform_tf,
                        "pipeline_yaml": request.pipeline_yaml,
                        "components": request.components,
                    },
                    task_id=task_id,
                )
            except Exception as exc:  # broker down / mid-command loss / timeout
                publish_errors.append(exc)
                if _publish_failure_is_pre_send(exc):
                    # A clean pre-send refusal is provable — but it must
                    # be JOURNALED to count; if the write fails, the
                    # attempt stays PUBLISHING (pending) and the run
                    # stays non-revertible. Stop retrying: we cannot
                    # record outcomes.
                    if not store.journal_dispatch_attempt(
                        run_id, dispatch_id, attempt_id,
                        store.ATTEMPT_PRE_SEND_FAILED,
                    ):
                        break
                else:
                    # Timeout / mid-command loss / unknown: the outcome
                    # is AMBIGUOUS (may have been accepted).
                    if not store.journal_dispatch_attempt(
                        run_id, dispatch_id, attempt_id,
                        store.ATTEMPT_AMBIGUOUS,
                    ):
                        break
                if _attempt + 1 < _PUBLISH_ATTEMPTS:
                    time.sleep(_PUBLISH_RETRY_DELAY_SECONDS)
                continue
            # Success: the PUBLISHED transition must be durably journaled
            # BEFORE responding — dispatched:true requires durable
            # publication evidence (a failed journal write leaves the
            # PUBLISHING entry: pending, non-revertible, not "true").
            if store.journal_dispatch_attempt(
                run_id, dispatch_id, attempt_id, store.ATTEMPT_PUBLISHED,
            ):
                publish_succeeded = True
            break

        if publish_succeeded:
            # Run-document convenience flag (best-effort; the journal is
            # authoritative and was written before this response).
            engine.record_dispatch_outcome(
                run_id, dispatch_id, ambiguous=False,
                may_have_been_published=True,
            )
            return {
                "dispatched": True,
                "run_id": run_id,
                "state": "EXECUTION_REQUESTED",
                "delivery": "at-least-once",
                "note": "poll GET /api/internal/deployments/{run_id} for the "
                        "terminal state; a dispatched run is not yet complete",
            }

        # The publish did not complete (or its success could not be
        # durably recorded). Independent audit (P1-2, third round): the
        # DURABLE ATTEMPT JOURNAL decides revert eligibility, atomically
        # in the store's Lua (with state + dispatch + revision + fence):
        # a revert applies ONLY when every journaled attempt for this
        # dispatch is terminal PRE_SEND_FAILED — from this call OR any
        # earlier one. Any PUBLISHING (in flight / crashed mid-flight /
        # unrecordable outcome), AMBIGUOUS, or PUBLISHED entry blocks
        # it, no matter what this call's errors show; a worker fence
        # that blocked the run-document history write earlier cannot
        # erase the journal.
        first_error = publish_errors[0] if publish_errors else None
        reverted = engine.revert_dispatch(run_id, dispatch_id)
        if reverted:
            logger.error(
                "deployment dispatch reverted for %s: every journaled "
                "attempt provably failed pre-send; run back to APPROVED",
                run_id,
            )
            raise HTTPException(
                status_code=503,
                detail="Execution dispatch is unavailable: every publish "
                       "attempt in this dispatch's durable journal "
                       "provably failed before reaching the broker; "
                       "the run remains APPROVED and nothing was "
                       "executed.",
            ) from first_error

        # NOT REVERTIBLE (or the run already advanced): the dispatch
        # outcome is unconfirmed. Keep the run EXECUTION_REQUESTED,
        # explicitly ambiguous, and eligible for idempotent same-id
        # re-dispatch.
        engine.record_dispatch_outcome(
            run_id, dispatch_id, ambiguous=True,
            may_have_been_published=True,
        )
        current = engine.store.get(run_id) or {}
        state = current.get("state", "EXECUTION_REQUESTED")
        logger.error(
            "deployment dispatch NOT REVERTIBLE for %s: %s; the durable "
            "journal does not prove every attempt stayed off the broker "
            "(or the run advanced to %s) — run kept non-revertible, "
            "re-dispatch is idempotent",
            run_id, type(first_error).__name__ if first_error else "N/A",
            state,
        )
        return {
            "dispatched": "unknown",
            "run_id": run_id,
            "state": state,
            "delivery": "at-least-once",
            "note": "the dispatch cannot be reverted: its durable attempt "
                    "journal does not prove that every publish attempt "
                    "stayed off the broker (a publish may be queued or "
                    "eligible for redelivery) — or the run had already "
                    "moved on. The run stays non-revertible: reverting "
                    "would falsely claim that no work was enqueued for "
                    "this dispatch. Poll the run, or re-POST this same "
                    "request: the re-dispatch is idempotent (same stable "
                    "task id; the worker absorbs duplicates).",
        }

    return application


app = create_app()

#: Module-level convenience reference to the running app's engine (the
#: same object as ``app.state.engine``) — kept so test/tool code that
#: imports the module can swap collaborators without app plumbing.
engine = app.state.engine
