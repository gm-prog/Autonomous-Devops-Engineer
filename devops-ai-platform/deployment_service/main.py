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

Execution contract (F7, audit P1-2 + follow-up Blockers A–D)
============================================================
POST .../execute is a DISPATCH, not an execution. The API never
conflates "the broker accepted the task", "the broker never received
it", and "we do not know which":

* 200 ``dispatched: true`` — the durable run moved to
  EXECUTION_REQUESTED (atomic revision-claim) AND the publish
  completed.
* 200 ``dispatched: "unknown"`` — the dispatch CANNOT be proven to
  have stayed off the broker: either this call's publish failed in a
  way that cannot be proven pre-send (timeout, mid-command disconnect,
  a broker that accepted and then died), or this call's attempts all
  failed pre-send but an EARLIER attempt of this same dispatch
  succeeded or was ambiguous (the monotonic, durable
  ``may_have_been_published`` history fact): the task MAY be queued
  and executing, so the run is NEVER reverted; it stays
  EXECUTION_REQUESTED, explicitly ambiguous, and the caller may poll
  or idempotently re-POST the same request (same stable task id; the
  worker absorbs duplicates).
* 503 — EVERY publish attempt in the dispatch's ENTIRE history
  provably failed pre-send (the broker refused the connection before
  any publish bytes were sent, and no earlier attempt succeeded or was
  ambiguous): the run is atomically reverted to APPROVED and nothing
  was executed.

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
        follow-up Blockers A–D).

        Tri-state truthful contract — the API never conflates "the
        broker accepted the task", "the broker never received it", and
        "we do not know which":

        * 200 ``dispatched: true`` — the run claimed EXECUTION_REQUESTED
          (atomic revision-claim) and the publish completed.
        * 200 ``dispatched: "unknown"`` — the dispatch cannot be proven
          to have stayed off the broker: either this call's publish
          failed in a way that cannot be proven pre-send (timeout,
          mid-command disconnect, a broker that accepted and then
          died), or this call's attempts all failed pre-send but the
          DURABLE dispatch history (monotonic may_have_been_published)
          shows an earlier attempt succeeded or was ambiguous. The task
          MAY already be queued and executing, so the run is NEVER
          reverted (a later ping — and even a later clean refusal —
          cannot prove historical non-acceptance); it stays
          EXECUTION_REQUESTED, explicitly ambiguous, and re-POSTing the
          SAME request idempotently re-publishes the SAME stable task
          id, which the worker's lease + terminal-state check absorb.
        * 503 — EVERY publish attempt in the dispatch's ENTIRE history
          provably failed pre-send (the broker refused the connection
          before any publish bytes were sent; no earlier attempt
          succeeded or was ambiguous): the run is atomically reverted
          to APPROVED and the API truthfully reports that nothing was
          executed.

        Duplicate handling: a FRESH (non-ambiguous, non-stale) run
        already in EXECUTION_REQUESTED is refused with 409 — exactly-once
        dispatch is preserved for the normal path; only ambiguous or
        stale dispatches are re-delivered. Concurrent initial dispatches
        race an atomic revision-claim: exactly one wins and publishes;
        the loser's claim is refused and it publishes nothing.
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

        publish_errors: "List[Exception]" = []
        for _attempt in range(_PUBLISH_ATTEMPTS):
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
                break
            except Exception as exc:  # broker down / mid-command loss / timeout
                publish_errors.append(exc)
                if _attempt + 1 < _PUBLISH_ATTEMPTS:
                    time.sleep(_PUBLISH_RETRY_DELAY_SECONDS)

        if not publish_errors:
            # A successful publish is itself history: the task reached
            # the broker, so this dispatch can never later be reverted
            # to APPROVED ("nothing was executed") — not even after a
            # retry whose attempts all fail pre-send (the original
            # message may still be queued or redelivered).
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

        # The publish failed on every attempt of THIS call. Audit P1-2
        # follow-up (Blocker D, second round): the outcome is revertible
        # ONLY if the ENTIRE dispatch history provably failed pre-send:
        # (a) every attempt of THIS call was a clean connection refusal
        # (no publish bytes could have reached the broker), AND
        # (b) the persisted dispatch history says no EARLIER attempt
        # succeeded or was ambiguous (may_have_been_published is
        # monotonic and durable: an earlier ambiguous or successful
        # publish is never erased by a later pre-send refusal on a
        # retry — the earlier task may still be queued and executing).
        # ANY ambiguous attempt — a timeout, a mid-command disconnect, a
        # broker that accepted and then died — means the run is NEVER
        # reverted: a later ping cannot prove historical non-acceptance.
        stored = engine.store.get(run_id) or {}
        stored_dispatch = (stored.get("execution") or {}).get("dispatch") or {}
        ever_maybe_published = bool(
            stored_dispatch.get("may_have_been_published")
        )
        all_current_pre_send = all(
            _publish_failure_is_pre_send(e) for e in publish_errors
        )
        if all_current_pre_send and not ever_maybe_published:
            reverted = engine.revert_dispatch(run_id, dispatch_id)
            if not reverted:
                current = engine.store.get(run_id)
                state = (current or {}).get("state", "UNKNOWN")
                logger.error(
                    "deployment dispatch failed pre-send for %s (%s) but the "
                    "run already advanced to %s; reporting current state",
                    run_id, type(publish_errors[0]).__name__, state,
                )
                return {
                    "dispatched": "unknown",
                    "run_id": run_id,
                    "state": state,
                    "delivery": "at-least-once",
                    "note": "the publish failed before reaching the broker "
                            "but the run had already moved on; poll for the "
                            "terminal state.",
                }
            logger.error(
                "deployment dispatch failed PRE-SEND for %s: %s; every "
                "attempt in the dispatch history provably stayed off the "
                "broker, run reverted to APPROVED",
                run_id, type(publish_errors[0]).__name__,
            )
            raise HTTPException(
                status_code=503,
                detail="Execution dispatch is unavailable: every publish "
                       "attempt in this dispatch's history provably failed "
                       "before reaching the broker (connection refused); "
                       "the run remains APPROVED and nothing was executed.",
            ) from publish_errors[0]

        # NOT REVERTIBLE: either at least one attempt of this call could
        # not be proven pre-send (timeout / mid-command loss — the task
        # may be queued and executing), or this call's attempts all
        # failed pre-send BUT the persisted dispatch history shows an
        # EARLIER attempt succeeded or was ambiguous (may_have_been_
        # published is monotonic: the earlier task may still be queued).
        # The run stays in EXECUTION_REQUESTED, explicitly ambiguous, and
        # remains eligible for idempotent same-id re-dispatch.
        engine.record_dispatch_outcome(
            run_id, dispatch_id, ambiguous=True,
            may_have_been_published=True,
        )
        logger.error(
            "deployment dispatch NOT REVERTIBLE for %s: %s; this call's "
            "attempts all pre-send=%s but dispatch history may_have_been_"
            "published=%s — run kept in EXECUTION_REQUESTED (ambiguous), "
            "re-dispatch is idempotent",
            run_id, type(publish_errors[0]).__name__, all_current_pre_send,
            ever_maybe_published,
        )
        return {
            "dispatched": "unknown",
            "run_id": run_id,
            "state": "EXECUTION_REQUESTED",
            "delivery": "at-least-once",
            "note": "the dispatch cannot be reverted: "
                    + ("every attempt of this call failed before reaching "
                       "the broker, but an EARLIER attempt of this dispatch "
                       "succeeded or was ambiguous, so that task may still "
                       "be queued and executing"
                      if all_current_pre_send else
                      "the outcome of this call CANNOT be proven to have "
                      "stayed off the broker (timeout or mid-command "
                      "failure), so the task may already be queued and "
                      "executing")
                    + " — the run stays EXECUTION_REQUESTED: reverting "
                      "would falsely claim that no work was enqueued for "
                      "this dispatch. Poll the run, or re-POST this same "
                      "request: the re-dispatch is idempotent (same "
                      "stable task id; the worker absorbs duplicates).",
        }

    return application


app = create_app()

#: Module-level convenience reference to the running app's engine (the
#: same object as ``app.state.engine``) — kept so test/tool code that
#: imports the module can swap collaborators without app plumbing.
engine = app.state.engine
