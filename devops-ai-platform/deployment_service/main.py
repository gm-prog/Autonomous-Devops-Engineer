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

Execution contract (F7, audit P1-2)
===================================
POST .../execute is a DISPATCH, not an execution. The API never
conflates "the broker accepted the task", "the broker never received
it", and "we do not know which":

* 200 ``dispatched: true`` — the durable run moved to
  EXECUTION_REQUESTED AND the publish completed.
* 200 ``dispatched: "unknown"`` — the publish failed while the broker
  was reachable (ambiguous timeout): the task MAY be queued and
  executing, so the run is NOT reverted; it stays EXECUTION_REQUESTED
  and the caller may poll or idempotently re-POST the same request
  (same stable task id; the worker absorbs duplicates).
* 503 — the publish failed AND the broker was confirmed unreachable:
  the run is atomically reverted to APPROVED and nothing was executed.

The dispatch identity (task_id) is persisted in the run document
BEFORE the publish, and a broker-failure revert is a Lua
compare-and-set guarded on state + dispatch identity + absence of a
worker fence, so a revert can never clobber a run a worker already
took. Delivery is at-least-once; the worker is idempotent.
"""

import logging
import re
import time
from typing import List

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


# Independent audit (P1-2): bounded publish retries and a bounded
# broker reachability probe. A failed publish is NOT automatically a
# "nothing executed" answer — the message may be queued — so the API
# retries a few times, then PROBES the broker: only a confirmed-down
# broker justifies a revert + 503; a reachable broker makes the outcome
# ambiguous, and the truthful answer is "unknown" with the run left in
# EXECUTION_REQUESTED for idempotent re-dispatch.
_PUBLISH_ATTEMPTS = 3
_PUBLISH_RETRY_DELAY_SECONDS = 0.5
_BROKER_PROBE_ATTEMPTS = 3
_BROKER_PROBE_RETRY_DELAY_SECONDS = 0.5


def _broker_reachable(engine: "DeploymentEngine") -> bool:
    """Bounded reachability probe for the post-publish decision (P1-2).

    True = the broker answered at least one probe (the failed publish is
    AMBIGUOUS — the task may be queued). False = every probe failed or
    raised (the broker is down — the task cannot be queued, so a revert
    is truthful)."""
    for _attempt in range(_BROKER_PROBE_ATTEMPTS):
        try:
            if engine.store.ping():
                return True
        except Exception:  # noqa: BLE001 — probe failure == unreachable
            pass
        if _attempt + 1 < _BROKER_PROBE_ATTEMPTS:
            time.sleep(_BROKER_PROBE_RETRY_DELAY_SECONDS)
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
        """DISPATCH an approved run to the worker (F7; audit P1-2).

        Tri-state truthful contract — the API never conflates "the
        broker accepted the task", "the broker never received it", and
        "we do not know which":

        * 200 ``dispatched: true`` — the run is durably
          EXECUTION_REQUESTED and the publish to the broker completed.
        * 200 ``dispatched: "unknown"`` — the publish FAILED while the
          broker was reachable (a timeout after the connection was
          established). The task MAY already be queued and executing, so
          the run is NOT reverted; it stays EXECUTION_REQUESTED and is
          eligible for idempotent re-dispatch. Re-POSTing the SAME
          request is safe: it re-publishes the SAME stable task id and
          the worker's lease + terminal-state check absorb any
          duplicate.
        * 503 — the publish failed AND a reachability probe confirmed
          the broker is down: the run is atomically reverted to
          APPROVED and the API truthfully reports that nothing was
          executed.

        Duplicate handling: a FRESH (non-ambiguous, non-stale) run
        already in EXECUTION_REQUESTED is refused with 409 — exactly-once
        dispatch is preserved for the normal path; only ambiguous or
        stale dispatches are re-delivered.
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

        publish_error: Exception = None
        for _attempt in range(_PUBLISH_ATTEMPTS):
            try:
                from deployment_service.infrastructure.celery import tasks as deployment_tasks

                # The SAME stable task_id on every attempt: a retry after
                # an ambiguous timeout publishes a duplicate message that
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
                publish_error = None
                break
            except Exception as exc:  # broker down / serialization refused
                publish_error = exc
                if _attempt + 1 < _PUBLISH_ATTEMPTS:
                    time.sleep(_PUBLISH_RETRY_DELAY_SECONDS)

        if publish_error is None:
            engine.record_dispatch_outcome(run_id, dispatch_id, ambiguous=False)
            return {
                "dispatched": True,
                "run_id": run_id,
                "state": "EXECUTION_REQUESTED",
                "delivery": "at-least-once",
                "note": "poll GET /api/internal/deployments/{run_id} for the "
                        "terminal state; a dispatched run is not yet complete",
            }

        # The publish failed on every attempt. Decide the truth:
        # (a) broker down → the task cannot be queued → atomic revert;
        # (b) broker reachable → the message may be queued → ambiguous.
        if _broker_reachable(engine):
            # AMBIGUOUS: never revert. The task may already be running.
            engine.record_dispatch_outcome(run_id, dispatch_id, ambiguous=True)
            logger.error(
                "deployment dispatch AMBIGUOUS for %s: %s; run kept in "
                "EXECUTION_REQUESTED, re-dispatch is idempotent",
                run_id, type(publish_error).__name__,
            )
            return {
                "dispatched": "unknown",
                "run_id": run_id,
                "state": "EXECUTION_REQUESTED",
                "delivery": "at-least-once",
                "note": "the broker publish timed out after the connection "
                        "was established, so the task MAY already be queued "
                        "and executing. Poll the run, or re-POST this same "
                        "request: the re-dispatch is idempotent (same stable "
                        "task id; the worker absorbs duplicates).",
            }

        # Broker confirmed down: the task cannot have been queued. Revert
        # atomically; if the run moved on in the meantime, report its
        # actual state instead of "nothing was executed".
        reverted = engine.revert_dispatch(run_id, dispatch_id)
        if not reverted:
            stored = engine.store.get(run_id)
            state = (stored or {}).get("state", "UNKNOWN")
            logger.error(
                "deployment dispatch failed for %s (%s) and the run already "
                "advanced to %s; reporting current state",
                run_id, type(publish_error).__name__, state,
            )
            return {
                "dispatched": "unknown",
                "run_id": run_id,
                "state": state,
                "delivery": "at-least-once",
                "note": "the publish failed but the run had already moved on; "
                        "poll for the terminal state.",
            }
        logger.error("deployment dispatch failed for %s: %s", run_id, type(publish_error).__name__)
        raise HTTPException(
            status_code=503,
            detail="Execution dispatch is unavailable (broker confirmed "
                   "unreachable); the run remains APPROVED and nothing was "
                   "executed.",
        ) from publish_error

    return application


app = create_app()

#: Module-level convenience reference to the running app's engine (the
#: same object as ``app.state.engine``) — kept so test/tool code that
#: imports the module can swap collaborators without app plumbing.
engine = app.state.engine
