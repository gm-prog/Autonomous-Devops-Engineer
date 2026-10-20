"""Deployment Celery tasks — worker-owned execution (Phase 8.8A
Correction-1, F5/F7).

This module is the asynchronous execution seam. The API validates,
persists a durable run in EXECUTION_REQUESTED and enqueues; THIS task
is the only thing that executes. It:

* short-circuits redelivered tasks for runs already in a terminal
  state — the persisted outcome is returned, nothing is re-run
  (at-least-once delivery is honest, not dangerous);
* acquires the run's fenced execution lease — a duplicate concurrent
  task finds the lease held and refuses without touching the run, so
  N duplicate dispatches yield exactly one active executor;
* invokes the real ``DeploymentEngine`` under the lease: every side
  effect is fenced, losing the lease cancels the running sandbox and
  marks the run LEASE_LOST (the stale worker commits nothing further).

Delivery semantics (honest, documented):
  * Celery provides AT-LEAST-ONCE delivery here. Exactly-once is NOT
    claimed; idempotency comes from the durable run state + the
    fenced lease, not from the broker.
  * Worker-loss behavior is EXPLICIT (audit P1): the message is acked
    only after the task completes (task_acks_late), a lost pool child
    rejects+requeues its in-flight task (task_reject_on_worker_lost),
    and a whole-worker crash leaves the message unacked, so the next
    running consumer restores it after the visibility timeout
    (3600s > the ~2790s worst-case bounded run, so healthy slow runs
    are never spuriously redelivered). Crash recovery therefore takes
    at most one visibility timeout; a stuck owner is overtaken sooner
    via the 120s lease TTL. Proven by tests/test_celery_crash_recovery.py
    (real Redis broker, real worker kill/restart).
  * a successful call returns a typed result reflecting the run's REAL
    final state (SUCCEEDED / ROLLED_BACK / FAILED / LEASE_LOST /
    BLOCKED / ALREADY_EXECUTING);
  * a refused execution (not approved, execution disabled, hash
    mismatch, sandbox BLOCKED, ...) returns a typed BLOCKED result —
    the run is NEVER left in an "accepted/completed" state by a failed
    dispatch;
  * any unexpected worker exception is mapped to a typed FAILED result.
"""

import logging
from typing import Any, Dict, List, Optional

from celery import Celery
import os
import sys
from pathlib import Path

# Worker import bootstrap: celery imports this module (-A target)
# inside a ``cwd_in_path()`` context (celery/utils/imports.py) that
# adds the cwd to sys.path TEMPORARILY and removes it again right
# after the import. The task's deferred imports
# (deployment_engine -> deployment_run -> shared_kernel) therefore
# cannot rely on the cwd entry: pin the platform root UNCONDITIONALLY
# (a permanent list entry, derived from THIS file's location, never
# from the process cwd). The ``not in sys.path`` guard would be wrong
# here — it would see celery's temporary cwd entry and skip the pin,
# which celery then removes.
_PLATFORM_ROOT = str(Path(__file__).resolve().parents[3])
sys.path.insert(0, _PLATFORM_ROOT)

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")

# ---------------------------------------------------------------------
# Explicit broker / worker-loss semantics (independent audit, P1).
#
# Celery provides AT-LEAST-ONCE delivery here. Exactly-once is NOT
# claimed and cannot be: on a Redis broker a publish/ack can be lost
# or redelivered. Safety comes from the durable run record + the fenced
# execution lease:
#
#   * a duplicate redelivery while the lease is HELD is refused
#     without touching the run (ALREADY_EXECUTING);
#   * a redelivery after a worker CRASH resumes the orphaned in-flight
#     run idempotently — its side effects are convergent (the exact
#     approved plan, declarative kubectl apply); see
#     DeploymentEngine.execute's F5 crash-redelivery contract;
#   * a redelivery of a TERMINAL run returns the persisted outcome.
#
# For any of that to work the message must stay UNACKED while the task
# executes; with the Celery default (ack on receipt) a killed worker's
# message is already acknowledged and is LOST — the run then sits in
# EXECUTION_REQUESTED/DEPLOYING forever while the API already reported
# "dispatched". These settings close that gap.
# ---------------------------------------------------------------------

#: Worst-case bounded single execution, every leg at its budget plus a
#: full rollback: terraform init 180 + validate 120 + plan 240 +
#: apply 600; k8s apply 300 + rollout 330; rollback rollout-undo 180 +
#: re-plan 240 + re-apply 600. ≈ 2790 seconds.
_MAX_BOUNDED_EXECUTION_SECONDS = 2790

#: A dead worker's in-flight message is restored to the queue by any
#: running consumer once it is older than this (kombu redis transport,
#: QoS.restore_visible). It MUST exceed the worst-case bounded run so a
#: healthy slow run is never spuriously redelivered; crash recovery
#: therefore takes at most one visibility timeout, while a STUCK owner
# is overtaken much sooner through the 120s lease TTL (fencing).
_BROKER_VISIBILITY_TIMEOUT_SECONDS = 3600


def broker_semantics(
    visibility_timeout: int = _BROKER_VISIBILITY_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """The explicit at-least-once delivery contract (audit P1).

    Shared by the production task app and the crash-recovery
    integration test (which shortens the visibility timeout so a kill
    is recoverable within test wall-clock).
    """
    return {
        # Ack AFTER the task completes, never on receipt: a worker that
        # dies mid-execution leaves the message unacked, so it can be
        # redelivered (see module comment).
        "task_acks_late": True,
        # A task that raises (never expected — every outcome is a typed
        # return) is NOT acked: it may be redelivered, and the
        # terminal-state + lease checks make that safe.
        "task_acks_on_failure_or_timeout": False,
        # Prefork fast path: if a pool child is lost but the worker
        # survives, its in-flight task is rejected+requeued immediately
        # (whole-process loss is covered by the visibility timeout).
        "task_reject_on_worker_lost": True,
        # One in-flight task per worker child: a dying worker takes at
        # most one message into the grave; bursts queue, never prefetch.
        "worker_prefetch_multiplier": 1,
        # The truth lives in the durable run record, not a result
        # backend; nothing reads AsyncResult.
        "task_ignore_result": True,
        # Explicit startup broker-retry behavior (no implicit default).
        "broker_connection_retry_on_startup": True,
        "broker_transport_options": {
            "visibility_timeout": visibility_timeout,
        },
    }


celery_app = Celery("deployment_tasks", broker=f"redis://{REDIS_HOST}:{REDIS_PORT}/0")
celery_app.conf.update(broker_semantics())

logger = logging.getLogger("DeploymentCeleryTasks")

#: The engine's terminal deployment states and the task-level status
#: each maps to. Anything not DEPLOYED is reported as a non-success.
_STATUS_BY_STATE = {
    "DEPLOYED": "SUCCEEDED",
    "ROLLED_BACK": "ROLLED_BACK",
    "ROLLBACK_FAILED": "FAILED",
    "DEPLOYMENT_FAILED": "FAILED",
    "DRY_RUN_FAILED": "FAILED",
    "VALIDATION_FAILED": "FAILED",
    "LEASE_LOST": "LEASE_LOST",
}

#: Every terminal state: a task redelivered for one of these must NOT
#: start another execution.
_TERMINAL_STATES = frozenset({
    "DEPLOYED", "DEPLOYMENT_FAILED", "ROLLED_BACK", "ROLLBACK_FAILED",
    "DRY_RUN_FAILED", "VALIDATION_FAILED", "LEASE_LOST",
})


def _result(status: str, run_id: Optional[str], *, dispatched: bool, **extra) -> Dict[str, Any]:
    """Bounded, typed, sanitized result — never a success-shaped string."""
    result: Dict[str, Any] = {
        "status": status,
        "run_id": run_id,
        "dispatched": dispatched,
    }
    result.update(extra)
    return result


@celery_app.task(name="tasks.execute_iac_deployment")
def execute_iac_deployment(
    run_id: str,
    artifact_hash: str,
    plan_hash: str,
    namespace: str = "devops-production-namespace",
    healthcheck_url: str = "",
    previous_good_terraform_tf: str = "",
    dockerfile: str = "",
    k8s_yaml: str = "",
    terraform_tf: str = "",
    pipeline_yaml: str = "",
    components: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Execute an APPROVED deployment run through the real engine.

    The payload here is the SAME artifact bundle the dry run was
    created from: the engine re-derives the canonical effective payload
    and re-checks its hash against the approval before touching
    anything. Idempotent under at-least-once delivery (see module
    docstring).
    """
    from deployment_service.application.services.deployment_engine import (
        DeploymentActionError,
        DeploymentEngine,
        DeploymentExecutionLeaseHeld,
        LeaseLostDuringExecutionError,
    )
    from deployment_service.domain.value_objects.deployment_state import (
        DeploymentState,
    )

    payload = {
        "dockerfile": dockerfile,
        "k8s_yaml": k8s_yaml,
        "terraform_tf": terraform_tf,
        "pipeline_yaml": pipeline_yaml,
        "components": components
        or ["dockerfile", "kubernetes", "terraform", "pipeline"],
    }

    try:
        engine = DeploymentEngine()
        # Idempotency (E.7/F7.3): a redelivered task for a finished run
        # returns the persisted outcome and starts NOTHING.
        stored = engine.store.get(run_id)
        if stored:
            stored_state = stored.get("state", "")
            if stored_state in _TERMINAL_STATES:
                return _result(
                    _STATUS_BY_STATE.get(stored_state, "FAILED"),
                    run_id,
                    dispatched=False,
                    idempotent_replay=True,
                    final_state=stored_state,
                )
        run = engine.execute(
            run_id,
            payload,
            artifact_hash,
            plan_hash,
            namespace,
            healthcheck_url,
            previous_good_terraform_tf,
        )
    except DeploymentExecutionLeaseHeld:
        # A concurrent duplicate: the run is executing under another
        # owner's lease. Nothing was started here — report the truth.
        return _result(
            "ALREADY_EXECUTING",
            run_id,
            dispatched=False,
            error_code="LEASE_HELD_BY_OTHER_OWNER",
        )
    except LeaseLostDuringExecutionError as exc:
        # The engine already marked the run LEASE_LOST (fenced).
        return _result(
            "LEASE_LOST",
            run_id,
            dispatched=True,
            error_code="LEASE_LOST",
            error=str(exc),
            final_state="LEASE_LOST",
        )
    except DeploymentActionError as exc:
        # Typed refusal: the run's state is whatever it already
        # legitimately is; this dispatch changes nothing.
        return _result(
            "BLOCKED",
            run_id,
            dispatched=False,
            error_code="EXECUTION_REFUSED",
            error=str(exc),
        )
    except Exception as exc:  # noqa: BLE001 — worker exceptions map to typed failure
        logger.exception("deployment execution failed for run %s", run_id)
        return _result(
            "FAILED",
            run_id,
            dispatched=False,
            error_code=type(exc).__name__,
            error=str(exc),
        )

    state = run.state.value if hasattr(run.state, "value") else str(run.state)
    status = _STATUS_BY_STATE.get(state, "FAILED")
    return _result(
        status,
        run_id,
        dispatched=True,
        final_state=state,
        error=getattr(run, "error", None),
    )
