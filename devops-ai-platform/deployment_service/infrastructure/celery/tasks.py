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
celery_app = Celery("deployment_tasks", broker=f"redis://{REDIS_HOST}:{REDIS_PORT}/0")

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
