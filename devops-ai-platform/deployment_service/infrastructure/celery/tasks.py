"""Deployment Celery tasks — REAL orchestration dispatch (Phase 8.8A).

This module is the asynchronous execution seam. It contains NO sleep-based
fakes and NO fake-healthy logging: the task invokes the real
``DeploymentEngine``, which verifies the APPROVED state, re-verifies the
approved artifact/plan hashes, applies the exact approved plan, performs
the Kubernetes apply under the approved execution identity, runs the
post-deployment health check and persists every state transition through
the engine's Redis store.

Delivery semantics (honest, documented):
  * a successful call returns a typed result reflecting the run's REAL
    final state (SUCCEEDED / ROLLED_BACK / FAILED);
  * a refused execution (not approved, execution disabled, hash mismatch,
    sandbox BLOCKED, ...) returns a typed BLOCKED result — the run is
    NEVER left in an "accepted/completed" state by a failed dispatch;
  * any unexpected worker exception is mapped to a typed FAILED result;
  * exactly-once delivery is NOT claimed: Celery provides at-least-once
    semantics here; durability of the RUN STATE comes from the engine's
    store, and the engine's execution lock makes a concurrent duplicate
    dispatch refuse rather than double-execute.
"""

import logging
from typing import Any, Dict, List, Optional

from celery import Celery
import os

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
celery_app = Celery("deployment_tasks", broker=f"redis://{REDIS_HOST}:{REDIS_PORT}/0")

logger = logging.getLogger("DeploymentCeleryTasks")

#: The engine's terminal deployment states and the task-level status each
#: maps to. Anything not DEPLOYED is reported as a non-success.
_STATUS_BY_STATE = {
    "DEPLOYED": "SUCCEEDED",
    "ROLLED_BACK": "ROLLED_BACK",
    "ROLLBACK_FAILED": "FAILED",
    "DEPLOYMENT_FAILED": "FAILED",
    "DRY_RUN_FAILED": "FAILED",
    "VALIDATION_FAILED": "FAILED",
}


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

    The payload here is the SAME artifact bundle the dry run was created
    from: the engine re-derives the canonical effective payload and
    re-checks its hash against the approval before touching anything.
    """
    from deployment_service.application.services.deployment_engine import (
        DeploymentActionError,
        DeploymentEngine,
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
        run = engine.execute(
            run_id,
            payload,
            artifact_hash,
            plan_hash,
            namespace,
            healthcheck_url,
            previous_good_terraform_tf,
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
