"""Execute deployment command (legacy pipeline path) — honest boundary (Phase 8.8A).

This command targeted the legacy ``PipelineRepositoryInterface`` port,
which has NO implementation in the forward-ported slice. The previous
version kept an in-process idempotency ``dict`` (documented in its own
comments as "simulating DB limits") and returned a run ID for a dispatch
that was commented out — a success for work that never happened.

That is no longer possible here:

  * there is no in-memory idempotency cache (a process-local dict is
    never durable idempotency and never exactly-once);
  * there is no fabricated run ID — the handler cannot return a run
    identifier for an execution that will not occur;
  * the handler returns a typed BLOCKED result naming the missing
    dependency, so a caller can route to the real boundary.

The REAL execution boundary in this slice is the DeploymentEngine
(HTTP ``/api/internal/deployments/*`` in ``deployment_service.main``
and the Celery task ``tasks.execute_iac_deployment``), which persists
run state in Redis and gates execution behind a hash-bound approval.
If durable pipeline idempotency is ever required, it must be built on a
real repository implementation with tests — not on a process-local cache.
"""

import hashlib
import logging
from typing import Any, Dict, Optional

from ...domain.repository_interface import PipelineRepositoryInterface
from ...domain.exceptions import DeploymentExecutionException

logger = logging.getLogger("ExecuteDeploymentCommandHandler")


class ExecuteDeploymentCommand:
    def __init__(self, pipeline_id: str, operator_email: str, idempotency_key: str):
        self.pipeline_id = pipeline_id
        self.operator_email = operator_email
        self.idempotency_key = idempotency_key

    def get_idempotency_hash(self) -> str:
        # Kept: the hash is a well-defined identity for the request. It is
        # computed for logging/audit only — nothing in this module caches
        # on it, because no durable store exists for it.
        return hashlib.sha256(
            f"{self.pipeline_id}:{self.idempotency_key}".encode()
        ).hexdigest()


class ExecuteDeploymentCommandHandler:
    """Refuses the legacy dispatch path rather than faking it.

    The constructor still accepts the repository port for signature
    compatibility; the handler does not — and cannot — use it, because
    no implementation of ``PipelineRepositoryInterface`` exists in this
    slice. Declaring the port implemented would be a false claim.
    """

    def __init__(self, pipeline_repo: Optional[PipelineRepositoryInterface] = None):
        self.repo = pipeline_repo

    def handle(self, cmd: ExecuteDeploymentCommand) -> Dict[str, Any]:
        logger.info(
            "Legacy execute-deployment command for pipeline %s refused: "
            "no pipeline repository implementation exists in this slice "
            "(request idempotency hash %s)",
            cmd.pipeline_id,
            cmd.get_idempotency_hash()[:12],
        )
        return {
            "status": "BLOCKED",
            "error_code": "PIPELINE_REPOSITORY_NOT_IMPLEMENTED",
            "error": (
                "the legacy pipeline dispatch path is not implemented: "
                "PipelineRepositoryInterface has no implementation in this "
                "slice and no durable idempotency store backs it. Use the "
                "DeploymentEngine boundary (HTTP /api/internal/deployments "
                "or Celery task tasks.execute_iac_deployment) for real, "
                "persisted execution."
            ),
            "run_id": None,
        }
