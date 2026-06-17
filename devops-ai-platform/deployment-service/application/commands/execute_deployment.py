import hashlib
import logging
from ...domain.repository_interface import PipelineRepositoryInterface
from ...domain.exceptions import DeploymentExecutionException

logger = logging.getLogger("ExecuteDeploymentCommandHandler")

class ExecuteDeploymentCommand:
    def __init__(self, pipeline_id: str, operator_email: str, idempotency_key: str):
        self.pipeline_id = pipeline_id
        self.operator_email = operator_email
        self.idempotency_key = idempotency_key

    def get_idempotency_hash(self) -> str:
        return hashlib.sha256(
            f"{self.pipeline_id}:{self.idempotency_key}".encode()
        ).hexdigest()

class ExecuteDeploymentCommandHandler:
    """Dispatches execution stages, instantiates trace states, and runs jobs via Celery task runners."""
    def __init__(self, pipeline_repo: PipelineRepositoryInterface):
        self.repo = pipeline_repo
        # Memory-based cache simulating DB limits for deployment_idempotency checks
        self._idempotency_cache = {}

    def handle(self, cmd: ExecuteDeploymentCommand) -> str:
        # Check idempotency hash to prevent double-submitting triggers
        cmd_hash = cmd.get_idempotency_hash()
        if cmd_hash in self._idempotency_cache:
            cached_run_id = self._idempotency_cache[cmd_hash]
            logger.info(f"[IDEMPOTENCY_DUPLICATE] Query matched cached state {cmd_hash}. Re-routing back to run ID: {cached_run_id}")
            return cached_run_id

        pipeline = self.repo.find_pipeline_by_id(cmd.pipeline_id)
        if not pipeline:
            raise ValueError(f"Pipeline with ID {cmd.pipeline_id} is missing.")

        run = pipeline.instantiate_run(triggered_by=cmd.operator_email)
        self.repo.save_pipeline(pipeline)

        # Cache successfully registered run trace
        self._idempotency_cache[cmd_hash] = run.id
        logger.info(f"[IDEMPOTENCY_REGISTER] Processed and securely cataloged deployment key {cmd.idempotency_key} into hash: {cmd_hash}")

        # Trigger asynchronous worker threads mapping task workloads
        # In actual platforms, we call celery tasks setup:
        # celery_app.send_task("tasks.execute_iac_deployment", args=[run.id])
        return run.id

class DeploymentExecutionException(Exception):
    pass

