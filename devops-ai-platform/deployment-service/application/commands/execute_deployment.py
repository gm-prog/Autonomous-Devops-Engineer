from ...domain.repository_interface import PipelineRepositoryInterface
from ...domain.exceptions import DeploymentExecutionException

class ExecuteDeploymentCommand:
    def __init__(self, pipeline_id: str, operator_email: str):
        self.pipeline_id = pipeline_id
        self.operator_email = operator_email

class ExecuteDeploymentCommandHandler:
    """Dispatches execution stages, instantiates trace states, and runs jobs via Celery task runners."""
    def __init__(self, pipeline_repo: PipelineRepositoryInterface):
        self.repo = pipeline_repo

    def handle(self, cmd: ExecuteDeploymentCommand) -> str:
        pipeline = self.repo.find_pipeline_by_id(cmd.pipeline_id)
        if not pipeline:
            raise ValueError(f"Pipeline with ID {cmd.pipeline_id} is missing.")

        run = pipeline.instantiate_run(triggered_by=cmd.operator_email)
        self.repo.save_pipeline(pipeline)

        # Trigger asynchronous worker threads mapping task workloads
        # In actual platforms, we call celery tasks setup:
        # celery_app.send_task("tasks.execute_iac_deployment", args=[run.id])
        return run.id
class DeploymentExecutionException(Exception):
    pass
