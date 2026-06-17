import logging
from ....shared_kernel.domain.events import RepositoryImportedEvent
from ..commands.execute_agent_task import ExecuteAgentTaskCommand, ExecuteAgentTaskCommandHandler

logger = logging.getLogger("OnRepoImportedEventHandler")

class OnRepositoryImportedEventHandler:
    """Listens to message queues for RepositoryImportedEvent to trigger autonomous AST scans."""
    def __init__(self, task_handler: ExecuteAgentTaskCommandHandler):
        self.handler = task_handler

    def handle_event(self, event: RepositoryImportedEvent):
        logger.info(f"[AMQP_CONSUMER_TRIGGERED] Received code register entry notification for {event.aggregate_id}.")
        payload = event.payload
        repo_name = payload.get("repo_name", "Unknown-VCS")
        
        # Dispatch command to generate containers based on parsed properties
        cmd = ExecuteAgentTaskCommand(
            raw_prompt=f"Assess repository {repo_name}. Prepare high quality containerisation Dockerfiles and configuration structures.",
            role="DevOpsArchitect"
        )
        self.handler.handle(cmd)
