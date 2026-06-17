from typing import List, Optional
from datetime import datetime
from ..entities.pipeline_run import PipelineRun

class PipelineAggregate:
    """
    Pipeline Aggregate Root.
    Orchestrates infrastructure compiles, secrets verification, 
    Terraform deployments, and tracks individual execution instances.
    """
    def __init__(self, id: str, name: str):
        self.id = id
        self.name = name
        self.steps = ["Lint", "CompileContainer", "TerraformPlan", "KubectlApply"]
        self.runs: List[PipelineRun] = []
        self.status = "Inactive"

    def instantiate_run(self, triggered_by: str) -> PipelineRun:
        self.status = "Running"
        run_id = f"run_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        new_run = PipelineRun(id=run_id, status="Started", triggered_by=triggered_by)
        self.runs.append(new_run)
        return new_run

    def update_run_state(self, run_id: str, status: str, error: Optional[str] = None):
        for r in self.runs:
            if r.id == run_id:
                r.status = status
                r.error_log = error
                if status in ["Completed", "Failed"]:
                    r.finished_at = datetime.utcnow()
                    self.status = "Idle"
                break
