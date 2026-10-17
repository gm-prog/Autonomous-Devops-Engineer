from typing import Any, Dict, List, Optional
from datetime import datetime
from ..entities.pipeline_run import PipelineRun

#: The only run states this aggregate accepts. Arbitrary strings can no
#: longer be assigned: a terminal "Completed" in particular must be
#: backed by explicit per-operation evidence (Phase 8.8A).
_VALID_RUN_STATES = ("Started", "Running", "Completed", "Failed", "RolledBack")


class PipelineAggregate:
    """
    Pipeline Aggregate Root.
    Orchestrates infrastructure compiles, secrets verification,
    Terraform deployments, and tracks individual execution instances.

    Phase 8.8A: terminal states are guarded. ``update_run_state`` accepts
    only the whitelisted states and REFUSES "Completed" unless the caller
    supplies ``verified_operations`` — explicit evidence that every
    required operation actually completed. The previous version assigned
    any status string from any caller, so a pipeline could be marked
    Completed without any proof of work; that false-success property is
    removed.
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

    def update_run_state(
        self,
        run_id: str,
        status: str,
        error: Optional[str] = None,
        verified_operations: Optional[Dict[str, Any]] = None,
    ) -> None:
        if status not in _VALID_RUN_STATES:
            raise ValueError(f"unknown pipeline run state: {status!r}")
        if status == "Completed" and not verified_operations:
            raise ValueError(
                "Completed requires proof that every required operation "
                "completed (verified_operations)"
            )
        for r in self.runs:
            if r.id == run_id:
                r.status = status
                r.error_log = error
                if status in ["Completed", "Failed", "RolledBack"]:
                    r.finished_at = datetime.utcnow()
                    self.status = "Idle"
                break
