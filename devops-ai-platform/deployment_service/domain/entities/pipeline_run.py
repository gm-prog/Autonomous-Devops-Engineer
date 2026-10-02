from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class PipelineRun:
    """PipelineRun Entity representing a historic or active pipeline execution cycle."""
    id: str
    status: str # Started, InProgress, Completed, Failed
    triggered_by: str # e.g. "GithubPushEvent", "OperatorTrigger"
    started_at: datetime = datetime.utcnow()
    finished_at: Optional[datetime] = None
    error_log: Optional[str] = None

    def elapsed_seconds(self) -> float:
        end = self.finished_at or datetime.utcnow()
        return (end - self.started_at).total_seconds()
