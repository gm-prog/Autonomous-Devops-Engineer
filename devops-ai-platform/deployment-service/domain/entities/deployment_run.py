
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from domain.value_objects.deployment_state import DeploymentState, transition

@dataclass
class DeploymentRun:
    id: str
    repository_id: int
    repository_name: str
    state: DeploymentState = DeploymentState.CREATED
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    validation: Dict = field(default_factory=dict)
    terraform_plan: Dict = field(default_factory=dict)
    kubernetes_dry_run: Dict = field(default_factory=dict)
    logs: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def move(self, target: DeploymentState, error: Optional[str] = None) -> None:
        self.state = transition(self.state, target)
        self.updated_at = datetime.now(timezone.utc)
        if error:
            self.error = error

    def add_log(self, line: str) -> None:
        self.logs.append(line)
        self.updated_at = datetime.now(timezone.utc)
