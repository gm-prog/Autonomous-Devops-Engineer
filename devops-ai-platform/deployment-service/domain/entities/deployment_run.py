
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from domain.value_objects.deployment_state import DeploymentState, transition


def _parse_datetime(value: Optional[str], fallback: datetime) -> datetime:
    if not value:
        return fallback
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass
class DeploymentRun:
    id: str
    repository_id: int
    repository_name: str
    requested_by: Optional[str] = None
    state: DeploymentState = DeploymentState.CREATED
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    validation: Dict[str, Any] = field(default_factory=dict)
    terraform_plan: Dict[str, Any] = field(default_factory=dict)
    kubernetes_dry_run: Dict[str, Any] = field(default_factory=dict)
    artifact_hash: str = ""
    plan_hash: str = ""
    approval: Dict[str, Any] = field(default_factory=dict)
    execution: Dict[str, Any] = field(default_factory=dict)
    health_check: Dict[str, Any] = field(default_factory=dict)
    rollback: Dict[str, Any] = field(default_factory=dict)
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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "repository_id": self.repository_id,
            "repository_name": self.repository_name,
            "requested_by": self.requested_by,
            "state": self.state.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "validation": self.validation,
            "terraform_plan": self.terraform_plan,
            "kubernetes_dry_run": self.kubernetes_dry_run,
            "artifact_hash": self.artifact_hash,
            "plan_hash": self.plan_hash,
            "approval": self.approval,
            "execution": self.execution,
            "health_check": self.health_check,
            "rollback": self.rollback,
            "logs": self.logs,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "DeploymentRun":
        now = datetime.now(timezone.utc)
        return cls(
            id=str(payload["id"]),
            repository_id=int(payload["repository_id"]),
            repository_name=str(payload["repository_name"]),
            requested_by=payload.get("requested_by"),
            state=DeploymentState(payload.get("state", DeploymentState.CREATED.value)),
            created_at=_parse_datetime(payload.get("created_at"), now),
            updated_at=_parse_datetime(payload.get("updated_at"), now),
            validation=payload.get("validation") or {},
            terraform_plan=payload.get("terraform_plan") or {},
            kubernetes_dry_run=payload.get("kubernetes_dry_run") or {},
            artifact_hash=payload.get("artifact_hash", ""),
            plan_hash=payload.get("plan_hash", ""),
            approval=payload.get("approval") or {},
            execution=payload.get("execution") or {},
            health_check=payload.get("health_check") or {},
            rollback=payload.get("rollback") or {},
            logs=list(payload.get("logs") or []),
            error=payload.get("error"),
        )
