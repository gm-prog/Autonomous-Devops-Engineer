
import json
import os
from typing import Optional
import redis

from domain.entities.deployment_run import DeploymentRun

class RedisPipelineStore:
    def __init__(self):
        self.client = redis.Redis(
            host=os.getenv("REDIS_HOST", "redis"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            db=1,
            decode_responses=True,
        )

    def save(self, run: DeploymentRun) -> None:
        payload = {
            "id": run.id,
            "repository_id": run.repository_id,
            "repository_name": run.repository_name,
            "state": run.state.value,
            "created_at": run.created_at.isoformat(),
            "updated_at": run.updated_at.isoformat(),
            "validation": run.validation,
            "terraform_plan": run.terraform_plan,
            "kubernetes_dry_run": run.kubernetes_dry_run,
            "logs": run.logs,
            "error": run.error,
        }
        self.client.setex(f"deployment_run:{run.id}", 86400, json.dumps(payload))

    def get(self, run_id: str) -> Optional[dict]:
        raw = self.client.get(f"deployment_run:{run_id}")
        return json.loads(raw) if raw else None
