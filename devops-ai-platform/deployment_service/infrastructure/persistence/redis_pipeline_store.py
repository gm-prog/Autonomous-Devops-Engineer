import json
import os
from typing import Optional

import redis

from deployment_service.domain.entities.deployment_run import DeploymentRun


class RedisPipelineStore:
    def __init__(self):
        self.client = redis.Redis(
            host=os.getenv("REDIS_HOST", "redis"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            db=1,
            decode_responses=True,
        )

    def ping(self) -> bool:
        """Broker readiness probe for the API health contract (F1)."""
        return bool(self.client.ping())

    def save(self, run: DeploymentRun) -> None:
        self.client.setex(
            f"deployment_run:{run.id}",
            86400,
            json.dumps(run.to_dict()),
        )

    def get(self, run_id: str) -> Optional[dict]:
        raw = self.client.get(f"deployment_run:{run_id}")
        return json.loads(raw) if raw else None
