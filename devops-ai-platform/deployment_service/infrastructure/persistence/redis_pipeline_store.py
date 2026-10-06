
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

    def save(self, run: DeploymentRun) -> None:
        self.client.setex(
            f"deployment_run:{run.id}",
            86400,
            json.dumps(run.to_dict()),
        )

    def get(self, run_id: str) -> Optional[dict]:
        raw = self.client.get(f"deployment_run:{run_id}")
        return json.loads(raw) if raw else None

    def acquire_lock(self, run_id: str, ttl_seconds: int = 900) -> bool:
        return bool(
            self.client.set(
                f"deployment_lock:{run_id}",
                "1",
                nx=True,
                ex=ttl_seconds,
            )
        )

    def release_lock(self, run_id: str) -> None:
        self.client.delete(f"deployment_lock:{run_id}")
