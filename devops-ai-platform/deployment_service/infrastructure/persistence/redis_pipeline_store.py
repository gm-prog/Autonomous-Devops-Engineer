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

    # Independent audit (P1-2): a dispatch revert is a CONCURRENT write —
    # between the API's failed publish and its revert, a worker could
    # have taken the run (the publish may have landed after all). A plain
    # read-check-write could clobber the worker's advanced state. This
    # Lua compare-and-set reverts only if the document is STILL in the
    # expected state, STILL carries the expected dispatch record, and NO
    # worker fence is active. Mirrors the lease guard's COMMIT_SCRIPT
    # pattern.
    REVERT_DISPATCH_CAS = """
local doc = redis.call('GET', KEYS[1])
if not doc then return 0 end
local run = cjson.decode(doc)
if run.state ~= ARGV[2] then return 0 end
local execution = run.execution or {}
local dispatch = execution.dispatch or {}
if dispatch.dispatch_id ~= ARGV[3] then return 0 end
if redis.call('EXISTS', KEYS[2]) == 1 then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'EX', tonumber(ARGV[4]))
return 1
"""

    def cas_run_document(
        self,
        run_id: str,
        expected_state: str,
        expected_dispatch_id: str,
        new_run: DeploymentRun,
    ) -> bool:
        """Atomically persist ``new_run``. Returns False (never raises)
        when the run moved on: state no longer the expected one, dispatch
        identity changed, or a worker fence is active. Callers that get
        False must report the run's CURRENT state, never assume their
        write applied."""
        from deployment_service.infrastructure.persistence.execution_lease import (
            active_fence_key,
        )

        try:
            ok = self.client.eval(
                self.REVERT_DISPATCH_CAS,
                2,
                f"deployment_run:{run_id}",
                active_fence_key(run_id),
                json.dumps(new_run.to_dict()),
                expected_state,
                expected_dispatch_id,
                "86400",
            )
            return bool(ok)
        except Exception:  # noqa: BLE001 - store blip: report, don't raise
            return False
