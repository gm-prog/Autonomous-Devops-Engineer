import json
import os
from typing import Optional

import redis

from deployment_service.domain.entities.deployment_run import DeploymentRun

# Independent audit (P1-2 follow-up): optimistic concurrency for the run
# document. The document's monotonic ``revision`` lives in a SEPARATE
# counter key (``deployment_run:<id>:rev``) that every durable write
# bumps inside the SAME Lua script that performs the write (atomic):
#
# * ``save``             — unconditional write: INCR the counter, SET the
#                          document bytes AS-IS (single-writer phases:
#                          dry run, approval, worker state advances).
# * ``save_cas``         — writes ONLY if the counter still equals the
#                          writer's read (the APPROVED ->
#                          EXECUTION_REQUESTED dispatch claim,
#                          re-dispatch updates); the loser's write is
#                          refused and the document stands untouched.
# * ``cas_run_document`` — like save_cas, additionally guarded on state,
#                          dispatch identity and the absence of a worker
#                          fence (revert, outcome bookkeeping).
# * the lease's fenced   — also bumps the counter, so a worker state
#   commit (COMMIT_SCRIPT)   advance is visible to every API-side claim.
#
# A writer that read revision N can never overwrite a document written
# after its read (counter > N), regardless of which process wrote it —
# stale whole-document writes are impossible by construction. The run
# document itself is never decoded/re-encoded by the write path (only
# read for condition checks), so no serialization artifact can corrupt
# it. The ``revision`` field inside the document is informational; the
# counter key is the source of truth (get() merges it into the payload).
_RUN_TTL_SECONDS = 86400


def _run_key(run_id: str) -> str:
    return f"deployment_run:{run_id}"


def _rev_key(run_id: str) -> str:
    return f"deployment_run:{run_id}:rev"


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

    # Unconditional write: bump the revision counter and store the
    # document bytes unchanged, in one atomic script.
    SAVE_BUMP_SCRIPT = """
redis.call('INCR', KEYS[2])
redis.call('EXPIRE', KEYS[2], tonumber(ARGV[2]))
redis.call('SET', KEYS[1], ARGV[1], 'EX', tonumber(ARGV[2]))
return redis.call('GET', KEYS[2])
"""

    # Optimistic-concurrency claim: the write applies ONLY if the
    # revision counter still equals the caller's read (nothing was
    # written in between). Returns 1 (applied) or 0 (lost).
    SAVE_CAS_SCRIPT = """
local rev = redis.call('GET', KEYS[2])
if (tonumber(rev) or 0) ~= tonumber(ARGV[2]) then return 0 end
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
redis.call('INCR', KEYS[2])
redis.call('EXPIRE', KEYS[2], tonumber(ARGV[3]))
redis.call('SET', KEYS[1], ARGV[1], 'EX', tonumber(ARGV[3]))
return 1
"""

    # Dispatch-scoped atomic revert / outcome bookkeeping (audit P1-2):
    # the document is replaced only if it is still in the expected
    # state, still carries the expected dispatch identity, the revision
    # counter still equals the caller's read, and NO worker fence is
    # active. The document bytes are stored unchanged. Returns 1 or 0.
    REVERT_DISPATCH_CAS = """
local doc = redis.call('GET', KEYS[1])
if not doc then return 0 end
local run = cjson.decode(doc)
if run.state ~= ARGV[2] then return 0 end
local rev = redis.call('GET', KEYS[3])
if (tonumber(rev) or 0) ~= tonumber(ARGV[3]) then return 0 end
local execution = run.execution or {}
local dispatch = execution.dispatch or {}
if dispatch.dispatch_id ~= ARGV[4] then return 0 end
if redis.call('EXISTS', KEYS[2]) == 1 then return 0 end
redis.call('INCR', KEYS[3])
redis.call('EXPIRE', KEYS[3], tonumber(ARGV[5]))
redis.call('SET', KEYS[1], ARGV[1], 'EX', tonumber(ARGV[5]))
return 1
"""

    def save(self, run: DeploymentRun) -> None:
        new_rev = self.client.eval(
            self.SAVE_BUMP_SCRIPT,
            2,
            _run_key(run.id),
            _rev_key(run.id),
            json.dumps(run.to_dict()),
            str(_RUN_TTL_SECONDS),
        )
        # Keep the in-memory object consistent with the stored revision
        # (the counter is the source of truth).
        try:
            run.revision = int(new_rev)
        except (TypeError, ValueError):
            pass

    def save_cas(self, run_id: str, expected_revision: int, run: DeploymentRun) -> bool:
        """Atomically persist ``run`` only if the revision counter is
        still at ``expected_revision``. Returns False (never raises)
        when the claim was lost to a concurrent writer — the stored
        document then stands untouched."""
        try:
            ok = self.client.eval(
                self.SAVE_CAS_SCRIPT,
                2,
                _run_key(run_id),
                _rev_key(run_id),
                json.dumps(run.to_dict()),
                str(int(expected_revision)),
                str(_RUN_TTL_SECONDS),
            )
            if ok:
                run.revision = int(expected_revision) + 1
            return bool(ok)
        except Exception:  # noqa: BLE001 - store blip: report, don't raise
            return False

    def get(self, run_id: str) -> Optional[dict]:
        raw = self.client.get(_run_key(run_id))
        if not raw:
            return None
        payload = json.loads(raw)
        # Merge the authoritative revision (counter key). A document
        # written before the counter existed has no counter: revision 0,
        # which the first CAS-claim treats as "expect 0" and bumps.
        rev = self.client.get(_rev_key(run_id))
        payload["revision"] = int(rev) if rev else int(payload.get("revision") or 0)
        return payload

    def get_revision(self, run_id: str) -> int:
        """The authoritative document revision (0 when unknown)."""
        rev = self.client.get(_rev_key(run_id))
        if rev is not None:
            return int(rev)
        raw = self.client.get(_run_key(run_id))
        if raw:
            try:
                return int(json.loads(raw).get("revision") or 0)
            except (ValueError, TypeError):
                return 0
        return 0

    def cas_run_document(
        self,
        run_id: str,
        expected_state: str,
        expected_dispatch_id: str,
        expected_revision: int,
        new_run: DeploymentRun,
    ) -> bool:
        """Atomically persist ``new_run`` guarded on state + dispatch
        identity + revision counter + absence of a worker fence.
        Returns False (never raises) when the run moved on; callers that
        get False must report the run's CURRENT state, never assume
        their write applied."""
        from deployment_service.infrastructure.persistence.execution_lease import (
            active_fence_key,
        )

        try:
            ok = self.client.eval(
                self.REVERT_DISPATCH_CAS,
                3,
                _run_key(run_id),
                active_fence_key(run_id),
                _rev_key(run_id),
                json.dumps(new_run.to_dict()),
                expected_state,
                str(int(expected_revision)),
                expected_dispatch_id,
                str(_RUN_TTL_SECONDS),
            )
            if ok:
                new_run.revision = int(expected_revision) + 1
            return bool(ok)
        except Exception:  # noqa: BLE001 - store blip: report, don't raise
            return False
