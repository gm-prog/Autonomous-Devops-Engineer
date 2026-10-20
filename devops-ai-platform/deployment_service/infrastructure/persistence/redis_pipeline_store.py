import json
import os
import time
from typing import Any, Dict, List, Optional

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
# Precise contract: EVERY durable write atomically ADVANCES the
# revision; the concurrency-sensitive dispatch writes (save_cas claims,
# cas_run_document revert/outcome) additionally CHECK it, so a stale
# dispatch write is refused — a dispatch writer that read revision N
# cannot apply after the counter passed N. An unconditional save (a
# single-writer phase such as dry-run/approval/worker state advances)
# does not check, but it advances the counter, so it invalidates any
# dispatch CAS based on an earlier read. The run document itself is
# never decoded/re-encoded by the write path (only read for condition
# checks), so no serialization artifact can corrupt it. The ``revision``
# field inside the document is informational; the counter key is the
# source of truth (get() merges it into the payload).
_RUN_TTL_SECONDS = 86400


def _run_key(run_id: str) -> str:
    return f"deployment_run:{run_id}"


def _rev_key(run_id: str) -> str:
    return f"deployment_run:{run_id}:rev"


def _journal_key(run_id: str) -> str:
    return f"deployment_run:{run_id}:dispatch_journal"


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

    # Dispatch-scoped atomic revert / outcome bookkeeping (audit P1-2,
    # third round): the document is replaced only if it is still in the
    # expected state, still carries the expected dispatch identity, the
    # revision counter still equals the caller's read, and NO worker
    # fence is active. With ARGV[6]=="1" (revert path) it ADDITIONALLY
    # requires:
    #  * the run-document history flag may_have_been_published is false,
    #  * the DURABLE ATTEMPT JOURNAL (KEYS[4], written before every
    #    send) records at least one attempt for this dispatch and EVERY
    #    such attempt is terminal PRE_SEND_FAILED. A missing journal, a
    #    pending PUBLISHING entry, an AMBIGUOUS entry, or a PUBLISHED
    #    entry all refuse the revert — including when a worker's active
    #    fence made the run-document history write impossible earlier
    #    (the journal is a separate key the fence cannot block).
    # The document bytes are stored unchanged. Returns 1 or 0.
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
if ARGV[6] == '1' then
  if dispatch.may_have_been_published then return 0 end
  local entries = redis.call('HGETALL', KEYS[4])
  local saw_attempt = false
  for i = 1, #entries, 2 do
    local entry = cjson.decode(entries[i+1])
    if entry.dispatch_id == ARGV[4] then
      saw_attempt = true
      if entry.state ~= 'PRE_SEND_FAILED' then return 0 end
    end
  end
  if not saw_attempt then return 0 end
end
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
        require_not_maybe_published: bool = False,
    ) -> bool:
        """Atomically persist ``new_run`` guarded on state + dispatch
        identity + revision counter + absence of a worker fence. With
        ``require_not_maybe_published`` (the revert path) the dispatch
        history must additionally prove that no publish attempt may
        have reached the broker. Returns False (never raises) when the
        run moved on or the history forbids the write; callers that get
        False must report the run's CURRENT state, never assume their
        write applied."""
        from deployment_service.infrastructure.persistence.execution_lease import (
            active_fence_key,
        )

        try:
            ok = self.client.eval(
                self.REVERT_DISPATCH_CAS,
                4,
                _run_key(run_id),
                active_fence_key(run_id),
                _rev_key(run_id),
                _journal_key(run_id),
                json.dumps(new_run.to_dict()),
                expected_state,
                str(int(expected_revision)),
                expected_dispatch_id,
                str(_RUN_TTL_SECONDS),
                "1" if require_not_maybe_published else "0",
            )
            if ok:
                new_run.revision = int(expected_revision) + 1
            return bool(ok)
        except Exception:  # noqa: BLE001 - store blip: report, don't raise
            return False

    # ------------------------------------------------------------ journal
    # Independent audit (P1-2, third round): the DURABLE ATTEMPT JOURNAL.
    # A separate hash key per run (NOT the run document, NOT fenced):
    # each publish attempt is journaled PUBLISHING BEFORE the send, then
    # transitioned to PUBLISHED / PRE_SEND_FAILED / AMBIGUOUS. The fence
    # an active worker creates cannot block it, so a fast worker cannot
    # make the audit trail disappear; a crashed API leaves a PUBLISHING
    # entry, which the server-side revert treats as "may have been
    # published" (never as "nothing was executed"). Revert is possible
    # only when every journaled attempt for the dispatch is terminal
    # PRE_SEND_FAILED (checked atomically in REVERT_DISPATCH_CAS).
    #: Attempt states (terminal states are marked with ``_`` here).
    ATTEMPT_PUBLISHING = "PUBLISHING"      # in flight (or crashed mid-flight)
    ATTEMPT_PUBLISHED = "PUBLISHED"        # the broker accepted the message
    ATTEMPT_PRE_SEND_FAILED = "PRE_SEND_FAILED"  # provably never sent
    ATTEMPT_AMBIGUOUS = "AMBIGUOUS"        # failed, cannot be proven pre-send

    def journal_dispatch_attempt(
        self,
        run_id: str,
        dispatch_id: str,
        attempt_id: str,
        state: str,
    ) -> bool:
        """Durably record one publish attempt transition. Returns False
        (never raises) on a store failure — callers must then fail
        closed (do not publish an untracked attempt; treat the attempt
        as pending)."""
        payload = json.dumps({
            "dispatch_id": dispatch_id,
            "state": state,
            "at": time.time(),
        })
        try:
            key = _journal_key(run_id)
            with self.client.pipeline() as pipe:
                pipe.hset(key, attempt_id, payload)
                pipe.expire(key, _RUN_TTL_SECONDS)
                pipe.execute()
            return True
        except Exception:  # noqa: BLE001 - store blip: report, don't raise
            return False

    def read_dispatch_journal(
        self, run_id: str, dispatch_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """The journal entries (optionally filtered to one dispatch).
        Returns [] on a store failure — callers decide the
        fail-closed interpretation."""
        try:
            raw = self.client.hgetall(_journal_key(run_id)) or {}
        except Exception:  # noqa: BLE001
            return []
        entries: List[Dict[str, Any]] = []
        for value in raw.values():
            try:
                entry = json.loads(value)
            except (TypeError, ValueError):
                continue
            if dispatch_id is None or entry.get("dispatch_id") == dispatch_id:
                entries.append(entry)
        return entries

    def all_attempts_pre_send_failed(self, run_id: str, dispatch_id: str) -> bool:
        """True only when the journal records at least one attempt for
        this dispatch and EVERY one is terminal PRE_SEND_FAILED.
        An empty journal (or a store failure) is NOT proof of
        non-publication — it returns False (fail closed)."""
        entries = self.read_dispatch_journal(run_id, dispatch_id)
        return bool(entries) and all(
            e.get("state") == self.ATTEMPT_PRE_SEND_FAILED for e in entries
        )

    def has_unresolved_attempt(self, run_id: str, dispatch_id: str) -> bool:
        """True when the journal holds a PUBLISHING (in flight / crashed
        mid-flight) or AMBIGUOUS attempt for this dispatch — the
        dispatch outcome is unconfirmed and idempotent re-dispatch is
        safe (same stable task id; the worker absorbs duplicates)."""
        entries = self.read_dispatch_journal(run_id, dispatch_id)
        return any(
            e.get("state") in (self.ATTEMPT_PUBLISHING, self.ATTEMPT_AMBIGUOUS)
            for e in entries
        )
