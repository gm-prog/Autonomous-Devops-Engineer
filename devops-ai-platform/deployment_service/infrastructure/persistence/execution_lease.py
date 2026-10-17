"""Durable execution lease with ownership, renewal and fencing (F5).

The Phase 8.8A store used a constant lock value (``"1"``) and an
unconditional ``DEL``: any process could release someone else's lock,
and the fixed 900s TTL was SHORTER than the configured maximum
operation budget (terraform apply 600s + kubernetes apply 300s +
rollout status 330s, before overhead), so a legitimately running
worker could lose its lock mid-run while a duplicate worker took over.

Design (proved against real Redis — see
``deployment_service/tests/test_execution_lease.py``):

* **acquire** — one atomic Lua script: refuse if the lease key exists,
  otherwise mint a monotonic fencing token (``INCR`` of a per-run
  counter), store a fresh cryptographic owner token with
  ``SET ... NX PX`` semantics inside the script, and publish the fence
  under the lease's own TTL. The owner token is unique per
  acquisition — never a shared constant.
* **release** — Lua compare-and-delete: the lease is deleted only if
  the stored token belongs to the releasing owner. A stale owner can
  never delete a new owner's lease (and cannot clear a newer fence).
* **renew** — Lua compare-and-expire: only the current owner extends.
* **fence** — every durable state commit of the run is a
  compare-and-set against the fence the worker captured at
  acquisition (``commit_fenced``). A worker whose lease expired and
  was re-acquired (higher fence) cannot commit state or start a
  subsequent side effect: its commits are silently rejected and the
  new owner's state wins.
* **watchdog** — a daemon thread renews at a bounded interval
  (``ttl / 3``). A renewal failure is tolerated only while the time
  since the last successful renewal is inside the TTL (the server-side
  lease may still be alive); once it exceeds the TTL the guard raises
  lease-lost, which the engine converts into a bounded cancellation of
  the running sandbox and a ``LEASE_LOST`` terminal mark.

Redis outages are never treated as "lease lost" before the TTL
elapses, and never treated as "lease kept" after it does.
"""
from __future__ import annotations

import secrets
import threading
import time
from typing import Optional


class LeaseLostError(RuntimeError):
    """The worker no longer owns the execution lease."""


#: acquire: KEYS[1]=lease, KEYS[2]=fence counter, KEYS[3]=active fence
#: ARGV[1]=owner token, ARGV[2]=ttl (ms). Returns the fence (>=1) or 0.
ACQUIRE_SCRIPT = """
if redis.call('EXISTS', KEYS[1]) == 1 then
  return 0
end
local fence = redis.call('INCR', KEYS[2])
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
redis.call('SET', KEYS[3], tostring(fence), 'PX', ARGV[2])
return fence
"""

#: release: KEYS[1]=lease, KEYS[3]=active fence; ARGV[1]=owner token,
#: ARGV[2]=my fence. Deletes only what belongs to this owner.
RELEASE_SCRIPT = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
  local removed = redis.call('DEL', KEYS[1])
  if redis.call('GET', KEYS[3]) == ARGV[2] then
    redis.call('DEL', KEYS[3])
  end
  return removed
end
return 0
"""

#: renew: KEYS[1]=lease, KEYS[3]=active fence; ARGV[1]=owner token,
#: ARGV[2]=ttl (ms), ARGV[3]=my fence.
RENEW_SCRIPT = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
  if redis.call('GET', KEYS[3]) == ARGV[3] then
    redis.call('PEXPIRE', KEYS[3], ARGV[2])
  end
  return 1
end
return 0
"""

#: commit: KEYS[1]=run key, KEYS[2]=active fence; ARGV[1]=run payload,
#: ARGV[2]=my fence, ARGV[3]=ttl (seconds). The run is rewritten only
#: while THIS owner's fence is the active one.
COMMIT_SCRIPT = """
if redis.call('GET', KEYS[2]) == ARGV[2] then
  redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[3])
  return 1
end
return 0
"""


def lease_key(run_id: str) -> str:
    return f"deployment_lease:{run_id}"


def fence_key(run_id: str) -> str:
    return f"deployment_fence:{run_id}"


def active_fence_key(run_id: str) -> str:
    return f"deployment_fence_active:{run_id}"


class ExecutionLeaseGuard:
    """One worker's ownership of one run's execution lease.

    Usage (see ``DeploymentEngine.execute``)::

        guard = ExecutionLeaseGuard(client, run_id)
        if not guard.acquire():
            # someone else owns it — refuse, do not double-execute
            ...
        try:
            ...
            if not guard.alive():
                raise LeaseLostError(...)   # bounded cancel + LEASE_LOST
            ok = guard.commit(run_payload)  # fence-guarded state save
            if not ok:
                raise LeaseLostError(...)
        finally:
            guard.release()
    """

    def __init__(self, client, run_id: str, *, ttl_seconds: int = 120) -> None:
        if ttl_seconds < 30:
            raise ValueError("lease ttl must be at least 30s")
        self._client = client
        self._run_id = run_id
        self._ttl_ms = int(ttl_seconds * 1000)
        self._owner = secrets.token_urlsafe(24)
        self._fence = 0
        self._lost = threading.Event()
        self._cancel = threading.Event()
        self._stop = threading.Event()
        self._last_success = 0.0
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------ acquire
    def acquire(self) -> bool:
        """Atomically acquire the lease + a fresh fence. False when the
        lease is already held by another owner (duplicate dispatch /
        redelivery) — the caller must refuse, never race."""
        result = self._client.eval(
            ACQUIRE_SCRIPT, 3,
            lease_key(self._run_id),
            fence_key(self._run_id),
            active_fence_key(self._run_id),
            self._owner,
            self._ttl_ms,
        )
        fence = int(result or 0)
        if fence <= 0:
            return False
        self._fence = fence
        self._last_success = time.monotonic()
        interval = max(2.0, self._ttl_ms / 3000.0)  # ttl / 3, bounded
        self._thread = threading.Thread(
            target=self._watchdog, args=(interval,), daemon=True,
            name=f"lease-watchdog-{self._run_id}",
        )
        self._thread.start()
        return True

    # ------------------------------------------------------------ renewal
    def renew_once(self) -> bool:
        """One atomic compare-and-expire. False when the lease is no
        longer ours OR the store is unreachable (the caller decides,
        from the TTL clock, whether that is still within grace)."""
        try:
            ok = self._client.eval(
                RENEW_SCRIPT, 3,
                lease_key(self._run_id),
                fence_key(self._run_id),
                active_fence_key(self._run_id),
                self._owner,
                self._ttl_ms,
                str(self._fence),
            )
            return bool(ok)
        except Exception:  # noqa: BLE001 — outage path is a first-class case
            return False

    def _watchdog(self, interval: float) -> None:
        while not self._stop.wait(interval):
            if self.renew_once():
                self._last_success = time.monotonic()
                if self._lost.is_set():
                    # Redis came back and we still own the lease: the
                    # run may continue (the TTL clock was honest).
                    self._lost.clear()
                    self._cancel.clear()
            else:
                # Either we lost ownership or the store is down. The
                # server-side lease can outlive a network blip for at
                # most its TTL — only after that is ownership provably
                # gone.
                silent_for = time.monotonic() - self._last_success
                if silent_for * 1000.0 >= self._ttl_ms:
                    self._lost.set()
                    self._cancel.set()

    # ------------------------------------------------------------ fencing
    @property
    def fence(self) -> int:
        return self._fence

    def alive(self) -> bool:
        """True while the worker still owns the lease (or is inside
        the post-blip grace window)."""
        return not self._lost.is_set()

    def request_cancel(self) -> None:
        """Signal the running sandbox to terminate (bounded cancel)."""
        self._cancel.set()

    @property
    def cancel_event(self) -> threading.Event:
        return self._cancel

    def commit(self, run_payload: str, ttl_seconds: int = 86400) -> bool:
        """Fence-guarded durable state commit. Returns False — never
        raises — when the commit was rejected (ownership lost) or the
        store was unreachable; the engine must treat False as
        lease-lost, not as "saved"."""
        try:
            ok = self._client.eval(
                COMMIT_SCRIPT, 2,
                f"deployment_run:{self._run_id}",
                active_fence_key(self._run_id),
                run_payload,
                str(self._fence),
                int(ttl_seconds),
            )
            return bool(ok)
        except Exception:  # noqa: BLE001
            return False

    # ------------------------------------------------------------ release
    def release(self) -> None:
        """Stop the watchdog and compare-and-delete our lease. A stale
        owner's release is a no-op by construction (token mismatch)."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        try:
            self._client.eval(
                RELEASE_SCRIPT, 3,
                lease_key(self._run_id),
                fence_key(self._run_id),
                active_fence_key(self._run_id),
                self._owner,
                str(self._fence),
            )
        except Exception:  # noqa: BLE001 — best effort; TTL bounds the rest
            pass

    def __enter__(self) -> "ExecutionLeaseGuard":
        if not self.acquire():
            raise LeaseLostError("the execution lease is already held")
        return self

    def __exit__(self, *exc: object) -> None:
        self.release()
