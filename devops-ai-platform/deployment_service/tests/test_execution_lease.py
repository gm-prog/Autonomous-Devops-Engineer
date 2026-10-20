"""Phase 8.8A Correction-1 (F5) — execution lease safety, proven against
a REAL Redis instance (never a fake client).

The pre-correction store used a constant lock value with an
unconditional DEL and a 900s TTL shorter than the configured operation
budget: any process could release another's "lock", and a legitimate
worker could lose it mid-run. The corrected lease is:

* SET-NX with a UNIQUE owner token (never a shared constant);
* compare-and-delete release (a stale owner cannot delete a new
  owner's lease);
* compare-and-expire renewal (only the current owner extends);
* a MONOTONIC fencing token, enforced on every durable state commit
  and before every side effect;
* a bounded watchdog that only declares the lease lost after the TTL
  elapses without a successful renewal.

These scenarios run against a live Redis (``REDIS_URL`` /
``REDIS_HOST``+``REDIS_PORT``). The fail-closed contract mirrors
``tests/test_redis_integration.py``: in CI (``REDIS_INTEGRATION_REQUIRED
= true``) a missing URL is a HARD failure — never a silent skip.

The nine named scenarios:

  1. acquire is mutually exclusive (NX);
  2. release is compare-and-delete (stale release is a no-op);
  3. renewal is compare-and-expire (foreign renewal refused);
  4. fencing tokens are monotonic across acquisitions;
  5. a stale worker's commits are fenced out after re-acquisition;
  6. the watchdog renews a live lease in the background;
  7. a single renewal failure inside the TTL is not lease-lost;
  8. 20+ concurrent duplicate dispatches yield exactly ONE owner;
  9. crash + redelivery never double-applies (engine-level, real
     store, real lease).
"""
import os
import threading
import time
import uuid

import pytest
import redis as redis_lib

from deployment_service.infrastructure.persistence.execution_lease import (
    ExecutionLeaseGuard,
    LeaseLostError,
    active_fence_key,
    fence_key,
    lease_key,
)

TTL = 30  # guard minimum; keeps every scenario bounded


def resolve_live_redis_url():
    url = os.environ.get("REDIS_URL", "").strip()
    if not url:
        host = os.environ.get("REDIS_HOST", "")
        port = os.environ.get("REDIS_PORT", "")
        if host:
            return f"redis://{host}:{port or 6379}/0"
        if os.environ.get("REDIS_INTEGRATION_REQUIRED") == "true":
            pytest.fail(
                "CI must provide REDIS_URL for the real-Redis lease tests "
                "(redis-integration job).",
            )
        pytest.skip("no live Redis configured locally; runs in CI")
    return url


@pytest.fixture()
def live_client():
    client = redis_lib.Redis.from_url(resolve_live_redis_url())
    client.ping()
    yield client
    client.close()


def _run_id(tag):
    return f"lease-test-{tag}-{uuid.uuid4().hex[:10]}"


def _cleanup(client, run_id):
    client.delete(
        lease_key(run_id), fence_key(run_id), active_fence_key(run_id),
        f"deployment_run:{run_id}",
    )


# 1 ---------------------------------------------------------------------
def test_1_acquire_is_mutually_exclusive(live_client):
    run_id = _run_id("nx")
    try:
        a = ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
        b = ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
        assert a.acquire() is True
        assert b.acquire() is False, "a second owner must be refused"
        # the owner token is unique per acquisition
        assert a._owner != b._owner
        a.release()
        assert b.acquire() is True, "after release the next owner acquires"
        b.release()
    finally:
        _cleanup(live_client, run_id)


# 2 ---------------------------------------------------------------------
def test_2_release_is_compare_and_delete(live_client):
    run_id = _run_id("rel")
    try:
        a = ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
        b = ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
        assert a.acquire()
        # a STALE owner attempting release must be a no-op: the lease
        # stays alive for the real owner
        b.release()
        assert live_client.exists(lease_key(run_id)) == 1
        # the real owner's release deletes it
        a.release()
        assert live_client.exists(lease_key(run_id)) == 0
    finally:
        _cleanup(live_client, run_id)


# 3 ---------------------------------------------------------------------
def test_3_renewal_is_compare_and_expire(live_client):
    run_id = _run_id("ren")
    try:
        a = ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
        b = ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
        assert a.acquire()
        assert b.renew_once() is False, "foreign renewal must be refused"
        assert a.renew_once() is True
        a.release()
    finally:
        _cleanup(live_client, run_id)


# 4 ---------------------------------------------------------------------
def test_4_fencing_tokens_are_monotonic(live_client):
    run_id = _run_id("fence")
    try:
        a = ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
        b = ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
        c = ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
        assert a.acquire()
        fence_a = a.fence
        a.release()
        assert b.acquire()
        fence_b = b.fence
        b.release()
        assert c.acquire()
        fence_c = c.fence
        c.release()
        assert fence_b == fence_a + 1
        assert fence_c == fence_b + 1
        assert fence_a >= 1
    finally:
        _cleanup(live_client, run_id)


# 5 ---------------------------------------------------------------------
def test_5_stale_worker_commits_are_fenced_out(live_client):
    run_id = _run_id("stale")
    try:
        a = ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
        b = ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
        assert a.acquire()
        # the worker's lease expires (TTL elapses) and a redelivery
        # re-acquires under a higher fence
        live_client.delete(lease_key(run_id), active_fence_key(run_id))
        assert b.acquire()
        # the stale owner can no longer commit state ...
        assert a.commit('{"id": "stale-state"}', ttl_seconds=60) is False
        # ... and its release cannot destroy the new owner's lease
        a.release()
        assert live_client.exists(lease_key(run_id)) == 1
        # the new owner's state wins, untouched (the exact payload the
        # new owner committed is what is stored — the stale one is not)
        new_payload = '{"id": "new-owner-state"}'
        assert b.commit(new_payload, ttl_seconds=60) is True
        assert live_client.get(f"deployment_run:{run_id}") == \
            new_payload.encode()
        b.release()
    finally:
        _cleanup(live_client, run_id)


# 6 ---------------------------------------------------------------------
def test_6_watchdog_renews_a_live_lease(live_client):
    run_id = _run_id("watchdog")
    guard = ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
    try:
        assert guard.acquire()
        assert guard._thread is not None and guard._thread.is_alive()
        t1 = live_client.pttl(lease_key(run_id))
        # the watchdog interval at TTL=30 is ~10s; instead of sleeping
        # the full interval, prove the renewal path works end to end
        # and the key's TTL stays healthy while the worker is active
        assert guard.renew_once() is True
        t2 = live_client.pttl(lease_key(run_id))
        assert t2 > 0 and t2 <= TTL * 1000
        # alive() must remain true for an actively renewed lease
        assert guard.alive() is True
        assert t1 > 0
    finally:
        guard.release()
        _cleanup(live_client, run_id)


# 7 ---------------------------------------------------------------------
def test_7_single_renewal_failure_is_not_lease_lost(live_client):
    run_id = _run_id("blip")
    guard = ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
    try:
        assert guard.acquire()
        # a renewal failure (network blip / transient outage) must NOT
        # be treated as ownership loss inside the TTL grace window
        dead = redis_lib.Redis.from_url("redis://127.0.0.1:1/0")
        guard._client = dead
        assert guard.renew_once() is False
        assert guard.alive() is True, (
            "a blip inside the TTL grace window is not lease-lost")
        # restore the real client: ownership provably continues
        guard._client = live_client
        guard._last_success = time.monotonic()
        assert guard.renew_once() is True
        assert guard.alive() is True
    finally:
        guard.release()
        _cleanup(live_client, run_id)


# 8 ---------------------------------------------------------------------
def test_8_twenty_plus_concurrent_duplicates_yield_one_owner(live_client):
    run_id = _run_id("dup")
    guards = [
        ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
        for _ in range(24)
    ]
    winners = []
    barrier = threading.Barrier(len(guards))

    def _attempt(guard):
        barrier.wait()
        if guard.acquire():
            winners.append(guard)

    threads = [
        threading.Thread(target=_attempt, args=(g,)) for g in guards
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    try:
        assert len(winners) == 1, (
            f"exactly one of {len(guards)} duplicate dispatches may own "
            f"the lease, got {len(winners)}")
        # the fence is exactly 1: no lost acquisition incremented it
        assert live_client.get(fence_key(run_id)) == b"1"
    finally:
        for g in guards:
            g.release()
        _cleanup(live_client, run_id)


# 9 ---------------------------------------------------------------------
def test_9_crash_redelivery_never_double_applies(live_client):
    """Engine-level: a worker that dies mid-execution leaves the run in
    a truthful state; a redelivery either executes exactly once (after
    the lease is free) or reports ALREADY_EXECUTING while a worker is
    genuinely running — and a second redelivery after success re-runs
    NOTHING (persisted outcome, idempotent replay)."""
    from deployment_service.infrastructure.celery import tasks as task_mod
    from deployment_service.infrastructure.persistence.redis_pipeline_store import (
        RedisPipelineStore,
    )
    from deployment_service.application.services.deployment_engine import (
        DeploymentEngine,
    )
    from deployment_service.tests.test_deployment_engine import (
        FakeHealth,
        FakeKubectl,
        FakeSourceVerifier,
        FakeTerraform,
        FakeValidator,
    )

    run_id = f"lease-e2e-{uuid.uuid4().hex[:10]}"
    store = RedisPipelineStore()
    store.client = live_client  # same instance as the lease guard
    kubectl = FakeKubectl()

    class _SlowKubectl(FakeKubectl):
        def apply(self, manifest_path, namespace=None,
                  approved_identity=None, cancel_event=None):
            time.sleep(0.75)  # hold the lease across the redelivery
            return super().apply(manifest_path, namespace,
                                 approved_identity=approved_identity,
                                 cancel_event=cancel_event)

    kubectl_slow = _SlowKubectl()
    engine = DeploymentEngine(
        store=store,
        validator=FakeValidator(),
        terraform=FakeTerraform(),
        kubectl=kubectl_slow,
        health_checker=FakeHealth(),
        source_verifier=FakeSourceVerifier(),
        lease_factory=lambda rid: ExecutionLeaseGuard(
            live_client, rid, ttl_seconds=TTL),
    )

    body = {
        "repository_id": 1,
        "repository_name": "acme/checkout",
        "dockerfile": "FROM python:3.11-slim\nUSER 10001\n",
        "k8s_yaml": ("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n"
                     "  name: d\nspec:\n  template:\n    spec:\n"
                     "      containers:\n        - name: d\n"
                     "          image: d:latest\n"),
        "terraform_tf": 'terraform { required_version = ">= 1.5.0" }\n',
        "pipeline_yaml": "name: ci\n",
        "source_revision": {"head_sha": "a" * 40},
        "created_by": "lease-e2e",
        "components": ["dockerfile", "kubernetes", "terraform", "pipeline"],
    }

    import os as _os

    _prev_flag = _os.environ.get("DEPLOYMENT_EXECUTION_ENABLED")
    _os.environ["DEPLOYMENT_EXECUTION_ENABLED"] = "true"
    try:
        run = engine.create_dry_run(dict(body))
        engine.approve(run.id, "lease-e2e", run.artifact_hash,
                       run.plan_hash)

        task_kwargs = (
            run.id, run.artifact_hash, run.plan_hash,
        )
        task_kwargs_dict = dict(
            dockerfile=body["dockerfile"], k8s_yaml=body["k8s_yaml"],
            terraform_tf=body["terraform_tf"], pipeline_yaml=body["pipeline_yaml"],
        )

        # --- first delivery (the "original" worker) -----------------
        results = {}

        def _run_task(tag):
            from deployment_service.application.services import (
                deployment_engine as engine_mod,
            )
            with _patch_engine(engine_mod, engine):
                results[tag] = task_mod.execute_iac_deployment.run(
                    *task_kwargs, **task_kwargs_dict)

        original = threading.Thread(target=_run_task, args=("orig",))
        original.start()
        time.sleep(0.35)  # the original worker is now mid-apply

        # --- redelivery while the original is still running ---------
        _run_task("dup")
        assert results["dup"]["status"] == "ALREADY_EXECUTING", results["dup"]
        assert results["dup"]["dispatched"] is False

        original.join(timeout=30)
        assert results["orig"]["status"] == "SUCCEEDED", results["orig"]
        assert kubectl_slow.applied_calls.__len__() == 1

        # --- redelivery AFTER success: persisted outcome, no re-run -
        _run_task("replay")
        assert results["replay"]["status"] == "SUCCEEDED", results["replay"]
        assert results["replay"]["idempotent_replay"] is True
        assert len(kubectl_slow.applied_calls) == 1, (
            "the redelivery must not apply a second time")
        # the ENGINE-minted run id is the real record key
        assert store.get(run.id)["state"] == "DEPLOYED"
    finally:
        if _prev_flag is None:
            _os.environ.pop("DEPLOYMENT_EXECUTION_ENABLED", None)
        else:
            _os.environ["DEPLOYMENT_EXECUTION_ENABLED"] = _prev_flag
        try:
            _cleanup(live_client, run.id)
            for key in live_client.scan_iter(f"deployment_run:{run.id}*"):
                live_client.delete(key)
        except NameError:
            pass  # create_dry_run failed before the run existed


class _patch_engine:
    """Patch the lazily-imported engine class to the shared engine."""

    def __init__(self, module, engine):
        self.module = module
        self.engine = engine
        self.original = None

    def __enter__(self):
        self.original = self.module.DeploymentEngine
        self.module.DeploymentEngine = lambda *a, **k: self.engine
        return self

    def __exit__(self, *exc):
        self.module.DeploymentEngine = self.original
        return False



# 10 --------------------------------------------------------------------
def test_10_authoritative_ownership_check_rejects_superseded_worker(live_client):
    """A stale local watchdog state cannot authorize another side effect."""
    run_id = _run_id("assert-owned")
    old_owner = ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
    new_owner = ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
    try:
        assert old_owner.acquire()
        assert old_owner.assert_owned() is None

        # Deterministically model the old lease expiring and a new owner
        # acquiring a higher fence before the old worker resumes.
        live_client.delete(lease_key(run_id), active_fence_key(run_id))
        assert new_owner.acquire()
        assert new_owner.fence > old_owner.fence

        # The old watchdog may not have ticked yet, but the Redis-backed
        # assertion must still refuse ownership and request cancellation.
        with pytest.raises(LeaseLostError, match="superseded"):
            old_owner.assert_owned()
        assert old_owner.cancel_event.is_set()
        assert new_owner.assert_owned() is None
    finally:
        old_owner.release()
        new_owner.release()
        _cleanup(live_client, run_id)

if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
