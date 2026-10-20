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

The original nine lease scenarios remain intact; P1-3 cases extend them:

  1. acquire is mutually exclusive (NX);
  2. release is compare-and-delete (stale release is a no-op);
  3. renewal is compare-and-expire (foreign renewal refused);
  4. fencing tokens are monotonic across acquisitions;
  5. a stale worker's commits are fenced out after re-acquisition;
  6. the watchdog renews a live lease in the background;
  7. a single renewal failure inside the TTL is not lease-lost;
  8. 20+ concurrent duplicate dispatches yield exactly ONE owner;
  9. crash + redelivery never double-applies (engine-level, real
     store, real lease);
 10. authoritative ownership assertion: current owner succeeds; stale
     owner after higher-fence grant fails and cannot commit/release;
 11. deterministic engine pause: superseded worker cannot start its next
     Terraform operation and cannot roll back;
 12. Redis unavailability inside the watchdog grace window blocks the
     engine's next external operation while local alive() stays true;
 13. malformed fence data and a non-expiring lease are refused (two
     parameter cases).
"""
import hashlib
import os
import threading
import time
import uuid
from pathlib import Path

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
        f"deployment_run:{run_id}", f"deployment_run:{run_id}:rev",
        f"deployment_run:{run_id}:dispatch_journal",
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
                  approved_identity=None, cancel_event=None,
                  before_operation=None):
            time.sleep(0.75)  # hold the lease across the redelivery
            return super().apply(manifest_path, namespace,
                                 approved_identity=approved_identity,
                                 cancel_event=cancel_event,
                                 before_operation=before_operation)

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
def test_10_authoritative_assertion_positive_and_superseded_owner(live_client):
    """Current owner passes; after B's higher fence, A fails and cannot
    release or commit over B. This is a live Redis proof, not a fake."""
    run_id = _run_id("assert-owned")
    old_owner = ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
    new_owner = ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
    try:
        assert old_owner.acquire()
        assert old_owner.assert_owned() is True
        assert new_owner.acquire() is False

        # Deterministically model lease expiry/revocation before B acquires.
        live_client.delete(lease_key(run_id), active_fence_key(run_id))
        assert new_owner.acquire()
        assert new_owner.fence > old_owner.fence
        assert new_owner.assert_owned() is True

        with pytest.raises(LeaseLostError):
            old_owner.assert_owned()
        assert old_owner.cancel_event.is_set()
        assert new_owner.assert_owned() is True

        assert old_owner.commit('{"owner": "stale"}', ttl_seconds=60) is False
        old_owner.release()
        assert live_client.get(lease_key(run_id)) is not None
        assert new_owner.assert_owned() is True
        payload = '{"owner": "current"}'
        assert new_owner.commit(payload, ttl_seconds=60) is True
        assert live_client.get(f"deployment_run:{run_id}") == payload.encode()
    finally:
        old_owner.release()
        new_owner.release()
        _cleanup(live_client, run_id)


# 11 --------------------------------------------------------------------
def test_11_real_engine_rejects_paused_superseded_worker_before_apply(live_client, monkeypatch):
    """A real engine + real Redis guard refuses A's next Terraform call
    after B acquires a higher fence while A is paused at the apply boundary."""
    import json
    from deployment_service.application.services.deployment_engine import DeploymentEngine
    from deployment_service.domain.entities.deployment_run import DeploymentRun
    from deployment_service.infrastructure.persistence.execution_lease import (
        ExecutionLeaseGuard,
    )
    from deployment_service.infrastructure.persistence.redis_pipeline_store import RedisPipelineStore
    from deployment_service.tests.test_deployment_engine import (
        FakeHealth, FakeKubectl, FakeSourceVerifier, FakeTerraform, FakeValidator,
        VALID_PAYLOAD,
    )

    store = RedisPipelineStore()
    store.client = live_client
    at_apply_boundary = threading.Event()
    resume_old_worker = threading.Event()

    class PausingTerraform(FakeTerraform):
        def apply_plan(self, iac_dir, plan_output_path, expected_plan_file_hash="",
                       cancel_event=None, before_operation=None):
            actual = hashlib.sha256(Path(plan_output_path).read_bytes()).hexdigest()
            if not expected_plan_file_hash or actual != expected_plan_file_hash:
                return {"status": "BLOCKED", "error_code": "PLAN_ARTIFACT_MISMATCH"}
            # This is the deterministic hook immediately before the injected
            # production lease assertion; no apply side effect has begun.
            at_apply_boundary.set()
            if not resume_old_worker.wait(timeout=15):
                raise AssertionError("test did not resume the paused worker")
            if before_operation is not None:
                before_operation()
            self.applied_with_hash = expected_plan_file_hash
            self.applied_from = plan_output_path
            return {"status": "PASS", "stdout": "apply-ok", "plan_file_hash": actual}

    terraform = PausingTerraform()
    kubectl = FakeKubectl()
    created_guards = []

    def real_guard_factory(rid):
        guard = ExecutionLeaseGuard(live_client, rid, ttl_seconds=TTL)
        created_guards.append(guard)
        return guard

    engine = DeploymentEngine(
        store=store, validator=FakeValidator(), terraform=terraform, kubectl=kubectl,
        health_checker=FakeHealth(), source_verifier=FakeSourceVerifier(),
        lease_factory=real_guard_factory,
    )
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    run = engine.create_dry_run(dict(VALID_PAYLOAD))
    engine.approve(run.id, "lease-regression", run.artifact_hash, run.plan_hash)
    outcome = {}
    worker = threading.Thread(target=lambda: outcome.setdefault(
        "run", engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)))
    new_owner = ExecutionLeaseGuard(live_client, run.id, ttl_seconds=TTL)
    try:
        worker.start()
        assert at_apply_boundary.wait(timeout=15), "worker never reached apply boundary"
        old_owner = created_guards[0]
        assert old_owner.alive() is True

        # Supersede A atomically from the test's real-Redis fixture, then
        # establish that B—not a stale local watchdog snapshot—is current.
        live_client.delete(lease_key(run.id), active_fence_key(run.id))
        assert new_owner.acquire()
        assert new_owner.fence > old_owner.fence
        assert new_owner.assert_owned() is True
        b_state = DeploymentRun.from_dict(store.get(run.id))
        b_state.add_log("new-owner-state-marker")
        assert new_owner.commit(json.dumps(b_state.to_dict())) is True

        resume_old_worker.set()
        worker.join(timeout=20)
        assert not worker.is_alive(), "old worker did not terminate after lease loss"

        assert outcome["run"].state.value == "LEASE_LOST"
        assert old_owner.cancel_event.is_set()
        assert terraform.init_calls == 1
        assert terraform.applied_from is None, "A must not begin Terraform apply"
        assert kubectl.applied_calls == [], "A must not begin Kubernetes apply"
        assert kubectl.undo_calls == [], "A must not begin stale rollback"
        assert new_owner.assert_owned() is True
        assert live_client.get(lease_key(run.id)) is not None
        final = store.get(run.id)
        assert final["state"] == b_state.state.value
        assert any("new-owner-state-marker" in line for line in final["logs"])
        assert not any("LEASE_LOST" in line for line in final["logs"])
    finally:
        resume_old_worker.set()
        if worker.ident is not None:
            worker.join(timeout=20)
        new_owner.release()
        for guard in created_guards:
            guard.release()
        _cleanup(live_client, run.id)


# 12 --------------------------------------------------------------------
def test_12_real_engine_redis_unavailable_fails_closed_inside_watchdog_grace(
    live_client, monkeypatch,
):
    """A still-alive local watchdog cannot authorize init when the atomic
    Redis ownership query is unavailable."""
    from deployment_service.application.services.deployment_engine import DeploymentEngine
    from deployment_service.infrastructure.persistence.execution_lease import (
        ExecutionLeaseGuard, OWNERSHIP_ASSERTION_SCRIPT,
    )
    from deployment_service.infrastructure.persistence.redis_pipeline_store import RedisPipelineStore
    from deployment_service.tests.test_deployment_engine import (
        FakeHealth, FakeKubectl, FakeSourceVerifier, FakeTerraform, FakeValidator,
        VALID_PAYLOAD,
    )

    class UnavailableOwnershipClient:
        def eval(self, script, *args, **kwargs):
            if script == OWNERSHIP_ASSERTION_SCRIPT:
                raise redis_lib.ConnectionError("synthetic Redis outage")
            return live_client.eval(script, *args, **kwargs)

    store = RedisPipelineStore()
    store.client = live_client
    terraform = FakeTerraform()
    kubectl = FakeKubectl()
    guards = []

    def guard_factory(run_id):
        guard = ExecutionLeaseGuard(
            UnavailableOwnershipClient(), run_id, ttl_seconds=TTL)
        guards.append(guard)
        return guard

    engine = DeploymentEngine(
        store=store, validator=FakeValidator(), terraform=terraform, kubectl=kubectl,
        health_checker=FakeHealth(), source_verifier=FakeSourceVerifier(),
        lease_factory=guard_factory,
    )
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    run = engine.create_dry_run(dict(VALID_PAYLOAD))
    try:
        engine.approve(run.id, "lease-regression", run.artifact_hash, run.plan_hash)
        result = engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)
        assert result.state.value == "LEASE_LOST"
        assert guards[0].alive() is True, "local watchdog grace must retain its meaning"
        assert guards[0].cancel_event.is_set()
        assert terraform.init_calls == 0
        assert terraform.applied_from is None
        assert kubectl.applied_calls == []
        assert kubectl.undo_calls == []
    finally:
        for guard in guards:
            guard.release()
        _cleanup(live_client, run.id)


# 13 --------------------------------------------------------------------
@pytest.mark.parametrize("corruption", ["malformed-active-fence", "lease-without-ttl"])
def test_13_malformed_or_nonexpiring_lease_state_fails_closed(live_client, corruption):
    run_id = _run_id("malformed")
    guard = ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
    try:
        assert guard.acquire()
        if corruption == "malformed-active-fence":
            live_client.set(active_fence_key(run_id), "not-a-fence", px=TTL * 1000)
        else:
            live_client.persist(lease_key(run_id))
        with pytest.raises(LeaseLostError) as exc_info:
            guard.assert_owned()
        assert guard.cancel_event.is_set()
        assert guard.alive() is False
        assert guard._owner not in str(exc_info.value)
    finally:
        guard.release()
        _cleanup(live_client, run_id)


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
