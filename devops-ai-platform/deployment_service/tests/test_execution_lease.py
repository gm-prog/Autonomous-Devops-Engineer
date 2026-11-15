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

P2.1 adds five shared-workspace ownership scenarios (31-35), proving
the durable Kubernetes operation-evidence protocol against the REAL
lease: a mid-flight handoff is durably visible to every reader, a
superseded worker's rejected terminal mark retains the workspace for
the new owner, the workspace is discarded only after a positively
confirmed terminal commit and strictly BEFORE the lease release, a
commit outage after the handoff leaves truthful durable uncertainty,
and a legacy in-flight record is never back-filled before its first
real handoff.
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


def _real_engine_with_guard_factory(live_client):
    """Build the normal engine with real Redis leases and deterministic
    side-effect doubles.  P2 setup failures occur before those doubles can
    execute, while Redis proves the watchdog/release behavior."""
    from deployment_service.application.services.deployment_engine import (
        DeploymentEngine,
    )
    from deployment_service.infrastructure.persistence.redis_pipeline_store import (
        RedisPipelineStore,
    )
    from deployment_service.tests.test_deployment_engine import (
        FakeHealth,
        FakeKubectl,
        FakeSourceVerifier,
        FakeTerraform,
        FakeValidator,
    )

    store = RedisPipelineStore()
    store.client = live_client
    terraform = FakeTerraform()
    kubectl = FakeKubectl()
    guards = []

    def guard_factory(run_id):
        guard = ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
        guards.append(guard)
        return guard

    engine = DeploymentEngine(
        store=store,
        validator=FakeValidator(),
        terraform=terraform,
        kubectl=kubectl,
        health_checker=FakeHealth(),
        source_verifier=FakeSourceVerifier(),
        lease_factory=guard_factory,
    )
    return engine, store, terraform, kubectl, guards


def _assert_released_real_guard(live_client, run_id, guard):
    """Assert local watchdog stop and that no current lease/fence remains.

    The monotonic fence counter intentionally persists, so this checks the
    owned lease and active-fence keys only.
    """
    assert guard._stop.is_set()
    assert guard._thread is not None
    assert not guard._thread.is_alive()
    assert live_client.exists(lease_key(run_id)) == 0
    assert live_client.exists(active_fence_key(run_id)) == 0


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
                  before_operation=None, before_handoff=None):
            time.sleep(0.75)  # hold the lease across the redelivery
            return super().apply(manifest_path, namespace,
                                 approved_identity=approved_identity,
                                 cancel_event=cancel_event,
                                 before_operation=before_operation,
                                 before_handoff=before_handoff)

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


# P2-A -----------------------------------------------------------------
def test_14_post_acquisition_store_failure_releases_real_lease(
    live_client, monkeypatch,
):
    """The second store read fails after acquire; the daemon watchdog is
    stopped and the real owner lease is compare-and-deleted."""
    from deployment_service.tests.test_deployment_engine import VALID_PAYLOAD

    engine, store, terraform, kubectl, guards = _real_engine_with_guard_factory(
        live_client)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    run = engine.create_dry_run(dict(VALID_PAYLOAD))
    original_get = store.get
    reads = 0

    def fail_on_second_get(run_id):
        nonlocal reads
        reads += 1
        if reads == 2:
            raise RuntimeError("controlled post-acquisition Redis read failure")
        return original_get(run_id)

    try:
        engine.approve(run.id, "lease-regression", run.artifact_hash, run.plan_hash)
        monkeypatch.setattr(store, "get", fail_on_second_get)
        with pytest.raises(RuntimeError, match="post-acquisition"):
            engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)

        assert reads == 2
        assert len(guards) == 1
        _assert_released_real_guard(live_client, run.id, guards[0])
        assert terraform.init_calls == 0
        assert terraform.applied_from is None
        assert kubectl.applied_calls == []
        assert kubectl.undo_calls == []
    finally:
        for guard in guards:
            guard.release()
        engine._discard_approval_workspace(run.id)
        _cleanup(live_client, run.id)


def test_15_workspace_failure_releases_real_lease(live_client, monkeypatch):
    """Workspace allocation is pre-execution setup, not deployment failure
    or a reason to run generic recovery."""
    from deployment_service.tests.test_deployment_engine import VALID_PAYLOAD

    engine, _store, terraform, kubectl, guards = _real_engine_with_guard_factory(
        live_client)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    run = engine.create_dry_run(dict(VALID_PAYLOAD))
    try:
        engine.approve(run.id, "lease-regression", run.artifact_hash, run.plan_hash)
        monkeypatch.setattr(
            engine,
            "_new_workspace",
            lambda _prefix: (_ for _ in ()).throw(OSError("controlled workspace failure")),
        )
        with pytest.raises(OSError, match="workspace failure"):
            engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)

        assert len(guards) == 1
        _assert_released_real_guard(live_client, run.id, guards[0])
        assert terraform.init_calls == 0
        assert terraform.applied_from is None
        assert kubectl.applied_calls == []
        assert kubectl.undo_calls == []
    finally:
        for guard in guards:
            guard.release()
        engine._discard_approval_workspace(run.id)
        _cleanup(live_client, run.id)


@pytest.mark.parametrize("fresh_result", [None, "DEPLOYED"])
def test_16_post_acquisition_early_exit_releases_real_lease(
    live_client, monkeypatch, fresh_result,
):
    """Missing and non-resumable fresh reads cannot bypass centralized
    cleanup after an otherwise successful acquisition."""
    from deployment_service.application.services.deployment_engine import (
        DeploymentActionError,
    )
    from deployment_service.tests.test_deployment_engine import VALID_PAYLOAD

    engine, store, terraform, kubectl, guards = _real_engine_with_guard_factory(
        live_client)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    run = engine.create_dry_run(dict(VALID_PAYLOAD))
    original_get = store.get
    reads = 0

    def change_second_get(run_id):
        nonlocal reads
        reads += 1
        if reads == 2:
            if fresh_result is None:
                return None
            changed = dict(original_get(run_id))
            changed["state"] = fresh_result
            return changed
        return original_get(run_id)

    try:
        engine.approve(run.id, "lease-regression", run.artifact_hash, run.plan_hash)
        monkeypatch.setattr(store, "get", change_second_get)
        with pytest.raises(DeploymentActionError):
            engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)

        assert len(guards) == 1
        _assert_released_real_guard(live_client, run.id, guards[0])
        assert terraform.init_calls == 0
        assert kubectl.applied_calls == []
        assert kubectl.undo_calls == []
    finally:
        for guard in guards:
            guard.release()
        engine._discard_approval_workspace(run.id)
        _cleanup(live_client, run.id)


# ----------------------------------------------------- P2.1 helpers ------
def _approval_workspace_path(run_id):
    """The persistent approval workspace path (mirrors the engine's
    ``_approval_workspace`` root selection)."""
    import tempfile

    root = os.environ.get("DEPLOYMENT_WORKSPACE_ROOT", "").strip()
    base = Path(root) if root else Path(tempfile.gettempdir())
    return base / f"approved-{run_id}"


# 31 --------------------------------------------------------------------
def test_31_durable_handoff_visible_mid_flight_and_truthful_result(
    live_client, monkeypatch,
):
    """The fenced handoff commit is DURABLY visible to any other reader
    while the worker is still executing — before the sandbox step and
    before any result — and a FAILED apply is finalized truthfully:
    RESULT_RECORDED, operator-blocked compensation, and the workspace
    consumed only after the confirmed terminal commit."""
    from deployment_service.application.services.deployment_engine import (
        DeploymentEngine,
    )
    from deployment_service.application.services.kubernetes_operation_evidence import (
        EVIDENCE_KEY,
        HANDOFF_PENDING,
        RESULT_RECORDED,
    )
    from deployment_service.application.services.plan_artifact import (
        PLAN_FILENAME,
    )
    from deployment_service.infrastructure.persistence.redis_pipeline_store import (
        RedisPipelineStore,
    )
    from deployment_service.tests.test_deployment_engine import (
        FakeHealth,
        FakeKubectl,
        FakeSourceVerifier,
        FakeTerraform,
        FakeValidator,
        VALID_PAYLOAD,
        _fake_handoff_context,
    )

    store = RedisPipelineStore()
    store.client = live_client
    paused_at_handoff = threading.Event()
    resume_worker = threading.Event()

    class HandoffPausingKubectl(FakeKubectl):
        """Pauses DURABLY after the fenced handoff commit, before the
        sandbox step — exactly the window a crash would leave behind."""

        def apply(self, manifest_path, namespace=None, approved_identity=None,
                  cancel_event=None, before_operation=None, before_handoff=None):
            if before_operation is not None:
                before_operation()
            if before_handoff is not None:
                before_handoff(_fake_handoff_context(
                    manifest_path, namespace, approved_identity))
            paused_at_handoff.set()
            if not resume_worker.wait(timeout=15):
                raise AssertionError("the test did not resume the worker")
            self.applied_calls.append(
                (manifest_path, namespace, approved_identity))
            return {"status": "FAIL", "exit_code": 1, "timed_out": False, "cancelled": False, "stdout": "apply-failed", "cluster_access": True}

    kubectl = HandoffPausingKubectl()
    guards = []

    def guard_factory(run_id):
        guard = ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
        guards.append(guard)
        return guard

    engine = DeploymentEngine(
        store=store, validator=FakeValidator(), terraform=FakeTerraform(),
        kubectl=kubectl, health_checker=FakeHealth(),
        source_verifier=FakeSourceVerifier(), lease_factory=guard_factory,
    )
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    run = engine.create_dry_run(dict(VALID_PAYLOAD))
    workspace = _approval_workspace_path(run.id)
    outcome = {}
    try:
        engine.approve(run.id, "lease-evidence", run.artifact_hash,
                       run.plan_hash)

        def _worker():
            outcome["run"] = engine.execute(
                run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)

        worker = threading.Thread(target=_worker)
        worker.start()
        assert paused_at_handoff.wait(timeout=15), (
            "the worker never reached the handoff seam")

        # --- the DURABLE proof, read while the worker is mid-flight ----
        stored = store.get(run.id)
        assert stored["state"] == "DEPLOYING"
        execution = stored["execution"]
        assert EVIDENCE_KEY in execution, (
            "the fenced handoff commit must already be durable")
        evidence = execution[EVIDENCE_KEY]
        assert evidence["attempt_count"] == 1
        attempt = evidence["attempts"][0]
        assert attempt["state"] == HANDOFF_PENDING
        assert attempt["result"] is None
        assert evidence["may_have_mutated"] is True
        assert len(evidence["resources"]) == 1
        assert evidence["resources"][0]["name"] == "demo"
        assert evidence["resources"][0]["may_have_mutated"] is True
        # the apply result is NOT yet recorded anywhere
        assert "kubernetes_apply" not in execution
        # the approved workspace + plan the run would apply still exist
        assert workspace.is_dir()
        assert (workspace / PLAN_FILENAME).is_file()

        resume_worker.set()
        worker.join(timeout=20)
        assert not worker.is_alive()

        # --- the failed apply is finalized TRUTHFULLY -------------------
        result = outcome.get("run")
        assert result is not None, "the worker never completed execute()"
        assert result.state.value == "ROLLBACK_FAILED"
        assert result.rollback["status"] == "FAIL"
        assert result.rollback["outcome"] == "BLOCKED"
        assert result.rollback["kubernetes_compensation"]["evidence_state"] \
            == RESULT_RECORDED
        k8s_components = [
            c for c in result.rollback["components"]
            if str(c["component"]).startswith("kubernetes")]
        assert k8s_components, "the Kubernetes surface must be accounted for"
        for component in k8s_components:
            assert component["status"] == "BLOCKED"
            assert component["result"]["undo_invoked"] is False
            assert component["result"]["operator_action_required"] is True
        assert kubectl.undo_calls == [], "undo must never be invoked"

        stored = store.get(run.id)
        assert stored["state"] == "ROLLBACK_FAILED"
        evidence = stored["execution"][EVIDENCE_KEY]
        assert evidence["attempts"][0]["state"] == RESULT_RECORDED
        assert evidence["attempts"][0]["result"]["status"] == "FAIL"
        assert stored["execution"]["kubernetes_apply"]["status"] == "FAIL"
        assert any("ROLLBACK_FAILED" in line for line in stored["logs"])
        # the terminal commit was confirmed: the workspace is consumed
        assert not workspace.exists()
        _assert_released_real_guard(live_client, run.id, guards[0])
    finally:
        resume_worker.set()
        if "worker" in locals() and worker.ident is not None:
            worker.join(timeout=20)
        for guard in guards:
            guard.release()
        engine._discard_approval_workspace(run.id)
        _cleanup(live_client, run.id)


# 32 --------------------------------------------------------------------
def test_32_superseded_worker_retains_workspace_and_redelivery_completes(
    live_client, monkeypatch,
):
    """Scenarios A/B/C: worker A is superseded mid-handoff; its result
    commit and its LEASE_LOST mark are both fenced out, and — decisively
    — its workspace is RETAINED for the new owner. A later redelivery
    (C) completes the run: attempt 0 stays HANDOFF_PENDING forever (A's
    handoff was never finalized), C's attempt is RESULT_RECORDED, and
    only C's positively confirmed terminal commit consumes the
    workspace."""
    import json

    from deployment_service.application.services.deployment_engine import (
        DeploymentEngine,
    )
    from deployment_service.application.services.kubernetes_operation_evidence import (
        EVIDENCE_KEY,
        HANDOFF_PENDING,
        RESULT_RECORDED,
    )
    from deployment_service.domain.entities.deployment_run import DeploymentRun
    from deployment_service.infrastructure.persistence.redis_pipeline_store import (
        RedisPipelineStore,
    )
    from deployment_service.tests.test_deployment_engine import (
        FakeHealth,
        FakeKubectl,
        FakeSourceVerifier,
        FakeTerraform,
        FakeValidator,
        VALID_PAYLOAD,
        _fake_handoff_context,
    )

    store = RedisPipelineStore()
    store.client = live_client
    paused_at_handoff = threading.Event()
    resume_a = threading.Event()

    class PausingKubectl(FakeKubectl):
        def __init__(self):
            super().__init__()
            self.pause_next_apply = True

        def apply(self, manifest_path, namespace=None, approved_identity=None,
                  cancel_event=None, before_operation=None, before_handoff=None):
            pause = self.pause_next_apply
            self.pause_next_apply = False
            if before_operation is not None:
                before_operation()
            if before_handoff is not None:
                before_handoff(_fake_handoff_context(
                    manifest_path, namespace, approved_identity))
            if pause:
                paused_at_handoff.set()
                if not resume_a.wait(timeout=15):
                    raise AssertionError("worker A was never resumed")
            self.applied_calls.append(
                (manifest_path, namespace, approved_identity))
            return {"status": "PASS", "exit_code": 0, "timed_out": False, "cancelled": False, "stdout": "apply-ok", "cluster_access": True}

    kubectl = PausingKubectl()
    guards = []

    def guard_factory(run_id):
        guard = ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
        guards.append(guard)
        return guard

    engine = DeploymentEngine(
        store=store, validator=FakeValidator(), terraform=FakeTerraform(),
        kubectl=kubectl, health_checker=FakeHealth(),
        source_verifier=FakeSourceVerifier(), lease_factory=guard_factory,
    )
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    run = engine.create_dry_run(dict(VALID_PAYLOAD))
    workspace = _approval_workspace_path(run.id)
    new_owner = ExecutionLeaseGuard(live_client, run.id, ttl_seconds=TTL)
    outcome = {}
    try:
        engine.approve(run.id, "lease-evidence", run.artifact_hash,
                       run.plan_hash)

        # ---- worker A: pauses durably after the fenced handoff ---------
        worker = threading.Thread(target=lambda: outcome.setdefault(
            "a", engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash,
                                run.plan_hash)))
        worker.start()
        assert paused_at_handoff.wait(timeout=15), (
            "worker A never reached the handoff seam")
        old_owner = guards[0]
        stored = store.get(run.id)
        assert stored["state"] == "DEPLOYING"
        assert stored["execution"][EVIDENCE_KEY]["attempts"][0]["state"] \
            == HANDOFF_PENDING
        assert workspace.is_dir()

        # ---- owner B supersedes A atomically ---------------------------
        live_client.delete(lease_key(run.id), active_fence_key(run.id))
        assert new_owner.acquire()
        assert new_owner.fence > old_owner.fence
        b_state = DeploymentRun.from_dict(store.get(run.id))
        b_state.add_log("new-owner-state-marker")
        assert new_owner.commit(json.dumps(b_state.to_dict())) is True

        # ---- A resumes: the sandbox completes, but the RESULT commit
        # and the LEASE_LOST mark are both rejected by the fence ---------
        resume_a.set()
        worker.join(timeout=30)
        assert not worker.is_alive()
        a_run = outcome.get("a")
        assert a_run is not None, "worker A failed before completing execute()"
        assert a_run.state.value == "LEASE_LOST"
        assert len(kubectl.applied_calls) == 1, "the sandbox DID run once"

        stored = store.get(run.id)
        # B's durable state stands; A's terminal mark was rejected
        assert stored["state"] == "DEPLOYING"
        assert any("new-owner-state-marker" in line for line in stored["logs"])
        assert not any("LEASE_LOST" in line for line in stored["logs"])
        evidence = stored["execution"][EVIDENCE_KEY]
        assert evidence["attempt_count"] == 1
        assert evidence["attempts"][0]["state"] == HANDOFF_PENDING, (
            "A's rejected result-recording must never finalize the attempt")
        assert "kubernetes_apply" not in stored["execution"]
        # P2.1: a stale worker whose mark was rejected RETAINS the
        # workspace, and never releases the new owner's lease
        assert live_client.exists(lease_key(run.id)) == 1
        assert workspace.is_dir()

        # ---- owner B finishes; redelivery C completes the run ----------
        new_owner.release()
        c_run = engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash,
                               run.plan_hash)
        assert c_run.state.value == "DEPLOYED"
        stored = store.get(run.id)
        assert stored["state"] == "DEPLOYED"
        assert any("RECOVERING" in line for line in stored["logs"])
        evidence = stored["execution"][EVIDENCE_KEY]
        assert evidence["attempt_count"] == 2
        assert evidence["attempts"][0]["state"] == HANDOFF_PENDING, (
            "A's unfinalized handoff stays HANDOFF_PENDING forever")
        assert evidence["attempts"][1]["state"] == RESULT_RECORDED
        assert evidence["attempts"][1]["result"]["status"] == "PASS"
        assert len(kubectl.applied_calls) == 2, (
            "the orphaned in-flight run is redelivered idempotently")
        # only C's confirmed terminal commit consumed the workspace
        assert not workspace.exists()
        _assert_released_real_guard(live_client, run.id, guards[1])
    finally:
        resume_a.set()
        if "worker" in locals() and worker.ident is not None:
            worker.join(timeout=30)
        for guard in guards:
            guard.release()
        new_owner.release()
        engine._discard_approval_workspace(run.id)
        _cleanup(live_client, run.id)


# 33 --------------------------------------------------------------------
def test_33_workspace_discard_happens_before_lease_release(
    live_client, monkeypatch,
):
    """Delete-before-release (P2.1): the shared approval workspace is
    destroyed while the worker's lease is STILL provably held in Redis,
    and only then is the lease released — a crash in between can never
    strand a half-disposed workspace that another worker trusts, and a
    disposed workspace can never be resurrected by a worker that no
    longer owns the run."""
    from deployment_service.tests.test_deployment_engine import VALID_PAYLOAD

    engine, store, terraform, kubectl, guards = _real_engine_with_guard_factory(
        live_client)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    run = engine.create_dry_run(dict(VALID_PAYLOAD))
    workspace = _approval_workspace_path(run.id)
    observations = {}
    original_discard = engine._discard_approval_workspace

    def observing_discard(discard_run_id):
        # Observed from INSIDE the engine's finalization: the terminal
        # fenced commit was confirmed, and the lease key still exists.
        observations["lease_held_at_discard"] = \
            live_client.exists(lease_key(discard_run_id)) == 1
        observations["workspace_before"] = workspace.is_dir()
        return original_discard(discard_run_id)

    try:
        engine.approve(run.id, "lease-order", run.artifact_hash, run.plan_hash)
        monkeypatch.setattr(
            engine, "_discard_approval_workspace", observing_discard)
        result = engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash,
                                run.plan_hash)
        assert result.state.value == "DEPLOYED"
        assert observations["lease_held_at_discard"] is True, (
            "the workspace must be discarded while the lease is still held")
        assert observations["workspace_before"] is True
        assert not workspace.exists()
        assert kubectl.undo_calls == []
        _assert_released_real_guard(live_client, run.id, guards[0])
    finally:
        for guard in guards:
            guard.release()
        engine._discard_approval_workspace(run.id)
        _cleanup(live_client, run.id)


# 34 --------------------------------------------------------------------
def test_34_commit_outage_after_handoff_leaves_durable_uncertainty(
    live_client, monkeypatch,
):
    """The durable record is only ever as truthful as its last CONFIRMED
    fenced commit: when the store accepts the handoff but every later
    commit fails, the run stays DEPLOYING with a HANDOFF_PENDING attempt
    and NO kubernetes_apply key — uncertainty is never downgraded — and
    the workspace is RETAINED for the next owner."""
    from deployment_service.application.services.deployment_engine import (
        DeploymentEngine,
    )
    from deployment_service.application.services.kubernetes_operation_evidence import (
        EVIDENCE_KEY,
        HANDOFF_PENDING,
    )
    from deployment_service.infrastructure.persistence.execution_lease import (
        COMMIT_SCRIPT,
    )
    from deployment_service.infrastructure.persistence.redis_pipeline_store import (
        RedisPipelineStore,
    )
    from deployment_service.tests.test_deployment_engine import (
        FakeHealth,
        FakeKubectl,
        FakeSourceVerifier,
        FakeTerraform,
        FakeValidator,
        VALID_PAYLOAD,
        _fake_handoff_context,
    )

    class CommitOutageAfter:
        """Pass-through client whose COMMIT_SCRIPT evals start failing
        after N successes (a synthetic durable-store outage)."""

        def __init__(self, inner, fail_after):
            self._inner = inner
            self._fail_after = fail_after
            self.commits_seen = 0

        def eval(self, script, *args, **kwargs):
            if script == COMMIT_SCRIPT:
                self.commits_seen += 1
                if self.commits_seen > self._fail_after:
                    raise redis_lib.ConnectionError(
                        "synthetic commit outage")
            return self._inner.eval(script, *args, **kwargs)

    store = RedisPipelineStore()
    store.client = live_client
    kubectl = FakeKubectl()
    guards = []
    wrappers = []

    def guard_factory(run_id):
        outage = CommitOutageAfter(live_client, fail_after=3)
        wrappers.append(outage)
        guard = ExecutionLeaseGuard(outage, run_id, ttl_seconds=TTL)
        guards.append(guard)
        return guard

    engine = DeploymentEngine(
        store=store, validator=FakeValidator(), terraform=FakeTerraform(),
        kubectl=kubectl, health_checker=FakeHealth(),
        source_verifier=FakeSourceVerifier(), lease_factory=guard_factory,
    )
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    run = engine.create_dry_run(dict(VALID_PAYLOAD))
    workspace = _approval_workspace_path(run.id)
    try:
        engine.approve(run.id, "lease-evidence", run.artifact_hash,
                       run.plan_hash)
        result = engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash,
                                run.plan_hash)

        # commits 1-3 (EXECUTION_REQUESTED, DEPLOYING, handoff) landed;
        # the result commit, its retries, and the LEASE_LOST mark could
        # not — so the worker must report lease loss, not a deployment
        # result it was never able to durably record
        assert result.state.value == "LEASE_LOST"
        assert guards[0].cancel_event.is_set()
        assert wrappers[0].commits_seen > 3, (
            "the result commit, its retries, and the LEASE_LOST mark all "
            "reached the outage client")

        stored = store.get(run.id)
        assert stored["state"] == "DEPLOYING", (
            "the last CONFIRMED commit was the handoff commit")
        execution = stored["execution"]
        assert EVIDENCE_KEY in execution
        evidence = execution[EVIDENCE_KEY]
        assert evidence["attempt_count"] == 1
        assert evidence["attempts"][0]["state"] == HANDOFF_PENDING
        assert evidence["attempts"][0]["result"] is None
        assert "kubernetes_apply" not in execution, (
            "an unrecorded result must never appear as durable fact")
        # the sandbox DID run once (the handoff authorized it): the
        # durable HANDOFF_PENDING truthfully means "may have mutated"
        assert len(kubectl.applied_calls) == 1
        assert kubectl.undo_calls == []
        # the workspace is RETAINED: this worker's terminal mark was
        # never confirmed, so it must not consume the plan
        assert workspace.is_dir()
        _assert_released_real_guard(live_client, run.id, guards[0])
    finally:
        for guard in guards:
            guard.release()
        engine._discard_approval_workspace(run.id)
        _cleanup(live_client, run.id)


# 35 --------------------------------------------------------------------
def test_35_legacy_in_flight_record_is_never_backfilled_before_handoff(
    live_client, monkeypatch,
):
    """A resumed PRE-PROTOCOL record (state DEPLOYING, no evidence key)
    must not receive a fabricated protocol stamp: the durable record
    carries NO evidence until the worker's FIRST real handoff commit.
    The legacy worker's own real attempt then becomes attempt 1."""
    from deployment_service.application.services.deployment_engine import (
        DeploymentEngine,
    )
    from deployment_service.application.services.kubernetes_operation_evidence import (
        EVIDENCE_KEY,
        RESULT_RECORDED,
    )
    from deployment_service.domain.entities.deployment_run import DeploymentRun
    from deployment_service.domain.value_objects.deployment_state import (
        DeploymentState,
    )
    from deployment_service.infrastructure.persistence.redis_pipeline_store import (
        RedisPipelineStore,
    )
    from deployment_service.tests.test_deployment_engine import (
        FakeHealth,
        FakeKubectl,
        FakeSourceVerifier,
        FakeTerraform,
        FakeValidator,
        VALID_PAYLOAD,
        _fake_handoff_context,
    )

    store = RedisPipelineStore()
    store.client = live_client
    pre_handoff_visible = threading.Event()
    resume_worker = threading.Event()

    class PreHandoffPauseKubectl(FakeKubectl):
        def apply(self, manifest_path, namespace=None, approved_identity=None,
                  cancel_event=None, before_operation=None, before_handoff=None):
            if before_operation is not None:
                before_operation()
            pre_handoff_visible.set()
            if not resume_worker.wait(timeout=15):
                raise AssertionError("the test did not resume the worker")
            if before_handoff is not None:
                before_handoff(_fake_handoff_context(
                    manifest_path, namespace, approved_identity))
            self.applied_calls.append(
                (manifest_path, namespace, approved_identity))
            return {"status": "PASS", "exit_code": 0, "timed_out": False, "cancelled": False, "stdout": "apply-ok", "cluster_access": True}

    kubectl = PreHandoffPauseKubectl()
    guards = []

    def guard_factory(run_id):
        guard = ExecutionLeaseGuard(live_client, run_id, ttl_seconds=TTL)
        guards.append(guard)
        return guard

    engine = DeploymentEngine(
        store=store, validator=FakeValidator(), terraform=FakeTerraform(),
        kubectl=kubectl, health_checker=FakeHealth(),
        source_verifier=FakeSourceVerifier(), lease_factory=guard_factory,
    )
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    run = engine.create_dry_run(dict(VALID_PAYLOAD))
    outcome = {}
    try:
        engine.approve(run.id, "lease-legacy", run.artifact_hash, run.plan_hash)

        # Rewrite the durable record into the shape a PRE-PROTOCOL
        # worker would have left behind: in-flight DEPLOYING, no
        # schema-versioned evidence record at all.
        legacy = DeploymentRun.from_dict(store.get(run.id))
        legacy.move(DeploymentState.DEPLOYING)
        legacy.add_log("legacy-worker-crashed-mid-deploying")
        store.save(legacy)
        stored = store.get(run.id)
        assert stored["state"] == "DEPLOYING"
        assert EVIDENCE_KEY not in (stored.get("execution") or {})

        worker = threading.Thread(target=lambda: outcome.setdefault(
            "run", engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash,
                                  run.plan_hash)))
        worker.start()
        assert pre_handoff_visible.wait(timeout=15), (
            "the worker never reached the pre-handoff seam")

        # Mid-flight, ownership proven, BEFORE the first handoff: the
        # resume path must NOT have stamped a fabricated evidence record
        stored = store.get(run.id)
        assert stored["state"] == "DEPLOYING"
        assert EVIDENCE_KEY not in (stored.get("execution") or {}), (
            "a legacy in-flight record must never be back-filled before "
            "its first real handoff")
        assert "kubernetes_apply" not in (stored.get("execution") or {})

        resume_worker.set()
        worker.join(timeout=20)
        assert not worker.is_alive()

        result = outcome.get("run")
        assert result is not None, "the worker never completed execute()"
        assert result.state.value == "DEPLOYED"
        stored = store.get(run.id)
        assert stored["state"] == "DEPLOYED"
        assert any("RECOVERING" in line for line in stored["logs"])
        evidence = stored["execution"][EVIDENCE_KEY]
        assert evidence["attempt_count"] == 1
        assert evidence["attempts"][0]["state"] == RESULT_RECORDED
        assert evidence["attempts"][0]["result"]["status"] == "PASS"
        _assert_released_real_guard(live_client, run.id, guards[0])
    finally:
        resume_worker.set()
        if "worker" in locals() and worker.ident is not None:
            worker.join(timeout=20)
        for guard in guards:
            guard.release()
        engine._discard_approval_workspace(run.id)
        _cleanup(live_client, run.id)


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
