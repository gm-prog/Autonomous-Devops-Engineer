"""Phase 8.7-D.1 — real-Redis integration tests (CI job: redis-integration).

Exercises the SHARED state against a real Redis instance:

* the Redis analysis rate limiter (shared across "replicas" — two limiter
  objects must see one counter);
* the Redis budget ledger (atomic reserve/finalize, ceiling rejection,
  conservative reconciliation, calendar-month rollover);
* fail-closed behavior when the store is unreachable.

Runs only when ``REDIS_URL`` points at a live store.  In CI the job always
provides it (a digest-pinned disposable Redis container); locally the tests
skip with an explicit reason — but in CI a missing ``REDIS_URL`` is a hard
failure, never a silent skip.
"""

from __future__ import annotations

import os

import pytest


def resolve_live_redis_url():
    """Resolve the live store URL with the FAIL-CLOSED contract (P1-C).

    A missing/empty ``REDIS_URL`` is a HARD failure when
    ``REDIS_INTEGRATION_REQUIRED=true`` (the CI contract — never a silent
    skip that would turn the mandatory gate green with zero Redis tests
    executed); otherwise it is an explicit local skip.  Returns the URL on
    success.  This is a plain function (not a fixture) so the fail-closed
    decision itself is directly unit-testable (mutation M24).
    """
    url = os.environ.get("REDIS_URL", "").strip()
    if not url:
        if os.environ.get("REDIS_INTEGRATION_REQUIRED") == "true":
            pytest.fail(
                "CI must provide REDIS_URL for the real-Redis integration "
                "tests (redis-integration job)."
            )
        pytest.skip("REDIS_URL not set locally; runs in CI (redis-integration job)")
    return url


@pytest.fixture()
def live_redis_url():
    """Live store URL; the disposable store is flushed before and after
    each test so the shared-key tests are deterministic."""
    url = resolve_live_redis_url()
    import redis

    client = redis.Redis.from_url(url, socket_connect_timeout=3, socket_timeout=3)
    client.ping()  # hard fail if the store is not reachable
    client.flushdb()
    yield url
    try:
        client.flushdb()
    finally:
        client.close()


def test_redis_limiter_shared_across_replicas(live_redis_url):
    from platform_pkg.api_gateway.core.analysis_rate_limit import (
        RedisAnalysisRateLimiter,
    )

    replica_1 = RedisAnalysisRateLimiter(
        redis_url=live_redis_url,
        limit_per_identity_per_minute=2,
        limit_per_ip_per_minute=100,
        key_prefix="ci:ratelimit:replica-shared",
    )
    replica_2 = RedisAnalysisRateLimiter(
        redis_url=live_redis_url,
        limit_per_identity_per_minute=2,
        limit_per_ip_per_minute=100,
        key_prefix="ci:ratelimit:replica-shared",
    )
    try:
        assert replica_1.check("user-x", "10.0.0.1").allowed
        # The OTHER replica sees the same counter:
        assert replica_2.check("user-x", "10.0.0.2").allowed
        # Third check from any replica: over the shared limit.
        denied = replica_1.check("user-x", "10.0.0.3")
        assert not denied.allowed
        assert denied.retry_after_seconds >= 1
        # A different identity is not affected.
        assert replica_2.check("user-y", "10.0.0.4").allowed
    finally:
        replica_1.close()
        replica_2.close()


def test_redis_limiter_store_down_fails_closed():
    from platform_pkg.api_gateway.core.analysis_rate_limit import (
        RateLimitStoreUnavailable,
    )

    try:
        limiter = _make_down_limiter()
    except RateLimitStoreUnavailable:
        return  # construction itself already refused (fail closed)
    try:
        with pytest.raises(RateLimitStoreUnavailable):
            limiter.check("user", "10.0.0.1")
    finally:
        limiter.close()


def _make_down_limiter():
    from platform_pkg.api_gateway.core.analysis_rate_limit import (
        RedisAnalysisRateLimiter,
    )

    # Nothing listens on this port in CI or locally.
    return RedisAnalysisRateLimiter(
        redis_url="redis://127.0.0.1:59998/0",
        limit_per_identity_per_minute=2,
        limit_per_ip_per_minute=10,
    )


def test_redis_budget_reserve_finalize_and_ceiling(live_redis_url):
    from platform_pkg.agent.infrastructure.llm.gemini_caller import (
        BudgetExceededException,
        RedisBudgetLedger,
    )

    ledger = RedisBudgetLedger(monthly_budget_usd=10.0, redis_url=live_redis_url)
    # Reserve 6 -> ok; finalize with the actual (cheaper) usage.
    res_a = ledger.reserve(6.0)
    ledger.finalize(res_a, actual_cost_usd=2.0)
    # committed=2.0; another 6.0 reservation fits (8.0 <= 10.0).
    res_b = ledger.reserve(6.0)
    # committed + reserved = 2.0 + 6.0 = 8.0; one more 6.0 would exceed 10.
    with pytest.raises(BudgetExceededException):
        ledger.reserve(6.0)
    # Conservative reconciliation: finalizing with NO usage metadata keeps
    # the FULL reservation (never undercount) -> committed = 8.0.
    ledger.finalize(res_b, actual_cost_usd=None)
    # 8.0 committed: a 1.0 reservation still fits (9.0 <= 10.0)...
    res_c = ledger.reserve(1.0)
    # ...but a further 2.0 would exceed the ceiling (9.0 + 2.0 > 10.0).
    with pytest.raises(BudgetExceededException):
        ledger.reserve(2.0)
    ledger.finalize(res_c, actual_cost_usd=None)
    ledger.close()


def test_redis_budget_concurrent_reservations_respect_ceiling(live_redis_url):
    from platform_pkg.agent.infrastructure.llm.gemini_caller import (
        BudgetExceededException,
        RedisBudgetLedger,
    )
    import threading

    ledger = RedisBudgetLedger(monthly_budget_usd=10.0, redis_url=live_redis_url)
    allowed = []
    rejected = []
    lock = threading.Lock()

    def worker():
        try:
            res = ledger.reserve(6.0)
            with lock:
                allowed.append(res)
        except BudgetExceededException:
            with lock:
                rejected.append(1)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 10.0 ceiling with 6.0 reservations: at most ONE can succeed.
    assert len(allowed) == 1, (
        f"shared ledger double-spent: {len(allowed)} concurrent reservations "
        f"admitted against a 10.0 ceiling with 6.0 each"
    )
    assert len(rejected) == 5
    for res in allowed:
        ledger.finalize(res, actual_cost_usd=None)
    ledger.close()


def test_redis_budget_calendar_rollover(live_redis_url, monkeypatch):
    from datetime import datetime, timedelta, timezone

    from platform_pkg.agent.infrastructure.llm.gemini_caller import (
        BudgetExceededException,
        RedisBudgetLedger,
        utc_period_key,
    )

    ledger = RedisBudgetLedger(monthly_budget_usd=5.0, redis_url=live_redis_url)
    current_period = RedisBudgetLedger._period_key()

    # Exhaust the current period on the SHARED store.
    res = ledger.reserve(5.0)
    ledger.finalize(res, actual_cost_usd=None)
    with pytest.raises(BudgetExceededException):
        ledger.reserve(1.0)

    # Simulate the NEXT month: the shared ledger's period key changes, so
    # the new period starts from zero (calendar rollover on the shared
    # store, not per-process state).
    def next_month():
        return utc_period_key(datetime.now(timezone.utc) + timedelta(days=32))

    monkeypatch.setattr(RedisBudgetLedger, "_period_key", staticmethod(next_month))
    res_next = ledger.reserve(5.0)
    assert res_next.period_key != current_period
    ledger.finalize(res_next, actual_cost_usd=None)
    ledger.close()


def test_redis_budget_duplicate_finalize_counts_once(live_redis_url):
    """Exactly-once finalization: a duplicate (retried) finalize of the
    same reservation must NOT release twice or commit twice."""
    from platform_pkg.agent.infrastructure.llm.gemini_caller import (
        RedisBudgetLedger,
    )

    ledger = RedisBudgetLedger(monthly_budget_usd=10.0, redis_url=live_redis_url)
    res = ledger.reserve(4.0)
    assert ledger.finalize(res, 2.0) is True, "first finalize applies accounting"
    assert ledger.finalize(res, 2.0) is False, "duplicate finalize is ignored"
    # A duplicate with DIFFERENT actual is equally ignored — the FIRST
    # reconciliation is the only one that counts:
    assert ledger.finalize(res, 9.9) is False
    assert ledger.accumulated_spend == pytest.approx(2.0), (
        "committed spend must be the actual cost counted exactly once"
    )
    # The reservation was released exactly once: the full remaining budget
    # is available again.
    res2 = ledger.reserve(8.0)  # 2.0 committed + 8.0 reserved = 10.0 <= ceiling
    ledger.finalize(res2, None)
    assert ledger.accumulated_spend == pytest.approx(10.0)
    ledger.close()


def test_redis_budget_concurrent_duplicate_finalizes_count_once(live_redis_url):
    """Eight replicas finalizing the SAME reservation concurrently:
    exactly one applies the accounting (atomic claim in Redis)."""
    import threading

    from platform_pkg.agent.infrastructure.llm.gemini_caller import (
        RedisBudgetLedger,
    )

    ledger = RedisBudgetLedger(monthly_budget_usd=20.0, redis_url=live_redis_url)
    res = ledger.reserve(6.0)
    results: list = []
    lock = threading.Lock()
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        applied = ledger.finalize(res, 1.5)
        with lock:
            results.append(applied)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count(True) == 1, (
        f"exactly one concurrent finalize may apply the accounting; "
        f"got {results.count(True)}"
    )
    assert ledger.accumulated_spend == pytest.approx(1.5), (
        "actual cost must be committed exactly once"
    )
    ledger.close()


def test_redis_budget_shared_across_ledger_instances(live_redis_url):
    """Two ledger instances (two replicas) see ONE budget: committed
    spend, reservations, and the ceiling are global on the store."""
    from platform_pkg.agent.infrastructure.llm.gemini_caller import (
        BudgetExceededException,
        RedisBudgetLedger,
    )

    replica_a = RedisBudgetLedger(monthly_budget_usd=10.0, redis_url=live_redis_url)
    replica_b = RedisBudgetLedger(monthly_budget_usd=10.0, redis_url=live_redis_url)
    # Replica A spends: finalize with the actual (cheaper) usage.
    res_a = replica_a.reserve(6.0)
    replica_a.finalize(res_a, 2.0)
    # Replica B sees the same committed spend:
    assert replica_b.accumulated_spend == pytest.approx(2.0)
    # Replica B reserves against the SHARED remaining budget:
    res_b = replica_b.reserve(6.0)  # 2.0 + 6.0 = 8.0 <= 10.0
    # And replica A now sees replica B's shared reservation too:
    with pytest.raises(BudgetExceededException):
        replica_a.reserve(3.0)  # 2.0 committed + 6.0 reserved + 3.0 > 10.0
    replica_b.finalize(res_b, None)  # missing usage -> full reservation counts
    assert replica_a.accumulated_spend == pytest.approx(8.0)
    replica_a.close()
    replica_b.close()
