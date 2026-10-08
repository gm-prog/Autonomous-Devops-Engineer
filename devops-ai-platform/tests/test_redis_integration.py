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


@pytest.fixture()
def live_redis_url():
    """Live store URL; the disposable store is flushed before and after
    each test so the shared-key tests are deterministic."""
    url = os.environ.get("REDIS_URL", "").strip()
    if not url:
        # The redis-integration CI job sets REDIS_INTEGRATION_REQUIRED=true:
        # there a missing store is a hard failure (never a silent skip).
        if os.environ.get("REDIS_INTEGRATION_REQUIRED") == "true":
            pytest.fail(
                "CI must provide REDIS_URL for the real-Redis integration "
                "tests (redis-integration job)."
            )
        pytest.skip("REDIS_URL not set locally; runs in CI (redis-integration job)")
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
