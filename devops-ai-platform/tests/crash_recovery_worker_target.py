"""Worker target for the Celery crash-recovery integration test.

CI job: redis-integration (real Redis broker, real worker processes).
This module is imported by a REAL ``celery`` worker subprocess (``-A``
target), not by pytest. It defines a throwaway app on a
per-test-run namespaced queue with the SAME explicit at-least-once
semantics as the production deployment task app
(``deployment_service.infrastructure.celery.tasks.broker_semantics``)
— only the visibility timeout is shortened so a killed worker's
in-flight message is restored within test wall-clock.

The ``probe`` task mirrors the production task contract:

* a redelivery of a COMPLETED run short-circuits on the durable
  terminal marker (the production task's ``_TERMINAL_STATES``
  check) and performs NO further side effect;
* in-flight side effects are idempotent/convergent (a declarative
  SET — the stand-in for ``kubectl apply`` of the exact approved
  artifact);
* completion is marked durable before the result is returned.
"""
from __future__ import annotations

import os
import time

import redis as redis_lib
from celery import Celery

from deployment_service.infrastructure.celery.tasks import broker_semantics

REDIS_URL = os.environ["REDIS_URL"]
RUN_KEY = os.environ["CRASH_RECOVERY_RUN_KEY"]

app = Celery("crash_recovery_test", broker=REDIS_URL)
app.conf.update(broker_semantics(visibility_timeout=5))
app.conf.task_default_queue = f"crash-recovery-{RUN_KEY}"

_client = redis_lib.Redis.from_url(REDIS_URL)


def _key(suffix: str) -> str:
    return f"crcr:{RUN_KEY}:{suffix}"


@app.task(name="crash_recovery.probe")
def probe() -> dict:
    # Terminal short-circuit: a redelivery of a finished run returns
    # the persisted outcome and does nothing else (production: the
    # run's terminal-state check before any execution).
    if _client.get(_key("done")):
        _client.incr(_key("replays"))
        return {"status": "REPLAY", "effect": _client.get(_key("effect"))}

    # In-flight work: convergent/idempotent side effect (re-applying
    # the same declarative value is a no-op, like kubectl apply of the
    # exact approved manifest).
    _client.incr(_key("attempts"))
    _client.set(_key("effect"), f"applied:{RUN_KEY}")
    _client.set(_key("blocked"), "1", ex=300)

    # Block until the test kills the worker (crash scenario) or
    # releases us (completion scenario). Bounded: a lost signal must
    # not pin the worker forever.
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        if _client.exists(_key("release")):
            break
        time.sleep(0.2)

    # Durable completion marker BEFORE the result (production: the
    # fenced terminal-state commit before the typed return).
    _client.set(_key("done"), "1", ex=3600)
    return {"status": "SUCCEEDED", "effect": f"applied:{RUN_KEY}"}
