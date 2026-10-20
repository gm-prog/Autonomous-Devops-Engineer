"""Celery crash recovery — real broker, real worker kill/restart (audit P1).

CI job: redis-integration. Proves, against a REAL Redis broker and REAL
``celery`` worker subprocesses, the explicit at-least-once worker-loss
semantics configured in
``deployment_service.infrastructure.celery.tasks.broker_semantics``:

Scenario A (crash mid-execution):
  1. a worker consumes a task whose in-flight side effect is
     idempotent/convergent (the production engine's contract);
  2. the worker process is SIGKILLed while the task is in flight;
  3. the message was acked LATE, so it is still unacked in the broker;
  4. a restarted worker restores and redelivers it (visibility-timeout
     restore); the task RESUMES idempotently and completes;
  5. exactly one side effect was applied, the run is not lost, and a
     second (duplicate) delivery of the now-terminal task is a pure
     replay that performs no further side effect.

Exactly-once execution is NOT claimed and NOT asserted: the test
asserts at-least-once delivery (the task ran on two worker processes)
with no double-applied effect — safety comes from idempotency + the
fenced lease (covered separately by the real-Redis lease suite), not
from the broker.

A second test asserts the PRODUCTION app's configuration contract
directly, so the semantics under test are the ones the deployment
worker actually runs.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest
import redis as redis_lib

_TESTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS_DIR))
from test_redis_integration import resolve_live_redis_url  # noqa: E402

_TARGET = _TESTS_DIR / "crash_recovery_worker_target.py"
RUN_KEY = uuid.uuid4().hex[:12]
QUEUE = f"crash-recovery-{RUN_KEY}"


def _key(client, suffix: str) -> str:
    return f"crcr:{RUN_KEY}:{suffix}"


def _worker_env(url: str) -> dict:
    return {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        # The target is imported as a dotted module (celery -A takes a
        # module name, not a file path); the platform root on
        # PYTHONPATH provides both `tests.*` and `deployment_service.*`.
        "PYTHONPATH": str(_TESTS_DIR.parent),
        "REDIS_URL": url,
        "CRASH_RECOVERY_RUN_KEY": RUN_KEY,
    }


def _start_worker(url: str, log_path: Path) -> subprocess.Popen:
    return subprocess.Popen(
        [
            sys.executable, "-m", "celery",
            "-A", "tests.crash_recovery_worker_target", "worker",
            "-P", "prefork", "--concurrency=1", "--loglevel=info",
            "-Q", QUEUE,
            f"--hostname=crash-recovery-{RUN_KEY}@%h",
            "--logfile", str(log_path),
            "--pidfile", str(log_path.with_suffix(".pid")),
        ],
        cwd=str(_TESTS_DIR.parent),
        env=_worker_env(url),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )


def _wait_for_worker_ready(
    proc: subprocess.Popen, log_path: Path, timeout: float = 90) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(
                f"worker exited prematurely (rc={proc.returncode}); "
                f"log: {log_path}"
            )
        if log_path.exists() and b"ready." in log_path.read_bytes():
            return
        time.sleep(0.5)
    raise AssertionError(
        f"worker did not become ready within timeout; log: {log_path}")


def _kill_worker_group(proc: subprocess.Popen) -> None:
    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    proc.wait(timeout=30)


def _poll(predicate, timeout: float, what: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.5)
    raise AssertionError(f"timed out waiting for: {what}")


@pytest.fixture()
def crash_ctx(tmp_path):
    """Fail-closed live store + per-run cleanup (audit P1)."""
    url = resolve_live_redis_url()
    client = redis_lib.Redis.from_url(
        url, socket_connect_timeout=3, socket_timeout=3)
    client.ping()

    def cleanup():
        for suffix in ("done", "effect", "attempts", "blocked",
                       "release", "replays"):
            client.delete(_key(client, suffix))
        client.close()

    yield url, client, tmp_path
    cleanup()


def test_worker_kill_redelivers_and_replays_terminal(crash_ctx):
    url, client, tmp_path = crash_ctx
    import importlib.util

    os.environ["REDIS_URL"] = url
    os.environ["CRASH_RECOVERY_RUN_KEY"] = RUN_KEY
    spec = importlib.util.spec_from_file_location(
        "crash_recovery_worker_target", _TARGET)
    target = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(target)

    # ---- worker 1: consumes the task, goes in-flight ---------------
    w1_log = tmp_path / "worker1.log"
    worker1 = _start_worker(url, w1_log)
    try:
        _wait_for_worker_ready(worker1, w1_log)
        target.app.send_task(
            "crash_recovery.probe", queue=QUEUE,
            task_id=f"{RUN_KEY}:delivery-1", kwargs={})

        def in_flight():
            return client.exists(_key(client, "blocked"))

        _poll(in_flight, timeout=60, what="probe task to go in-flight")
        assert int(client.get(_key(client, "attempts"))) == 1
        assert client.get(_key(client, "effect")) == f"applied:{RUN_KEY}".encode()

        # ---- the crash: hard-kill the whole worker ------------------
        _kill_worker_group(worker1)
    finally:
        if worker1.poll() is None:
            _kill_worker_group(worker1)
    worker1 = None

    # ---- worker 2: restored unacked message, resume, complete ------
    w2_log = tmp_path / "worker2.log"
    worker2 = _start_worker(url, w2_log)
    try:
        _wait_for_worker_ready(worker2, w2_log)

        def redelivered():
            return int(client.get(_key(client, "attempts")) or 0) >= 2

        _poll(redelivered, timeout=120,
              what="redelivery of the unacked message to worker 2 "
                   "(acks-late + visibility-timeout restore)")
        # The resumed run re-applies its idempotent effect and blocks
        # again; release it so it can complete.
        client.set(_key(client, "release"), "1", ex=600)

        def completed():
            return client.exists(_key(client, "done"))

        _poll(completed, timeout=120, what="resumed run to complete")
        assert client.get(_key(client, "effect")) == f"applied:{RUN_KEY}".encode()
        assert int(client.get(_key(client, "attempts"))) == 2

        # ---- duplicate delivery of the now-terminal task ------------
        target.app.send_task(
            "crash_recovery.probe", queue=QUEUE,
            task_id=f"{RUN_KEY}:delivery-2", kwargs={})

        def replayed():
            return int(client.get(_key(client, "replays")) or 0) >= 1

        _poll(replayed, timeout=120,
              what="terminal replay to short-circuit with no work")
        assert int(client.get(_key(client, "attempts"))) == 2
        assert client.get(_key(client, "effect")) == f"applied:{RUN_KEY}".encode()
    finally:
        if worker2 is not None and worker2.poll() is None:
            _kill_worker_group(worker2)


def test_production_app_configures_explicit_worker_loss_semantics():
    """The deployment task app itself must carry the P1 configuration.

    Contract assertion (no broker needed): if any of these regresses,
    a killed worker's in-flight message is lost or prefetched in
    batches and the run can sit in EXECUTION_REQUESTED forever.
    """
    from deployment_service.infrastructure.celery import tasks as deployment_tasks

    conf = deployment_tasks.celery_app.conf
    assert conf.task_acks_late is True, \
        "message must stay unacked while the task executes"
    assert conf.task_acks_on_failure_or_timeout is False, \
        "a raised task may be redelivered (idempotency makes it safe)"
    assert conf.task_reject_on_worker_lost is True, \
        "a lost pool child must requeue its in-flight task"
    assert conf.worker_prefetch_multiplier == 1, \
        "a dying worker may take at most one message"
    assert conf.task_ignore_result is True, \
        "the durable run record, not a result backend, is the truth"
    assert conf.broker_connection_retry_on_startup is True
    visibility = conf.broker_transport_options["visibility_timeout"]
    # A dead worker's message is restored within this window; it must
    # exceed the worst-case bounded run so healthy runs are never
    # spuriously redelivered.
    assert visibility > deployment_tasks._MAX_BOUNDED_EXECUTION_SECONDS
    assert visibility <= 3600, "crash recovery must be bounded (<= 1h)"
