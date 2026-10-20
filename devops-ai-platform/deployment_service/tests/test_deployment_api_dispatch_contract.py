"""Phase 8.8A Correction-1 (F7, independent audit P1-2 + follow-up
Blockers A–D) — single execution contract, truthful dispatch, safe
ambiguity, optimistic concurrency.

The API's ``/execute`` is a DISPATCH, not an execution, and it never
conflates "the broker accepted the task", "the broker never received
it", and "we do not know which":

* 200/``dispatched: true`` only after the durable run CLAIMED
  EXECUTION_REQUESTED (atomic revision-claim) AND the publish
  completed, with the REAL persisted run id;
* a duplicate dispatch of a FRESH (non-ambiguous, non-stale)
  EXECUTION_REQUESTED run is refused (409) and enqueues NOTHING extra;
* TWO CONCURRENT initial dispatches from the same APPROVED document
  race the atomic claim: exactly one wins and publishes; the loser's
  claim is refused and it publishes nothing (Blocker A);
* a publish that provably failed PRE-SEND on every attempt (the broker
  refused the connection before any publish bytes were sent) reverts
  the run to APPROVED (atomic CAS) and reports 503 — nothing was
  executed;
* ANY publish failure that cannot be proven pre-send — a timeout after
  send, a mid-command disconnect, a broker that accepted and then
  died — is AMBIGUOUS: the run is NEVER reverted (a later ping cannot
  prove historical non-acceptance, Blocker D), the API reports
  ``dispatched: "unknown"``, and re-POSTing the same request
  idempotently re-publishes the SAME stable task id (the worker's
  lease + terminal-state check absorb duplicates);
* a stale dispatch (no worker progress for > 2x the visibility
  timeout) is idempotently re-deliverable; the re-dispatch update is a
  revision-CAS that cannot overwrite a worker-advanced run (Blocker B);
* a revert / outcome bookkeeping write is a no-op — never a clobber —
  when the run already advanced, a worker fence is active, the dispatch
  identity changed, or the document revision moved (Blocker C): a
  stale writer at the same revision cannot reset bookkeeping a
  concurrent redelivery already advanced;
* the worker task is idempotent under at-least-once delivery: a
  redelivery for a terminal run returns the persisted outcome and
  starts nothing; a concurrent duplicate finds the lease held and
  reports ALREADY_EXECUTING without touching the run.
"""
import os
import threading
import time
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from deployment_service.application.services.deployment_engine import (
    DeploymentActionError,
)
from deployment_service.tests.test_deployment_auth import (
    TEST_INTERNAL,
    TEST_SECRET,
    _apply_env,
    _headers,
    _mint,
    _restore_env,
)
from deployment_service.domain.entities.deployment_run import DeploymentRun
from deployment_service.domain.value_objects.deployment_state import (
    DeploymentState,
)
from deployment_service.infrastructure.persistence.execution_lease import (
    active_fence_key,
)
from deployment_service.tests.test_deployment_engine import (
    FakeHealth,
    FakeKubectl,
    FakeLeaseFactory,
    FakeLeaseGuard,
    FakeSourceVerifier,
    FakeTerraform,
    FakeValidator,
)

OPERATOR = "dispatch-contract-operator"


class _ContractAppBase(unittest.TestCase):
    def setUp(self):
        self.app, self._snap = _apply_env(
            {
                "JWT_SECRET": TEST_SECRET,
                "AGENT_INTERNAL_TOKEN": TEST_INTERNAL,
                "DEPLOYMENT_EXECUTION_ENABLED": "true",
                "REDIS_HOST": os.environ.get("REDIS_HOST", "127.0.0.1"),
                "REDIS_PORT": os.environ.get("REDIS_PORT", "6399"),
            }
        )
        self.addCleanup(_restore_env, self._snap)
        engine = self.app.state.engine
        engine.validator = FakeValidator()
        engine.terraform = FakeTerraform()
        engine.kubectl = FakeKubectl()
        engine.health_checker = FakeHealth()
        engine.source_verifier = FakeSourceVerifier()
        engine.lease_factory = self.lease_factory = FakeLeaseFactory(engine.store)
        FakeLeaseGuard.holders.clear()
        self.client = TestClient(self.app)
        self.auth = _headers(_mint(OPERATOR, ["operator"]))

    # -- fixture: create + approve a run deterministically -------------

    def _create_and_approve(self):
        engine = self.app.state.engine
        run = engine.create_dry_run(
            {
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
                "created_by": OPERATOR,
                "components": ["dockerfile", "kubernetes", "terraform", "pipeline"],
            }
        )
        engine.approve(
            run.id, OPERATOR, run.artifact_hash, run.plan_hash)
        return run

    def _execute_body(self, run, **overrides):
        body = {
            "artifact_hash": run.artifact_hash,
            "plan_hash": run.plan_hash,
            "namespace": "devops-production-namespace",
            "healthcheck_url": "https://example.local/healthz",
            "dockerfile": "FROM python:3.11-slim\nUSER 10001\n",
            "k8s_yaml": ("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n"
                         "  name: d\nspec:\n  template:\n    spec:\n"
                         "      containers:\n        - name: d\n"
                         "          image: d:latest\n"),
            "terraform_tf": 'terraform { required_version = ">= 1.5.0" }\n',
            "pipeline_yaml": "name: ci\n",
            "components": ["dockerfile", "kubernetes", "terraform", "pipeline"],
        }
        body.update(overrides)
        return body

    def _patched_engine_class(self):
        """The task builds a fresh DeploymentEngine (imported lazily
        from the engine module); point that import at the app's engine
        (deterministic fakes + shared store) so the test proves the
        TASK's orchestration, not the sandbox stack."""
        from deployment_service.application.services import deployment_engine

        def _factory(*args, **kwargs):
            return self.app.state.engine

        return deployment_engine, _factory

    def _captured_task(self):
        calls = []
        task_ids = []

        def _apply_async(kwargs=None, **apply_kwargs):
            calls.append(kwargs)
            task_ids.append(apply_kwargs.get("task_id"))
            result = mock.MagicMock()
            result.id = "task-fake-1"
            return result

        return calls, task_ids, _apply_async

    def _post_execute(self, run, **overrides):
        return self.client.post(
            f"/api/internal/deployments/{run.id}/execute",
            json=self._execute_body(run, **overrides),
            headers=self.auth,
        )


class DispatchTruthTests(_ContractAppBase):
    TASK = "deployment_service.infrastructure.celery.tasks"

    def test_dispatch_persists_then_enqueues_and_reports_truth(self):
        run = self._create_and_approve()
        calls, task_ids, apply_async = self._captured_task()
        with mock.patch(f"{self.TASK}.execute_iac_deployment") as task:
            task.apply_async.side_effect = apply_async
            resp = self._post_execute(run)
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertTrue(body["dispatched"])
        # the REAL persisted run id, not a fabricated constant
        self.assertEqual(body["run_id"], run.id)
        self.assertEqual(body["state"], "EXECUTION_REQUESTED")
        # the durable state moved BEFORE the broker call
        stored = self.app.state.engine.store.get(run.id)
        self.assertEqual(stored["state"], "EXECUTION_REQUESTED")
        # the durable dispatch identity persisted with the run (audit
        # P1-2) and used as the celery task_id
        dispatch = stored["execution"]["dispatch"]
        self.assertTrue(dispatch["dispatch_id"])
        self.assertEqual(dispatch["task_id"], task_ids[0])
        # exactly one enqueue, carrying the same immutable artifact
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["run_id"], run.id)
        self.assertEqual(calls[0]["artifact_hash"], run.artifact_hash)
        self.assertEqual(calls[0]["plan_hash"], run.plan_hash)

    def test_duplicate_dispatch_is_refused_and_enqueues_nothing(self):
        run = self._create_and_approve()
        calls, task_ids, apply_async = self._captured_task()
        with mock.patch(f"{self.TASK}.execute_iac_deployment") as task:
            task.apply_async.side_effect = apply_async
            first = self._post_execute(run)
            self.assertEqual(first.status_code, 200, first.text)
            second = self._post_execute(run)
        self.assertEqual(second.status_code, 409, second.text)
        self.assertIn("fresh", second.text,
                      "a FRESH duplicate is refused, not re-delivered")
        self.assertEqual(len(calls), 1, "a duplicate must NOT enqueue again")

    def test_pre_send_refusal_reverts_and_reports_unavailable(self):
        # EVERY attempt provably failed PRE-SEND: a clean TCP refusal of
        # the connection means no publish bytes could have reached the
        # broker, so the atomic revert to APPROVED is truthful. (A
        # generic/timeout failure is NOT treated this way — see the
        # ambiguity tests below.)
        run = self._create_and_approve()

        def _refused(kwargs=None, **_):
            raise ConnectionError(
                "Error 111 connecting to 127.0.0.1:6379. Connection refused."
            )

        with mock.patch(f"{self.TASK}.execute_iac_deployment") as task:
            task.apply_async.side_effect = _refused
            resp = self._post_execute(run)
        self.assertEqual(resp.status_code, 503, resp.text)
        self.assertNotIn("dispatched\": true", resp.text)
        # the run went back to APPROVED — it can be dispatched later
        stored = self.app.state.engine.store.get(run.id)
        self.assertEqual(stored["state"], "APPROVED")
        # and the revert was recorded against the dispatch identity
        self.assertTrue(any("reverted" in line for line in stored["logs"]))

    def test_execute_without_approval_is_409(self):
        engine = self.app.state.engine
        run = engine.create_dry_run(
            {
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
                "created_by": OPERATOR,
                "components": ["dockerfile", "kubernetes", "terraform", "pipeline"],
            }
        )
        resp = self.client.post(
            f"/api/internal/deployments/{run.id}/execute",
            json=self._execute_body(run),
            headers=self.auth,
        )
        self.assertEqual(resp.status_code, 409, resp.text)

    def test_hash_mismatch_dispatch_is_409_and_run_untouched(self):
        run = self._create_and_approve()
        with mock.patch(f"{self.TASK}.execute_iac_deployment") as task:
            resp = self.client.post(
                f"/api/internal/deployments/{run.id}/execute",
                json=self._execute_body(run, artifact_hash="f" * 64),
                headers=self.auth,
            )
        self.assertEqual(resp.status_code, 409, resp.text)
        self.assertEqual(self.app.state.engine.store.get(run.id)["state"],
                         "APPROVED")
        task.apply_async.assert_not_called()


class DispatchSafetyTests(_ContractAppBase):
    """Audit P1-2: the ambiguous-publish window, idempotent re-dispatch,
    and the race-safe (CAS) revert."""

    TASK = "deployment_service.infrastructure.celery.tasks"

    # -- ambiguous publish ----------------------------------------------

    def test_ambiguous_publish_keeps_run_and_reports_unknown(self):
        # A publish that times out while the broker is REACHABLE must not
        # be answered with "nothing was executed": the task may already
        # be queued and executing. The run stays EXECUTION_REQUESTED, the
        # API reports dispatched:"unknown", and re-POSTing the same
        # request idempotently re-publishes the SAME stable task id.
        run = self._create_and_approve()
        attempts = []

        def _timeout(kwargs=None, **apply_kwargs):
            attempts.append(apply_kwargs.get("task_id"))
            raise TimeoutError("socket timeout while publishing to broker")

        with mock.patch(f"{self.TASK}.execute_iac_deployment") as task:
            task.apply_async.side_effect = _timeout
            first = self._post_execute(run)
        self.assertEqual(first.status_code, 200, first.text)
        body = first.json()
        self.assertEqual(body["dispatched"], "unknown", body)
        self.assertEqual(body["state"], "EXECUTION_REQUESTED")
        # NOT reverted — the task may be running
        stored = self.app.state.engine.store.get(run.id)
        self.assertEqual(stored["state"], "EXECUTION_REQUESTED")
        dispatch = stored["execution"]["dispatch"]
        self.assertTrue(dispatch["ambiguous"])
        # bounded retries before probing, all with the SAME task id
        self.assertEqual(len(attempts), 3, "bounded retries before probing")
        self.assertEqual(len(set(attempts)), 1)

        # re-POST the SAME request: the durable dispatch is ambiguous, so
        # it is eligible for idempotent re-delivery
        calls, task_ids, apply_async = self._captured_task()
        with mock.patch(f"{self.TASK}.execute_iac_deployment") as task:
            task.apply_async.side_effect = apply_async
            second = self._post_execute(run)
        self.assertEqual(second.status_code, 200, second.text)
        self.assertTrue(second.json()["dispatched"])
        self.assertEqual(len(calls), 1)
        # the SAME stable task id — the worker's idempotency absorbs any
        # duplicate message, never a second execution
        self.assertEqual(task_ids[0], dispatch["task_id"])
        stored = self.app.state.engine.store.get(run.id)
        dispatch = stored["execution"]["dispatch"]
        self.assertEqual(dispatch["attempts"], 2)
        self.assertFalse(dispatch["ambiguous"],
                         "a successful publish clears the ambiguity")

    # -- Blocker D: an ambiguous send is NEVER reverted ---------------------

    def test_accepted_then_timeout_never_reverts(self):
        # The broker ACCEPTED the message, then the producer lost its
        # reply (timeout). Even with the broker now unreachable, the run
        # must NOT be reverted and must not claim "nothing was executed"
        # — a ping cannot prove historical non-acceptance.
        run = self._create_and_approve()
        engine = self.app.state.engine
        attempts = []

        def _timeout_after_accept(kwargs=None, **apply_kwargs):
            attempts.append(apply_kwargs.get("task_id"))
            raise TimeoutError("timeout reading from broker after publish")

        with mock.patch(f"{self.TASK}.execute_iac_deployment") as task, \
             mock.patch.object(engine.store, "ping",
                               side_effect=OSError("broker outage")):
            task.apply_async.side_effect = _timeout_after_accept
            resp = self._post_execute(run)
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json()["dispatched"], "unknown")
        stored = engine.store.get(run.id)
        self.assertEqual(stored["state"], "EXECUTION_REQUESTED",
                         "an ambiguous send is never reverted, even if the "
                         "broker is down now")
        self.assertTrue(stored["execution"]["dispatch"]["ambiguous"])
        self.assertEqual(len(attempts), 3)
        self.assertEqual(len(set(attempts)), 1)

    def test_accepted_then_outage_never_reverts(self):
        # A mid-command disconnect (the message MAY have been accepted)
        # followed by a broker outage: the failure signature is not a
        # clean pre-send refusal, so the run must NOT be reverted.
        run = self._create_and_approve()
        engine = self.app.state.engine

        def _mid_command_reset(kwargs=None, **_):
            raise OSError("Connection reset by peer during publish")

        with mock.patch(f"{self.TASK}.execute_iac_deployment") as task, \
             mock.patch.object(engine.store, "ping",
                               side_effect=OSError("broker outage")):
            task.apply_async.side_effect = _mid_command_reset
            resp = self._post_execute(run)
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json()["dispatched"], "unknown")
        stored = engine.store.get(run.id)
        self.assertEqual(stored["state"], "EXECUTION_REQUESTED")
        self.assertTrue(stored["execution"]["dispatch"]["ambiguous"])

    def test_mixed_pre_send_and_ambiguous_attempts_is_ambiguous(self):
        # Attempt 1: clean refusal (pre-send). Attempt 2: mid-command
        # reset (ambiguous). ANY ambiguous attempt makes the whole
        # outcome ambiguous: no revert.
        run = self._create_and_approve()
        engine = self.app.state.engine
        sequence = [
            ConnectionError(
                "Error 111 connecting to 127.0.0.1:6379. Connection refused."
            ),
            OSError("Connection reset by peer during publish"),
            TimeoutError("timeout"),
        ]
        it = iter(sequence)

        def _mixed(kwargs=None, **_):
            raise next(it)

        with mock.patch(f"{self.TASK}.execute_iac_deployment") as task:
            task.apply_async.side_effect = _mixed
            resp = self._post_execute(run)
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json()["dispatched"], "unknown")
        self.assertEqual(engine.store.get(run.id)["state"],
                         "EXECUTION_REQUESTED")

    # -- Blocker A: concurrent initial dispatches ---------------------------

    def test_concurrent_execute_from_approved_exactly_one_claim_wins(self):
        # Two concurrent /execute requests from the SAME APPROVED
        # document, synchronized so both reach the claim phase: exactly
        # one dispatch claim wins; the loser publishes nothing.
        run = self._create_and_approve()
        engine = self.app.state.engine
        store = engine.store
        real_save_cas = store.save_cas
        barrier = threading.Barrier(2, timeout=20)
        calls, task_ids = [], []

        def _guarded_save_cas(run_id, expected_revision, run):
            barrier.wait()  # both requests reach the claim phase
            return real_save_cas(run_id, expected_revision, run)

        def _apply_async(kwargs=None, **apply_kwargs):
            calls.append(kwargs)
            task_ids.append(apply_kwargs.get("task_id"))
            result = mock.MagicMock()
            result.id = "task-fake-1"
            return result

        results, errors = [], []

        def _post(client):
            try:
                with mock.patch(f"{self.TASK}.execute_iac_deployment") as task:
                    task.apply_async.side_effect = _apply_async
                    results.append(client.post(
                        f"/api/internal/deployments/{run.id}/execute",
                        json=self._execute_body(run),
                        headers=self.auth,
                    ))
            except Exception as exc:  # noqa: BLE001 - surfaced as failure
                errors.append(exc)

        with mock.patch.object(store, "save_cas", _guarded_save_cas):
            t1 = threading.Thread(target=_post, args=(TestClient(self.app),))
            t2 = threading.Thread(target=_post, args=(TestClient(self.app),))
            t1.start(); t2.start(); t1.join(30); t2.join(30)
        self.assertEqual(errors, [], f"unexpected client error: {errors}")
        self.assertEqual(len(results), 2)
        codes = sorted(r.status_code for r in results)
        self.assertEqual(codes, [200, 409],
                         "exactly one claim wins; the loser is refused")
        self.assertEqual(len(calls), 1,
                         "the losing request must NOT publish")
        stored = store.get(run.id)
        self.assertEqual(stored["state"], "EXECUTION_REQUESTED")
        # the winning claim's dispatch identity is the one that was
        # published — stable, single, durable
        self.assertEqual(stored["execution"]["dispatch"]["task_id"],
                         task_ids[0])

    # -- Blocker B: redelivery cannot overwrite an advanced run -------------

    def test_redelivery_cannot_overwrite_advanced_run(self):
        run, dispatch = self._dispatched_run()
        engine = self.app.state.engine
        store = engine.store
        # the re-dispatch writer's read: EXECUTION_REQUESTED at rev R
        read = store.get(run.id)
        writer = DeploymentRun.from_dict(read)
        self.assertEqual(writer.state, DeploymentState.EXECUTION_REQUESTED)
        # between its read and its write, a worker advances the run
        # (the same revision-bumping write the fenced commit performs)
        advanced = DeploymentRun.from_dict(store.get(run.id))
        advanced.move(DeploymentState.DEPLOYING)
        store.save(advanced)
        # the writer's STALE claim must be refused
        writer.execution["dispatch"]["attempts"] += 1
        ok = store.save_cas(run.id, expected_revision=writer.revision,
                            run=writer)
        self.assertFalse(ok, "a stale redelivery write must be refused")
        # the worker's state stands — no clobber
        stored = store.get(run.id)
        self.assertEqual(stored["state"], "DEPLOYING")
        self.assertEqual(stored["execution"]["dispatch"]["attempts"], 1)
        # and the method itself, called after the advance, refuses
        with self.assertRaises(DeploymentActionError):
            engine.redeliver_dispatch(
                run.id, run.artifact_hash, run.plan_hash)
        self.assertEqual(store.get(run.id)["state"], "DEPLOYING")
        self.assertEqual(store.get(run.id)["execution"]["dispatch"]
                         ["attempts"], 1)

    # -- Blocker C: stale bookkeeping cannot reset newer state --------------

    def test_stale_outcome_cannot_reset_redelivery_bookkeeping(self):
        run, dispatch = self._dispatched_run()
        engine = self.app.state.engine
        store = engine.store
        read = store.get(run.id)
        rev = int(read.get("revision") or 0)
        dispatch_id = dispatch["dispatch_id"]
        # writer 1: a redelivery (attempts -> 2) reading at revision R
        w1 = DeploymentRun.from_dict(read)
        w1.execution["dispatch"]["attempts"] = 2
        w1.execution["dispatch"]["last_attempt_at"] = time.time()
        # writer 2: a STALE outcome from the original publish (attempts
        # still 1) reading at the SAME revision R
        w2 = DeploymentRun.from_dict(read)
        w2.execution["dispatch"]["ambiguous"] = False
        # both CAS on the same read: exactly one applies
        r1 = store.save_cas(run.id, expected_revision=rev, run=w1)
        r2 = store.cas_run_document(
            run.id, "EXECUTION_REQUESTED", dispatch_id, rev, w2)
        self.assertTrue(r1)
        self.assertFalse(r2,
                         "a stale writer at the same revision cannot apply "
                         "after the first write")
        final = store.get(run.id)
        self.assertEqual(final["execution"]["dispatch"]["attempts"], 2)
        self.assertEqual(final.get("revision"), rev + 1)
        # a stale outcome retrying the same old read is refused again —
        # the bookkeeping cannot be reset
        w3 = DeploymentRun.from_dict(read)
        w3.execution["dispatch"]["ambiguous"] = False
        self.assertFalse(store.cas_run_document(
            run.id, "EXECUTION_REQUESTED", dispatch_id, rev, w3))
        self.assertEqual(store.get(run.id)["execution"]["dispatch"]
                         ["attempts"], 2)

    # -- stale redelivery --------------------------------------------------

    def test_stale_dispatch_redelivered_idempotently(self):
        run = self._create_and_approve()
        calls, task_ids, apply_async = self._captured_task()
        with mock.patch(f"{self.TASK}.execute_iac_deployment") as task:
            task.apply_async.side_effect = apply_async
            first = self._post_execute(run)
        self.assertEqual(first.status_code, 200, first.text)
        original_task_id = task_ids[0]

        # simulate a lost message: no worker progress, and the last
        # attempt is older than the staleness threshold (2x visibility)
        engine = self.app.state.engine
        stored = engine.store.get(run.id)
        stored["execution"]["dispatch"]["last_attempt_at"] = (
            time.time() - engine.RE_DISPATCH_STALE_AFTER_SECONDS - 800
        )
        engine.store.save(DeploymentRun.from_dict(stored))

        calls, task_ids, apply_async = self._captured_task()
        with mock.patch(f"{self.TASK}.execute_iac_deployment") as task:
            task.apply_async.side_effect = apply_async
            second = self._post_execute(run)
        # a STALE dispatch is idempotently re-deliverable
        self.assertEqual(second.status_code, 200, second.text)
        self.assertTrue(second.json()["dispatched"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(task_ids[0], original_task_id,
                         "redelivery reuses the SAME stable task id")
        stored = engine.store.get(run.id)
        self.assertEqual(stored["execution"]["dispatch"]["attempts"], 2)
        self.assertFalse(stored["execution"]["dispatch"]["ambiguous"])

    # -- redelivery refusals ----------------------------------------------

    def test_redelivery_with_hash_mismatch_is_409(self):
        run = self._create_and_approve()
        calls, task_ids, apply_async = self._captured_task()
        with mock.patch(f"{self.TASK}.execute_iac_deployment") as task:
            task.apply_async.side_effect = apply_async
            first = self._post_execute(run)
        self.assertEqual(first.status_code, 200, first.text)

        # a re-dispatch for a NEWER pipeline generation (different
        # artifact) must be refused — it cannot attach to the old dispatch
        calls, task_ids, _apply_async = self._captured_task()
        with mock.patch(f"{self.TASK}.execute_iac_deployment") as task:
            task.apply_async.side_effect = _apply_async
            second = self._post_execute(run, artifact_hash="f" * 64)
        self.assertEqual(second.status_code, 409, second.text)
        self.assertIn("hash", second.text)
        self.assertEqual(len(calls), 0, "a refused redelivery enqueues nothing")
        stored = self.app.state.engine.store.get(run.id)
        self.assertEqual(stored["state"], "EXECUTION_REQUESTED")
        self.assertEqual(stored["execution"]["dispatch"]["attempts"], 1)

    def test_terminal_run_execute_is_409(self):
        from deployment_service.infrastructure.celery import tasks as task_mod

        run = self._create_and_approve()
        mod, factory = self._patched_engine_class()
        # run the task to a terminal state (DEPLOYED)
        with mock.patch.object(mod, "DeploymentEngine", factory):
            result = task_mod.execute_iac_deployment.run(
                run.id, run.artifact_hash, run.plan_hash,
                dockerfile="FROM python:3.11-slim\nUSER 10001\n",
                k8s_yaml=("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n"
                          "  name: d\nspec:\n  template:\n    spec:\n"
                          "      containers:\n        - name: d\n"
                          "          image: d:latest\n"),
                terraform_tf='terraform { required_version = ">= 1.5.0" }\n',
                pipeline_yaml="name: ci\n",
            )
        self.assertEqual(result["status"], "SUCCEEDED", result)
        self.assertEqual(self.app.state.engine.store.get(run.id)["state"],
                         "DEPLOYED")

        # executing a terminal run is refused — the run is not resurrected
        resp = self._post_execute(run)
        self.assertEqual(resp.status_code, 409, resp.text)
        self.assertEqual(self.app.state.engine.store.get(run.id)["state"],
                         "DEPLOYED")

    # -- the CAS revert: never a clobber -----------------------------------

    def _dispatched_run(self):
        """Create + approve + dispatch (publish OK); return (run, dispatch)."""
        run = self._create_and_approve()
        _, _, apply_async = self._captured_task()
        with mock.patch(f"{self.TASK}.execute_iac_deployment") as task:
            task.apply_async.side_effect = apply_async
            resp = self._post_execute(run)
        self.assertEqual(resp.status_code, 200, resp.text)
        dispatch = self.app.state.engine.store.get(run.id)[
            "execution"]["dispatch"]
        return run, dispatch

    def test_revert_cas_noop_when_run_advanced(self):
        # The publish failed and the broker is down, but a worker took
        # the run in the meantime (the message had landed). The revert
        # must be a NO-OP — it must not clobber the worker's DEPLOYING
        # state.
        run, dispatch = self._dispatched_run()
        engine = self.app.state.engine
        stored = engine.store.get(run.id)
        advanced = DeploymentRun.from_dict(stored)
        advanced.move(DeploymentState.DEPLOYING)
        engine.store.save(advanced)
        reverted = engine.revert_dispatch(run.id, dispatch["dispatch_id"])
        self.assertFalse(reverted)
        self.assertEqual(engine.store.get(run.id)["state"], "DEPLOYING")

    def test_revert_cas_noop_when_worker_fence_active(self):
        # Same window, fence evidence: a worker fence is active, so the
        # CAS revert refuses even though the state is still
        # EXECUTION_REQUESTED.
        run, dispatch = self._dispatched_run()
        engine = self.app.state.engine
        fence = active_fence_key(run.id)
        engine.store.client.set(fence, "worker-owner-token", ex=300)
        self.addCleanup(engine.store.client.delete, fence)
        reverted = engine.revert_dispatch(run.id, dispatch["dispatch_id"])
        self.assertFalse(reverted)
        self.assertEqual(engine.store.get(run.id)["state"],
                         "EXECUTION_REQUESTED")

    def test_revert_cas_noop_on_dispatch_identity_mismatch(self):
        # A revert carrying a DIFFERENT dispatch identity (a stale error
        # handler from an older request) must not touch the current
        # dispatch.
        run, dispatch = self._dispatched_run()
        engine = self.app.state.engine
        reverted = engine.revert_dispatch(run.id, "some-older-dispatch-id")
        self.assertFalse(reverted)
        stored = engine.store.get(run.id)
        self.assertEqual(stored["state"], "EXECUTION_REQUESTED")
        self.assertEqual(stored["execution"]["dispatch"]["dispatch_id"],
                         dispatch["dispatch_id"])


class WorkerIdempotencyTests(_ContractAppBase):
    """The worker task under at-least-once delivery (F5/F7)."""

    def test_terminal_run_redelivery_returns_persisted_outcome(self):
        from deployment_service.infrastructure.celery import tasks as task_mod

        run = self._create_and_approve()
        mod, factory = self._patched_engine_class()
        # first delivery: full execution through the fakes → DEPLOYED
        with mock.patch.object(mod, "DeploymentEngine", factory):
            result1 = task_mod.execute_iac_deployment.run(
            run.id, run.artifact_hash, run.plan_hash,
            dockerfile="FROM python:3.11-slim\nUSER 10001\n",
            k8s_yaml=("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n"
                      "  name: d\nspec:\n  template:\n    spec:\n"
                      "      containers:\n        - name: d\n"
                      "          image: d:latest\n"),
            terraform_tf='terraform { required_version = ">= 1.5.0" }\n',
            pipeline_yaml="name: ci\n",
            )
        self.assertEqual(result1["status"], "SUCCEEDED", result1)
        self.assertEqual(result1["final_state"], "DEPLOYED")
        self.assertFalse(result1.get("idempotent_replay", False))

        # the fakes record side effects: exactly one apply happened
        applied = self.app.state.engine.kubectl.applied_calls
        self.assertEqual(len(applied), 1)

        # redelivery: same payload, must NOT start anything
        mod, factory = self._patched_engine_class()
        with mock.patch.object(mod, "DeploymentEngine", factory):
            result2 = task_mod.execute_iac_deployment.run(
                run.id, run.artifact_hash, run.plan_hash,
                dockerfile="FROM python:3.11-slim\nUSER 10001\n",
                k8s_yaml=("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n"
                          "  name: d\nspec:\n  template:\n    spec:\n"
                          "      containers:\n        - name: d\n"
                          "          image: d:latest\n"),
                terraform_tf='terraform { required_version = ">= 1.5.0" }\n',
                pipeline_yaml="name: ci\n",
            )
        self.assertEqual(result2["status"], "SUCCEEDED", result2)
        self.assertTrue(result2["idempotent_replay"])
        self.assertEqual(result2["dispatched"], False)
        self.assertEqual(
            len(self.app.state.engine.kubectl.applied_calls), 1,
            "redelivery must not re-apply",
        )

    def test_concurrent_duplicate_reports_already_executing(self):
        from deployment_service.infrastructure.celery import tasks as task_mod

        run = self._create_and_approve()
        # hold the lease as a "concurrent" owner before the task runs
        guard = self.lease_factory.acquire(run.id)
        self.addCleanup(guard.release)

        mod, factory = self._patched_engine_class()
        # a true duplicate carries the SAME artifact bundle as the
        # original dispatch (hashes must verify before the lease check)
        with mock.patch.object(mod, "DeploymentEngine", factory):
            result = task_mod.execute_iac_deployment.run(
                run.id, run.artifact_hash, run.plan_hash,
                dockerfile="FROM python:3.11-slim\nUSER 10001\n",
                k8s_yaml=("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n"
                          "  name: d\nspec:\n  template:\n    spec:\n"
                          "      containers:\n        - name: d\n"
                          "          image: d:latest\n"),
                terraform_tf='terraform { required_version = ">= 1.5.0" }\n',
                pipeline_yaml="name: ci\n",
            )
        self.assertEqual(result["status"], "ALREADY_EXECUTING", result)
        self.assertFalse(result["dispatched"])
        self.assertEqual(result["error_code"], "LEASE_HELD_BY_OTHER_OWNER")
        # the run state was not touched by the duplicate
        self.assertEqual(self.app.state.engine.store.get(run.id)["state"],
                         "APPROVED")

    def test_execution_disabled_is_typed_blocked(self):
        from deployment_service.infrastructure.celery import tasks as task_mod

        run = self._create_and_approve()
        # flip the flag for the task's engine (fresh DeploymentEngine())
        with mock.patch.dict(
            "os.environ",
            {
                "JWT_SECRET": TEST_SECRET,
                "AGENT_INTERNAL_TOKEN": TEST_INTERNAL,
                "DEPLOYMENT_EXECUTION_ENABLED": "false",
            },
        ):
            result = task_mod.execute_iac_deployment.run(
                run.id, run.artifact_hash, run.plan_hash,
                dockerfile="FROM python:3.11-slim\nUSER 10001\n",
            )
        self.assertEqual(result["status"], "BLOCKED", result)
        self.assertFalse(result["dispatched"])
        self.assertEqual(result["error_code"], "EXECUTION_REFUSED")
        self.assertEqual(self.app.state.engine.store.get(run.id)["state"],
                         "APPROVED")


if __name__ == "__main__":
    unittest.main()
