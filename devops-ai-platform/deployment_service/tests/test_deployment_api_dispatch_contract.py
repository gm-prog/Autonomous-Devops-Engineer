"""Phase 8.8A Correction-1 (F7, independent audit P1-2) — single
execution contract, truthful dispatch, safe ambiguity.

The API's ``/execute`` is a DISPATCH, not an execution, and it never
conflates "the broker accepted the task", "the broker never received
it", and "we do not know which":

* 200/``dispatched: true`` only after the durable run moved to
  EXECUTION_REQUESTED AND the publish completed, with the REAL
  persisted run id;
* a duplicate dispatch of a FRESH (non-ambiguous, non-stale)
  EXECUTION_REQUESTED run is refused (409) and enqueues NOTHING extra;
* a publish that fails while the broker is CONFIRMED DOWN reverts the
  run to APPROVED (atomic CAS) and reports 503 — nothing was executed;
* a publish that fails while the broker is REACHABLE is AMBIGUOUS: the
  run is NOT reverted (the task may be queued and executing), the API
  reports ``dispatched: "unknown"``, and re-POSTing the same request
  idempotently re-publishes the SAME stable task id (the worker's lease
  + terminal-state check absorb duplicates);
* a stale dispatch (no worker progress for > 2x the visibility timeout)
  is idempotently re-deliverable;
* a broker-failure revert is a no-op — never a clobber — when the run
  already advanced, a worker fence is active, or the dispatch identity
  changed;
* the worker task is idempotent under at-least-once delivery: a
  redelivery for a terminal run returns the persisted outcome and
  starts nothing; a concurrent duplicate finds the lease held and
  reports ALREADY_EXECUTING without touching the run.
"""
import os
import time
import unittest
from unittest import mock

from fastapi.testclient import TestClient

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

    def test_broker_failure_reverts_and_reports_unavailable(self):
        # Broker CONFIRMED DOWN: the publish failed on every attempt AND
        # the reachability probe also failed, so the task cannot have
        # been enqueued — the atomic revert to APPROVED is truthful.
        run = self._create_and_approve()

        def _down(kwargs=None, **_):
            raise ConnectionError("broker unreachable")

        with mock.patch(f"{self.TASK}.execute_iac_deployment") as task, \
             mock.patch("deployment_service.main._broker_reachable",
                        return_value=False):
            task.apply_async.side_effect = _down
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
