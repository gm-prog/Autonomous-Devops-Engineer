"""Phase 8.8A Correction-1 (F7) — single execution contract, truthful
dispatch.

The API's ``/execute`` is a DISPATCH, not an execution:

* 200/``dispatched: true`` only after the durable run moved to
  EXECUTION_REQUESTED AND the task reached the broker, with the REAL
  persisted run id;
* a duplicate dispatch of an EXECUTION_REQUESTED run is refused (409)
  and enqueues NOTHING extra;
* a broker failure reverts the run to APPROVED and reports 503 — never
  an accepted/queued state for undelivered work;
* the worker task is idempotent under at-least-once delivery: a
  redelivery for a terminal run returns the persisted outcome and
  starts nothing; a concurrent duplicate finds the lease held and
  reports ALREADY_EXECUTING without touching the run.
"""
import os
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


class DispatchTruthTests(_ContractAppBase):
    TASK = "deployment_service.infrastructure.celery.tasks"

    def _captured_task(self):
        calls = []

        def _apply_async(kwargs=None, **_):
            calls.append(kwargs)
            result = mock.MagicMock()
            result.id = "task-fake-1"
            return result

        return calls, _apply_async

    def test_dispatch_persists_then_enqueues_and_reports_truth(self):
        run = self._create_and_approve()
        calls, apply_async = self._captured_task()
        with mock.patch(f"{self.TASK}.execute_iac_deployment") as task:
            task.apply_async.side_effect = apply_async
            resp = self.client.post(
                f"/api/internal/deployments/{run.id}/execute",
                json=self._execute_body(run),
                headers=self.auth,
            )
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertTrue(body["dispatched"])
        # the REAL persisted run id, not a fabricated constant
        self.assertEqual(body["run_id"], run.id)
        self.assertEqual(body["state"], "EXECUTION_REQUESTED")
        # the durable state moved BEFORE the broker call
        self.assertEqual(self.app.state.engine.store.get(run.id)["state"],
                         "EXECUTION_REQUESTED")
        # exactly one enqueue, carrying the same immutable artifact
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["run_id"], run.id)
        self.assertEqual(calls[0]["artifact_hash"], run.artifact_hash)
        self.assertEqual(calls[0]["plan_hash"], run.plan_hash)

    def test_duplicate_dispatch_is_refused_and_enqueues_nothing(self):
        run = self._create_and_approve()
        calls, apply_async = self._captured_task()
        with mock.patch(f"{self.TASK}.execute_iac_deployment") as task:
            task.apply_async.side_effect = apply_async
            first = self.client.post(
                f"/api/internal/deployments/{run.id}/execute",
                json=self._execute_body(run),
                headers=self.auth,
            )
            self.assertEqual(first.status_code, 200, first.text)
            second = self.client.post(
                f"/api/internal/deployments/{run.id}/execute",
                json=self._execute_body(run),
                headers=self.auth,
            )
        self.assertEqual(second.status_code, 409, second.text)
        self.assertEqual(len(calls), 1, "a duplicate must NOT enqueue again")

    def test_broker_failure_reverts_and_reports_unavailable(self):
        run = self._create_and_approve()

        def _down(kwargs=None, **_):
            raise ConnectionError("broker unreachable")

        with mock.patch(f"{self.TASK}.execute_iac_deployment") as task:
            task.apply_async.side_effect = _down
            resp = self.client.post(
                f"/api/internal/deployments/{run.id}/execute",
                json=self._execute_body(run),
                headers=self.auth,
            )
        self.assertEqual(resp.status_code, 503, resp.text)
        self.assertNotIn("dispatched\": true", resp.text)
        # the run went back to APPROVED — it can be dispatched later
        stored = self.app.state.engine.store.get(run.id)
        self.assertEqual(stored["state"], "APPROVED")

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


class WorkerIdempotencyTests(_ContractAppBase):
    """The worker task under at-least-once delivery (F5/F7)."""

    def _patched_engine_class(self):
        """The task builds a fresh DeploymentEngine (imported lazily
        from the engine module); point that import at the app's engine
        (deterministic fakes + shared store) so the test proves the
        TASK's orchestration, not the sandbox stack."""
        from deployment_service.application.services import deployment_engine

        def _factory(*args, **kwargs):
            return self.app.state.engine

        return deployment_engine, _factory

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
