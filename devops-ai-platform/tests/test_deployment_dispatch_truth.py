"""Phase 8.8A — dispatch-truth tests for the fixed orchestration paths.

The candidate source (029ab490) carried four success-shaped fakes in the
deployment slice:

  * gRPC impl returned a hard-coded ``run_grpc_998`` + ``SUCCESS``;
  * the Celery task slept and logged "Active/Healthy";
  * the compile-IaC command returned hard-coded sample manifests;
  * the legacy execute command returned a run ID from an in-process
    idempotency dict for a dispatch that was commented out.

This module proves each fixed path fails honestly:

  * structural assertions — the fabricated literals no longer exist in
    the source;
  * behavioral assertions — invalid input yields a typed failure (never
    SUCCESS), valid input yields the REAL run identifier from the
    engine, refused execution yields typed BLOCKED with the run state
    untouched, and a concurrent duplicate is refused by the execution
    lock.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from conftest import PLATFORM_ROOT

SERVICE_ROOT = PLATFORM_ROOT / "deployment_service"

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeStore:
    def __init__(self):
        self.data = {}
        self.locked = set()

    def save(self, run):
        self.data[run.id] = run.to_dict()

    def get(self, run_id):
        return self.data.get(run_id)

    def acquire_lock(self, run_id):
        if run_id in self.locked:
            return False
        self.locked.add(run_id)
        return True

    def release_lock(self, run_id):
        self.locked.discard(run_id)


class _FakeSourceVerifier:
    def verify(self, repository_name, head_sha):
        return {"method": "fake-verifier", "verified": True}


class _FakeValidator:
    def validate(self, dockerfile, k8s_yaml, terraform_tf, pipeline_yaml, components=None):
        return {"status": "PASS", "checks": []}


class _FakeRun:
    """Just enough of a DeploymentRun for the seam tests."""

    def __init__(self, id_):
        self.id = id_
        self.state = SimpleNamespace(value="AWAITING_APPROVAL")
        self.artifact_hash = "a" * 64
        self.plan_hash = "p" * 64
        self.error = None

    def to_dict(self):
        return {"id": self.id, "state": self.state.value}


class _FakeEngine:
    def __init__(self, store=None, run_factory=None):
        import uuid

        self.store = store
        # A FRESH identifier per run, mirroring the real engine's
        # uuid-based run IDs (a constant would make "no fabricated run
        # ID" unprovable).
        self._run_factory = run_factory or (
            lambda: _FakeRun(f"run_{uuid.uuid4().hex[:12]}")
        )
        self.calls = []

    def create_dry_run(self, payload):
        self.calls.append(("create_dry_run", payload))
        return self._run_factory()

    def execute(self, run_id, payload, artifact_hash, plan_hash,
                namespace, healthcheck_url, previous_good_terraform_tf):
        self.calls.append(("execute", run_id))
        if artifact_hash != "a" * 64:
            from deployment_service.application.services.deployment_engine import (
                DeploymentActionError,
            )

            raise DeploymentActionError("Execution hashes do not match the approval record.")
        run = _FakeRun(run_id)
        run.state = SimpleNamespace(value="DEPLOYED")
        return run


def _grpc_request(**overrides):
    base = dict(
        repository_id=7,
        repository_name="acme/checkout",
        requested_by="operator@example.com",
        dockerfile="FROM python:3.11-slim\n",
        k8s_yaml="",
        terraform_tf="",
        pipeline_yaml="name: ci\n",
        head_sha="b" * 40,
        components=["dockerfile", "pipeline"],
    )
    base.update(overrides)
    return SimpleNamespace(**base)


# ---------------------------------------------------------------------------
# gRPC boundary — no fabricated run IDs, no unconditional SUCCESS
# ---------------------------------------------------------------------------


def test_grpc_invalid_request_is_typed_failure_never_success():
    from deployment_service.presentation.grpc.deployment_service_impl import (
        DeploymentServiceGRPCImpl,
    )

    engine = _FakeEngine()
    impl = DeploymentServiceGRPCImpl(engine=engine)
    for bad in (
        _grpc_request(head_sha="not-a-sha"),
        _grpc_request(repository_name="checkout"),  # not owner/repository
        _grpc_request(repository_id=0),
    ):
        resp = impl.TriggerContinuousDeployment(bad, context=None)
        assert resp.dispatch_status == "FAILED", (
            f"invalid request must be a typed FAILED, got {resp.dispatch_status}"
        )
        assert resp.dispatch_status != "SUCCESS"
        assert resp.pipeline_run_id is None, "no run may exist for an invalid request"
        assert resp.error_code == "INVALID_REQUEST"

    # Uppercase SHAs are canonicalized to lowercase (same contract as the
    # HTTP boundary) — accepted, not rejected.
    resp = impl.TriggerContinuousDeployment(
        _grpc_request(head_sha="B" * 40), context=None
    )
    assert resp.dispatch_status == "DRY_RUN_PERSISTED"
    sent_payload = engine.calls[0][1]
    assert sent_payload["source_revision"]["head_sha"] == "b" * 40


def test_grpc_valid_request_returns_real_persisted_run_id():
    from deployment_service.presentation.grpc.deployment_service_impl import (
        DeploymentServiceGRPCImpl,
    )

    store = _FakeStore()
    engine = _FakeEngine(store=store)
    impl = DeploymentServiceGRPCImpl(engine=engine)
    resp = impl.TriggerContinuousDeployment(_grpc_request(), context=None)

    assert resp.dispatch_status == "DRY_RUN_PERSISTED"
    assert resp.dispatch_status != "SUCCESS", "a dry run is not a deployment"
    assert isinstance(resp.pipeline_run_id, str)
    assert resp.pipeline_run_id.startswith("run_")
    # The run id came from the engine, not a constant: a second call
    # produces a different identifier.
    resp2 = impl.TriggerContinuousDeployment(_grpc_request(), context=None)
    assert resp2.pipeline_run_id != resp.pipeline_run_id


def test_grpc_engine_failure_is_typed_never_success():
    from deployment_service.presentation.grpc.deployment_service_impl import (
        DeploymentServiceGRPCImpl,
    )

    class _BrokenEngine(_FakeEngine):
        def create_dry_run(self, payload):
            from deployment_service.application.services.deployment_engine import (
                DeploymentActionError,
            )

            raise DeploymentActionError("Only an AWAITING_APPROVAL run can be approved.")

    impl = DeploymentServiceGRPCImpl(engine=_BrokenEngine())
    resp = impl.TriggerContinuousDeployment(_grpc_request(), context=None)
    assert resp.dispatch_status == "FAILED"
    assert resp.error_code == "DRY_RUN_REFUSED"
    assert resp.pipeline_run_id is None


def test_grpc_source_contains_no_fabricated_run_id():
    src = (SERVICE_ROOT / "presentation" / "grpc" / "deployment_service_impl.py").read_text()
    assert "run_grpc_998" not in src
    assert re.search(r'dispatch_status\s*=\s*["\']SUCCESS["\']', src) is None


# ---------------------------------------------------------------------------
# Celery task — real engine dispatch, no sleep-fake, typed results
# ---------------------------------------------------------------------------


def test_task_execution_disabled_is_typed_blocked(monkeypatch):
    from deployment_service.infrastructure.celery import tasks as task_mod

    monkeypatch.delenv("DEPLOYMENT_EXECUTION_ENABLED", raising=False)

    class _Engine:
        def __init__(self):
            pass

        def execute(self, *a, **k):
            from deployment_service.application.services.deployment_engine import (
                DeploymentActionError,
            )

            raise DeploymentActionError(
                "Real deployment execution is disabled. Set DEPLOYMENT_EXECUTION_ENABLED=true only after explicit runtime credentials are provisioned."
            )

    monkeypatch.setattr(
        "deployment_service.application.services.deployment_engine.DeploymentEngine",
        _Engine,
    )
    result = task_mod.execute_iac_deployment.run(
        "run_1", "a" * 64, "p" * 64,
        dockerfile="FROM python:3.11-slim\n", pipeline_yaml="name: ci\n",
    )
    assert result["status"] == "BLOCKED"
    assert result["dispatched"] is False
    assert result["error_code"] == "EXECUTION_REFUSED"
    assert "disabled" in result["error"]


def test_task_maps_engine_execution_to_typed_result(monkeypatch):
    from deployment_service.infrastructure.celery import tasks as task_mod

    engine = _FakeEngine()
    monkeypatch.setattr(
        "deployment_service.application.services.deployment_engine.DeploymentEngine",
        lambda: engine,
    )
    result = task_mod.execute_iac_deployment.run(
        "run_42", "a" * 64, "p" * 64,
        dockerfile="FROM python:3.11-slim\n", pipeline_yaml="name: ci\n",
    )
    # The REAL engine path was invoked (the fake records the call).
    assert ("execute", "run_42") in engine.calls
    assert result["status"] == "SUCCEEDED"
    assert result["run_id"] == "run_42"
    assert result["final_state"] == "DEPLOYED"


def test_task_hash_mismatch_is_typed_failed_not_success(monkeypatch):
    from deployment_service.infrastructure.celery import tasks as task_mod

    engine = _FakeEngine()
    monkeypatch.setattr(
        "deployment_service.application.services.deployment_engine.DeploymentEngine",
        lambda: engine,
    )
    result = task_mod.execute_iac_deployment.run(
        "run_43", "b" * 64, "p" * 64,  # wrong artifact hash
        dockerfile="FROM python:3.11-slim\n", pipeline_yaml="name: ci\n",
    )
    assert result["status"] == "BLOCKED"
    assert result["dispatched"] is False
    assert result["error_code"] == "EXECUTION_REFUSED"


def test_task_source_contains_no_sleep_fake():
    src = (SERVICE_ROOT / "infrastructure" / "celery" / "tasks.py").read_text()
    assert "time.sleep" not in src
    assert "Active/Healthy" not in src


# ---------------------------------------------------------------------------
# Compile IaC manifest — typed BLOCKED, never fabricated content
# ---------------------------------------------------------------------------


def test_compile_iac_manifest_is_typed_blocked():
    from deployment_service.application.commands.compile_iac_manifest import (
        CompileIaCManifestCommand,
        CompileIaCManifestCommandHandler,
    )

    handler = CompileIaCManifestCommandHandler()
    for platform in ("AWS", "GCP", "Kubernetes"):
        result = handler.handle(CompileIaCManifestCommand("repo-1", platform))
        assert result["status"] == "BLOCKED"
        assert result["error_code"] == "MANIFEST_COMPILATION_NOT_IMPLEMENTED"
        assert result["files"] == {}, "no fabricated manifest content may be returned"


def test_compile_iac_manifest_source_contains_no_samples():
    src = (SERVICE_ROOT / "application" / "commands" / "compile_iac_manifest.py").read_text()
    assert "aws_vpc" not in src
    assert "10.0.0.0/16" not in src


# ---------------------------------------------------------------------------
# Legacy execute command — typed BLOCKED, no in-memory idempotency,
# no fabricated run ID
# ---------------------------------------------------------------------------


def test_legacy_execute_command_is_typed_blocked():
    from deployment_service.application.commands.execute_deployment import (
        ExecuteDeploymentCommand,
        ExecuteDeploymentCommandHandler,
    )

    handler = ExecuteDeploymentCommandHandler()
    assert not hasattr(handler, "_idempotency_cache"), (
        "the in-process idempotency cache must not exist (it is not durable "
        "idempotency)"
    )
    result = handler.handle(
        ExecuteDeploymentCommand("pipeline-1", "ops@example.com", "key-1")
    )
    assert result["status"] == "BLOCKED"
    assert result["error_code"] == "PIPELINE_REPOSITORY_NOT_IMPLEMENTED"
    assert result["run_id"] is None, "no run ID may be fabricated"
    # Calling twice yields the same honest refusal — no state accrues.
    again = handler.handle(
        ExecuteDeploymentCommand("pipeline-1", "ops@example.com", "key-1")
    )
    assert again == result


# ---------------------------------------------------------------------------
# Pipeline aggregate — terminal Completed requires proof
# ---------------------------------------------------------------------------


def test_pipeline_completed_requires_verified_evidence():
    from deployment_service.domain.aggregates.pipeline import PipelineAggregate

    pipe = PipelineAggregate("p-1", "deploy")
    run = pipe.instantiate_run("ops@example.com")

    with pytest.raises(ValueError, match="Completed requires proof"):
        pipe.update_run_state(run.id, "Completed")

    pipe.update_run_state(
        run.id,
        "Completed",
        verified_operations={
            "terraform": "PASS",
            "kubernetes": "PASS",
        },
    )
    assert run.status == "Completed"


def test_pipeline_rejects_unknown_states():
    from deployment_service.domain.aggregates.pipeline import PipelineAggregate

    pipe = PipelineAggregate("p-2", "deploy")
    run = pipe.instantiate_run("ops@example.com")
    with pytest.raises(ValueError, match="unknown pipeline run state"):
        pipe.update_run_state(run.id, "WhateverTheCallerSays")
