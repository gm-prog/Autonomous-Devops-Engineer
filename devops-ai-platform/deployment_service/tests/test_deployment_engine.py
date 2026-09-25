
import pytest

from deployment_service.application.services.deployment_engine import DeploymentActionError, DeploymentEngine
from deployment_service.domain.value_objects.deployment_state import DeploymentState


class FakeStore:
    def __init__(self):
        self.data, self.locks = {}, set()
    def save(self, run): self.data[run.id] = run.to_dict()
    def get(self, run_id): return self.data.get(run_id)
    def acquire_lock(self, run_id, ttl_seconds=900):
        if run_id in self.locks: return False
        self.locks.add(run_id); return True
    def release_lock(self, run_id): self.locks.discard(run_id)


class FakeTerraform:
    def run_plan(self, iac_dir, execution=False, plan_output_path=None):
        return {"status": "PASS", "execution": execution, "plan": {"stdout": "plan-ok"}, "plan_file_hash": "a" * 64 if execution else ""}
    def apply_plan(self, iac_dir, plan_output_path): return {"status": "PASS", "stdout": "apply-ok"}


class FakeKubectl:
    def dry_run(self, manifest_path, namespace="devops-production-namespace"): return {"status": "PASS", "stdout": "dry-run-ok", "cluster_access": False}
    def apply(self, manifest_path, namespace): return {"status": "PASS", "stdout": "apply-ok", "cluster_access": True}
    def rollout_status(self, deployment_name, namespace): return {"status": "PASS", "stdout": "rollout-ok", "cluster_access": True}
    def rollout_undo(self, deployment_name, namespace): return {"status": "PASS", "stdout": "undo-ok", "cluster_access": True}


class FakeHealth:
    def check(self, kubectl, deployment_names, namespace, healthcheck_url): return {"status": "PASS", "checks": [{"status": "PASS"}]}


class FakeValidator:
    def validate(self, *args): return {"status": "PASS", "checks": {}}


VALID_PAYLOAD = {
    "repository_id": 1, "repository_name": "demo", "requested_by": "developer",
    "dockerfile": "FROM python:3.11-slim\nUSER 10001\n",
    "k8s_yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\nspec:\n  template:\n    spec:\n      containers:\n        - name: demo\n          image: demo:latest\n",
    "terraform_tf": 'terraform { required_version = ">= 1.5.0" }\n',
    "pipeline_yaml": "name: ci\n",
    "source_revision": {
        "head_sha": "a" * 40,
        "commits": [{"sha": "a" * 40, "subject": "deploy change", "files_changed_count": 1}],
        "summary": {"commit_count": 1, "files_changed": 1, "additions": 10, "deletions": 2},
    },
}


def build_engine():
    return DeploymentEngine(store=FakeStore(), validator=FakeValidator(), terraform=FakeTerraform(), kubectl=FakeKubectl(), health_checker=FakeHealth())


def test_dry_run_waits_for_human_approval():
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    assert run.state == DeploymentState.AWAITING_APPROVAL
    assert len(run.artifact_hash) == 64 and len(run.plan_hash) == 64


def test_approval_binds_identity_to_hashes():
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    approved = engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    assert approved.state == DeploymentState.APPROVED
    assert approved.approval["approved_by"] == "human"


def test_approval_rejects_hash_mismatch():
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    with pytest.raises(DeploymentActionError):
        engine.approve(run.id, "human", "0" * 64, run.plan_hash)


def test_execution_is_disabled_by_default(monkeypatch):
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    monkeypatch.delenv("DEPLOYMENT_EXECUTION_ENABLED", raising=False)
    with pytest.raises(DeploymentActionError):
        engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)


def test_approved_execution_reaches_deployed(monkeypatch):
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    completed = engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)
    assert completed.state == DeploymentState.DEPLOYED
    assert completed.execution["terraform_applied"] is True
    assert completed.execution["kubernetes_applied"] is True


def test_source_revision_is_persisted_and_bound_to_plan_hash():
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    assert run.source_revision["head_sha"] == "a" * 40
    assert run.source_revision["summary"]["files_changed"] == 1
    assert len(run.plan_hash) == 64


def test_source_revision_changes_plan_hash():
    first = build_engine().create_dry_run(VALID_PAYLOAD)
    changed = dict(VALID_PAYLOAD)
    changed["source_revision"] = dict(VALID_PAYLOAD["source_revision"], head_sha="b" * 40)
    second = build_engine().create_dry_run(changed)
    assert first.plan_hash != second.plan_hash
