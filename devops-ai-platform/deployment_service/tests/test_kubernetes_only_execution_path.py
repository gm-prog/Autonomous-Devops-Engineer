"""Phase 8.6-A final corrective, Workstream B/C.

The authoritative Kubernetes E2E drives a real deployment-service over
HTTP against a real Kind cluster. These tests pin the engine behaviour
that path depends on, so a unit run catches a broken application path
before a container is ever built:

* component selection is authoritative for BOTH legs -- a deployment
  that declares no Terraform is not sent to a Terraform sandbox, and a
  deployment that declares no Kubernetes performs no kubectl work;
* "not requested" is a distinct outcome from "requested and failed", and
  neither is ever a success;
* the approval-bound execution identity is restored in full, including
  the workload-identity policy (dropping one field made every real
  execution fail closed, and would have hidden a policy relaxation);
* the manifest hash approved and the manifest hash applied are recorded
  separately and compared, and a mismatch fails the deployment;
* rollback is a mutation and is therefore bound by the same approval,
  namespace and identity controls as apply.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from deployment_service.application.services.deployment_engine import (
    DeploymentActionError,
    DeploymentEngine,
)
from deployment_service.application.services.iac_validator import IaCValidator
from deployment_service.domain.value_objects.deployment_state import DeploymentState
from deployment_service.tests.test_deployment_engine import (
    FakeHealth,
    FakeSourceVerifier,
    FakeStore,
    FakeTerraform,
)

NAMESPACE = "devops-production-namespace"

MANIFEST = (
    "apiVersion: apps/v1\n"
    "kind: Deployment\n"
    "metadata:\n"
    "  name: checkout-service\n"
    "spec:\n"
    "  replicas: 1\n"
    "  template:\n"
    "    spec:\n"
    "      automountServiceAccountToken: false\n"
    "      containers:\n"
    "        - name: checkout-service\n"
    "          image: workload:local\n"
)

TERRAFORM = 'resource "null_resource" "x" {}\n'

EXECUTION_IDENTITY = {
    "namespace": NAMESPACE,
    "api_server": "https://kind-control-plane:6443",
    "ca_fingerprint_sha256": "b" * 64,
    "credential_profile_id": "ares-k8s-deployer-v1",
    "manifest_policy_identity": "kubernetes-manifest-v1:1111",
    "sandbox_policy_identity": "kubernetes-sandbox-v1:2222",
    "network_identity": "kubernetes-sandbox-network-v1:3333",
    "workload_identity_policy": "kubernetes-workload-identity-v1:4444",
    "execution_identity": "5555",
}


def manifest_hash(manifest: str) -> str:
    return hashlib.sha256(manifest.encode()).hexdigest()


class RecordingKubectl:
    """A kubectl double that records calls and reports real hashes."""

    def __init__(self, apply_hash: str | None = None) -> None:
        self.calls: list = []
        self._apply_hash = apply_hash

    def dry_run(self, manifest_path, namespace=None):
        self.calls.append(("dry_run", str(manifest_path)))
        manifest = Path(manifest_path).read_text()
        return {
            "status": "PASS", "stdout": "server-side dry run ok", "stderr": "",
            "cluster_access": True, "sandboxed": True,
            "manifest_sha256": manifest_hash(manifest),
            "manifest_policy_identity": "kubernetes-manifest-v1:1111",
            "validation_mode": "server-side-dry-run",
            "execution_identity": dict(EXECUTION_IDENTITY),
        }

    def apply(self, manifest_path, namespace=None, approved_identity=None):
        self.calls.append(("apply", str(manifest_path), namespace,
                           getattr(approved_identity, "digest", lambda: None)()))
        manifest = Path(manifest_path).read_text()
        applied = self._apply_hash or manifest_hash(manifest)
        return {
            "status": "PASS", "stdout": "applied", "stderr": "",
            "cluster_access": True, "sandboxed": True,
            "namespace": namespace,
            "manifest_sha256": applied,
            "sandbox_policy_identity": "kubernetes-sandbox-v1:2222",
            "execution_identity": dict(EXECUTION_IDENTITY),
        }

    def rollout_status(self, deployment_name, namespace=None):
        self.calls.append(("rollout_status", deployment_name, namespace))
        return {"status": "PASS", "stdout": "rollout ok", "cluster_access": True}

    def rollout_undo(self, deployment_name, namespace=None, approved_identity=None):
        self.calls.append(("rollout_undo", deployment_name, namespace,
                           getattr(approved_identity, "digest", lambda: None)()))
        if approved_identity is None:
            return {"status": "BLOCKED", "stderr": "no approved execution identity"}
        return {"status": "PASS", "stdout": "rolled back", "cluster_access": True}


class TerraformTripwire:
    """Any call is a finding: this deployment declares no Terraform."""

    def __getattr__(self, name):
        def boom(*_args, **_kwargs):
            raise AssertionError(
                f"the Terraform runner was invoked ({name}) for a deployment "
                f"that does not declare Terraform"
            )
        return boom


class NoKubectl:
    """Any call is a finding: this deployment declares no Kubernetes."""

    def __getattr__(self, name):
        def boom(*_args, **_kwargs):
            raise AssertionError(
                f"kubectl was invoked ({name}) for a deployment that does not "
                f"declare Kubernetes"
            )
        return boom


def payload(**over):
    body = {
        "repository_id": 1,
        "repository_name": "ares-e2e/fixture",
        "requested_by": "unit",
        "dockerfile": "FROM scratch\n",
        "k8s_yaml": MANIFEST,
        "terraform_tf": "",
        "pipeline_yaml": "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
        "components": ["dockerfile", "kubernetes", "pipeline"],
        "source_revision": {"head_sha": "b" * 40},
    }
    body.update(over)
    return body


def build_engine(terraform=None, kubectl=None, store=None):
    return DeploymentEngine(
        store=store or FakeStore(),
        validator=IaCValidator(),
        terraform=terraform if terraform is not None else TerraformTripwire(),
        kubectl=kubectl if kubectl is not None else RecordingKubectl(),
        health_checker=FakeHealth(),
        source_verifier=FakeSourceVerifier(),
    )


@pytest.fixture(autouse=True)
def _execution_enabled(monkeypatch):
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    monkeypatch.setenv("DEPLOYMENT_KUBERNETES_NAMESPACE", NAMESPACE)


# =====================================================================
# 1. Not applicable is not blocked, and not the same as passed
# =====================================================================

def test_kubernetes_only_dry_run_waits_for_approval_with_terraform_not_applicable():
    engine = build_engine()
    run = engine.create_dry_run(payload())
    assert run.state == DeploymentState.AWAITING_APPROVAL, run.logs
    assert run.terraform_plan["status"] == "NOT_APPLICABLE"
    assert run.terraform_plan["terraform_applicable"] is False
    assert run.kubernetes_dry_run["status"] == "PASS"
    # The distinct outcome is recorded, never collapsed into "PASS".
    assert run.terraform_plan["status"] != run.kubernetes_dry_run["status"]


def test_kubernetes_only_execute_reaches_deployed_without_a_terraform_run():
    kubectl = RecordingKubectl()
    engine = build_engine(kubectl=kubectl)
    run = engine.create_dry_run(payload())
    engine.approve(run.id, "unit", run.artifact_hash, run.plan_hash)
    done = engine.execute(run.id, payload(), run.artifact_hash, run.plan_hash,
                          namespace=NAMESPACE)
    assert done.state == DeploymentState.DEPLOYED, done.error
    assert done.execution["kubernetes_applied"] is True
    assert done.execution["terraform_applied"] is False
    assert done.execution["terraform_plan"]["status"] == "NOT_APPLICABLE"
    assert [call[0] for call in kubectl.calls] == ["dry_run", "apply"]


def test_kubernetes_only_execution_binds_the_approved_manifest_hash():
    engine = build_engine()
    run = engine.create_dry_run(payload())
    engine.approve(run.id, "unit", run.artifact_hash, run.plan_hash)
    done = engine.execute(run.id, payload(), run.artifact_hash, run.plan_hash,
                          namespace=NAMESPACE)
    approved = done.execution["approved_manifest_hash"]
    applied = done.execution["applied_manifest_hash"]
    assert approved and applied
    assert approved == applied
    assert done.execution["kubernetes_apply"]["manifest_sha256"] == approved
    assert done.execution["replanned_after_approval"] is False


def test_terraform_only_deployment_still_runs_terraform_and_never_kubectl():
    """Phase 8.5-A regression: the Terraform path is untouched."""
    terraform = FakeTerraform()
    engine = build_engine(terraform=terraform, kubectl=NoKubectl())
    body = payload(components=["dockerfile", "terraform", "pipeline"], k8s_yaml="",
                   terraform_tf=TERRAFORM)
    run = engine.create_dry_run(body)
    assert run.state == DeploymentState.AWAITING_APPROVAL, run.logs
    assert run.kubernetes_dry_run["status"] == "NOT_APPLICABLE"
    assert run.kubernetes_dry_run["status"] != "PASS"
    assert run.kubernetes_dry_run["cluster_access"] is False
    engine.approve(run.id, "unit", run.artifact_hash, run.plan_hash)
    done = engine.execute(run.id, body, run.artifact_hash, run.plan_hash)
    assert done.state == DeploymentState.DEPLOYED, done.error
    assert done.execution["terraform_applied"] is True
    assert terraform.plan_calls == 1, "the approved plan must not be re-planned"
    assert terraform.init_calls == 1
    # A component that was never requested is NOT APPLICABLE, and is not
    # a mutation: "applied" must stay false so nothing claims credit for
    # cluster work that never happened (and nothing tries to roll it back).
    assert done.execution["kubernetes_apply"]["status"] == "NOT_APPLICABLE"
    assert done.execution["kubernetes_applied"] is False


def test_a_requested_kubernetes_component_is_never_reported_not_applicable():
    """A requested-but-unavailable component is a failure, not a skip."""
    engine = build_engine(kubectl=RecordingKubectl())
    run = engine.create_dry_run(payload(components=["dockerfile", "kubernetes"],
                                        k8s_yaml=""))
    assert run.state in (DeploymentState.VALIDATION_FAILED,
                         DeploymentState.DRY_RUN_FAILED), run.logs
    leg = run.kubernetes_dry_run or {}
    assert leg.get("status") != "NOT_APPLICABLE", \
        "a requested component must never be reported as not applicable"
    assert leg.get("status") != "PASS"


@pytest.mark.parametrize("status,ready", [
    ("PASS", True), ("NOT_APPLICABLE", True),
    ("BLOCKED", False), ("FAIL", False), ("TIMEOUT", False), ("", False),
])
def test_kubernetes_readiness_never_treats_a_failure_as_a_skip(status, ready):
    assert DeploymentEngine._kubernetes_ready({"status": status}) is ready


@pytest.mark.parametrize("status,ready", [
    ("PASS", True), ("NOT_APPLICABLE", True),
    ("BLOCKED", False), ("FAIL", False), ("", False),
])
def test_terraform_readiness_never_treats_a_failure_as_a_skip(status, ready):
    assert DeploymentEngine._terraform_ready({"status": status}) is ready


def test_a_malformed_payload_cannot_reach_not_applicable():
    result = IaCValidator().validate("", "", TERRAFORM, "", ["terraform"])
    assert result["status"] == "PASS"
    assert result["checks"]["kubernetes"]["status"] == "NOT_APPLICABLE"
    # content for an unrequested component is a hard failure
    hostile = IaCValidator().validate("", MANIFEST, TERRAFORM, "", ["terraform"])
    assert hostile["status"] == "FAIL"


# =====================================================================
# 2. The approval snapshot is restored in full (Workstream C)
# =====================================================================

def test_rebuilt_approved_identity_keeps_every_field():
    """Regression: a dropped field made every real execution fail closed."""
    from deployment_service.application.services.kubernetes_execution_identity import (
        KubernetesExecutionIdentity,
    )
    run = SimpleNamespace(execution={
        "kubernetes_execution_identity": dict(EXECUTION_IDENTITY)})
    rebuilt = DeploymentEngine._approved_kubernetes_identity(run)
    observed = KubernetesExecutionIdentity(
        namespace=EXECUTION_IDENTITY["namespace"],
        api_server=EXECUTION_IDENTITY["api_server"],
        ca_fingerprint_sha256=EXECUTION_IDENTITY["ca_fingerprint_sha256"],
        credential_profile_id=EXECUTION_IDENTITY["credential_profile_id"],
        manifest_policy_identity=EXECUTION_IDENTITY["manifest_policy_identity"],
        sandbox_policy_identity=EXECUTION_IDENTITY["sandbox_policy_identity"],
        network_identity=EXECUTION_IDENTITY["network_identity"],
        workload_identity_policy=EXECUTION_IDENTITY["workload_identity_policy"],
    )
    assert rebuilt is not None
    assert rebuilt.workload_identity_policy == \
        EXECUTION_IDENTITY["workload_identity_policy"]
    assert rebuilt.digest() == observed.digest(), \
        "the approved identity must rebuild to exactly the observed identity"


def test_identity_missing_a_field_from_an_older_record_fails_closed():
    from deployment_service.application.services.kubernetes_execution_identity import (
        KubernetesExecutionIdentity,
        KubernetesExecutionIdentityError,
        verify_binding,
    )
    stored = {k: v for k, v in EXECUTION_IDENTITY.items()
              if k != "workload_identity_policy"}
    run = SimpleNamespace(execution={"kubernetes_execution_identity": stored})
    rebuilt = DeploymentEngine._approved_kubernetes_identity(run)
    observed = KubernetesExecutionIdentity(
        namespace=EXECUTION_IDENTITY["namespace"],
        api_server=EXECUTION_IDENTITY["api_server"],
        ca_fingerprint_sha256=EXECUTION_IDENTITY["ca_fingerprint_sha256"],
        credential_profile_id=EXECUTION_IDENTITY["credential_profile_id"],
        manifest_policy_identity=EXECUTION_IDENTITY["manifest_policy_identity"],
        sandbox_policy_identity=EXECUTION_IDENTITY["sandbox_policy_identity"],
        network_identity=EXECUTION_IDENTITY["network_identity"],
        workload_identity_policy=EXECUTION_IDENTITY["workload_identity_policy"],
    )
    assert rebuilt is not None, "the record is present but incomplete"
    with pytest.raises(KubernetesExecutionIdentityError, match="changed after approval"):
        verify_binding(rebuilt, observed)


def test_identity_absent_entirely_is_refused_rather_than_guessed():
    run = SimpleNamespace(execution={})
    assert DeploymentEngine._approved_kubernetes_identity(run) is None


# =====================================================================
# 3. The applied bytes must be the approved bytes
# =====================================================================

def test_a_manifest_that_changes_after_approval_fails_the_deployment():
    kubectl = RecordingKubectl(apply_hash="f" * 64)
    engine = build_engine(kubectl=kubectl)
    run = engine.create_dry_run(payload())
    engine.approve(run.id, "unit", run.artifact_hash, run.plan_hash)
    done = engine.execute(run.id, payload(), run.artifact_hash, run.plan_hash,
                          namespace=NAMESPACE)
    assert done.state != DeploymentState.DEPLOYED
    assert done.execution["approved_manifest_hash"] != \
        done.execution["applied_manifest_hash"]
    assert done.execution["kubernetes_apply"]["status"] == "FAIL"


# =====================================================================
# 4. Rollback is a mutation and nothing more
# =====================================================================

def _deployed_run(engine=None, kubectl=None):
    engine = engine or build_engine(kubectl=kubectl or RecordingKubectl())
    run = engine.create_dry_run(payload())
    engine.approve(run.id, "unit", run.artifact_hash, run.plan_hash)
    done = engine.execute(run.id, payload(), run.artifact_hash, run.plan_hash,
                          namespace=NAMESPACE)
    assert done.state == DeploymentState.DEPLOYED, done.error
    return engine, done


def test_rollback_requires_the_approval_hashes():
    engine, run = _deployed_run()
    with pytest.raises(DeploymentActionError, match="hashes"):
        engine.rollback(run.id, "0" * 64, run.plan_hash)
    assert engine.store.get(run.id)["state"] == "DEPLOYED"


def test_rollback_requires_an_applied_kubernetes_mutation():
    """A Terraform-only deployment has no Kubernetes mutation to undo."""
    engine = build_engine(terraform=FakeTerraform(), kubectl=NoKubectl())
    body = payload(components=["dockerfile", "terraform", "pipeline"], k8s_yaml="",
                   terraform_tf=TERRAFORM)
    run = engine.create_dry_run(body)
    engine.approve(run.id, "unit", run.artifact_hash, run.plan_hash)
    done = engine.execute(run.id, body, run.artifact_hash, run.plan_hash)
    assert done.state == DeploymentState.DEPLOYED
    with pytest.raises(DeploymentActionError, match="nothing to roll back"):
        engine.rollback(run.id, run.artifact_hash, run.plan_hash)


def test_rollback_refuses_an_unspecified_run():
    engine = build_engine()
    with pytest.raises(DeploymentActionError, match="not found"):
        engine.rollback("run_missing", "a" * 64, "b" * 64)


def test_rollback_reaches_rolled_back_through_the_approved_workloads():
    kubectl = RecordingKubectl()
    engine, run = _deployed_run(kubectl=kubectl)
    kubectl.calls.clear()
    rolled = engine.rollback(run.id, run.artifact_hash, run.plan_hash,
                             namespace=NAMESPACE)
    assert rolled.state == DeploymentState.ROLLED_BACK
    assert rolled.rollback["status"] == "PASS"
    # Only the workload recorded from the APPROVED manifest is touched.
    assert [call[0] for call in kubectl.calls] == ["rollout_undo"]
    assert kubectl.calls[0][1] == "checkout-service"
    assert kubectl.calls[0][2] == NAMESPACE
    assert kubectl.calls[0][3], "the approved identity must be re-verified"


def test_rollback_cannot_guess_a_workload_when_the_approval_records_none():
    engine, run = _deployed_run()
    stored = engine.store.get(run.id)
    stored["execution"]["kubernetes_workloads"] = []
    engine.store.data[run.id] = stored
    with pytest.raises(DeploymentActionError, match="refusing to guess"):
        engine.rollback(run.id, run.artifact_hash, run.plan_hash)


def test_rollback_without_an_approved_identity_never_reaches_the_sandbox():
    kubectl = RecordingKubectl()
    engine, run = _deployed_run(kubectl=kubectl)
    stored = engine.store.get(run.id)
    stored["execution"].pop("kubernetes_execution_identity", None)
    engine.store.data[run.id] = stored
    kubectl.calls.clear()
    with pytest.raises(DeploymentActionError, match="approved Kubernetes execution identity"):
        engine.rollback(run.id, run.artifact_hash, run.plan_hash)
    assert kubectl.calls == [], "no sandbox call without an approved target"
    assert engine.store.get(run.id)["state"] == "DEPLOYED"


def test_rollback_failure_is_reported_as_a_failure():
    kubectl = RecordingKubectl()
    engine, run = _deployed_run(kubectl=kubectl)

    def refuse(*_args, **_kwargs):
        return {"status": "FAIL", "stderr": "no rollout history"}
    kubectl.rollout_undo = refuse  # type: ignore[assignment]
    rolled = engine.rollback(run.id, run.artifact_hash, run.plan_hash)
    assert rolled.state == DeploymentState.ROLLBACK_FAILED
    assert rolled.rollback["status"] == "FAIL"


def test_rollback_is_disabled_without_execution_enabled(monkeypatch):
    engine, run = _deployed_run()
    monkeypatch.delenv("DEPLOYMENT_EXECUTION_ENABLED", raising=False)
    with pytest.raises(DeploymentActionError, match="disabled"):
        engine.rollback(run.id, run.artifact_hash, run.plan_hash)


def test_rollback_http_contract(monkeypatch):
    """The route exists, validates its body, and refuses unknown runs."""
    from fastapi.testclient import TestClient

    from deployment_service import main as deployment_main

    class _FakeStore:
        def get(self, run_id):
            return None

    monkeypatch.setattr(deployment_main.engine, "store", _FakeStore())
    client = TestClient(deployment_main.app)
    body = {"artifact_hash": "a" * 64, "plan_hash": "b" * 64, "namespace": NAMESPACE}
    unknown = client.post("/api/internal/deployments/run_missing/rollback", json=body)
    assert unknown.status_code == 409
    malformed = client.post("/api/internal/deployments/run_missing/rollback",
                            json={"artifact_hash": "short", "plan_hash": "b" * 64})
    assert malformed.status_code == 422
