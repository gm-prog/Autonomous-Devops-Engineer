
import hashlib
import json
import threading as _threading
from pathlib import Path
import pytest

from deployment_service.application.services.deployment_engine import DeploymentActionError, DeploymentEngine
from deployment_service.application.services.source_verification import SourceVerificationError
from deployment_service.domain.value_objects.deployment_state import DeploymentState
from deployment_service.infrastructure.persistence.execution_lease import LeaseLostError
from shared_kernel.domain.provenance import verify_provenance_record


class FakeSourceVerifier:
    """Deterministic source-verification double (no network).

    Permissive by default (accepts any canonical pair) for tests that are
    about other properties; pass ``accepted_pairs`` to model a strict
    provider that only confirms explicitly registered ``(repo, sha)``
    combinations — everything else raises like the real fail-closed
    verifier.
    """

    METHOD = "test-source-verifier"

    def __init__(self, accepted_pairs=None):
        self.accepted_pairs = accepted_pairs
        self.calls = []

    def verify(self, repository_name, head_sha):
        sha = head_sha.strip().lower() if isinstance(head_sha, str) else ""
        self.calls.append((repository_name, sha))
        is_slug = (
            isinstance(repository_name, str)
            and repository_name.count("/") == 1
            and not repository_name.startswith("/")
            and not repository_name.endswith("/")
        )
        if not is_slug or len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha):
            # mirrors the real verifier's canonical-input gate (no network)
            raise SourceVerificationError(
                "not_found",
                "requested source revision was not confirmed for a "
                "canonical owner/repository identity",
            )
        if self.accepted_pairs is not None and (repository_name, sha) not in self.accepted_pairs:
            raise SourceVerificationError(
                "not_found",
                "requested source revision was not found in this repository",
            )
        return {
            "method": self.METHOD,
            "verified_at": "2026-09-27T00:00:00+00:00",
            "verified_repository": repository_name,
            "verified_source_sha": sha,
            "verified_remote_commit": sha,
        }


class FakeStore:
    def __init__(self):
        self.data, self.locks = {}, set()
    def save(self, run):
        # Audit P1-2 follow-up: mirror the real store — every durable
        # write bumps the document revision.
        stored = self.data.get(run.id)
        run.revision = (int(stored.get("revision") or 0) if stored else run.revision) + 1
        self.data[run.id] = run.to_dict()
    def save_cas(self, run_id, expected_revision, run):
        stored = self.data.get(run_id)
        if stored is None or int(stored.get("revision") or 0) != expected_revision:
            return False
        run.revision = expected_revision + 1
        self.data[run_id] = run.to_dict()
        return True
    def cas_run_document(self, run_id, expected_state, expected_dispatch_id,
                         expected_revision, new_run):
        stored = self.data.get(run_id)
        if not stored:
            return False
        if stored.get("state") != expected_state:
            return False
        if int(stored.get("revision") or 0) != expected_revision:
            return False
        dispatch = (stored.get("execution") or {}).get("dispatch") or {}
        if dispatch.get("dispatch_id") != expected_dispatch_id:
            return False
        new_run.revision = expected_revision + 1
        self.data[run_id] = new_run.to_dict()
        return True
    def get(self, run_id): return self.data.get(run_id)
    def ping(self): return True
    def acquire_lock(self, run_id, ttl_seconds=900):
        if run_id in self.locks: return False
        self.locks.add(run_id); return True
    def release_lock(self, run_id): self.locks.discard(run_id)


class FakeLeaseGuard:
    """Deterministic stand-in for ExecutionLeaseGuard (same contract).

    One shared holder registry per run id: a second acquire for the
    same run fails, exactly like the real NX lease. ``lose()`` simulates
    ownership loss (expiry + re-acquisition elsewhere): commits are
    rejected from that moment on.
    """
    holders = {}

    def __init__(self, run_id, store=None):
        self.run_id = run_id
        self.fence = 1
        self.commits = []
        self._store = store
        self._lost = _threading.Event()
        self._cancel = _threading.Event()

    def acquire(self):
        if self.run_id in FakeLeaseGuard.holders:
            return False
        FakeLeaseGuard.holders[self.run_id] = self
        return True

    def alive(self):
        return not self._lost.is_set()

    def assert_owned(self):
        # Mirror the production guard's authoritative ownership assertion.
        if self._lost.is_set() or FakeLeaseGuard.holders.get(self.run_id) is not self:
            self.lose()
            raise LeaseLostError("fake lease no longer owned")

    def request_cancel(self):
        self._cancel.set()

    @property
    def cancel_event(self):
        return self._cancel

    def commit(self, payload, ttl_seconds=86400):
        """Fence-guarded durable commit — mirrors the real guard,
        which rewrites the run record only while the fence matches.
        The fake persists into the (fake) store so subsequent reads
        observe the committed state exactly like production."""
        if self._lost.is_set():
            return False
        self.commits.append(payload)
        if self._store is not None:
            data = json.loads(payload) if isinstance(payload, str) else dict(payload)
            if hasattr(self._store, "data"):
                self._store.data[data["id"]] = data
            else:
                # real store (e.g. RedisPipelineStore): persist through
                # the same save path the engine uses
                from deployment_service.domain.entities.deployment_run import (
                    DeploymentRun,
                )
                self._store.save(DeploymentRun.from_dict(data))
        return True

    def release(self):
        if FakeLeaseGuard.holders.get(self.run_id) is self:
            del FakeLeaseGuard.holders[self.run_id]

    def lose(self):
        """Test hook: simulate losing ownership of the lease."""
        self._lost.set()
        self._cancel.set()


class FakeLeaseFactory:
    """Engine lease seam for tests.

    Pass the engine's store so fenced commits are observable by
    subsequent reads (as in production).
    """

    def __init__(self, store=None):
        self.created = []
        self.store = store

    def __call__(self, run_id):
        guard = FakeLeaseGuard(run_id, store=self.store)
        self.created.append(guard)
        return guard

    def acquire(self, run_id):
        """Convenience for tests: occupy the lease as another owner."""
        guard = FakeLeaseGuard(run_id, store=self.store)
        self.created.append(guard)
        if not guard.acquire():
            raise AssertionError(f"lease for {run_id} already held")
        return guard


class FakeTerraform:
    """Docker-free stand-in that honours the real runner contract.

    Phase 8.5-A corrective: it writes an actual saved plan and returns
    the hash of those exact bytes, so engine tests exercise the genuine
    approve-then-apply binding instead of a hash that was handed to them.
    It also counts plan operations, which is what proves the engine does
    not re-plan after approval.
    """

    def __init__(self):
        self.plan_calls = 0
        self.init_calls = 0
        self.applied_with_hash = None
        self.applied_from = None

    def run_plan(self, iac_dir, execution=False, plan_output_path=None, cancel_event=None):
        self.plan_calls += 1
        plan_file_hash = ""
        if plan_output_path:
            body = f"tfplan::{self.plan_calls}::{iac_dir}".encode()
            Path(plan_output_path).write_bytes(body)
            plan_file_hash = hashlib.sha256(body).hexdigest()
        return {
            "status": "PASS",
            "execution": execution,
            "plan": {"stdout": "plan-ok"},
            "plan_file_hash": plan_file_hash,
            "sandbox": {"sandbox_policy_identity": "fake-sandbox-v1"},
        }

    def initialize(self, iac_dir, cancel_event=None):
        self.init_calls += 1
        return {"status": "PASS", "operation": "init", "stdout": "init-ok"}

    def apply_plan(self, iac_dir, plan_output_path, expected_plan_file_hash="", cancel_event=None):
        # The engine re-verifies the saved plan's hash at the apply
        # boundary; mirror that so a mismatch cannot pass unnoticed.
        self.applied_with_hash = expected_plan_file_hash
        self.applied_from = plan_output_path
        actual = hashlib.sha256(Path(plan_output_path).read_bytes()).hexdigest()
        if not expected_plan_file_hash or actual != expected_plan_file_hash:
            return {
                "status": "BLOCKED",
                "error_code": "PLAN_ARTIFACT_MISMATCH",
                "plan_file_hash": actual,
            }
        return {"status": "PASS", "stdout": "apply-ok", "plan_file_hash": actual}


class FakeKubectl:
    def __init__(self):
        self.dry_run_calls = []
        self.applied_calls = []

    def namespace(self): return "devops-production-namespace"
    def dry_run(self, manifest_path, namespace=None, cancel_event=None):
        self.dry_run_calls.append((manifest_path, namespace))
        return {"status": "PASS", "stdout": "dry-run-ok", "cluster_access": False}
    def apply(self, manifest_path, namespace=None, approved_identity=None, cancel_event=None):
        self.applied_calls.append((manifest_path, namespace, approved_identity))
        return {"status": "PASS", "stdout": "apply-ok", "cluster_access": True}
    def rollout_status(self, deployment_name, namespace=None, timeout_seconds=300, cancel_event=None): return {"status": "PASS", "stdout": "rollout-ok", "cluster_access": True}
    def rollout_undo(self, deployment_name, namespace=None, approved_identity=None, cancel_event=None): return {"status": "PASS", "stdout": "undo-ok", "cluster_access": True}


class FakeHealth:
    def check(self, kubectl, deployment_names, namespace, healthcheck_url="", cancel_event=None): return {"status": "PASS", "checks": [{"status": "PASS"}]}


class FakeValidator:
    def validate(self, *args): return {"status": "PASS", "checks": {}}


VALID_PAYLOAD = {
    "repository_id": 1, "repository_name": "acme/demo", "requested_by": "developer",
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


def build_engine(source_verifier=None):
    FakeLeaseGuard.holders.clear()
    store = FakeStore()
    return DeploymentEngine(store=store, validator=FakeValidator(), terraform=FakeTerraform(), kubectl=FakeKubectl(), health_checker=FakeHealth(), source_verifier=source_verifier or FakeSourceVerifier(), lease_factory=FakeLeaseFactory(store))


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


def test_repository_name_changes_plan_hash():
    """Repository identity participates in plan identity: identical
    configuration + SHA from two repositories must not share a plan hash."""
    engine = build_engine()
    first = engine.create_dry_run(VALID_PAYLOAD)
    other_repo = dict(VALID_PAYLOAD, repository_name="evil/checkout")
    second = engine.create_dry_run(other_repo)
    assert first.plan_hash != second.plan_hash


# ---------------- Stage 5: source verification + provenance ----------------


def test_source_verification_failure_persists_no_run():
    """Fail closed: if the exact revision cannot be confirmed against the
    canonical repository, no run record exists at all (no state, no plan,
    no evidence surface)."""
    engine = build_engine(source_verifier=FakeSourceVerifier(accepted_pairs=set()))
    with pytest.raises(SourceVerificationError) as excinfo:
        engine.create_dry_run(VALID_PAYLOAD)
    assert excinfo.value.reason == "not_found"
    assert engine.store.data == {}


def test_source_verification_unavailable_also_persists_no_run():
    class _Unavailable:
        def verify(self, repository_name, head_sha):
            raise SourceVerificationError(
                "unavailable", "source verification is currently unavailable"
            )

    engine = build_engine(source_verifier=_Unavailable())
    with pytest.raises(SourceVerificationError) as excinfo:
        engine.create_dry_run(VALID_PAYLOAD)
    assert excinfo.value.reason == "unavailable"
    assert engine.store.data == {}


def test_source_verification_is_recorded_on_the_run():
    verifier = FakeSourceVerifier()
    engine = build_engine(source_verifier=verifier)
    run = engine.create_dry_run(VALID_PAYLOAD)
    assert verifier.calls == [("acme/demo", "a" * 40)]
    assert run.source_verification["method"] == FakeSourceVerifier.METHOD
    assert run.to_dict()["source_verification"]["method"] == FakeSourceVerifier.METHOD
    # the attestation never contains credentials or provider URLs
    assert "token" not in str(run.to_dict()["source_verification"]).lower()


def test_provenance_is_derived_and_verifiable():
    """to_dict() carries a provenance record that validates against the
    shared contract and reflects the run's own identity."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    provenance = run.to_dict()["provenance"]
    verify_provenance_record(provenance)  # no raise
    assert provenance["repository_name"] == "acme/demo"
    assert provenance["source_sha"] == "a" * 40
    assert provenance["artifact_hash"] == run.artifact_hash
    assert provenance["plan_hash"] == run.plan_hash
    assert provenance["deployment_run_id"] == run.id
    assert provenance["state"] == "AWAITING_APPROVAL"
    assert provenance["verification_method"] == FakeSourceVerifier.METHOD


def test_state_change_changes_provenance_identity(monkeypatch):
    """DEPLOYED provenance differs from AWAITING_APPROVAL provenance for the
    same run (state participates in the hashed identity), and both verify."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    before = run.to_dict()["provenance"]
    approved_run = engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    approved = approved_run.to_dict()["provenance"]
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    deployed_run = engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)
    after = deployed_run.to_dict()["provenance"]
    verify_provenance_record(before)
    verify_provenance_record(after)
    assert before["state"] == "AWAITING_APPROVAL"
    assert approved["state"] == "APPROVED"
    assert after["state"] == "DEPLOYED"
    assert before["provenance_hash"] != approved["provenance_hash"] != after["provenance_hash"]
    assert before["provenance_hash"] != after["provenance_hash"]


def test_provenance_is_rederived_and_never_trusted_from_storage():
    """A provenance value smuggled into a stored payload is ignored: from_dict
    does not read it and the next serialization re-derives it from the
    authoritative fields."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    stored = run.to_dict()
    genuine = dict(stored["provenance"])
    forged = dict(stored["provenance"])
    forged["repository_name"] = "evil/checkout"
    forged["provenance_hash"] = "0" * 64
    stored["provenance"] = forged
    roundtrip = type(run).from_dict(stored).to_dict()
    assert roundtrip["provenance"] == genuine
    verify_provenance_record(roundtrip["provenance"])


def test_execute_rejects_artifact_mutation_after_approval(monkeypatch):
    """Execution is bound to the approved artifact: changing the Dockerfile
    after approval can never execute under the old artifact hash."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    mutated = dict(VALID_PAYLOAD, dockerfile="FROM python:3.11-slim\nUSER 0\n")
    with pytest.raises(DeploymentActionError, match="do not match"):
        engine.execute(run.id, mutated, run.artifact_hash, run.plan_hash)


def test_execute_rejects_tampered_plan_hash(monkeypatch):
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    with pytest.raises(DeploymentActionError, match="approval record"):
        engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, "0" * 64)


def test_execution_rechecks_lease_before_each_external_side_effect(monkeypatch):
    """A worker that loses its lease during one step must not start the next."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)

    factory = FakeLeaseFactory(engine.store)
    engine.lease_factory = factory

    class LoseLeaseDuringTerraformInit(FakeTerraform):
        def initialize(self, iac_dir, cancel_event=None):
            result = super().initialize(iac_dir, cancel_event=cancel_event)
            # Deterministically model expiry + another worker taking over
            # between the init operation and the subsequent Terraform apply.
            factory.created[0].lose()
            return result

    terraform = LoseLeaseDuringTerraformInit()
    engine.terraform = terraform
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")

    result = engine.execute(
        run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash
    )

    assert result.state == DeploymentState.LEASE_LOST
    assert terraform.init_calls == 1
    assert terraform.applied_from is None, "stale worker must not start Terraform apply"
    assert engine.kubectl.applied_calls == [], "stale worker must not start Kubernetes apply"

