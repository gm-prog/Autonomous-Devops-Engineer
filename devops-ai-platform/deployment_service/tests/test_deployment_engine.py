
import pytest

from deployment_service.application.services.deployment_engine import DeploymentActionError, DeploymentEngine
from deployment_service.application.services.source_verification import SourceVerificationError
from deployment_service.domain.value_objects.deployment_state import DeploymentState
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
    def save(self, run): self.data[run.id] = run.to_dict()
    def get(self, run_id): return self.data.get(run_id)
    def acquire_lock(self, run_id, ttl_seconds=900):
        if run_id in self.locks: return False
        self.locks.add(run_id); return True
    def release_lock(self, run_id): self.locks.discard(run_id)


class FakeTerraform:
    def run_plan(self, iac_dir, execution=False, plan_output_path=None):
        return {"status": "PASS", "execution": execution, "plan": {"stdout": "plan-ok"}, "plan_file_hash": "a" * 64 if execution else ""}
    def apply_plan(self, iac_dir, plan_output_path, expected_plan_file_hash=""):
        # Phase 8.5-A: the engine now re-verifies the saved plan's hash at
        # the apply boundary; record it so tests can assert the binding.
        self.applied_with_hash = expected_plan_file_hash
        return {"status": "PASS", "stdout": "apply-ok"}


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
    return DeploymentEngine(store=FakeStore(), validator=FakeValidator(), terraform=FakeTerraform(), kubectl=FakeKubectl(), health_checker=FakeHealth(), source_verifier=source_verifier or FakeSourceVerifier())


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
