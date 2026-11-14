
import hashlib
import json
import threading as _threading
from pathlib import Path
import pytest
import yaml

from deployment_service.application.services.deployment_engine import DeploymentActionError, DeploymentEngine
from deployment_service.application.services.kubernetes_operation_evidence import (
    COMPENSATION_BLOCKED,
    COMPENSATION_NOT_REQUIRED,
    EVIDENCE_KEY,
    EVIDENCE_SCHEMA_VERSION,
    HANDOFF_PENDING,
    MAX_CANONICAL_RESOURCES,
    MAX_DETAILED_ATTEMPTS,
    RESULT_RECORDED,
    STATE_HANDOFF_PENDING,
    STATE_LEGACY_UNKNOWN,
    STATE_NOT_APPLICABLE,
    STATE_NOT_ATTEMPTED,
    STATE_RESULT_RECORDED,
    KubernetesAttemptCapacityRefused,
    KubernetesEvidenceError,
    canonical_resource_key,
    classify_compensation,
    empty_evidence,
    ensure_evidence,
    get_evidence,
    record_attempt,
    record_attempt_result,
)
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
    #: Attempt-journal states (mirror of RedisPipelineStore).
    ATTEMPT_PUBLISHING = "PUBLISHING"
    ATTEMPT_PUBLISHED = "PUBLISHED"
    ATTEMPT_PRE_SEND_FAILED = "PRE_SEND_FAILED"
    ATTEMPT_AMBIGUOUS = "AMBIGUOUS"

    def __init__(self):
        self.data, self.locks = {}, set()
        # Independent audit (P1-2, third round): the durable attempt
        # journal, mirrored per-run as {dispatch_id: {attempt_id: state}}.
        self.journal = {}
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
                         expected_revision, new_run,
                         require_not_maybe_published=False):
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
        if require_not_maybe_published:
            if dispatch.get("may_have_been_published"):
                return False
            if not self.all_attempts_pre_send_failed(run_id, expected_dispatch_id):
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

    def journal_dispatch_attempt(self, run_id, dispatch_id, attempt_id, state):
        self.journal.setdefault(run_id, {}).setdefault(dispatch_id, {})[attempt_id] = state
        return True
    def read_dispatch_journal(self, run_id, dispatch_id=None):
        dispatches = self.journal.get(run_id, {})
        if dispatch_id is not None:
            dispatches = {dispatch_id: dispatches.get(dispatch_id, {})}
        entries = []
        for did, attempts in dispatches.items():
            for attempt_id, state in attempts.items():
                entries.append({"dispatch_id": did,
                                "attempt_id": attempt_id, "state": state})
        return entries
    def all_attempts_pre_send_failed(self, run_id, dispatch_id):
        entries = self.read_dispatch_journal(run_id, dispatch_id)
        return bool(entries) and all(
            e["state"] == self.ATTEMPT_PRE_SEND_FAILED for e in entries)
    def has_unresolved_attempt(self, run_id, dispatch_id):
        return any(
            e["state"] in (self.ATTEMPT_PUBLISHING, self.ATTEMPT_AMBIGUOUS)
            for e in self.read_dispatch_journal(run_id, dispatch_id))


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
        if self._lost.is_set() or FakeLeaseGuard.holders.get(self.run_id) is not self:
            self.lose()
            raise LeaseLostError("fake lease ownership is not current")
        return True

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

    def run_plan(self, iac_dir, execution=False, plan_output_path=None, cancel_event=None,
                 before_operation=None):
        if before_operation is not None:
            before_operation()
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

    def initialize(self, iac_dir, cancel_event=None, before_operation=None):
        if before_operation is not None:
            before_operation()
        self.init_calls += 1
        return {"status": "PASS", "operation": "init", "stdout": "init-ok"}

    def apply_plan(self, iac_dir, plan_output_path, expected_plan_file_hash="",
                   cancel_event=None, before_operation=None):
        # The engine re-verifies the saved plan's hash at the apply
        # boundary; mirror that so a mismatch cannot pass unnoticed.
        actual = hashlib.sha256(Path(plan_output_path).read_bytes()).hexdigest()
        if not expected_plan_file_hash or actual != expected_plan_file_hash:
            return {
                "status": "BLOCKED",
                "error_code": "PLAN_ARTIFACT_MISMATCH",
                "plan_file_hash": actual,
            }
        if before_operation is not None:
            before_operation()
        self.applied_with_hash = expected_plan_file_hash
        self.applied_from = plan_output_path
        return {"status": "PASS", "stdout": "apply-ok", "plan_file_hash": actual}


def _fake_handoff_context(manifest_path, namespace, approved_identity):
    """Deterministic handoff context mirroring the runner's trusted
    metadata: parsed from the approved manifest file exactly like the
    real runner derives it from the validated policy result. The
    approved-identity digest is a placeholder when the fake receives no
    identity (the real runner would have refused before any handoff)."""
    raw = Path(manifest_path).read_text(encoding="utf-8")
    documents = [
        doc for doc in yaml.safe_load_all(raw) if isinstance(doc, dict)
    ]
    return {
        "operation": "apply",
        "schema_version": 1,
        "manifest_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "manifest_policy_identity": "fake-manifest-policy-v1",
        "namespace": namespace,
        "resources": [
            {
                "apiVersion": str(doc.get("apiVersion", "")),
                "kind": str(doc.get("kind", "")),
                "name": str((doc.get("metadata") or {}).get("name", "")),
            }
            for doc in documents
        ],
        "approved_identity_digest": (
            approved_identity.digest() if approved_identity is not None
            else "fake-approved-identity-digest"),
    }


class FakeKubectl:
    def __init__(self):
        self.dry_run_calls = []
        self.applied_calls = []
        self.undo_calls = []

    def namespace(self): return "devops-production-namespace"
    def dry_run(self, manifest_path, namespace=None, cancel_event=None):
        self.dry_run_calls.append((manifest_path, namespace))
        return {"status": "PASS", "stdout": "dry-run-ok", "cluster_access": False}
    def apply(self, manifest_path, namespace=None, approved_identity=None,
              cancel_event=None, before_operation=None, before_handoff=None):
        if before_operation is not None:
            before_operation()
        if before_handoff is not None:
            # P2.1: the durable handoff is committed BEFORE any sandbox
            # invocation; a callback failure means no apply ever ran.
            before_handoff(_fake_handoff_context(
                manifest_path, namespace, approved_identity))
        self.applied_calls.append((manifest_path, namespace, approved_identity))
        return {"status": "PASS", "stdout": "apply-ok", "cluster_access": True}
    def rollout_status(self, deployment_name, namespace=None, timeout_seconds=300, cancel_event=None): return {"status": "PASS", "stdout": "rollout-ok", "cluster_access": True}
    def rollout_undo(self, deployment_name, namespace=None, approved_identity=None,
                     cancel_event=None, before_operation=None):
        if before_operation is not None:
            before_operation()
        self.undo_calls.append((deployment_name, namespace, approved_identity))
        return {"status": "PASS", "stdout": "undo-ok", "cluster_access": True}


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


def test_execution_refuses_alive_only_guard_without_assert_owned(monkeypatch):
    """Missing assertion capability must not fall back to alive()."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    terraform = engine.terraform

    class AliveOnlyGuard:
        def __init__(self):
            self.cancel_event = _threading.Event()
            self.cancel_requested = False

        def acquire(self):
            return True

        def alive(self):
            return True

        def request_cancel(self):
            self.cancel_requested = True
            self.cancel_event.set()

        def commit(self, payload, ttl_seconds=86400):
            return False

        def release(self):
            pass

    guard = AliveOnlyGuard()
    engine.lease_factory = lambda _run_id: guard
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    result = engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)
    assert result.state == DeploymentState.LEASE_LOST
    assert guard.alive() is True
    assert guard.cancel_requested is True
    assert terraform.init_calls == 0
    assert terraform.applied_from is None


def test_post_acquisition_store_read_failure_releases_tracking_guard(monkeypatch):
    """P2-A: the second read is inside the acquired-lease cleanup scope."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")

    class TrackingGuard(FakeLeaseGuard):
        def __init__(self, run_id, store=None):
            super().__init__(run_id, store)
            self.released = False

        def release(self):
            self.released = True
            super().release()

    guard = TrackingGuard(run.id, engine.store)
    engine.lease_factory = lambda _run_id: guard
    original_get = engine.store.get
    reads = 0

    def fail_only_post_acquisition_read(run_id):
        nonlocal reads
        reads += 1
        if reads == 2:
            raise RuntimeError("controlled post-acquisition store failure")
        return original_get(run_id)

    monkeypatch.setattr(engine.store, "get", fail_only_post_acquisition_read)
    with pytest.raises(RuntimeError, match="post-acquisition"):
        engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)

    assert reads == 2
    assert guard.released is True
    assert FakeLeaseGuard.holders.get(run.id) is None
    assert engine.terraform.init_calls == 0
    assert engine.terraform.applied_from is None
    assert engine.kubectl.applied_calls == []
    assert engine.kubectl.undo_calls == []


@pytest.mark.parametrize("post_acquisition_result", [None, "DEPLOYED"])
def test_confirmed_post_acquisition_terminal_result_discards_approval_workspace(
    monkeypatch, post_acquisition_result,
):
    """P2-A: only confirmed missing/terminal records consume saved plans."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    discarded = []
    monkeypatch.setattr(
        engine, "_discard_approval_workspace", lambda run_id: discarded.append(run_id),
    )
    original_get = engine.store.get
    reads = 0

    def changed_only_post_acquisition_read(run_id):
        nonlocal reads
        reads += 1
        if reads == 2:
            if post_acquisition_result is None:
                return None
            changed = dict(original_get(run_id))
            changed["state"] = post_acquisition_result
            return changed
        return original_get(run_id)

    monkeypatch.setattr(engine.store, "get", changed_only_post_acquisition_read)
    with pytest.raises(DeploymentActionError):
        engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)

    assert discarded == [run.id]


def test_uncertain_post_acquisition_read_preserves_approval_workspace(monkeypatch):
    """A failed second read is not evidence that destructive cleanup is safe."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    discarded = []
    monkeypatch.setattr(
        engine, "_discard_approval_workspace", lambda run_id: discarded.append(run_id),
    )
    original_get = engine.store.get
    reads = 0

    def fail_only_post_acquisition_read(run_id):
        nonlocal reads
        reads += 1
        if reads == 2:
            raise RuntimeError("controlled post-acquisition store failure")
        return original_get(run_id)

    monkeypatch.setattr(engine.store, "get", fail_only_post_acquisition_read)
    with pytest.raises(RuntimeError, match="post-acquisition"):
        engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)

    assert discarded == []


def test_workspace_setup_failure_releases_tracking_guard(monkeypatch):
    """P2-A: workspace allocation failure is setup failure, never rollback."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")

    class TrackingGuard(FakeLeaseGuard):
        def __init__(self, run_id, store=None):
            super().__init__(run_id, store)
            self.released = False

        def release(self):
            self.released = True
            super().release()

    guard = TrackingGuard(run.id, engine.store)
    engine.lease_factory = lambda _run_id: guard
    monkeypatch.setattr(
        engine, "_new_workspace",
        lambda _prefix: (_ for _ in ()).throw(OSError("controlled workspace failure")),
    )

    with pytest.raises(OSError, match="workspace failure"):
        engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)

    assert guard.released is True
    assert FakeLeaseGuard.holders.get(run.id) is None
    assert engine.terraform.init_calls == 0
    assert engine.terraform.applied_from is None
    assert engine.kubectl.applied_calls == []
    assert engine.kubectl.undo_calls == []


@pytest.mark.parametrize("post_acquisition_result", [None, "DEPLOYED"])
def test_post_acquisition_early_exit_releases_tracking_guard(
    monkeypatch, post_acquisition_result,
):
    """P2-A: missing and now-terminal fresh runs share the release path."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")

    class TrackingGuard(FakeLeaseGuard):
        def __init__(self, run_id, store=None):
            super().__init__(run_id, store)
            self.released = False

        def release(self):
            self.released = True
            super().release()

    guard = TrackingGuard(run.id, engine.store)
    engine.lease_factory = lambda _run_id: guard
    original_get = engine.store.get
    reads = 0

    def changed_only_post_acquisition_read(run_id):
        nonlocal reads
        reads += 1
        if reads == 2:
            if post_acquisition_result is None:
                return None
            changed = dict(original_get(run_id))
            changed["state"] = post_acquisition_result
            return changed
        return original_get(run_id)

    monkeypatch.setattr(engine.store, "get", changed_only_post_acquisition_read)
    with pytest.raises(DeploymentActionError):
        engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)

    assert guard.released is True
    assert FakeLeaseGuard.holders.get(run.id) is None
    assert engine.terraform.init_calls == 0
    assert engine.kubectl.applied_calls == []
    assert engine.kubectl.undo_calls == []


def test_lease_loss_before_kubernetes_apply_does_not_enter_generic_rollback(monkeypatch):
    """A failure at the Kubernetes apply gate is lease loss, not a reason
    for the generic handler to roll back a completed Terraform apply."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    terraform, kubectl = engine.terraform, engine.kubectl

    class LoseAtKubernetesApply(FakeLeaseGuard):
        def __init__(self, run_id, store=None):
            super().__init__(run_id, store)
            self.assertions = 0

        def assert_owned(self):
            self.assertions += 1
            if self.assertions == 5:
                self.lose()
            return super().assert_owned()

    guard = LoseAtKubernetesApply(run.id, engine.store)
    engine.lease_factory = lambda _run_id: guard
    result = engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)
    assert result.state == DeploymentState.LEASE_LOST
    assert terraform.applied_from is not None
    assert kubectl.applied_calls == []
    assert kubectl.undo_calls == [], "lease-loss path must bypass generic rollback"
    assert guard.cancel_event.is_set()


def test_rollback_mutations_each_receive_a_fresh_authoritative_check(monkeypatch):
    """P2.1 amendment: a failed Kubernetes apply blocks (never invokes)
    automatic Kubernetes compensation — the undo is replaced by an
    operator-escalation component — while the Terraform leg is still
    compensated under a fresh ownership proof per step."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")

    class FailedKubernetesApply(FakeKubectl):
        def apply(self, *args, **kwargs):
            result = super().apply(*args, **kwargs)
            result["status"] = "FAIL"
            return result

    kubectl = FailedKubernetesApply()
    engine.kubectl = kubectl

    class CountingGuard(FakeLeaseGuard):
        def __init__(self, run_id, store=None):
            super().__init__(run_id, store)
            self.assertions = 0

        def assert_owned(self):
            self.assertions += 1
            return super().assert_owned()

    guard = CountingGuard(run.id, engine.store)
    engine.lease_factory = lambda _run_id: guard
    result = engine.execute(
        run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash,
        previous_good_terraform_tf='terraform { required_version = ">= 1.5.0" }\\n',
    )
    # Kubernetes may have mutated: automatic undo is never invoked and
    # the run can never claim ROLLED_BACK over an uncertain component.
    assert result.state == DeploymentState.ROLLBACK_FAILED
    assert result.rollback["outcome"] == "PARTIAL"
    assert result.rollback["status"] == "FAIL"
    assert kubectl.undo_calls == []
    assert len(kubectl.applied_calls) == 1
    assert engine.terraform.plan_calls == 2, "rollback Terraform plan did not run"
    applied = Path(engine.terraform.applied_from)
    assert applied.parts[-2:] == ("rollback", "rollback.tfplan"), (
        "the rollback plan must be applied from the rollback subdirectory")
    # Two state-transition gates, init, apply, Kubernetes apply, rollback
    # entry, rollback plan, and rollback apply. The fenced handoff commit
    # is the authorization itself and adds no assertion.
    assert guard.assertions == 8


def test_lease_loss_at_rollback_entry_prevents_undo_and_terraform_rollback(monkeypatch):
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    terraform = engine.terraform

    class FailedKubernetesApply(FakeKubectl):
        def apply(self, *args, **kwargs):
            result = super().apply(*args, **kwargs)
            result["status"] = "FAIL"
            return result

    kubectl = FailedKubernetesApply()
    engine.kubectl = kubectl

    class LoseAtRollbackEntry(FakeLeaseGuard):
        def __init__(self, run_id, store=None):
            super().__init__(run_id, store)
            self.assertions = 0

        def assert_owned(self):
            self.assertions += 1
            # 1-2 transition gates; 3 init; 4 Terraform apply; 5
            # Kubernetes apply; 6 is _rollback's preflight.
            if self.assertions == 6:
                self.lose()
            return super().assert_owned()

    guard = LoseAtRollbackEntry(run.id, engine.store)
    engine.lease_factory = lambda _run_id: guard
    result = engine.execute(
        run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash,
        previous_good_terraform_tf="terraform { required_version = \">= 1.5.0\" }\\n",
    )
    assert result.state == DeploymentState.LEASE_LOST
    assert len(kubectl.applied_calls) == 1
    assert kubectl.undo_calls == [], "no rollback mutation after lease loss"
    assert terraform.plan_calls == 1, "Terraform rollback plan must not start"


def test_generic_recovery_lease_loss_at_rollback_entry_is_handled(monkeypatch):
    """P2-B: a lease loss raised by recovery is not caught by a sibling
    handler, so the generic suite must handle it explicitly."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    terraform = engine.terraform

    class GenericKubernetesFailure(FakeKubectl):
        def apply(self, *args, before_operation=None, **kwargs):
            if before_operation is not None:
                before_operation()
            raise RuntimeError("controlled Kubernetes provider failure")

    kubectl = GenericKubernetesFailure()
    engine.kubectl = kubectl

    class LoseAtGenericRollbackPreflight(FakeLeaseGuard):
        def __init__(self, run_id, store=None):
            super().__init__(run_id, store)
            self.assertions = 0

        def assert_owned(self):
            self.assertions += 1
            # Two state gates, init, Terraform apply, Kubernetes preflight,
            # then the rollback preflight from the generic exception suite.
            if self.assertions == 6:
                self.lose()
                newer = dict(engine.store.data[run.id])
                newer["state"] = DeploymentState.DEPLOYED.value
                newer["error"] = None
                newer["logs"] = ["NEWER_OWNER: authoritative result"]
                engine.store.data[run.id] = newer
            return super().assert_owned()

    guard = LoseAtGenericRollbackPreflight(run.id, engine.store)
    engine.lease_factory = lambda _run_id: guard
    result = engine.execute(
        run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash,
        previous_good_terraform_tf='terraform { required_version = ">= 1.5.0" }\\n',
    )

    assert result.state == DeploymentState.LEASE_LOST
    assert guard.cancel_event.is_set()
    assert terraform.applied_from is not None
    assert kubectl.applied_calls == []
    assert kubectl.undo_calls == []
    assert terraform.plan_calls == 1, "rollback plan must not start"
    assert result.rollback == {}
    assert not any("ROLLED_BACK" in line for line in result.logs)
    persisted = engine.store.get(run.id)
    assert persisted["state"] == DeploymentState.DEPLOYED.value
    assert persisted["logs"] == ["NEWER_OWNER: authoritative result"]
    assert persisted["error"] is None


def test_generic_recovery_commit_lease_loss_is_handled(monkeypatch):
    """P2-B: the non-rollback generic recovery commit has the same
    nested lease-loss handling requirement."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")

    class FailingInitialize(FakeTerraform):
        def initialize(self, *args, before_operation=None, **kwargs):
            if before_operation is not None:
                before_operation()
            guard.lose()
            newer = dict(engine.store.data[run.id])
            newer["state"] = DeploymentState.DEPLOYED.value
            newer["error"] = None
            newer["logs"] = ["NEWER_OWNER: authoritative result"]
            engine.store.data[run.id] = newer
            raise RuntimeError("controlled initialization failure")

    class Guard(FakeLeaseGuard):
        pass

    guard = Guard(run.id, engine.store)
    engine.terraform = FailingInitialize()
    engine.lease_factory = lambda _run_id: guard
    result = engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)

    assert result.state == DeploymentState.LEASE_LOST
    assert guard.cancel_event.is_set()
    assert engine.terraform.applied_from is None
    assert engine.kubectl.applied_calls == []
    assert engine.kubectl.undo_calls == []
    persisted = engine.store.get(run.id)
    assert persisted["state"] == DeploymentState.DEPLOYED.value
    assert persisted["logs"] == ["NEWER_OWNER: authoritative result"]
    assert persisted["error"] is None


# =====================================================================
# P2.1 — durable Kubernetes operation provenance (35-scenario matrix).
# Scenarios 1-22: evidence protocol. 23-30: rollback outcomes.
# Scenarios 31-35 (two-owner, real-Redis) live in test_execution_lease.py.
# =====================================================================


def _attempt_context(namespace="devops-production-namespace",
                     resources=None, **overrides):
    """A valid trusted handoff context for evidence-module unit tests."""
    context = {
        "operation": "apply",
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "manifest_sha256": "m" * 64,
        "manifest_policy_identity": "kubernetes-manifest-policy-v1:test",
        "approved_identity_digest": "i" * 64,
        "namespace": namespace,
        "resources": resources if resources is not None else [
            {"apiVersion": "apps/v1", "kind": "Deployment", "name": "demo"},
        ],
    }
    context.update(overrides)
    return context


# 1 ---------------------------------------------------------------------
def test_01_the_empty_evidence_record_is_versioned_and_zeroed():
    evidence = empty_evidence()
    assert evidence["schema_version"] == EVIDENCE_SCHEMA_VERSION == 1
    assert evidence["may_have_mutated"] is False
    assert evidence["attempt_count"] == 0
    assert evidence["attempts"] == [] and evidence["resources"] == []


# 2 ---------------------------------------------------------------------
def test_02_ensure_evidence_is_idempotent_and_never_overwrites():
    execution = {}
    first = ensure_evidence(execution)
    first["attempt_count"] = 3  # simulate a record that already has work
    second = ensure_evidence(execution)
    assert second is first, "an existing record is returned untouched"
    assert execution[EVIDENCE_KEY]["attempt_count"] == 3


# 3 ---------------------------------------------------------------------
def test_03_ensure_evidence_refuses_a_malformed_record():
    execution = {EVIDENCE_KEY: {"note": "not a protocol record"}}
    with pytest.raises(KubernetesEvidenceError):
        ensure_evidence(execution)


# 4 ---------------------------------------------------------------------
def test_04_a_schema_less_record_is_never_evidence():
    assert get_evidence({}) is None
    assert get_evidence({"kubernetes_apply": {"status": "PASS"}}) is None
    assert get_evidence({EVIDENCE_KEY: "garbage"}) is None


# 5 ---------------------------------------------------------------------
def test_05_a_recorded_attempt_is_pending_and_summarizes_resources():
    evidence = empty_evidence()
    attempt = record_attempt(evidence, _attempt_context())
    assert attempt["state"] == HANDOFF_PENDING
    assert attempt["operation"] == "apply"
    assert attempt["may_have_mutated"] is True
    assert attempt["result"] is None
    assert evidence["attempt_count"] == 1
    assert evidence["may_have_mutated"] is True
    summaries = evidence["resources"]
    assert len(summaries) == 1
    summary = summaries[0]
    assert summary["resource_key"] == canonical_resource_key(
        {"apiVersion": "apps/v1", "kind": "Deployment", "name": "demo"},
        "devops-production-namespace")
    assert summary["may_have_mutated"] is True
    assert summary["last_attempt_id"] == attempt["attempt_id"]


# 6 ---------------------------------------------------------------------
def test_06_resource_summaries_are_monotonic_across_retries():
    evidence = empty_evidence()
    context = _attempt_context()
    record_attempt(evidence, context)
    second = record_attempt(evidence, context)
    assert evidence["attempt_count"] == 2
    assert len(evidence["resources"]) == 1, "summaries never duplicate"
    summary = evidence["resources"][0]
    assert summary["may_have_mutated"] is True
    assert summary["last_attempt_id"] == second["attempt_id"]


# 7 ---------------------------------------------------------------------
def test_07_an_attempt_without_trusted_metadata_is_refused_without_mutation():
    evidence = empty_evidence()
    context = _attempt_context()
    del context["manifest_sha256"]
    with pytest.raises(KubernetesEvidenceError, match="manifest_sha256"):
        record_attempt(evidence, context)
    assert evidence["attempt_count"] == 0
    assert evidence["attempts"] == [] and evidence["resources"] == []
    assert evidence["may_have_mutated"] is False


# 8 ---------------------------------------------------------------------
@pytest.mark.parametrize("field,value", [
    ("operation", "delete"),
    ("schema_version", 99),
])
def test_08_unknown_operations_and_schemas_are_refused(field, value):
    evidence = empty_evidence()
    with pytest.raises(KubernetesEvidenceError):
        record_attempt(evidence, _attempt_context(**{field: value}))
    assert evidence["attempt_count"] == 0
    assert evidence["may_have_mutated"] is False


# 9 ---------------------------------------------------------------------
def test_09_the_attempt_cap_refuses_the_next_mutation_without_eviction():
    evidence = empty_evidence()
    context = _attempt_context()
    for _ in range(MAX_DETAILED_ATTEMPTS):
        record_attempt(evidence, context)
    assert evidence["attempt_count"] == MAX_DETAILED_ATTEMPTS == 16
    with pytest.raises(KubernetesAttemptCapacityRefused) as excinfo:
        record_attempt(evidence, context)
    assert excinfo.value.reason_code == "ATTEMPT_CAP"
    assert evidence["attempt_count"] == 16, "refusal must never truncate"
    assert len(evidence["attempts"]) == 16


# 10 --------------------------------------------------------------------
def test_10_the_resource_cap_refuses_an_oversized_context():
    evidence = empty_evidence()
    oversized = [
        {"apiVersion": "apps/v1", "kind": "Deployment", "name": f"demo-{n}"}
        for n in range(MAX_CANONICAL_RESOURCES + 1)
    ]
    with pytest.raises(KubernetesAttemptCapacityRefused) as excinfo:
        record_attempt(evidence, _attempt_context(resources=oversized))
    assert excinfo.value.reason_code == "RESOURCE_CAP"
    assert evidence["attempt_count"] == 0
    assert evidence["resources"] == []


# 11 --------------------------------------------------------------------
def test_11_recorded_results_are_bounded_and_finalized_on_the_newest():
    evidence = empty_evidence()
    record_attempt(evidence, _attempt_context())
    newest_attempt = record_attempt(evidence, _attempt_context())
    attempt_id = record_attempt_result(evidence, {
        "status": "FAIL", "exit_code": 7, "timed_out": True,
        "cancelled": False, "stdout": "secret-output", "stderr": "secret-err",
    }, attempt_id=newest_attempt["attempt_id"])
    newest = evidence["attempts"][-1]
    assert attempt_id == newest["attempt_id"]
    assert newest["state"] == RESULT_RECORDED
    assert newest["result"] == {
        "status": "FAIL", "exit_code": 7,
        "timed_out": True, "cancelled": False,
    }
    serialized = json.dumps(evidence)
    assert "secret-output" not in serialized
    assert "secret-err" not in serialized, "runner output never enters evidence"
    earlier = evidence["attempts"][0]
    assert earlier["state"] == HANDOFF_PENDING, "only the newest is finalized"


# 12 --------------------------------------------------------------------
def test_12_a_failed_result_never_downgrades_the_mutation_fact():
    evidence = empty_evidence()
    attempt = record_attempt(evidence, _attempt_context())
    record_attempt_result(
        evidence, {"status": "FAIL", "exit_code": 1},
        attempt_id=attempt["attempt_id"],
    )
    assert evidence["may_have_mutated"] is True
    assert evidence["attempts"][0]["may_have_mutated"] is True


# 13 --------------------------------------------------------------------
def test_13_result_recording_without_an_attempt_id_is_a_no_op():
    evidence = empty_evidence()
    assert record_attempt_result(evidence, {"status": "PASS"}) is None
    assert evidence["attempt_count"] == 0
    assert evidence["may_have_mutated"] is False

    # A result without this invocation's handoff ID must not finalize an
    # older HANDOFF_PENDING attempt left by a previous worker.
    pending = record_attempt(evidence, _attempt_context())
    assert record_attempt_result(evidence, {"status": "PASS"}) is None
    assert pending["state"] == HANDOFF_PENDING
    assert evidence["attempt_count"] == 1
    assert evidence["may_have_mutated"] is True


# 14 --------------------------------------------------------------------
def test_14_undeclared_kubernetes_is_proven_not_applicable():
    verdict = classify_compensation(
        execution={}, state_value="DEPLOYMENT_FAILED",
        kubernetes_declared=False)
    assert verdict["state"] == COMPENSATION_NOT_REQUIRED
    assert verdict["evidence_state"] == STATE_NOT_APPLICABLE
    assert verdict["may_have_mutated"] is False


# 15 --------------------------------------------------------------------
def test_15_a_zero_attempt_protocol_record_proves_not_attempted():
    execution = {EVIDENCE_KEY: empty_evidence()}
    verdict = classify_compensation(
        execution=execution, state_value="DEPLOYMENT_FAILED",
        kubernetes_declared=True)
    assert verdict["state"] == COMPENSATION_NOT_REQUIRED
    assert verdict["evidence_state"] == STATE_NOT_ATTEMPTED
    assert verdict["may_have_mutated"] is False


# 16 --------------------------------------------------------------------
def test_16_any_handoff_blocks_automatic_compensation():
    execution = {EVIDENCE_KEY: empty_evidence()}
    attempt = record_attempt(execution[EVIDENCE_KEY], _attempt_context())
    pending = classify_compensation(
        execution=execution, state_value="DEPLOYMENT_FAILED",
        kubernetes_declared=True)
    assert pending["state"] == COMPENSATION_BLOCKED
    assert pending["evidence_state"] == STATE_HANDOFF_PENDING
    assert pending["may_have_mutated"] is True
    record_attempt_result(
        execution[EVIDENCE_KEY], {"status": "PASS", "exit_code": 0},
        attempt_id=attempt["attempt_id"],
    )
    finalized = classify_compensation(
        execution=execution, state_value="DEPLOYMENT_FAILED",
        kubernetes_declared=True)
    assert finalized["state"] == COMPENSATION_BLOCKED
    assert finalized["evidence_state"] == STATE_RESULT_RECORDED
    assert finalized["may_have_mutated"] is True


# 17 --------------------------------------------------------------------
@pytest.mark.parametrize("legacy_execution,state_value", [
    ({}, "DEPLOYMENT_FAILED"),
    ({"kubernetes_apply": {"status": "PASS", "cluster_access": True}},
     "DEPLOYMENT_FAILED"),
    ({"kubernetes_apply": {"status": "BLOCKED", "cluster_access": False}},
     "DEPLOYMENT_FAILED"),
    ({}, "DEPLOYING"),
])
def test_17_legacy_records_never_exclude_a_mutation(legacy_execution, state_value):
    verdict = classify_compensation(
        execution=legacy_execution, state_value=state_value,
        kubernetes_declared=True)
    assert verdict["state"] == COMPENSATION_BLOCKED
    assert verdict["evidence_state"] == STATE_LEGACY_UNKNOWN


# 18 --------------------------------------------------------------------
def test_18_the_handoff_is_committed_before_the_sandbox_and_the_result_after(monkeypatch):
    """The durable record is stamped zero-attempt at DEPLOYING, the
    pending handoff is committed BEFORE any runner result exists, and
    the result is committed immediately after the sandbox returns."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    completed = engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)
    assert completed.state == DeploymentState.DEPLOYED

    commits = [json.loads(payload)
               for payload in engine.lease_factory.created[0].commits]
    stamping = next(
        c for c in commits if any("DEPLOYING:" in line for line in c["logs"]))
    stamped = stamping["execution"][EVIDENCE_KEY]
    assert stamped["schema_version"] == 1
    assert stamped["attempt_count"] == 0
    assert stamped["may_have_mutated"] is False

    handoff_index = next(
        i for i, c in enumerate(commits)
        if (c["execution"].get(EVIDENCE_KEY) or {}).get("attempt_count"))
    handoff = commits[handoff_index]
    assert handoff["state"] == "DEPLOYING"
    attempt = handoff["execution"][EVIDENCE_KEY]["attempts"][0]
    assert attempt["state"] == HANDOFF_PENDING
    assert attempt["manifest_sha256"]
    assert attempt["approved_identity_digest"]
    assert handoff["execution"].get("kubernetes_apply") is None, (
        "the handoff commit must precede any runner result")

    finalized = commits[handoff_index + 1]
    assert finalized["execution"][EVIDENCE_KEY]["attempts"][0]["state"] == RESULT_RECORDED
    assert finalized["execution"]["kubernetes_apply"]["status"] == "PASS"
    assert finalized["execution"][EVIDENCE_KEY]["may_have_mutated"] is True


# 19 --------------------------------------------------------------------
def test_19_a_legacy_resume_is_never_stamped_not_attempted(monkeypatch):
    """A pre-protocol in-flight record gets NO fabricated evidence; the
    resumed worker only creates the record for its own real handoff."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    stored = engine.store.get(run.id)
    stored["state"] = "DEPLOYING"
    stored["logs"] = list(stored.get("logs") or []) + [
        "DEPLOYING: legacy worker crashed mid-flight."]
    engine.store.data[run.id] = stored
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    result = engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)
    assert result.state == DeploymentState.DEPLOYED

    commits = [json.loads(payload)
               for payload in engine.lease_factory.created[0].commits]
    resuming = commits[0]
    assert any("RECOVERING" in line for line in resuming["logs"])
    assert EVIDENCE_KEY not in resuming["execution"], (
        "a legacy resume must not receive a fabricated NOT_ATTEMPTED stamp")
    handoff = next(
        c for c in commits
        if (c["execution"].get(EVIDENCE_KEY) or {}).get("attempt_count"))
    evidence = handoff["execution"][EVIDENCE_KEY]
    assert evidence["attempt_count"] == 1
    assert evidence["attempts"][0]["state"] == HANDOFF_PENDING


# 20 --------------------------------------------------------------------
def test_20_malformed_evidence_fails_closed_before_the_sandbox(monkeypatch):
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    stored = engine.store.get(run.id)
    stored["state"] = "DEPLOYING"
    stored["execution"][EVIDENCE_KEY] = {"note": "legacy junk"}
    engine.store.data[run.id] = stored
    kubectl, terraform = engine.kubectl, engine.terraform
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    result = engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)

    assert result.state == DeploymentState.ROLLBACK_FAILED
    assert kubectl.applied_calls == [], "an unusable record stops the sandbox"
    assert kubectl.undo_calls == []
    assert terraform.applied_from is not None, (
        "Terraform had already applied before the refusal")
    assert result.rollback["outcome"] == "BLOCKED"
    assert result.rollback["kubernetes_compensation"]["evidence_state"] == \
        STATE_LEGACY_UNKNOWN
    assert any(
        component["component"] == "terraform"
        and component["result"]["status"] == "BLOCKED"
        for component in result.rollback["components"])
    # the malformed record itself is never silently upgraded
    assert result.execution[EVIDENCE_KEY] == {"note": "legacy junk"}


# 21 --------------------------------------------------------------------
def test_21_a_rejected_handoff_commit_never_reaches_the_sandbox(monkeypatch):
    """The fenced commit IS the handoff authorization: a rejected commit
    stops the sandbox invocation, keeps the attempt conservatively in
    memory, and takes the lease-loss path."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)

    class Guard(FakeLeaseGuard):
        def __init__(self, run_id, store=None):
            super().__init__(run_id, store)
            self.successful_commits = 0

        def commit(self, payload, ttl_seconds=86400):
            # 1 EXECUTION_REQUESTED, 2 DEPLOYING; every later commit fails.
            if self.successful_commits >= 2:
                return False
            if super().commit(payload, ttl_seconds=ttl_seconds):
                self.successful_commits += 1
                return True
            return False

    guard = Guard(run.id, engine.store)
    engine.lease_factory = lambda _run_id: guard
    kubectl = engine.kubectl
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    result = engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)

    assert result.state == DeploymentState.LEASE_LOST
    assert kubectl.applied_calls == []
    assert kubectl.undo_calls == []
    # the attempt marker is conservatively KEPT in memory
    evidence = result.execution[EVIDENCE_KEY]
    assert evidence["attempt_count"] == 1
    assert evidence["attempts"][0]["state"] == HANDOFF_PENDING
    # durably, only the confirmed DEPLOYING stamp exists
    persisted = engine.store.get(run.id)
    assert persisted["state"] == "DEPLOYING"
    assert persisted["execution"][EVIDENCE_KEY]["attempt_count"] == 0
    assert guard.cancel_event.is_set()


# 22 --------------------------------------------------------------------
def test_22_a_rejected_result_commit_keeps_the_durable_record_pending(monkeypatch):
    """When the result commit is fenced out, the evidence snapshot is
    restored so uncertainty stays HANDOFF_PENDING durably — never a
    fabricated finalization."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)

    class Guard(FakeLeaseGuard):
        def __init__(self, run_id, store=None):
            super().__init__(run_id, store)
            self.successful_commits = 0

        def commit(self, payload, ttl_seconds=86400):
            # 1 EXECUTION_REQUESTED, 2 DEPLOYING, 3 handoff; the RESULT
            # commit and everything after is rejected.
            if self.successful_commits >= 3:
                return False
            if super().commit(payload, ttl_seconds=ttl_seconds):
                self.successful_commits += 1
                return True
            return False

    guard = Guard(run.id, engine.store)
    engine.lease_factory = lambda _run_id: guard
    kubectl = engine.kubectl
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    result = engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)

    assert result.state == DeploymentState.LEASE_LOST
    assert len(kubectl.applied_calls) == 1, "the sandbox did run"
    assert kubectl.undo_calls == []
    # the in-memory downgrade was RESTORED
    evidence = result.execution[EVIDENCE_KEY]
    assert evidence["attempts"][0]["state"] == HANDOFF_PENDING
    # durably, the handoff stands and no result was ever recorded
    persisted = engine.store.get(run.id)
    assert persisted["state"] == "DEPLOYING"
    assert persisted["execution"][EVIDENCE_KEY]["attempts"][0]["state"] == HANDOFF_PENDING
    assert persisted["execution"].get("kubernetes_apply") is None


# 23 --------------------------------------------------------------------
def test_23_a_capacity_refusal_is_not_lease_loss(monkeypatch):
    """A host-owned evidence bound refuses the next sandbox invocation:
    the worker still owns its lease (no cancellation), the refusal is
    recorded truthfully, and no attempt is evicted."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    # Seed a pre-protocol in-flight record whose evidence is already at cap.
    stored = engine.store.get(run.id)
    stored["state"] = "DEPLOYING"
    seeded = empty_evidence()
    seeded["attempt_count"] = MAX_DETAILED_ATTEMPTS
    seeded["may_have_mutated"] = True
    seeded["attempts"] = [
        {"attempt_id": f"kat-{n:016x}", "operation": "apply",
         "state": RESULT_RECORDED, "may_have_mutated": True,
         "result": {"status": "PASS", "exit_code": 0}}
        for n in range(MAX_DETAILED_ATTEMPTS)
    ]
    seeded["resources"] = [{
        "resource_key": "apps/v1/Deployment/devops-production-namespace/demo",
        "kind": "Deployment", "name": "demo", "may_have_mutated": True,
    }]
    stored["execution"][EVIDENCE_KEY] = seeded
    engine.store.data[run.id] = stored

    guard = FakeLeaseGuard(run.id, engine.store)
    engine.lease_factory = lambda _run_id: guard
    kubectl, terraform = engine.kubectl, engine.terraform
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    result = engine.execute(
        run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash,
        previous_good_terraform_tf='terraform { required_version = ">= 1.5.0" }',
    )

    assert result.state == DeploymentState.ROLLBACK_FAILED
    assert guard.cancel_event.is_set() is False, (
        "a capacity refusal is a preflight refusal, not ownership loss")
    assert kubectl.applied_calls == [], "the next sandbox invocation is refused"
    assert kubectl.undo_calls == []
    assert "refused" in (result.error or "")
    evidence = result.execution[EVIDENCE_KEY]
    assert evidence["attempt_count"] == MAX_DETAILED_ATTEMPTS, "no eviction"
    assert evidence["blocked_reason"].startswith("ATTEMPT_CAP")
    assert result.rollback["outcome"] == "PARTIAL", "Terraform was restored"
    assert result.rollback["kubernetes_compensation"]["state"] == COMPENSATION_BLOCKED
    terraform_components = [
        c for c in result.rollback["components"] if c["component"] == "terraform"]
    assert terraform_components and terraform_components[0]["result"]["status"] == "PASS"


# 24 --------------------------------------------------------------------
def test_24_blocked_kubernetes_components_demand_operator_action(monkeypatch):
    """A failed apply leaves the resource set possibly-mutated: every
    affected surface receives a BLOCKED component with the escalation
    metadata, and the undo is never invoked."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")

    class FailedKubernetesApply(FakeKubectl):
        def apply(self, *args, **kwargs):
            result = super().apply(*args, **kwargs)
            result["status"] = "FAIL"
            return result

    kubectl = FailedKubernetesApply()
    engine.kubectl = kubectl
    result = engine.execute(
        run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash,
        previous_good_terraform_tf='terraform { required_version = ">= 1.5.0" }',
    )

    assert result.state == DeploymentState.ROLLBACK_FAILED
    rollback = result.rollback
    assert rollback["outcome"] == "PARTIAL"
    assert rollback["status"] == "FAIL"
    kubernetes_components = [
        c for c in rollback["components"] if c["component"].startswith("kubernetes:")]
    assert len(kubernetes_components) == 1
    component = kubernetes_components[0]
    assert component["result"]["status"] == "BLOCKED"
    assert component["result"]["reason_code"] == "KUBERNETES_COMPENSATION_BLOCKED"
    assert component["result"]["undo_invoked"] is False
    assert component["result"]["operator_action_required"] is True
    assert component["result"]["evidence_state"] == STATE_RESULT_RECORDED
    assert component["result"]["may_have_mutated"] is True
    assert kubectl.undo_calls == []
    assert not any("ROLLED_BACK" in line for line in result.logs)


# 25 --------------------------------------------------------------------
def test_25_without_a_previous_terraform_config_the_rollback_is_blocked(monkeypatch):
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")

    class FailedKubernetesApply(FakeKubectl):
        def apply(self, *args, **kwargs):
            result = super().apply(*args, **kwargs)
            result["status"] = "FAIL"
            return result

    engine.kubectl = FailedKubernetesApply()
    result = engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)

    assert result.state == DeploymentState.ROLLBACK_FAILED
    assert result.rollback["outcome"] == "BLOCKED"
    assert result.rollback["status"] == "FAIL"
    terraform_components = [
        c for c in result.rollback["components"] if c["component"] == "terraform"]
    assert terraform_components, "the terraform leg reports its refusal"
    assert terraform_components[0]["result"]["status"] == "BLOCKED"
    assert "No previous known-good Terraform" in terraform_components[0]["result"]["error"]
    assert engine.kubectl.undo_calls == []


# 26 --------------------------------------------------------------------
@pytest.mark.parametrize("with_kubernetes", [True, False])
def test_26_a_failed_terraform_apply_is_provenance_blocked(monkeypatch, with_kubernetes):
    """A FAIL/TIMEOUT/CANCELLED Terraform apply leaves its provenance
    unknown: no compensation may run, the run stays DEPLOYMENT_FAILED,
    and ROLLBACK_PENDING is never entered."""
    engine = build_engine()
    payload = VALID_PAYLOAD if with_kubernetes else dict(
        VALID_PAYLOAD,
        k8s_yaml="",
        components=["dockerfile", "terraform", "pipeline"],
    )
    run = engine.create_dry_run(payload)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")

    class FailedTerraformApply(engine.terraform.__class__):
        def apply_plan(self, iac_dir, plan_output_path, expected_plan_file_hash="",
                       cancel_event=None, before_operation=None):
            if before_operation is not None:
                before_operation()
            return {"status": "FAIL", "stdout": "apply-failed", "plan_file_hash": ""}

    terraform, kubectl = engine.terraform, engine.kubectl
    engine.terraform = FailedTerraformApply()
    result = engine.execute(run.id, payload, run.artifact_hash, run.plan_hash)

    assert result.state == DeploymentState.DEPLOYMENT_FAILED
    assert result.rollback["outcome"] == "BLOCKED"
    assert result.rollback["status"] == "FAIL"
    assert result.rollback["reason_code"] == "TERRAFORM_PROVENANCE_UNKNOWN"
    expected_evidence_state = (
        STATE_NOT_ATTEMPTED if with_kubernetes else STATE_NOT_APPLICABLE)
    assert result.rollback["kubernetes_compensation"]["evidence_state"] == \
        expected_evidence_state
    assert not any("ROLLBACK_PENDING" in line for line in result.logs), (
        "no rollback work may be claimed for an uncompensatable provenance")
    assert kubectl.applied_calls == []
    assert kubectl.undo_calls == []
    assert terraform.plan_calls == 1, "no rollback plan is ever started"


# 27 --------------------------------------------------------------------
def test_27_provenance_uncertainty_dominates_a_blocked_kubernetes_leg(monkeypatch):
    """A resumed run whose Kubernetes leg is already possibly-mutated AND
    whose fresh Terraform apply fails: neither leg may act, and the run
    stays DEPLOYMENT_FAILED with a single BLOCKED verdict."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    stored = engine.store.get(run.id)
    stored["state"] = "DEPLOYING"
    seeded = empty_evidence()
    seeded["attempt_count"] = 1
    seeded["may_have_mutated"] = True
    seeded["attempts"] = [{
        "attempt_id": "kat-" + "0" * 16, "operation": "apply",
        "state": RESULT_RECORDED, "may_have_mutated": True,
        "result": {"status": "PASS", "exit_code": 0},
    }]
    seeded["resources"] = [{
        "resource_key": "apps/v1/Deployment/devops-production-namespace/demo",
        "kind": "Deployment", "name": "demo", "may_have_mutated": True,
    }]
    stored["execution"][EVIDENCE_KEY] = seeded
    engine.store.data[run.id] = stored
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")

    class FailedTerraformApply(engine.terraform.__class__):
        def apply_plan(self, iac_dir, plan_output_path, expected_plan_file_hash="",
                       cancel_event=None, before_operation=None):
            if before_operation is not None:
                before_operation()
            return {"status": "FAIL", "stdout": "apply-failed", "plan_file_hash": ""}

    kubectl, terraform = engine.kubectl, engine.terraform
    engine.terraform = FailedTerraformApply()
    result = engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)

    assert result.state == DeploymentState.DEPLOYMENT_FAILED
    assert result.rollback["outcome"] == "BLOCKED"
    assert result.rollback["reason_code"] == "TERRAFORM_PROVENANCE_UNKNOWN"
    assert result.rollback["kubernetes_compensation"]["state"] == COMPENSATION_BLOCKED
    assert kubectl.applied_calls == []
    assert kubectl.undo_calls == []
    assert terraform.plan_calls == 1, "no rollback plan is ever started"


# 28 --------------------------------------------------------------------
def test_28_a_health_failure_cannot_claim_rolled_back(monkeypatch):
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")

    class FailingHealth:
        def check(self, *args, **kwargs):
            return {"status": "FAIL", "checks": [{"status": "FAIL"}]}

    engine.health_checker = FailingHealth()
    kubectl = engine.kubectl
    result = engine.execute(
        run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash,
        previous_good_terraform_tf='terraform { required_version = ">= 1.5.0" }',
    )

    assert result.state == DeploymentState.ROLLBACK_FAILED
    assert result.rollback["outcome"] == "PARTIAL"
    assert result.rollback["status"] == "FAIL"
    assert kubectl.undo_calls == [], "the apply succeeded; the undo is never invoked"
    assert len(kubectl.applied_calls) == 1
    assert result.execution["kubernetes_apply"]["status"] == "PASS"


# 29 --------------------------------------------------------------------
def test_29_proven_untouched_kubernetes_and_restored_terraform_is_complete(monkeypatch):
    """When the durable evidence proves no Kubernetes handoff ever happened
    and Terraform is provably restored, ROLLED_BACK is truthful."""
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")

    class GenericKubernetesFailure(FakeKubectl):
        def apply(self, *args, before_operation=None, **kwargs):
            if before_operation is not None:
                before_operation()
            raise RuntimeError("controlled Kubernetes provider failure")

    engine.kubectl = GenericKubernetesFailure()
    result = engine.execute(
        run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash,
        previous_good_terraform_tf='terraform { required_version = ">= 1.5.0" }',
    )

    assert result.state == DeploymentState.ROLLED_BACK
    assert result.rollback["outcome"] == "COMPLETE"
    assert result.rollback["status"] == "PASS"
    assert engine.kubectl.undo_calls == []
    assert engine.terraform.plan_calls == 2
    assert result.rollback["kubernetes_compensation"]["evidence_state"] == \
        STATE_NOT_ATTEMPTED


# 30 --------------------------------------------------------------------
def test_30_a_successful_deployment_never_claims_a_rollback(monkeypatch):
    engine = build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    result = engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)
    assert result.state == DeploymentState.DEPLOYED
    assert result.rollback == {}
    assert engine.kubectl.undo_calls == []
    evidence = result.execution[EVIDENCE_KEY]
    assert evidence["attempt_count"] == 1
    assert evidence["attempts"][0]["state"] == RESULT_RECORDED
    assert evidence["attempts"][0]["result"]["status"] == "PASS"
    assert evidence["may_have_mutated"] is True
