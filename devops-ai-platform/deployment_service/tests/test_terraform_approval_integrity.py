"""Phase 8.5-A corrective — exact-plan approval and plan-artifact safety.

The original Phase 8.5-A proved that *an* apply matched *a* plan. It did
not prove the far more important property: that the plan a human
approved is the plan that actually runs.

The flow used to be::

    dry run  -> plan A -> hash(A) -> workspace deleted
    approve  -> hash(A)
    execute  -> plan B -> hash(B) -> apply B      # A was never applied

Hashing B against itself always succeeds, so the check passed while the
approval meant nothing. These tests pin the corrected contract:

    dry run  -> plan A persisted
    approve  -> binds A's exact bytes
    execute  -> recovers A, re-verifies A, applies A, never re-plans

and the companion property that every host-side touch of a saved plan
(written by untrusted Terraform, into a directory it controls) refuses
to follow a symlink out of the workspace.

Everything here is Docker-free.
"""

import hashlib
import os
from pathlib import Path

import pytest

from deployment_service.application.services.deployment_engine import (
    DeploymentActionError,
    DeploymentEngine,
)
from deployment_service.application.services.plan_artifact import (
    MAX_PLAN_BYTES,
    PLAN_FILENAME,
    PlanArtifactError,
    hash_plan_artifact,
    read_plan_bytes,
    resolve_plan_artifact,
)
from deployment_service.application.services.terraform_sandbox import (
    CREDENTIALS_DISABLED_PROFILE,
    TerraformSandboxConfigurationError,
    credential_profile_identity,
    sandbox_runtime_identity,
)
from deployment_service.domain.value_objects.deployment_state import DeploymentState
from deployment_service.tests.test_deployment_engine import (
    VALID_PAYLOAD,
    FakeHealth,
    FakeKubectl,
    FakeTerraform,
    FakeValidator,
    build_engine,
)


@pytest.fixture(autouse=True)
def _isolated_workspace_root(tmp_path, monkeypatch):
    """Keep every approval workspace inside the test's own tmp tree."""
    root = tmp_path / "wsroot"
    root.mkdir()
    monkeypatch.setenv("DEPLOYMENT_WORKSPACE_ROOT", str(root))
    monkeypatch.delenv("DEPLOYMENT_CREDENTIAL_ENV_KEYS", raising=False)
    return root


def _approved(engine=None):
    """Drive a run to APPROVED and hand back (engine, run)."""
    engine = engine or build_engine()
    run = engine.create_dry_run(VALID_PAYLOAD)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    return engine, run


def _workspace_of(run):
    return run.terraform_plan["approval_workspace"]


# =====================================================================
# Gate C — the approved plan is the applied plan
# =====================================================================


class TestExactApprovalBinding:
    def test_dry_run_persists_a_real_saved_plan(self):
        _, run = _approved()
        workspace = Path(_workspace_of(run))
        assert workspace.is_dir(), "approval workspace must survive the dry run"
        saved = workspace / PLAN_FILENAME
        assert saved.is_file(), "the approved plan must exist on disk"
        assert run.terraform_plan["plan_file_hash"] == hashlib.sha256(
            saved.read_bytes()
        ).hexdigest()

    def test_approved_hash_equals_applied_hash(self, monkeypatch):
        engine, run = _approved()
        monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
        approved_hash = run.terraform_plan["plan_file_hash"]
        done = engine.execute(
            run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash
        )
        assert done.state == DeploymentState.DEPLOYED
        assert done.execution["approved_plan_hash"] == approved_hash
        assert done.execution["applied_plan_hash"] == approved_hash
        assert engine.terraform.applied_with_hash == approved_hash

    def test_execution_does_not_replan_after_approval(self, monkeypatch):
        """The regression that made approval meaningless (§25)."""
        engine, run = _approved()
        plans_at_approval = engine.terraform.plan_calls
        assert plans_at_approval == 1
        monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
        engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)
        assert engine.terraform.plan_calls == plans_at_approval, (
            "execute() generated a NEW plan after approval; the approved "
            "plan is then not the plan being applied"
        )
        # init is allowed (it cannot create or change a plan) and is
        # deliberately counted separately so it can never be mistaken
        # for a planning operation.
        assert engine.terraform.init_calls == 1

    def test_apply_reads_the_approved_workspace_not_a_fresh_one(
        self, monkeypatch
    ):
        engine, run = _approved()
        monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
        engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)
        assert engine.terraform.applied_from == str(
            Path(_workspace_of(run), PLAN_FILENAME)
        )

    def test_plan_identity_binds_the_exact_plan_bytes(self):
        """Two runs with identical inputs but different plan bytes differ."""
        first = DeploymentEngine._plan_hash(
            "artifact",
            {"status": "PASS", "plan": {"stdout": "same"}, "plan_file_hash": "a" * 64},
            {"status": "PASS", "stdout": "k8s"},
            {"head_sha": "c" * 40},
            "repo",
        )
        second = DeploymentEngine._plan_hash(
            "artifact",
            {"status": "PASS", "plan": {"stdout": "same"}, "plan_file_hash": "b" * 64},
            {"status": "PASS", "stdout": "k8s"},
            {"head_sha": "c" * 40},
            "repo",
        )
        assert first != second


# =====================================================================
# Gate C/E — tampering between approval and execution fails closed
# =====================================================================


class TestPostApprovalTampering:
    @staticmethod
    def _execute(engine, run):
        return engine.execute(
            run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash
        )

    def _assert_blocked_without_applying(self, done, engine):
        assert done.state == DeploymentState.DEPLOYMENT_FAILED
        assert not done.execution.get("terraform_applied")
        assert engine.terraform.applied_with_hash is None, (
            "apply must never be reached once the approved plan is in doubt"
        )

    def test_modified_plan_is_rejected(self, monkeypatch):
        engine, run = _approved()
        monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
        saved = Path(_workspace_of(run), PLAN_FILENAME)
        saved.write_bytes(saved.read_bytes() + b"-tampered")
        self._assert_blocked_without_applying(self._execute(engine, run), engine)

    def test_replaced_plan_is_rejected(self, monkeypatch):
        engine, run = _approved()
        monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
        Path(_workspace_of(run), PLAN_FILENAME).write_bytes(b"a different plan")
        self._assert_blocked_without_applying(self._execute(engine, run), engine)

    def test_plan_swapped_for_a_symlink_is_rejected(self, monkeypatch, tmp_path):
        engine, run = _approved()
        monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
        outside = tmp_path / "attacker.tfplan"
        outside.write_bytes(b"attacker controlled")
        saved = Path(_workspace_of(run), PLAN_FILENAME)
        saved.unlink()
        saved.symlink_to(outside)
        self._assert_blocked_without_applying(self._execute(engine, run), engine)

    def test_deleted_approval_workspace_is_rejected(self, monkeypatch):
        import shutil

        engine, run = _approved()
        monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
        shutil.rmtree(_workspace_of(run))
        done = self._execute(engine, run)
        self._assert_blocked_without_applying(done, engine)
        assert "re-run the dry run" in done.execution["terraform_plan"]["error"]

    def test_credential_profile_change_after_approval_is_rejected(
        self, monkeypatch
    ):
        engine, run = _approved()
        assert run.terraform_plan["credential_profile_id"] == (
            CREDENTIALS_DISABLED_PROFILE
        )
        monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
        # Credentials switched on after a human approved a credential-free
        # plan: the apply could now reach real infrastructure.
        monkeypatch.setenv(
            "DEPLOYMENT_CREDENTIAL_ENV_KEYS", "AWS_ACCESS_KEY_ID"
        )
        done = self._execute(engine, run)
        self._assert_blocked_without_applying(done, engine)
        assert "credential profile changed" in (
            done.execution["terraform_plan"]["error"].lower()
        )

    def test_artifact_mutation_after_approval_is_still_rejected(
        self, monkeypatch
    ):
        engine, run = _approved()
        monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
        mutated = dict(VALID_PAYLOAD, terraform_tf='resource "x" {}')
        with pytest.raises(DeploymentActionError):
            engine.execute(run.id, mutated, run.artifact_hash, run.plan_hash)


# =====================================================================
# Gate E — the plan-artifact guard
# =====================================================================


class TestPlanArtifactGuard:
    def test_accepts_a_plain_regular_plan(self, tmp_path):
        (tmp_path / PLAN_FILENAME).write_bytes(b"ok")
        proven = resolve_plan_artifact(str(tmp_path), str(tmp_path / PLAN_FILENAME))
        assert proven == (tmp_path.resolve() / PLAN_FILENAME)
        assert hash_plan_artifact(str(tmp_path), PLAN_FILENAME) == (
            hashlib.sha256(b"ok").hexdigest()
        )

    def test_rejects_a_symlinked_plan(self, tmp_path):
        secret = tmp_path / "secret"
        secret.write_bytes(b"host secret")
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / PLAN_FILENAME).symlink_to(secret)
        with pytest.raises(PlanArtifactError) as err:
            read_plan_bytes(str(ws), PLAN_FILENAME)
        assert err.value.code == "PLAN_ARTIFACT_SYMLINK"

    def test_rejects_a_symlink_that_resolves_back_inside(self, tmp_path):
        """Even a 'harmless' link is refused: no link is ever followed."""
        ws = tmp_path / "ws"
        ws.mkdir()
        real = ws / "real.bin"
        real.write_bytes(b"inside")
        (ws / PLAN_FILENAME).symlink_to(real)
        with pytest.raises(PlanArtifactError) as err:
            resolve_plan_artifact(str(ws), PLAN_FILENAME)
        assert err.value.code == "PLAN_ARTIFACT_SYMLINK"

    def test_rejects_a_plan_reached_through_a_symlinked_workspace_root(
        self, tmp_path
    ):
        real = tmp_path / "real"
        real.mkdir()
        (real / PLAN_FILENAME).write_bytes(b"plan")
        link = tmp_path / "link"
        link.symlink_to(real, target_is_directory=True)
        # Resolving the root is allowed, but the artifact must still be
        # proven to sit directly beneath the RESOLVED root.
        proven = resolve_plan_artifact(str(link), PLAN_FILENAME)
        assert proven.parent == real.resolve()

    @pytest.mark.parametrize("style", ["relative-traversal", "absolute", "nested"])
    def test_rejects_paths_outside_the_workspace(self, tmp_path, style):
        """Confinement must be the reason for the refusal.

        Each candidate is a REAL, EXISTING file with the exact expected
        plan filename, so the rejection cannot be satisfied by the
        "missing file" or "wrong name" checks instead. Without this, the
        test passes even when every confinement check is deleted (caught
        by the all-confinement-defences-removed mutation probe).
        """
        workspace = tmp_path / "ws"
        workspace.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / PLAN_FILENAME).write_bytes(b"attacker plan")
        nested = workspace / "nested"
        nested.mkdir()
        (nested / PLAN_FILENAME).write_bytes(b"nested plan")

        candidate = {
            "relative-traversal": f"../outside/{PLAN_FILENAME}",
            "absolute": str(outside / PLAN_FILENAME),
            "nested": f"nested/{PLAN_FILENAME}",
        }[style]

        with pytest.raises(PlanArtifactError) as err:
            resolve_plan_artifact(str(workspace), candidate)
        assert err.value.code == "PLAN_ARTIFACT_OUTSIDE_WORKSPACE", (
            f"{style} was refused as {err.value.code}, not as a confinement "
            "violation; the confinement checks may not be doing the work"
        )

    @pytest.mark.parametrize("name", ["", "   "])
    def test_rejects_an_empty_plan_path(self, tmp_path, name):
        with pytest.raises(PlanArtifactError) as err:
            resolve_plan_artifact(str(tmp_path), name)
        assert err.value.code == "PLAN_ARTIFACT_MISSING"

    def test_rejects_a_wrongly_named_artifact(self, tmp_path):
        (tmp_path / "other.tfplan").write_bytes(b"x")
        with pytest.raises(PlanArtifactError) as err:
            resolve_plan_artifact(str(tmp_path), "other.tfplan")
        assert err.value.code == "PLAN_ARTIFACT_UNEXPECTED_NAME"

    def test_rejects_a_directory_named_like_a_plan(self, tmp_path):
        (tmp_path / PLAN_FILENAME).mkdir()
        with pytest.raises(PlanArtifactError) as err:
            resolve_plan_artifact(str(tmp_path), PLAN_FILENAME)
        assert err.value.code == "PLAN_ARTIFACT_NOT_REGULAR"

    def test_rejects_a_fifo_named_like_a_plan(self, tmp_path):
        """A FIFO would block the control plane forever on read."""
        os.mkfifo(tmp_path / PLAN_FILENAME)
        with pytest.raises(PlanArtifactError) as err:
            resolve_plan_artifact(str(tmp_path), PLAN_FILENAME)
        assert err.value.code == "PLAN_ARTIFACT_NOT_REGULAR"

    @pytest.mark.parametrize("bad", ["relative/path", ""])
    def test_rejects_an_unusable_workspace(self, bad):
        with pytest.raises(PlanArtifactError) as err:
            resolve_plan_artifact(bad, PLAN_FILENAME)
        assert err.value.code == "PLAN_ARTIFACT_WORKSPACE_INVALID"

    def test_rejects_a_missing_workspace(self, tmp_path):
        with pytest.raises(PlanArtifactError):
            resolve_plan_artifact(str(tmp_path / "gone"), PLAN_FILENAME)

    def test_oversized_plan_is_refused(self, tmp_path, monkeypatch):
        target = tmp_path / PLAN_FILENAME
        target.write_bytes(b"x" * 64)
        monkeypatch.setattr(
            "deployment_service.application.services.plan_artifact."
            "MAX_PLAN_BYTES",
            8,
        )
        with pytest.raises(PlanArtifactError) as err:
            resolve_plan_artifact(str(tmp_path), PLAN_FILENAME)
        assert err.value.code == "PLAN_ARTIFACT_TOO_LARGE"

    def test_plan_contents_never_appear_in_the_error_text(self, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / PLAN_FILENAME).symlink_to(tmp_path / "nowhere")
        with pytest.raises(PlanArtifactError) as err:
            read_plan_bytes(str(ws), PLAN_FILENAME)
        assert "nowhere" not in str(err.value)


# =====================================================================
# Gate B/C — workspace ownership and runtime identity
# =====================================================================


class TestWorkspaceAndRuntimeIdentity:
    def test_approval_workspace_is_created_under_the_configured_root(
        self, _isolated_workspace_root
    ):
        _, run = _approved()
        assert Path(_workspace_of(run)).parent == _isolated_workspace_root

    def test_approval_workspace_is_not_world_accessible(self):
        _, run = _approved()
        mode = os.stat(_workspace_of(run)).st_mode & 0o777
        assert mode & 0o007 == 0, "a saved plan must not be world-accessible"
        assert mode & 0o700 == 0o700

    def test_approval_workspace_is_writable_by_the_sandbox_identity(self):
        """Gate B: non-root Terraform must be able to write the workspace."""
        _, run = _approved()
        uid, gid = sandbox_runtime_identity()
        info = os.stat(_workspace_of(run))
        if os.getuid() != 0:
            # Control plane is unprivileged: the sandbox reuses its
            # identity, so ownership already matches.
            assert (info.st_uid, uid) == (os.getuid(), os.getuid())
        else:  # pragma: no cover - only on a root control plane
            assert info.st_uid == uid and info.st_gid == gid

    def test_sandbox_identity_is_never_root(self):
        uid, gid = sandbox_runtime_identity()
        assert uid != 0 and gid != 0

    @pytest.mark.parametrize("value", ["0", "-1", "nonsense"])
    def test_root_or_malformed_sandbox_identity_is_refused(
        self, monkeypatch, value
    ):
        monkeypatch.setenv("DEPLOYMENT_TERRAFORM_SANDBOX_UID", value)
        with pytest.raises(TerraformSandboxConfigurationError):
            sandbox_runtime_identity()

    def test_failed_dry_run_leaves_no_saved_plan_behind(
        self, _isolated_workspace_root
    ):
        class FailingTerraform(FakeTerraform):
            def run_plan(self, iac_dir, execution=False, plan_output_path=None):
                super().run_plan(iac_dir, execution, plan_output_path)
                return {"status": "FAIL", "plan": {"stdout": "boom"}}

        engine = build_engine()
        engine.terraform = FailingTerraform()
        run = engine.create_dry_run(VALID_PAYLOAD)
        assert run.state == DeploymentState.DRY_RUN_FAILED
        assert list(_isolated_workspace_root.iterdir()) == []

    def test_terminal_run_discards_the_saved_plan(self, monkeypatch):
        engine, run = _approved()
        monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
        workspace = _workspace_of(run)
        engine.execute(run.id, VALID_PAYLOAD, run.artifact_hash, run.plan_hash)
        assert not Path(workspace).exists(), (
            "a sensitive saved plan must not outlive its deployment"
        )


# =====================================================================
# Workstream F — credential profile identity
# =====================================================================


class TestCredentialProfileIdentity:
    def test_v1_default_is_credentials_disabled(self):
        assert credential_profile_identity() == CREDENTIALS_DISABLED_PROFILE

    def test_profile_changes_when_credential_names_change(self, monkeypatch):
        monkeypatch.setenv("DEPLOYMENT_CREDENTIAL_ENV_KEYS", "AWS_ACCESS_KEY_ID")
        one = credential_profile_identity()
        monkeypatch.setenv(
            "DEPLOYMENT_CREDENTIAL_ENV_KEYS",
            "AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY",
        )
        assert credential_profile_identity() != one

    def test_profile_is_order_insensitive_and_deterministic(self, monkeypatch):
        monkeypatch.setenv("DEPLOYMENT_CREDENTIAL_ENV_KEYS", "B_KEY,A_KEY")
        first = credential_profile_identity()
        monkeypatch.setenv("DEPLOYMENT_CREDENTIAL_ENV_KEYS", "A_KEY,B_KEY")
        assert credential_profile_identity() == first

    def test_profile_never_contains_a_credential_value(self, monkeypatch):
        monkeypatch.setenv("DEPLOYMENT_CREDENTIAL_ENV_KEYS", "AWS_ACCESS_KEY_ID")
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA-SUPER-SECRET-VALUE")
        identity = credential_profile_identity()
        assert "AKIA" not in identity
        assert "SUPER-SECRET" not in identity
        # and not a hash of the value either
        assert hashlib.sha256(b"AKIA-SUPER-SECRET-VALUE").hexdigest() not in identity
