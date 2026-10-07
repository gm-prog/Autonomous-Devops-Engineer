"""Phase 8.5-A — Terraform execution trust boundary.

These tests treat Terraform configuration as UNTRUSTED EXECUTABLE INPUT
and assert the boundary that contains it. Negative tests dominate on
purpose: the security properties are the ones that must not regress.

Nothing here requires Docker, GitHub or secrets.
"""

import ast
import os
import pathlib
import subprocess

import pytest

from deployment_service.application.services.iac_validator import IaCValidator
from deployment_service.application.services.plan_artifact import (
    PLAN_FILENAME,
    PlanArtifactError,
    hash_plan_artifact,
    resolve_plan_artifact,
)
from deployment_service.application.services.terraform_runner import (
    TerraformRunnerService,
)
from deployment_service.application.services.terraform_sandbox import (
    OPERATION_TIMEOUTS,
    SANDBOX_ENV_ALLOWLIST,
    SANDBOX_MAX_OUTPUT_BYTES,
    SANDBOX_WORKSPACE_MOUNT,
    TERRAFORM_SANDBOX_POLICY_VERSION,
    TerraformOperation,
    TerraformSandboxConfigurationError,
    TerraformSandboxOutcome,
    TerraformSandboxPolicyViolation,
    TerraformSandboxSpec,
    TerraformSandboxStep,
    TerraformSandboxUnavailableError,
    build_run_plan,
    build_terraform_argv,
    new_container_name,
    resolve_credential_env_keys,
    sandbox_policy_identity,
    validate_runtime_spec,
    validate_workspace,
)
from deployment_service.infrastructure.sandbox.container_terraform_sandbox import (  # noqa: E501
    ContainerTerraformSandbox,
)

GOOD_IMAGE = "ghcr.io/arena/terraform@sha256:" + "a" * 64
GOOD_USER = "1000:1000"


def _spec(**overrides) -> TerraformSandboxSpec:
    base = {
        "image": GOOD_IMAGE,
        "user": GOOD_USER,
        "network_mode": "none",
        "terraform_version": "1.9.8",
    }
    base.update(overrides)
    return TerraformSandboxSpec(**base)


def _step(operation=TerraformOperation.VALIDATE, **overrides):
    base = {
        "operation": operation,
        "argv": build_terraform_argv(operation),
        "timeout_seconds": 10.0,
        "max_output_bytes": 1024,
    }
    base.update(overrides)
    return TerraformSandboxStep(**base)


def _plan(workspace, **overrides):
    kwargs = {
        "spec": _spec(),
        "step": _step(),
        "workspace_path": workspace,
        "container_name": "tf-sbx-test-0123456789ab",
    }
    kwargs.update(overrides)
    return build_run_plan(**kwargs)


class FakeTerraformSandbox:
    """Deterministic sandbox double: records what it was asked to run."""

    def __init__(self, outcome=None, raises=None):
        self.calls = []
        self._outcome = outcome
        self._raises = raises

    def execute(self, step, workspace_path):
        self.calls.append(
            {
                "operation": step.operation,
                "argv": step.argv,
                "workspace": str(workspace_path),
                "credential_env_keys": step.credential_env_keys,
            }
        )
        if self._raises is not None:
            raise self._raises
        if self._outcome is not None:
            return self._outcome
        return TerraformSandboxOutcome(
            operation=step.operation, exit_code=0, stdout="ok", stderr="",
            timed_out=False, output_truncated=False,
        )

    def describe(self):
        return {
            "sandbox_policy_identity": sandbox_policy_identity(_spec()),
            "sandbox_image": GOOD_IMAGE,
            "execution_mode": "fake",
        }


# =====================================================================
# 24.1 — sandbox configuration is rejected when it would weaken isolation
# =====================================================================


class TestSandboxConfigurationRejection:
    @pytest.mark.parametrize(
        "image",
        [
            "",
            "   ",
            "hashicorp/terraform:latest",
            "hashicorp/terraform:1.9.8",          # tag, not a digest
            "hashicorp/terraform@sha256:short",
            "hashicorp/terraform@sha256:" + "a" * 63,
            "hashicorp/terraform@md5:" + "a" * 64,
            "@sha256:" + "a" * 64,
        ],
    )
    def test_image_must_be_digest_pinned(self, image):
        with pytest.raises(TerraformSandboxConfigurationError):
            validate_runtime_spec(_spec(image=image))

    @pytest.mark.parametrize("user", ["0", "0:0", "root", "", "   ", "abc"])
    def test_root_or_malformed_user_is_rejected(self, user):
        with pytest.raises(TerraformSandboxPolicyViolation):
            validate_runtime_spec(_spec(user=user))

    @pytest.mark.parametrize(
        "mode", ["bridge", "host", "container:other", "default", ""]
    )
    def test_only_network_none_is_permitted(self, mode):
        with pytest.raises(TerraformSandboxPolicyViolation):
            validate_runtime_spec(_spec(network_mode=mode))

    def test_valid_spec_is_accepted(self):
        validate_runtime_spec(_spec())  # must not raise

    def test_relative_workspace_is_rejected(self):
        with pytest.raises(TerraformSandboxPolicyViolation):
            validate_workspace(pathlib.Path("relative/dir"))

    def test_missing_workspace_is_rejected(self, tmp_path):
        with pytest.raises(TerraformSandboxPolicyViolation):
            validate_workspace(tmp_path / "does-not-exist")

    def test_traversal_in_workspace_is_rejected(self, tmp_path):
        with pytest.raises(TerraformSandboxPolicyViolation):
            validate_workspace(tmp_path / ".." / tmp_path.name)

    def test_workspace_outside_configured_root_is_rejected(
        self, tmp_path, monkeypatch
    ):
        root = tmp_path / "root"
        outside = tmp_path / "outside"
        root.mkdir()
        outside.mkdir()
        monkeypatch.setenv("DEPLOYMENT_WORKSPACE_ROOT", str(root))
        with pytest.raises(TerraformSandboxPolicyViolation):
            validate_workspace(outside)
        # the in-root one is fine
        inside = root / "ws"
        inside.mkdir()
        assert validate_workspace(inside) == inside.resolve()

    def test_symlink_escape_from_root_is_rejected(self, tmp_path, monkeypatch):
        root = tmp_path / "root"
        outside = tmp_path / "outside"
        root.mkdir()
        outside.mkdir()
        link = root / "escape"
        link.symlink_to(outside, target_is_directory=True)
        monkeypatch.setenv("DEPLOYMENT_WORKSPACE_ROOT", str(root))
        with pytest.raises(TerraformSandboxPolicyViolation):
            validate_workspace(link)

    @pytest.mark.parametrize("timeout", [0, -1, -0.5, 10_000])
    def test_invalid_timeout_is_rejected(self, tmp_path, timeout):
        with pytest.raises(TerraformSandboxPolicyViolation):
            _plan(tmp_path, step=_step(timeout_seconds=timeout))

    @pytest.mark.parametrize(
        "limit", [0, -1, SANDBOX_MAX_OUTPUT_BYTES + 1, 1 << 30]
    )
    def test_oversized_output_limit_is_rejected(self, tmp_path, limit):
        with pytest.raises(TerraformSandboxPolicyViolation):
            _plan(tmp_path, step=_step(max_output_bytes=limit))

    @pytest.mark.parametrize(
        "name", ["", "-leading", "has space", "a" * 200, "bad/name", "x;y"]
    )
    def test_invalid_container_name_is_rejected(self, tmp_path, name):
        with pytest.raises(TerraformSandboxPolicyViolation):
            _plan(tmp_path, container_name=name)

    def test_per_operation_timeout_budget_is_enforced(self, tmp_path):
        # FORMAT's budget is far below APPLY's: borrowing APPLY's budget
        # for a FORMAT step must be refused.
        too_long = OPERATION_TIMEOUTS[TerraformOperation.APPLY]
        with pytest.raises(TerraformSandboxPolicyViolation):
            _plan(
                tmp_path,
                step=_step(
                    TerraformOperation.FORMAT, timeout_seconds=too_long
                ),
            )


# =====================================================================
# 24.2 — the generated runtime configuration enforces the baseline
# =====================================================================


class TestRuntimePolicy:
    REQUIRED = [
        ("--rm",),
        ("--network", "none"),
        ("--user", GOOD_USER),
        ("--read-only",),
        ("--cap-drop", "ALL"),
        ("--security-opt", "no-new-privileges:true"),
        ("--pull", "never"),
    ]

    def test_required_isolation_flags_are_present(self, tmp_path):
        argv = _plan(tmp_path).cli_argv
        for flag in self.REQUIRED:
            if len(flag) == 1:
                assert flag[0] in argv, flag
            else:
                index = argv.index(flag[0])
                assert argv[index + 1] == flag[1], flag

    def test_resource_limits_are_present(self, tmp_path):
        argv = _plan(tmp_path).cli_argv
        for flag in ("--pids-limit", "--memory", "--cpus"):
            assert flag in argv
            assert argv[argv.index(flag) + 1].strip() != ""

    def test_image_is_digest_pinned_in_argv(self, tmp_path):
        assert GOOD_IMAGE in _plan(tmp_path).cli_argv

    def test_exactly_one_mount_and_it_is_the_workspace(self, tmp_path):
        plan = _plan(tmp_path)
        assert len(plan.mounts) == 1
        assert plan.mounts[0] == (
            f"{tmp_path.resolve()}:{SANDBOX_WORKSPACE_MOUNT}:rw"
        )
        assert plan.cli_argv.count("-v") == 1
        assert plan.working_directory == SANDBOX_WORKSPACE_MOUNT

    @pytest.mark.parametrize(
        "forbidden",
        [
            "--privileged",
            "/var/run/docker.sock",
            "docker.sock",
            "--pid=host",
            "--network=host",
            "--ipc=host",
            "--userns=host",
            "--cap-add",
            "seccomp=unconfined",
            "--device",
            "/:/host",
            "-v/:/",
        ],
    )
    def test_dangerous_runtime_options_never_appear(self, tmp_path, forbidden):
        joined = " ".join(_plan(tmp_path).cli_argv)
        assert forbidden not in joined

    def test_no_host_sensitive_path_is_mounted(self, tmp_path):
        joined = " ".join(_plan(tmp_path).cli_argv)
        for path in ("/root", "/home/", "/.ssh", "/.aws", "/etc/shadow",
                     "/proc", "/sys", "/var/run"):
            assert f"{path}:" not in joined

    def test_policy_identity_is_deterministic_and_version_prefixed(self):
        first = sandbox_policy_identity(_spec())
        second = sandbox_policy_identity(_spec())
        assert first == second
        assert first.startswith(f"{TERRAFORM_SANDBOX_POLICY_VERSION}:")

    @pytest.mark.parametrize(
        "change",
        [
            {"image": "ghcr.io/arena/terraform@sha256:" + "b" * 64},
            {"user": "1001:1001"},
            {"terraform_version": "1.5.0"},
        ],
    )
    def test_policy_identity_changes_when_posture_changes(self, change):
        assert sandbox_policy_identity(_spec()) != sandbox_policy_identity(
            _spec(**change)
        )

    def test_container_names_are_never_reused(self):
        names = {new_container_name("PLAN") for _ in range(50)}
        assert len(names) == 50


# =====================================================================
# 24.3 — the sandbox cannot be turned into an arbitrary-command runner
# =====================================================================


class TestNoArbitraryCommandExecution:
    @pytest.mark.parametrize(
        "argv",
        [
            ("sh", "-c", "curl evil"),
            ("bash", "-c", "id"),
            ("python", "-c", "import os"),
            ("/bin/sh",),
            ("terraform; id",),
            ("env",),
        ],
    )
    def test_non_terraform_executables_are_refused(self, tmp_path, argv):
        step = TerraformSandboxStep(
            operation=TerraformOperation.VALIDATE,
            argv=argv,
            timeout_seconds=10.0,
            max_output_bytes=1024,
        )
        with pytest.raises(TerraformSandboxPolicyViolation):
            _plan(tmp_path, step=step)

    def test_extra_smuggled_flags_are_refused(self, tmp_path):
        """argv must equal the policy template for the operation."""
        smuggled = build_terraform_argv(TerraformOperation.VALIDATE) + (
            "-chdir=/etc",
        )
        step = TerraformSandboxStep(
            operation=TerraformOperation.VALIDATE,
            argv=smuggled,
            timeout_seconds=10.0,
            max_output_bytes=1024,
        )
        with pytest.raises(TerraformSandboxPolicyViolation):
            _plan(tmp_path, step=step)

    def test_operation_must_come_from_the_closed_enum(self):
        for bogus in ("APPLY", "destroy", None, 7, object()):
            with pytest.raises(TerraformSandboxPolicyViolation):
                build_terraform_argv(bogus)

    @pytest.mark.parametrize(
        "plan_file",
        [
            "../escape.tfplan",
            "/etc/passwd",
            "sub/dir.tfplan",
            "-out",
            "--help",
            "plan file.tfplan",
            "plan;id",
            "",
        ],
    )
    def test_plan_file_names_are_strictly_validated(self, plan_file):
        with pytest.raises(TerraformSandboxPolicyViolation):
            build_terraform_argv(
                TerraformOperation.PLAN, execution=True, plan_file=plan_file
            )

    def test_every_operation_argv_starts_with_terraform(self):
        for operation in TerraformOperation:
            argv = build_terraform_argv(
                operation,
                execution=True,
                plan_file="terraform.tfplan"
                if operation in (TerraformOperation.PLAN,
                                 TerraformOperation.APPLY)
                else None,
            )
            assert argv[0] == "terraform"

    def test_apply_requires_a_saved_plan(self):
        with pytest.raises(TerraformSandboxPolicyViolation):
            build_terraform_argv(TerraformOperation.APPLY, execution=True)

    def test_apply_argv_is_exactly_the_saved_plan(self):
        argv = build_terraform_argv(
            TerraformOperation.APPLY, execution=True,
            plan_file="terraform.tfplan",
        )
        assert argv == (
            "terraform", "apply", "-input=false", "-no-color",
            "terraform.tfplan",
        )
        assert "-auto-approve" not in argv


# =====================================================================
# 24.4 / 37 — no host Terraform fallback, proven statically and at runtime
# =====================================================================


class TestNoHostTerraformFallback:
    RUNNER = pathlib.Path(
        "deployment_service/application/services/terraform_runner.py"
    )

    @classmethod
    def _runner_source(cls) -> str:
        here = pathlib.Path(__file__).resolve()
        for parent in here.parents:
            candidate = parent / cls.RUNNER
            if candidate.exists():
                return candidate.read_text()
        raise AssertionError("terraform_runner.py not found")

    def test_runner_module_never_imports_a_process_api(self):
        """AST contract: future refactors cannot reintroduce host exec."""
        tree = ast.parse(self._runner_source())
        forbidden = {"subprocess", "os", "pty", "popen2", "commands"}
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        assert not (imported & forbidden), sorted(imported & forbidden)

    def test_runner_module_calls_no_process_primitive(self):
        tree = ast.parse(self._runner_source())
        banned = {"run", "Popen", "call", "check_output", "system",
                  "execv", "execve", "spawnv", "fork"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = getattr(func, "attr", None) or getattr(func, "id", None)
                if name in banned:
                    owner = getattr(getattr(func, "value", None), "id", "")
                    assert owner not in {"subprocess", "os"}, (
                        f"host process call {owner}.{name}"
                    )

    def test_runner_runs_nothing_on_the_host(self, tmp_path, monkeypatch):
        """Instrument the real process APIs; the count must stay zero."""
        calls = []
        for module, attr in (
            (subprocess, "run"), (subprocess, "Popen"),
            (subprocess, "call"), (subprocess, "check_output"),
            (os, "system"),
        ):
            monkeypatch.setattr(
                module, attr,
                lambda *a, _n=attr, **k: calls.append((_n, a)) or 0,
            )
        sandbox = FakeTerraformSandbox()
        runner = TerraformRunnerService(sandbox=sandbox)
        result = runner.run_plan(str(tmp_path), execution=False)

        assert result["status"] == "PASS"
        assert calls == [], f"host process execution occurred: {calls}"
        assert [c["operation"] for c in sandbox.calls] == [
            TerraformOperation.FORMAT, TerraformOperation.INIT,
            TerraformOperation.VALIDATE, TerraformOperation.PLAN,
        ]

    def test_dry_run_is_sandboxed_exactly_like_execution(self, tmp_path):
        """Dry-run must not be the open side door: init/plan load plugins."""
        for execution in (False, True):
            sandbox = FakeTerraformSandbox()
            TerraformRunnerService(sandbox=sandbox).run_plan(
                str(tmp_path), execution=execution
            )
            assert len(sandbox.calls) == 4


# =====================================================================
# 24.5 / 21 / 22 — unavailable runtime fails closed, never "PASS"
# =====================================================================


class TestFailClosed:
    @pytest.mark.parametrize(
        "error",
        [
            TerraformSandboxUnavailableError("docker CLI not found"),
            TerraformSandboxUnavailableError("daemon unreachable"),
            TerraformSandboxConfigurationError("image not configured"),
            TerraformSandboxPolicyViolation("network mode forbidden"),
        ],
    )
    def test_sandbox_errors_block_and_never_pass(self, tmp_path, error):
        runner = TerraformRunnerService(
            sandbox=FakeTerraformSandbox(raises=error)
        )
        result = runner.run_plan(str(tmp_path), execution=True)
        assert result["status"] == "BLOCKED"
        assert result["status"] != "PASS"
        assert result["plan_file_hash"] == ""
        assert result["steps"][0]["executed"] is False
        assert result["steps"][0]["error_code"] == error.code

    def test_apply_is_blocked_when_the_sandbox_is_unavailable(self, tmp_path):
        plan_path = tmp_path / "terraform.tfplan"
        plan_path.write_bytes(b"plan-bytes")
        runner = TerraformRunnerService(
            sandbox=FakeTerraformSandbox(
                raises=TerraformSandboxUnavailableError("daemon down")
            )
        )
        result = runner.apply_plan(str(tmp_path), str(plan_path))
        assert result["status"] == "BLOCKED"
        assert result["executed"] is False

    def test_missing_docker_cli_raises_unavailable_not_fallback(
        self, tmp_path
    ):
        def explode(argv, timeout, env):
            raise FileNotFoundError("docker")

        sandbox = ContainerTerraformSandbox(
            image=GOOD_IMAGE, user=GOOD_USER, cli_runner=explode
        )
        with pytest.raises(TerraformSandboxUnavailableError):
            sandbox.execute(_step(), tmp_path)

    def test_daemon_error_is_classified_unavailable(self, tmp_path):
        class R:
            exit_code = 125
            stdout = b""
            stderr = b"Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
            timed_out = False

        sandbox = ContainerTerraformSandbox(
            image=GOOD_IMAGE, user=GOOD_USER,
            cli_runner=lambda *a, **k: R(),
        )
        with pytest.raises(TerraformSandboxUnavailableError):
            sandbox.execute(_step(), tmp_path)

    def test_missing_image_is_configuration_error_not_a_pull(self, tmp_path):
        class R:
            exit_code = 125
            stdout = b""
            stderr = b"docker: Error response from daemon: No such image: x"
            timed_out = False

        sandbox = ContainerTerraformSandbox(
            image=GOOD_IMAGE, user=GOOD_USER,
            cli_runner=lambda *a, **k: R(),
        )
        with pytest.raises(TerraformSandboxConfigurationError):
            sandbox.execute(_step(), tmp_path)

    def test_malformed_result_is_refused(self, tmp_path):
        class R:
            exit_code = None
            stdout = b""
            stderr = b""
            timed_out = False

        from deployment_service.application.services.terraform_sandbox import (
            TerraformSandboxResultError,
        )

        sandbox = ContainerTerraformSandbox(
            image=GOOD_IMAGE, user=GOOD_USER,
            cli_runner=lambda *a, **k: R(),
        )
        with pytest.raises(TerraformSandboxResultError):
            sandbox.execute(_step(), tmp_path)

    def test_a_failing_plan_never_yields_a_synthetic_success(self, tmp_path):
        outcome = TerraformSandboxOutcome(
            operation=TerraformOperation.FORMAT, exit_code=1,
            stdout="", stderr="boom", timed_out=False,
            output_truncated=False,
        )
        runner = TerraformRunnerService(
            sandbox=FakeTerraformSandbox(outcome=outcome)
        )
        result = runner.run_plan(str(tmp_path))
        assert result["status"] == "FAIL"
        assert result["plan_file_hash"] == ""

    def test_plan_success_without_a_saved_plan_is_blocked(self, tmp_path):
        """A PASS with no plan artifact must not look like a usable plan."""
        runner = TerraformRunnerService(sandbox=FakeTerraformSandbox())
        result = runner.run_plan(
            str(tmp_path), execution=True,
            plan_output_path=str(tmp_path / "terraform.tfplan"),
        )
        assert result["status"] == "BLOCKED"
        assert result["plan_file_hash"] == ""


# =====================================================================
# 24.6 / 24.7 — timeout and output bounds
# =====================================================================


class TestTimeoutAndOutputBounds:
    def test_timeout_is_reported_and_is_not_success(self, tmp_path):
        outcome = TerraformSandboxOutcome(
            operation=TerraformOperation.PLAN, exit_code=-9,
            stdout="partial", stderr="", timed_out=True,
            output_truncated=False,
        )
        runner = TerraformRunnerService(
            sandbox=FakeTerraformSandbox(outcome=outcome)
        )
        result = runner.run_plan(str(tmp_path))
        assert result["status"] == "TIMEOUT"
        assert result["status"] != "PASS"
        assert result["steps"][-1]["error_code"] == "SANDBOX_TIMEOUT"

    def test_timeout_kills_the_process_group_and_cleans_up(self, tmp_path):
        killed, removed = [], []

        def runner(argv, timeout, env):
            if argv[:3] == ("docker", "rm", "-f"):
                removed.append(argv[3])

                class Ok:
                    exit_code, stdout, stderr, timed_out = 0, b"", b"", False

                return Ok()
            killed.append(argv)

            class TimedOut:
                exit_code, stdout, stderr, timed_out = None, b"", b"", True

            return TimedOut()

        sandbox = ContainerTerraformSandbox(
            image=GOOD_IMAGE, user=GOOD_USER, cli_runner=runner
        )
        outcome = sandbox.execute(_step(), tmp_path)
        assert outcome.timed_out is True
        assert removed, "container cleanup was not attempted"

    def test_output_is_bounded_and_truncation_is_explicit(self, tmp_path):
        secret = "SUPER-SECRET-VALUE"
        blob = (b"x" * 5000) + secret.encode()

        class R:
            exit_code = 0
            stdout = blob
            stderr = b""
            timed_out = False

        sandbox = ContainerTerraformSandbox(
            image=GOOD_IMAGE, user=GOOD_USER, cli_runner=lambda *a, **k: R(),
        )
        outcome = sandbox.execute(_step(max_output_bytes=1024), tmp_path)
        assert len(outcome.stdout) <= 1024
        assert outcome.output_truncated is True
        # the tail (where the secret sat) was dropped, not surfaced
        assert secret not in outcome.stdout


# =====================================================================
# 19 / 20 / 42 — environment and credential policy
# =====================================================================


class TestEnvironmentAndCredentialPolicy:
    def test_host_environment_is_never_inherited(self, tmp_path, monkeypatch):
        monkeypatch.setenv("JWT_SECRET", "super-secret-jwt")
        monkeypatch.setenv("DATABASE_URL", "postgres://u:p@h/db")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
        plan = _plan(tmp_path)
        joined = " ".join(plan.cli_argv)
        for secret in ("super-secret-jwt", "postgres://u:p@h/db",
                       "aws-secret", "ghp_secret"):
            assert secret not in joined
        assert set(plan.env) == set(SANDBOX_ENV_ALLOWLIST)

    def test_env_values_are_constants_not_host_values(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("PATH", "/attacker/bin")
        monkeypatch.setenv("HOME", "/root")
        plan = _plan(tmp_path)
        assert plan.env["PATH"] == SANDBOX_ENV_ALLOWLIST["PATH"]
        assert plan.env["HOME"] == SANDBOX_ENV_ALLOWLIST["HOME"]
        assert "/attacker/bin" not in " ".join(plan.cli_argv)

    def test_credential_values_never_enter_argv(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
        plan = _plan(
            tmp_path,
            step=_step(credential_env_keys=("AWS_ACCESS_KEY_ID",)),
        )
        joined = " ".join(plan.cli_argv)
        assert "AKIAEXAMPLE" not in joined
        # the NAME is forwarded so docker reads the value from its own env
        assert "-e" in plan.cli_argv
        assert "AWS_ACCESS_KEY_ID" in plan.cli_argv

    @pytest.mark.parametrize(
        "key", ["JWT_SECRET", "DATABASE_URL", "REDIS_URL", "DOCKER_HOST",
                "PATH", "HOME", "GITHUB_TOKEN"]
    )
    def test_dangerous_names_can_never_be_forwarded(self, tmp_path, key):
        with pytest.raises(TerraformSandboxPolicyViolation):
            _plan(tmp_path, step=_step(credential_env_keys=(key,)))

    def test_credential_allowlist_filters_junk(self, monkeypatch):
        monkeypatch.setenv(
            "DEPLOYMENT_CREDENTIAL_ENV_KEYS",
            "AWS_ACCESS_KEY_ID, JWT_SECRET ,bad-name,, PATH ,TF_TOKEN",
        )
        keys = resolve_credential_env_keys()
        assert "AWS_ACCESS_KEY_ID" in keys
        assert "TF_TOKEN" in keys
        for rejected in ("JWT_SECRET", "bad-name", "PATH", ""):
            assert rejected not in keys

    def test_dry_run_forwards_no_credentials_at_all(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv(
            "DEPLOYMENT_CREDENTIAL_ENV_KEYS", "AWS_ACCESS_KEY_ID"
        )
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
        sandbox = FakeTerraformSandbox()
        TerraformRunnerService(sandbox=sandbox).run_plan(
            str(tmp_path), execution=False
        )
        for call in sandbox.calls:
            assert call["credential_env_keys"] == ()

    def test_execution_forwards_only_configured_names(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv(
            "DEPLOYMENT_CREDENTIAL_ENV_KEYS", "AWS_ACCESS_KEY_ID"
        )
        sandbox = FakeTerraformSandbox()
        TerraformRunnerService(sandbox=sandbox).run_plan(
            str(tmp_path), execution=True
        )
        assert sandbox.calls[0]["credential_env_keys"] == (
            "AWS_ACCESS_KEY_ID",
        )

    def test_missing_credential_on_host_fails_closed(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
        sandbox = ContainerTerraformSandbox(
            image=GOOD_IMAGE, user=GOOD_USER,
            cli_runner=lambda *a, **k: None,
        )
        with pytest.raises(TerraformSandboxConfigurationError):
            sandbox.execute(
                _step(credential_env_keys=("AWS_ACCESS_KEY_ID",)), tmp_path
            )


# =====================================================================
# 15 / 16 — saved plan integrity and the apply boundary
# =====================================================================


class TestPlanArtifactBinding:
    def _runner(self):
        return TerraformRunnerService(sandbox=FakeTerraformSandbox())

    def test_plan_hash_is_recorded_for_the_saved_plan(self, tmp_path):
        import hashlib

        plan_path = tmp_path / "terraform.tfplan"

        class WritingSandbox(FakeTerraformSandbox):
            def execute(self, step, workspace_path):
                if step.operation is TerraformOperation.PLAN:
                    plan_path.write_bytes(b"saved-plan-bytes")
                return super().execute(step, workspace_path)

        runner = TerraformRunnerService(sandbox=WritingSandbox())
        result = runner.run_plan(
            str(tmp_path), execution=True, plan_output_path=str(plan_path)
        )
        assert result["status"] == "PASS"
        assert result["plan_file_hash"] == hashlib.sha256(
            b"saved-plan-bytes"
        ).hexdigest()

    def test_apply_refuses_a_modified_plan(self, tmp_path):
        import hashlib

        plan_path = tmp_path / "terraform.tfplan"
        plan_path.write_bytes(b"approved-plan")
        approved = hashlib.sha256(b"approved-plan").hexdigest()
        plan_path.write_bytes(b"tampered-plan")  # mutated after approval

        result = self._runner().apply_plan(
            str(tmp_path), str(plan_path), expected_plan_file_hash=approved
        )
        assert result["status"] == "BLOCKED"
        assert result["error_code"] == "PLAN_ARTIFACT_MISMATCH"
        assert result["executed"] is False

    def test_apply_accepts_the_exact_approved_plan(self, tmp_path):
        import hashlib

        plan_path = tmp_path / "terraform.tfplan"
        plan_path.write_bytes(b"approved-plan")
        approved = hashlib.sha256(b"approved-plan").hexdigest()
        sandbox = FakeTerraformSandbox()
        result = TerraformRunnerService(sandbox=sandbox).apply_plan(
            str(tmp_path), str(plan_path), expected_plan_file_hash=approved
        )
        assert result["status"] == "PASS"
        assert sandbox.calls[-1]["argv"][-1] == "terraform.tfplan"

    def test_apply_refuses_a_missing_plan(self, tmp_path):
        result = self._runner().apply_plan(
            str(tmp_path),
            str(tmp_path / PLAN_FILENAME),
            expected_plan_file_hash="b" * 64,
        )
        assert result["status"] == "BLOCKED"
        assert result["error_code"] == "PLAN_ARTIFACT_MISSING"

    def test_apply_refuses_when_no_approved_hash_is_supplied(self, tmp_path):
        """Corrective: there is no unverified apply mode.

        Applying with nothing to compare against would make the approval
        binding unprovable, so it is refused even when the plan exists.
        """
        (tmp_path / PLAN_FILENAME).write_bytes(b"plan-bytes")
        result = self._runner().apply_plan(
            str(tmp_path), str(tmp_path / PLAN_FILENAME)
        )
        assert result["status"] == "BLOCKED"
        assert result["error_code"] == "PLAN_ARTIFACT_UNVERIFIED"
        assert result["executed"] is False

    @pytest.mark.parametrize(
        "evil", ["/etc/passwd", "../outside.tfplan", "nested/dir.tfplan"]
    )
    def test_apply_refuses_a_plan_outside_the_workspace(self, tmp_path, evil):
        result = self._runner().apply_plan(str(tmp_path), evil)
        assert result["status"] == "BLOCKED"
        assert result["executed"] is False

    def test_plan_path_outside_workspace_blocks_the_plan(self, tmp_path):
        result = self._runner().run_plan(
            str(tmp_path), execution=True,
            plan_output_path="/tmp/elsewhere.tfplan",
        )
        assert result["status"] == "BLOCKED"


# =====================================================================
# 25 — hostile Terraform content
# =====================================================================


class TestHostileTerraformContent:
    """Static rejection stays; the sandbox is the real boundary."""

    HOSTILE = {
        "local-exec": 'resource "null_resource" "x" {\n'
                      '  provisioner "local-exec" { command = "id" }\n}\n',
        "remote-exec": 'resource "null_resource" "x" {\n'
                       '  provisioner "remote-exec" { inline = ["id"] }\n}\n',
        "external": 'data "external" "x" {\n  program = ["sh", "-c", "id"]\n}\n',
    }

    @pytest.mark.parametrize("name", sorted(HOSTILE))
    def test_existing_static_rejections_are_preserved(self, name):
        result = IaCValidator()._terraform(self.HOSTILE[name])
        assert result["status"] == "FAIL"
        assert result["errors"]

    def test_hostile_content_cannot_change_the_runtime_policy(self, tmp_path):
        """The decisive property: content never reaches runtime config."""
        (tmp_path / "main.tf").write_text(
            self.HOSTILE["local-exec"]
            + '\nprovider "docker" { host = "unix:///var/run/docker.sock" }\n'
        )
        argv = _plan(tmp_path).cli_argv
        joined = " ".join(argv)
        assert "docker.sock" not in joined
        assert "--privileged" not in joined
        assert argv[argv.index("--network") + 1] == "none"

    def test_network_dependent_provider_fails_closed(self, tmp_path):
        """No automatic internet access to satisfy a provider fetch."""
        outcome = TerraformSandboxOutcome(
            operation=TerraformOperation.INIT, exit_code=1, stdout="",
            stderr="Could not retrieve the list of available versions for "
                   "provider hashicorp/aws: could not connect",
            timed_out=False, output_truncated=False,
        )
        runner = TerraformRunnerService(
            sandbox=FakeTerraformSandbox(outcome=outcome)
        )
        result = runner.run_plan(str(tmp_path), execution=True)
        assert result["status"] == "FAIL"
        assert result["status"] != "PASS"
        # and the policy still says network none
        assert _plan(tmp_path).cli_argv[
            _plan(tmp_path).cli_argv.index("--network") + 1
        ] == "none"

    def test_zero_provider_fixture_remains_executable_in_policy(
        self, tmp_path
    ):
        """The committed zero-cloud fixture must stay sandbox-compatible."""
        here = pathlib.Path(__file__).resolve()
        fixture = None
        for parent in here.parents:
            candidate = parent / "e2e" / "terraform" / "main.tf"
            if candidate.exists():
                fixture = candidate
                break
        assert fixture is not None, "E2E terraform fixture not found"
        content = fixture.read_text()
        assert "terraform_data" in content
        assert IaCValidator()._terraform(content)["status"] == "PASS"
        # no provider block means init needs no registry access
        assert 'provider "' not in content


# =====================================================================
# 36 — the PRODUCTION path is really mediated (not a test-only sandbox)
# =====================================================================


class TestProductionWiringIsReal:
    def test_default_runner_resolves_to_the_container_sandbox(self):
        from deployment_service.application.services import terraform_runner

        assert (
            type(terraform_runner._default_sandbox()).__name__
            == "ContainerTerraformSandbox"
        )

    def test_deployment_engine_uses_the_sandboxed_runner_by_default(self):
        from deployment_service.application.services.deployment_engine import (
            DeploymentEngine,
        )

        engine = DeploymentEngine()
        assert isinstance(engine.terraform, TerraformRunnerService)
        # and that runner owns no host execution path
        assert not hasattr(engine.terraform, "_run")

    def test_unconfigured_sandbox_blocks_instead_of_running_on_the_host(
        self, tmp_path, monkeypatch
    ):
        """No image configured must mean "no Terraform", not "host Terraform"."""
        monkeypatch.delenv("DEPLOYMENT_TERRAFORM_SANDBOX_IMAGE", raising=False)
        calls = []
        monkeypatch.setattr(
            subprocess, "run", lambda *a, **k: calls.append(a) or 0
        )
        result = TerraformRunnerService().run_plan(
            str(tmp_path), execution=True
        )
        assert result["status"] == "BLOCKED"
        assert result["steps"][0]["error_code"] == "SANDBOX_CONFIGURATION_ERROR"
        assert calls == []

    def test_sandbox_evidence_is_safe_and_deterministic(self, monkeypatch):
        monkeypatch.setenv("DEPLOYMENT_TERRAFORM_SANDBOX_IMAGE", GOOD_IMAGE)
        monkeypatch.setenv("DEPLOYMENT_TERRAFORM_SANDBOX_VERSION", "1.9.8")
        monkeypatch.setenv("JWT_SECRET", "super-secret-jwt")
        evidence = TerraformRunnerService().describe_sandbox()
        assert evidence["sandbox_image"] == GOOD_IMAGE
        assert evidence["terraform_version"] == "1.9.8"
        assert evidence["sandbox_network_mode"] == "none"
        assert evidence["sandbox_policy_identity"].startswith(
            TERRAFORM_SANDBOX_POLICY_VERSION
        )
        assert "super-secret-jwt" not in str(evidence)
        assert TerraformRunnerService().describe_sandbox() == evidence


# =====================================================================
# 32 — the trust boundary participates in plan identity
# =====================================================================


class TestPlanIdentityBindsTheTrustBoundary:
    @staticmethod
    def _hash(sandbox_identity):
        from deployment_service.application.services.deployment_engine import (
            DeploymentEngine,
        )

        return DeploymentEngine._plan_hash(
            "artifact-hash",
            {
                "status": "PASS",
                "plan": {"stdout": "plan-output"},
                "sandbox": {"sandbox_policy_identity": sandbox_identity},
            },
            {"status": "PASS", "stdout": "k8s"},
            {"head_sha": "a" * 40},
            "gm-prog/Autonomous-Devops-Engineer",
        )

    def test_same_artifact_under_a_different_boundary_differs(self):
        """A weakened sandbox must not inherit an existing approval."""
        strong = self._hash("terraform-sandbox-v1:" + "a" * 32)
        weakened = self._hash("terraform-sandbox-v2:" + "b" * 32)
        assert strong != weakened

    def test_identical_inputs_are_deterministic(self):
        identity = sandbox_policy_identity(_spec())
        assert self._hash(identity) == self._hash(identity)
