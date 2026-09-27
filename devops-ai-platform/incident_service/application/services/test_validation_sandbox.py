"""Phase 6.2.2 — sandbox security boundary regression tests.

Configuration-level proofs for the isolation properties (no kernel
claims): no host fallback, secret isolation, filesystem isolation,
network isolation, privilege hardening, resource bounds, cleanup,
lease-guard ordering, and malicious repository content handling.

The single integration test at the end runs REAL containers only when a
docker runtime is available; it is honestly skipped otherwise (no fake
kernel-isolation claims).
"""

import inspect
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from incident_service.application.services.local_validation_executor import (
    LocalProcessValidationExecutor,
)
from incident_service.application.services.remediation_orchestration_service import (
    RemediationOrchestrationService,
    RemediationStageGuardError,
)
from incident_service.application.services.remediation_validation_runner import (
    RemediationValidationRunner,
    ValidationSandboxConfigurationError,
    ValidationSandboxResultError,
    ValidationSandboxUnavailableError,
    ValidationStep,
    ValidationWorkspaceMutationError,
)
from incident_service.application.services.remediation_workspace_service import (
    RemediationWorkspace,
)
from incident_service.application.services.validation_sandbox import (
    SANDBOX_ENV_ALLOWLIST,
    SANDBOX_MAX_OUTPUT_BYTES,
    SANDBOX_MAX_RUNTIME_SECONDS,
    SANDBOX_MEMORY_BYTES,
    SANDBOX_PIDS_LIMIT,
    SANDBOX_WALL_GRACE_SECONDS,
    SandboxPolicyViolation,
    SandboxRuntimeSpec,
    SandboxStepSpec,
    build_run_plan,
    validate_runtime_spec,
)
from incident_service.infrastructure.sandbox.container_validation_sandbox import (
    ContainerValidationSandbox,
)

DIGEST_IMAGE = "registry.example/incident-validation@sha256:" + "a" * 64
WORKSPACE = Path("/tmp/remediation-sandbox-test-workspace")
SOURCE_SHA = "a" * 40

_SECRET_ENV = {
    "GITHUB_OAUTH_TOKEN": "ghp_host_token_value_123",
    "JWT_SECRET": "host_jwt_secret_value_456",
    "DATABASE_URL": "postgres://user:pw@db.internal/prod",
    "REDIS_URL": "redis://:pw@cache.internal:6379/0",
    "AWS_SECRET_ACCESS_KEY": "aws_host_key_789",
    "AGENT_API_SECRET": "agent_host_secret_000",
}


def _step(
    timeout: float = 5.0,
    max_output: int = 4096,
    argv: tuple = ("python", "-c", "print('ok')"),
    working_directory: str = ".",
) -> SandboxStepSpec:
    return SandboxStepSpec(
        name="test-step",
        argv=argv,
        working_directory=working_directory,
        timeout_seconds=timeout,
        max_output_bytes=max_output,
    )


def _runtime(**overrides) -> SandboxRuntimeSpec:
    defaults = {
        "image": DIGEST_IMAGE,
        "user": "1000:1000",
        "network_mode": "none",
        "seccomp_profile": None,
    }
    defaults.update(overrides)
    return SandboxRuntimeSpec(**defaults)


def _plan(spec=None, step=None, name: str = "remed-sbx-test-1"):
    return build_run_plan(
        spec=spec or _runtime(),
        step=step or _step(),
        workspace_path=WORKSPACE,
        container_name=name,
    )


def _argv_text(plan) -> str:
    return " ".join(plan.cli_argv)


def make_git_workspace() -> tuple[str, RemediationWorkspace]:
    root = Path(tempfile.mkdtemp(prefix="devops-sbx-ws-"))
    repo = root / "repository"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "t@example.com"], cwd=repo, check=True
    )
    subprocess.run(
        ["git", "config", "user.name", "T"], cwd=repo, check=True
    )
    target = repo / "service.py"
    target.write_text("print('old')\n", encoding="utf-8")
    subprocess.run(["git", "add", "service.py"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "fixture"], cwd=repo, check=True)
    target.write_text("print('new')\n", encoding="utf-8")
    workspace = RemediationWorkspace(
        path=str(repo),
        cleanup_path=str(root),
        repository_slug="owner/repo",
        source_sha=SOURCE_SHA,
        base_branch="main",
        branch_name="automation/remediation/inc-1/proposal-1",
    )
    return root, workspace


class _SpySandbox:
    def __init__(self, outcome=None, error=None):
        self.calls = []
        self._outcome = outcome
        self._error = error

    def execute(self, step, workspace_path):
        self.calls.append((step, workspace_path))
        if self._error is not None:
            raise self._error
        return self._outcome


def _ok_outcome(stdout="ok\n"):
    from incident_service.application.services.validation_sandbox import (
        SandboxStepOutcome,
    )

    return SandboxStepOutcome(
        exit_code=0,
        stdout=stdout,
        stderr="",
        timed_out=False,
        output_truncated=False,
    )


class NoHostFallbackTests(unittest.TestCase):
    """A. Sandbox failure never reaches a host/in-process executor."""

    def test_runner_rejects_missing_sandbox(self):
        with self.assertRaises(ValueError) as ctx:
            RemediationValidationRunner(sandbox=None)  # type: ignore[arg-type]
        self.assertIn("fallback", str(ctx.exception))

    def test_runner_sandbox_parameter_has_no_default(self):
        signature = inspect.signature(RemediationValidationRunner)
        parameter = signature.parameters["sandbox"]
        self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_sandbox_failure_is_typed_fail_closed_not_host_run(self):
        root, workspace = make_git_workspace()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        profiles = {
            "test": (
                ValidationStep(
                    name="s",
                    working_directory=".",
                    argv=("python", "-c", "print('ok')"),
                    timeout_seconds=5,
                    max_output_bytes=4096,
                ),
            )
        }
        runner = RemediationValidationRunner(
            sandbox=_SpySandbox(
                error=ValidationSandboxUnavailableError("runtime gone")
            ),
            profiles=profiles,
        )
        with patch.object(
            LocalProcessValidationExecutor,
            "execute",
            side_effect=AssertionError("host execution must never run"),
        ) as host_execute:
            with self.assertRaises(ValidationSandboxUnavailableError):
                runner.validate(workspace, "test", "service.py")
        host_execute.assert_not_called()  # the host seam was never reached

    def test_container_runtime_unavailable_fails_closed(self):
        def missing_cli(argv, timeout):
            raise FileNotFoundError("docker not found")

        sandbox = ContainerValidationSandbox(
            image=DIGEST_IMAGE, cli_runner=missing_cli
        )
        with self.assertRaises(ValidationSandboxUnavailableError):
            sandbox.execute(_step(), WORKSPACE)

    def test_unconfigured_image_fails_closed(self):
        sandbox = ContainerValidationSandbox(
            image="", cli_runner=MagicMock()
        )
        with self.assertRaises(ValidationSandboxConfigurationError):
            sandbox.execute(_step(), WORKSPACE)
        sandbox._cli_runner.assert_not_called()

    def test_production_wiring_uses_container_sandbox(self):
        from incident_service.presentation.rest.controllers import (
            get_remediation_orchestrator,
        )

        orchestrator = get_remediation_orchestrator()
        runner = orchestrator.validation_runner
        self.assertIsInstance(
            runner.sandbox, ContainerValidationSandbox
        )


class SecretIsolationTests(unittest.TestCase):
    """B. Host secrets can never enter the sandbox environment."""

    def test_sandbox_env_is_exact_allowlist(self):
        with patch.dict(os.environ, _SECRET_ENV):
            plan = _plan()
        self.assertEqual(set(plan.env), set(SANDBOX_ENV_ALLOWLIST))
        for key in _SECRET_ENV:
            self.assertNotIn(key, plan.env)
        argv_text = _argv_text(plan)
        for value in _SECRET_ENV.values():
            self.assertNotIn(value, argv_text)

    def test_env_values_come_from_policy_not_host(self):
        with patch.dict(os.environ, {"PATH": "/host/evil/bin", "LANG": "xx"}):
            plan = _plan()
        self.assertEqual(plan.env["PATH"], SANDBOX_ENV_ALLOWLIST["PATH"])
        self.assertNotIn("/host/evil/bin", _argv_text(plan))

    def test_allowlist_keys_cannot_look_like_secrets(self):
        import re

        pattern = re.compile(
            r"(TOKEN|PASSWORD|SECRET|PRIVATE_KEY|API_KEY|CREDENTIAL)",
            re.IGNORECASE,
        )
        for key in SANDBOX_ENV_ALLOWLIST:
            self.assertIsNone(pattern.search(key), key)


class FilesystemIsolationTests(unittest.TestCase):
    """C. Only the intended workspace is mounted."""

    def test_only_workspace_mount_present(self):
        plan = _plan()
        self.assertEqual(
            plan.mounts, (f"{WORKSPACE}:/workspace:rw",)
        )

    def test_no_sensitive_host_paths_mounted(self):
        plan = _plan()
        forbidden = (
            "/var/run/docker.sock",
            "/proc",
            "/sys",
            "/home",
            "/root",
            "/.ssh",
            "/etc",
        )
        for mount in plan.mounts:
            source = mount.split(":", 1)[0]
            for needle in forbidden:
                self.assertNotEqual(source, needle, mount)
                self.assertFalse(source.startswith(needle + "/"), mount)
        self.assertNotIn("/var/run/docker.sock", _argv_text(plan))


class NetworkIsolationTests(unittest.TestCase):
    """D. Network disabled by default; exceptions are policy-only."""

    def test_network_none_in_generated_config(self):
        plan = _plan()
        pairs = list(zip(plan.cli_argv, plan.cli_argv[1:]))
        self.assertIn(("--network", "none"), pairs)

    def test_non_none_network_is_rejected(self):
        spec = _runtime(network_mode="bridge")
        with self.assertRaises(SandboxPolicyViolation):
            validate_runtime_spec(spec)
        with self.assertRaises(SandboxPolicyViolation):
            build_run_plan(
                spec=spec,
                step=_step(),
                workspace_path=WORKSPACE,
                container_name="remed-sbx-test-1",
            )


class PrivilegeHardeningTests(unittest.TestCase):
    """E. Generated runtime configuration hardening (config, not kernel)."""

    def test_hardening_flags_present_and_dangerous_ones_absent(self):
        plan = _plan()
        argv = plan.cli_argv
        argv_text = _argv_text(plan)

        self.assertIn("--read-only", argv)
        self.assertIn("--rm", argv)
        self.assertIn("no-new-privileges:true", argv)
        pairs = list(zip(argv, argv[1:]))
        self.assertIn(("--cap-drop", "ALL"), pairs)
        user = argv[argv.index("--user") + 1]
        self.assertNotEqual(int(user.split(":")[0]), 0)

        self.assertNotIn("--privileged", argv_text)
        self.assertNotIn("seccomp=unconfined", argv_text)
        self.assertNotIn("--network host", argv_text)
        self.assertNotIn("--pid host", argv_text)
        self.assertNotIn("--ipc host", argv_text)

    def test_seccomp_profile_is_optional_but_never_unconfined(self):
        plan = _plan(
            spec=_runtime(
                seccomp_profile="/etc/docker/seccomp/remediation.json"
            )
        )
        self.assertIn(
            "seccomp=/etc/docker/seccomp/remediation.json", plan.cli_argv
        )
        with self.assertRaises(SandboxPolicyViolation):
            validate_runtime_spec(
                _runtime(seccomp_profile="unconfined.json")
            )
        with self.assertRaises(SandboxPolicyViolation):
            validate_runtime_spec(
                _runtime(seccomp_profile="/etc/profile.conf")
            )


class ResourceLimitTests(unittest.TestCase):
    """F. Time/CPU/memory/process limits bounded and policy-owned."""

    def test_limits_present_and_bounded(self):
        plan = _plan(step=_step(timeout=30.0))
        argv = plan.cli_argv
        pairs = list(zip(argv, argv[1:]))
        self.assertIn(("--pids-limit", str(SANDBOX_PIDS_LIMIT)), pairs)
        self.assertIn(("--memory", str(SANDBOX_MEMORY_BYTES)), pairs)
        self.assertIn(("--cpus", "2"), pairs)
        self.assertEqual(
            plan.wall_timeout_seconds, 30.0 + SANDBOX_WALL_GRACE_SECONDS
        )
        self.assertLessEqual(
            plan.wall_timeout_seconds,
            SANDBOX_MAX_RUNTIME_SECONDS + SANDBOX_WALL_GRACE_SECONDS,
        )

    def test_oversized_step_limits_rejected(self):
        for bad_step in (
            _step(timeout=SANDBOX_MAX_RUNTIME_SECONDS + 1),
            _step(timeout=0),
            _step(max_output=SANDBOX_MAX_OUTPUT_BYTES + 1),
            _step(argv=("bash", "-c", "echo hi")),
            _step(working_directory="../escape"),
        ):
            with self.assertRaises(SandboxPolicyViolation):
                build_run_plan(
                    spec=_runtime(),
                    step=bad_step,
                    workspace_path=WORKSPACE,
                    container_name="remed-sbx-test-1",
                )

    def test_runner_profile_policy_still_bounds_steps(self):
        with self.assertRaises(ValueError):
            RemediationValidationRunner(
                sandbox=LocalProcessValidationExecutor(),
                profiles={
                    "p": (
                        ValidationStep(
                            name="s",
                            working_directory=".",
                            argv=("python", "-c", "print(1)"),
                            timeout_seconds=SANDBOX_MAX_RUNTIME_SECONDS + 1,
                        ),
                    )
                },
            )


class _RecordingCli:
    """Deterministic fake docker CLI: records every invocation."""

    def __init__(self, run_result=None, raise_on_first=None):
        self.calls = []
        self._run_result = run_result
        self._raise_on_first = raise_on_first

    def __call__(self, argv, timeout):
        from incident_service.infrastructure.sandbox.container_validation_sandbox import (
            _CliResult,
        )

        self.calls.append((tuple(argv), timeout))
        if self._raise_on_first is not None and len(self.calls) == 1:
            raise self._raise_on_first
        if tuple(argv)[:3] == ("docker", "rm", "-f"):
            return _CliResult(0, b"", b"")
        if self._run_result is not None:
            return self._run_result
        return _CliResult(0, b"ok\n", b"")

    @property
    def cleanup_calls(self):
        return [
            c for c in self.calls if c[0][:3] == ("docker", "rm", "-f")
        ]

    @property
    def run_calls(self):
        return [c for c in self.calls if c[0][:2] == ("docker", "run")]


class CleanupTests(unittest.TestCase):
    """G. Cleanup on success, timeout, failure and startup failure."""

    def _sandbox(self, cli):
        return ContainerValidationSandbox(image=DIGEST_IMAGE, cli_runner=cli)

    def test_cleanup_on_success(self):
        cli = _RecordingCli()
        outcome = self._sandbox(cli).execute(_step(), WORKSPACE)
        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual(len(cli.run_calls), 1)
        self.assertEqual(len(cli.cleanup_calls), 1)
        self.assertEqual(
            cli.run_calls[0][0][4], cli.cleanup_calls[0][0][3]
        )  # same --name container removed

    def test_cleanup_on_timeout(self):
        from incident_service.infrastructure.sandbox.container_validation_sandbox import (
            _CliResult,
        )

        cli = _RecordingCli(
            run_result=_CliResult(-9, b"", b"wall clock", timed_out=True)
        )
        outcome = self._sandbox(cli).execute(_step(timeout=5.0), WORKSPACE)
        self.assertTrue(outcome.timed_out)
        self.assertEqual(len(cli.cleanup_calls), 1)

    def test_cleanup_on_command_failure(self):
        cli = _RecordingCli(run_result=_import_result(3, b"", b"boom"))
        outcome = self._sandbox(cli).execute(_step(), WORKSPACE)
        self.assertEqual(outcome.exit_code, 3)
        self.assertFalse(outcome.timed_out)
        self.assertEqual(len(cli.cleanup_calls), 1)

    def test_startup_failure_is_typed_and_not_host_run(self):
        cli = _RecordingCli(raise_on_first=FileNotFoundError("docker"))
        with self.assertRaises(ValidationSandboxUnavailableError):
            self._sandbox(cli).execute(_step(), WORKSPACE)
        # the run attempt failed before any container existed, and
        # best-effort cleanup still ran without raising
        self.assertEqual(cli.calls[0][0][:2], ("docker", "run"))
        self.assertEqual(len(cli.cleanup_calls), 1)

    def test_malformed_result_fails_closed(self):
        cli = _RecordingCli(
            run_result=_import_result(None, b"", b"")
        )
        with self.assertRaises(ValidationSandboxResultError):
            self._sandbox(cli).execute(_step(), WORKSPACE)

    def test_daemon_unreachable_is_typed_unavailable(self):
        cli = _RecordingCli(
            run_result=_import_result(
                125, b"", b"Cannot connect to the Docker daemon"
            )
        )
        with self.assertRaises(ValidationSandboxUnavailableError):
            self._sandbox(cli).execute(_step(), WORKSPACE)


def _import_result(exit_code, stdout, stderr):
    from incident_service.infrastructure.sandbox.container_validation_sandbox import (
        _CliResult,
    )

    return _CliResult(exit_code, stdout, stderr)


class LeaseGuardOrderingTests(unittest.TestCase):
    """H. before_side_effect gates sandbox creation; lease loss still
    blocks the next durable side effect after sandbox execution."""

    def _orchestrator(self, runner):
        workspace_service = MagicMock()
        workspace_service.prepare.return_value = RemediationWorkspace(
            path="/tmp/ws",
            cleanup_path="/tmp/ws-root",
            repository_slug="owner/repo",
            source_sha="a" * 40,
            base_branch="main",
            branch_name="automation/remediation/inc-1/proposal-1",
        )
        patch_executor = MagicMock()
        patch_executor.apply.return_value = MagicMock(
            target_filepath="src/service.py"
        )
        validation_runner = MagicMock()
        validation_runner.validate.return_value = MagicMock(passed=True)
        validation_runner.validate.side_effect = (
            runner.validate if runner is not None else None
        )
        commit_service = MagicMock()
        commit_service.create.return_value = MockCommit()
        github = MagicMock()
        github.create_branch_from_commit.return_value = "https://example/tree"
        github.create_pull_request.return_value = (
            "https://github.com/owner/repo/pull/42"
        )
        return RemediationOrchestrationService(
            workspace_service=workspace_service,
            patch_executor=patch_executor,
            validation_runner=validation_runner,
            commit_service=commit_service,
            github_client=github,
        ), validation_runner, commit_service

    def test_guard_failure_prevents_sandbox_creation(self):
        root, workspace = make_git_workspace()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        spy = _SpySandbox(outcome=_ok_outcome())
        real_runner = RemediationValidationRunner(
            sandbox=spy,
            profiles={
                "test": (
                    ValidationStep(
                        name="s",
                        working_directory=".",
                        argv=("python", "-c", "print('ok')"),
                        timeout_seconds=5,
                        max_output_bytes=4096,
                    ),
                )
            },
        )
        service, validation_runner, _ = self._orchestrator(real_runner)

        def guard(operation):
            if operation == "validation.run":
                raise RemediationStageGuardError("lease lost")

        from incident_service.domain.entities.hotfix_proposal import (
            HotfixProposal,
        )

        proposal = HotfixProposal(
            id="proposal-1",
            target_filepath="src/service.py",
            diff_patch_payload=(
                "--- a/src/service.py\n+++ b/src/service.py\n"
                "@@ -1 +1 @@\n-old\n+new\n"
            ),
            is_verified=True,
            source_sha="a" * 40,
            repository="owner/repo",
        )
        # point the real runner's workspace checks at our git fixture by
        # monkeypatching the validation call boundary: orchestration must
        # never reach validate() when the guard refuses.
        with self.assertRaises(RemediationStageGuardError):
            service.execute(
                incident_id="inc-1",
                proposal=proposal,
                repository_slug="owner/repo",
                before_side_effect=guard,
            )
        self.assertEqual(spy.calls, [], "sandbox must not be created")
        validation_runner.validate.assert_not_called()

    def test_lease_loss_after_sandbox_blocks_next_side_effect(self):
        service, validation_runner, commit_service = self._orchestrator(None)
        validation_runner.validate.return_value = MagicMock(
            passed=True, source_sha="a" * 40
        )

        def guard(operation):
            if operation == "commit.create":
                raise RemediationStageGuardError("lease lost after validation")

        from incident_service.domain.entities.hotfix_proposal import (
            HotfixProposal,
        )

        proposal = HotfixProposal(
            id="proposal-1",
            target_filepath="src/service.py",
            diff_patch_payload=(
                "--- a/src/service.py\n+++ b/src/service.py\n"
                "@@ -1 +1 @@\n-old\n+new\n"
            ),
            is_verified=True,
            source_sha="a" * 40,
            repository="owner/repo",
        )
        with self.assertRaises(RemediationStageGuardError):
            service.execute(
                incident_id="inc-1",
                proposal=proposal,
                repository_slug="owner/repo",
                before_side_effect=guard,
            )
        validation_runner.validate.assert_called_once()
        commit_service.create.assert_not_called()


class MockCommit:
    parent_sha = "a" * 40
    commit_sha = "b" * 40
    branch_name = "automation/remediation/inc-1/proposal-1"
    target_filepath = "src/service.py"


class MaliciousRepositoryContentTests(unittest.TestCase):
    """I. Hostile repository content stays untrusted data."""

    PAYLOADS = (
        "'; rm -rf / #",
        "__import__('os').system('cat /proc/self/environ')",
        "cat ~/.ssh/id_rsa",
        "unix:///var/run/docker.sock",
        "http://169.254.169.254/latest/meta-data/",
        "postgresql://prod:password@db-internal:5432/postgres",
    )

    def test_payloads_never_reach_generated_command_or_env(self):
        plan = _plan(step=_step(argv=("python", "-c", "print('ok')")))
        argv_text = _argv_text(plan)
        for payload in self.PAYLOADS:
            self.assertNotIn(payload, argv_text)
        for payload in self.PAYLOADS:
            for value in plan.env.values():
                self.assertNotIn(payload, value)

    def test_payload_in_file_content_is_only_untrusted_input(self):
        root, workspace = make_git_workspace()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        target = Path(workspace.path) / "service.py"
        target.write_text(
            "import os\n"
            + "\n".join(f"# {p}\n" for p in self.PAYLOADS)
            + "print('new')\n",
            encoding="utf-8",
        )
        spy = _SpySandbox(outcome=_ok_outcome())
        runner = RemediationValidationRunner(
            sandbox=spy,
            profiles={
                "test": (
                    ValidationStep(
                        name="s",
                        working_directory=".",
                        argv=("python", "-c", "print('ok')"),
                        timeout_seconds=5,
                        max_output_bytes=4096,
                    ),
                )
            },
        )
        result = runner.validate(workspace, "test", "service.py")
        self.assertTrue(result.passed)
        self.assertEqual(len(spy.calls), 1)
        step, _ = spy.calls[0]
        self.assertEqual(step.argv, ("python", "-c", "print('ok')"))

    def test_hostile_filename_never_reaches_execution(self):
        root, workspace = make_git_workspace()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        repo = Path(workspace.path)
        (repo / "$(reboot).py").write_text("print('x')\n", encoding="utf-8")
        (repo / "a; rm -rf ~.py").write_text("print('y')\n", encoding="utf-8")
        spy = _SpySandbox(outcome=_ok_outcome())
        runner = RemediationValidationRunner(
            sandbox=spy,
            profiles={
                "test": (
                    ValidationStep(
                        name="s",
                        working_directory=".",
                        argv=("python", "-c", "print('ok')"),
                        timeout_seconds=5,
                        max_output_bytes=4096,
                    ),
                )
            },
        )
        with self.assertRaises(ValidationWorkspaceMutationError):
            runner.validate(workspace, "test", "service.py")
        self.assertEqual(
            spy.calls, [], "hostile workspace must never execute"
        )


def _docker_reachable() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        completed = subprocess.run(
            ["docker", "info"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


@unittest.skipUnless(
    _docker_reachable(),
    "docker runtime unavailable — configuration tests above remain the "
    "proof surface; no kernel-isolation claims are made without a runtime",
)
class RealContainerIntegrationTests(unittest.TestCase):
    """Small real-container check: bounded launch -> result -> cleanup.

    Provisions its image EXPLICITLY (docker pull by tag, then resolves the
    content digest) — the sandbox itself runs with --pull never.
    """

    @classmethod
    def setUpClass(cls):
        cls.image_tag = os.environ.get(
            "REMEDIATION_SANDBOX_TEST_IMAGE", "python:3.11-slim"
        )
        pull = subprocess.run(
            ["docker", "pull", cls.image_tag],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=300,
            check=False,
        )
        if pull.returncode != 0:
            raise unittest.SkipTest(
                f"could not provision test image {cls.image_tag!r}"
            )
        inspect_result = subprocess.run(
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{index .RepoDigests 0}}",
                cls.image_tag,
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
        cls.image_digest = inspect_result.stdout.strip()
        if "@sha256:" not in cls.image_digest:
            raise unittest.SkipTest("image has no resolvable content digest")

    def setUp(self):
        if os.getuid() == 0:
            self.skipTest("host runs as root; non-root assertion unavailable")
        self._tmp = tempfile.TemporaryDirectory(prefix="devops-sbx-int-")
        self.addCleanup(self._tmp.cleanup)
        repo = Path(self._tmp.name) / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(
            ["git", "config", "user.email", "t@example.com"],
            cwd=repo,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "T"], cwd=repo, check=True
        )
        (repo / "service.py").write_text("print('old')\n", encoding="utf-8")
        subprocess.run(["git", "add", "service.py"], cwd=repo, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "fixture"], cwd=repo, check=True
        )
        (repo / "service.py").write_text("print('new')\n", encoding="utf-8")
        # sensitive file OUTSIDE the workspace (must be invisible inside)
        outside = Path(self._tmp.name) / "host-secret.txt"
        outside.write_text("HOST-SECRET-VALUE", encoding="utf-8")

        self.workspace = RemediationWorkspace(
            path=str(repo),
            cleanup_path=self._tmp.name,
            repository_slug="owner/repo",
            source_sha="a" * 40,
            base_branch="main",
            branch_name="automation/remediation/inc-1/proposal-1",
        )

        self.steps = (
            ("uid", "import os,sys; sys.stdout.write(str(os.getuid()))"),
            (
                "net",
                "import socket,sys; sys.stdout.write("
                "repr([n for n, _ in socket.if_nameindex()]))",
            ),
            (
                "secret",
                "import os,sys; sys.stdout.write("
                "os.environ.get('GITHUB_OAUTH_TOKEN', 'ABSENT') + '|' + "
                "os.environ.get('JWT_SECRET', 'ABSENT'))",
            ),
            (
                "visible",
                "import sys; sys.stdout.write(open('service.py').read())",
            ),
            (
                "outside",
                "import sys\n"
                "try:\n"
                "    open('../host-secret.txt').read()\n"
                "    sys.stdout.write('OUTSIDE-VISIBLE')\n"
                "except OSError:\n"
                "    sys.stdout.write('OUTSIDE-ABSENT')\n",
            ),
        )

    def test_sandboxed_execution_isolation_and_cleanup(self):
        profiles = {
            "integration": tuple(
                ValidationStep(
                    name=f"step-{name}",
                    working_directory=".",
                    argv=("python", "-c", code),
                    timeout_seconds=60,
                    max_output_bytes=4096,
                )
                for name, code in self.steps
            )
        }
        sandbox = ContainerValidationSandbox(image=self.image_digest)
        runner = RemediationValidationRunner(
            sandbox=sandbox, profiles=profiles
        )
        with patch.dict(os.environ, _SECRET_ENV):
            result = runner.validate(
                self.workspace, "integration", "service.py"
            )
        self.assertTrue(result.passed, result)
        outputs = {s.name: s.stdout for s in result.steps}

        # non-root
        self.assertNotEqual(outputs["uid"], "0")
        self.assertNotIn("root", outputs["uid"])
        # network disabled: loopback only
        self.assertEqual(outputs["net"], "['lo']")
        # host secrets absent from sandbox env
        self.assertEqual(outputs["secret"], "ABSENT|ABSENT")
        # expected workspace file visible
        self.assertIn("print('new')", outputs["visible"])
        # file outside the mount unavailable
        self.assertEqual(outputs["outside"], "OUTSIDE-ABSENT")
        # sandbox containers removed afterwards
        listing = subprocess.run(
            [
                "docker",
                "ps",
                "-a",
                "--filter",
                "label=dev.arena.remediation-sandbox=1",
                "--format",
                "{{.Names}}",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(listing.stdout.strip(), "")


if __name__ == "__main__":
    unittest.main()
