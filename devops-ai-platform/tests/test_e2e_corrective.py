"""Phase 8.4.2-C — focused regression tests for the nine audited defects.

Each class maps to one defect group (P0-1..P1-6, items 7-9) from the
corrective brief. These tests are static/contractual where Docker/kind/
GitHub are required (those properties are proven live by the dispatch-only
workflow); they are behavioral where the code runs locally. No test mocks
the golden path itself — fakes appear only as in-process stand-ins for
parser/contract units (e.g. a fake `compose config` command that echoes
its environment, or a recorder for the workspace service's git calls).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
PLATFORM = REPO_ROOT / "devops-ai-platform"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "e2e-golden-path.yml"
COMPOSE_E2E = REPO_ROOT / "docker-compose.e2e.yml"
DOCKERFILES = (
    PLATFORM / "deployment_service" / "Dockerfile.e2e",
    PLATFORM / "incident_service" / "Dockerfile.e2e",
    PLATFORM / "e2e" / "workload" / "Dockerfile",
)
PINNED_FILE = PLATFORM / "e2e" / "pinned-images.txt"
DRIVER = PLATFORM / "e2e" / "golden_path.py"
WORKSPACE_SERVICE = (
    PLATFORM / "incident_service" / "application" / "services"
    / "remediation_workspace_service.py"
)
REPORT = REPO_ROOT / "docs" / "PHASE-8.4.2-E2E-GOLDEN-PATH-IMPLEMENTATION-REPORT.md"

sys.path.insert(0, str(PLATFORM))


def _workflow_text() -> str:
    return WORKFLOW.read_text()


def _workflow_doc() -> dict:
    return yaml.safe_load(_workflow_text())


def _job(doc: dict) -> dict:
    return next(iter(doc["jobs"].values()))


def _steps(doc: dict) -> list:
    return _job(doc)["steps"]


def _step(doc: dict, prefix: str) -> dict:
    for step in _steps(doc):
        if str(step.get("name", "")).startswith(prefix):
            return step
    raise AssertionError(f"step not found: {prefix}")


# --------------------------------------------------------------------------
# P0-1: registry must not assume the kind network pre-exists
# --------------------------------------------------------------------------

class TestRegistryOrderingRegression:
    @staticmethod
    def _configure_run() -> str:
        return _step(_workflow_doc(), "Configure registry (own network)")["run"]

    def test_registry_created_before_kind(self):
        run = self._configure_run()
        create_net = run.index("docker network create e2e-registry-net")
        run_registry = run.index("--name kind-registry")
        create_kind = run.index("kind create cluster")
        assert create_net < run_registry < create_kind

    def test_registry_attached_to_kind_only_after_kind_exists(self):
        run = self._configure_run()
        create_kind = run.index("kind create cluster")
        connect = run.index("docker network connect kind kind-registry")
        inspect_kind = run.index("docker network inspect kind")
        assert connect > create_kind
        assert inspect_kind > create_kind

    def test_registry_runs_on_its_own_dedicated_network(self):
        run = self._configure_run()
        launch = run.split("docker run -d", 1)[1].split("docker ps", 1)[0]
        assert "--network e2e-registry-net" in launch
        assert "--network-alias kind-registry" in launch
        assert "--network kind" not in launch

    def test_registry_state_networks_and_pull_proof_recorded(self):
        text = _workflow_text()
        for record in (
            "registry-state.txt",
            "registry-networks-postconnect.txt",
            "kind-registry-connectivity.txt",
            "kind-image-pull-proof.txt",
            "workload-push.txt",
        ):
            assert record in text, record

    def test_kind_config_mirrors_local_registry(self):
        kind_cfg = (PLATFORM / "e2e" / "kind-config.yaml").read_text()
        assert "localhost:5001" in kind_cfg

    def test_reachability_and_image_pull_proven_from_kind(self):
        text = _workflow_text()
        assert "</dev/tcp/kind-registry/5000" in text
        assert "wait --for=condition=Ready pod/checkout-service" in text
        assert 'sed "s|WORKLOAD_IMAGE_REF|${E2E_WORKLOAD_IMAGE}|g"' in text


# --------------------------------------------------------------------------
# P0-2: one dedicated host-visible workspace root; fail-closed sandbox
# --------------------------------------------------------------------------

class TestHostVisibleWorkspace:
    def test_service_rejects_relative_workspace_root(self):
        from incident_service.application.services.remediation_workspace_service import (
            RemediationWorkspaceService,
        )
        with pytest.raises(ValueError, match="absolute"):
            RemediationWorkspaceService(workspace_root="relative/path")

    def test_service_requires_root_itself_to_exist(self, tmp_path):
        from incident_service.application.services.remediation_workspace_service import (
            RemediationWorkspaceService,
        )
        with pytest.raises(ValueError, match="does not exist"):
            RemediationWorkspaceService(workspace_root=str(tmp_path / "absent"))

    def test_root_mode_missing_token_fails_closed_before_clone(
        self, tmp_path, monkeypatch
    ):
        from incident_service.application.services.remediation_workspace_service import (
            RemediationWorkspaceError,
            RemediationWorkspaceService,
        )
        monkeypatch.setenv("REMEDIATION_WORKSPACE_ROOT", str(tmp_path))
        monkeypatch.delenv("GITHUB_OAUTH_TOKEN", raising=False)
        svc = RemediationWorkspaceService(workspace_root=str(tmp_path))
        called = {"clone": 0}
        monkeypatch.setattr(
            svc,
            "_run_git",
            lambda *a, **k: called.__setitem__("clone", called["clone"] + 1),
        )
        with pytest.raises(RemediationWorkspaceError, match="GITHUB_OAUTH_TOKEN"):
            svc.prepare("gm-prog/ares-e2e-fixture", "a" * 40, "inc", "prop")
        assert called["clone"] == 0
        assert not list(tmp_path.glob("devops-remediation-*"))

    def test_prepare_places_workspace_under_root_and_authenticates(
        self, tmp_path, monkeypatch
    ):
        from incident_service.application.services.remediation_workspace_service import (
            RemediationWorkspaceService,
        )
        token = "ghp_fixture_token_UNIT_TEST_ONLY"
        monkeypatch.setenv("REMEDIATION_WORKSPACE_ROOT", str(tmp_path))
        monkeypatch.setenv("GITHUB_OAUTH_TOKEN", token)
        svc = RemediationWorkspaceService(workspace_root=str(tmp_path))
        sha = "b" * 40
        calls: list[tuple[list[str], dict]] = []

        def fake_run_git(args, cwd=None, extra_env=None):
            calls.append((list(args), dict(extra_env or {})))

            class _R:
                stdout = ""

            if args[1] == "clone":
                target = Path(args[-1])
                (target / ".git").mkdir(parents=True, exist_ok=True)
            if args[1:3] == ["rev-parse", "HEAD"]:
                _R.stdout = sha + "\n"
            elif args[1:3] == ["rev-parse", "--abbrev-ref"]:
                _R.stdout = "main\n"
            return _R()

        monkeypatch.setattr(svc, "_run_git", fake_run_git)
        ws = svc.prepare(
            "gm-prog/ares-e2e-fixture", sha, "inc-1", "proposal-inc-1"
        )
        root = Path(tmp_path).resolve()
        path = Path(ws.path).resolve()
        assert path.is_relative_to(root)
        assert Path(ws.cleanup_path).resolve().is_relative_to(root)
        assert path.is_dir()
        for argv, extra in calls:
            joined = " ".join(argv)
            assert token not in joined, argv
            assert "-c" not in argv, argv
            if argv[1] in ("clone", "fetch"):
                assert extra.get("GIT_CONFIG_KEY_0") == "http.extraHeader"
                assert extra.get("GIT_CONFIG_VALUE_0") == (
                    f"Authorization: Bearer {token}"
                )
                assert extra.get("GIT_CONFIG_COUNT") == "1"
            if argv[1] == "clone":
                assert argv[-2].startswith("https://github.com/")
                host = argv[-2].split("://", 1)[1].split("/", 1)[0]
                assert "@" not in host
        # cleanup cannot escape the root
        from incident_service.application.services.remediation_workspace_service import (
            RemediationWorkspaceError,
        )
        outside = Path(tempfile.gettempdir()) / "must-not-be-removed"
        outside.mkdir(exist_ok=True)
        with pytest.raises(RemediationWorkspaceError, match="outside the workspace root"):
            svc._cleanup_path(outside)
        assert outside.exists()
        svc._cleanup_path(path.parent)  # in-root path is removable
        assert not path.parent.exists()

    def test_sandbox_guard_enforces_root_and_existence(self, monkeypatch):
        from incident_service.application.services.validation_sandbox import (
            SANDBOX_WORKSPACE_MOUNT,
            SandboxPolicyViolation,
            SandboxRuntimeSpec,
            SandboxStepSpec,
            build_run_plan,
        )
        spec = SandboxRuntimeSpec(
            image="x@sha256:" + "c" * 64,
            user="1000:1000",
            network_mode="none",
            seccomp_profile=None,
        )
        step = SandboxStepSpec(
            name="unit-test",
            argv=("python", "-V"),
            working_directory=".",
            timeout_seconds=5.0,
            max_output_bytes=1024,
        )
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root) / "ws-root"
            root_path.mkdir()
            monkeypatch.setenv("REMEDIATION_WORKSPACE_ROOT", str(root_path))
            with pytest.raises(SandboxPolicyViolation, match="does not exist"):
                build_run_plan(spec=spec, step=step,
                               workspace_path=root_path / "missing",
                               container_name="c1")
            with tempfile.TemporaryDirectory() as other:
                with pytest.raises(SandboxPolicyViolation, match="beneath"):
                    build_run_plan(spec=spec, step=step,
                                   workspace_path=Path(other),
                                   container_name="c2")
            inside = root_path / "repo"
            inside.mkdir()
            plan = build_run_plan(spec=spec, step=step,
                                  workspace_path=inside, container_name="c3")
            ro_mounts = [m for m in plan.cli_argv if ":ro" in str(m)]
            assert ro_mounts == [f"{inside}:{SANDBOX_WORKSPACE_MOUNT}:ro"]
            assert plan.mounts == (f"{inside}:{SANDBOX_WORKSPACE_MOUNT}:ro",)
            # the bind source appears exactly once in the argv
            occurrences = sum(str(inside) in str(a) for a in plan.cli_argv)
            assert occurrences == 1

    def test_sandbox_never_mounts_docker_socket_or_falls_back_to_host(self):
        from incident_service.application.services import validation_sandbox
        from incident_service.infrastructure.sandbox import (
            container_validation_sandbox as container_mod,
        )
        v_src = Path(validation_sandbox.__file__).read_text()
        c_src = Path(container_mod.__file__).read_text()
        assert "docker.sock" not in v_src
        assert "docker.sock" not in c_src
        assert v_src.count("{workspace}:{SANDBOX_WORKSPACE_MOUNT}:ro") == 1
        assert "no host fallback" in v_src or "host/in-process fallback" in v_src
        assert "remediation validation will not run on the host" in c_src

    def test_workflow_mounts_root_at_identical_host_and_container_path(self):
        compose = COMPOSE_E2E.read_text()
        assert (
            "- /tmp/ares-e2e-workspaces:/tmp/ares-e2e-workspaces" in compose
        )
        assert "- REMEDIATION_WORKSPACE_ROOT=/tmp/ares-e2e-workspaces" in compose
        text = _workflow_text()
        assert 'E2E_WORKSPACES_ROOT: "/tmp/ares-e2e-workspaces"' in text
        proof = _step(_workflow_doc(), "Prove host-visible workspace")
        run = proof["run"]
        assert "docker exec devops_incident_service sh -c" in run
        assert '"$SRC:/workspace:ro"' in run
        assert "sandbox-ro-ok" in run
        assert "REMEDIATION_WORKSPACE_ROOT" in run
        mkdir = _step(_workflow_doc(), "Create host-visible remediation workspace root")
        assert 'rm -rf "$E2E_WORKSPACES_ROOT"' in mkdir["run"]
        cleanup = _step(_workflow_doc(), "Cleanup (local + remote")
        assert 'rm -rf "$E2E_WORKSPACES_ROOT"' in cleanup["run"]


# --------------------------------------------------------------------------
# P0-3: authenticated fixture clone (static contract + workflow proof)
# --------------------------------------------------------------------------

class TestAuthenticatedFixtureClone:
    def test_token_required_and_fail_closed_in_root_mode(self):
        src = WORKSPACE_SERVICE.read_text()
        assert "GITHUB_OAUTH_TOKEN is required to acquire the private" in src
        assert "GIT_CONFIG_VALUE_0" in src
        assert 'f"Authorization: Bearer {oauth_token}"' in src

    def test_no_token_in_url_config_or_argv_anywhere(self):
        src = WORKSPACE_SERVICE.read_text()
        assert 'f"https://github.com/{repo}.git"' in src
        assert "x-access-token" not in src
        assert "GIT_CONFIG_VALUE_0" in src and "http.extraHeader" in src
        assert not re.search(r"https://[^\n]*\{oauth_token\}", src)
        assert not re.search(r"https://[^\n]*\{token\}", src)

    def test_workflow_token_travels_via_stdin_env_not_argv(self):
        text = _workflow_text()
        assert (
            'printf \'%s\' "$E2E_FIXTURE_GITHUB_TOKEN" | docker exec -i'
            in text
        )
        assert not re.search(r"https://[^\s]*E2E_FIXTURE_GITHUB_TOKEN", text)
        assert not re.search(r"docker exec [^\n]*-e [^\n]*TOKEN", text)
        assert "x-access-token" not in text

    def test_workflow_proves_private_then_authenticated_fetch(self):
        step = _step(_workflow_doc(), "Prove fixture repo is private")
        run = step["run"]
        assert "unauthenticated-fetch=denied" in run
        assert "GIT_CONFIG_KEY_0=http.extraHeader" in run
        assert "git-auth-proof.txt" in run

    def test_sha_pinning_contract_after_auth_fetch(self):
        src = WORKSPACE_SERVICE.read_text()
        assert '"git", "fetch", "--no-tags", "origin", sha' in src
        assert '"git", "checkout", "--detach", sha' in src
        assert "checked out revision did not match the requested source SHA" in src

    def test_fixture_to_fixture_scope_production_never_targeted(self):
        driver = DRIVER.read_text()
        assert 'FIXTURE_REPO = os.environ.get("E2E_FIXTURE_REPOSITORY"' in driver
        assert 'f"/repos/{FIXTURE_REPO}/pulls"' in driver
        assert "/repos/gm-prog/Autonomous-Devops-Engineer/pulls" not in driver
        # workflow cleanup refuses the production repo explicitly
        assert 'repo == "gm-prog/Autonomous-Devops-Engineer"' in _workflow_text()


# --------------------------------------------------------------------------
# P1-4: concurrency oracle
# --------------------------------------------------------------------------

class TestConcurrencyOracle:
    @pytest.mark.parametrize(
        "statuses",
        [
            [200, 409],
            [409, 200],
            [502, 409],
            [409, 502],
            [504, 409],
            [409, 504],
        ],
    )
    def test_acceptable_patterns(self, statuses):
        from e2e.helpers import classify_execution_outcomes
        result = classify_execution_outcomes(statuses)
        assert result["acceptable"] is True
        assert len(result["winners"]) == 1
        assert len(result["conflicts"]) == 1
        assert result["invalid"] == []

    @pytest.mark.parametrize(
        "statuses",
        [
            [200, 200],
            [502, 502],
            [504, 504],
            [409, 409],
            [200, 500],
            [404, 409],
            [],
            [200],
            [200, 409, 409],
        ],
    )
    def test_unacceptable_patterns(self, statuses):
        from e2e.helpers import classify_execution_outcomes
        result = classify_execution_outcomes(statuses)
        assert result["acceptable"] is False

    def test_driver_assertion_is_strict(self):
        src = DRIVER.read_text()
        assert 'gate["successes"] >= 0' not in src
        assert (
            'bool(gate["acceptable"]) and state.get("status") == "PR_CREATED"'
            in src
        )

    def test_acceptable_documents_relay_timeout_winner_semantics(self):
        text = REPORT.read_text()
        assert "relay-timeout" in text or "relay timeout" in text


# --------------------------------------------------------------------------
# P1-5: immutability of build inputs
# --------------------------------------------------------------------------

class TestImmutability:
    FORBIDDEN = ("python:3.11-slim", "python:latest", "python@invalid")
    SCANNED = (WORKFLOW, COMPOSE_E2E, *DOCKERFILES)

    @pytest.mark.parametrize("path", SCANNED, ids=lambda p: p.name)
    def test_no_forbidden_image_references(self, path):
        text = path.read_text()
        for token in self.FORBIDDEN:
            assert token not in text, f"{path}: contains {token}"

    @pytest.mark.parametrize("path", SCANNED, ids=lambda p: p.name)
    def test_every_digest_reference_is_64hex(self, path):
        for digest in re.findall(r"@sha256:([0-9a-fA-F]+)", path.read_text()):
            assert re.fullmatch(r"[0-9a-f]{64}", digest), f"{path}: {digest}"

    def test_dockerfiles_fail_closed_without_digest_base(self):
        for path in DOCKERFILES:
            text = path.read_text()
            assert "ARG BASE_IMAGE\n" in text, path
            assert "FROM ${BASE_IMAGE:?" in text, path

    def test_compose_requires_digest_pinned_refs(self):
        text = COMPOSE_E2E.read_text()
        assert text.count("${E2E_PYTHON_BASE_IMAGE:?") == 2
        assert text.count("${E2E_POSTGRES_IMAGE:?") == 1
        assert text.count("${E2E_REDIS_IMAGE:?") == 1
        assert text.count("${E2E_QDRANT_IMAGE:?") == 1
        assert ":-postgres" not in text and ":-redis" not in text

    def test_pinned_file_has_no_invented_digests(self):
        seen_keys = 0
        for line in PINNED_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            assert len(parts) == 3, line
            name, pin, key = parts
            assert "@" not in name, name
            assert re.fullmatch(r"[A-Z][A-Z0-9_]*", key), key
            if pin != "UNRESOLVED":
                assert re.fullmatch(r"sha256:[0-9a-f]{64}", pin), pin
            seen_keys += 1
        assert seen_keys == 6

    def test_workflow_resolves_inputs_from_pinned_file_only(self):
        step = _step(_workflow_doc(), "Resolve immutable build inputs")
        run = step["run"]
        assert "pinned-images.txt" in run
        assert 'echo "${KEY}=${REF}" >> "$GITHUB_ENV"' in run
        # no image source name appears anywhere in the workflow text
        pinned_names = [
            ln.split()[0]
            for ln in PINNED_FILE.read_text().splitlines()
            if ln.strip() and not ln.startswith("#")
        ]
        text = _workflow_text()
        for name in pinned_names:
            assert name not in text, name

    def test_manifest_records_build_inputs(self):
        src = DRIVER.read_text()
        for field in (
            "fixture_seed_sha=FIXTURE_SEED_SHA",
            "workspace_root=WORKSPACES_ROOT",
            "registry_image_digest=",
            "kind_node_image_digest=",
            "base_images=",
            "built_image_digests=",
        ):
            assert field in src, field

    def test_sandbox_digest_enforcement_not_weakened(self):
        src = (
            PLATFORM / "incident_service" / "application" / "services"
            / "validation_sandbox.py"
        ).read_text()
        assert "content-addressed digest reference" in src
        assert "Floating tags" in src


# --------------------------------------------------------------------------
# P1-6: secret staging
# --------------------------------------------------------------------------

class TestSecretStaging:
    SECRET = "ghp_Xx9K2pQr7Ws3Tn5Vb8Za"  # synthetic, matches scanner {20,}

    def test_sanitized_env_redacts_known_secret_keys(self):
        from e2e.compose_diagnostics import REDACTED, sanitized_env
        env = {
            "E2E_JWT_SECRET": self.SECRET,
            "E2E_FIXTURE_GITHUB_TOKEN": self.SECRET,
            "JWT_SECRET": self.SECRET,
            "GITHUB_OAUTH_TOKEN": self.SECRET,
            "PATH": "/usr/bin",
        }
        clean = sanitized_env(env)
        assert clean["E2E_JWT_SECRET"] == REDACTED
        assert clean["E2E_FIXTURE_GITHUB_TOKEN"] == REDACTED
        assert clean["PATH"] == "/usr/bin"
        assert self.SECRET not in clean.values()

    def test_render_uses_sanitized_env(self, tmp_path):
        from e2e.compose_diagnostics import render_compose_config
        out = tmp_path / "compose-config.txt"
        env = dict(os.environ)
        env["E2E_JWT_SECRET"] = self.SECRET
        env["E2E_FIXTURE_GITHUB_TOKEN"] = self.SECRET
        env["PATH"] = env.get("PATH", "/usr/bin")
        rendered = render_compose_config(
            ["bash", "-c",
             'echo "jwt=$E2E_JWT_SECRET tok=$E2E_FIXTURE_GITHUB_TOKEN"'],
            str(out),
            env=env,
        )
        assert self.SECRET not in rendered
        assert self.SECRET not in out.read_text()
        assert "[REDACTED-NON-SECRET]" in rendered

    def test_scan_detects_injected_fixture_secret(self, tmp_path):
        from e2e.compose_diagnostics import scan_tree
        bad = tmp_path / "leak.txt"
        bad.write_text(f"authorization: {self.SECRET}\n")
        findings = scan_tree(str(tmp_path))
        assert findings and any("leak.txt" in f for f in findings)

    def test_scan_backstop_exit_codes(self, tmp_path):
        from e2e.compose_diagnostics import main
        clean = tmp_path / "ok.txt"
        clean.write_text("nothing to see")
        assert main([str(tmp_path)]) == 0
        (tmp_path / "bad.txt").write_text(f"Bearer {self.SECRET}")
        assert main([str(tmp_path)]) == 1
        assert main([]) == 2

    def test_injected_secret_blocks_upload_via_scan_step(self):
        doc = _workflow_doc()
        scan = _step(doc, "Secret scan backstop")
        assert scan["id"] == "secretscan"
        upload = _step(doc, "Upload E2E artifacts")
        assert "steps.secretscan.outcome == 'success'" in str(upload["if"])
        names = [s.get("name", "") for s in _steps(doc)]
        assert names.index(scan["name"]) < names.index(upload["name"])

    def test_diagnostics_rendered_from_sanitized_helper(self):
        text = _workflow_text()
        assert "render_compose_config(" in text
        assert (
            'out = os.path.join(os.environ["E2E_ARTIFACT_DIR"], '
            '"compose-config.txt")' in text
        )
        assert 'config > "$E2E_ARTIFACT_DIR/compose-config.txt"' not in text

    def test_secrets_are_step_scoped_not_job_scoped(self):
        doc = _workflow_doc()
        job = _job(doc)
        assert not any("secrets." in str(v) for v in job.get("env", {}).values())
        for step in _steps(doc):
            if "secrets." in yaml.safe_dump(step):
                assert step.get("env"), step.get("name")

    def test_no_token_in_command_lines_or_git_remotes(self):
        text = _workflow_text()
        assert "-c http.extraHeader" not in text
        assert not re.search(
            r"https://[^\s\"']*\$\{?E2E_FIXTURE_GITHUB_TOKEN", text
        )


# --------------------------------------------------------------------------
# 7: bounded observable replay polling (no fixed sleep as proof)
# --------------------------------------------------------------------------

class TestReplayPolling:
    def test_replay_has_no_fixed_sleep(self):
        src = DRIVER.read_text()
        assert "time.sleep(6)" not in src
        replay = src[src.index("def replay("):src.index("def _replay_consumer_probe(")]
        assert "time.sleep" not in replay
        assert "time.sleep" not in src[
            src.index("def _replay_consumer_probe("):
            src.index("def evidence(")
        ]

    def test_replay_uses_bounded_observable_probe(self):
        src = DRIVER.read_text()
        assert 'wait_until("replay-consumed"' in src
        assert "_replay_consumer_probe" in src
        assert "XPENDING" in src
        assert "last-delivered-id" in src
        replay = src[src.index("def replay("):src.index("def _replay_consumer_probe(")]
        assert "ReadinessTimeout" in replay
        assert "replayed event delivered and acknowledged" in replay

    def test_readiness_polling_is_deadline_and_interval_based(self):
        readiness = (PLATFORM / "e2e" / "readiness.py").read_text()
        assert "deadline" in readiness and "interval" in readiness


# --------------------------------------------------------------------------
# 8/9 + driver contracts
# --------------------------------------------------------------------------

class TestDocumentationAndDriverContracts:
    def test_docs_list_six_integration_refs(self):
        text = REPORT.read_text()
        for sha in (
            "4bd799b3", "3d87007d", "71713d83",
            "a0bf7600", "1184eb67", "d1961e43",
        ):
            assert sha in text, sha
        assert "all five" not in text
        assert "six integration refs" in text
        assert "6 audited / 0 modified" in text

    def test_docs_state_cancel_in_progress_scope_honestly(self):
        text = REPORT.read_text()
        assert "cancel-in-progress" in text
        assert "no stronger" in text or "does not guarantee" in text

    def test_workflow_comments_state_no_stronger_queue_guarantee(self):
        text = _workflow_text()
        assert "no stronger queue guarantee is claimed" in text

    def test_driver_uses_recorded_branch_not_synthesized_one(self):
        src = DRIVER.read_text()
        assert 'getattr(self, "branch_name", "")' in src
        assert 'self._fixture_prs(branch="")' in src
        assert "build_branch_name(" in src
        assert "_planned_branch()" in src

    def test_preflight_fail_closed_preconditions(self):
        src = DRIVER.read_text()
        preflight = src[src.index("def preflight("):src.index("def security(")]
        for needle in (
            "E2E_FIXTURE_REPOSITORY is not owner/repo",
            "E2E_FIXTURE_SEED_SHA is not 40-hex",
            "E2E_JWT_SECRET missing",
            "E2E_FIXTURE_GITHUB_TOKEN missing",
            "REMEDIATION_SANDBOX_IMAGE is not digest-pinned",
            "E2E_WORKSPACES_ROOT missing or not absolute",
            "fixture repo unreachable",
            "fixture seed content mismatch",
        ):
            assert needle in preflight, needle

    def test_seed_and_target_service_contract(self):
        driver = DRIVER.read_text()
        assert 'SERVICE_NAME = \\"checkout-service\\"' in driver or (
            'SERVICE_NAME = "checkout-service"' in driver
        )
        from incident_service.application.services import (
            remediation_validation_runner as runner,
        )
        assert runner.E2E_FIXTURE_PATCHED_SERVICE_NAME == "checkout-service-remediated"
        # fixture config must not alter the target: patched name applied
        # only by the runner's profile branch
        fixture_cfg = (
            PLATFORM / "tests" / "fixtures" / "e2e_fixture_repo" / "src"
            / "service_config.py"
        ).read_text()
        assert "checkout-service-remediated" not in fixture_cfg
        assert 'SERVICE_NAME = "checkout-service"' in fixture_cfg

    def test_all_29_execution_assertions_retained(self):
        src = DRIVER.read_text()
        for method in (
            "def sandbox_failure(",
            "def execution(",
            "def remote_checks(",
            "def db_cross_check(",
            "def replay(",
            "def finalize(",
        ):
            assert method in src, method
        assert src.count("st.check(") >= 29


# --------------------------------------------------------------------------
# §17 workflow static validation
# --------------------------------------------------------------------------

class TestWorkflowStaticValidation:
    def test_dispatch_only_and_no_pull_request_target(self):
        doc = _workflow_doc()
        on = doc.get(True, doc.get("on"))
        assert list(on) == ["workflow_dispatch"]
        assert "pull_request" not in on and "pull_request_target" not in on
        # no YAML key enables PR triggers anywhere (comments exempt)
        text = _workflow_text()
        assert not re.search(r"^\s*pull_request(_target)?\s*:", text, re.M)

    def test_permissions_and_environment(self):
        doc = _workflow_doc()
        assert doc["permissions"] == {"contents": "read"}
        job = _job(doc)
        assert job["environment"] == "e2e-staging"
        assert job.get("env", {}).get("E2E_FIXTURE_GITHUB_TOKEN") is None
        assert job.get("env", {}).get("E2E_JWT_SECRET") is None

    def test_actions_pinned_to_full_shas(self):
        for step in _steps(_workflow_doc()):
            uses = step.get("uses")
            if uses:
                assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", uses), uses

    def test_concurrency_cancel_in_progress_false(self):
        doc = _workflow_doc()
        conc = doc["concurrency"]
        assert conc["cancel-in-progress"] is False
        assert conc["group"] == "e2e-golden-path"

    def test_boot_and_driver_steps_receive_secrets_at_step_scope(self):
        doc = _workflow_doc()
        boot = _step(doc, "Boot compose stack")
        assert boot["env"]["JWT_SECRET"] == "${{ secrets.E2E_JWT_SECRET }}"
        assert boot["env"]["E2E_FIXTURE_GITHUB_TOKEN"] == (
            "${{ secrets.E2E_FIXTURE_GITHUB_TOKEN }}"
        )
        driver = _step(doc, "Execute golden path driver")
        assert driver["env"]["E2E_JWT_SECRET"] == "${{ secrets.E2E_JWT_SECRET }}"
        assert driver["env"]["E2E_FIXTURE_GITHUB_TOKEN"] == (
            "${{ secrets.E2E_FIXTURE_GITHUB_TOKEN }}"
        )

    def test_run_blocks_parse_with_bash_n(self):
        for step in _steps(_workflow_doc()):
            run = step.get("run")
            if not run:
                continue
            proc = subprocess.run(
                ["bash", "-n"], input=run, capture_output=True, text=True
            )
            assert proc.returncode == 0, (step.get("name"), proc.stderr[:300])

    def test_no_static_secret_values(self):
        text = _workflow_text()
        for match in re.findall(r"['\"](ghp_[A-Za-z0-9]{20,})['\"]", text):
            pytest.fail(f"literal token in workflow: {match[:8]}…")
        assert "ghs_" not in text

    def test_workflow_step_order_has_no_forward_dependencies(self):
        doc = _workflow_doc()
        names = [s.get("name", "") for s in _steps(doc)]
        required_order = [
            "Checkout",
            "Validate untrusted identifiers",
            "Install pinned toolchain",
            "Compose config validation",
            "Resolve immutable build inputs",
            "Configure registry (own network)",
            "Build immutable E2E images",
            "Publish workload image",
            "Create host-visible remediation workspace root",
            "Boot compose stack",
            "Prove host-visible workspace",
            "Prove fixture repo is private",
            "Execute golden path driver",
            "Collect evidence",
            "Secret scan backstop",
            "Upload E2E artifacts",
            "Cleanup (local + remote",
        ]
        indexes = []
        for prefix in required_order:
            match = next(
                (i for i, n in enumerate(names) if n.startswith(prefix)), None
            )
            assert match is not None, prefix
            indexes.append(match)
        assert indexes == sorted(indexes), list(zip(required_order, indexes))
