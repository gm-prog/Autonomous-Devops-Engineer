"""Phase 8.4.2-C/-D — focused regression tests for the audited defects.

Each class maps to one defect group (8.4.2-C: P0-1..P1-6, items 7-9;
8.4.2-D: committed image provenance, manifest provenance wiring, P2
credential hygiene). These tests are static/contractual where Docker/
kind/GitHub are required (those properties are proven live by the
dispatch-only workflow); they are behavioral where the code runs locally.
No test mocks the golden path itself — fakes appear only as in-process
stand-ins for parser/contract units (e.g. a fake `compose config` command
that echoes its environment, or a recorder for the workspace service's
git calls).
"""

from __future__ import annotations

import importlib
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
COMPOSE_BASE = PLATFORM / "docker-compose.yml"
PRODUCTION_DOCKERFILES = (
    PLATFORM / "api_gateway" / "Dockerfile",
    PLATFORM / "repo_service" / "Dockerfile",
    PLATFORM / "agent_service" / "Dockerfile",
    PLATFORM / "deployment_service" / "Dockerfile",
    PLATFORM / "monitoring_service" / "Dockerfile",
    PLATFORM / "incident_service" / "Dockerfile",
)
PINNED_FILE = PLATFORM / "e2e" / "pinned-images.txt"
DRIVER = PLATFORM / "e2e" / "golden_path.py"
WORKSPACE_SERVICE = (
    PLATFORM / "incident_service" / "application" / "services"
    / "remediation_workspace_service.py"
)
REPORT = REPO_ROOT / "docs" / "PHASE-8.4.2-E2E-GOLDEN-PATH-IMPLEMENTATION-REPORT.md"

#: the four manifest provenance variables the driver reads (§7.5).
PROVENANCE_VARS = (
    "E2E_REGISTRY_DIGEST",
    "E2E_KIND_NODE_DIGEST",
    "E2E_BASE_IMAGES",
    "E2E_BUILT_IMAGE_DIGESTS",
)
DRIVER_STEP = "Execute golden path driver"

sys.path.insert(0, str(PLATFORM))

from e2e import build_surfaces as BS  # noqa: E402
from e2e import helpers as H  # noqa: E402
from e2e import image_pins  # noqa: E402

#: §6.2/§10 — the single authoritative inventory lives in
#: ``e2e.build_surfaces``; these names are derived from it so a new build
#: surface cannot be covered here while being missed by the CI gate (or
#: the other way round).
E2E_BUILD_SURFACES = dict(BS.E2E_BUILD_SURFACES)
#: every distinct E2E Dockerfile, as absolute paths
DOCKERFILES = tuple(REPO_ROOT / path for path in BS.dockerfiles())


def _workflow_text() -> str:
    return WORKFLOW.read_text()


def _run_code(step: dict) -> str:
    """A step's shell body with comment-only lines removed.

    Contracts must be satisfied by executable shell, never by a comment
    that merely mentions a variable name.
    """
    return "\n".join(
        line
        for line in str(step.get("run", "")).splitlines()
        if not line.strip().startswith("#")
    )


def _github_env_exports(step: dict) -> set:
    """Variables a step demonstrably appends to ``$GITHUB_ENV``.

    Both recognised mechanisms are *verified*, not assumed:

    * literal ``echo "VAR=…"`` lines in a block redirected to
      ``$GITHUB_ENV`` (comments stripped first);
    * the committed-pin renderer — its real output is computed here from
      the committed pin file whenever the step redirects that output to a
      file and appends that same file to ``$GITHUB_ENV``.
    """
    code = _run_code(step)
    found: set = set()
    if '>> "$GITHUB_ENV"' in code:
        found |= set(re.findall(r'echo\s+"([A-Z][A-Z0-9_]*)=', code))
    match = re.search(r"--exports\s*\\?\s*>\s*(\S+)", code)
    if match:
        target = match.group(1)
        if re.search(rf"cat\s+{re.escape(target)}\s*>>\s*\"\$GITHUB_ENV\"", code):
            for line in image_pins.render(PINNED_FILE.read_text(), "--exports"):
                found.add(line.split("=", 1)[0])
    return found


def _step_index(doc: dict, prefix: str) -> int:
    for index, step in enumerate(_steps(doc)):
        if str(step.get("name", "")).startswith(prefix):
            return index
    raise AssertionError(f"step not found: {prefix}")


def _pin_records() -> list:
    return H.parse_pinned_images(PINNED_FILE.read_text())


def _complete_provenance() -> dict:
    """A manifest carrying realistic, non-secret provenance values."""
    return dict(
        source_sha="a" * 40,
        fixture_seed_sha="b" * 40,
        workspace_root="/tmp/ares-e2e-workspaces",
        registry_image_digest="registry@sha256:" + "1" * 64,
        kind_node_image_digest="kindest/node@sha256:" + "2" * 64,
        base_images="E2E_PYTHON_BASE_IMAGE=python@sha256:" + "3" * 64,
        built_image_digests=(
            "E2E_WORKLOAD_IMAGE=localhost:5001/ares-e2e-workload@sha256:" + "4" * 64
        ),
        sandbox_image_digest="localhost:5001/ares-e2e-sandbox@sha256:" + "5" * 64,
    )


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
        """Phase 8.4.2-E1: supported syntax, no default, no fallback."""
        for path in DOCKERFILES:
            text = path.read_text()
            assert "ARG BASE_IMAGE\n" in text, path
            assert re.search(r"^FROM \$\{BASE_IMAGE\}$", text, re.M), path
            for form in BS.FORBIDDEN_BASE_IMAGE_FORMS:
                assert form not in text, f"{path}: {form}"

    def test_compose_requires_digest_pinned_refs(self):
        text = COMPOSE_E2E.read_text()
        # one per E2E build surface (§6.2: seven services are actually built)
        assert text.count("${E2E_PYTHON_BASE_IMAGE:?") == len(E2E_BUILD_SURFACES)
        assert text.count("${E2E_POSTGRES_IMAGE:?") == 1
        assert text.count("${E2E_REDIS_IMAGE:?") == 1
        assert text.count("${E2E_QDRANT_IMAGE:?") == 1
        assert ":-postgres" not in text and ":-redis" not in text

    def test_pinned_file_rejects_non_digest_pins(self):
        """Every committed pin is a real sha256 digest — no sentinel."""
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
            assert pin != "UNRESOLVED", line
            assert re.fullmatch(r"sha256:[0-9a-f]{64}", pin), pin
            seen_keys += 1
        assert seen_keys == 6

    def test_workflow_consumes_the_committed_pins_only(self):
        step = _step(_workflow_doc(), "Load immutable image pins")
        run = _run_code(step)
        assert "pinned-images.txt" in step["run"]
        assert "e2e.image_pins" in run and "--refs" in run
        assert 'echo "${KEY}=${REF}" >> "$GITHUB_ENV"' in run
        # no image source name appears anywhere in the workflow text
        pinned_names = [
            record["name"]
            for record in H.parse_pinned_images(PINNED_FILE.read_text())
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
            "Load immutable image pins",
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


# --------------------------------------------------------------------------
# Phase 8.4.2-D §5/§10.1-10.2: committed pins are genuinely immutable
# --------------------------------------------------------------------------

class TestCommittedImmutablePins:
    """The pin file is the single source of external image identity."""

    def test_sentinel_is_rejected_by_the_parser(self):
        text = "python:3.11-slim UNRESOLVED E2E_PYTHON_BASE_IMAGE\n"
        with pytest.raises(ValueError, match="not an immutable sha256"):
            H.parse_pinned_images(text)

    def test_valid_digest_is_accepted(self):
        records = _pin_records()
        assert len(records) == 6
        for record in records:
            assert re.fullmatch(r"sha256:[0-9a-f]{64}", record["digest"])
            assert H.validate_digest_ref(record["ref"]), record

    @pytest.mark.parametrize(
        "pin",
        [
            "UNRESOLVED",
            "latest",
            "sha256:" + "a" * 63,
            "sha256:" + "A" * 64,
            "sha256:" + "g" * 64,
            "sha1:" + "a" * 40,
            "@sha256:" + "a" * 64,
        ],
        ids=lambda p: p[:18],
    )
    def test_malformed_pins_fail_closed(self, pin):
        with pytest.raises(ValueError):
            H.parse_pinned_images(f"python:3.11-slim {pin} E2E_PYTHON_BASE_IMAGE\n")

    def test_missing_pin_column_fails_closed(self):
        with pytest.raises(ValueError, match="expected"):
            H.parse_pinned_images("python:3.11-slim E2E_PYTHON_BASE_IMAGE\n")

    def test_bad_env_key_fails_closed(self):
        digest = "sha256:" + "a" * 64
        with pytest.raises(ValueError, match="invalid env key"):
            H.parse_pinned_images(f"python:3.11-slim {digest} lower_case\n")

    def test_duplicate_key_and_duplicate_source_fail_closed(self):
        digest = "sha256:" + "a" * 64
        dup_key = (
            f"python:3.11-slim {digest} E2E_PYTHON_BASE_IMAGE\n"
            f"redis:7-alpine {digest} E2E_PYTHON_BASE_IMAGE\n"
        )
        with pytest.raises(ValueError, match="duplicate env key"):
            H.parse_pinned_images(dup_key)
        dup_name = (
            f"python:3.11-slim {digest} E2E_PYTHON_BASE_IMAGE\n"
            f"python:3.11-slim {digest} E2E_POSTGRES_IMAGE\n"
        )
        with pytest.raises(ValueError, match="duplicate source image"):
            H.parse_pinned_images(dup_name)

    def test_exactly_the_six_expected_keys_are_required(self):
        assert sorted(r["key"] for r in _pin_records()) == sorted(
            H.PINNED_IMAGE_KEYS
        )
        assert len(H.PINNED_IMAGE_KEYS) == 6
        short = "\n".join(
            line
            for line in PINNED_FILE.read_text().splitlines()
            if not line.startswith("registry:")
        )
        with pytest.raises(ValueError, match="must define exactly"):
            H.parse_pinned_images(short)
        extra = PINNED_FILE.read_text() + (
            "busybox:1.36 sha256:" + "a" * 64 + " EXTRA_IMAGE\n"
        )
        with pytest.raises(ValueError, match="must define exactly"):
            H.parse_pinned_images(extra)

    def test_every_committed_entry_matches_the_grammar(self):
        for record in _pin_records():
            assert re.fullmatch(
                r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
                r":[A-Za-z0-9][A-Za-z0-9._-]*",
                record["name"],
            ), record["name"]
            assert re.fullmatch(r"sha256:[0-9a-f]{64}", record["digest"])
            assert re.fullmatch(r"[A-Z][A-Z0-9_]*", record["key"])
            assert record["ref"].endswith("@" + record["digest"])
            assert ":" not in record["ref"].split("@")[0]

    def test_sentinel_token_is_gone_from_the_repository_surface(self):
        assert "UNRESOLVED" not in PINNED_FILE.read_text()
        assert "UNRESOLVED" not in _workflow_text()
        assert "UNRESOLVED" not in (PLATFORM / "e2e" / "image_pins.py").read_text()

    def test_canonical_ref_drops_the_tag_and_keeps_the_digest(self):
        digest = "sha256:" + "c" * 64
        assert H.canonical_digest_ref("python:3.11-slim", digest) == (
            f"python@{digest}"
        )
        assert H.canonical_digest_ref("qdrant/qdrant:v1.12.4", digest) == (
            f"qdrant/qdrant@{digest}"
        )
        with pytest.raises(ValueError):
            H.canonical_digest_ref("python:3.11-slim", "UNRESOLVED")

    def test_renderer_output_is_deterministic_and_digest_only(self):
        text = PINNED_FILE.read_text()
        refs = image_pins.render(text, "--refs")
        assert refs == image_pins.render(text, "--refs")
        assert len(refs) == 6
        for line in refs:
            key, ref = line.split()
            assert key in H.PINNED_IMAGE_KEYS
            assert H.validate_digest_ref(ref), line
        exports = image_pins.render(text, "--exports")
        assert [line.split("=", 1)[0] for line in exports] == [
            "E2E_BASE_IMAGES",
            "E2E_KIND_NODE_DIGEST",
            "E2E_REGISTRY_DIGEST",
        ]

    def test_cli_exits_nonzero_on_a_sentinel_pin(self, tmp_path, capsys):
        bad = tmp_path / "pins.txt"
        bad.write_text("python:3.11-slim UNRESOLVED E2E_PYTHON_BASE_IMAGE\n")
        assert image_pins.main([str(bad), "--refs"]) == 1
        captured = capsys.readouterr()
        assert captured.out.strip() == ""
        assert "::error::" in captured.err
        good = tmp_path / "good.txt"
        good.write_text(PINNED_FILE.read_text())
        assert image_pins.main([str(good), "--refs"]) == 0
        assert image_pins.main([str(good)]) == 2


# --------------------------------------------------------------------------
# Phase 8.4.2-D §10.3/§10.4/§10.7/§10.8: workflow provenance wiring
# --------------------------------------------------------------------------

class TestWorkflowProvenanceWiring:
    def test_no_dispatch_time_mutable_tag_resolution(self):
        doc = _workflow_doc()
        code = "\n".join(_run_code(step) for step in _steps(doc))
        pulls = re.findall(r"docker\s+(?:image\s+)?pull\s+(?:-\S+\s+)*(\S+)", code)
        assert pulls, "the workflow must still pull its inputs"
        for target in pulls:
            assert target in ('"$REF"', '"${REF}"'), target
        # the old sentinel branch and tag→digest lookup must not come back
        assert not re.search(r'\$\{?PIN\}?"?\s*=\s*"?UNRESOLVED', code)
        assert not re.search(r"REF=.*RepoDigests", code)
        assert not re.search(r"docker\s+(?:image\s+)?pull[^\n]*\$\{?NAME\}?", code)
        assert "UNRESOLVED" not in _workflow_text()

    def test_pins_step_pulls_and_inspects_by_digest_only(self):
        code = _run_code(_step(_workflow_doc(), "Load immutable image pins"))
        assert 'docker pull -q "$REF"' in code
        assert 'docker image inspect "$REF"' in code
        assert "RepoDigests" in code and 'grep -Fxq "$REF"' in code
        # fail-closed: a non-digest reference can never reach docker
        assert "@sha256:[0-9a-f]{64}$'" in code
        assert "e2e.image_pins" in code

    def test_all_four_provenance_vars_are_exported_before_the_driver(self):
        doc = _workflow_doc()
        steps = _steps(doc)
        driver_index = _step_index(doc, DRIVER_STEP)
        for var in PROVENANCE_VARS:
            producers = [
                index
                for index, step in enumerate(steps)
                if var in _github_env_exports(step)
            ]
            assert producers, f"{var} is never exported to $GITHUB_ENV"
            assert max(producers) < driver_index, (var, producers, driver_index)

    def test_provenance_vars_are_not_satisfied_by_comments(self):
        doc = _workflow_doc()
        for var in PROVENANCE_VARS:
            commented = [
                step.get("name")
                for step in _steps(doc)
                if re.search(rf"^\s*#.*{var}", step.get("run", "") or "", re.M)
                and var not in _github_env_exports(step)
            ]
            assert not commented or any(
                var in _github_env_exports(step) for step in _steps(doc)
            ), (var, commented)

    def test_built_image_digests_come_from_post_push_inspection(self):
        code = _run_code(_step(_workflow_doc(), "Build immutable E2E images"))
        assert code.index("docker push") < code.index("RepoDigests")
        assert 'WORKLOAD_DIGEST="$(docker inspect' in code
        assert 'SANDBOX_DIGEST="$(docker inspect' in code
        assert "{{index .RepoDigests 0}}" in code
        built = re.search(r'BUILT="([^"]+)"', code)
        assert built, "E2E_BUILT_IMAGE_DIGESTS must be assembled from variables"
        value = built.group(1)
        assert "${WORKLOAD_DIGEST}" in value and "${SANDBOX_DIGEST}" in value
        assert ":${E2E_SOURCE_SHA}" not in value, "mutable tag in built provenance"
        assert 'echo "E2E_BUILT_IMAGE_DIGESTS=${BUILT}"' in code
        assert "built image is not digest-addressed" in code
        assert "manifest provenance not exported" in code

    def test_registry_and_kind_digests_map_to_the_committed_pins(self):
        doc = _workflow_doc()
        registry_step = _run_code(_step(doc, "Configure registry"))
        assert '"${REGISTRY_IMAGE}"' in registry_step
        assert '--image "$NODE_IMAGE"' in registry_step
        by_key = {record["key"]: record["ref"] for record in _pin_records()}
        exports = H.pin_provenance_exports(_pin_records())
        assert exports["E2E_REGISTRY_DIGEST"] == by_key["REGISTRY_IMAGE"]
        assert exports["E2E_KIND_NODE_DIGEST"] == by_key["NODE_IMAGE"]
        assert H.validate_digest_ref(exports["E2E_REGISTRY_DIGEST"])
        assert H.validate_digest_ref(exports["E2E_KIND_NODE_DIGEST"])

    def test_base_images_scalar_is_deterministic_and_parsable(self):
        exports = H.pin_provenance_exports(_pin_records())
        scalar = exports["E2E_BASE_IMAGES"]
        assert isinstance(scalar, str) and ";" in scalar
        mapping = H.parse_scalar_mapping(scalar)
        assert sorted(mapping) == sorted(H.BASE_IMAGE_KEYS)
        for key, ref in mapping.items():
            assert H.validate_digest_ref(ref), (key, ref)
        assert scalar == H.pin_provenance_exports(_pin_records())["E2E_BASE_IMAGES"]
        with pytest.raises(ValueError):
            H.format_scalar_mapping({"KEY": "has;separator"})
        with pytest.raises(ValueError):
            H.format_scalar_mapping({"KEY": ""})

    def test_provenance_artifacts_are_recorded_without_secrets(self):
        doc = _workflow_doc()
        pins = _run_code(_step(doc, "Load immutable image pins"))
        build = _run_code(_step(doc, "Build immutable E2E images"))
        assert "image-provenance-inputs.txt" in pins
        assert "manifest-provenance-env.txt" in pins
        assert "image-provenance-built.txt" in build
        for step in (_step(doc, "Load immutable image pins"),
                     _step(doc, "Build immutable E2E images")):
            assert "secrets." not in str(step.get("run", ""))
            assert step.get("env") is None

    def test_driver_step_still_runs_after_every_provenance_producer(self):
        doc = _workflow_doc()
        assert _step_index(doc, "Load immutable image pins") < _step_index(
            doc, "Build immutable E2E images"
        ) < _step_index(doc, DRIVER_STEP)


# --------------------------------------------------------------------------
# Phase 8.4.2-D §6.2: every E2E build surface is digest-controlled
# --------------------------------------------------------------------------

class TestE2EBuildSurfaces:
    def test_every_built_service_uses_an_e2e_dockerfile(self):
        base = yaml.safe_load(COMPOSE_BASE.read_text())
        override = yaml.safe_load(COMPOSE_E2E.read_text())
        built = {
            name
            for name, spec in base["services"].items()
            if isinstance(spec, dict) and spec.get("build")
        }
        assert built == set(E2E_BUILD_SURFACES), built
        for service, dockerfile in E2E_BUILD_SURFACES.items():
            spec = override["services"][service]["build"]
            assert spec["dockerfile"] == dockerfile, service
            assert spec["context"] == "./devops-ai-platform", service
            assert spec["args"]["BASE_IMAGE"].startswith("${E2E_PYTHON_BASE_IMAGE:?")

    def test_every_e2e_dockerfile_is_fail_closed(self):
        seen = set()
        for dockerfile in set(E2E_BUILD_SURFACES.values()):
            path = PLATFORM / dockerfile.lstrip("./")
            text = path.read_text()
            assert "ARG BASE_IMAGE\n" in text, path
            assert re.search(r"^FROM \$\{BASE_IMAGE\}$", text, re.M), path
            assert not re.search(r"^FROM\s+[a-z0-9]+:", text, re.M), path
            seen.add(path)
        assert seen <= set(DOCKERFILES)
        for path in DOCKERFILES:
            text = path.read_text()
            assert "ARG BASE_IMAGE\n" in text, path
            assert re.search(r"^FROM \$\{BASE_IMAGE\}$", text, re.M), path

    def test_production_dockerfiles_stay_tag_based_and_unbuilt_by_e2e(self):
        override = yaml.safe_load(COMPOSE_E2E.read_text())
        used = {
            spec["build"]["dockerfile"]
            for spec in override["services"].values()
            if isinstance(spec, dict) and spec.get("build")
        }
        for path in PRODUCTION_DOCKERFILES:
            text = path.read_text()
            assert re.search(r"^FROM\s+python:3\.11-slim\s*$", text, re.M), path
            assert "@sha256:" not in text, path
            relative = "./" + str(path.relative_to(PLATFORM))
            assert relative not in used, f"{relative} is built by the E2E stack"

    def test_no_duplicate_service_keys_in_the_override(self):
        names = re.findall(r"^  ([a-z0-9-]+):\s*$", COMPOSE_E2E.read_text(), re.M)
        assert len(names) == len(set(names)), names


# --------------------------------------------------------------------------
# Phase 8.4.2-D §7/§9/§10.5/§10.6/§10.9: manifest provenance completeness
# --------------------------------------------------------------------------

class TestManifestProvenance:
    def test_driver_reads_all_four_variables(self):
        src = DRIVER.read_text()
        for field, env in (
            ("registry_image_digest", "E2E_REGISTRY_DIGEST"),
            ("kind_node_image_digest", "E2E_KIND_NODE_DIGEST"),
            ("base_images", "E2E_BASE_IMAGES"),
            ("built_image_digests", "E2E_BUILT_IMAGE_DIGESTS"),
        ):
            assert re.search(
                rf'{field}=os\.environ\.get\("{env}"', src
            ), field
        assert "finalize_execution_manifest" in src

    def test_harness_manifest_is_populated_from_the_environment(
        self, tmp_path, monkeypatch
    ):
        """Offline proof: no Docker, no GitHub, no secrets required."""
        values = {
            "E2E_REGISTRY_DIGEST": "registry@sha256:" + "1" * 64,
            "E2E_KIND_NODE_DIGEST": "kindest/node@sha256:" + "2" * 64,
            "E2E_BASE_IMAGES": "E2E_PYTHON_BASE_IMAGE=python@sha256:" + "3" * 64,
            "E2E_BUILT_IMAGE_DIGESTS": (
                "E2E_WORKLOAD_IMAGE=localhost:5001/ares-e2e-workload@sha256:"
                + "4" * 64
            ),
            "E2E_SANDBOX_DIGEST": "localhost:5001/ares-e2e-sandbox@sha256:" + "5" * 64,
            "E2E_SOURCE_SHA": "a" * 40,
            "E2E_FIXTURE_SEED_SHA": "b" * 40,
            "E2E_WORKSPACES_ROOT": str(tmp_path / "workspaces"),
            "E2E_ARTIFACT_DIR": str(tmp_path / "artifacts"),
            "E2E_JWT_SECRET": "unit-test-secret-not-a-credential",
            "E2E_FIXTURE_REPOSITORY": "gm-prog/ares-e2e-fixture",
        }
        for key, value in values.items():
            monkeypatch.setenv(key, value)
        driver = importlib.reload(importlib.import_module("e2e.golden_path"))
        try:
            manifest = driver.Harness().manifest
            assert manifest["registry_image_digest"] == values["E2E_REGISTRY_DIGEST"]
            assert manifest["kind_node_image_digest"] == values["E2E_KIND_NODE_DIGEST"]
            assert manifest["base_images"] == values["E2E_BASE_IMAGES"]
            assert manifest["built_image_digests"] == (
                values["E2E_BUILT_IMAGE_DIGESTS"]
            )
            assert manifest["sandbox_image_digest"] == values["E2E_SANDBOX_DIGEST"]
            assert manifest["source_sha"] == values["E2E_SOURCE_SHA"]
            assert manifest["fixture_seed_sha"] == values["E2E_FIXTURE_SEED_SHA"]
            assert manifest["workspace_root"] == values["E2E_WORKSPACES_ROOT"]
            assert H.validate_manifest(manifest) == []
            assert H.missing_execution_provenance(manifest) == []
            H.finalize_execution_manifest(manifest, H.PASS)
            assert manifest["result"] == H.PASS
            assert "provenance_rejection" not in manifest
        finally:
            monkeypatch.undo()
            importlib.reload(importlib.import_module("e2e.golden_path"))

    def test_pass_with_complete_provenance_is_accepted(self):
        manifest = H.new_manifest(**_complete_provenance())
        H.finalize_execution_manifest(manifest, H.PASS)
        assert manifest["result"] == H.PASS
        assert H.validate_manifest(manifest) == []

    @pytest.mark.parametrize("field", H.REQUIRED_EXECUTION_PROVENANCE)
    def test_pass_with_any_empty_required_field_is_rejected(self, field):
        fields = _complete_provenance()
        fields[field] = ""
        manifest = H.new_manifest(**fields)
        assert H.missing_execution_provenance(manifest) == [field]
        H.finalize_execution_manifest(manifest, H.PASS)
        assert manifest["result"] == H.FAIL
        assert field in manifest["provenance_rejection"]
        assert H.validate_manifest(manifest) == []

    def test_empty_four_provenance_vars_cannot_claim_success(self):
        fields = _complete_provenance()
        for field in (
            "registry_image_digest",
            "kind_node_image_digest",
            "base_images",
            "built_image_digests",
        ):
            fields[field] = ""
        manifest = H.new_manifest(**fields)
        H.finalize_execution_manifest(manifest, H.PASS)
        assert manifest["result"] == H.FAIL
        rejection = manifest["provenance_rejection"]
        for field in (
            "registry_image_digest",
            "kind_node_image_digest",
            "base_images",
            "built_image_digests",
        ):
            assert field in rejection

    def test_whitespace_only_provenance_is_not_accepted(self):
        fields = _complete_provenance()
        fields["registry_image_digest"] = "   "
        manifest = H.new_manifest(**fields)
        H.finalize_execution_manifest(manifest, H.PASS)
        assert manifest["result"] == H.FAIL

    def test_preflight_manifests_stay_representable(self):
        """NOT_VERIFIED / BLOCKED runs legitimately have no provenance."""
        manifest = H.new_manifest(workflow_run_id="local")
        H.finalize_manifest(manifest, H.NOT_VERIFIED)
        assert manifest["result"] == H.NOT_VERIFIED
        blocked = H.new_manifest(workflow_run_id="local")
        H.finalize_execution_manifest(blocked, H.BLOCKED)
        assert blocked["result"] == H.BLOCKED
        assert "provenance_rejection" not in blocked
        failed = H.new_manifest(workflow_run_id="local")
        H.finalize_execution_manifest(failed, H.FAIL)
        assert failed["result"] == H.FAIL

    def test_manifest_schema_still_scalar_only(self):
        manifest = H.new_manifest(**_complete_provenance())
        H.finalize_execution_manifest(manifest, H.PASS)
        for key, value in manifest.items():
            assert re.fullmatch(r"[a-z_]+", key), key
            assert isinstance(value, (str, int, float, bool)), key

    def test_driver_exit_code_follows_the_finalized_manifest(self):
        src = DRIVER.read_text()
        assert "H.finalize_execution_manifest(self.manifest, overall)" in src
        assert 'overall = str(self.manifest["result"])' in src
        assert src.index("H.finalize_execution_manifest(self.manifest, overall)") < (
            src.index('return overall, 0 if overall == H.PASS else 1')
        )


# --------------------------------------------------------------------------
# Phase 8.4.2-D P2: raw Git credential is not inherited by child processes
# --------------------------------------------------------------------------

class TestCredentialHygiene:
    TOKEN = "ghp_UnitTestOnly0000000000000000000000"

    def _service(self, tmp_path, monkeypatch):
        from incident_service.application.services.remediation_workspace_service import (
            RemediationWorkspaceService,
        )
        monkeypatch.setenv("GITHUB_OAUTH_TOKEN", self.TOKEN)
        monkeypatch.setenv("HOME", str(tmp_path))
        return RemediationWorkspaceService(workspace_root=str(tmp_path))

    def test_auth_free_git_call_gets_no_raw_token(self, tmp_path, monkeypatch):
        import incident_service.application.services.remediation_workspace_service as mod

        service = self._service(tmp_path, monkeypatch)
        captured = {}

        def fake_run(args, **kwargs):
            captured["env"] = dict(kwargs.get("env") or {})

            class _R:
                stdout = ""
                returncode = 0

            return _R()

        monkeypatch.setattr(mod.subprocess, "run", fake_run)
        service._run_git(["git", "rev-parse", "HEAD"], cwd=tmp_path)
        env = captured["env"]
        assert "GITHUB_OAUTH_TOKEN" not in env
        assert all(self.TOKEN not in value for value in env.values())
        assert env["GIT_TERMINAL_PROMPT"] == "0"
        assert "GIT_CONFIG_VALUE_0" not in env

    def test_auth_required_call_gets_only_the_header_env(self, tmp_path, monkeypatch):
        import incident_service.application.services.remediation_workspace_service as mod

        service = self._service(tmp_path, monkeypatch)
        captured = {}

        def fake_run(args, **kwargs):
            captured["env"] = dict(kwargs.get("env") or {})

            class _R:
                stdout = ""
                returncode = 0

            return _R()

        monkeypatch.setattr(mod.subprocess, "run", fake_run)
        service._run_git(
            ["git", "fetch", "--no-tags", "origin", "a" * 40],
            cwd=tmp_path,
            extra_env={
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "http.extraHeader",
                "GIT_CONFIG_VALUE_0": f"Authorization: Bearer {self.TOKEN}",
            },
        )
        env = captured["env"]
        assert "GITHUB_OAUTH_TOKEN" not in env
        assert env["GIT_CONFIG_VALUE_0"] == f"Authorization: Bearer {self.TOKEN}"
        assert env["GIT_CONFIG_KEY_0"] == "http.extraHeader"

    def test_real_child_git_process_cannot_see_the_token(self, tmp_path, monkeypatch):
        """Live process proof using the real `git` binary (no network)."""
        service = self._service(tmp_path, monkeypatch)
        header = f"Authorization: Bearer {self.TOKEN}"
        authenticated = service._run_git(
            ["git", "config", "--get", "http.extraHeader"],
            extra_env={
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "http.extraHeader",
                "GIT_CONFIG_VALUE_0": header,
            },
        )
        assert authenticated.stdout.strip() == header
        try:
            plain = service._run_git(["git", "config", "--get", "http.extraHeader"])
        except subprocess.CalledProcessError:
            pass  # no header configured at all — the intended outcome
        else:
            assert self.TOKEN not in plain.stdout

    def test_service_source_scrubs_the_token_for_every_child(self):
        src = WORKSPACE_SERVICE.read_text()
        block = src[src.index("def _run_git"):]
        assert '"GITHUB_OAUTH_TOKEN",' in block.split("env[\"GIT_TERMINAL_PROMPT\"]")[0]
        assert "x-access-token" not in src
        assert "GIT_ASKPASS" not in src


# --------------------------------------------------------------------------
# Phase 8.4.2-D §16: deterministic provenance audit (no Docker, no GitHub)
# --------------------------------------------------------------------------

class TestProvenanceAudit:
    """Nine mechanical checks an auditor can run offline."""

    def test_1_pin_file_has_zero_unresolved_entries(self):
        assert "UNRESOLVED" not in PINNED_FILE.read_text()

    def test_2_every_pin_is_a_sha256_digest(self):
        for record in _pin_records():
            assert re.fullmatch(r"sha256:[0-9a-f]{64}", record["digest"])

    def test_3_every_key_is_valid_and_expected(self):
        keys = [record["key"] for record in _pin_records()]
        assert sorted(keys) == sorted(H.PINNED_IMAGE_KEYS)
        for key in keys:
            assert re.fullmatch(r"[A-Z][A-Z0-9_]*", key)

    def test_4_workflow_has_no_mutable_tag_resolution_path(self):
        code = "\n".join(_run_code(step) for step in _steps(_workflow_doc()))
        assert "UNRESOLVED" not in code
        for target in re.findall(
            r"docker\s+(?:image\s+)?pull\s+(?:-\S+\s+)*(\S+)", code
        ):
            assert target in ('"$REF"', '"${REF}"'), target

    def test_5_workflow_exports_all_four_manifest_provenance_variables(self):
        exported = set()
        for step in _steps(_workflow_doc()):
            exported |= _github_env_exports(step)
        assert set(PROVENANCE_VARS) <= exported, sorted(exported)

    def test_6_exports_occur_before_driver_execution(self):
        doc = _workflow_doc()
        driver_index = _step_index(doc, DRIVER_STEP)
        for index, step in enumerate(_steps(doc)):
            if _github_env_exports(step) & set(PROVENANCE_VARS):
                assert index < driver_index, step.get("name")

    def test_7_driver_maps_all_four_variables_into_the_manifest(self):
        src = DRIVER.read_text()
        for field, env in (
            ("registry_image_digest", "E2E_REGISTRY_DIGEST"),
            ("kind_node_image_digest", "E2E_KIND_NODE_DIGEST"),
            ("base_images", "E2E_BASE_IMAGES"),
            ("built_image_digests", "E2E_BUILT_IMAGE_DIGESTS"),
        ):
            assert f'{field}=os.environ.get("{env}", "")' in src

    def test_8_successful_finalization_rejects_missing_provenance(self):
        manifest = H.new_manifest(**{**_complete_provenance(),
                                     "registry_image_digest": ""})
        H.finalize_execution_manifest(manifest, H.PASS)
        assert manifest["result"] == H.FAIL

    def test_9_documentation_does_not_claim_live_e2e_pass(self):
        text = REPORT.read_text()
        assert "LIVE E2E: NOT VERIFIED" in text
        assert not re.search(r"LIVE E2E:\s*PASS", text)
        assert not re.search(r"golden[- ]path(?: workflow)?[^.\n]{0,40}executed "
                             r"successfully", text, re.I)


# --------------------------------------------------------------------------
# Phase 8.4.2-E1: Dockerfile build contract (supported syntax + CI gate)
# --------------------------------------------------------------------------

CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
#: the exact historical form this phase closed — kept as a fixture so the
#: regression is expressed as a contract, never committed to a Dockerfile
HISTORICAL_DEFECT = "FROM ${BASE_IMAGE:?BASE_IMAGE must be a name@sha256:<64hex> reference}"


def _ci_gate_step():
    doc = yaml.safe_load(CI_WORKFLOW.read_text())
    for step in doc["jobs"]["compose"]["steps"]:
        if "BuildKit" in (step.get("name") or ""):
            return step
    raise AssertionError("ci.yml has no BuildKit Dockerfile contract step")


class TestDockerfileBuildContract:
    """§11/§12 — supported Dockerfile syntax, proven statically here and
    by real BuildKit in CI."""

    def test_authoritative_inventory_is_the_only_list(self):
        assert len(BS.E2E_DOCKERFILES) == 8
        assert len(set(BS.dockerfiles())) == 8
        for dockerfile, context in BS.E2E_DOCKERFILES:
            assert (REPO_ROOT / dockerfile).is_file(), dockerfile
            assert (REPO_ROOT / context).is_dir(), context
        # the six compose surfaces resolve into the same inventory
        for relative in set(BS.E2E_BUILD_SURFACES.values()):
            path = f"{BS.PLATFORM_DIR}/{relative.lstrip('./')}"
            assert path in BS.dockerfiles(), path

    @pytest.mark.parametrize("dockerfile", BS.dockerfiles())
    def test_every_e2e_dockerfile_satisfies_the_static_contract(self, dockerfile):
        text = (REPO_ROOT / dockerfile).read_text()
        assert BS.validate_dockerfile_text(text) == []

    @pytest.mark.parametrize("dockerfile", BS.dockerfiles())
    def test_supported_arg_from_pairing(self, dockerfile):
        text = (REPO_ROOT / dockerfile).read_text()
        assert "\nARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n" in text, dockerfile

    @pytest.mark.parametrize("dockerfile", BS.dockerfiles())
    def test_no_unsupported_or_mutable_base_image_form(self, dockerfile):
        text = (REPO_ROOT / dockerfile).read_text()
        for form in BS.FORBIDDEN_BASE_IMAGE_FORMS:
            assert form not in text, f"{dockerfile}: {form}"
        # the only FROM is the digest-fed one — no tag, no second stage base
        froms = re.findall(r"^FROM\s+(.+)$", text, re.M)
        assert froms == ["${BASE_IMAGE}"], f"{dockerfile}: {froms}"

    @pytest.mark.parametrize("dockerfile", BS.dockerfiles())
    def test_parser_directives_are_pinned_and_first(self, dockerfile):
        lines = (REPO_ROOT / dockerfile).read_text().splitlines()
        assert lines[0] == BS.SYNTAX_DIRECTIVE, dockerfile
        assert lines[1] == BS.CHECK_DIRECTIVE, dockerfile
        # a floating frontend would reintroduce a mutable build input
        assert re.fullmatch(
            r"# syntax=docker/dockerfile:1@sha256:[0-9a-f]{64}", lines[0]
        ), dockerfile
        # only the one rule that contradicts "no default" may be skipped
        assert "skip=all" not in lines[1]
        assert lines[1].startswith("# check=skip=InvalidDefaultArgInFrom;error=true")

    def test_one_frontend_digest_across_every_surface(self):
        digests = {
            (REPO_ROOT / path).read_text().splitlines()[0]
            for path in BS.dockerfiles()
        }
        assert digests == {BS.SYNTAX_DIRECTIVE}

    def test_compose_keeps_required_value_interpolation(self):
        """`:?` is valid in Compose — that is where the requirement lives."""
        override = yaml.safe_load(COMPOSE_E2E.read_text())
        for service in BS.E2E_BUILD_SURFACES:
            arg = override["services"][service]["build"]["args"]["BASE_IMAGE"]
            assert arg.startswith("${E2E_PYTHON_BASE_IMAGE:?"), service
        assert COMPOSE_E2E.read_text().count("${E2E_PYTHON_BASE_IMAGE:?") == len(
            BS.E2E_BUILD_SURFACES
        )

    def test_the_two_languages_are_not_mixed_up(self):
        """Compose keeps `:?`; no Dockerfile may carry it."""
        assert "${E2E_PYTHON_BASE_IMAGE:?" in COMPOSE_E2E.read_text()
        for path in BS.dockerfiles():
            assert ":?" not in (REPO_ROOT / path).read_text(), path

    # --- §12 regression against the exact historical implementation ------

    def test_historical_defective_form_is_rejected_by_the_contract(self):
        text = "\n".join(BS.REQUIRED_HEADER) + f"\nARG BASE_IMAGE\n{HISTORICAL_DEFECT}\n"
        problems = BS.validate_dockerfile_text(text)
        assert problems, "the pre-E1 Dockerfile form must not be acceptable"
        assert any("${BASE_IMAGE:?" in p for p in problems)

    @pytest.mark.parametrize(
        "mutation",
        [
            "ARG BASE_IMAGE\nFROM ${BASE_IMAGE?required}\n",
            "ARG BASE_IMAGE=python:3.11-slim\nFROM ${BASE_IMAGE}\n",
            "ARG BASE_IMAGE\nFROM ${BASE_IMAGE:-python:3.11-slim}\n",
            "FROM python:3.11-slim\n",
            "ARG BASE_IMAGE\nFROM python@sha256:" + "0" * 64 + "\n",
        ],
        ids=["bare-question", "mutable-default", "tag-fallback", "tag-from", "second-base"],
    )
    def test_mutable_or_unsupported_mutations_are_rejected(self, mutation):
        text = "\n".join(BS.REQUIRED_HEADER) + "\n" + mutation
        assert BS.validate_dockerfile_text(text), mutation

    def test_corrected_form_is_accepted(self):
        text = "\n".join(BS.REQUIRED_HEADER) + "\nARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n"
        assert BS.validate_dockerfile_text(text) == []

    def test_no_dockerfile_still_carries_the_historical_form(self):
        for path in (*BS.dockerfiles(), "docker-compose.e2e.yml"):
            text = (REPO_ROOT / path).read_text()
            assert HISTORICAL_DEFECT not in text, path
        assert HISTORICAL_DEFECT not in WORKFLOW.read_text()


class TestCIDockerfileGate:
    """§9 — ordinary CI must execute the real BuildKit contract."""

    def test_ci_runs_on_push_and_pull_request(self):
        doc = yaml.safe_load(CI_WORKFLOW.read_text())
        triggers = doc[True] if True in doc else doc["on"]
        assert "pull_request" in triggers
        assert "arena/**" in triggers["push"]["branches"]
        assert "main" in triggers["push"]["branches"]

    def test_gate_lives_in_the_compose_job_and_uses_real_buildkit(self):
        run = _ci_gate_step()["run"]
        assert "docker buildx build --check" in run
        # positive: the committed digest is passed as the build argument
        assert '--build-arg BASE_IMAGE="$BASE" -f "$DF" "$CTX"' in run
        # negative: the same file is checked with no build argument
        assert 'docker buildx build --check -f "$DF" "$CTX"' in run
        assert "a default or fallback exists" in run

    def test_gate_consumes_the_committed_pin_not_a_tag(self):
        run = _ci_gate_step()["run"]
        assert "e2e.image_pins" in run and "pinned-images.txt" in run
        assert 'E2E_PYTHON_BASE_IMAGE' in run
        assert "^[A-Za-z0-9][A-Za-z0-9._/-]*@sha256:[0-9a-f]{64}$" in run
        assert "python:3.11-slim" not in run

    def test_gate_iterates_the_authoritative_inventory(self):
        run = _ci_gate_step()["run"]
        assert "e2e.build_surfaces --plan" in run
        assert "e2e.build_surfaces --validate" in run
        # every surface must be reached, and the count is asserted in-job
        assert f'[ "$CHECKED" -eq {len(BS.E2E_DOCKERFILES)} ]' in run

    def test_gate_runs_a_live_mutation_probe(self):
        run = _ci_gate_step()["run"]
        assert "mutation probe" in run
        assert "FROM ${BASE_IMAGE:?" in run
        assert "regression gate assumption broken" in run

    def test_gate_is_a_gate_not_a_warning(self):
        step = _ci_gate_step()
        assert step.get("continue-on-error") in (None, False)
        assert "set -euo pipefail" in step["run"]
        assert '[ "$FAILURES" -eq 0 ] || exit 1' in step["run"]

    def test_gate_needs_no_credentials(self):
        doc = yaml.safe_load(CI_WORKFLOW.read_text())
        compose_job = doc["jobs"]["compose"]
        text = yaml.safe_dump(compose_job)
        for forbidden in (
            "secrets.",
            "E2E_FIXTURE_GITHUB_TOKEN",
            "E2E_JWT_SECRET",
            "GITHUB_OAUTH_TOKEN",
        ):
            assert forbidden not in text, forbidden
        assert doc["permissions"] == {"contents": "read"}

    def test_gate_does_not_execute_the_golden_path(self):
        run = _ci_gate_step()["run"]
        for forbidden in ("golden_path", "kind create", "docker compose up", "docker push"):
            assert forbidden not in run, forbidden


class TestSandboxSurfaceIsCommitted:
    """The sandbox image is a build surface like any other (§10)."""

    SANDBOX = REPO_ROOT / "devops-ai-platform" / "e2e" / "sandbox" / "Dockerfile"

    def test_workflow_builds_the_committed_sandbox_dockerfile(self):
        text = WORKFLOW.read_text()
        assert "-f devops-ai-platform/e2e/sandbox/Dockerfile" in text
        assert "/tmp/sandbox.Dockerfile" not in text
        assert "printf 'ARG BASE_IMAGE" not in text

    def test_sandbox_dockerfile_is_in_the_authoritative_inventory(self):
        assert "devops-ai-platform/e2e/sandbox/Dockerfile" in BS.dockerfiles()
        assert BS.validate_dockerfile_text(self.SANDBOX.read_text()) == []

    def test_sandbox_image_still_runs_as_non_root_and_carries_nothing_else(self):
        instructions = [
            line
            for line in self.SANDBOX.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        assert instructions == ["ARG BASE_IMAGE", "FROM ${BASE_IMAGE}", "USER nobody"]


# --------------------------------------------------------------------------
# Phase 8.4.2-F: the fixture repository may never be production (§21-F)
# --------------------------------------------------------------------------


class TestFixtureRepositoryIsNeverProduction:
    """The golden path pushes branches and opens PRs against the fixture.

    Before this phase the only guard was a slug *shape* check, which the
    production slug satisfies; the prohibition was structural (the value is
    a hardcoded workflow env, not a dispatch input) but never asserted.
    """

    PRODUCTION = "gm-prog/Autonomous-Devops-Engineer"

    @pytest.mark.parametrize(
        "slug",
        [
            PRODUCTION,
            PRODUCTION.lower(),
            PRODUCTION.upper(),
            PRODUCTION + ".git",
            PRODUCTION + "/",
            "  " + PRODUCTION + "  ",
        ],
    )
    def test_guard_rejects_every_spelling_of_production(self, slug):
        assert H.is_production_repository(slug) is True

    @pytest.mark.parametrize(
        "slug",
        [
            "gm-prog/ares-e2e-fixture",
            "gm-prog/Autonomous-Devops-Engineer-fixture",
            "other/Autonomous-Devops-Engineer",
            "",
            None,
        ],
    )
    def test_guard_accepts_disposable_fixtures(self, slug):
        assert H.is_production_repository(slug) is False

    def test_production_constant_matches_this_repository(self):
        assert H.PRODUCTION_REPOSITORY == self.PRODUCTION

    def test_driver_preflight_rejects_a_production_fixture(self):
        src = DRIVER.read_text()
        assert "is_production_repository(FIXTURE_REPO)" in src
        assert "must not be the production repository" in src

    def test_workflow_denies_a_production_fixture_before_any_build(self):
        text = WORKFLOW.read_text()
        assert "fixture repository must never be the production repository" in text
        assert "gm-prog/autonomous-devops-engineer" in text
        guard = text.index("must never be the production repository")
        for later in ("docker build --build-arg BASE_IMAGE=", "kind create cluster"):
            assert text.index(later) > guard, f"{later} must run after the guard"
