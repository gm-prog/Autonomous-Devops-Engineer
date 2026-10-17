"""Phase 8.8A Correction-1 (F4) — private credential staging.

The pre-correction sandbox staged the kubeconfig at 0444 under a 0711
parent: world-readable. The corrected staging must:

* stage into a 0700 private root and per-run 0700 directory;
* create the credential EXCLUSIVELY (O_EXCL) at 0600, owned by the
  sandbox identity — no 0444 fallback, no adoption of foreign paths;
* refuse symlinked / world-readable / foreign-owned / non-directory
  staging roots;
* refuse a pre-planted file or symlink at a staged path (O_EXCL race);
* prove the sandbox UID can read the credential while an
  unprivileged peer cannot (true uid switch where the test process is
  privileged; exact mode-bit proof otherwise);
* clean up on every path without following symlinks;
* never leak credential content into results, plans or logs.

These tests exercise the REAL staging code (only the docker launch and
the network inspection are stood in); the sandbox user is the current
process identity so the chown step is exact and unprivileged-safe.
"""
import os
import stat
import tempfile
import sys

import pytest

from deployment_service.application.services.kubectl_sandbox import (
    KUBECONFIG_PATH,
    KubectlOperation,
    KubectlSandboxConfigurationError,
    KubectlSandboxSpec,
    KubectlSandboxStep,
)
from deployment_service.infrastructure.sandbox import (
    kubernetes_sandbox_network,
)
from deployment_service.infrastructure.sandbox.container_kubectl_sandbox import (
    ContainerKubectlSandbox,
    KubectlSandboxResult,
)

IMAGE = "registry.local/kubectl@sha256:" + "a" * 64
NETWORK = "ares-k8s-staging-test-000000000000"
NAMESPACE = "devops-production-namespace"
SECRET_MARKER = "api-key: super-secret-credential-0123456789"

KUBECONFIG = (
    "apiVersion: v1\n"
    "kind: Config\n"
    f"clusters:\n  - name: c\n    cluster:\n      server: https://10.0.0.1\n"
    f"      {SECRET_MARKER}\n"
    "users:\n  - name: u\n    user: {{}}\n"
    "contexts:\n  - name: ctx\n    context: {{cluster: c, user: u}}\n"
    "current-context: ctx\n"
)

if sys.platform != "linux":
    pytest.skip("F4 permission semantics are Linux-specific", allow_module_level=True)


def _spec(user=None):
    uid = os.getuid()
    gid = os.getgid()
    return KubectlSandboxSpec(
        image=IMAGE,
        network=NETWORK,
        user=user or f"{uid}:{gid}",
        kubectl_version="v1.31.4",
    )


def _step():
    return KubectlSandboxStep(
        operation=KubectlOperation.APPLY,
        argv=("kubectl", "apply", "-f", "/workspace/deployment.yaml"),
        timeout_seconds=120,
    )


class _Capture:
    """Stands in for the docker launch; records the staged layout while
    the credential window is still open (before cleanup)."""

    def __init__(self):
        self.stat = {}
        self.content_seen = {}

    @staticmethod
    def _host_path_for(plan, container_path):
        # the plan argv carries "-v <host>:<container>:ro" triples
        for arg in plan.argv:
            if isinstance(arg, str) and arg.endswith(":ro"):
                host, container, _mode = arg.rsplit(":", 2)
                if container == container_path:
                    return host
        raise AssertionError(f"no host mount for {container_path}")

    def record(self, plan):
        kubeconfig = self._host_path_for(plan, KUBECONFIG_PATH)
        staging = os.path.dirname(kubeconfig)
        self.kubeconfig_path = kubeconfig
        self.stat["staging"] = os.lstat(staging)
        self.stat["kubeconfig"] = os.lstat(kubeconfig)
        self.stat["manifest"] = os.lstat(os.path.join(staging, "deployment.yaml"))
        # prove the owner (== sandbox uid here) can read it
        with open(kubeconfig, "rb") as handle:
            self.content_seen["kubeconfig"] = handle.read()
        return _dummy_result()


def _dummy_result():
    return KubectlSandboxResult(
        operation=KubectlOperation.APPLY,
        exit_code=0,
        stdout="ok",
        stderr="",
        timed_out=False,
        truncated=False,
        policy_identity="test-policy",
        container_argv=(),
    )


@pytest.fixture()
def sandbox_env(monkeypatch, tmp_path):
    """Network verification stood in (F3 has its own suite); the
    staging code under test is untouched."""
    monkeypatch.setattr(
        kubernetes_sandbox_network, "validate_network",
        lambda *a, **k: None,
    )
    monkeypatch.setattr(
        kubernetes_sandbox_network, "approved_peers_from_environment",
        lambda: ("ares-e2e-control-plane",),
    )
    staging_root = tmp_path / "staging-root"
    staging_root.mkdir(mode=0o700)
    return str(staging_root)


@pytest.fixture()
def sandbox(sandbox_env):
    return ContainerKubectlSandbox(_spec(), staging_root=sandbox_env)


def _run_staged(sandbox, capture, monkeypatch):
    """Patch the launch seam: a bound function receives the sandbox
    instance as its first argument, then (plan, namespace, cancel)."""

    def _launch(self_sandbox, plan, namespace, cancel_event=None):
        return capture.record(plan)

    monkeypatch.setattr(ContainerKubectlSandbox, "_run_container", _launch)
    return sandbox.execute(
        _step(),
        manifest_yaml="kind: Deployment\n",
        kubeconfig_yaml=KUBECONFIG,
        namespace=NAMESPACE,
    )


def test_staging_layout_is_private(sandbox, sandbox_env, monkeypatch):
    capture = _Capture()
    _run_staged(sandbox, capture, monkeypatch)
    st = capture.stat
    assert stat.S_IMODE(st["staging"].st_mode) == 0o700
    assert stat.S_IMODE(st["kubeconfig"].st_mode) == 0o600
    assert stat.S_IMODE(st["manifest"].st_mode) == 0o600
    # no group/other bits anywhere
    for mode in (st["staging"].st_mode, st["kubeconfig"].st_mode,
                 st["manifest"].st_mode):
        assert mode & 0o077 == 0
    # regular files, not symlinks
    assert stat.S_ISREG(st["kubeconfig"].st_mode)
    # owned by the sandbox identity
    uid, gid = _spec().user.split(":")
    assert st["kubeconfig"].st_uid == int(uid)
    assert st["kubeconfig"].st_gid == int(gid)


def test_sandbox_uid_reads_peer_cannot(sandbox, monkeypatch):
    capture = _Capture()
    _run_staged(sandbox, capture, monkeypatch)
    st = capture.stat["kubeconfig"]
    mode = stat.S_IMODE(st.st_mode)
    assert mode & 0o044 == 0, "peer read bits must be absent"
    assert mode & 0o022 == 0, "peer write bits must be absent"
    # the owner can read (proved by the capture having read it)
    assert SECRET_MARKER.encode() in capture.content_seen["kubeconfig"]
    # a true uid-switched read attempt when privileged:
    if os.geteuid() == 0:
        assert _peer_read_attempt(capture.kubeconfig_path, 65534), (
            "an unprivileged peer must not read the staged credential")


def test_world_readable_staging_root_is_refused(sandbox_env, tmp_path, monkeypatch):
    root = tmp_path / "badroot"
    root.mkdir()
    os.chmod(root, 0o755)
    bad = ContainerKubectlSandbox(_spec(), staging_root=str(root))
    with pytest.raises(KubectlSandboxConfigurationError,
                       match="mode must be 0700"):
        bad.execute(
            _step(),
            manifest_yaml="kind: Deployment\n",
            kubeconfig_yaml=KUBECONFIG,
            namespace=NAMESPACE,
        )


def test_symlinked_staging_root_is_refused(sandbox_env, tmp_path, monkeypatch):
    real = tmp_path / "real-root"
    real.mkdir(mode=0o700)
    link = tmp_path / "link-root"
    os.symlink(str(real), str(link))
    bad = ContainerKubectlSandbox(_spec(), staging_root=str(link))
    with pytest.raises(KubectlSandboxConfigurationError, match="symlink"):
        bad.execute(
            _step(),
            manifest_yaml="kind: Deployment\n",
            kubeconfig_yaml=KUBECONFIG,
            namespace=NAMESPACE,
        )


def test_staging_root_existing_as_file_is_refused(sandbox_env, tmp_path, monkeypatch):
    f = tmp_path / "rootfile"
    f.write_text("x")
    bad = ContainerKubectlSandbox(_spec(), staging_root=str(f))
    with pytest.raises(KubectlSandboxConfigurationError,
                       match="does not exist or is not a directory"):
        bad.execute(
            _step(),
            manifest_yaml="kind: Deployment\n",
            kubeconfig_yaml=KUBECONFIG,
            namespace=NAMESPACE,
        )


def test_foreign_owned_staging_root_is_refused(sandbox_env, tmp_path, monkeypatch):
    if os.geteuid() != 0:
        pytest.skip("requires root to create a foreign-owned directory")
    root = tmp_path / "foreign"
    root.mkdir(mode=0o700)
    os.chown(root, 65534, 65534)
    bad = ContainerKubectlSandbox(_spec(), staging_root=str(root))
    with pytest.raises(KubectlSandboxConfigurationError,
                       match="owned by another identity"):
        bad.execute(
            _step(),
            manifest_yaml="kind: Deployment\n",
            kubeconfig_yaml=KUBECONFIG,
            namespace=NAMESPACE,
        )


def test_pre_planted_symlink_at_staged_path_is_refused(sandbox, monkeypatch, tmp_path):
    """A symlink planted at the kubeconfig path (race/attack) must
    abort the step — O_EXCL refuses to write through it."""
    from deployment_service.infrastructure.sandbox import (
        container_kubectl_sandbox as sandbox_mod,
    )

    base = tmp_path / "preplant"
    base.mkdir(mode=0o700)
    target = base / "target"
    target.write_text("original-target-content")
    staging = tempfile.mkdtemp(prefix="ares-k8s-", dir=str(base))
    os.chmod(staging, 0o700)
    os.symlink(str(target), os.path.join(staging, "kubeconfig"))

    # force the per-run staging dir to be the pre-planted one
    monkeypatch.setattr(sandbox_mod, "_make_run_dir", lambda base_: staging)

    def _no_launch(sandbox_self, plan, namespace, cancel_event=None):
        raise AssertionError("launch must not happen")

    monkeypatch.setattr(ContainerKubectlSandbox, "_run_container", _no_launch)
    with pytest.raises(KubectlSandboxConfigurationError,
                       match="already exists"):
        sandbox.execute(
            _step(),
            manifest_yaml="kind: Deployment\n",
            kubeconfig_yaml=KUBECONFIG,
            namespace=NAMESPACE,
        )
    # the target must be untouched
    assert target.read_text() == "original-target-content"


def test_cleanup_removes_staging_without_following_symlinks(sandbox, monkeypatch, tmp_path):
    """A symlink planted INSIDE the staging dir during execution must
    be unlinked, never followed: the link target survives."""
    victim = tmp_path / "victim"
    victim.write_text("must survive")
    real_capture = _Capture()

    def _capture(sandbox_self, plan, namespace, cancel_event=None):
        kubeconfig = _Capture._host_path_for(plan, KUBECONFIG_PATH)
        staging = os.path.dirname(kubeconfig)
        os.symlink(str(victim), os.path.join(staging, "intruder-link"))
        return real_capture.record(plan)

    monkeypatch.setattr(ContainerKubectlSandbox, "_run_container", _capture)
    sandbox.execute(
        _step(),
        manifest_yaml="kind: Deployment\n",
        kubeconfig_yaml=KUBECONFIG,
        namespace=NAMESPACE,
    )
    # the victim was NOT removed through the link
    assert victim.exists()
    assert victim.read_text() == "must survive"
    # the per-run staging dir is gone
    leftovers = [d for d in os.listdir(sandbox._staging_root)
                 if d.startswith("ares-k8s-")]
    assert leftovers == [], "per-run staging directory must be cleaned up"


def test_no_secret_content_in_result_or_plan(sandbox, monkeypatch):
    captured = {}

    def _capture(sandbox_self, plan, namespace, cancel_event=None):
        captured["plan"] = plan
        return _dummy_result()

    monkeypatch.setattr(ContainerKubectlSandbox, "_run_container", _capture)
    result = sandbox.execute(
        _step(),
        manifest_yaml="kind: Deployment\n",
        kubeconfig_yaml=KUBECONFIG,
        namespace=NAMESPACE,
    )
    # the result carries bounded output only — never the credential
    assert SECRET_MARKER not in result.stdout
    assert SECRET_MARKER not in result.stderr
    # the launch plan references the credential by PATH, never content
    plan_repr = repr(captured["plan"])
    assert SECRET_MARKER not in plan_repr


def _peer_read_attempt(path: str, peer_uid: int) -> bool:
    """Privileged check: switch to an unprivileged uid in a forked
    child and attempt to read the staged credential. Returns True when
    the peer is correctly refused (PermissionError)."""
    import multiprocessing as mp
    import os as _os

    def _child(conn, path_):
        try:
            _os.setgid(peer_uid)
            _os.setuid(peer_uid)
            with open(path_, "rb"):
                conn.send(False)  # the peer COULD read it: fail
        except PermissionError:
            conn.send(True)
        except Exception:
            conn.send(None)

    parent_conn, child_conn = mp.Pipe()
    p = mp.Process(target=_child, args=(child_conn, path))
    p.start()
    result = parent_conn.recv()
    p.join(timeout=10)
    return result is True


if __name__ == "__main__":
    unittest.main()
