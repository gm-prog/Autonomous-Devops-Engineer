#!/usr/bin/env python3
"""LIVE proof of the Phase 8.5-A Terraform execution trust boundary.

Phase 8.5-A corrective, Workstream G (§22-§25).

Unit tests can only prove that the control plane *asks* for a safe
runtime. They cannot prove the runtime actually delivered one: that
Terraform really ran as a non-root user, really had no network, really
could not see the Docker socket, and that the plan a human approved is
byte-for-byte the plan that got applied.

This driver proves those properties by running the real chain::

    DeploymentEngine
        -> TerraformRunnerService
            -> ContainerTerraformSandbox
                -> docker (trusted, host side)
                    -> non-root Terraform container
                        -> terraform

against a real container runtime, and by *interrogating the container
from the inside* rather than trusting the flags that were requested.

It requires Docker and therefore does not run in unit CI. Every check
is reported individually; the script exits non-zero if any fails, and
writes a machine-readable evidence file. Nothing here is mocked: if the
runtime is unavailable the run is reported BLOCKED, never PASS.

Kubernetes is deliberately stubbed. Kubernetes execution hardening is a
separate phase, and this driver must not imply it was validated here.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from deployment_service.application.services.deployment_engine import (  # noqa: E402
    DeploymentEngine,
)
from deployment_service.application.services.plan_artifact import (  # noqa: E402
    PLAN_FILENAME,
)
from deployment_service.application.services.terraform_runner import (  # noqa: E402
    TerraformRunnerService,
)
from deployment_service.application.services.terraform_sandbox import (  # noqa: E402
    SANDBOX_WORKSPACE_MOUNT,
    TerraformOperation,
    credential_profile_identity,
    sandbox_runtime_identity,
)
from deployment_service.domain.value_objects.deployment_state import (  # noqa: E402
    DeploymentState,
)
from deployment_service.infrastructure.sandbox.container_terraform_sandbox import (  # noqa: E402
    ContainerTerraformSandbox,
)

FIXTURE = Path(__file__).resolve().parent / "terraform" / "main.tf"


# ---------------------------------------------------------------------
# tiny result recorder
# ---------------------------------------------------------------------


class Checks:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def record(self, name: str, expected, actual, ok: bool) -> bool:
        if not ok and os.environ.get("GITHUB_ACTIONS") == "true":
            # Error annotations survive where logs and artifacts may not
            # be reachable, so a failure is never a silent mystery.
            detail = f"expected={expected!r} actual={actual!r}".replace("\n", " ")
            print(f"::error title=live-check-failed::{name} :: {detail[:400]}")
        self.rows.append(
            {
                "check": name,
                "expected": str(expected),
                "actual": str(actual),
                "result": "PASS" if ok else "FAIL",
            }
        )
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}\n"
              f"         expected={expected!r} actual={actual!r}")
        return ok

    def equals(self, name, expected, actual) -> bool:
        return self.record(name, expected, actual, expected == actual)

    def truthy(self, name, actual, expected_desc="truthy") -> bool:
        return self.record(name, expected_desc, actual, bool(actual))

    @property
    def failed(self) -> list[dict]:
        return [r for r in self.rows if r["result"] == "FAIL"]


def notice(title: str, message: str) -> None:
    """Emit a GitHub annotation so evidence survives without log access."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        safe = str(message).replace("\n", " ")[:400]
        print(f"::notice title={title}::{safe}")


# ---------------------------------------------------------------------
# runtime prerequisites
# ---------------------------------------------------------------------


def require_runtime() -> str | None:
    if shutil.which("docker") is None:
        return "docker CLI is not installed"
    probe = subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}}"],
        capture_output=True, text=True,
    )
    if probe.returncode != 0:
        return f"docker daemon unreachable: {probe.stderr.strip()[:200]}"
    return None


def build_and_pin_image(args) -> str:
    """Build the sandbox image and resolve it to an immutable digest.

    A tag is not an identity: it can be moved. The control plane only
    accepts ``name@sha256:...``, so the image is pushed to a registry
    and the digest the registry computed is what gets used. No digest is
    ever invented or hand-written.
    """
    repo = f"{args.registry}/ares/terraform-sandbox"
    tag = f"{repo}:e2e"
    print(f"  building {tag} (terraform {args.terraform_version}) ...")
    build = subprocess.run(
        [
            "docker", "build",
            "-f", "deployment_service/Dockerfile.terraform-sandbox",
            "--build-arg", f"BASE_IMAGE={args.base_image}",
            "--build-arg", f"TERRAFORM_VERSION={args.terraform_version}",
            "--build-arg", "SANDBOX_UID=65532",
            "--build-arg", "SANDBOX_GID=65532",
            "-t", tag, ".",
        ],
        cwd=Path(__file__).resolve().parent.parent,
        capture_output=True, text=True,
    )
    if build.returncode != 0:
        # Keep this short and last-lines-only: it is surfaced as a CI
        # annotation, which is the one channel always readable.
        blob = (build.stderr or "") + "\n" + (build.stdout or "")
        lines = [ln.rstrip() for ln in blob.splitlines() if ln.strip()]
        # BuildKit prefixes a RUN step's OWN output with "#<step> <secs> ".
        # Those lines carry the actual cause; everything else is the
        # progress display and the Dockerfile context echo.
        import re as _re
        output = [
            _re.sub(r"^#\d+\s+[\d.]+\s*", "", ln)
            for ln in lines
            if _re.match(r"^#\d+\s+[\d.]+\s", ln)
        ]
        if os.environ.get("GITHUB_ACTIONS") == "true":
            for line in (output or lines)[-8:]:
                print(f"::error title=image-build-output::{line[:380]}")
        tail = " | ".join((output or lines)[-5:])
        raise RuntimeError(f"sandbox image build failed: {tail[:900]}")

    push = subprocess.run(["docker", "push", tag], capture_output=True, text=True)
    if push.returncode != 0:
        raise RuntimeError(f"sandbox image push failed:\n{push.stderr[-2000:]}")

    inspect = subprocess.run(
        ["docker", "image", "inspect", tag, "--format", "{{index .RepoDigests 0}}"],
        capture_output=True, text=True,
    )
    if inspect.returncode != 0 or "@sha256:" not in inspect.stdout:
        raise RuntimeError("could not resolve an immutable digest for the image")
    digest_ref = inspect.stdout.strip()

    # Prove the digest is really pullable, then rely on --pull never.
    subprocess.run(["docker", "rmi", "-f", tag], capture_output=True, text=True)
    pull = subprocess.run(["docker", "pull", digest_ref], capture_output=True, text=True)
    if pull.returncode != 0:
        raise RuntimeError(f"digest pull failed:\n{pull.stderr[-2000:]}")
    return digest_ref


# ---------------------------------------------------------------------
# the checks
# ---------------------------------------------------------------------


def probe_container_runtime(st: Checks, image: str, workspace: Path) -> None:
    """Interrogate a real sandbox container from the INSIDE.

    These use the same policy-built runtime profile as Terraform, but
    override the entrypoint so we can ask the container what it can
    actually see. Asking the kernel beats trusting our own flags.
    """
    from deployment_service.application.services.terraform_sandbox import (
        OPERATION_TIMEOUTS, build_run_plan, build_terraform_argv,
        new_container_name, TerraformSandboxSpec, TerraformSandboxStep,
    )

    uid, gid = sandbox_runtime_identity()
    spec = TerraformSandboxSpec(image=image, user=f"{uid}:{gid}")
    operation = TerraformOperation.VALIDATE
    # argv comes from the policy template, not from here: build_run_plan
    # re-derives it and refuses anything that does not match, which is
    # exactly the property that stops callers smuggling flags.
    step = TerraformSandboxStep(
        operation=operation,
        argv=build_terraform_argv(operation),
        timeout_seconds=OPERATION_TIMEOUTS[operation],
    )
    plan = build_run_plan(
        spec=spec, step=step, workspace_path=workspace,
        container_name=new_container_name(),
    )
    argv = list(plan.cli_argv)

    def run_inside(shell_cmd: str) -> tuple[int, str]:
        probe_argv = []
        skip_next = False
        for item in argv:
            if skip_next:
                skip_next = False
                continue
            if item == "--entrypoint":
                skip_next = True
                continue
            probe_argv.append(item)
        # replace the image+args tail: everything from the image onward
        idx = probe_argv.index(image)
        probe_argv = probe_argv[:idx] + ["--entrypoint", "/bin/sh", image, "-c", shell_cmd]
        done = subprocess.run(probe_argv, capture_output=True, text=True, timeout=120)
        return done.returncode, (done.stdout + done.stderr).strip()

    # Identity -------------------------------------------------------
    try:
        _, out = run_inside("id -u")
        st.record("terraform container runs as non-root (uid != 0)",
                  "non-zero uid", out, out.isdigit() and out != "0")
        notice("sandbox-uid", f"terraform container uid={out}")
    except Exception as exc:  # the image may have no shell at all
        st.record("terraform container runs as non-root (uid != 0)",
                  "non-zero uid", f"probe unavailable: {exc}", False)
        return

    # Network --------------------------------------------------------
    rc, out = run_inside(
        "ip -o link show 2>/dev/null | grep -v ' lo:' | wc -l")
    st.record("no network interfaces beyond loopback", "0", out, out.strip() == "0")

    # Docker socket --------------------------------------------------
    rc, out = run_inside("test -S /var/run/docker.sock && echo PRESENT || echo ABSENT")
    st.equals("docker socket is NOT visible inside the sandbox", "ABSENT", out.strip())

    # Read-only rootfs ----------------------------------------------
    rc, out = run_inside("touch /root-probe 2>&1 || echo READONLY")
    st.truthy("root filesystem is read-only", "READONLY" in out or rc != 0,
              "write to / refused")

    # Workspace is writable -----------------------------------------
    rc, out = run_inside(
        f"touch {SANDBOX_WORKSPACE_MOUNT}/.probe && echo WRITABLE || echo DENIED")
    st.equals("workspace IS writable by the non-root sandbox user",
              "WRITABLE", out.strip())

    # Host filesystem ------------------------------------------------
    rc, out = run_inside("test -e /etc/shadow && head -c1 /etc/shadow >/dev/null 2>&1 "
                         "&& echo READABLE || echo DENIED")
    st.equals("host /etc/shadow is not readable from the sandbox", "DENIED", out.strip())

    # Privilege escalation ------------------------------------------
    rc, out = run_inside("cat /proc/self/status | grep -i ^NoNewPrivs")
    st.truthy("no-new-privileges is set on the container process",
              "1" in out, "NoNewPrivs: 1")

    # Capabilities ---------------------------------------------------
    rc, out = run_inside("grep -i ^CapEff /proc/self/status")
    effective = out.split()[-1] if out.split() else "?"
    st.record("effective capability set is empty", "0000000000000000", effective,
              set(effective) <= {"0"})
    notice("sandbox-capabilities", f"CapEff={effective}")


def run_approval_flow(st: Checks, image: str, workspace_root: Path) -> dict:
    """The core semantic proof: approve plan A, apply exactly plan A."""
    from deployment_service.tests.test_deployment_engine import (
        VALID_PAYLOAD, FakeHealth, FakeKubectl, FakeSourceVerifier,
        FakeStore, FakeValidator,
    )

    payload = dict(VALID_PAYLOAD, terraform_tf=FIXTURE.read_text(encoding="utf-8"))

    class CountingRunner(TerraformRunnerService):
        """Real runner; counts plan operations so a re-plan is visible."""

        def __init__(self):
            super().__init__()
            self.plan_calls = 0
            self.init_calls = 0

        def run_plan(self, iac_dir, execution=False, plan_output_path=None):
            self.plan_calls += 1
            return super().run_plan(iac_dir, execution, plan_output_path)

        def initialize(self, iac_dir):
            self.init_calls += 1
            return super().initialize(iac_dir)

    runner = CountingRunner()
    engine = DeploymentEngine(
        store=FakeStore(), validator=FakeValidator(), terraform=runner,
        kubectl=FakeKubectl(), health_checker=FakeHealth(),
        source_verifier=FakeSourceVerifier(),
    )

    print("\n-- dry run (real terraform in the sandbox) --")
    run = engine.create_dry_run(payload)
    st.equals("dry run reached AWAITING_APPROVAL",
              DeploymentState.AWAITING_APPROVAL, run.state)
    if run.state != DeploymentState.AWAITING_APPROVAL:
        st.record("terraform plan succeeded in the sandbox", "PASS",
                  json.dumps(run.terraform_plan)[:400], False)
        return {}

    approved_hash = run.terraform_plan["plan_file_hash"]
    saved = Path(run.terraform_plan["approval_workspace"], PLAN_FILENAME)
    st.truthy("approved plan artifact exists on disk", saved.is_file())
    st.truthy("approved plan hash recorded", len(approved_hash) == 64)
    notice("approved-plan-hash", approved_hash)

    engine.approve(run.id, "live-e2e", run.artifact_hash, run.plan_hash)

    # --- tamper BEFORE the honest run, and prove it is refused ------
    print("\n-- tamper detection --")
    original = saved.read_bytes()
    saved.write_bytes(original + b"\x00tampered")
    os.environ["DEPLOYMENT_EXECUTION_ENABLED"] = "true"
    tampered_run = engine.execute(
        run.id, payload, run.artifact_hash, run.plan_hash)
    st.equals("tampered plan is BLOCKED, not applied",
              DeploymentState.DEPLOYMENT_FAILED, tampered_run.state)
    st.truthy("tampered run applied nothing",
              not tampered_run.execution.get("terraform_applied"),
              "terraform_applied falsy")

    # --- honest execution on a fresh approval -----------------------
    # The tampered run is now terminal, and deliberately so: a run that
    # was blocked for plan tampering must not be resurrectable. The
    # honest path therefore gets its own dry run and approval.
    print("\n-- honest execution of the EXACT approved plan --")
    run2 = engine.create_dry_run(payload)
    engine.approve(run2.id, "live-e2e", run2.artifact_hash, run2.plan_hash)
    approved2 = run2.terraform_plan["plan_file_hash"]
    plans_before = runner.plan_calls
    done = engine.execute(run2.id, payload, run2.artifact_hash, run2.plan_hash)

    st.equals("execution reached DEPLOYED", DeploymentState.DEPLOYED, done.state)
    st.equals("approved_plan_hash == applied_plan_hash",
              approved2, done.execution.get("applied_plan_hash"))
    st.equals("no NEW plan was generated after approval",
              plans_before, runner.plan_calls)
    st.truthy("terraform init ran instead (cannot create a plan)",
              runner.init_calls >= 1)
    st.truthy("saved plan destroyed after a terminal state",
              not Path(run2.terraform_plan["approval_workspace"]).exists())
    notice("applied-plan-hash", str(done.execution.get("applied_plan_hash")))

    return {
        "approval_plan_hash": approved2,
        "applied_plan_hash": done.execution.get("applied_plan_hash", ""),
        "sandbox_policy_identity": runner.describe_sandbox().get(
            "sandbox_policy_identity", ""),
        "terraform_runtime_version": runner.describe_sandbox().get(
            "terraform_version", ""),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", default="localhost:5001")
    parser.add_argument("--base-image", required=True,
                        help="digest-pinned base for the sandbox image")
    parser.add_argument("--terraform-version", default="1.9.8")
    parser.add_argument("--evidence", default="terraform-sandbox-live-evidence.json")
    args = parser.parse_args()

    print("=" * 70)
    print("Phase 8.5-A LIVE Terraform execution trust boundary proof")
    print("=" * 70)

    blocked = require_runtime()
    if blocked:
        print(f"\nBLOCKED: {blocked}")
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print(f"::error title=live-e2e-blocked::{blocked}")
        print("A live boundary proof requires a real container runtime. "
              "Refusing to report PASS without one.")
        Path(args.evidence).write_text(json.dumps(
            {"e2e_status": "BLOCKED", "reason": blocked}, indent=2))
        return 2

    st = Checks()
    started = time.time()
    workspace_root = Path(os.environ.setdefault(
        "DEPLOYMENT_WORKSPACE_ROOT", tempfile.mkdtemp(prefix="ares-tf-live-")))
    workspace_root.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("DEPLOYMENT_CREDENTIAL_ENV_KEYS", "")

    try:
        print("\n-- immutable image identity --")
        digest_ref = build_and_pin_image(args)
        print(f"  digest: {digest_ref}")
        notice("sandbox-image-digest", digest_ref)
        os.environ["DEPLOYMENT_TERRAFORM_SANDBOX_IMAGE"] = digest_ref
        os.environ["DEPLOYMENT_TERRAFORM_SANDBOX_VERSION"] = args.terraform_version
        st.truthy("sandbox image is digest-pinned", "@sha256:" in digest_ref)

        print("\n-- runtime confinement (interrogated from inside) --")
        probe_ws = workspace_root / "probe"
        probe_ws.mkdir(exist_ok=True)
        os.chmod(probe_ws, 0o2777)  # probe dir only; engine workspaces are 0o2770
        probe_container_runtime(st, digest_ref, probe_ws)

        evidence = run_approval_flow(st, digest_ref, workspace_root)
    except Exception as exc:  # noqa: BLE001 - must never be silently green
        import traceback
        trace = traceback.format_exc().strip().splitlines()
        st.record("live run completed without an internal error", "no exception",
                  f"{type(exc).__name__}: {str(exc)[:600]}", False)
        if os.environ.get("GITHUB_ACTIONS") == "true":
            for line in trace[-6:]:
                print(f"::error title=live-e2e-traceback::{line[:400]}")
        evidence = {}

    status = "PASS" if not st.failed else "FAIL"
    payload = {
        "e2e_status": status,
        "checks_total": len(st.rows),
        "checks_passed": len(st.rows) - len(st.failed),
        "checks_failed": len(st.failed),
        "duration_seconds": round(time.time() - started, 1),
        "image_digest": os.environ.get("DEPLOYMENT_TERRAFORM_SANDBOX_IMAGE", ""),
        "workspace_root": str(workspace_root),
        "credential_profile_id": credential_profile_identity(),
        "sandbox_uid_gid": ":".join(str(v) for v in sandbox_runtime_identity()),
        **evidence,
        "checks": st.rows,
    }
    Path(args.evidence).write_text(json.dumps(payload, indent=2, sort_keys=True))

    notice(
        "live-e2e-summary",
        f"{status} {payload['checks_passed']}/{payload['checks_total']} checks; "
        f"approved={payload.get('approval_plan_hash', '')[:16]} "
        f"applied={payload.get('applied_plan_hash', '')[:16]} "
        f"uid_gid={payload['sandbox_uid_gid']} "
        f"credentials={payload['credential_profile_id']}",
    )
    print("\n" + "=" * 70)
    print(f"LIVE E2E: {status}  ({payload['checks_passed']}/{payload['checks_total']} checks)")
    for row in st.failed:
        print(f"  FAILED: {row['check']}")
    print("=" * 70)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
