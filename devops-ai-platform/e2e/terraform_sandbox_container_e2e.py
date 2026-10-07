#!/usr/bin/env python3
"""Authoritative containerized proof of the Terraform trust boundary.

Phase 8.5-A closeout, Workstream A.

The previous live proof ran the application *in the CI runner's Python
process*. That proved the sandbox worked; it did not prove the shipped
deployment-service container could reach it. Those are different claims,
and only the second one matters for acceptance:

    deployment-service CONTAINER
        -> docker CLI inside that container
            -> docker socket mounted into that container
                -> Docker daemon on the host
                    -> untrusted Terraform sandbox container

So this driver never imports the application. It builds the real images,
starts the real service, and speaks to it only over HTTP:

    POST /api/internal/deployments/dry-run
    POST /api/internal/deployments/{id}/approve
    POST /api/internal/deployments/{id}/execute
    GET  /api/internal/deployments/{id}

Two boundaries are stubbed at the TOPOLOGY level (never inside the
application, and never by changing production code):

* the canonical commit API, served by a local stub the service is
  pointed at with DEPLOYMENT_SOURCE_API_BASE_URL. Verification still
  runs in full and still demands the exact SHA back.
* kubectl, bind-mounted over the binary in the running container.
  Kubernetes hardening is a separate phase and is NOT validated here.

Terraform -- the thing actually under test -- is entirely real.

Every probe must be able to OBSERVE the property it reports. A probe
that cannot inspect (missing tool, failed inspect) is a FAIL, never a
pass. Exit code 0 only if every check passed.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLATFORM_ROOT = HERE.parent
REPO_ROOT = PLATFORM_ROOT.parent
FIXTURE_TF = HERE / "terraform" / "main.tf"
FIXTURES = HERE / "fixtures"

SERVICE_NAME = "ares-e2e-deployment-service"
REDIS_NAME = "ares-e2e-redis"
NETWORK_NAME = "ares-e2e-net"
SERVICE_PORT = 8030
FIXTURE_SHA = "a" * 40
FIXTURE_REPO = "ares-e2e/fixture"


# =====================================================================
# result recorder
# =====================================================================


class Checks:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def record(self, name, expected, observed, ok) -> bool:
        self.rows.append(
            {
                "check": name,
                "expected": str(expected)[:300],
                "observed": str(observed)[:300],
                "result": "PASS" if ok else "FAIL",
            }
        )
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        print(f"         expected={expected!r}")
        print(f"         observed={observed!r}")
        if not ok and os.environ.get("GITHUB_ACTIONS") == "true":
            print(f"::error title=e2e-check-failed::{name} :: "
                  f"expected={str(expected)[:150]} observed={str(observed)[:200]}")
        return ok

    def equals(self, name, expected, observed) -> bool:
        return self.record(name, expected, observed, expected == observed)

    def truthy(self, name, observed, expected="truthy") -> bool:
        return self.record(name, expected, observed, bool(observed))

    @property
    def failed(self):
        return [r for r in self.rows if r["result"] == "FAIL"]


def notice(title, message):
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::notice title={title}::{str(message)[:400]}")


def sh(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, **kw)


# =====================================================================
# commit-API stub (topology-level, not an application change)
# =====================================================================


class _CommitStub(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        match = re.fullmatch(r"/repos/([^/]+/[^/]+)/commits/([0-9a-f]{40})", self.path)
        if not match:
            self.send_error(404)
            return
        body = json.dumps({
            "sha": match.group(2),
            "commit": {"message": "ares e2e fixture commit",
                       "author": {"name": "ares-e2e", "date": "2026-01-01T00:00:00Z"}},
            "files": [{"filename": "main.tf", "status": "added"}],
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # keep CI output clean
        pass


def start_commit_stub() -> tuple[http.server.HTTPServer, int]:
    server = http.server.HTTPServer(("0.0.0.0", 0), _CommitStub)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, port


def host_gateway_ip() -> str:
    """An address the service container can use to reach this process."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("10.255.255.255", 1))
        return probe.getsockname()[0]
    finally:
        probe.close()


# =====================================================================
# images
# =====================================================================


def build_sandbox_image(registry, base_image, terraform_version) -> str:
    repo = f"{registry}/ares/terraform-sandbox"
    tag = f"{repo}:e2e"
    print(f"  building sandbox image {tag}")
    build = sh([
        "docker", "build",
        "-f", "deployment_service/Dockerfile.terraform-sandbox",
        "--build-arg", f"BASE_IMAGE={base_image}",
        "--build-arg", f"TERRAFORM_VERSION={terraform_version}",
        "--build-arg", "SANDBOX_UID=65532",
        "--build-arg", "SANDBOX_GID=65532",
        "-t", tag, ".",
    ], cwd=PLATFORM_ROOT)
    if build.returncode != 0:
        raise RuntimeError(_build_error("sandbox image", build))
    if sh(["docker", "push", tag]).returncode != 0:
        raise RuntimeError("sandbox image push failed")
    inspect = sh(["docker", "image", "inspect", tag,
                  "--format", "{{index .RepoDigests 0}}"])
    if "@sha256:" not in inspect.stdout:
        raise RuntimeError("no registry digest for the sandbox image")
    digest = inspect.stdout.strip()
    # Prove the digest is genuinely pullable, then rely on --pull never.
    sh(["docker", "rmi", "-f", tag])
    if sh(["docker", "pull", digest]).returncode != 0:
        raise RuntimeError(f"digest pull failed for {digest}")
    return digest


def build_service_image(base_image) -> str:
    tag = "ares/deployment-service:e2e"
    print(f"  building deployment-service image {tag}")
    build = sh([
        "docker", "build",
        "-f", "deployment_service/Dockerfile.e2e",
        "--build-arg", f"BASE_IMAGE={base_image}",
        "-t", tag, ".",
    ], cwd=PLATFORM_ROOT)
    if build.returncode != 0:
        raise RuntimeError(_build_error("deployment-service image", build))
    return tag


def _build_error(what, completed) -> str:
    blob = (completed.stderr or "") + "\n" + (completed.stdout or "")
    lines = [ln.rstrip() for ln in blob.splitlines() if ln.strip()]
    output = [re.sub(r"^#\d+\s+[\d.]+\s*", "", ln) for ln in lines
              if re.match(r"^#\d+\s+[\d.]+\s", ln)]
    if os.environ.get("GITHUB_ACTIONS") == "true":
        for line in (output or lines)[-8:]:
            print(f"::error title=image-build-output::{line[:380]}")
    return f"{what} build failed: {' | '.join((output or lines)[-5:])[:800]}"


# =====================================================================
# the service container
# =====================================================================


def write_kubectl_stub(directory: Path) -> Path:
    """Deterministic kubectl for the test topology ONLY.

    Bind-mounted over the binary in the running container, so the image
    itself is never altered and the real kubectl remains in place for
    every other consumer. Kubernetes is explicitly NOT validated here.
    """
    stub = directory / "kubectl"
    stub.write_text(
        "#!/bin/sh\n"
        "# ARES E2E topology stub. Kubernetes is out of scope for the\n"
        "# Terraform execution trust boundary; this keeps the deployment\n"
        "# API deterministic without a cluster.\n"
        'echo \"kubectl-e2e-stub $*\"\n'
        "exit 0\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub


def start_support_stack(redis_image: str) -> None:
    """Redis is a declared runtime dependency of the service (compose
    `depends_on: [redis]`), so the proof runs the real thing on a
    user-defined network rather than stubbing the service's own storage."""
    sh(["docker", "rm", "-f", REDIS_NAME])
    sh(["docker", "network", "rm", NETWORK_NAME])
    created = sh(["docker", "network", "create", NETWORK_NAME])
    if created.returncode != 0:
        raise RuntimeError(f"could not create e2e network: {created.stderr[-300:]}")
    started = sh([
        "docker", "run", "-d", "--name", REDIS_NAME,
        "--network", NETWORK_NAME, "--network-alias", "redis",
        redis_image,
    ])
    if started.returncode != 0:
        raise RuntimeError(f"redis failed to start: {started.stderr[-500:]}")
    deadline = time.time() + 60
    while time.time() < deadline:
        ping = sh(["docker", "exec", REDIS_NAME, "redis-cli", "ping"])
        if "PONG" in ping.stdout.upper():
            return
        time.sleep(1)
    raise RuntimeError("redis did not become ready within 60s")


def start_service(image, workspace_root: Path, sandbox_digest,
                  stub_dir: Path, commit_api) -> str:
    sh(["docker", "rm", "-f", SERVICE_NAME])
    argv = [
        "docker", "run", "-d", "--name", SERVICE_NAME,
        "--network", NETWORK_NAME,
        "-p", f"{SERVICE_PORT}:8030",
        "-e", "REDIS_HOST=redis",
        "-e", "REDIS_PORT=6379",
        # TRUSTED control plane: it needs daemon authority to launch the
        # sandbox. This is the documented v1 residual risk.
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        # Host-visible workspace at an IDENTICAL absolute path, so the
        # daemon resolves the sandbox bind source correctly.
        "-v", f"{workspace_root}:{workspace_root}",
        "-v", f"{stub_dir / 'kubectl'}:/usr/local/bin/kubectl:ro",
        "-e", "DEPLOYMENT_EXECUTION_ENABLED=true",
        "-e", f"DEPLOYMENT_WORKSPACE_ROOT={workspace_root}",
        "-e", f"DEPLOYMENT_TERRAFORM_SANDBOX_IMAGE={sandbox_digest}",
        "-e", "DEPLOYMENT_TERRAFORM_SANDBOX_VERSION=1.9.8",
        "-e", "DEPLOYMENT_ALLOWED_NAMESPACES=devops-production-namespace",
        "-e", "DEPLOYMENT_CREDENTIAL_ENV_KEYS=",
        "-e", f"DEPLOYMENT_SOURCE_API_BASE_URL={commit_api}",
        image,
    ]
    started = sh(argv)
    if started.returncode != 0:
        raise RuntimeError(f"service container failed to start: {started.stderr[-500:]}")
    return started.stdout.strip()


def wait_for_health(timeout=120) -> dict:
    """Deterministic readiness: poll /health, never a bare sleep."""
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{SERVICE_PORT}/health", timeout=5
            ) as response:
                if response.status == 200:
                    return json.loads(response.read())
        except Exception as exc:  # noqa: BLE001
            last = f"{type(exc).__name__}: {exc}"
        time.sleep(2)
    logs = sh(["docker", "logs", "--tail", "40", SERVICE_NAME])
    raise RuntimeError(
        f"deployment-service never became healthy ({last}); "
        f"logs: {(logs.stdout + logs.stderr)[-800:]}"
    )


def api(method, path, body=None, expect=(200, 201)):
    url = f"http://127.0.0.1:{SERVICE_PORT}{path}"
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw or b"{}")
        except Exception:  # noqa: BLE001
            return exc.code, {"raw": raw.decode(errors="replace")[:500]}


def exec_in_service(command):
    return sh(["docker", "exec", SERVICE_NAME, "sh", "-c", command])


# =====================================================================
# runtime observation of the sandbox container
# =====================================================================


def observe_sandbox(st: Checks, digest, workspace_root: Path):
    """Observe delivered runtime properties, never the requested flags.

    The container is launched with the SAME policy-built profile the
    service uses, but with a shell entrypoint so the kernel can be asked
    directly. Any probe that cannot inspect its property FAILS.
    """
    probe_ws = workspace_root / "runtime-probe"
    probe_ws.mkdir(parents=True, exist_ok=True)
    os.chmod(probe_ws, 0o2777)
    name = "ares-e2e-sandbox-probe"
    sh(["docker", "rm", "-f", name])

    base = [
        "docker", "run", "--rm", "--name", name, "--pull", "never",
        "--network", "none", "--user", "65532:65532", "--read-only",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "--pids-limit", "256", "--memory", "1073741824", "--cpus", "2",
        "-v", f"{probe_ws}:/workspace:rw", "-w", "/workspace",
        "--entrypoint", "/bin/sh", digest, "-c",
    ]

    def inside(cmd, timeout=90):
        done = sh(base + [cmd], timeout=timeout)
        return done.returncode, (done.stdout + done.stderr).strip()

    # --- identity -------------------------------------------------
    rc, uid = inside("id -u")
    st.record("sandbox UID observed and non-root", "integer != 0", uid,
              rc == 0 and uid.isdigit() and uid != "0")
    rc, gid = inside("id -g")
    st.record("sandbox GID observed and non-root", "integer != 0", gid,
              rc == 0 and gid.isdigit() and gid != "0")
    notice("sandbox-uid-gid", f"{uid}:{gid}")

    # --- capabilities ---------------------------------------------
    rc, caps = inside("grep ^CapEff /proc/self/status | awk '{print $2}'")
    st.record("effective capabilities are empty", "0000000000000000", caps,
              rc == 0 and bool(caps) and set(caps) <= {"0"})

    # --- no-new-privileges ----------------------------------------
    rc, nnp = inside("grep ^NoNewPrivs /proc/self/status | awk '{print $2}'")
    st.record("NoNewPrivs is set", "1", nnp, rc == 0 and nnp == "1")

    # --- rootfs: READ-ONLY MOUNT, not merely unwritable -----------
    # A writable rootfs also denies writes to a non-root user, so the
    # old `touch /` probe proved nothing. Ask the kernel instead.
    rc, mountinfo = inside(
        "awk '$5==\"/\"{print $6}' /proc/self/mountinfo | head -1")
    observed = mountinfo.split(",")[0] if mountinfo else ""
    st.record("root filesystem is mounted read-only (kernel mountinfo)",
              "ro", observed or "mountinfo unavailable",
              rc == 0 and observed == "ro")

    # --- network: must OBSERVE, not infer from a missing tool ------
    rc, netdev = inside("cat /proc/net/dev")
    if rc != 0 or "|" not in netdev:
        st.record("network interfaces observable", "readable /proc/net/dev",
                  f"rc={rc}", False)
    else:
        names = [ln.split(":")[0].strip() for ln in netdev.splitlines()
                 if ":" in ln and not ln.strip().startswith("Inter")]
        non_loopback = [n for n in names if n and n != "lo"]
        st.record("only loopback exists inside the sandbox", "[]",
                  non_loopback, non_loopback == [])

    # --- docker socket ---------------------------------------------
    rc, sock = inside(
        "if [ -S /var/run/docker.sock ]; then echo PRESENT; else echo ABSENT; fi")
    st.record("docker socket absent inside the sandbox", "ABSENT", sock,
              rc == 0 and sock == "ABSENT")

    # --- workspace writability by the non-root user ----------------
    rc, write = inside(
        "touch /workspace/.probe && echo WRITABLE || echo DENIED")
    st.record("workspace writable by the non-root sandbox user",
              "WRITABLE", write, rc == 0 and write == "WRITABLE")

    # --- host filesystem: enumerate EVERY bind, not one file -------
    rc, mounts = inside(
        "awk '{print $5}' /proc/self/mountinfo | sort -u | tr '\\n' ' '")
    if rc != 0 or not mounts:
        st.record("sandbox mount table observable", "mountinfo readable",
                  f"rc={rc}", False)
    else:
        points = [m for m in mounts.split() if m]
        # Anything outside this set would be an unexpected host surface.
        permitted = {"/", "/workspace", "/tmp", "/proc", "/sys", "/dev",
                     "/etc/hosts", "/etc/hostname", "/etc/resolv.conf"}
        unexpected = [
            m for m in points
            if m not in permitted
            and not m.startswith(("/proc/", "/sys/", "/dev/"))
        ]
        st.record("no host mounts beyond the single workspace bind",
                  "[]", unexpected, unexpected == [])
        notice("sandbox-mounts", " ".join(points)[:380])

    # --- terraform runtime version (observed, not declared) --------
    version = sh([
        "docker", "run", "--rm", "--pull", "never", "--network", "none",
        "--user", "65532:65532", "--read-only",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true", digest, "version",
    ], timeout=90)
    observed_version = (version.stdout or "").strip().splitlines()[:1]
    observed_version = observed_version[0] if observed_version else ""
    st.truthy("terraform runtime version observed from the image",
              observed_version.startswith("Terraform v"), "Terraform v...")
    notice("terraform-runtime-version", observed_version)
    return {"uid": uid, "gid": gid, "cap_eff": caps, "no_new_privs": nnp,
            "rootfs": observed or "", "terraform_version": observed_version}


# =====================================================================
# the deployment flow, over HTTP, against the real container
# =====================================================================


#: Only the fields ExecuteRequest actually accepts.
_EXECUTE_FIELDS = (
    "dockerfile", "k8s_yaml", "terraform_tf", "pipeline_yaml",
)


def deployment_payload():
    """The committed E2E fixtures, which are built to pass IaCValidator.

    The real validator runs inside the service -- there is no fake here --
    so hand-rolled manifests would be rejected for unrelated reasons and
    the Terraform boundary would never be reached.
    """
    def read(name):
        return (FIXTURES / name).read_text(encoding="utf-8")

    return {
        "repository_id": 1,
        "repository_name": FIXTURE_REPO,
        "requested_by": "ares-e2e",
        "dockerfile": read("Dockerfile"),
        "k8s_yaml": read("k8s-deployment.yaml"),
        "terraform_tf": FIXTURE_TF.read_text(encoding="utf-8"),
        "pipeline_yaml": read("pipeline.yaml"),
        "source_revision": {"head_sha": FIXTURE_SHA},
    }


def execute_body(payload, dry):
    body = {k: payload[k] for k in _EXECUTE_FIELDS}
    body["artifact_hash"] = dry.get("artifact_hash")
    body["plan_hash"] = dry.get("plan_hash")
    return body


def run_deployment_flow(st: Checks, workspace_root: Path):
    payload = deployment_payload()

    # ---- tamper run ------------------------------------------------
    print("\n-- run 1: dry-run, approve, TAMPER, execute (must fail closed) --")
    status, dry = api("POST", "/api/internal/deployments/dry-run", payload)
    st.equals("dry-run API accepted (HTTP 200)", 200, status)
    if status != 200:
        st.record("dry-run body", "run object", json.dumps(dry)[:300], False)
        return {}
    run_id = dry.get("id") or dry.get("run_id")
    tf_plan = dry.get("terraform_plan") or {}
    st.equals("terraform plan PASS inside the sandbox", "PASS", tf_plan.get("status"))
    st.equals("dry run awaits approval", "AWAITING_APPROVAL", dry.get("state"))
    workspace = tf_plan.get("approval_workspace", "")
    approved_hash = tf_plan.get("plan_file_hash", "")
    st.truthy("approved plan hash recorded (64 hex)", len(approved_hash) == 64)

    # The workspace the SERVICE created must be visible to this host
    # process at the same absolute path -- that is the shared-root proof.
    saved = Path(workspace, "terraform.tfplan")
    st.truthy("approval workspace is host-visible at the same path",
              saved.is_file(), f"{saved} exists on the host")
    st.truthy("terraform wrote .terraform/ in the shared workspace",
              (Path(workspace) / ".terraform").exists()
              or (Path(workspace) / ".terraform.lock.hcl").exists())

    api("POST", f"/api/internal/deployments/{run_id}/approve",
        {"approved_by": "ares-e2e", "artifact_hash": dry.get("artifact_hash"),
         "plan_hash": dry.get("plan_hash")})

    saved.write_bytes(saved.read_bytes() + b"\x00tampered")
    status, tampered = api(
        "POST", f"/api/internal/deployments/{run_id}/execute",
        execute_body(payload, dry))
    tampered_state = tampered.get("state", "")
    st.truthy("tampered plan execution fails closed",
              tampered_state not in {"DEPLOYED", "HEALTH_CHECKING"},
              "not DEPLOYED")
    st.truthy("tampered run applied no terraform",
              not (tampered.get("execution") or {}).get("terraform_applied"))

    # ---- honest run -------------------------------------------------
    print("\n-- run 2: honest dry-run, approve, execute exact approved plan --")
    status, dry2 = api("POST", "/api/internal/deployments/dry-run", payload)
    run2 = dry2.get("id") or dry2.get("run_id")
    tf2 = dry2.get("terraform_plan") or {}
    approved2 = tf2.get("plan_file_hash", "")
    workspace2 = tf2.get("approval_workspace", "")
    api("POST", f"/api/internal/deployments/{run2}/approve",
        {"approved_by": "ares-e2e", "artifact_hash": dry2.get("artifact_hash"),
         "plan_hash": dry2.get("plan_hash")})

    status, done = api("POST", f"/api/internal/deployments/{run2}/execute",
                       execute_body(payload, dry2))
    execution = done.get("execution") or {}
    st.equals("deployment reached DEPLOYED", "DEPLOYED", done.get("state"))
    st.equals("approved_plan_hash == applied_plan_hash",
              approved2, execution.get("applied_plan_hash"))
    st.equals("execution recorded the approved hash",
              approved2, execution.get("approved_plan_hash"))
    st.equals("execution did not re-plan after approval", False,
              (execution.get("terraform_plan") or {}).get(
                  "replanned_after_approval"))
    st.equals("execution applied the approved plan artifact", "approved",
              (execution.get("terraform_plan") or {}).get("plan_source"))
    st.truthy("terraform init ran on the approved workspace",
              (execution.get("terraform_init") or {}).get("status") == "PASS")
    st.truthy("approval workspace removed after a terminal state",
              not Path(workspace2).exists())

    # ---- durability: approved plan gone -> fail closed --------------
    print("\n-- run 3: approval workspace disappears before execute --")
    status, dry3 = api("POST", "/api/internal/deployments/dry-run", payload)
    run3 = dry3.get("id") or dry3.get("run_id")
    ws3 = (dry3.get("terraform_plan") or {}).get("approval_workspace", "")
    api("POST", f"/api/internal/deployments/{run3}/approve",
        {"approved_by": "ares-e2e", "artifact_hash": dry3.get("artifact_hash"),
         "plan_hash": dry3.get("plan_hash")})
    shutil.rmtree(ws3, ignore_errors=True)
    status, lost = api("POST", f"/api/internal/deployments/{run3}/execute",
                       execute_body(payload, dry3))
    st.truthy("missing approved plan fails closed (no silent re-plan)",
              lost.get("state") not in {"DEPLOYED", "HEALTH_CHECKING"}
              and not (lost.get("execution") or {}).get("terraform_applied"))

    notice("approved-plan-hash-honest", approved2)
    notice("applied-plan-hash-honest", str(execution.get("applied_plan_hash")))
    return {
        "approval_plan_hash": approved2,
        "applied_plan_hash": execution.get("applied_plan_hash", ""),
        "tampered_run_state": tampered_state,
        "missing_plan_run_state": lost.get("state", ""),
    }


# =====================================================================


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", default="localhost:5001")
    parser.add_argument("--base-image", required=True)
    parser.add_argument("--terraform-version", default="1.9.8")
    parser.add_argument("--redis-image", required=True)
    parser.add_argument("--workspace-root", default="/tmp/ares-e2e-tf-workspaces")
    parser.add_argument("--evidence", default="terraform-container-e2e-evidence.json")
    args = parser.parse_args()

    print("=" * 72)
    print("Phase 8.5-A closeout — CONTAINERIZED deployment-service E2E")
    print("=" * 72)

    if shutil.which("docker") is None:
        print("\nBLOCKED: docker CLI unavailable on the orchestrator")
        Path(args.evidence).write_text(json.dumps(
            {"e2e_status": "BLOCKED", "reason": "no docker CLI"}, indent=2))
        return 2

    st = Checks()
    started = time.time()
    workspace_root = Path(args.workspace_root)
    workspace_root.mkdir(parents=True, exist_ok=True)
    os.chmod(workspace_root, 0o2777)  # root dir only; per-run dirs are 0o2770
    stub_dir = Path(tempfile.mkdtemp(prefix="ares-e2e-stubs-"))
    os.chmod(stub_dir, 0o755)
    write_kubectl_stub(stub_dir)
    server = None
    evidence = {}
    runtime = {}
    digest = ""

    try:
        server, stub_port = start_commit_stub()
        commit_api = f"http://{host_gateway_ip()}:{stub_port}"
        print(f"\n-- images --")
        digest = build_sandbox_image(args.registry, args.base_image,
                                     args.terraform_version)
        print(f"  sandbox digest: {digest}")
        notice("sandbox-image-digest", digest)
        st.truthy("sandbox image is digest-pinned", "@sha256:" in digest)
        service_image = build_service_image(args.base_image)

        print("\n-- control-plane image contract --")
        probe = sh(["docker", "run", "--rm", "--entrypoint", "sh",
                    service_image, "-c",
                    "command -v terraform >/dev/null 2>&1 && echo PRESENT "
                    "|| echo ABSENT"])
        st.equals("control-plane image contains NO terraform binary",
                  "ABSENT", probe.stdout.strip())
        probe = sh(["docker", "run", "--rm", "--entrypoint", "sh",
                    service_image, "-c", "docker --version >/dev/null 2>&1 "
                    "&& echo PRESENT || echo ABSENT"])
        st.equals("control-plane image contains the docker CLI",
                  "PRESENT", probe.stdout.strip())

        print("\n-- starting the real deployment-service container --")
        start_support_stack(args.redis_image)
        start_service(service_image, workspace_root, digest, stub_dir, commit_api)
        health = wait_for_health()
        st.truthy("deployment-service container started", True)
        st.equals("deployment-service health reports the service",
                  "deployment-service", health.get("service", ""))
        st.equals("execution is enabled in the running service", True,
                  bool(health.get("execution_enabled")))

        print("\n-- control-plane runtime capabilities (inside the container) --")
        inside = exec_in_service("docker --version")
        st.truthy("docker CLI usable INSIDE deployment-service",
                  inside.returncode == 0 and "Docker version" in inside.stdout,
                  inside.stdout.strip()[:80] or inside.stderr.strip()[:80])
        inside = exec_in_service(
            "if [ -S /var/run/docker.sock ]; then echo PRESENT; else echo ABSENT; fi")
        st.equals("docker socket present INSIDE deployment-service (trusted)",
                  "PRESENT", inside.stdout.strip())
        inside = exec_in_service(
            "command -v terraform >/dev/null 2>&1 && echo PRESENT || echo ABSENT")
        st.equals("no terraform binary inside the running control plane",
                  "ABSENT", inside.stdout.strip())
        inside = exec_in_service(f"test -d {workspace_root} && echo PRESENT || echo ABSENT")
        st.equals("workspace root visible inside deployment-service",
                  "PRESENT", inside.stdout.strip())

        print("\n-- observed sandbox runtime properties --")
        runtime = observe_sandbox(st, digest, workspace_root)

        print("\n-- deployment flow over the real HTTP API --")
        evidence = run_deployment_flow(st, workspace_root)

    except Exception as exc:  # noqa: BLE001
        import traceback
        trace = traceback.format_exc().strip().splitlines()
        st.record("e2e completed without an internal error", "no exception",
                  f"{type(exc).__name__}: {str(exc)[:400]}", False)
        if os.environ.get("GITHUB_ACTIONS") == "true":
            for line in trace[-6:]:
                print(f"::error title=e2e-traceback::{line[:380]}")
    finally:
        logs = sh(["docker", "logs", "--tail", "200", SERVICE_NAME])
        if st.failed and (logs.stdout or logs.stderr):
            blob = logs.stdout + logs.stderr
            print("\n-- deployment-service logs (tail) --")
            print(blob[-6000:])
            # Job logs are not always retrievable through the API, so the
            # service's own failure lines are promoted to annotations.
            if os.environ.get("GITHUB_ACTIONS") == "true":
                lines = [ln.rstrip() for ln in blob.splitlines() if ln.strip()]
                keep = [
                    ln for ln in lines
                    if ("Traceback" in ln or 'File "' in ln or "Error" in ln
                        or "error" in ln or "raise" in ln or "Exception" in ln)
                ]
                for line in (keep or lines)[-10:]:
                    print(f"::error title=service-log::{line[:380]}")
        sh(["docker", "rm", "-f", SERVICE_NAME])
        sh(["docker", "rm", "-f", REDIS_NAME])
        sh(["docker", "network", "rm", NETWORK_NAME])
        if server:
            server.shutdown()
        shutil.rmtree(stub_dir, ignore_errors=True)

    status = "PASS" if not st.failed else "FAIL"
    payload = {
        "e2e_status": status,
        "e2e_kind": "containerized-deployment-service",
        "commit_sha": os.environ.get("GITHUB_SHA", ""),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "checks_total": len(st.rows),
        "checks_passed": len(st.rows) - len(st.failed),
        "checks_failed": len(st.failed),
        "duration_seconds": round(time.time() - started, 1),
        "image_digest": digest,
        "workspace_root": str(workspace_root),
        "credential_profile_id": "credentials-disabled",
        "observed_runtime": runtime,
        "kubernetes": "STUBBED at the test topology — NOT validated",
        **evidence,
        "checks": st.rows,
    }
    Path(args.evidence).write_text(json.dumps(payload, indent=2, sort_keys=True))
    notice("container-e2e-summary",
           f"{status} {payload['checks_passed']}/{payload['checks_total']} "
           f"approved={str(evidence.get('approval_plan_hash',''))[:16]} "
           f"applied={str(evidence.get('applied_plan_hash',''))[:16]} "
           f"uid_gid={runtime.get('uid','?')}:{runtime.get('gid','?')} "
           f"rootfs={runtime.get('rootfs','?')}")
    print("\n" + "=" * 72)
    print(f"CONTAINERIZED E2E: {status} "
          f"({payload['checks_passed']}/{payload['checks_total']} checks)")
    for row in st.failed:
        print(f"  FAILED: {row['check']}")
    print("=" * 72)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
