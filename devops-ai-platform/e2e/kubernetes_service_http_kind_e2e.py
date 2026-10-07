#!/usr/bin/env python3
"""Phase 8.6-A Workstream B -- the authoritative Kubernetes proof.

Every earlier Kubernetes E2E drove ``KubectlRunnerService`` directly
from the test process. That proves the runner, but it steps over the
part of the system an operator actually uses, so an API that bypassed
approval, a request field that never reached the engine, or a boundary
enforced only in test wiring would all have gone unnoticed.

This driver instantiates NOTHING on the authoritative path. It speaks
HTTP to a real deployment-service container, which runs the real
DeploymentEngine, the real KubectlRunnerService and the real
ContainerKubectlSandbox against a real Kind cluster:

    runner -> HTTP -> deployment-service container
           -> DeploymentAPI -> DeploymentEngine
           -> KubectlRunnerService -> ContainerKubectlSandbox
           -> kubectl (pinned, digest-addressed) -> Kind

The only objects imported from the application are value readers used
to describe evidence. No engine, runner or sandbox is constructed here.

Usage:
    python e2e/kubernetes_service_http_kind_e2e.py \
        --service-image <image> --sandbox-image <digest-pinned> \
        --cluster ares-e2e
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess  # noqa: S404 - E2E driver; orchestrates docker/kind/kubectl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from e2e.evidence_provenance import provenance, seal  # noqa: E402
# The deployment-service verifies that the requested revision exists
# before it will plan anything. 8.5-A already ships a deterministic,
# host-owned endpoint for exactly this; reusing it keeps one
# implementation rather than a second, divergent stub. It serves
# repository metadata only -- it is NOT a Kubernetes API server and
# nothing on the Kubernetes path is stubbed.
from e2e.terraform_sandbox_container_e2e import (  # noqa: E402
    host_gateway_ip,
    start_commit_stub,
)

SERVICE_NAME = "ares-k8s-http-service"
REDIS_NAME = "ares-k8s-http-redis"
SERVICE_NET = "ares-k8s-http-net"
SERVICE_PORT = 8041
NAMESPACE = "devops-production-namespace"
CREDENTIAL_PROFILE = "ares-k8s-deployer-v1"

RESULTS: List[Dict[str, Any]] = []


def notice(message: str) -> None:
    print(f"[8.6-B] {message}", flush=True)


def record(name: str, requested: str, observed: str, ok: bool) -> bool:
    RESULTS.append({"check": name, "requested": requested,
                    "observed": observed, "status": "PASS" if ok else "FAIL"})
    print(f"  [{'PASS' if ok else 'FAIL'}] {name} :: observed={observed}", flush=True)
    return ok


def sh(argv: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def must(argv: List[str], what: str, timeout: int = 300) -> str:
    out = sh(argv, timeout=timeout)
    if out.returncode != 0:
        raise RuntimeError(f"{what} failed: {(out.stderr or out.stdout)[-500:]}")
    return out.stdout


# --------------------------------------------------------------- HTTP client

def api(method: str, path: str, body: Optional[dict] = None,
        expect: Tuple[int, ...] = (200, 201)) -> Tuple[int, Any]:
    """The only way this driver is allowed to touch the system."""
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        f"http://127.0.0.1:{SERVICE_PORT}{path}", data=data, method=method,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            payload = response.read()
            parsed = json.loads(payload) if payload else {}
            return response.status, parsed
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        try:
            parsed = json.loads(payload)
        except Exception:  # noqa: BLE001
            parsed = {"raw": payload.decode(errors="replace")[:600]}
        if expect and exc.code not in expect:
            return exc.code, parsed
        return exc.code, parsed


def wait_for_health(timeout: int = 180) -> dict:
    deadline, last = time.time() + timeout, ""
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{SERVICE_PORT}/health", timeout=5) as response:
                if response.status == 200:
                    return json.loads(response.read())
        except Exception as exc:  # noqa: BLE001
            last = f"{type(exc).__name__}: {exc}"
        time.sleep(2)
    logs = sh(["docker", "logs", "--tail", "60", SERVICE_NAME])
    raise RuntimeError(f"deployment-service never became healthy ({last}); "
                       f"logs: {(logs.stdout + logs.stderr)[-900:]}")


# ------------------------------------------------------------ cluster set-up

def kubectl(cluster: str, *args: str, timeout: int = 180) -> subprocess.CompletedProcess:
    return sh(["kubectl", "--context", f"kind-{cluster}", *args], timeout=timeout)


def ensure_namespace(cluster: str) -> None:
    kubectl(cluster, "create", "namespace", NAMESPACE)
    must(["kubectl", "--context", f"kind-{cluster}", "get", "namespace", NAMESPACE],
         "namespace creation")


def apply_least_privilege_rbac(cluster: str) -> str:
    """A namespaced Role only. No ClusterRole, no wildcard verbs."""
    rbac = f"""
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ares-deployer
  namespace: {NAMESPACE}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ares-deployer
  namespace: {NAMESPACE}
rules:
  - apiGroups: ["apps"]
    resources: ["deployments", "deployments/status"]
    verbs: ["get", "list", "watch", "create", "update", "patch"]
  - apiGroups: [""]
    resources: ["services", "pods"]
    verbs: ["get", "list", "watch", "create", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ares-deployer
  namespace: {NAMESPACE}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ares-deployer
subjects:
  - kind: ServiceAccount
    name: ares-deployer
    namespace: {NAMESPACE}
"""
    path = Path("/tmp/ares-k8s-http-rbac.yaml")
    path.write_text(rbac)
    must(["kubectl", "--context", f"kind-{cluster}", "apply", "-f", str(path)],
         "RBAC apply")
    cluster_roles = kubectl(cluster, "get", "clusterrole", "-o", "name")
    mine = [line for line in cluster_roles.stdout.splitlines()
            if "ares-deployer" in line]
    record("rbac:least-privilege-namespaced-only",
           "a namespaced Role and RoleBinding, and no ClusterRole",
           f"clusterroles_named_ares={mine}", not mine)
    return "ares-deployer"


def build_sanitized_kubeconfig(cluster: str, control_plane: str,
                               service_account: str) -> Tuple[Path, str, str]:
    """A token-bound kubeconfig for the least-privilege SA.

    The token is written to a file mounted read-only into the service.
    It is never printed, logged or hashed into evidence.
    """
    ca = must(["kubectl", "--context", f"kind-{cluster}", "config", "view",
               "--raw", "-o",
               "jsonpath={.clusters[?(@.name==\"kind-" + cluster + "\")]"
               ".cluster.certificate-authority-data}"], "CA extraction").strip()
    if not ca:
        raise RuntimeError("could not read the cluster CA from the kind context")
    fingerprint = hashlib.sha256(base64.b64decode(ca)).hexdigest()

    token = must(["kubectl", "--context", f"kind-{cluster}", "-n", NAMESPACE,
                  "create", "token", service_account, "--duration=2h"],
                 "token mint").strip()
    # The API endpoint as seen FROM the sandbox network: the control
    # plane's container name, not the host-published 127.0.0.1 port.
    server = f"https://{control_plane}:6443"
    kubeconfig = f"""apiVersion: v1
kind: Config
clusters:
  - name: ares
    cluster:
      server: {server}
      certificate-authority-data: {ca}
contexts:
  - name: ares
    context:
      cluster: ares
      user: ares
      namespace: {NAMESPACE}
current-context: ares
users:
  - name: ares
    user:
      token: {token}
"""
    path = Path("/tmp/ares-k8s-http-kubeconfig")
    path.write_text(kubeconfig)
    path.chmod(0o644)
    return path, server, fingerprint


# ------------------------------------------------------- service container

def start_redis(redis_image: str) -> None:
    sh(["docker", "rm", "-f", REDIS_NAME])
    sh(["docker", "network", "rm", SERVICE_NET])
    must(["docker", "network", "create", SERVICE_NET], "service network create")
    must(["docker", "run", "-d", "--name", REDIS_NAME, "--network", SERVICE_NET,
          "--network-alias", "redis", redis_image], "redis start")
    deadline = time.time() + 60
    while time.time() < deadline:
        if "PONG" in sh(["docker", "exec", REDIS_NAME, "redis-cli", "ping"]).stdout.upper():
            return
        time.sleep(1)
    raise RuntimeError("redis did not become ready within 60s")


def start_service(service_image: str, sandbox_digest: str, kubeconfig: Path,
                  workspace_root: Path, sandbox_network: str,
                  network_identity: str, peers: List[str],
                  api_server: str, ca_fingerprint: str,
                  commit_api: str) -> None:
    sh(["docker", "rm", "-f", SERVICE_NAME])
    argv = [
        "docker", "run", "-d", "--name", SERVICE_NAME,
        "--network", SERVICE_NET,
        "-p", f"{SERVICE_PORT}:8030",
        "-e", "REDIS_HOST=redis", "-e", "REDIS_PORT=6379",
        # TRUSTED control plane. It needs daemon authority to launch the
        # sandbox; the sandbox itself never receives the socket. This is
        # the documented v1 residual risk, not an accident.
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", f"{workspace_root}:{workspace_root}",
        "-v", f"{kubeconfig}:/etc/ares/kubeconfig:ro",
        "-e", "DEPLOYMENT_EXECUTION_ENABLED=true",
        "-e", f"DEPLOYMENT_WORKSPACE_ROOT={workspace_root}",
        "-e", "DEPLOYMENT_KUBECONFIG_PATH=/etc/ares/kubeconfig",
        "-e", f"DEPLOYMENT_KUBERNETES_NAMESPACE={NAMESPACE}",
        "-e", f"DEPLOYMENT_ALLOWED_NAMESPACES={NAMESPACE}",
        "-e", f"DEPLOYMENT_K8S_CREDENTIAL_PROFILE={CREDENTIAL_PROFILE}",
        # Host-owned pinning: the endpoint and CA the approval is bound to.
        "-e", f"DEPLOYMENT_K8S_API_SERVER={api_server}",
        "-e", f"DEPLOYMENT_K8S_CA_FINGERPRINT={ca_fingerprint}",
        "-e", f"DEPLOYMENT_KUBECTL_SANDBOX_IMAGE={sandbox_digest}",
        "-e", "DEPLOYMENT_KUBECTL_SANDBOX_VERSION=v1.31.4",
        # Workstream A: the dedicated destination-isolated network, its
        # canonical identity, and the only peers the sandbox may reach.
        "-e", f"DEPLOYMENT_KUBECTL_SANDBOX_NETWORK={sandbox_network}",
        "-e", f"DEPLOYMENT_K8S_SANDBOX_NETWORK_IDENTITY={network_identity}",
        "-e", f"DEPLOYMENT_K8S_SANDBOX_PEERS={','.join(peers)}",
        "-e", "DEPLOYMENT_CREDENTIAL_ENV_KEYS=",
        "-e", f"DEPLOYMENT_SOURCE_API_BASE_URL={commit_api}",
        # Host-owned and deny-by-default: an empty allowlist blocks
        # every URL. The harness endpoint is named explicitly here; the
        # SSRF control itself is untouched.
        "-e", f"HEALTHCHECK_ALLOWED_HOSTS={urlparse(commit_api).hostname}",
        service_image,
    ]
    out = sh(argv)
    if out.returncode != 0:
        raise RuntimeError(f"service container failed to start: {out.stderr[-600:]}")


def service_exec(command: str) -> subprocess.CompletedProcess:
    return sh(["docker", "exec", SERVICE_NAME, "sh", "-c", command])


# ------------------------------------------------------------- the payload

FIXTURE_REPO = "ares-e2e/fixture"
FIXTURE_SHA = "b" * 40

#: The committed fixture manifest, which the real IaCValidator accepts.
#: A hand-rolled manifest would be rejected for unrelated reasons and
#: the Kubernetes boundary would never be reached.
MANIFEST = (ROOT / "e2e" / "fixtures" / "k8s-deployment.yaml").read_text()
WORKLOAD_NAME = "checkout-service"


def manifest_for(workload_image: str) -> str:
    return MANIFEST.replace("WORKLOAD_IMAGE_REF", workload_image)


def payload(manifest: str) -> dict:
    fixtures = ROOT / "e2e" / "fixtures"
    return {
        "repository_id": 1,
        "repository_name": FIXTURE_REPO,
        "requested_by": "ares-8.6-b",
        "dockerfile": (fixtures / "Dockerfile").read_text(),
        "k8s_yaml": manifest,
        "terraform_tf": "",
        "pipeline_yaml": (fixtures / "pipeline.yaml").read_text(),
        "components": ["dockerfile", "kubernetes", "pipeline"],
        "source_revision": {"head_sha": FIXTURE_SHA},
    }


def dry_run(body: dict, expect: Tuple[int, ...] = (200, 201)) -> Tuple[int, Any]:
    return api("POST", "/api/internal/deployments/dry-run", body, expect=expect)


def execute_body(body: dict, dry: dict, **over: Any) -> dict:
    out = {k: body[k] for k in ("dockerfile", "k8s_yaml", "terraform_tf",
                                "pipeline_yaml", "components")}
    out.update({"artifact_hash": dry.get("artifact_hash"),
                "plan_hash": dry.get("plan_hash"),
                "namespace": NAMESPACE})
    out.update(over)
    return out


def approve(run_id: str, dry: dict) -> Tuple[int, Any]:
    return api("POST", f"/api/internal/deployments/{run_id}/approve",
               {"approved_by": "ares-8.6-b", "artifact_hash": dry.get("artifact_hash"),
                "plan_hash": dry.get("plan_hash")})


def k8s_leg(result: dict) -> dict:
    """The Kubernetes leg of an EXECUTED run."""
    execution = result.get("execution") or {}
    return (execution.get("kubernetes_apply") or execution.get("kubernetes")
            or {})


def k8s_dry(result: dict) -> dict:
    """The Kubernetes leg of a DRY RUN."""
    return result.get("kubernetes_dry_run") or {}


# ---------------------------------------------------------------- the proof

def run_sequence(cluster: str, control_plane: str, workload_image: str) -> None:
    manifest = manifest_for(workload_image)
    body = payload(manifest)

    # ---- 8/9. dry run over HTTP, with real server-side validation ----
    status, dry = dry_run(body)
    run_id = dry.get("id") or dry.get("run_id") or ""
    record("http:dry-run-accepted",
           "the real service accepts a dry run over HTTP",
           f"status={status} state={dry.get('state')} run_id={run_id or 'ABSENT'} "
           f"detail={json.dumps(dry)[:200] if status not in (200, 201) else ''}",
           status in (200, 201) and dry.get("state") == "AWAITING_APPROVAL"
           and bool(run_id) and bool(dry.get("plan_hash")))
    if not run_id:
        for name in ("http:server-side-dry-run-performed", "approval:identity-captured",
                     "http:approval-accepted", "http:execute-over-the-real-path",
                     "manifest:approved-equals-applied",
                     "manifest:no-post-approval-replan"):
            record(name, "the sequence continues from an accepted dry run",
                   "NOT VERIFIED: the dry run produced no run id", False)
        return

    leg = k8s_dry(dry)
    record("http:server-side-dry-run-performed",
           "validation happened on the API server, not on the client",
           f"kubernetes_dry_run={json.dumps(leg)[:220]}",
           leg.get("status") == "PASS")

    # ---- 10. the approval identity the service itself derived ----
    identity = leg.get("execution_identity") or {}
    record("approval:identity-captured",
           "the approval records the cluster, namespace and network it was taken against",
           f"namespace={identity.get('namespace')!r} "
           f"api_server={identity.get('api_server')!r} "
           f"network={str(identity.get('network_identity'))[:40]!r} "
           f"workload_policy={str(identity.get('workload_identity_policy'))[:40]!r}",
           bool(identity.get("namespace")) and bool(identity.get("api_server"))
           and bool(identity.get("network_identity")))

    # ---- 11. approve ----
    code, approved = approve(run_id, dry)
    record("http:approval-accepted", "the hash-bound approval is accepted",
           f"status={code} state={approved.get('state')}",
           code in (200, 201) and approved.get("state") == "APPROVED")

    # ---- 12. execute over HTTP ----
    code, executed = api("POST", f"/api/internal/deployments/{run_id}/execute",
                         execute_body(body, dry))
    applied = k8s_leg(executed)
    record("http:execute-over-the-real-path",
           "the mutation is driven through the service, not the runner",
           f"status={code} state={executed.get('state')} "
           f"kubernetes={json.dumps(applied)[:220]}",
           code in (200, 201) and applied.get("status") == "PASS")

    # ---- 13. approved manifest == applied manifest ----
    approved_hash = identity.get("approved_manifest_hash") or dry.get("artifact_hash")
    applied_hash = (applied.get("applied_manifest_hash")
                    or executed.get("artifact_hash"))
    record("manifest:approved-equals-applied",
           "the bytes approved are the bytes applied",
           f"approved={str(approved_hash)[:20]} applied={str(applied_hash)[:20]}",
           bool(approved_hash) and approved_hash == applied_hash)
    replanned = (executed.get("replanned_after_approval")
                 if "replanned_after_approval" in executed
                 else applied.get("replanned_after_approval"))
    record("manifest:no-post-approval-replan",
           "no second artifact was produced after approval",
           f"replanned_after_approval={replanned}", replanned in (False, None))

    # ---- 14/15. the cluster really changed, and the rollout converged ----
    got = kubectl(cluster, "-n", NAMESPACE, "get", "deployment", WORKLOAD_NAME,
                  "-o", "jsonpath={.metadata.name}")
    record("cluster:deployment-exists",
           "the Deployment exists in the real cluster after execution",
           f"name={got.stdout.strip()!r} rc={got.returncode} "
           f"err={got.stderr.strip()[:120]!r}",
           got.stdout.strip() == WORKLOAD_NAME)
    rollout = kubectl(cluster, "-n", NAMESPACE, "rollout", "status",
                      f"deployment/{WORKLOAD_NAME}", "--timeout=180s", timeout=240)
    record("cluster:rollout-converged", "the rollout reaches a ready state",
           f"rc={rollout.returncode} out={rollout.stdout.strip()[:140]!r} "
           f"err={rollout.stderr.strip()[:140]!r}", rollout.returncode == 0)

    # ---- 18. tamper: execute a manifest that was never approved ----
    tampered = dict(body)
    tampered["k8s_yaml"] = manifest.replace("replicas: 1", "replicas: 7")
    code, result = api("POST", f"/api/internal/deployments/{run_id}/execute",
                       execute_body(tampered, dry), expect=(200, 201, 400, 409, 422))
    state = result.get("state", "")
    # A 404 would mean the run was never found, which proves nothing
    # about tamper rejection; it must be a real refusal of a real run.
    record("tamper:unapproved-manifest-is-refused",
           "a manifest differing from the approved one cannot execute",
           f"status={code} state={state}",
           code != 404 and state not in ("DEPLOYED", "HEALTH_CHECKING"))
    live = kubectl(cluster, "-n", NAMESPACE, "get", "deployment", WORKLOAD_NAME,
                   "-o", "jsonpath={.spec.replicas}")
    record("tamper:cluster-was-not-mutated",
           "the refused run changed nothing in the cluster",
           f"replicas={live.stdout.strip()!r} rc={live.returncode}",
           live.returncode == 0 and live.stdout.strip() == "1")

    # ---- 19. namespace / credential / cluster switches ----
    code, result = api("POST", f"/api/internal/deployments/{run_id}/execute",
                       execute_body(body, dry, namespace="kube-system"),
                       expect=(200, 201, 400, 403, 409, 422))
    record("switch:namespace-after-approval-is-refused",
           "a different namespace cannot reuse this approval",
           f"status={code} state={result.get('state')}",
           code != 404 and result.get("state") not in ("DEPLOYED", "HEALTH_CHECKING"))

    hijack = manifest.replace("kind: Deployment",
                              "kind: Deployment", 1).replace(
        "metadata:\n  name: checkout-service",
        "metadata:\n  namespace: kube-system\n  name: checkout-service", 1)
    code, result = dry_run(payload(hijack), expect=(200, 201, 400, 422))
    hijack_leg = k8s_dry(result)
    record("switch:manifest-namespace-hijack-is-refused",
           "a manifest naming another namespace is rejected at validation",
           f"status={code} kubernetes={json.dumps(hijack_leg)[:180]} "
           f"state={result.get('state')}",
           code != 422 and hijack_leg.get("status") != "PASS")

    # ---- 20. Secret / PVC / workload-identity regressions, over HTTP ----
    escalations = {
        "secret-volume":
            (manifest.replace("      automountServiceAccountToken: false",
                              "      automountServiceAccountToken: false\n"
                              "      volumes:\n        - name: stolen\n"
                              "          secret:\n            secretName: kube-root-ca.crt")),
        "service-account-token":
            (manifest.replace("automountServiceAccountToken: false",
                              "automountServiceAccountToken: true")),
        "deployer-identity-reuse":
            (manifest.replace("      automountServiceAccountToken: false",
                              "      serviceAccountName: ares-deployer\n"
                              "      automountServiceAccountToken: false")),
        "arbitrary-pvc":
            (manifest.replace("      automountServiceAccountToken: false",
                              "      automountServiceAccountToken: false\n"
                              "      volumes:\n        - name: stolen\n"
                              "          persistentVolumeClaim:\n"
                              "            claimName: someone-elses-data")),
    }
    for label, bad in escalations.items():
        code, result = dry_run(payload(bad), expect=(200, 201, 400, 422))
        bad_leg = k8s_dry(result)
        record(f"policy:{label}-is-refused",
               "privilege escalation through the manifest is rejected by policy",
               f"status={code} kubernetes={json.dumps(bad_leg)[:180]} "
               f"state={result.get('state')}",
               code != 422 and bad_leg.get("status") != "PASS")

    # ---- 16/17. rollback ----
    code, result = api("POST", f"/api/internal/deployments/{run_id}/rollback", {},
                       expect=(200, 201, 202, 400, 404, 405, 409, 422))
    if code in (404, 405):
        record("rollback:performed",
               "a rollback path returns the workload to a known good state",
               f"NOT VERIFIED: the service exposes no rollback endpoint "
               f"(status={code}); rollback is proven by the live Kind E2E's "
               f"rollout_undo path, not here", False)
    else:
        record("rollback:performed",
               "a rollback path returns the workload to a known good state",
               f"status={code} state={result.get('state')}", code in (200, 201, 202))
    after = kubectl(cluster, "-n", NAMESPACE, "get", "deployment", WORKLOAD_NAME,
                    "-o", "jsonpath={.status.replicas}")
    record("rollback:workload-still-consistent",
           "the workload is in a defined state afterwards",
           f"replicas={after.stdout.strip()!r} rc={after.returncode}",
           after.returncode == 0)


def check_sandbox_runtime_posture(sandbox_digest: str, sandbox_network: str) -> None:
    """Observe the sandbox the SERVICE launched, not one we launched.

    Every probe fails closed: if the property cannot be observed, that
    is a FAIL, never an implicit pass.
    """
    inspect = sh(["docker", "ps", "-a", "--filter", "name=ares-kubectl-",
                  "--format", "{{.Names}}"])
    names = [n for n in inspect.stdout.split() if n.startswith("ares-kubectl-")]
    if not names:
        for name in ("sandbox:observed-by-the-service", "sandbox:no-docker-socket",
                     "sandbox:non-root", "sandbox:read-only-rootfs",
                     "sandbox:no-new-privileges", "sandbox:all-capabilities-dropped",
                     "sandbox:on-the-isolated-network"):
            record(name, "the service-launched sandbox is inspectable",
                   "NOT VERIFIED: no ares-kubectl-* container was retained", False)
        return
    target = names[0]
    record("sandbox:observed-by-the-service",
           "the sandbox container the service itself launched is inspected",
           f"container={target}", True)

    def field(fmt: str) -> str:
        out = sh(["docker", "inspect", "-f", fmt, target])
        return out.stdout.strip() if out.returncode == 0 else ""

    binds = field("{{json .HostConfig.Binds}}")
    record("sandbox:no-docker-socket",
           "the untrusted sandbox never receives daemon authority",
           f"binds={binds[:200]!r}",
           bool(binds) and "docker.sock" not in binds and "containerd.sock" not in binds)
    user = field("{{.Config.User}}")
    record("sandbox:non-root", "the sandbox runs as a non-root uid",
           f"user={user!r}", bool(user) and not user.startswith(("0:", "root")) )
    readonly = field("{{.HostConfig.ReadonlyRootfs}}")
    record("sandbox:read-only-rootfs", "the root filesystem is read-only",
           f"ReadonlyRootfs={readonly!r}", readonly == "true")
    secopt = field("{{json .HostConfig.SecurityOpt}}")
    record("sandbox:no-new-privileges", "privilege escalation is disabled",
           f"SecurityOpt={secopt[:120]!r}", "no-new-privileges" in (secopt or ""))
    capdrop = field("{{json .HostConfig.CapDrop}}")
    record("sandbox:all-capabilities-dropped", "every capability is dropped",
           f"CapDrop={capdrop[:120]!r}", "ALL" in (capdrop or ""))
    networks = field("{{json .NetworkSettings.Networks}}")
    try:
        joined = sorted(json.loads(networks or "{}").keys())
    except Exception:  # noqa: BLE001
        joined = []
    record("sandbox:on-the-isolated-network",
           "the sandbox ran only on the dedicated destination-isolated network",
           f"networks={joined}", joined == [sandbox_network])


def build_service_image(base_image: str) -> str:
    """The REAL service image -- the same Dockerfile 8.5-A proves."""
    tag = "ares/deployment-service:k8s-http-e2e"
    notice(f"building deployment-service image {tag}")
    build = sh(["docker", "build", "-f", "deployment_service/Dockerfile.e2e",
                "--build-arg", f"BASE_IMAGE={base_image}", "-t", tag, "."],
               timeout=1800)
    if build.returncode != 0:
        raise RuntimeError(
            f"deployment-service image build failed: "
            f"{(build.stderr or build.stdout)[-900:]}")
    return tag


def build_sandbox_image(base_image: str, registry: str, kubectl_version: str) -> str:
    """Build the kubectl sandbox and resolve it to an immutable digest.

    The sandbox spec refuses a tag, so the image is pushed to the
    job-local registry purely to acquire a repository digest. The
    kubectl binary comes from the committed checksum-verified download,
    never from inside the image build.
    """
    import shutil
    import tempfile
    import uuid as _uuid
    binary = os.environ.get("ARES_KUBECTL_BINARY", "")
    if not binary or not Path(binary).is_file():
        raise RuntimeError(
            "ARES_KUBECTL_BINARY must point at the checksum-verified kubectl; "
            "this driver will not download one itself")
    ctx = Path(tempfile.mkdtemp(prefix="ares-k8s-http-ctx-"))
    shutil.copy(ROOT / "e2e" / "kubectl-sandbox" / "Dockerfile", ctx / "Dockerfile")
    shutil.copy(binary, ctx / "kubectl")
    repo = f"{registry}/ares-kubectl-sandbox"
    tag = f"{repo}:{_uuid.uuid4().hex[:10]}"
    must(["docker", "build", "--build-arg", f"BASE_IMAGE={base_image}",
          "-t", tag, str(ctx)], "sandbox image build", timeout=1800)
    must(["docker", "push", tag], "sandbox image push", timeout=900)
    digests = json.loads(must(["docker", "image", "inspect", tag, "-f",
                               "{{json .RepoDigests}}"], "digest resolve").strip()
                         or "[]")
    pinned = next((d for d in digests if d.startswith(repo + "@")), "")
    if "@sha256:" not in pinned:
        raise RuntimeError(
            f"could not resolve a repository digest for {tag}; observed {digests}")
    return pinned


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cluster", default="ares-e2e")
    parser.add_argument("--service-image", default="")
    parser.add_argument("--sandbox-image", default="")
    parser.add_argument("--base-image", default="")
    parser.add_argument("--registry", default="")
    parser.add_argument("--kubectl-version", default="v1.31.4")
    parser.add_argument("--redis-image", default="redis:7-alpine")
    parser.add_argument("--workload-image", default="ares-e2e-workload:local")
    parser.add_argument("--evidence", default="e2e-evidence/kubernetes-http-e2e.json")
    args = parser.parse_args()

    control_plane = f"{args.cluster}-control-plane"
    workspace_root = Path("/tmp/ares-k8s-http-workspace")
    workspace_root.mkdir(parents=True, exist_ok=True)
    exec_network = None
    started = False

    from deployment_service.infrastructure.sandbox.kubernetes_sandbox_network import (
        PerExecutionNetwork,
    )

    try:
        # Image builds live inside the try so a build failure produces
        # evidence and an annotation instead of a silent traceback.
        if not args.service_image:
            if not args.base_image:
                raise RuntimeError("--service-image or --base-image is required")
            args.service_image = build_service_image(args.base_image)
        if not args.sandbox_image:
            if not (args.base_image and args.registry):
                raise RuntimeError(
                    "--sandbox-image, or --base-image with --registry, is required")
            args.sandbox_image = build_sandbox_image(
                args.base_image, args.registry, args.kubectl_version)
        record("build:images-ready",
               "the real service image and a digest-pinned sandbox image exist",
               f"service={args.service_image} sandbox={args.sandbox_image[:72]}",
               "@sha256:" in args.sandbox_image)

        # ---- 1-3. cluster, namespace, least-privilege RBAC ----
        alive = sh(["docker", "inspect", "-f", "{{.State.Running}}", control_plane])
        if alive.stdout.strip() != "true":
            raise RuntimeError(
                f"the Kind control plane {control_plane!r} is not running; this "
                f"driver requires a real cluster and will not fake one")
        record("cluster:kind-is-live", "a real Kind control plane is running",
               f"container={control_plane} running=true", True)
        loaded = sh(["kind", "load", "docker-image", args.workload_image,
                     "--name", args.cluster], timeout=600)
        record("cluster:workload-image-loaded",
               "the workload image is in the cluster store, not fetched from a registry",
               f"image={args.workload_image} rc={loaded.returncode} "
               f"err={loaded.stderr.strip()[:140]!r}", loaded.returncode == 0)
        ensure_namespace(args.cluster)
        record("cluster:namespace-ready", "the execution namespace exists",
               f"namespace={NAMESPACE}", True)
        service_account = apply_least_privilege_rbac(args.cluster)

        # ---- 4. the destination-isolated network (host-owned) ----
        exec_network = PerExecutionNetwork(approved_peers=(control_plane,))
        identity = exec_network.create()
        record("network:dedicated-isolated-network",
               "a dedicated internal network carrying only the API endpoint",
               f"name={exec_network.name} internal={identity.internal} "
               f"driver={identity.driver} peers={list(identity.approved_peers)}",
               identity.internal and identity.driver == "bridge"
               and list(identity.approved_peers) == [control_plane])

        # ---- 5-7. kubeconfig, redis, the real service container ----
        kubeconfig, api_server, ca_fingerprint = build_sanitized_kubeconfig(
            args.cluster, control_plane, service_account)
        record("credentials:sanitized-kubeconfig",
               "a token-bound kubeconfig for the least-privilege account",
               f"server={api_server} ca_sha256={ca_fingerprint[:16]}... "
               f"profile={CREDENTIAL_PROFILE}", True)
        stub, stub_port = start_commit_stub()
        commit_api = f"http://{host_gateway_ip()}:{stub_port}"
        start_redis(args.redis_image)
        start_service(args.service_image, args.sandbox_image, kubeconfig,
                      workspace_root, exec_network.name, identity.digest(),
                      [control_plane], api_server, ca_fingerprint, commit_api)
        started = True
        # The service container must also reach the sandbox network's
        # peers to launch containers on it; the daemon does that, not
        # the service, so only the Kind network join is required here.
        sh(["docker", "network", "connect", SERVICE_NET, control_plane])
        health = wait_for_health()
        record("http:service-is-healthy",
               "the real deployment-service container answers /health",
               f"status={health.get('status', 'unknown')}", True)

        # ---- 8-20 ----
        run_sequence(args.cluster, control_plane, args.workload_image)
        check_sandbox_runtime_posture(args.sandbox_image, exec_network.name)

    except Exception as exc:  # noqa: BLE001
        import traceback
        record("harness:completed", "the driver reached the end of the sequence",
               f"{type(exc).__name__}: {str(exc)[:600]}", False)
        notice("traceback:\n" + traceback.format_exc()[-3000:])
        logs = sh(["docker", "logs", "--tail", "120", SERVICE_NAME])
        if logs.stdout or logs.stderr:
            notice(f"service logs:\n{(logs.stdout + logs.stderr)[-2500:]}")
    finally:
        if started:
            logs = sh(["docker", "logs", "--tail", "400", SERVICE_NAME])
            Path("/tmp/ares-k8s-http-service.log").write_text(
                logs.stdout + logs.stderr)
        sh(["docker", "rm", "-f", SERVICE_NAME])
        sh(["docker", "rm", "-f", REDIS_NAME])
        if exec_network is not None:
            try:
                exec_network.destroy()
            except Exception:  # noqa: BLE001
                pass
        sh(["docker", "network", "rm", SERVICE_NET])

    passed = sum(1 for r in RESULTS if r["status"] == "PASS")
    total = len(RESULTS)
    evidence = {
        "suite": "phase-8.6-A-workstream-B-service-http-kind",
        "authoritative_path": ("runner -> HTTP -> deployment-service container -> "
                               "DeploymentAPI -> DeploymentEngine -> "
                               "KubectlRunnerService -> ContainerKubectlSandbox -> Kind"),
        "driver_instantiates_engine_or_runner": False,
        "cluster": args.cluster,
        "namespace": NAMESPACE,
        "credential_profile": CREDENTIAL_PROFILE,
        "kubectl_sandbox_image": args.sandbox_image,
        "service_image": args.service_image,
        "passed": passed, "total": total,
        "checks": RESULTS,
        "provenance": provenance(),
    }
    out = Path(args.evidence)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=2))
    seal(out)
    notice(f"{passed}/{total} PASS -- evidence at {out}")
    print(f"::notice title=8.6-B::service->HTTP->Kind E2E: {passed}/{total} PASS, "
          f"{total - passed} FAIL")
    # GitHub keeps only ten annotations per step and raw log download
    # is unreliable for this repository, so the full result table also
    # goes out as one compact, self-describing annotation.
    import gzip as _gzip
    packed = base64.b64encode(_gzip.compress(
        json.dumps(RESULTS, separators=(",", ":")).encode())).decode()
    for index in range(0, len(packed), 900):
        print(f"::notice title=8.6-B results {index // 900}::"
              f"{packed[index:index + 900]}")
    for row in RESULTS[:6]:
        if row["status"] != "PASS":
            print(f"::error title=8.6-B FAIL::{row['check']} :: "
                  f"observed={row['observed'][:280]}")
    return 0 if passed == total and total > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
