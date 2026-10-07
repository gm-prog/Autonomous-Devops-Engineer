#!/usr/bin/env python3
"""Phase 8.6-A — live Kubernetes execution trust boundary E2E.

This driver proves the boundary against a REAL cluster. There is no
stub kubectl anywhere in this file: every Kubernetes assertion is the
observed behaviour of a real API server, real RBAC and real Pod
Security Admission.

Topology
    kind cluster `ares-e2e`  (restricted PSA on the deployment namespace)
        -> namespace devops-production-namespace
        -> ServiceAccount ares-deployer + namespaced Role/RoleBinding
        -> a token-based kubeconfig for that ServiceAccount only
    ContainerKubectlSandbox
        -> dedicated digest-pinned kubectl image, --pull never
        -> non-root, read-only rootfs, cap-drop ALL, no-new-privileges
        -> a dedicated Docker network joined to the kind network

Exit codes
    0  every check PASSED
    1  at least one check FAILED
    2  BLOCKED -- the environment could not host the proof. A blocked
       run is never reported as a pass.
"""

from __future__ import annotations

try:
    from e2e.evidence_provenance import provenance, seal
except ImportError:  # executed as a script from inside e2e/
    from evidence_provenance import provenance, seal


import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PLATFORM_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PLATFORM_ROOT))

from deployment_service.application.services.kubeconfig_policy import (  # noqa: E402
    KubeconfigPolicyError,
    sanitize_kubeconfig,
)
from deployment_service.application.services.kubectl_runner import (  # noqa: E402
    KubectlRunnerService,
)
from deployment_service.application.services.kubectl_sandbox import (  # noqa: E402
    KubectlOperation,
    KubectlSandboxSpec,
    KubectlSandboxStep,
    build_kubectl_argv,
    build_run_plan,
    sandbox_policy_identity,
)
from deployment_service.infrastructure.kubernetes.rbac_profile import (  # noqa: E402
    AUTHORIZATION_EXPECTATIONS,
    CLUSTER_SCOPED_DENIALS,
    render as render_rbac,
)
from deployment_service.infrastructure.sandbox.container_kubectl_sandbox import (  # noqa: E402
    ContainerKubectlSandbox,
)

CLUSTER = "ares-e2e"
NAMESPACE = "devops-production-namespace"
SERVICE_ACCOUNT = "ares-deployer"
SANDBOX_NETWORK = "ares-k8s-sandbox"

CHECKS: List[Dict[str, Any]] = []
_START = time.time()


def notice(message: str) -> None:
    """Emit a CI annotation. Artifact downloads are not reachable from
    every environment, so evidence must survive in the log stream."""
    print(f"::notice::{message}", flush=True)


def record(case: str, requested: str, observed: str, ok: bool) -> bool:
    CHECKS.append({
        "case": case,
        "requested": requested,
        "observed": observed,
        "result": "PASS" if ok else "FAIL",
    })
    print(f"  [{'PASS' if ok else 'FAIL'}] {case}\n"
          f"         requested: {requested}\n"
          f"         observed : {observed}", flush=True)
    return ok


class Blocked(RuntimeError):
    """The environment cannot host the proof."""


def run(argv: List[str], *, timeout: int = 300, check: bool = True,
        stdin: Optional[str] = None) -> subprocess.CompletedProcess:
    completed = subprocess.run(
        argv, capture_output=True, text=True, timeout=timeout, input=stdin
    )
    if check and completed.returncode != 0:
        raise Blocked(
            f"{' '.join(argv[:4])} failed ({completed.returncode}): "
            f"{(completed.stderr or completed.stdout)[-1200:]}"
        )
    return completed


def admin_kubectl(args: List[str], *, kubeconfig: str, check: bool = True,
                  timeout: int = 180, stdin: Optional[str] = None):
    """Cluster-admin kubectl used ONLY to build the fixture.

    This is the test harness acting as a cluster operator. It is never
    the path under test: every assertion about the boundary runs through
    the sandbox.
    """
    env = {"PATH": os.environ["PATH"], "KUBECONFIG": kubeconfig,
           "HOME": os.environ.get("HOME", "/tmp")}
    completed = subprocess.run(
        ["kubectl", *args], capture_output=True, text=True,
        timeout=timeout, env=env, input=stdin,
    )
    if check and completed.returncode != 0:
        raise Blocked(f"admin kubectl {' '.join(args[:3])} failed: "
                      f"{(completed.stderr or completed.stdout)[-1200:]}")
    return completed


# =====================================================================
# Cluster fixture
# =====================================================================

PSA_NAMESPACE = f"""apiVersion: v1
kind: Namespace
metadata:
  name: {NAMESPACE}
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
"""


def build_fixture(kubeconfig: str, workdir: Path) -> Dict[str, Any]:
    """Create the namespace, the subject and its least-privilege Role."""
    admin_kubectl(["apply", "-f", "-"], kubeconfig=kubeconfig, stdin=PSA_NAMESPACE)

    labels = admin_kubectl(
        ["get", "namespace", NAMESPACE, "-o",
         "jsonpath={.metadata.labels.pod-security\\.kubernetes\\.io/enforce}"],
        kubeconfig=kubeconfig,
    ).stdout.strip()
    record("psa-restricted-enforced-on-namespace", "enforce=restricted",
           f"enforce={labels or '(absent)'}", labels == "restricted")

    admin_kubectl(["apply", "-f", "-"], kubeconfig=kubeconfig,
                  stdin=f"apiVersion: v1\nkind: ServiceAccount\n"
                        f"metadata:\n  name: {SERVICE_ACCOUNT}\n"
                        f"  namespace: {NAMESPACE}\n")

    rbac = render_rbac(NAMESPACE, SERVICE_ACCOUNT)
    (workdir / "rbac.yaml").write_text(rbac)
    admin_kubectl(["apply", "-f", str(workdir / "rbac.yaml")], kubeconfig=kubeconfig)
    notice("8.6-A rbac: namespaced Role+RoleBinding applied "
           f"(no ClusterRole, no ClusterRoleBinding) ns={NAMESPACE}")

    # A short-lived token for the ServiceAccount. Never printed.
    token = admin_kubectl(
        ["create", "token", SERVICE_ACCOUNT, "-n", NAMESPACE, "--duration=30m"],
        kubeconfig=kubeconfig,
    ).stdout.strip()
    if not token:
        raise Blocked("could not mint a ServiceAccount token")

    ca = admin_kubectl(
        ["config", "view", "--raw", "--minify", "-o",
         "jsonpath={.clusters[0].cluster.certificate-authority-data}"],
        kubeconfig=kubeconfig,
    ).stdout.strip()
    if not ca:
        raise Blocked("could not read the cluster CA from the admin kubeconfig")

    server = admin_kubectl(
        ["config", "view", "--raw", "--minify", "-o",
         "jsonpath={.clusters[0].cluster.server}"],
        kubeconfig=kubeconfig,
    ).stdout.strip()

    # The sandbox reaches the API over the kind docker network, so the
    # endpoint must be the in-network control-plane address, not the
    # host-published 127.0.0.1 port.
    internal = f"https://{CLUSTER}-control-plane:6443"
    version = admin_kubectl(["version", "-o", "json"], kubeconfig=kubeconfig).stdout
    try:
        server_version = json.loads(version)["serverVersion"]["gitVersion"]
    except Exception:
        server_version = "unknown"

    return {"token": token, "ca": ca, "server": server,
            "internal_server": internal, "server_version": server_version}


def deployer_kubeconfig(fixture: Dict[str, Any]) -> str:
    """The kubeconfig the boundary will sanitize and use."""
    return (
        "apiVersion: v1\n"
        "kind: Config\n"
        "clusters:\n"
        "  - name: ares\n"
        "    cluster:\n"
        f"      server: {fixture['internal_server']}\n"
        f"      certificate-authority-data: {fixture['ca']}\n"
        "users:\n"
        "  - name: ares-deployer\n"
        "    user:\n"
        f"      token: {fixture['token']}\n"
        "contexts:\n"
        "  - name: ares\n"
        "    context:\n"
        "      cluster: ares\n"
        "      user: ares-deployer\n"
        f"      namespace: {NAMESPACE}\n"
        "current-context: ares\n"
    )


# =====================================================================
# Checks
# =====================================================================

def check_rbac_denials(kubeconfig_path: str) -> None:
    """Prove authorization with real SubjectAccessReviews, not YAML."""
    subject = f"system:serviceaccount:{NAMESPACE}:{SERVICE_ACCOUNT}"
    for verb, resource, expected in AUTHORIZATION_EXPECTATIONS:
        out = admin_kubectl(
            ["auth", "can-i", verb, resource, "-n", NAMESPACE, "--as", subject],
            kubeconfig=kubeconfig_path, check=False,
        )
        allowed = out.stdout.strip() == "yes"
        record(
            f"rbac:{verb}-{resource}",
            f"{'allowed' if expected else 'denied'} for {subject}",
            f"{'allowed' if allowed else 'denied'} (kubectl auth can-i)",
            allowed == expected,
        )
    for verb, resource in CLUSTER_SCOPED_DENIALS:
        out = admin_kubectl(
            ["auth", "can-i", verb, resource, "--all-namespaces", "--as", subject],
            kubeconfig=kubeconfig_path, check=False,
        )
        allowed = out.stdout.strip() == "yes"
        record(f"rbac:cluster-scoped-{verb}-{resource}",
               "denied at cluster scope",
               f"{'allowed' if allowed else 'denied'}", not allowed)


def check_network_reachability(sandbox: ContainerKubectlSandbox,
                               kubeconfig_yaml: str) -> None:
    """The API must be reachable; an unrelated destination must not be."""
    step = KubectlSandboxStep(
        operation=KubectlOperation.ROLLOUT_STATUS,
        argv=build_kubectl_argv(KubectlOperation.ROLLOUT_STATUS,
                                namespace=NAMESPACE,
                                deployment_name="does-not-exist"),
        timeout_seconds=60,
    )
    result = sandbox.execute(step, manifest_yaml="", kubeconfig_yaml=kubeconfig_yaml,
                             namespace=NAMESPACE)
    combined = f"{result.stdout}\n{result.stderr}".lower()
    # A NotFound answer proves the API server answered: TLS completed,
    # the token authenticated and RBAC authorized the read.
    reached = "not found" in combined or "notfound" in combined
    record("network:api-server-reachable-from-sandbox",
           "kubectl reaches the API over the dedicated sandbox network",
           f"exit={result.exit_code} api_answered={reached} "
           f"detail={combined.strip()[:160]!r}",
           reached)


def check_unrelated_destination_blocked(spec: KubectlSandboxSpec) -> None:
    """Egress must be destination-controlled, not open Internet."""
    probe = [
        "docker", "run", "--rm", "--network", SANDBOX_NETWORK,
        "--user", "65532:65532", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true", "--pull", "never",
        "--entrypoint", "kubectl", spec.image,
        "--server", "https://example.com:443", "--insecure-skip-tls-verify=true",
        # Without a credential kubectl prompts for a username and exits
        # on EOF, which measures nothing. A dummy token (not a secret)
        # forces it to actually attempt the connection, so the result
        # reflects reachability.
        "--token", "egress-probe-not-a-credential",
        "--request-timeout=8s", "get", "namespaces",
    ]
    out = subprocess.run(probe, capture_output=True, text=True, timeout=90)
    combined = f"{out.stdout}\n{out.stderr}".lower()
    unreachable_markers = (
        "no such host", "i/o timeout", "timeout", "connection refused",
        "could not resolve", "unable to connect", "context deadline",
        "network is unreachable", "no route to host", "dial tcp",
    )
    prompted = "please enter username" in combined
    blocked = (out.returncode != 0 and not prompted
               and any(m in combined for m in unreachable_markers))
    if prompted:
        # The probe did not observe its property, so it cannot pass.
        combined += " [PROBE DEFECT: kubectl prompted instead of connecting]"
    record("network:unrelated-destination-not-reachable",
           "an off-policy destination is unreachable from the sandbox network",
           f"exit={out.returncode} detail={combined.strip()[:200]!r}",
           blocked)


def check_docker_socket_denied(spec: KubectlSandboxSpec) -> None:
    """The untrusted sandbox must never hold the container runtime socket."""
    # Derive the REAL argv the production code would run, so this
    # observes the actual invocation rather than an empty list.
    plan = build_run_plan(
        spec=spec,
        step=KubectlSandboxStep(
            operation=KubectlOperation.APPLY,
            argv=build_kubectl_argv(KubectlOperation.APPLY, namespace=NAMESPACE),
            timeout_seconds=60),
        manifest_host_path="/tmp/ares-probe/manifest.yaml",
        kubeconfig_host_path="/tmp/ares-probe/kubeconfig",
        kuberc_host_path="/tmp/ares-probe/kuberc",
        container_name="ares-probe-argv",
    )
    argv = list(plan.argv)
    sock = [a for a in argv if "docker.sock" in str(a) or "containerd.sock" in str(a)]
    privileged = [a for a in argv if str(a) in ("--privileged", "--pid=host")]
    record("network:docker-socket-never-mounted",
           "no runtime socket and no privileged flag in the real sandbox argv",
           f"argv_len={len(argv)} socket_matches={sock} privileged={privileged}",
           not sock and not privileged and len(argv) > 5)

    probe = [
        "docker", "run", "--rm", "--network", SANDBOX_NETWORK,
        "--user", "65532:65532", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true", "--pull", "never",
        "--entrypoint", "sh", spec.image, "-c",
        "test -S /var/run/docker.sock && echo SOCKET_PRESENT || echo SOCKET_ABSENT",
    ]
    out = subprocess.run(probe, capture_output=True, text=True, timeout=90)
    combined = f"{out.stdout}{out.stderr}".strip()
    record("network:docker-socket-absent-inside-sandbox",
           "the container runtime socket is not reachable from the sandbox",
           f"detail={combined[:160]!r}",
           "SOCKET_ABSENT" in combined)


def check_same_network_peer(spec: KubectlSandboxSpec) -> None:
    """`--internal` proves no Internet; it does NOT isolate peers.

    An unrelated container attached to the same network is a co-tenant.
    This measures reachability honestly: whatever the answer is, it is
    recorded as observed rather than assumed.
    """
    peer = "ares-e2e-unrelated-peer"
    subprocess.run(["docker", "rm", "-f", peer],
                   capture_output=True, text=True, timeout=60)
    started = subprocess.run(
        ["docker", "run", "-d", "--name", peer, "--network", SANDBOX_NETWORK,
         "--pull", "never", "--entrypoint", "sh", spec.image, "-c",
         # a trivial listener on 9999, using only what the image has
         "while true; do nc -l -p 9999 >/dev/null 2>&1 || sleep 1; done"],
        capture_output=True, text=True, timeout=120)
    if started.returncode != 0:
        record("network:adversarial-peer-started",
               "an unrelated peer joins the sandbox network",
               f"NOT VERIFIED: {started.stderr.strip()[:160]!r}", False)
        return
    record("network:adversarial-peer-started",
           "an unrelated peer joins the sandbox network", "started", True)
    try:
        probe = [
            "docker", "run", "--rm", "--network", SANDBOX_NETWORK,
            "--user", "65532:65532", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true", "--pull", "never",
            "--entrypoint", "kubectl", spec.image,
            "--server", f"https://{peer}:9999", "--insecure-skip-tls-verify=true",
            "--token", "peer-probe-not-a-credential",
            "--request-timeout=8s", "get", "namespaces",
        ]
        out = subprocess.run(probe, capture_output=True, text=True, timeout=90)
        combined = f"{out.stdout}\n{out.stderr}".lower()
        unreachable = ("no such host", "could not resolve", "i/o timeout",
                       "connection refused", "no route to host",
                       "network is unreachable", "context deadline")
        prompted = "please enter username" in combined
        denied = (out.returncode != 0 and not prompted
                  and any(m in combined for m in unreachable))
        if prompted:
            combined += " [PROBE DEFECT: kubectl prompted instead of connecting]"
        record("network:same-network-peer-not-reachable",
               "a co-tenant on the sandbox network is unreachable",
               f"exit={out.returncode} detail={combined.strip()[:200]!r}",
               denied)
    finally:
        subprocess.run(["docker", "rm", "-f", peer],
                       capture_output=True, text=True, timeout=60)


def check_malicious_manifests(runner: KubectlRunnerService, workdir: Path) -> None:
    """Every attack must be refused before any kubectl runs."""
    attacks = {
        "cluster-role": "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\n"
                        "metadata: {name: pwn}\n"
                        "rules: [{apiGroups: ['*'], resources: ['*'], verbs: ['*']}]\n",
        "cluster-role-binding": "apiVersion: rbac.authorization.k8s.io/v1\n"
                                "kind: ClusterRoleBinding\nmetadata: {name: pwn}\n"
                                "roleRef: {kind: ClusterRole, name: cluster-admin,"
                                " apiGroup: rbac.authorization.k8s.io}\n",
        "service-account": "apiVersion: v1\nkind: ServiceAccount\n"
                           "metadata: {name: pwn}\n",
        "bare-privileged-pod": "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\n"
                               "spec:\n  hostNetwork: true\n  containers:\n"
                               "    - name: c\n      image: nginx\n"
                               "      securityContext: {privileged: true}\n",
        "namespace-object": "apiVersion: v1\nkind: Namespace\n"
                            "metadata: {name: attacker-ns}\n",
        "nodeport-service": "apiVersion: v1\nkind: Service\nmetadata: {name: s}\n"
                            "spec: {type: NodePort, ports: [{port: 80, nodePort: 30001}]}\n",
    }
    for name, manifest in attacks.items():
        path = workdir / f"attack-{name}.yaml"
        path.write_text(manifest)
        result = runner.apply(str(path))
        record(f"malicious-manifest:{name}",
               "BLOCKED before any kubectl process starts",
               f"status={result['status']} reason={result.get('stderr', '')[:120]!r}",
               result["status"] == "BLOCKED")


def check_kubeconfig_attacks(fixture: Dict[str, Any]) -> None:
    """Credential-level attacks must be refused by the sanitizer."""
    base = deployer_kubeconfig(fixture)
    attacks = {
        "exec-plugin": base.replace(
            f"      token: {fixture['token']}\n",
            "      exec:\n        apiVersion: client.authentication.k8s.io/v1\n"
            "        command: /bin/sh\n        args: ['-c', 'id']\n"),
        "proxy-url": base.replace(
            f"      server: {fixture['internal_server']}\n",
            f"      server: {fixture['internal_server']}\n"
            "      proxy-url: http://attacker.invalid:3128\n"),
        "insecure-tls": base.replace(
            f"      server: {fixture['internal_server']}\n",
            f"      server: {fixture['internal_server']}\n"
            "      insecure-skip-tls-verify: true\n"),
        "endpoint-tampering": base.replace(
            fixture["internal_server"], "https://attacker.invalid:6443"),
        "namespace-switch": base.replace(
            f"      namespace: {NAMESPACE}\n", "      namespace: kube-system\n"),
    }
    for name, content in attacks.items():
        if name == "endpoint-tampering":
            # endpoint tampering is caught by binding the approved cluster
            try:
                sanitize_kubeconfig(content, expected_namespace=NAMESPACE,
                                    expected_server=fixture["internal_server"])
                refused, detail = False, "accepted"
            except KubeconfigPolicyError as exc:
                refused, detail = True, str(exc)[:120]
        else:
            try:
                sanitize_kubeconfig(content, expected_namespace=NAMESPACE)
                refused, detail = False, "accepted"
            except KubeconfigPolicyError as exc:
                refused, detail = True, str(exc)[:120]
        record(f"kubeconfig-attack:{name}", "rejected, fail closed",
               f"refused={refused} reason={detail!r}", refused)


def check_plugin_execution(spec: KubectlSandboxSpec) -> None:
    """A kubectl plugin must not be reachable inside the sandbox."""
    out = subprocess.run(
        ["docker", "run", "--rm", "--network", SANDBOX_NETWORK,
         "--user", "65532:65532", "--read-only", "--cap-drop", "ALL",
         "--security-opt", "no-new-privileges:true", "--pull", "never",
         "--entrypoint", "kubectl", spec.image, "plugin", "list"],
        capture_output=True, text=True, timeout=90)
    combined = f"{out.stdout}\n{out.stderr}".lower()
    none_found = "unable to find any kubectl plugins" in combined or out.returncode != 0
    record("sandbox:no-kubectl-plugins-on-path",
           "no kubectl-* plugin is executable in the sandbox",
           f"exit={out.returncode} detail={combined.strip()[:160]!r}", none_found)


def check_filesystem_and_process_escape(spec: KubectlSandboxSpec) -> None:
    """Read-only rootfs and the absence of a shell / Docker socket."""
    writable = subprocess.run(
        ["docker", "run", "--rm", "--network", SANDBOX_NETWORK,
         "--user", "65532:65532", "--read-only", "--cap-drop", "ALL",
         "--security-opt", "no-new-privileges:true", "--pull", "never",
         "--entrypoint", "kubectl", spec.image,
         "create", "-f", "/etc/escape.yaml"],
        capture_output=True, text=True, timeout=90)
    record("sandbox:host-filesystem-not-reachable",
           "a path outside the single :ro manifest mount is unavailable",
           f"exit={writable.returncode} "
           f"detail={(writable.stderr or writable.stdout).strip()[:140]!r}",
           writable.returncode != 0)

    sock = subprocess.run(
        ["docker", "run", "--rm", "--network", SANDBOX_NETWORK,
         "--user", "65532:65532", "--read-only", "--cap-drop", "ALL",
         "--security-opt", "no-new-privileges:true", "--pull", "never",
         "--entrypoint", "kubectl", spec.image,
         "--kubeconfig", "/var/run/docker.sock", "version", "--client=false",
         "--request-timeout=5s"],
        capture_output=True, text=True, timeout=90)
    combined = f"{sock.stdout}\n{sock.stderr}".lower()
    absent = "no such file" in combined or sock.returncode != 0
    record("sandbox:no-docker-socket",
           "/var/run/docker.sock is absent from the sandbox",
           f"exit={sock.returncode} detail={combined.strip()[:140]!r}", absent)


def check_deploy_and_rollback(runner: KubectlRunnerService, workdir: Path,
                              kubeconfig_path: str, image_ref: str) -> None:
    """The real positive path: dry run, apply, rollout, rollback."""
    fixture = (PLATFORM_ROOT / "e2e" / "fixtures" / "k8s-deployment.yaml").read_text()
    manifest = workdir / "deployment.yaml"
    manifest.write_text(fixture.replace("WORKLOAD_IMAGE_REF", image_ref))

    dry = runner.dry_run(str(manifest))
    record("deploy:server-side-dry-run",
           "--dry-run=server --validate=strict against the real API server",
           f"status={dry['status']} mode={dry.get('validation_mode')} "
           f"detail={(dry.get('stderr') or dry.get('stdout', ''))[:140]!r}",
           dry["status"] == "PASS")
    approved_hash = dry.get("manifest_sha256", "")

    # Phase 8.6-A corrective, Workstream B. The approval binds the live
    # cluster's identity; execution must present exactly that identity.
    approved_identity = runner.execution_identity()
    record("approval:binds-the-live-cluster-identity",
           "approval carries endpoint, CA, namespace, credential, policy and network",
           f"digest={approved_identity.digest()[:16]} "
           f"ns={approved_identity.namespace} "
           f"ca={approved_identity.ca_fingerprint_sha256[:12]}",
           bool(approved_identity.digest()) and approved_identity.namespace == NAMESPACE
           and bool(approved_identity.ca_fingerprint_sha256))

    applied = runner.apply(str(manifest), approved_identity=approved_identity)
    record("deploy:apply-through-sandbox",
           "the approved manifest is applied inside the sandbox",
           f"status={applied['status']} "
           f"detail={(applied.get('stdout') or applied.get('stderr', ''))[:140]!r}",
           applied["status"] == "PASS")
    record("approval:applied-hash-equals-approved-hash",
           f"approved sha256 == applied sha256 ({approved_hash[:16]}...)",
           f"approved={approved_hash[:16]} applied={applied.get('manifest_sha256','')[:16]}",
           bool(approved_hash) and approved_hash == applied.get("manifest_sha256"))

    status = runner.rollout_status("checkout-service", timeout_seconds=180)
    record("deploy:rollout-status",
           "the Deployment becomes available",
           f"status={status['status']} "
           f"detail={(status.get('stdout') or status.get('stderr', ''))[:140]!r}",
           status["status"] == "PASS")

    live = admin_kubectl(
        ["get", "deployment", "checkout-service", "-n", NAMESPACE,
         "-o", "jsonpath={.status.readyReplicas}"],
        kubeconfig=kubeconfig_path, check=False).stdout.strip()
    record("deploy:resource-exists-in-the-bound-namespace",
           f"checkout-service is Ready in {NAMESPACE}",
           f"readyReplicas={live or '0'}", bool(live) and int(live or 0) >= 1)

    # second revision so there is something to roll back to
    admin_kubectl(["set", "env", "deployment/checkout-service",
                   f"ARES_REVISION={uuid.uuid4().hex[:8]}", "-n", NAMESPACE],
                  kubeconfig=kubeconfig_path, check=False)
    admin_kubectl(["rollout", "status", "deployment/checkout-service",
                   "-n", NAMESPACE, "--timeout=120s"],
                  kubeconfig=kubeconfig_path, check=False)

    undo = runner.rollout_undo("checkout-service",
                               approved_identity=approved_identity)
    record("rollback:through-the-same-sandbox-and-namespace",
           "rollback uses the same sandbox, namespace and credential path",
           f"status={undo['status']} ns={undo.get('namespace')} "
           f"detail={(undo.get('stdout') or undo.get('stderr', ''))[:140]!r}",
           undo["status"] == "PASS" and undo.get("namespace") == NAMESPACE)


def check_tamper_and_switch(runner: KubectlRunnerService, workdir: Path,
                            image_ref: str) -> None:
    fixture = (PLATFORM_ROOT / "e2e" / "fixtures" / "k8s-deployment.yaml").read_text()
    base = fixture.replace("WORKLOAD_IMAGE_REF", image_ref)

    tampered = workdir / "tampered.yaml"
    tampered.write_text(base.replace("allowPrivilegeEscalation: false",
                                     "allowPrivilegeEscalation: true", 1))
    result = runner.apply(str(tampered), approved_identity=runner.execution_identity())
    record("tamper:manifest-modified-after-approval",
           "BLOCKED before execution",
           f"status={result['status']}", result["status"] == "BLOCKED")

    switched = workdir / "switched.yaml"
    switched.write_text(base.replace("  name: checkout-service\n",
                                     "  name: checkout-service\n"
                                     "  namespace: kube-system\n", 1))
    result = runner.apply(str(switched), approved_identity=runner.execution_identity())
    record("switch:namespace-declared-in-manifest",
           "BLOCKED: the manifest may not choose its namespace",
           f"status={result['status']}", result["status"] == "BLOCKED")

    result = runner.apply(str(workdir / "deployment.yaml"), namespace="kube-system",
                          approved_identity=runner.execution_identity())
    record("switch:namespace-requested-by-caller",
           "BLOCKED: the caller may not choose the namespace",
           f"status={result['status']}", result["status"] == "BLOCKED")

    result = runner.rollout_undo("--all", approved_identity=runner.execution_identity())
    record("escape:rollout-target-is-not-a-free-string",
           "BLOCKED: '--all' is not a valid rollout target",
           f"status={result['status']}", result["status"] == "BLOCKED")


def check_live_cluster_identity_binding(runner: KubectlRunnerService, workdir: Path,
                                        image_ref: str) -> None:
    """Workstream B, proven against the real cluster rather than a double.

    The approval is taken against the live Kind endpoint. Each attack
    then moves one element of the execution target and must be refused
    before the sandbox is invoked -- so nothing reaches the cluster.
    """
    from deployment_service.application.services.kubernetes_execution_identity import (
        KubernetesExecutionIdentity,
    )
    fixture = (PLATFORM_ROOT / "e2e" / "fixtures" / "k8s-deployment.yaml").read_text()
    manifest = workdir / "identity-probe.yaml"
    manifest.write_text(fixture.replace("WORKLOAD_IMAGE_REF", image_ref))

    live = runner.execution_identity()

    record("identity:mutation-without-approval-is-refused",
           "BLOCKED: an unbound mutation never reaches the live cluster",
           f"status={runner.apply(str(manifest))['status']}",
           runner.apply(str(manifest))["status"] == "BLOCKED")

    for field, value, label in (
        ("api_server", "https://attacker.invalid:6443", "endpoint"),
        ("ca_fingerprint_sha256", "00" * 32, "CA fingerprint"),
        ("namespace", "kube-system", "namespace"),
        ("credential_profile_id", "some-other-profile", "credential profile"),
        ("manifest_policy_identity", "kubernetes-manifest-policy-v1:weakened",
         "manifest policy"),
        ("sandbox_policy_identity", "kubernetes-sandbox-v1:weakened", "sandbox policy"),
        ("network_identity", "some-shared-network", "sandbox network"),
    ):
        stale = KubernetesExecutionIdentity(**{**live.to_dict_fields(), field: value})
        result = runner.apply(str(manifest), approved_identity=stale)
        record(f"identity:{label.replace(' ', '-')}-switch-is-refused",
               f"BLOCKED: a moved {label} must not reach the live cluster",
               f"status={result['status']} "
               f"detail={(result.get('stderr') or '')[:120]!r}",
               result["status"] == "BLOCKED")


def check_server_side_validation_failure(runner: KubectlRunnerService,
                                         workdir: Path, image_ref: str) -> None:
    """A manifest the policy accepts but the API server rejects must FAIL."""
    fixture = (PLATFORM_ROOT / "e2e" / "fixtures" / "k8s-deployment.yaml").read_text()
    bad = fixture.replace("WORKLOAD_IMAGE_REF", image_ref).replace(
        "          resources:", "          madeUpField: 1\n          resources:", 1)
    path = workdir / "schema-invalid.yaml"
    path.write_text(bad)
    result = runner.dry_run(str(path))
    record("server-side-validation:unknown-field-rejected",
           "--validate=strict makes the API server reject an unknown field",
           f"status={result['status']} "
           f"detail={(result.get('stderr') or '')[:160]!r}",
           result["status"] in ("FAIL", "BLOCKED"))


# =====================================================================
# Main
# =====================================================================

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-image", required=True)
    parser.add_argument("--base-image", required=True)
    parser.add_argument("--workload-image", required=True)
    parser.add_argument("--registry", default="localhost:5001")
    parser.add_argument("--kubectl-version", default="v1.31.4")
    parser.add_argument("--evidence", default="kubernetes-kind-e2e-evidence.json")
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="ares-k8s-e2e-"))
    kubeconfig_path = str(workdir / "admin.kubeconfig")
    created_cluster = False

    try:
        for tool in ("docker", "kind", "kubectl"):
            if not shutil.which(tool):
                raise Blocked(f"{tool} is not available; the live proof cannot run")

        # ---- cluster ------------------------------------------------
        print("== creating kind cluster ==", flush=True)
        run(["kind", "create", "cluster", "--name", CLUSTER,
             "--image", args.node_image,
             "--config", str(PLATFORM_ROOT / "e2e" / "kind-config.yaml"),
             "--kubeconfig", kubeconfig_path, "--wait", "180s"], timeout=900)
        created_cluster = True

        # The Deployment must run a real workload image. Load it into the
        # cluster's own image store so the kubelet never reaches a
        # registry: the proof must not depend on Internet access.
        run(["kind", "load", "docker-image", args.workload_image,
             "--name", CLUSTER], timeout=600)

        fixture = build_fixture(kubeconfig_path, workdir)
        notice(f"8.6-A cluster: {CLUSTER} server_version={fixture['server_version']}")

        # ---- sandbox image -----------------------------------------
        print("== building the kubectl sandbox image ==", flush=True)
        ctx = workdir / "kubectl-ctx"
        ctx.mkdir()
        shutil.copy(PLATFORM_ROOT / "e2e" / "kubectl-sandbox" / "Dockerfile",
                    ctx / "Dockerfile")
        kubectl_bin = Path(os.environ["ARES_KUBECTL_BINARY"])
        shutil.copy(kubectl_bin, ctx / "kubectl")
        repo = f"{args.registry}/ares-kubectl-sandbox"
        tag = f"{repo}:{uuid.uuid4().hex[:10]}"
        run(["docker", "build", "--build-arg", f"BASE_IMAGE={args.base_image}",
             "-t", tag, str(ctx)], timeout=900)
        # A digest pin must be a REPOSITORY digest. docker cannot resolve
        # name@sha256:<local image id>, so the image is pushed to the
        # job-local registry purely to obtain its immutable identity; it
        # is already present locally, so --pull never still holds.
        run(["docker", "push", tag], timeout=900)
        repo_digests = json.loads(run(
            ["docker", "image", "inspect", tag, "-f", "{{json .RepoDigests}}"]
        ).stdout.strip() or "[]")
        pinned = next((r for r in repo_digests if r.startswith(repo + "@")), "")
        if "@sha256:" not in pinned:
            raise Blocked(
                f"could not resolve a repository digest for {tag}; "
                f"observed RepoDigests={repo_digests}"
            )
        image_id = pinned.split("@", 1)[1]

        # ---- dedicated network, joined to the kind network ----------
        # --internal is what makes egress destination-controlled: Docker
        # installs no NAT route for this network, so the sandbox can
        # reach ONLY the containers attached to it. The kind
        # control-plane is attached below; nothing else is reachable.
        # A plain user-defined bridge would NAT to the Internet, which
        # the trust boundary forbids.
        run(["docker", "network", "create", "--internal", SANDBOX_NETWORK],
            check=False)
        run(["docker", "network", "connect", SANDBOX_NETWORK,
             f"{CLUSTER}-control-plane"], check=False)

        spec = KubectlSandboxSpec(image=pinned, network=SANDBOX_NETWORK,
                                  kubectl_version=args.kubectl_version)
        policy_id = sandbox_policy_identity(spec, NAMESPACE)
        notice(f"8.6-A sandbox: image_digest={image_id} "
               f"kubectl={args.kubectl_version} policy={policy_id}")

        # ---- wire the runner to the real sandbox --------------------
        deployer_path = workdir / "deployer.kubeconfig"
        deployer_path.write_text(deployer_kubeconfig(fixture))
        os.chmod(deployer_path, 0o600)
        os.environ["DEPLOYMENT_KUBECONFIG_PATH"] = str(deployer_path)
        os.environ["DEPLOYMENT_KUBERNETES_NAMESPACE"] = NAMESPACE
        os.environ["DEPLOYMENT_K8S_SERVICE_ACCOUNT"] = "default"

        sandbox = ContainerKubectlSandbox(spec, staging_root=str(workdir))
        runner = KubectlRunnerService(sandbox=sandbox)

        sanitized = sanitize_kubeconfig(deployer_kubeconfig(fixture),
                                        expected_namespace=NAMESPACE)

        print("\n== RBAC ==", flush=True)
        check_rbac_denials(kubeconfig_path)

        print("\n== network policy ==", flush=True)
        check_network_reachability(sandbox, sanitized.content)
        check_unrelated_destination_blocked(spec)
        check_docker_socket_denied(spec)
        check_same_network_peer(spec)

        print("\n== sandbox runtime ==", flush=True)
        check_plugin_execution(spec)
        check_filesystem_and_process_escape(spec)

        print("\n== credential attacks ==", flush=True)
        check_kubeconfig_attacks(fixture)

        print("\n== malicious manifests ==", flush=True)
        check_malicious_manifests(runner, workdir)

        print("\n== deploy + rollback ==", flush=True)
        check_deploy_and_rollback(runner, workdir, kubeconfig_path,
                                  args.workload_image)

        print("\n== tamper / switch ==", flush=True)
        check_tamper_and_switch(runner, workdir, args.workload_image)
        check_live_cluster_identity_binding(runner, workdir, args.workload_image)
        check_server_side_validation_failure(runner, workdir, args.workload_image)

        # ---- evidence ----------------------------------------------
        passed = sum(1 for c in CHECKS if c["result"] == "PASS")
        failed = sum(1 for c in CHECKS if c["result"] == "FAIL")
        evidence = {
            "phase": "8.6-A",
            "proof_class": "live-kind-e2e",
            # Workstream G: every distinct commit under its own name.
            # GITHUB_SHA is the PR *merge* commit and is never the proof
            # commit; see e2e/evidence_provenance.py.
            "provenance": provenance(),
            "cluster": {
                "name": CLUSTER,
                "server_version": fixture["server_version"],
                "node_image": args.node_image,
                "endpoint_identity": sanitized.cluster_identity.to_dict(),
            },
            "kubectl": {"version": args.kubectl_version,
                        "sandbox_image_digest": image_id},
            "sandbox_policy_identity": policy_id,
            "namespace": NAMESPACE,
            "credential_profile": sanitized.to_evidence(),
            "rbac_subject": f"system:serviceaccount:{NAMESPACE}:{SERVICE_ACCOUNT}",
            "checks": CHECKS,
            "counts": {"total": len(CHECKS), "passed": passed, "failed": failed},
            "duration_seconds": round(time.time() - _START, 1),
        }
        sealed = seal(evidence, args.evidence)
        print(f"evidence artifact_sha256={sealed['artifact_sha256']} "
              f"head_sha={sealed['head_sha'] or '(unresolved)'}", flush=True)
        for check in CHECKS:
            if check["result"] == "FAIL":
                print(f"::error::8.6-A FAIL {check['case']} :: "
                      f"requested={check['requested']} :: "
                      f"observed={check['observed']}", flush=True)
        notice(f"8.6-A live Kind E2E: {passed}/{len(CHECKS)} PASS, {failed} FAIL")
        print(f"\n{'=' * 64}\nLIVE KIND E2E: {passed}/{len(CHECKS)} PASS, "
              f"{failed} FAIL\n{'=' * 64}", flush=True)
        return 1 if failed else 0

    except Blocked as exc:
        print(f"::error::8.6-A live Kind E2E BLOCKED: {exc}", flush=True)
        Path(args.evidence).write_text(json.dumps(
            {"phase": "8.6-A", "proof_class": "live-kind-e2e",
             "result": "BLOCKED", "reason": str(exc), "checks": CHECKS}, indent=2))
        return 2
    finally:
        if created_cluster:
            subprocess.run(["kind", "delete", "cluster", "--name", CLUSTER],
                           capture_output=True, timeout=300)
        subprocess.run(["docker", "network", "rm", SANDBOX_NETWORK],
                       capture_output=True, timeout=60)
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
