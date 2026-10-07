"""Phase 8.6-A — Kubernetes execution trust boundary.

Every test here is a *negative* test unless its name says otherwise: it
asserts that a specific attack against the boundary fails closed. The
positive path is proven by the repository's own manifest fixture, so a
policy that rejects everything cannot pass this file either.
"""

from __future__ import annotations

import ast
import base64
import re
from pathlib import Path

import pytest
import yaml

from deployment_service.application.services.kubeconfig_policy import (
    KubeconfigPolicyError,
    sanitize_kubeconfig,
)
from deployment_service.application.services.kubectl_runner import KubectlRunnerService
from deployment_service.application.services.kubectl_sandbox import (
    KUBECONFIG_PATH,
    MANIFEST_PATH,
    KubectlOperation,
    KubectlSandboxConfigurationError,
    KubectlSandboxPolicyViolation,
    KubectlSandboxSpec,
    KubectlSandboxStep,
    build_kubectl_argv,
    build_run_plan,
    sandbox_environment,
    sandbox_policy_identity,
)
from deployment_service.application.services.kubernetes_manifest_policy import (
    KubernetesManifestPolicy,
)

NAMESPACE = "devops-production-namespace"
FIXTURE = Path(__file__).resolve().parents[2] / "e2e" / "fixtures" / "k8s-deployment.yaml"
DIGEST = "ghcr.io/example/kubectl@sha256:" + "b" * 64


def real_manifest() -> str:
    return FIXTURE.read_text(encoding="utf-8").replace(
        "WORKLOAD_IMAGE_REF", "registry.local/checkout@sha256:" + "c" * 64
    )


@pytest.fixture()
def policy() -> KubernetesManifestPolicy:
    return KubernetesManifestPolicy(namespace=NAMESPACE)


@pytest.fixture()
def spec() -> KubectlSandboxSpec:
    return KubectlSandboxSpec(image=DIGEST, network="ares-e2e-net", kubectl_version="v1.31.4")


# =====================================================================
# 1. Manifest policy  (§11-§24)
# =====================================================================

def test_positive_the_repositorys_own_manifest_is_accepted(policy):
    """Guards against a policy that passes by rejecting everything."""
    result = policy.evaluate(real_manifest())
    assert result.passed, result.errors
    assert result.deployment_names == ["checkout-service"]
    assert len(result.manifest_sha256) == 64


def _mutate(old: str, new: str) -> str:
    text = real_manifest()
    assert old in text, f"anchor missing: {old!r}"
    return text.replace(old, new, 1)


ATTACKS = {
    # --- cluster-scoped / authorization-bearing kinds -----------------
    "cluster_role": "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\n"
                    "metadata: {name: pwn}\nrules: [{apiGroups: ['*'], resources: ['*'], verbs: ['*']}]\n",
    "cluster_role_binding": "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\n"
                            "metadata: {name: pwn}\nroleRef: {kind: ClusterRole, name: cluster-admin,"
                            " apiGroup: rbac.authorization.k8s.io}\n",
    "namespaced_role": "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\n"
                       "metadata: {name: r}\nrules: []\n",
    "role_binding": "apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\n"
                    "metadata: {name: rb}\nroleRef: {kind: Role, name: r,"
                    " apiGroup: rbac.authorization.k8s.io}\n",
    "service_account": "apiVersion: v1\nkind: ServiceAccount\nmetadata: {name: sa}\n",
    "namespace_object": "apiVersion: v1\nkind: Namespace\nmetadata: {name: evil}\n",
    "crd": "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\n"
           "metadata: {name: x.example.com}\n",
    "validating_webhook": "apiVersion: admissionregistration.k8s.io/v1\n"
                          "kind: ValidatingWebhookConfiguration\nmetadata: {name: w}\n",
    "pod_security_policy": "apiVersion: policy/v1\nkind: PodSecurityPolicy\nmetadata: {name: p}\n",
    "persistent_volume": "apiVersion: v1\nkind: PersistentVolume\nmetadata: {name: pv}\n",
    "node": "apiVersion: v1\nkind: Node\nmetadata: {name: n}\n",
    # --- kinds outside the allowlist ----------------------------------
    "bare_pod": "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  hostNetwork: true\n"
                "  containers: [{name: c, image: nginx, securityContext: {privileged: true}}]\n",
    "daemonset": "apiVersion: apps/v1\nkind: DaemonSet\nmetadata: {name: d}\nspec: {}\n",
    "job": "apiVersion: batch/v1\nkind: Job\nmetadata: {name: j}\nspec: {}\n",
    "secret": "apiVersion: v1\nkind: Secret\nmetadata: {name: s}\nstringData: {a: b}\n",
    "unversioned_kind": "apiVersion: apps/v1beta1\nkind: Deployment\nmetadata: {name: d}\nspec: {}\n",
}


@pytest.mark.parametrize("name", sorted(ATTACKS))
def test_denied_kinds_are_rejected(policy, name):
    result = policy.evaluate(ATTACKS[name])
    assert not result.passed, f"{name} was ACCEPTED by the manifest policy"


MUTATIONS = {
    "cross_namespace": ("  name: checkout-service\n",
                        "  name: checkout-service\n  namespace: kube-system\n"),
    "host_network": ("      automountServiceAccountToken: false",
                     "      hostNetwork: true\n      automountServiceAccountToken: false"),
    "host_pid": ("      automountServiceAccountToken: false",
                 "      hostPID: true\n      automountServiceAccountToken: false"),
    "host_ipc": ("      automountServiceAccountToken: false",
                 "      hostIPC: true\n      automountServiceAccountToken: false"),
    "host_path_volume": ("      automountServiceAccountToken: false",
                         "      volumes: [{name: h, hostPath: {path: /}}]\n"
                         "      automountServiceAccountToken: false"),
    "host_port": ("            - containerPort: 8080",
                  "            - containerPort: 8080\n              hostPort: 8080"),
    "privileged_init_container": ("      containers:",
                                  "      initContainers:\n        - name: i\n"
                                  "          image: nginx\n"
                                  "          securityContext: {privileged: true}\n"
                                  "      containers:"),
    "ephemeral_containers": ("      containers:",
                             "      ephemeralContainers: [{name: dbg, image: busybox}]\n"
                             "      containers:"),
    "allow_privilege_escalation": ("allowPrivilegeEscalation: false",
                                   "allowPrivilegeEscalation: true"),
    "capability_add": ('drop: ["ALL"]', 'drop: ["ALL"]\n              add: ["SYS_ADMIN"]'),
    "no_drop_all": ('drop: ["ALL"]', 'drop: ["NET_RAW"]'),
    "run_as_root": ("            allowPrivilegeEscalation: false",
                    "            runAsUser: 0\n            allowPrivilegeEscalation: false"),
    "run_as_non_root_removed": ("        runAsNonRoot: true\n", ""),
    "seccomp_removed": ("        seccompProfile:\n          type: RuntimeDefault\n", ""),
    "arbitrary_service_account": ("      automountServiceAccountToken: false",
                                  "      serviceAccountName: cluster-admin-sa\n"
                                  "      automountServiceAccountToken: false"),
    "unbounded_resources": ("          resources:\n            requests:\n"
                            "              cpu: 50m\n              memory: 64Mi\n"
                            "            limits:\n              cpu: 500m\n"
                            "              memory: 128Mi\n", ""),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_unsafe_workload_mutations_are_rejected(policy, name):
    old, new = MUTATIONS[name]
    result = policy.evaluate(_mutate(old, new))
    assert not result.passed, f"{name} was ACCEPTED by the manifest policy"


def test_privileged_is_rejected_even_when_nothing_else_is_wrong(policy):
    """Isolates the privileged check.

    The init-container case above also violates other rules, so it would
    still fail if the privileged check were deleted. This case violates
    exactly one rule.
    """
    manifest = _mutate("            allowPrivilegeEscalation: false",
                       "            privileged: true\n"
                       "            allowPrivilegeEscalation: false")
    result = policy.evaluate(manifest)
    assert not result.passed
    assert any("privileged" in e for e in result.errors), result.errors


def test_loadbalancer_service_type_is_rejected(policy):
    """Isolates the service-type check: no nodePort field to catch it."""
    manifest = ("apiVersion: v1\nkind: Service\nmetadata: {name: s}\n"
                "spec: {type: LoadBalancer, ports: [{port: 80}]}\n")
    result = policy.evaluate(manifest)
    assert not result.passed
    assert any("service type" in e for e in result.errors), result.errors


def test_nodeport_service_is_rejected(policy):
    manifest = ("apiVersion: v1\nkind: Service\nmetadata: {name: s}\n"
                "spec: {type: NodePort, ports: [{port: 80, nodePort: 30001}]}\n")
    assert not policy.evaluate(manifest).passed


def test_service_external_ips_are_rejected(policy):
    manifest = ("apiVersion: v1\nkind: Service\nmetadata: {name: s}\n"
                "spec: {type: ClusterIP, externalIPs: ['1.2.3.4'], ports: [{port: 80}]}\n")
    assert not policy.evaluate(manifest).passed


def test_policy_rejects_rather_than_rewrites(policy):
    """An unsafe field must never be silently stripped and accepted."""
    result = policy.evaluate(_mutate("allowPrivilegeEscalation: false",
                                     "allowPrivilegeEscalation: true"))
    assert not result.passed
    assert result.canonical_yaml == ""


def test_a_denied_kind_hidden_behind_a_valid_document_is_still_rejected(policy):
    combined = real_manifest() + "\n---\n" + ATTACKS["cluster_role"]
    assert not policy.evaluate(combined).passed


def test_manifest_hash_is_deterministic_and_order_independent(policy):
    first = policy.evaluate(real_manifest())
    second = policy.evaluate(real_manifest() + "\n")
    assert first.manifest_sha256 == second.manifest_sha256


def test_namespace_is_injected_into_the_canonical_manifest(policy):
    result = policy.evaluate(real_manifest())
    for doc in yaml.safe_load_all(result.canonical_yaml):
        assert doc["metadata"]["namespace"] == NAMESPACE


def test_a_widened_allowlist_cannot_reintroduce_a_denied_kind():
    """Hard-denied kinds override configuration."""
    widened = KubernetesManifestPolicy(
        namespace=NAMESPACE,
        allowed_resources={("rbac.authorization.k8s.io/v1", "ClusterRole"),
                           ("apps/v1", "Deployment")},
    )
    assert not widened.evaluate(ATTACKS["cluster_role"]).passed


def test_policy_identity_changes_when_the_namespace_changes():
    a = KubernetesManifestPolicy(namespace=NAMESPACE).identity()
    b = KubernetesManifestPolicy(namespace="other-namespace").identity()
    assert a != b


# =====================================================================
# 2. Kubeconfig policy  (§25-§29)
# =====================================================================

CA_PEM = b"-----BEGIN CERTIFICATE-----\nMIIBdummy\n-----END CERTIFICATE-----\n"
CA_B64 = base64.b64encode(CA_PEM).decode()


def kubeconfig(**overrides) -> str:
    user = overrides.pop("user", {"token": "redacted-test-token"})
    cluster = {"server": "https://api.ares-e2e.local:6443",
               "certificate-authority-data": CA_B64}
    cluster.update(overrides.pop("cluster", {}))
    context = {"cluster": "c", "user": "u", "namespace": NAMESPACE}
    context.update(overrides.pop("context", {}))
    doc = {
        "apiVersion": "v1", "kind": "Config",
        "clusters": [{"name": "c", "cluster": cluster}],
        "users": [{"name": "u", "user": user}],
        "contexts": [{"name": "ctx", "context": context}],
        "current-context": "ctx",
    }
    doc.update(overrides)
    return yaml.safe_dump(doc)


def test_positive_a_clean_kubeconfig_is_accepted():
    result = sanitize_kubeconfig(kubeconfig(), expected_namespace=NAMESPACE)
    assert result.credential_kind == "token"
    assert len(result.cluster_identity.ca_fingerprint_sha256) == 64


KUBECONFIG_ATTACKS = {
    "exec_credential_plugin": {"user": {"exec": {"command": "/bin/sh", "args": ["-c", "curl evil"]}}},
    "auth_provider": {"user": {"auth-provider": {"name": "gcp"}}},
    "basic_auth": {"user": {"username": "admin", "password": "hunter2"}},
    "impersonation": {"user": {"token": "t", "act-as": "system:admin"}},
    "client_cert_file_path": {"user": {"client-certificate": "/etc/passwd", "token": "t"}},
    "token_file_path": {"user": {"tokenFile": "/var/run/secrets/token"}},
    "unknown_user_key": {"user": {"token": "t", "exec-probe": "x"}},
    "proxy_url": {"cluster": {"proxy-url": "http://attacker:3128"}},
    "insecure_tls": {"cluster": {"insecure-skip-tls-verify": True}},
    "tls_server_name_override": {"cluster": {"tls-server-name": "evil.local"}},
    "plain_http_endpoint": {"cluster": {"server": "http://api.ares-e2e.local:6443"}},
    "endpoint_with_path": {"cluster": {"server": "https://api.local:6443/evil"}},
    "endpoint_with_embedded_creds": {"cluster": {"server": "https://u:p@api.local:6443"}},
    "ca_file_path": {"cluster": {"certificate-authority": "/tmp/evil.pem"}},
}


@pytest.mark.parametrize("name", sorted(KUBECONFIG_ATTACKS))
def test_dangerous_kubeconfig_constructs_are_rejected(name):
    with pytest.raises(KubeconfigPolicyError):
        sanitize_kubeconfig(kubeconfig(**KUBECONFIG_ATTACKS[name]),
                            expected_namespace=NAMESPACE)


def test_missing_ca_data_is_rejected():
    raw = yaml.safe_load(kubeconfig())
    del raw["clusters"][0]["cluster"]["certificate-authority-data"]
    with pytest.raises(KubeconfigPolicyError):
        sanitize_kubeconfig(yaml.safe_dump(raw), expected_namespace=NAMESPACE)


def test_namespace_mismatch_in_kubeconfig_is_rejected():
    with pytest.raises(KubeconfigPolicyError):
        sanitize_kubeconfig(kubeconfig(context={"cluster": "c", "user": "u",
                                                "namespace": "kube-system"}),
                            expected_namespace=NAMESPACE)


def test_cluster_endpoint_switch_is_rejected():
    with pytest.raises(KubeconfigPolicyError):
        sanitize_kubeconfig(kubeconfig(), expected_namespace=NAMESPACE,
                            expected_server="https://api.other-cluster.local:6443")


def test_sanitized_kubeconfig_drops_everything_not_required():
    """Rebuilt, not filtered: extra entries cannot survive."""
    raw = yaml.safe_load(kubeconfig())
    raw["clusters"].append({"name": "evil", "cluster": {
        "server": "https://evil:6443", "insecure-skip-tls-verify": True}})
    raw["users"].append({"name": "evil", "user": {"exec": {"command": "sh"}}})
    out = sanitize_kubeconfig(yaml.safe_dump(raw), expected_namespace=NAMESPACE)
    doc = yaml.safe_load(out.content)
    assert len(doc["clusters"]) == 1 and len(doc["users"]) == 1 and len(doc["contexts"]) == 1
    assert "evil" not in out.content
    assert "exec" not in out.content


def test_credential_evidence_never_contains_the_credential():
    out = sanitize_kubeconfig(kubeconfig(user={"token": "super-secret-value"}),
                              expected_namespace=NAMESPACE)
    evidence = out.to_evidence()
    assert "super-secret-value" not in repr(evidence)
    # the credential *kind* is a non-secret label and is expected; the
    # credential *value* must appear nowhere.
    assert evidence["credential_kind"] == "token"
    assert all("super-secret-value" not in str(v) for v in evidence.values())


def test_cluster_identity_binds_endpoint_and_ca():
    a = sanitize_kubeconfig(kubeconfig(), expected_namespace=NAMESPACE)
    other_ca = base64.b64encode(
        b"-----BEGIN CERTIFICATE-----\nMIIBother\n-----END CERTIFICATE-----\n").decode()
    b = sanitize_kubeconfig(kubeconfig(cluster={"certificate-authority-data": other_ca}),
                            expected_namespace=NAMESPACE)
    assert a.cluster_identity.identity() != b.cluster_identity.identity()


# =====================================================================
# 3. Command policy  (§8-§10)
# =====================================================================

def test_dry_run_uses_server_side_validation_not_client():
    argv = build_kubectl_argv(KubectlOperation.SERVER_SIDE_DRY_RUN, namespace=NAMESPACE)
    assert "--dry-run=server" in argv
    assert "--validate=strict" in argv
    assert "--dry-run=client" not in argv
    assert "--validate=false" not in argv


def test_every_operation_targets_only_the_approved_manifest_path():
    for op in (KubectlOperation.SERVER_SIDE_DRY_RUN, KubectlOperation.APPLY):
        argv = build_kubectl_argv(op, namespace=NAMESPACE)
        assert argv[argv.index("-f") + 1] == MANIFEST_PATH
        assert "-k" not in argv and "--kustomize" not in argv
        assert not any(t.startswith(("http://", "https://")) for t in argv)


@pytest.mark.parametrize("bad", [
    "default ", "-n", "--namespace=kube-system", "a/b",
    "NS", "", "x" * 300, "ns;rm -rf /", "../kube-system",
])
def test_namespace_injection_is_rejected(bad):
    with pytest.raises(KubectlSandboxPolicyViolation):
        build_kubectl_argv(KubectlOperation.APPLY, namespace=bad)


@pytest.mark.parametrize("bad", [
    "--all", "-n kube-system", "d;whoami", "../../etc/passwd", "", None,
    "deployment/x --kubeconfig=/evil", "UPPER",
])
def test_deployment_name_injection_is_rejected(bad):
    with pytest.raises(KubectlSandboxPolicyViolation):
        build_kubectl_argv(KubectlOperation.ROLLOUT_STATUS,
                           namespace=NAMESPACE, deployment_name=bad)


@pytest.mark.parametrize("reserved", ["kube-system", "kube-public",
                                      "kube-node-lease", "default"])
def test_reserved_system_namespaces_are_refused_by_the_command_policy(reserved):
    """Defence in depth below the runner's single-namespace pin."""
    with pytest.raises(KubectlSandboxPolicyViolation):
        build_kubectl_argv(KubectlOperation.APPLY, namespace=reserved)


def test_there_is_no_generic_command_entry_point():
    import deployment_service.application.services.kubectl_sandbox as mod
    for forbidden in ("run_command", "run", "exec_command", "shell"):
        assert not hasattr(mod, forbidden), f"{forbidden} is a generic command surface"


@pytest.mark.parametrize("sub", ["exec", "cp", "port-forward", "proxy", "delete",
                                 "plugin", "auth", "config", "debug", "run"])
def test_forbidden_subcommands_cannot_be_constructed(sub):
    with pytest.raises(KubectlSandboxPolicyViolation):
        KubectlSandboxStep(operation=KubectlOperation.APPLY,
                           argv=("kubectl", sub), timeout_seconds=60)


@pytest.mark.parametrize("flag", ["--kubeconfig", "--server", "--token",
                                  "--insecure-skip-tls-verify", "--as", "-k"])
def test_host_owned_flags_cannot_appear_in_argv(flag):
    with pytest.raises(KubectlSandboxPolicyViolation):
        KubectlSandboxStep(operation=KubectlOperation.APPLY,
                           argv=("kubectl", "apply", flag, "x"), timeout_seconds=60)


def test_step_rejects_a_filename_other_than_the_approved_manifest():
    with pytest.raises(KubectlSandboxPolicyViolation):
        KubectlSandboxStep(operation=KubectlOperation.APPLY,
                           argv=("kubectl", "apply", "-f", "/etc/passwd"),
                           timeout_seconds=60)


def test_step_rejects_remote_manifest_urls():
    with pytest.raises(KubectlSandboxPolicyViolation):
        KubectlSandboxStep(operation=KubectlOperation.APPLY,
                           argv=("kubectl", "apply", "-f", "https://evil/x.yaml"),
                           timeout_seconds=60)


# =====================================================================
# 4. Sandbox runtime  (§30-§34)
# =====================================================================

def test_image_must_be_digest_pinned():
    for bad in ("kubectl:latest", "kubectl", "repo/kubectl:v1.31.4", ""):
        with pytest.raises(KubectlSandboxConfigurationError):
            KubectlSandboxSpec(image=bad, network="ares-e2e-net")


@pytest.mark.parametrize("bad", ["host", "none", "bridge", "container", ""])
def test_unsafe_network_modes_are_rejected(bad):
    with pytest.raises(KubectlSandboxConfigurationError):
        KubectlSandboxSpec(image=DIGEST, network=bad)


def test_sandbox_must_not_run_as_root():
    for bad in ("0:0", "0:65532", "65532:0"):
        with pytest.raises(KubectlSandboxConfigurationError):
            KubectlSandboxSpec(image=DIGEST, network="ares-e2e-net", user=bad)


def plan_argv(spec) -> list:
    step = KubectlSandboxStep(
        operation=KubectlOperation.APPLY,
        argv=build_kubectl_argv(KubectlOperation.APPLY, namespace=NAMESPACE),
        timeout_seconds=300,
    )
    return list(build_run_plan(
        spec=spec, step=step,
        manifest_host_path="/tmp/stage/deployment.yaml",
        kubeconfig_host_path="/tmp/stage/kubeconfig",
        kuberc_host_path="/tmp/stage/kuberc",
        container_name="ares-kubectl-test",
    ).argv)


@pytest.mark.parametrize("pair", [
    ("--read-only", None), ("--cap-drop", "ALL"),
    ("--security-opt", "no-new-privileges:true"), ("--pull", "never"),
    ("--user", "65532:65532"), ("--network", "ares-e2e-net"),
])
def test_run_plan_enforces_each_runtime_control(spec, pair):
    argv = plan_argv(spec)
    flag, value = pair
    assert flag in argv
    if value is not None:
        assert argv[argv.index(flag) + 1] == value


def test_run_plan_has_no_docker_socket_and_no_host_namespaces(spec):
    joined = " ".join(plan_argv(spec))
    for forbidden in ("docker.sock", "--privileged", "--pid=host", "--ipc=host",
                      "--network host", "--net=host", "--cap-add", "/var/run",
                      "--security-opt seccomp=unconfined", "-v /:/"):
        assert forbidden not in joined, f"{forbidden} present in sandbox argv"


def test_run_plan_mounts_only_read_only_inputs(spec):
    argv = plan_argv(spec)
    mounts = [argv[i + 1] for i, t in enumerate(argv) if t == "-v"]
    assert len(mounts) == 3
    for mount in mounts:
        assert mount.endswith(":ro"), mount
    assert any(m.endswith(f"{MANIFEST_PATH}:ro") for m in mounts)
    assert any(m.endswith(f"{KUBECONFIG_PATH}:ro") for m in mounts)


def test_sandbox_environment_is_explicit_and_carries_no_host_state():
    env = sandbox_environment()
    assert set(env) == {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL",
                        "KUBECONFIG", "KUBERC"}
    assert env["KUBECONFIG"] == KUBECONFIG_PATH
    for proxy in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
                  "http_proxy", "https_proxy", "no_proxy"):
        assert proxy not in env, f"{proxy} would let the host redirect API traffic"
    assert "kubectl-" not in env["PATH"]


def test_sandbox_modules_never_copy_the_host_environment():
    """§75: os.environ.copy() must not exist on this boundary."""
    base = Path(__file__).resolve().parents[1]
    targets = [
        base / "application" / "services" / "kubectl_runner.py",
        base / "application" / "services" / "kubectl_sandbox.py",
        base / "application" / "services" / "kubeconfig_policy.py",
        base / "infrastructure" / "sandbox" / "container_kubectl_sandbox.py",
    ]
    for path in targets:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        # AST, not grep: a prose mention of the forbidden call in a
        # docstring must not pass or fail this test. Only real calls count.
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if (isinstance(func, ast.Attribute) and func.attr == "copy"
                        and isinstance(func.value, ast.Attribute)
                        and func.value.attr == "environ"):
                    raise AssertionError(
                        f"{path.name}:{node.lineno} calls os.environ.copy()")
                for kw in node.keywords:
                    if kw.arg == "shell" and not (
                            isinstance(kw.value, ast.Constant) and kw.value.value is False):
                        raise AssertionError(
                            f"{path.name}:{node.lineno} passes a non-False shell=")


def test_policy_identity_changes_when_the_posture_weakens(spec):
    strong = sandbox_policy_identity(spec, NAMESPACE)
    weaker = sandbox_policy_identity(
        KubectlSandboxSpec(image=DIGEST, network="ares-e2e-net",
                           kubectl_version="v1.31.4", pids_limit=4096), NAMESPACE)
    assert strong != weaker


# =====================================================================
# 5. Runner: no host kubectl, fail closed  (§7, §23, §35, §38)
# =====================================================================

class RecordingSandbox:
    """Captures what the runner asks for. Never executes anything."""

    def __init__(self, exit_code=0, stdout="deployment.apps/checkout-service configured"):
        self.calls = []
        self._exit_code = exit_code
        self._stdout = stdout

    def execute(self, step, *, manifest_yaml, kubeconfig_yaml, namespace):
        self.calls.append({"step": step, "manifest": manifest_yaml,
                           "kubeconfig": kubeconfig_yaml, "namespace": namespace})

        class _R:
            exit_code = self._exit_code
            stdout = self._stdout
            stderr = ""
            timed_out = False
            truncated = False
            policy_identity = "kubernetes-sandbox-v1:test"
        return _R()

    def policy_identity(self, namespace):
        return "kubernetes-sandbox-v1:test"


@pytest.fixture()
def wired(tmp_path, monkeypatch):
    kc = tmp_path / "kubeconfig"
    kc.write_text(kubeconfig())
    monkeypatch.setenv("DEPLOYMENT_KUBECONFIG_PATH", str(kc))
    monkeypatch.setenv("DEPLOYMENT_KUBERNETES_NAMESPACE", NAMESPACE)
    manifest = tmp_path / "k8s.yaml"
    manifest.write_text(real_manifest())
    sandbox = RecordingSandbox()
    return KubectlRunnerService(sandbox=sandbox), sandbox, manifest


def test_runner_module_cannot_spawn_a_process():
    import deployment_service.application.services.kubectl_runner as mod
    source = Path(mod.__file__).read_text(encoding="utf-8")
    assert "import subprocess" not in source
    assert "shutil.which" not in source
    for api in ("subprocess.run", "os.system", "os.popen", "os.execv"):
        assert api not in source, f"{api} present in the runner"


def test_apply_goes_through_the_sandbox_with_the_canonical_manifest(wired):
    runner, sandbox, manifest = wired
    result = runner.apply(str(manifest))
    assert result["status"] == "PASS"
    assert result["sandboxed"] is True
    assert len(sandbox.calls) == 1
    sent = sandbox.calls[0]["manifest"]
    for doc in yaml.safe_load_all(sent):
        assert doc["metadata"]["namespace"] == NAMESPACE


def test_dry_run_is_server_side_against_the_real_cluster(wired):
    runner, sandbox, manifest = wired
    result = runner.dry_run(str(manifest))
    assert result["validation_mode"] == "server-side-dry-run"
    assert result["cluster_access"] is True
    assert "--dry-run=server" in sandbox.calls[0]["step"].argv


def test_dry_run_never_falls_back_to_client_validation(wired, monkeypatch):
    """§38: a failing server dry run must not become a client PASS."""
    runner, _, manifest = wired
    failing = RecordingSandbox(exit_code=1, stdout="")
    runner._sandbox = failing
    result = runner.dry_run(str(manifest))
    assert result["status"] == "FAIL"
    assert "--dry-run=client" not in " ".join(failing.calls[0]["step"].argv)


def test_namespace_switch_is_refused(wired):
    runner, sandbox, manifest = wired
    result = runner.apply(str(manifest), namespace="kube-system")
    assert result["status"] == "BLOCKED"
    assert sandbox.calls == [], "a refused namespace must not reach the sandbox"


def test_tampered_manifest_is_refused_before_execution(wired):
    runner, sandbox, manifest = wired
    manifest.write_text(_mutate("allowPrivilegeEscalation: false",
                                "allowPrivilegeEscalation: true"))
    result = runner.apply(str(manifest))
    assert result["status"] == "BLOCKED"
    assert sandbox.calls == []


def test_cluster_scoped_manifest_is_refused_before_execution(wired):
    runner, sandbox, manifest = wired
    manifest.write_text(ATTACKS["cluster_role"])
    assert runner.apply(str(manifest))["status"] == "BLOCKED"
    assert sandbox.calls == []


def test_missing_kubeconfig_fails_closed(tmp_path, monkeypatch):
    monkeypatch.delenv("DEPLOYMENT_KUBECONFIG_PATH", raising=False)
    monkeypatch.setenv("DEPLOYMENT_KUBERNETES_NAMESPACE", NAMESPACE)
    manifest = tmp_path / "k8s.yaml"
    manifest.write_text(real_manifest())
    sandbox = RecordingSandbox()
    result = KubectlRunnerService(sandbox=sandbox).apply(str(manifest))
    assert result["status"] == "BLOCKED"
    assert sandbox.calls == []


def test_hostile_kubeconfig_fails_closed(tmp_path, monkeypatch):
    kc = tmp_path / "kubeconfig"
    kc.write_text(kubeconfig(user={"exec": {"command": "/bin/sh"}}))
    monkeypatch.setenv("DEPLOYMENT_KUBECONFIG_PATH", str(kc))
    monkeypatch.setenv("DEPLOYMENT_KUBERNETES_NAMESPACE", NAMESPACE)
    manifest = tmp_path / "k8s.yaml"
    manifest.write_text(real_manifest())
    sandbox = RecordingSandbox()
    result = KubectlRunnerService(sandbox=sandbox).apply(str(manifest))
    assert result["status"] == "BLOCKED"
    assert sandbox.calls == [], "an exec-plugin kubeconfig must never be staged"


def test_rollout_target_cannot_be_an_arbitrary_string(wired):
    runner, sandbox, _ = wired
    assert runner.rollout_undo("--all")["status"] == "BLOCKED"
    assert runner.rollout_status("x;whoami")["status"] == "BLOCKED"
    assert sandbox.calls == []


def test_rollback_uses_the_same_sandbox_and_namespace(wired):
    """§79: rollback is not a privileged side door."""
    runner, sandbox, _ = wired
    result = runner.rollout_undo("checkout-service")
    assert result["status"] == "PASS"
    assert result["namespace"] == NAMESPACE
    assert sandbox.calls[0]["step"].argv[:3] == ("kubectl", "rollout", "undo")


def test_runner_evidence_never_leaks_credentials(wired):
    runner, _, manifest = wired
    blob = repr(runner.apply(str(manifest)))
    for secret in ("redacted-test-token", "BEGIN CERTIFICATE", CA_B64):
        assert secret not in blob
