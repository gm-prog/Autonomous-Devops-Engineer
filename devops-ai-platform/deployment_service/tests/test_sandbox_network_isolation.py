"""Phase 8.6-A final corrective, Workstream A + C.

`--internal` removes the NAT route but does not isolate the network's
own members. A co-tenant on the same bridge is reachable -- proven live
as `dial tcp 172.20.0.3:9999: connect: connection refused`, which is a
*reached* peer, not a blocked one.

These tests pin the replacement: a dedicated network carrying only
approved destinations, a canonical identity that survives renaming
tricks, membership re-validated before every execution, and an
inspection failure that fails closed.
"""
from __future__ import annotations

import json
from unittest import mock

import pytest

from deployment_service.application.services.kubernetes_execution_identity import (
    KubernetesExecutionConfig,
    KubernetesExecutionIdentity,
)
from deployment_service.infrastructure.sandbox.kubernetes_sandbox_network import (
    ALLOWED_DRIVERS,
    KubernetesSandboxNetworkError,
    SandboxNetworkIdentity,
    identity_from_inspection,
    observed_members,
    validate_network,
)

PEER = "ares-e2e-control-plane"
SANDBOX_NET = "ares-k8s-x-abc123"


def _inspection(*, members=(PEER,), internal=True, driver="bridge",
                net_id="deadbeef" * 8, subnet="172.31.0.0/16",
                gateway="172.31.0.1"):
    return [{
        "Name": SANDBOX_NET,
        "Id": net_id,
        "Driver": driver,
        "Internal": internal,
        "IPAM": {"Config": [{"Subnet": subnet, "Gateway": gateway}]},
        "Containers": {f"c{i}": {"Name": n} for i, n in enumerate(members)},
    }]


def _patch(payload, returncode=0):
    completed = mock.Mock(returncode=returncode,
                          stdout=json.dumps(payload) if payload is not None else "",
                          stderr="" if returncode == 0 else "no such network")
    return mock.patch(
        "deployment_service.infrastructure.sandbox.kubernetes_sandbox_network._run",
        return_value=completed)


# ------------------------------------------------------------ happy path

def test_an_isolated_network_with_only_approved_peers_validates():
    with _patch(_inspection()):
        identity = validate_network(SANDBOX_NET, approved_identity=None,
                                    approved_peers=[PEER])
    assert identity.internal is True
    assert identity.driver in ALLOWED_DRIVERS
    assert identity.approved_peers == (PEER,)


def test_transient_sandbox_containers_are_permitted():
    with _patch(_inspection(members=(PEER, "ares-kubectl-0123456789ab"))):
        validate_network(SANDBOX_NET, approved_identity=None, approved_peers=[PEER])


# ------------------------------------------------------- isolation failures

def test_an_unapproved_co_tenant_is_refused():
    """The exact flaw found live: a reachable peer on the same bridge."""
    with _patch(_inspection(members=(PEER, "ares-e2e-unrelated-peer"))):
        with pytest.raises(KubernetesSandboxNetworkError, match="co-tenant"):
            validate_network(SANDBOX_NET, approved_identity=None,
                             approved_peers=[PEER])


def test_a_non_internal_network_is_refused():
    with _patch(_inspection(internal=False)):
        with pytest.raises(KubernetesSandboxNetworkError, match="not internal"):
            validate_network(SANDBOX_NET, approved_identity=None,
                             approved_peers=[PEER])


def test_an_unexpected_driver_is_refused():
    with _patch(_inspection(driver="macvlan")):
        with pytest.raises(KubernetesSandboxNetworkError, match="driver"):
            validate_network(SANDBOX_NET, approved_identity=None,
                             approved_peers=[PEER])


def test_a_missing_approved_destination_is_refused():
    with _patch(_inspection(members=())):
        with pytest.raises(KubernetesSandboxNetworkError, match="missing"):
            validate_network(SANDBOX_NET, approved_identity=None,
                             approved_peers=[PEER])


def test_inspection_failure_fails_closed():
    """Cannot inspect the network => FAIL, never an implicit pass."""
    with _patch(None, returncode=1):
        with pytest.raises(KubernetesSandboxNetworkError, match="could not be inspected"):
            validate_network(SANDBOX_NET, approved_identity=None,
                             approved_peers=[PEER])


def test_a_nonexistent_network_fails_closed():
    with _patch([]):
        with pytest.raises(KubernetesSandboxNetworkError, match="does not exist"):
            validate_network(SANDBOX_NET, approved_identity=None,
                             approved_peers=[PEER])


def test_a_malformed_network_name_is_refused():
    with pytest.raises(KubernetesSandboxNetworkError, match="malformed"):
        validate_network("not a name!", approved_identity=None, approved_peers=[PEER])


# ------------------------------------------------- identity, not just a name

def test_a_rebuilt_network_with_the_same_name_is_detected():
    """A name is not an identity: recreation must not pass silently."""
    with _patch(_inspection()):
        approved = validate_network(SANDBOX_NET, approved_identity=None,
                                    approved_peers=[PEER])
    with _patch(_inspection(net_id="feedface" * 8, subnet="172.99.0.0/16")):
        with pytest.raises(KubernetesSandboxNetworkError, match="changed after approval"):
            validate_network(SANDBOX_NET, approved_identity=approved,
                             approved_peers=[PEER])


@pytest.mark.parametrize("field,value", [
    ("name", "other"), ("network_id", "aa" * 16), ("driver", "bridge2"),
    ("internal", False), ("subnet", "10.0.0.0/8"), ("gateway", "10.0.0.1"),
])
def test_every_network_identity_field_participates(field, value):
    base = dict(name=SANDBOX_NET, network_id="ab" * 16, driver="bridge",
                internal=True, subnet="172.31.0.0/16", gateway="172.31.0.1",
                approved_peers=(PEER,))
    a = SandboxNetworkIdentity(**base)
    b = SandboxNetworkIdentity(**{**base, field: value})
    assert a.digest() != b.digest(), f"{field} does not affect the identity"
    assert field in a.differences(b)


def test_approved_peer_set_participates_in_the_identity():
    base = dict(name=SANDBOX_NET, network_id="ab" * 16, driver="bridge",
                internal=True, subnet="172.31.0.0/16", gateway="172.31.0.1")
    a = SandboxNetworkIdentity(**base, approved_peers=(PEER,))
    b = SandboxNetworkIdentity(**base, approved_peers=(PEER, "extra"))
    assert a.digest() != b.digest()


def test_identity_is_order_independent_for_peers():
    base = dict(name=SANDBOX_NET, network_id="ab" * 16, driver="bridge",
                internal=True, subnet="172.31.0.0/16", gateway="172.31.0.1")
    a = SandboxNetworkIdentity(**base, approved_peers=tuple(sorted(("b", "a"))))
    b = SandboxNetworkIdentity(**base, approved_peers=tuple(sorted(("a", "b"))))
    assert a.digest() == b.digest()


def test_members_are_read_from_the_inspection():
    assert observed_members(_inspection(members=("x", "a"))[0]) == ["a", "x"]


def test_identity_excludes_volatile_fields():
    """A legitimate re-attach must not look like a configuration change."""
    one = identity_from_inspection(_inspection(members=(PEER,))[0], [PEER])
    two = identity_from_inspection(
        _inspection(members=(PEER, "ares-kubectl-ffffffffffff"))[0], [PEER])
    assert one.digest() == two.digest()


# ------------------------------------------- Workstream C: the config snapshot

def test_config_snapshot_reads_every_value_in_one_pass(monkeypatch):
    monkeypatch.setenv("DEPLOYMENT_KUBERNETES_NAMESPACE", "ns-a")
    monkeypatch.setenv("DEPLOYMENT_K8S_API_SERVER", "https://a:6443")
    monkeypatch.setenv("DEPLOYMENT_K8S_SANDBOX_NETWORK_IDENTITY", "net-v1:abc")
    snapshot = KubernetesExecutionConfig.from_environment()
    # the environment moves underneath us; the snapshot must not
    monkeypatch.setenv("DEPLOYMENT_KUBERNETES_NAMESPACE", "ns-b")
    monkeypatch.setenv("DEPLOYMENT_K8S_API_SERVER", "https://b:6443")
    assert snapshot.namespace == "ns-a"
    assert snapshot.expected_api_server == "https://a:6443"
    assert snapshot.network_identity == "net-v1:abc"


def test_config_snapshot_is_immutable():
    snapshot = KubernetesExecutionConfig.from_environment()
    with pytest.raises(Exception):
        snapshot.namespace = "other"  # type: ignore[misc]


def test_config_snapshot_carries_no_secret_material(monkeypatch):
    monkeypatch.setenv("DEPLOYMENT_KUBECONFIG_PATH", "/etc/ares/kubeconfig")
    blob = json.dumps(KubernetesExecutionConfig.from_environment().to_dict())
    assert "kubeconfig_path" not in blob, "a filesystem path is not an identity"
    for leak in ("token", "BEGIN ", "password", "bearer"):
        assert leak.lower() not in blob.lower()


def test_network_identity_prefers_the_canonical_digest(monkeypatch):
    monkeypatch.setenv("DEPLOYMENT_KUBECTL_SANDBOX_NETWORK", "plain-name")
    monkeypatch.delenv("DEPLOYMENT_K8S_SANDBOX_NETWORK_IDENTITY", raising=False)
    assert KubernetesExecutionConfig.from_environment().network_identity == "plain-name"
    monkeypatch.setenv("DEPLOYMENT_K8S_SANDBOX_NETWORK_IDENTITY", "net-v1:deadbeef")
    assert (KubernetesExecutionConfig.from_environment().network_identity
            == "net-v1:deadbeef")


@pytest.mark.parametrize("field,value", [
    ("namespace", "other"), ("credential_profile_id", "p2"),
    ("expected_api_server", "https://z:6443"), ("expected_ca_fingerprint", "ff" * 32),
    ("sandbox_network", "n2"), ("sandbox_network_identity", "net-v1:ff"),
    ("container_runtime", "podman"),
])
def test_every_config_field_participates_in_the_snapshot_digest(field, value):
    base = KubernetesExecutionConfig(
        namespace="ns", kubeconfig_path="/k", credential_profile_id="p",
        expected_api_server="https://a:6443", expected_ca_fingerprint="ab" * 32,
        sandbox_network="n", sandbox_network_identity="net-v1:aa",
        container_runtime="docker")
    import dataclasses
    other = dataclasses.replace(base, **{field: value})
    assert base.digest() != other.digest(), f"{field} is not bound"


def test_workload_identity_policy_participates_in_the_execution_identity():
    base = dict(namespace="n", api_server="https://a:6443",
                ca_fingerprint_sha256="ab", credential_profile_id="p",
                manifest_policy_identity="m", sandbox_policy_identity="s",
                network_identity="net")
    a = KubernetesExecutionIdentity(**base, workload_identity_policy="w1")
    b = KubernetesExecutionIdentity(**base, workload_identity_policy="w2")
    assert a.digest() != b.digest()
    assert "workload_identity_policy" in a.differences(b)


def test_approved_digest_mismatch_is_refused():
    with _patch(_inspection()):
        with pytest.raises(KubernetesSandboxNetworkError, match="rebuilt"):
            validate_network(SANDBOX_NET, approved_identity=None,
                             approved_peers=[PEER],
                             approved_digest="0" * 64)


def test_approved_digest_match_is_accepted():
    with _patch(_inspection()):
        good = validate_network(SANDBOX_NET, approved_identity=None,
                                approved_peers=[PEER])
    with _patch(_inspection()):
        validate_network(SANDBOX_NET, approved_identity=None,
                         approved_peers=[PEER], approved_digest=good.digest())


def test_sandbox_refuses_to_execute_on_an_unverifiable_network(monkeypatch, tmp_path):
    """Workstream A, production path: inspection failure blocks execution."""
    from deployment_service.application.services.kubectl_sandbox import (
        KubectlOperation, KubectlSandboxPolicyViolation, KubectlSandboxSpec,
        KubectlSandboxStep,
    )
    from deployment_service.infrastructure.sandbox.container_kubectl_sandbox import (
        ContainerKubectlSandbox,
    )
    monkeypatch.setenv("DEPLOYMENT_K8S_SANDBOX_PEERS", "ares-e2e-control-plane")
    spec = KubectlSandboxSpec(
        image="registry.local/kubectl@sha256:" + "a" * 64,
        network="ares-k8s-x-000000000000", kubectl_version="v1.31.4")
    sandbox = ContainerKubectlSandbox(spec, staging_root=str(tmp_path))
    launched = []
    with mock.patch("subprocess.run", side_effect=lambda *a, **k: launched.append(a)):
        with _patch(None, returncode=1):
            with pytest.raises(KubectlSandboxPolicyViolation, match="could not be verified"):
                sandbox.execute(
                    KubectlSandboxStep(
                        operation=KubectlOperation.APPLY,
                        argv=("kubectl", "apply", "-f", "/workspace/deployment.yaml"),
                        timeout_seconds=120),
                    manifest_yaml="kind: Deployment\n",
                    kubeconfig_yaml="apiVersion: v1\n",
                    namespace="devops-production-namespace")
    assert launched == [], "the sandbox container was launched despite a bad network"


def test_sa_token_posture_alone_changes_the_workload_identity(monkeypatch):
    """Only the SA-token posture moves; the identity must still move."""
    from deployment_service.application.services.kubernetes_manifest_policy import (
        KubernetesManifestPolicy,
    )
    strict = KubernetesManifestPolicy(namespace="n", allow_service_account_tokens=False)
    relaxed = KubernetesManifestPolicy(namespace="n", allow_service_account_tokens=True)
    assert strict.workload_identity_policy() != relaxed.workload_identity_policy(), \
        "enabling service-account tokens did not change the workload identity"
    assert strict.identity() != relaxed.identity()


# ------------------------------------- Workstream B: the authoritative path

def test_workstream_b_driver_never_instantiates_the_engine_or_runner():
    """The §5 rule, enforced mechanically rather than by reading.

    If this driver ever constructs the engine, the runner or the
    sandbox directly, it stops proving the HTTP path and silently
    becomes another unit test wearing an E2E's name.
    """
    import ast
    import pathlib
    source = pathlib.Path("e2e/kubernetes_service_http_kind_e2e.py").read_text()
    tree = ast.parse(source)
    forbidden = {"DeploymentEngine", "KubectlRunnerService", "ContainerKubectlSandbox",
                 "KubernetesManifestPolicy", "build_run_plan"}
    built = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id in forbidden
    }
    assert not built, (
        f"the authoritative Workstream B driver constructs {sorted(built)} "
        f"directly; it must reach the system only over HTTP")


def test_workstream_b_driver_talks_http_to_the_real_service():
    import pathlib
    source = pathlib.Path("e2e/kubernetes_service_http_kind_e2e.py").read_text()
    assert "/api/internal/deployments/dry-run" in source
    assert "/approve" in source and "/execute" in source
    assert "urllib.request" in source


def test_workstream_b_driver_refuses_to_fake_a_cluster():
    """A missing Kind control plane must abort, never degrade to a stub."""
    import pathlib
    source = pathlib.Path("e2e/kubernetes_service_http_kind_e2e.py").read_text()
    assert "will not fake one" in source
    for forbidden in ("stub_kubectl", "fake_cluster", "--dry-run=client",
                      "--validate=false"):
        assert forbidden not in source, f"{forbidden} appears on the authoritative path"
