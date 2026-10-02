"""Phase 6.5.2 — authoritative deployment identity → workload runtime.

Security/binding proofs for the release-identity injection at the real
execution boundary (``DeploymentEngine.execute`` → ``kubectl apply``):

* A — exact propagation of the authoritative ``run_id`` + ``head_sha``
  into ``DEVOPS_DEPLOYMENT_ID`` / ``DEVOPS_SOURCE_SHA`` env entries.
* B — both values come from the SAME authoritative run record.
* C — client-controlled manifest env entries cannot influence the
  injected identity (authoritative record wins, duplicates collapsed).
* D — missing/unusable identity fails closed: manifest byte-identical,
  nothing fabricated.
* E — existing deployment/provenance behavior stays green (battery).
* F — injected runtime values are exactly compatible with the Phase
  6.5.1 carrier contract (``backend/app/release_identity.py``).
"""

import importlib.util
from pathlib import Path

import pytest
import yaml

from deployment_service.application.services.deployment_engine import DeploymentEngine
from deployment_service.application.services import release_identity_injection as injection
from deployment_service.application.services.release_identity_injection import (
    DEPLOYMENT_ID_ENV,
    SOURCE_SHA_ENV,
    bind_release_identity,
    inject_release_identity,
    validate_release_identity,
)
from deployment_service.domain.value_objects.deployment_state import DeploymentState
from deployment_service.tests.test_deployment_engine import (
    VALID_PAYLOAD,
    FakeHealth,
    FakeKubectl,
    FakeSourceVerifier,
    FakeStore,
    FakeTerraform,
    FakeValidator,
)

RUN_ID = "run_deadbeef0123"  # exact engine-shaped id fixture
SHA = "0123456789abcdef0123456789abcdef01234567"

# Multi-document manifest: two pod-template kinds, a bare Pod and a
# non-workload document that must never be touched.
MANIFEST = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
spec:
  template:
    spec:
      containers:
        - name: demo
          image: demo:latest
          env:
            - name: PLANTED
              value: keep-me
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly
spec:
  schedule: "0 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: job
              image: job:latest
          initContainers:
            - name: init
              image: init:latest
---
apiVersion: v1
kind: Pod
metadata:
  name: bare
spec:
  containers:
    - name: bare
      image: bare:latest
---
apiVersion: v1
kind: Service
metadata:
  name: demo-svc
spec:
  ports:
    - port: 80
"""


def _all_containers(manifest_text):
    """Independent container walker (does not reuse module internals)."""
    containers = []
    for document in yaml.safe_load_all(manifest_text):
        if not isinstance(document, dict):
            continue
        spec = document.get("spec") or {}
        kind = document.get("kind")
        if kind == "Pod":
            pod_spec = spec
        elif kind == "CronJob":
            pod_spec = (
                ((spec.get("jobTemplate") or {}).get("spec") or {})
                .get("template", {})
                .get("spec")
            )
        else:
            pod_spec = (spec.get("template") or {}).get("spec")
        if not isinstance(pod_spec, dict):
            continue
        for key in ("containers", "initContainers"):
            for container in pod_spec.get(key) or []:
                containers.append(container)
    return containers


def _identity_env(manifest_text):
    """Every DEVOPS_* env entry across all containers (name → [values])."""
    found = {}
    for container in _all_containers(manifest_text):
        for item in container.get("env") or []:
            name = item.get("name")
            if isinstance(name, str) and name.startswith("DEVOPS_"):
                found.setdefault(name, []).append(item)
    return found


def _payload(**overrides):
    body = dict(VALID_PAYLOAD)
    body.update(overrides)
    return body


def _build_engine(kubectl):
    return DeploymentEngine(
        store=FakeStore(),
        validator=FakeValidator(),
        terraform=FakeTerraform(),
        kubectl=kubectl,
        health_checker=FakeHealth(),
        source_verifier=FakeSourceVerifier(),
    )


class RecordingKubectl(FakeKubectl):
    """Captures the exact manifest handed to ``kubectl apply``."""

    def __init__(self):
        self.applied_manifests = []

    def apply(self, manifest_path, namespace):
        self.applied_manifests.append(
            Path(manifest_path).read_text(encoding="utf-8")
        )
        return super().apply(manifest_path, namespace)


def _execute_approved(kubectl, payload):
    engine = _build_engine(kubectl)
    run = engine.create_dry_run(payload)
    engine.approve(run.id, "human", run.artifact_hash, run.plan_hash)
    completed = engine.execute(run.id, payload, run.artifact_hash, run.plan_hash)
    return run, completed


# ---------------------------------------------------------------- A, B


def test_a_exact_propagation_into_container_env():
    text, injected = inject_release_identity(MANIFEST, RUN_ID, SHA)
    assert injected is True
    env = _identity_env(text)
    assert set(env) == {DEPLOYMENT_ID_ENV, SOURCE_SHA_ENV}
    # every container (Deployment, CronJob, init, bare Pod) carries exactly
    # the authoritative pair, with nothing else added
    containers = _all_containers(text)
    assert len(containers) == 4
    for container in containers:
        devops_env = {
            item["name"]: item.get("value")
            for item in container.get("env") or []
            if str(item.get("name", "")).startswith("DEVOPS_")
        }
        assert devops_env == {
            DEPLOYMENT_ID_ENV: RUN_ID,
            SOURCE_SHA_ENV: SHA,
        }
    # non-workload document untouched
    assert "demo-svc" in text


def test_a_engine_execute_injects_authoritative_identity(monkeypatch):
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    kubectl = RecordingKubectl()
    run, completed = _execute_approved(kubectl, _payload())
    assert completed.state == DeploymentState.DEPLOYED
    assert len(kubectl.applied_manifests) == 1
    env = _identity_env(kubectl.applied_manifests[0])
    # exact propagation from the executed run's own record
    assert env[DEPLOYMENT_ID_ENV] == [
        {"name": DEPLOYMENT_ID_ENV, "value": run.id}
    ]
    assert env[SOURCE_SHA_ENV] == [
        {"name": SOURCE_SHA_ENV, "value": run.source_revision["head_sha"]}
    ]


def test_b_same_record_binding(monkeypatch):
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    sha_a = "a" * 40
    sha_b = "b" * 40
    kubectl = RecordingKubectl()
    run_a, done_a = _execute_approved(kubectl, _payload())
    run_b, done_b = _execute_approved(
        kubectl, _payload(source_revision=dict(VALID_PAYLOAD["source_revision"], head_sha=sha_b))
    )
    assert done_a.state == done_b.state == DeploymentState.DEPLOYED
    assert run_a.id != run_b.id
    assert kubectl.applied_manifests[0] is not kubectl.applied_manifests[1]
    env_a = _identity_env(kubectl.applied_manifests[0])
    env_b = _identity_env(kubectl.applied_manifests[1])
    # id AND sha are always read from the SAME run record — never mixed,
    # never global, never derived from request fields
    assert env_a[DEPLOYMENT_ID_ENV][0]["value"] == run_a.id
    assert env_a[SOURCE_SHA_ENV][0]["value"] == sha_a
    assert env_b[DEPLOYMENT_ID_ENV][0]["value"] == run_b.id
    assert env_b[SOURCE_SHA_ENV][0]["value"] == sha_b
    assert run_a.source_revision["head_sha"] == sha_a
    assert run_b.source_revision["head_sha"] == sha_b


# ---------------------------------------------------------------- C


def test_c_client_planted_env_is_replaced_not_extended():
    planted = MANIFEST.replace(
        "env:\n            - name: PLANTED\n              value: keep-me",
        "env:\n"
        "            - name: PLANTED\n"
        "              value: keep-me\n"
        f"            - name: {DEPLOYMENT_ID_ENV}\n"
        "              value: attacker-fabricated-id\n"
        f"            - name: {SOURCE_SHA_ENV}\n"
        "              value: attacker-fabricated-sha\n"
        f"            - name: {DEPLOYMENT_ID_ENV}\n"
        "              value: attacker-duplicate-id",
    )
    text, injected = inject_release_identity(planted, RUN_ID, SHA)
    assert injected is True
    env = _identity_env(text)
    # every container's entries carry only the authoritative values (one
    # entry per name per container), no trace of the planted values anywhere
    assert {item["value"] for item in env[DEPLOYMENT_ID_ENV]} == {RUN_ID}
    assert {item["value"] for item in env[SOURCE_SHA_ENV]} == {SHA}
    for container in _all_containers(text):
        names = [item.get("name") for item in container.get("env") or []]
        assert names.count(DEPLOYMENT_ID_ENV) == 1
        assert names.count(SOURCE_SHA_ENV) == 1
    assert "attacker-fabricated-id" not in text
    assert "attacker-duplicate-id" not in text
    # unrelated client env entries are preserved
    containers = _all_containers(text)
    assert {"name": "PLANTED", "value": "keep-me"} in containers[0]["env"]


def test_c_engine_execute_overrides_planted_identity_in_manifest(monkeypatch):
    # k8s_yaml is the client-controlled channel: plant identity entries in
    # the submitted manifest so they are part of the approved artifact.
    planted_manifest = MANIFEST.replace(
        "value: keep-me",
        f"value: keep-me\n"
        f"            - name: {DEPLOYMENT_ID_ENV}\n"
        f"              value: attacker-fabricated-id",
    )
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    kubectl = RecordingKubectl()
    run, completed = _execute_approved(kubectl, _payload(k8s_yaml=planted_manifest))
    assert completed.state == DeploymentState.DEPLOYED
    env = _identity_env(kubectl.applied_manifests[0])
    assert {item["value"] for item in env[DEPLOYMENT_ID_ENV]} == {run.id}
    assert "attacker-fabricated-id" not in kubectl.applied_manifests[0]


# ---------------------------------------------------------------- D


@pytest.mark.parametrize(
    "deployment_id, source_sha",
    [
        ("", SHA),  # missing id
        ("   ", SHA),  # blank id
        (None, SHA),  # non-string id
        (RUN_ID, ""),  # missing sha
        (RUN_ID, "0123456789ABCDEF0123456789ABCDEF01234567"),  # uppercase
        (RUN_ID, "0123456789abcdef"),  # short sha
        (RUN_ID, SHA + "0"),  # long sha
        (RUN_ID, "sha:" + SHA),  # prefixed sha
        (RUN_ID, SHA.upper()),  # fully uppercase sha
        (f"run\nx{RUN_ID}", SHA),  # control character in id
        ("i" * 129, SHA),  # overlong id
    ],
)
def test_d_unusable_identity_is_not_injected(deployment_id, source_sha):
    text, injected = inject_release_identity(MANIFEST, deployment_id, source_sha)
    assert injected is False
    assert text == MANIFEST  # byte-identical, nothing fabricated
    assert validate_release_identity(deployment_id, source_sha) is None


def test_d_bind_file_fails_closed(tmp_path):
    target = tmp_path / "deployment.yaml"
    target.write_text(MANIFEST, encoding="utf-8")
    assert bind_release_identity(str(target), RUN_ID, "not-a-sha") is False
    assert target.read_text(encoding="utf-8") == MANIFEST


def test_d_unparseable_manifest_is_left_unchanged():
    broken = "kind: Deployment\n  spec: [unclosed\n"
    text, injected = inject_release_identity(broken, RUN_ID, SHA)
    assert injected is False
    assert text == broken


def test_d_manifest_without_containers_is_left_unchanged():
    service_only = "apiVersion: v1\nkind: Service\nmetadata:\n  name: s\n"
    text, injected = inject_release_identity(service_only, RUN_ID, SHA)
    assert injected is False
    assert text == service_only


# ---------------------------------------------------------------- F


def test_f_injected_values_satisfy_carrier_validation_rules(monkeypatch):
    """The env produced by a real execution passes the 6.5.1 rules."""
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    kubectl = RecordingKubectl()
    run, _ = _execute_approved(kubectl, _payload())
    env = _identity_env(kubectl.applied_manifests[0])
    injected_id = env[DEPLOYMENT_ID_ENV][0]["value"]
    injected_sha = env[SOURCE_SHA_ENV][0]["value"]
    # rules restated from backend/app/release_identity.py:
    assert injected_id == run.id
    assert injected_id.strip()  # non-blank
    assert 1 <= len(injected_id) <= injection.MAX_DEPLOYMENT_ID_LENGTH
    assert not any(ord(c) < 32 or ord(c) == 127 for c in injected_id)
    assert len(injected_sha) == 40
    assert all(c in "0123456789abcdef" for c in injected_sha)


def _load_carrier_module():
    """Load backend/app/release_identity.py directly (no app startup)."""
    backend_contract = (
        Path(__file__).resolve().parents[3] / "backend" / "app" / "release_identity.py"
    )
    if not backend_contract.exists():
        pytest.skip("backend carrier contract not present in this checkout")
    spec = importlib.util.spec_from_file_location(
        "carrier_contract_under_test", backend_contract
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_f_carrier_contract_accepts_engine_identity(monkeypatch):
    """REAL cross-boundary proof: values injected at the execution boundary
    are accepted by the actual Phase 6.5.1 carrier module, producing the
    devops_release_identity_info series (no live Prometheus involved)."""
    monkeypatch.setenv("DEPLOYMENT_EXECUTION_ENABLED", "true")
    kubectl = RecordingKubectl()
    run, _ = _execute_approved(kubectl, _payload())
    env = _identity_env(kubectl.applied_manifests[0])
    injected_id = env[DEPLOYMENT_ID_ENV][0]["value"]
    injected_sha = env[SOURCE_SHA_ENV][0]["value"]

    carrier = _load_carrier_module()
    # contract names unchanged on both sides
    assert carrier.DEPLOYMENT_ID_ENV == DEPLOYMENT_ID_ENV == "DEVOPS_DEPLOYMENT_ID"
    assert carrier.SOURCE_SHA_ENV == SOURCE_SHA_ENV == "DEVOPS_SOURCE_SHA"
    assert carrier.validate_deployment_id(injected_id) == injected_id
    assert carrier.validate_source_sha(injected_sha) == injected_sha

    from prometheus_client import CollectorRegistry, Gauge, generate_latest

    registry = CollectorRegistry()
    gauge = Gauge(
        carrier.RELEASE_IDENTITY._name,
        carrier.RELEASE_IDENTITY._documentation,
        ["deployment_id", "source_sha"],
        registry=registry,
    )
    assert carrier.apply_release_identity(injected_id, injected_sha, gauge=gauge) is True
    body = generate_latest(registry).decode()
    assert f'{{deployment_id="{injected_id}",source_sha="{injected_sha}"}} 1.0' in body
