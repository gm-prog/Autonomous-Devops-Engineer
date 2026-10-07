"""Phase 8.6-A corrective, Workstream A.

A deployment may declare which components it contains. A component that
was not requested is NOT APPLICABLE: nothing is validated, planned or
executed for it, and no sandbox is invoked on its behalf.

The security-critical property is that "not requested" and "requested
but failed" never collapse into one another, and that a malformed or
contradictory payload can never reach "not applicable".
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from deployment_service.application.services.deployment_engine import DeploymentEngine
from deployment_service.application.services.iac_validator import IaCValidator
from deployment_service.main import KNOWN_COMPONENTS, app

TF = 'resource "null_resource" "x" {}\n'
DOCKERFILE = "FROM scratch\n"
PIPELINE = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
MANIFEST = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"


# ---------------------------------------------------------------- validator

def test_unrequested_component_is_not_applicable_not_passed():
    result = IaCValidator().validate("", "", TF, "", ["terraform"])
    assert result["status"] == "PASS"
    assert result["checks"]["kubernetes"]["status"] == "NOT_APPLICABLE"
    assert result["checks"]["kubernetes"]["status"] != "PASS", \
        "a skipped component must never be reported as having passed"


def test_requested_but_empty_component_still_fails():
    """'Not requested' and 'requested but failed' must not collapse."""
    result = IaCValidator().validate("", "", TF, "", ["terraform", "kubernetes"])
    assert result["status"] == "FAIL"
    assert result["checks"]["kubernetes"]["status"] == "FAIL"
    assert "empty" in result["checks"]["kubernetes"]["errors"][0].lower()


def test_content_for_an_unrequested_component_is_rejected():
    """A malformed payload must never reach 'not applicable'."""
    result = IaCValidator().validate("", MANIFEST, TF, "", ["terraform"])
    assert result["status"] == "FAIL"
    assert result["checks"]["kubernetes"]["status"] == "FAIL"
    assert "not a requested component" in result["checks"]["kubernetes"]["errors"][0]


def test_default_selection_preserves_legacy_behaviour():
    legacy = IaCValidator().validate(DOCKERFILE, "", TF, PIPELINE)
    assert legacy["checks"]["kubernetes"]["status"] == "FAIL", \
        "with no selection an absent manifest is still an error"


@pytest.mark.parametrize("component", KNOWN_COMPONENTS)
def test_every_component_can_be_individually_omitted(component):
    requested = [c for c in KNOWN_COMPONENTS if c != component]
    result = IaCValidator().validate(
        DOCKERFILE if "dockerfile" in requested else "",
        MANIFEST if "kubernetes" in requested else "",
        TF if "terraform" in requested else "",
        PIPELINE if "pipeline" in requested else "",
        requested)
    assert result["checks"][component]["status"] == "NOT_APPLICABLE"
    assert result["requested_components"] == requested


# ------------------------------------------------------------------- engine

def test_engine_applicability_follows_the_declared_selection():
    assert DeploymentEngine._kubernetes_is_declared(
        {"components": ["terraform"], "k8s_yaml": ""}) is False
    assert DeploymentEngine._kubernetes_is_declared(
        {"components": ["terraform", "kubernetes"], "k8s_yaml": MANIFEST}) is True


def test_selection_is_bound_into_the_artifact_hash():
    """A terraform-only approval can never later acquire Kubernetes."""
    base = {"dockerfile": "", "k8s_yaml": "", "terraform_tf": TF, "pipeline_yaml": ""}
    tf_only = DeploymentEngine._artifact_hash({**base, "components": ["terraform"]})
    with_k8s = DeploymentEngine._artifact_hash(
        {**base, "components": ["terraform", "kubernetes"]})
    assert tf_only != with_k8s


def test_not_applicable_result_is_explicit_and_not_a_success():
    result = DeploymentEngine._kubernetes_not_applicable()
    assert result.get("cluster_access") is not True
    assert result.get("status") != "PASS"


# ---------------------------------------------------------------- contract

@pytest.fixture()
def client():
    return TestClient(app)


def _payload(**over):
    body = {
        "repository_id": 1, "repository_name": "acme/demo", "requested_by": "dev",
        "dockerfile": DOCKERFILE, "k8s_yaml": MANIFEST, "terraform_tf": TF,
        "pipeline_yaml": PIPELINE,
        "source_revision": {"head_sha": "a" * 40, "ref": "refs/heads/main"},
    }
    body.update(over)
    return body


def test_components_defaults_to_all_so_existing_callers_are_unaffected(client):
    r = client.post("/api/internal/deployments/dry-run", json=_payload())
    assert r.status_code != 422, r.text


def test_unknown_component_is_rejected_by_the_contract(client):
    r = client.post("/api/internal/deployments/dry-run",
                    json=_payload(components=["terraform", "wordpress"]))
    assert r.status_code == 422
    assert "unknown component" in r.text


def test_empty_component_selection_is_rejected(client):
    r = client.post("/api/internal/deployments/dry-run",
                    json=_payload(components=[]))
    assert r.status_code == 422


def test_repeated_component_is_rejected(client):
    r = client.post("/api/internal/deployments/dry-run",
                    json=_payload(components=["terraform", "terraform"]))
    assert r.status_code == 422


def test_k8s_yaml_remains_a_required_field(client):
    """The API contract is unchanged: omission is still a 422."""
    body = _payload()
    del body["k8s_yaml"]
    assert client.post("/api/internal/deployments/dry-run", json=body).status_code == 422
