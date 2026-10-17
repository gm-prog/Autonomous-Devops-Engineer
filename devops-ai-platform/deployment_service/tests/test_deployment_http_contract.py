"""Deployment HTTP contract: canonical repository + exact source revision.

Covers the HTTP boundary of the trust chain:

    HTTP request -> request model -> engine -> plan -> persistence -> evidence

* `source_revision.head_sha` is mandatory, 40-hex, normalized to lowercase.
* `repository_name` must be canonical `owner/repo`.
* The pair survives parsing, plan creation, persistence and the evidence
  endpoint unchanged (HTTP preservation invariant).
* Plan identity includes both the source SHA and the repository identity.
* A dry-run alone produces AWAITING_APPROVAL - never an authoritative state.
"""

import unittest
from unittest.mock import patch

from deployment_service.main import app as deployment_app
from deployment_service.tests.test_deployment_engine import (
    VALID_PAYLOAD,
    FakeHealth,
    FakeKubectl,
    FakeSourceVerifier,
    FakeStore,
    FakeTerraform,
    FakeValidator,
)
from shared_kernel.domain.provenance import verify_provenance_record

from fastapi.testclient import TestClient

SHA_A = "a" * 40
SHA_B = "B" * 40  # uppercase in requests must normalize to lowercase

client = TestClient(deployment_app)


def _payload(repository_name="acme/checkout", head_sha=SHA_A, **overrides):
    body = dict(VALID_PAYLOAD)
    body.update(
        repository_name=repository_name,
        source_revision=dict(VALID_PAYLOAD["source_revision"], head_sha=head_sha),
    )
    body.update(overrides)
    # VALID_PAYLOAD carries a canonical acme/demo pair; force the test pair
    body["repository_id"] = overrides.get("repository_id", 1)
    return body


class DeploymentHttpContractTests(unittest.TestCase):
    def setUp(self):
        self.store = FakeStore()
        import deployment_service.main as deployment_main

        self._originals = {
            name: getattr(deployment_main.engine, name)
            for name in (
                "store",
                "validator",
                "terraform",
                "kubectl",
                "health_checker",
                "source_verifier",
            )
        }
        deployment_main.engine.store = self.store
        deployment_main.engine.validator = FakeValidator()
        deployment_main.engine.terraform = FakeTerraform()
        deployment_main.engine.kubectl = FakeKubectl()
        deployment_main.engine.health_checker = FakeHealth()
        # deterministic source verification (no network in contract tests)
        deployment_main.engine.source_verifier = FakeSourceVerifier()
        self.addCleanup(self._restore)

    def _restore(self):
        import deployment_service.main as deployment_main

        for name, value in self._originals.items():
            setattr(deployment_main.engine, name, value)

    # ---------------- happy path / preservation ----------------

    def test_valid_canonical_repository_and_sha_accepted(self):
        resp = client.post(
            "/api/internal/deployments/dry-run", json=_payload()
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertEqual(body["repository_name"], "acme/checkout")
        self.assertEqual(body["source_revision"]["head_sha"], SHA_A)
        self.assertEqual(body["state"], "AWAITING_APPROVAL")

    def test_uppercase_sha_is_normalized_to_lowercase(self):
        resp = client.post(
            "/api/internal/deployments/dry-run",
            json=_payload(head_sha=SHA_B),
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json()["source_revision"]["head_sha"], SHA_B.lower())

    def test_whitespace_padded_sha_is_stripped_and_accepted(self):
        resp = client.post(
            "/api/internal/deployments/dry-run",
            json=_payload(head_sha=f"  {SHA_A}\n"),
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json()["source_revision"]["head_sha"], SHA_A)

    def test_source_revision_survives_request_plan_persistence_and_evidence(self):
        """HTTP preservation invariant (§22): request SHA == plan SHA ==
        persisted/evidence SHA, fetched back over the same HTTP contract."""
        resp = client.post(
            "/api/internal/deployments/dry-run", json=_payload()
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        run_id = resp.json()["id"]

        # plan identity carries the SHA (64-hex plan_hash exists)
        self.assertEqual(len(resp.json()["plan_hash"]), 64)

        # persisted evidence endpoint returns the exact same pair
        fetched = client.get(f"/api/internal/deployments/{run_id}")
        self.assertEqual(fetched.status_code, 200, fetched.text)
        evidence = fetched.json()
        self.assertEqual(evidence["repository_name"], "acme/checkout")
        self.assertEqual(evidence["source_revision"]["head_sha"], SHA_A)
        self.assertEqual(evidence["state"], "AWAITING_APPROVAL")

    def test_unknown_source_revision_fields_are_dropped(self):
        resp = client.post(
            "/api/internal/deployments/dry-run",
            json=_payload(source_revision={"head_sha": SHA_A, "branch": "main"}),
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        persisted = resp.json()["source_revision"]
        self.assertNotIn("branch", persisted)
        self.assertEqual(persisted["head_sha"], SHA_A)

    def test_dry_run_alone_is_not_an_authoritative_state(self):
        resp = client.post(
            "/api/internal/deployments/dry-run", json=_payload()
        )
        self.assertEqual(resp.status_code, 200)
        self.assertNotEqual(resp.json()["state"], "DEPLOYED")

    # ---------------- plan identity (§6) ----------------

    def test_changing_sha_changes_plan_identity(self):
        first = client.post("/api/internal/deployments/dry-run", json=_payload())
        second = client.post(
            "/api/internal/deployments/dry-run",
            json=_payload(head_sha="b" * 40),
        )
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(second.status_code, 200, second.text)
        self.assertNotEqual(first.json()["plan_hash"], second.json()["plan_hash"])

    def test_changing_repository_changes_plan_identity(self):
        first = client.post("/api/internal/deployments/dry-run", json=_payload())
        second = client.post(
            "/api/internal/deployments/dry-run",
            json=_payload(repository_name="acme/payments"),
        )
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(second.status_code, 200, second.text)
        self.assertNotEqual(first.json()["plan_hash"], second.json()["plan_hash"])

    # ---------------- rejection matrix (§4/§5/§24) ----------------

    def test_malformed_repository_rejected(self):
        for bad in (
            "checkout",
            "acme",
            "a/b/c",
            "../checkout",
            "https://github.com/acme/checkout",
            "git@github.com:acme/checkout.git",
            "",
            "acme/check out",
        ):
            with self.subTest(repository=bad):
                resp = client.post(
                    "/api/internal/deployments/dry-run",
                    json=_payload(repository_name=bad),
                )
                self.assertEqual(resp.status_code, 422, resp.text)

    def test_malformed_sha_rejected(self):
        for bad in (
            "abc",
            "main",
            "master",
            "refs/heads/main",
            "refs/tags/v1",
            "a" * 39,
            "a" * 41,
            "z" * 40,
            "",
        ):
            with self.subTest(head_sha=bad):
                resp = client.post(
                    "/api/internal/deployments/dry-run",
                    json=_payload(head_sha=bad),
                )
                self.assertEqual(resp.status_code, 422, resp.text)

    def test_missing_source_revision_rejected(self):
        body = _payload()
        body.pop("source_revision")
        resp = client.post("/api/internal/deployments/dry-run", json=body)
        self.assertEqual(resp.status_code, 422, resp.text)

    def test_missing_head_sha_rejected(self):
        body = _payload()
        body["source_revision"] = {"commits": []}
        resp = client.post("/api/internal/deployments/dry-run", json=body)
        self.assertEqual(resp.status_code, 422, resp.text)

    def test_null_or_non_string_sha_rejected(self):
        for bad in (None, 12345, ["a"] * 40):
            with self.subTest(head_sha=bad):
                resp = client.post(
                    "/api/internal/deployments/dry-run",
                    json=_payload(source_revision={"head_sha": bad}),
                )
                self.assertEqual(resp.status_code, 422, resp.text)

    def test_whitespace_padded_repository_rejected(self):
        resp = client.post(
            "/api/internal/deployments/dry-run",
            json=_payload(repository_name="  acme/checkout"),
        )
        self.assertEqual(resp.status_code, 422, resp.text)

    # ---------------- Stage 5: source verification (§B) ----------------

    def test_dry_run_records_independent_source_verification(self):
        resp = client.post("/api/internal/deployments/dry-run", json=_payload())
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertEqual(
            body["source_verification"]["method"], FakeSourceVerifier.METHOD
        )
        self.assertEqual(
            body["source_verification"]["verified_source_sha"], SHA_A
        )
        provenance = body["provenance"]
        verify_provenance_record(provenance)  # no raise
        self.assertEqual(provenance["verification_method"], FakeSourceVerifier.METHOD)
        self.assertEqual(provenance["state"], "AWAITING_APPROVAL")

    def test_unverified_source_revision_rejected_and_no_run_persisted(self):
        """A revision the provider does not confirm → 422 and NO run exists
        (fail closed; nothing to approve, nothing to collect evidence from)."""
        import deployment_service.main as deployment_main

        deployment_main.engine.source_verifier = FakeSourceVerifier(
            accepted_pairs=set()
        )
        resp = client.post(
            "/api/internal/deployments/dry-run",
            json=_payload(repository_name="acme/checkout", head_sha="f" * 40),
        )
        self.assertEqual(resp.status_code, 422, resp.text)
        self.assertIn("not found", resp.json()["detail"])
        self.assertEqual(len(self.store.data), 0)

    def test_source_verification_unavailable_fails_closed_503(self):
        import deployment_service.main as deployment_main
        from deployment_service.application.services.source_verification import (
            SourceVerificationError,
        )

        class _Unavailable:
            def verify(self, repository_name, head_sha):
                raise SourceVerificationError(
                    "unavailable",
                    "source verification is currently unavailable; "
                    "deployment requests fail closed",
                )

        deployment_main.engine.source_verifier = _Unavailable()
        resp = client.post("/api/internal/deployments/dry-run", json=_payload())
        self.assertEqual(resp.status_code, 503, resp.text)
        self.assertIn("fail closed", resp.json()["detail"])
        self.assertEqual(len(self.store.data), 0)

    # ---------------- Stage 5: no state/identity forgery (§L/§M) ----------------

    def test_caller_supplied_state_is_dropped_and_never_reaches_provenance(self):
        """`state` and `provenance` are not part of the request contract:
        pydantic drops them and the run state/provenance come only from the
        server-side state machine."""
        forged_provenance = {
            "schema": "devops.deployment-provenance/1",
            "state": "DEPLOYED",
            "provenance_hash": "0" * 64,
        }
        resp = client.post(
            "/api/internal/deployments/dry-run",
            json=_payload(state="DEPLOYED", provenance=forged_provenance),
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertEqual(body["state"], "AWAITING_APPROVAL")
        self.assertNotEqual(body["state"], "DEPLOYED")
        provenance = body["provenance"]
        self.assertEqual(provenance["state"], "AWAITING_APPROVAL")
        self.assertNotEqual(provenance, forged_provenance)
        verify_provenance_record(provenance)  # server-derived, self-consistent

    def test_caller_supplied_state_cannot_skip_approval(self):
        dry = client.post("/api/internal/deployments/dry-run", json=_payload())
        self.assertEqual(dry.status_code, 200, dry.text)
        run = dry.json()
        resp = client.post(
            f"/api/internal/deployments/{run['id']}/approve",
            json={
                "approved_by": "attacker",
                "state": "DEPLOYED",
                "artifact_hash": run["artifact_hash"],
                "plan_hash": run["plan_hash"],
            },
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        # the state machine, not the request body, decided the transition
        self.assertEqual(resp.json()["state"], "APPROVED")

    def test_execute_with_mutated_artifact_is_rejected_409(self):
        """Artifacts mutated after approval cannot execute under the old
        artifact hash (execution stays bound to the approved identity)."""
        dry = client.post("/api/internal/deployments/dry-run", json=_payload())
        self.assertEqual(dry.status_code, 200, dry.text)
        run = dry.json()
        approval = client.post(
            f"/api/internal/deployments/{run['id']}/approve",
            json={
                "approved_by": "human",
                "artifact_hash": run["artifact_hash"],
                "plan_hash": run["plan_hash"],
            },
        )
        self.assertEqual(approval.status_code, 200, approval.text)
        with patch.dict("os.environ", {"DEPLOYMENT_EXECUTION_ENABLED": "true"}):
            resp = client.post(
                f"/api/internal/deployments/{run['id']}/execute",
                json={
                    "artifact_hash": run["artifact_hash"],
                    "plan_hash": run["plan_hash"],
                    "dockerfile": "FROM python:3.11-slim\nUSER 0\n",  # mutated
                    "k8s_yaml": _payload()["k8s_yaml"],
                    "terraform_tf": _payload()["terraform_tf"],
                    "pipeline_yaml": _payload()["pipeline_yaml"],
                },
            )
        self.assertEqual(resp.status_code, 409, resp.text)
        self.assertIn("immutable approved artifact hash", resp.json()["detail"])

    def test_execute_with_tampered_plan_hash_is_rejected_409(self):
        dry = client.post("/api/internal/deployments/dry-run", json=_payload())
        self.assertEqual(dry.status_code, 200, dry.text)
        run = dry.json()
        approval = client.post(
            f"/api/internal/deployments/{run['id']}/approve",
            json={
                "approved_by": "human",
                "artifact_hash": run["artifact_hash"],
                "plan_hash": run["plan_hash"],
            },
        )
        self.assertEqual(approval.status_code, 200, approval.text)
        with patch.dict("os.environ", {"DEPLOYMENT_EXECUTION_ENABLED": "true"}):
            resp = client.post(
                f"/api/internal/deployments/{run['id']}/execute",
                json={
                    "artifact_hash": run["artifact_hash"],
                    "plan_hash": "0" * 64,  # tampered
                    "dockerfile": _payload()["dockerfile"],
                    "k8s_yaml": _payload()["k8s_yaml"],
                    "terraform_tf": _payload()["terraform_tf"],
                    "pipeline_yaml": _payload()["pipeline_yaml"],
                },
            )
        self.assertEqual(resp.status_code, 409, resp.text)
        self.assertIn("approval record", resp.json()["detail"])

    def test_evidence_endpoint_carries_verifiable_provenance(self):
        """GET evidence (the surface the incident collector reads) exposes
        the run's source verification and a provenance record that validates."""
        resp = client.post("/api/internal/deployments/dry-run", json=_payload())
        self.assertEqual(resp.status_code, 200, resp.text)
        run_id = resp.json()["id"]
        fetched = client.get(f"/api/internal/deployments/{run_id}")
        self.assertEqual(fetched.status_code, 200, fetched.text)
        evidence = fetched.json()
        self.assertEqual(
            evidence["source_verification"]["method"], FakeSourceVerifier.METHOD
        )
        verify_provenance_record(evidence["provenance"])  # no raise
        self.assertEqual(evidence["provenance"]["repository_name"], "acme/checkout")
        self.assertEqual(evidence["provenance"]["source_sha"], SHA_A)


if __name__ == "__main__":
    unittest.main()
