"""End-to-end trust chain: HTTP deployment → evidence → remediation auth.

Proves the complete provenance path demanded by the security objective:

    authenticated (in-network) HTTP deployment request
        → validated source_revision.head_sha
        → deployment plan bound to the exact SHA (+ repository identity)
        → persisted deployment evidence (state=DEPLOYED)
        → incident evidence via the REAL DeploymentEvidenceCollector
        → remediation target binding (same-record pair)
        → orchestrator constructed only after authorization

plus the two attack variants (wrong SHA; cross-evidence repo/SHA mixing).

Trust boundary note: the deployment/incident services are reachable only on
the private compose network (no host ports); the external boundary is the
authenticated API gateway, covered by api_gateway tests. This test plays the
role of an in-network caller and exercises the real HTTP handlers, real
state machine, real persistence objects and real collector normalization -
only external tools (terraform/kubectl) and the process boundary of Redis
are replaced with deterministic fakes, exactly as in the engine unit tests.
"""

import os
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import HTTPException
from fastapi.testclient import TestClient

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

from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.infrastructure.database.postgres_incident_repo import (
    PostgresIncidentRepositoryAdapter,
)
from incident_service.presentation.rest import controllers as controllers_module
from incident_service.presentation.rest.controllers import (
    RemediationRequest,
    create_remediation,
)

import tempfile

SHA_A = "a" * 40
SHA_B = "b" * 40

REMEDIATION_PATCH = """--- a/src/service.py
+++ b/src/service.py
@@ -1 +1 @@
-old()
+new()
"""


class _RoutedResponse:
    """urlopen-compatible response backed by the deployment TestClient."""

    def __init__(self, status: int, body: bytes):
        self._status, self._body = status, body

    def getcode(self):
        return self._status

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _route_urlopen_to_test_client(client: TestClient):
    """Pipe the real collector's urlopen call into the real HTTP app so the
    evidence that reaches the incident is produced by the live endpoint."""

    def _router(request, timeout=None):
        url = request.full_url  # e.g. http://deployment-service:8030/api/...
        path = "/" + url.split("/", 3)[3]
        response = client.get(path)
        return _RoutedResponse(response.status_code, response.content)

    return _router


def _orchestrator_spy():
    spy = MagicMock()
    spy.execute.return_value = MagicMock(
        incident_id="inc-e2e",
        proposal_id="remediation-inc-e2e",
        source_sha=SHA_A,
        branch_name="automation/remediation/inc-e2e/remediation-inc-e2e",
        commit_sha="c" * 40,
        pull_request_url="https://github.com/acme/checkout/pull/4242",
        validation_result=MagicMock(passed=True, steps=[]),
    )
    return spy


class DeploymentToRemediationEndToEndTests(unittest.TestCase):
    def setUp(self):
        import deployment_service.main as deployment_main

        self.client = TestClient(deployment_app)
        self.store = FakeStore()
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
        # deterministic source verification: the E2E proves the chain, not
        # GitHub's availability (the real verifier has its own unit tests)
        deployment_main.engine.source_verifier = FakeSourceVerifier()
        self.addCleanup(self._restore)

        self._tmp = tempfile.TemporaryDirectory()
        self.repository = PostgresIncidentRepositoryAdapter(
            f"sqlite:///{os.path.join(self._tmp.name, 'incidents.db')}"
        )
        self.addCleanup(self._tmp.cleanup)

    def _restore(self):
        import deployment_service.main as deployment_main

        for name, value in self._originals.items():
            setattr(deployment_main.engine, name, value)

    # ---------- Step A: full HTTP deployment to DEPLOYED ----------

    def _deploy(self, repository_name: str, head_sha: str) -> dict:
        body = dict(VALID_PAYLOAD)
        body.update(repository_name=repository_name)
        body["source_revision"] = dict(
            VALID_PAYLOAD["source_revision"], head_sha=head_sha
        )

        # A1: authenticated (in-network) dry-run request
        dry = self.client.post("/api/internal/deployments/dry-run", json=body)
        self.assertEqual(dry.status_code, 200, dry.text)
        run = dry.json()

        # B: response carries the exact source revision
        self.assertEqual(run["source_revision"]["head_sha"], head_sha.lower())
        self.assertEqual(run["repository_name"], repository_name)
        self.assertEqual(run["state"], "AWAITING_APPROVAL")

        # approve (hashes returned by the service - not attacker-chosen)
        approval = self.client.post(
            f"/api/internal/deployments/{run['id']}/approve",
            json={
                "approved_by": "e2e-tester",
                "artifact_hash": run["artifact_hash"],
                "plan_hash": run["plan_hash"],
            },
        )
        self.assertEqual(approval.status_code, 200, approval.text)

        with patch.dict(os.environ, {"DEPLOYMENT_EXECUTION_ENABLED": "true"}):
            execute = self.client.post(
                f"/api/internal/deployments/{run['id']}/execute",
                json={
                    "artifact_hash": run["artifact_hash"],
                    "plan_hash": run["plan_hash"],
                    "dockerfile": body["dockerfile"],
                    "k8s_yaml": body["k8s_yaml"],
                    "terraform_tf": body["terraform_tf"],
                    "pipeline_yaml": body["pipeline_yaml"],
                },
            )
        self.assertEqual(execute.status_code, 200, execute.text)
        self.assertEqual(execute.json()["state"], "DEPLOYED")

        # C: persisted evidence over HTTP
        evidence = self.client.get(f"/api/internal/deployments/{run['id']}")
        self.assertEqual(evidence.status_code, 200, evidence.text)
        payload = evidence.json()
        self.assertEqual(payload["repository_name"], repository_name)
        self.assertEqual(payload["source_revision"]["head_sha"], head_sha.lower())
        self.assertEqual(payload["state"], "DEPLOYED")
        return payload

    def _incident_with_collected_evidence(self, run_id: str, incident_id: str):
        """D: attach evidence through the REAL collector + real incident."""
        from incident_service.infrastructure.deployment.deployment_evidence_collector import (
            DeploymentEvidenceCollector,
        )

        router = _route_urlopen_to_test_client(self.client)
        with patch(
            "incident_service.infrastructure.deployment."
            "deployment_evidence_collector.urlopen",
            side_effect=router,
        ):
            evidence = DeploymentEvidenceCollector(
                base_url="http://deployment-service:8030"
            ).collect(run_id)

        incident = IncidentAggregate(incident_id, "Checkout 5xx", "HIGH", "gateway")
        incident.move_to_triage()
        incident.attach_evidence(evidence)
        from incident_service.presentation.rest.test_remediation_authorization import (
            promote_to_root_cause_found,
        )

        # canonical precondition for proposal intake (Phase 8/8.1)
        promote_to_root_cause_found(incident)
        self.repository.save_incident(incident)
        return incident, evidence

    def _remediate(self, incident_id, repository_slug, source_sha):
        spy = _orchestrator_spy()
        request = RemediationRequest(
            target_filepath="src/service.py",
            patch=REMEDIATION_PATCH,
            source_sha=source_sha,
            repository_slug=repository_slug,
        )
        with patch.object(
            controllers_module,
            "get_remediation_orchestrator",
            return_value=spy,
        ) as provider:
            try:
                result = create_remediation(incident_id, request, self.repository)
            except Exception as exc:  # HTTPException on rejection
                return spy, provider, exc
            return spy, provider, result

    # ---------- E: exact pair authorizes through the whole chain ----------

    def test_http_deployment_reaches_remediation_authorization(self):
        payload = self._deploy("acme/checkout", SHA_A)
        incident, evidence = self._incident_with_collected_evidence(
            payload["id"], "inc-e2e"
        )

        # HTTP preservation: every hop carries the same canonical pair
        self.assertEqual(evidence.payload["repository_name"], "acme/checkout")
        self.assertEqual(evidence.payload["source_revision"]["head_sha"], SHA_A)
        self.assertEqual(evidence.payload["state"], "DEPLOYED")

        spy, provider, result = self._remediate(
            incident.id, "acme/checkout", SHA_A.upper()  # normalization hop
        )
        self.assertNotIsInstance(result, Exception, result)
        # Phase 8.1 shim: binding passes but the legacy route stops at
        # PROPOSED — no orchestrator, no PR (normalization still honored).
        provider.assert_not_called()
        spy.execute.assert_not_called()
        self.assertEqual(result["status"], "PROPOSED")
        self.assertEqual(result["source_sha"], SHA_A)
        self.assertNotIn("pull_request_url", result)

    # ---------- F: wrong SHA ----------

    def test_wrong_source_sha_is_rejected(self):
        payload = self._deploy("acme/checkout", SHA_A)
        incident, _ = self._incident_with_collected_evidence(
            payload["id"], "inc-e2e-f"
        )

        spy, provider, exc = self._remediate(
            incident.id, "acme/checkout", SHA_B
        )
        from fastapi import HTTPException

        self.assertIsInstance(exc, HTTPException)
        self.assertEqual(exc.status_code, 403)
        provider.assert_not_called()
        spy.execute.assert_not_called()

    # ---------- G: cross-evidence mixing ----------

    def test_cross_evidence_mixing_is_rejected(self):
        # Deployment A: acme/payment + SHA_A ; Deployment B: evil/checkout + SHA_B
        payload_a = self._deploy("acme/payment", SHA_A)
        payload_b = self._deploy("evil/checkout", SHA_B)

        self._incident_with_collected_evidence(payload_a["id"], "inc-e2e-a")
        self._incident_with_collected_evidence(payload_b["id"], "inc-e2e-g")
        # one incident holding BOTH evidence records (as an attacker with
        # write access to incident evidence might arrange). The evidence rows
        # are keyed by a global id, so deployment A's record is re-attached
        # under a fresh storage identity with its payload byte-identical -
        # the security-relevant content (kind/state/repository/SHA) is exact.
        from incident_service.domain.entities.incident_evidence import (
            IncidentEvidence,
        )

        combined = self.repository.get_incident_by_id("inc-e2e-g")
        for item in self.repository.get_incident_by_id("inc-e2e-a").evidence:
            combined.attach_evidence(
                IncidentEvidence(
                    id=f"grafted-{item.id}",
                    kind=item.kind,
                    source=item.source,
                    observed_at=item.observed_at,
                    payload=dict(item.payload),
                )
            )
        self.repository.save_incident(combined)

        # request: repository from B + SHA from A → rejected
        spy, provider, exc = self._remediate(
            "inc-e2e-g", "evil/checkout", SHA_A
        )
        from fastapi import HTTPException

        self.assertIsInstance(exc, HTTPException)
        self.assertEqual(exc.status_code, 403)
        provider.assert_not_called()
        spy.execute.assert_not_called()

        # and each record's OWN pair still works (state provenance intact)
        spy_b, provider_b, result_b = self._remediate(
            "inc-e2e-g", "evil/checkout", SHA_B
        )
        self.assertNotIsInstance(result_b, Exception, result_b)
        provider_b.assert_not_called()
        spy_b.execute.assert_not_called()
        self.assertEqual(result_b["status"], "PROPOSED")
        self.assertEqual(result_b["repository"], "evil/checkout")
        self.assertEqual(result_b["source_sha"], SHA_B)

    # ---------- Phase 8.1 §26: legacy → restart → canonical chain -------

    def test_phase81_restart_approve_execute_then_cannot_reset(self):
        from fastapi import HTTPException

        from incident_service.application.services.proposal_approval_service import (
            ProposalApprovalService,
        )
        from incident_service.application.services.proposal_execution_service import (
            ProposalExecutionService,
        )
        from incident_service.presentation.rest.controllers import (
            ProposalExecutionRequest,
            execute_proposal,
        )

        # 1) legacy intake stops at PROPOSED
        payload = self._deploy("acme/checkout", SHA_A)
        incident, _ = self._incident_with_collected_evidence(
            payload["id"], "inc-p81-26"
        )
        spy, provider, result = self._remediate(
            incident.id, "acme/checkout", SHA_A
        )
        self.assertNotIsInstance(result, Exception, result)
        self.assertEqual(result["status"], "PROPOSED")
        provider.assert_not_called()
        spy.execute.assert_not_called()

        # 2) RESTART: a brand-new process = fresh adapter + engine over the
        #    same durable file; the proposal and version both survive.
        restarted = PostgresIncidentRepositoryAdapter(
            f"sqlite:///{os.path.join(self._tmp.name, 'incidents.db')}"
        )
        loaded = restarted.get_incident_by_id(incident.id)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.patch_proposals[0].status, "PROPOSED")
        durable_version = loaded.version

        # 3) canonical approval on the restarted process
        ProposalApprovalService(restarted).approve(
            incident_id=incident.id,
            proposal_id=result["proposal_id"],
            proposal_hash=result["proposal_hash"],
            approved_by="alice-operator",
        )
        approved = restarted.get_incident_by_id(incident.id)
        self.assertEqual(approved.patch_proposals[0].status, "APPROVED")
        self.assertGreater(approved.version, durable_version)

        # 4) canonical execution → PR_CREATED (real execution service,
        #    orchestrator faked at the documented factory seam only)
        def orchestrator_factory():
            def execute(
                incident_id,
                proposal,
                repository_slug,
                validation_profile,
                stage_callback=None,
                before_side_effect=None,
            ):
                return SimpleNamespace(
                    proposal_id=proposal.id,
                    incident_id=incident_id,
                    source_sha=proposal.source_sha,
                    branch_name="automation/remediation/p81/restart",
                    commit_sha="d" * 40,
                    pull_request_url="https://github.com/acme/checkout/pull/826",
                    validation_result=SimpleNamespace(
                        passed=True,
                        steps=(SimpleNamespace(name="unit", passed=True),),
                    ),
                )

            return SimpleNamespace(execute=execute)

        execution_service = ProposalExecutionService(
            repository=restarted,
            orchestrator_factory=orchestrator_factory,
            ttl_seconds=3600.0,
        )
        executed = execute_proposal(
            incident.id,
            ProposalExecutionRequest(
                proposal_id=result["proposal_id"],
                proposal_hash=result["proposal_hash"],
                requested_by="alice-operator",
            ),
            service=execution_service,
        )
        self.assertEqual(executed["status"], "PR_CREATED")
        pr_url = executed["proposal"]["pull_request_url"]

        # 5) repeat legacy /remediation on the terminal incident → 409;
        #    it cannot reset PR_CREATED or mint a second proposal/PR.
        original_repository = self.repository
        self.repository = restarted
        try:
            spy2, provider2, exc2 = self._remediate(
                incident.id, "acme/checkout", SHA_A
            )
        finally:
            self.repository = original_repository
        self.assertIsInstance(exc2, HTTPException)
        self.assertEqual(exc2.status_code, 409)
        provider2.assert_not_called()
        spy2.execute.assert_not_called()

        final = restarted.get_incident_by_id(incident.id)
        self.assertEqual(final.status, "RemediationPRCreated")
        self.assertEqual(len(final.patch_proposals), 1)
        self.assertEqual(final.patch_proposals[0].id, result["proposal_id"])
        self.assertEqual(final.patch_proposals[0].status, "PR_CREATED")
        self.assertEqual(final.patch_proposals[0].pull_request_url, pr_url)

    # ---------- Phase 8.1 §27: concurrent approve vs regenerate ---------

    def test_phase81_concurrent_approve_vs_regenerate_e2e(self):
        import threading

        from incident_service.application.failures import (
            ApprovalPolicyError,
            IncidentConcurrencyConflict,
            ProposalIntegrityError,
        )
        from incident_service.application.services.proposal_approval_service import (
            ProposalApprovalService,
        )

        payload = self._deploy("acme/checkout", SHA_A)
        incident, _ = self._incident_with_collected_evidence(
            payload["id"], "inc-p81-27"
        )
        _, _, result = self._remediate(incident.id, "acme/checkout", SHA_A)
        self.assertNotIsInstance(result, Exception, result)

        barrier = threading.Barrier(2)
        outcomes = {}

        def approve_call():
            barrier.wait()
            try:
                outcomes["approve"] = ProposalApprovalService(
                    self.repository
                ).approve(
                    incident_id=incident.id,
                    proposal_id=result["proposal_id"],
                    proposal_hash=result["proposal_hash"],
                    approved_by="alice-operator",
                )
            except (
                IncidentConcurrencyConflict,
                ApprovalPolicyError,
                ProposalIntegrityError,
            ) as exc:
                outcomes["approve"] = exc

        def regenerate_call():
            barrier.wait()
            try:
                with patch.object(
                    controllers_module,
                    "get_remediation_orchestrator",
                    return_value=MagicMock(),
                ) as provider:
                    outcomes["regenerate"] = create_remediation(
                        incident.id,
                        RemediationRequest(
                            target_filepath="src/service.py",
                            patch=REMEDIATION_PATCH,
                            source_sha=SHA_A,
                            repository_slug="acme/checkout",
                        ),
                        self.repository,
                    )
                    provider.assert_not_called()
            except (
                IncidentConcurrencyConflict,
                HTTPException,
            ) as exc:
                outcomes["regenerate"] = exc

        threads = [
            threading.Thread(target=approve_call),
            threading.Thread(target=regenerate_call),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
            self.assertFalse(thread.is_alive())

        self.assertEqual(
            sorted(outcomes), ["approve", "regenerate"], outcomes
        )
        for label, outcome in outcomes.items():
            if isinstance(outcome, BaseException):
                self.assertIsInstance(
                    outcome,
                    (
                        IncidentConcurrencyConflict,
                        HTTPException,
                        ApprovalPolicyError,
                        ProposalIntegrityError,
                    ),
                    f"{label}: unexpected {outcome!r}",
                )

        # durable post-race state is coherent: exactly one proposal, and
        # approval metadata present ⇔ status APPROVED (never a torn mix).
        final = self.repository.get_incident_by_id(incident.id)
        self.assertEqual(len(final.patch_proposals), 1)
        proposal = final.patch_proposals[0]
        if proposal.status == "APPROVED":
            self.assertEqual(proposal.approved_by, "alice-operator")
            self.assertTrue(proposal.approval_hash)
        else:
            self.assertEqual(proposal.status, "PROPOSED")
            self.assertEqual(proposal.approved_by, "")
            self.assertEqual(proposal.approval_hash, "")


if __name__ == "__main__":
    unittest.main()
