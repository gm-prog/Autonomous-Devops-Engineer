"""Integration E2E: persisted proposal → approval → execution → draft PR (§23).

Real components throughout the deterministic chain:

    real sqlite persistence + real generation (canonical hash)
        → real ProposalApprovalService (policy + hash binding + target)
        → real ProposalExecutionService (pre-side-effect revalidation)
        → real RemediationOrchestrationService
              isolated workspace cloned from a LOCAL bare origin
              real patch application, real bounded validation profile,
              real deterministic commit, real ``git push`` publication
        → GitHub REST layer mocked only (draft PR creation)

The local commit SHA must reach the GitHub abstraction unchanged, the
bare origin must actually contain the published remediation branch, and
repeat calls must reconcile instead of creating a second PR (§21).
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock

from shared_kernel.domain.provenance import build_provenance_record

from incident_service.application.failures import (
    ProposalIntegrityError,
    RemediationValidationFailedError,
    TargetRevalidationError,
)
from incident_service.application.services.proposal_approval_service import (
    ProposalApprovalService,
)
from incident_service.application.services.proposal_execution_policy import (
    execution_id_for,
)
from incident_service.application.services.proposal_execution_service import (
    EXECUTION_EVIDENCE_KIND,
    ProposalExecutionService,
)
from incident_service.application.services.proposal_generation_service import (
    ProposalGenerationService,
)
from incident_service.application.services.rca_analyzer import RcaAnalyzerPort
from incident_service.application.services.remediation_commit_service import (
    RemediationCommitService,
)
from incident_service.application.services.remediation_orchestration_service import (
    RemediationOrchestrationService,
)
from incident_service.application.services.remediation_patch_executor import (
    RemediationPatchExecutor,
)
from incident_service.application.services.remediation_validation_runner import (
    RemediationValidationRunner,
    ValidationStep,
)
from incident_service.application.services.remediation_workspace_service import (
    RemediationWorkspaceService,
)
from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.domain.entities.incident_evidence import IncidentEvidence
from incident_service.infrastructure.database.postgres_incident_repo import (
    PostgresIncidentRepositoryAdapter,
)

INCIDENT_ID = "inc-exec-e2e"
REPO_SLUG = "acme/checkout"
SEED_CONTENT = "old()\n"
PATCH = (
    "--- a/src/service.py\n"
    "+++ b/src/service.py\n"
    "@@ -1 +1 @@\n"
    "-old()\n"
    "+new()\n"
)


def _git(args, cwd=None, check=True):
    return subprocess.run(
        ["git", *args], cwd=cwd, check=check, capture_output=True, text=True
    )


class FakeAnalyzer(RcaAnalyzerPort):
    def analyze(self, evidence_pack):
        return {
            "root_cause": "pool leak after rollout",
            "confidence": 0.95,
            "evidence_refs": ["evt-1", "deploy-1"],
            "remediation_draft": {
                "target_file": "src/service.py",
                "risk_class": "low",
                "patch": PATCH,
                "validation_plan": ["pytest -q"],
            },
        }


class ProposalExecutionE2ETests(unittest.TestCase):
    def setUp(self):
        self._root = tempfile.mkdtemp(prefix="e2e-proposal-exec-")
        self.addCleanup(shutil.rmtree, self._root, ignore_errors=True)

        # --- local origin + seed commit (real git) --------------------
        self.bare = os.path.join(self._root, "origin.git")
        work = os.path.join(self._root, "checkout")
        _git(["init", "--bare", "--initial-branch=main", self.bare])
        _git(["init", "--initial-branch=main", work])
        _git(["config", "user.email", "e2e@example.com"], cwd=work)
        _git(["config", "user.name", "E2E"], cwd=work)
        os.makedirs(os.path.join(work, "src"))
        with open(os.path.join(work, "src", "service.py"), "w") as handle:
            handle.write(SEED_CONTENT)
        _git(["add", "src/service.py"], cwd=work)
        _git(["commit", "-m", "seed"], cwd=work)
        _git(["remote", "add", "origin", self.bare], cwd=work)
        _git(["push", "origin", "main"], cwd=work)
        self.source_sha = _git(["rev-parse", "HEAD"], cwd=work).stdout.strip()

        # --- persisted incident with provenance-backed deployment ----
        self.db_path = os.path.join(self._root, "incidents.db")
        self.repository = PostgresIncidentRepositoryAdapter(
            f"sqlite:///{self.db_path}"
        )
        self.incident = IncidentAggregate(
            INCIDENT_ID, "pool leak", "HIGH", "gateway"
        )
        self.incident.move_to_triage()
        self.incident.attach_evidence(
            IncidentEvidence(
                id="evt-1",
                kind="threshold_breach",
                source="monitoring-service",
                payload={"metric": "pool_wait_ms"},
            )
        )
        payload = {
            "deployment_run_id": "run-e2e",
            "repository_name": REPO_SLUG,
            "source_revision": {"head_sha": self.source_sha, "commits": []},
            "state": "DEPLOYED",
            "artifact_hash": "c" * 64,
            "plan_hash": "d" * 64,
        }
        payload["provenance"] = build_provenance_record(
            repository_name=REPO_SLUG,
            source_sha=self.source_sha,
            artifact_hash=payload["artifact_hash"],
            plan_hash=payload["plan_hash"],
            deployment_run_id="run-e2e",
            state="DEPLOYED",
            verification_method="test-source-verifier",
        )
        self.incident.attach_evidence(
            IncidentEvidence(
                id="deploy-1",
                kind="deployment_run",
                source="deployment-service",
                payload=payload,
            )
        )
        self.repository.save_incident(self.incident)

        # --- real generation against the local git SHA ----------------
        generated = ProposalGenerationService(
            repository=self.repository, analyzer=FakeAnalyzer()
        ).generate(INCIDENT_ID)
        self.assertEqual(generated["proposal"]["status"], "PROPOSED")
        self.assertEqual(generated["target"]["source_sha"], self.source_sha)
        self.proposal_id = generated["proposal"]["id"]
        self.proposal_hash = generated["proposal"]["proposal_hash"]

        self.github = MagicMock()
        self.github.create_branch_from_commit.return_value = (
            f"https://github.com/{REPO_SLUG}/tree/automation/remediation"
        )
        self.github.create_pull_request.return_value = (
            f"https://github.com/{REPO_SLUG}/pull/77"
        )

        # [] before create; the created PR afterwards so post-create
        # exact-identity verification (Phase 6.2.1B) can succeed
        from incident_service.infrastructure.source_provider.github_pr_client import (
            ExistingPullRequest,
        )

        def _discovery(**kwargs):
            if self.github.create_pull_request.call_count == 0:
                return []
            proposal = self._proposal()
            return [
                ExistingPullRequest(
                    number=77,
                    url=f"https://github.com/{REPO_SLUG}/pull/77",
                    state="open",
                    draft=True,
                    merged=False,
                    head_ref=proposal.branch_name,
                    base_ref="main",
                    body="",
                    head_sha=proposal.commit_sha,
                    head_repository=REPO_SLUG,
                )
            ]

        self.github.find_existing_pull_requests.side_effect = _discovery

    # --- builders -------------------------------------------------------
    def _approval_service(self):
        return ProposalApprovalService(
            repository=self.repository, ttl_seconds=3600.0
        )

    def _approve(self):
        return self._approval_service().approve(
            incident_id=INCIDENT_ID,
            proposal_id=self.proposal_id,
            proposal_hash=self.proposal_hash,
            approved_by="alice-operator",
        )

    def _orchestrator(self, validation_ok=True):
        if validation_ok:
            argv = (
                "python",
                "-c",
                "import sys; sys.exit(0 if open('service.py').read() "
                "== 'new()\\n' else 1)",
            )
        else:
            argv = ("python", "-c", "import sys; sys.exit(1)")
        profiles = {
            "e2e": (
                ValidationStep(
                    name="assert-patched-content",
                    working_directory="src",
                    argv=argv,
                    timeout_seconds=60.0,
                    max_output_bytes=4096,
                ),
            )
        }
        return RemediationOrchestrationService(
            workspace_service=RemediationWorkspaceService(
                remote_url_factory=lambda slug: f"file://{self.bare}"
            ),
            patch_executor=RemediationPatchExecutor(),
            validation_runner=RemediationValidationRunner(profiles=profiles),
            commit_service=RemediationCommitService(),
            github_client=self.github,
            github_oauth_token="e2e-token",
        )

    def _execution_service(self, validation_ok=True):
        orchestrator = self._orchestrator(validation_ok=validation_ok)
        return ProposalExecutionService(
            repository=self.repository,
            orchestrator_factory=lambda: orchestrator,
            ttl_seconds=3600.0,
            validation_profile="e2e",
        )

    def _execute(self, service=None, proposal_hash=None):
        return (service or self._execution_service()).execute(
            incident_id=INCIDENT_ID,
            proposal_id=self.proposal_id,
            proposal_hash=proposal_hash or self.proposal_hash,
            requested_by="alice-operator",
        )

    def _proposal(self):
        return self.repository.get_incident_by_id(
            INCIDENT_ID
        ).patch_proposals[0]

    def _branch_on_remote(self, branch):
        result = _git(
            ["rev-parse", f"refs/heads/{branch}"], cwd=self.bare, check=False
        )
        return result.returncode == 0, result.stdout.strip()

    # --- tests ----------------------------------------------------------
    def test_full_chain_from_persisted_proposal_to_draft_pr(self):
        self._approve()
        body = self._execute()

        self.assertEqual(body["status"], "PR_CREATED")
        proposal = self._proposal()
        self.assertEqual(proposal.status, "PR_CREATED")
        self.assertEqual(
            proposal.execution_id,
            execution_id_for(self.proposal_id, self.proposal_hash),
        )
        branch = proposal.branch_name
        self.assertEqual(
            branch,
            f"automation/remediation/{INCIDENT_ID}/{self.proposal_id}",
        )

        # local commit really exists with the pinned parent
        # (clone/checkout happen in a disposable workspace; verify via the
        #  bare origin which must hold the exact pushed commit)
        exists, remote_sha = self._branch_on_remote(branch)
        self.assertTrue(exists, "remediation branch was published to origin")
        self.assertEqual(proposal.commit_sha, remote_sha)

        # GitHub abstraction received the local commit + pinned parent
        self.github.create_branch_from_commit.assert_called_once()
        branch_kwargs = self.github.create_branch_from_commit.call_args.kwargs
        self.assertEqual(branch_kwargs["commit_sha"], proposal.commit_sha)
        self.assertEqual(branch_kwargs["expected_parent_sha"], self.source_sha)
        self.assertEqual(branch_kwargs["branch"], branch)
        self.assertEqual(branch_kwargs["repo_slug"], REPO_SLUG)

        # draft PR only, never merge/update of base
        self.github.create_pull_request.assert_called_once()
        pr_kwargs = self.github.create_pull_request.call_args.kwargs
        self.assertEqual(pr_kwargs["branch"], branch)
        self.assertTrue(pr_kwargs["draft"])
        self.assertEqual(
            proposal.pull_request_url,
            f"https://github.com/{REPO_SLUG}/pull/77",
        )

        # persisted execution evidence (machine readable, no secrets)
        incident = self.repository.get_incident_by_id(INCIDENT_ID)
        records = [
            item for item in incident.evidence
            if item.kind == EXECUTION_EVIDENCE_KIND
        ]
        self.assertEqual(len(records), 1)
        payload = records[0].payload
        self.assertEqual(payload["status"], "PR_CREATED")
        self.assertEqual(payload["repository"], REPO_SLUG)
        self.assertEqual(payload["source_sha"], self.source_sha)
        self.assertEqual(payload["approved_by"], "alice-operator")
        self.assertEqual(payload["requested_by"], "alice-operator")
        self.assertEqual(payload["validation"]["profile"], "e2e")
        self.assertEqual(payload["commit_sha"], proposal.commit_sha)
        self.assertEqual(payload["pull_request_url"], proposal.pull_request_url)
        self.assertNotIn("e2e-token", str(payload))

    def test_repeat_execution_reconciles_same_pr_no_second_push(self):
        self._approve()
        first = self._execute()
        second = self._execute()
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        self.assertEqual(first["execution_id"], second["execution_id"])
        # GitHub called exactly once across both calls
        self.github.create_pull_request.assert_called_once()
        self.github.create_branch_from_commit.assert_called_once()

    def test_deployment_drift_after_approval_stops_before_workspace(self):
        self._approve()
        incident = self.repository.get_incident_by_id(INCIDENT_ID)
        incident.evidence = [
            item for item in incident.evidence if item.id != "deploy-1"
        ]
        # newer DEPLOYED record, different SHA — never retarget
        payload = {
            "deployment_run_id": "run-e2e-2",
            "repository_name": REPO_SLUG,
            "source_revision": {"head_sha": "b" * 40, "commits": []},
            "state": "DEPLOYED",
            "artifact_hash": "e" * 64,
            "plan_hash": "f" * 64,
        }
        payload["provenance"] = build_provenance_record(
            repository_name=REPO_SLUG,
            source_sha="b" * 40,
            artifact_hash=payload["artifact_hash"],
            plan_hash=payload["plan_hash"],
            deployment_run_id="run-e2e-2",
            state="DEPLOYED",
            verification_method="test-source-verifier",
        )
        incident.attach_evidence(
            IncidentEvidence(
                id="deploy-2",
                kind="deployment_run",
                source="deployment-service",
                payload=payload,
            )
        )
        self.repository.save_incident(incident)

        with self.assertRaises(TargetRevalidationError):
            self._execute()
        # no GitHub activity, no branch on the remote, status unchanged
        self.github.create_pull_request.assert_not_called()
        self.github.create_branch_from_commit.assert_not_called()
        exists, _ = self._branch_on_remote(
            f"automation/remediation/{INCIDENT_ID}/{self.proposal_id}"
        )
        self.assertFalse(exists)
        self.assertEqual(self._proposal().status, "APPROVED")

    def test_tampered_proposal_stops_before_workspace(self):
        self._approve()
        incident = self.repository.get_incident_by_id(INCIDENT_ID)
        incident.patch_proposals[0].diff_patch_payload = PATCH.replace(
            "new()", "malicious()"
        )
        self.repository.save_incident(incident)

        with self.assertRaises(ProposalIntegrityError):
            self._execute()
        self.github.create_pull_request.assert_not_called()
        exists, _ = self._branch_on_remote(
            f"automation/remediation/{INCIDENT_ID}/{self.proposal_id}"
        )
        self.assertFalse(exists)
        self.assertEqual(self._proposal().status, "APPROVED")

    def test_validation_failure_has_no_commit_push_or_pr(self):
        self._approve()
        with self.assertRaises(RemediationValidationFailedError):
            self._execute(service=self._execution_service(validation_ok=False))

        proposal = self._proposal()
        self.assertEqual(proposal.status, "EXECUTION_FAILED")
        self.assertFalse(proposal.pull_request_url)
        self.assertFalse(proposal.commit_sha)
        self.github.create_pull_request.assert_not_called()
        self.github.create_branch_from_commit.assert_not_called()
        exists, _ = self._branch_on_remote(
            f"automation/remediation/{INCIDENT_ID}/{self.proposal_id}"
        )
        self.assertFalse(exists, "failed validation must never publish")
        incident = self.repository.get_incident_by_id(INCIDENT_ID)
        records = [
            item for item in incident.evidence
            if item.kind == EXECUTION_EVIDENCE_KIND
        ]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].payload["status"], "EXECUTION_FAILED")


if __name__ == "__main__":
    unittest.main()
