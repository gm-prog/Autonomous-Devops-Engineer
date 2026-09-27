"""Phase 6.2.1 §44 recovery E2E: crash + worker-B convergence.

Deterministic chain, real boundaries:

    real sqlite persistence + real generation/approval (canonical hash)
        → real ProposalExecutionService (durable lease via SQLite)
        → real RemediationOrchestrationService
              local bare origin  ← real `git push` (worker A)
        → REAL GitHubPRClient over a deterministic in-memory HTTP fake
          (refs + pulls; not a generic MagicMock)

Worker A pushes the remediation commit for real, then dies at the PR
boundary. Worker B (separate service + repository instances over the same
store) must recover by inspecting the actual remote state and converge to
exactly one commit, one branch, and one pull request — never a second.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from shared_kernel.domain.provenance import build_provenance_record

from incident_service.application.failures import (
    ExistingPullRequestConflict,
    ProposalExecutionFailedError,
    RemoteBranchConflict,
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
from incident_service.infrastructure.source_provider.github_pr_client import (
    GitHubPRClient,
    PRCreationFailedException,
)

INCIDENT_ID = "inc-rec-e2e"
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


class _Resp:
    def __init__(self, status_code, payload=None, invalid_json=False):
        self.status_code = status_code
        self._payload = payload
        self._invalid_json = invalid_json
        self.text = str(payload)

    def json(self):
        if self._invalid_json:
            raise ValueError("invalid json")
        return self._payload


class DeterministicFakeGitHub:
    """In-memory GitHub REST boundary: refs + pulls, deterministic.

    Failure injection is explicit and bounded: ``fail_pull_create = "500"``
    or ``"timeout"`` fires ``fail_pull_create_times`` times, then stops.
    """

    def __init__(self, source_sha):
        self.source_sha = source_sha.lower()
        self.refs = {}          # branch -> sha
        self.prs = []           # created PR payloads
        self.ref_post_count = 0
        self.pull_create_attempts = 0
        self.fail_pull_create = None
        self.fail_pull_create_times = 0
        self._branch = None

    # --- requests.get ---------------------------------------------------
    def get(self, url, **kwargs):
        if "/commits/" in url:
            sha = url.rsplit("/", 1)[-1].lower()
            return _Resp(
                200,
                {"sha": sha, "parents": [{"sha": self.source_sha}]},
            )
        if "/git/ref/heads/" in url:
            branch = url.split("/git/ref/heads/", 1)[1]
            if branch in self.refs:
                return _Resp(200, {"object": {"sha": self.refs[branch]}})
            return _Resp(404, {"message": "Not Found"})
        if url.endswith("/pulls"):
            # discovery: return every PR; the real client filters by
            # exact head/base identity
            return _Resp(200, list(self.prs))
        raise AssertionError(f"unexpected GET {url}")

    # --- requests.post --------------------------------------------------
    def post(self, url, **kwargs):
        if url.endswith("/git/refs"):
            payload = kwargs.get("json") or {}
            ref = payload.get("ref", "")
            branch = ref.split("refs/heads/", 1)[-1]
            if branch in self.refs:
                return _Resp(422, {"message": "Reference already exists"})
            self.refs[branch] = payload.get("sha", "")
            self._branch = branch
            self.ref_post_count += 1
            return _Resp(201, {"ref": ref, "object": {"sha": payload.get("sha")}})
        if url.endswith("/pulls"):
            self.pull_create_attempts += 1
            if self.fail_pull_create and self.fail_pull_create_times > 0:
                self.fail_pull_create_times -= 1
                if self.fail_pull_create == "timeout":
                    import requests as _requests

                    raise _requests.Timeout("pr response timed out")
                return _Resp(500, {"message": "server exploded"})
            payload = kwargs.get("json") or {}
            number = 100 + len(self.prs) + 1
            pr = {
                "number": number,
                "html_url": f"https://github.com/{REPO_SLUG}/pull/{number}",
                "state": "open",
                "draft": bool(payload.get("draft", True)),
                "merged": False,
                "merged_at": None,
                "title": payload.get("title", ""),
                "body": payload.get("body", ""),
                "head": {"ref": payload.get("head", ""), "sha": ""},
                "base": {"ref": payload.get("base", ""), "sha": ""},
            }
            self.prs.append(pr)
            return _Resp(201, {"html_url": pr["html_url"]})
        raise AssertionError(f"unexpected POST {url}")


class ExecutionRecoveryE2ETests(unittest.TestCase):
    def setUp(self):
        self._root = tempfile.mkdtemp(prefix="e2e-rec-")
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
        self.work = work

        # --- persisted incident + provenance-backed deployment --------
        self.db_path = os.path.join(self._root, "incidents.db")
        self.repository = PostgresIncidentRepositoryAdapter(
            f"sqlite:///{self.db_path}"
        )
        incident = IncidentAggregate(INCIDENT_ID, "pool leak", "HIGH", "gateway")
        incident.move_to_triage()
        incident.attach_evidence(
            IncidentEvidence(
                id="evt-1",
                kind="threshold_breach",
                source="monitoring-service",
                payload={"metric": "pool_wait_ms"},
            )
        )
        payload = {
            "deployment_run_id": "run-rec",
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
            deployment_run_id="run-rec",
            state="DEPLOYED",
            verification_method="test-source-verifier",
        )
        incident.attach_evidence(
            IncidentEvidence(
                id="deploy-1",
                kind="deployment_run",
                source="deployment-service",
                payload=payload,
            )
        )
        self.repository.save_incident(incident)

        generated = ProposalGenerationService(
            repository=self.repository, analyzer=FakeAnalyzer()
        ).generate(INCIDENT_ID)
        self.proposal_id = generated["proposal"]["id"]
        self.proposal_hash = generated["proposal"]["proposal_hash"]

        self._approve()

        # --- deterministic fake GitHub + real client ------------------
        self.fake_github = DeterministicFakeGitHub(self.source_sha)
        self._patches = [
            patch(
                "incident_service.infrastructure.source_provider."
                "github_pr_client.requests.get",
                side_effect=self.fake_github.get,
            ),
            patch(
                "incident_service.infrastructure.source_provider."
                "github_pr_client.requests.post",
                side_effect=self.fake_github.post,
            ),
        ]
        for item in self._patches:
            item.start()
            self.addCleanup(item.stop)

    # --- builders -------------------------------------------------------
    def _approval_service(self, repository=None):
        return ProposalApprovalService(
            repository=repository or self.repository, ttl_seconds=3600.0
        )

    def _approve(self):
        return self._approval_service().approve(
            incident_id=INCIDENT_ID,
            proposal_id=self.proposal_id,
            proposal_hash=self.proposal_hash,
            approved_by="alice-operator",
        )

    def _orchestrator(self):
        profiles = {
            "e2e": (
                ValidationStep(
                    name="assert-patched-content",
                    working_directory="src",
                    argv=(
                        "python",
                        "-c",
                        "import sys; sys.exit(0 if open('service.py').read() "
                        "== 'new()\\n' else 1)",
                    ),
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
            github_client=GitHubPRClient(oauth_token="e2e-token"),
            github_oauth_token="e2e-token",
        )

    def _worker(self, lease_owner):
        """A distinct execution service = a distinct worker process."""
        repository = (
            self.repository
            if lease_owner == "worker-a"
            else PostgresIncidentRepositoryAdapter(f"sqlite:///{self.db_path}")
        )
        orchestrator = self._orchestrator()
        # the durable-mode inspector must target the same remote the
        # orchestrator publishes to (the local bare origin here)
        inspector = RemediationWorkspaceService(
            remote_url_factory=lambda slug: f"file://{self.bare}"
        )
        service = ProposalExecutionService(
            repository=repository,
            orchestrator_factory=lambda: orchestrator,
            ttl_seconds=3600.0,
            lease_seconds=600.0,
            lease_owner=lease_owner,
            validation_profile="e2e",
            remote_inspector=inspector,
        )
        return service, repository

    def _execute(self, service):
        return service.execute(
            incident_id=INCIDENT_ID,
            proposal_id=self.proposal_id,
            proposal_hash=self.proposal_hash,
            requested_by="alice-operator",
        )

    def _proposal(self, repository=None):
        return (repository or self.repository).get_incident_by_id(
            INCIDENT_ID
        ).patch_proposals[0]

    def _branch_name(self):
        return f"automation/remediation/{INCIDENT_ID}/{self.proposal_id}"

    def _branch_on_bare(self):
        result = _git(
            ["rev-parse", f"refs/heads/{self._branch_name()}"],
            cwd=self.bare,
            check=False,
        )
        return (result.returncode == 0), result.stdout.strip()

    def _commits_above_main(self):
        result = _git(
            ["rev-list", "--count", f"main..{self._branch_name()}"],
            cwd=self.bare,
            check=False,
        )
        return result.stdout.strip()

    def _evidence(self, repository=None):
        incident = (repository or self.repository).get_incident_by_id(
            INCIDENT_ID
        )
        return [
            item for item in incident.evidence
            if item.kind == EXECUTION_EVIDENCE_KIND
        ]

    # --- scenarios ---------------------------------------------------------
    def test_worker_b_recovers_after_worker_a_crash_post_push(self):
        self.fake_github.fail_pull_create = "500"
        self.fake_github.fail_pull_create_times = 1

        worker_a, repo_a = self._worker("worker-a")
        with self.assertRaises(ProposalExecutionFailedError) as ctx:
            self._execute(worker_a)
        # typed client failure preserved as cause; stage-annotated wrapper
        self.assertIsInstance(
            ctx.exception.__cause__, PRCreationFailedException
        )
        self.assertEqual(ctx.exception.stage, "pr")

        # worker A really pushed the remediation commit before dying
        exists, pushed_sha = self._branch_on_bare()
        self.assertTrue(exists, "worker A published the branch for real")
        proposal = self._proposal()
        self.assertEqual(proposal.status, "EXECUTION_FAILED")
        self.assertEqual(proposal.commit_sha, pushed_sha)
        first_evidence = self._evidence()
        self.assertEqual(len(first_evidence), 1)
        self.assertEqual(first_evidence[0].payload["status"], "EXECUTION_FAILED")
        self.assertEqual(first_evidence[0].payload["attempt"], 1)
        self.assertEqual(first_evidence[0].payload["lease_owner"], "worker-a")
        self.assertEqual(len(self.fake_github.prs), 0)

        # worker B: separate service + repository instance, same store
        worker_b, repo_b = self._worker("worker-b")
        body = self._execute(worker_b)

        self.assertEqual(body["status"], "PR_CREATED")
        proposal = self._proposal()
        self.assertEqual(proposal.status, "PR_CREATED")
        self.assertEqual(proposal.execution_attempts, 2)
        self.assertEqual(proposal.commit_sha, pushed_sha, "commit is stable")

        # exactly one commit, one branch, one PR
        self.assertEqual(self._commits_above_main(), "1")
        self.assertEqual(self.fake_github.ref_post_count, 1, "no second branch")
        self.assertEqual(len(self.fake_github.prs), 1, "exactly one PR")
        self.assertEqual(
            self.fake_github.pull_create_attempts, 2, "A failed + B succeeded"
        )
        self.assertEqual(
            proposal.pull_request_url,
            f"https://github.com/{REPO_SLUG}/pull/101",
        )

        # durable per-attempt evidence, no secrets
        records = self._evidence()
        self.assertEqual(len(records), 2)
        self.assertEqual(
            sorted(rec.payload["attempt"] for rec in records), [1, 2]
        )
        self.assertEqual(records[1].payload["status"], "PR_CREATED")
        self.assertNotIn("e2e-token", str([rec.payload for rec in records]))

        # deterministic execution id across both attempts
        self.assertEqual(
            proposal.execution_id,
            execution_id_for(self.proposal_id, self.proposal_hash),
        )

    def test_pr_response_timeout_then_retry_converges(self):
        self.fake_github.fail_pull_create = "timeout"
        self.fake_github.fail_pull_create_times = 1

        worker_a, _ = self._worker("worker-a")
        with self.assertRaises(ProposalExecutionFailedError) as ctx:
            self._execute(worker_a)
        self.assertIsInstance(
            ctx.exception.__cause__, PRCreationFailedException
        )
        self.assertTrue(self._branch_on_bare()[0], "push happened before crash")
        self.assertEqual(len(self.fake_github.prs), 0)

        worker_b, _ = self._worker("worker-b")
        body = self._execute(worker_b)
        self.assertEqual(body["status"], "PR_CREATED")
        self.assertEqual(self._commits_above_main(), "1")
        self.assertEqual(len(self.fake_github.prs), 1)
        self.assertEqual(self.fake_github.ref_post_count, 1)

    def test_wrong_remote_sha_fails_closed_on_recovery(self):
        self.fake_github.fail_pull_create = "500"
        self.fake_github.fail_pull_create_times = 1

        worker_a, _ = self._worker("worker-a")
        with self.assertRaises(ProposalExecutionFailedError):
            self._execute(worker_a)
        _, durable_sha = self._branch_on_bare()
        self.assertTrue(durable_sha)

        # the remote branch moves behind our back (someone else pushed)
        _git(["fetch", "origin", self._branch_name()], cwd=self.work)
        _git(
            ["checkout", "-B", self._branch_name(), f"origin/{self._branch_name()}"],
            cwd=self.work,
        )
        with open(os.path.join(self.work, "src", "service.py"), "a") as handle:
            handle.write("# someone else changed this\n")
        _git(["add", "src/service.py"], cwd=self.work)
        _git(["commit", "-m", "intruder commit"], cwd=self.work)
        _git(["push", "origin", self._branch_name()], cwd=self.work)
        moved_sha = _git(
            ["rev-parse", f"refs/heads/{self._branch_name()}"], cwd=self.bare
        ).stdout.strip()
        self.assertNotEqual(moved_sha, durable_sha)

        worker_b, _ = self._worker("worker-b")
        with self.assertRaises(RemoteBranchConflict):
            self._execute(worker_b)

        # fail closed: no PR, no retarget, durable conflict record
        self.assertEqual(len(self.fake_github.prs), 0)
        self.assertEqual(self.fake_github.ref_post_count, 1, "no ref rewrite")
        proposal = self._proposal()
        self.assertEqual(proposal.status, "EXECUTION_FAILED")
        self.assertEqual(proposal.commit_sha, durable_sha, "no retarget")
        conflicts = [
            rec
            for rec in self._evidence()
            if rec.payload.get("status") == "RECONCILIATION_CONFLICT"
        ]
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0].payload["attempt"], 1)

    def test_merged_remote_pr_blocks_second_pr(self):
        # a merged PR already exists for the deterministic head/base pair
        self.fake_github.prs.append(
            {
                "number": 5,
                "html_url": f"https://github.com/{REPO_SLUG}/pull/5",
                "state": "closed",
                "draft": False,
                "merged": True,
                "merged_at": "2026-09-26T00:00:00Z",
                "title": "Automated remediation for incident " + INCIDENT_ID,
                "body": f"Incident: {INCIDENT_ID}\nProposal hash: "
                f"{self.proposal_hash}\n",
                "head": {"ref": self._branch_name(), "sha": ""},
                "base": {"ref": "main", "sha": ""},
            }
        )

        worker_a, _ = self._worker("worker-a")
        with self.assertRaises(ExistingPullRequestConflict):
            self._execute(worker_a)

        self.assertEqual(len(self.fake_github.prs), 1, "no second PR")
        self.assertEqual(
            self.fake_github.pull_create_attempts, 0, "discovery blocked POST"
        )
        proposal = self._proposal()
        self.assertEqual(proposal.status, "EXECUTION_FAILED")
        self.assertEqual(proposal.last_failure_stage, "pr.discovery")


if __name__ == "__main__":
    unittest.main()
