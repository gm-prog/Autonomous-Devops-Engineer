"""End-to-end remediation boundary: real git, real commit, real publication.

Proves the critical state transition with NO faked local commit:

    isolated workspace → patch → bounded validation → deterministic commit
        → publication (real ``git push`` to a local bare remote)
        → verified remote SHA → draft GitHub PR (REST mocked only)

The local commit SHA produced by the commit service must arrive unchanged
at the GitHub abstraction layer, and the bare "remote" must actually
contain the published commit.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock

from ...domain.entities.hotfix_proposal import HotfixProposal
from .remediation_commit_service import RemediationCommitService
from .remediation_orchestration_service import (
    RemediationOrchestrationError,
    RemediationOrchestrationService,
)
from .remediation_patch_executor import RemediationPatchExecutor
from .remediation_validation_runner import (
    RemediationValidationRunner,
    ValidationStep,
)
from .remediation_workspace_service import (
    RemediationWorkspace,
    RemediationWorkspaceService,
)

INCIDENT_ID = "inc-e2e"
PROPOSAL_ID = "remediation-inc-e2e"
REPO_SLUG = "acme/demo"
BRANCH = "automation/remediation/inc-e2e/remediation-inc-e2e"

SEED_CONTENT = "old()\n"
PATCHED_CONTENT = "new()\n"
PATCH = """--- a/src/service.py
+++ b/src/service.py
@@ -1 +1 @@
-old()
+new()
"""


def _git(args, cwd=None, check=True):
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=check,
        capture_output=True,
        text=True,
    )


class RemediationE2EBoundaryTests(unittest.TestCase):
    """Materializes a local origin + isolated workspace, then drives the
    real orchestrator with only the GitHub REST client mocked."""

    def _build_workspace(self):
        tmp = tempfile.mkdtemp(prefix="e2e-remediation-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)

        bare = os.path.join(tmp, "origin.git")
        work = os.path.join(tmp, "checkout")
        _git(["init", "--bare", "--initial-branch=main", bare])
        _git(["init", "--initial-branch=main", work])
        _git(["config", "user.email", "e2e@example.com"], cwd=work)
        _git(["config", "user.name", "E2E"], cwd=work)

        os.makedirs(os.path.join(work, "src"))
        with open(os.path.join(work, "src", "service.py"), "w") as f:
            f.write(SEED_CONTENT)
        _git(["add", "src/service.py"], cwd=work)
        _git(["commit", "-m", "seed"], cwd=work)
        _git(["remote", "add", "origin", bare], cwd=work)
        _git(["push", "origin", "main"], cwd=work)

        source_sha = _git(["rev-parse", "HEAD"], cwd=work).stdout.strip()
        _git(["switch", "-c", BRANCH], cwd=work)

        workspace = RemediationWorkspace(
            path=work,
            cleanup_path=tmp,
            repository_slug=REPO_SLUG,
            source_sha=source_sha,
            base_branch="main",
            branch_name=BRANCH,
        )
        return workspace, bare, source_sha

    @staticmethod
    def _proposal(source_sha):
        proposal = HotfixProposal(
            id=PROPOSAL_ID,
            target_filepath="src/service.py",
            diff_patch_payload=PATCH,
            source_sha=source_sha,
        )
        verified = proposal.apply_verification_pass()
        assert verified, "E2E fixture patch failed deterministic verification"
        return proposal

    @staticmethod
    def _orchestrator(github, token="e2e-token"):
        profiles = {
            "e2e": (
                ValidationStep(
                    name="assert-patched-content",
                    working_directory="src",
                    argv=(
                        "python",
                        "-c",
                        "import sys; "
                        "sys.exit(0 if open('service.py').read() == 'new()\\n' else 1)",
                    ),
                    timeout_seconds=60.0,
                    max_output_bytes=4096,
                ),
            )
        }
        return RemediationOrchestrationService(
            workspace_service=RemediationWorkspaceService(),
            patch_executor=RemediationPatchExecutor(),
            validation_runner=RemediationValidationRunner(profiles=profiles),
            commit_service=RemediationCommitService(),
            github_client=github,
            github_oauth_token=token,
        )

    def test_local_commit_sha_flows_through_publication_to_draft_pr(self):
        workspace, bare, source_sha = self._build_workspace()
        proposal = self._proposal(source_sha)

        github = MagicMock()
        github.create_branch_from_commit.return_value = (
            f"https://github.com/{REPO_SLUG}/tree/{BRANCH}"
        )
        github.create_pull_request.return_value = (
            f"https://github.com/{REPO_SLUG}/pull/99"
        )
        orchestrator = self._orchestrator(github)

        result = orchestrator.execute(
            incident_id=INCIDENT_ID,
            proposal=proposal,
            repository_slug=REPO_SLUG,
            validation_profile="e2e",
            prepared_workspace=workspace,
        )

        # 1) The local commit is real and deterministic.
        local_head = _git(["rev-parse", "HEAD"], cwd=workspace.path).stdout.strip()
        local_parent = _git(
            ["rev-parse", "HEAD^"], cwd=workspace.path
        ).stdout.strip()
        self.assertEqual(result.commit_sha, local_head)
        self.assertEqual(local_parent, source_sha)

        # 2) Publication really pushed the commit to the remote.
        remote_sha = _git(
            ["rev-parse", f"refs/heads/{BRANCH}"], cwd=bare
        ).stdout.strip()
        self.assertEqual(remote_sha, local_head)

        # 3) The GitHub abstraction received EXACTLY the local commit SHA.
        github.create_branch_from_commit.assert_called_once()
        kwargs = github.create_branch_from_commit.call_args.kwargs
        self.assertEqual(kwargs["commit_sha"], local_head)
        self.assertEqual(kwargs["expected_parent_sha"], source_sha)
        self.assertEqual(kwargs["branch"], BRANCH)
        self.assertEqual(kwargs["repo_slug"], REPO_SLUG)

        # 4) Draft PR created only after publication, same branch.
        github.create_pull_request.assert_called_once()
        pr_kwargs = github.create_pull_request.call_args.kwargs
        self.assertEqual(pr_kwargs["branch"], BRANCH)
        self.assertTrue(pr_kwargs["draft"])
        self.assertEqual(
            result.pull_request_url,
            f"https://github.com/{REPO_SLUG}/pull/99",
        )

    def test_missing_token_fails_closed_before_any_github_call(self):
        from .remediation_workspace_service import RemediationRemotePublishError

        workspace, _bare, source_sha = self._build_workspace()
        proposal = self._proposal(source_sha)

        github = MagicMock()
        orchestrator = self._orchestrator(github, token="")

        with self.assertRaises(RemediationOrchestrationError) as ctx:
            orchestrator.execute(
                incident_id=INCIDENT_ID,
                proposal=proposal,
                repository_slug=REPO_SLUG,
                validation_profile="e2e",
                prepared_workspace=workspace,
            )

        self.assertIn("published", str(ctx.exception))
        github.create_branch_from_commit.assert_not_called()
        github.create_pull_request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
