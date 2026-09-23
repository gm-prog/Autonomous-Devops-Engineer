import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from application.services.remediation_workspace_service import (
    RemediationWorkspace,
    UnsafeRemediationBranchError,
)

_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_MAX_COMMIT_MESSAGE_LENGTH = 160
_AUTOMATION_BRANCH_PREFIX = "automation/remediation/"
_PROTECTED_BRANCHES = frozenset({"main", "master", "production", "release"})


class RemediationCommitError(RuntimeError):
    """Base error for deterministic remediation commit creation."""


class CommitSourceMismatchError(RemediationCommitError):
    """The workspace HEAD no longer matches the pinned source revision."""


class CommitWorkspaceDirtyError(RemediationCommitError):
    """The workspace contains changes outside the expected remediation target."""


class CommitStagingRejectedError(RemediationCommitError):
    """The exact remediation target could not be staged safely."""


class CommitCreationRejectedError(RemediationCommitError):
    """Git rejected creation or verification of the remediation commit."""


@dataclass(frozen=True)
class RemediationCommitResult:
    repository_slug: str
    source_sha: str
    commit_sha: str
    parent_sha: str
    target_filepath: str
    branch_name: str
    commit_message: str


class RemediationCommitService:
    """Creates exactly one remediation commit from one verified workspace."""

    def __init__(self, git_timeout_seconds: float = 60.0):
        if git_timeout_seconds <= 0:
            raise ValueError("git_timeout_seconds must be greater than zero")
        self.git_timeout_seconds = git_timeout_seconds

    def create(
        self,
        workspace: RemediationWorkspace,
        target_filepath: str,
        incident_id: str,
        proposal_id: str,
    ) -> RemediationCommitResult:
        target = self._validate_target(target_filepath)
        source_sha = self._validate_sha(workspace.source_sha)
        branch_name = self._validate_branch(workspace.branch_name)

        expected_branch = self._build_expected_branch(incident_id, proposal_id)
        if branch_name != expected_branch:
            raise UnsafeRemediationBranchError(
                "workspace branch does not match the deterministic remediation branch"
            )

        cwd = Path(workspace.path).resolve()
        if not cwd.is_dir():
            raise CommitCreationRejectedError("remediation workspace does not exist")

        self._assert_head(cwd, source_sha)

        tracked = self._run_git(
            ["git", "ls-files", "--error-unmatch", "--", target], cwd
        )
        if tracked.stdout.strip() != target:
            raise CommitStagingRejectedError(
                "remediation target is not a tracked file"
            )

        self._assert_only_target_modified(cwd, target)

        self._run_git(["git", "add", "--", target], cwd)

        staged = self._run_git(
            ["git", "diff", "--cached", "--name-status"], cwd
        ).stdout.splitlines()
        if staged != [f"M\t{target}"]:
            self._run_git(["git", "reset", "--", target], cwd, check=False)
            raise CommitStagingRejectedError(
                "staged remediation change must contain exactly one modified target file"
            )

        commit_message = self._build_commit_message(incident_id, proposal_id)
        try:
            self._run_git(
                ["git", "commit", "--no-verify", "-m", commit_message],
                cwd,
            )
        except subprocess.CalledProcessError as exc:
            self._run_git(["git", "reset", "--", target], cwd, check=False)
            raise CommitCreationRejectedError(
                "Git rejected the remediation commit"
            ) from exc

        commit_sha = self._run_git(["git", "rev-parse", "HEAD"], cwd).stdout.strip()
        parent_sha = self._run_git(
            ["git", "rev-parse", "HEAD^"], cwd
        ).stdout.strip()

        if not _SHA_PATTERN.fullmatch(commit_sha) or parent_sha != source_sha:
            raise CommitCreationRejectedError(
                "created commit does not have the pinned source revision as its parent"
            )

        final_status = self._run_git(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd
        ).stdout.strip()
        if final_status:
            raise CommitCreationRejectedError(
                "remediation workspace is not clean after commit creation"
            )

        return RemediationCommitResult(
            repository_slug=workspace.repository_slug,
            source_sha=source_sha,
            commit_sha=commit_sha,
            parent_sha=parent_sha,
            target_filepath=target,
            branch_name=branch_name,
            commit_message=commit_message,
        )

    @staticmethod
    def _validate_sha(value: str) -> str:
        normalized = value.strip().lower()
        if not _SHA_PATTERN.fullmatch(normalized):
            raise CommitSourceMismatchError("source SHA must be a full 40-character SHA")
        return normalized

    @staticmethod
    def _validate_target(value: str) -> str:
        target = value.replace("\\", "/").strip()
        if not target or target.startswith("/"):
            raise CommitStagingRejectedError("target filepath is unsafe")
        if any(part in {"", ".", ".."} for part in target.split("/")):
            raise CommitStagingRejectedError("target filepath contains unsafe segments")
        return target

    @staticmethod
    def _validate_branch(branch: str) -> str:
        normalized = branch.strip()
        if (
            not normalized.startswith(_AUTOMATION_BRANCH_PREFIX)
            or normalized in _PROTECTED_BRANCHES
            or normalized.startswith("-")
            or normalized.endswith(".")
            or ".." in normalized
            or any(part in {"", ".", ".."} for part in normalized.split("/"))
            or not re.fullmatch(r"[A-Za-z0-9._/-]+", normalized)
        ):
            raise UnsafeRemediationBranchError(
                "remediation branch does not satisfy the controlled branch policy"
            )
        return normalized

    @staticmethod
    def _build_expected_branch(incident_id: str, proposal_id: str) -> str:
        from application.services.remediation_workspace_service import (
            RemediationWorkspaceService,
        )
        return RemediationWorkspaceService.build_branch_name(
            incident_id, proposal_id
        )

    @staticmethod
    def _build_commit_message(incident_id: str, proposal_id: str) -> str:
        def sanitize(value: str) -> str:
            result = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
            return result.strip("-._") or "unknown"

        message = (
            f"chore(remediation): incident {sanitize(incident_id)} "
            f"proposal {sanitize(proposal_id)}"
        )
        return message[:_MAX_COMMIT_MESSAGE_LENGTH]

    def _assert_head(self, cwd: Path, expected_sha: str) -> None:
        head = self._run_git(
            ["git", "rev-parse", "HEAD"], cwd
        ).stdout.strip().lower()
        if head != expected_sha:
            raise CommitSourceMismatchError(
                "workspace HEAD does not match the pinned source SHA"
            )

    def _assert_only_target_modified(self, cwd: Path, target: str) -> None:
        status = self._run_git(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd
        ).stdout.splitlines()
        if status != [f" M {target}"]:
            raise CommitWorkspaceDirtyError(
                "workspace must contain exactly one modified remediation target"
            )

    def _run_git(
        self,
        args: list[str],
        cwd: Path,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        if args[:1] != ["git"]:
            raise CommitCreationRejectedError("only fixed Git commands are permitted")

        env = {
            key: value
            for key, value in os.environ.items()
            if key
            not in {
                "GIT_SSH_COMMAND",
                "GIT_CONFIG_GLOBAL",
                "GIT_CONFIG_SYSTEM",
                "GIT_ASKPASS",
                "SSH_AUTH_SOCK",
            }
        }
        env["GIT_TERMINAL_PROMPT"] = "0"

        try:
            return subprocess.run(
                args,
                cwd=str(cwd),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=check,
                shell=False,
                env=env,
                timeout=self.git_timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise CommitCreationRejectedError(
                "Git remediation commit operation exceeded its bounded timeout"
            ) from exc
