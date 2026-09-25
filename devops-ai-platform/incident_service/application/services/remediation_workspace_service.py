import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

logger = logging.getLogger("RemediationWorkspaceService")

_GIT_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")
_REPO_SLUG_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_INVALID_BRANCH_CHARS = re.compile(r"[^A-Za-z0-9._-]+")
_PROTECTED_BRANCHES = frozenset(
    {"main", "master", "production", "release"}
)

MAX_BRANCH_LENGTH = 120
MAX_BRANCH_COMPONENT_LENGTH = 40
DEFAULT_GIT_TIMEOUT_SECONDS = 120.0
WORKSPACE_PREFIX = "devops-remediation-"


class RemediationWorkspaceError(RuntimeError):
    """Base error for the isolated remediation workspace boundary."""


class InvalidSourceRevisionError(RemediationWorkspaceError):
    """Raised when a remediation source SHA is not a full immutable revision."""


class UnsafeRemediationBranchError(RemediationWorkspaceError):
    """Raised when a generated remediation branch violates branch policy."""


class RemediationWorkspaceCommandError(RemediationWorkspaceError):
    """Raised when a bounded Git command cannot prepare the workspace."""


class RemediationRemotePublishError(RemediationWorkspaceError):
    """Raised when a verified remediation commit cannot be published to the remote repository."""


@dataclass(frozen=True)
class RemediationWorkspace:
    """An ephemeral checkout pinned to one immutable source revision."""

    path: str
    cleanup_path: str
    repository_slug: str
    source_sha: str
    base_branch: str
    branch_name: str


class RemediationWorkspaceService:
    """Creates a clean, SHA-pinned Git workspace without allowing model-supplied shell commands."""

    def __init__(
        self,
        git_timeout_seconds: float = DEFAULT_GIT_TIMEOUT_SECONDS,
        workspace_prefix: str = WORKSPACE_PREFIX,
    ):
        if git_timeout_seconds <= 0:
            raise ValueError("git_timeout_seconds must be greater than zero")
        if not workspace_prefix or not workspace_prefix.endswith("-"):
            raise ValueError("workspace_prefix must be non-empty and end with '-'")

        self.git_timeout_seconds = git_timeout_seconds
        self.workspace_prefix = workspace_prefix
        self._active_workspaces: set[Path] = set()

    @staticmethod
    def validate_repository_slug(repository_slug: str) -> str:
        normalized = repository_slug.strip()
        if not _REPO_SLUG_PATTERN.fullmatch(normalized):
            raise RemediationWorkspaceError(
                "repository_slug must use owner/repository format"
            )
        return normalized

    @staticmethod
    def validate_source_sha(source_sha: str) -> str:
        normalized = source_sha.strip().lower()
        if not _GIT_SHA_PATTERN.fullmatch(normalized):
            raise InvalidSourceRevisionError(
                "source_sha must be a full 40-character hexadecimal Git commit SHA"
            )
        return normalized

    @staticmethod
    def _sanitize_branch_component(value: str, fallback: str) -> str:
        normalized = _INVALID_BRANCH_CHARS.sub("-", value.strip())
        normalized = normalized.strip("-._")
        normalized = normalized[:MAX_BRANCH_COMPONENT_LENGTH].rstrip("-._")
        return normalized or fallback

    @classmethod
    def build_branch_name(cls, incident_id: str, proposal_id: str) -> str:
        incident = cls._sanitize_branch_component(incident_id, "incident")
        proposal = cls._sanitize_branch_component(proposal_id, "proposal")
        branch = f"automation/remediation/{incident}/{proposal}"
        return branch[:MAX_BRANCH_LENGTH].rstrip("-._/")

    @staticmethod
    def validate_head_branch(branch_name: str, base_branch: str) -> str:
        normalized_head = branch_name.strip()
        normalized_base = base_branch.strip()

        if not normalized_head or not normalized_base:
            raise UnsafeRemediationBranchError(
                "both remediation head and base branches are required"
            )
        if normalized_head == normalized_base:
            raise UnsafeRemediationBranchError(
                "remediation head branch must differ from the base branch"
            )
        if normalized_head.lower() in _PROTECTED_BRANCHES:
            raise UnsafeRemediationBranchError(
                f"protected branch cannot be used as remediation head: {normalized_head}"
            )
        if normalized_head.startswith("refs/") or normalized_head.startswith("-"):
            raise UnsafeRemediationBranchError(
                "remediation head branch has an unsafe Git ref shape"
            )
        if any(part in {"", ".", ".."} for part in normalized_head.split("/")):
            raise UnsafeRemediationBranchError(
                "remediation head branch contains an unsafe path segment"
            )
        if len(normalized_head) > MAX_BRANCH_LENGTH:
            raise UnsafeRemediationBranchError(
                f"remediation head branch exceeds {MAX_BRANCH_LENGTH} characters"
            )
        return normalized_head

    def prepare(
        self,
        repository_slug: str,
        source_sha: str,
        incident_id: str,
        proposal_id: str,
        base_branch: str = "main",
    ) -> RemediationWorkspace:
        repo = self.validate_repository_slug(repository_slug)
        sha = self.validate_source_sha(source_sha)
        branch = self.build_branch_name(incident_id, proposal_id)
        self.validate_head_branch(branch, base_branch)

        cleanup_root = Path(
            tempfile.mkdtemp(prefix=self.workspace_prefix)
        ).resolve()
        workspace_path = cleanup_root / "repository"

        try:
            remote_url = f"https://github.com/{repo}.git"

            self._run_git(
                [
                    "git",
                    "clone",
                    "--no-checkout",
                    "--no-tags",
                    remote_url,
                    str(workspace_path),
                ]
            )
            self._run_git(
                ["git", "fetch", "--no-tags", "origin", sha],
                cwd=workspace_path,
            )
            self._run_git(
                ["git", "checkout", "--detach", sha],
                cwd=workspace_path,
            )

            actual_sha = self._run_git(
                ["git", "rev-parse", "HEAD"],
                cwd=workspace_path,
            ).stdout.strip().lower()
            if actual_sha != sha:
                raise InvalidSourceRevisionError(
                    "checked out revision did not match the requested source SHA"
                )

            self._run_git(
                ["git", "switch", "--create", branch],
                cwd=workspace_path,
            )

            workspace = RemediationWorkspace(
                path=str(workspace_path),
                cleanup_path=str(cleanup_root),
                repository_slug=repo,
                source_sha=sha,
                base_branch=base_branch.strip(),
                branch_name=branch,
            )
            self._active_workspaces.add(cleanup_root)
            return workspace
        except RemediationWorkspaceError:
            self._cleanup_path(cleanup_root)
            raise
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
            self._cleanup_path(cleanup_root)
            raise RemediationWorkspaceCommandError(
                "bounded Git operation failed while preparing remediation workspace"
            ) from exc
        except Exception as exc:
            self._cleanup_path(cleanup_root)
            raise RemediationWorkspaceError(
                "unexpected failure while preparing remediation workspace"
            ) from exc

    def publish_branch(self, workspace: RemediationWorkspace, oauth_token: str) -> str:
        """Publish the workspace HEAD commit to its controlled remote branch.

        The remediation commit is created locally, so it does not exist in
        GitHub's object database until it is transferred over the wire. This
        step pushes exactly that commit to the controlled remediation ref and
        verifies the remote ref points at the exact verified SHA before the
        GitHub REST layer (create_branch_from_commit / create_pull_request)
        is allowed to proceed.

        Credentials travel only through the process environment via Git's
        GIT_CONFIG_* variables (an http.extraHeader Authorization value) -
        never in the remote URL or in command arguments.
        """
        if not oauth_token or not oauth_token.strip():
            raise RemediationRemotePublishError(
                "GITHUB_OAUTH_TOKEN is required to publish the remediation commit"
            )

        cwd = Path(workspace.path).resolve()
        if not cwd.is_dir():
            raise RemediationRemotePublishError("remediation workspace does not exist")

        branch = workspace.branch_name
        head_sha = self._run_git(["git", "rev-parse", "HEAD"], cwd).stdout.strip().lower()
        if not _GIT_SHA_PATTERN.fullmatch(head_sha):
            raise RemediationRemotePublishError(
                "workspace HEAD is not a full 40-character Git commit SHA"
            )

        credential_env = {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.extraHeader",
            "GIT_CONFIG_VALUE_0": f"Authorization: Bearer {oauth_token.strip()}",
        }

        try:
            self._run_git(
                ["git", "push", "--no-tags", "origin", f"HEAD:refs/heads/{branch}"],
                cwd=cwd,
                extra_env=credential_env,
            )
        except subprocess.CalledProcessError as exc:
            # Do not echo stderr: it can contain credential-bearing URLs in some Git builds.
            raise RemediationRemotePublishError(
                "Git push of the verified remediation commit was rejected by the remote"
            ) from exc

        remote_listing = self._run_git(
            ["git", "ls-remote", "origin", f"refs/heads/{branch}"],
            cwd=cwd,
            extra_env=credential_env,
        ).stdout.strip()
        expected_line = f"{head_sha}\trefs/heads/{branch}"
        if remote_listing != expected_line:
            raise RemediationRemotePublishError(
                "remote branch does not point at the verified remediation commit"
            )

        logger.info(
            "Published remediation commit %s to refs/heads/%s", head_sha[:12], branch
        )
        return head_sha

    def cleanup(self, workspace: RemediationWorkspace) -> None:
        cleanup_root = Path(workspace.cleanup_path).resolve()
        if cleanup_root not in self._active_workspaces:
            return
        self._cleanup_path(cleanup_root)
        self._active_workspaces.discard(cleanup_root)

    def _run_git(
        self,
        args: Sequence[str],
        cwd: Path | None = None,
        extra_env: Mapping[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if not args or args[0] != "git":
            raise RemediationWorkspaceCommandError(
                "workspace service accepts only fixed Git commands"
            )
        if any("\x00" in arg for arg in args):
            raise RemediationWorkspaceCommandError(
                "Git command arguments must not contain NUL bytes"
            )

        env = {
            key: value
            for key, value in os.environ.items()
            if key not in {"GIT_SSH_COMMAND", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"}
        }
        env["GIT_TERMINAL_PROMPT"] = "0"
        if extra_env:
            env.update(extra_env)

        try:
            return subprocess.run(
                list(args),
                cwd=str(cwd) if cwd else None,
                capture_output=True,
                text=True,
                check=True,
                shell=False,
                env=env,
                timeout=self.git_timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            logger.error("Bounded Git command timed out: %s", args[1:3])
            raise

    def _cleanup_path(self, cleanup_root: Path) -> None:
        resolved = cleanup_root.resolve()
        if resolved.name.startswith(self.workspace_prefix):
            shutil.rmtree(resolved, ignore_errors=True)
