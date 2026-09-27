import dataclasses
import logging
import os
import re
from typing import Optional

import requests

logger = logging.getLogger("GitHubPRClient")

_GITHUB_API = "https://api.github.com"
_GITHUB_API_VERSION = "2026-03-10"
_REPO_SLUG_PATTERN = re.compile(r"^[^/\s]+/[^/\s]+$")


class PRCreationFailedException(Exception):
    pass


class InvalidGitHubTokenException(Exception):
    pass


class RepositoryNotFoundException(Exception):
    pass


class UnsafePullRequestTargetException(Exception):
    pass


class GitHubPRClient:
    """Creates reviewable draft PRs through a bounded GitHub API surface.

    This adapter intentionally never fabricates a PR URL and never changes a
    branch directly. PR creation is limited to an allowlisted base branch and
    a non-protected head branch.
    """

    def __init__(
        self,
        oauth_token: Optional[str] = None,
        api_base_url: str = _GITHUB_API,
        timeout_seconds: float = 30.0,
        allowed_base_branches: Optional[set[str]] = None,
        protected_head_branches: Optional[set[str]] = None,
    ):
        self.oauth_token = oauth_token or os.getenv("GITHUB_OAUTH_TOKEN", "")
        self.api_base_url = api_base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")

        self.allowed_base_branches = allowed_base_branches or self._csv_env(
            "GITHUB_ALLOWED_BASE_BRANCHES",
            "main",
        )
        self.protected_head_branches = protected_head_branches or self._csv_env(
            "GITHUB_PROTECTED_HEAD_BRANCHES",
            "main,master,production,release",
        )

        if not self.allowed_base_branches:
            raise ValueError("at least one allowed base branch is required")

    @staticmethod
    def _csv_env(name: str, default: str) -> set[str]:
        return {
            item.strip()
            for item in os.getenv(name, default).split(",")
            if item.strip()
        }

    @property
    def _headers(self) -> dict[str, str]:
        if not self.oauth_token:
            return {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": _GITHUB_API_VERSION,
            }
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.oauth_token}",
            "X-GitHub-Api-Version": _GITHUB_API_VERSION,
        }

    def _require_token(self) -> None:
        if not self.oauth_token:
            raise InvalidGitHubTokenException(
                "GITHUB_OAUTH_TOKEN is required for GitHub operations"
            )

    @staticmethod
    def _validate_repo_slug(repo_slug: str) -> str:
        normalized = repo_slug.strip()
        if not _REPO_SLUG_PATTERN.fullmatch(normalized):
            raise RepositoryNotFoundException(
                "repo_slug must use the owner/repository format"
            )
        owner, repository = normalized.split("/", 1)
        repository = repository.removesuffix(".git")
        if not owner or not repository:
            raise RepositoryNotFoundException("GitHub repository is invalid")
        return f"{owner}/{repository}"

    def _validate_pr_target(self, head: str, base: str) -> tuple[str, str]:
        normalized_head = head.strip()
        normalized_base = base.strip()

        if not normalized_head or not normalized_base:
            raise UnsafePullRequestTargetException(
                "both head and base branches are required"
            )
        if normalized_head == normalized_base:
            raise UnsafePullRequestTargetException(
                "head and base branches must differ"
            )
        if normalized_head in self.protected_head_branches:
            raise UnsafePullRequestTargetException(
                f"automation cannot use protected head branch: {normalized_head}"
            )
        if normalized_base not in self.allowed_base_branches:
            raise UnsafePullRequestTargetException(
                f"base branch is not allowlisted: {normalized_base}"
            )
        return normalized_head, normalized_base

    def verify_credentials(self) -> bool:
        self._require_token()
        response = requests.get(
            f"{self.api_base_url}/user",
            headers=self._headers,
            timeout=self.timeout_seconds,
        )
        if response.status_code == 401:
            raise InvalidGitHubTokenException(
                "The provided GitHub OAuth token is invalid or expired."
            )
        return response.status_code == 200

    def create_pull_request(
        self,
        repo_slug: str,
        branch: str,
        title: str,
        body: str,
        draft: bool = True,
        base: Optional[str] = None,
    ) -> str:
        self._require_token()
        repo = self._validate_repo_slug(repo_slug)
        head, target_base = self._validate_pr_target(
            branch,
            base or os.getenv("GITHUB_DEFAULT_BASE_BRANCH", "main"),
        )

        if not title.strip():
            raise PRCreationFailedException("pull request title must not be empty")

        payload = {
            "title": title.strip(),
            "body": body,
            "head": head,
            "base": target_base,
            "draft": bool(draft),
            "maintainer_can_modify": False,
        }

        try:
            response = requests.post(
                f"{self.api_base_url}/repos/{repo}/pulls",
                json=payload,
                headers=self._headers,
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as exc:
            raise PRCreationFailedException(
                "network failure while communicating with GitHub API"
            ) from exc

        if response.status_code == 401:
            raise InvalidGitHubTokenException(
                "The provided GitHub OAuth token is invalid or expired."
            )
        if response.status_code == 404:
            raise RepositoryNotFoundException(
                f"Target repository {repo} was not found on GitHub."
            )
        if response.status_code != 201:
            raise PRCreationFailedException(
                f"GitHub rejected pull request creation with HTTP {response.status_code}"
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise PRCreationFailedException(
                "GitHub returned invalid JSON after creating the pull request"
            ) from exc

        url = data.get("html_url")
        if not isinstance(url, str) or not url.startswith("https://github.com/"):
            raise PRCreationFailedException(
                "GitHub response did not contain a valid pull request URL"
            )
        return url

    def create_branch_from_commit(
        self,
        repo_slug: str,
        branch: str,
        commit_sha: str,
        expected_parent_sha: str,
    ) -> str:
        """Create a remote branch exactly at a verified commit; never update an existing ref."""
        self._require_token()
        repo = self._validate_repo_slug(repo_slug)
        normalized_branch = branch.strip()
        normalized_commit = commit_sha.strip().lower()
        normalized_parent = expected_parent_sha.strip().lower()

        if not re.fullmatch(r"[0-9a-f]{40}", normalized_commit):
            raise PRCreationFailedException("commit_sha must be a full Git SHA")
        if not re.fullmatch(r"[0-9a-f]{40}", normalized_parent):
            raise PRCreationFailedException("expected_parent_sha must be a full Git SHA")
        if (
            not normalized_branch.startswith("automation/remediation/")
            or normalized_branch.startswith("-")
            or ".." in normalized_branch
            or any(part in {"", ".", ".."} for part in normalized_branch.split("/"))
            or not re.fullmatch(r"[A-Za-z0-9._/-]+", normalized_branch)
            or normalized_branch in self.protected_head_branches
        ):
            raise UnsafePullRequestTargetException(
                "remediation branch violates the controlled branch policy"
            )

        commit_response = requests.get(
            f"{self.api_base_url}/repos/{repo}/commits/{normalized_commit}",
            headers=self._headers,
            timeout=self.timeout_seconds,
        )
        if commit_response.status_code == 401:
            raise InvalidGitHubTokenException("The provided GitHub OAuth token is invalid or expired.")
        if commit_response.status_code == 404:
            raise PRCreationFailedException("commit does not exist on the remote repository")
        if commit_response.status_code != 200:
            raise PRCreationFailedException(
                f"GitHub rejected commit verification with HTTP {commit_response.status_code}"
            )

        try:
            parents = commit_response.json().get("parents", [])
        except ValueError as exc:
            raise PRCreationFailedException("GitHub returned invalid commit JSON") from exc

        if len(parents) != 1 or parents[0].get("sha", "").lower() != normalized_parent:
            raise PRCreationFailedException(
                "remote commit parent does not match the pinned source SHA"
            )

        ref_url = f"{self.api_base_url}/repos/{repo}/git/ref/heads/{normalized_branch}"
        existing = requests.get(
            ref_url,
            headers=self._headers,
            timeout=self.timeout_seconds,
        )
        if existing.status_code == 200:
            try:
                existing_sha = existing.json().get("object", {}).get("sha", "").lower()
            except ValueError as exc:
                raise PRCreationFailedException(
                    "GitHub returned invalid existing branch JSON"
                ) from exc
            if existing_sha == normalized_commit:
                return f"https://github.com/{repo}/tree/{normalized_branch}"
            raise PRCreationFailedException(
                "remediation branch already exists at a different commit"
            )
        if existing.status_code not in {404}:
            if existing.status_code == 401:
                raise InvalidGitHubTokenException(
                    "The provided GitHub OAuth token is invalid or expired."
                )
            raise PRCreationFailedException(
                f"GitHub rejected branch existence check with HTTP {existing.status_code}"
            )

        try:
            response = requests.post(
                f"{self.api_base_url}/repos/{repo}/git/refs",
                json={"ref": f"refs/heads/{normalized_branch}", "sha": normalized_commit},
                headers=self._headers,
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as exc:
            raise PRCreationFailedException(
                "network failure while publishing remediation branch"
            ) from exc

        if response.status_code == 401:
            raise InvalidGitHubTokenException("The provided GitHub OAuth token is invalid or expired.")
        if response.status_code == 422:
            raise PRCreationFailedException(
                "remediation branch already exists or GitHub rejected the ref"
            )
        if response.status_code != 201:
            raise PRCreationFailedException(
                f"GitHub rejected branch publication with HTTP {response.status_code}"
            )

        verification = requests.get(
            f"{self.api_base_url}/repos/{repo}/git/ref/heads/{normalized_branch}",
            headers=self._headers,
            timeout=self.timeout_seconds,
        )
        if verification.status_code != 200:
            raise PRCreationFailedException(
                "GitHub branch publication could not be verified"
            )
        try:
            verification_sha = (
                verification.json().get("object", {}).get("sha", "").lower()
            )
        except ValueError as exc:
            raise PRCreationFailedException(
                "GitHub returned invalid branch verification JSON"
            ) from exc
        if verification_sha != normalized_commit:
            raise PRCreationFailedException(
                "remote remediation branch does not point to the created commit"
            )

        return f"https://github.com/{repo}/tree/{normalized_branch}"

    def find_existing_pull_requests(
        self,
        repo_slug: str,
        head: str,
        base: str,
    ) -> list["ExistingPullRequest"]:
        """Find PRs for the exact deterministic head/base pair (section 40).

        Returns every match for callers to apply explicit policy (none ->
        create, one -> reuse/conflict, many -> fail closed). Never creates,
        never mutates; bounded timeouts; distinct 401/403/404/429/5xx
        handling; malformed payloads fail closed.
        """
        self._require_token()
        repo = self._validate_repo_slug(repo_slug)
        normalized_head, normalized_base = self._validate_pr_target(head, base)
        owner = repo.split("/", 1)[0]

        try:
            response = requests.get(
                f"{self.api_base_url}/repos/{repo}/pulls",
                params={
                    "head": f"{owner}:{normalized_head}",
                    "base": normalized_base,
                    "state": "all",
                    "per_page": 20,
                },
                headers=self._headers,
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as exc:
            raise PullRequestLookupFailedException(
                "network failure while querying existing pull requests"
            ) from exc

        if response.status_code == 401:
            raise InvalidGitHubTokenException(
                "The provided GitHub OAuth token is invalid or expired "
                "(GitHub HTTP 401 during pull request discovery)."
            )
        if response.status_code == 404:
            raise RepositoryNotFoundException(
                f"Target repository {repo} was not found on GitHub."
            )
        if response.status_code == 403:
            raise PullRequestLookupFailedException(
                "GitHub refused pull request discovery (HTTP 403 forbidden)"
            )
        if response.status_code == 429:
            raise PullRequestLookupFailedException(
                "GitHub rate limit exceeded during pull request discovery"
            )
        if response.status_code != 200:
            raise PullRequestLookupFailedException(
                "GitHub rejected pull request discovery with HTTP "
                f"{response.status_code}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise PullRequestLookupFailedException(
                "GitHub returned invalid JSON during pull request discovery"
            ) from exc
        if not isinstance(payload, list):
            raise PullRequestLookupFailedException(
                "GitHub returned an unexpected pull request discovery payload"
            )

        matches: list[ExistingPullRequest] = []
        for item in payload:
            try:
                head_ref = item["head"]["ref"]
                base_ref = item["base"]["ref"]
                number = int(item["number"])
                url = str(item["html_url"])
                state = str(item["state"])
                draft = bool(item.get("draft", False))
                merged = (
                    item.get("merged") is True
                    or item.get("merged_at") is not None
                )
                body = str(item.get("body") or "")
            except (KeyError, TypeError, ValueError) as exc:
                raise PullRequestLookupFailedException(
                    "GitHub returned a malformed pull request entry"
                ) from exc
            if head_ref != normalized_head or base_ref != normalized_base:
                continue  # API filters are hints; verify exact identity here
            if not url.startswith("https://github.com/"):
                raise PullRequestLookupFailedException(
                    "GitHub returned a pull request with an unexpected URL"
                )
            matches.append(
                ExistingPullRequest(
                    number=number,
                    url=url,
                    state=state,
                    draft=draft,
                    merged=merged,
                    head_ref=head_ref,
                    base_ref=base_ref,
                    body=body,
                )
            )
        return matches

    def mark_pr_ready_for_review(self, repo_slug: str, pr_number: int) -> bool:
        """Transition a draft PR to ready only when explicitly enabled."""
        self._require_token()
        if os.getenv("GITHUB_ALLOW_READY_FOR_REVIEW", "false").lower() != "true":
            raise UnsafePullRequestTargetException(
                "ready-for-review transition is disabled by policy"
            )
        if pr_number <= 0:
            raise ValueError("pr_number must be positive")

        repo = self._validate_repo_slug(repo_slug)
        try:
            response = requests.patch(
                f"{self.api_base_url}/repos/{repo}/pulls/{pr_number}",
                json={"draft": False},
                headers=self._headers,
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as exc:
            raise PRCreationFailedException(
                "network failure while updating GitHub pull request"
            ) from exc

        if response.status_code == 401:
            raise InvalidGitHubTokenException(
                "The provided GitHub OAuth token is invalid or expired."
            )
        if response.status_code == 404:
            raise RepositoryNotFoundException(
                f"Pull request #{pr_number} or repository {repo} was not found."
            )
        if response.status_code != 200:
            raise PRCreationFailedException(
                f"GitHub rejected ready-for-review transition with HTTP {response.status_code}"
            )
        return True


class PullRequestLookupFailedException(Exception):
    """GitHub could not return a trustworthy answer for PR discovery."""


@dataclasses.dataclass(frozen=True)
class ExistingPullRequest:
    """Typed, minimal view of a remote PR used for reconciliation."""

    number: int
    url: str
    state: str  # "open" | "closed"
    draft: bool
    merged: bool
    head_ref: str
    base_ref: str
    body: str
