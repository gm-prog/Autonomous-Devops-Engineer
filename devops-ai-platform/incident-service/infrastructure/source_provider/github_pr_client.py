import os
import requests
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("GitHubPRClient")

# Exceptions
class PRCreationFailedException(Exception): pass
class InvalidGitHubTokenException(Exception): pass
class RepositoryNotFoundException(Exception): pass

class GitHubPRClient:
    """Interacts with upstream GitHub REST APIs via authorization tokens to merge patches.

    Honesty contract (Phase 8.7-D.1): when credentials are missing or the
    API call fails, these operations RAISE — they never return a fake PR URL
    or report success for a no-op.
    """
    def __init__(self, oauth_token: Optional[str] = None):
        self.oauth_token = oauth_token or os.getenv("GITHUB_OAUTH_TOKEN", "")

    def verify_credentials(self) -> bool:
        if not self.oauth_token:
            return False
        headers = {
            "Authorization": f"token {self.oauth_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        resp = requests.get("https://api.github.com/user", headers=headers)
        return resp.status_code == 200

    def create_pull_request(self, repo_slug: str, branch: str, title: str, body: str, draft: bool = True) -> str:
        logger.info(f"Opening automated {'DRAFT ' if draft else ''}Pull Request on slug '{repo_slug}' targeting changes in '{branch}'")
        if not self.oauth_token:
            # Never fabricate a PR URL: without credentials no PR exists.
            raise PRCreationFailedException(
                "GitHub credentials are not configured; no pull request was "
                "created and no URL is fabricated."
            )

        endpoint = f"https://api.github.com/repos/{repo_slug}/pulls"
        headers = {
            "Authorization": f"token {self.oauth_token}",
            "Accept": "application/vnd.github.v3+json"
        }

        payload = {
            "title": title,
            "body": body,
            "head": branch,
            "base": "main",
            "draft": draft
        }

        try:
            response = requests.post(endpoint, json=payload, headers=headers, timeout=30)
        except requests.RequestException as e:
            raise PRCreationFailedException(f"Network failure while communicating with GitHub API: {e}")

        if response.status_code == 401:
            raise InvalidGitHubTokenException("The provided GitHub OAuth token is invalid or expired.")
        elif response.status_code == 404:
            raise RepositoryNotFoundException(f"Target repository slug {repo_slug} was not found on GitHub.")
        elif response.status_code != 201:
            raise PRCreationFailedException(f"Failed to compile GitHub PR: {response.text}")

        data = response.json()
        html_url = data.get("html_url")
        if not html_url:
            # The PR was created but the API did not return its URL: report
            # the anomaly explicitly instead of inventing one.
            raise PRCreationFailedException(
                "GitHub PR creation succeeded but the response carried no "
                "html_url; no URL is fabricated."
            )
        return html_url

    def mark_pr_ready_for_review(self, repo_slug: str, pr_number: int) -> bool:
        """Transition a draft PR to ready-for-review.

        Uses the correct GitHub operation (PUT /repos/{slug}/pulls/{number}
        with ``draft: false``) and fails explicitly on missing credentials or
        any non-success response — it never returns success for a no-op.
        """
        if not self.oauth_token:
            raise InvalidGitHubTokenException(
                "GitHub credentials are not configured; the PR was not "
                "transitioned to ready-for-review."
            )
        endpoint = f"https://api.github.com/repos/{repo_slug}/pulls/{pr_number}"
        headers = {
            "Authorization": f"token {self.oauth_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        logger.info(f"Marking PR #{pr_number} in {repo_slug} ready for review (draft=false).")
        try:
            response = requests.put(
                endpoint, json={"draft": False}, headers=headers, timeout=30
            )
        except requests.RequestException as e:
            raise PRCreationFailedException(
                f"Network failure while transitioning PR #{pr_number} in {repo_slug}: {e}"
            )
        if response.status_code == 401:
            raise InvalidGitHubTokenException("The provided GitHub OAuth token is invalid or expired.")
        if response.status_code not in (200, 204):
            raise PRCreationFailedException(
                f"Failed to mark PR #{pr_number} in {repo_slug} ready for review "
                f"(HTTP {response.status_code})."
            )
        return True
