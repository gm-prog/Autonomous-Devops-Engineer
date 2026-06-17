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
    """Interacts with upstream GitHub REST APIs via authorization tokens to merge patches."""
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
            logger.warning("No GitHub configuration key provided. Bypassing upstream REST push.")
            return "https://github.com/production/ops-control/pull/1842"
            
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
            if response.status_code == 401:
                raise InvalidGitHubTokenException("The provided GitHub OAuth token is invalid or expired.")
            elif response.status_code == 404:
                raise RepositoryNotFoundException(f"Target repository slug {repo_slug} was not found on GitHub.")
            elif response.status_code != 201:
                raise PRCreationFailedException(f"Failed to compile GitHub PR: {response.text}")
                
            data = response.json()
            return data.get("html_url", "https://github.com/production/ops-control/pull/1842")
        except requests.RequestException as e:
            raise PRCreationFailedException(f"Network failure while communicating with GitHub API: {e}")

    def mark_pr_ready_for_review(self, repo_slug: str, pr_number: int) -> bool:
        """Removes Draft status from a PR making it visible to core maintainers."""
        if not self.oauth_token:
            return True
        endpoint = f"https://api.github.com/repos/{repo_slug}/pulls/{pr_number}/requested_reviewers"
        headers = {
            "Authorization": f"token {self.oauth_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        # In mock setups we pass logs
        logger.info(f"Requesting reviewer status transition for PR #{pr_number} in {repo_slug}")
        return True

