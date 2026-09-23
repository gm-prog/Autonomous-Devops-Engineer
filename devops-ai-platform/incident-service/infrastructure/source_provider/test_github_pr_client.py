import unittest
from unittest.mock import Mock, patch

from github_pr_client import (
    GitHubPRClient,
    InvalidGitHubTokenException,
    PRCreationFailedException,
    UnsafePullRequestTargetException,
)


class GitHubPRClientTests(unittest.TestCase):
    def test_missing_token_never_fabricates_url(self):
        client = GitHubPRClient(oauth_token="")
        with self.assertRaises(InvalidGitHubTokenException):
            client.create_pull_request(
                "owner/repo",
                "automation/fix-123",
                "Fix incident",
                "Automated remediation",
            )

    def test_protected_head_branch_is_rejected(self):
        client = GitHubPRClient(oauth_token="secret")
        with self.assertRaises(UnsafePullRequestTargetException):
            client.create_pull_request(
                "owner/repo",
                "main",
                "Fix incident",
                "Automated remediation",
            )

    def test_non_allowlisted_base_branch_is_rejected(self):
        client = GitHubPRClient(oauth_token="secret", allowed_base_branches={"main"})
        with self.assertRaises(UnsafePullRequestTargetException):
            client.create_pull_request(
                "owner/repo",
                "automation/fix-123",
                "Fix incident",
                "Automated remediation",
                base="production",
            )

    @patch("github_pr_client.requests.post")
    def test_success_returns_github_url(self, post):
        response = Mock(status_code=201)
        response.json.return_value = {
            "html_url": "https://github.com/owner/repo/pull/42"
        }
        post.return_value = response

        client = GitHubPRClient(oauth_token="secret")
        url = client.create_pull_request(
            "owner/repo",
            "automation/fix-123",
            "Fix incident",
            "Automated remediation",
        )

        self.assertEqual(url, "https://github.com/owner/repo/pull/42")
        payload = post.call_args.kwargs["json"]
        self.assertTrue(payload["draft"])
        self.assertFalse(payload["maintainer_can_modify"])

    @patch("github_pr_client.requests.post")
    def test_github_failure_does_not_return_placeholder_url(self, post):
        post.return_value = Mock(status_code=500, text="server error")

        client = GitHubPRClient(oauth_token="secret")
        with self.assertRaises(PRCreationFailedException):
            client.create_pull_request(
                "owner/repo",
                "automation/fix-123",
                "Fix incident",
                "Automated remediation",
            )


if __name__ == "__main__":
    unittest.main()
