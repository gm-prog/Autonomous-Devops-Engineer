import unittest
from unittest.mock import Mock, patch

from incident_service.infrastructure.source_provider.github_pr_client import (
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

    @patch("incident_service.infrastructure.source_provider.github_pr_client.requests.post")
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

    @patch("incident_service.infrastructure.source_provider.github_pr_client.requests.get")
    @patch("incident_service.infrastructure.source_provider.github_pr_client.requests.post")
    def test_existing_branch_at_same_commit_is_idempotent(self, post, get):
        commit_response = Mock(status_code=200)
        commit_response.json.return_value = {"sha": "b" * 40, "parents": [{"sha": "a" * 40}]}
        existing_ref = Mock(status_code=200)
        existing_ref.json.return_value = {"object": {"sha": "b" * 40}}
        get.side_effect = [commit_response, existing_ref]

        client = GitHubPRClient(oauth_token="secret")
        url = client.create_branch_from_commit("owner/repo", "automation/remediation/inc-1/proposal-1", "b" * 40, "a" * 40)
        self.assertTrue(url.endswith("/tree/automation/remediation/inc-1/proposal-1"))
        post.assert_not_called()

    @patch("incident_service.infrastructure.source_provider.github_pr_client.requests.get")
    @patch("incident_service.infrastructure.source_provider.github_pr_client.requests.post")
    def test_existing_branch_at_different_commit_is_rejected(self, post, get):
        commit_response = Mock(status_code=200)
        commit_response.json.return_value = {"sha": "b" * 40, "parents": [{"sha": "a" * 40}]}
        existing_ref = Mock(status_code=200)
        existing_ref.json.return_value = {"object": {"sha": "c" * 40}}
        get.side_effect = [commit_response, existing_ref]

        client = GitHubPRClient(oauth_token="secret")
        with self.assertRaises(PRCreationFailedException):
            client.create_branch_from_commit("owner/repo", "automation/remediation/inc-1/proposal-1", "b" * 40, "a" * 40)
        post.assert_not_called()

    @patch("incident_service.infrastructure.source_provider.github_pr_client.requests.get")
    @patch("incident_service.infrastructure.source_provider.github_pr_client.requests.post")
    def test_branch_publication_verifies_parent_and_remote_ref(self, post, get):
        commit_response = Mock(status_code=200)
        commit_response.json.return_value = {
            "sha": "b" * 40,
            "parents": [{"sha": "a" * 40}],
        }
        missing_ref = Mock(status_code=404)
        ref_response = Mock(status_code=200)
        ref_response.json.return_value = {"object": {"sha": "b" * 40}}
        get.side_effect = [commit_response, missing_ref, ref_response]
        post.return_value = Mock(status_code=201)

        client = GitHubPRClient(oauth_token="secret")
        url = client.create_branch_from_commit(
            "owner/repo",
            "automation/remediation/inc-1/proposal-1",
            "b" * 40,
            "a" * 40,
        )

        self.assertEqual(
            url,
            "https://github.com/owner/repo/tree/automation/remediation/inc-1/proposal-1",
        )
        payload = post.call_args.kwargs["json"]
        self.assertEqual(
            payload,
            {
                "ref": "refs/heads/automation/remediation/inc-1/proposal-1",
                "sha": "b" * 40,
            },
        )

    @patch("incident_service.infrastructure.source_provider.github_pr_client.requests.get")
    def test_branch_publication_rejects_parent_mismatch(self, get):
        response = Mock(status_code=200)
        response.json.return_value = {
            "sha": "b" * 40,
            "parents": [{"sha": "c" * 40}],
        }
        get.return_value = response

        client = GitHubPRClient(oauth_token="secret")
        with self.assertRaises(PRCreationFailedException):
            client.create_branch_from_commit(
                "owner/repo",
                "automation/remediation/inc-1/proposal-1",
                "b" * 40,
                "a" * 40,
            )

    @patch("incident_service.infrastructure.source_provider.github_pr_client.requests.post")
    @patch("incident_service.infrastructure.source_provider.github_pr_client.requests.get")
    def test_branch_publication_rejects_create_race(self, get, post):
        commit_response = Mock(status_code=200)
        commit_response.json.return_value = {
            "sha": "b" * 40, "parents": [{"sha": "a" * 40}]
        }
        missing_ref = Mock(status_code=404)
        get.side_effect = [commit_response, missing_ref]
        post.return_value = Mock(status_code=422)

        client = GitHubPRClient(oauth_token="secret")
        with self.assertRaises(PRCreationFailedException):
            client.create_branch_from_commit(
                "owner/repo",
                "automation/remediation/inc-1/proposal-1",
                "b" * 40,
                "a" * 40,
            )
        self.assertEqual(post.call_count, 1)

    @patch("incident_service.infrastructure.source_provider.github_pr_client.requests.post")
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
