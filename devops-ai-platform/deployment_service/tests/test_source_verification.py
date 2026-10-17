"""Server-side source revision verification (Stage 5 §B).

Exercises the real ``GitHubSourceVerifier`` against a mocked GitHub API:

* 200 + matching commit sha → attestation recorded (method, canonical
  repo/sha, remote commit id);
* 404 → ``not_found`` (the revision does not exist in that repository);
* 401/403/429/5xx, network failures, non-JSON bodies, or a 200 for a
  DIFFERENT commit → ``unavailable`` (fail closed, never substituted);
* canonical input gates reject malformed repo/SHA without any network call;
* the credential never appears in the URL, argv, exception messages or the
  returned attestation.
"""

import unittest
from unittest.mock import patch

import requests

from deployment_service.application.services.source_verification import (
    GitHubSourceVerifier,
    SourceVerificationError,
)

REPO = "acme/checkout"
SHA = "a" * 40
FAKE_TOKEN = "ghp_placeholder_token_not_a_real_credential"


def _response(status_code=200, json_body=None, json_error=False):
    resp = requests.Response()
    resp.status_code = status_code
    if json_error:
        resp._content = b"not json"
    else:
        import json as _json

        resp._content = _json.dumps(json_body or {}).encode("utf-8")
    return resp


def _get_mock(side_effect=None, return_value=None):
    return patch(
        "deployment_service.application.services.source_verification.requests.get",
        side_effect=side_effect,
        return_value=return_value,
    )


class GitHubSourceVerifierTests(unittest.TestCase):
    def test_verified_revision_returns_attestation(self):
        with _get_mock(return_value=_response(200, {"sha": SHA})):
            result = GitHubSourceVerifier(token="").verify(REPO, SHA)
        self.assertEqual(result["method"], "github-commit-lookup")
        self.assertEqual(result["verified_repository"], REPO)
        self.assertEqual(result["verified_source_sha"], SHA)
        self.assertEqual(result["verified_remote_commit"], SHA)
        self.assertIn("verified_at", result)
        # no credentials in the attestation
        self.assertNotIn("token", str(result).lower())

    def test_uppercase_sha_is_canonicalized_before_lookup(self):
        with _get_mock(return_value=_response(200, {"sha": SHA})) as getter:
            GitHubSourceVerifier(token="").verify(REPO, SHA.upper())
        url = getter.call_args[0][0]
        self.assertIn(f"/repos/{REPO}/commits/{SHA}", url)
        self.assertNotIn("A", url.split("/commits/")[1])

    def test_unknown_revision_is_not_found(self):
        with _get_mock(return_value=_response(404)):
            with self.assertRaises(SourceVerificationError) as ctx:
                GitHubSourceVerifier(token="").verify(REPO, "f" * 40)
        self.assertEqual(ctx.exception.reason, "not_found")
        self.assertIn("not found", ctx.exception.public_message)

    def test_rate_limit_and_auth_errors_fail_closed_as_unavailable(self):
        for status in (401, 403, 429, 500, 502, 503):
            with self.subTest(status=status):
                with _get_mock(return_value=_response(status)):
                    with self.assertRaises(SourceVerificationError) as ctx:
                        GitHubSourceVerifier(token=FAKE_TOKEN).verify(REPO, SHA)
                self.assertEqual(ctx.exception.reason, "unavailable")

    def test_network_failure_fails_closed_as_unavailable(self):
        with _get_mock(side_effect=requests.ConnectionError("dns down")):
            with self.assertRaises(SourceVerificationError) as ctx:
                GitHubSourceVerifier(token="").verify(REPO, SHA)
        self.assertEqual(ctx.exception.reason, "unavailable")
        # the public message carries no provider details
        self.assertNotIn("dns", ctx.exception.public_message)

    def test_non_json_body_fails_closed(self):
        with _get_mock(return_value=_response(200, json_error=True)):
            with self.assertRaises(SourceVerificationError) as ctx:
                GitHubSourceVerifier(token="").verify(REPO, SHA)
        self.assertEqual(ctx.exception.reason, "unavailable")

    def test_200_for_a_different_commit_is_not_confirmation(self):
        """A provider answer for a different sha never substitutes for the
        requested revision (no silent head/branch/tag substitution)."""
        with _get_mock(return_value=_response(200, {"sha": "b" * 40})):
            with self.assertRaises(SourceVerificationError) as ctx:
                GitHubSourceVerifier(token="").verify(REPO, SHA)
        self.assertEqual(ctx.exception.reason, "unavailable")

    def test_malformed_inputs_never_reach_the_network(self):
        for repo, sha, why in (
            ("checkout", SHA, "bare repo"),
            ("a/b/c", SHA, "triple segment"),
            ("../checkout", SHA, "path trick"),
            (REPO, "main", "branch name"),
            (REPO, "a" * 39, "short sha"),
            (REPO, "", "empty sha"),
            (REPO, "z" * 40, "non-hex"),
            (None, SHA, "null repo"),
        ):
            with self.subTest(why=why):
                with _get_mock() as getter:
                    with self.assertRaises(SourceVerificationError) as ctx:
                        GitHubSourceVerifier(token="").verify(repo, sha)
                self.assertEqual(ctx.exception.reason, "not_found")
                getter.assert_not_called()

    def test_token_travels_only_in_the_authorization_header(self):
        with _get_mock(return_value=_response(200, {"sha": SHA})) as getter:
            GitHubSourceVerifier(token=FAKE_TOKEN).verify(REPO, SHA)
        url = getter.call_args[0][0]
        headers = getter.call_args.kwargs["headers"]
        self.assertNotIn(FAKE_TOKEN, url)
        self.assertNotIn("token", url.lower())
        self.assertEqual(headers["Authorization"], f"Bearer {FAKE_TOKEN}")

    def test_missing_token_sends_no_authorization_header(self):
        with _get_mock(return_value=_response(200, {"sha": SHA})) as getter:
            GitHubSourceVerifier(token="").verify(REPO, SHA)
        headers = getter.call_args.kwargs["headers"]
        self.assertNotIn("Authorization", headers)

    def test_token_from_environment_is_read_at_construction(self):
        import os
        from unittest.mock import patch as _patch_env

        with _patch_env.dict(os.environ, {"GITHUB_OAUTH_TOKEN": FAKE_TOKEN}):
            verifier = GitHubSourceVerifier()
        with _get_mock(return_value=_response(200, {"sha": SHA})) as getter:
            verifier.verify(REPO, SHA)
        headers = getter.call_args.kwargs["headers"]
        self.assertEqual(headers["Authorization"], f"Bearer {FAKE_TOKEN}")
        self.assertNotIn(FAKE_TOKEN, getter.call_args[0][0])

    def test_bounded_timeout_is_passed(self):
        with _get_mock(return_value=_response(200, {"sha": SHA})) as getter:
            GitHubSourceVerifier(token="", timeout_seconds=3.5).verify(REPO, SHA)
        self.assertEqual(getter.call_args.kwargs["timeout"], 3.5)

    def test_non_positive_timeout_is_refused(self):
        with self.assertRaises(ValueError):
            GitHubSourceVerifier(timeout_seconds=0)


if __name__ == "__main__":
    unittest.main()
