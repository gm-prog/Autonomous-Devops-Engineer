"""Tests for publishing a verified remediation commit to the remote repository."""

import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from .remediation_workspace_service import (
    RemediationRemotePublishError,
    RemediationWorkspace,
    RemediationWorkspaceService,
)

_BRANCH = "automation/remediation/inc-1/proposal-1"
_SHA = "b" * 40
_TOKEN = "ghp_test_secret_token_value"


def _workspace(path: str = "/tmp/workspace") -> RemediationWorkspace:
    return RemediationWorkspace(
        path=path,
        cleanup_path=path + "-root",
        repository_slug="owner/repo",
        source_sha="a" * 40,
        base_branch="main",
        branch_name=_BRANCH,
    )


class RemediationWorkspacePushTests(unittest.TestCase):
    def _service(self):
        return RemediationWorkspaceService()

    def test_missing_token_raises_before_any_git_command(self):
        service = self._service()
        with patch.object(service, "_run_git") as git:
            with self.assertRaises(RemediationRemotePublishError):
                service.publish_branch(_workspace(), oauth_token="")
        git.assert_not_called()

    def test_whitespace_token_raises_before_any_git_command(self):
        service = self._service()
        with patch.object(service, "_run_git") as git:
            with self.assertRaises(RemediationRemotePublishError):
                service.publish_branch(_workspace(), oauth_token="   ")
        git.assert_not_called()

    def test_push_transfers_commit_and_verifies_remote_ref(self):
        service = self._service()
        calls = []

        def fake_git(args, cwd=None, extra_env=None):
            command = list(args)
            calls.append((command, dict(extra_env or {})))
            if command[1] == "rev-parse":
                return Mock(stdout=_SHA + "\n")
            if command[1] == "ls-remote":
                return Mock(stdout=f"{_SHA}\trefs/heads/{_BRANCH}\n")
            return Mock(stdout="")

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(service, "_run_git", side_effect=fake_git):
                published = service.publish_branch(_workspace(tmp), oauth_token=_TOKEN)

        self.assertEqual(published, _SHA)
        commands = [c for c, _ in calls]
        self.assertEqual(
            commands[1],
            ["git", "push", "--no-tags", "origin", f"HEAD:refs/heads/{_BRANCH}"],
        )
        self.assertEqual(
            commands[2], ["git", "ls-remote", "origin", f"refs/heads/{_BRANCH}"]
        )

        # Credential hygiene: the token must never appear in command arguments.
        for command, _ in calls:
            self.assertNotIn(_TOKEN, command)

        # Credential transport: token travels only through the GIT_CONFIG_*
        # environment (http.extraHeader), never through the remote URL.
        for command, env in calls[1:]:
            if command[1] in {"push", "ls-remote"}:
                self.assertEqual(env.get("GIT_CONFIG_KEY_0"), "http.extraHeader")
                self.assertEqual(
                    env.get("GIT_CONFIG_VALUE_0"), f"Authorization: Bearer {_TOKEN}"
                )

    def test_remote_ref_mismatch_is_rejected(self):
        service = self._service()

        def fake_git(args, cwd=None, extra_env=None):
            command = list(args)
            if command[1] == "rev-parse":
                return Mock(stdout=_SHA + "\n")
            if command[1] == "ls-remote":
                # Remote points at a different commit than the verified one.
                return Mock(stdout=f"{'c' * 40}\trefs/heads/{_BRANCH}\n")
            return Mock(stdout="")

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(service, "_run_git", side_effect=fake_git):
                with self.assertRaises(RemediationRemotePublishError):
                    service.publish_branch(_workspace(tmp), oauth_token=_TOKEN)

    def test_push_rejection_by_remote_is_reported_without_stderr(self):
        service = self._service()

        def fake_git(args, cwd=None, extra_env=None):
            command = list(args)
            if command[1] == "rev-parse":
                return Mock(stdout=_SHA + "\n")
            if command[1] == "push":
                raise subprocess.CalledProcessError(
                    128, "git push", stderr="fatal: Authentication failed for 'https://github.com/'"
                )
            return Mock(stdout="")

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(service, "_run_git", side_effect=fake_git):
                with self.assertRaises(RemediationRemotePublishError) as ctx:
                    service.publish_branch(_workspace(tmp), oauth_token=_TOKEN)
        # The message must not echo raw Git stderr (credential exposure).
        self.assertNotIn("Authentication failed", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
