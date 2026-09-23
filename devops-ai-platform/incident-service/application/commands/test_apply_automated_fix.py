import unittest
from unittest.mock import Mock

from application.commands.apply_automated_fix import (
    ApplyAutomatedFixCommand,
    ApplyAutomatedFixCommandHandler,
)
from domain.aggregates.incident import IncidentAggregate
from domain.entities.hotfix_proposal import HotfixProposal


PATCH = """--- a/src/service.py
+++ b/src/service.py
@@ -1 +1 @@
-old()
+new()
"""

SOURCE_SHA = "a" * 40


class FakeRepository:
    def __init__(self):
        self.incident = IncidentAggregate("inc-1", "Checkout", "HIGH", "5xx")
        self.saved = 0

    def get_incident_by_id(self, incident_id):
        return self.incident if incident_id == self.incident.id else None

    def save_incident(self, incident):
        self.saved += 1
        self.incident = incident


class FakeGitHub:
    def __init__(self):
        self.calls = []

    def create_pull_request(self, **kwargs):
        self.calls.append(kwargs)
        return "https://github.com/owner/repo/pull/42"


class ApplyAutomatedFixTests(unittest.TestCase):
    def test_validated_patch_creates_draft_pr_and_persists_proposal(self):
        repository = FakeRepository()
        github = FakeGitHub()
        handler = ApplyAutomatedFixCommandHandler(repository, github)

        result = handler.handle(
            ApplyAutomatedFixCommand(
                "inc-1",
                "src/service.py",
                PATCH,
                repository_slug="owner/repo",
                source_branch="automation/fix-inc-1",
                source_sha=SOURCE_SHA,
            )
        )

        self.assertTrue(result)
        self.assertEqual(repository.incident.status, "RemediationProposed")
        self.assertEqual(len(repository.incident.patch_proposals), 1)
        proposal = repository.incident.patch_proposals[0]
        self.assertTrue(proposal.is_verified)
        self.assertEqual(proposal.source_sha, SOURCE_SHA)
        self.assertEqual(proposal.pull_request_url, "https://github.com/owner/repo/pull/42")
        self.assertTrue(github.calls[0]["draft"])
        self.assertEqual(repository.saved, 1)

    def test_invalid_patch_never_reaches_github(self):
        repository = FakeRepository()
        github = FakeGitHub()
        handler = ApplyAutomatedFixCommandHandler(repository, github)

        result = handler.handle(
            ApplyAutomatedFixCommand(
                "inc-1",
                "src/service.py",
                "not a unified diff",
                repository_slug="owner/repo",
                source_branch="automation/fix-inc-1",
                source_sha=SOURCE_SHA,
            )
        )

        self.assertFalse(result)
        self.assertEqual(github.calls, [])
        self.assertEqual(repository.incident.patch_proposals, [])

    def test_missing_github_client_is_not_reported_as_applied(self):
        repository = FakeRepository()
        handler = ApplyAutomatedFixCommandHandler(repository, None)

        result = handler.handle(
            ApplyAutomatedFixCommand(
                "inc-1",
                "src/service.py",
                PATCH,
                repository_slug="owner/repo",
                source_branch="automation/fix-inc-1",
                source_sha=SOURCE_SHA,
            )
        )

        self.assertFalse(result)
        self.assertEqual(repository.incident.patch_proposals, [])

    def test_missing_source_sha_is_rejected(self):
        repository = FakeRepository()
        github = FakeGitHub()
        handler = ApplyAutomatedFixCommandHandler(repository, github)

        result = handler.handle(
            ApplyAutomatedFixCommand(
                "inc-1",
                "src/service.py",
                PATCH,
                repository_slug="owner/repo",
                source_branch="automation/fix-inc-1",
            )
        )

        self.assertFalse(result)
        self.assertEqual(github.calls, [])

    def test_multiple_file_patch_is_rejected(self):
        patch = PATCH + """--- a/other.py
+++ b/other.py
@@ -1 +1 @@
-old_other()
+new_other()
"""
        proposal = HotfixProposal("patch-multi", "src/service.py", patch)
        self.assertFalse(proposal.apply_verification_pass())
        self.assertFalse(proposal.is_verified)

    def test_mismatched_old_path_is_rejected(self):
        patch = """--- a/other.py
+++ b/src/service.py
@@ -1 +1 @@
-old()
+new()
"""
        proposal = HotfixProposal("patch-mismatch", "src/service.py", patch)
        self.assertFalse(proposal.apply_verification_pass())
        self.assertFalse(proposal.is_verified)


if __name__ == "__main__":
    unittest.main()
