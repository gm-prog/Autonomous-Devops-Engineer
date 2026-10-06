"""Phase 8 §40 — incident lifecycle + proposal lifecycle state matrix.

Tests the STATES, not just the helpers: every required transition, every
invalid transition from the brief, idempotent replays, and the Phase 8
regeneration guard that prevents APPROVED/EXECUTING/PR_CREATED/
EXECUTION_FAILED proposals from being reset to PROPOSED/BLOCKED.
"""

import unittest

from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.domain.entities.hotfix_proposal import HotfixProposal


def _proposal(
    proposal_id="prop-1",
    status="PROPOSED",
    is_verified=True,
    patch="--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+new\n",
):
    return HotfixProposal(
        id=proposal_id,
        target_filepath="app.py",
        diff_patch_payload=patch,
        is_verified=is_verified,
        status=status,
        source_sha="a" * 40,
        incident_id="inc-1",
        repository="owner/repo",
        proposal_hash="f" * 64,
    )


def _raised():
    return IncidentAggregate("inc-1", "[test] breach", "HIGH", "ctx")


def _at(status):
    """Incident driven to ``status`` through explicit legal transitions."""
    chain = {
        "Raised": ("",),
        "Triage": ("triage",),
        "Investigating": ("triage", "investigate"),
        "RootCauseFound": ("triage", "investigate", "rca"),
        "RemediationProposed": ("triage", "investigate", "rca", "proposal"),
        "RemediationPRCreated": (
            "triage",
            "investigate",
            "rca",
            "proposal",
            "pr",
        ),
    }[status]
    incident = _raised()
    if "triage" in chain:
        incident.move_to_triage()
    if "investigate" in chain:
        incident.begin_investigation()
    if "rca" in chain:
        incident.mark_root_cause_found()
    if "proposal" in chain:
        incident.upsert_remediation_proposal(_proposal())
    if "pr" in chain:
        incident.mark_remediation_pr_created()
    return incident


class IncidentLifecycleMatrixTests(unittest.TestCase):
    """§40 row-by-row coverage of the canonical incident chain."""

    # --- valid transitions ---------------------------------------------
    def test_raised_to_triage(self):
        incident = _raised()
        incident.move_to_triage()
        self.assertEqual(incident.status, "Triage")

    def test_triage_to_investigating(self):
        incident = _at("Triage")
        incident.begin_investigation()
        self.assertEqual(incident.status, "Investigating")

    def test_investigating_to_root_cause_found(self):
        incident = _at("Investigating")
        incident.mark_root_cause_found()
        self.assertEqual(incident.status, "RootCauseFound")

    def test_root_cause_found_to_remediation_proposed(self):
        incident = _at("RootCauseFound")
        incident.upsert_remediation_proposal(_proposal())
        self.assertEqual(incident.status, "RemediationProposed")

    def test_remediation_proposed_to_pr_created(self):
        incident = _at("RemediationProposed")
        incident.mark_remediation_pr_created()
        self.assertEqual(incident.status, "RemediationPRCreated")

    # --- invalid transitions must be rejected --------------------------
    def test_raised_cannot_skip_to_root_cause_found(self):
        with self.assertRaises(ValueError):
            _raised().mark_root_cause_found()

    def test_raised_cannot_skip_to_remediation_proposed(self):
        with self.assertRaises(ValueError):
            _raised().upsert_remediation_proposal(_proposal())

    def test_raised_cannot_skip_to_investigating(self):
        with self.assertRaises(ValueError):
            _raised().begin_investigation()

    def test_triage_cannot_skip_to_root_cause_found(self):
        with self.assertRaises(ValueError):
            _at("Triage").mark_root_cause_found()

    def test_triage_cannot_skip_to_remediation_pr_created(self):
        with self.assertRaises(ValueError):
            _at("Triage").mark_remediation_pr_created()

    def test_investigating_cannot_skip_to_remediation_pr_created(self):
        with self.assertRaises(ValueError):
            _at("Investigating").mark_remediation_pr_created()

    def test_root_cause_found_cannot_skip_to_remediation_pr_created(self):
        with self.assertRaises(ValueError):
            _at("RootCauseFound").mark_remediation_pr_created()

    def test_root_cause_found_cannot_revert_to_triage(self):
        with self.assertRaises(ValueError):
            _at("RootCauseFound").move_to_triage()

    def test_pr_created_cannot_revert_to_root_cause_found(self):
        with self.assertRaises(ValueError):
            _at("RemediationPRCreated").mark_root_cause_found()

    def test_root_cause_found_cannot_reopen_investigation_silently(self):
        with self.assertRaises(ValueError):
            _at("RootCauseFound").begin_investigation()

    # --- idempotent replays --------------------------------------------
    def test_replays_are_idempotent(self):
        incident = _at("Triage")
        incident.move_to_triage()
        incident.begin_investigation()
        incident.begin_investigation()
        incident.mark_root_cause_found()
        incident.mark_root_cause_found()
        incident.upsert_remediation_proposal(_proposal())
        incident.mark_remediation_pr_created()
        incident.mark_remediation_pr_created()
        self.assertEqual(incident.status, "RemediationPRCreated")

    # --- BLOCKED proposals never promote the incident -------------------
    def test_blocked_proposal_does_not_promote(self):
        incident = _at("RootCauseFound")
        blocked = _proposal(status="BLOCKED")
        incident.attach_blocked_proposal(blocked)
        self.assertEqual(incident.status, "RootCauseFound")
        self.assertEqual(incident.patch_proposals[0].status, "BLOCKED")


class ProposalRegenerationGuardTests(unittest.TestCase):
    """Phase 8 §4/§35: regeneration may refresh only BLOCKED/PROPOSED
    proposals — approved/executing/published records are immutable to it."""

    PROTECTED = ("APPROVED", "EXECUTING", "PR_CREATED", "EXECUTION_FAILED")

    def test_proposed_regeneration_replaces_same_id(self):
        incident = _at("RootCauseFound")
        incident.upsert_remediation_proposal(_proposal(status="PROPOSED"))
        refreshed = _proposal(status="PROPOSED", patch="--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-x\n+y\n")
        refreshed.proposal_hash = "e" * 64
        incident.upsert_remediation_proposal(refreshed)
        self.assertEqual(len(incident.patch_proposals), 1)
        self.assertEqual(incident.patch_proposals[0].proposal_hash, "e" * 64)
        self.assertEqual(incident.status, "RemediationProposed")

    def test_blocked_regeneration_to_proposed_is_allowed(self):
        incident = _at("RootCauseFound")
        incident.attach_blocked_proposal(_proposal(status="BLOCKED"))
        incident.upsert_remediation_proposal(_proposal(status="PROPOSED"))
        self.assertEqual(incident.patch_proposals[0].status, "PROPOSED")

    def test_protected_statuses_reject_upsert_reset(self):
        for status in self.PROTECTED:
            with self.subTest(status=status):
                incident = _at("RootCauseFound")
                incident.upsert_remediation_proposal(_proposal(status="PROPOSED"))
                current = incident.patch_proposals[0]
                current.status = status
                with self.assertRaises(ValueError):
                    incident.upsert_remediation_proposal(
                        _proposal(status="PROPOSED")
                    )
                # record untouched
                self.assertEqual(incident.patch_proposals[0].status, status)

    def test_protected_statuses_reject_blocked_overwrite(self):
        for status in self.PROTECTED:
            with self.subTest(status=status):
                incident = _at("RootCauseFound")
                incident.upsert_remediation_proposal(_proposal(status="PROPOSED"))
                incident.patch_proposals[0].status = status
                with self.assertRaises(ValueError):
                    incident.attach_blocked_proposal(
                        _proposal(status="BLOCKED")
                    )
                self.assertEqual(incident.patch_proposals[0].status, status)

    def test_unverified_proposal_still_rejected(self):
        with self.assertRaises(ValueError):
            _raised().upsert_remediation_proposal(
                _proposal(is_verified=False)
            )


if __name__ == "__main__":
    unittest.main()
