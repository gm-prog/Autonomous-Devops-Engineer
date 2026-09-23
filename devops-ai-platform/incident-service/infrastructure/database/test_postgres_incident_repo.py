import os
import tempfile
import unittest
from datetime import timezone

from domain.aggregates.incident import IncidentAggregate
from domain.entities.hotfix_proposal import HotfixProposal
from infrastructure.database.postgres_incident_repo import PostgresIncidentRepositoryAdapter


class PostgresIncidentRepositoryAdapterTests(unittest.TestCase):
    def test_round_trip_and_update(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_url = f"sqlite:///{os.path.join(temp_dir, 'incidents.db')}"
            repository = PostgresIncidentRepositoryAdapter(database_url)

            incident = IncidentAggregate(
                id="incident-1",
                title="[PROMETHEUS-ALERT] cpu_percent-threshold-breached",
                severity="CRITICAL",
                context_details="Service=gateway; metric=cpu_percent; value=95.0",
            )
            incident.move_to_triage()
            repository.save_incident(incident)

            restored = repository.get_incident_by_id("incident-1")

            self.assertIsNotNone(restored)
            self.assertEqual(restored.title, incident.title)
            self.assertEqual(restored.severity, "CRITICAL")
            self.assertEqual(restored.status, "Triage")
            self.assertEqual(restored.context, incident.context)
            self.assertEqual(restored.created_at.tzinfo, timezone.utc)
            self.assertEqual(restored.domain_events, [])

            proposal = HotfixProposal(
                id="patch-1",
                target_filepath="app.py",
                diff_patch_payload="@@ -1 +1 @@",
            )
            proposal.apply_verification_pass()
            incident.attach_verified_patch(proposal)
            repository.save_incident(incident)

            updated = repository.get_incident_by_id("incident-1")

            self.assertEqual(updated.status, "RemediationVerified")
            self.assertEqual(len(updated.patch_proposals), 1)
            self.assertEqual(updated.patch_proposals[0].id, "patch-1")
            self.assertTrue(updated.patch_proposals[0].is_verified)

    def test_active_incidents_excludes_resolved_states(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = PostgresIncidentRepositoryAdapter(
                f"sqlite:///{os.path.join(temp_dir, 'incidents.db')}"
            )

            active = IncidentAggregate("active", "active", "HIGH", "details")
            active.move_to_triage()
            repository.save_incident(active)

            resolved = IncidentAggregate("resolved", "resolved", "HIGH", "details")
            resolved.status = "Resolved"
            repository.save_incident(resolved)

            fixed = IncidentAggregate("fixed", "fixed", "HIGH", "details")
            fixed.status = "Fixed"
            repository.save_incident(fixed)

            incidents = repository.get_active_incidents()

            self.assertEqual([item.id for item in incidents], ["active"])


if __name__ == "__main__":
    unittest.main()
