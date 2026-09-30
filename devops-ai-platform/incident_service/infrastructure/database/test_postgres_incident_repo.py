import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from sqlalchemy import event

from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.domain.entities.hotfix_proposal import HotfixProposal
from incident_service.domain.entities.incident_evidence import IncidentEvidence
from incident_service.infrastructure.database.postgres_incident_repo import PostgresIncidentRepositoryAdapter


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
            incident.attach_evidence(IncidentEvidence(
                id="evidence-1",
                kind="threshold_breach",
                source="monitoring-service",
                payload={"metric": "cpu_percent", "value": 95.0},
            ))
            repository.save_incident(incident)

            restored = repository.get_incident_by_id("incident-1")

            self.assertIsNotNone(restored)
            self.assertEqual(restored.title, incident.title)
            self.assertEqual(restored.severity, "CRITICAL")
            self.assertEqual(restored.status, "Triage")
            self.assertEqual(restored.context, incident.context)
            self.assertEqual(len(restored.evidence), 1)
            self.assertEqual(restored.evidence[0].id, "evidence-1")
            self.assertEqual(restored.evidence[0].payload["value"], 95.0)
            self.assertEqual(restored.created_at.tzinfo, timezone.utc)
            self.assertEqual(restored.domain_events, [])

            proposal = HotfixProposal(
                id="patch-1",
                target_filepath="app.py",
                diff_patch_payload="""--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-old()
+new()
""",
                source_sha="b" * 40,
            )
            proposal.apply_verification_pass()
            incident.attach_verified_patch(proposal)
            repository.save_incident(incident)

            updated = repository.get_incident_by_id("incident-1")

            self.assertEqual(updated.status, "RemediationVerified")
            self.assertEqual(len(updated.patch_proposals), 1)
            self.assertEqual(updated.patch_proposals[0].id, "patch-1")
            self.assertTrue(updated.patch_proposals[0].is_verified)
            self.assertEqual(updated.patch_proposals[0].source_sha, "b" * 40)

    def test_active_incidents_excludes_resolved_states(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = PostgresIncidentRepositoryAdapter(
                f"sqlite:///{os.path.join(temp_dir, 'incidents.db')}"
            )

            active = IncidentAggregate("active", "active", "HIGH", "details")
            active.move_to_triage()
            active.attach_evidence(IncidentEvidence(
                id="active-evidence",
                kind="threshold_breach",
                source="monitoring-service",
                payload={"metric": "latency_ms", "value": 1200.0},
            ))
            repository.save_incident(active)

            resolved = IncidentAggregate("resolved", "resolved", "HIGH", "details")
            resolved.status = "Resolved"
            repository.save_incident(resolved)

            fixed = IncidentAggregate("fixed", "fixed", "HIGH", "details")
            fixed.status = "Fixed"
            repository.save_incident(fixed)

            incidents = repository.get_active_incidents()

            self.assertEqual([item.id for item in incidents], ["active"])
            self.assertEqual(incidents[0].evidence[0].id, "active-evidence")
            self.assertEqual(incidents[0].evidence[0].payload["value"], 1200.0)


class WindowReadQueryBudgetTests(unittest.TestCase):
    """Phase 6.3 corrective: the analytics window read is 1+1 statements,
    never one execution-claims query per incident (N+1). Normal read
    semantics (overlay on get_incident_by_id) are proven unchanged."""

    _START = datetime(2026, 9, 1, tzinfo=timezone.utc)
    _END = datetime(2026, 9, 8, tzinfo=timezone.utc)

    def _seed_window_incidents(self, repository, count=3):
        for index in range(count):
            incident = IncidentAggregate(
                id=f"window-inc-{index}",
                title=f"[PROMETHEUS-ALERT] window-{index}",
                severity="HIGH",
                context_details="windowed cohort fixture",
            )
            incident.created_at = self._START + timedelta(hours=index + 1)
            proposal = HotfixProposal(
                id=f"window-patch-{index}",
                target_filepath="app.py",
                diff_patch_payload="--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old()\n+new()\n",
            )
            proposal.apply_verification_pass()
            incident.attach_verified_patch(proposal)
            repository.save_incident(incident)

    @staticmethod
    def _record_statements(repository):
        statements = []

        def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            statements.append(statement)

        event.listen(repository.engine, "before_cursor_execute", before_cursor_execute)
        return statements, before_cursor_execute

    def test_window_read_is_two_statements_not_per_incident(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = PostgresIncidentRepositoryAdapter(
                f"sqlite:///{os.path.join(temp_dir, 'window-budget.db')}"
            )
            self._seed_window_incidents(repository, count=3)

            statements, hook = self._record_statements(repository)
            try:
                incidents = repository.list_incidents_in_window(
                    self._START, self._END
                )
            finally:
                event.remove(
                    repository.engine, "before_cursor_execute", hook
                )

            self.assertEqual(len(incidents), 3)
            selects = [
                sql
                for sql in statements
                if sql.strip().upper().startswith("SELECT")
            ]
            # Exactly the incident query + one bulk evidence query — the
            # former per-incident execution_claims overlay is gone.
            self.assertLessEqual(len(selects), 2)
            self.assertFalse(
                any("execution_claims" in sql for sql in selects),
                selects,
            )

    def test_normal_read_still_applies_claim_overlay(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = PostgresIncidentRepositoryAdapter(
                f"sqlite:///{os.path.join(temp_dir, 'overlay-control.db')}"
            )
            self._seed_window_incidents(repository, count=1)

            statements, hook = self._record_statements(repository)
            try:
                restored = repository.get_incident_by_id("window-inc-0")
            finally:
                event.remove(
                    repository.engine, "before_cursor_execute", hook
                )

            self.assertIsNotNone(restored)
            self.assertTrue(
                any(
                    "execution_claims" in sql
                    for sql in statements
                    if sql.strip().upper().startswith("SELECT")
                ),
                "get_incident_by_id must keep its claim overlay",
            )


if __name__ == "__main__":
    unittest.main()
