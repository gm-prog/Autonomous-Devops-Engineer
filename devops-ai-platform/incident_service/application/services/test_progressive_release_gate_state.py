"""Phase 6.6.1 durable progressive-release gate state tests."""

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from incident_service.application.services.progressive_release_gate_service import (
    GATE_EVALUATION_TTL_SECONDS,
    InvalidProgressiveReleaseGateRequest,
    ProgressiveReleaseGateService,
)
from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.infrastructure.database.postgres_incident_repo import (
    PostgresIncidentRepositoryAdapter,
)
from incident_service.presentation.rest.test_remediation_authorization import (
    _deployment_evidence,
)
from monitoring_service.infrastructure.prometheus.scraper_client import (
    RangeQueryResult,
    RangeSample,
    RangeSeries,
)

UTC = timezone.utc
START = datetime(2026, 9, 1, tzinfo=UTC)
END = datetime(2026, 9, 8, tzinfo=UTC)
SOURCE_SHA = "a" * 40


class FakePrometheus:
    def __init__(self, cpu=0.30, request=10.0):
        self.cpu = cpu
        self.request = request
        self.calls = []

    def query_range_metric(self, template_name, start, end):
        self.calls.append(template_name)
        value = self.request if template_name == "request_rate" else self.cpu
        return RangeQueryResult(
            template=template_name,
            query="fixed-test-query",
            start=start.timestamp(),
            end=end.timestamp(),
            step_seconds=60,
            series=(
                RangeSeries(
                    labels={"deployment_id": "run-gate-state"},
                    samples=tuple(
                        RangeSample(
                            timestamp=START.timestamp() + 3600 + i * 600,
                            value=value,
                        )
                        for i in range(6)
                    ),
                ),
            ),
        )


class DurableGateStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repository = PostgresIncidentRepositoryAdapter(
            f"sqlite:///{os.path.join(self.temp.name, 'gate.db')}"
        )
        incident = IncidentAggregate(
            id="inc-gate-state",
            title="[release] gate state",
            severity="HIGH",
            context_details="progressive gate fixture",
        )
        incident.created_at = START + timedelta(hours=1)
        incident.status = "Fixed"
        incident.evidence.append(
            _deployment_evidence(
                run_id="run-gate-state",
                evidence_id="gate-state-evidence",
                kind_extra={
                    "health_check_status": "PASS",
                    "source_sha": SOURCE_SHA,
                },
            )
        )
        self.repository.save_incident(incident)

    def _service(self, now, cpu=0.30):
        return ProgressiveReleaseGateService(
            self.repository,
            FakePrometheus(cpu=cpu),
            now_factory=lambda: now,
        )

    def test_round_trip_persists_authoritative_identity_and_decision(self):
        now = datetime(2026, 9, 8, 12, tzinfo=UTC)
        result = self._service(now).evaluate(
            "run-gate-state", START, END, 5
        )
        rows = self.repository.get_progressive_release_gate_evaluations(
            "run-gate-state"
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["evaluation_id"], result["evaluation_id"])
        self.assertEqual(rows[0]["source_sha"], SOURCE_SHA)
        self.assertEqual(rows[0]["gate_decision"], "PROMOTE")
        self.assertEqual(rows[0]["target_percentage"], 5)

    def test_identical_evaluation_is_idempotent_inside_ttl(self):
        first_now = datetime(2026, 9, 8, 12, tzinfo=UTC)
        second_now = first_now + timedelta(seconds=30)
        first = self._service(first_now).evaluate(
            "run-gate-state", START, END, 5
        )
        second = self._service(second_now).evaluate(
            "run-gate-state", START, END, 5
        )
        self.assertEqual(first["evaluation_id"], second["evaluation_id"])
        self.assertFalse(first["reused"])
        self.assertTrue(second["reused"])
        self.assertEqual(
            len(
                self.repository.get_progressive_release_gate_evaluations(
                    "run-gate-state"
                )
            ),
            1,
        )

    def test_new_freshness_slot_creates_new_analysis_record(self):
        now = datetime(2026, 9, 8, 12, tzinfo=UTC)
        first = self._service(now).evaluate(
            "run-gate-state", START, END, 5
        )
        second = self._service(
            now + timedelta(seconds=GATE_EVALUATION_TTL_SECONDS)
        ).evaluate("run-gate-state", START, END, 5)
        self.assertNotEqual(first["evaluation_id"], second["evaluation_id"])
        self.assertEqual(
            len(
                self.repository.get_progressive_release_gate_evaluations(
                    "run-gate-state"
                )
            ),
            2,
        )

    def test_history_marks_expired_state_and_does_not_authorize_anything(self):
        now = datetime(2026, 9, 8, 12, tzinfo=UTC)
        self._service(now).evaluate("run-gate-state", START, END, 5)
        history = self._service(
            now + timedelta(seconds=GATE_EVALUATION_TTL_SECONDS + 1)
        ).history("run-gate-state")
        self.assertEqual(history["count"], 1)
        self.assertFalse(history["evaluations"][0]["fresh"])
        self.assertEqual(history["evaluations"][0]["gate_decision"], "PROMOTE")

    def test_failed_health_maps_to_abort_and_remains_read_only(self):
        now = datetime(2026, 9, 8, 12, tzinfo=UTC)
        before = self.repository.get_incident_by_id("inc-gate-state").to_dict()
        result = self._service(now, cpu=0.95).evaluate(
            "run-gate-state", START, END, 5
        )
        after = self.repository.get_incident_by_id("inc-gate-state").to_dict()
        self.assertEqual(result["health_decision"], "FAILED")
        self.assertEqual(result["gate_decision"], "ABORT")
        self.assertEqual(before, after)

    def test_exposure_above_five_requires_explicit_baseline(self):
        now = datetime(2026, 9, 8, 12, tzinfo=UTC)
        with self.assertRaises(InvalidProgressiveReleaseGateRequest):
            self._service(now).evaluate("run-gate-state", START, END, 25)

    def test_invalid_limit_is_rejected(self):
        with self.assertRaises(InvalidProgressiveReleaseGateRequest):
            self._service(datetime(2026, 9, 8, tzinfo=UTC)).history(
                "run-gate-state", limit=0
            )

    def test_repository_rejects_identity_conflict_for_same_evaluation_id(self):
        now = datetime(2026, 9, 8, 12, tzinfo=UTC)
        result = self._service(now).evaluate(
            "run-gate-state", START, END, 5
        )
        row = self.repository.get_progressive_release_gate_evaluations(
            "run-gate-state"
        )[0]
        row["gate_decision"] = "ABORT"
        with self.assertRaises(ValueError):
            self.repository.save_progressive_release_gate_evaluation(row)
        self.assertEqual(
            self.repository.get_progressive_release_gate_evaluations(
                "run-gate-state"
            )[0]["gate_decision"],
            result["gate_decision"],
        )


if __name__ == "__main__":
    unittest.main()
