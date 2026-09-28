"""Phase 6.3 analytics summary over real HTTP (TestClient + real SQLite).

Covers what direct controller calls cannot: FastAPI query-parameter
parsing (missing/malformed datetimes → 422), window business rules
relayed as 422, route resolution (the two-segment analytics path must not
be captured by ``/{incident_id}``), and byte-level determinism for
identical requests. The repository provider is overridden with a fresh
temp-file SQLite adapter per test — the legitimate hermetic fixture.
"""

import os
import tempfile
import unittest
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.infrastructure.database.postgres_incident_repo import (
    PostgresIncidentRepositoryAdapter,
)
from incident_service.main import app as incident_app
from incident_service.presentation.rest import controllers as controllers_module

SUMMARY = "/incidents/analytics/summary"
WINDOW = "?start=2026-09-01T00:00:00Z&end=2026-09-08T00:00:00Z"


class AnalyticsSummaryHttpTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        url = f"sqlite:///{os.path.join(self._temp.name, 'http-analytics.db')}"
        self.repository = PostgresIncidentRepositoryAdapter(url)
        incident_app.dependency_overrides[
            controllers_module.get_incident_repository
        ] = lambda: self.repository
        self.client = TestClient(incident_app)

    def tearDown(self):
        incident_app.dependency_overrides.clear()
        self._temp.cleanup()

    def test_summary_route_resolves_and_is_not_shadowed_by_incident_id(self):
        resp = self.client.get(SUMMARY + WINDOW)
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        # /{incident_id} would 404 here if the analytics path were shadowed
        self.assertEqual(body["window"]["start"], "2026-09-01T00:00:00+00:00")
        self.assertEqual(body["window"]["end"], "2026-09-08T00:00:00+00:00")
        self.assertEqual(body["incidents"]["total"], 0)
        self.assertIn("data_quality", body)
        self.assertIn("unsupported", body)

    def test_missing_parameters_are_rejected_with_422(self):
        resp = self.client.get(SUMMARY)
        self.assertEqual(resp.status_code, 422)

    def test_malformed_datetime_is_rejected_with_422(self):
        resp = self.client.get(
            SUMMARY + "?start=not-a-date&end=2026-09-08T00:00:00Z"
        )
        self.assertEqual(resp.status_code, 422)

    def test_window_over_31_days_is_rejected_with_422(self):
        resp = self.client.get(
            SUMMARY + "?start=2026-08-01T00:00:00Z&end=2026-09-08T00:00:00Z"
        )
        self.assertEqual(resp.status_code, 422)
        self.assertIn("31 days", resp.json()["detail"])

    def test_inverted_window_is_rejected_with_422(self):
        resp = self.client.get(
            SUMMARY + "?start=2026-09-08T00:00:00Z&end=2026-09-01T00:00:00Z"
        )
        self.assertEqual(resp.status_code, 422)
        self.assertIn("strictly before end", resp.json()["detail"])

    def test_identical_requests_return_identical_json(self):
        first = self.client.get(SUMMARY + WINDOW)
        second = self.client.get(SUMMARY + WINDOW)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.content, second.content)

    def test_seeded_incident_round_trips_through_http(self):
        incident = IncidentAggregate(
            id="inc-http-analytics",
            title="[prometheus] queue depth",
            severity="HIGH",
            context_details="queue backlog",
        )
        incident.created_at = datetime(2026, 9, 2, 6, 0, tzinfo=timezone.utc)
        self.repository.save_incident(incident)

        resp = self.client.get(SUMMARY + WINDOW)
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertEqual(body["incidents"]["total"], 1)
        self.assertEqual(body["incidents"]["by_severity"], {"HIGH": 1})
        series = {
            point["date"]: point["count"]
            for point in body["incidents"]["timeseries"]
        }
        self.assertEqual(series["2026-09-02"], 1)
        self.assertEqual(series["2026-09-01"], 0)

        # boundary: window ending before the incident excludes it
        before = self.client.get(
            SUMMARY
            + "?start=2026-09-01T00:00:00Z&end=2026-09-02T06:00:00Z"
        )
        self.assertEqual(before.status_code, 200, before.text)
        self.assertEqual(before.json()["incidents"]["total"], 0)


if __name__ == "__main__":
    unittest.main()
