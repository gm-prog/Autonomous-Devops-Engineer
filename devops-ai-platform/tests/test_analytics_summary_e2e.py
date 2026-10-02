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
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.infrastructure.database.postgres_incident_repo import (
    PostgresIncidentRepositoryAdapter,
)
from incident_service.main import app as incident_app
from incident_service.application import dependencies as app_dependencies
from incident_service.presentation.rest import controllers as controllers_module
from monitoring_service.infrastructure.prometheus.scraper_client import (
    RangeQueryResult,
    RangeSample,
    RangeSeries,
)

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


class ChangeHealthHttpTests(unittest.TestCase):
    """Phase 6.4 health endpoint over real HTTP (TestClient + SQLite)."""

    HEALTH = "/changes/run-http/health"
    HEALTH_WINDOW = WINDOW  # same Phase 6.3 window contract

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        url = f"sqlite:///{os.path.join(self._temp.name, 'http-health.db')}"
        self.repository = PostgresIncidentRepositoryAdapter(url)
        incident_app.dependency_overrides[
            controllers_module.get_incident_repository
        ] = lambda: self.repository
        self.client = TestClient(incident_app)

    def tearDown(self):
        incident_app.dependency_overrides.clear()
        self._temp.cleanup()

    def _seed_carrier(self):
        from incident_service.presentation.rest.test_remediation_authorization import (
            _deployment_evidence,
        )

        incident = IncidentAggregate(
            id="inc-http-health",
            title="[sentry] 5xx on checkout",
            severity="CRITICAL",
            context_details="error budget burn",
        )
        incident.created_at = datetime(2026, 9, 2, 6, 0, tzinfo=timezone.utc)
        incident.status = "Fixed"
        incident.evidence.append(
            _deployment_evidence(
                run_id="run-http",
                evidence_id="deploy-http-health",
                kind_extra={"health_check_status": "PASS"},
            )
        )
        self.repository.save_incident(incident)

    def test_unknown_deployment_is_404(self):
        resp = self.client.get(self.HEALTH + self.HEALTH_WINDOW)
        self.assertEqual(resp.status_code, 404, resp.text)
        self.assertIn("no deployment-run evidence", resp.json()["detail"])

    def test_seeded_change_is_200_and_byte_deterministic(self):
        self._seed_carrier()
        first = self.client.get(self.HEALTH + self.HEALTH_WINDOW)
        second = self.client.get(self.HEALTH + self.HEALTH_WINDOW)
        self.assertEqual(first.status_code, 200, first.text)
        body = first.json()
        self.assertEqual(body["deployment_run_id"], "run-http")
        self.assertIn(
            body["decision"], {"HEALTHY", "DEGRADED", "FAILED", "INCONCLUSIVE"}
        )
        self.assertEqual(first.content, second.content)

    def test_missing_parameters_are_422(self):
        resp = self.client.get(self.HEALTH)
        self.assertEqual(resp.status_code, 422)

    def test_malformed_datetime_is_422(self):
        resp = self.client.get(
            self.HEALTH + "?start=nope&end=2026-09-08T00:00:00Z"
        )
        self.assertEqual(resp.status_code, 422)

    def test_oversized_window_is_422(self):
        resp = self.client.get(
            self.HEALTH + "?start=2026-08-01T00:00:00Z&end=2026-09-08T00:00:00Z"
        )
        self.assertEqual(resp.status_code, 422)
        self.assertIn("31 days", resp.json()["detail"])

    def test_inverted_window_is_422(self):
        resp = self.client.get(
            self.HEALTH + "?start=2026-09-08T00:00:00Z&end=2026-09-01T00:00:00Z"
        )
        self.assertEqual(resp.status_code, 422)


class _FakeLivePrometheus:
    """Deterministic attributable telemetry over real HTTP tests."""

    def __init__(self):
        self.calls = []

    def query_range_metric(self, template_name, start, end):
        self.calls.append(template_name)
        base_ts = datetime(2026, 9, 2, 6, 0, tzinfo=timezone.utc).timestamp()
        value = 100.0 if template_name == "request_rate" else 0.3
        return RangeQueryResult(
            template=template_name,
            query="q",
            start=start.timestamp(),
            end=end.timestamp(),
            step_seconds=60,
            series=tuple(
                RangeSeries(
                    labels={"deployment_id": run_id},
                    samples=tuple(
                        RangeSample(timestamp=base_ts + i * 600, value=value)
                        for i in range(6)
                    ),
                )
                for run_id in ("run-http", "run-base")
            ),
        )


class ChangeLiveHealthHttpTests(unittest.TestCase):
    """Phase 6.5 live-health over real HTTP (TestClient + SQLite + fake
    Prometheus boundary)."""

    LIVE = "/changes/run-http/live-health"
    LIVE_WINDOW = WINDOW

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        url = f"sqlite:///{os.path.join(self._temp.name, 'http-live.db')}"
        self.repository = PostgresIncidentRepositoryAdapter(url)
        incident_app.dependency_overrides[
            controllers_module.get_incident_repository
        ] = lambda: self.repository
        self.prometheus = _FakeLivePrometheus()
        incident_app.dependency_overrides[
            app_dependencies.get_live_prometheus_client
        ] = lambda: self.prometheus
        self.client = TestClient(incident_app)
        from incident_service.presentation.rest.test_remediation_authorization import (
            _deployment_evidence,
        )

        for run_id in ("run-http", "run-base"):
            incident = IncidentAggregate(
                id=f"inc-http-{run_id}",
                title="[sentry] 5xx on checkout",
                severity="CRITICAL",
                context_details="error budget burn",
            )
            incident.created_at = datetime(2026, 9, 2, 6, 0, tzinfo=timezone.utc)
            incident.status = "Fixed"
            incident.evidence.append(
                _deployment_evidence(
                    run_id=run_id,
                    evidence_id=f"deploy-{run_id}",
                    kind_extra={"health_check_status": "PASS"},
                )
            )
            self.repository.save_incident(incident)

    def tearDown(self):
        incident_app.dependency_overrides.clear()
        self._temp.cleanup()

    def test_seeded_change_is_200_and_byte_deterministic(self):
        first = self.client.get(self.LIVE + self.LIVE_WINDOW)
        second = self.client.get(self.LIVE + self.LIVE_WINDOW)
        self.assertEqual(first.status_code, 200, first.text)
        body = first.json()
        self.assertIn("durable_assessment", body)
        self.assertIn("live_assessment", body)
        live = body["live_assessment"]
        self.assertEqual(live["deployment_run_id"], "run-http")
        self.assertIn(
            live["decision"], {"HEALTHY", "DEGRADED", "FAILED", "INCONCLUSIVE"}
        )
        self.assertEqual(body["durable_assessment"]["decision"], "HEALTHY")
        self.assertEqual(first.content, second.content)

    def test_baseline_parameter_is_resolved_and_returned(self):
        resp = self.client.get(
            self.LIVE
            + self.LIVE_WINDOW
            + "&baseline_deployment_run_id=run-base"
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        live = resp.json()["live_assessment"]
        self.assertEqual(live["baseline_identity"]["deployment_run_id"], "run-base")
        self.assertEqual(live["decision"], "HEALTHY")

    def test_unknown_deployment_is_404(self):
        resp = self.client.get(
            "/changes/run-unknown/live-health" + self.LIVE_WINDOW
        )
        self.assertEqual(resp.status_code, 404, resp.text)
        self.assertIn("no deployment-run evidence", resp.json()["detail"])

    def test_missing_parameters_are_422(self):
        resp = self.client.get(self.LIVE)
        self.assertEqual(resp.status_code, 422)

    def test_malformed_datetime_is_422(self):
        resp = self.client.get(
            self.LIVE + "?start=nope&end=2026-09-08T00:00:00Z"
        )
        self.assertEqual(resp.status_code, 422)

    def test_oversized_window_is_422(self):
        resp = self.client.get(
            self.LIVE + "?start=2026-08-01T00:00:00Z&end=2026-09-08T00:00:00Z"
        )
        self.assertEqual(resp.status_code, 422)
        self.assertIn("31 days", resp.json()["detail"])

    def test_inverted_window_is_422(self):
        resp = self.client.get(
            self.LIVE + "?start=2026-09-08T00:00:00Z&end=2026-09-01T00:00:00Z"
        )
        self.assertEqual(resp.status_code, 422)


class RolloutStageHttpTests(unittest.TestCase):
    """Phase 6.6.2 rollout-state over real HTTP (TestClient + SQLite).

    Covers what direct handler calls cannot: FastAPI request-body
    parsing (missing/malformed fields → 422), full 404/409/200 relay
    through the real router, and that the transition endpoint mutates
    only durable rollout state.
    """

    SHA = "a" * 40
    RUN_ID = "run-rollout-e2e"
    STATE = "/changes/run-rollout-e2e/rollout-state"
    TRANSITION = "/changes/run-rollout-e2e/rollout-state/transition"

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        url = f"sqlite:///{os.path.join(self._temp.name, 'rollout-e2e.db')}"
        self.repository = PostgresIncidentRepositoryAdapter(url)
        incident_app.dependency_overrides[
            controllers_module.get_incident_repository
        ] = lambda: self.repository
        self.client = TestClient(incident_app)

        from incident_service.presentation.rest.test_remediation_authorization import (
            _deployment_evidence,
        )

        incident = IncidentAggregate(
            id="inc-rollout-e2e",
            title="[release] rollout e2e",
            severity="HIGH",
            context_details="rollout state http fixture",
        )
        incident.created_at = datetime(2026, 9, 1, tzinfo=timezone.utc) + timedelta(
            hours=1
        )
        incident.status = "Fixed"
        incident.evidence.append(
            _deployment_evidence(
                run_id=self.RUN_ID,
                evidence_id="rollout-e2e-evidence",
                head_sha=self.SHA,
                kind_extra={
                    "health_check_status": "PASS",
                    "source_sha": self.SHA,
                },
            )
        )
        self.repository.save_incident(incident)
        self.now = datetime.now(timezone.utc)
        self.addCleanup(incident_app.dependency_overrides.clear)
        self.addCleanup(self._temp.cleanup)

    def _evaluate(self, target=5, cpu=0.30):
        from incident_service.application.services.progressive_release_gate_service import (
            ProgressiveReleaseGateService,
        )

        run_id = self.RUN_ID
        start = datetime(2026, 9, 1, tzinfo=timezone.utc)
        end = datetime(2026, 9, 8, tzinfo=timezone.utc)

        class _Prom:
            def query_range_metric(inner, template_name, s, e):
                value = 10.0 if template_name == "request_rate" else cpu
                return RangeQueryResult(
                    template=template_name,
                    query="q",
                    start=start.timestamp(),
                    end=end.timestamp(),
                    step_seconds=60,
                    series=(
                        RangeSeries(
                            labels={"deployment_id": run_id},
                            samples=tuple(
                                RangeSample(
                                    timestamp=start.timestamp() + 3600 + i * 600,
                                    value=value,
                                )
                                for i in range(6)
                            ),
                        ),
                    ),
                )

        return ProgressiveReleaseGateService(
            self.repository,
            _Prom(),
            now_factory=lambda: self.now,
        ).evaluate(
            self.RUN_ID,
            start,
            end,
            target,
            baseline_deployment_run_id=(
                self.RUN_ID if target > 5 else None
            ),
        )

    def _bootstrap_over_http(self):
        evaluation = self._evaluate(5)
        resp = self.client.post(
            self.TRANSITION,
            json={
                "expected_percentage": 0,
                "target_percentage": 5,
                "evaluation_id": evaluation["evaluation_id"],
                "source_sha": evaluation["source_sha"],
            },
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        return evaluation

    def test_read_missing_state_is_404(self):
        resp = self.client.get(self.STATE)
        self.assertEqual(resp.status_code, 404)
        self.assertIn("rollout state not found", resp.json()["detail"])

    def test_malformed_bodies_are_422(self):
        malformed = [
            {},  # missing every field
            {"expected_percentage": "five", "target_percentage": 5,
             "evaluation_id": "e", "source_sha": self.SHA},
            {"expected_percentage": 0, "target_percentage": 5,
             "evaluation_id": "e"},  # missing source_sha
        ]
        for payload in malformed:
            with self.subTest(payload=sorted(payload)):
                resp = self.client.post(self.TRANSITION, json=payload)
                self.assertEqual(resp.status_code, 422, resp.text)

    def test_read_and_transition_over_http(self):
        self._bootstrap_over_http()
        read = self.client.get(self.STATE)
        self.assertEqual(read.status_code, 200, read.text)
        self.assertEqual(read.json()["current_percentage"], 5)
        self.assertEqual(read.json()["state"], "ACTIVE")

        evaluation = self._evaluate(25)
        promote = self.client.post(
            self.TRANSITION,
            json={
                "expected_percentage": 5,
                "target_percentage": 25,
                "evaluation_id": evaluation["evaluation_id"],
                "source_sha": evaluation["source_sha"],
            },
        )
        self.assertEqual(promote.status_code, 200, promote.text)
        self.assertEqual(promote.json()["current_percentage"], 25)
        self.assertEqual(
            self.client.get(self.STATE).json()["current_percentage"], 25
        )

    def test_illegal_transition_is_409_over_http(self):
        self._bootstrap_over_http()
        evaluation = self._evaluate(50)  # 5 → 50 is never a legal step
        resp = self.client.post(
            self.TRANSITION,
            json={
                "expected_percentage": 5,
                "target_percentage": 50,
                "evaluation_id": evaluation["evaluation_id"],
                "source_sha": evaluation["source_sha"],
            },
        )
        self.assertEqual(resp.status_code, 409, resp.text)
        # durable state untouched by the rejected request
        self.assertEqual(
            self.client.get(self.STATE).json()["current_percentage"], 5
        )

    def test_unknown_evaluation_is_404_over_http(self):
        self._bootstrap_over_http()
        resp = self.client.post(
            self.TRANSITION,
            json={
                "expected_percentage": 5,
                "target_percentage": 25,
                "evaluation_id": "missing-eval",
                "source_sha": self.SHA,
            },
        )
        self.assertEqual(resp.status_code, 404, resp.text)


if __name__ == "__main__":
    unittest.main()
