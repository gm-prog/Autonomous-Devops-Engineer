"""Phase 6.3 analytics endpoint: controller contract tests.

Direct controller calls (the established presentation-test convention)
pin the typed window failure → HTTP 422 map, the success payload shape,
and route registration order for ``GET /incidents/analytics/summary``.
FastAPI-level parameter parsing (missing/malformed query strings → 422)
is covered over real HTTP in ``tests/test_analytics_summary_e2e.py``.
"""

import os
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException

from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.domain.entities.hotfix_proposal import HotfixProposal
from incident_service.infrastructure.database.postgres_incident_repo import (
    PostgresIncidentRepositoryAdapter,
)
from incident_service.presentation.rest.changes_controller import (
    get_change_health,
    get_change_live_health,
    get_change_release_gate,
    router as changes_router,
)
from incident_service.presentation.rest.controllers import (
    get_operational_analytics_summary,
    router,
)

# Phase 6.4 fixture: durable deployment-run evidence (genuine provenance).
from incident_service.presentation.rest.test_remediation_authorization import (
    _deployment_evidence,
)
from monitoring_service.infrastructure.prometheus.scraper_client import (
    PrometheusUnavailableError,
    RangeQueryResult,
    RangeSample,
    RangeSeries,
)

UTC = timezone.utc
W_START = datetime(2026, 9, 1, tzinfo=UTC)
W_END = datetime(2026, 9, 8, tzinfo=UTC)


class AnalyticsEndpointContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temp = tempfile.TemporaryDirectory()
        url = f"sqlite:///{os.path.join(cls._temp.name, 'endpoint.db')}"
        cls.repository = PostgresIncidentRepositoryAdapter(url)
        incident = IncidentAggregate(
            id="inc-analytics-1",
            title="[sentry] checkout latency",
            severity="CRITICAL",
            context_details="p99 latency spike",
        )
        incident.created_at = W_START + timedelta(hours=1)
        incident.status = "RootCauseFound"
        incident.patch_proposals.append(
            HotfixProposal(
                id="proposal-inc-analytics-1",
                target_filepath="app/checkout.py",
                diff_patch_payload="--- a/app/checkout.py\n+++ b/app/checkout.py\n",
                status="PROPOSED",
                generated_at=W_START + timedelta(hours=2),
            )
        )
        cls.repository.save_incident(incident)

    @classmethod
    def tearDownClass(cls):
        cls._temp.cleanup()

    def _summarize(self, start, end):
        return get_operational_analytics_summary(
            start=start, end=end, repository=self.repository
        )

    def test_success_returns_full_summary_shape(self):
        summary = self._summarize(W_START, W_END)
        self.assertEqual(summary["window"]["start"], W_START.isoformat())
        self.assertEqual(summary["window"]["end"], W_END.isoformat())
        self.assertEqual(summary["incidents"]["total"], 1)
        self.assertEqual(summary["incidents"]["by_severity"], {"CRITICAL": 1})
        self.assertEqual(summary["remediation"]["proposals_created"], 1)
        self.assertIn("data_quality", summary)
        self.assertIn("exclusions", summary["data_quality"])
        self.assertIn("unsupported", summary)

    def test_inverted_window_maps_to_http_422(self):
        with self.assertRaises(HTTPException) as ctx:
            self._summarize(W_END, W_START)
        self.assertEqual(ctx.exception.status_code, 422)
        self.assertIn("strictly before end", str(ctx.exception.detail))

    def test_window_over_31_days_maps_to_http_422(self):
        with self.assertRaises(HTTPException) as ctx:
            self._summarize(W_START, W_START + timedelta(days=31, seconds=1))
        self.assertEqual(ctx.exception.status_code, 422)
        self.assertIn("31 days", str(ctx.exception.detail))

    def test_equal_bounds_map_to_http_422(self):
        with self.assertRaises(HTTPException) as ctx:
            self._summarize(W_START, W_START)
        self.assertEqual(ctx.exception.status_code, 422)

    def test_route_is_registered_and_not_shadowed_by_incident_id(self):
        paths = [
            (route.path, route.methods)
            for route in router.routes
            if getattr(route, "path", "").endswith("/analytics/summary")
        ]
        self.assertTrue(paths, "analytics summary route must be registered")
        analytics_index = next(
            index
            for index, route in enumerate(router.routes)
            if getattr(route, "path", "").endswith("/analytics/summary")
        )
        incident_id_index = next(
            index
            for index, route in enumerate(router.routes)
            if getattr(route, "path", "").endswith("/{incident_id}")
        )
        self.assertLess(
            analytics_index,
            incident_id_index,
            "analytics route must be declared before the /{incident_id} catch-all",
        )


class ChangeHealthEndpointTests(unittest.TestCase):
    """Phase 6.4 controller contract: one typed, read-only health read."""

    @classmethod
    def setUpClass(cls):
        cls._temp = tempfile.TemporaryDirectory()
        url = f"sqlite:///{os.path.join(cls._temp.name, 'change-health.db')}"
        cls.repository = PostgresIncidentRepositoryAdapter(url)
        incident = IncidentAggregate(
            id="inc-change-health",
            title="[sentry] checkout 5xx",
            severity="HIGH",
            context_details="elevated error rate",
        )
        incident.created_at = W_START + timedelta(hours=1)
        incident.status = "Fixed"  # terminal → does not force DEGRADED
        incident.evidence.append(
            _deployment_evidence(
                run_id="run-health-1",
                evidence_id="deploy-change-health",
                kind_extra={"health_check_status": "PASS"},
            )
        )
        cls.repository.save_incident(incident)

    @classmethod
    def tearDownClass(cls):
        cls._temp.cleanup()

    def _assess(self, deployment_run_id="run-health-1", start=W_START, end=W_END):
        return get_change_health(
            deployment_run_id=deployment_run_id,
            start=start,
            end=end,
            repository=self.repository,
        )

    def test_success_returns_typed_assessment_shape(self):
        summary = self._assess()
        self.assertEqual(summary["deployment_run_id"], "run-health-1")
        self.assertEqual(
            summary["decision"], "HEALTHY"
        )  # carrier is terminal-status, all signals green
        self.assertIn(summary["decision"], {"HEALTHY", "DEGRADED", "FAILED", "INCONCLUSIVE"})
        self.assertEqual(summary["observation_window"]["start"], W_START.isoformat())
        self.assertIn("change_impact", summary)
        self.assertIn("signals", summary)
        self.assertIn("data_quality", summary)
        self.assertIn("exclusions", summary["data_quality"])
        self.assertIsInstance(summary["reasons"], list)

    def test_unknown_deployment_maps_to_http_404(self):
        with self.assertRaises(HTTPException) as ctx:
            self._assess(deployment_run_id="run-unknown")
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertIn("no deployment-run evidence", str(ctx.exception.detail))

    def test_inverted_window_maps_to_http_422(self):
        with self.assertRaises(HTTPException) as ctx:
            self._assess(start=W_END, end=W_START)
        self.assertEqual(ctx.exception.status_code, 422)

    def test_oversized_window_maps_to_http_422(self):
        with self.assertRaises(HTTPException) as ctx:
            self._assess(end=W_START + timedelta(days=31, seconds=1))
        self.assertEqual(ctx.exception.status_code, 422)
        self.assertIn("31 days", str(ctx.exception.detail))

    def test_read_endpoint_never_invokes_mutation_paths(self):
        from unittest.mock import patch

        with patch.object(
            self.repository,
            "save_incident",
            side_effect=AssertionError("health endpoint must be read-only"),
        ) as save:
            self._assess()
        save.assert_not_called()

    def test_response_carries_no_patch_or_credential_material(self):
        import json as _json

        text = _json.dumps(self._assess())
        self.assertNotIn("diff_patch_payload", text)
        self.assertNotIn("--- a/", text)
        self.assertNotIn("JWT", text)
        self.assertNotIn("authorization", text.lower())

    def test_health_route_registered(self):
        paths = [
            getattr(route, "path", "")
            for route in changes_router.routes
        ]
        self.assertTrue(
            any(path.endswith("/{deployment_run_id}/health") for path in paths),
            paths,
        )


class _FakeLivePrometheus:
    """Canned attributable telemetry for controller contract tests."""

    def __init__(self, error=None):
        self.error = error
        self.calls = []

    def query_range_metric(self, template_name, start, end):
        self.calls.append(template_name)
        if self.error is not None:
            raise self.error
        base_ts = W_START.timestamp() + 3600
        value = 10.0 if template_name == "request_rate" else 0.3
        return RangeQueryResult(
            template=template_name,
            query="q",
            start=W_START.timestamp(),
            end=W_END.timestamp(),
            step_seconds=60,
            series=(
                RangeSeries(
                    labels={"deployment_id": "run-live-1"},
                    samples=tuple(
                        RangeSample(timestamp=base_ts + i * 600, value=value)
                        for i in range(6)
                    ),
                ),
            ),
        )


class ChangeLiveHealthEndpointTests(unittest.TestCase):
    """Phase 6.5 controller contract: combined read model, fail-closed map."""

    @classmethod
    def setUpClass(cls):
        cls._temp = tempfile.TemporaryDirectory()
        url = f"sqlite:///{os.path.join(cls._temp.name, 'live-health.db')}"
        cls.repository = PostgresIncidentRepositoryAdapter(url)
        incident = IncidentAggregate(
            id="inc-live-1",
            title="[sentry] checkout 5xx",
            severity="HIGH",
            context_details="elevated error rate",
        )
        incident.created_at = W_START + timedelta(hours=1)
        incident.status = "Fixed"
        incident.evidence.append(
            _deployment_evidence(
                run_id="run-live-1",
                evidence_id="deploy-live-1",
                kind_extra={"health_check_status": "PASS"},
            )
        )
        cls.repository.save_incident(incident)

    @classmethod
    def tearDownClass(cls):
        cls._temp.cleanup()

    def _call(
        self,
        deployment_run_id="run-live-1",
        start=W_START,
        end=W_END,
        baseline_deployment_run_id=None,
        prometheus=None,
    ):
        return get_change_live_health(
            deployment_run_id=deployment_run_id,
            start=start,
            end=end,
            baseline_deployment_run_id=baseline_deployment_run_id,
            repository=self.repository,
            prometheus=prometheus or _FakeLivePrometheus(),
        )

    def test_success_returns_combined_read_model(self):
        body = self._call()
        self.assertIn("durable_assessment", body)
        self.assertIn("live_assessment", body)
        durable = body["durable_assessment"]
        live = body["live_assessment"]
        self.assertEqual(durable["deployment_run_id"], "run-live-1")
        self.assertEqual(durable["decision"], "HEALTHY")  # 6.4 semantics intact
        self.assertIn(
            live["decision"], {"HEALTHY", "DEGRADED", "FAILED", "INCONCLUSIVE"}
        )
        self.assertEqual(live["observation_window"], durable["observation_window"])
        self.assertEqual(
            live["release_identity"]["source_sha"],
            durable["change_impact"]["source_sha"],
        )
        self.assertEqual(len(live["slis"]), 2)
        self.assertIsNone(live["baseline_identity"])

    def test_unknown_deployment_maps_to_http_404(self):
        with self.assertRaises(HTTPException) as ctx:
            self._call(deployment_run_id="run-unknown")
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertIn("no deployment-run evidence", str(ctx.exception.detail))

    def test_inverted_window_maps_to_http_422(self):
        prometheus = _FakeLivePrometheus()
        with self.assertRaises(HTTPException) as ctx:
            self._call(start=W_END, end=W_START, prometheus=prometheus)
        self.assertEqual(ctx.exception.status_code, 422)
        self.assertEqual(prometheus.calls, [])

    def test_oversized_window_maps_to_http_422(self):
        with self.assertRaises(HTTPException) as ctx:
            self._call(end=W_START + timedelta(days=31, seconds=1))
        self.assertEqual(ctx.exception.status_code, 422)

    def test_unreachable_prometheus_still_returns_200_inconclusive(self):
        body = self._call(
            prometheus=_FakeLivePrometheus(
                error=PrometheusUnavailableError("refused")
            )
        )
        live = body["live_assessment"]
        self.assertEqual(live["decision"], "INCONCLUSIVE")
        self.assertEqual(live["reasons"], ["telemetry_unavailable"])

    def test_read_endpoint_never_invokes_mutation_paths(self):
        from unittest.mock import patch

        with patch.object(
            self.repository,
            "save_incident",
            side_effect=AssertionError("live-health must be read-only"),
        ) as save:
            self._call()
        save.assert_not_called()

    def test_response_carries_no_patch_or_credential_material(self):
        import json as _json

        text = _json.dumps(self._call())
        self.assertNotIn("diff_patch_payload", text)
        self.assertNotIn("--- a/", text)
        self.assertNotIn("authorization", text.lower())

    def test_live_health_route_registered(self):
        paths = [
            getattr(route, "path", "")
            for route in changes_router.routes
        ]
        self.assertTrue(
            any(path.endswith("/live-health") for path in paths),
            paths,
        )


class _FakeGateRepository:
    def __init__(self):
        self._incidents = []
        incident = IncidentAggregate(
            id="inc-gate-1",
            title="[release] gate",
            severity="HIGH",
            context_details="gate fixture",
        )
        incident.created_at = W_START + timedelta(hours=1)
        incident.status = "Fixed"
        incident.evidence.append(
            _deployment_evidence(
                run_id="run-gate-1",
                evidence_id="gate-evidence-1",
                kind_extra={"health_check_status": "PASS"},
            )
        )
        self._incidents.append(incident)

    def list_incidents_in_window(self, start, end):
        return list(self._incidents)

    def save_incident(self, *args, **kwargs):
        raise AssertionError("gate controller must be read-only")


class _FakeGatePrometheus:
    def __init__(self, error=None, cpu=0.30, request=10.0):
        self.error = error
        self.cpu = cpu
        self.request = request
        self.calls = []

    def query_range_metric(self, template_name, start, end):
        self.calls.append(template_name)
        if self.error is not None:
            raise self.error
        value = self.request if template_name == "request_rate" else self.cpu
        return RangeQueryResult(
            template=template_name,
            query="q",
            start=W_START.timestamp(),
            end=W_END.timestamp(),
            step_seconds=60,
            series=(
                RangeSeries(
                    labels={"deployment_id": "run-gate-1"},
                    samples=tuple(
                        RangeSample(
                            timestamp=W_START.timestamp() + 3600 + i * 600,
                            value=value,
                        )
                        for i in range(6)
                    ),
                ),
            ),
        )




class ChangeReleaseGateEndpointTests(unittest.TestCase):
    """Phase 6.6 controller contract: read-only gate evaluation."""

    def _repo(self):
        return _FakeGateRepository()

    def _call(self, percentage=5, baseline=None, prometheus=None):
        return get_change_release_gate(
            deployment_run_id="run-gate-1",
            start=W_START,
            end=W_END,
            target_percentage=percentage,
            baseline_deployment_run_id=baseline,
            repository=self._repo(),
            prometheus=prometheus or _FakeGatePrometheus(),
        )

    def test_healthy_gate_promotes(self):
        body = self._call()
        self.assertEqual(body["gate_decision"], "PROMOTE")
        self.assertEqual(body["target_percentage"], 5)

    def test_above_five_requires_baseline(self):
        with self.assertRaises(HTTPException) as ctx:
            self._call(percentage=25)
        self.assertEqual(ctx.exception.status_code, 422)
        self.assertIn("baseline", str(ctx.exception.detail))

    def test_invalid_percentage_maps_to_422(self):
        with self.assertRaises(HTTPException) as ctx:
            self._call(percentage=10)
        self.assertEqual(ctx.exception.status_code, 422)

    def test_route_is_registered(self):
        paths = [getattr(route, "path", "") for route in changes_router.routes]
        self.assertIn("/changes/{deployment_run_id}/gate", paths)

    def test_gate_is_read_only(self):
        repo = self._repo()
        with patch.object(
            repo, "save_incident",
            side_effect=AssertionError("gate must be read-only"),
        ) as save:
            body = get_change_release_gate(
                deployment_run_id="run-gate-1",
                start=W_START,
                end=W_END,
                target_percentage=5,
                repository=repo,
                prometheus=_FakeGatePrometheus(),
            )
        self.assertEqual(body["gate_decision"], "PROMOTE")
        save.assert_not_called()


if __name__ == "__main__":
    unittest.main()
