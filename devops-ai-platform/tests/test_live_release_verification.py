"""Phase 6.5 — bounded Prometheus range query + live release verification.

Covers: template-only bounded range queries (timeout/HTTP/window/sample
caps, malformed/unsupported responses, instant-query preservation),
exact release attribution (deployment_id / source_sha only — never
timestamps), the deterministic SLI rules, baseline comparison, the
fixed data-quality vocabulary, exact [start,end) sample semantics, the
fixed query budget (no N+1), and read-only behavior. The Prometheus
boundary is mocked throughout; no live Prometheus server is required.
"""

import json
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from incident_service.application.services.live_release_verification_service import (
    LiveReleaseVerificationService,
)
from incident_service.application.services.operational_analytics_service import (
    InvalidAnalyticsWindowError,
)
from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.presentation.rest.test_remediation_authorization import (
    OTHER_SHA,
    SOURCE_SHA,
    _deployment_evidence,
)
from monitoring_service.infrastructure.prometheus import scraper_client as scraper_module
from monitoring_service.infrastructure.prometheus.scraper_client import (
    MAX_RANGE_DAYS,
    QUERY_TIMEOUT_SECONDS,
    PrometheusMalformedResponseError,
    PrometheusQueryError,
    PrometheusScraperClient,
    PrometheusUnsupportedError,
    PrometheusUnavailableError,
    RangeQueryResult,
    RangeSample,
    RangeSeries,
)

W_START = datetime(2026, 9, 1, tzinfo=timezone.utc)
W_END = datetime(2026, 9, 8, tzinfo=timezone.utc)
IN_WINDOW_UNIX = [W_START.timestamp() + 3600 + i * 600 for i in range(6)]


class FakeRepository:
    """In-memory stand-in whose mutation entry points hard-fail."""

    def __init__(self, incidents=None):
        self.incidents = list(incidents or [])

    def list_incidents_in_window(self, start, end):
        return list(self.incidents)

    def save_incident(self, *args, **kwargs):
        raise AssertionError("live verification must be read-only")


def _carrier(run_id, evidence_id, status="Fixed"):
    incident = IncidentAggregate(
        id=f"inc-{run_id}", title="[sentry] live check", severity="HIGH",
        context_details="live verification fixture",
    )
    incident.created_at = W_START + timedelta(hours=6)
    incident.status = status
    incident.evidence.append(
        _deployment_evidence(
            run_id=run_id,
            evidence_id=evidence_id,
            kind_extra={"health_check_status": "PASS"},
        )
    )
    return incident


def _result(name, labeled_series):
    """Typed RangeQueryResult: [(labels, values...), ...] over IN_WINDOW_UNIX."""
    return RangeQueryResult(
        template=name,
        query="q",
        start=W_START.timestamp(),
        end=W_END.timestamp(),
        step_seconds=60,
        series=tuple(
            RangeSeries(
                labels=dict(labels),
                samples=tuple(
                    RangeSample(timestamp=ts, value=value)
                    for ts, value in zip(IN_WINDOW_UNIX, values)
                ),
            )
            for labels, values in labeled_series
        ),
    )


class FakePrometheus:
    """Canned bounded range queries; records every call (query budget)."""

    def __init__(self, cpu=0.3, request=10.0, error=None):
        self.cpu = cpu
        self.request = request
        self.error = error
        self.calls = []

    def query_range_metric(self, template_name, start, end):
        self.calls.append(template_name)
        if self.error is not None:
            raise self.error
        if template_name == "request_rate":
            return _result(
                template_name,
                [({"job": "api-gateway", "deployment_id": "run-live",
                   "source_sha": SOURCE_SHA}, [self.request] * 6)],
            )
        return _result(
            template_name,
            [({"job": "api-gateway", "source_sha": SOURCE_SHA}, [self.cpu] * 6)],
        )


def _verify(repository, prometheus, **kwargs):
    service = LiveReleaseVerificationService(repository, prometheus)
    return service.verify(
        deployment_run_id=kwargs.pop("deployment_run_id", "run-live"),
        start=kwargs.pop("start", W_START),
        end=kwargs.pop("end", W_END),
        **kwargs,
    )


# --------------------------------------------------------------------------- #
# Deliverable A — bounded Prometheus range query
# --------------------------------------------------------------------------- #

_AUTO = object()


class _FakeHTTPResponse:
    """http.client.HTTPResponse stand-in with honest read semantics.

    ``read()`` without an explicit amount raises AssertionError, so any
    unbounded ``response.read()`` on the range-query path fails every
    test that uses this fake. Optional ``producer(amt)`` simulates an
    endless chunked stream without allocating the data up front.
    """

    def __init__(self, body=b"", status=200, content_length=_AUTO, producer=None):
        self.status = status
        self._body = body
        self._pos = 0
        self._producer = producer
        self.reads = []  # amt per call; None never occurs (guard above)
        self.bytes_returned = 0
        if content_length is _AUTO:
            content_length = len(body)
        self._content_length = (
            None if content_length is None else str(content_length)
        )

    def getheader(self, name, default=None):
        if name == "Content-Length":
            return self._content_length
        return default

    def read(self, amt=None):
        if amt is None:
            raise AssertionError("unbounded response.read() on range path")
        self.reads.append(amt)
        if self._producer is not None:
            chunk = self._producer(amt)
        else:
            chunk = self._body[self._pos : self._pos + amt]
            self._pos += len(chunk)
        self.bytes_returned += len(chunk)
        return chunk


@contextmanager
def _fake_http(response):
    """Patch HTTPConnection.getresponse() to yield ``response``."""
    connection_patch = patch.object(
        scraper_module.http.client, "HTTPConnection"
    )
    connection_cls = connection_patch.start()
    try:
        connection_cls.return_value.getresponse.return_value = response
        yield connection_cls, response
    finally:
        connection_patch.stop()


class BoundedRangeQueryTests(unittest.TestCase):
    def _client(self):
        return PrometheusScraperClient()  # default endpoint prometheus:9090

    @staticmethod
    def _matrix_body(values=None, result_type="matrix", status="success",
                     metric=None, result=None):
        payload = {
            "status": status,
            "data": {
                "resultType": result_type,
                "result": result if result is not None else [
                    {
                        "metric": metric if metric is not None else
                        {"job": "api-gateway", "deployment_id": "run-live"},
                        "values": values if values is not None else
                        [[1788224400, "12.5"], [1788225000, "13.0"]],
                    }
                ],
            },
        }
        return json.dumps(payload).encode("utf-8")

    def test_range_query_is_template_only_bounded_and_read_only(self):
        body = self._matrix_body()
        with _fake_http(_FakeHTTPResponse(body)) as (connection_cls, response):
            result = self._client().query_range_metric("request_rate", W_START, W_END)

            connection_cls.assert_called_once_with(
                "prometheus", 9090, timeout=QUERY_TIMEOUT_SECONDS
            )
            method, path = connection_cls.return_value.request.call_args[0]
            self.assertEqual(method, "GET")
            self.assertIn("/api/v1/query_range?", path)
            # exact predefined template, URL-encoded — no user PromQL
            from urllib.parse import quote_plus
            expected = scraper_module._RANGE_TEMPLATES["request_rate"]
            self.assertIn(f"query={quote_plus(expected)}", path)
            self.assertIn(f"end={W_END.timestamp():.3f}", path)
            connection_cls.return_value.close.assert_called()
            # body consumed only through bounded, explicitly-sized reads
            self.assertTrue(response.reads)
            self.assertNotIn(None, response.reads)

        self.assertIsInstance(result, RangeQueryResult)
        self.assertEqual(result.template, "request_rate")
        self.assertEqual(result.step_seconds % 60, 0)
        self.assertGreaterEqual(result.step_seconds, 60)
        span = W_END.timestamp() - W_START.timestamp()
        self.assertLessEqual(
            (span / result.step_seconds) + 1, scraper_module.MAX_RANGE_POINTS + 1
        )
        self.assertIsInstance(result.series[0].samples[0], RangeSample)
        self.assertEqual(result.series[0].samples[0].value, 12.5)

    def test_unknown_template_is_rejected_without_any_http(self):
        with patch.object(scraper_module.http.client, "HTTPConnection") as conn:
            with self.assertRaises(PrometheusUnsupportedError):
                self._client().query_range_metric(
                    "arbitrary_promql", W_START, W_END
                )
            conn.assert_not_called()

    # ---- Phase 6.5.1 identity-carrier join ---- #

    def test_template_catalog_names_remain_the_supported_set(self):
        self.assertEqual(
            PrometheusScraperClient.template_names(),
            ("request_rate", "cpu_saturation"),
        )

    def test_templates_join_identity_carrier_on_scrape_target(self):
        expectations = {
            "request_rate": "rate(devops_api_requests_total[5m])",
            "cpu_saturation": "rate(process_cpu_seconds_total[2m])",
        }
        for name, logical_query in expectations.items():
            with self.subTest(template=name):
                expr = scraper_module._RANGE_TEMPLATES[name]
                # logical SLI query preserved verbatim inside the template
                self.assertIn(logical_query, expr)
                # join to the low-volume carrier on the verified target keys
                self.assertIn("devops_release_identity_info", expr)
                self.assertIn("* on(job, instance)", expr)
                self.assertIn("group_left(deployment_id, source_sha)", expr)

    def test_template_by_clause_propagates_only_authoritative_identity(self):
        for name, aggregate in (("request_rate", "sum"), ("cpu_saturation", "avg")):
            with self.subTest(template=name):
                expr = scraper_module._RANGE_TEMPLATES[name]
                prefix = f"{aggregate} by ("
                self.assertTrue(expr.startswith(prefix), expr)
                by_clause = expr[len(prefix) : expr.index(")")]
                keys = [key.strip() for key in by_clause.split(",")]
                self.assertEqual(
                    keys,
                    ["job", "instance", "deployment_id", "source_sha"],
                )
                # only the two authoritative identity labels propagate
                self.assertEqual(
                    {"deployment_id", "source_sha"},
                    set(keys) & {"deployment_id", "source_sha"},
                )
                # nothing user-supplied or high-cardinality joins in
                for forbidden in (
                    "path=",
                    "method=",
                    "incident",
                    "user",
                    "pr_",
                    "timestamp",
                ):
                    self.assertNotIn(forbidden, by_clause)

    def test_window_bound_is_enforced_without_any_http(self):
        with patch.object(scraper_module.http.client, "HTTPConnection") as conn:
            with self.assertRaises(PrometheusQueryError):
                self._client().query_range_metric(
                    "request_rate", W_START, W_END + timedelta(days=MAX_RANGE_DAYS + 1)
                )
            with self.assertRaises(PrometheusQueryError):
                self._client().query_range_metric(
                    "request_rate", W_END, W_START  # inverted
                )
            conn.assert_not_called()

    def test_connection_error_times_out_fail_closed(self):
        with patch.object(scraper_module.http.client, "HTTPConnection") as conn:
            conn.return_value.request.side_effect = OSError("connection refused")
            with self.assertRaises(PrometheusUnavailableError):
                self._client().query_range_metric("request_rate", W_START, W_END)

    def test_non_200_response_fails_closed(self):
        with _fake_http(_FakeHTTPResponse(b"", status=503)):
            with self.assertRaises(PrometheusUnavailableError):
                self._client().query_range_metric("request_rate", W_START, W_END)

    def test_malformed_json_fails_closed(self):
        with _fake_http(_FakeHTTPResponse(b"not-json")):
            with self.assertRaises(PrometheusMalformedResponseError):
                self._client().query_range_metric("request_rate", W_START, W_END)

    def test_error_envelope_and_bad_shapes_fail_closed(self):
        bodies = [
            self._matrix_body(status="error"),
            self._matrix_body(result="not-a-list"),
            self._matrix_body(result=[{"metric": [], "values": []}]),
            self._matrix_body(result=[{"metric": {}, "values": ["x"]}]),
            self._matrix_body(result=[{"metric": {}, "values": [[1, "NaN"]]}]),
        ]
        for body in bodies:
            with self.subTest(body=body[:60]):
                with _fake_http(_FakeHTTPResponse(body)):
                    with self.assertRaises(PrometheusMalformedResponseError):
                        self._client().query_range_metric(
                            "request_rate", W_START, W_END
                        )

    def test_unsupported_result_type_fails_closed(self):
        with _fake_http(
            _FakeHTTPResponse(self._matrix_body(result_type="vector"))
        ):
            with self.assertRaises(PrometheusUnsupportedError):
                self._client().query_range_metric("request_rate", W_START, W_END)

    def test_sample_count_cap_fails_closed(self):
        values = [[1788224400 + i, str(i)] for i in range(10)]
        with patch.object(scraper_module, "MAX_RESPONSE_SAMPLES", 5):
            with _fake_http(_FakeHTTPResponse(self._matrix_body(values=values))):
                with self.assertRaises(PrometheusMalformedResponseError):
                    self._client().query_range_metric("request_rate", W_START, W_END)

    def test_instant_query_behavior_is_unchanged(self):
        canned = self._client().query_instant_metric("up")
        self.assertEqual(canned["status"], "success")
        self.assertEqual(canned["data"]["resultType"], "vector")
        self.assertEqual(
            canned["data"]["result"][0]["metric"]["__name__"], "http_requests_total"
        )
        with patch.object(scraper_module.http.client, "HTTPConnection") as conn:
            self._client().query_instant_metric("up")
            conn.assert_not_called()

    def test_step_computation_is_deterministic_and_bounded(self):
        first = PrometheusScraperClient.compute_step_seconds(W_START, W_END)
        second = PrometheusScraperClient.compute_step_seconds(W_START, W_END)
        self.assertEqual(first, second)
        self.assertGreaterEqual(first, 60)
        self.assertEqual(first % 60, 0)
        longer = PrometheusScraperClient.compute_step_seconds(
            W_START, W_END + timedelta(days=20)
        )
        self.assertGreater(longer, first)

    # ---- Response-body byte bound (corrective hardening) ---- #

    def test_a_oversized_content_length_fails_before_any_body_read(self):
        body = self._matrix_body()  # contains distinctive 'api-gateway'
        response = _FakeHTTPResponse(
            body,
            content_length=str(scraper_module.MAX_RESPONSE_BYTES + 1),
        )
        with _fake_http(response):
            with patch.object(
                scraper_module.json, "loads",
                side_effect=AssertionError("JSON parser invoked"),
            ):
                with self.assertRaises(PrometheusMalformedResponseError) as ctx:
                    self._client().query_range_metric(
                        "request_rate", W_START, W_END
                    )
        self.assertEqual(response.reads, [])  # body never consumed
        self.assertEqual(
            str(ctx.exception),
            "Prometheus response exceeds configured byte limit",
        )
        message = str(ctx.exception)
        self.assertNotIn("api-gateway", message)  # no body/headers echoed
        self.assertNotIn(str(scraper_module.MAX_RESPONSE_BYTES + 1), message)

    def test_b_content_length_exactly_at_byte_limit_is_accepted(self):
        target = 2048
        payload = json.loads(self._matrix_body())
        base = json.dumps(payload, separators=(",", ":"))
        overhead = len(json.dumps({"pad": ""}, separators=(",", ":"))) - 1
        pad_len = target - len(base) - overhead
        self.assertGreater(pad_len, 0)
        payload["pad"] = "x" * pad_len
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.assertEqual(len(body), target)  # declared CL == limit exactly

        with patch.object(scraper_module, "MAX_RESPONSE_BYTES", target):
            with _fake_http(_FakeHTTPResponse(body)) as (conn, response):
                result = self._client().query_range_metric(
                    "request_rate", W_START, W_END
                )
        self.assertIsInstance(result, RangeQueryResult)
        self.assertEqual(response.bytes_returned, target)
        self.assertTrue(response.reads)
        self.assertNotIn(None, response.reads)

    def test_c_unknown_length_overflow_fails_at_the_byte_budget(self):
        target = 4096
        body = b"x" * (target + 100)  # would-be payload, never parsed
        with patch.object(scraper_module, "MAX_RESPONSE_BYTES", target):
            with _fake_http(
                _FakeHTTPResponse(body, content_length=None)
            ) as (conn, response):
                with patch.object(
                    scraper_module.json, "loads",
                    side_effect=AssertionError("JSON parser invoked"),
                ):
                    with self.assertRaises(PrometheusMalformedResponseError) as ctx:
                        self._client().query_range_metric(
                            "request_rate", W_START, W_END
                        )
        self.assertIn("byte limit", str(ctx.exception))
        # incremental, explicitly-sized reads only; stopped at budget + 1 probe
        self.assertTrue(response.reads)
        self.assertNotIn(None, response.reads)
        self.assertEqual(
            response.bytes_returned, target + 1
        )

    def test_d_unknown_length_valid_body_succeeds(self):
        with _fake_http(
            _FakeHTTPResponse(self._matrix_body(), content_length=None)
        ) as (conn, response):
            result = self._client().query_range_metric(
                "request_rate", W_START, W_END
            )
        self.assertIsInstance(result, RangeQueryResult)
        self.assertTrue(response.reads)
        self.assertNotIn(None, response.reads)

    def test_e_unknown_length_one_byte_over_limit_fails_deterministically(self):
        target = 4096
        body = b"[" * (target + 1)
        with patch.object(scraper_module, "MAX_RESPONSE_BYTES", target):
            with _fake_http(
                _FakeHTTPResponse(body, content_length=None)
            ) as (conn, response):
                with self.assertRaises(PrometheusMalformedResponseError) as ctx:
                    self._client().query_range_metric(
                        "request_rate", W_START, W_END
                    )
        self.assertIn("byte limit", str(ctx.exception))
        self.assertEqual(response.bytes_returned, target + 1)

    def test_f_sample_limit_still_enforces_under_byte_limit(self):
        # 10,001 real samples: serialized well under the 4 MiB byte bound,
        # so the logical MAX_RESPONSE_SAMPLES guard must still reject it.
        values = [
            [1788224400 + i, "1"] for i in range(scraper_module.MAX_RESPONSE_SAMPLES + 1)
        ]
        body = self._matrix_body(values=values)
        self.assertLess(len(body), scraper_module.MAX_RESPONSE_BYTES)
        with _fake_http(_FakeHTTPResponse(body)):
            with self.assertRaises(PrometheusMalformedResponseError) as ctx:
                self._client().query_range_metric("request_rate", W_START, W_END)
        self.assertIn("samples", str(ctx.exception))
        self.assertNotIn("byte limit", str(ctx.exception))

    def test_untrusted_content_length_fails_closed(self):
        for bad in ("not-a-number", "", "-5", "12_000", "4194304.5"):
            with self.subTest(header=bad):
                with _fake_http(
                    _FakeHTTPResponse(b"{}", content_length=bad)
                ) as (conn, response):
                    with self.assertRaises(PrometheusMalformedResponseError) as ctx:
                        self._client().query_range_metric(
                            "request_rate", W_START, W_END
                        )
                self.assertIn("untrusted Content-Length", str(ctx.exception))
                self.assertEqual(response.reads, [])  # refused pre-read

    def test_j_streaming_overflow_stops_at_budget_without_giant_allocation(self):
        target = 64 * 1024  # small but > _CHUNK_BYTES exercises multi-read loop

        def endless(amt):  # synthetic infinite stream, no bulk allocation
            return b"x" * amt

        with patch.object(scraper_module, "MAX_RESPONSE_BYTES", target):
            with _fake_http(
                _FakeHTTPResponse(content_length=None, producer=endless)
            ) as (conn, response):
                with self.assertRaises(PrometheusMalformedResponseError) as ctx:
                    self._client().query_range_metric(
                        "request_rate", W_START, W_END
                    )
        self.assertIn("byte limit", str(ctx.exception))
        # reader stopped exactly at budget + minimal probe, after a small,
        # bounded number of explicitly-sized reads
        self.assertEqual(response.bytes_returned, target + 1)
        self.assertLessEqual(len(response.reads), 8)
        self.assertNotIn(None, response.reads)


# --------------------------------------------------------------------------- #
# Deliverable B — exact release attribution
# --------------------------------------------------------------------------- #

class LiveAttributionTests(unittest.TestCase):
    def setUp(self):
        self.repository = FakeRepository([_carrier("run-live", "d1")])

    def test_exact_deployment_id_attributes(self):
        prometheus = FakePrometheus(cpu=0.3)
        out = _verify(self.repository, prometheus)
        self.assertEqual(out["live_assessment"]["decision"], "HEALTHY")

    def test_exact_source_sha_attributes(self):
        # cpu series carries only source_sha — still attributable
        prometheus = FakePrometheus(cpu=0.3)
        out = _verify(self.repository, prometheus)
        identity = out["live_assessment"]["release_identity"]
        self.assertEqual(identity["source_sha"], SOURCE_SHA)
        self.assertEqual(identity["deployment_run_id"], "run-live")
        self.assertEqual(out["live_assessment"]["decision"], "HEALTHY")

    def test_wrong_sha_and_wrong_run_never_attribute(self):
        class WrongIdentity(FakePrometheus):
            def query_range_metric(self, template_name, start, end):
                self.calls.append(template_name)
                return _result(
                    template_name,
                    [({"deployment_id": "run-other", "source_sha": OTHER_SHA},
                      [0.3] * 6)],
                )

        out = _verify(self.repository, WrongIdentity())
        live = out["live_assessment"]
        self.assertEqual(live["decision"], "INCONCLUSIVE")
        self.assertIn("attribution_unavailable", live["reasons"])
        self.assertIsNone(live["slis"][1]["value"])

    def test_timestamp_only_overlap_never_attributes(self):
        class TimeOnly(FakePrometheus):
            def query_range_metric(self, template_name, start, end):
                self.calls.append(template_name)
                return _result(
                    template_name, [({"job": "api-gateway"}, [0.3] * 6)]
                )

        out = _verify(self.repository, TimeOnly())
        live = out["live_assessment"]
        self.assertEqual(live["decision"], "INCONCLUSIVE")
        self.assertEqual(live["reasons"], ["attribution_unavailable"])
        self.assertEqual(
            live["release_identity"]["deployment_run_id"], "run-live"
        )

    def test_join_output_series_shape_attributes_both_slis(self):
        # Exact label shape produced by the Phase 6.5.1 carrier join:
        # (job, instance) target keys + propagated deployment_id/source_sha.
        class JoinedShape(FakePrometheus):
            def query_range_metric(self, template_name, start, end):
                self.calls.append(template_name)
                value = 10.0 if template_name == "request_rate" else 0.3
                return _result(template_name, [({
                    "job": "devops-api-gateway",
                    "instance": "api:8000",
                    "deployment_id": "run-live",
                    "source_sha": SOURCE_SHA,
                }, [value] * 6)])

        out = _verify(self.repository, JoinedShape())
        live = out["live_assessment"]
        self.assertEqual(live["decision"], "HEALTHY")
        self.assertEqual(live["reasons"], ["all_required_signals_healthy"])
        self.assertTrue(all(item["value"] is not None for item in live["slis"]))

    def test_persistence_is_never_touched(self):
        with patch.object(
            self.repository,
            "save_incident",
            side_effect=AssertionError("read-only"),
        ) as save:
            _verify(self.repository, FakePrometheus())
        save.assert_not_called()


# --------------------------------------------------------------------------- #
# Deliverable C — deterministic decisions + §5 baseline
# --------------------------------------------------------------------------- #

class LiveDecisionTests(unittest.TestCase):
    def setUp(self):
        self.repository = FakeRepository(
            [_carrier("run-live", "d1"), _carrier("run-base", "d2")]
        )

    def test_healthy_attributable_telemetry(self):
        out = _verify(self.repository, FakePrometheus(cpu=0.3))
        live = out["live_assessment"]
        self.assertEqual(live["decision"], "HEALTHY")
        self.assertEqual(live["reasons"], ["all_required_signals_healthy"])
        self.assertTrue(all(item["value"] is not None for item in live["slis"]))
        for entry in live["data_quality"]["exclusions"]:
            self.assertEqual(entry["count"], 0, entry)

    def test_exact_minimum_sample_boundary_is_sufficient(self):
        class ThreeSamples(FakePrometheus):
            def query_range_metric(self, template_name, start, end):
                self.calls.append(template_name)
                labels = {"deployment_id": "run-live"}
                return RangeQueryResult(
                    template=template_name, query="q", start=0, end=0,
                    step_seconds=60,
                    series=(RangeSeries(
                        labels=labels,
                        samples=tuple(
                            RangeSample(timestamp=ts, value=0.3 if template_name == "cpu_saturation" else 10.0)
                            for ts in IN_WINDOW_UNIX[:3]
                        ),
                    ),),
                )

        out = _verify(self.repository, ThreeSamples())
        self.assertEqual(out["live_assessment"]["decision"], "HEALTHY")
        self.assertEqual(out["live_assessment"]["slis"][0]["samples"], 3)

    def test_policy_failure_is_failed(self):
        out = _verify(self.repository, FakePrometheus(cpu=0.95))
        live = out["live_assessment"]
        self.assertEqual(live["decision"], "FAILED")
        self.assertEqual(live["reasons"], ["cpu_saturation_critical"])

    def test_warning_breach_is_degraded(self):
        out = _verify(self.repository, FakePrometheus(cpu=0.75))
        live = out["live_assessment"]
        self.assertEqual(live["decision"], "DEGRADED")
        self.assertEqual(live["reasons"], ["cpu_saturation_warning"])

    def test_failed_outranks_gaps_in_reason_order(self):
        class HalfAttributed(FakePrometheus):
            def query_range_metric(self, template_name, start, end):
                self.calls.append(template_name)
                if template_name == "request_rate":
                    return _result(template_name, [({"job": "api-gateway"}, [10.0] * 6)])
                return _result(template_name, [({"deployment_id": "run-live"}, [0.95] * 6)])

        out = _verify(self.repository, HalfAttributed(cpu=0.95))
        live = out["live_assessment"]
        self.assertEqual(live["decision"], "FAILED")
        self.assertEqual(live["reasons"], ["cpu_saturation_critical"])
        counts = {
            item["reason"]: item["count"]
            for item in live["data_quality"]["exclusions"]
        }
        self.assertEqual(counts["attribution_unavailable"], 1)

    def test_baseline_drop_is_degraded_when_explicitly_requested(self):
        class DropPrometheus(FakePrometheus):
            def query_range_metric(self, template_name, start, end):
                self.calls.append(template_name)
                if template_name == "request_rate":
                    return _result(template_name, [
                        ({"deployment_id": "run-live"}, [30.0] * 6),
                        ({"deployment_id": "run-base"}, [100.0] * 6),
                    ])
                return _result(template_name, [({"deployment_id": "run-live"}, [0.3] * 6)])

        out = _verify(
            self.repository, DropPrometheus(),
            baseline_deployment_run_id="run-base",
        )
        live = out["live_assessment"]
        self.assertEqual(live["decision"], "DEGRADED")
        self.assertEqual(live["reasons"], ["request_rate_dropped_vs_baseline"])
        self.assertEqual(
            live["baseline_identity"]["deployment_run_id"], "run-base"
        )
        self.assertEqual(live["baseline_identity"]["source_sha"], SOURCE_SHA)

    def test_valid_baseline_without_drop_stays_healthy(self):
        class FlatPrometheus(FakePrometheus):
            def query_range_metric(self, template_name, start, end):
                self.calls.append(template_name)
                if template_name == "request_rate":
                    return _result(template_name, [
                        ({"deployment_id": "run-live"}, [100.0] * 6),
                        ({"deployment_id": "run-base"}, [100.0] * 6),
                    ])
                return _result(template_name, [({"deployment_id": "run-live"}, [0.3] * 6)])

        out = _verify(
            self.repository, FlatPrometheus(),
            baseline_deployment_run_id="run-base",
        )
        self.assertEqual(out["live_assessment"]["decision"], "HEALTHY")

    def test_missing_baseline_identity_is_invalid_baseline(self):
        out = _verify(
            self.repository, FakePrometheus(cpu=0.3),
            baseline_deployment_run_id="run-ghost",
        )
        live = out["live_assessment"]
        self.assertEqual(live["decision"], "INCONCLUSIVE")
        self.assertIn("invalid_baseline", live["reasons"])
        self.assertIsNone(live["baseline_identity"])

    def test_baseline_with_unattributable_reference_is_invalid(self):
        class NoReferenceSeries(FakePrometheus):
            def query_range_metric(self, template_name, start, end):
                self.calls.append(template_name)
                if template_name == "request_rate":
                    return _result(
                        template_name,
                        [({"deployment_id": "run-live"}, [100.0] * 6)],
                    )
                return _result(template_name, [({"deployment_id": "run-live"}, [0.3] * 6)])

        out = _verify(
            self.repository, NoReferenceSeries(),
            baseline_deployment_run_id="run-base",
        )
        live = out["live_assessment"]
        self.assertEqual(live["decision"], "INCONCLUSIVE")
        self.assertIn("invalid_baseline", live["reasons"])

    def test_no_baseline_parameter_is_not_an_invalid_baseline(self):
        out = _verify(self.repository, FakePrometheus(cpu=0.3))
        counts = {
            item["reason"]: item["count"]
            for item in out["live_assessment"]["data_quality"]["exclusions"]
        }
        self.assertEqual(counts["invalid_baseline"], 0)
        self.assertIsNone(out["live_assessment"]["baseline_identity"])

    def test_unavailable_telemetry_is_inconclusive_never_failed(self):
        out = _verify(
            self.repository,
            FakePrometheus(error=PrometheusUnavailableError("refused")),
        )
        live = out["live_assessment"]
        self.assertEqual(live["decision"], "INCONCLUSIVE")
        self.assertEqual(live["reasons"], ["telemetry_unavailable"])
        counts = {
            item["reason"]: item["count"]
            for item in live["data_quality"]["exclusions"]
        }
        self.assertEqual(counts["telemetry_unavailable"], 2)  # one per SLI

    def test_malformed_response_is_inconclusive(self):
        out = _verify(
            self.repository,
            FakePrometheus(error=PrometheusMalformedResponseError("bad")),
        )
        live = out["live_assessment"]
        self.assertEqual(live["decision"], "INCONCLUSIVE")
        counts = {
            item["reason"]: item["count"]
            for item in live["data_quality"]["exclusions"]
        }
        self.assertEqual(counts["malformed_response"], 2)

    def test_unsupported_metric_is_inconclusive(self):
        out = _verify(
            self.repository,
            FakePrometheus(error=PrometheusUnsupportedError("nope")),
        )
        live = out["live_assessment"]
        self.assertEqual(live["decision"], "INCONCLUSIVE")
        counts = {
            item["reason"]: item["count"]
            for item in live["data_quality"]["exclusions"]
        }
        self.assertEqual(counts["unsupported_metric"], 2)

    def test_insufficient_samples_is_inconclusive_and_never_zero(self):
        class TwoSamples(FakePrometheus):
            def query_range_metric(self, template_name, start, end):
                self.calls.append(template_name)
                return RangeQueryResult(
                    template=template_name, query="q", start=0, end=0,
                    step_seconds=60,
                    series=(RangeSeries(
                        labels={"deployment_id": "run-live"},
                        samples=tuple(
                            RangeSample(timestamp=ts, value=0.3)
                            for ts in IN_WINDOW_UNIX[:2]
                        ),
                    ),),
                )

        out = _verify(self.repository, TwoSamples())
        live = out["live_assessment"]
        self.assertEqual(live["decision"], "INCONCLUSIVE")
        self.assertEqual(live["reasons"], ["insufficient_samples"])
        for item in live["slis"]:
            self.assertIsNone(item["value"])  # missing != 0.0

    def test_data_quality_vocabulary_is_pinned(self):
        out = _verify(self.repository, FakePrometheus())
        live = out["live_assessment"]
        self.assertEqual(live["data_quality"]["slis_evaluated"], 2)
        self.assertEqual(
            [(item["scope"], item["reason"]) for item in live["data_quality"]["exclusions"]],
            [
                ("telemetry", "telemetry_unavailable"),
                ("telemetry", "malformed_response"),
                ("telemetry", "unsupported_metric"),
                ("telemetry", "insufficient_samples"),
                ("telemetry", "attribution_unavailable"),
                ("telemetry", "invalid_baseline"),
            ],
        )

    def test_combined_read_model_keeps_durable_semantics(self):
        out = _verify(self.repository, FakePrometheus(cpu=0.3))
        self.assertIn("durable_assessment", out)
        self.assertIn("live_assessment", out)
        durable = out["durable_assessment"]
        # Phase 6.4 semantics intact: terminal carrier + green evidence = HEALTHY
        self.assertEqual(durable["decision"], "HEALTHY")
        self.assertEqual(durable["deployment_run_id"], "run-live")
        self.assertIn("change_impact", durable)
        self.assertEqual(out["live_assessment"]["deployment_run_id"], "run-live")

    def test_identical_inputs_produce_identical_json(self):
        first = _verify(self.repository, FakePrometheus(cpu=0.75))
        second = _verify(self.repository, FakePrometheus(cpu=0.75))
        self.assertEqual(json.dumps(first), json.dumps(second))


# --------------------------------------------------------------------------- #
# Window semantics + query budget
# --------------------------------------------------------------------------- #

class LiveWindowTests(unittest.TestCase):
    def setUp(self):
        self.repository = FakeRepository([_carrier("run-live", "d1")])

    def test_inverted_window_is_rejected_before_any_query(self):
        prometheus = FakePrometheus()
        with self.assertRaises(InvalidAnalyticsWindowError):
            _verify(self.repository, prometheus, start=W_END, end=W_START)
        self.assertEqual(prometheus.calls, [])

    def test_oversized_window_is_rejected_before_any_query(self):
        prometheus = FakePrometheus()
        with self.assertRaises(InvalidAnalyticsWindowError):
            _verify(
                self.repository, prometheus,
                start=W_START, end=W_START + timedelta(days=MAX_RANGE_DAYS, seconds=1),
            )
        self.assertEqual(prometheus.calls, [])

    def test_unknown_deployment_is_lookup_error_before_any_query(self):
        prometheus = FakePrometheus()
        with self.assertRaises(LookupError):
            _verify(
                self.repository, prometheus, deployment_run_id="run-unknown"
            )
        self.assertEqual(prometheus.calls, [])

    def test_sample_at_exact_end_is_excluded_and_exact_start_included(self):
        class BoundarySamples(FakePrometheus):
            def query_range_metric(self, template_name, start, end):
                self.calls.append(template_name)
                points = [
                    (W_START.timestamp() - 1, 999.0),   # before window: out
                    (W_START.timestamp(), 0.3),          # exact start: in
                    (W_START.timestamp() + 60, 0.3),     # in
                    (W_START.timestamp() + 120, 0.3),    # in
                    (W_END.timestamp() - 60, 0.3),       # in
                    (W_END.timestamp(), 999.0),          # exact end: out
                ]
                return RangeQueryResult(
                    template=template_name, query="q", start=0, end=0,
                    step_seconds=60,
                    series=(RangeSeries(
                        labels={"deployment_id": "run-live"},
                        samples=tuple(
                            RangeSample(timestamp=ts, value=value)
                            for ts, value in points
                        ),
                    ),),
                )

        out = _verify(self.repository, BoundarySamples())
        live = out["live_assessment"]
        self.assertEqual(live["decision"], "HEALTHY")
        for item in live["slis"]:
            self.assertEqual(item["samples"], 4, item)
        # out-of-window sentinels (999.0) never polluted the means
        self.assertAlmostEqual(live["slis"][1]["value"], 0.3)


class LiveQueryBudgetTests(unittest.TestCase):
    def test_fixed_prometheus_call_count_with_baseline_and_many_series(self):
        repository = FakeRepository(
            [_carrier("run-live", "d1"), _carrier("run-base", "d2")]
        )

        class ManySeries(FakePrometheus):
            def query_range_metric(self, template_name, start, end):
                self.calls.append(template_name)
                attributed = [{"deployment_id": "run-live"}, {"deployment_id": "run-base"}]
                noise = [{"job": f"noise-{i}"} for i in range(50)]
                return _result(
                    template_name,
                    [
                        (labels, [0.3 if template_name == "cpu_saturation" else 100.0] * 6)
                        for labels in attributed + noise
                    ],
                )

        prometheus = ManySeries()
        out = _verify(
            repository, prometheus, baseline_deployment_run_id="run-base"
        )
        # exactly one query per SLI regardless of series/sample volume
        self.assertEqual(len(prometheus.calls), 2)
        self.assertEqual(prometheus.calls, ["request_rate", "cpu_saturation"])
        self.assertEqual(out["live_assessment"]["decision"], "HEALTHY")


if __name__ == "__main__":
    unittest.main()
