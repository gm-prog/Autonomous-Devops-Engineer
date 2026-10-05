"""Phase 6.5 — change-aware live release verification (read-only).

Answers a different question than Phase 6.4: durable evidence says what
*was* deployed and what durable outcomes followed; this service asks
whether **live telemetry attributable to that exact release** supports
the same conclusion over an explicit UTC ``[start, end)`` window.

Attribution contract (the ONLY fields treated as authoritative — every
one of them is an exact string match against the Phase 6.4 authoritative
deployment record, never a timestamp, title, or “near enough” guess):

* series label ``deployment_id`` == the deployment run id, or
* series label ``source_sha``   == the exact 40-hex source SHA
  (case-insensitive hex normalization only).

Label ``service_version`` is deliberately NOT authoritative: this
repository's durable identity carries no version string to match
against, so accepting it would be guessing. A series matching neither
field is never attributed, regardless of when its samples occurred.

Supported SLIs (fixed catalog, each backed by real telemetry that
exists in this repository):

* ``request_rate``   — ``rate(devops_api_requests_total[5m])`` sum,
  instrumented by the backend gateway and scraped via
  ``monitoring/prometheus.yml``;
* ``cpu_saturation`` — ``rate(process_cpu_seconds_total[2m])`` avg from
  the default process collector on the same scrape targets.

Error-rate and latency SLIs are intentionally absent: no error-labeled
or duration-histogram metric exists in this repository's telemetry
path, and inventing one would fabricate data.

Deterministic rule evaluator (no ML/LLM/probabilistic scoring), fixed
precedence ``FAILED > DEGRADED > INCONCLUSIVE > HEALTHY``:

* FAILED  — ``cpu_saturation_critical`` (mean >= 0.90 cores, attributable
  samples only);
* DEGRADED — ``cpu_saturation_warning`` (mean >= 0.70 cores) or
  ``request_rate_dropped_vs_baseline`` (candidate mean < 50% of an
  explicit, attributable baseline mean);
* INCONCLUSIVE — any data-quality gap: telemetry unavailable, malformed
  response, unsupported metric, insufficient attributable samples,
  attribution unavailable, or an explicitly requested baseline that
  cannot be established;
* HEALTHY — all required signals attributable, >= ``_MIN_SAMPLES``
  populated, within policy, and no gaps (``all_required_signals_healthy``).

Missing data is never zero, malformed data is never a breach, and time
proximity never creates attribution. Every Prometheus interaction is a
bounded read: fixed timeout, fixed template catalog, fixed call count
(one call per SLI — identical with or without a baseline, so sample
volume and series count cannot fan out into N+1 queries).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from monitoring_service.infrastructure.prometheus.scraper_client import (
    PrometheusMalformedResponseError,
    PrometheusQueryError,
    PrometheusScraperClient,
    PrometheusUnsupportedError,
    PrometheusUnavailableError,
    RangeQueryResult,
)

from incident_service.application.services.change_intelligence_service import (
    ChangeIntelligenceService,
)
from incident_service.application.services.operational_analytics_service import (
    InvalidAnalyticsWindowError,
    OperationalAnalyticsService,
    _aware_utc,
)

#: Fixed SLI catalog, in evaluation order (must mirror the scraper's
#: template catalog — there is no other telemetry query in the system).
_SLI_ORDER: Tuple[str, ...] = ("request_rate", "cpu_saturation")

#: Minimum attributable in-window samples before an SLI value is trusted.
_MIN_SAMPLES = 3

#: Deterministic saturation policy (cores, arithmetic mean of attributable
#: in-window samples — simple, bounded, reviewable; no analytics framework).
_CPU_WARNING = 0.70
_CPU_CRITICAL = 0.90

#: Deterministic relative policy: candidate request_rate must retain at
#: least this fraction of the explicit baseline's request_rate.
_REQUEST_DROP_WARNING_RATIO = 0.50

#: Fixed data-quality vocabulary — always fully present, every entry has
#: a genuine emission path and a test (window validation failures are not
#: listed here: they are rejected with HTTP 422 before any assessment
#: exists, see the controller contract).
_TELEMETRY_DQ_REASONS: Tuple[str, ...] = (
    "telemetry_unavailable",
    "malformed_response",
    "unsupported_metric",
    "insufficient_samples",
    "attribution_unavailable",
    "invalid_baseline",
)

_REASON_FAILED = "cpu_saturation_critical"
_REASON_DEGRADED_CPU = "cpu_saturation_warning"
_REASON_DEGRADED_DROP = "request_rate_dropped_vs_baseline"
_REASON_HEALTHY = "all_required_signals_healthy"


def _attributed(labels: Dict[str, str], identity: Dict[str, Optional[str]]) -> bool:
    """Exact-identifier attribution (see module docstring). Timestamps are
    never consulted."""
    run_id = identity.get("deployment_run_id") or ""
    if run_id and str(labels.get("deployment_id") or "") == run_id:
        return True
    source_sha = (identity.get("source_sha") or "").lower()
    if source_sha and str(labels.get("source_sha") or "").lower() == source_sha:
        return True
    return False


def _attributable_values(
    result: RangeQueryResult,
    identity: Dict[str, Optional[str]],
    start_unix: float,
    end_unix: float,
) -> Tuple[list, int]:
    """(in-window attributable values, number of attributed series).

    Window semantics are exact half-open ``[start, end)`` on sample
    timestamps.
    """
    values = []
    attributed_series = 0
    for series in result.series:
        if not _attributed(series.labels, identity):
            continue
        attributed_series += 1
        for sample in series.samples:
            if start_unix <= sample.timestamp < end_unix:
                values.append(sample.value)
    return values, attributed_series


@dataclass(frozen=True)
class SliObservation:
    """One SLI's attributable in-window state (value None = not evaluable;
    missing telemetry is never coerced to zero)."""

    name: str
    samples: int
    value: Optional[float]

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "samples": self.samples, "value": self.value}


@dataclass(frozen=True)
class LiveReleaseAssessment:
    """Typed, deterministic Phase 6.5 output for one release + window."""

    deployment_run_id: str
    observation_window: Dict[str, str]
    release_identity: Dict[str, Any]
    baseline_identity: Optional[Dict[str, Any]]
    slis: Tuple[SliObservation, ...]
    decision: str
    reasons: Tuple[str, ...]
    data_quality: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "deployment_run_id": self.deployment_run_id,
            "observation_window": dict(self.observation_window),
            "release_identity": dict(self.release_identity),
            "baseline_identity": (
                dict(self.baseline_identity) if self.baseline_identity else None
            ),
            "slis": [item.to_dict() for item in self.slis],
            "decision": self.decision,
            "reasons": list(self.reasons),
            "data_quality": {
                "slis_evaluated": self.data_quality["slis_evaluated"],
                "exclusions": [
                    dict(item) for item in self.data_quality["exclusions"]
                ],
            },
        }


class LiveReleaseVerificationService:
    """Read-only live verification over durable identity + bounded telemetry.

    Combine step: the returned read model carries BOTH the unchanged
    Phase 6.4 durable assessment and this live assessment — Phase 6.4
    decision semantics are consumed verbatim, never re-evaluated here.
    """

    def __init__(self, repository, prometheus: PrometheusScraperClient):
        self.repository = repository
        self.prometheus = prometheus

    def verify(
        self,
        deployment_run_id: str,
        start: datetime,
        end: datetime,
        baseline_deployment_run_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        # Single window-validation authority (Phase 6.3/6.4 reuse): UTC
        # half-open [start, end), <= 31 days, else InvalidAnalyticsWindowError.
        start_utc, end_utc = OperationalAnalyticsService._validate_window(start, end)

        # Phase 6.4 supplies the exact release identity (404 for unknown
        # runs) and the durable half of the combined read model.
        durable = ChangeIntelligenceService(self.repository).assess(
            deployment_run_id=deployment_run_id, start=start, end=end
        )
        impact = durable["change_impact"]
        identity: Dict[str, Optional[str]] = {
            "deployment_run_id": durable["deployment_run_id"],
            "repository_name": impact.get("repository_name"),
            "source_sha": impact.get("source_sha"),
        }

        exclusions = {reason: 0 for reason in _TELEMETRY_DQ_REASONS}

        baseline_identity: Optional[Dict[str, Optional[str]]] = None
        if baseline_deployment_run_id:
            try:
                baseline_durable = ChangeIntelligenceService(self.repository).assess(
                    deployment_run_id=baseline_deployment_run_id,
                    start=start,
                    end=end,
                )
            except LookupError:
                exclusions["invalid_baseline"] += 1
            else:
                baseline_impact = baseline_durable["change_impact"]
                baseline_identity = {
                    "deployment_run_id": baseline_durable["deployment_run_id"],
                    "repository_name": baseline_impact.get("repository_name"),
                    "source_sha": baseline_impact.get("source_sha"),
                }

        start_unix = _aware_utc(start_utc).timestamp()
        end_unix = _aware_utc(end_utc).timestamp()

        # Fixed call count: exactly one bounded range query per SLI,
        # regardless of series/sample volume or baseline presence.
        results: Dict[str, RangeQueryResult] = {}
        for template in _SLI_ORDER:
            try:
                results[template] = self.prometheus.query_range_metric(
                    template, start_utc, end_utc
                )
            except PrometheusUnavailableError:
                exclusions["telemetry_unavailable"] += 1
            except PrometheusMalformedResponseError:
                exclusions["malformed_response"] += 1
            except PrometheusUnsupportedError:
                exclusions["unsupported_metric"] += 1
            except PrometheusQueryError:
                # Defensive fail-closed catch for bound violations.
                exclusions["telemetry_unavailable"] += 1

        values: Dict[str, Optional[float]] = {}
        sample_counts: Dict[str, int] = {}
        for template, identity_for_sli in (
            ("request_rate", identity),
            ("cpu_saturation", identity),
        ):
            result = results.get(template)
            if result is None:
                values[template] = None
                sample_counts[template] = 0
                continue
            in_window, attributed_series = _attributable_values(
                result, identity_for_sli, start_unix, end_unix
            )
            sample_counts[template] = len(in_window)
            if attributed_series == 0:
                exclusions["attribution_unavailable"] += 1
                values[template] = None
            elif len(in_window) < _MIN_SAMPLES:
                exclusions["insufficient_samples"] += 1
                values[template] = None
            else:
                values[template] = math.fsum(in_window) / len(in_window)

        # Baseline: explicit, attributable reference for the relative rule.
        baseline_usable = False
        baseline_request_rate: Optional[float] = None
        if baseline_identity is not None:
            baseline_result = results.get("request_rate")
            if baseline_result is not None:
                baseline_values, baseline_series = _attributable_values(
                    baseline_result, baseline_identity, start_unix, end_unix
                )
                if baseline_series > 0 and len(baseline_values) >= _MIN_SAMPLES:
                    baseline_request_rate = math.fsum(baseline_values) / len(
                        baseline_values
                    )
                    baseline_usable = True
            if not baseline_usable:
                exclusions["invalid_baseline"] += 1

        # Fixed rule order (precedence FAILED > DEGRADED > INCONCLUSIVE > HEALTHY).
        cpu = values.get("cpu_saturation")
        request_rate = values.get("request_rate")
        failed_reasons = []
        degraded_reasons = []
        if cpu is not None and cpu >= _CPU_CRITICAL:
            failed_reasons.append(_REASON_FAILED)
        if cpu is not None and cpu >= _CPU_WARNING:
            degraded_reasons.append(_REASON_DEGRADED_CPU)
        if (
            request_rate is not None
            and baseline_usable
            and baseline_request_rate is not None
            and request_rate < _REQUEST_DROP_WARNING_RATIO * baseline_request_rate
        ):
            degraded_reasons.append(_REASON_DEGRADED_DROP)

        gap_reasons = [
            reason
            for reason in _TELEMETRY_DQ_REASONS
            if exclusions[reason] > 0
        ]

        if failed_reasons:
            decision = "FAILED"
            reasons = failed_reasons
        elif degraded_reasons:
            decision = "DEGRADED"
            reasons = degraded_reasons
        elif gap_reasons:
            decision = "INCONCLUSIVE"
            reasons = gap_reasons
        else:
            decision = "HEALTHY"
            reasons = [_REASON_HEALTHY]

        assessment = LiveReleaseAssessment(
            deployment_run_id=durable["deployment_run_id"],
            observation_window=durable["observation_window"],
            release_identity=identity,
            baseline_identity=baseline_identity,
            slis=tuple(
                SliObservation(
                    name=template,
                    samples=sample_counts.get(template, 0),
                    value=values.get(template),
                )
                for template in _SLI_ORDER
            ),
            decision=decision,
            reasons=tuple(reasons),
            data_quality={
                "slis_evaluated": len(_SLI_ORDER),
                "exclusions": [
                    {"scope": "telemetry", "reason": reason, "count": exclusions[reason]}
                    for reason in _TELEMETRY_DQ_REASONS
                ],
            },
        )
        # Combined read model: Phase 6.4 durable assessment (unchanged
        # semantics) + Phase 6.5 live assessment, one response.
        return {
            "durable_assessment": durable,
            "live_assessment": assessment.to_dict(),
        }


__all__ = [
    "InvalidAnalyticsWindowError",
    "LiveReleaseAssessment",
    "LiveReleaseVerificationService",
    "SliObservation",
]
