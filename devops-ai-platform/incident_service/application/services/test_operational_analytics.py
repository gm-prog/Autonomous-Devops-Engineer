"""Phase 6.3 operational analytics: unit, data-quality and E2E-fixture tests.

Proves the analytics service contract end to end over durable records only:

* window contract — half-open UTC ``[start, end)``, at most 31 days,
  explicit rejection otherwise (service-owned validation);
* deterministic aggregation — fixed sorts, zero-filled UTC day buckets,
  identical output for identical input regardless of record order;
* phase classification over proposal status + execution-evidence ``stages``
  (membership/`passed` only), with every proposal landing in exactly one
  bucket per phase;
* timing samples with nearest-rank p50/p95 and visible exclusions;
* data-quality counters always present (zero unless stated) and an
  explicit UNSUPPORTED manifest — nothing is ever fabricated;
* one end-to-end fixture through the REAL repository adapter (SQLite as
  the legitimate test database) proving SQL window bounds + evidence
  round-trip → summary.
"""

import json
import os
import tempfile
import unittest
from collections import Counter
from datetime import datetime, timedelta, timezone

from incident_service.application.services.operational_analytics_service import (
    InvalidAnalyticsWindowError,
    OperationalAnalyticsService,
)
from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.domain.entities.hotfix_proposal import HotfixProposal
from incident_service.domain.entities.incident_evidence import IncidentEvidence
from incident_service.domain.repository_interface import IncidentRepositoryPort
from incident_service.infrastructure.database.postgres_incident_repo import (
    PostgresIncidentRepositoryAdapter,
)

UTC = timezone.utc
W_START = datetime(2026, 9, 1, tzinfo=UTC)
W_END = datetime(2026, 9, 8, tzinfo=UTC)


class FakeRepository(IncidentRepositoryPort):
    """In-memory port double: returns exactly what the test seeded."""

    def __init__(self, incidents=None):
        self._incidents = list(incidents or [])

    def save_incident(self, incident):
        raise AssertionError("analytics must never write")

    def get_incident_by_id(self, incident_id):
        return None

    def get_active_incidents(self):
        return []

    def list_incidents_in_window(self, start, end):
        assert start < end
        return list(self._incidents)


def _incident(incident_id, created_at, severity="HIGH", status="Raised"):
    incident = IncidentAggregate(
        id=incident_id,
        title=f"[sentry] {incident_id}",
        severity=severity,
        context_details="cpu saturation",
    )
    incident.created_at = created_at
    incident.status = status
    return incident


def _proposal(
    proposal_id,
    *,
    status="PROPOSED",
    generated_at=W_START + timedelta(hours=1),
    approved_at=None,
    last_failure_stage="",
    pull_request_url="",
):
    return HotfixProposal(
        id=proposal_id,
        target_filepath="app/worker.py",
        diff_patch_payload="--- a/app/worker.py\n+++ b/app/worker.py\n",
        status=status,
        generated_at=generated_at,
        approved_at=approved_at,
        last_failure_stage=last_failure_stage,
        pull_request_url=pull_request_url or None,
    )


def _stage(name, **metadata):
    return {"stage": name, "metadata": dict(metadata)}


def _exec_evidence(evidence_id, proposal_id, stages, observed_at, status):
    return IncidentEvidence(
        id=evidence_id,
        kind="remediation_execution",
        source="proposal_execution_service",
        observed_at=observed_at,
        payload={
            "schema": "devops.remediation.execution/2",
            "proposal_id": proposal_id,
            "status": status,
            "attempt": 1,
            "stages": list(stages),
        },
    )


def _rca_evidence(evidence_id, payload, observed_at):
    return IncidentEvidence(
        id=evidence_id,
        kind="rca_result",
        source="rca_agent",
        observed_at=observed_at,
        payload=payload,
    )


def _dq_counts(summary):
    return {
        (item["scope"], item["reason"]): item["count"]
        for item in summary["data_quality"]["exclusions"]
    }


class WindowContractTests(unittest.TestCase):
    def _summarize(self, start, end):
        return OperationalAnalyticsService(FakeRepository()).summarize(
            start=start, end=end
        )

    def test_start_not_before_end_is_rejected(self):
        with self.assertRaises(InvalidAnalyticsWindowError):
            self._summarize(W_END, W_START)
        with self.assertRaises(InvalidAnalyticsWindowError):
            self._summarize(W_START, W_START)

    def test_window_longer_than_31_days_is_rejected(self):
        with self.assertRaises(InvalidAnalyticsWindowError):
            self._summarize(W_START, W_START + timedelta(days=31, seconds=1))
        # exactly 31 days is allowed
        summary = self._summarize(W_START, W_START + timedelta(days=31))
        self.assertEqual(summary["window"]["max_days"], 31)

    def test_naive_datetimes_are_treated_as_utc(self):
        naive_summary = self._summarize(
            datetime(2026, 9, 1), datetime(2026, 9, 3)
        )
        aware_summary = self._summarize(
            datetime(2026, 9, 1, tzinfo=UTC), datetime(2026, 9, 3, tzinfo=UTC)
        )
        self.assertEqual(naive_summary, aware_summary)

    def test_offset_datetimes_normalize_to_utc(self):
        ist = timezone(timedelta(hours=5, minutes=30))
        offset_summary = self._summarize(
            datetime(2026, 9, 1, 5, 30, tzinfo=ist),
            datetime(2026, 9, 3, 5, 30, tzinfo=ist),
        )
        aware_summary = self._summarize(
            datetime(2026, 9, 1, tzinfo=UTC), datetime(2026, 9, 3, tzinfo=UTC)
        )
        self.assertEqual(offset_summary, aware_summary)


class EmptyDatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.summary = OperationalAnalyticsService(FakeRepository()).summarize(
            start=W_START, end=W_END
        )

    def test_all_top_level_sections_present(self):
        self.assertEqual(
            list(self.summary),
            [
                "window",
                "incidents",
                "remediation",
                "timing",
                "data_quality",
                "unsupported",
            ],
        )

    def test_timeseries_zero_fills_every_utc_day_in_window(self):
        days = [point["date"] for point in self.summary["incidents"]["timeseries"]]
        self.assertEqual(
            days,
            [
                "2026-09-01",
                "2026-09-02",
                "2026-09-03",
                "2026-09-04",
                "2026-09-05",
                "2026-09-06",
                "2026-09-07",
            ],
        )
        self.assertTrue(
            all(point["count"] == 0 for point in self.summary["incidents"]["timeseries"])
        )

    def test_every_data_quality_reason_is_present_with_zero_count(self):
        counts = _dq_counts(self.summary)
        self.assertTrue(counts, "data-quality exclusions must be visible")
        self.assertTrue(all(count == 0 for count in counts.values()), counts)
        self.assertEqual(
            self.summary["data_quality"]["incidents_considered"], 0
        )

    def test_unsupported_manifest_is_explicit(self):
        metrics = [item["metric"] for item in self.summary["unsupported"]]
        self.assertEqual(
            metrics,
            [
                "incidents_by_service",
                "rca_category_distribution",
                "proposals_rejected",
                "proposals_expired",
                "recovery_outcome_distribution",
                "incident_recurrence",
            ],
        )
        for item in self.summary["unsupported"]:
            self.assertTrue(item["reason"])
            self.assertTrue(item["would_require"])
        intervals = [
            item["interval"] for item in self.summary["timing"]["unsupported_intervals"]
        ]
        self.assertEqual(
            intervals,
            [
                "approval_to_validation",
                "validation_to_commit",
                "commit_to_publication",
                "publication_to_pull_request",
                "proposal_to_pull_request",
            ],
        )


class IncidentAggregateTests(unittest.TestCase):
    def test_counts_by_day_severity_status_with_window_defence(self):
        inside_first = _incident("inc-a", W_START, severity="HIGH")
        inside_second = _incident("inc-b", W_START + timedelta(days=1), severity="LOW")
        inside_second.status = "Resolved"
        outside = _incident("inc-out", W_END + timedelta(days=2), severity="HIGH")
        summary = OperationalAnalyticsService(
            FakeRepository([inside_first, inside_second, outside])
        ).summarize(start=W_START, end=W_END)

        self.assertEqual(summary["incidents"]["total"], 2)
        self.assertEqual(summary["incidents"]["by_severity"], {"HIGH": 1, "LOW": 1})
        self.assertEqual(
            summary["incidents"]["by_status"], {"Raised": 1, "Resolved": 1}
        )
        series = {
            point["date"]: point["count"]
            for point in summary["incidents"]["timeseries"]
        }
        self.assertEqual(series["2026-09-01"], 1)
        self.assertEqual(series["2026-09-02"], 1)
        self.assertEqual(series["2026-09-03"], 0)
        # defence-in-depth: repository returned an out-of-window row
        counts = _dq_counts(summary)
        self.assertEqual(counts[("window", "incident_outside_window")], 1)
        self.assertEqual(summary["data_quality"]["incidents_considered"], 3)

    def test_rca_coverage_partition_and_malformed_exclusion(self):
        with_rca = _incident("inc-rca", W_START)
        with_rca.evidence.append(
            _rca_evidence(
                "ev-rca-1",
                {"root_cause": "cpu saturation", "confidence": 0.9},
                W_START + timedelta(minutes=5),
            )
        )
        without_rca = _incident("inc-no-rca", W_START)
        malformed = _incident("inc-bad-rca", W_START)
        malformed.evidence.append(
            _rca_evidence("ev-bad", ["not-a-mapping"], W_START)
        )
        summary = OperationalAnalyticsService(
            FakeRepository([with_rca, without_rca, malformed])
        ).summarize(start=W_START, end=W_END)
        self.assertEqual(summary["incidents"]["reached_rca"], 1)
        self.assertEqual(summary["incidents"]["without_rca"], 1)
        self.assertEqual(summary["incidents"]["rca_malformed"], 1)
        counts = _dq_counts(summary)
        self.assertEqual(
            counts[("rca_coverage", "rca_evidence_malformed")], 1
        )


class PhaseClassificationTests(unittest.TestCase):
    def _summarize_with_proposals(self, proposals):
        incident = _incident("inc-phases", W_START)
        incident.patch_proposals.extend(proposals)
        summary = OperationalAnalyticsService(
            FakeRepository([incident])
        ).summarize(start=W_START, end=W_END)
        return summary["remediation"]

    def test_proposed_and_approved_proposals_are_not_reached(self):
        remediation = self._summarize_with_proposals(
            [
                _proposal("p-proposed"),
                _proposal(
                    "p-approved",
                    status="APPROVED",
                    approved_at=W_START + timedelta(hours=2),
                ),
            ]
        )
        for phase in ("validation", "commit", "publication"):
            self.assertEqual(
                remediation[phase],
                {"succeeded": 0, "failed": 0, "not_reached": 2},
                phase,
            )
        self.assertEqual(
            remediation["pull_request"],
            {"created": 0, "failed": 0, "not_reached": 2},
        )
        self.assertEqual(remediation["approved"], 1)

    def test_successful_pr_created_implies_every_phase(self):
        remediation = self._summarize_with_proposals(
            [
                _proposal(
                    "p-pr",
                    status="PR_CREATED",
                    approved_at=W_START + timedelta(hours=2),
                    pull_request_url="https://github.com/o/r/pull/1",
                )
            ]
        )
        self.assertEqual(
            remediation["validation"],
            {"succeeded": 1, "failed": 0, "not_reached": 0},
        )
        self.assertEqual(
            remediation["commit"],
            {"succeeded": 1, "failed": 0, "not_reached": 0},
        )
        self.assertEqual(
            remediation["publication"],
            {"succeeded": 1, "failed": 0, "not_reached": 0},
        )
        self.assertEqual(
            remediation["pull_request"],
            {"created": 1, "failed": 0, "not_reached": 0},
        )

    def test_validation_failure_from_evidence_passed_false(self):
        incident = _incident("inc-vfail", W_START)
        proposal = _proposal(
            "p-vfail",
            status="EXECUTION_FAILED",
            approved_at=W_START + timedelta(hours=2),
            last_failure_stage="validation.completed",
        )
        incident.patch_proposals.append(proposal)
        incident.evidence.append(
            _exec_evidence(
                "ev-x1",
                "p-vfail",
                [
                    _stage("workspace.created"),
                    _stage("patch.applied"),
                    _stage("validation.started"),
                    _stage("validation.completed", passed=False, profile="default"),
                ],
                W_START + timedelta(hours=3),
                "EXECUTION_FAILED",
            )
        )
        remediation = OperationalAnalyticsService(
            FakeRepository([incident])
        ).summarize(start=W_START, end=W_END)["remediation"]
        self.assertEqual(
            remediation["validation"],
            {"succeeded": 0, "failed": 1, "not_reached": 0},
        )
        self.assertEqual(
            remediation["commit"],
            {"succeeded": 0, "failed": 0, "not_reached": 1},
        )
        self.assertEqual(
            remediation["failures_by_stage"],
            [{"stage": "validation.completed", "count": 1}],
        )

    def test_failure_after_validation_is_attributed_to_commit(self):
        incident = _incident("inc-cfail", W_START)
        incident.patch_proposals.append(
            _proposal(
                "p-cfail",
                status="EXECUTION_FAILED",
                approved_at=W_START + timedelta(hours=2),
                last_failure_stage="commit.create",
            )
        )
        incident.evidence.append(
            _exec_evidence(
                "ev-x2",
                "p-cfail",
                [
                    _stage("validation.started"),
                    _stage("validation.completed", passed=True),
                ],
                W_START + timedelta(hours=3),
                "EXECUTION_FAILED",
            )
        )
        remediation = OperationalAnalyticsService(
            FakeRepository([incident])
        ).summarize(start=W_START, end=W_END)["remediation"]
        self.assertEqual(
            remediation["validation"],
            {"succeeded": 1, "failed": 0, "not_reached": 0},
        )
        self.assertEqual(
            remediation["commit"],
            {"succeeded": 0, "failed": 1, "not_reached": 0},
        )

    def test_publication_and_pull_request_failure_boundaries(self):
        incident = _incident("inc-boundaries", W_START)
        incident.patch_proposals.extend(
            [
                _proposal(
                    "p-pub-fail",
                    status="EXECUTION_FAILED",
                    approved_at=W_START + timedelta(hours=2),
                    last_failure_stage="remote.publish",
                ),
                _proposal(
                    "p-pr-fail",
                    status="EXECUTION_FAILED",
                    approved_at=W_START + timedelta(hours=2),
                    last_failure_stage="pr.discovery",
                ),
            ]
        )
        incident.evidence.extend(
            [
                _exec_evidence(
                    "ev-x3",
                    "p-pub-fail",
                    [
                        _stage("validation.completed", passed=True),
                        _stage("commit.created", commit_sha="a" * 40),
                    ],
                    W_START + timedelta(hours=3),
                    "EXECUTION_FAILED",
                ),
                _exec_evidence(
                    "ev-x4",
                    "p-pr-fail",
                    [
                        _stage("validation.completed", passed=True),
                        _stage("commit.created", commit_sha="b" * 40),
                        _stage("remote.published", branch="fix/x"),
                        _stage("remote.verified"),
                        _stage("pr.discovery"),
                    ],
                    W_START + timedelta(hours=4),
                    "EXECUTION_FAILED",
                ),
            ]
        )
        remediation = OperationalAnalyticsService(
            FakeRepository([incident])
        ).summarize(start=W_START, end=W_END)["remediation"]
        # publication boundary
        self.assertEqual(
            remediation["publication"],
            {"succeeded": 1, "failed": 1, "not_reached": 0},
        )
        # both failures validated + committed; first never published, second did
        self.assertEqual(
            remediation["commit"],
            {"succeeded": 2, "failed": 0, "not_reached": 0},
        )
        self.assertEqual(
            remediation["pull_request"],
            {"created": 0, "failed": 1, "not_reached": 1},
        )
        self.assertEqual(
            remediation["failures_by_stage"],
            [
                {"stage": "pr.discovery", "count": 1},
                {"stage": "remote.publish", "count": 1},
            ],
        )

    def test_failed_execution_without_evidence_counts_exclusion(self):
        incident = _incident("inc-noevidence", W_START)
        incident.patch_proposals.append(
            _proposal(
                "p-lost",
                status="EXECUTION_FAILED",
                approved_at=W_START + timedelta(hours=2),
                last_failure_stage="",
            )
        )
        summary = OperationalAnalyticsService(
            FakeRepository([incident])
        ).summarize(start=W_START, end=W_END)
        counts = _dq_counts(summary)
        self.assertEqual(
            counts[("execution", "execution_evidence_missing")], 1
        )
        self.assertEqual(
            counts[("failures_by_stage", "missing_last_failure_stage")], 1
        )
        self.assertEqual(
            summary["remediation"]["validation"],
            {"succeeded": 0, "failed": 0, "not_reached": 1},
        )

    def test_unmatched_execution_evidence_is_counted(self):
        incident = _incident("inc-unmatched", W_START)
        incident.evidence.append(
            _exec_evidence(
                "ev-x9",
                "p-does-not-exist",
                [_stage("workspace.created")],
                W_START + timedelta(hours=1),
                "EXECUTION_FAILED",
            )
        )
        summary = OperationalAnalyticsService(
            FakeRepository([incident])
        ).summarize(start=W_START, end=W_END)
        counts = _dq_counts(summary)
        self.assertEqual(
            counts[("execution", "execution_evidence_unmatched")], 1
        )


class TimingTests(unittest.TestCase):
    def test_samples_nearest_rank_percentiles_and_exclusions(self):
        incident = _incident("inc-timing", W_START)
        approved = W_START + timedelta(hours=1)
        # approved proposal with a finished execution: completion at +300s
        good = _proposal(
            "p-good",
            status="PR_CREATED",
            generated_at=W_START,
            approved_at=approved,
            pull_request_url="https://github.com/o/r/pull/9",
        )
        incident.patch_proposals.append(good)
        incident.evidence.append(
            _exec_evidence(
                "ev-t1",
                "p-good",
                [_stage("validation.completed", passed=True)],
                approved + timedelta(seconds=300),
                "PR_CREATED",
            )
        )
        # approved earlier by exactly 60s from generation
        earlier = _proposal(
            "p-earlier",
            status="PROPOSED",
            generated_at=W_START,
            approved_at=W_START + timedelta(seconds=60),
        )
        incident.patch_proposals.append(earlier)
        # negative approval duration → excluded
        negative = _proposal(
            "p-negative",
            status="PROPOSED",
            generated_at=W_START + timedelta(hours=5),
            approved_at=W_START + timedelta(hours=1),
        )
        incident.patch_proposals.append(negative)
        # approved but never completed → completion exclusion
        incomplete = _proposal(
            "p-incomplete",
            status="EXECUTING",
            generated_at=W_START,
            approved_at=W_START + timedelta(seconds=120),
        )
        incident.patch_proposals.append(incomplete)
        # never approved → outside the approval-timing population
        unapproved = _proposal("p-unapproved", generated_at=W_START)
        incident.patch_proposals.append(unapproved)

        summary = OperationalAnalyticsService(
            FakeRepository([incident])
        ).summarize(start=W_START, end=W_END)
        approval = summary["timing"]["proposal_to_approval"]
        # samples: 60s (p-earlier), 120s (p-incomplete — approval time is
        # still valid), 3600s (p-good); p-negative excluded → n=3
        self.assertEqual(approval["sample_count"], 3)
        self.assertEqual(approval["p50_seconds"], 120)
        self.assertEqual(approval["p95_seconds"], 3600)
        self.assertEqual(approval["excluded_count"], 1)

        completion = summary["timing"]["approval_to_execution_completion"]
        # only p-good completed: 300s; p-earlier + p-negative missing, p-incomplete missing
        self.assertEqual(completion["sample_count"], 1)
        self.assertEqual(completion["p50_seconds"], 300)
        self.assertEqual(completion["p95_seconds"], 300)
        self.assertEqual(completion["excluded_count"], 3)

        counts = _dq_counts(summary)
        self.assertEqual(
            counts[("timing_proposal_to_approval", "negative_duration")], 1
        )
        self.assertEqual(
            counts[("timing_approval_to_completion", "execution_completion_missing")],
            3,
        )

    def test_nearest_rank_math_over_multiple_samples(self):
        incident = _incident("inc-rank", W_START)
        approved = W_START + timedelta(minutes=30)
        for index, offset in enumerate((10, 20, 30, 40)):
            proposal = _proposal(
                f"p-rank-{index}",
                status="PR_CREATED",
                generated_at=approved - timedelta(seconds=offset),
                approved_at=approved,
                pull_request_url=f"https://github.com/o/r/pull/{index}",
            )
            incident.patch_proposals.append(proposal)
        summary = OperationalAnalyticsService(
            FakeRepository([incident])
        ).summarize(start=W_START, end=W_END)
        approval = summary["timing"]["proposal_to_approval"]
        # sorted [10,20,30,40]: p50 → idx ceil(0.5*4)-1 = 1 → 20; p95 → idx 3 → 40
        self.assertEqual(approval["sample_count"], 4)
        self.assertEqual(approval["p50_seconds"], 20)
        self.assertEqual(approval["p95_seconds"], 40)
        self.assertEqual(approval["excluded_count"], 0)

    def test_empty_samples_report_null_percentiles(self):
        summary = OperationalAnalyticsService(FakeRepository()).summarize(
            start=W_START, end=W_END
        )
        for key in ("proposal_to_approval", "approval_to_execution_completion"):
            stats = summary["timing"][key]
            self.assertEqual(stats["sample_count"], 0)
            self.assertIsNone(stats["p50_seconds"])
            self.assertIsNone(stats["p95_seconds"])


class DeterminismTests(unittest.TestCase):
    def _incident(self, incident_id, day_offset):
        incident = _incident(incident_id, W_START + timedelta(days=day_offset))
        incident.patch_proposals.append(
            _proposal(
                f"proposal-{incident_id}",
                status="PR_CREATED",
                approved_at=W_START + timedelta(hours=2),
                pull_request_url="https://github.com/o/r/pull/7",
            )
        )
        return incident

    def test_identical_records_produce_identical_summaries(self):
        incidents = [
            self._incident("inc-1", 0),
            self._incident("inc-2", 1),
            self._incident("inc-3", 2),
        ]
        first = OperationalAnalyticsService(
            FakeRepository(incidents)
        ).summarize(start=W_START, end=W_END)
        second = OperationalAnalyticsService(
            FakeRepository(list(incidents))
        ).summarize(start=W_START, end=W_END)
        self.assertEqual(json.dumps(first, sort_keys=False), json.dumps(second))
        # shuffled input order → same summary (aggregation is order-free)
        shuffled = OperationalAnalyticsService(
            FakeRepository(list(reversed(incidents)))
        ).summarize(start=W_START, end=W_END)
        self.assertEqual(json.dumps(first), json.dumps(shuffled))


class EndToEndSqliteFixtureTests(unittest.TestCase):
    """E2E fixture: REAL repository adapter over SQLite (legitimate test DB)."""

    @classmethod
    def setUpClass(cls):
        cls._temp = tempfile.TemporaryDirectory()
        url = f"sqlite:///{os.path.join(cls._temp.name, 'analytics.db')}"
        cls.repository = PostgresIncidentRepositoryAdapter(url)

        in_window = _incident("inc-in", W_START + timedelta(hours=2), severity="HIGH")
        in_window.status = "RootCauseFound"
        in_window.evidence.append(
            _rca_evidence(
                "ev-e2e-rca",
                {"root_cause": "disk pressure", "confidence": 0.8},
                W_START + timedelta(hours=3),
            )
        )
        approved_at = W_START + timedelta(hours=4)
        proposal = _proposal(
            "proposal-inc-in",
            status="PR_CREATED",
            generated_at=W_START + timedelta(hours=3),
            approved_at=approved_at,
            pull_request_url="https://github.com/o/r/pull/42",
        )
        proposal.incident_id = "inc-in"
        in_window.patch_proposals.append(proposal)
        in_window.evidence.append(
            _exec_evidence(
                "ev-e2e-x",
                "proposal-inc-in",
                [
                    _stage("validation.started"),
                    _stage("validation.completed", passed=True),
                    _stage("commit.created", commit_sha="c" * 40),
                    _stage("remote.published", branch="fix/e2e"),
                    _stage("remote.verified"),
                    _stage("pr.created", pull_request_url="https://github.com/o/r/pull/42"),
                ],
                approved_at + timedelta(seconds=90),
                "PR_CREATED",
            )
        )
        cls.repository.save_incident(in_window)

        outside = _incident(
            "inc-out", W_END + timedelta(days=1), severity="LOW"
        )
        cls.repository.save_incident(outside)

    @classmethod
    def tearDownClass(cls):
        cls._temp.cleanup()

    def test_sql_window_filter_and_full_summary(self):
        summary = OperationalAnalyticsService(self.repository).summarize(
            start=W_START, end=W_END
        )
        self.assertEqual(summary["incidents"]["total"], 1)
        self.assertEqual(summary["incidents"]["by_severity"], {"HIGH": 1})
        self.assertEqual(summary["incidents"]["reached_rca"], 1)
        self.assertEqual(summary["remediation"]["proposals_created"], 1)
        self.assertEqual(summary["remediation"]["approved"], 1)
        self.assertEqual(
            summary["remediation"]["pull_request"],
            {"created": 1, "failed": 0, "not_reached": 0},
        )
        approval = summary["timing"]["proposal_to_approval"]
        self.assertEqual(approval["sample_count"], 1)
        self.assertEqual(approval["p50_seconds"], 3600)
        completion = summary["timing"]["approval_to_execution_completion"]
        self.assertEqual(completion["sample_count"], 1)
        self.assertEqual(completion["p50_seconds"], 90)
        counts = _dq_counts(summary)
        self.assertEqual(counts[("window", "incident_outside_window")], 0)

    def test_window_half_open_bounds_at_sql_level(self):
        # incident created at W_START+2h: start inclusive → included
        inside = OperationalAnalyticsService(self.repository).summarize(
            start=W_START, end=W_START + timedelta(days=1)
        )
        self.assertEqual(inside["incidents"]["total"], 1)
        # window whose end lands exactly on creation time → excluded
        # (end is exclusive), even though start is one hour earlier
        empty = OperationalAnalyticsService(self.repository).summarize(
            start=W_START + timedelta(hours=1), end=W_START + timedelta(hours=2)
        )
        self.assertEqual(empty["incidents"]["total"], 0)
        # window starting exactly at creation time → included (start inclusive)
        at_start = OperationalAnalyticsService(self.repository).summarize(
            start=W_START + timedelta(hours=2), end=W_START + timedelta(hours=3)
        )
        self.assertEqual(at_start["incidents"]["total"], 1)
        # empty window still returns the full shape
        self.assertIn("data_quality", empty)
        self.assertIn("unsupported", empty)


if __name__ == "__main__":
    unittest.main()
