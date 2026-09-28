"""Phase 6.3 — evidence-driven operational analytics (read-only).

One application service owns window validation, aggregation and the typed
result DTOs for a single summary endpoint. Every number is derived from
durable authoritative records only:

* incidents: ``devops_incidents`` rows (id, created_at, severity, status)
* RCA coverage: ``kind="rca_result"`` evidence records (category
  distribution is UNSUPPORTED — ``root_cause`` is free text)
* remediation outcomes: durable proposal ``status``/``approved_at``/
  ``pull_request_url`` plus the LATEST ``kind="remediation_execution"``
  evidence payload (``stages`` = durable notify progression for the
  finished attempt, ``observed_at`` = attempt completion time)
* timing: ``generated_at → approved_at`` and ``approved_at →`` latest
  execution evidence ``observed_at`` (the only intervals where BOTH
  timestamps are durable and semantically compatible)

Explicitly UNSUPPORTED (never inferred): incident counts by service
(no dedicated field), RCA category histogram, proposal rejected/expired
counts (never persisted — the approval TTL only gates approval), recovery
and recurrence outcomes (no durable identity), and every other timing
interval (no durable timestamps; ``HotfixProposal.executed_at`` is never
written in production).

Determinism rules: bounded half-open UTC window ``[start, end)`` of at
most 31 days; explicit sorts everywhere; percentile definition =
nearest-rank (p50/p95) over integer-second samples with the sample and
exclusion counts always visible; no percentages are exposed (there is no
supported categorical distribution to divide by); data-quality exclusion
counters are always present in every response; aggregation is pure (no
clock reads — the window is fully caller-specified).
"""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from math import ceil
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from incident_service.application.services.proposal_execution_policy import (
    EXECUTION_STAGES,
)
from incident_service.application.services.proposal_execution_service import (
    EXECUTION_EVIDENCE_KIND,
)
from incident_service.domain.aggregates.incident import IncidentAggregate
from incident_service.domain.entities.hotfix_proposal import HotfixProposal
from incident_service.domain.repository_interface import IncidentRepositoryPort

try:  # §17: analytics-system self-observability only (never a data source)
    from shared_kernel.infrastructure.metrics.prometheus_metrics import (
        analytics_summary_requests,
    )
except Exception:  # pragma: no cover - metrics must never break queries
    analytics_summary_requests = None

# Mirrors the evidence kind written by ``investigate_root_cause``
# (presentation layer writes ``kind="rca_result"``).
RCA_EVIDENCE_KIND = "rca_result"

MAX_WINDOW_DAYS = 31
_ONE_DAY = timedelta(days=1)
_MAX_WINDOW = timedelta(days=MAX_WINDOW_DAYS)

# Orchestration notify vocabulary (durable stage progression persisted in
# execution-evidence ``stages``) — membership checks only, no inference.
_NOTIFY_PR_CREATED = "pr.created"
_NOTIFY_PR_RECONCILED = "pr.reconciled"
_NOTIFY_COMMIT_CREATED = "commit.created"
_NOTIFY_REMOTE_PUBLISHED = "remote.published"
_NOTIFY_VALIDATION_STARTED = "validation.started"
_NOTIFY_VALIDATION_COMPLETED = "validation.completed"

# Fixed data-quality reason vocabulary — every counter always present in
# each response (count zero unless stated). Counters are keyed
# "<scope>:<reason>" internally so identically named reasons in different
# scopes never collide.
_DQ_REASONS: Tuple[Tuple[str, str], ...] = (
    ("window", "incident_outside_window"),
    ("rca_coverage", "rca_evidence_malformed"),
    ("execution", "execution_evidence_missing"),
    ("execution", "execution_evidence_malformed"),
    ("execution", "execution_evidence_unmatched"),
    ("execution", "execution_stages_malformed"),
    ("failures_by_stage", "missing_last_failure_stage"),
    ("timing_proposal_to_approval", "missing_generated_at"),
    ("timing_proposal_to_approval", "negative_duration"),
    ("timing_approval_to_completion", "execution_completion_missing"),
    ("timing_approval_to_completion", "negative_duration"),
    ("timing_approval_to_completion", "evidence_payload_malformed"),
)


def _dq_key(scope: str, reason: str) -> str:
    return f"{scope}:{reason}"


class InvalidAnalyticsWindowError(ValueError):
    """Raised when the requested window is outside the supported contract."""


def _aware_utc(value: datetime) -> datetime:
    """Normalize to aware UTC; naive values are assumed UTC (repo convention)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _nearest_rank(sorted_values: Sequence[int], percentile: float) -> Optional[int]:
    """Nearest-rank percentile (ceil(p*n)-1) over an ascending sample."""
    if not sorted_values:
        return None
    rank = max(1, int(ceil(percentile * len(sorted_values))))
    return sorted_values[min(rank, len(sorted_values)) - 1]


def _last_stage_metadata(
    stages: Sequence[Any], notify_name: str
) -> Optional[Mapping[str, Any]]:
    """Metadata of the LAST occurrence of ``notify_name`` (deterministic)."""
    for entry in reversed(stages):
        if isinstance(entry, Mapping) and entry.get("stage") == notify_name:
            metadata = entry.get("metadata")
            return metadata if isinstance(metadata, Mapping) else {}
    return None


def _has_stage(stages: Sequence[Any], notify_name: str) -> bool:
    return _last_stage_metadata(stages, notify_name) is not None or any(
        isinstance(entry, Mapping) and entry.get("stage") == notify_name
        for entry in stages
    )


@dataclass(frozen=True)
class TimingStats:
    """Percentile summary with its exclusion accounting attached."""

    sample_count: int
    excluded_count: int
    p50_seconds: Optional[int]
    p95_seconds: Optional[int]

    @classmethod
    def from_samples(
        cls, samples: Sequence[int], excluded_count: int
    ) -> "TimingStats":
        ordered = sorted(int(value) for value in samples)
        return cls(
            sample_count=len(ordered),
            excluded_count=int(excluded_count),
            p50_seconds=_nearest_rank(ordered, 0.50),
            p95_seconds=_nearest_rank(ordered, 0.95),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample_count": self.sample_count,
            "excluded_count": self.excluded_count,
            "p50_seconds": self.p50_seconds,
            "p95_seconds": self.p95_seconds,
        }


@dataclass(frozen=True)
class PhaseCounts:
    """Per-proposal partition of one pipeline phase (invariant total)."""

    succeeded: int
    failed: int
    not_reached: int

    @classmethod
    def from_buckets(cls, buckets: Counter) -> "PhaseCounts":
        return cls(
            succeeded=int(buckets.get("succeeded", 0)),
            failed=int(buckets.get("failed", 0)),
            not_reached=int(buckets.get("not_reached", 0)),
        )

    def to_dict(self) -> Dict[str, int]:
        return {
            "succeeded": self.succeeded,
            "failed": self.failed,
            "not_reached": self.not_reached,
        }


@dataclass(frozen=True)
class IncidentSection:
    total: int
    by_severity: Dict[str, int]
    by_status: Dict[str, int]
    timeseries: Tuple[Tuple[str, int], ...]
    reached_rca: int
    without_rca: int
    rca_malformed: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "by_severity": dict(self.by_severity),
            "by_status": dict(self.by_status),
            "timeseries": [
                {"date": day, "count": count} for day, count in self.timeseries
            ],
            "reached_rca": self.reached_rca,
            "without_rca": self.without_rca,
            "rca_malformed": self.rca_malformed,
        }


@dataclass(frozen=True)
class RemediationSection:
    proposals_created: int
    by_status: Dict[str, int]
    approved: int
    validation: PhaseCounts
    commit: PhaseCounts
    publication: PhaseCounts
    pull_request: PhaseCounts
    failures_by_stage: Tuple[Tuple[str, int], ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proposals_created": self.proposals_created,
            "by_status": dict(self.by_status),
            "approved": self.approved,
            "validation": self.validation.to_dict(),
            "commit": self.commit.to_dict(),
            "publication": self.publication.to_dict(),
            "pull_request": {
                "created": self.pull_request.succeeded,
                "failed": self.pull_request.failed,
                "not_reached": self.pull_request.not_reached,
            },
            "failures_by_stage": [
                {"stage": stage, "count": count}
                for stage, count in self.failures_by_stage
            ],
        }


@dataclass(frozen=True)
class TimingSection:
    proposal_to_approval: TimingStats
    approval_to_execution_completion: TimingStats
    unsupported_intervals: Tuple[Dict[str, str], ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proposal_to_approval": self.proposal_to_approval.to_dict(),
            "approval_to_execution_completion": (
                self.approval_to_execution_completion.to_dict()
            ),
            "unsupported_intervals": [dict(item) for item in self.unsupported_intervals],
        }


@dataclass(frozen=True)
class DataQualitySection:
    incidents_considered: int
    exclusions: Tuple[Dict[str, Any], ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incidents_considered": self.incidents_considered,
            "exclusions": [dict(item) for item in self.exclusions],
        }


@dataclass(frozen=True)
class OperationalAnalyticsSummary:
    """Typed summary for one bounded window (serialized by ``to_dict``)."""

    start: datetime
    end: datetime
    incidents: IncidentSection
    remediation: RemediationSection
    timing: TimingSection
    data_quality: DataQualitySection
    unsupported: Tuple[Dict[str, str], ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "window": {
                "start": self.start.isoformat(),
                "end": self.end.isoformat(),
                "timezone": "UTC",
                "max_days": MAX_WINDOW_DAYS,
            },
            "incidents": self.incidents.to_dict(),
            "remediation": self.remediation.to_dict(),
            "timing": self.timing.to_dict(),
            "data_quality": self.data_quality.to_dict(),
            "unsupported": [dict(item) for item in self.unsupported],
        }


class OperationalAnalyticsService:
    """Window-validated, read-only aggregation over durable incident records."""

    def __init__(self, repository: IncidentRepositoryPort) -> None:
        self._repository = repository

    def summarize(self, *, start: datetime, end: datetime) -> Dict[str, Any]:
        """Validate the window, aggregate, and return the JSON-ready summary."""
        try:
            window_start, window_end = self._validate_window(start, end)
            summary = self._build(window_start, window_end)
        except InvalidAnalyticsWindowError:
            self._observe("window_rejected")
            raise
        self._observe("ok")
        return summary.to_dict()

    # ------------------------------------------------------------------ #
    # Window contract: [start, end), aware UTC, at most 31 days.
    # ------------------------------------------------------------------ #
    @staticmethod
    def _validate_window(start: datetime, end: datetime) -> Tuple[datetime, datetime]:
        if not isinstance(start, datetime) or not isinstance(end, datetime):
            raise InvalidAnalyticsWindowError("start and end must be datetimes")
        window_start = _aware_utc(start)
        window_end = _aware_utc(end)
        if window_start >= window_end:
            raise InvalidAnalyticsWindowError(
                "start must be strictly before end (half-open [start, end) window)"
            )
        if window_end - window_start > _MAX_WINDOW:
            raise InvalidAnalyticsWindowError(
                f"window must not exceed {MAX_WINDOW_DAYS} days"
            )
        return window_start, window_end

    # ------------------------------------------------------------------ #
    # Aggregation
    # ------------------------------------------------------------------ #
    def _build(self, start: datetime, end: datetime) -> OperationalAnalyticsSummary:
        incidents = self._repository.list_incidents_in_window(start, end)
        exclusions: Counter = Counter()

        accepted: List[IncidentAggregate] = []
        for incident in incidents:
            created_at = _aware_utc(incident.created_at)
            if start <= created_at < end:
                accepted.append(incident)
            else:
                exclusions[_dq_key("window", "incident_outside_window")] += 1

        incident_section = self._incident_section(accepted, start, end, exclusions)
        evidence_maps: Dict[str, Dict[str, Any]] = {
            incident.id: self._latest_execution_evidence(incident, exclusions)
            for incident in accepted
        }
        remediation_section = self._remediation_section(
            accepted, evidence_maps, exclusions
        )
        timing_section = self._timing_section(accepted, evidence_maps, exclusions)

        dq_exclusions = tuple(
            {
                "scope": scope,
                "reason": reason,
                "count": int(exclusions.get(_dq_key(scope, reason), 0)),
            }
            for scope, reason in _DQ_REASONS
        )
        data_quality = DataQualitySection(
            incidents_considered=len(incidents),
            exclusions=dq_exclusions,
        )
        return OperationalAnalyticsSummary(
            start=start,
            end=end,
            incidents=incident_section,
            remediation=remediation_section,
            timing=timing_section,
            data_quality=data_quality,
            unsupported=self._unsupported(),
        )

    def _incident_section(
        self,
        incidents: Sequence[IncidentAggregate],
        start: datetime,
        end: datetime,
        exclusions: Counter,
    ) -> IncidentSection:
        by_severity: Counter = Counter()
        by_status: Counter = Counter()
        per_day: Counter = Counter()
        reached_rca = 0
        rca_malformed = 0

        for incident in incidents:
            by_severity[str(incident.severity)] += 1
            by_status[str(incident.status)] += 1
            per_day[_aware_utc(incident.created_at).date().isoformat()] += 1
            rca_evidence = [
                item for item in incident.evidence if item.kind == RCA_EVIDENCE_KIND
            ]
            if not rca_evidence:
                continue
            # Deterministic choice when several exist: the latest observed.
            latest = sorted(
                rca_evidence, key=lambda item: (item.observed_at, item.id)
            )[-1]
            if isinstance(latest.payload, Mapping):
                reached_rca += 1
            else:
                rca_malformed += 1
                exclusions[_dq_key("rca_coverage", "rca_evidence_malformed")] += 1

        timeseries: List[Tuple[str, int]] = []
        day = start.date()
        last_day = (end - timedelta(microseconds=1)).date()
        while day <= last_day:
            timeseries.append((day.isoformat(), int(per_day.get(day.isoformat(), 0))))
            day += _ONE_DAY

        total = len(incidents)
        return IncidentSection(
            total=total,
            by_severity={key: by_severity[key] for key in sorted(by_severity)},
            by_status={key: by_status[key] for key in sorted(by_status)},
            timeseries=tuple(timeseries),
            reached_rca=reached_rca,
            without_rca=total - reached_rca - rca_malformed,
            rca_malformed=rca_malformed,
        )

    @staticmethod
    def _latest_execution_evidence(
        incident: IncidentAggregate, exclusions: Counter
    ) -> Dict[str, Any]:
        """proposal_id → latest finished-attempt evidence (deterministic).

        Also records data-quality counters for unusable execution-evidence
        records (malformed payload / no proposal id / unknown proposal id)
        so every record is accounted for.
        """
        latest: Dict[str, Any] = {}
        known_proposal_ids = {
            proposal.id for proposal in incident.patch_proposals
        }
        for item in incident.evidence:
            if item.kind != EXECUTION_EVIDENCE_KIND:
                continue
            payload = item.payload
            if not isinstance(payload, Mapping):
                exclusions[_dq_key("execution", "execution_evidence_malformed")] += 1
                continue
            proposal_id = str(payload.get("proposal_id") or "")
            if not proposal_id:
                exclusions[_dq_key("execution", "execution_evidence_unmatched")] += 1
                continue
            if proposal_id not in known_proposal_ids:
                exclusions[_dq_key("execution", "execution_evidence_unmatched")] += 1
                continue
            current = latest.get(proposal_id)
            key = (_aware_utc(item.observed_at), str(item.id))
            if current is None or key > current["key"]:
                latest[proposal_id] = {"key": key, "item": item, "payload": payload}
        return latest

    def _remediation_section(
        self,
        incidents: Sequence[IncidentAggregate],
        evidence_maps: Mapping[str, Mapping[str, Any]],
        exclusions: Counter,
    ) -> RemediationSection:
        by_status: Counter = Counter()
        failures_by_stage: Counter = Counter()
        phase_buckets = {
            "validation": Counter(),
            "commit": Counter(),
            "publication": Counter(),
            "pull_request": Counter(),
        }
        proposals_created = 0
        approved = 0

        for incident in incidents:
            evidence_by_proposal = evidence_maps.get(incident.id, {})
            for proposal in incident.patch_proposals:
                proposals_created += 1
                by_status[str(proposal.status)] += 1
                if proposal.approved_at is not None:
                    approved += 1

                if str(proposal.status) == "EXECUTION_FAILED":
                    failure_stage = str(proposal.last_failure_stage or "").strip()
                    if failure_stage:
                        failures_by_stage[failure_stage] += 1
                    else:
                        exclusions[
                            _dq_key("failures_by_stage", "missing_last_failure_stage")
                        ] += 1

                evidence = evidence_by_proposal.get(proposal.id)
                if evidence is None and str(proposal.status) == "EXECUTION_FAILED":
                    exclusions[_dq_key("execution", "execution_evidence_missing")] += 1
                self._classify_phases(
                    proposal=proposal,
                    evidence=evidence,
                    buckets=phase_buckets,
                    exclusions=exclusions,
                )

        # Note: data-quality counters for unusable execution-evidence
        # records (malformed/unmatched) are recorded inside
        # ``_latest_execution_evidence`` — one scan, no double counting.

        return RemediationSection(
            proposals_created=proposals_created,
            by_status={key: by_status[key] for key in sorted(by_status)},
            approved=approved,
            validation=PhaseCounts.from_buckets(phase_buckets["validation"]),
            commit=PhaseCounts.from_buckets(phase_buckets["commit"]),
            publication=PhaseCounts.from_buckets(phase_buckets["publication"]),
            pull_request=PhaseCounts.from_buckets(phase_buckets["pull_request"]),
            failures_by_stage=tuple(sorted(failures_by_stage.items())),
        )

    @staticmethod
    def _classify_phases(
        *,
        proposal: HotfixProposal,
        evidence: Optional[Mapping[str, Any]],
        buckets: Dict[str, Counter],
        exclusions: Counter,
    ) -> None:
        """Partition every proposal into exactly one bucket per phase.

        Phase facts come from the durable proposal status plus the latest
        execution-evidence ``stages`` notify progression (membership and
        ``validation.completed.passed`` only — never inferred values).
        """
        status = str(proposal.status)
        stages: Sequence[Any] = ()
        if evidence is not None:
            payload = evidence["payload"]
            raw_stages = payload.get("stages")
            if isinstance(raw_stages, list):
                stages = raw_stages
            else:
                exclusions[_dq_key("execution", "execution_stages_malformed")] += 1

        pipeline_succeeded = status == "PR_CREATED"

        # --- validation ------------------------------------------------
        completed = _last_stage_metadata(stages, _NOTIFY_VALIDATION_COMPLETED)
        validation_passed = pipeline_succeeded or (
            completed is not None and bool(completed.get("passed"))
        )
        validation_failed = False
        if status == "EXECUTION_FAILED":
            if completed is not None and not bool(completed.get("passed")):
                validation_failed = True
            elif not validation_passed and _has_stage(
                stages, _NOTIFY_VALIDATION_STARTED
            ):
                validation_failed = True
        if validation_passed:
            buckets["validation"]["succeeded"] += 1
        elif validation_failed:
            buckets["validation"]["failed"] += 1
        else:
            buckets["validation"]["not_reached"] += 1

        # --- commit ----------------------------------------------------
        if pipeline_succeeded or _has_stage(stages, _NOTIFY_COMMIT_CREATED):
            buckets["commit"]["succeeded"] += 1
        elif status == "EXECUTION_FAILED" and validation_passed:
            buckets["commit"]["failed"] += 1
        else:
            buckets["commit"]["not_reached"] += 1

        # --- publication -----------------------------------------------
        if pipeline_succeeded or _has_stage(stages, _NOTIFY_REMOTE_PUBLISHED):
            buckets["publication"]["succeeded"] += 1
        elif (
            status == "EXECUTION_FAILED"
            and _has_stage(stages, _NOTIFY_COMMIT_CREATED)
        ):
            buckets["publication"]["failed"] += 1
        else:
            buckets["publication"]["not_reached"] += 1

        # --- pull request ----------------------------------------------
        pr_created = (
            pipeline_succeeded
            or bool(str(proposal.pull_request_url or "").strip())
            or _has_stage(stages, _NOTIFY_PR_CREATED)
            or _has_stage(stages, _NOTIFY_PR_RECONCILED)
        )
        if pr_created:
            buckets["pull_request"]["succeeded"] += 1
        elif status == "EXECUTION_FAILED" and _has_stage(
            stages, _NOTIFY_REMOTE_PUBLISHED
        ):
            buckets["pull_request"]["failed"] += 1
        else:
            buckets["pull_request"]["not_reached"] += 1

    def _timing_section(
        self,
        incidents: Sequence[IncidentAggregate],
        evidence_maps: Mapping[str, Mapping[str, Any]],
        exclusions: Counter,
    ) -> TimingSection:
        approval_samples: List[int] = []
        completion_samples: List[int] = []
        approval_scope = "timing_proposal_to_approval"
        completion_scope = "timing_approval_to_completion"

        for incident in incidents:
            evidence_by_proposal = evidence_maps.get(incident.id, {})
            for proposal in incident.patch_proposals:
                approved_at = proposal.approved_at
                if approved_at is None:
                    # Not part of the approval-timing population (a proposal
                    # that was never approved has no approval duration).
                    continue
                approved_utc = _aware_utc(approved_at)

                generated_at = proposal.generated_at
                if generated_at is None:
                    exclusions[_dq_key(approval_scope, "missing_generated_at")] += 1
                else:
                    delta = (approved_utc - _aware_utc(generated_at)).total_seconds()
                    if delta < 0:
                        exclusions[_dq_key(approval_scope, "negative_duration")] += 1
                    else:
                        approval_samples.append(int(round(delta)))

                evidence = evidence_by_proposal.get(proposal.id)
                if evidence is None:
                    exclusions[
                        _dq_key(completion_scope, "execution_completion_missing")
                    ] += 1
                    continue
                observed = _aware_utc(evidence["item"].observed_at)
                delta = (observed - approved_utc).total_seconds()
                if delta < 0:
                    exclusions[_dq_key(completion_scope, "negative_duration")] += 1
                else:
                    completion_samples.append(int(round(delta)))

        approval_excluded = sum(
            exclusions.get(_dq_key(approval_scope, reason), 0)
            for reason in ("missing_generated_at", "negative_duration")
        )
        completion_excluded = sum(
            exclusions.get(_dq_key(completion_scope, reason), 0)
            for reason in (
                "execution_completion_missing",
                "negative_duration",
                "evidence_payload_malformed",
            )
        )
        return TimingSection(
            proposal_to_approval=TimingStats.from_samples(
                approval_samples, approval_excluded
            ),
            approval_to_execution_completion=TimingStats.from_samples(
                completion_samples, completion_excluded
            ),
            unsupported_intervals=self._unsupported_intervals(),
        )

    # ------------------------------------------------------------------ #
    # Explicit UNSUPPORTED manifest (no fabrication — see module docstring)
    # ------------------------------------------------------------------ #
    @staticmethod
    def _unsupported_intervals() -> Tuple[Dict[str, str], ...]:
        intervals = (
            (
                "approval_to_validation",
                "no durable validation-start timestamp",
            ),
            (
                "validation_to_commit",
                "no durable commit timestamp independent of validation completion",
            ),
            (
                "commit_to_publication",
                "no durable publication timestamp on the proposal record",
            ),
            (
                "publication_to_pull_request",
                "no durable pull-request creation timestamp",
            ),
            (
                "proposal_to_pull_request",
                "no durable pull-request creation timestamp "
                "(HotfixProposal.executed_at is never written in production)",
            ),
        )
        return tuple(
            {
                "interval": name,
                "reason": reason,
                "would_require": "a durable timestamp for the boundary stage "
                "persisted alongside the stage progression",
            }
            for name, reason in intervals
        )

    @staticmethod
    def _unsupported() -> Tuple[Dict[str, str], ...]:
        entries = (
            {
                "metric": "incidents_by_service",
                "reason": "incidents carry no dedicated service/component field "
                "(only free-text title/context details)",
                "would_require": "a durable per-incident service or component "
                "field populated at ingestion",
            },
            {
                "metric": "rca_category_distribution",
                "reason": "RCA root_cause is free text with no canonical "
                "category vocabulary (never guessed from wording)",
                "would_require": "a persisted RCA category enum produced by "
                "the RCA pipeline",
            },
            {
                "metric": "proposals_rejected",
                "reason": "a REJECTED status is never persisted on any "
                "proposal record",
                "would_require": "durable approval-decision records with an "
                "explicit rejection status",
            },
            {
                "metric": "proposals_expired",
                "reason": "the approval TTL only gates approval attempts; no "
                "expiry outcome or timestamp is persisted",
                "would_require": "a durable expiry marker recorded when the "
                "TTL lapses",
            },
            {
                "metric": "recovery_outcome_distribution",
                "reason": "no durable RECOVERED/RECURRED outcome or "
                "recovered-at timestamp exists on incidents",
                "would_require": "durable recovery state transitions per "
                "incident",
            },
            {
                "metric": "incident_recurrence",
                "reason": "no incident fingerprint, correlation id, or "
                "durable service identity links repeat occurrences",
                "would_require": "a durable deterministic identity (fingerprint) "
                "per incident",
            },
        )
        return entries

    # ------------------------------------------------------------------ #
    # §17 self-observability (bounded label vocabulary; never a data source)
    # ------------------------------------------------------------------ #
    @staticmethod
    def _observe(outcome: str) -> None:
        if analytics_summary_requests is None:
            return
        try:
            analytics_summary_requests.labels(outcome=outcome).inc()
        except Exception:  # pragma: no cover - metrics must never fail queries
            pass
