"""Phase 6.6.1 — durable progressive-release gate analysis state.

The gate remains read-only with respect to deployment control. Each evaluation
is a durable, immutable analysis record derived from a fresh Phase 6.5 live
assessment. Persistence is for audit/history/recovery; a stored record is
never treated as authorization for a later rollout action.

The design mirrors the useful part of progressive-delivery analysis systems:
an analysis result is a first-class durable observation, while actual traffic
mutation remains a separate controller concern.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from incident_service.application.services.live_release_verification_service import (
    LiveReleaseVerificationService,
)

ALLOWED_EXPOSURE_PERCENTAGES: Tuple[int, ...] = (5, 25, 50, 100)
BASELINE_REQUIRED_AFTER_PERCENT = 5
GATE_POLICY_VERSION = "6.6.1"
GATE_EVALUATION_TTL_SECONDS = 900


class InvalidProgressiveReleaseGateRequest(ValueError):
    """Raised when a progressive-release gate request is malformed."""


@dataclass(frozen=True)
class ProgressiveReleaseGateAssessment:
    evaluation_id: str
    deployment_run_id: str
    source_sha: str
    target_percentage: int
    gate_decision: str
    health_decision: str
    reasons: Tuple[str, ...]
    live_assessment: Dict[str, Any]
    baseline_deployment_run_id: Optional[str]
    baseline_source_sha: Optional[str]
    observed_at: datetime
    expires_at: datetime
    fresh: bool
    reused: bool
    policy_version: str = GATE_POLICY_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evaluation_id": self.evaluation_id,
            "deployment_run_id": self.deployment_run_id,
            "source_sha": self.source_sha,
            "target_percentage": self.target_percentage,
            "gate_decision": self.gate_decision,
            "health_decision": self.health_decision,
            "reasons": list(self.reasons),
            "live_assessment": dict(self.live_assessment),
            "baseline_deployment_run_id": self.baseline_deployment_run_id,
            "baseline_source_sha": self.baseline_source_sha,
            "observed_at": self.observed_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "fresh": self.fresh,
            "reused": self.reused,
            "policy_version": self.policy_version,
        }


def _validate_target_percentage(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise InvalidProgressiveReleaseGateRequest(
            "target_percentage must be an integer"
        )
    if value not in ALLOWED_EXPOSURE_PERCENTAGES:
        allowed = ", ".join(str(item) for item in ALLOWED_EXPOSURE_PERCENTAGES)
        raise InvalidProgressiveReleaseGateRequest(
            f"target_percentage must be one of: {allowed}"
        )
    return value


def _validate_baseline_deployment_id(
    value: Optional[str],
) -> Optional[str]:
    if value is not None and not isinstance(value, str):
        raise InvalidProgressiveReleaseGateRequest(
            "baseline_deployment_run_id must be a string or null"
        )
    if value is not None and not value.strip():
        raise InvalidProgressiveReleaseGateRequest(
            "baseline_deployment_run_id must not be empty"
        )
    return value


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _fingerprint(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


class ProgressiveReleaseGateService:
    """Durable, read-only gate analysis over authoritative live evidence."""

    def __init__(self, repository, prometheus, *, now_factory=None):
        self.repository = repository
        self.prometheus = prometheus
        self.now_factory = now_factory or (lambda: datetime.now(timezone.utc))

    @staticmethod
    def _gate_decision(health_decision: str) -> str:
        return {
            "HEALTHY": "PROMOTE",
            "DEGRADED": "PAUSE",
            "FAILED": "ABORT",
            "INCONCLUSIVE": "INCONCLUSIVE",
        }.get(health_decision, "INCONCLUSIVE")

    def evaluate(
        self,
        deployment_run_id: str,
        start: datetime,
        end: datetime,
        target_percentage: int,
        baseline_deployment_run_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        target_percentage = _validate_target_percentage(target_percentage)
        baseline_deployment_run_id = _validate_baseline_deployment_id(
            baseline_deployment_run_id
        )

        if (
            target_percentage > BASELINE_REQUIRED_AFTER_PERCENT
            and not baseline_deployment_run_id
        ):
            raise InvalidProgressiveReleaseGateRequest(
                "an explicit baseline deployment is required for exposure "
                f"above {BASELINE_REQUIRED_AFTER_PERCENT}%"
            )

        result = LiveReleaseVerificationService(
            self.repository, self.prometheus
        ).verify(
            deployment_run_id=deployment_run_id,
            start=start,
            end=end,
            baseline_deployment_run_id=baseline_deployment_run_id,
        )

        live = result["live_assessment"]
        identity = dict(live.get("release_identity") or {})
        authoritative_run_id = str(identity.get("deployment_run_id") or "")
        source_sha = str(identity.get("source_sha") or "").lower()

        if authoritative_run_id != deployment_run_id:
            raise InvalidProgressiveReleaseGateRequest(
                "live evidence deployment identity does not match requested deployment"
            )
        if len(source_sha) != 40:
            raise InvalidProgressiveReleaseGateRequest(
                "authoritative source SHA is unavailable"
            )

        health_decision = str(live.get("decision") or "INCONCLUSIVE")
        gate_decision = self._gate_decision(health_decision)
        baseline_identity = live.get("baseline_identity") or {}
        baseline_source_sha = (
            str(baseline_identity.get("source_sha") or "").lower() or None
        )
        now = _utc(self.now_factory())
        observation_start = _utc(start)
        observation_end = _utc(end)

        request_fingerprint = _fingerprint(
            {
                "deployment_run_id": deployment_run_id,
                "source_sha": source_sha,
                "repository_name": str(identity.get("repository_name") or ""),
                "target_percentage": target_percentage,
                "observation_start": observation_start.isoformat(),
                "observation_end": observation_end.isoformat(),
                "baseline_deployment_run_id": baseline_deployment_run_id,
                "baseline_source_sha": baseline_source_sha,
                "policy_version": GATE_POLICY_VERSION,
            }
        )
        assessment_fingerprint = _fingerprint(live)

        # A slot makes repeated identical evaluations idempotent for the
        # 15-minute freshness window. The repository treats the timestamps
        # as immutable metadata but deliberately does not make them part of
        # the identity-conflict comparison.
        slot = int(now.timestamp()) // GATE_EVALUATION_TTL_SECONDS
        evaluation_id = _fingerprint(
            {
                "request": request_fingerprint,
                "assessment": assessment_fingerprint,
                "slot": slot,
            }
        )
        expires_at = now + timedelta(seconds=GATE_EVALUATION_TTL_SECONDS)

        record = {
            "evaluation_id": evaluation_id,
            "deployment_run_id": deployment_run_id,
            "source_sha": source_sha,
            "repository_name": str(identity.get("repository_name") or ""),
            "target_percentage": target_percentage,
            "observation_start": observation_start,
            "observation_end": observation_end,
            "baseline_deployment_run_id": baseline_deployment_run_id,
            "baseline_source_sha": baseline_source_sha,
            "health_decision": health_decision,
            "gate_decision": gate_decision,
            "reasons": list(live.get("reasons") or []),
            "live_assessment": live,
            "policy_version": GATE_POLICY_VERSION,
            "request_fingerprint": request_fingerprint,
            "assessment_fingerprint": assessment_fingerprint,
            "observed_at": now,
            "expires_at": expires_at,
        }

        saved = self.repository.save_progressive_release_gate_evaluation(record)
        reused = _utc(saved["observed_at"]) != now

        assessment = ProgressiveReleaseGateAssessment(
            evaluation_id=str(saved["evaluation_id"]),
            deployment_run_id=str(saved["deployment_run_id"]),
            source_sha=str(saved["source_sha"]),
            target_percentage=int(saved["target_percentage"]),
            gate_decision=str(saved["gate_decision"]),
            health_decision=str(saved["health_decision"]),
            reasons=tuple(str(reason) for reason in saved["reasons"]),
            live_assessment=dict(saved["live_assessment"]),
            baseline_deployment_run_id=saved.get("baseline_deployment_run_id"),
            baseline_source_sha=saved.get("baseline_source_sha"),
            observed_at=_utc(saved["observed_at"]),
            expires_at=_utc(saved["expires_at"]),
            fresh=_utc(saved["expires_at"]) > now,
            reused=reused,
        )
        output = assessment.to_dict()
        # Preserve the unchanged Phase 6.4 result for callers that already
        # consume the combined Phase 6.5 read model.
        output["durable_assessment"] = result["durable_assessment"]
        return output

    def history(self, deployment_run_id: str, limit: int = 50) -> Dict[str, Any]:
        if not isinstance(deployment_run_id, str) or not deployment_run_id.strip():
            raise InvalidProgressiveReleaseGateRequest(
                "deployment_run_id must be a non-empty string"
            )
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= 100
        ):
            raise InvalidProgressiveReleaseGateRequest(
                "limit must be an integer between 1 and 100"
            )

        now = _utc(self.now_factory())
        rows = self.repository.get_progressive_release_gate_evaluations(
            deployment_run_id, limit
        )
        evaluations = []
        for row in rows:
            item = dict(row)
            item["observed_at"] = _utc(row["observed_at"]).isoformat()
            item["expires_at"] = _utc(row["expires_at"]).isoformat()
            item["fresh"] = _utc(row["expires_at"]) > now
            evaluations.append(item)

        return {
            "deployment_run_id": deployment_run_id,
            "count": len(evaluations),
            "evaluations": evaluations,
            "policy_version": GATE_POLICY_VERSION,
        }


__all__ = [
    "ALLOWED_EXPOSURE_PERCENTAGES",
    "BASELINE_REQUIRED_AFTER_PERCENT",
    "GATE_EVALUATION_TTL_SECONDS",
    "GATE_POLICY_VERSION",
    "InvalidProgressiveReleaseGateRequest",
    "ProgressiveReleaseGateAssessment",
    "ProgressiveReleaseGateService",
]
