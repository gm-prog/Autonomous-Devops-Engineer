"""Phase 6.6 — deterministic progressive-release gate foundation.

This service is deliberately read-only. It consumes Phase 6.5 live release
verification and maps its evidence-backed decision into a fixed rollout gate:

    HEALTHY       -> PROMOTE
    DEGRADED      -> PAUSE
    FAILED        -> ABORT
    INCONCLUSIVE  -> INCONCLUSIVE

No traffic is shifted, no deployment is mutated, and no rollback is executed
here. The output is a policy decision that a later progressive-delivery
controller may consume.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from incident_service.application.services.live_release_verification_service import (
    LiveReleaseVerificationService,
)

ALLOWED_EXPOSURE_PERCENTAGES: Tuple[int, ...] = (5, 25, 50, 100)
BASELINE_REQUIRED_AFTER_PERCENT: int = 5


class InvalidProgressiveReleaseGateRequest(ValueError):
    """Raised when a requested progressive-release gate is malformed."""


@dataclass(frozen=True)
class ProgressiveReleaseGateAssessment:
    deployment_run_id: str
    target_percentage: int
    gate_decision: str
    health_decision: str
    reasons: Tuple[str, ...]
    live_assessment: Dict[str, Any]
    baseline_deployment_run_id: Optional[str]
    policy: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "deployment_run_id": self.deployment_run_id,
            "target_percentage": self.target_percentage,
            "gate_decision": self.gate_decision,
            "health_decision": self.health_decision,
            "reasons": list(self.reasons),
            "baseline_deployment_run_id": self.baseline_deployment_run_id,
            "live_assessment": dict(self.live_assessment),
            "policy": {
                "allowed_exposure_percentages": list(
                    self.policy["allowed_exposure_percentages"]
                ),
                "baseline_required_after_percent": self.policy[
                    "baseline_required_after_percent"
                ],
            },
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
    """Keep the application boundary strictly typed.

    FastAPI parses the public query parameter before the controller invokes
    this service. Direct callers/tests must follow the same contract: a
    baseline is either omitted/None or a deployment-run identifier string.
    """
    if value is not None and not isinstance(value, str):
        raise InvalidProgressiveReleaseGateRequest(
            "baseline_deployment_run_id must be a string or null"
        )
    return value


class ProgressiveReleaseGateService:
    """Read-only progressive-release gate over the Phase 6.5 verifier."""

    def __init__(self, repository, prometheus):
        self.repository = repository
        self.prometheus = prometheus

    @staticmethod
    def _gate_decision(health_decision: str) -> str:
        mapping = {
            "HEALTHY": "PROMOTE",
            "DEGRADED": "PAUSE",
            "FAILED": "ABORT",
            "INCONCLUSIVE": "INCONCLUSIVE",
        }
        # Unknown health states must never become an approval.
        return mapping.get(health_decision, "INCONCLUSIVE")

    def evaluate(
        self,
        deployment_run_id: str,
        start,
        end,
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
        health_decision = str(live.get("decision") or "INCONCLUSIVE")
        gate_decision = self._gate_decision(health_decision)

        assessment = ProgressiveReleaseGateAssessment(
            deployment_run_id=deployment_run_id,
            target_percentage=target_percentage,
            gate_decision=gate_decision,
            health_decision=health_decision,
            reasons=tuple(str(reason) for reason in (live.get("reasons") or [])),
            live_assessment=live,
            baseline_deployment_run_id=baseline_deployment_run_id,
            policy={
                "allowed_exposure_percentages": ALLOWED_EXPOSURE_PERCENTAGES,
                "baseline_required_after_percent": BASELINE_REQUIRED_AFTER_PERCENT,
            },
        )
        return assessment.to_dict()


__all__ = [
    "ALLOWED_EXPOSURE_PERCENTAGES",
    "BASELINE_REQUIRED_AFTER_PERCENT",
    "InvalidProgressiveReleaseGateRequest",
    "ProgressiveReleaseGateAssessment",
    "ProgressiveReleaseGateService",
]
