from __future__ import annotations

from typing import Any, Mapping

from domain.events import ThreatThresholdExceededEvent


def create_threshold_event(
    service_id: str,
    metrics: Mapping[str, Any],
    evaluation: Mapping[str, Any],
) -> ThreatThresholdExceededEvent | None:
    """Create a domain event only when at least one threshold is breached."""
    if evaluation.get("status") != "BREACHED":
        return None

    return ThreatThresholdExceededEvent(
        aggregate_id=service_id,
        payload={
            "severity": evaluation.get("severity"),
            "breach_count": evaluation.get("breach_count", 0),
            "breaches": evaluation.get("breaches", []),
            "metrics": {
                key: metrics.get(key)
                for key in (
                    "latency_ms",
                    "cpu_percent",
                    "memory_usage_mib",
                    "rps",
                )
            },
        },
    )
