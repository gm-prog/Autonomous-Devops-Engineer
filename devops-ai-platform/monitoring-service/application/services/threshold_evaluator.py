from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping


@dataclass(frozen=True)
class ThresholdRule:
    metric: str
    threshold: float
    operator: str = ">="
    severity: str = "high"

    def matches(self, value: float) -> bool:
        if self.operator == ">=":
            return value >= self.threshold
        if self.operator == ">":
            return value > self.threshold
        if self.operator == "<=":
            return value <= self.threshold
        if self.operator == "<":
            return value < self.threshold
        raise ValueError(f"Unsupported threshold operator: {self.operator}")


class ThresholdEvaluator:
    """Pure threshold evaluation over normalized monitoring metrics."""

    def __init__(self, rules: Iterable[ThresholdRule] | None = None):
        self.rules = tuple(
            rules or (
                ThresholdRule("cpu_percent", 90.0, ">=", "critical"),
                ThresholdRule("latency_ms", 1000.0, ">=", "high"),
            )
        )

    def evaluate(self, metrics: Mapping[str, Any]) -> Dict[str, Any]:
        breaches = []

        for rule in self.rules:
            raw_value = metrics.get(rule.metric)
            if raw_value is None:
                continue

            try:
                value = float(raw_value)
            except (TypeError, ValueError):
                continue

            if rule.matches(value):
                breaches.append({
                    "metric": rule.metric,
                    "value": value,
                    "threshold": rule.threshold,
                    "operator": rule.operator,
                    "severity": rule.severity,
                })

        return {
            "status": "BREACHED" if breaches else "OK",
            "breaches": breaches,
            "severity": self._highest_severity(breaches),
            "breach_count": len(breaches),
        }

    @staticmethod
    def _highest_severity(breaches: list[Dict[str, Any]]) -> str | None:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        highest = None
        highest_rank = 0
        for breach in breaches:
            severity = str(breach["severity"]).lower()
            rank = order.get(severity, 0)
            if rank > highest_rank:
                highest = severity
                highest_rank = rank
        return highest
