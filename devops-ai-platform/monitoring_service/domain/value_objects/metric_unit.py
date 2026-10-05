from dataclasses import dataclass

@dataclass(frozen=True)
class MetricUnit:
    """Immutable Value Object modeling valid dimensional measurements."""
    symbol: str # e.g. "%", "ms", "MiB", "RPS"
    description: str

    def format_value(self, val: float) -> str:
        return f"{val:.2f}{self.symbol}"
