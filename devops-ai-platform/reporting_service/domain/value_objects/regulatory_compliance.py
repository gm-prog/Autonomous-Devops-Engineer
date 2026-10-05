from dataclasses import dataclass

@dataclass(frozen=True)
class RegulatoryCompliance:
    """Immutable Value Object storing compliance assertions (e.g. SOC2, HIPAA)."""
    authority: str # e.g. "SOC2", "HIPAA", "PCI-DSS-v4"
    is_supported: bool
    assessing_officer: str = "Autonomous DevOps AI Verification Loop"
