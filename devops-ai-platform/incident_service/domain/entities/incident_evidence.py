from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping
import uuid


@dataclass
class IncidentEvidence:
    """Immutable-ish evidence captured from an incident signal for later RCA."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    kind: str = "observation"
    source: str = "unknown"
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    payload: Mapping[str, Any] = field(default_factory=dict)
