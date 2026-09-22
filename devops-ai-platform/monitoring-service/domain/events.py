from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import uuid
from typing import Any, Dict, Mapping


@dataclass(frozen=True)
class ThreatThresholdExceededEvent:
    """Monitoring-domain event emitted for a confirmed metric threshold breach."""

    aggregate_id: str
    payload: Mapping[str, Any]
    event_id: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.event_id:
            object.__setattr__(self, "event_id", str(uuid.uuid4()))
        if not self.timestamp:
            object.__setattr__(
                self,
                "timestamp",
                datetime.now(timezone.utc).isoformat(),
            )

    @property
    def event_type(self) -> str:
        return self.__class__.__name__

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "aggregate_id": self.aggregate_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "payload": dict(self.payload),
        }
