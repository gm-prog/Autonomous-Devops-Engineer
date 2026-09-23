from __future__ import annotations

from datetime import datetime, timezone
import uuid
from typing import Any, Dict, Mapping


class DomainEvent:
    def __init__(
        self,
        aggregate_id: str,
        payload: Mapping[str, Any] | None = None,
    ):
        self.event_id = str(uuid.uuid4())
        self.aggregate_id = aggregate_id
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.payload = dict(payload or {})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "aggregate_id": self.aggregate_id,
            "event_type": self.__class__.__name__,
            "timestamp": self.timestamp,
            "payload": self.payload,
        }


class OutOfBoundsIncidentLoggedEvent(DomainEvent):
    """Raised when an incident aggregate enters the triage workflow."""
