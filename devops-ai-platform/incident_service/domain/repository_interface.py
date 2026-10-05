from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, List
from .aggregates.incident import IncidentAggregate

class IncidentRepositoryPort(ABC):
    """Port interface locking database logic from application transaction workflows."""
    @abstractmethod
    def save_incident(self, incident: IncidentAggregate) -> None:
        """Persist the aggregate under optimistic concurrency (Phase 8.1).

        The aggregate carries the durable ``version`` it was loaded at.
        Implementations MUST use the database write predicate as the
        authoritative freshness gate (``UPDATE ... WHERE id AND
        version``) and raise ``IncidentConcurrencyConflict`` when zero
        rows match — a stale write is rejected, never silently applied,
        and there is no force/bypass flag for ordinary paths.
        Successful saves advance ``incident.version`` exactly once.
        """

    @abstractmethod
    def get_incident_by_id(self, id: str) -> Optional[IncidentAggregate]:
        pass

    @abstractmethod
    def get_active_incidents(self) -> List[IncidentAggregate]:
        pass

    # Phase 6.3: window-bounded analytics read. `start` is inclusive and
    # `end` is exclusive (half-open UTC interval, caller-validated).
    # Deterministic ordering (created_at ASC, id ASC) so aggregation over
    # the same durable records always yields identical results.
    @abstractmethod
    def list_incidents_in_window(
        self, start: datetime, end: datetime
    ) -> List[IncidentAggregate]:
        pass
