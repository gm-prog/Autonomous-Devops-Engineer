from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, List
from .aggregates.incident import IncidentAggregate

class IncidentRepositoryPort(ABC):
    """Port interface locking database logic from application transaction workflows."""
    @abstractmethod
    def save_incident(self, incident: IncidentAggregate) -> None:
        pass

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

    @abstractmethod
    def save_progressive_release_gate_evaluation(self, evaluation: dict) -> dict:
        pass

    @abstractmethod
    def get_progressive_release_gate_evaluations(self, deployment_run_id: str, limit: int = 50) -> List[dict]:
        pass
