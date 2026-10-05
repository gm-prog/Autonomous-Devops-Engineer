from abc import ABC, abstractmethod
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
