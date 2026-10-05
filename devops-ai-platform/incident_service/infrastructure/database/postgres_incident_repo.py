from ...domain.repository_interface import IncidentRepositoryPort
from ...domain.aggregates.incident import IncidentAggregate
from typing import Optional, List

class PostgresIncidentRepositoryAdapter(IncidentRepositoryPort):
    """Adapts pure incident aggregate actions to physical database storage rows."""
    def save_incident(self, incident: IncidentAggregate) -> None:
        # Commit domain aggregate changes to relational tables
        pass

    def get_incident_by_id(self, id: str) -> Optional[IncidentAggregate]:
        return None

    def get_active_incidents(self) -> List[IncidentAggregate]:
        return []
