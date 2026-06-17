from abc import ABC, abstractmethod
from typing import Optional, List
from .aggregates.repository import RepositoryAggregate

class RepositoryPersistencePort(ABC):
    """
    Interface definition (Port) for persistence adapters.
    Injectable standard mapping domain entity state to and from SQL engines.
    """
    @abstractmethod
    def save(self, repository: RepositoryAggregate) -> None:
        """Persists the aggregate root and resolves pending domain events."""
        pass

    @abstractmethod
    def find_by_id(self, id: str) -> Optional[RepositoryAggregate]:
        """Loads a hydrated Repository aggregate based on unique ID."""
        pass

    @abstractmethod
    def find_by_name(self, name: str) -> Optional[RepositoryAggregate]:
        """Resolves an aggregate utilizing plain names."""
        pass

    @abstractmethod
    def list_all(self) -> List[RepositoryAggregate]:
        """Fetches all repository trackers loaded in system scope."""
        pass
