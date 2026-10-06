from ...domain.repository_interface import RepositoryPersistencePort
from typing import Optional, Dict, Any

class GetRepositoryDetailsQuery:
    def __init__(self, repository_id: str):
        self.repository_id = repository_id

class GetRepositoryDetailsQueryHandler:
    def __init__(self, persistence_adapter: RepositoryPersistencePort):
        self.repo = persistence_adapter

    def handle(self, query: GetRepositoryDetailsQuery) -> Optional[Dict[str, Any]]:
        aggregate = self.repo.find_by_id(query.repository_id)
        if not aggregate:
            return None
        
        return {
            "id": aggregate.id,
            "name": aggregate.name,
            "url": aggregate.url.value,
            "status": aggregate.status,
            "created_at": aggregate.created_at.isoformat(),
            "total_files": len(aggregate.files),
            "tech_stack": {
                "language": aggregate.tech_stack.primary_language if aggregate.tech_stack else "Unknown",
                "frameworks": aggregate.tech_stack.detected_frameworks if aggregate.tech_stack else []
            } if aggregate.tech_stack else None
        }
