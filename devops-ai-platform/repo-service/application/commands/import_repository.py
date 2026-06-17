from ....shared_kernel.domain.value_objects import RepoUrl
from ...domain.aggregates.repository import RepositoryAggregate
from ...domain.repository_interface import RepositoryPersistencePort
from ...domain.exceptions import DuplicateRepositoryException
import uuid

class ImportRepositoryCommand:
    """Request command envelope to fetch catalog registries."""
    def __init__(self, name: str, url: str):
        self.name = name
        self.url = url

class ImportRepositoryCommandHandler:
    """Executes use case logic mapping input requests into persisted domain models."""
    def __init__(self, persistence_adapter: RepositoryPersistencePort):
        self.repo = persistence_adapter

    def handle(self, cmd: ImportRepositoryCommand) -> str:
        # Check invariants
        existing = self.repo.find_by_name(cmd.name)
        if existing:
            raise DuplicateRepositoryException(f"Repository matching name {cmd.name} exists.")

        # Instantiate Domain Aggregate Root
        target_url = RepoUrl(cmd.url)
        repo_id = str(uuid.uuid4())
        
        repository = RepositoryAggregate(
            id=repo_id,
            name=cmd.name,
            url=target_url
        )

        self.repo.save(repository)
        return repository.id
