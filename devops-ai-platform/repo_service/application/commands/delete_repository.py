from ...domain.repository_interface import RepositoryPersistencePort
from ...domain.exceptions import InvalidGitRepositoryException

class DeleteRepositoryCommand:
    def __init__(self, repository_id: str):
        self.repository_id = repository_id

class DeleteRepositoryCommandHandler:
    def __init__(self, persistence_adapter: RepositoryPersistencePort):
        self.repo = persistence_adapter

    def handle(self, cmd: DeleteRepositoryCommand) -> bool:
        target = self.repo.find_by_id(cmd.repository_id)
        if not target:
            raise InvalidGitRepositoryException(f"Repository with ID {cmd.repository_id} does not exist.")
        
        # Implementation of deletion (e.g. database deletes and local file system purging)
        return True
