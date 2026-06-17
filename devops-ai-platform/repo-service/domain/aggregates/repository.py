from typing import List, Optional
from datetime import datetime
from ...shared_kernel.domain.value_objects import RepoUrl
from ..entities.code_file import CodeFile
from ..value_objects.tech_stack import TechStack
from ...shared_kernel.domain.events import RepositoryImportedEvent

class RepositoryAggregate:
    """
    The Repository Aggregate Root.
    Encapsulates all invariants of a code repository under analysis, 
    including its files, parsed technology stack, and tracking domain events.
    """
    def __init__(self, id: str, name: str, url: RepoUrl, created_at: Optional[datetime] = None):
        self.id = id
        self.name = name
        self.url = url
        self.created_at = created_at or datetime.utcnow()
        self.files: List[CodeFile] = []
        self.tech_stack: Optional[TechStack] = None
        self.status = "Imported" # Imported, Analyzed, DeployFailed, Active
        self.domain_events = []

        # Record domain event on aggregation initiation
        self.domain_events.append(RepositoryImportedEvent(
            aggregate_id=self.id,
            payload={"repo_name": self.name, "url": self.url.value}
        ))

    def add_file(self, code_file: CodeFile):
        """Domain action ensuring unique files in code base."""
        if any(f.filepath == code_file.filepath for f in self.files):
            return # Avoid duplicating files
        self.files.append(code_file)

    def set_tech_stack(self, tech_stack: TechStack):
        """Saves verified tech stack definition to aggregate."""
        self.tech_stack = tech_stack
        self.status = "Analyzed"

    def clear_events(self):
        self.domain_events = []
