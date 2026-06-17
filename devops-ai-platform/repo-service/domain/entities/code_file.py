from dataclasses import dataclass
from datetime import datetime

@dataclass
class CodeFile:
    """
    CodeFile Entity.
    Represents an individual source file scanned inside our parsed repository namespace.
    """
    id: str
    filepath: str
    language: str
    size_bytes: int
    content: str
    last_modified: datetime = datetime.utcnow()

    def is_yaml_config(self) -> bool:
        return self.filepath.endswith(".yaml") or self.filepath.endswith(".yml")

    def is_docker_target(self) -> bool:
        return "Dockerfile" in self.filepath
