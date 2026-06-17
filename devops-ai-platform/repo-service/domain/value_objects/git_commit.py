from dataclasses import dataclass
from datetime import datetime

@dataclass(frozen=True)
class GitCommit:
    """Immutable value object representing VCS commit metrics."""
    sha: str
    message: str
    author: str
    committed_at: datetime

    def __post_init__(self):
        if len(self.sha) != 40:
            raise ValueError(f"Invalid full SHA-1 hash length specification: {self.sha}")
