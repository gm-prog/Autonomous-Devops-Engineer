from dataclasses import dataclass
import re

@dataclass(frozen=True)
class RepoUrl:
    """Immutable Value Object verifying and representing a valid Git link."""
    value: str

    def __post_init__(self):
        # Validate HTTPS or SSH Git target
        pattern = r"^(https?://|git@)[a-zA-Z0-9.-]+(:|/)[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(\.git)?$"
        if not re.match(pattern, self.value):
            raise ValueError(f"Invalid Git URL signature: {self.value}")

@dataclass(frozen=True)
class IPAddress:
    """Immutable value object to parse and lock valid cluster IPv4 structures."""
    value: str

    def __post_init__(self):
        pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        if not re.match(pattern, self.value):
            raise ValueError(f"Invalid network target IP representation: {self.value}")
        parts = self.value.split(".")
        if any(int(part) < 0 or int(part) > 255 for part in parts):
            raise ValueError(f"OOB IP range validation failed: {self.value}")
