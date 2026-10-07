from dataclasses import dataclass
from typing import List

@dataclass(frozen=True)
class TechStack:
    """Immutable Value Object cataloging programming languages and matched application frameworks."""
    primary_language: str
    detected_frameworks: List[str]
    has_dockerfile: bool
    has_k8s_manifests: bool

    def is_cloud_ready(self) -> bool:
        return self.has_dockerfile and self.has_k8s_manifests
