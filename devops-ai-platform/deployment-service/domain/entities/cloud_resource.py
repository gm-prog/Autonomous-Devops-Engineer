from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class CloudResource:
    """CloudResource Entity tracking physical or planned provision status flags."""
    resource_id: str
    resource_type: str # e.g. "aws_alb", "kubernetes_service"
    provider: str # e.g. "AWS", "Kubernetes"
    desired_state: Dict[str, Any]
    actual_state: Dict[str, Any]
    status: str = "Unapplied" # Unapplied, Transitioning, InSync, Drifted
