from datetime import datetime
import uuid
from typing import Dict, Any

class DomainEvent:
    """
    Base Domain Event model for handling Event Sourcing or publishing 
    asynchronous messaging schemas to RabbitMQ / Kafka queues.
    """
    def __init__(self, aggregate_id: str, payload: Dict[str, Any] = None):
        self.event_id = str(uuid.uuid4())
        self.aggregate_id = aggregate_id
        self.timestamp = datetime.utcnow().isoformat()
        self.payload = payload or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "aggregate_id": self.aggregate_id,
            "event_type": self.__class__.__name__,
            "timestamp": self.timestamp,
            "payload": self.payload
        }

class RepositoryImportedEvent(DomainEvent):
    """Fired immediately when a Git VCS repo has been fetched & cataloged."""
    pass

class CodeAnalysisCompletedEvent(DomainEvent):
    """Fired when AST parsing and package vulnerability checks succeed."""
    pass

class IaCManifestCompiledEvent(DomainEvent):
    """Fired when Terraform profiles and K8s configuration blueprints are finished coding."""
    pass

class LiveDeploymentTriggeredEvent(DomainEvent):
    """Fired when infra provisioning orchestrators dispatch task packages to staging clusters."""
    pass

class ThreatThresholdExceededEvent(DomainEvent):
    """Fired when Prometheus scrapers catch CPU spikes or security intrusions."""
    pass

class OutOfBoundsIncidentLoggedEvent(DomainEvent):
    """Fired when Sentry triggers anomalous error webhook indicators."""
    pass

class AutoFixPRLoggedEvent(DomainEvent):
    """Fired when our Autonomous Healing agents push code revisions to VCS repos."""
    pass
