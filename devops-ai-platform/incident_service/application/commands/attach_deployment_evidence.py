from incident_service.domain.entities.incident_evidence import IncidentEvidence
from incident_service.infrastructure.deployment.deployment_evidence_collector import DeploymentEvidenceCollector
from incident_service.domain.repository_interface import IncidentRepositoryPort


class AttachDeploymentEvidenceCommand:
    def __init__(self, incident_id: str, deployment_run_id: str):
        if not incident_id.strip():
            raise ValueError("incident_id must not be empty")
        if not deployment_run_id.strip():
            raise ValueError("deployment_run_id must not be empty")
        self.incident_id = incident_id.strip()
        self.deployment_run_id = deployment_run_id.strip()


class AttachDeploymentEvidenceCommandHandler:
    def __init__(self, repository: IncidentRepositoryPort, collector: DeploymentEvidenceCollector):
        self.repository = repository
        self.collector = collector

    def handle(self, command: AttachDeploymentEvidenceCommand) -> IncidentEvidence:
        incident = self.repository.get_incident_by_id(command.incident_id)
        if incident is None:
            raise LookupError("Incident not found")

        evidence = self.collector.collect(command.deployment_run_id)
        incident.attach_evidence(evidence)
        self.repository.save_incident(incident)
        return evidence