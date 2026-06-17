from ...domain.entities.hotfix_proposal import HotfixProposal
from ...domain.repository_interface import IncidentRepositoryPort
import uuid

class ApplyAutomatedFixCommand:
    def __init__(self, incident_id: str, target_file: str, raw_patch: str):
        self.incident_id = incident_id
        self.target_file = target_file
        self.raw_patch = raw_patch

class ApplyAutomatedFixCommandHandler:
    """Takes generated patch, applies compile verification check, and uploads PR details."""
    def __init__(self, persistence: IncidentRepositoryPort, github_client_mock: Any = None):
        self.repo = persistence
        self.git = github_client_mock

    def handle(self, cmd: ApplyAutomatedFixCommand) -> bool:
        incident = self.repo.get_incident_by_id(cmd.incident_id)
        if not incident:
            return False

        proposal = HotfixProposal(
            id=str(uuid.uuid4()),
            target_filepath=cmd.target_file,
            diff_patch_payload=cmd.raw_patch
        )

        passed = proposal.apply_verification_pass()
        if passed:
            incident.attach_verified_patch(proposal)
            self.repo.save_incident(incident)
            return True
            
        return False
