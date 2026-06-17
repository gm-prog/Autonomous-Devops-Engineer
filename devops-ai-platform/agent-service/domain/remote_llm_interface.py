from abc import ABC, abstractmethod
from typing import Dict, Any, List

class RemoteLLMInterface(ABC):
    """
    Contract (Port) defining interaction logic with AI language generation platforms.
    Isolates domain logic from specific model providers.
    """
    @abstractmethod
    def generate_remediation(self, prompt: str, system_instruction: str) -> str:
        """Invokes raw text generation mapping remedial recommendations."""
        pass

    @abstractmethod
    def generate_iac_blueprint(self, tech_metadata: Dict[str, Any]) -> Dict[str, str]:
        """Auto-computes structural Terraform/Dockerfiles scripts based on code files."""
        pass
