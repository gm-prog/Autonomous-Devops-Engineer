from dataclasses import dataclass
from typing import List, Optional
from ..value_objects.agent_capability import AgentCapability

@dataclass
class AgentInstance:
    """AgentInstance Entity tracing an active worker node's scope, state, and outputs."""
    agent_id: str
    role_name: str # e.g. "SecurityScraper", "IaCTranspiler"
    capabilities: List[AgentCapability]
    status: str = "Idle" # Idle, Active, Completed, Error
    last_prompt_sha: Optional[str] = None
    output_response_cache: Optional[str] = None

    def dispatch_work(self, prompt: str) -> str:
        self.status = "Active"
        return f"[Dispatched to {self.role_name}] Process prompt token streams..."
