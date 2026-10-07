from dataclasses import dataclass
from typing import List

@dataclass(frozen=True)
class AgentCapability:
    """Immutable Value Object modeling specialized skills and system access limits."""
    domain_sector: str # e.g. "KUBERNETES", "TERRAFORM", "AWS_EC2_AUTOSCALING"
    allowed_mcp_tools: List[str]
    max_tokens_budget: int

    def can_invoke_tool(self, tool_name: str) -> bool:
        return tool_name in self.allowed_mcp_tools or "*" in self.allowed_mcp_tools
