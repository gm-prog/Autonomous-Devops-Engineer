from dataclasses import dataclass
from typing import Dict, Any

@dataclass(frozen=True)
class PromptTemplate:
    """Immutable prompt compiler holding base persona profiles and placeholders."""
    system_instruction: str
    user_prompt_format: str

    def compile(self, variables: Dict[str, Any]) -> str:
        try:
            return self.user_prompt_format.format(**variables)
        except KeyError as e:
            raise ValueError(f"Prompt compiling failed on missing variable interpolation: {e}")
