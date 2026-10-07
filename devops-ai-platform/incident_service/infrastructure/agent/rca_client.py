from __future__ import annotations

import os
from typing import Any, Dict

import requests


class RcaAgentUnavailable(Exception):
    """Raised when the agent service cannot provide an RCA."""


class RcaAgentClient:
    """HTTP adapter for the internal agent-service RCA boundary."""

    def __init__(self, base_url: str | None = None, timeout_seconds: float = 20.0):
        self.base_url = (base_url or os.getenv("AGENT_SERVICE_URL", "")).rstrip("/")
        self.timeout_seconds = timeout_seconds
        if not self.base_url:
            raise ValueError("AGENT_SERVICE_URL must be configured")

    def analyze(self, evidence_pack: Dict[str, Any]) -> Dict[str, Any]:
        try:
            response = requests.post(
                f"{self.base_url}/api/internal/analyze-rca",
                json={"evidence_pack": evidence_pack},
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            result = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise RcaAgentUnavailable("agent-service RCA request failed") from exc

        if not isinstance(result, dict):
            raise RcaAgentUnavailable("agent-service returned a non-object RCA result")
        return result
