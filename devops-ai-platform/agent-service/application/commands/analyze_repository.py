"""Repository analysis application command (Phase 8.7-D, D1).

Drives the LLM port (``RemoteLLMInterface``) to produce validated DevOps
blueprints for a registered repository.  The command:

* sends only typed, validated repository metadata to the provider (never a
  provider credential — the credential lives in the infrastructure adapter,
  server-side only);
* demands a strict JSON payload from the provider and validates every field
  through the SINGLE shared strict contract
  (``domain.analysis_payload.parse_strict_asset_payload``) — the same
  contract the IaC blueprint generation path uses (D1 P0-6);
* fails closed: any unparseable or incomplete provider response raises
  ``MalformedAnalysisResponseError`` — it never fabricates blueprint content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ...domain.analysis_payload import (
    ANALYSIS_ASSET_FIELDS as ASSET_FIELDS,  # backward-compatible name
    MAX_ASSET_CHARS,  # noqa: F401  (re-exported for existing importers/tests)
    MAX_REPORT_CHARS,  # noqa: F401  (re-exported for existing importers/tests)
    MalformedAnalysisResponseError,  # re-exported (single contract)
    RepositoryAnalysisAssets,  # re-exported (single contract)
    parse_strict_asset_payload,
)
from ...domain.remote_llm_interface import RemoteLLMInterface

# Hard input bounds (defense in depth — the gateway re-validates these).
MAX_REPO_NAME = 120
MAX_REPO_URL = 2048
MAX_FIELD = 200


@dataclass(frozen=True)
class AnalyzeRepositoryCommand:
    repo_name: str
    repo_url: str
    framework: str
    technology: str


class AnalyzeRepositoryCommandHandler:
    """Use case: repository analysis via the injected LLM port (DI).

    The handler is constructed ONCE per agent application instance and
    shared across requests (application-lifetime wiring — see
    ``agent-service/main.py``), so the LLM engine's resilience and budget
    state persist for the life of the process.
    """

    def __init__(self, llm_engine: RemoteLLMInterface):
        self.llm = llm_engine

    def handle(self, cmd: AnalyzeRepositoryCommand) -> RepositoryAnalysisAssets:
        self._validate_input(cmd)
        raw = self.llm.generate_remediation(
            self._build_prompt(cmd),
            self._SYSTEM_INSTRUCTION,
        )
        return self._parse_payload(raw)

    _SYSTEM_INSTRUCTION = (
        "You are a senior DevOps platform architect. You analyze repository "
        "metadata and emit production-grade DevOps blueprints. You respond "
        "with strictly validated JSON only — no markdown fences, no "
        "commentary, no omissions, no extra fields."
    )

    @staticmethod
    def _validate_input(cmd: AnalyzeRepositoryCommand) -> None:
        if not isinstance(cmd.repo_name, str) or not cmd.repo_name.strip():
            raise ValueError("repo_name must be a non-empty string.")
        if len(cmd.repo_name) > MAX_REPO_NAME:
            raise ValueError(f"repo_name exceeds {MAX_REPO_NAME} characters.")
        if not isinstance(cmd.repo_url, str) or not cmd.repo_url.strip():
            raise ValueError("repo_url must be a non-empty string.")
        if len(cmd.repo_url) > MAX_REPO_URL:
            raise ValueError(f"repo_url exceeds {MAX_REPO_URL} characters.")
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://\S+$", cmd.repo_url):
            raise ValueError("repo_url must be an absolute URL with a scheme.")
        for field in ("framework", "technology"):
            value = getattr(cmd, field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field} must be a non-empty string.")
            if len(value) > MAX_FIELD:
                raise ValueError(f"{field} exceeds {MAX_FIELD} characters.")

    @staticmethod
    def _build_prompt(cmd: AnalyzeRepositoryCommand) -> str:
        return (
            "Analyze the following repository and generate complete DevOps "
            "blueprints for it.\n"
            f"Repository name: {cmd.repo_name}\n"
            f"Repository URL: {cmd.repo_url}\n"
            f"Framework: {cmd.framework}\n"
            f"Technology: {cmd.technology}\n\n"
            "Respond with ONLY a JSON object with exactly these keys: "
            '{"dockerfile": "...", "k8s_yaml": "...", "terraform_tf": "...", '
            '"pipeline_yaml": "...", "report": "..."}. '
            "No extra fields, no markdown fences.\n"
            "Each value must be a complete, non-empty string. "
            "\"report\" is a concise plain-text summary (max ~4000 chars)."
        )

    @staticmethod
    def _parse_payload(raw: str) -> RepositoryAnalysisAssets:
        # The single shared strict contract (also used by
        # GeminiCallerAdapter.generate_iac_blueprint) — there is no
        # alternate lenient parser (D1 P0-6).
        return parse_strict_asset_payload(raw)
