"""Repository analysis application command (Phase 8.7-D).

Drives the LLM port (``RemoteLLMInterface``) to produce validated DevOps
blueprints for a registered repository.  The command:

* sends only typed, validated repository metadata to the provider (never a
  provider credential — the credential lives in the infrastructure adapter,
  server-side only);
* demands a strict JSON payload from the provider and validates every field;
* fails closed: any unparseable or incomplete provider response raises
  ``MalformedAnalysisResponseError`` — it never fabricates blueprint content.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Dict

from ...domain.remote_llm_interface import RemoteLLMInterface

# Hard input bounds (defense in depth — the gateway re-validates these).
MAX_REPO_NAME = 120
MAX_REPO_URL = 2048
MAX_FIELD = 200
# Hard output bounds per generated asset.
MAX_ASSET_CHARS = 60_000
MAX_REPORT_CHARS = 4_000

ASSET_FIELDS = ("dockerfile", "k8s_yaml", "terraform_tf", "pipeline_yaml", "report")


class MalformedAnalysisResponseError(Exception):
    """The provider response was not a valid, complete analysis payload."""


@dataclass(frozen=True)
class RepositoryAnalysisAssets:
    """Validated, typed analysis output."""

    dockerfile: str
    k8s_yaml: str
    terraform_tf: str
    pipeline_yaml: str
    report: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "dockerfile": self.dockerfile,
            "k8s_yaml": self.k8s_yaml,
            "terraform_tf": self.terraform_tf,
            "pipeline_yaml": self.pipeline_yaml,
            "report": self.report,
        }


@dataclass(frozen=True)
class AnalyzeRepositoryCommand:
    repo_name: str
    repo_url: str
    framework: str
    technology: str


class AnalyzeRepositoryCommandHandler:
    """Use case: repository analysis via the injected LLM port (DI)."""

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
        "commentary, no omissions."
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
            '"pipeline_yaml": "...", "report": "..."}.\n'
            "Each value must be a complete, non-empty string. "
            "\"report\" is a concise plain-text summary (max ~4000 chars)."
        )

    @staticmethod
    def _parse_payload(raw: str) -> RepositoryAnalysisAssets:
        text = (raw or "").strip()
        if text.startswith("```"):
            lines = text.splitlines()
            if len(lines) >= 2 and lines[0].startswith("```") and lines[-1].strip().startswith("```"):
                text = "\n".join(lines[1:-1]).strip()
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise MalformedAnalysisResponseError(
                "Provider response was not a JSON object."
            ) from exc
        if not isinstance(data, dict):
            raise MalformedAnalysisResponseError("Provider payload was not a JSON object.")
        unexpected = set(data) - set(ASSET_FIELDS)
        if unexpected:
            raise MalformedAnalysisResponseError("Provider payload contained unexpected fields.")
        for field in ASSET_FIELDS:
            value = data.get(field)
            if not isinstance(value, str) or not value.strip():
                raise MalformedAnalysisResponseError(
                    f"Provider payload missing non-empty string field: {field!r}."
                )
            limit = MAX_REPORT_CHARS if field == "report" else MAX_ASSET_CHARS
            if len(value) > limit:
                raise MalformedAnalysisResponseError(
                    f"Provider payload field {field!r} exceeds the {limit} character limit."
                )
        return RepositoryAnalysisAssets(
            dockerfile=data["dockerfile"],
            k8s_yaml=data["k8s_yaml"],
            terraform_tf=data["terraform_tf"],
            pipeline_yaml=data["pipeline_yaml"],
            report=data["report"],
        )
