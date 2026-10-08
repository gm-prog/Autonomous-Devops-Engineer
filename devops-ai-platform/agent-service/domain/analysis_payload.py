"""Strict analysis-payload contract (Phase 8.7-D.1).

Single, shared parse/validate contract for EVERY LLM generation path in the
agent-service (the repository-analysis command and the IaC blueprint
generation).  The provider's formatting is defense-in-depth only: this
module is the authority.

* Exactly the five known asset fields — anything else is a failure.
* Every field must be a non-empty string.
* Per-field character ceilings (defensive; the provider's ``maxOutputTokens``
  bound is the primary output ceiling).

There is deliberately NO lenient parser in the codebase: a generation path
that accepted arbitrary extra fields while the analysis path rejects them
would be a contract violation (see the D1 audit).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict

# Hard output bounds per generated asset (characters).
MAX_ASSET_CHARS = 60_000
MAX_REPORT_CHARS = 4_000

# The exact, closed set of asset fields a valid payload may contain.
ANALYSIS_ASSET_FIELDS = ("dockerfile", "k8s_yaml", "terraform_tf", "pipeline_yaml", "report")


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


def parse_strict_asset_payload(raw: str) -> RepositoryAnalysisAssets:
    """Parse a provider response into the strict five-field payload.

    Tolerates exactly one accidental markdown fence pair around the JSON —
    nothing else is forgiven.  Raises ``MalformedAnalysisResponseError`` on
    any structural surprise (non-object, unexpected fields, missing or
    empty values, oversized fields).
    """
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
    unexpected = set(data) - set(ANALYSIS_ASSET_FIELDS)
    if unexpected:
        raise MalformedAnalysisResponseError(
            "Provider payload contained unexpected fields: "
            + ", ".join(sorted(unexpected))
            + "."
        )
    for field in ANALYSIS_ASSET_FIELDS:
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
