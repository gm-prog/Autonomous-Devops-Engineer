"""Incident → repository → source-revision authorization binding.

The public remediation endpoint must not trust ``repository_slug`` /
``source_sha`` request fields independently: a caller could otherwise turn
the incident API into an arbitrary GitHub write primitive. Before any
workspace is cloned, the requested target must be proven to belong to the
incident through persisted deployment evidence:

    incident
      → known deployment run(s) (evidence kind ``deployment_run``)
      → repository identity (``repository_slug`` / ``repository_name``)
      → source revision (``source_revision.head_sha``)

Both gates must pass: the repository identity AND the exact 40-character
source SHA must appear in the incident's deployment evidence.
"""

from __future__ import annotations

import re
from typing import Any

_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_SLUG_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

_DEPLOYMENT_EVIDENCE_KIND = "deployment_run"
_SHA_KEYS = ("head_sha", "sha", "commit_sha")


class RemediationTargetBindingError(PermissionError):
    """Raised when the requested remediation target is not bound to the incident."""


def _deployment_evidence(incident: Any) -> list:
    return [
        item
        for item in getattr(incident, "evidence", [])
        if item.kind == _DEPLOYMENT_EVIDENCE_KIND
    ]


def _evidence_repository_names(evidence_items: list) -> set[str]:
    names: set[str] = set()
    for item in evidence_items:
        payload = dict(item.payload or {})
        slug = str(payload.get("repository_slug") or "").strip()
        if _SLUG_PATTERN.fullmatch(slug):
            names.add(slug)
        name = str(payload.get("repository_name") or "").strip()
        if name:
            names.add(name)
    return names


def _evidence_source_shas(evidence_items: list) -> set[str]:
    shas: set[str] = set()
    for item in evidence_items:
        payload = dict(item.payload or {})
        revision = payload.get("source_revision")
        if not isinstance(revision, dict):
            continue
        for key in _SHA_KEYS:
            value = str(revision.get(key) or "").strip().lower()
            if _SHA_PATTERN.fullmatch(value):
                shas.add(value)
    return shas


def authorize_remediation_target(
    incident: Any,
    repository_slug: str,
    source_sha: str,
) -> None:
    """Raise :class:`RemediationTargetBindingError` unless the requested
    ``(repository_slug, source_sha)`` pair is bound to this incident via
    its deployment evidence.
    """
    slug = (repository_slug or "").strip()
    sha = (source_sha or "").strip().lower()

    evidence_items = _deployment_evidence(incident)
    if not evidence_items:
        raise RemediationTargetBindingError(
            "incident has no deployment evidence binding it to a repository; "
            "refusing remediation of an unbound target"
        )

    known_names = _evidence_repository_names(evidence_items)
    repo_segment = slug.split("/", 1)[-1] if slug else ""
    repository_ok = bool(slug) and any(
        slug == name or repo_segment == name for name in known_names
    )
    if not repository_ok:
        raise RemediationTargetBindingError(
            "requested repository is not bound to this incident's deployment evidence"
        )

    known_shas = _evidence_source_shas(evidence_items)
    if not _SHA_PATTERN.fullmatch(sha):
        raise RemediationTargetBindingError(
            "requested source revision is not a full 40-character SHA"
        )
    if sha not in known_shas:
        raise RemediationTargetBindingError(
            "requested source revision was never deployed for this incident"
        )
