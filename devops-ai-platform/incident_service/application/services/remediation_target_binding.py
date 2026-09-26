"""Incident → repository → source-revision authorization binding.

The public remediation endpoint must not trust ``repository_slug`` /
``source_sha`` request fields independently: a caller could otherwise turn
the incident API into an arbitrary GitHub write primitive. Before any
workspace is cloned, the requested target must be proven to belong to the
incident through persisted deployment evidence.

Security invariant (same-record pair matching)::

    authorized(request)  ⇔  ∃ one deployment_run evidence record E such that
        canonical_repository(E) == request.repository_slug
        AND
        canonical_source_sha(E) == request.source_sha

Both values must come from the **same** evidence object. Values harvested
from different records are never combined, so two deployments cannot be
cross-mixed (repository from deployment A + SHA from deployment B).

Canonical forms:

* repository identity — ``payload["repository_name"]`` in ``owner/repo``
  form matching ``^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$``. Bare names
  (``checkout``) are ambiguous and are **never** accepted, upgraded, or
  segment-matched.
* source revision — ``payload["source_revision"]["head_sha"]``, a full
  40-character hex string, compared case-insensitively (normalized to
  lowercase). Branch names, tags, short SHAs and malformed values are
  rejected.
"""

from __future__ import annotations

import re
from typing import Any

_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_SLUG_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

_DEPLOYMENT_EVIDENCE_KIND = "deployment_run"


class RemediationTargetBindingError(PermissionError):
    """Raised when the requested remediation target is not bound to the incident."""


def _deployment_evidence(incident: Any) -> list:
    return [
        item
        for item in getattr(incident, "evidence", [])
        if item.kind == _DEPLOYMENT_EVIDENCE_KIND
    ]


def _canonical_repository(payload: dict) -> str | None:
    """Return the record's canonical ``owner/repo`` identity, or None.

    Only ``repository_name`` in full slug form counts. A bare or malformed
    value makes this record contribute no repository identity at all
    (fail closed) — it is never segment-matched or upgraded.
    """
    name = payload.get("repository_name")
    if not isinstance(name, str):
        return None
    name = name.strip()
    if _SLUG_PATTERN.fullmatch(name):
        return name
    return None


def _canonical_source_sha(payload: dict) -> str | None:
    """Return the record's canonical 40-hex ``source_revision.head_sha``, or None."""
    revision = payload.get("source_revision")
    if not isinstance(revision, dict):
        return None
    value = revision.get("head_sha")
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    if _SHA_PATTERN.fullmatch(value):
        return value
    return None


def authorize_remediation_target(
    incident: Any,
    repository_slug: str,
    source_sha: str,
) -> None:
    """Raise :class:`RemediationTargetBindingError` unless the requested
    ``(repository_slug, source_sha)`` pair is bound to this incident.

    The pair must occur together in a **single** ``deployment_run`` evidence
    record; values from different records are never combined.
    """
    # --- validate the request (fail fast on malformed input) ---
    if not isinstance(repository_slug, str):
        raise RemediationTargetBindingError(
            "requested repository must be a canonical owner/repository slug"
        )
    slug = repository_slug.strip()
    if not _SLUG_PATTERN.fullmatch(slug):
        raise RemediationTargetBindingError(
            "requested repository must be a canonical owner/repository slug"
        )
    if not isinstance(source_sha, str):
        raise RemediationTargetBindingError(
            "requested source revision is not a full 40-character SHA"
        )
    sha = source_sha.strip().lower()
    if not _SHA_PATTERN.fullmatch(sha):
        raise RemediationTargetBindingError(
            "requested source revision is not a full 40-character SHA"
        )

    # --- the incident must have deployment evidence at all ---
    evidence_items = _deployment_evidence(incident)
    if not evidence_items:
        raise RemediationTargetBindingError(
            "incident has no deployment evidence binding it to a repository; "
            "refusing remediation of an unbound target"
        )

    # --- same-record pair match ---
    for item in evidence_items:
        payload = dict(item.payload or {})
        record_repository = _canonical_repository(payload)
        if record_repository is None:
            continue  # malformed/ambiguous identity contributes nothing
        record_sha = _canonical_source_sha(payload)
        if record_sha is None:
            continue  # malformed revision contributes nothing
        if record_repository == slug and record_sha == sha:
            return  # exact pair found together in ONE evidence record

    raise RemediationTargetBindingError(
        "requested (repository, source SHA) pair does not occur together in any "
        "single deployment evidence record of this incident"
    )
