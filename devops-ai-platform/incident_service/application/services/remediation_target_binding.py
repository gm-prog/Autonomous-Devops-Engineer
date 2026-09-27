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

**Deployment provenance:** only evidence from a successfully *deployed*
run is authoritative. The deployment domain's terminal success state is
``DeploymentState.DEPLOYED`` (``domain/value_objects/deployment_state.py``);
records left in ``AWAITING_APPROVAL``, ``DRY_RUN_*``, ``DEPLOYMENT_*``,
``ROLLED_BACK`` etc. - or with a missing/malformed ``state`` - never
authorize remediation.

**Platform provenance record (Stage 5):** a ``DEPLOYED`` record is only
authoritative when it also carries the platform's provenance object
(``shared_kernel.domain.provenance``): the record must exist, its
``provenance_hash`` must recompute over the canonical payload, its
identity fields must match *this* evidence record (repository, SHA, run
id, state, artifact/plan hashes), and it must record an *independent*
source verification (method ``unverified`` never verifies).  Missing,
tampered, grafted or unverified provenance fails closed with a
provenance-specific error - a plausible repository name plus SHA is never
enough on its own.  The hash is unkeyed integrity, not authenticity: the
authenticity root for evidence remains the private network + gateway
boundary (README trust model).

Canonical forms:

* repository identity — ``payload["repository_name"]`` in ``owner/repo``
  form matching ``^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`` where each
  segment contains at least one alphanumeric character (dot-only segments
  such as ``..`` are rejected). Bare names
  (``checkout``) are ambiguous and are **never** accepted, upgraded, or
  segment-matched.
* source revision — ``payload["source_revision"]["head_sha"]``, a full
  40-character hex string, compared case-insensitively (normalized to
  lowercase). Branch names, tags, short SHAs and malformed values are
  rejected.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from shared_kernel.domain.provenance import (
    ProvenanceError,
    verify_provenance_record,
)

_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_SLUG_PATTERN = re.compile(r"^(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+/(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+$")

_DEPLOYMENT_EVIDENCE_KIND = "deployment_run"
# Authoritative deployment state: only a fully deployed revision may feed
# remediation authorization (mirrors DeploymentState.DEPLOYED).
_AUTHORITATIVE_DEPLOYMENT_STATE = "DEPLOYED"


class RemediationTargetBindingError(PermissionError):
    """Raised when the requested remediation target is not bound to the incident."""


def _deployment_evidence(incident: Any) -> list:
    return [
        item
        for item in getattr(incident, "evidence", [])
        if item.kind == _DEPLOYMENT_EVIDENCE_KIND
    ]


def _is_authoritative(payload: dict) -> bool:
    """True only for evidence produced by a successfully deployed run.

    Exact match only: the deployment service emits the domain enum value
    verbatim, so anything else (padding, different case, non-string,
    missing) is treated as non-authoritative.
    """
    state = payload.get("state")
    return isinstance(state, str) and state == _AUTHORITATIVE_DEPLOYMENT_STATE


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


def _provenance_satisfies_record(payload: dict) -> bool:
    """True only when the payload carries a *valid* provenance record that
    describes THIS record (Stage 5).

    Checks, in order: presence, full structural + hash verification via the
    shared contract (rejects unknown/missing fields, malformed hex,
    ``unverified`` source method, over-claimed artifact derivation, and any
    tampering), then identity cross-checks against the surrounding evidence
    payload so provenance grafted from a different record (or a different
    state) never matches.
    """
    provenance = payload.get("provenance")
    if not isinstance(provenance, dict):
        return False
    try:
        verify_provenance_record(provenance)
    except ProvenanceError:
        return False
    # the provenance must describe the deployment state actually recorded
    if provenance.get("state") != _AUTHORITATIVE_DEPLOYMENT_STATE:
        return False
    if provenance.get("repository_name") != payload.get("repository_name"):
        return False
    record_sha = _canonical_source_sha(payload)
    if record_sha is None or provenance.get("source_sha") != record_sha:
        return False
    if provenance.get("deployment_run_id") != str(
        payload.get("deployment_run_id")
    ):
        return False
    # when the evidence record carries artifact/plan identity, it must agree
    for field in ("artifact_hash", "plan_hash"):
        recorded = payload.get(field)
        if recorded and provenance.get(field) != str(recorded):
            return False
    return True


def resolve_authoritative_deployment_target(incident: Any) -> dict | None:
    """Most recent trusted DEPLOYED target for this incident, or None.

    Single source of truth for "trusted execution target" (Phase 6.1 §6):
    a candidate record must pass the SAME gates as remediation binding —
    state == DEPLOYED, canonical repository + full 40-hex SHA coexisting
    in ONE record, and a valid platform provenance record describing that
    same record. The winner is the most recent candidate by
    ``(observed_at, evidence_id)`` — deterministic, and always ONE record's
    pair, so repo-A + sha-B combinations are structurally impossible.
    """
    candidates = []
    for item in _deployment_evidence(incident):
        payload = dict(item.payload or {})
        if not _is_authoritative(payload):
            continue
        if not _provenance_satisfies_record(payload):
            continue
        repository = _canonical_repository(payload)
        sha = _canonical_source_sha(payload)
        if repository is None or sha is None:
            continue
        candidates.append(
            (
                getattr(item, "observed_at", None),
                item.id,
                repository,
                sha,
                payload,
            )
        )
    if not candidates:
        return None

    def _recency_key(entry: tuple) -> tuple:
        observed = entry[0]
        if isinstance(observed, datetime):
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=timezone.utc)
            timestamp = observed.timestamp()
        else:
            timestamp = 0.0
        return (timestamp, str(entry[1]))

    candidates.sort(key=_recency_key, reverse=True)
    _, evidence_id, repository, sha, payload = candidates[0]
    return {
        "repository_name": repository,
        "source_sha": sha,
        "evidence_id": evidence_id,
        "deployment_run_id": str(payload.get("deployment_run_id") or ""),
        "artifact_hash": str(payload.get("artifact_hash") or ""),
        "plan_hash": str(payload.get("plan_hash") or ""),
    }


def authorize_remediation_target(
    incident: Any,
    repository_slug: str,
    source_sha: str,
) -> None:
    """Raise :class:`RemediationTargetBindingError` unless the requested
    ``(repository_slug, source_sha)`` pair is bound to this incident.

    The pair must occur together in a **single** ``deployment_run`` evidence
    record whose state is ``DEPLOYED`` *and* whose platform provenance
    record verifies (Stage 5); values from different records are never
    combined.
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

    # --- deployment-state gate: only successfully deployed runs are proof ---
    authoritative_items = [
        item for item in evidence_items if _is_authoritative(dict(item.payload or {}))
    ]
    if not authoritative_items:
        raise RemediationTargetBindingError(
            "incident has no successfully deployed (state=DEPLOYED) deployment "
            "evidence; dry-run, failed or awaiting-approval runs cannot "
            "authorize remediation"
        )

    # --- same-record pair match + provenance gate (Stage 5) ---
    # Authorization requires ONE record where the exact requested pair
    # co-occurs AND that record carries a valid platform provenance record.
    pair_present_without_provenance = False
    for item in authoritative_items:
        payload = dict(item.payload or {})
        record_repository = _canonical_repository(payload)
        if record_repository is None:
            continue  # malformed/ambiguous identity contributes nothing
        record_sha = _canonical_source_sha(payload)
        if record_sha is None:
            continue  # malformed revision contributes nothing
        if record_repository != slug or record_sha != sha:
            continue  # this record proves a different target
        if _provenance_satisfies_record(payload):
            return  # exact pair + verified provenance in ONE evidence record
        # The requested pair exists in this record but cannot be
        # corroborated by platform provenance → fail closed, never
        # downgrade to "plausible repository + SHA is enough".
        pair_present_without_provenance = True

    if pair_present_without_provenance:
        raise RemediationTargetBindingError(
            "requested deployment evidence lacks a valid platform provenance "
            "record (missing, tampered, unverified source, or mismatched "
            "with its deployment record); refusing remediation on "
            "unverifiable deployment evidence"
        )

    raise RemediationTargetBindingError(
        "requested (repository, source SHA) pair does not occur together in any "
        "single deployment evidence record of this incident"
    )
