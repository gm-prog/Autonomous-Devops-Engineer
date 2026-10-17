"""Platform-owned deployment provenance records (Stage 5).

What this record IS
-------------------
A deterministic, hash-covered description of **which deployment run** proved
**which source revision** of **which repository**, identified by **which
artifact and plan hashes**, in **which state**, and **how the source
revision was independently verified**.  ``provenance_hash`` is SHA-256 over
the canonical JSON (``sort_keys``, compact separators) of every other field,
so any edit to any identity field breaks the hash.

What this record is NOT
-----------------------
* **Not a signature.**  The hash is unkeyed integrity, not authenticity.
  The authenticity root for evidence remains the private compose network +
  authenticated gateway (see README "Network & authentication trust
  boundary").
* **Not artifact-to-source derivation.**  The platform hashes the submitted
  IaC artifact but never deterministically generates it from the verified
  source tree, so ``artifact_source_derivation`` is permanently
  ``"not-established"``.  :func:`build_provenance_record` refuses to record
  any stronger claim, and :func:`verify_provenance_record` rejects one —
  "source-verified" and "artifact-identity-verified" are honest claims here;
  "derivation-verified" is not.

Consumers: ``deployment_service`` builds records (via
``DeploymentRun.to_dict``); ``incident_service`` remediation binding verifies
them before deployment evidence can authorize a remediation target.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Dict, Mapping

PROVENANCE_SCHEMA = "devops.deployment-provenance/1"

#: The only artifact-to-source linkage the platform can truthfully record.
#: The deployment pipeline hashes caller-submitted IaC files; it does not
#: derive them from the verified source tree, so no stronger claim may be
#: fabricated (fail closed instead).
ARTIFACT_SOURCE_DERIVATION_NOT_ESTABLISHED = "not-established"

#: verification_method value for records produced without an independent
#: source check.  Such provenance never verifies (fail closed).
VERIFICATION_METHOD_UNVERIFIED = "unverified"

_PROVENANCE_FIELDS = frozenset(
    {
        "schema",
        "repository_name",
        "source_sha",
        "artifact_hash",
        "plan_hash",
        "deployment_run_id",
        "state",
        "verification_method",
        "artifact_source_derivation",
    }
)

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA64 = re.compile(r"^[0-9a-f]{64}$")
# canonical owner/repo: each segment must contain at least one alphanumeric
# character (dot-only segments such as ".." are rejected)
_SLUG = re.compile(
    r"^(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+"
    r"/(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+$"
)


class ProvenanceError(ValueError):
    """A provenance record is missing, malformed, tampered with, or claims
    a property the platform cannot establish."""


def compute_provenance_hash(fields: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical JSON of ``fields`` minus any
    ``provenance_hash`` key (deterministic across processes and key order)."""
    material = {key: fields[key] for key in fields if key != "provenance_hash"}
    canonical = json.dumps(
        material, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_provenance_record(
    *,
    repository_name: Any,
    source_sha: Any,
    artifact_hash: Any,
    plan_hash: Any,
    deployment_run_id: Any,
    state: Any,
    verification_method: Any,
    artifact_source_derivation: str = ARTIFACT_SOURCE_DERIVATION_NOT_ESTABLISHED,
) -> Dict[str, Any]:
    """Build a complete provenance record for the *current* run identity.

    Raises :class:`ProvenanceError` for any non-canonical input instead of
    silently normalizing it into a claim the platform did not verify.
    Empty ``artifact_hash`` / ``plan_hash`` are permitted only because a run
    is serialized before its dry-run snapshot exists; such a record fails
    :func:`verify_provenance_record` until the hashes are set (incomplete
    provenance never authorizes anything).
    """
    if artifact_source_derivation != ARTIFACT_SOURCE_DERIVATION_NOT_ESTABLISHED:
        raise ProvenanceError(
            "platform cannot establish artifact-to-source derivation; "
            "refusing to record a stronger provenance claim"
        )
    repo = repository_name if isinstance(repository_name, str) else ""
    if not _SLUG.fullmatch(repo):
        raise ProvenanceError(
            "repository_name must be canonical owner/repository"
        )
    sha = source_sha.strip().lower() if isinstance(source_sha, str) else ""
    if not _SHA40.fullmatch(sha):
        raise ProvenanceError("source_sha must be a full 40-hex commit SHA")
    for name, value in (("artifact_hash", artifact_hash), ("plan_hash", plan_hash)):
        text = value if isinstance(value, str) else ""
        if text and not _SHA64.fullmatch(text):
            raise ProvenanceError(f"{name} must be empty or a 64-hex digest")
    run_id = str(deployment_run_id) if deployment_run_id is not None else ""
    if not run_id.strip():
        raise ProvenanceError("deployment_run_id must not be empty")
    record_state = state if isinstance(state, str) else ""
    if not record_state.strip():
        raise ProvenanceError("state must not be empty")
    method = (
        verification_method.strip()
        if isinstance(verification_method, str) and verification_method.strip()
        else ""
    )
    if not method:
        raise ProvenanceError("verification_method must not be empty")

    record: Dict[str, Any] = {
        "schema": PROVENANCE_SCHEMA,
        "repository_name": repo,
        "source_sha": sha,
        "artifact_hash": artifact_hash or "",
        "plan_hash": plan_hash or "",
        "deployment_run_id": run_id,
        "state": record_state,
        "verification_method": method,
        "artifact_source_derivation": ARTIFACT_SOURCE_DERIVATION_NOT_ESTABLISHED,
    }
    record["provenance_hash"] = compute_provenance_hash(record)
    return record


def verify_provenance_record(record: Any) -> None:
    """Validate structure, honest claims and hash integrity.

    Raises :class:`ProvenanceError` on anything that does not check out —
    missing/unknown fields, wrong schema, non-canonical identities,
    incomplete hashes, an ``unverified`` source, an over-claimed artifact
    derivation, or a hash mismatch (tampering).  Returns ``None`` when the
    record is fully valid.
    """
    if not isinstance(record, dict):
        raise ProvenanceError("provenance record must be a JSON object")
    expected_keys = _PROVENANCE_FIELDS | {"provenance_hash"}
    if set(record) != expected_keys:
        raise ProvenanceError(
            "provenance record has missing or unknown fields"
        )
    if record["schema"] != PROVENANCE_SCHEMA:
        raise ProvenanceError("unknown provenance schema")
    if not isinstance(record["repository_name"], str) or not _SLUG.fullmatch(
        record["repository_name"]
    ):
        raise ProvenanceError("provenance repository_name is not canonical")
    if not isinstance(record["source_sha"], str) or not _SHA40.fullmatch(
        record["source_sha"]
    ):
        raise ProvenanceError("provenance source_sha is not a full 40-hex SHA")
    for name in ("artifact_hash", "plan_hash"):
        value = record[name]
        if not isinstance(value, str) or not _SHA64.fullmatch(value):
            raise ProvenanceError(
                f"provenance {name} is incomplete or not a 64-hex digest"
            )
    if not isinstance(record["deployment_run_id"], str) or not record[
        "deployment_run_id"
    ].strip():
        raise ProvenanceError("provenance deployment_run_id must not be empty")
    if not isinstance(record["state"], str) or not record["state"].strip():
        raise ProvenanceError("provenance state must not be empty")
    method = record["verification_method"]
    if (
        not isinstance(method, str)
        or not method.strip()
        or method.strip().lower() == VERIFICATION_METHOD_UNVERIFIED
    ):
        raise ProvenanceError(
            "provenance does not record an independent source verification"
        )
    if record["artifact_source_derivation"] != (
        ARTIFACT_SOURCE_DERIVATION_NOT_ESTABLISHED
    ):
        raise ProvenanceError(
            "provenance claims an artifact-to-source derivation the platform "
            "cannot establish"
        )
    stored_hash = record["provenance_hash"]
    if not isinstance(stored_hash, str) or not _SHA64.fullmatch(stored_hash):
        raise ProvenanceError("provenance_hash is malformed")
    if not hmac.compare_digest(stored_hash, compute_provenance_hash(record)):
        raise ProvenanceError("provenance hash mismatch (record was altered)")
