"""Runtime release identity carrier for Prometheus attribution (Phase 6.5.1).

Operator/runtime inputs — never HTTP parameters, never end-user input:

* ``DEVOPS_DEPLOYMENT_ID`` — the exact Phase 6.4 deployment run id.
* ``DEVOPS_SOURCE_SHA``    — the exact 40-character lowercase hexadecimal
  source SHA of the deployed artifact.

Validation is deterministic, fail-closed and unit-testable without
starting the application: a missing, blank, malformed or
control-character identity is *unavailable* — never fabricated,
normalized, or guessed. Only a fully valid identity exposes exactly one
``devops_release_identity_info`` series (value 1); an unavailable
identity exposes no series, which Phase 6.5's existing attribution
logic reports as INCONCLUSIVE. Validation outcomes never echo the raw
identity values.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

from prometheus_client import Gauge

DEPLOYMENT_ID_ENV = "DEVOPS_DEPLOYMENT_ID"
SOURCE_SHA_ENV = "DEVOPS_SOURCE_SHA"

#: Bounded deployment-id length (exact accepted string preserved verbatim;
#: no case normalization, no trimming of a non-blank value).
MAX_DEPLOYMENT_ID_LENGTH = 128

#: Exact source SHA: full-match lowercase 40-hex only. Rejects uppercase,
#: whitespace, ``sha:`` prefixes, short hashes and arbitrary strings.
_SOURCE_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")

#: Low-volume identity carrier: one series per process (not per request),
#: so release identity never multiplies the request counter's cardinality.
RELEASE_IDENTITY = Gauge(
    "devops_release_identity_info",
    "Authoritative release identity for this runtime instance.",
    ["deployment_id", "source_sha"],
)


def validate_deployment_id(raw: object) -> Optional[str]:
    """Return the exact accepted deployment id, or None if unavailable."""
    if not isinstance(raw, str):
        return None
    if not raw.strip():  # missing / blank / whitespace-only
        return None
    if len(raw) > MAX_DEPLOYMENT_ID_LENGTH:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        return None  # newline / control characters rejected
    return raw  # verbatim — preserved exactly, never normalized


def validate_source_sha(raw: object) -> Optional[str]:
    """Return the exact source SHA, or None if it is not 40-hex lowercase."""
    if not isinstance(raw, str) or not raw:
        return None
    if _SOURCE_SHA_PATTERN.fullmatch(raw) is None:
        return None
    return raw


def resolve_release_identity(
    deployment_id: object, source_sha: object
) -> Optional[Tuple[str, str]]:
    """Both halves valid → exact ``(deployment_id, source_sha)``; else None."""
    validated_id = validate_deployment_id(deployment_id)
    validated_sha = validate_source_sha(source_sha)
    if validated_id is None or validated_sha is None:
        return None
    return validated_id, validated_sha


def apply_release_identity(
    deployment_id: object, source_sha: object, gauge: Optional[Gauge] = None
) -> bool:
    """Expose exactly one carrier series iff identity is fully valid.

    Invalid/missing identity exposes NO series (fail-closed): the Phase
    6.5 verifier then reports attribution unavailable instead of
    guessing. Returns whether the series was applied. Intended to be
    evaluated once at the application import/startup boundary.
    """
    target = RELEASE_IDENTITY if gauge is None else gauge
    identity = resolve_release_identity(deployment_id, source_sha)
    if identity is None:
        return False
    target.labels(deployment_id=identity[0], source_sha=identity[1]).set(1)
    return True
