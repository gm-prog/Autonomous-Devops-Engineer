"""Pure helper logic for the Phase 8.4.2 CI golden-path harness.

Everything here is side-effect free so the live workflow is never the
first test of its own helper code (unit-tested under
``tests/test_e2e_harness.py``).
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Sequence, Tuple

SCHEMA = "ares.e2e.golden-path/1"

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_REPO_SLUG = re.compile(
    r"^(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+"
    r"/(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+$"
)
_BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
_DIGEST_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*@sha256:[0-9a-f]{64}$")
_MANIFEST_KEY = re.compile(r"^[a-z_]+$")

PASS, FAIL, BLOCKED, NOT_VERIFIED = "PASS", "FAIL", "BLOCKED", "NOT_VERIFIED"

_SECRET_PATTERNS: Sequence[re.Pattern[str]] = (
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"(?i)\bauthorization:\s*(bearer|token)\s+\S+"),
    # the sanitized-render placeholder is not a secret (Phase 8.4.2-C §10:
    # primary control substitutes [REDACTED-NON-SECRET]; the scan must not
    # reject its own placeholder — injected REAL values still match).
    re.compile(r"(?i)(JWT_SECRET|GITHUB_OAUTH_TOKEN|E2E_FIXTURE_GITHUB_TOKEN|"
               r"E2E_JWT_SECRET|GEMINI_API_KEY)\s*[=:]\s*"
               r"(?!\[REDACTED-NON-SECRET\])\S+"),
    re.compile(r"x-access-token:[^@\s]+@"),
)


_PIN_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._/:-]*$")
_PIN_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_PIN_KEY_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")


def parse_pinned_images(text: str) -> List[Tuple[str, str, str]]:
    """Parse pinned-images.txt strictly (Phase 8.4.2-D §5).

    Every non-comment entry must be ``<name> <sha256:64hex> <ENV_KEY>``.
    A pin of anything else — the retired sentinel value, a malformed
    digest, a missing column, an unknown key — raises ``ValueError``
    (fail-closed; there is no tag fallback).
    """
    entries: List[Tuple[str, str, str]] = []
    seen_keys: set = set()
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 3:
            raise ValueError(
                f"pin line {lineno}: expected 3 columns, got {len(parts)}"
            )
        name, pin, key = parts
        if not _PIN_NAME_PATTERN.fullmatch(name) or "@" in name:
            raise ValueError(f"pin line {lineno}: bad image name {name!r}")
        if not _PIN_DIGEST_PATTERN.fullmatch(pin):
            raise ValueError(
                f"pin line {lineno}: pin must be sha256:<64hex>, got {pin!r}"
            )
        if not _PIN_KEY_PATTERN.fullmatch(key):
            raise ValueError(f"pin line {lineno}: bad env key {key!r}")
        if key in seen_keys:
            raise ValueError(f"pin line {lineno}: duplicate env key {key!r}")
        seen_keys.add(key)
        entries.append((name, pin, key))
    if not entries:
        raise ValueError("pinned-images.txt contains no entries")
    return entries


# Fields a live PASS execution must carry as non-empty scalars
# (Phase 8.4.2-D §7/§9). NOT_VERIFIED/BLOCKED manifests may omit them.
EXECUTION_PROVENANCE_FIELDS: Tuple[str, ...] = (
    "source_sha",
    "fixture_seed_sha",
    "workspace_root",
    "registry_image_digest",
    "kind_node_image_digest",
    "base_images",
    "built_image_digests",
    "sandbox_image_digest",
)


def finalize_execution_manifest(manifest: Dict[str, Any], result: str) -> Dict[str, Any]:
    """Live-execution finalization gate (Phase 8.4.2-D §9).

    A PASS result is REJECTED (downgraded to FAIL with an auditable
    ``provenance_rejection`` reason) when any required provenance field
    is empty. NOT_VERIFIED/BLOCKED/FAIL results remain representable so
    preflight and never-started runs keep working.
    """
    if result == PASS:
        missing = [
            field
            for field in EXECUTION_PROVENANCE_FIELDS
            if not str(manifest.get(field) or "").strip()
        ]
        if missing:
            result = FAIL
            manifest["provenance_rejection"] = (
                "PASS rejected: empty provenance fields: " + ",".join(missing)
            )
    return finalize_manifest(manifest, result)


def validate_sha40(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA40.fullmatch(value))


def validate_repo_slug(value: Any) -> bool:
    return isinstance(value, str) and bool(_REPO_SLUG.fullmatch(value))


def validate_branch(value: Any) -> bool:
    return isinstance(value, str) and bool(_BRANCH.fullmatch(value)) and ".." not in value


def validate_digest_ref(value: Any) -> bool:
    return isinstance(value, str) and bool(_DIGEST_REF.fullmatch(value))


def extract_repo_digest(refs: Iterable[str]) -> str:
    """Return the first digest-bearing repo digest from ``docker inspect``
    RepoDigests output, fail-closed to '' when nothing is digest-pinned."""
    for ref in refs or ():
        if validate_digest_ref(str(ref).strip()):
            return str(ref).strip()
    return ""


def image_digest_of(image_id: str) -> str:
    """Normalize a docker image Id (sha256:<64hex>) to bare 64-hex or ''."""
    value = str(image_id or "").strip()
    if value.startswith("sha256:"):
        value = value[len("sha256:"):]
    return value if re.fullmatch(r"[0-9a-f]{64}", value) else ""


def row(case: str, expected: str, observed: str, ok: bool) -> Dict[str, Any]:
    return {"case": case, "expected": expected, "observed": observed,
            "result": PASS if ok else FAIL}


def classify_gate(outcomes: Sequence[Dict[str, Any]]) -> str:
    """Aggregate stage rows: any FAIL → FAIL; else any NOT_VERIFIED →
    NOT_VERIFIED; else PASS.  BLOCKED never coexists with execution."""
    results = {o.get("result") for o in outcomes}
    if FAIL in results:
        return FAIL
    if BLOCKED in results:
        return BLOCKED
    if NOT_VERIFIED in results:
        return NOT_VERIFIED
    return PASS


def validate_manifest(manifest: Dict[str, Any]) -> List[str]:
    """Return a list of schema violations (empty == valid)."""
    problems: List[str] = []
    if not isinstance(manifest, dict):
        return ["manifest must be an object"]
    if manifest.get("schema") != SCHEMA:
        problems.append(f"schema must be {SCHEMA}")
    for key, value in manifest.items():
        if not isinstance(key, str) or not _MANIFEST_KEY.fullmatch(key):
            problems.append(f"invalid manifest key: {key!r}")
        if isinstance(value, (dict, list)):
            problems.append(f"manifest values must be scalars: {key}")
        elif value is not None and not isinstance(value, (str, int, float, bool)):
            problems.append(f"manifest values must be scalars: {key}")
    if manifest.get("result") not in {PASS, FAIL, BLOCKED, NOT_VERIFIED}:
        problems.append("result must be PASS/FAIL/BLOCKED/NOT_VERIFIED")
    return problems


def new_manifest(**fields: Any) -> Dict[str, Any]:
    manifest: Dict[str, Any] = {"schema": SCHEMA}
    manifest.update(fields)
    manifest.setdefault("result", NOT_VERIFIED)
    return manifest


def finalize_manifest(manifest: Dict[str, Any], result: str) -> Dict[str, Any]:
    manifest["result"] = result
    problems = validate_manifest(manifest)
    if problems:
        raise ValueError("invalid manifest: " + "; ".join(problems))
    return manifest


def secret_scan_text(text: str) -> List[str]:
    findings: List[str] = []
    for pattern in _SECRET_PATTERNS:
        match = pattern.search(text or "")
        if match:
            findings.append(match.group(0)[:16] + "…")
    return findings


def canonical_proposal_hash_inputs(*, incident_id: str, root_cause: str,
                                   evidence_refs: Sequence[str], repository: str,
                                   source_sha: str, file_paths: Sequence[str],
                                   patch: str, validation_plan: Sequence[str],
                                   risk_class: str) -> Dict[str, Any]:
    """Fixed-field canonical document shared with the reproduction test
    (semantics must equal ``compute_proposal_hash`` — the live harness
    imports the real implementation; this mirrors it for unit tests)."""
    return {
        "incident_id": incident_id,
        "root_cause": root_cause,
        "evidence_refs": list(evidence_refs),
        "repository": repository,
        "source_sha": source_sha,
        "file_paths": list(file_paths),
        "patch": patch,
        "validation_plan": list(validation_plan),
        "risk_class": risk_class,
    }


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def redact(text: str) -> str:
    out = text or ""
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub("[REDACTED]", out)
    return out


def classify_execution_outcomes(statuses: Sequence[int]) -> Dict[str, Any]:
    """Strict two-request race oracle (§8): exactly ONE winner-transport
    (200, or relay-timeout 502/504 while the durable operation continues —
    documented in the Phase 8.4.2 report) and exactly ONE 409 conflict,
    zero invalid codes, exactly two outcomes. Order-independent.
    [200,409]/[409,200]/[502,409]/[409,502]/[504,409] pass;
    [200,200], [502,502], [504,504], [409,409], [200,500], [404,409],
    [] all fail."""
    observed = list(statuses)
    winners = [s for s in observed if s in (200, 502, 504)]
    conflicts = [s for s in observed if s == 409]
    invalid = [s for s in observed if s not in (200, 409, 502, 504)]
    acceptable = (
        len(observed) == 2
        and len(winners) == 1
        and len(conflicts) == 1
        and not invalid
    )
    return {
        "winners": winners,
        "conflicts": conflicts,
        "successes": len(winners),
        "invalid": invalid,
        "acceptable": acceptable,
    }


def dump_json(path: str, data: Any) -> str:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True, default=str)
        handle.write("\n")
    return path
