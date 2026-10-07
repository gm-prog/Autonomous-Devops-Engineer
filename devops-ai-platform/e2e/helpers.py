"""Pure helper logic for the Phase 8.4.2 CI golden-path harness.

Everything here is side-effect free so the live workflow is never the
first test of its own helper code (unit-tested under
``tests/test_e2e_harness.py``).
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Mapping, Sequence

SCHEMA = "ares.e2e.golden-path/1"

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_REPO_SLUG = re.compile(
    r"^(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+"
    r"/(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+$"
)
_BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
# A content-addressed image reference, optionally carrying a registry host
# (and port) — e.g. ``python@sha256:…`` or
# ``localhost:5001/ares-e2e-sandbox@sha256:…``. The port form is required:
# the run-scoped workload/sandbox images live in the kind-local registry
# (Phase 8.4.2-D audit finding D-1; the sandbox module's own
# ``^[^@\s]+@sha256:[0-9a-f]{64}$`` guard already accepted it).
_DIGEST_REF = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]{1,5})?/)?"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    r"@sha256:[0-9a-f]{64}$"
)
_MANIFEST_KEY = re.compile(r"^[a-z_]+$")

# --- committed immutable image pins (Phase 8.4.2-D §5) -------------------
#: env keys the committed pin file MUST define — exactly these six.
PINNED_IMAGE_KEYS: Sequence[str] = (
    "E2E_PYTHON_BASE_IMAGE",
    "E2E_POSTGRES_IMAGE",
    "E2E_REDIS_IMAGE",
    "E2E_QDRANT_IMAGE",
    "REGISTRY_IMAGE",
    "NODE_IMAGE",
)
#: the subset consumed as build bases / service images by the E2E stack.
BASE_IMAGE_KEYS: Sequence[str] = (
    "E2E_PYTHON_BASE_IMAGE",
    "E2E_POSTGRES_IMAGE",
    "E2E_REDIS_IMAGE",
    "E2E_QDRANT_IMAGE",
)
REGISTRY_IMAGE_KEY = "REGISTRY_IMAGE"
KIND_NODE_IMAGE_KEY = "NODE_IMAGE"

#: The exact set of external YAML artifacts the weighted-traffic
#: topology stack may download (Phase 8.7-B.0). Pinned by digest in
#: e2e/pinned-traffic-topology.txt, exactly like the image pins.
ARTIFACT_PIN_KEYS: Sequence[str] = (
    "GATEWAY_API_CRDS_URL",
    "ENVOY_GATEWAY_CRDS_URL",
    "ENVOY_GATEWAY_INSTALL_URL",
)

_PIN_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
#: Path segments that must never appear in a pinned artifact URL: a
#: branch or a `latest` alias is a moving target even when the digest is
#: committed beside it, and the pin file is supposed to make the source
#: itself unambiguous.
_FLOATING_URL_SEGMENTS = frozenset({"latest", "main", "master", "head", "trunk"})
#: An artifact pin must be an https URL to a .yaml file. Deliberately
#: narrow: no query strings, no fragments, no archives, no bare hostnames.
_ARTIFACT_URL = re.compile(
    r"^https://[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
    r"(?:/[A-Za-z0-9._-]+)*/[A-Za-z0-9._-]+\.yaml$"
)
_PIN_SOURCE = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    r":[A-Za-z0-9][A-Za-z0-9._-]*$"
)
_ENV_KEY = re.compile(r"^[A-Z][A-Z0-9_]*$")

#: manifest fields that MUST carry a real value before a live execution is
#: allowed to claim PASS (Phase 8.4.2-D §7/§9).
REQUIRED_EXECUTION_PROVENANCE: Sequence[str] = (
    "source_sha",
    "fixture_seed_sha",
    "workspace_root",
    "registry_image_digest",
    "kind_node_image_digest",
    "base_images",
    "built_image_digests",
    "sandbox_image_digest",
)

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


def validate_sha40(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA40.fullmatch(value))


#: The production repository. The disposable golden-path fixture must never
#: resolve to it: the harness pushes branches and opens PRs against the
#: fixture, so pointing it here would let an E2E run mutate production
#: source (Phase 8.4.2-F §21-F).
PRODUCTION_REPOSITORY = "gm-prog/Autonomous-Devops-Engineer"


def is_production_repository(value: Any) -> bool:
    """True when ``value`` names the production repository (§21-F).

    Comparison is deliberately permissive about shapes that denote the same
    repository — surrounding whitespace, a trailing ``.git``, trailing
    slashes and letter case — so the guard cannot be sidestepped by a
    cosmetic variation of the slug.
    """
    slug = str(value or "").strip()
    slug = slug[:-4] if slug.casefold().endswith(".git") else slug
    return slug.strip("/").casefold() == PRODUCTION_REPOSITORY.casefold()


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


def canonical_digest_ref(name: str, digest: str) -> str:
    """Build the canonical ``<repository>@sha256:<64hex>`` identity.

    The tag of ``name`` is dropped on purpose: the digest IS the identity,
    the tag column of the pin file only records where that digest was
    observed. Raises ``ValueError`` when the result is not a valid
    content-addressed reference (fail closed — never return a tag).
    """
    source = str(name or "").strip()
    pin = str(digest or "").strip()
    if not _PIN_DIGEST.fullmatch(pin):
        raise ValueError(f"not an immutable sha256 digest: {pin!r}")
    head, sep, tail = source.rpartition(":")
    repository = head if (sep and "/" not in tail) else source
    ref = f"{repository}@{pin}"
    if not validate_digest_ref(ref):
        raise ValueError(f"not a digest-addressed image reference: {ref!r}")
    return ref


def parse_pinned_images(text: str) -> List[Dict[str, str]]:
    """Parse the committed immutable-pin file — fail closed (§5.2/§5.4).

    Grammar, one record per non-comment line::

        <source-name:tag> sha256:<64hex> <ENV_KEY>

    ``ValueError`` is raised for ANY deviation: a missing digest, a
    malformed digest, a mutable tag in the pin column (this explicitly
    includes the retired ``UNRESOLVED`` sentinel, which is just another
    non-digest value), a bad env key, a duplicate key or source, or a key
    set that is not exactly :data:`PINNED_IMAGE_KEYS`. There is no
    fallback and no compatibility mode.
    """
    records: List[Dict[str, str]] = []
    seen_keys: Dict[str, int] = {}
    seen_names: Dict[str, int] = {}
    for lineno, raw in enumerate(str(text or "").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 3:
            raise ValueError(
                f"line {lineno}: expected '<source> sha256:<64hex> <ENV_KEY>', "
                f"got {line!r}"
            )
        name, pin, key = parts
        if not _PIN_SOURCE.fullmatch(name):
            raise ValueError(f"line {lineno}: invalid source image name {name!r}")
        if not _PIN_DIGEST.fullmatch(pin):
            raise ValueError(
                f"line {lineno}: pin for {name!r} is not an immutable "
                f"sha256:<64hex> digest: {pin!r}"
            )
        if not _ENV_KEY.fullmatch(key):
            raise ValueError(f"line {lineno}: invalid env key {key!r}")
        if key in seen_keys:
            raise ValueError(
                f"line {lineno}: duplicate env key {key!r} (first seen on line "
                f"{seen_keys[key]})"
            )
        if name in seen_names:
            raise ValueError(
                f"line {lineno}: duplicate source image {name!r} (first seen on "
                f"line {seen_names[name]})"
            )
        seen_keys[key] = lineno
        seen_names[name] = lineno
        records.append(
            {
                "name": name,
                "digest": pin,
                "key": key,
                "ref": canonical_digest_ref(name, pin),
            }
        )
    expected = sorted(PINNED_IMAGE_KEYS)
    if sorted(seen_keys) != expected:
        raise ValueError(
            f"pin file must define exactly {expected}, got {sorted(seen_keys)}"
        )
    return records


def parse_pinned_artifacts(text: str) -> List[Dict[str, str]]:
    """Parse the committed artifact pin file — fail closed.

    Grammar, one record per non-comment line::

        <https-url-to-a-yaml-file> sha256:<64hex> <ENV_KEY>

    ``ValueError`` is raised for ANY deviation: a non-https or non-.yaml
    source, a missing or malformed digest, a bad env key, a duplicate key
    or source, or a key set that is not exactly :data:`ARTIFACT_PIN_KEYS`.
    There is no fallback, no tag resolution and no compatibility mode, so
    the same commit can never consume different bytes tomorrow.
    """
    records: List[Dict[str, str]] = []
    seen_keys: Dict[str, int] = {}
    seen_urls: Dict[str, int] = {}
    for lineno, raw in enumerate(str(text or "").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 3:
            raise ValueError(
                f"line {lineno}: expected '<https-url> sha256:<64hex> "
                f"<ENV_KEY>', got {line!r}"
            )
        url, pin, key = parts
        if not _ARTIFACT_URL.fullmatch(url):
            raise ValueError(
                f"line {lineno}: artifact source must be an https URL to a "
                f".yaml file: {url!r}"
            )
        floating = sorted(segment.lower() for segment in url.split("/")
                          if segment.lower() in _FLOATING_URL_SEGMENTS)
        if floating:
            raise ValueError(
                f"line {lineno}: artifact source must not float on {floating}; "
                f"pin an exact release instead: {url!r}"
            )
        if not _PIN_DIGEST.fullmatch(pin):
            raise ValueError(
                f"line {lineno}: pin for {url!r} is not an immutable "
                f"sha256:<64hex> digest: {pin!r}"
            )
        if not _ENV_KEY.fullmatch(key):
            raise ValueError(f"line {lineno}: invalid env key {key!r}")
        if key in seen_keys:
            raise ValueError(
                f"line {lineno}: duplicate env key {key!r} (first seen on "
                f"line {seen_keys[key]})"
            )
        if url in seen_urls:
            raise ValueError(
                f"line {lineno}: duplicate artifact source {url!r} (first "
                f"seen on line {seen_urls[url]})"
            )
        seen_keys[key] = lineno
        seen_urls[url] = lineno
        records.append({"url": url, "pin": pin, "key": key})
    if not records:
        raise ValueError("no artifact pins found")
    found = {record["key"] for record in records}
    expected = set(ARTIFACT_PIN_KEYS)
    if found != expected:
        missing = sorted(expected - found)
        extra = sorted(found - expected)
        raise ValueError(
            f"artifact pin key set mismatch: missing={missing} "
            f"unexpected={extra}"
        )
    return records


def artifact_pin_exports(records: Sequence[Mapping[str, str]]) -> Dict[str, str]:
    """``<KEY>_URL`` and ``<KEY>_SHA256`` for ``$GITHUB_ENV``.

    ``_SHA256`` is the bare 64-hex digest so a shell can feed it straight
    to ``sha256sum -c`` after downloading ``_URL``.
    """
    exports: Dict[str, str] = {}
    for record in records:
        key = str(record["key"])
        exports[f"{key}_URL"] = str(record["url"])
        exports[f"{key}_SHA256"] = str(record["pin"]).split(":", 1)[1]
    return exports


def format_scalar_mapping(mapping: Mapping[str, str]) -> str:
    """Deterministic scalar encoding of a key→ref map (§7.3/§7.4).

    ``KEY=value;KEY=value`` with keys sorted and no trailing separator —
    the manifest schema forbids containers, so provenance maps travel as
    one auditable, machine-parsable string. Values carrying ``;``, ``=``
    or whitespace are rejected so the encoding stays unambiguous.
    """
    parts: List[str] = []
    for key in sorted(mapping):
        value = str(mapping[key] or "").strip()
        if not _ENV_KEY.fullmatch(str(key)):
            raise ValueError(f"invalid provenance key: {key!r}")
        if not value:
            raise ValueError(f"empty provenance value for {key}")
        if any(ch in value for ch in ";=") or any(ch.isspace() for ch in value):
            raise ValueError(f"unencodable provenance value for {key}: {value!r}")
        parts.append(f"{key}={value}")
    return ";".join(parts)


def parse_scalar_mapping(text: str) -> Dict[str, str]:
    """Inverse of :func:`format_scalar_mapping` (auditor/test helper)."""
    out: Dict[str, str] = {}
    for item in str(text or "").split(";"):
        item = item.strip()
        if not item:
            continue
        key, sep, value = item.partition("=")
        if not sep or not _ENV_KEY.fullmatch(key) or not value:
            raise ValueError(f"malformed scalar mapping entry: {item!r}")
        out[key] = value
    return out


def pin_provenance_exports(records: Sequence[Mapping[str, str]]) -> Dict[str, str]:
    """Manifest-ready provenance derived from the committed pins (§7).

    Returns the exact variables the driver reads for the external inputs:
    ``E2E_REGISTRY_DIGEST``, ``E2E_KIND_NODE_DIGEST`` and the scalar
    ``E2E_BASE_IMAGES`` map. Built (dynamic) images are exported later by
    the build step from real ``RepoDigests``.
    """
    by_key = {str(r["key"]): str(r["ref"]) for r in records}
    missing = [k for k in PINNED_IMAGE_KEYS if not by_key.get(k)]
    if missing:
        raise ValueError(f"missing immutable pins for: {missing}")
    bad = [k for k, ref in by_key.items() if not validate_digest_ref(ref)]
    if bad:
        raise ValueError(f"non-digest references for: {sorted(bad)}")
    return {
        "E2E_REGISTRY_DIGEST": by_key[REGISTRY_IMAGE_KEY],
        "E2E_KIND_NODE_DIGEST": by_key[KIND_NODE_IMAGE_KEY],
        "E2E_BASE_IMAGES": format_scalar_mapping(
            {k: by_key[k] for k in BASE_IMAGE_KEYS}
        ),
    }


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


def missing_execution_provenance(manifest: Mapping[str, Any]) -> List[str]:
    """Required provenance fields that are absent/empty (§9)."""
    data = manifest if isinstance(manifest, Mapping) else {}
    return [
        field
        for field in REQUIRED_EXECUTION_PROVENANCE
        if not str(data.get(field, "") or "").strip()
    ]


def finalize_execution_manifest(manifest: Dict[str, Any], result: str) -> Dict[str, Any]:
    """Finalize a manifest that describes a LIVE execution (§9).

    Schema validity and live-execution provenance completeness are kept
    separate on purpose: :func:`finalize_manifest` still accepts any
    structurally valid manifest (preflight/local contexts legitimately
    produce ``NOT_VERIFIED``/``BLOCKED`` manifests with no run behind
    them), while this function refuses to let a *successful* run claim
    PASS when a required provenance field is empty — the result is
    downgraded to FAIL and the gap recorded in ``provenance_rejection``.
    """
    gaps = missing_execution_provenance(manifest)
    if result == PASS and gaps:
        manifest["provenance_rejection"] = (
            "incomplete execution provenance: " + ",".join(gaps)
        )
        result = FAIL
    return finalize_manifest(manifest, result)


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
