"""Authoritative release-identity injection for the workload manifest (Phase 6.5.2).

Closes the attribution gap between the authoritative deployment record and
the real workload runtime:

    ``DeploymentRun.id`` + ``DeploymentRun.source_revision.head_sha``
      (created and persisted by the deployment engine, independently
      source-verified before any run exists)
        -> container env ``DEVOPS_DEPLOYMENT_ID`` / ``DEVOPS_SOURCE_SHA``
        -> ``devops_release_identity_info`` carrier (Phase 6.5.1 backend
           contract, applied at backend startup)
        -> Prometheus vector join -> Phase 6.5 attribution.

Contract (fail closed — mirrors ``backend/app/release_identity.py``):

* Identity comes ONLY from the trusted deployment execution context: the
  persisted run record handed in by the engine at the point the workload
  manifest is applied. Never from HTTP request payloads, query parameters,
  client headers, repository names, branches, timestamps, hostnames,
  image tags or the current Git HEAD.
* Both values are bound together or not at all. A missing/unusable
  identity injects **nothing** — no fallback, no partial and no
  fabricated identity — so a runtime without identity exposes no carrier
  series and Phase 6.5 correctly stays INCONCLUSIVE.
* Client-planted ``DEVOPS_*`` env entries already present in the manifest
  are replaced: the authoritative record wins over submitted spec fields.
* A manifest with no pod containers, or an unparseable manifest, is
  returned unchanged (the existing execution path behaves exactly as
  before).

Pure functions over manifest text — deterministic and unit-testable
without any engine, cluster, kubectl or network access.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

#: Phase 6.5.1 runtime contract names — must stay identical to
#: ``backend/app/release_identity.py`` (the backend re-validates both
#: values again at startup before exposing the carrier series).
DEPLOYMENT_ID_ENV = "DEVOPS_DEPLOYMENT_ID"
SOURCE_SHA_ENV = "DEVOPS_SOURCE_SHA"

#: Same deployment-id bound as the carrier contract: exact string is
#: preserved verbatim (no case/whitespace normalization), length 1-128,
#: no control characters.
MAX_DEPLOYMENT_ID_LENGTH = 128

#: Exact source SHA: full-match lowercase 40-hex only (uppercase,
#: whitespace, prefixes, short or arbitrary strings are unusable).
_SOURCE_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")

#: Workload kinds that carry a pod template under ``spec.template``.
_POD_TEMPLATE_KINDS = frozenset(
    {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}
)


def validate_release_identity(
    deployment_id: object, source_sha: object
) -> Optional[Tuple[str, str]]:
    """Return the exact pair to inject, or ``None`` if identity is unusable.

    Mirrors the Phase 6.5.1 fail-closed rules: the deployment id is kept
    verbatim (never normalized), the source SHA must be exactly 40
    lowercase hex characters.
    """
    if not isinstance(deployment_id, str) or not isinstance(source_sha, str):
        return None
    if not deployment_id.strip():  # missing / blank / whitespace-only
        return None
    if len(deployment_id) > MAX_DEPLOYMENT_ID_LENGTH:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in deployment_id):
        return None  # newline / control characters rejected
    if not _SOURCE_SHA_PATTERN.fullmatch(source_sha):
        return None
    return deployment_id, source_sha  # verbatim id, exact sha


def _pod_specs(document: Dict) -> List[Dict]:
    """Pod specs (``spec.template.spec``-shaped) contained in a document."""
    spec = document.get("spec")
    if not isinstance(spec, dict):
        return []
    kind = document.get("kind")
    if kind == "Pod":
        return [spec]
    if kind == "CronJob":
        job_template = spec.get("jobTemplate")
        if not isinstance(job_template, dict):
            return []
        job_spec = job_template.get("spec")
        if not isinstance(job_spec, dict):
            return []
        template = job_spec.get("template")
        if not isinstance(template, dict):
            return []
        pod_spec = template.get("spec")
        return [pod_spec] if isinstance(pod_spec, dict) else []
    if kind in _POD_TEMPLATE_KINDS:
        template = spec.get("template")
        if not isinstance(template, dict):
            return []
        pod_spec = template.get("spec")
        return [pod_spec] if isinstance(pod_spec, dict) else []
    return []


def _bind_container_env(container: object, identity: Tuple[str, str]) -> bool:
    """Upsert the identity pair into one container's ``env`` list.

    Existing entries with the same names are replaced (authoritative
    record wins); all other env entries are left untouched. Returns True
    when at least one container received the pair.
    """
    if not isinstance(container, dict):
        return False
    env = container.get("env")
    if not isinstance(env, list):
        env = []
        container["env"] = env
    for name, value in (
        (DEPLOYMENT_ID_ENV, identity[0]),
        (SOURCE_SHA_ENV, identity[1]),
    ):
        entry = {"name": name, "value": value}
        matches = [
            index
            for index, item in enumerate(env)
            if isinstance(item, dict) and item.get("name") == name
        ]
        if matches:
            # replace the client-planted value and drop any duplicate
            # entries so exactly one authoritative value remains
            env[matches[0]] = entry
            for index in reversed(matches[1:]):
                del env[index]
        else:
            env.append(entry)
    return True


def inject_release_identity(
    manifest_text: str,
    deployment_id: object,
    source_sha: object,
) -> Tuple[str, bool]:
    """Return ``(manifest_text, injected)`` with the identity pair bound.

    ``injected`` is True only when a fully valid identity was written into
    at least one container. Invalid/missing identity, unparseable YAML or
    a manifest without containers all return the original text untouched.
    """
    identity = validate_release_identity(deployment_id, source_sha)
    if identity is None:
        return manifest_text, False  # fail closed: nothing fabricated
    try:
        documents = list(yaml.safe_load_all(manifest_text))
    except yaml.YAMLError:
        return manifest_text, False  # unparseable → behavior unchanged
    injected = False
    for document in documents:
        if not isinstance(document, dict):
            continue
        for pod_spec in _pod_specs(document):
            for key in ("containers", "initContainers"):
                containers = pod_spec.get(key)
                if isinstance(containers, list):
                    for container in containers:
                        injected = _bind_container_env(container, identity) or injected
    if not injected:
        return manifest_text, False
    return (
        yaml.safe_dump_all(documents, sort_keys=False, default_flow_style=False),
        True,
    )


def bind_release_identity(
    manifest_path: str,
    deployment_id: object,
    source_sha: object,
) -> bool:
    """In-place binding helper; True iff identity bound into the file.

    Kept for compatibility and direct fail-closed tests. The deployment
    engine does NOT use it as a post-hash step anymore: canonicalization
    happens once in ``DeploymentEngine._effective_payload`` BEFORE
    validation, dry-run and ``artifact_hash``, so the approved artifact
    and the applied manifest are the same bytes.
    """
    text = Path(manifest_path).read_text(encoding="utf-8")
    bound_text, injected = inject_release_identity(text, deployment_id, source_sha)
    if injected:
        Path(manifest_path).write_text(bound_text, encoding="utf-8")
    return injected
