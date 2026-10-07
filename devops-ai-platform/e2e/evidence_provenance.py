"""Phase 8.6-A corrective, Workstream G: unambiguous evidence provenance.

An evidence file must say exactly which commit it proves. The previous
records carried a single `commit` field populated from ``GITHUB_SHA``.
On a ``pull_request`` event that variable holds the ephemeral
**merge** commit GitHub synthesises for the run, not the commit under
review, so evidence appeared to prove a commit that exists in no
branch and that nobody ever reviewed.

This module emits every distinct commit under its own unambiguous name
so the three can never be confused:

``head_sha``
    The commit under review -- the branch tip. On a pull_request event
    this is ``pull_request.head.sha`` from the event payload, NOT
    ``GITHUB_SHA``.
``workflow_merge_sha``
    The ephemeral merge commit the workflow ran on, when one exists.
    Empty on push events. Never used as the proof commit.
``evidence_generation_commit``
    What ``git rev-parse HEAD`` reports in the checkout that produced
    the evidence. It is recorded independently so a mismatch with
    ``head_sha`` is visible rather than hidden.

No field is duplicated under a second name, and nothing is guessed: a
value that cannot be resolved is reported as the empty string, never
as a plausible-looking substitute.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

PROVENANCE_VERSION = "evidence-provenance-v1"


def _git(*args: str) -> str:
    try:
        out = subprocess.run(("git", *args), capture_output=True, text=True,
                             timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.strip() if out.returncode == 0 else ""


def _event_payload() -> Dict[str, Any]:
    path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not path or not Path(path).is_file():
        return {}
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def resolve_head_sha() -> str:
    """The commit under review, never the synthetic merge commit."""
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    if event.startswith("pull_request"):
        payload = _event_payload()
        head = (((payload.get("pull_request") or {}).get("head") or {})
                .get("sha") or "")
        if head:
            return head
        # Fall back to the documented variable rather than GITHUB_SHA,
        # which is the merge commit on this event.
        return os.environ.get("GITHUB_HEAD_SHA", "")
    return os.environ.get("GITHUB_SHA", "")


def resolve_merge_sha() -> str:
    """The ephemeral merge commit, when the event has one."""
    if os.environ.get("GITHUB_EVENT_NAME", "").startswith("pull_request"):
        return os.environ.get("GITHUB_SHA", "")
    return ""


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
    except OSError:
        return ""
    return digest.hexdigest()


def provenance(artifact_path: Optional[str | Path] = None) -> Dict[str, Any]:
    """Build the provenance block for an evidence artifact.

    ``artifact_sha256`` is deliberately omitted here when the artifact is
    the file being written: a file cannot contain its own digest. Use
    :func:`seal` to write the file and record its digest alongside it.
    """
    head = resolve_head_sha()
    generated_from = _git("rev-parse", "HEAD")
    block: Dict[str, Any] = {
        "provenance_version": PROVENANCE_VERSION,
        "head_sha": head,
        "workflow_merge_sha": resolve_merge_sha(),
        "evidence_generation_commit": generated_from,
        "head_sha_matches_generation_commit": bool(head) and head == generated_from,
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "branch": (os.environ.get("GITHUB_HEAD_REF")
                   or os.environ.get("GITHUB_REF_NAME", "")),
        "workflow": os.environ.get("GITHUB_WORKFLOW", ""),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "workflow_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        "job": os.environ.get("GITHUB_JOB", ""),
        "event_name": os.environ.get("GITHUB_EVENT_NAME", ""),
        "runner_os": os.environ.get("RUNNER_OS", ""),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if artifact_path is not None:
        block["artifact_sha256"] = sha256_file(artifact_path)
    return block


def seal(evidence: Dict[str, Any], path: str | Path) -> Dict[str, str]:
    """Write ``evidence`` to ``path`` and return its digest record.

    The digest covers the exact bytes written, so it is independently
    recomputable with ``sha256sum``. The sidecar is written next to the
    artifact rather than inside it, because a file cannot contain its
    own hash.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    target.write_text(body, encoding="utf-8")
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    record = {
        "artifact": target.name,
        "artifact_sha256": digest,
        "head_sha": evidence.get("provenance", {}).get("head_sha", ""),
        "workflow_run_id": evidence.get("provenance", {}).get("workflow_run_id", ""),
    }
    sidecar = target.with_name(target.name + ".sha256")
    # `sha256sum -c` compatible: "<digest>  <filename>"
    sidecar.write_text(f"{digest}  {target.name}\n", encoding="utf-8")
    return record
