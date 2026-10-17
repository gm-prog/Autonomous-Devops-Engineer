"""Phase 8.6-A corrective, Workstream G: evidence provenance is unambiguous.

The defect these tests pin down: on a ``pull_request`` event
``GITHUB_SHA`` is the ephemeral merge commit GitHub synthesises, not the
commit under review. Evidence that records it as *the* proof commit
claims to prove a commit that exists in no branch.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from e2e.evidence_provenance import (
    PROVENANCE_VERSION, provenance, resolve_head_sha, resolve_merge_sha,
    sha256_file, seal,
)

HEAD = "b" * 40
MERGE = "4a302393" + "0" * 32


@pytest.fixture()
def pull_request_event(tmp_path, monkeypatch):
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"head": {"sha": HEAD}}}))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_SHA", MERGE)
    monkeypatch.setenv("GITHUB_RUN_ID", "37629402074")
    monkeypatch.setenv("GITHUB_REPOSITORY", "gm-prog/Autonomous-Devops-Engineer")
    return event


def test_merge_sha_is_never_reported_as_the_head_sha(pull_request_event):
    assert resolve_head_sha() == HEAD
    assert resolve_merge_sha() == MERGE
    assert resolve_head_sha() != resolve_merge_sha()


def test_provenance_separates_the_three_commits(pull_request_event):
    block = provenance()
    assert block["head_sha"] == HEAD
    assert block["workflow_merge_sha"] == MERGE
    assert block["head_sha"] != block["workflow_merge_sha"]
    assert "evidence_generation_commit" in block


def test_no_bare_commit_field_can_be_misread(pull_request_event):
    """No ambiguous duplicate: every commit is named for what it is."""
    block = provenance()
    assert "commit" not in block
    assert "proof_commit" not in block
    commit_fields = {k for k in block
                     if k.endswith(("_sha", "_commit")) and isinstance(block[k], str)}
    assert commit_fields == {"head_sha", "workflow_merge_sha",
                             "evidence_generation_commit"}, commit_fields
    # the two that must never be conflated carry different values
    assert block["head_sha"] != block["workflow_merge_sha"]


def test_push_event_has_no_merge_sha(monkeypatch):
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_SHA", HEAD)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    assert resolve_head_sha() == HEAD
    assert resolve_merge_sha() == ""


def test_required_provenance_fields_are_present(pull_request_event):
    block = provenance()
    for field in ("provenance_version", "head_sha", "workflow_merge_sha",
                  "evidence_generation_commit", "repository", "branch",
                  "workflow_run_id", "generated_at"):
        assert field in block, f"missing provenance field {field}"
    assert block["provenance_version"] == PROVENANCE_VERSION


def test_unresolvable_values_are_empty_not_guessed(monkeypatch):
    for var in ("GITHUB_EVENT_NAME", "GITHUB_EVENT_PATH", "GITHUB_SHA",
                "GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_REF_NAME",
                "GITHUB_HEAD_REF"):
        monkeypatch.delenv(var, raising=False)
    block = provenance()
    assert block["head_sha"] == ""
    assert block["repository"] == ""
    assert "unknown" not in json.dumps(block)


def test_sealed_digest_is_independently_recomputable(tmp_path, pull_request_event):
    target = tmp_path / "evidence.json"
    record = seal({"provenance": provenance(), "checks": []}, target)
    assert record["artifact_sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()
    assert record["artifact_sha256"] == sha256_file(target)
    assert record["head_sha"] == HEAD


def test_sidecar_is_sha256sum_checkable(tmp_path, pull_request_event):
    target = tmp_path / "evidence.json"
    record = seal({"provenance": provenance()}, target)
    sidecar = (target.parent / (target.name + ".sha256")).read_text()
    assert sidecar == f"{record['artifact_sha256']}  {target.name}\n"


def test_evidence_cannot_contain_its_own_digest(tmp_path, pull_request_event):
    """A self-referential digest would be unverifiable by construction."""
    target = tmp_path / "evidence.json"
    record = seal({"provenance": provenance()}, target)
    assert record["artifact_sha256"] not in target.read_text()
