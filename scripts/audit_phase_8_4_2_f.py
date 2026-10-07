#!/usr/bin/env python3
"""Deterministic Git-topology audit guard for Phase 8.4.2-F.

Why this exists
---------------
The Phase 8.4.2-F audit report originally claimed that ``main`` and the
feature line had *no common ancestor*. That claim was false: it was an
artefact of auditing inside a **shallow clone**, where ``main`` is grafted
to a parentless commit and ``git merge-base`` therefore reports nothing.
GitHub's compare API disagreed, and GitHub was right.

This guard makes that class of drift mechanically detectable:

* it recomputes every topology fact from the local Git object graph;
* it compares them against a committed audit record;
* it exits non-zero on any mismatch;
* it **refuses to run in a shallow clone**, because the facts would be
  unreliable in exactly the way that produced the original defect.

It is an audit *guard*, not a report generator: it never edits the audit
record, never edits the report, and never mutates the repository. When the
record is wrong, a human decides whether the record or the code is at fault.

Usage
-----
Verify the committed record::

    python scripts/audit_phase_8_4_2_f.py

Verify an explicit record, in an explicit repository::

    python scripts/audit_phase_8_4_2_f.py --facts path/to/facts.json --repo /path/to/repo

Ad-hoc measurement of any two refs (prints facts, asserts nothing)::

    python scripts/audit_phase_8_4_2_f.py --base <ref> --head <ref>

Output is deterministic JSON on stdout (sorted keys, two-space indent,
trailing newline) so it can be diffed byte-for-byte. Exit codes:
``0`` PASS, ``1`` FAIL (a recorded fact does not match Git), ``2`` the
audit could not be performed at all (bad usage, missing ref, shallow clone).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

SCHEMA = "ares.audit.phase-8.4.2-f/1"
PASS = "PASS"
FAIL = "FAIL"

#: Fields compared between the committed record and live Git.
COMPARED_FIELDS = (
    "merge_base",
    "ahead",
    "behind",
    "changed_files",
    "additions",
    "deletions",
    "merge_commits",
)

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_UNUSABLE = 2


class AuditError(RuntimeError):
    """The audit could not be performed (as opposed to: it failed)."""


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise AuditError(
            f"git {' '.join(args)} failed ({proc.returncode}): "
            f"{proc.stderr.strip() or proc.stdout.strip()}"
        )
    return proc.stdout.strip()


def assert_usable_repository(repo: Path) -> None:
    """Refuse to audit a repository whose object graph is incomplete.

    A shallow clone silently truncates history, which makes ``merge-base``,
    ``rev-list`` counts and three-dot diffs wrong rather than absent. That
    is the precise failure mode this guard was written to prevent, so it is
    a hard error and never a warning.
    """
    if _git(repo, "rev-parse", "--is-shallow-repository") == "true":
        raise AuditError(
            "refusing to audit a shallow clone: merge-base and commit counts "
            "are unreliable here (run `git fetch --unshallow`, or check out "
            "with fetch-depth: 0)"
        )


def resolve(repo: Path, ref: str) -> str:
    """Resolve a ref to a full 40-hex object id."""
    try:
        return _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}")
    except AuditError as exc:
        raise AuditError(f"cannot resolve ref {ref!r}: {exc}") from exc


def measure(repo: Path, base: str, head: str) -> Dict[str, Any]:
    """Compute the topology facts for ``base`` → ``head``.

    ``changed_files``/``additions``/``deletions`` use the three-dot diff
    (``base...head``), i.e. the merge-base diff a pull request shows, so the
    numbers are comparable with GitHub's compare view. ``ahead``/``behind``
    are plain commit counts either side of the merge base.
    """
    base_sha = resolve(repo, base)
    head_sha = resolve(repo, head)

    merge_base: Optional[str]
    try:
        merge_base = _git(repo, "merge-base", base_sha, head_sha) or None
    except AuditError:
        merge_base = None  # genuinely unrelated histories

    ahead = int(_git(repo, "rev-list", "--count", f"{base_sha}..{head_sha}"))
    behind = int(_git(repo, "rev-list", "--count", f"{head_sha}..{base_sha}"))
    merge_commits = int(
        _git(repo, "rev-list", "--merges", "--count", f"{base_sha}..{head_sha}")
    )

    spec = f"{base_sha}...{head_sha}" if merge_base else f"{base_sha}..{head_sha}"
    additions = deletions = changed_files = binary_files = 0
    numstat = _git(repo, "diff", "--numstat", spec)
    for line in numstat.splitlines():
        if not line.strip():
            continue
        added, removed, _path = line.split("\t", 2)
        changed_files += 1
        if added == "-" or removed == "-":
            binary_files += 1
            continue
        additions += int(added)
        deletions += int(removed)

    return {
        "additions": additions,
        "ahead": ahead,
        "base": base_sha,
        "behind": behind,
        "binary_files": binary_files,
        "changed_files": changed_files,
        "deletions": deletions,
        "head": head_sha,
        "merge_base": merge_base,
        "merge_commits": merge_commits,
        "unrelated_histories": merge_base is None,
    }


def compare(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> List[str]:
    """Return a sorted list of human-readable mismatches (empty == PASS)."""
    mismatches: List[str] = []
    for field in COMPARED_FIELDS:
        if field not in expected:
            continue
        want = expected[field]
        got = actual.get(field)
        if field == "merge_base":
            # A recorded null asserts "no common ancestor". Finding one is a
            # mismatch, and so is recording one that Git cannot reproduce.
            want_norm = None if want in (None, "", "none") else str(want)
            if want_norm != got:
                mismatches.append(
                    f"merge_base: recorded {want_norm or 'none (unrelated histories)'}, "
                    f"git reports {got or 'none (unrelated histories)'}"
                )
            continue
        if int(want) != int(got or 0):
            mismatches.append(f"{field}: recorded {want}, git reports {got}")
    return sorted(mismatches)


def load_facts(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise AuditError(f"audit record not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise AuditError(f"audit record is not valid JSON: {path}: {exc}") from exc
    if data.get("schema") != SCHEMA:
        raise AuditError(f"audit record schema must be {SCHEMA}")
    if not isinstance(data.get("comparisons"), list) or not data["comparisons"]:
        raise AuditError("audit record must contain a non-empty 'comparisons' list")
    return data


def audit(repo: Path, facts: Mapping[str, Any]) -> Dict[str, Any]:
    results = []
    for entry in facts["comparisons"]:
        for key in ("name", "base", "head", "expected"):
            if key not in entry:
                raise AuditError(f"comparison entry is missing {key!r}")
        actual = measure(repo, str(entry["base"]), str(entry["head"]))
        mismatches = compare(entry["expected"], actual)
        results.append(
            {
                "actual": actual,
                "expected": dict(entry["expected"]),
                "mismatches": mismatches,
                "name": entry["name"],
                "result": FAIL if mismatches else PASS,
            }
        )
    return {
        "comparisons": results,
        "result": FAIL if any(r["mismatches"] for r in results) else PASS,
        "schema": SCHEMA,
    }


def emit(payload: Mapping[str, Any]) -> str:
    """Deterministic rendering: sorted keys, fixed indent, trailing newline."""
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="audit_phase_8_4_2_f",
        description="Verify the Phase 8.4.2-F audit record against live Git.",
    )
    default_repo = Path(__file__).resolve().parent.parent
    parser.add_argument("--repo", type=Path, default=default_repo)
    parser.add_argument(
        "--facts",
        type=Path,
        default=default_repo / "docs" / "phase-8.4.2-f-audit-facts.json",
    )
    parser.add_argument("--base", help="ad-hoc measurement: base ref")
    parser.add_argument("--head", help="ad-hoc measurement: head ref")
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        assert_usable_repository(args.repo)
        if args.base or args.head:
            if not (args.base and args.head):
                raise AuditError("--base and --head must be given together")
            payload: Dict[str, Any] = {
                "measurement": measure(args.repo, args.base, args.head),
                "result": "MEASURED",
                "schema": SCHEMA,
            }
            sys.stdout.write(emit(payload))
            return EXIT_PASS
        report = audit(args.repo, load_facts(args.facts))
    except AuditError as exc:
        sys.stdout.write(
            emit({"error": str(exc), "result": "UNUSABLE", "schema": SCHEMA})
        )
        return EXIT_UNUSABLE

    sys.stdout.write(emit(report))
    return EXIT_PASS if report["result"] == PASS else EXIT_FAIL


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
