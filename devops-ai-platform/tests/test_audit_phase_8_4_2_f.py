"""Tests for the Phase 8.4.2-F audit guard (``scripts/audit_phase_8_4_2_f.py``).

Every test builds its own throwaway Git repository, so nothing here touches
the network, GitHub, Docker or any credential. The one test that looks at
the real repository skips itself when the checkout is shallow, because a
shallow clone cannot answer topology questions correctly — which is the
exact defect this guard exists to prevent.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GUARD = REPO_ROOT / "scripts" / "audit_phase_8_4_2_f.py"
FACTS = REPO_ROOT / "docs" / "phase-8.4.2-f-audit-facts.json"

_spec = importlib.util.spec_from_file_location("audit_phase_8_4_2_f", GUARD)
audit_mod = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(audit_mod)

_ENV = {
    "GIT_AUTHOR_NAME": "Audit Fixture",
    "GIT_AUTHOR_EMAIL": "audit@example.invalid",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+00:00",
    "GIT_COMMITTER_NAME": "Audit Fixture",
    "GIT_COMMITTER_EMAIL": "audit@example.invalid",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+00:00",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "PATH": "/usr/bin:/bin:/usr/local/bin",
}


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, check=True, env=_ENV,
    )
    return proc.stdout.strip()


def _commit(repo: Path, name: str, lines: int, message: str) -> str:
    (repo / name).write_text("".join(f"line {i}\n" for i in range(lines)))
    _git(repo, "add", name)
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture()
def fixture_repo(tmp_path: Path):
    """base──┬─ E              (base branch: 1 commit after the fork)
             └─ C ── D         (head: 2 commits, 2 files, +5 lines)
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "trunk")
    _commit(repo, "root.txt", 1, "root")
    fork = _commit(repo, "shared.txt", 2, "shared")

    _git(repo, "checkout", "-q", "-b", "base_branch")
    _commit(repo, "only_on_base.txt", 1, "base-side commit")

    _git(repo, "checkout", "-q", "trunk")
    _commit(repo, "f1.txt", 3, "head commit C")
    head = _commit(repo, "f2.txt", 2, "head commit D")

    return {
        "repo": repo,
        "base": "base_branch",
        "head": head,
        "fork": fork,
        # hand-computed, never derived from the code under test
        "expected": {
            "merge_base": fork,
            "ahead": 2,
            "behind": 1,
            "changed_files": 2,
            "additions": 5,
            "deletions": 0,
            "merge_commits": 0,
        },
    }


def _facts_file(tmp_path: Path, entry: dict, name: str = "facts.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps({
        "schema": audit_mod.SCHEMA,
        "comparisons": [entry],
    }))
    return path


def _run(repo: Path, facts: Path):
    proc = subprocess.run(
        [sys.executable, str(GUARD), "--repo", str(repo), "--facts", str(facts)],
        capture_output=True, text=True, check=False,
    )
    return proc.returncode, proc.stdout


def _entry(fx, **overrides) -> dict:
    expected = dict(fx["expected"])
    expected.update(overrides)
    return {
        "name": "fixture", "base": fx["base"], "head": fx["head"],
        "expected": expected,
    }


# --------------------------------------------------------------------------
# normal case
# --------------------------------------------------------------------------


def test_correct_record_passes(fixture_repo, tmp_path):
    code, out = _run(fixture_repo["repo"], _facts_file(tmp_path, _entry(fixture_repo)))
    payload = json.loads(out)
    assert payload["result"] == audit_mod.PASS
    assert payload["comparisons"][0]["mismatches"] == []
    assert code == audit_mod.EXIT_PASS


# --------------------------------------------------------------------------
# each falsified field must fail, and must name itself
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field, bad_value",
    [
        ("merge_base", "0" * 40),
        ("ahead", 99),
        ("behind", 99),
        ("changed_files", 7),
        ("additions", 1234),
        ("deletions", 42),
        ("merge_commits", 3),
    ],
)
def test_falsified_fact_fails(fixture_repo, tmp_path, field, bad_value):
    facts = _facts_file(tmp_path, _entry(fixture_repo, **{field: bad_value}))
    code, out = _run(fixture_repo["repo"], facts)
    payload = json.loads(out)
    assert code == audit_mod.EXIT_FAIL
    assert payload["result"] == audit_mod.FAIL
    mismatches = payload["comparisons"][0]["mismatches"]
    assert any(m.startswith(f"{field}:") for m in mismatches), mismatches


def test_failure_reports_both_recorded_and_actual_values(fixture_repo, tmp_path):
    facts = _facts_file(tmp_path, _entry(fixture_repo, additions=1234))
    _code, out = _run(fixture_repo["repo"], facts)
    message = json.loads(out)["comparisons"][0]["mismatches"][0]
    assert "recorded 1234" in message and "git reports 5" in message


# --------------------------------------------------------------------------
# the specific defect this phase corrects: a false "no common ancestor"
# --------------------------------------------------------------------------


def test_claiming_unrelated_histories_when_a_merge_base_exists_fails(
    fixture_repo, tmp_path
):
    facts = _facts_file(tmp_path, _entry(fixture_repo, merge_base=None))
    code, out = _run(fixture_repo["repo"], facts)
    payload = json.loads(out)
    assert code == audit_mod.EXIT_FAIL
    assert payload["comparisons"][0]["actual"]["unrelated_histories"] is False
    assert any(
        "unrelated histories" in m and fixture_repo["fork"] in m
        for m in payload["comparisons"][0]["mismatches"]
    )


def test_genuinely_unrelated_histories_are_reported_as_such(tmp_path):
    repo = tmp_path / "orphan"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "trunk")
    _commit(repo, "a.txt", 1, "trunk root")
    _git(repo, "checkout", "-q", "--orphan", "island")
    _git(repo, "rm", "-q", "-rf", ".")
    head = _commit(repo, "b.txt", 1, "island root")

    facts = _facts_file(tmp_path, {
        "name": "orphan", "base": "trunk", "head": head,
        "expected": {"merge_base": None, "ahead": 1, "behind": 1},
    })
    code, out = _run(repo, facts)
    payload = json.loads(out)
    assert code == audit_mod.EXIT_PASS
    assert payload["comparisons"][0]["actual"]["unrelated_histories"] is True


def test_recording_a_merge_base_that_does_not_exist_fails(tmp_path):
    repo = tmp_path / "orphan2"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "trunk")
    _commit(repo, "a.txt", 1, "trunk root")
    _git(repo, "checkout", "-q", "--orphan", "island")
    _git(repo, "rm", "-q", "-rf", ".")
    head = _commit(repo, "b.txt", 1, "island root")

    facts = _facts_file(tmp_path, {
        "name": "orphan", "base": "trunk", "head": head,
        "expected": {"merge_base": "1" * 40},
    })
    code, _out = _run(repo, facts)
    assert code == audit_mod.EXIT_FAIL


# --------------------------------------------------------------------------
# a shallow clone must be refused, not silently mis-measured
# --------------------------------------------------------------------------


def test_shallow_clone_is_refused(fixture_repo, tmp_path):
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1",
         "file://" + str(fixture_repo["repo"]), str(shallow)],
        check=True, capture_output=True, env=_ENV,
    )
    assert _git(shallow, "rev-parse", "--is-shallow-repository") == "true"

    facts = _facts_file(tmp_path, _entry(fixture_repo))
    code, out = _run(shallow, facts)
    payload = json.loads(out)
    assert code == audit_mod.EXIT_UNUSABLE
    assert payload["result"] == "UNUSABLE"
    assert "shallow" in payload["error"]


# --------------------------------------------------------------------------
# determinism and non-mutation
# --------------------------------------------------------------------------


def test_output_is_byte_for_byte_deterministic(fixture_repo, tmp_path):
    facts = _facts_file(tmp_path, _entry(fixture_repo))
    first = _run(fixture_repo["repo"], facts)[1]
    second = _run(fixture_repo["repo"], facts)[1]
    assert first == second
    assert first.endswith("}\n")
    assert json.dumps(json.loads(first), indent=2, sort_keys=True) + "\n" == first


def test_guard_does_not_mutate_the_repository(fixture_repo, tmp_path):
    repo = fixture_repo["repo"]
    before = (
        _git(repo, "rev-parse", "HEAD"),
        _git(repo, "status", "--porcelain"),
        _git(repo, "rev-list", "--count", "--all"),
    )
    _run(repo, _facts_file(tmp_path, _entry(fixture_repo)))
    after = (
        _git(repo, "rev-parse", "HEAD"),
        _git(repo, "status", "--porcelain"),
        _git(repo, "rev-list", "--count", "--all"),
    )
    assert before == after


def test_unreadable_record_is_unusable_not_a_pass(tmp_path, fixture_repo):
    missing = tmp_path / "nope.json"
    code, out = _run(fixture_repo["repo"], missing)
    assert code == audit_mod.EXIT_UNUSABLE
    assert json.loads(out)["result"] == "UNUSABLE"

    bad_schema = tmp_path / "bad.json"
    bad_schema.write_text(json.dumps({"schema": "wrong/1", "comparisons": []}))
    code, out = _run(fixture_repo["repo"], bad_schema)
    assert code == audit_mod.EXIT_UNUSABLE


def test_adhoc_measurement_mode_asserts_nothing(fixture_repo):
    proc = subprocess.run(
        [sys.executable, str(GUARD), "--repo", str(fixture_repo["repo"]),
         "--base", fixture_repo["base"], "--head", fixture_repo["head"]],
        capture_output=True, text=True, check=False,
    )
    payload = json.loads(proc.stdout)
    assert proc.returncode == audit_mod.EXIT_PASS
    assert payload["result"] == "MEASURED"
    assert payload["measurement"]["merge_base"] == fixture_repo["fork"]
    assert payload["measurement"]["additions"] == 5


# --------------------------------------------------------------------------
# the committed record must describe THIS repository
# --------------------------------------------------------------------------


def test_committed_audit_record_matches_this_repository():
    if _git(REPO_ROOT, "rev-parse", "--is-shallow-repository") == "true":
        pytest.skip("shallow checkout cannot verify topology (needs fetch-depth: 0)")
    record = json.loads(FACTS.read_text())
    for entry in record["comparisons"]:
        for ref in (entry["base"], entry["head"]):
            if subprocess.run(
                ["git", "-C", str(REPO_ROOT), "cat-file", "-e", f"{ref}^{{commit}}"],
                capture_output=True,
            ).returncode:
                pytest.skip(f"commit {ref} is not present in this checkout")

    proc = subprocess.run(
        [sys.executable, str(GUARD)], capture_output=True, text=True, check=False
    )
    payload = json.loads(proc.stdout)
    assert payload["result"] == audit_mod.PASS, payload
    assert proc.returncode == audit_mod.EXIT_PASS


def test_record_does_not_assert_unrelated_histories_for_main():
    record = json.loads(FACTS.read_text())
    main_entry = next(
        e for e in record["comparisons"] if e["name"] == "main-divergence"
    )
    assert main_entry["expected"]["merge_base"], (
        "the main comparison must record a real merge base: main and this "
        "line are divergent, not unrelated"
    )


# --------------------------------------------------------------------------
# the report must stay consistent with the audit record (documentation drift)
# --------------------------------------------------------------------------

REPORT = REPO_ROOT / "docs" / "PHASE-8.4.2-F-INTEGRATION-AND-LIVE-E2E-AUDIT-REPORT.md"


def _record():
    data = json.loads(FACTS.read_text())
    return {e["name"]: e for e in data["comparisons"]}


def test_report_never_reasserts_the_false_topology_claim():
    """The retraction may discuss the claim; the report may not make it."""
    text = REPORT.read_text()
    for banned in (
        "(empty: unrelated histories)",
        "have no common ancestor",
        "has no common ancestor",
        "share no ancestor",
        "git rev-list --count main       -> 1",
    ):
        assert banned not in text, f"stale topology claim present: {banned!r}"


def test_report_states_the_real_merge_bases():
    text = REPORT.read_text()
    rec = _record()
    assert rec["main-divergence"]["expected"]["merge_base"][:8] in text
    assert rec["focused-integration-slice"]["expected"]["merge_base"][:8] in text
    assert "divergent" in text


@pytest.mark.parametrize("name,fields", [
    ("focused-integration-slice", ("ahead", "changed_files", "additions", "deletions")),
    ("main-divergence", ("ahead", "behind", "changed_files", "additions", "deletions")),
])
def test_report_quotes_the_recorded_figures(name, fields):
    text = REPORT.read_text()
    expected = _record()[name]["expected"]
    for field in fields:
        value = expected[field]
        assert f"{value:,}" in text or str(value) in text, (
            f"{name}.{field} = {value} does not appear in the report"
        )


def test_report_keeps_live_e2e_not_verified():
    import re
    text = REPORT.read_text()
    assert "LIVE E2E: NOT VERIFIED" in text
    assert not re.search(r"LIVE E2E:\s*PASS", text)


def test_report_labels_the_main_comparison_as_pr12_topology():
    """381 files is the main comparison and must never read as the PR #13 slice."""
    text = REPORT.read_text()
    assert "PR #12 topology" in text or "PR #12's\ntopology" in text
    marker = "The 381-file / +57,956 / −765 column is the **`main` comparison"
    assert marker in text, "the large comparison must be explicitly attributed"
