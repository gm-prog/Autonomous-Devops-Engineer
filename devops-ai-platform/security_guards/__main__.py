"""Standalone structural security guard runner (CI job: structural-guards).

Usage:
    PYTHONPATH=devops-ai-platform python -m security_guards [--repo-root PATH]

Exits 0 when every guard passes on the actual repository source, 1 when any
guard reports a violation.  Failures are printed, never downgraded to
warnings: a failed security invariant must fail CI.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import ALL_GUARDS


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        default=None,
        help="Repository root to inspect (default: auto-detected from this file).",
    )
    args = parser.parse_args(argv)

    if args.repo_root:
        repo_root = Path(args.repo_root).resolve()
    else:
        # security_guards/ lives in devops-ai-platform/; repo root is one up.
        repo_root = Path(__file__).resolve().parents[2]

    print(f"structural security guards — repository root: {repo_root}")
    print("=" * 72)

    any_failed = False
    for name, check in ALL_GUARDS.items():
        violations = check(repo_root)
        if violations:
            any_failed = True
            print(f"[FAIL] {name}")
            for v in violations:
                print(f"  - {v}")
        else:
            print(f"[PASS] {name}: no violations on actual repository source")
    print("=" * 72)

    if any_failed:
        print("RESULT: FAIL — security invariant violated on current source.")
        return 1
    print("RESULT: PASS — all structural security guards hold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
