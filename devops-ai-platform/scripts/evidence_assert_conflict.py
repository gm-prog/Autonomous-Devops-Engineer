#!/usr/bin/env python3
"""Assert the contradictory-SHA fixture behaves as Phase 8.4.2-G.1 requires.

A pack built from two deployment records that disagree about ``source_sha``
must (a) report CONFLICTING, (b) keep BOTH observations, and (c) still
replay to the identical hash. Resolving the disagreement — picking a
winner, dropping a claim — is the failure this guard exists to catch.
"""

import json
import sys


def main(argv):
    if len(argv) != 2:
        print("usage: evidence_assert_conflict.py <fingerprint.json>", file=sys.stderr)
        return 2
    report = json.load(open(argv[1]))

    problems = []
    if report["pack_status"] != "CONFLICTING":
        problems.append(
            "pack_status is {!r}, expected CONFLICTING".format(report["pack_status"])
        )
    # five coherent observations plus the contradicting deployment record
    if report["item_count"] != 6:
        problems.append(
            "item_count is {}, expected 6 (both contradicting records kept)".format(
                report["item_count"]
            )
        )
    if len(set(report["evidence_ids"])) != report["item_count"]:
        problems.append("evidence ids are not unique")
    if not report["replay_matches"]:
        problems.append("replay did not reproduce the pack hash")

    print(
        "conflict fixture: status={} items={} replay_matches={} pack_hash={}".format(
            report["pack_status"], report["item_count"],
            report["replay_matches"], report["pack_hash"],
        )
    )
    for problem in problems:
        print("FAIL " + problem)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
