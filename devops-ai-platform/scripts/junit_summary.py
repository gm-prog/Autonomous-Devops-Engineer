#!/usr/bin/env python3
"""Print a one-line, machine-readable summary of a JUnit XML report.

Used by CI so the result survives in a step summary and an annotation:
job logs are not readable through the API on this installation.
"""

import sys
import xml.etree.ElementTree as ET


def main(argv):
    if len(argv) != 2:
        print("usage: junit_summary.py <report.xml>", file=sys.stderr)
        return 2
    root = ET.parse(argv[1]).getroot()
    suite = root if root.tag == "testsuite" else root[0]
    print(
        "collected={} failures={} errors={} skipped={}".format(
            suite.get("tests"), suite.get("failures"),
            suite.get("errors"), suite.get("skipped"),
        )
    )
    failed = [
        case.get("classname", "") + "::" + case.get("name", "")
        for case in suite.iter("testcase")
        if case.find("failure") is not None or case.find("error") is not None
    ]
    if failed:
        print("failed: " + ", ".join(sorted(failed)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
