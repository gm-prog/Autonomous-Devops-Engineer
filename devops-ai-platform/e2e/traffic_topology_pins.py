"""Committed artifact pins → verified download refs / provenance exports.

Phase 8.7-B.0. The weighted-traffic topology E2E downloads three external
YAML artifacts (Gateway API CRDs, Envoy Gateway CRDs, Envoy Gateway
controller manifest). None of them is an image, so they cannot use
``e2e/pinned-images.txt``: this module gives them the same discipline
from ``e2e/pinned-traffic-topology.txt``.

``--refs``
    ``<ENV_KEY> <url> sha256:<64hex>`` lines (sorted by key) — the exact
    URLs the workflow downloads and the digests it must observe.
``--exports``
    ``<VAR>=<value>`` lines for ``$GITHUB_ENV``: ``<KEY>_URL`` and the
    bare 64-hex ``<KEY>_SHA256`` suitable for ``sha256sum -c``.

Fail closed: any missing, malformed, duplicated or unpinned artifact
aborts with exit code 1 and an empty stdout. There is no floating tag,
no ``latest`` and no fallback mode.
"""

from __future__ import annotations

import os
import sys
from typing import List, Sequence

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from e2e.helpers import (  # noqa: E402
    artifact_pin_exports,
    parse_pinned_artifacts,
)

USAGE = "usage: python -m e2e.traffic_topology_pins <pin-file> --refs|--exports"


def render(text: str, mode: str) -> List[str]:
    """Pure renderer: pin-file text → output lines for ``mode``."""
    records = parse_pinned_artifacts(text)
    if mode == "--refs":
        ordered = sorted(records, key=lambda r: r["key"])
        return [f"{r['key']} {r['url']} {r['pin']}" for r in ordered]
    if mode == "--exports":
        exports = artifact_pin_exports(records)
        return [f"{key}={exports[key]}" for key in sorted(exports)]
    raise ValueError(f"unknown mode {mode!r}")


def main(argv: Sequence[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if len(args) != 2 or args[1] not in ("--refs", "--exports"):
        print(USAGE, file=sys.stderr)
        return 2
    path, mode = args
    try:
        with open(path, encoding="utf-8") as handle:
            lines = render(handle.read(), mode)
    except (OSError, ValueError) as exc:
        print(f"::error::artifact pins rejected: {exc}", file=sys.stderr)
        return 1
    print("\n".join(lines))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
