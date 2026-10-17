"""Committed immutable image pins → verified refs / provenance exports.

Phase 8.4.2-D §5/§8. The golden-path workflow calls this module BEFORE it
pulls anything, so every external image identity the job can possibly use
comes from the committed ``e2e/pinned-images.txt`` digests:

``--refs``
    ``<ENV_KEY> <repository@sha256:…>`` lines (sorted by key) — the exact
    references the workflow pulls and inspects.
``--exports``
    ``<VAR>=<value>`` lines for ``$GITHUB_ENV``: ``E2E_REGISTRY_DIGEST``,
    ``E2E_KIND_NODE_DIGEST`` and the scalar ``E2E_BASE_IMAGES`` map that
    the driver copies into the manifest.

Fail closed: any missing, malformed, duplicated or non-digest pin aborts
with exit code 1 and an empty stdout. There is no sentinel value, no
dispatch-time tag resolution and no fallback mode.
"""

from __future__ import annotations

import os
import sys
from typing import List, Sequence

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from e2e.helpers import (  # noqa: E402
    parse_pinned_images,
    pin_provenance_exports,
)

USAGE = "usage: python -m e2e.image_pins <pin-file> --refs|--exports"


def render(text: str, mode: str) -> List[str]:
    """Pure renderer: pin-file text → output lines for ``mode``."""
    records = parse_pinned_images(text)
    if mode == "--refs":
        return [
            f"{record['key']} {record['ref']}"
            for record in sorted(records, key=lambda r: r["key"])
        ]
    if mode == "--exports":
        exports = pin_provenance_exports(records)
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
        print(f"::error::immutable image pins rejected: {exc}", file=sys.stderr)
        return 1
    print("\n".join(lines))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
