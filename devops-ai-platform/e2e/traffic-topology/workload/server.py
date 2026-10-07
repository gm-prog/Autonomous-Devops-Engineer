"""Deterministic traffic-topology workload (Phase 8.7-B.0).

Every response says which stable/canary backend produced it, so the E2E
can attribute a real HTTP response to a real pod instead of inferring
the route from cluster objects. The identity is deliberately loud — a
header AND a body — because the whole proof rests on being able to tell
the two backends apart at the wire.

Fail closed: if ``ARES_TRACK`` is missing or not one of the two known
tracks, the process refuses to start. A workload that silently defaulted
its identity would let a misconfigured backend look like a valid one,
which is exactly the failure this fixture exists to make impossible.
"""

from __future__ import annotations

import json
import os
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KNOWN_TRACKS = ("stable", "canary")
TRACK_HEADER = "X-Ares-Track"

TRACK = os.environ.get("ARES_TRACK", "").strip().lower()
if TRACK not in KNOWN_TRACKS:
    print(
        f"refusing to start: ARES_TRACK must be one of {KNOWN_TRACKS}, "
        f"got {TRACK!r}",
        file=sys.stderr,
    )
    raise SystemExit(2)

INSTANCE = socket.gethostname()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # Small responses on a keep-alive connection otherwise pay the
    # delayed-ACK penalty (~40ms) per request, which would turn a
    # multi-thousand-request sample into a multi-minute crawl.
    disable_nagle_algorithm = True

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        # One write, not three: headers and body share a single segment.
        head = (
            f"HTTP/1.1 {status} {self.responses[status][0]}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"{TRACK_HEADER}: {TRACK}\r\n"
            f"X-Ares-Instance: {INSTANCE}\r\n"
            f"Connection: keep-alive\r\n\r\n"
        ).encode("latin-1")
        self.wfile.write(head + body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/healthz":
            # Probe endpoint: identity is in the header, body stays plain
            # so a readiness probe cannot depend on fixture semantics.
            self._send(200, b"ok", "text/plain")
            return
        if self.path in ("/", "/whoami"):
            body = json.dumps(
                {"track": TRACK, "instance": INSTANCE, "path": self.path},
                sort_keys=True,
            ).encode()
            self._send(200, body, "application/json")
            return
        self._send(404, b"not found", "text/plain")

    def log_message(self, *args):  # noqa: D102 - quiet by design
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
