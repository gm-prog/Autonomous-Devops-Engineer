"""In-cluster HTTP sampler for the weighted-traffic proof (Phase 8.7-B.0).

Runs inside the cluster and issues real HTTP requests through the real
Envoy Gateway data plane, then reports ONE JSON object on stdout:

    {"total": N, "stable": s, "canary": c, "other": o,
     "unattributed": u, "errors": e, "statuses": {"200": n, ...},
     "body_disagreements": b, "instances": {...}, "elapsed_ms": ms}

Attribution is taken from the ``X-Ares-Track`` response header the
workload sets, NOT from which URL was called: a misrouted request must be
counted against the backend that actually served it. The JSON body's
``track`` field is compared with the header and any disagreement is
counted separately (``body_disagreements``) rather than silently
resolved in favour of one of them.

The sampler deliberately does not fail on a mixed distribution — that is
the driver's job, with the driver's tolerance. It exits non-zero only
when it could not perform the measurement at all (no responses, bad
arguments), so a broken harness cannot look like a valid 0/0 sample.
"""

from __future__ import annotations

import http.client
import json
import os
import sys
import time

TRACKS = ("stable", "canary")
TRACK_HEADER = "X-Ares-Track"


def _env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        print(f"refusing to run: {name} is required", file=sys.stderr)
        raise SystemExit(2)
    return value


def main() -> int:
    url = _env("ARES_SAMPLER_URL")
    count = int(_env("ARES_SAMPLER_COUNT"))
    timeout = float(os.environ.get("ARES_SAMPLER_TIMEOUT_SECONDS", "10"))
    warmup = int(os.environ.get("ARES_SAMPLER_WARMUP", "3"))
    if count <= 0 or count > 200000:
        print(f"refusing to run: implausible count {count}", file=sys.stderr)
        return 2

    # http://<service>.<namespace>.svc.cluster.local[:port][/path]
    without_scheme = url.split("://", 1)[1]
    hostport, _, path = without_scheme.partition("/")
    host, _, port = hostport.partition(":")
    path = "/" + path if path else "/"
    connection = http.client.HTTPConnection(host, int(port or 80), timeout=timeout)

    statuses: dict[str, int] = {}
    counts = {track: 0 for track in TRACKS}
    instances: dict[str, set[str]] = {track: set() for track in TRACKS}
    unattributed = 0
    errors = 0
    body_disagreements = 0
    last_error = ""

    started = time.monotonic()
    for index in range(count + warmup):
        try:
            connection.request("GET", path, headers={"Connection": "keep-alive"})
            response = connection.getresponse()
            status = response.status
            header_track = (response.getheader(TRACK_HEADER) or "").strip().lower()
            instance = (response.getheader("X-Ares-Instance") or "").strip()
            body = response.read()
        except Exception as exc:  # noqa: BLE001 - recorded, never hidden
            if index >= warmup:
                errors += 1
            last_error = f"{type(exc).__name__}: {exc}"
            # A dropped keep-alive connection is normal over a long run.
            try:
                connection.close()
            except Exception:  # noqa: BLE001
                pass
            connection = http.client.HTTPConnection(
                host, int(port or 80), timeout=timeout
            )
            continue
        if index < warmup:
            continue  # warm-up: establish connections, do not measure
        statuses[str(status)] = statuses.get(str(status), 0) + 1
        if status == 200 and header_track in counts:
            counts[header_track] += 1
            if instance:
                instances[header_track].add(instance)
            try:
                parsed = json.loads(body.decode("utf-8"))
                body_track = str(parsed.get("track", "")).strip().lower()
            except Exception:  # noqa: BLE001
                body_track = ""
            if body_track != header_track:
                body_disagreements += 1
        else:
            unattributed += 1

    measured = sum(counts.values()) + unattributed + errors
    result = {
        "total": measured,
        "stable": counts["stable"],
        "canary": counts["canary"],
        "other": unattributed,
        "unattributed": unattributed,
        "errors": errors,
        "statuses": statuses,
        "body_disagreements": body_disagreements,
        "instances": {track: sorted(instances[track]) for track in TRACKS},
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "last_error": last_error,
    }
    print(json.dumps(result, sort_keys=True), flush=True)
    # Fail closed only when no HTTP response arrived at all: the sampler
    # could not measure anything (e.g. the Service has no endpoints), and
    # an empty report must never look like a valid zero-traffic result.
    # A run that received responses and attributed none of them IS a
    # measurement, and is reported as such (the negative probe relies on
    # exactly that: a 500 must not be mistaken for a broken harness).
    if not statuses:
        print(f"no HTTP response was received at all ({errors} transport errors); "
              f"the measurement is meaningless", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
