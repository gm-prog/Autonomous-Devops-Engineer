"""Machine-authenticated telemetry producer boundary (Phase 8.7-C).

Telemetry provenance is a **service-to-service** trust domain that is
separate from human JWT authentication.  The only accepted credential for
ingesting monitoring telemetry is a shared-secret HMAC-SHA256 signature over
a canonical request message, held by trusted telemetry producers
(e.g. Prometheus alerting, agent-service metric scrapers) and configured
server-side via ``TELEMETRY_HMAC_SECRET``.

Authentication envelope (HTTP headers):

* ``X-Telemetry-Signature`` — ``sha256=<hex>`` HMAC-SHA256 over the
  canonical message (below).
* ``X-Telemetry-Timestamp`` — Unix epoch seconds at signing time.
* ``X-Telemetry-Nonce``     — unique random string (replay protection).

Canonical message::

    METHOD\n
    PATH\n
    TIMESTAMP\n
    NONCE\n
    sha256hex(raw_body)

Fail-closed guarantees
======================

* No configured secret  -> every ingestion request is rejected (503) and no
  telemetry is recorded, no event is published.
* Missing/malformed headers, stale timestamp, replayed nonce, or any
  signature mismatch -> rejected (401/403) **before** any domain object is
  touched: rejected requests produce no metric datapoints and no threshold
  events.
* Signature comparison is constant-time (``hmac.compare_digest``).
* Timestamps are bound to a skew window so captured requests cannot be
  replayed indefinitely; nonces are single-use.
* No secret material is ever logged.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from collections import OrderedDict
from typing import Dict, Optional

logger = logging.getLogger("TelemetryAuth")

HEADER_SIGNATURE = "x-telemetry-signature"
HEADER_TIMESTAMP = "x-telemetry-timestamp"
HEADER_NONCE = "x-telemetry-nonce"

SIGNATURE_SCHEME = "sha256"

# Maximum accepted clock skew between producer and monitoring service.
DEFAULT_MAX_CLOCK_SKEW_SECONDS = 300

# Bounded replay window for seen nonces (keyed by nonce, value = expire-at).
_NONCE_STORE_MAX_ENTRIES = 4096


class TelemetryAuthenticationError(Exception):
    """Raised when a telemetry producer request cannot be authenticated."""

    def __init__(self, reason: str, status_code: int = 401):
        super().__init__(reason)
        self.reason = reason
        self.status_code = status_code


class NonceStore:
    """Bounded single-use nonce cache with expiry (replay protection)."""

    def __init__(self, max_entries: int = _NONCE_STORE_MAX_ENTRIES):
        self._entries: "OrderedDict[str, float]" = OrderedDict()
        self._max_entries = max_entries

    def seen_before(self, nonce: str, now: Optional[float] = None) -> bool:
        now = now if now is not None else time.time()
        self._evict(now)
        return nonce in self._entries

    def record(self, nonce: str, ttl_seconds: int, now: Optional[float] = None) -> None:
        now = now if now is not None else time.time()
        self._entries[nonce] = now + ttl_seconds
        self._evict(now)
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)

    def _evict(self, now: float) -> None:
        expired = [k for k, v in self._entries.items() if v <= now]
        for k in expired:
            self._entries.pop(k, None)


def canonical_message(
    method: str, path: str, timestamp: str, nonce: str, raw_body: bytes
) -> bytes:
    body_digest = hashlib.sha256(raw_body).hexdigest()
    return f"{method}\n{path}\n{timestamp}\n{nonce}\n{body_digest}\n".encode("utf-8")


def compute_signature(secret: str, canonical: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def verify_telemetry_signature(
    *,
    secret: Optional[str],
    method: str,
    path: str,
    raw_body: bytes,
    signature_header: Optional[str],
    timestamp_header: Optional[str],
    nonce_header: Optional[str],
    nonce_store: Optional[NonceStore] = None,
    max_clock_skew_seconds: int = DEFAULT_MAX_CLOCK_SKEW_SECONDS,
    now: Optional[float] = None,
) -> None:
    """Verify a telemetry producer request.  Raises TelemetryAuthenticationError.

    This function has NO side effects on any domain state — verification is
    pure (apart from nonce recording on success).
    """
    now = now if now is not None else time.time()

    # 1. Fail closed when the platform has no producer secret configured.
    if not secret:
        raise TelemetryAuthenticationError(
            "telemetry ingestion is disabled: no trusted producer secret configured",
            status_code=503,
        )

    # 2. Header presence (any missing component -> reject).
    if not signature_header or not timestamp_header or not nonce_header:
        raise TelemetryAuthenticationError(
            "missing telemetry authentication envelope "
            "(signature/timestamp/nonce headers required)"
        )

    # 3. Signature scheme + format.
    parts = signature_header.split("=", 1)
    if len(parts) != 2 or parts[0] != SIGNATURE_SCHEME or not parts[1]:
        raise TelemetryAuthenticationError("malformed X-Telemetry-Signature header")
    provided_signature = parts[1].strip().lower()
    if len(provided_signature) != 64:
        raise TelemetryAuthenticationError("malformed signature digest")

    # 4. Timestamp must be numeric and within the skew window (replay bound).
    try:
        request_time = float(timestamp_header)
    except ValueError:
        raise TelemetryAuthenticationError("malformed X-Telemetry-Timestamp header")
    if abs(now - request_time) > max_clock_skew_seconds:
        raise TelemetryAuthenticationError(
            "stale or out-of-window X-Telemetry-Timestamp (possible replay)"
        )

    # 5. Nonce must be fresh (replay protection).
    if not nonce_header.strip():
        raise TelemetryAuthenticationError("empty X-Telemetry-Nonce header")
    store = nonce_store if nonce_store is not None else NonceStore()
    if store.seen_before(nonce_header, now=now):
        raise TelemetryAuthenticationError("replayed X-Telemetry-Nonce (possible replay)")

    # 6. Constant-time signature comparison.
    expected = compute_signature(secret, canonical_message(method, path,
                                                           timestamp_header,
                                                           nonce_header, raw_body))
    if not hmac.compare_digest(expected, provided_signature):
        raise TelemetryAuthenticationError("invalid telemetry signature")

    # 7. Success: mark the nonce as used for the replay window.
    store.record(nonce_header, ttl_seconds=max_clock_skew_seconds * 2, now=now)


def make_signed_headers(
    secret: str,
    method: str,
    path: str,
    raw_body: bytes,
    now: Optional[float] = None,
    nonce: Optional[str] = None,
) -> Dict[str, str]:
    """Produce a valid producer envelope (used by trusted producers & tests)."""
    import uuid

    now = now if now is not None else time.time()
    nonce = nonce or uuid.uuid4().hex
    timestamp = str(int(now))
    signature = compute_signature(
        secret, canonical_message(method, path, timestamp, nonce, raw_body)
    )
    return {
        HEADER_SIGNATURE: f"{SIGNATURE_SCHEME}={signature}",
        HEADER_TIMESTAMP: timestamp,
        HEADER_NONCE: nonce,
    }
