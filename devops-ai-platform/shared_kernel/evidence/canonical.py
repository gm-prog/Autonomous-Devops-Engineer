"""Canonical serialization, hashing and temporal rules (Phase 8.4.2-G.1).

Every deterministic property of the evidence layer rests on this module.
The rules below are **normative**: two logically identical observations must
produce byte-identical canonical form, and therefore an identical SHA-256,
in any process, on any host, in any Python dict insertion order.

Canonical form (§15)
--------------------
1. **Format** — JSON, UTF-8, produced by :func:`canonical_json`.
2. **Field ordering** — ``sort_keys=True`` applied recursively; mapping key
   order from the producer is never observable.
3. **Separators** — ``(",", ":")``; no insignificant whitespace.
4. **Null** — an explicit ``None`` serializes to ``null`` and is *retained*.
   An absent key is simply absent. ``None`` and "key missing" are therefore
   different canonical forms, because they are different claims (§16).
5. **Unicode** — text is NFC-normalized, then emitted with
   ``ensure_ascii=True`` so the byte form never depends on the host locale
   or filesystem encoding.
6. **Timestamps** — :class:`datetime` must be timezone-aware, is converted
   to UTC, and is emitted as ``YYYY-MM-DDTHH:MM:SS.ffffffZ`` (always six
   fractional digits).
7. **Numbers** — ``bool`` stays boolean; ``int`` stays integral; ``float``
   is rejected when NaN/Inf and otherwise emitted via :func:`repr` of the
   shortest round-trip representation. An integral float (``3.0``) is
   **not** silently folded into ``3`` — different input, different hash.
8. **Algorithm** — SHA-256, hex digest, lowercase.

This mirrors the convention already established by
``shared_kernel/domain/provenance.py`` (``sort_keys``/compact/``ensure_ascii``
+ SHA-256), so the platform has one hashing discipline rather than two.

Explicitly forbidden: hashing ``repr()`` of Python objects, hashing
``pickle`` output, or relying on dict insertion order.
"""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Mapping, Sequence

__all__ = [
    "CanonicalizationError",
    "canonical_json",
    "content_hash",
    "ensure_utc",
    "format_timestamp",
    "freeze",
    "normalize_text",
]

#: Timestamps always carry exactly six fractional digits so that
#: ``T12:00:00Z`` and ``T12:00:00.000000Z`` cannot hash differently.
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"

#: Guard against pathological nesting from untrusted producers (§34). The
#: limit is enforced during canonicalization so it also protects the hash
#: path, not just ingestion.
MAX_CANONICAL_DEPTH = 32


class CanonicalizationError(ValueError):
    """A value cannot be canonically serialized.

    Raised instead of coercing the value into something plausible — a
    silent coercion would make two different observations share a hash.
    """


def normalize_text(value: str) -> str:
    """NFC-normalize text so visually identical strings hash identically."""
    return unicodedata.normalize("NFC", value)


def ensure_utc(value: datetime, *, field: str = "timestamp") -> datetime:
    """Return ``value`` in UTC, rejecting naive datetimes (§13).

    A naive datetime has no defined instant, so accepting one would make
    the hash depend on the host's local clock configuration.
    """
    if not isinstance(value, datetime):
        raise CanonicalizationError(f"{field} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise CanonicalizationError(
            f"{field} must be timezone-aware; naive datetimes are rejected "
            "at the domain boundary"
        )
    return value.astimezone(timezone.utc)


def format_timestamp(value: datetime, *, field: str = "timestamp") -> str:
    """Canonical RFC3339-style UTC rendering with fixed microsecond width."""
    return ensure_utc(value, field=field).strftime(_TIMESTAMP_FORMAT) + "Z"


def _canonicalize(value: Any, *, depth: int = 0, path: str = "$") -> Any:
    """Recursively convert ``value`` into JSON-canonical primitives."""
    if depth > MAX_CANONICAL_DEPTH:
        raise CanonicalizationError(
            f"payload nesting exceeds {MAX_CANONICAL_DEPTH} levels at {path}"
        )

    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise CanonicalizationError(
                f"non-finite float at {path} has no canonical form"
            )
        return value
    if isinstance(value, str):
        return normalize_text(value)
    if isinstance(value, datetime):
        return format_timestamp(value, field=path)
    if isinstance(value, bytes):
        raise CanonicalizationError(
            f"raw bytes at {path} have no canonical JSON form; encode them "
            "explicitly at the adapter boundary"
        )
    if isinstance(value, Mapping):
        out = {}
        for key in value:
            if not isinstance(key, str):
                raise CanonicalizationError(
                    f"mapping key at {path} must be a string, got "
                    f"{type(key).__name__}"
                )
            out[normalize_text(key)] = _canonicalize(
                value[key], depth=depth + 1, path=f"{path}.{key}"
            )
        return out
    if isinstance(value, Sequence):
        return [
            _canonicalize(item, depth=depth + 1, path=f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    raise CanonicalizationError(
        f"value of type {type(value).__name__} at {path} is not canonically "
        "serializable"
    )


def canonical_json(value: Any) -> str:
    """Return the canonical JSON text for ``value``.

    Deterministic across processes: recursively key-sorted, compact,
    ASCII-escaped, NFC-normalized, with timezone-aware timestamps rendered
    to fixed-width UTC.
    """
    return json.dumps(
        _canonicalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def content_hash(value: Any) -> str:
    """SHA-256 hex digest over :func:`canonical_json` of ``value``."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def freeze(value: Any) -> Any:
    """Deep-freeze a payload so an EvidenceItem cannot be mutated in place.

    Mappings become :class:`~types.MappingProxyType`, sequences become
    tuples. Scalars pass through. The result still canonicalizes
    identically, because :func:`_canonicalize` treats the frozen forms as
    their mutable equivalents.
    """
    if isinstance(value, Mapping):
        return MappingProxyType({key: freeze(value[key]) for key in value})
    if isinstance(value, (list, tuple)):
        return tuple(freeze(item) for item in value)
    return value
