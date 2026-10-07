"""Write-once evidence persistence port and in-process implementation (§27).

The port exposes exactly the four reads the contract promises — by
incident, by evidence id, by pack id, and "list packs for an incident" —
plus append-only writes. There is deliberately **no update and no delete**:
historical evidence is never rewritten in place. A correction is a *new*
observation (it hashes differently, so it gets a new id) and the original
remains retrievable (§27, §28).

Persistence technology is intentionally not introduced here. The platform
already owns its Postgres repositories; this module defines the domain port
so a Postgres-backed adapter can be written later without changing a single
caller. Phase G.1 ships the in-process implementation that the deterministic
test suite uses — see the Known Limitations section of the G.1 document.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Sequence, Tuple

from .model import (
    EvidenceError,
    EvidenceErrorCode,
    EvidenceItem,
    EvidencePack,
)

__all__ = ["EvidenceRepository", "InMemoryEvidenceRepository"]


class EvidenceRepository(ABC):
    """Append-only repository port for evidence items and packs."""

    @abstractmethod
    def put_item(self, item: EvidenceItem) -> EvidenceItem:
        """Store an item. Re-storing the identical observation is a no-op."""

    @abstractmethod
    def get_item(self, evidence_id: str) -> EvidenceItem:
        """Fetch by id or raise ``EVIDENCE_NOT_FOUND``."""

    @abstractmethod
    def list_items_for_incident(self, incident_id: str) -> Sequence[EvidenceItem]:
        """All items bound to an incident, in deterministic order."""

    @abstractmethod
    def put_pack(self, pack: EvidencePack) -> EvidencePack:
        """Store a finalized pack. Re-storing an identical pack is a no-op."""

    @abstractmethod
    def get_pack(self, evidence_pack_id: str) -> EvidencePack:
        """Fetch by id or raise ``PACK_NOT_FOUND``."""

    @abstractmethod
    def list_packs_for_incident(self, incident_id: str) -> Sequence[EvidencePack]:
        """All packs generated for an incident, in deterministic order."""


class InMemoryEvidenceRepository(EvidenceRepository):
    """Deterministic, write-once, in-process implementation.

    Suitable for the correlation pipeline, unit tests and single-process
    reads. Thread-safety and durability are explicitly out of scope for
    G.1 and are documented as such rather than quietly assumed.
    """

    def __init__(self) -> None:
        self._items: Dict[str, EvidenceItem] = {}
        self._packs: Dict[str, EvidencePack] = {}
        #: incident -> evidence ids bound by a stored pack (append-only)
        self._items_by_incident: Dict[str, set] = {}

    # -- items ---------------------------------------------------------

    def put_item(self, item: EvidenceItem) -> EvidenceItem:
        if not isinstance(item, EvidenceItem):
            raise EvidenceError(
                EvidenceErrorCode.INVALID_EVIDENCE,
                "only EvidenceItem instances can be stored",
            )
        existing = self._items.get(item.evidence_id)
        if existing is not None:
            # Identity is derived from content, so a collision with a
            # different hash would mean the derivation was broken. Fail
            # loudly rather than overwrite history.
            if existing.content_hash != item.content_hash:
                raise EvidenceError(
                    EvidenceErrorCode.IMMUTABLE_EVIDENCE,
                    "refusing to overwrite stored evidence with different "
                    "content under the same id",
                    evidence_id=item.evidence_id,
                )
            return existing
        self._items[item.evidence_id] = item
        return item

    def get_item(self, evidence_id: str) -> EvidenceItem:
        item = self._items.get(evidence_id)
        if item is None:
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_NOT_FOUND,
                f"no evidence item {evidence_id!r}",
                evidence_id=evidence_id,
            )
        return item

    def list_items_for_incident(self, incident_id: str) -> Sequence[EvidenceItem]:
        """Evidence associated with an incident, in deterministic order.

        Membership has two sources, and both are real: an item may carry
        ``incident_id`` itself, or it may have been bound to the incident
        by the correlation engine and stored as part of a pack. A metric
        emitted by a deployment never carries an incident id, yet it is
        unambiguously part of that incident's evidence once correlated.
        """
        member_ids = set(self._items_by_incident.get(incident_id, ()))
        member_ids.update(
            item.evidence_id
            for item in self._items.values()
            if item.incident_id == incident_id
        )
        return tuple(
            sorted(
                (self._items[evidence_id] for evidence_id in member_ids),
                key=lambda i: i.evidence_id,
            )
        )

    # -- packs ---------------------------------------------------------

    def put_pack(self, pack: EvidencePack) -> EvidencePack:
        if not isinstance(pack, EvidencePack):
            raise EvidenceError(
                EvidenceErrorCode.INVALID_EVIDENCE,
                "only EvidencePack instances can be stored",
            )
        existing = self._packs.get(pack.evidence_pack_id)
        if existing is not None:
            if existing.pack_hash != pack.pack_hash:
                raise EvidenceError(
                    EvidenceErrorCode.IMMUTABLE_EVIDENCE,
                    "refusing to overwrite a stored pack with a different hash",
                    evidence_pack_id=pack.evidence_pack_id,
                )
            return existing
        membership = self._items_by_incident.setdefault(pack.incident_id, set())
        for item in pack.evidence_items:
            self.put_item(item)
            membership.add(item.evidence_id)
        self._packs[pack.evidence_pack_id] = pack
        return pack

    def get_pack(self, evidence_pack_id: str) -> EvidencePack:
        pack = self._packs.get(evidence_pack_id)
        if pack is None:
            raise EvidenceError(
                EvidenceErrorCode.PACK_NOT_FOUND,
                f"no evidence pack {evidence_pack_id!r}",
                evidence_pack_id=evidence_pack_id,
            )
        return pack

    def list_packs_for_incident(self, incident_id: str) -> Sequence[EvidencePack]:
        return tuple(
            sorted(
                (
                    pack
                    for pack in self._packs.values()
                    if pack.incident_id == incident_id
                ),
                key=lambda p: p.evidence_pack_id,
            )
        )
