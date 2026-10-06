"""Operational Evidence Contract (Phase 8.4.2-G.1).

A deterministic, typed, provenance-preserving substrate that turns scattered
operational signals into one authoritative evidence pack.

    observations -> normalization -> provenance -> deterministic correlation
                 -> EvidencePack

The pack is the structured input a future agent will reason *over*. This
layer contains no model call, no reasoning transcript and no authorization
decision: the agent may reason over evidence, but it must never manufacture
the evidence.

See ``docs/PHASE-8.4.2-G.1-OPERATIONAL-EVIDENCE-CONTRACT.md``.
"""

from .canonical import (
    CanonicalizationError,
    canonical_json,
    content_hash,
    ensure_utc,
    format_timestamp,
)
from .correlation import (
    CORRELATION_POLICY_VERSION,
    CorrelationPolicy,
    DEFAULT_POLICY,
    OperationalCorrelationEngine,
)
from .identities import (
    DeploymentIdentity,
    IdentityError,
    RepositoryIdentity,
    RuntimeIdentity,
    ServiceIdentity,
)
from .model import (
    DEFAULT_LIMITS,
    EVIDENCE_SCHEMA_VERSION,
    CorrelationKey,
    CorrelationKeyType,
    EvidenceError,
    EvidenceErrorCode,
    EvidenceItem,
    EvidenceLimits,
    EvidencePack,
    EvidenceProvenance,
    EvidenceRelationship,
    EvidenceStatus,
    EvidenceStrength,
    ObservationType,
    RelationshipType,
    SourceReference,
    ScopeAuthority,
    SourceType,
)
from .replay import CAPTURE_SCHEMA, capture_inputs, rehydrate_item, replay_capture
from .store import EvidenceRepository, InMemoryEvidenceRepository

__all__ = [
    "CAPTURE_SCHEMA",
    "CORRELATION_POLICY_VERSION",
    "CanonicalizationError",
    "CorrelationKey",
    "CorrelationKeyType",
    "CorrelationPolicy",
    "DEFAULT_LIMITS",
    "DEFAULT_POLICY",
    "DeploymentIdentity",
    "EVIDENCE_SCHEMA_VERSION",
    "EvidenceError",
    "EvidenceErrorCode",
    "EvidenceItem",
    "EvidenceLimits",
    "EvidencePack",
    "EvidenceProvenance",
    "EvidenceRelationship",
    "EvidenceRepository",
    "EvidenceStatus",
    "EvidenceStrength",
    "IdentityError",
    "InMemoryEvidenceRepository",
    "ObservationType",
    "OperationalCorrelationEngine",
    "RelationshipType",
    "RepositoryIdentity",
    "RuntimeIdentity",
    "ServiceIdentity",
    "SourceReference",
    "ScopeAuthority",
    "SourceType",
    "canonical_json",
    "capture_inputs",
    "content_hash",
    "ensure_utc",
    "format_timestamp",
    "rehydrate_item",
    "replay_capture",
]
