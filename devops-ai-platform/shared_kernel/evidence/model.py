"""Typed operational evidence domain model (Phase 8.4.2-G.1).

Raw operational observations are facts; correlation is deterministic
interpretation; agent reasoning comes later and lives nowhere in this file.
Nothing here calls a model, scores a hunch, or decides whether two events
"feel" related.

Immutability
------------
Every object is a frozen dataclass and every payload is deep-frozen via
:func:`~shared_kernel.evidence.canonical.freeze`, so an ``EvidenceItem``
cannot be edited after construction — not by a later pipeline stage, not by
a consumer holding a reference to its payload.

Absence vs emptiness
--------------------
``None`` means *we have no observation*. It is never rendered as the string
``"unknown"``, and an empty string is rejected where ``None`` is the honest
answer. :class:`EvidenceStatus` distinguishes the several different reasons
a fact may be absent, because "we did not ask", "the source said no such
object" and "the source was unreachable" are three different claims (§16).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .canonical import (
    CanonicalizationError,
    canonical_json,
    content_hash,
    ensure_utc,
    format_timestamp,
    freeze,
    normalize_text,
)
from .identities import (
    DeploymentIdentity,
    IdentityError,
    RepositoryIdentity,
    RuntimeIdentity,
    ServiceIdentity,
)

__all__ = [
    "EvidenceError",
    "EvidenceErrorCode",
    "ObservationType",
    "SourceType",
    "EvidenceStatus",
    "EvidenceStrength",
    "CorrelationKeyType",
    "RelationshipType",
    "EvidenceLimits",
    "DEFAULT_LIMITS",
    "SourceReference",
    "CorrelationKey",
    "EvidenceProvenance",
    "EvidenceItem",
    "EvidenceRelationship",
    "EvidencePack",
    "EVIDENCE_SCHEMA_VERSION",
]

#: Bump when the serialized shape of an EvidenceItem/EvidencePack changes.
EVIDENCE_SCHEMA_VERSION = "devops.operational-evidence/1"


# ---------------------------------------------------------------------------
# Error model (§37)
# ---------------------------------------------------------------------------

class EvidenceErrorCode(str, Enum):
    """Machine-readable error codes; no predictable failure returns a 500."""

    INVALID_EVIDENCE = "INVALID_EVIDENCE"
    INVALID_PROVENANCE = "INVALID_PROVENANCE"
    INVALID_CORRELATION_KEY = "INVALID_CORRELATION_KEY"
    INVALID_IDENTITY = "INVALID_IDENTITY"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
    STALE_EVIDENCE = "STALE_EVIDENCE"
    EVIDENCE_TOO_LARGE = "EVIDENCE_TOO_LARGE"
    EVIDENCE_NOT_FOUND = "EVIDENCE_NOT_FOUND"
    PACK_NOT_FOUND = "PACK_NOT_FOUND"
    SCHEMA_VERSION_UNSUPPORTED = "SCHEMA_VERSION_UNSUPPORTED"
    CORRELATION_POLICY_UNSUPPORTED = "CORRELATION_POLICY_UNSUPPORTED"
    IMMUTABLE_EVIDENCE = "IMMUTABLE_EVIDENCE"


class EvidenceError(ValueError):
    """Structured, machine-readable evidence failure."""

    def __init__(self, code: EvidenceErrorCode, message: str, **details: Any) -> None:
        super().__init__(f"{code.value}: {message}")
        self.code = code
        self.message = message
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_code": self.code.value,
            "message": self.message,
            "details": dict(self.details),
        }


# ---------------------------------------------------------------------------
# Controlled vocabularies (§7, §8, §16, §17, §12, §18)
# ---------------------------------------------------------------------------

class ObservationType(str, Enum):
    """What kind of thing was observed (§7) — finite and explicit."""

    METRIC = "METRIC"
    LOG = "LOG"
    TRACE = "TRACE"
    INCIDENT = "INCIDENT"
    DEPLOYMENT = "DEPLOYMENT"
    GIT_COMMIT = "GIT_COMMIT"
    GITHUB_EVENT = "GITHUB_EVENT"
    KUBERNETES_STATE = "KUBERNETES_STATE"
    CONFIGURATION_CHANGE = "CONFIGURATION_CHANGE"
    REMEDIATION_HISTORY = "REMEDIATION_HISTORY"
    HEALTH_CHECK = "HEALTH_CHECK"
    VALIDATION_RESULT = "VALIDATION_RESULT"


class SourceType(str, Enum):
    """Which trusted subsystem produced the observation (§8).

    A controlled enum, so caller-supplied strings can never become trusted
    source identities. External identifiers live in
    :class:`SourceReference`, not here.
    """

    MONITORING = "monitoring"
    INCIDENT_SERVICE = "incident_service"
    DEPLOYMENT_SERVICE = "deployment_service"
    GITHUB = "github"
    GIT = "git"
    KUBERNETES = "kubernetes"
    E2E = "e2e"
    DATABASE = "database"


class EvidenceStatus(str, Enum):
    """Epistemic status of the observation (§16)."""

    #: The observation exists and carries a payload.
    AVAILABLE = "AVAILABLE"
    #: The source was queried and authoritatively reported no such object.
    MISSING = "MISSING"
    #: The source could not be consulted (unreachable, forbidden, 404 of
    #: ambiguous meaning). NOT the same as MISSING.
    UNAVAILABLE = "UNAVAILABLE"
    #: We never asked for it.
    NOT_REQUESTED = "NOT_REQUESTED"
    #: Returned, but failed validation.
    INVALID = "INVALID"
    #: Contradicted by another observation; both are retained.
    CONFLICTING = "CONFLICTING"
    #: Valid historically, but outside the freshness window for real-time use.
    STALE = "STALE"


class EvidenceStrength(str, Enum):
    """How the item relates to the incident (§17).

    Deliberately ordinal-free labels rather than an invented probability.
    No numeric confidence is manufactured to make the schema look clever.
    """

    DIRECT = "DIRECT"
    DERIVED = "DERIVED"
    CORRELATED = "CORRELATED"
    CONFLICTING = "CONFLICTING"


class ScopeAuthority(str, Enum):
    """Who asserted a service/environment scope (§12, §15).

    A Git commit is a fact GitHub can attest to; the deployed scope that
    commit relates to is *not*. When a caller supplies the scope, the
    evidence must say so rather than letting the assertion inherit the
    credibility of the source system.

    ``SOURCE_NATIVE``
        the source system itself reported the scope (monitoring knows which
        service emitted a metric; the deployment service knows its target).
    ``CALLER_ASSERTED``
        the collecting caller supplied the scope as context. The source
        system never claimed it.
    """

    SOURCE_NATIVE = "SOURCE_NATIVE"
    CALLER_ASSERTED = "CALLER_ASSERTED"


class CorrelationKeyType(str, Enum):
    """Typed join keys (§12) — never flattened into one opaque string."""

    INCIDENT_ID = "incident_id"
    TRACE_ID = "trace_id"
    SPAN_ID = "span_id"
    REQUEST_ID = "request_id"
    DEPLOYMENT_ID = "deployment_id"
    WORKFLOW_RUN_ID = "workflow_run_id"
    COMMIT_SHA = "commit_sha"
    REPOSITORY = "repository"
    POD_UID = "pod_uid"
    SERVICE_NAME = "service.name"
    SERVICE_INSTANCE_ID = "service.instance.id"
    ENVIRONMENT = "environment"
    SERVICE_SCOPE = "service.scope"


class RelationshipType(str, Enum):
    """Typed edges (§18).

    ``PRECEDED`` and ``CORRELATES_WITH`` are observational. ``CAUSED_BY`` is
    a causal claim and the deterministic engine never emits it from
    temporal proximity alone.
    """

    CAUSED_BY = "CAUSED_BY"
    PRECEDED = "PRECEDED"
    DEPLOYED_AS = "DEPLOYED_AS"
    GENERATED_BY = "GENERATED_BY"
    OBSERVED_ON = "OBSERVED_ON"
    CORRELATES_WITH = "CORRELATES_WITH"
    DERIVED_FROM = "DERIVED_FROM"
    VALIDATES = "VALIDATES"
    CONTRADICTS = "CONTRADICTS"
    AFFECTS = "AFFECTS"


# ---------------------------------------------------------------------------
# Limits (§34)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EvidenceLimits:
    """Explicit bounds so ingestion cannot become a DoS vector.

    Policy is *rejection with a structured reason*, never silent truncation:
    a truncated payload would hash differently from the real observation
    while still claiming to be it.
    """

    max_payload_bytes: int = 256 * 1024
    max_string_length: int = 32 * 1024
    max_payload_depth: int = 16
    max_items_per_pack: int = 2_000
    max_relationships_per_pack: int = 20_000
    max_correlation_keys_per_item: int = 32

    def check_payload(self, payload: Any, *, evidence_hint: str = "") -> None:
        try:
            encoded = canonical_json(payload)
        except CanonicalizationError as exc:
            raise EvidenceError(
                EvidenceErrorCode.INVALID_EVIDENCE, str(exc), evidence=evidence_hint
            ) from exc
        size = len(encoded.encode("utf-8"))
        if size > self.max_payload_bytes:
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_TOO_LARGE,
                f"payload is {size} bytes, limit is {self.max_payload_bytes}",
                evidence=evidence_hint,
                size_bytes=size,
                limit_bytes=self.max_payload_bytes,
            )
        self._check_depth(payload, 0, evidence_hint)

    def _check_depth(self, value: Any, depth: int, hint: str) -> None:
        if depth > self.max_payload_depth:
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_TOO_LARGE,
                f"payload nesting exceeds {self.max_payload_depth} levels",
                evidence=hint,
            )
        if isinstance(value, str) and len(value) > self.max_string_length:
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_TOO_LARGE,
                f"string field exceeds {self.max_string_length} characters",
                evidence=hint,
            )
        if isinstance(value, Mapping):
            for item in value.values():
                self._check_depth(item, depth + 1, hint)
        elif isinstance(value, (list, tuple)):
            for item in value:
                self._check_depth(item, depth + 1, hint)


DEFAULT_LIMITS = EvidenceLimits()


# ---------------------------------------------------------------------------
# Source reference and provenance (§8, §14)
# ---------------------------------------------------------------------------

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@=-]{0,254}$")


def _safe_identifier(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise EvidenceError(
            EvidenceErrorCode.INVALID_PROVENANCE,
            f"{field_name} must be a string",
        )
    text = normalize_text(value).strip()
    if not _SAFE_ID.fullmatch(text):
        raise EvidenceError(
            EvidenceErrorCode.INVALID_PROVENANCE,
            f"{field_name} is not a valid structured identifier: {value!r}",
        )
    return text


@dataclass(frozen=True)
class SourceReference:
    """A *structured* pointer back to the originating object (§8).

    Deliberately not free prose: a reader must be able to go from this back
    to the exact source object without parsing an English sentence.
    """

    object_type: str
    object_id: str
    uri: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "object_type", _safe_identifier(self.object_type, "object_type")
        )
        object.__setattr__(
            self, "object_id", _safe_identifier(self.object_id, "object_id")
        )
        if self.uri is not None:
            if not isinstance(self.uri, str) or not self.uri.strip():
                raise EvidenceError(
                    EvidenceErrorCode.INVALID_PROVENANCE,
                    "source_reference.uri must be a non-empty string or None",
                )
            object.__setattr__(self, "uri", normalize_text(self.uri).strip())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "object_type": self.object_type,
            "object_id": self.object_id,
            "uri": self.uri,
        }

    @property
    def locator(self) -> str:
        return f"{self.object_type}:{self.object_id}"


@dataclass(frozen=True)
class EvidenceProvenance:
    """Where this fact came from, exactly (§14) — immutable once attached."""

    source_system: SourceType
    source_reference: SourceReference
    retrieved_at: datetime
    source_api_version: Optional[str] = None
    repository: Optional[RepositoryIdentity] = None
    commit_sha: Optional[str] = None
    workflow_run_id: Optional[str] = None
    artifact_digest: Optional[str] = None
    query: Optional[str] = None
    query_hash: Optional[str] = None
    #: Set only when the service/environment scope on the item did NOT come
    #: from ``source_system``. ``None`` means no caller assertion was made:
    #: either the item carries no scope, or the source reported it natively.
    service_scope_authority: Optional["ScopeAuthority"] = None

    def __post_init__(self) -> None:
        if not isinstance(self.source_system, SourceType):
            raise EvidenceError(
                EvidenceErrorCode.INVALID_PROVENANCE,
                "source_system must be a SourceType member; arbitrary strings "
                "cannot become trusted source identities",
            )
        if not isinstance(self.source_reference, SourceReference):
            raise EvidenceError(
                EvidenceErrorCode.INVALID_PROVENANCE,
                "source_reference must be a structured SourceReference",
            )
        try:
            object.__setattr__(
                self, "retrieved_at", ensure_utc(self.retrieved_at, field="retrieved_at")
            )
        except CanonicalizationError as exc:
            raise EvidenceError(
                EvidenceErrorCode.INVALID_PROVENANCE, str(exc)
            ) from exc
        if self.commit_sha is not None:
            text = str(self.commit_sha).strip().lower()
            if not _SHA40.fullmatch(text):
                raise EvidenceError(
                    EvidenceErrorCode.INVALID_PROVENANCE,
                    f"provenance commit_sha must be 40-hex or None, got "
                    f"{self.commit_sha!r}",
                )
            object.__setattr__(self, "commit_sha", text)
        if self.artifact_digest is not None:
            text = str(self.artifact_digest).strip().lower()
            if not _DIGEST.fullmatch(text):
                raise EvidenceError(
                    EvidenceErrorCode.INVALID_PROVENANCE,
                    "provenance artifact_digest must be 'sha256:<64hex>' or None",
                )
            object.__setattr__(self, "artifact_digest", text)
        if self.query is not None and self.query_hash is None:
            object.__setattr__(self, "query_hash", content_hash(self.query))
        if self.service_scope_authority is not None and not isinstance(
            self.service_scope_authority, ScopeAuthority
        ):
            raise EvidenceError(
                EvidenceErrorCode.INVALID_PROVENANCE,
                "service_scope_authority must be a ScopeAuthority member",
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_system": self.source_system.value,
            "source_reference": self.source_reference.to_dict(),
            "retrieved_at": format_timestamp(self.retrieved_at, field="retrieved_at"),
            "source_api_version": self.source_api_version,
            "repository": self.repository.to_dict() if self.repository else None,
            "commit_sha": self.commit_sha,
            "workflow_run_id": self.workflow_run_id,
            "artifact_digest": self.artifact_digest,
            "query": self.query,
            "query_hash": self.query_hash,
            # One uniform rule, matching the hash material: the authority
            # claim is serialized only where a caller actually made it.
            # Absence is not "unknown" - it means no caller assertion was
            # made, so the scope (if any) is the source system's own.
            **(
                {"service_scope_authority": self.service_scope_authority.value}
                if self.service_scope_authority is not None
                else {}
            ),
        }


# ---------------------------------------------------------------------------
# Correlation keys (§12)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CorrelationKey:
    """A typed, attributed join key.

    ``source`` records *who asserted* the key, so a key injected by a log
    line is distinguishable from one asserted by the deployment service.
    """

    key_type: CorrelationKeyType
    value: str
    source: SourceType
    #: Whether ``source`` actually asserted this key, or merely carried a
    #: caller-supplied assertion. Serialized only when it is not the
    #: default, so adding the field moved no existing hash.
    authority: "ScopeAuthority" = ScopeAuthority.SOURCE_NATIVE

    def __post_init__(self) -> None:
        if not isinstance(self.authority, ScopeAuthority):
            raise EvidenceError(
                EvidenceErrorCode.INVALID_CORRELATION_KEY,
                "correlation key authority must be a ScopeAuthority member",
            )
        if not isinstance(self.key_type, CorrelationKeyType):
            raise EvidenceError(
                EvidenceErrorCode.INVALID_CORRELATION_KEY,
                "key_type must be a CorrelationKeyType member",
            )
        if not isinstance(self.source, SourceType):
            raise EvidenceError(
                EvidenceErrorCode.INVALID_CORRELATION_KEY,
                "correlation key source must be a SourceType member",
            )
        if not isinstance(self.value, str) or not self.value.strip():
            raise EvidenceError(
                EvidenceErrorCode.INVALID_CORRELATION_KEY,
                f"correlation key {self.key_type.value} must have a non-empty value",
            )
        text = normalize_text(self.value).strip()
        if len(text) > 512:
            raise EvidenceError(
                EvidenceErrorCode.INVALID_CORRELATION_KEY,
                f"correlation key {self.key_type.value} value exceeds 512 chars",
            )
        if self.key_type is CorrelationKeyType.COMMIT_SHA:
            lowered = text.lower()
            if not _SHA40.fullmatch(lowered):
                raise EvidenceError(
                    EvidenceErrorCode.INVALID_CORRELATION_KEY,
                    f"commit_sha correlation key must be 40-hex, got {text!r}",
                )
            text = lowered
        object.__setattr__(self, "value", text)

    @property
    def join_token(self) -> str:
        """The exact token used for index lookups: type-qualified by design."""
        return f"{self.key_type.value}={self.value}"

    def to_dict(self) -> Dict[str, Any]:
        if self.authority is not ScopeAuthority.SOURCE_NATIVE:
            return {
                "key_type": self.key_type.value,
                "value": self.value,
                "source": self.source.value,
                "authority": self.authority.value,
            }
        return {
            "key_type": self.key_type.value,
            "value": self.value,
            "source": self.source.value,
        }


# ---------------------------------------------------------------------------
# Evidence item (§6)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EvidenceItem:
    """One normalized operational fact.

    ``evidence_id`` and ``content_hash`` are derived, never supplied: the
    same logical observation ingested twice yields the same id, which is
    what makes ingestion idempotent (§35).
    """

    observation_type: ObservationType
    provenance: EvidenceProvenance
    observed_at: datetime
    collected_at: datetime
    service_identity: Optional[ServiceIdentity] = None
    deployment_identity: Optional[DeploymentIdentity] = None
    resource_identity: Optional[RuntimeIdentity] = None
    incident_id: Optional[str] = None
    correlation_keys: Tuple[CorrelationKey, ...] = ()
    payload: Mapping[str, Any] = field(default_factory=dict)
    status: EvidenceStatus = EvidenceStatus.AVAILABLE
    strength: EvidenceStrength = EvidenceStrength.DIRECT
    limits: EvidenceLimits = DEFAULT_LIMITS
    evidence_id: str = ""
    content_hash: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.observation_type, ObservationType):
            raise EvidenceError(
                EvidenceErrorCode.INVALID_EVIDENCE,
                "observation_type must be an ObservationType member",
            )
        if not isinstance(self.provenance, EvidenceProvenance):
            raise EvidenceError(
                EvidenceErrorCode.INVALID_PROVENANCE,
                "evidence requires an EvidenceProvenance; provenance is mandatory",
            )
        if not isinstance(self.status, EvidenceStatus):
            raise EvidenceError(
                EvidenceErrorCode.INVALID_EVIDENCE, "status must be an EvidenceStatus"
            )
        if not isinstance(self.strength, EvidenceStrength):
            raise EvidenceError(
                EvidenceErrorCode.INVALID_EVIDENCE,
                "strength must be an EvidenceStrength",
            )

        for name in ("observed_at", "collected_at"):
            try:
                object.__setattr__(
                    self, name, ensure_utc(getattr(self, name), field=name)
                )
            except CanonicalizationError as exc:
                raise EvidenceError(
                    EvidenceErrorCode.INVALID_EVIDENCE, str(exc)
                ) from exc

        if self.incident_id is not None:
            object.__setattr__(
                self, "incident_id", _safe_identifier(self.incident_id, "incident_id")
            )

        for name, expected in (
            ("service_identity", ServiceIdentity),
            ("deployment_identity", DeploymentIdentity),
            ("resource_identity", RuntimeIdentity),
        ):
            value = getattr(self, name)
            if value is not None and not isinstance(value, expected):
                raise EvidenceError(
                    EvidenceErrorCode.INVALID_IDENTITY,
                    f"{name} must be a {expected.__name__} or None",
                )

        keys = tuple(self.correlation_keys or ())
        if len(keys) > self.limits.max_correlation_keys_per_item:
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_TOO_LARGE,
                f"more than {self.limits.max_correlation_keys_per_item} "
                "correlation keys on one item",
            )
        for key in keys:
            if not isinstance(key, CorrelationKey):
                raise EvidenceError(
                    EvidenceErrorCode.INVALID_CORRELATION_KEY,
                    "correlation_keys must contain CorrelationKey instances",
                )
        # deterministic, de-duplicated ordering: ingestion order must not be
        # observable in the hash
        keys = tuple(
            sorted(
                {key.join_token: key for key in keys}.values(),
                key=lambda k: (k.key_type.value, k.value, k.source.value),
            )
        )
        object.__setattr__(self, "correlation_keys", keys)

        payload = self.payload if self.payload is not None else {}
        if not isinstance(payload, Mapping):
            raise EvidenceError(
                EvidenceErrorCode.INVALID_EVIDENCE,
                "payload must be a mapping (use an explicit field, not a blob)",
            )
        if self.status in (
            EvidenceStatus.MISSING,
            EvidenceStatus.UNAVAILABLE,
            EvidenceStatus.NOT_REQUESTED,
        ) and payload:
            raise EvidenceError(
                EvidenceErrorCode.INVALID_EVIDENCE,
                f"status {self.status.value} records an absence and must not "
                "carry a payload",
            )
        self.limits.check_payload(
            payload, evidence_hint=self.provenance.source_reference.locator
        )
        object.__setattr__(self, "payload", freeze(dict(payload)))

        if (
            self.provenance.service_scope_authority is not None
            and self.service_identity is None
        ):
            raise EvidenceError(
                EvidenceErrorCode.INVALID_PROVENANCE,
                "service_scope_authority was declared but the item carries "
                "no service identity to attribute",
            )

        computed_hash = content_hash(self._content_material(payload))
        if self.content_hash and self.content_hash != computed_hash:
            raise EvidenceError(
                EvidenceErrorCode.INVALID_EVIDENCE,
                "supplied content_hash does not match the observation",
            )
        object.__setattr__(self, "content_hash", computed_hash)

        computed_id = self._derive_evidence_id()
        if self.evidence_id and self.evidence_id != computed_id:
            raise EvidenceError(
                EvidenceErrorCode.INVALID_EVIDENCE,
                "supplied evidence_id does not match its derived identity",
            )
        object.__setattr__(self, "evidence_id", computed_id)

    def _content_material(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Everything the observation actually *claims* (§14, §35).

        The hash must cover the typed identity fields, not only the free
        payload: two deployment records that disagree about ``source_sha``
        are different claims and must never collapse onto one evidence id,
        otherwise a contradiction would be silently deduplicated away.

        Deliberately excluded are the *circumstances of collection* —
        ``collected_at`` and ``provenance.retrieved_at`` — so that
        re-collecting the same observation is idempotent (§34).
        """
        provenance = self.provenance
        return {
            "observation_type": self.observation_type.value,
            "observed_at": format_timestamp(self.observed_at, field="observed_at"),
            "status": self.status.value,
            "strength": self.strength.value,
            "payload": payload,
            "incident_id": self.incident_id,
            "service_identity": (
                self.service_identity.to_dict() if self.service_identity else None
            ),
            "deployment_identity": (
                self.deployment_identity.to_dict()
                if self.deployment_identity
                else None
            ),
            "resource_identity": (
                self.resource_identity.to_dict() if self.resource_identity else None
            ),
            "correlation_keys": [key.to_dict() for key in self.correlation_keys],
            "provenance_claims": {
                "source_system": provenance.source_system.value,
                "source_reference": provenance.source_reference.to_dict(),
                "source_api_version": provenance.source_api_version,
                "repository": (
                    provenance.repository.qualified_name
                    if provenance.repository
                    else None
                ),
                "commit_sha": provenance.commit_sha,
                "workflow_run_id": provenance.workflow_run_id,
                "artifact_digest": provenance.artifact_digest,
                "query_hash": provenance.query_hash,
                # Present only when a caller asserted the scope. Existing
                # evidence therefore hashes exactly as before this field
                # existed, while the assertion itself is integrity-covered
                # wherever it is actually made.
                **(
                    {
                        "service_scope_authority":
                            provenance.service_scope_authority.value
                    }
                    if provenance.service_scope_authority is not None
                    else {}
                ),
            },
        }

    def _derive_evidence_id(self) -> str:
        """Deterministic identity (§35).

        ``sha256(source_system + source_reference + observed_at +
        content_hash)``, truncated to 32 hex characters and prefixed. The
        same observation re-ingested therefore collapses onto one item,
        while a *changed* payload yields a new id rather than silently
        overwriting history.
        """
        digest = content_hash(
            {
                "source_system": self.provenance.source_system.value,
                "source_reference": self.provenance.source_reference.to_dict(),
                "observed_at": format_timestamp(self.observed_at, field="observed_at"),
                "content_hash": self.content_hash,
            }
        )
        return f"ev-{digest[:32]}"

    @property
    def source_type(self) -> SourceType:
        return self.provenance.source_system

    @property
    def source_reference(self) -> SourceReference:
        """Single source of truth: the reference lives in provenance."""
        return self.provenance.source_reference

    @property
    def environment(self) -> Optional[str]:
        return self.service_identity.environment if self.service_identity else None

    def correlation_tokens(self) -> Tuple[str, ...]:
        return tuple(key.join_token for key in self.correlation_keys)

    def with_status(self, status: EvidenceStatus) -> "EvidenceItem":
        """Return a **new** item with a different status.

        Freshness and conflict are recorded by deriving a new object; the
        original observation is never mutated (§23, §27).
        """
        if status in (
            EvidenceStatus.MISSING,
            EvidenceStatus.UNAVAILABLE,
            EvidenceStatus.NOT_REQUESTED,
        ) and self.payload:
            raise EvidenceError(
                EvidenceErrorCode.INVALID_EVIDENCE,
                f"cannot relabel an item carrying a payload as {status.value}",
            )
        return EvidenceItem(
            observation_type=self.observation_type,
            provenance=self.provenance,
            observed_at=self.observed_at,
            collected_at=self.collected_at,
            service_identity=self.service_identity,
            deployment_identity=self.deployment_identity,
            resource_identity=self.resource_identity,
            incident_id=self.incident_id,
            correlation_keys=self.correlation_keys,
            payload=dict(self.payload),
            status=status,
            strength=self.strength,
            limits=self.limits,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "incident_id": self.incident_id,
            "observation_type": self.observation_type.value,
            "source_type": self.source_type.value,
            "observed_at": format_timestamp(self.observed_at, field="observed_at"),
            "collected_at": format_timestamp(self.collected_at, field="collected_at"),
            "service_identity": (
                self.service_identity.to_dict() if self.service_identity else None
            ),
            "deployment_identity": (
                self.deployment_identity.to_dict() if self.deployment_identity else None
            ),
            "resource_identity": (
                self.resource_identity.to_dict() if self.resource_identity else None
            ),
            "correlation_keys": [key.to_dict() for key in self.correlation_keys],
            "source_reference": self.source_reference.to_dict(),
            "provenance": self.provenance.to_dict(),
            "payload": _unfreeze(self.payload),
            "content_hash": self.content_hash,
            "status": self.status.value,
            "strength": self.strength.value,
        }


def _unfreeze(value: Any) -> Any:
    """Plain-Python view of a frozen payload (for serialization only)."""
    if isinstance(value, (MappingProxyType, Mapping)):
        return {key: _unfreeze(value[key]) for key in value}
    if isinstance(value, tuple):
        return [_unfreeze(item) for item in value]
    return value


# ---------------------------------------------------------------------------
# Relationships and packs (§18, §24)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EvidenceRelationship:
    """A typed, justified edge between two evidence items.

    ``basis`` names the rule that produced the edge, so every relationship
    in a pack is auditable back to a documented correlation rule rather
    than to an opaque heuristic.
    """

    source_evidence_id: str
    target_evidence_id: str
    relationship_type: RelationshipType
    basis: str
    rule_id: str
    temporal: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.relationship_type, RelationshipType):
            raise EvidenceError(
                EvidenceErrorCode.INVALID_EVIDENCE,
                "relationship_type must be a RelationshipType member",
            )
        for name in ("source_evidence_id", "target_evidence_id", "basis", "rule_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise EvidenceError(
                    EvidenceErrorCode.INVALID_EVIDENCE,
                    f"relationship {name} must be a non-empty string",
                )
        if self.relationship_type is RelationshipType.CAUSED_BY and self.temporal:
            raise EvidenceError(
                EvidenceErrorCode.INVALID_EVIDENCE,
                "a causal claim may not be derived from temporal proximity",
            )

    @property
    def sort_key(self) -> Tuple[str, str, str, str]:
        return (
            self.source_evidence_id,
            self.target_evidence_id,
            self.relationship_type.value,
            self.rule_id,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_evidence_id": self.source_evidence_id,
            "target_evidence_id": self.target_evidence_id,
            "relationship_type": self.relationship_type.value,
            "basis": self.basis,
            "rule_id": self.rule_id,
            "temporal": self.temporal,
        }


@dataclass(frozen=True)
class EvidencePack:
    """Immutable, versioned, replayable output of the correlation engine."""

    incident_id: str
    generated_at: datetime
    evidence_items: Tuple[EvidenceItem, ...]
    relationships: Tuple[EvidenceRelationship, ...]
    correlation_policy_version: str
    summary: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = EVIDENCE_SCHEMA_VERSION
    evidence_pack_id: str = ""
    pack_hash: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "incident_id", _safe_identifier(self.incident_id, "incident_id")
        )
        try:
            object.__setattr__(
                self, "generated_at", ensure_utc(self.generated_at, field="generated_at")
            )
        except CanonicalizationError as exc:
            raise EvidenceError(EvidenceErrorCode.INVALID_EVIDENCE, str(exc)) from exc
        object.__setattr__(self, "evidence_items", tuple(self.evidence_items))
        object.__setattr__(self, "relationships", tuple(self.relationships))
        object.__setattr__(self, "summary", freeze(dict(self.summary)))

        computed_hash = content_hash(self._hash_material())
        object.__setattr__(self, "pack_hash", computed_hash)
        # The pack id is a pure function of its content, so replaying the
        # same inputs reproduces the same id — no clock, no uuid4.
        object.__setattr__(self, "evidence_pack_id", f"pack-{computed_hash[:32]}")

    def _hash_material(self) -> Dict[str, Any]:
        """Canonical material for :attr:`pack_hash`.

        ``generated_at`` is deliberately excluded: the pack hash identifies
        *the evidence and its interpretation*, so replaying captured inputs
        at a later wall-clock time must reproduce the same hash (§26).
        """
        return {
            "schema_version": self.schema_version,
            "correlation_policy_version": self.correlation_policy_version,
            "incident_id": self.incident_id,
            "evidence_items": [item.to_dict() for item in self.evidence_items],
            "relationships": [rel.to_dict() for rel in self.relationships],
            "summary": _unfreeze(self.summary),
        }

    @property
    def integrity(self) -> Dict[str, Any]:
        return {
            "pack_hash": self.pack_hash,
            "hash_algorithm": "sha256",
            "canonical_form": "json/sorted/compact/ascii",
            "item_count": len(self.evidence_items),
            "relationship_count": len(self.relationships),
            "item_hashes": [item.content_hash for item in self.evidence_items],
        }

    @property
    def provenance(self) -> Dict[str, Any]:
        """Distinct source systems that contributed to this pack."""
        systems = sorted({item.source_type.value for item in self.evidence_items})
        return {
            "source_systems": systems,
            "schema_version": self.schema_version,
            "correlation_policy_version": self.correlation_policy_version,
        }

    def item(self, evidence_id: str) -> Optional[EvidenceItem]:
        for candidate in self.evidence_items:
            if candidate.evidence_id == evidence_id:
                return candidate
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_pack_id": self.evidence_pack_id,
            "incident_id": self.incident_id,
            "generated_at": format_timestamp(self.generated_at, field="generated_at"),
            "schema_version": self.schema_version,
            "correlation_policy_version": self.correlation_policy_version,
            "evidence_items": [item.to_dict() for item in self.evidence_items],
            "relationships": [rel.to_dict() for rel in self.relationships],
            "summary": _unfreeze(self.summary),
            "provenance": self.provenance,
            "integrity": self.integrity,
            "pack_hash": self.pack_hash,
        }
