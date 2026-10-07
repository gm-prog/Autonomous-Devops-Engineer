"""Canonical identities for the operational evidence contract (G.1).

These value objects are the *join keys* of the whole evidence layer. If two
observations disagree about identity they must not silently merge, so every
identity here is frozen, validated at construction, and canonicalized once —
never re-derived ad hoc by a consumer.

Naming follows OpenTelemetry semantic conventions (``service.name``,
``service.version``, ``service.instance.id``,
``deployment.environment.name``) rather than inventing a competing
vocabulary (§9). Internally the attributes use Python-legal snake_case and
:meth:`ServiceIdentity.to_otel_attributes` emits the dotted OTel form; the
parallel spellings ``serviceName`` / ``svc_name`` / ``serviceId`` are
deliberately *not* accepted anywhere.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from .canonical import CanonicalizationError, normalize_text

__all__ = [
    "IdentityError",
    "RepositoryIdentity",
    "ServiceIdentity",
    "DeploymentIdentity",
    "RuntimeIdentity",
]

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SEGMENT = re.compile(r"^(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+$")
_SERVICE_NAME = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$")
_ENVIRONMENT = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,30}[a-z0-9])?$")

#: Maximum length accepted for any single identity component (§34).
MAX_IDENTITY_LENGTH = 253


class IdentityError(ValueError):
    """An identity value is malformed.

    Malformed identities are rejected, never coerced: an invalid SHA must
    not become a lowercase invalid string that then travels as trusted
    provenance (§30).
    """


def _require_text(value: Any, field: str, *, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str):
        raise IdentityError(f"{field} must be a string, got {type(value).__name__}")
    text = normalize_text(value).strip()
    if not text:
        raise IdentityError(f"{field} must not be empty")
    if len(text) > MAX_IDENTITY_LENGTH:
        raise IdentityError(
            f"{field} exceeds {MAX_IDENTITY_LENGTH} characters"
        )
    if not pattern.fullmatch(text):
        raise IdentityError(f"{field} is not canonical: {text!r}")
    return text


def _optional_sha(value: Any, field: str) -> Optional[str]:
    """Validate an optional 40-hex commit SHA.

    ``None`` means *absent evidence* and is always permitted. A present but
    malformed value (``"trust-me"``) is rejected rather than stored.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise IdentityError(f"{field} must be a 40-hex SHA string or None")
    text = value.strip().lower()
    if not _SHA40.fullmatch(text):
        raise IdentityError(
            f"{field} must be a full 40-hex commit SHA or None, got {value!r}"
        )
    return text


def _optional_digest(value: Any, field: str) -> Optional[str]:
    """Validate an optional ``sha256:<64hex>`` artifact digest."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise IdentityError(f"{field} must be a sha256 digest string or None")
    text = value.strip().lower()
    if not _DIGEST.fullmatch(text):
        raise IdentityError(
            f"{field} must be 'sha256:<64 hex>' or None, got {value!r}"
        )
    return text


def _optional_text(value: Any, field: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise IdentityError(f"{field} must be a string or None")
    text = normalize_text(value).strip()
    if not text:
        raise IdentityError(
            f"{field} must be a non-empty string or None; an empty string is "
            "not a synonym for absent evidence"
        )
    if len(text) > MAX_IDENTITY_LENGTH:
        raise IdentityError(f"{field} exceeds {MAX_IDENTITY_LENGTH} characters")
    return text


@dataclass(frozen=True)
class RepositoryIdentity:
    """Provider-qualified repository identity (§11).

    ``canonical_name`` is the normalized ``owner/repository`` slug used for
    correlation; ``source_representation`` preserves exactly what the
    source system said, so normalization never destroys forensic detail.
    """

    provider: str
    owner: str
    repository: str
    source_representation: Optional[str] = None

    @property
    def canonical_name(self) -> str:
        return f"{self.owner}/{self.repository}"

    @property
    def qualified_name(self) -> str:
        """Globally unique name including the provider."""
        return f"{self.provider}:{self.canonical_name}"

    @classmethod
    def parse(
        cls, value: Any, *, provider: str = "github"
    ) -> "RepositoryIdentity":
        """Parse ``owner/repo`` (or a URL-ish form) into a canonical identity.

        Normalizes surrounding whitespace, a trailing ``/``, a trailing
        ``.git`` and — for GitHub, whose slugs are case-insensitive — case.
        The untouched input is kept in ``source_representation``.
        """
        if not isinstance(value, str):
            raise IdentityError("repository must be a string")
        original = value
        text = normalize_text(value).strip()
        for prefix in ("https://github.com/", "http://github.com/", "git@github.com:"):
            if text.lower().startswith(prefix.lower()):
                text = text[len(prefix):]
                break
        text = text.rstrip("/")
        if text.lower().endswith(".git"):
            text = text[: -len(".git")]
        parts = [part for part in text.split("/") if part]
        if len(parts) != 2:
            raise IdentityError(
                f"repository must be 'owner/repository', got {original!r}"
            )
        owner, repository = parts
        if provider == "github":
            # GitHub slugs are case-insensitive; other providers may not be,
            # so case folding is provider-scoped rather than universal.
            owner, repository = owner.lower(), repository.lower()
        return cls(
            provider=_require_text(provider, "provider", pattern=_SEGMENT),
            owner=_require_text(owner, "owner", pattern=_SEGMENT),
            repository=_require_text(repository, "repository", pattern=_SEGMENT),
            source_representation=original,
        )

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "provider", _require_text(self.provider, "provider", pattern=_SEGMENT)
        )
        object.__setattr__(
            self, "owner", _require_text(self.owner, "owner", pattern=_SEGMENT)
        )
        object.__setattr__(
            self,
            "repository",
            _require_text(self.repository, "repository", pattern=_SEGMENT),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "owner": self.owner,
            "repository": self.repository,
            "canonical_name": self.canonical_name,
            "source_representation": self.source_representation,
        }


@dataclass(frozen=True)
class ServiceIdentity:
    """Canonical service identity (§9).

    ``environment`` is part of the identity, not an attribute of it: a
    ``checkout`` in ``staging`` and a ``checkout`` in ``production`` are
    different identities and must never correlate on name alone (§20, the
    environment-isolation gate).
    """

    name: str
    environment: str
    version: Optional[str] = None
    instance_id: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "name", _require_text(self.name, "service.name", pattern=_SERVICE_NAME)
        )
        object.__setattr__(
            self,
            "environment",
            _require_text(
                self.environment,
                "deployment.environment.name",
                pattern=_ENVIRONMENT,
            ),
        )
        object.__setattr__(
            self, "version", _optional_text(self.version, "service.version")
        )
        object.__setattr__(
            self,
            "instance_id",
            _optional_text(self.instance_id, "service.instance.id"),
        )

    @property
    def scope(self) -> str:
        """The correlation scope: name **and** environment, never name alone."""
        return f"{self.name}@{self.environment}"

    def to_otel_attributes(self) -> Dict[str, Any]:
        """Emit OpenTelemetry-conventional attribute names."""
        return {
            "service.name": self.name,
            "service.version": self.version,
            "service.instance.id": self.instance_id,
            "deployment.environment.name": self.environment,
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.to_otel_attributes()


@dataclass(frozen=True)
class RuntimeIdentity:
    """Where an observation was physically produced (optional everywhere)."""

    platform: Optional[str] = None
    namespace: Optional[str] = None
    workload: Optional[str] = None
    pod_uid: Optional[str] = None
    node: Optional[str] = None
    container: Optional[str] = None

    def __post_init__(self) -> None:
        for field in ("platform", "namespace", "workload", "pod_uid", "node", "container"):
            object.__setattr__(
                self, field, _optional_text(getattr(self, field), f"runtime.{field}")
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "platform": self.platform,
            "namespace": self.namespace,
            "workload": self.workload,
            "pod_uid": self.pod_uid,
            "node": self.node,
            "container": self.container,
        }


@dataclass(frozen=True)
class DeploymentIdentity:
    """Independently identifiable deployment (§10).

    Unknown fields are ``None`` — *absent evidence*. The contract never
    fabricates a literal ``"unknown"``, because that would be a claim the
    platform cannot support.
    """

    deployment_id: str
    service: ServiceIdentity
    source_sha: Optional[str] = None
    artifact_digest: Optional[str] = None
    status: Optional[str] = None
    started_at: Optional[Any] = None
    completed_at: Optional[Any] = None
    repository: Optional[RepositoryIdentity] = None
    branch: Optional[str] = None
    workflow_id: Optional[str] = None
    workflow_run_id: Optional[str] = None
    image_reference: Optional[str] = None
    image_digest: Optional[str] = None
    builder_identity: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "deployment_id",
            _require_text(self.deployment_id, "deployment_id", pattern=_SEGMENT),
        )
        if not isinstance(self.service, ServiceIdentity):
            raise IdentityError("deployment.service must be a ServiceIdentity")
        object.__setattr__(
            self, "source_sha", _optional_sha(self.source_sha, "source_sha")
        )
        object.__setattr__(
            self,
            "artifact_digest",
            _optional_digest(self.artifact_digest, "artifact_digest"),
        )
        object.__setattr__(
            self, "image_digest", _optional_digest(self.image_digest, "image_digest")
        )
        for field in (
            "status",
            "branch",
            "workflow_id",
            "workflow_run_id",
            "image_reference",
            "builder_identity",
        ):
            object.__setattr__(
                self, field, _optional_text(getattr(self, field), f"deployment.{field}")
            )
        if self.repository is not None and not isinstance(
            self.repository, RepositoryIdentity
        ):
            raise IdentityError(
                "deployment.repository must be a RepositoryIdentity or None"
            )

    def to_dict(self) -> Dict[str, Any]:
        from .canonical import format_timestamp

        def _ts(value: Any) -> Optional[str]:
            if value is None:
                return None
            try:
                return format_timestamp(value, field="deployment timestamp")
            except CanonicalizationError as exc:
                raise IdentityError(str(exc)) from exc

        return {
            "deployment_id": self.deployment_id,
            "service": self.service.to_dict(),
            "source_sha": self.source_sha,
            "artifact_digest": self.artifact_digest,
            "status": self.status,
            "started_at": _ts(self.started_at),
            "completed_at": _ts(self.completed_at),
            "repository": self.repository.to_dict() if self.repository else None,
            "branch": self.branch,
            "workflow_id": self.workflow_id,
            "workflow_run_id": self.workflow_run_id,
            "image_reference": self.image_reference,
            "image_digest": self.image_digest,
            "builder_identity": self.builder_identity,
        }


def identity_to_canonical(value: Any) -> Any:
    """Best-effort canonical dict for any identity value object."""
    if value is None:
        return None
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, Mapping):
        return dict(value)
    raise IdentityError(f"cannot canonicalize identity of type {type(value).__name__}")
