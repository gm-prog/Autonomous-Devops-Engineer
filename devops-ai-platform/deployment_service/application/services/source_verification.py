"""Independent, server-side verification of a requested source revision.

The deployment boundary already rejects non-canonical inputs (owner/repo
slug, full 40-hex SHA); this service answers the remaining trust question:
*does that exact revision actually exist in that canonical repository on
the authoritative host?*  Nothing may be inferred from plausible-looking
caller input alone.

Contract (fail closed):

* ``verify()`` returns an attestation dict (``method``, ``verified_at``,
  canonical repository/sha, remote commit id) on success.
* :class:`SourceVerificationError` with ``reason="not_found"`` — the
  revision cannot be confirmed to exist (HTTP 422 at the boundary).
* :class:`SourceVerificationError` with ``reason="unavailable"`` — the
  provider could not be consulted or answered inconsistently (HTTP 503).
  Nothing is inferred in either case: no branch/tag/short-SHA/default-HEAD
  substitution ever happens, and failure never degrades into success.

Credentials: the optional ``GITHUB_OAUTH_TOKEN`` travels ONLY in the
``Authorization`` header — never in the URL, never in argv, never in log
lines, never in the returned attestation or any persisted record.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any, Dict

import requests

_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_SLUG_PATTERN = re.compile(
    r"^(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+"
    r"/(?=[A-Za-z0-9_.-]*[A-Za-z0-9])[A-Za-z0-9_.-]+$"
)

_API_VERSION = "2026-03-10"
_TIMEOUT_SECONDS = 10.0


class SourceVerificationError(RuntimeError):
    """Raised when the requested revision cannot be independently verified.

    ``reason`` is one of ``"not_found"`` (revision/repository unconfirmed)
    or ``"unavailable"`` (provider unreachable, unauthorized, rate-limited
    or inconsistent).  ``public_message`` is safe to surface over HTTP; the
    exception never carries credentials or provider response bodies.
    """

    def __init__(self, reason: str, public_message: str):
        super().__init__(public_message)
        self.reason = reason
        self.public_message = public_message


class GitHubSourceVerifier:
    """Verifies ``repository_name`` + full SHA against the GitHub commits
    API.  The real default for ``DeploymentEngine``; tests inject fakes
    through the engine's ``source_verifier`` seam."""

    METHOD = "github-commit-lookup"

    def __init__(
        self,
        api_base_url: str = "https://api.github.com",
        token: str | None = None,
        timeout_seconds: float = _TIMEOUT_SECONDS,
    ):
        self.api_base_url = api_base_url.rstrip("/")
        # token=None → read the environment once at construction; the token
        # is only ever attached to the Authorization header below.
        self._token = token if token is not None else os.getenv("GITHUB_OAUTH_TOKEN", "")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        self.timeout_seconds = timeout_seconds

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": _API_VERSION,
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def verify(self, repository_name: Any, head_sha: Any) -> Dict[str, Any]:
        # Canonical-input gate first: malformed values never reach the
        # network and are never substituted with anything else.
        repo = repository_name if isinstance(repository_name, str) else ""
        if not _SLUG_PATTERN.fullmatch(repo):
            raise SourceVerificationError(
                "not_found",
                "requested source revision was not confirmed for a "
                "canonical owner/repository identity",
            )
        sha = head_sha.strip().lower() if isinstance(head_sha, str) else ""
        if not _SHA_PATTERN.fullmatch(sha):
            raise SourceVerificationError(
                "not_found",
                "requested source revision is not a full 40-character commit SHA",
            )

        url = f"{self.api_base_url}/repos/{repo}/commits/{sha}"
        try:
            response = requests.get(
                url, headers=self._headers(), timeout=self.timeout_seconds
            )
        except requests.RequestException as exc:
            # provider unreachable/timeout/DNS → fail closed; the message
            # carries only the exception class (never URL query or headers).
            raise SourceVerificationError(
                "unavailable",
                "source verification is currently unavailable; "
                "deployment requests fail closed",
            ) from exc

        if response.status_code == 404:
            raise SourceVerificationError(
                "not_found",
                "requested source revision was not found in this repository",
            )
        if response.status_code in (401, 403, 429) or response.status_code >= 500:
            raise SourceVerificationError(
                "unavailable",
                "source verification is currently unavailable; "
                "deployment requests fail closed",
            )
        if response.status_code != 200:
            raise SourceVerificationError(
                "unavailable",
                "source verification returned an unexpected result; "
                "deployment requests fail closed",
            )

        try:
            body = response.json()
            remote_sha = str(body.get("sha") or "")
        except (ValueError, AttributeError) as exc:
            raise SourceVerificationError(
                "unavailable",
                "source verification returned an unexpected result; "
                "deployment requests fail closed",
            ) from exc
        if remote_sha.lower() != sha:
            # A 200 for a different commit is a provider inconsistency —
            # never treated as confirmation of the requested revision.
            raise SourceVerificationError(
                "unavailable",
                "source verification did not confirm the requested revision; "
                "deployment requests fail closed",
            )

        return {
            "method": self.METHOD,
            "verified_at": datetime.now(timezone.utc).isoformat(),
            "verified_repository": repo,
            "verified_source_sha": sha,
            "verified_remote_commit": remote_sha.lower(),
        }
