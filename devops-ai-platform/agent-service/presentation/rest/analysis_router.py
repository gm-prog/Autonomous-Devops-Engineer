"""Agent-service internal repository-analysis boundary (Phase 8.7-D).

Trust model
===========

* This surface is **internal**: it is reached only through the API gateway's
  typed, JWT-authenticated ``POST /api/v1/repository/analyze`` route, which
  forwards a fixed, typed payload and propagates the authorizing identity
  via ``X-Gateway-Identity``.  It is not part of any user-facing generic
  dispatch surface.
* The handler is injected (``Depends(get_analysis_handler)``) around the
  ``RemoteLLMInterface`` port — production wires
  ``GeminiCallerAdapter`` (server-side ``GEMINI_API_KEY`` only); tests wire
  fakes via ``app.dependency_overrides``.
* Fail closed: when the server has no Gemini key the endpoint returns 503 —
  it never fabricates an analysis.
* No provider credential is ever accepted from, or returned to, any client.
"""

from __future__ import annotations

import hmac
import logging
import os
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from ...application.commands.analyze_repository import (
    ASSET_FIELDS,
    MAX_FIELD,
    MAX_REPO_NAME,
    MAX_REPO_URL,
    AnalyzeRepositoryCommand,
    AnalyzeRepositoryCommandHandler,
    MalformedAnalysisResponseError,
)
from ...infrastructure.llm.gemini_caller import (
    BudgetExceededException,
    BudgetStoreUnavailableException,
    GeminiAuthException,
    GeminiMalformedResponseException,
    GeminiRateLimitException,
    GeminiServiceUnavailableException,
    GeminiTimeoutException,
    GeminiUpstreamException,
)

logger = logging.getLogger("AgentAnalysisRouter")

router = APIRouter(prefix="/api/internal", tags=["Agent Internal"])


INTERNAL_TOKEN_HEADER = "X-Agent-Internal-Token"
IDENTITY_HEADER = "X-Gateway-Identity"


def require_gateway_internal_auth(
    internal_token: Optional[str] = Header(default=None, alias=INTERNAL_TOKEN_HEADER),
    gateway_identity: Optional[str] = Header(default=None, alias=IDENTITY_HEADER),
) -> str:
    """Authenticate the gateway-to-agent hop before any provider call."""
    expected = os.getenv("AGENT_INTERNAL_TOKEN", "").strip()
    if len(expected) < 32:
        logger.error("AGENT_INTERNAL_TOKEN is missing or too short; refusing internal analysis.")
        raise HTTPException(status_code=503, detail="Agent internal authentication is not configured.")
    if not gateway_identity or not gateway_identity.strip():
        raise HTTPException(status_code=401, detail="Gateway identity header is required.")
    if not internal_token or not hmac.compare_digest(internal_token, expected):
        raise HTTPException(status_code=401, detail="Invalid internal gateway credential.")
    return gateway_identity.strip()


# ---------------------------------------------------------------------------
# Strict, typed contract (no provider credential field is accepted)
# ---------------------------------------------------------------------------


class RepositoryAnalysisRequest(BaseModel):
    """Typed internal analysis request.  ``extra="forbid"`` makes any
    client-supplied field — including a provider key field — a 422."""

    model_config = ConfigDict(extra="forbid")

    repo_name: str = Field(min_length=1, max_length=MAX_REPO_NAME)
    repo_url: str = Field(min_length=1, max_length=MAX_REPO_URL, pattern=r"^[a-zA-Z][a-zA-Z0-9+.\-]*://\S+$")
    framework: str = Field(min_length=1, max_length=MAX_FIELD)
    technology: str = Field(min_length=1, max_length=MAX_FIELD)


class RepositoryAnalysisResponse(BaseModel):
    """Typed analysis response.  Contains only generated assets — never a
    provider credential or provider transport detail."""

    model_config = ConfigDict(extra="forbid")

    status: str = "ANALYSIS_COMPLETE"
    source: str = "server_gemini"
    analysis: dict[str, str]


# ---------------------------------------------------------------------------
# Dependency injection around the LLM port
# ---------------------------------------------------------------------------


def get_analysis_handler(request: Request) -> AnalyzeRepositoryCommandHandler:
    """Production wiring: the SHARED, application-lifetime analysis handler.

    The handler (and therefore the single ``GeminiCallerAdapter`` with its
    circuit-breaker and budget state) is created ONCE per agent application
    instance in ``create_app`` and stored on ``request.app.state`` — it is
    shared across requests, never rebuilt per request (D1 P0-1).  Overridable
    in tests via ``app.dependency_overrides``.
    """
    handler = getattr(request.app.state, "analysis_handler", None)
    if handler is None:  # defensive: mis-assembled app -> fail closed, never build ad hoc
        raise HTTPException(
            status_code=503,
            detail="Agent analysis handler is not initialized (application lifecycle not run).",
        )
    return handler


# ---------------------------------------------------------------------------
# Error mapping (typed Gemini failures -> stable HTTP semantics)
# ---------------------------------------------------------------------------


def _handle_failure(exc: Exception) -> HTTPException:
    if isinstance(exc, GeminiAuthException):
        return HTTPException(status_code=502, detail="Server-side Gemini credential was rejected by the provider.")
    if isinstance(exc, GeminiRateLimitException):
        return HTTPException(status_code=429, detail="Server-side Gemini is currently rate limited.")
    if isinstance(exc, GeminiTimeoutException):
        return HTTPException(status_code=504, detail="Server-side Gemini did not respond in time.")
    if isinstance(exc, (GeminiUpstreamException, GeminiMalformedResponseException, MalformedAnalysisResponseError)):
        return HTTPException(status_code=502, detail="Server-side Gemini returned an unusable result.")
    if isinstance(exc, BudgetExceededException):
        return HTTPException(status_code=503, detail="Server-side AI budget ceiling reached; analysis is blocked.")
    if isinstance(exc, BudgetStoreUnavailableException):
        # Fail closed: without a reachable budget store the call cannot be
        # spend-bounded, so it is blocked (never run unlimited).
        return HTTPException(status_code=503, detail="Server-side AI budget store is unavailable; analysis is blocked.")
    if isinstance(exc, GeminiServiceUnavailableException):
        return HTTPException(status_code=503, detail="Server-side Gemini is not available or not configured; the client should use its offline mode.")
    logger.exception("Unhandled analysis failure (%s).", type(exc).__name__)
    return HTTPException(status_code=500, detail="Internal analysis failure.")


@router.post("/repository/analyze", response_model=RepositoryAnalysisResponse)
def analyze_repository(
    body: RepositoryAnalysisRequest,
    handler: AnalyzeRepositoryCommandHandler = Depends(get_analysis_handler),
    identity: str = Depends(require_gateway_internal_auth),
):
    """Run validated repository analysis via the server-side Gemini path."""
    logger.info("Internal analysis request by identity=%s.", identity)
    try:
        assets = handler.handle(
            AnalyzeRepositoryCommand(
                repo_name=body.repo_name,
                repo_url=body.repo_url,
                framework=body.framework,
                technology=body.technology,
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # typed mapping; no secret material is logged
        raise _handle_failure(exc) from exc
    return RepositoryAnalysisResponse(
        status="ANALYSIS_COMPLETE",
        source="server_gemini",
        analysis={field: getattr(assets, field) for field in ASSET_FIELDS},
    )
