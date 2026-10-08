"""Gateway-owned typed repository-analysis route (Phase 8.7-D).

Trust model
===========

* **Explicitly typed**: one fixed route (``POST /api/v1/repository/analyze``)
  with a strict Pydantic contract.  No generic dispatch, no user-controlled
  downstream service or path — the downstream target is the fixed
  ``agent`` entry of the gateway routing table plus a constant internal
  path (same pattern as the operator control-plane routes).
* **Authenticated + role-authorized**: requires a valid HS256 JWT
  (``verify_token``) and an analysis role (``require_analysis_role``).
  Unauthenticated requests get 401; insufficient roles get 403.
* **No provider credential in, none out**: the request schema uses
  ``extra="forbid"``, so a client-supplied ``gemini_api_key`` (or any other
  field) is a 422.  The server-side ``GEMINI_API_KEY`` is read only from the
  agent-service environment and is never echoed in responses or logs.
* **Fail closed downstream**: if the agent-service path is unavailable or
  reports the provider is unconfigured, the gateway returns a stable
  typed error (502/503/504) — the client then stays in its offline mode.
"""

from __future__ import annotations

import logging
import os

import requests
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from ..core.auth import require_analysis_role
from .gateway_router import (
    INCIDENT_INTERNAL_BASE,
    SERVICES,
    _DownstreamTransport,
)

logger = logging.getLogger("GatewayAnalysisRouter")

router = APIRouter(tags=["Repository Analysis"])

# Fixed downstream target: service constant + constant internal path.
_ANALYSIS_SERVICE = "agent"
ANALYSIS_INTERNAL_PATH = "/repository/analyze"


class AgentInternalConfigurationError(RuntimeError):
    """Gateway-to-agent transport is not configured safely."""


class _AgentAnalysisTransport:
    """Dedicated authenticated gateway-to-agent HTTP transport."""

    def call(self, method: str, url: str, json_body: dict, authorizing_identity: str) -> dict:
        token = os.getenv("AGENT_INTERNAL_TOKEN", "").strip()
        if len(token) < 32:
            raise AgentInternalConfigurationError("AGENT_INTERNAL_TOKEN is missing or too short.")
        response = requests.request(
            method,
            url,
            json=json_body,
            headers={
                "X-Gateway-Identity": authorizing_identity,
                "X-Agent-Internal-Token": token,
            },
            timeout=20,
        )
        response.raise_for_status()
        try:
            payload = response.json()
        except ValueError as exc:
            raise requests.RequestException("Agent-service returned a non-JSON response.") from exc
        if not isinstance(payload, dict):
            raise requests.RequestException("Agent-service returned a non-object response.")
        return payload


def get_agent_analysis_transport() -> _AgentAnalysisTransport:
    return _AgentAnalysisTransport()


class RepositoryAnalysisRequest(BaseModel):
    """Strict public analysis contract.

    ``extra="forbid"`` structurally rejects client-supplied fields —
    including any provider-key field — with a 422.
    """

    model_config = ConfigDict(extra="forbid")

    repo_name: str = Field(min_length=1, max_length=120)
    repo_url: str = Field(
        min_length=1, max_length=2048, pattern=r"^[a-zA-Z][a-zA-Z0-9+.\-]*://\S+$"
    )
    framework: str = Field(min_length=1, max_length=200)
    technology: str = Field(min_length=1, max_length=200)


def _map_downstream_error(exc: Exception) -> HTTPException:
    """Map agent-service failures to stable public semantics.

    The downstream detail may be relayed (it is provider-neutral by
    construction in the agent-service boundary) — never the credential.
    """
    if isinstance(exc, requests.HTTPError):
        status = exc.response.status_code if exc.response is not None else 502
        if status == 429:
            return HTTPException(status_code=429, detail="Server-side analysis is currently rate limited.")
        if status == 503:
            return HTTPException(status_code=503, detail="Server-side analysis is unavailable or not configured; use offline mode.")
        if status in (502, 504):
            return HTTPException(status_code=status, detail="Server-side analysis failure.")
        if 400 <= status < 500:
            return HTTPException(status_code=422, detail="Server-side analysis rejected the request.")
        return HTTPException(status_code=502, detail="Server-side analysis failure.")
    return HTTPException(status_code=502, detail="Downstream service 'agent' unavailable.")


@router.post("/api/v1/repository/analyze")
def analyze_repository(
    body: RepositoryAnalysisRequest,
    user: dict = Depends(require_analysis_role),
    transport: _AgentAnalysisTransport = Depends(get_agent_analysis_transport),
):
    """Typed, authenticated repository analysis.

    Forwards a fixed, typed payload to the fixed agent-service internal
    path.  The downstream host and path are code constants — never taken
    from request input.
    """
    base = SERVICES.get(_ANALYSIS_SERVICE)
    if base is None:  # defensive: the table is code-owned
        raise HTTPException(status_code=503, detail="Target microservice 'agent' is not registered for typed analysis.")
    url = f"{base}{INCIDENT_INTERNAL_BASE}{ANALYSIS_INTERNAL_PATH}"
    try:
        result = transport.call("POST", url, body.model_dump(), user["sub"])
    except AgentInternalConfigurationError as exc:
        raise HTTPException(status_code=503, detail="Internal analysis transport is not configured.") from exc
    except requests.HTTPError as exc:
        raise _map_downstream_error(exc) from exc
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502, detail="Downstream service 'agent' unavailable."
        ) from exc
    analysis = result.get("analysis") if isinstance(result, dict) else None
    if not isinstance(analysis, dict):
        raise HTTPException(
            status_code=502,
            detail="Server-side analysis returned an unparseable result.",
        )
    return {
        "status": result.get("status", "ANALYSIS_COMPLETE") if isinstance(result, dict) else "ANALYSIS_COMPLETE",
        "source": result.get("source", "server_gemini") if isinstance(result, dict) else "server_gemini",
        "analysis": analysis,
    }
