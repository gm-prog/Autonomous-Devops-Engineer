"""API Gateway control-plane router (Phase 8.7-C).

Trust model
===========

This router exposes **explicitly typed, function-specific** downstream
operations only.  The pre-8.7-C generic dispatcher

    POST /v1/gateway/dispatch/{service_name}

which forwarded an arbitrary authenticated user's arbitrary JSON body to an
arbitrary ``{service}/api/internal`` target — including the monitoring
service — has been **removed**.  It is structurally unavailable: no route on
this router accepts a user-chosen downstream service, a user-chosen internal
path, or an untyped relay payload.

In particular:

* There is **no** user-facing route that forwards to the monitoring service.
  Monitoring telemetry is ingested only through the machine-authenticated
  (HMAC-SHA256) producer boundary of the monitoring service
  (``monitoring-service/presentation/rest/telemetry_router.py``).  Human JWT
  authentication (any role, including operator) is not a valid telemetry
  producer credential — telemetry provenance and operator authorization are
  separate trust domains.
* Privileged control-plane operations (hotfix proposal approval / execution)
  are operator-role gated and forward a fixed, typed payload to a fixed
  incident-service path.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import requests
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..core.auth import GatewayRateLimiter, require_operator, verify_token

logger = logging.getLogger("GatewayRouter")

router = APIRouter(prefix="/v1/gateway", tags=["Gateway Router"])
limiter = GatewayRateLimiter()

# Downstream routing table for the explicitly typed operations below.
# NOTE: "monitoring" is intentionally ABSENT — the gateway has no
# user-facing route into the monitoring service. Telemetry ingestion lives
# exclusively behind the monitoring service's machine-authenticated boundary.
SERVICES = {
    "repo": "http://repo-service:8010",
    "agent": "http://agent-service:8020",
    "deployment": "http://deployment-service:8030",
    "incident": "http://incident-service:8050",
}

# Fixed internal paths the typed operations may call.  Paths are constants:
# no user input may influence the downstream path or host.
INCIDENT_INTERNAL_BASE = "/api/internal"


class ApproveHotfixProposalRequest(BaseModel):
    """Typed request for approving a verified hotfix proposal."""

    expected_state: str = Field(default="PendingApproval", max_length=40)
    approver_note: Optional[str] = Field(default=None, max_length=500)


class ExecuteHotfixProposalRequest(BaseModel):
    """Typed request for executing an approved hotfix proposal."""

    expected_state: str = Field(default="Approved", max_length=40)
    execution_note: Optional[str] = Field(default=None, max_length=500)


class _DownstreamTransport:
    """Downstream HTTP transport (injectable in tests; real call by default)."""

    def call(self, method: str, url: str, json_body: Dict[str, Any],
             authorizing_identity: str) -> Dict[str, Any]:
        response = requests.request(
            method,
            url,
            json=json_body,
            headers={"X-Gateway-Identity": authorizing_identity},
            timeout=10,
        )
        response.raise_for_status()
        try:
            return response.json()
        except ValueError:
            return {"status": "DOWNSTREAM_OK", "raw": response.text}


def get_downstream_transport() -> _DownstreamTransport:
    return _DownstreamTransport()


def _forward_typed_call(
    transport: _DownstreamTransport,
    service_name: str,
    path: str,
    body: Dict[str, Any],
    authorizing_identity: str,
) -> Dict[str, Any]:
    """Forward a fixed, typed payload to a fixed internal path.

    Both ``service_name`` and ``path`` are chosen from code constants —
    never from request input.
    """
    base = SERVICES.get(service_name)
    if base is None:
        raise HTTPException(
            status_code=503,
            detail=f"Target microservice '{service_name}' is not registered for "
                   "typed control-plane operations.",
        )
    url = f"{base}{INCIDENT_INTERNAL_BASE}{path}"
    try:
        return transport.call("POST", url, body, authorizing_identity)
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Downstream service '{service_name}' unavailable.",
        ) from exc


# ---------------------------------------------------------------------------
# Existing operator surface
# ---------------------------------------------------------------------------


@router.get("/metrics")
def get_clustered_gateway_telemetry(request: Request, user: dict = Depends(verify_token)):
    """Gateway self-telemetry (status of the gateway itself, not monitoring
    service data).  Any authenticated user may read it; it exposes no
    internal targets reachable for writes."""
    client_ip = request.client.host
    if limiter.is_rate_limited(client_ip):
        raise HTTPException(status_code=429, detail="Too many microservice request calls from client.")
    return {
        "gateway_status": "ONLINE",
        "route_mapping_matrix": SERVICES,
        "active_socket_clients": 12,
        "load_balancer": "round-robin",
    }


# ---------------------------------------------------------------------------
# Typed control-plane operations (operator role only)
# ---------------------------------------------------------------------------


@router.post("/incidents/{incident_id}/proposals/{proposal_id}/approve")
def approve_hotfix_proposal(
    incident_id: str,
    proposal_id: str,
    body: ApproveHotfixProposalRequest,
    user: dict = Depends(require_operator),
    transport: _DownstreamTransport = Depends(get_downstream_transport),
):
    """Approve a verified hotfix proposal (operator control-plane operation)."""
    result = _forward_typed_call(
        transport,
        "incident",
        f"/incidents/{incident_id}/proposals/{proposal_id}/approve",
        {
            "expected_state": body.expected_state,
            "approver_note": body.approver_note,
            "authorizing_identity": user["sub"],
        },
        user["sub"],
    )
    return {"status": "APPROVAL_RELAYED", "incident_id": incident_id,
            "proposal_id": proposal_id, "downstream": result}


@router.post("/incidents/{incident_id}/proposals/{proposal_id}/execute")
def execute_hotfix_proposal(
    incident_id: str,
    proposal_id: str,
    body: ExecuteHotfixProposalRequest,
    user: dict = Depends(require_operator),
    transport: _DownstreamTransport = Depends(get_downstream_transport),
):
    """Execute an approved hotfix proposal (operator control-plane operation)."""
    result = _forward_typed_call(
        transport,
        "incident",
        f"/incidents/{incident_id}/proposals/{proposal_id}/execute",
        {
            "expected_state": body.expected_state,
            "execution_note": body.execution_note,
            "authorizing_identity": user["sub"],
        },
        user["sub"],
    )
    return {"status": "EXECUTION_RELAYED", "incident_id": incident_id,
            "proposal_id": proposal_id, "downstream": result}
