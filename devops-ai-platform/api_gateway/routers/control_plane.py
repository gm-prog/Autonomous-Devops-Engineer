"""Authenticated control plane for deployments and remediation (Stage 5).

The gateway is the product's real control-plane boundary: it exposes
named, function-authorized operations instead of proxying guessed
``/api/internal/*`` paths (knowing an internal URL grants nothing — those
routes do not exist here and the services themselves are not published to
the host).

Function-level authorization (§F):

* every route requires a valid HS256 JWT (``verify_token`` → 401);
* ``approve`` / ``execute`` / ``remediation`` additionally require an
  operator role (``OPERATOR_ROLES``) → 403 otherwise, and the check runs
  BEFORE any downstream call, so an ordinary user cannot even probe
  run/incident existence through this plane;
* the authenticated identity always overwrites caller-supplied
  ``requested_by`` / ``approved_by`` — request strings are never trusted
  as identity.

Object-level scope (§G): this product is intentionally **single-operator**.
There is no per-user ownership model to enforce and none is invented here:
any operator-role principal may act on any run/incident id, ids must exist
downstream (404 relayed), deployments are additionally guarded by the
state machine + hash binding, and remediation is guarded by the
incident-evidence provenance binding. Cross-"tenant" isolation is not
claimed because no tenants exist.

Transport: requests are forwarded over the private network to the URLs in
``gateway_router.SERVICES`` (single source of truth covered by the compose
boundary test), with the shared per-IP rate limiter, bounded timeouts, and
faithful relay of downstream status/body (502 only when the downstream is
unreachable). The internal trust model — who may call what without a
second token system — is documented in the platform README.
"""

import logging
from typing import Dict

import requests
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from ..core.auth import verify_token
from .gateway_router import (
    _FORWARD_TIMEOUT_SECONDS,
    _rate_limit_or_429,
    SERVICES,
)

logger = logging.getLogger("ControlPlane")

router = APIRouter(prefix="/v1", tags=["Control Plane"])

# Roles allowed to approve/execute deployments and drive remediation.
# Operator-role equivalents documented in the README (control plane section).
OPERATOR_ROLES = frozenset({"operator", "DevOpsLead", "ClusterAdmin"})


def require_operator(user: dict = Depends(verify_token)) -> dict:
    """Function-level authorization for destructive control-plane actions."""
    roles = user.get("roles") or []
    if not isinstance(roles, list):
        roles = []
    if not (set(str(role) for role in roles) & OPERATOR_ROLES):
        raise HTTPException(
            status_code=403,
            detail="operator role required for this control-plane function",
        )
    return user


def _forward_post(service_name: str, path: str, payload: Dict) -> JSONResponse:
    """POST to a private-network downstream and relay its response verbatim
    (status + JSON body) — never fabricate success or swallow failures."""
    target_url = f"{SERVICES[service_name]}{path}"
    try:
        downstream = requests.post(
            target_url, json=payload, timeout=_FORWARD_TIMEOUT_SECONDS
        )
    except requests.RequestException as exc:
        logger.warning("Control-plane forward to %s failed: %s", target_url, exc)
        raise HTTPException(
            status_code=502,
            detail=(
                f"Downstream service '{service_name}' is unreachable "
                f"({exc.__class__.__name__})"
            ),
        ) from exc
    try:
        body = downstream.json()
    except ValueError:
        body = {"raw": downstream.text[:1000]}
    return JSONResponse(status_code=downstream.status_code, content=body)


@router.post("/deployments/dry-run")
def control_plane_dry_run(
    payload: Dict,
    request: Request,
    user: dict = Depends(verify_token),
):
    """Request a deployment dry-run (any authenticated user may *request*).

    ``requested_by`` is stamped with the JWT subject — the client's own
    value, whatever it sent, is discarded.
    """
    _rate_limit_or_429(request)
    forwarded = dict(payload)
    forwarded["requested_by"] = user["sub"]
    return _forward_post(
        "deployment", "/api/internal/deployments/dry-run", forwarded
    )


@router.post("/deployments/{run_id}/approve")
def control_plane_approve(
    run_id: str,
    payload: Dict,
    request: Request,
    user: dict = Depends(require_operator),
):
    """Approve a run as the authenticated operator.

    ``approved_by`` is the JWT subject, never the request string.
    """
    _rate_limit_or_429(request)
    forwarded = dict(payload)
    forwarded["approved_by"] = user["sub"]
    return _forward_post(
        "deployment", f"/api/internal/deployments/{run_id}/approve", forwarded
    )


@router.post("/deployments/{run_id}/execute")
def control_plane_execute(
    run_id: str,
    payload: Dict,
    request: Request,
    user: dict = Depends(require_operator),
):
    """Execute an approved run (operator role required)."""
    _rate_limit_or_429(request)
    return _forward_post(
        "deployment", f"/api/internal/deployments/{run_id}/execute", dict(payload)
    )


@router.post("/incidents/{incident_id}/remediation")
def control_plane_remediation(
    incident_id: str,
    payload: Dict,
    request: Request,
    user: dict = Depends(require_operator),
):
    """Drive remediation for an incident (operator role required).

    The downstream binding still proves the requested repository + SHA
    against this incident's own DEPLOYED evidence with valid provenance —
    the role gate and the evidence gate are complementary.
    """
    _rate_limit_or_429(request)
    return _forward_post(
        "incident", f"/incidents/{incident_id}/remediation", dict(payload)
    )


def _forward_get(service_name: str, path: str) -> JSONResponse:
    """GET from a private-network downstream, relayed verbatim."""
    target_url = f"{SERVICES[service_name]}{path}"
    try:
        downstream = requests.get(target_url, timeout=_FORWARD_TIMEOUT_SECONDS)
    except requests.RequestException as exc:
        logger.warning("Control-plane forward to %s failed: %s", target_url, exc)
        raise HTTPException(
            status_code=502,
            detail=(
                f"Downstream service '{service_name}' is unreachable "
                f"({exc.__class__.__name__})"
            ),
        ) from exc
    try:
        body = downstream.json()
    except ValueError:
        body = {"raw": downstream.text[:1000]}
    return JSONResponse(status_code=downstream.status_code, content=body)


@router.get("/incidents/{incident_id}/proposal")
def control_plane_get_proposal(
    incident_id: str,
    request: Request,
    user: dict = Depends(require_operator),
):
    """Read the incident's persisted remediation proposal (§27).

    Read-only, but gated by the same operator-role authorization as the
    remediation control plane: proposals embed patch content and trusted
    repository/SHA identity, so they are not exposed to ordinary users.
    Authentication happens at the gateway (JWT); knowing the internal
    incident URL grants nothing.
    """
    _rate_limit_or_429(request)
    return _forward_get("incident", f"/incidents/{incident_id}/proposal")
