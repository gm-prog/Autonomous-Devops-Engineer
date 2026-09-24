import logging

import requests
from fastapi import APIRouter, Depends, HTTPException, Request

from ..core.auth import GatewayRateLimiter, verify_token

logger = logging.getLogger("GatewayRouter")

router = APIRouter(prefix="/v1/gateway", tags=["Gateway Router"])
limiter = GatewayRateLimiter()

# Downstream routing mappings matching our dynamic microservices.
# NOTE: the 5 sibling services are not yet bootable (see platform README),
# so dispatches to them will surface a 502 until they are stood up.
SERVICES = {
    "repo": "http://repo-service:8010",
    "agent": "http://agent-service:8020",
    "deployment": "http://deployment-service:8030",
    "monitoring": "http://monitoring-service:8040",
    "incident": "http://incident-service:8050",
}

_FORWARD_TIMEOUT_SECONDS = 10


def _rate_limit_or_429(request: Request) -> None:
    if limiter.is_rate_limited(request.client.host):
        raise HTTPException(
            status_code=429,
            detail="Too many microservice request calls from client.",
        )


@router.get("/metrics")
def get_clustered_gateway_telemetry(request: Request, user: dict = Depends(verify_token)):
    """Gateway self-telemetry (operator health view, not Prometheus)."""
    _rate_limit_or_429(request)
    return {
        "gateway_status": "ONLINE",
        "route_mapping_matrix": SERVICES,
        "load_balancer": "round-robin",
        "authorizing_identity": user["sub"],
    }


@router.post("/dispatch/{service_name}")
def dispatch_service_proxy(
    service_name: str,
    payload: dict,
    request: Request,
    user: dict = Depends(verify_token),
):
    """Forward the payload to the target service and relay its response.

    This performs a real downstream POST and never fabricates a successful
    forwarding result.
    """
    if service_name not in SERVICES:
        raise HTTPException(
            status_code=404,
            detail="Target microservice not reachable or registered in BFF catalog.",
        )
    _rate_limit_or_429(request)

    target_url = f"{SERVICES[service_name]}/api/internal"
    try:
        downstream = requests.post(
            target_url,
            json={"payload": payload, "forwarded_by": user["sub"]},
            timeout=_FORWARD_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        logger.warning("Dispatch to %s failed: %s", target_url, exc)
        raise HTTPException(
            status_code=502,
            detail=f"Downstream service '{service_name}' is unreachable ({exc.__class__.__name__})",
        )

    try:
        body = downstream.json()
    except ValueError:
        body = {"raw": downstream.text[:1000]}

    return {
        "status": "FORWARDED",
        "forwarded_to": target_url,
        "authorizing_identity": user["sub"],
        "upstream_status": downstream.status_code,
        "upstream_body": body,
    }
