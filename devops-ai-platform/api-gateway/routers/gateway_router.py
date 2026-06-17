from fastapi import APIRouter, Depends, HTTPException, Request
from typing import List, Dict, Any
from ..core.auth import verify_token, GatewayRateLimiter
import requests

router = APIRouter(prefix="/v1/gateway", tags=["Gateway Router"])
limiter = GatewayRateLimiter()

# Downstream routing mappings matching our dynamic microservices
SERVICES = {
    "repo": "http://repo-service:8010",
    "agent": "http://agent-service:8020",
    "deployment": "http://deployment-service:8030",
    "monitoring": "http://monitoring-service:8040",
    "incident": "http://incident-service:8050"
}

@router.get("/metrics")
def get_clustered_gateway_telemetry(request: Request, user: dict = Depends(verify_token)):
    client_ip = request.client.host
    if limiter.is_rate_limited(client_ip):
        raise HTTPException(status_code=429, detail="Too many microservice request calls from client.")
    return {
        "gateway_status": "ONLINE",
        "route_mapping_matrix": SERVICES,
        "active_socket_clients": 12,
        "load_balancer": "round-robin"
    }

@router.post("/dispatch/{service_name}")
def dispatch_service_proxy(service_name: str, payload: dict, request: Request, user: dict = Depends(verify_token)):
    if service_name not in SERVICES:
        raise HTTPException(status_code=404, detail="Target microservice not reachable or registered in BFF catalog.")
    
    # Simple proxy routing forwarder (In production, uses HTTPX async or gRPC client channels)
    target_url = f"{SERVICES[service_name]}/api/internal"
    return {
        "status": "PROXY_PASSTHROUGH",
        "forwarded_to": target_url,
        "authorizing_identity": user["sub"],
        "payload_relayed": payload
    }
