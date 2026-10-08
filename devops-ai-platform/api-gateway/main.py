"""API Gateway application factory (Phase 8.7-C).

Startup is fail-closed: ``create_app()`` resolves the validated gateway
configuration, which raises ``GatewayConfigurationError`` when ``JWT_SECRET``
is absent in a non-development environment.  A misconfigured gateway process
therefore cannot boot and silently substitute a bundled signing secret.

Run (with JWT_SECRET / APP_ENV exported as appropriate):

    uvicorn api_gateway.main:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import logging

from fastapi import FastAPI

from .config import GatewayConfigurationError, load_gateway_settings
from .core.analysis_rate_limit import (
    AnalysisRateLimitConfigurationError,
    build_analysis_rate_limiter,
)
from .core.auth import make_bound_verify_token, set_active_config, verify_token
from .routers.analysis_router import router as analysis_router
from .routers.gateway_router import router as gateway_router

logger = logging.getLogger("GatewayMain")


def create_app(env=None) -> FastAPI:
    """Build the gateway app.

    Raises:
        GatewayConfigurationError: when the JWT environment contract cannot
            be satisfied (fail closed — no bundled secret is substituted).
    """
    config = load_gateway_settings(env)  # may raise: fail closed
    set_active_config(config)
    app = FastAPI(
        title="Autonomous DevOps AI — API Gateway",
        version="8.7-C",
        description="Control-plane gateway. Telemetry ingestion is NOT part of "
                    "this surface; it is machine-authenticated on the monitoring "
                    "service.",
    )
    app.state.gateway_config = config
    # Authenticate every request with exactly this app's validated secret.
    app.dependency_overrides[verify_token] = make_bound_verify_token(config)
    # Phase 8.7-D.1: route-specific rate limiter for the expensive analysis
    # route (shared Redis state when configured; explicit single-instance
    # mode otherwise; the route fails closed when the shared store is
    # unreachable — protection is never silently disabled).
    app.state.analysis_rate_limiter = build_analysis_rate_limiter(env)
    app.include_router(gateway_router)
    # Phase 8.7-D: typed, JWT-authenticated repository-analysis route.
    app.include_router(analysis_router)

    @app.get("/api/v1/health", tags=["Health"])
    def health() -> dict:
        """Container liveness/readiness probe (diagnostics).

        Unauthenticated by design — a probe endpoint must not require a
        credential.  It reports process health only and exposes no
        configuration, secrets, or request state.
        """
        return {"status": "ok", "service": "api-gateway"}

    logger.info(
        "API gateway configured (jwt_secret_origin=%s, app_env=%r).",
        config.jwt_secret_origin,
        config.app_env or "<unset>",
    )
    return app


app = create_app()
