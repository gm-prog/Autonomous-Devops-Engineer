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
    app.include_router(gateway_router)
    # Phase 8.7-D: typed, JWT-authenticated repository-analysis route.
    app.include_router(analysis_router)
    logger.info(
        "API gateway configured (jwt_secret_origin=%s, app_env=%r).",
        config.jwt_secret_origin,
        config.app_env or "<unset>",
    )
    return app


app = create_app()
