"""Agent-service application factory (Phase 8.7-D, hardened in 8.7-D.1).

Exposes the internal repository-analysis boundary (and the existing agent
stream surface).

Lifecycle (D1 P0-1)
===================

``create_app`` constructs EXACTLY ONE ``AnalyzeRepositoryCommandHandler``
per application instance — wrapping ONE ``GeminiCallerAdapter`` whose
circuit-breaker and budget state therefore persist for the life of the
process and are shared across all requests.  The handler is published on
``app.state.analysis_handler`` and resolved by the router dependency
``get_analysis_handler``; nothing constructs a new adapter per request.

The LLM engine is injectable: tests substitute a fake via ``create_app(
llm_engine=...)`` or ``app.dependency_overrides[get_analysis_handler]``;
production uses ``GeminiCallerAdapter`` configured from the environment
(single-source ``GeminiRuntimeConfig``), which reads ``GEMINI_API_KEY``
from the server environment and fails closed per call when it is absent
(it never fabricates a provider response).

Run (with GEMINI_API_KEY exported for the live path):

    uvicorn agent_service.main:app --host 0.0.0.0 --port 8020
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import FastAPI

from .application.commands.analyze_repository import AnalyzeRepositoryCommandHandler
from .domain.remote_llm_interface import RemoteLLMInterface
from .infrastructure.llm.gemini_caller import (
    GeminiCallerAdapter,
    GeminiRuntimeConfig,
)
from .presentation.rest.analysis_router import (
    get_analysis_handler,
    router as analysis_router,
)
from .presentation.rest.stream_controller import router as stream_router

logger = logging.getLogger("AgentServiceMain")


def create_app(
    llm_engine: Optional[RemoteLLMInterface] = None,
    config: Optional[GeminiRuntimeConfig] = None,
) -> FastAPI:
    """Build the agent-service app.

    * ``llm_engine``: test injection seam — a fake provider engine.  When
      given, the single shared handler wraps it (the production adapter is
      not constructed at all).
    * ``config``: explicit runtime configuration seam (tests).  Production
      resolves the single-source ``GeminiRuntimeConfig.from_env()``.

    The handler is created exactly once here and shared via ``app.state``;
    the ``app.dependency_overrides[get_analysis_handler]`` seam remains
    available for tests.
    """
    app = FastAPI(
        title="Autonomous DevOps AI — Agent Service",
        version="8.7-D.1",
        description="Agent/analysis service. The repository-analysis boundary "
                    "is internal: it is reached only through the API gateway's "
                    "typed, JWT-authenticated analysis route.",
    )
    if llm_engine is not None:
        handler = AnalyzeRepositoryCommandHandler(llm_engine)
    else:
        cfg = config if config is not None else GeminiRuntimeConfig.from_env()
        app.state.gemini_config = cfg
        if not os.getenv("GEMINI_API_KEY", ""):
            logger.warning(
                "GEMINI_API_KEY is not set in the server environment: the "
                "repository-analysis endpoint will FAIL CLOSED (503) on every "
                "call instead of fabricating a response."
            )
        handler = AnalyzeRepositoryCommandHandler(
            GeminiCallerAdapter(config=cfg)
        )
    # Application-lifetime wiring: ONE shared handler (D1 P0-1).  Tests may
    # still replace the resolution entirely via
    # app.dependency_overrides[get_analysis_handler].
    app.state.analysis_handler = handler

    app.include_router(analysis_router)
    app.include_router(stream_router)

    @app.get("/health", tags=["Health"])
    def health() -> dict:
        """Container liveness/readiness probe.

        Reports process health only — never provider credentials, budget
        state, or request details.
        """
        return {"status": "ok", "service": "agent-service"}

    return app


app = create_app()
