"""Agent-service application factory (Phase 8.7-D).

Exposes the internal repository-analysis boundary (and the existing agent
stream surface).  The LLM engine is injected so tests can substitute a fake
provider; production defaults to ``GeminiCallerAdapter``, which reads
``GEMINI_API_KEY`` from the server environment and fails closed per call
when it is absent (it never fabricates a provider response).

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
from .infrastructure.llm.gemini_caller import GeminiCallerAdapter
from .presentation.rest.analysis_router import (
    get_analysis_handler,
    router as analysis_router,
)
from .presentation.rest.stream_controller import router as stream_router

logger = logging.getLogger("AgentServiceMain")


def create_app(llm_engine: Optional[RemoteLLMInterface] = None) -> FastAPI:
    """Build the agent-service app.

    ``llm_engine`` defaults to the production Gemini adapter (server-env
    credential, fail closed per call).  Tests inject fakes here or via
    ``app.dependency_overrides[get_analysis_handler]``.
    """
    app = FastAPI(
        title="Autonomous DevOps AI — Agent Service",
        version="8.7-D",
        description="Agent/analysis service. The repository-analysis boundary "
                    "is internal: it is reached only through the API gateway's "
                    "typed, JWT-authenticated analysis route.",
    )
    if llm_engine is not None:
        app.dependency_overrides[get_analysis_handler] = lambda: AnalyzeRepositoryCommandHandler(llm_engine)
    else:
        if not os.getenv("GEMINI_API_KEY", ""):
            logger.warning(
                "GEMINI_API_KEY is not set in the server environment: the "
                "repository-analysis endpoint will FAIL CLOSED (503) on every "
                "call instead of fabricating a response."
            )
    app.include_router(analysis_router)
    app.include_router(stream_router)
    return app


app = create_app()
