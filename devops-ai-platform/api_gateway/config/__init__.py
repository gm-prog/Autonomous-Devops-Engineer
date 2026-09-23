import logging
import os

# Committed development-only fallback. Using it outside local dev is a
# security hole: anyone reading the repo can mint valid admin tokens.
_DEV_FALLBACK_SECRET = "super-secret-devops-platform-signature-token"


class GatewaySettings:
    """API Gateway specific environmental variables and JWT authenticators."""
    JWT_SECRET: str = os.getenv("JWT_SECRET", _DEV_FALLBACK_SECRET)
    RATE_LIMIT_MAX_REQUESTS: int = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", 100)) # per minute

    @classmethod
    def using_dev_fallback_secret(cls) -> bool:
        return cls.JWT_SECRET == _DEV_FALLBACK_SECRET


if GatewaySettings.using_dev_fallback_secret():
    logging.getLogger("GatewayConfig").warning(
        "JWT_SECRET is not set - falling back to the committed development secret. "
        "Set a strong JWT_SECRET before exposing this gateway beyond local dev."
    )
    
    # Downstream Internal gRPC connection coordinates
    REPO_SERVICE_GRPC: str = os.getenv("REPO_SERVICE_GRPC", "repo-service:50051")
    AGENT_SERVICE_GRPC: str = os.getenv("AGENT_SERVICE_GRPC", "agent-service:50052")
    DEPLOYMENT_SERVICE_GRPC: str = os.getenv("DEPLOYMENT_SERVICE_GRPC", "deployment-service:50053")
    MONITORING_SERVICE_GRPC: str = os.getenv("MONITORING_SERVICE_GRPC", "monitoring-service:50054")
    INCIDENT_SERVICE_GRPC: str = os.getenv("INCIDENT_SERVICE_GRPC", "incident-service:50055")
