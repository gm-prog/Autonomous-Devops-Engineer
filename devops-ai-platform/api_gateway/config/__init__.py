import logging
import os

_DEV_FALLBACK_SECRET = "super-secret-devops-platform-signature-token"


class GatewaySettings:
    """API Gateway environmental settings and JWT configuration."""
    JWT_SECRET: str = os.getenv("JWT_SECRET") or _DEV_FALLBACK_SECRET
    RATE_LIMIT_MAX_REQUESTS: int = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "100"))

    REPO_SERVICE_GRPC: str = os.getenv("REPO_SERVICE_GRPC", "repo-service:50051")
    AGENT_SERVICE_GRPC: str = os.getenv("AGENT_SERVICE_GRPC", "agent-service:50052")
    DEPLOYMENT_SERVICE_GRPC: str = os.getenv("DEPLOYMENT_SERVICE_GRPC", "deployment-service:50053")
    MONITORING_SERVICE_GRPC: str = os.getenv("MONITORING_SERVICE_GRPC", "monitoring-service:50054")
    INCIDENT_SERVICE_GRPC: str = os.getenv("INCIDENT_SERVICE_GRPC", "incident-service:50055")

    @classmethod
    def using_dev_fallback_secret(cls) -> bool:
        return cls.JWT_SECRET == _DEV_FALLBACK_SECRET


if GatewaySettings.using_dev_fallback_secret():
    logging.getLogger("GatewayConfig").warning(
        "JWT_SECRET is not set - using a development-only fallback for direct local execution. "
        "The platform compose contract requires JWT_SECRET."
    )
