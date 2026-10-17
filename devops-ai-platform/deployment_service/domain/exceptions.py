class DeploymentDomainException(Exception):
    """Base exception for the deployment bounded context."""
    pass


class DeploymentExecutionException(DeploymentDomainException):
    """Raised when a pipeline run fails during IaC execution or apply stages."""
    pass
