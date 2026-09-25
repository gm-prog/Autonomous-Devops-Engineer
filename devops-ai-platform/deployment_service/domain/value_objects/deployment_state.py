
from enum import Enum


class DeploymentState(str, Enum):
    CREATED = "CREATED"
    VALIDATING = "VALIDATING"
    VALIDATED = "VALIDATED"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    DRY_RUNNING = "DRY_RUNNING"
    DRY_RUN_PASSED = "DRY_RUN_PASSED"
    DRY_RUN_FAILED = "DRY_RUN_FAILED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    DEPLOYING = "DEPLOYING"
    HEALTH_CHECKING = "HEALTH_CHECKING"
    DEPLOYED = "DEPLOYED"
    DEPLOYMENT_FAILED = "DEPLOYMENT_FAILED"
    ROLLBACK_PENDING = "ROLLBACK_PENDING"
    ROLLED_BACK = "ROLLED_BACK"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"


_ALLOWED = {
    DeploymentState.CREATED: {DeploymentState.VALIDATING},
    DeploymentState.VALIDATING: {
        DeploymentState.VALIDATED,
        DeploymentState.VALIDATION_FAILED,
    },
    DeploymentState.VALIDATED: {DeploymentState.DRY_RUNNING},
    DeploymentState.DRY_RUNNING: {
        DeploymentState.DRY_RUN_PASSED,
        DeploymentState.DRY_RUN_FAILED,
    },
    DeploymentState.DRY_RUN_PASSED: {DeploymentState.AWAITING_APPROVAL},
    DeploymentState.AWAITING_APPROVAL: {DeploymentState.APPROVED},
    DeploymentState.APPROVED: {DeploymentState.DEPLOYING},
    DeploymentState.DEPLOYING: {
        DeploymentState.HEALTH_CHECKING,
        DeploymentState.DEPLOYMENT_FAILED,
    },
    DeploymentState.HEALTH_CHECKING: {
        DeploymentState.DEPLOYED,
        DeploymentState.DEPLOYMENT_FAILED,
    },
    DeploymentState.DEPLOYMENT_FAILED: {DeploymentState.ROLLBACK_PENDING},
    DeploymentState.ROLLBACK_PENDING: {
        DeploymentState.ROLLED_BACK,
        DeploymentState.ROLLBACK_FAILED,
    },
    DeploymentState.ROLLBACK_FAILED: {DeploymentState.ROLLBACK_PENDING},
    DeploymentState.VALIDATION_FAILED: set(),
    DeploymentState.DRY_RUN_FAILED: set(),
    DeploymentState.DEPLOYED: set(),
    DeploymentState.ROLLED_BACK: set(),
}


class InvalidDeploymentTransition(ValueError):
    pass


def transition(current: DeploymentState, target: DeploymentState) -> DeploymentState:
    if target not in _ALLOWED.get(current, set()):
        raise InvalidDeploymentTransition(
            f"Invalid deployment transition: {current.value} -> {target.value}"
        )
    return target
