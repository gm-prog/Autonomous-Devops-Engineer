
from enum import Enum

class DeploymentState(str, Enum):
    CREATED = "CREATED"
    VALIDATING = "VALIDATING"
    VALIDATED = "VALIDATED"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    DRY_RUNNING = "DRY_RUNNING"
    DRY_RUN_PASSED = "DRY_RUN_PASSED"
    DRY_RUN_FAILED = "DRY_RUN_FAILED"

_ALLOWED = {
    DeploymentState.CREATED: {DeploymentState.VALIDATING},
    DeploymentState.VALIDATING: {DeploymentState.VALIDATED, DeploymentState.VALIDATION_FAILED},
    DeploymentState.VALIDATED: {DeploymentState.DRY_RUNNING},
    DeploymentState.DRY_RUNNING: {DeploymentState.DRY_RUN_PASSED, DeploymentState.DRY_RUN_FAILED},
    DeploymentState.VALIDATION_FAILED: set(),
    DeploymentState.DRY_RUN_PASSED: set(),
    DeploymentState.DRY_RUN_FAILED: set(),
}

class InvalidDeploymentTransition(ValueError):
    pass

def transition(current: DeploymentState, target: DeploymentState) -> DeploymentState:
    if target not in _ALLOWED.get(current, set()):
        raise InvalidDeploymentTransition(f"Invalid deployment transition: {current.value} -> {target.value}")
    return target
