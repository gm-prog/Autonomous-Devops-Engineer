
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
    #: Phase 8.8A Correction-1 (F7): the durable, persisted acknowledgement
    #: that an execution was dispatched — set by the API after validation
    #: and BEFORE the broker dispatch, reverted to APPROVED if the
    #: dispatch fails. The worker moves it to DEPLOYING once it owns the
    #: fenced execution lease.
    EXECUTION_REQUESTED = "EXECUTION_REQUESTED"
    DEPLOYING = "DEPLOYING"
    HEALTH_CHECKING = "HEALTH_CHECKING"
    DEPLOYED = "DEPLOYED"
    DEPLOYMENT_FAILED = "DEPLOYMENT_FAILED"
    ROLLBACK_PENDING = "ROLLBACK_PENDING"
    ROLLED_BACK = "ROLLED_BACK"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"
    #: Phase 8.8A Correction-1 (F5): the executing worker lost ownership
    #: of its lease (expired + superseded, or renewal failure past the
    #: TTL). The run is terminal: the stale worker commits nothing
    #: further and starts no subsequent side effects (no rollback).
    LEASE_LOST = "LEASE_LOST"


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
    # F7: dispatch first persists EXECUTION_REQUESTED; a failed broker
    # dispatch reverts it (APPROVED is the only legitimate outcome when
    # nothing was enqueued). DEPLOYING stays reachable directly for the
    # worker's defensive re-validation path.
    DeploymentState.APPROVED: {
        DeploymentState.EXECUTION_REQUESTED,
        DeploymentState.DEPLOYING,
        DeploymentState.LEASE_LOST,
    },
    DeploymentState.EXECUTION_REQUESTED: {
        DeploymentState.DEPLOYING,
        DeploymentState.APPROVED,
        DeploymentState.LEASE_LOST,
    },
    DeploymentState.DEPLOYING: {
        DeploymentState.HEALTH_CHECKING,
        DeploymentState.DEPLOYMENT_FAILED,
        DeploymentState.LEASE_LOST,
    },
    DeploymentState.HEALTH_CHECKING: {
        DeploymentState.DEPLOYED,
        DeploymentState.DEPLOYMENT_FAILED,
        DeploymentState.LEASE_LOST,
    },
    DeploymentState.DEPLOYMENT_FAILED: {
        DeploymentState.ROLLBACK_PENDING,
        DeploymentState.LEASE_LOST,
    },
    DeploymentState.ROLLBACK_PENDING: {
        DeploymentState.ROLLED_BACK,
        DeploymentState.ROLLBACK_FAILED,
        DeploymentState.LEASE_LOST,
    },
    DeploymentState.ROLLBACK_FAILED: {DeploymentState.ROLLBACK_PENDING},
    DeploymentState.VALIDATION_FAILED: set(),
    DeploymentState.DRY_RUN_FAILED: set(),
    DeploymentState.DEPLOYED: set(),
    DeploymentState.ROLLED_BACK: set(),
    DeploymentState.LEASE_LOST: set(),
}


class InvalidDeploymentTransition(ValueError):
    pass


def transition(current: DeploymentState, target: DeploymentState) -> DeploymentState:
    if target not in _ALLOWED.get(current, set()):
        raise InvalidDeploymentTransition(
            f"Invalid deployment transition: {current.value} -> {target.value}"
        )
    return target
