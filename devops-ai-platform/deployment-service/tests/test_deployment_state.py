
import pytest
from domain.value_objects.deployment_state import DeploymentState, InvalidDeploymentTransition, transition

def test_dry_run_passed_requires_approval():
    assert transition(DeploymentState.DRY_RUN_PASSED, DeploymentState.AWAITING_APPROVAL) == DeploymentState.AWAITING_APPROVAL

def test_approved_requires_deploying():
    assert transition(DeploymentState.APPROVED, DeploymentState.DEPLOYING) == DeploymentState.DEPLOYING

def test_invalid_skip_to_deployed_is_blocked():
    with pytest.raises(InvalidDeploymentTransition):
        transition(DeploymentState.APPROVED, DeploymentState.DEPLOYED)

def test_failed_deployment_enters_rollback():
    assert transition(DeploymentState.DEPLOYMENT_FAILED, DeploymentState.ROLLBACK_PENDING) == DeploymentState.ROLLBACK_PENDING
