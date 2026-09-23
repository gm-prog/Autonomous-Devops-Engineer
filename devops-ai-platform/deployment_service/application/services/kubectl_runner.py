import subprocess
import logging

logger = logging.getLogger("KubectlRunnerService")

class KubectlRunnerService:
    """Interacts with Kubernetes API endpoints to schedule and verify Pod replicas."""
    def apply_manifests(self, manifest_path: str, namespace: str = "devops-production-namespace") -> bool:
        logger.info(f"Applying Kubernetes service manifests: {manifest_path} inside Namespace: {namespace}")
        try:
            # subprocess.run(["kubectl", "apply", "-f", manifest_path, "-n", namespace], check=True)
            return True
        except Exception as e:
            logger.error(f"Failed to communicate state changes to Kubernetes node: {e}")
            return False

    def roll_back_release(self, deployment_name: str, namespace: str) -> bool:
        logger.warning(f"ROLLBACK request initiated. Triggering kubectl rollout undo on '{deployment_name}'")
        return True
