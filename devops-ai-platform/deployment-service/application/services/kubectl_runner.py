
import os
import shutil
import subprocess
from typing import Any, Dict

class KubectlRunnerService:
    """Runs cluster-free kubectl client-side dry-run; it never applies to a cluster."""

    def dry_run(self, manifest_path: str, namespace: str = "devops-production-namespace") -> Dict[str, Any]:
        if not shutil.which("kubectl"):
            return {"status": "TOOL_UNAVAILABLE", "stderr": "kubectl is not installed.", "cluster_access": False}
        env = os.environ.copy()
        env["KUBECONFIG"] = "/dev/null"
        env.pop("KUBERNETES_SERVICE_HOST", None)
        env.pop("KUBERNETES_SERVICE_PORT", None)
        try:
            result = subprocess.run(
                ["kubectl", "apply", "--dry-run=client", "--validate=false", "-f", manifest_path, "-n", namespace],
                env=env, capture_output=True, text=True, timeout=120, check=False,
            )
            return {
                "status": "PASS" if result.returncode == 0 else "FAIL",
                "exit_code": result.returncode,
                "command": "kubectl apply --dry-run=client --validate=false",
                "stdout": result.stdout[-12000:],
                "stderr": result.stderr[-12000:],
                "cluster_access": False,
            }
        except subprocess.TimeoutExpired:
            return {"status": "TIMEOUT", "stderr": "kubectl dry-run timed out.", "cluster_access": False}
