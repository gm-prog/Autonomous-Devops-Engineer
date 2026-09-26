
import os
import shutil
import subprocess
from typing import Any, Dict, List


class KubectlRunnerService:
    """Fixed-command Kubernetes runner with explicit cluster credentials."""

    def _execution_env(self) -> Dict[str, str]:
        kubeconfig = os.getenv("DEPLOYMENT_KUBECONFIG_PATH", "").strip()
        if not kubeconfig:
            raise RuntimeError(
                "DEPLOYMENT_KUBECONFIG_PATH must be explicitly configured for cluster execution."
            )

        env = {
            key: value
            for key, value in os.environ.items()
            if key in {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"}
        }
        env["KUBECONFIG"] = kubeconfig
        for key in (
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "NO_PROXY",
            "https_proxy",
            "http_proxy",
            "no_proxy",
        ):
            if key in os.environ:
                env[key] = os.environ[key]
        return env

    def _allowed_namespace(self, namespace: str) -> bool:
        allowed = {
            value.strip()
            for value in os.getenv(
                "DEPLOYMENT_ALLOWED_NAMESPACES",
                "devops-production-namespace",
            ).split(",")
            if value.strip()
        }
        return namespace in allowed

    def _run(self, args: List[str], env: Dict[str, str], timeout: int) -> Dict[str, Any]:
        if not shutil.which("kubectl"):
            return {
                "status": "TOOL_UNAVAILABLE",
                "stderr": "kubectl is not installed.",
                "cluster_access": False,
            }
        try:
            result = subprocess.run(
                args,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return {
                "status": "PASS" if result.returncode == 0 else "FAIL",
                "exit_code": result.returncode,
                "command": " ".join(args),
                "stdout": result.stdout[-12000:],
                "stderr": result.stderr[-12000:],
                "cluster_access": True,
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "TIMEOUT",
                "command": " ".join(args),
                "stdout": "",
                "stderr": "kubectl command timed out.",
                "cluster_access": True,
            }

    def dry_run(
        self,
        manifest_path: str,
        namespace: str = "devops-production-namespace",
    ) -> Dict[str, Any]:
        if not self._allowed_namespace(namespace):
            return {
                "status": "BLOCKED",
                "stderr": f"Namespace {namespace!r} is not allowed.",
                "cluster_access": False,
            }

        env = os.environ.copy()
        env["KUBECONFIG"] = "/dev/null"
        env.pop("KUBERNETES_SERVICE_HOST", None)
        env.pop("KUBERNETES_SERVICE_PORT", None)
        return self._run(
            [
                "kubectl",
                "apply",
                "--dry-run=client",
                "--validate=false",
                "-f",
                manifest_path,
                "-n",
                namespace,
            ],
            env,
            120,
        ) | {"cluster_access": False}

    def apply(
        self,
        manifest_path: str,
        namespace: str = "devops-production-namespace",
    ) -> Dict[str, Any]:
        if not self._allowed_namespace(namespace):
            return {
                "status": "BLOCKED",
                "stderr": f"Namespace {namespace!r} is not allowed.",
                "cluster_access": False,
            }
        try:
            env = self._execution_env()
        except RuntimeError as exc:
            return {"status": "BLOCKED", "stderr": str(exc), "cluster_access": False}
        return self._run(
            ["kubectl", "apply", "-f", manifest_path, "-n", namespace],
            env,
            300,
        )

    def rollout_status(
        self,
        deployment_name: str,
        namespace: str = "devops-production-namespace",
        timeout_seconds: int = 300,
    ) -> Dict[str, Any]:
        if not self._allowed_namespace(namespace):
            return {
                "status": "BLOCKED",
                "stderr": f"Namespace {namespace!r} is not allowed.",
                "cluster_access": False,
            }
        try:
            env = self._execution_env()
        except RuntimeError as exc:
            return {"status": "BLOCKED", "stderr": str(exc), "cluster_access": False}
        return self._run(
            [
                "kubectl",
                "rollout",
                "status",
                f"deployment/{deployment_name}",
                "-n",
                namespace,
                f"--timeout={timeout_seconds}s",
            ],
            env,
            timeout_seconds + 30,
        )

    def rollout_undo(
        self,
        deployment_name: str,
        namespace: str = "devops-production-namespace",
    ) -> Dict[str, Any]:
        if not self._allowed_namespace(namespace):
            return {
                "status": "BLOCKED",
                "stderr": f"Namespace {namespace!r} is not allowed.",
                "cluster_access": False,
            }
        try:
            env = self._execution_env()
        except RuntimeError as exc:
            return {"status": "BLOCKED", "stderr": str(exc), "cluster_access": False}
        return self._run(
            [
                "kubectl",
                "rollout",
                "undo",
                f"deployment/{deployment_name}",
                "-n",
                namespace,
            ],
            env,
            300,
        )
