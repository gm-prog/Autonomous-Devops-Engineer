
import os
import shutil
import subprocess
from typing import Any, Dict, List

class TerraformRunnerService:
    """Runs real Terraform validation/plan with backend disabled and cloud credentials removed."""

    def _run(self, args: List[str], cwd: str, timeout: int = 120) -> Dict[str, Any]:
        if not shutil.which(args[0]):
            return {"status": "TOOL_UNAVAILABLE", "command": " ".join(args), "stdout": "", "stderr": f"{args[0]} is not installed."}
        env = os.environ.copy()
        for key in list(env):
            if key.startswith("AWS_") or key in {
                "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
                "AZURE_TENANT_ID", "ARM_CLIENT_ID", "ARM_CLIENT_SECRET", "ARM_TENANT_ID"
            }:
                env.pop(key, None)
        env["AWS_EC2_METADATA_DISABLED"] = "true"
        env["TF_IN_AUTOMATION"] = "1"
        try:
            result = subprocess.run(
                args, cwd=cwd, env=env, capture_output=True, text=True,
                timeout=timeout, check=False,
            )
            return {
                "status": "PASS" if result.returncode == 0 else "FAIL",
                "exit_code": result.returncode,
                "command": " ".join(args),
                "stdout": result.stdout[-12000:],
                "stderr": result.stderr[-12000:],
            }
        except subprocess.TimeoutExpired:
            return {"status": "TIMEOUT", "command": " ".join(args), "stdout": "", "stderr": "Terraform command timed out."}

    def run_plan(self, iac_dir: str) -> Dict[str, Any]:
        steps = [
            self._run(["terraform", "fmt", "-check", "-diff"], iac_dir, 60),
            self._run(["terraform", "init", "-backend=false", "-input=false", "-no-color"], iac_dir, 180),
            self._run(["terraform", "validate", "-no-color"], iac_dir, 120),
            self._run(["terraform", "plan", "-refresh=false", "-input=false", "-lock=false", "-no-color"], iac_dir, 180),
        ]
        statuses = [step["status"] for step in steps]
        status = "PASS" if all(x == "PASS" for x in statuses) else (
            "TOOL_UNAVAILABLE" if "TOOL_UNAVAILABLE" in statuses else "FAIL"
        )
        return {"status": status, "steps": steps, "plan": steps[-1]}
