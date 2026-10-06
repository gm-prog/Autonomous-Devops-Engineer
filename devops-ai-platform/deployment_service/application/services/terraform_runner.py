
import hashlib
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


class TerraformRunnerService:
    """Run fixed Terraform commands without exposing arbitrary shell execution."""

    def _credential_allowlist(self) -> Dict[str, str]:
        names = {
            name.strip()
            for name in os.getenv("DEPLOYMENT_CREDENTIAL_ENV_KEYS", "").split(",")
            if name.strip()
        }
        return {name: os.environ[name] for name in names if name in os.environ}

    def _env(self, execution: bool) -> Dict[str, str]:
        if not execution:
            env = os.environ.copy()
            for key in list(env):
                if key.startswith("AWS_") or key in {
                    "GOOGLE_APPLICATION_CREDENTIALS",
                    "AZURE_CLIENT_ID",
                    "AZURE_CLIENT_SECRET",
                    "AZURE_TENANT_ID",
                    "ARM_CLIENT_ID",
                    "ARM_CLIENT_SECRET",
                    "ARM_TENANT_ID",
                }:
                    env.pop(key, None)
        else:
            # Execution receives only a small process environment plus explicitly
            # allowlisted credential/config variables.
            env = {
                key: value
                for key, value in os.environ.items()
                if key in {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"}
            }
            env.update(self._credential_allowlist())

        env["AWS_EC2_METADATA_DISABLED"] = "true"
        env["TF_IN_AUTOMATION"] = "1"
        env["TF_INPUT"] = "0"
        return env

    def _run(
        self,
        args: List[str],
        cwd: str,
        timeout: int = 120,
        execution: bool = False,
    ) -> Dict[str, Any]:
        if not shutil.which(args[0]):
            return {
                "status": "TOOL_UNAVAILABLE",
                "command": " ".join(args),
                "stdout": "",
                "stderr": f"{args[0]} is not installed.",
            }

        try:
            result = subprocess.run(
                args,
                cwd=cwd,
                env=self._env(execution),
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
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "TIMEOUT",
                "command": " ".join(args),
                "stdout": "",
                "stderr": "Terraform command timed out.",
            }

    def run_plan(
        self,
        iac_dir: str,
        execution: bool = False,
        plan_output_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        init_args = [
            "terraform",
            "init",
            "-input=false",
            "-no-color",
        ]
        if not execution:
            init_args.insert(2, "-backend=false")

        plan_args = [
            "terraform",
            "plan",
            "-input=false",
            "-lock=false" if not execution else "-lock=true",
            "-no-color",
        ]
        if not execution:
            plan_args.insert(2, "-refresh=false")
        if plan_output_path:
            plan_args.extend(["-out", plan_output_path])

        steps = [
            self._run(
                ["terraform", "fmt", "-check", "-diff"],
                iac_dir,
                60,
                execution,
            ),
            self._run(init_args, iac_dir, 180, execution),
            self._run(
                ["terraform", "validate", "-no-color"],
                iac_dir,
                120,
                execution,
            ),
            self._run(plan_args, iac_dir, 240, execution),
        ]
        statuses = [step["status"] for step in steps]
        status = (
            "PASS"
            if all(value == "PASS" for value in statuses)
            else "TOOL_UNAVAILABLE"
            if "TOOL_UNAVAILABLE" in statuses
            else "FAIL"
        )
        plan_file_hash = ""
        if plan_output_path and Path(plan_output_path).exists():
            plan_file_hash = hashlib.sha256(
                Path(plan_output_path).read_bytes()
            ).hexdigest()

        return {
            "status": status,
            "steps": steps,
            "plan": steps[-1],
            "plan_file_hash": plan_file_hash,
            "execution": execution,
        }

    def apply_plan(self, iac_dir: str, plan_output_path: str) -> Dict[str, Any]:
        return self._run(
            [
                "terraform",
                "apply",
                "-input=false",
                "-no-color",
                plan_output_path,
            ],
            iac_dir,
            600,
            execution=True,
        )
