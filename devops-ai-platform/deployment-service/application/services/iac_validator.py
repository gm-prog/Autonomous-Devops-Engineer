
import re
from typing import Any, Dict
import yaml

class IaCValidator:
    """Static safety and syntax checks performed before any Terraform/Kubernetes command."""

    def validate(self, dockerfile: str, k8s_yaml: str, terraform_tf: str, pipeline_yaml: str) -> Dict[str, Any]:
        checks = {
            "dockerfile": self._dockerfile(dockerfile),
            "kubernetes": self._kubernetes(k8s_yaml),
            "terraform": self._terraform(terraform_tf),
            "pipeline": self._yaml_document("pipeline", pipeline_yaml),
        }
        blocking = [name for name, result in checks.items() if result["status"] == "FAIL"]
        return {"status": "FAIL" if blocking else "PASS", "checks": checks, "blocking_checks": blocking}

    def _dockerfile(self, content: str) -> Dict[str, Any]:
        if not content.strip():
            return {"status": "FAIL", "errors": ["Dockerfile is empty."]}
        if not re.search(r"(?im)^\s*FROM\s+\S+", content):
            return {"status": "FAIL", "errors": ["Dockerfile has no FROM instruction."]}
        warnings = []
        if not re.search(r"(?im)^\s*USER\s+\S+", content):
            warnings.append("No explicit USER instruction; container may run as root.")
        return {"status": "PASS", "errors": [], "warnings": warnings}

    def _kubernetes(self, content: str) -> Dict[str, Any]:
        if not content.strip():
            return {"status": "FAIL", "errors": ["Kubernetes manifest is empty."]}
        try:
            docs = [doc for doc in yaml.safe_load_all(content) if doc]
        except yaml.YAMLError as exc:
            return {"status": "FAIL", "errors": [f"Invalid YAML: {exc}"]}
        errors = []
        if not docs:
            errors.append("No Kubernetes resources found.")
        for index, doc in enumerate(docs, 1):
            if not isinstance(doc, dict) or not doc.get("apiVersion") or not doc.get("kind"):
                errors.append(f"Document {index} must contain apiVersion and kind.")
                continue
            pod_spec = ((doc.get("spec") or {}).get("template") or {}).get("spec") or {}
            if pod_spec.get("hostNetwork") is True:
                errors.append(f"Document {index} enables hostNetwork.")
            if pod_spec.get("hostPID") is True:
                errors.append(f"Document {index} enables hostPID.")
            for volume in pod_spec.get("volumes", []) or []:
                if isinstance(volume, dict) and "hostPath" in volume:
                    errors.append(f"Document {index} uses hostPath.")
            for container in pod_spec.get("containers", []) or []:
                if isinstance(container, dict) and (container.get("securityContext") or {}).get("privileged") is True:
                    errors.append(f"Document {index} enables privileged container execution.")
        return {"status": "FAIL" if errors else "PASS", "errors": errors, "warnings": []}

    def _terraform(self, content: str) -> Dict[str, Any]:
        if not content.strip():
            return {"status": "FAIL", "errors": ["Terraform configuration is empty."]}
        errors = []
        if re.search(r'(?ms)provisioner\s+"(local-exec|remote-exec)"', content):
            errors.append("Terraform local-exec/remote-exec provisioners are blocked.")
        if re.search(r'(?ms)data\s+"external"', content):
            errors.append("Terraform external data sources are blocked.")
        return {"status": "FAIL" if errors else "PASS", "errors": errors, "warnings": []}

    def _yaml_document(self, name: str, content: str) -> Dict[str, Any]:
        if not content.strip():
            return {"status": "FAIL", "errors": [f"{name.title()} YAML is empty."]}
        try:
            list(yaml.safe_load_all(content))
            return {"status": "PASS", "errors": [], "warnings": []}
        except yaml.YAMLError as exc:
            return {"status": "FAIL", "errors": [f"Invalid YAML: {exc}"]}
