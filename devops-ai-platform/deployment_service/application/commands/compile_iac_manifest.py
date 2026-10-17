"""Compile IaC manifest command — honest boundary (Phase 8.8A).

The forward-ported slice contains NO real IaC compiler: no repository
content is supplied to this command (only an id and a platform name), so
no evidence-backed manifest can be produced from its inputs. The previous
version answered every call with hard-coded sample ``main.tf``/``VPC``
content — a false success that could be mistaken for a real compile.

This version returns a typed BLOCKED result instead. Manifest material
that is actually deployed is always the caller-supplied artifact bundle
(``terraform_tf`` / ``k8s_yaml`` / ``dockerfile`` / ``pipeline_yaml``)
validated and hash-bound by the DeploymentEngine — never generated here.
"""

from typing import Any, Dict


class CompileIaCManifestCommand:
    def __init__(self, repo_id: str, cloud_platform: str):
        self.repo_id = repo_id
        self.cloud_platform = cloud_platform


class CompileIaCManifestCommandHandler:
    """Refuses to fabricate provision content.

    ``handle`` can only return a typed BLOCKED result. If a real compiler
    is implemented later, it must take the actual repository content as
    input, produce an auditable artifact, and be covered by tests — it
    must not silently resume emitting samples.
    """

    def handle(self, cmd: CompileIaCManifestCommand) -> Dict[str, Any]:
        return {
            "status": "BLOCKED",
            "error_code": "MANIFEST_COMPILATION_NOT_IMPLEMENTED",
            "error": (
                "IaC manifest compilation is not implemented in this slice; "
                "returning fabricated sample content would be a false "
                "success. Deployed manifests are the caller-supplied, "
                "hash-bound artifact bundle validated by the DeploymentEngine."
            ),
            "files": {},
        }
