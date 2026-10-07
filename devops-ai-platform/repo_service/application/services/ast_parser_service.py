import ast
import logging
from typing import List
from ...domain.entities.code_file import CodeFile
from ...domain.value_objects.tech_stack import TechStack

logger = logging.getLogger("ASTParserService")

class ASTParserService:
    """
    Abstract Syntax Tree Inspector analyzing codebase entities
    to automatically extract active developer blueprints and libraries.
    """
    def extract_dependencies(self, file: CodeFile) -> List[str]:
        if file.language != "python":
            return []
        
        frameworks = []
        try:
            tree = ast.parse(file.content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        frameworks.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        frameworks.append(node.module)
        except Exception as e:
            logger.warning(f"Failed to scan Python Abstract Syntax tree for {file.filepath}: {e}")
        
        return list(set(frameworks))

    def evaluate_codebase(self, files: List[CodeFile]) -> TechStack:
        all_frameworks = []
        has_docker = False
        has_k8s = False

        for f in files:
            all_frameworks.extend(self.extract_dependencies(f))
            if "Dockerfile" in f.filepath:
                has_docker = True
            if f.filepath.endswith(".yaml") or f.filepath.endswith(".yml"):
                if "apiVersion:" in f.content and "kind:" in f.content:
                    has_k8s = True
                    
        # Normalize frameworks lists matching DevOps domains
        normalized = []
        for term in all_frameworks:
            if "fastapi" in term.lower():
                normalized.append("FastAPI")
            if "django" in term.lower():
                normalized.append("Django")
            if "flask" in term.lower():
                normalized.append("Flask")

        return TechStack(
            primary_language="python" if len(files) > 0 else "unknown",
            detected_frameworks=list(set(normalized)),
            has_dockerfile=has_docker,
            has_k8s_manifests=has_k8s
        )
