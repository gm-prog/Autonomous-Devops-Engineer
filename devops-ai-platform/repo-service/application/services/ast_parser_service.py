import ast
import logging
from typing import List
from domain.entities.code_file import CodeFile
from domain.value_objects.tech_stack import TechStack

logger = logging.getLogger("ASTParserService")

_LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
}

class ASTParserService:
    """Inspect source files and derive a conservative technology profile."""

    def extract_dependencies(self, file: CodeFile) -> List[str]:
        if file.language != "python":
            return []

        dependencies: List[str] = []
        try:
            tree = ast.parse(file.content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    dependencies.extend(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    dependencies.append(node.module.split(".")[0])
        except SyntaxError as exc:
            logger.warning("Skipping invalid Python AST for %s: %s", file.filepath, exc)
        except Exception as exc:
            logger.warning("Failed to inspect Python AST for %s: %s", file.filepath, exc)

        return list(dict.fromkeys(dependencies))

    def detect_language(self, filepath: str) -> str:
        path = filepath.lower()
        for suffix, language in _LANGUAGE_EXTENSIONS.items():
            if path.endswith(suffix):
                return language
        if filepath == "Dockerfile" or filepath.endswith("/Dockerfile"):
            return "dockerfile"
        return "unknown"

    def evaluate_codebase(self, files: List[CodeFile]) -> TechStack:
        language_counts = {}
        dependencies: List[str] = []
        has_docker = False
        has_k8s = False

        for file in files:
            language_counts[file.language] = language_counts.get(file.language, 0) + 1
            dependencies.extend(self.extract_dependencies(file))

            basename = file.filepath.rsplit("/", 1)[-1]
            if basename == "Dockerfile" or basename.startswith("Dockerfile."):
                has_docker = True

            if file.is_yaml_config() and "apiVersion:" in file.content and "kind:" in file.content:
                has_k8s = True

        primary_language = (
            max(language_counts.items(), key=lambda item: item[1])[0]
            if language_counts else "unknown"
        )

        normalized = []
        for term in dependencies:
            lower = term.lower()
            if "fastapi" in lower:
                normalized.append("FastAPI")
            elif "django" in lower:
                normalized.append("Django")
            elif "flask" in lower:
                normalized.append("Flask")
            elif "express" in lower:
                normalized.append("Express")
            elif "next" in lower:
                normalized.append("Next.js")
            elif "spring" in lower:
                normalized.append("Spring")
            elif "sqlalchemy" in lower:
                normalized.append("SQLAlchemy")

        return TechStack(
            primary_language=primary_language,
            detected_frameworks=list(dict.fromkeys(normalized)),
            has_dockerfile=has_docker,
            has_k8s_manifests=has_k8s,
        )
