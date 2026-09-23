import os

class RepoServiceSettings:
    """Config maps targeting the code analysis bounded context."""
    PROJECT_NAME: str = "RepoService"
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@db:5432/devops_prod")
    LOCAL_CACHE_DIR: str = os.getenv("LOCAL_CACHE_DIR", "/tmp/devops_clones")
