from fastapi import APIRouter, Depends, HTTPException, status
from .dto import ImportRepositoryDTO, RepositorySummaryDTO
from ...application.commands.import_repository import ImportRepositoryCommand, ImportRepositoryCommandHandler
from ...domain.exceptions import DuplicateRepositoryException

router = APIRouter(prefix="/repositories", tags=["Repositories Context"])

# This would receive an injected command handler in enterprise systems (depends_on_provider)
def get_imported_handler() -> ImportRepositoryCommandHandler:
    # Mocks for instantiation
    class MockAdapter:
        def find_by_name(self, name): return None
        def save(self, agg): pass
    return ImportRepositoryCommandHandler(MockAdapter())

@router.post("", response_model=RepositorySummaryDTO, status_code=status.HTTP_201_CREATED)
def import_git_repository(dto: ImportRepositoryDTO, handler: ImportRepositoryCommandHandler = Depends(get_imported_handler)):
    try:
        cmd = ImportRepositoryCommand(dto.name, dto.url)
        repo_id = handler.handle(cmd)
        return {
            "id": repo_id,
            "name": dto.name,
            "url": dto.url,
            "status": "Imported"
        }
    except DuplicateRepositoryException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to ingest codebase target: {e}")
