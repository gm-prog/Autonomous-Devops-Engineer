from pydantic import BaseModel, HttpUrl

class ImportRepositoryDTO(BaseModel):
    name: str
    url: str

class RepositorySummaryDTO(BaseModel):
    id: str
    name: str
    url: str
    status: str
