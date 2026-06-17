from abc import ABC, abstractmethod
from typing import Optional, List
from .aggregates.pipeline import PipelineAggregate

class PipelineRepositoryInterface(ABC):
    """Port separating our application workflows from the Redis or postgres log cache engines."""
    @abstractmethod
    def save_pipeline(self, pipeline: PipelineAggregate) -> None:
        pass

    @abstractmethod
    def find_pipeline_by_id(self, id: str) -> Optional[PipelineAggregate]:
        pass

    @abstractmethod
    def list_pipelines(self) -> List[PipelineAggregate]:
        pass
