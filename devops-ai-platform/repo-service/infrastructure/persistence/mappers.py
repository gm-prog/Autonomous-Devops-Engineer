from ...domain.aggregates.repository import RepositoryAggregate
from ...domain.entities.code_file import CodeFile
from ...domain.value_objects.tech_stack import TechStack
from ....shared_kernel.domain.value_objects import RepoUrl

class RepositoryDomainMapper:
    """Translates raw database model shapes directly into encapsulated Domain entities."""
    def to_domain(self, db_model) -> RepositoryAggregate:
        url_vo = RepoUrl(db_model.url)
        aggregate = RepositoryAggregate(
            id=str(db_model.id),
            name=db_model.name,
            url=url_vo,
            created_at=db_model.created_at
        )
        if db_model.framework:
            aggregate.set_tech_stack(TechStack(
                primary_language=db_model.technology,
                detected_frameworks=[db_model.framework],
                has_dockerfile=bool(db_model.dockerfile),
                has_k8s_manifests=bool(db_model.k8s_yaml)
            ))
        return aggregate

    def to_db(self, aggregate: RepositoryAggregate):
        # Maps Domain Aggregate properties back to SQLAlchemy DB classes
        class DBMock:
            pass
        db = DBMock()
        db.id = aggregate.id
        db.name = aggregate.name
        db.url = aggregate.url.value
        db.created_at = aggregate.created_at
        if aggregate.tech_stack:
            db.technology = aggregate.tech_stack.primary_language
            db.framework = aggregate.tech_stack.detected_frameworks[0] if aggregate.tech_stack.detected_frameworks else ""
        return db
