"""
Shared test configuration for the operator gateway.

The environment is configured at import time (before ``app.main`` is
imported) so the engine/redis/qdrant singletons pick up the test settings:

* SQLite file database  - no PostgreSQL required for the test suite
* Unreachable Redis     - deterministically exercises the Celery
  "async bypass / inline mock" fallback path
* Unreachable Qdrant    - exercises the graceful vector-store degradation
* No GEMINI_API_KEY     - forces the offline template engine
"""
import os
import sys
import tempfile

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

_TEST_DB = os.path.join(tempfile.gettempdir(), "devops_backend_test.sqlite3")

os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB}"
os.environ["REDIS_HOST"] = "127.0.0.1"
os.environ["REDIS_PORT"] = "6390"   # intentionally unreachable
os.environ["QDRANT_HOST"] = "127.0.0.1"
os.environ["QDRANT_PORT"] = "6334"  # intentionally unreachable
os.environ.pop("GEMINI_API_KEY", None)
os.environ["CORS_ORIGINS"] = "*"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from app.main import app, Base, engine  # noqa: E402


@pytest.fixture(scope="session")
def client():
    """Fresh-schema FastAPI test client (lifespan runs schema creation)."""
    Base.metadata.drop_all(bind=engine)
    with TestClient(app) as c:
        yield c
    Base.metadata.drop_all(bind=engine)
    if os.path.exists(_TEST_DB):
        os.remove(_TEST_DB)


@pytest.fixture()
def sample_repo_payload():
    return {
        "name": "test-flask-svc",
        "url": "https://github.com/example/flask-svc",
        "framework": "Flask",
        "technology": "Python 3.12 / Gunicorn",
    }
