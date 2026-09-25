"""Platform smoke-test configuration (env fixed before any app import)."""
import os
import sys

PLATFORM_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PLATFORM_DIR not in sys.path:
    sys.path.insert(0, PLATFORM_DIR)

os.environ["JWT_SECRET"] = "pytest-secret-not-for-production"
os.environ["SENTRY_WEBHOOK_SECRET"] = "pytest-sentry-shared-secret"
os.environ.setdefault("REDIS_HOST", "127.0.0.1")
os.environ.setdefault("REDIS_PORT", "6390")  # unreachable: deterministic

# Incident persistence (remediation stack) requires a database URL; SQLite
# keeps the smoke suite hermetic - no PostgreSQL needed in CI.
import tempfile  # noqa: E402

_SQLITE = os.path.join(tempfile.gettempdir(), "devops_incident_smoke.sqlite3")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_SQLITE}")
