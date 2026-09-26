"""CORS allowlist behavior (§14): canonical env var is CORS_ORIGINS.

The in-process suite (conftest) pins CORS_ORIGINS="*" to exercise the
wildcard-without-credentials mode. These subprocess probes verify the
explicit-allowlist mode and the committed default with a fresh import.
"""

import json
import os
import subprocess
import sys
import unittest

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _probe(python_code: str, cors_value=None, strip_cors=False):
    env = dict(os.environ)
    env.pop("CORS_ORIGINS", None)
    if cors_value is not None:
        env["CORS_ORIGINS"] = cors_value
    if strip_cors:
        env.pop("CORS_ORIGINS", None)
    return subprocess.run(
        [sys.executable, "-c", python_code],
        cwd=BACKEND_DIR,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )


DEFAULT_PROBE = """
from app.main import CORS_ORIGINS
import json
print(json.dumps(CORS_ORIGINS))
"""

BEHAVIOR_PROBE = """
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

allowed = client.get("/health", headers={"Origin": "https://app.example.com"})
evil = client.get("/health", headers={"Origin": "https://evil.example.net"})
preflight = client.options(
    "/health",
    headers={
        "Origin": "https://app.example.com",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization",
    },
)
print("ALLOWED", allowed.headers.get("access-control-allow-origin"))
print("EVIL", evil.headers.get("access-control-allow-origin"))
print("PREFLIGHT", preflight.status_code,
      preflight.headers.get("access-control-allow-origin"))
print("CRED", allowed.headers.get("access-control-allow-credentials"))
"""


class CorsAllowlistTests(unittest.TestCase):
    def test_default_origins_are_explicit_local_dev(self):
        result = _probe(DEFAULT_PROBE, strip_cors=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        origins = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertNotIn("*", origins)
        self.assertIn("http://localhost:5173", origins)
        self.assertIn("http://localhost:3000", origins)

    def test_allowlist_mode_allowed_disallowed_preflight(self):
        result = _probe(
            BEHAVIOR_PROBE, cors_value="https://app.example.com"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = {l.split(" ", 1)[0]: l.split(" ", 1)[1]
                 for l in result.stdout.strip().splitlines()
                 if " " in l and l.split(" ", 1)[0] in
                 {"ALLOWED", "EVIL", "PREFLIGHT", "CRED"}}

        self.assertEqual(lines["ALLOWED"], "https://app.example.com")
        # disallowed origin must receive NO Access-Control-Allow-Origin
        self.assertIn(lines["EVIL"], ("None", "null"))
        self.assertTrue(lines["PREFLIGHT"].startswith("200"))
        self.assertIn("https://app.example.com", lines["PREFLIGHT"])
        # allowlisted origins may use credentials
        self.assertEqual(lines["CRED"], "true")

    def test_wildcard_never_combines_with_credentials(self):
        code = """
from app.main import CORS_ORIGINS, app
mw = [m for m in app.user_middleware
      if m.cls.__name__ == "CORSMiddleware"]
assert mw, "CORS middleware missing"
# starlette stores init kwargs on the middleware class entry
kwargs = mw[0].kwargs
print("CRED", kwargs.get("allow_credentials"))
print("ORIGINS", kwargs.get("allow_origins"))
"""
        result = _probe(code, cors_value="*")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CRED False", result.stdout)
        self.assertIn("ORIGINS ['*']", result.stdout)


if __name__ == "__main__":
    unittest.main()
