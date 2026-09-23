
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from typing import Any, Dict, Iterable


class HealthCheckService:
    """Verify Kubernetes rollout health and an explicitly allowlisted HTTP endpoint."""

    def _http_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        allowed = {
            value.strip().lower()
            for value in os.getenv("HEALTHCHECK_ALLOWED_HOSTS", "").split(",")
            if value.strip()
        }
        return parsed.hostname.lower() in allowed

    def _http_check(self, url: str, timeout_seconds: int = 15) -> Dict[str, Any]:
        if not self._http_allowed(url):
            return {"status": "BLOCKED", "url": url, "error": "HTTP health-check host is not allowlisted."}
        request = Request(url, method="GET", headers={"User-Agent": "DevOps-AI-HealthCheck/2"})
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                return {
                    "status": "PASS" if 200 <= response.status < 400 else "FAIL",
                    "status_code": response.status,
                    "url": url,
                }
        except HTTPError as exc:
            return {"status": "FAIL", "status_code": exc.code, "url": url, "error": "HTTP health-check returned an error."}
        except URLError:
            return {"status": "FAIL", "url": url, "error": "HTTP health-check could not reach the endpoint."}
        except TimeoutError:
            return {"status": "TIMEOUT", "url": url, "error": "HTTP health-check timed out."}

    def check(
        self,
        kubectl,
        deployment_names: Iterable[str],
        namespace: str,
        healthcheck_url: str = "",
    ) -> Dict[str, Any]:
        checks = [
            {"deployment": name, "result": kubectl.rollout_status(name, namespace)}
            for name in deployment_names
        ]
        if healthcheck_url.strip():
            checks.append({"http": self._http_check(healthcheck_url.strip())})
        if not checks:
            return {"status": "FAIL", "checks": [], "error": "No deterministic health signal was configured."}

        failed = []
        for check in checks:
            result = check.get("result") or check.get("http") or {}
            if result.get("status") != "PASS":
                failed.append(result.get("status", "UNKNOWN"))
        return {"status": "PASS" if not failed else "FAIL", "checks": checks, "failed_checks": failed}
