"""Bounded readiness polling for the E2E stack (§39).

No sleep-as-proof: every waiter has an explicit deadline and returns
structured diagnostics for the failure artifact bundle.
"""

from __future__ import annotations

import json
import socket
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional


class ReadinessTimeout(RuntimeError):
    def __init__(self, name: str, deadline_seconds: float, history: List[str]):
        self.name = name
        self.deadline_seconds = deadline_seconds
        self.history = history[-20:]
        super().__init__(
            f"readiness probe {name!r} did not pass within "
            f"{deadline_seconds:.0f}s; last observations: {self.history}"
        )


def _observe(name: str, history: List[str], ok: bool, note: str) -> bool:
    history.append(f"{'ok' if ok else 'wait'}: {note}"[:300])
    return ok


def wait_until(name: str, probe: Callable[[], tuple[bool, str]],
               timeout: float, interval: float = 2.0,
               clock: Callable[[], float] = time.monotonic) -> Dict[str, Any]:
    """Run ``probe`` until it reports success or ``timeout`` elapses."""
    if timeout <= 0 or interval <= 0:
        raise ValueError("timeout and interval must be positive")
    deadline = clock() + timeout
    history: List[str] = []
    while clock() < deadline:
        try:
            ok, note = probe()
        except Exception as exc:  # probes must never crash the waiter
            ok, note = False, f"{type(exc).__name__}: {exc}"
        if _observe(name, history, ok, note):
            return {"name": name, "passed": True, "attempts": len(history)}
        time.sleep(interval)
    raise ReadinessTimeout(name, timeout, history)


def http_ok(url: str, timeout: float = 3.0,
            expect_status: int = 200) -> Callable[[], tuple[bool, str]]:
    def probe() -> tuple[bool, str]:
        request = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.status
        return status == expect_status, f"{url} -> {status}"
    return probe


def tcp_open(host: str, port: int, timeout: float = 2.0) -> Callable[[], tuple[bool, str]]:
    def probe() -> tuple[bool, str]:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"tcp {host}:{port} open"
    return probe


def docker_exec_ok(container: str, argv: List[str], timeout: float = 5.0
                   ) -> Callable[[], tuple[bool, str]]:
    def probe() -> tuple[bool, str]:
        completed = subprocess.run(
            ["docker", "exec", container, *argv],
            capture_output=True, text=True, timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        note = (completed.stdout or completed.stderr or "").strip()[:200]
        return completed.returncode == 0, f"docker exec {container}: rc={completed.returncode} {note}"
    return probe


def docker_log_probe(container: str, pattern: str, timeout: float = 5.0
                     ) -> Callable[[], tuple[bool, str]]:
    def probe() -> tuple[bool, str]:
        completed = subprocess.run(
            ["docker", "logs", "--tail", "200", container],
            capture_output=True, text=True, timeout=timeout,
        )
        blob = (completed.stdout or "") + (completed.stderr or "")
        found = re_search(pattern, blob)
        return found, f"log pattern {pattern!r} {'found' if found else 'absent'}"
    return probe


def re_search(pattern: str, text: str) -> bool:
    import re
    return re.search(pattern, text or "") is not None


def redis_group_probe(host: str, port: int, stream: str, group: str,
                      redis_client_factory: Optional[Callable[[], Any]] = None
                      ) -> Callable[[], tuple[bool, str]]:
    def probe() -> tuple[bool, str]:
        factory = redis_client_factory
        if factory is None:
            import redis as redis_lib
            factory = lambda: redis_lib.Redis(host=host, port=port, socket_timeout=3.0)
        client = factory()
        client.ping()
        groups = [g["name"] for g in client.xinfo_groups(stream)]
        return group in groups, f"stream {stream} groups={groups}"
    return probe


def collect_diagnostics(commands: List[List[str]], limit: int = 4000) -> str:
    """Run read-only diagnostic commands, return a bounded text bundle."""
    parts: List[str] = []
    for argv in commands:
        try:
            completed = subprocess.run(
                argv, capture_output=True, text=True, timeout=20,
                stdin=subprocess.DEVNULL,
            )
            parts.append(f"$ {' '.join(argv)}\n{(completed.stdout + completed.stderr)[:2000]}")
        except Exception as exc:
            parts.append(f"$ {' '.join(argv)}\nERROR {type(exc).__name__}: {exc}")
    return "\n".join(parts)[:limit]


def json_line(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, default=str)
