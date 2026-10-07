"""Secret-safe Compose diagnostics + artifact secret scanning (§10/§40).

Two layers, deliberately separated:

* ``render_compose_config`` — primary control: rendered Compose
  diagnostics are produced from a SANITIZED environment, so secret
  values never enter the artifact staging tree in the first place.
* ``scan_tree`` / ``main`` — backstop: recursive pattern scan run
  immediately before upload; any finding fails the job before upload.
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import Dict, Iterable, List, Mapping, Sequence

from e2e.helpers import secret_scan_text

REDACTED = "[REDACTED-NON-SECRET]"

#: environment keys whose VALUES must never reach rendered diagnostics.
SECRET_ENV_KEYS = (
    "E2E_JWT_SECRET",
    "E2E_FIXTURE_GITHUB_TOKEN",
    "JWT_SECRET",
    "GITHUB_OAUTH_TOKEN",
    "GEMINI_API_KEY",
    "SENTRY_WEBHOOK_SECRET",
)


def sanitized_env(
    env: Mapping[str, str],
    extra_secret_keys: Iterable[str] = (),
    placeholder: str = REDACTED,
) -> Dict[str, str]:
    """Copy of ``env`` with secret-valued keys replaced by a placeholder."""
    secrets = {k.upper() for k in SECRET_ENV_KEYS} | {
        k.upper() for k in extra_secret_keys
    }
    return {
        key: (placeholder if key.upper() in secrets else value)
        for key, value in env.items()
    }


def render_compose_config(
    compose_argv: Sequence[str],
    out_path: str,
    env: Mapping[str, str] | None = None,
    extra_secret_keys: Iterable[str] = (),
) -> str:
    """Run ``compose config`` under a sanitized environment and write the
    rendered diagnostics to ``out_path`` (never the live secrets)."""
    base_env = dict(os.environ if env is None else env)
    clean = sanitized_env(base_env, extra_secret_keys)
    completed = subprocess.run(
        list(compose_argv),
        capture_output=True,
        text=True,
        env=clean,
        timeout=300,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"compose config failed: {completed.stderr.strip()[:500]}"
        )
    rendered = completed.stdout
    # defense in depth: never persist a line that still pattern-matches
    leaked = secret_scan_text(rendered)
    if leaked:
        raise RuntimeError(
            f"rendered compose diagnostics still contain secret markers: {leaked}"
        )
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as handle:
        handle.write(rendered)
    return rendered


def scan_tree(root: str) -> List[str]:
    """Recursive backstop scan; returns ``path: finding`` strings."""
    findings: List[str] = []
    for base, _dirs, files in os.walk(root):
        for name in files:
            path = os.path.join(base, name)
            try:
                with open(path, encoding="utf-8", errors="ignore") as handle:
                    hits = secret_scan_text(handle.read())
            except OSError:
                continue
            if hits:
                findings.append(f"{os.path.relpath(path, root)}: {hits}")
    return findings


def main(argv: Sequence[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if len(args) != 1:
        print("usage: python -m e2e.artifact_scan <artifact-dir>", file=sys.stderr)
        return 2
    findings = scan_tree(args[0])
    if findings:
        for line in findings:
            print(f"::error::secret marker in artifact: {line}")
        return 1
    print("secret scan clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
