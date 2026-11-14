# Engineering-agent entry point

Before editing this repository, every agent must:

1. Read [docs/PROJECT_STATE.md](docs/PROJECT_STATE.md).
2. Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
3. Review the newest entries in [docs/WORK_LOG.md](docs/WORK_LOG.md).
4. Inspect the actual branch, HEAD, remotes, ancestry, and complete Git status.
5. Treat source, tests, configuration, and Git evidence as authoritative; never assume a prior conversation or AI report is authoritative.
6. Preserve all existing changes. Never reset, clean, stash, force-push, checkout-overwrite, or otherwise discard candidate work to obtain a clean tree.

At the end of every completed engineering task, update `PROJECT_STATE.md` and append a dated, evidence-backed entry to `WORK_LOG.md`. Update `ARCHITECTURE.md` when implemented architecture changes. Do not commit, push, deploy, or modify `main` unless separately authorized.
