# Shell Coding Guidelines

Applies to: `*.sh` (the build, audit, and update scripts at the repo root).

See [`../coding-guidelines.md`](../coding-guidelines.md) for general conventions and formatting requirements that apply to all code.

## Conventions

- Bash with `set -euo pipefail` and `cd "$(dirname "$0")"` at the top, so the script is location-independent and fails loudly.
- **POSIX-compatible when the script runs inside the Alpine devcontainer image** (e.g. `audit.sh` is invoked via `sh` in CI): that image has no `bash`. Avoid bashisms in such scripts and verify with `sh -n`.
- Preserve current flag semantics. New flags get a clear `--long-name` and a usage line; reject unknown args with a non-zero exit.
- Make destructive or expensive operations safe: provide verbose output, prefer idempotent re-runs (the `update*.sh` scripts are no-ops when already current), and use `trap` to clean up temp dirs.
- Keep builds reproducible: pin inputs (toolchain, base image, kernel version + sha256, apk versions) and neutralize timestamps/host paths. Do not float a version that was previously pinned.
- Do not introduce `curl` to new external domains without rationale. Verify downloads against a pinned checksum (see `kernel/Dockerfile`'s `sha256sum -c`).
- Never embed credentials in scripts or Docker layers, and do not echo secrets.
- Prefer the dedicated tools the repo already uses (`sed -nE`, `sha256sum`, `cargo`) over reinventing parsing; keep one script focused on one job (binaries vs. kernel vs. audit vs. updates).
