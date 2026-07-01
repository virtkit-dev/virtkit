# Coding Guidelines

## General Coding Conventions

- Small, surgical diffs. Preserve existing style in untouched code.
- Extend patterns already present rather than inventing new ones.
- Validate assumptions by inspecting files before large changes.
- Do not mass-format unrelated files.
- Favor the standard library over external dependencies. Each new dep adds supply-chain surface, version churn, and reader burden. Pull one in only when stdlib genuinely lacks the capability, the algorithm is correctness-critical and risky to reimplement, or the dep is already transitive. "Slightly more ergonomic" is not a reason. Prefer writing the glue. Language-specific rules in per-area files.
- Reproducibility is a hard constraint here: the binaries are baked into microVM images. Do not introduce build-time non-determinism (timestamps, host paths, network-dependent inputs) — see the build scripts and CI for the pinning that must be preserved.

## Formatting Requirements

Generated code **must** pass CI's formatting and lint checks (`.github/workflows/quality.yml`). Format per language:

| Language | Formatter / Linter | Check command | Fix command |
|----------|--------------------|---------------|-------------|
| Rust | rustfmt + clippy | `cargo fmt --check --all` && `cargo clippy --workspace --all-targets -- -D warnings` | `cargo fmt --all` |
| Shell (*.sh) | — (no formatter configured) | `bash -n <file>` (and POSIX `sh -n` for in-image scripts) | — |

## Area-Specific Conventions

Each language has its own file under [`coding-guidelines/`](coding-guidelines/):

- [Rust (`vk-core/`, `vk-driver/`, `vk-agent/`)](coding-guidelines/rust.md)
- [Shell (`*.sh`, build & update scripts)](coding-guidelines/shell.md)
