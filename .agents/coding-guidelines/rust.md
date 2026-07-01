# Rust Coding Guidelines

Applies to: `vk-driver/**`, `vk-agent/**`.

See [`../coding-guidelines.md`](../coding-guidelines.md) for general conventions and formatting requirements that apply to all code.

## Conventions

- Single responsibility per module; avoid cyclic dependencies.
- When you change a function's signature or return type, update every call site. A successful build does not prove all callers are covered — use repo-wide search or find-references first.
- `Result` with custom error enums; validate external inputs early; no panics/unwraps on untrusted data. Use inline interpolation in format macros: `write!(f, "Error: {key}")` not `write!(f, "Error: {}", key)`.
- **TOCTOU on paths:** never trust a `&Path` across two syscalls. Anchor operations on a file descriptor (`openat`, `fstatat`, `*at` family) instead of re-resolving the path. Use `OpenOptions::create_new(true)` when creating files to reject symlinks. If you act on the same path twice, assume it is a TOCTOU bug until proven otherwise.
- **Permissions at creation:** set file/directory permissions at creation time with `OpenOptions::mode()` / `DirBuilderExt::mode()`, not with a separate `fs::set_permissions` call after creation (race window).
- **Path identity:** never compare paths as strings. Use `fs::canonicalize` or compare `(dev, inode)` pairs for filesystem identity.
- **Stay in bytes at Unix boundaries:** use `Path`/`PathBuf` for filesystem paths, `OsString`/`OsStr` for env vars, and `&[u8]`/`Vec<u8>` for stream contents. Never round-trip through `String`; avoid `from_utf8_lossy` (silent data corruption) and `from_utf8().unwrap()` (panic on valid Unix input). Prefer `Write::write_all` over `print!`/`format!` for binary data.
- **Panics are DoS:** treat every `unwrap`, `expect`, indexing, and `as` cast on untrusted input as a potential denial-of-service. Use `?`, `.get()`, `checked_*`, `TryFrom`, and surface real errors. Enable clippy lints: `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects` (allow in `#[cfg(test)]` modules).
- **Propagate errors:** do not discard `Result` with `.ok()`, `.unwrap_or_default()`, or `let _ =` without a comment explaining why the failure is safe to ignore. Propagate the worst exit code, not just the last one.
- **Resolve before crossing trust boundaries:** resolve all user-supplied inputs (usernames, paths, dynamic library lookups) before entering a restricted context (`chroot`, privilege drop, seccomp). After crossing, any library call may execute attacker-controlled code. This matters directly here — virtkit runs rootless and the agent is guest PID 1.
- Deterministic seeds for property/fuzz tests. Co-locate fast unit tests; heavier integration tests under `tests/` (e.g. `vk-agent/tests/exec.rs`).
- Measure before optimizing; document benchmark context when micro-optimizing.

## Dependencies — favor the standard library

See [General Coding Conventions](../coding-guidelines.md#general-coding-conventions) for the rationale. Concrete guidance:

- `std::collections` (`HashMap`, `BTreeMap`, `HashSet`) over `hashbrown`/`indexmap`/`dashmap` unless you need a specific feature (`indexmap` for insertion-order, `dashmap` for measured concurrent contention).
- `std::sync` (`Mutex`, `RwLock`, `Arc`) over `parking_lot` unless contention is measured.
- `thiserror` only when an error enum has many variants and the boilerplate genuinely hurts; `anyhow` only at application boundaries (binaries, top-level handlers), never in libraries. For small error types, hand-written `Display`/`From` impls are fine.
- `std::process::Command` over `duct`/`subprocess`.
- `serde` + `serde_json` for structured I/O — but resist a derive crate just for one struct; a 5-line `Display` impl is sometimes the right answer.
- Acceptable when stdlib is genuinely insufficient: `serde` (de-facto standard), `tokio` (no async runtime in stdlib), `rayon` for data parallelism, `regex`, `chrono`/`time` for date arithmetic beyond `SystemTime`.
- New dependencies enlarge the `cargo-audit` surface and must stay statically linkable under musl. Dependency versions are centralized in the workspace `Cargo.toml` (`[workspace.dependencies]`); add a new advisory ignore only with documented rationale in `.cargo/audit.toml`.
