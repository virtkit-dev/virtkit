//! Embed the guest kernel and vk-agent into the `vk` binary.
//!
//! With the `embed` feature (on by default), src/embed.rs pulls the two blobs in
//! via `.incbin "${env!(...)}"`. This script sets those env vars to the paths
//! given by VK_EMBED_KERNEL / VK_EMBED_AGENT (build.sh supplies them).
//! When a var is unset — a plain dev `cargo build` — it points the include at an
//! empty file, which the runtime treats as "not embedded" and falls back to
//! --kernel/--agent.
use std::path::PathBuf;

fn main() {
    embed("VK_EMBED_KERNEL", "VK_EMBED_KERNEL_PATH");
    embed("VK_EMBED_AGENT", "VK_EMBED_AGENT_PATH");
    emit_git_hash();
}

/// Expose the source commit as `VK_GIT_HASH` so `vk --version` can report exactly which build
/// it is. `build.sh` supplies `VK_GIT_COMMIT` (its reproducible builds run in a tree copy with
/// no `.git`); a plain `cargo build` reads it from git, re-running when HEAD or the checked-out
/// ref moves so the stamp tracks the commit, and marks a dirty tree.
fn emit_git_hash() {
    println!("cargo::rerun-if-env-changed=VK_GIT_COMMIT");
    if let Some(c) = std::env::var_os("VK_GIT_COMMIT") {
        let c = c.to_string_lossy().trim().to_string();
        if !c.is_empty() {
            println!("cargo::rustc-env=VK_GIT_HASH={c}");
            return;
        }
    }
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let git = PathBuf::from(&manifest).parent().unwrap().join(".git");
    if git.is_dir() {
        println!("cargo::rerun-if-changed={}", git.join("HEAD").display());
        if let Ok(head) = std::fs::read_to_string(git.join("HEAD"))
            && let Some(refname) = head.strip_prefix("ref: ")
        {
            println!(
                "cargo::rerun-if-changed={}",
                git.join(refname.trim()).display()
            );
        }
    }
    let git_out = |args: &[&str]| {
        std::process::Command::new("git")
            .args(args)
            .current_dir(&manifest)
            .output()
            .ok()
            .filter(|o| o.status.success())
    };
    let hash = match git_out(&["rev-parse", "HEAD"]) {
        Some(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        None => "unknown".to_string(),
    };
    let dirty = git_out(&["status", "--porcelain", "--untracked-files=no"])
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);
    let suffix = if dirty { "-dirty" } else { "" };
    println!("cargo::rustc-env=VK_GIT_HASH={hash}{suffix}");
}

fn embed(src_var: &str, path_var: &str) {
    println!("cargo::rerun-if-env-changed={src_var}");
    // Only the `embed` feature compiles the include; skip the work otherwise.
    if std::env::var_os("CARGO_FEATURE_EMBED").is_none() {
        return;
    }
    // A content stamp of the embedded blob, emitted as a rustc-env the `.incbin`
    // module references. `.incbin` splices the file at assemble time, but cargo keys
    // recompilation on the *path* env (stable here) and on source text — never on the
    // included file's content. Without this stamp, rebuilding only the agent leaves
    // `vk` embedding the previous blob (a silent stale-embed footgun). A changed stamp
    // forces the embed module to recompile and re-run `.incbin`.
    let (path, stamp) = match std::env::var_os(src_var) {
        Some(p) if !p.is_empty() => {
            let p = PathBuf::from(p);
            // A set var naming a missing file is a build-system bug (typo, path drift),
            // not a dev build — fail rather than silently ship a non-embedded `vk`.
            assert!(
                p.is_file(),
                "{src_var} is set but {} is not a file — fix the path or unset it",
                p.display()
            );
            println!("cargo::rerun-if-changed={}", p.display());
            let stamp = content_stamp(&p);
            (std::fs::canonicalize(&p).unwrap_or(p), stamp)
        }
        _ => {
            // Only warn for a release build: a non-embedded release artifact is a
            // shippable-binary footgun worth flagging. In debug (dev iteration, and
            // `cargo check`/`clippy`) the fallback to --kernel/--agent is the norm, so
            // the warning is pure noise — notably it cluttered every `lint.sh` run.
            if std::env::var_os("PROFILE").as_deref() == Some(std::ffi::OsStr::new("release")) {
                println!(
                    "cargo::warning={src_var} unset — `vk` built without an embedded \
                     blob; set it (see build.sh) for a self-contained binary"
                );
            }
            let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
            let empty = out_dir.join(format!("{path_var}.empty"));
            std::fs::write(&empty, []).expect("write empty embed placeholder");
            (empty, 0)
        }
    };
    println!("cargo::rustc-env={path_var}={}", path.display());
    println!("cargo::rustc-env={src_var}_STAMP={stamp:016x}");
}

/// A 64-bit content hash of `p`, so the embed module recompiles when the blob changes.
fn content_stamp(p: &std::path::Path) -> u64 {
    use std::hash::Hasher;
    let bytes = std::fs::read(p).unwrap_or_default();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    h.write(&bytes);
    h.finish()
}
