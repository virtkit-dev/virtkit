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
}

fn embed(src_var: &str, path_var: &str) {
    println!("cargo::rerun-if-env-changed={src_var}");
    // Only the `embed` feature compiles the include; skip the work otherwise.
    if std::env::var_os("CARGO_FEATURE_EMBED").is_none() {
        return;
    }
    let path = match std::env::var_os(src_var) {
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
            std::fs::canonicalize(&p).unwrap_or(p)
        }
        _ => {
            println!(
                "cargo::warning={src_var} unset — `vk` built without an embedded \
                 blob; set it (see build.sh) for a self-contained binary"
            );
            let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
            let empty = out_dir.join(format!("{path_var}.empty"));
            std::fs::write(&empty, []).expect("write empty embed placeholder");
            empty
        }
    };
    println!("cargo::rustc-env={path_var}={}", path.display());
}
