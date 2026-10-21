//! Stamp the source commit into the `vk` binary. The guest kernel, vk-agent and UEFI firmware
//! are not part of the compile: build.sh appends them to the linked binary (assemble.sh, read
//! back by src/embed.rs).
use std::path::PathBuf;

fn main() {
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
