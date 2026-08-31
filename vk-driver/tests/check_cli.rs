//! Integration tests for `vk check --min-version` routing around config loading, which
//! `main.rs` decides beyond unit-test reach.

use std::path::PathBuf;
use std::process::Command;

fn vk() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vk"))
}

/// A fresh scratch directory removed even after a failed assertion.
struct TmpDir(PathBuf);
impl TmpDir {
    fn new(tag: &str) -> TmpDir {
        let dir = std::env::temp_dir().join(format!("vk-check-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TmpDir(dir)
    }
}
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Answer version-only checks despite an invalid config, without host-dependent probes or
/// letting exit 2 masquerade as an old `vk` to a script.
#[test]
fn a_minimum_version_is_answered_over_an_unreadable_config() {
    let dir = TmpDir::new("badconfig");
    let bad = dir.0.join("config.toml");
    std::fs::write(&bad, "this is not toml\n").unwrap();

    // Met, and the config is never opened.
    let out = vk()
        .args(["--config".as_ref(), bad.as_os_str()])
        .args(["check", "--min-version", "0"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(stdout.starts_with("ok   version "), "{stdout}");
    assert!(!stdout.contains("config"), "{stdout}");

    // Not met is exit 1 — the answer, not an error.
    let out = vk()
        .args(["--config".as_ref(), bad.as_os_str()])
        .args(["check", "--min-version", "999"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");

    // Host checks still report the invalid config and exit 2, including when a version
    // accompanies `--feature`; the shortcut therefore requires an empty feature list.
    for args in [
        &["check"][..],
        &["check", "--feature", "kvm"][..],
        &["check", "--min-version", "0", "--feature", "kvm"][..],
    ] {
        let out = vk()
            .args(["--config".as_ref(), bad.as_os_str()])
            .args(args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}: {out:?}");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(stderr.contains("config.toml"), "{args:?}: {stderr}");
    }
}

/// Reject a non-release as a usage error rather than an unmet version floor.
#[test]
fn a_version_that_is_not_a_release_number_is_a_usage_error() {
    let out = vk()
        .args(["check", "--min-version", "0.45.0-rc1"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(stderr.contains("0.45.0-rc1"), "{stderr}");
}
