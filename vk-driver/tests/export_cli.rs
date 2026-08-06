//! `vk export` CLI wiring: the per-format flag validation, the overwrite guard
//! and the report line live in main.rs, out of unit-test reach — drive the
//! built binary instead.

use std::path::PathBuf;
use std::process::Command;

fn vk() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vk"))
}

/// A fresh scratch directory, removed on drop so a failing assertion cannot leak it.
struct TmpDir(PathBuf);
impl TmpDir {
    fn new(tag: &str) -> TmpDir {
        let dir = std::env::temp_dir().join(format!("vk-export-cli-{tag}-{}", std::process::id()));
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

#[test]
fn a_flag_for_another_format_is_a_usage_error() {
    let dir = TmpDir::new("flags");
    let disk = dir.0.join("disk.raw");
    std::fs::write(&disk, vec![7u8; 512]).unwrap();

    // An ISO knob on a vmdk export names the right subcommand and exits 2.
    let out = vk()
        .args(["export", "vmdk"])
        .arg(&disk)
        .args(["--volid", "X"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(stderr.contains("vk export iso"), "{stderr}");

    // And an appliance knob on an iso export points at ova the same way.
    let tree = dir.0.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    let out = vk()
        .args(["export", "iso"])
        .arg(&tree)
        .arg(dir.0.join("out.iso"))
        .args(["--name", "x"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(stderr.contains("vk export ova"), "{stderr}");
}

#[test]
fn an_output_aliasing_the_input_is_refused_by_identity() {
    let dir = TmpDir::new("alias");
    let disk = dir.0.join("disk.raw");
    std::fs::write(&disk, vec![7u8; 512]).unwrap();
    // Same file, different spelling: the dev+inode guard has to catch it.
    let alias = dir.0.join(".").join("disk.raw");
    let out = vk()
        .args(["export", "vmdk"])
        .arg(&disk)
        .arg(&alias)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(stderr.contains("overwrite the input"), "{stderr}");
    assert_eq!(
        std::fs::read(&disk).unwrap(),
        vec![7u8; 512],
        "input intact"
    );
}

#[test]
fn an_iso_export_reports_the_tree_it_wrote() {
    let dir = TmpDir::new("happy");
    let tree = dir.0.join("tree");
    std::fs::create_dir_all(tree.join("payload")).unwrap();
    std::fs::write(tree.join("install.sh"), b"#!/bin/sh\n").unwrap();
    std::fs::write(tree.join("payload/disk.img.zst"), vec![7u8; 4096]).unwrap();
    let iso = dir.0.join("out.iso");
    let out = vk()
        .args(["export", "iso"])
        .arg(&tree)
        .arg(&iso)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(stdout.contains("tree of 3 members"), "{stdout}");
    assert!(iso.is_file());
}
