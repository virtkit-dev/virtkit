//! `fleet` ensure — bring each VM's ext4 up to date before boot. Each image is
//! content-addressed: its ext4 UUID is a fingerprint of what it was built from, so
//! the staleness check is just a UUID compare. The staleness check and the fingerprint
//! recipe both live in the build script (`build-{builder,service}-image.sh`), which
//! calls `vk fingerprint` to compute the UUID and `blkid` to check the existing
//! image. This module just invokes the build script; the script exits 0 immediately
//! when the image is already fresh.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    let d = Sha256::digest(data);
    let mut s = String::with_capacity(64);
    for b in d {
        use std::fmt::Write;
        write!(s, "{b:02x}").unwrap();
    }
    s
}

/// Content fingerprint as a canonical UUID: sha256 of the parts joined by '\n', the
/// first 16 bytes formatted 8-4-4-4-12. Called by the `vk fingerprint` subcommand
/// so build scripts can compute the same value without reimplementing the algorithm.
pub fn fingerprint(parts: &[&str]) -> String {
    let hex = sha256_hex(parts.join("\n"));
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Run the VM's build script. The script owns the staleness check (UUID compare)
/// and exits 0 immediately when the image is already fresh.
pub fn ensure_vm(build_script: &Path) -> Result<()> {
    run_build(build_script, &[])
}

/// Run build-service-image.sh <image> <name>. The script owns the staleness check
/// and exits 0 immediately when the image is already fresh.
pub fn ensure_service(name: &str, image: &str, build_script: &Path) -> Result<()> {
    run_build(build_script, &[image, name])
}

fn run_build(script: &Path, args: &[&str]) -> Result<()> {
    let st = Command::new(script)
        .args(args)
        .status()
        .with_context(|| format!("running {}", script.display()))?;
    if !st.success() {
        bail!("{} failed ({st})", script.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_a_canonical_uuid_and_stable() {
        let fp = fingerprint(&["myservice:tag", "abc123"]);
        // 8-4-4-4-12 lowercase hex
        let parts: Vec<&str> = fp.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(fp.chars().all(|c| c == '-' || c.is_ascii_hexdigit()));
        // deterministic + order-sensitive
        assert_eq!(fp, fingerprint(&["myservice:tag", "abc123"]));
        assert_ne!(fp, fingerprint(&["abc123", "myservice:tag"]));
    }
}
