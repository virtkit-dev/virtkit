//! `fleet` ensure — bring each VM's ext4 up to date before boot. Each image is
//! content-addressed: its ext4 UUID is a fingerprint of what it was built from, so
//! the staleness check is just "compute the fingerprint of the current inputs and
//! compare it to the image's UUID". No `.imgref`/`.stamp` sidecars — the identity
//! lives in the filesystem itself (and doubles as the CoW-overlay key). The actual
//! build stays the shell script (`docker export` -> `mkext-tar --uuid <fingerprint>`),
//! which must compute the SAME fingerprint (see build-{builder,service}-image.sh).
//! The build inputs live alongside the build script, so their paths derive from it.

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

/// Rebuild builder.ext4 via `build_script` when it is missing or when its UUID no
/// longer matches the fingerprint of the build inputs (the agent binary baked in as
/// PID 1, the build script, the profile-env shim). Docker-image staleness is the
/// caller's job (devenv --vm builds the images first), so the image id is not in it.
pub fn ensure_builder(ext4: &Path, build_script: &Path, agent: &Path) -> Result<()> {
    let dir = build_script.parent().unwrap_or(Path::new("."));
    let want = fingerprint(&[
        file_sha256(agent)?,
        file_sha256(build_script)?,
        file_sha256(&dir.join("profile-image-env.sh"))?,
    ]);
    ensure(ext4, &want, build_script, &[], "builder.ext4")
}

/// Rebuild a service ext4 via `build_script <image> <name>` when it is missing or
/// when its UUID no longer matches the fingerprint of the source image ref and the
/// agent binary (PID 1); the image tag itself embeds the image's content hash.
pub fn ensure_service(
    name: &str,
    image: &str,
    ext4: &Path,
    build_script: &Path,
    agent: &Path,
) -> Result<()> {
    let want = fingerprint(&[image.to_string(), file_sha256(agent)?]);
    ensure(
        ext4,
        &want,
        build_script,
        &[image, name],
        &format!("{name}.ext4"),
    )
}

/// Build `ext4` (via `build_script args`) when missing or when its UUID != `want`;
/// after building, assert the rebuilt image carries `want` (i.e. the shell script's
/// fingerprint recipe matches ours — a guard against the two drifting apart).
fn ensure(ext4: &Path, want: &str, build_script: &Path, args: &[&str], label: &str) -> Result<()> {
    let have = crate::fleet::fs_uuid(ext4);
    if ext4.is_file() && have.as_deref() == Some(want) {
        return Ok(());
    }
    let why = if ext4.is_file() { "stale" } else { "missing" };
    println!("fleet: {label} {why} — building ...");
    run_build(build_script, args)?;
    if crate::fleet::fs_uuid(ext4).as_deref() != Some(want) {
        bail!(
            "{} did not produce {} with the expected uuid {want} — the build script's \
             fingerprint recipe is out of sync with ensure",
            build_script.display(),
            ext4.display()
        );
    }
    Ok(())
}

/// Content fingerprint as a canonical UUID: sha256 of the parts joined by '\n', the
/// first 16 bytes formatted 8-4-4-4-12. The build scripts compute the SAME value and
/// stamp it as the ext4 UUID (`mkext-tar --uuid`), so a mismatch means stale.
fn fingerprint(parts: &[String]) -> String {
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

/// sha256 (hex) of a file's contents, matching `sha256sum | cut -d' ' -f1`.
fn file_sha256(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(sha256_hex(&bytes))
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
        let fp = fingerprint(&["wabredis:tag".into(), "abc123".into()]);
        // 8-4-4-4-12 lowercase hex
        let parts: Vec<&str> = fp.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(fp.chars().all(|c| c == '-' || c.is_ascii_hexdigit()));
        // deterministic + order-sensitive
        assert_eq!(fp, fingerprint(&["wabredis:tag".into(), "abc123".into()]));
        assert_ne!(fp, fingerprint(&["abc123".into(), "wabredis:tag".into()]));
    }
}
