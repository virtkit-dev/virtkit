//! MICROVM_IMAGE resolution.
//!
//! Jobs select a guest image with `MICROVM_IMAGE`:
//!   - `default` — the builtin bundle baked into the runner host (the static
//!     `[image]` paths): the bootstrap guest, never fetched from a registry.
//!   - `docker/<name>[:tag|@sha256:…]` — a docker image of the host-configured
//!     `[convert] repo` (the allowlist), turned into a bootable bundle on demand
//!     (see convert.rs). Only the name/reference is job-controlled.
//!
//! This module is the thin dispatcher plus the reference-parsing, oras and
//! local-cache helpers shared with the conversion path.

use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::jobctx::JobCtx;

/// The boot flavour recorded per converted bundle (`boot.kind`), so a cache hit
/// — which skips the conversion — still knows how to boot it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootKind {
    /// The image ships its own kernel + systemd (a self-booting ext4 bundle).
    Systemd,
    /// Generic OCI image (no kernel, no init), booted from a cpio initramfs in
    /// RAM on the pinned guest kernel, virtkit-agent as PID 1.
    GenericCpio,
    /// Generic OCI image, booted from an ext4 disk on the pinned guest kernel,
    /// virtkit-agent as PID 1.
    GenericDisk,
}

/// What `resolve` produced for a job's MICROVM_IMAGE.
pub enum ResolvedImage {
    /// A CoW ext4 rootfs booted off /dev/vda. `generic=false`: a self-booting
    /// image — its own kernel + initrd, the agent (service mode) hands off to systemd.
    /// `generic=true`: the pinned shared kernel (virtio+ext4 built in, so
    /// `initrd=None`), the agent as PID 1, `ip=` networking.
    Disk {
        rootfs: PathBuf,
        kernel: PathBuf,
        initrd: Option<PathBuf>,
        generic: bool,
    },
    /// Generic image: kernel + a cpio initramfs (the rootfs, in RAM), virtkit-agent
    /// as PID 1 (no disk). Network via the kernel `ip=` autoconfig param.
    Initramfs { kernel: PathBuf, initramfs: PathBuf },
}

/// Resolve the job's MICROVM_IMAGE, if any. None = no variable set, the
/// caller falls back to the static [image] paths.
pub fn resolve(ctx: &JobCtx) -> Result<Option<ResolvedImage>> {
    let Some(image_ref) = ctx.image_ref.as_deref() else {
        return Ok(None);
    };
    // `default` = the builtin host bundle, never the registry: the bootstrap
    // guest, works with no registry access and cannot be silently overridden.
    if image_ref == "default" {
        println!("virtkit: image default (builtin host bundle)");
        return Ok(None);
    }
    // docker/<name>[:tag|@digest] = a docker image of the [convert] repo, turned
    // into a bootable bundle on demand (digest-keyed local cache).
    if let Some(docker_ref) = image_ref.strip_prefix("docker/") {
        return crate::convert::resolve(ctx, docker_ref).map(Some);
    }
    bail!(
        "invalid MICROVM_IMAGE {image_ref:?} (want `default` or `docker/<name>[:tag|@sha256:…]`)"
    );
}

/// Read the boot flavour recorded in a bundle dir's `boot.kind` marker; an
/// unknown/absent marker reads as systemd (older bundles).
pub(crate) fn read_boot_kind(dir: &Path) -> BootKind {
    match std::fs::read_to_string(dir.join("boot.kind")).as_deref() {
        Ok("generic-cpio") => BootKind::GenericCpio,
        Ok("generic-disk") => BootKind::GenericDisk,
        _ => BootKind::Systemd,
    }
}

/// The `boot.kind` marker string for a boot flavour (the value recorded in the
/// bundle marker).
pub(crate) fn boot_kind_tag(kind: BootKind) -> &'static str {
    match kind {
        BootKind::Systemd => "systemd",
        BootKind::GenericCpio => "generic-cpio",
        BootKind::GenericDisk => "generic-disk",
    }
}

pub(crate) enum Reference {
    Tag(String),
    Digest(String),
}

/// `<name>[:tag|@sha256:<64 hex>]`; name and tag are restricted to one safe
/// path component each (they end up in registry URLs and cache paths).
pub(crate) fn parse_ref(s: &str) -> Result<(String, Reference)> {
    let (name, reference) = if let Some((n, d)) = s.split_once('@') {
        (n, Reference::Digest(d.to_string()))
    } else if let Some((n, t)) = s.split_once(':') {
        (n, Reference::Tag(t.to_string()))
    } else {
        (s, Reference::Tag("latest".into()))
    };
    let component_ok = |v: &str| {
        !v.is_empty()
            && !v.starts_with('.')
            && v.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    if !component_ok(name) {
        bail!("invalid MICROVM_IMAGE name {name:?}");
    }
    match &reference {
        Reference::Tag(t) if !component_ok(t) => bail!("invalid MICROVM_IMAGE tag {t:?}"),
        Reference::Digest(d) if parse_digest(d).is_none() => {
            bail!("invalid MICROVM_IMAGE digest {d:?} (want sha256:<64 hex>)")
        }
        _ => {}
    }
    Ok((name.to_string(), reference))
}

pub(crate) fn parse_digest(s: &str) -> Option<String> {
    let hex = s.strip_prefix("sha256:")?;
    (hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit())).then(|| s.to_string())
}

/// Pull-serialization lock: an abstract unix socket derived from the image
/// directory. Binding the name IS the lock — the kernel releases it when the
/// holding process dies, and unlike a lock file it cannot be unlinked by a
/// cache cleanup (an `rm -rf images/` mid-pull would let two prepares race
/// again). A hash collision only serializes two unrelated pulls.
fn pull_lock_addr(dir: &Path) -> std::io::Result<SocketAddr> {
    // FNV-1a, to stay within the 108-byte sun_path limit
    let h = fnv64(&[dir.as_os_str().as_bytes()]);
    SocketAddr::from_abstract_name(format!("virtkit-pull-{h:016x}"))
}

/// FNV-1a over concatenated byte slices (cache keys and lock names, not
/// security)
pub(crate) fn fnv64(parts: &[&[u8]]) -> u64 {
    parts
        .iter()
        .flat_map(|p| p.iter())
        .fold(0xcbf29ce484222325u64, |h, b| {
            (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
        })
}

pub(crate) fn acquire_pull_lock(dir: &Path, name: &str, digest: &str) -> Result<UnixListener> {
    let addr = pull_lock_addr(dir)?;
    let mut waiting = false;
    loop {
        match UnixListener::bind_addr(&addr) {
            Ok(lock) => return Ok(lock),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                if !waiting {
                    println!("virtkit: waiting for a concurrent pull of {name}@{digest} ...");
                    waiting = true;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(e) => return Err(e).context("binding the pull-lock socket"),
        }
    }
}

/// Keep the `keep` most recently pulled versions of this image (plus the one
/// just resolved, always).
pub(crate) fn gc(images_dir: &Path, current: &Path, keep: u32) {
    let Ok(entries) = std::fs::read_dir(images_dir) else {
        return;
    };
    let mut dirs: Vec<(std::time::SystemTime, PathBuf)> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir() && p != current && p.extension().is_none())
        .filter_map(|p| Some((p.metadata().ok()?.modified().ok()?, p)))
        .collect();
    dirs.sort_by_key(|(mtime, _)| std::cmp::Reverse(*mtime));
    for (_, dir) in dirs.into_iter().skip(keep.saturating_sub(1) as usize) {
        println!("virtkit: evicting cached image {}", dir.display());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// oras invocation for the [convert] path (TLS/auth wiring); the password goes
/// through stdin, never argv.
pub(crate) fn oras_run(
    oras: &Path,
    ca_file: Option<&Path>,
    username: &str,
    password_file: Option<&Path>,
    args: &[&str],
) -> Result<String> {
    let mut cmd = Command::new(oras);
    cmd.args(args);
    if let Some(ca) = ca_file {
        cmd.arg("--ca-file").arg(ca);
    }
    let mut password = None;
    if !username.is_empty() {
        let file = password_file.context("registry username set but no password_file")?;
        password = Some(
            std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?,
        );
        cmd.args(["--username", username, "--password-stdin"]);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning {}", oras.display()))?;
    if let Some(pass) = password {
        use std::io::Write;
        child
            .stdin
            .take()
            .context("no stdin pipe")?
            .write_all(pass.trim_end().as_bytes())?;
    } else {
        drop(child.stdin.take());
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "oras {} failed ({}): {}",
            args.first().unwrap_or(&""),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pull_lock_excludes_and_releases() {
        let dir = Path::new("/tmp/virtkit-test-pull-lock");
        let addr = pull_lock_addr(dir).unwrap();
        let held = UnixListener::bind_addr(&addr).unwrap();
        let err = UnixListener::bind_addr(&addr).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
        drop(held);
        UnixListener::bind_addr(&addr).unwrap();
    }

    #[test]
    fn parse_refs() {
        // bare `default` never reaches parse_ref (resolve() short-circuits it
        // to the builtin bundle); any other bare name defaults to :latest
        let (n, r) = parse_ref("myimage").unwrap();
        assert_eq!(n, "myimage");
        assert!(matches!(r, Reference::Tag(t) if t == "latest"));

        let (n, r) = parse_ref("default:20260610-abc").unwrap();
        assert_eq!(n, "default");
        assert!(matches!(r, Reference::Tag(t) if t == "20260610-abc"));

        let digest = format!("sha256:{}", "a".repeat(64));
        let (n, r) = parse_ref(&format!("myimage@{digest}")).unwrap();
        assert_eq!(n, "myimage");
        assert!(matches!(r, Reference::Digest(d) if d == digest));

        for bad in [
            "",
            "../etc",
            "a/b",
            "name:",
            "name:tag:tag",
            "name@sha256:zz",
            "name@md5:abcd",
            ".hidden",
        ] {
            assert!(parse_ref(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
