//! MICROVM_IMAGE resolution.
//!
//! `MICROVM_IMAGE` is prefix-based: the part before the first `/` names the
//! source, the rest is source-specific. Jobs select a guest image with it:
//!   - unset — treated as `local/default`.
//!   - `local/<name>` — a bundle directory under the host-configured
//!     `[local] dir` (see local.rs). `<name>` is a single safe path component;
//!     local bundles are never tagged or digested.
//!   - `registry/<name>[:tag|@sha256:…]` — a bundle in the host-configured
//!     `[registry] repo` (the allowlist), pulled+cached natively with CDC+zstd
//!     chunk dedup (see registry.rs). Only the name/reference is job-controlled.
//!   - `docker/<name>[:tag|@sha256:…]` — a docker image in the host-configured
//!     `[docker] repo` (the allowlist), pulled and booted directly via OCI on
//!     demand (see dockerimg.rs). Only the name/reference is job-controlled.
//!
//! This module is the thin dispatcher plus the reference-parsing and local-cache
//! helpers shared with the docker, registry and local paths.

use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixListener};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::jobctx::JobCtx;

/// The boot flavour recorded per converted bundle (`boot.kind`), so a cache hit
/// — which skips the conversion — still knows how to boot it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootKind {
    /// The image ships its own kernel + systemd (a self-booting ext4 bundle).
    Systemd,
    /// Generic OCI image, booted from an ext4 disk on the pinned guest kernel,
    /// virtkit-agent as PID 1.
    GenericDisk,
}

/// What `resolve` produced for a job's MICROVM_IMAGE.
pub enum ResolvedImage {
    /// A CoW ext4 rootfs booted off /dev/vda. `generic=false`: a self-booting
    /// image — its own kernel + initrd, the agent (service mode) hands off to systemd.
    /// `generic=true`: the embedded shared kernel (virtio+ext4 built in, so
    /// `initrd=None`), the agent as PID 1, `ip=` networking.
    /// `kernel=None` boots vk's embedded kernel (a kernel-less bundle / OCI image);
    /// `Some(path)` boots a kernel the bundle ships.
    Disk {
        rootfs: PathBuf,
        kernel: Option<PathBuf>,
        initrd: Option<PathBuf>,
        generic: bool,
    },
}

/// Resolve the job's MICROVM_IMAGE to a concrete bootable image. The variable is
/// prefix-based (the prefix names the source, split on the FIRST `/`); unset is
/// treated as `local/default`.
pub fn resolve(ctx: &JobCtx) -> Result<ResolvedImage> {
    let image_ref = ctx.image_ref.as_deref().unwrap_or("local/default");
    match image_ref.split_once('/') {
        // local/<name> = a bundle directory under [local] dir.
        Some(("local", rest)) => crate::local::resolve(ctx, rest),
        // registry/<name>[:tag|@digest] = a bundle in the [registry] repo,
        // pulled+cached natively (CDC+zstd chunk dedup).
        Some(("registry", rest)) => crate::registry::resolve(ctx, rest),
        // docker/<name>[:tag|@digest] = an OCI image of the [docker] repo, pulled
        // and booted directly (embedded kernel + agent; digest-keyed local cache).
        Some(("docker", rest)) => crate::dockerimg::resolve(ctx, rest),
        // anything else = a raw OCI reference (the job's `image:`): booted directly,
        // accepted only under the [docker] repo allowlist.
        _ => crate::dockerimg::resolve_image(ctx, image_ref),
    }
}

/// Return a `ResolvedImage` from a cached/baked bundle dir, shared by the registry and
/// local paths: the boot shape from the recorded `boot.kind`, and which kernel/initrd
/// files the bundle ships. A bundle that ships no kernel boots vk's embedded one
/// (`kernel=None`).
pub(crate) fn resolved_from_dir(dir: &Path, kind: BootKind) -> ResolvedImage {
    let rootfs = dir.join("runner.ext4");
    let vmlinuz = dir.join("vmlinuz");
    match kind {
        // self-booting (systemd): the image's own kernel + initrd if it shipped
        // one, otherwise the embedded shared kernel, booting the ext4 root directly.
        BootKind::Systemd => {
            let (kernel, initrd) = if vmlinuz.is_file() {
                (Some(vmlinuz), Some(dir.join("initrd.img")))
            } else {
                (None, None)
            };
            ResolvedImage::Disk {
                rootfs,
                kernel,
                initrd,
                generic: false,
            }
        }
        // generic: the embedded shared kernel (virtio + ext4 built in), mounting the
        // ext4 root directly.
        BootKind::GenericDisk => ResolvedImage::Disk {
            rootfs,
            kernel: None,
            initrd: None,
            generic: true,
        },
    }
}

/// Read the boot flavour from a bundle dir. An absent marker reads as systemd
/// (bundles predating the marker); an unrecognised marker — e.g. the retired
/// `generic-cpio` — reads as `None`, which callers treat as a stale bundle.
/// The marker is trimmed before matching, so a file written with a trailing
/// newline (e.g. `echo generic-disk > boot.kind`) is read correctly.
pub(crate) fn read_boot_kind(dir: &Path) -> Option<BootKind> {
    parse_boot_kind(
        std::fs::read_to_string(dir.join("boot.kind"))
            .ok()
            .as_deref(),
    )
}

fn parse_boot_kind(marker: Option<&str>) -> Option<BootKind> {
    match marker.map(str::trim) {
        None | Some("systemd") => Some(BootKind::Systemd),
        Some("generic-disk") => Some(BootKind::GenericDisk),
        Some(_) => None,
    }
}

/// The `boot.kind` marker string for a boot flavour (the value the registry
/// config blob and the bundle marker record).
pub(crate) fn boot_kind_tag(kind: BootKind) -> &'static str {
    match kind {
        BootKind::Systemd => "systemd",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_kind_marker_is_trimmed() {
        // exact tags
        assert!(matches!(
            parse_boot_kind(Some("generic-disk")),
            Some(BootKind::GenericDisk)
        ));
        // trailing newline (echo) / surrounding whitespace must still match
        assert!(matches!(
            parse_boot_kind(Some("generic-disk\n")),
            Some(BootKind::GenericDisk)
        ));
        assert!(matches!(
            parse_boot_kind(Some("  systemd \n")),
            Some(BootKind::Systemd)
        ));
        // absent marker -> legacy systemd bundle
        assert!(matches!(parse_boot_kind(None), Some(BootKind::Systemd)));
        // unknown markers (including the retired generic-cpio) -> stale bundle
        assert!(parse_boot_kind(Some("generic-cpio")).is_none());
        assert!(parse_boot_kind(Some("bogus")).is_none());
    }

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
        // a bare name defaults to :latest
        let (n, r) = parse_ref("myimage").unwrap();
        assert_eq!(n, "myimage");
        assert!(matches!(r, Reference::Tag(t) if t == "latest"));

        let (n, r) = parse_ref("runner:20260610-abc").unwrap();
        assert_eq!(n, "runner");
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
