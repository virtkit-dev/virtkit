//! MICROVM_IMAGE resolution.
//!
//! `MICROVM_IMAGE` is prefix-based: the part before the first `/` names the
//! source, the rest is source-specific. Jobs select a guest image with it:
//!   - unset — treated as `local/default`.
//!   - `local/<name>` — a bundle directory under the host-configured
//!     `[local] dir` (see local.rs). `<name>` is a single safe path component;
//!     local bundles are never tagged or digested.
//!   - `virtkit/<name>[:tag|@sha256:…]` — a bundle in the host-configured
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
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{SocketAddr, UnixListener};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::jobctx::JobCtx;

/// The boot flavour recorded per cached bundle (`boot.kind`), so a cache hit
/// — which skips the pull/build — still knows how to boot it.
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
        /// The image's runtime config (Env/User/Workdir/Cmd), applied at boot so the guest
        /// runs as the image intends. `None` for a bundle/image that ships no config sidecar
        /// (an older bundle, or a self-booting systemd image that carries its own).
        config: Option<vk_core::runcfg::RunConfig>,
    },
}

/// Resolve the job's MICROVM_IMAGE to a concrete bootable image. The variable is
/// prefix-based (the prefix names the source, split on the FIRST `/`); unset is
/// treated as `local/default`.
pub fn resolve(ctx: &JobCtx) -> Result<ResolvedImage> {
    resolve_ref(ctx, ctx.image_ref.as_deref().unwrap_or("local/default"))
}

/// Resolve an explicit MICROVM_IMAGE-style `image_ref` — the same prefix dispatch and
/// digest-keyed cache `resolve` applies to the job's own image. Service units resolve
/// their `image:` through here too, so a job image and a service naming the same ref
/// share one cache entry (each boots its own CoW overlay over the shared rootfs).
pub fn resolve_ref(ctx: &JobCtx, image_ref: &str) -> Result<ResolvedImage> {
    match image_ref.split_once('/') {
        // local/<name> = a bundle directory under [local] dir.
        Some(("local", rest)) => crate::local::resolve(ctx, rest),
        // virtkit/<name>[:tag|@digest] = a native virtkit bundle in the [registry] repo,
        // pulled+cached natively (CDC+zstd chunk dedup); published by `vk build --tag`.
        Some(("virtkit", rest)) => crate::registry::resolve(ctx, rest),
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
    // The image's runtime config, written next to runner.ext4 by the bundle pull (from the
    // manifest's run_config); the boot applies it. Absent for bundles built without it.
    let config = std::fs::read(dir.join("runner.ext4.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
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
                config,
            }
        }
        // generic: the embedded shared kernel (virtio + ext4 built in), mounting the
        // ext4 root directly.
        BootKind::GenericDisk => ResolvedImage::Disk {
            rootfs,
            kernel: None,
            initrd: None,
            generic: true,
            config,
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

/// Mark a resolved base as freshly used: ensure its `.inuse` lock file exists and bump the
/// `.used` idle marker to now, so the idle GC never reclaims a base the executor is about to
/// overlay. Called on every resolve (hit or miss). Best-effort.
pub(crate) fn mark_used(dir: &Path) {
    let _ = std::fs::File::create(dir.join(".inuse"));
    let _ = std::fs::File::create(dir.join(".used"));
}

/// A held reference to a materialized image base: a shared advisory lock on the base's
/// `.inuse`, kept for the whole lifetime of the VM overlaying it. The kernel drops the lock
/// when this process exits for any reason, so a crashed job never pins a base — and
/// `gc_idle`, which needs a non-blocking *exclusive* lock to evict, can therefore never
/// reclaim a base under a live overlay. Released on drop.
pub(crate) struct UseGuard {
    _file: std::fs::File,
}

/// Take a shared-lock reference on the materialized base backing `rootfs`, iff it lives in
/// the managed cache (`<state_dir>/{registry,docker}/…`). Returns `None` for a baked
/// `[local]` bundle or an ephemeral rootfs — nothing there is reference-counted or evicted.
/// Hold the returned guard for the overlay's whole lifetime.
pub(crate) fn acquire_use_lock_for(state_dir: &Path, rootfs: &Path) -> Result<Option<UseGuard>> {
    let Some(dir) = rootfs.parent() else {
        return Ok(None);
    };
    if !dir.starts_with(state_dir.join("registry")) && !dir.starts_with(state_dir.join("docker")) {
        return Ok(None);
    }
    let path = dir.join(".inuse");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    // SAFETY: the fd is owned by `file`, kept alive by the returned guard. LOCK_SH contends
    // only with the GC's momentary exclusive lock.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("shared-locking {}", path.display()));
    }
    let _ = std::fs::File::create(dir.join(".used"));
    Ok(Some(UseGuard { _file: file }))
}

/// Evict every materialized base under `root` that no process is overlaying and that has
/// been idle at least `idle`. A live overlay holds a shared lock on the base's `.inuse`, so
/// the non-blocking exclusive lock here fails and that base is skipped — a running base is
/// never reclaimed. A base whose `.used` marker is missing (still being set up) is left
/// alone. Best-effort.
pub(crate) fn gc_idle(root: &Path, idle: std::time::Duration) {
    let now = std::time::SystemTime::now();
    for base in base_dirs(root) {
        let Ok(file) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(base.join(".inuse"))
        else {
            continue;
        };
        // A live overlay holds LOCK_SH; a non-blocking LOCK_EX then fails (EWOULDBLOCK).
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            continue;
        }
        let idle_ok = match std::fs::metadata(base.join(".used")).and_then(|m| m.modified()) {
            // A `.used` timestamp can read microseconds *ahead* of `now`: the filesystem stamps
            // mtime from a coarse clock while `now` is precise, so under load the marker can
            // appear to be in the future. Treat that as "used just now" (zero elapsed) rather
            // than "keep forever", so a zero idle window still reclaims an unreferenced base.
            Ok(t) => now.duration_since(t).unwrap_or_default() >= idle,
            Err(_) => false, // missing/unreadable marker: mid-materialize, leave alone
        };
        if !idle_ok {
            continue;
        }
        // Hold the exclusive lock across removal: a would-be new consumer's shared lock
        // blocks on it, then finds the base gone and re-materializes.
        println!("virtkit: evicting idle image base {}", base.display());
        let _ = std::fs::remove_dir_all(&base);
    }
}

/// Every materialized base under `root`: a directory directly holding a `runner.ext4`. The
/// name between `root` and the digest can be multi-level (a `team/img` docker repo), so walk
/// down, treating any dir with a `runner.ext4` as a base and not descending into it.
fn base_dirs(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if dir.join("runner.ext4").is_file() {
            out.push(dir);
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            }
        }
    }
    out
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

    /// Run `gc_idle` until `base` is evicted. `gc_idle`'s liveness probe is a non-blocking
    /// exclusive `flock`; a *concurrent* test that spawns a subprocess (e.g. the qcow2 tests
    /// run `qemu-img`) briefly leaks this test's `.inuse` lock fd into the forked child across
    /// `fork()`, keeping the shared lock alive until the child `exec`s and drops it. That makes
    /// a single-shot eviction check racy under parallel load, so retry — exactly as the periodic
    /// production GC would. Converges once the transient inheriting child is gone.
    fn evict_eventually(root: &Path, base: &Path) {
        use std::time::{Duration, Instant};
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            gc_idle(root, Duration::ZERO);
            if !base.exists() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "base {} was not reclaimed within the timeout",
                base.display()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn gc_idle_reference_counts_and_respects_the_timeout() {
        use std::time::Duration;
        let tmp = std::env::temp_dir().join(format!("vk-gcidle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let root = tmp.join("registry");
        // A materialized base under the managed cache: <root>/<name>/<digest>/runner.ext4.
        let base = |name: &str| -> PathBuf {
            let d = root.join(name).join("deadbeef");
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("runner.ext4"), b"x").unwrap();
            d
        };
        let rootfs = |d: &Path| d.join("runner.ext4");

        // Idle (marked used, no live overlay): a zero timeout evicts it.
        let idle = base("idle");
        mark_used(&idle);
        evict_eventually(&root, &idle);

        // Referenced: a held use-lock survives a zero timeout, and is reclaimed once dropped.
        let live = base("live");
        mark_used(&live);
        let guard = acquire_use_lock_for(&tmp, &rootfs(&live)).unwrap();
        assert!(
            guard.is_some(),
            "a base under the managed cache is reference-counted"
        );
        gc_idle(&root, Duration::ZERO);
        assert!(
            live.exists(),
            "a base under a live overlay must never be evicted"
        );
        drop(guard);
        evict_eventually(&root, &live);

        // No `.used` marker (mid-materialize): never evicted, even at a zero timeout.
        let fresh = base("fresh");
        gc_idle(&root, Duration::ZERO);
        assert!(
            fresh.exists(),
            "a base still being set up (no .used) must be left alone"
        );

        // A non-zero timeout keeps a just-used base (its `.used` is recent).
        mark_used(&fresh);
        gc_idle(&root, Duration::from_secs(3600));
        assert!(
            fresh.exists(),
            "a recently used base must survive within the idle window"
        );

        // A base outside the managed cache is not reference-counted.
        let unmanaged = tmp.join("elsewhere");
        std::fs::create_dir_all(&unmanaged).unwrap();
        assert!(
            acquire_use_lock_for(&tmp, &unmanaged.join("runner.ext4"))
                .unwrap()
                .is_none()
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn gc_idle_tolerates_a_used_marker_in_the_future() {
        // The filesystem stamps `.used` from a coarse clock while `gc_idle` reads a precise
        // one, so under load the marker can read slightly ahead of `now`. Such a base must
        // still be reclaimable at a zero idle window (treated as elapsed 0), and still kept
        // within a non-zero window — never wrongly pinned forever by the skew.
        use std::time::{Duration, SystemTime};
        let tmp = std::env::temp_dir().join(format!("vk-gcidle-future-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let root = tmp.join("registry");
        let base = |name: &str| -> PathBuf {
            let d = root.join(name).join("deadbeef");
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("runner.ext4"), b"x").unwrap();
            // Stamp `.used` a minute into the future to force the skew deterministically.
            let f = std::fs::File::create(d.join(".used")).unwrap();
            f.set_times(
                std::fs::FileTimes::new().set_modified(SystemTime::now() + Duration::from_secs(60)),
            )
            .unwrap();
            d
        };

        let keep = base("keep");
        gc_idle(&root, Duration::from_secs(3600));
        assert!(
            keep.exists(),
            "a future-skewed base must survive a non-zero idle window"
        );

        let evict = base("evict");
        evict_eventually(&root, &evict);

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
