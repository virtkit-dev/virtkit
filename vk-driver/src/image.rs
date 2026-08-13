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

use std::io::{Read, Write};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use anyhow::{Context, Result, bail};

use crate::config::Config;

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

/// Resolve an explicit MICROVM_IMAGE-style `image_ref` to a concrete bootable image,
/// caching materialized bases under `state_dir`. The reference is prefix-based (the
/// prefix names the source, split on the FIRST `/`). Every consumer — the CI job image,
/// CI/compose service `image:` units, and `vk run` — resolves through here, so the same
/// ref shares one digest-keyed cache entry (each boots its own CoW overlay over the
/// shared rootfs). Takes just `(&Config, state_dir)` so a non-CI caller need not build a
/// `JobCtx`.
pub fn resolve_ref(cfg: &Config, state_dir: &Path, image_ref: &str) -> Result<ResolvedImage> {
    match image_ref.split_once('/') {
        // local/<name> = a bundle directory under [local] dir.
        Some(("local", rest)) => crate::local::resolve(cfg, state_dir, rest),
        // virtkit/<name>[:tag|@digest] = a native virtkit bundle in the [registry] repo,
        // pulled+cached natively (CDC+zstd chunk dedup); published by `vk build --tag`.
        Some(("virtkit", rest)) => crate::registry::resolve(cfg, state_dir, rest),
        // docker/<name>[:tag|@digest] = an OCI image, pulled and booted directly
        // (embedded kernel + agent; digest-keyed local cache).
        Some(("docker", rest)) => crate::dockerimg::resolve(cfg, state_dir, rest),
        // anything else = a raw OCI reference (the job's `image:`): booted directly.
        _ => crate::dockerimg::resolve_image(cfg, state_dir, image_ref),
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
fn pull_lock_hash(dir: &Path) -> u64 {
    // FNV-1a, to stay within the 108-byte sun_path limit
    fnv64(&[dir.as_os_str().as_bytes()])
}

fn pull_lock_addr(h: u64) -> std::io::Result<SocketAddr> {
    SocketAddr::from_abstract_name(format!("virtkit-pull-{h:016x}"))
}

/// Ask the current lock holder who it is, over the same abstract socket it holds: the
/// holder's responder answers each connection with its `jobctx::job_identity()`. None if nothing
/// answers in time (holder crashed, or racing our connect) — best-effort diagnostics.
fn query_holder(addr: &SocketAddr) -> Option<String> {
    let mut s = UnixStream::connect_addr(addr).ok()?;
    let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(1)));
    let mut buf = String::new();
    s.read_to_string(&mut buf).ok()?;
    let who = buf.trim();
    (!who.is_empty()).then(|| who.to_string())
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

/// A held pull lock. The bound abstract socket IS the lock (the kernel frees it when this
/// process dies); `_sock` keeps it bound for the whole hold — independent of the responder —
/// so the lock is never released early even if that thread exits. The responder answers
/// waiters with this job's identity; dropping the guard stops it and frees the socket.
pub(crate) struct PullLock {
    _sock: UnixListener,
    stop: Arc<AtomicBool>,
    responder: Option<std::thread::JoinHandle<()>>,
}

impl Drop for PullLock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.responder.take() {
            let _ = h.join();
        }
        // `_sock` drops after this, releasing the abstract socket.
    }
}

/// `verb` names the serialized operation in the wait message ("pull" for a registry/OCI
/// fetch, "build" for a build-tier stage) — the lock itself is shared across both.
pub(crate) fn acquire_pull_lock(
    dir: &Path,
    verb: &str,
    name: &str,
    digest: &str,
) -> Result<PullLock> {
    let addr = pull_lock_addr(pull_lock_hash(dir))?;
    let mut waiting = false;
    loop {
        match UnixListener::bind_addr(&addr) {
            Ok(lock) => return Ok(spawn_holder(lock)),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                if !waiting {
                    match query_holder(&addr) {
                        Some(who) => println!(
                            "virtkit: waiting for a concurrent {verb} of {name}@{digest} \
                             (held by {who}) ..."
                        ),
                        None => println!(
                            "virtkit: waiting for a concurrent {verb} of {name}@{digest} ..."
                        ),
                    }
                    waiting = true;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(e) => return Err(e).context("binding the pull-lock socket"),
        }
    }
}

/// Start the holder's responder: a thread that owns a clone of the bound `lock` and answers
/// each waiter's connection with our `jobctx::job_identity()` until the guard is dropped. It uses a
/// non-blocking accept + a stop flag so drop ends it promptly (a bounded join). The guard
/// keeps the original `lock`, so even if this thread dies the socket stays bound (the lock
/// is held); a dead responder only means waiters get no name, never a released lock.
fn spawn_holder(lock: UnixListener) -> PullLock {
    let stop = Arc::new(AtomicBool::new(false));
    let responder = match lock.try_clone() {
        Ok(accept_sock) => {
            let id = crate::jobctx::job_identity();
            let stop = stop.clone();
            Some(std::thread::spawn(move || {
                let _ = accept_sock.set_nonblocking(true);
                while !stop.load(Ordering::Relaxed) {
                    match accept_sock.accept() {
                        Ok((mut s, _)) => {
                            let _ = s.set_write_timeout(Some(std::time::Duration::from_secs(2)));
                            let _ = s.write_all(id.as_bytes());
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(100));
                        }
                        Err(_) => break,
                    }
                }
            }))
        }
        Err(_) => None,
    };
    PullLock {
        _sock: lock,
        stop,
        responder,
    }
}

/// Mark a resolved base as freshly used: ensure its `.inuse` lock file exists and bump the
/// `.used` idle marker to now, so the idle GC never reclaims a base the executor is about to
/// overlay. Called on every resolve (hit or miss). Best-effort.
pub(crate) fn mark_used(dir: &Path) {
    crate::cachelock::stamp(&dir.join(".inuse"), &dir.join(".used"));
}

/// The managed cache tiers under `state_dir`: pulled registry bundles, pulled docker
/// images, and built `build:` stages. A base in any of these is reference-counted and
/// idle-evicted; a baked `[local]` bundle or an ephemeral rootfs is not.
pub(crate) fn cache_tiers(state_dir: &Path) -> [PathBuf; 3] {
    [
        state_dir.join("registry"),
        state_dir.join("docker"),
        state_dir.join("build"),
    ]
}

/// Take a shared-lock reference on the materialized base backing `rootfs`, iff it lives in
/// a managed cache tier (see [`cache_tiers`]). Returns `None` for a baked `[local]` bundle
/// or an ephemeral rootfs — nothing there is reference-counted or evicted. Hold the returned
/// guard for the overlay's whole lifetime: a base under a live overlay is never reclaimed.
pub(crate) fn acquire_use_lock_for(
    state_dir: &Path,
    rootfs: &Path,
) -> Result<Option<crate::cachelock::Guard>> {
    let Some(dir) = rootfs.parent() else {
        return Ok(None);
    };
    if !cache_tiers(state_dir).iter().any(|t| dir.starts_with(t)) {
        return Ok(None);
    }
    // Every resolve re-dates the marker (see `mark_used`), so a base's idle window runs from the
    // most recent boot that wanted it.
    Ok(Some(crate::cachelock::acquire_shared(
        &dir.join(".inuse"),
        &dir.join(".used"),
        crate::cachelock::IdleFrom::Acquire,
    )?))
}

/// Evict every materialized base under `root` that no process is overlaying and that has
/// been idle at least `idle`, on [`crate::cachelock`]'s protocol. Best-effort.
pub(crate) fn gc_idle(root: &Path, idle: std::time::Duration) {
    let now = std::time::SystemTime::now();
    for base in base_dirs(root) {
        crate::cachelock::try_reclaim(&base.join(".inuse"), &base.join(".used"), idle, now, || {
            println!("virtkit: evicting idle image base {}", base.display());
            let _ = std::fs::remove_dir_all(&base);
        });
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

/// The name a pull stages a chunk under before renaming it onto its digest: the digest,
/// then who is writing it. Two pulls of one chunk — concurrent stage restores within a
/// build, or two jobs sharing the store — must not share the file. Both write the same
/// bytes, since the name is the digest, so the hazard is not a mix but a truncation: one
/// writer reopening the file empty under another's finished write lets that writer's rename
/// publish a partial chunk. The pid separates processes, the counter the writes inside one.
pub(crate) fn staging_chunk_name(hex: &str) -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    format!(
        "{hex}.{}-{}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// Whether the pull that staged a [`staging_chunk_name`] in the chunk store is dead, so the
/// file will never be renamed into place. A name that does not carry a pid is from an older
/// `vk` (or is not ours at all) and is reported as still live — never reclaiming someone
/// else's in-flight write is worth leaving the odd stale file behind.
fn staging_writer_is_gone(name: &str) -> bool {
    name.strip_suffix(".tmp")
        .and_then(|rest| rest.rsplit_once('.'))
        .and_then(|(_hex, owner)| owner.split_once('-'))
        .and_then(|(pid, _seq)| pid.parse::<u32>().ok())
        .is_some_and(|pid| !crate::spawn::pid_alive(pid))
}

/// Drop chunk blobs in `<registry_root>/chunks/` that no cached bundle references. Each
/// pulled bundle records the chunk digests it was reassembled from in a `chunks.list`; the
/// union over every still-present bundle is the live set. A chunk is only a re-pull
/// optimization shared across bundles, so once every bundle that used it has been evicted it
/// is dead weight — this ties the deduped chunk store's lifetime to the idle-evicted bundles.
/// Re-materializing a swept chunk just re-downloads it. Best-effort.
pub(crate) fn sweep_chunks(registry_root: &Path) {
    let Ok(entries) = std::fs::read_dir(registry_root.join("chunks")) else {
        return;
    };
    let mut live = std::collections::HashSet::new();
    for base in base_dirs(registry_root) {
        if let Ok(list) = std::fs::read_to_string(base.join("chunks.list")) {
            live.extend(
                list.lines()
                    .map(str::trim)
                    .filter(|h| !h.is_empty())
                    .map(str::to_string),
            );
        }
    }
    let mut dropped = 0usize;
    for e in entries.flatten() {
        let p = e.path();
        let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // A chunk being staged into the store right now (`pull_chunk` writes
        // `<hex>.<pid>-<seq>.tmp` then renames) is left alone; one whose writer is gone is
        // reclaimed, since nothing will ever rename it into place. An in-flight *bundle* is
        // instead kept live by its `chunks.list`, which `pull_into` writes into the staging
        // dir before fetching any chunk.
        if name.ends_with(".tmp") {
            if staging_writer_is_gone(name) && std::fs::remove_file(&p).is_ok() {
                dropped += 1;
            }
            continue;
        }
        if live.contains(name) {
            continue;
        }
        if std::fs::remove_file(&p).is_ok() {
            dropped += 1;
        }
    }
    if dropped > 0 {
        println!("virtkit: swept {dropped} unreferenced cache chunk file(s)");
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
        // A per-process dir keys a per-process abstract socket name: cargo runs test binaries
        // in parallel, so a fixed name would collide with a concurrent vk-driver test process.
        let dir =
            std::env::temp_dir().join(format!("virtkit-test-pull-lock-{}", std::process::id()));
        let addr = pull_lock_addr(pull_lock_hash(&dir)).unwrap();
        let held = UnixListener::bind_addr(&addr).unwrap();
        let err = UnixListener::bind_addr(&addr).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
        drop(held);
        // A concurrent test that spawns a subprocess can briefly inherit this listener fd across
        // `fork()`, keeping the abstract name bound past our drop until the child execs; retry
        // the rebind until it frees rather than failing on that transient contention.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match UnixListener::bind_addr(&addr) {
                Ok(_) => break,
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the lock addr stayed bound after release"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => panic!("rebinding the released lock addr failed: {e}"),
            }
        }
    }

    #[test]
    fn pull_lock_answers_holder_identity_then_releases() {
        let dir = std::env::temp_dir().join(format!("virtkit-test-holder-{}", std::process::id()));
        let addr = pull_lock_addr(pull_lock_hash(&dir)).unwrap();
        let lock = acquire_pull_lock(&dir, "build", "myimg", "sha256:x").unwrap();
        // a waiter reads the holder's identity over the lock socket (pid fallback, no CI env)
        let who = query_holder(&addr).expect("the holder should answer");
        assert!(!who.trim().is_empty());
        // released on drop: the addr binds again (retry for fork-inherited fd races)
        drop(lock);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match UnixListener::bind_addr(&addr) {
                Ok(_) => break,
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the lock addr stayed bound after release"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => panic!("rebinding the released lock addr failed: {e}"),
            }
        }
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

    /// Run `gc_idle` until `base` is evicted — retried for the reason
    /// [`crate::cachelock::reclaimed_eventually`] documents.
    fn evict_eventually(root: &Path, base: &Path) {
        assert!(
            crate::cachelock::reclaimed_eventually(|| {
                gc_idle(root, std::time::Duration::ZERO);
                !base.exists()
            }),
            "base {} was not reclaimed within the timeout",
            base.display()
        );
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

    #[test]
    fn sweep_chunks_drops_only_unreferenced_blobs() {
        let root = std::env::temp_dir().join(format!("vk-sweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // A cached bundle referencing chunk "aaa" (and nothing else).
        let bundle = root.join("img").join("deadbeef");
        std::fs::create_dir_all(&bundle).unwrap();
        std::fs::write(bundle.join("runner.ext4"), b"x").unwrap();
        std::fs::write(bundle.join("chunks.list"), "aaa\n").unwrap();
        // The chunk store: a referenced blob, an orphan, and five staged temps. The live one
        // is named by `staging_chunk_name` itself, so keeping it also proves the name's
        // producer and its parser still agree; one is a dead writer's, to be reclaimed; the
        // last three cover every way the parser can fail to name a writer at all, each of
        // which must be read as live.
        // A guaranteed-dead pid: spawn a child and reap it.
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let dead = child.id();
        child.wait().unwrap();
        let live_tmp = staging_chunk_name("ccc");
        let dead_tmp = format!("ddd.{dead}-0.tmp");
        let no_seq_tmp = format!("fff.{dead}.tmp");
        let chunks = root.join("chunks");
        std::fs::create_dir_all(&chunks).unwrap();
        for f in [
            "aaa",
            "bbb",
            &live_tmp,
            &dead_tmp,
            "eee.tmp",
            &no_seq_tmp,
            "ggg.notapid-0.tmp",
        ] {
            std::fs::write(chunks.join(f), b"z").unwrap();
        }

        sweep_chunks(&root);
        assert!(chunks.join("aaa").exists(), "a referenced chunk is kept");
        assert!(!chunks.join("bbb").exists(), "an orphan chunk is dropped");
        assert!(
            chunks.join(&live_tmp).exists(),
            "an in-flight chunk is left alone"
        );
        assert!(
            !chunks.join(&dead_tmp).exists(),
            "a chunk staged by a dead pull is reclaimed"
        );
        assert!(
            chunks.join("eee.tmp").exists(),
            "a temp with no owner in its name is left alone"
        );
        assert!(
            chunks.join(&no_seq_tmp).exists(),
            "a temp naming no write counter is left alone"
        );
        assert!(
            chunks.join("ggg.notapid-0.tmp").exists(),
            "a temp whose owner is not a pid is left alone"
        );

        // Once the only bundle referencing "aaa" is evicted, "aaa" becomes reclaimable.
        std::fs::remove_dir_all(&bundle).unwrap();
        sweep_chunks(&root);
        assert!(
            !chunks.join("aaa").exists(),
            "a chunk no remaining bundle references is dropped"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn sweep_chunks_keeps_chunks_of_an_in_flight_bundle() {
        // A pull stages a bundle in `<digest>.tmp/` and writes its `chunks.list` before
        // fetching any chunk, so a concurrent sweep must count that staging bundle as live
        // and not reclaim the chunks it is still reassembling.
        let root = std::env::temp_dir().join(format!("vk-sweep-inflight-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let staging = root.join("img").join("deadbeef.tmp");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("runner.ext4"), b"x").unwrap();
        std::fs::write(staging.join("chunks.list"), "aaa\n").unwrap();
        let chunks = root.join("chunks");
        std::fs::create_dir_all(&chunks).unwrap();
        std::fs::write(chunks.join("aaa"), b"z").unwrap();

        sweep_chunks(&root);
        assert!(
            chunks.join("aaa").exists(),
            "a chunk referenced by an in-flight staging bundle is kept"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
