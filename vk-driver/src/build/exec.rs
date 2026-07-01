//! Executor abstraction: how a stage's instructions become a root filesystem.
//!
//! The driver (see [`super::build`]) walks the planned stages and calls these
//! primitives; the backend decides *how* each happens. Two backends:
//!   - [`DryRun`] records every primitive as a transcript line and touches nothing —
//!     it lets the parser + planner + driver be exercised end to end with no host,
//!     and is what the tests assert against.
//!   - [`Host`] builds the no-`RUN` subset (`FROM scratch` + `COPY`) entirely on the
//!     host: stage dirs + file copies, exported via virtkit's pure-Rust ext4 builder.
//!   - [`MicroVm`] builds the `FROM <image>` + `RUN` shape: pull/flatten the base with
//!     the OCI client into a bootable ext4 (agent injected, free space for writes),
//!     and run each `RUN` inside a Cloud Hypervisor guest (a rw qcow2 overlay over the
//!     ext4, committed back so writes persist; egress via a `vk switch` so
//!     `apt`/`apk` work; root remounted read-only before teardown so the exported ext4
//!     is clean). Needs KVM + the runtime tools (cloud-hypervisor + the guest kernel).
//!     `COPY --from=<stage>` and `RUN --mount=type=bind,from=<stage>` work by attaching
//!     the source stage's ext4 read-only and copying / bind-mounting inside the guest;
//!     `COPY` from the build context copies from the context shared over virtiofs,
//!     honoring `.dockerignore`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use super::parser::{Cmdline, Copy, Mount};

/// An opaque handle to a stage's working filesystem (a host dir, an overlay, a VM
/// disk — the backend's choice). The label is for diagnostics/transcripts.
#[derive(Debug, Clone)]
pub struct Rootfs {
    pub label: String,
}

/// The mutable per-stage shell state that `ENV`/`WORKDIR`/`USER` accumulate and that
/// each `RUN` (and the exported image config) sees.
#[derive(Debug, Clone, Default)]
pub struct ShellState {
    pub env: Vec<(String, String)>,
    pub workdir: String,
    pub user: String,
}

/// How a `RUN`'s `--mount=…,from=` resolves: the source stage's committed rootfs.
pub struct ResolvedMount<'a> {
    /// The parsed mount (target/source/ro) — read by the microVM backend when it
    /// wires the mount into the guest; the dry-run backend only needs `from`.
    #[allow(dead_code)]
    pub spec: &'a Mount,
    pub from: Option<&'a Rootfs>,
}

// from_image/from_scratch/from_stage take &mut self (they mutate backend state and
// return a handle, not a constructor) — the `from_*` name reads best for "a rootfs
// derived from X", so opt out of the wrong-self-convention lint.
#[allow(clippy::wrong_self_convention)]
pub trait Executor {
    /// A stage based on an external image: pull + flatten to a writable working rootfs
    /// labelled by the stage (so later `--from=<stage>` resolves to it).
    fn from_image(&mut self, stage: &str, image: &str) -> Result<Rootfs>;
    /// The empty base (`FROM scratch`), labelled by the stage.
    fn from_scratch(&mut self, stage: &str) -> Result<Rootfs>;
    /// Fork a prior stage's committed rootfs into a new writable working rootfs for
    /// `stage`.
    fn from_stage(&mut self, stage: &str, parent: &Rootfs) -> Result<Rootfs>;
    /// Pull an external image as a read-only source for `COPY --from=<image>` /
    /// `RUN --mount=…,from=<image>` (not a build stage).
    fn pull(&mut self, image: &str) -> Result<Rootfs>;
    /// Execute a `RUN` over `fs` with the accumulated shell state and resolved mounts.
    fn run(
        &mut self,
        fs: &Rootfs,
        cmd: &Cmdline,
        mounts: &[ResolvedMount<'_>],
        state: &ShellState,
    ) -> Result<()>;
    /// Apply a `COPY` into `fs` (from the build context, or `from`'s committed rootfs).
    fn copy(&mut self, fs: &Rootfs, op: &Copy, from: Option<&Rootfs>) -> Result<()>;

    /// Declare the stages this stage will `COPY --from` / `RUN --mount=from` (their
    /// committed rootfs), before its instructions run, so a backend can attach them
    /// (default: nothing).
    fn stage_sources(&mut self, _sources: &[Rootfs]) -> Result<()> {
        Ok(())
    }

    /// The base image's inherited config (`ENV`/`USER`/`WORKDIR`) for `FROM <image>`,
    /// so a stage's `RUN`s start with the base's environment (default: empty).
    fn base_config(&mut self, _image: &str) -> Result<crate::oci::ImageConfig> {
        Ok(crate::oci::ImageConfig::default())
    }
    /// The base image's manifest digest, for the cache key so a moved tag busts the cache.
    /// `None` (the default, and any resolve failure) keys by the image ref instead. The
    /// microVM backend memoizes the result and reuses it for the base ext4 cache key.
    fn resolve_base_digest(&mut self, _image: &str) -> Option<String> {
        None
    }
    /// Export `fs` as a bootable ext4 image at `out`.
    fn export_ext4(&mut self, fs: &Rootfs, out: &Path) -> Result<()>;

    /// Instruction-level cache (default: no cache). `key` is the chained content hash
    /// up to and including an instruction; the backend stores/loads the resulting
    /// rootfs snapshot keyed by it.
    /// Is a snapshot for `key` available?
    fn cache_has(&mut self, _key: &str) -> bool {
        false
    }
    /// Restore the snapshot keyed `key` as `fs`'s current state.
    fn cache_restore(&mut self, _fs: &Rootfs, _key: &str) -> Result<()> {
        Ok(())
    }
    /// Save `fs`'s current state under `key` (best-effort).
    fn cache_save(&mut self, _fs: &Rootfs, _key: &str) -> Result<()> {
        Ok(())
    }

    /// Finalize a stage once all its instructions have run (default: nothing). The
    /// microVM backend uses this to shut down the stage's long-lived guest, whose writes
    /// are already persisted in the stage image (the booted disk).
    fn stage_end(&mut self, _fs: &Rootfs) -> Result<()> {
        Ok(())
    }
}

/// Records every primitive without doing anything — drives the whole pipeline on any
/// host so the frontend/planner/driver are testable, and doubles as `--dry-run`.
#[derive(Default)]
pub struct DryRun {
    pub transcript: Vec<String>,
}

impl DryRun {
    pub fn new() -> Self {
        Self::default()
    }
    /// Record a transcript line; return a rootfs handle labelled `label`.
    fn emit(&mut self, line: String, label: &str) -> Rootfs {
        self.transcript.push(line);
        Rootfs {
            label: label.to_string(),
        }
    }
}

impl Executor for DryRun {
    fn from_image(&mut self, stage: &str, image: &str) -> Result<Rootfs> {
        Ok(self.emit(format!("from-image {stage} ({image})"), stage))
    }
    fn from_scratch(&mut self, stage: &str) -> Result<Rootfs> {
        Ok(self.emit(format!("from-scratch {stage}"), stage))
    }
    fn from_stage(&mut self, stage: &str, parent: &Rootfs) -> Result<Rootfs> {
        Ok(self.emit(format!("from-stage {stage} (<- {})", parent.label), stage))
    }
    fn pull(&mut self, image: &str) -> Result<Rootfs> {
        let label = format!("image:{image}");
        Ok(self.emit(format!("pull {image}"), &label))
    }
    fn run(
        &mut self,
        _fs: &Rootfs,
        cmd: &Cmdline,
        mounts: &[ResolvedMount<'_>],
        state: &ShellState,
    ) -> Result<()> {
        let froms: Vec<&str> = mounts
            .iter()
            .filter_map(|m| m.from.map(|f| f.label.as_str()))
            .collect();
        self.transcript.push(format!(
            "run [user={} cwd={} mounts_from={:?}] {}",
            state.user,
            state.workdir,
            froms,
            render_cmd(cmd)
        ));
        Ok(())
    }
    fn copy(&mut self, _fs: &Rootfs, op: &Copy, from: Option<&Rootfs>) -> Result<()> {
        self.transcript.push(format!(
            "copy from={} {:?} -> {}",
            from.map(|f| f.label.as_str()).unwrap_or("context"),
            op.sources,
            op.dest
        ));
        Ok(())
    }
    fn export_ext4(&mut self, fs: &Rootfs, out: &Path) -> Result<()> {
        self.transcript
            .push(format!("export-ext4 {} -> {}", fs.label, out.display()));
        Ok(())
    }
}

fn render_cmd(cmd: &Cmdline) -> String {
    match cmd {
        Cmdline::Shell(s) => s.clone(),
        Cmdline::Exec(v) => format!("{v:?}"),
    }
}

/// A non-building backend that answers only the read-only queries the key/scope
/// resolution needs — the base manifest digest and base image config, resolved over the
/// network exactly as a real build does. It never materializes a rootfs, so it lets
/// `docker-hash` compute each stage's cache key (via `resolve_stages`) without pulling,
/// running, or copying anything. Memoizes both lookups so a base shared by several stages
/// is fetched once.
#[derive(Default)]
pub struct Planner {
    digests: HashMap<String, Option<String>>,
    configs: HashMap<String, crate::oci::ImageConfig>,
}

impl Planner {
    pub fn new() -> Self {
        Self::default()
    }
}

// resolve_stages only calls resolve_base_digest + base_config; the materialization
// primitives are unreachable on this backend (it never builds), so they error.
impl Executor for Planner {
    fn resolve_base_digest(&mut self, image: &str) -> Option<String> {
        if let Some(d) = self.digests.get(image) {
            return d.clone();
        }
        let d = match block_on(crate::oci::resolve_digest(image)) {
            Ok(d) => Some(d),
            Err(e) => {
                eprintln!(
                    "virtkit: docker-hash: digest resolve failed for {image} ({e:#}) — keying by ref"
                );
                None
            }
        };
        self.digests.insert(image.to_string(), d.clone());
        d
    }
    fn base_config(&mut self, image: &str) -> Result<crate::oci::ImageConfig> {
        if let Some(c) = self.configs.get(image) {
            return Ok(c.clone());
        }
        let c = block_on(crate::oci::pull_config(image, None, None, None, false))?;
        self.configs.insert(image.to_string(), c.clone());
        Ok(c)
    }
    fn from_image(&mut self, _stage: &str, _image: &str) -> Result<Rootfs> {
        bail!("Planner backend does not materialize stages")
    }
    fn from_scratch(&mut self, _stage: &str) -> Result<Rootfs> {
        bail!("Planner backend does not materialize stages")
    }
    fn from_stage(&mut self, _stage: &str, _parent: &Rootfs) -> Result<Rootfs> {
        bail!("Planner backend does not materialize stages")
    }
    fn pull(&mut self, _image: &str) -> Result<Rootfs> {
        bail!("Planner backend does not materialize stages")
    }
    fn run(
        &mut self,
        _fs: &Rootfs,
        _cmd: &Cmdline,
        _mounts: &[ResolvedMount<'_>],
        _state: &ShellState,
    ) -> Result<()> {
        bail!("Planner backend does not run instructions")
    }
    fn copy(&mut self, _fs: &Rootfs, _op: &Copy, _from: Option<&Rootfs>) -> Result<()> {
        bail!("Planner backend does not run instructions")
    }
    fn export_ext4(&mut self, _fs: &Rootfs, _out: &Path) -> Result<()> {
        bail!("Planner backend does not export")
    }
}

/// The microVM backend: a stage is a bootable ext4 (the OCI base pulled + flattened
/// with the agent injected), `RUN` boots it in a Cloud Hypervisor guest with egress
/// (a `vk switch`) and execs the command — changes persist and the exported ext4
/// is left clean. `COPY` / `RUN --mount=from` are not wired yet, so it builds the
/// `FROM <image>` + `RUN` (+ multi-stage fork) shape. Each stage's ext4 lives under
/// `scratch`.
pub struct MicroVm {
    cloud_hypervisor: PathBuf,
    kernel: PathBuf,
    /// virtkit-agent binary, injected as PID 1 into each stage's ext4 so the guest
    /// can boot and serve the exec channel.
    agent: PathBuf,
    scratch: PathBuf,
    cpus: u32,
    mem: String,
    boot_timeout_secs: u64,
    /// spare free blocks left in each stage's ext4 so RUN steps can write.
    free_blocks: u64,
    /// instruction-cache registry: each instruction's resulting ext4 is pushed here
    /// keyed by its chained content hash, and pulled back on a rebuild hit. The CDC
    /// chunk dedup makes successive snapshots share almost all blobs. `None` = no cache.
    cache: Option<crate::config::Registry>,
    /// stage label → its ext4 image path.
    images: HashMap<String, PathBuf>,
    /// the current stage's long-lived guest (booted on its first RUN, reused for the
    /// rest, committed + torn down by `stage_end`). `None` between stages.
    session: Option<crate::run::VmSession>,
    /// cache key of the last snapshot saved/restored in this stage — the parent a diff
    /// push re-chunks against (only its dirty clusters). Seeded from the base image on
    /// `from_image`; `None` means a full push (no known parent chunks).
    parent_key: Option<String>,
    /// add a journal to the exported image (the build itself stays journal-less).
    journal: bool,
    /// source-stage ext4s to attach read-only (as vdb, vdc, …) to this stage's guest,
    /// for `COPY --from` / `RUN --mount=from`. Set per stage by the driver.
    sources: Vec<PathBuf>,
    /// source stage label → its guest device (e.g. `/dev/vdb`), matching `sources`.
    source_dev: HashMap<String, String>,
    /// build-context dir, shared into each stage's guest over virtiofs for `COPY` from
    /// the context (no `--from`).
    context: PathBuf,
    /// the in-flight cache push (run on a background thread) and the snapshot raw it reads.
    /// At most one runs at a time: it is spawned at the end of an instruction's `cache_save`
    /// and joined at the start of the next one — so the push (chunk + manifest + upload, the
    /// IO-bound bulk of cache-on overhead) overlaps the next instruction's RUN instead of
    /// serializing after it. Its snapshot also serves as the previous baseline the next
    /// instruction's `content_diff` reads, so it is freed only after that join.
    inflight: Option<PushInflight>,
    /// monotonic counter for unique per-instruction snapshot filenames (several may exist
    /// at once: the live one plus the in-flight push's).
    push_seq: u64,
    /// stage label → the cache key of its last pushed snapshot (its committed image). A
    /// `FROM <stage>` fork starts from exactly that image, so its first instruction can
    /// diff against this key instead of a full re-chunk of the whole image.
    stage_last_key: HashMap<String, String>,
    /// the previous diff push's layer list (+ total size), kept in memory so the next
    /// instruction diffs against it without re-fetching+parsing the parent manifest from
    /// the registry every push. `None` at a stage's first instruction (it fetches once) and
    /// after a full push. Reset at stage boundaries.
    parent_layers: Option<(Vec<oci_client::manifest::OciDescriptor>, u64)>,
    /// resolved manifest digest per base image ref, memoized so the cache-key seed and the
    /// base ext4 cache key share one lookup. `Some(None)` = a resolve that failed (key by ref).
    base_digests: HashMap<String, Option<String>>,
}

/// What `cache_save` chunks + uploads in the background. The thread returns the pushed
/// layer list (so the next instruction diffs against it in memory) — `None` for a full
/// push, which has no chainable layers.
type PushOutput = Result<Option<(Vec<oci_client::manifest::OciDescriptor>, u64)>>;

struct PushInflight {
    handle: std::thread::JoinHandle<PushOutput>,
    /// the snapshot raw the push reads; freed after it is joined (and used as the next
    /// instruction's `content_diff` baseline).
    snap: PathBuf,
    /// the instruction key this push caches (recorded as the stage's last key on success).
    key: String,
}

/// How the agent re-invokes its own native mount/umount/copy helpers over the exec
/// channel: `/proc/self/exe` is the running agent binary in the forked child, so it
/// works even though the agent is no longer present anywhere in the image's rootfs.
const GUEST_AGENT: &str = "/proc/self/exe";

/// The byte ranges where `cur` differs from `prev`, examined only within `within` (the
/// regions that could possibly have changed — the stage overlay's cumulative dirty set;
/// outside it both snapshots equal the base). Both are captured overlay qcow2s, read
/// natively (resolving unchanged clusters through their backing). This recovers a single
/// instruction's delta from two consecutive cumulative snapshots, so a diff push re-chunks
/// only what changed (not everything written so far).
fn content_diff(prev: &Path, cur: &Path, within: &[(u64, u64)]) -> Result<Vec<(u64, u64)>> {
    let mut a = crate::qcow2::Qcow2::open(prev)?;
    let mut b = crate::qcow2::Qcow2::open(cur)?;
    const BLK: usize = 256 * 1024; // comparison + dirty-extent granularity
    let mut ba = vec![0u8; BLK];
    let mut bb = vec![0u8; BLK];
    let mut out: Vec<(u64, u64)> = Vec::new();
    for &(off, len) in within {
        let mut pos = off;
        let end = off + len;
        while pos < end {
            let n = ((end - pos) as usize).min(BLK);
            a.read_at(pos, &mut ba[..n])?;
            b.read_at(pos, &mut bb[..n])?;
            if ba[..n] != bb[..n] {
                // coalesce with the previous extent when contiguous.
                match out.last_mut() {
                    Some(last) if last.0 + last.1 == pos => last.1 += n as u64,
                    _ => out.push((pos, n as u64)),
                }
            }
            pos += n as u64;
        }
    }
    Ok(out)
}

/// The Linux disk name for the `n`th virtio-blk device (0 = `vda`, 25 = `vdz`,
/// 26 = `vdaa`, …) — matches the kernel's `disk_name` enumeration order.
fn vd_name(n: usize) -> String {
    let mut n = n + 1;
    let mut s = String::new();
    while n > 0 {
        n -= 1;
        s.insert(0, (b'a' + (n % 26) as u8) as char);
        n /= 26;
    }
    format!("vd{s}")
}

/// Cache repo (under the registry's repo prefix) holding the instruction snapshots.
const CACHE_REPO: &str = "dfcache";

/// Cache tag for a base image's materialized ext4 — `base-<sha256(image ref)>`, in the
/// same `CACHE_REPO` as the instruction snapshots (the `base-` prefix can't collide
/// with the 64-hex chained instruction keys).
fn base_cache_key(image: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"FROM image ");
    h.update(image.as_bytes());
    let mut s = String::from("base-");
    for b in h.finalize() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

impl MicroVm {
    pub fn new(
        cloud_hypervisor: PathBuf,
        kernel: PathBuf,
        agent: PathBuf,
        scratch: PathBuf,
        cache: Option<crate::config::Registry>,
        journal: bool,
        context: PathBuf,
    ) -> Self {
        MicroVm {
            cloud_hypervisor,
            kernel,
            agent,
            scratch,
            cpus: 2,
            mem: "2G".into(),
            boot_timeout_secs: 120,
            // 32 GiB of writable headroom: a real image (full toolchains + large apt
            // installs) writes many GiB into a single stage. The ext4 is sparse and the
            // overlay/push are hole-aware, so the unused capacity costs nothing on disk.
            free_blocks: 32u64 * 1024 * 1024 * 1024 / 4096,
            cache,
            images: HashMap::new(),
            session: None,
            parent_key: None,
            journal,
            sources: Vec::new(),
            source_dev: HashMap::new(),
            context,
            inflight: None,
            push_seq: 0,
            stage_last_key: HashMap::new(),
            parent_layers: None,
            base_digests: HashMap::new(),
        }
    }

    /// Boot this stage's guest (over `fs`'s ext4, with the stage's source disks attached
    /// read-only) if it isn't running yet.
    fn ensure_session(&mut self, fs: &Rootfs) -> Result<()> {
        if self.session.is_none() {
            let ext4 = self.stage_image(fs)?;
            let s = block_on(crate::run::boot_session(
                &self.cloud_hypervisor,
                &self.kernel,
                &self.agent,
                &ext4,
                true,
                self.cpus,
                &self.mem,
                self.boot_timeout_secs,
                &self.sources,
                Some(self.context.as_path()),
            ))?;
            self.session = Some(s);
        }
        Ok(())
    }
    fn image_path(&self, stage: &str) -> PathBuf {
        self.scratch
            .join(format!("{}.ext4", stage.replace(['/', '\\', ':'], "_")))
    }
    fn stage_image(&self, fs: &Rootfs) -> Result<PathBuf> {
        self.images
            .get(&fs.label)
            .cloned()
            .with_context(|| format!("no ext4 for stage {:?}", fs.label))
    }
    fn stage_overlay_path(&self, stage: &str) -> PathBuf {
        self.scratch
            .join(format!("{}.qcow2", stage.replace(['/', '\\', ':'], "_")))
    }
    /// Register a freshly built or pulled raw ext4 `base` as `stage`'s image by wrapping it
    /// in a rw qcow2 overlay — the stage's guest boots that overlay directly and its writes
    /// accumulate into it (no separate boot overlay, no commit). The raw stays as the
    /// overlay's read-only backing; export later flattens the chain.
    fn wrap_base(&mut self, stage: &str, base: &Path) -> Result<()> {
        let overlay = self.stage_overlay_path(stage);
        crate::qcow2::create_overlay(&overlay, base)?;
        self.images.insert(stage.to_string(), overlay);
        Ok(())
    }
    /// Parent layers + total size for the next diff push: the previous push's layers held in
    /// memory, else (a stage's first instruction) fetched once from the registry by parent
    /// key. An empty parent ⇒ the diff push re-chunks the whole image (a full push that still
    /// reads the qcow2 natively and yields layers). Consumes `self.parent_layers`.
    fn parent_for_push(
        &mut self,
        rg: &crate::config::Registry,
        total_size: u64,
    ) -> (Vec<oci_client::manifest::OciDescriptor>, u64) {
        match self.parent_layers.take() {
            Some((l, t)) => (l, t),
            None => match self.parent_key.clone().and_then(|pk| {
                crate::registry::fetch_chunks(rg, CACHE_REPO, &pk)
                    .ok()
                    .flatten()
            }) {
                Some((l, t)) => (l, t),
                None => (Vec::new(), total_size),
            },
        }
    }
    /// Join the in-flight cache push (if any), recording the stage's last key and freeing
    /// the snapshot raw. A barrier the build must cross before a stage's image is reused (a
    /// fork or export) and before exit, so the cache is fully populated.
    fn drain_push(&mut self, label: &str) {
        if let Some(inf) = self.inflight.take() {
            match inf.handle.join().expect("cache push thread panicked") {
                Ok(layers) => {
                    self.parent_layers = layers;
                    self.stage_last_key.insert(label.to_string(), inf.key);
                }
                Err(e) => eprintln!("virtkit: build async push failed ({e:#}) — not cached"),
            }
            let _ = std::fs::remove_file(&inf.snap);
        }
    }
}

impl Drop for MicroVm {
    /// On an error mid-stage the backend can be dropped with a cache push still in flight:
    /// join it so its thread finishes and its snapshot raw is removed, rather than detaching
    /// the thread and leaking the multi-MB capture. (The live `session` cleans its own VM
    /// via `VmSession`'s own `Drop`.)
    fn drop(&mut self) {
        if let Some(inf) = self.inflight.take() {
            let _ = inf.handle.join();
            let _ = std::fs::remove_file(&inf.snap);
        }
    }
}

impl Executor for MicroVm {
    fn from_image(&mut self, stage: &str, image: &str) -> Result<Rootfs> {
        std::fs::create_dir_all(&self.scratch)
            .with_context(|| format!("creating {}", self.scratch.display()))?;
        let ext4 = self.image_path(stage);
        // Base-image ext4 cache: the materialized base (OCI-flattened + agent injected
        // + free headroom) is keyed by the image's manifest digest (resolved + memoized by
        // resolve_base_digest, falling back to the ref) and stored in the cache registry.
        // A repeat build pulls it back instead of re-running the pull/flatten/ext4-build
        // — and, because the base's chunks are now in the store, an instruction snapshot
        // on a cold build dedups its unchanged base region against them, so only the
        // RUN's diff is compressed and uploaded. Digest-keyed so a moved tag is not served
        // a stale base (matching the chain-key seed).
        let base_id = match self.resolve_base_digest(image) {
            Some(d) => format!("{image}@{d}"),
            None => image.to_string(),
        };
        let base_key = base_cache_key(&base_id);
        if let Some(rg) = self.cache.clone()
            && crate::registry::exists(&rg, CACHE_REPO, &base_key)
            && crate::registry::try_pull_ext4(&rg, CACHE_REPO, &base_key, &ext4)?
        {
            println!("virtkit: build base CACHED {image}");
            self.wrap_base(stage, &ext4)?;
            self.parent_key = Some(base_key);
            self.parent_layers = None;
            return Ok(Rootfs {
                label: stage.to_string(),
            });
        }
        // pull + flatten the OCI image to a rootfs tar (no docker), then build a
        // bootable ext4 with the agent injected as PID 1.
        let tar = self
            .scratch
            .join(format!("{}.tar", stage.replace(['/', '\\', ':'], "_")));
        block_on(crate::oci::pull_flatten(
            image, None, None, None, false, &tar,
        ))
        .with_context(|| format!("pulling {image}"))?;
        // Build the base ext4 with free space for the RUN steps to write into
        // (build_from_tar leaves none, which would ENOSPC on the first write). The agent
        // is NOT injected: it boots from the initramfs and pivots into this rootfs, so the
        // image stays clean (no agent binary baked in).
        crate::ext4::build_from_tar_injecting(
            &tar,
            &[],
            self.free_blocks,
            // No journal: the runtime boots a rw overlay over this ext4 (read-only), so
            // the journal is never used — during the build it is dead weight (a 4 MiB
            // circular log rewritten every RUN, so it never dedups and churns every
            // snapshot). Snapshots stay consistent via the fsfreeze quiesce.
            &crate::ext4::FsId {
                with_journal: false,
                ..Default::default()
            },
            &ext4,
        )?;
        let _ = std::fs::remove_file(&tar);
        // Populate the base cache (best-effort: a push failure must not fail the build).
        if let Some(rg) = self.cache.clone() {
            let boot_kind = crate::image::boot_kind_tag(crate::image::BootKind::GenericDisk);
            if let Err(e) = crate::registry::push_ext4(&rg, CACHE_REPO, &base_key, &ext4, boot_kind)
            {
                eprintln!("virtkit: build base cache push of {image} failed ({e:#}) — not cached");
            }
        }
        self.wrap_base(stage, &ext4)?;
        self.parent_key = Some(base_key);
        self.parent_layers = None;
        Ok(Rootfs {
            label: stage.to_string(),
        })
    }
    fn from_scratch(&mut self, stage: &str) -> Result<Rootfs> {
        // `FROM scratch` is an empty base. COPY (from a stage or the context) still needs
        // a guest to drive the copy; the guest's agent boots from the initramfs and pivots
        // into this rootfs, so an empty ext4 is enough — no agent is baked in, leaving the
        // assembled image byte-clean.
        std::fs::create_dir_all(&self.scratch)
            .with_context(|| format!("creating {}", self.scratch.display()))?;
        let ext4 = self.image_path(stage);
        let empty_tar = self.scratch.join(format!(
            "{}-empty.tar",
            stage.replace(['/', '\\', ':'], "_")
        ));
        // A valid empty tar archive is the two 512-byte end-of-archive zero records.
        std::fs::write(&empty_tar, [0u8; 1024])
            .with_context(|| format!("writing {}", empty_tar.display()))?;
        // Generous headroom: scratch pool stages COPY large .deb pools (well over the 1 GiB
        // base default). Sparse, so the extra capacity costs nothing until written.
        let free_blocks = 8u64 * 1024 * 1024 * 1024 / 4096;
        crate::ext4::build_from_tar_injecting(
            &empty_tar,
            &[],
            free_blocks,
            &crate::ext4::FsId {
                with_journal: false,
                ..Default::default()
            },
            &ext4,
        )?;
        let _ = std::fs::remove_file(&empty_tar);
        self.wrap_base(stage, &ext4)?;
        // No cached parent snapshot (the base is empty, built locally); the first COPY
        // here falls back to a full push if caching is enabled.
        self.parent_key = None;
        self.parent_layers = None;
        Ok(Rootfs {
            label: stage.to_string(),
        })
    }
    fn from_stage(&mut self, stage: &str, parent: &Rootfs) -> Result<Rootfs> {
        // COW fork: a qcow2 overlay backed by the parent stage's image (itself a qcow2), so
        // this stage mutates only its own diff while the parent stays immutable (it may also
        // be the base of sibling stages or a COPY --from source). No data copy — instant, and
        // the overlay holds just this stage's writes.
        let src = self.stage_image(parent)?;
        let overlay = self.stage_overlay_path(stage);
        crate::qcow2::create_overlay(&overlay, &src)
            .with_context(|| format!("forking {} -> {}", src.display(), overlay.display()))?;
        self.images.insert(stage.to_string(), overlay);
        // This fork starts from the parent stage's final image, which was cached under
        // the parent's last key — so the first instruction here can diff against it instead
        // of fully re-chunking the whole image. (None if the parent wasn't cached, e.g.
        // caching off → full push.)
        self.parent_key = self.stage_last_key.get(&parent.label).cloned();
        self.parent_layers = None;
        Ok(Rootfs {
            label: stage.to_string(),
        })
    }
    fn pull(&mut self, image: &str) -> Result<Rootfs> {
        bail!("microVM backend: `--from={image}` (external image source) not yet wired")
    }
    fn run(
        &mut self,
        fs: &Rootfs,
        cmd: &Cmdline,
        mounts: &[ResolvedMount<'_>],
        state: &ShellState,
    ) -> Result<()> {
        // Resolve `--mount=type=bind,from=<stage>`: each binds the source stage's
        // `source` subtree at `target` (read-only) for the command's duration.
        // For each mount: an optional (device, scratch mountpoint) to mount first (a
        // cross-stage source), the absolute source to bind from, and the bind target.
        // A `from=<stage>` mount attaches that stage's ext4 read-only; a `from`-less
        // `type=bind` mount binds a subtree of the build context (already virtiofs-mounted
        // at CONTEXT_MOUNT) — the standard `--mount=type=bind,source=/setup.sh,...` idiom.
        // (optional source (device, mountpoint), bind source path, bind target).
        type Bind = (Option<(String, String)>, String, String);
        let mut binds: Vec<Bind> = Vec::new();
        for (i, m) in mounts.iter().enumerate() {
            let source = m.spec.source.clone().unwrap_or_else(|| "/".into());
            let target = m
                .spec
                .target
                .clone()
                .context("RUN --mount=bind requires target=")?;
            match m.from {
                Some(src_fs) => {
                    let dev = self.source_dev.get(&src_fs.label).with_context(|| {
                        format!("RUN --mount from={}: source not attached", src_fs.label)
                    })?;
                    let mp = format!("/mnt/m-{}-{i}", src_fs.label.replace(['/', '\\', ':'], "_"));
                    let bindsrc = format!("{mp}/{}", source.trim_start_matches('/'));
                    binds.push((Some((dev.clone(), mp)), bindsrc, target));
                }
                None if m.spec.typ == "bind" => {
                    let bindsrc = format!(
                        "{}/{}",
                        crate::run::CONTEXT_MOUNT,
                        source.trim_start_matches('/')
                    );
                    binds.push((None, bindsrc, target));
                }
                None => bail!(
                    "microVM RUN --mount type={} without from=<stage> is not supported",
                    m.spec.typ
                ),
            }
        }
        let shell = match cmd {
            Cmdline::Shell(s) => s.clone(),
            Cmdline::Exec(v) => v.join(" "),
        };
        // assemble a /bin/sh script: env exports, cd into WORKDIR, then the command.
        let mut script = String::new();
        for (k, v) in &state.env {
            script.push_str(&format!("export {k}={}; ", shell_single_quote(v)));
        }
        let wd = if state.workdir.is_empty() {
            "/"
        } else {
            &state.workdir
        };
        // WORKDIR creates the directory (as Docker does), so `cd` into a not-yet-existing
        // workdir succeeds; best-effort so a non-root RUN over an existing dir still runs.
        let q = shell_single_quote(wd);
        script.push_str(&format!("mkdir -p {q} 2>/dev/null; cd {q} && {shell}"));
        let argv = vec!["sh".to_string(), "-c".to_string(), script];
        let user = match state.user.as_str() {
            "" | "root" => None,
            u => Some(u.to_string()),
        };
        // Boot the stage's guest once (on the first RUN/COPY) and reuse it for the rest
        // — one VM per stage, not per RUN.
        self.ensure_session(fs)?;
        let session = self.session.as_ref().expect("session booted");
        // Set up the bind mounts: mount each source device read-only, then bind its
        // subtree at the target.
        for (device, bindsrc, target) in &binds {
            if let Some((dev, mp)) = device {
                let m1 = [
                    GUEST_AGENT.to_string(),
                    "mount".into(),
                    "--ro".into(),
                    dev.clone(),
                    mp.clone(),
                ];
                if block_on(session.exec(&m1, None))? != 0 {
                    bail!("RUN --mount: mounting source device {dev} failed");
                }
            }
            let m2 = [
                GUEST_AGENT.to_string(),
                "mount".into(),
                "--bind".into(),
                bindsrc.clone(),
                target.clone(),
            ];
            if block_on(session.exec(&m2, None))? != 0 {
                bail!("RUN --mount: bind-mounting {bindsrc} at {target} failed");
            }
        }
        let code = block_on(session.exec(&argv, user))?;
        // Tear the mounts down (target before its device mountpoint), best-effort.
        for (device, _, target) in binds.iter().rev() {
            let _ = block_on(session.exec(
                &[GUEST_AGENT.to_string(), "umount".into(), target.clone()],
                None,
            ));
            if let Some((_, mp)) = device {
                let _ = block_on(session.exec(
                    &[GUEST_AGENT.to_string(), "umount".into(), mp.clone()],
                    None,
                ));
            }
        }
        if code != 0 {
            bail!("RUN exited {code}: {shell}");
        }
        Ok(())
    }
    fn copy(&mut self, fs: &Rootfs, op: &Copy, from: Option<&Rootfs>) -> Result<()> {
        self.ensure_session(fs)?;
        // The source tree lives at `root` in the guest: a `--from` stage is mounted
        // read-only from its attached device; the build context is already mounted (over
        // virtiofs) at CONTEXT_MOUNT by the agent at boot.
        let (root, mount): (String, Option<String>) = match from {
            Some(src) => {
                let dev = self
                    .source_dev
                    .get(&src.label)
                    .with_context(|| {
                        format!(
                            "COPY --from={}: source not attached to this stage",
                            src.label
                        )
                    })?
                    .clone();
                let mp = format!("/mnt/src-{}", src.label.replace(['/', '\\', ':'], "_"));
                let session = self.session.as_ref().expect("session booted");
                let m = [
                    GUEST_AGENT.to_string(),
                    "mount".into(),
                    "--ro".into(),
                    dev,
                    mp.clone(),
                ];
                if block_on(session.exec(&m, None))? != 0 {
                    bail!("mounting source {} for COPY failed", src.label);
                }
                (mp.clone(), Some(mp))
            }
            None => (crate::run::CONTEXT_MOUNT.to_string(), None),
        };
        let session = self.session.as_ref().expect("session booted");
        // agent copy [--chown u:g] [--chmod OCTAL] [--ignore-root R] <root>/<src>... <dst>
        let mut argv = vec![GUEST_AGENT.to_string(), "copy".to_string()];
        if from.is_none() {
            // context COPY: apply the context's .dockerignore.
            argv.push("--ignore-root".into());
            argv.push(root.clone());
        }
        if let Some(c) = &op.chown {
            argv.push("--chown".into());
            argv.push(c.clone());
        }
        if let Some(c) = &op.chmod {
            argv.push("--chmod".into());
            argv.push(c.clone());
        }
        for s in &op.sources {
            // normalise so `.` / `./x` / `/x` all resolve cleanly under `root` (a stray
            // `./` component would break .dockerignore's relative-path matching).
            let rel = s.trim_start_matches('/');
            let rel = rel.strip_prefix("./").unwrap_or(rel);
            if rel.is_empty() || rel == "." {
                argv.push(root.clone());
            } else {
                argv.push(format!("{root}/{rel}"));
            }
        }
        argv.push(op.dest.clone());
        let code = block_on(session.exec(&argv, None))?;
        if let Some(mp) = mount {
            let _ = block_on(session.exec(&[GUEST_AGENT.to_string(), "umount".into(), mp], None));
        }
        if code != 0 {
            let src = from.map_or("context", |f| f.label.as_str());
            bail!("COPY from {src} {:?} -> {} failed", op.sources, op.dest);
        }
        Ok(())
    }
    fn export_ext4(&mut self, fs: &Rootfs, out: &Path) -> Result<()> {
        let image = self.stage_image(fs)?;
        // Warm-rebuild fast path: a fully-cached stage is a restored raw ext4 wrapped in an
        // empty overlay (never booted, so no writes of its own). Its content IS the backing
        // raw, so move that out (a rename on the same fs) instead of flattening a full copy.
        let moved = crate::qcow2::Qcow2::open(&image)?
            .empty_raw_backing()?
            .filter(|raw| std::fs::rename(raw, out).is_ok())
            .is_some();
        if !moved {
            // Otherwise flatten the qcow2 overlay chain natively into a raw ext4 (a base ext4
            // plus the stage's CoW layers; sparse, like qemu-img convert).
            crate::qcow2::flatten_to_raw(&image, out)
                .with_context(|| format!("exporting {} -> {}", image.display(), out.display()))?;
        }
        self.images.remove(&fs.label);
        // Zero the superblock's volatile bookkeeping (write/mount/check times + the
        // kbytes-written/mount counters) so the artifact is deterministic: a cache-restored
        // (warm) build and a cold build are byte-identical, and rebuilds are reproducible.
        crate::ext4::normalize_superblock(out)?;
        // The build is journal-less (a journal is dead weight under the rw-overlay
        // runtime and churns every snapshot). Optionally add one to the exported
        // artifact, natively, so a consumer that mounts it read-write directly recovers.
        if self.journal {
            crate::ext4::add_journal(out)?;
        }
        Ok(())
    }

    fn cache_has(&mut self, key: &str) -> bool {
        match &self.cache {
            Some(rg) => crate::registry::exists(rg, CACHE_REPO, key),
            None => false,
        }
    }
    fn cache_restore(&mut self, fs: &Rootfs, key: &str) -> Result<()> {
        let Some(rg) = self.cache.clone() else {
            bail!("cache_restore with no cache registry");
        };
        // pull the snapshot's ext4 (chunk-cached, byte-exact), then wrap it in a rw qcow2 so
        // any remaining instructions can boot it directly and write into the overlay.
        let ext4 = self.image_path(&fs.label);
        if !crate::registry::try_pull_ext4(&rg, CACHE_REPO, key, &ext4)? {
            bail!("cached instruction {key} vanished from the registry");
        }
        self.wrap_base(&fs.label, &ext4)?;
        // the restored snapshot is the parent the next save diffs against.
        self.parent_key = Some(key.to_string());
        Ok(())
    }
    fn cache_save(&mut self, fs: &Rootfs, key: &str) -> Result<()> {
        let Some(rg) = self.cache.clone() else {
            return Ok(());
        };
        let boot_kind =
            crate::image::boot_kind_tag(crate::image::BootKind::GenericDisk).to_string();

        // No live guest (rare: a metadata-only instruction never booted a VM). The static
        // stage image is a stable qcow2, so push it synchronously — read natively and deduped
        // against the parent chain, like the live path below but with the image as its own
        // capture (no freeze/copy needed).
        if self.session.is_none() {
            let img = self.stage_image(fs)?;
            let (cumulative, total_size) = {
                let mut q = crate::qcow2::Qcow2::open(&img)?;
                (q.data_extents()?, q.virtual_size())
            };
            let (parent_layers, parent_total) = self.parent_for_push(&rg, total_size);
            match crate::registry::push_ext4_diff(
                &rg,
                CACHE_REPO,
                key,
                &img,
                &boot_kind,
                parent_total,
                &cumulative,
                &parent_layers,
            ) {
                Ok(layers) => {
                    self.parent_layers = Some(layers);
                    self.stage_last_key
                        .insert(fs.label.clone(), key.to_string());
                }
                Err(e) => {
                    eprintln!("virtkit: build cache push of {key} failed ({e:#}) — not cached");
                    self.parent_layers = None;
                }
            }
            self.parent_key = Some(key.to_string());
            return Ok(());
        }

        // Capture a consistent point-in-time copy of the live overlay (freeze + copy, to a
        // qcow2). This is the only synchronous part — the live overlay keeps moving as the
        // next RUN starts, so the copy must happen now; flatten/diff/push read the qcow2
        // natively, off this thread. (Session borrow scoped so the `&mut self` below is free.)
        self.push_seq += 1;
        let snap = self.image_path(&format!("{}.{}.cap.qcow2", fs.label, self.push_seq));
        block_on(
            self.session
                .as_ref()
                .expect("session present")
                .capture(&snap),
        )?;
        // Native qcow2 read: the overlay's own clusters (cumulative dirty) + its size.
        let (cumulative, total_size) = {
            let mut q = crate::qcow2::Qcow2::open(&snap)?;
            (q.data_extents()?, q.virtual_size())
        };
        // Per-instruction delta: diff this capture against the previous one (the in-flight
        // push's qcow2) within the cumulative bound — the overlay is cumulative, so this
        // recovers just what this instruction changed.
        let dirty = match &self.inflight {
            Some(inf) => content_diff(&inf.snap, &snap, &cumulative)?,
            None => cumulative,
        };

        // Reap the previous push (it ran during this instruction's RUN + capture, so it is
        // usually already done): harvest its layers as the in-memory parent and free its
        // capture — content_diff above was its last reader.
        if let Some(inf) = self.inflight.take() {
            match inf.handle.join().expect("cache push thread panicked") {
                Ok(layers) => {
                    self.parent_layers = layers;
                    self.stage_last_key.insert(fs.label.clone(), inf.key);
                }
                Err(e) => {
                    eprintln!("virtkit: build async push failed ({e:#}) — not cached");
                    self.parent_layers = None;
                }
            }
            let _ = std::fs::remove_file(&inf.snap);
        }

        let (parent_layers, parent_total) = self.parent_for_push(&rg, total_size);

        // Spawn the push on a background thread; it overlaps the next instruction's RUN. Only
        // one runs at a time (joined above before the next is spawned), so the parent-layer
        // chain stays ordered and the registry sees one writer.
        let snap_push = snap.clone();
        let key_s = key.to_string();
        let handle = std::thread::spawn(move || -> PushOutput {
            let t = std::time::Instant::now();
            let layers = crate::registry::push_ext4_diff(
                &rg,
                CACHE_REPO,
                &key_s,
                &snap_push,
                &boot_kind,
                parent_total,
                &dirty,
                &parent_layers,
            )?;
            crate::run::tlog("cache.push", t);
            Ok(Some(layers))
        });
        self.inflight = Some(PushInflight {
            handle,
            snap,
            key: key.to_string(),
        });
        self.parent_key = Some(key.to_string());
        Ok(())
    }

    fn base_config(&mut self, image: &str) -> Result<crate::oci::ImageConfig> {
        block_on(crate::oci::pull_config(image, None, None, None, false))
    }

    fn resolve_base_digest(&mut self, image: &str) -> Option<String> {
        if let Some(d) = self.base_digests.get(image) {
            return d.clone();
        }
        let d = match block_on(crate::oci::resolve_digest(image)) {
            Ok(d) => Some(d),
            Err(e) => {
                eprintln!(
                    "virtkit: build: digest resolve failed for {image} ({e:#}) — keying by ref"
                );
                None
            }
        };
        self.base_digests.insert(image.to_string(), d.clone());
        d
    }

    fn stage_sources(&mut self, sources: &[Rootfs]) -> Result<()> {
        // Resolve each source stage to its ext4 and assign it the next guest device
        // (vdb, vdc, …); the session for this stage boots with these attached read-only.
        self.sources.clear();
        self.source_dev.clear();
        for (i, s) in sources.iter().enumerate() {
            self.sources.push(self.stage_image(s)?);
            self.source_dev
                .insert(s.label.clone(), format!("/dev/{}", vd_name(i + 1)));
        }
        Ok(())
    }

    fn stage_end(&mut self, fs: &Rootfs) -> Result<()> {
        // Barrier: finish the stage's last cache push before its image is reused (a fork or
        // export) or the build exits — so the cache is fully populated.
        self.drain_push(&fs.label);
        // Shut the stage's guest down cleanly; its writes are already in the stage image
        // (the booted disk), so later stages / the export see them with no commit step.
        if let Some(session) = self.session.take() {
            block_on(session.finish())?;
        }
        // the next stage starts a fresh cache lineage; clear its attached sources and the
        // in-memory parent layers.
        self.parent_key = None;
        self.parent_layers = None;
        self.sources.clear();
        self.source_dev.clear();
        Ok(())
    }
}

/// Single-quote a value for a `/bin/sh` script (wrap in `'…'`, escaping embedded `'`).
fn shell_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Drive an async future to completion from a sync context, even when already inside a
/// tokio runtime (the CLI's async main): run it on a dedicated thread with its own
/// runtime — a nested `block_on` on the calling thread would panic. Mirrors
/// `registry::block_on`.
fn block_on<F>(fut: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    std::thread::scope(|s| {
        s.spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("building the build tokio runtime")
                .block_on(fut)
        })
        .join()
        .expect("the build runtime thread panicked")
    })
}

/// Host backend for the no-`RUN` subset (`FROM scratch` + `COPY`): each stage is a
/// real host directory, `COPY` is a host-side file copy, and the export is virtkit's
/// own pure-Rust ext4 builder ([`crate::ext4::build_from_dir`]) — no docker, no
/// buildkit, no `mke2fs`, no VM. `RUN` and `FROM <image>` need the microVM/OCI path
/// and error here. This is the end-to-end "Dockerfile → ext4 with only virtkit" PoC.
pub struct Host {
    /// Scratch root holding each stage's directory (`<scratch>/<stage>`).
    scratch: PathBuf,
    /// Build context root that `COPY <src>` (no `--from`) resolves against.
    context: PathBuf,
    /// stage label → its host directory.
    dirs: HashMap<String, PathBuf>,
}

impl Host {
    pub fn new(context: PathBuf, scratch: PathBuf) -> Self {
        Host {
            scratch,
            context,
            dirs: HashMap::new(),
        }
    }
    fn stage_dir(&self, fs: &Rootfs) -> Result<PathBuf> {
        self.dirs
            .get(&fs.label)
            .cloned()
            .with_context(|| format!("no host dir for stage {:?}", fs.label))
    }
    fn fresh_dir(&mut self, stage: &str) -> Result<Rootfs> {
        let dir = self.scratch.join(stage.replace(['/', '\\', ':'], "_"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        self.dirs.insert(stage.to_string(), dir);
        Ok(Rootfs {
            label: stage.to_string(),
        })
    }
}

impl Executor for Host {
    fn from_image(&mut self, _stage: &str, image: &str) -> Result<Rootfs> {
        bail!(
            "host PoC builds only `FROM scratch`; base image {image:?} needs the OCI/microVM path"
        )
    }
    fn from_scratch(&mut self, stage: &str) -> Result<Rootfs> {
        self.fresh_dir(stage)
    }
    fn from_stage(&mut self, stage: &str, parent: &Rootfs) -> Result<Rootfs> {
        let parent_dir = self.stage_dir(parent)?;
        let fs = self.fresh_dir(stage)?;
        let dir = self.stage_dir(&fs)?;
        copy_tree(&parent_dir, &dir)?; // fork: copy the parent stage's tree
        Ok(fs)
    }
    fn pull(&mut self, image: &str) -> Result<Rootfs> {
        bail!("host PoC: `--from={image}` (external image) needs the OCI path")
    }
    fn run(
        &mut self,
        _fs: &Rootfs,
        cmd: &Cmdline,
        _mounts: &[ResolvedMount<'_>],
        _state: &ShellState,
    ) -> Result<()> {
        bail!(
            "host PoC does not execute RUN ({}) — that needs the microVM executor",
            render_cmd(cmd)
        )
    }
    fn copy(&mut self, fs: &Rootfs, op: &Copy, from: Option<&Rootfs>) -> Result<()> {
        let src_root = match from {
            Some(r) => self.stage_dir(r)?,
            None => self.context.clone(),
        };
        let dest_root = self.stage_dir(fs)?;
        // dest is relative to the rootfs root; a trailing '/' or multiple sources mean
        // dest is a directory. (Simplified Docker COPY semantics — see module status.)
        let dest = dest_root.join(op.dest.trim_start_matches('/'));
        let dest_is_dir = op.dest.ends_with('/') || op.sources.len() > 1;
        for s in &op.sources {
            let src = src_root.join(s.trim_start_matches("./"));
            if src.is_dir() {
                // Docker copies the *contents* of a directory source into dest.
                std::fs::create_dir_all(&dest)
                    .with_context(|| format!("creating {}", dest.display()))?;
                copy_tree(&src, &dest)?;
            } else {
                let target = if dest_is_dir {
                    dest.join(src.file_name().context("COPY source has no file name")?)
                } else {
                    dest.clone()
                };
                if let Some(p) = target.parent() {
                    std::fs::create_dir_all(p)
                        .with_context(|| format!("creating {}", p.display()))?;
                }
                std::fs::copy(&src, &target)
                    .with_context(|| format!("copy {} -> {}", src.display(), target.display()))?;
            }
        }
        Ok(())
    }
    fn export_ext4(&mut self, fs: &Rootfs, out: &Path) -> Result<()> {
        let dir = self.stage_dir(fs)?;
        crate::ext4::build_from_dir(&dir, out)
    }
}

/// Recursively copy the *contents* of `src` into `dst` (files, dirs, symlinks).
fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    for entry in std::fs::read_dir(src).with_context(|| format!("reading {}", src.display()))? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_dir() {
            std::fs::create_dir_all(&to)?;
            copy_tree(&from, &to)?;
        } else if ft.is_symlink() {
            let target = std::fs::read_link(&from)?;
            let _ = std::fs::remove_file(&to);
            std::os::unix::fs::symlink(&target, &to)?;
        } else {
            std::fs::copy(&from, &to)
                .with_context(|| format!("copy {} -> {}", from.display(), to.display()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dryrun_records_primitives() {
        let mut ex = DryRun::new();
        let base = ex.from_image("build", "debian:bookworm").unwrap();
        assert_eq!(base.label, "build");
        ex.run(
            &base,
            &Cmdline::Shell("apt-get update".into()),
            &[],
            &ShellState {
                user: "root".into(),
                workdir: "/".into(),
                env: vec![],
            },
        )
        .unwrap();
        ex.export_ext4(&base, Path::new("/tmp/out.ext4")).unwrap();
        assert_eq!(ex.transcript[0], "from-image build (debian:bookworm)");
        assert!(ex.transcript[1].contains("apt-get update"));
        assert!(ex.transcript[2].starts_with("export-ext4"));
    }

    #[test]
    fn host_builds_a_real_ext4_from_scratch_and_copy() {
        // exercises the actual "Dockerfile → ext4 with only virtkit" path: a scratch
        // stage + a COPY, exported via crate::ext4. No docker/buildkit/mke2fs/VM.
        let tmp = std::env::temp_dir().join(format!("vk-build-host-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let ctx = tmp.join("ctx");
        std::fs::create_dir_all(&ctx).unwrap();
        std::fs::write(ctx.join("hello.txt"), b"hi from virtkit").unwrap();

        let mut h = Host::new(ctx, tmp.join("scratch"));
        let fs = h.from_scratch("s").unwrap();
        let op = Copy {
            sources: vec!["hello.txt".into()],
            dest: "/hello.txt".into(),
            from: None,
            chown: None,
            chmod: None,
            link: false,
        };
        h.copy(&fs, &op, None).unwrap();
        let out = tmp.join("out.ext4");
        h.export_ext4(&fs, &out).unwrap();

        let bytes = std::fs::read(&out).unwrap();
        assert!(bytes.len() > 4096, "ext4 image should be non-trivial");
        // ext4 superblock magic 0xEF53 (LE) at byte offset 0x438.
        assert_eq!(&bytes[0x438..0x43a], &[0x53, 0xEF], "ext4 superblock magic");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
