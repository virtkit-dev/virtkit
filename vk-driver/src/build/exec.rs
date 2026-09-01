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
//!     and run each `RUN` inside a microVM guest (a rw qcow2 overlay over the
//!     ext4, committed back so writes persist; egress via a `vk switch` so
//!     `apt`/`apk` work; root remounted read-only before teardown so the exported ext4
//!     is clean). Needs KVM; the VMM is the embedded libkrun by default (or an external
//!     cloud-hypervisor when `VIRTKIT_VMM=cloud-hypervisor`), plus the guest kernel.
//!     `COPY --from=<stage>` and `RUN --mount=type=bind,from=<stage>` work by attaching
//!     the source stage's ext4 read-only and copying / bind-mounting inside the guest;
//!     `COPY` from the build context copies from the context shared over virtiofs,
//!     honoring `.dockerignore`.

use std::collections::{BTreeMap, HashMap};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use anyhow::{Context, Result, bail};
use tokio_util::sync::CancellationToken;

use super::Ns;
use super::parser::{Cmdline, Copy, Mount};
use crate::blockrt::block_on;
use crate::timing::Timings;

/// An opaque handle to a stage's working filesystem (a host dir, an overlay, a VM
/// disk — the backend's choice). The label is for diagnostics/transcripts.
#[derive(Debug, Clone)]
pub struct Rootfs {
    pub label: String,
}

/// The mutable per-stage shell state that `ENV`/`WORKDIR`/`USER` (and, for the
/// exported runtime config, `ENTRYPOINT`/`CMD`/`EXPOSE`) accumulate and that each `RUN` — and
/// the exported image's runtime-config sidecar — sees. Seeded from the base image's
/// OCI config (or the parent stage's final state) so the values survive RUN-less
/// stages exactly as they would in Docker.
#[derive(Debug, Clone, Default)]
pub struct ShellState {
    pub env: Vec<(String, String)>,
    pub workdir: String,
    pub user: String,
    /// Entrypoint argv (shell form already wrapped as `/bin/sh -c`).
    pub entrypoint: Vec<String>,
    /// Default arguments appended to the entrypoint.
    pub cmd: Vec<String>,
    /// TCP ports the stage's `EXPOSE`s declare, on top of the ones its base image did — what a
    /// service built from a Dockerfile gates its readiness on, as a pulled one gates on the
    /// `ExposedPorts` of its OCI config.
    pub exposed_ports: Vec<u16>,
    /// In-scope `ARG` values, exported into a `RUN`'s shell environment so `$VAR` resolves
    /// there (Docker leaves a RUN command to the shell). Build-time only — `ENV` already
    /// lives in `env`, and this is not part of the exported runtime config. Set per RUN
    /// step by the resolver; empty otherwise.
    pub build_args: Vec<(String, String)>,
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
    /// Materialize the named build context `name` (`--build-context <name>=<dir>`) as a
    /// read-only source labelled `context/<name>`, so `COPY --from=<name>` /
    /// `RUN --mount=…,from=<name>` read the host directory `dir` — files outside the
    /// stage's own build context. Under the microVM backend a `COPY` from it honours the
    /// directory's own `.dockerignore`, as a context COPY does; a `RUN --mount=type=bind` from
    /// it sees the unfiltered tree, as it does for the stage's own context. Default: unsupported.
    fn context_source(&mut self, _name: &str, _dir: &Path) -> Result<Rootfs> {
        bail!("this backend does not support named build contexts")
    }
    /// Size the guest for the stage about to be built (`# vk: mem=…` above its `FROM`),
    /// before it is admitted or booted. Called for every stage, so an unset field must
    /// restore the build-wide default rather than keep the last stage's. No-op for a
    /// backend that boots no guest.
    fn set_stage_guest(&mut self, _hint: &super::parser::GuestHint) {}
    /// Guest RAM reserved before this backend starts a stage, in MiB.
    ///
    /// Guest-less backends return `None` and bypass memory admission.
    fn stage_mem_mib(&self) -> Option<u64> {
        None
    }
    /// Execute a `RUN` over `fs` with the accumulated shell state and resolved mounts.
    fn run(
        &mut self,
        fs: &Rootfs,
        cmd: &Cmdline,
        mounts: &[ResolvedMount<'_>],
        state: &ShellState,
    ) -> Result<()>;
    /// Apply a `COPY` into `fs` (from the build context, or `from`'s committed rootfs).
    /// `workdir` is the active `WORKDIR`, against which a relative destination resolves
    /// (Docker semantics).
    fn copy(&mut self, fs: &Rootfs, op: &Copy, from: Option<&Rootfs>, workdir: &str) -> Result<()>;

    /// Declare a stage's inputs before its instructions run: the stages it will
    /// `COPY --from` / `RUN --mount=from` (their committed rootfs), and its build
    /// context (what `COPY` without `--from` resolves against — per stage, since each
    /// stage copies from the context of the Dockerfile that declared it). A backend
    /// attaches/mounts them here (default: nothing).
    fn stage_sources(&mut self, _sources: &[Rootfs], _context: &Path) -> Result<()> {
        Ok(())
    }

    /// The base image's inherited config (`ENV`/`USER`/`WORKDIR`) for `FROM <image>`,
    /// so a stage's `RUN`s start with the base's environment (default: empty).
    fn base_config(&mut self, _image: &str) -> Result<crate::oci::ImageConfig> {
        Ok(crate::oci::ImageConfig::default())
    }
    /// The base image's manifest digest, for the cache key so a moved tag busts the cache.
    /// `None` (the default, and any resolve failure) keys by the image ref instead. The real
    /// backends share one process-wide memo ([`base_digest`]), so every key a process computes
    /// resolves a given base once and agrees on the answer.
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

    /// Acquire a cross-runner build-once lock on `key` (a stage's final content hash) when
    /// the cache is a remote vk-registry offering a lock endpoint, so peers building the
    /// same stage don't duplicate it. `None` = uncoordinated (local cache, no cache, or the
    /// registry has no lock). The guard releases on drop. `on_wait` is called once with the
    /// current holder's identity if the lock is contended, before parking. Default: no lock.
    fn build_lock(
        &mut self,
        _key: &str,
        _on_wait: &mut dyn FnMut(&str),
    ) -> Option<crate::registry::BuildLock> {
        None
    }

    /// Did `key` (a stage's final content hash) already fail to build earlier in this same
    /// CI pipeline? A backend backed by a remote vk-registry checks its failure memo;
    /// default: never (no memoized failure — local cache, no cache, or outside CI).
    fn check_build_failure(&mut self, _key: &str) -> Option<vk_registry::FailInfo> {
        None
    }
    /// Record that `key` just failed to build, so a peer in this same pipeline — another
    /// job needing the same content-key, or this job's own runner-level retry — fails fast
    /// instead of repeating the same doomed build. Default: nowhere to record it.
    fn report_build_failure(&mut self, _key: &str, _reason: &str) {}

    /// Finalize a stage once all its instructions have run (default: nothing). The
    /// microVM backend uses this to shut down the stage's long-lived guest, whose writes
    /// are already persisted in the stage image (the booted disk). `final_key` is the
    /// stage's last content key, so a backend that changes the image while shutting down
    /// can re-cache it under the key a later build will restore — and under no other.
    fn stage_end(&mut self, _fs: &Rootfs, _final_key: Option<&str>) -> Result<()> {
        Ok(())
    }

    /// Route this stage's guest command output through `sink` (the build progress
    /// reporter, which line-buffers + stage-prefixes it). Default: ignored — only the
    /// microVM backend runs guests that produce output.
    fn set_output_sink(&mut self, _sink: crate::executor::OutputSink) {}

    /// Give this stage the build-wide cancellation token so a RUN executing in its guest
    /// is interrupted when another stage fails. Default: ignored — only the microVM
    /// backend boots guests that a cancellation can interrupt.
    fn set_cancel(&mut self, _cancel: CancellationToken) {}

    /// Declare whether this stage runs its RUNs on the base image's own kernel
    /// (`FROM --kernel=image`) rather than vk's embedded build kernel. Called at stage
    /// begin, before the first boot. Default: ignored — only the microVM backend boots.
    fn stage_kernel(&mut self, _image_kernel: bool) {}
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
        let label = image_source_label(image);
        Ok(self.emit(format!("pull {image}"), &label))
    }
    fn context_source(&mut self, name: &str, dir: &Path) -> Result<Rootfs> {
        let label = context_source_label(name);
        Ok(self.emit(format!("context-source {name} ({})", dir.display()), &label))
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
    fn copy(
        &mut self,
        _fs: &Rootfs,
        op: &Copy,
        from: Option<&Rootfs>,
        workdir: &str,
    ) -> Result<()> {
        self.transcript.push(format!(
            "copy from={} {:?} -> {}",
            from.map(|f| f.label.as_str()).unwrap_or("context"),
            op.sources,
            resolve_copy_dest(&op.dest, workdir)
        ));
        Ok(())
    }
    fn stage_sources(&mut self, sources: &[Rootfs], context: &Path) -> Result<()> {
        // The declaration itself, not just its effect: a real backend can only attach a source
        // it was told about before the boot, so a test has to be able to see what was declared.
        let labels: Vec<&str> = sources.iter().map(|s| s.label.as_str()).collect();
        self.transcript.push(format!("stage-sources {labels:?}"));
        self.transcript
            .push(format!("stage-context {}", context.display()));
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

/// Base-image manifest digests this process has resolved. Process-wide rather than per
/// executor because one `build:` unit is keyed several times over — addressed, built, and
/// re-checked by `vk list --stale` — each through a fresh [`Planner`], and a tag-pinned base
/// costs a live registry request every time. Consistency matters more than the requests: a
/// failed resolve keys the stage by the bare ref instead (see `super::resolve_stages`), and
/// `ensure::ensure_build_tier` names a tier dir from one computation's key while the build
/// stamps the ext4 with its own — so two that disagreed about whether the registry answered
/// leave an entry no freshness check can accept, rebuilt from scratch on every start.
///
/// A failure is therefore memoized like an answer, and that is what agreement costs: one
/// unreachable registry keys everything by ref for the rest of the process, so
/// `--require-cached` keeps refusing and a ref-keyed entry an earlier outage left behind is
/// taken as fresh. A loud, consistent miss beats a split cache. `BTreeMap` because
/// `HashMap::new` is not `const`, so it cannot initialize a `static`.
static BASE_DIGESTS: Mutex<BTreeMap<String, Option<String>>> = Mutex::new(BTreeMap::new());

/// The manifest digest for `image`, resolved once per process. `None` — including any resolve
/// failure — means the caller keys by the bare image ref.
fn base_digest(image: &str) -> Option<String> {
    memoized_digest(image, || {
        match block_on(crate::oci::resolve_digest(image)) {
            Ok(d) => Some(d),
            Err(e) => {
                eprintln!("virtkit: digest resolve failed for {image} ({e:#}) — keying by ref");
                None
            }
        }
    })
}

/// [`base_digest`] without the registry: look `image` up in the memo and call `resolve` only
/// on a miss. Split out so a test can prove the memoization — including that a failure is
/// remembered — without a network.
fn memoized_digest(image: &str, resolve: impl FnOnce() -> Option<String>) -> Option<String> {
    // Recovering a poisoned guard rather than propagating: `resolve` runs outside the lock and
    // is the only thing here that can panic, so a poisoned guard still hands back an intact map.
    if let Some(d) = BASE_DIGESTS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(image)
        .cloned()
    {
        return d;
    }
    let d = resolve();
    // Resolved outside the lock: `oci::resolve_digest` carries no timeout, and holding it would
    // stall every other base in the process behind one unreachable registry. The first answer
    // stored wins, so two threads racing the same base still return the same one.
    BASE_DIGESTS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(image.to_string())
        .or_insert(d)
        .clone()
}

/// A non-building backend that answers only the read-only queries the key/scope resolution
/// needs — the base manifest digest and base image config, resolved over the network exactly
/// as a real build does. It never materializes a rootfs, so it lets
/// `docker-hash` compute each stage's cache key (via `resolve_stages`) without pulling,
/// running, or copying anything. Memoizes the base config it pulls, so a base shared by
/// several stages is fetched once; the digest memo behind [`base_digest`] outlives it.
#[derive(Default)]
pub struct Planner {
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
        base_digest(image)
    }
    fn base_config(&mut self, image: &str) -> Result<crate::oci::ImageConfig> {
        if let Some(c) = self.configs.get(image) {
            return Ok(c.clone());
        }
        let c = block_on(crate::oci::pull_config(
            image,
            &crate::oci::Creds::anonymous(),
        ))?;
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
    fn copy(
        &mut self,
        _fs: &Rootfs,
        _op: &Copy,
        _from: Option<&Rootfs>,
        _workdir: &str,
    ) -> Result<()> {
        bail!("Planner backend does not run instructions")
    }
    fn export_ext4(&mut self, _fs: &Rootfs, _out: &Path) -> Result<()> {
        bail!("Planner backend does not export")
    }
}

/// The microVM backend: a stage is a bootable ext4 (the OCI base pulled + flattened; the agent
/// rides the initramfs and is never baked in), `RUN` boots it in a microVM guest with egress
/// per the build's [`BuildNet`](crate::build::BuildNet) policy (a `vk switch`,
/// unrestricted by default) and execs the command — changes persist and the exported ext4
/// is left clean. A `COPY` / `RUN --mount=from` source — another stage or an external image —
/// is attached read-only as its own disk for the instructions that read it. Each stage's ext4
/// lives under `scratch`.
pub struct MicroVm {
    cloud_hypervisor: PathBuf,
    kernel: PathBuf,
    /// virtkit-agent binary, injected as PID 1 into each stage's ext4 so the guest
    /// can boot and serve the exec channel.
    agent: PathBuf,
    scratch: PathBuf,
    /// The current stage's guest size — the build-wide default, or what its `# vk:` line
    /// asked for ([`Executor::set_stage_guest`]).
    cpus: u32,
    mem: String,
    /// The build-wide `[build] cpus` / `[build] mem`, kept so a stage with no hint (or a
    /// hint that sets only one of the two) goes back to them rather than inheriting the
    /// last stage's size.
    build_cpus: u32,
    build_mem: String,
    boot_timeout_secs: u64,
    /// `--debug`: e2fsck each stage snapshot as it crosses the cache (after a load, before
    /// an upload) to catch a corrupt ext4 early. Best-effort; adds an fsck per instruction.
    debug: bool,
    /// spare free blocks left in each stage's ext4 so RUN steps can write.
    free_blocks: u64,
    /// instruction-cache registry: each instruction's resulting ext4 is pushed here
    /// keyed by its chained content hash, and pulled back on a rebuild hit. The CDC
    /// chunk dedup makes successive snapshots share almost all blobs. `None` = no cache.
    cache: Option<crate::config::Registry>,
    /// stage label → its ext4 image path. Shared across concurrent stage workers
    /// (a fork / `COPY --from` reads a dep's committed image): the driver commits a
    /// stage before unblocking its dependents, so the write happens-before the read.
    images: Arc<Mutex<HashMap<String, PathBuf>>>,
    /// Per-image-source materialization guard, shared across workers like `images`: `pull`'s
    /// memo check and the pull/flatten that follows it write one scratch ext4 named by the
    /// image, so two stages reading the same `--from=<image>` must not race — the loser would
    /// rewrite an ext4 the winner already has attached to a booted guest.
    image_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    /// the current stage's long-lived guest (booted on its first RUN, reused for the
    /// rest, committed + torn down by `stage_end`). `None` between stages.
    session: Option<crate::run::VmSession>,
    /// `FROM --kernel=image`: the current stage runs its RUNs on the base image's own
    /// kernel, not vk's embedded build kernel. Set by `stage_kernel`, cleared at `stage_end`.
    stage_image_kernel: bool,
    /// The (kernel, preinit initramfs) extracted from a `--kernel=image` stage's rootfs,
    /// prepared once at its first boot (flatten the rootfs to raw + `fullvm::prepare`) and
    /// reused across the stage's reboots. Cleared at `stage_end`.
    image_kernel_boot: Option<crate::fullvm::FullVmBoot>,
    /// `vk build --disk`: a caller-owned raw disk attached rw as `/dev/vdb` to this
    /// worker's RUN guests (set only on the target stage's worker). Its writes are the
    /// build artifact; never snapshotted, created, or removed by vk.
    out_disk: Option<PathBuf>,
    /// Instruction keys this worker must never restore from or save to the cache — the
    /// `--disk` target stage's steps, whose disk output the cache does not capture. Empty
    /// for every normal stage. See [`MicroVm::set_uncacheable`].
    uncacheable_keys: std::collections::HashSet<String>,
    /// immutable manifest digest of the current parent's cached snapshot — the *only*
    /// reference a diff push fetches its reusable parent chunks by. Never fall back to
    /// fetching by a mutable cache-key tag instead: concurrent builds of the same instruction
    /// clobber the tag with byte-different but equivalent content, so re-fetching parent
    /// chunks by tag can splice another build's bytes onto this stage's actual backing and
    /// corrupt the reused (unchanged) regions. `None` means no known-safe parent (seeded on
    /// `from_image` when the base wasn't itself pulled from cache, or after a push whose
    /// digest we don't have) — `parent_for_push` then does a full re-chunk rather than risk a
    /// tag-based lookup.
    parent_digest: Option<String>,
    /// shared timing collector: fine-grained phase probes (`VIRTKIT_TIMING`) from the
    /// guest lifecycle and cache-push path record here, surfacing in the end-of-run
    /// breakdown instead of printing mid-build over the live dashboard.
    timings: Arc<Timings>,
    /// egress policy for the stage guests (no network / unrestricted / allowlist).
    net: crate::build::BuildNet,
    /// audit mode (`--build-audit-egress`): the shared channel every stage switch appends the
    /// external domains its RUNs resolve to, drained into the post-build summary. `None` =
    /// off. All workers share this one path (they share `scratch`).
    audit_log: Option<PathBuf>,
    /// source-stage ext4s available to attach read-only to this stage's guest, in the
    /// first-use order computed by the driver. A boot attaches only a budget-sized subset.
    sources: Vec<(String, PathBuf)>,
    /// source stage label → its guest device (e.g. `/dev/vdb`) for the current boot.
    source_dev: HashMap<String, String>,
    /// Give each stage guest a disk-backed `/tmp` scratch (the default) so a bulk RUN write
    /// (e.g. a large toolchain unpack) is bounded by disk rather than ½·guest-RAM. Cleared by
    /// `--build-tmp-tmpfs`, which reverts `/tmp` to a RAM tmpfs.
    tmp_disk_enabled: bool,
    /// The stage's disk-backed `/tmp` (only when `tmp_disk_enabled`), reused across source-batch
    /// reboots and removed at `stage_end`. It is outside the stage image, so it never enters
    /// snapshots/cache.
    tmp_disk: Option<PathBuf>,
    /// The stage's writable scratch disk backing `RUN --mount=type=bind,from=scratch,rw`,
    /// lazily provisioned on the first such RUN and then reused across source-batch reboots
    /// (removed at `stage_end`). Like `tmp_disk`, a separate device that never enters the
    /// stage snapshot.
    scratch_disk: Option<PathBuf>,
    /// The *current stage's* build-context dir, shared into its guest over virtiofs for
    /// `COPY` from the context (no `--from`). Set by `stage_sources` before the stage's
    /// first boot and consumed by the next `ensure_session`; `None` between stages.
    /// This per-stage handoff relies on the session-per-stage invariant (`stage_end`
    /// tears the guest down) — a session outliving its stage would keep a stale share.
    context: Option<PathBuf>,
    /// the in-flight cache push (run on a background thread) and the snapshot raw it reads.
    /// At most one runs at a time: it is spawned at the end of an instruction's `cache_save`
    /// and joined at the start of the next one — so the push (chunk + manifest + upload, the
    /// IO-bound bulk of cache-on overhead) overlaps the next instruction's RUN instead of
    /// serializing after it. Its snapshot also serves as the previous baseline the next
    /// instruction's `content_diff` reads, so it is freed only after that join.
    inflight: Option<PushInflight>,
    /// terminal pushes handed off at `stage_end`, awaiting a fork's adoption or the build-wide
    /// drain. Shared across workers (the base executor holds the last reference). See
    /// [`PushPool`].
    pending: Arc<PushPool>,
    /// for a `FROM <stage>` fork, the parent stage whose terminal push this fork must join before
    /// its first diff push chains onto the parent's chunks. Consumed (once) by `parent_for_push`,
    /// so the join overlaps this fork's first RUN instead of blocking its start. `None` otherwise.
    fork_parent: Option<String>,
    /// monotonic counter for unique per-instruction snapshot filenames (several may exist
    /// at once: the live one plus the in-flight push's).
    push_seq: u64,
    /// stage label → the immutable manifest digest of its last pushed snapshot (its committed
    /// image). A `FROM <stage>` fork pins this so its first diff push reuses that stage's
    /// exact chunks regardless of concurrent tag clobbering on the mutable cache-key tag.
    /// Shared across workers (same happens-before as `images`).
    stage_last_digest: Arc<Mutex<HashMap<String, String>>>,
    /// the previous diff push's layer list (+ total size), kept in memory so the next
    /// instruction diffs against it without re-fetching+parsing the parent manifest from
    /// the registry every push. `None` at a stage's first instruction (it fetches once) and
    /// after a full push. Reset at stage boundaries.
    parent_layers: Option<(Vec<oci_client::manifest::OciDescriptor>, u64)>,
    /// where this stage's guest command output goes — set per stage by the driver to the
    /// progress reporter's stage sink. `Inherit` (the default) writes straight to stdout.
    output_sink: crate::executor::OutputSink,
    /// build-wide cancellation, set per stage by the driver: the first stage failure
    /// cancels it, interrupting the RUN steps still executing in every other stage's guest
    /// so the build stops promptly instead of running the in-flight steps to completion.
    cancel: Option<CancellationToken>,
    /// stage label → the qcow2 overlay's cumulative allocated extents at the previous
    /// checkpoint. The next checkpoint diffs the current allocation against this to fold
    /// newly-allocated clusters into the delta — a ground-truth backstop for libkrun's dirty
    /// side-channel (a cluster cannot be written without the overlay allocating it, so this
    /// recovers writes the dirty set drops). Local + sequential (a stage's checkpoints run in
    /// order on one worker); cleared implicitly by rebuilding a stage from a fresh key.
    stage_prev_extents: HashMap<String, Vec<(u64, u64)>>,
    /// stage label → dirty-cluster ranges carried across mid-stage reboots since the last
    /// checkpoint. The block device's dirty set dies with its VM, but a source-batch reboot
    /// keeps the same qcow2 disk — so the set is drained just before each reboot and folded in
    /// here, and a checkpoint combines it with the live VM's set before resetting it. Without
    /// this the set would be per-VM-boot, and a checkpoint after a reboot would miss every write
    /// from before it.
    dirty_carry: HashMap<String, DirtySet>,
    /// stage label → the last content key `cache_save` pushed for it. `stage_end` re-pushes
    /// that key when the guest's shutdown changed the image, and refuses to touch any other.
    last_saved_key: HashMap<String, String>,
}

/// A background cache push's layers, total size, and manifest digest. The next instruction
/// diffs against the layers in memory; a `FROM <stage>` child pins the digest. Full pushes
/// also return layers because `push_ext4_diff` re-chunks the whole image.
type PushResult = ((Vec<oci_client::manifest::OciDescriptor>, u64), String);
type PushOutput = Result<PushResult>;

/// A checkpoint prepared under a freeze: the stable snapshot to push, the written extents to
/// read and push as data, the discarded extents to represent as holes, and the image's virtual
/// size — handed to the background push once the guest has thawed.
type CapturedDelta = (PathBuf, Vec<(u64, u64)>, Vec<(u64, u64)>, u64);

struct PushInflight {
    handle: std::thread::JoinHandle<PushOutput>,
    /// the snapshot raw the push reads; freed after it is joined (and used as the next
    /// instruction's `content_diff` baseline).
    snap: PathBuf,
}

/// Join a background push and turn upload errors or thread panics into messages. Cache
/// failures stay non-fatal: rebuilding an instruction is cheaper than aborting the run.
fn join_push(handle: std::thread::JoinHandle<PushOutput>) -> Result<PushResult, String> {
    match handle.join() {
        Ok(Ok(out)) => Ok(out),
        Ok(Err(e)) => Err(format!("build async push failed ({e:#})")),
        Err(_) => Err("cache push thread panicked".to_string()),
    }
}

/// Terminal cache pushes handed off at `stage_end` and awaiting their join, keyed by stage
/// label. A stage's last push has no next instruction to overlap it, so rather than block the
/// worker on the upload the push lands here and the worker moves on to the next DAG stage. It
/// is joined either by a `FROM <stage>` fork that must diff against its chunks
/// ([`MicroVm::join_pending`]) or, for everything else, by this pool's `Drop` — the build-wide
/// barrier the process crosses before it exits so the cache is fully populated. Shared across
/// the parallel driver's per-stage workers; the base executor holds the last reference, so the
/// drain runs once, when it drops at build end (before the scratch dir is removed).
#[derive(Default)]
struct PushPool {
    inflight: Mutex<HashMap<String, PushInflight>>,
}

impl PushPool {
    fn insert(&self, label: String, inf: PushInflight) {
        self.inflight.lock().unwrap().insert(label, inf);
    }
    fn take(&self, label: &str) -> Option<PushInflight> {
        self.inflight.lock().unwrap().remove(label)
    }
}

impl Drop for PushPool {
    /// Join every terminal push no fork already adopted, so the cache is fully populated before
    /// exit and every snapshot raw is freed before the scratch dir is removed. A failed push is
    /// non-fatal (its instruction is simply left uncached), matching the intra-stage push path.
    fn drop(&mut self) {
        for (_, inf) in self.inflight.get_mut().unwrap().drain() {
            if let Err(msg) = join_push(inf.handle) {
                eprintln!("virtkit: {msg} — not cached");
            }
            let _ = std::fs::remove_file(&inf.snap);
        }
    }
}

/// How the agent re-invokes its own native mount/umount/copy helpers over the exec
/// channel: `/proc/self/exe` is the running agent binary in the forked child, so it
/// works even though the agent is no longer present anywhere in the image's rootfs.
const GUEST_AGENT: &str = "/proc/self/exe";

/// The byte ranges where `cur` differs from `prev`, examined only within `within`. Both are
/// captured overlay qcow2s, read natively (resolving unchanged clusters through their backing).
/// This recovers a single instruction's delta from two consecutive cumulative snapshots, so a
/// diff push re-chunks only what changed (not everything written so far).
///
/// With `skip_new_is_dirty`, reads are avoided where `prev`'s allocation map already decides the
/// outcome: a block that `cur` allocates but `prev` does not is new to this interval and dirty by
/// construction — no read needed (over `prev`'s backing it could only match by coincidence, which
/// chunk dedup collapses on upload anyway). Only blocks allocated in *both* need the byte compare:
/// an in-place rewrite reuses the same qcow2 cluster, invisible to the allocation map, so only the
/// data reveals it. This is sound only when `within` is confined to `cur`'s own allocation (the
/// diff-push path); a caller that passes a `within` spanning regions `cur` does not allocate (the
/// full-image reassembly localizer) must clear the flag to force a true logical byte-compare over
/// every block.
fn content_diff(
    prev: &Path,
    cur: &Path,
    within: &[(u64, u64)],
    skip_new_is_dirty: bool,
) -> Result<Vec<(u64, u64)>> {
    let mut a = crate::qcow2::Qcow2::open(prev)?;
    let mut b = crate::qcow2::Qcow2::open(cur)?;
    // `prev`'s own allocated clusters (sorted, non-overlapping) — the blocks whose bytes must
    // actually be compared; anything in `within` outside this set is new in `cur`. Only needed
    // for the read-skip; a full byte-compare leaves it empty and compares every block.
    let prev_alloc = if skip_new_is_dirty {
        a.data_extents()?
    } else {
        Vec::new()
    };
    const BLK: usize = 256 * 1024; // comparison + dirty-extent granularity
    let mut ba = vec![0u8; BLK];
    let mut bb = vec![0u8; BLK];
    let mut out: Vec<(u64, u64)> = Vec::new();
    // Cursor into `prev_alloc`, advanced monotonically: `within` and `prev_alloc` are both
    // sorted, and `pos` only increases, so each extent is visited at most once.
    let mut pi = 0usize;
    for &(off, len) in within {
        let mut pos = off;
        let end = off + len;
        while pos < end {
            let n = ((end - pos) as usize).min(BLK);
            let block_end = pos + n as u64;
            // Compare the block unless the read-skip decides it dirty from allocation alone: with
            // the skip off, `prev_alloc` is empty so `in_prev` is always true — a full logical
            // diff over every block, holes included.
            let in_prev = if skip_new_is_dirty {
                // Drop `prev_alloc` extents that end at/before this block — they can't cover it or
                // any later block.
                while pi < prev_alloc.len() && prev_alloc[pi].0 + prev_alloc[pi].1 <= pos {
                    pi += 1;
                }
                // Allocated in `prev` iff the next surviving extent starts before the block ends
                // (it already ends after `pos` by the loop above).
                pi < prev_alloc.len() && prev_alloc[pi].0 < block_end
            } else {
                true
            };
            let changed = if in_prev {
                a.read_at(pos, &mut ba[..n])?;
                b.read_at(pos, &mut bb[..n])?;
                ba[..n] != bb[..n]
            } else {
                true // new in `cur` this interval — dirty without reading.
            };
            if changed {
                // coalesce with the previous extent when contiguous.
                match out.last_mut() {
                    Some(last) if last.0 + last.1 == pos => last.1 += n as u64,
                    _ => out.push((pos, n as u64)),
                }
            }
            pos = block_end;
        }
    }
    Ok(out)
}

/// Whether `[off, off+len)` intersects any of `ranges` (used to test a differing extent
/// against the drained dirty set — a difference disjoint from every dirty range is a
/// cluster the capture failed to mark).
fn any_overlap(ranges: &[(u64, u64)], off: u64, len: u64) -> bool {
    let end = off + len;
    ranges.iter().any(|&(o, l)| o < end && off < o + l)
}

/// Sort `(offset, len)` extents by offset and coalesce touching/overlapping ones into a
/// canonical minimal list. Empty extents are dropped.
fn coalesce_ranges(mut r: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    r.retain(|&(_, l)| l > 0);
    r.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(r.len());
    for (o, l) in r {
        match out.last_mut() {
            Some(last) if o <= last.0 + last.1 => last.1 = (last.0 + last.1).max(o + l) - last.0,
            _ => out.push((o, l)),
        }
    }
    out
}

/// The parts of `a` present in both `a` and `b`. Used to clamp the dirty set to the snapshot's
/// allocated clusters before pushing — the block device may report a written offset that has
/// since been deallocated (trimmed), which the qcow2 no longer holds; pushing it would read a
/// cluster that isn't there.
fn intersect_ranges(a: &[(u64, u64)], b: &[(u64, u64)]) -> Vec<(u64, u64)> {
    subtract_ranges(a, &subtract_ranges(a, b))
}

/// The parts of `a` not covered by `b` (both coalesced first). Used to isolate the clusters
/// the dirty set missed (`a` = newly-allocated, `b` = drained dirty).
fn subtract_ranges(a: &[(u64, u64)], b: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let a = coalesce_ranges(a.to_vec());
    let b = coalesce_ranges(b.to_vec());
    let mut out = Vec::new();
    let mut bi = 0;
    for (mut pos, len) in a {
        let end = pos + len;
        // advance past b-ranges entirely left of `pos`
        while bi < b.len() && b[bi].0 + b[bi].1 <= pos {
            bi += 1;
        }
        let mut j = bi;
        while pos < end {
            if j >= b.len() || b[j].0 >= end {
                out.push((pos, end - pos));
                break;
            }
            if b[j].0 > pos {
                out.push((pos, b[j].0 - pos));
            }
            pos = pos.max(b[j].0 + b[j].1);
            j += 1;
        }
    }
    out
}

/// A checkpoint's mutated clusters split by last operation: `(written, discarded)` byte ranges.
type DirtySet = (Vec<(u64, u64)>, Vec<(u64, u64)>);

/// Fold two `(written, discarded)` sets into one with written-wins semantics: a cluster written
/// in either is written (read whole from the overlay), and a cluster is discarded only if it was
/// discarded somewhere and written nowhere. Used to accumulate the set carried across mid-stage
/// reboots and to fold that carry into the live drain at the checkpoint. Written-wins (not
/// last-op-wins) because the sets are cluster-granular: a cluster both written and discarded was
/// only partly freed, so holing it would drop the live sub-part.
fn merge_dirty(base: DirtySet, newer: DirtySet) -> DirtySet {
    let (bw, bd) = base;
    let (nw, nd) = newer;
    let written = coalesce_ranges([bw, nw].concat());
    let discarded = subtract_ranges(&coalesce_ranges([bd, nd].concat()), &written);
    (written, discarded)
}

/// The Linux disk name for the `n`th virtio-blk device (0 = `vda`, 25 = `vdz`,
/// 26 = `vdaa`, …) — matches the kernel's `disk_name` enumeration order.
pub(crate) fn vd_name(n: usize) -> String {
    let mut n = n + 1;
    let mut s = String::new();
    while n > 0 {
        n -= 1;
        s.insert(0, (b'a' + (n % 26) as u8) as char);
        n /= 26;
    }
    format!("vd{s}")
}

/// `/dev` path for the `index`-th source disk. Sources follow the rootfs (`vda`), so they
/// start at `vdb`; with `vk build --disk` the caller's target disk takes `vdb` and sources
/// shift one later to `vdc+`. Must stay in step with `boot_session`'s disk ordering.
fn source_dev_path(index: usize, has_out_disk: bool) -> String {
    let src_base = 1 + has_out_disk as usize;
    format!("/dev/{}", vd_name(index + src_base))
}

/// Cache repo (under the registry's repo prefix) holding the instruction snapshots and
/// the base filesystems they chain from. Named for what it is, not for how it is keyed:
/// it is what `vk registry status` and a shared registry's listings show.
const CACHE_REPO: &str = "build-cache";

/// Conservative virtio-pci source-disk budget for a build guest. libkrun puts every virtio
/// device on PCI bus 0, whose 31 usable slots (slot 0 is the host bridge) — not the scarce
/// IOAPIC pins of the old MMIO/INTx transport — are now the limit. A build guest always
/// spends slots on rootfs, context-fs, vsock, console, rng, and balloon (6), plus one reserved
/// ephemeral scratch slot (`/tmp` and/or `--mount=from=scratch`); that leaves 24, held back to
/// 22 for headroom. (Build-guest egress rides an extra vsock port, not a virtio-net device, so
/// `--net` costs no PCI slot.) When a boot attaches *both* a `/tmp` disk and a scratch disk, the caller
/// drops the effective budget by one (see `ensure_session_with`). The batching/reboot path is
/// kept as the backstop for the rare instruction that still needs more sources than fit.
const MAX_SOURCE_DISKS: usize = 22;

/// Pick the source disks for one guest boot (at most `max`). The common case is a forward
/// scan through source stages: boot sources 0..max, then the next window, and so on. If one
/// instruction needs scattered sources, keep all of them and fill whatever space remains.
fn select_source_batch(
    sources: &[(String, PathBuf)],
    needed: &[&str],
    stage: &str,
    max: usize,
) -> Result<Vec<(String, PathBuf)>> {
    let mut needed_unique: Vec<&str> = Vec::new();
    for label in needed {
        if !needed_unique.contains(label) {
            needed_unique.push(*label);
        }
    }
    if needed_unique.len() > max {
        bail!(
            "stage {stage} needs {} sources in a single instruction, but this VMM can attach at most {max} sources per boot: {}",
            needed_unique.len(),
            needed_unique.join(", ")
        );
    }

    let mut needed_positions = Vec::new();
    for label in &needed_unique {
        let pos = sources
            .iter()
            .position(|(source_label, _)| source_label.as_str() == *label)
            .with_context(|| {
                format!("internal: source {label:?} needed by stage {stage:?} was not declared")
            })?;
        needed_positions.push(pos);
    }

    let mut subset: Vec<(String, PathBuf)> = Vec::new();
    let add = |subset: &mut Vec<(String, PathBuf)>, source: &(String, PathBuf)| {
        if subset.iter().all(|(label, _)| label != &source.0) {
            subset.push((source.0.clone(), source.1.clone()));
        }
    };

    if needed_positions.is_empty() {
        for source in sources.iter().take(max) {
            add(&mut subset, source);
        }
        return Ok(subset);
    }

    let start = *needed_positions.iter().min().expect("not empty");
    for source in sources.iter().skip(start).take(max) {
        add(&mut subset, source);
    }
    if needed_unique
        .iter()
        .all(|needed| subset.iter().any(|(label, _)| label.as_str() == *needed))
    {
        return Ok(subset);
    }

    subset.clear();
    for source in sources {
        if needed_unique.contains(&source.0.as_str()) {
            add(&mut subset, source);
        }
    }
    for source in sources.iter().skip(start).chain(sources.iter().take(start)) {
        if subset.len() >= max {
            break;
        }
        add(&mut subset, source);
    }
    Ok(subset)
}

/// The label an external image is attached under, as a `--from=<image>` source. The `image/`
/// prefix shares the backend's label namespace with the build stages without colliding: a
/// stage's label is `<stage>` or `<unit>:<stage>`, a compose service name is a DNS label, and
/// `Plan::check_reserved_names` rejects a `/` in a Dockerfile `AS` name — which the parser
/// itself would otherwise accept.
pub(crate) fn image_source_label(image: &str) -> String {
    format!("image/{image}")
}

/// Label prefix marking a source as a named build context, so a COPY from one can be told from
/// a stage's (bare label) or an image's ([`image_source_label`]) — see [`is_context_source`].
const CONTEXT_LABEL_PREFIX: &str = "context/";

/// The label a named build context is attached under, as a `--from=<name>` source. Collision-free
/// against a stage label for the same reason [`image_source_label`] is, and against an image
/// source because the two differ in their first path component.
pub(crate) fn context_source_label(name: &str) -> String {
    format!("{CONTEXT_LABEL_PREFIX}{name}")
}

/// Is this source a named build context — a host directory attached read-only — rather than a
/// build stage (bare label) or an external image? A COPY from one is a context COPY, so it
/// honours the directory's `.dockerignore`.
fn is_context_source(fs: &Rootfs) -> bool {
    fs.label.starts_with(CONTEXT_LABEL_PREFIX)
}

/// A filesystem-safe name for a rootfs label — path separators and `:` flattened to `_`, plus
/// a short digest of the original whenever that flattening was lossy. Every scratch file and
/// guest mountpoint a label names goes through here, so the disambiguation has to be part of
/// the slug rather than the caller's business: an image source's label carries a registry ref,
/// and `image/a/b` and `image/a_b` would otherwise share one ext4 and one mountpoint.
fn label_slug(label: &str) -> String {
    let flat = label.replace(['/', '\\', ':'], "_");
    if flat == label {
        return flat;
    }
    // 48 bits of sha256(label) restores what the flattening lost. Hashed here rather than
    // reusing a cache tag, so a change to that tag's format cannot rename every scratch file.
    use sha2::{Digest, Sha256};
    let mut short = String::new();
    for b in Sha256::digest(label.as_bytes()).iter().take(6) {
        short.push_str(&format!("{b:02x}"));
    }
    format!("{flat}-{short}")
}

/// Cache key for a base image's materialized ext4 — an [`Ns::Base`] key over the `FROM`
/// reference — living in the same `CACHE_REPO` as the instruction snapshots.
///
/// Salted with the same `CACHE_KEY_VERSION` as `build.rs`'s `hash_key`, so bumping it
/// invalidates base entries too, and namespaced by the same mechanism: the input here is
/// the very string `hash_key` builds a stage's chain root from, so it is `Ns`'s label —
/// folded into both hashes — that keeps the two apart, not the prefix alone.
pub(super) fn base_cache_key(image: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(super::CACHE_KEY_VERSION.as_bytes());
    h.update(b"\n");
    h.update(Ns::Base.label().as_bytes());
    h.update(b"\n");
    h.update(b"FROM image ");
    h.update(image.as_bytes());
    Ns::Base.key(&super::hex(&h.finalize()))
}

/// The host's logical CPU count (fallback 4) — the default per-stage build guest vCPUs
/// before the [`resolve_build_cpus`] clamp.
pub(crate) fn host_cpus() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(4)
}

/// Per-stage build guest vCPUs: the configured `[build] cpus` verbatim when it is `>= 1`
/// (an explicit request is honoured uncapped); unset falls back to `host` clamped to 16,
/// bounding per-stage oversubscription. CPU oversubscribes across concurrent stages by
/// design (see `resolve_build_jobs`), so each heavy stage gets real parallelism.
pub(crate) fn resolve_build_cpus(cfg: Option<u32>, host: u32) -> u32 {
    cfg.filter(|&n| n >= 1).unwrap_or(host.min(16))
}

/// Per-stage build guest RAM: the configured `[build] mem` (trimmed, non-blank) else 4G —
/// headroom for the parallel compile/link processes a high-vCPU stage spawns. Raising it
/// lowers the RAM-derived job count (`resolve_build_jobs`), trading stage concurrency for
/// per-stage throughput. Passed to the VMM as-is, like `--mem`.
pub(crate) fn resolve_build_mem(cfg: Option<&str>) -> String {
    cfg.map(str::trim)
        .filter(|v| !v.is_empty())
        .map(String::from)
        .unwrap_or_else(|| "4G".into())
}

impl MicroVm {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cloud_hypervisor: PathBuf,
        kernel: PathBuf,
        agent: PathBuf,
        scratch: PathBuf,
        cpus: u32,
        mem: String,
        cache: Option<crate::config::Registry>,
        net: crate::build::BuildNet,
        debug: bool,
        tmp_disk_enabled: bool,
        audit_log: Option<PathBuf>,
        timings: Arc<Timings>,
    ) -> Self {
        MicroVm {
            cloud_hypervisor,
            kernel,
            agent,
            scratch,
            build_cpus: cpus,
            build_mem: mem.clone(),
            cpus,
            mem,
            boot_timeout_secs: 120,
            debug,
            // 32 GiB of writable headroom: a real image (full toolchains + large apt
            // installs) writes many GiB into a single stage. The ext4 is sparse and the
            // overlay/push are hole-aware, so the unused capacity costs nothing on disk.
            free_blocks: 32u64 * 1024 * 1024 * 1024 / 4096,
            cache,
            images: Arc::new(Mutex::new(HashMap::new())),
            image_locks: Arc::new(Mutex::new(HashMap::new())),
            session: None,
            stage_image_kernel: false,
            image_kernel_boot: None,
            out_disk: None,
            uncacheable_keys: std::collections::HashSet::new(),
            parent_digest: None,
            timings,
            net,
            audit_log,
            sources: Vec::new(),
            source_dev: HashMap::new(),
            tmp_disk_enabled,
            tmp_disk: None,
            scratch_disk: None,
            context: None,
            inflight: None,
            pending: Arc::new(PushPool::default()),
            fork_parent: None,
            push_seq: 0,
            stage_last_digest: Arc::new(Mutex::new(HashMap::new())),
            parent_layers: None,
            output_sink: crate::executor::OutputSink::Inherit,
            cancel: None,
            stage_prev_extents: HashMap::new(),
            dirty_carry: HashMap::new(),
            last_saved_key: HashMap::new(),
        }
    }

    /// Attach a caller-owned raw disk as `/dev/vdb` to this worker's RUN guests
    /// (`vk build --disk`). The driver calls this only on the target stage's worker, so
    /// exactly one stage writes the disk (no concurrent rw sharing).
    pub fn set_out_disk(&mut self, path: Option<PathBuf>) {
        self.out_disk = path;
    }

    /// Mark these instruction keys non-cacheable (never restored or saved) — the
    /// `--disk` target stage's steps, so its disk-writing RUNs always run. The driver
    /// sets this on the cache probe and the target stage's worker.
    pub fn set_uncacheable(&mut self, keys: std::collections::HashSet<String>) {
        self.uncacheable_keys = keys;
    }

    /// This executor's guest RAM in MiB — the build-wide default, or the current stage's own
    /// size once `set_stage_guest` has applied its `# vk: mem=…`. What the host-memory gate
    /// charges the stage. `2048` when `mem` cannot be parsed.
    pub fn mem_mib(&self) -> u64 {
        crate::run::parse_mem_mib(&self.mem).unwrap_or(2048)
    }

    /// Each stage guest's vCPUs.
    pub fn cpus(&self) -> u32 {
        self.cpus
    }

    /// Each stage guest's memory as passed to the VMM (`4G`) — the build-wide default, which
    /// a stage's own `# vk: mem=…` overrides. [`Self::mem_mib`] is the same figure parsed.
    pub fn mem(&self) -> &str {
        &self.mem
    }

    /// Ask the live guest agent for this stage's peak demand, excluding faulted page cache that
    /// inflates host-side VMM memory figures.
    ///
    /// The bounded, best-effort query runs on both teardown paths; no memory figure warrants
    /// blocking the build on an unresponsive guest, especially one that may be out of memory.
    /// An old agent, failed exec, or timeout leaves the stage unmeasured instead of reporting
    /// zero demand.
    fn record_stage_mem(&self, label: &str, session: &crate::run::VmSession) {
        let t = std::time::Instant::now();
        let (out, sink) = crate::executor::stdout_capture();
        let argv = [GUEST_AGENT.to_string(), "memmark".to_string()];
        // Construct the timeout after entering the shared runtime; `run_dag` stage workers have
        // no Tokio context in which to create it.
        let asked = block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                session.exec(&argv, None, &sink),
            )
            .await
        });
        self.timings.probe("stage.memmark", t.elapsed());
        if !matches!(asked, Ok(Ok(0))) {
            return;
        }
        let Ok(buf) = out.lock() else { return };
        // Discard the guest's MemTotal: hints target the slightly larger host-assigned size.
        // Requiring both figures still rejects a half-written mark.
        if let Some((peak, _)) = crate::executor::parse_mark(&buf) {
            self.timings
                .record_mem(label, peak, self.mem_mib().saturating_mul(1024 * 1024));
        }
    }

    /// A fresh per-stage worker that shares this executor's cross-stage state (the
    /// `images` / `stage_last_digest` maps and the cache registry) but
    /// starts with an empty per-stage working set (no session, sources, or in-flight
    /// push). The parallel driver builds each concurrent stage on its own worker, so the
    /// per-stage guest and cache-push bookkeeping never alias across threads; those maps and
    /// the process-wide digest memo ([`base_digest`]) are the only synchronization points.
    /// Config (kernel/agent/net/…) is cheap to clone per worker.
    pub fn worker(&self) -> MicroVm {
        MicroVm {
            cloud_hypervisor: self.cloud_hypervisor.clone(),
            kernel: self.kernel.clone(),
            agent: self.agent.clone(),
            scratch: self.scratch.clone(),
            cpus: self.cpus,
            mem: self.mem.clone(),
            build_cpus: self.build_cpus,
            build_mem: self.build_mem.clone(),
            boot_timeout_secs: self.boot_timeout_secs,
            debug: self.debug,
            free_blocks: self.free_blocks,
            cache: self.cache.clone(),
            images: Arc::clone(&self.images),
            image_locks: Arc::clone(&self.image_locks),
            stage_last_digest: Arc::clone(&self.stage_last_digest),
            timings: Arc::clone(&self.timings),
            net: self.net.clone(),
            audit_log: self.audit_log.clone(),
            session: None,
            stage_image_kernel: false,
            image_kernel_boot: None,
            // Set by the driver on the target stage's worker only (`set_out_disk` /
            // `set_uncacheable`); a fresh worker inherits neither.
            out_disk: None,
            uncacheable_keys: std::collections::HashSet::new(),
            parent_digest: None,
            sources: Vec::new(),
            source_dev: HashMap::new(),
            tmp_disk_enabled: self.tmp_disk_enabled,
            tmp_disk: None,
            scratch_disk: None,
            context: None,
            inflight: None,
            pending: Arc::clone(&self.pending),
            fork_parent: None,
            push_seq: 0,
            parent_layers: None,
            // A fresh worker inherits nothing; the driver sets the stage's sink before
            // its instructions run.
            output_sink: crate::executor::OutputSink::Inherit,
            // Set per stage by the driver (`build_stage`), before its instructions run.
            cancel: None,
            stage_prev_extents: HashMap::new(),
            dirty_carry: HashMap::new(),
            last_saved_key: HashMap::new(),
        }
    }

    /// Boot this stage's guest with every `needed` source label attached. When the live
    /// guest has the right source batch, reuse it; otherwise quiesce it and reboot the
    /// same stage image with a new read-only source subset. Reuse is scoped to the current
    /// instruction's sources only — it does not anticipate the next one, so a stage that
    /// alternates sources across the batch boundary reboots on each instruction.
    fn ensure_session_with(
        &mut self,
        fs: &Rootfs,
        needed: &[&str],
        needs_scratch: bool,
    ) -> Result<()> {
        let have_scratch = self
            .session
            .as_ref()
            .is_some_and(|s| s.scratch_dev().is_some());
        if self.session.is_some()
            && needed
                .iter()
                .all(|label| self.source_dev.contains_key(*label))
            && (!needs_scratch || have_scratch)
        {
            return Ok(());
        }

        // Ephemeral scratch devices this boot attaches: the `/tmp` disk (default; off under
        // --build-tmp-tmpfs) and
        // the `--mount=from=scratch` disk (once provisioned, kept attached for the rest of the
        // stage so it survives source-batch reboots). One scratch slot is already in the source
        // budget; a boot carrying *both* disks costs one extra, so drop the source budget then.
        let want_tmp = self.tmp_disk_enabled;
        let want_scratch = needs_scratch || self.scratch_disk.is_some();
        // `vk build --disk` attaches one more rw device (the target disk at /dev/vdb), so it
        // costs a source slot too. One scratch slot is already in the source budget.
        let want_out_disk = self.out_disk.is_some();
        let extra =
            (want_tmp as usize + want_scratch as usize + want_out_disk as usize).saturating_sub(1);
        let max_sources = MAX_SOURCE_DISKS - extra;

        let subset = select_source_batch(&self.sources, needed, &fs.label, max_sources)?;
        if let Some(session) = self.session.take() {
            // Read the mark before the final filesystem freeze while guest exec still works.
            self.record_stage_mem(&fs.label, &session);
            // Carry this VM's dirty set across the reboot before it dies with the VM: the disk
            // persists, so a checkpoint after the reboot must still see writes from before it.
            // Freeze first so the guest flushes its page cache to the block device (the set only
            // records writes that actually reached virtio-blk), then thaw so the `finish()` below
            // quiesces the image normally rather than shutting down a still-frozen fs.
            if session.supports_dirty() {
                let frozen = block_on(session.freeze());
                match session.drain_dirty() {
                    Ok(newer) => {
                        let carry = self.dirty_carry.entry(fs.label.clone()).or_default();
                        *carry = merge_dirty(std::mem::take(carry), newer);
                    }
                    Err(e) => {
                        eprintln!("virtkit: carrying the dirty set across a reboot failed ({e:#})")
                    }
                }
                block_on(session.thaw(frozen));
            }
            let t_fin = std::time::Instant::now();
            block_on(session.finish())?;
            self.timings.probe("reboot.finish", t_fin.elapsed());
            self.source_dev.clear();
        }

        let ext4 = self.stage_image(fs)?;
        let context = self
            .context
            .clone()
            .context("internal: stage booted before stage_sources set its context")?;
        // Disk-backed /tmp unless the build opted out (--build-tmp-tmpfs), in which case the
        // guest uses a RAM tmpfs /tmp. The disk is provisioned once per stage and reused across
        // its source-batch reboots (removed at stage_end), so it survives the reboots yet never
        // enters the stage snapshot.
        let tmp_disk = if want_tmp {
            Some(match &self.tmp_disk {
                Some(path) => path.clone(),
                None => {
                    let path = crate::run::build_tmp_disk(&ext4)?;
                    self.tmp_disk = Some(path.clone());
                    path
                }
            })
        } else {
            None
        };
        // Writable scratch disk for `RUN --mount=from=scratch,rw`: same lazy, once-per-stage
        // provisioning as the /tmp disk. Once created it stays attached across reboots.
        let scratch_disk = if want_scratch {
            Some(match &self.scratch_disk {
                Some(path) => path.clone(),
                None => {
                    let path = crate::run::build_scratch_disk(&ext4)?;
                    self.scratch_disk = Some(path.clone());
                    path
                }
            })
        } else {
            None
        };
        let source_paths: Vec<PathBuf> = subset.iter().map(|(_, path)| path.clone()).collect();
        // `FROM --kernel=image`: boot this stage's RUNs on the base image's own kernel.
        // Extract it once (flatten the stage rootfs to raw so fullvm can read the ext4,
        // then fullvm::prepare) and reuse the (kernel, preinit initramfs) across reboots.
        if self.stage_image_kernel && self.image_kernel_boot.is_none() {
            let work = self
                .scratch
                .join(format!("imgkernel-{}", label_slug(&fs.label)));
            std::fs::create_dir_all(&work)?;
            let raw = work.join("rootfs.raw");
            crate::qcow2::flatten_to_raw(&ext4, &raw).with_context(|| {
                format!(
                    "--kernel=image: flattening {} to read its kernel",
                    ext4.display()
                )
            })?;
            let boot = crate::fullvm::prepare(
                &raw,
                &self.agent,
                &work.join("vmlinuz"),
                &work.join("initramfs.cpio"),
                None,
                &crate::run::KernelSource::Image,
                &self.kernel,
            )
            .context(
                "--kernel=image: extracting the base image's kernel — the base must install \
                 a kernel (e.g. in a prior stage)",
            )?;
            let _ = std::fs::remove_file(&raw);
            self.image_kernel_boot = Some(boot);
        }
        let image_kernel = self
            .image_kernel_boot
            .as_ref()
            .map(|b| (b.kernel.as_path(), b.initramfs.as_path()));
        // The one channel every stage's switch appends to, beside the audit log in the
        // scratch the workers share — which is where the build reads it back from.
        let bytes_log = self.scratch.join(crate::run::NET_BYTES);
        let s = block_on(crate::run::boot_session(
            &self.cloud_hypervisor,
            &self.kernel,
            &self.agent,
            &ext4,
            &self.net,
            self.cpus,
            &self.mem,
            self.boot_timeout_secs,
            &source_paths,
            Some(&context),
            tmp_disk.as_deref(),
            scratch_disk.as_deref(),
            image_kernel,
            self.out_disk.as_deref(),
            self.audit_log.as_deref(),
            Some(&bytes_log),
            self.cancel.clone(),
            &self.timings,
        ))?;
        let has_out_disk = self.out_disk.is_some();
        self.source_dev = subset
            .iter()
            .enumerate()
            .map(|(i, (label, _))| (label.clone(), source_dev_path(i, has_out_disk)))
            .collect();
        self.session = Some(s);
        Ok(())
    }
    /// Whether a cache restore should write a lazy `.vk_ro_img` view instead of eagerly
    /// decompressing the whole cached image to a raw ext4: only libkrun's virtio-blk knows
    /// how to read one (`LazyChunkStorage` in `third_party/libkrun`).
    ///
    /// `--debug` deliberately does *not* turn this off: it used to, which left the check looking
    /// only at the eager path it substituted in. [`Self::verify_lazy_view`] materializes the view
    /// instead, so the check covers what the build really restores.
    fn lazy_restore_enabled(&self) -> bool {
        crate::vmm::libkrun_selected()
    }
    /// `--debug`: verify a lazily restored `.vk_ro_img` view — the chunks it names, reassembled
    /// through the host-side reader — as [`Self::verify_ext4`] does for a raw restore. Writes a
    /// throwaway raw (the whole point of the lazy path is not to, so this is `--debug`-only) and
    /// discards it. No-op unless `--debug` is set.
    ///
    /// What it covers is the manifest and the chunks behind it, not libkrun's own reader of them
    /// (`LazyChunkStorage`), which only a booted guest exercises. And with `--debug` no longer
    /// forcing the eager path, the eager reassembly is checked by [`Self::verify_reassembly`]
    /// and by a cloud-hypervisor build, rather than at this boundary.
    fn verify_lazy_view(&self, view: &Path, context: &str) -> Result<()> {
        if !self.debug {
            return Ok(());
        }
        // Only ever called on what a lazy restore just wrote. Anything else — wrong name, or the
        // right name over bytes that are not a manifest — would be copied through verbatim and
        // reach `e2fsck` as "not an ext4", which is a skip, which is a pass. Check both.
        let ext = crate::registry::VK_RO_IMG_EXT;
        let named = view.extension() == Some(std::ffi::OsStr::new(ext));
        let f = std::fs::File::open(view).with_context(|| format!("opening {}", view.display()))?;
        if !named || crate::qcow2::sniff_kind(&f) != crate::qcow2::ImageKind::Lazy {
            bail!("--debug: {} is not a .{ext} view", view.display());
        }
        drop(f);
        let raw = view.with_extension("fsck-view.raw");
        let materialized = crate::qcow2::materialize_to_raw(view, &raw)
            .with_context(|| format!("reassembling {} for the --debug ext4 check", view.display()));
        if materialized.is_err() {
            // A partially-written raw may linger even on failure; do not leak it.
            let _ = std::fs::remove_file(&raw);
        }
        materialized?;
        let r = self.verify_ext4(&raw, context);
        let _ = std::fs::remove_file(&raw); // best-effort: the raw is scratch for the check
        r
    }
    /// `--debug`: run `e2fsck` on a raw ext4 as it crosses the cache boundary. A clean fs
    /// (or an inconclusive skip — e2fsck absent) passes; genuine corruption fails the build
    /// with `context` naming where it was caught, so a bad snapshot never silently becomes a
    /// corrupt image or an EUCLEAN mid-build. No-op unless `--debug` is set.
    fn verify_ext4(&self, image: &Path, context: &str) -> Result<()> {
        if !self.debug {
            return Ok(());
        }
        match crate::ext4::fsck(image) {
            crate::ext4::FsckResult::Clean => Ok(()),
            crate::ext4::FsckResult::Skipped(why) => {
                eprintln!("virtkit: --debug: ext4 check of {context} skipped ({why})");
                Ok(())
            }
            crate::ext4::FsckResult::Corrupt(report) => bail!(
                "--debug: {context} is a corrupt ext4 (e2fsck):\n{report}\n\
                 this snapshot must not be used; evict it from the cache and rebuild"
            ),
        }
    }
    /// `--debug`: verify a snapshot qcow2 that is about to be uploaded to the cache. The
    /// capture is synchronous (only the upload is async), so a corrupt snapshot fails the
    /// build here and now — it must not ship in the image or poison the cache for a later
    /// build. Flattens to a throwaway raw for `e2fsck`, then discards it. No-op unless
    /// `--debug` is set.
    fn verify_snapshot(&self, snap: &Path, context: &str) -> Result<()> {
        if !self.debug {
            return Ok(());
        }
        let raw = snap.with_extension("fsck.raw");
        let flattened = crate::qcow2::flatten_to_raw(snap, &raw)
            .with_context(|| format!("flattening {} for the --debug ext4 check", snap.display()));
        if flattened.is_err() {
            // A partially-written raw may linger even on failure; do not leak it.
            let _ = std::fs::remove_file(&raw);
        }
        flattened?;
        let r = self.verify_ext4(&raw, context);
        let _ = std::fs::remove_file(&raw);
        r
    }
    /// `--debug`: verify the *reassembled* cache entry — parent layers spliced with this
    /// instruction's delta — which is what a later build restores, unlike [`Self::verify_snapshot`]
    /// (the frozen source overlay is always the full, consistent fs, so it can never expose an
    /// incomplete delta). Pull `key` back and e2fsck it. On corruption, `content_diff` the
    /// reassembly against the frozen source `snap` and report how many differing extents the
    /// drained `dirty` set failed to mark — pinpointing the capture gap that poisoned the layer.
    /// No-op unless `--debug`.
    fn verify_reassembly(
        &self,
        rg: &crate::config::Registry,
        key: &str,
        snap: &Path,
        dirty: &[(u64, u64)],
        total_size: u64,
        context: &str,
    ) -> Result<()> {
        if !self.debug {
            return Ok(());
        }
        let pulled = self.image_path(&format!("verify-{}", key.replace([':', '/'], "_")));
        let digest = crate::registry::try_pull_ext4(rg, CACHE_REPO, key, &pulled, context)
            .with_context(|| format!("--debug: pulling {context} back to verify the reassembly"))?;
        if digest.is_none() {
            bail!(
                "--debug: {context} vanished from the cache before its reassembly could be verified"
            );
        }
        let fsck = crate::ext4::fsck(&pulled);
        if let crate::ext4::FsckResult::Corrupt(report) = &fsck {
            // Localize the poisoning: the frozen `snap` is the full, correct fs, so every extent
            // where the reassembly differs is a cluster the delta got wrong; those disjoint from
            // `dirty` are exactly what the capture failed to record.
            let overlay = pulled.with_extension("cmp.qcow2");
            let localize = (|| -> Result<String> {
                crate::qcow2::create_overlay(&overlay, &pulled)?;
                // Full logical byte-compare: `within` spans the whole image (holes included),
                // not `overlay`'s own allocation, so the read-skip would misreport — disable it.
                let diffs = content_diff(snap, &overlay, &[(0, total_size)], false)?;
                let missed: Vec<(u64, u64)> = diffs
                    .iter()
                    .copied()
                    .filter(|&(o, l)| !any_overlap(dirty, o, l))
                    .collect();
                Ok(format!(
                    "{} extent(s) differ from the frozen image; {} are outside the drained \
                     dirty set (missed by capture) — first: {:?}",
                    diffs.len(),
                    missed.len(),
                    missed.iter().take(8).collect::<Vec<_>>()
                ))
            })();
            let _ = std::fs::remove_file(&overlay);
            let _ = std::fs::remove_file(&pulled);
            let detail =
                localize.unwrap_or_else(|e| format!("(diff against source failed: {e:#})"));
            bail!(
                "--debug: reassembled {context} is a corrupt ext4 (e2fsck):\n{report}\n\
                 dirty-delta audit: {detail}\n\
                 the O(delta) capture produced an incomplete delta; rebuild with \
                 --cache-registry none to bypass it"
            );
        }
        let _ = std::fs::remove_file(&pulled);
        if let crate::ext4::FsckResult::Skipped(why) = fsck {
            eprintln!("virtkit: --debug: reassembly check of {context} skipped ({why})");
        }
        Ok(())
    }
    fn image_path(&self, stage: &str) -> PathBuf {
        self.scratch.join(format!("{}.ext4", label_slug(stage)))
    }
    /// Where a lazy cache restore (see [`Self::lazy_restore_enabled`]) writes its
    /// `.vk_ro_img` manifest instead of a fully reassembled ext4.
    fn lazy_image_path(&self, stage: &str) -> PathBuf {
        self.scratch
            .join(format!("{}.vk_ro_img", label_slug(stage)))
    }
    fn stage_image(&self, fs: &Rootfs) -> Result<PathBuf> {
        self.images
            .lock()
            .unwrap()
            .get(&fs.label)
            .cloned()
            .with_context(|| format!("no ext4 for stage {:?}", fs.label))
    }
    fn stage_overlay_path(&self, stage: &str) -> PathBuf {
        self.scratch.join(format!("{}.qcow2", label_slug(stage)))
    }
    /// Materialize `image` as an ext4 under `label`'s scratch path: restore the cached base
    /// (keyed by the image's manifest digest) or pull + flatten the OCI image and populate the
    /// cache. Returns the ext4, its base cache key, and the digest of the cached snapshot
    /// (`None` when nothing was cached) — the lineage a stage's first diff push chunks against.
    /// Shared by `from_image`, which wraps it as the stage's writable rootfs, and `pull`, which
    /// attaches it read-only as a `--from=<image>` source.
    fn materialize_image(&mut self, label: &str, image: &str) -> Result<(PathBuf, Option<String>)> {
        std::fs::create_dir_all(&self.scratch)
            .with_context(|| format!("creating {}", self.scratch.display()))?;
        let ext4 = self.image_path(label);
        // Base-image ext4 cache: the materialized base (OCI-flattened + free headroom) is keyed
        // by the image's manifest digest (resolved + memoized by resolve_base_digest, falling
        // back to the ref) and stored in the cache registry. A repeat build pulls it back
        // instead of re-running the pull/flatten/ext4-build — and, because the base's chunks
        // are now in the store, an instruction snapshot on a cold build dedups its unchanged
        // base region against them, so only the RUN's diff is compressed and uploaded.
        // Digest-keyed so a moved tag is not served a stale base (matching the chain-key seed).
        let base_id = match self.resolve_base_digest(image) {
            Some(d) => format!("{image}@{d}"),
            None => image.to_string(),
        };
        let base_key = base_cache_key(&base_id);
        if let Some(rg) = self.cache.clone()
            && crate::registry::exists(&rg, CACHE_REPO, &base_key)
        {
            if self.lazy_restore_enabled() {
                let lazy = self.lazy_image_path(label);
                if let Some(digest) =
                    crate::registry::try_pull_ext4_lazy(&rg, CACHE_REPO, &base_key, &lazy, image)?
                {
                    self.verify_lazy_view(&lazy, &format!("cached image {image} (after load)"))?;
                    return Ok((lazy, Some(digest)));
                }
            } else if let Some(digest) =
                crate::registry::try_pull_ext4(&rg, CACHE_REPO, &base_key, &ext4, image)?
            {
                self.verify_ext4(&ext4, &format!("cached image {image} (after load)"))?;
                return Ok((ext4, Some(digest)));
            }
        }
        // pull + flatten the OCI image to a rootfs tar (no docker), then build the ext4.
        let tar = self.scratch.join(format!("{}.tar", label_slug(label)));
        // Swallow the pull's status lines: the live build dashboard owns the terminal
        // (a raw write would corrupt its cursor accounting) and already shows this
        // stage's FROM step, so the "pulling …"/"flattened …" notes are redundant here.
        block_on(crate::oci::pull_flatten(
            image,
            &crate::oci::Creds::anonymous(),
            &tar,
            &|_| {},
        ))
        .with_context(|| format!("pulling {image}"))?;
        // Build the base ext4 with free space for the RUN steps to write into
        // (a zero extra_free_blocks leaves none, which would ENOSPC on the first write). The agent
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
        let mut digest = None;
        if let Some(rg) = self.cache.clone() {
            let boot_kind = crate::image::boot_kind_tag(crate::image::BootKind::GenericDisk);
            match crate::registry::push_ext4(&rg, CACHE_REPO, &base_key, &ext4, boot_kind) {
                // pin the digest we just wrote, not the tag: another process may clobber
                // base_key with its own (byte-different) base before our first diff push.
                Ok(d) => digest = Some(d),
                Err(e) => {
                    eprintln!(
                        "virtkit: build base cache push of {image} failed ({e:#}) — not cached"
                    )
                }
            }
        }
        Ok((ext4, digest))
    }

    /// Register a freshly built or pulled raw ext4 `base` as `stage`'s image by wrapping it
    /// in a rw qcow2 overlay — the stage's guest boots that overlay directly and its writes
    /// accumulate into it (no separate boot overlay, no commit). The raw stays as the
    /// overlay's read-only backing; export later flattens the chain.
    fn wrap_base(&mut self, stage: &str, base: &Path) -> Result<()> {
        let overlay = self.stage_overlay_path(stage);
        crate::qcow2::create_overlay(&overlay, base)?;
        self.images
            .lock()
            .unwrap()
            .insert(stage.to_string(), overlay);
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
        // A `FROM <stage>` fork's first push chains onto the parent's chunks: join the parent's
        // (possibly still-uploading) terminal push now, so its blobs are in the registry before
        // the fetch below references them, and seed the pinned digest it forked from. Runs
        // once — later pushes chain onto this stage's own in-memory `parent_layers`.
        if let Some(parent) = self.fork_parent.take() {
            self.join_pending(&parent);
            self.parent_digest = self.stage_last_digest.lock().unwrap().get(&parent).cloned();
        }
        match self.parent_layers.take() {
            Some((l, t)) => (l, t),
            // Resolve the parent ONLY by its pinned immutable digest — never by a mutable
            // cache-key tag. Under concurrent builds the tag may have been clobbered with a
            // byte-different snapshot of the same instruction, and reusing those chunks over
            // this stage's actual backing would corrupt the unchanged regions (see
            // `parent_digest`'s doc comment). No pinned digest (e.g. an earlier push failed, or
            // the fork's parent never recorded one) means no known-safe parent: fall through to
            // a full re-chunk rather than risk a tag lookup.
            None => match self.parent_digest.clone().and_then(|r| {
                crate::registry::fetch_chunks(rg, CACHE_REPO, &r)
                    .ok()
                    .flatten()
            }) {
                Some((l, t)) => (l, t),
                None => (Vec::new(), total_size),
            },
        }
    }

    /// Push `snap`'s `dirty` extents as this instruction's cache layer, chained onto the
    /// stage's parent layers, and record the result as the new parent (or clear the pinned
    /// parent on failure so the next push full-re-chunks rather than splicing stale bytes).
    /// The synchronous commit shared by the no-guest path (a metadata-only instruction that
    /// never booted a VM) and the libkrun dirty-tracked path; cloud-hypervisor pushes async.
    #[allow(clippy::too_many_arguments)]
    fn push_snapshot_sync(
        &mut self,
        rg: &crate::config::Registry,
        fs: &Rootfs,
        key: &str,
        boot_kind: &str,
        snap: &Path,
        dirty: &[(u64, u64)],
        total_size: u64,
    ) -> Result<()> {
        let (parent_layers, parent_total) = self.parent_for_push(rg, total_size);
        // A stable full image (no live guest, or cloud-hypervisor's write-through) carries no
        // separate discard set — freed space shows up as zero content the chunker already drops.
        match crate::registry::push_ext4_diff(
            rg,
            CACHE_REPO,
            key,
            snap,
            boot_kind,
            parent_total,
            dirty,
            &[],
            &parent_layers,
        ) {
            Ok((layers, total, digest)) => {
                self.parent_layers = Some((layers, total));
                self.record_stage_digest(&fs.label, &digest);
                self.parent_digest = Some(digest);
                // Verify what actually got cached (parent + this delta), not just the frozen
                // source — an incomplete delta reassembles to a corrupt ext4 that the source
                // check can never catch. `--debug` only.
                self.verify_reassembly(
                    rg,
                    key,
                    snap,
                    dirty,
                    total_size,
                    &format!("cached instruction {key}"),
                )?;
            }
            Err(e) => {
                eprintln!("virtkit: build cache push of {key} failed ({e:#}) — not cached");
                // This push published no digest. Clear the previous parent so the next diff
                // cannot splice stale bytes over this instruction's changes;
                // `parent_for_push` will re-chunk the full image. Also clear the stage map so
                // forks cannot reuse the superseded digest.
                self.parent_layers = None;
                self.parent_digest = None;
                self.forget_stage_digest(&fs.label);
            }
        }
        Ok(())
    }

    /// Join the previous in-flight push (if any) and adopt its result as the parent for the
    /// next diff push: on success pin its layers + digest as the parent — on failure clear the
    /// pinned parent so the next diff has no known-safe parent and re-chunks fully, rather than
    /// splicing a stale digest's bytes over this stage's backing. Frees the pushed snapshot.
    /// Called before spawning the next push.
    fn harvest_prev_push(&mut self, label: &str) {
        let Some(inf) = self.inflight.take() else {
            return;
        };
        match join_push(inf.handle) {
            Ok((layers, digest)) => {
                self.parent_layers = Some(layers);
                self.record_stage_digest(label, &digest);
                self.parent_digest = Some(digest);
            }
            Err(msg) => {
                eprintln!("virtkit: {msg} — not cached");
                self.parent_layers = None;
                self.parent_digest = None;
                self.forget_stage_digest(label);
            }
        }
        let _ = std::fs::remove_file(&inf.snap);
    }

    /// Adopt a stage's parked terminal push (parked at its `stage_end`) before a `FROM <stage>`
    /// fork's first diff push chains onto it: join the upload and record the stage's immutable
    /// digest so `parent_for_push` can pin the parent's chunks. The fork must cross this
    /// barrier — its first diff push fetches those chunks from the registry, so they must be
    /// uploaded first. Idempotent: a stage forked by several children joins once (later calls find
    /// it gone but the recorded digest already in place). A failed push leaves no digest, so the
    /// fork full-pushes.
    fn join_pending(&self, label: &str) {
        let Some(inf) = self.pending.take(label) else {
            return;
        };
        match join_push(inf.handle) {
            Ok((_, digest)) => self.record_stage_digest(label, &digest),
            Err(msg) => {
                eprintln!("virtkit: {msg} — not cached");
                self.forget_stage_digest(label);
            }
        }
        let _ = std::fs::remove_file(&inf.snap);
    }

    /// Record `digest` as the cache parent for a `FROM <stage>` fork of `label`.
    /// Centralize writes because the map is shared across workers.
    fn record_stage_digest(&self, label: &str, digest: &str) {
        self.stage_last_digest
            .lock()
            .unwrap()
            .insert(label.to_string(), digest.to_string());
    }

    /// Remove `label`'s digest after a push fails to publish its changes. The previous digest
    /// is superseded; without a known registry parent, a `FROM <stage>` fork safely re-chunks
    /// the full image.
    fn forget_stage_digest(&self, label: &str) {
        self.stage_last_digest.lock().unwrap().remove(label);
    }
}

impl Drop for MicroVm {
    /// On an error mid-stage the backend can be dropped with a cache push still in flight:
    /// join it so its thread finishes and its snapshot raw is removed, rather than detaching
    /// the thread and leaking the multi-MB capture.
    fn drop(&mut self) {
        // Kill the guest first (a build-cancel teardown otherwise leaves it holding its RAM
        // while the push join below runs); the push reads an already-captured snapshot, not
        // the live VM, so this is independent of it. `VmSession`'s own `Drop` does the kill.
        self.session.take();
        if let Some(tmp) = self.tmp_disk.take() {
            let _ = std::fs::remove_file(tmp);
        }
        if let Some(scratch) = self.scratch_disk.take() {
            let _ = std::fs::remove_file(scratch);
        }
        if let Some(inf) = self.inflight.take() {
            if let Err(msg) = join_push(inf.handle) {
                eprintln!("virtkit: {msg} — not cached");
            }
            let _ = std::fs::remove_file(&inf.snap);
        }
    }
}

/// Validate a RUN step's `--mount` specs and return the `from=scratch` mount's target, if any.
/// Enforces the from=scratch contract without touching the guest, so it is unit-testable: at
/// most one `from=scratch` per step (they would share the single scratch device), and `rw` /
/// `uid` / `gid` / `mode` only on a `from=scratch` mount — a stage or build-context bind is a
/// read-only view of committed bytes, always root-owned.
fn scratch_mount_target(specs: &[&Mount]) -> Result<Option<String>> {
    let mut scratch: Option<&Mount> = None;
    for m in specs {
        // tmpfs mounts are RAM-backed and mounted separately (mount_tmpfs): they take no
        // from=/source and are writable by nature, so they are exempt from the read-only
        // stage/context-bind restrictions below. Only size= is honored — reject uid/gid/mode
        // rather than silently ignore them (the guest mount never applies them).
        if m.typ == "tmpfs" {
            if m.uid.is_some() || m.gid.is_some() || m.mode.is_some() {
                bail!(
                    "RUN --mount=type=tmpfs at {:?}: only size= is supported (uid/gid/mode are not)",
                    m.target
                );
            }
            continue;
        }
        if m.from.as_deref() == Some("scratch") {
            if scratch.is_some() {
                bail!(
                    "RUN --mount: at most one type=bind,from=scratch mount per step is supported \
                     (they would share one scratch device); split the extra scratch across steps"
                );
            }
            scratch = Some(m);
            continue;
        }
        if m.rw {
            bail!(
                "RUN --mount ...,rw at {:?}: a writable mount is only supported with from=scratch \
                 (an ephemeral disk-backed scratch); a stage or build-context mount is always \
                 read-only",
                m.target
            );
        }
        if m.uid.is_some() || m.gid.is_some() || m.mode.is_some() {
            bail!(
                "RUN --mount ...,uid/gid/mode at {:?}: only supported with from=scratch",
                m.target
            );
        }
    }
    match scratch {
        Some(m) => {
            Ok(Some(m.target.clone().context(
                "RUN --mount=type=bind,from=scratch requires target=",
            )?))
        }
        None => Ok(None),
    }
}

/// Resolve a `COPY` destination against the active `WORKDIR`: an absolute dest is used
/// verbatim, a relative one joins onto `workdir` (Docker semantics). `workdir` is expected
/// absolute — a relative `WORKDIR` is stored verbatim (not stacked onto the previous one, a
/// pre-existing limitation) and so yields a relative dest, which stays consistent with how
/// `RUN` uses `WORKDIR` as its cwd from `/`.
pub(crate) fn resolve_copy_dest(dest: &str, workdir: &str) -> String {
    if dest.starts_with('/') {
        return dest.to_string();
    }
    // "/" -> "" so joining never doubles the slash; any other workdir loses its trailing /.
    let wd = workdir.trim_end_matches('/');
    let rel = dest.strip_prefix("./").unwrap_or(dest);
    if rel.is_empty() || rel == "." {
        format!("{wd}/") // WORKDIR itself, as a directory target
    } else {
        format!("{wd}/{rel}")
    }
}

impl Executor for MicroVm {
    fn set_stage_guest(&mut self, hint: &super::parser::GuestHint) {
        self.mem = hint.mem.clone().unwrap_or_else(|| self.build_mem.clone());
        self.cpus = hint.cpus.unwrap_or(self.build_cpus);
    }
    fn stage_mem_mib(&self) -> Option<u64> {
        Some(self.mem_mib())
    }
    fn from_image(&mut self, stage: &str, image: &str) -> Result<Rootfs> {
        // The stage's writable working rootfs: a qcow2 overlay over the materialized base,
        // whose cache key + digest seed this stage's snapshot lineage.
        let (ext4, digest) = self.materialize_image(stage, image)?;
        self.wrap_base(stage, &ext4)?;
        self.parent_digest = digest;
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
        let empty_tar = self
            .scratch
            .join(format!("{}-empty.tar", label_slug(stage)));
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
        self.images
            .lock()
            .unwrap()
            .insert(stage.to_string(), overlay);
        // The fork boots from the parent's local image above; only its *first cache push* needs
        // the parent's chunks in the registry (to diff against instead of re-chunking the whole
        // image). The parent's terminal push may still be uploading, so defer joining it — record
        // the parent label and let the first `parent_for_push` join it, overlapping that upload
        // with this fork's first RUN rather than stalling the fork's start.
        self.fork_parent = Some(parent.label.clone());
        self.parent_digest = None;
        self.parent_layers = None;
        Ok(Rootfs {
            label: stage.to_string(),
        })
    }
    fn pull(&mut self, image: &str) -> Result<Rootfs> {
        // A `--from=<image>` source: the image's materialized ext4, attached read-only like a
        // source stage's (the attach path detects the raw format), memoized so several
        // instructions referencing the same image pull and flatten it once. The stage's own cache
        // lineage (`parent_digest`) is deliberately untouched: this is a source, not a
        // base. It is materialized exactly like a base, free headroom and all — nothing here
        // will write to it, but building it any other way would fork the base cache entry the
        // same image shares with a `FROM` that uses it.
        let label = image_source_label(image);
        // Serialize on this image before consulting the memo: two stages reading the same one
        // run concurrently, and the loser of a race would rewrite the ext4 the winner already
        // has attached. Waiting here costs nothing the second stage was not going to spend.
        let lock = {
            let mut locks = self.image_locks.lock().unwrap();
            Arc::clone(locks.entry(label.clone()).or_default())
        };
        let _materializing = lock.lock().unwrap();
        if self.images.lock().unwrap().contains_key(&label) {
            return Ok(Rootfs { label });
        }
        let (ext4, _) = self.materialize_image(&label, image)?;
        self.images.lock().unwrap().insert(label.clone(), ext4);
        Ok(Rootfs { label })
    }
    fn context_source(&mut self, name: &str, dir: &Path) -> Result<Rootfs> {
        // Served like a source stage: the directory is packed into an ext4 and attached
        // read-only. (The stage's own build context rides a virtiofs share, but a guest gets
        // just the one, so every *extra* context becomes a disk.) Packed once per build.
        let label = context_source_label(name);
        // Serialized per context, for the reason `pull` is: two stages reading the same one run
        // concurrently, and the loser of a race would repack the ext4 the winner has attached.
        let lock = {
            let mut locks = self.image_locks.lock().unwrap();
            Arc::clone(locks.entry(label.clone()).or_default())
        };
        let _packing = lock.lock().unwrap();
        if self.images.lock().unwrap().contains_key(&label) {
            return Ok(Rootfs { label });
        }
        std::fs::create_dir_all(&self.scratch)
            .with_context(|| format!("creating {}", self.scratch.display()))?;
        let ext4 = self.image_path(&label);
        crate::ext4::build_from_dir(dir, &ext4)
            .with_context(|| format!("packing build context {name} ({})", dir.display()))?;
        self.images.lock().unwrap().insert(label.clone(), ext4);
        Ok(Rootfs { label })
    }
    fn run(
        &mut self,
        fs: &Rootfs,
        cmd: &Cmdline,
        mounts: &[ResolvedMount<'_>],
        state: &ShellState,
    ) -> Result<()> {
        let mut needed: Vec<&str> = Vec::new();
        for m in mounts {
            if let Some(src) = m.from
                && !needed.contains(&src.label.as_str())
            {
                needed.push(src.label.as_str());
            }
        }
        // `from=scratch` asks for an empty, writable, disk-backed scratch fs at the target
        // (BuildKit's writable-bind idiom, disk-backed so it dodges the ½·RAM tmpfs cap). It
        // is served by an ephemeral scratch disk attached to the guest — provisioned on demand
        // and mounted directly at the target. One per step (a second would need to share the
        // single device); split extra scratch needs across steps.
        let specs: Vec<&Mount> = mounts.iter().map(|m| m.spec).collect();
        let scratch_target = scratch_mount_target(&specs)?;
        let scratch = specs
            .iter()
            .copied()
            .find(|m| m.from.as_deref() == Some("scratch"));
        let needs_scratch = scratch_target.is_some();
        // Boot the stage's guest once (on the first RUN/COPY) and reuse it while its
        // attached source batch satisfies the next instruction.
        self.ensure_session_with(fs, &needed, needs_scratch)?;

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
        // `type=tmpfs` mounts: an empty RAM-backed fs at the target for the RUN's duration
        // (never committed to the layer). (target, size). Mounted after the binds, torn down
        // with them.
        let mut tmpfs: Vec<(String, Option<String>)> = Vec::new();
        for (i, m) in mounts.iter().enumerate() {
            // Scratch mounts are wired separately (mounted rw at the target, not bind-mounted).
            if m.spec.from.as_deref() == Some("scratch") {
                continue;
            }
            let source = m.spec.source.clone().unwrap_or_else(|| "/".into());
            let target = m
                .spec
                .target
                .clone()
                .context("RUN --mount=bind requires target=")?;
            if m.spec.typ == "tmpfs" {
                // tmpfs takes no from=/source; size= is its only honored option.
                tmpfs.push((target, m.spec.size.clone()));
                continue;
            }
            match m.from {
                Some(src_fs) => {
                    let dev = self.source_dev.get(&src_fs.label).with_context(|| {
                        format!("RUN --mount from={}: source not attached", src_fs.label)
                    })?;
                    let mp = format!("/mnt/m-{}-{i}", label_slug(&src_fs.label));
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
        // A RUN command is executed raw (Docker leaves it to the shell), so the in-scope
        // ENV and ARG are exported here for the shell to expand `$VAR` against.
        let mut script = String::new();
        for (k, v) in state.env.iter().chain(&state.build_args) {
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
        let sink = self.output_sink.clone();
        let session = self.session.as_ref().expect("session booted");
        // Mount the ephemeral writable scratch at its target (rw). Defaults to the ext4
        // root:root 0755 (like BuildKit); optional uid/gid/mode override it so a non-root RUN
        // can write. The agent validates and applies them (`-` = keep the default).
        if let Some(target) = &scratch_target {
            let dev = session
                .scratch_dev()
                .context("internal: from=scratch mount but no scratch disk attached")?;
            let spec = scratch.expect("scratch_target implies a scratch mount");
            let opt = |o: &Option<String>| o.clone().unwrap_or_else(|| "-".into());
            let ms = [
                GUEST_AGENT.to_string(),
                "mount".into(),
                "--scratch".into(),
                dev.to_string(),
                target.clone(),
                opt(&spec.uid),
                opt(&spec.gid),
                opt(&spec.mode),
            ];
            if block_on(session.exec(&ms, None, &sink))? != 0 {
                bail!("RUN --mount from=scratch: mounting the scratch device at {target} failed");
            }
        }
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
                if block_on(session.exec(&m1, None, &sink))? != 0 {
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
            if block_on(session.exec(&m2, None, &sink))? != 0 {
                bail!("RUN --mount: bind-mounting {bindsrc} at {target} failed");
            }
        }
        // Mount each tmpfs at its target: an empty RAM-backed fs for the RUN's duration,
        // torn down afterwards so nothing lands in the committed layer. `size=` caps it
        // (`-` = the kernel default, ½ RAM); the default 1777 mode lets a non-root RUN write.
        for (target, size) in &tmpfs {
            let ms = [
                GUEST_AGENT.to_string(),
                "mount".into(),
                "--tmpfs".into(),
                target.clone(),
                size.clone().unwrap_or_else(|| "-".into()),
            ];
            if block_on(session.exec(&ms, None, &sink))? != 0 {
                bail!("RUN --mount=type=tmpfs: mounting tmpfs at {target} failed");
            }
        }
        let code = block_on(session.exec(&argv, user, &sink))?;
        // Tear the mounts down (target before its device mountpoint), best-effort.
        for (device, _, target) in binds.iter().rev() {
            let _ = block_on(session.exec(
                &[GUEST_AGENT.to_string(), "umount".into(), target.clone()],
                None,
                &sink,
            ));
            if let Some((_, mp)) = device {
                let _ = block_on(session.exec(
                    &[GUEST_AGENT.to_string(), "umount".into(), mp.clone()],
                    None,
                    &sink,
                ));
            }
        }
        // Unmount the tmpfs mounts (best-effort); their RAM-backed contents are discarded.
        for (target, _) in &tmpfs {
            let _ = block_on(session.exec(
                &[GUEST_AGENT.to_string(), "umount".into(), target.clone()],
                None,
                &sink,
            ));
        }
        // Unmount the scratch target too, so its (discarded) contents don't shadow the target
        // path for the next step; the scratch device itself stays attached for the stage.
        if let Some(target) = &scratch_target {
            let _ = block_on(session.exec(
                &[GUEST_AGENT.to_string(), "umount".into(), target.clone()],
                None,
                &sink,
            ));
        }
        if code != 0 {
            bail!("RUN exited {code}: {shell}");
        }
        Ok(())
    }
    fn copy(&mut self, fs: &Rootfs, op: &Copy, from: Option<&Rootfs>, workdir: &str) -> Result<()> {
        let needed: Vec<&str> = from.map(|src| vec![src.label.as_str()]).unwrap_or_default();
        self.ensure_session_with(fs, &needed, false)?;
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
                let mp = format!("/mnt/src-{}", label_slug(&src.label));
                let session = self.session.as_ref().expect("session booted");
                let m = [
                    GUEST_AGENT.to_string(),
                    "mount".into(),
                    "--ro".into(),
                    dev,
                    mp.clone(),
                ];
                if block_on(session.exec(&m, None, &self.output_sink))? != 0 {
                    bail!("mounting source {} for COPY failed", src.label);
                }
                (mp.clone(), Some(mp))
            }
            None => (crate::run::CONTEXT_MOUNT.to_string(), None),
        };
        let session = self.session.as_ref().expect("session booted");
        // agent copy [--chown u:g] [--chmod OCTAL] [--ignore-root R] <root>/<src>... <dst>
        let mut argv = vec![GUEST_AGENT.to_string(), "copy".to_string()];
        // context COPY: apply the context's .dockerignore — for the stage's own context and
        // for a named build context alike (its directory is packed with its .dockerignore, and
        // the cache key already hashes only the files it does *not* ignore, so the copy must
        // match). A stage or image source is a committed rootfs, not a context: nothing is
        // ignored there.
        if from.is_none_or(is_context_source) {
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
        argv.push(resolve_copy_dest(&op.dest, workdir));
        let code = block_on(session.exec(&argv, None, &self.output_sink))?;
        if let Some(mp) = mount {
            let _ = block_on(session.exec(
                &[GUEST_AGENT.to_string(), "umount".into(), mp],
                None,
                &self.output_sink,
            ));
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
        self.images.lock().unwrap().remove(&fs.label);
        // Zero the superblock's volatile bookkeeping (write/mount/check times + the
        // kbytes-written/mount counters), so a fully-cached restore exports the same bytes as
        // the cold build that filled the cache. That is the whole guarantee: an uncached rebuild
        // of this stage does not reproduce the bytes (see `normalize_superblock`).
        crate::ext4::normalize_superblock(out)?;
        // Left journal-less here deliberately (a journal is dead weight under the
        // rw-overlay build runtime and churns every snapshot): the caller stamps the
        // content-freshness UUID next, and `ext4::set_uuid` refuses an already-journaled
        // image (the JBD2 superblock embeds the UUID at journal creation), so `journal:
        // true` in `Options` is applied by the caller, via `ext4::add_journal`, only after
        // that stamp — never here.
        Ok(())
    }

    fn cache_has(&mut self, key: &str) -> bool {
        // Keys marked non-cacheable (a `vk build --disk` stage, whose disk output is an
        // external side effect the cache does not capture) never hit — restoring would
        // skip the disk-writing RUNs.
        if self.uncacheable_keys.contains(key) {
            return false;
        }
        match &self.cache {
            Some(rg) => crate::registry::exists(rg, CACHE_REPO, key),
            None => false,
        }
    }
    fn build_lock(
        &mut self,
        key: &str,
        on_wait: &mut dyn FnMut(&str),
    ) -> Option<crate::registry::BuildLock> {
        // Namespace the lock key by the cache repo so unrelated stores don't collide.
        crate::registry::build_lock(
            self.cache.as_ref()?,
            &format!("{CACHE_REPO}/{key}"),
            on_wait,
        )
    }
    fn check_build_failure(&mut self, key: &str) -> Option<vk_registry::FailInfo> {
        crate::registry::check_build_failure(self.cache.as_ref()?, &format!("{CACHE_REPO}/{key}"))
    }
    fn report_build_failure(&mut self, key: &str, reason: &str) {
        if let Some(rg) = self.cache.as_ref() {
            crate::registry::report_build_failure(rg, &format!("{CACHE_REPO}/{key}"), reason);
        }
    }
    fn cache_restore(&mut self, fs: &Rootfs, key: &str) -> Result<()> {
        let Some(rg) = self.cache.clone() else {
            bail!("cache_restore with no cache registry");
        };
        // pull the snapshot's ext4 (chunk-cached, byte-exact) — or, when lazy restore
        // applies, a `.vk_ro_img` view over it — then wrap it in a rw qcow2 so any remaining
        // instructions can boot it directly and write into the overlay.
        let (base, digest) = if self.lazy_restore_enabled() {
            let lazy = self.lazy_image_path(&fs.label);
            let Some(digest) =
                crate::registry::try_pull_ext4_lazy(&rg, CACHE_REPO, key, &lazy, &fs.label)?
            else {
                bail!("cached instruction {key} vanished from the registry");
            };
            // Same check the eager branch runs below, against the view the guest will read.
            self.verify_lazy_view(&lazy, &format!("cached instruction {key} (after load)"))?;
            (lazy, digest)
        } else {
            let ext4 = self.image_path(&fs.label);
            let Some(digest) =
                crate::registry::try_pull_ext4(&rg, CACHE_REPO, key, &ext4, &fs.label)?
            else {
                bail!("cached instruction {key} vanished from the registry");
            };
            // `--debug`: a reassembled snapshot must be a clean ext4 before the build boots
            // or forks it — else a corrupt cache entry (bad chunks / a poisoned push)
            // silently becomes a corrupt image or an EUCLEAN mid-build.
            self.verify_ext4(&ext4, &format!("cached instruction {key} (after load)"))?;
            (ext4, digest)
        };
        self.wrap_base(&fs.label, &base)?;
        // the restored snapshot is the parent the next save diffs against — pin its digest.
        self.parent_digest = Some(digest);
        Ok(())
    }
    fn cache_save(&mut self, fs: &Rootfs, key: &str) -> Result<()> {
        // Don't cache a non-cacheable key (a `--disk` stage): a later build restoring it
        // would skip the disk-writing RUNs.
        if self.uncacheable_keys.contains(key) {
            return Ok(());
        }
        let Some(rg) = self.cache.clone() else {
            return Ok(());
        };
        self.last_saved_key
            .insert(fs.label.clone(), key.to_string());
        let boot_kind =
            crate::image::boot_kind_tag(crate::image::BootKind::GenericDisk).to_string();

        // No live guest (rare: a metadata-only instruction never booted a VM). The static
        // stage image is a stable qcow2, so push it synchronously — its whole data set is the
        // "delta" (deduped against the parent chain), no freeze/copy needed.
        if self.session.is_none() {
            let img = self.stage_image(fs)?;
            self.verify_snapshot(&img, &format!("snapshot of {key} (before upload)"))?;
            let (cumulative, total_size) = {
                let mut q = crate::qcow2::Qcow2::open(&img)?;
                (q.data_extents()?, q.virtual_size())
            };
            return self.push_snapshot_sync(
                &rg,
                fs,
                key,
                &boot_kind,
                &img,
                &cumulative,
                total_size,
            );
        }

        // Live guest with block-level dirty tracking (libkrun): freeze the fs, drain the clusters
        // the block device recorded this interval (folding in any carried across mid-stage
        // reboots), and push exactly those on a background thread — the per-interval delta, no
        // whole-stage re-chunk. Same async shape as cloud-hypervisor, so the guest is only frozen
        // for the (delta-sized) copy. The delta is guarded by the allocation map: every cluster
        // newly allocated this interval must be in the dirty set (a write can't reach the disk
        // without allocating its cluster), else it is a dropped write and the build aborts —
        // FATAL, so a lossy set can never cache a stale delta.
        if self.session.as_ref().is_some_and(|s| s.supports_dirty()) {
            // Discard blocks freed since the last checkpoint *before* quiescing (a frozen fs
            // rejects the discard), so the allocation map below lists only live data — a file
            // created and deleted within this interval never enters the delta.
            block_on(self.session.as_ref().unwrap().trim());
            let frozen = block_on(self.session.as_ref().unwrap().freeze());
            // Drain + gap-check + copy while frozen; defer any error past the thaw so the guest is
            // never left frozen on a failure.
            let prepared = (|| -> Result<CapturedDelta> {
                let (image, written, discarded, cumulative, total_size) = {
                    let session = self.session.as_ref().unwrap();
                    let (written, discarded) = session.drain_dirty()?;
                    let image = session.image().to_path_buf();
                    let mut q = crate::qcow2::Qcow2::open(&image)?;
                    // The overlay's allocated clusters — ground truth for what the guest wrote,
                    // since a write cannot reach the disk without allocating its cluster.
                    let cumulative = q.data_extents()?;
                    (image, written, discarded, cumulative, q.virtual_size())
                };
                // Fold in anything drained across mid-stage reboots since the last checkpoint
                // (last-operation-wins), then reset the carry — so the set is per-checkpoint, not
                // per-VM-boot. `written` is read and pushed as data; `discarded` becomes holes.
                let carried = self.dirty_carry.remove(&fs.label).unwrap_or_default();
                let (written, discarded) = merge_dirty(carried, (written, discarded));
                // Guard the delta: every cluster newly allocated this interval (`cumulative -
                // prev`) MUST have been touched (written or discarded), since a mutation cannot
                // reach the disk without allocating its cluster. Any that wasn't is a write the
                // side-channel dropped — pushing then would cache a stale delta, so abort loudly.
                let touched = coalesce_ranges([written.clone(), discarded.clone()].concat());
                let prev = self
                    .stage_prev_extents
                    .get(&fs.label)
                    .cloned()
                    .unwrap_or_default();
                let missed = subtract_ranges(&subtract_ranges(&cumulative, &prev), &touched);
                if !missed.is_empty() {
                    let bytes: u64 = missed.iter().map(|&(_, l)| l).sum();
                    bail!(
                        "dirty-tracking gap at {key}: {} newly-allocated extent(s) ({bytes} bytes) \
                         were written but absent from the block device's dirty set. First: {:?}",
                        missed.len(),
                        missed.iter().take(6).collect::<Vec<_>>()
                    );
                }
                // Data to read and push: written clusters the snapshot still holds. Clamping to
                // the allocation map drops a written-then-freed cluster (deallocated, so a read
                // would fail) and keeps the delta to what actually changed. A discarded cluster is
                // never read — it is pushed as a hole below, so the reassembly clears the parent's
                // stale bytes there instead of reusing them.
                let delta = intersect_ranges(&written, &cumulative);
                let holes = subtract_ranges(&discarded, &delta);
                self.stage_prev_extents.insert(fs.label.clone(), cumulative);
                // A stable, standalone copy the background push reads after the guest resumes.
                self.push_seq += 1;
                let snap = self.image_path(&format!("{}.{}.cap.qcow2", fs.label, self.push_seq));
                std::fs::copy(&image, &snap).with_context(|| {
                    format!("copying {} -> {}", image.display(), snap.display())
                })?;
                self.verify_snapshot(&snap, &format!("snapshot of {key} (before upload)"))?;
                Ok((snap, delta, holes, total_size))
            })();
            block_on(self.session.as_ref().unwrap().thaw(frozen));
            let (snap, delta, holes, total_size) = prepared?;

            // Push on a background thread; it overlaps the next instruction's RUN. Ordering +
            // parent chaining as in the cloud-hypervisor path below.
            self.harvest_prev_push(&fs.label);
            let (parent_layers, parent_total) = self.parent_for_push(&rg, total_size);
            let snap_push = snap.clone();
            let key_s = key.to_string();
            let boot_kind = boot_kind.clone();
            let rg = rg.clone();
            let timings = Arc::clone(&self.timings);
            let handle = std::thread::spawn(move || -> PushOutput {
                let t = std::time::Instant::now();
                let (layers, total, digest) = crate::registry::push_ext4_diff(
                    &rg,
                    CACHE_REPO,
                    &key_s,
                    &snap_push,
                    &boot_kind,
                    parent_total,
                    &delta,
                    &holes,
                    &parent_layers,
                )?;
                timings.probe("cache.push", t.elapsed());
                Ok(((layers, total), digest))
            });
            self.inflight = Some(PushInflight { handle, snap });
            return Ok(());
        }

        // Cloud-hypervisor (no dirty hook): capture a stable point-in-time copy of the live
        // overlay (freeze + copy, to a qcow2), then diff + push it on a background thread that
        // overlaps the next instruction's RUN. The copy is the only synchronous part — the live
        // overlay keeps moving once the next RUN starts, so it must happen now; the diff/push read
        // the copy natively, off this thread. (Session borrow scoped so the `&mut self` is free.)
        self.push_seq += 1;
        let snap = self.image_path(&format!("{}.{}.cap.qcow2", fs.label, self.push_seq));
        // Discard blocks freed since the last checkpoint before capturing (a frozen fs rejects
        // the discard, so this runs ahead of `capture`'s freeze), so a file created and deleted
        // within this interval is released to holes and never enters the delta.
        block_on(self.session.as_ref().expect("session present").trim());
        block_on(
            self.session
                .as_ref()
                .expect("session present")
                .capture(&snap, &self.timings),
        )?;
        self.verify_snapshot(&snap, &format!("snapshot of {key} (before upload)"))?;
        // Native qcow2 read: the overlay's own clusters (cumulative dirty) + its size.
        let (cumulative, total_size) = {
            let mut q = crate::qcow2::Qcow2::open(&snap)?;
            (q.data_extents()?, q.virtual_size())
        };
        // Per-instruction delta: diff this capture against the previous one (the in-flight
        // push's qcow2) within the cumulative bound — the overlay is cumulative, so this
        // recovers just what this instruction changed.
        let dirty = match &self.inflight {
            // `within` is `snap`'s own allocation, so a block new to `snap` is dirty by
            // construction — the read-skip is sound here.
            Some(inf) => content_diff(&inf.snap, &snap, &cumulative, true)?,
            None => cumulative,
        };

        // Reap the previous push (it ran during this instruction's RUN + capture, so it is
        // usually already done): harvest its layers as the in-memory parent and free its
        // capture — content_diff above was its last reader.
        self.harvest_prev_push(&fs.label);

        let (parent_layers, parent_total) = self.parent_for_push(&rg, total_size);

        // Spawn the push on a background thread; it overlaps the next instruction's RUN.
        // Within a stage only one push runs at a time (joined above before the next is
        // spawned), so this stage's parent-layer chain stays ordered. Across concurrent
        // stages (the parallel driver) several pushes may hit the store at once; that is
        // safe — the store is content-addressed and writes atomically (temp + rename), and a
        // dependent that reads a stage's chunks (a `FROM <stage>` fork) joins that stage's
        // push (join_pending) before it fetches them.
        let snap_push = snap.clone();
        let key_s = key.to_string();
        let timings = Arc::clone(&self.timings);
        let handle = std::thread::spawn(move || -> PushOutput {
            let t = std::time::Instant::now();
            let (layers, total, digest) = crate::registry::push_ext4_diff(
                &rg,
                CACHE_REPO,
                &key_s,
                &snap_push,
                &boot_kind,
                parent_total,
                &dirty,
                &[],
                &parent_layers,
            )?;
            timings.probe("cache.push", t.elapsed());
            Ok(((layers, total), digest))
        });
        self.inflight = Some(PushInflight { handle, snap });
        Ok(())
    }

    fn base_config(&mut self, image: &str) -> Result<crate::oci::ImageConfig> {
        block_on(crate::oci::pull_config(
            image,
            &crate::oci::Creds::anonymous(),
        ))
    }

    fn resolve_base_digest(&mut self, image: &str) -> Option<String> {
        base_digest(image)
    }

    fn stage_sources(&mut self, sources: &[Rootfs], context: &Path) -> Result<()> {
        // Resolve source stages to their ext4s in first-use order. Guest devices are
        // assigned per boot, because large stages attach only a budget-sized subset.
        self.sources.clear();
        self.source_dev.clear();
        for s in sources {
            self.sources.push((s.label.clone(), self.stage_image(s)?));
        }
        self.context = Some(context.to_path_buf());
        Ok(())
    }

    fn stage_end(&mut self, fs: &Rootfs, final_key: Option<&str>) -> Result<()> {
        // Only the key the stage's last step actually pushed can be re-pushed below; without one
        // (no cache, an uncacheable stage, a stage whose last step never saved) there is nothing
        // to correct and no reason to bother the guest.
        let repushable = final_key
            .is_some_and(|k| self.last_saved_key.get(&fs.label).map(String::as_str) == Some(k));
        // Whether the shutdown's `cleanup` will still change the image. Asked before the
        // shutdown, because answering it needs the agent, which is reachable only as
        // `/proc/self/exe` — i.e. only while `/proc` is still one of the mountpoints cleanup is
        // about to drop. Exit 0 = yes, so the snapshot pushed mid-stage no longer describes the
        // image this stage hands on.
        let cleanup_changes_image = repushable
            && match self.session.as_ref() {
                None => false,
                Some(session) => {
                    let argv = [GUEST_AGENT.to_string(), "cleanup-pending".to_string()];
                    match block_on(session.exec(&argv, None, &self.output_sink)) {
                        Ok(code) => code == 0,
                        Err(e) => {
                            // Not knowing leaves the mid-stage snapshot published under this
                            // stage's final key, so a later cached build would ship bytes the
                            // export does not have. Say so rather than diverge silently.
                            eprintln!(
                                "virtkit: build: could not ask the guest whether its shutdown \
                                 changes the image ({e:#}) — this stage's cache entry may not \
                                 match the exported image"
                            );
                            false
                        }
                    }
                }
            };
        // The stage's last step always checkpoints (consuming its carry), but drop any remainder
        // so a fresh stage on this worker never inherits a stale carry.
        self.dirty_carry.remove(&fs.label);
        // Hand the stage's last cache push to the shared pool instead of blocking on its upload
        // here. The last step has no next instruction to overlap it, so joining it now would
        // stall this worker on the whole last-layer upload; parking it lets the worker move on
        // to the next DAG stage. A `FROM <stage>` fork joins it before diffing against its chunks
        // (join_pending); everything else drains at build end (PushPool's Drop). A COPY --from
        // consumer reads this stage's local image, not the registry, so it needs no join.
        if let Some(inf) = self.inflight.take() {
            self.pending.insert(fs.label.clone(), inf);
        }
        // Shut the stage's guest down cleanly; its writes are already in the stage image
        // (the booted disk), so later stages / the export see them with no commit step.
        if let Some(session) = self.session.take() {
            self.record_stage_mem(&fs.label, &session);
            let t_fin = std::time::Instant::now();
            block_on(session.finish())?;
            self.timings.probe("stage.finish", t_fin.elapsed());
        }
        // The shutdown just dropped the ephemeral mountpoints and stubs from the image, so the
        // snapshot pushed for the last step — captured mid-stage, while they still had to exist —
        // no longer matches what this stage hands on. Re-push that key from the finished image:
        // a fully-cached restore ships its snapshot verbatim without ever booting a guest that
        // could clean it, so leaving the mid-stage one there is what made a cached build's
        // artifact differ from a cold build's. `repushable` pinned this to the key the last step
        // already saved, so this can never publish content under a key not meant to hold it.
        if cleanup_changes_image && let Some(key) = final_key {
            // The mid-stage push for this key may still be uploading; let it land first so its
            // manifest cannot overwrite the one below.
            self.join_pending(&fs.label);
            // Diff against the snapshot being replaced rather than the previous step's, so the
            // re-push is a near-empty delta: `join_pending` records that digest but, unlike
            // `harvest_prev_push`, does not pin it as the parent. A failed push leaves none
            // recorded, and the older pinned digest still yields a complete manifest.
            let pushed = self
                .stage_last_digest
                .lock()
                .unwrap()
                .get(&fs.label)
                .cloned();
            if pushed.is_some() {
                self.parent_digest = pushed;
            }
            // The guest is gone, so `cache_save` takes its static-image path: the whole stage
            // image, deduped against the parent chain, pushed synchronously.
            self.cache_save(fs, key)?;
        }
        self.last_saved_key.remove(&fs.label);
        if let Some(tmp) = self.tmp_disk.take() {
            let _ = std::fs::remove_file(tmp);
        }
        if let Some(scratch) = self.scratch_disk.take() {
            let _ = std::fs::remove_file(scratch);
        }
        // the next stage starts a fresh cache lineage; clear its attached sources, its
        // context, and the in-memory parent layers.
        self.parent_layers = None;
        self.sources.clear();
        self.source_dev.clear();
        self.context = None;
        // Drop the per-stage image-kernel selection and its extracted boot scratch.
        self.stage_image_kernel = false;
        if let Some(boot) = self.image_kernel_boot.take() {
            let _ = std::fs::remove_file(&boot.kernel);
            let _ = std::fs::remove_file(&boot.initramfs);
        }
        Ok(())
    }

    fn set_output_sink(&mut self, sink: crate::executor::OutputSink) {
        self.output_sink = sink;
    }
    fn set_cancel(&mut self, cancel: CancellationToken) {
        self.cancel = Some(cancel);
    }
    fn stage_kernel(&mut self, image_kernel: bool) {
        self.stage_image_kernel = image_kernel;
        // A stale extraction from a prior stage on this worker must never leak in.
        if let Some(boot) = self.image_kernel_boot.take() {
            let _ = std::fs::remove_file(&boot.kernel);
            let _ = std::fs::remove_file(&boot.initramfs);
        }
    }
}

/// Single-quote a value for a `/bin/sh` script (wrap in `'…'`, escaping embedded `'`).
fn shell_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Host backend for the no-`RUN` subset (`FROM scratch` + `COPY`): each stage is a
/// real host directory, `COPY` is a host-side file copy, and the export is virtkit's
/// own pure-Rust ext4 builder ([`crate::ext4::build_from_dir`]) — no docker, no
/// buildkit, no `mke2fs`, no VM. `RUN` and `FROM <image>` need the microVM/OCI path
/// and error here. This is the end-to-end "Dockerfile → ext4 with only virtkit" PoC.
pub struct Host {
    /// Scratch root holding each stage's directory (`<scratch>/<stage>`).
    scratch: PathBuf,
    /// Build context root that `COPY <src>` (no `--from`) resolves against — set per
    /// stage by `stage_sources` before any instruction runs; `None` until then.
    context: Option<PathBuf>,
    /// stage label → its host directory.
    dirs: HashMap<String, PathBuf>,
}

impl Host {
    pub fn new(scratch: PathBuf) -> Self {
        Host {
            scratch,
            context: None,
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
        let dir = self.scratch.join(label_slug(stage));
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
    fn context_source(&mut self, name: &str, dir: &Path) -> Result<Rootfs> {
        // No packing needed: this backend copies host-to-host, so the context directory
        // *is* the source tree (registered under the same label the microVM backend uses).
        let label = context_source_label(name);
        self.dirs.insert(label.clone(), dir.to_path_buf());
        Ok(Rootfs { label })
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
    fn stage_sources(&mut self, _sources: &[Rootfs], context: &Path) -> Result<()> {
        self.context = Some(context.to_path_buf());
        Ok(())
    }
    fn copy(&mut self, fs: &Rootfs, op: &Copy, from: Option<&Rootfs>, workdir: &str) -> Result<()> {
        let src_root = match from {
            Some(r) => self.stage_dir(r)?,
            None => self
                .context
                .clone()
                .context("internal: copy before stage_sources set the context")?,
        };
        let dest_root = self.stage_dir(fs)?;
        // A relative dest is resolved against the active WORKDIR (Docker semantics), then
        // under the rootfs root; a trailing '/' or multiple sources mean dest is a directory.
        let rdest = resolve_copy_dest(&op.dest, workdir);
        let dest = dest_root.join(rdest.trim_start_matches('/'));
        let dest_is_dir = rdest.ends_with('/') || op.sources.len() > 1;
        for s in &op.sources {
            // sources resolve under the source root like dest does under the rootfs
            // root — an absolute source (the COPY --from=<stage> idiom) must not
            // escape to the host (`join` would replace the root with it).
            let rel = s.trim_start_matches('/');
            let src = src_root.join(rel.strip_prefix("./").unwrap_or(rel));
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
        // The exported image has to be a function of the staged tree alone. `std::fs::copy`
        // does not carry an mtime across and a freshly created directory carries the clock,
        // so without this the wall-clock second of the build leaks into the image's inode
        // timestamps (`build_from_dir` reads them from the tree) — making two builds of one
        // tree differ whenever they fall either side of a tick.
        stamp_epoch_tree(&dir)?;
        crate::ext4::build_from_dir(&dir, out)
    }
}

/// Set the atime and mtime of every entry in the tree at `path` — the root included — to
/// the epoch, so the mtimes the ext4 builder reads out of the tree are a function of its
/// shape and not of when the build ran.
fn stamp_epoch_tree(path: &Path) -> Result<()> {
    // `symlink_metadata` (not `metadata`) and `AT_SYMLINK_NOFOLLOW` keep both the walk and
    // the stamp on the link itself: a symlink's own mtime is what the ext4 builder reads for
    // it, and a staged tree can hold an absolute symlink copied verbatim out of the build
    // context — following one would leave the scratch dir and zero a *host* file's mtime.
    // Re-resolving the path per syscall is safe here only because nothing else writes the
    // scratch stage dir while the export runs — `read_dir` would follow a symlink swapped in
    // for a directory. `File::set_times` cannot do this job: there is no fd for a symlink.
    if std::fs::symlink_metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .is_dir()
    {
        for entry in
            std::fs::read_dir(path).with_context(|| format!("reading {}", path.display()))?
        {
            stamp_epoch_tree(&entry?.path())?;
        }
    }
    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("{} has an interior NUL", path.display()))?;
    let epoch = [libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    }; 2];
    // SAFETY: `cpath` is a valid NUL-terminated path and `epoch` a 2-element timespec array,
    // both alive across the call; utimensat returns 0 or -1 with errno set.
    let rc = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            cpath.as_ptr(),
            epoch.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("stamping {}", path.display()));
    }
    Ok(())
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
    // Temp dirs are minted over in `build`'s tests, so the tags here share one namespace with
    // the tags there — keep any tag added here distinct from both.
    use crate::build::tests::tmpdir;

    /// `base_cache_key` must actually fold in `CACHE_KEY_VERSION`, not just carry it in a
    /// doc comment — mirrors `build::tests::hash_key_is_salted_by_the_cache_key_version`
    /// for this crate's other root cache key: a change that silently stopped salting it
    /// would leave old, possibly-corrupt base-image cache entries resolving forever. The
    /// reference hash folds in the namespace label, so the version salt is the only
    /// difference between the two — and dropping it is the only way they can agree.
    #[test]
    fn base_cache_key_is_salted_by_the_cache_key_version() {
        use sha2::{Digest, Sha256};
        let unsalted = {
            let mut h = Sha256::new();
            h.update(b"base\n");
            h.update(b"FROM image ");
            h.update(b"alpine:3.20");
            let mut s = String::from("base-");
            for b in h.finalize() {
                s.push_str(&format!("{b:02x}"));
            }
            s
        };
        assert_ne!(base_cache_key("alpine:3.20"), unsalted);
    }

    // `DryRun` never overrides `check_build_failure`/`report_build_failure`, so it exercises
    // the `Executor` trait's own defaults — a backend with no remote vk-registry (dry-run,
    // planning, or a plain local build) must never see a memoized failure and must accept
    // reporting one as a silent no-op, not an error.
    #[test]
    fn a_backend_without_a_remote_registry_never_memoizes_a_build_failure() {
        let mut ex = DryRun::new();
        assert!(
            ex.check_build_failure("some-key").is_none(),
            "the default check must never claim a memoized failure"
        );
        ex.report_build_failure("some-key", "boom"); // must not panic
    }

    #[test]
    fn a_base_digest_is_resolved_once_per_process() {
        // Every key computation over one `build:` unit — addressing it, building it, and
        // `vk list --stale` re-checking it — goes through this memo, so each base costs one
        // registry request per process. A failure is remembered too, and that is the part
        // that matters: keying by the bare ref for one computation and by a digest for the
        // next would give one set of sources two keys. Refs unique to this test, since the
        // memo is process-wide and tests share it.
        let hit = "vk-memo-test/hit:1";
        assert_eq!(
            memoized_digest(hit, || Some("sha256:aa".to_string())),
            Some("sha256:aa".to_string())
        );
        assert_eq!(
            memoized_digest(hit, || panic!("resolved a second time")),
            Some("sha256:aa".to_string())
        );
        let miss = "vk-memo-test/miss:1";
        assert_eq!(memoized_digest(miss, || None), None);
        assert_eq!(
            memoized_digest(miss, || panic!("re-resolved a failure")),
            None
        );
    }

    // Which sources a COPY filters through a `.dockerignore` rides entirely on this predicate:
    // read a stage or an image as a context and the copy would drop files the key counted, read
    // a context as a stage and it would copy files the key never saw.
    #[test]
    fn is_context_source_only_matches_a_named_context_label() {
        let fs = |label: &str| Rootfs {
            label: label.to_string(),
        };
        assert!(is_context_source(&fs(&context_source_label("shared"))));
        // A stage — bare, or prefixed by its build unit — is a committed rootfs, not a context.
        assert!(!is_context_source(&fs("build")));
        assert!(!is_context_source(&fs("web:build")));
        // Nor is an external image, even one whose ref itself starts with `context/`.
        assert!(!is_context_source(&fs(&image_source_label(
            "context/shared:16"
        ))));
    }

    #[test]
    fn source_dev_shifts_to_vdc_with_out_disk() {
        // No --disk: rootfs is vda, sources start at vdb.
        assert_eq!(source_dev_path(0, false), "/dev/vdb");
        assert_eq!(source_dev_path(1, false), "/dev/vdc");
        // --disk: the target disk takes vdb, so sources shift one later to vdc+.
        assert_eq!(source_dev_path(0, true), "/dev/vdc");
        assert_eq!(source_dev_path(1, true), "/dev/vdd");
    }

    #[test]
    fn coalesce_merges_touching_and_overlapping() {
        assert_eq!(
            coalesce_ranges(vec![(10, 5), (0, 4), (4, 6), (100, 0), (15, 5)]),
            vec![(0, 20)] // 0-4, 4-10, 10-15, 15-20 all touch; empty dropped
        );
        assert_eq!(
            coalesce_ranges(vec![(0, 4), (10, 4), (6, 2)]),
            vec![(0, 4), (6, 2), (10, 4)] // gaps preserved
        );
    }

    #[test]
    fn subtract_isolates_the_uncovered_parts() {
        // a fully covered by b → nothing missed
        assert!(subtract_ranges(&[(0, 10)], &[(0, 20)]).is_empty());
        // a disjoint from b → all of a missed
        assert_eq!(subtract_ranges(&[(0, 10)], &[(20, 5)]), vec![(0, 10)]);
        // b carves a hole in the middle and clips an edge
        assert_eq!(
            subtract_ranges(&[(0, 100)], &[(10, 10), (50, 10)]),
            vec![(0, 10), (20, 30), (60, 40)]
        );
        // the newly-allocated-minus-dirty case: dirty covered the first cluster only
        assert_eq!(
            subtract_ranges(&[(0, 65536), (65536, 65536)], &[(0, 65536)]),
            vec![(65536, 65536)]
        );
    }

    #[test]
    fn merge_dirty_lets_writes_win() {
        let cl = 65536u64;
        // base wrote clusters 0 and 1; newer discards 1 and 2 and writes 3.
        let base = (vec![(0, cl), (cl, cl)], vec![]);
        let newer = (vec![(3 * cl, cl)], vec![(cl, cl), (2 * cl, cl)]);
        let (written, discarded) = merge_dirty(base, newer);
        // 0,1,3 are written (1 stays written despite the newer discard); only 2 is a hole.
        assert_eq!(written, vec![(0, 2 * cl), (3 * cl, cl)]);
        assert_eq!(discarded, vec![(2 * cl, cl)]);

        // A write of a cluster discarded in the other set keeps it written, not holed.
        let base = (vec![], vec![(0, cl)]);
        let newer = (vec![(0, cl)], vec![]);
        assert_eq!(merge_dirty(base, newer), (vec![(0, cl)], vec![]));
    }

    #[test]
    fn resolve_build_cpus_prefers_configured_over_host() {
        // A configured positive value wins and is honoured uncapped.
        assert_eq!(resolve_build_cpus(Some(8), 4), 8);
        assert_eq!(resolve_build_cpus(Some(64), 8), 64);
        // Unset or zero falls back to the host count.
        assert_eq!(resolve_build_cpus(None, 8), 8);
        assert_eq!(resolve_build_cpus(Some(0), 8), 8);
        // The host-derived default is clamped to 16; an explicit value is not.
        assert_eq!(resolve_build_cpus(None, 64), 16);
    }

    #[test]
    fn resolve_build_mem_defaults_to_4g_and_round_trips() {
        // Unset or blank yields the 4G default, which parses back to 4096 MiB.
        assert_eq!(resolve_build_mem(None), "4G");
        assert_eq!(resolve_build_mem(Some("   ")), "4G");
        assert_eq!(
            crate::run::parse_mem_mib(&resolve_build_mem(None)),
            Some(4096)
        );
        // A set value is trimmed and passed through verbatim.
        assert_eq!(resolve_build_mem(Some(" 8G ")), "8G");
        assert_eq!(resolve_build_mem(Some("2048")), "2048");
    }

    #[test]
    fn resolve_copy_dest_honours_workdir() {
        // Absolute dest: used verbatim, whatever the workdir.
        assert_eq!(resolve_copy_dest("/opt/app", "/w"), "/opt/app");
        // Relative dest: resolved against WORKDIR (the reported bug — `.` landed at /).
        assert_eq!(resolve_copy_dest(".", "/w"), "/w/");
        assert_eq!(resolve_copy_dest("./s.sh", "/w"), "/w/s.sh");
        assert_eq!(resolve_copy_dest("s.sh", "/w"), "/w/s.sh");
        // A trailing slash (directory target) is preserved.
        assert_eq!(resolve_copy_dest("sub/", "/w"), "/w/sub/");
        // WORKDIR = / (or a trailing slash on it) must not double the separator.
        assert_eq!(resolve_copy_dest("s.sh", "/"), "/s.sh");
        assert_eq!(resolve_copy_dest(".", "/"), "/");
        assert_eq!(resolve_copy_dest("s.sh", "/w/"), "/w/s.sh");
        // A relative WORKDIR is stored verbatim (not stacked), so it yields a relative dest —
        // consistent with RUN using WORKDIR as its cwd from /.
        assert_eq!(resolve_copy_dest("s.sh", "w"), "w/s.sh");
    }

    #[test]
    fn scratch_mount_target_enforces_the_from_scratch_contract() {
        let mount = |from: Option<&str>, target: Option<&str>| Mount {
            typ: "bind".into(),
            from: from.map(str::to_string),
            target: target.map(str::to_string),
            ..Mount::default()
        };

        // No mounts, or only stage/context binds → no scratch target, no error.
        assert_eq!(scratch_mount_target(&[]).unwrap(), None);
        let stage = mount(Some("builder"), Some("/in"));
        assert_eq!(scratch_mount_target(&[&stage]).unwrap(), None);

        // A single from=scratch mount returns its target.
        let scratch = mount(Some("scratch"), Some("/s"));
        assert_eq!(
            scratch_mount_target(&[&scratch]).unwrap(),
            Some("/s".into())
        );

        // from=scratch without a target is rejected.
        let no_target = mount(Some("scratch"), None);
        assert!(scratch_mount_target(&[&no_target]).is_err());

        // Two from=scratch mounts in one step are rejected (they share one device).
        let scratch2 = mount(Some("scratch"), Some("/s2"));
        assert!(scratch_mount_target(&[&scratch, &scratch2]).is_err());

        // rw on a non-scratch mount is rejected.
        let rw_stage = Mount {
            rw: true,
            ..mount(Some("builder"), Some("/in"))
        };
        assert!(scratch_mount_target(&[&rw_stage]).is_err());

        // uid/gid/mode on a non-scratch mount is rejected.
        for spec in [
            Mount {
                uid: Some("1000".into()),
                ..mount(Some("builder"), Some("/in"))
            },
            Mount {
                gid: Some("1000".into()),
                ..mount(None, Some("/in"))
            },
            Mount {
                mode: Some("0700".into()),
                ..mount(None, Some("/in"))
            },
        ] {
            assert!(scratch_mount_target(&[&spec]).is_err());
        }

        // A tmpfs mount is exempt from the read-only checks (writable by nature, only size=
        // honored) and is not a scratch target.
        let tmpfs = Mount {
            typ: "tmpfs".into(),
            target: Some("/cache".into()),
            size: Some("1g".into()),
            ..Mount::default()
        };
        assert_eq!(scratch_mount_target(&[&tmpfs]).unwrap(), None);
        // uid/gid/mode are not honored on tmpfs, so they are rejected rather than ignored.
        for spec in [
            Mount {
                uid: Some("1000".into()),
                ..tmpfs.clone()
            },
            Mount {
                mode: Some("0700".into()),
                ..tmpfs.clone()
            },
        ] {
            assert!(scratch_mount_target(&[&spec]).is_err());
        }
        // A tmpfs alongside a from=scratch mount still yields the scratch target.
        assert_eq!(
            scratch_mount_target(&[&tmpfs, &scratch]).unwrap(),
            Some("/s".into())
        );

        // The same options on the from=scratch mount are accepted.
        let scratch_opts = Mount {
            rw: true,
            uid: Some("1000".into()),
            gid: Some("1000".into()),
            mode: Some("0700".into()),
            ..mount(Some("scratch"), Some("/s"))
        };
        assert_eq!(
            scratch_mount_target(&[&scratch_opts]).unwrap(),
            Some("/s".into())
        );
    }

    fn source_labels(batch: &[(String, PathBuf)]) -> Vec<String> {
        batch.iter().map(|(label, _)| label.clone()).collect()
    }

    fn test_sources(n: usize) -> Vec<(String, PathBuf)> {
        (0..n)
            .map(|i| (format!("s{i}"), PathBuf::from(format!("/tmp/s{i}.ext4"))))
            .collect()
    }

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
                ..Default::default()
            },
        )
        .unwrap();
        ex.export_ext4(&base, Path::new("/tmp/out.ext4")).unwrap();
        assert_eq!(ex.transcript[0], "from-image build (debian:bookworm)");
        assert!(ex.transcript[1].contains("apt-get update"));
        assert!(ex.transcript[2].starts_with("export-ext4"));
    }

    #[test]
    fn source_batch_slides_forward_in_first_use_order() {
        let n = MAX_SOURCE_DISKS + 7;
        let sources = test_sources(n);

        let first = select_source_batch(&sources, &["s0"], "app", MAX_SOURCE_DISKS).unwrap();
        assert_eq!(
            source_labels(&first),
            (0..MAX_SOURCE_DISKS)
                .map(|i| format!("s{i}"))
                .collect::<Vec<_>>()
        );

        let next_label = format!("s{MAX_SOURCE_DISKS}");
        let second =
            select_source_batch(&sources, &[next_label.as_str()], "app", MAX_SOURCE_DISKS).unwrap();
        assert_eq!(
            source_labels(&second),
            (MAX_SOURCE_DISKS..n)
                .map(|i| format!("s{i}"))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn source_batch_keeps_scattered_needed_sources() {
        // Two needed sources farther apart than one forward window forces the scatter path.
        let n = MAX_SOURCE_DISKS + 8;
        let sources = test_sources(n);
        let far = format!("s{}", n - 1);
        let batch =
            select_source_batch(&sources, &["s0", far.as_str()], "app", MAX_SOURCE_DISKS).unwrap();
        let labels = source_labels(&batch);

        assert!(labels.iter().any(|label| label == "s0"));
        assert!(labels.contains(&far));
        assert!(labels.len() <= MAX_SOURCE_DISKS);
    }

    #[test]
    fn source_batch_with_no_needed_sources_takes_the_first_window() {
        // A context-only instruction needs no source stage; the batch still fills the boot
        // with the leading window so a later source-using instruction can likely reuse it.
        let sources = test_sources(MAX_SOURCE_DISKS + 8);
        let batch = select_source_batch(&sources, &[], "app", MAX_SOURCE_DISKS).unwrap();
        assert_eq!(
            source_labels(&batch),
            (0..MAX_SOURCE_DISKS)
                .map(|i| format!("s{i}"))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn source_batch_rejects_single_instruction_over_budget() {
        let sources = test_sources(MAX_SOURCE_DISKS + 8);
        let needed: Vec<String> = (0..=MAX_SOURCE_DISKS).map(|i| format!("s{i}")).collect();
        let needed_refs: Vec<&str> = needed.iter().map(String::as_str).collect();
        let err = select_source_batch(&sources, &needed_refs, "app", MAX_SOURCE_DISKS).unwrap_err();

        assert!(
            err.to_string()
                .contains(&format!("at most {MAX_SOURCE_DISKS} sources"))
        );
    }

    #[test]
    fn host_copy_from_stage_resolves_absolute_sources_in_the_stage() {
        // `COPY --from=<stage> /t /t2`: the absolute source is a path *in the source
        // stage*, never a host path.
        let tmp = tmpdir("host-from");
        let mut h = Host::new(tmp.join("scratch"));
        let lib = h.from_scratch("lib").unwrap();
        std::fs::write(h.stage_dir(&lib).unwrap().join("t"), "tool").unwrap();
        let app = h.from_scratch("app").unwrap();
        let op = Copy {
            sources: vec!["/t".into()],
            dest: "/t2".into(),
            from: Some("lib".into()),
            chown: None,
            chmod: None,
            link: false,
        };
        h.copy(&app, &op, Some(&lib), "/").unwrap();
        let copied = std::fs::read_to_string(h.stage_dir(&app).unwrap().join("t2")).unwrap();
        assert_eq!(copied, "tool");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn host_copy_requires_and_reads_the_stage_context() {
        // A context COPY reads the context `stage_sources` declared for the stage —
        // and errors if it runs before any stage declared one.
        let tmp = tmpdir("host-ctx");
        let stage = tmp.join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("f.txt"), "from-stage").unwrap();

        let mut h = Host::new(tmp.join("scratch"));
        let fs = h.from_scratch("s").unwrap();
        let op = Copy {
            sources: vec!["f.txt".into()],
            dest: "/f.txt".into(),
            from: None,
            chown: None,
            chmod: None,
            link: false,
        };
        assert!(h.copy(&fs, &op, None, "/").is_err());
        h.stage_sources(&[], &stage).unwrap();
        h.copy(&fs, &op, None, "/").unwrap();
        let copied = std::fs::read_to_string(h.stage_dir(&fs).unwrap().join("f.txt")).unwrap();
        assert_eq!(copied, "from-stage");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn named_context_source_is_read_by_copy_from() {
        // The case this exists for: a file that must stay outside the Dockerfile's own context is
        // reached through `--build-context <name>=<dir>` + `COPY --from=<name>`, with no
        // staging copy into the context.
        let tmp = tmpdir("namedctx");
        let ctx = tmp.join("ctx");
        let extra = tmp.join("shared");
        std::fs::create_dir_all(&ctx).unwrap();
        std::fs::create_dir_all(&extra).unwrap();
        std::fs::write(ctx.join("own.txt"), b"from the stage's own context").unwrap();
        std::fs::write(extra.join("setup.sh"), b"#!/bin/sh\necho setup").unwrap();

        let mut h = Host::new(tmp.join("scratch"));
        let src = h.context_source("shared", &extra).unwrap();
        assert_eq!(
            src.label, "context/shared",
            "labelled distinctly from a stage"
        );
        h.stage_sources(std::slice::from_ref(&src), &ctx).unwrap();
        let fs = h.from_scratch("s").unwrap();

        let copy = |sources: Vec<String>, dest: &str, from: Option<&str>| Copy {
            sources,
            dest: dest.into(),
            from: from.map(str::to_string),
            chown: None,
            chmod: None,
            link: false,
        };
        // A COPY from the named context reads that directory...
        h.copy(
            &fs,
            &copy(vec!["setup.sh".into()], "/setup.sh", Some("shared")),
            Some(&src),
            "/",
        )
        .unwrap();
        // ...while a plain COPY still reads the stage's own context.
        h.copy(
            &fs,
            &copy(vec!["own.txt".into()], "/own.txt", None),
            None,
            "/",
        )
        .unwrap();

        let dir = h.stage_dir(&fs).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("setup.sh")).unwrap(),
            "#!/bin/sh\necho setup"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("own.txt")).unwrap(),
            "from the stage's own context"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn host_builds_a_real_ext4_from_scratch_and_copy() {
        // exercises the actual "Dockerfile → ext4 with only virtkit" path: a scratch
        // stage + a COPY, exported via crate::ext4. No docker/buildkit/mke2fs/VM.
        let tmp = tmpdir("host");
        let ctx = tmp.join("ctx");
        std::fs::create_dir_all(&ctx).unwrap();
        std::fs::write(ctx.join("hello.txt"), b"hi from virtkit").unwrap();

        let mut h = Host::new(tmp.join("scratch"));
        h.stage_sources(&[], &ctx).unwrap();
        let fs = h.from_scratch("s").unwrap();
        let op = Copy {
            sources: vec!["hello.txt".into()],
            dest: "/hello.txt".into(),
            from: None,
            chown: None,
            chmod: None,
            link: false,
        };
        h.copy(&fs, &op, None, "/").unwrap();
        let out = tmp.join("out.ext4");
        h.export_ext4(&fs, &out).unwrap();

        let bytes = std::fs::read(&out).unwrap();
        assert!(bytes.len() > 4096, "ext4 image should be non-trivial");
        // ext4 superblock magic 0xEF53 (LE) at byte offset 0x438.
        assert_eq!(&bytes[0x438..0x43a], &[0x53, 0xEF], "ext4 superblock magic");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn stamp_epoch_tree_zeroes_the_tree_without_following_a_symlink() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tmpdir("stamp-epoch");
        let sub = tmp.join("tree/sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("f"), "x").unwrap();
        // an absolute symlink out of the tree, as `copy_tree` recreates one from a context;
        // it targets a *directory* so a walk that followed it would stamp host files
        let outside = tmp.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("keep"), "keep").unwrap();
        std::os::unix::fs::symlink(&outside, tmp.join("tree/link")).unwrap();

        stamp_epoch_tree(&tmp.join("tree")).unwrap();

        for p in [
            tmp.join("tree"),
            sub.clone(),
            sub.join("f"),
            tmp.join("tree/link"),
        ] {
            let mtime = std::fs::symlink_metadata(&p).unwrap().mtime();
            assert_eq!(mtime, 0, "{} was not stamped", p.display());
        }
        // the link itself was stamped, never what it points at
        assert_ne!(std::fs::symlink_metadata(&outside).unwrap().mtime(), 0);
        assert_ne!(
            std::fs::symlink_metadata(outside.join("keep"))
                .unwrap()
                .mtime(),
            0
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// `content_diff` reports exactly this interval's changed extents between two overlay
    /// captures: an unchanged shared cluster is skipped, an in-place-rewritten shared cluster
    /// is dirty (caught by the byte compare), and a cluster new to `cur` is dirty by its
    /// allocation alone — the read-skipping path must not miss or misreport any of them.
    #[test]
    fn content_diff_reports_rewritten_and_new_clusters() {
        fn have(tool: &str) -> bool {
            std::process::Command::new(tool)
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
        if !have("qemu-img") || !have("qemu-io") {
            eprintln!("skipping: qemu-img/qemu-io not available");
            return;
        }
        let dir = tmpdir("content-diff");
        let base = dir.join("base.raw");
        let prev = dir.join("prev.qcow2");
        let cur = dir.join("cur.qcow2");
        // 512 KiB base (eight 64 KiB clusters) of 0xAA.
        std::fs::write(&base, vec![0xAAu8; 512 * 1024]).unwrap();
        let overlay = |img: &std::path::Path| {
            assert!(
                std::process::Command::new("qemu-img")
                    .args(["create", "-q", "-f", "qcow2", "-F", "raw", "-b"])
                    .arg(&base)
                    .arg(img)
                    .status()
                    .unwrap()
                    .success()
            );
        };
        let write = |img: &std::path::Path, spec: &str| {
            assert!(
                std::process::Command::new("qemu-io")
                    .args(["-c", spec])
                    .arg(img)
                    .status()
                    .unwrap()
                    .success()
            );
        };
        // prev: cluster 1 = 0xBB, cluster 3 = 0xDD.
        overlay(&prev);
        write(&prev, "write -P 0xBB 65536 65536");
        write(&prev, "write -P 0xDD 196608 65536");
        // cur: cluster 1 = 0xBB (unchanged), cluster 3 = 0xEE (rewritten), cluster 5 = 0xCC (new).
        overlay(&cur);
        write(&cur, "write -P 0xBB 65536 65536");
        write(&cur, "write -P 0xEE 196608 65536");
        write(&cur, "write -P 0xCC 327680 65536");

        let within = crate::qcow2::Qcow2::open(&cur)
            .unwrap()
            .data_extents()
            .unwrap();
        let dirty = content_diff(&prev, &cur, &within, true).unwrap();
        assert_eq!(
            dirty,
            vec![(196608, 65536), (327680, 65536)],
            "only the rewritten (cluster 3) and new (cluster 5) clusters are dirty; the \
             unchanged shared cluster 1 is skipped"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With the read-skip off, `content_diff` is a true logical byte-compare over the whole
    /// `within` — base-identical regions that neither overlay wrote (holes) come back clean.
    /// This is the reassembly-localizer contract; the read-skip (valid only when `within` is
    /// `cur`'s own allocation) would instead flag every hole outside `prev`'s allocation, so
    /// the two flag values are asserted to diverge on exactly this shape.
    #[test]
    fn content_diff_full_compare_leaves_holes_clean() {
        fn have(tool: &str) -> bool {
            std::process::Command::new(tool)
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
        if !have("qemu-img") || !have("qemu-io") {
            eprintln!("skipping: qemu-img/qemu-io not available");
            return;
        }
        let dir = tmpdir("content-diff-full");
        let base = dir.join("base.raw");
        let prev = dir.join("prev.qcow2");
        let cur = dir.join("cur.qcow2");
        // 1 MiB base (sixteen 64 KiB clusters) of 0xAA — four 256 KiB comparison blocks.
        std::fs::write(&base, vec![0xAAu8; 1024 * 1024]).unwrap();
        let overlay = |img: &std::path::Path| {
            assert!(
                std::process::Command::new("qemu-img")
                    .args(["create", "-q", "-f", "qcow2", "-F", "raw", "-b"])
                    .arg(&base)
                    .arg(img)
                    .status()
                    .unwrap()
                    .success()
            );
        };
        let write = |img: &std::path::Path, spec: &str| {
            assert!(
                std::process::Command::new("qemu-io")
                    .args(["-c", spec])
                    .arg(img)
                    .status()
                    .unwrap()
                    .success()
            );
        };
        // prev writes cluster 2 (in block 0); cur writes cluster 10 (in block 2). Each overlay
        // leaves the other's cluster — and every other cluster — resolving to the base, so the
        // only logical differences are those two clusters, one per non-adjacent 256 KiB block.
        overlay(&prev);
        write(&prev, "write -P 0xBB 131072 65536");
        overlay(&cur);
        write(&cur, "write -P 0xCC 655360 65536");

        let whole = [(0u64, 1024 * 1024u64)];
        // Full compare: only the two blocks that actually differ, at 256 KiB granularity.
        let full = content_diff(&prev, &cur, &whole, false).unwrap();
        assert_eq!(
            full,
            vec![(0, 262144), (524288, 262144)],
            "full compare flags only the blocks whose bytes differ; base-identical holes are clean"
        );
        // Read-skip on this shape over-reports: blocks 1 and 3 are holes `prev` never allocated,
        // so they are flagged dirty without a compare — strictly more bytes than the true diff.
        let skipped: u64 = content_diff(&prev, &cur, &whole, true)
            .unwrap()
            .iter()
            .map(|&(_, l)| l)
            .sum();
        let truth: u64 = full.iter().map(|&(_, l)| l).sum();
        assert!(
            skipped > truth,
            "read-skip must over-report when within spans holes cur does not allocate \
             (skipped {skipped} > truth {truth})"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
