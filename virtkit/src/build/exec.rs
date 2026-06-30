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
//!     ext4, committed back so writes persist; egress via a `virtkit switch` so
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

/// Host backend for the no-`RUN` subset (`FROM scratch` + `COPY`): each stage is a real
/// host directory, `COPY` is a host-side file copy, and the export is virtkit's own
/// pure-Rust ext4 builder — no docker, no buildkit, no `mke2fs`, no VM. `RUN` and
/// `FROM <image>` need the microVM/OCI path (added next) and error here.
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
