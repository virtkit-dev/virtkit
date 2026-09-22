//! microVM lifecycle: prepare (overlay + cloud-hypervisor + wait for the in-guest
//! agent) and cleanup (ACPI poweroff, escalation, state removal). One VM per job.

use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};

use crate::image::ResolvedImage;
use crate::jobctx::JobCtx;

/// The boot medium: a read-only base rootfs (booted through a CoW overlay) plus a
/// self-booting image's own initrd, if it shipped one, and the image's runtime config
/// (Env/User), applied at boot for a byte-clean generic bundle.
struct Media {
    rootfs: PathBuf,
    initrd: Option<PathBuf>,
    config: Option<vk_core::runcfg::RunConfig>,
    /// A held reference on `rootfs`, for a base freshly resolved from the shared build tier
    /// (a `dockerfile:`/compose `build:` unit) — `None` for anything resolved through
    /// `image::resolve_ref`, which takes no reference of its own. Whoever ends up with this
    /// `Media` must hold this guard (fold it into whatever it already keeps `media.rootfs`'s
    /// own reference in) for as long as it keeps referring to `rootfs`, and take one itself
    /// when this is `None` — nothing else protects a resolved base from the idle GC.
    use_guard: Option<crate::cachelock::Guard>,
}

impl Media {
    fn files(&self) -> Vec<&Path> {
        let mut v = vec![self.rootfs.as_path()];
        v.extend(self.initrd.as_deref());
        v
    }
}

/// What MICROVM_IMAGE resolved to: the boot files plus the two facts about the boot that
/// only the resolve step knows. A struct rather than a tuple because `generic` and `nested`
/// are both bare bools — positional, they are one transposition away from a silent swap.
struct BootPlan {
    /// `None` = boot vk's embedded kernel.
    kernel: Option<PathBuf>,
    media: Media,
    /// A generic boot: the embedded agent rides a preinit initramfs as `/init` and pivots,
    /// rather than the image booting its own init.
    generic: bool,
    /// The compose primary's own `x-virtkit.nested`; the boot ORs it with the runner's
    /// `[executor.vm] nested` through [`crate::run::effective_nested`]. False for every non-compose
    /// form: nothing else carries the marker.
    nested: bool,
}

/// Resolve a `name`'s uid and primary gid from a `/etc/passwd` blob
/// (`name:passwd:uid:gid:…` per line). A non-UTF-8 line, or a name-matching line whose uid/gid
/// fields are absent or unparseable, is skipped and the scan continues. None if none resolves.
fn passwd_lookup(passwd: &[u8], name: &str) -> Option<(u32, u32)> {
    for line in passwd.split(|&b| b == b'\n') {
        let Ok(line) = std::str::from_utf8(line) else {
            continue;
        };
        let f: Vec<&str> = line.split(':').collect();
        if f.first() == Some(&name)
            && let (Some(uid), Some(gid)) = (f.get(2), f.get(3))
            && let (Ok(uid), Ok(gid)) = (uid.parse(), gid.parse())
        {
            return Some((uid, gid));
        }
    }
    None
}

/// Resolve a `name`'s gid from an `/etc/group` blob (`name:passwd:gid:…` per line). Lines are
/// skipped on non-UTF-8 or an unparseable gid, like `passwd_lookup`. None if none resolves.
fn group_lookup(group: &[u8], name: &str) -> Option<u32> {
    for line in group.split(|&b| b == b'\n') {
        let Ok(line) = std::str::from_utf8(line) else {
            continue;
        };
        let f: Vec<&str> = line.split(':').collect();
        if f.first() == Some(&name)
            && let Some(gid) = f.get(2)
            && let Ok(gid) = gid.parse()
        {
            return Some(gid);
        }
    }
    None
}

/// The guest job user's (uid, gid) for the `cibuild` host_checkout share. Accepts the Docker
/// `User` forms `name`, `uid`, `name:group`, and `uid:gid` (either half may be a name). The user
/// half gives the uid and a default primary gid — numeric, else resolved against the guest rootfs
/// `/etc/passwd`; an explicit `:group` overrides the gid — numeric, else against `/etc/group`.
/// Both files are read out of `rootfs` without mounting. None when the user is empty or root
/// (uid 0 already writes the host-owned tree) or when resolution fails (don't guess an id).
fn guest_run_user_ids(user: &str, rootfs: &Path) -> Option<(u32, u32)> {
    let user = user.trim();
    if user.is_empty() || user == "root" || user == "0" {
        return None;
    }
    let (user_part, group_part) = match user.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (user, None),
    };
    // Read a file out of the guest rootfs without mounting it, for name resolution.
    let read_rootfs = |path: &str| -> Option<Vec<u8>> {
        crate::ext4_read::Ext4Reader::open(rootfs)
            .ok()?
            .read_file(path)
            .ok()
    };
    let (uid, mut gid) = match user_part.parse::<u32>() {
        Ok(uid) => (uid, uid),
        Err(_) => passwd_lookup(&read_rootfs("/etc/passwd")?, user_part)?,
    };
    if let Some(group) = group_part {
        gid = match group.parse::<u32>() {
            Ok(g) => g,
            Err(_) => group_lookup(&read_rootfs("/etc/group")?, group)?,
        };
    }
    Some((uid, gid))
}

/// The 1:1 virtio-fs UID/GID maps for the host_checkout share: the guest job user's ids mapped
/// onto the host `owner`'s `(uid, gid)`. Empty (no map) when the run user is root or unresolvable
/// — the tree then stays owned by the host user vk runs as on the guest side too.
fn checkout_id_maps(
    run_user: &str,
    rootfs: &Path,
    owner: (u32, u32),
) -> (Vec<String>, Vec<String>) {
    match guest_run_user_ids(run_user, rootfs) {
        Some((guid, ggid)) => (
            vec![format!("map:{guid}:{}:1", owner.0)],
            vec![format!("map:{ggid}:{}:1", owner.1)],
        ),
        None => (Vec::new(), Vec::new()),
    }
}

/// The virtio-fs tag of the host_checkout share. The cmdline helper and the FsShare
/// registration must agree on it: the agent mounts whatever tag the cmdline names.
const CIBUILD_TAG: &str = "cibuild";

/// Seed share tag, guest mountpoint and tar name ([`pack_checkout_seed`]).
/// The cmdline helper and FsShare registration must agree on all three.
const CICHECKOUT_TAG: &str = "cicheckout";
const CICHECKOUT_MOUNT: &str = "/run/virtkit-checkout";
const CICHECKOUT_TAR: &str = "worktree.tar";

/// The cmdline fragment mounting the host_checkout share in the guest. The agent mounts
/// VIRTKIT_VIRTIOFS shares at boot (mkdir -p'ing the mount point), in order; CI supervise sets
/// no other share, so a plain assignment is safe. With `overlay`, VIRTKIT_VIRTIOFS_OVERLAY
/// tells the agent to build the tree on a tmpfs-backed overlay above the (then read-only)
/// share instead of mounting it directly, and VIRTKIT_VIRTIOFS_OVERLAY_SIZE how much of the
/// VM's memory that layer may take. With `seed`, list its share first so the tar is available
/// before overlay mount. VIRTKIT_VIRTIOFS_OVERLAY_SEED names the tar to unpack into the upper.
fn checkout_virtiofs_cmdline(mount: &str, overlay: bool, size: &str, seed: bool) -> String {
    let seed = overlay && seed;
    let mut s = if seed {
        format!(" VIRTKIT_VIRTIOFS={CICHECKOUT_TAG}:{CICHECKOUT_MOUNT},{CIBUILD_TAG}:{mount}")
    } else {
        format!(" VIRTKIT_VIRTIOFS={CIBUILD_TAG}:{mount}")
    };
    if overlay {
        s.push_str(&format!(" VIRTKIT_VIRTIOFS_OVERLAY={CIBUILD_TAG}"));
        s.push_str(&format!(" VIRTKIT_VIRTIOFS_OVERLAY_SIZE={size}"));
    }
    if seed {
        s.push_str(&format!(
            " VIRTKIT_VIRTIOFS_OVERLAY_SEED={CIBUILD_TAG}:{CICHECKOUT_MOUNT}/{CICHECKOUT_TAR}"
        ));
    }
    s
}

/// Pack the host checkout's worktree — everything but the top-level `.git` — into `dest`, for the
/// guest to unpack onto its overlay's tmpfs upper at boot. Read file by file through virtio-fs the
/// tree costs a round trip per file on every pass over it (a build tool hashing its inputs, a
/// scanner, git); as one tar it streams through the share's DAX window at memory speed and unpacks
/// in guest RAM in well under a second per 100k files.
///
/// Built with the `tar` crate rather than the `tar` binary, so it needs no GNU tar on the host:
/// virtkit ships as a static musl binary and runs where only BusyBox tar may exist, and BusyBox
/// tar cannot stamp ownership at all. `owner` is the guest job user's `(uid, gid)`: every entry is
/// stamped with it, so the unpacked tree is the job's just as the id-mapped lower appears to be;
/// `None` (root, or an unresolved user) keeps the host owner, as the unmapped lower does.
///
/// Regular files, directories (empty ones and their modes included) and symlinks are packed;
/// mtimes keep tar's one-second granularity and xattrs are not carried, so a seeded file can
/// differ from the lower in those — neither of which a source checkout depends on. Returns the
/// tar's size in bytes.
fn pack_checkout_seed(host_dir: &Path, dest: &Path, owner: Option<(u32, u32)>) -> Result<u64> {
    let file =
        std::fs::File::create(dest).with_context(|| format!("creating {}", dest.display()))?;
    let mut builder = tar::Builder::new(std::io::BufWriter::new(file));
    append_checkout_entries(&mut builder, host_dir, host_dir, owner)?;
    let buffered = builder.into_inner().context("finishing the checkout tar")?;
    buffered
        .into_inner()
        .map_err(std::io::IntoInnerError::into_error)
        .context("flushing the checkout tar")?;
    Ok(std::fs::metadata(dest)
        .with_context(|| format!("stat {}", dest.display()))?
        .len())
}

/// Append every entry under `dir` to `builder` recursively, naming each by its path relative to
/// `root` and stamping `owner` (when set) onto it. The top-level `.git` is skipped, and anything
/// that is not a regular file, directory or symlink (a device, fifo or socket a source tree never
/// has) is left out. Entries are visited in name order so the tar is reproducible run to run.
fn append_checkout_entries<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    dir: &Path,
    root: &Path,
    owner: Option<(u32, u32)>,
) -> Result<()> {
    let mut entries = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("reading {}", dir.display()))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let disk = entry.path();
        let rel = disk
            .strip_prefix(root)
            .expect("a read_dir entry is under the root");
        if dir == root && rel == Path::new(".git") {
            continue;
        }
        let meta = entry
            .metadata()
            .with_context(|| format!("stat {}", disk.display()))?;
        let file_type = meta.file_type();
        let mut header = tar::Header::new_gnu();
        header.set_metadata(&meta);
        if let Some((uid, gid)) = owner {
            header.set_uid(uid.into());
            header.set_gid(gid.into());
        }
        if file_type.is_dir() {
            header.set_size(0);
            builder
                .append_data(&mut header, rel, std::io::empty())
                .with_context(|| format!("packing directory {}", disk.display()))?;
            append_checkout_entries(builder, &disk, root, owner)?;
        } else if file_type.is_symlink() {
            let target = std::fs::read_link(&disk)
                .with_context(|| format!("reading symlink {}", disk.display()))?;
            header.set_size(0);
            header.set_entry_type(tar::EntryType::Symlink);
            append_symlink(builder, &mut header, rel, target.as_os_str().as_bytes())
                .with_context(|| format!("packing symlink {}", disk.display()))?;
        } else if file_type.is_file() {
            let f = std::fs::File::open(&disk)
                .with_context(|| format!("opening {}", disk.display()))?;
            builder
                .append_data(&mut header, rel, f)
                .with_context(|| format!("packing {}", disk.display()))?;
        }
    }
    Ok(())
}

/// Append the symlink `rel` with the target bytes readlink returned. `Builder::append_link`
/// stores a target through `Header::set_link_name`, which re-joins the target's `Path`
/// components: `a//b` and `a/./b` come out as `a/b`. The unpacked link then differs from the
/// blob git committed and the job's tree starts out modified. A target the 100-byte header field
/// cannot hold goes in a GNU long-link record, as `append_link` writes it.
fn append_symlink<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    header: &mut tar::Header,
    rel: &Path,
    target: &[u8],
) -> std::io::Result<()> {
    if header.set_link_name_literal(target).is_err() {
        let mut long = tar::Header::new_gnu();
        let name = b"././@LongLink";
        long.as_gnu_mut().expect("a GNU header").name[..name.len()].copy_from_slice(name);
        long.set_mode(0o644);
        long.set_uid(0);
        long.set_gid(0);
        long.set_mtime(0);
        long.set_size(target.len() as u64 + 1);
        long.set_entry_type(tar::EntryType::GNULongLink);
        long.set_cksum();
        builder.append(&long, target.chain(std::io::repeat(0).take(1)))?;
    }
    builder.append_data(header, rel, std::io::empty())
}

/// `[executor] checkout_overlay_size` as a tmpfs `size=` token: a percentage (`80%`) or an
/// absolute size (`12G`), the units `mount` itself takes.
///
/// Rejected rather than passed on when it is anything else. The value is spliced into the
/// kernel cmdline and then into the guest's mount options, where a stray space or comma would
/// not fail but silently mount something other than what was asked for — and a layer sized
/// wrong is discovered as a job dying for want of space.
fn checkout_overlay_size(spec: &str) -> Result<&str> {
    let (digits, unit) = spec.split_at(
        spec.find(|c: char| !c.is_ascii_digit())
            .unwrap_or(spec.len()),
    );
    let sized = !digits.is_empty() && matches!(unit, "" | "%" | "k" | "K" | "m" | "M" | "g" | "G");
    // A percentage of nothing and a zero-byte layer are both a checkout that cannot be written
    // to at all, which is a misconfiguration rather than a policy anyone means.
    if !sized || digits.trim_start_matches('0').is_empty() {
        bail!(
            "[executor] checkout_overlay_size {spec:?} is not a tmpfs size: \
             want a percentage of the VM memory (e.g. \"80%\") or an absolute size (e.g. \"12G\")"
        );
    }
    // A parse failure on all-digit input is u32 overflow, which is even more than 100%.
    if unit == "%" && !digits.parse::<u32>().is_ok_and(|pct| pct <= 100) {
        bail!("[executor] checkout_overlay_size {spec:?} is more than all of the VM's memory");
    }
    Ok(spec)
}

pub async fn prepare(ctx: &JobCtx) -> Result<()> {
    let cfg = &ctx.cfg;
    // Cheap fail-fast checks first (crisp errors in the runner-visible process beat a
    // supervisor-log pointer).
    crate::check::require_kvm()?;
    refuse_unsupported_nesting(cfg.executor.vm.nested, crate::vmm::host_nesting_enabled())?;
    let (cpus, mem) = vm_size(ctx)?;
    // Validate the run-phase egress narrowing here so a MICROVM_EGRESS_ALLOW_* request
    // outside the `[egress]` cap fails with a crisp job-visible error — the switch itself is
    // spawned later in the detached supervisor, whose log the job never sees. (The build
    // phase validates in build_git_image / build_compose_unit, also in prepare.)
    effective_run_egress(cfg, ctx)?;
    if ctx.egress_dry_run_req && !ctx.egress_run_dry_run() {
        eprintln!(
            "virtkit: MICROVM_EGRESS_DRY_RUN ignored: the host enforces a run-phase allowlist"
        );
    }
    // Same fail-fast rationale for the writable-layer size: it is pure config, and the
    // authoritative check runs in the detached supervisor whose log the job never sees.
    checkout_overlay_size(&cfg.executor.checkout_overlay_size)?;
    // And `[executor] atop_interval_secs`, before admission can hold a misconfigured job in
    // the queue for its whole wait.
    let atop_interval = match crate::atop::enabled(cfg) {
        true => Some(crate::atop::interval_secs(cfg)?),
        false => None,
    };

    // A leftover job (failed cleanup, retried job id) must not leak: signal its
    // supervisor — everything it owns cascades by PDEATHSIG — and drop the state. Done before
    // the checkout so a dying supervisor is not still virtio-fs-sharing the checkout dir.
    stop_supervisor(ctx);
    crate::net::release(ctx);
    if ctx.job_dir.exists() {
        std::fs::remove_dir_all(&ctx.job_dir)
            .with_context(|| format!("removing stale {}", ctx.job_dir.display()))?;
    }
    std::fs::create_dir_all(&ctx.job_dir)
        .with_context(|| format!("creating {}", ctx.job_dir.display()))
        .map_err(|e| name_full_fs(e, ctx.jobs_dir()))?;

    // Admission (`[executor.schedule]`): claim the guest RAM this job is about to boot and the
    // room its job dir will grow into before booting it, waiting for both on a full host. Held
    // for the rest of prepare; the supervisor takes its own hold on the same reservation, so it
    // never lapses between the two. After the stale-job teardown above, which frees a
    // predecessor's claim, and before anything is written into the job dir.
    let _reservation = admit(ctx, &mem)?;

    // [executor] atop: give this job somewhere to record what its guest does, and remember
    // where — the supervisor shares that directory into the guest, and the last stage
    // reports the log's path. Fatal only for a full job dirs' filesystem, which has no room for
    // the overlay either: a host whose archive cannot be written still runs jobs, unrecorded but
    // for the warning.
    if let Some(interval) = atop_interval {
        // Bound what the archive costs the host before adding a job to it.
        crate::atop::prune_archive_daily(cfg);
        // Each failure paired with whether it was a write to the job dirs' filesystem: the
        // archive may be elsewhere, but the marker recording it is in the job dir.
        let recorded = match crate::atop::prepare_archive(ctx) {
            Ok(dir) => crate::atop::record_archive_dir(ctx, &dir)
                .map(|()| dir)
                .map_err(|e| (e, true)),
            Err(e) => {
                let on_jobs_fs = same_fs(ctx.jobs_dir(), &crate::atop::archive_root(cfg));
                Err((e, on_jobs_fs))
            }
        };
        match recorded {
            Ok(dir) => println!(
                "virtkit: recording guest stats every {interval}s -> {}",
                dir.join(vk_core::atop::LOG_NAME).display()
            ),
            Err((e, on_jobs_fs))
                if atop_failure_is_fatal(storage_full(&e), on_jobs_fs, || {
                    jobs_fs_full(ctx).is_some()
                }) =>
            {
                return Err(name_full_fs(e, ctx.jobs_dir()));
            }
            Err((e, _)) => eprintln!("virtkit: warning: not recording guest stats: {e:#}"),
        }
    }

    // [executor] host_checkout: check the sources out on the host NOW — before resolving the
    // image (a `dockerfile:`/`compose:` image is built from these sources) and before the
    // guest boots — so supervise can share the tree in and the git token never enters the
    // guest (the job sets GIT_STRATEGY: none). Crisp errors here (the runner-visible prepare)
    // beat a supervisor-log pointer; like any prepare failure a checkout error exits
    // system_failure.
    // Held to the end of prepare, which outlasts the supervisor taking its own hold below, so the
    // tree is referenced continuously from the clone until the job's VM is gone.
    let _checkout_use = if cfg.executor.host_checkout {
        let url = ctx
            .ci_repo_url
            .as_deref()
            .context("host_checkout is set but CI_REPOSITORY_URL is unset")?;
        let sha = ctx
            .ci_commit_sha
            .as_deref()
            .context("host_checkout is set but CI_COMMIT_SHA is unset")?;
        let dest = ctx.host_checkout_dir();
        let guard = crate::checkout::acquire_use_lock(&dest)
            .with_context(|| format!("locking host checkout {}", dest.display()))?;
        // Bound what abandoned checkouts cost the host before adding one more — on a tmpfs
        // `checkout_dir` they hold RAM that `vk tune` charges against this runner's concurrency.
        // Swept while already holding our own reference, so an idle window that has just
        // elapsed cannot evict the tree this job is about to reuse and turn its fetch into a
        // re-clone.
        crate::checkout::gc_idle(&ctx.host_checkout_root(), cfg.checkout_cache_idle());
        println!("virtkit: host checkout of {sha} -> {}", dest.display());
        // Bind the external bookkeeping to the destination before the clone fills it, so a
        // prepare killed part-way through leaves a partial tree the idle sweep can still find.
        crate::checkout::claim(&dest)
            .with_context(|| format!("claiming host checkout {}", dest.display()))?;
        crate::checkout::ensure(url, ctx.ci_commit_ref.as_deref().unwrap_or(""), sha, &dest)
            .context("host checkout")?;
        Some(guard)
    } else {
        None
    };

    // Resolve (and, for a `dockerfile:` image, build) the boot media in the runner-visible process;
    // the supervisor re-resolves from the same env (a fingerprint hit for a build). A `None`
    // kernel boots vk's embedded copy — nothing to stat.
    let mut plan = resolve_media(ctx)?;
    // Every base this phase resolves or builds, held until prepare returns — same rationale as
    // `_checkout_use` above: nothing else protects a resolved base from the idle GC, and this
    // (possibly long, sequential) phase warms every service image before the supervisor, in
    // another process, takes its own references. A `vk gc` landing in between would otherwise
    // evict one this phase, or the supervisor moments later, still means to use. The primary
    // contributes the guard its build already took, or a fresh one when it came from
    // `image::resolve_ref`.
    let mut warm_guards: Vec<crate::cachelock::Guard> = match plan.media.use_guard.take() {
        Some(g) => vec![g],
        None => crate::image::acquire_use_lock_for(cfg.state_dir(), &plan.media.rootfs)?
            .into_iter()
            .collect(),
    };
    // Referenced first, then checked, so nothing can be evicted between the two. A base
    // already gone before this runs now reports itself from the acquisition rather than from
    // the check below, which is the cost of closing that window.
    for p in plan.media.files().into_iter().chain(plan.kernel.as_deref()) {
        if !p.is_file() {
            bail!("image file missing: {}", p.display());
        }
    }

    // Warm any git-defined service images into the build tier NOW, alongside the primary — a
    // stage build is far slower than a boot, so building it here (rather than in supervise's
    // plan_services) keeps the guest boot within the runner's readiness budget. supervise then
    // just hits the fresh tier. Non-build services are left for supervise (a pull is quick).
    let image_ref = ctx.image_ref.as_deref().unwrap_or("local/default");
    let mut service_names: Vec<String> = Vec::new();
    if let Some(spec) = image_ref.strip_prefix("compose:") {
        for unit in compose_service_units(&load_compose_fleet(ctx, spec)?)? {
            validate_service_egress(cfg, &unit)?;
            if matches!(unit.source, crate::compose::Source::Build { .. }) {
                let (_, _, guard) = build_compose_unit(ctx, &unit)
                    .with_context(|| format!("service {}", unit.name))?;
                warm_guards.push(guard);
            }
            service_names.push(unit.name);
        }
    } else {
        for unit in crate::services::to_units(crate::services::from_env()?) {
            validate_service_egress(cfg, &unit)?;
            if let crate::compose::Source::Image(image) = &unit.source
                && let Some(spec) = image.strip_prefix("dockerfile:")
            {
                let (_, _, guard) =
                    build_git_image(ctx, spec).with_context(|| format!("service {}", unit.name))?;
                warm_guards.push(guard);
            }
            service_names.push(unit.name);
        }
    }

    // ONE detached process owns the job from here (the runner protocol requires
    // this stage to exit — ready is signaled by exiting 0): the supervisor spawns
    // the switch/virtiofsds/forwards/VMM as tied children, supervises them, and
    // tears everything down on SIGTERM (cleanup) or by dying. The job dir on its
    // cmdline is the pid-reuse guard for the later signal.
    let mut sup_cmd = Command::new(crate::spawn::self_exe());
    sup_cmd.args(["gitlab", "supervise"]).arg(&ctx.job_dir);
    // The supervisor re-loads the config; pin it to the file THIS phase resolved,
    // which the inherited environment alone does not carry when it came from --config.
    if let Some(src) = &ctx.cfg.source {
        sup_cmd.arg("--config").arg(src);
    }
    let mut sup = spawn_detached(sup_cmd, &ctx.supervisor_log())
        .context("spawning the job supervisor")
        .map_err(|e| name_full_fs(e, ctx.jobs_dir()))?;

    println!("virtkit: booting microVM {image_ref} (cpus={cpus}, mem={mem})");

    // Ready = the in-guest virtkit-agent answers on vsock. The supervisor exiting
    // during boot (the VMM died, a helper failed to start) fails the poll fast.
    let addr = crate::vmm::exec_addr(&ctx.vsock_sock(), cfg.executor.vm.vsock_port);
    let start = Instant::now();
    let deadline = start + Duration::from_secs(cfg.executor.vm.boot_timeout_secs);
    loop {
        if let Some(status) = sup.try_wait()? {
            log_tail(&ctx.supervisor_log(), 15);
            log_tail(&ctx.console_log(), 30);
            log_tail(&ctx.vmm_log(), 20);
            // The supervisor's log is in the job dir, so a supervisor that ran out of space
            // there could not write down why; this process still can.
            let full = jobs_fs_no_room(ctx)
                .map(|why| format!(" — {why}"))
                .unwrap_or_default();
            bail!(
                "the job supervisor exited during boot ({status}, see {}){full}",
                ctx.supervisor_log().display()
            );
        }
        match vk_core::status::get_status_within(&addr, vk_core::status::BOOT_PROBE_BUDGET).await {
            Ok(status) => {
                // Fail fast on a wire-protocol skew (the guest bundle's virtkit-agent
                // predates this virtkit, or vice versa): rmp_serde structs are
                // fixed-length arrays, so a mismatched virtkit-agent cannot decode our
                // commands and would otherwise drop the connection mid-command with
                // an opaque "connection to the VM lost". A pre-versioning virtkit-agent
                // reports protocol 0.
                let want = vk_core::messages::PROTOCOL_VERSION;
                if status.protocol() != want {
                    bail!(
                        "guest vk-agent wire protocol v{} != vk v{want} — the guest \
                         bundle and the host are out of sync; rebuild/republish the guest \
                         bundle with a matching vk-agent",
                        status.protocol(),
                    );
                }
                println!(
                    "vk: VM ready in {:.1}s (vk-agent {status})",
                    start.elapsed().as_secs_f32()
                );
                probe_guest_shell(ctx, &addr).await;
                // Only signal ready (exit 0) once the services the job declared are up too:
                // they boot concurrently in the supervisor and the job script runs the moment
                // this stage exits.
                wait_for_services(ctx, &service_names).await?;
                // The supervisor holds its own references now: this phase is done depending
                // on the bases it warmed. Explicit so a later edit cannot shorten the hold
                // without noticing.
                drop(warm_guards);
                return Ok(());
            }
            Err(e) => {
                if Instant::now() >= deadline {
                    log_tail(&ctx.console_log(), 30);
                    log_tail(&ctx.vmm_log(), 20);
                    bail!(
                        "VM not ready after {}s ({e}) — console tail above, logs in {}",
                        cfg.executor.vm.boot_timeout_secs,
                        ctx.job_dir.display()
                    );
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Gate `prepare` on every declared service's readiness. Each service boots concurrently in
/// the detached supervisor as a sibling VM, and gitlab-runner runs the job script the instant
/// prepare exits — so a service still coming up, or one that died at boot, must surface here as
/// a crisp prepare failure (system_failure) instead of an opaque connection error mid-script.
/// Readiness is the sibling's in-guest agent answering on its exec channel — the same signal
/// the primary uses — served via `VIRTKIT_SERVE=1` and bridged to the host by `units::boot_unit`.
/// For an image that declares `EXPOSE`d ports the guest holds that channel back until each port
/// accepts connections (see vk-agent's `wait_for_exposed_ports`), so a database service gates on
/// the port being up, not merely on the guest booting. The names mirror `plan_services`, so each
/// path addresses the same `svc-<name>` runtime dir.
async fn wait_for_services(ctx: &JobCtx, names: &[String]) -> Result<()> {
    let cfg = &ctx.cfg;
    // The siblings boot concurrently in the supervisor, so a single readiness budget spans them
    // all rather than a fresh one per service.
    let start = Instant::now();
    let deadline = start + Duration::from_secs(cfg.executor.vm.boot_timeout_secs);
    for name in names {
        let dir = ctx.job_dir.join(format!("svc-{name}"));
        let addr = crate::vmm::exec_addr(&dir.join("vsock.sock"), crate::units::VSOCK_PORT);
        loop {
            match vk_core::status::get_status_within(&addr, vk_core::status::BOOT_PROBE_BUDGET)
                .await
            {
                Ok(_) => {
                    println!(
                        "vk: service {name} ready in {:.1}s",
                        start.elapsed().as_secs_f32()
                    );
                    break;
                }
                Err(e) => {
                    if Instant::now() >= deadline {
                        log_tail(&dir.join(crate::run::CONSOLE_LOG), 30);
                        bail!(
                            "service {name} not ready after {}s ({e}) — console tail above",
                            cfg.executor.vm.boot_timeout_secs
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }
    Ok(())
}

/// Resolve MICROVM_IMAGE to the [`BootPlan`] the job VM boots: its kernel and media, plus
/// whether the boot is generic and whether a compose primary asked to nest.
///
/// `MICROVM_IMAGE: dockerfile:<path>[#<stage>]` builds a **git-defined** image from the
/// host-side checkout into the shared build tier and boots that; `compose:<file>#<primary>`
/// takes the primary out of the fleet and resolves that unit; any other form resolves
/// through the shared image cache (`resolve_ref`).
fn resolve_media(ctx: &JobCtx) -> Result<BootPlan> {
    let image_ref = ctx.image_ref.as_deref().unwrap_or("local/default");
    if let Some(spec) = image_ref.strip_prefix("dockerfile:") {
        return resolve_dockerfile_form(ctx, spec);
    }
    if let Some(spec) = image_ref.strip_prefix("compose:") {
        let fleet = load_compose_fleet(ctx, spec)?;
        return compose_unit_media(ctx, &fleet.units[fleet.primary]);
    }
    match crate::image::resolve_ref(&ctx.cfg, ctx.cfg.state_dir(), image_ref)? {
        ResolvedImage::Disk {
            rootfs,
            kernel,
            initrd,
            generic,
            config,
        } => Ok(BootPlan {
            kernel,
            media: Media {
                rootfs,
                initrd,
                config,
                use_guard: None,
            },
            generic,
            // A plain image ref carries no compose marker; only `[executor.vm] nested` can grant it.
            nested: false,
        }),
    }
}

/// The job's primary as a git-defined image
/// (`MICROVM_IMAGE: dockerfile:<path>[?context=<dir>&buildcontext=<N>=<dir>&arg=<N>=<V>][#<stage>]`):
/// build it and return it as generic-disk boot media (embedded kernel, agent + config riding
/// the preinit initramfs — the byte-clean model `vk build`/bundles use).
fn resolve_dockerfile_form(ctx: &JobCtx, spec: &str) -> Result<BootPlan> {
    let (rootfs, config, guard) = build_git_image(ctx, spec)?;
    Ok(BootPlan {
        kernel: None,
        media: Media {
            rootfs,
            initrd: None,
            config: Some(config),
            use_guard: Some(guard),
        },
        generic: true,
        nested: false,
    })
}

/// Build a git-defined image
/// `<path>[?context=<dir>&buildcontext=<N>=<dir>&arg=<N>=<V>][#<stage>]` from the host-side
/// checkout into the shared build tier and return its rootfs, captured runtime config, and a
/// held reference on the entry (see [`crate::ensure::ensure_build_tier`]). Shared
/// by the job's primary (`resolve_dockerfile_form`) and its git-defined services
/// (`plan_services`). Requires `[executor] host_checkout`: the Dockerfile + context are the
/// checked-out sources. The context defaults to the Dockerfile's directory; `?context=<dir>`
/// overrides it. `--build-arg`s come from `?arg=<NAME>=<VALUE>` parameters (repeatable), and
/// `?buildcontext=<NAME>=<DIR>` (repeatable) names an extra context directory — every path
/// confined to the checkout, since all of them are job-authored.
fn build_git_image(
    ctx: &JobCtx,
    spec: &str,
) -> Result<(PathBuf, vk_core::runcfg::RunConfig, crate::cachelock::Guard)> {
    let cfg = &ctx.cfg;
    if !cfg.executor.host_checkout {
        bail!(
            "a git-defined (dockerfile:/compose:) image requires [executor] host_checkout — the \
             Dockerfile and its context are the checked-out sources"
        );
    }
    let parsed = parse_dockerfile_spec(spec)?;
    let stage = parsed.stage;
    let checkout = ctx.host_checkout_dir();
    // The Dockerfile path is job-controlled; confine it to the checkout so a `dockerfile:` job
    // cannot read another tenant's checkout or an arbitrary host file during the host-side
    // build (this runs outside the microVM boundary).
    let dockerfile = confined_dockerfile(&checkout, parsed.path)?;
    let context = resolve_build_context(&checkout, &dockerfile, parsed.context)?;
    let dockerfiles = vec![dockerfile];
    let contexts = vec![context];
    let build_args: Vec<(String, String)> = parsed
        .build_args
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    // Named contexts are job-controlled paths too: confine each to the checkout, exactly as
    // the Dockerfile path and `context=` are, so a job cannot read outside its own checkout
    // during the host-side build.
    let build_contexts: Vec<(String, PathBuf)> = parsed
        .build_contexts
        .iter()
        .map(|(name, dir)| {
            let dir = confined_dockerfile(&checkout, dir)
                .with_context(|| format!("resolving buildcontext {name}"))?;
            Ok(((*name).to_string(), dir))
        })
        .collect::<Result<_>>()?;
    let stage_key = crate::build::target_stage_key(
        &dockerfiles,
        &contexts,
        &build_contexts,
        &build_args,
        stage,
    )
    .context("computing the git-defined image's stage fingerprint")?;
    let (net, audit) = effective_build_egress(cfg, ctx)?;
    let cache = crate::build::CacheOpts::from_config(&cfg.build);
    let recipe = crate::ensure::BuildRecipe {
        dockerfiles,
        contexts,
        build_contexts,
        build_args,
        kernel: cfg.build.kernel.clone(),
        cloud_hypervisor: Some(cfg.cloud_hypervisor().to_path_buf()),
        agent: cfg.build.agent.clone(),
        cache_registry: cache.registry,
        cache_insecure: cache.insecure,
        cache_auth: cache.auth,
        net,
        audit,
    };
    let (dir, guard) = crate::ensure::ensure_build_tier(
        cfg.state_dir(),
        cfg.image_cache_idle(),
        &recipe,
        stage,
        &stage_key,
        spec,
        None,
    )
    .with_context(|| format!("building the git-defined image {spec:?}"))?;
    let rootfs = dir.join(crate::ensure::UNIT_IMAGE);
    // The stage's Env/User captured by the build (applied at boot via the preinit initramfs).
    let config = crate::build::read_config_sidecar(&rootfs)?;
    Ok((rootfs, config, guard))
}

/// Resolve a job-controlled repo-relative path — the Dockerfile, a `context=`, a
/// `buildcontext=` directory — against the checkout root, refusing to escape it. Rejects an absolute path (`Path::join` would discard the base) and any `..`/root
/// component up front, then canonicalizes and re-checks the prefix so a symlink committed in
/// the repo cannot redirect the read outside the checkout (`read_to_string` follows symlinks).
/// A `dockerfile:` job fully controls its repo, so this is the boundary that keeps it inside its
/// own tree on a shared runner. The checked path is later read in a separate syscall, but the
/// checkout is host-private to this job and the job author owns its contents, so the resolve↔read
/// window is not a cross-tenant boundary — the confinement guards against reaching *another*
/// tenant's tree or the host, not against the job racing itself.
fn confined_dockerfile(checkout: &Path, rel: &str) -> Result<PathBuf> {
    use std::path::Component;
    let rel_path = Path::new(rel);
    if rel_path.components().any(|c| {
        matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        bail!("dockerfile:/context path must be relative and stay inside the repo: {rel:?}");
    }
    let root = checkout
        .canonicalize()
        .with_context(|| format!("resolving the checkout {}", checkout.display()))?;
    confine_under(&root, &checkout.join(rel_path))
}

/// Require an already-joined path to stay within `root` (a canonicalized checkout root):
/// canonicalize it and assert the prefix, defeating `..`/absolute/symlink escape. Used to
/// confine a compose file's job-authored `build:` context/Dockerfile paths, which the shared
/// compose parser resolves relative to the file without any confinement (fine for a trusted
/// `vk run --compose`, unsafe for an untrusted executor job).
fn confine_under(root: &Path, path: &Path) -> Result<PathBuf> {
    let canon = path
        .canonicalize()
        .with_context(|| format!("resolving {}", path.display()))?;
    if !canon.starts_with(root) {
        bail!("path {} resolves outside the repo checkout", path.display());
    }
    Ok(canon)
}

/// Read a unit's job-authored `env_file`s, confining every path to the checkout first.
///
/// `compose::load_with_env` leaves them unread so a file naming runner secrets cannot be
/// opened first. Keeping validation and reading together enforces that order.
///
/// Resolving and reading are separate operations. No job code can race them because this
/// runs before any guest boots in a slot-private, freshly `git clean`ed checkout, as does
/// [`confined_dockerfile`].
fn resolve_job_env_files(root: &Path, unit: &mut crate::compose::Unit) -> Result<()> {
    let mut vetted = Vec::new();
    for (path, required) in std::mem::take(&mut unit.env_files) {
        // Check confinement before existence so optional files cannot probe host paths.
        let abs = crate::compose::absolute(&path)?;
        if !abs.starts_with(root) {
            bail!(
                "compose service {:?}: env_file {} resolves outside the repo checkout",
                unit.name,
                path.display()
            );
        }
        // Canonicalize paths inside the checkout to reject symlinks that escape it.
        match abs.canonicalize() {
            Ok(real) if real.starts_with(root) => vetted.push((real, required)),
            Ok(_) => bail!(
                "compose service {:?}: env_file {} resolves outside the repo checkout",
                unit.name,
                path.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !required => continue,
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "compose service {:?}: env_file {}",
                        unit.name,
                        path.display()
                    )
                });
            }
        }
    }
    unit.env_files = vetted;
    crate::compose::resolve_env_files(unit)
}

/// Resolve a git-defined image's build context against the checkout. It defaults to the
/// (already-confined) Dockerfile's own directory — like `docker build <dir>`, so the
/// Dockerfile's `COPY`/`.dockerignore` paths are relative to where it lives — and re-confines
/// that directory, so a degenerate Dockerfile path resolving to the checkout root itself (whose
/// parent lies outside the checkout) is rejected rather than escaping it. A `?context=<dir>`
/// override is confined to the checkout the same way the Dockerfile path is.
fn resolve_build_context(
    checkout: &Path,
    dockerfile: &Path,
    rel_context: Option<&str>,
) -> Result<PathBuf> {
    match rel_context {
        Some(rel) => confined_dockerfile(checkout, rel),
        None => {
            let root = checkout
                .canonicalize()
                .with_context(|| format!("resolving the checkout {}", checkout.display()))?;
            let parent = dockerfile
                .parent()
                .context("a dockerfile: path has no parent directory")?;
            confine_under(&root, parent)
        }
    }
}

/// Parsed body of a `dockerfile:` image ref — `<path>[?<params>][#<stage>]`, query before
/// fragment (URL-style). `<params>` are `&`-separated `key=value`.
struct DockerfileSpec<'a> {
    /// The Dockerfile, relative to the checkout.
    path: &'a str,
    /// `context=<dir>`: the build context, defaulting to the Dockerfile's own directory.
    context: Option<&'a str>,
    /// `#<stage>`: the build target, if any.
    stage: Option<&'a str>,
    /// `arg=<NAME>=<VALUE>` (repeatable): `--build-arg`s for the build.
    build_args: Vec<(&'a str, &'a str)>,
    /// `buildcontext=<NAME>=<DIR>` (repeatable): named build contexts, so a stage can
    /// `COPY --from=<NAME>` files that live outside its own context — no staging copy into
    /// the context. Each `<DIR>` is checkout-relative and confined like `context=`.
    build_contexts: Vec<(&'a str, &'a str)>,
}

/// Parse a `dockerfile:` image spec's body into a [`DockerfileSpec`]. Query before fragment,
/// URL-style: the `#` binds first, so a `?`-parameter placed after a `#` lands inside the stage
/// rather than being parsed. `<params>` are `&`-separated `key=value`: `context=<dir>` overrides
/// the build context (default: the Dockerfile's own directory), `arg=<NAME>=<VALUE>`
/// (repeatable) supplies a `--build-arg`, and `buildcontext=<NAME>=<DIR>` (repeatable) names an
/// extra context directory a `COPY --from=<NAME>` or `RUN --mount=…,from=<NAME>` may read.
/// Anything else — an unknown parameter, an empty or repeated `context=`, an `arg` missing its
/// `=VALUE`, or a `buildcontext` that is not `NAME=DIR`, has an empty half, or repeats a name —
/// is rejected so a typo fails loudly rather than silently building the wrong thing. A build-arg `VALUE` may itself contain `=`, but
/// no value can contain `&` (the parameter separator) or `#` (the stage delimiter).
fn parse_dockerfile_spec(spec: &str) -> Result<DockerfileSpec<'_>> {
    let (head, stage) = match spec.split_once('#') {
        Some((h, s)) => (h, Some(s)),
        None => (spec, None),
    };
    let (path, query) = match head.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (head, None),
    };
    let mut context = None;
    let mut build_args = Vec::new();
    let mut build_contexts: Vec<(&str, &str)> = Vec::new();
    for kv in query
        .into_iter()
        .flat_map(|q| q.split('&'))
        .filter(|s| !s.is_empty())
    {
        match kv.split_once('=') {
            Some(("context", "")) => {
                bail!(
                    "dockerfile: context= value must not be empty (use context=. for the repo root)"
                )
            }
            Some(("context", _)) if context.is_some() => {
                bail!("dockerfile: context specified more than once in {query:?}")
            }
            Some(("context", v)) => context = Some(v),
            Some(("arg", v)) => {
                let nv = v
                    .split_once('=')
                    .with_context(|| format!("dockerfile: arg must be NAME=VALUE: {v:?}"))?;
                build_args.push(nv);
            }
            Some(("buildcontext", v)) => {
                let (name, dir) = v
                    .split_once('=')
                    .with_context(|| format!("dockerfile: buildcontext must be NAME=DIR: {v:?}"))?;
                if name.is_empty() || dir.is_empty() {
                    bail!("dockerfile: buildcontext NAME and DIR must both be set: {v:?}");
                }
                if build_contexts.iter().any(|(n, _)| *n == name) {
                    bail!("dockerfile: buildcontext {name:?} specified more than once");
                }
                build_contexts.push((name, dir));
            }
            _ => bail!(
                "unknown dockerfile: parameter {kv:?} (expected context=<dir>, \
                 buildcontext=NAME=DIR or arg=NAME=VALUE)"
            ),
        }
    }
    Ok(DockerfileSpec {
        path,
        context,
        stage,
        build_args,
        build_contexts,
    })
}

/// A `compose:<file>#<primary>` job's fleet, loaded from the host checkout: the parsed compose
/// units, the primary index (the job VM the stages exec into), and which units boot (the
/// primary's dependency closure, plus any `MICROVM_PROFILE`-enabled set). The primary + its
/// deps always boot; a profile can pull in extra services.
struct ComposeFleet {
    units: Vec<crate::compose::Unit>,
    primary: usize,
    enabled: Vec<bool>,
}

/// Parse `compose:<file>#<primary>` and load the fleet from the host checkout. Requires
/// `[executor] host_checkout` (the compose file + its build contexts are the checked-out
/// sources) and a `#<primary>` naming the job VM. `MICROVM_PROFILE` (space/comma separated)
/// selects extra services.
fn load_compose_fleet(ctx: &JobCtx, spec: &str) -> Result<ComposeFleet> {
    if !ctx.cfg.executor.host_checkout {
        bail!(
            "a compose: image requires [executor] host_checkout — the compose file and its build \
             contexts are the checked-out sources"
        );
    }
    let (rel_file, primary_name) = spec.split_once('#').with_context(|| {
        format!("compose: image {spec:?} must name the primary service: compose:<file>#<service>")
    })?;
    let checkout = ctx.host_checkout_dir();
    let file = confined_dockerfile(&checkout, rel_file)?;
    // The compose file is job-authored (untrusted): interpolate only the job's own
    // `CUSTOM_ENV_*` variables (plus the committed `.env`), never the executor's ambient
    // process environment, so it cannot pull runner-level secrets into an image or sibling.
    // Withhold `${VK_*}` too because it exposes runner paths and ids.
    let mut units = crate::compose::load_with_env(
        &file,
        &|name| std::env::var(format!("CUSTOM_ENV_{name}")).ok(),
        None,
    )?;
    let primary = units
        .iter()
        .position(|u| u.name == primary_name)
        .with_context(|| {
            format!(
                "compose: primary {primary_name:?} is not a service in {rel_file} (declared: {})",
                units
                    .iter()
                    .map(|u| u.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
    let profiles: Vec<String> = std::env::var("CUSTOM_ENV_MICROVM_PROFILE")
        .unwrap_or_default()
        .split([',', ' ', '\t'])
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    // Boot the primary + its dependency closure, plus anything a profile enables.
    let mut enabled = crate::compose::enabled(&units, &profiles);
    for (i, on) in crate::compose::dependency_closure(&units, primary)
        .into_iter()
        .enumerate()
    {
        enabled[i] |= on;
    }
    enabled[primary] = true;
    // Confine every booting unit's job-authored `build:` and `env_file` paths to the
    // checkout before the host reads them. Reject `volumes:` because a bind mount would
    // expose a host path to the untrusted guest.
    let root = checkout
        .canonicalize()
        .with_context(|| format!("resolving the checkout {}", checkout.display()))?;
    for (i, unit) in units.iter_mut().enumerate() {
        // Leave disabled units' `env_files` unread.
        if !enabled[i] {
            continue;
        }
        if !unit.volumes.is_empty() {
            bail!(
                "compose service {:?}: volumes: are not supported on the GitLab executor — a \
                 bind mount would expose a host path across the microVM boundary",
                unit.name
            );
        }
        refuse_job_nesting(ctx.cfg.executor.vm.nested, unit)?;
        resolve_job_env_files(&root, unit)?;
        if let crate::compose::Source::Build {
            context,
            dockerfiles,
            build_contexts,
            ..
        } = &mut unit.source
        {
            *context = confine_under(&root, context)?;
            for df in dockerfiles.iter_mut() {
                *df = confine_under(&root, df)?;
            }
            // `additional_contexts` are job-authored paths too, and they are read host-side
            // during the build — confine each like the context and the Dockerfiles.
            for (name, dir) in build_contexts.iter_mut() {
                *dir = confine_under(&root, dir)
                    .with_context(|| format!("compose additional_contexts {name}"))?;
            }
        }
    }
    Ok(ComposeFleet {
        units,
        primary,
        enabled,
    })
}

/// The enabled service units of a compose fleet — every booting unit except the primary — in
/// boot order, for provisioning + warming as siblings.
fn compose_service_units(fleet: &ComposeFleet) -> Result<Vec<crate::compose::Unit>> {
    Ok(crate::compose::boot_order(&fleet.units)?
        .into_iter()
        .filter(|&i| i != fleet.primary && fleet.enabled[i])
        .map(|i| fleet.units[i].clone())
        .collect())
}

/// Resolve one compose unit to boot media: a `build:` unit is built into the shared build tier
/// (from the host checkout), an `image:` unit resolves through the shared image cache. Its
/// compose `environment`/`user` overrides are merged into the boot config either way.
fn compose_unit_media(ctx: &JobCtx, unit: &crate::compose::Unit) -> Result<BootPlan> {
    match &unit.source {
        crate::compose::Source::Build { .. } => {
            let (rootfs, config, guard) = build_compose_unit(ctx, unit)?;
            Ok(BootPlan {
                kernel: None,
                media: Media {
                    rootfs,
                    initrd: None,
                    config: Some(config),
                    use_guard: Some(guard),
                },
                generic: true,
                nested: unit.nested,
            })
        }
        crate::compose::Source::Image(image) => {
            let crate::image::ResolvedImage::Disk {
                rootfs,
                kernel,
                initrd,
                generic,
                config,
            } = crate::image::resolve_ref(&ctx.cfg, ctx.cfg.state_dir(), image)?;
            let config = Some(crate::compose::merged_config(
                &config.unwrap_or_default(),
                unit,
            ));
            Ok(BootPlan {
                kernel,
                media: Media {
                    rootfs,
                    initrd,
                    config,
                    use_guard: None,
                },
                generic,
                nested: unit.nested,
            })
        }
    }
}

/// Build a compose `build:` unit into the shared build tier (from the host checkout) and return
/// its rootfs, merged runtime config, and a held reference on the entry (see
/// [`crate::ensure::ensure_build_tier`]). The build wiring comes from `[build]` (embedded kernel/
/// agent by default); `--build-arg`s are the unit's own (from the compose file / its `.env`).
fn build_compose_unit(
    ctx: &JobCtx,
    unit: &crate::compose::Unit,
) -> Result<(PathBuf, vk_core::runcfg::RunConfig, crate::cachelock::Guard)> {
    let cfg = &ctx.cfg;
    // Held across the build: an embedded asset lives in a memfd whose /proc/self/fd path is
    // valid only while the handle is open, and the build is synchronous.
    let agent = crate::embed::resolve(crate::embed::Asset::Agent, cfg.build.agent.as_deref())?;
    let kernel = crate::embed::resolve(crate::embed::Asset::Kernel, cfg.build.kernel.as_deref())?;
    // A compose `build:` service's RUN egress is the build phase — same `[egress.build]`
    // policy and audit as the git-defined primary.
    let (net, audit) = effective_build_egress(cfg, ctx)?;
    let cache = crate::build::CacheOpts::from_config(&cfg.build);
    let build = crate::units::BuildOpts {
        // A compose unit's build args are its own (compose file / `.env`); there is no
        // executor-global build-arg channel.
        build_args: vec![],
        kernel: kernel.path.clone(),
        cloud_hypervisor: cfg.cloud_hypervisor().to_path_buf(),
        agent: agent.path.clone(),
        cache_registry: cache.registry,
        cache_insecure: cache.insecure,
        cache_auth: cache.auth,
        net,
        audit,
    };
    // The build reports the entry it materialized; addressing it separately would pin the
    // fingerprint computed here rather than the one the build settled on.
    crate::units::ensure_unit_build_sync(
        unit,
        cfg.state_dir(),
        cfg.image_cache_idle(),
        &build,
        None,
    )
}

/// The detached job supervisor (`vk gitlab supervise <job_dir>`, spawned by
/// prepare): assembles and boots everything the job needs — switch, virtiofsds,
/// forwards, the VMM — as tied children (PDEATHSIG), then supervises. SIGTERM
/// (cleanup, or the stale-state sweep) shuts the guest down gracefully and exits;
/// the children cascade. Readiness is prepare's business (it polls the agent).
pub async fn supervise(ctx: &JobCtx, job_dir_arg: &Path) -> Result<()> {
    if job_dir_arg != ctx.job_dir {
        bail!(
            "supervise arg {} != the job dir the environment derives ({}) — refusing",
            job_dir_arg.display(),
            ctx.job_dir.display()
        );
    }
    // The pidfile is written by this process (not prepare): it exists from the
    // first moment there is something to signal, whatever happens to prepare.
    std::fs::write(ctx.supervisor_pidfile(), std::process::id().to_string())
        .with_context(|| format!("writing {}", ctx.supervisor_pidfile().display()))?;

    let cfg = &ctx.cfg;
    // Prepare still holds its own reference on the checkout — it does not return until this
    // process has booted the VM it is polling for — so taking ours here leaves no window in
    // which the tree is unreferenced. Taken before resolving any git-defined image out of it,
    // and kept until the VM and its virtio-fs share are gone.
    let _checkout_use = if cfg.executor.host_checkout {
        let dest = ctx.host_checkout_dir();
        Some(
            crate::checkout::acquire_use_lock(&dest)
                .with_context(|| format!("locking host checkout {}", dest.display()))?,
        )
    } else {
        None
    };
    let BootPlan {
        kernel: kernel_opt,
        mut media,
        generic,
        nested: primary_nested,
    } = resolve_media(ctx)?;
    let (cpus, mem) = vm_size(ctx)?;
    // The agent and kernel back each guest boot (they ride the boot media) and any
    // service build; an embedded copy lives in a memfd whose path is valid only while
    // its handle is open — supervise runs for the job's whole life. `[build] agent`/
    // `[build] kernel` override; a bundle that ships its own kernel resolves to that.
    let agent = crate::embed::resolve(crate::embed::Asset::Agent, cfg.build.agent.as_deref())?;
    let kernel = crate::embed::resolve(
        crate::embed::Asset::Kernel,
        kernel_opt.as_deref().or(cfg.build.kernel.as_deref()),
    )?;
    let mut children: Vec<std::process::Child> = Vec::new();
    // Remember the switch so `stop_helpers` can drain it after stopping the other helpers.
    // `None` unless `net.mode = "switch"`.
    let mut switch_pid: Option<u32> = None;
    // Reference the materialized image bases this job overlays (the primary plus every
    // service) for the whole life of `supervise`, so the cache's idle GC cannot evict a
    // base out from under a running overlay. A shared advisory lock the kernel drops when
    // this process exits — held in this Vec until supervise returns (job teardown).
    let mut use_guards: Vec<crate::cachelock::Guard> = Vec::new();
    // The other half of the admission reservation prepare took (see admit): held here for the
    // job's whole life, so the memory and disk this job claimed keep counting until the VM is
    // gone. `None` when admission is off.
    let reservation = crate::admit::hold(&ctx.admit_dir(), &ctx.job_id);
    // Record placement in the reservation this supervisor holds for the VM's lifetime.
    let placement = job_placement(ctx, reservation.as_ref(), cpus).unwrap_or_else(|e| {
        // Fall back to live host memory; a placement error must not fail the job.
        eprintln!("virtkit: placing this job from the ledger ({e:#}) — using the live figures");
        crate::numa::Numa::Auto
    });
    // A build-tier base already carries its own reference straight from the build that
    // promoted it (see `Media::use_guard`) — no gap to close here. Anything resolved through
    // `image::resolve_ref` instead takes its reference fresh, now.
    if let Some(g) = media.use_guard.take() {
        use_guards.push(g);
    } else if let Some(g) = crate::image::acquire_use_lock_for(cfg.state_dir(), &media.rootfs)? {
        use_guards.push(g);
    }
    // Every guest gets a throwaway CoW overlay over the ro base rootfs.
    let overlay = ctx.overlay();
    crate::qcow2::create_overlay(&overlay, &media.rootfs)?;

    let (mut cmdline, initramfs) = if generic {
        // generic guest: the embedded agent rides a preinit initramfs as /init, pivots
        // into the ext4 root on /dev/vda and serves the exec channel — the rootfs stays
        // byte-clean (no baked agent), and the image's Env/User are applied from the
        // bundle config. Same model `vk run -f`/`vk build` use.
        let cpio = ctx.job_dir.join("initramfs.cpio");
        crate::initramfs::build_agent_initramfs_with_config(
            &agent.path,
            media.config.as_ref(),
            &cpio,
        )
        .context("building the guest preinit initramfs")?;
        (
            format!(
                "console=ttyS0 rdinit=/init VIRTKIT_PIVOT=/dev/vda \
                 VIRTKIT_HOSTNAME={} VIRTKIT_VSOCK_PORT={}",
                cfg.executor.vm.hostname, cfg.executor.vm.vsock_port
            ),
            Some(cpio),
        )
    } else {
        // self-booting image: virtkit-agent (baked) is PID 1, execs the image's captured
        // entrypoint (VIRTKIT_MODE=service) which brings up systemd; the in-guest serve
        // agent then runs as a systemd unit. The image ships its own initrd, if any.
        (
            format!(
                "console=ttyS0 root=/dev/vda rw rootfstype=ext4 init=/usr/local/bin/vk-agent \
                 VIRTKIT_MODE=service VIRTKIT_HOSTNAME={}",
                cfg.executor.vm.hostname
            ),
            media.initrd.clone(),
        )
    };

    let mut shares: Vec<crate::vmm::FsShare> = Vec::new();
    // `[executor.vm] dax`: the window each directory share gets, so the guest reads a shared tree
    // out of the host page cache rather than copying it into its own. Same window for every
    // share here — the tools tree is the one several job VMs read at once.
    let dax = crate::run::dax_share(vm_dax(cfg)?, None, crate::vmm::libkrun_selected());
    if let Some(share) = &cfg.executor.share {
        let vfsd_sock = ctx.vfsd_sock();
        // libkrun mounts the host dir directly (built-in virtio-fs); only
        // cloud-hypervisor needs an external virtiofsd on the socket.
        if !crate::vmm::libkrun_selected() {
            let mut vfsd = cfg.virtiofsd_command(); // bundled `vk virtiofsd` unless configured
            vfsd.arg(format!("--socket-path={}", vfsd_sock.display()))
                .arg(format!("--shared-dir={}", share.dir.display()))
                .args(["--cache=auto", "--sandbox=none"]);
            if share.readonly {
                vfsd.arg("--readonly");
            }
            children.push(spawn_tied_logged(vfsd, &ctx.vfsd_log()).context("spawning virtiofsd")?);
            wait_for_socket(&vfsd_sock, Duration::from_secs(5))
                .context("virtiofsd did not create its socket")?;
        }
        shares.push(crate::vmm::FsShare {
            tag: "workdir".into(),
            socket: vfsd_sock,
            host_dir: share.dir.clone(),
            read_only: share.readonly,
            dax,
            uid_map: Vec::new(),
            gid_map: Vec::new(),
            cache: crate::vmm::ShareCache::Auto,
        });
    }

    // GitLab CI tools ([executor] tools_dir): a second, read-only virtio-fs share. The
    // in-guest agent links the tools the job image lacks onto its PATH — dynamic,
    // so nothing is baked into the bundle and a host update needs no re-conversion.
    if let Some(dir) = &cfg.executor.tools_dir {
        let sock = ctx.tools_vfsd_sock();
        if !crate::vmm::libkrun_selected() {
            let mut vfsd = cfg.virtiofsd_command();
            vfsd.arg(format!("--socket-path={}", sock.display()))
                .arg(format!("--shared-dir={}", dir.display()))
                .args(["--cache=auto", "--sandbox=none", "--readonly"]);
            children.push(
                spawn_tied_logged(vfsd, &ctx.tools_vfsd_log())
                    .context("spawning the tools virtiofsd")?,
            );
            wait_for_socket(&sock, Duration::from_secs(5))
                .context("the tools virtiofsd did not create its socket")?;
        }
        shares.push(crate::vmm::FsShare {
            tag: "vktools".into(),
            socket: sock,
            host_dir: dir.clone(),
            read_only: true,
            dax,
            uid_map: Vec::new(),
            gid_map: Vec::new(),
            cache: crate::vmm::ShareCache::Auto,
        });
        cmdline.push_str(" VIRTKIT_TOOLS=vktools:/run/virtkit-tools");
    }

    // [executor] host_checkout: the sources checked out on the host in prepare, shared
    // into the guest at CI_PROJECT_DIR. The job sets GIT_STRATEGY: none so its
    // get_sources reuses this tree — the git token never enters the guest. With
    // checkout_overlay (the default) the share is exported read-only and the guest
    // builds on an overlay above it; checkout_overlay = false exports it read-write,
    // which is added attack surface toward an untrusted guest.
    if cfg.executor.host_checkout {
        let overlay = cfg.executor.checkout_overlay;
        let mount = ctx
            .ci_project_dir
            .as_deref()
            .context("host_checkout is set but CI_PROJECT_DIR is unset")?;
        let host_dir = ctx.host_checkout_dir();
        let sock = ctx.job_dir.join("cibuild-vfsd.sock");

        // The checkout tree is 0700 and owned by the user vk runs as (protects the embedded
        // git token at rest). Map the guest job user 1:1 onto that host owner, both ways: the
        // guest writes the tree as the owner, and — since the guest FUSE enforces perms on the
        // ownership it SEES — the tree must appear owned by the job user, so host-owned files
        // map back to the job user guest-side. We resolve the job's ids here; the run user is
        // MICROVM_USER, else the image `User`; root (or a failed resolve) needs no map.
        use std::os::unix::fs::MetadataExt;
        let owner = std::fs::metadata(&host_dir)
            .with_context(|| format!("stat host checkout dir {}", host_dir.display()))?;
        let run_user = ctx
            .user_req
            .clone()
            .or_else(|| media.config.as_ref().map(|c| c.user.clone()))
            .unwrap_or_default();
        let (uid_map, gid_map) =
            checkout_id_maps(&run_user, &media.rootfs, (owner.uid(), owner.gid()));
        // Behind the overlay the host tree is read-only for the whole job (prepare wrote it,
        // nothing on the host touches it until cleanup), so the guest may keep every entry,
        // attribute and miss it fetched: a tree-wide pass — git status, a build tool's
        // dependency check — round-trips to the host once instead of once per pass. Exported
        // read-write instead, the tree is the guest's alone for the job — the host only resets
        // it for the next one — so it caches the same way and skips every flush and fsync
        // besides: its writes need survive neither the job nor a host crash.
        let cache = if overlay {
            crate::vmm::ShareCache::Immutable
        } else {
            crate::vmm::ShareCache::Ephemeral
        };

        // checkout_tmpfs: the tree itself goes into the overlay's upper at boot, packed here as
        // one tar the guest streams and unpacks onto its tmpfs — every read of it is then guest
        // RAM, where the lower costs a virtio-fs round trip per file on every pass. A pack
        // failure loses only that: the lower still serves the tree.
        let seed_dir = if overlay && cfg.executor.checkout_tmpfs {
            let seed_dir = ctx.job_dir.join("checkout");
            std::fs::create_dir_all(&seed_dir)
                .with_context(|| format!("creating {}", seed_dir.display()))?;
            let started = std::time::Instant::now();
            let owner = guest_run_user_ids(&run_user, &media.rootfs);
            match pack_checkout_seed(&host_dir, &seed_dir.join(CICHECKOUT_TAR), owner) {
                Ok(bytes) => {
                    let secs = started.elapsed().as_secs_f64();
                    eprintln!(
                        "virtkit: checkout packed for the guest tmpfs: {} MiB in {secs:.1}s",
                        bytes >> 20
                    );
                    // This process's output stays in the supervisor log; the cleanup stage
                    // reads this record to put the figures in the job trace.
                    let _ = std::fs::write(ctx.checkout_seed_log(), format!("{bytes} {secs:.1}\n"));
                    Some(seed_dir)
                }
                // No space for the tar is no space for the overlay beside it either.
                Err(e) if storage_full(&e).is_some() => {
                    return Err(name_full_fs(e, ctx.jobs_dir()));
                }
                Err(e) => {
                    eprintln!(
                        "virtkit: warning: checkout not seeded into the guest tmpfs ({e:#}); \
                         the guest reads it through virtio-fs"
                    );
                    None
                }
            }
        } else {
            None
        };

        if !crate::vmm::libkrun_selected() {
            let mut vfsd = cfg.virtiofsd_command();
            vfsd.arg(format!("--socket-path={}", sock.display()))
                .arg(format!("--shared-dir={}", host_dir.display()))
                .args(cache.virtiofsd_args())
                .arg("--sandbox=none");
            if overlay {
                vfsd.arg("--readonly");
            }
            for m in &uid_map {
                vfsd.arg(format!("--uid-map={m}"));
            }
            for m in &gid_map {
                vfsd.arg(format!("--gid-map={m}"));
            }
            children.push(
                spawn_tied_logged(vfsd, &ctx.job_dir.join("cibuild-vfsd.log"))
                    .context("spawning the checkout virtiofsd")?,
            );
            wait_for_socket(&sock, Duration::from_secs(5))
                .context("the checkout virtiofsd did not create its socket")?;
        }
        shares.push(crate::vmm::FsShare {
            tag: CIBUILD_TAG.into(),
            socket: sock,
            host_dir,
            read_only: overlay,
            dax,
            uid_map,
            gid_map,
            cache,
        });
        // Keep the tar outside the checkout, on a private read-only share removed with the job.
        if let Some(seed_dir) = &seed_dir {
            let sock = ctx.job_dir.join("cicheckout-vfsd.sock");
            if !crate::vmm::libkrun_selected() {
                let mut vfsd = cfg.virtiofsd_command();
                vfsd.arg(format!("--socket-path={}", sock.display()))
                    .arg(format!("--shared-dir={}", seed_dir.display()))
                    .args(crate::vmm::ShareCache::Immutable.virtiofsd_args())
                    .args(["--sandbox=none", "--readonly"]);
                children.push(
                    spawn_tied_logged(vfsd, &ctx.job_dir.join("cicheckout-vfsd.log"))
                        .context("spawning the checkout seed virtiofsd")?,
                );
                wait_for_socket(&sock, Duration::from_secs(5))
                    .context("the checkout seed virtiofsd did not create its socket")?;
            }
            shares.push(crate::vmm::FsShare {
                tag: CICHECKOUT_TAG.into(),
                socket: sock,
                host_dir: seed_dir.clone(),
                read_only: true,
                dax,
                uid_map: Vec::new(),
                gid_map: Vec::new(),
                cache: crate::vmm::ShareCache::Immutable,
            });
        }
        cmdline.push_str(&checkout_virtiofs_cmdline(
            mount,
            overlay,
            checkout_overlay_size(&cfg.executor.checkout_overlay_size)?,
            seed_dir.is_some(),
        ));
    }

    // [executor] atop: this job's statistics archive (created by prepare), shared
    // read-write — the guest's own sampler writes the log, so this is the one share a
    // job guest must be able to write. Only its own directory is exported, and the
    // knob on the cmdline is what starts the sampler at all.
    if let Some(dir) = crate::atop::job_archive_dir(ctx) {
        let sock = ctx.atop_vfsd_sock();
        // Recording is optional and on by default, so a share that will not start costs the
        // job its statistics and nothing else — it must never be the reason a job fails.
        let mut recording = true;
        if !crate::vmm::libkrun_selected() {
            let mut vfsd = cfg.virtiofsd_command();
            vfsd.arg(format!("--socket-path={}", sock.display()))
                .arg(format!("--shared-dir={}", dir.display()))
                .args(["--cache=auto", "--sandbox=none"]);
            match spawn_tied_logged(vfsd, &ctx.atop_vfsd_log()) {
                Ok(child) => children.push(child),
                Err(e) => {
                    eprintln!("virtkit: warning: not recording guest stats: {e:#}");
                    recording = false;
                }
            }
            if recording && let Err(e) = wait_for_socket(&sock, Duration::from_secs(5)) {
                eprintln!(
                    "virtkit: warning: not recording guest stats: the stats virtiofsd did not \
                     create its socket: {e:#}"
                );
                recording = false;
            }
        }
        // Both together or neither: the share with no knob mounts an archive nothing writes
        // to, and the knob with no share starts a sampler with nowhere to write.
        if recording {
            shares.push(crate::vmm::FsShare {
                tag: vk_core::atop::TAG.into(),
                socket: sock,
                host_dir: dir,
                read_only: false,
                dax: None,
                uid_map: Vec::new(),
                gid_map: Vec::new(),
                cache: crate::vmm::ShareCache::Auto,
            });
            crate::run::push_knob(
                &mut cmdline,
                &vk_core::atop::cmdline_knob(crate::atop::interval_secs(cfg)?),
            );
        }
    }

    // Charged before the tag list is built: a share whose window will not fit must not be
    // named to the agent, which would mount it `dax=always` and be refused every boot.
    crate::vmm::apply_dax_budget(&mut shares, &mem);
    let dax_tags = crate::run::dax_tags(&shares);
    if !dax_tags.is_empty() {
        cmdline.push_str(&format!(" VIRTKIT_VIRTIOFS_DAX={dax_tags}"));
    }
    // Tell the agent which shares use `dax=inode` and a file-size floor.
    let dax_inode_tags = crate::run::dax_inode_tags(&shares);
    if !dax_inode_tags.is_empty() {
        cmdline.push_str(&format!(" VIRTKIT_VIRTIOFS_DAX_INODE={dax_inode_tags}"));
    }

    // Idle page-cache trimming (`[executor.vm] reclaim`): the job guest gives file cache it stopped
    // using back to the host whenever it is not under memory pressure, so a job's read-once
    // trees stop counting against the box once it moves on. The job guest always keeps the
    // agent as PID 1, so `[executor.vm] balloon` is the only axis that can take the knob away —
    // without free-page reporting the job would lose its cache and the host would gain
    // nothing. Its services keep a balloon of their own whatever this says, so `plan_services`
    // hands them `[executor.vm] reclaim` regardless.
    let reclaim = vm_reclaim(cfg)?;
    if crate::run::wants_reclaim(crate::run::InitSource::Default, cfg.executor.vm.balloon) {
        crate::run::push_knob(&mut cmdline, &crate::run::reclaim_cmdline(reclaim, &mem)?);
    }

    let mut net = crate::vmm::Net::None;
    // services: need the per-job LAN — they are sibling VMs on the switch.
    if cfg.net.mode != "switch" && !crate::services::from_env()?.is_empty() {
        bail!(
            "the job declares services:, which boot as sibling VMs on the per-job \
             switch — set [net] mode = \"switch\" (got {:?})",
            cfg.net.mode
        );
    }
    // (ip, prefix, gw, dns) once a tap is wired, rendered onto the cmdline below
    // in the form the chosen init understands.
    let mut net_info: Option<(String, u32, String, String)> = None;
    // The job VM's switch attach (`net.mode = switch`): its NICs or vsock bridge.
    let mut job_attach: Option<crate::vmm::SwitchAttach> = None;
    match cfg.net.mode.as_str() {
        "none" => {}
        "tap" => {
            if cfg.net.tap.is_empty() {
                bail!("net.mode = \"tap\" requires net.tap");
            }
            net = crate::vmm::Net::Tap {
                tap: cfg.net.tap.clone(),
                mac: cfg.net.mac.clone(),
            };
            if !cfg.net.ip.is_empty() {
                let (ip, prefix) = split_cidr(&cfg.net.ip)?;
                net_info = Some((ip, prefix, cfg.net.gw.clone(), cfg.net.dns.clone()));
            }
        }
        "pool" => {
            let lease = crate::net::allocate(ctx)?;
            net = crate::vmm::Net::Tap {
                tap: lease.tap.clone(),
                mac: lease.mac.clone(),
            };
            net_info = Some((lease.ip, lease.prefix.into(), lease.gw, lease.dns));
        }
        "switch" => {
            // Per-job userspace switch, no kernel `ip=`: the agent sets the static
            // address on eth0 — a virtio-net device backed by the switch's socket under
            // libkrun, a tap the agent bridges over vsock under cloud-hypervisor. Spawn
            // the switch (with the egress allowlist) so it is listening before the VMM or
            // the guest dials it; then point the agent at it. The same shared LAN/egress
            // core `run --compose` uses.
            let (gateway, prefix, guest_ip) = crate::net::switch_addrs(&cfg.net.subnet)?;
            // Every service's guard lands directly in `use_guards` inside `plan_services`: a
            // git-defined/`build:` service's the moment its build promotes it, an `image:`
            // service's fresh off `image::resolve_ref` — no gap either way.
            let services = plan_services(ctx, gateway, prefix, &mut use_guards)?;
            // the switch binds each service's vsock socket at startup: the
            // runtime dirs must exist before it spawns.
            for svc in &services {
                std::fs::create_dir_all(ctx.job_dir.join(format!("svc-{}", svc.name)))
                    .with_context(|| format!("creating service dir for {}", svc.name))?;
            }
            let switch = spawn_switch(ctx, gateway, prefix, guest_ip, &services)?;
            switch_pid = Some(switch.id());
            children.push(switch);
            for svc in &services {
                let dir = ctx.job_dir.join(format!("svc-{}", svc.name));
                let (child, aux) = crate::units::boot_unit(
                    svc,
                    &dir,
                    &kernel.path,
                    cfg.cloud_hypervisor(),
                    &agent.path,
                    cfg.net.net_port,
                    gateway,
                )
                .with_context(|| format!("booting service {}", svc.name))?;
                println!("virtkit: service {} booting ({})", svc.name, svc.ip);
                children.push(child);
                children.extend(aux);
            }
            let attach = crate::vmm::switch_attach(
                &ctx.vsock_sock(),
                cfg.net.net_port,
                &[guest_ip],
                prefix,
                gateway,
                crate::vmm::libkrun_selected(),
            );
            cmdline.push_str(&attach.cmdline);
            job_attach = Some(attach);
        }
        other => bail!("unsupported net.mode {other:?} (none|tap|pool|switch)"),
    }
    if let Some((ip, prefix, gw, dns)) = net_info {
        // Both flavours bring eth0 up from the kernel `ip=` autoconfig param
        // (CONFIG_IP_PNP) at boot — earlier and more reliable than configuring it
        // from a userspace init. Format:
        // <client>:<server>:<gw>:<netmask>:<host>:<device>:<autoconf>.
        // The agent writes resolv.conf from VIRTKIT_VM_DNS.
        cmdline.push_str(" net.ifnames=0 biosdevname=0");
        cmdline.push_str(&format!(
            " ip={ip}::{gw}:{}::eth0:off",
            prefix_to_netmask(prefix)
        ));
        if !dns.is_empty() {
            cmdline.push_str(&format!(" VIRTKIT_VM_DNS={dns}"));
        }
    }

    // RAM scratch mounts (e.g. CI /builds): the agent mounts these (VIRTKIT_TMPFS)
    // before handing off to the payload, in any mode.
    if !cfg.executor.guest.tmpfs.is_empty() {
        // lands on the kernel cmdline: a space or comma in an entry would split
        // or corrupt the VIRTKIT_TMPFS list the agent parses
        for entry in &cfg.executor.guest.tmpfs {
            if !entry.starts_with('/')
                || !entry.contains(':')
                || entry.contains(|c: char| c.is_whitespace() || c == ',')
            {
                bail!("invalid guest.tmpfs entry {entry:?} (want \"/path:size\")");
            }
        }
        cmdline.push_str(&format!(
            " VIRTKIT_TMPFS={}",
            cfg.executor.guest.tmpfs.join(",")
        ));
    }

    // SSH-agent forwarding ([executor.auth] ssh_agent): tell the guest agent to present
    // SSH_AUTH_SOCK and relay it over a vsock port to the host side (the forward from
    // ssh_agent_forward_command, started by the supervisor). A no-op if the runner has
    // no agent — warn so a misconfig is visible.
    if ssh_agent_forwarding(cfg) {
        cmdline.push_str(&format!(
            " VIRTKIT_SSH_AGENT_PORT={}",
            crate::run::SSH_AGENT_VSOCK_PORT
        ));
    } else if cfg.executor.auth.ssh_agent {
        eprintln!(
            "virtkit: [executor.auth] ssh_agent set but SSH_AUTH_SOCK is unset — not forwarding"
        );
    }

    if !cfg.executor.vm.cmdline_extra.is_empty() {
        cmdline.push(' ');
        cmdline.push_str(&cfg.executor.vm.cmdline_extra);
    }

    // kernel is common; the boot medium is the CoW disk overlay plus a
    // self-booting image's initrd. A generic guest on the pinned kernel ships
    // no initrd (virtio-blk + ext4 built in).
    // The overlay is deleted with the job, so it offers the guest no FLUSH: each fsync a
    // package manager or build tool issues per file would otherwise be a host fsync plus
    // qcow2 metadata writeback, for data nobody keeps.
    let disks = vec![crate::vmm::Disk::overlay(overlay.clone()).ephemeral()];

    // shared=on (set via shared_mem): required by virtio-fs, harmless without.
    // vsock ports the guest uses: the exec channel always, plus the switch bridge in
    // `switch` net mode (guest egress over the userspace switch) and the ssh-agent
    // bridge when agent forwarding is on. Tap/pool networking uses a virtio-net device,
    // not vsock. Only the libkrun backend consumes this; cloud-hypervisor derives it.
    let mut vsock_ports = vec![crate::vmm::VsockPort::exec(
        &ctx.vsock_sock(),
        cfg.executor.vm.vsock_port,
    )];
    let nics = job_attach
        .map(|attach| attach.apply(&mut vsock_ports))
        .unwrap_or_default();
    if ssh_agent_forwarding(cfg) {
        vsock_ports.push(crate::vmm::VsockPort::bridge(
            &ctx.vsock_sock(),
            crate::run::SSH_AGENT_VSOCK_PORT,
        ));
    }

    let spec = crate::vmm::VmSpec {
        kernel: kernel.path.clone(),
        cmdline,
        disks,
        initramfs,
        shares,
        vsock_cid: 3,
        vsock_socket: ctx.vsock_sock(),
        vsock_ports,
        cpus,
        mem: mem.clone(),
        shared_mem: true,
        net,
        nics,
        balloon: cfg.executor.vm.balloon,
        serial_log: ctx.console_log(),
        // an image (stock) kernel keeps serial via the VIRTKIT_KERNEL=image cmdline token;
        // the executor has no BYO-kernel flag, so nothing forces it otherwise.
        console_serial: false,
        pmu: false,
        // `[executor.vm] nested`, the runner's grant (checked against the host in prepare), ORed
        // with the compose primary's own marker exactly as `vk run` does it. The grant is
        // what let that marker past `refuse_job_nesting`, so today the OR only ever agrees
        // with the grant — it is here so the two paths cannot drift apart.
        nested: crate::run::effective_nested(cfg.executor.vm.nested, primary_nested),
        // libkrun has no API socket (it is driven as a subprocess); cloud-hypervisor
        // uses one for graceful shutdown in graceful_vmm_stop.
        api_socket: (!crate::vmm::libkrun_selected()).then(|| ctx.api_sock()),
        pass_fds: Vec::new(),
        // The CI job runs in its own process (no `--vm-name`), so the default template
        // applies: `vk:<hostname>`.
        proc_name: crate::vmm::resolve_proc_name(&cfg.executor.vm.hostname),
        // A CI job VM ends on a guest reset rather than rebooting in place.
        reboot: false,
        numa: placement,
    };
    // passive listeners the guest dials once up: safe (and simplest) to start before
    // the VMM, and intentionally not bind-waited — they bind long before the guest
    // boots far enough to dial them. Both are plain `vk forward` children.
    if let Some(fwd) = ssh_agent_forward_command(ctx)? {
        children.push(
            spawn_tied_logged(fwd, &ctx.ssh_agent_forward_log())
                .context("spawning the ssh-agent forward")?,
        );
    }
    let vmm = crate::vmm::selected(cfg.cloud_hypervisor());
    // The one VMM spawn shared with `vk run`/`vk build`: it clears CLOEXEC on the
    // embedded-kernel (and any pass-fd) so those fds survive the exec into the VMM
    // subprocess — open-coding a plain spawn here silently dropped them.
    let mut vmm_child = crate::run::spawn_vmm(&*vmm, &spec, crate::prio::Prio::Normal)
        .with_context(|| format!("spawning the {} VMM", vmm.name()))?;

    // Own the job until told to stop (SIGTERM: cleanup or a stale-state sweep) or
    // the guest dies on its own. Tied children die with this process either way;
    // the explicit kills below just make teardown prompt instead of lazy.
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing the SIGTERM handler")?;
    loop {
        tokio::select! {
            _ = term.recv() => {
                graceful_vmm_stop(ctx, &mut vmm_child);
                stop_helpers(children, switch_pid);
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                if let Some(status) = vmm_child.try_wait()? {
                    stop_helpers(children, switch_pid);
                    bail!("{} exited ({status})", vmm.name());
                }
                // any owned helper dying (the switch, a service VM, a virtiofsd,
                // a forward) leaves a broken job: fail loudly rather than limp.
                for c in &mut children {
                    if let Some(status) = c.try_wait()? {
                        graceful_vmm_stop(ctx, &mut vmm_child);
                        stop_helpers(children, switch_pid);
                        bail!("a supervised helper exited ({status}) — job torn down");
                    }
                }
            }
        }
    }
}

/// Stop a job's helpers after its primary VM. Kill helpers with no remaining work, then
/// let the switch drain uploads from the now-stopped sibling VMs
/// ([`crate::run::stop_switch`]).
fn stop_helpers(children: Vec<std::process::Child>, switch_pid: Option<u32>) {
    let mut switch = None;
    for mut c in children {
        if Some(c.id()) == switch_pid {
            switch = Some(c);
            continue;
        }
        let _ = c.kill();
        let _ = c.wait();
    }
    if let Some(switch) = switch {
        crate::run::stop_switch(switch);
    }
}

/// SSH-agent forwarding is on when `[executor.auth] ssh_agent` is set AND the runner actually has an
/// agent (`$SSH_AUTH_SOCK`). The guest side is driven by the cmdline var; the host side is
/// the forward started below.
fn ssh_agent_forwarding(cfg: &crate::config::Config) -> bool {
    cfg.executor.auth.ssh_agent && std::env::var_os("SSH_AUTH_SOCK").is_some()
}

/// Host side of the SSH-agent forward ([executor.auth] ssh_agent): the guest dials vsock
/// port SSH_AGENT_VSOCK_PORT, surfaced by the VMM as `<vsock.sock>_<port>`; a
/// `vk forward` binds it and splices to the runner's `$SSH_AUTH_SOCK`. Only agent
/// protocol bytes cross — the keys never enter the guest. `None` when forwarding
/// is off. A passive listener: started before the guest, no readiness to wait for.
fn ssh_agent_forward_command(ctx: &JobCtx) -> Result<Option<Command>> {
    if !ssh_agent_forwarding(&ctx.cfg) {
        return Ok(None);
    }
    let host_sock = std::env::var_os("SSH_AUTH_SOCK").expect("checked by ssh_agent_forwarding");
    let mut listen = ctx.vsock_sock().into_os_string();
    listen.push(format!("_{}", crate::run::SSH_AGENT_VSOCK_PORT));

    let mut fwd = Command::new(crate::spawn::self_exe());
    fwd.arg("forward")
        .arg("--listen")
        .arg(&listen)
        .arg("--to")
        .arg(&host_sock);
    Ok(Some(fwd))
}

/// Probe the booted guest for bash and record the result for the run stage (a
/// separate process): the configured run_command (bash) serves most images, but a
/// bash-less OCI guest (alpine, distroless) needs the POSIX-sh fallback. Probing
/// the actual guest replaces the old medium-based guess (cpio => sh), which broke
/// bash-less images once generic bundles became ext4 disks. Best-effort: an
/// unreadable marker falls back to the configured command.
async fn probe_guest_shell(ctx: &JobCtx, addr: &vk_core::addr::SocketAddr) {
    let has_bash = matches!(
        crate::executor::exec_script(
            addr,
            &["sh".to_string()],
            b"command -v bash >/dev/null 2>&1".to_vec(),
            None,
            &crate::executor::OutputSink::Inherit,
            None,
        )
        .await,
        Ok(res) if res.code == Some(0)
    );
    let _ = std::fs::write(
        ctx.job_dir.join("guest.shell"),
        if has_bash { "configured" } else { "sh" },
    );
}

/// Where a CI service's image comes from — the three-way choice [`plan_services`] makes.
#[derive(Debug, PartialEq, Eq)]
enum ServiceMedia<'a> {
    Git(&'a str),
    Build,
    Image,
}

/// [`ServiceMedia`] for one unit's source. Split out so the choice itself is testable:
/// provisioning a service needs a job context, a checkout and a real build, but which of the
/// three a unit takes is a function of its source alone.
fn service_media(source: &crate::compose::Source) -> ServiceMedia<'_> {
    match source {
        crate::compose::Source::Image(image) => match image.strip_prefix("dockerfile:") {
            Some(spec) => ServiceMedia::Git(spec),
            None => ServiceMedia::Image,
        },
        crate::compose::Source::Build { .. } => ServiceMedia::Build,
    }
}

/// Map the job's services onto provisioned units, assigning static addresses from the top of
/// the job subnet and CIDs from the service range, and merging each unit's boot config. The
/// services come from a `compose:<file>#<primary>` fleet (every enabled unit but the primary)
/// or, otherwise, from the GitLab `services:` list (`CI_JOB_SERVICES`). A `dockerfile:` service
/// (or a compose `build:` unit) is git-defined — built from the host checkout into the shared
/// build tier; any other name resolves through the shared digest-keyed cache the job's own image
/// uses (a job image and a service naming the same ref share one cache entry).
fn plan_services(
    ctx: &JobCtx,
    gateway: Ipv4Addr,
    prefix: u8,
    guards: &mut Vec<crate::cachelock::Guard>,
) -> Result<Vec<crate::units::Provisioned>> {
    let image_ref = ctx.image_ref.as_deref().unwrap_or("local/default");
    let units = match image_ref.strip_prefix("compose:") {
        Some(spec) => compose_service_units(&load_compose_fleet(ctx, spec)?)?,
        None => crate::services::to_units(crate::services::from_env()?),
    };
    let mut out = Vec::new();
    // Addresses for the NICs after eth0, from the static region past the service slots — one
    // allocator for the job's whole LAN, so no two services are handed the same address. The
    // job VM itself stays on one NIC: the executor has no axis to ask for more.
    let mut extra = crate::units::ExtraNics::after_slots(units.len() as u32);
    let reclaim = vm_reclaim(&ctx.cfg)?;
    let dax = vm_dax(&ctx.cfg)?;
    for (slot, mut unit) in units.into_iter().enumerate() {
        // A compose service's declared sizing obeys the same host ceilings as the job's own.
        clamp_service_size(&ctx.cfg, &mut unit)?;
        // A service without an x-virtkit.reclaim of its own trims like the job guest does.
        unit.reclaim = unit.reclaim.or(Some(reclaim));
        // Likewise for its shares' DAX window.
        unit.dax = unit.dax.or(dax);
        let extra_ips = extra.take(gateway, prefix, unit.nics.saturating_sub(1))?;
        // The three media paths resolve the image differently but site the unit identically.
        let siting = |slot: usize, extra_ips: Vec<Ipv4Addr>| crate::units::Siting {
            gateway,
            prefix,
            slot: slot as u32,
            extra_ips,
        };
        let prov = match service_media(&unit.source) {
            ServiceMedia::Git(spec) => {
                let (ext4, config, guard) =
                    build_git_image(ctx, spec).with_context(|| format!("service {}", unit.name))?;
                guards.push(guard);
                let merged = crate::compose::merged_config(&config, &unit);
                crate::units::provisioned(&unit, ext4, merged, siting(slot, extra_ips))?
            }
            // Ask the build where it put the image, as the primary does (`resolve_media` ->
            // `compose_unit_media`), rather than predicting the address: normally a fingerprint
            // hit on what prepare's warm pass built moments ago, and on a miss a rebuild inside
            // prepare's readiness budget. Predicting would assume this process reaches the
            // stage key prepare's build used, and that key is not a function of the sources
            // alone (`build::tests::a_base_digest_that_does_not_resolve_changes_the_stage_key`).
            // The build also reports the image's own config, already merged with the unit's
            // compose overrides, which an address cannot carry — hence no `merged_config` here.
            ServiceMedia::Build => {
                let (ext4, config, guard) = build_compose_unit(ctx, &unit)
                    .with_context(|| format!("service {}", unit.name))?;
                guards.push(guard);
                crate::units::provisioned(&unit, ext4, config, siting(slot, extra_ips))?
            }
            ServiceMedia::Image => {
                let prov = crate::units::provision(
                    &ctx.cfg,
                    ctx.cfg.state_dir(),
                    &[],
                    &unit,
                    siting(slot, extra_ips),
                )?;
                if let Some(g) =
                    crate::image::acquire_use_lock_for(ctx.cfg.state_dir(), &prov.ext4)?
                {
                    guards.push(g);
                }
                prov
            }
        };
        out.push(prov);
    }
    Ok(out)
}

/// The per-job userspace switch (net.mode = "switch"): a tied supervisor child
/// on the guest's vsock-bridge socket (`<vsock.sock>_<net_port>`) plus each
/// service's, with the `[egress]` allowlist and the service aliases in the
/// gateway resolver. Returns once every socket is bound.
fn spawn_switch(
    ctx: &JobCtx,
    gateway: Ipv4Addr,
    prefix: u8,
    guest_ip: Ipv4Addr,
    services: &[crate::units::Provisioned],
) -> Result<std::process::Child> {
    let cfg = &ctx.cfg;
    // Bind every socket to its assigned address and VM id. The job uses 0, services use their
    // position, and all NICs of a service share its id so its addresses work on any port.
    const JOB_VM: u32 = 0;
    let mut listen = vec![(ctx.net_vsock_sock(cfg.net.net_port), guest_ip, JOB_VM)];
    let mut hosts = Vec::new();
    // Reserve the job VM's eth0 by its attach-assigned MAC so image-init DHCP receives the
    // job-assigned address, not a pool lease. Services follow the same rule below.
    let mut reservations = vec![(crate::units::mac_for_ip(guest_ip), guest_ip.to_string())];
    for (i, svc) in services.iter().enumerate() {
        let vm = JOB_VM + 1 + i as u32;
        let svc_dir = ctx.job_dir.join(format!("svc-{}", svc.name));
        listen.push((
            svc_dir.join(format!("vsock.sock_{}", cfg.net.net_port)),
            svc.addr,
            vm,
        ));
        let ip = svc.ip.split('/').next().unwrap_or_default();
        hosts.push((svc.hostname.clone(), ip.to_string()));
        if let Ok(ip4) = ip.parse::<Ipv4Addr>() {
            reservations.push((crate::units::mac_for_ip(ip4), ip.to_string()));
        }
        // Each NIC after eth0 is its own port on the switch: its own socket (net_port + the
        // interface index, matching the bridge ports `boot_unit` gives the guest), bound to
        // its own address, with the same per-MAC reservation. The resolver still names only
        // eth0 — a service name is one address.
        for (i, extra) in svc.extra_ips.iter().enumerate() {
            let port = cfg.net.net_port + i as u32 + 1;
            listen.push((svc_dir.join(format!("vsock.sock_{port}")), *extra, vm));
            reservations.push((crate::units::mac_for_ip(*extra), extra.to_string()));
        }
    }
    // Opt-in credential proxy: expose the runner's `[registry]` to the job at
    // `registry.vk`, injecting its credentials, so the job stays credential-free. The
    // switch redirects the sentinel (an unroutable class-E address) to the host-local
    // proxy; see regproxy.rs / switch.rs.
    let registry_proxy = match &cfg.registry {
        Some(rg) if rg.proxy_guests => {
            const SENTINEL: Ipv4Addr = Ipv4Addr::new(240, 0, 0, 1);
            let addr =
                crate::regproxy::spawn_blocking(crate::regproxy::ProxyCfg::from_registry(rg)?)
                    .context("starting the job registry proxy")?;
            hosts.push(("registry.vk".to_string(), SENTINEL.to_string()));
            Some((SENTINEL, addr))
        }
        _ => None,
    };
    let (allow_ip, allow_name, restrict) = effective_run_egress(cfg, ctx)?;
    let per_source = service_per_source(cfg, services)?;
    crate::switch::spawn(&crate::switch::Spawn {
        listen,
        gateway,
        prefix,
        hosts,
        reservations,
        allow_ip,
        allow_name,
        restrict,
        dry_run: ctx.egress_run_dry_run(),
        per_source,
        registry_proxy,
        log: ctx.switch_log(),
        denied_log: Some(ctx.egress_denied_log()),
        // Not gated on audit mode: the names a job resolves are what its allowlist is
        // written from, and a host that only records them once someone turns auditing on has
        // them for the run after the question was asked. The audit *summary* stays opt-in.
        audit_log: Some(ctx.egress_audit_log()),
        bytes_log: Some(ctx.net_bytes_log()),
        // A CI job's own switch: the runner has nothing else to stay responsive for.
        prio: crate::prio::Prio::Normal,
    })
    .context("spawning the per-job switch")
}

/// This job's effective run-phase switch egress: the host `[egress]` cap narrowed by the
/// job's `MICROVM_EGRESS_ALLOW_IP` / `_ALLOW_NAME` requests, returned as `(allow_ip,
/// allow_name, restrict)` for `switch::Spawn`. `restrict` is true when either dimension is
/// configured, so an empty allowlist denies (see the switch's `--egress-restrict`).
pub(crate) fn effective_run_egress(
    cfg: &crate::config::Config,
    ctx: &JobCtx,
) -> Result<(Vec<String>, Vec<String>, bool)> {
    let (ips, names) = effective_policy(
        cfg.egress.allow_ip.as_deref(),
        cfg.egress.allow_name.as_deref(),
        ctx.egress_allow_ip_req.as_deref(),
        ctx.egress_allow_name_req.as_deref(),
        "MICROVM_EGRESS_ALLOW_IP",
        "MICROVM_EGRESS_ALLOW_NAME",
    )?;
    let restrict = ips.is_some() || names.is_some();
    Ok((ips.unwrap_or_default(), names.unwrap_or_default(), restrict))
}

/// Validate a service's own egress request against the host `[egress]` cap, in prepare, so a
/// bad `MICROVM_EGRESS_ALLOW_*` in a service's `variables:` fails with a crisp job-visible
/// error rather than an opaque switch failure in the detached supervisor. No-op when the
/// service declared none.
fn validate_service_egress(cfg: &crate::config::Config, unit: &crate::compose::Unit) -> Result<()> {
    let ip_req = crate::units::service_egress_req(&unit.environment, "MICROVM_EGRESS_ALLOW_IP");
    let name_req = crate::units::service_egress_req(&unit.environment, "MICROVM_EGRESS_ALLOW_NAME");
    if ip_req.is_none() && name_req.is_none() {
        return Ok(());
    }
    effective_policy(
        cfg.egress.allow_ip.as_deref(),
        cfg.egress.allow_name.as_deref(),
        ip_req.as_deref(),
        name_req.as_deref(),
        &format!("service {:?} MICROVM_EGRESS_ALLOW_IP", unit.name),
        &format!("service {:?} MICROVM_EGRESS_ALLOW_NAME", unit.name),
    )?;
    Ok(())
}

/// Per-source egress overrides for the switch: one entry per service that set its own
/// `MICROVM_EGRESS_ALLOW_IP` / `_ALLOW_NAME` in its `variables:`, narrowed against the host
/// `[egress]` cap (a service can restrict itself but not exceed the cap). A declaring service
/// is always a restricted allowlist (empty = deny); a service that declared nothing gets no
/// entry and shares the run policy. Returns `(source-ip, allow_ip, allow_name)` per override.
#[allow(clippy::type_complexity)]
fn service_per_source(
    cfg: &crate::config::Config,
    services: &[crate::units::Provisioned],
) -> Result<Vec<(Ipv4Addr, Vec<String>, Vec<String>)>> {
    let mut out = Vec::new();
    for svc in services {
        if svc.egress_allow_ip_req.is_none() && svc.egress_allow_name_req.is_none() {
            continue;
        }
        let (ips, names) = effective_policy(
            cfg.egress.allow_ip.as_deref(),
            cfg.egress.allow_name.as_deref(),
            svc.egress_allow_ip_req.as_deref(),
            svc.egress_allow_name_req.as_deref(),
            &format!("service {:?} MICROVM_EGRESS_ALLOW_IP", svc.name),
            &format!("service {:?} MICROVM_EGRESS_ALLOW_NAME", svc.name),
        )?;
        out.push((svc.addr, ips.unwrap_or_default(), names.unwrap_or_default()));
    }
    Ok(out)
}

/// This job's effective build-phase egress ([`crate::build::BuildNet`]) plus its build-audit
/// flag: the `[egress.build]` cap narrowed by `MICROVM_BUILD_EGRESS_ALLOW_IP` / `_ALLOW_NAME`.
/// Both dimensions absent ⇒ `BuildNet::All` (unrestricted, as `docker build`); otherwise a
/// restricted `BuildNet::Allow` whose empty lists deny.
fn effective_build_egress(
    cfg: &crate::config::Config,
    ctx: &JobCtx,
) -> Result<(crate::build::BuildNet, bool)> {
    let (ips, names) = effective_policy(
        cfg.egress.build.allow_ip.as_deref(),
        cfg.egress.build.allow_name.as_deref(),
        ctx.egress_build_allow_ip_req.as_deref(),
        ctx.egress_build_allow_name_req.as_deref(),
        "MICROVM_BUILD_EGRESS_ALLOW_IP",
        "MICROVM_BUILD_EGRESS_ALLOW_NAME",
    )?;
    let net = match (ips, names) {
        (None, None) => crate::build::BuildNet::All,
        (ips, names) => crate::build::BuildNet::Allow {
            ips: ips.unwrap_or_default(),
            names: names.unwrap_or_default(),
        },
    };
    Ok((net, ctx.egress_build_audit()))
}

/// Narrow a phase's `(allow_ip, allow_name)` config cap by the job's requests. Each
/// dimension: an absent request keeps the config cap unchanged; a present request must fall
/// within the cap (`narrow_ips`/`narrow_names`) and becomes the effective list. `None` in
/// the result = that dimension is unconstrained; `Some(list)` = an allowlist (empty = deny).
///
/// Once *either* dimension is configured the phase is a restricted allowlist, so an absent
/// sibling dimension denies its dimension rather than staying unconstrained — this matches
/// enforcement (`restrict = ips.is_some() || names.is_some()`). Validating against that
/// collapsed cap is a security boundary: without it a job could pass e.g. a
/// `MICROVM_EGRESS_ALLOW_IP` against a name-only cap and widen its egress past the cap.
#[allow(clippy::type_complexity)]
fn effective_policy(
    cap_ip: Option<&[String]>,
    cap_name: Option<&[String]>,
    ip_req: Option<&str>,
    name_req: Option<&str>,
    ip_var: &str,
    name_var: &str,
) -> Result<(Option<Vec<String>>, Option<Vec<String>>)> {
    // A restricted phase denies an omitted dimension, so validate against that collapsed
    // (deny-all) cap rather than treating the absent list as unconstrained.
    let restricted = cap_ip.is_some() || cap_name.is_some();
    let cap_ip = if restricted {
        Some(cap_ip.unwrap_or(&[]))
    } else {
        cap_ip
    };
    let cap_name = if restricted {
        Some(cap_name.unwrap_or(&[]))
    } else {
        cap_name
    };

    let ips = match ip_req {
        Some(req) => Some(narrow_ips(cap_ip, req, ip_var)?),
        None => cap_ip.map(<[String]>::to_vec),
    };
    let names = match name_req {
        Some(req) => Some(narrow_names(cap_name, req, name_var)?),
        None => cap_name.map(<[String]>::to_vec),
    };
    Ok((ips, names))
}

/// Split a space/comma/newline-separated job-variable list into non-empty items. A `#`
/// begins an end-of-line comment (the rest of that line is dropped), so a YAML block-scalar
/// list can annotate each entry inline — e.g. `crates.io   # Rust registry`.
fn split_req(req: &str) -> Vec<String> {
    req.lines()
        .map(|line| line.split_once('#').map_or(line, |(head, _)| head))
        .flat_map(|line| line.split([',', ' ', '\t']))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Validate a job's requested DNS-name list against the config `cap` (`None` = unconstrained
/// ⇒ the request defines the list freely; `Some(list)` ⇒ each request must be within a cap
/// suffix, `Some([])` ⇒ none). A name outside the cap fails the job — it can narrow, not widen.
fn narrow_names(cap: Option<&[String]>, req: &str, var: &str) -> Result<Vec<String>> {
    let requested = split_req(req);
    let policy = match cap {
        None => crate::switch::Egress::AllowAll,
        Some(c) => crate::switch::Egress::restricted(&[], c)?,
    };
    for name in &requested {
        if !policy.allows_host(name) {
            bail!("{var} {name:?} is not within the configured allow_name cap");
        }
    }
    Ok(requested)
}

/// Validate a job's requested IPv4 CIDR list against the config `cap` (`None` = unconstrained;
/// `Some(list)` ⇒ each request must be a subset of some cap rule; `Some([])` ⇒ none). A CIDR
/// outside the cap fails the job.
fn narrow_ips(cap: Option<&[String]>, req: &str, var: &str) -> Result<Vec<String>> {
    let requested = split_req(req);
    let policy = match cap {
        None => crate::switch::Egress::AllowAll,
        Some(c) => crate::switch::Egress::restricted(c, &[])?,
    };
    for ip in &requested {
        if !policy.contains_cidr(ip)? {
            bail!("{var} {ip:?} is not within the configured allow_ip cap");
        }
    }
    Ok(requested)
}

/// `[executor.vm] dax` as a policy, `None` where the host set none; a misspelt value fails naming
/// the key.
fn vm_dax(cfg: &crate::config::Config) -> Result<Option<crate::vmm::Dax>> {
    cfg.executor
        .vm
        .dax
        .as_deref()
        .map(|s| s.parse().map_err(|e| anyhow!("[executor.vm] dax: {e}")))
        .transpose()
}

/// `[executor.vm] reclaim` as a policy; a misspelt value fails prepare naming the key.
fn vm_reclaim(cfg: &crate::config::Config) -> Result<vk_core::reclaim::Policy> {
    cfg.executor
        .vm
        .reclaim
        .parse()
        .map_err(|e| anyhow!("[executor.vm] reclaim: {e}"))
}

/// Effective vCPU count and memory size: the job's MICROVM_CPUS/MICROVM_MEM
/// requests, silently clamped to the host ceilings (vm.max_cpus/max_mem,
/// defaulting to the base values — config opt-in for any elevation).
fn vm_size(ctx: &JobCtx) -> Result<(u32, String)> {
    let vm = &ctx.cfg.executor.vm;
    let cpus = match &ctx.cpus_req {
        None => vm.cpus,
        Some(s) => {
            let n: u32 = s
                .parse()
                .ok()
                .filter(|n| *n > 0)
                .with_context(|| format!("invalid MICROVM_CPUS {s:?}"))?;
            n.min(vm.max_cpus.unwrap_or(vm.cpus))
        }
    };
    let mem = match &ctx.mem_req {
        None => vm.mem.clone(),
        Some(s) => {
            let req = parse_gib(s).with_context(|| format!("invalid MICROVM_MEM {s:?}"))?;
            let max = match &vm.max_mem {
                Some(m) => parse_gib(m).context("invalid vm.max_mem")?,
                None => parse_gib(&vm.mem).context("invalid vm.mem")?,
            };
            // `[executor.schedule] mem_budget` is a host ceiling like the others: a request above the
            // whole budget could never be admitted, and failing prepare over it would be a
            // *system* failure — the retryable class, which no retry could ever satisfy.
            let max = match budget_mib(&ctx.cfg) {
                Some(b) => max.min(b? / 1024),
                None => max,
            };
            format!("{}G", req.min(max))
        }
    };
    Ok((cpus, mem))
}

/// A compose file may ask a service to nest only where the runner granted nesting
/// (`[executor.vm] nested`). Nesting widens the guest's attack surface on host KVM (see
/// `VmSpec::nested`), so the grant is the host admin's and not a job-authored compose
/// file's — the same reason the executor never hands a job the PMU. Once granted, the
/// marker is honoured, so a fleet can put its nesting builder wherever it belongs instead
/// of only in the primary. Ungranted it is refused rather than quietly cleared: a fleet
/// that asked for a nesting builder must not look like it got one, and on the
/// cloud-hypervisor backend clearing the flag would not mask VMX/SVM anyway. Checked where
/// the fleet loads, so it covers the primary as well as the siblings and the error reaches
/// the job from `prepare` rather than only the supervisor's log.
fn refuse_job_nesting(granted: bool, unit: &crate::compose::Unit) -> Result<()> {
    if unit.nested && !granted {
        bail!(
            "compose service {:?}: x-virtkit.nested needs a runner that allows nesting — it \
             reaches host KVM, so `[executor.vm] nested` is the host admin's grant to make, not a job's",
            unit.name
        );
    }
    Ok(())
}

/// `[executor.vm] nested` on a host whose KVM will not nest boots a job guest that advertises VMX/SVM
/// and cannot use it, so the jobs counting on it fail deep inside themselves instead of at
/// the misconfiguration. Refused in `prepare`, whose error reaches the job trace, rather than
/// in the detached supervisor's log.
pub(crate) fn refuse_unsupported_nesting(requested: bool, host_nests: bool) -> Result<()> {
    if requested && !host_nests {
        bail!(
            "[executor.vm] nested is set but this host does not allow nesting — load kvm_intel or \
             kvm_amd with nested=1, or unset it"
        );
    }
    Ok(())
}

/// Clamp a service unit's declared sizing (its compose `x-virtkit.cpus`/`.mem`) to the
/// same host ceilings a job's MICROVM_CPUS/MICROVM_MEM requests are clamped to
/// (vm.max_cpus/max_mem, defaulting to the base values) — a committed compose file must
/// not size a service past what the runner's config lets a job declare. Silent, like
/// `vm_size`; an undeclared axis stays `None` (the service default), not the job base.
fn clamp_service_size(cfg: &crate::config::Config, unit: &mut crate::compose::Unit) -> Result<()> {
    let vm = &cfg.executor.vm;
    if let Some(n) = unit.cpus {
        unit.cpus = Some(n.min(vm.max_cpus.unwrap_or(vm.cpus)));
    }
    if let Some(mem) = &unit.mem {
        // parse validated at compose load; the context covers a unit built elsewhere.
        let req_mib = crate::run::parse_mem_mib(mem)
            .with_context(|| format!("service {:?}: invalid mem {mem:?}", unit.name))?;
        let max_mib = match &vm.max_mem {
            Some(m) => parse_gib(m).context("invalid vm.max_mem")?,
            None => parse_gib(&vm.mem).context("invalid vm.mem")?,
        }
        .checked_mul(1024)
        .context("guest memory ceiling is absurdly large")?;
        // `[executor.schedule] mem_budget` is a host ceiling like the others (see `vm_size`): a service
        // sized above the whole budget could never boot healthily on this runner.
        let max_mib = match budget_mib(cfg) {
            Some(b) => max_mib.min(b?),
            None => max_mib,
        };
        if req_mib > max_mib {
            unit.mem = Some(format!("{max_mib}M"));
        }
    }
    Ok(())
}

/// Where this job's VM goes on a multi-socket host, announced in the job trace.
///
/// Use the admission ledger on hosts with a memory budget: other runners' grants count
/// even before guests fault in their RAM. Without a budget, in `mode = "interleave"`, or on
/// a single-node host, defer to the shared boot path ([`crate::numa::auto_place`]).
fn job_placement(
    ctx: &JobCtx,
    reservation: Option<&crate::admit::Reservation>,
    cpus: u32,
) -> Result<crate::numa::Numa> {
    use crate::config::NumaMode;
    let cfg = &ctx.cfg;
    match cfg.numa.mode {
        NumaMode::Off => return Ok(crate::numa::Numa::Off),
        // Interleaving chooses no node, so it needs neither the ledger nor a job's size.
        NumaMode::Interleave => return Ok(crate::numa::Numa::Auto),
        NumaMode::Auto => {}
    }
    let (Some(reservation), Some(budget), Some(topology)) = (
        reservation,
        budget_mib(cfg),
        crate::numa::Topology::detect(),
    ) else {
        return Ok(crate::numa::Numa::Auto);
    };
    let placement = reservation.place(
        &ctx.admit_dir(),
        &topology,
        budget?,
        crate::schedule::host_total_mib(),
        cpus,
    )?;
    println!("virtkit: NUMA: {}", crate::numa::announce(&placement));
    Ok(crate::numa::Numa::Placed(placement))
}

/// The guest RAM this job declares, in MiB: `MICROVM_MEM` clamped by the host ceilings, the
/// figure a reservation is capped at and the job's history is read against.
pub(crate) fn declared_mem_mib(ctx: &JobCtx) -> Result<u64> {
    parse_gib(&vm_size(ctx)?.1)?
        .checked_mul(1024)
        .context("guest memory size is absurdly large")
}

/// Reserve this job's guest RAM against the host's `[executor.schedule] mem_budget`, and room for
/// its job dir on the filesystem holding it (`disk_admission`), blocking until there is room for
/// both (see admit). `None` when both are off — the host then admits every job the runner hands
/// it. A job that never gets room fails prepare, which exits `SYSTEM_FAILURE_EXIT_CODE`: a
/// system failure, not the job's fault.
fn admit(ctx: &JobCtx, mem: &str) -> Result<Option<crate::admit::Reservation>> {
    let declared_mib = parse_gib(mem)
        .context("invalid guest memory size")?
        .checked_mul(1024)
        .context("guest memory size is absurdly large")?;
    let ask = crate::admit::Ask {
        mem: admit_memory(ctx, declared_mib)?,
        disk: admit_disk(ctx, declared_mib)?,
    };
    if ask.mem.is_none() && ask.disk.is_none() {
        return Ok(None);
    }
    let timeout = Duration::from_secs(ctx.cfg.executor.schedule.wait_timeout_secs.unwrap_or(600));
    let reservation = crate::admit::acquire(&ctx.admit_dir(), &ctx.job_id, &ask, timeout)?;
    Ok(Some(reservation))
}

/// This job's share of `[executor.schedule] mem_budget`, or `None` when no budget is configured.
fn admit_memory(ctx: &JobCtx, declared_mib: u64) -> Result<Option<crate::admit::MemAsk>> {
    let Some(budget) = budget_mib(&ctx.cfg) else {
        return Ok(None);
    };
    let budget_mib = budget?;
    // `[executor.schedule] from_history`: reserve what this job has been using rather than what it
    // declares. Announced, because it is the difference between a job waiting and not.
    let want_mib = match ctx.cfg.executor.schedule.from_history {
        true => crate::admit::expect_mib(&ctx.history_dir(), &ctx.usage_key(), declared_mib)
            .inspect(|mib| {
                // Only worth saying when it changes the reservation: a job whose peak fills
                // its ceiling would otherwise be told it reserves what it declares.
                if *mib < declared_mib {
                    println!(
                        "virtkit: reserving {mib} MiB from what this job has been using \
                         (it declares {declared_mib} MiB)"
                    );
                }
            })
            .unwrap_or(declared_mib),
        false => declared_mib,
    };
    Ok(Some(crate::admit::MemAsk {
        want_mib,
        budget_mib,
    }))
}

/// What this job's dir is expected to grow to, for `[executor.schedule] disk_admission`: from
/// its history where it has one, else `disk_default`. `None` when disk admission is off.
fn admit_disk(ctx: &JobCtx, declared_mib: u64) -> Result<Option<crate::admit::DiskAsk<'_>>> {
    let schedule = &ctx.cfg.executor.schedule;
    if !schedule.disk_admission.unwrap_or(true) {
        return Ok(None);
    }
    let jobs = ctx.jobs_dir();
    let total = crate::usage::fs_space(jobs)
        .with_context(|| format!("reading the free space of {}", jobs.display()))?
        .total;
    // Resolved whether or not this job needs it, so a mistyped setting fails the first job
    // rather than the first one without a history, days later.
    let default = disk_default(schedule.disk_default.as_deref(), total)?;
    let want = crate::admit::expect_disk(&ctx.history_dir(), &ctx.usage_key(), declared_mib, total)
        .unwrap_or(default);
    Ok(Some(crate::admit::DiskAsk { want, jobs }))
}

/// What a job with no history is expected to write into its job dir, on a filesystem of
/// `total` bytes: `[executor.schedule] disk_default` as set — admission refuses one larger than
/// the filesystem, which no job could ever be admitted against — or, unset, [`DISK_DEFAULT`]
/// capped at the filesystem, as an expectation from history is: a host that never chose the
/// figure must not have every new job fail on a filesystem smaller than it.
fn disk_default(raw: Option<&str>, total: u64) -> Result<u64> {
    let Some(raw) = raw else {
        return Ok(DISK_DEFAULT.min(total));
    };
    parse_gib(raw)
        .ok()
        .and_then(|gib| gib.checked_mul(1 << 30))
        .with_context(|| {
            format!("[executor.schedule] disk_default {raw:?} is not a size (want \"<n>G\")")
        })
}

/// `[executor.schedule] disk_default` unset: what a job with no history is expected to write,
/// 8 GiB.
const DISK_DEFAULT: u64 = 8 << 30;

/// The host's `[executor.schedule] mem_budget` in MiB, resolving a percentage against this host, for a
/// report that says there is no budget rather than inventing one. `None` when no budget is set,
/// `Some(Err(..))` when one is set that this host cannot resolve — it does not parse, or it is a
/// percentage and `/proc/meminfo` is unreadable — which the report has to tell apart, since a
/// budget it cannot resolve is one every job's prepare is already failing on, not the absence of
/// a budget. The error names the setting, so callers add no context of their own.
pub(crate) fn budget_mib(cfg: &crate::config::Config) -> Option<Result<u64>> {
    let raw = cfg.executor.schedule.mem_budget.as_deref()?;
    // Only a percentage needs the host measured, and a `<n>G` budget must keep working on a host
    // whose `/proc/meminfo` cannot be read.
    let host_total_mib = raw
        .ends_with('%')
        .then(crate::schedule::host_total_mib)
        .flatten();
    Some(
        // "cannot resolve", not "invalid": a percentage is a valid setting on a host whose
        // memory this process simply cannot read.
        parse_budget_mib(raw, host_total_mib)
            .with_context(|| format!("cannot resolve [executor.schedule] mem_budget {raw:?}")),
    )
}

/// `"<n>G"` as an exact size, or `"<n>%"` as a share of `host_total_mib`.
fn parse_budget_mib(raw: &str, host_total_mib: Option<u64>) -> Result<u64> {
    let Some(percent) = raw.strip_suffix('%') else {
        if !raw.ends_with('G') {
            bail!("expected <n>G or <n>%");
        }
        return parse_gib(raw)
            .context("expected <n>G or <n>%")?
            .checked_mul(1024)
            .context("size is absurdly large");
    };
    let percent: u64 = percent.parse().context("expected <n>%")?;
    if !(1..=100).contains(&percent) {
        bail!("a percentage budget must be between 1% and 100%");
    }
    let total_mib = host_total_mib
        .context("cannot read MemTotal from /proc/meminfo to resolve a percentage")?;
    // Guest sizes are whole GiB, so the share is one too. Round it *up*, so 50% of a nominal
    // 32 GiB runner — whose MemTotal is always somewhat under 32 GiB — still admits the two 8G
    // jobs the operator asked for rather than one; and cap it at the whole GiB the host really
    // has, so 100% cannot round past the machine.
    let gib = (total_mib.checked_mul(percent))
        .context("size is absurdly large")?
        .div_ceil(100 * 1024)
        .min(total_mib / 1024);
    if gib == 0 {
        bail!("this host has under 1 GiB to give a percentage budget");
    }
    Ok(gib * 1024)
}

/// "<n>G" (GiB) — the only size format the sizing variables accept
pub(crate) fn parse_gib(s: &str) -> Result<u64> {
    let n = s
        .strip_suffix('G')
        .ok_or_else(|| anyhow!("expected <n>G"))?
        .parse::<u64>()?;
    if n == 0 {
        bail!("expected a non-zero size");
    }
    Ok(n)
}

/// Split "a.b.c.d/prefix" into (ip, prefix).
fn split_cidr(cidr: &str) -> Result<(String, u32)> {
    let (ip, p) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow!("net.ip {cidr:?} is not CIDR (a.b.c.d/prefix)"))?;
    let prefix: u32 = p
        .parse()
        .ok()
        .filter(|p| *p <= 32)
        .with_context(|| format!("invalid prefix in {cidr:?}"))?;
    Ok((ip.to_string(), prefix))
}

/// IPv4 prefix length → dotted netmask, for the kernel `ip=` autoconf param.
fn prefix_to_netmask(prefix: u32) -> String {
    let bits: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.min(32))
    };
    format!(
        "{}.{}.{}.{}",
        (bits >> 24) & 0xff,
        (bits >> 16) & 0xff,
        (bits >> 8) & 0xff,
        bits & 0xff
    )
}

/// The pid of the job's supervisor, or `None` if the pidfile is absent or unparseable,
/// or if its pid no longer belongs to this job (`pid_running`'s pid-reuse guard).
pub fn live_supervisor_pid(ctx: &JobCtx) -> Option<i32> {
    let pid = read_pidfile(&ctx.supervisor_pidfile())?;
    pid_running(pid, &ctx.job_dir.to_string_lossy()).then_some(pid)
}

/// Signal the job's supervisor and wait for it to go — everything it owns (the
/// switch, virtiofsds, forwards, the VMM after its graceful guest shutdown)
/// follows, by its TERM handler or by PDEATHSIG. Idempotent: tolerates a missing
/// or stale pidfile (the job-dir cmdline tag guards against pid reuse).
pub fn stop_supervisor(ctx: &JobCtx) {
    let Some(pid) = live_supervisor_pid(ctx) else {
        return;
    };
    let tag = ctx.job_dir.to_string_lossy().into_owned();
    unsafe { libc::kill(pid, libc::SIGTERM) };
    // the supervisor's own teardown runs the graceful guest shutdown; give it
    // that budget, the switch drain, and margin for the VMM fallback shutdown steps.
    let grace = Duration::from_secs(ctx.cfg.executor.vm.shutdown_timeout_secs + 15)
        + crate::run::SWITCH_STOP;
    if !wait_gone(pid, &tag, grace) {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        wait_gone(pid, &tag, Duration::from_secs(3));
    }
}

/// Gracefully stop the supervisor's own VMM child: ACPI power-button over the API
/// socket, then vm.shutdown, then SIGTERM/SIGKILL — each step only if the previous
/// one did not end the process. libkrun has no API socket: TERM then KILL.
fn graceful_vmm_stop(ctx: &JobCtx, child: &mut std::process::Child) {
    let timeout = Duration::from_secs(ctx.cfg.executor.vm.shutdown_timeout_secs);
    if crate::vmm::libkrun_selected() {
        unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
        if !wait_child_gone(child, timeout) {
            let _ = child.kill();
            let _ = child.wait();
        }
        return;
    }
    let api = ctx.api_sock();
    let _ = ch_api_put(&api, "vm.power-button");
    if !wait_child_gone(child, timeout) {
        let _ = ch_api_put(&api, "vm.shutdown");
        if !wait_child_gone(child, Duration::from_secs(5)) {
            unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
            if !wait_child_gone(child, Duration::from_secs(3)) {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

/// Poll the held child (exact — no /proc parsing, no pid-reuse race) until it
/// exits or `timeout` passes.
pub(crate) fn wait_child_gone(child: &mut std::process::Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn cleanup(ctx: &JobCtx) -> Result<()> {
    stop_supervisor(ctx);
    crate::net::release(ctx);
    // After the supervisor is gone, so the freed budget is visible to the next job the
    // moment its entry disappears rather than while its VM is still shutting down.
    crate::admit::release(&ctx.admit_dir(), &ctx.job_id);
    match std::fs::remove_dir_all(&ctx.job_dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", ctx.job_dir.display())),
    }
}

/// Spawn a tied child (PDEATHSIG — it dies with this process, see
/// `spawn::spawn_tied`) with stdout+stderr appended to a log file. The
/// supervisor's spawn primitive: children need no pidfiles, killing the
/// supervisor cascades.
fn spawn_tied_logged(mut cmd: Command, log: &Path) -> Result<std::process::Child> {
    let logfile = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .with_context(|| format!("opening {}", log.display()))?;
    cmd.stdin(Stdio::null())
        .stdout(logfile.try_clone()?)
        .stderr(logfile);
    crate::spawn::spawn_tied(cmd).map_err(Into::into)
}

/// Spawn a long-lived child in its own process group (it must survive this
/// short-lived executor stage and never receive its signals), stdout+stderr
/// appended to a log file. The returned Child is never killed on drop; later
/// stages find the process again through its pidfile. Only the job supervisor is
/// spawned this way — everything else is its tied child.
fn spawn_detached(mut cmd: Command, log: &Path) -> Result<std::process::Child> {
    let logfile = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .with_context(|| format!("opening {}", log.display()))?;
    Ok(cmd
        .stdin(Stdio::null())
        .stdout(logfile.try_clone()?)
        .stderr(logfile)
        .process_group(0)
        .spawn()?)
}

fn wait_for_socket(path: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        if Instant::now() >= deadline {
            bail!("{} did not appear within {timeout:?}", path.display());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

fn read_pidfile(path: &Path) -> Option<i32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// A recorded pid counts as ours only while its cmdline still references the job
/// dir — guards the kill/wait logic against pid reuse after a crash.
fn pid_running(pid: i32, expect_in_cmdline: &str) -> bool {
    let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    String::from_utf8_lossy(&cmdline)
        .replace('\0', " ")
        .contains(expect_in_cmdline)
}

fn wait_gone(pid: i32, expect_in_cmdline: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while pid_running(pid, expect_in_cmdline) {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    true
}

/// Minimal HTTP PUT on the Cloud Hypervisor API socket (same calls as
/// shutdown.sh's `curl --unix-socket`); not worth an HTTP client dependency.
fn ch_api_put(sock: &Path, endpoint: &str) -> Result<()> {
    let mut stream = UnixStream::connect(sock)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    write!(
        stream,
        "PUT /api/v1/{endpoint} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
    )?;
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf)?;
    let resp = String::from_utf8_lossy(&buf[..n]);
    if resp.starts_with("HTTP/1.1 2") {
        Ok(())
    } else {
        Err(anyhow!(
            "{endpoint}: {}",
            resp.lines().next().unwrap_or("no response")
        ))
    }
}

/// Free space under which the job dirs' filesystem counts as full: the overlay's metadata and
/// the agent's initramfs alone take more.
const FULL_BELOW: u64 = 16 * 1024 * 1024;

/// Free inodes under which the job dirs' filesystem counts as full: a job dir alone takes
/// a couple of dozen.
const FULL_INODES_BELOW: u64 = 64;

/// Whether `space` has next to no bytes or inodes left.
fn exhausted(space: &crate::usage::FsSpace) -> bool {
    space.avail < FULL_BELOW || inodes_exhausted(space)
}

fn inodes_exhausted(space: &crate::usage::FsSpace) -> bool {
    space.files > 0 && space.files_avail < FULL_INODES_BELOW
}

/// The figures of the filesystem holding the job dirs, if it has next to nothing left. A
/// quota does not show in them, so an exhausted one goes unnoticed here; a write it refuses
/// is still named by [`name_full_fs`].
fn jobs_fs_full(ctx: &JobCtx) -> Option<crate::usage::FsSpace> {
    // A filesystem statvfs cannot read goes undiagnosed: the diagnosis is an extra, and the
    // caller's own error stands without it.
    crate::usage::fs_space(ctx.jobs_dir())
        .ok()
        .filter(exhausted)
}

/// Why the job dirs' filesystem has no room, if it has none: its figures where they show it
/// full, else what it answers a small write into the job dir — a quota, or a btrfs out of
/// metadata space, does not show in the figures.
fn jobs_fs_no_room(ctx: &JobCtx) -> Option<String> {
    if let Some(space) = jobs_fs_full(ctx) {
        return Some(full_fs(ctx.jobs_dir(), space));
    }
    let probe = ctx.job_dir.join(".space-probe");
    use std::io::Write;
    let wrote = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .and_then(|mut f| f.write_all(&[0u8; 4096]));
    // Best effort: the job dir, probe and all, goes at cleanup.
    let _ = std::fs::remove_file(&probe);
    let kind = wrote.err()?.kind();
    use std::io::ErrorKind::{QuotaExceeded, StorageFull};
    matches!(kind, StorageFull | QuotaExceeded)
        .then(|| no_room(kind, ctx.jobs_dir()))
        .flatten()
}

/// Whether a failure to set up the atop archive fails the job: only one that found the job
/// dirs' filesystem full (`kind` is [`storage_full`]'s). `on_jobs_fs` is whether the failed
/// write was to that filesystem; for one that was not, `jobs_full` asks whether it is full all
/// the same. A full archive elsewhere costs the job only its statistics.
fn atop_failure_is_fatal(
    kind: Option<std::io::ErrorKind>,
    on_jobs_fs: bool,
    jobs_full: impl FnOnce() -> bool,
) -> bool {
    kind.is_some() && (on_jobs_fs || jobs_full())
}

/// The kind of `e` if it is a write refused for want of space or quota.
fn storage_full(e: &anyhow::Error) -> Option<std::io::ErrorKind> {
    use std::io::ErrorKind::{QuotaExceeded, StorageFull};
    e.chain().find_map(|c| {
        c.downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind)
            .filter(|kind| matches!(kind, StorageFull | QuotaExceeded))
    })
}

/// Whether `a` and `b` are on the same filesystem. `b` may not exist yet, so its nearest
/// existing ancestor answers for it.
fn same_fs(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let dev = |p: &Path| {
        p.ancestors()
            .find_map(|p| std::fs::metadata(p).ok())
            .map(|m| m.dev())
    };
    matches!((dev(a), dev(b)), (Some(x), Some(y)) if x == y)
}

/// `e` led by `dir`, the directory whose filesystem it filled, and what that filesystem ran out
/// of: a bare `ENOSPC` names neither, and the job dir holding the file is gone by the time
/// anyone reads the trace. Any other error, or one whose filesystem cannot be read, comes back
/// as it is.
fn name_full_fs(e: anyhow::Error, dir: &Path) -> anyhow::Error {
    match storage_full(&e).and_then(|kind| no_room(kind, dir)) {
        Some(lead) => e.context(lead),
        None => e,
    }
}

/// What the filesystem holding `dir` ran out of, for a write refused with `kind`
/// (`StorageFull` or `QuotaExceeded`).
fn no_room(kind: std::io::ErrorKind, dir: &Path) -> Option<String> {
    match kind {
        // statvfs does not see quotas: its figures would show a filesystem with room.
        std::io::ErrorKind::QuotaExceeded => {
            Some(format!("{} is over its disk quota", dir.display()))
        }
        // Figures statvfs cannot read give no lead: the caller's error stands as it came.
        _ => crate::usage::fs_space(dir)
            .ok()
            .map(|space| full_fs(dir, space)),
    }
}

/// How full the filesystem holding `dir` is, in inodes where those ran out with bytes left.
/// Figures that show room (space freed since, or a btrfs out of metadata space) get "ran out
/// of space" rather than "is full".
fn full_fs(dir: &Path, space: crate::usage::FsSpace) -> String {
    if inodes_exhausted(&space) && space.avail >= FULL_BELOW {
        return format!(
            "{} is out of inodes ({} of {} used)",
            dir.display(),
            space.files_used(),
            space.files
        );
    }
    format!(
        "{} {} ({} of {} used)",
        dir.display(),
        match exhausted(&space) {
            true => "is full",
            false => "ran out of space",
        },
        crate::usage::fmt_bytes(space.used()),
        crate::usage::fmt_bytes(space.total)
    )
}

/// Dump the end of the serial console to stderr — the only useful trace when the
/// guest never brings virtkit-agent up.
fn log_tail(path: &Path, lines: usize) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let all: Vec<&str> = text.lines().collect();
    let tail = &all[all.len().saturating_sub(lines)..];
    if !tail.is_empty() {
        eprintln!("--- console tail ({}) ---", path.display());
        for line in tail {
            eprintln!("{line}");
        }
        eprintln!("--- end console tail ---");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::jobctx::JobCtx;

    /// Unset is not "8G": the cloud-hypervisor backend warns only about a window the host
    /// asked for, so "left alone" has to be distinguishable from the default.
    #[test]
    fn vm_dax_is_unset_by_default_and_names_its_key_when_misspelt() {
        let mut cfg = Config::default();
        assert_eq!(vm_dax(&cfg).unwrap(), None);
        cfg.executor.vm.dax = Some("4G".into());
        assert_eq!(
            vm_dax(&cfg).unwrap(),
            Some(crate::vmm::Dax::Inode {
                window: 4 << 30,
                min: crate::vmm::DAX_INODE_MIN_DEFAULT
            })
        );
        cfg.executor.vm.dax = Some("off".into());
        assert_eq!(vm_dax(&cfg).unwrap(), Some(crate::vmm::Dax::Off));
        cfg.executor.vm.dax = Some("lots".into());
        let err = vm_dax(&cfg).unwrap_err().to_string();
        assert!(err.contains("[executor.vm] dax"), "{err}");
    }

    fn ctx(cpus_req: Option<&str>, mem_req: Option<&str>) -> JobCtx {
        let mut cfg = Config::default();
        cfg.executor.vm.cpus = 4;
        cfg.executor.vm.mem = "8G".into();
        cfg.executor.vm.max_cpus = Some(16);
        cfg.executor.vm.max_mem = Some("64G".into());
        let mut ctx = JobCtx::new_for_job(cfg, "42".into()).unwrap();
        ctx.cpus_req = cpus_req.map(String::from);
        ctx.mem_req = mem_req.map(String::from);
        ctx
    }

    #[test]
    fn live_supervisor_pid_rejects_a_pid_that_is_no_longer_ours() {
        let dir = std::env::temp_dir().join(format!("vk-live-pid-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = Config {
            state_dir: Some(dir.clone()),
            ..Default::default()
        };
        let ctx = JobCtx::new_for_job(cfg, "42".into()).unwrap();
        std::fs::create_dir_all(&ctx.job_dir).unwrap();

        // No pidfile: nothing was ever recorded.
        assert_eq!(live_supervisor_pid(&ctx), None);

        // A live pid whose cmdline does not name the job dir is a reused pid, not ours
        // — this test process itself stands in for one.
        std::fs::write(ctx.supervisor_pidfile(), std::process::id().to_string()).unwrap();
        assert_eq!(live_supervisor_pid(&ctx), None);

        // Positive control for that guard: the same pid does match a tag its cmdline
        // carries, so the None above is the tag mismatch and not an unreadable /proc.
        let exe = std::env::current_exe().unwrap();
        let exe_name = exe.file_name().unwrap().to_string_lossy().into_owned();
        assert!(pid_running(std::process::id() as i32, &exe_name));

        // An unparseable pidfile yields None, like an absent one.
        std::fs::write(ctx.supervisor_pidfile(), "not-a-pid").unwrap();
        assert_eq!(live_supervisor_pid(&ctx), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn narrowing_honors_the_config_cap() {
        // Unconstrained cap (None): the request defines the list freely.
        assert_eq!(
            narrow_names(None, "a.com, b.com", "V").unwrap(),
            vec!["a.com".to_string(), "b.com".to_string()]
        );
        assert_eq!(
            narrow_ips(None, "8.8.8.8/32", "V").unwrap(),
            vec!["8.8.8.8/32".to_string()]
        );

        // Some(cap): within is accepted, outside fails, and an empty cap (deny-all) rejects any.
        let cap = ["corp.example.com".to_string()];
        assert!(narrow_names(Some(&cap), "api.corp.example.com", "V").is_ok());
        assert!(narrow_names(Some(&cap), "evil.com", "V").is_err());
        assert!(narrow_names(Some(&[]), "anything.com", "V").is_err());

        let ipcap = ["10.0.0.0/8".to_string()];
        assert!(narrow_ips(Some(&ipcap), "10.1.2.0/24", "V").is_ok());
        assert!(narrow_ips(Some(&ipcap), "192.168.0.0/16", "V").is_err());
        assert!(narrow_ips(Some(&[]), "10.0.0.0/8", "V").is_err());
    }

    #[test]
    fn split_req_strips_inline_comments() {
        // `#` begins an end-of-line comment; entries still split on comma/space/newline and a
        // whole-line comment yields nothing.
        assert_eq!(
            split_req("crates.io # Rust registry\npypi.org, debian.org\n# whole-line comment\n"),
            vec![
                "crates.io".to_string(),
                "pypi.org".to_string(),
                "debian.org".to_string()
            ]
        );
        // Comment text never leaks in as a bogus allowlist entry.
        assert_eq!(
            narrow_names(None, "a.com # note", "V").unwrap(),
            vec!["a.com".to_string()]
        );
        // `\r\n` line endings are stripped and a `#` with no leading space still starts a
        // comment.
        assert_eq!(
            split_req("crates.io#tight\r\ndebian.org\r\n"),
            vec!["crates.io".to_string(), "debian.org".to_string()]
        );
    }

    #[test]
    fn a_job_var_cannot_widen_the_omitted_dimension() {
        // A name-only run cap denies all direct-IP egress, so an IP job var may add nothing:
        // the job cannot escape the cap by populating the dimension the config left absent.
        let mut cfg = Config::default();
        cfg.egress.allow_name = Some(vec!["corp.example.com".into()]);
        let mut c = JobCtx::new_for_job(cfg, "1".into()).unwrap();
        c.egress_allow_ip_req = Some("8.8.8.8/32".into());
        assert!(effective_run_egress(&c.cfg, &c).is_err());

        // Symmetrically for the build phase: an IP-only cap denies names.
        let mut cfg = Config::default();
        cfg.egress.build.allow_ip = Some(vec!["10.0.0.0/8".into()]);
        let mut c = JobCtx::new_for_job(cfg, "1".into()).unwrap();
        c.egress_build_allow_name_req = Some("evil.com".into());
        assert!(effective_build_egress(&c.cfg, &c).is_err());

        // But with both dimensions absent (unrestricted / audit-to-discover) a job var still
        // defines its dimension freely — the collapse only applies to a restricted phase.
        let mut c = JobCtx::new_for_job(Config::default(), "1".into()).unwrap();
        c.egress_allow_ip_req = Some("8.8.8.8/32".into());
        let (ips, names, restrict) = effective_run_egress(&c.cfg, &c).unwrap();
        assert_eq!(ips, vec!["8.8.8.8/32".to_string()]);
        assert!(names.is_empty() && restrict);
    }

    #[test]
    fn effective_build_egress_maps_config_and_job_vars() {
        // Absent [egress.build] => unrestricted (BuildNet::All), audit off.
        let mut cfg = Config::default();
        let c = JobCtx::new_for_job(cfg, "1".into()).unwrap();
        let (net, audit) = effective_build_egress(&c.cfg, &c).unwrap();
        assert!(matches!(net, crate::build::BuildNet::All) && !audit);

        // Configured allow_name (+ audit) => restricted Allow, audit on. A job var narrows it.
        cfg = Config::default();
        cfg.egress.build.allow_name = Some(vec!["crates.io".into(), "pypi.org".into()]);
        cfg.egress.build.audit = true;
        let mut c = JobCtx::new_for_job(cfg, "1".into()).unwrap();
        c.egress_build_allow_name_req = Some("crates.io".into());
        let (net, audit) = effective_build_egress(&c.cfg, &c).unwrap();
        match net {
            crate::build::BuildNet::Allow { names, ips } => {
                assert_eq!(names, vec!["crates.io".to_string()]);
                assert!(ips.is_empty());
            }
            other => panic!("expected Allow, got {other:?}"),
        }
        assert!(audit);

        // A job var outside the cap fails the job.
        c.egress_build_allow_name_req = Some("evil.com".into());
        assert!(effective_build_egress(&c.cfg, &c).is_err());
    }

    // pack_checkout_seed builds a portable tar (the `tar` crate, no host `tar` binary): it drops
    // the top-level .git, packs files/dirs/symlinks, stamps `owner`, and round-trips.
    #[test]
    fn pack_checkout_seed_excludes_git_stamps_owner_and_round_trips() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("vk-packseed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("src");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::create_dir_all(src.join(".git")).unwrap();
        std::fs::write(src.join("a.txt"), b"hello").unwrap();
        std::fs::write(src.join("sub/b.txt"), b"world").unwrap();
        std::fs::write(src.join(".git/config"), b"[core]").unwrap();
        symlink("a.txt", src.join("link")).unwrap();
        // Targets tar-rs would rewrite: a doubled slash, and one past the 100-byte header field.
        symlink("sub//./b.txt", src.join("odd")).unwrap();
        let long_target = format!("{}/b.txt", "sub/..//".repeat(20));
        assert!(long_target.len() > 100);
        symlink(&long_target, src.join("long")).unwrap();

        let dest = root.join(CICHECKOUT_TAR);
        let bytes = pack_checkout_seed(&src, &dest, Some((4242, 4243))).unwrap();
        assert_eq!(bytes, std::fs::metadata(&dest).unwrap().len());

        // Collect (name, entry-type, owner, symlink target) from the archive.
        let mut entries = std::collections::BTreeMap::new();
        for e in tar::Archive::new(std::fs::File::open(&dest).unwrap())
            .entries()
            .unwrap()
        {
            let e = e.unwrap();
            let name = e.path().unwrap().to_string_lossy().into_owned();
            let link = e
                .link_name()
                .unwrap()
                .map(|p| p.to_string_lossy().into_owned());
            entries.insert(
                name,
                (
                    e.header().entry_type(),
                    e.header().uid().unwrap(),
                    e.header().gid().unwrap(),
                    link,
                ),
            );
        }

        // The worktree is packed; the top-level .git is not.
        assert!(entries.contains_key("a.txt"), "{entries:?}");
        assert!(entries.contains_key("sub/b.txt"), "{entries:?}");
        assert!(entries.contains_key("sub"), "{entries:?}");
        assert!(
            !entries.keys().any(|n| n.starts_with(".git")),
            ".git must be excluded: {entries:?}"
        );
        // The symlink is a symlink pointing at its target, not the target's contents.
        assert_eq!(
            entries
                .get("link")
                .map(|(t, .., l)| (t.is_symlink(), l.clone())),
            Some((true, Some("a.txt".to_string())))
        );
        // Link targets are stored byte for byte, so the unpacked tree matches git's blobs.
        assert_eq!(
            entries.get("odd").and_then(|(.., l)| l.clone()).as_deref(),
            Some("sub//./b.txt")
        );
        assert_eq!(
            entries.get("long").and_then(|(.., l)| l.clone()).as_deref(),
            Some(long_target.as_str())
        );
        // Every entry is stamped with the requested owner.
        for (name, (_, uid, gid, _)) in &entries {
            assert_eq!((*uid, *gid), (4242, 4243), "owner of {name}");
        }

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn checkout_virtiofs_cmdline_pins_the_agent_contract() {
        assert_eq!(
            checkout_virtiofs_cmdline("/builds/grp/proj", false, "80%", false),
            " VIRTKIT_VIRTIOFS=cibuild:/builds/grp/proj",
            "a read-write checkout has no layer to size"
        );
        assert_eq!(
            checkout_virtiofs_cmdline("/builds/grp/proj", false, "80%", true),
            " VIRTKIT_VIRTIOFS=cibuild:/builds/grp/proj",
            "a read-write checkout has no upper to seed either"
        );
        assert_eq!(
            checkout_virtiofs_cmdline("/builds/grp/proj", true, "80%", false),
            " VIRTKIT_VIRTIOFS=cibuild:/builds/grp/proj VIRTKIT_VIRTIOFS_OVERLAY=cibuild \
             VIRTKIT_VIRTIOFS_OVERLAY_SIZE=80%"
        );
        assert_eq!(
            checkout_virtiofs_cmdline("/builds/grp/proj", true, "80%", true),
            " VIRTKIT_VIRTIOFS=cicheckout:/run/virtkit-checkout,cibuild:/builds/grp/proj \
             VIRTKIT_VIRTIOFS_OVERLAY=cibuild VIRTKIT_VIRTIOFS_OVERLAY_SIZE=80% \
             VIRTKIT_VIRTIOFS_OVERLAY_SEED=cibuild:/run/virtkit-checkout/worktree.tar",
            "the seed share is mounted first, then named as the overlay's seed"
        );
    }

    /// The size crosses into the guest's mount options, so what reaches the cmdline has to be a
    /// tmpfs size and nothing else — a value carrying a separator would mount the job's writable
    /// layer with options the operator never wrote.
    #[test]
    fn only_a_tmpfs_size_reaches_the_overlay_cmdline() {
        for good in ["80%", "100%", "1%", "12G", "512M", "1024k", "2048"] {
            assert_eq!(checkout_overlay_size(good).unwrap(), good);
        }
        for bad in [
            "",
            "80 %",
            "80%,mode=0777",
            "eighty",
            "%80",
            "12GB",
            "12Gi",
            "-1",
            // All of the memory is a policy; more than all of it is a typo, and zero is a layer
            // no job could write a byte to. A percentage that overflows a u32 is not a bypass.
            "101%",
            "4294967296%",
            "0",
            "0%",
        ] {
            assert!(
                checkout_overlay_size(bad).is_err(),
                "accepted {bad:?} as a tmpfs size"
            );
        }
    }

    #[test]
    fn passwd_lookup_resolves_uid_and_primary_gid() {
        let passwd = b"root:x:0:0:root:/root:/bin/sh\ndev:x:1000:1001:dev:/home/dev:/bin/bash\n";
        assert_eq!(passwd_lookup(passwd, "dev"), Some((1000, 1001)));
        assert_eq!(passwd_lookup(passwd, "root"), Some((0, 0)));
        assert_eq!(passwd_lookup(passwd, "nobody"), None);
        // A name-matching line with an unparseable uid is skipped, not fatal: the later good
        // line for the same name still resolves.
        let dup = b"dev:x:bogus:1001:::\ndev:x:1000:1001:::\n";
        assert_eq!(passwd_lookup(dup, "dev"), Some((1000, 1001)));
    }

    #[test]
    fn group_lookup_resolves_gid() {
        let group = b"root:x:0:\nstaff:x:50:dev\ndev:x:1001:\n";
        assert_eq!(group_lookup(group, "staff"), Some(50));
        assert_eq!(group_lookup(group, "dev"), Some(1001));
        assert_eq!(group_lookup(group, "nogroup"), None);
    }

    #[test]
    fn run_user_ids_numeric_and_root_branches() {
        let no_rootfs = Path::new("/nonexistent/runner.ext4");
        assert_eq!(guest_run_user_ids("1000", no_rootfs), Some((1000, 1000)));
        assert_eq!(
            guest_run_user_ids("1000:2000", no_rootfs),
            Some((1000, 2000))
        );
        assert_eq!(guest_run_user_ids("", no_rootfs), None);
        assert_eq!(guest_run_user_ids("root", no_rootfs), None);
        assert_eq!(guest_run_user_ids("0", no_rootfs), None);
        // Any half that is a name needs the rootfs; with none readable it resolves to nothing
        // (no guess) rather than the old squash's blanket owner map.
        assert_eq!(guest_run_user_ids("dev", no_rootfs), None);
        assert_eq!(guest_run_user_ids("1000:staff", no_rootfs), None);
        assert_eq!(guest_run_user_ids("dev:2000", no_rootfs), None);
    }

    #[test]
    fn run_user_ids_resolves_names_against_a_real_rootfs() {
        // Build a throwaway ext4 image carrying just /etc/passwd and /etc/group, then resolve
        // name-form `User` values against it exactly as the pre-boot path does.
        let dir = std::env::temp_dir().join(format!("vk-vm-userids-{}", std::process::id()));
        let src = dir.join("src");
        std::fs::create_dir_all(src.join("etc")).unwrap();
        std::fs::write(
            src.join("etc/passwd"),
            b"root:x:0:0:root:/root:/bin/sh\ndev:x:1000:1001:dev:/home/dev:/bin/bash\n",
        )
        .unwrap();
        std::fs::write(src.join("etc/group"), b"dev:x:1001:\nstaff:x:50:dev\n").unwrap();
        let img = dir.join("rootfs.ext4");
        crate::ext4::build_from_dir(&src, &img).unwrap();

        // Plain name → uid + primary gid from /etc/passwd.
        assert_eq!(guest_run_user_ids("dev", &img), Some((1000, 1001)));
        // uid:group-name → uid kept, gid resolved from /etc/group.
        assert_eq!(guest_run_user_ids("1000:staff", &img), Some((1000, 50)));
        // name:group-name → both halves resolved.
        assert_eq!(guest_run_user_ids("dev:staff", &img), Some((1000, 50)));
        // Unknown name → no map.
        assert_eq!(guest_run_user_ids("nobody", &img), None);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn checkout_id_maps_direction_and_no_map() {
        let no_rootfs = Path::new("/nonexistent/runner.ext4");
        // A resolvable (here numeric) run user → a 1:1 map from the job's ids onto the owner's,
        // uid and gid each in that order. Guards the spec string against an owner/job arg swap.
        assert_eq!(
            checkout_id_maps("1000:2000", no_rootfs, (5000, 6000)),
            (
                vec!["map:1000:5000:1".to_string()],
                vec!["map:2000:6000:1".to_string()],
            )
        );
        // Root or an unresolvable user → no map at all (the tree stays host-owner-owned).
        assert_eq!(
            checkout_id_maps("root", no_rootfs, (5000, 6000)),
            (Vec::new(), Vec::new())
        );
        assert_eq!(
            checkout_id_maps("dev", no_rootfs, (5000, 6000)),
            (Vec::new(), Vec::new())
        );
    }

    #[test]
    fn sizing() {
        assert_eq!(vm_size(&ctx(None, None)).unwrap(), (4, "8G".into()));
        assert_eq!(
            vm_size(&ctx(Some("12"), Some("32G"))).unwrap(),
            (12, "32G".into())
        );
        // clamped to the ceilings
        assert_eq!(
            vm_size(&ctx(Some("64"), Some("256G"))).unwrap(),
            (16, "64G".into())
        );
        // garbage rejected
        assert!(vm_size(&ctx(Some("zero"), None)).is_err());
        assert!(vm_size(&ctx(Some("0"), None)).is_err());
        assert!(vm_size(&ctx(None, Some("64"))).is_err());
        assert!(vm_size(&ctx(None, Some("4096M"))).is_err());
    }

    /// A memory budget is a host ceiling like `max_mem`: a request above the whole budget is
    /// clamped to it rather than left to fail admission, which no retry could ever satisfy.
    #[test]
    fn sizing_clamps_to_the_memory_budget() {
        let mut ctx = ctx(None, Some("64G"));
        assert_eq!(vm_size(&ctx).unwrap().1, "64G", "max_mem alone");
        ctx.cfg.executor.schedule.mem_budget = Some("48G".into());
        assert_eq!(vm_size(&ctx).unwrap().1, "48G");
        // The lower of the two ceilings wins whichever it is.
        ctx.cfg.executor.schedule.mem_budget = Some("256G".into());
        assert_eq!(vm_size(&ctx).unwrap().1, "64G");
        // A job that asked for nothing keeps the configured default, budget or not.
        let mut plain = self::ctx(None, None);
        plain.cfg.executor.schedule.mem_budget = Some("2G".into());
        assert_eq!(vm_size(&plain).unwrap().1, "8G");
    }

    /// A compose service's declared sizing obeys the same `[executor.vm] max_*` ceilings a job's
    /// own MICROVM_CPUS/MICROVM_MEM requests are clamped to; an undeclared axis stays
    /// `None` (the service default), never the job base size.
    #[test]
    fn service_sizing_clamps_to_the_host_ceilings() {
        let ctx = ctx(None, None); // vm: 4 cpus / 8G, max: 16 / 64G
        let service = |marker: &str| {
            crate::compose::parse(
                &format!("services:\n  db:\n    image: x\n{marker}"),
                std::path::Path::new("/b"),
                &|_| None,
                None,
            )
            .unwrap()
            .pop()
            .unwrap()
        };
        // over the ceilings: clamped to them
        let mut unit = service("    x-virtkit: { cpus: 32, mem: 100G }\n");
        clamp_service_size(&ctx.cfg, &mut unit).unwrap();
        assert_eq!(unit.cpus, Some(16));
        assert_eq!(unit.mem.as_deref(), Some("65536M"));
        // a `[executor.schedule] mem_budget` below `max_mem` is the effective ceiling: a service
        // sized above the whole budget could never boot healthily.
        let mut budgeted = self::ctx(None, None);
        budgeted.cfg.executor.schedule.mem_budget = Some("32G".into());
        let mut unit = service("    x-virtkit: { cpus: 2, mem: 100G }\n");
        clamp_service_size(&budgeted.cfg, &mut unit).unwrap();
        assert_eq!(unit.mem.as_deref(), Some("32768M"));
        // under them: kept verbatim
        let mut unit = service("    x-virtkit: { cpus: 2, mem: 512M }\n");
        clamp_service_size(&ctx.cfg, &mut unit).unwrap();
        assert_eq!(unit.cpus, Some(2));
        assert_eq!(unit.mem.as_deref(), Some("512M"));
        // undeclared: untouched
        let mut unit = service("");
        clamp_service_size(&ctx.cfg, &mut unit).unwrap();
        assert_eq!((unit.cpus, unit.mem), (None, None));
    }

    /// A job-authored fleet cannot grant itself host KVM. Checked where the fleet loads, so
    /// it covers the primary as well as the siblings — `compose_service_units` drops the
    /// primary, so a later per-service pass would let `compose:file#builder` nest silently.
    #[test]
    fn a_fleet_may_ask_to_nest_only_where_the_runner_allows_it() {
        let service = |marker: &str| {
            crate::compose::parse(
                &format!("services:\n  db:\n    image: x\n{marker}"),
                std::path::Path::new("/b"),
                &|_| None,
                None,
            )
            .unwrap()
            .pop()
            .unwrap()
        };
        let asks = service("    x-virtkit: { nested: true }\n");
        // ungranted the request is refused, not cleared
        let err = refuse_job_nesting(false, &asks).unwrap_err().to_string();
        assert!(err.contains("needs a runner that allows nesting"), "{err}");
        // granted, the same fleet loads
        refuse_job_nesting(true, &asks).unwrap();
        // declaring it off is not a request, and neither is leaving it out
        for granted in [false, true] {
            refuse_job_nesting(granted, &service("    x-virtkit: { nested: false }\n")).unwrap();
            refuse_job_nesting(granted, &service("")).unwrap();
        }
    }

    /// The runner may grant nesting, but only where host KVM will actually nest — asking
    /// on a host that will not is a misconfiguration, not a guest that quietly lacks VMX.
    #[test]
    fn nesting_is_refused_on_a_host_that_will_not_nest() {
        let err = refuse_unsupported_nesting(true, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not allow nesting"), "{err}");
        // granted and supported, and every shape of not asking
        refuse_unsupported_nesting(true, true).unwrap();
        refuse_unsupported_nesting(false, false).unwrap();
        refuse_unsupported_nesting(false, true).unwrap();
    }

    #[test]
    fn a_percentage_memory_budget_is_a_share_of_this_host() {
        // MemTotal always reads somewhat under the machine's nominal size, so the share is
        // rounded up to the whole-GiB unit job sizes come in — except at 100%, which never
        // claims more whole GiB than the host reports.
        let total = 30 * 1024 + 512;
        assert_eq!(parse_budget_mib("50%", Some(total)).unwrap(), 16 * 1024);
        assert_eq!(parse_budget_mib("60%", Some(total)).unwrap(), 19 * 1024);
        assert_eq!(parse_budget_mib("100%", Some(total)).unwrap(), 30 * 1024);
        // An exact size is unchanged, and needs no reading of the host.
        assert_eq!(parse_budget_mib("20G", None).unwrap(), 20 * 1024);
        for invalid in ["0%", "101%", "%", "50", "0G", "-1%", "5 %", "50g"] {
            assert!(
                parse_budget_mib(invalid, Some(total)).is_err(),
                "{invalid:?} must be rejected"
            );
        }
        // A percentage of a host that cannot be measured is refused, not silently taken as all
        // of it: the budget is the one number that must never be guessed upwards.
        assert!(
            parse_budget_mib("50%", None)
                .unwrap_err()
                .to_string()
                .contains("MemTotal")
        );
        // Rounding up means any percentage of a host with at least a GiB resolves to at least
        // one whole GiB; only a host with under a GiB has no budget to give at all.
        assert_eq!(parse_budget_mib("1%", Some(1024)).unwrap(), 1024);
        assert!(parse_budget_mib("50%", Some(512)).is_err());
    }

    /// The ceiling a finished run is stamped with and the ceiling the next admission looks it
    /// up under are computed in two different processes. They agree only because both route
    /// through `declared_mem_mib`, and `under_ceiling` matches on exact equality — so any drift
    /// between them turns `from_history` into a permanent, silent fallback to declared sizes.
    #[test]
    fn a_remembered_run_is_what_the_next_admission_reserves() {
        let dir = std::env::temp_dir().join(format!("vk-hist-seam-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut ctx = ctx(None, Some("8G"));
        ctx.cfg.state_dir = Some(dir.clone());
        ctx.cfg.executor.schedule.mem_budget = Some("48G".into());
        ctx.cfg.executor.schedule.from_history = true;

        let ceiling_mib = declared_mem_mib(&ctx).unwrap();
        assert_eq!(ceiling_mib, 8192, "the job declares what the test set");
        crate::admit::remember(
            &ctx.history_dir(),
            &ctx.usage_key(),
            crate::admit::Run {
                peak: 1000 * 1024 * 1024,
                ceiling: ceiling_mib * 1024 * 1024,
                ..crate::admit::Run::default()
            },
        );
        // 1000 MiB + 25% headroom, under the 8 GiB it declares.
        assert_eq!(
            crate::admit::expect_mib(&ctx.history_dir(), &ctx.usage_key(), ceiling_mib),
            Some(1250),
            "the run just recorded is what the next admission reserves"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With no budget configured and disk admission off the gate is absent: nothing is claimed,
    /// and no ledger is created under the state dir. Disk admission is on by default, and on
    /// its own claims room for the job dir and no memory.
    #[test]
    fn admission_is_absent_without_a_budget_or_disk_admission() {
        let dir = std::env::temp_dir().join(format!("vk-admit-off-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut cfg = Config {
            state_dir: Some(dir.clone()),
            ..Config::default()
        };
        cfg.executor.schedule.disk_admission = Some(false);
        let mut ctx = JobCtx::new_for_job(cfg, "42".into()).unwrap();
        assert!(ctx.cfg.executor.schedule.mem_budget.is_none());
        assert!(admit(&ctx, "8G").unwrap().is_none());
        assert!(!ctx.admit_dir().exists(), "no ledger without a budget");

        let schedule = &mut ctx.cfg.executor.schedule;
        schedule.disk_admission = None;
        schedule.disk_default = Some("1G".into());
        schedule.wait_timeout_secs = Some(0);
        std::fs::create_dir_all(&ctx.job_dir).unwrap();
        let held = admit(&ctx, "8G").unwrap();
        assert!(held.is_some(), "disk admission is on by default");
        let entry = std::fs::read_to_string(ctx.admit_dir().join("42")).unwrap();
        assert!(
            entry.starts_with("0 ") && entry.ends_with(&format!(" granted disk={}\n", 1u64 << 30)),
            "{entry}"
        );
        drop(held);

        // Not a size at all (only `G` is): refused before any history is consulted.
        ctx.cfg.executor.schedule.disk_default = Some("1T".into());
        let err = admit(&ctx, "8G").unwrap_err();
        assert!(
            format!("{err:#}").contains("disk_default \"1T\""),
            "{err:#}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Unset, the default is capped at the filesystem, so a small one runs new jobs one at a
    /// time rather than none; set, it is taken as given, for admission to refuse if it cannot
    /// fit.
    #[test]
    fn the_built_in_disk_default_fits_the_filesystem_and_a_set_one_is_as_given() {
        const GIB: u64 = 1 << 30;
        assert_eq!(disk_default(None, 100 * GIB).unwrap(), DISK_DEFAULT);
        assert_eq!(disk_default(None, 3 * GIB).unwrap(), 3 * GIB);
        assert_eq!(disk_default(Some("20G"), 3 * GIB).unwrap(), 20 * GIB);
        assert!(disk_default(Some("8GiB"), 100 * GIB).is_err());
        assert!(disk_default(Some("0G"), 100 * GIB).is_err());
    }

    #[test]
    fn cidr_and_netmask() {
        assert_eq!(
            split_cidr("192.168.231.16/24").unwrap(),
            ("192.168.231.16".into(), 24)
        );
        assert_eq!(split_cidr("10.0.0.1/8").unwrap(), ("10.0.0.1".into(), 8));
        assert!(split_cidr("10.0.0.1").is_err());
        assert!(split_cidr("10.0.0.1/33").is_err());
        assert_eq!(prefix_to_netmask(24), "255.255.255.0");
        assert_eq!(prefix_to_netmask(16), "255.255.0.0");
        assert_eq!(prefix_to_netmask(8), "255.0.0.0");
        assert_eq!(prefix_to_netmask(0), "0.0.0.0");
        assert_eq!(prefix_to_netmask(32), "255.255.255.255");
    }

    #[test]
    fn confined_dockerfile_stays_inside_the_checkout() {
        let root = std::env::temp_dir().join(format!("vk-confine-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("docker")).unwrap();
        std::fs::write(root.join("Dockerfile"), b"FROM scratch\n").unwrap();
        std::fs::write(root.join("docker").join("ci"), b"FROM scratch\n").unwrap();

        // A plain repo-relative Dockerfile resolves inside the checkout.
        assert!(confined_dockerfile(&root, "Dockerfile").is_ok());
        assert!(confined_dockerfile(&root, "docker/ci").is_ok());

        // Absolute paths (which `Path::join` would honour, discarding the base) and `..`
        // traversal are refused before any read.
        assert!(confined_dockerfile(&root, "/etc/passwd").is_err());
        assert!(confined_dockerfile(&root, "../../etc/passwd").is_err());
        assert!(confined_dockerfile(&root, "docker/../../escape").is_err());

        // A symlink committed in the repo that points outside the checkout is refused after
        // canonicalization, even though it has no `..` component.
        let outside = std::env::temp_dir().join(format!("vk-confine-out-{}", std::process::id()));
        let _ = std::fs::remove_file(&outside);
        std::fs::write(&outside, b"FROM scratch\n").unwrap();
        let link = root.join("evil");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        assert!(
            confined_dockerfile(&root, "evil").is_err(),
            "a symlink escaping the checkout must be refused"
        );

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(&outside);
    }

    #[test]
    fn a_job_env_file_cannot_reach_outside_the_checkout() {
        let root = std::env::temp_dir().join(format!("vk-envconfine-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        std::fs::write(root.join("app.env"), b"OK=1\n").unwrap();
        let secrets = std::env::temp_dir().join(format!("vk-envsecret-{}", std::process::id()));
        std::fs::write(&secrets, b"RUNNER_TOKEN=glrt-real\n").unwrap();

        let unit = |files: Vec<(PathBuf, bool)>| {
            let mut u = crate::services::to_units(vec![crate::services::Service {
                name: "x".into(),
                alias: "s".into(),
                entrypoint: vec![],
                command: vec![],
                variables: Default::default(),
            }])
            .pop()
            .unwrap();
            u.env_files = files;
            u
        };

        // Inside the checkout: read, with the paths consumed on the way.
        let mut ok = unit(vec![(root.join("app.env"), true)]);
        resolve_job_env_files(&root, &mut ok).unwrap();
        assert_eq!(ok.environment, vec![("OK".to_string(), "1".to_string())]);
        assert!(ok.env_files.is_empty());

        // An absolute path (which `Path::join` honours, discarding the base), a `..`
        // traversal, and a symlink that leaves the checkout are all refused — before the
        // file is opened, so nothing leaks even into the error.
        let link = root.join("out.env");
        std::os::unix::fs::symlink(&secrets, &link).unwrap();
        for escape in [secrets.clone(), root.join("../../etc/passwd"), link.clone()] {
            let mut bad = unit(vec![(escape.clone(), true)]);
            let msg = format!("{:#}", resolve_job_env_files(&root, &mut bad).unwrap_err());
            assert!(
                msg.contains("outside the repo checkout"),
                "{escape:?}: {msg}"
            );
            assert!(!msg.contains("glrt-real"), "leaked the file: {msg}");
        }

        // Optional does not buy a way past the check: a path outside the checkout is
        // refused whether or not it is there, so the error cannot be read as an answer to
        // "does this host file exist?".
        let outside_absent = std::env::temp_dir().join("vk-definitely-not-here.env");
        for probe in [secrets.clone(), outside_absent] {
            let mut bad = unit(vec![(probe.clone(), false)]);
            let err = resolve_job_env_files(&root, &mut bad).unwrap_err();
            assert!(
                format!("{err:#}").contains("outside the repo checkout"),
                "{probe:?} should be refused the same way whether or not it exists"
            );
        }

        // Inside the checkout, existence is the job's own business: optional and absent is
        // skipped, required and absent is an error.
        let mut absent = unit(vec![(root.join("nope.env"), false)]);
        resolve_job_env_files(&root, &mut absent).unwrap();
        assert!(absent.environment.is_empty());
        let mut needed = unit(vec![(root.join("nope.env"), true)]);
        assert!(resolve_job_env_files(&root, &mut needed).is_err());

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(&secrets);
    }

    #[test]
    fn parse_dockerfile_spec_splits_path_params_and_stage() {
        // Bare path: no params, no stage — the context defaults to the Dockerfile's dir.
        let p = parse_dockerfile_spec("docker/wabbuilder/Dockerfile").unwrap();
        assert_eq!(p.path, "docker/wabbuilder/Dockerfile");
        assert_eq!(p.context, None);
        assert_eq!(p.stage, None);
        assert!(p.build_args.is_empty());

        // `#<stage>` selects a target.
        let p = parse_dockerfile_spec("docker/wabbuilder/Dockerfile#bastion-builder").unwrap();
        assert_eq!(p.path, "docker/wabbuilder/Dockerfile");
        assert_eq!(p.context, None);
        assert_eq!(p.stage, Some("bastion-builder"));
        assert!(p.build_args.is_empty());

        // `?context=<dir>` plus repeated `?arg=NAME=VALUE`; query comes before the `#` fragment,
        // and a build-arg value may itself contain `=`.
        let p = parse_dockerfile_spec(
            "docker/wabbuilder/Dockerfile?context=.&arg=UID=1000&arg=KV=a=b#bastion-builder",
        )
        .unwrap();
        assert_eq!(p.path, "docker/wabbuilder/Dockerfile");
        assert_eq!(p.context, Some("."));
        assert_eq!(p.stage, Some("bastion-builder"));
        assert_eq!(p.build_args, vec![("UID", "1000"), ("KV", "a=b")]);

        // A context override without a stage.
        let p = parse_dockerfile_spec("a/Dockerfile?context=a/ctx").unwrap();
        assert_eq!(p.path, "a/Dockerfile");
        assert_eq!(p.context, Some("a/ctx"));
        assert_eq!(p.stage, None);
        assert!(p.build_args.is_empty());

        // Named contexts (repeatable), mixed with the other params and a stage: each is a
        // NAME=DIR pair, distinct from the positional `context=`.
        let p = parse_dockerfile_spec(
            "docker/dev-container/Dockerfile?buildcontext=shared=shared&arg=X=y\
             &buildcontext=tools=ci/tools#builder-ci",
        )
        .unwrap();
        assert_eq!(p.path, "docker/dev-container/Dockerfile");
        assert_eq!(p.context, None);
        assert_eq!(p.stage, Some("builder-ci"));
        assert_eq!(p.build_args, vec![("X", "y")]);
        assert_eq!(
            p.build_contexts,
            vec![("shared", "shared"), ("tools", "ci/tools")]
        );

        // A malformed or duplicated named context is refused rather than half-honoured.
        assert!(parse_dockerfile_spec("a/Dockerfile?buildcontext=shared").is_err());
        assert!(parse_dockerfile_spec("a/Dockerfile?buildcontext==shared").is_err());
        assert!(parse_dockerfile_spec("a/Dockerfile?buildcontext=shared=").is_err());
        assert!(parse_dockerfile_spec("a/Dockerfile?buildcontext=p=a&buildcontext=p=b").is_err());

        // A param-only spec without a stage.
        let p = parse_dockerfile_spec("a/Dockerfile?arg=X=y").unwrap();
        assert_eq!(p.stage, None);
        assert_eq!(p.build_args, vec![("X", "y")]);

        // An empty query (`?` with nothing after it) leaves the path bare, no params.
        let p = parse_dockerfile_spec("a/Dockerfile?").unwrap();
        assert_eq!(p.path, "a/Dockerfile");
        assert_eq!(p.context, None);
        assert_eq!(p.stage, None);
        assert!(p.build_args.is_empty());

        // The `#` binds before the `?`, so a `?context=` placed after a `#` is swallowed by the
        // stage rather than parsed as a parameter — pin that ordering.
        let p = parse_dockerfile_spec("a/Dockerfile#s?context=.").unwrap();
        assert_eq!(p.path, "a/Dockerfile");
        assert_eq!(p.context, None);
        assert_eq!(p.stage, Some("s?context=."));

        // An unknown parameter is rejected rather than silently ignored.
        assert!(parse_dockerfile_spec("a/Dockerfile?ctx=.#s").is_err());
        // A known parameter mixed with an unknown one still fails loudly.
        assert!(parse_dockerfile_spec("a/Dockerfile?context=.&bogus=1").is_err());
        // An empty `context=` value is a mistake (use `context=.` for the repo root), not a
        // silent revert to the old repo-root default.
        assert!(parse_dockerfile_spec("a/Dockerfile?context=").is_err());
        // A repeated `context=` is rejected rather than silently taking one.
        assert!(parse_dockerfile_spec("a/Dockerfile?context=a&context=b").is_err());
        // An `arg` missing its `=VALUE` is rejected.
        assert!(parse_dockerfile_spec("a/Dockerfile?arg=NOEQUALS").is_err());
    }

    #[test]
    fn resolve_build_context_defaults_to_the_dockerfile_dir_and_stays_confined() {
        let root = std::env::temp_dir().join(format!("vk-ctx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("docker").join("ci")).unwrap();
        std::fs::write(root.join("docker").join("Dockerfile"), b"FROM scratch\n").unwrap();
        let canon_root = root.canonicalize().unwrap();

        // With no override, the context defaults to the (confined) Dockerfile's own directory.
        let dockerfile = confined_dockerfile(&root, "docker/Dockerfile").unwrap();
        assert_eq!(
            resolve_build_context(&root, &dockerfile, None).unwrap(),
            canon_root.join("docker")
        );

        // A `?context=<dir>` override is confined and resolves inside the checkout.
        assert_eq!(
            resolve_build_context(&root, &dockerfile, Some("docker/ci")).unwrap(),
            canon_root.join("docker").join("ci")
        );
        // An override escaping the checkout is refused, the same way the Dockerfile path is.
        assert!(resolve_build_context(&root, &dockerfile, Some("../escape")).is_err());

        // A degenerate Dockerfile path that resolves to the checkout root itself would default
        // its context to the root's parent — outside the checkout — so it is refused.
        let root_as_dockerfile = confined_dockerfile(&root, ".").unwrap();
        assert!(resolve_build_context(&root, &root_as_dockerfile, None).is_err());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn confine_under_rejects_paths_outside_the_root() {
        // Guards a compose file's job-authored `build:` context/Dockerfile paths, which arrive
        // already joined (absolute or `..`-laden) from the shared parser.
        let root = std::env::temp_dir().join(format!("vk-confine-under-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("ctx")).unwrap();
        let canon_root = root.canonicalize().unwrap();

        // An in-checkout context resolves.
        assert!(confine_under(&canon_root, &root.join("ctx")).is_ok());
        // An absolute path outside the checkout (what `base.join("/etc")` yields) is refused.
        assert!(confine_under(&canon_root, Path::new("/etc")).is_err());
        // A `..` traversal out of the checkout is refused after canonicalization.
        assert!(confine_under(&canon_root, &root.join("ctx").join("../../..")).is_err());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_ci_service_takes_its_image_from_its_build_not_the_image_cache() {
        use crate::compose::Source;
        // A compose `build:` unit is built and then asked where it landed, rather than
        // provisioned at a predicted address: this process need not reach the stage key
        // prepare's build used, so the address it would compute can name an entry that was
        // never written (see the branch in `plan_services`).
        assert_eq!(
            service_media(&Source::Build {
                dockerfiles: vec![PathBuf::from("Dockerfile")],
                context: PathBuf::from("."),
                build_contexts: Vec::new(),
                target: None,
                args: Vec::new(),
            }),
            ServiceMedia::Build
        );
        // The other two are unchanged: a `dockerfile:` ref builds from the job's checkout,
        // and a plain ref resolves through the shared image cache.
        assert_eq!(
            service_media(&Source::Image("dockerfile:svc/Dockerfile".into())),
            ServiceMedia::Git("svc/Dockerfile")
        );
        assert_eq!(
            service_media(&Source::Image("alpine:3.21".into())),
            ServiceMedia::Image
        );
    }

    /// A write that found no space names the filesystem it filled and how full that is, ahead
    /// of the bare `ENOSPC`; any other failure is left as it was.
    #[test]
    fn a_full_filesystem_is_named_in_front_of_the_error() {
        use std::io::ErrorKind::{PermissionDenied, QuotaExceeded, StorageFull};
        let dir = std::env::temp_dir();
        let failed = |kind| {
            anyhow::Error::new(std::io::Error::from(kind)).context("writing /jobs/1/atop.dir")
        };
        let enospc = failed(StorageFull);
        assert_eq!(storage_full(&enospc), Some(StorageFull));
        let named = format!("{:#}", name_full_fs(enospc, &dir));
        // "is full" or "ran out of space", as the real filesystem's figures have it.
        let lead = format!("{} ", dir.display());
        assert!(named.starts_with(&lead), "{named}");
        assert!(
            named.contains(" used): writing /jobs/1/atop.dir: "),
            "{named}"
        );

        // A quota is not in the filesystem's figures, so none are given.
        let edquot = failed(QuotaExceeded);
        assert_eq!(storage_full(&edquot), Some(QuotaExceeded));
        assert_eq!(
            format!(
                "{:#}",
                name_full_fs(edquot, Path::new("/var/lib/virtkit/jobs"))
            ),
            format!(
                "/var/lib/virtkit/jobs is over its disk quota: writing /jobs/1/atop.dir: {}",
                std::io::Error::from(QuotaExceeded)
            )
        );

        let other = failed(PermissionDenied);
        assert_eq!(storage_full(&other), None);
        let kept = format!("{:#}", name_full_fs(other, &dir));
        assert!(kept.starts_with("writing /jobs/1/atop.dir: "), "{kept}");

        // No filesystem to ask about leaves the error as it came.
        let unnamed = anyhow::Error::new(std::io::Error::from(StorageFull));
        let missing = dir.join("vk-no-such-dir-for-name-full-fs");
        assert_eq!(
            format!("{:#}", name_full_fs(unnamed, &missing)),
            std::io::Error::from(StorageFull).to_string()
        );

        let jobs = Path::new("/var/lib/virtkit/jobs");
        let bytes_out = crate::usage::FsSpace {
            avail: 0,
            total: 128 << 30,
            files_avail: 1 << 20,
            files: 8 << 20,
        };
        assert!(exhausted(&bytes_out));
        assert_eq!(
            full_fs(jobs, bytes_out),
            "/var/lib/virtkit/jobs is full (128.0 GiB of 128.0 GiB used)"
        );
        let inodes_out = crate::usage::FsSpace {
            avail: 64 << 30,
            files_avail: 0,
            ..bytes_out
        };
        assert!(exhausted(&inodes_out));
        assert_eq!(
            full_fs(jobs, inodes_out),
            "/var/lib/virtkit/jobs is out of inodes (8388608 of 8388608 used)"
        );
        // A filesystem with no fixed inode count (btrfs) is never out of inodes.
        let no_inode_count = crate::usage::FsSpace {
            files_avail: 0,
            files: 0,
            ..inodes_out
        };
        assert!(!exhausted(&no_inode_count));
        assert_eq!(
            full_fs(jobs, no_inode_count),
            "/var/lib/virtkit/jobs ran out of space (64.0 GiB of 128.0 GiB used)"
        );
    }

    /// An atop setup failure fails the job only where it found the job dirs' filesystem full.
    #[test]
    fn only_a_full_job_dirs_filesystem_fails_the_atop_setup() {
        use std::io::ErrorKind::StorageFull;
        let unasked = || panic!("a write to the job dirs' filesystem needs no statvfs");
        assert!(atop_failure_is_fatal(Some(StorageFull), true, unasked));
        assert!(atop_failure_is_fatal(Some(StorageFull), false, || true));
        // A full archive elsewhere costs only the statistics.
        assert!(!atop_failure_is_fatal(Some(StorageFull), false, || false));
        assert!(!atop_failure_is_fatal(None, true, || true));
    }

    /// A path that does not exist yet is on its nearest existing ancestor's filesystem.
    #[test]
    fn same_fs_answers_for_a_missing_path_with_its_ancestor() {
        let dir = std::env::temp_dir();
        assert!(same_fs(&dir, &dir.join("vk-no-such-dir/child")));
        assert!(!same_fs(&dir, Path::new("/proc")));
    }
}
