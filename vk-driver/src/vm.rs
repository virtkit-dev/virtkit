//! microVM lifecycle: prepare (overlay + cloud-hypervisor + wait for the in-guest
//! agent) and cleanup (ACPI poweroff, escalation, state removal). One VM per job.

use std::io::{Read, Write};
use std::net::Ipv4Addr;
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
    /// `[vm] nested` through [`crate::run::effective_nested`]. False for every non-compose
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

/// The cmdline fragment mounting the host_checkout share in the guest. The agent mounts
/// VIRTKIT_VIRTIOFS shares at boot (mkdir -p'ing the mount point); CI supervise sets no
/// other share, so a plain assignment is safe. With `overlay`, VIRTKIT_VIRTIOFS_OVERLAY
/// tells the agent to build the tree on a tmpfs-backed overlay above the (then read-only)
/// share instead of mounting it directly, and VIRTKIT_VIRTIOFS_OVERLAY_SIZE how much of the
/// VM's memory that layer may take.
fn checkout_virtiofs_cmdline(mount: &str, overlay: bool, size: &str) -> String {
    let mut s = format!(" VIRTKIT_VIRTIOFS={CIBUILD_TAG}:{mount}");
    if overlay {
        s.push_str(&format!(" VIRTKIT_VIRTIOFS_OVERLAY={CIBUILD_TAG}"));
        s.push_str(&format!(" VIRTKIT_VIRTIOFS_OVERLAY_SIZE={size}"));
    }
    s
}

/// `[gitlab] checkout_overlay_size` as a tmpfs `size=` token: a percentage (`80%`) or an
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
            "[gitlab] checkout_overlay_size {spec:?} is not a tmpfs size: \
             want a percentage of the VM memory (e.g. \"80%\") or an absolute size (e.g. \"12G\")"
        );
    }
    // A parse failure on all-digit input is u32 overflow, which is even more than 100%.
    if unit == "%" && !digits.parse::<u32>().is_ok_and(|pct| pct <= 100) {
        bail!("[gitlab] checkout_overlay_size {spec:?} is more than all of the VM's memory");
    }
    Ok(spec)
}

pub async fn prepare(ctx: &JobCtx) -> Result<()> {
    let cfg = &ctx.cfg;
    // Cheap fail-fast checks first (crisp errors in the runner-visible process beat a
    // supervisor-log pointer).
    if unsafe { libc::access(c"/dev/kvm".as_ptr(), libc::R_OK | libc::W_OK) } != 0 {
        bail!("no rw access to /dev/kvm (is the runner user in the kvm group?)");
    }
    refuse_unsupported_nesting(cfg.vm.nested, crate::vmm::host_nesting_enabled())?;
    let (cpus, mem) = vm_size(ctx)?;
    // Validate the run-phase egress narrowing here so a MICROVM_EGRESS_ALLOW_* request
    // outside the `[egress]` cap fails with a crisp job-visible error — the switch itself is
    // spawned later in the detached supervisor, whose log the job never sees. (The build
    // phase validates in build_git_image / build_compose_unit, also in prepare.)
    effective_run_egress(cfg, ctx)?;
    // Same fail-fast rationale for the writable-layer size: it is pure config, and the
    // authoritative check runs in the detached supervisor whose log the job never sees.
    if let Some(gl) = &cfg.gitlab {
        checkout_overlay_size(&gl.checkout_overlay_size)?;
    }

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
        .with_context(|| format!("creating {}", ctx.job_dir.display()))?;

    // [gitlab] atop: give this job somewhere to record what its guest does, and remember
    // where — the supervisor shares that directory into the guest, and the last stage
    // reports the log's path. Validated here (a job-visible error names the setting) but
    // never fatal beyond that: a host whose archive cannot be written still runs jobs,
    // silently unrecorded but for the warning.
    if crate::atop::enabled(cfg) {
        let interval = crate::atop::interval_secs(cfg)?;
        // Bound what the archive costs the host before adding a job to it.
        crate::atop::prune_archive_daily(cfg);
        match crate::atop::prepare_archive(ctx) {
            Ok(dir) => println!(
                "virtkit: recording guest stats every {interval}s -> {}",
                dir.join(vk_core::atop::LOG_NAME).display()
            ),
            Err(e) => eprintln!("virtkit: warning: not recording guest stats: {e:#}"),
        }
    }

    // Memory admission (`[schedule] mem_budget`): claim the guest RAM this job is about to
    // boot before booting it, waiting for room on a full host. Held for the rest of prepare;
    // the supervisor takes its own hold on the same reservation, so it never lapses between
    // the two. After the stale-job teardown above, which frees a predecessor's claim.
    let _reservation = admit_memory(ctx, &mem)?;

    // [gitlab] host_checkout: check the sources out on the host NOW — before resolving the
    // image (a `dockerfile:`/`compose:` image is built from these sources) and before the
    // guest boots — so supervise can share the tree in and the git token never enters the
    // guest (the job sets GIT_STRATEGY: none). Crisp errors here (the runner-visible prepare)
    // beat a supervisor-log pointer; like any prepare failure a checkout error exits
    // system_failure.
    // Held to the end of prepare, which outlasts the supervisor taking its own hold below, so the
    // tree is referenced continuously from the clone until the job's VM is gone.
    let _checkout_use = if cfg.gitlab.as_ref().is_some_and(|g| g.host_checkout) {
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
    let mut sup =
        spawn_detached(sup_cmd, &ctx.supervisor_log()).context("spawning the job supervisor")?;

    println!("virtkit: booting microVM {image_ref} (cpus={cpus}, mem={mem})");

    // Ready = the in-guest virtkit-agent answers on vsock. The supervisor exiting
    // during boot (the VMM died, a helper failed to start) fails the poll fast.
    let addr = crate::vmm::exec_addr(&ctx.vsock_sock(), cfg.vm.vsock_port);
    let start = Instant::now();
    let deadline = start + Duration::from_secs(cfg.vm.boot_timeout_secs);
    loop {
        if let Some(status) = sup.try_wait()? {
            log_tail(&ctx.supervisor_log(), 15);
            log_tail(&ctx.console_log(), 30);
            log_tail(&ctx.vmm_log(), 20);
            bail!(
                "the job supervisor exited during boot ({status}, see {})",
                ctx.supervisor_log().display()
            );
        }
        match vk_core::status::get_status(&addr).await {
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
                        cfg.vm.boot_timeout_secs,
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
    let deadline = start + Duration::from_secs(cfg.vm.boot_timeout_secs);
    for name in names {
        let dir = ctx.job_dir.join(format!("svc-{name}"));
        let addr = crate::vmm::exec_addr(&dir.join("vsock.sock"), crate::units::VSOCK_PORT);
        loop {
            match vk_core::status::get_status(&addr).await {
                Ok(_) => {
                    println!(
                        "vk: service {name} ready in {:.1}s",
                        start.elapsed().as_secs_f32()
                    );
                    break;
                }
                Err(e) => {
                    if Instant::now() >= deadline {
                        log_tail(&dir.join("console.log"), 30);
                        bail!(
                            "service {name} not ready after {}s ({e}) — console tail above",
                            cfg.vm.boot_timeout_secs
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
            // A plain image ref carries no compose marker; only `[vm] nested` can grant it.
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
            config,
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
/// (`plan_services`). Requires `[gitlab] host_checkout`: the Dockerfile + context are the
/// checked-out sources. The context defaults to the Dockerfile's directory; `?context=<dir>`
/// overrides it. `--build-arg`s come from `?arg=<NAME>=<VALUE>` parameters (repeatable), and
/// `?buildcontext=<NAME>=<DIR>` (repeatable) names an extra context directory — every path
/// confined to the checkout, since all of them are job-authored.
fn build_git_image(
    ctx: &JobCtx,
    spec: &str,
) -> Result<(
    PathBuf,
    Option<vk_core::runcfg::RunConfig>,
    crate::cachelock::Guard,
)> {
    let cfg = &ctx.cfg;
    if !cfg.gitlab.as_ref().is_some_and(|g| g.host_checkout) {
        bail!(
            "a git-defined (dockerfile:/compose:) image requires [gitlab] host_checkout — the \
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
    let rootfs = dir.join("runner.ext4");
    // The stage's Env/User captured by the build (applied at boot via the preinit initramfs).
    let config = std::fs::read_to_string(crate::build::config_sidecar(&rootfs))
        .ok()
        .and_then(|s| vk_core::runcfg::RunConfig::from_json(&s).ok());
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
/// `[gitlab] host_checkout` (the compose file + its build contexts are the checked-out
/// sources) and a `#<primary>` naming the job VM. `MICROVM_PROFILE` (space/comma separated)
/// selects extra services.
fn load_compose_fleet(ctx: &JobCtx, spec: &str) -> Result<ComposeFleet> {
    if !ctx.cfg.gitlab.as_ref().is_some_and(|g| g.host_checkout) {
        bail!(
            "a compose: image requires [gitlab] host_checkout — the compose file and its build \
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
        refuse_job_nesting(ctx.cfg.vm.nested, unit)?;
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
    let _checkout_use = if cfg.gitlab.as_ref().is_some_and(|g| g.host_checkout) {
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
    // Reference the materialized image bases this job overlays (the primary plus every
    // service) for the whole life of `supervise`, so the cache's idle GC cannot evict a
    // base out from under a running overlay. A shared advisory lock the kernel drops when
    // this process exits — held in this Vec until supervise returns (job teardown).
    let mut use_guards: Vec<crate::cachelock::Guard> = Vec::new();
    // The other half of the memory reservation prepare took (see admit): held here for the
    // job's whole life, so what this job booted keeps counting against the host budget until
    // the VM is gone. `None` when admission is off.
    let _reservation = crate::admit::hold(&ctx.admit_dir(), &ctx.job_id);
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
                cfg.vm.hostname, cfg.vm.vsock_port
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
                cfg.vm.hostname
            ),
            media.initrd.clone(),
        )
    };

    let mut shares: Vec<crate::vmm::FsShare> = Vec::new();
    if let Some(share) = &cfg.share {
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
            uid_map: Vec::new(),
            gid_map: Vec::new(),
        });
    }

    // GitLab CI tools ([gitlab] dir): a second, read-only virtio-fs share. The
    // in-guest agent links the tools the job image lacks onto its PATH — dynamic,
    // so nothing is baked into the bundle and a host update needs no re-conversion.
    if let Some(gl) = &cfg.gitlab
        && let Some(dir) = &gl.dir
    {
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
            uid_map: Vec::new(),
            gid_map: Vec::new(),
        });
        cmdline.push_str(" VIRTKIT_TOOLS=vktools:/run/virtkit-tools");
    }

    // [gitlab] host_checkout: the sources checked out on the host in prepare, shared
    // into the guest at CI_PROJECT_DIR. The job sets GIT_STRATEGY: none so its
    // get_sources reuses this tree — the git token never enters the guest. With
    // checkout_overlay (the default) the share is exported read-only and the guest
    // builds on an overlay above it; checkout_overlay = false exports it read-write,
    // which is added attack surface toward an untrusted guest.
    if let Some(gl) = cfg.gitlab.as_ref().filter(|g| g.host_checkout) {
        let overlay = gl.checkout_overlay;
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

        if !crate::vmm::libkrun_selected() {
            let mut vfsd = cfg.virtiofsd_command();
            vfsd.arg(format!("--socket-path={}", sock.display()))
                .arg(format!("--shared-dir={}", host_dir.display()))
                .args(["--cache=auto", "--sandbox=none"]);
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
            uid_map,
            gid_map,
        });
        cmdline.push_str(&checkout_virtiofs_cmdline(
            mount,
            overlay,
            checkout_overlay_size(&gl.checkout_overlay_size)?,
        ));
    }

    // [gitlab] atop: this job's statistics archive (created by prepare), shared
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
                uid_map: Vec::new(),
                gid_map: Vec::new(),
            });
            cmdline.push_str(&vk_core::atop::cmdline_knob(crate::atop::interval_secs(
                cfg,
            )?));
        }
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
            // Per-job userspace switch: no virtio-net device and no kernel `ip=`
            // (eth0 does not exist at kernel init) — the in-guest agent forks a
            // tap bridged to the switch over vsock, then sets a static address.
            // Spawn the switch (with the egress allowlist) so it is listening
            // before the guest dials it; then point the agent at it. The same
            // shared LAN/egress core `run --compose` uses.
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
            children.push(spawn_switch(ctx, gateway, prefix, guest_ip, &services)?);
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
            cmdline.push_str(&format!(
                " VIRTKIT_NET_PORT={} VIRTKIT_VM_IP={guest_ip}/{prefix} \
                 VIRTKIT_VM_GW={gateway} VIRTKIT_VM_DNS={gateway}",
                cfg.net.net_port
            ));
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
    if !cfg.guest.tmpfs.is_empty() {
        // lands on the kernel cmdline: a space or comma in an entry would split
        // or corrupt the VIRTKIT_TMPFS list the agent parses
        for entry in &cfg.guest.tmpfs {
            if !entry.starts_with('/')
                || !entry.contains(':')
                || entry.contains(|c: char| c.is_whitespace() || c == ',')
            {
                bail!("invalid guest.tmpfs entry {entry:?} (want \"/path:size\")");
            }
        }
        cmdline.push_str(&format!(" VIRTKIT_TMPFS={}", cfg.guest.tmpfs.join(",")));
    }

    // SSH-agent forwarding ([auth] ssh_agent): tell the guest agent to present
    // SSH_AUTH_SOCK and relay it over a vsock port to the host side (the forward from
    // ssh_agent_forward_command, started by the supervisor). A no-op if the runner has
    // no agent — warn so a misconfig is visible.
    if ssh_agent_forwarding(cfg) {
        cmdline.push_str(&format!(
            " VIRTKIT_SSH_AGENT_PORT={}",
            crate::run::SSH_AGENT_VSOCK_PORT
        ));
    } else if cfg.auth.ssh_agent {
        eprintln!("virtkit: [auth] ssh_agent set but SSH_AUTH_SOCK is unset — not forwarding");
    }

    if !cfg.vm.cmdline_extra.is_empty() {
        cmdline.push(' ');
        cmdline.push_str(&cfg.vm.cmdline_extra);
    }

    // kernel is common; the boot medium is the CoW disk overlay plus a
    // self-booting image's initrd. A generic guest on the pinned kernel ships
    // no initrd (virtio-blk + ext4 built in).
    let disks = vec![crate::vmm::Disk::overlay(overlay.clone())];

    // shared=on (set via shared_mem): required by virtio-fs, harmless without.
    // vsock ports the guest uses: the exec channel always, plus the switch bridge in
    // `switch` net mode (guest egress over the userspace switch) and the ssh-agent
    // bridge when agent forwarding is on. Tap/pool networking uses a virtio-net device,
    // not vsock. Only the libkrun backend consumes this; cloud-hypervisor derives it.
    let mut vsock_ports = vec![crate::vmm::VsockPort::exec(
        &ctx.vsock_sock(),
        cfg.vm.vsock_port,
    )];
    if cfg.net.mode == "switch" {
        vsock_ports.push(crate::vmm::VsockPort::bridge(
            &ctx.vsock_sock(),
            cfg.net.net_port,
        ));
    }
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
        balloon: cfg.vm.balloon,
        serial_log: ctx.console_log(),
        // an image (stock) kernel keeps serial via the VIRTKIT_KERNEL=image cmdline token;
        // the executor has no BYO-kernel flag, so nothing forces it otherwise.
        console_serial: false,
        pmu: false,
        // `[vm] nested`, the runner's grant (checked against the host in prepare), ORed
        // with the compose primary's own marker exactly as `vk run` does it. The grant is
        // what let that marker past `refuse_job_nesting`, so today the OR only ever agrees
        // with the grant — it is here so the two paths cannot drift apart.
        nested: crate::run::effective_nested(cfg.vm.nested, primary_nested),
        // libkrun has no API socket (it is driven as a subprocess); cloud-hypervisor
        // uses one for graceful shutdown in graceful_vmm_stop.
        api_socket: (!crate::vmm::libkrun_selected()).then(|| ctx.api_sock()),
        pass_fds: Vec::new(),
        // The CI job runs in its own process (no `--vm-name`), so the default template
        // applies: `vk:<hostname>`.
        proc_name: crate::vmm::resolve_proc_name(&cfg.vm.hostname),
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
                for mut c in children {
                    let _ = c.kill();
                    let _ = c.wait();
                }
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                if let Some(status) = vmm_child.try_wait()? {
                    for mut c in children {
                        let _ = c.kill();
                        let _ = c.wait();
                    }
                    bail!("{} exited ({status})", vmm.name());
                }
                // any owned helper dying (the switch, a service VM, a virtiofsd,
                // a forward) leaves a broken job: fail loudly rather than limp.
                for c in &mut children {
                    if let Some(status) = c.try_wait()? {
                        graceful_vmm_stop(ctx, &mut vmm_child);
                        for mut c in children {
                            let _ = c.kill();
                            let _ = c.wait();
                        }
                        bail!("a supervised helper exited ({status}) — job torn down");
                    }
                }
            }
        }
    }
}

/// SSH-agent forwarding is on when `[auth] ssh_agent` is set AND the runner actually has an
/// agent (`$SSH_AUTH_SOCK`). The guest side is driven by the cmdline var; the host side is
/// the forward started below.
fn ssh_agent_forwarding(cfg: &crate::config::Config) -> bool {
    cfg.auth.ssh_agent && std::env::var_os("SSH_AUTH_SOCK").is_some()
}

/// Host side of the SSH-agent forward ([auth] ssh_agent): the guest dials vsock
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
    for (slot, mut unit) in units.into_iter().enumerate() {
        // A compose service's declared sizing obeys the same host ceilings as the job's own.
        clamp_service_size(&ctx.cfg, &mut unit)?;
        let prov = match service_media(&unit.source) {
            ServiceMedia::Git(spec) => {
                let (ext4, config, guard) =
                    build_git_image(ctx, spec).with_context(|| format!("service {}", unit.name))?;
                guards.push(guard);
                let merged = crate::compose::merged_config(&config.unwrap_or_default(), &unit);
                crate::units::provisioned(&unit, ext4, merged, gateway, prefix, slot as u32)?
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
                crate::units::provisioned(&unit, ext4, config, gateway, prefix, slot as u32)?
            }
            ServiceMedia::Image => {
                let prov = crate::units::provision(
                    &ctx.cfg,
                    ctx.cfg.state_dir(),
                    &[],
                    &unit,
                    gateway,
                    prefix,
                    slot as u32,
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
    // Each listen socket is bound to its VM's assigned address so the switch can trust the
    // source of a frame (see switch.rs): the primary at `guest_ip`, each service at its addr.
    let mut listen = vec![(ctx.net_vsock_sock(cfg.net.net_port), guest_ip)];
    let mut hosts = Vec::new();
    let mut reservations = Vec::new();
    for svc in services {
        let socket = ctx
            .job_dir
            .join(format!("svc-{}", svc.name))
            .join(format!("vsock.sock_{}", cfg.net.net_port));
        listen.push((socket, svc.addr));
        let ip = svc.ip.split('/').next().unwrap_or_default();
        hosts.push((svc.hostname.clone(), ip.to_string()));
        if let Ok(ip4) = ip.parse::<Ipv4Addr>() {
            reservations.push((crate::units::mac_for_ip(ip4), ip.to_string()));
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

/// Effective vCPU count and memory size: the job's MICROVM_CPUS/MICROVM_MEM
/// requests, silently clamped to the host ceilings (vm.max_cpus/max_mem,
/// defaulting to the base values — config opt-in for any elevation).
fn vm_size(ctx: &JobCtx) -> Result<(u32, String)> {
    let vm = &ctx.cfg.vm;
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
            // `[schedule] mem_budget` is a host ceiling like the others: a request above the
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
/// (`[vm] nested`). Nesting widens the guest's attack surface on host KVM (see
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
             reaches host KVM, so `[vm] nested` is the host admin's grant to make, not a job's",
            unit.name
        );
    }
    Ok(())
}

/// `[vm] nested` on a host whose KVM will not nest boots a job guest that advertises VMX/SVM
/// and cannot use it, so the jobs counting on it fail deep inside themselves instead of at
/// the misconfiguration. Refused in `prepare`, whose error reaches the job trace, rather than
/// in the detached supervisor's log.
pub(crate) fn refuse_unsupported_nesting(requested: bool, host_nests: bool) -> Result<()> {
    if requested && !host_nests {
        bail!(
            "[vm] nested is set but this host does not allow nesting — load kvm_intel or \
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
    let vm = &cfg.vm;
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
        // `[schedule] mem_budget` is a host ceiling like the others (see `vm_size`): a service
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

/// The guest RAM this job declares, in MiB: `MICROVM_MEM` clamped by the host ceilings, the
/// figure a reservation is capped at and the job's history is read against.
pub(crate) fn declared_mem_mib(ctx: &JobCtx) -> Result<u64> {
    parse_gib(&vm_size(ctx)?.1)?
        .checked_mul(1024)
        .context("guest memory size is absurdly large")
}

/// Reserve this job's guest RAM against the host's `[schedule] mem_budget`, blocking until
/// there is room for it (see admit). `None` when no budget is configured — the host then
/// admits every job the runner hands it, as it did before. A job that never gets room fails
/// prepare, which exits `SYSTEM_FAILURE_EXIT_CODE`: a system failure, not the job's fault.
fn admit_memory(ctx: &JobCtx, mem: &str) -> Result<Option<crate::admit::Reservation>> {
    let Some(budget) = budget_mib(&ctx.cfg) else {
        return Ok(None);
    };
    let budget_mib = budget?;
    let timeout = Duration::from_secs(ctx.cfg.schedule.wait_timeout_secs.unwrap_or(600));
    let declared_mib = parse_gib(mem)
        .context("invalid guest memory size")?
        .checked_mul(1024)
        .context("guest memory size is absurdly large")?;
    // `[schedule] from_history`: reserve what this job has been using rather than what it
    // declares. Announced, because it is the difference between a job waiting and not.
    let want_mib = match ctx.cfg.schedule.from_history {
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
    let reservation =
        crate::admit::acquire(&ctx.admit_dir(), &ctx.job_id, want_mib, budget_mib, timeout)?;
    Ok(Some(reservation))
}

/// The host's `[schedule] mem_budget` in MiB, resolving a percentage against this host, for a
/// report that says there is no budget rather than inventing one. `None` when no budget is set,
/// `Some(Err(..))` when one is set that this host cannot resolve — it does not parse, or it is a
/// percentage and `/proc/meminfo` is unreadable — which the report has to tell apart, since a
/// budget it cannot resolve is one every job's prepare is already failing on, not the absence of
/// a budget. The error names the setting, so callers add no context of their own.
pub(crate) fn budget_mib(cfg: &crate::config::Config) -> Option<Result<u64>> {
    let raw = cfg.schedule.mem_budget.as_deref()?;
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
            .with_context(|| format!("cannot resolve [schedule] mem_budget {raw:?}")),
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
    // that budget plus margin before the hammer.
    let grace = Duration::from_secs(ctx.cfg.vm.shutdown_timeout_secs + 15);
    if !wait_gone(pid, &tag, grace) {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        wait_gone(pid, &tag, Duration::from_secs(3));
    }
}

/// Gracefully stop the supervisor's own VMM child: ACPI power-button over the API
/// socket, then vm.shutdown, then SIGTERM/SIGKILL — each step only if the previous
/// one did not end the process. libkrun has no API socket: TERM then KILL.
fn graceful_vmm_stop(ctx: &JobCtx, child: &mut std::process::Child) {
    let timeout = Duration::from_secs(ctx.cfg.vm.shutdown_timeout_secs);
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

    fn ctx(cpus_req: Option<&str>, mem_req: Option<&str>) -> JobCtx {
        let mut cfg = Config::default();
        cfg.vm.cpus = 4;
        cfg.vm.mem = "8G".into();
        cfg.vm.max_cpus = Some(16);
        cfg.vm.max_mem = Some("64G".into());
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

    #[test]
    fn checkout_virtiofs_cmdline_pins_the_agent_contract() {
        assert_eq!(
            checkout_virtiofs_cmdline("/builds/grp/proj", false, "80%"),
            " VIRTKIT_VIRTIOFS=cibuild:/builds/grp/proj",
            "a read-write checkout has no layer to size"
        );
        assert_eq!(
            checkout_virtiofs_cmdline("/builds/grp/proj", true, "80%"),
            " VIRTKIT_VIRTIOFS=cibuild:/builds/grp/proj VIRTKIT_VIRTIOFS_OVERLAY=cibuild \
             VIRTKIT_VIRTIOFS_OVERLAY_SIZE=80%"
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
        ctx.cfg.schedule.mem_budget = Some("48G".into());
        assert_eq!(vm_size(&ctx).unwrap().1, "48G");
        // The lower of the two ceilings wins whichever it is.
        ctx.cfg.schedule.mem_budget = Some("256G".into());
        assert_eq!(vm_size(&ctx).unwrap().1, "64G");
        // A job that asked for nothing keeps the configured default, budget or not.
        let mut plain = self::ctx(None, None);
        plain.cfg.schedule.mem_budget = Some("2G".into());
        assert_eq!(vm_size(&plain).unwrap().1, "8G");
    }

    /// A compose service's declared sizing obeys the same `[vm] max_*` ceilings a job's
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
        // a `[schedule] mem_budget` below `max_mem` is the effective ceiling: a service
        // sized above the whole budget could never boot healthily.
        let mut budgeted = self::ctx(None, None);
        budgeted.cfg.schedule.mem_budget = Some("32G".into());
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
        ctx.cfg.schedule.mem_budget = Some("48G".into());
        ctx.cfg.schedule.from_history = true;

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

    /// With no budget configured the gate is absent: nothing is claimed, and no ledger is
    /// created under the state dir.
    #[test]
    fn admission_is_absent_without_a_budget() {
        let dir = std::env::temp_dir().join(format!("vk-admit-off-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = Config {
            state_dir: Some(dir.clone()),
            ..Config::default()
        };
        let ctx = JobCtx::new_for_job(cfg, "42".into()).unwrap();
        assert!(ctx.cfg.schedule.mem_budget.is_none());
        assert!(admit_memory(&ctx, "8G").unwrap().is_none());
        assert!(!ctx.admit_dir().exists(), "no ledger without a budget");
        let _ = std::fs::remove_dir_all(&dir);
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
}
