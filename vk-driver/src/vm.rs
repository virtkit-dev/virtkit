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
}

impl Media {
    fn files(&self) -> Vec<&Path> {
        let mut v = vec![self.rootfs.as_path()];
        v.extend(self.initrd.as_deref());
        v
    }
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
/// share instead of mounting it directly.
fn checkout_virtiofs_cmdline(mount: &str, overlay: bool) -> String {
    let mut s = format!(" VIRTKIT_VIRTIOFS={CIBUILD_TAG}:{mount}");
    if overlay {
        s.push_str(&format!(" VIRTKIT_VIRTIOFS_OVERLAY={CIBUILD_TAG}"));
    }
    s
}

pub async fn prepare(ctx: &JobCtx) -> Result<()> {
    let cfg = &ctx.cfg;
    // Cheap fail-fast checks first (crisp errors in the runner-visible process beat a
    // supervisor-log pointer).
    if unsafe { libc::access(c"/dev/kvm".as_ptr(), libc::R_OK | libc::W_OK) } != 0 {
        bail!("no rw access to /dev/kvm (is the runner user in the kvm group?)");
    }
    let (cpus, mem) = vm_size(ctx)?;

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

    // [gitlab] host_checkout: check the sources out on the host NOW — before resolving the
    // image (a `dockerfile:`/`compose:` image is built from these sources) and before the
    // guest boots — so supervise can share the tree in and the git token never enters the
    // guest (the job sets GIT_STRATEGY: none). Crisp errors here (the runner-visible prepare)
    // beat a supervisor-log pointer; like any prepare failure a checkout error exits
    // system_failure.
    if cfg.gitlab.as_ref().is_some_and(|g| g.host_checkout) {
        let url = ctx
            .ci_repo_url
            .as_deref()
            .context("host_checkout is set but CI_REPOSITORY_URL is unset")?;
        let sha = ctx
            .ci_commit_sha
            .as_deref()
            .context("host_checkout is set but CI_COMMIT_SHA is unset")?;
        let dest = ctx.host_checkout_dir();
        println!("virtkit: host checkout of {sha} -> {}", dest.display());
        crate::checkout::ensure(url, ctx.ci_commit_ref.as_deref().unwrap_or(""), sha, &dest)
            .context("host checkout")?;
    }

    // Resolve (and, for a `dockerfile:` image, build) the boot media in the runner-visible process;
    // the supervisor re-resolves from the same env (a fingerprint hit for a build). A `None`
    // kernel boots vk's embedded copy — nothing to stat.
    let (kernel, media, _generic) = resolve_media(ctx)?;
    for p in media.files().into_iter().chain(kernel.as_deref()) {
        if !p.is_file() {
            bail!("image file missing: {}", p.display());
        }
    }

    // Warm any git-defined service images into the build tier NOW, alongside the primary — a
    // stage build is far slower than a boot, so building it here (rather than in supervise's
    // plan_services) keeps the guest boot within the runner's readiness budget. supervise then
    // just hits the fresh tier. Non-build services are left for supervise (a pull is quick).
    let image_ref = ctx.image_ref.as_deref().unwrap_or("local/default");
    if let Some(spec) = image_ref.strip_prefix("compose:") {
        for unit in compose_service_units(&load_compose_fleet(ctx, spec)?)? {
            if matches!(unit.source, crate::compose::Source::Build { .. }) {
                build_compose_unit(ctx, &unit).with_context(|| format!("service {}", unit.name))?;
            }
        }
    } else {
        for unit in crate::services::to_units(crate::services::from_env()?) {
            if let crate::compose::Source::Image(image) = &unit.source
                && let Some(spec) = image.strip_prefix("dockerfile:")
            {
                build_git_image(ctx, spec).with_context(|| format!("service {}", unit.name))?;
            }
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

    println!("virtkit: booting microVM (cpus={cpus}, mem={mem})");

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

/// Resolve MICROVM_IMAGE to the boot files: an optional kernel (`None` = boot vk's
/// embedded kernel), the rootfs + optional initrd, and whether it is a generic boot.
///
/// `MICROVM_IMAGE: dockerfile:<path>[#<stage>]` builds a **git-defined** image from the
/// host-side checkout into the shared build tier and boots that; any other form resolves
/// through the shared image cache (`resolve_ref`).
fn resolve_media(ctx: &JobCtx) -> Result<(Option<PathBuf>, Media, bool)> {
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
        } => Ok((
            kernel,
            Media {
                rootfs,
                initrd,
                config,
            },
            generic,
        )),
    }
}

/// The job's primary as a git-defined image (`MICROVM_IMAGE: dockerfile:<path>[?context=<dir>&arg=<N>=<V>][#<stage>]`):
/// build it and return it as generic-disk boot media (embedded kernel, agent + config riding
/// the preinit initramfs — the byte-clean model `vk build`/bundles use).
fn resolve_dockerfile_form(ctx: &JobCtx, spec: &str) -> Result<(Option<PathBuf>, Media, bool)> {
    let (rootfs, config) = build_git_image(ctx, spec)?;
    Ok((
        None,
        Media {
            rootfs,
            initrd: None,
            config,
        },
        true,
    ))
}

/// Build a git-defined image `<path>[?context=<dir>&arg=<N>=<V>][#<stage>]` from the host-side checkout into
/// the shared build tier and return its rootfs + captured runtime config. Shared by the job's
/// primary (`resolve_dockerfile_form`) and its git-defined services (`plan_services`). Requires
/// `[gitlab] host_checkout`: the Dockerfile + context are the checked-out sources. The context
/// defaults to the Dockerfile's directory; `?context=<dir>` overrides it. `--build-arg`s come
/// from `?arg=<NAME>=<VALUE>` parameters (repeatable).
fn build_git_image(
    ctx: &JobCtx,
    spec: &str,
) -> Result<(PathBuf, Option<vk_core::runcfg::RunConfig>)> {
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
    let stage_key = crate::build::target_stage_key(&dockerfiles, &contexts, &build_args, stage)
        .context("computing the git-defined image's stage fingerprint")?;
    let recipe = crate::ensure::BuildRecipe {
        dockerfiles,
        contexts,
        build_args,
        kernel: cfg.build.kernel.clone(),
        cloud_hypervisor: Some(cfg.cloud_hypervisor().to_path_buf()),
        agent: cfg.build.agent.clone(),
        cache_registry: cfg.build.cache_registry.clone(),
        cache_insecure: cfg.build.cache_insecure,
        cache_auth: crate::build::CacheAuth {
            ca_file: cfg.build.cache_ca_file.clone(),
            username: cfg.build.cache_username.clone(),
            password_file: cfg.build.cache_password_file.clone(),
            token_file: cfg.build.cache_token_file.clone(),
        },
    };
    let dir = crate::ensure::ensure_build_tier(
        cfg.state_dir(),
        cfg.image_cache_idle(),
        &recipe,
        stage,
        &stage_key,
        None,
    )
    .with_context(|| format!("building the git-defined image {spec:?}"))?;
    let rootfs = dir.join("runner.ext4");
    // The stage's Env/User captured by the build (applied at boot via the preinit initramfs).
    let config = std::fs::read_to_string(crate::build::config_sidecar(&rootfs))
        .ok()
        .and_then(|s| vk_core::runcfg::RunConfig::from_json(&s).ok());
    Ok((rootfs, config))
}

/// Resolve the job-controlled Dockerfile path against the checkout root, refusing to escape
/// it. Rejects an absolute path (`Path::join` would discard the base) and any `..`/root
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
}

/// Parse a `dockerfile:` image spec's body into a [`DockerfileSpec`]. Query before fragment,
/// URL-style: the `#` binds first, so a `?`-parameter placed after a `#` lands inside the stage
/// rather than being parsed. `<params>` are `&`-separated `key=value`: `context=<dir>` overrides
/// the build context (default: the Dockerfile's own directory) and `arg=<NAME>=<VALUE>`
/// (repeatable) supplies a `--build-arg`. Anything else — an unknown parameter, an empty or
/// repeated `context=`, or an `arg` missing its `=VALUE` — is rejected so a typo fails loudly
/// rather than silently building the wrong thing. A build-arg `VALUE` may itself contain `=`, but
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
            _ => bail!(
                "unknown dockerfile: parameter {kv:?} (expected context=<dir> or arg=NAME=VALUE)"
            ),
        }
    }
    Ok(DockerfileSpec {
        path,
        context,
        stage,
        build_args,
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
    let mut units = crate::compose::load_with_env(&file, &|name| {
        std::env::var(format!("CUSTOM_ENV_{name}")).ok()
    })?;
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
    // Confine every booting unit to the checkout: its `build:` context/Dockerfiles are
    // job-authored paths resolved on the host (outside the microVM boundary), so — like the
    // `dockerfile:` primary — they must not escape into another tenant's tree or the host. A
    // `volumes:` bind mount would punch a host path straight through the boundary into an
    // untrusted guest, so it is refused outright on the executor.
    let root = checkout
        .canonicalize()
        .with_context(|| format!("resolving the checkout {}", checkout.display()))?;
    for (i, unit) in units.iter_mut().enumerate() {
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
        if let crate::compose::Source::Build {
            context,
            dockerfiles,
            ..
        } = &mut unit.source
        {
            *context = confine_under(&root, context)?;
            for df in dockerfiles.iter_mut() {
                *df = confine_under(&root, df)?;
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
fn compose_unit_media(
    ctx: &JobCtx,
    unit: &crate::compose::Unit,
) -> Result<(Option<PathBuf>, Media, bool)> {
    match &unit.source {
        crate::compose::Source::Build { .. } => {
            let (rootfs, config) = build_compose_unit(ctx, unit)?;
            Ok((
                None,
                Media {
                    rootfs,
                    initrd: None,
                    config: Some(config),
                },
                true,
            ))
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
            Ok((
                kernel,
                Media {
                    rootfs,
                    initrd,
                    config,
                },
                generic,
            ))
        }
    }
}

/// Build a compose `build:` unit into the shared build tier (from the host checkout) and return
/// its rootfs + merged runtime config. The build wiring comes from `[build]` (embedded kernel/
/// agent by default); `--build-arg`s are the unit's own (from the compose file / its `.env`).
fn build_compose_unit(
    ctx: &JobCtx,
    unit: &crate::compose::Unit,
) -> Result<(PathBuf, vk_core::runcfg::RunConfig)> {
    let cfg = &ctx.cfg;
    // Held across the build: an embedded asset lives in a memfd whose /proc/self/fd path is
    // valid only while the handle is open, and the build is synchronous.
    let agent = crate::embed::resolve(crate::embed::Asset::Agent, cfg.build.agent.as_deref())?;
    let kernel = crate::embed::resolve(crate::embed::Asset::Kernel, cfg.build.kernel.as_deref())?;
    let build = crate::units::BuildOpts {
        // A compose unit's build args are its own (compose file / `.env`); there is no
        // executor-global build-arg channel.
        build_args: vec![],
        kernel: kernel.path.clone(),
        cloud_hypervisor: cfg.cloud_hypervisor().to_path_buf(),
        agent: agent.path.clone(),
        cache_registry: cfg.build.cache_registry.clone(),
        cache_insecure: cfg.build.cache_insecure,
        cache_auth: crate::build::CacheAuth {
            ca_file: cfg.build.cache_ca_file.clone(),
            username: cfg.build.cache_username.clone(),
            password_file: cfg.build.cache_password_file.clone(),
            token_file: cfg.build.cache_token_file.clone(),
        },
    };
    let ext4 = crate::units::build_unit_ext4(cfg.state_dir(), &build.build_args, unit)?;
    let config = crate::units::ensure_unit_build_sync(
        unit,
        cfg.state_dir(),
        cfg.image_cache_idle(),
        &build,
        None,
    )?;
    Ok((ext4, config))
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
    let (kernel_opt, media, generic) = resolve_media(ctx)?;
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
    let mut use_guards: Vec<crate::image::UseGuard> = Vec::new();
    if let Some(g) = crate::image::acquire_use_lock_for(cfg.state_dir(), &media.rootfs)? {
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
        cmdline.push_str(&checkout_virtiofs_cmdline(mount, overlay));
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
            let services = plan_services(ctx, gateway, prefix)?;
            // Reference each service's shared base for the job's life, like the primary above.
            for svc in &services {
                if let Some(g) = crate::image::acquire_use_lock_for(cfg.state_dir(), &svc.ext4)? {
                    use_guards.push(g);
                }
            }
            // the switch binds each service's vsock socket at startup: the
            // runtime dirs must exist before it spawns.
            for svc in &services {
                std::fs::create_dir_all(ctx.job_dir.join(format!("svc-{}", svc.name)))
                    .with_context(|| format!("creating service dir for {}", svc.name))?;
            }
            children.push(spawn_switch(ctx, gateway, prefix, &services)?);
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
    let mut vmm_child = crate::run::spawn_vmm(&*vmm, &spec)
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
) -> Result<Vec<crate::units::Provisioned>> {
    let image_ref = ctx.image_ref.as_deref().unwrap_or("local/default");
    let units = match image_ref.strip_prefix("compose:") {
        Some(spec) => compose_service_units(&load_compose_fleet(ctx, spec)?)?,
        None => crate::services::to_units(crate::services::from_env()?),
    };
    let mut out = Vec::new();
    for (slot, unit) in units.into_iter().enumerate() {
        // A `dockerfile:` service (the CI_JOB_SERVICES form) builds from the checkout via the
        // tier; a compose `build:` unit and any plain image ref go through the shared provision
        // path (Build -> tier ext4, built up front by prepare's warm pass; Image -> resolve_ref).
        let git_spec = match &unit.source {
            crate::compose::Source::Image(image) => image.strip_prefix("dockerfile:"),
            _ => None,
        };
        let prov = if let Some(spec) = git_spec {
            let (ext4, config) =
                build_git_image(ctx, spec).with_context(|| format!("service {}", unit.name))?;
            let merged = crate::compose::merged_config(&config.unwrap_or_default(), &unit);
            crate::units::provisioned(&unit, ext4, merged, gateway, prefix, slot as u32)?
        } else {
            crate::units::provision(
                &ctx.cfg,
                ctx.cfg.state_dir(),
                &[],
                &unit,
                gateway,
                prefix,
                slot as u32,
            )?
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
    services: &[crate::units::Provisioned],
) -> Result<std::process::Child> {
    let cfg = &ctx.cfg;
    let mut listen = vec![ctx.net_vsock_sock(cfg.net.net_port)];
    let mut hosts = Vec::new();
    let mut reservations = Vec::new();
    for svc in services {
        listen.push(
            ctx.job_dir
                .join(format!("svc-{}", svc.name))
                .join(format!("vsock.sock_{}", cfg.net.net_port)),
        );
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
    crate::switch::spawn(&crate::switch::Spawn {
        listen,
        gateway,
        prefix,
        hosts,
        reservations,
        allow_ip: cfg.egress.allow_ip.clone(),
        allow_name: effective_allow_names(cfg, ctx)?,
        registry_proxy,
        log: ctx.switch_log(),
    })
    .context("spawning the per-job switch")
}

/// The switch `--allow-name` list for this job: the host `[egress]` cap by default,
/// or the job's `MICROVM_EGRESS_ALLOW_NAME` subset of it. The cap is host-only, so a
/// job can restrict its own egress (least privilege) but never widen it.
fn effective_allow_names(cfg: &crate::config::Config, ctx: &JobCtx) -> Result<Vec<String>> {
    match &ctx.egress_allow_name_req {
        None => Ok(cfg.egress.allow_name.clone()),
        Some(req) => narrow_allow_names(&cfg.egress.allow_ip, &cfg.egress.allow_name, req),
    }
}

/// Parse a space/comma separated `MICROVM_EGRESS_ALLOW_NAME` request and check each
/// name falls within the host `[egress]` cap, using the switch's own suffix
/// semantics. A name outside the cap is an error — the job cannot widen its egress.
///
/// The check is against the *full* host policy `Egress::new(allow_ip, allow_name)`,
/// not `allow_name` alone: the host egress is unrestricted only when both lists are
/// empty (`Egress::AllowAll`). An empty `allow_name` with a non-empty `allow_ip`
/// denies all names, so the job cannot add any — otherwise a job could append a name
/// to an IP-only cap and widen its egress.
fn narrow_allow_names(allow_ip: &[String], cap: &[String], req: &str) -> Result<Vec<String>> {
    let requested: Vec<String> = req
        .split([',', ' ', '\t', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let policy = crate::switch::Egress::new(allow_ip, cap)?;
    for name in &requested {
        if !policy.allows_host(name) {
            bail!(
                "MICROVM_EGRESS_ALLOW_NAME {name:?} is not within the host [egress] allow_name cap"
            );
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
            format!("{}G", req.min(max))
        }
    };
    Ok((cpus, mem))
}

/// "<n>G" (GiB) — the only size format the sizing variables accept
fn parse_gib(s: &str) -> Result<u64> {
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

/// Signal the job's supervisor and wait for it to go — everything it owns (the
/// switch, virtiofsds, forwards, the VMM after its graceful guest shutdown)
/// follows, by its TERM handler or by PDEATHSIG. Idempotent: tolerates a missing
/// or stale pidfile (the job-dir cmdline tag guards against pid reuse).
pub fn stop_supervisor(ctx: &JobCtx) {
    let Some(pid) = read_pidfile(&ctx.supervisor_pidfile()) else {
        return;
    };
    let tag = ctx.job_dir.to_string_lossy().into_owned();
    if !pid_running(pid, &tag) {
        return;
    }
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
fn wait_child_gone(child: &mut std::process::Child, timeout: Duration) -> bool {
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
    fn checkout_virtiofs_cmdline_pins_the_agent_contract() {
        assert_eq!(
            checkout_virtiofs_cmdline("/builds/grp/proj", false),
            " VIRTKIT_VIRTIOFS=cibuild:/builds/grp/proj"
        );
        assert_eq!(
            checkout_virtiofs_cmdline("/builds/grp/proj", true),
            " VIRTKIT_VIRTIOFS=cibuild:/builds/grp/proj VIRTKIT_VIRTIOFS_OVERLAY=cibuild"
        );
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

    #[test]
    fn per_job_allow_name_narrows_within_cap() {
        let cap = vec!["corp.example.com".to_string(), "github.com".to_string()];
        // a subset (exact + under a suffix) is accepted, returned as the job's set
        assert_eq!(
            narrow_allow_names(&[], &cap, "gitlab.corp.example.com, github.com").unwrap(),
            vec![
                "gitlab.corp.example.com".to_string(),
                "github.com".to_string()
            ]
        );
        // a name outside the cap fails the job (no widening)
        assert!(narrow_allow_names(&[], &cap, "pypi.org").is_err());
        assert!(narrow_allow_names(&[], &cap, "gitlab.corp.example.com pypi.org").is_err());
        // both caps empty = unrestricted host egress (AllowAll), so any name is within it
        assert_eq!(
            narrow_allow_names(&[], &[], "anything.example").unwrap(),
            vec!["anything.example".to_string()]
        );
        // an IP-only cap (allow_ip set, allow_name empty) allows NO names: the host
        // permits no name egress, so a job cannot add one and widen past the cap.
        let ip_cap = vec!["10.0.0.0/8".to_string()];
        assert!(narrow_allow_names(&ip_cap, &[], "evil.example").is_err());
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
}
