//! Bringing the environment up: what a boot is made of, and who is already doing it.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::dev::config::{CheckoutMode, Cpus, Freshness};
use crate::dev::plan::{Plan, Source};

use super::hooks::{Where, check_requirements, note_lock, run_hook};
use super::identity::{
    LeftBehind, NotReady, VmTie, applied_on_attach, claim_not_ready, clear_not_ready, drift,
    identity_of, identity_path, left_behind, live_identity, note_older_creator, read_not_ready,
    sha256_hex, try_read_identity,
};
use super::session::{ask_on_terminal, on_terminal, running_vm};
use super::{GENERATION_MARKER, INFLIGHT_POLL, Identity, Overrides, TRANSITION_WAIT, Transition};

/// Shared stop timeout for refresh and the default `vk dev stop --timeout`, in seconds.
pub(super) const STOP_TIMEOUT_SECS: u64 = 10;

/// Restart stop timeout in seconds; tests wait only one second for an unresponsive stand-in.
const SWAP_STOP_SECS: u64 = if cfg!(test) { 1 } else { STOP_TIMEOUT_SECS };

/// The state dir, created private. Everything in it is host-owned — keys, the host-command
/// allowlist, this identity — so it is 0700 from the moment it exists. The managed storage
/// the config mounts from under it is created too, before any mount resolves, so a first
/// boot and a refreshed one find the same directories.
pub(super) fn ensure_state_dir(plan: &Plan) -> Result<()> {
    if !plan.state_dir.is_dir() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&plan.state_dir)
            .with_context(|| format!("creating {}", plan.state_dir.display()))?;
    }
    for dir in &plan.managed_dirs {
        if !dir.is_dir() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .create(dir)
                .with_context(|| format!("creating {}", dir.display()))?;
        }
        mark_generation(dir)?;
    }
    Ok(())
}

/// Write that token, once. A directory the boot has just created gets a fresh one and keeps
/// it across every later boot; a `vk dev storage reset` removes the directory, so the next
/// boot writes another — which is how the `create` hook that populated it learns it has to
/// run again. Never rewritten: the token identifies the directory's contents, not the boot.
fn mark_generation(dir: &Path) -> Result<()> {
    let path = dir.join(GENERATION_MARKER);
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("creating {}", path.display())),
    };
    file.write_all(generation_token().as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

/// A token no other directory has: 16 bytes of `/dev/urandom`, hex — the clock and this pid
/// where that cannot be read. What matters is that a recreated directory gets a different
/// one, not that it is unguessable.
fn generation_token() -> String {
    use std::io::Read;

    let mut bytes = [0u8; 16];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .is_ok()
    {
        return bytes.iter().map(|b| format!("{b:02x}")).collect();
    }
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("{since_epoch}-{}", std::process::id())
}

/// The file the child leaves for its parent to say whether this invocation actually booted
/// the VM. Keyed by the parent's pid, so concurrent invocations never read each other's.
fn transition_path(state_dir: &Path, parent_pid: u32) -> PathBuf {
    state_dir.join(format!(".transition.{parent_pid}"))
}

/// Put the host-exec allowlist into the state dir and return it and its digest.
///
/// The guest can write the workspace, so the wrapper it is *checked against* must not be the
/// copy that lives there: a guest that could edit the dispatcher would be choosing what runs
/// on the host. A project wrapper is opened `O_NOFOLLOW` and read through that one
/// descriptor — a symlink the guest planted to redirect the host is refused, and no second
/// path resolution races the open; a built-in policy is generated here instead, its text naming
/// this vk and this workspace so either one moving reads as drift. Both are published by
/// rename, so the running server never sees a partial file. 0500: the host executes it,
/// nothing writes it.
fn snapshot_wrapper(plan: &Plan) -> Result<Option<(PathBuf, String)>> {
    let Some(host_exec) = &plan.host_exec else {
        return Ok(None);
    };
    let body = match &host_exec.builtin {
        Some(policy) => builtin_wrapper(plan, policy)?.into_bytes(),
        None => read_wrapper(&host_exec.wrapper)?,
    };

    let dest = plan.state_dir.join("host-exec-wrapper");
    let tmp = plan.state_dir.join(".host-exec-wrapper.tmp");
    // Clear a temp a killed run left behind; there is usually none, and a removal that
    // fails is reported by the `create_new` below, which then refuses to open it.
    let _ = std::fs::remove_file(&tmp);
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    out.write_all(&body)?;
    out.sync_all()?;
    drop(out);
    std::fs::rename(&tmp, &dest).with_context(|| format!("publishing {}", dest.display()))?;
    Ok(Some((dest, sha256_hex(&body))))
}

/// The one-line script a built-in policy is: it hands the guest's argv straight to the
/// hidden `vk host-policy`, which is where the policy actually lives. The on-disk path of
/// this vk, not `/proc/self/exe` — the script outlives this process, and the host runs it
/// from a shell of its own.
///
/// Both paths go into the script as text, so a path this host does not spell in UTF-8 is
/// refused: replacing the bytes it cannot encode would name a *different* file, and the
/// host would run whatever that turned out to be.
fn builtin_wrapper(plan: &Plan, policy: &str) -> Result<String> {
    let vk = std::env::current_exe().context("locating this vk on disk")?;
    Ok(format!(
        "#!/bin/sh\nexec {} host-policy {policy} --workspace {} -- \"$@\"\n",
        shell_quote_utf8(&vk, "this vk's own path")?,
        shell_quote_utf8(&plan.workspace, "the workspace")?,
    ))
}

/// `path`, quoted for the shell, or an error naming `what` when it is not UTF-8.
fn shell_quote_utf8(path: &Path, what: &str) -> Result<String> {
    let text = path
        .to_str()
        .with_context(|| format!("{what} ({}) is not valid UTF-8", path.display()))?;
    Ok(crate::shell::quote_word(text))
}

fn read_wrapper(path: &Path) -> Result<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    // O_NOFOLLOW: read the wrapper as the file it is, never through a symlink a guest that
    // can write the workspace planted to redirect the host at one of its choosing. The
    // metadata is then taken off this one descriptor, so no second path resolution races the
    // open.
    let source = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let meta = source.metadata()?;
    if !meta.is_file() {
        bail!("host.wrapper {} is not a regular file", path.display());
    }
    // The host runs this; one another user owns is not one this operator vouched for.
    if meta.uid() != unsafe { libc::geteuid() } {
        bail!("host.wrapper {} is not owned by this user", path.display());
    }
    if meta.permissions().mode() & 0o111 == 0 {
        bail!("host.wrapper {} is not executable", path.display());
    }
    let mut reader = source;
    let mut body = Vec::with_capacity(meta.len() as usize);
    std::io::Read::read_to_end(&mut reader, &mut body)?;
    Ok(body)
}

/// Convert the plan to `vk run` arguments, preserving CLI defaults for unspecified settings.
fn run_args(
    plan: &Plan,
    wrapper: Option<&Path>,
    over: &Overrides,
    cfg: &crate::config::Config,
    share: CheckoutMode,
) -> Result<crate::run::RunArgs> {
    let cpus = match plan.cpus {
        None => None,
        Some(Cpus::Host) => Some(
            std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .context("detecting the host CPU count")?,
        ),
        Some(Cpus::Count(n)) => Some(n),
    };
    // Where stages cache: this command, then the config, then `[build]` — the fall-through
    // `vk run` makes for itself, so an environment caches where every other build on this
    // host does instead of warming a store nothing else reads.
    let cache = crate::build::CacheOpts::resolve(
        over.cache_registry
            .as_deref()
            .or(plan.cache.registry.as_deref()),
        over.cache_insecure || plan.cache.insecure,
        &cfg.build,
    );
    let mut volumes = Vec::new();
    for m in &plan.mounts {
        if let Some(v) = crate::compose::parse_volume(&m.spec()?, &plan.workspace)? {
            volumes.push(v);
        }
    }
    // A linked worktree's `.git` is a file pointing at the real git dir somewhere else, so
    // a guest that only sees the workspace has a repository it cannot read. Mount that
    // directory at the path the pointer names, which is the only path git will look for.
    if let Some(dir) = worktree_git_dir(&plan.workspace) {
        let spec = format!("{}:{}", dir.display(), dir.display());
        if let Some(v) = crate::compose::parse_volume(&spec, &plan.workspace)? {
            volumes.push(v);
        }
    }
    let mut args = crate::run::RunArgs {
        workspace: Some(plan.workspace.clone()),
        state_dir: Some(plan.state_dir.clone()),
        // Egress, and for compose the LAN its services share.
        net: true,
        egress_allow: plan.egress.as_ref().map(|e| crate::switch::EgressFile {
            allow_ip: e.allow_ip.clone(),
            allow_name: e.allow_name.clone(),
        }),
        // Followed by the switch, so `vk dev up` can apply an edit to the lists in place.
        egress_file: plan
            .egress
            .as_ref()
            .map(|_| plan.state_dir.join(crate::dev::plan::EGRESS_FILE)),
        cpus,
        mem: plan.mem.clone(),
        env: plan
            .container_env
            .iter()
            .map(|e| (e.name.clone(), e.value.clone()))
            .collect(),
        cache,
        host_exec: wrapper.is_some(),
        host_exec_wrapper: wrapper.map(Path::to_path_buf),
        host_exec_env: plan
            .host_exec
            .as_ref()
            .map(|h| h.env.clone())
            .unwrap_or_default(),
        nested: plan.nests_here(),
        // The managed client is how `vk dev shell`, `vk dev code` and the editor reach it.
        ssh: true,
        ssh_client: true,
        ssh_alias: checked_alias(plan)?,
        ssh_user: plan.user.clone().unwrap_or_else(|| "root".into()),
        detach: true,
        detach_log: Some(plan.state_dir.join("boot.log")),
        ..Default::default()
    };
    match &plan.source {
        Source::Compose {
            file,
            service,
            profiles,
        } => {
            args.compose = Some(file.clone());
            args.primary = Some(service.clone());
            args.profiles = profiles.clone();
        }
        Source::Image { reference } => args.image = reference.clone(),
        Source::Build {
            context,
            dockerfile,
            target,
            args: build_args,
        } => {
            args.dockerfiles = vec![dockerfile.clone()];
            args.contexts = vec![context.clone()];
            args.target = target.clone();
            args.build_args = build_args.clone();
            // `cached-only`: the stage is restored or the run refuses, so nothing is ever
            // built behind a policy that says it must not be.
            args.require_cached = plan.cached_only;
        }
    }
    // A compose primary lives as long as its service's command; an image or build alone has
    // no command to live by, so the run keeps the VM until `vk dev stop`.
    if !matches!(plan.source, Source::Compose { .. }) {
        args.inactivity_timeout_secs = Some(0);
    }
    // Alone in its VM, the checkout reaches the guest only through the plan; a compose
    // service says where in its own `volumes:` (the plan requires `workspace` otherwise).
    if !matches!(plan.source, Source::Compose { .. })
        && let Some(folder) = &plan.workspace_folder
    {
        // `overlay`: the checkout goes in read-only under a tmpfs the guest writes to, so a
        // task can normalize files in place without touching the host tree.
        let spec = match share {
            CheckoutMode::Shared => format!("{}:{folder}", plan.workspace.display()),
            CheckoutMode::Overlay => format!("{}:{folder}:overlay", plan.workspace.display()),
        };
        if let Some(v) = crate::compose::parse_volume(&spec, &plan.workspace)? {
            volumes.push(v);
        }
    }
    args.volumes = volumes;
    Ok(args)
}

/// Where an ephemeral task's VM keeps its sockets and scratch:
/// `<readable>{-env}-task-<name>-<token>`, a sibling of the environment's own directory,
/// created here and removed by the caller once the run ends.
///
/// Named with a random token, not this pid, so a leaked directory is never adopted by a
/// later run the OS gives the same pid.
fn task_state_dir(plan: &Plan, task: &crate::dev::plan::TaskPlan) -> Result<PathBuf> {
    for _ in 0..8 {
        // Eight hex digits: the directory name goes into the VM's vsock socket path, which
        // must stay under the 108-byte `sun_path` limit; the full token would overrun it.
        let token: String = generation_token().chars().take(8).collect();
        let name = crate::dev::plan::task_state_dir_name(plan, &task.name, &token)?;
        let dir = plan.state_dir.with_file_name(name);
        // Fails if anything is already there, symlink included, so this run's directory is
        // one it made itself.
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_context(|| format!("creating {}", dir.display())),
        }
    }
    bail!(
        "no free state directory for task {} next to {}",
        task.name,
        plan.state_dir.display()
    )
}

/// The `vk run` an ephemeral task is: the environment's own arguments, minus everything that
/// belongs to an environment somebody works in — no SSH or managed client, no host command
/// channel, no endpoints, nothing detached and no idle wait — plus the command itself. The
/// VM lives exactly as long as that command, and the task's environment is added to the
/// guest's own, since the run has no session to carry `exec-env`.
///
/// The command runs as the image's own user: an ephemeral VM has no session, and the plan's
/// `user` is what sessions in a running environment log in as.
pub fn task_args(
    plan: &Plan,
    over: &Overrides,
    cfg: &crate::config::Config,
    task: &crate::dev::plan::TaskPlan,
    extra: &[String],
    target: Option<&str>,
    state_dir: Option<&Path>,
) -> Result<crate::run::RunArgs> {
    let mut args = run_args(plan, None, over, cfg, task.checkout)?;
    // A VM of its own needs a state directory of its own: the environment's may hold a live
    // run (an ephemeral task while the dev environment is up), and a throwaway must leave
    // nothing behind. A sibling of the environment's directory, so `vk dev list` shows one
    // that leaked as `ephemeral` and `vk dev gc` removes it.
    args.state_dir = Some(match state_dir {
        Some(dir) => dir.to_path_buf(),
        None => task_state_dir(plan, task)?,
    });
    args.ssh = false;
    args.ssh_client = false;
    // Tasks have no session or `[dev.ssh]` forwarding. Only the main-env boot resolves it;
    // clear these defensively even though they are already unset.
    args.ssh_allow_pub = None;
    args.ssh_guest_config = None;
    args.host_exec = false;
    args.host_exec_wrapper = None;
    args.host_exec_env.clear();
    args.detach = false;
    args.detach_log = None;
    args.inactivity_timeout_secs = None;
    // Tasks use a fixed allowlist and must not overwrite the file the running
    // environment's switch follows.
    args.egress_file = None;
    if let Some(t) = target {
        // The fallback stage, built because the configured one was not cached.
        args.target = Some(t.to_string());
        args.require_cached = false;
    }
    args.env.extend(
        plan.exec_env
            .iter()
            .chain(&task.env)
            .map(|e| (e.name.clone(), e.value.clone())),
    );
    let mut argv = task.argv.clone();
    argv.extend_from_slice(extra);
    // `vk run` has no working directory of its own for the guest command, so the task's is
    // spelled out — the workspace folder, as a session would get.
    args.command = match &plan.workspace_folder {
        Some(folder) => {
            let mut c = vec![
                "sh".to_string(),
                "-c".into(),
                format!("cd {} && exec \"$@\"", crate::shell::quote_word(folder)),
                "sh".into(),
            ];
            c.extend(argv);
            c
        }
        None => argv,
    };
    Ok(args)
}

/// The git directory a linked worktree points at, when the workspace is one and that
/// directory lies outside it. `None` for a main checkout — whose `.git` is inside the
/// workspace and already shared — and for anything git does not call a repository.
pub(super) fn worktree_git_dir(workspace: &Path) -> Option<PathBuf> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let dir = PathBuf::from(String::from_utf8(out.stdout).ok()?.trim());
    outside_workspace(workspace, dir)
}

/// The mount a common git dir needs, or `None` when it is already inside the workspace.
fn outside_workspace(workspace: &Path, git_dir: PathBuf) -> Option<PathBuf> {
    (!git_dir.starts_with(workspace)).then_some(git_dir)
}

/// [`alias`], with a state directory whose name this host does not spell in UTF-8 refused:
/// the alias is written into an ssh_config and passed to ssh as text, where the replacement
/// character would quietly name a different host.
fn checked_alias(plan: &Plan) -> Result<String> {
    plan.state_dir
        .file_name()
        .unwrap_or_default()
        .to_str()
        .with_context(|| {
            format!(
                "the state directory name ({}) is not valid UTF-8",
                plan.state_dir.display()
            )
        })?;
    Ok(alias(plan))
}

/// The ssh host alias for this environment. Derived from the state dir's own name, which is
/// already a readable workspace name plus a digest, so two workspaces never answer to one
/// alias and the name survives a reboot.
pub fn alias(plan: &Plan) -> String {
    alias_for(&plan.state_dir)
}

/// [`alias`], for the environment whose state directory is `state_dir`.
pub fn alias_for(state_dir: &Path) -> String {
    let name = state_dir
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "workspace".into());
    format!("vk-{name}")
}

/// What an `up` does about an environment that is running from a different configuration.
#[derive(Debug, PartialEq, Eq)]
enum Drifted {
    /// leave it alone and attach to it as recorded; the text says why
    Reuse(&'static str),
    /// rebuild and restart it into the configuration as it now reads
    Restart,
    /// refuse to do either: the policy is that a running environment matches its config
    Refuse,
}

/// Which of those the freshness policy asks for. `ask` is consulted only under
/// `freshness = ask`, and only when `terminal` says there is somebody to answer.
fn decide(
    freshness: Freshness,
    terminal: bool,
    ask: impl FnOnce() -> Result<bool>,
) -> Result<Drifted> {
    Ok(match freshness {
        Freshness::Reuse => Drifted::Reuse("freshness = reuse"),
        Freshness::RequireCurrent => Drifted::Refuse,
        Freshness::Refresh => Drifted::Restart,
        Freshness::Ask if !terminal => Drifted::Reuse("no terminal to ask on"),
        Freshness::Ask if ask()? => Drifted::Restart,
        Freshness::Ask => Drifted::Reuse("not rebuilding"),
    })
}

/// Explain why attaching keeps `running`'s recorded egress mode when `wanted` changes it:
/// only a restart replaces the switch. If both modes are restricted, list edits apply on attach.
fn egress_as_booted(
    running: &serde_json::Value,
    wanted: &serde_json::Value,
) -> Option<&'static str> {
    let restricted = |m: &serde_json::Value| m["egress"]["mode"] == "restricted";
    match (restricted(running), restricted(wanted)) {
        (false, true) => Some(
            "its egress stays unrestricted as booted — the config's allowlist applies only \
             from `vk dev refresh`",
        ),
        (true, false) => Some(
            "its egress stays restricted, to the allowlist last applied, until `vk dev refresh`",
        ),
        _ => None,
    }
}

/// Restart state after rebuilding (see [`after_build`]).
#[derive(Debug)]
enum AfterBuild {
    /// `targeted` is still running: stop this entry
    Stop(Box<crate::vms::VmEntry>),
    /// `targeted` survived a stop attempt; contains the unprinted report
    Stuck(String),
    /// nothing of `targeted` is up: boot, unless another boot holds the lock
    Clear,
    /// another VM replaced `targeted`: join the boot that brought it up
    Replaced(VmTie),
}

/// Compare the restart's `targeted` VM with the running VM, `now`.
/// `stopped` holds the unprinted report from an attempted stop of `targeted`.
fn after_build(
    targeted: VmTie,
    now: Option<crate::vms::VmEntry>,
    stopped: Option<String>,
) -> AfterBuild {
    match (now, stopped) {
        (None, _) => AfterBuild::Clear,
        (Some(vm), _) if VmTie::of(&vm) != targeted => AfterBuild::Replaced(VmTie::of(&vm)),
        (Some(_), Some(report)) => AfterBuild::Stuck(report),
        (Some(vm), None) => AfterBuild::Stop(Box::new(vm)),
    }
}

/// What [`swap`] leaves for [`boot`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Swap {
    /// the way is clear: boot
    Boot,
    /// joined another boot, its transition recorded: nothing left to boot
    Joined,
}

/// Rebuild for the current config, stop `targeted`, and check that a new VM can boot.
/// Return [`Swap::Joined`] after joining a replacement boot or finishing its setup:
/// nothing remains to boot. Reject ready replacements that [`serves`] says need a restart
/// for `wanted`, or unfinished replacements from another config: the drift policy already ran.
async fn swap(
    plan: &Plan,
    cfg: &crate::config::Config,
    over: &Overrides,
    wait: bool,
    parent_pid: u32,
    targeted: VmTie,
    wanted: Wanted<'_>,
) -> Result<Swap> {
    // Build first, with the current environment still up and usable: a build that fails
    // then costs only time, and the boot below restores what this just cached rather than
    // building it cold — seconds of downtime instead of minutes.
    eprintln!("virtkit: rebuilding while the current environment keeps running …");
    build_into_cache(plan, over, cfg, None)?;
    // During the build, the target may exit or another refresh or joiner may replace it.
    // Stop only the target; join any replacement boot below.
    let mut tried = false;
    // Defer a failed stop's report until rechecking: discard it if the target exited or
    // was replaced. A successful stop's report is already printed.
    let mut stopped = None;
    let state = loop {
        match after_build(targeted, running_vm(plan), stopped.take()) {
            AfterBuild::Stop(vm) => {
                // Left open: the targeted run dies and a replacement not yet registered takes
                // the lock, after `stop_entry` checks the holder or where procfs cannot name
                // it. The stale entry then reads as alive, and the stop ends the
                // replacement's relays and signals a dead pid.
                let Some((report, down)) = crate::vms::stop_entry(&vm, SWAP_STOP_SECS) else {
                    // Another run holds the lock, so the targeted one is gone even though its
                    // entry still reads as up: that run's boot is joined below.
                    break AfterBuild::Clear;
                };
                if down {
                    // Every other line of a boot goes to stderr, and this one runs in a child
                    // whose stdout the caller may have closed.
                    eprint!("{report}");
                    stopped = Some(String::new());
                } else {
                    stopped = Some(report);
                }
                tried = true;
            }
            AfterBuild::Stuck(report) => {
                eprint!("{report}");
                bail!("the dev environment did not stop; not booting a new one")
            }
            state => break state,
        }
    };
    let holder = lock_holder(&plan.state_dir);
    let replaced = match state {
        AfterBuild::Replaced(vm) => Some(vm),
        _ if holder.is_none() => {
            if !tried {
                eprintln!("virtkit: the environment went down during the rebuild — booting it");
            }
            // Relays cannot outlive their VM, but their records can, and so can the addresses
            // they hold until their next probe: left in place, the boot's own publishing would
            // take them for the relays it wants and leave its endpoints unpublished. A stop
            // that found the VM already gone cleared none, and clearing twice is harmless.
            // Nothing procfs can name holds the lock, and nothing is up, so there is no other
            // boot whose relays these could be.
            crate::publish::stop_all_quietly(&plan.state_dir, Duration::from_secs(5));
            return Ok(Swap::Boot);
        }
        _ => None,
    };
    // Another boot took over: its VM is up, or it holds the lock to boot one. This caller has
    // already restarted into its config, so what that boot readied is attached to only if it
    // serves this config, what it left not ready is taken over rather than restarted again,
    // and either from a different config is refused. A replacement already ready is judged
    // by its identity at once — nothing more is coming to wait for, `--no-wait` or not — and
    // one whose identity cannot be read never will be.
    let ready = match replaced {
        Some(vm) => match try_read_identity(plan) {
            Ok(Some(identity)) => Some(Joined::Ready { identity, vm }),
            Ok(None) => None,
            Err(e) => {
                return Err(e.context(
                    "the running environment's identity cannot be read — `vk dev stop` ends it",
                ));
            }
        },
        None => None,
    };
    // A replacement that is up has its `vk run` holding the lock whether or not procfs can
    // name it, so what this waits on is the VM, not a named holder.
    let joined = match ready.or_else(|| take_over(plan, parent_pid, wanted, false)) {
        Some(joined) => joined,
        None if !wait => bail!(
            "another boot of this environment{} took over while this one was rebuilding — \
             wait for that one, or re-run without --no-wait",
            holder.map(|h| format!(" ({h})")).unwrap_or_default()
        ),
        None => wait_for_boot(plan, parent_pid, wanted, false).await?,
    };
    let transition = after_takeover(joined, wanted)?;
    note_transition(plan, parent_pid, transition);
    Ok(Swap::Joined)
}

/// The transition after a restart joins a boot that took over during the rebuild.
/// Refuse a ready environment that [`serves`] says needs a restart for `wanted`.
/// Also refuse an environment left not ready from a different config.
fn after_takeover(joined: Joined, wanted: Wanted<'_>) -> Result<Transition> {
    Ok(match joined {
        Joined::Ready { identity, .. } => match serves(&identity, wanted) {
            Serves::Same | Serves::OnAttach => Transition::Reused,
            Serves::NeedsRestart => bail!("{}", readied_elsewhere(&identity, wanted.digest)),
        },
        Joined::Claimed => Transition::Booted,
        Joined::Drifted(left) => bail!("{}", refused(&left, wanted.digest)),
        // `restart` is false in `swap`, so neither call there returns this.
        Joined::Restart(_) => bail!(
            "the environment the boot that took over left needs a restart — re-run \
             `vk dev refresh`"
        ),
    })
}

/// The refusal when a boot that took over during the rebuild readied the environment from
/// a different configuration.
fn readied_elsewhere(running: &Identity, digest: &str) -> String {
    format!(
        "another boot of this environment took over while this one was rebuilding and \
         readied it from a different configuration (booted {}, now {}) — re-running \
         `vk dev refresh` reboots it into this one, or `vk dev stop` ends it",
        short(&running.digest),
        short(digest)
    )
}

/// Outcome of joining another caller's boot.
#[derive(Debug)]
enum Joined {
    /// the environment is ready: `identity` is what it recorded, `vm` the VM up when it was
    /// found
    Ready { identity: Identity, vm: VmTie },
    /// this caller took over failed or abandoned setup
    Claimed,
    /// failed or abandoned setup from another config, subject to the caller's drift policy
    /// if it has not already been applied
    Drifted(NotReady),
    /// a refresh restarts failed or abandoned setup regardless of its boot config, and a
    /// ready environment whose identity cannot be read, with the VM up when it was found
    Restart(VmTie),
}

/// The running VM's abandoned marker and its compatibility with `wanted` (see
/// [`left_behind`]). A live readier means a boot is in flight and returns `None`.
fn not_ready_here(plan: &Plan, wanted: Wanted<'_>) -> Option<(NotReady, LeftBehind)> {
    let left = read_not_ready(plan).filter(NotReady::abandoned)?;
    let running = running_vm(plan).map(|vm| VmTie::of(&vm));
    let how = left_behind(&left, running, wanted.digest, wanted.manifest)?;
    Some((left, how))
}

/// Claim the marker [`not_ready_here`] found for the parent `parent_pid`, saying so: `false`
/// when another caller got there first, or the marker is no longer one to claim.
fn claim(plan: &Plan, parent_pid: u32, wanted: Wanted<'_>) -> bool {
    let Some(left) = claim_not_ready(plan, parent_pid, |left| {
        let running = running_vm(plan).map(|vm| VmTie::of(&vm));
        left_behind(left, running, wanted.digest, wanted.manifest) == Some(LeftBehind::Claim)
    }) else {
        return false;
    };
    eprintln!(
        "virtkit: the environment is up but its last boot did not finish readying it ({}) — \
         doing that now",
        left.reason()
    );
    true
}

/// How an environment left not ready from another configuration is described.
fn not_ready_summary(left: &NotReady, digest: &str) -> String {
    format!(
        "the environment is up but its last boot did not finish readying it ({}), and it was \
         booted from a different configuration (booted {}, now {})",
        left.reason(),
        short(&left.digest),
        short(digest)
    )
}

/// The refusal for such an environment, where nothing restarts it.
fn refused(left: &NotReady, digest: &str) -> String {
    format!(
        "{} — `vk dev refresh` reboots it into this one, or `vk dev stop` ends it",
        not_ready_summary(left, digest)
    )
}

/// Take over an environment a failed or abandoned readying left behind, for the parent
/// `parent_pid`: [`Joined::Claimed`] once claimed, `None` when there is nothing to take over
/// or another caller claimed it first. One booted from another configuration is
/// [`Joined::Drifted`], for the caller's drift policy — not readied with this config, which
/// would record it as booted from a config it was not. With `restart`, a refresh's, either is
/// [`Joined::Restart`] instead: the caller restarts it.
fn take_over(plan: &Plan, parent_pid: u32, wanted: Wanted<'_>, restart: bool) -> Option<Joined> {
    match not_ready_here(plan, wanted)? {
        (left, _) if restart => Some(Joined::Restart(left.vm)),
        (_, LeftBehind::Claim) => claim(plan, parent_pid, wanted).then_some(Joined::Claimed),
        (left, LeftBehind::Drifted) => Some(Joined::Drifted(left)),
    }
}

/// Whether to restart an environment left not ready from another configuration: `Ok` to
/// restart it when the freshness policy's `decision` says so, an error for anything else.
/// Attaching to it as recorded, as for a drifted identity, is not on offer, since nothing
/// ready is recorded. A refresh restarts it without asking (see [`Joined::Restart`]).
fn restart_left_behind(
    decision: impl FnOnce() -> Result<Drifted>,
    left: &NotReady,
    digest: &str,
) -> Result<()> {
    match decision()? {
        Drifted::Restart => Ok(()),
        Drifted::Reuse(why) => bail!(
            "{}; {why}, but there is nothing ready to attach to — `vk dev refresh` reboots it \
             into this one, `vk dev stop` ends it",
            not_ready_summary(left, digest)
        ),
        Drifted::Refuse => bail!("{}", refused(left, digest)),
    }
}

/// The readable head of a digest. Taken by characters rather than bytes: these are read
/// back from `dev.json`, which a hand-edited or truncated file can make anything at all.
fn short(digest: &str) -> String {
    digest.chars().take(12).collect()
}

/// Config identity from [`identity_of`], used to judge running or left-behind environments.
#[derive(Debug, Clone, Copy)]
struct Wanted<'a> {
    digest: &'a str,
    manifest: &'a serde_json::Value,
}

/// How a running environment serves the wanted config (see [`serves`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Serves {
    /// booted from this very config
    Same,
    /// booted from one that differs only in what attaching applies (`exec-env`, editor
    /// settings, endpoints, tasks, the egress allowlist the running switch follows), none of
    /// which the running VM itself holds
    OnAttach,
    /// not without a restart
    NeedsRestart,
}

/// Whether `running` serves `wanted` without a restart.
fn serves(running: &Identity, wanted: Wanted<'_>) -> Serves {
    if running.digest == wanted.digest {
        Serves::Same
    } else if applied_on_attach(&drift(&running.manifest, wanted.manifest)) {
        Serves::OnAttach
    } else {
        Serves::NeedsRestart
    }
}

/// Whether a boot is a refresh, and how it came to the ready environment it targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refresh {
    /// not a refresh
    No,
    /// a refresh that found the environment ready on arrival
    Found,
    /// a refresh that waited for a boot in flight to ready the environment
    Joined,
}

/// Whether `all_fresh` finds all images current for the VM whose identity the waiter read.
/// Return `false` if that VM is gone or replaced. Refresh requires every image to be known
/// current (see [`crate::vms::all_fresh`]).
fn current_images_of(
    plan: &Plan,
    vm: VmTie,
    all_fresh: impl FnOnce(&crate::vms::VmEntry) -> bool,
) -> bool {
    running_vm(plan).is_some_and(|now| VmTie::of(&now) == vm && all_fresh(&now))
}

/// The action `up` takes for a ready environment.
#[derive(Debug, PartialEq, Eq)]
enum Live {
    /// Attach: the environment serves this config (see [`serves`]).
    Current { session_only: bool },
    /// Attach: a refresh joined the boot that started the VM, which readied it from this
    /// config and images matching the sources, so restarting it would only boot the same
    /// thing twice.
    JustBooted,
    /// The action when serving this config requires a restart.
    Decided(Drifted),
}

/// Choose an action for `running` given `wanted`. Refresh reuses only a joined boot that
/// started and readied the VM (see [`Identity::readied_by_its_boot`]), with the same digest
/// and images that `current_images` says match the sources. Merely matching [`serves`] is
/// insufficient. Outside refresh, attach when it serves the config or consult the
/// freshness `decision`.
fn live_decision(
    running: &Identity,
    wanted: Wanted<'_>,
    refresh: Refresh,
    current_images: impl FnOnce() -> bool,
    decision: impl FnOnce() -> Result<Drifted>,
) -> Result<Live> {
    match refresh {
        Refresh::No => {}
        Refresh::Joined
            if running.readied_by_its_boot
                && running.digest == wanted.digest
                && current_images() =>
        {
            return Ok(Live::JustBooted);
        }
        Refresh::Found | Refresh::Joined => return Ok(Live::Decided(Drifted::Restart)),
    }
    Ok(match serves(running, wanted) {
        Serves::Same => Live::Current {
            session_only: false,
        },
        Serves::OnAttach => Live::Current { session_only: true },
        Serves::NeedsRestart => Live::Decided(decision()?),
    })
}

/// The freshness policy for an environment booted from another configuration, `over` taking
/// precedence over the plan's.
///
/// Under `freshness = ask`, the question reaches the terminal because this child inherited
/// the parent's stdin and stderr and the parent is blocked reading the readiness pipe — the
/// `setsid` that detached it (in [`boot`]) cost it the controlling terminal, not the
/// descriptors. With no terminal there is nobody to answer, so the running environment
/// stands.
fn policy(plan: &Plan, over: &Overrides) -> Result<Drifted> {
    decide(
        over.freshness.unwrap_or(plan.freshness),
        on_terminal(),
        || ask_on_terminal("rebuild and restart it now?"),
    )
}

/// What [`attach_or_restart`] did about a ready environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attach {
    /// attached to it, the transition recorded
    Attached,
    /// left it for the caller to restart
    ToRestart,
}

/// Apply [`live_decision`] to `running`, whether found on arrival or after waiting: attach,
/// recording the transition, leave it to restart, or fail on refusal.
/// `announce_reuse` has the same meaning as in [`boot`], and `current_images` as in
/// [`live_decision`].
#[allow(clippy::too_many_arguments)]
fn attach_or_restart(
    plan: &Plan,
    over: &Overrides,
    refresh: Refresh,
    current_images: impl FnOnce() -> bool,
    announce_reuse: bool,
    parent_pid: u32,
    running: &Identity,
    wanted: Wanted<'_>,
) -> Result<Attach> {
    let decision = live_decision(running, wanted, refresh, current_images, || {
        policy(plan, over)
    })?;
    let summary = || {
        format!(
            "the running environment was booted from a different configuration (booted {}, \
             now {})",
            short(&running.digest),
            short(wanted.digest)
        )
    };
    match decision {
        Live::Current { session_only } => {
            if announce_reuse {
                eprintln!(
                    "virtkit: dev environment already running ({})",
                    plan.state_dir.display()
                );
                if session_only {
                    eprintln!(
                        "virtkit: its config changed only in what attaching applies (exec-env, \
                         editor, endpoints, tasks, egress allowlist) — no restart needed"
                    );
                }
                note_older_creator(running);
                // Its configuration still matches; the images it was built from may not.
                // Say so rather than leave a caller to find out, and leave the decision to
                // them.
                if let Some(vm) = running_vm(plan)
                    && crate::vms::freshness_all(&vm) == crate::vms::Freshness::Stale
                {
                    eprintln!(
                        "virtkit: its image no longer matches the sources — `vk dev refresh` \
                         rebuilds and restarts it"
                    );
                }
            }
        }
        // Only `vk dev refresh` gets here, so this prints regardless of `announce_reuse`, as
        // for `Drifted::Reuse`: a refresh that does not restart says why.
        Live::JustBooted => eprintln!(
            "virtkit: the boot this refresh waited for readied the environment from this \
             configuration and images matching the sources — not restarting it"
        ),
        Live::Decided(Drifted::Reuse(why)) => {
            eprintln!(
                "virtkit: {}; {why} — attaching to it as recorded, `vk dev refresh` applies \
                 the config",
                summary()
            );
            if let Some(note) = egress_as_booted(&running.manifest, wanted.manifest) {
                eprintln!("virtkit: {note}");
            }
            note_older_creator(running);
        }
        Live::Decided(Drifted::Refuse) => bail!(
            "{} — `vk dev refresh` reboots it into this one, `vk dev stop` ends it, or \
             `--freshness reuse` attaches to it as it is",
            summary()
        ),
        Live::Decided(Drifted::Restart) => return Ok(Attach::ToRestart),
    }
    note_transition(plan, parent_pid, Transition::Reused);
    Ok(Attach::Attached)
}

/// Boot the environment. Runs in the detached child (see the module docs): it returns only
/// when the VM stops, so anything that should happen once the guest is up belongs in
/// [`after_boot`](super::after_boot).
///
/// Reuse a running environment. `announce_reuse` prints the note for `vk dev up`;
/// `exec`, `shell`, `code`, `service up` and tasks suppress it to keep their output clear.
pub async fn boot(
    plan: &Plan,
    cfg: &crate::config::Config,
    over: &Overrides,
    refresh: bool,
    wait: bool,
    announce_reuse: bool,
    parent_pid: u32,
) -> Result<()> {
    plan.require_resolved()?;
    check_requirements(plan, cfg)?;
    note_lock(plan);
    ensure_state_dir(plan)?;
    // Whatever is at this boot's note path belongs to a run that is over: this one writes
    // its own below, and until it does there is nothing for the parent to read back.
    let _ = std::fs::remove_file(transition_path(&plan.state_dir, parent_pid));
    // Before the checks and the boot both: it runs on every attempt because what it
    // prepares — a generated file the build reads, a checked-out submodule — is what the
    // rest of this is about to look at.
    if let Some(hook) = &plan.hooks.init {
        run_hook(plan, "hooks.init", hook, Where::Host, &[]).await?;
    }
    let snapshot = snapshot_wrapper(plan)?;
    let (digest, manifest) = identity_of(plan, snapshot.as_ref().map(|(_, d)| d.as_str()))?;
    let wanted = Wanted {
        digest: &digest,
        manifest: &manifest,
    };
    let as_refresh = |how| if refresh { how } else { Refresh::No };

    if let Some((running, vm)) = live_identity(plan) {
        if attach_or_restart(
            plan,
            over,
            as_refresh(Refresh::Found),
            // Never judged: what a refresh finds ready on arrival, it restarts.
            || false,
            announce_reuse,
            parent_pid,
            &running,
            wanted,
        )? == Attach::Attached
        {
            return Ok(());
        }
        if swap(plan, cfg, over, wait, parent_pid, vm, wanted).await? == Swap::Joined {
            return Ok(());
        }
    } else if let Some(holder) = lock_holder(&plan.state_dir) {
        // Up with nothing recorded: a boot still readying it, which this waits for, or one
        // whose readying failed or was abandoned, which this takes over — found now or while
        // waiting. What that boot readies is then taken as if found on arrival, and one left
        // not ready from another configuration gets the freshness policy too; a refresh
        // restarts either, whatever it was booted from, and what it waited for unless that
        // boot started the VM itself and readied it from this config and current images.
        let joined = match take_over(plan, parent_pid, wanted, refresh) {
            Some(joined) => joined,
            None if !wait => bail!(
                "another boot of this environment is already in flight ({holder}); its \
                 output goes to the terminal that started it — wait for that one, or re-run \
                 without --no-wait"
            ),
            None => wait_for_boot(plan, parent_pid, wanted, refresh).await?,
        };
        // Keep the VM selected for restart so `swap` stops only that VM.
        let targeted = match joined {
            Joined::Ready {
                identity: running,
                vm,
            } => {
                if attach_or_restart(
                    plan,
                    over,
                    as_refresh(Refresh::Joined),
                    || current_images_of(plan, vm, crate::vms::all_fresh),
                    announce_reuse,
                    parent_pid,
                    &running,
                    wanted,
                )? == Attach::Attached
                {
                    return Ok(());
                }
                vm
            }
            Joined::Claimed => {
                note_transition(plan, parent_pid, Transition::Booted);
                return Ok(());
            }
            Joined::Restart(vm) => vm,
            Joined::Drifted(left) => {
                restart_left_behind(|| policy(plan, over), &left, wanted.digest)?;
                left.vm
            }
        };
        if swap(plan, cfg, over, wait, parent_pid, targeted, wanted).await? == Swap::Joined {
            return Ok(());
        }
    }

    note_transition(plan, parent_pid, Transition::Booted);
    // What was recorded describes an environment that is about to be replaced, and nothing
    // describes the new one until `after_boot` has it ready or leaves it marked not ready.
    // Removing both now is what a joining `vk dev` waits on (see `wait_for_boot`); a removal
    // that fails — including the first boot's, where there is no file — only leaves that
    // wait to time out, and a marker left in place names the VM being replaced, which no
    // joiner takes for this one.
    let _ = std::fs::remove_file(identity_path(plan));
    clear_not_ready(plan);
    // Remove any previous boot's allowlist on an unrestricted boot. A leftover file is
    // harmless: attaching rewrites it only when the recorded identity is restricted.
    if plan.egress.is_none() {
        let _ = std::fs::remove_file(plan.state_dir.join(crate::dev::plan::EGRESS_FILE));
    }
    let mut args = run_args(
        plan,
        snapshot.as_ref().map(|(p, _)| p.as_path()),
        over,
        cfg,
        CheckoutMode::Shared,
    )?;
    // Resolve `[dev.ssh]` here using the host agent and $HOME: forward the whole agent or
    // whitelisted keys and inject a matching guest ~/.ssh/config. Keep `run_args` pure so
    // builds and tasks that reuse it neither enumerate the agent nor write files.
    if let Some(ssh) = &plan.ssh {
        let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
        let upstream = std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from);
        let scratch = plan.state_dir.join("ssh-agent-allow");
        match crate::dev::sshsetup::resolve(ssh, &home, upstream.as_deref(), &scratch) {
            Ok((allow, guest_config, warnings)) => {
                for w in warnings {
                    eprintln!("virtkit: [dev.ssh] {w}");
                }
                args.ssh_allow_pub = allow;
                args.ssh_guest_config = guest_config;
            }
            Err(e) => eprintln!("virtkit: [dev.ssh] agent forwarding disabled: {e:#}"),
        }
    }
    crate::run::run(&args, cfg).await
}

/// Build the environment's images into the cache, running nothing.
///
/// The primary's, or — with `--service` — the named compose sibling's, the way
/// `vk dev service up` would build it on first use. Runs `hooks.init` first, since what it
/// prepares is what the build then reads, and works whether or not the environment is up. A
/// primary that boots a prebuilt image has nothing to build, so it runs neither.
pub async fn build(
    plan: &Plan,
    cfg: &crate::config::Config,
    over: &Overrides,
    service: Option<&str>,
) -> Result<()> {
    plan.require_resolved()?;
    ensure_state_dir(plan)?;
    // A prebuilt-image primary needs nothing from the init hook. Skip it to avoid
    // surprising a caller who only asked for a build.
    if service.is_none()
        && let Source::Image { reference } = &plan.source
    {
        eprintln!("virtkit: nothing to build — the environment boots {reference}");
        return Ok(());
    }
    if let Some(hook) = &plan.hooks.init {
        run_hook(plan, "hooks.init", hook, Where::Host, &[]).await?;
    }
    build_into_cache(plan, over, cfg, service)
}

/// Reuse the boot's [`run_args`], substituting a named service for the primary so it
/// uses the environment's cache and build arguments.
fn build_args(
    plan: &Plan,
    over: &Overrides,
    cfg: &crate::config::Config,
    service: Option<&str>,
) -> Result<crate::run::RunArgs> {
    let mut args = run_args(plan, None, over, cfg, CheckoutMode::Shared)?;
    if let Some(name) = service {
        if !matches!(plan.source, Source::Compose { .. }) {
            bail!(
                "--service needs a compose source; {} builds the environment's own image, \
                 which `vk dev build` builds without it",
                plan.config.display()
            );
        }
        args.primary = Some(name.to_string());
    }
    Ok(args)
}

/// Reject an unknown compose service and list the declared names. Otherwise an empty
/// selection would build only image services and appear to satisfy the request.
fn check_service(units: &[crate::compose::Unit], service: &str) -> Result<()> {
    if units.iter().any(|u| u.name == service) {
        return Ok(());
    }
    bail!(
        "--service {service:?}: no such compose service (declared: {})",
        units
            .iter()
            .map(|u| u.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Build the images needed by a boot or a service's first start into the cache, with no
/// export or other changes. Reuse the boot's [`run_args`] so it requests the same images
/// and cache and can restore these stages without rebuilding them.
fn build_into_cache(
    plan: &Plan,
    over: &Overrides,
    cfg: &crate::config::Config,
    service: Option<&str>,
) -> Result<()> {
    let args = build_args(plan, over, cfg, service)?;
    let agent = crate::embed::resolve(crate::embed::Asset::Agent, args.agent.as_deref())?;
    let kernel = crate::embed::resolve(crate::embed::Asset::Kernel, None)?;
    // No export path: a warm run leaves the stages in the cache, and the boot writes the
    // image it actually runs.
    let to_build = match &plan.source {
        Source::Compose { file, .. } => {
            // Build selection ignores backing paths, so leave `persist_anchor` unset.
            // Boot sets it via `run::compose_builtins`.
            let builtins =
                crate::compose::Builtins::resolve(Some(&plan.workspace), Some(&plan.state_dir))?;
            let units = crate::compose::load(file, Some(&builtins))?;
            if let Some(name) = service {
                check_service(&units, name)?;
            }
            let selected = crate::run::compose_build_selection(
                &units,
                &args.profiles,
                args.primary.as_deref(),
            )?;
            crate::run::compose_build_units(&args.build_args, &units, &selected, |_| None)
        }
        Source::Build {
            context,
            dockerfile,
            target,
            ..
        } => vec![crate::build::BuildUnit {
            label: target.clone().unwrap_or_else(|| "build".into()),
            input: crate::build::UnitInput::Build {
                dockerfiles: vec![dockerfile.clone()],
                contexts: vec![context.clone()],
                build_contexts: Vec::new(),
            },
            build_args: args.build_args.clone(),
            targets: vec![crate::build::TargetSpec {
                label: target.clone().unwrap_or_else(|| "build".into()),
                selector: target.clone(),
                out: None,
            }],
        }],
        // Nothing is built from an image; the boot pulls it.
        Source::Image { .. } => return Ok(()),
    };
    let opts = crate::run::service_build_options(&args, &kernel.path, &agent.path);
    crate::build::build_units(to_build, &opts)?;
    Ok(())
}

/// Who holds a state directory's lock, if anyone: the `vk` booting the environment or
/// holding its VM — which is also what tells an idle state directory from one somebody is
/// in the middle of using ([`crate::dev::list`] removes only the idle ones), and what a
/// second boot names instead of failing on the lock with nothing to say about whose it is.
///
/// Asked of `/proc/locks`, never by taking the lock: a probe that grabs it, even for the
/// instant it takes to drop it again, is one a real [`crate::run::lock_state_dir`] running at
/// that moment has to wait out (see [`crate::run::STATE_DIR_LOCK_GRACE`]), and this one runs
/// in a loop. The trade is that a holder
/// procfs cannot name — a lock over NFS, or a filesystem whose `st_dev` is not the
/// superblock device the file lists — reads here as nobody, and the boot that follows fails
/// on the lock itself as it did before this existed.
pub(crate) fn lock_holder(state_dir: &Path) -> Option<String> {
    // No state dir is no lock and so no boot in flight: this runs before `up` creates it.
    let f = std::fs::File::open(state_dir).ok()?;
    crate::run::flock_holder(&f)
}

/// How long a joined boot may sit with its VM up but nothing recorded before this gives up
/// on it. Generous: it covers the leader's endpoint publishing and its `hooks.start`.
const READY_WAIT: Duration = Duration::from_secs(300);

/// Wait for another boot's registered VM and the identity written once ready.
/// Return [`Joined::Ready`] for the caller to compare with its config as on arrival.
/// If setup fails or the parent dies, return [`take_over`]'s result for `wanted`, passing
/// `restart` through.
/// If another caller wins the claim, wait for its setup instead.
///
/// Waiting for the VM alone released this process while the boot's own parent was still
/// publishing endpoints and pushing the session environment — two writers doing the same
/// work at the same time.
async fn wait_for_boot(
    plan: &Plan,
    parent_pid: u32,
    wanted: Wanted<'_>,
    restart: bool,
) -> Result<Joined> {
    let mut announced = false;
    let mut up_since = None;
    let mut waited_on = None;
    loop {
        let vm = running_vm(plan).map(|vm| VmTie::of(&vm));
        let up = vm.is_some();
        // One read, since a restart may remove the identity between two. Absent, it is still
        // to come; written whole (see `write_identity`), one that does not parse or cannot be
        // read stays that way however long this waits.
        if let Some(vm) = vm {
            match try_read_identity(plan) {
                Ok(None) => {}
                Ok(Some(identity)) => return Ok(Joined::Ready { identity, vm }),
                // A refresh restarts what it joins, so it needs nothing that was recorded.
                Err(_) if restart => return Ok(Joined::Restart(vm)),
                Err(e) => {
                    return Err(e.context(
                        "the running environment's identity cannot be read — `vk dev stop` \
                         ends it",
                    ));
                }
            }
        }
        if up && let Some(joined) = take_over(plan, parent_pid, wanted, restart) {
            return Ok(joined);
        }
        if !announced {
            eprintln!("waiting for the boot already in flight …");
            announced = true;
        }
        // An up VM's `vk run` holds the lock, named or not — procfs cannot always say whose
        // it is (see `lock_holder`) — so only with nothing up does no holder mean no boot.
        if !up && lock_holder(&plan.state_dir).is_none() {
            bail!("the boot that was in flight ended without leaving a running environment");
        }
        // A readier that took over from another gets the whole budget for its own readying.
        let readier = read_not_ready(plan).and_then(|left| left.readier);
        if readier != waited_on {
            waited_on = readier;
            if let Some(since) = &mut up_since {
                *since = std::time::Instant::now();
            }
        }
        if up
            && up_since
                .get_or_insert_with(|| {
                    eprintln!(
                        "its VM is up; waiting for that boot to publish the endpoints and \
                         run hooks.start …"
                    );
                    std::time::Instant::now()
                })
                .elapsed()
                >= READY_WAIT
        {
            bail!(
                "the boot that was in flight brought the environment up but never recorded \
                 it as ready — `vk dev status` says where it stands"
            );
        }
        tokio::time::sleep(INFLIGHT_POLL).await;
    }
}

/// Leave the parent the note it reads back: what happened, which process says so, and this
/// invocation's nonce. The nonce is what makes the note *this* boot's — the file is named
/// after the parent's pid, which the operating system hands out again, so a note a killed
/// boot left behind would otherwise be read by whichever later invocation happened to be
/// forked by a process with the same pid.
fn note_transition(plan: &Plan, parent_pid: u32, transition: Transition) {
    let verb = match transition {
        Transition::Booted => "booted",
        Transition::Reused => "reused",
    };
    let body = format!(
        "{verb} {} {}\n",
        std::process::id(),
        crate::detach::boot_nonce()
    );
    // The parent reads an absent note as no transition (see `take_transition`), which is
    // the safe reading: nothing that only makes sense after a fresh boot runs on a guess.
    let _ = std::fs::write(transition_path(&plan.state_dir, parent_pid), body);
}

/// Read (and clear) what the child left, for the parent whose pid is `pid`. A note that is
/// missing — or that another invocation wrote — means this child never got as far as
/// saying, so treat it as no transition: nothing that only makes sense after a fresh boot
/// should run on a guess.
pub(super) async fn take_transition(plan: &Plan, pid: u32) -> Option<Transition> {
    let path = transition_path(&plan.state_dir, pid);
    let deadline = std::time::Instant::now() + TRANSITION_WAIT;
    loop {
        if let Ok(body) = std::fs::read_to_string(&path) {
            // Taken once, whatever it says: a note this run cannot use is a note nothing
            // else may pick up either.
            let _ = std::fs::remove_file(&path);
            let mut fields = body.split_whitespace();
            let verb = fields.next();
            // The pid is for whoever reads the file; the nonce is what is checked.
            let _child = fields.next();
            if fields.next() != Some(crate::detach::boot_nonce()) {
                return None;
            }
            return match verb {
                Some("booted") => Some(Transition::Booted),
                Some("reused") => Some(Transition::Reused),
                _ => None,
            };
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        // Yields rather than blocking: this runs on a runtime worker, and the wait is long
        // enough that parking one would hold up everything else `after_boot` has to do.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::config::Nested;
    use crate::dev::identity::marker_of;
    use crate::dev::plan::HostExecPlan;
    use crate::dev::testutil::{StandIn, plan_in, scratch};

    #[test]
    fn an_environment_caches_where_the_rest_of_the_host_caches() {
        let t = scratch("cache");
        let mut plan = plan_in(&t.0);

        // What the config asks for wins.
        plan.cache = crate::dev::config::Cache {
            registry: Some("127.0.0.1:5000/cache".into()),
            insecure: true,
        };
        let cfg = crate::config::Config::default();
        let args = run_args(
            &plan,
            None,
            &Overrides::default(),
            &cfg,
            CheckoutMode::Shared,
        )
        .unwrap();
        let opts = crate::run::service_build_options(&args, Path::new("/k"), Path::new("/a"));
        assert_eq!(opts.cache_registry.as_deref(), Some("127.0.0.1:5000/cache"));
        assert!(opts.cache_insecure);

        // Saying nothing falls through to `[build]`, the same answer `vk run` gets, with the
        // credentials that destination needs — not the local store nothing else reads.
        plan.cache = Default::default();
        let mut host = crate::config::Config::default();
        host.build.cache_registry = Some("registry.example/cache".into());
        host.build.cache_username = "ci".into();
        let args = run_args(
            &plan,
            None,
            &Overrides::default(),
            &host,
            CheckoutMode::Shared,
        )
        .unwrap();
        let opts = crate::run::service_build_options(&args, Path::new("/k"), Path::new("/a"));
        assert_eq!(
            opts.cache_registry.as_deref(),
            Some("registry.example/cache")
        );
        assert_eq!(opts.cache_auth.username, "ci");
    }

    #[test]
    fn the_wrapper_is_snapshotted_out_of_the_guests_reach() {
        let t = scratch("snapshot");
        let mut plan = plan_in(&t.0);
        std::fs::create_dir_all(&plan.workspace).unwrap();
        let source = plan.workspace.join("host-dispatch.sh");
        std::fs::write(&source, "#!/bin/sh\necho one\n").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755)).unwrap();
        plan.host_exec = Some(HostExecPlan {
            wrapper: source.clone(),
            builtin: None,
            env: vec![],
        });
        ensure_state_dir(&plan).unwrap();

        let (snapshot, digest) = snapshot_wrapper(&plan).unwrap().unwrap();
        assert!(
            snapshot.starts_with(&plan.state_dir),
            "not in the workspace the guest writes"
        );
        assert_eq!(
            std::fs::read_to_string(&snapshot).unwrap(),
            "#!/bin/sh\necho one\n"
        );
        assert_eq!(
            std::fs::metadata(&snapshot).unwrap().permissions().mode() & 0o777,
            0o500,
            "executable, and writable by nothing"
        );

        // Editing the source after the snapshot changes neither the copy the host runs nor
        // its digest until the next boot takes a new one.
        std::fs::write(&source, "#!/bin/sh\necho two\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&snapshot).unwrap(),
            "#!/bin/sh\necho one\n"
        );
        let (_, again) = snapshot_wrapper(&plan).unwrap().unwrap();
        assert_ne!(digest, again);

        // A source that is not an executable regular file is refused rather than snapshotted.
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(snapshot_wrapper(&plan).is_err());

        // A symlink planted where the wrapper is named — the redirection `O_NOFOLLOW` exists
        // to refuse — is not followed to whatever it points at.
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = plan.workspace.join("host-dispatch.link");
        std::os::unix::fs::symlink(&source, &link).unwrap();
        plan.host_exec.as_mut().unwrap().wrapper = link;
        let err = snapshot_wrapper(&plan).unwrap_err().to_string();
        assert!(err.contains("opening"), "{err}");
    }

    #[test]
    fn a_builtin_policy_generates_its_own_wrapper() {
        let t = scratch("snapshot-builtin");
        let mut plan = plan_in(&t.0);
        std::fs::create_dir_all(&plan.workspace).unwrap();
        plan.host_exec = Some(HostExecPlan {
            wrapper: plan.state_dir.join("host-exec-wrapper"),
            builtin: Some("git-gui".into()),
            env: vec![],
        });
        ensure_state_dir(&plan).unwrap();

        let (snapshot, digest) = snapshot_wrapper(&plan).unwrap().unwrap();
        let text = std::fs::read_to_string(&snapshot).unwrap();
        assert!(text.starts_with("#!/bin/sh\nexec "), "{text}");
        assert!(text.contains("host-policy git-gui --workspace "), "{text}");
        assert!(
            text.contains(&crate::shell::quote_word(&plan.workspace.to_string_lossy())),
            "{text}"
        );
        assert!(text.ends_with(" -- \"$@\"\n"), "{text}");

        // A moved workspace is a different wrapper, so the environment reports drift.
        plan.workspace = plan.workspace.join("elsewhere");
        let (_, moved) = snapshot_wrapper(&plan).unwrap().unwrap();
        assert_ne!(digest, moved);

        // A path this host does not spell in UTF-8 is refused rather than written into the
        // script with the offending bytes replaced — that would name another file.
        use std::os::unix::ffi::OsStrExt;
        plan.workspace = PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/w\xff"));
        let err = snapshot_wrapper(&plan).unwrap_err().to_string();
        assert!(err.contains("not valid UTF-8"), "{err}");
    }

    #[test]
    fn the_run_is_the_plan_and_nothing_else() {
        let t = scratch("runargs");
        let mut plan = plan_in(&t.0);
        plan.cpus = Some(Cpus::Count(4));
        plan.mem = Some("8G".into());
        plan.nested = Nested::Required;
        plan.source = Source::Compose {
            file: t.0.join("repo/compose.yaml"),
            service: "devcontainer".into(),
            profiles: vec!["runner".into()],
        };
        let cfg = crate::config::Config::default();
        let over = Overrides::default();
        let args = run_args(
            &plan,
            Some(Path::new("/state/wrapper")),
            &over,
            &cfg,
            CheckoutMode::Shared,
        )
        .unwrap();

        assert_eq!(
            args.compose.as_deref(),
            Some(t.0.join("repo/compose.yaml").as_path())
        );
        assert_eq!(args.primary.as_deref(), Some("devcontainer"));
        assert_eq!(args.profiles, ["runner"]);
        assert!(args.image.is_empty() && args.dockerfiles.is_empty());
        assert_eq!(args.state_dir.as_deref(), Some(plan.state_dir.as_path()));
        assert_eq!(args.workspace.as_deref(), Some(plan.workspace.as_path()));
        assert_eq!(args.cpus, Some(4));
        assert_eq!(args.mem.as_deref(), Some("8G"));
        assert!(
            args.nested,
            "required nesting is asked for whatever the host says"
        );
        assert!(args.net, "compose services need the run's LAN");
        assert!(
            args.inactivity_timeout_secs.is_none(),
            "the service's own command holds the VM"
        );
        // `[dev.ssh]` is resolved on the boot path, not in the pure `run_args`.
        assert!(args.ssh_allow_pub.is_none() && args.ssh_guest_config.is_none());
        assert!(
            args.volumes.is_empty(),
            "a compose service mounts the checkout itself"
        );
        assert!(
            args.ssh && args.ssh_client,
            "the managed client is how it is reached"
        );
        assert_eq!(args.ssh_user, "dev");
        assert!(
            args.detach,
            "a dev environment outlives the command that started it"
        );
        assert!(args.host_exec);
        assert_eq!(
            args.host_exec_wrapper.as_deref(),
            Some(Path::new("/state/wrapper"))
        );
        // Untouched by the config, and so left exactly as `vk run` would have it.
        let d = crate::run::RunArgs::default();
        assert_eq!(args.boot_timeout_secs, d.boot_timeout_secs);
        assert_eq!(args.vm_name, d.vm_name);
        assert_eq!(args.init, d.init);
        assert!(
            args.command.is_empty(),
            "the compose service's own command runs"
        );

        // `host` asks this machine what it has.
        plan.cpus = Some(Cpus::Host);
        assert_eq!(
            run_args(&plan, None, &over, &cfg, CheckoutMode::Shared)
                .unwrap()
                .cpus,
            Some(std::thread::available_parallelism().unwrap().get() as u32)
        );
        plan.cpus = None;

        // Alone in its VM, an image or build source gets the checkout mounted where the
        // config says, and the source spelled the way `vk run` takes it.
        plan.source = Source::Image {
            reference: "debian:13".into(),
        };
        let args = run_args(&plan, None, &over, &cfg, CheckoutMode::Shared).unwrap();
        assert_eq!(args.image, "debian:13");
        assert!(args.compose.is_none() && args.primary.is_none());
        assert_eq!(args.volumes.len(), 1);
        assert_eq!(args.volumes[0].host, plan.workspace);
        assert_eq!(args.volumes[0].guest, "/workdir");
        assert!(args.net, "an image alone still needs egress");
        assert_eq!(
            args.inactivity_timeout_secs,
            Some(0),
            "nothing runs in it to hold it, so the run does, until stopped"
        );
        plan.source = Source::Build {
            context: t.0.join("repo/docker"),
            dockerfile: t.0.join("repo/docker/Dockerfile"),
            target: Some("dev".into()),
            args: vec![("DEVUSER_UID".into(), "1000".into())],
        };
        let args = run_args(&plan, None, &over, &cfg, CheckoutMode::Shared).unwrap();
        assert_eq!(args.dockerfiles, [t.0.join("repo/docker/Dockerfile")]);
        assert_eq!(args.contexts, [t.0.join("repo/docker")]);
        assert_eq!(args.target.as_deref(), Some("dev"));

        // Egress is the host's unless the config restricts it; a restriction reaches the
        // switch as it was written, an empty one included (which denies everything).
        assert!(args.egress_allow.is_none() && args.egress_file.is_none());
        plan.egress = Some(crate::dev::plan::EgressPlan {
            mode: crate::dev::config::Egress::Restricted,
            allow_name: vec!["debian.org".into()],
            allow_ip: vec!["10.0.0.0/8".into()],
        });
        let args = run_args(&plan, None, &over, &cfg, CheckoutMode::Shared).unwrap();
        assert_eq!(
            args.egress_allow,
            Some(crate::switch::EgressFile {
                allow_ip: vec!["10.0.0.0/8".into()],
                allow_name: vec!["debian.org".into()],
            })
        );
        // … through a file in the state dir, which the switch follows for later edits.
        assert_eq!(
            args.egress_file,
            Some(plan.state_dir.join(crate::dev::plan::EGRESS_FILE))
        );
        plan.egress = Some(crate::dev::plan::EgressPlan {
            mode: crate::dev::config::Egress::Restricted,
            allow_name: vec![],
            allow_ip: vec![],
        });
        let args = run_args(&plan, None, &over, &cfg, CheckoutMode::Shared).unwrap();
        assert_eq!(
            args.egress_allow,
            Some(crate::switch::EgressFile::default())
        );
    }

    #[test]
    fn the_prebuild_and_the_boot_ask_for_the_same_images_and_cache() {
        // Warming is only worth anything if the boot then restores what it cached, so both
        // sides read their build inputs off one `RunArgs`. Compare what the build actually
        // receives, rather than trusting the two call sites to stay alike.
        let t = scratch("cache");
        let mut plan = plan_in(&t.0);
        plan.cache = crate::dev::config::Cache {
            registry: Some("127.0.0.1:5000/cache".into()),
            insecure: true,
        };
        let cfg = crate::config::Config::default();

        let args = run_args(
            &plan,
            None,
            &Overrides::default(),
            &cfg,
            CheckoutMode::Shared,
        )
        .unwrap();
        let opts = crate::run::service_build_options(&args, Path::new("/k"), Path::new("/a"));
        assert_eq!(opts.cache_registry.as_deref(), Some("127.0.0.1:5000/cache"));
        assert!(opts.cache_insecure);

        // The command line is the last word, over what the config says.
        let over = Overrides {
            cache_registry: Some("/var/cache/vk".into()),
            cache_insecure: false,
            freshness: None,
        };
        let args = run_args(&plan, None, &over, &cfg, CheckoutMode::Shared).unwrap();
        let opts = crate::run::service_build_options(&args, Path::new("/k"), Path::new("/a"));
        assert_eq!(opts.cache_registry.as_deref(), Some("/var/cache/vk"));
        // …and only over what it speaks about: the config still asked for plain HTTP.
        assert!(opts.cache_insecure);
    }

    #[test]
    fn a_service_build_targets_that_service_and_needs_a_compose_source() {
        let t = scratch("build");
        let mut plan = plan_in(&t.0);
        let cfg = crate::config::Config::default();
        let over = Overrides::default();

        // Nothing named: the primary, exactly as the boot builds it.
        let args = build_args(&plan, &over, &cfg, None).unwrap();
        assert_eq!(args.primary.as_deref(), Some("devcontainer"));

        // A service takes the primary's place, off the same compose file — so the sibling
        // builds against what the environment builds against.
        let args = build_args(&plan, &over, &cfg, Some("runner")).unwrap();
        assert_eq!(args.primary.as_deref(), Some("runner"));
        assert_eq!(
            args.compose.as_deref(),
            Some(t.0.join("repo/compose.yaml").as_path())
        );

        // An environment that is one image has no sibling to name.
        plan.source = Source::Image {
            reference: "debian:13".into(),
        };
        assert!(build_args(&plan, &over, &cfg, Some("runner")).is_err());
        assert!(build_args(&plan, &over, &cfg, None).is_ok());
    }

    #[test]
    fn an_unknown_service_names_the_ones_the_compose_file_declares() {
        let yaml = "services:\n\
             \x20 dev:\n    build: ./dev\n\
             \x20 runner:\n    build: ./runner\n    profiles: [runner]\n";
        let units = crate::compose::parse(yaml, Path::new("/base"), &|_| None, None).unwrap();
        check_service(&units, "runner").unwrap();
        let err = check_service(&units, "runer").unwrap_err().to_string();
        assert!(err.contains("dev, runner"), "{err}");
    }

    #[test]
    fn a_linked_worktrees_git_dir_is_mounted_and_a_main_checkouts_is_not() {
        let ws = Path::new("/home/dev/repo-wip");
        // A linked worktree: git names a directory elsewhere, which the guest must see at
        // that same path — it is what the worktree's `.git` file points at.
        assert_eq!(
            outside_workspace(ws, PathBuf::from("/home/dev/repo/.git")),
            Some(PathBuf::from("/home/dev/repo/.git"))
        );
        // A main checkout: already inside what the guest has, so mounting it again would
        // shadow part of the workspace with itself.
        assert_eq!(
            outside_workspace(ws, PathBuf::from("/home/dev/repo-wip/.git")),
            None
        );
    }

    #[test]
    fn a_workspace_that_is_no_repository_gets_no_git_mount() {
        let t = scratch("worktree");
        let plan = plan_in(&t.0);
        let cfg = crate::config::Config::default();
        let args = run_args(
            &plan,
            None,
            &Overrides::default(),
            &cfg,
            CheckoutMode::Shared,
        )
        .unwrap();
        // The mount is for a linked worktree's common directory; a directory git does not
        // call a repository has none.
        assert!(args.volumes.is_empty());
    }

    #[test]
    fn a_reuse_says_when_egress_stays_as_booted() {
        let t = scratch("egress-as-booted");
        let open = plan_in(&t.0);
        let held = |names: &[&str]| {
            let mut p = open.clone();
            p.egress = Some(crate::dev::plan::EgressPlan {
                mode: crate::dev::config::Egress::Restricted,
                allow_name: names.iter().map(|n| n.to_string()).collect(),
                allow_ip: vec![],
            });
            identity_of(&p, None).unwrap().1
        };
        let (_, unrestricted) = identity_of(&open, None).unwrap();
        let note = |running: &serde_json::Value, wanted: &serde_json::Value| {
            egress_as_booted(running, wanted).unwrap_or_default()
        };
        assert!(note(&unrestricted, &held(&[])).contains("stays unrestricted"));
        assert!(note(&held(&["debian.org"]), &unrestricted).contains("allowlist last applied"));
        // Restricted on both sides, lists edited or not, or on neither: nothing to say.
        assert_eq!(egress_as_booted(&held(&["debian.org"]), &held(&[])), None);
        assert_eq!(egress_as_booted(&unrestricted, &unrestricted), None);
    }

    #[test]
    fn the_freshness_policy_decides_what_a_drifted_environment_gets() {
        let never = || panic!("asked without a terminal to ask on");
        // The two policies that decide by themselves.
        assert_eq!(
            decide(Freshness::Reuse, true, never).unwrap(),
            Drifted::Reuse("freshness = reuse")
        );
        assert_eq!(
            decide(Freshness::Refresh, false, never).unwrap(),
            Drifted::Restart
        );
        // `require-current` refuses rather than choosing for the caller.
        assert_eq!(
            decide(Freshness::RequireCurrent, true, never).unwrap(),
            Drifted::Refuse
        );
        // `ask` off a terminal — a hook, a CI step — keeps what is running instead of
        // rebooting somebody's environment on an answer nobody gave.
        assert_eq!(
            decide(Freshness::Ask, false, never).unwrap(),
            Drifted::Reuse("no terminal to ask on")
        );
        assert_eq!(
            decide(Freshness::Ask, true, || Ok(true)).unwrap(),
            Drifted::Restart
        );
        assert_eq!(
            decide(Freshness::Ask, true, || Ok(false)).unwrap(),
            Drifted::Reuse("not rebuilding")
        );
        assert!(decide(Freshness::Ask, true, || bail!("no stdin")).is_err());
    }

    #[test]
    fn a_boot_left_not_ready_from_another_config_is_restarted_or_refused_never_attached() {
        let left = NotReady {
            vm: VmTie {
                pid: 41,
                created_secs: 7,
            },
            digest: "a".repeat(64),
            manifest: serde_json::json!({}),
            booted_secs: 0,
            readier: None,
            why: "hooks.start: exited with 1".into(),
        };
        let now = "b".repeat(64);
        assert!(restart_left_behind(|| Ok(Drifted::Restart), &left, &now).is_ok());
        let reuse = restart_left_behind(|| Ok(Drifted::Reuse("freshness = reuse")), &left, &now)
            .unwrap_err()
            .to_string();
        assert!(reuse.contains("nothing ready to attach to"), "{reuse}");
        assert!(reuse.contains("hooks.start: exited with 1"), "{reuse}");
        let refuse = restart_left_behind(|| Ok(Drifted::Refuse), &left, &now)
            .unwrap_err()
            .to_string();
        assert!(
            refuse.contains("booted aaaaaaaaaaaa, now bbbbbbbbbbbb"),
            "{refuse}"
        );
    }

    /// A VM tie no test registers.
    const VM: VmTie = VmTie {
        pid: 41,
        created_secs: 7,
    };

    /// Record `digest`/`manifest`, the only identity fields the decision reads.
    fn recorded(digest: &str, manifest: serde_json::Value) -> Identity {
        Identity {
            digest: digest.into(),
            booted_secs: 1000,
            created_by: String::new(),
            generation: String::new(),
            manifest,
            storage_backings: None,
            readied_by_its_boot: true,
        }
    }

    #[test]
    fn a_ready_environment_is_attached_to_restarted_or_refused_as_its_config_and_policy_say() {
        let t = scratch("live-decision");
        let plan = plan_in(&t.0);
        let (digest, manifest) = identity_of(&plan, None).unwrap();
        let wanted = Wanted {
            digest: &digest,
            manifest: &manifest,
        };
        let mut endpoints = manifest.clone();
        endpoints["endpoints"] = serde_json::json!([{ "name": "web", "host_port": 8080 }]);
        let same = recorded(&digest, manifest.clone());
        let session_only = recorded(&"b".repeat(64), endpoints);
        let drifted = recorded(&"a".repeat(64), serde_json::json!({}));
        let never = || -> Result<Drifted> { panic!("the policy was consulted") };
        let unasked = || -> bool { panic!("the images were judged") };

        assert_eq!(serves(&same, wanted), Serves::Same);
        assert_eq!(serves(&session_only, wanted), Serves::OnAttach);
        assert_eq!(serves(&drifted, wanted), Serves::NeedsRestart);
        assert_eq!(
            live_decision(&same, wanted, Refresh::No, unasked, never).unwrap(),
            Live::Current {
                session_only: false
            }
        );
        assert_eq!(
            live_decision(&session_only, wanted, Refresh::No, unasked, never).unwrap(),
            Live::Current { session_only: true }
        );
        // Changes requiring a restart follow any of the policy's three outcomes.
        let answers: [fn() -> Drifted; 3] = [
            || Drifted::Restart,
            || Drifted::Refuse,
            || Drifted::Reuse("freshness = reuse"),
        ];
        for answer in answers {
            assert_eq!(
                live_decision(&drifted, wanted, Refresh::No, unasked, || Ok(answer())).unwrap(),
                Live::Decided(answer())
            );
        }
        // Refresh restarts every configuration without consulting the policy: on arrival
        // whatever its images, after joining a boot unless that boot readied it from this
        // digest — not merely a session-only drift — and current images, judged only then.
        for running in [&same, &session_only, &drifted] {
            assert_eq!(
                live_decision(running, wanted, Refresh::Found, unasked, never).unwrap(),
                Live::Decided(Drifted::Restart)
            );
        }
        for running in [&session_only, &drifted] {
            assert_eq!(
                live_decision(running, wanted, Refresh::Joined, unasked, never).unwrap(),
                Live::Decided(Drifted::Restart)
            );
        }
        // A claim's re-readying of a VM that was already up, or a record that does not say,
        // is restarted before the images are judged. Outside a refresh the flag plays no
        // part: either is attached to as `same` is.
        let reclaimed = Identity {
            readied_by_its_boot: false,
            ..recorded(&digest, manifest.clone())
        };
        let mut old = serde_json::to_value(&same).unwrap();
        old.as_object_mut().unwrap().remove("readied_by_its_boot");
        let old: Identity = serde_json::from_value(old).unwrap();
        for running in [&reclaimed, &old] {
            assert_eq!(
                live_decision(running, wanted, Refresh::Joined, unasked, never).unwrap(),
                Live::Decided(Drifted::Restart)
            );
            assert_eq!(
                live_decision(running, wanted, Refresh::No, unasked, never).unwrap(),
                Live::Current {
                    session_only: false
                }
            );
        }
        for (current, joined) in [
            (true, Live::JustBooted),
            (false, Live::Decided(Drifted::Restart)),
        ] {
            assert_eq!(
                live_decision(&same, wanted, Refresh::Joined, || current, never).unwrap(),
                joined
            );
        }
        let refusal = readied_elsewhere(&drifted, &digest);
        assert!(refusal.contains("booted aaaaaaaaaaaa, now "), "{refusal}");
    }

    /// Waiting for another boot gives the same decision as finding it ready on arrival, except
    /// that a refresh which waited for a boot of this config from current images keeps it.
    #[tokio::test]
    async fn a_joiner_decides_on_what_it_waited_for_as_on_what_it_found() {
        const CHILD: &str = "VK_TEST_BOOT_JOIN_DECIDES";
        let Some(tmp) = std::env::var_os(CHILD).map(std::path::PathBuf::from) else {
            let tmp = scratch("join-decides");
            crate::dev::testutil::in_child(
                "dev::boot::tests::a_joiner_decides_on_what_it_waited_for_as_on_what_it_found",
                CHILD,
                &tmp.0,
            );
            return;
        };
        let plan = plan_in(&tmp);
        // The ordering `outcome` relies on below: with no `hooks.init`, `boot` has nothing to
        // await before `wait_for_boot`.
        assert!(plan.hooks.init.is_none());
        // The restart cases must fail in the rebuild, reading the compose file, before
        // anything is stopped.
        std::fs::create_dir_all(&plan.workspace).unwrap();
        let Source::Compose { file, .. } = &plan.source else {
            unreachable!("plan_in boots a compose service");
        };
        assert!(
            !file.exists(),
            "{} would let the rebuild succeed",
            file.display()
        );
        // And should one ever reach the stop, it signals this stand-in, not this process.
        let stand_in = StandIn::spawn();
        let _vm = crate::dev::testutil::register_vm_as(&plan, stand_in.id());
        // Without a holder to name, the joiner would boot rather than wait.
        assert!(lock_holder(&plan.state_dir).is_some());
        let (digest, manifest) = identity_of(&plan, None).unwrap();
        let mut endpoints = manifest.clone();
        endpoints["endpoints"] = serde_json::json!([{ "name": "web", "host_port": 8080 }]);
        let cfg = crate::config::Config::default();
        let parent = 4242;

        // The boot's outcome and the note it left, with `booted` recorded before it starts or
        // while it waits on the readying.
        let outcome = async |booted: &[u8], freshness: Freshness, refresh: bool, waited: bool| {
            let _ = std::fs::remove_file(identity_path(&plan));
            let _ = std::fs::remove_file(transition_path(&plan.state_dir, parent));
            let write = || std::fs::write(identity_path(&plan), booted).unwrap();
            if !waited {
                write();
            }
            let over = Overrides {
                freshness: Some(freshness),
                ..Default::default()
            };
            // `join!` polls the boot first, and on this current-thread runtime it runs to its
            // first await, the poll in `wait_for_boot` (see the `hooks.init` check above):
            // nothing is recorded when it looks.
            let (result, ()) = tokio::join!(
                boot(&plan, &cfg, &over, refresh, true, false, parent),
                async {
                    if waited {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        write();
                    }
                }
            );
            let note = std::fs::read_to_string(transition_path(&plan.state_dir, parent))
                .ok()
                .and_then(|n| n.split_whitespace().next().map(str::to_string));
            (result.map_err(|e| format!("{e:#}")), note)
        };

        #[derive(Debug)]
        enum Expect {
            Reused,
            Refused,
            Restart,
        }
        let json = |digest: &str, manifest: serde_json::Value| {
            serde_json::to_vec(&recorded(digest, manifest)).unwrap()
        };
        let same = json(&digest, manifest.clone());
        let session_only = json(&"b".repeat(64), endpoints);
        let drifted = json(&"a".repeat(64), serde_json::json!({}));
        for (booted, freshness, refresh, expect) in [
            (&same, Freshness::RequireCurrent, false, Expect::Reused),
            (
                &session_only,
                Freshness::RequireCurrent,
                false,
                Expect::Reused,
            ),
            (&drifted, Freshness::Reuse, false, Expect::Reused),
            // No terminal in this child: `ask` keeps what is running.
            (&drifted, Freshness::Ask, false, Expect::Reused),
            (&drifted, Freshness::RequireCurrent, false, Expect::Refused),
            (&drifted, Freshness::Refresh, false, Expect::Restart),
            // Refresh reuses a joined boot only if it started and readied the VM from this
            // config with known-current images. This stand-in has no recipe, so it restarts
            // as if found on arrival. Tests for `live_decision`, `attach_or_restart` and
            // `current_images_of` cover reuse.
            (&same, Freshness::Reuse, true, Expect::Restart),
        ] {
            let found = outcome(booted, freshness, refresh, false).await;
            let waited = outcome(booted, freshness, refresh, true).await;
            assert_eq!(waited, found, "{freshness:?}, refresh {refresh}");
            match (expect, found) {
                (Expect::Reused, (Ok(()), Some(note))) if note == "reused" => {}
                (Expect::Refused, (Err(e), None)) if e.contains("reboots it into this one") => {}
                (Expect::Restart, (Err(e), None))
                    if e.contains("compose.yaml") && !e.contains("did not stop") => {}
                (expect, found) => panic!("expected {expect:?}, got {found:?}"),
            }
        }

        // An identity that does not parse is reported at once rather than waited on, and a
        // refresh, which needs none of it, restarts the environment.
        for refresh in [false, true] {
            let (result, note) = tokio::time::timeout(
                Duration::from_secs(5),
                outcome(b"{", Freshness::Reuse, refresh, false),
            )
            .await
            .expect("decided without waiting");
            let e = result.unwrap_err();
            if refresh {
                assert!(
                    e.contains("compose.yaml") && !e.contains("did not stop"),
                    "{e}"
                );
            } else {
                assert!(e.contains("cannot be read"), "{e}");
            }
            assert_eq!(note, None);
        }
    }

    #[test]
    fn a_restart_attaches_only_to_what_the_boot_that_took_over_readied_from_its_config() {
        let t = scratch("after-takeover");
        let plan = plan_in(&t.0);
        let (digest, manifest) = identity_of(&plan, None).unwrap();
        let wanted = Wanted {
            digest: &digest,
            manifest: &manifest,
        };
        let mut endpoints = manifest.clone();
        endpoints["endpoints"] = serde_json::json!([{ "name": "web", "host_port": 8080 }]);
        let after = |joined| after_takeover(joined, wanted);
        let ready = |identity| Joined::Ready { identity, vm: VM };

        assert_eq!(
            after(ready(recorded(&digest, manifest.clone()))).unwrap(),
            Transition::Reused
        );
        assert_eq!(
            after(ready(recorded(&"b".repeat(64), endpoints))).unwrap(),
            Transition::Reused
        );
        assert_eq!(after(Joined::Claimed).unwrap(), Transition::Booted);
        let drifted = after(ready(recorded(&"a".repeat(64), serde_json::json!({}))))
            .unwrap_err()
            .to_string();
        assert!(
            drifted.contains("readied it from a different configuration"),
            "{drifted}"
        );
        let left = after(Joined::Drifted(NotReady {
            vm: VmTie {
                pid: 41,
                created_secs: 7,
            },
            digest: "a".repeat(64),
            manifest: serde_json::json!({}),
            booted_secs: 0,
            readier: None,
            why: "hooks.start: exited with 1".into(),
        }))
        .unwrap_err()
        .to_string();
        assert!(left.contains("reboots it into this one"), "{left}");
        let restart = after(Joined::Restart(VM)).unwrap_err().to_string();
        assert!(restart.contains("needs a restart"), "{restart}");
    }

    #[test]
    fn a_drifted_ready_environment_is_restarted_refused_or_attached_to_as_the_override_says() {
        let t = scratch("restarts-live");
        let plan = plan_in(&t.0);
        ensure_state_dir(&plan).unwrap();
        let (digest, manifest) = identity_of(&plan, None).unwrap();
        let wanted = Wanted {
            digest: &digest,
            manifest: &manifest,
        };
        let drifted = recorded(&"a".repeat(64), serde_json::json!({}));
        let under = |freshness| Overrides {
            freshness: Some(freshness),
            ..Overrides::default()
        };
        let pid = std::process::id();

        let restarts = attach_or_restart(
            &plan,
            &under(Freshness::Refresh),
            Refresh::No,
            || false,
            true,
            pid,
            &drifted,
            wanted,
        );
        assert_eq!(restarts.unwrap(), Attach::ToRestart);
        let err = attach_or_restart(
            &plan,
            &under(Freshness::RequireCurrent),
            Refresh::No,
            || false,
            true,
            pid,
            &drifted,
            wanted,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains(&format!(
                "booted from a different configuration (booted {}, now {})",
                short(&drifted.digest),
                short(&digest)
            )),
            "{err}"
        );
        assert!(
            err.contains("`--freshness reuse` attaches to it as it is"),
            "{err}"
        );
        let restarts = attach_or_restart(
            &plan,
            &under(Freshness::Reuse),
            Refresh::No,
            || false,
            true,
            pid,
            &drifted,
            wanted,
        );
        assert_eq!(restarts.unwrap(), Attach::Attached);
        let note = std::fs::read_to_string(transition_path(&plan.state_dir, pid)).unwrap();
        assert!(note.starts_with("reused "), "{note}");
    }

    #[test]
    fn a_refresh_keeps_what_it_waited_for_only_when_its_images_are_current() {
        let t = scratch("restarts-joined");
        let plan = plan_in(&t.0);
        ensure_state_dir(&plan).unwrap();
        let (digest, manifest) = identity_of(&plan, None).unwrap();
        let wanted = Wanted {
            digest: &digest,
            manifest: &manifest,
        };
        let same = recorded(&digest, manifest.clone());
        let pid = std::process::id();
        let joined = |current: bool| {
            attach_or_restart(
                &plan,
                &Overrides::default(),
                Refresh::Joined,
                || current,
                false,
                pid,
                &same,
                wanted,
            )
        };

        assert_eq!(joined(true).unwrap(), Attach::Attached);
        let note_path = transition_path(&plan.state_dir, pid);
        let note = std::fs::read_to_string(&note_path).unwrap();
        assert!(note.starts_with("reused "), "{note}");
        std::fs::remove_file(&note_path).unwrap();
        assert_eq!(joined(false).unwrap(), Attach::ToRestart);
        assert!(!note_path.exists(), "a restart notes no reuse");
        let reclaimed = Identity {
            readied_by_its_boot: false,
            ..recorded(&digest, manifest.clone())
        };
        let restarts = attach_or_restart(
            &plan,
            &Overrides::default(),
            Refresh::Joined,
            || true,
            false,
            pid,
            &reclaimed,
            wanted,
        );
        assert_eq!(
            restarts.unwrap(),
            Attach::ToRestart,
            "a claim's re-readying is restarted"
        );
    }

    /// A waiter's images are judged on the VM it read the identity of, and only while it is up.
    #[test]
    fn current_images_are_judged_on_the_vm_waited_for() {
        const CHILD: &str = "VK_TEST_BOOT_CURRENT_IMAGES";
        let Some(tmp) = std::env::var_os(CHILD).map(std::path::PathBuf::from) else {
            let tmp = scratch("current-images");
            crate::dev::testutil::in_child(
                "dev::boot::tests::current_images_are_judged_on_the_vm_waited_for",
                CHILD,
                &tmp.0,
            );
            return;
        };
        let plan = plan_in(&tmp);
        let vm = VmTie {
            pid: std::process::id(),
            created_secs: 7,
        };
        let fresh = |_: &crate::vms::VmEntry| true;
        assert!(!current_images_of(&plan, vm, fresh), "no VM up");
        let _vm = crate::dev::testutil::register_vm(&plan);
        assert_eq!(VmTie::of(&running_vm(&plan).unwrap()), vm);
        assert!(current_images_of(&plan, vm, fresh));
        assert!(!current_images_of(&plan, vm, |_| false));
        let replaced = VmTie {
            created_secs: 8,
            ..vm
        };
        assert!(
            !current_images_of(&plan, replaced, |_| panic!("judged another VM")),
            "a VM other than the one waited for"
        );
    }

    /// The flag a readying writes reaches a waiter through the identity it reads.
    #[tokio::test]
    async fn a_waiter_reads_whether_the_vms_own_boot_readied_it() {
        const CHILD: &str = "VK_TEST_BOOT_JOIN_CLAIMED";
        let Some(tmp) = std::env::var_os(CHILD).map(std::path::PathBuf::from) else {
            let tmp = scratch("join-claimed");
            crate::dev::testutil::in_child(
                "dev::boot::tests::a_waiter_reads_whether_the_vms_own_boot_readied_it",
                CHILD,
                &tmp.0,
            );
            return;
        };
        let plan = plan_in(&tmp);
        let _vm = crate::dev::testutil::register_vm(&plan);
        let vm = VmTie::of(&running_vm(&plan).unwrap());
        let (digest, manifest) = identity_of(&plan, None).unwrap();
        let wanted = Wanted {
            digest: &digest,
            manifest: &manifest,
        };
        let joined = async |by_its_boot: bool| {
            let _ = std::fs::remove_file(identity_path(&plan));
            crate::dev::identity::mark_not_ready(
                &plan,
                &NotReady {
                    vm,
                    digest: digest.clone(),
                    manifest: manifest.clone(),
                    booted_secs: 1000,
                    readier: crate::dev::identity::Readier::of(std::process::id()),
                    why: String::new(),
                },
            );
            let identity = Identity {
                readied_by_its_boot: by_its_boot,
                ..recorded(&digest, manifest.clone())
            };
            let (joined, ()) = tokio::join!(wait_for_boot(&plan, 4242, wanted, true), async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                crate::dev::identity::write_identity(&plan, &identity).unwrap();
                clear_not_ready(&plan);
            });
            joined.unwrap()
        };

        for by_its_boot in [true, false] {
            match joined(by_its_boot).await {
                Joined::Ready {
                    identity: running,
                    vm: tie,
                } => {
                    assert_eq!(tie, vm);
                    assert_eq!(running.readied_by_its_boot, by_its_boot);
                    let decided = live_decision(
                        &running,
                        wanted,
                        Refresh::Joined,
                        || true,
                        || panic!("the policy was consulted"),
                    )
                    .unwrap();
                    let kept = decided == Live::JustBooted;
                    assert_eq!(kept, by_its_boot, "{decided:?}");
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn a_restart_stops_only_the_vm_it_was_decided_on() {
        let entry = |tie: VmTie| -> crate::vms::VmEntry {
            serde_json::from_value(serde_json::json!({
                "state_dir": "/state",
                "pid": tie.pid,
                "label": "devcontainer",
                "exec_addr": "unused",
                "created_secs": tie.created_secs
            }))
            .unwrap()
        };
        let other = VmTie {
            pid: VM.pid,
            created_secs: VM.created_secs + 1,
        };
        let report = || Some("devcontainer (pid 41) did not stop after 10s\n".to_string());
        let state = after_build(VM, Some(entry(VM)), None);
        assert!(
            matches!(&state, AfterBuild::Stop(vm) if VmTie::of(vm) == VM),
            "{state:?}"
        );
        // Still up after a failed stop: that stop's report is the one reported.
        let state = after_build(VM, Some(entry(VM)), report());
        assert!(
            matches!(&state, AfterBuild::Stuck(r) if Some(r) == report().as_ref()),
            "{state:?}"
        );
        // Down on its own, or after all: nothing to stop, and no failure to report.
        for failed in [None, report()] {
            let state = after_build(VM, None, failed);
            assert!(matches!(state, AfterBuild::Clear), "{state:?}");
        }
        // Another boot's VM, even under the same pid, is joined and never stopped, whatever a
        // stop of the targeted one reported.
        for failed in [None, report()] {
            let state = after_build(VM, Some(entry(other)), failed);
            assert!(
                matches!(state, AfterBuild::Replaced(vm) if vm == other),
                "{state:?}"
            );
        }
    }

    /// Once rebuilt, a restart boots over the VM it targeted — gone on its own or stopped —
    /// and joins, never stops, one that replaced it or another boot holding the lock.
    #[tokio::test]
    async fn swap_acts_on_the_vm_up_after_the_build() {
        use std::os::unix::process::ExitStatusExt;

        use crate::dev::testutil::{register_entry, register_vm_in_child};

        /// A relay of `state_dir`'s VM, and a thread that runs `then` once something has
        /// stopped it — a stop ends the relays before it signals the VM.
        fn relay_then<T: Send + 'static>(
            state_dir: &Path,
            then: impl FnOnce() -> T + Send + 'static,
        ) -> std::thread::JoinHandle<T> {
            let mut victim = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap();
            let lock = crate::publish::fake_publisher(
                state_dir,
                "web",
                "tcp://127.0.0.1:8600",
                "vsock://80",
                victim.id(),
                None,
            );
            std::thread::spawn(move || {
                let _ = victim.wait();
                // The lifetime lock goes when the publisher does.
                drop(lock);
                then()
            })
        }

        const CHILD: &str = "VK_TEST_BOOT_SWAP_REPLACED";
        let Some(tmp) = std::env::var_os(CHILD).map(std::path::PathBuf::from) else {
            let tmp = scratch("swap-replaced");
            crate::dev::testutil::in_child(
                "dev::boot::tests::swap_acts_on_the_vm_up_after_the_build",
                CHILD,
                &tmp.0,
            );
            return;
        };
        let mut plan = plan_in(&tmp);
        // Nothing to build, so the restart goes straight on to the stop.
        plan.source = Source::Image {
            reference: "debian:13".into(),
        };
        std::fs::create_dir_all(&plan.workspace).unwrap();
        ensure_state_dir(&plan).unwrap();
        let cfg = crate::config::Config::default();
        let over = Overrides::default();
        let (digest, manifest) = identity_of(&plan, None).unwrap();
        let wanted = Wanted {
            digest: &digest,
            manifest: &manifest,
        };
        let parent = 4242;
        let try_swap = async |wait: bool, targeted: VmTie| {
            let _ = std::fs::remove_file(transition_path(&plan.state_dir, parent));
            let result = swap(&plan, &cfg, &over, wait, parent, targeted, wanted).await;
            let note = std::fs::read_to_string(transition_path(&plan.state_dir, parent))
                .ok()
                .and_then(|n| n.split_whitespace().next().map(str::to_string));
            (result.map_err(|e| format!("{e:#}")), note)
        };
        let write = |identity: &Identity| {
            std::fs::write(identity_path(&plan), serde_json::to_vec(identity).unwrap()).unwrap()
        };

        // Gone on its own during the build, with no other boot: this one boots, once the
        // relays that VM left are gone.
        let relay = relay_then(&plan.state_dir, || ());
        let record = plan.state_dir.join("publish/web.json");
        assert!(record.exists());
        assert_eq!(try_swap(false, VM).await, (Ok(Swap::Boot), None));
        assert!(!record.exists(), "a leftover relay is cleared");
        relay.join().unwrap();

        // Still up: stopped, and then booted over.
        let (registration, mut child) = register_vm_in_child(&plan, false);
        let targeted = VmTie::of(&running_vm(&plan).unwrap());
        assert_eq!(try_swap(false, targeted).await, (Ok(Swap::Boot), None));
        // Its lock goes before its exit is reported, so the status may lag the stop.
        let mut status = None;
        for _ in 0..100 {
            status = child.try_wait();
            if status.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            status.and_then(|s| s.signal()),
            Some(libc::SIGTERM),
            "the targeted VM was stopped"
        );
        drop(registration);

        // Still up after the stop: refused, rather than booted over.
        let (registration, mut stubborn) = register_vm_in_child(&plan, true);
        let targeted = VmTie::of(&running_vm(&plan).unwrap());
        let (result, note) = try_swap(false, targeted).await;
        let e = result.unwrap_err();
        assert!(e.contains("did not stop"), "{e}");
        assert_eq!(note, None);
        assert!(stubborn.alive());

        // Gone from the registry while the stop was failing, its lock still held: no failure
        // after all, but a boot holding the lock, which is joined.
        let relay = relay_then(&plan.state_dir, move || drop(registration));
        let (result, note) = try_swap(false, targeted).await;
        let e = result.unwrap_err();
        assert!(e.contains("took over while this one was rebuilding"), "{e}");
        assert_eq!(note, None);
        relay.join().unwrap();

        // Replaced while the stop was failing, by a VM readied from this config: attached to.
        write(&recorded(&digest, manifest.clone()));
        let registration = register_entry(&plan, stubborn.id());
        let relay = relay_then(&plan.state_dir, {
            let plan = plan.clone();
            move || {
                drop(registration);
                // A stand-in, so a regression that stops the replacement signals it rather
                // than this process.
                let replacement = StandIn::spawn();
                (register_entry(&plan, replacement.id()), replacement)
            }
        });
        assert_eq!(
            try_swap(false, targeted).await,
            (Ok(Swap::Joined), Some("reused".into()))
        );
        let (registration, mut replacement) = relay.join().unwrap();
        assert!(replacement.alive());
        drop(registration);
        std::fs::remove_file(identity_path(&plan)).unwrap();
        assert!(stubborn.alive());
        drop(stubborn);

        // Gone, with another boot holding the lock and nothing up yet: joined, not booted.
        let held = crate::dev::list::try_lock_state_dir(&plan.state_dir).unwrap();
        let (result, note) = try_swap(false, VM).await;
        let e = result.unwrap_err();
        assert!(e.contains("took over while this one was rebuilding"), "{e}");
        assert_eq!(note, None);
        drop(held);

        let mut stand_in = StandIn::spawn();
        let _vm = crate::dev::testutil::register_vm_as(&plan, stand_in.id());
        let replacement = VmTie::of(&running_vm(&plan).unwrap());
        // Its lock is this process's, not its `vk run`'s: a run that replaced it holds it, and
        // stopping it is left to that run's boot, which this joins. Only a holder procfs names
        // tells the two apart.
        assert!(lock_holder(&plan.state_dir).is_some());
        let (result, note) = try_swap(false, replacement).await;
        let e = result.unwrap_err();
        assert!(e.contains("took over while this one was rebuilding"), "{e}");
        assert_eq!(note, None);
        assert!(stand_in.alive());

        // Under the pid it was targeted under, but registered at another time: another VM.
        let targeted = VmTie {
            pid: replacement.pid,
            created_secs: replacement.created_secs + 1,
        };

        // Readied from this config: attached to, even under --no-wait.
        write(&recorded(&digest, manifest.clone()));
        assert_eq!(
            try_swap(false, targeted).await,
            (Ok(Swap::Joined), Some("reused".into()))
        );
        assert!(stand_in.alive());

        // Readied from another: refused.
        write(&recorded(&"a".repeat(64), serde_json::json!({})));
        let (result, note) = try_swap(true, targeted).await;
        let e = result.unwrap_err();
        assert!(
            e.contains("readied it from a different configuration"),
            "{e}"
        );
        assert_eq!(note, None);
        assert!(stand_in.alive());

        // Not ready yet, under --no-wait: refused rather than waited on.
        std::fs::remove_file(identity_path(&plan)).unwrap();
        let (result, note) = try_swap(false, targeted).await;
        let e = result.unwrap_err();
        assert!(e.contains("took over while this one was rebuilding"), "{e}");
        assert_eq!(note, None);
        assert!(stand_in.alive());

        // Not ready yet, waited on: attached to once readied from this config. Renamed into
        // place, as the identity is written whole.
        let writer = std::thread::spawn({
            let path = identity_path(&plan);
            let body = serde_json::to_vec(&recorded(&digest, manifest.clone())).unwrap();
            move || {
                std::thread::sleep(Duration::from_millis(300));
                let part = path.with_extension("part");
                std::fs::write(&part, body).unwrap();
                std::fs::rename(part, path).unwrap();
            }
        });
        assert_eq!(
            try_swap(true, targeted).await,
            (Ok(Swap::Joined), Some("reused".into()))
        );
        writer.join().unwrap();
        assert!(stand_in.alive());

        // Recorded, but unreadable: reported rather than waited on.
        std::fs::write(identity_path(&plan), b"{").unwrap();
        let (result, note) = try_swap(true, targeted).await;
        let e = result.unwrap_err();
        assert!(e.contains("cannot be read"), "{e}");
        assert_eq!(note, None);
        assert!(stand_in.alive());
    }

    #[test]
    fn a_failed_readying_is_claimed_or_under_a_refresh_restarted() {
        const CHILD: &str = "VK_TEST_BOOT_TAKE_OVER";
        let Some(tmp) = std::env::var_os(CHILD).map(std::path::PathBuf::from) else {
            let tmp = scratch("take-over");
            crate::dev::testutil::in_child(
                "dev::boot::tests::a_failed_readying_is_claimed_or_under_a_refresh_restarted",
                CHILD,
                &tmp.0,
            );
            return;
        };
        let plan = plan_in(&tmp);
        let _vm = crate::dev::testutil::register_vm(&plan);
        let (digest, manifest) = identity_of(&plan, None).unwrap();
        let wanted = Wanted {
            digest: &digest,
            manifest: &manifest,
        };
        let pid = std::process::id();
        assert!(
            take_over(&plan, pid, wanted, true).is_none(),
            "nothing left"
        );
        crate::dev::identity::mark_not_ready(
            &plan,
            &NotReady {
                vm: VmTie::of(&running_vm(&plan).unwrap()),
                digest: digest.clone(),
                manifest: manifest.clone(),
                booted_secs: 1000,
                readier: None,
                why: "hooks.start: exited with 1".into(),
            },
        );
        let joined = take_over(&plan, pid, wanted, true);
        let vm = VmTie::of(&running_vm(&plan).unwrap());
        assert!(
            matches!(joined, Some(Joined::Restart(tie)) if tie == vm),
            "{joined:?}"
        );
        let joined = take_over(&plan, pid, wanted, false);
        assert!(matches!(joined, Some(Joined::Claimed)), "{joined:?}");
        let left = read_not_ready(&plan).unwrap();
        assert_eq!(left.readier, crate::dev::identity::Readier::of(pid));
        assert!(
            take_over(&plan, pid, wanted, true).is_none(),
            "a claimed readying is waited on, even by a refresh"
        );
    }

    #[test]
    fn a_digest_read_back_from_the_state_dir_is_shortened_by_characters() {
        assert_eq!(short(&"a".repeat(64)), "a".repeat(12));
        // Whatever is in `dev.json`: indexing these bytes panicked on a truncated or
        // hand-edited file.
        assert_eq!(short("abc"), "abc");
        assert_eq!(short(""), "");
        assert_eq!(short("héllo-wörld-digest"), "héllo-wörld-");
    }

    #[test]
    fn probing_the_lock_leaves_it_free_to_take() {
        use std::os::fd::AsRawFd;

        let t = scratch("lockprobe");
        let plan = plan_in(&t.0);
        ensure_state_dir(&plan).unwrap();

        // Probing must not disturb a held lock: a real `lock_state_dir` racing it would
        // otherwise have to wait out the lock grace, or fail if the probe outlasted it.
        for _ in 0..3 {
            assert!(lock_holder(&plan.state_dir).is_none(), "nobody holds it");
        }
        let held = std::fs::File::open(&plan.state_dir).unwrap();
        assert_eq!(
            unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0,
            "a probed directory is still lockable"
        );
        // Naming the holder is best-effort (see `crate::run::flock_holder`), so what is
        // asserted here is only that probing a held lock does not disturb it.
        let _ = lock_holder(&plan.state_dir);
        assert_eq!(
            unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_UN) },
            0,
            "unlocking our own lock"
        );
    }

    #[tokio::test]
    async fn the_transition_is_passed_from_the_child_to_its_own_parent() {
        let t = scratch("transition");
        let plan = plan_in(&t.0);
        ensure_state_dir(&plan).unwrap();
        // Nothing written: nothing that only makes sense after a fresh boot may be inferred.
        assert_eq!(take_transition(&plan, 4242).await, None);
        note_transition(&plan, 4242, Transition::Booted);
        // Another invocation's parent must not read this one's.
        assert_eq!(take_transition(&plan, 9999).await, None);
        assert_eq!(take_transition(&plan, 4242).await, Some(Transition::Booted));
        // Taken once, and gone.
        assert_eq!(take_transition(&plan, 4242).await, None);
    }

    #[tokio::test]
    async fn a_note_from_another_run_is_not_this_ones() {
        let t = scratch("transition-stale");
        let plan = plan_in(&t.0);
        ensure_state_dir(&plan).unwrap();
        // What a boot that died before this one left behind, under a pid the operating
        // system has since handed out again. It says "booted", and acting on it would
        // rewrite the identity and re-run the start hooks for a boot that never happened.
        std::fs::write(
            transition_path(&plan.state_dir, 4242),
            "booted 31337 stale\n",
        )
        .unwrap();
        assert_eq!(take_transition(&plan, 4242).await, None);
        // …and it is gone, so nothing else picks it up either.
        assert!(!transition_path(&plan.state_dir, 4242).exists());
    }

    #[test]
    fn each_ephemeral_task_run_gets_a_directory_of_its_own() {
        let t = scratch("task-state");
        let plan = plan_in(&t.0);
        ensure_state_dir(&plan).unwrap();
        let task = crate::dev::plan::TaskPlan {
            name: "pre commit".into(),
            argv: vec!["true".into()],
            env: vec![],
            policy: crate::dev::config::Policy::Ephemeral,
            environment: "dev".into(),
            reuse: "dev".into(),
            checkout: CheckoutMode::Shared,
        };

        let first = task_state_dir(&plan, &task).unwrap();
        let second = task_state_dir(&plan, &task).unwrap();
        assert_ne!(first, second, "a leaked directory is never inherited");
        let suffix = first.to_str().unwrap().rsplit('-').next().unwrap();
        assert_eq!(suffix.len(), 8, "short enough for the vsock socket path");
        // Named after the workspace, like the environment's own directory.
        let workspace = plan.workspace.file_name().unwrap().to_str().unwrap();
        for dir in [&first, &second] {
            assert!(dir.is_dir(), "created, not merely named");
            assert_eq!(
                std::fs::metadata(dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
            // A sibling of the environment's, so `vk dev list` shows one that leaked and
            // `vk dev gc` removes it.
            assert_eq!(dir.parent(), plan.state_dir.parent());
            let name = dir.file_name().unwrap().to_string_lossy().to_string();
            assert!(
                name.starts_with(&format!("{workspace}-task-pre-commit-")),
                "{name}"
            );
        }
    }

    #[test]
    fn a_long_task_name_cannot_overrun_the_socket_path() {
        let t = scratch("task-name-len");
        let plan = plan_in(&t.0);
        ensure_state_dir(&plan).unwrap();
        let task = crate::dev::plan::TaskPlan {
            name: "x".repeat(100),
            argv: vec!["true".into()],
            env: vec![],
            policy: crate::dev::config::Policy::Ephemeral,
            environment: "dev".into(),
            reuse: "dev".into(),
            checkout: CheckoutMode::Shared,
        };
        let dir = task_state_dir(&plan, &task).unwrap();
        let leaf = dir.file_name().unwrap().to_str().unwrap();
        // The whole point of the bound: every socket the VM binds under this directory has
        // to fit what `sun_path` holds.
        let socket = dir.join("vsock.sock_65535");
        assert!(
            socket.as_os_str().len() <= 107,
            "{} bytes: {socket:?}",
            socket.as_os_str().len()
        );
        // `<workspace>-task-<name>-<8 hex>`: drop the fixed prefix and the trailing token to
        // read back the sanitized name. It is cut to at most TASK_NAME_MAX, and further when
        // the temp base is long — either way it is truncated from the 100 given, and fits.
        let workspace = plan.workspace.file_name().unwrap().to_str().unwrap();
        let name = leaf
            .strip_prefix(&format!("{workspace}-task-"))
            .unwrap()
            .rsplit_once('-')
            .unwrap()
            .0;
        assert!(
            (1..=32).contains(&name.chars().count()),
            "a long name is truncated to fit: {leaf}"
        );
    }

    #[test]
    fn task_args_is_an_ephemeral_run_carrying_the_task_command_and_no_session() {
        let t = scratch("task-args");
        let mut plan = plan_in(&t.0);
        plan.exec_env = vec![crate::dev::plan::EnvVar {
            name: "FROM_ENV".into(),
            value: "env".into(),
            sensitive: false,
        }];
        let scratch_dir = t.0.join("scratch");
        let task = crate::dev::plan::TaskPlan {
            name: "check".into(),
            argv: vec!["cargo".into(), "test".into()],
            env: vec![crate::dev::plan::EnvVar {
                name: "FROM_TASK".into(),
                value: "task".into(),
                sensitive: false,
            }],
            policy: crate::dev::config::Policy::Ephemeral,
            environment: "dev".into(),
            reuse: "dev".into(),
            checkout: CheckoutMode::Shared,
        };
        let cfg = crate::config::Config::default();
        let args = task_args(
            &plan,
            &Overrides::default(),
            &cfg,
            &task,
            &["--".to_string(), "--nocapture".to_string()],
            None,
            Some(&scratch_dir),
        )
        .unwrap();

        // The caller's scratch directory is taken as is — none is created for this run.
        assert_eq!(args.state_dir.as_deref(), Some(scratch_dir.as_path()));
        // Nothing that belongs to an environment someone works in.
        assert!(!args.ssh && !args.ssh_client && !args.ssh_agent);
        assert!(args.ssh_allow_pub.is_none() && args.ssh_guest_config.is_none());
        assert!(!args.host_exec);
        assert!(args.host_exec_wrapper.is_none());
        assert!(args.host_exec_env.is_empty());
        assert!(!args.detach);
        assert!(args.detach_log.is_none());
        assert!(args.inactivity_timeout_secs.is_none());

        // The command runs in the workspace folder, its argv followed by the extra args.
        assert_eq!(
            args.command,
            vec![
                "sh".to_string(),
                "-c".into(),
                "cd /workdir && exec \"$@\"".into(),
                "sh".into(),
                "cargo".into(),
                "test".into(),
                "--".into(),
                "--nocapture".into(),
            ]
        );
        // Both the environment's exec-env and the task's own reach the guest.
        assert!(
            args.env
                .contains(&("FROM_ENV".to_string(), "env".to_string()))
        );
        assert!(
            args.env
                .contains(&("FROM_TASK".to_string(), "task".to_string()))
        );

        // A fallback target is forced uncached, so the cache miss it stands in for rebuilds.
        let fallback = task_args(
            &plan,
            &Overrides::default(),
            &cfg,
            &task,
            &[],
            Some("builder"),
            Some(&scratch_dir),
        )
        .unwrap();
        assert_eq!(fallback.target.as_deref(), Some("builder"));
        assert!(!fallback.require_cached);

        // A restricted environment's task is held to the same lists, but never through the
        // file the environment's own switch follows.
        plan.egress = Some(crate::dev::plan::EgressPlan {
            mode: crate::dev::config::Egress::Restricted,
            allow_name: vec!["debian.org".into()],
            allow_ip: vec![],
        });
        let restricted = task_args(
            &plan,
            &Overrides::default(),
            &cfg,
            &task,
            &[],
            None,
            Some(&scratch_dir),
        )
        .unwrap();
        assert!(restricted.egress_allow.is_some() && restricted.egress_file.is_none());
    }

    #[test]
    fn a_managed_directorys_generation_marker_is_written_once() {
        let t = scratch("marker");
        let mut plan = plan_in(&t.0);
        let store = plan.state_dir.join("store");
        plan.managed_dirs = vec![store.clone()];
        ensure_state_dir(&plan).unwrap();

        let token = marker_of(&store);
        assert!(!token.is_empty(), "a created directory carries a token");
        // Every later boot finds the directory as it was and leaves its token alone —
        // contents the creation hook produced are not re-created on a restart.
        for _ in 0..3 {
            ensure_state_dir(&plan).unwrap();
            assert_eq!(marker_of(&store), token);
        }
        assert!(store.join(GENERATION_MARKER).is_file());
    }

    #[test]
    fn the_ssh_alias_is_the_workspaces_own() {
        let t = scratch("alias");
        let mut plan = plan_in(&t.0);
        let alias = alias(&plan);
        assert_eq!(alias, "vk-state");
        crate::sshclient::validate_alias(&alias).expect("usable as an ssh Host pattern");

        // A state directory this host does not spell in UTF-8 is refused before the boot
        // rather than turned into an alias naming another host.
        use std::os::unix::ffi::OsStrExt;
        plan.state_dir = PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/st\xffate"));
        let err = checked_alias(&plan).unwrap_err().to_string();
        assert!(err.contains("not valid UTF-8"), "{err}");
    }
}
