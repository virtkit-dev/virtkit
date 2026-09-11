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
    applied_on_attach, drift, identity_of, identity_path, live_identity, note_older_creator,
    sha256_hex,
};
use super::session::{ask_on_terminal, on_terminal, running_vm, stop};
use super::{GENERATION_MARKER, INFLIGHT_POLL, Overrides, TRANSITION_WAIT, Transition};

/// Shared stop timeout for refresh and the default `vk dev stop --timeout`, in seconds.
pub(super) const STOP_TIMEOUT_SECS: u64 = 10;

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
        cloud_hypervisor: cfg.cloud_hypervisor().to_path_buf(),
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
    let name = plan
        .state_dir
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

/// Replace what is running with what the config now says: build, stop, and check that the
/// way is clear. `false` when another boot took the environment over while this one was
/// building and this process joined it instead — there is then nothing left to boot.
async fn swap(
    plan: &Plan,
    cfg: &crate::config::Config,
    over: &Overrides,
    wait: bool,
    parent_pid: u32,
) -> Result<bool> {
    // Build first, with the current environment still up and usable: a build that fails
    // then costs only time, and the boot below restores what this just cached rather than
    // building it cold — seconds of downtime instead of minutes.
    eprintln!("virtkit: rebuilding while the current environment keeps running …");
    build_into_cache(plan, over, cfg, None)?;
    let stopped = stop(plan, STOP_TIMEOUT_SECS)?;
    // Every other line of a boot goes to stderr, and this one runs in a child whose stdout
    // the caller may have closed.
    eprint!("{}", stopped.report);
    // What matters is the state now, not whether *this* stop found something to do:
    // another refresh may have swapped the environment while this one was building, in
    // which case there was nothing left here to stop and nothing to report as a failure.
    if running_vm(plan).is_some() {
        bail!("the dev environment did not stop; not booting a new one");
    }
    if let Some(holder) = lock_holder(&plan.state_dir) {
        if !wait {
            bail!(
                "another boot of this environment ({holder}) took over while this one was \
                 rebuilding — wait for that one, or re-run without --no-wait"
            );
        }
        wait_for_boot(plan).await?;
        note_transition(plan, parent_pid, Transition::Reused);
        return Ok(false);
    }
    Ok(true)
}

/// The readable head of a digest. Taken by characters rather than bytes: these are read
/// back from `dev.json`, which a hand-edited or truncated file can make anything at all.
fn short(digest: &str) -> String {
    digest.chars().take(12).collect()
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

    if let Some(running) = live_identity(plan) {
        let drifted = running.digest != digest;
        // A change the running VM never sees — `exec-env`, editor settings, endpoints,
        // tasks — is applied by this attach or the next session, not by a restart, so it is
        // no reason to offer one.
        let session_only = drifted && applied_on_attach(&drift(&running.manifest, &manifest));
        if (!drifted || session_only) && !refresh {
            if announce_reuse {
                eprintln!(
                    "virtkit: dev environment already running ({})",
                    plan.state_dir.display()
                );
                if session_only {
                    eprintln!(
                        "virtkit: its config changed only in what attaching applies (exec-env, \
                         editor, endpoints, tasks) — no restart needed"
                    );
                }
                note_older_creator(&running);
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
            note_transition(plan, parent_pid, Transition::Reused);
            return Ok(());
        }
        if drifted && !refresh {
            let summary = format!(
                "the running environment was booted from a different configuration (booted \
                 {}, now {})",
                short(&running.digest),
                short(&digest)
            );
            // The question reaches the terminal because this child inherited the parent's
            // stdin and stderr and the parent is blocked reading the readiness pipe — the
            // `setsid` above cost it the controlling terminal, not the descriptors. With no
            // terminal there is nobody to answer, so the running environment stands.
            match decide(
                over.freshness.unwrap_or(plan.freshness),
                on_terminal(),
                || ask_on_terminal("rebuild and restart it now?"),
            )? {
                Drifted::Reuse(why) => {
                    eprintln!(
                        "virtkit: {summary}; {why} — attaching to it as recorded, \
                         `vk dev refresh` applies the config"
                    );
                    note_older_creator(&running);
                    note_transition(plan, parent_pid, Transition::Reused);
                    return Ok(());
                }
                Drifted::Refuse => bail!(
                    "{summary} — `vk dev refresh` reboots it into this one, `vk dev stop` \
                     ends it, or `--freshness reuse` attaches to it as it is"
                ),
                Drifted::Restart => {}
            }
        }
        if !swap(plan, cfg, over, wait, parent_pid).await? {
            return Ok(());
        }
    } else if let Some(holder) = lock_holder(&plan.state_dir) {
        if !wait {
            bail!(
                "another boot of this environment is already in flight ({holder}); its output \
                 goes to the terminal that started it — wait for that one, or re-run \
                 without --no-wait"
            );
        }
        wait_for_boot(plan).await?;
        note_transition(plan, parent_pid, Transition::Reused);
        return Ok(());
    }

    note_transition(plan, parent_pid, Transition::Booted);
    // What was recorded describes an environment that is about to be replaced, and nothing
    // describes the new one until `after_boot` has it ready. Removing it now is what a
    // joining `vk dev` waits on (see `wait_for_boot`); a removal that fails — including the
    // first boot's, where there is no file — only leaves that wait to time out.
    let _ = std::fs::remove_file(identity_path(plan));
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
/// Asked of `/proc/locks`, never by taking the lock: a probe that grabbed it, even for the
/// instant it takes to drop it again, made whatever real [`crate::run::lock_state_dir`] was
/// running at that moment fail with "state-dir is in use". The trade is that a holder
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

/// Wait for the boot someone else started to produce a *ready* environment: a registered
/// VM, and the identity written after it.
///
/// Waiting for the VM alone released this process while the boot's own parent was still
/// publishing endpoints and pushing the session environment — two writers doing the same
/// work at the same time.
async fn wait_for_boot(plan: &Plan) -> Result<()> {
    eprintln!("waiting for the boot already in flight …");
    let mut up_since = None;
    loop {
        let up = running_vm(plan).is_some();
        if up && identity_path(plan).exists() {
            return Ok(());
        }
        if lock_holder(&plan.state_dir).is_none() {
            bail!("the boot that was in flight ended without leaving a running environment");
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
    use crate::dev::testutil::{plan_in, scratch};

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
        // otherwise fail with "state-dir is in use".
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
