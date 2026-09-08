//! The run plan a `.virtkit/config.toml` resolves to on this host.
//!
//! [`crate::dev::config`] reads and layers the files; this decides what they mean here: paths
//! made absolute against the workspace root, `${…}` substituted, the state directory
//! derived, mounts and endpoints spelled the way `vk run` takes them. Nothing is done: the
//! [`Plan`] is the seam between configuration and execution — `vk dev plan` prints it and
//! every other `vk dev` command works from it.
//!
//! Values that came from the host environment — `${localEnv:…}`, where a token would come
//! from — are marked and redacted when a plan is printed or recorded.
//!
//! A config is as trusted as the checkout it comes from: a mount source may not walk out of
//! the project, but `wrapper` and `compose` are resolved wherever they point.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;

use crate::dev::config::{
    CheckoutMode, Command, Cpus, Environment, Freshness, Loaded, Nested, Policy, Requires,
    lexical_join,
};

/// Where `vk dev` keeps environment state: `$XDG_STATE_HOME/virtkit/dev`, else
/// `~/.local/state/virtkit/dev`. State home, not the data or cache base: these directories
/// hold a live VM's sockets, keys and logs, which a cache sweep must never reclaim.
pub fn dev_state_base() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
        let dir = PathBuf::from(dir);
        // Relative, it would put a VM's state wherever the command happened to be run.
        if !dir.is_absolute() {
            bail!("XDG_STATE_HOME {} is not an absolute path", dir.display());
        }
        return Ok(dir.join("virtkit/dev"));
    }
    let home = std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .context("neither XDG_STATE_HOME nor HOME is set, so there is nowhere to keep VM state")?;
    Ok(PathBuf::from(home).join(".local/state/virtkit/dev"))
}

/// What the primary VM boots from.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Source {
    /// a compose service, with its siblings on the run's LAN
    Compose {
        file: PathBuf,
        service: String,
        /// profiles activated eagerly, besides the service's dependencies
        profiles: Vec<String>,
    },
    /// an image, alone
    Image { reference: String },
    /// a Dockerfile target, alone
    Build {
        context: PathBuf,
        /// absolute; inside `context` unless the config said otherwise
        dockerfile: PathBuf,
        target: Option<String>,
        /// `--build-arg` values, in config order
        args: Vec<(String, String)>,
    },
}

/// One `[dev.tasks.<name>]`, resolved: what runs, where, and how the environment is
/// obtained.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TaskPlan {
    pub name: String,
    pub argv: Vec<String>,
    /// the environment an ephemeral or required run uses: `dev`, or one under
    /// `[environments]`
    pub environment: String,
    /// the environment a reusing policy attaches to when it is running
    pub reuse: String,
    pub policy: Policy,
    /// what the task sees of the checkout
    pub checkout: CheckoutMode,
    /// added to the environment's `exec-env` for this task
    pub env: Vec<EnvVar>,
}

/// An environment variable with its host provenance. Host values may contain tokens or
/// passwords, so printed plans redact them.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
    /// serialized: a redacted plan still says which values this host fed
    pub sensitive: bool,
}

/// One `[dev.mounts.<name>]`, resolved: a host path, where it goes in the guest, and how.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MountPlan {
    /// the config's name for it, or vk's own for a mount it manages
    pub name: String,
    /// the host path, absolute
    pub source: PathBuf,
    /// the guest path, folded lexically; no two mounts in a plan share one
    pub to: String,
    pub read_only: bool,
    /// an absent source is skipped rather than a failure
    pub optional: bool,
}

impl MountPlan {
    /// The `vk run -v` spec this mount is.
    pub fn spec(&self) -> Result<String> {
        let source = self.source.to_str().with_context(|| {
            format!(
                "mount {} ({}) is not valid UTF-8",
                self.name,
                self.source.display()
            )
        })?;
        let mut spec = format!("{source}:{}", self.to);
        match (self.read_only, self.optional) {
            (true, true) => spec.push_str(":ro,optional"),
            (true, false) => spec.push_str(":ro"),
            (false, true) => spec.push_str(":rw,optional"),
            (false, false) => {}
        }
        Ok(spec)
    }
}

/// A guest port published on the host: the primary's once the environment is up, a
/// service's while that service runs.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EndpointPlan {
    /// the publisher's name (`vk publish list`)
    pub name: String,
    /// the compose service that listens; `None` for the primary
    pub service: Option<String>,
    /// the host port
    pub host_port: u16,
    /// the host address as configured: an address, or `auto` for the stable loopback
    /// allocation `devendpoints` makes when publishing (kept symbolic here so the plan's
    /// identity does not move with the allocation)
    pub address: String,
    /// `tcp://<address>:<host_port>` as configured — `auto` stays `auto`
    pub listen: String,
    pub to: String,
    /// for `vk dev open`: the URL's scheme …
    pub scheme: Option<String>,
    /// … and path
    pub path: Option<String>,
    /// the environment (or its service) is not ready until this is published
    pub required: bool,
}

impl EndpointPlan {
    /// Whether the host address is allocated rather than configured.
    pub fn auto(&self) -> bool {
        self.address == "auto"
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HostExecPlan {
    /// absolute: a project wrapper, or — for a `builtin` policy — the state-dir path the
    /// boot generates it at. Checked to exist at plan time; the boot re-checks before it
    /// hands the channel over.
    pub wrapper: PathBuf,
    /// the built-in policy vk generates the wrapper for, if any (`git-gui`)
    pub builtin: Option<String>,
    pub env: Vec<String>,
}

/// A hook, resolved: what runs, where, for how long, and whether its failure is the
/// operation's.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum HookPlan {
    Command(HookCommand),
    /// the named hooks run in turn; the group fails if a required member does
    Group(BTreeMap<String, HookPlan>),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HookCommand {
    /// as the config wrote it: a shell line, or an argv list
    pub run: Command,
    /// relative to the workspace (host) or the workspace folder (guest) unless absolute
    pub cwd: Option<String>,
    pub timeout_secs: Option<u64>,
    pub required: bool,
}

impl HookCommand {
    /// The argv that runs.
    pub fn argv(&self) -> Vec<String> {
        command_argv(&self.run)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct HooksPlan {
    pub init: Option<HookPlan>,
    pub create: Option<HookPlan>,
    pub start: Option<HookPlan>,
}

/// The managed VS Code remote: kept across refreshes or not, and how it is reconciled.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VsCodePlan {
    pub persistent: bool,
    /// the guest home the server data directory lives under
    pub home: String,
    pub reconcile: Option<HookPlan>,
    pub extensions: Vec<String>,
    pub settings: serde_json::Value,
}

/// What a config resolves to on this host.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Plan {
    /// the checkout, absolute
    pub workspace: PathBuf,
    /// the config it was read from, absolute
    pub config: PathBuf,
    /// `dev`, or a name under `[environments]`
    pub environment: String,
    pub state_dir: PathBuf,
    pub source: Source,
    /// where the checkout is in the guest
    pub workspace_folder: Option<String>,
    /// who exec, shell and SSH sessions run as
    pub user: Option<String>,
    pub freshness: Freshness,
    pub cpus: Option<Cpus>,
    pub mem: Option<String>,
    pub nested: Nested,
    /// extra binds, in name order, vk's own among them
    pub mounts: Vec<MountPlan>,
    pub container_env: Vec<EnvVar>,
    pub exec_env: Vec<EnvVar>,
    pub endpoints: Vec<EndpointPlan>,
    pub host_exec: Option<HostExecPlan>,
    pub ssh_agent: bool,
    pub cache: crate::dev::config::Cache,
    pub requires: Requires,
    /// the image is restored from the cache and never built (a `build` source only)
    pub cached_only: bool,
    /// the stage `cached_only` builds instead when the cache misses
    pub fallback_target: Option<String>,
    /// what `vk dev task` runs, in name order
    pub tasks: Vec<TaskPlan>,
    pub hooks: HooksPlan,
    pub vscode: Option<VsCodePlan>,
    /// mount sources under the state dir — editor servers, caches — that the boot creates
    /// before the VM mounts them, so an environment's managed storage exists from its first
    /// start and survives its refreshes. A share of a single file lands here too, so
    /// whatever creates these must not assume a directory.
    pub managed_dirs: Vec<PathBuf>,
    /// `${localEnv:…}` references this host could not fill, one message each. A plan with
    /// any is complete enough to print, compare, or stop — and not to boot or exec, since a
    /// session would then run with a token missing.
    pub unresolved: Vec<String>,
    /// What this host fed the config through `${localEnv:…}`, wherever it expanded: an
    /// environment value, a task's environment, a mount source, a build argument. Never
    /// serialized — it is the list of what a printed plan must not spell out.
    #[serde(skip)]
    pub secrets: BTreeSet<String>,
}

/// The name vk gives the mount it makes for a persistent editor server, reserved so a
/// configured mount cannot claim it.
const EDITOR_MOUNT: &str = "vscode-server";

/// What the state dir holds for the host's own use. A mount may not name these: a guest that
/// could write the key, the client config or the recorded identity would be steering the
/// host, and one that could read the key could reach the next boot too.
const RESERVED_STATE_ENTRIES: &[&str] = &[
    "editor",
    "endpoints.json",
    "id_ed25519",
    "id_ed25519.pub",
    "ssh-config",
    "bin",
    "dev.json",
    "lifecycle",
    "host-exec-wrapper",
    "boot.log",
    // `crate::publish`'s registry of what is published, which the host reads back
    "publish",
];

/// Resolve the environment `name` of a loaded config against this host.
pub fn resolve(loaded: &Loaded, name: &str) -> Result<Plan> {
    let env = loaded.environment(name)?;
    let at = match name {
        "dev" => "dev".to_string(),
        n => format!("environments.{n}"),
    };
    let workspace = std::fs::canonicalize(&loaded.files.workspace)
        .with_context(|| format!("resolving {}", loaded.files.workspace.display()))?;
    let config = std::fs::canonicalize(&loaded.files.config)
        .with_context(|| format!("resolving {}", loaded.files.config.display()))?;
    let state_dir = derived_state_dir(&workspace, name)?;
    let vars = Vars {
        workspace: workspace.clone(),
        state: state_dir.clone(),
        home: std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from),
        // SAFETY: geteuid/getegid always succeed and touch no memory.
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
        env_file: &loaded.env_file,
        missing: Default::default(),
        secrets: Default::default(),
    };

    let source = source_of(env, &at, &workspace, &vars)?;
    // Alone in its VM, the checkout reaches the guest only through the plan; a compose
    // service says where in its own `volumes:`.
    if !matches!(source, Source::Compose { .. }) && env.workspace.is_none() {
        bail!("[{at}] an image or build source needs `workspace`: where the checkout is mounted");
    }

    let vscode = match &env.editor.vscode {
        None => None,
        Some(vs) => Some(VsCodePlan {
            persistent: vs.state.unwrap_or_default() == crate::dev::config::EditorState::Persistent,
            home: vs
                .home
                .clone()
                .unwrap_or_else(|| guest_home(env.user.as_deref())),
            reconcile: vs
                .reconcile
                .as_ref()
                .map(|h| resolve_hook(h).with_context(|| format!("[{at}.editor.vscode] reconcile")))
                .transpose()?,
            extensions: vs.extensions.clone(),
            settings: serde_json::to_value(&vs.settings)
                .with_context(|| format!("[{at}.editor.vscode] settings"))?,
        }),
    };

    // vk's own mount for a persistent editor server, where the source has no compose file
    // to declare one: managed storage under the state dir, at the server's default data
    // directory. Reserved before the configured mounts are read, so a config cannot claim
    // either; added after the state-dir check, whose reserved `editor` entry it points into.
    let editor_mount = match vscode
        .as_ref()
        .filter(|vs| vs.persistent && !matches!(source, Source::Compose { .. }))
    {
        None => None,
        Some(vs) => {
            let key = format!("{at}.editor.vscode");
            let m = MountPlan {
                name: EDITOR_MOUNT.to_string(),
                source: state_dir.join("editor/vscode-server"),
                to: guest_path(&format!("{}/.vscode-server", vs.home))
                    .with_context(|| format!("[{key}] home"))?,
                read_only: false,
                optional: false,
            };
            // Through the same parse as a configured mount: `home` comes from the config,
            // and a `:` in it would rewrite the spec's mode rather than name a directory.
            let spec = m.spec().with_context(|| format!("[{key}]"))?;
            crate::compose::parse_volume(&spec, &workspace).with_context(|| format!("[{key}]"))?;
            Some(m)
        }
    };

    let taken = editor_mount
        .iter()
        .map(|m| (m.name.clone(), PathBuf::from(&m.to)))
        .collect();
    let resolved = mounts_of(env, &at, &workspace, &vars, taken)?;
    let mut managed_dirs = managed_storage(&resolved, &state_dir)?;
    let mut mounts: Vec<MountPlan> = resolved.into_iter().map(|r| r.mount).collect();
    if let Some(m) = editor_mount {
        managed_dirs.push(m.source.clone());
        mounts.push(m);
    }
    mounts.sort_by(|a, b| a.name.cmp(&b.name));

    let endpoints = endpoints_of(env, &at)?;

    let host_exec = match (env.host.git_gui, &env.host.wrapper) {
        (true, Some(_)) => bail!(
            "[{at}.host] choose one: git-gui = true or a wrapper, not both — a wrapper \
             can call `vk host-policy git-gui` itself"
        ),
        // The wrapper is generated at boot, into the state dir the guest cannot write.
        (true, None) => Some(HostExecPlan {
            wrapper: state_dir.join("host-exec-wrapper"),
            builtin: Some("git-gui".to_string()),
            env: Vec::new(),
        }),
        (false, Some(w)) => {
            let wrapper = in_workspace(&workspace, w);
            if !wrapper.is_file() {
                bail!("[{at}.host] wrapper {} does not exist", wrapper.display());
            }
            Some(HostExecPlan {
                wrapper,
                builtin: None,
                env: env.host.wrapper_env.clone(),
            })
        }
        (false, None) => None,
    };

    let hook = |name: &str, h: &Option<crate::dev::config::Hook>| -> Result<Option<HookPlan>> {
        h.as_ref()
            .map(|h| resolve_hook(h).with_context(|| format!("[{at}.hooks] {name}")))
            .transpose()
    };
    let hooks = HooksPlan {
        init: hook("init", &env.hooks.init)?,
        create: hook("create", &env.hooks.create)?,
        start: hook("start", &env.hooks.start)?,
    };
    let container_env = env_vars(&env.container_env, &vars)?;
    let exec_env = env_vars(&env.exec_env, &vars)?;

    let tasks = tasks_of(env, &at, loaded, &vars)?;

    let unresolved: Vec<String> = vars.missing.into_inner().into_iter().collect();
    let secrets = vars.secrets.into_inner();
    Ok(Plan {
        workspace,
        config,
        environment: name.to_string(),
        state_dir,
        source,
        workspace_folder: env.workspace.clone(),
        user: env.user.clone(),
        freshness: env.freshness.unwrap_or(Freshness::Ask),
        cpus: env.cpus,
        mem: env.mem.clone(),
        nested: env.nested,
        mounts,
        container_env,
        exec_env,
        endpoints,
        host_exec,
        ssh_agent: env.host.ssh_agent,
        cache: env.cache.clone(),
        requires: loaded.schema.requires.clone(),
        cached_only: env.cached_only,
        fallback_target: env.fallback.as_ref().and_then(|f| f.target.clone()),
        tasks,
        hooks,
        vscode,
        managed_dirs,
        unresolved,
        secrets,
    })
}

/// Resolve source paths against the workspace and check that they exist, catching missing
/// compose files and Dockerfiles before boot.
fn source_of(env: &Environment, at: &str, workspace: &Path, vars: &Vars) -> Result<Source> {
    Ok(match (&env.compose, &env.image, &env.build) {
        (Some(c), _, _) => {
            let file = in_workspace(workspace, c);
            if !file.is_file() {
                bail!("[{at}] compose {} does not exist", file.display());
            }
            Source::Compose {
                file,
                service: env
                    .service
                    .clone()
                    .with_context(|| format!("[{at}] compose needs `service`"))?,
                profiles: env.profiles.clone(),
            }
        }
        (_, Some(i), _) => Source::Image {
            reference: i.clone(),
        },
        (_, _, Some(b)) => {
            let context = in_workspace(
                workspace,
                b.context
                    .as_deref()
                    .with_context(|| format!("[{at}] build needs `context`"))?,
            );
            if !context.is_dir() {
                bail!(
                    "[{at}] build.context {} is not a directory",
                    context.display()
                );
            }
            let dockerfile = lexical_join(
                &context,
                Path::new(b.dockerfile.as_deref().unwrap_or("Dockerfile")),
            );
            if !dockerfile.is_file() {
                bail!(
                    "[{at}] build.dockerfile {} does not exist",
                    dockerfile.display()
                );
            }
            let mut args = Vec::new();
            for (name, value) in &b.args {
                args.push((
                    name.clone(),
                    vars.expand(value)
                        .with_context(|| format!("[{at}] build arg {name}"))?
                        .value,
                ));
            }
            Source::Build {
                context,
                dockerfile,
                target: b.target.clone(),
                args,
            }
        }
        (None, None, None) => bail!("[{at}] names no source"),
    })
}

/// A configured mount and the share it parses to. `None` for an `optional` source that is
/// absent: the boot skips that mount, and what is not there cannot hold the state directory
/// either.
struct Resolved {
    mount: MountPlan,
    share: Option<crate::compose::Volume>,
}

/// The configured mounts, in name order, each parsed once as the share `vk run` will make
/// of it. `taken` starts with the name and guest path vk mounts itself under, so a config
/// claiming either is refused here rather than mounted twice.
fn mounts_of(
    env: &Environment,
    at: &str,
    workspace: &Path,
    vars: &Vars,
    taken: BTreeSet<(String, PathBuf)>,
) -> Result<Vec<Resolved>> {
    let mut names: BTreeSet<String> = taken.iter().map(|(n, _)| n.clone()).collect();
    let mut targets: BTreeSet<PathBuf> = taken.into_iter().map(|(_, t)| t).collect();
    let mut mounts = Vec::new();
    for (mname, m) in env.mounts.iter().filter(|(_, m)| m.enabled) {
        let key = format!("{at}.mounts.{mname}");
        let source = vars
            .expand(m.source.as_deref().unwrap_or_default())
            .with_context(|| format!("[{key}] source"))?
            .value;
        let to = vars
            .expand(m.to.as_deref().unwrap_or_default())
            .with_context(|| format!("[{key}] to"))?
            .value;
        if source.is_empty() || to.is_empty() {
            bail!("[{key}] needs both `source` and `to`");
        }
        // `:` separates the fields of the `vk run -v` spec these become, so one inside a
        // path would set the volume's mode instead of naming a file.
        if source.contains(':') {
            bail!("[{key}] source {source:?} contains ':', which separates a mount's fields");
        }
        // A host path relative to the project, like every other path in the file, and folded
        // either way: `${state}/x/../id_ed25519` names the key, and the checks below compare
        // paths rather than guess at what a `..` in one would reach.
        let source =
            crate::dev::config::lexical_normalize(&match Path::new(&source).is_absolute() {
                true => PathBuf::from(source),
                false => in_workspace(workspace, &source),
            });
        if source
            .components()
            .any(|c| c == std::path::Component::ParentDir)
        {
            bail!(
                "[{key}] source {} escapes upward; write the path it means",
                source.display()
            );
        }
        let to = guest_path(&to).with_context(|| format!("[{key}] to"))?;
        if !names.insert(mname.clone()) {
            bail!("[{key}] {mname} is the name of a mount vk makes itself; choose another");
        }
        if !targets.insert(PathBuf::from(&to)) {
            bail!("[{key}] mounts {to} a second time; one guest path takes one mount");
        }
        let mount = MountPlan {
            name: mname.clone(),
            source,
            to,
            read_only: m.read_only,
            optional: m.optional,
        };
        // Parsed now so a spec `vk run` would refuse names its config key, and so the
        // state-dir check below sees every share.
        let spec = mount.spec().with_context(|| format!("[{key}]"))?;
        let share =
            crate::compose::parse_volume(&spec, workspace).with_context(|| format!("[{key}]"))?;
        mounts.push(Resolved { mount, share });
    }
    Ok(mounts)
}

/// The mount sources under the state directory: managed storage, created by the boot and
/// kept across refreshes, and never one of the entries the host keeps there for itself.
/// Every other source is checked against the state directory as a whole, which is the
/// host's alone.
///
/// Both sides are resolved first: a symlink whose name says nothing about the state dir but
/// which lands on `lifecycle` or `dev.json` is that entry.
fn managed_storage(mounts: &[Resolved], state_dir: &Path) -> Result<Vec<PathBuf>> {
    use std::os::unix::ffi::OsStrExt;
    let resolved_state = resolve_symlinks(state_dir);
    let mut managed_dirs = Vec::new();
    let mut volumes = Vec::new();
    for m in mounts {
        // An `optional` bind whose source is absent has no share: that mount is skipped at
        // boot, and what is not there cannot hold the state dir anyway.
        let Some(v) = &m.share else { continue };
        let name = &m.mount.name;
        let host = resolve_symlinks(&v.host);
        match host.strip_prefix(&resolved_state) {
            Ok(rel) if !rel.as_os_str().is_empty() => {
                let Some(first) = rel.components().next().map(|c| c.as_os_str()) else {
                    bail!("mount {name}: empty path under the state directory");
                };
                if RESERVED_STATE_ENTRIES
                    .iter()
                    .any(|e| first == std::ffi::OsStr::new(e))
                    || first.as_bytes().starts_with(b".")
                {
                    bail!(
                        "mount {name}: {} under the state directory is the host's own; \
                         managed storage needs another name",
                        Path::new(first).display()
                    );
                }
                managed_dirs.push(v.host.clone());
            }
            Ok(_) => bail!(
                "mount {name}: the state directory is the host's own — keys, logs, the \
                 recorded identity; mount a subdirectory of it instead"
            ),
            // Nothing to do with the state dir; the checks below have the last word.
            Err(_) => volumes.push((name, v, host)),
        }
    }
    // The state dir holds what the host reads back — keys, logs, the host-exec allowlist —
    // so a guest that could write it would be steering the host. A share `hooks.init` has
    // yet to create cannot be canonicalized, so the containment its future contents would
    // give the guest is decided here, from the symlink-resolved paths.
    for (name, v, host) in &volumes {
        let writable = !(v.read_only || v.overlay || v.disk || v.socket);
        if writable && resolved_state.starts_with(host) {
            bail!(
                "mount {name}: {} holds the state directory, which the guest would then \
                 mount read-write — mount something that does not contain it",
                host.display()
            );
        }
    }
    // The shares that do exist go through the full check, which also covers the host's own
    // entries. Planning happens before `up` creates the state dir, so hand it the nearest
    // ancestor that exists: `dir.starts_with(share)` answers the same for an ancestor of a
    // path a share contains, and every entry the check derives from `dir` is one that cannot
    // exist yet either.
    let present: Vec<&crate::compose::Volume> = volumes
        .iter()
        .filter(|(_, v, _)| v.host.exists())
        .map(|(_, v, _)| *v)
        .collect();
    let existing = state_dir
        .ancestors()
        .find(|p| p.exists())
        .unwrap_or(state_dir);
    crate::sshclient::check_state_dir_is_host_only(existing, present, [])
        .context("checking the mounts against the state directory")?;
    Ok(managed_dirs)
}

/// The endpoints to publish, in name order: one host address and port each, checked here
/// for what only fails once the VM is up — a privileged port, an address two of them share.
fn endpoints_of(env: &Environment, at: &str) -> Result<Vec<EndpointPlan>> {
    let mut endpoints = Vec::new();
    let mut listens = BTreeSet::new();
    let floor = lowest_bindable_port();
    for (ename, e) in env.endpoints.iter().filter(|(_, e)| e.enabled) {
        let key = format!("{at}.endpoints.{ename}");
        crate::publish::validate_name(ename).with_context(|| format!("[{key}]"))?;
        let target = e
            .target
            .with_context(|| format!("[{key}] needs `target`"))?;
        let host_port = e.host_port.unwrap_or(target);
        refuse_privileged(host_port, floor).with_context(|| format!("[{key}]"))?;
        // `auto` is one loopback address per (environment, service), so two auto endpoints
        // of one service on one port collide as surely as two fixed ones.
        let address = match e.address.as_deref() {
            None | Some("auto") => "auto".to_string(),
            Some(a) => a.to_string(),
        };
        let listen = format!("tcp://{address}:{host_port}");
        let slot = (e.service.clone(), listen.clone());
        if !listens.insert(slot) {
            bail!("[{key}] publishes {listen}, which another endpoint already takes");
        }
        let to = match &e.service {
            Some(s) => format!("tcp://{s}:{target}"),
            None => format!("tcp://127.0.0.1:{target}"),
        };
        if let Some(scheme) = &e.scheme
            && !scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            bail!("[{key}] scheme {scheme:?} is not a URL scheme");
        }
        if let Some(path) = &e.path
            && !path.starts_with('/')
        {
            bail!("[{key}] path {path:?} must start with '/'");
        }
        endpoints.push(EndpointPlan {
            name: ename.clone(),
            service: e.service.clone(),
            host_port,
            address,
            listen,
            to,
            scheme: e.scheme.clone(),
            path: e.path.clone(),
            required: e.required,
        });
    }
    Ok(endpoints)
}

/// A host port this user cannot bind: it fails once the VM is already up, so refuse it
/// while there is still a config key to name.
fn refuse_privileged(host_port: u16, floor: u16) -> Result<()> {
    if host_port < floor {
        bail!(
            "host-port {host_port}: this user cannot bind a port below {floor} — publish an \
             unprivileged port instead"
        );
    }
    Ok(())
}

/// What `vk dev task` runs, in name order, with the environment each names checked against
/// the config that declares it.
fn tasks_of(env: &Environment, at: &str, loaded: &Loaded, vars: &Vars) -> Result<Vec<TaskPlan>> {
    let mut tasks = Vec::new();
    for (tname, t) in env.tasks.iter().filter(|(_, t)| t.enabled) {
        let key = format!("{at}.tasks.{tname}");
        let environment = t.environment.clone().unwrap_or_else(|| "dev".into());
        let reuse = t.reuse.clone().unwrap_or_else(|| environment.clone());
        // Named here, resolved when the task runs: a task pointing at an environment the
        // config does not declare is a typo, and the place to hear about it is the plan.
        for e in [&environment, &reuse] {
            loaded.environment(e).with_context(|| format!("[{key}]"))?;
        }
        tasks.push(TaskPlan {
            name: tname.clone(),
            argv: command_argv(
                &checked_command(
                    t.run
                        .as_ref()
                        .with_context(|| format!("[{key}] needs `run`"))?,
                )
                .with_context(|| format!("[{key}]"))?,
            ),
            environment,
            reuse,
            policy: t.policy.unwrap_or(Policy::ReuseOrEphemeral),
            checkout: t.checkout.unwrap_or_default(),
            env: env_vars(&t.env, vars).with_context(|| format!("[{key}]"))?,
        });
    }
    Ok(tasks)
}

impl Plan {
    /// Whether the run asks for nested virtualization on this host: always for
    /// `nested = true` (and `vk run` says why when the host cannot), only where the host
    /// allows it for `"auto"`.
    pub fn nests_here(&self) -> bool {
        match self.nested {
            Nested::Off => false,
            Nested::Auto => crate::vmm::host_nesting_enabled(),
            Nested::Required => true,
        }
    }

    /// Fail unless every `${localEnv:…}` was filled — the gate before a boot or a session,
    /// where an empty token would be worse than a refusal.
    pub fn require_resolved(&self) -> Result<()> {
        if self.unresolved.is_empty() {
            return Ok(());
        }
        bail!(
            "the config refers to host variables this shell does not have:\n  {}",
            self.unresolved.join("\n  ")
        )
    }
}

/// A path a config wrote, relative to the project like every other path in the file.
fn in_workspace(workspace: &Path, rel: &str) -> PathBuf {
    lexical_join(workspace, Path::new(rel))
}

/// Normalize guest paths lexically; the host cannot canonicalize them. `/home/dev/.config`,
/// `/home/dev/.config/` and `/home/dev/./.config` identify the same mount target.
fn guest_path(to: &str) -> Result<String> {
    if to.contains(':') {
        bail!("guest path {to:?} contains ':', which separates a mount's fields");
    }
    let folded = crate::dev::config::lexical_normalize(Path::new(to));
    Ok(utf8(&folded, "a guest path")?.to_string())
}

/// The guest home for a user, overridable as `editor.vscode.home`.
fn guest_home(user: Option<&str>) -> String {
    match user {
        None | Some("root") => "/root".to_string(),
        Some(u) => format!("/home/{u}"),
    }
}

/// A configured command as the argv that runs. A string is what a config means when it
/// writes `a && b`, so it goes through a shell; a list is written as a list to avoid one.
fn command_argv(c: &Command) -> Vec<String> {
    match c {
        Command::Shell(s) => vec!["/bin/sh".into(), "-c".into(), s.clone()],
        Command::Argv(a) => a.clone(),
    }
}

/// Reject an empty argv list.
fn checked_command(c: &Command) -> Result<Command> {
    if matches!(c, Command::Argv(a) if a.is_empty()) {
        bail!("the argv list is empty");
    }
    Ok(c.clone())
}

/// A hook as written, resolved to what runs.
fn resolve_hook(h: &crate::dev::config::Hook) -> Result<HookPlan> {
    use crate::dev::config::Hook as Configured;
    // The plain forms take the defaults; only the option form says otherwise.
    let plain = |run: Command| {
        HookPlan::Command(HookCommand {
            run,
            cwd: None,
            timeout_secs: None,
            required: true,
        })
    };
    Ok(match h {
        Configured::Shell(s) => plain(Command::Shell(s.clone())),
        Configured::Argv(a) if a.is_empty() => bail!("the argv list is empty"),
        Configured::Argv(a) => plain(Command::Argv(a.clone())),
        Configured::Detailed(spec) => HookPlan::Command(HookCommand {
            run: checked_command(spec.run.as_ref().context("needs `run`")?)?,
            cwd: spec.cwd.clone(),
            timeout_secs: spec
                .timeout
                .as_deref()
                .map(crate::dev::config::parse_duration)
                .transpose()?
                .map(|d| d.as_secs()),
            required: spec.required,
        }),
        Configured::Group(group) => HookPlan::Group(
            group
                .iter()
                .map(|(k, v)| {
                    resolve_hook(v)
                        .map(|h| (k.clone(), h))
                        .with_context(|| k.clone())
                })
                .collect::<Result<_>>()?,
        ),
    })
}

/// State directory name components: workspace, environment, and their digest.
struct NameParts {
    /// the workspace's basename, everything but `[A-Za-z0-9.-]` turned into `-`
    readable: String,
    /// `-<environment>`, empty for `dev`
    suffix: String,
    /// 16 hex digits of sha256(canonical workspace, NUL, environment)
    slug: String,
}

impl NameParts {
    fn of(workspace: &Path, environment: &str) -> Result<NameParts> {
        use sha2::{Digest, Sha256};
        use std::os::unix::ffi::OsStrExt;
        let mut hasher = Sha256::new();
        hasher.update(workspace.as_os_str().as_bytes());
        hasher.update([0]);
        hasher.update(environment.as_bytes());
        let digest = hasher.finalize();
        let slug: String = digest
            .get(..8)
            .context("sha256 returned fewer than 8 bytes")?
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let name = workspace
            .file_name()
            .filter(|n| !n.as_bytes().is_empty())
            .unwrap_or_else(|| std::ffi::OsStr::new("workspace"));
        // One ASCII byte per input byte: truncation before or after conversion is equivalent.
        let readable: String = name
            .as_bytes()
            .iter()
            .take(READABLE_MAX)
            .map(|&b| match b {
                b'.' | b'-' => char::from(b),
                b if b.is_ascii_alphanumeric() => char::from(b),
                _ => '-',
            })
            .collect();
        Ok(NameParts {
            readable,
            suffix: match environment {
                "dev" => String::new(),
                e => format!("-{e}"),
            },
            slug,
        })
    }

    /// `{readable}{suffix}-{slug}`, with the workspace name truncated to fit under `base`.
    fn environment_dir(&self, base: &Path) -> Result<String> {
        let room = state_dir_room(base)?;
        // Reject names with no room for at least one workspace byte.
        let fits = room
            .checked_sub(self.suffix.len() + 1 + self.slug.len())
            .filter(|r| *r >= 1)
            .ok_or_else(|| no_room(base))?;
        let readable = &self.readable[..fits.min(self.readable.len())];
        Ok(format!("{readable}{}-{}", self.suffix, self.slug))
    }

    /// `{readable}{suffix}-task-{name}-{token}`, the workspace name given up before the task
    /// name: the environment's own directory sits beside this one and still spells the
    /// workspace out, while the task name is what tells one ephemeral run from another.
    ///
    /// No digest here. The token already makes the name unique, and the 17 bytes a slug
    /// would take are what keep both names readable within the socket path limit.
    ///
    /// `name` is byte-truncated, so the caller passes it already folded to ASCII.
    fn task_dir(&self, base: &Path, name: &str, token: &str) -> Result<String> {
        debug_assert!(
            name.is_ascii(),
            "task name must be folded to ASCII: {name:?}"
        );
        let room = state_dir_room(base)?;
        let fixed = self.suffix.len() + "-task-".len() + 1 + token.len();
        // At least one byte of each name.
        let avail = room
            .checked_sub(fixed)
            .filter(|a| *a >= 2)
            .ok_or_else(|| no_room(base))?;
        let mut readable = self.readable.len();
        let mut task = name.len().min(TASK_NAME_MAX);
        if readable + task > avail {
            readable = readable.min(avail.saturating_sub(task)).max(1);
            task = task.min(avail - readable);
        }
        Ok(format!(
            "{}{}-task-{}-{token}",
            &self.readable[..readable],
            self.suffix,
            &name[..task]
        ))
    }
}

/// Maximum workspace basename bytes in a directory name, subject to available room.
const READABLE_MAX: usize = 64;

/// Maximum `[dev.tasks.<name>]` bytes in an ephemeral run's directory name.
const TASK_NAME_MAX: usize = 32;

/// Directory name budget: [`crate::run::STATE_DIR_MAX`] minus `base` and its separator.
fn state_dir_room(base: &Path) -> Result<usize> {
    crate::run::STATE_DIR_MAX
        .checked_sub(base.as_os_str().len() + 1)
        .filter(|room| *room >= 1)
        .ok_or_else(|| no_room(base))
}

fn no_room(base: &Path) -> anyhow::Error {
    anyhow!(
        "{} leaves no room for a VM's own state directory: its sockets are bound under \
         that directory and a unix socket path holds at most {} bytes. Point XDG_STATE_HOME \
         at a shorter path.",
        base.display(),
        crate::run::SUN_PATH_MAX
    )
}

/// The state dir an environment gets: a readable name plus a digest of what identifies it —
/// the canonical workspace path and the environment name — so two worktrees of one repo,
/// and two environments of one workspace, never share a VM, and the same one always resolves
/// to the same directory.
fn derived_state_dir(workspace: &Path, environment: &str) -> Result<PathBuf> {
    let base = dev_state_base()?;
    let name = NameParts::of(workspace, environment)?.environment_dir(&base)?;
    Ok(base.join(name))
}

/// Name of an ephemeral task's state directory, beside the environment's directory.
pub(super) fn task_state_dir_name(plan: &Plan, task_name: &str, token: &str) -> Result<String> {
    let base = plan
        .state_dir
        .parent()
        .with_context(|| format!("{} has no parent directory", plan.state_dir.display()))?;
    // Non-alphanumerics folded away, so the name is one ASCII byte per character here too.
    let name: String = task_name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    NameParts::of(&plan.workspace, &plan.environment)?.task_dir(base, &name, token)
}

/// `path` with the symlinks it does have resolved, keeping the tail that does not exist
/// yet: what a mount source means, for a comparison a symlink must not slip past. Neither
/// the state directory nor a mount source is required to exist when a plan is made.
fn resolve_symlinks(path: &Path) -> PathBuf {
    let mut tail = Vec::new();
    let mut at = path;
    loop {
        if let Ok(resolved) = std::fs::canonicalize(at) {
            return tail.iter().rev().fold(resolved, |p, name| p.join(name));
        }
        match (at.file_name(), at.parent()) {
            (Some(name), Some(parent)) => {
                tail.push(name.to_os_string());
                at = parent;
            }
            // A root, or a path with nothing left to strip: nothing was resolvable.
            _ => return path.to_path_buf(),
        }
    }
}

/// One expanded string, and whether the host environment fed it.
#[derive(Debug)]
struct Expanded {
    value: String,
    sensitive: bool,
}

/// The substitutions a config may use: `~`, `${HOME}`, `${workspace}`, `${state}`,
/// `${VK_UID}`, `${VK_GID}` and `${localEnv:NAME}` (or `${localEnv:NAME:default}`).
/// Deliberately few: an unknown `${…}` is an error, so a config written against a variable
/// vk does not implement fails rather than mounting a path with `${...}` in its name.
struct Vars<'a> {
    workspace: PathBuf,
    state: PathBuf,
    home: Option<PathBuf>,
    /// `${VK_UID}` / `${VK_GID}`: the host identity a build arg hands an image so a shared
    /// tree's ownership stays coherent — spelled as compose spells them
    uid: u32,
    gid: u32,
    /// `local.env` and friends: consulted after the process environment
    env_file: &'a BTreeMap<String, String>,
    /// `${localEnv:…}` this host could not fill, for [`Plan::unresolved`]: recorded rather
    /// than failing the whole plan, so `status` and `stop` still work without a token
    /// exported in this shell. A set: one message per variable, whatever else was expanded
    /// between two of its uses.
    missing: std::cell::RefCell<BTreeSet<String>>,
    /// Every value this host fed a `${localEnv:…}` with, for [`Plan::secrets`]. An empty
    /// value is not recorded — it would match every empty string in the plan.
    secrets: std::cell::RefCell<BTreeSet<String>>,
}

impl Vars<'_> {
    fn home(&self) -> Result<&Path> {
        self.home
            .as_deref()
            .context("HOME is not set, and the config refers to it")
    }

    /// Read the process environment before the local env file. An empty value is present;
    /// invalid UTF-8 is an error, so the user is not told to export an already set variable.
    fn local_env(&self, name: &str) -> Result<Option<String>> {
        match std::env::var_os(name) {
            Some(v) => Ok(Some(v.into_string().map_err(|_| {
                anyhow!("${{localEnv:{name}}} is set but not valid UTF-8")
            })?)),
            None => Ok(self.env_file.get(name).cloned()),
        }
    }

    fn expand(&self, text: &str) -> Result<Expanded> {
        let mut out = String::with_capacity(text.len());
        let mut sensitive = false;
        // `~` means the home directory only where a shell would take it so: alone, or at
        // the start of a path.
        let mut rest = match text.strip_prefix('~') {
            Some(r) if r.is_empty() || r.starts_with('/') => {
                out.push_str(&self.home()?.to_string_lossy());
                r
            }
            _ => text,
        };
        while let Some(start) = rest.find("${") {
            out.push_str(&rest[..start]);
            let after = &rest[start + 2..];
            let end = after
                .find('}')
                .with_context(|| format!("unterminated ${{…}} in {text:?}"))?;
            let name = &after[..end];
            rest = &after[end + 1..];
            // `${localEnv:NAME:default}` splits twice and no further: a default is a value,
            // and a URL or a path list has colons of its own.
            match name.split_once(':') {
                None => match name {
                    "HOME" => out.push_str(&self.home()?.to_string_lossy()),
                    "workspace" => out.push_str(&self.workspace.to_string_lossy()),
                    "state" => out.push_str(&self.state.to_string_lossy()),
                    "VK_UID" => out.push_str(&self.uid.to_string()),
                    "VK_GID" => out.push_str(&self.gid.to_string()),
                    _ => bail!("${{{name}}} is not a variable vk substitutes"),
                },
                Some(("localEnv", rest)) => {
                    let (var, default) = match rest.split_once(':') {
                        Some((var, default)) => (var, Some(default)),
                        None => (rest, None),
                    };
                    match self.local_env(var)? {
                        Some(v) => {
                            sensitive = true;
                            if !v.is_empty() {
                                self.secrets.borrow_mut().insert(v.clone());
                            }
                            out.push_str(&v);
                        }
                        // Absent is a config asking for something this host does not have:
                        // noted, and refused by whatever would run with the value missing —
                        // unless the config says what to use instead.
                        None => match default {
                            Some(d) => out.push_str(d),
                            None => {
                                self.missing.borrow_mut().insert(format!(
                                    "${{localEnv:{var}}} is not set — export it, put it in \
                                     .virtkit/local.env, or give it a default as \
                                     ${{localEnv:{var}:default}}"
                                ));
                                sensitive = true;
                            }
                        },
                    }
                }
                Some(_) => bail!("${{{name}}} is not a variable vk substitutes"),
            }
        }
        out.push_str(rest);
        Ok(Expanded {
            value: out,
            sensitive,
        })
    }
}

fn env_vars(map: &BTreeMap<String, String>, vars: &Vars) -> Result<Vec<EnvVar>> {
    let mut out = Vec::new();
    for (name, value) in map {
        let e = vars
            .expand(value)
            .with_context(|| format!("environment variable {name}"))?;
        out.push(EnvVar {
            name: name.clone(),
            value: e.value,
            sensitive: e.sensitive,
        });
    }
    Ok(out)
}

/// The lowest port this user may bind. Linux lets a host lower it
/// (`net.ipv4.ip_unprivileged_port_start`), and several do, so ask rather than assume 1024.
fn lowest_bindable_port() -> u16 {
    // SAFETY: geteuid always succeeds and touches no memory.
    if unsafe { libc::geteuid() } == 0 {
        return 0;
    }
    // A kernel without that sysctl enforces 1024 itself, and one that answers something
    // this cannot parse has named no lower floor: 1024 either way, not a swallowed failure.
    std::fs::read_to_string("/proc/sys/net/ipv4/ip_unprivileged_port_start")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(1024)
}

/// What a printed plan says in place of a value it does not print. Fixed text: a length is
/// itself something about the value.
const REDACTED: &str = "<redacted: --show-secrets prints it>";

impl Plan {
    /// Render the canonical JSON plan. Unless `reveal`, redact every environment value and
    /// build argument: literals in `local.toml` may contain tokens just as exported values do.
    pub fn to_json(&self, reveal: bool) -> Result<String> {
        let mut plan = self.clone();
        if !reveal {
            plan.redact();
        }
        Ok(serde_json::to_string_pretty(&plan).context("serializing the plan")? + "\n")
    }

    /// Replace every value a config hands to a command or an image with [`REDACTED`] — the
    /// two environment scopes, a task's environment, the build arguments — and then scrub
    /// what this host fed the config out of every other string, since a `${localEnv:…}`
    /// expands into a mount source or a guest path as readily as into an environment value,
    /// and there it has no provenance of its own to be redacted by.
    fn redact(&mut self) {
        let envs = self
            .container_env
            .iter_mut()
            .chain(&mut self.exec_env)
            .chain(self.tasks.iter_mut().flat_map(|t| &mut t.env));
        for e in envs {
            e.value = REDACTED.to_string();
        }
        if let Source::Build { args, .. } = &mut self.source {
            for (_, value) in args {
                *value = REDACTED.to_string();
            }
        }
        // Longest first: a secret that contains another must not be replaced piecemeal.
        let mut secrets: Vec<String> = self.secrets.iter().cloned().collect();
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        if secrets.is_empty() {
            return;
        }
        let s = &secrets;
        match &mut self.source {
            Source::Compose {
                service, profiles, ..
            } => {
                scrub(s, service);
                profiles.iter_mut().for_each(|p| scrub(s, p));
            }
            Source::Image { reference } => scrub(s, reference),
            Source::Build { target, args, .. } => {
                if let Some(t) = target {
                    scrub(s, t);
                }
                args.iter_mut().for_each(|(name, _)| scrub(s, name));
            }
        }
        if let Some(f) = &mut self.workspace_folder {
            scrub(s, f);
        }
        if let Some(u) = &mut self.user {
            scrub(s, u);
        }
        for m in &mut self.mounts {
            scrub_path(s, &mut m.source);
            scrub(s, &mut m.to);
        }
        for e in &mut self.endpoints {
            if let Some(service) = &mut e.service {
                scrub(s, service);
            }
            scrub(s, &mut e.address);
            scrub(s, &mut e.listen);
            scrub(s, &mut e.to);
            if let Some(scheme) = &mut e.scheme {
                scrub(s, scheme);
            }
            if let Some(path) = &mut e.path {
                scrub(s, path);
            }
        }
        if let Some(h) = &mut self.host_exec {
            scrub_path(s, &mut h.wrapper);
            h.env.iter_mut().for_each(|e| scrub(s, e));
        }
        for t in &mut self.tasks {
            t.argv.iter_mut().for_each(|a| scrub(s, a));
            scrub(s, &mut t.environment);
            scrub(s, &mut t.reuse);
        }
        for h in [
            &mut self.hooks.init,
            &mut self.hooks.create,
            &mut self.hooks.start,
        ]
        .into_iter()
        .flatten()
        {
            h.scrub(s);
        }
        if let Some(vs) = &mut self.vscode {
            scrub(s, &mut vs.home);
            vs.extensions.iter_mut().for_each(|e| scrub(s, e));
            if let Some(r) = &mut vs.reconcile {
                r.scrub(s);
            }
            scrub_json(s, &mut vs.settings);
        }
        self.managed_dirs.iter_mut().for_each(|d| scrub_path(s, d));
    }

    /// The plan as the `vk run` it stands for. For reading: the hooks and publishers are
    /// comments, being steps around the boot rather than arguments to it — but a reader may
    /// well copy it, so every path is spelled exactly and one this host does not spell in
    /// UTF-8 is an error.
    pub fn to_shell(&self, reveal: bool) -> Result<String> {
        match reveal {
            true => self.render_shell(),
            // Redacted on a copy, so every word below is rendered from something already
            // safe to print — a mount source a `${localEnv:…}` filled in included.
            false => {
                let mut plan = self.clone();
                plan.redact();
                plan.render_shell()
            }
        }
    }

    fn render_shell(&self) -> Result<String> {
        let mut out = String::from("vk run \\\n");
        match &self.source {
            Source::Compose {
                file,
                service,
                profiles,
            } => {
                arg(&mut out, "--compose", utf8(file, "the compose file")?);
                arg(&mut out, "--primary", service);
                for p in profiles {
                    arg(&mut out, "--profile", p);
                }
            }
            Source::Image { reference } => arg(&mut out, "--image", reference),
            Source::Build {
                context,
                dockerfile,
                target,
                args,
            } => {
                arg(&mut out, "--file", utf8(dockerfile, "the Dockerfile")?);
                arg(&mut out, "--context", utf8(context, "the build context")?);
                if let Some(t) = target {
                    arg(&mut out, "--target", t);
                }
                for (name, value) in args {
                    arg(&mut out, "--build-arg", &format!("{name}={value}"));
                }
            }
        }
        let workspace = utf8(&self.workspace, "the workspace")?;
        let state_dir = utf8(&self.state_dir, "the state directory")?;
        arg(&mut out, "--workspace", workspace);
        arg(&mut out, "--state-dir", state_dir);
        if let Some(c) = &self.cpus {
            arg(&mut out, "--cpus", &c.to_string());
        }
        if let Some(m) = &self.mem {
            arg(&mut out, "--mem", m);
        }
        if !matches!(self.source, Source::Compose { .. })
            && let Some(folder) = &self.workspace_folder
        {
            arg(&mut out, "-v", &format!("{workspace}:{folder}"));
        }
        for m in &self.mounts {
            arg(&mut out, "-v", &m.spec()?);
        }
        for e in &self.container_env {
            arg(&mut out, "--env", &format!("{}={}", e.name, e.value));
        }
        if let Some(h) = &self.host_exec {
            arg(
                &mut out,
                "--host-exec-wrapper",
                utf8(&h.wrapper, "the host-exec wrapper")?,
            );
        }
        if let Some(r) = &self.cache.registry {
            arg(&mut out, "--cache-registry", r);
        }
        if let Some(u) = &self.user {
            arg(&mut out, "--ssh-user", u);
        }
        if self.ssh_agent {
            out.push_str("  --ssh-agent \\\n");
        }
        if self.nests_here() {
            out.push_str("  --nested \\\n");
        }
        if self.cached_only {
            out.push_str("  --require-cached \\\n");
        }
        out.push_str("  --ssh-client\n");
        if let Some(h) = &self.host_exec
            && let Some(builtin) = &h.builtin
        {
            comment(
                &mut out,
                &format!("the wrapper is generated at boot: vk's built-in {builtin} policy"),
            );
        }
        if let Some(t) = &self.fallback_target {
            comment(
                &mut out,
                &format!("on a cache miss: the same, --target {t}"),
            );
        }
        for t in &self.tasks {
            let argv = t
                .argv
                .iter()
                .map(|a| crate::shell::quote_word(a))
                .collect::<Vec<_>>()
                .join(" ");
            comment(
                &mut out,
                &format!(
                    "vk dev task {}: {argv} ({} in {})",
                    crate::shell::quote_word(&t.name),
                    t.policy.as_str(),
                    crate::shell::quote_word(&t.environment),
                ),
            );
        }
        for p in &self.endpoints {
            comment(
                &mut out,
                &format!(
                    "vk publish ensure {} --name {} --listen {} --to {}{}",
                    crate::shell::quote_word(state_dir),
                    crate::shell::quote_word(&p.name),
                    crate::shell::quote_word(&p.listen),
                    crate::shell::quote_word(&p.to),
                    if p.required { "  # required" } else { "" }
                ),
            );
        }
        for (when, hook) in [
            ("hooks.init (host, before the boot)", &self.hooks.init),
            (
                "hooks.create (guest, once per generation)",
                &self.hooks.create,
            ),
            ("hooks.start (guest, each start)", &self.hooks.start),
        ] {
            if let Some(h) = hook {
                comment(&mut out, &format!("{when}: {}", h.describe()));
            }
        }
        Ok(out)
    }
}

/// Replace every secret in `text` with [`REDACTED`].
fn scrub(secrets: &[String], text: &mut String) {
    for s in secrets {
        if text.contains(s.as_str()) {
            *text = text.replace(s.as_str(), REDACTED);
        }
    }
}

/// As [`scrub`], for a path. One this host does not spell in UTF-8 is left alone: rewriting
/// it would name a different file, and [`utf8`] refuses it where it would be printed.
fn scrub_path(secrets: &[String], path: &mut PathBuf) {
    let Some(text) = path.to_str() else { return };
    let mut text = text.to_string();
    scrub(secrets, &mut text);
    *path = PathBuf::from(text);
}

/// As [`scrub`], through the editor settings a config supplies as free-form JSON.
fn scrub_json(secrets: &[String], value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) => scrub(secrets, s),
        serde_json::Value::Array(a) => a.iter_mut().for_each(|v| scrub_json(secrets, v)),
        serde_json::Value::Object(o) => o.values_mut().for_each(|v| scrub_json(secrets, v)),
        _ => {}
    }
}

/// Append a `flag value` line with shell quoting. A function avoids holding `out` borrowed
/// across direct writes between calls, as a capturing closure would.
fn arg(out: &mut String, flag: &str, value: &str) {
    out.push_str(&format!(
        "  {flag} {} \\\n",
        crate::shell::quote_word(value)
    ));
}

/// Prefix every rendered comment line with `# `, including multiline TOML hook strings,
/// so copying the output cannot turn continuation lines into commands.
fn comment(out: &mut String, text: &str) {
    for line in text.trim_end_matches('\n').split('\n') {
        out.push_str("# ");
        out.push_str(line);
        out.push('\n');
    }
}

/// `path` as text, or an error naming `what` when this host does not spell it in UTF-8.
/// Replacing the bytes it cannot encode would name a different file.
fn utf8<'a>(path: &'a Path, what: &str) -> Result<&'a str> {
    path.to_str()
        .with_context(|| format!("{what} ({}) is not valid UTF-8", path.display()))
}

impl HookPlan {
    /// One line saying what would run, for the plan's shell rendering.
    pub fn describe(&self) -> String {
        match self {
            HookPlan::Command(c) => {
                // As the config wrote it: a shell line reads as itself, and an argv list as
                // the words it is.
                let mut s = match &c.run {
                    Command::Shell(line) => line.clone(),
                    Command::Argv(a) => a
                        .iter()
                        .map(|w| crate::shell::quote_word(w))
                        .collect::<Vec<_>>()
                        .join(" "),
                };
                if let Some(cwd) = &c.cwd {
                    s.push_str(&format!(" (in {})", crate::shell::quote_word(cwd)));
                }
                if let Some(t) = c.timeout_secs {
                    s.push_str(&format!(" (within {t}s)"));
                }
                if !c.required {
                    s.push_str(" (best effort)");
                }
                s
            }
            HookPlan::Group(map) => map
                .iter()
                .map(|(name, h)| format!("{name}: {}", h.describe()))
                .collect::<Vec<_>>()
                .join("; "),
        }
    }

    /// Replace every secret in what this hook runs, and where.
    fn scrub(&mut self, secrets: &[String]) {
        match self {
            HookPlan::Command(c) => {
                match &mut c.run {
                    Command::Shell(line) => scrub(secrets, line),
                    Command::Argv(a) => a.iter_mut().for_each(|w| scrub(secrets, w)),
                }
                if let Some(cwd) = &mut c.cwd {
                    scrub(secrets, cwd);
                }
            }
            HookPlan::Group(map) => map.values_mut().for_each(|h| h.scrub(secrets)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The process environment is shared by every test in this binary, and these tests set
    /// variables a config reads. Hold this while doing so, and take it back after a panic
    /// rather than failing every later test with a poisoned lock.
    static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV.lock().unwrap_or_else(|e| e.into_inner())
    }

    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    /// A workspace shaped like the one this is for: the config under `.virtkit/`, a compose
    /// file beside it, a host-command dispatcher in the project's own tooling.
    fn wab_like(tag: &str) -> Fixture {
        let root = std::env::temp_dir().join(format!("vk-devplan-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".virtkit")).unwrap();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(root.join("virtkit")).unwrap();
        std::fs::create_dir_all(root.join("home-config")).unwrap();
        std::fs::write(
            root.join(".virtkit/compose.yaml"),
            "services:\n  devcontainer:\n    image: x\n",
        )
        .unwrap();
        std::fs::write(root.join("virtkit/host-dispatch.sh"), "#!/bin/sh\n").unwrap();
        std::fs::write(
            root.join(crate::dev::config::CONFIG_FILE),
            r#"
schema = 1

[requires]
features = ["publish"]

[dev]
compose = ".virtkit/compose.yaml"
service = "devcontainer"
workspace = "/workdir"
user = "dev"
freshness = "require-current"
profiles = ["runner"]
cpus = "host"
mem = "16G"
nested = true

[dev.container-env]
WAB_IN_VM = "1"

[dev.exec-env]
GITLAB_TOKEN = "${localEnv:VK_TEST_TOKEN}"

[dev.mounts.config]
source = "home-config"
to = "/home/dev/.config"

[dev.mounts.gitconfig]
source = "~/.gitconfig"
to = "/home/dev/.gitconfig"
read-only = true
optional = true

[dev.mounts.state]
source = "${state}/vscode-server"
to = "/home/dev/.vscode-server"

[dev.host]
wrapper = "virtkit/host-dispatch.sh"
wrapper-env = ["LC_*"]
ssh-agent = true

[dev.cache]
registry = "127.0.0.1:5000/cache"
insecure = true

[dev.endpoints.web]
target = 8080

[dev.endpoints."runner.https"]
service = "runner"
target = 443
host-port = 8443
scheme = "https"
path = "/ui"
required = true

[dev.hooks]
init = "./prepare.sh"
create = { run = ["make", "fixtures"], cwd = "tests", timeout = "10m", required = false }
start = { redis = "redis-cli ping" }

[dev.editor.vscode]
state = "persistent"
reconcile = ["/workdir/.devcontainer/install-extensions.sh", "-postcreate"]
extensions = ["ms-python.python"]
[dev.editor.vscode.settings]
"extensions.autoUpdate" = false
"#,
        )
        .unwrap();
        Fixture(root)
    }

    fn plan_of(root: &Path, env: &str) -> Result<Plan> {
        let loaded = crate::dev::config::load(crate::dev::config::discover(root, None, None)?)?;
        resolve(&loaded, env)
    }

    #[test]
    fn a_workspace_config_resolves_to_the_run_it_describes() {
        let _env = env_guard();
        let f = wab_like("wab");
        // SAFETY: single-threaded under the guard; removed below.
        unsafe { std::env::set_var("VK_TEST_TOKEN", "s3cret") };
        // The fixture's own home, so `~/.gitconfig` is a file this test put there rather
        // than one the host happens to have.
        // SAFETY: single-threaded under the guard; restored below.
        let saved_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &f.0) };
        std::fs::write(f.0.join(".gitconfig"), "[user]\n").unwrap();
        let p = plan_of(&f.0, "dev").unwrap();
        let root = std::fs::canonicalize(&f.0).unwrap();

        assert_eq!(p.workspace, root);
        assert_eq!(
            p.source,
            Source::Compose {
                file: root.join(".virtkit/compose.yaml"),
                service: "devcontainer".into(),
                profiles: vec!["runner".into()],
            }
        );
        assert_eq!(p.environment, "dev");
        assert_eq!(p.workspace_folder.as_deref(), Some("/workdir"));
        assert_eq!(p.user.as_deref(), Some("dev"));
        assert_eq!(p.freshness, Freshness::RequireCurrent);
        assert_eq!(p.cpus, Some(Cpus::Host));
        assert_eq!(p.mem.as_deref(), Some("16G"));
        assert_eq!(p.nested, Nested::Required);
        assert!(
            p.nests_here(),
            "required nesting is asked for whatever the host says"
        );
        assert!(
            p.to_shell(false).unwrap().contains("--nested"),
            "the run it describes carries --nested"
        );
        let mut off = p.clone();
        off.nested = Nested::Off;
        assert!(!off.nests_here(), "off never asks for nesting");
        assert_eq!(p.requires.features, ["publish"]);

        // Mounts: a project-relative source, `~`, and `${state}`, parsed and in name order,
        // each rendering back to the `vk run -v` spec it stands for.
        let home = f.0.display().to_string();
        assert_eq!(
            p.mounts
                .iter()
                .map(|m| (m.name.as_str(), m.source.clone(), m.to.as_str()))
                .collect::<Vec<_>>(),
            [
                ("config", root.join("home-config"), "/home/dev/.config"),
                (
                    "gitconfig",
                    PathBuf::from(&home).join(".gitconfig"),
                    "/home/dev/.gitconfig"
                ),
                (
                    "state",
                    p.state_dir.join("vscode-server"),
                    "/home/dev/.vscode-server"
                ),
            ]
        );
        assert!(p.mounts[1].read_only && p.mounts[1].optional);
        assert_eq!(
            p.mounts[1].spec().unwrap(),
            format!("{home}/.gitconfig:/home/dev/.gitconfig:ro,optional")
        );

        // The two environment scopes stay apart, and only host-fed values are sensitive.
        assert_eq!(p.container_env.len(), 1);
        assert_eq!(p.container_env[0].name, "WAB_IN_VM");
        assert!(!p.container_env[0].sensitive);
        assert_eq!(p.exec_env[0].value, "s3cret");
        assert!(p.exec_env[0].sensitive);

        // Endpoints: the primary's own port, and a sibling's, in name order.
        assert_eq!(
            p.endpoints,
            [
                EndpointPlan {
                    name: "runner.https".into(),
                    service: Some("runner".into()),
                    host_port: 8443,
                    address: "auto".into(),
                    listen: "tcp://auto:8443".into(),
                    to: "tcp://runner:443".into(),
                    scheme: Some("https".into()),
                    path: Some("/ui".into()),
                    required: true,
                },
                EndpointPlan {
                    name: "web".into(),
                    service: None,
                    host_port: 8080,
                    address: "auto".into(),
                    listen: "tcp://auto:8080".into(),
                    to: "tcp://127.0.0.1:8080".into(),
                    scheme: None,
                    path: None,
                    required: false,
                },
            ]
        );

        let he = p.host_exec.as_ref().unwrap();
        assert_eq!(he.wrapper, root.join("virtkit/host-dispatch.sh"));
        assert_eq!(he.builtin, None);
        assert_eq!(he.env, ["LC_*"]);
        assert!(p.ssh_agent);
        assert_eq!(p.cache.registry.as_deref(), Some("127.0.0.1:5000/cache"));

        // Hooks: a string through a shell, a detailed command with its options, a group.
        assert_eq!(
            p.hooks.init,
            Some(HookPlan::Command(HookCommand {
                run: Command::Shell("./prepare.sh".into()),
                cwd: None,
                timeout_secs: None,
                required: true,
            }))
        );
        assert_eq!(
            p.hooks.create,
            Some(HookPlan::Command(HookCommand {
                run: Command::Argv(vec!["make".into(), "fixtures".into()]),
                cwd: Some("tests".into()),
                timeout_secs: Some(600),
                required: false,
            }))
        );
        assert!(matches!(p.hooks.start, Some(HookPlan::Group(ref g)) if g.len() == 1));
        assert_eq!(
            p.managed_dirs,
            [p.state_dir.join("vscode-server")],
            "created by the boot, not required to exist yet"
        );
        let vs = p.vscode.as_ref().unwrap();
        assert!(vs.persistent);
        assert_eq!(vs.home, "/home/dev");
        assert!(
            !p.mounts.iter().any(|m| m.name == EDITOR_MOUNT),
            "a compose source declares its own server mount"
        );
        assert_eq!(vs.extensions, ["ms-python.python"]);
        assert_eq!(vs.settings["extensions.autoUpdate"], false);
        // SAFETY: as above.
        unsafe { std::env::remove_var("VK_TEST_TOKEN") };
        match saved_home {
            // SAFETY: as above.
            Some(h) => unsafe { std::env::set_var("HOME", h) },
            None => unsafe { std::env::remove_var("HOME") },
        }
    }

    #[test]
    fn a_plan_redacts_every_value_a_config_hands_to_a_command_or_an_image() {
        let _env = env_guard();
        let f = wab_like("redact");
        // SAFETY: single-threaded under the guard.
        unsafe { std::env::set_var("VK_TEST_TOKEN", "s3cret") };
        let p = plan_of(&f.0, "dev").unwrap();
        let json = p.to_json(false).unwrap();
        assert!(
            !json.contains("s3cret"),
            "a plan must be safe to paste anywhere"
        );
        assert!(json.contains("<redacted"), "{json}");
        assert!(
            p.to_json(true).unwrap().contains("s3cret"),
            "unless asked for"
        );
        // A literal in the file is as much a secret as one this shell exported: which of
        // them carries a token is the project's business.
        assert!(!json.contains("WAB_IN_VM\": \"1"), "{json}");

        let shell = p.to_shell(false).unwrap();
        assert!(!shell.contains("s3cret"));
        assert!(
            shell.contains("--compose") && shell.contains("--primary devcontainer"),
            "{shell}"
        );
        assert!(shell.contains("--ssh-agent"), "{shell}");
        assert!(shell.contains("# vk publish ensure"), "{shell}");
        assert!(shell.contains("# hooks.start"), "{shell}");
        assert!(shell.contains("(best effort)"), "{shell}");

        // A path this host does not spell in UTF-8 is named rather than rendered with the
        // bytes it cannot encode: this is a command a reader may run.
        use std::os::unix::ffi::OsStrExt;
        let mut odd = p.clone();
        odd.state_dir = PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/s\xff"));
        let err = odd.to_shell(false).unwrap_err().to_string();
        assert!(err.contains("the state directory"), "{err}");
        assert!(err.contains("not valid UTF-8"), "{err}");
        // SAFETY: as above.
        unsafe { std::env::remove_var("VK_TEST_TOKEN") };
    }

    #[test]
    fn local_env_comes_from_the_process_then_the_file_and_absent_is_noted() {
        let _env = env_guard();
        let f = wab_like("localenv");
        // SAFETY: single-threaded under the guard.
        unsafe { std::env::remove_var("VK_TEST_TOKEN") };
        // Absent: the plan still resolves — `status` and `stop` need it — but says what is
        // missing, and refuses to be run.
        let p = plan_of(&f.0, "dev").unwrap();
        assert_eq!(p.unresolved.len(), 1);
        assert!(
            p.unresolved[0].contains("VK_TEST_TOKEN") && p.unresolved[0].contains("local.env"),
            "{}",
            p.unresolved[0]
        );
        assert_eq!(p.exec_env[0].value, "");
        let msg = format!("{:#}", p.require_resolved().unwrap_err());
        assert!(msg.contains("VK_TEST_TOKEN"), "{msg}");

        std::fs::write(
            f.0.join(crate::dev::config::LOCAL_ENV_FILE),
            "VK_TEST_TOKEN=from-file\n",
        )
        .unwrap();
        let p = plan_of(&f.0, "dev").unwrap();
        assert_eq!(p.exec_env[0].value, "from-file");
        assert!(p.exec_env[0].sensitive, "a local value is still a secret");

        // SAFETY: as above; removed below.
        unsafe { std::env::set_var("VK_TEST_TOKEN", "from-process") };
        assert_eq!(
            plan_of(&f.0, "dev").unwrap().exec_env[0].value,
            "from-process"
        );
        // SAFETY: as above.
        unsafe { std::env::remove_var("VK_TEST_TOKEN") };
    }

    #[test]
    fn the_state_dir_is_derived_per_workspace_and_environment() {
        let _env = env_guard();
        let f = wab_like("state");
        // SAFETY: single-threaded under the guard; both removed below.
        unsafe { std::env::set_var("VK_TEST_TOKEN", "x") };
        unsafe { std::env::set_var("XDG_STATE_HOME", f.0.join("xdg")) };
        let a = plan_of(&f.0, "dev").unwrap();
        assert!(
            a.state_dir.starts_with(f.0.join("xdg/virtkit/dev")),
            "{}",
            a.state_dir.display()
        );
        let name = a
            .state_dir
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert!(
            name.starts_with(f.0.file_name().unwrap().to_string_lossy().as_ref()),
            "recognizable: {name}"
        );
        // Stable for the same inputs …
        assert_eq!(a.state_dir, plan_of(&f.0, "dev").unwrap().state_dir);
        // … including the same workspace reached by another name: the digest is over the
        // canonical path, so a symlink is not a second environment.
        let link =
            f.0.parent()
                .unwrap()
                .join(format!("vk-devplan-state-link-{}", std::process::id()));
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&f.0, &link).unwrap();
        assert_eq!(a.state_dir, plan_of(&link, "dev").unwrap().state_dir);
        std::fs::remove_file(&link).unwrap();
        // … and different for a second environment of the same workspace.
        let mut text = std::fs::read_to_string(f.0.join(crate::dev::config::CONFIG_FILE)).unwrap();
        text.push_str("\n[environments.ci]\nimage = \"debian:13\"\nworkspace = \"/src\"\n");
        std::fs::write(f.0.join(crate::dev::config::CONFIG_FILE), text).unwrap();
        let b = plan_of(&f.0, "ci").unwrap();
        assert_ne!(a.state_dir, b.state_dir);
        assert!(
            b.state_dir.to_string_lossy().contains("-ci-"),
            "{}",
            b.state_dir.display()
        );
        assert_eq!(
            b.source,
            Source::Image {
                reference: "debian:13".into()
            }
        );
        assert!(b.mounts.is_empty(), "nothing is inherited from [dev]");
        // SAFETY: as above.
        unsafe { std::env::remove_var("VK_TEST_TOKEN") };
        // SAFETY: as above.
        unsafe { std::env::remove_var("XDG_STATE_HOME") };
    }

    #[test]
    fn the_builtin_git_gui_policy_is_a_wrapper_vk_generates_itself() {
        let _env = env_guard();
        let f = wab_like("gitgui");
        let path = f.0.join(crate::dev::config::CONFIG_FILE);
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replace(
                "wrapper = \"virtkit/host-dispatch.sh\"\n",
                "git-gui = true\n",
            )
            .replace("wrapper-env = [\"LC_*\"]\n", "");
        std::fs::write(&path, text).unwrap();
        let p = plan_of(&f.0, "dev").unwrap();
        let he = p.host_exec.as_ref().unwrap();
        assert_eq!(he.builtin.as_deref(), Some("git-gui"));
        // Not a project file: the state dir, which the guest cannot write.
        assert_eq!(he.wrapper, p.state_dir.join("host-exec-wrapper"));
        assert!(he.env.is_empty());
        assert!(
            p.to_shell(false)
                .unwrap()
                .contains("built-in git-gui policy"),
            "{}",
            p.to_shell(false).unwrap()
        );
    }

    fn with_dev(f: &Fixture, extra: &str) {
        let path = f.0.join(crate::dev::config::CONFIG_FILE);
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            text.replace(
                "[dev.container-env]",
                &format!("{extra}\n[dev.container-env]"),
            ),
        )
        .unwrap();
    }

    #[test]
    fn what_the_host_cannot_do_is_refused_at_plan_time() {
        let _env = env_guard();
        // SAFETY: single-threaded under the guard; removed at the end.
        unsafe { std::env::set_var("VK_TEST_TOKEN", "x") };

        // A state dir the guest could write hands it the host's keys and command wrapper —
        // whole, or by one of its own entries. Its other subdirectories are managed storage.
        let f = wab_like("guest-state");
        with_dev(
            &f,
            "[dev.mounts.evil]\nsource = \"${state}\"\nto = \"/tmp/state\"\n",
        );
        let msg = format!("{:#}", plan_of(&f.0, "dev").unwrap_err());
        assert!(msg.contains("host's own"), "{msg}");
        let f = wab_like("guest-key");
        with_dev(
            &f,
            "[dev.mounts.evil]\nsource = \"${state}/bin\"\nto = \"/tmp/bin\"\n",
        );
        let msg = format!("{:#}", plan_of(&f.0, "dev").unwrap_err());
        assert!(msg.contains("host's own"), "{msg}");
        // A `..` names what it folds to, wherever it sits: an absolute source is folded
        // like a relative one before either is checked.
        let f = wab_like("guest-updir");
        with_dev(
            &f,
            "[dev.mounts.evil]\nsource = \"${state}/x/../id_ed25519\"\nto = \"/tmp/k\"\n",
        );
        let msg = format!("{:#}", plan_of(&f.0, "dev").unwrap_err());
        assert!(
            msg.contains("host's own") && msg.contains("id_ed25519"),
            "{msg}"
        );

        // …including vk's own mount for the editor server, which is at a guest path a
        // config can name too.
        let f = wab_like("dup-editor");
        std::fs::write(
            f.0.join(crate::dev::config::CONFIG_FILE),
            "schema = 1\n[dev]\nimage = \"debian:13\"\nworkspace = \"/src\"\n\
             [dev.editor.vscode]\nstate = \"persistent\"\nhome = \"/home/dev/\"\n\
             [dev.mounts.server]\nsource = \"home-config\"\nto = \"/home/dev/.vscode-server\"\n",
        )
        .unwrap();
        let msg = format!("{:#}", plan_of(&f.0, "dev").unwrap_err());
        assert!(msg.contains("second time"), "{msg}");

        // A symlink is what it points at: a source landing inside the state directory is
        // refused like one spelled there.
        let f = wab_like("guest-link");
        // SAFETY: single-threaded under the guard; removed below.
        unsafe { std::env::set_var("XDG_STATE_HOME", f.0.join("state")) };
        let state_dir = plan_of(&f.0, "dev").unwrap().state_dir;
        std::fs::create_dir_all(state_dir.join("lifecycle")).unwrap();
        std::os::unix::fs::symlink(state_dir.join("lifecycle"), f.0.join("link")).unwrap();
        with_dev(
            &f,
            "[dev.mounts.evil]\nsource = \"link\"\nto = \"/tmp/lifecycle\"\n",
        );
        let msg = format!("{:#}", plan_of(&f.0, "dev").unwrap_err());
        assert!(msg.contains("host's own"), "{msg}");
        // SAFETY: as above.
        unsafe { std::env::remove_var("XDG_STATE_HOME") };

        // Two mounts at one guest path is ambiguous, however the second one spells it.
        for (i, to) in [
            "/home/dev/.config",
            "/home/dev/.config/",
            "/home/dev//.config",
            "/home/dev/./.config",
        ]
        .into_iter()
        .enumerate()
        {
            let f = wab_like(&format!("dup-{i}"));
            with_dev(
                &f,
                &format!("[dev.mounts.again]\nsource = \"virtkit\"\nto = \"{to}\"\n"),
            );
            let msg = format!("{:#}", plan_of(&f.0, "dev").unwrap_err());
            assert!(msg.contains("second time"), "{to}: {msg}");
        }

        // A `:` would set the volume's mode rather than name a path: in a guest path a
        // config wrote, in a host path, and in the home vk builds its own mount from.
        let f = wab_like("colon-to");
        with_dev(
            &f,
            "[dev.mounts.bad]\nsource = \"virtkit\"\nto = \"/g:ro\"\n",
        );
        let msg = format!("{:#}", plan_of(&f.0, "dev").unwrap_err());
        assert!(msg.contains("separates a mount's fields"), "{msg}");
        let f = wab_like("colon-source");
        with_dev(&f, "[dev.mounts.bad]\nsource = \"virt:kit\"\nto = \"/g\"\n");
        let msg = format!("{:#}", plan_of(&f.0, "dev").unwrap_err());
        assert!(msg.contains("separates a mount's fields"), "{msg}");
        let f = wab_like("colon-home");
        std::fs::write(
            f.0.join(crate::dev::config::CONFIG_FILE),
            "schema = 1\n[dev]\nimage = \"debian:13\"\nworkspace = \"/src\"\n\
             [dev.editor.vscode]\nstate = \"persistent\"\nhome = \"/home/dev:x\"\n",
        )
        .unwrap();
        let msg = format!("{:#}", plan_of(&f.0, "dev").unwrap_err());
        assert!(msg.contains("separates a mount's fields"), "{msg}");

        // A source `hooks.init` has yet to create is not resolvable, and still cannot be
        // one whose contents would hold the state directory.
        let f = wab_like("pending-holds-state");
        // SAFETY: single-threaded under the guard; removed below.
        unsafe { std::env::set_var("XDG_STATE_HOME", f.0.join("later/state")) };
        with_dev(
            &f,
            "[dev.mounts.evil]\nsource = \"later\"\nto = \"/tmp/later\"\n",
        );
        let msg = format!("{:#}", plan_of(&f.0, "dev").unwrap_err());
        assert!(msg.contains("holds the state directory"), "{msg}");
        // SAFETY: as above.
        unsafe { std::env::remove_var("XDG_STATE_HOME") };

        // Two endpoints on one host address.
        let f = wab_like("dup-port");
        with_dev(
            &f,
            "[dev.endpoints.again]\ntarget = 9090\nhost-port = 8080\n",
        );
        let msg = format!("{:#}", plan_of(&f.0, "dev").unwrap_err());
        assert!(msg.contains("already takes"), "{msg}");

        // A built-in policy and a project wrapper are two answers to the same question.
        let f = wab_like("gitgui-and-wrapper");
        let path = f.0.join(crate::dev::config::CONFIG_FILE);
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replace("ssh-agent = true", "ssh-agent = true\ngit-gui = true");
        std::fs::write(&path, text).unwrap();
        let msg = format!("{:#}", plan_of(&f.0, "dev").unwrap_err());
        assert!(msg.contains("choose one"), "{msg}");

        // A URL scheme and path are what `vk dev open` builds an address from.
        for (i, (extra, expect)) in [
            ("scheme = \"ht tp\"", "URL scheme"),
            ("path = \"ui\"", "must start with"),
        ]
        .into_iter()
        .enumerate()
        {
            let f = wab_like(&format!("url-{i}"));
            with_dev(
                &f,
                &format!("[dev.endpoints.bad]\ntarget = 80\nhost-port = 8081\n{extra}\n"),
            );
            let msg = format!("{:#}", plan_of(&f.0, "dev").unwrap_err());
            assert!(msg.contains(expect), "{extra}: {msg}");
        }

        // A port this user cannot bind is refused now, not once the VM is up.
        let floor = lowest_bindable_port();
        if floor > 1 {
            let f = wab_like("privileged");
            with_dev(
                &f,
                &format!(
                    "[dev.endpoints.low]\ntarget = 80\nhost-port = {}\n",
                    floor - 1
                ),
            );
            let msg = format!("{:#}", plan_of(&f.0, "dev").unwrap_err());
            assert!(msg.contains("cannot bind"), "{msg}");
        }

        // A compose file, wrapper or Dockerfile that is not there names its key.
        let f = wab_like("nofile");
        std::fs::remove_file(f.0.join(".virtkit/compose.yaml")).unwrap();
        let msg = format!("{:#}", plan_of(&f.0, "dev").unwrap_err());
        assert!(msg.contains("[dev] compose"), "{msg}");

        // An image alone needs to know where the checkout goes.
        let f = wab_like("noworkspace");
        std::fs::write(
            f.0.join(crate::dev::config::CONFIG_FILE),
            "schema = 1\n[dev]\nimage = \"debian:13\"\n",
        )
        .unwrap();
        let msg = format!("{:#}", plan_of(&f.0, "dev").unwrap_err());
        assert!(msg.contains("workspace"), "{msg}");
        // SAFETY: as above.
        unsafe { std::env::remove_var("VK_TEST_TOKEN") };
    }

    #[test]
    fn what_a_local_layer_switches_off_is_not_in_the_plan() {
        let _env = env_guard();
        // SAFETY: single-threaded under the guard; removed below.
        unsafe { std::env::set_var("VK_TEST_TOKEN", "x") };
        let f = wab_like("disabled");
        with_dev(&f, "[dev.tasks.fmt]\nrun = \"cargo fmt\"\n");
        std::fs::write(
            f.0.join(crate::dev::config::LOCAL_FILE),
            "[dev.mounts.config]\nenabled = false\n\
             [dev.endpoints.web]\nenabled = false\n\
             [dev.tasks.fmt]\nenabled = false\n",
        )
        .unwrap();
        let p = plan_of(&f.0, "dev").unwrap();
        assert!(
            !p.mounts.iter().any(|m| m.name == "config"),
            "{:?}",
            p.mounts
        );
        assert!(!p.endpoints.iter().any(|e| e.name == "web"));
        assert!(p.tasks.is_empty());
        // SAFETY: as above.
        unsafe { std::env::remove_var("VK_TEST_TOKEN") };
    }

    #[test]
    fn a_build_source_resolves_its_dockerfile_inside_the_context() {
        let _env = env_guard();
        let f = wab_like("build");
        std::fs::create_dir_all(f.0.join("docker/dev")).unwrap();
        std::fs::write(f.0.join("docker/dev/Dockerfile"), "FROM x\n").unwrap();
        std::fs::write(
            f.0.join(crate::dev::config::CONFIG_FILE),
            "schema = 1\n[dev]\nbuild = { context = \"docker/dev\", target = \"dev\" }\n\
             workspace = \"/src\"\n",
        )
        .unwrap();
        let p = plan_of(&f.0, "dev").unwrap();
        let root = std::fs::canonicalize(&f.0).unwrap();
        assert_eq!(
            p.source,
            Source::Build {
                context: root.join("docker/dev"),
                dockerfile: root.join("docker/dev/Dockerfile"),
                target: Some("dev".into()),
                args: Vec::new(),
            }
        );
        let shell = p.to_shell(false).unwrap();
        assert!(
            shell.contains("--file") && shell.contains("--target dev"),
            "{shell}"
        );
        assert!(
            shell.contains(&format!("-v {}:/src", root.display())),
            "the checkout is mounted where the config says: {shell}"
        );
        assert!(p.vscode.is_none() && p.managed_dirs.is_empty());

        // A persistent editor on an image or build source gets vk's managed server mount at
        // the user's home — the default one, or the one the config names.
        let mut text = std::fs::read_to_string(f.0.join(crate::dev::config::CONFIG_FILE)).unwrap();
        text.push_str("[dev.editor.vscode]\nstate = \"persistent\"\n");
        std::fs::write(f.0.join(crate::dev::config::CONFIG_FILE), &text).unwrap();
        let p = plan_of(&f.0, "dev").unwrap();
        let host = p.state_dir.join("editor/vscode-server");
        assert_eq!(
            p.mounts
                .iter()
                .map(|m| (m.source.clone(), m.to.as_str()))
                .collect::<Vec<_>>(),
            [(host.clone(), "/root/.vscode-server")]
        );
        assert_eq!(p.managed_dirs, std::slice::from_ref(&host));
        text.push_str("home = \"/home/me\"\n");
        std::fs::write(f.0.join(crate::dev::config::CONFIG_FILE), &text).unwrap();
        let p = plan_of(&f.0, "dev").unwrap();
        assert_eq!(
            p.mounts
                .iter()
                .map(|m| (m.source.clone(), m.to.as_str()))
                .collect::<Vec<_>>(),
            [(host, "/home/me/.vscode-server")]
        );
    }

    #[test]
    fn tasks_resolve_to_what_runs_and_where() {
        let _env = env_guard();
        // SAFETY: single-threaded under the guard; removed below.
        unsafe { std::env::set_var("VK_TEST_TOKEN", "x") };
        let f = wab_like("tasks");
        std::fs::create_dir_all(f.0.join("docker/wabbuilder")).unwrap();
        std::fs::write(f.0.join("docker/wabbuilder/Dockerfile"), "FROM x\n").unwrap();
        let mut text = std::fs::read_to_string(f.0.join(crate::dev::config::CONFIG_FILE)).unwrap();
        text.push_str(
            r#"
[dev.tasks.pre-commit]
run = ["./dev/tools/git/hooks/pre-commit"]
environment = "hook"
reuse = "dev"
policy = "reuse-or-ephemeral"
checkout = "overlay"
env = { PRE_COMMIT_ISOLATED = "1" }

[dev.tasks.fmt]
run = "cargo fmt --check"

[environments.hook]
build = { context = "docker/wabbuilder", target = "builder", args = { DEVUSER_UID = "${VK_UID}" } }
cached-only = true
fallback = { target = "precommit" }
workspace = "/workdir"
user = "dev"
"#,
        );
        std::fs::write(f.0.join(crate::dev::config::CONFIG_FILE), &text).unwrap();

        let p = plan_of(&f.0, "dev").unwrap();
        assert_eq!(
            p.tasks.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
            ["fmt", "pre-commit"]
        );
        let t = &p.tasks[1];
        assert_eq!(t.argv, ["./dev/tools/git/hooks/pre-commit"]);
        assert_eq!((t.environment.as_str(), t.reuse.as_str()), ("hook", "dev"));
        assert_eq!(t.policy, Policy::ReuseOrEphemeral);
        assert_eq!(t.checkout, CheckoutMode::Overlay);
        assert_eq!(t.env[0].name, "PRE_COMMIT_ISOLATED");
        // A shell string is a shell string here as it is in a hook, and the defaults are
        // the dev environment, shared, `reuse-or-ephemeral`.
        let t = &p.tasks[0];
        assert_eq!(t.argv, ["/bin/sh", "-c", "cargo fmt --check"]);
        assert_eq!((t.environment.as_str(), t.reuse.as_str()), ("dev", "dev"));
        assert_eq!(t.checkout, CheckoutMode::Shared);
        // Tasks belong to the config, not to the environment they name.
        assert!(!p.cached_only && p.fallback_target.is_none());

        let h = plan_of(&f.0, "hook").unwrap();
        assert!(h.cached_only);
        assert_eq!(h.fallback_target.as_deref(), Some("precommit"));
        // SAFETY: geteuid touches no memory.
        let uid = unsafe { libc::geteuid() }.to_string();
        assert_eq!(
            h.source,
            Source::Build {
                context: std::fs::canonicalize(f.0.join("docker/wabbuilder")).unwrap(),
                dockerfile: std::fs::canonicalize(f.0.join("docker/wabbuilder/Dockerfile"))
                    .unwrap(),
                target: Some("builder".into()),
                args: vec![("DEVUSER_UID".into(), uid)],
            }
        );
        let shell = h.to_shell(false).unwrap();
        // A build argument's value is where a token reaches an image, so it is redacted
        // like an environment value, in both formats.
        assert!(
            shell.contains("--build-arg 'DEVUSER_UID=<redacted"),
            "{shell}"
        );
        assert!(
            h.to_shell(true)
                .unwrap()
                .contains("--build-arg DEVUSER_UID="),
            "unless asked for"
        );
        assert!(shell.contains("--require-cached"), "{shell}");
        assert!(shell.contains("# on a cache miss"), "{shell}");
        assert!(
            p.to_json(false).unwrap().contains("\"pre-commit\""),
            "the plan is what `vk dev plan` shows"
        );
        // SAFETY: as above.
        unsafe { std::env::remove_var("VK_TEST_TOKEN") };
    }

    #[test]
    fn a_task_names_an_environment_the_config_declares() {
        let _env = env_guard();
        // SAFETY: single-threaded under the guard; removed below.
        unsafe { std::env::set_var("VK_TEST_TOKEN", "x") };
        let f = wab_like("task-env");
        with_dev(
            &f,
            "[dev.tasks.check]
run = [\"true\"]
environment = \"hook\"
",
        );
        let msg = format!("{:#}", plan_of(&f.0, "dev").unwrap_err());
        assert!(
            msg.contains("dev.tasks.check") && msg.contains("environments.hook"),
            "{msg}"
        );
        // SAFETY: as above.
        unsafe { std::env::remove_var("VK_TEST_TOKEN") };
    }

    #[test]
    fn variables_are_the_documented_few() {
        let _env = env_guard();
        let file = BTreeMap::from([("FROM_FILE".to_string(), "f".to_string())]);
        let vars = Vars {
            workspace: PathBuf::from("/w/repo"),
            state: PathBuf::from("/s"),
            home: Some(PathBuf::from("/home/me")),
            uid: 1000,
            gid: 100,
            env_file: &file,
            missing: Default::default(),
            secrets: Default::default(),
        };
        assert_eq!(vars.expand("${workspace}/x").unwrap().value, "/w/repo/x");
        assert_eq!(vars.expand("${state}/y").unwrap().value, "/s/y");
        assert_eq!(
            vars.expand("~/.gitconfig").unwrap().value,
            "/home/me/.gitconfig"
        );
        assert_eq!(vars.expand("~").unwrap().value, "/home/me");
        assert_eq!(
            vars.expand("~user/x").unwrap().value,
            "~user/x",
            "not a home reference"
        );
        assert_eq!(vars.expand("${HOME}/z").unwrap().value, "/home/me/z");
        let e = vars.expand("${localEnv:FROM_FILE}").unwrap();
        assert_eq!(e.value, "f");
        assert!(e.sensitive);
        // SAFETY: single-threaded under the guard; both removed below.
        unsafe { std::env::set_var("VK_TEST_EMPTY", "") };
        unsafe { std::env::remove_var("VK_TEST_ABSENT") };
        assert_eq!(
            vars.expand("a${localEnv:VK_TEST_EMPTY}b").unwrap().value,
            "ab"
        );
        assert_eq!(vars.expand("${localEnv:VK_TEST_ABSENT}").unwrap().value, "");
        assert_eq!(vars.missing.borrow().len(), 1, "noted, not failed");
        assert_eq!(
            vars.expand("${localEnv:VK_TEST_ABSENT:fallback}")
                .unwrap()
                .value,
            "fallback"
        );
        // A default is a value, colons and all.
        assert_eq!(
            vars.expand("${localEnv:VK_TEST_ABSENT:https://h:8443/x}")
                .unwrap()
                .value,
            "https://h:8443/x"
        );
        // The same variable, twice, with something else expanded in between: one message.
        vars.expand("${localEnv:VK_TEST_ABSENT}").unwrap();
        vars.expand("${workspace}").unwrap();
        vars.expand("${localEnv:VK_TEST_ABSENT}").unwrap();
        assert_eq!(vars.missing.borrow().len(), 1, "one message per variable");
        assert!(
            vars.expand("${localWorkspaceFolder}").is_err(),
            "the old spelling"
        );
        assert!(vars.expand("${unterminated").is_err());
        // Set to bytes this host does not spell in UTF-8: an error, not a variable the user
        // is told to export.
        use std::os::unix::ffi::OsStrExt;
        // SAFETY: as above; removed below.
        unsafe { std::env::set_var("VK_TEST_ODD", std::ffi::OsStr::from_bytes(b"\xff")) };
        let err = vars
            .expand("${localEnv:VK_TEST_ODD}")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("VK_TEST_ODD") && err.contains("UTF-8"),
            "{err}"
        );
        // SAFETY: as above.
        unsafe { std::env::remove_var("VK_TEST_ODD") };
        // SAFETY: as above.
        unsafe { std::env::remove_var("VK_TEST_EMPTY") };

        let homeless = Vars {
            home: None,
            missing: Default::default(),
            ..vars
        };
        assert!(homeless.expand("~/x").is_err());
        assert_eq!(homeless.expand("/plain").unwrap().value, "/plain");
    }

    #[test]
    fn a_rendered_command_line_quotes_what_a_config_wrote() {
        let _env = env_guard();
        let f = wab_like("quoting");
        std::fs::create_dir_all(f.0.join("ctx")).unwrap();
        std::fs::write(f.0.join("ctx/Dockerfile"), "FROM x\n").unwrap();
        std::fs::write(
            f.0.join(crate::dev::config::CONFIG_FILE),
            "schema = 1\n[dev]\nworkspace = \"/src\"\n\
             build = { context = \"ctx\", args = { ODD = \"a b\" } }\n\
             [dev.mounts.spaced]\nsource = \"home-config\"\nto = \"/g/with space\"\n\
             [dev.tasks.odd]\nrun = [\"./it's\"]\n",
        )
        .unwrap();
        let p = plan_of(&f.0, "dev").unwrap();
        let root = std::fs::canonicalize(&f.0).unwrap();
        let shell = p.to_shell(true).unwrap();
        assert!(
            shell.contains(&format!(
                "-v '{}:/g/with space'",
                root.join("home-config").display()
            )),
            "{shell}"
        );
        assert!(shell.contains("--build-arg 'ODD=a b'"), "{shell}");
        assert!(shell.contains(r"'./it'\''s'"), "{shell}");
    }

    #[test]
    fn a_host_fed_mount_source_is_redacted_like_an_environment_value() {
        let _env = env_guard();
        let f = wab_like("secret-mount");
        std::fs::create_dir_all(f.0.join("home-config/s3cret-dir")).unwrap();
        // SAFETY: single-threaded under the guard; removed below.
        unsafe { std::env::set_var("VK_TEST_TOKEN", "s3cret-dir") };
        std::fs::write(
            f.0.join(crate::dev::config::CONFIG_FILE),
            "schema = 1\n[dev]\nimage = \"debian:13\"\nworkspace = \"/src\"\n\
             [dev.mounts.fed]\nsource = \"home-config/${localEnv:VK_TEST_TOKEN}\"\n\
             to = \"/g/fed\"\n",
        )
        .unwrap();
        let p = plan_of(&f.0, "dev").unwrap();
        assert!(p.secrets.contains("s3cret-dir"));
        // A mount source has no provenance of its own in the plan, so a value this host fed
        // it is found by what it is rather than by where it sits.
        for text in [p.to_json(false).unwrap(), p.to_shell(false).unwrap()] {
            assert!(!text.contains("s3cret-dir"), "{text}");
            assert!(text.contains(REDACTED), "{text}");
        }
        assert!(
            p.to_json(true).unwrap().contains("s3cret-dir"),
            "unless asked for"
        );
        // SAFETY: as above.
        unsafe { std::env::remove_var("VK_TEST_TOKEN") };
    }

    #[test]
    fn a_multi_line_hook_stays_inside_the_comment_it_renders_as() {
        let _env = env_guard();
        let f = wab_like("multiline");
        std::fs::write(
            f.0.join(crate::dev::config::CONFIG_FILE),
            "schema = 1\n[dev]\nimage = \"debian:13\"\nworkspace = \"/src\"\n\
             [dev.hooks]\ninit = \"\"\"\nmake fixtures\nrm -rf /\n\"\"\"\n",
        )
        .unwrap();
        let p = plan_of(&f.0, "dev").unwrap();
        let shell = p.to_shell(false).unwrap();
        let (_, comments) = shell.split_once("--ssh-client\n").unwrap();
        assert!(comments.contains("rm -rf /"), "{shell}");
        for line in comments.lines() {
            assert!(
                line.starts_with('#'),
                "a config's second line ran off the comment: {line:?}\n{shell}"
            );
        }
    }

    #[test]
    fn a_source_a_hook_has_yet_to_create_still_plans() {
        let _env = env_guard();
        let f = wab_like("pending-source");
        std::fs::write(
            f.0.join(crate::dev::config::CONFIG_FILE),
            "schema = 1\n[dev]\nimage = \"debian:13\"\nworkspace = \"/src\"\n\
             [dev.hooks]\ninit = \"mkdir -p build/out\"\n\
             [dev.mounts.out]\nsource = \"build/out\"\nto = \"/out\"\n",
        )
        .unwrap();
        let p = plan_of(&f.0, "dev").unwrap();
        let root = std::fs::canonicalize(&f.0).unwrap();
        assert_eq!(
            p.mounts
                .iter()
                .map(|m| (m.name.as_str(), m.source.clone()))
                .collect::<Vec<_>>(),
            [("out", root.join("build/out"))]
        );
    }

    #[test]
    fn vks_own_editor_mount_sorts_among_the_configured_ones() {
        let _env = env_guard();
        let f = wab_like("order");
        std::fs::write(
            f.0.join(crate::dev::config::CONFIG_FILE),
            "schema = 1\n[dev]\nimage = \"debian:13\"\nworkspace = \"/src\"\n\
             [dev.mounts.alpha]\nsource = \"virtkit\"\nto = \"/g/a\"\n\
             [dev.mounts.zed]\nsource = \"home-config\"\nto = \"/g/z\"\n\
             [dev.editor.vscode]\nstate = \"persistent\"\n",
        )
        .unwrap();
        let p = plan_of(&f.0, "dev").unwrap();
        assert_eq!(
            p.mounts.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(),
            ["alpha", EDITOR_MOUNT, "zed"]
        );
    }

    #[test]
    fn a_host_port_below_the_floor_is_refused() {
        assert!(refuse_privileged(1024, 1024).is_ok());
        assert!(refuse_privileged(8080, 1024).is_ok());
        let err = refuse_privileged(80, 1024).unwrap_err().to_string();
        assert!(
            err.contains("cannot bind") && err.contains("below 1024"),
            "{err}"
        );
        // A host that lowered the floor binds what a default one would not.
        assert!(refuse_privileged(80, 80).is_ok());
    }

    #[test]
    fn the_state_base_needs_an_absolute_directory_to_put_state_under() {
        let _env = env_guard();
        let (xdg, home) = (std::env::var_os("XDG_STATE_HOME"), std::env::var_os("HOME"));
        // SAFETY: single-threaded under the guard; both restored below.
        unsafe { std::env::set_var("XDG_STATE_HOME", "relative/state") };
        let err = dev_state_base().unwrap_err().to_string();
        assert!(err.contains("not an absolute path"), "{err}");
        // SAFETY: as above.
        unsafe { std::env::remove_var("XDG_STATE_HOME") };
        // SAFETY: as above.
        unsafe { std::env::remove_var("HOME") };
        let err = format!("{:#}", dev_state_base().unwrap_err());
        assert!(err.contains("nowhere to keep VM state"), "{err}");
        // SAFETY: as above.
        unsafe { std::env::set_var("XDG_STATE_HOME", "/s") };
        assert_eq!(dev_state_base().unwrap(), PathBuf::from("/s/virtkit/dev"));
        match xdg {
            // SAFETY: as above.
            Some(v) => unsafe { std::env::set_var("XDG_STATE_HOME", v) },
            None => unsafe { std::env::remove_var("XDG_STATE_HOME") },
        }
        match home {
            // SAFETY: as above.
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
    }

    /// A state base of the length `$XDG_STATE_HOME` unset gives a `/home/<user>` account.
    const BASE: &str = "/home/alice/.local/state/virtkit/dev";

    /// The longest path the directory `name` under `base` ever has to bind.
    fn socket_len(base: &Path, name: &str) -> usize {
        base.join(name).join("vsock.sock_65535").as_os_str().len()
    }

    #[test]
    fn an_environment_directory_that_fits_keeps_its_whole_name() {
        let base = Path::new(BASE);
        let parts = NameParts::of(Path::new("/home/alice/src/my-project"), "hook").unwrap();
        let name = parts.environment_dir(base).unwrap();
        assert_eq!(name, format!("my-project-hook-{}", parts.slug));
        assert!(socket_len(base, &name) <= crate::run::SUN_PATH_MAX);
    }

    #[test]
    fn a_long_workspace_name_is_cut_to_what_the_base_leaves() {
        let base = Path::new(BASE);
        let parts = NameParts::of(&PathBuf::from(format!("/w/{}", "n".repeat(200))), "hook")
            .expect("a name is derived from any workspace");
        let name = parts.environment_dir(base).unwrap();
        assert_eq!(socket_len(base, &name), crate::run::SUN_PATH_MAX);
        // The digest still tells this workspace from another cut to the same prefix.
        assert!(name.ends_with(&format!("-hook-{}", parts.slug)), "{name}");
        assert!(name.starts_with("nnn"), "{name}");
    }

    #[test]
    fn an_ephemeral_task_directory_leaves_room_for_its_sockets() {
        let base = Path::new(BASE);
        let parts = NameParts::of(Path::new("/home/alice/src/my-project"), "hook").unwrap();
        let name = parts.task_dir(base, "pre-commit", "34e89283").unwrap();
        assert_eq!(name, "my-project-hook-task-pre-commit-34e89283");
        assert!(socket_len(base, &name) <= crate::run::SUN_PATH_MAX);
    }

    #[test]
    fn a_task_directory_gives_up_the_workspace_name_before_the_task_name() {
        let base = Path::new(BASE);
        let parts = NameParts::of(&PathBuf::from(format!("/w/{}", "w".repeat(200))), "hook")
            .expect("a name is derived from any workspace");
        let name = parts.task_dir(base, "pre-commit", "34e89283").unwrap();
        assert_eq!(socket_len(base, &name), crate::run::SUN_PATH_MAX);
        assert!(name.starts_with("www"), "{name}");
        assert!(name.ends_with("-hook-task-pre-commit-34e89283"), "{name}");

        // A base that leaves less than the two names want: the workspace is down to a
        // single byte before the task name gives up anything.
        let tight = PathBuf::from(format!("/{}", "b".repeat(59)));
        let name = parts.task_dir(&tight, "pre-commit", "34e89283").unwrap();
        assert_eq!(socket_len(&tight, &name), crate::run::SUN_PATH_MAX);
        assert_eq!(name, "w-hook-task-pre-comm-34e89283");
    }

    #[test]
    fn a_base_with_no_room_for_a_state_directory_says_what_to_do() {
        let base = PathBuf::from(format!("/{}", "b".repeat(120)));
        let parts = NameParts::of(Path::new("/w/repo"), "dev").unwrap();
        for err in [
            parts.environment_dir(&base).unwrap_err().to_string(),
            parts
                .task_dir(&base, "check", "34e89283")
                .unwrap_err()
                .to_string(),
        ] {
            assert!(err.contains(base.to_str().unwrap()), "{err}");
            assert!(err.contains("XDG_STATE_HOME"), "{err}");
            assert!(err.contains(&crate::run::SUN_PATH_MAX.to_string()), "{err}");
        }
    }

    #[test]
    fn a_workspace_named_in_any_bytes_folds_to_an_ascii_readable_name() {
        // The byte-truncation of `readable` is safe only because it is ASCII whatever the
        // workspace is called — a multibyte, punctuation-laden basename included.
        let parts = NameParts::of(Path::new("/w/café münster+x"), "dev").unwrap();
        assert!(parts.readable.is_ascii(), "{}", parts.readable);
        assert!(
            parts
                .readable
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
            "{}",
            parts.readable
        );
        // ASCII alphanumerics survive; every other byte becomes '-'.
        assert!(parts.readable.starts_with("caf"), "{}", parts.readable);
        assert!(parts.readable.ends_with("nster-x"), "{}", parts.readable);
    }

    #[test]
    fn a_base_that_fits_a_state_dir_but_not_a_readable_name_is_refused() {
        // 68 bytes: `state_dir_room` still returns a positive budget, but the fixed parts of
        // each name — suffix and digest for an environment, suffix, `-task-` and token for a
        // task — leave no room for even one byte of the workspace name, so both directories
        // refuse rather than emit a name with nothing legible left.
        let base = PathBuf::from(format!("/{}", "b".repeat(67)));
        assert!(state_dir_room(&base).is_ok());
        let parts = NameParts::of(Path::new("/w/repo"), "hook").unwrap();
        assert!(parts.environment_dir(&base).is_err());
        assert!(parts.task_dir(&base, "pre-commit", "34e89283").is_err());
    }
}
