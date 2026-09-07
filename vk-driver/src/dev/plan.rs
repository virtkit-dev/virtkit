//! The run plan a `.virtkit/config.toml` resolves to on this host.
//!
//! [`crate::dev::config`] reads and layers the files; this decides what they mean here: paths
//! made absolute against the workspace root, `${…}` substituted, the state directory
//! derived, mounts and endpoints spelled the way `vk run` takes them. Nothing is done: the
//! [`Plan`] is the seam between configuration and execution — `vk dev plan` prints it, every
//! other `vk dev` command works from it, and the tests compare it rather than a rendered
//! command line.
//!
//! Values that came from the host environment — `${localEnv:…}`, where a token would come
//! from — are marked and redacted when a plan is printed or recorded.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::dev::config::{
    CheckoutMode, Command, Cpus, Environment, Freshness, Loaded, Policy, Requires, lexical_join,
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

/// One environment variable, and whether its value came from the host environment — which
/// is where a token or a password would come from, so it is redacted when the plan is
/// printed.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
    #[serde(skip)]
    pub sensitive: bool,
}

/// One `[dev.mounts.<name>]`, resolved: a host path, where it goes in the guest, and how.
/// The `vk run -v` spelling is rendered from this where a command line is built, rather
/// than being what the plan carries.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MountPlan {
    /// the config's name for it, or vk's own for a mount it manages
    pub name: String,
    /// the host path, absolute
    pub source: PathBuf,
    /// the guest path; no two mounts in a plan share one
    pub to: String,
    pub read_only: bool,
    /// an absent source is skipped rather than a failure
    pub optional: bool,
}

impl MountPlan {
    /// The `vk run -v` spec this mount is.
    pub fn spec(&self) -> Result<String> {
        let mut spec = format!(
            "{}:{}",
            utf8(&self.source, &format!("mount {}", self.name))?,
            self.to
        );
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

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HostExecPlan {
    /// absolute: a project wrapper that exists, or — for a `builtin` policy — the state-dir
    /// path the boot generates it at. A guest command channel pointed at a missing allowlist
    /// is a boot that would run nothing, or worse, everything.
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

/// What a config resolves to on this host. Everything here is decided; nothing here has
/// been done.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Plan {
    /// the checkout, absolute
    pub workspace: PathBuf,
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
    /// extra binds, in name order
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
    /// start and survives its refreshes
    pub managed_dirs: Vec<PathBuf>,
    /// `${localEnv:…}` references this host could not fill, one message each. A plan with
    /// any is complete enough to print, compare, or stop — and not to boot or exec, since a
    /// session would then run with a token missing.
    pub unresolved: Vec<String>,
    /// What this host fed the config through `${localEnv:…}`, wherever it expanded: an
    /// exec or container environment, a task's environment, a mount source, a build
    /// argument. Never serialized — it is the list of what must not be written down, and
    /// what the recorded identity fingerprints and a printed plan redacts.
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
    // directory. Its name and guest path are taken before the configured mounts are read,
    // so a config mount at either is refused rather than silently doubled; the mount itself
    // is added after the state-dir check below, whose reserved `editor` entry is where it
    // points.
    let editor_mount = vscode
        .as_ref()
        .filter(|vs| vs.persistent && !matches!(source, Source::Compose { .. }))
        .map(|vs| MountPlan {
            name: EDITOR_MOUNT.to_string(),
            source: state_dir.join("editor/vscode-server"),
            to: format!("{}/.vscode-server", vs.home),
            read_only: false,
            optional: false,
        });

    let taken = editor_mount
        .iter()
        .map(|m| (m.name.clone(), m.to.clone()))
        .collect();
    let resolved = mounts_of(env, &at, &workspace, &vars, taken)?;
    let mut managed_dirs = managed_storage(&resolved, &state_dir)?;
    let mut mounts: Vec<MountPlan> = resolved.into_iter().map(|r| r.mount).collect();
    if let Some(m) = editor_mount {
        managed_dirs.push(m.source.clone());
        mounts.push(m);
    }

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
        config: loaded.files.config.clone(),
        environment: name.to_string(),
        state_dir,
        source,
        workspace_folder: env.workspace.clone(),
        user: env.user.clone(),
        freshness: env.freshness.unwrap_or(Freshness::Ask),
        cpus: env.cpus,
        mem: env.mem.clone(),
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

/// What the primary boots from, with every path it names resolved against the workspace and
/// checked to exist: a missing compose file or Dockerfile is a boot that would fail late.
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
    taken: BTreeSet<(String, String)>,
) -> Result<Vec<Resolved>> {
    let mut names: BTreeSet<String> = taken.iter().map(|(n, _)| n.clone()).collect();
    let mut targets: BTreeSet<String> = taken.into_iter().map(|(_, t)| t).collect();
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
        // A host path relative to the project, like every other path in the file.
        let source = match Path::new(&source).is_absolute() {
            true => PathBuf::from(source),
            false => in_workspace(workspace, &source),
        };
        if !names.insert(mname.clone()) {
            bail!("[{key}] {mname} is the name of a mount vk makes itself; choose another");
        }
        if !targets.insert(to.clone()) {
            bail!("[{key}] mounts {to} a second time; one guest path takes one mount");
        }
        let mount = MountPlan {
            name: mname.clone(),
            source,
            to,
            read_only: m.read_only,
            optional: m.optional,
        };
        // Parsed here so a spec `vk run` would refuse names its key now rather than failing
        // the boot, and so the state-dir check below sees every share.
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
    let resolved_state = resolve_symlinks(state_dir);
    let mut managed_dirs = Vec::new();
    let mut volumes = Vec::new();
    for m in mounts {
        // An `optional` bind whose source is absent has no share: that mount is skipped at
        // boot, and what is not there cannot hold the state dir anyway.
        let Some(v) = &m.share else { continue };
        let name = &m.mount.name;
        match resolve_symlinks(&v.host).strip_prefix(&resolved_state) {
            Ok(rel) if !rel.as_os_str().is_empty() => {
                let first = rel
                    .components()
                    .next()
                    .map(|c| c.as_os_str().to_string_lossy().to_string())
                    .unwrap_or_default();
                if RESERVED_STATE_ENTRIES.contains(&first.as_str()) || first.starts_with('.') {
                    bail!(
                        "mount {name}: {first} under the state directory is the host's own; \
                         managed storage needs another name"
                    );
                }
                managed_dirs.push(v.host.clone());
            }
            Ok(_) => bail!(
                "mount {name}: the state directory is the host's own — keys, logs, the \
                 recorded identity; mount a subdirectory of it instead"
            ),
            // Nothing to do with the state dir; the check below has the last word.
            Err(_) => volumes.push(v),
        }
    }
    // The state dir holds what the host reads back — keys, logs, the host-exec allowlist —
    // so a guest that could write it would be steering the host. Planning happens before
    // `up` creates the state dir, and the check resolves the path it is given, so hand it
    // the nearest ancestor that exists: the overlap it looks for is a prefix relation, which
    // an ancestor answers the same way.
    let existing = state_dir
        .ancestors()
        .find(|p| p.exists())
        .unwrap_or(state_dir);
    crate::sshclient::check_state_dir_is_host_only(existing, volumes, [])?;
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
        let target = e
            .target
            .with_context(|| format!("[{key}] needs `target`"))?;
        let host_port = e.host_port.unwrap_or(target);
        // A privileged port fails to bind once the VM is already up; say so here.
        if host_port < floor {
            bail!(
                "[{key}] host-port {host_port}: this user cannot bind a port below {floor} — \
                 publish an unprivileged port instead"
            );
        }
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
        crate::publish::validate_name(ename).with_context(|| format!("[{key}]"))?;
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

/// A path a config wrote, relative to the project like every other path in the file.
fn in_workspace(workspace: &Path, rel: &str) -> PathBuf {
    lexical_join(workspace, Path::new(rel))
}

/// Where a user's home is in the guest, absent a better answer: what every image this is
/// for does, and overridable as `editor.vscode.home`.
fn guest_home(user: Option<&str>) -> String {
    match user {
        None | Some("root") => "/root".to_string(),
        Some(u) => format!("/home/{u}"),
    }
}

/// A configured command as the argv that runs. A string is what a config means when it
/// writes `a && b`, so it goes through a shell; a list is written as a list precisely to
/// avoid one.
fn command_argv(c: &Command) -> Vec<String> {
    match c {
        Command::Shell(s) => vec!["/bin/sh".into(), "-c".into(), s.clone()],
        Command::Argv(a) => a.clone(),
    }
}

/// A configured command, refused when it says nothing.
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

/// The state dir an environment gets: a readable name plus a digest of what identifies it —
/// the canonical workspace path and the environment name — so two worktrees of one repo,
/// and two environments of one workspace, never share a VM, and the same one always resolves
/// to the same directory.
fn derived_state_dir(workspace: &Path, environment: &str) -> Result<PathBuf> {
    use sha2::{Digest, Sha256};
    use std::os::unix::ffi::OsStrExt;
    let mut hasher = Sha256::new();
    hasher.update(workspace.as_os_str().as_bytes());
    hasher.update([0]);
    hasher.update(environment.as_bytes());
    let digest = hasher.finalize();
    let slug: String = digest[..4].iter().map(|b| format!("{b:02x}")).collect();
    let name = workspace
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "workspace".to_string());
    let readable: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let suffix = match environment {
        "dev" => String::new(),
        e => format!("-{e}"),
    };
    Ok(dev_state_base()?.join(format!("{readable}{suffix}-{slug}")))
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
    /// Every value this host fed a `${localEnv:…}` with, for [`Plan::secrets`]: recorded
    /// here rather than at each call site, so a value that lands somewhere with no
    /// provenance of its own — a mount source, a build argument, a task's environment — is
    /// still known for what it is. An empty value is not recorded: it matches nothing worth
    /// hiding and would fingerprint every empty string in the plan.
    secrets: std::cell::RefCell<BTreeSet<String>>,
}

impl Vars<'_> {
    fn home(&self) -> Result<&Path> {
        self.home
            .as_deref()
            .context("HOME is not set, and the config refers to it")
    }

    /// A host variable: the process environment first, then the local env file. Set but
    /// empty is a value; absent is not.
    fn local_env(&self, name: &str) -> Option<String> {
        std::env::var(name)
            .ok()
            .or_else(|| self.env_file.get(name).cloned())
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
                    match self.local_env(var) {
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
    // A kernel without that sysctl enforces 1024 itself, so the fallback is the answer
    // rather than a swallowed failure.
    std::fs::read_to_string("/proc/sys/net/ipv4/ip_unprivileged_port_start")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(1024)
}

/// What a printed plan says in place of a value it does not print.
fn redacted(value: &str) -> String {
    format!(
        "<redacted: {} chars; --show-secrets prints it>",
        value.len()
    )
}

impl Plan {
    /// The plan as JSON — the canonical form, and what the tests compare. Every environment
    /// value and build argument is redacted unless `reveal`, so a plan can be pasted into an
    /// issue: which of them carries a token is the project's business, not something this
    /// can tell from where the value came from — a literal written into `local.toml` is as
    /// much a secret as one read out of this shell.
    pub fn to_json(&self, reveal: bool) -> Result<String> {
        let mut plan = self.clone();
        if !reveal {
            plan.redact();
        }
        Ok(serde_json::to_string_pretty(&plan).context("serializing the plan")? + "\n")
    }

    /// Replace every value a config hands to a command or an image with [`redacted`]: the
    /// two environment scopes, a task's environment, and the build arguments.
    fn redact(&mut self) {
        let envs = self
            .container_env
            .iter_mut()
            .chain(&mut self.exec_env)
            .chain(self.tasks.iter_mut().flat_map(|t| &mut t.env));
        for e in envs {
            e.value = redacted(&e.value);
        }
        if let Source::Build { args, .. } = &mut self.source {
            for (_, value) in args {
                *value = redacted(value);
            }
        }
    }

    /// The plan as the `vk run` it stands for. For reading, not for running: the hooks and
    /// publishers are shown as comments, since they are steps around the boot rather than
    /// arguments to it.
    ///
    /// Every path here goes into the text as it is spelled, so one this host does not spell
    /// in UTF-8 is an error: rendering it with the offending bytes replaced would name a
    /// different file, and this is a command a reader is invited to run.
    pub fn to_shell(&self, reveal: bool) -> Result<String> {
        let mut out = String::from("vk run \\\n");
        let mut arg = |flag: &str, value: &str| {
            out.push_str(&format!(
                "  {flag} {} \\\n",
                crate::shell::quote_word(value)
            ));
        };
        match &self.source {
            Source::Compose {
                file,
                service,
                profiles,
            } => {
                arg("--compose", utf8(file, "the compose file")?);
                arg("--primary", service);
                for p in profiles {
                    arg("--profile", p);
                }
            }
            Source::Image { reference } => arg("--image", reference),
            Source::Build {
                context,
                dockerfile,
                target,
                args,
            } => {
                arg("--file", utf8(dockerfile, "the Dockerfile")?);
                arg("--context", utf8(context, "the build context")?);
                if let Some(t) = target {
                    arg("--target", t);
                }
                for (name, value) in args {
                    let value = match reveal {
                        true => value.clone(),
                        false => redacted(value),
                    };
                    arg("--build-arg", &format!("{name}={value}"));
                }
            }
        }
        let workspace = utf8(&self.workspace, "the workspace")?;
        let state_dir = utf8(&self.state_dir, "the state directory")?;
        arg("--workspace", workspace);
        arg("--state-dir", state_dir);
        if let Some(c) = &self.cpus {
            arg("--cpus", &c.to_string());
        }
        if let Some(m) = &self.mem {
            arg("--mem", m);
        }
        if !matches!(self.source, Source::Compose { .. })
            && let Some(folder) = &self.workspace_folder
        {
            arg("-v", &format!("{workspace}:{folder}"));
        }
        for m in &self.mounts {
            arg("-v", &m.spec()?);
        }
        for e in &self.container_env {
            let value = match reveal {
                true => e.value.clone(),
                false => redacted(&e.value),
            };
            arg("--env", &format!("{}={}", e.name, value));
        }
        if let Some(h) = &self.host_exec {
            arg(
                "--host-exec-wrapper",
                utf8(&h.wrapper, "the host-exec wrapper")?,
            );
        }
        if let Some(r) = &self.cache.registry {
            arg("--cache-registry", r);
        }
        if let Some(u) = &self.user {
            arg("--ssh-user", u);
        }
        if self.ssh_agent {
            out.push_str("  --ssh-agent \\\n");
        }
        if self.cached_only {
            out.push_str("  --require-cached \\\n");
        }
        out.push_str("  --ssh-client\n");
        if let Some(h) = &self.host_exec
            && let Some(builtin) = &h.builtin
        {
            out.push_str(&format!(
                "# the wrapper is generated at boot: vk's built-in {builtin} policy\n"
            ));
        }
        if let Some(t) = &self.fallback_target {
            out.push_str(&format!("# on a cache miss: the same, --target {t}\n"));
        }
        for t in &self.tasks {
            out.push_str(&format!(
                "# vk dev task {}: {} ({} in {})\n",
                t.name,
                t.argv
                    .iter()
                    .map(|a| crate::shell::quote_word(a))
                    .collect::<Vec<_>>()
                    .join(" "),
                t.policy.as_str(),
                t.environment
            ));
        }
        for p in &self.endpoints {
            out.push_str(&format!(
                "# vk publish ensure {} --name {} --listen {} --to {}{}\n",
                crate::shell::quote_word(state_dir),
                p.name,
                p.listen,
                p.to,
                if p.required { "  # required" } else { "" }
            ));
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
                out.push_str(&format!("# {when}: {}\n", h.describe()));
            }
        }
        Ok(out)
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
                    s.push_str(&format!(" (in {cwd})"));
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
        assert_eq!(p.requires.features, ["publish"]);

        // Mounts: a project-relative source, `~`, and `${state}`, parsed and in name order,
        // each rendering back to the `vk run -v` spec it stands for.
        let home = std::env::var("HOME").unwrap();
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
        // SAFETY: single-threaded under the guard.
        unsafe { std::env::set_var("VK_TEST_TOKEN", "x") };
        let a = plan_of(&f.0, "dev").unwrap();
        assert!(a.state_dir.starts_with(dev_state_base().unwrap()));
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
    }

    #[test]
    fn the_builtin_git_gui_policy_is_a_wrapper_vk_generates_itself() {
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

        // …including vk's own mount for the editor server, which is at a guest path a
        // config can name too.
        let f = wab_like("dup-editor");
        std::fs::write(
            f.0.join(crate::dev::config::CONFIG_FILE),
            "schema = 1\n[dev]\nimage = \"debian:13\"\nworkspace = \"/src\"\n\
             [dev.editor.vscode]\nstate = \"persistent\"\nhome = \"/home/dev\"\n\
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

        // Two mounts at one guest path is ambiguous.
        let f = wab_like("dup");
        with_dev(
            &f,
            "[dev.mounts.again]\nsource = \"virtkit\"\nto = \"/home/dev/.config\"\n",
        );
        let msg = format!("{:#}", plan_of(&f.0, "dev").unwrap_err());
        assert!(msg.contains("second time"), "{msg}");

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
    fn cached_only_needs_a_stage_to_take_from_the_cache() {
        let _env = env_guard();
        // SAFETY: single-threaded under the guard; removed below.
        unsafe { std::env::set_var("VK_TEST_TOKEN", "x") };
        let f = wab_like("cached-only");
        with_dev(
            &f,
            "cached-only = true
",
        );
        let msg = format!("{:#}", plan_of(&f.0, "dev").unwrap_err());
        assert!(
            msg.contains("cached-only") && msg.contains("build source"),
            "{msg}"
        );
        let f = wab_like("fallback");
        with_dev(
            &f,
            "fallback = { target = \"x\" }
",
        );
        let msg = format!("{:#}", plan_of(&f.0, "dev").unwrap_err());
        assert!(msg.contains("fallback"), "{msg}");
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
    fn shell_quoting_survives_a_hostile_path() {
        assert_eq!(
            crate::shell::quote_word("/plain/path-1.2"),
            "/plain/path-1.2"
        );
        assert_eq!(crate::shell::quote_word("with space"), "'with space'");
        assert_eq!(crate::shell::quote_word("it's"), r"'it'\''s'");
        assert_eq!(crate::shell::quote_word("$(rm -rf /)"), "'$(rm -rf /)'");
        assert_eq!(crate::shell::quote_word(""), "''");
    }
}
