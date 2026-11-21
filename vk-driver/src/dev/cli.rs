//! `vk dev` arguments and command dispatch.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Subcommand};

use super::{config, init, plan, schema};
use crate::{
    build, console_log_path, consolelog, dev, exec, exit_code, fail, show_console_log, sshclient,
    write_report,
};

// `Cmd::Dev` supplies the help; a doc comment here would duplicate its `about`.
#[derive(Args)]
pub struct Dev {
    #[command(subcommand)]
    action: DevAction,
    /// the project workspace
    ///
    /// `--workspace` overrides `$VIRTKIT_WORKSPACE`. With neither, `--dev-config` locates
    /// the workspace. Otherwise, look for `.virtkit/config.toml` in the current directory
    /// and, inside a checkout, up to its root. If this search finds no config, exit 5.
    #[arg(long, value_name = "DIR", global = true)]
    workspace: Option<PathBuf>,
    /// the config file to read, instead of `.virtkit/config.toml`
    ///
    /// Named `--dev-config` because `--config` is virtkit's own config file.
    #[arg(long = "dev-config", value_name = "FILE", global = true)]
    dev_config: Option<PathBuf>,
    /// the environment to work in: `dev`, or a name under `[environments]`
    #[arg(long, value_name = "NAME", default_value = "dev", global = true)]
    environment: String,
    /// what to do about a running environment that is out of date
    ///
    /// One that no longer matches the config, or that an older vk created. Overrides the
    /// config's own `freshness` for this invocation.
    #[arg(long, value_name = "POLICY", global = true)]
    freshness: Option<crate::dev::config::Freshness>,
    /// where built stages are cached, over the config's `[dev.cache]`
    #[arg(long = "cache-registry", value_name = "REF|DIR|none", global = true)]
    cache_registry: Option<String>,
    /// the cache registry speaks plain HTTP (a loopback vk-registry)
    #[arg(long = "cache-insecure", global = true)]
    cache_insecure: bool,
}

impl Dev {
    /// Does this command bring the environment up? The fork `main` performs before the
    /// runtime exists is decided here, so that the list cannot drift from the dispatch
    /// below (see [`crate::detach`]).
    pub fn boots(&self) -> bool {
        self.action.boots()
    }
}

/// `vk dev`: the entry point `main` dispatches to. `host_config` is the global `--config`
/// this `vk` was given, for the `vk dev` it runs on a named environment.
pub async fn run(
    dev: Dev,
    host_cfg: &crate::config::Config,
    host_config: Option<&Path>,
) -> ExitCode {
    let over = dev::Overrides {
        cache_registry: dev.cache_registry,
        cache_insecure: dev.cache_insecure,
        freshness: dev.freshness,
        no_build: false,
    };
    let workspace =
        config::chosen_workspace(dev.workspace, std::env::var_os(config::WORKSPACE_ENV));
    dev_action(
        dev.action,
        workspace.as_deref(),
        dev.dev_config.as_deref(),
        &dev.environment,
        &over,
        host_cfg,
        host_config,
    )
    .await
}

/// `vk dev`: drive a workspace's dev environment from its `.virtkit/config.toml`.
#[derive(Subcommand)]
enum DevAction {
    /// Write a first `.virtkit/config.toml`, or validate the one that exists
    ///
    /// With a config already there, reads it — and `.virtkit/local.toml` beside it — and
    /// reports what it describes; an unknown key or a value that means nothing is an error
    /// with its location. Without one, translates what the project has: a devcontainer.json,
    /// a compose file at the root, a Dockerfile, else a commented config booting a stock
    /// image. The report says what was carried over, what still needs a decision, and what
    /// was left out; a draft missing an essential choice is written but exits 1. Data
    /// conversion only — nothing runs, downloads or boots. Never touches the local files.
    Init {
        /// what to translate from, instead of detecting it
        #[arg(long, value_name = "SOURCE")]
        from: Option<crate::dev::init::Source>,
        /// the image reference, with `--from image`
        #[arg(long, value_name = "REF")]
        image: Option<String>,
        /// replace an existing config
        #[arg(long)]
        force: bool,
    },
    /// Bring the environment up, or confirm it already is
    ///
    /// Boots what the config describes and leaves it running: the build and boot are in the
    /// foreground, and this returns once the guest is ready. An environment already running
    /// the same configuration is a no-op; one running a different configuration, or created
    /// by an older vk, is handled as the config's `freshness` (or `--freshness`) says. To
    /// rebuild and restart one that matches, use `vk dev refresh`.
    ///
    /// Names select services or environments in this workspace. For a service, `up` first
    /// applies the environment's freshness policy, then builds the service image if needed.
    Up {
        /// fail promptly when a boot someone else started is in flight, instead of joining it
        #[arg(long)]
        no_wait: bool,
        #[command(flatten)]
        targets: Targets,
    },
    /// Start the environment from what is already built
    ///
    /// Use `up` for the first boot. Reuse a running environment even if its config changed.
    /// A stopped environment can restore images from the build cache. If the boot needs a
    /// build, attempt to restore its previous boot record and exit 3. With NAMEs, start those compose
    /// services or environments of this workspace without building.
    Start {
        #[command(flatten)]
        targets: Targets,
    },
    /// Stop the environment, then start it from what is already built
    ///
    /// `stop`, then `start`. With NAMEs, restarts those compose services or environments.
    Restart {
        #[command(flatten)]
        targets: Targets,
        /// seconds to wait per environment stop or per socket operation when stopping a service
        #[arg(long, default_value_t = super::boot::STOP_TIMEOUT_SECS)]
        timeout: u64,
    },
    /// Run a command in the environment, bringing it up first
    ///
    /// As the config's `user`, with its `exec-env`, in the guest directory that stands for
    /// yours — your working directory mapped into `workspace` when it lies inside the
    /// workspace. Arguments are passed as given: `vk dev exec -- cargo test -p vk-core`.
    Exec {
        /// the guest directory to run in, instead of the one standing for yours
        #[arg(long, value_name = "DIR")]
        dir: Option<String>,
        /// give the command a terminal, as `vk exec -t` does
        #[arg(short = 't', long)]
        tty: bool,
        /// run in this compose service instead of the primary
        ///
        /// The service must be running (`vk dev service up`). Waits if it is still booting.
        /// It gets none of the primary's contract — no `exec-env`, no `user`, no
        /// workspace directory — only what is passed here: the service is its own guest.
        #[arg(long, value_name = "NAME")]
        service: Option<String>,
        /// run as this user, instead of the config's (or, in a service, its default)
        #[arg(long, value_name = "USER")]
        user: Option<String>,
        /// the command and its arguments
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            required = true,
            value_name = "ARG"
        )]
        command: Vec<String>,
    },
    /// Open an interactive shell in the environment, bringing it up first
    ///
    /// Runs a login shell as the configured `user` with `exec-env`, in the guest
    /// directory corresponding to your current working directory, or the guest
    /// workspace root if you are outside the workspace. With `--service`, it boots
    /// nothing and opens the shell in that running service instead.
    ///
    /// Exiting the shell leaves the environment running.
    Shell {
        /// open the shell in this compose service instead of the primary
        ///
        /// The service must be running (`vk dev service up`). Waits if it is still booting.
        /// As with `vk dev exec --service`, it gets none of the primary's contract — no
        /// `exec-env`, no `user`, no workspace directory: the shell runs as the service's
        /// default user, in its working directory (its WORKDIR, or `/` under an image init).
        #[arg(long, value_name = "NAME")]
        service: Option<String>,
    },
    /// Open the workspace in VS Code, bringing the environment up first
    ///
    /// Attaches over Remote-SSH, with the run's own SSH setup — nothing to configure, and
    /// none of your own SSH keys or known-hosts involved. Behind the editor, a detached operation brings the
    /// guest's server to what `[dev.editor.vscode]` says (extensions, settings, the project's
    /// reconcile command) once Remote-SSH has installed it; `vk dev editor status` follows it.
    Code {
        /// the editor to launch [default: the first VS Code on PATH]
        ///
        /// Looked for as code, code-insiders, codium, vscodium, then code-oss. Its Remote-SSH
        /// extension must be installed.
        #[arg(long, value_name = "BIN")]
        editor: Option<String>,
        /// Start the guest's VS Code server over before opening
        ///
        /// Stops the server and empties its data directory in the guest (`~/.vscode-server`
        /// for a stable build; the channel's own directory otherwise) — installed server,
        /// extensions, machine settings, caches — and forgets its reconciliation, so
        /// Remote-SSH installs the server again and `[dev.editor.vscode]` is applied afresh.
        /// Windows already attached lose their server and reconnect. Works whatever holds the
        /// directory: vk's managed storage, a mount of your own, or the environment itself.
        #[arg(long)]
        reset_server: bool,
    },
    /// Follow or retry the editor reconciliation, or start the server over
    ///
    /// `vk dev code` leaves a detached operation behind that brings the guest's VS Code
    /// server to what `[dev.editor.vscode]` says, once Remote-SSH has installed it. These
    /// say whether it is still running and how it went, print its log, run it again in the
    /// foreground, or start the guest's server over. None of them boots the environment.
    Editor {
        #[command(subcommand)]
        action: EditorAction,
    },
    /// List the environment's endpoints: address, URL, and whether each is published
    ///
    /// An `auto` address is the stable loopback allocation this environment holds, shown
    /// once it exists. Reads only: nothing is allocated, published or booted.
    Endpoints {
        /// only this compose service's endpoints
        #[arg(long, value_name = "NAME", conflicts_with = "primary")]
        service: Option<String>,
        /// only the primary's endpoints — the ones no compose service claims
        #[arg(long)]
        primary: bool,
        /// print as JSON
        #[arg(long)]
        json: bool,
    },
    /// Open an endpoint's URL in the desktop's browser (or print it)
    ///
    /// The endpoint must name a `scheme`. Uses xdg-open when the desktop has one; prints the
    /// URL otherwise, or with `--print`.
    Open {
        /// the endpoint, as `[dev.endpoints.<name>]` names it
        name: String,
        /// print the URL instead of opening it
        #[arg(long)]
        print: bool,
    },
    /// Control the environment's compose services from the host
    ///
    /// The same operations `vk-agent service` offers inside the guest, addressed through the
    /// config instead of a state directory: bring a profiled service up (booting the
    /// environment first if it is down, building the service's image on first use with the
    /// build streamed here), take it down, reboot it, or ask where it stands. Only `up`
    /// boots anything; the rest report an environment that is down as such.
    Service {
        #[command(subcommand)]
        action: DevServiceAction,
    },
    /// Run a project task where its policy says
    ///
    /// `[dev.tasks.<name>]` declares the command and how it gets an environment: attach to
    /// one that is running (`reuse`), boot one first (`require`), run in a throwaway VM
    /// (`ephemeral`), or take the running one when there is one (`reuse-or-ephemeral`).
    /// Arguments after `--` are appended to the command, whose exit status is reproduced:
    /// `vk dev task pre-commit -- "$@"`.
    Task {
        /// the task, as `[dev.tasks.<name>]` names it
        name: String,
        /// arguments appended to the task's command
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "ARG"
        )]
        args: Vec<String>,
    },
    /// Build the environment's images into the cache, without running anything
    ///
    /// The primary's, or one compose service's with `--service` — what a boot, or that
    /// service's first start, would build, built now with the config's cache settings and
    /// the progress streamed here. Works whether or not the environment is running, and
    /// starts, stops and exports nothing.
    Build {
        /// build this compose service's image instead of the primary's
        #[arg(long, value_name = "NAME")]
        service: Option<String>,
    },
    /// List the environment's storage, and reset one durable item
    ///
    /// Storage is what the compose file's `disk` volumes and persistent roots, the config's
    /// `${state}` mounts and the editor's server storage add up to. `list` names each item,
    /// what it is for, where it is backed and whether it exists yet; `reset` is the only
    /// thing here that destroys anything. Neither boots the environment.
    Storage {
        #[command(subcommand)]
        action: DevStorageAction,
    },
    /// (internal) the detached reconciliation `vk dev code` starts
    #[command(name = "editor-reconcile", hide = true)]
    EditorReconcile {
        /// the editor whose server to reconcile
        #[arg(long, value_name = "BIN")]
        editor: String,
    },
    /// SSH into the environment (it must already be up)
    ///
    /// The system ssh, against the setup the boot wrote into the state directory — that
    /// run's config, key and host alias — so none of your own identities are involved and
    /// there is nothing to configure. Boots nothing: `vk dev shell` is the one that does.
    Ssh {
        /// arguments passed to ssh verbatim, after the host
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "ARG"
        )]
        args: Vec<String>,
    },
    /// Print the environment's ssh_config stanza
    ///
    /// The `Host` block `vk dev ssh` uses, for an editor, an rsync or an `Include` in your
    /// own ssh_config. It names the state directory's key and socket, so it is good for as
    /// long as this environment's state directory is. `--windows` prints the block a Windows
    /// `ssh.exe` needs instead, for a Windows editor driven from WSL2 — the same block
    /// `vk dev code` writes there, without writing it.
    #[command(name = "ssh-config")]
    SshConfig {
        /// print the block for a Windows `ssh.exe` reached from this WSL2 distro
        #[arg(long)]
        windows: bool,
    },
    /// Rebuild the environment and restart it into the result
    ///
    /// Unconditional, and the only command that is: `up` leaves an environment that matches
    /// its config alone, and `--freshness` only says what one that has drifted (or that an
    /// older vk created) gets. The build runs while the current environment keeps working, so
    /// the only downtime is the restart itself — and a build that fails leaves what is
    /// running alone. Does not ask: a wrapper that wants to confirm first should do the
    /// asking. The one exception: a refresh that waited for another `vk dev`'s boot keeps it
    /// when that boot started the VM from this config and from images all known to match the
    /// sources.
    Refresh {
        /// say what would change (as `plan --diff` does) without building or restarting
        #[arg(long)]
        dry_run: bool,
    },
    /// Say whether the environment is running, and whether it still matches its config
    ///
    /// Where it stands in one place: the state directory, whether a VM answers, what it was
    /// booted from and whether that is still what the config resolves to, its images, and
    /// what it publishes. `vk dev plan --diff` says what a difference would take to apply.
    /// Reads only, and reports an environment that is down as such rather than failing.
    Status {
        /// print the same facts as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show the environment's console log, or a service's
    ///
    /// `vk logs` for the environment's state directory: kernel, vk-agent and guest output
    /// told apart, `--level`, `-f`. Works after the VM has exited, too.
    Logs {
        /// read this compose service's console instead of the primary's
        #[arg(long, value_name = "NAME")]
        service: Option<String>,
        /// show the last N lines (after filtering); 0 streams the whole log
        #[arg(short = 'n', long, default_value_t = 50, value_name = "N")]
        lines: usize,
        /// only lines at least this severe: error, warn, info, debug, trace
        #[arg(long, value_name = "LEVEL")]
        level: Option<consolelog::Level>,
        /// only the guest kernel's lines
        #[arg(long)]
        kernel: bool,
        /// only vk-agent's lines
        #[arg(long)]
        agent: bool,
        /// only what the guest's programs printed
        #[arg(long)]
        guest: bool,
        /// keep printing new lines as the guest writes them (until Ctrl-C or the VM ends)
        #[arg(short = 'f', long)]
        follow: bool,
    },
    /// Check that this host can run the environment, without changing anything
    ///
    /// The config's requirements, KVM and the VMM, the tools the commands shell out to, the
    /// source and mount paths, free host ports for the endpoints, the state directory, and
    /// the host variables the config refers to. Exits 1 when a check fails.
    Doctor,
    /// Stop the environment and everything published from it (`down` is the same)
    ///
    /// Powers off the guest, its compose services with it, and stops its publishers. The
    /// next `vk dev start` or `up` reuses its storage, keys and identity. Use `vk dev gc` to
    /// remove the state directory. Stopping an environment that is already down succeeds.
    ///
    /// Stopping a sibling service leaves its environment up. The primary service name stops
    /// the whole environment. Use `vk stop NAME` for a VM outside this workspace, including
    /// one whose workspace is gone.
    #[command(visible_alias = "down")]
    Stop {
        #[command(flatten)]
        targets: Targets,
        /// plumbing: the environment on this state dir alone, whatever its workspace
        #[arg(
            long,
            value_name = "DIR",
            hide = true,
            conflicts_with_all = ["names", "services", "vms"]
        )]
        state_dir: Option<PathBuf>,
        /// seconds to wait per environment stop or per socket operation when stopping a service
        #[arg(long, default_value_t = super::boot::STOP_TIMEOUT_SECS)]
        timeout: u64,
    },
    /// List this workspace's dev environments, or use `--all` for host-wide state
    ///
    /// List declared environments and their secondary compose services (`NAME/SERVICE`),
    /// followed by recorded environments this workspace no longer declares. An environment
    /// without state reads `not built`. `--all` lists state directories under
    /// `$XDG_STATE_HOME/virtkit/dev` without reading a workspace config, including state
    /// left by throwaway tasks.
    ///
    /// Environment rows show the workspace, environment, status, creator, last boot, memory
    /// and disk usage. MEM shows the running VM's whole process tree over its configured
    /// memory (`1.2G/8G`), as in `vk list`. A stopped VM shows `-`. `--no-sizes` skips disk
    /// usage. Flags identify missing workspaces and state directories without a recorded boot.
    List {
        /// list dev state directories across all workspaces
        #[arg(long, short = 'a')]
        all: bool,
        /// print JSON, including whether vk delete recognizes each state directory as its own
        #[arg(long)]
        json: bool,
        /// skip the on-disk size measurement (a stat walk of every file)
        ///
        /// The `ON DISK` column then shows `-`.
        #[arg(long)]
        no_sizes: bool,
        /// show each workspace's full path
        ///
        /// WORKSPACE uses the shortest path suffix that distinguishes each listed workspace.
        /// JSON includes the full path when known.
        #[arg(short = 'w', long, conflicts_with = "json")]
        wide: bool,
    },
    /// Remove the state of environments that are finished with
    ///
    /// With no NAME, remove the configured environment. Names select environments in this
    /// workspace. Both forms read its config. `--all-stale` needs no config and selects stopped environments anywhere
    /// on the host whose workspace is gone or that never recorded a boot. It takes no names.
    /// Running environments cannot be removed. Without `--yes`, preview the state and
    /// storage to remove, then ask on a terminal. Use `vk delete NAME` for a stopped VM
    /// in another workspace.
    Gc {
        /// remove without asking
        #[arg(long)]
        yes: bool,
        /// every environment on the host whose workspace is gone, or that recorded no boot
        #[arg(long = "all-stale", conflicts_with = "names")]
        all_stale: bool,
        /// environments of this workspace, as `vk list` names them [default: this one]
        #[arg(value_name = "NAME")]
        names: Vec<String>,
    },
    /// Remove this environment's local boot images or persistent data
    ///
    /// Defaults to local boot images. --storage selects persistent roots, overlays,
    /// disks and managed directories inside the state directory; --all selects both.
    /// Keeps the environment identity, SSH keys, external backings and shared caches.
    /// Stop the environment first. Shows the paths and asks before deleting; without
    /// a terminal, requires --yes. --dry-run only previews.
    ///
    /// With no NAME, prune the configured environment. NAME selects an environment in this
    /// workspace and uses its last boot record to select what to prune. Use `vk reset NAME` for a
    /// recorded dev environment in another workspace.
    Prune {
        /// an environment of this workspace, as `vk list` names it [default: this one]
        #[arg(value_name = "NAME")]
        name: Option<String>,
        #[command(flatten)]
        options: super::prune::Options,
    },
    /// Print what the config resolves to, without doing any of it
    ///
    /// Which source, mounts, environment, endpoints and state directory the config means
    /// on this host, with `.virtkit/local.toml` layered in. Nothing is built, bound,
    /// started or written. The values of `exec-env`, `container-env`, a task's `env` and
    /// `build.args` are redacted — in every format, `--explain` included — so a plan can be
    /// pasted anywhere; `--show-secrets` prints them.
    Plan {
        /// print as JSON (the canonical form) or as the `vk run` it stands for
        #[arg(long, value_name = "FORMAT", default_value = "json")]
        format: PlanFormat,
        /// print the environment values and build arguments instead of redacting them
        ///
        /// They are where a token would be, so a plan can otherwise be pasted anywhere.
        #[arg(long)]
        show_secrets: bool,
        /// list each configured value with the file it came from, before the plan
        #[arg(long, conflicts_with = "diff")]
        explain: bool,
        /// compare the plan with the running environment instead of printing it
        ///
        /// Each difference is classified by what applying it takes: a new session, a
        /// host-side step, a restart, or a rebuilt image.
        #[arg(long)]
        diff: bool,
    },
    /// Print the JSON schema for .virtkit/config.toml
    ///
    /// The shape this `vk` accepts, for `taplo`, an editor, or a project that vendors its
    /// own copy. A `#:schema` directive on the config's first line is how an editor finds
    /// it without being told. Needs no config of its own.
    Schema,
}

impl DevAction {
    /// Whether this action needs the environment running, and so boots it. Every arm is
    /// spelled out: an action added without a decision here fails to compile rather than
    /// silently losing its fork — a boot in the foreground would then hold the VM forever.
    fn boots(&self) -> bool {
        match self {
            // A task boots only under `policy = "require"`, which is in the config rather
            // than on the command line; the fork is where a boot *may* happen, and the
            // policies that boot nothing leave the work to the parent (see `dev_up`).
            // Named services and environments are reached from this process: it boots none
            // itself (see `act_on`).
            Self::Up { targets, .. } | Self::Start { targets } => targets.is_empty(),
            Self::Code { .. } | Self::Task { .. } => true,
            // A service exec or shell reaches a running service and boots nothing.
            Self::Exec { service, .. } | Self::Shell { service } => service.is_none(),
            // Of the service operations only `up` boots the environment.
            Self::Service { action } => matches!(action, DevServiceAction::Up { .. }),
            // A dry run only reports; forking it would report twice.
            Self::Refresh { dry_run } => !dry_run,
            Self::Init { .. }
            | Self::Editor { .. }
            | Self::Endpoints { .. }
            | Self::Open { .. }
            | Self::Build { .. }
            | Self::Storage { .. }
            | Self::EditorReconcile { .. }
            | Self::Ssh { .. }
            | Self::SshConfig { .. }
            | Self::Status { .. }
            | Self::Logs { .. }
            | Self::Doctor
            | Self::Stop { .. }
            | Self::Restart { .. }
            | Self::List { .. }
            | Self::Gc { .. }
            | Self::Prune { .. }
            | Self::Plan { .. }
            | Self::Schema => false,
        }
    }
}

/// What `up`, `start`, `stop` and `restart` act on, by name: compose services of the
/// environment, or environments of this workspace. None means the environment itself.
#[derive(Args, Debug, Default)]
struct Targets {
    /// compose services, or environments of this workspace [default: the environment]
    ///
    /// A service by its compose name (the primary's is the environment itself), an
    /// environment as `vk list` names it, or `ENV/SERVICE`. A name that is both is refused:
    /// `--service` or `--name` says which. A VM of another workspace is refused too: `vk`
    /// itself (`vk start NAME`, `vk stop NAME`) reaches any VM.
    #[arg(value_name = "NAME")]
    names: Vec<String>,
    /// a compose service of the environment (repeatable)
    #[arg(long = "service", value_name = "SERVICE")]
    services: Vec<String>,
    /// an environment of this workspace, as `vk list` names it (repeatable)
    #[arg(long = "name", value_name = "NAME")]
    vms: Vec<String>,
}

impl Targets {
    fn is_empty(&self) -> bool {
        self.names.is_empty() && self.services.is_empty() && self.vms.is_empty()
    }
}

/// `vk dev editor`: the reconciliation that follows `vk dev code`, and the server it works on.
#[derive(Subcommand)]
enum EditorAction {
    /// Whether a reconciliation is running, and which servers were reconciled
    Status {
        /// print the same facts as JSON
        #[arg(long)]
        json: bool,
    },
    /// Print the newest reconciliation log
    Log,
    /// Run the reconciliation now, in the foreground, and report how it went
    ///
    /// The environment must be up and the editor connected, or about to be: the operation
    /// waits for the server Remote-SSH installs.
    Retry {
        /// the editor whose server to reconcile [default: the first VS Code on PATH]
        #[arg(long, value_name = "BIN")]
        editor: Option<String>,
    },
    /// Start the guest's server over, without opening the editor
    ///
    /// What `vk dev code --reset-server` does before it opens the editor: stops the server,
    /// empties its data directory in the guest and forgets its reconciliation, so the next
    /// window to connect gets a fresh install and `[dev.editor.vscode]` applied afresh. The
    /// environment must be up.
    Reset {
        /// the editor whose server to start over [default: the first VS Code on PATH]
        #[arg(long, value_name = "BIN")]
        editor: Option<String>,
    },
}

#[derive(Subcommand)]
enum DevServiceAction {
    /// Bring a service up, building its image on first use
    Up {
        /// the service, as the compose file names it
        name: String,
    },
    /// Stop a running service (a no-op if already stopped)
    Down {
        /// the service
        name: String,
        /// seconds to wait for each socket connect, read or write while stopping the service
        ///
        /// 0 waits indefinitely.
        #[arg(long, default_value_t = 120, value_name = "SECS")]
        timeout: u64,
    },
    /// Reboot a running service's guest in place (same VM, no image rebuild)
    Reboot {
        /// the service
        name: String,
    },
    /// Print a service's state and address, or every service's when no name is given
    ///
    /// One line per service, `<name> <state> <address>`, as from `vk-agent service status`.
    Status {
        /// the service; omit to list all
        name: Option<String>,
    },
}

/// `vk dev storage`: what the environment keeps, and the one operation that removes it.
#[derive(Subcommand)]
enum DevStorageAction {
    /// List every storage item: what owns it, how long it lives, where it is backed
    List {
        /// print the same facts as JSON
        #[arg(long)]
        json: bool,
        /// measure what each item holds on disk, which reads every file in it
        #[arg(long)]
        sizes: bool,
    },
    /// Remove a durable item's data, with whatever owns it stopped first
    ///
    /// Refuses an item a refresh or the editor adapter owns, and asks before stopping a
    /// running owner — declining keeps both the owner and its data. The next start
    /// recreates the item empty.
    Reset {
        /// the item, as `vk dev storage list` names it
        name: String,
        /// stop the owner and remove the data without asking
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum PlanFormat {
    /// the canonical form: every resolved value, as JSON
    Json,
    /// the `vk run` the plan stands for, for reading rather than running
    Shell,
}

/// Render one `<name> <state> <address>` line per unit on stdout, followed by the
/// reply's message on stdout for success or stderr for failure. Supply a fallback
/// message for failures without one, so a non-zero exit is never silent.
fn render_service_reply(reply: &vk_core::fleetctl::Reply) -> (String, Option<String>) {
    let mut out = String::new();
    for u in &reply.units {
        out.push_str(&format!("{:<16} {:<9} {}\n", u.name, u.state, u.ip));
    }
    let note = if reply.message.is_empty() {
        (!reply.ok).then(|| "the service manager reported a failure with no detail".to_string())
    } else if reply.ok {
        out.push_str(&reply.message);
        out.push('\n');
        None
    } else {
        Some(reply.message.clone())
    };
    (out, note)
}

/// `vk dev service`: print the manager's answer as `vk-agent service` prints it — the unit
/// lines, then the message — and turn its verdict into the exit code.
fn service_reply(reply: anyhow::Result<vk_core::fleetctl::Reply>) -> ExitCode {
    match reply {
        Ok(reply) => {
            let (out, note) = render_service_reply(&reply);
            if let Some(note) = note {
                eprintln!("{note}");
            }
            match write_report(&out) {
                ExitCode::SUCCESS if !reply.ok => exit_code(1),
                code => code,
            }
        }
        Err(e) => fail(&e, 1),
    }
}

/// `--environment ENV ` for an environment other than `dev`, for a command to repeat.
fn environment_flag(environment: &str) -> String {
    match environment {
        "dev" => String::new(),
        env => format!("--environment {env} "),
    }
}

/// `vk dev`: resolve the workspace's config, then act on the plan.
async fn dev_action(
    action: DevAction,
    workspace: Option<&Path>,
    config: Option<&Path>,
    environment: &str,
    over: &dev::Overrides,
    host_cfg: &crate::config::Config,
    host_config: Option<&Path>,
) -> ExitCode {
    // Return the embedded schema before resolving cwd, even if that directory was deleted.
    if matches!(action, DevAction::Schema) {
        return write_report(schema::SCHEMA_JSON);
    }
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => return fail(&anyhow::anyhow!(e).context("resolving the current dir"), 1),
    };
    // Init writes a config rather than reading one, but still needs the workspace.
    if let DevAction::Init { from, image, force } = action {
        let opts = init::Opts { from, image, force };
        return match init::run(&cwd, workspace, &opts) {
            Ok(out) => {
                let code = write_report(&out.report);
                if out.ok { code } else { exit_code(1) }
            }
            Err(e) => fail(&e, 2),
        };
    }
    if let DevAction::List {
        all,
        json,
        no_sizes,
        wide,
    } = action
    {
        let scope = match all {
            true => None,
            false => Some((workspace, config)),
        };
        return match dev_list(&cwd, scope, json, !no_sizes, wide) {
            Ok(report) => write_report(&report),
            Err(code) => code,
        };
    }
    if let DevAction::Stop {
        state_dir: Some(dir),
        timeout,
        ..
    } = &action
    {
        return stop_dir(dir, *timeout);
    }
    // The host-wide stale sweep needs no config. Clap rejects names with `--all-stale`.
    if let DevAction::Gc {
        yes,
        all_stale: true,
        ..
    } = &action
    {
        return dev_gc(*yes, Gc::AllStale);
    }
    // A config that cannot be read or does not describe something virtkit can build is the
    // caller's to fix, like a usage error.
    let loaded = match config::discover(&cwd, workspace, config).and_then(config::load) {
        Ok(l) => l,
        Err(e) => {
            let host_wide = match &action {
                DevAction::Gc { .. } => Some("vk delete NAME"),
                DevAction::Prune { .. } => Some("vk reset NAME"),
                DevAction::Stop { .. } => Some("vk stop NAME"),
                _ => None,
            };
            return no_workspace_or(e, 2, host_wide);
        }
    };
    // Named cleanup acts on what each environment recorded, and takes only the workspace from
    // the config: a compose file or Dockerfile gone since does not stand in its way.
    let action = match action {
        DevAction::Gc { yes, names, .. } if !names.is_empty() => {
            return match in_scope(&loaded.files.workspace, &names, "vk delete") {
                Ok(dirs) => {
                    eprintln!(
                        "vk: note: use `vk delete {}` for stopped VMs; it preserves directories vk does not recognize as its own",
                        names.join(" ")
                    );
                    dev_gc(yes, Gc::Dirs(&dirs))
                }
                Err(code) => code,
            };
        }
        DevAction::Prune {
            name: Some(name),
            options,
        } => {
            return match in_scope(
                &loaded.files.workspace,
                std::slice::from_ref(&name),
                "vk reset",
            ) {
                Ok(dirs) => {
                    eprintln!(
                        "vk: note: to prune a recorded dev environment, use `vk reset {name}{}`",
                        options.flags()
                    );
                    match super::prune::run_in(&dirs[0], &options) {
                        Ok(report) => write_report(&report),
                        Err(e) => fail(&e, 1),
                    }
                }
                Err(code) => code,
            };
        }
        action => action,
    };
    let plan = match plan::resolve(&loaded, environment) {
        Ok(p) => p,
        Err(e) => return fail(&e, 2),
    };
    let globals = Globals {
        loaded: &loaded,
        over,
        host_config,
    };
    match action {
        DevAction::Up { no_wait, targets } if !targets.is_empty() => {
            act_on(Verb::Up { no_wait }, &targets, 0, &plan, &globals).await
        }
        DevAction::Start { targets } if !targets.is_empty() => {
            act_on(Verb::Start, &targets, 0, &plan, &globals).await
        }
        DevAction::Stop {
            targets, timeout, ..
        } if !targets.is_empty() => act_on(Verb::Stop, &targets, timeout, &plan, &globals).await,
        DevAction::Restart { targets, timeout } if !targets.is_empty() => {
            act_on(Verb::Restart, &targets, timeout, &plan, &globals).await
        }
        DevAction::Restart { timeout, .. } => {
            let env = plan.environment.clone();
            match restart_env(&env, &plan.state_dir, timeout, &globals) {
                Ok(report) => write_report(&report),
                Err(e) => fail(&e, if build::not_cached(&e) { 3 } else { 1 }),
            }
        }
        // Only a bare `prune` gets here: a named one returned before the plan.
        DevAction::Prune { options, .. } => match super::prune::run(&plan, &options) {
            Ok(report) => write_report(&report),
            Err(e) => fail(&e, 1),
        },
        DevAction::Up { no_wait, .. } => {
            match dev_up(&plan, host_cfg, over, false, !no_wait, true).await {
                Ready::Act => ExitCode::SUCCESS,
                Ready::Done(code) => code,
            }
        }
        DevAction::Start { .. } => {
            // Check before boot. The process released at guest readiness can race
            // publication of the new identity.
            let up = format!("vk dev {}up", environment_flag(&plan.environment));
            if !crate::detach::after_boot() && !plan.state_dir.join("dev.json").exists() {
                let e = anyhow::anyhow!(
                    "the {} environment has no finished boot to start again: `{up}` builds \
                     and starts it",
                    plan.environment
                );
                return fail(&e, 1);
            }
            let over = dev::Overrides {
                freshness: Some(config::Freshness::Reuse),
                no_build: true,
                ..over.clone()
            };
            match dev_up(&plan, host_cfg, &over, false, true, true).await {
                Ready::Act => ExitCode::SUCCESS,
                Ready::Done(code) if code == exit_code(3) => {
                    eprintln!("vk: hint: `{up}` builds it");
                    code
                }
                Ready::Done(code) => code,
            }
        }
        DevAction::Refresh { dry_run: true } => match dev::plan_diff(&plan) {
            Ok(Some(report)) => write_report(&format!(
                "{report}a refresh rebuilds the image and restarts the environment\n"
            )),
            Ok(None) => write_report(NOTHING_RUNNING),
            Err(e) => fail(&e, 1),
        },
        // The one unconditional rebuild-and-restart: `up` never reboots an environment
        // that matches and has no older creator. Only stale environments follow the policy.
        DevAction::Refresh { dry_run: false } => {
            match dev_up(&plan, host_cfg, over, true, true, true).await {
                Ready::Act => ExitCode::SUCCESS,
                Ready::Done(code) => code,
            }
        }
        // Each of these needs the environment, so each is an `up` and then the thing itself
        // — which happens in the parent, released once the boot the child performed is up.
        // A service is its own guest: no boot, none of the primary's session contract.
        DevAction::Exec {
            dir,
            tty,
            service: Some(service),
            user,
            command,
        } => match dev::exec_in_service(&plan, &service, &command, dir, tty, user).await {
            Ok(result) => exec::exit(result),
            Err(e) => fail(&e, 1),
        },
        DevAction::Exec {
            dir,
            tty,
            service: None,
            user,
            command,
        } => match dev_up(&plan, host_cfg, over, false, true, false).await {
            Ready::Done(code) => code,
            Ready::Act => match dev::exec_session(
                &plan,
                &command,
                dir.or_else(|| dev::guest_cwd(&plan)),
                tty,
                user,
            )
            .await
            {
                Ok(result) => exec::exit(result),
                Err(e) => fail(&e, 1),
            },
        },
        DevAction::Service {
            action: DevServiceAction::Up { name },
        } => match dev_up(&plan, host_cfg, over, false, true, false).await {
            Ready::Done(code) => code,
            Ready::Act => service_reply(
                dev::service(&plan, &vk_core::fleetctl::Request::Start { unit: name }).await,
            ),
        },
        DevAction::Service {
            action: DevServiceAction::Down { name, timeout },
        } => service_reply(
            dev::service_within(
                &plan,
                &vk_core::fleetctl::Request::Stop { unit: name },
                (timeout > 0).then(|| std::time::Duration::from_secs(timeout)),
                std::env::var(crate::vms::STOP_RUN_ENV).ok().as_deref(),
            )
            .await,
        ),
        DevAction::Service {
            action: DevServiceAction::Reboot { name },
        } => service_reply(
            dev::service(&plan, &vk_core::fleetctl::Request::Reboot { unit: name }).await,
        ),
        DevAction::Service {
            action: DevServiceAction::Status { name },
        } => service_reply(
            dev::service(
                &plan,
                &match name {
                    Some(unit) => vk_core::fleetctl::Request::Status { unit },
                    None => vk_core::fleetctl::Request::List,
                },
            )
            .await,
        ),
        DevAction::Storage {
            action: DevStorageAction::List { json, sizes },
        } => match crate::dev::storage::inventory(&plan, sizes) {
            Ok(items) if json => match serde_json::to_string_pretty(&items) {
                Ok(text) => write_report(&(text + "\n")),
                Err(e) => fail(&anyhow::anyhow!(e), 1),
            },
            Ok(items) => match crate::dev::storage::running(&plan) {
                Ok(running) => write_report(&crate::dev::storage::render(&items, &running)),
                Err(e) => fail(&e, 1),
            },
            Err(e) => fail(&e, 1),
        },
        DevAction::Storage {
            action: DevStorageAction::Reset { name, yes },
        } => match crate::dev::storage::reset(&plan, &name, yes).await {
            Ok(report) => write_report(&(report + "\n")),
            Err(e) => fail(&e, 1),
        },
        DevAction::Endpoints {
            service,
            primary,
            json,
        } => {
            use crate::dev::endpoints::Which;
            let which = match (&service, primary) {
                (Some(name), _) => Which::Service(name),
                (None, true) => Which::Primary,
                (None, false) => Which::All,
            };
            let views = crate::dev::endpoints::views(&plan, which);
            if json {
                match serde_json::to_string_pretty(&views) {
                    Ok(text) => write_report(&(text + "\n")),
                    Err(e) => fail(&anyhow::anyhow!(e), 1),
                }
            } else {
                write_report(&crate::dev::endpoints::render(&views))
            }
        }
        DevAction::Open { name, print } => {
            let Some(view) = crate::dev::endpoints::views(&plan, crate::dev::endpoints::Which::All)
                .into_iter()
                .find(|v| v.name == name)
            else {
                return fail(&anyhow::anyhow!("no endpoint {name:?} in the config"), 1);
            };
            let Some(url) = view.url else {
                return fail(
                    &anyhow::anyhow!(match view.listen {
                        Some(_) => format!("endpoint {name} names no `scheme`, so it has no URL"),
                        None => format!(
                            "endpoint {name} has no address yet — it is allocated when published"
                        ),
                    }),
                    1,
                );
            };
            if !view.published {
                eprintln!("virtkit: note: {name} is not published right now");
            }
            if print {
                return write_report(&format!("{url}\n"));
            }
            match std::process::Command::new("xdg-open").arg(&url).status() {
                Ok(st) if st.success() => ExitCode::SUCCESS,
                _ => write_report(&format!("{url}\n")),
            }
        }
        DevAction::Shell { service } => {
            let argv: Vec<String> = dev::LOGIN_SHELL.iter().map(|s| s.to_string()).collect();
            let result = match service {
                Some(service) => {
                    dev::exec_in_service(&plan, &service, &argv, None, true, None).await
                }
                None => match dev_up(&plan, host_cfg, over, false, true, false).await {
                    Ready::Done(code) => return code,
                    Ready::Act => {
                        dev::exec_in_guest(
                            &plan,
                            &argv,
                            dev::guest_cwd(&plan),
                            true,
                            vk_core::exec::client::Stdin::Forward,
                        )
                        .await
                    }
                },
            };
            match result {
                Ok(result) => exec::exit(result),
                Err(e) => fail(&e, 1),
            }
        }
        DevAction::Code {
            editor,
            reset_server,
        } => match dev_up(&plan, host_cfg, over, false, true, false).await {
            Ready::Done(code) => code,
            Ready::Act => {
                let editor = match crate::dev::editor::select(editor.as_deref()) {
                    Ok(e) => e,
                    Err(e) => return fail(&e, 1),
                };
                // Before the reconciliation starts: it would otherwise apply to a server
                // about to be emptied and leave a stamp for it. And only once the editor can
                // launch — no point emptying the server if the open would fail.
                if reset_server {
                    if let Err(e) = dev::launch_checks(&plan) {
                        return fail(&e, 1);
                    }
                    match crate::dev::editor::reset_server(&plan, &editor).await {
                        Ok(done) => eprintln!("virtkit: editor: {done}"),
                        Err(e) => return fail(&e, 1),
                    }
                }
                // Started before the editor and not waited for: the server appears only
                // once the editor connects, and the editor must not wait for this.
                match crate::dev::editor::spawn(&plan, &editor) {
                    Ok(crate::dev::editor::Started::Spawned { pid, log }) => eprintln!(
                        "virtkit: editor reconciliation started (pid {pid}); log: {}",
                        log.display()
                    ),
                    Ok(crate::dev::editor::Started::Joined { holder }) => {
                        eprintln!("virtkit: editor reconciliation already running ({holder})")
                    }
                    Ok(crate::dev::editor::Started::Nothing) => {}
                    Err(e) => eprintln!("virtkit: editor reconciliation not started: {e:#}"),
                }
                match dev::launch_editor(&plan, &editor) {
                    Ok(never) => match never {},
                    Err(e) => fail(&e, 1),
                }
            }
        },
        DevAction::Editor {
            action: EditorAction::Status { json },
        } => match json {
            true => match serde_json::to_string_pretty(&crate::dev::editor::status_view(&plan)) {
                Ok(text) => write_report(&(text + "\n")),
                Err(e) => fail(&anyhow::anyhow!(e), 1),
            },
            false => write_report(&crate::dev::editor::status(&plan)),
        },
        DevAction::Editor {
            action: EditorAction::Log,
        } => match crate::dev::editor::latest_log(&plan) {
            Ok(text) => write_report(&text),
            Err(e) => fail(&e, 1),
        },
        // Only a `require` task boots the environment; the rest attach to what runs or boot
        // a throwaway VM, so there is nothing for a forked child to do and this parent — the
        // one holding the terminal — runs the task (see `dev`'s module docs and `detach`).
        DevAction::Task { name, args } => {
            let placement = match crate::dev::task::placement(&loaded, &plan, &name) {
                Ok(p) => p,
                Err(e) => return fail(&e, 2),
            };
            let ready = match placement.boots() {
                Some(target) => dev_up(target, host_cfg, over, false, true, false).await,
                None => dev_after_fork(),
            };
            match ready {
                Ready::Done(code) => code,
                Ready::Act => {
                    match crate::dev::task::run(
                        placement, &loaded, &plan, &name, &args, host_cfg, over,
                    )
                    .await
                    {
                        Ok(code) => code,
                        Err(e) => fail(&e, 1),
                    }
                }
            }
        }
        DevAction::Build { service } => {
            match dev::build(&plan, host_cfg, over, service.as_deref()).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&e, 1),
            }
        }
        DevAction::Editor {
            action: EditorAction::Retry { editor },
        } => match crate::dev::editor::select(editor.as_deref()) {
            Err(e) => fail(&e, 1),
            Ok(editor) => match crate::dev::editor::reconcile(&plan, &editor).await {
                Ok(_) => ExitCode::SUCCESS,
                Err(e) => fail(&e, 1),
            },
        },
        DevAction::Editor {
            action: EditorAction::Reset { editor },
        } => {
            if dev::running_vm(&plan).is_none() {
                return fail(
                    &anyhow::anyhow!(
                        "{} is not running — `vk dev up` first, or `vk dev code --reset-server` \
                         to boot, reset and open in one go",
                        plan.environment
                    ),
                    1,
                );
            }
            match crate::dev::editor::select(editor.as_deref()) {
                Err(e) => fail(&e, 1),
                Ok(editor) => match crate::dev::editor::reset_server(&plan, &editor).await {
                    Ok(done) => {
                        eprintln!("virtkit: editor: {done}");
                        ExitCode::SUCCESS
                    }
                    Err(e) => fail(&e, 1),
                },
            }
        }
        DevAction::EditorReconcile { editor } => match crate::dev::editor::select(Some(&editor)) {
            Err(e) => fail(&e, 1),
            Ok(editor) => match crate::dev::editor::reconcile(&plan, &editor).await {
                Ok(_) => ExitCode::SUCCESS,
                Err(e) => fail(&e, 1),
            },
        },
        DevAction::Ssh { args } => match sshclient::exec_ssh(&plan.state_dir, &args) {
            Ok(never) => match never {},
            Err(e) => fail(&e, 1),
        },
        DevAction::SshConfig { windows } => {
            let printed = match windows {
                true => dev::wsl::print_stanza(&plan.state_dir),
                false => sshclient::print_config(&plan.state_dir),
            };
            match printed {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&e, 1),
            }
        }
        DevAction::Status { json } => match dev::status(&plan) {
            Ok(status) if json => match serde_json::to_string_pretty(&status) {
                Ok(text) => write_report(&(text + "\n")),
                Err(e) => fail(&anyhow::anyhow!(e), 1),
            },
            Ok(status) => write_report(&status.render()),
            Err(e) => fail(&e, 1),
        },
        DevAction::Logs {
            service,
            lines,
            level,
            kernel,
            agent,
            guest,
            follow,
        } => {
            let mut sources = Vec::new();
            if kernel {
                sources.push(consolelog::Source::Kernel);
            }
            if agent {
                sources.push(consolelog::Source::Agent);
            }
            if guest {
                sources.push(consolelog::Source::Guest);
            }
            // A stopped environment's console, and each service's under `svc-<name>/`, are
            // still read from its state directory.
            let path = console_log_path(Some(&plan.state_dir), service.as_deref());
            match path {
                Ok((path, writer)) => {
                    match show_console_log(&path, writer.as_ref(), &sources, level, lines, follow)
                        .await
                    {
                        Ok(()) => ExitCode::SUCCESS,
                        Err(e) => fail(&e, 1),
                    }
                }
                Err(e) => fail(&e, 2),
            }
        }
        DevAction::Doctor => {
            let (report, ok) = dev::doctor(&plan, host_cfg);
            let code = write_report(&report);
            if ok { code } else { exit_code(1) }
        }
        DevAction::Stop { timeout, .. } => stop_dir(&plan.state_dir, timeout),
        // Only a bare `gc` gets here; named runs are above and `--all-stale` returned before
        // the config. Selected by the plan's own state dir, which no other environment shares.
        DevAction::Gc { yes, .. } => dev_gc(yes, Gc::Dirs(std::slice::from_ref(&plan.state_dir))),
        DevAction::Init { .. } | DevAction::List { .. } | DevAction::Schema => {
            unreachable!("handled before the plan is resolved")
        }
        // Nothing running is not an error for a read-only preview — `refresh --dry-run`
        // prints the same report and says so in the same words.
        DevAction::Plan { diff: true, .. } => match dev::plan_diff(&plan) {
            Ok(Some(report)) => write_report(&report),
            Ok(None) => write_report(NOTHING_RUNNING),
            Err(e) => fail(&e, 1),
        },
        DevAction::Plan {
            format,
            show_secrets,
            explain,
            ..
        } => {
            let body = match format {
                PlanFormat::Json => plan.to_json(show_secrets),
                PlanFormat::Shell => plan.to_shell(show_secrets),
            };
            let body = match body {
                Ok(b) => b,
                Err(e) => return fail(&e, 1),
            };
            match explain {
                false => write_report(&body),
                true => {
                    let mut out = origins(&loaded, show_secrets);
                    out.push('\n');
                    out.push_str(&body);
                    write_report(&out)
                }
            }
        }
    }
}

/// Each configured value with the file it came from, one per line.
fn origins(loaded: &config::Loaded, show_secrets: bool) -> String {
    let mut out = String::new();
    for o in loaded.origins() {
        let file = match o.layer {
            config::Layer::Project => &loaded.files.config,
            config::Layer::Local => &loaded.files.local,
        };
        // The two files sit side by side, so their names tell them apart.
        let name = file.strip_prefix(&loaded.files.workspace).unwrap_or(file);
        let value = match o.secret && !show_secrets {
            true => "<redacted>".to_string(),
            false => o.value.to_string(),
        };
        out.push_str(&format!("{} = {value}  # {}\n", o.key, name.display()));
    }
    out
}

/// What `plan --diff` and `refresh --dry-run` say when there is no environment to compare
/// the config against. One sentence, so the two read alike.
const NOTHING_RUNNING: &str =
    "not running: a refresh would build the image and boot the environment\n";

/// What a `vk dev` process should do once the environment is up.
enum Ready {
    /// this process is the one that acts on the environment
    Act,
    /// nothing more to do here — exit with this
    Done(ExitCode),
}

/// What `vk dev gc` removes.
enum Gc<'a> {
    /// every stale environment on the host
    AllStale,
    /// the environments on these state dirs, as this workspace's were resolved: by
    /// directory, so a name given to another environment since is not followed to it
    Dirs(&'a [PathBuf]),
}

/// Preview the selected environments and remove them after confirmation. A state dir with
/// no state is skipped, so a bare `gc` of an environment never booted succeeds. Without a
/// terminal or `--yes`, the command prints the preview without doing what it
/// was asked, and exits 1.
fn dev_gc(yes: bool, which: Gc<'_>) -> ExitCode {
    // Always measured: the preview's whole job is to show what is about to be destroyed.
    let selected = match crate::dev::list::state(true).and_then(|rows| match which {
        Gc::Dirs(dirs) => crate::dev::list::select_dirs(rows, dirs),
        Gc::AllStale => crate::dev::list::select_gc(rows, &[], true, crate::names::resolve),
    }) {
        Ok(s) => s,
        Err(e) => return fail(&e, 1),
    };
    if selected.is_empty() {
        return write_report("nothing to remove\n");
    }
    if !yes {
        let preview = crate::dev::list::preview(&selected);
        if !crate::dev::on_terminal() {
            let asked = format!("{preview}nothing was removed: --yes removes it\n");
            return match write_report(&asked) {
                ExitCode::SUCCESS => exit_code(1),
                code => code,
            };
        }
        match write_report(&preview) {
            ExitCode::SUCCESS => {}
            code => return code,
        }
        let question = format!("remove {} environment(s)?", selected.len());
        match crate::dev::ask_on_terminal(&question) {
            Ok(false) => return write_report("nothing was removed\n"),
            Ok(true) => {}
            Err(e) => return fail(&e, 1),
        }
    }
    match crate::names::Index::open().and_then(|idx| crate::dev::list::remove(&selected, &idx)) {
        Ok(report) => write_report(&report),
        Err(e) => fail(&e, 1),
    }
}

/// Stop the environment on the state dir `dir`; one already down succeeds.
fn stop_dir(dir: &Path, timeout: u64) -> ExitCode {
    match dev::stop(dir, timeout) {
        Ok(stopped) => match write_report(&stopped.report) {
            ExitCode::SUCCESS if !stopped.all_down => exit_code(1),
            code => code,
        },
        // A stop that fails is a runtime failure like any other; 2 is what this command
        // set reserves for a config or usage error.
        Err(e) => fail(&e, 1),
    }
}

/// With a workspace, combine its recorded state and declared environments and services.
/// Invalid config or compose input is a usage error (2). With `--all`, read only host state.
fn dev_list(
    cwd: &Path,
    scope: Option<(Option<&Path>, Option<&Path>)>,
    json: bool,
    sizes: bool,
    wide: bool,
) -> Result<String, ExitCode> {
    let here = match scope {
        None => None,
        Some((workspace, config)) => {
            let loaded = config::discover(cwd, workspace, config)
                // The common hint already names `vk dev list --all`.
                .map_err(|e| no_workspace_or(e, 2, None))?;
            let loaded = config::load(loaded).map_err(|e| fail(&e, 2))?;
            Some(declared_environments(&loaded).map_err(|e| fail(&e, 2))?)
        }
    };
    let (live, _) = crate::vms::registered();
    let rows = match &here {
        None => crate::dev::list::state_in(&live, sizes),
        Some((here, declared)) => crate::dev::list::state_in(&live, false).map(|mut rows| {
            // A state dir that recorded no boot is this workspace's only if its config
            // declares that dir.
            let dirs: Vec<PathBuf> = declared
                .iter()
                .map(|d| crate::vms::canonical(&d.state_dir))
                .collect();
            rows.retain(|r| match &r.workspace {
                Some(w) => crate::vms::canonical(w) == *here,
                None => dirs.contains(&crate::vms::canonical(&r.dir)),
            });
            if sizes {
                crate::dev::list::measure(&mut rows);
            }
            crate::dev::list::with_services(rows, declared, sizes, &|dir| {
                reported_units(&live, dir)
            })
        }),
    }
    .map_err(|e| fail(&e, 1))?;
    match (json, &here) {
        (true, _) => crate::dev::list::json(&rows).map_err(|e| fail(&e, 1)),
        (false, Some((here, _))) if rows.is_empty() => Ok(format!(
            "no dev environment for {} (`vk dev list --all` lists host-wide state)\n",
            here.display()
        )),
        (false, _) => Ok(crate::dev::list::render(&rows, wide)),
    }
}

/// Resolve the canonical workspace, state directories and secondary compose services.
/// List `dev` first when declared, then `[environments]`. Boot-only inputs such as
/// build contexts may be missing.
fn declared_environments(
    loaded: &config::Loaded,
) -> anyhow::Result<(PathBuf, Vec<crate::dev::list::Declared>)> {
    use anyhow::Context as _;
    let workspace = std::fs::canonicalize(&loaded.files.workspace)
        .with_context(|| format!("resolving {}", loaded.files.workspace.display()))?;
    let names = loaded
        .schema
        .dev
        .iter()
        .map(|_| "dev".to_string())
        .chain(loaded.schema.environments.keys().cloned());
    let mut declared = Vec::new();
    for environment in names {
        let env = loaded.environment(&environment)?;
        let services = match (&env.compose, &env.service) {
            (Some(compose), primary) => {
                let file = plan::in_workspace(&workspace, compose);
                let names = init::booted_service_names(&file)
                    .with_context(|| format!("the {environment} environment's compose file"))?;
                // Boot requires DNS labels. Service names also become state path components.
                for name in &names {
                    crate::compose::check_service_name(name)
                        .with_context(|| format!("in {}", file.display()))?;
                }
                if let Some(p) = primary
                    && !names.contains(p)
                {
                    anyhow::bail!("no compose service {p:?} in {}", file.display());
                }
                names
                    .into_iter()
                    .filter(|s| Some(s) != primary.as_ref())
                    .collect()
            }
            _ => Vec::new(),
        };
        declared.push(crate::dev::list::Declared {
            state_dir: plan::derived_state_dir(&workspace, &environment)?,
            environment,
            workspace: workspace.clone(),
            services,
        });
    }
    Ok((workspace, declared))
}

/// The units the service manager of the environment running on `state_dir` reports, as
/// `(name, state)`; `None` when nothing in `live` runs there or it cannot be asked.
fn reported_units(live: &[crate::vms::VmEntry], state_dir: &Path) -> Option<Vec<(String, String)>> {
    let dir = crate::vms::canonical(state_dir);
    let entry = live.iter().find(|e| e.state_dir == dir)?;
    Some(
        crate::vms::service_units(entry)?
            .into_iter()
            .map(|u| (u.name, u.state))
            .collect(),
    )
}

/// The exit status of a `vk dev` command that needs a workspace and was given none: it is
/// run outside any, with neither `--workspace` nor `$VIRTKIT_WORKSPACE`. Its own status, so
/// a script can tell "not in a workspace" from a workspace whose config is wrong (2).
pub(crate) const NO_WORKSPACE_EXIT: i32 = 5;

/// Fail with `e`: as [`NO_WORKSPACE_EXIT`] when it says there is no workspace — with, on a
/// terminal, how one is chosen and what works without one — and as `code` otherwise.
/// `host_wide` is the command that does this command's job on any workspace's VMs.
fn no_workspace_or(e: anyhow::Error, code: i32, host_wide: Option<&str>) -> ExitCode {
    if e.downcast_ref::<config::NoWorkspace>().is_none() {
        return fail(&e, code);
    }
    let status = fail(&e.context("not in a workspace"), NO_WORKSPACE_EXIT);
    if dev::on_terminal() {
        eprint!("{}", no_workspace_hint(host_wide));
    }
    status
}

/// How a workspace is chosen, for someone who ran `vk dev` outside one.
fn no_workspace_hint(host_wide: Option<&str>) -> String {
    let mut hint = format!(
        "vk: hint: `vk dev` works on one workspace, the project holding {file}:\n\
         \x20         cd into it, or name it with `vk dev --workspace DIR …` or {env}=DIR\n\
         \x20         `vk dev list --all` lists host-wide state, `vk list` every VM\n",
        file = config::CONFIG_FILE,
        env = config::WORKSPACE_ENV,
    );
    if let Some(cmd) = host_wide {
        hint.push_str(&format!("\x20         `{cmd}` works from anywhere\n"));
    }
    hint
}

/// Refuse a VM of another workspace, naming on a terminal the `vk` command that reaches it.
fn refuse_outside(name: &str, global: &str) -> ExitCode {
    let mut e = anyhow::anyhow!("{name} is not a VM of this workspace");
    if dev::on_terminal() {
        e = e.context(format!("`{global} {name}` looks up names host-wide"));
    }
    fail(&e, 2)
}

/// The state dirs of `names`, each an environment of this workspace, as `gc` and `prune`
/// take them. What is resolved here is what they act on: a name is not looked up
/// again, so one given to another environment meanwhile does not redirect them.
fn in_scope(workspace: &Path, names: &[String], global: &str) -> Result<Vec<PathBuf>, ExitCode> {
    let scope = super::targets::Scope {
        envs: super::targets::recorded(workspace).map_err(|e| fail(&e, 1))?,
        ..Default::default()
    };
    match super::targets::pick_envs(&scope, names, &super::targets::known_anywhere) {
        Ok(envs) => Ok(envs.into_iter().map(|e| e.dir).collect()),
        Err(e) => Err(match e.downcast_ref::<super::targets::Outside>() {
            Some(o) => refuse_outside(&o.0, global),
            None => fail(&e, 2),
        }),
    }
}

/// What the commands acting on named VMs carry from `vk`'s and `vk dev`'s own options.
#[derive(Clone, Copy)]
struct Globals<'a> {
    loaded: &'a config::Loaded,
    over: &'a dev::Overrides,
    /// the global `--config` this `vk` was given
    host_config: Option<&'a Path>,
}

/// A lifecycle verb on named services and environments.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Verb {
    Up { no_wait: bool },
    Start,
    Stop,
    Restart,
}

impl Verb {
    /// The `vk` command that does the same to a VM of any workspace.
    fn global(self) -> &'static str {
        match self {
            Verb::Up { .. } => "vk start --build",
            Verb::Start => "vk start",
            Verb::Stop => "vk stop",
            Verb::Restart => "vk restart",
        }
    }

    /// The `vk dev` verb that boots an environment for this one.
    fn boot(self) -> &'static [&'static str] {
        match self {
            Verb::Up { no_wait: true } => &["up", "--no-wait"],
            Verb::Up { no_wait: false } => &["up"],
            Verb::Start | Verb::Stop | Verb::Restart => &["start"],
        }
    }
}

/// `vk dev up | start | stop | restart NAME…`: act on each named service or environment in
/// turn, each once. An environment that has to boot does so in a `vk dev` of its own, so this
/// process boots nothing and can go on to the next name. The exit status is
/// [`crate::lifecycle::worst`] of theirs: 3 when all that failed were not built.
async fn act_on(
    verb: Verb,
    targets: &Targets,
    timeout: u64,
    plan: &plan::Plan,
    g: &Globals<'_>,
) -> ExitCode {
    use super::targets::Pick;
    let (scope, picks) = match picks(verb, targets, plan, g) {
        Ok(p) => p,
        Err(e) => {
            return match e.downcast_ref::<super::targets::Outside>() {
                Some(o) => refuse_outside(&o.0, verb.global()),
                None => fail(&e, 2),
            };
        }
    };
    let mut codes = Vec::new();
    for pick in picks {
        let (Pick::Env(env) | Pick::Service(env, _)) = &pick;
        // Stopping a resolved environment still works if its recorded config is gone.
        let own = match (&pick, verb) {
            (Pick::Env(_), Verb::Stop) => Ok(None),
            _ => own_config(env, scope.current.as_ref(), g),
        };
        let done = match own {
            Err(e) => Err(e),
            Ok(own) => {
                let g = &Globals {
                    loaded: own.as_ref().unwrap_or(g.loaded),
                    ..*g
                };
                match &pick {
                    Pick::Env(env) => env_verb(verb, env, timeout, g),
                    Pick::Service(env, service) => {
                        service_verb(verb, env, service, timeout, g).await
                    }
                }
            }
        };
        codes.push(match done {
            Ok(report) => u8::from(write_report(&report) != ExitCode::SUCCESS),
            Err(e) => {
                eprintln!("vk: {e:#}");
                if build::not_cached(&e) { 3 } else { 1 }
            }
        });
    }
    crate::lifecycle::worst(codes)
}

/// What the names `verb` was given resolve to, each once, and the scope they resolved in.
/// Another environment's services are what the config it last booted from declares.
fn picks(
    verb: Verb,
    targets: &Targets,
    plan: &plan::Plan,
    g: &Globals<'_>,
) -> anyhow::Result<(super::targets::Scope, Vec<super::targets::Pick>)> {
    use super::targets::{Env, catalog, pick, scope};
    let scope = scope(plan)?;
    let catalog_of = |env: &Env| {
        let own = own_config(env, scope.current.as_ref(), g)?;
        catalog(&plan::resolve(
            own.as_ref().unwrap_or(g.loaded),
            &env.environment,
        )?)
    };
    let picks = pick(
        &scope,
        &targets.names,
        &targets.services,
        &targets.vms,
        matches!(verb, Verb::Up { .. }),
        &super::targets::known_anywhere,
        &catalog_of,
    )?;
    Ok((scope, picks))
}

/// The config `env` was last booted from, when it is another environment of this workspace
/// and that is not the config this command read: its services, and how it boots again, are
/// that config's. `None` for the environment this command is about, and for one that
/// recorded no config.
fn own_config(
    env: &super::targets::Env,
    current: Option<&super::targets::Env>,
    g: &Globals<'_>,
) -> anyhow::Result<Option<config::Loaded>> {
    use anyhow::Context;
    let Some(recorded) = env.config.as_deref() else {
        return Ok(None);
    };
    let canonical = crate::vms::canonical;
    if current == Some(env) || canonical(recorded) == canonical(&g.loaded.files.config) {
        return Ok(None);
    }
    let workspace = &g.loaded.files.workspace;
    config::discover(workspace, Some(workspace), Some(recorded))
        .and_then(config::load)
        .map(Some)
        .with_context(|| format!("{} was booted with {}", env.name, recorded.display()))
}

/// Forward the target's workspace and config and the caller's overrides to [`dev_child`].
/// Keep paths as OS strings so non-UTF-8 paths survive the child invocation.
fn dev_child_args(environment: &str, verb: &[&str], g: &Globals<'_>) -> Vec<std::ffi::OsString> {
    use std::ffi::OsString;
    let joined = |flag: &str, value: &std::ffi::OsStr| {
        let mut arg = OsString::from(flag);
        arg.push("=");
        arg.push(value);
        arg
    };
    let mut args = Vec::new();
    if let Some(config) = g.host_config {
        args.push(joined("--config", config.as_os_str()));
    }
    args.push("dev".into());
    let files = &g.loaded.files;
    args.push(joined("--workspace", files.workspace.as_os_str()));
    args.push(joined("--dev-config", files.config.as_os_str()));
    args.push(joined("--environment", environment.as_ref()));
    if let Some(f) = g.over.freshness {
        args.push(joined("--freshness", f.as_str().as_ref()));
    }
    if let Some(r) = &g.over.cache_registry {
        args.push(joined("--cache-registry", r.as_ref()));
    }
    if g.over.cache_insecure {
        args.push("--cache-insecure".into());
    }
    args.extend(verb.iter().map(OsString::from));
    args
}

/// Run `vk dev <verb>` on `environment` of this workspace in a process of its own, its
/// output ours. One that exits 3 found something not built: a [`build::NotBuilt`].
fn dev_child(environment: &str, verb: &[&str], g: &Globals<'_>) -> anyhow::Result<()> {
    use anyhow::Context;
    let exe = std::env::current_exe().context("resolving the running vk")?;
    let status = std::process::Command::new(exe)
        .args(dev_child_args(environment, verb, g))
        .status()
        .context("running vk")?;
    let flag = hint_flags(environment, g);
    let ran = format!("`vk dev {flag}{}` {status}", verb.join(" "));
    match status.code() {
        Some(0) => Ok(()),
        Some(3) => Err(build::NotBuilt(format!("{ran}: `vk dev {flag}up` builds it")).into()),
        _ => anyhow::bail!("{ran}"),
    }
}

/// The `vk dev` options a hint names `environment` with: `--environment` but for `dev`, and
/// `--dev-config` for a config other than the workspace's own, which the command read.
fn hint_flags(environment: &str, g: &Globals<'_>) -> String {
    let files = &g.loaded.files;
    let config = match files.config == files.workspace.join(config::CONFIG_FILE) {
        true => String::new(),
        false => format!("--dev-config {} ", files.config.display()),
    };
    format!("{config}{}", environment_flag(environment))
}

/// Stop the environment on `dir`, then start it again from what is built.
fn restart_env(
    environment: &str,
    dir: &Path,
    timeout: u64,
    g: &Globals<'_>,
) -> anyhow::Result<String> {
    let stopped = dev::stop(dir, timeout)?;
    if !stopped.all_down {
        anyhow::bail!("{}it did not stop", stopped.report);
    }
    if write_report(&stopped.report) != ExitCode::SUCCESS {
        anyhow::bail!("writing what was stopped");
    }
    dev_child(environment, &["start"], g)?;
    Ok(String::new())
}

/// `verb` on an environment of this workspace.
fn env_verb(
    verb: Verb,
    env: &super::targets::Env,
    timeout: u64,
    g: &Globals<'_>,
) -> anyhow::Result<String> {
    match verb {
        Verb::Up { .. } | Verb::Start => {
            dev_child(&env.environment, verb.boot(), g)?;
            Ok(String::new())
        }
        Verb::Stop => {
            let stopped = dev::stop(&env.dir, timeout)?;
            if !stopped.all_down {
                anyhow::bail!("{}{} did not stop", stopped.report, env.name);
            }
            Ok(stopped.report)
        }
        Verb::Restart => restart_env(&env.environment, &env.dir, timeout, g),
    }
}

/// `verb` on the compose service `service` of `env`: a start brings the environment up
/// first, a stop leaves it up. Each stop socket operation has its own `timeout`.
async fn service_verb(
    verb: Verb,
    env: &super::targets::Env,
    service: &str,
    timeout: u64,
    g: &Globals<'_>,
) -> anyhow::Result<String> {
    use vk_core::fleetctl::Request;
    let plan = plan::resolve(g.loaded, &env.environment)?;
    let shown = format!("{}/{service}", env.name);
    let up = super::targets::running(&env.dir);
    let unit = service.to_string();
    let stop = Request::Stop { unit: unit.clone() };
    let start = |cached| match cached {
        true => Request::StartCached { unit: unit.clone() },
        false => Request::Start { unit: unit.clone() },
    };
    let reqs: Vec<Request> = match verb {
        Verb::Stop if !up => return Ok(format!("{shown} is not running\n")),
        Verb::Stop => vec![stop],
        Verb::Up { .. } => vec![start(false)],
        Verb::Start => vec![start(true)],
        Verb::Restart if up => vec![stop, start(true)],
        Verb::Restart => vec![start(true)],
    };
    if boots_first(verb, up) {
        dev_child(&env.environment, verb.boot(), g)?;
    }
    let mut out = String::new();
    for req in &reqs {
        let reply = match req {
            Request::Stop { .. } => {
                let within = Some(std::time::Duration::from_secs(timeout));
                dev::service_within(&plan, req, within, None).await?
            }
            _ => dev::service(&plan, req).await?,
        };
        let (lines, note) = render_service_reply(&reply);
        out.push_str(&lines);
        let said = note.unwrap_or_else(|| reply.message.clone());
        if reply.not_built {
            let flag = hint_flags(&env.environment, g);
            return Err(build::NotBuilt(format!(
                "{out}{shown}: {said} — `vk dev {flag}up --service {service}` builds it"
            ))
            .into());
        }
        if !reply.ok {
            anyhow::bail!("{out}{shown}: {said}");
        }
    }
    Ok(out)
}

/// Whether `verb` on a service brings its environment up first, in a `vk dev` of its own: `up`
/// always, as `vk dev service up` does, so a running environment meets the freshness policy
/// before its manager is asked for the service; a start only when it is not running.
fn boots_first(verb: Verb, running: bool) -> bool {
    match verb {
        Verb::Up { .. } => true,
        Verb::Start | Verb::Restart => !running,
        Verb::Stop => false,
    }
}

/// Bring the environment up, from whichever of the two processes this is (see `dev`'s module
/// docs). The child boots and then holds the VM, so it never gets here to act; where there
/// was nothing to boot it is finished too, and the parent — released once the guest is ready
/// — is what goes on to run the command.
///
/// Set `announce_reuse` to print a note when reusing a running environment.
async fn dev_up(
    plan: &crate::dev::plan::Plan,
    host_cfg: &crate::config::Config,
    over: &dev::Overrides,
    refresh: bool,
    wait: bool,
    announce_reuse: bool,
) -> Ready {
    if crate::detach::after_boot() {
        return match dev::after_boot(plan).await {
            Ok(_) => Ready::Act,
            Err(e) => Ready::Done(fail(&e, 1)),
        };
    }
    // Route each concurrent `up`'s result to its own parent. After reparenting, `getppid`
    // would send it to the adopter.
    let parent = crate::detach::parent_pid();
    match dev::boot(plan, host_cfg, over, refresh, wait, announce_reuse, parent).await {
        // Returned rather than blocked: there was nothing to boot. This process is done
        // either way — the parent it wakes is what acts on the environment.
        Ok(()) => Ready::Done(ExitCode::SUCCESS),
        Err(e) if build::not_cached(&e) => Ready::Done(fail(&e, 3)),
        Err(e) => Ready::Done(fail(&e, 1)),
    }
}

/// The half of [`dev_up`] an action that boots nothing still needs: this fork's child has no
/// boot to perform, so it is finished, and the parent — the one holding the terminal — is
/// what acts.
fn dev_after_fork() -> Ready {
    if crate::detach::after_boot() {
        Ready::Act
    } else {
        Ready::Done(ExitCode::SUCCESS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// The `vk dev` half of the CLI, parsed on its own.
    #[derive(Parser)]
    struct Harness {
        #[command(subcommand)]
        cmd: Which,
    }

    #[derive(Subcommand)]
    enum Which {
        Dev(Dev),
    }

    fn parse(args: &[&str]) -> Dev {
        let Which::Dev(dev) = Harness::parse_from(args).cmd;
        dev
    }

    #[test]
    fn schema_takes_no_flags_and_needs_no_workspace() {
        let dev = parse(&["vk", "dev", "schema"]);
        assert!(matches!(dev.action, DevAction::Schema));
        assert!(dev.workspace.is_none() && dev.dev_config.is_none());
        assert_eq!(dev.environment, "dev");
    }

    #[test]
    fn list_measures_sizes_by_default_and_no_sizes_opts_out() {
        assert!(matches!(
            parse(&["vk", "dev", "list"]).action,
            DevAction::List {
                no_sizes: false,
                ..
            }
        ));
        assert!(matches!(
            parse(&["vk", "dev", "list", "--no-sizes"]).action,
            DevAction::List { no_sizes: true, .. }
        ));
    }

    #[test]
    fn lifecycle_verbs_take_names_services_and_vms() {
        // No name is this workspace's environment, resolved from a config.
        assert!(matches!(
            parse(&["vk", "dev", "stop"]).action,
            DevAction::Stop { targets, .. } if targets.is_empty()
        ));
        // `down` is `stop`.
        assert!(matches!(
            parse(&["vk", "dev", "down", "db", "redis"]).action,
            DevAction::Stop { targets, .. } if targets.names == ["db", "redis"]
        ));
        // A local UI's: one state dir, never with a name.
        assert!(matches!(
            parse(&["vk", "dev", "stop", "--state-dir=/s/app-1234"]).action,
            DevAction::Stop { targets, state_dir: Some(d), .. }
                if targets.is_empty() && d == Path::new("/s/app-1234")
        ));
        for named in [&["a"][..], &["--service", "a"], &["--name", "a"]] {
            let mut args = vec!["vk", "dev", "stop", "--state-dir=/s/a"];
            args.extend(named);
            assert!(Harness::try_parse_from(args).is_err());
        }
        let Dev {
            action: DevAction::Start { targets },
            ..
        } = parse(&[
            "vk",
            "dev",
            "start",
            "db",
            "--service",
            "web",
            "--name",
            "app-test",
            "--service",
            "cache",
        ])
        else {
            panic!("not a start");
        };
        assert_eq!(targets.names, ["db"]);
        assert_eq!(targets.services, ["web", "cache"]);
        assert_eq!(targets.vms, ["app-test"]);
        assert!(matches!(
            parse(&["vk", "dev", "restart", "db"]).action,
            DevAction::Restart { targets, .. } if targets.names == ["db"]
        ));
        assert!(matches!(
            parse(&["vk", "dev", "up", "--no-wait", "db"]).action,
            DevAction::Up { no_wait: true, targets } if targets.names == ["db"]
        ));
        // Only a bare `up` or `start` boots in this process.
        assert!(parse(&["vk", "dev", "start"]).boots());
        assert!(!parse(&["vk", "dev", "start", "db"]).boots());
        assert!(!parse(&["vk", "dev", "up", "--service", "db"]).boots());
    }

    #[test]
    fn gc_takes_optional_names_or_all_stale_but_not_both() {
        // No name and no `--all-stale` is this workspace's environment, as with `stop`.
        assert!(matches!(
            parse(&["vk", "dev", "gc"]).action,
            DevAction::Gc { yes: false, all_stale: false, names } if names.is_empty()
        ));
        assert!(matches!(
            parse(&["vk", "dev", "gc", "a-1", "b-2"]).action,
            DevAction::Gc { all_stale: false, names, .. } if names == ["a-1", "b-2"]
        ));
        // Host-wide `--all-stale` would take a NAME of another workspace with it.
        let both = Harness::try_parse_from(["vk", "dev", "gc", "--all-stale", "a-1"]);
        assert!(both.is_err());
    }

    /// Record in `dir` a boot of `environment` of `workspace`, as `vk dev list` reads one.
    fn booted(dir: &Path, workspace: &Path, environment: &str) {
        std::fs::create_dir_all(dir).unwrap();
        let identity = dev::Identity {
            digest: "d".into(),
            booted_secs: 0,
            created_by: String::new(),
            generation: String::new(),
            manifest: serde_json::json!({
                "workspace": workspace,
                "environment": environment,
            }),
            storage_backings: Some(Vec::new()),
            readied_by_its_boot: true,
        };
        std::fs::write(dir.join("dev.json"), serde_json::to_vec(&identity).unwrap()).unwrap();
    }

    /// Scoped listing matches partial boots by directory and includes unbuilt declarations.
    /// Invalid config or compose input exits 2. Outside a workspace, listing exits 5
    /// unless `--all` selects host-wide state.
    #[test]
    fn a_bare_list_follows_the_config_and_all_lists_the_host() {
        const CHILD: &str = "VK_TEST_DEV_LIST";
        if std::env::var_os(CHILD).is_some() {
            let cwd = std::env::current_dir().unwrap();
            let ws = std::fs::canonicalize(&cwd).unwrap();
            let state = |env: &str| plan::derived_state_dir(&ws, env).unwrap();
            let base = state("dev").parent().unwrap().to_path_buf();
            booted(&state("dev"), &ws, "dev");
            // A first boot that failed before recording its identity.
            std::fs::create_dir_all(state("ci")).unwrap();
            let elsewhere = cwd.parent().unwrap().join("elsewhere");
            std::fs::create_dir_all(&elsewhere).unwrap();
            booted(&base.join("other"), &elsewhere, "dev");
            std::fs::create_dir_all(base.join("stray")).unwrap();
            let rows = |report: Result<String, ExitCode>| -> Vec<serde_json::Value> {
                serde_json::from_str(&report.unwrap()).unwrap()
            };
            let by_dir = |rows: &[serde_json::Value], dir: &Path| {
                let name = dir.file_name().unwrap().to_str().unwrap();
                rows.iter().find(|r| r["dir_name"] == name).cloned()
            };

            let here = rows(dev_list(&cwd, Some((Some(&cwd), None)), true, true, false));
            assert_eq!(here.len(), 3, "{here:#?}");
            let dev = by_dir(&here, &state("dev")).unwrap();
            assert_eq!(dev["status"], "stopped");
            assert!(dev["size_bytes"].is_u64(), "{dev}");
            let ci = by_dir(&here, &state("ci")).unwrap();
            assert_eq!(ci["status"], "never-booted");
            assert_eq!(ci["environment"], "ci");
            assert_eq!(ci["flags"], serde_json::json!(["ephemeral"]));
            let e2e = by_dir(&here, &state("e2e")).unwrap();
            assert_eq!(e2e["status"], "not-built");
            // Its prospective name may be another VM's: only `dir_name` identifies it.
            assert_eq!(e2e.get("name"), Some(&serde_json::Value::Null), "{e2e}");
            let e2e_dir = state("e2e");
            assert_eq!(
                e2e["dir_name"],
                e2e_dir.file_name().unwrap().to_str().unwrap()
            );
            assert!(dev["name"].is_string(), "{dev}");
            assert!(e2e.get("size_bytes").is_none(), "{e2e}");
            let table = dev_list(&cwd, Some((Some(&cwd), None)), false, false, false).unwrap();
            assert!(
                table
                    .lines()
                    .any(|l| l.starts_with("-  ") && l.contains("not built"))
            );

            // What the config declares is read, or the list fails as a usage error.
            let at = |name: &str, text: &str| {
                let path = cwd.join(".virtkit").join(name);
                std::fs::write(&path, text).unwrap();
                path
            };
            let compose = |file: &str| {
                format!("schema = 1\n[dev]\ncompose = \"{file}\"\nservice = \"app\"\n")
            };
            std::fs::write(cwd.join("bad.yaml"), "services: [\n").unwrap();
            // Nothing writes to it: reading it must not wait for a writer.
            use std::os::unix::ffi::OsStrExt as _;
            let fifo = std::ffi::CString::new(cwd.join("fifo.yaml").as_os_str().as_bytes());
            assert_eq!(unsafe { libc::mkfifo(fifo.unwrap().as_ptr(), 0o600) }, 0);
            let bad_name = "services:\n  app: {}\n  \"bad/name\": {}\n";
            std::fs::write(cwd.join("bad-name.yaml"), bad_name).unwrap();
            let bad_name = at("bad-name.toml", &compose("bad-name.yaml"));
            std::fs::write(cwd.join("no-app.yaml"), "services:\n  db: {}\n").unwrap();
            for config in [
                at("broken.toml", "schema = 1\n[dev\n"),
                at("gone.toml", &compose("gone.yaml")),
                at("bad.toml", &compose("bad.yaml")),
                at("fifo.toml", &compose("fifo.yaml")),
                bad_name.clone(),
                at("no-app.toml", &compose("no-app.yaml")),
            ] {
                let scope = Some((Some(cwd.as_path()), Some(config.as_path())));
                assert_eq!(
                    dev_list(&cwd, scope, true, false, false).unwrap_err(),
                    exit_code(2),
                    "{}",
                    config.display()
                );
            }

            // The service the boot would reject is named, with its file.
            let loaded = config::discover(&cwd, Some(&cwd), Some(&bad_name)).unwrap();
            let err = declared_environments(&config::load(loaded).unwrap()).unwrap_err();
            let err = format!("{err:#}");
            assert!(
                err.contains("\"bad/name\"") && err.contains("bad-name.yaml"),
                "{err}"
            );

            // A symlinked compose file is read through the link, as the boot reads it.
            std::fs::write(cwd.join("real.yaml"), "services:\n  app: {}\n  db: {}\n").unwrap();
            std::os::unix::fs::symlink("real.yaml", cwd.join("linked.yaml")).unwrap();
            let linked = at("linked.toml", &compose("linked.yaml"));
            let scope = Some((Some(cwd.as_path()), Some(linked.as_path())));
            let listed = rows(dev_list(&cwd, scope, true, false, false));
            let dev = by_dir(&listed, &state("dev")).unwrap();
            assert_eq!(dev["services"][0]["name"], "db", "{dev}");

            let nowhere = cwd.parent().unwrap().join("nowhere");
            std::fs::create_dir_all(&nowhere).unwrap();
            std::env::set_current_dir(&nowhere).unwrap();
            assert_eq!(
                dev_list(&nowhere, Some((None, None)), true, false, false).unwrap_err(),
                exit_code(NO_WORKSPACE_EXIT)
            );
            let all = rows(dev_list(&nowhere, None, true, false, false));
            assert_eq!(all.len(), 4, "{all:#?}");
            assert!(by_dir(&all, &base.join("other")).is_some());
            assert!(by_dir(&all, &base.join("stray")).is_some());
            assert!(
                by_dir(&all, &state("e2e")).is_none(),
                "--all reads no config"
            );
            return;
        }
        let _guard = crate::dev::testutil::env_guard();
        let tmp = crate::dev::testutil::scratch("dev-list");
        let cwd = tmp.0.join("ws");
        std::fs::create_dir_all(cwd.join(".virtkit")).unwrap();
        std::fs::write(
            cwd.join(config::CONFIG_FILE),
            "schema = 1\n[dev]\nimage = \"x\"\nworkspace = \"/w\"\n\
             [environments.ci]\nimage = \"x\"\nworkspace = \"/w\"\n\
             [environments.e2e]\nbuild = { context = \"gone\" }\nworkspace = \"/w\"\n",
        )
        .unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "dev::cli::tests::a_bare_list_follows_the_config_and_all_lists_the_host",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("XDG_STATE_HOME", tmp.0.join("state"))
            .env("XDG_DATA_HOME", tmp.0.join("data"))
            .env_remove(config::WORKSPACE_ENV)
            .current_dir(&cwd)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }

    #[test]
    fn bare_gc_removes_this_workspaces_environment_and_a_named_gc_stays_in_it() {
        const CHILD: &str = "VK_TEST_BARE_GC";
        if std::env::var_os(CHILD).is_some() {
            let cwd = std::env::current_dir().unwrap();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            let gc = |names: &[&str], all_stale: bool, config: Option<&Path>| {
                runtime.block_on(dev_action(
                    DevAction::Gc {
                        yes: true,
                        all_stale,
                        names: names.iter().map(|n| n.to_string()).collect(),
                    },
                    Some(&cwd),
                    config,
                    "dev",
                    &dev::Overrides::default(),
                    &crate::config::Config::default(),
                    None,
                ))
            };
            let files = config::discover(&cwd, Some(&cwd), None).unwrap();
            let plan = plan::resolve(&config::load(files).unwrap(), "dev").unwrap();
            let state_dir = plan.state_dir.clone();
            let base = state_dir.parent().unwrap().to_path_buf();
            let elsewhere = cwd.parent().unwrap().join("elsewhere");
            std::fs::create_dir_all(&elsewhere).unwrap();
            booted(&state_dir, &cwd, "dev");
            booted(&base.join("mine"), &cwd, "test");
            booted(&base.join("moved"), &cwd, "ci");
            booted(&base.join("other"), &elsewhere, "dev");
            std::fs::create_dir_all(base.join("stale")).unwrap();

            // A named gc takes this workspace's environments only: `other` is another's.
            assert_eq!(gc(&["other"], false, None), exit_code(2));
            assert_eq!(gc(&["nothing"], false, None), exit_code(2));
            assert!(base.join("other").is_dir());
            assert_eq!(gc(&["mine"], false, None), ExitCode::SUCCESS);
            assert!(!base.join("mine").exists());
            // A gc that cannot read its workspace's config takes nothing by name.
            let missing = cwd.join("missing.toml");
            assert_eq!(gc(&["moved"], false, Some(&missing)), exit_code(2));
            assert!(base.join("moved").is_dir());
            // What the workspace resolved is what goes, even when the name moves meanwhile
            // to another workspace's environment.
            let idx = crate::names::Index::open().unwrap();
            let (moved, other) = (base.join("moved"), base.join("other"));
            idx.release(&moved).unwrap();
            idx.claim_exact(&moved, "app-ci").unwrap();
            let dirs = in_scope(&plan.workspace, &["app-ci".into()], "vk delete").unwrap();
            idx.release(&moved).unwrap();
            idx.release(&other).unwrap();
            idx.claim_exact(&other, "app-ci").unwrap();
            assert_eq!(dev_gc(true, Gc::Dirs(&dirs)), ExitCode::SUCCESS);
            assert!(!base.join("moved").exists());
            assert!(base.join("other").is_dir());
            // Named cleanup reads the workspace from the config, not the boot inputs it
            // names: a compose file gone since does not stand in its way.
            let composed = cwd.join(".virtkit/composed.toml");
            std::fs::write(
                &composed,
                "schema = 1\n[dev]\ncompose = \"gone.yaml\"\nservice = \"app\"\n",
            )
            .unwrap();
            booted(&base.join("pruned"), &cwd, "pruned");
            booted(&base.join("collected"), &cwd, "collected");
            let prune = parse(&["vk", "dev", "prune", "pruned", "--dry-run"]).action;
            let pruned = runtime.block_on(dev_action(
                prune,
                Some(&cwd),
                Some(&composed),
                "dev",
                &dev::Overrides::default(),
                &crate::config::Config::default(),
                None,
            ));
            assert_eq!(pruned, ExitCode::SUCCESS);
            assert_eq!(
                gc(&["collected"], false, Some(&composed)),
                ExitCode::SUCCESS
            );
            assert!(!base.join("collected").exists());

            assert_eq!(gc(&[], false, None), ExitCode::SUCCESS);
            assert!(!state_dir.exists());
            // Already gone is what a gc leaves, not a failure.
            assert_eq!(gc(&[], false, None), ExitCode::SUCCESS);
            // A bare gc reads the config, so a missing one is a usage error.
            assert_eq!(gc(&[], false, Some(&missing)), exit_code(2));
            // `--all-stale` is host-wide and never reads the config.
            assert_eq!(gc(&[], true, Some(&missing)), ExitCode::SUCCESS);
            assert!(!base.join("stale").exists());
            assert!(base.join("other").is_dir());
            return;
        }
        let _guard = crate::dev::testutil::env_guard();
        let tmp = crate::dev::testutil::scratch("bare-gc");
        let cwd = tmp.0.join("ws");
        std::fs::create_dir_all(cwd.join(".virtkit")).unwrap();
        std::fs::write(
            cwd.join(config::CONFIG_FILE),
            "schema = 1\n[dev]\nimage = \"x\"\nworkspace = \"/w\"\n",
        )
        .unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "dev::cli::tests::bare_gc_removes_this_workspaces_environment_and_a_named_gc_stays_in_it",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("XDG_STATE_HOME", tmp.0.join("state"))
            .env("XDG_DATA_HOME", tmp.0.join("data"))
            .current_dir(&cwd)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }

    /// A named stop takes only this workspace's services and environments: a VM of another
    /// workspace, a name nothing has, and a name that cannot be one are refused alike. Outside any
    /// workspace, a `vk dev` command that needs one exits 5.
    #[test]
    fn a_named_stop_stays_in_its_workspace() {
        const CHILD: &str = "VK_TEST_NAMED_STOP";
        if std::env::var_os(CHILD).is_some() {
            let cwd = std::env::current_dir().unwrap();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            let stop = |name: &str, workspace: Option<&Path>| {
                runtime.block_on(dev_action(
                    DevAction::Stop {
                        targets: Targets {
                            names: vec![name.into()],
                            ..Targets::default()
                        },
                        state_dir: None,
                        timeout: 0,
                    },
                    workspace,
                    None,
                    "dev",
                    &dev::Overrides::default(),
                    &crate::config::Config::default(),
                    None,
                ))
            };
            assert_eq!(stop("known", Some(&cwd)), ExitCode::SUCCESS);
            for name in ["elsewhere", "unknown", "linked", "../outside"] {
                assert_eq!(stop(name, Some(&cwd)), exit_code(2), "{name}");
            }
            let nowhere = cwd.parent().unwrap().join("nowhere");
            std::fs::create_dir_all(&nowhere).unwrap();
            std::env::set_current_dir(&nowhere).unwrap();
            assert_eq!(stop("known", None), exit_code(NO_WORKSPACE_EXIT));
            return;
        }
        let _guard = crate::dev::testutil::env_guard();
        let tmp = crate::dev::testutil::scratch("named-stop");
        let state = tmp.0.join("state");
        let base = state.join("virtkit/dev");
        let cwd = tmp.0.join("ws");
        std::fs::create_dir_all(cwd.join(".virtkit")).unwrap();
        std::fs::write(
            cwd.join(config::CONFIG_FILE),
            "schema = 1\n[dev]\nimage = \"x\"\nworkspace = \"/w\"\n",
        )
        .unwrap();
        booted(&base.join("known"), &cwd, "test");
        booted(&base.join("elsewhere"), &tmp.0, "dev");
        std::os::unix::fs::symlink(base.join("known"), base.join("linked")).unwrap();
        std::fs::create_dir_all(state.join("virtkit/outside")).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "dev::cli::tests::a_named_stop_stays_in_its_workspace",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("XDG_STATE_HOME", &state)
            .env("XDG_DATA_HOME", tmp.0.join("data"))
            .env_remove(config::WORKSPACE_ENV)
            .current_dir(&cwd)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(base.join("known").is_dir());
    }

    #[test]
    fn the_workspace_is_the_flag_else_the_environment_variable() {
        let flag = Some(PathBuf::from("/a"));
        let env = Some(std::ffi::OsString::from("/b"));
        assert_eq!(config::chosen_workspace(flag.clone(), env.clone()), flag);
        assert_eq!(
            config::chosen_workspace(None, env),
            Some(PathBuf::from("/b"))
        );
        assert_eq!(config::chosen_workspace(None, Some("".into())), None);
        assert!(
            no_workspace_hint(Some("vk stop NAME")).contains("`vk stop NAME` works from anywhere")
        );
    }

    /// A named environment boots in a `vk dev` of its own, given what this one was: the global
    /// `--config` and the `vk dev` options, with every path as it is, bytes and all.
    #[test]
    fn a_child_boot_carries_this_one_s_options_and_paths() {
        use std::ffi::{OsStr, OsString};
        use std::os::unix::ffi::OsStrExt;
        let tmp = crate::dev::testutil::scratch("child-args");
        let ws = tmp.0.join(OsStr::from_bytes(b"ws-\xff"));
        std::fs::create_dir_all(ws.join(".virtkit")).unwrap();
        std::fs::write(
            ws.join(config::CONFIG_FILE),
            "schema = 1\n[dev]\nimage = \"x\"\nworkspace = \"/w\"\n",
        )
        .unwrap();
        let loaded = config::load(config::discover(&ws, Some(&ws), None).unwrap()).unwrap();
        let host = tmp.0.join(OsStr::from_bytes(b"vk-\xfe.toml"));
        let over = dev::Overrides {
            freshness: Some(config::Freshness::Reuse),
            cache_registry: Some("none".into()),
            cache_insecure: true,
            ..Default::default()
        };
        let g = Globals {
            loaded: &loaded,
            over: &over,
            host_config: Some(&host),
        };
        let joined = |flag: &str, path: &Path| {
            let mut arg = OsString::from(flag);
            arg.push(path.as_os_str());
            arg
        };
        assert_eq!(
            dev_child_args("test", &["up", "--no-wait"], &g),
            [
                joined("--config=", &host),
                "dev".into(),
                joined("--workspace=", &loaded.files.workspace),
                joined("--dev-config=", &loaded.files.config),
                "--environment=test".into(),
                "--freshness=reuse".into(),
                "--cache-registry=none".into(),
                "--cache-insecure".into(),
                "up".into(),
                "--no-wait".into(),
            ]
        );
        let g = Globals {
            host_config: None,
            over: &dev::Overrides::default(),
            ..g
        };
        assert_eq!(dev_child_args("dev", &["start"], &g)[0], "dev");
        assert_eq!(environment_flag("dev"), "");
        assert_eq!(environment_flag("test"), "--environment test ");
    }

    /// Another environment of this workspace goes by the config it was booted with: two
    /// configs giving `test` different primaries, `ENV/SERVICE` and the child boot follow the
    /// one `shop-test` recorded, not the one this command read.
    #[test]
    fn another_environment_goes_by_the_config_it_was_booted_with() {
        let homes = crate::dev::testutil::Homes::new("own-config");
        let ws = homes.dir().join("shop");
        std::fs::create_dir_all(ws.join(".virtkit")).unwrap();
        std::fs::write(
            ws.join("compose.yaml"),
            "services:\n  app:\n    image: x\n  db:\n    image: y\n",
        )
        .unwrap();
        let config = |primary: &str| {
            format!(
                "schema = 1\n[dev]\ncompose = \"compose.yaml\"\nservice = \"app\"\n\
                 [environments.test]\ncompose = \"compose.yaml\"\nservice = \"{primary}\"\n"
            )
        };
        std::fs::write(ws.join(config::CONFIG_FILE), config("db")).unwrap();
        let alt = ws.join(".virtkit/alt.toml");
        std::fs::write(&alt, config("app")).unwrap();
        let loaded = config::load(config::discover(&ws, Some(&ws), None).unwrap()).unwrap();
        let plan = plan::resolve(&loaded, "dev").unwrap();
        let base = plan.state_dir.parent().unwrap().to_path_buf();
        let recorded = |dir: &Path, config: &Path| {
            std::fs::create_dir_all(dir).unwrap();
            let identity = dev::Identity {
                digest: "d".into(),
                booted_secs: 0,
                created_by: String::new(),
                generation: String::new(),
                manifest: serde_json::json!({
                    "workspace": ws,
                    "environment": "test",
                    "config": config,
                }),
                storage_backings: Some(Vec::new()),
                readied_by_its_boot: true,
            };
            std::fs::write(dir.join("dev.json"), serde_json::to_vec(&identity).unwrap()).unwrap();
        };
        recorded(&base.join("shop-test"), &alt);
        let over = dev::Overrides::default();
        let g = Globals {
            loaded: &loaded,
            over: &over,
            host_config: None,
        };
        let targets = Targets {
            names: vec!["shop-test/db".into()],
            ..Targets::default()
        };
        let (scope, picked) = picks(Verb::Stop, &targets, &plan, &g).unwrap();
        let [super::super::targets::Pick::Service(env, service)] = picked.as_slice() else {
            panic!("{picked:?}");
        };
        assert_eq!((env.name.as_str(), service.as_str()), ("shop-test", "db"));
        assert_eq!(hint_flags("test", &g), "--environment test ");
        let own = own_config(env, scope.current.as_ref(), &g)
            .unwrap()
            .unwrap();
        let g = Globals { loaded: &own, ..g };
        let args = dev_child_args("test", &["start"], &g);
        let mut want = std::ffi::OsString::from("--dev-config=");
        want.push(&own.files.config);
        assert!(args.contains(&want), "{args:?}");
        // What it finds not built, an `up` from that config builds.
        assert_eq!(
            hint_flags("test", &g),
            format!(
                "--dev-config {} --environment test ",
                own.files.config.display()
            )
        );
        assert_eq!(
            crate::vms::canonical(&own.files.config),
            crate::vms::canonical(&alt)
        );
        // Booted with the config this command read: nothing else to read.
        recorded(&base.join("shop-test"), &loaded.files.config);
        let (_, picked) = picks(Verb::Stop, &targets, &plan, &g).unwrap();
        assert!(
            matches!(picked.as_slice(), [super::super::targets::Pick::Env(_)]),
            "{picked:?}"
        );
        // A stop of the environment needs only its state dir: the config it was booted with,
        // gone since, does not stand in its way. A restart reads it.
        recorded(&base.join("shop-test"), &alt);
        std::fs::remove_file(&alt).unwrap();
        let g = Globals {
            loaded: &loaded,
            over: &over,
            host_config: None,
        };
        let targets = Targets {
            vms: vec!["shop-test".into()],
            ..Targets::default()
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let act = |verb| runtime.block_on(act_on(verb, &targets, 0, &plan, &g));
        assert_eq!(act(Verb::Stop), ExitCode::SUCCESS);
        assert_eq!(act(Verb::Restart), ExitCode::from(1));
    }

    /// `up` of a service brings its environment up first even while it runs, so the freshness
    /// policy applies before its manager is asked; a start does only when it is down.
    #[test]
    fn a_service_up_goes_through_its_environment_s_up() {
        assert!(boots_first(Verb::Up { no_wait: false }, true));
        assert!(boots_first(Verb::Up { no_wait: false }, false));
        assert!(!boots_first(Verb::Start, true) && boots_first(Verb::Start, false));
        assert!(!boots_first(Verb::Restart, true) && boots_first(Verb::Restart, false));
        assert!(!boots_first(Verb::Stop, false));
    }

    #[test]
    fn prune_takes_an_optional_name_selector() {
        assert!(matches!(
            parse(&["vk", "dev", "prune"]).action,
            DevAction::Prune { name: None, .. }
        ));
        assert!(matches!(
            parse(&["vk", "dev", "prune", "myenv-1a2b", "--all"]).action,
            DevAction::Prune { name: Some(n), .. } if n == "myenv-1a2b"
        ));
    }

    #[test]
    fn a_service_reply_renders_units_and_routes_the_message_by_verdict() {
        use vk_core::fleetctl::{Reply, UnitStatus};
        let unit = |name: &str, state: &str, ip: &str| UnitStatus {
            name: name.into(),
            state: state.into(),
            ip: ip.into(),
        };
        // Success with a message: the unit lines and then the message land on stdout, with
        // nothing on stderr.
        let (out, note) = render_service_reply(&Reply {
            ok: true,
            message: "runner is up".into(),
            units: vec![unit("runner", "running", "127.0.0.2")],
            not_built: false,
        });
        let line = format!("{:<16} {:<9} {}\n", "runner", "running", "127.0.0.2");
        assert_eq!(out, format!("{line}runner is up\n"));
        assert!(note.is_none());

        // Failure with a message: the message goes to stderr, not stdout.
        let (out, note) = render_service_reply(&Reply {
            ok: false,
            message: "no such service".into(),
            units: vec![],
            not_built: false,
        });
        assert_eq!(out, "");
        assert_eq!(note.as_deref(), Some("no such service"));

        // Failure with no message still says something, so the non-zero exit is not silent.
        let (_out, note) = render_service_reply(&Reply {
            ok: false,
            message: String::new(),
            units: vec![],
            not_built: false,
        });
        assert!(note.is_some());
    }

    /// Every `vk dev` action, as a command line, with whether it boots the environment.
    /// The test below asserts this covers every subcommand clap knows, so a new action
    /// cannot be added without saying which side of the fork it is on.
    const ACTIONS: &[(&[&str], bool)] = &[
        (&["init"], false),
        (&["up"], true),
        (&["up", "db"], false),
        (&["start"], true),
        (&["start", "--service", "db"], false),
        (&["restart"], false),
        (&["restart", "db"], false),
        (&["exec", "--", "true"], true),
        (&["exec", "--service", "db", "--", "true"], false),
        (&["shell"], true),
        (&["shell", "--service", "db"], false),
        (&["code"], true),
        (&["editor", "status"], false),
        (&["editor", "reset"], false),
        (&["endpoints", "--primary"], false),
        (&["open", "app"], false),
        (&["service", "up", "runner"], true),
        (&["service", "down", "runner"], false),
        (&["service", "reboot", "runner"], false),
        (&["service", "status"], false),
        (&["task", "pre-commit"], true),
        (&["build"], false),
        (&["storage", "list"], false),
        (&["storage", "reset", "runner:/var/wab", "--yes"], false),
        (&["editor-reconcile", "--editor", "code"], false),
        (&["ssh"], false),
        (&["ssh-config"], false),
        (&["refresh"], true),
        (&["refresh", "--dry-run"], false),
        (&["status"], false),
        (&["logs", "-f"], false),
        (&["doctor"], false),
        (&["stop"], false),
        (&["down", "db"], false),
        (&["list"], false),
        (&["gc", "--all-stale", "--yes"], false),
        (&["prune"], false),
        (&["plan", "--diff"], false),
        (&["schema"], false),
    ];

    #[test]
    fn every_action_says_whether_it_boots_the_environment() {
        use clap::CommandFactory;

        for (argv, boots) in ACTIONS {
            let mut args = vec!["vk", "dev"];
            args.extend_from_slice(argv);
            assert_eq!(parse(&args).boots(), *boots, "vk dev {}", argv.join(" "));
        }
        // The fork happens before anything is dispatched, so an action missing from the
        // table above is an action whose fork nobody has checked.
        let cmd = <Harness as CommandFactory>::command();
        let dev = cmd
            .get_subcommands()
            .find(|c| c.get_name() == "dev")
            .expect("the dev subcommand");
        for sub in dev.get_subcommands() {
            assert!(
                ACTIONS.iter().any(|(argv, _)| argv[0] == sub.get_name()),
                "vk dev {} is not in ACTIONS",
                sub.get_name()
            );
        }
    }

    #[test]
    fn the_global_flags_are_accepted_on_either_side_of_the_action() {
        let dev = parse(&["vk", "dev", "--workspace", "/w", "status", "--json"]);
        assert_eq!(dev.workspace.as_deref(), Some(Path::new("/w")));
        assert!(matches!(dev.action, DevAction::Status { json: true }));
        let dev = parse(&["vk", "dev", "status", "--workspace", "/w"]);
        assert_eq!(dev.workspace.as_deref(), Some(Path::new("/w")));
    }
}
