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
    /// the workspace, instead of finding it from the current directory
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
    /// what to do about a running environment that no longer matches the config
    ///
    /// Overrides the config's own `freshness` for this invocation.
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

/// `vk dev`: the entry point `main` dispatches to.
pub async fn run(dev: Dev, host_cfg: &crate::config::Config) -> ExitCode {
    let over = dev::Overrides {
        cache_registry: dev.cache_registry,
        cache_insecure: dev.cache_insecure,
        freshness: dev.freshness,
    };
    dev_action(
        dev.action,
        dev.workspace.as_deref(),
        dev.dev_config.as_deref(),
        &dev.environment,
        &over,
        host_cfg,
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
    /// the same configuration is a no-op; one running a different configuration is handled
    /// as the config's `freshness` (or `--freshness`) says. To rebuild and restart one that
    /// matches, use `vk dev refresh`.
    Up {
        /// fail promptly when a boot someone else started is in flight, instead of joining it
        #[arg(long)]
        no_wait: bool,
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
        /// The service must be running (`vk dev service up`). It gets none of the primary's
        /// contract — no `exec-env`, no `user`, no workspace directory — only what is passed
        /// here: the service is its own guest.
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
    /// The session `vk dev exec` gives a command, with a terminal: the config's `user` and
    /// `exec-env`, in the guest directory that stands for yours. Ends when the shell does;
    /// the environment stays up, so opening another costs nothing.
    Shell,
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
    },
    /// Follow or retry the editor reconciliation, apart from the VM's own status
    ///
    /// `vk dev code` leaves a detached operation behind that brings the guest's VS Code
    /// server to what `[dev.editor.vscode]` says, once Remote-SSH has installed it. These
    /// say whether it is still running and how it went, print its log, or run it again in
    /// the foreground. None of them boots the environment.
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
    /// The same operations `vk service` offers inside the guest, addressed through the
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
    /// long as this environment's state directory is.
    #[command(name = "ssh-config")]
    SshConfig,
    /// Rebuild the environment and restart it into the result
    ///
    /// Unconditional, and the only command that is: `up` leaves an environment that matches
    /// its config alone, and `--freshness` only says what one that has drifted gets. The
    /// build runs while the current environment keeps working, so the only downtime is the
    /// restart itself — and a build that fails leaves what is running alone. Does not ask: a
    /// wrapper that wants to confirm first should do the asking.
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
    /// Stop the environment and everything published from it
    ///
    /// Powers the guest off and takes down the publishers that were reaching into it. The
    /// state directory stays — its storage, keys and identity are what the next `vk dev up`
    /// starts from; `vk dev gc` is what removes it. Stopping what is already stopped is the
    /// state asked for, not a failure.
    Stop {
        /// seconds to wait for it to go
        #[arg(long, default_value_t = super::boot::STOP_TIMEOUT_SECS)]
        timeout: u64,
    },
    /// List every dev environment this host keeps state for
    ///
    /// Host-wide, and needs no config in the current directory: one row per state directory
    /// under `$XDG_STATE_HOME/virtkit/dev` — which workspace and environment it belongs to,
    /// whether it is running, which vk created it, how long ago it last booted and — with
    /// `--sizes` — what it holds on disk. Flagged when its workspace is gone, or when it
    /// recorded no boot at all — the shape a task run in a throwaway environment leaves.
    /// Reads only.
    List {
        /// print the same facts as JSON
        #[arg(long)]
        json: bool,
        /// measure what each environment holds on disk, which reads every file in it
        #[arg(long)]
        sizes: bool,
    },
    /// Remove the state of environments that are finished with
    ///
    /// Takes the environments named, or with `--all-stale` every one that is not running and
    /// whose workspace is gone or that never recorded a boot. A running environment is
    /// refused. Without `--yes`, lists what would go — including the storage inside each —
    /// and removes nothing; on a terminal it asks instead. Also needs no config.
    Gc {
        /// remove without asking
        #[arg(long)]
        yes: bool,
        /// every environment whose workspace is gone, or that recorded no boot
        #[arg(long = "all-stale")]
        all_stale: bool,
        /// the environments to remove, as `vk dev list` names them
        #[arg(value_name = "NAME")]
        names: Vec<String>,
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
            Self::Up { .. } | Self::Shell | Self::Code { .. } | Self::Task { .. } => true,
            // A service exec reaches a running service and boots nothing.
            Self::Exec { service, .. } => service.is_none(),
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
            | Self::SshConfig
            | Self::Status { .. }
            | Self::Logs { .. }
            | Self::Doctor
            | Self::Stop { .. }
            | Self::List { .. }
            | Self::Gc { .. }
            | Self::Plan { .. }
            | Self::Schema => false,
        }
    }
}

/// `vk dev editor`: the reconciliation that follows `vk dev code`.
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
    },
    /// Reboot a running service's guest in place (same VM, no image rebuild)
    Reboot {
        /// the service
        name: String,
    },
    /// Print a service's state and address, or every service's when no name is given
    ///
    /// One line per service: `<name> <state> <address>`, as `vk service status` prints it.
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

/// `vk dev service`: print the manager's answer as `vk service` prints it — the unit lines,
/// then the message — and turn its verdict into the exit code.
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

/// `vk dev`: resolve the workspace's config, then act on the plan.
async fn dev_action(
    action: DevAction,
    workspace: Option<&Path>,
    config: Option<&Path>,
    environment: &str,
    over: &dev::Overrides,
    host_cfg: &crate::config::Config,
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
    // Like `init`, these host-wide commands read the state base and need no config.
    if let DevAction::List { json, sizes } = action {
        let report = match crate::dev::list::state(sizes).and_then(|rows| match json {
            true => crate::dev::list::json(&rows),
            false => Ok(crate::dev::list::render(&rows)),
        }) {
            Ok(report) => report,
            Err(e) => return fail(&e, 1),
        };
        return write_report(&report);
    }
    if let DevAction::Gc {
        yes,
        all_stale,
        names,
    } = action
    {
        return dev_gc(yes, all_stale, &names);
    }
    // A config that cannot be read or does not describe something virtkit can build is the
    // caller's to fix, like a usage error.
    let loaded = match config::discover(&cwd, workspace, config).and_then(config::load) {
        Ok(l) => l,
        Err(e) => return fail(&e, 2),
    };
    let plan = match plan::resolve(&loaded, environment) {
        Ok(p) => p,
        Err(e) => return fail(&e, 2),
    };
    match action {
        DevAction::Up { no_wait } => match dev_up(&plan, host_cfg, over, false, !no_wait).await {
            Ready::Act => ExitCode::SUCCESS,
            Ready::Done(code) => code,
        },
        DevAction::Refresh { dry_run: true } => match dev::plan_diff(&plan) {
            Ok(Some(report)) => write_report(&format!(
                "{report}a refresh rebuilds the image and restarts the environment\n"
            )),
            Ok(None) => write_report(NOTHING_RUNNING),
            Err(e) => fail(&e, 1),
        },
        // The one unconditional rebuild-and-restart: `up` never reboots an environment
        // that matches, and `--freshness` only says what a drifted one gets.
        DevAction::Refresh { dry_run: false } => {
            match dev_up(&plan, host_cfg, over, true, true).await {
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
        } => match dev_up(&plan, host_cfg, over, false, true).await {
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
        } => match dev_up(&plan, host_cfg, over, false, true).await {
            Ready::Done(code) => code,
            Ready::Act => service_reply(
                dev::service(&plan, &vk_core::fleetctl::Request::Start { unit: name }).await,
            ),
        },
        DevAction::Service {
            action: DevServiceAction::Down { name },
        } => service_reply(
            dev::service(&plan, &vk_core::fleetctl::Request::Stop { unit: name }).await,
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
        DevAction::Shell => match dev_up(&plan, host_cfg, over, false, true).await {
            Ready::Done(code) => code,
            Ready::Act => {
                let argv: Vec<String> = dev::LOGIN_SHELL.iter().map(|s| s.to_string()).collect();
                match dev::exec_in_guest(
                    &plan,
                    &argv,
                    dev::guest_cwd(&plan),
                    true,
                    vk_core::exec::client::Stdin::Forward,
                )
                .await
                {
                    Ok(result) => exec::exit(result),
                    Err(e) => fail(&e, 1),
                }
            }
        },
        DevAction::Code { editor } => match dev_up(&plan, host_cfg, over, false, true).await {
            Ready::Done(code) => code,
            Ready::Act => {
                let editor = match crate::dev::editor::select(editor.as_deref()) {
                    Ok(e) => e,
                    Err(e) => return fail(&e, 1),
                };
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
                Some(target) => dev_up(target, host_cfg, over, false, true).await,
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
        DevAction::SshConfig => match sshclient::print_config(&plan.state_dir) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        },
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
            let target = Some(plan.state_dir.as_path());
            // A stopped environment is no longer registered, but its state directory still
            // says where each service kept its console: `svc-<name>/`.
            let path = console_log_path(target, service.as_deref()).or_else(|e| match &service {
                Some(name) => {
                    let log = plan
                        .state_dir
                        .join(format!("svc-{name}"))
                        .join(crate::run::CONSOLE_LOG);
                    if log.is_file() { Ok(log) } else { Err(e) }
                }
                None => Err(e),
            });
            match path {
                Ok(path) => {
                    match show_console_log(&path, target, &sources, level, lines, follow).await {
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
        DevAction::Stop { timeout } => match dev::stop(&plan, timeout) {
            Ok(stopped) => match write_report(&stopped.report) {
                ExitCode::SUCCESS if !stopped.all_down => exit_code(1),
                code => code,
            },
            // A stop that fails is a runtime failure like any other; 2 is what this command
            // set reserves for a config or usage error.
            Err(e) => fail(&e, 1),
        },
        DevAction::Init { .. }
        | DevAction::List { .. }
        | DevAction::Gc { .. }
        | DevAction::Schema => {
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

/// `vk dev gc`: choose what goes, show it, ask, and remove exactly that. Host-wide, so it
/// works from a directory with no config. A run that only showed what would go did not do
/// what it was asked, and exits 1.
fn dev_gc(yes: bool, all_stale: bool, names: &[String]) -> ExitCode {
    // Always measured: the preview's whole job is to show what is about to be destroyed.
    let selected = match crate::dev::list::state(true)
        .and_then(|rows| crate::dev::list::select_gc(rows, names, all_stale))
    {
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
    match crate::dev::list::remove(&selected) {
        Ok(report) => write_report(&report),
        Err(e) => fail(&e, 1),
    }
}

/// Bring the environment up, from whichever of the two processes this is (see `dev`'s module
/// docs). The child boots and then holds the VM, so it never gets here to act; where there
/// was nothing to boot it is finished too, and the parent — released once the guest is ready
/// — is what goes on to run the command.
async fn dev_up(
    plan: &crate::dev::plan::Plan,
    host_cfg: &crate::config::Config,
    over: &dev::Overrides,
    refresh: bool,
    wait: bool,
) -> Ready {
    if crate::detach::after_boot() {
        return match dev::after_boot(plan).await {
            Ok(_) => Ready::Act,
            Err(e) => Ready::Done(fail(&e, 1)),
        };
    }
    // getppid: the parent reads back what this boot decided, and two concurrent `up`s must
    // not read each other's.
    // SAFETY: getppid always succeeds and touches no memory.
    let parent = unsafe { libc::getppid() } as u32;
    match dev::boot(plan, host_cfg, over, refresh, wait, parent).await {
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
        });
        let line = format!("{:<16} {:<9} {}\n", "runner", "running", "127.0.0.2");
        assert_eq!(out, format!("{line}runner is up\n"));
        assert!(note.is_none());

        // Failure with a message: the message goes to stderr, not stdout.
        let (out, note) = render_service_reply(&Reply {
            ok: false,
            message: "no such service".into(),
            units: vec![],
        });
        assert_eq!(out, "");
        assert_eq!(note.as_deref(), Some("no such service"));

        // Failure with no message still says something, so the non-zero exit is not silent.
        let (_out, note) = render_service_reply(&Reply {
            ok: false,
            message: String::new(),
            units: vec![],
        });
        assert!(note.is_some());
    }

    /// Every `vk dev` action, as a command line, with whether it boots the environment.
    /// The test below asserts this covers every subcommand clap knows, so a new action
    /// cannot be added without saying which side of the fork it is on.
    const ACTIONS: &[(&[&str], bool)] = &[
        (&["init"], false),
        (&["up"], true),
        (&["exec", "--", "true"], true),
        (&["exec", "--service", "db", "--", "true"], false),
        (&["shell"], true),
        (&["code"], true),
        (&["editor", "status"], false),
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
        (&["list"], false),
        (&["gc", "--all-stale", "--yes"], false),
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
