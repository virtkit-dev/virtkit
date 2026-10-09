//! `vk-hub` — the fleet hub. Nodes running `vk node` enroll with it, hold a session to it,
//! and report their inventory and heartbeats; operators issue enrollment tokens, list the
//! fleet and steer it. See `docs/fleet-design.md` and `docs/fleet-prototype.md`.
//!
//! `vk-hub local` serves a web UI for the VMs of the machine it runs on instead, as the user
//! who owns them, on a loopback name of its own ("Local mode" in the prototype's reference).
//! People sign in with single-use links the hub prints, or issues over a unix socket only its
//! own user reaches; what they do is recorded in an audit log.
//!
//! Experimental. The hub steers its nodes only within what each node's own configuration
//! allows: a concurrency ceiling, stopping and resuming acquisition, drain and quarantine —
//! all issued over the admin socket, audited, and resent to a node until it has them. It holds
//! `vk` releases and serves each only to a node it has asked to update to it, and rolls a
//! release out to the fleet a wave at a time. A node
//! whose `vk` speaks only the first fleet protocol version is monitored, not steered. A web UI
//! on a listener of its own shows the fleet to people signed in with links the admin socket
//! issues. Automation holding an API key — `vk-gitlab` — reserves capacity on nodes and has
//! jobs placed on them through the client API (`docs/gitlab-dispatch.md`).

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};

mod admin;
mod client;
mod config;
mod fetch;
mod jobs;
mod local;
mod ops;
mod releases;
mod rollout;
mod server;
mod session;
mod store;
mod ui;
mod workloads;

use config::HubConfig;
use vk_hub_proto::{Acquisition, Operation};

// Match vk-registry: jemalloc under musl for a long-lived server.
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

/// Fleet hub: node enrollment, inventory, heartbeats and steering; and a web UI for this
/// machine's VMs (experimental)
#[derive(Parser)]
#[command(name = "vk-hub", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

/// The config file every subcommand reads: `serve` for everything, the others for the data
/// directory whose admin socket they dial.
#[derive(clap::Args)]
struct ConfigArg {
    /// hub.toml: addr, tls_cert, tls_key, data_dir, ui_addr, ui_url, ui_tls_cert,
    /// ui_tls_key, release_repository, job_lost_after_secs, job_history, [oidc] [default:
    /// built-in defaults]
    #[arg(long, value_name = "FILE", global = true)]
    config: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve nodes until stopped
    Serve {
        #[command(flatten)]
        config: ConfigArg,
    },
    /// Manage enrollment tokens
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
    /// List the enrolled nodes, or steer or remove one
    Nodes {
        #[command(flatten)]
        config: ConfigArg,
        #[command(subcommand)]
        cmd: Option<NodesCmd>,
    },
    /// Keep vk binaries for nodes to update to
    Release {
        #[command(flatten)]
        config: ConfigArg,
        #[command(subcommand)]
        cmd: ReleaseCmd,
    },
    /// Roll a release out to the fleet, a wave at a time
    Rollout {
        #[command(flatten)]
        config: ConfigArg,
        #[command(subcommand)]
        cmd: RolloutCmd,
    },
    /// List the VMs running on the nodes: CI jobs, dev environments, pinned runs
    Workloads {
        #[command(flatten)]
        config: ConfigArg,
        /// Only this node's: its ID, or a hostname only it has
        #[arg(long, value_name = "NODE")]
        node: Option<String>,
    },
    /// Show the audit log: operators' actions and what nodes reported of them
    Audit {
        #[command(flatten)]
        config: ConfigArg,
        /// Only this node's lines
        #[arg(long, value_name = "ID")]
        node: Option<String>,
        /// How many of the latest lines
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Sign in to the web UI, and see or end its sessions
    Ui {
        #[command(flatten)]
        config: ConfigArg,
        #[command(subcommand)]
        cmd: UiCmd,
    },
    /// List, grant and revoke who may sign in to the web UI through OIDC, and as what
    ///
    /// A grant gives an email address the provider signs someone in with a role; `*` makes
    /// anyone else it signs in a viewer. Grants are kept in the hub's database and take effect
    /// at once, on a hub with [oidc]; nobody else may sign in through it.
    Accounts {
        #[command(flatten)]
        config: ConfigArg,
        #[command(subcommand)]
        cmd: Option<AccountsCmd>,
    },
    /// Issue, list and revoke the API keys automation such as vk-gitlab places jobs with
    Keys {
        #[command(flatten)]
        config: ConfigArg,
        #[command(subcommand)]
        cmd: Option<KeysCmd>,
    },
    /// List the jobs placed on the fleet through the client API, newest first
    Jobs {
        #[command(flatten)]
        config: ConfigArg,
        /// How many of the latest
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Serve a web UI for this machine's VMs, signed into with a link it prints
    ///
    /// Runs as you and shows the VMs you run: pinned `vk run`s, dev environments and CI jobs.
    /// It keeps its state in $XDG_STATE_HOME/virtkit/hub-local and serves on loopback under a
    /// name drawn as it starts, `vk-<random>.localhost`; sessions end when it restarts. The
    /// sign-in link opens in the browser unless --no-browser, and is printed when that is
    /// given or stderr is a terminal.
    #[command(args_conflicts_with_subcommands = true)]
    Local {
        /// Where the hub keeps its database and admin socket
        /// [default: $XDG_STATE_HOME/virtkit/hub-local]
        #[arg(long, value_name = "DIR", global = true)]
        state_dir: Option<std::path::PathBuf>,
        #[command(flatten)]
        args: LocalArgs,
        #[command(subcommand)]
        cmd: Option<LocalCmd>,
    },
}

#[derive(Subcommand)]
enum ReleaseCmd {
    /// Copy a vk binary into the hub, as the version it reports
    ///
    /// The hub never runs it: it checks that the file is an x86-64 ELF holding the version
    /// as a string of its own. The file must be readable by the hub's user.
    Add {
        /// The vk binary
        file: PathBuf,
        /// The version its `vk --version` prints
        #[arg(long)]
        version: String,
        /// A file holding a release key's signature of it, as `vk release-key sign` prints
        /// one
        #[arg(long, value_name = "FILE")]
        signature: Option<PathBuf>,
    },
    /// Download a release's vk from the hub's release_repository and hold it
    ///
    /// The hub downloads the vk of that virtkit release (linux x86-64), requires it to hash to
    /// the sha256 the release publishes beside it and to hold the version as a string of its
    /// own, and holds it unsigned. That proves the bytes are the ones published, not who built
    /// them; a node that requires signed releases refuses it.
    Fetch {
        /// The release's version, or `latest`
        #[arg(default_value = "latest")]
        version: String,
        /// Only print which version the latest release is
        #[arg(long, conflicts_with = "version")]
        check: bool,
    },
    /// List the releases the hub holds
    List,
    /// Delete a release, unless a node is still updating to it or a rollout of it is not over
    Remove {
        /// Its sha256, or at least the first 8 hex digits
        release: String,
    },
}

#[derive(Subcommand)]
enum RolloutCmd {
    /// Start updating nodes to a release, a wave at a time
    ///
    /// Each wave's nodes are updated and back where they were before the next starts; nodes
    /// already running the release, and nodes only monitored, are skipped. A failed node
    /// pauses the rollout, and one failure past --max-failures aborts it.
    Create {
        /// The release's sha256, or at least its first 8 hex digits
        #[arg(long)]
        release: String,
        /// `all`, or node IDs (at least their first 8 hex digits) separated by commas
        #[arg(long, default_value = "all")]
        nodes: String,
        /// Nodes per wave
        #[arg(long, default_value_t = 1)]
        batch: u32,
        /// Update one node of each hardware profile first, on its own
        ///
        /// A profile is the CPU model, the RAM rounded to a power of two, and the declared
        /// speed of the job and checkout filesystems.
        #[arg(long)]
        canary_per_profile: bool,
        /// Failures to absorb, pausing at each, before aborting
        #[arg(long, default_value_t = 0)]
        max_failures: u32,
        /// How long a node's update may take once drained: <n>m, <n>h or <n>d (1m to 7d)
        ///
        /// The node rolls the release back past it, and the rollout counts the failure.
        #[arg(long, default_value = "30m", value_parser = parse_window)]
        node_timeout: Duration,
        /// How long a node may take to drain for its update: <n>m, <n>h or <n>d (1m to 7d)
        ///
        /// A node still draining then calls the update off.
        #[arg(long, default_value = "4h", value_parser = parse_window)]
        drain_timeout: Duration,
        /// Include nodes whose runner is external, updated without a drain
        #[arg(long)]
        force: bool,
    },
    /// List the rollouts, or show one node by node
    Status {
        /// The rollout's ID, or at least its first 4 hex digits
        id: Option<String>,
    },
    /// Issue no more updates until resumed; those under way finish
    Pause { id: String },
    /// Carry on with a paused rollout
    Resume { id: String },
    /// End a rollout for good; updates under way finish
    Abort { id: String },
}

/// A rollout's window for a node: from a minute to a week.
fn parse_window(s: &str) -> Result<Duration, String> {
    match parse_ttl(s, Duration::from_secs(7 * 86_400), "a window") {
        Ok(d) if d >= Duration::from_secs(60) => Ok(d),
        _ => Err(format!("{s:?}: expected <n>m, <n>h or <n>d, from 1m to 7d")),
    }
}

#[derive(Subcommand)]
enum UiCmd {
    /// Print a single-use link that opens a web UI session
    ///
    /// The link is a credential until it is used or expires: open it yourself, pasting it into
    /// the browser rather than passing it on a command line, which other local users can
    /// read, or hand it only to whoever the session is for.
    Login {
        /// viewer (read only) or operator
        #[arg(long, default_value = "viewer", value_parser = parse_role)]
        role: store::Role,
        /// How long the link stays valid: <n>s, <n>m, <n>h or <n>d (at most 1d)
        #[arg(long, default_value = "10m", value_parser = parse_login_ttl)]
        ttl: Duration,
    },
    /// List the open web UI sessions
    Sessions,
    /// End a web UI session, as `vk-hub ui sessions` lists it, or every one
    Logout {
        #[arg(required_unless_present = "all")]
        id: Option<String>,
        #[arg(long, conflicts_with = "id")]
        all: bool,
    },
}

#[derive(Debug, Subcommand)]
enum AccountsCmd {
    /// List every grant (the default)
    List,
    /// Give an email address a role, replacing the one it was granted
    ///
    /// Its open web UI sessions that hold more than a sign-in now gets end.
    Grant {
        /// The address, compared ignoring ASCII case, or `*`: anyone the provider signs in,
        /// with a verified email or not, whom no grant of their own names (viewer only)
        #[arg(value_parser = parse_account)]
        email: String,
        /// viewer (read only) or operator
        #[arg(long, value_parser = parse_role)]
        role: store::Role,
    },
    /// Remove a grant and end the web UI sessions it admitted that a sign-in no longer would
    Revoke {
        /// The address, or `*`
        #[arg(value_parser = parse_account)]
        email: String,
    },
}

#[derive(Subcommand)]
enum KeysCmd {
    /// List every key, revoked and expired ones included (the default)
    List,
    /// Issue an API key, printed once
    ///
    /// The key is a bearer credential for the hub's client API: hand it to the automation
    /// it is for through a file only it reads, never on a command line.
    Create {
        /// What the key is for, unique among the keys that work: letters, digits, '.', '_', '-'
        #[arg(long)]
        name: String,
        /// jobs (reserve capacity, place and follow jobs) or capacity (only ask for room);
        /// repeat for both
        #[arg(long = "scope", value_name = "SCOPE", default_value = "jobs", value_parser = parse_scope)]
        scopes: Vec<store::Scope>,
        /// A pool its jobs may be placed in, or * for any; repeat for several
        #[arg(long = "pool", value_name = "POOL", required = true)]
        pools: Vec<String>,
        /// The most memory one of its jobs may ask for: <n>M, <n>G or <n>T
        #[arg(long, value_name = "SIZE", value_parser = parse_mem_size)]
        max_mem: Option<u64>,
        /// The most CPUs one of its jobs may ask for
        #[arg(long, value_name = "N")]
        max_cpus: Option<u32>,
        /// The most job disk one of its jobs may ask for: <n>M, <n>G or <n>T
        #[arg(long, value_name = "SIZE", value_parser = parse_size)]
        max_disk: Option<u64>,
        /// How long the key works: <n>s, <n>m, <n>h or <n>d (at most 365d)
        #[arg(long, default_value = "90d", value_parser = parse_key_ttl)]
        ttl: Duration,
    },
    /// Revoke the working key of that name; with none working, remove those that no longer
    /// work
    Revoke { name: String },
}

fn parse_scope(s: &str) -> Result<store::Scope, String> {
    store::Scope::parse(s).ok_or_else(|| format!("{s:?}: expected jobs or capacity"))
}

/// A size in bytes: a number with a binary unit, `K`, `M`, `G` or `T`.
fn parse_size(s: &str) -> Result<u64, String> {
    let bad = || format!("{s:?}: expected <n>K, <n>M, <n>G or <n>T");
    let (n, unit) = s.split_at(s.len().saturating_sub(1));
    let shift = match unit {
        "K" | "k" => 10,
        "M" | "m" => 20,
        "G" | "g" => 30,
        "T" | "t" => 40,
        _ => return Err(bad()),
    };
    let n: u64 = n.parse().map_err(|_| bad())?;
    n.checked_mul(1 << shift).filter(|b| *b > 0).ok_or_else(bad)
}

/// A memory size, at least 1 MiB: envelopes count memory in MiB.
fn parse_mem_size(s: &str) -> Result<u64, String> {
    let bytes = parse_size(s)?;
    if bytes < 1 << 20 {
        return Err(format!("{s:?}: expected at least 1M"));
    }
    Ok(bytes)
}

/// An API key's lifetime, at most [`store::MAX_KEY_TTL`].
fn parse_key_ttl(s: &str) -> Result<Duration, String> {
    parse_ttl(s, store::MAX_KEY_TTL, "a key")
}

/// An email address, or `*`.
fn parse_account(s: &str) -> Result<String, String> {
    store::account_key(s).ok_or_else(|| format!("{s:?} is neither an email address nor *"))
}

#[derive(clap::Args)]
struct LocalArgs {
    /// The loopback port to serve on [default: one the system picks]
    #[arg(long)]
    port: Option<u16>,
    /// Print the sign-in link without opening a browser
    #[arg(long)]
    no_browser: bool,
    /// The vk to run [default: the one beside vk-hub, else vk on PATH]
    #[arg(long, value_name = "PATH")]
    vk: Option<std::path::PathBuf>,
}

/// `vk-hub local`'s own sign-in commands: `vk-hub ui`'s, for the local hub.
#[derive(Subcommand)]
enum LocalCmd {
    /// Print another single-use link that opens a session on the running `vk-hub local`
    ///
    /// The link is a credential until it is used or expires: open it yourself, pasting it into
    /// the browser rather than passing it on a command line, which other local users can read.
    Login {
        /// viewer (read only) or operator (also acts on the VMs)
        #[arg(long, default_value = "operator", value_parser = parse_role)]
        role: store::Role,
        /// How long the link stays valid: <n>s, <n>m, <n>h or <n>d (at most 1d)
        #[arg(long, default_value = "10m", value_parser = parse_login_ttl)]
        ttl: Duration,
    },
    /// List the open web UI sessions
    Sessions,
    /// End a web UI session, as `vk-hub local sessions` lists it, or every one
    Logout {
        #[arg(required_unless_present = "all")]
        id: Option<String>,
        #[arg(long, conflicts_with = "id")]
        all: bool,
    },
}

impl From<LocalCmd> for UiCmd {
    fn from(cmd: LocalCmd) -> Self {
        match cmd {
            LocalCmd::Login { role, ttl } => UiCmd::Login { role, ttl },
            LocalCmd::Sessions => UiCmd::Sessions,
            LocalCmd::Logout { id, all } => UiCmd::Logout { id, all },
        }
    }
}

#[derive(Subcommand)]
enum NodesCmd {
    /// Remove a node: unpin its key and end its session
    ///
    /// The host can join again only as a new node, with a new token.
    Remove {
        /// The node's ID, as `vk-hub nodes` lists it
        id: String,
    },
    /// Cap how many jobs the node's runner accepts, or lift the cap with `none`
    ///
    /// The node takes the smallest of this, its own estimate and its local ceiling; the hub
    /// only ever lowers what the node would take.
    Ceiling {
        id: String,
        /// A number of jobs, or `none`
        #[arg(value_parser = parse_ceiling)]
        ceiling: Ceiling,
    },
    /// Stop the node's runner taking new jobs; running ones finish
    ///
    /// With `[node] runner = "external"`, the node stops taking the jobs the hub places and
    /// reports that its runner may still take jobs. Drain and quarantine behave the same way.
    Stop { id: String },
    /// Let the node's runner take jobs again
    Resume { id: String },
    /// Stop taking jobs and report `drained` once everything running has finished
    ///
    /// With `[node] runner = "external"`, only the jobs the hub places.
    Drain { id: String },
    /// End a drain: back to `ready`, taking jobs
    Undrain { id: String },
    /// Stop taking jobs until `release`, whatever else the node is told
    ///
    /// With `[node] runner = "external"`, only the jobs the hub places.
    Quarantine { id: String },
    /// End a quarantine: back to `ready`
    Release { id: String },
    /// Drain the node, clear what its past jobs left, validate, and return it where it was
    ///
    /// The node stops whatever its user still runs from past jobs and removes their job
    /// directories and its idle host checkouts; the build cache's registry store is never
    /// touched. A node that fails validation afterwards stays drained. Needs `[node] runner =
    /// "managed"` on the node.
    Reset {
        id: String,
        /// Evict the node's materialized images too
        #[arg(long)]
        images: bool,
    },
    /// Put the node in the pools placed jobs name, replacing those it was in, or `none`
    Pools {
        id: String,
        /// Pool names separated by commas, or `none`
        pools: String,
    },
    /// Ask the node to replace its vk with a release the hub holds
    Update {
        id: String,
        /// The release's sha256, or at least its first 8 hex digits
        #[arg(long)]
        release: String,
        /// Update without draining when vk node cannot drain the external runner
        #[arg(long)]
        force: bool,
    },
}

/// `nodes ceiling`'s value: a number, or none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ceiling(Option<u32>);

fn parse_ceiling(s: &str) -> Result<Ceiling, String> {
    if s == "none" {
        return Ok(Ceiling(None));
    }
    match s.parse::<u32>() {
        Ok(n) if n > 0 => Ok(Ceiling(Some(n))),
        _ => Err(format!(
            "{s:?}: expected a number of jobs of at least 1, or none — stopping acquisition is \
             `vk-hub nodes stop`"
        )),
    }
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Issue a single-use enrollment token, printed once
    Create {
        #[command(flatten)]
        config: ConfigArg,
        /// How long the token stays valid: <n>s, <n>m, <n>h or <n>d (at most 30d)
        #[arg(long, default_value = "1h", value_parser = parse_token_ttl)]
        ttl: Duration,
    },
}

fn parse_role(s: &str) -> Result<store::Role, String> {
    match s {
        "viewer" => Ok(store::Role::Viewer),
        "operator" => Ok(store::Role::Operator),
        _ => Err(format!("{s:?}: expected viewer or operator")),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vk-hub: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Serve { config } => serve(HubConfig::load(config.config.as_deref())?).await,
        Cmd::Token {
            cmd: TokenCmd::Create { config, ttl },
        } => {
            let client = admin_client(&HubConfig::load(config.config.as_deref())?)?;
            let created = tokio::task::spawn_blocking(move || client.create_token(ttl)).await??;
            // The token alone on stdout, so `$(vk-hub token create)` captures just it.
            println!("{}", created.token);
            eprintln!(
                "vk-hub: single-use, valid for {}; enroll with `vk node join <hub-url> --token -` \
                 reading it on stdin",
                human_duration(ttl)
            );
            Ok(())
        }
        Cmd::Nodes { config, cmd } => {
            let client = admin_client(&HubConfig::load(config.config.as_deref())?)?;
            match cmd {
                None => {
                    let nodes = tokio::task::spawn_blocking(move || client.list_nodes()).await??;
                    print!("{}", render_nodes(&nodes, now_secs()));
                    Ok(())
                }
                Some(NodesCmd::Remove { id }) => {
                    let what = id.clone();
                    if !tokio::task::spawn_blocking(move || client.remove_node(&id)).await?? {
                        bail!("there is no node {what}");
                    }
                    eprintln!("vk-hub: removed node {what}");
                    Ok(())
                }
                Some(NodesCmd::Ceiling { id, ceiling }) => {
                    let changed =
                        tokio::task::spawn_blocking(move || client.set_ceiling(&id, ceiling.0))
                            .await??;
                    report_desired(changed.as_ref());
                    Ok(())
                }
                Some(NodesCmd::Stop { id }) => acquisition(client, id, Acquisition::Stop).await,
                Some(NodesCmd::Resume { id }) => acquisition(client, id, Acquisition::Run).await,
                Some(NodesCmd::Drain { id }) => command(client, id, Operation::Drain).await,
                Some(NodesCmd::Undrain { id }) => command(client, id, Operation::Undrain).await,
                Some(NodesCmd::Quarantine { id }) => {
                    command(client, id, Operation::Quarantine).await
                }
                Some(NodesCmd::Release { id }) => command(client, id, Operation::Release).await,
                Some(NodesCmd::Reset { id, images }) => {
                    command(client, id, Operation::Reset { images }).await
                }
                Some(NodesCmd::Pools { id, pools }) => {
                    let pools: Vec<String> = match pools.as_str() {
                        "none" => Vec::new(),
                        list => list
                            .split(',')
                            .map(|p| p.trim().to_string())
                            .filter(|p| !p.is_empty())
                            .collect(),
                    };
                    let changed =
                        tokio::task::spawn_blocking(move || client.set_pools(&id, pools)).await??;
                    if !changed {
                        eprintln!("vk-hub: already so; nothing changed");
                    }
                    Ok(())
                }
                Some(NodesCmd::Update { id, release, force }) => {
                    let command = tokio::task::spawn_blocking(move || {
                        client.update_node(&id, &release, force)
                    })
                    .await??;
                    eprintln!(
                        "vk-hub: issued {} (command {}); `vk-hub audit --node <id>` shows what \
                         the node makes of it",
                        store::operation_name(&command.op),
                        command.id
                    );
                    Ok(())
                }
            }
        }
        Cmd::Release { config, cmd } => {
            let client = admin_client(&HubConfig::load(config.config.as_deref())?)?;
            match cmd {
                ReleaseCmd::Add {
                    file,
                    version,
                    signature,
                } => {
                    let signature = signature.map(|path| read_signature(&path)).transpose()?;
                    // Absolute, since the hub resolves it from its own working directory.
                    let file = std::path::absolute(&file)
                        .with_context(|| format!("resolving {}", file.display()))?;
                    let added = tokio::task::spawn_blocking(move || {
                        client.add_release(&file, &version, signature)
                    })
                    .await??;
                    // The sha256 alone on stdout, so `$(vk-hub release add …)` captures it.
                    println!("{}", added.sha256);
                    eprintln!(
                        "vk-hub: holding vk {} ({} bytes); `vk-hub nodes update <id> --release \
                         {}` updates a node to it",
                        added.row.version,
                        added.row.size,
                        store::short(&added.sha256)
                    );
                }
                ReleaseCmd::Fetch { check: true, .. } => {
                    let latest =
                        tokio::task::spawn_blocking(move || client.latest_release()).await??;
                    println!("{latest}");
                }
                ReleaseCmd::Fetch { version, .. } => {
                    let version = fetch::wanted(&version)?;
                    let fetched = tokio::task::spawn_blocking(move || {
                        client.fetch_release(version.as_deref())
                    })
                    .await??;
                    // The sha256 alone on stdout, as `release add` prints it.
                    println!("{}", fetched.sha256);
                    eprintln!(
                        "vk-hub: holding vk {} ({} bytes, unsigned); `vk-hub rollout create \
                         --release {}` rolls it out",
                        fetched.row.version,
                        fetched.row.size,
                        store::short(&fetched.sha256)
                    );
                }
                ReleaseCmd::List => {
                    let releases = tokio::task::spawn_blocking(move || client.releases()).await??;
                    for r in releases {
                        println!(
                            "{}  {:<12}  {:>10}  {:<8}  added {} by {}",
                            r.sha256,
                            r.row.version,
                            r.row.size,
                            if r.row.signature.is_some() {
                                "signed"
                            } else {
                                "unsigned"
                            },
                            utc(r.row.added_at),
                            r.row.added_by
                        );
                    }
                }
                ReleaseCmd::Remove { release } => {
                    let what = release.clone();
                    match tokio::task::spawn_blocking(move || client.remove_release(&release))
                        .await??
                    {
                        Some(r) => eprintln!("vk-hub: removed release {}", r.sha256),
                        None => bail!("there is no release {what}"),
                    }
                }
            }
            Ok(())
        }
        Cmd::Rollout { config, cmd } => {
            let client = admin_client(&HubConfig::load(config.config.as_deref())?)?;
            rollout_cmd(client, cmd).await
        }
        Cmd::Audit {
            config,
            node,
            limit,
        } => {
            let client = admin_client(&HubConfig::load(config.config.as_deref())?)?;
            let rows =
                tokio::task::spawn_blocking(move || client.audit(node.as_deref(), limit)).await??;
            for row in rows {
                println!(
                    "{}  {}  {}  {}",
                    utc(row.at),
                    row.node.as_deref().unwrap_or("-"),
                    row.actor,
                    row.event
                );
            }
            Ok(())
        }
        Cmd::Ui { config, cmd } => {
            ui_cmd(
                admin_client(&HubConfig::load(config.config.as_deref())?)?,
                cmd,
            )
            .await
        }
        Cmd::Accounts { config, cmd } => {
            accounts_cmd(
                admin_client(&HubConfig::load(config.config.as_deref())?)?,
                cmd.unwrap_or(AccountsCmd::List),
            )
            .await
        }
        Cmd::Local {
            state_dir,
            args,
            cmd: None,
        } => {
            local::serve(local::Options {
                state_dir,
                port: args.port,
                open_browser: !args.no_browser,
                vk: args.vk,
            })
            .await
        }
        Cmd::Local {
            state_dir,
            cmd: Some(cmd),
            ..
        } => {
            let state_dir = match state_dir {
                Some(dir) => dir,
                None => local::state_dir()?,
            };
            let socket = state_dir.join(local::ADMIN_SOCKET);
            ui_cmd(
                admin_client_at(&socket, "vk-hub local` running")?,
                cmd.into(),
            )
            .await
        }
        Cmd::Keys { config, cmd } => {
            keys_cmd(
                admin_client(&HubConfig::load(config.config.as_deref())?)?,
                cmd.unwrap_or(KeysCmd::List),
            )
            .await
        }
        Cmd::Jobs { config, limit } => {
            let client = admin_client(&HubConfig::load(config.config.as_deref())?)?;
            let jobs = tokio::task::spawn_blocking(move || client.jobs(limit)).await??;
            print!("{}", render_jobs(&jobs, now_secs()));
            Ok(())
        }
        Cmd::Workloads { config, node } => {
            let client = admin_client(&HubConfig::load(config.config.as_deref())?)?;
            let nodes =
                tokio::task::spawn_blocking(move || client.workloads(node.as_deref())).await??;
            print!("{}", render_workloads(&nodes));
            Ok(())
        }
    }
}

async fn rollout_cmd(client: admin::Client, cmd: RolloutCmd) -> Result<()> {
    use rollout::RolloutAction;
    match cmd {
        RolloutCmd::Create {
            release,
            nodes,
            batch,
            canary_per_profile,
            max_failures,
            node_timeout,
            drain_timeout,
            force,
        } => {
            let nodes = match nodes.as_str() {
                "all" => ops::Selection::All,
                list => ops::Selection::Nodes(
                    list.split(',')
                        .map(|n| n.trim().to_string())
                        .filter(|n| !n.is_empty())
                        .collect(),
                ),
            };
            let plan = ops::RolloutPlan {
                release,
                nodes,
                batch,
                canary_per_profile,
                max_failures,
                node_timeout_secs: node_timeout.as_secs(),
                drain_timeout_secs: drain_timeout.as_secs(),
                force,
            };
            let r = tokio::task::spawn_blocking(move || client.create_rollout(plan)).await??;
            // The ID alone on stdout, so `$(vk-hub rollout create …)` captures it.
            println!("{}", r.id);
            eprint!("{}", render_rollout(&r, now_secs()));
        }
        RolloutCmd::Status { id: None } => {
            let rollouts = tokio::task::spawn_blocking(move || client.rollouts()).await??;
            for r in rollouts {
                println!("{}", rollout_line(&r));
            }
        }
        RolloutCmd::Status { id: Some(id) } => {
            rollout::check_prefix(&id)?;
            let rollouts = tokio::task::spawn_blocking(move || client.rollouts()).await??;
            let mut found = rollouts.iter().filter(|r| r.id.starts_with(id.as_str()));
            match (found.next(), found.next()) {
                (Some(r), None) => print!("{}", render_rollout(r, now_secs())),
                (None, _) => bail!("there is no rollout {id}"),
                (Some(_), Some(_)) => bail!("{id} names more than one rollout; give more digits"),
            }
        }
        RolloutCmd::Pause { id } => steer_rollout(client, id, RolloutAction::Pause).await?,
        RolloutCmd::Resume { id } => steer_rollout(client, id, RolloutAction::Resume).await?,
        RolloutCmd::Abort { id } => steer_rollout(client, id, RolloutAction::Abort).await?,
    }
    Ok(())
}

async fn steer_rollout(
    client: admin::Client,
    id: String,
    action: rollout::RolloutAction,
) -> Result<()> {
    let r = tokio::task::spawn_blocking(move || client.steer_rollout(&id, action)).await??;
    eprintln!(
        "vk-hub: rollout {} is {}",
        rollout::short_id(&r.id),
        rollout_state(&r.row.state)
    );
    Ok(())
}

/// One line of `vk-hub rollout status`: what it is and how far it has got.
pub(crate) fn rollout_line(r: &rollout::Rollout) -> String {
    let counts: Vec<String> = r
        .counts()
        .iter()
        .filter(|(_, n)| *n > 0)
        .map(|(name, n)| format!("{n} {name}"))
        .collect();
    let wave = match r.wave() {
        Some(w) if r.row.state.active() => format!(" at wave {w}"),
        _ => String::new(),
    };
    format!(
        "{}  vk {} ({})  {}{wave}  started {} by {}  {}",
        r.id,
        r.row.version,
        store::short(&r.row.release),
        rollout_state(&r.row.state),
        utc(r.row.created_at),
        r.row.created_by,
        counts.join(", ")
    )
}

/// A rollout's state, with why it is paused or aborted.
pub(crate) fn rollout_state(s: &rollout::RolloutState) -> String {
    match s {
        rollout::RolloutState::Paused { reason } | rollout::RolloutState::Aborted { reason } => {
            format!("{} ({reason})", s.name())
        }
        _ => s.name().to_string(),
    }
}

/// A node of a rollout, as its status shows it.
pub(crate) fn rollout_node_status(s: &rollout::NodeStatus, now: u64) -> String {
    use rollout::NodeStatus;
    match s {
        NodeStatus::Pending => "pending".to_string(),
        NodeStatus::Skipped { reason } => format!("skipped: {reason}"),
        NodeStatus::Updating { command, since, .. } => format!(
            "updating for {} (command {command})",
            human_duration(ago(now, *since))
        ),
        NodeStatus::Succeeded { at } => format!("succeeded at {}", utc(*at)),
        NodeStatus::Failed { reason, .. } => format!("failed: {reason}"),
    }
}

/// `vk-hub rollout status <id>`: the rollout, then each node by wave.
fn render_rollout(r: &rollout::Rollout, now: u64) -> String {
    let mut out = format!("{}\n", rollout_line(r));
    for n in &r.row.nodes {
        out.push_str(&format!(
            "  wave {}  {}  {:<16}  {}  [{}]\n",
            n.wave,
            n.id,
            n.hostname,
            rollout_node_status(&n.status, now),
            n.profile
        ));
    }
    out
}

async fn acquisition(client: admin::Client, id: String, acquisition: Acquisition) -> Result<()> {
    let changed =
        tokio::task::spawn_blocking(move || client.set_acquisition(&id, acquisition)).await??;
    report_desired(changed.as_ref());
    Ok(())
}

async fn command(client: admin::Client, id: String, op: Operation) -> Result<()> {
    let command = tokio::task::spawn_blocking(move || client.command(&id, op)).await??;
    eprintln!(
        "vk-hub: issued command {}; `vk-hub audit --node <id>` shows what the node makes of it",
        command.id
    );
    Ok(())
}

/// Say what a desired-state change came to.
fn report_desired(changed: Option<&vk_hub_proto::DesiredState>) {
    match changed {
        Some(d) => eprintln!(
            "vk-hub: desired state is now generation {}: ceiling {}, acquisition {}",
            d.generation,
            d.ceiling
                .map_or_else(|| "none".to_string(), |n| n.to_string()),
            acquisition_name(d.acquisition)
        ),
        None => eprintln!("vk-hub: already so; nothing changed"),
    }
}

pub(crate) fn acquisition_name(a: Acquisition) -> &'static str {
    match a {
        Acquisition::Run => "run",
        Acquisition::Stop => "stop",
    }
}

/// Best-effort raise of the soft `RLIMIT_NOFILE` to the hard limit, capped at 1M: the client
/// connections alone may hold [`server::MAX_CLIENT_CONNS`] descriptors, past a service's
/// usual soft limit of 1024, and a hub out of them stops accepting nodes too. Warns when the
/// limit stays below what the connection caps add up to.
fn raise_nofile() {
    let need = server::MAX_CLIENT_CONNS + 2 * server::MAX_PRE_AUTH + server::MAX_DOWNLOADS;
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit/setrlimit read/write only the `rlimit` we pass.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            return;
        }
        let want = lim.rlim_max.min(1024 * 1024);
        if lim.rlim_cur < want {
            lim.rlim_cur = want;
            if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) != 0 {
                return;
            }
        }
    }
    if lim.rlim_cur < need as libc::rlim_t {
        eprintln!(
            "vk-hub: warning: open file limit is {}, below the {need} connections the hub may \
             hold; raise its hard limit (LimitNOFILE=)",
            lim.rlim_cur
        );
    }
}

async fn serve(cfg: HubConfig) -> Result<()> {
    raise_nofile();
    let listener = server::listen(cfg.addr).with_context(|| format!("binding {}", cfg.addr))?;
    let tls = cfg.build_tls()?;
    let ui = match &cfg.ui {
        Some(ui) => Some((
            server::listen(ui.addr).with_context(|| format!("binding ui_addr {}", ui.addr))?,
            ui.build_tls()?,
            ui,
        )),
        None => None,
    };
    // Read before anything is opened, so a bad secret file stops the hub at startup rather
    // than at the first sign-in.
    let oidc = match cfg
        .ui
        .as_ref()
        .and_then(|ui| ui.oidc.as_ref().map(|o| (ui, o)))
    {
        Some((ui, o)) => {
            let secret = vk_oidc::read_client_secret(&o.client_secret_file, |file| {
                warn_if_file_mode(
                    file,
                    &o.client_secret_file,
                    0o077,
                    "OIDC client secret",
                    "it is group/world-accessible — restrict it to 0600",
                )
            })?;
            // The provider's HTTPS client takes the process's default rustls provider.
            let _ = rustls::crypto::ring::default_provider().install_default();
            Some(ui::OidcSignIn::new(
                &ui.url,
                o.issuer.clone(),
                o.client_id.clone(),
                secret,
            ))
        }
        None => None,
    };
    let default_role = cfg
        .ui
        .as_ref()
        .and_then(|ui| ui.oidc.as_ref())
        .and_then(|o| o.default_role);
    let mut db = store::Db::open(&cfg.db_path())?;
    if let Some(role) = default_role {
        db = db.with_oidc_default_role(role);
    }
    // A default role lowered or removed while the hub was stopped takes effect at once, as a
    // lowered grant does.
    let ended = db.end_oidc_sessions_above_grants("hub", now_secs())?;
    if ended > 0 {
        eprintln!(
            "vk-hub: ended {ended} web UI session(s) holding more than the grants and \
             [oidc] default_role now give"
        );
    }
    let db = Arc::new(db);
    // Before anything could be staging a release: what is staged is a stopped hub's.
    releases::sweep(&cfg.releases_dir());
    let mut hub = server::Hub::new(db, cfg.ui.as_ref().map(|ui| ui.url.clone()))
        .with_node_url(cfg.node_url())
        .with_releases(cfg.releases_dir())
        .with_release_source(cfg.release_source.clone());
    if oidc.is_some() {
        if let Some(role) = default_role {
            eprintln!(
                "vk-hub: anyone the OIDC provider signs in whom no grant names gets the {} role \
                 ([oidc] default_role), audited within the same bounds as `*`",
                role.name()
            );
        } else if hub.db.accounts()?.is_empty() {
            eprintln!(
                "vk-hub: warning: no role is granted, so nobody can sign in through the OIDC \
                 provider yet; `vk-hub accounts grant <email> --role operator` grants one"
            );
        }
        hub = hub.with_oidc();
    }
    let hub = Arc::new(hub.with_jobs(cfg.jobs_dir(), cfg.job_lost_after, cfg.job_history)?);
    jobs::recover(&hub).await?;
    tokio::spawn(jobs::drive(hub.clone()));
    // Fatal, unlike the registry's optional admin socket: here it is the only way to issue
    // a token, so a hub without it could never enroll anything.
    let admin = admin::bind(&cfg.admin_socket())?;
    tokio::spawn(admin::serve(admin, hub.clone()));
    tokio::spawn(rollout::drive(hub.clone()));
    let ui = match ui {
        Some((listener, tls, ui)) => {
            eprintln!(
                "vk-hub: serving the web UI on {}://{} as {}",
                if tls.is_some() { "https" } else { "http" },
                ui.addr,
                ui.url
            );
            let mut site = ui::Ui::new(hub.clone(), &ui.url);
            if let Some(oidc) = oidc {
                eprintln!(
                    "vk-hub: web UI sign-in through {}, redirect URI {}{}",
                    oidc.provider(),
                    ui.url,
                    ui::OIDC_CALLBACK_PATH
                );
                site = site.with_oidc(oidc);
            }
            Some(ui::serve(listener, tls, Arc::new(site)))
        }
        None => None,
    };
    eprintln!(
        "vk-hub: serving nodes on {}://{} (data in {})",
        if tls.is_some() { "https" } else { "http" },
        cfg.addr,
        cfg.data_dir.display()
    );
    let nodes = server::serve(listener, tls, hub);
    // Each serves until the process ends; the first to stop ends the hub.
    match ui {
        Some(ui) => tokio::select! {
            result = nodes => result,
            result = ui => result.context("serving the web UI"),
        },
        None => nodes.await,
    }
}

/// `vk-hub ui login|sessions|logout`, and `vk-hub local`'s, over the running hub's admin
/// socket.
async fn ui_cmd(client: admin::Client, cmd: UiCmd) -> Result<()> {
    match cmd {
        UiCmd::Login { role, ttl } => {
            let link = tokio::task::spawn_blocking(move || client.ui_login(role, ttl)).await??;
            // The link alone on stdout, so `$(vk-hub ui login)` or `$(vk-hub local login)`
            // captures just it.
            println!("{}", link.url);
            eprintln!(
                "vk-hub: single-use {} sign-in link, valid for {}; the session it opens \
                 lasts {}",
                role.name(),
                human_duration(ttl),
                human_duration(store::UI_SESSION_TTL)
            );
        }
        UiCmd::Sessions => {
            let sessions = tokio::task::spawn_blocking(move || client.ui_sessions()).await??;
            let now = now_secs();
            for s in sessions {
                let how = match &s.identity {
                    Some(who) => format!("{who} through {}", s.issued_by),
                    None => format!("link from {}", s.issued_by),
                };
                println!(
                    "{}  {:<8}  signed in {}  expires in {}  {how}",
                    s.id,
                    s.role.name(),
                    utc(s.created_at),
                    human_duration(rounded(s.expires_at.saturating_sub(now))),
                );
            }
        }
        UiCmd::Logout { id, all: _ } => {
            // `--all` is `id` absent: clap requires one or the other.
            let which = id.clone();
            let ended =
                tokio::task::spawn_blocking(move || client.ui_logout(which.as_deref())).await??;
            match (id, ended) {
                (Some(id), 0) => bail!("there is no web UI session {id}"),
                _ => eprintln!("vk-hub: ended {ended} web UI session(s)"),
            }
        }
    }
    Ok(())
}

/// `vk-hub accounts list|grant|revoke`, over the running hub's admin socket.
async fn accounts_cmd(client: admin::Client, cmd: AccountsCmd) -> Result<()> {
    let oidc = match cmd {
        AccountsCmd::List => {
            let accounts = tokio::task::spawn_blocking(move || client.accounts()).await??;
            print!(
                "{}",
                render_accounts(&accounts.accounts, accounts.default_role)
            );
            if accounts.oidc && accounts.accounts.is_empty() && accounts.default_role.is_none() {
                eprintln!("vk-hub: no role is granted: nobody can sign in through OIDC");
            }
            accounts.oidc
        }
        AccountsCmd::Grant { email, role } => {
            let out =
                tokio::task::spawn_blocking(move || client.grant_account(&email, role)).await??;
            match out.change.previous {
                Some(p) if p == role => eprintln!(
                    "vk-hub: {} is already granted the {} role; nothing changed",
                    out.email,
                    role.name()
                ),
                Some(p) => eprintln!(
                    "vk-hub: granted {} the {} role, replacing {}",
                    out.email,
                    role.name(),
                    p.name()
                ),
                None => eprintln!("vk-hub: granted {} the {} role", out.email, role.name()),
            }
            report_ended(&out);
            out.oidc
        }
        AccountsCmd::Revoke { email } => {
            let out = tokio::task::spawn_blocking(move || client.revoke_account(&email)).await??;
            let Some(p) = out.change.previous else {
                bail!("{} has no grant to revoke", out.email);
            };
            eprintln!("vk-hub: revoked {}'s {} grant", out.email, p.name());
            report_ended(&out);
            out.oidc
        }
    };
    if !oidc {
        eprintln!("vk-hub: this hub has no [oidc] in its config: grants take effect once it does");
    }
    Ok(())
}

/// `vk-hub keys list|create|revoke`, over the running hub's admin socket.
async fn keys_cmd(client: admin::Client, cmd: KeysCmd) -> Result<()> {
    match cmd {
        KeysCmd::List => {
            let keys = tokio::task::spawn_blocking(move || client.keys()).await??;
            print!("{}", render_keys(&keys, now_secs()));
        }
        KeysCmd::Create {
            name,
            scopes,
            pools,
            max_mem,
            max_cpus,
            max_disk,
            ttl,
        } => {
            let max_envelope = (max_mem.is_some() || max_cpus.is_some() || max_disk.is_some())
                .then(|| vk_hub_proto::job::Envelope {
                    mem_mib: max_mem.map_or(u64::MAX, |b| b >> 20),
                    cpus: max_cpus.unwrap_or(u32::MAX),
                    disk_bytes: max_disk.unwrap_or(u64::MAX),
                });
            let policy = store::KeyPolicy {
                scopes,
                pools,
                max_envelope,
            };
            let created =
                tokio::task::spawn_blocking(move || client.create_key(&name, policy, ttl))
                    .await??;
            // The key alone on stdout, so `vk-hub keys create … > file` captures just it.
            println!("{}", created.key);
            eprintln!(
                "vk-hub: API key {} works for {}; keep it in a file only its holder reads",
                created.row.name,
                human_duration(ttl)
            );
        }
        KeysCmd::Revoke { name } => {
            let what = name.clone();
            if !tokio::task::spawn_blocking(move || client.revoke_key(&name)).await?? {
                bail!("there is no key {what}");
            }
            eprintln!("vk-hub: key {what} revoked");
        }
    }
    Ok(())
}

/// `vk-hub keys`' table.
fn render_keys(keys: &[store::KeyRow], now: u64) -> String {
    let rows: Vec<[String; 8]> = keys
        .iter()
        .map(|k| {
            let state = if k.revoked_at.is_some() {
                "revoked".to_string()
            } else if k.expires_at <= now {
                "expired".to_string()
            } else {
                format!(
                    "expires in {}",
                    human_duration(rounded(k.expires_at.saturating_sub(now)))
                )
            };
            let scopes: Vec<&str> = k.scopes.iter().map(|s| s.name()).collect();
            [
                k.name.clone(),
                format!("vkk_{}…", k.prefix),
                scopes.join(","),
                k.pools.join(","),
                k.max_envelope
                    .map_or_else(|| "-".to_string(), store::envelope_text),
                utc(k.created_at),
                k.created_by.clone(),
                state,
            ]
        })
        .collect();
    table(
        &[
            "NAME", "KEY", "SCOPES", "POOLS", "LARGEST", "CREATED", "BY", "STATE",
        ],
        &rows,
    )
}

/// `vk-hub jobs`' table: how long each job ran, or has been running, and the most memory
/// its VM held, rounded up to a MiB, where its node reported it.
fn render_jobs(jobs: &[(String, store::JobRow)], now: u64) -> String {
    let rows: Vec<[String; 10]> = jobs
        .iter()
        .map(|(id, j)| {
            let usage = j.result.as_ref().and_then(|r| r.usage);
            [
                id.clone(),
                j.key_name.clone(),
                j.placement.pool.clone(),
                jobs::state_text(j),
                j.node.clone().unwrap_or_else(|| "-".to_string()),
                j.output_len.to_string(),
                format!("{} ago", human_duration(ago(now, j.created_at))),
                j.ran_ms(now)
                    .map_or_else(|| "-".to_string(), jobs::run_text),
                usage.and_then(|u| u.peak_mem_bytes).map_or_else(
                    || "-".to_string(),
                    |b| workloads::size_mib(b.div_ceil(1 << 20)),
                ),
                j.title.clone(),
            ]
        })
        .collect();
    table(
        &[
            "ID",
            "KEY",
            "POOL",
            "STATE",
            "NODE",
            "OUTPUT",
            "SUBMITTED",
            "RAN",
            "PEAK",
            "JOB",
        ],
        &rows,
    )
}

/// Say how many sessions a grant or revoke ended.
fn report_ended(out: &ops::AccountOutcome) {
    if out.change.ended > 0 {
        eprintln!(
            "vk-hub: ended {} web UI session(s) that held more than a sign-in now gets",
            out.change.ended
        );
    }
}

/// `vk-hub accounts`' table: each grant, and who made it when.
fn render_accounts(
    accounts: &[(String, store::AccountRow)],
    default_role: Option<store::Role>,
) -> String {
    if accounts.is_empty() && default_role.is_none() {
        return String::new();
    }
    let mut rows: Vec<[String; 4]> = accounts
        .iter()
        .map(|(email, g)| {
            [
                email.clone(),
                g.role.name().to_string(),
                g.granted_by.clone(),
                utc(g.granted_at),
            ]
        })
        .collect();
    // Last, as a sign-in falls back to it last.
    if let Some(role) = default_role {
        rows.push([
            "(default)".to_string(),
            role.name().to_string(),
            "[oidc] default_role".to_string(),
            String::new(),
        ]);
    }
    table(&["EMAIL", "ROLE", "GRANTED BY", "AT"], &rows)
}

/// The signature `vk release-key sign` wrote to `path`: a line of base64, read whole up to a
/// bound well past one, which the hub checks the shape of.
fn read_signature(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut text = String::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(4096).read_to_string(&mut text))
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(text.trim().to_string())
}

/// The running fleet hub's admin socket.
fn admin_client(cfg: &HubConfig) -> Result<admin::Client> {
    admin_client_at(
        &cfg.admin_socket(),
        "vk-hub serve` running with this --config",
    )
}

/// The running hub's admin socket at `path`, with a pointer at the likely cause when nothing
/// answers: `what` is asked about.
fn admin_client_at(path: &Path, what: &str) -> Result<admin::Client> {
    admin::Client::connect(path).map_err(|e| {
        let hint = match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                format!(" — is `{what}?")
            }
            std::io::ErrorKind::PermissionDenied => {
                " — run as the user vk-hub runs as, or root".to_string()
            }
            _ => String::new(),
        };
        anyhow!(e).context(format!(
            "connecting to the hub's admin socket at {}{hint}",
            path.display()
        ))
    })
}

/// A sign-in link's lifetime, at most [`store::MAX_LOGIN_TTL`].
fn parse_login_ttl(s: &str) -> Result<Duration, String> {
    parse_ttl(s, store::MAX_LOGIN_TTL, "a sign-in link")
}

/// An enrollment token's lifetime, at most [`store::MAX_TOKEN_TTL`].
fn parse_token_ttl(s: &str) -> Result<Duration, String> {
    parse_ttl(s, store::MAX_TOKEN_TTL, "a token")
}

/// `<n>s`, `<n>m`, `<n>h` or `<n>d`, from 1s to `max`; `what` names it in the error.
fn parse_ttl(s: &str, max: Duration, what: &str) -> Result<Duration, String> {
    let unit = |c| match c {
        's' => Some(1),
        'm' => Some(60),
        'h' => Some(3600),
        'd' => Some(86_400),
        _ => None,
    };
    let Some((n, scale)) = s
        .char_indices()
        .next_back()
        .and_then(|(at, c)| Some((s.get(..at)?, unit(c)?)))
    else {
        return Err(format!("{s:?}: expected <n>s, <n>m, <n>h or <n>d"));
    };
    let n: u64 = n.parse().map_err(|_| format!("{s:?}: expected a number"))?;
    let secs = n
        .checked_mul(scale)
        .ok_or_else(|| format!("{s:?} is too long"))?;
    let ttl = Duration::from_secs(secs);
    if ttl.is_zero() || ttl > max {
        return Err(format!(
            "{s:?}: {what} lives between 1s and {}",
            human_duration(max)
        ));
    }
    Ok(ttl)
}

pub(crate) fn human_duration(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        _ if s >= 86_400 && s.is_multiple_of(86_400) => format!("{}d", s / 86_400),
        _ if s >= 3600 && s.is_multiple_of(3600) => format!("{}h", s / 3600),
        _ if s >= 60 && s.is_multiple_of(60) => format!("{}m", s / 60),
        _ => format!("{s}s"),
    }
}

/// The columns of `vk-hub nodes`, and of the web UI's nodes table.
pub(crate) const NODE_COLUMNS: [&str; 14] = [
    "ID",
    "NAME",
    "REACH",
    "STATE",
    "ACQUIRE",
    "CEILING",
    "CONC",
    "SYNC",
    "LAST SEEN",
    "VK",
    "CPUS",
    "RAM",
    "ADMITTED",
    "VMS",
];

/// One node's cells under [`NODE_COLUMNS`]: what it is, and for what the hub steers, what it
/// wants beside what the node last reported. A node only monitored has no steering to show.
pub(crate) fn node_cells(n: &ops::NodeView, now: u64) -> [String; 14] {
    let gib = |mib: u64| format!("{}G", mib / 1024);
    let dash = || "-".to_string();
    let count = |n: Option<u32>| n.map_or_else(dash, |c| c.to_string());
    let report = n.report.as_ref();
    let concurrency = report.and_then(|r| r.concurrency);
    let [state, acquire, ceiling, sync] = match n.protocol {
        Some(v) if n.monitoring_only() => [format!("monitor only (v{v})"), dash(), dash(), dash()],
        _ => steering_cells(n),
    };
    [
        n.id.clone(),
        n.hostname.clone(),
        if n.connected {
            "connected"
        } else {
            "unreachable"
        }
        .to_string(),
        state,
        acquire,
        ceiling,
        count(concurrency.and_then(|c| c.effective)),
        sync,
        match n.last_seen {
            Some(t) => format!("{} ago", human_duration(ago(now, t))),
            None => "never".to_string(),
        },
        n.vk.clone().unwrap_or_else(dash),
        count(n.cpus),
        n.mem_total_mib.map_or_else(dash, gib),
        match (n.committed_mib, n.budget_mib) {
            (Some(c), Some(b)) => format!("{}/{}", gib(c), gib(b)),
            (Some(c), None) => format!("{}/-", gib(c)),
            (None, _) => dash(),
        },
        n.workloads.map_or_else(dash, |w| w.to_string()),
    ]
}

/// A steered node's STATE, ACQUIRE, CEILING and SYNC cells. STATE is the node's; the others
/// are the hub's side, or its defaults when it has asked nothing, with the node's beside it
/// where they differ.
fn steering_cells(n: &ops::NodeView) -> [String; 4] {
    let dash = || "-".to_string();
    let count = |n: Option<u32>| n.map_or_else(dash, |c| c.to_string());
    let report = n.report.as_ref();
    let (want_acquisition, want_ceiling) = n
        .desired
        .as_ref()
        .map_or((Acquisition::Run, None), |d| (d.acquisition, d.ceiling));
    let mut state = report
        .and_then(|r| r.state)
        .map_or_else(dash, |s| store::state_name(s).to_string());
    // Show update progress; keep a rollback visible until the next update.
    if let Some(u) = report.and_then(|r| r.update.as_ref()) {
        use vk_hub_proto::UpdatePhase;
        match u.phase {
            UpdatePhase::Draining | UpdatePhase::Downloading | UpdatePhase::Validating => {
                state.push_str(&format!(
                    ", updating to {}: {}",
                    u.version,
                    store::update_phase_name(u.phase)
                ));
            }
            UpdatePhase::RolledBack => {
                state.push_str(&format!(", update to {} rolled back", u.version));
            }
            UpdatePhase::Done | UpdatePhase::Failed => {}
        }
    }
    if n.pending_commands > 0 {
        state.push_str(&format!(", {} pending", n.pending_commands));
    }
    let mut acquire = acquisition_name(want_acquisition).to_string();
    if let Some(r) = report
        && let Some(theirs) = r.acquisition
    {
        // A runner told to stop is still taking jobs until it has exited.
        let quitting = r.runner_state == Some(vk_hub_proto::RunnerState::Quitting);
        if theirs != want_acquisition || quitting {
            acquire.push_str(&format!(
                " (node: {}{})",
                acquisition_name(theirs),
                if quitting { ", quitting" } else { "" }
            ));
        }
    }
    let mut ceiling = count(want_ceiling);
    if let Some(c) = report.and_then(|r| r.concurrency)
        && c.hub_ceiling != want_ceiling
    {
        ceiling.push_str(&format!(" (node: {})", count(c.hub_ceiling)));
    }
    let sync = match (&n.desired, report) {
        (None, _) => dash(),
        (Some(_), None) => "unknown".to_string(),
        (Some(d), Some(r)) if r.applied.as_ref() == Some(d) => "ok".to_string(),
        // The node took another state under this generation, before a hub restore; it ignores
        // this one until a change moves the hub past it.
        (Some(d), Some(r)) if r.applied_generation() == Some(d.generation) => "differs".to_string(),
        // A node that took a generation this hub never issued: the hub re-issues past it on
        // the node's next report.
        (Some(d), Some(r)) if r.applied_generation() > Some(d.generation) => format!(
            "ahead ({}>{})",
            r.applied_generation().unwrap_or(0),
            d.generation
        ),
        (Some(d), Some(r)) => format!(
            "behind ({}<{})",
            r.applied_generation().unwrap_or(0),
            d.generation
        ),
    };
    [state, acquire, ceiling, sync]
}

/// What a node says it cannot do: sentences, not cells.
fn node_notes(n: &ops::NodeView) -> Vec<String> {
    let mut placement = Vec::new();
    if !n.pools.is_empty() {
        placement.push(format!("{}: in pools {}", n.hostname, n.pools.join(", ")));
    }
    if !n.labels.is_empty() {
        placement.push(format!("{}: labels {}", n.hostname, n.labels.join(", ")));
    }
    if let Some(why) = &n.last_refusal {
        placement.push(format!("{}: refuses reservations: {why}", n.hostname));
    }
    let Some(report) = &n.report else {
        return placement;
    };
    let mut notes: Vec<String> = placement;
    notes.extend(
        report
            .unsupported
            .iter()
            .map(|note| format!("{}: cannot comply: {note}", n.hostname)),
    );
    if let Some(error) = &report.concurrency_error {
        notes.push(format!(
            "{}: cannot set its concurrency: {error}",
            n.hostname
        ));
    }
    notes
}

/// `vk-hub nodes`' table, with each node's notes under it.
fn render_nodes(nodes: &[ops::NodeView], now: u64) -> String {
    let rows: Vec<[String; 14]> = nodes.iter().map(|n| node_cells(n, now)).collect();
    let mut out = table(&NODE_COLUMNS, &rows);
    for n in nodes {
        for note in node_notes(n) {
            out.push_str(&note);
            out.push('\n');
        }
    }
    out
}

/// `headers` and `rows` as columns two spaces apart, each as wide as its widest cell is on a
/// terminal.
fn table<const N: usize>(headers: &[&str; N], rows: &[[String; N]]) -> String {
    use unicode_width::UnicodeWidthStr;
    let mut widths = headers.map(|h| h.width());
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.width());
        }
    }
    let mut out = String::new();
    let mut line = |cells: &[&str]| {
        let mut l = String::new();
        for (i, (cell, w)) in cells.iter().zip(widths).enumerate() {
            l.push_str(cell);
            if i + 1 < cells.len() {
                l.push_str(&" ".repeat(w.saturating_sub(cell.width()) + 2));
            }
        }
        out.push_str(l.trim_end());
        out.push('\n');
    };
    line(headers);
    for row in rows {
        line(&row.each_ref().map(String::as_str));
    }
    out
}

/// `vk-hub workloads`' table, each node's VMs under its name, and a line for each node that
/// has not reported any, left some out, had them left out of the reply, or is not connected.
fn render_workloads(nodes: &[ops::NodeWorkloads]) -> String {
    let mut rows: Vec<[String; 10]> = Vec::new();
    let mut notes = Vec::new();
    for n in nodes {
        let Some(workloads) = &n.workloads else {
            notes.push(format!("{}: has not reported its workloads", n.hostname));
            continue;
        };
        if !n.connected {
            notes.push(match n.last_seen {
                Some(at) => format!("{}: not connected; as last seen at {}", n.hostname, utc(at)),
                None => format!("{}: not connected", n.hostname),
            });
        }
        if n.withheld > 0 {
            notes.push(format!(
                "{}: {} listed, too many to show with every node's: see \
                 `vk-hub workloads --node {}`",
                n.hostname, n.withheld, n.id
            ));
        }
        for w in &workloads.listed {
            let [a, b, c, d, e, f, g, h, i] =
                workloads::cells(w, workloads.mem_bytes.get(&w.id).copied());
            rows.push([n.hostname.clone(), a, b, c, d, e, f, g, h, i]);
        }
        if workloads.omitted > 0 {
            notes.push(format!(
                "{}: {} more running, not listed",
                n.hostname, workloads.omitted
            ));
        }
    }
    let mut headers = ["NODE"; 10];
    headers[1..].copy_from_slice(&workloads::COLUMNS);
    let mut out = table(&headers, &rows);
    for note in notes {
        out.push_str(&note);
        out.push('\n');
    }
    out
}

/// `secs` since the epoch as `YYYY-MM-DDTHH:MM:SSZ`.
pub(crate) fn utc(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    // Days since 1970-01-01 to a civil date (Howard Hinnant's `civil_from_days`), in the
    // unsigned form: the epoch is past its era's start, so nothing goes negative.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// How long before `now` the instant `then` was, rounded down to the unit it prints in.
pub(crate) fn ago(now: u64, then: u64) -> Duration {
    rounded(now.saturating_sub(then))
}

/// `s` seconds rounded down to the unit [`human_duration`] prints them in.
fn rounded(s: u64) -> Duration {
    Duration::from_secs(match s {
        0..60 => s,
        60..3600 => s / 60 * 60,
        3600..86_400 => s / 3600 * 3600,
        _ => s / 86_400 * 86_400,
    })
}

/// Seconds since the epoch. A clock before 1970 reads as 0 rather than failing a request.
pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `n` bytes from the kernel's CSPRNG, which `getrandom` waits on until it is seeded.
pub(crate) fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let mut filled = 0;
    while let Some(rest) = buf.get_mut(filled..).filter(|rest| !rest.is_empty()) {
        // SAFETY: `rest` is valid for writes of `rest.len()` bytes for the call's duration.
        let got = unsafe { libc::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
        match usize::try_from(got) {
            Ok(got) => filled += got,
            Err(_) => {
                let e = std::io::Error::last_os_error();
                if e.kind() != std::io::ErrorKind::Interrupted {
                    return Err(anyhow!(e).context("reading the kernel's random number generator"));
                }
            }
        }
    }
    Ok(buf)
}

/// `n` random bytes as hex: tokens, session secrets.
pub(crate) fn random_hex(n: usize) -> Result<String> {
    Ok(vk_hub_proto::to_hex(&random_bytes(n)?))
}

/// Whether `signature` is `public_key`'s ed25519 signature over `message`.
pub(crate) fn verify(
    public_key: &[u8; vk_hub_proto::PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; vk_hub_proto::SIGNATURE_LEN],
) -> bool {
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
        .verify(message, signature)
        .is_ok()
}

/// Warn when `path` has any of the `forbidden` mode bits. Advisory: the caller carries on.
pub(crate) fn warn_if_mode(path: &Path, forbidden: u32, what: &str, advice: &str) {
    if let Ok(meta) = std::fs::metadata(path) {
        warn_mode(&meta, path, forbidden, what, advice);
    }
}

/// [`warn_if_mode`] on an open file, so the mode judged is the file's that was opened.
pub(crate) fn warn_if_file_mode(
    file: &std::fs::File,
    path: &Path,
    forbidden: u32,
    what: &str,
    advice: &str,
) {
    if let Ok(meta) = file.metadata() {
        warn_mode(&meta, path, forbidden, what, advice);
    }
}

fn warn_mode(meta: &std::fs::Metadata, path: &Path, forbidden: u32, what: &str, advice: &str) {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode();
    if mode & forbidden != 0 {
        eprintln!(
            "vk-hub: warning: {what} {} has mode {:o}; {advice}",
            path.display(),
            mode & 0o7777
        );
    }
}

#[cfg(test)]
mod tests;
