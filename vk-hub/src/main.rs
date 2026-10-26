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
//! issues. GitLab relays — `vk-gitlab`, enrolled — and automation holding an API key reserve
//! capacity on nodes and have jobs placed on them through the client API
//! (`docs/gitlab-dispatch.md`).

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};

mod admin;
mod client;
mod clients;
mod config;
mod egress;
mod fetch;
mod jobs;
mod local;
mod ops;
mod registries;
mod relays;
mod releases;
mod rollout;
mod server;
mod session;
mod store;
mod subject;
mod tokens;
mod tools;
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
    /// ui_tls_key, release_repository, job_lost_after_secs, job_history, kept_failure_output,
    /// kept_output, kept_output_total, image_affinity_max_load, image_affinity_max_extra_load,
    /// max_job_token_secs, [jobs] egress_rules, [oidc] [default: built-in defaults]
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
    /// List the registries the hub manages, or steer, update or remove one
    Registries {
        #[command(flatten)]
        config: ConfigArg,
        #[command(subcommand)]
        cmd: Option<RegistriesCmd>,
    },
    /// List the GitLab relays (vk-gitlab) enrolled with the hub, or show or remove one
    Relays {
        #[command(flatten)]
        config: ConfigArg,
        #[command(subcommand)]
        cmd: Option<RelaysCmd>,
    },
    /// Keep vk or vk-registry binaries for nodes or registries to update to
    Release {
        #[command(flatten)]
        config: ConfigArg,
        #[command(subcommand)]
        cmd: ReleaseCmd,
    },
    /// Keep the CI tools definitions nodes build their tools_dir from
    ///
    /// A definition is a build context: a directory with a Dockerfile whose `tools` stage
    /// holds static tools (git, git-lfs, gitlab-runner…) at its root. `vk-hub nodes tools`
    /// has nodes build one with `vk build` and install what the stage holds as
    /// `<state_dir>/tools/current`, the directory their `[executor] tools_dir` names. Those
    /// tools then run in every job VM: holding the admin socket is what registering them
    /// takes.
    Tools {
        #[command(flatten)]
        config: ConfigArg,
        #[command(subcommand)]
        cmd: ToolsCmd,
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
    /// Add, list, approve, reject and remove the GitLab instances the hub takes jobs from,
    /// and approve their projects
    ///
    /// A GitLab server a relay reports is pending until approved under a name, which its
    /// relays then poll, or rejected. The name is what registry namespaces and egress rules
    /// call {gitlab}.
    Gitlabs {
        #[command(flatten)]
        config: ConfigArg,
        #[command(subcommand)]
        cmd: Option<GitlabsCmd>,
    },
    /// List, add and remove a registry's namespaces: who may read, write or lock under which
    /// path prefix
    ///
    /// A placed job's registry token carries what the namespaces selecting it grant. A path
    /// is a repository name whose components may be {gitlab}, {project_id}, {pipeline_id} or
    /// {protection}; a grant is <rights>:<subject>, rights some of r, w and l, the subject
    /// comma-separated terms among *, own project, own pipeline, gitlab <name>,
    /// projects <glob>, project-id <n>, ref <glob>, protected and unprotected. Projects and
    /// project IDs go with gitlab <name>: they repeat across GitLab instances.
    Namespaces {
        #[command(flatten)]
        config: ConfigArg,
        #[command(subcommand)]
        cmd: NamespacesCmd,
    },
    /// List, set and remove the hub's egress rules: what each project's jobs may reach
    ///
    /// A rule selects jobs by a subject, comma-separated terms among *, gitlab <name>,
    /// projects <glob>, project-id <n>, ref <glob> (with protected), protected and
    /// unprotected, and says per phase, run and build, what they may reach: unrestricted,
    /// none, or DNS suffixes and IPv4 CIDRs[:port], as a node's [egress] lists. Rules that
    /// select a job add up; the rule named default, the Fallback, takes the jobs no other
    /// enforced rule selects. A rule in dry-run blocks nothing and reports what it would.
    /// Rules restrict placed jobs once hub.toml sets [jobs] egress_rules = true.
    Egress {
        #[command(flatten)]
        config: ConfigArg,
        #[command(subcommand)]
        cmd: Option<EgressCmd>,
    },
    /// List the keys registry tokens are signed with, or make a new one the signer
    TokenKeys {
        #[command(flatten)]
        config: ConfigArg,
        #[command(subcommand)]
        cmd: Option<TokenKeysCmd>,
    },
    /// Issue, list and revoke the API keys automation reserves capacity and places jobs with
    Keys {
        #[command(flatten)]
        config: ConfigArg,
        #[command(subcommand)]
        cmd: Option<KeysCmd>,
    },
    /// List the jobs placed on the fleet through the client API, newest first
    #[command(args_conflicts_with_subcommands = true)]
    Jobs {
        #[command(flatten)]
        config: ConfigArg,
        /// How many of the latest
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Only jobs that reported events: a virtio-fs stall the VMM detected and retried, …
        #[arg(long)]
        events: bool,
        #[command(subcommand)]
        cmd: Option<JobsCmd>,
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
    /// Copy a vk or vk-registry binary into the hub, as the version it reports
    ///
    /// The hub never runs it: it checks that the file is an x86-64 ELF holding the version
    /// as a string of its own. The file must be readable by the hub's user.
    Add {
        /// The binary
        file: PathBuf,
        /// The version its `--version` prints
        #[arg(long)]
        version: String,
        /// A file holding a release key's signature of it, as `vk release-key sign` prints
        /// one
        #[arg(long, value_name = "FILE")]
        signature: Option<PathBuf>,
        /// The program it is: vk, for nodes, or vk-registry, for registries
        #[arg(long, default_value = "vk", value_parser = ["vk", "vk-registry"])]
        program: String,
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
enum ToolsCmd {
    /// Pack a build context into a tools definition the hub holds
    ///
    /// Regular files and directories only, packed reproducibly: the same tree is the same
    /// definition, by sha256. It needs a Dockerfile at its root; the directory must be
    /// readable by the hub's user.
    Add {
        /// The build context
        dir: PathBuf,
        /// A label for it, shown beside it on every node that builds it
        #[arg(long)]
        version: String,
    },
    /// List the tools definitions the hub holds
    List,
    /// Delete a tools definition, unless a node still has to build it
    Remove {
        /// Its sha256, or at least the first 8 hex digits
        tools: String,
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
    /// Forget an ended rollout; its audit lines stay
    ///
    /// Refused while it is running or paused, or while an update it issued is still under way.
    Delete {
        /// The rollout's ID, or at least its first 4 hex digits
        id: String,
    },
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
enum JobsCmd {
    /// Show a job's record and the end of its output that the hub kept
    Show {
        /// The job's ID, as `vk-hub jobs` lists it
        id: String,
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

#[derive(Subcommand)]
enum GitlabsCmd {
    /// List the instances (the default)
    List,
    /// Add an instance under a name: lowercase letters, digits and '-'
    Add { name: String, url: String },
    /// List the GitLab servers relays report that no instance has, and the projects waiting
    /// for approval
    Pending,
    /// Approve a pending server under a name: `add` with the arguments swapped
    Approve {
        url: String,
        /// Lowercase letters, digits and '-': what namespaces and egress rules call {gitlab}
        #[arg(long)]
        name: String,
    },
    /// Refuse the jobs of a server relays report, and stop listing it as pending
    ///
    /// `approve` still approves it later.
    Reject { url: String },
    /// Forget a server's rejection: it is pending again while a relay reports it
    Forget { url: String },
    /// Remove an instance no relay is bound to, and forget its projects
    Remove { name: String },
    /// List, approve, reject and forget the projects whose jobs an instance's relays submit
    ///
    /// A project's first job makes it pending, and is refused; its jobs are accepted once it
    /// is approved.
    Projects {
        #[command(subcommand)]
        cmd: Option<ProjectsCmd>,
    },
}

#[derive(Subcommand)]
enum ProjectsCmd {
    /// List the projects of an instance, or of every instance (the default)
    List {
        gitlab: Option<String>,
        /// Only those waiting for approval
        #[arg(long)]
        pending: bool,
    },
    /// Approve projects of an instance, pending or not, by ID: <id> or <id>:<path>
    Approve {
        gitlab: String,
        #[arg(required = true, value_parser = parse_project_ref)]
        projects: Vec<store::ProjectRef>,
    },
    /// Reject projects of an instance by ID: their jobs are refused, and they are no longer
    /// pending
    Reject {
        gitlab: String,
        #[arg(required = true, value_parser = parse_project_ref)]
        projects: Vec<store::ProjectRef>,
    },
    /// Forget projects of an instance: the next job of one makes it pending again
    Forget {
        gitlab: String,
        #[arg(required = true)]
        ids: Vec<u64>,
    },
}

fn parse_project_ref(s: &str) -> Result<store::ProjectRef, String> {
    store::ProjectRef::parse(s)
}

#[derive(Subcommand)]
enum RelaysCmd {
    /// List the relays (the default)
    List,
    /// Show a relay: its GitLab server and runners
    Show {
        /// The relay's ID, as `vk-hub relays` lists it
        id: String,
    },
    /// Remove a relay: unpin its key and end its session
    ///
    /// It can join again only with a new token.
    Remove { id: String },
}

#[derive(Subcommand)]
enum NamespacesCmd {
    /// List a registry's namespaces
    List {
        /// The registry's ID
        registry: String,
    },
    /// Show one namespace
    Show { registry: String, name: String },
    /// Add a namespace, or replace one of that name
    Add {
        registry: String,
        name: String,
        /// The path template, as ci-pipeline/{gitlab}/{project_id}/{pipeline_id}
        #[arg(long)]
        path: String,
        /// Drop tags idle under the path's leading fixed components for this many days, 1 to
        /// 3650; the registry applies it only with gc in its [hub] allow, within its own floors
        #[arg(long, value_name = "DAYS")]
        retention_days: Option<u64>,
        /// What jobs reach the path by on their guest registry proxy, as job/<ALIAS> under
        /// /v2/ and /dav/files/ and in lock names: one repository name component, as task-cache
        #[arg(long, value_name = "ALIAS")]
        alias: Option<String>,
        /// A grant line, <rights>:<subject>, as 'rw:own project' or 'r:*'; repeat for several
        #[arg(long = "grant", value_name = "LINE", required = true)]
        grants: Vec<String>,
    },
    /// Remove a namespace
    Remove { registry: String, name: String },
}

#[derive(Subcommand)]
enum EgressCmd {
    /// List the rules (the default)
    List,
    /// Show one rule
    Show { name: String },
    /// Add a rule, or change one: what is not given stays as it is
    ///
    /// A new rule chooses both phases, and starts in dry-run unless --mode says otherwise;
    /// the Fallback, default, takes no subject and chooses its mode when added. A phase given
    /// replaces the rule's: unrestricted, none, or the destinations listed.
    Set {
        name: String,
        /// The jobs it selects, as 'gitlab gl, projects wab/**, protected'
        #[arg(long)]
        subject: Option<String>,
        /// The run phase: unrestricted or none, unless destinations are listed
        #[arg(long, value_name = "unrestricted|none")]
        run: Option<String>,
        /// A DNS suffix the run phase may reach; repeat for several
        #[arg(long = "run-name", value_name = "SUFFIX")]
        run_names: Vec<String>,
        /// An IPv4 CIDR, optionally CIDR:port, the run phase may reach; repeat for several
        #[arg(long = "run-ip", value_name = "CIDR")]
        run_ips: Vec<String>,
        /// The build phase: unrestricted or none, unless destinations are listed
        #[arg(long, value_name = "unrestricted|none")]
        build: Option<String>,
        /// A DNS suffix the build phase may reach; repeat for several
        #[arg(long = "build-name", value_name = "SUFFIX")]
        build_names: Vec<String>,
        /// An IPv4 CIDR, optionally CIDR:port, the build phase may reach; repeat for several
        #[arg(long = "build-ip", value_name = "CIDR")]
        build_ips: Vec<String>,
        /// enforce or dry-run
        #[arg(long)]
        mode: Option<String>,
    },
    /// Enforce a rule, or put it in dry-run
    Mode {
        name: String,
        /// enforce or dry-run
        mode: String,
    },
    /// Remove a rule
    Delete { name: String },
    /// Print the egress layer a placed job of these claims gets from the rules now, as JSON
    ///
    /// Without --gitlab, a job of no GitLab instance, as an older hub recorded some: the Fallback
    /// alone.
    Resolve {
        /// The GitLab instance the job's relay is bound to, by the hub's name for it
        #[arg(long)]
        gitlab: Option<String>,
        /// The project's path
        #[arg(long, value_name = "PATH", default_value = "")]
        project: String,
        /// The project's ID
        #[arg(long, value_name = "N", default_value_t = 0)]
        project_id: u64,
        /// The job's ref
        #[arg(long = "ref", value_name = "REF", default_value = "")]
        git_ref: String,
        /// The ref is protected
        #[arg(long)]
        protected: bool,
    },
}

#[derive(Subcommand)]
enum TokenKeysCmd {
    /// List the keys (the default)
    List,
    /// Make a new key the signer; registries get it before it signs their tokens
    Rotate,
}

pub(crate) fn parse_scope(s: &str) -> Result<store::Scope, String> {
    store::Scope::parse(s).ok_or_else(|| format!("{s:?}: expected jobs or capacity"))
}

/// A size in bytes: a number with a binary unit, `K`, `M`, `G` or `T`.
pub(crate) fn parse_size(s: &str) -> Result<u64, String> {
    let bad = || format!("{s:?}: expected <n>K, <n>M, <n>G or <n>T");
    let (n, unit) = s
        .char_indices()
        .next_back()
        .and_then(|(at, _)| s.split_at_checked(at))
        .unwrap_or(("", ""));
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
pub(crate) fn parse_mem_size(s: &str) -> Result<u64, String> {
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

/// The reset `vk-hub nodes reset` asks for: one that evicts the images unless told to keep
/// them.
fn reset_op(keep_images: bool) -> Operation {
    Operation::Reset {
        images: !keep_images,
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
    /// Cap how many jobs the node runs at once, or lift the cap with `none`
    ///
    /// For the node's runner, the node takes the smallest of this, its own estimate and its
    /// local ceiling; the hub only ever lowers what the node would take. On a node that takes
    /// the hub's jobs instead, they are capped at it: reservations and jobs not finished,
    /// counted by the hub and again by the node. Running jobs past a lowered cap carry on.
    Ceiling {
        id: String,
        /// A number of jobs, or `none`
        #[arg(value_parser = parse_ceiling)]
        ceiling: Ceiling,
    },
    /// Stop the node's runner taking new jobs; running ones finish
    ///
    /// With `[node] runner = "external"`, a gitlab-runner of the node's own is not stopped, and
    /// the node reports that it may still take jobs. Drain and quarantine behave the same way.
    Stop { id: String },
    /// Let the node's runner take jobs again
    Resume { id: String },
    /// Stop taking jobs and report `drained` once everything running has finished
    ///
    /// With `[node] runner = "external"`, a gitlab-runner of the node's own is not stopped.
    Drain { id: String },
    /// End a drain: back to `ready`, taking jobs
    Undrain { id: String },
    /// Stop taking jobs until `release`, whatever else the node is told
    ///
    /// With `[node] runner = "external"`, a gitlab-runner of the node's own is not stopped.
    Quarantine { id: String },
    /// End a quarantine: back to `ready`
    Release { id: String },
    /// Drain the node, clear what its past jobs left, validate, and return it where it was
    ///
    /// The node stops whatever its user still runs from past jobs, removes their job
    /// directories and its idle host checkouts, and evicts its idle materialized images; the
    /// build cache's registry store is never touched. A node that fails validation afterwards
    /// stays drained. Needs `[node] runner = "managed"` on the node.
    Reset {
        id: String,
        /// Keep the node's materialized images
        #[arg(long)]
        keep_images: bool,
        /// Evict the node's materialized images: the default, accepted for older callers
        #[arg(long, hide = true, conflicts_with = "keep_images")]
        images: bool,
    },
    /// Put the node in the pools placed jobs name, replacing those it was in, or `none`
    Pools {
        id: String,
        /// Pool names separated by commas, or `none`
        pools: String,
    },
    /// Ask the node to build a tools definition and make the tools current
    ///
    /// The node builds it with `vk build` in microVMs, apart from its build cache, checks
    /// that the `tools` stage holds a static git, and switches
    /// `<state_dir>/tools/current` to them: jobs that start from then on get them, running
    /// ones keep theirs. Nothing drains. Needs protocol version 4 on the node.
    Tools {
        /// The node's ID; omitted with --all
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        id: Option<String>,
        /// Every node that speaks version 4 and has not these tools current or building
        #[arg(long)]
        all: bool,
        /// The definition's sha256, or at least its first 8 hex digits
        #[arg(long)]
        tools: String,
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
        /// What it enrolls: a node (`vk node join`), a registry (`vk-registry join`) or a
        /// GitLab relay (`vk-gitlab join`)
        #[arg(long, default_value = "node", value_parser = parse_token_kind)]
        kind: store::TokenKind,
        /// The URL clients reach the registry it enrolls at, https://host[:port]: nodes whose
        /// [registry] is this URL get registry tokens for it
        #[arg(long, value_name = "URL")]
        url: Option<String>,
    },
}

fn parse_token_kind(s: &str) -> Result<store::TokenKind, String> {
    match s {
        "node" => Ok(store::TokenKind::Node),
        "registry" => Ok(store::TokenKind::Registry),
        "gitlab" => Ok(store::TokenKind::Gitlab),
        _ => Err(format!("{s:?}: expected node, registry or gitlab")),
    }
}

#[derive(Subcommand)]
enum RegistriesCmd {
    /// Show a registry: what it reports, what the hub wants of it, its commands
    Show {
        /// The registry's ID, as `vk-hub registries` lists it
        id: String,
    },
    /// Remove a registry: unpin its key and end its session
    ///
    /// The registry serves on as before; it can join again only with a new token.
    Remove { id: String },
    /// Make the registry refuse writes (`on`), take them again (`off`), or do as its config says
    ///
    /// Needs `read-only` in the registry's `[hub] allow`.
    ReadOnly {
        id: String,
        #[arg(value_parser = ["on", "off", "default"])]
        state: String,
    },
    /// Have the registry run gc on a schedule, or stop scheduling it
    ///
    /// Needs `gc` in the registry's `[hub] allow`.
    GcSchedule {
        id: String,
        /// How often: <n>m, <n>h or <n>d (at least 10m)
        #[arg(long, value_parser = parse_gc_every, required_unless_present = "off")]
        every: Option<Duration>,
        /// Drop tags unused for more than this many days
        #[arg(long, default_value_t = registries::GC_RETENTION_DAYS)]
        retention_days: u64,
        /// Keep unreferenced blobs this many days past their last use
        #[arg(long, default_value_t = registries::GC_GRACE_DAYS)]
        grace_days: u64,
        /// Stop the scheduled gc
        #[arg(long, conflicts_with = "every")]
        off: bool,
    },
    /// Run gc on the registry now
    ///
    /// Needs `gc` in the registry's `[hub] allow`.
    Gc {
        id: String,
        #[arg(long, default_value_t = registries::GC_RETENTION_DAYS)]
        retention_days: u64,
        #[arg(long, default_value_t = registries::GC_GRACE_DAYS)]
        grace_days: u64,
        /// Report what would go without removing anything
        #[arg(long)]
        dry_run: bool,
    },
    /// Update the registry to a vk-registry release the hub holds
    ///
    /// Needs `update` in the registry's `[hub] allow`. The registry checks the release's
    /// signature against its own `[hub] release_keys`, runs it, and keeps it only once it is
    /// back in session with the hub.
    Update {
        id: String,
        /// The release's sha256, or at least the first 8 hex digits
        #[arg(long)]
        release: String,
    },
    /// Bind the registry to the URL clients reach it at, or unbind it
    SetUrl {
        id: String,
        /// https://host[:port]
        #[arg(required_unless_present = "none")]
        url: Option<String>,
        /// Unbind it: nodes get no tokens for it
        #[arg(long, conflicts_with = "url")]
        none: bool,
    },
    /// Mint a token for the registry, printed once: for automation or a test
    Token {
        id: String,
        /// A grant, <prefix>=<rights>, rights some of r, w and l; repeat for several
        #[arg(long = "grant", value_name = "PREFIX=RIGHTS", required = true)]
        grants: Vec<String>,
        /// The pipeline its lock requests speak for, <gitlab>/<pipeline id>
        #[arg(long)]
        pipeline: Option<String>,
        /// How long it lives: <n>s, <n>m, <n>h or <n>d (at most max_job_token_secs)
        #[arg(long, default_value = "1h", value_parser = parse_mint_ttl)]
        ttl: Duration,
    },
}

fn parse_mint_ttl(s: &str) -> Result<Duration, String> {
    parse_ttl(
        s,
        Duration::from_secs(vk_hub_proto::token::MAX_TTL_SECS),
        "a token's lifetime",
    )
}

fn parse_gc_every(s: &str) -> Result<Duration, String> {
    let every = parse_ttl(s, Duration::from_secs(365 * 86_400), "a gc interval")?;
    if every < Duration::from_secs(600) {
        return Err(format!("{s:?}: a gc runs at most every 10 minutes"));
    }
    Ok(every)
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
            cmd:
                TokenCmd::Create {
                    config,
                    ttl,
                    kind,
                    url,
                },
        } => {
            let client = admin_client(&HubConfig::load(config.config.as_deref())?)?;
            let created =
                tokio::task::spawn_blocking(move || client.create_token_bound(kind, ttl, url))
                    .await??;
            // The token alone on stdout, so `$(vk-hub token create)` captures just it.
            println!("{}", created.token);
            eprintln!(
                "vk-hub: single-use, valid for {}; enroll with `{} join <hub-url> --token -` \
                 reading it on stdin",
                human_duration(ttl),
                match kind {
                    store::TokenKind::Node => "vk node",
                    store::TokenKind::Registry => "vk-registry",
                    store::TokenKind::Gitlab => "vk-gitlab",
                }
            );
            Ok(())
        }
        Cmd::Relays { config, cmd } => {
            let client = admin_client(&HubConfig::load(config.config.as_deref())?)?;
            tokio::task::spawn_blocking(move || relays_blocking(&client, cmd)).await?
        }
        Cmd::Registries { config, cmd } => {
            let client = admin_client(&HubConfig::load(config.config.as_deref())?)?;
            registries_cmd(client, cmd).await
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
                Some(NodesCmd::Reset {
                    id, keep_images, ..
                }) => command(client, id, reset_op(keep_images)).await,
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
                Some(NodesCmd::Tools { id, all: _, tools }) => {
                    let issued = tokio::task::spawn_blocking(move || {
                        client.node_tools(id.as_deref(), &tools)
                    })
                    .await??;
                    for n in issued {
                        match (n.command, n.skipped) {
                            (Some(command), _) => eprintln!(
                                "vk-hub: {} ({}): issued (command {command})",
                                n.hostname, n.id
                            ),
                            (None, why) => eprintln!(
                                "vk-hub: {} ({}): skipped: {}",
                                n.hostname,
                                n.id,
                                why.unwrap_or_default()
                            ),
                        }
                    }
                    eprintln!(
                        "vk-hub: `vk-hub nodes` and `vk-hub audit --node <id>` show how the \
                         builds go"
                    );
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
                    program,
                } => {
                    let signature = signature.map(|path| read_signature(&path)).transpose()?;
                    // Absolute, since the hub resolves it from its own working directory.
                    let file = std::path::absolute(&file)
                        .with_context(|| format!("resolving {}", file.display()))?;
                    let added = tokio::task::spawn_blocking(move || {
                        client.add_release(&file, &version, signature, Some(&program))
                    })
                    .await??;
                    // The sha256 alone on stdout, so `$(vk-hub release add …)` captures it.
                    println!("{}", added.sha256);
                    eprintln!(
                        "vk-hub: holding {} {} ({} bytes); `vk-hub {} update <id> --release {}` \
                         updates one to it",
                        added.row.program(),
                        added.row.version,
                        added.row.size,
                        if added.row.program() == store::REGISTRY_PROGRAM {
                            "registries"
                        } else {
                            "nodes"
                        },
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
                            "{}  {:<11}  {:<12}  {:>10}  {:<8}  added {} by {}",
                            r.sha256,
                            r.row.program(),
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
        Cmd::Tools { config, cmd } => {
            let client = admin_client(&HubConfig::load(config.config.as_deref())?)?;
            tools_cmd(client, cmd).await
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
        Cmd::Gitlabs { config, cmd } => {
            let client = admin_client(&HubConfig::load(config.config.as_deref())?)?;
            tokio::task::spawn_blocking(move || gitlabs_blocking(&client, cmd)).await?
        }
        Cmd::Namespaces { config, cmd } => {
            let client = admin_client(&HubConfig::load(config.config.as_deref())?)?;
            tokio::task::spawn_blocking(move || namespaces_blocking(&client, cmd)).await?
        }
        Cmd::Egress { config, cmd } => {
            let client = admin_client(&HubConfig::load(config.config.as_deref())?)?;
            tokio::task::spawn_blocking(move || egress_blocking(&client, cmd)).await?
        }
        Cmd::TokenKeys { config, cmd } => {
            let client = admin_client(&HubConfig::load(config.config.as_deref())?)?;
            tokio::task::spawn_blocking(move || token_keys_blocking(&client, cmd)).await?
        }
        Cmd::Keys { config, cmd } => {
            keys_cmd(
                admin_client(&HubConfig::load(config.config.as_deref())?)?,
                cmd.unwrap_or(KeysCmd::List),
            )
            .await
        }
        Cmd::Jobs {
            config,
            limit,
            events,
            cmd: None,
        } => {
            let client = admin_client(&HubConfig::load(config.config.as_deref())?)?;
            let jobs = tokio::task::spawn_blocking(move || client.jobs(limit, events)).await??;
            print!("{}", render_jobs(&jobs, now_secs()));
            Ok(())
        }
        Cmd::Jobs {
            config,
            cmd: Some(JobsCmd::Show { id }),
            ..
        } => {
            let client = admin_client(&HubConfig::load(config.config.as_deref())?)?;
            let job = {
                let id = id.clone();
                tokio::task::spawn_blocking(move || client.job(&id)).await??
            };
            let Some((row, output)) = job else {
                bail!("no job {} in the history", vk_hub_proto::display_safe(&id));
            };
            print!("{}", render_job(&id, &row, output.as_deref(), now_secs()));
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

async fn tools_cmd(client: admin::Client, cmd: ToolsCmd) -> Result<()> {
    match cmd {
        ToolsCmd::Add { dir, version } => {
            // Absolute, since the hub resolves it from its own working directory.
            let dir = std::path::absolute(&dir)
                .with_context(|| format!("resolving {}", dir.display()))?;
            let added =
                tokio::task::spawn_blocking(move || client.add_tools(&dir, &version)).await??;
            // The sha256 alone on stdout, so `$(vk-hub tools add …)` captures it.
            println!("{}", added.sha256);
            eprintln!(
                "vk-hub: holding tools {} ({} files, {} bytes packed); `vk-hub nodes tools <id> \
                 --tools {}` has a node build them",
                added.row.version,
                added.row.files,
                added.row.size,
                store::short(&added.sha256)
            );
        }
        ToolsCmd::List => {
            let tools = tokio::task::spawn_blocking(move || client.tools()).await??;
            for t in tools {
                println!(
                    "{}  {:<16}  {:>4} files  {:>10}  added {} by {}",
                    t.sha256,
                    t.row.version,
                    t.row.files,
                    t.row.size,
                    utc(t.row.added_at),
                    t.row.added_by
                );
            }
        }
        ToolsCmd::Remove { tools } => {
            let what = tools.clone();
            match tokio::task::spawn_blocking(move || client.remove_tools(&tools)).await?? {
                Some(t) => eprintln!("vk-hub: removed tools {}", t.sha256),
                None => bail!("there are no tools {what}"),
            }
        }
    }
    Ok(())
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
        RolloutCmd::Delete { id } => {
            let r = tokio::task::spawn_blocking(move || client.delete_rollout(&id)).await??;
            eprintln!(
                "vk-hub: deleted rollout {} of vk {}",
                rollout::short_id(&r.id),
                r.row.version
            );
        }
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
    // A kept_output_total lowered while the hub was stopped holds from its start.
    db.fit_job_cache(cfg.kept_output_total)?;
    if let Some(role) = default_role {
        db = db.with_oidc_default_role(role);
    }
    db = db.with_egress_rules(cfg.egress_rules);
    // [jobs] egress_rules turned on or off while the hub was stopped holds from its start.
    if cfg.egress_rules {
        let rules = egress::rules::Rules {
            generation: 0,
            rules: db.egress_rules()?.1,
            enabled: true,
        };
        if let Some(warning) = rules.warning() {
            eprintln!("vk-hub: warning: {warning}");
        }
    }
    let steered = db.steer_fallbacks(now_secs())?;
    if !steered.is_empty() {
        eprintln!(
            "vk-hub: the egress Fallback for gitlab-runner jobs changed on {} node(s)",
            steered.len()
        );
    }
    if cfg.egress_rules {
        eprintln!(
            "vk-hub: placed jobs are held to the hub's egress rules ([jobs] egress_rules), on \
             nodes that enforce them only"
        );
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
    // Before anything could be staging a release or tools: what is staged is a stopped hub's.
    releases::sweep(&cfg.releases_dir());
    releases::sweep(&cfg.tools_dir());
    let mut hub = server::Hub::new(db, cfg.ui.as_ref().map(|ui| ui.url.clone()))
        .with_node_url(cfg.node_url())
        .with_releases(cfg.releases_dir())
        .with_tools(cfg.tools_dir())
        .with_release_source(cfg.release_source.clone())
        .with_token_keys(cfg.token_keys_dir(), cfg.max_job_token);
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
    let hub = Arc::new(
        hub.with_jobs(cfg.jobs_dir(), cfg.job_lost_after, cfg.job_history)?
            .keeping_failure_output(cfg.kept_failure_output)
            .keeping_output(cfg.kept_output, cfg.kept_output_total)
            .preferring_warm_images(cfg.image_affinity),
    );
    jobs::recover(&hub).await?;
    // Retires keys no token can need any more, and resends what changed while stopped; then
    // again every hour. A failure is logged: registries go on without the hub's keys.
    let h = hub.clone();
    match tokio::task::spawn_blocking(move || tokens::sync_all(&h)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("vk-hub: syncing registry tokens: {e:#}"),
        Err(e) => eprintln!("vk-hub: syncing registry tokens: {e}"),
    }
    tokio::spawn(tokens::sweep(hub.clone()));
    tokio::spawn(jobs::drive(hub.clone()));
    tokio::spawn(clients::drive(hub.clone()));
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
            let policy = store::KeyPolicy::with_limits(scopes, pools, max_mem, max_cpus, max_disk);
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

/// `vk-hub gitlabs` and its subcommands, which block on the admin socket.
fn gitlabs_blocking(client: &admin::Client, cmd: Option<GitlabsCmd>) -> Result<()> {
    match cmd.unwrap_or(GitlabsCmd::List) {
        GitlabsCmd::List => {
            let rows: Vec<[String; 4]> = client
                .gitlabs()?
                .into_iter()
                .map(|(name, g)| [name, g.url, utc(g.created_at), g.created_by])
                .collect();
            print!("{}", table(&["NAME", "URL", "ADDED", "BY"], &rows));
            for (url, r) in client.rejected_gitlabs()? {
                println!(
                    "rejected: {url} (by {}, {})",
                    r.rejected_by,
                    utc(r.rejected_at)
                );
            }
        }
        GitlabsCmd::Add { name, url } | GitlabsCmd::Approve { url, name } => {
            let row = client.add_gitlab(&name, &url)?;
            eprintln!("vk-hub: GitLab instance {name} is {}", row.url);
        }
        GitlabsCmd::Pending => {
            let rows: Vec<[String; 4]> = client
                .pending_gitlabs()?
                .into_iter()
                .map(|p| {
                    let since = p.relays.iter().map(|(_, _, at)| *at).min();
                    [
                        p.url,
                        p.spki_sha256.unwrap_or_else(|| "-".to_string()),
                        p.relays
                            .iter()
                            .map(|(id, name, _)| format!("{name} ({id})"))
                            .collect::<Vec<_>>()
                            .join(", "),
                        since.map_or("-".to_string(), utc),
                    ]
                })
                .collect();
            print!(
                "{}",
                table(&["URL", "CERTIFICATE KEY SHA256", "RELAYS", "SINCE"], &rows)
            );
            let projects: Vec<store::ProjectView> = client
                .gitlab_projects(None)?
                .into_iter()
                .filter(|p| p.row.state == store::ProjectState::Pending)
                .collect();
            if !projects.is_empty() {
                println!();
                print!("{}", render_projects(&projects));
            }
        }
        GitlabsCmd::Reject { url } => {
            if client.reject_gitlab(&url)? {
                eprintln!("vk-hub: rejected GitLab server {url}");
            } else {
                eprintln!("vk-hub: GitLab server {url} was rejected already");
            }
        }
        GitlabsCmd::Forget { url } => {
            if !client.forget_gitlab(&url)? {
                bail!("GitLab server {url} is not rejected");
            }
            eprintln!("vk-hub: forgot the rejection of GitLab server {url}");
        }
        GitlabsCmd::Projects { cmd } => projects_blocking(client, cmd)?,
        GitlabsCmd::Remove { name } => {
            if !client.remove_gitlab(&name)? {
                bail!("there is no GitLab instance {name}");
            }
            eprintln!("vk-hub: removed GitLab instance {name}");
        }
    }
    Ok(())
}

/// `vk-hub gitlabs projects` and its subcommands.
fn projects_blocking(client: &admin::Client, cmd: Option<ProjectsCmd>) -> Result<()> {
    let cmd = cmd.unwrap_or(ProjectsCmd::List {
        gitlab: None,
        pending: false,
    });
    match cmd {
        ProjectsCmd::List { gitlab, pending } => {
            let projects: Vec<store::ProjectView> = client
                .gitlab_projects(gitlab.as_deref())?
                .into_iter()
                .filter(|p| !pending || p.row.state == store::ProjectState::Pending)
                .collect();
            print!("{}", render_projects(&projects));
        }
        ProjectsCmd::Approve { gitlab, projects } => {
            let n = client.decide_projects(&gitlab, projects, store::Decision::Approve)?;
            eprintln!("vk-hub: approved {n} project(s) of GitLab instance {gitlab}");
        }
        ProjectsCmd::Reject { gitlab, projects } => {
            let n = client.decide_projects(&gitlab, projects, store::Decision::Reject)?;
            eprintln!("vk-hub: rejected {n} project(s) of GitLab instance {gitlab}");
        }
        ProjectsCmd::Forget { gitlab, ids } => {
            let n = client.forget_projects(&gitlab, ids)?;
            eprintln!("vk-hub: forgot {n} project(s) of GitLab instance {gitlab}");
        }
    }
    Ok(())
}

/// Projects as `vk-hub gitlabs projects` and `gitlabs pending` print them.
fn render_projects(projects: &[store::ProjectView]) -> String {
    let rows: Vec<[String; 7]> = projects
        .iter()
        .map(|p| {
            let r = &p.row;
            [
                p.gitlab.clone(),
                p.id.to_string(),
                if r.path.is_empty() {
                    "-".to_string()
                } else {
                    r.path.clone()
                },
                r.state.name().to_string(),
                utc(r.since),
                r.refused.to_string(),
                match (&r.decided_by, r.first_job, &r.relay) {
                    (Some(by), _, _) => format!("by {by}"),
                    (None, Some(job), Some(relay)) => format!("job {job} via relay {relay}"),
                    (None, Some(job), None) => format!("job {job}"),
                    _ => "-".to_string(),
                },
            ]
        })
        .collect();
    table(
        &["GITLAB", "ID", "PATH", "STATE", "SINCE", "REFUSED", "FROM"],
        &rows,
    )
}

/// `vk-hub relays` and its subcommands, which block on the admin socket.
fn relays_blocking(client: &admin::Client, cmd: Option<RelaysCmd>) -> Result<()> {
    let now = now_secs();
    match cmd.unwrap_or(RelaysCmd::List) {
        RelaysCmd::List => print!("{}", render_relays(&client.list_relays()?, now)),
        RelaysCmd::Show { id } => {
            let Some(r) = client.show_relay(&id)? else {
                bail!("there is no relay {id}");
            };
            print!("{}", render_relay(&r, now));
        }
        RelaysCmd::Remove { id } => {
            if !client.remove_relay(&id)? {
                bail!("there is no relay {id}");
            }
            eprintln!("vk-hub: removed relay {id}");
        }
    }
    Ok(())
}

/// `vk-hub relays`' table, with each relay's notes under it.
fn render_relays(views: &[relays::RelayView], now: u64) -> String {
    let rows: Vec<[String; 7]> = views.iter().map(|r| relays::cells(r, now)).collect();
    let mut out = table(&relays::COLUMNS, &rows);
    for r in views {
        for note in relays::notes(r) {
            out.push_str(&note);
            out.push('\n');
        }
    }
    out
}

/// `vk-hub relays show`.
fn render_relay(r: &relays::RelayView, now: u64) -> String {
    let mut out = render_relays(std::slice::from_ref(r), now);
    let Some(i) = &r.row.inventory else {
        out.push_str("\nno inventory yet\n");
        return out;
    };
    out.push_str(&format!(
        "\nhost {}, system ID {}, concurrent {}\n",
        i.hostname, i.system_id, i.concurrent
    ));
    out.push_str(&format!("GitLab {}", i.server.url));
    if let Some(v) = &i.server.version {
        out.push_str(&format!(", version {v}"));
    }
    out.push('\n');
    if let Some(k) = &i.server.spki_sha256 {
        out.push_str(&format!("certificate key sha256 {k}\n"));
    }
    if let Some(s) = &r.server {
        out.push_str(&format!("server {}\n", relays::server_text(s)));
    }
    let state = |name: &str| {
        r.row
            .report
            .as_ref()
            .and_then(|rep| rep.runners.iter().find(|x| x.name == name))
            .map_or("-".to_string(), |x| {
                let state = serde_json::to_value(x.state)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default();
                match &x.message {
                    Some(m) => format!("{state}: {m}"),
                    None => state,
                }
            })
    };
    let load = |name: &str| {
        r.row
            .heartbeat
            .as_ref()
            .and_then(|h| h.runners.iter().find(|x| x.name == name))
            .map_or("-".to_string(), |x| {
                format!("{} held, {} asking", x.jobs, x.requests)
            })
    };
    let rows: Vec<[String; 7]> = i
        .runners
        .iter()
        .map(|x| {
            let mut placement = x.placement.pool.clone();
            if !x.placement.labels.is_empty() {
                placement.push_str(&format!(" [{}]", x.placement.labels.join(", ")));
            }
            [
                x.name.clone(),
                x.runner_id.map_or("-".to_string(), |id| id.to_string()),
                placement,
                store::envelope_text(x.placement.envelope),
                x.limit.map_or("-".to_string(), |l| l.to_string()),
                if x.verified {
                    state(&x.name)
                } else {
                    format!("not verified; {}", state(&x.name))
                },
                load(&x.name),
            ]
        })
        .collect();
    out.push('\n');
    out.push_str(&table(
        &[
            "RUNNER",
            "GITLAB ID",
            "POOL",
            "ENVELOPE",
            "LIMIT",
            "STATE",
            "LOAD",
        ],
        &rows,
    ));
    out
}

/// `vk-hub namespaces` and its subcommands, which block on the admin socket.
fn namespaces_blocking(client: &admin::Client, cmd: NamespacesCmd) -> Result<()> {
    let show = |ns: &store::NamespaceRow| {
        let mut out = format!("{} {}", ns.name, ns.path);
        if let Some(a) = &ns.alias {
            out.push_str(&format!(" (alias {a})"));
        }
        if let Some(d) = ns.retention_days {
            out.push_str(&format!(" (retention {d} days)"));
        }
        out.push('\n');
        for g in &ns.grants {
            out.push_str(&format!("  {g}\n"));
        }
        out
    };
    match cmd {
        NamespacesCmd::List { registry } => {
            for ns in client.namespaces(&registry)? {
                print!("{}", show(&ns));
            }
        }
        NamespacesCmd::Show { registry, name } => {
            let Some(ns) = client
                .namespaces(&registry)?
                .into_iter()
                .find(|n| n.name == name)
            else {
                bail!("registry {registry} has no namespace {name}");
            };
            print!("{}", show(&ns));
        }
        NamespacesCmd::Add {
            registry,
            name,
            path,
            retention_days,
            alias,
            grants,
        } => {
            let ns = client.put_namespace(
                &registry,
                &name,
                &path,
                retention_days,
                alias.as_deref(),
                grants,
            )?;
            print!("{}", show(&ns));
        }
        NamespacesCmd::Remove { registry, name } => {
            if !client.remove_namespace(&registry, &name)? {
                bail!("registry {registry} has no namespace {name}");
            }
            eprintln!("vk-hub: removed namespace {name}");
        }
    }
    Ok(())
}

/// A rule as `vk-hub egress` prints it.
fn egress_rule_text(r: &store::EgressRuleRow) -> String {
    format!(
        "egress {}  {}  ({}, version {})\n  run    {}\n  build  {}\n",
        r.name,
        r.subject_text(),
        r.mode.name(),
        r.version,
        store::rule_phase_text(&r.run),
        store::rule_phase_text(&r.build)
    )
}

/// A phase from `vk-hub egress set`'s flags: `None` when none is given.
fn egress_phase(
    phase: &str,
    choice: Option<String>,
    names: Vec<String>,
    ips: Vec<String>,
) -> Result<Option<vk_hub_proto::egress::HubPhase>> {
    use vk_hub_proto::egress::HubPhase;
    let listed = !names.is_empty() || !ips.is_empty();
    Ok(match choice.as_deref() {
        Some(_) if listed => {
            bail!("--{phase} is unrestricted or none; the destinations listed already choose it")
        }
        Some("unrestricted") => Some(HubPhase::Unrestricted),
        Some("none") => Some(HubPhase::Allow {
            names: Vec::new(),
            ips: Vec::new(),
        }),
        Some(other) => bail!("--{phase} {other:?}: expected unrestricted or none"),
        None if listed => Some(HubPhase::Allow { names, ips }),
        None => None,
    })
}

fn rule_mode(mode: &str) -> Result<store::RuleMode> {
    store::RuleMode::parse(mode)
        .ok_or_else(|| anyhow::anyhow!("{mode:?}: expected enforce or dry-run"))
}

/// `vk-hub egress` and its subcommands, which block on the admin socket.
fn egress_blocking(client: &admin::Client, cmd: Option<EgressCmd>) -> Result<()> {
    match cmd.unwrap_or(EgressCmd::List) {
        EgressCmd::List => {
            let listed = client.egress_rules()?;
            if listed.rules.is_empty() {
                eprintln!("vk-hub: no egress rules");
            }
            if let Some(warning) = listed.warning() {
                eprintln!("vk-hub: warning: {warning}");
            }
            for r in &listed.rules {
                print!("{}", egress_rule_text(r));
            }
        }
        EgressCmd::Show { name } => {
            let Some(r) = client
                .egress_rules()?
                .rules
                .into_iter()
                .find(|r| r.name == name)
            else {
                bail!("there is no egress rule {name}");
            };
            print!("{}", egress_rule_text(&r));
        }
        EgressCmd::Set {
            name,
            subject,
            run,
            run_names,
            run_ips,
            build,
            build_names,
            build_ips,
            mode,
        } => {
            let change = egress::rules::Change {
                name,
                subject,
                run: egress_phase("run", run, run_names, run_ips)?,
                build: egress_phase("build", build, build_names, build_ips)?,
                mode: mode.as_deref().map(rule_mode).transpose()?,
            };
            let (r, changed) = client.put_egress_rule(change, false)?;
            if !changed {
                eprintln!("vk-hub: egress rule {} is already so", r.name);
            }
            print!("{}", egress_rule_text(&r));
        }
        EgressCmd::Mode { name, mode } => {
            let change = egress::rules::Change {
                name,
                mode: Some(rule_mode(&mode)?),
                ..Default::default()
            };
            let (r, _) = client.put_egress_rule(change, true)?;
            print!("{}", egress_rule_text(&r));
        }
        EgressCmd::Delete { name } => {
            if !client.remove_egress_rule(&name)? {
                bail!("there is no egress rule {name}");
            }
            eprintln!("vk-hub: removed egress rule {name}");
        }
        EgressCmd::Resolve {
            gitlab,
            project,
            project_id,
            git_ref,
            protected,
        } => {
            let layer = client.resolve_egress(egress::rules::Claims {
                gitlab,
                project_id,
                project_path: project,
                git_ref,
                protected,
            })?;
            println!("{}", serde_json::to_string_pretty(&layer)?);
            // Placement holds the layer to the same bounds, and fails a job whose layer fails.
            if let Err(why) = layer.check() {
                bail!("a job of these claims would fail: its layer cannot be sent: {why}");
            }
        }
    }
    Ok(())
}

/// `vk-hub token-keys` and its subcommands, which block on the admin socket.
fn token_keys_blocking(client: &admin::Client, cmd: Option<TokenKeysCmd>) -> Result<()> {
    match cmd.unwrap_or(TokenKeysCmd::List) {
        TokenKeysCmd::List => {
            let rows: Vec<[String; 3]> = client
                .token_keys()?
                .into_iter()
                .map(|k| {
                    [
                        k.public.kid,
                        utc(k.created_at),
                        k.superseded_at.map_or_else(
                            || "signing".to_string(),
                            |at| format!("superseded {}", utc(at)),
                        ),
                    ]
                })
                .collect();
            print!("{}", table(&["KEY", "CREATED", "STATE"], &rows));
        }
        TokenKeysCmd::Rotate => {
            let row = client.rotate_token_keys()?;
            eprintln!(
                "vk-hub: token-signing key {} signs each registry's tokens once it has applied it",
                row.public.kid
            );
        }
    }
    Ok(())
}

/// `vk-hub jobs`' table: how long each job prepared and ran, or has so far, and the most memory
/// its VM held, rounded up to a MiB, where its node reported it.
fn render_jobs(jobs: &[(String, store::JobRow)], now: u64) -> String {
    let rows: Vec<[String; 12]> = jobs
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
                j.prepare_ms(now)
                    .map_or_else(|| "-".to_string(), jobs::run_text),
                j.ran_ms(now)
                    .map_or_else(|| "-".to_string(), jobs::run_text),
                usage.and_then(|u| u.peak_mem_bytes).map_or_else(
                    || "-".to_string(),
                    |b| workloads::size_mib(b.div_ceil(1 << 20)),
                ),
                j.result
                    .as_ref()
                    .and_then(|r| jobs::events_summary(&r.events))
                    .unwrap_or_else(|| "-".to_string()),
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
            "PREP",
            "RAN",
            "PEAK",
            "EVENTS",
            "JOB",
        ],
        &rows,
    )
}

/// `vk-hub jobs show`: job `id`'s record, a field a line, then what was kept of its output
/// made readable ([`jobs::readable`]): the job's escape sequences never reach the terminal.
fn render_job(id: &str, j: &store::JobRow, output: Option<&[u8]>, now: u64) -> String {
    let result = j.result.as_ref();
    let usage = result.and_then(|r| r.usage);
    let dash = || "-".to_string();
    let at = |t: Option<u64>| t.map_or_else(dash, utc);
    let mut fields = vec![
        ("job", id.to_string()),
        ("title", j.title.clone()),
        ("project", j.project.clone().unwrap_or_else(dash)),
        ("branch", j.git_ref.clone().unwrap_or_else(dash)),
        ("commit", j.commit.clone().unwrap_or_else(dash)),
        ("state", jobs::state_text(j)),
    ];
    if let Some(code) = result.and_then(|r| r.exit_code) {
        fields.push(("exit code", code.to_string()));
    }
    if let Some(message) = result.and_then(|r| r.message.clone()) {
        fields.push(("message", message));
    }
    // Shown only as a plain web link, as the web UI does.
    if let Some(url) = j.job_url.clone().filter(|u| vk_hub_proto::is_web_link(u)) {
        fields.push(("gitlab", url));
    }
    fields.extend([
        ("node", j.node.clone().unwrap_or_else(dash)),
        ("pool", j.placement.pool.clone()),
        ("key", j.key_name.clone()),
        ("submitted", utc(j.created_at)),
        ("started", at(j.started_at)),
        ("finished", at(j.finished_at)),
        ("settled", at(j.settled_at)),
        (
            "prepared in",
            j.prepare_ms(now).map_or_else(dash, jobs::run_text),
        ),
        ("ran", j.ran_ms(now).map_or_else(dash, jobs::run_text)),
        (
            "size",
            jobs::size_text(j, workloads::size_mib).unwrap_or_else(dash),
        ),
        (
            "peak memory",
            usage
                .and_then(|u| u.peak_mem_bytes)
                .map_or_else(dash, |b| workloads::size_mib(b.div_ceil(1 << 20))),
        ),
        (
            "cpu time",
            usage
                .and_then(|u| u.cpu_ms)
                .map_or_else(dash, jobs::run_text),
        ),
        ("output", format!("{} bytes", j.output_len)),
    ]);
    let mut out = String::new();
    for (key, value) in fields {
        let value = vk_hub_proto::display_safe(&value);
        out.push_str(&format!("{key:<12} {value}\n"));
    }
    // Print the full sanitized detail: its ending explains what happened and can exceed
    // the usual field limit.
    for event in result.map_or(&[][..], |r| &r.events) {
        out.push_str(&format!("{:<12} {event}\n", "event"));
    }
    if let Some(applied) = &j.egress_rules {
        out.push_str(&format!(
            "{:<12} {}\n",
            "hub rules",
            egress::rules_applied_text(applied)
        ));
    }
    for (key, value) in egress::lines(j) {
        let value = vk_hub_proto::display_safe(&value);
        out.push_str(&format!("{key:<12} {value}\n"));
    }
    if let Some(output) = output {
        out.push_str(&format!(
            "\nThe last {} bytes of its output, masked as the node streamed it:\n",
            output.len()
        ));
        for line in jobs::readable(output) {
            if let Some(at) = &line.at {
                out.push_str(at.get(11..19).unwrap_or(at));
                out.push(' ');
            }
            out.push_str(&line.text);
            out.push('\n');
        }
    }
    out
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
    // On a hub that places jobs, a runner of the node's own, which says why it refuses them.
    let own_runner = (n.report.as_ref())
        .and_then(|r| r.placed.as_ref())
        .and_then(|p| p.runner.as_ref())
        .filter(|_| n.placed.is_some());
    if let Some(why) = &n.last_refusal
        && !(own_runner.is_some() && (why == "runner" || why.starts_with("runner: ")))
    {
        placement.push(format!("{}: refuses reservations: {why}", n.hostname));
    }
    if let Some(why) = own_runner {
        placement.push(format!(
            "{}: takes none of the hub's jobs: it runs its own gitlab-runner ({why})",
            n.hostname
        ));
    }
    if n.without_egress_rules {
        placement.push(format!(
            "{}: takes none of the hub's jobs: it does not enforce the hub's egress rules, \
             which [jobs] egress_rules turns on",
            n.hostname
        ));
    }
    if n.report.as_ref().and_then(|r| r.runner) == Some(vk_hub_proto::RunnerMode::None) {
        placement.push(format!(
            "{}: no gitlab-runner, placed jobs only",
            n.hostname
        ));
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
    notes.extend(tools_notes(n));
    notes
}

/// What a node says of its CI tools: those current, and the build under way or the last one,
/// with the end of its output when it failed.
fn tools_notes(n: &ops::NodeView) -> Vec<String> {
    let mut notes = Vec::new();
    if let Some(t) = &n.tools {
        let found: Vec<String> = t.tools.values().cloned().collect();
        notes.push(format!(
            "{}: tools {} ({}){}{}",
            n.hostname,
            t.version,
            store::short(&t.sha256),
            if found.is_empty() {
                String::new()
            } else {
                format!(": {}", found.join(", "))
            },
            if t.in_use {
                ""
            } else {
                "; not in use: [executor] tools_dir names another directory"
            }
        ));
    }
    let Some(b) = n.report.as_ref().and_then(|r| r.tools.as_ref()) else {
        return notes;
    };
    // A build that ended well is the tools line above.
    if b.phase == vk_hub_proto::ToolsPhase::Done {
        return notes;
    }
    notes.push(format!(
        "{}: tools {} ({}): {}{}",
        n.hostname,
        b.version,
        store::short(&b.sha256),
        store::tools_phase_name(b.phase),
        b.message
            .as_deref()
            .map_or_else(String::new, |m| format!(": {m}"))
    ));
    notes.extend(b.log.iter().map(|line| format!("    {line}")));
    notes
}

/// `vk-hub registries` and its subcommands.
async fn registries_cmd(client: admin::Client, cmd: Option<RegistriesCmd>) -> Result<()> {
    tokio::task::spawn_blocking(move || registries_blocking(&client, cmd)).await?
}

/// [`registries_cmd`]'s calls, which block on the admin socket.
fn registries_blocking(client: &admin::Client, cmd: Option<RegistriesCmd>) -> Result<()> {
    let desired = |id: &str, desired: Option<vk_hub_proto::registry::DesiredState>| match desired {
        Some(d) => eprintln!(
            "vk-hub: registry {id}: desired state generation {}",
            d.generation
        ),
        None => eprintln!("vk-hub: already so; nothing changed"),
    };
    match cmd {
        None => print!(
            "{}",
            render_registries(&client.list_registries()?, now_secs())
        ),
        Some(RegistriesCmd::Show { id }) => {
            let Some((view, commands)) = client.show_registry(&id)? else {
                bail!("there is no registry {id}");
            };
            print!("{}", render_registry(&view, &commands, now_secs()));
        }
        Some(RegistriesCmd::Remove { id }) => {
            if !client.remove_registry(&id)? {
                bail!("there is no registry {id}");
            }
            eprintln!("vk-hub: removed registry {id}");
        }
        Some(RegistriesCmd::ReadOnly { id, state }) => {
            let read_only = match state.as_str() {
                "on" => Some(true),
                "off" => Some(false),
                _ => None,
            };
            desired(&id, client.set_registry_read_only(&id, read_only)?);
        }
        Some(RegistriesCmd::GcSchedule {
            id,
            every,
            retention_days,
            grace_days,
            off: _,
        }) => {
            // `--off` conflicts with `--every`, so it leaves `every` unset.
            let gc = every.map(|every| vk_hub_proto::registry::GcPolicy {
                every_secs: every.as_secs(),
                retention_days,
                grace_days,
            });
            desired(&id, client.set_registry_gc(&id, gc)?);
        }
        Some(RegistriesCmd::Gc {
            id,
            retention_days,
            grace_days,
            dry_run,
        }) => {
            let command = client.registry_gc(&id, retention_days, grace_days, dry_run)?;
            eprintln!("vk-hub: registry {id}: issued command {}", command.id);
        }
        Some(RegistriesCmd::Update { id, release }) => {
            let command = client.update_registry(&id, &release)?;
            eprintln!("vk-hub: registry {id}: issued command {}", command.id);
        }
        Some(RegistriesCmd::SetUrl { id, url, none: _ }) => {
            // `--none` conflicts with a URL, so it leaves `url` unset.
            if client.set_registry_url(&id, url)? {
                eprintln!("vk-hub: registry {id}: URL changed");
            } else {
                eprintln!("vk-hub: already so; nothing changed");
            }
        }
        Some(RegistriesCmd::Token {
            id,
            grants,
            pipeline,
            ttl,
        }) => {
            let token = client.mint_registry_token(&id, grants, pipeline, ttl)?;
            // The token alone on stdout, so `$(vk-hub registries token …)` captures just it.
            println!("{token}");
            eprintln!(
                "vk-hub: registry token for {id}, valid for {}",
                human_duration(ttl)
            );
        }
    }
    Ok(())
}

/// `vk-hub registries`' table, with each registry's notes under it.
fn render_registries(views: &[registries::RegistryView], now: u64) -> String {
    let rows: Vec<[String; 9]> = views.iter().map(|r| registries::cells(r, now)).collect();
    let mut out = table(&registries::COLUMNS, &rows);
    for r in views {
        for note in registries::notes(r) {
            out.push_str(&note);
            out.push('\n');
        }
    }
    out
}

/// `vk-hub registries show`.
fn render_registry(
    r: &registries::RegistryView,
    commands: &[store::RegistryCommandRow],
    now: u64,
) -> String {
    let mut out = render_registries(std::slice::from_ref(r), now);
    let mut field = |name: &str, value: String| out.push_str(&format!("{name}: {value}\n"));
    if let Some(i) = &r.row.inventory {
        field(
            "listen",
            format!("{}{}", i.listen, if i.tls { " (TLS)" } else { "" }),
        );
        field("store", i.store.clone());
        field("webdav", i.webdav.to_string());
        field(
            "the hub may",
            if i.allow.is_empty() {
                "nothing ([hub] allow is empty)".to_string()
            } else {
                i.allow.join(", ")
            },
        );
        field("signed updates only", i.requires_signed.to_string());
        field("takes tokens", i.tokens.to_string());
    }
    field(
        "url",
        r.row
            .url
            .clone()
            .unwrap_or_else(|| "none bound (vk-hub registries set-url)".to_string()),
    );
    if let Some(u) = &r.row.usage {
        field(
            "usage",
            format!(
                "{} stored, {} referenced, {} tags, {} blobs (at {})",
                registries::gib(u.stored_bytes),
                registries::gib(u.referenced_bytes),
                u.tags,
                u.blobs,
                utc(u.at)
            ),
        );
    }
    match &r.row.desired {
        Some(d) => field(
            "desired",
            format!(
                "generation {}, read-only {}, gc {}",
                d.generation,
                d.read_only
                    .map_or("as configured".to_string(), |b| b.to_string()),
                d.gc.map_or("not scheduled".to_string(), |gc| format!(
                    "every {}",
                    human_duration(Duration::from_secs(gc.every_secs))
                ))
            ),
        ),
        None => field("desired", "nothing asked".to_string()),
    }
    if let Some(applied) = r.row.report.as_ref().and_then(|rep| rep.applied) {
        field("applied", format!("generation {applied}"));
    }
    for c in commands {
        out.push_str(&format!(
            "command {} {} at {}: {}\n",
            c.command.id,
            store::registry_operation_name(&c.command.op),
            utc(c.issued_at),
            match &c.outcome {
                Some(o) => store::outcome_text(o),
                None if c.command.expires_at <= now => "expired, never taken".to_string(),
                None => "not taken yet".to_string(),
            }
        ));
    }
    out
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
