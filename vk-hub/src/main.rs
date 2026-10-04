//! `vk-hub` — the fleet hub. Nodes running `vk node` enroll with it, hold a session to it,
//! and report their inventory and heartbeats; operators issue enrollment tokens and list the
//! fleet. See `docs/fleet-design.md`.
//!
//! `vk-hub local` serves a web UI for the VMs of the machine it runs on instead, as the user
//! who owns them, on a loopback name of its own ("Local mode" in the same document). People
//! sign in with single-use links the hub prints, or issues over a unix socket only its own
//! user reaches; what they do is recorded in an audit log.
//!
//! Experimental. A web UI on a listener of its own shows the fleet to people signed in with
//! links the admin socket issues.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};

mod admin;
mod config;
mod local;
mod ops;
mod server;
mod session;
mod store;
mod ui;
mod workloads;

use config::HubConfig;

// Match vk-registry: jemalloc under musl for a long-lived server.
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

/// Fleet hub: node enrollment, inventory and heartbeats; and a web UI for this
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
    /// ui_tls_key [default: built-in defaults]
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
    /// List the enrolled nodes, or remove one
    Nodes {
        #[command(flatten)]
        config: ConfigArg,
        #[command(subcommand)]
        cmd: Option<NodesCmd>,
    },
    /// List the VMs running on the nodes: CI jobs, dev environments, pinned runs
    Workloads {
        #[command(flatten)]
        config: ConfigArg,
        /// Only this node's: its ID, or a hostname only it has
        #[arg(long, value_name = "ID")]
        node: Option<String>,
    },
    /// Sign in to the web UI, and see or end its sessions
    Ui {
        #[command(flatten)]
        config: ConfigArg,
        #[command(subcommand)]
        cmd: UiCmd,
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
enum UiCmd {
    /// Print a single-use link that opens a web UI session
    ///
    /// The link is a credential until it is used or expires: open it yourself, or hand it
    /// only to whoever the session is for.
    Login {
        /// viewer (read only) or operator
        #[arg(long, default_value = "viewer", value_parser = parse_role)]
        role: store::Role,
        /// How long the link stays valid: <n>s, <n>m, <n>h or <n>d (at most 24h)
        #[arg(long, default_value = "10m", value_parser = parse_ttl)]
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
        /// How long the link stays valid: <n>s, <n>m, <n>h or <n>d (at most 24h)
        #[arg(long, default_value = "10m", value_parser = parse_ttl)]
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
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Issue a single-use enrollment token, printed once
    Create {
        #[command(flatten)]
        config: ConfigArg,
        /// How long the token stays valid: <n>s, <n>m, <n>h or <n>d (at most 30d)
        #[arg(long, default_value = "1h", value_parser = parse_ttl)]
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
    // rustls is built without a default provider (see the workspace Cargo.toml).
    let _ = rustls::crypto::ring::default_provider().install_default();
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
            }
        }
        Cmd::Ui { config, cmd } => {
            ui_cmd(
                admin_client(&HubConfig::load(config.config.as_deref())?)?,
                cmd,
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
        Cmd::Workloads { config, node } => {
            let client = admin_client(&HubConfig::load(config.config.as_deref())?)?;
            let nodes =
                tokio::task::spawn_blocking(move || client.workloads(node.as_deref())).await??;
            print!("{}", render_workloads(&nodes));
            Ok(())
        }
    }
}

async fn serve(cfg: HubConfig) -> Result<()> {
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
    let db = Arc::new(store::Db::open(&cfg.db_path())?);
    let hub = Arc::new(server::Hub::new(
        db,
        cfg.ui.as_ref().map(|ui| ui.url.clone()),
    ));
    // Fatal, unlike the registry's optional admin socket: here it is the only way to issue
    // a token, so a hub without it could never enroll anything.
    let admin = admin::bind(&cfg.admin_socket())?;
    tokio::spawn(admin::serve(admin, hub.clone()));
    if let Some((listener, tls, ui)) = ui {
        eprintln!(
            "vk-hub: serving the web UI on {}://{} as {}",
            if tls.is_some() { "https" } else { "http" },
            ui.addr,
            ui.url
        );
        let ui = Arc::new(ui::Ui::new(hub.clone(), &ui.url));
        tokio::spawn(async move {
            if let Err(e) = ui::serve(listener, tls, ui).await {
                eprintln!("vk-hub: the web UI stopped: {e:#}");
            }
        });
    }
    eprintln!(
        "vk-hub: serving nodes on {}://{} (data in {})",
        if tls.is_some() { "https" } else { "http" },
        cfg.addr,
        cfg.data_dir.display()
    );
    server::serve(listener, tls, hub).await
}

/// `vk-hub ui login|sessions|logout`, and `vk-hub local`'s, over the running hub's admin
/// socket.
async fn ui_cmd(client: admin::Client, cmd: UiCmd) -> Result<()> {
    match cmd {
        UiCmd::Login { role, ttl } => {
            let link = tokio::task::spawn_blocking(move || client.ui_login(role, ttl)).await??;
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
                println!(
                    "{}  {:<8}  signed in {}  expires in {}  link from {}",
                    s.id,
                    s.role.name(),
                    utc(s.created_at),
                    human_duration(ago(s.expires_at, now)),
                    s.issued_by
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

/// `<n>s`, `<n>m`, `<n>h` or `<n>d`.
fn parse_ttl(s: &str) -> Result<Duration, String> {
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
    if ttl.is_zero() || ttl > store::MAX_TOKEN_TTL {
        return Err(format!("{s:?}: a token lives between 1s and 30d"));
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
pub(crate) const NODE_COLUMNS: [&str; 9] = [
    "ID",
    "NAME",
    "REACH",
    "LAST SEEN",
    "VK",
    "CPUS",
    "RAM",
    "ADMITTED",
    "VMS",
];

/// One node's cells under [`NODE_COLUMNS`]: what it is.
pub(crate) fn node_cells(n: &ops::NodeView, now: u64) -> [String; 9] {
    let gib = |mib: u64| format!("{}G", mib / 1024);
    let dash = || "-".to_string();
    let count = |n: Option<u32>| n.map_or_else(dash, |c| c.to_string());
    [
        n.id.clone(),
        n.hostname.clone(),
        if n.connected {
            "connected"
        } else {
            "unreachable"
        }
        .to_string(),
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

/// `vk-hub nodes`' table.
fn render_nodes(nodes: &[ops::NodeView], now: u64) -> String {
    let rows: Vec<[String; 9]> = nodes.iter().map(|n| node_cells(n, now)).collect();
    table(&NODE_COLUMNS, &rows)
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
/// has not reported any or left some out.
fn render_workloads(nodes: &[ops::NodeWorkloads]) -> String {
    let mut rows: Vec<[String; 10]> = Vec::new();
    let mut notes = Vec::new();
    for n in nodes {
        let Some(workloads) = &n.workloads else {
            notes.push(format!("{}: has not reported its workloads", n.hostname));
            continue;
        };
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
    let s = now.saturating_sub(then);
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

/// Whether `signature` (hex) is `public_key`'s ed25519 signature over `message`.
pub(crate) fn verify(public_key: &[u8], message: &[u8], signature: &str) -> bool {
    let Some(signature) = vk_hub_proto::from_hex(signature) else {
        return false;
    };
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
        .verify(message, &signature)
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
