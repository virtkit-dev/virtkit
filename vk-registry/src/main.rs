//! `vk-registry` — the standalone central OCI-distribution daemon.
//!
//! One server, shared by every CI runner, backing a content-addressed + CDC-dedup
//! store: runners (and the `task` build cache) push a built image/bundle once and
//! everyone else pulls it. It also fronts upstream registries as a pull-through
//! cache and coordinates build-once via a lock API. See `DESIGN.md`.
//!
//! This binary is the serving front end; the store and its helpers live in the
//! `vk_registry` library, which `vk` also links for its in-process build cache.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use vk_selfupdate::{Outcome, Tool};

/// The `accounts` subcommand's implementation. A module of this binary rather than
/// of the library: its whole contract is printing operator prose on stdout, which is no
/// part of the store API `vk-driver` links.
mod accounts_cli;

// Match vk-driver: jemalloc under musl (the glibc allocator fragments on the
// long-lived, many-small-allocation server workload).
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

/// Central OCI-distribution server: build-once dedup, pull-through relay, build lock
#[derive(Parser)]
#[command(
    name = "vk-registry",
    version,
    after_help = "The `serve`/`install-service` --config file's keys are documented in \
                  `vk-registry serve --help`."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve the registry over HTTP, backed by a content-addressed store
    ///
    /// With no upstreams configured it is a plain local OCI server; configure `[[upstream]]` in
    /// the config file to make it a pull-through mirror.
    ///
    /// Every config-file key is listed at the end of this help, with two examples.
    #[command(
        after_help = "Every --config key is listed by `vk-registry serve --help`.",
        after_long_help = vk_registry::config::config_file_help()
    )]
    Serve {
        /// Listen address [default: the `addr` in --config, else 127.0.0.1:5000]
        #[arg(long)]
        addr: Option<SocketAddr>,
        /// Store directory [default: the `root` in --config, else the shared virtkit store]
        ///
        /// The shared store is $XDG_DATA_HOME/virtkit/registry.
        #[arg(long, value_name = "DIR")]
        root: Option<PathBuf>,
        /// TOML config file with `[[upstream]]` relay entries, addr/root, TLS and auth
        ///
        /// Its keys are documented below.
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
    /// Write the unit that runs `serve`
    ///
    /// Installs and starts a `systemd --user` one, or with `--system` prints a machine-wide one
    /// for an admin to install. The `--user` unit runs as you, on a port you can bind, and
    /// comes back with your session (or without one, after `loginctl enable-linger`). The
    /// `--system` unit runs as an unprivileged account of its own, may write only the store,
    /// and is allowed to bind a privileged port only when the port is one — it is printed, not
    /// installed, because creating that account and writing under /etc are the admin's step, so
    /// nothing here needs root.
    InstallService {
        /// Listen address to bake into the unit
        ///
        /// A --config file is where a unit's addr belongs, so the two cannot be combined.
        #[arg(long, default_value_t = vk_registry::DEFAULT_ADDR, conflicts_with = "config")]
        addr: SocketAddr,
        /// Store directory to bake into the unit [default: the shared virtkit store]
        ///
        /// The shared store is $XDG_DATA_HOME/virtkit/registry, which a --system unit cannot
        /// use — that shape needs this flag, or a --config that sets `root`.
        #[arg(long, conflicts_with = "config", value_name = "DIR")]
        root: Option<PathBuf>,
        /// The `serve` config file the unit should read
        ///
        /// It carries addr/root/TLS/auth, so passing it together with --addr or --root is an
        /// error.
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
        /// Print a hardened machine-wide unit on stdout rather than installing a --user one
        #[arg(long)]
        system: bool,
        /// The account a --system unit runs as; it has to exist and own the store
        #[arg(
            long,
            default_value = "vk-registry",
            requires = "system",
            value_name = "NAME"
        )]
        service_user: String,
    },
    /// Report the store's usage and content
    ///
    /// On-disk size, dedup savings, and a per-repository breakdown. Read-only — it creates no
    /// store.
    Status {
        /// Store directory [default: the `root` in --config, else the shared virtkit store]
        ///
        /// The shared store is $XDG_DATA_HOME/virtkit/registry.
        #[arg(long, value_name = "DIR")]
        root: Option<PathBuf>,
        /// The `serve` config file to take the store root from
        ///
        /// Reporting then covers the store the server actually uses.
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
    /// Garbage-collect the store
    ///
    /// Drops tags idle past the retention window, then sweeps unreferenced blobs and stale
    /// uploads (both after a grace window).
    Gc {
        /// Store directory [default: the `root` in --config, else the shared virtkit store]
        ///
        /// The shared store is $XDG_DATA_HOME/virtkit/registry.
        #[arg(long, value_name = "DIR")]
        root: Option<PathBuf>,
        /// The `serve` config file to take the store root from
        ///
        /// The sweep then covers the store the server actually uses.
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
        /// Drop tags unused for more than this many days
        #[arg(long, default_value_t = 30, value_name = "DAYS")]
        retention_days: u64,
        /// Keep unreferenced blobs and stale uploads this many days past their last use
        ///
        /// The window protects in-flight multi-request pushes.
        #[arg(long, default_value_t = 1, value_name = "DAYS")]
        grace_days: u64,
        /// Report what would be removed without removing anything
        #[arg(long)]
        dry_run: bool,
    },
    /// Replace this `vk-registry` with a GitHub release build
    ///
    /// Installs the latest release, or the VERSION given. Prints what it is about to install
    /// and asks before touching anything; the download is checked against the digest published
    /// beside it and must report its own version before it replaces the running binary. Needs
    /// write access to the directory `vk-registry` is installed in. A server already running
    /// keeps serving the build it started as, so restart its unit to pick this one up.
    /// `--check` only reports what is available, downloading nothing. Exit: 0 up to date,
    /// installed, or declined at the prompt; 1 a newer release is available (`--check`); 2 the
    /// update or check itself failed.
    Update {
        /// release to install, `0.33.0` or `v0.33.0` (default: the latest release)
        ///
        /// An older version downgrades, which `--check` does not report as an update available.
        version: Option<String>,
        /// skip the confirmation prompt (for unattended use)
        #[arg(short = 'y', long, conflicts_with = "check")]
        yes: bool,
        /// report whether a newer release is available and exit
        ///
        /// Downloads nothing, installs nothing (exit 1 when a newer release exists).
        #[arg(long)]
        check: bool,
    },
    /// Manage users and API keys in `mode = "accounts"` (see DESIGN.md)
    ///
    /// Works with the registry running — through its local admin socket — and with it
    /// stopped, by opening the accounts db directly; only one process can hold that file
    /// at a time. Either way there is no HTTP route for any of this, by design: an
    /// operator on the machine holding the accounts is the trust level it assumes.
    Accounts {
        #[command(subcommand)]
        cmd: AccountsCmd,
    },
}

/// Which accounts a subcommand works on, and how it reaches them. The db is an explicit
/// `--accounts-db`, else the `serve` config's (`--config`), else
/// `<root>/accounts/accounts.db` under the resolved store root; the running server holding
/// it is `--admin-socket`, else the config's `admin_socket`, else the socket beside that db.
/// Shared by every `accounts` subcommand.
#[derive(clap::Args)]
struct StoreArgs {
    /// Store directory [default: the `root` in --config, else the shared virtkit store]
    #[arg(long, value_name = "DIR")]
    root: Option<PathBuf>,
    /// The `serve` config file to take root/accounts_db/admin_socket from
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Accounts db file [default: --config's accounts_db, else <root>/accounts/accounts.db]
    #[arg(long, value_name = "FILE", conflicts_with_all = ["root", "config"])]
    accounts_db: Option<PathBuf>,
    /// Admin socket of the running server [default: admin.sock beside the accounts db]
    ///
    /// Where to reach a server that holds the db. Nothing listening there is not an
    /// error: the db is then opened directly. Naming one picks the *server*, so it is that
    /// server's accounts an operation lands in — check the server each subcommand reports.
    #[arg(long, value_name = "FILE")]
    admin_socket: Option<PathBuf>,
}

#[derive(Subcommand)]
enum AccountsCmd {
    /// List every known user
    ListUsers {
        #[command(flatten)]
        store: StoreArgs,
    },
    /// Grant a user admin (write access to every repo)
    GrantAdmin {
        /// The user's OIDC email claim
        email: String,
        /// Which provider's user, when one email matches more than one
        #[arg(long, value_name = "URL")]
        issuer: Option<String>,
        #[command(flatten)]
        store: StoreArgs,
    },
    /// Revoke a user's admin
    RevokeAdmin {
        /// The user's OIDC email claim
        email: String,
        /// Which provider's user, when one email matches more than one
        #[arg(long, value_name = "URL")]
        issuer: Option<String>,
        #[command(flatten)]
        store: StoreArgs,
    },
    /// List API keys — every key, or one user's
    ListKeys {
        /// Only this user's keys
        #[arg(long, value_name = "EMAIL")]
        owner_email: Option<String>,
        /// Which provider's user, when one email matches more than one
        ///
        /// Only means anything alongside --owner-email, and is refused without it: on its
        /// own it reads as a filter and would silently list every key instead.
        #[arg(long, value_name = "URL", requires = "owner_email")]
        issuer: Option<String>,
        #[command(flatten)]
        store: StoreArgs,
    },
    /// Revoke an API key by id (see `list-keys`)
    ///
    /// Reports failure for an id that is unknown *or* already revoked — it does not
    /// distinguish the two.
    RevokeKey {
        /// The key's id, as `list-keys` prints it
        id: String,
        #[command(flatten)]
        store: StoreArgs,
    },
    /// Create a scoped API key, printed once
    CreateKey {
        /// The key owner's email [default: a system key, owned by no one]
        ///
        /// CI usually wants a system key rather than one tied to a person who may
        /// leave or have their own admin status revoked later.
        #[arg(long, value_name = "EMAIL")]
        owner_email: Option<String>,
        /// Which provider's user, when one email matches more than one
        ///
        /// Only means anything alongside --owner-email, and is refused without it.
        #[arg(long, value_name = "URL", requires = "owner_email")]
        issuer: Option<String>,
        /// A short label for the key
        #[arg(long)]
        name: String,
        /// ACTION:repo_pattern, e.g. write:team-a/* — repeat for more than one
        #[arg(long = "scope", value_name = "ACTION:PATTERN", required = true)]
        scopes: Vec<String>,
        /// Expire the key after this many days [default: never]
        #[arg(long, value_name = "DAYS")]
        expires_days: Option<u64>,
        #[command(flatten)]
        store: StoreArgs,
    },
}

/// How a `StoreArgs` reaches the accounts: over the admin socket of a running server when
/// one answers there, else by opening the db itself. Also the label naming that store, for
/// the messages that report on it.
///
/// The socket first, because the alternative fails outright while a server is up: redb
/// holds the file exclusively. A socket nobody answers is the ordinary case (no server
/// running) and falls through silently; one that refuses *this* user does not — falling
/// through would only fail again on the db, with a worse explanation than the real one.
///
/// **Which accounts get touched is the socket's answer, not the store selector's.** Left to
/// default, the socket is derived from the resolved db, so the two agree by construction.
/// Named instead — `--admin-socket`, or `admin_socket` in the config file — it is a
/// deliberate choice of *server*, and no handshake carries that server's own db path back
/// for comparison: if it holds a different one, that is the db the operation lands in and
/// `--root` picks only the fallback. Which is why every subcommand announces on stderr
/// which server or which db it reached, before doing anything to it.
fn open_accounts_ops(store: &StoreArgs) -> Result<(Box<dyn accounts_cli::AccountsOps>, String)> {
    let db_path = vk_registry::ServerConfig::accounts_db_of(
        store.config.as_deref(),
        store.root.clone(),
        store.accounts_db.clone(),
    )?;
    // Derived from the resolved db, so an `--accounts-db` is not honoured on one path and
    // dropped on the other. See the caveat above for a socket named outright.
    let socket = vk_registry::ServerConfig::admin_socket_of(
        store.config.as_deref(),
        &db_path,
        store.admin_socket.clone(),
    )?;
    let mut probed = None;
    if let Some(path) = &socket {
        match vk_registry::admin::Client::connect(path) {
            Ok(client) => {
                let origin = format!("the running server at {}", path.display());
                // On stderr, and on both paths: stdout carries the listing and
                // `create-key`'s token, and an operator has to be able to see which server
                // a grant landed in — especially when a named socket, not the store
                // selector, is what chose it.
                eprintln!("vk-registry accounts: through {origin}");
                return Ok((Box::new(client), origin));
            }
            // Nothing is listening: no server, or one configured with `admin_socket =
            // false`. The db is then this process's to open.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                probed = Some(path.clone());
            }
            // Named, because this is the one the socket's `0600` and its peer-uid check
            // produce, and the fix is a different user rather than a different path.
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(anyhow::Error::new(e).context(format!(
                    "connecting to the admin socket at {} — run as the user vk-registry \
                     runs as, or as root",
                    path.display()
                )));
            }
            // Anything else speaks for itself: a path too long for `sun_path`, a component
            // that is not a directory, a descriptor table that is full. Advising a uid
            // change for those would send an operator after the wrong thing.
            Err(e) => {
                return Err(anyhow::Error::new(e).context(format!(
                    "connecting to the admin socket at {}",
                    path.display()
                )));
            }
        }
    }
    // `probed` is `Some` for every socket that was dialled and did not answer, and every
    // other outcome returned above — so `None` here means there was no socket to dial.
    let db = open_accounts_db(&db_path).map_err(|e| match probed {
        // The db refused *and* nothing was listening: say where a server's socket was
        // looked for, since a server running without one is the case that lands here.
        Some(socket) => e.context(format!(
            "no admin socket answered at {}, so the db itself was tried",
            socket.display()
        )),
        // No socket resolved at all. `admin_socket_of` says `None` both for
        // `admin_socket = false` and for a config that is not accounts mode, and cannot
        // tell the caller which — so name both rather than advise removing a setting the
        // file may not contain.
        None => e.context(
            "no admin socket is configured for this store — `admin_socket = false`, or a \
             config that is not mode = \"accounts\" — so the db itself was tried",
        ),
    })?;
    let origin = format!("the accounts db at {}", db_path.display());
    eprintln!("vk-registry accounts: on {origin}");
    Ok((Box::new(db), origin))
}

/// The accounts db at `path` — the one a `StoreArgs` resolved to — opened only if it is
/// already there.
///
/// Never creates one: a mistyped `--root` would otherwise leave an empty db behind and
/// every subcommand would then report truthfully about the wrong file — "no users yet"
/// for a registry that has plenty. `serve` is what brings an accounts db into being.
fn open_accounts_db(path: &Path) -> Result<vk_registry::accounts::Db> {
    // Advisory only, and deliberately so: this resolves the path a second time, but it is
    // a usability guard (do not leave an empty db behind a mistyped `--root`), not a
    // security one. `Db::open` is the gate — it opens `O_NOFOLLOW` and judges the mode off
    // the descriptor, so a symlink or a file swapped in after this check is still refused.
    if !path.is_file() {
        anyhow::bail!(
            "no accounts db at {} — check --root/--config/--accounts-db, or start the \
             server once in mode = \"accounts\" to create it",
            path.display()
        );
    }
    vk_registry::accounts::Db::open(path)
}

/// This binary as `update` replaces it: the release asset `vk-registry` ships as, and
/// the version this build was made from.
const TOOL: Tool = Tool {
    name: "vk-registry",
    version: env!("CARGO_PKG_VERSION"),
};

/// Resolve an optional `--root` to a store directory, defaulting to the shared
/// virtkit store location.
fn resolve_root(root: Option<PathBuf>) -> Result<PathBuf> {
    root.map(Ok).unwrap_or_else(vk_registry::default_root)
}

#[tokio::main]
async fn main() -> ExitCode {
    // Install the rustls crypto backend both HTTPS clients here need — the relay's and
    // `update`'s (the workspace builds reqwest with rustls-no-provider), matching vk-driver.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    // `update` reads no store and owns its own exit codes, so it is handled before the
    // dispatch below rather than inside it.
    if let Cmd::Update {
        version,
        yes,
        check,
    } = &cli.cmd
    {
        return update(version.as_deref(), *yes, *check).await;
    }
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&e, 1),
    }
}

fn fail(e: &anyhow::Error, code: u8) -> ExitCode {
    eprintln!("vk-registry: {e:#}");
    ExitCode::from(code)
}

async fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Serve { addr, root, config } => {
            let cfg = match config {
                Some(path) => vk_registry::ServerConfig::load(&path, addr, root)?,
                None => vk_registry::ServerConfig::local(
                    addr.unwrap_or(vk_registry::DEFAULT_ADDR),
                    resolve_root(root)?,
                ),
            };
            vk_registry::serve_config(cfg).await
        }
        Cmd::InstallService {
            addr,
            root,
            config,
            system,
            service_user,
        } => {
            let facts = vk_registry::UnitFacts::resolve(config.as_deref(), addr, root)?;
            if !system {
                return vk_registry::install_service(&facts);
            }
            // The unit goes to stdout so it can be piped or reviewed; what to do with it
            // goes to stderr, so a pipe carries only the unit.
            let exe = std::env::current_exe().context("locating the vk-registry binary")?;
            print!("{}", vk_registry::system_unit(&facts, &service_user, &exe)?);
            let unit = vk_registry::SERVICE_UNIT;
            // `install -d` rather than `chown -R`: on a fresh host there is nothing to own
            // yet, and `ReadWritePaths=` on a path that does not exist fails the unit's
            // namespace setup rather than reporting a missing directory. No `--shell`, since
            // `nologin` is at a different place on each distribution and `--system` accounts
            // get a non-login one anyway.
            let store = facts.named_store().unwrap_or(Path::new("")).display();
            eprintln!("vk-registry: the account it runs as has to exist and own the store:");
            eprintln!("\n    sudo useradd --system --no-create-home {service_user}");
            eprintln!("    sudo install -d -o {service_user} -m 0750 {store}");
            eprintln!("\nvk-registry: then install the unit above as root:");
            eprintln!(
                "\n    vk-registry install-service --system{} | \\",
                match &config {
                    Some(c) => format!(" --config {}", c.display()),
                    None => format!(" --root {store}"),
                }
            );
            eprintln!("      sudo tee /etc/systemd/system/{unit}");
            eprintln!("    sudo systemctl daemon-reload && sudo systemctl enable --now {unit}");
            Ok(())
        }
        // `--root` first, then the root the `serve` config file names, then the shared
        // default: the same order `serve` resolves them in, so these report on and sweep
        // the store the server actually uses.
        Cmd::Status { root, config } => {
            let root = vk_registry::ServerConfig::root_of(config.as_deref(), root)?;
            vk_registry::status(root)
        }
        Cmd::Gc {
            root,
            config,
            retention_days,
            grace_days,
            dry_run,
        } => {
            let days = |d: u64| Duration::from_secs(d * 86_400);
            vk_registry::gc(
                vk_registry::ServerConfig::root_of(config.as_deref(), root)?,
                days(retention_days),
                days(grace_days),
                dry_run,
            )
        }
        // handled in `main`, before this dispatch
        Cmd::Update { .. } => unreachable!("update is handled in main"),
        Cmd::Accounts { cmd } => run_accounts(cmd),
    }
}

fn run_accounts(cmd: AccountsCmd) -> Result<()> {
    match cmd {
        AccountsCmd::ListUsers { store } => {
            let (ops, origin) = open_accounts_ops(&store)?;
            accounts_cli::list_users(ops.as_ref(), &origin)
        }
        AccountsCmd::GrantAdmin {
            email,
            issuer,
            store,
        } => {
            let (ops, _) = open_accounts_ops(&store)?;
            accounts_cli::set_admin(ops.as_ref(), &email, issuer.as_deref(), true)
        }
        AccountsCmd::RevokeAdmin {
            email,
            issuer,
            store,
        } => {
            let (ops, _) = open_accounts_ops(&store)?;
            accounts_cli::set_admin(ops.as_ref(), &email, issuer.as_deref(), false)
        }
        AccountsCmd::ListKeys {
            owner_email,
            issuer,
            store,
        } => {
            let (ops, _) = open_accounts_ops(&store)?;
            accounts_cli::list_keys(ops.as_ref(), owner_email.as_deref(), issuer.as_deref())
        }
        AccountsCmd::RevokeKey { id, store } => {
            let (ops, _) = open_accounts_ops(&store)?;
            accounts_cli::revoke_key(ops.as_ref(), &id)
        }
        AccountsCmd::CreateKey {
            owner_email,
            issuer,
            name,
            scopes,
            expires_days,
            store,
        } => {
            // Parsed and validated before the db is touched, so a mistyped --scope or
            // --name is a usage error rather than something that surfaces after a lock is
            // taken. `validate_key_input` is the whole of what the store will check, so
            // nothing is left to fail late.
            let scopes = scopes
                .iter()
                .map(|s| accounts_cli::parse_scope(s))
                .collect::<Result<Vec<_>>>()?;
            vk_registry::accounts::validate_key_input(&name, &scopes)?;
            let (ops, _) = open_accounts_ops(&store)?;
            accounts_cli::create_key(
                ops.as_ref(),
                owner_email.as_deref(),
                issuer.as_deref(),
                &name,
                &scopes,
                expires_days,
            )
        }
    }
}

/// `vk-registry update`: install a release build over this binary, or report what is
/// available with `--check`. Errors exit 2 throughout, leaving 1 to mean `--check` found
/// a newer release — so a script can branch on "an update is available" without reading
/// it as failure.
async fn update(version: Option<&str>, yes: bool, check: bool) -> ExitCode {
    if check {
        return match TOOL.check(version).await {
            Ok(false) => ExitCode::SUCCESS,
            Ok(true) => ExitCode::from(1),
            Err(e) => fail(&e, 2),
        };
    }
    match TOOL.update(version, yes).await {
        Ok(Outcome::Installed) => {
            restart_hint();
            ExitCode::SUCCESS
        }
        // Up to date or declined: nothing was written, so there is nothing to restart.
        // Named rather than caught, so a fourth outcome has to be decided here too.
        Ok(Outcome::AlreadyCurrent | Outcome::Declined) => ExitCode::SUCCESS,
        Err(e) => fail(&e, 2),
    }
}

/// What the probe below can come back with: the unit is serving, nothing is, or systemd
/// could not be asked at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Serving {
    Unit,
    Nothing,
    Unknown,
}

/// `systemctl --user is-active`'s verdict: 0 the unit is serving, 3 it is stopped, 4 there
/// is no such unit — the last two are answers, and both mean there is nothing to restart.
/// Anything else is not an answer: no systemd to ask, no `systemctl` to ask it with, or a
/// probe killed before it replied.
fn serving(asked: std::io::Result<std::process::ExitStatus>) -> Serving {
    match asked.map(|s| s.code()) {
        Ok(Some(0)) => Serving::Unit,
        Ok(Some(3 | 4)) => Serving::Nothing,
        _ => Serving::Unknown,
    }
}

/// Name the restart a running server needs. The install is a rename, so a `serve` already
/// under way holds the inode it started from and goes on answering from the old build —
/// which is the point (an update never interrupts a pull), but leaves the operator with a
/// step to take.
fn restart_hint() {
    let unit = vk_registry::SERVICE_UNIT;
    // A probe, so systemctl's own diagnostics stay out of an update's output: asked without
    // a user bus to reach — under `sudo`, from cron, inside a container — it reports failing
    // to connect on stderr.
    let ask = |scope: &str| {
        serving(
            std::process::Command::new("systemctl")
                .args([scope, "is-active", "--quiet", unit])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status(),
        )
    };
    // Both scopes, because both shapes exist: `install-service --system` installs the unit
    // machine-wide and the plain form installs it per-user, and the machine-wide one — the
    // server every runner depends on — is the one an update most has to name.
    let mut unanswered = false;
    for (scope, restart) in [
        ("--system", format!("sudo systemctl restart {unit}")),
        ("--user", format!("systemctl --user restart {unit}")),
    ] {
        match ask(scope) {
            // The unit runs the binary that installed it, which need not be the one just
            // replaced — so name the restart without promising it picks this build up.
            Serving::Unit => {
                println!(
                    "vk-registry: {unit} is still serving the build it started as — restart \
                     it if it runs this binary:"
                );
                println!("    {restart}");
                return;
            }
            Serving::Nothing => {}
            Serving::Unknown => unanswered = true,
        }
    }
    // Neither scope said a unit is serving, and at least one could not say anything at all —
    // a server may well be running where systemd could not be asked about it, so say what an
    // update needs without naming a unit that was never checked.
    if unanswered {
        println!(
            "vk-registry: a server already running keeps serving the previous build until it \
             is restarted"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `vk-registry update` CLI shape: the version is an optional positional (absent =
    // latest), `-y` is a flag rather than the version, and `--check` (which installs
    // nothing) cannot be combined with the flag that skips the install prompt.
    #[test]
    fn update_cli_takes_optional_version_and_yes() {
        let cli = Cli::try_parse_from(["vk-registry", "update"]).unwrap();
        let Cmd::Update {
            version,
            yes,
            check,
        } = cli.cmd
        else {
            panic!("expected Cmd::Update")
        };
        assert_eq!(version, None);
        assert!(!yes && !check);

        let cli = Cli::try_parse_from(["vk-registry", "update", "-y", "v0.33.0"]).unwrap();
        let Cmd::Update { version, yes, .. } = cli.cmd else {
            panic!("expected Cmd::Update")
        };
        assert_eq!(version.as_deref(), Some("v0.33.0"));
        assert!(yes);

        let cli = Cli::try_parse_from(["vk-registry", "update", "--check", "0.33.0"]).unwrap();
        let Cmd::Update { version, check, .. } = cli.cmd else {
            panic!("expected Cmd::Update")
        };
        assert_eq!(version.as_deref(), Some("0.33.0"));
        assert!(check);

        assert!(Cli::try_parse_from(["vk-registry", "update", "--check", "--yes"]).is_err());
    }

    // `install-service`'s two shapes: a config file replaces the flags it would otherwise
    // bake in, so asking for both is refused rather than one of them being dropped from a
    // unit that still claims to describe the other; and the account only a system unit has
    // cannot be named without asking for that shape.
    #[test]
    fn install_service_refuses_a_config_beside_the_flags_it_replaces() {
        let ok = |args: &[&str]| Cli::try_parse_from(args).is_ok();
        assert!(ok(&["vk-registry", "install-service"]));
        assert!(ok(&["vk-registry", "install-service", "--root", "/srv/s"]));
        assert!(ok(&[
            "vk-registry",
            "install-service",
            "--config",
            "/etc/r.toml"
        ]));
        assert!(ok(&[
            "vk-registry",
            "install-service",
            "--system",
            "--root",
            "/srv/s"
        ]));

        // a config file plus a flag it supersedes
        assert!(!ok(&[
            "vk-registry",
            "install-service",
            "--config",
            "/etc/r.toml",
            "--root",
            "/srv/s"
        ]));
        assert!(!ok(&[
            "vk-registry",
            "install-service",
            "--config",
            "/etc/r.toml",
            "--addr",
            "0.0.0.0:443"
        ]));
        // the service account is meaningless without --system, and a defaulted one does
        // not trip the requirement
        assert!(!ok(&[
            "vk-registry",
            "install-service",
            "--service-user",
            "svc"
        ]));
    }

    // The unit is named only for the one code that says it is serving. A probe that came
    // back with no answer at all must not be read as "nothing to restart": a server may be
    // running where systemd could not be asked about it.
    #[test]
    fn only_a_unit_that_answers_that_it_runs_is_named() {
        use std::os::unix::process::ExitStatusExt;
        // `from_raw` takes a wait status, where the exit code is the second byte.
        let exited = |code: i32| Ok(std::process::ExitStatus::from_raw(code << 8));
        assert_eq!(serving(exited(0)), Serving::Unit);
        // stopped, and no such unit: both answer that nothing is serving
        assert_eq!(serving(exited(3)), Serving::Nothing);
        assert_eq!(serving(exited(4)), Serving::Nothing);
        // no user bus to ask over, killed mid-probe, and no `systemctl` to run at all
        assert_eq!(serving(exited(1)), Serving::Unknown);
        assert_eq!(
            serving(Ok(std::process::ExitStatus::from_raw(libc::SIGKILL))),
            Serving::Unknown
        );
        assert_eq!(
            serving(Err(std::io::Error::from(std::io::ErrorKind::NotFound))),
            Serving::Unknown
        );
    }

    // `status`/`gc` take the same `--config` `serve` does: the store to report on is the
    // one the server was configured with, and naming that file is how they are told.
    /// The `accounts` subcommands' shape: a store selector on each, `--scope` required
    /// and repeatable, and `--accounts-db` refusing to sit beside the flags it replaces.
    #[test]
    fn accounts_subcommands_take_a_store_and_require_a_scope() {
        let parse = |args: &[&str]| Cli::try_parse_from(args);

        let cli = parse(&[
            "vk-registry",
            "accounts",
            "grant-admin",
            "a@b.c",
            "--root",
            "/srv/store",
        ])
        .expect("grant-admin takes an email and a store");
        match cli.cmd {
            Cmd::Accounts {
                cmd: AccountsCmd::GrantAdmin { email, store, .. },
            } => {
                assert_eq!(email, "a@b.c");
                assert_eq!(store.root.as_deref(), Some(Path::new("/srv/store")));
            }
            _ => panic!("expected accounts grant-admin"),
        }

        // `--issuer` narrows `--owner-email`; on its own it would read as a filter and
        // silently list every key, so clap refuses the combination outright
        assert!(
            parse(&[
                "vk-registry",
                "accounts",
                "list-keys",
                "--issuer",
                "https://idp",
                "--root",
                "/srv/store",
            ])
            .is_err(),
            "--issuer without --owner-email must be a usage error"
        );
        assert!(
            parse(&[
                "vk-registry",
                "accounts",
                "list-keys",
                "--owner-email",
                "a@b.c",
                "--issuer",
                "https://idp",
                "--root",
                "/srv/store",
            ])
            .is_ok(),
            "together they are the disambiguating pair"
        );

        // --scope is required, and repeats
        assert!(
            parse(&[
                "vk-registry",
                "accounts",
                "create-key",
                "--owner-email",
                "a@b.c",
                "--name",
                "ci"
            ])
            .is_err(),
            "create-key without --scope must not parse"
        );
        let cli = parse(&[
            "vk-registry",
            "accounts",
            "create-key",
            "--owner-email",
            "a@b.c",
            "--name",
            "ci",
            "--scope",
            "read:*",
            "--scope",
            "write:team-a/*",
        ])
        .expect("--scope repeats");
        match cli.cmd {
            Cmd::Accounts {
                cmd: AccountsCmd::CreateKey { scopes, .. },
            } => assert_eq!(scopes, vec!["read:*", "write:team-a/*"]),
            _ => panic!("expected accounts create-key"),
        }

        // --issuer narrows an email, so it means nothing without one
        assert!(
            parse(&[
                "vk-registry",
                "accounts",
                "create-key",
                "--issuer",
                "https://idp",
                "--name",
                "ci",
                "--scope",
                "read:*"
            ])
            .is_err(),
            "--issuer without --owner-email must be refused, not ignored"
        );
        assert!(
            parse(&[
                "vk-registry",
                "accounts",
                "list-keys",
                "--issuer",
                "https://idp"
            ])
            .is_err(),
            "--issuer without --owner-email must be refused, not ignored"
        );
        // an ownerless key is what create-key mints with no --owner-email
        let cli = parse(&[
            "vk-registry",
            "accounts",
            "create-key",
            "--name",
            "system-ci",
            "--scope",
            "read:*",
        ])
        .expect("--owner-email is optional");
        match cli.cmd {
            Cmd::Accounts {
                cmd: AccountsCmd::CreateKey { owner_email, .. },
            } => assert_eq!(owner_email, None),
            _ => panic!("expected accounts create-key"),
        }

        // and the db selector is not combined with the flags it supersedes
        assert!(
            parse(&[
                "vk-registry",
                "accounts",
                "list-users",
                "--accounts-db",
                "/srv/a.db",
                "--root",
                "/srv/store"
            ])
            .is_err(),
            "--accounts-db beside --root must be refused, not silently preferred"
        );

        // `--admin-socket` names where a *running* server is reached, so unlike
        // `--accounts-db` it complements the store selector rather than replacing it: the
        // db is still what the fallback opens.
        let cli = parse(&[
            "vk-registry",
            "accounts",
            "list-users",
            "--root",
            "/srv/store",
            "--admin-socket",
            "/run/vkr/admin.sock",
        ])
        .expect("--admin-socket sits beside a store selector");
        match cli.cmd {
            Cmd::Accounts {
                cmd: AccountsCmd::ListUsers { store },
            } => {
                assert_eq!(store.root.as_deref(), Some(Path::new("/srv/store")));
                assert_eq!(
                    store.admin_socket.as_deref(),
                    Some(Path::new("/run/vkr/admin.sock"))
                );
            }
            _ => panic!("expected accounts list-users"),
        }
    }

    #[test]
    fn status_and_gc_take_the_serve_config() {
        use std::path::Path;

        let cli = Cli::try_parse_from(["vk-registry", "status", "--config", "/etc/reg.toml"])
            .expect("status must accept --config");
        let Cmd::Status { root, config } = cli.cmd else {
            panic!("expected Cmd::Status")
        };
        assert_eq!(root, None);
        assert_eq!(config.as_deref(), Some(Path::new("/etc/reg.toml")));

        let cli = Cli::try_parse_from(["vk-registry", "gc", "--config", "/etc/reg.toml"])
            .expect("gc must accept --config");
        let Cmd::Gc { root, config, .. } = cli.cmd else {
            panic!("expected Cmd::Gc")
        };
        assert_eq!(root, None);
        assert_eq!(config.as_deref(), Some(Path::new("/etc/reg.toml")));
    }

    // `--addr`'s `[default: …]` is prose, not clap's own line: with no clap default there
    // is nothing keeping it in step with the address `serve` really falls back to.
    #[test]
    fn serve_addr_help_names_the_built_in_default() {
        let cmd = <Cli as clap::CommandFactory>::command();
        let help = cmd
            .find_subcommand("serve")
            .expect("serve must exist")
            .get_arguments()
            .find(|a| a.get_long() == Some("addr"))
            .expect("serve must take --addr")
            .get_help()
            .expect("--addr must carry help")
            .to_string();
        assert!(
            help.contains(&vk_registry::DEFAULT_ADDR.to_string()),
            "{help}"
        );
    }

    // `-h` is a summary: a short line per command, per flag and per possible value, with
    // the detail in the doc comment's second paragraph (which clap shows as `--help`). A
    // one-paragraph doc comment is both, so it lands in `-h` in full — this is what
    // catches that. It also catches the opposite slip, an entry with no help at all.
    // Short is not the same as one rendered line: clap appends `[default: …]` and
    // `[possible values: …]`, and lays wide groups out on a second line regardless.
    // Mirrors `vk-driver`'s test of the same name.
    #[test]
    fn help_summaries_stay_short() {
        // The same budget as `vk`'s copy of this test: an 80-column terminal plus a
        // little slack (the longest entry here is 81).
        const LIMIT: usize = 84;

        // Every `-h` entry of `cmd` and, recursively, of its subcommands: the command's
        // own about, each argument's help, and each possible value's help.
        fn collect(path: &str, cmd: &clap::Command, out: &mut Vec<(String, Option<usize>)>) {
            out.push((format!("{path} about"), summary_len(cmd.get_about())));
            for arg in cmd.get_arguments() {
                let name = match arg.get_long() {
                    Some(long) => format!("--{long}"),
                    None => format!("<{}>", arg.get_id()),
                };
                out.push((format!("{path} {name}"), summary_len(arg.get_help())));
                // A bool flag carries synthetic true/false values clap never prints;
                // only an arg that takes a value gets a `[possible values: …]` line.
                let is_bool_flag = matches!(
                    arg.get_action(),
                    clap::ArgAction::SetTrue | clap::ArgAction::SetFalse
                );
                if !is_bool_flag {
                    for value in arg.get_possible_values() {
                        let what = format!("{path} {name}={}", value.get_name());
                        out.push((what, summary_len(value.get_help())));
                    }
                }
            }
            for sub in cmd.get_subcommands() {
                collect(&format!("{path} {}", sub.get_name()), sub, out);
            }
        }
        fn summary_len(text: Option<&clap::builder::StyledStr>) -> Option<usize> {
            Some(text?.to_string().chars().count())
        }

        let mut entries = Vec::new();
        collect(
            "vk-registry",
            &<Cli as clap::CommandFactory>::command(),
            &mut entries,
        );
        let bad: Vec<_> = entries
            .into_iter()
            .filter_map(|(what, len)| match len {
                Some(len) if len > LIMIT => Some(format!("{what}: {len} chars")),
                None => Some(format!("{what}: no help")),
                Some(_) => None,
            })
            .collect();
        assert!(
            bad.is_empty(),
            "help entries over {LIMIT} chars or missing:\n  {}",
            bad.join("\n  ")
        );
    }

    /// A `StoreArgs` naming a store directory and nothing else — what every case below
    /// varies from.
    fn store_at(dir: &Path) -> StoreArgs {
        StoreArgs {
            root: Some(dir.to_path_buf()),
            config: None,
            accounts_db: None,
            admin_socket: None,
        }
    }

    /// The error of an `open_accounts_ops` that had to fail — the `Box<dyn AccountsOps>` in
    /// the `Ok` arm is not `Debug`, so `unwrap_err` cannot report it.
    fn err_of(r: Result<(Box<dyn accounts_cli::AccountsOps>, String)>) -> String {
        match r {
            Ok((_, origin)) => panic!("expected a failure, reached {origin}"),
            Err(e) => format!("{e:#}"),
        }
    }

    /// A store root with a real accounts db in it, at the path `StoreArgs` resolves.
    fn seeded_store(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("vk-registry-ops-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = vk_registry::config::default_accounts_db(&dir);
        // Opened and dropped: the file has to exist, and nothing may still hold it.
        drop(vk_registry::accounts::Db::open(&db).unwrap());
        dir
    }

    /// With no server running, the accounts are this process's to open — and the origin
    /// names the db, because a mistyped `--root` reports truthfully about the wrong file
    /// and the store named is what gives that away.
    #[test]
    fn ops_fall_back_to_the_db_when_nothing_answers() {
        let dir = seeded_store("fallback");
        let db_path = vk_registry::config::default_accounts_db(&dir);

        let (ops, origin) = open_accounts_ops(&store_at(&dir)).unwrap();
        assert_eq!(origin, format!("the accounts db at {}", db_path.display()));
        assert!(ops.list_users().unwrap().is_empty());
        drop(ops);

        // A socket file with nobody behind it — what a killed server leaves — is the same
        // case, not an error.
        let socket = vk_registry::config::default_admin_socket(&db_path);
        drop(vk_registry::admin::bind(&socket).unwrap());
        assert!(socket.exists(), "the file outlives the listener");
        let (ops, origin) = open_accounts_ops(&store_at(&dir)).unwrap();
        assert!(origin.contains("the accounts db at"), "{origin}");
        drop(ops);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With a server holding the db, the socket is what answers — the whole point, since
    /// the db cannot be opened at all while it is held.
    #[test]
    fn ops_reach_a_running_server_over_its_socket() {
        let dir = seeded_store("held");
        let db_path = vk_registry::config::default_accounts_db(&dir);
        let socket = vk_registry::config::default_admin_socket(&db_path);
        let db = std::sync::Arc::new(vk_registry::accounts::Db::open(&db_path).unwrap());
        db.upsert_user("https://issuer", "sub-1", Some("a@example.com"), None)
            .unwrap();
        let listener = vk_registry::admin::bind(&socket).unwrap();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(vk_registry::admin::serve_admin(listener, db));
        });

        let (ops, origin) = open_accounts_ops(&store_at(&dir)).unwrap();
        assert_eq!(
            origin,
            format!("the running server at {}", socket.display())
        );
        assert_eq!(ops.list_users().unwrap().len(), 1, "over the wire");
        drop(ops);

        // `--admin-socket` reaches the same one by name.
        let mut store = store_at(&dir);
        store.admin_socket = Some(socket.clone());
        let (ops, origin) = open_accounts_ops(&store).unwrap();
        assert_eq!(
            origin,
            format!("the running server at {}", socket.display())
        );
        drop(ops);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A socket that cannot be reached for a reason that is not "nobody is listening" is
    /// reported as itself, rather than as the uid advice that only fits `PermissionDenied`
    /// — a path over `sun_path` used to send an operator after `sudo`.
    #[test]
    fn a_socket_that_cannot_be_dialled_is_not_reported_as_a_uid_problem() {
        let dir = seeded_store("badsock");
        let mut store = store_at(&dir);
        store.admin_socket = Some(dir.join("s".repeat(200)));

        let err = err_of(open_accounts_ops(&store));
        assert!(err.contains("connecting to the admin socket at"), "{err}");
        assert!(!err.contains("as root"), "the wrong advice: {err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Neither path available: the error has to name both, since "stop the server" and
    /// "check --root" are opposite fixes and only the pair says which.
    #[test]
    fn a_missing_db_and_a_missing_socket_name_both() {
        let dir = std::env::temp_dir().join(format!("vk-registry-ops-none-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let err = err_of(open_accounts_ops(&store_at(&dir)));
        assert!(err.contains("no admin socket answered at"), "{err}");
        assert!(err.contains("no accounts db at"), "{err}");
    }

    /// A config that resolves no socket at all: the db is tried, and the failure says the
    /// socket was never in play without claiming which of the two reasons it was — the
    /// resolution cannot tell them apart, and advising the removal of a key the file does
    /// not contain would send an operator after nothing.
    #[test]
    fn no_socket_configured_is_said_without_guessing_why() {
        let dir = std::env::temp_dir().join(format!("vk-registry-ops-off-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let write = |name: &str, body: String| {
            let p = dir.join(name);
            std::fs::write(&p, body).unwrap();
            p
        };
        let root = dir.join("store");
        for (name, body) in [
            (
                "off.toml",
                format!("mode = \"accounts\"\nadmin_socket = false\nroot = {root:?}\n"),
            ),
            // Not accounts mode, and saying nothing about the socket at all.
            (
                "shared.toml",
                format!("password_file = \"/etc/vkr.pw\"\nroot = {root:?}\n"),
            ),
        ] {
            let cfg = write(name, body);
            let store = StoreArgs {
                root: None,
                config: Some(cfg),
                accounts_db: None,
                admin_socket: None,
            };
            let err = err_of(open_accounts_ops(&store));
            assert!(
                err.contains("no admin socket is configured"),
                "{name}: {err}"
            );
            assert!(err.contains("no accounts db at"), "{name}: {err}");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
