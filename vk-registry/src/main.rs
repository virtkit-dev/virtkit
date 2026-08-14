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
use std::path::PathBuf;
use std::process::{ExitCode, Stdio};
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use vk_selfupdate::{Outcome, Tool};

// Match vk-driver: jemalloc under musl (the glibc allocator fragments on the
// long-lived, many-small-allocation server workload).
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[derive(Parser)]
#[command(
    name = "vk-registry",
    version,
    about = "Central OCI-distribution server: build-once dedup, pull-through relay, and a build lock"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve the registry over HTTP, backed by a content-addressed store. With no
    /// upstreams configured it is a plain local OCI server; configure `[[upstream]]`
    /// in the config file to make it a pull-through mirror.
    Serve {
        /// Listen address.
        #[arg(long, default_value = "127.0.0.1:5000")]
        addr: SocketAddr,
        /// Store directory [default: the `root` in --config, else
        /// $XDG_DATA_HOME/virtkit/registry].
        #[arg(long)]
        root: Option<PathBuf>,
        /// TOML config file with `[[upstream]]` relay entries (and optional addr/root).
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Install + start a `systemd --user` unit running `serve`, so the store is
    /// always available (survives logout/reboot).
    InstallService {
        #[arg(long, default_value = "127.0.0.1:5000")]
        addr: SocketAddr,
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Report the store's usage and content: on-disk size, dedup savings, and a
    /// per-repository breakdown. Read-only — it creates no store.
    Status {
        /// Store directory [default: the `root` in --config, else
        /// $XDG_DATA_HOME/virtkit/registry].
        #[arg(long)]
        root: Option<PathBuf>,
        /// The `serve` config file to take the store root from, so this reports on the
        /// store the server uses.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Garbage-collect the store: drop tags idle past the retention window, then
    /// sweep unreferenced blobs and stale uploads (both after a grace window).
    Gc {
        /// Store directory [default: the `root` in --config, else
        /// $XDG_DATA_HOME/virtkit/registry].
        #[arg(long)]
        root: Option<PathBuf>,
        /// The `serve` config file to take the store root from, so this sweeps the store
        /// the server uses.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Drop tags unused for more than this many days.
        #[arg(long, default_value_t = 30)]
        retention_days: u64,
        /// Keep unreferenced blobs and stale uploads this many days past their
        /// last use (protects in-flight multi-request pushes).
        #[arg(long, default_value_t = 1)]
        grace_days: u64,
        /// Report what would be removed without removing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Replace this `vk-registry` with a GitHub release build — the latest release, or
    /// the VERSION given. Prints what it is about to install and asks before touching
    /// anything; the download is checked against the digest published beside it and must
    /// report its own version before it replaces the running binary. Needs write access
    /// to the directory `vk-registry` is installed in. A server already running keeps
    /// serving the build it started as, so restart its unit to pick this one up.
    /// `--check` only reports what is available, downloading nothing. Exit: 0 up to date,
    /// installed, or declined at the prompt; 1 a newer release is available (`--check`);
    /// 2 the update or check itself failed.
    Update {
        /// release to install, `0.33.0` or `v0.33.0` (default: the latest release).
        /// An older version downgrades, which `--check` does not report as an update
        /// available.
        version: Option<String>,
        /// skip the confirmation prompt (for unattended use)
        #[arg(short = 'y', long, conflicts_with = "check")]
        yes: bool,
        /// report whether a newer release is available and exit — download nothing,
        /// install nothing (exit 1 when there is one)
        #[arg(long)]
        check: bool,
    },
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
                None => vk_registry::ServerConfig::local(addr, resolve_root(root)?),
            };
            vk_registry::serve_config(cfg).await
        }
        Cmd::InstallService { addr, root } => {
            vk_registry::install_service(addr, &resolve_root(root)?)
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
    let asked = std::process::Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", unit])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match serving(asked) {
        // The unit runs the binary that installed it, which need not be the one just
        // replaced — so name the restart without promising it picks this build up.
        Serving::Unit => {
            println!(
                "vk-registry: {unit} is still serving the build it started as — restart it \
                 if it runs this binary:"
            );
            println!("    systemctl --user restart {unit}");
        }
        Serving::Nothing => {}
        // Nothing was answered, and a server may well be running under something else, so
        // say what an update needs without naming a unit that was never checked.
        Serving::Unknown => println!(
            "vk-registry: a server already running keeps serving the previous build until it \
             is restarted"
        ),
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
}
