//! `vk-hub` — a web UI for vk's VMs. `vk-hub local` serves it for the machine it runs on, as
//! the user who owns the VMs, on a loopback name of its own.
//!
//! Experimental. People sign in with single-use links the hub prints, or issues over a unix
//! socket only its own user reaches; what they do is recorded in an audit log.

use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};

mod admin;
mod local;
mod server;
mod store;
mod ui;
mod workloads;

// Match vk-registry: jemalloc under musl for a long-lived server.
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

/// Web UI for vk's VMs (experimental)
#[derive(Parser)]
#[command(name = "vk-hub", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
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
            ui_cmd(admin_client(&state_dir.join(local::ADMIN_SOCKET))?, cmd).await
        }
    }
}

/// `vk-hub local login|sessions|logout`, over the running hub's admin socket.
async fn ui_cmd(client: admin::Client, cmd: LocalCmd) -> Result<()> {
    match cmd {
        LocalCmd::Login { role, ttl } => {
            let link = tokio::task::spawn_blocking(move || client.ui_login(role, ttl)).await??;
            // The link alone on stdout, so `$(vk-hub local login)` captures just it.
            println!("{}", link.url);
            eprintln!(
                "vk-hub: single-use, valid for {}, signs a browser in as {}",
                human_duration(ttl),
                role.name()
            );
        }
        LocalCmd::Sessions => {
            let sessions = tokio::task::spawn_blocking(move || client.ui_sessions()).await??;
            print!("{}", render_sessions(&sessions));
        }
        LocalCmd::Logout { id, all } => {
            let id = if all { None } else { id };
            let ended =
                tokio::task::spawn_blocking(move || client.ui_logout(id.as_deref())).await??;
            eprintln!("vk-hub: ended {ended} session(s)");
        }
    }
    Ok(())
}

fn render_sessions(sessions: &[store::UiSession]) -> String {
    if sessions.is_empty() {
        return "no open sessions\n".to_string();
    }
    let mut out = format!(
        "{:<14} {:<9} {:<21} {:<21} ISSUED BY\n",
        "ID", "ROLE", "SINCE", "UNTIL"
    );
    for s in sessions {
        out.push_str(&format!(
            "{:<14} {:<9} {:<21} {:<21} {}\n",
            s.id,
            s.role.name(),
            utc(s.created_at),
            utc(s.expires_at),
            s.issued_by
        ));
    }
    out
}

/// The running hub's admin socket, with a pointer at the likely cause when nothing answers.
fn admin_client(path: &Path) -> Result<admin::Client> {
    admin::Client::connect(path).map_err(|e| {
        let hint = match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                " — is `vk-hub local` running?"
            }
            std::io::ErrorKind::PermissionDenied => " — run as the user vk-hub runs as, or root",
            _ => "",
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
    if ttl.is_zero() || ttl > store::MAX_LOGIN_TTL {
        return Err(format!("{s:?}: a sign-in link lives between 1s and 24h"));
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
mod tests {
    use super::*;

    #[test]
    fn times_read_as_people_write_them() {
        assert_eq!(utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc(1_800_000_000), "2027-01-15T08:00:00Z");
        assert_eq!(human_duration(Duration::from_secs(7200)), "2h");
        assert_eq!(human_duration(Duration::from_secs(90)), "90s");
    }

    #[test]
    fn a_link_lives_at_most_a_day() {
        assert_eq!(parse_ttl("10m"), Ok(Duration::from_secs(600)));
        assert!(parse_ttl("25h").is_err());
        assert!(parse_ttl("0s").is_err());
        assert!(parse_ttl("10").is_err());
        assert!(parse_ttl("").is_err());
        assert!(parse_ttl("5é").is_err());
        assert!(parse_ttl("é").is_err());
    }

    #[test]
    fn random_bytes_are_as_many_as_asked() {
        assert!(random_bytes(0).unwrap().is_empty());
        let (a, b) = (random_bytes(300).unwrap(), random_bytes(300).unwrap());
        assert_eq!(a.len(), 300);
        assert_ne!(a, b);
    }
}
