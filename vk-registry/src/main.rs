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
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};

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
        /// Store directory [default: $XDG_DATA_HOME/virtkit/registry].
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
    /// per-repository breakdown. Read-only.
    Status {
        /// Store directory [default: $XDG_DATA_HOME/virtkit/registry].
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Garbage-collect the store: drop tags idle past the retention window, then
    /// sweep unreferenced blobs and stale uploads (both after a grace window).
    Gc {
        /// Store directory [default: $XDG_DATA_HOME/virtkit/registry].
        #[arg(long)]
        root: Option<PathBuf>,
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
}

/// Resolve an optional `--root` to a store directory, defaulting to the shared
/// virtkit store location.
fn resolve_root(root: Option<PathBuf>) -> Result<PathBuf> {
    root.map(Ok).unwrap_or_else(vk_registry::default_root)
}

#[tokio::main]
async fn main() -> ExitCode {
    // Install the rustls crypto backend for the relay's HTTPS client (the workspace
    // builds reqwest with rustls-no-provider), matching vk-driver.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vk-registry: {e:#}");
            ExitCode::FAILURE
        }
    }
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
        Cmd::Status { root } => vk_registry::status(resolve_root(root)?),
        Cmd::Gc {
            root,
            retention_days,
            grace_days,
            dry_run,
        } => {
            let days = |d: u64| Duration::from_secs(d * 86_400);
            vk_registry::gc(
                resolve_root(root)?,
                days(retention_days),
                days(grace_days),
                dry_run,
            )
        }
    }
}
