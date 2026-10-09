//! `vk-gitlab`: run the configured GitLab runners, or check their tokens.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use log::LevelFilter;
use tokio::signal::unix::{SignalKind, signal};

use vk_gitlab::config::Config;
use vk_gitlab::dispatch::NoCapacity;
use vk_gitlab::poll::{self, RunOptions, ShutdownHandle};
use vk_gitlab::{logging, system_id};

#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[derive(Parser)]
#[command(
    name = "vk-gitlab",
    version,
    about = "A GitLab runner that hands jobs to a vk fleet"
)]
struct Cli {
    /// error, warn, info, debug or trace; trace also shows the HTTP and TLS stacks' own
    /// records.
    #[arg(long, global = true, default_value = "info")]
    log_level: LevelFilter,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Request jobs for every configured runner and hand them to the dispatcher.
    Run {
        #[arg(long, short, default_value = "/etc/vk-gitlab/config.toml")]
        config: PathBuf,
    },
    /// Check every configured runner's token against GitLab.
    Verify {
        #[arg(long, short, default_value = "/etc/vk-gitlab/config.toml")]
        config: PathBuf,
    },
}

fn system_id_for(cfg: &Config) -> Result<String> {
    if let Some(id) = &cfg.system_id {
        if !system_id::is_valid(id) {
            anyhow::bail!("system_id {id:?} is not s_ or r_ followed by 12 alphanumerics");
        }
        return Ok(id.clone());
    }
    let path = cfg.system_id_file.as_deref().context("no system_id_file")?;
    system_id::load_or_create(path)
}

async fn verify(config: PathBuf) -> Result<bool> {
    let cfg = Config::load(&config)?;
    let system_id = system_id_for(&cfg)?;
    let mut all_ok = true;
    for r in &cfg.runners {
        let info = poll::runner_info();
        let client = poll::client_for(r, &system_id, info, Default::default())?;
        match client.verify().await {
            Ok(Some(_)) => println!("{}: valid", r.name),
            Ok(None) => {
                all_ok = false;
                println!("{}: token refused by GitLab", r.name);
            }
            Err(e) => {
                all_ok = false;
                println!("{}: {e}", r.name);
            }
        }
    }
    Ok(all_ok)
}

async fn run(config: PathBuf) -> Result<()> {
    let cfg = Config::load(&config)?;
    if cfg.runners.is_empty() {
        anyhow::bail!("{}: no [[runners]] configured", config.display());
    }
    let system_id = system_id_for(&cfg)?;
    log::info!(system_id = system_id.as_str(), runners = cfg.runners.len(), concurrent = cfg.concurrent; "Starting vk-gitlab");
    log::warn!(
        "No hub dispatcher is available yet: runners report no capacity and request no jobs"
    );
    let (handle, shutdown) = ShutdownHandle::new();
    let shutdown_timeout = cfg.shutdown_timeout();
    let mut term = signal(SignalKind::terminate()).context("installing the SIGTERM handler")?;
    let mut int = signal(SignalKind::interrupt()).context("installing the SIGINT handler")?;
    let signals = tokio::spawn(async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
        log::warn!(timeout_s = shutdown_timeout.as_secs(); "Stopping: no new jobs; running jobs get the shutdown timeout to finish");
        handle.stop();
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
            () = tokio::time::sleep(shutdown_timeout) => {}
        }
        log::warn!("Aborting running jobs");
        handle.abort();
        // Keep the handle: the abort must stay visible to jobs still reporting.
        std::future::pending::<()>().await;
    });
    let result = poll::run(
        &cfg,
        &system_id,
        Arc::new(NoCapacity),
        RunOptions::default(),
        shutdown,
    )
    .await;
    signals.abort();
    result
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    logging::init(cli.log_level);
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            log::error!(error = e.to_string().as_str(); "Starting the async runtime failed");
            return ExitCode::FAILURE;
        }
    };
    let result = rt.block_on(async {
        match cli.command {
            Command::Run { config } => run(config).await.map(|()| true),
            Command::Verify { config } => verify(config).await,
        }
    });
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            log::error!(error = format!("{e:#}").as_str(); "vk-gitlab failed");
            ExitCode::FAILURE
        }
    }
}
