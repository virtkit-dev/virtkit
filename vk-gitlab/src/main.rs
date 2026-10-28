//! `vk-gitlab`: run the configured GitLab runners, or check their tokens.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use log::LevelFilter;
use tokio::signal::unix::{SignalKind, signal};

use vk_gitlab::config::Config;
use vk_gitlab::hub::{HubClient, HubOptions};
use vk_gitlab::poll::{self, RunOptions, ShutdownHandle};
use vk_gitlab::{logging, relay, session, system_id};

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
    /// Enroll this relay with a vk-hub, which then runs its jobs
    ///
    /// Generates the relay's key under <state_dir>/hub/ and enrolls it with a single-use token
    /// from `vk-hub token create --kind gitlab`. Refused while a runner's state file holds a
    /// job. `vk-gitlab leave` undoes it.
    Join {
        /// The hub's URL: https, or http to a hub on loopback
        hub: String,
        /// The token; prefer --token - (read on stdin) or --token-file
        #[arg(long, conflicts_with = "token_file")]
        token: Option<String>,
        /// A file holding the token
        #[arg(long, value_name = "FILE")]
        token_file: Option<PathBuf>,
        /// Verify the hub against this CA bundle alone, not the system's roots
        #[arg(long, value_name = "FILE")]
        ca: Option<PathBuf>,
        /// Enroll again, as a new relay, though this one is enrolled
        #[arg(long)]
        replace: bool,
        #[arg(long, short, default_value = "/etc/vk-gitlab/config.toml")]
        config: PathBuf,
    },
    /// Forget the hub this relay is enrolled with
    ///
    /// Deletes <state_dir>/hub/; refused while a runner's state file holds a job. The hub
    /// keeps the relay, disconnected, until `vk-hub relays remove`.
    Leave {
        #[arg(long, short, default_value = "/etc/vk-gitlab/config.toml")]
        config: PathBuf,
    },
}

fn state_dir(cfg: &Config) -> PathBuf {
    cfg.state_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(vk_gitlab::config::DEFAULT_STATE_DIR))
}

async fn join(
    config: PathBuf,
    hub: String,
    token: vk_peer::net::TokenSource,
    ca: Option<PathBuf>,
    replace: bool,
) -> Result<()> {
    let cfg = Config::load(&config)?;
    let state_dir = state_dir(&cfg);
    let id = relay::join(&state_dir, &hub, &token, ca.as_deref(), replace).await?;
    println!("{id}");
    log::info!(relay = id.as_str(), state_dir = state_dir.display().to_string().as_str(); "Enrolled with the hub; `vk-gitlab run` takes jobs once an operator has approved its GitLab server there");
    Ok(())
}

fn leave(config: PathBuf) -> Result<()> {
    let cfg = Config::load(&config)?;
    let state_dir = state_dir(&cfg);
    if relay::leave(&state_dir)? {
        log::info!("Left the hub; `vk-hub relays remove` the relay there");
    } else {
        log::info!(state_dir = state_dir.display().to_string().as_str(); "Not enrolled with a hub");
    }
    Ok(())
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
        let client = poll::client_for(cfg.gitlab_url(), r, &system_id, info, Default::default())?;
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
    // Held until the daemon exits: no join or leave meanwhile.
    let _lock = relay::lock(&state_dir(&cfg))?;
    let relay = Arc::new(relay::open(&state_dir(&cfg))?);
    log::info!(hub = relay.enrollment.hub.as_str(), relay = relay.enrollment.relay_id.as_str(); "Relaying jobs to the hub");
    let status = session::Status::new(&cfg, &system_id, &relay::hostname());
    // Report held work in the first heartbeat, before a session can grant new work.
    let prepared = poll::prepare_state(&cfg, &relay.enrollment.relay_id, Arc::clone(&status))?;
    let session = tokio::spawn(session::hold(Arc::clone(&relay), Arc::clone(&status)));
    let dispatcher = Arc::new(HubClient::new(HubOptions {
        hub: relay.enrollment.hub.clone(),
        tls: Arc::clone(&relay.tls),
        relay_id: relay.enrollment.relay_id.clone(),
        identity: Arc::clone(&relay.identity),
        retry: Default::default(),
    }));
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
        log::warn!("Aborting running jobs; a third signal exits at once");
        handle.abort();
        // The handle stays alive meanwhile: the abort must stay visible to jobs still
        // reporting.
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
        log::error!("Exiting now; the jobs still in the state files resume on the next start");
        std::process::exit(1);
    });
    let result = poll::run(
        &cfg,
        &system_id,
        &relay.enrollment,
        prepared,
        dispatcher,
        RunOptions::default(),
        shutdown,
    )
    .await;
    session.abort();
    signals.abort();
    result
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    logging::init(cli.log_level);
    // reqwest is built without a crypto provider; ring is the one this binary links.
    let _ = rustls::crypto::ring::default_provider().install_default();
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
            Command::Join {
                hub,
                token,
                token_file,
                ca,
                replace,
                config,
            } => {
                let token = match (token, token_file) {
                    (Some(t), _) if t == "-" => vk_peer::net::TokenSource::Stdin,
                    (Some(t), _) => vk_peer::net::TokenSource::Literal(t),
                    (None, Some(f)) => vk_peer::net::TokenSource::File(f),
                    (None, None) => Err(anyhow::anyhow!(
                        "pass the token: --token - to read it on stdin, or --token-file"
                    ))?,
                };
                join(config, hub, token, ca, replace).await.map(|()| true)
            }
            Command::Leave { config } => leave(config).map(|()| true),
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
