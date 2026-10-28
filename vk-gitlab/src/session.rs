//! The relay's session with its hub: dial `/v1/gitlab/session`, the handshake every peer
//! shares, then its inventory, heartbeats and reports one way and its GitLab server's status
//! the other, until the connection is lost — and dial again, backing off, unless the hub
//! refused the relay for good.
//!
//! [`Status`] is what the poll loop and the session share: the server's status the hub last
//! sent, which the loop waits on before it asks GitLab for a job, and what each runner is
//! doing, which the session reports. The status outlives a lost session: a relay whose server
//! is approved goes on polling while it redials, and one the hub never approved, or no longer
//! knows, does not poll at all.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use futures::StreamExt;
use tokio::sync::{Notify, watch};
use tokio_tungstenite::tungstenite::Message;
use vk_hub_proto::RefusalCode;
use vk_hub_proto::gitlab::{
    Heartbeat, HubRelayMsg, Inventory, RelayMsg, Report, Runner, RunnerLoad, RunnerReport,
    RunnerState, Server, ServerState, ServerStatus,
};
use vk_peer::session::{Permanent, Superseded, Ws};

use crate::config::Config;
use crate::relay::Relay;

/// How long each step of a connection may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Redial delays: from the first to the longest, doubled in between.
const BACKOFF: (Duration, Duration) = (Duration::from_secs(1), Duration::from_secs(60));

/// A session that lasted this long starts the backoff over.
const STABLE_SESSION: Duration = Duration::from_secs(60);

/// One runner as the relay reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunnerStatus {
    /// Its name, placement and limit, from the config.
    pub runner: Runner,
    pub state: RunnerState,
    pub message: Option<String>,
    /// Job requests to GitLab outstanding, and jobs held.
    pub requests: u32,
    pub jobs: u32,
    /// When GitLab last answered it, and with what status.
    pub last_answer: Option<(u64, u16)>,
}

/// What the poll loop and the session share.
pub struct Status {
    /// What `vk-gitlab` is, but its runners.
    inventory: Inventory,
    server: watch::Sender<Option<ServerStatus>>,
    runners: Mutex<Vec<RunnerStatus>>,
    /// The digest of the GitLab server's key, once a runner reached it over TLS.
    spki: Mutex<Option<String>>,
    /// Woken when the inventory or the report may have changed.
    changed: Notify,
}

impl std::fmt::Debug for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Status")
            .field("server", &*self.server.borrow())
            .finish_non_exhaustive()
    }
}

impl Status {
    /// The status of the relay `cfg` configures, its server's not known yet.
    pub fn new(cfg: &Config, system_id: &str, hostname: &str) -> Arc<Self> {
        let runners = cfg
            .runners
            .iter()
            .map(|r| RunnerStatus {
                runner: Runner {
                    name: r.name.clone(),
                    runner_id: None,
                    placement: r.placement(),
                    limit: (r.limit > 0).then(|| u32::try_from(r.limit).unwrap_or(u32::MAX)),
                    request_concurrency: u32::try_from(r.request_concurrency()).unwrap_or(u32::MAX),
                    verified: false,
                },
                state: RunnerState::ServerPending,
                message: None,
                requests: 0,
                jobs: 0,
                last_answer: None,
            })
            .collect();
        Arc::new(Self {
            inventory: Inventory {
                version: env!("CARGO_PKG_VERSION").to_owned(),
                hostname: hostname.to_owned(),
                system_id: system_id.to_owned(),
                concurrent: u32::try_from(cfg.concurrent).unwrap_or(u32::MAX),
                server: Server {
                    // Without credentials, query or fragment, which the config refuses.
                    url: cfg.gitlab_url().trim_end_matches('/').to_owned(),
                    spki_sha256: None,
                    version: None,
                },
                runners: Vec::new(),
            },
            server: watch::channel(None).0,
            runners: Mutex::new(runners),
            spki: Mutex::new(None),
            changed: Notify::new(),
        })
    }

    /// The status the hub last sent of the relay's server.
    pub fn server(&self) -> Option<ServerStatus> {
        self.server.borrow().clone()
    }

    /// Whether the relay may poll its server.
    pub fn approved(&self) -> bool {
        self.server
            .borrow()
            .as_ref()
            .is_some_and(|s| s.state.approved())
    }

    /// Record the server's status the hub sent, or forget it.
    pub fn set_server(&self, status: Option<ServerStatus>) {
        self.server.send_if_modified(|s| {
            let changed = *s != status;
            *s = status;
            changed
        });
    }

    /// Wait until the server is approved.
    pub async fn wait_approved(&self) {
        let mut rx = self.server.subscribe();
        // Only an error once the sender, which `self` holds, is gone.
        let _ = rx
            .wait_for(|s| s.as_ref().is_some_and(|s| s.state.approved()))
            .await;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<RunnerStatus>> {
        self.runners.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Change runner `name`'s status with `f`.
    pub fn runner(&self, name: &str, f: impl FnOnce(&mut RunnerStatus)) {
        let mut runners = self.lock();
        if let Some(r) = runners.iter_mut().find(|r| r.runner.name == name) {
            let before = (r.runner.clone(), r.state, r.message.clone());
            f(r);
            if before != (r.runner.clone(), r.state, r.message.clone()) {
                self.changed.notify_one();
            }
        }
    }

    /// Runner `name`'s status.
    pub fn runner_status(&self, name: &str) -> Option<RunnerStatus> {
        self.lock().iter().find(|r| r.runner.name == name).cloned()
    }

    /// The digest of the GitLab server's key, once a runner reached it over TLS.
    pub fn set_spki(&self, spki: Option<String>) {
        if spki.is_none() {
            return;
        }
        let mut slot = self.spki.lock().unwrap_or_else(|e| e.into_inner());
        if *slot != spki {
            *slot = spki;
            self.changed.notify_one();
        }
    }

    /// What the relay is, now.
    pub fn inventory(&self) -> Inventory {
        let mut inventory = self.inventory.clone();
        inventory.server.spki_sha256 = self.spki.lock().unwrap_or_else(|e| e.into_inner()).clone();
        inventory.runners = self.lock().iter().map(|r| r.runner.clone()).collect();
        inventory
    }

    /// What each runner is doing.
    pub fn report(&self) -> Report {
        Report {
            runners: self
                .lock()
                .iter()
                .map(|r| RunnerReport {
                    name: r.runner.name.clone(),
                    state: r.state,
                    message: r.message.clone(),
                })
                .collect(),
        }
    }

    /// Each runner's load.
    pub fn heartbeat(&self) -> Heartbeat {
        Heartbeat {
            runners: self
                .lock()
                .iter()
                .map(|r| RunnerLoad {
                    name: r.runner.name.clone(),
                    requests: r.requests,
                    jobs: r.jobs,
                    request_admissions: vec![],
                    job_admissions: vec![],
                    last_answer_at: r.last_answer.map(|(at, _)| at),
                    last_status: r.last_answer.map(|(_, status)| status),
                })
                .collect(),
        }
    }
}

/// Keep a session with the hub for as long as `run` runs.
pub async fn hold(relay: Arc<Relay>, status: Arc<Status>) {
    let mut incarnation = [0u8; vk_hub_proto::ID_BYTES];
    if let Err(e) = vk_peer::fill_random(&mut incarnation) {
        log::error!(error = format!("{e:#}").as_str(); "No session with the hub");
        return;
    }
    let incarnation = vk_hub_proto::to_hex(&incarnation);
    let mut backoff = BACKOFF.0;
    loop {
        let started = tokio::time::Instant::now();
        match run(&relay, &status, &incarnation).await {
            Ok(()) => {}
            Err(e) if e.is::<Permanent>() => {
                // The hub no longer knows this relay: its jobs would be refused.
                status.set_server(None);
                log::error!(error = format!("{e:#}").as_str(); "The hub refused this relay; no longer taking jobs from GitLab");
                return;
            }
            Err(e) => {
                log::warn!(error = format!("{e:#}").as_str(); "Session with the hub lost; dialing again")
            }
        }
        if started.elapsed() >= STABLE_SESSION {
            backoff = BACKOFF.0;
        }
        tokio::time::sleep(vk_peer::jittered(backoff)).await;
        backoff = (backoff * 2).min(BACKOFF.1);
    }
}

/// A refusal from the hub as an error: [`Permanent`] when its code says so.
fn refusal(code: RefusalCode, reason: &str) -> anyhow::Error {
    let mut message = format!(
        "the hub refused the session: {}",
        vk_hub_proto::display_safe(reason)
    );
    if matches!(code, RefusalCode::NotEnrolled | RefusalCode::Revoked) {
        message.push_str(
            " — the hub does not know this relay any more: drain it, then `vk-gitlab leave` and \
             enroll it again with `vk-gitlab join`",
        );
    }
    if code.is_permanent() {
        anyhow::Error::new(Permanent(message))
    } else if code == RefusalCode::Superseded {
        anyhow::Error::new(Superseded(message))
    } else {
        anyhow!(message)
    }
}

/// One session, from dial to its end.
async fn run(relay: &Relay, status: &Status, incarnation: &str) -> Result<()> {
    let hub = &relay.enrollment.hub;
    let (mut ws, exported) = tokio::time::timeout(
        CONNECT_TIMEOUT,
        vk_peer::session::connect(hub, &relay.tls, vk_hub_proto::gitlab::SESSION_PATH),
    )
    .await
    .map_err(|_| anyhow!("connecting to {hub} timed out"))??;
    let hello = vk_peer::session::Hello {
        versions: vk_hub_proto::gitlab::PROTOCOL,
        id: &relay.enrollment.relay_id,
        identity: &relay.identity,
        incarnation,
        version: env!("CARGO_PKG_VERSION"),
    };
    let (heartbeat_secs, _version) =
        vk_peer::session::handshake(&mut ws, &hello, exported.as_ref(), CONNECT_TIMEOUT, refusal)
            .await?;
    log::info!(hub = hub.as_str(), relay = relay.enrollment.relay_id.as_str(); "In session with the hub");
    let beat = Duration::from_secs(u64::from(heartbeat_secs.clamp(1, 300)));
    let quiet = beat * 3;
    let mut sent_inventory = status.inventory();
    send(&mut ws, &RelayMsg::Inventory(sent_inventory.clone()), beat).await?;
    let mut sent_report = status.report();
    send(&mut ws, &RelayMsg::Report(sent_report.clone()), beat).await?;
    let mut heartbeat = tokio::time::interval(beat);
    let mut deadline = tokio::time::Instant::now() + quiet;
    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                send(&mut ws, &RelayMsg::Heartbeat(status.heartbeat()), beat).await?;
            }
            () = status.changed.notified() => {
                let inventory = status.inventory();
                if inventory != sent_inventory {
                    send(&mut ws, &RelayMsg::Inventory(inventory.clone()), beat).await?;
                    sent_inventory = inventory;
                }
                let report = status.report();
                if report != sent_report {
                    send(&mut ws, &RelayMsg::Report(report.clone()), beat).await?;
                    sent_report = report;
                }
            }
            () = tokio::time::sleep_until(deadline) => {
                bail!("nothing heard from the hub for {}s", quiet.as_secs());
            }
            frame = ws.next() => {
                let text = match frame {
                    None => bail!("the hub closed the connection"),
                    Some(Err(e)) => bail!("reading from the hub: {e}"),
                    Some(Ok(Message::Close(_))) => bail!("the hub closed the session"),
                    Some(Ok(Message::Text(text))) => text,
                    Some(Ok(_)) => {
                        deadline = tokio::time::Instant::now() + quiet;
                        continue;
                    }
                };
                deadline = tokio::time::Instant::now() + quiet;
                match vk_peer::session::parse::<HubRelayMsg>(text.as_str())? {
                    HubRelayMsg::Server(server) => told(status, server),
                    HubRelayMsg::Refused { code, reason } => return Err(refusal(code, &reason)),
                }
            }
        }
    }
}

/// The hub's status of the relay's server: kept, and logged when it changes.
fn told(status: &Status, server: ServerStatus) {
    if status.server().as_ref() == Some(&server) {
        return;
    }
    let url = vk_hub_proto::display_safe(&server.url);
    match server.state {
        ServerState::Approved => {
            let name = vk_hub_proto::display_safe(server.name.as_deref().unwrap_or(""));
            log::info!(gitlab = url.as_str(), name = name.as_str(); "The hub approved this GitLab server; taking its jobs");
        }
        ServerState::Pending => {
            log::warn!(gitlab = url.as_str(); "This GitLab server is waiting for approval on the hub (`vk-hub gitlabs pending`); taking no job until then");
        }
        ServerState::Rejected => {
            log::error!(gitlab = url.as_str(); "The hub rejected this GitLab server; taking no job");
        }
        ServerState::Rebound => {
            log::error!(gitlab = url.as_str(); "The hub bound this relay to another GitLab server than [gitlab] url; taking no job until it is enrolled again (`vk-gitlab join --replace`)");
        }
        ServerState::Other => {
            log::warn!(gitlab = url.as_str(); "The hub sent a server status this vk-gitlab does not know; taking no job");
        }
    }
    status.set_server(Some(server));
}

async fn send(ws: &mut Ws, msg: &RelayMsg, within: Duration) -> Result<()> {
    vk_peer::session::send(ws, msg, within).await
}
