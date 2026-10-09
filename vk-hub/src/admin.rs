//! `vk-hub token`, `vk-hub nodes`, `vk-hub release`, `vk-hub tools`, `vk-hub rollout`,
//! `vk-hub workloads`, `vk-hub audit`, `vk-hub ui`, `vk-hub accounts`, `vk-hub keys`,
//! `vk-hub jobs` and `vk-hub local login`, `sessions` and `logout` reach the running hub
//! through a unix socket in its data directory.
//!
//! Enrollment tokens admit machines to the fleet and must be issued outside the node-facing
//! network; sign-in links must be issued outside the web UI. The CLI cannot open the database:
//! redb holds it exclusively, and only the running server knows which sessions are open.
//! Like `vk-registry`'s accounts socket, this local channel is `0600` from creation
//! ([`vk_fs::bind_private`]) and accepts only the hub's uid or root via `SO_PEERCRED`.
//! Both can already read the database.
//!
//! Each connection carries one JSON request and reply. The client half-closes to end the
//! request; the server closes to end the reply. The envelope carries [`PROTOCOL_VERSION`]
//! because the CLI and running server upgrade separately.

use std::io::{Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::ops::{self, AccountOutcome, NodeView};
use crate::rollout::{Rollout, RolloutAction};
use crate::server::Hub;
use crate::store::{
    AccountRow, AuditRow, JobRow, KeyPolicy, KeyRow, Release, Role, Tools, UiSession,
};
use vk_hub_proto::{Acquisition, Command, DesiredState, Operation};

/// Bumped only for a change an older peer could misread.
pub const PROTOCOL_VERSION: u32 = 1;

/// Ceiling on a request: the largest is a hundred bytes or so.
const MAX_REQUEST: u64 = 64 * 1024;

/// Ceiling on a reply, for the client: a runaway guard, sized for a listing of a fleet far
/// past its target size. Every node's workloads, which can pass it, are sent as counts
/// instead when they would ([`ops::workloads`]).
const MAX_REPLY: u64 = 16 * 1024 * 1024;

/// What of [`MAX_REPLY`] a reply's value may take, leaving the rest to its envelope.
const MAX_REPLY_VALUE: usize = (MAX_REPLY - 64 * 1024) as usize;

/// How long either side waits on the other. Every operation is a small redb transaction, but
/// adding a release, which copies and hashes a binary first: see [`ADD_TIMEOUT`].
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the CLI waits for a release or tools to be added: a gigabyte copied and hashed on
/// a slow disk. An add retried after this ran out finds the release added and answers with it.
const ADD_TIMEOUT: Duration = Duration::from_secs(600);

/// How long the CLI waits for a fetch: past the hub's own limit on one, so it hears how it
/// ended. A fetch goes on when the CLI stops waiting; the next finds the release held.
const FETCH_WAIT: Duration = Duration::from_secs(35 * 60);

/// How long the CLI waits to hear which release is the latest: the hub's own limit on asking,
/// twice over, as it may be waiting on a check the pages started.
const CHECK_WAIT: Duration = Duration::from_secs(2 * crate::fetch::CHECK_TIMEOUT.as_secs() + 30);

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
enum Call {
    CreateToken {
        ttl_secs: u64,
    },
    ListNodes,
    /// Every node's workloads, or one node's: by ID, or by a hostname only it has.
    Workloads {
        node: Option<String>,
    },
    RemoveNode {
        id: String,
    },
    /// `None` lifts the ceiling.
    SetCeiling {
        id: String,
        ceiling: Option<u32>,
    },
    SetAcquisition {
        id: String,
        acquisition: Acquisition,
    },
    Command {
        id: String,
        operation: Operation,
    },
    /// Update a node to a release, named by its sha256 or a prefix of it.
    UpdateNode {
        id: String,
        release: String,
        force: bool,
    },
    /// Copy the binary at `path`, which the hub's user must be able to read, into the hub.
    AddRelease {
        path: PathBuf,
        version: String,
        /// A release key's signature, base64.
        #[serde(default)]
        signature: Option<String>,
    },
    /// Download a release's `vk` from the configured repository: `None` for the latest.
    FetchRelease {
        version: Option<String>,
    },
    /// The latest release the configured repository publishes.
    LatestRelease,
    ListReleases,
    RemoveRelease {
        release: String,
    },
    /// Pack the build context at `path`, which the hub's user must be able to read, into a
    /// tools definition.
    AddTools {
        path: PathBuf,
        version: String,
    },
    ListTools,
    RemoveTools {
        tools: String,
    },
    /// Have a node build a tools definition, named by its sha256 or a prefix of it; `None`
    /// for every node that can and needs to.
    NodeTools {
        id: Option<String>,
        tools: String,
    },
    CreateRollout {
        plan: ops::RolloutPlan,
    },
    ListRollouts,
    /// Pause, resume or abort a rollout, named by its ID or a prefix of it.
    SteerRollout {
        id: String,
        action: RolloutAction,
    },
    /// The latest `limit` audit lines, of one node or of all.
    Audit {
        node: Option<String>,
        limit: usize,
    },
    UiLogin {
        role: Role,
        ttl_secs: u64,
    },
    UiSessions,
    /// `None` ends every session.
    UiLogout {
        id: Option<String>,
    },
    ListAccounts,
    GrantAccount {
        email: String,
        role: Role,
    },
    RevokeAccount {
        email: String,
    },
    /// Put a node in pools, replacing the ones it was in.
    SetPools {
        id: String,
        pools: Vec<String>,
    },
    CreateKey {
        name: String,
        policy: KeyPolicy,
        ttl_secs: u64,
    },
    ListKeys,
    RevokeKey {
        name: String,
    },
    /// The latest `limit` placed jobs.
    ListJobs {
        limit: usize,
    },
    /// One placed job's record, and for a failed one the end of its output.
    ShowJob {
        id: String,
    },
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    v: u32,
    call: Call,
}

/// Read first, so a version mismatch is reported as one even when the rest does not parse.
#[derive(Deserialize)]
struct VersionProbe {
    v: u32,
}

#[derive(Serialize, Deserialize)]
enum Reply<T> {
    #[serde(rename = "ok")]
    Ok(T),
    #[serde(rename = "err")]
    Err(String),
}

/// A freshly minted enrollment token.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreatedToken {
    pub token: String,
    pub expires_at: u64,
}

/// A web UI sign-in link, and when it stops working.
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginLink {
    pub url: String,
    pub expires_at: u64,
}

/// OIDC sign-in grants and their roles.
#[derive(Debug, Serialize, Deserialize)]
pub struct Accounts {
    /// Whether the running hub has `[oidc]`: grants take effect only once it does.
    pub oidc: bool,
    /// Every grant, by address, `*` first.
    pub accounts: Vec<(String, AccountRow)>,
    /// `[oidc] default_role`, used when no grant matches. Older hubs omit it and have none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_role: Option<Role>,
}

/// A placed job's record and, for a failed job, its node-masked output tail encoded as
/// base64 ([`crate::jobs::detail`]).
#[derive(Debug, Serialize, Deserialize)]
pub struct JobDetail {
    pub row: JobRow,
    pub output: Option<String>,
}

/// A freshly minted API key, and its row.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreatedKey {
    pub key: String,
    pub row: KeyRow,
}

/// Bind the admin socket at `path`, replacing one a hub that is gone left behind.
///
/// A socket that answers is a live hub's and is refused; anything at `path` that is not a
/// socket is refused untouched, since a `connect` to a regular file fails the same way a
/// stale socket does.
///
/// Returned ready for the runtime, so every way serving it can fail fails here, at startup.
pub fn bind(path: &Path) -> Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_socket() => bail!(
            "{} is not a socket; it is left alone rather than replaced",
            path.display()
        ),
        Ok(_) => match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => bail!(
                "another vk-hub is already serving {} — only one may use a data directory",
                path.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {}
            Err(e) => {
                return Err(anyhow!(e).context(format!("probing {}", path.display())));
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(anyhow!(e).context(format!("inspecting {}", path.display()))),
    }
    let listener = vk_fs::bind_private(path)
        .with_context(|| format!("binding the admin socket at {}", path.display()))?;
    listener
        .set_nonblocking(true)
        .context("making the admin socket non-blocking")?;
    UnixListener::from_std(listener).context("serving the admin socket")
}

/// Serve the admin socket until the process ends. A failed connection fails only itself.
pub async fn serve(listener: UnixListener, hub: Arc<Hub>) {
    // SAFETY: `geteuid` takes no arguments, touches no memory and cannot fail.
    let own_uid = unsafe { libc::geteuid() };
    let mut refused = std::collections::HashSet::new();
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                eprintln!("vk-hub: admin socket accept error: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let uid = match stream.peer_cred() {
            Ok(cred) => cred.uid(),
            Err(e) => {
                eprintln!("vk-hub: admin socket: refusing a peer with unreadable credentials: {e}");
                continue;
            }
        };
        if uid != own_uid && uid != 0 {
            // One line per uid, so a peer retrying cannot fill the journal.
            if refused.insert(uid) {
                eprintln!(
                    "vk-hub: admin socket: refusing uid {uid} — only uid {own_uid} and root may \
                     administer the hub"
                );
            }
            continue;
        }
        let hub = hub.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_one(stream, hub, uid).await {
                eprintln!("vk-hub: admin socket: {e:#}");
            }
        });
    }
}

async fn serve_one(mut stream: UnixStream, hub: Arc<Hub>, uid: u32) -> Result<()> {
    let mut body = Vec::new();
    tokio::time::timeout(
        IO_TIMEOUT,
        (&mut stream).take(MAX_REQUEST + 1).read_to_end(&mut body),
    )
    .await
    .map_err(|_| anyhow!("a peer took longer than {IO_TIMEOUT:?} to send its request"))?
    .context("reading an admin request")?;
    if body.len() as u64 > MAX_REQUEST {
        bail!("an admin request may not exceed {MAX_REQUEST} bytes");
    }
    // A connect with no request is `Client::connect`'s liveness probe.
    if body.is_empty() {
        return Ok(());
    }
    let done = match fetch_call(&body) {
        Some(call) => Some(dispatch_fetch(call, &hub, uid).await),
        None => None,
    };
    let reply = tokio::task::spawn_blocking(move || {
        match done.unwrap_or_else(|| dispatch(&body, &hub, uid)) {
            Ok(value) => serde_json::to_vec(&Reply::Ok(value)),
            Err(e) => serde_json::to_vec(&Reply::<()>::Err(format!("{e:#}"))),
        }
    })
    .await
    .context("running an admin operation")?
    .context("encoding an admin reply")?;
    tokio::time::timeout(IO_TIMEOUT, async {
        stream.write_all(&reply).await?;
        stream.shutdown().await
    })
    .await
    .map_err(|_| anyhow!("a peer took longer than {IO_TIMEOUT:?} to read its reply"))?
    .context("writing an admin reply")
}

/// Extract calls that await network I/O on the runtime rather than a blocking thread.
/// Leave other calls, including version mismatches, to [`dispatch`].
fn fetch_call(body: &[u8]) -> Option<Call> {
    let probe: VersionProbe = serde_json::from_slice(body).ok()?;
    if probe.v != PROTOCOL_VERSION {
        return None;
    }
    let envelope: Envelope = serde_json::from_slice(body).ok()?;
    matches!(
        envelope.call,
        Call::FetchRelease { .. } | Call::LatestRelease
    )
    .then_some(envelope.call)
}

async fn dispatch_fetch(call: Call, hub: &Arc<Hub>, uid: u32) -> Result<serde_json::Value> {
    let actor = format!("uid {uid}");
    match call {
        Call::FetchRelease { version } => {
            let version = match version {
                Some(v) => crate::fetch::wanted(&v)?,
                None => None,
            };
            let release = crate::fetch::start(hub, &actor, version)?
                .await
                .context("fetching the release")??;
            Ok(serde_json::to_value(release)?)
        }
        Call::LatestRelease => Ok(serde_json::to_value(crate::fetch::latest(hub).await?)?),
        _ => bail!("not a fetch"),
    }
}

fn dispatch(body: &[u8], hub: &Hub, uid: u32) -> Result<serde_json::Value> {
    let probe: VersionProbe =
        serde_json::from_slice(body).context("this does not look like a vk-hub admin request")?;
    if probe.v != PROTOCOL_VERSION {
        bail!(
            "the running vk-hub speaks admin protocol v{PROTOCOL_VERSION}, the caller v{} — \
             restart the hub so both are this build",
            probe.v
        );
    }
    let envelope: Envelope = serde_json::from_slice(body).context(
        "the running vk-hub does not understand this operation — it is older than the CLI; \
         restart it",
    )?;
    let actor = format!("uid {uid}");
    let value = match envelope.call {
        Call::CreateToken { ttl_secs } => {
            let (token, expires_at) =
                hub.db
                    .create_token(Duration::from_secs(ttl_secs), &actor, crate::now_secs())?;
            // The token itself is never logged: it is the credential.
            eprintln!("vk-hub: admin: uid {uid} issued an enrollment token valid for {ttl_secs}s");
            serde_json::to_value(CreatedToken { token, expires_at })?
        }
        Call::ListNodes => serde_json::to_value(ops::node_views(hub)?)?,
        Call::Workloads { node } => {
            serde_json::to_value(ops::workloads(hub, node.as_deref(), MAX_REPLY_VALUE)?)?
        }
        Call::SetCeiling { id, ceiling } => {
            serde_json::to_value(ops::set_ceiling(hub, &actor, &id, ceiling)?)?
        }
        Call::SetAcquisition { id, acquisition } => {
            serde_json::to_value(ops::set_acquisition(hub, &actor, &id, acquisition)?)?
        }
        Call::Command { id, operation } => {
            serde_json::to_value(ops::command(hub, &actor, &id, operation)?)?
        }
        Call::UpdateNode { id, release, force } => {
            serde_json::to_value(ops::update(hub, &actor, &id, &release, force)?)?
        }
        Call::AddRelease {
            path,
            version,
            signature,
        } => serde_json::to_value(crate::releases::add(
            hub, &actor, &path, &version, signature,
        )?)?,
        Call::FetchRelease { .. } | Call::LatestRelease => {
            bail!("a fetch is served on its own path")
        }
        Call::ListReleases => serde_json::to_value(hub.db.releases()?)?,
        Call::RemoveRelease { release } => {
            let release = hub.db.resolve_release(&release)?;
            let removed = crate::releases::remove(hub, &actor, &release.sha256)?;
            serde_json::to_value(removed.then_some(release))?
        }
        Call::AddTools { path, version } => {
            serde_json::to_value(crate::tools::add(hub, &actor, &path, &version)?)?
        }
        Call::ListTools => serde_json::to_value(hub.db.tools_list()?)?,
        Call::RemoveTools { tools } => {
            let tools = hub.db.resolve_tools(&tools)?;
            let removed = crate::tools::remove(hub, &actor, &tools.sha256)?;
            serde_json::to_value(removed.then_some(tools))?
        }
        Call::NodeTools {
            id: Some(id),
            tools,
        } => serde_json::to_value(vec![ops::ToolsIssued {
            command: Some(ops::tools(hub, &actor, &id, &tools)?.id),
            hostname: hub.db.node(&id)?.map(|n| n.hostname).unwrap_or_default(),
            skipped: None,
            id,
        }])?,
        Call::NodeTools { id: None, tools } => {
            serde_json::to_value(ops::tools_all(hub, &actor, &tools)?)?
        }
        Call::CreateRollout { plan } => {
            serde_json::to_value(ops::create_rollout(hub, &actor, &plan)?)?
        }
        Call::ListRollouts => serde_json::to_value(ops::rollouts(hub)?)?,
        Call::SteerRollout { id, action } => {
            serde_json::to_value(ops::steer_rollout(hub, &actor, &id, action)?)?
        }
        Call::Audit { node, limit } => serde_json::to_value(audit(hub, node.as_deref(), limit)?)?,
        Call::UiLogin { role, ttl_secs } => {
            let Some(base) = &hub.ui_url else {
                bail!("the web UI is off; set ui_addr in the hub's config to turn it on");
            };
            let (token, expires_at) = hub.db.create_login(
                role,
                Duration::from_secs(ttl_secs),
                &actor,
                crate::now_secs(),
            )?;
            // The link is a credential: it goes to the caller alone, never to the hub's log.
            eprintln!(
                "vk-hub: admin: {actor} issued a sign-in link for the {} role, valid for \
                 {ttl_secs}s",
                role.name()
            );
            serde_json::to_value(LoginLink {
                url: format!("{base}{}?t={token}", crate::ui::LOGIN_PATH),
                expires_at,
            })?
        }
        Call::UiSessions => serde_json::to_value(hub.db.ui_sessions(crate::now_secs())?)?,
        Call::UiLogout { id } => {
            let ended = hub
                .db
                .end_ui_sessions(id.as_deref(), &actor, crate::now_secs())?;
            if ended > 0 {
                eprintln!("vk-hub: admin: {actor} ended {ended} web UI session(s)");
                // Their pages' live updates end on it.
                hub.sessions_changed();
            }
            serde_json::to_value(ended)?
        }
        Call::ListAccounts => serde_json::to_value(Accounts {
            oidc: hub.oidc,
            accounts: hub.db.accounts()?,
            default_role: hub.db.oidc_default_role(),
        })?,
        Call::GrantAccount { email, role } => {
            serde_json::to_value(ops::set_account(hub, &actor, &email, Some(role), false)?)?
        }
        Call::RevokeAccount { email } => {
            serde_json::to_value(ops::set_account(hub, &actor, &email, None, false)?)?
        }
        Call::SetPools { id, pools } => {
            let changed = hub.db.set_pools(&id, &pools, &actor, crate::now_secs())?;
            hub.changed(&id);
            serde_json::to_value(changed)?
        }
        Call::CreateKey {
            name,
            policy,
            ttl_secs,
        } => {
            let (key, row) = hub.db.create_api_key(
                &name,
                &policy,
                Duration::from_secs(ttl_secs),
                &actor,
                crate::now_secs(),
            )?;
            // The key itself is never logged: it is the credential.
            eprintln!("vk-hub: admin: {actor} created API key {name}");
            serde_json::to_value(CreatedKey { key, row })?
        }
        Call::ListKeys => serde_json::to_value(hub.db.api_keys()?)?,
        Call::RevokeKey { name } => {
            let revoked = hub.db.revoke_api_key(&name, &actor, crate::now_secs())?;
            if revoked {
                eprintln!("vk-hub: admin: {actor} revoked API key {name}");
            }
            serde_json::to_value(revoked)?
        }
        Call::ListJobs { limit } => {
            serde_json::to_value(crate::jobs::listing(hub, limit.min(10_000))?)?
        }
        Call::ShowJob { id } => {
            let detail = crate::jobs::detail(hub, &id)?.map(|(row, output)| JobDetail {
                row,
                output: output.as_deref().map(vk_hub_proto::to_base64),
            });
            serde_json::to_value(detail)?
        }
        Call::RemoveNode { id } => {
            let removed = hub.db.remove_node(&id, &actor, crate::now_secs())?;
            if removed {
                hub.revoke(&id);
            }
            eprintln!(
                "vk-hub: admin: uid {uid} removed node {} ({})",
                vk_hub_proto::display_safe(&id),
                if removed { "applied" } else { "no such node" }
            );
            serde_json::to_value(removed)?
        }
    };
    Ok(value)
}

/// The latest `limit` audit lines, of `node` or of all, oldest first: as many of them as fit
/// the reply, since a line can carry what a node reported at length.
fn audit(hub: &Hub, node: Option<&str>, limit: usize) -> Result<Vec<AuditRow>> {
    let mut bytes = 0usize;
    let mut rows: Vec<AuditRow> = hub
        .db
        .audit_page(node, None, limit)?
        .into_iter()
        .map(|(_, row)| row)
        .take_while(|row| {
            let size = serde_json::to_vec(row).map_or(usize::MAX, |j| j.len().saturating_add(1));
            bytes = bytes.saturating_add(size);
            bytes <= MAX_REPLY_VALUE
        })
        .collect();
    rows.reverse();
    Ok(rows)
}

/// The running hub, reached over its admin socket. One short connection per call.
pub struct Client {
    path: PathBuf,
}

impl Client {
    /// Dial `path` once to find out whether a hub is listening. The `io::Error` is passed
    /// through so its kind can tell "no hub running" from "not yours".
    pub fn connect(path: &Path) -> std::io::Result<Self> {
        drop(std::os::unix::net::UnixStream::connect(path)?);
        Ok(Client {
            path: path.to_path_buf(),
        })
    }

    pub fn create_token(&self, ttl: Duration) -> Result<CreatedToken> {
        self.call(Call::CreateToken {
            ttl_secs: ttl.as_secs(),
        })
    }

    pub fn list_nodes(&self) -> Result<Vec<NodeView>> {
        self.call(Call::ListNodes)
    }

    pub fn workloads(&self, node: Option<&str>) -> Result<Vec<ops::NodeWorkloads>> {
        self.call(Call::Workloads {
            node: node.map(str::to_string),
        })
    }

    /// Whether there was such a node to remove.
    pub fn remove_node(&self, id: &str) -> Result<bool> {
        self.call(Call::RemoveNode { id: id.to_string() })
    }

    /// The new desired state, or `None` when it was already so.
    pub fn set_ceiling(&self, id: &str, ceiling: Option<u32>) -> Result<Option<DesiredState>> {
        self.call(Call::SetCeiling {
            id: id.to_string(),
            ceiling,
        })
    }

    /// The new desired state, or `None` when it was already so.
    pub fn set_acquisition(
        &self,
        id: &str,
        acquisition: Acquisition,
    ) -> Result<Option<DesiredState>> {
        self.call(Call::SetAcquisition {
            id: id.to_string(),
            acquisition,
        })
    }

    pub fn command(&self, id: &str, operation: Operation) -> Result<Command> {
        self.call(Call::Command {
            id: id.to_string(),
            operation,
        })
    }

    pub fn update_node(&self, id: &str, release: &str, force: bool) -> Result<Command> {
        self.call(Call::UpdateNode {
            id: id.to_string(),
            release: release.to_string(),
            force,
        })
    }

    pub fn add_release(
        &self,
        path: &Path,
        version: &str,
        signature: Option<String>,
    ) -> Result<Release> {
        self.call(Call::AddRelease {
            path: path.to_path_buf(),
            version: version.to_string(),
            signature,
        })
    }

    /// Fetch `version`'s `vk`, `None` for the latest release's, waiting until it is held.
    pub fn fetch_release(&self, version: Option<&str>) -> Result<Release> {
        self.call(Call::FetchRelease {
            version: version.map(str::to_string),
        })
    }

    /// The latest release the hub's repository publishes.
    pub fn latest_release(&self) -> Result<String> {
        self.call(Call::LatestRelease)
    }

    pub fn releases(&self) -> Result<Vec<Release>> {
        self.call(Call::ListReleases)
    }

    /// The release removed, or `None` when another removal took it first. A prefix naming no
    /// release is an error.
    pub fn remove_release(&self, release: &str) -> Result<Option<Release>> {
        self.call(Call::RemoveRelease {
            release: release.to_string(),
        })
    }

    pub fn add_tools(&self, path: &Path, version: &str) -> Result<Tools> {
        self.call(Call::AddTools {
            path: path.to_path_buf(),
            version: version.to_string(),
        })
    }

    pub fn tools(&self) -> Result<Vec<Tools>> {
        self.call(Call::ListTools)
    }

    /// The definition removed, or `None` when another removal took it first. A prefix naming
    /// none is an error.
    pub fn remove_tools(&self, tools: &str) -> Result<Option<Tools>> {
        self.call(Call::RemoveTools {
            tools: tools.to_string(),
        })
    }

    /// Have node `id`, or with `None` every node that can and needs to, build `tools`.
    pub fn node_tools(&self, id: Option<&str>, tools: &str) -> Result<Vec<ops::ToolsIssued>> {
        self.call(Call::NodeTools {
            id: id.map(str::to_string),
            tools: tools.to_string(),
        })
    }

    pub fn create_rollout(&self, plan: ops::RolloutPlan) -> Result<Rollout> {
        self.call(Call::CreateRollout { plan })
    }

    /// Newest first.
    pub fn rollouts(&self) -> Result<Vec<Rollout>> {
        self.call(Call::ListRollouts)
    }

    /// The rollout as it now is.
    pub fn steer_rollout(&self, id: &str, action: RolloutAction) -> Result<Rollout> {
        self.call(Call::SteerRollout {
            id: id.to_string(),
            action,
        })
    }

    /// Oldest first.
    pub fn audit(&self, node: Option<&str>, limit: usize) -> Result<Vec<AuditRow>> {
        self.call(Call::Audit {
            node: node.map(str::to_string),
            limit,
        })
    }

    pub fn ui_login(&self, role: Role, ttl: Duration) -> Result<LoginLink> {
        self.call(Call::UiLogin {
            role,
            ttl_secs: ttl.as_secs(),
        })
    }

    pub fn ui_sessions(&self) -> Result<Vec<UiSession>> {
        self.call(Call::UiSessions)
    }

    /// How many sessions ended.
    pub fn ui_logout(&self, id: Option<&str>) -> Result<usize> {
        self.call(Call::UiLogout {
            id: id.map(str::to_string),
        })
    }

    pub fn accounts(&self) -> Result<Accounts> {
        self.call(Call::ListAccounts)
    }

    pub fn grant_account(&self, email: &str, role: Role) -> Result<AccountOutcome> {
        self.call(Call::GrantAccount {
            email: email.to_string(),
            role,
        })
    }

    pub fn revoke_account(&self, email: &str) -> Result<AccountOutcome> {
        self.call(Call::RevokeAccount {
            email: email.to_string(),
        })
    }

    /// Whether the node's pools changed.
    pub fn set_pools(&self, id: &str, pools: Vec<String>) -> Result<bool> {
        self.call(Call::SetPools {
            id: id.to_string(),
            pools,
        })
    }

    pub fn create_key(&self, name: &str, policy: KeyPolicy, ttl: Duration) -> Result<CreatedKey> {
        self.call(Call::CreateKey {
            name: name.to_string(),
            policy,
            ttl_secs: ttl.as_secs(),
        })
    }

    /// Oldest first.
    pub fn keys(&self) -> Result<Vec<KeyRow>> {
        self.call(Call::ListKeys)
    }

    /// Whether anything was revoked or removed.
    pub fn revoke_key(&self, name: &str) -> Result<bool> {
        self.call(Call::RevokeKey {
            name: name.to_string(),
        })
    }

    /// Newest first.
    pub fn jobs(&self, limit: usize) -> Result<Vec<(String, JobRow)>> {
        self.call(Call::ListJobs { limit })
    }

    /// Job `id`'s record and, for a failed job, the end of its output; `None` for a job not in
    /// the history.
    pub fn job(&self, id: &str) -> Result<Option<(JobRow, Option<Vec<u8>>)>> {
        let call = Call::ShowJob { id: id.to_string() };
        let Some(detail) = self.call::<Option<JobDetail>>(call)? else {
            return Ok(None);
        };
        let output = match detail.output {
            Some(b64) => {
                Some(vk_hub_proto::from_base64(&b64).context("the job's output is not base64")?)
            }
            None => None,
        };
        Ok(Some((detail.row, output)))
    }

    fn call<T: DeserializeOwned>(&self, call: Call) -> Result<T> {
        let timeout = match call {
            Call::AddRelease { .. } | Call::AddTools { .. } => ADD_TIMEOUT,
            Call::FetchRelease { .. } => FETCH_WAIT,
            Call::LatestRelease => CHECK_WAIT,
            _ => IO_TIMEOUT,
        };
        let request = serde_json::to_vec(&Envelope {
            v: PROTOCOL_VERSION,
            call,
        })
        .context("encoding an admin request")?;
        let mut stream = std::os::unix::net::UnixStream::connect(&self.path)
            .with_context(|| format!("connecting to {}", self.path.display()))?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        stream
            .write_all(&request)
            .context("sending an admin request")?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .context("finishing an admin request")?;
        let mut body = Vec::new();
        (&mut stream)
            .take(MAX_REPLY + 1)
            .read_to_end(&mut body)
            .context("reading the admin reply")?;
        if body.len() as u64 > MAX_REPLY {
            bail!("the admin reply exceeded {MAX_REPLY} bytes");
        }
        match serde_json::from_slice(&body).context("parsing the admin reply")? {
            Reply::Ok(value) => Ok(value),
            Reply::Err(message) => Err(anyhow!(message)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Db;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-hub-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tokens_and_nodes_are_served_over_the_socket() {
        let dir = scratch("admin");
        let path = dir.join("admin.sock");
        let hub = Arc::new(Hub::new(Arc::new(Db::open_memory().unwrap()), None));
        tokio::spawn(serve(bind(&path).unwrap(), hub.clone()));
        let client = Client::connect(&path).unwrap();
        let created = tokio::task::spawn_blocking(move || {
            client.create_token(Duration::from_secs(60)).unwrap()
        })
        .await
        .unwrap();
        assert!(created.expires_at > crate::now_secs());
        hub.db
            .enroll(&created.token, "aa", "ci-1", "peer p", crate::now_secs())
            .unwrap();
        let client = Client::connect(&path).unwrap();
        let (nodes, refused, removed) = tokio::task::spawn_blocking(move || {
            let nodes = client.list_nodes().unwrap();
            let refused = client.create_token(Duration::ZERO).unwrap_err();
            let id = nodes[0].id.clone();
            let removed = (
                client.remove_node(&id).unwrap(),
                client.remove_node(&id).unwrap(),
                client.list_nodes().unwrap().len(),
            );
            (nodes, refused, removed)
        })
        .await
        .unwrap();
        assert_eq!(removed, (true, false, 0));
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].hostname, "ci-1");
        assert!(!nodes[0].connected);
        assert!(format!("{refused:#}").contains("lifetime"), "{refused:#}");
        let events: Vec<String> = hub
            .db
            .audits(Some(&nodes[0].id), 10)
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect();
        assert_eq!(events.len(), 2, "{events:?}");
        assert!(events[1].ends_with(&format!("removed node {}", nodes[0].id)));
        let all = hub.db.audits(None, 10).unwrap();
        assert!(
            all[0]
                .event
                .ends_with("issued an enrollment token valid for 60s"),
            "{all:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn binding_refuses_a_live_hub_and_a_non_socket_and_replaces_a_stale_socket() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("bind");
        let path = dir.join("admin.sock");
        let live = bind(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(bind(&path).is_err());
        drop(live);
        // The listener is gone and the socket file stays: a stale one, replaced — once a child
        // another test forked meanwhile has exec'd, closing the copy of the socket it got.
        let mut again = bind(&path);
        for _ in 0..250 {
            if again.is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
            again = bind(&path);
        }
        let _again = again.unwrap();
        let file = dir.join("not-a-socket");
        std::fs::write(&file, b"keep").unwrap();
        assert!(bind(&file).is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"keep");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The tools calls, as the CLI sends them: added from a directory, issued to one node and
    /// to every node, listed, and removed once nothing is left to build, each audited as the
    /// caller.
    #[test]
    fn tools_calls_are_served_and_audited_as_the_caller() {
        let dir = scratch("tools");
        let hub = Hub::new(Arc::new(Db::open_memory().unwrap()), None).with_tools(dir.join("held"));
        let ctx = dir.join("ctx");
        std::fs::create_dir_all(&ctx).unwrap();
        std::fs::write(ctx.join("Dockerfile"), "FROM scratch AS tools\n").unwrap();
        let (token, _) = hub
            .db
            .create_token(Duration::from_secs(60), "uid 0", 0)
            .unwrap();
        let crate::store::Enrollment::Enrolled { node_id: id } =
            hub.db.enroll(&token, "aa", "h", "peer p", 1).unwrap()
        else {
            panic!("expected an enrollment");
        };
        let call = |call: serde_json::Value| {
            dispatch(
                serde_json::json!({"v": 1, "call": call})
                    .to_string()
                    .as_bytes(),
                &hub,
                7,
            )
        };
        let added: Tools = serde_json::from_value(
            call(serde_json::json!({"op": "add-tools", "path": ctx, "version": "2026.10"}))
                .unwrap(),
        )
        .unwrap();
        let listed: Vec<Tools> =
            serde_json::from_value(call(serde_json::json!({"op": "list-tools"})).unwrap()).unwrap();
        assert_eq!(listed, std::slice::from_ref(&added));
        let prefix = &added.sha256[..8];
        let one: Vec<ops::ToolsIssued> = serde_json::from_value(
            call(serde_json::json!({"op": "node-tools", "id": id, "tools": prefix})).unwrap(),
        )
        .unwrap();
        assert_eq!((one.len(), one[0].hostname.as_str()), (1, "h"));
        assert!(one[0].command.is_some());
        let all: Vec<ops::ToolsIssued> = serde_json::from_value(
            call(serde_json::json!({"op": "node-tools", "id": null, "tools": prefix})).unwrap(),
        )
        .unwrap();
        assert_eq!(
            all[0].skipped.as_deref(),
            Some("is building these tools already")
        );
        let err = call(serde_json::json!({"op": "remove-tools", "tools": prefix})).unwrap_err();
        assert!(format!("{err:#}").contains("still has to build"), "{err:#}");
        let events: Vec<String> = hub
            .db
            .audits(None, 10)
            .unwrap()
            .into_iter()
            .map(|a| format!("{} {}", a.actor, a.event))
            .collect();
        let short = crate::store::short(&added.sha256);
        for want in [
            format!("uid 7 uid 7 added tools {short} as version 2026.10 (1 file)"),
            format!("uid 7 uid 7 issued tools 2026.10 ({short})"),
        ] {
            assert!(
                events.iter().any(|e| e.starts_with(&want)),
                "{want}: {events:?}"
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_version_mismatch_says_so() {
        let hub = Hub::new(Arc::new(Db::open_memory().unwrap()), None);
        let err = dispatch(br#"{"v":99,"call":{"op":"ui-sessions"}}"#, &hub, 0).unwrap_err();
        assert!(format!("{err:#}").contains("v99"), "{err:#}");
        let err = dispatch(br#"{"v":1,"call":{"op":"format-disks"}}"#, &hub, 0).unwrap_err();
        assert!(format!("{err:#}").contains("older"), "{err:#}");
    }

    #[test]
    fn steering_calls_are_served_and_a_zero_ceiling_refused() {
        let hub = Hub::new(Arc::new(Db::open_memory().unwrap()), None);
        let (token, _) = hub
            .db
            .create_token(Duration::from_secs(60), "uid 0", 0)
            .unwrap();
        let crate::store::Enrollment::Enrolled { node_id: id } =
            hub.db.enroll(&token, "aa", "h", "peer p", 1).unwrap()
        else {
            panic!("expected an enrollment");
        };
        let call =
            |call: String| dispatch(format!(r#"{{"v":1,"call":{call}}}"#).as_bytes(), &hub, 7);
        let err = call(format!(r#"{{"op":"set-ceiling","id":"{id}","ceiling":0}}"#)).unwrap_err();
        assert!(format!("{err:#}").contains("stop acquisition"), "{err:#}");
        let set: Option<DesiredState> = serde_json::from_value(
            call(format!(
                r#"{{"op":"set-acquisition","id":"{id}","acquisition":"stop"}}"#
            ))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(set.map(|d| d.generation), Some(1));
        let issued: Command = serde_json::from_value(
            call(format!(
                r#"{{"op":"command","id":"{id}","operation":{{"kind":"drain"}}}}"#
            ))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(issued.op, Operation::Drain);
        let reset: Command = serde_json::from_value(
            call(format!(
                r#"{{"op":"command","id":"{id}","operation":{{"kind":"reset","images":true}}}}"#
            ))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(reset.op, Operation::Reset { images: true });
        // An update goes through a release the hub holds, never a version and digest the
        // caller made up.
        let err = call(format!(
            r#"{{"op":"command","id":"{id}","operation":{{"kind":"update","version":"1","sha256":"ab","size":1}}}}"#
        ))
        .unwrap_err();
        assert!(format!("{err:#}").contains("names a release"), "{err:#}");
        let err = call(format!(
            r#"{{"op":"update-node","id":"{id}","release":"abababab","force":false}}"#
        ))
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("no release abababab"),
            "{err:#}"
        );
        let lines: Vec<AuditRow> = serde_json::from_value(
            call(format!(r#"{{"op":"audit","node":"{id}","limit":2}}"#)).unwrap(),
        )
        .unwrap();
        let events: Vec<&str> = lines.iter().map(|r| r.event.as_str()).collect();
        assert_eq!(
            events,
            [
                &format!("uid 7 issued drain (command {})", issued.id),
                &format!("uid 7 issued reset, images included (command {})", reset.id)
            ]
        );
    }

    /// Grants are made and revoked over the socket as the peer's uid, by address normalized,
    /// or `*`, which is only ever a viewer.
    #[test]
    fn accounts_are_granted_listed_and_revoked() {
        let hub = Hub::new(Arc::new(Db::open_memory().unwrap()), None).with_oidc();
        let call =
            |call: &str| dispatch(format!(r#"{{"v":1,"call":{call}}}"#).as_bytes(), &hub, 1000);
        let outcome = |v| serde_json::from_value::<AccountOutcome>(v).unwrap();
        let granted = outcome(
            call(r#"{"op":"grant-account","email":"Bob@Example.com","role":"operator"}"#).unwrap(),
        );
        assert_eq!(granted.email, "bob@example.com");
        assert!(granted.oidc);
        outcome(call(r#"{"op":"grant-account","email":"*","role":"viewer"}"#).unwrap());
        for bad in [
            r#"{"op":"grant-account","email":"bob","role":"viewer"}"#,
            r#"{"op":"grant-account","email":"*","role":"operator"}"#,
        ] {
            assert!(call(bad).is_err(), "{bad}");
        }

        let listed: Accounts =
            serde_json::from_value(call(r#"{"op":"list-accounts"}"#).unwrap()).unwrap();
        assert!(listed.oidc);
        let rows: Vec<(&str, Role, &str)> = listed
            .accounts
            .iter()
            .map(|(e, a)| (e.as_str(), a.role, a.granted_by.as_str()))
            .collect();
        assert_eq!(
            rows,
            [
                ("*", Role::Viewer, "uid 1000"),
                ("bob@example.com", Role::Operator, "uid 1000"),
            ]
        );

        let revoked =
            outcome(call(r#"{"op":"revoke-account","email":"BOB@example.com"}"#).unwrap());
        assert_eq!(revoked.change.previous, Some(Role::Operator));
        let audit = hub.db.audits(None, 10).unwrap();
        assert_eq!(audit.len(), 3, "{audit:?}");
        assert!(audit.iter().all(|r| r.actor == "uid 1000"), "{audit:?}");
        assert_eq!(
            audit[2].event,
            "uid 1000 revoked bob@example.com's grant of the operator role"
        );

        // Without `[oidc]`, a grant is kept all the same, and the reply says it waits.
        let hub = Hub::new(Arc::new(Db::open_memory().unwrap()), None);
        let reply = dispatch(
            br#"{"v":1,"call":{"op":"grant-account","email":"a@b","role":"viewer"}}"#,
            &hub,
            0,
        )
        .unwrap();
        assert!(!outcome(reply).oidc);
        assert_eq!(hub.db.oidc_role(Some("a@b")).unwrap(), Some(Role::Viewer));
    }

    /// The listing carries the default role, and reads from a hub that predates it as none.
    #[test]
    fn the_accounts_listing_carries_the_default_role() {
        let db = Db::open_memory().unwrap();
        let hub = Hub::new(Arc::new(db.with_oidc_default_role(Role::Viewer)), None).with_oidc();
        let listed = dispatch(br#"{"v":1,"call":{"op":"list-accounts"}}"#, &hub, 0).unwrap();
        assert_eq!(listed["default_role"], "viewer");
        let listed: Accounts = serde_json::from_value(listed).unwrap();
        assert_eq!(listed.default_role, Some(Role::Viewer));
        let old: Accounts = serde_json::from_str(r#"{"oidc":true,"accounts":[]}"#).unwrap();
        assert_eq!(old.default_role, None);
        let hub = Hub::new(Arc::new(Db::open_memory().unwrap()), None).with_oidc();
        let listed = dispatch(br#"{"v":1,"call":{"op":"list-accounts"}}"#, &hub, 0).unwrap();
        assert!(listed.get("default_role").is_none(), "{listed}");
    }

    #[test]
    fn keys_pools_and_jobs_are_served_over_the_socket() {
        let hub = Hub::new(Arc::new(Db::open_memory().unwrap()), None);
        let call =
            |call: &str| dispatch(format!(r#"{{"v":1,"call":{call}}}"#).as_bytes(), &hub, 1000);
        let created: CreatedKey = serde_json::from_value(
            call(
                r#"{"op":"create-key","name":"gitlab","policy":{"scopes":["jobs"],"pools":["ci"],"max_envelope":null},"ttl_secs":3600}"#,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(created.key.starts_with("vkk_"));
        assert!(
            hub.db
                .api_key(&created.key, crate::now_secs())
                .unwrap()
                .is_some()
        );
        let keys: Vec<KeyRow> =
            serde_json::from_value(call(r#"{"op":"list-keys"}"#).unwrap()).unwrap();
        assert_eq!(keys, [created.row]);
        assert_eq!(
            call(r#"{"op":"revoke-key","name":"gitlab"}"#).unwrap(),
            true
        );
        assert!(
            hub.db
                .api_key(&created.key, crate::now_secs())
                .unwrap()
                .is_none()
        );

        let (token, _) = hub
            .db
            .create_token(Duration::from_secs(60), "uid 0", 0)
            .unwrap();
        let crate::store::Enrollment::Enrolled { node_id: id } =
            hub.db.enroll(&token, "aa", "h", "peer p", 1).unwrap()
        else {
            panic!("expected an enrollment");
        };
        let set = format!(r#"{{"op":"set-pools","id":"{id}","pools":["ci","big"]}}"#);
        assert_eq!(call(&set).unwrap(), true);
        assert_eq!(call(&set).unwrap(), false);
        assert_eq!(hub.db.node(&id).unwrap().unwrap().pools, ["big", "ci"]);
        let bad = format!(r#"{{"op":"set-pools","id":"{id}","pools":["no pool"]}}"#);
        assert!(call(&bad).is_err());
        let jobs = call(r#"{"op":"list-jobs","limit":10}"#).unwrap();
        assert_eq!(jobs, serde_json::json!([]));
        let job = call(&format!(r#"{{"op":"show-job","id":"{id}"}}"#)).unwrap();
        assert_eq!(job, serde_json::Value::Null);
        // Not an ID: no file is looked for under it.
        let job = call(r#"{"op":"show-job","id":"../x"}"#).unwrap();
        assert_eq!(job, serde_json::Value::Null);
        let audit = hub.db.audits(None, 10).unwrap();
        let events: Vec<&str> = audit.iter().map(|r| r.event.as_str()).collect();
        assert!(
            events.contains(&"uid 1000 revoked API key gitlab"),
            "{events:?}"
        );
        assert!(
            events.contains(&format!("uid 1000 put node {id} in pools big, ci").as_str()),
            "{events:?}"
        );
    }

    #[test]
    fn a_sign_in_link_needs_the_web_ui_and_starts_with_its_url() {
        let call = br#"{"v":1,"call":{"op":"ui-login","role":"operator","ttl_secs":60}}"#;
        let hub = Hub::new(Arc::new(Db::open_memory().unwrap()), None);
        let err = dispatch(call, &hub, 0).unwrap_err();
        assert!(format!("{err:#}").contains("web UI is off"), "{err:#}");
        let hub = Hub::new(
            Arc::new(Db::open_memory().unwrap()),
            Some("http://hub.example".into()),
        );
        let link: LoginLink = serde_json::from_value(dispatch(call, &hub, 1000).unwrap()).unwrap();
        let token = link
            .url
            .strip_prefix("http://hub.example/login?t=")
            .unwrap();
        let (_, session) = hub
            .db
            .redeem_login(token, crate::now_secs())
            .unwrap()
            .unwrap();
        assert_eq!(
            (session.role, session.issued_by.as_str()),
            (Role::Operator, "uid 1000")
        );
        let listed = dispatch(br#"{"v":1,"call":{"op":"ui-sessions"}}"#, &hub, 0).unwrap();
        assert_eq!(
            serde_json::from_value::<Vec<UiSession>>(listed).unwrap(),
            [session]
        );
        let ended = dispatch(br#"{"v":1,"call":{"op":"ui-logout","id":null}}"#, &hub, 0).unwrap();
        assert_eq!(ended, 1);
    }
}
