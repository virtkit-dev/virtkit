//! `vk-hub token`, `vk-hub nodes` and `vk-hub local login`, `sessions` and `logout` reach the
//! running hub through a unix socket in its data directory.
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

use crate::ops::{self, NodeView};
use crate::server::Hub;
use crate::store::{Role, UiSession};

/// Bumped only for a change an older peer could misread.
pub const PROTOCOL_VERSION: u32 = 1;

/// Ceiling on a request: the largest is a few dozen bytes.
const MAX_REQUEST: u64 = 64 * 1024;

/// Ceiling on a reply, for the client: a runaway guard, sized for a listing of a fleet far
/// past its target size.
const MAX_REPLY: u64 = 16 * 1024 * 1024;

/// How long either side waits on the other. Every operation is a small redb transaction.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
enum Call {
    CreateToken {
        ttl_secs: u64,
    },
    ListNodes,
    RemoveNode {
        id: String,
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
    let reply = tokio::task::spawn_blocking(move || match dispatch(&body, &hub, uid) {
        Ok(value) => serde_json::to_vec(&Reply::Ok(value)),
        Err(e) => serde_json::to_vec(&Reply::<()>::Err(format!("{e:#}"))),
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
        Call::UiLogin { role, ttl_secs } => {
            let Some(base) = &hub.ui_url else {
                bail!("the web UI is not being served");
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

    /// Whether there was such a node to remove.
    pub fn remove_node(&self, id: &str) -> Result<bool> {
        self.call(Call::RemoveNode { id: id.to_string() })
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

    fn call<T: DeserializeOwned>(&self, call: Call) -> Result<T> {
        let request = serde_json::to_vec(&Envelope {
            v: PROTOCOL_VERSION,
            call,
        })
        .context("encoding an admin request")?;
        let mut stream = std::os::unix::net::UnixStream::connect(&self.path)
            .with_context(|| format!("connecting to {}", self.path.display()))?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
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

    #[test]
    fn a_version_mismatch_says_so() {
        let hub = Hub::new(Arc::new(Db::open_memory().unwrap()), None);
        let err = dispatch(br#"{"v":99,"call":{"op":"ui-sessions"}}"#, &hub, 0).unwrap_err();
        assert!(format!("{err:#}").contains("v99"), "{err:#}");
        let err = dispatch(br#"{"v":1,"call":{"op":"format-disks"}}"#, &hub, 0).unwrap_err();
        assert!(format!("{err:#}").contains("older"), "{err:#}");
    }

    #[test]
    fn a_sign_in_link_needs_the_web_ui_and_starts_with_its_url() {
        let call = br#"{"v":1,"call":{"op":"ui-login","role":"operator","ttl_secs":60}}"#;
        let hub = Hub::new(Arc::new(Db::open_memory().unwrap()), None);
        let err = dispatch(call, &hub, 0).unwrap_err();
        assert!(format!("{err:#}").contains("not being served"), "{err:#}");
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
