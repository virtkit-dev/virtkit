//! The accounts admin channel: a unix socket beside the accounts db, over which the
//! `vk-registry accounts` CLI reaches the db a running server holds.
//!
//! It exists because redb takes an exclusive `flock` for the life of the process, so the
//! CLI opening the same file itself needs `serve` stopped — including for `list-users`,
//! and including for revoking a leaked system key, which nothing else can revoke. Asking
//! the process that already holds the db removes that outage from the loop.
//!
//! **Not HTTP, and not on the listener.** Granting admin and minting keys deliberately
//! have no HTTP route (see `DESIGN.md`): this socket is never mounted on `route()`, is
//! unreachable from any network, and cannot be reached by a browser, so there is no
//! session, no CSRF token and no `authorize()` check here.
//!
//! Two gates instead, because what this channel can do — grant admin, mint an ownerless
//! key with any scope — is worth more than one. The socket is `0600` from the moment it
//! exists and is published atomically at that mode (see [`bind`]); and every connection's
//! `SO_PEERCRED` uid must be the server's own or root's, so a socket left somewhere loose,
//! or a directory that was not as private as it looked, is not by itself enough. That is
//! the access the CLI needed to open the db directly — the trust level
//! [`accounts::Db::set_admin`] has assumed since it had no caller but an operator — and no
//! more. Every change made here leaves a line naming the peer, since this path has no
//! request log behind it.
//!
//! The wire format is one JSON request per connection, answered by one JSON reply: the
//! peer half-closes to mark the end of its request and the server closes to mark the end
//! of the reply, so neither side has to frame or parse anything beyond `serde_json`. The
//! envelope carries [`PROTOCOL_VERSION`] because the CLI binary and the running server are
//! separately upgradable — an operator who installs a new `vk-registry` and has not
//! restarted the old one gets told so, rather than a parse error.
//!
//! The reply types are this module's own, not `accounts.rs`'s row structs: those are the
//! on-disk format, with a forward-compatibility rule about rows written by older builds,
//! and a protocol has different obligations than a file.

use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::accounts::{ApiKey, Db, Scope, User};

/// The envelope version. Bumped only for a change an older peer could misread; adding a
/// `Call` variant does not need one, since an unknown operation is already reported as
/// the version skew it is.
pub const PROTOCOL_VERSION: u32 = 1;

/// Ceiling on a request. The largest legitimate one is a `create-key` with the maximum
/// name and 32 scopes of the maximum pattern length (`accounts.rs`'s caps), a few
/// kilobytes; this leaves room to spare and keeps a confused peer from being answered with
/// unbounded buffering.
const MAX_REQUEST: usize = 64 * 1024;

/// Ceiling on a reply, for the client. Generous where [`MAX_REQUEST`] is tight: the largest
/// legitimate reply is a listing of every user or every API key, which grows with the
/// deployment, and the server answering is exactly as trusted as the db the CLI would
/// otherwise have opened itself. A runaway guard, not a trust boundary — and one that
/// reports itself rather than truncating, since a truncated JSON reply would reach an
/// operator as a parse error with no mention of a limit.
const MAX_REPLY: usize = 16 * 1024 * 1024;

/// How long a connection may take to deliver its request, and a client to get its reply.
/// Every operation is a handful of small redb transactions, so a wait beyond this is a
/// wedged peer rather than a slow one — and an operator waiting on a terminal deserves an
/// error long before a TCP-scale timeout.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait after an `accept` that failed for a reason that may still hold —
/// EMFILE, chiefly. Short enough that a transient failure costs an operator nothing.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// `sockaddr_un::sun_path`, terminator included: the ceiling on a socket path, and low
/// enough that a configured one can reach it.
const SUN_PATH_MAX: usize = 108;

/// One operation on the accounts db. The set the `vk-registry accounts` CLI needs, one
/// variant per `Db` method it calls — the socket deliberately exposes nothing else, so it
/// cannot become a general remote-control surface for the store.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub(crate) enum Call {
    ListUsers,
    FindUsersByEmail {
        email: String,
    },
    SetAdmin {
        user_id: String,
        is_admin: bool,
    },
    ListApiKeys {
        owner_user_id: String,
    },
    ListAllApiKeys,
    RevokeApiKey {
        id: String,
    },
    RevokeSessions {
        user_id: String,
    },
    CreateApiKey {
        owner_user_id: Option<String>,
        name: String,
        scopes: Vec<Scope>,
        /// Epoch seconds, or `None` for a key that never expires.
        expires_at: Option<i64>,
    },
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    v: u32,
    call: Call,
}

/// Read first, so a version mismatch is reported as one even when the rest of the
/// envelope is a shape this build cannot parse.
#[derive(Deserialize)]
struct VersionProbe {
    v: u32,
}

/// What the server answers: the operation's own JSON, or the error it failed with. A
/// message travels verbatim so an operator reads exactly what the direct path would have
/// printed.
#[derive(Serialize, Deserialize)]
enum Reply<T> {
    #[serde(rename = "ok")]
    Ok(T),
    #[serde(rename = "err")]
    Err(String),
}

/// A [`User`] on the wire: the same fields with the timestamps as epoch seconds.
#[derive(Serialize, Deserialize)]
pub(crate) struct WireUser {
    id: String,
    oidc_issuer: String,
    oidc_subject: String,
    email: Option<String>,
    display_name: Option<String>,
    is_admin: bool,
    created_at: i64,
    last_login_at: i64,
}

/// An [`ApiKey`] on the wire. Carries no secret: `id` is `sha256(token)` and
/// `token_prefix` is 32 bits of the random half, both already safe to display
/// (`accounts.rs`), and the bearer string itself is only ever in a `create-key` reply.
#[derive(Serialize, Deserialize)]
pub(crate) struct WireApiKey {
    id: String,
    owner_user_id: Option<String>,
    name: String,
    token_prefix: String,
    scopes: Vec<Scope>,
    created_at: i64,
    expires_at: Option<i64>,
    last_used_at: Option<i64>,
    revoked_at: Option<i64>,
}

/// A minted key and its one-time bearer token.
#[derive(Serialize, Deserialize)]
pub(crate) struct WireCreatedKey {
    key: WireApiKey,
    token: String,
}

impl From<&User> for WireUser {
    fn from(u: &User) -> Self {
        WireUser {
            id: u.id.clone(),
            oidc_issuer: u.oidc_issuer.clone(),
            oidc_subject: u.oidc_subject.clone(),
            email: u.email.clone(),
            display_name: u.display_name.clone(),
            is_admin: u.is_admin,
            created_at: to_epoch(u.created_at),
            last_login_at: to_epoch(u.last_login_at),
        }
    }
}

impl From<WireUser> for User {
    fn from(u: WireUser) -> Self {
        User {
            id: u.id,
            oidc_issuer: u.oidc_issuer,
            oidc_subject: u.oidc_subject,
            email: u.email,
            display_name: u.display_name,
            is_admin: u.is_admin,
            created_at: from_epoch(u.created_at),
            last_login_at: from_epoch(u.last_login_at),
        }
    }
}

impl From<&ApiKey> for WireApiKey {
    fn from(k: &ApiKey) -> Self {
        WireApiKey {
            id: k.id.clone(),
            owner_user_id: k.owner_user_id.clone(),
            name: k.name.clone(),
            token_prefix: k.token_prefix.clone(),
            scopes: k.scopes.clone(),
            created_at: to_epoch(k.created_at),
            expires_at: k.expires_at.map(to_epoch),
            last_used_at: k.last_used_at.map(to_epoch),
            revoked_at: k.revoked_at.map(to_epoch),
        }
    }
}

impl From<WireApiKey> for ApiKey {
    fn from(k: WireApiKey) -> Self {
        ApiKey {
            id: k.id,
            owner_user_id: k.owner_user_id,
            name: k.name,
            token_prefix: k.token_prefix,
            scopes: k.scopes,
            created_at: from_epoch(k.created_at),
            expires_at: k.expires_at.map(from_epoch),
            last_used_at: k.last_used_at.map(from_epoch),
            revoked_at: k.revoked_at.map(from_epoch),
        }
    }
}

/// Epoch seconds for a stamp read out of the db, which stored it as exactly that: the
/// round trip is lossless for every value `accounts.rs` can have written, and a stamp from
/// outside that range is a listing column, so saturating keeps a report readable rather
/// than failing it.
fn to_epoch(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => i64::try_from(e.duration().as_secs()).map_or(i64::MIN, |s| -s),
    }
}

/// The inverse, and total: a stamp the platform cannot represent saturates rather than
/// panicking, because this runs on values that arrived over a socket.
fn from_epoch(secs: i64) -> SystemTime {
    let delta = Duration::from_secs(secs.unsigned_abs());
    let shifted = if secs >= 0 {
        UNIX_EPOCH.checked_add(delta)
    } else {
        UNIX_EPOCH.checked_sub(delta)
    };
    shifted.unwrap_or(UNIX_EPOCH)
}

/// Bind the admin socket at `path`, replacing a socket left behind by a server that is
/// gone.
///
/// Never reachable at a laxer mode than `0600`, and published atomically. Both matter. `bind`
/// honours the ambient umask *and* `listen`s, so a socket bound at its real name under the
/// usual `umask 022` and chmodded a syscall later is connectable and group-reachable in
/// between — and a connection made then waits in the backlog to be served with everything
/// this channel can do. Nor is `fchmod` on the listener's fd an escape: it changes the
/// sockfs inode, not the directory entry anyone connects through.
///
/// So the socket is bound inside a `0700` staging directory of its own, restricted to `0600`
/// there — where nothing else can enter to reach it, or to swap the name for a symlink
/// between the two calls — and only then `rename`d onto `path`. Nothing appears at `path`
/// except a socket that is already private, replacing a dead one leaves no moment where the
/// name is absent, and no process-global umask is touched to do it. The peer-uid check in
/// [`serve_admin`] is the gate that depends on none of this.
///
/// A path that answers a connect is a *live* server: refused, because unlinking it would
/// take a running server's channel away without stopping it. A socket nobody is listening
/// on is what a killed server leaves, and that one is replaced. Anything at `path` that is
/// *not* a socket is a configuration error — `admin_socket` naming a real file, the
/// accounts db a line above it in the config being the easy mistake — and is refused
/// untouched: a `connect` to a regular file also fails with `ECONNREFUSED`, so "nobody
/// answered" is not evidence that the file is a socket to throw away.
pub fn bind(path: &Path) -> Result<std::os::unix::net::UnixListener> {
    if let Some(dir) = path.parent()
        && !dir.as_os_str().is_empty()
        && !dir.is_dir()
    {
        bail!(
            "no directory {} for the admin socket — create it, owned by the user \
             vk-registry runs as",
            dir.display()
        );
    }
    // `symlink_metadata`: a symlink at the path is the link, not what it points at, so a
    // link planted over the name cannot make the target below look replaceable.
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_socket() => bail!(
            "{} is not a socket — admin_socket must name a path of its own, and this one \
             is left alone rather than replaced",
            path.display()
        ),
        Ok(_) => match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => bail!(
                "something is already listening on {} — only one server may serve an \
                 admin socket at a path",
                path.display()
            ),
            // Nobody is listening: the socket outlived the server that made it, and the
            // `rename` below replaces it.
            Err(e) if matches!(e.kind(), std::io::ErrorKind::ConnectionRefused) => {}
            Err(e) => {
                return Err(anyhow!(e).context(format!(
                    "probing what is at {} before binding it",
                    path.display()
                )));
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(anyhow!(e).context(format!("inspecting {}", path.display())));
        }
    }
    if path.file_name().is_none() {
        bail!("{} is not a path a socket can be bound at", path.display());
    }
    // Deliberately short: it is bound at, so it spends `sun_path` budget the operator's own
    // path needs. `.<pid>/s` costs the same ten bytes `admin.sock` does, so the default
    // placement gives up nothing, and a leftover from a killed process carries our pid and
    // is therefore ours to clear.
    let staging_dir = path.with_file_name(format!(".{}", std::process::id()));
    let staging = staging_dir.join("s");
    // Both, since a path that only *binds* at its staging name would be published where no
    // client can connect. Said here rather than as an `EINVAL` from `bind` on a path the
    // operator can do nothing about from the error alone.
    let longest = std::cmp::max(path.as_os_str().len(), staging.as_os_str().len());
    if longest >= SUN_PATH_MAX {
        bail!(
            "{} is too long for a unix socket: {longest} bytes are needed to bind and \
             publish it, and {SUN_PATH_MAX} is the limit — put the admin socket on a \
             shorter path",
            path.display(),
        );
    }
    let _ = std::fs::remove_dir_all(&staging_dir);
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(&staging_dir)
        .with_context(|| format!("creating {}", staging_dir.display()))?;
    let published = std::os::unix::net::UnixListener::bind(&staging)
        .with_context(|| format!("binding {}", staging.display()))
        .and_then(|listener| {
            // Safe from a swapped name and from a connect that beats it: only this process
            // can enter the directory it is in.
            std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("restricting {} to 0600", staging.display()))?;
            std::fs::rename(&staging, path)
                .with_context(|| format!("publishing the admin socket at {}", path.display()))?;
            Ok(listener)
        });
    // Either the socket moved out of it or it never got there; either way the directory has
    // done its job, and a name left behind would only confuse the next start.
    let _ = std::fs::remove_dir_all(&staging_dir);
    let listener = published?;
    if let Some(dir) = path.parent() {
        crate::warn_if_mode(
            dir,
            0o077,
            "the admin socket's directory",
            "the socket's own 0600 and the peer-uid check still hold, but restrict it to 0700",
        );
    }
    // `serve_admin` hands it to tokio, which needs it non-blocking; done here so binding
    // stays callable outside a runtime — a startup failure should not need a reactor.
    listener
        .set_nonblocking(true)
        .context("making the admin socket non-blocking")?;
    Ok(listener)
}

/// Who is on the other end, from `SO_PEERCRED` — the kernel's answer, not the peer's, so
/// nothing here is something a caller can claim. Named in the audit line every mutation
/// leaves, which is the only trace this HTTP-less path has.
#[derive(Clone, Copy)]
struct Peer {
    uid: u32,
    pid: Option<i32>,
}

impl std::fmt::Display for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "uid {}", self.uid)?;
        match self.pid {
            Some(pid) => write!(f, " pid {pid}"),
            None => Ok(()),
        }
    }
}

/// Serve the admin socket until the process ends. One request per connection, and a
/// connection that fails only fails itself: this channel must never be able to take the
/// registry down.
///
/// Every connection's peer uid must be this process's own or root's. The socket's `0600`
/// already says the same thing, but it says it through the filesystem — a socket moved
/// somewhere less private with `admin_socket`, or a directory that was `0755` before the
/// server ever saw it, and the mode is doing all the work alone. This check does not depend
/// on any of the paths involved, and it is what makes "gated by the machine, not by the
/// network" true rather than intended.
///
/// Takes the accounts db and nothing else — no `ServerState`, so the content store,
/// the relay upstreams and the lock authority are all out of reach from here by
/// construction.
pub async fn serve_admin(listener: std::os::unix::net::UnixListener, db: Arc<Db>) {
    let listener = match UnixListener::from_std(listener) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("vk-registry: cannot serve the admin socket: {e}");
            return;
        }
    };
    // SAFETY: `geteuid` takes no arguments, touches no memory and cannot fail.
    let own_uid = unsafe { libc::geteuid() };
    // One line per uid turned away, not one per attempt: a peer that can open the socket but
    // is not allowed to use it could otherwise fill the journal at accept rate.
    let mut refused = std::collections::HashSet::new();
    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("vk-registry: admin socket accept error: {e}");
                // Usually per-connection (a peer gone between the handshake and here), but
                // EMFILE persists for as long as the descriptor table is full, and a bare
                // `continue` on that is a busy loop against the HTTP listener's own runtime.
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        let peer = match stream.peer_cred() {
            Ok(cred) => Peer {
                uid: cred.uid(),
                pid: cred.pid(),
            },
            // No credentials, no answer: this is the gate, so a failure to read it is a
            // refusal and not a reason to proceed.
            Err(e) => {
                eprintln!(
                    "vk-registry: admin socket: refusing a peer whose credentials could not be read: {e}"
                );
                continue;
            }
        };
        if peer.uid != own_uid && peer.uid != 0 {
            if refused.insert(peer.uid) {
                eprintln!(
                    "vk-registry: admin socket: refusing uid {} — only uid {own_uid} and \
                     root may administer the accounts; further attempts by it are silent",
                    peer.uid
                );
            }
            continue;
        }
        let db = db.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_one(stream, db, peer).await {
                eprintln!("vk-registry: admin socket: {e:#}");
            }
        });
    }
}

/// One request/reply exchange. The reply is a `Reply::Err` for anything the *operation*
/// failed at — the client prints it as the direct path would — and this returns `Err`
/// only for a failure of the exchange itself, which there is nobody left to tell.
async fn serve_one(mut stream: UnixStream, db: Arc<Db>, peer: Peer) -> Result<()> {
    let mut body = Vec::new();
    tokio::time::timeout(IO_TIMEOUT, async {
        (&mut stream)
            .take(cap(MAX_REQUEST) + 1)
            .read_to_end(&mut body)
            .await
    })
    .await
    .map_err(|_| anyhow!("a peer took longer than {IO_TIMEOUT:?} to send its request"))?
    .context("reading an admin request")?;
    if body.len() > MAX_REQUEST {
        bail!("an admin request may not exceed {MAX_REQUEST} bytes");
    }
    // Connected and gone without a word: what `Client::connect`'s liveness probe is. Not an
    // exchange to answer, and answering it would only earn an `EPIPE` to log.
    if body.is_empty() {
        return Ok(());
    }
    // redb is synchronous, and this runtime also serves the HTTP listener: a listing of
    // every key must not hold a worker while it reads.
    let reply = tokio::task::spawn_blocking(move || match dispatch(&body, &db, peer) {
        Ok(value) => serde_json::to_vec(&Reply::Ok(value)),
        Err(e) => serde_json::to_vec(&Reply::<()>::Err(format!("{e:#}"))),
    })
    .await
    .context("running an admin operation")?
    .context("serializing an admin reply")?;
    tokio::time::timeout(IO_TIMEOUT, async {
        stream.write_all(&reply).await?;
        stream.shutdown().await
    })
    .await
    .map_err(|_| anyhow!("a peer took longer than {IO_TIMEOUT:?} to read its reply"))?
    .context("writing an admin reply")?;
    Ok(())
}

/// A byte ceiling as the `u64` [`Read::take`] wants. The constants are small literals, so
/// the fallback is unreachable — it is here so a length limit is never an `as` cast.
fn cap(bytes: usize) -> u64 {
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

/// Parse one request and run it, yielding the JSON its operation answers with.
///
/// Every call that *changes* something leaves a line naming the peer: this channel has no
/// request log, no session and no HTTP access log behind it, so without one an admin grant
/// or a minted key would be invisible on the server that performed it.
fn dispatch(body: &[u8], db: &Db, peer: Peer) -> Result<serde_json::Value> {
    let probe: VersionProbe = serde_json::from_slice(body)
        .context("this does not look like a vk-registry admin request")?;
    if probe.v != PROTOCOL_VERSION {
        bail!(
            "the running vk-registry speaks admin protocol v{PROTOCOL_VERSION}, the caller \
             v{} — restart the server so both are this build, or run the CLI with it stopped",
            probe.v
        );
    }
    let envelope: Envelope = serde_json::from_slice(body).context(
        "the running vk-registry does not understand this operation — it is an older \
         build than the CLI that sent it; restart the server, or run the CLI with it stopped",
    )?;
    match envelope.call {
        Call::ListUsers => json(&wire_users(db.list_users()?)),
        Call::FindUsersByEmail { email } => json(&wire_users(db.find_users_by_email(&email)?)),
        Call::SetAdmin { user_id, is_admin } => {
            let found = db.set_admin(&user_id, is_admin)?;
            audit(
                peer,
                format_args!(
                    "set admin={is_admin} on user {user_id:?} ({})",
                    if found { "applied" } else { "no such user" }
                ),
            );
            json(&found)
        }
        Call::ListApiKeys { owner_user_id } => json(&wire_keys(db.list_api_keys(&owner_user_id)?)),
        Call::ListAllApiKeys => json(&wire_keys(db.list_all_api_keys()?)),
        Call::RevokeApiKey { id } => {
            let revoked = db.revoke_api_key_unchecked(&id)?;
            audit(
                peer,
                format_args!(
                    "revoked API key {id:?} ({})",
                    if revoked {
                        "applied"
                    } else {
                        "nothing live to revoke"
                    }
                ),
            );
            json(&revoked)
        }
        Call::RevokeSessions { user_id } => {
            let ended = db.delete_sessions_for_user(&user_id)?;
            audit(
                peer,
                format_args!("ended {ended} session(s) of user {user_id:?}"),
            );
            json(&ended)
        }
        Call::CreateApiKey {
            owner_user_id,
            name,
            scopes,
            expires_at,
        } => {
            let (key, token) = db.create_api_key(
                owner_user_id.as_deref(),
                &name,
                &scopes,
                expires_at.map(from_epoch),
            )?;
            // The grants, not their count: "scopes 1" does not tell a later reader whether
            // this key reads one repository or writes every one, which is the whole reason
            // the line is here. Bounded by `accounts.rs`'s caps on both, so it cannot run
            // away. The token itself never appears — it is the credential, and the operator
            // who asked for it is the only one who should hold a copy.
            // The owner escaped like the rest: a `User::id` is `issuer\x1fsubject`, and a
            // terminal swallows the separator — two different people would read as one.
            let owner = key
                .owner_user_id
                .as_deref()
                .map_or_else(|| "nobody".to_string(), |o| format!("{o:?}"));
            audit(
                peer,
                format_args!(
                    "minted API key {} ({name:?}, owner {owner}, {})",
                    key.id,
                    scope_summary(&key.scopes),
                ),
            );
            json(&WireCreatedKey {
                key: WireApiKey::from(&key),
                token,
            })
        }
    }
}

/// What a key may do, for the audit line: every grant, or that it has none.
fn scope_summary(scopes: &[Scope]) -> String {
    if scopes.is_empty() {
        return "no scopes".to_string();
    }
    let grants: Vec<String> = scopes
        .iter()
        .map(|s| format!("{:?} {:?}", s.action, s.repo_pattern))
        .collect();
    format!("scopes [{}]", grants.join(", "))
}

/// One line for one change, on the server that made it.
fn audit(peer: Peer, what: std::fmt::Arguments<'_>) {
    eprintln!("vk-registry: accounts admin: {peer}: {what}");
}

/// One operation's answer as the JSON it is replied with.
fn json<T: Serialize>(value: &T) -> Result<serde_json::Value> {
    serde_json::to_value(value).context("serializing an admin reply")
}

fn wire_users(users: Vec<User>) -> Vec<WireUser> {
    users.iter().map(WireUser::from).collect()
}

fn wire_keys(keys: Vec<ApiKey>) -> Vec<WireApiKey> {
    keys.iter().map(WireApiKey::from).collect()
}

/// The other end: the accounts db of a running server, reached over its admin socket.
///
/// Synchronous, one short-lived connection per call — the CLI is a sequence of single
/// operations, and a connection that is not held cannot be a lock the operator has to
/// think about. Nothing here is stateful, so a `Client` is only the path it dials.
pub struct Client {
    path: PathBuf,
}

impl Client {
    /// Dial `path` once to establish that a server is listening there, and keep it as the
    /// address for later calls. The `io::Error` is passed through unwrapped: its kind is
    /// how a caller tells "no server running" (`NotFound`, `ConnectionRefused`) from "not
    /// yours to talk to" (`PermissionDenied`), which are different things to tell an
    /// operator.
    pub fn connect(path: &Path) -> std::io::Result<Self> {
        let stream = std::os::unix::net::UnixStream::connect(path)?;
        drop(stream);
        Ok(Client {
            path: path.to_path_buf(),
        })
    }

    /// Where this client dials, for the messages that name it.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn call<T: DeserializeOwned>(&self, call: Call) -> Result<T> {
        let request = serde_json::to_vec(&Envelope {
            v: PROTOCOL_VERSION,
            call,
        })
        .context("serializing an admin request")?;
        // Named here rather than reaching the operator as the truncated-JSON parse error a
        // server that drops an over-long request would produce.
        if request.len() > MAX_REQUEST {
            bail!(
                "this operation does not fit in an admin request ({} bytes, ceiling \
                 {MAX_REQUEST}) — run the subcommand with the server stopped",
                request.len()
            );
        }
        let mut stream = std::os::unix::net::UnixStream::connect(&self.path)
            .with_context(|| format!("connecting to {}", self.path.display()))?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        stream
            .write_all(&request)
            .context("sending an admin request")?;
        // Half-close: what marks the end of the request, since neither side length-prefixes.
        stream
            .shutdown(std::net::Shutdown::Write)
            .context("finishing an admin request")?;
        let mut body = Vec::new();
        stream
            .take(cap(MAX_REPLY) + 1)
            .read_to_end(&mut body)
            .context("reading the admin reply")?;
        if body.len() > MAX_REPLY {
            bail!(
                "the admin reply exceeded {MAX_REPLY} bytes — run the subcommand with the \
                 server stopped, so it reads the db directly"
            );
        }
        match serde_json::from_slice(&body).context("parsing the admin reply")? {
            Reply::Ok(value) => Ok(value),
            // The server's own message, verbatim: an operator sees what the db said, not a
            // paraphrase of it wrapped in transport detail.
            Reply::Err(message) => Err(anyhow!(message)),
        }
    }

    pub fn list_users(&self) -> Result<Vec<User>> {
        Ok(self
            .call::<Vec<WireUser>>(Call::ListUsers)?
            .into_iter()
            .map(User::from)
            .collect())
    }

    pub fn find_users_by_email(&self, email: &str) -> Result<Vec<User>> {
        Ok(self
            .call::<Vec<WireUser>>(Call::FindUsersByEmail {
                email: email.to_string(),
            })?
            .into_iter()
            .map(User::from)
            .collect())
    }

    pub fn set_admin(&self, user_id: &str, is_admin: bool) -> Result<bool> {
        self.call(Call::SetAdmin {
            user_id: user_id.to_string(),
            is_admin,
        })
    }

    pub fn list_api_keys(&self, owner_user_id: &str) -> Result<Vec<ApiKey>> {
        Ok(self
            .call::<Vec<WireApiKey>>(Call::ListApiKeys {
                owner_user_id: owner_user_id.to_string(),
            })?
            .into_iter()
            .map(ApiKey::from)
            .collect())
    }

    pub fn list_all_api_keys(&self) -> Result<Vec<ApiKey>> {
        Ok(self
            .call::<Vec<WireApiKey>>(Call::ListAllApiKeys)?
            .into_iter()
            .map(ApiKey::from)
            .collect())
    }

    pub fn revoke_api_key_unchecked(&self, id: &str) -> Result<bool> {
        self.call(Call::RevokeApiKey { id: id.to_string() })
    }

    pub fn delete_sessions_for_user(&self, user_id: &str) -> Result<usize> {
        self.call(Call::RevokeSessions {
            user_id: user_id.to_string(),
        })
    }

    pub fn create_api_key(
        &self,
        owner_user_id: Option<&str>,
        name: &str,
        scopes: &[Scope],
        expires_at: Option<SystemTime>,
    ) -> Result<(ApiKey, String)> {
        let created: WireCreatedKey = self.call(Call::CreateApiKey {
            owner_user_id: owner_user_id.map(str::to_string),
            name: name.to_string(),
            scopes: scopes.to_vec(),
            expires_at: expires_at.map(to_epoch),
        })?;
        Ok((ApiKey::from(created.key), created.token))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use crate::accounts::Action;

    use super::*;

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// A server on its own thread, holding the db exactly as `serve` does — the situation
    /// the CLI could not work in before this socket existed.
    struct Server {
        dir: PathBuf,
        socket: PathBuf,
    }

    impl Server {
        fn start() -> Server {
            let dir = std::env::temp_dir().join(format!(
                "vk-registry-admin-test-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed),
            ));
            let _ = std::fs::remove_dir_all(&dir);
            let db_path = crate::config::default_accounts_db(&dir);
            let socket = crate::config::default_admin_socket(&db_path);
            let db = Arc::new(Db::open(&db_path).unwrap());
            // Seeded through the same handle the server keeps, because nothing else can
            // open the file while it lives.
            let alice = db
                .upsert_user(
                    "https://issuer",
                    "sub-1",
                    Some("alice@example.com"),
                    Some("Alice"),
                )
                .unwrap();
            db.create_api_key(Some(&alice.id), "alice-key", &[], None)
                .unwrap();
            // Two, so ending them is a count and not a boolean; and one already expired,
            // which is not reported as a session anybody held.
            db.create_session(&alice.id, Duration::from_secs(3600))
                .unwrap();
            db.create_session(&alice.id, Duration::from_secs(3600))
                .unwrap();
            db.create_session(&alice.id, Duration::ZERO).unwrap();
            let listener = bind(&socket).unwrap();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(serve_admin(listener, db));
            });
            Server { dir, socket }
        }

        fn client(&self) -> Client {
            Client::connect(&self.socket).unwrap()
        }
    }

    impl Drop for Server {
        /// Removing the directory unlinks the socket, so nothing can reach the server
        /// again; its thread stays parked in `accept` on the unlinked inode until the test
        /// binary exits. Deliberate — `serve_admin` runs until the process ends by design,
        /// and a shutdown channel added for the tests would be API the server does not
        /// want.
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    /// Every operation the CLI needs, against a db this process cannot open — the whole
    /// point of the socket. Also that the values survive the wire unchanged, since the
    /// listing an operator reads is rendered from them.
    fn every_operation_round_trips_against_a_held_db() {
        let server = Server::start();
        assert!(
            Db::open(&crate::config::default_accounts_db(&server.dir)).is_err(),
            "the server must still hold the db, or this proves nothing"
        );
        let c = server.client();

        let users = c.list_users().unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].email.as_deref(), Some("alice@example.com"));
        assert_eq!(users[0].display_name.as_deref(), Some("Alice"));
        assert_eq!(users[0].oidc_subject, "sub-1");
        assert!(!users[0].is_admin);
        // A stamp the db wrote, back through the wire: seconds, and not shifted.
        let age = SystemTime::now()
            .duration_since(users[0].created_at)
            .unwrap();
        assert!(age < Duration::from_secs(60), "{age:?}");

        let alice = &c.find_users_by_email("alice@example.com").unwrap()[0];
        assert_eq!(alice.id, users[0].id);
        assert!(
            c.find_users_by_email("nobody@example.com")
                .unwrap()
                .is_empty()
        );

        assert!(c.set_admin(&alice.id, true).unwrap());
        assert!(c.list_users().unwrap()[0].is_admin);
        assert!(!c.set_admin("no-such-user", true).unwrap());

        let scopes = vec![Scope {
            action: Action::Write,
            repo_pattern: "team-a/*".to_string(),
        }];
        let expiry = SystemTime::now() + Duration::from_secs(86_400);
        let (key, token) = c.create_api_key(None, "ci", &scopes, Some(expiry)).unwrap();
        assert!(token.starts_with("vkr_"), "{token}");
        assert_eq!(key.owner_user_id, None, "an ownerless system key");
        assert_eq!(key.scopes, scopes);
        // Second granularity is what the db stores, so compare at that.
        assert_eq!(
            key.expires_at.map(to_epoch),
            Some(to_epoch(expiry)),
            "the expiry has to survive the round trip: it is a security decision"
        );

        // Sessions are the server's to end, and it ends them while it serves: the two live
        // ones are the count, the expired one is swept without being reported, and a second
        // call finds nothing left — which is a report, not a failure.
        assert_eq!(c.delete_sessions_for_user(&alice.id).unwrap(), 2);
        assert_eq!(c.delete_sessions_for_user(&alice.id).unwrap(), 0);
        assert_eq!(c.delete_sessions_for_user("no-such-user").unwrap(), 0);

        assert_eq!(c.list_all_api_keys().unwrap().len(), 2);
        assert_eq!(c.list_api_keys(&alice.id).unwrap().len(), 1);
        assert!(c.revoke_api_key_unchecked(&key.id).unwrap());
        assert!(
            !c.revoke_api_key_unchecked(&key.id).unwrap(),
            "a second revoke has nothing live to revoke"
        );
        assert!(!c.revoke_api_key_unchecked("no-such-key").unwrap());
    }

    #[test]
    /// A failure of the operation comes back as the message the direct path would have
    /// printed, and leaves the socket usable.
    fn an_operation_error_is_reported_verbatim_and_the_socket_survives() {
        let server = Server::start();
        let c = server.client();
        let err = c
            .create_api_key(None, "", &[], None)
            .unwrap_err()
            .to_string();
        assert_eq!(err, "an API key needs a name", "{err}");
        let err = c
            .create_api_key(Some("no-such-user"), "k", &[], None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no such user"), "{err}");
        assert_eq!(c.list_users().unwrap().len(), 1, "still serving");
    }

    #[test]
    /// The socket is not group- or world-reachable, in its own mode and in its directory's:
    /// the outer of the two gates this channel has.
    fn the_socket_and_its_directory_are_private() {
        let server = Server::start();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&server.socket), 0o600);
        assert_eq!(mode(server.socket.parent().unwrap()), 0o700);
    }

    #[test]
    /// The socket's `0600` is the socket's own, not something the directory granted:
    /// `Db::open` chmods the accounts directory only when it *creates* it, so a pre-existing
    /// looser one is a deployment that really happens, and the peer-uid check is then the
    /// gate standing behind the mode.
    fn the_socket_is_private_in_a_directory_that_is_not() {
        let server = Server::start();
        let loose = server.dir.join("loose");
        std::fs::create_dir_all(&loose).unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
        let listener = bind(&loose.join("admin.sock")).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&loose.join("admin.sock")), 0o600);
        assert_eq!(
            mode(&loose),
            0o755,
            "the directory is left as the operator had it"
        );
        // The socket got there through a staging directory of its own, and nothing of it is
        // left to enter.
        assert_eq!(entries(&loose), ["admin.sock"]);
        drop(listener);
    }

    #[test]
    /// A path that holds something other than a socket is a configuration error, not a
    /// stale socket: `admin_socket` naming the accounts db must not delete it. A regular
    /// file refuses a `connect` exactly as a dead socket does, which is why the file type
    /// has to be looked at.
    fn binding_refuses_a_non_socket_rather_than_unlinking_it() {
        let server = Server::start();
        let precious = server.dir.join("accounts.db");
        std::fs::write(&precious, b"not a socket").unwrap();
        let err = bind(&precious).unwrap_err().to_string();
        assert!(err.contains("is not a socket"), "{err}");
        assert_eq!(
            std::fs::read(&precious).unwrap(),
            b"not a socket",
            "the file has to still be there"
        );

        // A symlink at the name is the symlink, not what it points at.
        let link = server.dir.join("link.sock");
        std::os::unix::fs::symlink(&precious, &link).unwrap();
        let err = bind(&link).unwrap_err().to_string();
        assert!(err.contains("is not a socket"), "{err}");
        assert!(precious.exists(), "the target has to still be there");
    }

    /// Everything in a directory, for the assertions about what binding leaves behind.
    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    /// Binding leaves no half-published name behind — on the way through *and* when the
    /// publish itself fails, since a staging socket left at the name is what the next start
    /// would refuse.
    fn binding_leaves_no_staging_socket_behind() {
        let server = Server::start();
        let dir = server.socket.parent().unwrap();
        assert_eq!(
            entries(dir),
            ["accounts.db", "admin.sock"],
            "after a good bind"
        );

        // The bind that replaces a dead socket goes through the same rename, and is the one
        // with a name already at the destination.
        let stale = server.dir.join("replaced.sock");
        drop(bind(&stale).unwrap());
        drop(bind(&stale).unwrap());
        assert_eq!(entries(&server.dir), ["accounts", "replaced.sock"]);
    }

    #[test]
    /// A socket path `sun_path` cannot hold is refused with that said, rather than as an
    /// `EINVAL` on a path the operator can do nothing about from the error alone — whether
    /// it is the operator's own name that overruns or only the name it is staged under.
    fn a_path_too_long_to_bind_says_so() {
        let server = Server::start();
        let room = SUN_PATH_MAX - server.dir.as_os_str().len() - 1;

        // Over the ceiling on its own.
        let long = server.dir.join("s".repeat(room));
        assert!(long.as_os_str().len() >= SUN_PATH_MAX);
        let err = bind(&long).unwrap_err().to_string();
        assert!(err.contains("too long for a unix socket"), "{err}");

        // And a name that fits but cannot be *staged*: the staging length does not depend on
        // the socket's own name, so a deep enough directory reaches the ceiling with a
        // one-byte name still well under it.
        let staging_cost = format!(".{}/s", std::process::id()).len();
        let deep = {
            let want = SUN_PATH_MAX - staging_cost;
            let pad = want - server.dir.as_os_str().len() - 1;
            server.dir.join("d".repeat(pad))
        };
        std::fs::create_dir_all(&deep).unwrap();
        let barely = deep.join("s");
        assert!(
            barely.as_os_str().len() < SUN_PATH_MAX,
            "the operator's own name has to fit, or this proves nothing"
        );
        let err = bind(&barely).unwrap_err().to_string();
        assert!(err.contains("too long for a unix socket"), "{err}");

        // The default placement gives up nothing to staging: `.<pid>/s` is no longer than
        // `admin.sock`, so every path that used to bind still does.
        assert!(staging_cost <= "admin.sock".len(), "{staging_cost}");
    }

    #[test]
    /// A request past the ceiling is refused with the ceiling named, and the socket is
    /// still serving afterwards — a confused peer is not an outage.
    fn an_oversized_request_is_refused_and_the_socket_survives() {
        let server = Server::start();
        let mut stream = std::os::unix::net::UnixStream::connect(&server.socket).unwrap();
        // Valid JSON, just far too much of it: the size is what is being refused, not the
        // shape.
        let body = format!(
            r#"{{"v":1,"call":{{"op":"find-users-by-email","email":"{}"}}}}"#,
            "a".repeat(MAX_REQUEST)
        );
        // A peer that stops reading may make this fail short of the whole body; either way
        // the server is the side under test.
        let _ = stream.write_all(body.as_bytes());
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut reply = String::new();
        let _ = stream.read_to_string(&mut reply);
        assert!(
            reply.is_empty(),
            "an over-long request gets no reply: {reply}"
        );
        assert_eq!(
            server.client().list_users().unwrap().len(),
            1,
            "still serving"
        );
    }

    #[test]
    /// A connection that says nothing is what `Client::connect` probes with. The server
    /// must treat it as the non-event it is: no reply attempted, since there is nobody left
    /// to read one, and nothing logged as a failure.
    fn a_silent_connection_is_not_an_exchange() {
        let server = Server::start();
        for _ in 0..3 {
            drop(Client::connect(&server.socket).unwrap());
        }
        // A peer that half-closes without writing, rather than dropping outright.
        let stream = std::os::unix::net::UnixStream::connect(&server.socket).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut reply = String::new();
        (&stream)
            .take(cap(MAX_REPLY))
            .read_to_string(&mut reply)
            .unwrap();
        assert!(reply.is_empty(), "{reply}");
        assert_eq!(
            server.client().list_users().unwrap().len(),
            1,
            "still serving"
        );
    }

    #[test]
    /// A listing bigger than a request may be is a reply, not a request: the two ceilings
    /// are separate, and `list-users` past a few hundred people has to keep working.
    fn a_listing_far_past_the_request_ceiling_round_trips() {
        let server = Server::start();
        let c = server.client();
        // Keys rather than users, because only the server can open the db to upsert one and
        // the socket has no upsert — and a key listing is what grows without bound anyway.
        let mut minted = Vec::new();
        for i in 0..600 {
            let (key, _) = c
                .create_api_key(None, &format!("ci-key-{i}"), &[], None)
                .unwrap();
            minted.push(key.id);
        }
        let all = c.list_all_api_keys().unwrap();
        assert_eq!(all.len(), 601, "the seeded key plus every minted one");
        // Well past MAX_REQUEST: this is the reply that used to come back truncated.
        let bytes = serde_json::to_vec(&wire_keys(all)).unwrap().len();
        assert!(
            bytes > MAX_REQUEST,
            "{bytes} bytes is not past the request ceiling"
        );
    }

    #[test]
    /// Two operators at once, because a socket that serialized its callers would be a lock
    /// an operator has to think about.
    fn two_clients_are_served_concurrently() {
        let server = Server::start();
        let socket = server.socket.clone();
        let threads: Vec<_> = (0..4)
            .map(|i| {
                let socket = socket.clone();
                std::thread::spawn(move || {
                    let c = Client::connect(&socket).unwrap();
                    let (key, _) = c
                        .create_api_key(None, &format!("concurrent-{i}"), &[], None)
                        .unwrap();
                    assert_eq!(c.list_users().unwrap().len(), 1);
                    key.id
                })
            })
            .collect();
        let ids: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(ids.len(), 4);
        let all = server.client().list_all_api_keys().unwrap();
        for id in &ids {
            assert!(all.iter().any(|k| &k.id == id), "{id} is missing");
        }
    }

    #[test]
    /// A live socket is never unlinked from under the server holding it, and a dead one is
    /// not an obstacle to the next start.
    fn binding_refuses_a_live_socket_and_replaces_a_stale_one() {
        let server = Server::start();
        let err = bind(&server.socket).unwrap_err().to_string();
        assert!(err.contains("already listening"), "{err}");

        // A socket file with nobody behind it: what a killed server leaves.
        let stale = server.socket.with_file_name("stale.sock");
        drop(bind(&stale).unwrap());
        assert!(stale.exists(), "the file outlives the listener");
        let listener = bind(&stale).expect("a stale socket is replaced, not refused");
        drop(listener);
    }

    #[test]
    /// Version skew between a CLI and the server it talks to is an explicit message, not a
    /// parse error — the two are separately upgradable.
    fn a_version_mismatch_says_which_side_to_restart() {
        let server = Server::start();
        let mut stream = std::os::unix::net::UnixStream::connect(&server.socket).unwrap();
        stream
            .write_all(br#"{"v":99,"call":{"op":"list-users"}}"#)
            .unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut body = String::new();
        stream.read_to_string(&mut body).unwrap();
        assert!(body.contains("admin protocol v1"), "{body}");
        assert!(body.contains("v99"), "{body}");
    }

    #[test]
    /// An operation this build does not know is reported as the skew it is, rather than
    /// leaving an operator with a serde error about a variant name.
    fn an_unknown_operation_names_the_older_side() {
        let server = Server::start();
        let mut stream = std::os::unix::net::UnixStream::connect(&server.socket).unwrap();
        stream
            .write_all(br#"{"v":1,"call":{"op":"reticulate-splines"}}"#)
            .unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut body = String::new();
        stream.read_to_string(&mut body).unwrap();
        assert!(body.contains("older build than the CLI"), "{body}");
    }

    #[test]
    /// Epoch conversion is lossless over the range a stamp can hold, and total: a value
    /// from outside it must not panic a listing.
    fn epoch_conversion_round_trips_and_does_not_panic() {
        for secs in [0, 1, 1_700_000_000, i64::from(i32::MAX), -1, -86_400] {
            assert_eq!(to_epoch(from_epoch(secs)), secs, "{secs}");
        }
        assert!(to_epoch(SystemTime::now()) > 1_700_000_000);
        // The extremes arrive from a peer, not from the db: an answer, never a panic —
        // whether the platform can represent them (it round-trips) or not (it clamps).
        for secs in [i64::MAX, i64::MIN] {
            let _ = from_epoch(secs);
        }
    }
}
