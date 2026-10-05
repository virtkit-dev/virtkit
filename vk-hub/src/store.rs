//! The hub's database: enrolled nodes, what the hub wants of them and the commands issued to
//! them, outstanding enrollment tokens, the web UI's sign-in links and sessions, and the audit
//! log, in [`redb`] like `vk-registry`'s accounts store — tables of JSON rows, small enough
//! that listing every node is a scan.
//!
//! Enrollment tokens, sign-in tokens and session secrets are stored as `sha256` hashes, so
//! the file cannot enroll a node or supply sign-in credentials. A read transaction rejects
//! token guesses without a durable write. Spending a token shares one write transaction with
//! what it opens — the node's pinned key, the session — so concurrent requests can enroll
//! only one node or open only one session per token.
//!
//! Every string a node or the host's `vk` reports is stored through
//! [`vk_hub_proto::display_safe`]: the database is where it crosses into the operator's
//! terminal and pages.
//!
//! Heartbeats are written at [`Durability::None`]: one arrives from every node every few
//! seconds, and losing the last few to a crash costs nothing — the next one replaces them.
//! One a minute is durable all the same ([`HEARTBEAT_SYNC_SECS`]). A node's workloads are
//! written at [`Durability::None`] too, since the node sends them again on every session;
//! they change with every CI job started or ended, so they are kept apart from the node's
//! row, which every heartbeat rewrites, and their memory readings apart from them.
//! Everything else is durable.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vk_hub_proto::{
    Acquisition, Command, CommandAck, DesiredState, Heartbeat, Inventory, NodeState, Operation,
    Outcome, Report, STEERING, Workload,
};

/// Key: node ID. Value: JSON [`NodeRow`].
const NODES: TableDefinition<&str, &[u8]> = TableDefinition::new("nodes");
/// Key: `sha256(token)`, hex. Value: JSON [`TokenRow`].
const TOKENS: TableDefinition<&str, &[u8]> = TableDefinition::new("tokens");
/// Key: `<node id>/<command id>`, so a node's commands are one range. Value: JSON
/// [`CommandRow`].
const COMMANDS: TableDefinition<&str, &[u8]> = TableDefinition::new("commands");
/// Key: a sequence number, oldest first. Value: JSON [`AuditRow`].
const AUDIT: TableDefinition<u64, &[u8]> = TableDefinition::new("audit");
/// Key: `(node id, sequence number)` of each node's audit rows, so one node's log is a range.
const AUDIT_BY_NODE: TableDefinition<(&str, u64), ()> = TableDefinition::new("audit_by_node");
/// Key: `sha256(sign-in token)`, hex. Value: JSON [`LoginRow`].
const UI_LOGINS: TableDefinition<&str, &[u8]> = TableDefinition::new("ui_logins");
/// Key: `sha256(session secret)`, hex. Value: JSON [`UiSessionRow`].
const UI_SESSIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("ui_sessions");
/// Each node's latest [`Workloads`], by node ID: the list, without its memory readings.
const WORKLOADS: TableDefinition<&str, &[u8]> = TableDefinition::new("workloads");
/// What each node's workloads hold, by node ID: a map of workload ID to bytes.
const WORKLOAD_MEM: TableDefinition<&str, &[u8]> = TableDefinition::new("workload_mem");
/// Key: a `vk` release's sha256, hex. Value: JSON [`ReleaseRow`]; the binary is the file of
/// that name in the hub's releases directory.
const RELEASES: TableDefinition<&str, &[u8]> = TableDefinition::new("releases");

/// The most audit rows kept. Bounded by count rather than age: a quiet fleet keeps its history
/// for years, and a busy one keeps the newest hundred thousand actions and outcomes — months
/// at the rate of a few dozen nodes. Past it, the oldest go, a thousand at a time.
const AUDIT_MAX: u64 = 100_000;
const AUDIT_PRUNE: u64 = 1000;

/// How long a command is kept once it is settled — finished, refused, expired, or never
/// taken by its expiry — for `vk-hub nodes` and a look back. The audit log keeps the record.
const COMMAND_KEEP: u64 = 30 * 86_400;

/// At least this often, in seconds, a heartbeat's write is made durable. redb keeps every
/// non-durable commit's bookkeeping in memory, and the pages it frees unreusable, until the
/// next durable one; a fleet whose inventories stay put commits nothing else.
const HEARTBEAT_SYNC_SECS: u64 = 60;

/// The most filesystems, memory nodes, hardware checks and runner names kept from one
/// inventory: far above what a host reports, and a bound on the row a node can make the hub
/// store and every listing read back.
const MAX_INVENTORY_ITEMS: usize = 64;

/// Every enrollment token starts with this, so one pasted into the wrong place is
/// recognizable.
const TOKEN_PREFIX: &str = "vkh_";

/// The longest-lived token an operator may issue. A token is a bearer credential for adding
/// a machine to the fleet; one that outlives its purpose by months is one somebody finds.
pub const MAX_TOKEN_TTL: Duration = Duration::from_secs(30 * 86_400);

/// Every web UI sign-in token starts with this.
pub(crate) const LOGIN_PREFIX: &str = "vkl_";

/// The longest-lived sign-in link: it is meant to be opened right away, by whoever asked
/// for it.
pub const MAX_LOGIN_TTL: Duration = Duration::from_secs(86_400);

/// How long a web UI session lasts from sign-in: a working day, then a new link.
pub const UI_SESSION_TTL: Duration = Duration::from_secs(12 * 3600);

/// How many hex digits of a session's key name it: in `vk-hub ui sessions` and `vk-hub local
/// sessions`, and in the audit log as the principal of what it did. 48 bits, unique among the
/// few sessions a hub holds but not guaranteed to be: `logout <id>` ends every session that
/// shares one, and a browser's own sign-out ends its session by the whole key.
const SESSION_ID_LEN: usize = 12;

/// What a web UI session may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Read everything.
    Viewer,
    /// And act: in local mode, stop, start, reboot and remove VMs.
    Operator,
}

impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct LoginRow {
    role: Role,
    issued_by: String,
    expires_at: u64,
}

#[derive(Serialize, Deserialize)]
struct UiSessionRow {
    role: Role,
    issued_by: String,
    created_at: u64,
    expires_at: u64,
}

/// A web UI session, as the UI and `vk-hub ui sessions` see it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiSession {
    /// The start of its key, the hash of its secret — [`SESSION_ID_LEN`] hex digits, which
    /// another session may share: what names it, and no use as the secret.
    pub id: String,
    pub role: Role,
    /// Who issued the sign-in link it was opened with.
    pub issued_by: String,
    pub created_at: u64,
    pub expires_at: u64,
}

impl UiSession {
    fn new(key: &str, row: UiSessionRow) -> Self {
        UiSession {
            id: key.get(..SESSION_ID_LEN).unwrap_or(key).to_string(),
            role: row.role,
            issued_by: row.issued_by,
            created_at: row.created_at,
            expires_at: row.expires_at,
        }
    }

    /// Who the audit log says did what this session did.
    pub fn principal(&self) -> String {
        format!("ui session {} ({})", self.id, self.role.name())
    }
}

/// An enrolled node. Fields added later carry `#[serde(default)]` so rows written by an
/// older hub still read.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NodeRow {
    /// The pinned ed25519 public key, hex.
    pub public_key: String,
    /// The hostname given at enrollment, replaced by each inventory's.
    pub hostname: String,
    pub enrolled_at: u64,
    /// The incarnation of the node's latest session.
    #[serde(default)]
    pub incarnation: Option<String>,
    /// The protocol version of the node's latest session.
    #[serde(default)]
    pub protocol: Option<u32>,
    /// When the node last authenticated or sent anything.
    #[serde(default)]
    pub last_seen: Option<u64>,
    #[serde(default)]
    pub inventory: Option<Inventory>,
    #[serde(default)]
    pub heartbeat: Option<Heartbeat>,
    #[serde(default)]
    pub heartbeat_at: Option<u64>,
    /// How many VMs the node last said it runs, listed or not; `None` until it has said.
    #[serde(default)]
    pub workloads: Option<u32>,
    /// The node's latest report of itself, without its workloads: those are kept apart.
    #[serde(default)]
    pub report: Option<Report>,
    /// What the hub wants of the node; `None` until an operator sets it or the hub adopts the
    /// node's reported applied state.
    #[serde(default)]
    pub desired: Option<DesiredState>,
    /// Fields of `desired` set by an operator on the defaults before the node's state was
    /// known. Unset fields come from the node's applied state when reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_on_defaults: Option<SetFields>,
}

/// Which fields of a desired state an operator set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetFields {
    pub ceiling: bool,
    pub acquisition: bool,
}

/// One change an operator makes to what the hub wants of a node.
#[derive(Clone, Copy, Debug)]
pub enum DesiredChange {
    Ceiling(Option<u32>),
    Acquisition(Acquisition),
}

/// A command issued to a node, and what the node last said it came to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandRow {
    pub command: Command,
    pub issued_at: u64,
    /// Issue order among the node's commands, whatever the clock did: one more than the
    /// highest of its commands kept when this one was issued.
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub outcome: Option<Outcome>,
    #[serde(default)]
    pub outcome_at: Option<u64>,
}

impl CommandRow {
    /// Still to be delivered or finished: no outcome yet, or one that is under way.
    fn pending(&self) -> bool {
        matches!(self.outcome, None | Some(Outcome::Accepted))
    }

    /// Still to deliver or finish, and not past an expiry the node never answered: it would
    /// only refuse it. A command the node has accepted runs on past its expiry.
    fn live(&self, now: u64) -> bool {
        self.pending() && (self.outcome.is_some() || self.command.expires_at > now)
    }

    /// [`CommandRow::live`], and an update to release `sha256`: what keeps the release on the
    /// hub, and what a node's download of it is allowed for.
    fn updates_to(&self, sha256: &str, now: u64) -> bool {
        self.live(now)
            && matches!(&self.command.op, Operation::Update { sha256: s, .. } if s == sha256)
    }

    /// Settled more than `keep` before `now`: a final outcome that old, or an expiry that
    /// old for a command never taken.
    fn settled_before(&self, now: u64, keep: u64) -> bool {
        let settled_at = match &self.outcome {
            Some(Outcome::Accepted) => return false,
            Some(_) => self.outcome_at.unwrap_or(self.issued_at),
            None => self.command.expires_at,
        };
        now.saturating_sub(settled_at) > keep
    }
}

/// What a node last said runs on it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workloads {
    pub listed: Vec<Workload>,
    /// Running, but left out of `listed` by the node or cut by the hub.
    #[serde(default)]
    pub omitted: u32,
    /// What each listed one holds on the host, in bytes, by its ID, from the latest heartbeat.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub mem_bytes: BTreeMap<String, u64>,
}

/// A `vk` binary the hub holds for its nodes to update to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRow {
    /// The version the operator stated, which the binary's `--version` must report.
    pub version: String,
    pub size: u64,
    /// A release key's ed25519 signature over [`vk_hub_proto::release_message`], base64.
    #[serde(default)]
    pub signature: Option<String>,
    pub added_at: u64,
    pub added_by: String,
}

/// A release as `vk-hub release list` shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    pub sha256: String,
    #[serde(flatten)]
    pub row: ReleaseRow,
}

/// One line of the audit log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRow {
    pub at: u64,
    /// The node it is about; `None` for the hub's own, and for everything in local mode.
    #[serde(default)]
    pub node: Option<String>,
    /// Who: `uid <n>` for an operator on the admin socket, a session's principal for what it
    /// did, `vk-hub local` for what local mode did as it started, `peer <addr>` for an
    /// enrollment.
    pub actor: String,
    pub event: String,
}

#[derive(Serialize, Deserialize)]
struct TokenRow {
    created_at: u64,
    expires_at: u64,
}

/// A node's row is gone: it was never enrolled, or has been removed.
#[derive(Debug)]
pub struct NotEnrolled(pub String);

impl std::fmt::Display for NotEnrolled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "node {} is not enrolled", self.0)
    }
}

impl std::error::Error for NotEnrolled {}

/// The node's latest session ran a protocol version below [`STEERING`]: the hub can monitor
/// it, not steer it.
#[derive(Debug)]
pub struct MonitoringOnly {
    pub id: String,
    pub version: u32,
}

impl std::fmt::Display for MonitoringOnly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "node {} speaks fleet protocol version {}: the hub can monitor it but not steer \
             it; update its vk",
            self.id, self.version
        )
    }
}

impl std::error::Error for MonitoringOnly {}

/// Refuse to steer node `id` whose latest session ran below [`STEERING`]. A node that has not
/// connected yet is taken at its word: what it is sent waits for a session that can carry it.
fn steerable(id: &str, row: &NodeRow) -> Result<()> {
    match row.protocol {
        Some(version) if version < STEERING => Err(MonitoringOnly {
            id: id.to_string(),
            version,
        }
        .into()),
        _ => Ok(()),
    }
}

/// What an enrollment came to.
#[derive(Debug, PartialEq, Eq)]
pub enum Enrollment {
    Enrolled {
        node_id: String,
    },
    /// Return the node already pinned to this key. After a lost enrollment reply, a node
    /// retries with a new token and the same key, meeting the original enrollment requirements.
    Reenrolled {
        node_id: String,
    },
    /// The token is unknown, already used, or expired — deliberately not said which, to a
    /// caller who may be guessing.
    BadToken,
}

pub struct Db {
    db: Database,
    /// When a heartbeat's write was last made durable ([`HEARTBEAT_SYNC_SECS`]).
    heartbeat_synced_at: AtomicU64,
}

impl Db {
    /// Open the database at `path`, creating it — and a `0700` directory for it — if absent.
    ///
    /// The file holds who may sign in, so it is created `0600` and only ever opened
    /// `O_NOFOLLOW`, as the registry's accounts db is.
    pub fn open(path: &Path) -> Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
            crate::warn_if_mode(
                parent,
                0o022,
                "the hub's data directory",
                "it is writable by others, who could replace the database in it",
            );
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW);
        // `create_new` first: creation is when the mode is honoured and a planted symlink
        // refused outright.
        let file = match opts.clone().create_new(true).open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let file = opts.open(path).with_context(|| {
                    format!(
                        "opening {} (a symlink at this path is refused)",
                        path.display()
                    )
                })?;
                crate::warn_if_file_mode(
                    &file,
                    path,
                    0o077,
                    "hub database",
                    "it is group/world-accessible — restrict it to 0600",
                );
                file
            }
            Err(e) => return Err(e).with_context(|| format!("creating {}", path.display())),
        };
        let db = Database::builder().create_file(file).with_context(|| {
            format!(
                "opening the hub database at {}: only one vk-hub may hold it",
                path.display()
            )
        })?;
        Self::init(db)
    }

    #[cfg(test)]
    pub fn open_memory() -> Result<Self> {
        let db = Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .context("opening an in-memory hub database")?;
        Self::init(db)
    }

    fn init(db: Database) -> Result<Self> {
        let txn = db
            .begin_write()
            .context("starting the hub db's first write")?;
        txn.open_table(NODES).context("opening the nodes table")?;
        txn.open_table(TOKENS).context("opening the tokens table")?;
        txn.open_table(COMMANDS)
            .context("opening the commands table")?;
        txn.open_table(AUDIT).context("opening the audit table")?;
        txn.open_table(AUDIT_BY_NODE)
            .context("opening the audit index")?;
        txn.open_table(UI_LOGINS)
            .context("opening the sign-in links table")?;
        txn.open_table(UI_SESSIONS)
            .context("opening the web UI sessions table")?;
        txn.open_table(WORKLOADS)
            .context("opening the workloads table")?;
        txn.open_table(WORKLOAD_MEM)
            .context("opening the workload memory table")?;
        txn.open_table(RELEASES)
            .context("opening the releases table")?;
        txn.commit().context("initializing the hub database")?;
        Ok(Db {
            db,
            heartbeat_synced_at: AtomicU64::new(0),
        })
    }

    /// Issue a single-use enrollment token valid for `ttl`, audited as `actor`'s. Returns the
    /// token — shown once, never stored — and when it expires. Expired tokens are swept in the
    /// same write.
    pub fn create_token(&self, ttl: Duration, actor: &str, now: u64) -> Result<(String, u64)> {
        if ttl.is_zero() || ttl > MAX_TOKEN_TTL {
            bail!(
                "a token's lifetime must be between 1s and {} days",
                MAX_TOKEN_TTL.as_secs() / 86_400
            );
        }
        let token = format!("{TOKEN_PREFIX}{}", crate::random_hex(32)?);
        let expires_at = now.saturating_add(ttl.as_secs());
        let txn = self.db.begin_write().context("starting a write")?;
        {
            let mut table = txn.open_table(TOKENS)?;
            let mut expired = Vec::new();
            for entry in table.iter()? {
                let (key, value) = entry?;
                if decode::<TokenRow>(value.value())?.expires_at <= now {
                    expired.push(key.value().to_string());
                }
            }
            for key in expired {
                table.remove(key.as_str())?;
            }
            let row = TokenRow {
                created_at: now,
                expires_at,
            };
            table.insert(token_key(&token).as_str(), encode(&row)?.as_slice())?;
        }
        let event = format!(
            "{actor} issued an enrollment token valid for {}s",
            ttl.as_secs()
        );
        append_audit(&txn, None, actor, &event, now)?;
        txn.commit().context("storing an enrollment token")?;
        Ok((token, expires_at))
    }

    /// Consume `token` and pin `public_key` (hex) as a new node, or answer with the node it is
    /// already pinned to, audited as `actor`'s. The caller has checked the node's signature.
    pub fn enroll(
        &self,
        token: &str,
        public_key: &str,
        hostname: &str,
        actor: &str,
        now: u64,
    ) -> Result<Enrollment> {
        let key = token_key(token);
        {
            let txn = self.db.begin_read().context("starting a read")?;
            let tokens = txn.open_table(TOKENS)?;
            let live = tokens
                .get(key.as_str())?
                .map(|g| decode::<TokenRow>(g.value()))
                .transpose()?
                .is_some_and(|row| row.expires_at > now);
            // Expired tokens are left for `create_token`'s sweep: removing one here would be
            // the write this read exists to avoid.
            if !live {
                return Ok(Enrollment::BadToken);
            }
        }
        // Checked again under the write lock: another enrollment may have spent it since.
        let txn = self.db.begin_write().context("starting a write")?;
        let outcome = {
            let mut tokens = txn.open_table(TOKENS)?;
            let row = tokens
                .remove(key.as_str())?
                .map(|g| decode::<TokenRow>(g.value()))
                .transpose()?;
            // Removed whether or not it is still valid: an expired token is no use to anyone
            // and a spent one is removed by definition.
            match row {
                Some(row) if row.expires_at > now => {
                    let mut nodes = txn.open_table(NODES)?;
                    let mut pinned = None;
                    for entry in nodes.iter()? {
                        let (id, value) = entry?;
                        if decode::<NodeRow>(value.value())?.public_key == public_key {
                            pinned = Some(id.value().to_string());
                            break;
                        }
                    }
                    if let Some(node_id) = pinned {
                        let event = format!("node {node_id} enrolled again with its pinned key");
                        append_audit(&txn, Some(&node_id), actor, &event, now)?;
                        Enrollment::Reenrolled { node_id }
                    } else {
                        let node_id = crate::random_hex(vk_hub_proto::ID_BYTES)?;
                        let row = NodeRow {
                            public_key: public_key.to_string(),
                            hostname: vk_hub_proto::display_safe(hostname),
                            enrolled_at: now,
                            ..NodeRow::default()
                        };
                        nodes.insert(node_id.as_str(), encode(&row)?.as_slice())?;
                        let event = format!("node {node_id} enrolled as {}", row.hostname);
                        append_audit(&txn, Some(&node_id), actor, &event, now)?;
                        Enrollment::Enrolled { node_id }
                    }
                }
                _ => Enrollment::BadToken,
            }
        };
        txn.commit().context("recording an enrollment")?;
        Ok(outcome)
    }

    pub fn node(&self, id: &str) -> Result<Option<NodeRow>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(NODES)?;
        table
            .get(id)?
            .map(|g| decode::<NodeRow>(g.value()))
            .transpose()
    }

    /// Read node `id` and its workloads in one snapshot, with [`Db::workloads`] semantics.
    /// Return `None` if the node does not exist.
    pub fn node_with_workloads(&self, id: &str) -> Result<Option<(NodeRow, Option<Workloads>)>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let Some(row) = txn
            .open_table(NODES)?
            .get(id)?
            .map(|g| decode::<NodeRow>(g.value()))
            .transpose()?
        else {
            return Ok(None);
        };
        Ok(Some((row, workloads_in(&txn, id)?)))
    }

    /// Every node's hostname, by ID.
    pub fn node_names(&self) -> Result<Vec<(String, String)>> {
        let txn = self.db.begin_read().context("starting a read")?;
        Ok(nodes_in(&txn)?
            .into_iter()
            .map(|(id, row)| (id, row.hostname))
            .collect())
    }

    /// Every node, by ID.
    pub fn nodes(&self) -> Result<Vec<(String, NodeRow)>> {
        let txn = self.db.begin_read().context("starting a read")?;
        nodes_in(&txn)
    }

    /// Record an authenticated session's `incarnation` and protocol `version` only if
    /// `current` holds inside the write, preserving a newer session's values if superseded.
    /// Return whether the session was recorded.
    pub fn record_session(
        &self,
        id: &str,
        incarnation: &str,
        version: u32,
        now: u64,
        current: impl FnOnce() -> bool,
    ) -> Result<bool> {
        self.update_txn(now, id, |row, _| {
            let current = current();
            if current {
                row.incarnation = Some(incarnation.to_string());
                row.protocol = Some(version);
                row.last_seen = Some(now);
            }
            Ok((current, Vec::new(), Durability::Immediate))
        })
    }

    /// Remove a node, audited as `actor`'s: its key is no longer pinned, a session it opens is
    /// refused, and its commands go. `Ok(false)` when there was no such node.
    pub fn remove_node(&self, id: &str, actor: &str, now: u64) -> Result<bool> {
        let txn = self.db.begin_write().context("starting a write")?;
        let removed = txn.open_table(NODES)?.remove(id)?.is_some();
        if removed {
            append_audit(
                &txn,
                Some(id),
                actor,
                &format!("{actor} removed node {id}"),
                now,
            )?;
            txn.open_table(WORKLOADS)?.remove(id)?;
            txn.open_table(WORKLOAD_MEM)?.remove(id)?;
            let (start, end) = command_range(id);
            txn.open_table(COMMANDS)?
                .retain_in(start.as_str()..end.as_str(), |_, _| false)?;
        }
        txn.commit().context("removing a node")?;
        Ok(removed)
    }

    /// Store an inventory, durably if `durable`. Its hostname replaces the enrollment's unless
    /// it is empty. One identical to the stored one only refreshes `last_seen`, without a
    /// durable write.
    pub fn record_inventory(
        &self,
        id: &str,
        inventory: Inventory,
        durable: bool,
        now: u64,
    ) -> Result<()> {
        let inventory = display_safe_inventory(inventory);
        self.update_txn(now, id, |row, _| {
            let changed = row.inventory.as_ref() != Some(&inventory);
            if !inventory.hostname.is_empty() {
                row.hostname = inventory.hostname.clone();
            }
            row.inventory = Some(inventory);
            row.last_seen = Some(now);
            let durability = if changed && durable {
                Durability::Immediate
            } else {
                Durability::None
            };
            Ok(((), Vec::new(), durability))
        })
    }

    pub fn record_heartbeat(&self, id: &str, heartbeat: Heartbeat, now: u64) -> Result<()> {
        let durability = if self.heartbeat_syncs(now) {
            Durability::Immediate
        } else {
            Durability::None
        };
        let mut heartbeat = bound_heartbeat(heartbeat);
        // Kept apart from the row, as a lookup for the listed workloads.
        let mem = std::mem::take(&mut heartbeat.workload_mem_bytes);
        self.update_txn(now, id, |row, txn| {
            row.heartbeat = Some(heartbeat);
            row.heartbeat_at = Some(now);
            row.last_seen = Some(now);
            // Written only when it moved: a node repeats its figures between measurements.
            let mut table = txn.open_table(WORKLOAD_MEM)?;
            // One that does not decode is as good as none: this one replaces it.
            let stored = match table.get(id)? {
                Some(g) => decode::<BTreeMap<String, u64>>(g.value()).ok(),
                None => Some(BTreeMap::new()),
            };
            if stored.as_ref() != Some(&mem) {
                table.insert(id, encode(&mem)?.as_slice())?;
            }
            Ok(((), Vec::new(), durability))
        })
    }

    /// Whether the heartbeat written at `now` is to be durable: the first one
    /// [`HEARTBEAT_SYNC_SECS`] after the last that was. Claimed before the write, so two at
    /// once do not both sync.
    fn heartbeat_syncs(&self, now: u64) -> bool {
        let last = self.heartbeat_synced_at.load(Ordering::Relaxed);
        now.saturating_sub(last) >= HEARTBEAT_SYNC_SECS
            && self
                .heartbeat_synced_at
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
    }

    /// Record `event`, done by `actor`, in the audit log.
    pub fn audit(&self, actor: &str, event: &str, now: u64) -> Result<()> {
        let txn = self.db.begin_write().context("starting a write")?;
        append_audit(&txn, None, actor, event, now)?;
        txn.commit().context("writing an audit line")
    }

    /// Node `id`'s workloads, with their memory readings; `None` until a report listed them.
    #[cfg(test)]
    pub fn workloads(&self, id: &str) -> Result<Option<Workloads>> {
        let txn = self.db.begin_read().context("starting a read")?;
        workloads_in(&txn, id)
    }

    /// The nodes `pick` keeps of every node, by ID, each with its workloads as
    /// [`Db::workloads`] has them: all read at one moment, and only the picked ones' workloads
    /// read. Rows that do not decode are left out as [`Db::nodes`] leaves them out.
    pub fn nodes_with_workloads(
        &self,
        pick: impl FnOnce(Vec<(String, NodeRow)>) -> Result<Vec<(String, NodeRow)>>,
    ) -> Result<Vec<(String, NodeRow, Option<Workloads>)>> {
        let txn = self.db.begin_read().context("starting a read")?;
        pick(nodes_in(&txn)?)?
            .into_iter()
            .map(|(id, row)| {
                let workloads = workloads_in(&txn, &id)?;
                Ok((id, row, workloads))
            })
            .collect()
    }

    /// Store node `id`'s report durably when changed, with workloads stored separately and
    /// preserved when absent from the report. Audit changes to state, applied generation and
    /// what the node cannot carry out.
    ///
    /// After a hub restore, a node may report a newer generation. Reissue desired state one
    /// generation above the node's, since it ignores generations at or below the one applied.
    /// A hub with no desired state for the node — restored from a backup older than its
    /// steering, or after a hub of protocol version 1 rewrote the row — adopts what the node
    /// applied instead, so the node keeps the restrictions it was given. Changes an operator
    /// made in that state before the node reported what it applied are applied onto the node's,
    /// past its generation, rather than onto the defaults they were made on.
    pub fn record_report(&self, id: &str, mut report: Report, now: u64) -> Result<()> {
        let workloads = report.workloads.take().map(|listed| {
            // Bounded again, as the node bounds them: what it sends is not trusted to be.
            let (kept, cut) =
                vk_hub_proto::bound_workloads(listed.into_iter().map(|w| (w, ())).collect());
            Workloads {
                listed: kept.into_iter().map(|(w, ())| w).collect(),
                omitted: report.workloads_omitted.saturating_add(cut),
                mem_bytes: BTreeMap::new(),
            }
        });
        report.workloads_omitted = 0;
        let report = display_safe_report(report);
        self.update_txn(now, id, |row, txn| {
            let durability = if row.report.as_ref() == Some(&report) {
                Durability::None
            } else {
                Durability::Immediate
            };
            let mut events: Vec<(String, String)> = report_events(row.report.as_ref(), &report)
                .into_iter()
                .map(|e| ("node".to_string(), e))
                .collect();
            // A report without `applied` (a fresh node, or a session at protocol version 1)
            // leaves `set_on_defaults` for the next one that has it.
            let set = if report.applied.is_some() {
                row.set_on_defaults.take()
            } else {
                None
            };
            match (&row.desired, &report.applied, set) {
                (Some(ours), Some(theirs), Some(set)) => {
                    let mut merged = DesiredState {
                        generation: theirs.generation,
                        ceiling: if set.ceiling {
                            ours.ceiling
                        } else {
                            theirs.ceiling
                        },
                        acquisition: if set.acquisition {
                            ours.acquisition
                        } else {
                            theirs.acquisition
                        },
                    };
                    let same = |s: &DesiredState| (s.ceiling, s.acquisition);
                    if ours.generation > theirs.generation && same(&merged) == same(ours) {
                        // Ours already carries the change past the node's generation, and may
                        // be in flight: it stands, as the generation must never go back.
                        merged.generation = ours.generation;
                    } else if merged != *theirs || ours.generation > theirs.generation {
                        merged.generation =
                            ours.generation.max(theirs.generation).saturating_add(1);
                        events.push((
                            "hub".to_string(),
                            format!(
                                "applied the operator's change onto the node's desired state, \
                                 generation {}",
                                merged.generation
                            ),
                        ));
                    } else if ours != theirs {
                        events.push((
                            "hub".to_string(),
                            format!(
                                "adopted the node's desired state, generation {}",
                                theirs.generation
                            ),
                        ));
                    }
                    row.desired = Some(merged);
                }
                (None, Some(applied), _) => {
                    events.push((
                        "hub".to_string(),
                        format!(
                            "adopted the node's desired state, generation {}",
                            applied.generation
                        ),
                    ));
                    row.desired = Some(applied.clone());
                }
                (Some(ours), Some(theirs), None) if theirs.generation > ours.generation => {
                    let desired = DesiredState {
                        generation: theirs.generation.saturating_add(1),
                        ..ours.clone()
                    };
                    events.push((
                        "hub".to_string(),
                        format!(
                            "the node applied generation {}, past this hub's {}: re-issued \
                             the desired state as generation {}",
                            theirs.generation, ours.generation, desired.generation
                        ),
                    ));
                    row.desired = Some(desired);
                }
                _ => {}
            }
            row.report = Some(report);
            row.last_seen = Some(now);
            // Kept apart from the row, which carries their count.
            if let Some(workloads) = workloads {
                let total = u32::try_from(workloads.listed.len())
                    .unwrap_or(u32::MAX)
                    .saturating_add(workloads.omitted);
                row.workloads = Some(total);
                txn.open_table(WORKLOADS)?
                    .insert(id, encode(&workloads)?.as_slice())?;
            }
            let durability = if events.is_empty() {
                durability
            } else {
                Durability::Immediate
            };
            Ok(((), events, durability))
        })
    }

    /// Change what the hub wants of node `id` by `change`, from the defaults — no ceiling,
    /// acquisition running — when nothing was wanted yet, audited as `actor` doing `what`. A
    /// change takes the next generation after both the hub's and the one the node last reported
    /// applying, so it is newer to the node whatever the hub has forgotten; one that changes
    /// nothing is not stored. While the hub knows nothing the node applied, a change made on
    /// the defaults is recorded as set, even to a default value, so that
    /// [`Db::record_report`] applies it onto the node's state once reported. Returns the new
    /// desired state, or `None` when it was already so. A node only monitored is refused
    /// ([`MonitoringOnly`]).
    pub fn set_desired(
        &self,
        id: &str,
        change: DesiredChange,
        actor: &str,
        what: &str,
        now: u64,
    ) -> Result<Option<DesiredState>> {
        self.update_txn(now, id, |row, _| {
            steerable(id, row)?;
            let applied = row.report.as_ref().and_then(Report::applied_generation);
            let mut set = row
                .set_on_defaults
                .or_else(|| (row.desired.is_none() && applied.is_none()).then(SetFields::default));
            let before = row.desired.clone().unwrap_or(DEFAULT_DESIRED);
            let mut next = before.clone();
            let newly_set = match change {
                DesiredChange::Ceiling(ceiling) => {
                    next.ceiling = ceiling;
                    set.as_mut()
                        .is_some_and(|s| !std::mem::replace(&mut s.ceiling, true))
                }
                DesiredChange::Acquisition(acquisition) => {
                    next.acquisition = acquisition;
                    set.as_mut()
                        .is_some_and(|s| !std::mem::replace(&mut s.acquisition, true))
                }
            };
            if next == before && !newly_set {
                // The unchanged row is still written back, without an fsync.
                return Ok((None, Vec::new(), Durability::None));
            }
            next.generation = before
                .generation
                .max(applied.unwrap_or(0))
                .saturating_add(1);
            row.desired = Some(next.clone());
            row.set_on_defaults = set;
            let event = format!("{actor} {what} (generation {})", next.generation);
            Ok((
                Some(next),
                vec![(actor.to_string(), event)],
                Durability::Immediate,
            ))
        })
    }

    /// Issue `op` to node `id`, valid for `ttl`, audited as `actor`'s. The node must be
    /// enrolled and not only monitored ([`MonitoringOnly`]). Its commands settled longer than
    /// [`COMMAND_KEEP`] ago go in the same write.
    pub fn issue_command(
        &self,
        id: &str,
        op: Operation,
        ttl: Duration,
        actor: &str,
        now: u64,
    ) -> Result<Command> {
        let command = Command {
            id: crate::random_hex(vk_hub_proto::ID_BYTES)?,
            expires_at: now.saturating_add(ttl.as_secs()),
            op,
        };
        let mut row = CommandRow {
            command: command.clone(),
            issued_at: now,
            seq: 0,
            outcome: None,
            outcome_at: None,
        };
        let txn = self.db.begin_write().context("starting a write")?;
        {
            let node = txn
                .open_table(NODES)?
                .get(id)?
                .map(|g| decode::<NodeRow>(g.value()))
                .transpose()?;
            let Some(node) = node else {
                return Err(NotEnrolled(id.to_string()).into());
            };
            steerable(id, &node)?;
            let mut commands = txn.open_table(COMMANDS)?;
            let (start, end) = command_range(id);
            commands.retain_in(start.as_str()..end.as_str(), |_, value| {
                decode::<CommandRow>(value).map_or(true, |r| !r.settled_before(now, COMMAND_KEEP))
            })?;
            for entry in commands.range(start.as_str()..end.as_str())? {
                let seq = decode::<CommandRow>(entry?.1.value())?.seq;
                row.seq = row.seq.max(seq.saturating_add(1));
            }
            let key = format!("{id}/{}", command.id);
            commands.insert(key.as_str(), encode(&row)?.as_slice())?;
            let event = format!(
                "{actor} issued {} (command {})",
                operation_name(&command.op),
                command.id
            );
            append_audit(&txn, Some(id), actor, &event, now)?;
        }
        txn.commit().context("issuing a command")?;
        Ok(command)
    }

    /// Node `id`'s commands still to deliver or finish, oldest first, leaving out those past
    /// their expiry that it never answered: it would only refuse them.
    pub fn pending_commands(&self, id: &str, now: u64) -> Result<Vec<Command>> {
        let mut rows = self.node_commands(id)?;
        rows.retain(|r| r.live(now));
        Ok(rows.into_iter().map(|r| r.command).collect())
    }

    /// Every command of node `id`, oldest first.
    pub fn node_commands(&self, id: &str) -> Result<Vec<CommandRow>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(COMMANDS)?;
        let (start, end) = command_range(id);
        let mut out = Vec::new();
        for entry in table.range(start.as_str()..end.as_str())? {
            let (_, value) = entry?;
            out.push(decode::<CommandRow>(value.value())?);
        }
        out.sort_by_key(|r| (r.seq, r.issued_at));
        Ok(out)
    }

    /// Store and audit node `id`'s outcome for command `ack.id`. Return `false` for duplicate
    /// outcomes, unknown commands or any ack after a final outcome: a late `accepted` must
    /// not reopen a finished command.
    pub fn record_ack(&self, id: &str, ack: &CommandAck, now: u64) -> Result<bool> {
        let key = format!("{id}/{}", ack.id);
        let outcome = display_safe_outcome(ack.outcome.clone());
        let txn = self.db.begin_write().context("starting a write")?;
        let news = {
            let mut table = txn.open_table(COMMANDS)?;
            let row = table
                .get(key.as_str())?
                .map(|g| decode::<CommandRow>(g.value()))
                .transpose()?;
            match row {
                // A final outcome stays: nothing the node sends after it replaces it.
                Some(mut row) if row.pending() && row.outcome.as_ref() != Some(&outcome) => {
                    row.outcome = Some(outcome.clone());
                    row.outcome_at = Some(now);
                    table.insert(key.as_str(), encode(&row)?.as_slice())?;
                    Some(row.command)
                }
                _ => None,
            }
        };
        // Acks are not paced: one that changes nothing must not cost a commit.
        let Some(command) = news else {
            txn.abort().context("dropping a write")?;
            return Ok(false);
        };
        let event = format!(
            "command {} ({}): {}",
            command.id,
            operation_name(&command.op),
            outcome_text(&outcome)
        );
        append_audit(&txn, Some(id), "node", &event, now)?;
        txn.commit().context("recording an ack")?;
        Ok(true)
    }

    /// Record release `sha256`, whose binary is already in place, audited as `actor`'s. A
    /// release already recorded is refused: its version is what nodes were told, and replacing
    /// it under a command in flight would change what that command means.
    pub fn add_release(&self, sha256: &str, row: &ReleaseRow, actor: &str) -> Result<()> {
        let txn = self.db.begin_write().context("starting a write")?;
        {
            let mut table = txn.open_table(RELEASES)?;
            if let Some(existing) = table.get(sha256)? {
                let existing = decode::<ReleaseRow>(existing.value())?;
                bail!(
                    "release {sha256} is already held, as vk {}",
                    existing.version
                );
            }
            table.insert(sha256, encode(row)?.as_slice())?;
            let event = format!(
                "{actor} added release {} as vk {}",
                short(sha256),
                row.version
            );
            append_audit(&txn, None, actor, &event, row.added_at)?;
        }
        txn.commit().context("recording a release")
    }

    pub fn release(&self, sha256: &str) -> Result<Option<ReleaseRow>> {
        let txn = self.db.begin_read().context("starting a read")?;
        txn.open_table(RELEASES)?
            .get(sha256)?
            .map(|g| decode::<ReleaseRow>(g.value()))
            .transpose()
    }

    /// Every release, newest first.
    pub fn releases(&self) -> Result<Vec<Release>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(RELEASES)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            out.push(Release {
                sha256: key.value().to_string(),
                row: decode(value.value())?,
            });
        }
        out.sort_by(|a, b| (b.row.added_at, &b.sha256).cmp(&(a.row.added_at, &a.sha256)));
        Ok(out)
    }

    /// The one release whose sha256 starts with `prefix`, of at least 8 lowercase hex digits.
    pub fn resolve_release(&self, prefix: &str) -> Result<Release> {
        if prefix.len() < 8
            || !prefix
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            bail!(
                "{}: name a release by its sha256, or at least its first 8 hex digits",
                vk_hub_proto::display_safe(prefix)
            );
        }
        let mut found = self
            .releases()?
            .into_iter()
            .filter(|r| r.sha256.starts_with(prefix));
        match (found.next(), found.next()) {
            (Some(r), None) => Ok(r),
            (None, _) => bail!("there is no release {prefix}"),
            (Some(_), Some(_)) => bail!("{prefix} names more than one release; give more digits"),
        }
    }

    /// Forget release `sha256`, audited as `actor`'s, unless a command still to finish
    /// updates a node to it. `Ok(false)` when there was no such release.
    pub fn remove_release(&self, sha256: &str, actor: &str, now: u64) -> Result<bool> {
        let txn = self.db.begin_write().context("starting a write")?;
        let removed = {
            for entry in txn.open_table(COMMANDS)?.iter()? {
                let (key, value) = entry?;
                let row = decode::<CommandRow>(value.value())?;
                if row.updates_to(sha256, now) {
                    let key = key.value();
                    bail!(
                        "node {} is still being updated to this release (command {})",
                        key.split_once('/').map_or(key, |(node, _)| node),
                        row.command.id
                    );
                }
            }
            let removed = txn.open_table(RELEASES)?.remove(sha256)?.is_some();
            if removed {
                let event = format!("{actor} removed release {}", short(sha256));
                append_audit(&txn, None, actor, &event, now)?;
            }
            removed
        };
        txn.commit().context("removing a release")?;
        Ok(removed)
    }

    /// Whether node `id` has a command still to finish that updates it to `sha256`: the one
    /// thing a node's download of that release is allowed for.
    pub fn updating_to(&self, id: &str, sha256: &str, now: u64) -> Result<bool> {
        Ok(self
            .node_commands(id)?
            .iter()
            .any(|c| c.updates_to(sha256, now)))
    }

    /// The last `limit` audit lines, oldest first, of one node or of all.
    #[cfg(test)]
    pub fn audits(&self, node: Option<&str>, limit: usize) -> Result<Vec<AuditRow>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(AUDIT)?;
        let mut out = Vec::new();
        match node {
            None => {
                for entry in table.iter()?.rev().take(limit) {
                    out.push(decode::<AuditRow>(entry?.1.value())?);
                }
            }
            Some(node) => {
                let index = txn.open_table(AUDIT_BY_NODE)?;
                for entry in index.range((node, 0)..=(node, u64::MAX))?.rev().take(limit) {
                    let seq = entry?.0.value().1;
                    if let Some(row) = table.get(seq)? {
                        out.push(decode::<AuditRow>(row.value())?);
                    }
                }
            }
        }
        out.reverse();
        Ok(out)
    }

    /// Issue a single-use sign-in link's token for the web UI, for `role`, valid for `ttl`.
    /// Returns the token — shown once, stored only as its hash — and when it expires. Expired
    /// ones are swept in the same write.
    pub fn create_login(
        &self,
        role: Role,
        ttl: Duration,
        actor: &str,
        now: u64,
    ) -> Result<(String, u64)> {
        if ttl.is_zero() || ttl > MAX_LOGIN_TTL {
            bail!(
                "a sign-in link's lifetime must be between 1s and {}h",
                MAX_LOGIN_TTL.as_secs() / 3600
            );
        }
        let token = format!("{LOGIN_PREFIX}{}", crate::random_hex(32)?);
        let expires_at = now.saturating_add(ttl.as_secs());
        let txn = self.db.begin_write().context("starting a write")?;
        {
            let mut table = txn.open_table(UI_LOGINS)?;
            table.retain(|_, value| decode::<LoginRow>(value).is_ok_and(|r| r.expires_at > now))?;
            let row = LoginRow {
                role,
                issued_by: actor.to_string(),
                expires_at,
            };
            table.insert(token_key(&token).as_str(), encode(&row)?.as_slice())?;
        }
        append_audit(
            &txn,
            None,
            actor,
            &format!(
                "{actor} issued a sign-in link for the {} role, valid for {}s",
                role.name(),
                ttl.as_secs()
            ),
            now,
        )?;
        txn.commit().context("storing a sign-in link")?;
        Ok((token, expires_at))
    }

    /// Spend sign-in token `token` on a new web UI session. Returns the session's secret — the
    /// cookie, stored only as its hash — and the session, or `None` for a token that is
    /// unknown, spent or expired. Looked up in a read first, as an enrollment token is, so a
    /// guess costs no write.
    pub fn redeem_login(&self, token: &str, now: u64) -> Result<Option<(String, UiSession)>> {
        let key = token_key(token);
        {
            let txn = self.db.begin_read().context("starting a read")?;
            let live = txn
                .open_table(UI_LOGINS)?
                .get(key.as_str())?
                .map(|g| decode::<LoginRow>(g.value()))
                .transpose()?
                .is_some_and(|row| row.expires_at > now);
            if !live {
                return Ok(None);
            }
        }
        let txn = self.db.begin_write().context("starting a write")?;
        let session = {
            let row = txn
                .open_table(UI_LOGINS)?
                .remove(key.as_str())?
                .map(|g| decode::<LoginRow>(g.value()))
                .transpose()?;
            match row {
                Some(login) if login.expires_at > now => {
                    let secret = crate::random_hex(32)?;
                    let session_key = token_key(&secret);
                    let row = UiSessionRow {
                        role: login.role,
                        issued_by: login.issued_by,
                        created_at: now,
                        expires_at: now.saturating_add(UI_SESSION_TTL.as_secs()),
                    };
                    let mut sessions = txn.open_table(UI_SESSIONS)?;
                    sessions.retain(|_, value| {
                        decode::<UiSessionRow>(value).is_ok_and(|r| r.expires_at > now)
                    })?;
                    sessions.insert(session_key.as_str(), encode(&row)?.as_slice())?;
                    let session = UiSession::new(&session_key, row);
                    let event = format!(
                        "{} signed in with a link {} issued",
                        session.principal(),
                        session.issued_by
                    );
                    append_audit(&txn, None, &session.principal(), &event, now)?;
                    Some((secret, session))
                }
                _ => None,
            }
        };
        txn.commit().context("opening a web UI session")?;
        Ok(session)
    }

    /// The live web UI session whose cookie is `secret`.
    pub fn ui_session(&self, secret: &str, now: u64) -> Result<Option<UiSession>> {
        let key = token_key(secret);
        let txn = self.db.begin_read().context("starting a read")?;
        let row = match txn.open_table(UI_SESSIONS)?.get(key.as_str())? {
            Some(value) => match decode::<UiSessionRow>(value.value()) {
                Ok(row) => Some(row),
                // As in the listing: one that does not decode opens nothing.
                Err(e) => {
                    eprintln!("vk-hub: warning: a web UI session row does not decode: {e:#}");
                    None
                }
            },
            None => None,
        };
        Ok(row
            .filter(|r| r.expires_at > now)
            .map(|r| UiSession::new(&key, r)))
    }

    /// Every live web UI session, oldest first.
    pub fn ui_sessions(&self, now: u64) -> Result<Vec<UiSession>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(UI_SESSIONS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            // One that does not decode opens nothing, and goes at the next write that sweeps.
            let row = match decode::<UiSessionRow>(value.value()) {
                Ok(row) => row,
                Err(e) => {
                    eprintln!("vk-hub: warning: skipping a web UI session row: {e:#}");
                    continue;
                }
            };
            if row.expires_at > now {
                out.push(UiSession::new(key.value(), row));
            }
        }
        out.sort_by_key(|s| s.created_at);
        Ok(out)
    }

    /// End every web UI session listed as `id` — more than one where they share it — or every
    /// one with `None`, audited as `actor`'s. Returns how many ended.
    pub fn end_ui_sessions(&self, id: Option<&str>, actor: &str, now: u64) -> Result<usize> {
        self.end_sessions(
            |_, session| id.is_none_or(|id| id == session.id),
            actor,
            now,
        )
    }

    /// End the web UI session whose cookie is `secret`, audited as `actor`'s. Returns how many
    /// ended: one, or none for a session already gone.
    pub fn end_ui_session(&self, secret: &str, actor: &str, now: u64) -> Result<usize> {
        let key = token_key(secret);
        self.end_sessions(|k, _| k == key, actor, now)
    }

    /// End the sessions `ends` picks by key and session, dropping every row that does not
    /// decode on the way.
    fn end_sessions(
        &self,
        ends: impl Fn(&str, &UiSession) -> bool,
        actor: &str,
        now: u64,
    ) -> Result<usize> {
        let txn = self.db.begin_write().context("starting a write")?;
        let mut ended = Vec::new();
        {
            let mut table = txn.open_table(UI_SESSIONS)?;
            table.retain(|key, value| {
                let Ok(row) = decode::<UiSessionRow>(value) else {
                    return false;
                };
                let session = UiSession::new(key, row);
                if ends(key, &session) {
                    // An expired one goes silently: it had ended already.
                    if session.expires_at > now {
                        ended.push(session.principal());
                    }
                    return false;
                }
                true
            })?;
        }
        for principal in &ended {
            let event = if principal == actor {
                format!("{principal} signed out")
            } else {
                format!("{actor} ended {principal}")
            };
            append_audit(&txn, None, actor, &event, now)?;
        }
        txn.commit().context("ending web UI sessions")?;
        Ok(ended.len())
    }

    /// Void every unspent sign-in link, recorded as `actor`'s doing. Returns how many.
    pub fn end_ui_logins(&self, actor: &str, now: u64) -> Result<usize> {
        let txn = self.db.begin_write().context("starting a write")?;
        let mut live = 0;
        txn.open_table(UI_LOGINS)?.retain(|_, value| {
            // An expired one goes silently: it had ended already.
            live += usize::from(decode::<LoginRow>(value).is_ok_and(|r| r.expires_at > now));
            false
        })?;
        if live > 0 {
            let event = format!("{actor} voided {live} unspent sign-in link(s)");
            append_audit(&txn, None, actor, &event, now)?;
        }
        txn.commit().context("voiding sign-in links")?;
        Ok(live)
    }

    /// Up to `limit` audit lines older than sequence number `before` — all of them for
    /// `None` — of one node or of all, newest first, each with its sequence number for the
    /// next page.
    pub fn audit_page(
        &self,
        node: Option<&str>,
        before: Option<u64>,
        limit: usize,
    ) -> Result<Vec<(u64, AuditRow)>> {
        let before = before.unwrap_or(u64::MAX);
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(AUDIT)?;
        let mut out = Vec::new();
        match node {
            None => {
                for entry in table.range(..before)?.rev().take(limit) {
                    let (seq, value) = entry?;
                    out.push((seq.value(), decode::<AuditRow>(value.value())?));
                }
            }
            Some(node) => {
                let index = txn.open_table(AUDIT_BY_NODE)?;
                for entry in index.range((node, 0)..(node, before))?.rev().take(limit) {
                    let seq = entry?.0.value().1;
                    if let Some(row) = table.get(seq)? {
                        out.push((seq, decode::<AuditRow>(row.value())?));
                    }
                }
            }
        }
        Ok(out)
    }

    /// Rewrite a node's row and append the `(actor, event)` audit pairs returned by `change`
    /// in one transaction. `change` can write other tables and selects the durability.
    /// Return [`NotEnrolled`] if the node was removed: the hub no longer recognizes its
    /// session.
    fn update_txn<R>(
        &self,
        now: u64,
        id: &str,
        change: impl FnOnce(
            &mut NodeRow,
            &redb::WriteTransaction,
        ) -> Result<(R, Vec<(String, String)>, Durability)>,
    ) -> Result<R> {
        let mut txn = self.db.begin_write().context("starting a write")?;
        let (out, durability) = {
            let mut table = txn.open_table(NODES)?;
            let mut row = match table.get(id)? {
                Some(g) => decode::<NodeRow>(g.value())?,
                None => return Err(NotEnrolled(id.to_string()).into()),
            };
            let (out, events, durability) = change(&mut row, &txn)?;
            table.insert(id, encode(&row)?.as_slice())?;
            for (actor, event) in events {
                append_audit(&txn, Some(id), &actor, &event, now)?;
            }
            (out, durability)
        };
        txn.set_durability(durability)
            .context("setting a write's durability")?;
        txn.commit().context("updating a node")?;
        Ok(out)
    }
}

/// What the hub wants of a node it has asked nothing of.
const DEFAULT_DESIRED: DesiredState = DesiredState {
    generation: 0,
    ceiling: None,
    acquisition: Acquisition::Run,
};

/// The key range of node `id`'s commands.
fn command_range(id: &str) -> (String, String) {
    // `0` is the character after `/`.
    (format!("{id}/"), format!("{id}0"))
}

/// Every node in `txn`, by ID.
fn nodes_in(txn: &redb::ReadTransaction) -> Result<Vec<(String, NodeRow)>> {
    let table = txn.open_table(NODES)?;
    let mut out = Vec::new();
    for entry in table.iter()? {
        let (key, value) = entry?;
        // One that does not decode is left out rather than failing the whole listing.
        match decode::<NodeRow>(value.value()) {
            Ok(row) => out.push((key.value().to_string(), row)),
            Err(e) => eprintln!(
                "vk-hub: warning: skipping node {}: {e:#}",
                vk_hub_proto::display_safe(key.value())
            ),
        }
    }
    Ok(out)
}

/// Node `id`'s workloads in `txn`, with their memory readings; `None` until a report listed
/// them.
fn workloads_in(txn: &redb::ReadTransaction, id: &str) -> Result<Option<Workloads>> {
    let Some(listed) = txn.open_table(WORKLOADS)?.get(id)? else {
        return Ok(None);
    };
    // One that does not decode is left out rather than failing the whole listing, as
    // [`nodes_in`] leaves out a node's row.
    let warn = |what: &str, e: anyhow::Error| {
        eprintln!(
            "vk-hub: warning: skipping node {}'s {what}: {e:#}",
            vk_hub_proto::display_safe(id)
        );
    };
    let mut workloads: Workloads = match decode(listed.value()) {
        Ok(w) => w,
        Err(e) => {
            warn("workloads", e);
            return Ok(None);
        }
    };
    if let Some(mem) = txn.open_table(WORKLOAD_MEM)?.get(id)? {
        match decode(mem.value()) {
            Ok(mem) => workloads.mem_bytes = mem,
            Err(e) => warn("workload memory readings", e),
        }
    }
    Ok(Some(workloads))
}

/// Append an audit row inside `txn`, dropping the oldest past [`AUDIT_MAX`].
fn append_audit(
    txn: &redb::WriteTransaction,
    node: Option<&str>,
    actor: &str,
    event: &str,
    now: u64,
) -> Result<()> {
    let row = AuditRow {
        at: now,
        node: node.map(str::to_string),
        actor: actor.to_string(),
        event: vk_hub_proto::display_safe(event),
    };
    let mut table = txn.open_table(AUDIT)?;
    let mut index = txn.open_table(AUDIT_BY_NODE)?;
    let seq = table
        .last()?
        .map_or(0, |(k, _)| k.value().saturating_add(1));
    table.insert(seq, encode(&row)?.as_slice())?;
    if let Some(node) = node {
        index.insert((node, seq), ())?;
    }
    let first = table.first()?.map_or(seq, |(k, _)| k.value());
    if seq.saturating_sub(first) >= AUDIT_MAX {
        let cut = first.saturating_add(AUDIT_PRUNE);
        let mut dropped = Vec::new();
        for entry in table.range(first..cut)? {
            let (k, v) = entry?;
            dropped.push((k.value(), decode::<AuditRow>(v.value())?.node));
        }
        for (seq, node) in dropped {
            table.remove(seq)?;
            if let Some(node) = node {
                index.remove((node.as_str(), seq))?;
            }
        }
    }
    Ok(())
}

/// Audit changes in state, applied generation, update phase, what the node cannot carry out,
/// and concurrency errors.
fn report_events(previous: Option<&Report>, report: &Report) -> Vec<String> {
    let mut events = Vec::new();
    if previous.is_none_or(|p| p.state != report.state)
        && let Some(state) = report.state
    {
        events.push(format!("state {}", state_name(state)));
    }
    if previous.is_none_or(|p| p.applied_generation() != report.applied_generation())
        && let Some(generation) = report.applied_generation()
    {
        events.push(format!("applied generation {generation}"));
    }
    if previous.is_none_or(|p| p.unsupported != report.unsupported) {
        for note in &report.unsupported {
            events.push(format!("cannot comply: {note}"));
        }
    }
    if let Some(u) = &report.update
        && previous.is_none_or(|p| {
            p.update.as_ref().map(|u| (&u.command, u.phase)) != Some((&u.command, u.phase))
        })
    {
        let mut event = format!(
            "update to vk {} ({}): {}",
            u.version,
            short(&u.sha256),
            update_phase_name(u.phase)
        );
        if let Some(message) = &u.message {
            event.push_str(&format!(": {message}"));
        }
        events.push(event);
    }
    if previous.is_none_or(|p| p.concurrency_error != report.concurrency_error)
        && let Some(error) = &report.concurrency_error
    {
        events.push(format!("cannot set its concurrency: {error}"));
    }
    events
}

pub(crate) fn state_name(state: NodeState) -> &'static str {
    match state {
        NodeState::Ready => "ready",
        NodeState::Draining => "draining",
        NodeState::Drained => "drained",
        NodeState::Maintenance => "maintenance",
        NodeState::Validating => "validating",
        NodeState::Quarantined => "quarantined",
    }
}

pub(crate) fn update_phase_name(phase: vk_hub_proto::UpdatePhase) -> &'static str {
    use vk_hub_proto::UpdatePhase;
    match phase {
        UpdatePhase::Draining => "draining",
        UpdatePhase::Downloading => "downloading",
        UpdatePhase::Validating => "validating",
        UpdatePhase::Done => "done",
        UpdatePhase::RolledBack => "rolled back",
        UpdatePhase::Failed => "failed",
    }
}

pub(crate) fn operation_name(op: &Operation) -> String {
    match op {
        Operation::Drain => "drain".into(),
        Operation::Undrain => "undrain".into(),
        Operation::Quarantine => "quarantine".into(),
        Operation::Release => "release".into(),
        Operation::Update {
            version, sha256, ..
        } => format!(
            "update to vk {} ({})",
            vk_hub_proto::display_safe(version),
            vk_hub_proto::display_safe(short(sha256))
        ),
    }
}

/// A sha256's first 12 hex digits, as releases are named in lines people read.
pub(crate) fn short(sha256: &str) -> &str {
    sha256.get(..12).unwrap_or(sha256)
}

fn outcome_text(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Accepted => "accepted".into(),
        Outcome::Done => "done".into(),
        Outcome::Failed { message } => format!("failed: {message}"),
        Outcome::Refused { reason } => format!("refused: {reason}"),
        Outcome::Expired => "expired".into(),
    }
}

/// `outcome` with the node's text in it made [`vk_hub_proto::display_safe`].
fn display_safe_outcome(outcome: Outcome) -> Outcome {
    use vk_hub_proto::display_safe as safe;
    match outcome {
        Outcome::Failed { message } => Outcome::Failed {
            message: safe(&message),
        },
        Outcome::Refused { reason } => Outcome::Refused {
            reason: safe(&reason),
        },
        other => other,
    }
}

/// A token's key in [`TOKENS`], and a sign-in token's or session secret's in its table.
pub(crate) fn token_key(token: &str) -> String {
    vk_hub_proto::to_hex(&Sha256::digest(token.as_bytes()))
}

/// `inventory` with every string in it made [`vk_hub_proto::display_safe`], and each list cut
/// to [`MAX_INVENTORY_ITEMS`].
fn display_safe_inventory(mut inventory: Inventory) -> Inventory {
    use vk_hub_proto::display_safe as safe;
    let clean = |s: &mut String| *s = safe(s);
    let clean_opt = |s: &mut Option<String>| {
        if let Some(v) = s.as_mut() {
            *v = safe(v);
        }
    };
    inventory.hardware.checks.truncate(MAX_INVENTORY_ITEMS);
    inventory
        .hardware
        .memory_nodes
        .truncate(MAX_INVENTORY_ITEMS);
    inventory.storage.truncate(MAX_INVENTORY_ITEMS);
    if let Some(runner) = inventory.runner.as_mut() {
        runner.runners.truncate(MAX_INVENTORY_ITEMS);
    }
    clean(&mut inventory.hostname);
    clean_opt(&mut inventory.hardware.cpu_model);
    for check in &mut inventory.hardware.checks {
        clean(&mut check.name);
        clean(&mut check.detail);
    }
    for fs in &mut inventory.storage {
        clean(&mut fs.path);
        clean(&mut fs.device);
    }
    clean(&mut inventory.versions.vk);
    clean_opt(&mut inventory.versions.guest_kernel);
    clean(&mut inventory.versions.config_hash);
    let sha = &mut inventory.versions.vk_sha256;
    if sha
        .as_deref()
        .is_some_and(|s| !vk_hub_proto::valid_sha256(s))
    {
        *sha = None;
    }
    if let Some(runner) = inventory.runner.as_mut() {
        clean(&mut runner.config);
        for name in &mut runner.runners {
            clean(name);
        }
    }
    inventory
}

/// `report`'s strings made display-safe, its list cut like an inventory's. An update whose
/// command ID or sha256 is malformed is dropped: both are identifiers, not text.
fn display_safe_report(mut report: Report) -> Report {
    report.unsupported.truncate(MAX_INVENTORY_ITEMS);
    report.update = report
        .update
        .filter(|u| vk_hub_proto::valid_id(&u.command) && vk_hub_proto::valid_sha256(&u.sha256));
    let mut update = Vec::new();
    if let Some(u) = report.update.as_mut() {
        update.push(&mut u.version);
        update.extend(u.message.as_mut());
    }
    for s in report
        .unsupported
        .iter_mut()
        .chain(report.concurrency_error.as_mut())
        .chain(update)
    {
        *s = vk_hub_proto::display_safe(s);
    }
    report
}

/// `heartbeat` cut to what an inventory may hold: [`MAX_INVENTORY_ITEMS`] filesystems, and
/// the memory of at most [`vk_hub_proto::MAX_WORKLOADS`] workloads, each keyed by an ID of
/// the shape `vk` gives one — anything else is dropped rather than stored for display.
fn bound_heartbeat(mut heartbeat: Heartbeat) -> Heartbeat {
    heartbeat.storage.truncate(MAX_INVENTORY_ITEMS);
    let mem = std::mem::take(&mut heartbeat.workload_mem_bytes);
    heartbeat.workload_mem_bytes = mem
        .into_iter()
        .filter(|(id, _)| vk_hub_proto::is_workload_id(id))
        .take(vk_hub_proto::MAX_WORKLOADS)
        .collect();
    heartbeat
}

fn encode<T: Serialize>(row: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(row).context("encoding a row")
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).context("decoding a row")
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: Duration = Duration::from_secs(86_400);

    #[test]
    fn a_token_enrolls_exactly_one_node() {
        let db = Db::open_memory().unwrap();
        let (token, expires) = db.create_token(DAY, "uid 0", 1000).unwrap();
        assert!(token.starts_with(TOKEN_PREFIX));
        assert_eq!(expires, 1000 + 86_400);
        let Enrollment::Enrolled { node_id } =
            db.enroll(&token, "aa", "ci-1", "peer p", 1001).unwrap()
        else {
            panic!("expected an enrollment");
        };
        assert!(vk_hub_proto::valid_id(&node_id));
        assert_eq!(
            db.enroll(&token, "bb", "ci-2", "peer p", 1002).unwrap(),
            Enrollment::BadToken
        );
        let row = db.node(&node_id).unwrap().unwrap();
        assert_eq!(
            (row.public_key.as_str(), row.hostname.as_str()),
            ("aa", "ci-1")
        );
        assert_eq!(db.nodes().unwrap().len(), 1);
    }

    #[test]
    fn an_expired_or_unknown_token_enrolls_nothing() {
        let db = Db::open_memory().unwrap();
        let (token, expires) = db
            .create_token(Duration::from_secs(60), "uid 0", 1000)
            .unwrap();
        assert_eq!(
            db.enroll(&token, "aa", "h", "peer p", expires).unwrap(),
            Enrollment::BadToken
        );
        assert_eq!(
            db.enroll("vkh_nope", "aa", "h", "peer p", 1000).unwrap(),
            Enrollment::BadToken
        );
        assert!(db.nodes().unwrap().is_empty());
    }

    #[test]
    fn a_pinned_key_enrolls_again_as_its_node_and_a_removed_one_anew() {
        let db = Db::open_memory().unwrap();
        let (t1, _) = db.create_token(DAY, "uid 0", 0).unwrap();
        let (t2, _) = db.create_token(DAY, "uid 0", 0).unwrap();
        let (t3, _) = db.create_token(DAY, "uid 0", 0).unwrap();
        let Enrollment::Enrolled { node_id } = db.enroll(&t1, "aa", "h", "peer p", 1).unwrap()
        else {
            panic!("expected an enrollment");
        };
        assert_eq!(
            db.enroll(&t2, "aa", "h", "peer p", 1).unwrap(),
            Enrollment::Reenrolled {
                node_id: node_id.clone()
            }
        );
        // The second token is spent by it all the same.
        assert_eq!(
            db.enroll(&t2, "bb", "h", "peer p", 1).unwrap(),
            Enrollment::BadToken
        );
        assert_eq!(db.nodes().unwrap().len(), 1);
        assert!(db.remove_node(&node_id, "uid 0", 2).unwrap());
        assert!(!db.remove_node(&node_id, "uid 0", 2).unwrap());
        let Enrollment::Enrolled { node_id: again } =
            db.enroll(&t3, "aa", "h", "peer p", 1).unwrap()
        else {
            panic!("expected a new enrollment");
        };
        assert_ne!(again, node_id);
    }

    #[test]
    fn tokens_enrollments_and_removals_are_audited() {
        let db = Db::open_memory().unwrap();
        let (t1, _) = db.create_token(DAY, "uid 7", 0).unwrap();
        let (t2, _) = db.create_token(DAY, "uid 7", 0).unwrap();
        let Enrollment::Enrolled { node_id } = db
            .enroll(&t1, "aa", "ci-1", "peer 10.0.0.1:4000", 1)
            .unwrap()
        else {
            panic!("expected an enrollment");
        };
        db.enroll(&t2, "aa", "ci-1", "peer 10.0.0.1:4001", 2)
            .unwrap();
        assert!(db.remove_node(&node_id, "uid 7", 3).unwrap());
        let events = |node: Option<&str>| -> Vec<(String, String)> {
            db.audits(node, 10)
                .unwrap()
                .into_iter()
                .map(|r| (r.actor, r.event))
                .collect()
        };
        assert_eq!(
            events(Some(&node_id)),
            [
                (
                    "peer 10.0.0.1:4000".to_string(),
                    format!("node {node_id} enrolled as ci-1")
                ),
                (
                    "peer 10.0.0.1:4001".to_string(),
                    format!("node {node_id} enrolled again with its pinned key")
                ),
                ("uid 7".to_string(), format!("uid 7 removed node {node_id}")),
            ]
        );
        let all = events(None);
        assert_eq!(all.len(), 5, "{all:?}");
        assert_eq!(
            all[0],
            (
                "uid 7".to_string(),
                "uid 7 issued an enrollment token valid for 86400s".to_string()
            )
        );
    }

    #[test]
    fn an_inventory_is_bounded_and_an_empty_hostname_keeps_the_enrolled_one() {
        let db = Db::open_memory().unwrap();
        let (token, _) = db.create_token(DAY, "uid 0", 0).unwrap();
        let Enrollment::Enrolled { node_id } =
            db.enroll(&token, "aa", "ci-1", "peer p", 1).unwrap()
        else {
            panic!("expected an enrollment");
        };
        let many = MAX_INVENTORY_ITEMS + 10;
        let filesystem = vk_hub_proto::Filesystem {
            role: vk_hub_proto::StorageRole::Jobs,
            path: "/srv".into(),
            device: "8:1".into(),
            size_bytes: 1,
            tmpfs: false,
            speed: None,
        };
        let inventory = Inventory {
            hostname: "\u{1b}".into(),
            hardware: vk_hub_proto::Hardware {
                checks: vec![vk_hub_proto::Check::default(); many],
                memory_nodes: vec![vk_hub_proto::MemoryNode::default(); many],
                ..Default::default()
            },
            storage: vec![filesystem; many],
            runner: Some(vk_hub_proto::Runner {
                runners: vec!["r".into(); many],
                ..Default::default()
            }),
            ..Inventory::default()
        };
        db.record_inventory(&node_id, inventory, true, 2).unwrap();
        let row = db.node(&node_id).unwrap().unwrap();
        assert_eq!(row.hostname, "ci-1");
        let kept = row.inventory.unwrap();
        assert_eq!(kept.hostname, "");
        assert_eq!(kept.hardware.checks.len(), MAX_INVENTORY_ITEMS);
        assert_eq!(kept.hardware.memory_nodes.len(), MAX_INVENTORY_ITEMS);
        assert_eq!(kept.storage.len(), MAX_INVENTORY_ITEMS);
        assert_eq!(kept.runner.unwrap().runners.len(), MAX_INVENTORY_ITEMS);
    }

    #[test]
    fn a_heartbeat_is_bounded_to_workload_ids_and_filesystems() {
        let db = Db::open_memory().unwrap();
        let (token, _) = db.create_token(DAY, "uid 0", 0).unwrap();
        let Enrollment::Enrolled { node_id } = db.enroll(&token, "aa", "h", "peer p", 1).unwrap()
        else {
            panic!("expected an enrollment");
        };
        let usage = vk_hub_proto::FsUsage {
            role: vk_hub_proto::StorageRole::Jobs,
            free_bytes: 1,
            free_inodes: 1,
            inodes: 1,
        };
        let mut mem: std::collections::BTreeMap<String, u64> = (0..vk_hub_proto::MAX_WORKLOADS
            + 10)
            .map(|i| (format!("{i:016x}"), 1))
            .collect();
        for bad in ["0123456789ABCDEF", "\u{1b}[2J", "0123", &"ab".repeat(16)] {
            mem.insert(bad.to_string(), 1);
        }
        let heartbeat = Heartbeat {
            storage: vec![usage; MAX_INVENTORY_ITEMS + 10],
            workload_mem_bytes: mem,
            ..Heartbeat::default()
        };
        // Memory readings are shown with a listed workload.
        let listed = Report {
            workloads: Some(Vec::new()),
            ..Report::default()
        };
        db.record_report(&node_id, listed, 2).unwrap();
        db.record_heartbeat(&node_id, heartbeat, 2).unwrap();
        let kept = db.node(&node_id).unwrap().unwrap().heartbeat.unwrap();
        assert_eq!(kept.storage.len(), MAX_INVENTORY_ITEMS);
        let mem = db.workloads(&node_id).unwrap().unwrap().mem_bytes;
        assert_eq!(mem.len(), vk_hub_proto::MAX_WORKLOADS);
        assert!(mem.keys().all(|id| vk_hub_proto::is_workload_id(id)));
    }

    #[test]
    fn an_inventory_is_stored_and_an_unchanged_one_only_refreshes_last_seen() {
        let db = Db::open_memory().unwrap();
        let (token, _) = db.create_token(DAY, "uid 0", 0).unwrap();
        let Enrollment::Enrolled { node_id } = db.enroll(&token, "aa", "h", "peer p", 1).unwrap()
        else {
            panic!("expected an enrollment");
        };
        let inventory = Inventory {
            hostname: "ci-1".into(),
            ..Inventory::default()
        };
        db.record_inventory(&node_id, inventory.clone(), true, 2)
            .unwrap();
        db.record_inventory(&node_id, inventory.clone(), true, 3)
            .unwrap();
        let row = db.node(&node_id).unwrap().unwrap();
        assert_eq!(row.last_seen, Some(3));
        assert_eq!(row.inventory.as_ref(), Some(&inventory));
        // Not durable, and stored all the same.
        let changed = Inventory {
            hostname: "ci-2".into(),
            ..inventory
        };
        db.record_inventory(&node_id, changed.clone(), false, 4)
            .unwrap();
        let row = db.node(&node_id).unwrap().unwrap();
        assert_eq!((row.last_seen, row.inventory), (Some(4), Some(changed)));
        assert_eq!(row.hostname, "ci-2");
    }

    #[test]
    fn a_node_row_that_does_not_decode_is_left_out_of_the_listing() {
        let db = Db::open_memory().unwrap();
        let (token, _) = db.create_token(DAY, "uid 0", 0).unwrap();
        db.enroll(&token, "aa", "h", "peer p", 1).unwrap();
        let txn = db.db.begin_write().unwrap();
        txn.open_table(NODES)
            .unwrap()
            .insert("corrupt", b"not json".as_slice())
            .unwrap();
        txn.commit().unwrap();
        let nodes = db.nodes().unwrap();
        assert_eq!(nodes.len(), 1);
        assert_ne!(nodes[0].0, "corrupt");
    }

    #[test]
    fn a_heartbeat_a_minute_is_durable() {
        let db = Db::open_memory().unwrap();
        assert!(db.heartbeat_syncs(1000));
        assert!(!db.heartbeat_syncs(1000 + HEARTBEAT_SYNC_SECS - 1));
        assert!(db.heartbeat_syncs(1000 + HEARTBEAT_SYNC_SECS));
        assert!(!db.heartbeat_syncs(1000 + HEARTBEAT_SYNC_SECS));
    }

    #[test]
    fn token_lifetimes_are_bounded_and_expired_tokens_are_swept() {
        let db = Db::open_memory().unwrap();
        assert!(db.create_token(Duration::ZERO, "uid 0", 0).is_err());
        assert!(db.create_token(MAX_TOKEN_TTL + DAY, "uid 0", 0).is_err());
        db.create_token(Duration::from_secs(10), "uid 0", 0)
            .unwrap();
        db.create_token(DAY, "uid 0", 20).unwrap();
        let txn = db.db.begin_read().unwrap();
        let table = txn.open_table(TOKENS).unwrap();
        assert_eq!(redb::ReadableTableMetadata::len(&table).unwrap(), 1);
    }

    #[test]
    fn a_session_inventory_and_heartbeat_are_recorded() {
        let db = Db::open_memory().unwrap();
        let (token, _) = db.create_token(DAY, "uid 0", 0).unwrap();
        let Enrollment::Enrolled { node_id } = db.enroll(&token, "aa", "h", "peer p", 1).unwrap()
        else {
            panic!("expected an enrollment");
        };
        assert!(db.record_session(&node_id, "inc", 2, 2, || true).unwrap());
        assert!(!db.record_session(&node_id, "old", 1, 2, || false).unwrap());
        let inventory = Inventory {
            hostname: "renamed\u{1b}[2J".into(),
            versions: vk_hub_proto::Versions {
                vk: "0.80\u{202e}.0".into(),
                vk_sha256: Some("ab\u{1b}[2J".into()),
                ..Default::default()
            },
            ..Inventory::default()
        };
        db.record_inventory(&node_id, inventory, true, 3).unwrap();
        db.record_heartbeat(&node_id, Heartbeat::default(), 4)
            .unwrap();
        let row = db.node(&node_id).unwrap().unwrap();
        assert_eq!(row.incarnation.as_deref(), Some("inc"));
        assert_eq!(row.protocol, Some(2));
        assert_eq!(row.hostname, "renamed[2J");
        let versions = &row.inventory.as_ref().unwrap().versions;
        assert_eq!(versions.vk, "0.80.0");
        assert_eq!(versions.vk_sha256, None);
        assert_eq!((row.heartbeat_at, row.last_seen), (Some(4), Some(4)));
        assert!(row.inventory.is_some() && row.heartbeat.is_some());
        assert!(
            db.record_heartbeat("0".repeat(32).as_str(), Heartbeat::default(), 5)
                .is_err()
        );
    }

    /// A node's workloads are its report's latest, cut to the cap with every string made
    /// display-safe, kept apart from its row with a count on it; their memory readings are a
    /// bounded lookup; and neither is audited.
    #[test]
    fn workloads_are_stored_latest_only_bounded_and_display_safe() {
        use vk_hub_proto::{MAX_WORKLOADS, WorkloadKind};
        let db = Db::open_memory().unwrap();
        let id = enrolled(&db);
        assert_eq!(db.workloads(&id).unwrap(), None);
        let hostile = "a\u{1b}[2J\u{202e}<b>";
        let workload = |i: usize| Workload {
            id: format!("{i:016x}"),
            kind: WorkloadKind::CiJob,
            state_dir: hostile.into(),
            label: Some(hostile.into()),
            project: Some(hostile.into()),
            job_name: Some(hostile.into()),
            job_id: Some(hostile.into()),
            workspace: Some(hostile.into()),
            environment: Some(hostile.into()),
            pid: Some(1),
            cpus: Some(2),
            mem_reserved_mib: Some(1024),
            started_at: Some(5),
            ssh_alias: Some(hostile.into()),
            guest_workspace: Some(hostile.into()),
        };
        let report = |n: usize, omitted| Report {
            workloads: Some((0..n).map(workload).collect()),
            workloads_omitted: omitted,
            ..Report::default()
        };
        db.record_report(&id, report(MAX_WORKLOADS + 5, 7), 2)
            .unwrap();
        let row = db.node(&id).unwrap().unwrap();
        // The row keeps the count, those cut counted as left out.
        assert_eq!(row.workloads, Some(MAX_WORKLOADS as u32 + 12));
        let stored = db.workloads(&id).unwrap().unwrap();
        assert_eq!((stored.listed.len(), stored.omitted), (MAX_WORKLOADS, 12));
        let w = &stored.listed[0];
        for s in [
            &w.state_dir,
            w.label.as_ref().unwrap(),
            w.project.as_ref().unwrap(),
            w.job_name.as_ref().unwrap(),
            w.job_id.as_ref().unwrap(),
            w.workspace.as_ref().unwrap(),
            w.environment.as_ref().unwrap(),
        ] {
            assert_eq!(s, "a[2J<b>");
        }
        // What a link is built of is dropped rather than altered.
        assert_eq!((&w.ssh_alias, &w.guest_workspace), (&None, &None));
        // The next report replaces the list; a node stopping its VMs empties it; a report
        // that has not looked yet leaves the last one.
        db.record_report(&id, report(0, 0), 3).unwrap();
        db.record_report(&id, Report::default(), 4).unwrap();
        assert_eq!(db.node(&id).unwrap().unwrap().workloads, Some(0));
        assert_eq!(db.workloads(&id).unwrap().unwrap().listed, Vec::new());
        // Past the bytes a node may list, the rest are counted as left out.
        let long = || Some("x".repeat(vk_hub_proto::MAX_DISPLAY));
        let big = |i: usize| Workload {
            label: long(),
            project: long(),
            job_name: long(),
            job_id: long(),
            workspace: long(),
            environment: long(),
            ssh_alias: long(),
            guest_workspace: long(),
            ..workload(i)
        };
        let n = MAX_WORKLOADS;
        db.record_report(
            &id,
            Report {
                workloads: Some((0..n).map(big).collect()),
                workloads_omitted: 1,
                ..Report::default()
            },
            4,
        )
        .unwrap();
        let stored = db.workloads(&id).unwrap().unwrap();
        assert!(stored.listed.len() < n);
        assert_eq!(stored.listed.len() as u32 + stored.omitted, n as u32 + 1);
        assert!(
            serde_json::to_vec(&stored.listed).unwrap().len() <= vk_hub_proto::MAX_WORKLOADS_BYTES
        );
        assert!(
            db.audits(Some(&id), 100)
                .unwrap()
                .iter()
                .all(|a| !a.event.contains("a[2J")),
        );

        let mut mem: BTreeMap<String, u64> = (0..MAX_WORKLOADS + 5)
            .map(|i| (format!("{i:016x}"), 1))
            .collect();
        mem.insert("x".repeat(1000), 1);
        db.record_heartbeat(
            &id,
            Heartbeat {
                workload_mem_bytes: mem,
                ..Heartbeat::default()
            },
            4,
        )
        .unwrap();
        let kept = db.workloads(&id).unwrap().unwrap().mem_bytes;
        assert_eq!(kept.len(), MAX_WORKLOADS);
        assert!(kept.keys().all(|k| k.len() == 16));
        // Not on the row, which every heartbeat rewrites.
        let row = db.node(&id).unwrap().unwrap();
        assert!(row.heartbeat.unwrap().workload_mem_bytes.is_empty());
        // A removed node takes its workloads with it.
        assert!(db.remove_node(&id, "uid 0", 5).unwrap());
        assert_eq!(db.workloads(&id).unwrap(), None);
    }

    /// An update's progress with `junk` in each of its free-text strings.
    fn update(junk: &str) -> vk_hub_proto::UpdateProgress {
        vk_hub_proto::UpdateProgress {
            command: "c".repeat(32),
            version: format!("v{junk}"),
            sha256: "ab".repeat(vk_hub_proto::SHA256_LEN),
            phase: vk_hub_proto::UpdatePhase::RolledBack,
            message: Some(format!("m{junk}")),
        }
    }

    /// A report's steering is stored on the row display-safe, its workloads apart; one that
    /// has not listed workloads yet still replaces it.
    #[test]
    fn a_report_s_steering_is_stored_on_the_row() {
        let db = Db::open_memory().unwrap();
        let id = enrolled(&db);
        let report = Report {
            workloads: Some(Vec::new()),
            workloads_omitted: 2,
            state: Some(vk_hub_proto::NodeState::Draining),
            unsupported: vec!["no\u{1b}[2J".into()],
            concurrency_error: Some("bad\u{202e}".into()),
            update: Some(update("\u{202e}")),
            ..Report::default()
        };
        db.record_report(&id, report, 2).unwrap();
        let row = db.node(&id).unwrap().unwrap();
        assert_eq!(
            row.report,
            Some(Report {
                state: Some(vk_hub_proto::NodeState::Draining),
                unsupported: vec!["no[2J".into()],
                concurrency_error: Some("bad".into()),
                update: Some(update("")),
                ..Report::default()
            })
        );
        assert_eq!(row.workloads, Some(2));
        for bad in [
            vk_hub_proto::UpdateProgress {
                command: "c\u{202e}".into(),
                ..update("")
            },
            vk_hub_proto::UpdateProgress {
                sha256: "../x".into(),
                ..update("")
            },
        ] {
            let report = Report {
                update: Some(bad),
                ..Report::default()
            };
            db.record_report(&id, report, 3).unwrap();
            let row = db.node(&id).unwrap().unwrap();
            assert_eq!(row.report.unwrap().update, None);
        }
        db.record_report(&id, Report::default(), 3).unwrap();
        let row = db.node(&id).unwrap().unwrap();
        assert_eq!(row.report, Some(Report::default()));
        assert_eq!(row.workloads, Some(2));
    }

    /// Each phase of an update a node reports is audited once, as it reaches it.
    #[test]
    fn update_phases_are_audited_as_they_change() {
        let db = Db::open_memory().unwrap();
        let id = enrolled(&db);
        let report = |phase, message: Option<&str>| Report {
            update: Some(vk_hub_proto::UpdateProgress {
                command: "c1".repeat(16),
                version: "0.85.0".into(),
                sha256: "ab".repeat(32),
                phase,
                message: message.map(str::to_string),
            }),
            ..Report::default()
        };
        use vk_hub_proto::UpdatePhase::{Draining, RolledBack};
        db.record_report(&id, report(Draining, None), 2).unwrap();
        db.record_report(&id, report(Draining, None), 3).unwrap();
        db.record_report(&id, report(RolledBack, Some("validation failed")), 4)
            .unwrap();
        let events: Vec<String> = db
            .audits(Some(&id), 10)
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .filter(|e| e.starts_with("update"))
            .collect();
        assert_eq!(
            events,
            [
                "update to vk 0.85.0 (abababababab): draining",
                "update to vk 0.85.0 (abababababab): rolled back: validation failed"
            ]
        );
    }

    /// A stored list or set of memory readings that does not decode does not fail a listing,
    /// nor the heartbeat that replaces the readings.
    #[test]
    fn undecodable_workloads_are_skipped_and_replaced() {
        let db = Db::open_memory().unwrap();
        let id = enrolled(&db);
        let listed = Report {
            workloads: Some(Vec::new()),
            ..Report::default()
        };
        db.record_report(&id, listed.clone(), 2).unwrap();
        let garble = |table: TableDefinition<&str, &[u8]>| {
            let txn = db.db.begin_write().unwrap();
            txn.open_table(table)
                .unwrap()
                .insert(id.as_str(), b"{not json".as_slice())
                .unwrap();
            txn.commit().unwrap();
        };
        garble(WORKLOAD_MEM);
        assert_eq!(
            db.workloads(&id).unwrap().unwrap().mem_bytes,
            BTreeMap::new()
        );
        let mem = BTreeMap::from([("ab".repeat(8), 5)]);
        db.record_heartbeat(
            &id,
            Heartbeat {
                workload_mem_bytes: mem.clone(),
                ..Heartbeat::default()
            },
            3,
        )
        .unwrap();
        assert_eq!(db.workloads(&id).unwrap().unwrap().mem_bytes, mem);
        garble(WORKLOADS);
        assert_eq!(db.workloads(&id).unwrap(), None);
        let all = db.nodes_with_workloads(Ok).unwrap();
        assert_eq!((all.len(), &all[0].2), (1, &None));
        // The next report replaces it.
        db.record_report(&id, listed, 4).unwrap();
        assert!(db.workloads(&id).unwrap().is_some());
    }

    fn enrolled(db: &Db) -> String {
        let (token, _) = db.create_token(DAY, "uid 0", 0).unwrap();
        let Enrollment::Enrolled { node_id } = db.enroll(&token, "aa", "h", "peer p", 1).unwrap()
        else {
            panic!("expected an enrollment");
        };
        node_id
    }

    #[test]
    fn a_desired_change_takes_the_next_generation_and_no_change_takes_none() {
        let db = Db::open_memory().unwrap();
        let id = enrolled(&db);
        let set = |ceiling| {
            db.set_desired(
                &id,
                DesiredChange::Ceiling(ceiling),
                "uid 0",
                "set a ceiling",
                5,
            )
            .unwrap()
        };
        let d = set(Some(4)).unwrap();
        assert_eq!((d.generation, d.ceiling), (1, Some(4)));
        assert!(set(Some(4)).is_none());
        let d = db
            .set_desired(
                &id,
                DesiredChange::Acquisition(Acquisition::Stop),
                "uid 0",
                "stopped acquisition",
                5,
            )
            .unwrap()
            .unwrap();
        assert_eq!((d.generation, d.ceiling), (2, Some(4)));
        assert_eq!(db.node(&id).unwrap().unwrap().desired, Some(d));
        let events: Vec<String> = db
            .audits(Some(&id), 10)
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect();
        assert_eq!(
            events[1..],
            [
                "uid 0 set a ceiling (generation 1)",
                "uid 0 stopped acquisition (generation 2)"
            ]
        );
        let err = db
            .set_desired(
                &"0".repeat(32),
                DesiredChange::Ceiling(None),
                "uid 0",
                "changed",
                5,
            )
            .unwrap_err();
        assert!(err.is::<NotEnrolled>(), "{err:#}");
    }

    #[test]
    fn a_command_is_pending_until_it_has_a_final_outcome() {
        let db = Db::open_memory().unwrap();
        let id = enrolled(&db);
        let other = {
            let (token, _) = db.create_token(DAY, "uid 0", 0).unwrap();
            let Enrollment::Enrolled { node_id } =
                db.enroll(&token, "bb", "h", "peer p", 1).unwrap()
            else {
                panic!("expected an enrollment");
            };
            node_id
        };
        let drain = db
            .issue_command(&id, Operation::Drain, DAY, "uid 0", 10)
            .unwrap();
        db.issue_command(&other, Operation::Quarantine, DAY, "uid 0", 10)
            .unwrap();
        assert_eq!(
            db.pending_commands(&id, 11).unwrap(),
            std::slice::from_ref(&drain)
        );
        let ack = |outcome| CommandAck {
            id: drain.id.clone(),
            outcome,
        };
        assert!(db.record_ack(&id, &ack(Outcome::Accepted), 12).unwrap());
        // Under way is still pending; recording the same outcome again is no news.
        assert_eq!(db.pending_commands(&id, 13).unwrap().len(), 1);
        assert!(!db.record_ack(&id, &ack(Outcome::Accepted), 13).unwrap());
        assert!(db.record_ack(&id, &ack(Outcome::Done), 14).unwrap());
        assert!(db.pending_commands(&id, 15).unwrap().is_empty());
        // A late `accepted` does not reopen it, nor another outcome replace the final one.
        assert!(!db.record_ack(&id, &ack(Outcome::Accepted), 16).unwrap());
        assert!(!db.record_ack(&id, &ack(Outcome::Expired), 16).unwrap());
        // Nor is another node's command settled by this one's ack.
        let theirs = db.node_commands(&other).unwrap().remove(0).command;
        let stray = CommandAck {
            id: theirs.id,
            outcome: Outcome::Done,
        };
        assert!(!db.record_ack(&id, &stray, 16).unwrap());
        let row = db.node_commands(&id).unwrap().remove(0);
        assert_eq!(row.outcome, Some(Outcome::Done));
        let events: Vec<String> = db
            .audits(Some(&id), 10)
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect();
        assert_eq!(events.len(), 4, "{events:?}");
        assert_eq!(
            events[1],
            format!("uid 0 issued drain (command {})", drain.id)
        );
        assert_eq!(events[3], format!("command {} (drain): done", drain.id));
        // An unanswered command past its expiry is not resent.
        db.issue_command(&id, Operation::Release, Duration::from_secs(5), "uid 0", 20)
            .unwrap();
        assert!(db.pending_commands(&id, 30).unwrap().is_empty());
        assert_eq!(db.node_commands(&other).unwrap().len(), 1);
        let err = db
            .issue_command(&"0".repeat(32), Operation::Drain, DAY, "uid 0", 1)
            .unwrap_err();
        assert!(err.is::<NotEnrolled>(), "{err:#}");
    }

    /// A node's failure message is stored and audited made display-safe.
    #[test]
    fn a_failure_message_is_stored_display_safe() {
        let db = Db::open_memory().unwrap();
        let id = enrolled(&db);
        let drain = db
            .issue_command(&id, Operation::Drain, DAY, "uid 0", 10)
            .unwrap();
        let message = format!(
            "disk\u{202e}full\n{}",
            "x".repeat(2 * vk_hub_proto::MAX_DISPLAY)
        );
        let ack = CommandAck {
            id: drain.id.clone(),
            outcome: Outcome::Failed { message },
        };
        assert!(db.record_ack(&id, &ack, 11).unwrap());
        // A second failure does not replace the first.
        assert!(!db.record_ack(&id, &ack, 12).unwrap());
        let Some(Outcome::Failed { message }) = db.node_commands(&id).unwrap().remove(0).outcome
        else {
            panic!("expected a failure");
        };
        assert!(message.starts_with("diskfullx"), "{message:?}");
        assert_eq!(message.chars().count(), vk_hub_proto::MAX_DISPLAY);
        let event = db.audits(Some(&id), 1).unwrap().remove(0).event;
        let head = format!("command {} (drain): failed: diskfullx", drain.id);
        assert!(event.starts_with(&head), "{event:?}");
    }

    /// A node whose latest session ran version 1 is refused steering; one that has not
    /// connected yet is not.
    #[test]
    fn a_node_on_version_1_is_monitored_only() {
        let db = Db::open_memory().unwrap();
        let id = enrolled(&db);
        db.set_desired(
            &id,
            DesiredChange::Ceiling(Some(2)),
            "uid 0",
            "set a ceiling",
            1,
        )
        .unwrap()
        .unwrap();
        db.issue_command(&id, Operation::Drain, DAY, "uid 0", 1)
            .unwrap();
        assert!(db.record_session(&id, "ab", 1, 2, || true).unwrap());
        let err = db
            .set_desired(
                &id,
                DesiredChange::Ceiling(Some(3)),
                "uid 0",
                "set a ceiling",
                3,
            )
            .unwrap_err();
        assert!(err.is::<MonitoringOnly>(), "{err:#}");
        assert!(format!("{err:#}").contains("update its vk"), "{err:#}");
        let err = db
            .issue_command(&id, Operation::Undrain, DAY, "uid 0", 3)
            .unwrap_err();
        assert!(err.is::<MonitoringOnly>(), "{err:#}");
        // Nothing of either was stored or audited.
        assert_eq!(
            db.node(&id).unwrap().unwrap().desired.unwrap().ceiling,
            Some(2)
        );
        assert_eq!(db.node_commands(&id).unwrap().len(), 1);
        assert_eq!(db.audits(Some(&id), 10).unwrap().len(), 3);
        assert!(db.record_session(&id, "ab", STEERING, 4, || true).unwrap());
        db.issue_command(&id, Operation::Undrain, DAY, "uid 0", 5)
            .unwrap();
    }

    fn update_to(sha256: &str) -> Operation {
        Operation::Update {
            version: "0.84.0".into(),
            sha256: sha256.into(),
            size: 10,
            signature: None,
            force: false,
            within_secs: None,
        }
    }

    #[test]
    fn a_release_is_recorded_once_and_kept_while_a_node_updates_to_it() {
        let db = Db::open_memory().unwrap();
        let sha = "ab".repeat(32);
        let row = ReleaseRow {
            version: "0.84.0".into(),
            size: 10,
            signature: None,
            added_at: 5,
            added_by: "uid 0".into(),
        };
        db.add_release(&sha, &row, "uid 0").unwrap();
        assert!(db.add_release(&sha, &row, "uid 0").is_err());
        assert_eq!(db.resolve_release(&sha[..8]).unwrap().row, row);
        assert!(db.resolve_release("abab").is_err());
        assert!(db.resolve_release("ABABABAB").is_err());
        assert!(db.resolve_release("cdcdcdcd").is_err());
        let id = enrolled(&db);
        let cmd = db
            .issue_command(&id, update_to(&sha), DAY, "uid 0", 10)
            .unwrap();
        assert!(db.updating_to(&id, &sha, 11).unwrap());
        assert!(!db.updating_to(&id, &"cd".repeat(32), 11).unwrap());
        // Past its expiry, unanswered, it no longer counts.
        assert!(!db.updating_to(&id, &sha, cmd.expires_at).unwrap());
        let err = db.remove_release(&sha, "uid 0", 11).unwrap_err();
        assert!(
            format!("{err:#}").contains(&format!("node {id} is still being updated")),
            "{err:#}"
        );
        db.record_ack(
            &id,
            &CommandAck {
                id: cmd.id,
                outcome: Outcome::Done,
            },
            12,
        )
        .unwrap();
        assert!(!db.updating_to(&id, &sha, 13).unwrap());
        assert!(db.remove_release(&sha, "uid 0", 13).unwrap());
        assert!(!db.remove_release(&sha, "uid 0", 13).unwrap());
        assert!(db.releases().unwrap().is_empty());
        let events: Vec<String> = db
            .audits(None, 10)
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect();
        assert!(
            events.contains(&"uid 0 added release abababababab as vk 0.84.0".to_string()),
            "{events:?}"
        );
        assert!(
            events.contains(&"uid 0 removed release abababababab".to_string()),
            "{events:?}"
        );
    }

    /// A hub restored from a backup may be behind the generation a node applied; it moves
    /// past the node's rather than send what the node would ignore.
    #[test]
    fn a_node_ahead_of_the_hub_gets_the_desired_state_reissued_past_it() {
        let db = Db::open_memory().unwrap();
        let id = enrolled(&db);
        db.set_desired(
            &id,
            DesiredChange::Ceiling(Some(4)),
            "uid 0",
            "set a ceiling",
            1,
        )
        .unwrap();
        let report = |applied: Option<u64>| Report {
            applied: applied.map(|generation| DesiredState {
                generation,
                ceiling: Some(4),
                ..DEFAULT_DESIRED
            }),
            ..Report::default()
        };
        db.record_report(&id, report(Some(1)), 2).unwrap();
        let generation = |db: &Db| db.node(&id).unwrap().unwrap().desired.unwrap().generation;
        assert_eq!(generation(&db), 1);
        db.record_report(&id, report(Some(9)), 3).unwrap();
        let desired = db.node(&id).unwrap().unwrap().desired.unwrap();
        assert_eq!((desired.generation, desired.ceiling), (10, Some(4)));
        // And a change takes the generation after both.
        db.record_report(&id, report(Some(12)), 4).unwrap();
        let next = db
            .set_desired(
                &id,
                DesiredChange::Ceiling(None),
                "uid 0",
                "lifted the ceiling",
                5,
            )
            .unwrap()
            .unwrap();
        assert_eq!(next.generation, 14);
        let events: Vec<String> = db
            .audits(Some(&id), 20)
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect();
        assert!(
            events.contains(
                &"the node applied generation 9, past this hub's 1: re-issued the desired \
                  state as generation 10"
                    .to_string()
            ),
            "{events:?}"
        );
        assert!(events.contains(&"applied generation 12".to_string()));
    }

    /// A hub with no desired state of its own for a node takes what the node applied, rather
    /// than lift the node's ceiling or resume its acquisition with the defaults.
    #[test]
    fn a_hub_without_desired_state_adopts_the_nodes() {
        let db = Db::open_memory().unwrap();
        let id = enrolled(&db);
        let applied = DesiredState {
            generation: 3,
            ceiling: Some(2),
            acquisition: Acquisition::Stop,
        };
        let report = Report {
            applied: Some(applied.clone()),
            ..Report::default()
        };
        db.record_report(&id, report.clone(), 2).unwrap();
        assert_eq!(
            db.node(&id).unwrap().unwrap().desired,
            Some(applied.clone())
        );
        // Adopted once: the same report again changes nothing.
        db.record_report(&id, report, 3).unwrap();
        assert_eq!(db.node(&id).unwrap().unwrap().desired, Some(applied));
        let events: Vec<String> = db
            .audits(Some(&id), 20)
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect();
        let adopted = "adopted the node's desired state, generation 3";
        assert_eq!(
            events.iter().filter(|e| *e == adopted).count(),
            1,
            "{events:?}"
        );
        // A change goes on from it.
        let next = db
            .set_desired(
                &id,
                DesiredChange::Ceiling(None),
                "uid 0",
                "lifted the ceiling",
                4,
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            next,
            DesiredState {
                generation: 4,
                ceiling: None,
                acquisition: Acquisition::Stop,
            }
        );
        // A node that applied nothing gives the hub nothing to adopt.
        let (token, _) = db.create_token(DAY, "uid 0", 0).unwrap();
        let Enrollment::Enrolled { node_id: fresh } =
            db.enroll(&token, "cc", "h", "peer p", 1).unwrap()
        else {
            panic!("expected an enrollment");
        };
        db.record_report(&fresh, Report::default(), 2).unwrap();
        assert_eq!(db.node(&fresh).unwrap().unwrap().desired, None);
    }

    /// When the hub knows neither its desired state nor the node's applied state, operator
    /// changes override only the fields they set once the node reports its applied state.
    #[test]
    fn a_change_made_on_the_defaults_is_applied_onto_the_nodes_state() {
        let applied = DesiredState {
            generation: 7,
            ceiling: Some(2),
            acquisition: Acquisition::Stop,
        };
        let report = Report {
            applied: Some(applied.clone()),
            ..Report::default()
        };
        let outcome = |changes: &[DesiredChange]| {
            let db = Db::open_memory().unwrap();
            let id = enrolled(&db);
            for &change in changes {
                db.set_desired(&id, change, "uid 0", "changed", 1).unwrap();
            }
            db.record_report(&id, report.clone(), 2).unwrap();
            let row = db.node(&id).unwrap().unwrap();
            assert_eq!(row.set_on_defaults, None);
            let events: Vec<String> = db
                .audits(Some(&id), 20)
                .unwrap()
                .into_iter()
                .map(|r| r.event)
                .collect();
            (row.desired.unwrap(), events)
        };
        let state = |ceiling, acquisition| DesiredState {
            generation: 8,
            ceiling,
            acquisition,
        };
        let (desired, events) = outcome(&[DesiredChange::Ceiling(Some(5))]);
        assert_eq!(desired, state(Some(5), Acquisition::Stop));
        let merged = "applied the operator's change onto the node's desired state, generation 8";
        assert!(events.contains(&merged.to_string()), "{events:?}");
        // Resuming is a change even though the defaults already run acquisition.
        let (desired, _) = outcome(&[DesiredChange::Acquisition(Acquisition::Run)]);
        assert_eq!(desired, state(Some(2), Acquisition::Run));
        let (desired, _) = outcome(&[
            DesiredChange::Ceiling(Some(5)),
            DesiredChange::Acquisition(Acquisition::Run),
        ]);
        assert_eq!(desired, state(Some(5), Acquisition::Run));
        // What the node already applied needs no new generation.
        let (desired, events) = outcome(&[DesiredChange::Ceiling(Some(2))]);
        assert_eq!(desired, applied);
        let adopted = "adopted the node's desired state, generation 7";
        assert!(events.contains(&adopted.to_string()), "{events:?}");

        // A report without what the node applied leaves the change for the next one.
        let db = Db::open_memory().unwrap();
        let id = enrolled(&db);
        db.set_desired(&id, DesiredChange::Ceiling(Some(5)), "uid 0", "changed", 1)
            .unwrap();
        db.record_report(&id, Report::default(), 2).unwrap();
        db.record_report(&id, report.clone(), 3).unwrap();
        let desired = db.node(&id).unwrap().unwrap().desired.unwrap();
        assert_eq!(desired, state(Some(5), Acquisition::Stop));

        // A node behind the hub's generations is never sent an older one: the hub's stands
        // when it carries the change, and one past it is issued when it does not.
        let db = Db::open_memory().unwrap();
        let id = enrolled(&db);
        for (ceiling, now) in [(4, 1), (5, 2), (4, 3)] {
            db.set_desired(
                &id,
                DesiredChange::Ceiling(Some(ceiling)),
                "uid 0",
                "changed",
                now,
            )
            .unwrap();
        }
        let behind = Report {
            applied: Some(DesiredState {
                generation: 1,
                ceiling: Some(4),
                acquisition: Acquisition::Run,
            }),
            ..Report::default()
        };
        db.record_report(&id, behind, 4).unwrap();
        let ours = DesiredState {
            generation: 3,
            ceiling: Some(4),
            acquisition: Acquisition::Run,
        };
        assert_eq!(db.node(&id).unwrap().unwrap().desired, Some(ours.clone()));
        let caught_up = Report {
            applied: Some(ours.clone()),
            ..Report::default()
        };
        db.record_report(&id, caught_up, 5).unwrap();
        assert_eq!(db.node(&id).unwrap().unwrap().desired, Some(ours));
        let events: Vec<String> = db
            .audits(Some(&id), 20)
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect();
        assert!(
            !events.iter().any(|e| e.starts_with("the node applied")),
            "{events:?}"
        );
        let db = Db::open_memory().unwrap();
        let id = enrolled(&db);
        for (ceiling, now) in [(4, 1), (5, 2)] {
            db.set_desired(
                &id,
                DesiredChange::Ceiling(Some(ceiling)),
                "uid 0",
                "changed",
                now,
            )
            .unwrap();
        }
        let stopped = Report {
            applied: Some(DesiredState {
                generation: 1,
                ceiling: Some(4),
                acquisition: Acquisition::Stop,
            }),
            ..Report::default()
        };
        db.record_report(&id, stopped, 3).unwrap();
        let desired = db.node(&id).unwrap().unwrap().desired.unwrap();
        assert_eq!(
            desired,
            DesiredState {
                generation: 3,
                ceiling: Some(5),
                acquisition: Acquisition::Stop,
            }
        );

        // A node that reported first is adopted, and a change goes on from its state.
        let db = Db::open_memory().unwrap();
        let id = enrolled(&db);
        db.record_report(&id, report.clone(), 1).unwrap();
        let next = db
            .set_desired(&id, DesiredChange::Ceiling(Some(5)), "uid 0", "changed", 2)
            .unwrap()
            .unwrap();
        assert_eq!(next, state(Some(5), Acquisition::Stop));
        assert_eq!(db.node(&id).unwrap().unwrap().set_on_defaults, None);
    }

    /// A hub of protocol version 1 rewrites a node's row without its desired state or what the
    /// node applied. A change made in the version-2 session before the node's first report is
    /// applied onto the node's state all the same.
    #[test]
    fn a_change_after_a_version_1_rewrite_is_applied_onto_the_nodes_state() {
        let db = Db::open_memory().unwrap();
        let id = enrolled(&db);
        // The row as such a hub leaves it: a report without what the node applied.
        db.record_report(&id, Report::default(), 2).unwrap();
        assert!(db.record_session(&id, "ab", STEERING, 3, || true).unwrap());
        db.set_desired(
            &id,
            DesiredChange::Acquisition(Acquisition::Stop),
            "uid 0",
            "stopped acquisition",
            4,
        )
        .unwrap()
        .unwrap();
        let report = Report {
            applied: Some(DesiredState {
                generation: 3,
                ceiling: Some(2),
                acquisition: Acquisition::Run,
            }),
            ..Report::default()
        };
        db.record_report(&id, report, 5).unwrap();
        assert_eq!(
            db.node(&id).unwrap().unwrap().desired,
            Some(DesiredState {
                generation: 4,
                ceiling: Some(2),
                acquisition: Acquisition::Stop,
            })
        );
    }

    #[test]
    fn commands_keep_their_issue_order_in_one_second_and_across_a_clock_step() {
        let db = Db::open_memory().unwrap();
        let id = enrolled(&db);
        let ops = [Operation::Drain, Operation::Undrain];
        // Eight in one second, then one after the clock stepped back.
        let issued: Vec<Command> = (0..9)
            .map(|i| {
                let now = if i < 8 { 10 } else { 5 };
                db.issue_command(&id, ops[i % 2].clone(), DAY, "uid 0", now)
                    .unwrap()
            })
            .collect();
        assert_eq!(db.pending_commands(&id, 10).unwrap(), issued);
        let listed: Vec<Command> = db
            .node_commands(&id)
            .unwrap()
            .into_iter()
            .map(|r| r.command)
            .collect();
        assert_eq!(listed, issued);
    }

    #[test]
    fn settled_commands_are_pruned_and_go_with_their_node() {
        let db = Db::open_memory().unwrap();
        let id = enrolled(&db);
        let old = db
            .issue_command(&id, Operation::Release, DAY, "uid 0", 0)
            .unwrap();
        let ack = CommandAck {
            id: old.id,
            outcome: Outcome::Done,
        };
        db.record_ack(&id, &ack, 1).unwrap();
        // Under way, however old, stays.
        let running = db
            .issue_command(&id, Operation::Drain, DAY, "uid 0", 1)
            .unwrap();
        let ack = CommandAck {
            id: running.id.clone(),
            outcome: Outcome::Accepted,
        };
        db.record_ack(&id, &ack, 1).unwrap();
        db.issue_command(&id, Operation::Release, DAY, "uid 0", 2 + COMMAND_KEEP)
            .unwrap();
        let kept: Vec<String> = db
            .node_commands(&id)
            .unwrap()
            .into_iter()
            .map(|r| r.command.id)
            .collect();
        assert_eq!(kept.len(), 2);
        assert!(kept.contains(&running.id));
        assert!(db.remove_node(&id, "uid 0", 3 + COMMAND_KEEP).unwrap());
        assert!(db.node_commands(&id).unwrap().is_empty());
    }

    #[test]
    fn old_audit_rows_are_pruned() {
        let db = Db::open_memory().unwrap();
        let txn = db.db.begin_write().unwrap();
        for i in 0..AUDIT_MAX + 5 {
            append_audit(&txn, Some("n"), "uid 0", &format!("e{i}"), i).unwrap();
        }
        txn.commit().unwrap();
        let txn = db.db.begin_read().unwrap();
        let rows = redb::ReadableTableMetadata::len(&txn.open_table(AUDIT).unwrap()).unwrap();
        let indexed =
            redb::ReadableTableMetadata::len(&txn.open_table(AUDIT_BY_NODE).unwrap()).unwrap();
        assert!(
            rows <= AUDIT_MAX && rows > AUDIT_MAX - AUDIT_PRUNE,
            "{rows}"
        );
        assert_eq!(rows, indexed);
        drop(txn);
        assert_eq!(
            db.audits(Some("n"), 1).unwrap()[0].event,
            format!("e{}", AUDIT_MAX + 4)
        );
    }

    #[test]
    fn the_audit_log_reads_back_in_order_and_by_node() {
        let db = Db::open_memory().unwrap();
        for i in 0..5u64 {
            let node = if i % 2 == 0 { Some("a") } else { Some("b") };
            let txn = db.db.begin_write().unwrap();
            append_audit(&txn, node, "uid 0", &format!("event {i}"), i).unwrap();
            txn.commit().unwrap();
        }
        let txn = db.db.begin_write().unwrap();
        append_audit(&txn, None, "uid 0", "issued a token\u{1b}[2J", 9).unwrap();
        txn.commit().unwrap();
        let all = db.audits(None, 100).unwrap();
        assert_eq!(all.len(), 6);
        assert_eq!(all[5].event, "issued a token[2J");
        let a: Vec<_> = db
            .audits(Some("a"), 2)
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect();
        assert_eq!(a, ["event 2", "event 4"]);
    }

    #[test]
    fn a_sign_in_link_opens_one_session_that_ends_by_expiry_or_logout() {
        let db = Db::open_memory().unwrap();
        assert!(
            db.create_login(Role::Viewer, Duration::ZERO, "uid 0", 0)
                .is_err()
        );
        assert!(
            db.create_login(Role::Viewer, MAX_LOGIN_TTL + DAY, "uid 0", 0)
                .is_err()
        );
        let (link, expires) = db
            .create_login(Role::Operator, Duration::from_secs(600), "uid 7", 1000)
            .unwrap();
        assert!(link.starts_with(LOGIN_PREFIX));
        assert_eq!(expires, 1600);
        // Expired, a link opens nothing, and is not spent by trying.
        assert!(db.redeem_login(&link, 1600).unwrap().is_none());
        let (secret, session) = db.redeem_login(&link, 1100).unwrap().unwrap();
        assert!(db.redeem_login(&link, 1101).unwrap().is_none());
        assert_eq!(session.role, Role::Operator);
        assert_eq!(session.issued_by, "uid 7");
        assert_eq!(session.expires_at, 1100 + UI_SESSION_TTL.as_secs());
        assert_eq!(
            session.principal(),
            format!("ui session {} (operator)", session.id)
        );
        assert_eq!(db.ui_session(&secret, 1200).unwrap(), Some(session.clone()));
        assert!(
            db.ui_session(&secret, session.expires_at)
                .unwrap()
                .is_none()
        );
        assert!(db.ui_session(&link, 1200).unwrap().is_none());
        // Neither secret nor link is in the file, only their hashes.
        let txn = db.db.begin_read().unwrap();
        for table in [UI_SESSIONS, UI_LOGINS] {
            for entry in txn.open_table(table).unwrap().iter().unwrap() {
                let (k, v) = entry.unwrap();
                assert!(!k.value().contains(&secret) && !k.value().contains(&link));
                let v = String::from_utf8_lossy(v.value()).to_string();
                assert!(!v.contains(&secret) && !v.contains(&link));
            }
        }
        drop(txn);

        let (other, _) = db
            .create_login(Role::Viewer, Duration::from_secs(600), "uid 7", 1000)
            .unwrap();
        let (other, _) = db.redeem_login(&other, 1100).unwrap().unwrap();
        assert_eq!(db.ui_sessions(1200).unwrap().len(), 2);
        assert_eq!(db.end_ui_sessions(Some("nope"), "uid 0", 1200).unwrap(), 0);
        assert_eq!(
            db.end_ui_sessions(Some(&session.id), "uid 0", 1200)
                .unwrap(),
            1
        );
        assert!(db.ui_session(&secret, 1200).unwrap().is_none());
        assert!(db.ui_session(&other, 1200).unwrap().is_some());
        assert_eq!(db.end_ui_sessions(None, "uid 0", 1200).unwrap(), 1);
        assert!(db.ui_sessions(1200).unwrap().is_empty());
        let events: Vec<String> = db
            .audits(None, 20)
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect();
        assert!(
            events.contains(
                &"uid 7 issued a sign-in link for the operator role, valid for 600s".to_string()
            ),
            "{events:?}"
        );
        assert!(
            events.contains(&format!("uid 0 ended {}", session.principal())),
            "{events:?}"
        );
    }

    /// A row that does not decode is left out of the listing, not made to fail it, and the
    /// next end of sessions drops it; a browser's sign-out ends its own session alone, even
    /// beside one listed under the same ID.
    #[test]
    fn a_corrupt_row_is_skipped_and_a_sign_out_ends_one_session() {
        let db = Db::open_memory().unwrap();
        let ttl = Duration::from_secs(600);
        let (link, _) = db.create_login(Role::Viewer, ttl, "uid 0", 1000).unwrap();
        let (secret, session) = db.redeem_login(&link, 1000).unwrap().unwrap();
        let twin = format!("{}{}", session.id, "0".repeat(64 - SESSION_ID_LEN));
        let txn = db.db.begin_write().unwrap();
        {
            let mut table = txn.open_table(UI_SESSIONS).unwrap();
            table.insert("corrupt", b"not json".as_slice()).unwrap();
            let row = UiSessionRow {
                role: Role::Viewer,
                issued_by: "uid 0".into(),
                created_at: 1000,
                expires_at: 5000,
            };
            table
                .insert(twin.as_str(), encode(&row).unwrap().as_slice())
                .unwrap();
        }
        txn.commit().unwrap();
        let listed = db.ui_sessions(1100).unwrap();
        assert_eq!(listed.len(), 2);
        let txn = db.db.begin_write().unwrap();
        txn.open_table(UI_SESSIONS)
            .unwrap()
            .insert(token_key("bad").as_str(), b"{".as_slice())
            .unwrap();
        txn.commit().unwrap();
        assert!(db.ui_session("bad", 1100).unwrap().is_none());
        assert!(listed.iter().all(|s| s.id == session.id));

        assert_eq!(db.end_ui_session(&secret, "uid 0", 1100).unwrap(), 1);
        assert!(db.ui_session(&secret, 1100).unwrap().is_none());
        assert_eq!(db.ui_sessions(1100).unwrap().len(), 1);
        assert_eq!(db.end_ui_session(&secret, "uid 0", 1100).unwrap(), 0);
        let txn = db.db.begin_read().unwrap();
        let table = txn.open_table(UI_SESSIONS).unwrap();
        assert!(table.get("corrupt").unwrap().is_none());
        assert!(table.get(twin.as_str()).unwrap().is_some());
    }

    #[test]
    fn the_audit_log_pages_back_newest_first() {
        let db = Db::open_memory().unwrap();
        for i in 0..5u64 {
            let node = if i % 2 == 0 { Some("a") } else { Some("b") };
            let txn = db.db.begin_write().unwrap();
            append_audit(&txn, node, "uid 0", &format!("event {i}"), i).unwrap();
            txn.commit().unwrap();
        }
        let events = |rows: Vec<(u64, AuditRow)>| -> Vec<(u64, String)> {
            rows.into_iter().map(|(s, r)| (s, r.event)).collect()
        };
        let first = events(db.audit_page(None, None, 2).unwrap());
        assert_eq!(first, [(4, "event 4".into()), (3, "event 3".into())]);
        let next = events(db.audit_page(None, Some(3), 2).unwrap());
        assert_eq!(next, [(2, "event 2".into()), (1, "event 1".into())]);
        let a = events(db.audit_page(Some("a"), Some(4), 10).unwrap());
        assert_eq!(a, [(2, "event 2".into()), (0, "event 0".into())]);
    }

    #[test]
    fn the_file_is_private_and_held_exclusively() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("vk-hub-db-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("data").join("hub.db");
        let db = Db::open(&path).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert!(Db::open(&path).is_err());
        drop(db);
        assert!(Db::open(&path).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
