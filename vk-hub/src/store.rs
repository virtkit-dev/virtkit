//! The hub's database: enrolled nodes and outstanding enrollment tokens, the web UI's sign-in
//! links and sessions, and the audit log, in [`redb`] like `vk-registry`'s accounts store —
//! tables of JSON rows, small enough that listing every node is a scan.
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
//! So are a node's workloads, which change with every CI job started or ended and which the
//! node sends again on every session; they are kept apart from the node's row, which every
//! heartbeat rewrites, and their memory readings apart from them. Everything else is durable.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vk_hub_proto::{Heartbeat, Inventory, Report, Workload};

/// Key: node ID. Value: JSON [`NodeRow`].
const NODES: TableDefinition<&str, &[u8]> = TableDefinition::new("nodes");
/// Key: `sha256(token)`, hex. Value: JSON [`TokenRow`].
const TOKENS: TableDefinition<&str, &[u8]> = TableDefinition::new("tokens");
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

/// The most audit rows kept. Bounded by count rather than age: a quiet fleet keeps its history
/// for years, and a busy one keeps the newest hundred thousand actions and outcomes — months
/// at the rate of a few dozen nodes. Past it, the oldest go, a thousand at a time.
const AUDIT_MAX: u64 = 100_000;
const AUDIT_PRUNE: u64 = 1000;

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
}

/// What a node last said runs on it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workloads {
    pub listed: Vec<Workload>,
    /// Running, but left out of `listed` by the node.
    #[serde(default)]
    pub omitted: u32,
    /// What each listed one holds on the host, in bytes, by its ID, from the latest heartbeat.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub mem_bytes: BTreeMap<String, u64>,
}

/// One line of the audit log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRow {
    pub at: u64,
    /// The node it is about; `None` for the hub's own, and for everything in local mode.
    #[serde(default)]
    pub node: Option<String>,
    /// Who: `uid <n>` for an operator on the admin socket, a session's principal for what it
    /// did, `vk-hub local` for what local mode did as it started.
    pub actor: String,
    pub event: String,
}

#[derive(Serialize, Deserialize)]
struct TokenRow {
    created_at: u64,
    expires_at: u64,
}

/// What an enrollment came to.
#[derive(Debug, PartialEq, Eq)]
pub enum Enrollment {
    Enrolled {
        node_id: String,
    },
    /// The key was already pinned, so the node it was pinned to is the answer: a node whose
    /// first enrollment reply was lost enrolls again with a new token and the same key, and
    /// holding both is exactly what the first enrollment asked for.
    Reenrolled {
        node_id: String,
    },
    /// The token is unknown, already used, or expired — deliberately not said which, to a
    /// caller who may be guessing.
    BadToken,
}

pub struct Db {
    db: Database,
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
        txn.commit().context("initializing the hub database")?;
        Ok(Db { db })
    }

    /// Issue a single-use enrollment token valid for `ttl`. Returns the token — shown once,
    /// never stored — and when it expires. Expired tokens are swept in the same write.
    pub fn create_token(&self, ttl: Duration, now: u64) -> Result<(String, u64)> {
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
        txn.commit().context("storing an enrollment token")?;
        Ok((token, expires_at))
    }

    /// Consume `token` and pin `public_key` (hex) as a new node, or answer with the node it is
    /// already pinned to. The caller has checked the node's signature.
    pub fn enroll(
        &self,
        token: &str,
        public_key: &str,
        hostname: &str,
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

    /// Every node, by ID.
    pub fn nodes(&self) -> Result<Vec<(String, NodeRow)>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(NODES)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            out.push((key.value().to_string(), decode::<NodeRow>(value.value())?));
        }
        Ok(out)
    }

    /// A node authenticated a session as `incarnation`.
    pub fn record_session(&self, id: &str, incarnation: &str, now: u64) -> Result<()> {
        self.update(id, Durability::Immediate, |row| {
            row.incarnation = Some(incarnation.to_string());
            row.last_seen = Some(now);
        })
    }

    /// Remove a node: its key is no longer pinned, and a session it opens is refused.
    /// `Ok(false)` when there was no such node.
    pub fn remove_node(&self, id: &str) -> Result<bool> {
        let txn = self.db.begin_write().context("starting a write")?;
        let removed = txn.open_table(NODES)?.remove(id)?.is_some();
        if removed {
            txn.open_table(WORKLOADS)?.remove(id)?;
            txn.open_table(WORKLOAD_MEM)?.remove(id)?;
        }
        txn.commit().context("removing a node")?;
        Ok(removed)
    }

    pub fn record_inventory(&self, id: &str, inventory: Inventory, now: u64) -> Result<()> {
        let inventory = display_safe_inventory(inventory);
        self.update(id, Durability::Immediate, |row| {
            row.hostname = inventory.hostname.clone();
            row.inventory = Some(inventory);
            row.last_seen = Some(now);
        })
    }

    pub fn record_heartbeat(&self, id: &str, heartbeat: Heartbeat, now: u64) -> Result<()> {
        let mut heartbeat = heartbeat;
        // Kept only as a lookup for the listed workloads, whose IDs are a few bytes: an ID no
        // workload can have, and anything past what a report can list, is dropped.
        let mut mem = std::mem::take(&mut heartbeat.workload_mem_bytes);
        mem.retain(|id, _| id.len() <= MAX_WORKLOAD_ID);
        while mem.len() > vk_hub_proto::MAX_WORKLOADS {
            mem.pop_last();
        }
        self.update_txn(now, id, |row, txn| {
            row.heartbeat = Some(heartbeat);
            row.heartbeat_at = Some(now);
            row.last_seen = Some(now);
            // Written only when it moved: a node repeats its figures between measurements.
            let mut table = txn.open_table(WORKLOAD_MEM)?;
            let stored = match table.get(id)? {
                Some(g) => decode::<BTreeMap<String, u64>>(g.value())?,
                None => BTreeMap::new(),
            };
            if stored != mem {
                table.insert(id, encode(&mem)?.as_slice())?;
            }
            Ok(((), Vec::new(), Durability::None))
        })
    }

    /// Record `event`, done by `actor`, in the audit log.
    pub fn audit(&self, actor: &str, event: &str, now: u64) -> Result<()> {
        let txn = self.db.begin_write().context("starting a write")?;
        append_audit(&txn, None, actor, event, now)?;
        txn.commit().context("writing an audit line")
    }

    /// Node `id`'s workloads, with their memory readings; `None` until a report listed them.
    pub fn workloads(&self, id: &str) -> Result<Option<Workloads>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let Some(listed) = txn.open_table(WORKLOADS)?.get(id)? else {
            return Ok(None);
        };
        let mut workloads: Workloads = decode(listed.value())?;
        if let Some(mem) = txn.open_table(WORKLOAD_MEM)?.get(id)? {
            workloads.mem_bytes = decode(mem.value())?;
        }
        Ok(Some(workloads))
    }

    /// Store node `id`'s report.
    pub fn record_report(&self, id: &str, report: Report, now: u64) -> Result<()> {
        let mut report = report;
        // Kept apart from the row.
        let listed = report.workloads.take().map(|mut listed| {
            display_safe_workloads(&mut listed);
            Workloads {
                listed,
                omitted: std::mem::take(&mut report.workloads_omitted),
                mem_bytes: BTreeMap::new(),
            }
        });
        self.update_txn(now, id, |row, txn| {
            if let Some(workloads) = &listed {
                let total = u32::try_from(workloads.listed.len())
                    .unwrap_or(u32::MAX)
                    .saturating_add(workloads.omitted);
                row.workloads = Some(total);
                txn.open_table(WORKLOADS)?
                    .insert(id, encode(workloads)?.as_slice())?;
            }
            row.last_seen = Some(now);
            Ok(((), Vec::new(), Durability::None))
        })
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

    /// Rewrite one node's row. A node removed meanwhile is an error: its session is then
    /// one the hub no longer recognizes.
    fn update(
        &self,
        id: &str,
        durability: Durability,
        change: impl FnOnce(&mut NodeRow),
    ) -> Result<()> {
        self.update_audited(
            id,
            durability,
            |row| {
                change(row);
                ((), Vec::new())
            },
            0,
        )
    }

    /// [`Db::update`], with the audit rows `change` returns — `(actor, event)` pairs — written
    /// in the same transaction as the change they describe.
    fn update_audited<R>(
        &self,
        id: &str,
        durability: Durability,
        change: impl FnOnce(&mut NodeRow) -> (R, Vec<(String, String)>),
        now: u64,
    ) -> Result<R> {
        self.update_txn(now, id, |row, _| {
            let (out, events) = change(row);
            Ok((out, events, durability))
        })
    }

    /// [`Db::update_audited`], with the transaction for `change` to write other tables in and
    /// the durability `change` decides on.
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
                None => bail!("node {id} is not enrolled"),
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

/// A token's key in [`TOKENS`], and a sign-in token's or session secret's in its table.
pub(crate) fn token_key(token: &str) -> String {
    vk_hub_proto::to_hex(&Sha256::digest(token.as_bytes()))
}

/// The longest workload ID the hub keeps a memory reading for: a node makes them 16 hex
/// digits.
const MAX_WORKLOAD_ID: usize = 64;

/// `workloads` cut to [`vk_hub_proto::MAX_WORKLOADS`], with every string in them made
/// [`vk_hub_proto::display_safe`].
fn display_safe_workloads(workloads: &mut Vec<vk_hub_proto::Workload>) {
    use vk_hub_proto::display_safe as safe;
    workloads.truncate(vk_hub_proto::MAX_WORKLOADS);
    for w in workloads {
        w.id = safe(&w.id);
        w.state_dir = safe(&w.state_dir);
        for s in [
            &mut w.label,
            &mut w.project,
            &mut w.job_name,
            &mut w.job_id,
            &mut w.workspace,
            &mut w.environment,
            &mut w.ssh_alias,
            &mut w.guest_workspace,
        ]
        .into_iter()
        .flatten()
        {
            *s = safe(s);
        }
    }
}

/// `inventory` with every string in it made [`vk_hub_proto::display_safe`].
fn display_safe_inventory(mut inventory: Inventory) -> Inventory {
    use vk_hub_proto::display_safe as safe;
    let clean = |s: &mut String| *s = safe(s);
    let clean_opt = |s: &mut Option<String>| {
        if let Some(v) = s.as_mut() {
            *v = safe(v);
        }
    };
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
    if let Some(runner) = inventory.runner.as_mut() {
        clean(&mut runner.config);
        for name in &mut runner.runners {
            clean(name);
        }
    }
    inventory
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
        let (token, expires) = db.create_token(DAY, 1000).unwrap();
        assert!(token.starts_with(TOKEN_PREFIX));
        assert_eq!(expires, 1000 + 86_400);
        let Enrollment::Enrolled { node_id } = db.enroll(&token, "aa", "ci-1", 1001).unwrap()
        else {
            panic!("expected an enrollment");
        };
        assert!(vk_hub_proto::valid_id(&node_id));
        assert_eq!(
            db.enroll(&token, "bb", "ci-2", 1002).unwrap(),
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
        let (token, expires) = db.create_token(Duration::from_secs(60), 1000).unwrap();
        assert_eq!(
            db.enroll(&token, "aa", "h", expires).unwrap(),
            Enrollment::BadToken
        );
        assert_eq!(
            db.enroll("vkh_nope", "aa", "h", 1000).unwrap(),
            Enrollment::BadToken
        );
        assert!(db.nodes().unwrap().is_empty());
    }

    #[test]
    fn a_pinned_key_enrolls_again_as_its_node_and_a_removed_one_anew() {
        let db = Db::open_memory().unwrap();
        let (t1, _) = db.create_token(DAY, 0).unwrap();
        let (t2, _) = db.create_token(DAY, 0).unwrap();
        let (t3, _) = db.create_token(DAY, 0).unwrap();
        let Enrollment::Enrolled { node_id } = db.enroll(&t1, "aa", "h", 1).unwrap() else {
            panic!("expected an enrollment");
        };
        assert_eq!(
            db.enroll(&t2, "aa", "h", 1).unwrap(),
            Enrollment::Reenrolled {
                node_id: node_id.clone()
            }
        );
        // The second token is spent by it all the same.
        assert_eq!(db.enroll(&t2, "bb", "h", 1).unwrap(), Enrollment::BadToken);
        assert_eq!(db.nodes().unwrap().len(), 1);
        assert!(db.remove_node(&node_id).unwrap());
        assert!(!db.remove_node(&node_id).unwrap());
        let Enrollment::Enrolled { node_id: again } = db.enroll(&t3, "aa", "h", 1).unwrap() else {
            panic!("expected a new enrollment");
        };
        assert_ne!(again, node_id);
    }

    #[test]
    fn token_lifetimes_are_bounded_and_expired_tokens_are_swept() {
        let db = Db::open_memory().unwrap();
        assert!(db.create_token(Duration::ZERO, 0).is_err());
        assert!(db.create_token(MAX_TOKEN_TTL + DAY, 0).is_err());
        db.create_token(Duration::from_secs(10), 0).unwrap();
        db.create_token(DAY, 20).unwrap();
        let txn = db.db.begin_read().unwrap();
        let table = txn.open_table(TOKENS).unwrap();
        assert_eq!(redb::ReadableTableMetadata::len(&table).unwrap(), 1);
    }

    #[test]
    fn a_session_inventory_and_heartbeat_are_recorded() {
        let db = Db::open_memory().unwrap();
        let (token, _) = db.create_token(DAY, 0).unwrap();
        let Enrollment::Enrolled { node_id } = db.enroll(&token, "aa", "h", 1).unwrap() else {
            panic!("expected an enrollment");
        };
        db.record_session(&node_id, "inc", 2).unwrap();
        let inventory = Inventory {
            hostname: "renamed\u{1b}[2J".into(),
            versions: vk_hub_proto::Versions {
                vk: "0.80\u{202e}.0".into(),
                ..Default::default()
            },
            ..Inventory::default()
        };
        db.record_inventory(&node_id, inventory, 3).unwrap();
        db.record_heartbeat(&node_id, Heartbeat::default(), 4)
            .unwrap();
        let row = db.node(&node_id).unwrap().unwrap();
        assert_eq!(row.incarnation.as_deref(), Some("inc"));
        assert_eq!(row.hostname, "renamed[2J");
        assert_eq!(row.inventory.as_ref().unwrap().versions.vk, "0.80.0");
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
        };
        db.record_report(&id, report(MAX_WORKLOADS + 5, 7), 2)
            .unwrap();
        let row = db.node(&id).unwrap().unwrap();
        // The row keeps the count and a report without them.
        assert_eq!(row.workloads, Some(MAX_WORKLOADS as u32 + 7));
        let stored = db.workloads(&id).unwrap().unwrap();
        assert_eq!((stored.listed.len(), stored.omitted), (MAX_WORKLOADS, 7));
        let w = &stored.listed[0];
        for s in [
            &w.state_dir,
            w.label.as_ref().unwrap(),
            w.project.as_ref().unwrap(),
            w.job_name.as_ref().unwrap(),
            w.job_id.as_ref().unwrap(),
            w.workspace.as_ref().unwrap(),
            w.environment.as_ref().unwrap(),
            w.ssh_alias.as_ref().unwrap(),
            w.guest_workspace.as_ref().unwrap(),
        ] {
            assert_eq!(s, "a[2J<b>");
        }
        // The next report replaces the list; a node stopping its VMs empties it; a report
        // that has not looked yet leaves the last one.
        db.record_report(&id, report(0, 0), 3).unwrap();
        db.record_report(&id, Report::default(), 4).unwrap();
        assert_eq!(db.node(&id).unwrap().unwrap().workloads, Some(0));
        assert_eq!(db.workloads(&id).unwrap().unwrap().listed, Vec::new());
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
        assert!(db.remove_node(&id).unwrap());
        assert_eq!(db.workloads(&id).unwrap(), None);
    }

    fn enrolled(db: &Db) -> String {
        let (token, _) = db.create_token(DAY, 0).unwrap();
        let Enrollment::Enrolled { node_id } = db.enroll(&token, "aa", "h", 1).unwrap() else {
            panic!("expected an enrollment");
        };
        node_id
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
