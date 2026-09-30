//! The hub's database: enrolled nodes and outstanding enrollment tokens, the web UI's sign-in
//! links and sessions, and the audit log, in [`redb`] like `vk-registry`'s accounts store —
//! tables of JSON rows, small enough that listing every node is a scan.
//!
//! A token is stored as `sha256(token)`, so the file holds nothing that enrolls a node.
//! Consuming a token and pinning the node's key happen in one write transaction: a token
//! enrolls exactly one node even with two enrollments racing on it. A token is looked up in a
//! read transaction first, so an unauthenticated caller guessing at tokens costs the hub
//! reads, never a durable write. The web UI's sign-in tokens and session cookies are kept the
//! same way: by hash, a sign-in token spent in the write that opens its session.
//!
//! Every string a node or the host's `vk` reports is stored through
//! [`vk_fleet_proto::display_safe`]: the database is where it crosses into the operator's
//! terminal and pages.
//!
//! Heartbeats are written at [`Durability::None`]: one arrives from every node every few
//! seconds, and losing the last few to a crash costs nothing — the next one replaces them.
//! Everything else is durable.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vk_fleet_proto::{
    Acquisition, Command, CommandAck, DesiredState, Heartbeat, Inventory, NodeState, Operation,
    Outcome, Report,
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

/// The most audit rows kept. Bounded by count rather than age: a quiet fleet keeps its history
/// for years, and a busy one keeps the newest hundred thousand actions and outcomes — months
/// at the rate of a few dozen nodes. Past it, the oldest go, a thousand at a time.
const AUDIT_MAX: u64 = 100_000;
const AUDIT_PRUNE: u64 = 1000;

/// How long a command is kept once it is settled — finished, refused, expired, or never
/// taken by its expiry — for `vk-hub nodes` and a look back. The audit log keeps the record.
const COMMAND_KEEP: u64 = 30 * 86_400;

/// Every enrollment token starts with this, so one pasted into the wrong place is
/// recognizable.
const TOKEN_PREFIX: &str = "vkh_";

/// The longest-lived token an operator may issue. A token is a bearer credential for adding
/// a machine to the fleet; one that outlives its purpose by months is one somebody finds.
pub const MAX_TOKEN_TTL: Duration = Duration::from_secs(30 * 86_400);

/// Every web UI sign-in token starts with this, so one pasted into the wrong place is
/// recognizable.
pub(crate) const LOGIN_PREFIX: &str = "vkl_";

/// The longest-lived sign-in link: it is meant to be opened right away, by whoever asked
/// for it.
pub const MAX_LOGIN_TTL: Duration = Duration::from_secs(86_400);

/// How long a web UI session lasts from sign-in: a working day, then a new link.
pub const UI_SESSION_TTL: Duration = Duration::from_secs(12 * 3600);

/// How many hex digits of a session's key name it: in `vk-hub local sessions`, and in the
/// audit log as the principal of what it did.
const SESSION_ID_LEN: usize = 12;

/// What a web UI session may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Read everything.
    Viewer,
    /// And act: stop, start, reboot and remove VMs.
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

/// A web UI session, as the UI and `vk-hub local sessions` see it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiSession {
    /// The start of its key, the hash of its secret: what names it, and no use as the
    /// secret.
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
    /// What the hub wants of the node; `None` until an operator first asks for anything.
    #[serde(default)]
    pub desired: Option<DesiredState>,
    /// The node's latest report of itself.
    #[serde(default)]
    pub report: Option<Report>,
}

/// A command issued to a node, and what the node last said it came to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandRow {
    pub node_id: String,
    pub command: Command,
    pub issued_at: u64,
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

/// One line of the audit log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRow {
    pub at: u64,
    /// The node it is about; `None` for the hub's own, and for everything in local mode.
    #[serde(default)]
    pub node: Option<String>,
    /// Who: `uid <n>` for an operator on the admin socket, a session's principal for what it
    /// did, `node` for what a node reported.
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
        txn.open_table(COMMANDS)
            .context("opening the commands table")?;
        txn.open_table(AUDIT).context("opening the audit table")?;
        txn.open_table(AUDIT_BY_NODE)
            .context("opening the audit index")?;
        txn.open_table(UI_LOGINS)
            .context("opening the sign-in links table")?;
        txn.open_table(UI_SESSIONS)
            .context("opening the web UI sessions table")?;
        txn.commit().context("initializing the hub database")?;
        Ok(Db { db })
    }

    /// Issue a single-use enrollment token valid for `ttl`. Returns the token — shown once,
    /// never stored — and when it expires. Expired tokens are swept in the same write.
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
        // The token itself is never logged: it is the credential.
        append_audit(
            &txn,
            None,
            actor,
            &format!(
                "{actor} issued an enrollment token valid for {}s",
                ttl.as_secs()
            ),
            now,
        )?;
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
                        let node_id = crate::random_hex(vk_fleet_proto::ID_BYTES)?;
                        let row = NodeRow {
                            public_key: public_key.to_string(),
                            hostname: vk_fleet_proto::display_safe(hostname),
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

    /// Remove a node: its key is no longer pinned, a session it opens is refused, and its
    /// commands go. Audited as `actor`'s. `Ok(false)` when there was no such node.
    pub fn remove_node(&self, id: &str, actor: &str, now: u64) -> Result<bool> {
        let txn = self.db.begin_write().context("starting a write")?;
        let removed = txn.open_table(NODES)?.remove(id)?.is_some();
        if removed {
            let (start, end) = command_range(id);
            txn.open_table(COMMANDS)?
                .retain_in(start.as_str()..end.as_str(), |_, _| false)?;
            append_audit(
                &txn,
                Some(id),
                actor,
                &format!("{actor} removed the node"),
                now,
            )?;
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
        self.update(id, Durability::None, |row| {
            row.heartbeat = Some(heartbeat);
            row.heartbeat_at = Some(now);
            row.last_seen = Some(now);
        })
    }

    /// Record `event`, done by `actor`, in the audit log.
    pub fn audit(&self, actor: &str, event: &str, now: u64) -> Result<()> {
        let txn = self.db.begin_write().context("starting a write")?;
        append_audit(&txn, None, actor, event, now)?;
        txn.commit().context("writing an audit line")
    }

    /// Change what the hub wants of node `id` through `change`, from the defaults — no
    /// ceiling, acquisition running — when nothing was wanted yet. A change takes the next
    /// generation after both the hub's and the one the node last reported applying, so it is
    /// newer to the node whatever the hub has forgotten; one that changes nothing is not
    /// stored. Audited as `actor` doing `what`. Returns the new desired state, or `None` when
    /// it was already so.
    pub fn set_desired(
        &self,
        id: &str,
        change: impl FnOnce(&mut DesiredState),
        actor: &str,
        what: &str,
        now: u64,
    ) -> Result<Option<DesiredState>> {
        self.update_audited(
            id,
            Durability::Immediate,
            |row| {
                let before = row.desired.clone().unwrap_or(DEFAULT_DESIRED);
                let mut next = before.clone();
                change(&mut next);
                if next.ceiling == before.ceiling && next.acquisition == before.acquisition {
                    return (None, Vec::new());
                }
                next.generation = before.generation.max(applied(row)).saturating_add(1);
                row.desired = Some(next.clone());
                let event = format!("{actor} {what} (generation {})", next.generation);
                (Some(next), vec![(actor.to_string(), event)])
            },
            now,
        )
    }

    /// Store node `id`'s report, and audit what it says that is new: a state, an applied
    /// generation, what the node cannot carry out.
    ///
    /// A node that reports a generation newer than the hub's own has taken it from a hub that
    /// knew more — this one restored from a backup, say. The hub then moves past it: its
    /// desired state is re-issued as the generation after the node's, so the node, which
    /// ignores anything not newer than what it applied, takes it, and nothing is sent before
    /// the report that shows where the node is.
    pub fn record_report(&self, id: &str, report: Report, now: u64) -> Result<()> {
        let mut report = report;
        for note in &mut report.unsupported {
            *note = vk_fleet_proto::display_safe(note);
        }
        if let Some(error) = report.concurrency_error.as_mut() {
            *error = vk_fleet_proto::display_safe(error);
        }
        self.update_audited(
            id,
            Durability::Immediate,
            |row| {
                let mut events: Vec<(String, String)> = report_events(row.report.as_ref(), &report)
                    .into_iter()
                    .map(|e| ("node".to_string(), e))
                    .collect();
                let ours = row.desired.as_ref().map_or(0, |d| d.generation);
                if let Some(theirs) = report.applied_generation
                    && theirs > ours
                {
                    let mut desired = row.desired.clone().unwrap_or(DEFAULT_DESIRED);
                    desired.generation = theirs.saturating_add(1);
                    events.push((
                        "hub".to_string(),
                        format!(
                            "the node applied generation {theirs}, past this hub's {ours}: \
                         re-issued the desired state as generation {}",
                            desired.generation
                        ),
                    ));
                    row.desired = Some(desired);
                }
                row.report = Some(report);
                row.last_seen = Some(now);
                ((), events)
            },
            now,
        )
    }

    /// Issue `op` to node `id`, valid for `ttl`, audited as `actor`'s. The node must be
    /// enrolled. Its commands settled longer than [`COMMAND_KEEP`] ago go in the same write.
    pub fn issue_command(
        &self,
        id: &str,
        op: Operation,
        ttl: Duration,
        actor: &str,
        now: u64,
    ) -> Result<Command> {
        let command = Command {
            id: crate::random_hex(vk_fleet_proto::ID_BYTES)?,
            expires_at: now.saturating_add(ttl.as_secs()),
            op,
        };
        let row = CommandRow {
            node_id: id.to_string(),
            command: command.clone(),
            issued_at: now,
            outcome: None,
            outcome_at: None,
        };
        let txn = self.db.begin_write().context("starting a write")?;
        {
            if txn.open_table(NODES)?.get(id)?.is_none() {
                bail!("node {id} is not enrolled");
            }
            let mut commands = txn.open_table(COMMANDS)?;
            let (start, end) = command_range(id);
            commands.retain_in(start.as_str()..end.as_str(), |_, value| {
                decode::<CommandRow>(value).map_or(true, |r| !r.settled_before(now, COMMAND_KEEP))
            })?;
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
    /// their expiry that it never answered — it would only refuse them.
    pub fn pending_commands(&self, id: &str, now: u64) -> Result<Vec<Command>> {
        let mut rows = self.node_commands(id)?;
        rows.retain(|r| r.pending() && (r.outcome.is_some() || r.command.expires_at > now));
        rows.sort_by_key(|r| r.issued_at);
        Ok(rows.into_iter().map(|r| r.command).collect())
    }

    /// Every command of node `id`.
    pub fn node_commands(&self, id: &str) -> Result<Vec<CommandRow>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(COMMANDS)?;
        let (start, end) = command_range(id);
        let mut out = Vec::new();
        for entry in table.range(start.as_str()..end.as_str())? {
            let (_, value) = entry?;
            out.push(decode::<CommandRow>(value.value())?);
        }
        Ok(out)
    }

    /// Store what node `id` said command `ack.id` came to, and audit it. Returns whether the
    /// outcome was news; `false` for one already recorded, a command this hub never issued,
    /// and anything after a final outcome — a stale `accepted` arriving late must not reopen a
    /// finished command.
    pub fn record_ack(&self, id: &str, ack: &CommandAck, now: u64) -> Result<bool> {
        let key = format!("{id}/{}", ack.id);
        let txn = self.db.begin_write().context("starting a write")?;
        let news = {
            let mut table = txn.open_table(COMMANDS)?;
            let row = table
                .get(key.as_str())?
                .map(|g| decode::<CommandRow>(g.value()))
                .transpose()?;
            match row {
                // A final outcome stays: nothing the node sends after it replaces it.
                Some(mut row) if row.pending() && row.outcome.as_ref() != Some(&ack.outcome) => {
                    row.outcome = Some(ack.outcome.clone());
                    row.outcome_at = Some(now);
                    table.insert(key.as_str(), encode(&row)?.as_slice())?;
                    Some(row.command)
                }
                _ => None,
            }
        };
        if let Some(command) = &news {
            let event = format!(
                "command {} ({}): {}",
                command.id,
                operation_name(&command.op),
                outcome_text(&ack.outcome)
            );
            append_audit(&txn, Some(id), "node", &event, now)?;
        }
        txn.commit().context("recording an ack")?;
        Ok(news.is_some())
    }

    /// The last `limit` audit lines, oldest first, of one node or of all.
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
    /// unknown, spent or expired. Looked up in a read first, so a guess costs no write.
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
        let row = txn
            .open_table(UI_SESSIONS)?
            .get(key.as_str())?
            .map(|g| decode::<UiSessionRow>(g.value()))
            .transpose()?;
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
            let row = decode::<UiSessionRow>(value.value())?;
            if row.expires_at > now {
                out.push(UiSession::new(key.value(), row));
            }
        }
        out.sort_by_key(|s| s.created_at);
        Ok(out)
    }

    /// End the web UI session listed as `id`, or every one with `None`, audited as `actor`'s.
    /// Returns how many ended.
    pub fn end_ui_sessions(&self, id: Option<&str>, actor: &str, now: u64) -> Result<usize> {
        let txn = self.db.begin_write().context("starting a write")?;
        let mut ended = Vec::new();
        {
            let mut table = txn.open_table(UI_SESSIONS)?;
            table.retain(|key, value| {
                let Ok(row) = decode::<UiSessionRow>(value) else {
                    return false;
                };
                let session = UiSession::new(key, row);
                if id.is_none_or(|id| id == session.id) {
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

    /// Up to `limit` audit lines older than sequence number `before` — all of them for
    /// `None` — newest first, each with its sequence number for the next page.
    pub fn audit_page(&self, before: Option<u64>, limit: usize) -> Result<Vec<(u64, AuditRow)>> {
        let before = before.unwrap_or(u64::MAX);
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(AUDIT)?;
        let mut out = Vec::new();
        for entry in table.range(..before)?.rev().take(limit) {
            let (seq, value) = entry?;
            out.push((seq.value(), decode::<AuditRow>(value.value())?));
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
        let mut txn = self.db.begin_write().context("starting a write")?;
        txn.set_durability(durability)
            .context("setting a write's durability")?;
        let out = {
            let mut table = txn.open_table(NODES)?;
            let mut row = match table.get(id)? {
                Some(g) => decode::<NodeRow>(g.value())?,
                None => bail!("node {id} is not enrolled"),
            };
            let (out, events) = change(&mut row);
            table.insert(id, encode(&row)?.as_slice())?;
            for (actor, event) in events {
                append_audit(&txn, Some(id), &actor, &event, now)?;
            }
            out
        };
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

/// The generation node `row` last reported applying, 0 before any.
fn applied(row: &NodeRow) -> u64 {
    row.report
        .as_ref()
        .and_then(|r| r.applied_generation)
        .unwrap_or(0)
}

/// The key range of node `id`'s commands.
fn command_range(id: &str) -> (String, String) {
    (format!("{id}/"), format!("{id}0"))
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
        event: vk_fleet_proto::display_safe(event),
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

/// The audit lines a report is worth: a new state, a newly applied generation, and what of it
/// the node cannot carry out — or its concurrency — as it changes.
fn report_events(previous: Option<&Report>, report: &Report) -> Vec<String> {
    let mut events = Vec::new();
    if previous.is_none_or(|p| p.state != report.state) {
        events.push(format!("state {}", state_name(report.state)));
    }
    if previous.is_none_or(|p| p.applied_generation != report.applied_generation)
        && let Some(generation) = report.applied_generation
    {
        events.push(format!("applied generation {generation}"));
    }
    if previous.is_none_or(|p| p.unsupported != report.unsupported) {
        for note in &report.unsupported {
            events.push(format!("cannot comply: {note}"));
        }
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
        NodeState::Quarantined => "quarantined",
    }
}

pub(crate) fn operation_name(op: &Operation) -> String {
    match op {
        Operation::Drain => "drain".into(),
        Operation::Undrain => "undrain".into(),
        Operation::Quarantine => "quarantine".into(),
        Operation::Release => "release".into(),
        Operation::Update { version } => {
            format!("update to {}", vk_fleet_proto::display_safe(version))
        }
        Operation::Reset => "reset".into(),
    }
}

fn outcome_text(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Accepted => "accepted".into(),
        Outcome::Done => "done".into(),
        Outcome::Failed { message } => format!("failed: {}", vk_fleet_proto::display_safe(message)),
        Outcome::Refused { reason } => format!("refused: {}", vk_fleet_proto::display_safe(reason)),
        Outcome::Expired => "expired".into(),
    }
}

/// A token's key in [`TOKENS`], and a sign-in token's or session secret's in its table.
fn token_key(token: &str) -> String {
    vk_fleet_proto::to_hex(&Sha256::digest(token.as_bytes()))
}

/// `inventory` with every string in it made [`vk_fleet_proto::display_safe`].
fn display_safe_inventory(mut inventory: Inventory) -> Inventory {
    use vk_fleet_proto::display_safe as safe;
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

    fn audit(db: &Db, event: &str, at: u64) {
        let txn = db.db.begin_write().unwrap();
        append_audit(&txn, None, "uid 0", event, at).unwrap();
        txn.commit().unwrap();
    }

    #[test]
    fn a_token_enrolls_exactly_one_node() {
        let db = Db::open_memory().unwrap();
        let (token, expires) = db.create_token(DAY, "uid 0", 1000).unwrap();
        assert!(token.starts_with(TOKEN_PREFIX));
        assert_eq!(expires, 1000 + 86_400);
        let Enrollment::Enrolled { node_id } = db.enroll(&token, "aa", "ci-1", 1001).unwrap()
        else {
            panic!("expected an enrollment");
        };
        assert!(vk_fleet_proto::valid_id(&node_id));
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
        let (token, expires) = db
            .create_token(Duration::from_secs(60), "uid 0", 1000)
            .unwrap();
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
        let (t1, _) = db.create_token(DAY, "uid 0", 0).unwrap();
        let (t2, _) = db.create_token(DAY, "uid 0", 0).unwrap();
        let (t3, _) = db.create_token(DAY, "uid 0", 0).unwrap();
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
        assert!(db.remove_node(&node_id, "uid 0", 2).unwrap());
        assert!(!db.remove_node(&node_id, "uid 0", 2).unwrap());
        let Enrollment::Enrolled { node_id: again } = db.enroll(&t3, "aa", "h", 1).unwrap() else {
            panic!("expected a new enrollment");
        };
        assert_ne!(again, node_id);
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
        let Enrollment::Enrolled { node_id } = db.enroll(&token, "aa", "h", 1).unwrap() else {
            panic!("expected an enrollment");
        };
        db.record_session(&node_id, "inc", 2).unwrap();
        let inventory = Inventory {
            hostname: "renamed\u{1b}[2J".into(),
            versions: vk_fleet_proto::Versions {
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

    fn enrolled(db: &Db) -> String {
        let (token, _) = db.create_token(DAY, "uid 0", 0).unwrap();
        let Enrollment::Enrolled { node_id } = db.enroll(&token, "aa", "h", 1).unwrap() else {
            panic!("expected an enrollment");
        };
        node_id
    }

    #[test]
    fn a_desired_change_takes_the_next_generation_and_no_change_takes_none() {
        let db = Db::open_memory().unwrap();
        let id = enrolled(&db);
        let set = |ceiling| {
            db.set_desired(&id, |d| d.ceiling = ceiling, "uid 0", "set a ceiling", 5)
                .unwrap()
        };
        let d = set(Some(4)).unwrap();
        assert_eq!((d.generation, d.ceiling), (1, Some(4)));
        assert!(set(Some(4)).is_none());
        let d = db
            .set_desired(
                &id,
                |d| d.acquisition = Acquisition::Stop,
                "uid 0",
                "changed",
                5,
            )
            .unwrap()
            .unwrap();
        assert_eq!((d.generation, d.ceiling), (2, Some(4)));
        assert_eq!(db.node(&id).unwrap().unwrap().desired, Some(d));
        assert!(
            db.set_desired(&"0".repeat(32), |d| d.ceiling = None, "uid 0", "changed", 5)
                .is_err()
        );
    }

    #[test]
    fn a_command_is_pending_until_it_has_a_final_outcome() {
        let db = Db::open_memory().unwrap();
        let id = enrolled(&db);
        let other = {
            let (token, _) = db.create_token(DAY, "uid 0", 0).unwrap();
            let Enrollment::Enrolled { node_id } = db.enroll(&token, "bb", "h", 1).unwrap() else {
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
        let row = db
            .node_commands(&id)
            .unwrap()
            .into_iter()
            .find(|r| r.command.id == drain.id)
            .unwrap();
        assert_eq!(row.outcome, Some(Outcome::Done));
        let events: Vec<String> = db
            .audits(Some(&id), 10)
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect();
        assert!(events[0].starts_with("uid 0 issued drain"), "{events:?}");
        assert_eq!(events.len(), 3, "{events:?}");
        // An unanswered command past its expiry is not resent; another node's is not ours.
        db.issue_command(&id, Operation::Release, Duration::from_secs(5), "uid 0", 20)
            .unwrap();
        assert!(db.pending_commands(&id, 30).unwrap().is_empty());
        assert_eq!(db.node_commands(&other).unwrap().len(), 1);
        assert!(
            db.issue_command(&"0".repeat(32), Operation::Drain, DAY, "uid 0", 1)
                .is_err()
        );
    }

    /// A hub restored from a backup may be behind the generation a node applied; it moves
    /// past the node's rather than send what the node would ignore.
    #[test]
    fn a_node_ahead_of_the_hub_gets_the_desired_state_reissued_past_it() {
        let db = Db::open_memory().unwrap();
        let id = enrolled(&db);
        db.set_desired(&id, |d| d.ceiling = Some(4), "uid 0", "set a ceiling", 1)
            .unwrap();
        let report = |applied| Report {
            applied_generation: applied,
            ..Report::default()
        };
        db.record_report(&id, report(Some(1)), 2).unwrap();
        assert_eq!(
            db.node(&id).unwrap().unwrap().desired.unwrap().generation,
            1
        );
        db.record_report(&id, report(Some(9)), 3).unwrap();
        let desired = db.node(&id).unwrap().unwrap().desired.unwrap();
        assert_eq!((desired.generation, desired.ceiling), (10, Some(4)));
        // And a change takes the generation after both.
        db.record_report(&id, report(Some(12)), 4).unwrap();
        let next = db
            .set_desired(&id, |d| d.ceiling = None, "uid 0", "lifted the ceiling", 5)
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
            events
                .iter()
                .any(|e| e.contains("re-issued the desired state as generation 10")),
            "{events:?}"
        );
    }

    #[test]
    fn old_audit_rows_and_settled_commands_are_pruned() {
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

        let id = enrolled(&db);
        let old = db
            .issue_command(&id, Operation::Release, DAY, "uid 0", 0)
            .unwrap();
        db.record_ack(
            &id,
            &CommandAck {
                id: old.id,
                outcome: Outcome::Done,
            },
            1,
        )
        .unwrap();
        db.issue_command(&id, Operation::Release, DAY, "uid 0", 2 + COMMAND_KEEP)
            .unwrap();
        assert_eq!(db.node_commands(&id).unwrap().len(), 1);
        assert!(db.remove_node(&id, "uid 0", 3 + COMMAND_KEEP).unwrap());
        assert!(db.node_commands(&id).unwrap().is_empty());
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

    #[test]
    fn the_audit_log_pages_back_newest_first() {
        let db = Db::open_memory().unwrap();
        for i in 0..5u64 {
            audit(&db, &format!("event {i}"), i);
        }
        let events = |rows: Vec<(u64, AuditRow)>| -> Vec<(u64, String)> {
            rows.into_iter().map(|(s, r)| (s, r.event)).collect()
        };
        let first = events(db.audit_page(None, 2).unwrap());
        assert_eq!(first, [(4, "event 4".into()), (3, "event 3".into())]);
        let next = events(db.audit_page(Some(3), 2).unwrap());
        assert_eq!(next, [(2, "event 2".into()), (1, "event 1".into())]);
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
