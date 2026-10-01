//! The hub's database: the web UI's sign-in links and sessions, and the audit log, in
//! [`redb`] like `vk-registry`'s accounts store — tables of JSON rows.
//!
//! Sign-in tokens and session secrets are stored as `sha256` hashes, so the file cannot
//! supply sign-in credentials. A read transaction rejects token guesses without a durable
//! write. Redeeming a token and creating its session share one write transaction, so
//! concurrent posts can open only one session per link.
//!
//! Every audit line goes through [`vk_hub_proto::display_safe`]: it holds what the host's
//! `vk` said, and the log is read on terminals and pages.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Key: a sequence number, oldest first. Value: JSON [`AuditRow`].
const AUDIT: TableDefinition<u64, &[u8]> = TableDefinition::new("audit");
/// Key: `sha256(sign-in token)`, hex. Value: JSON [`LoginRow`].
const UI_LOGINS: TableDefinition<&str, &[u8]> = TableDefinition::new("ui_logins");
/// Key: `sha256(session secret)`, hex. Value: JSON [`UiSessionRow`].
const UI_SESSIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("ui_sessions");

/// The most audit rows kept. Bounded by count rather than age: a quiet hub keeps its history
/// for years, and a busy one the newest hundred thousand actions. Past it, the oldest go, a
/// thousand at a time.
const AUDIT_MAX: u64 = 100_000;
const AUDIT_PRUNE: u64 = 1000;

/// Every web UI sign-in token starts with this, so one pasted into the wrong place is
/// recognizable.
pub(crate) const LOGIN_PREFIX: &str = "vkl_";

/// The longest-lived sign-in link: it is meant to be opened right away, by whoever asked
/// for it.
pub const MAX_LOGIN_TTL: Duration = Duration::from_secs(86_400);

/// How long a web UI session lasts from sign-in: a working day, then a new link.
pub const UI_SESSION_TTL: Duration = Duration::from_secs(12 * 3600);

/// How many hex digits of a session's key name it: in `vk-hub local sessions`, and in the
/// audit log as the principal of what it did. 48 bits, unique among the few sessions a hub
/// holds but not guaranteed to be: `vk-hub local logout <id>` ends every session that shares
/// one, and a browser's own sign-out ends its session by the whole key.
const SESSION_ID_LEN: usize = 12;

/// What a web UI session may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Viewer,
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

/// One line of the audit log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRow {
    pub at: u64,
    /// Who: `uid <n>` for whoever used the admin socket, a session's principal for what it
    /// did, `vk-hub local` for what the hub itself did as it started.
    pub actor: String,
    pub event: String,
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
        txn.open_table(AUDIT).context("opening the audit table")?;
        txn.open_table(UI_LOGINS)
            .context("opening the sign-in links table")?;
        txn.open_table(UI_SESSIONS)
            .context("opening the web UI sessions table")?;
        txn.commit().context("initializing the hub database")?;
        Ok(Db { db })
    }

    /// The last `limit` audit lines, oldest first.
    #[cfg(test)]
    pub fn audits(&self, limit: usize) -> Result<Vec<AuditRow>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(AUDIT)?;
        let mut out = Vec::new();
        for entry in table.iter()?.rev().take(limit) {
            out.push(decode::<AuditRow>(entry?.1.value())?);
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
                    append_audit(&txn, &session.principal(), &event, now)?;
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
            append_audit(&txn, actor, &event, now)?;
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
            append_audit(&txn, actor, &event, now)?;
        }
        txn.commit().context("voiding sign-in links")?;
        Ok(live)
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
}

/// Append an audit row inside `txn`, dropping the oldest past [`AUDIT_MAX`].
fn append_audit(txn: &redb::WriteTransaction, actor: &str, event: &str, now: u64) -> Result<()> {
    let row = AuditRow {
        at: now,
        actor: actor.to_string(),
        event: vk_hub_proto::display_safe(event),
    };
    let mut table = txn.open_table(AUDIT)?;
    let seq = table
        .last()?
        .map_or(0, |(k, _)| k.value().saturating_add(1));
    table.insert(seq, encode(&row)?.as_slice())?;
    let first = table.first()?.map_or(seq, |(k, _)| k.value());
    if seq.saturating_sub(first) >= AUDIT_MAX {
        let cut = first.saturating_add(AUDIT_PRUNE);
        table.retain_in(first..cut, |_, _| false)?;
    }
    Ok(())
}

/// A secret's key in its table.
pub(crate) fn token_key(token: &str) -> String {
    crate::hex::to_hex(&Sha256::digest(token.as_bytes()))
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
        append_audit(&txn, "uid 0", event, at).unwrap();
        txn.commit().unwrap();
    }

    #[test]
    fn old_audit_rows_are_pruned() {
        let db = Db::open_memory().unwrap();
        let txn = db.db.begin_write().unwrap();
        for i in 0..AUDIT_MAX + 5 {
            append_audit(&txn, "uid 0", &format!("e{i}"), i).unwrap();
        }
        txn.commit().unwrap();
        let txn = db.db.begin_read().unwrap();
        let rows = redb::ReadableTableMetadata::len(&txn.open_table(AUDIT).unwrap()).unwrap();
        assert!(
            rows <= AUDIT_MAX && rows > AUDIT_MAX - AUDIT_PRUNE,
            "{rows}"
        );
        drop(txn);
        assert_eq!(
            db.audits(1).unwrap()[0].event,
            format!("e{}", AUDIT_MAX + 4)
        );
    }

    #[test]
    fn the_audit_log_reads_back_in_order_and_display_safe() {
        let db = Db::open_memory().unwrap();
        for i in 0..5u64 {
            audit(&db, &format!("event {i}"), i);
        }
        audit(&db, "stopped a VM\u{1b}[2J", 9);
        let all = db.audits(100).unwrap();
        assert_eq!(all.len(), 6);
        assert_eq!(all[5].event, "stopped a VM[2J");
        assert_eq!(db.audits(2).unwrap()[0].event, "event 4");
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
            .audits(20)
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
