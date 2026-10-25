//! GitLab relays: their enrollment, pinned keys, what they report, and the GitLab server each
//! is bound to. Separate tables and token kinds keep a relay from being taken for a node or a
//! registry. Audit rows are indexed by relay ID, as node audit rows are by node ID.
//!
//! A relay is bound to the server its first inventory names. A server no instance has (see
//! [`super::gitlabs`]) is pending: an operator approves it by adding an instance at its URL.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use redb::{Durability, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use vk_hub_proto::gitlab::{Heartbeat, Inventory, Report, ServerState, ServerStatus};

use super::gitlabs::{GITLABS, GitlabRow, normalize_gitlab_url};
use super::{Db, NotEnrolled, TokenKind, append_audit, decode, encode, spend_token, token_key};

/// Key: relay ID. Value: JSON [`RelayRow`].
pub(super) const RELAYS: TableDefinition<&str, &[u8]> = TableDefinition::new("relays");

/// A relay as the hub knows it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayRow {
    /// Its pinned ed25519 key, hex.
    pub public_key: String,
    pub hostname: String,
    pub enrolled_at: u64,
    #[serde(default)]
    pub incarnation: Option<String>,
    #[serde(default)]
    pub protocol: Option<u32>,
    #[serde(default)]
    pub last_seen: Option<u64>,
    #[serde(default)]
    pub inventory: Option<Inventory>,
    #[serde(default)]
    pub heartbeat: Option<Heartbeat>,
    #[serde(default)]
    pub heartbeat_at: Option<u64>,
    #[serde(default)]
    pub report: Option<Report>,
    /// The URL of the GitLab server it is bound to, as [`normalize_gitlab_url`] writes it,
    /// and since when: from its first inventory on.
    #[serde(default)]
    pub server_url: Option<String>,
    #[serde(default)]
    pub bound_at: Option<u64>,
}

/// What a relay's enrollment came to.
#[derive(Debug, PartialEq, Eq)]
pub enum RelayEnrollment {
    Enrolled {
        id: String,
    },
    /// The relay already pinned to this key, after a lost enrollment answer.
    Reenrolled {
        id: String,
    },
    /// Unknown, spent, expired, or issued for another kind of peer.
    BadToken,
}

/// What a relay's session writes.
pub enum RelayWrite {
    Inventory(Inventory),
    Heartbeat(Heartbeat),
    Report(Report),
}

/// A GitLab server relays report and no instance has, waiting for an operator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingGitlab {
    /// As [`normalize_gitlab_url`] writes it.
    pub url: String,
    /// What a relay bound to it last reported of it: the sha256 of its certificate's public
    /// key, and its version. Each relay reports its own; the first one reporting this server
    /// is shown.
    pub spki_sha256: Option<String>,
    pub version: Option<String>,
    /// The relays bound to it: ID, hostname, since when.
    pub relays: Vec<(String, String, u64)>,
}

/// The status of a relay bound to `bound` that reports `reported`, given `instances`.
fn status_of(
    bound: &str,
    reported: Option<&str>,
    instances: &[(String, GitlabRow)],
) -> ServerStatus {
    let rebound = reported.is_some_and(|r| normalize_gitlab_url(r).as_deref() != Some(bound));
    let name = instances
        .iter()
        .find(|(_, row)| row.url == bound)
        .map(|(name, _)| name.clone());
    let state = match (&name, rebound) {
        (_, true) => ServerState::Rebound,
        (Some(_), false) => ServerState::Approved,
        (None, false) => ServerState::Pending,
    };
    ServerStatus {
        state,
        url: bound.to_string(),
        name: name.filter(|_| state.approved()),
    }
}

fn instances_in(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<Vec<(String, GitlabRow)>> {
    let mut out = Vec::new();
    for entry in table.iter()? {
        let (name, value) = entry?;
        out.push((name.value().to_string(), decode(value.value())?));
    }
    Ok(out)
}

impl Db {
    /// Consume `token`, issued for a relay, and pin `public_key` (hex) as a new relay, or
    /// answer with the one it is already pinned to, audited as `actor`'s. The caller has
    /// checked the relay's signature.
    pub fn enroll_relay(
        &self,
        token: &str,
        public_key: &str,
        hostname: &str,
        actor: &str,
        now: u64,
    ) -> Result<RelayEnrollment> {
        let key = token_key(token);
        if !self.token_live(&key, TokenKind::Gitlab, now)? {
            return Ok(RelayEnrollment::BadToken);
        }
        let txn = self.db.begin_write().context("starting a write")?;
        let outcome = if spend_token(&txn, &key, TokenKind::Gitlab, now)? {
            let mut table = txn.open_table(RELAYS)?;
            let mut pinned = None;
            for entry in table.iter()? {
                let (id, value) = entry?;
                if decode::<RelayRow>(value.value())?.public_key == public_key {
                    pinned = Some(id.value().to_string());
                    break;
                }
            }
            if let Some(id) = pinned {
                let event = format!("relay {id} enrolled again with its pinned key");
                append_audit(&txn, Some(&id), actor, &event, now)?;
                RelayEnrollment::Reenrolled { id }
            } else {
                let id = crate::random_hex(vk_hub_proto::ID_BYTES)?;
                let row = RelayRow {
                    public_key: public_key.to_string(),
                    hostname: vk_hub_proto::display_safe(hostname),
                    enrolled_at: now,
                    ..RelayRow::default()
                };
                table.insert(id.as_str(), encode(&row)?.as_slice())?;
                let event = format!("relay {id} enrolled as {}", row.hostname);
                append_audit(&txn, Some(&id), actor, &event, now)?;
                RelayEnrollment::Enrolled { id }
            }
        } else {
            RelayEnrollment::BadToken
        };
        txn.commit().context("recording an enrollment")?;
        Ok(outcome)
    }

    pub fn relay(&self, id: &str) -> Result<Option<RelayRow>> {
        let txn = self.db.begin_read().context("starting a read")?;
        txn.open_table(RELAYS)?
            .get(id)?
            .map(|g| decode(g.value()))
            .transpose()
    }

    /// Every relay, by ID.
    pub fn relays(&self) -> Result<Vec<(String, RelayRow)>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(RELAYS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (id, value) = entry?;
            out.push((id.value().to_string(), decode(value.value())?));
        }
        Ok(out)
    }

    /// Every relay, by ID, with the status of its server once it is bound to one, read in
    /// one snapshot.
    pub fn relays_with_status(&self) -> Result<Vec<(String, RelayRow, Option<ServerStatus>)>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let instances = instances_in(&txn.open_table(GITLABS)?)?;
        let table = txn.open_table(RELAYS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (id, value) = entry?;
            let row: RelayRow = decode(value.value())?;
            let status = relay_status(&row, &instances);
            out.push((id.value().to_string(), row, status));
        }
        Ok(out)
    }

    /// Relay `id`, with the status of its server once it is bound to one.
    pub fn relay_with_status(&self, id: &str) -> Result<Option<(RelayRow, Option<ServerStatus>)>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let Some(row) = txn
            .open_table(RELAYS)?
            .get(id)?
            .map(|g| decode::<RelayRow>(g.value()))
            .transpose()?
        else {
            return Ok(None);
        };
        let instances = instances_in(&txn.open_table(GITLABS)?)?;
        let status = relay_status(&row, &instances);
        Ok(Some((row, status)))
    }

    /// The IDs of the relays bound to the server at `url`, normalized.
    pub fn relays_of(&self, url: &str) -> Result<Vec<String>> {
        Ok(self
            .relays()?
            .into_iter()
            .filter(|(_, r)| r.server_url.as_deref() == Some(url))
            .map(|(id, _)| id)
            .collect())
    }

    /// The servers relays are bound to that no instance has, by URL.
    pub fn pending_gitlabs(&self) -> Result<Vec<PendingGitlab>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let instances = instances_in(&txn.open_table(GITLABS)?)?;
        let mut pending: BTreeMap<String, PendingGitlab> = BTreeMap::new();
        let table = txn.open_table(RELAYS)?;
        for entry in table.iter()? {
            let (id, value) = entry?;
            let row: RelayRow = decode(value.value())?;
            let Some(url) = row.server_url.clone() else {
                continue;
            };
            if instances.iter().any(|(_, i)| i.url == url) {
                continue;
            }
            // What a relay reports of another server is not this one's.
            let server = row
                .inventory
                .as_ref()
                .map(|i| &i.server)
                .filter(|s| normalize_gitlab_url(&s.url).as_deref() == Some(url.as_str()));
            let p = pending.entry(url.clone()).or_insert_with(|| PendingGitlab {
                url,
                spki_sha256: None,
                version: None,
                relays: Vec::new(),
            });
            if p.spki_sha256.is_none()
                && p.version.is_none()
                && let Some(s) = server
            {
                p.spki_sha256.clone_from(&s.spki_sha256);
                p.version.clone_from(&s.version);
            }
            p.relays.push((
                id.value().to_string(),
                row.hostname.clone(),
                row.bound_at.unwrap_or(row.enrolled_at),
            ));
        }
        let mut pending: Vec<PendingGitlab> = pending.into_values().collect();
        for p in &mut pending {
            p.relays.sort_by_key(|(id, _, at)| (*at, id.clone()));
        }
        Ok(pending)
    }

    /// Remove a relay, audited as `actor`'s: its key is no longer pinned. `Ok(false)` when
    /// there was no such relay.
    pub fn remove_relay(&self, id: &str, actor: &str, now: u64) -> Result<bool> {
        let txn = self.db.begin_write().context("starting a write")?;
        let removed = txn.open_table(RELAYS)?.remove(id)?.is_some();
        if removed {
            append_audit(
                &txn,
                Some(id),
                actor,
                &format!("{actor} removed relay {id}"),
                now,
            )?;
        }
        txn.commit().context("removing a relay")?;
        Ok(removed)
    }

    /// Record an authenticated session's `incarnation` and protocol `version` if `current`
    /// holds inside the write; whether it was recorded.
    pub fn record_relay_session(
        &self,
        id: &str,
        incarnation: &str,
        version: u32,
        now: u64,
        current: impl FnOnce() -> bool,
    ) -> Result<bool> {
        self.update_relay(now, id, Durability::Immediate, |row| {
            let current = current();
            if current {
                row.incarnation = Some(incarnation.to_string());
                row.protocol = Some(version);
                row.last_seen = Some(now);
            }
            Ok((current, Vec::new()))
        })
    }

    /// Store what a relay's session reported, which the session made display-safe on
    /// receipt. The first inventory binds the relay to its server, whose URL the caller has
    /// checked [`normalize_gitlab_url`] takes. A heartbeat is made durable only as a node's
    /// is (see [`Db::heartbeat_syncs`]).
    pub fn record_relay(&self, id: &str, write: RelayWrite, now: u64) -> Result<()> {
        let durability = match write {
            RelayWrite::Heartbeat(_) if !self.heartbeat_syncs(now) => Durability::None,
            _ => Durability::Immediate,
        };
        self.update_relay(now, id, durability, |row| {
            row.last_seen = Some(now);
            let mut events = Vec::new();
            match write {
                RelayWrite::Inventory(inventory) => {
                    if let Some(old) = &row.inventory
                        && old.version != inventory.version
                    {
                        events.push((
                            "relay".to_string(),
                            format!("runs vk-gitlab {} (was {})", inventory.version, old.version),
                        ));
                    }
                    let url = normalize_gitlab_url(&inventory.server.url);
                    match (&row.server_url, url) {
                        (None, Some(url)) => {
                            events.push(("relay".to_string(), format!("bound to GitLab {url}")));
                            row.server_url = Some(url);
                            row.bound_at = Some(now);
                        }
                        (Some(bound), Some(url))
                            if *bound != url
                                && row.inventory.as_ref().is_none_or(|old| {
                                    normalize_gitlab_url(&old.server.url).as_deref()
                                        == Some(bound.as_str())
                                }) =>
                        {
                            events.push((
                                "relay".to_string(),
                                format!("reports GitLab {url}, not {bound} it is bound to"),
                            ));
                        }
                        _ => {}
                    }
                    row.hostname.clone_from(&inventory.hostname);
                    row.inventory = Some(inventory);
                }
                RelayWrite::Heartbeat(heartbeat) => {
                    row.heartbeat = Some(heartbeat);
                    row.heartbeat_at = Some(now);
                }
                RelayWrite::Report(report) => row.report = Some(report),
            }
            Ok(((), events))
        })
    }

    /// Read-modify-write relay `id`'s row and append the audit pairs `change` returns, in one
    /// transaction at `durability`. [`NotEnrolled`] when the relay was removed.
    fn update_relay<R>(
        &self,
        now: u64,
        id: &str,
        durability: Durability,
        change: impl FnOnce(&mut RelayRow) -> Result<(R, Vec<(String, String)>)>,
    ) -> Result<R> {
        let mut txn = self.db.begin_write().context("starting a write")?;
        let out = {
            let mut table = txn.open_table(RELAYS)?;
            let mut row = match table.get(id)? {
                Some(g) => decode::<RelayRow>(g.value())?,
                None => return Err(NotEnrolled(id.to_string()).into()),
            };
            let (out, events) = change(&mut row)?;
            table.insert(id, encode(&row)?.as_slice())?;
            for (actor, event) in events {
                append_audit(&txn, Some(id), &actor, &event, now)?;
            }
            out
        };
        txn.set_durability(durability)
            .context("setting a write's durability")?;
        txn.commit().context("updating a relay")?;
        Ok(out)
    }
}

/// The status of `row`'s server, once it is bound to one.
fn relay_status(row: &RelayRow, instances: &[(String, GitlabRow)]) -> Option<ServerStatus> {
    let bound = row.server_url.as_deref()?;
    let reported = row.inventory.as_ref().map(|i| i.server.url.as_str());
    Some(status_of(bound, reported, instances))
}

/// A relay bound to the server at `url`, normalized, if any: its instance is not removed
/// while there is one.
pub(super) fn relay_bound_to(txn: &redb::WriteTransaction, url: &str) -> Result<Option<String>> {
    for entry in txn.open_table(RELAYS)?.iter()? {
        let (id, value) = entry?;
        if decode::<RelayRow>(value.value())?.server_url.as_deref() == Some(url) {
            return Ok(Some(id.value().to_string()));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use vk_hub_proto::gitlab::Server;

    use super::*;

    fn inventory(url: &str) -> Inventory {
        Inventory {
            version: "0.96.0".into(),
            hostname: "relay-1".into(),
            server: Server {
                url: url.into(),
                ..Server::default()
            },
            ..Inventory::default()
        }
    }

    /// Reads of a hub no relay has enrolled with yet, as `vk-hub gitlabs` and the UI make.
    #[test]
    fn a_new_hub_reads_its_relays() {
        let db = Db::open_memory().unwrap();
        assert!(db.relays().unwrap().is_empty());
        assert!(db.relays_with_status().unwrap().is_empty());
        assert!(db.pending_gitlabs().unwrap().is_empty());
    }

    fn enrolled(db: &Db, key: &str) -> String {
        let (token, _) = db
            .create_token_for(
                TokenKind::Gitlab,
                std::time::Duration::from_secs(60),
                None,
                "u",
                1,
            )
            .unwrap();
        let RelayEnrollment::Enrolled { id } =
            db.enroll_relay(&token, key, "h", "peer p", 1).unwrap()
        else {
            panic!("expected an enrollment");
        };
        id
    }

    #[test]
    fn a_relay_enrolls_with_a_gitlab_token_only() {
        let db = Db::open_memory().unwrap();
        let (node, _) = db
            .create_token(std::time::Duration::from_secs(60), "u", 1)
            .unwrap();
        assert_eq!(
            db.enroll_relay(&node, "aa", "h", "p", 1).unwrap(),
            RelayEnrollment::BadToken
        );
        let id = enrolled(&db, "aa");
        // The same key with a new token is the same relay.
        let (token, _) = db
            .create_token_for(
                TokenKind::Gitlab,
                std::time::Duration::from_secs(60),
                None,
                "u",
                1,
            )
            .unwrap();
        assert_eq!(
            db.enroll_relay(&token, "aa", "h", "p", 2).unwrap(),
            RelayEnrollment::Reenrolled { id: id.clone() }
        );
        // Spent.
        assert_eq!(
            db.enroll_relay(&token, "bb", "h", "p", 2).unwrap(),
            RelayEnrollment::BadToken
        );
        // A relay's token enrolls no node.
        let (token, _) = db
            .create_token_for(
                TokenKind::Gitlab,
                std::time::Duration::from_secs(60),
                None,
                "u",
                1,
            )
            .unwrap();
        assert_eq!(
            db.enroll(&token, "cc", "h", "p", 2).unwrap(),
            crate::store::Enrollment::BadToken
        );
        assert!(db.node(&id).unwrap().is_none());
        assert!(db.registry(&id).unwrap().is_none());
    }

    #[test]
    fn the_first_inventory_binds_a_relay_to_its_server() {
        let db = Db::open_memory().unwrap();
        let id = enrolled(&db, "aa");
        assert_eq!(db.relay_with_status(&id).unwrap().unwrap().1, None);
        db.record_relay(
            &id,
            RelayWrite::Inventory(inventory("https://GL.example/")),
            5,
        )
        .unwrap();
        let (row, status) = db.relay_with_status(&id).unwrap().unwrap();
        assert_eq!(
            (row.server_url.as_deref(), row.bound_at),
            (Some("https://gl.example"), Some(5))
        );
        assert_eq!(
            status,
            Some(ServerStatus {
                state: ServerState::Pending,
                url: "https://gl.example".into(),
                name: None,
            })
        );
        let pending = db.pending_gitlabs().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].url, "https://gl.example");
        assert_eq!(
            pending[0].relays,
            vec![(id.clone(), "relay-1".to_string(), 5)]
        );

        // Approving the server is adding an instance at its URL.
        db.add_gitlab("gl", "https://gl.example", "u", 6).unwrap();
        let status = db.relay_with_status(&id).unwrap().unwrap().1.unwrap();
        assert_eq!(
            (status.state, status.name.as_deref()),
            (ServerState::Approved, Some("gl"))
        );
        assert!(db.pending_gitlabs().unwrap().is_empty());
        assert_eq!(
            db.relays_of("https://gl.example").unwrap(),
            vec![id.clone()]
        );
        // Which cannot be removed while the relay is bound to it.
        let err = db.remove_gitlab("gl", "u", 7).unwrap_err();
        assert!(err.to_string().contains(&id), "{err:#}");

        // Another URL later does not rebind it.
        db.record_relay(
            &id,
            RelayWrite::Inventory(inventory("https://other.example")),
            8,
        )
        .unwrap();
        let (row, status) = db.relay_with_status(&id).unwrap().unwrap();
        assert_eq!(row.server_url.as_deref(), Some("https://gl.example"));
        let status = status.unwrap();
        assert_eq!((status.state, status.name), (ServerState::Rebound, None));
        assert!(db.pending_gitlabs().unwrap().is_empty());

        assert!(db.remove_relay(&id, "u", 9).unwrap());
        assert!(!db.remove_relay(&id, "u", 9).unwrap());
        assert!(db.remove_gitlab("gl", "u", 10).unwrap());
    }

    /// A pending server is shown with what a relay reports of it, not of another server.
    #[test]
    fn a_pending_server_shows_only_its_own_certificate() {
        let db = Db::open_memory().unwrap();
        let (a, b) = (enrolled(&db, "aa"), enrolled(&db, "bb"));
        let with_key = |url: &str, key: &str| {
            let mut i = inventory(url);
            i.server.spki_sha256 = Some(key.repeat(32));
            RelayWrite::Inventory(i)
        };
        db.record_relay(&a, with_key("https://a.example", "aa"), 1)
            .unwrap();
        db.record_relay(&b, with_key("https://a.example", "bb"), 2)
            .unwrap();
        // Relay a moves to another server: what it says of that one is not a's.
        db.record_relay(&a, with_key("https://b.example", "cc"), 3)
            .unwrap();
        let pending = db.pending_gitlabs().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].spki_sha256, Some("bb".repeat(32)));
        assert_eq!(pending[0].relays.len(), 2);
    }
}
