//! Reading the audit log back filtered: by node or registry, by whom ([`who`]), by category
//! ([`AuditKind`]) and by text, a bounded number of lines at a time.
//!
//! A line stores only its time, node, actor and text, so its category is read from them: from
//! its actor, and from the fixed wording of what the hub writes about jobs. Lines written
//! before the categories existed are sorted the same way.

use anyhow::Result;
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};

use super::jobs::contains_folded;
use super::{AUDIT, AUDIT_BY_NODE, AuditRow, Db, decode};

/// Key: `(who, sequence number)` of every audit row, by [`who`] of its actor, so the lines of
/// one person or actor are a range.
pub(super) const AUDIT_BY_WHO: TableDefinition<(&str, u64), ()> =
    TableDefinition::new("audit_by_who");

/// The most lines one [`Db::audit_search`] examines: a filter matching little of a busy log
/// is read on in steps, not whole on every page.
pub const AUDIT_SCAN: usize = 20_000;

/// The most actors [`Db::audit_actors`] lists, those who acted last.
pub const AUDIT_ACTORS: usize = 200;

/// What an audit line is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditKind {
    /// What a person did: on the admin socket, in the web UI, or a refused sign-in.
    People,
    /// What the hub, its nodes, registries and rollouts did and reported.
    System,
    /// Jobs and their reservations: what API keys submitted and canceled, and what the hub
    /// did with them.
    Jobs,
}

/// Which [`AuditKind`]s a page shows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum AuditCategory {
    /// Everything but jobs.
    #[default]
    NotJobs,
    People,
    System,
    Jobs,
    All,
}

impl AuditCategory {
    /// Every choice, in the filter's order.
    pub const ALL: [AuditCategory; 5] = [
        AuditCategory::NotJobs,
        AuditCategory::People,
        AuditCategory::System,
        AuditCategory::Jobs,
        AuditCategory::All,
    ];

    /// The query's value; empty for the default.
    pub fn name(self) -> &'static str {
        match self {
            AuditCategory::NotJobs => "",
            AuditCategory::People => "people",
            AuditCategory::System => "system",
            AuditCategory::Jobs => "jobs",
            AuditCategory::All => "all",
        }
    }

    /// The label shown in the filter.
    pub fn label(self) -> &'static str {
        match self {
            AuditCategory::NotJobs => "Everything but jobs",
            AuditCategory::People => "People's actions",
            AuditCategory::System => "Hub, nodes and registries",
            AuditCategory::Jobs => "Jobs",
            AuditCategory::All => "Everything",
        }
    }

    pub fn parse(s: &str) -> Option<AuditCategory> {
        AuditCategory::ALL.into_iter().find(|c| c.name() == s)
    }

    fn admits(self, kind: AuditKind) -> bool {
        match self {
            AuditCategory::NotJobs => kind != AuditKind::Jobs,
            AuditCategory::People => kind == AuditKind::People,
            AuditCategory::System => kind == AuditKind::System,
            AuditCategory::Jobs => kind == AuditKind::Jobs,
            AuditCategory::All => true,
        }
    }
}

/// Audit lines matching every set field.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct AuditFilter {
    /// The node or registry it is about.
    pub node: Option<String>,
    /// [`who`] of its actor, exactly.
    pub who: Option<String>,
    pub category: AuditCategory,
    /// Part of its actor or text, ignoring ASCII case.
    pub text: Option<String>,
}

impl AuditFilter {
    pub fn matches(&self, row: &AuditRow) -> bool {
        self.node
            .as_ref()
            .is_none_or(|n| row.node.as_ref() == Some(n))
            && self.who.as_ref().is_none_or(|w| who(&row.actor) == w)
            && self.category.admits(kind(&row.actor, &row.event))
            && self
                .text
                .as_ref()
                .is_none_or(|t| contains_folded(&row.event, t) || contains_folded(&row.actor, t))
    }
}

/// A page of the audit log, newest first.
#[derive(Debug, Default)]
pub struct AuditFound {
    /// The lines matched, with their sequence numbers.
    pub rows: Vec<(u64, AuditRow)>,
    /// The next page's exclusive cursor, when there may be older lines to match.
    pub older: Option<u64>,
    /// The search stopped short of older lines, [`AUDIT_SCAN`] of them examined.
    pub cut: bool,
}

/// Whom the audit log's filter puts `actor`'s lines under: the identity of a web UI session
/// opened through OIDC, so a person's sessions and refused sign-ins are theirs; `rollout` and
/// `peer` for every rollout and enrollment; the actor itself otherwise — `uid <n>`, a session
/// opened from a sign-in link, `key <name>`, `hub`.
pub fn who(actor: &str) -> &str {
    if let Some(session) = actor.strip_prefix("ui session ")
        && let Some((_, inside)) = session.split_once(" (")
        && let Some((_, identity)) = inside.strip_suffix(')').and_then(|i| i.split_once(", "))
        && !identity.is_empty()
    {
        return identity;
    }
    match actor.split_once(' ') {
        Some((group @ ("rollout" | "peer"), _)) => group,
        _ => actor,
    }
}

/// What the line `event`, done by `actor`, is about. An actor that is not one of the hub's own
/// is a person's.
pub fn kind(actor: &str, event: &str) -> AuditKind {
    if actor.starts_with("key ") || (actor == "hub" && about_a_job(event)) {
        return AuditKind::Jobs;
    }
    let system = matches!(actor, "hub" | "node" | "registry" | "vk-hub local")
        || actor.starts_with("rollout ")
        || actor.starts_with("peer ");
    if system {
        AuditKind::System
    } else {
        AuditKind::People
    }
}

/// Whether `event`, the hub's own, is one it writes about a job or a reservation: one ended,
/// refused, its reservation ended, or a registry token issued for it.
fn about_a_job(event: &str) -> bool {
    if event.starts_with("job ") || event.starts_with("reservation ") {
        return true;
    }
    if let Some(rest) = event.strip_prefix("node ")
        && let Some((_, rest)) = rest.split_once(' ')
        && rest.starts_with("refused job ")
    {
        return true;
    }
    if let Some((count, rest)) = event.split_once(' ')
        && !count.is_empty()
        && count.bytes().all(|b| b.is_ascii_digit())
        && rest.starts_with("reservation(s) on node ")
    {
        return true;
    }
    event.starts_with("issued registry token ") && event.contains(" for job ")
}

impl Db {
    /// Up to `limit` lines `filter` matches, newest first, older than sequence number
    /// `before` if given. Reads one node's lines, or one person's, by their index; stops
    /// after [`AUDIT_SCAN`] lines examined.
    pub fn audit_search(
        &self,
        filter: &AuditFilter,
        before: Option<u64>,
        limit: usize,
    ) -> Result<AuditFound> {
        self.audit_search_scanning(filter, before, limit, AUDIT_SCAN)
    }

    fn audit_search_scanning(
        &self,
        filter: &AuditFilter,
        before: Option<u64>,
        limit: usize,
        scan: usize,
    ) -> Result<AuditFound> {
        let before = before.unwrap_or(u64::MAX);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(AUDIT)?;
        let mut found = AuditFound::default();
        let (mut examined, mut last) = (0usize, None);
        // Whether to stop at the line at `seq`, short of it: the page is full or the budget
        // spent, and older lines remain.
        let mut take = |found: &mut AuditFound, seq: u64, row: &[u8]| -> Result<bool> {
            if examined >= scan {
                found.older = last;
                found.cut = true;
                return Ok(true);
            }
            let row: AuditRow = decode(row)?;
            if filter.matches(&row) {
                if found.rows.len() == limit {
                    found.older = found.rows.last().map(|r| r.0);
                    return Ok(true);
                }
                found.rows.push((seq, row));
            }
            examined = examined.saturating_add(1);
            last = Some(seq);
            Ok(false)
        };
        if let Some(who) = filter.who.as_deref() {
            let index = txn.open_table(AUDIT_BY_WHO)?;
            for entry in index.range((who, 0)..(who, before))?.rev() {
                let seq = entry?.0.value().1;
                if let Some(row) = table.get(seq)?
                    && take(&mut found, seq, row.value())?
                {
                    break;
                }
            }
        } else if let Some(node) = filter.node.as_deref() {
            let index = txn.open_table(AUDIT_BY_NODE)?;
            for entry in index.range((node, 0)..(node, before))?.rev() {
                let seq = entry?.0.value().1;
                if let Some(row) = table.get(seq)?
                    && take(&mut found, seq, row.value())?
                {
                    break;
                }
            }
        } else {
            for entry in table.range(..before)?.rev() {
                let (seq, row) = entry?;
                if take(&mut found, seq.value(), row.value())? {
                    break;
                }
            }
        }
        Ok(found)
    }

    /// Each [`who`] in the log, those who acted last first, at most [`AUDIT_ACTORS`].
    pub fn audit_actors(&self) -> Result<Vec<String>> {
        let txn = self.db.begin_read()?;
        let index = txn.open_table(AUDIT_BY_WHO)?;
        let mut last: Vec<(u64, String)> = Vec::new();
        let mut next = index.first()?.map(|(k, _)| k.value().0.to_string());
        while let Some(who) = next {
            let newest = index
                .range((who.as_str(), 0)..=(who.as_str(), u64::MAX))?
                .next_back()
                .transpose()?
                .map_or(0, |(k, _)| k.value().1);
            next = index
                .range((who.as_str(), u64::MAX)..)?
                .map(|e| e.map(|(k, _)| k.value().0.to_string()))
                .find(|w| !matches!(w, Ok(w) if *w == who))
                .transpose()?;
            last.push((newest, who));
        }
        last.sort_by_key(|a| std::cmp::Reverse(a.0));
        last.truncate(AUDIT_ACTORS);
        Ok(last.into_iter().map(|(_, who)| who).collect())
    }
}

/// Index the log by [`who`] if it is not yet: a log written before the index.
pub(super) fn index_audit_by_who(txn: &redb::WriteTransaction) -> Result<()> {
    /// A line's actor alone: the rest is skipped, not decoded.
    #[derive(serde::Deserialize)]
    struct Actor {
        actor: String,
    }
    let mut index = txn.open_table(AUDIT_BY_WHO)?;
    let table = txn.open_table(AUDIT)?;
    if !index.is_empty()? || table.is_empty()? {
        return Ok(());
    }
    for entry in table.iter()? {
        let (seq, row) = entry?;
        let Ok(row) = decode::<Actor>(row.value()) else {
            continue;
        };
        index.insert((who(&row.actor), seq.value()), ())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::append_audit;

    #[test]
    fn a_session_s_lines_are_its_person_s_and_rollouts_and_peers_are_grouped() {
        assert_eq!(
            who("ui session 1a2b (admin, ann@example.com)"),
            "ann@example.com"
        );
        assert_eq!(who("ann@example.com"), "ann@example.com");
        assert_eq!(
            who("ui session 1a2b (operator)"),
            "ui session 1a2b (operator)"
        );
        assert_eq!(who("uid 1000"), "uid 1000");
        assert_eq!(who("key gitlab"), "key gitlab");
        assert_eq!(who("rollout 1a2b"), "rollout");
        assert_eq!(who("peer 10.0.0.1:4000"), "peer");
        assert_eq!(who("hub"), "hub");
    }

    #[test]
    fn job_lines_are_told_from_the_rest() {
        let (job, node) = ("ab".repeat(16), "cd".repeat(16));
        for (actor, event) in [
            (
                "key gitlab",
                format!("key gitlab submitted job {job}: build"),
            ),
            (
                "key gitlab",
                format!("key gitlab canceled job {job} immediately"),
            ),
            (
                "hub",
                format!("job {job} ended: lost: node {node} no longer holds it"),
            ),
            ("hub", format!("node {node} refused job {job}: busy")),
            ("hub", format!("reservation {job} on node {node} lapsed")),
            (
                "hub",
                format!("2 reservation(s) on node {node} ended with its session"),
            ),
            (
                "hub",
                format!("issued registry token t1 for job {job} on node {node}: ci=rw"),
            ),
        ] {
            assert_eq!(kind(actor, &event), AuditKind::Jobs, "{event}");
        }
        for (actor, event, want) in [
            ("hub", "rotated the token-signing key", AuditKind::System),
            ("hub", "node x refused to drain", AuditKind::System),
            ("node", "state draining", AuditKind::System),
            (
                "rollout 1a2b",
                "rollout 1a2b updated node x",
                AuditKind::System,
            ),
            ("peer 10.0.0.1:4000", "enrolled", AuditKind::System),
            ("uid 0", "uid 0 canceled job x", AuditKind::People),
            (
                "uid 0",
                "uid 0 minted registry token t for registry r",
                AuditKind::People,
            ),
            ("ui session 1a2b (admin)", "signed in", AuditKind::People),
            ("ann@example.com", "refused sign-in", AuditKind::People),
        ] {
            assert_eq!(kind(actor, event), want, "{event}");
        }
    }

    fn log(db: &Db, lines: &[(Option<&str>, &str, &str)]) {
        let txn = db.db.begin_write().unwrap();
        for (i, (node, actor, event)) in (0u64..).zip(lines) {
            append_audit(&txn, *node, actor, event, i).unwrap();
        }
        txn.commit().unwrap();
    }

    fn events(found: &AuditFound) -> Vec<(u64, &str)> {
        found
            .rows
            .iter()
            .map(|(s, r)| (*s, r.event.as_str()))
            .collect()
    }

    /// By default jobs are left out; a person's lines are found across their sessions, by
    /// node, by text, and page back from the last line matched.
    #[test]
    fn the_audit_log_is_searched_by_category_person_node_and_text() {
        let db = Db::open_memory().unwrap();
        let ann = "ui session 1 (admin, ann@example.com)";
        let ann2 = "ui session 2 (operator, ann@example.com)";
        log(
            &db,
            &[
                (None, "uid 0", "uid 0 created API key gitlab"),
                (None, "key gitlab", "key gitlab submitted job j1: build"),
                (Some("n"), ann, "drained node n"),
                (Some("n"), "hub", "job j1 ended: lost"),
                (Some("n"), "node", "state draining"),
                (None, ann2, "granted bob@example.com operator"),
            ],
        );
        let search =
            |filter: &AuditFilter, before, limit| db.audit_search(filter, before, limit).unwrap();
        let default = search(&AuditFilter::default(), None, 10);
        assert_eq!(
            events(&default),
            [
                (5, "granted bob@example.com operator"),
                (4, "state draining"),
                (2, "drained node n"),
                (0, "uid 0 created API key gitlab"),
            ]
        );
        assert_eq!(default.older, None);
        let jobs = AuditFilter {
            category: AuditCategory::Jobs,
            ..AuditFilter::default()
        };
        assert_eq!(
            events(&search(&jobs, None, 10)),
            [
                (3, "job j1 ended: lost"),
                (1, "key gitlab submitted job j1: build")
            ]
        );
        let ann_only = AuditFilter {
            who: Some("ann@example.com".into()),
            ..AuditFilter::default()
        };
        let first = search(&ann_only, None, 1);
        assert_eq!(events(&first), [(5, "granted bob@example.com operator")]);
        assert_eq!(first.older, Some(5));
        let next = search(&ann_only, first.older, 1);
        assert_eq!(events(&next), [(2, "drained node n")]);
        assert_eq!(next.older, None);
        let node = AuditFilter {
            node: Some("n".into()),
            category: AuditCategory::All,
            ..AuditFilter::default()
        };
        assert_eq!(search(&node, None, 10).rows.len(), 3);
        let text = AuditFilter {
            text: Some("API KEY".into()),
            ..AuditFilter::default()
        };
        assert_eq!(
            events(&search(&text, None, 10)),
            [(0, "uid 0 created API key gitlab")]
        );
        assert_eq!(
            db.audit_actors().unwrap(),
            ["ann@example.com", "node", "hub", "key gitlab", "uid 0"]
        );
    }

    /// A search reads at most its budget of lines, and goes on from the last one read.
    #[test]
    fn a_search_stops_at_its_budget_and_goes_on_from_there() {
        let db = Db::open_memory().unwrap();
        log(
            &db,
            &[
                (None, "uid 0", "removed node a"),
                (None, "hub", "job j1 ended: lost"),
                (None, "hub", "job j2 ended: lost"),
                (None, "hub", "job j3 ended: lost"),
            ],
        );
        let filter = AuditFilter::default();
        let cut = db.audit_search_scanning(&filter, None, 10, 2).unwrap();
        assert!(cut.rows.is_empty());
        assert!(cut.cut);
        assert_eq!(cut.older, Some(2));
        let rest = db.audit_search_scanning(&filter, cut.older, 10, 2).unwrap();
        assert_eq!(events(&rest), [(0, "removed node a")]);
        assert!(!rest.cut);
        assert_eq!(rest.older, None);
    }

    /// A log written before the index is indexed as the database opens.
    #[test]
    fn an_unindexed_log_is_indexed_by_who() {
        let db = Db::open_memory().unwrap();
        log(
            &db,
            &[(None, "ui session 1 (admin, ann@example.com)", "signed in")],
        );
        let txn = db.db.begin_write().unwrap();
        txn.delete_table(AUDIT_BY_WHO).unwrap();
        index_audit_by_who(&txn).unwrap();
        txn.commit().unwrap();
        assert_eq!(db.audit_actors().unwrap(), ["ann@example.com"]);
    }
}
