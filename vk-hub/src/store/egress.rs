//! The Egress page's *Blocked* rows ([`crate::egress::blocked`]), kept as the job history is:
//! each record written adds its job's shares and takes back those of the record it replaces,
//! and each record leaving the history takes back its own, so a row counts the jobs of the
//! history and nothing else, and a row no job shares any more goes. Triage and mutes are
//! people's, and audited: a mute takes a subject's rows out of the inbox and its count, never
//! out of the store.
//!
//! A row is *New* until acknowledged, and again once a job adds to it after that: a share that
//! is new or has more attempts moves the row's generation on, past the one acknowledged.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::ControlFlow;

use anyhow::{Context, Result};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use super::jobs::{JOBS, JobRow};
use super::{Db, append_audit, decode, encode};
use crate::egress::blocked::{Finding, Share, Subject, View, shares};

/// Key: a row's ID ([`crate::egress::blocked::row_id`]). Value: JSON [`BlockedRow`].
pub(super) const EGRESS_ROWS: TableDefinition<&str, &[u8]> = TableDefinition::new("egress_rows");
/// Key: `(row ID, when the job ended, job ID)` of each job sharing a row, so a row's jobs are a
/// range, latest last. Value: the attempts the job recorded.
pub(super) const EGRESS_JOBS: TableDefinition<(&str, u64, &str), u64> =
    TableDefinition::new("egress_jobs");
/// Key: a subject ([`Subject::param`]). Value: how many of its rows are New, kept in the
/// writes that change them, so the count of New rows reads no row.
pub(super) const EGRESS_NEW: TableDefinition<&str, u64> = TableDefinition::new("egress_new");
/// Key: a subject ([`Subject::param`]). Value: JSON [`Mute`].
pub(super) const EGRESS_MUTES: TableDefinition<&str, &[u8]> = TableDefinition::new("egress_mutes");
/// Key: `(view, state, u64::MAX - latest_at, row ID)` of each row ([`View::name`],
/// [`Stored::key`]), so a view's rows of one state are a range, the latest first and those of
/// one time by ID. Value: its subject ([`Subject::param`]).
pub(super) const EGRESS_ORDER: TableDefinition<(&str, &str, u64, &str), &str> =
    TableDefinition::new("egress_order");
/// The same by subject: key `(subject, view, state, u64::MAX - latest_at, row ID)`.
pub(super) const EGRESS_SUBJECT_ORDER: TableDefinition<(&str, &str, &str, u64, &str), ()> =
    TableDefinition::new("egress_subject_order");
/// Key: `(subject, view, state)`. Value: how many rows are so.
pub(super) const EGRESS_COUNTS: TableDefinition<(&str, &str, &str), u64> =
    TableDefinition::new("egress_counts");
/// Key: `(view, state)`. Value: how many rows are so, of every subject.
pub(super) const EGRESS_TOTALS: TableDefinition<(&str, &str), u64> =
    TableDefinition::new("egress_totals");
/// Key: a subject. Value: how many rows it has, and its words as the row last written of it
/// says them ([`BlockedRow::who`]).
pub(super) const EGRESS_SUBJECTS: TableDefinition<&str, (u64, &str)> =
    TableDefinition::new("egress_subjects");
/// Key: [`BUILT`]. Value: 1 once the rows hold every job of the history.
const EGRESS_META: TableDefinition<&str, u64> = TableDefinition::new("egress_meta");
const BUILT: &str = "built";

/// The longest reason a mute takes.
pub const MAX_MUTE_REASON: usize = vk_hub_proto::MAX_DISPLAY;

/// A destination refused, or a declaration refused, gathered over the jobs of one subject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedRow {
    pub subject: Subject,
    pub finding: Finding,
    /// The display-safe project its latest job named, as that job was added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Its latest job's key name, for display.
    pub key_name: String,
    /// The jobs sharing it.
    pub jobs: u64,
    /// Their attempts; 0 for a declaration refusal.
    pub attempts: u64,
    /// When the latest of them ended, on the hub's clock.
    pub latest_at: u64,
    /// The jobs it was decided in by each layer ([`crate::egress::blocked::layer_key`]).
    pub layers: BTreeMap<String, u64>,
    /// The jobs it was seen in in each phase ([`crate::egress::blocked::phase_key`]).
    pub phases: BTreeMap<String, u64>,
    /// Moved on by each job that adds to it.
    pub generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledged: Option<Acknowledged>,
}

/// Who acknowledged a row, when, and as far as which generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acknowledged {
    pub generation: u64,
    pub by: String,
    pub at: u64,
}

/// How a row stands as stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Stored {
    New,
    Acknowledged,
}

impl Stored {
    pub const ALL: [Stored; 2] = [Stored::New, Stored::Acknowledged];

    fn key(self) -> &'static str {
        match self {
            Stored::New => "new",
            Stored::Acknowledged => "acknowledged",
        }
    }

    pub fn of(row: &BlockedRow) -> Stored {
        if row.is_new() {
            Stored::New
        } else {
            Stored::Acknowledged
        }
    }
}

/// What the indexes hold of a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Indexed {
    view: View,
    stored: Stored,
    latest_at: u64,
}

impl Indexed {
    fn of(row: &BlockedRow) -> Indexed {
        Indexed {
            view: row.finding.view(),
            stored: Stored::of(row),
            latest_at: row.latest_at,
        }
    }
}

/// A range of the rows of one view and state, the latest first: every subject's, or one's.
#[derive(Clone, Copy, Debug)]
pub struct RowRange<'a> {
    pub view: View,
    pub stored: Stored,
    pub subject: Option<&'a str>,
}

impl BlockedRow {
    /// Neither acknowledged nor added to since.
    pub fn is_new(&self) -> bool {
        self.acknowledged
            .as_ref()
            .is_none_or(|a| a.generation < self.generation)
    }

    /// Its subject in words ([`Subject::text`]).
    pub fn who(&self) -> String {
        self.subject.text(self.project.as_deref(), &self.key_name)
    }

    fn new(share: &Share) -> Self {
        BlockedRow {
            subject: share.subject.clone(),
            finding: share.finding.clone(),
            project: None,
            key_name: String::new(),
            jobs: 0,
            attempts: 0,
            latest_at: 0,
            layers: BTreeMap::new(),
            phases: BTreeMap::new(),
            generation: 0,
            acknowledged: None,
        }
    }

    fn count(map: &mut BTreeMap<String, u64>, keys: &BTreeSet<&'static str>, add: bool) {
        for k in keys {
            let n = map.entry((*k).to_string()).or_default();
            *n = if add {
                n.saturating_add(1)
            } else {
                n.saturating_sub(1)
            };
            if *n == 0 {
                map.remove(*k);
            }
        }
    }
}

/// Rows of one subject taken out of the inbox and its count, for a while or until undone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mute {
    /// The subject in words, as when it was muted.
    pub who: String,
    pub reason: String,
    /// When it ends; `None` for never.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    pub by: String,
    pub at: u64,
}

impl Mute {
    pub fn live(&self, now: u64) -> bool {
        self.until.is_none_or(|u| now < u)
    }
}

/// The tables a change to the rows writes.
struct Tables<'t> {
    rows: redb::Table<'t, &'static str, &'static [u8]>,
    jobs: redb::Table<'t, (&'static str, u64, &'static str), u64>,
    new: redb::Table<'t, &'static str, u64>,
    index: Index<'t>,
}

/// The tables that index the rows.
struct Index<'t> {
    order: redb::Table<'t, (&'static str, &'static str, u64, &'static str), &'static str>,
    by_subject: redb::Table<'t, (&'static str, &'static str, &'static str, u64, &'static str), ()>,
    counts: redb::Table<'t, (&'static str, &'static str, &'static str), u64>,
    totals: redb::Table<'t, (&'static str, &'static str), u64>,
    subjects: redb::Table<'t, &'static str, (u64, &'static str)>,
}

/// `n` moved by one, up when `add`.
fn step(n: u64, add: bool) -> u64 {
    if add {
        n.saturating_add(1)
    } else {
        n.saturating_sub(1)
    }
}

impl<'t> Index<'t> {
    fn open(txn: &'t redb::WriteTransaction) -> Result<Self> {
        Ok(Index {
            order: txn.open_table(EGRESS_ORDER)?,
            by_subject: txn.open_table(EGRESS_SUBJECT_ORDER)?,
            counts: txn.open_table(EGRESS_COUNTS)?,
            totals: txn.open_table(EGRESS_TOTALS)?,
            subjects: txn.open_table(EGRESS_SUBJECTS)?,
        })
    }

    /// Move row `id` of `subject` from `was` to `is`, either absent, `row` what it is now.
    fn put(
        &mut self,
        id: &str,
        subject: &str,
        was: Option<Indexed>,
        is: Option<Indexed>,
        row: Option<&BlockedRow>,
    ) -> Result<()> {
        if was != is {
            for (i, add) in [(was, false), (is, true)] {
                let Some(i) = i else {
                    continue;
                };
                let (view, stored) = (i.view.name(), i.stored.key());
                let order = u64::MAX - i.latest_at;
                if add {
                    self.order.insert((view, stored, order, id), subject)?;
                    self.by_subject
                        .insert((subject, view, stored, order, id), ())?;
                } else {
                    self.order.remove((view, stored, order, id))?;
                    self.by_subject.remove((subject, view, stored, order, id))?;
                }
                let n = self
                    .counts
                    .get((subject, view, stored))?
                    .map_or(0, |g| g.value());
                match step(n, add) {
                    0 => self.counts.remove((subject, view, stored))?,
                    n => self.counts.insert((subject, view, stored), n)?,
                };
                let n = self.totals.get((view, stored))?.map_or(0, |g| g.value());
                match step(n, add) {
                    0 => self.totals.remove((view, stored))?,
                    n => self.totals.insert((view, stored), n)?,
                };
            }
        }
        let rows = self.subjects.get(subject)?.map_or(0, |g| g.value().0);
        let rows = match (was.is_some(), is.is_some()) {
            (false, true) => rows.saturating_add(1),
            (true, false) => rows.saturating_sub(1),
            _ => rows,
        };
        match row {
            Some(row) => {
                self.subjects.insert(subject, (rows, row.who().as_str()))?;
            }
            None if rows == 0 => {
                self.subjects.remove(subject)?;
            }
            None => {
                let who = self
                    .subjects
                    .get(subject)?
                    .map(|g| g.value().1.to_string())
                    .unwrap_or_default();
                self.subjects.insert(subject, (rows, who.as_str()))?;
            }
        }
        Ok(())
    }
}

impl<'t> Tables<'t> {
    fn open(txn: &'t redb::WriteTransaction) -> Result<Self> {
        Ok(Tables {
            rows: txn.open_table(EGRESS_ROWS)?,
            jobs: txn.open_table(EGRESS_JOBS)?,
            new: txn.open_table(EGRESS_NEW)?,
            index: Index::open(txn)?,
        })
    }

    fn get(&self, id: &str) -> Result<Option<BlockedRow>> {
        self.rows.get(id)?.map(|g| decode(g.value())).transpose()
    }

    /// Store `row` as `id`, or remove it when no job shares it, keeping its subject's count of
    /// New rows and the indexes given how it `was` stored, if it was.
    fn put(
        &mut self,
        id: &str,
        row: Option<&BlockedRow>,
        was: Option<Indexed>,
        subject: &Subject,
    ) -> Result<()> {
        let was_new = was.is_some_and(|w| w.stored == Stored::New);
        self.index
            .put(id, &subject.param(), was, row.map(Indexed::of), row)?;
        match row {
            Some(row) => {
                self.rows.insert(id, encode(row)?.as_slice())?;
            }
            None => {
                self.rows.remove(id)?;
            }
        }
        let is_new = row.is_some_and(BlockedRow::is_new);
        if is_new != was_new {
            let key = subject.param();
            let n = self.new.get(key.as_str())?.map_or(0, |g| g.value());
            let n = if is_new {
                n.saturating_add(1)
            } else {
                n.saturating_sub(1)
            };
            if n == 0 {
                self.new.remove(key.as_str())?;
            } else {
                self.new.insert(key.as_str(), n)?;
            }
        }
        Ok(())
    }
}

/// Replace job `id`'s shares from record `old` with those from `new`, either absent.
pub(super) fn reshare(
    txn: &redb::WriteTransaction,
    id: &str,
    old: Option<&JobRow>,
    new: Option<&JobRow>,
) -> Result<()> {
    let before = old.map(shares).unwrap_or_default();
    let after = new.map(shares).unwrap_or_default();
    if before == after {
        return Ok(());
    }
    let mut t = Tables::open(txn)?;
    let ids: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    for row_id in ids {
        let (was, is) = (before.get(row_id), after.get(row_id));
        if was == is {
            continue;
        }
        let stored = t.get(row_id)?;
        let indexed = stored.as_ref().map(Indexed::of);
        let mut row = match (stored, is) {
            (Some(row), _) => row,
            (None, Some(share)) => BlockedRow::new(share),
            // Nothing of it is kept to take back.
            (None, None) => continue,
        };
        let subject = row.subject.clone();
        if let Some(share) = was {
            t.jobs.remove((row_id.as_str(), share.at, id))?;
            row.jobs = row.jobs.saturating_sub(1);
            row.attempts = row.attempts.saturating_sub(share.attempts);
            BlockedRow::count(&mut row.layers, &share.layers, false);
            BlockedRow::count(&mut row.phases, &share.phases, false);
        }
        if let Some(share) = is {
            t.jobs
                .insert((row_id.as_str(), share.at, id), share.attempts)?;
            row.jobs = row.jobs.saturating_add(1);
            row.attempts = row.attempts.saturating_add(share.attempts);
            BlockedRow::count(&mut row.layers, &share.layers, true);
            BlockedRow::count(&mut row.phases, &share.phases, true);
            // Named as its latest job names it.
            if let Some(job) = new.filter(|_| share.at >= row.latest_at) {
                row.project = job.project.clone();
                row.key_name = job.key_name.clone();
            }
            if was.is_none_or(|w| share.attempts > w.attempts) {
                row.generation = row.generation.saturating_add(1);
            }
        }
        if row.jobs == 0 {
            t.put(row_id, None, indexed, &subject)?;
            continue;
        }
        let range = (row_id.as_str(), 0, "")..=(row_id.as_str(), u64::MAX, "~");
        if let Some(latest) = t.jobs.range(range)?.next_back() {
            row.latest_at = latest?.0.value().1;
        }
        t.put(row_id, Some(&row), indexed, &subject)?;
    }
    Ok(())
}

/// A view as the audit log names it.
fn view_text(v: View) -> &'static str {
    match v {
        View::Blocked => "blocked",
        View::WouldBlock => "would-block",
        View::Refused => "declaration issue",
    }
}

/// Fill the rows from the history once: the jobs a build without them recorded. A job's
/// record is decoded at a time.
pub(super) fn share_history(txn: &redb::WriteTransaction) -> Result<()> {
    let mut meta = txn.open_table(EGRESS_META)?;
    // Created for the reads to find, rows or not.
    drop(Tables::open(txn)?);
    txn.open_table(EGRESS_MUTES)?;
    if meta.get(BUILT)?.is_none() {
        let jobs = txn.open_table(JOBS)?;
        for entry in jobs.iter()? {
            let (id, row) = entry?;
            // A record this build cannot read shares nothing, as it shows nothing.
            let Ok(row) = decode::<JobRow>(row.value()) else {
                continue;
            };
            if row.started_at.is_none() {
                continue;
            }
            reshare(txn, id.value(), None, Some(&row))?;
        }
    }
    meta.insert(BUILT, 1)?;
    Ok(())
}

impl Db {
    /// Every row, by ID.
    #[cfg(test)]
    pub fn egress_rows(&self) -> Result<Vec<(String, BlockedRow)>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(EGRESS_ROWS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (id, row) = entry?;
            out.push((id.value().to_string(), decode(row.value())?));
        }
        Ok(out)
    }

    /// Visit the rows of `ranges`, merged the latest first and those of one time by ID, decoding
    /// at most `budget` of them (taken from it), until `visit` breaks: whether rows were left
    /// unread for the budget.
    pub fn egress_scan(
        &self,
        ranges: &[RowRange],
        budget: &mut usize,
        mut visit: impl FnMut(&str, BlockedRow) -> ControlFlow<()>,
    ) -> Result<bool> {
        type Cursor<'c> = Box<dyn Iterator<Item = Result<(u64, String)>> + 'c>;
        let txn = self.db.begin_read()?;
        let rows = txn.open_table(EGRESS_ROWS)?;
        let order = txn.open_table(EGRESS_ORDER)?;
        let by_subject = txn.open_table(EGRESS_SUBJECT_ORDER)?;
        let mut cursors: Vec<Cursor> = Vec::new();
        for r in ranges {
            let (view, stored) = (r.view.name(), r.stored.key());
            let cursor: Cursor = match r.subject {
                None => Box::new(
                    order
                        .range((view, stored, 0, "")..=(view, stored, u64::MAX, "~"))?
                        .map(|e| {
                            let (k, _) = e?;
                            let (_, _, at, id) = k.value();
                            Ok((at, id.to_string()))
                        }),
                ),
                Some(subject) => Box::new(
                    by_subject
                        .range(
                            (subject, view, stored, 0, "")..=(subject, view, stored, u64::MAX, "~"),
                        )?
                        .map(|e| {
                            let (k, _) = e?;
                            let (_, _, _, at, id) = k.value();
                            Ok((at, id.to_string()))
                        }),
                ),
            };
            cursors.push(cursor);
        }
        let mut heads = Vec::new();
        for c in &mut cursors {
            heads.push(c.next().transpose()?);
        }
        loop {
            let next = heads
                .iter()
                .enumerate()
                .filter_map(|(i, h)| Some((i, h.as_ref()?)))
                .min_by(|a, b| a.1.cmp(b.1))
                .map(|(i, _)| i);
            let (Some(head), Some(cursor)) = (
                next.and_then(|i| heads.get_mut(i)),
                next.and_then(|i| cursors.get_mut(i)),
            ) else {
                return Ok(false);
            };
            if *budget == 0 {
                return Ok(true);
            }
            *budget -= 1;
            let Some((_, id)) = std::mem::replace(head, cursor.next().transpose()?) else {
                return Ok(false);
            };
            let Some(row) = rows.get(id.as_str())? else {
                continue;
            };
            if visit(&id, decode(row.value())?).is_break() {
                return Ok(false);
            }
        }
    }

    /// How many rows there are of each view and state: every subject's, or `subject`'s.
    pub fn egress_counts(&self, subject: Option<&str>) -> Result<HashMap<(View, Stored), u64>> {
        let txn = self.db.begin_read()?;
        let mut out = HashMap::new();
        let counts = txn.open_table(EGRESS_COUNTS)?;
        let totals = txn.open_table(EGRESS_TOTALS)?;
        for view in View::ALL {
            for stored in Stored::ALL {
                let (v, s) = (view.name(), stored.key());
                let n = match subject {
                    Some(subject) => counts.get((subject, v, s))?.map(|g| g.value()),
                    None => totals.get((v, s))?.map(|g| g.value()),
                };
                out.insert((view, stored), n.unwrap_or_default());
            }
        }
        Ok(out)
    }

    /// Every subject with rows, by [`Subject::param`], in its words.
    pub fn egress_subjects(&self) -> Result<Vec<(String, String)>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(EGRESS_SUBJECTS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            out.push((k.value().to_string(), v.value().1.to_string()));
        }
        Ok(out)
    }

    pub fn egress_row(&self, id: &str) -> Result<Option<BlockedRow>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(EGRESS_ROWS)?;
        table.get(id)?.map(|g| decode(g.value())).transpose()
    }

    /// The rows of `ids` there are, in one read.
    pub fn egress_rows_of(&self, ids: &[&String]) -> Result<Vec<(String, BlockedRow)>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(EGRESS_ROWS)?;
        let mut out = Vec::new();
        for id in ids {
            if let Some(row) = table.get(id.as_str())? {
                out.push(((*id).clone(), decode(row.value())?));
            }
        }
        Ok(out)
    }

    /// The latest `limit` jobs sharing row `id`, latest first: each one's ID, when it ended and
    /// its attempts.
    pub fn egress_row_jobs(&self, id: &str, limit: usize) -> Result<Vec<(String, u64, u64)>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(EGRESS_JOBS)?;
        let mut out = Vec::new();
        for entry in table
            .range((id, 0, "")..=(id, u64::MAX, "~"))?
            .rev()
            .take(limit)
        {
            let (k, attempts) = entry?;
            let (_, at, job) = k.value();
            out.push((job.to_string(), at, attempts.value()));
        }
        Ok(out)
    }

    /// The mutes in force at `now`, by subject ([`Subject::param`]).
    pub fn egress_mutes(&self, now: u64) -> Result<HashMap<String, Mute>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(EGRESS_MUTES)?;
        let mut out = HashMap::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            let mute: Mute = decode(v.value())?;
            if mute.live(now) {
                out.insert(k.value().to_string(), mute);
            }
        }
        Ok(out)
    }

    /// How many rows are New and not muted at `now`: the Egress link's count.
    pub fn egress_new(&self, now: u64) -> Result<u64> {
        let muted = self.egress_mutes(now)?;
        let txn = self.db.begin_read()?;
        let table = txn.open_table(EGRESS_NEW)?;
        let mut n = 0u64;
        for entry in table.iter()? {
            let (subject, count) = entry?;
            if !muted.contains_key(subject.value()) {
                n = n.saturating_add(count.value());
            }
        }
        Ok(n)
    }

    /// Acknowledge row `id` as `actor`, as far as the jobs it has now, or reopen it; audited.
    /// Return the row, or `None` for no such row.
    pub fn egress_triage(
        &self,
        id: &str,
        acknowledge: bool,
        actor: &str,
        now: u64,
    ) -> Result<Option<BlockedRow>> {
        let txn = self.db.begin_write().context("starting a write")?;
        let row = {
            let mut t = Tables::open(&txn)?;
            let Some(mut row) = t.get(id)? else {
                return Ok(None);
            };
            let was = Indexed::of(&row);
            row.acknowledged = acknowledge.then(|| Acknowledged {
                generation: row.generation,
                by: actor.to_string(),
                at: now,
            });
            let subject = row.subject.clone();
            t.put(id, Some(&row), Some(was), &subject)?;
            row
        };
        let did = if acknowledge {
            "acknowledged"
        } else {
            "reopened"
        };
        let what = view_text(row.finding.view());
        let event = format!(
            "{actor} {did} egress {what} {} for {}",
            row.finding.text(),
            row.who()
        );
        append_audit(&txn, None, actor, &event, now)?;
        txn.commit().context("triaging an egress row")?;
        Ok(Some(row))
    }

    /// Mute `subject`'s rows as `actor`, for `reason`, until `until` or for good; audited. A
    /// mute of it in force is replaced, and mutes past their end are swept.
    pub fn egress_mute(
        &self,
        subject: &Subject,
        who: &str,
        reason: &str,
        until: Option<u64>,
        actor: &str,
        now: u64,
    ) -> Result<()> {
        let reason = vk_hub_proto::display_safe_up_to(reason.trim(), MAX_MUTE_REASON);
        if reason.is_empty() {
            anyhow::bail!("a mute needs a reason");
        }
        let txn = self.db.begin_write().context("starting a write")?;
        {
            let mut table = txn.open_table(EGRESS_MUTES)?;
            table.retain(|_, v| decode::<Mute>(v).is_ok_and(|m| m.live(now)))?;
            let mute = Mute {
                who: who.to_string(),
                reason: reason.clone(),
                until,
                by: actor.to_string(),
                at: now,
            };
            table.insert(subject.param().as_str(), encode(&mute)?.as_slice())?;
        }
        let until = match until {
            Some(t) => format!("until {}", crate::utc(t)),
            None => "until unmuted".to_string(),
        };
        let event = format!("{actor} muted egress of {who} {until}: {reason}");
        append_audit(&txn, None, actor, &event, now)?;
        txn.commit().context("muting egress rows")?;
        Ok(())
    }

    /// End `subject`'s mute as `actor`; audited. Return whether one was in force.
    pub fn egress_unmute(&self, subject: &Subject, actor: &str, now: u64) -> Result<bool> {
        let txn = self.db.begin_write().context("starting a write")?;
        let removed = {
            let mut table = txn.open_table(EGRESS_MUTES)?;
            let removed = table
                .remove(subject.param().as_str())?
                .map(|g| decode::<Mute>(g.value()))
                .transpose()?;
            removed.filter(|m| m.live(now))
        };
        let Some(mute) = removed else {
            return Ok(false);
        };
        let event = format!("{actor} unmuted egress of {}", mute.who);
        append_audit(&txn, None, actor, &event, now)?;
        txn.commit().context("unmuting egress rows")?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use vk_hub_proto::egress::{
        EgressDestination, EgressEntry, EgressLayer, EgressOutcome, EgressProtocol, EgressReport,
    };

    use super::*;
    use crate::egress::testing::{entry, job};

    fn denied(count: u64) -> EgressReport {
        EgressReport {
            entries: vec![EgressEntry {
                count,
                ..entry(
                    EgressOutcome::Blocked,
                    EgressProtocol::Tcp,
                    EgressDestination::address("10.0.0.1:443"),
                    Some(EgressLayer::NodeCap),
                )
            }],
            ..EgressReport::default()
        }
    }

    /// Job `n`, submitted then ended with `report`.
    fn ended(db: &Db, n: u64, report: EgressReport) -> (String, JobRow) {
        let id = format!("{n:032x}");
        let row = job(n, report);
        let mut queued = row.clone();
        queued.result = None;
        queued.revision = 1;
        db.submit_job(&id, &queued, &id, b"{}", "key gitlab", 10)
            .unwrap();
        assert!(db.put_job(&id, &row, &[], 11).unwrap());
        (id, row)
    }

    fn only_row(db: &Db) -> (String, BlockedRow) {
        let mut rows = db.egress_rows().unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
        rows.remove(0)
    }

    /// A row counts the jobs of the history that share it: written again, a job's record adds
    /// nothing; another job adds to it and moves it on; a job leaving the history takes its
    /// share back, and the last one the row.
    #[test]
    fn a_row_counts_the_history_s_jobs_once_each() {
        let db = Db::open_memory().unwrap();
        let (a, mut row_a) = ended(&db, 1, denied(2));
        let (id, row) = only_row(&db);
        assert_eq!((row.jobs, row.attempts, row.generation), (1, 2, 1));
        assert_eq!(row.layers, BTreeMap::from([("node_cap".to_string(), 1)]));
        assert_eq!(
            (row.latest_at, row.project.as_deref()),
            (1_001, Some("acme/web"))
        );
        assert_eq!(db.egress_new(0).unwrap(), 1);

        // The same report again, as a settle or a replayed result writes it.
        row_a.revision += 1;
        row_a.settled_at = Some(12);
        assert!(db.put_job(&a, &row_a, &[], 12).unwrap());
        assert_eq!(only_row(&db).1, row);

        let (b, _) = ended(&db, 2, denied(5));
        let (_, row) = only_row(&db);
        assert_eq!((row.jobs, row.attempts, row.generation), (2, 7, 2));
        assert_eq!(row.latest_at, 1_002);
        assert_eq!(
            db.egress_row_jobs(&id, 10).unwrap(),
            [(b.clone(), 1_002, 5), (a.clone(), 1_001, 2)]
        );
        assert_eq!(db.egress_new(0).unwrap(), 1);

        // A settled job leaves the history first.
        db.prune_jobs(20, 1).unwrap();
        let (_, row) = only_row(&db);
        assert_eq!((row.jobs, row.attempts), (1, 5));
        assert_eq!(
            db.egress_row_jobs(&id, 10).unwrap(),
            [(b.clone(), 1_002, 5)]
        );
        let mut row_b = db.job(&b).unwrap().unwrap();
        row_b.revision += 1;
        row_b.settled_at = Some(13);
        db.put_job(&b, &row_b, &[], 13).unwrap();
        db.prune_jobs(20, 0).unwrap();
        assert!(db.egress_rows().unwrap().is_empty());
        assert_eq!(db.egress_new(0).unwrap(), 0);
        assert!(db.egress_row_jobs(&id, 10).unwrap().is_empty());
    }

    /// Job `n` of key `k<n % 3>`, ended refused `10.0.0.<n % 7>:443`.
    fn varied(db: &Db, n: u64) -> String {
        let id = format!("{n:032x}");
        let mut report = denied(1);
        if let Some(e) = report.entries.first_mut() {
            e.destination = EgressDestination::address(&format!("10.0.0.{}:443", n % 7));
        }
        let mut row = job(n, report);
        row.key = format!("k{}", n % 3);
        let mut queued = row.clone();
        queued.result = None;
        queued.revision = 1;
        db.submit_job(&id, &queued, &id, b"{}", "key gitlab", 10)
            .unwrap();
        assert!(db.put_job(&id, &row, &[], 11).unwrap());
        id
    }

    /// The indexes say of the rows what the rows say: each view's and state's rows, every
    /// subject's and each one's, the latest first, their counts, and the subjects.
    fn check_index(db: &Db) {
        let rows = db.egress_rows().unwrap();
        let subjects: BTreeSet<String> = rows.iter().map(|(_, r)| r.subject.param()).collect();
        let listed: BTreeSet<String> = (db.egress_subjects().unwrap().into_iter())
            .map(|(s, _)| s)
            .collect();
        assert_eq!(listed, subjects);
        let scan = |range: RowRange| {
            let mut got = Vec::new();
            let mut budget = usize::MAX;
            let cut = db
                .egress_scan(&[range], &mut budget, |id, _| {
                    got.push(id.to_string());
                    ControlFlow::Continue(())
                })
                .unwrap();
            assert!(!cut);
            got
        };
        let totals = db.egress_counts(None).unwrap();
        for view in View::ALL {
            for stored in Stored::ALL {
                let of = |subject: Option<&str>| {
                    let mut want: Vec<&(String, BlockedRow)> = (rows.iter())
                        .filter(|(_, r)| r.finding.view() == view && Stored::of(r) == stored)
                        .filter(|(_, r)| subject.is_none_or(|s| r.subject.param() == s))
                        .collect();
                    want.sort_by(|a, b| b.1.latest_at.cmp(&a.1.latest_at).then(a.0.cmp(&b.0)));
                    want.into_iter()
                        .map(|(id, _)| id.clone())
                        .collect::<Vec<_>>()
                };
                let all = of(None);
                assert_eq!(
                    scan(RowRange {
                        view,
                        stored,
                        subject: None
                    }),
                    all
                );
                assert_eq!(totals[&(view, stored)], all.len() as u64);
                for subject in &subjects {
                    let one = of(Some(subject));
                    let range = RowRange {
                        view,
                        stored,
                        subject: Some(subject),
                    };
                    assert_eq!(scan(range), one);
                    let counts = db.egress_counts(Some(subject)).unwrap();
                    assert_eq!(counts[&(view, stored)], one.len() as u64);
                }
            }
        }
    }

    /// The indexes follow the rows as jobs add to them, are triaged, and leave the history;
    /// a scan merges its ranges the latest first and reads no more than its budget.
    #[test]
    fn the_rows_are_indexed_by_view_state_subject_and_time() {
        let db = Db::open_memory().unwrap();
        for n in 1..=30 {
            varied(&db, n);
        }
        check_index(&db);
        let rows = db.egress_rows().unwrap();
        for (i, (id, _)) in rows.iter().enumerate() {
            if i % 2 == 0 {
                db.egress_triage(id, true, "ops", 20).unwrap();
            }
        }
        check_index(&db);
        // Added to again, an acknowledged row is New again and moves on in time.
        for n in 31..=40 {
            varied(&db, n);
        }
        check_index(&db);
        db.prune_jobs(50, 12).unwrap();
        check_index(&db);

        // New and Acknowledged rows merged: the latest first, whichever range holds it.
        let ranges = [Stored::New, Stored::Acknowledged].map(|stored| RowRange {
            view: View::Blocked,
            stored,
            subject: None,
        });
        let mut all = Vec::new();
        let mut budget = usize::MAX;
        db.egress_scan(&ranges, &mut budget, |id, r| {
            all.push((r.latest_at, id.to_string()));
            ControlFlow::Continue(())
        })
        .unwrap();
        assert!(all.windows(2).all(|w| w[0].0 >= w[1].0), "{all:?}");
        assert_eq!(all.len(), db.egress_rows().unwrap().len());
        // Within a budget: no more rows read, and the scan says it was cut.
        let mut budget = 3;
        let mut read = Vec::new();
        let cut = db
            .egress_scan(&ranges, &mut budget, |id, r| {
                read.push((r.latest_at, id.to_string()));
                ControlFlow::Continue(())
            })
            .unwrap();
        assert!(cut);
        assert_eq!((budget, read.as_slice()), (0, &all[..3]));
    }

    /// Rows built from a history recorded without them are those kept as it was recorded.
    #[test]
    fn the_rows_are_built_once_from_the_history() {
        let db = Db::open_memory().unwrap();
        ended(&db, 1, denied(2));
        ended(&db, 2, denied(3));
        let kept = db.egress_rows().unwrap();
        let txn = db.db.begin_write().unwrap();
        txn.delete_table(EGRESS_ROWS).unwrap();
        txn.delete_table(EGRESS_JOBS).unwrap();
        txn.delete_table(EGRESS_NEW).unwrap();
        txn.delete_table(EGRESS_ORDER).unwrap();
        txn.delete_table(EGRESS_SUBJECT_ORDER).unwrap();
        txn.delete_table(EGRESS_COUNTS).unwrap();
        txn.delete_table(EGRESS_TOTALS).unwrap();
        txn.delete_table(EGRESS_SUBJECTS).unwrap();
        txn.delete_table(EGRESS_META).unwrap();
        share_history(&txn).unwrap();
        txn.commit().unwrap();
        assert_eq!(db.egress_rows().unwrap(), kept);
        assert_eq!(db.egress_new(0).unwrap(), 1);
        check_index(&db);
        // Once: a second pass finds them built.
        let txn = db.db.begin_write().unwrap();
        share_history(&txn).unwrap();
        txn.commit().unwrap();
        assert_eq!(db.egress_rows().unwrap(), kept);
    }

    /// An acknowledged row is New again once a job adds to it, in the same second as much as
    /// later; a job written again does not reopen it. A mute takes its subject's rows out of the
    /// count until it ends, with no write to end it, or is undone.
    #[test]
    fn triage_and_mutes_hold_until_a_job_adds_or_they_end() {
        let db = Db::open_memory().unwrap();
        let (a, mut row_a) = ended(&db, 1, denied(2));
        let (id, row) = only_row(&db);
        let acked = db
            .egress_triage(&id, true, "uid 0", 1_002)
            .unwrap()
            .unwrap();
        assert!(!acked.is_new());
        assert_eq!(db.egress_new(0).unwrap(), 0);
        row_a.revision += 1;
        db.put_job(&a, &row_a, &[], 12).unwrap();
        assert!(!only_row(&db).1.is_new());
        // Another job, ending the second it was acknowledged.
        ended(&db, 2, denied(1));
        assert!(only_row(&db).1.is_new());
        assert_eq!(db.egress_new(0).unwrap(), 1);
        db.egress_triage(&id, true, "uid 0", 1_002).unwrap();
        db.egress_triage(&id, false, "uid 0", 1_003).unwrap();
        assert_eq!(db.egress_new(0).unwrap(), 1);
        assert!(
            db.egress_triage(&"0".repeat(32), true, "uid 0", 1)
                .unwrap()
                .is_none()
        );

        let who = row.who();
        assert!(
            db.egress_mute(&row.subject, &who, " \n", None, "uid 0", 10)
                .is_err()
        );
        db.egress_mute(&row.subject, &who, "known", Some(100), "uid 0", 10)
            .unwrap();
        assert_eq!(db.egress_new(99).unwrap(), 0);
        assert_eq!(
            db.egress_mutes(99).unwrap()[&row.subject.param()].reason,
            "known"
        );
        assert_eq!(db.egress_new(100).unwrap(), 1);
        assert!(!db.egress_unmute(&row.subject, "uid 0", 100).unwrap());
        db.egress_mute(&row.subject, &who, "known", None, "uid 0", 10)
            .unwrap();
        assert!(db.egress_unmute(&row.subject, "uid 0", 11).unwrap());
        assert_eq!(db.egress_new(11).unwrap(), 1);
        let audit: Vec<String> = db
            .audits(None, 10)
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .filter(|e| e.contains("egress"))
            .collect();
        assert!(
            audit.contains(&format!(
                "uid 0 acknowledged egress blocked TCP 10.0.0.1:443 for {who}"
            )),
            "{audit:?}"
        );
        assert!(audit.contains(&format!("uid 0 muted egress of {who} until unmuted: known")));
        assert!(audit.contains(&format!("uid 0 unmuted egress of {who}")));
        assert_eq!(audit.len(), 6, "{audit:?}");
    }
}
