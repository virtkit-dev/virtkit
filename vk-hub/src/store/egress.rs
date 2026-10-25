//! The Egress page's *Blocked* rows ([`crate::egress::blocked`]), kept as the job history is:
//! each record written adds its job's shares and takes back those of the record it replaces,
//! and each record leaving the history takes back its own, so a row counts the jobs of the
//! history and nothing else, and a row no job shares any more goes. Triage and mutes are
//! people's, and audited: a mute takes a subject's rows out of the inbox and its count, never
//! out of the store.
//!
//! A row is *New* until acknowledged, and again once a job adds to it after that: a share that
//! is new or has more attempts moves the row's generation on, past the one acknowledged.
//!
//! An allow saved from the row's proposal ([`crate::egress::proposal`]) takes it out of New too,
//! one per phase, keyed to the rules' generation it was saved at: *Allow saved, awaiting
//! confirmation*, until a later job of its subject placed under that generation or a later one,
//! with the rule saved applying to it, reaches the destination in that phase without being
//! refused it, and reports the phase completely. A row whose every phase is so confirmed is
//! *Allowed by current policy*. A job placed under an earlier generation than the allow of each
//! phase it adds to the row in leaves the row standing; any other, one with no generation
//! recorded included, reopens it.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::ControlFlow;

use anyhow::{Context, Result};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use vk_hub_proto::egress::{EgressCoverage, EgressOutcome, EgressPhase};

use super::jobs::{JOBS, JobRow};
use super::{Db, append_audit, decode, encode};
use crate::egress::blocked::{Finding, Share, Subject, View, shares};
use crate::egress::matching::Dest;
use crate::subject::JobClaims;

/// Key: a row's ID ([`crate::egress::blocked::row_id`]). Value: JSON [`BlockedRow`].
pub(super) const EGRESS_ROWS: TableDefinition<&str, &[u8]> = TableDefinition::new("egress_rows");
/// Key: `(row ID, when the job ended, job ID)` of each job sharing a row, so a row's jobs are a
/// range, latest last. Value: the attempts the job recorded.
pub(super) const EGRESS_JOBS: TableDefinition<(&str, u64, &str), u64> =
    TableDefinition::new("egress_jobs");
/// Key: a subject ([`Subject::param`]). Value: how many of its rows are New, kept in the
/// writes that change them, so the count of New rows reads no row.
pub(super) const EGRESS_NEW: TableDefinition<&str, u64> = TableDefinition::new("egress_new");
/// Key: `(subject, row ID)` of each row whose allow awaits confirmation ([`AllowSaved`]), so
/// that a job's subject finds its own. Value: the rules' generation it was saved at.
pub(super) const EGRESS_ALLOWS: TableDefinition<(&str, &str), u64> =
    TableDefinition::new("egress_allows");
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
/// Key: [`BUILT`], [`OBSERVED_BUILT`]. Value: 1 once the rows, and Observed traffic, hold every
/// job of the history.
const EGRESS_META: TableDefinition<&str, u64> = TableDefinition::new("egress_meta");
const BUILT: &str = "built";
const OBSERVED_BUILT: &str = "observed";

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
    /// The allows saved from its proposals, a phase's latest each, until a job reopens it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allows: Vec<AllowSaved>,
}

/// An allow saved for one phase of a row: the rule changed, and against which generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowSaved {
    /// The rules' generation the save left them at.
    pub generation: u64,
    pub phase: EgressPhase,
    pub rule: String,
    /// The claims the rules were checked against: the row's latest job's; `None` for a job of no
    /// GitLab instance (an older hub's, of a key bound to none).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<JobClaims>,
    pub by: String,
    pub at: u64,
    /// The job that confirmed it, once one has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed: Option<Confirmed>,
}

/// The later job that reached a row's destination without being refused it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confirmed {
    pub job: String,
    pub at: u64,
}

/// What an allow is saved for: a row, the phase and rule its proposal changed, and the claims
/// the rules are checked against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowRequest {
    pub row: String,
    pub phase: EgressPhase,
    pub rule: String,
    pub claims: Option<JobClaims>,
}

/// Who acknowledged a row, when, and as far as which generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acknowledged {
    pub generation: u64,
    pub by: String,
    pub at: u64,
}

/// How a row stands as stored: its triage but for whether the rules saved now allow what was
/// saved for it, which only they say.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Stored {
    New,
    Acknowledged,
    /// Not New, with allows saved.
    Allows,
}

impl Stored {
    pub const ALL: [Stored; 3] = [Stored::New, Stored::Acknowledged, Stored::Allows];

    fn key(self) -> &'static str {
        match self {
            Stored::New => "new",
            Stored::Acknowledged => "acknowledged",
            Stored::Allows => "allows",
        }
    }

    pub fn of(row: &BlockedRow) -> Stored {
        if row.is_new() {
            Stored::New
        } else if row.allows.is_empty() {
            Stored::Acknowledged
        } else {
            Stored::Allows
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

    /// Its subject as pages name it ([`Subject::label`]), the instance `sole` left out.
    pub fn label(&self, sole: Option<&str>) -> String {
        self.subject
            .label(self.project.as_deref(), &self.key_name, sole)
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
            allows: Vec::new(),
        }
    }

    /// Whether the rules `rules` allow its destination to the claims each of its allows was
    /// saved for, in its phase: `false` without one.
    pub fn allowed_by(&self, rules: &[crate::store::EgressRuleRow]) -> bool {
        !self.allows.is_empty() && self.allows.iter().all(|a| self.allows_now(a, rules))
    }

    /// Whether the rules `rules` allow its destination as allow `a` was saved for.
    pub fn allows_now(&self, a: &AllowSaved, rules: &[crate::store::EgressRuleRow]) -> bool {
        let Finding::Denial {
            view, destination, ..
        } = &self.finding
        else {
            return false;
        };
        Dest::of(destination).is_some_and(|d| {
            crate::egress::proposal::allows(*view, &a.rule, rules, a.claims.as_ref(), a.phase, &d)
        })
    }

    /// Whether a job bore out an allow in every phase it was seen in.
    pub fn confirmed(&self) -> bool {
        !self.allows.is_empty()
            && self.phases.keys().all(|p| {
                self.allows.iter().any(|a| {
                    crate::egress::proposal::phase_key(a.phase) == Some(p.as_str())
                        && a.confirmed.is_some()
                })
            })
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
    allows: redb::Table<'t, (&'static str, &'static str), u64>,
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
            allows: txn.open_table(EGRESS_ALLOWS)?,
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
        // Indexed while an allow awaits confirmation, by the earliest generation of those.
        let key = subject.param();
        let due = row.and_then(|r| {
            (r.allows.iter())
                .filter(|a| a.confirmed.is_none())
                .map(|a| a.generation)
                .min()
        });
        match due {
            Some(generation) => {
                self.allows.insert((key.as_str(), id), generation)?;
            }
            None => {
                self.allows.remove((key.as_str(), id))?;
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
                // A job placed before the allow of each phase it adds to the row in was saved
                // leaves it standing; any other reopens it, one with no generation recorded
                // included.
                let placed = new
                    .and_then(|j| j.egress_rules.as_ref())
                    .map(|a| a.generation);
                let before = share.phases.iter().all(|p| {
                    row.allows.iter().any(|a| {
                        crate::egress::proposal::phase_key(a.phase) == Some(*p)
                            && placed.is_some_and(|g| g < a.generation)
                    })
                });
                match (row.allows.is_empty(), before) {
                    (true, _) => {}
                    (false, true) => {
                        if let Some(ack) = row.acknowledged.as_mut() {
                            ack.generation = row.generation;
                        }
                    }
                    (false, false) => row.allows.clear(),
                }
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

/// Confirm the allows of job `id`'s subject awaiting it that its record `job` bears out: placed
/// under their generation or a later one, with their rule applying to it, it reached their
/// destination in their phase and was refused it by no VM, and reported that phase completely.
pub(super) fn confirm(
    txn: &redb::WriteTransaction,
    id: &str,
    job: &JobRow,
    now: u64,
) -> Result<()> {
    let (Some(placed), Some(report)) = (&job.egress_rules, crate::egress::report(job)) else {
        return Ok(());
    };
    let subject = Subject::of(job);
    let key = subject.param();
    let mut t = Tables::open(txn)?;
    let mut due = Vec::new();
    for entry in t.allows.range((key.as_str(), "")..=(key.as_str(), "~"))? {
        let (k, generation) = entry?;
        if generation.value() <= placed.generation {
            due.push(k.value().1.to_string());
        }
    }
    if due.is_empty() {
        return Ok(());
    }
    for row_id in due {
        let Some(mut row) = t.get(&row_id)? else {
            t.allows.remove((key.as_str(), row_id.as_str()))?;
            continue;
        };
        let was = Indexed::of(&row);
        let Finding::Denial {
            view,
            protocol,
            destination,
        } = row.finding.clone()
        else {
            continue;
        };
        let mut changed = false;
        for a in row
            .allows
            .iter_mut()
            .filter(|a| a.confirmed.is_none() && a.generation <= placed.generation)
        {
            // The rule saved applied to it: enforced, or for a would-block as the dry-run rule.
            let applied = placed.rules.contains(&a.rule)
                || (view == View::WouldBlock && placed.dry_run.contains(&a.rule));
            let complete = report
                .phases
                .iter()
                .any(|p| p.phase == a.phase && p.coverage == EgressCoverage::Complete);
            let of_it = |e: &&vk_hub_proto::egress::EgressEntry| {
                e.phase == a.phase && e.protocol == protocol && e.destination == destination
            };
            let reached = report.entries.iter().filter(of_it).any(|e| {
                matches!(
                    e.outcome,
                    EgressOutcome::Observed | EgressOutcome::WouldBlock
                )
            });
            let refused = report
                .entries
                .iter()
                .filter(of_it)
                .any(|e| match e.outcome {
                    EgressOutcome::Observed => false,
                    EgressOutcome::WouldBlock => view == View::WouldBlock,
                    _ => true,
                });
            if applied && complete && reached && !refused {
                a.confirmed = Some(Confirmed {
                    job: id.to_string(),
                    at: now,
                });
                changed = true;
            }
        }
        if changed {
            t.put(&row_id, Some(&row), Some(was), &subject)?;
        }
    }
    Ok(())
}

/// Save an allow for `req`'s row as `actor`, its rule saved in `txn`, the rules now `rules` at
/// `generation`, if they allow its destination to the claims and in the phase it names:
/// audited. Return whether they did.
pub(super) fn save_allow(
    txn: &redb::WriteTransaction,
    req: &AllowRequest,
    generation: u64,
    rules: &[crate::store::EgressRuleRow],
    actor: &str,
    now: u64,
) -> Result<bool> {
    let mut t = Tables::open(txn)?;
    let Some(mut row) = t.get(&req.row)? else {
        return Ok(false);
    };
    let was = Indexed::of(&row);
    let allow = AllowSaved {
        generation,
        phase: req.phase,
        rule: req.rule.clone(),
        claims: req.claims.clone(),
        by: actor.to_string(),
        at: now,
        confirmed: None,
    };
    if !row.allows_now(&allow, rules) {
        return Ok(false);
    }
    // A phase's latest replaces its earlier one.
    row.allows.retain(|a| a.phase != req.phase);
    row.allows.push(allow);
    row.acknowledged = Some(Acknowledged {
        generation: row.generation,
        by: actor.to_string(),
        at: now,
    });
    let subject = row.subject.clone();
    t.put(&req.row, Some(&row), Some(was), &subject)?;
    let phase = crate::egress::phase_text(req.phase).to_ascii_lowercase();
    let event = format!(
        "{actor} saved an allow for egress {} {} for {}: rule {}, {phase} phase, rules \
         generation {generation}",
        view_text(row.finding.view()),
        row.finding.text(),
        row.who(),
        req.rule,
    );
    append_audit(txn, None, actor, &event, now)?;
    Ok(true)
}

/// A view as the audit log names it.
fn view_text(v: View) -> &'static str {
    match v {
        View::Blocked => "blocked",
        View::WouldBlock => "would-block",
        View::Refused => "declaration issue",
    }
}

/// Fill the rows and Observed traffic from the history once each: the jobs a build without
/// them recorded. A job's record is decoded at a time.
pub(super) fn share_history(txn: &redb::WriteTransaction) -> Result<()> {
    let mut meta = txn.open_table(EGRESS_META)?;
    // Created for the reads to find, rows or not.
    drop(Tables::open(txn)?);
    txn.open_table(EGRESS_MUTES)?;
    super::observed::create(txn)?;
    let rows = meta.get(BUILT)?.is_none();
    let observed = meta.get(OBSERVED_BUILT)?.is_none();
    if rows || observed {
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
            if rows {
                reshare(txn, id.value(), None, Some(&row))?;
            }
            if observed {
                super::observed::reshare(txn, id.value(), None, Some(&row))?;
            }
        }
    }
    meta.insert(BUILT, 1)?;
    meta.insert(OBSERVED_BUILT, 1)?;
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
            // An operator's triage replaces the allows saved.
            row.allows.clear();
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

    /// Job `n`, placed under rules generation `placed` (none recorded for `None`), ended with
    /// `report`.
    fn placed(db: &Db, n: u64, report: EgressReport, placed: Option<u64>) -> String {
        let id = format!("{n:032x}");
        let mut row = job(n, report);
        row.egress_rules = placed.map(|generation| crate::store::EgressRulesApplied {
            rules: vec![crate::store::DEFAULT_RULE.into()],
            dry_run: vec![],
            generation,
        });
        let mut queued = row.clone();
        queued.result = None;
        queued.revision = 1;
        db.submit_job(&id, &queued, &id, b"{}", "key gitlab", 10)
            .unwrap();
        assert!(db.put_job(&id, &row, &[], 11).unwrap());
        id
    }

    /// An allow saved takes a row out of New until a job placed under its generation refuses
    /// it again; one placed before adds to it and leaves it standing. A later job reaching the
    /// destination, its phase reported completely, confirms it. A save the rules as saved do
    /// not bear out saves no allow.
    #[test]
    fn an_allow_saved_awaits_a_later_job_and_a_refusal_under_it_reopens_the_row() {
        use vk_hub_proto::egress::{EgressCoverage, EgressPhase, HubPhase};

        use crate::egress::testing::phase;
        use crate::store::{AllowRequest, DEFAULT_RULE, RuleChange, RuleMode};
        let db = Db::open_memory().unwrap();
        let fallback = |names: &[&str]| RuleChange {
            name: DEFAULT_RULE.into(),
            subject: None,
            run: Some(HubPhase::Unrestricted),
            build: Some(HubPhase::Allow {
                names: names.iter().map(|n| n.to_string()).collect(),
                ips: vec![],
            }),
            mode: Some(RuleMode::Enforce),
        };
        db.put_egress_rule(&fallback(&[]), false, "uid 1", 1)
            .unwrap();
        let deb = || EgressDestination::domain("deb.debian.org");
        let at_build = |e: EgressEntry| EgressEntry {
            phase: EgressPhase::Build,
            ..e
        };
        let refused = || EgressReport {
            entries: vec![at_build(entry(
                EgressOutcome::Blocked,
                EgressProtocol::Dns,
                deb(),
                Some(EgressLayer::HubRule),
            ))],
            ..EgressReport::default()
        };
        let reached = |coverage| EgressReport {
            entries: vec![at_build(entry(
                EgressOutcome::Observed,
                EgressProtocol::Dns,
                deb(),
                None,
            ))],
            phases: vec![phase(EgressPhase::Build, coverage)],
            ..EgressReport::default()
        };
        placed(&db, 1, refused(), Some(1));
        let (id, _) = only_row(&db);
        let req = AllowRequest {
            row: id.clone(),
            phase: EgressPhase::Build,
            rule: DEFAULT_RULE.into(),
            claims: None,
        };
        // Another entry: the rules as saved still refuse it.
        let (_, _, _, saved) = db
            .put_egress_rule_allowing(&fallback(&["x.example"]), true, 1, &req, "uid 1", 2)
            .unwrap();
        assert!(!saved);
        assert!(only_row(&db).1.is_new());
        let (_, _, _, saved) = db
            .put_egress_rule_allowing(&fallback(&["deb.debian.org"]), true, 2, &req, "uid 1", 3)
            .unwrap();
        assert!(saved);
        let row = only_row(&db).1;
        assert!(!row.is_new());
        assert_eq!(
            row.allows.iter().map(|a| a.generation).collect::<Vec<_>>(),
            [3]
        );
        assert_eq!(db.egress_new(0).unwrap(), 0);

        // Placed before the save: it adds to the row, and leaves it standing.
        placed(&db, 2, refused(), Some(2));
        let row = only_row(&db).1;
        assert!(!row.is_new() && !row.allows.is_empty(), "{row:?}");
        // Reached under it, but reported in part: no confirmation yet.
        placed(&db, 3, reached(EgressCoverage::Partial), Some(3));
        assert!(!only_row(&db).1.confirmed());
        // Reached under it, but the rule saved did not apply to it.
        let mut elsewhere = job(6, reached(EgressCoverage::Complete));
        elsewhere.egress_rules = Some(crate::store::EgressRulesApplied {
            rules: vec!["other".into()],
            dry_run: vec![],
            generation: 3,
        });
        let other = format!("{:032x}", 6);
        let mut queued = elsewhere.clone();
        queued.result = None;
        queued.revision = 1;
        db.submit_job(&other, &queued, &other, b"{}", "key gitlab", 10)
            .unwrap();
        db.put_job(&other, &elsewhere, &[], 11).unwrap();
        assert!(!only_row(&db).1.confirmed());
        let confirming = placed(&db, 4, reached(EgressCoverage::Complete), Some(3));
        let row = only_row(&db).1;
        assert!(row.confirmed());
        assert_eq!(
            row.allows[0].confirmed.as_ref().map(|c| c.job.clone()),
            Some(confirming)
        );
        assert!(row.allowed_by(&db.egress_rules().unwrap().1));
        assert!(!row.allowed_by(&[]));

        // Refused again by a job with no generation recorded: New again.
        placed(&db, 5, refused(), None);
        let row = only_row(&db).1;
        assert!(row.is_new() && row.allows.is_empty(), "{row:?}");
        assert_eq!(db.egress_new(0).unwrap(), 1);
        let audit: Vec<String> = db
            .audits(None, 10)
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect();
        assert!(
            audit.contains(
                &"uid 1 saved an allow for egress blocked DNS deb.debian.org for key gitlab: rule \
                  default, build phase, rules generation 3"
                    .to_string()
            ),
            "{audit:?}"
        );
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
