//! The Egress page's *Observed traffic* ([`crate::egress::observed`]), kept as the job history
//! is, as the Blocked rows are: each record written takes back its job's part as the record it
//! replaces had it and adds its own, and each record leaving the history takes back its own.
//!
//! A project keeps at most [`MAX_OBSERVED_CONTACTS`] destinations, phase by phase. A job's
//! contact past them is not kept but counted, by job, so that it is taken back with the job; a
//! destination its jobs no longer reach frees its place for the next job written.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use super::jobs::JobRow;
use super::{Db, decode, encode};
use crate::egress::blocked::Subject;
use crate::egress::observed::{Contact, Observation, Reported, observation};

/// [`OBSERVED`]'s key.
type UseKey = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    u64,
);
/// [`OBSERVED_LAST`]'s key.
type LastKey = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    u64,
    &'static str,
);
/// [`OBSERVED_COVERAGE`]'s key.
type CoverageKey = (&'static str, &'static str, &'static str, &'static str, u64);
/// Two counts: `(jobs, attempts)`, `(jobs, complete)`.
type Counts = (u64, u64);

/// Key: `(subject, phase, contact, protection, ref, day)`: a project's ([`Subject::param`]) use
/// of a destination ([`Contact::key`]) in a phase, by its jobs of a protection and ref whose
/// first attempt was on a day (since the epoch, on their nodes' clocks). Value: `(jobs,
/// attempts)`.
pub(super) const OBSERVED: TableDefinition<UseKey, Counts> =
    TableDefinition::new("egress_observed");
/// Key: `(subject, phase, contact, protection, last attempt in ms, job ID)` of each job kept
/// as using a destination, so that its latest is the end of a range. Value: its attempts.
pub(super) const OBSERVED_LAST: TableDefinition<LastKey, u64> =
    TableDefinition::new("egress_observed_last");
/// Key: `(subject, phase, contact)`. Value: the jobs kept as using it: the project's
/// destinations, counted against [`MAX_OBSERVED_CONTACTS`].
pub(super) const OBSERVED_CONTACTS: TableDefinition<(&str, &str, &str), u64> =
    TableDefinition::new("egress_observed_contacts");
/// Key: `(subject, job ID)`. Value: the job's contacts not kept, past the project's bound.
pub(super) const OBSERVED_DROPPED: TableDefinition<(&str, &str), u64> =
    TableDefinition::new("egress_observed_dropped");
/// Key: `(subject, phase, protection, ref, day)`: the jobs of a project, protection and ref
/// that ran a phase, by the day they ended (since the epoch, on the hub's clock); phase
/// [`UNREPORTED`] for those that ran and sent no report. Value: `(jobs, of them reported
/// complete)`.
pub(super) const OBSERVED_COVERAGE: TableDefinition<CoverageKey, Counts> =
    TableDefinition::new("egress_coverage");
/// Key: `(subject, when the job ended or was last heard of, job ID)` of each job in
/// [`OBSERVED_SUBJECTS`], so that a project's latest is the end of a range. Value: unused.
pub(super) const OBSERVED_JOBS: TableDefinition<(&str, u64, &str), u64> =
    TableDefinition::new("egress_observed_jobs");
/// Key: a subject ([`Subject::param`]). Value: JSON [`ObservedSubject`].
pub(super) const OBSERVED_SUBJECTS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("egress_observed_subjects");

/// The phase [`OBSERVED_COVERAGE`] counts jobs that sent no report under.
pub const UNREPORTED: &str = "unreported";

/// The most destinations, phase by phase, kept of one project.
#[cfg(not(test))]
pub const MAX_OBSERVED_CONTACTS: u64 = 1000;
#[cfg(test)]
pub const MAX_OBSERVED_CONTACTS: u64 = 3;

/// A project's jobs in Observed traffic.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedSubject {
    /// The display-safe project its latest job named, as that job was added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Its latest job's key name, for display.
    pub key_name: String,
    /// When its latest job ended, or was last heard of.
    pub latest_at: u64,
    /// Its jobs with a report, a running job's so far included.
    pub jobs: u64,
    /// Its jobs that ran and sent no report.
    pub unreported: u64,
    /// Its destinations kept, phase by phase.
    pub contacts: u64,
    /// Its jobs' contacts not kept, past [`MAX_OBSERVED_CONTACTS`].
    pub dropped: u64,
}

/// The tables a change writes.
struct Tables<'t> {
    observed: redb::Table<'t, UseKey, Counts>,
    last: redb::Table<'t, LastKey, u64>,
    contacts: redb::Table<'t, (&'static str, &'static str, &'static str), u64>,
    dropped: redb::Table<'t, (&'static str, &'static str), u64>,
    coverage: redb::Table<'t, CoverageKey, Counts>,
    jobs: redb::Table<'t, (&'static str, u64, &'static str), u64>,
    subjects: redb::Table<'t, &'static str, &'static [u8]>,
}

/// Add `n` to `v`, or take it away.
fn step(v: u64, n: u64, add: bool) -> u64 {
    if add {
        v.saturating_add(n)
    } else {
        v.saturating_sub(n)
    }
}

impl<'t> Tables<'t> {
    fn open(txn: &'t redb::WriteTransaction) -> Result<Self> {
        Ok(Tables {
            observed: txn.open_table(OBSERVED)?,
            last: txn.open_table(OBSERVED_LAST)?,
            contacts: txn.open_table(OBSERVED_CONTACTS)?,
            dropped: txn.open_table(OBSERVED_DROPPED)?,
            coverage: txn.open_table(OBSERVED_COVERAGE)?,
            jobs: txn.open_table(OBSERVED_JOBS)?,
            subjects: txn.open_table(OBSERVED_SUBJECTS)?,
        })
    }

    /// Add job `id`'s part `o`, from `row`, or take it back.
    fn apply(&mut self, id: &str, o: &Observation, row: &JobRow, add: bool) -> Result<()> {
        let subject = o.subject.param();
        let s = subject.as_str();
        let mut summary: ObservedSubject = match self.subjects.get(s)? {
            Some(g) => decode(g.value())?,
            None => ObservedSubject::default(),
        };
        let day = o.day();
        let (protection, git_ref) = (o.protection, o.git_ref.as_str());
        let mut cover = |phase: &str, complete: bool| -> Result<()> {
            let key = (s, phase, protection, git_ref, day);
            let (jobs, done) = self.coverage.get(key)?.map_or((0, 0), |g| g.value());
            let (jobs, done) = (step(jobs, 1, add), step(done, u64::from(complete), add));
            if jobs == 0 {
                self.coverage.remove(key)?;
            } else {
                self.coverage.insert(key, (jobs, done))?;
            }
            Ok(())
        };
        match &o.reported {
            Reported::No => {
                cover(UNREPORTED, false)?;
                summary.unreported = step(summary.unreported, 1, add);
            }
            Reported::Yes { phases, uses } => {
                for (phase, complete) in phases {
                    cover(phase, *complete)?;
                }
                summary.jobs = step(summary.jobs, 1, add);
                if !add && let Some(n) = self.dropped.remove((s, id))? {
                    summary.dropped = summary.dropped.saturating_sub(n.value());
                }
                let mut dropped = 0u64;
                for ((phase, contact), u) in uses {
                    let at = (s, *phase, contact.as_str());
                    let last = (s, *phase, contact.as_str(), protection, u.last_ms, id);
                    let kept = self.contacts.get(at)?.map_or(0, |g| g.value());
                    if add {
                        if kept == 0 && summary.contacts >= MAX_OBSERVED_CONTACTS {
                            dropped = dropped.saturating_add(1);
                            continue;
                        }
                        if kept == 0 {
                            summary.contacts = summary.contacts.saturating_add(1);
                        }
                        self.contacts.insert(at, kept.saturating_add(1))?;
                        self.last.insert(last, u.attempts)?;
                    } else {
                        // Not kept when it was added: counted among the dropped, gone above.
                        if self.last.remove(last)?.is_none() {
                            continue;
                        }
                        if kept <= 1 {
                            self.contacts.remove(at)?;
                            summary.contacts = summary.contacts.saturating_sub(1);
                        } else {
                            self.contacts.insert(at, kept - 1)?;
                        }
                    }
                    let key = (
                        s,
                        *phase,
                        contact.as_str(),
                        protection,
                        git_ref,
                        o.use_day(u),
                    );
                    let (jobs, attempts) = self.observed.get(key)?.map_or((0, 0), |g| g.value());
                    let (jobs, attempts) = (step(jobs, 1, add), step(attempts, u.attempts, add));
                    if jobs == 0 {
                        self.observed.remove(key)?;
                    } else {
                        self.observed.insert(key, (jobs, attempts))?;
                    }
                }
                if dropped > 0 {
                    self.dropped.insert((s, id), dropped)?;
                    summary.dropped = summary.dropped.saturating_add(dropped);
                }
            }
        }
        if add {
            self.jobs.insert((s, o.at, id), 0)?;
        } else {
            self.jobs.remove((s, o.at, id))?;
        }
        if summary.jobs == 0 && summary.unreported == 0 {
            self.subjects.remove(s)?;
            return Ok(());
        }
        // Named as its latest job names it, as that job was added.
        if add && o.at >= summary.latest_at {
            summary.project = row.project.clone();
            summary.key_name = row.key_name.clone();
        }
        if let Some(latest) = self
            .jobs
            .range((s, 0, "")..=(s, u64::MAX, "~"))?
            .next_back()
        {
            summary.latest_at = latest?.0.value().1;
        }
        self.subjects.insert(s, encode(&summary)?.as_slice())?;
        Ok(())
    }
}

/// Replace job `id`'s part from record `old` with that from `new`, either absent: the old part
/// taken back whole, then the new one added, so that a destination it no longer reaches frees
/// its place first.
pub(super) fn reshare(
    txn: &redb::WriteTransaction,
    id: &str,
    old: Option<&JobRow>,
    new: Option<&JobRow>,
) -> Result<()> {
    let before = old.and_then(|r| observation(r).map(|o| (o, r)));
    let after = new.and_then(|r| observation(r).map(|o| (o, r)));
    if before.as_ref().map(|(o, _)| o) == after.as_ref().map(|(o, _)| o) {
        return Ok(());
    }
    let mut t = Tables::open(txn)?;
    if let Some((o, row)) = &before {
        t.apply(id, o, row, false)?;
    }
    if let Some((o, row)) = &after {
        t.apply(id, o, row, true)?;
    }
    Ok(())
}

/// What the page asks of one project's Observed traffic: one phase or all, one protection or all.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObservedFilter<'a> {
    /// A [`crate::egress::blocked::phase_key`].
    pub phase: Option<&'a str>,
    /// A [`crate::egress::observed::protection_key`].
    pub protection: Option<&'a str>,
}

impl ObservedFilter<'_> {
    fn admits(&self, phase: &str, protection: &str) -> bool {
        self.phase.is_none_or(|p| p == phase) && self.protection.is_none_or(|p| p == protection)
    }
}

/// One destination of a project in one phase, over its jobs a filter admits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedUse {
    pub phase: String,
    pub contact: Contact,
    pub jobs: u64,
    pub attempts: u64,
    /// The first day it was used on, in days since the epoch.
    pub first_day: u64,
    /// The days it was used on.
    pub days: BTreeSet<u64>,
    /// Its latest attempt, in milliseconds on its node's clock, and that job's ID.
    pub last_ms: u64,
    pub last_job: String,
    /// The jobs by ref and protection.
    pub refs: BTreeMap<(String, String), u64>,
}

/// How completely a project's jobs reported one phase.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Coverage {
    /// Its jobs that ran the phase.
    pub ran: u64,
    /// Of them, those whose node recorded it whole.
    pub complete: u64,
}

/// A project's coverage: each phase's, those that sent no report as [`UNREPORTED`]; and the
/// first day its jobs ended on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Coverages {
    pub phases: BTreeMap<String, Coverage>,
    pub since_day: Option<u64>,
}

impl Db {
    /// Every project in Observed traffic, by subject ([`Subject::param`]).
    pub fn observed_subjects(&self) -> Result<Vec<(String, ObservedSubject)>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(OBSERVED_SUBJECTS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            out.push((k.value().to_string(), decode(v.value())?));
        }
        Ok(out)
    }

    /// Project `subject`'s coverage over the jobs `filter` admits.
    pub fn observed_coverage(
        &self,
        subject: &Subject,
        filter: ObservedFilter,
    ) -> Result<Coverages> {
        let s = subject.param();
        let txn = self.db.begin_read()?;
        let table = txn.open_table(OBSERVED_COVERAGE)?;
        let mut out = Coverages::default();
        for entry in table.range((s.as_str(), "", "", "", 0)..)? {
            let (k, v) = entry?;
            let (subject, phase, protection, _, day) = k.value();
            if subject != s {
                break;
            }
            out.since_day = Some(out.since_day.map_or(day, |d| d.min(day)));
            // Those that sent no report ran some phase, which one unknown.
            let admitted = match phase {
                UNREPORTED => filter.protection.is_none_or(|p| p == protection),
                _ => filter.admits(phase, protection),
            };
            if !admitted {
                continue;
            }
            let (jobs, complete) = v.value();
            let c = out.phases.entry(phase.to_string()).or_default();
            c.ran = c.ran.saturating_add(jobs);
            c.complete = c.complete.saturating_add(complete);
        }
        Ok(out)
    }

    /// Project `subject`'s destinations, over the jobs `filter` admits.
    pub fn observed_uses(
        &self,
        subject: &Subject,
        filter: ObservedFilter,
    ) -> Result<Vec<ObservedUse>> {
        let s = subject.param();
        let txn = self.db.begin_read()?;
        let observed = txn.open_table(OBSERVED)?;
        let mut uses: BTreeMap<(String, String), ObservedUse> = BTreeMap::new();
        for entry in observed.range((s.as_str(), "", "", "", "", 0)..)? {
            let (k, v) = entry?;
            let (subject, phase, contact, protection, git_ref, day) = k.value();
            if subject != s {
                break;
            }
            if !filter.admits(phase, protection) {
                continue;
            }
            let key = (phase.to_string(), contact.to_string());
            let u = match uses.entry(key) {
                std::collections::btree_map::Entry::Occupied(u) => u.into_mut(),
                std::collections::btree_map::Entry::Vacant(at) => {
                    // A contact this build cannot read shows as nothing.
                    let Some(contact) = Contact::parse(contact) else {
                        continue;
                    };
                    at.insert(ObservedUse {
                        phase: phase.to_string(),
                        contact,
                        jobs: 0,
                        attempts: 0,
                        first_day: day,
                        days: BTreeSet::new(),
                        last_ms: 0,
                        last_job: String::new(),
                        refs: BTreeMap::new(),
                    })
                }
            };
            let (jobs, attempts) = v.value();
            u.jobs = u.jobs.saturating_add(jobs);
            u.attempts = u.attempts.saturating_add(attempts);
            u.first_day = u.first_day.min(day);
            u.days.insert(day);
            let n = u
                .refs
                .entry((git_ref.to_string(), protection.to_string()))
                .or_default();
            *n = n.saturating_add(jobs);
        }
        let last = txn.open_table(OBSERVED_LAST)?;
        for ((phase, contact), u) in &mut uses {
            let protections: BTreeSet<&str> = u.refs.keys().map(|(_, p)| p.as_str()).collect();
            for p in protections {
                let range = (s.as_str(), phase.as_str(), contact.as_str(), p, 0, "")
                    ..=(
                        s.as_str(),
                        phase.as_str(),
                        contact.as_str(),
                        p,
                        u64::MAX,
                        "~",
                    );
                if let Some(entry) = last.range(range)?.next_back() {
                    let (k, _) = entry?;
                    let (_, _, _, _, ms, job) = k.value();
                    if ms >= u.last_ms {
                        u.last_ms = ms;
                        u.last_job = job.to_string();
                    }
                }
            }
        }
        Ok(uses.into_values().collect())
    }
}

/// One record of a project's use of a destination: its jobs of a protection and ref that first
/// used it on a day ([`OBSERVED`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedRecord {
    /// [`Subject::param`].
    pub subject: String,
    pub phase: String,
    /// [`Contact::key`].
    pub contact: String,
    pub protection: String,
    pub git_ref: String,
    pub day: u64,
    pub jobs: u64,
    pub attempts: u64,
}

/// One record of how completely a project's jobs of a protection and ref that ended on a day
/// reported a phase ([`OBSERVED_COVERAGE`]); phase [`UNREPORTED`] for those that sent no
/// report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageRecord {
    pub subject: String,
    pub phase: String,
    pub protection: String,
    pub git_ref: String,
    pub day: u64,
    pub jobs: u64,
    pub complete: u64,
}

impl Db {
    /// Visit every project's use of each destination, in key order, at most `limit` records:
    /// whether every one was visited.
    pub fn observed_records(
        &self,
        limit: usize,
        mut visit: impl FnMut(ObservedRecord),
    ) -> Result<bool> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(OBSERVED)?;
        for (i, entry) in table.iter()?.enumerate() {
            if i >= limit {
                return Ok(false);
            }
            let (k, v) = entry?;
            let (subject, phase, contact, protection, git_ref, day) = k.value();
            let (jobs, attempts) = v.value();
            visit(ObservedRecord {
                subject: subject.to_string(),
                phase: phase.to_string(),
                contact: contact.to_string(),
                protection: protection.to_string(),
                git_ref: git_ref.to_string(),
                day,
                jobs,
                attempts,
            });
        }
        Ok(true)
    }

    /// Visit how completely every project's jobs reported each phase, in key order, at most
    /// `limit` records: whether every one was visited.
    pub fn coverage_records(
        &self,
        limit: usize,
        mut visit: impl FnMut(CoverageRecord),
    ) -> Result<bool> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(OBSERVED_COVERAGE)?;
        for (i, entry) in table.iter()?.enumerate() {
            if i >= limit {
                return Ok(false);
            }
            let (k, v) = entry?;
            let (subject, phase, protection, git_ref, day) = k.value();
            let (jobs, complete) = v.value();
            visit(CoverageRecord {
                subject: subject.to_string(),
                phase: phase.to_string(),
                protection: protection.to_string(),
                git_ref: git_ref.to_string(),
                day,
                jobs,
                complete,
            });
        }
        Ok(true)
    }
}

/// Create the tables, for the reads to find them however empty.
pub(super) fn create(txn: &redb::WriteTransaction) -> Result<()> {
    drop(Tables::open(txn)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use vk_hub_proto::egress::{
        EgressCoverage, EgressDestination, EgressEntry, EgressOutcome, EgressPhase, EgressProtocol,
        EgressReport,
    };

    use redb::ReadableTableMetadata;

    use super::*;
    use crate::egress::testing::{entry, job, phase};

    fn reached(names: &[&str]) -> EgressReport {
        EgressReport {
            entries: names
                .iter()
                .map(|n| EgressEntry {
                    count: 2,
                    first_seen_ms: 5 * crate::egress::observed::DAY_MS,
                    last_seen_ms: 5 * crate::egress::observed::DAY_MS + 10,
                    ..entry(
                        EgressOutcome::Observed,
                        EgressProtocol::Dns,
                        EgressDestination::domain(n),
                        None,
                    )
                })
                .collect(),
            phases: vec![phase(EgressPhase::Run, EgressCoverage::Complete)],
            ..EgressReport::default()
        }
    }

    /// Job `n`, submitted then ended with `row`'s report.
    fn ended(db: &Db, n: u64, row: JobRow) -> String {
        let id = format!("{n:032x}");
        let mut queued = row.clone();
        (queued.result, queued.started_at, queued.revision) = (None, None, 1);
        db.submit_job(&id, &queued, &id, b"{}", "key gitlab", 10)
            .unwrap();
        assert!(db.put_job(&id, &row, &[], 11).unwrap());
        id
    }

    fn subject() -> Subject {
        Subject::Key { key: "k".into() }
    }

    fn summary(db: &Db) -> Option<ObservedSubject> {
        let mut all = db.observed_subjects().unwrap();
        assert!(all.len() <= 1, "{all:?}");
        all.pop().map(|(s, o)| {
            assert_eq!(s, subject().param());
            o
        })
    }

    /// A destination counts the history's jobs that reached it, by ref and protection, with
    /// its latest job; a record written again adds nothing, and a job leaving the history takes
    /// its part back, the last one the destination and the project.
    #[test]
    fn a_destination_counts_the_history_s_jobs_once_each() {
        let db = Db::open_memory().unwrap();
        let mut row_a = job(1, reached(&["a.example"]));
        row_a.protected = Some(true);
        let a = ended(&db, 1, row_a.clone());
        let mut row_b = job(2, reached(&["a.example", "b.example"]));
        row_b.git_ref = Some("topic".into());
        row_b.protected = Some(false);
        let b = ended(&db, 2, row_b.clone());
        row_b.revision += 1;
        row_b.settled_at = Some(12);
        assert!(db.put_job(&b, &row_b, &[], 12).unwrap());

        let all = ObservedFilter::default();
        let uses = db.observed_uses(&subject(), all).unwrap();
        assert_eq!(uses.len(), 2, "{uses:?}");
        let a_use = uses
            .iter()
            .find(|u| u.contact.text() == "DNS a.example")
            .unwrap();
        assert_eq!(
            (a_use.jobs, a_use.attempts, a_use.first_day, &a_use.last_job),
            (2, 4, 5, &b)
        );
        assert_eq!(a_use.phase, "run");
        assert_eq!(
            a_use.refs,
            BTreeMap::from([
                (("main".into(), "protected".into()), 1),
                (("topic".into(), "unprotected".into()), 1)
            ])
        );
        let protected = ObservedFilter {
            protection: Some("protected"),
            ..ObservedFilter::default()
        };
        let uses = db.observed_uses(&subject(), protected).unwrap();
        assert_eq!(uses.len(), 1);
        assert_eq!((uses[0].jobs, &uses[0].last_job), (1, &a));
        let s = summary(&db).unwrap();
        assert_eq!((s.jobs, s.contacts, s.dropped), (2, 2, 0));
        let cover = db.observed_coverage(&subject(), all).unwrap();
        assert_eq!(
            cover.phases,
            BTreeMap::from([(
                "run".to_string(),
                Coverage {
                    ran: 2,
                    complete: 2
                }
            )])
        );
        assert_eq!(cover.since_day, Some(0));

        assert_eq!(summary(&db).unwrap().latest_at, 1_002);
        // A settled job leaves the history first: the latest one, here.
        db.prune_jobs(20, 1).unwrap();
        let uses = db.observed_uses(&subject(), all).unwrap();
        assert_eq!(uses.iter().map(|u| u.jobs).sum::<u64>(), 1);
        let s = summary(&db).unwrap();
        assert_eq!((s.jobs, s.latest_at), (1, 1_001));
        row_a.revision += 1;
        row_a.settled_at = Some(13);
        db.put_job(&a, &row_a, &[], 13).unwrap();
        db.prune_jobs(20, 0).unwrap();
        assert_eq!(summary(&db), None);
        assert!(db.observed_uses(&subject(), all).unwrap().is_empty());
        let txn = db.db.begin_read().unwrap();
        for empty in [
            txn.open_table(OBSERVED_LAST).unwrap().is_empty().unwrap(),
            txn.open_table(OBSERVED_JOBS).unwrap().is_empty().unwrap(),
            txn.open_table(OBSERVED_CONTACTS)
                .unwrap()
                .is_empty()
                .unwrap(),
            txn.open_table(OBSERVED_COVERAGE)
                .unwrap()
                .is_empty()
                .unwrap(),
        ] {
            assert!(empty);
        }
    }

    /// Past the project's bound a job's contact is counted, not kept, and taken back with the
    /// job; a place freed goes to the next job written. A job that ran and sent no report counts
    /// as such, apart from the phases.
    #[test]
    fn a_project_keeps_its_bound_and_counts_what_it_drops() {
        let db = Db::open_memory().unwrap();
        let a = ended(&db, 1, job(1, reached(&["a.x", "b.x", "c.x", "d.x"])));
        let s = summary(&db).unwrap();
        assert_eq!((s.contacts, s.dropped), (MAX_OBSERVED_CONTACTS, 1));
        let b = ended(&db, 2, job(2, reached(&["d.x", "a.x"])));
        let s = summary(&db).unwrap();
        assert_eq!((s.contacts, s.dropped), (3, 2));
        let all = ObservedFilter::default();
        let jobs: u64 = db
            .observed_uses(&subject(), all)
            .unwrap()
            .iter()
            .map(|u| u.jobs)
            .sum();
        assert_eq!(jobs, 4);

        // Job 1 goes: its places free, and its dropped contact is no longer counted.
        let mut row = db.job(&a).unwrap().unwrap();
        (row.revision, row.settled_at) = (row.revision + 1, Some(12));
        db.put_job(&a, &row, &[], 12).unwrap();
        db.prune_jobs(20, 1).unwrap();
        let s = summary(&db).unwrap();
        assert_eq!((s.jobs, s.contacts, s.dropped), (1, 1, 1));
        ended(&db, 3, job(3, reached(&["d.x"])));
        let s = summary(&db).unwrap();
        assert_eq!((s.contacts, s.dropped), (2, 1));
        let mut row = db.job(&b).unwrap().unwrap();
        (row.revision, row.settled_at) = (row.revision + 1, Some(13));
        db.put_job(&b, &row, &[], 13).unwrap();
        db.prune_jobs(20, 1).unwrap();
        let s = summary(&db).unwrap();
        assert_eq!((s.jobs, s.contacts, s.dropped), (1, 1, 0));

        let mut silent = job(4, EgressReport::default());
        silent.result.as_mut().unwrap().egress = None;
        ended(&db, 4, silent);
        assert_eq!(summary(&db).unwrap().unreported, 1);
        let cover = db.observed_coverage(&subject(), all).unwrap();
        assert_eq!(
            cover.phases.get(UNREPORTED),
            Some(&Coverage {
                ran: 1,
                complete: 0
            })
        );
        let build = ObservedFilter {
            phase: Some("build"),
            ..ObservedFilter::default()
        };
        let cover = db.observed_coverage(&subject(), build).unwrap();
        assert_eq!(cover.phases.keys().collect::<Vec<_>>(), [UNREPORTED]);
    }

    /// Observed traffic built from a history recorded without it is what was kept as it was
    /// recorded.
    #[test]
    fn observed_traffic_is_built_once_from_the_history() {
        let db = Db::open_memory().unwrap();
        ended(&db, 1, job(1, reached(&["a.x"])));
        ended(&db, 2, job(2, reached(&["a.x", "b.x"])));
        let all = ObservedFilter::default();
        let kept = (
            db.observed_subjects().unwrap(),
            db.observed_uses(&subject(), all).unwrap(),
        );
        let txn = db.db.begin_write().unwrap();
        for table in [
            "egress_observed",
            "egress_observed_last",
            "egress_observed_contacts",
            "egress_observed_dropped",
            "egress_coverage",
            "egress_observed_subjects",
            "egress_observed_jobs",
        ] {
            txn.delete_table(redb::TableDefinition::<&str, &[u8]>::new(table))
                .unwrap();
        }
        txn.open_table(redb::TableDefinition::<&str, u64>::new("egress_meta"))
            .unwrap()
            .remove("observed")
            .unwrap();
        super::super::egress::share_history(&txn).unwrap();
        txn.commit().unwrap();
        assert_eq!(
            (
                db.observed_subjects().unwrap(),
                db.observed_uses(&subject(), all).unwrap()
            ),
            kept
        );
    }
}
