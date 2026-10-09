//! Job records and redacted submission specs. Successful create requests are keyed by
//! `request_id` so retries reuse the first answer. Full specs contain tokens and secrets;
//! the hub keeps them only in memory until a node accepts the job ([`crate::jobs`]).
//! Output is stored in separate files beside the database.
//!
//! The records are the hub's job history: the newest jobs, up to a count the operator sets,
//! in submission order ([`JOB_ORDER`]), so the oldest go first and a page of history is a
//! range read from the newest end.

use std::collections::HashSet;
use std::sync::atomic::Ordering;

use anyhow::{Context, Result};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use vk_hub_proto::client::{CancelMode, JobState, JobView, Placement};
use vk_hub_proto::job::{FailureClass, JobResult};

use super::{Db, append_audit, decode, encode};

/// Key: job ID. Value: JSON [`JobRow`].
pub(super) const JOBS: TableDefinition<&str, &[u8]> = TableDefinition::new("jobs");
/// Key: job ID. Value: the job's spec as submitted, redacted, JSON.
pub(super) const JOB_SPECS: TableDefinition<&str, &[u8]> = TableDefinition::new("job_specs");
/// Key: `<key id>/<request_id>`. Value: JSON [`RequestRow`].
pub(super) const REQUESTS: TableDefinition<&str, &[u8]> = TableDefinition::new("requests");
/// Key: a sequence number, oldest submission first. Value: the job's ID.
pub(super) const JOB_ORDER: TableDefinition<u64, &str> = TableDefinition::new("job_order");
/// The history's bookkeeping. Key: one of the names below. Value: a [`JOB_ORDER`] sequence.
const JOB_META: TableDefinition<&str, u64> = TableDefinition::new("job_meta");
/// Every job placed below this in [`JOB_ORDER`] has finished and expired past [`JOB_KEEP`].
const EXPIRED_BELOW: &str = "expired_below";

/// How long a `request_id` keeps its answer.
pub const REQUEST_KEEP: u64 = 86_400;

/// How long after a job was settled or finished its redacted spec is kept, and its output when
/// its producer never settled it; its record stays in the history.
const JOB_KEEP: u64 = 30 * 86_400;

/// How many jobs past the excess one trim of the history examines at most: a history whose
/// oldest jobs cannot go yet is trimmed further on later passes, not read whole on each.
const TRIM_SCAN: u64 = 10_000;

/// How many jobs' records the history keeps by default (`job_history` in `hub.toml`).
pub const DEFAULT_JOB_HISTORY: usize = 10_000;

/// Maximum number of matching jobs in a history summary, counted newest first.
pub const SUMMARY_JOBS: usize = 10_000;

/// How often, at most, requests past [`REQUEST_KEEP`] are swept.
const REQUEST_SWEEP_SECS: u64 = 600;

/// A job the hub has taken.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRow {
    /// The submitting key's ID ([`super::ApiPrincipal::id`]).
    pub key: String,
    /// Its name, for display.
    pub key_name: String,
    pub request_id: String,
    pub placement: Placement,
    /// What the job is, for display: GitLab's job ID, project and name.
    #[serde(default)]
    pub title: String,
    /// Display-safe GitLab project (`group/project`); `None` for an older hub's record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// The job's name in its pipeline, display-safe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The job's GitLab page from its spec; `None` for an invalid URL or an older hub's record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_url: Option<String>,
    pub created_at: u64,
    pub state: JobState,
    pub revision: u64,
    #[serde(default)]
    pub node: Option<String>,
    #[serde(default)]
    pub stage: Option<String>,
    #[serde(default)]
    pub cancel: Option<CancelMode>,
    #[serde(default)]
    pub result: Option<JobResult>,
    /// The output's length: as stored while the job runs, final once it has finished.
    #[serde(default)]
    pub output_len: u64,
    /// When a node accepted it, on the hub's clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<u64>,
    #[serde(default)]
    pub finished_at: Option<u64>,
    /// When its producer settled it and its output was dropped.
    #[serde(default)]
    pub settled_at: Option<u64>,
    /// When expiry past [`JOB_KEEP`] removed its redacted spec and any unsettled output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired_at: Option<u64>,
}

impl JobRow {
    /// The job as the client API shows it, with `output_len` the output held now.
    pub fn view(&self, id: &str, output_len: u64) -> JobView {
        JobView {
            id: id.to_string(),
            revision: self.revision,
            state: self.state,
            node: self.node.clone(),
            stage: self.stage.clone(),
            output_len,
            cancel: self.cancel,
            result: self.result.clone(),
        }
    }

    /// Runtime in milliseconds, using the node's measurement when available. Otherwise,
    /// use the hub's time from acceptance to completion, or to `now` while running.
    /// `None` for a job no node accepted.
    pub fn ran_ms(&self, now: u64) -> Option<u64> {
        if let Some(usage) = self.result.as_ref().and_then(|r| r.usage) {
            return Some(usage.wall_ms);
        }
        let end = match self.state {
            JobState::Finished => self.finished_at?,
            _ => now,
        };
        Some(end.saturating_sub(self.started_at?).saturating_mul(1000))
    }

    /// The job's outcome for history filtering.
    pub fn outcome(&self) -> JobOutcome {
        match (self.state, &self.result) {
            (JobState::Finished, Some(r)) => match r.failure {
                None => JobOutcome::Success,
                Some(FailureClass::Canceled) => JobOutcome::Canceled,
                Some(_) => JobOutcome::Failed,
            },
            (JobState::Finished, None) => JobOutcome::Failed,
            _ => JobOutcome::Running,
        }
    }
}

/// Job outcome used by the history filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobOutcome {
    /// Queued, starting or running.
    Running,
    Success,
    /// Ended by a failure of any class but a cancel.
    Failed,
    Canceled,
}

impl JobOutcome {
    pub const ALL: [JobOutcome; 4] = [
        JobOutcome::Running,
        JobOutcome::Success,
        JobOutcome::Failed,
        JobOutcome::Canceled,
    ];

    pub fn name(self) -> &'static str {
        match self {
            JobOutcome::Running => "running",
            JobOutcome::Success => "success",
            JobOutcome::Failed => "failed",
            JobOutcome::Canceled => "canceled",
        }
    }

    /// The label shown in the result filter.
    pub fn label(self) -> &'static str {
        match self {
            JobOutcome::Running => "Running",
            JobOutcome::Success => "Success",
            JobOutcome::Failed => "Failed",
            JobOutcome::Canceled => "Canceled",
        }
    }

    pub fn parse(s: &str) -> Option<JobOutcome> {
        JobOutcome::ALL.into_iter().find(|o| o.name() == s)
    }
}

/// Which jobs a page of history shows: those matching every filter set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JobFilter {
    /// The node it was sent to.
    pub node: Option<String>,
    /// Its GitLab project, exactly.
    pub project: Option<String>,
    pub outcome: Option<JobOutcome>,
}

impl JobFilter {
    pub fn matches(&self, row: &JobRow) -> bool {
        self.node
            .as_ref()
            .is_none_or(|n| row.node.as_ref() == Some(n))
            && (self.project.as_ref()).is_none_or(|p| row.project.as_ref() == Some(p))
            && self.outcome.is_none_or(|o| row.outcome() == o)
    }
}

/// Summary of the newest [`SUMMARY_JOBS`] matching jobs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JobSummary {
    pub matched: usize,
    /// More jobs match than were summed up.
    pub capped: bool,
    /// Those that ended, whichever way.
    pub finished: usize,
    pub succeeded: usize,
    /// The median of how long the finished ones ran, in milliseconds.
    pub median_ms: Option<u64>,
}

/// The median of `values`, the mean of the middle two for an even count.
fn median(values: &mut [u64]) -> Option<u64> {
    values.sort_unstable();
    let mid = values.len() / 2;
    match values.len() {
        0 => None,
        n if n % 2 == 1 => Some(values[mid]),
        _ => Some(values[mid - 1].midpoint(values[mid])),
    }
}

/// A page of the job history, newest first.
#[derive(Debug, Default)]
pub struct JobPage {
    /// Each job's place in the history ([`JOB_ORDER`]), ID and record.
    pub rows: Vec<(u64, String, JobRow)>,
    /// The last job's position, used as the next page's exclusive cursor when older jobs match.
    pub older: Option<u64>,
    pub summary: JobSummary,
    /// Every project in the history, sorted, for the filter's choices.
    pub projects: Vec<String>,
}

/// A client request that created something, and what it was answered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestRow {
    pub at: u64,
    /// `sha256` of the request's body as parsed, hex: the same ID with another body is a
    /// conflict, not a retry.
    pub digest: String,
    /// The job created, or the reservation granted.
    pub answer: serde_json::Value,
}

/// What a job submission came to.
#[derive(Debug)]
pub enum Submitted {
    New,
    /// The request was made before, with the same body: this job.
    Again(String),
    /// The request ID was used before with another body.
    Conflict,
}

/// A request's key in [`REQUESTS`].
fn request_key(key: &str, request_id: &str) -> String {
    format!("{key}/{request_id}")
}

impl Db {
    /// Record job `id` for `row`, submitted as `request_id` with a body hashing to `digest`,
    /// and its redacted spec, audited as `actor`'s — or, for a request ID seen before, what
    /// that came to.
    pub fn submit_job(
        &self,
        id: &str,
        row: &JobRow,
        digest: &str,
        redacted_spec: &[u8],
        actor: &str,
        now: u64,
    ) -> Result<Submitted> {
        let request = request_key(&row.key, &row.request_id);
        let txn = self.db.begin_write().context("starting a write")?;
        {
            let mut requests = txn.open_table(REQUESTS)?;
            if let Some(previous) = requests
                .get(request.as_str())?
                .map(|g| decode::<RequestRow>(g.value()))
                .transpose()?
                .filter(|r| now.saturating_sub(r.at) < REQUEST_KEEP)
            {
                return Ok(if previous.digest == digest {
                    match previous.answer.as_str() {
                        Some(job) => Submitted::Again(job.to_string()),
                        None => Submitted::Conflict,
                    }
                } else {
                    Submitted::Conflict
                });
            }
            sweep_requests(self, &mut requests, now)?;
            let answer = RequestRow {
                at: now,
                digest: digest.to_string(),
                answer: serde_json::Value::String(id.to_string()),
            };
            requests.insert(request.as_str(), encode(&answer)?.as_slice())?;
            txn.open_table(JOBS)?.insert(id, encode(row)?.as_slice())?;
            txn.open_table(JOB_SPECS)?.insert(id, redacted_spec)?;
            let mut order = txn.open_table(JOB_ORDER)?;
            let seq = next_seq(&order, &txn.open_table(JOB_META)?)?;
            order.insert(seq, id)?;
        }
        let event = format!("{actor} submitted job {id}: {}", row.title);
        append_audit(&txn, None, actor, &event, now)?;
        txn.commit().context("recording a job")?;
        Ok(Submitted::New)
    }

    /// The answer a reservation request made as `request_id` by key `key` got, if it was made
    /// within [`REQUEST_KEEP`].
    pub fn request(&self, key: &str, request_id: &str, now: u64) -> Result<Option<RequestRow>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(REQUESTS)?;
        Ok(table
            .get(request_key(key, request_id).as_str())?
            .map(|g| decode::<RequestRow>(g.value()))
            .transpose()?
            .filter(|r| now.saturating_sub(r.at) < REQUEST_KEEP))
    }

    /// Record that the request `request_id` of key `key` was answered `answer`, with `event`
    /// audited as `actor`'s against `node`.
    #[allow(clippy::too_many_arguments)]
    pub fn record_request(
        &self,
        key: &str,
        request_id: &str,
        row: &RequestRow,
        node: Option<&str>,
        actor: &str,
        event: &str,
        now: u64,
    ) -> Result<()> {
        let txn = self.db.begin_write().context("starting a write")?;
        {
            let mut requests = txn.open_table(REQUESTS)?;
            sweep_requests(self, &mut requests, now)?;
            requests.insert(
                request_key(key, request_id).as_str(),
                encode(row)?.as_slice(),
            )?;
        }
        append_audit(&txn, node, actor, event, now)?;
        txn.commit().context("recording a request")
    }

    pub fn job(&self, id: &str) -> Result<Option<JobRow>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(JOBS)?;
        table
            .get(id)?
            .map(|g| decode::<JobRow>(g.value()))
            .transpose()
    }

    /// Write `row` for job `id` and audit each `(node, actor, event)` in `events`, unless
    /// a later revision is already stored or the job is gone from the history: only
    /// [`Db::submit_job`] adds a job. Racing writes keep the newer revision.
    /// Return whether the row was written.
    pub fn put_job(
        &self,
        id: &str,
        row: &JobRow,
        events: &[(Option<String>, String, String)],
        now: u64,
    ) -> Result<bool> {
        let txn = self.db.begin_write().context("starting a write")?;
        {
            let mut table = txn.open_table(JOBS)?;
            let stored = table
                .get(id)?
                .map(|g| decode::<JobRow>(g.value()))
                .transpose()?;
            let Some(stored) = stored.filter(|s| s.revision <= row.revision) else {
                return Ok(false);
            };
            // A write prepared before the job expired keeps it expired.
            let mut row = row.clone();
            row.expired_at = row.expired_at.or(stored.expired_at);
            table.insert(id, encode(&row)?.as_slice())?;
        }
        for (node, actor, event) in events {
            append_audit(&txn, node.as_deref(), actor, event, now)?;
        }
        txn.commit().context("updating a job")?;
        Ok(true)
    }

    /// Every job not finished.
    pub fn unfinished_jobs(&self) -> Result<Vec<(String, JobRow)>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(JOBS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let row = decode::<JobRow>(value.value())?;
            if row.state != JobState::Finished {
                out.push((key.value().to_string(), row));
            }
        }
        Ok(out)
    }

    /// The latest `limit` jobs, newest first.
    pub fn jobs(&self, limit: usize) -> Result<Vec<(String, JobRow)>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(JOBS)?;
        let order = txn.open_table(JOB_ORDER)?;
        let mut out = Vec::new();
        for entry in order.iter()?.rev() {
            if out.len() >= limit {
                break;
            }
            let id = entry?.1.value().to_string();
            if let Some(row) = table.get(id.as_str())? {
                let row = decode::<JobRow>(row.value())?;
                out.push((id, row));
            }
        }
        Ok(out)
    }

    /// Up to `limit` matching jobs, newest first, submitted before the job at `before`.
    /// Includes a summary of the newest [`SUMMARY_JOBS`] jobs matching `filter`.
    pub fn job_page(
        &self,
        filter: &JobFilter,
        before: Option<u64>,
        limit: usize,
        now: u64,
    ) -> Result<JobPage> {
        self.job_page_summing(filter, before, limit, now, SUMMARY_JOBS)
    }

    /// [`Db::job_page`], summing up at most the newest `summed` jobs `filter` matches. The
    /// scan stops once the page is full, its next job found, and `summed` jobs counted, so
    /// the filter's projects are those of the jobs read.
    fn job_page_summing(
        &self,
        filter: &JobFilter,
        before: Option<u64>,
        limit: usize,
        now: u64,
        summed: usize,
    ) -> Result<JobPage> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(JOBS)?;
        let order = txn.open_table(JOB_ORDER)?;
        let mut page = JobPage::default();
        let mut projects = std::collections::BTreeSet::new();
        let mut ran = Vec::new();
        for entry in order.iter()?.rev() {
            let (seq, id) = entry?;
            let Some(row) = table.get(id.value())? else {
                continue;
            };
            // One that does not decode is left out rather than failing every page.
            let Ok(row) = decode::<JobRow>(row.value()) else {
                continue;
            };
            if let Some(p) = &row.project {
                projects.insert(p.clone());
            }
            if !filter.matches(&row) {
                continue;
            }
            let summary = &mut page.summary;
            if summary.matched < summed {
                summary.matched += 1;
                if row.state == JobState::Finished {
                    summary.finished += 1;
                    summary.succeeded += usize::from(row.outcome() == JobOutcome::Success);
                    ran.extend(row.ran_ms(now));
                }
            } else {
                summary.capped = true;
            }
            let seq = seq.value();
            if before.is_some_and(|b| seq >= b) {
                continue;
            }
            if page.rows.len() < limit {
                page.rows.push((seq, id.value().to_string(), row));
            } else {
                page.older = page.rows.last().map(|r| r.0);
                if page.summary.capped {
                    break;
                }
            }
        }
        page.summary.median_ms = median(&mut ran);
        page.projects = projects.into_iter().collect();
        Ok(page)
    }

    /// Job `id`'s spec as submitted, redacted.
    #[cfg(test)]
    pub fn job_spec(&self, id: &str) -> Result<Option<Vec<u8>>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(JOB_SPECS)?;
        Ok(table.get(id)?.map(|g| g.value().to_vec()))
    }

    /// Keep the history to its newest `keep` jobs: past that count, the oldest finished jobs
    /// that were settled or expired go, record and spec; a job its producer may still read
    /// stays. A finished job settled or finished more than [`JOB_KEEP`] before `now` expires:
    /// its spec goes, and so does its output if it was never settled. The IDs whose output
    /// files go: the jobs dropped and the jobs expired that still held output.
    ///
    /// Trimming reads from the oldest job as far as the excess goes, and at most
    /// [`TRIM_SCAN`] jobs past it; expiring, from
    /// [`EXPIRED_BELOW`] up to the first job submitted within [`JOB_KEEP`], since none
    /// submitted later can have ended before it.
    pub fn prune_jobs(&self, now: u64, keep: usize) -> Result<Vec<String>> {
        self.prune_jobs_scanning(now, keep, TRIM_SCAN)
    }

    /// [`Db::prune_jobs`], trimming past at most `scan` jobs that cannot go yet.
    fn prune_jobs_scanning(&self, now: u64, keep: usize, scan: u64) -> Result<Vec<String>> {
        let past_keep = |t: u64| now.saturating_sub(t) > JOB_KEEP;
        let expires = |row: &JobRow| {
            row.state == JobState::Finished
                && row.settled_at.or(row.finished_at).is_some_and(past_keep)
        };
        let holds_output = |row: &JobRow| row.settled_at.is_none() && row.expired_at.is_none();
        let txn = self.db.begin_write().context("starting a write")?;
        let outputs = {
            let mut table = txn.open_table(JOBS)?;
            let mut specs = txn.open_table(JOB_SPECS)?;
            let mut order = txn.open_table(JOB_ORDER)?;
            let mut meta = txn.open_table(JOB_META)?;
            let mut outputs = Vec::new();

            let mut excess = order
                .len()?
                .saturating_sub(u64::try_from(keep).unwrap_or(u64::MAX));
            let (mut unplaced, mut dropped) = (Vec::new(), Vec::new());
            let mut budget = excess.saturating_add(scan);
            for entry in order.iter()? {
                if excess == 0 || budget == 0 {
                    break;
                }
                budget -= 1;
                let (seq, id) = entry?;
                let (seq, id) = (seq.value(), id.value().to_string());
                let Some(row) = table.get(id.as_str())? else {
                    excess = excess.saturating_sub(1);
                    unplaced.push(seq);
                    continue;
                };
                let row = decode::<JobRow>(row.value())?;
                if row.state == JobState::Finished && (row.settled_at.is_some() || expires(&row)) {
                    excess = excess.saturating_sub(1);
                    unplaced.push(seq);
                    if holds_output(&row) {
                        outputs.push(id.clone());
                    }
                    dropped.push(id);
                }
            }
            for seq in unplaced {
                order.remove(seq)?;
            }
            for id in &dropped {
                table.remove(id.as_str())?;
                specs.remove(id.as_str())?;
            }

            let from = meta.get(EXPIRED_BELOW)?.map_or(0, |g| g.value());
            // `below` follows the expired jobs only up to the first that is not.
            let (mut below, mut contiguous, mut expired) = (from, true, Vec::new());
            for entry in order.range(from..)? {
                let (seq, id) = entry?;
                let (seq, id) = (seq.value(), id.value().to_string());
                let row = match table.get(id.as_str())? {
                    Some(row) => decode::<JobRow>(row.value())?,
                    // Its record is gone: nothing to expire.
                    None => {
                        if contiguous {
                            below = seq.saturating_add(1);
                        }
                        continue;
                    }
                };
                if !past_keep(row.created_at) {
                    break;
                }
                if row.expired_at.is_none() {
                    if !expires(&row) {
                        contiguous = false;
                        continue;
                    }
                    expired.push((id, row));
                }
                if contiguous {
                    below = seq.saturating_add(1);
                }
            }
            for (id, mut row) in expired {
                specs.remove(id.as_str())?;
                if holds_output(&row) {
                    outputs.push(id.clone());
                }
                row.expired_at = Some(now);
                table.insert(id.as_str(), encode(&row)?.as_slice())?;
            }
            if below != from {
                meta.insert(EXPIRED_BELOW, below)?;
            }
            outputs
        };
        txn.commit().context("pruning jobs")?;
        Ok(outputs)
    }
}

/// The next sequence in `order`, past the newest and at least [`EXPIRED_BELOW`],
/// so jobs added after rebuilding the order are not mistaken for expired jobs.
fn next_seq(
    order: &impl ReadableTable<u64, &'static str>,
    meta: &impl ReadableTable<&'static str, u64>,
) -> Result<u64> {
    let next = order
        .last()?
        .map_or(0, |(k, _)| k.value().saturating_add(1));
    let floor = meta.get(EXPIRED_BELOW)?.map_or(0, |g| g.value());
    Ok(next.max(floor))
}

/// Append unindexed jobs in submission order and remove entries for missing records,
/// inside `txn`. Run at every start: an older hub may have added or removed jobs,
/// either before the index existed or since this hub last ran.
pub(super) fn order_jobs(txn: &redb::WriteTransaction) -> Result<()> {
    let mut order = txn.open_table(JOB_ORDER)?;
    let table = txn.open_table(JOBS)?;
    let (mut placed, mut gone) = (HashSet::new(), Vec::new());
    for entry in order.iter()? {
        let (seq, id) = entry?;
        if table.get(id.value())?.is_some() {
            placed.insert(id.value().to_string());
        } else {
            gone.push(seq.value());
        }
    }
    for seq in gone {
        order.remove(seq)?;
    }
    let mut jobs = Vec::new();
    for entry in table.iter()? {
        let (id, row) = entry?;
        if placed.contains(id.value()) {
            continue;
        }
        // One that does not decode is placed first among them, as the oldest, rather than
        // failing the hub's start.
        let at = decode::<JobRow>(row.value()).map_or(0, |r| r.created_at);
        jobs.push((at, id.value().to_string()));
    }
    jobs.sort();
    let next = next_seq(&order, &txn.open_table(JOB_META)?)?;
    for (seq, (_, id)) in (next..).zip(&jobs) {
        order.insert(seq, id.as_str())?;
    }
    Ok(())
}

/// Drop requests past [`REQUEST_KEEP`], at most once every [`REQUEST_SWEEP_SECS`].
fn sweep_requests(db: &Db, requests: &mut redb::Table<'_, &str, &[u8]>, now: u64) -> Result<()> {
    let last = db.requests_swept_at.load(Ordering::Relaxed);
    if now.saturating_sub(last) < REQUEST_SWEEP_SECS {
        return Ok(());
    }
    db.requests_swept_at.store(now, Ordering::Relaxed);
    requests.retain(|_, value| {
        decode::<RequestRow>(value).is_ok_and(|r| now.saturating_sub(r.at) < REQUEST_KEEP)
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vk_hub_proto::job::{Envelope, FailureClass};

    fn row(revision: u64) -> JobRow {
        JobRow {
            key: "k".into(),
            key_name: "gitlab".into(),
            request_id: "1".repeat(32),
            placement: Placement {
                pool: "ci".into(),
                labels: vec![],
                envelope: Envelope::default(),
            },
            title: "gitlab job 7".into(),
            job_url: None,
            project: None,
            name: None,
            created_at: 10,
            state: JobState::Queued,
            revision,
            node: None,
            stage: None,
            cancel: None,
            result: None,
            output_len: 0,
            started_at: None,
            finished_at: None,
            settled_at: None,
            expired_at: None,
        }
    }

    #[test]
    fn a_submission_is_recorded_once_and_a_reused_id_with_another_body_conflicts() {
        let db = Db::open_memory().unwrap();
        let id = "a".repeat(32);
        assert!(matches!(
            db.submit_job(&id, &row(1), "d1", b"{}", "key gitlab", 10)
                .unwrap(),
            Submitted::New
        ));
        match db
            .submit_job(&"b".repeat(32), &row(1), "d1", b"{}", "key gitlab", 11)
            .unwrap()
        {
            Submitted::Again(again) => assert_eq!(again, id),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            db.submit_job(&"b".repeat(32), &row(1), "d2", b"{}", "key gitlab", 11)
                .unwrap(),
            Submitted::Conflict
        ));
        // A day on, the ID is free again.
        assert!(matches!(
            db.submit_job(
                &"c".repeat(32),
                &row(1),
                "d2",
                b"{}",
                "key gitlab",
                10 + REQUEST_KEEP
            )
            .unwrap(),
            Submitted::New
        ));
        assert_eq!(db.job_spec(&id).unwrap().unwrap(), b"{}");
    }

    #[test]
    fn an_older_revision_does_not_overwrite_a_newer() {
        let db = Db::open_memory().unwrap();
        let id = "a".repeat(32);
        db.submit_job(&id, &row(1), "d", b"{}", "key gitlab", 10)
            .unwrap();
        assert!(db.put_job(&id, &row(3), &[], 11).unwrap());
        assert!(!db.put_job(&id, &row(2), &[], 12).unwrap());
        assert_eq!(db.job(&id).unwrap().unwrap().revision, 3);
        let mut finished = row(4);
        finished.state = JobState::Finished;
        finished.finished_at = Some(20);
        db.put_job(&id, &finished, &[], 20).unwrap();
        assert!(db.unfinished_jobs().unwrap().is_empty());
        assert!(db.prune_jobs(20 + JOB_KEEP, 10).unwrap().is_empty());
        // Unsettled past its keep: its output and spec go, its record stays in the history.
        assert_eq!(
            db.prune_jobs(21 + JOB_KEEP, 10).unwrap(),
            std::slice::from_ref(&id)
        );
        let expired = db.job(&id).unwrap().unwrap();
        assert_eq!(
            (expired.revision, expired.expired_at),
            (4, Some(21 + JOB_KEEP))
        );
        assert!(db.job_spec(&id).unwrap().is_none());
    }

    /// Job `n` of a history in `state`: submitted at `n`, on node `a…` or `b…` by parity, of
    /// project `p<n % 3>`, started at once and, finished, ended by `failure` `n` seconds on.
    fn job(n: u64, state: JobState, failure: Option<FailureClass>) -> JobRow {
        let mut row = row(1);
        row.request_id = format!("{n:032}");
        row.created_at = n;
        row.project = Some(format!("p{}", n % 3));
        row.node = Some(if n.is_multiple_of(2) { "a" } else { "b" }.repeat(32));
        row.state = state;
        if state == JobState::Queued {
            return row;
        }
        row.started_at = Some(n);
        if state != JobState::Finished {
            return row;
        }
        row.finished_at = Some(n + n);
        row.result = Some(JobResult {
            failure,
            exit_code: None,
            message: None,
            output_len: 0,
            artifacts: Vec::new(),
            usage: None,
        });
        row
    }

    /// Job `n`, finished and settled by its producer as it finished.
    fn settled(n: u64) -> JobRow {
        let mut row = job(n, JobState::Finished, None);
        row.settled_at = row.finished_at;
        row
    }

    fn id(n: u64) -> String {
        format!("{n:032x}")
    }

    fn submit(db: &Db, n: u64, row: &JobRow) {
        let digest = n.to_string();
        let new = db.submit_job(&id(n), row, &digest, b"{}", "key gitlab", n);
        assert!(matches!(new.unwrap(), Submitted::New));
    }

    fn listed(db: &Db) -> Vec<String> {
        db.jobs(100).unwrap().into_iter().map(|j| j.0).collect()
    }

    fn placed(db: &Db) -> u64 {
        let txn = db.db.begin_read().unwrap();
        txn.open_table(JOB_ORDER).unwrap().len().unwrap()
    }

    fn expired_below(db: &Db) -> Option<u64> {
        let txn = db.db.begin_read().unwrap();
        let meta = txn.open_table(JOB_META).unwrap();
        meta.get(EXPIRED_BELOW).unwrap().map(|g| g.value())
    }

    /// Past its count, the history drops its oldest settled or expired jobs, record and spec,
    /// and keeps one still running, or one finished its producer may still read, however old.
    #[test]
    fn the_history_keeps_its_newest_jobs() {
        let db = Db::open_memory().unwrap();
        submit(&db, 1, &job(1, JobState::Running, None));
        submit(&db, 2, &settled(2));
        submit(&db, 3, &job(3, JobState::Finished, None));
        for n in 4..=10 {
            submit(&db, n, &settled(n));
        }
        // Settled, the dropped jobs held no output.
        assert!(db.prune_jobs(11, 6).unwrap().is_empty());
        assert_eq!(listed(&db), [10, 9, 8, 7, 3, 1].map(id));
        assert!(db.job_spec(&id(2)).unwrap().is_none());
        assert!(db.job_spec(&id(7)).unwrap().is_some());
        assert!(db.prune_jobs(11, 6).unwrap().is_empty());
        assert_eq!(placed(&db), 6);
        // Past its keep, the unsettled one goes, its output with it.
        assert_eq!(db.prune_jobs(7 + JOB_KEEP, 5).unwrap(), [id(3)]);
        assert_eq!(listed(&db), [10, 9, 8, 7, 1].map(id));
        // Once it finishes and is settled, the running one goes first.
        let mut done = settled(1);
        done.revision = 2;
        assert!(db.put_job(&id(1), &done, &[], 12).unwrap());
        assert!(db.prune_jobs(12, 4).unwrap().is_empty());
        assert_eq!(listed(&db), [10, 9, 8, 7].map(id));
    }

    /// A job's write that lands after the trim dropped it does not bring the job back.
    #[test]
    fn a_write_racing_the_trim_does_not_bring_a_job_back() {
        let db = Db::open_memory().unwrap();
        submit(&db, 1, &settled(1));
        assert!(db.prune_jobs(3, 0).unwrap().is_empty());
        let mut late = settled(1);
        late.revision = 2;
        assert!(!db.put_job(&id(1), &late, &[], 4).unwrap());
        assert!(db.job(&id(1)).unwrap().is_none());
        assert!(listed(&db).is_empty());
        assert_eq!(placed(&db), 0);
    }

    /// A finished job expires once, past its keep: its spec goes, its output too if it was
    /// never settled, and later passes start past every job expired in a row.
    #[test]
    fn a_job_past_its_keep_expires_once() {
        let db = Db::open_memory().unwrap();
        submit(&db, 1, &job(1, JobState::Finished, None));
        submit(&db, 2, &job(2, JobState::Running, None));
        submit(&db, 3, &settled(3));
        submit(&db, 4, &job(4, JobState::Finished, None));
        let now = 10 + JOB_KEEP;
        let mut outputs = db.prune_jobs(now, 100).unwrap();
        outputs.sort();
        assert_eq!(outputs, [id(1), id(4)]);
        for n in [1, 3, 4] {
            assert_eq!(db.job(&id(n)).unwrap().unwrap().expired_at, Some(now));
            assert!(db.job_spec(&id(n)).unwrap().is_none());
        }
        assert!(db.job_spec(&id(2)).unwrap().is_some());
        assert_eq!(expired_below(&db), Some(1));
        assert!(db.prune_jobs(now + 1, 100).unwrap().is_empty());
        // A write prepared before it expired leaves it expired.
        let mut late = job(1, JobState::Finished, None);
        late.revision = 2;
        assert!(db.put_job(&id(1), &late, &[], now + 1).unwrap());
        assert_eq!(db.job(&id(1)).unwrap().unwrap().expired_at, Some(now));
        // The running one ends; past its keep, it expires and the mark passes every job.
        let mut done = settled(2);
        done.revision = 2;
        done.finished_at = Some(now);
        done.settled_at = Some(now);
        assert!(db.put_job(&id(2), &done, &[], now).unwrap());
        assert!(db.prune_jobs(now + JOB_KEEP + 1, 100).unwrap().is_empty());
        assert!(db.job_spec(&id(2)).unwrap().is_none());
        assert_eq!(expired_below(&db), Some(4));
        assert_eq!(listed(&db), [4, 3, 2, 1].map(id));
    }

    /// A page is newest first, filtered on every field set, continues before the last one
    /// shown, and sums up every job the filter matches.
    #[test]
    fn a_history_page_is_filtered_and_continues() {
        let db = Db::open_memory().unwrap();
        let failures = [
            None,
            Some(FailureClass::Script),
            Some(FailureClass::Canceled),
        ];
        for n in 1..=11 {
            let failure = failures[(n % 3) as usize];
            submit(&db, n, &job(n, JobState::Finished, failure));
        }
        submit(&db, 12, &job(12, JobState::Running, None));
        let all = JobFilter::default();
        let page = db.job_page(&all, None, 5, 100).unwrap();
        let ids = |page: &JobPage| page.rows.iter().map(|r| r.1.clone()).collect::<Vec<_>>();
        assert_eq!(ids(&page), [12, 11, 10, 9, 8].map(id));
        assert_eq!(page.older, Some(page.rows[4].0));
        assert_eq!(page.projects, ["p0", "p1", "p2"]);
        assert_eq!(
            page.summary,
            JobSummary {
                matched: 12,
                capped: false,
                finished: 11,
                succeeded: 3,
                // n seconds each, 1 to 11.
                median_ms: Some(6000),
            }
        );
        let next = db.job_page(&all, Some(page.rows[4].0), 5, 100).unwrap();
        assert_eq!(ids(&next), [7, 6, 5, 4, 3].map(id));
        let last = db.job_page(&all, Some(next.rows[4].0), 5, 100).unwrap();
        assert_eq!(ids(&last), [2, 1].map(id));
        assert_eq!(last.older, None);

        // Project p0 is jobs 3, 6, 9 and 12; on node a…, 6 and 12.
        let filter = JobFilter {
            node: Some("a".repeat(32)),
            project: Some("p0".into()),
            outcome: None,
        };
        assert_eq!(
            ids(&db.job_page(&filter, None, 5, 100).unwrap()),
            [12, 6].map(id)
        );
        let failed = JobFilter {
            outcome: Some(JobOutcome::Failed),
            ..JobFilter::default()
        };
        let page = db.job_page(&failed, None, 5, 100).unwrap();
        assert_eq!(ids(&page), [10, 7, 4, 1].map(id));
        assert_eq!((page.summary.matched, page.summary.succeeded), (4, 0));
        let page = db.job_page(&failed, None, 2, 100).unwrap();
        assert_eq!(ids(&page), [10, 7].map(id));
        let next = db.job_page(&failed, page.older, 2, 100).unwrap();
        assert_eq!(ids(&next), [4, 1].map(id));
        assert_eq!((next.older, next.summary.matched), (None, 4));
        let past = db.job_page(&failed, Some(next.rows[1].0), 2, 100).unwrap();
        assert!(past.rows.is_empty());
        assert_eq!((past.older, past.summary.matched), (None, 4));
        let running = JobFilter {
            outcome: Some(JobOutcome::Running),
            ..JobFilter::default()
        };
        let page = db.job_page(&running, None, 5, 100).unwrap();
        assert_eq!(ids(&page), [id(12)]);
        assert_eq!(page.summary.median_ms, None);
        // Running for 88 seconds of the hub's clock.
        assert_eq!(page.rows[0].2.ran_ms(100), Some(88_000));

        // A row that does not decode is left out.
        let txn = db.db.begin_write().unwrap();
        txn.open_table(JOBS)
            .unwrap()
            .insert(id(5).as_str(), b"not json".as_slice())
            .unwrap();
        txn.commit().unwrap();
        let page = db.job_page(&all, None, 20, 100).unwrap();
        assert_eq!(page.rows.len(), 11);
        assert!(!ids(&page).contains(&id(5)));
    }

    /// The summary is of the newest jobs the filter matches, up to its bound, and says when
    /// more match; the page past them is still served.
    #[test]
    fn a_history_page_sums_up_a_bounded_number_of_jobs() {
        let db = Db::open_memory().unwrap();
        for n in 1..=11 {
            let failure = (n % 3 != 0).then_some(FailureClass::Script);
            submit(&db, n, &job(n, JobState::Finished, failure));
        }
        submit(&db, 12, &job(12, JobState::Running, None));
        let all = JobFilter::default();
        let ids = |page: &JobPage| page.rows.iter().map(|r| r.1.clone()).collect::<Vec<_>>();
        let page = db.job_page_summing(&all, None, 2, 100, 5).unwrap();
        assert_eq!(ids(&page), [12, 11].map(id));
        assert_eq!(page.older, Some(page.rows[1].0));
        assert_eq!(
            page.summary,
            JobSummary {
                matched: 5,
                capped: true,
                finished: 4,
                succeeded: 1,
                // Jobs 8 to 11 ran 8 to 11 seconds: the mean of the middle two.
                median_ms: Some(9500),
            }
        );
        let deep = db
            .job_page_summing(&all, Some(page.rows[1].0 - 4), 2, 100, 5)
            .unwrap();
        assert_eq!(ids(&deep), [6, 5].map(id));
        assert_eq!(deep.summary, page.summary);
        let whole = db.job_page_summing(&all, None, 2, 100, 12).unwrap();
        assert_eq!((whole.summary.matched, whole.summary.capped), (12, false));
    }

    /// The node's own measure of a job's run wins over the hub's timestamps.
    #[test]
    fn a_jobs_run_is_the_nodes_measure_when_it_sent_one() {
        let mut row = job(5, JobState::Finished, None);
        assert_eq!(row.ran_ms(100), Some(5000));
        if let Some(r) = row.result.as_mut() {
            r.usage = Some(vk_hub_proto::job::JobUsage {
                wall_ms: 4321,
                ..Default::default()
            });
        }
        assert_eq!(row.ran_ms(100), Some(4321));
        assert_eq!(job(5, JobState::Queued, None).ran_ms(100), None);
    }

    /// Jobs a hub recorded before the history had an order get one, oldest submission first,
    /// when the database is next opened.
    #[test]
    fn jobs_recorded_before_the_order_are_ordered_by_submission() {
        let db = Db::open_memory().unwrap();
        for n in [3, 1, 2] {
            submit(&db, n, &job(n, JobState::Finished, None));
        }
        let txn = db.db.begin_write().unwrap();
        txn.delete_table(JOB_ORDER).unwrap();
        order_jobs(&txn).unwrap();
        txn.commit().unwrap();
        assert_eq!(listed(&db), [3, 2, 1].map(id));
    }

    /// A job an older hub recorded without placing it in the order joins its newest end, and
    /// places whose records an older hub dropped go, though as many were added as dropped.
    #[test]
    fn jobs_an_older_hub_recorded_join_the_order() {
        let db = Db::open_memory().unwrap();
        for n in 1..=3 {
            submit(&db, n, &job(n, JobState::Finished, None));
        }
        let txn = db.db.begin_write().unwrap();
        {
            let mut order = txn.open_table(JOB_ORDER).unwrap();
            order.remove(0).unwrap();
            order.insert(7, id(8).as_str()).unwrap();
        }
        order_jobs(&txn).unwrap();
        txn.commit().unwrap();
        assert_eq!(listed(&db), [1, 3, 2].map(id));
        assert_eq!(placed(&db), 3);
    }

    fn seq_of(db: &Db, n: u64) -> u64 {
        let txn = db.db.begin_read().unwrap();
        let order = txn.open_table(JOB_ORDER).unwrap();
        let mut seqs = order.iter().unwrap().map(Result::unwrap);
        seqs.find(|(_, v)| v.value() == id(n)).unwrap().0.value()
    }

    /// A job placed once the order emptied, or rebuilt, is placed past every job expired: it
    /// is never taken for expired.
    #[test]
    fn a_job_placed_after_the_order_emptied_is_past_the_expired() {
        let db = Db::open_memory().unwrap();
        for n in 1..=2 {
            submit(&db, n, &settled(n));
        }
        assert!(db.prune_jobs(10 + JOB_KEEP, 100).unwrap().is_empty());
        assert_eq!(expired_below(&db), Some(2));
        assert!(db.prune_jobs(10 + JOB_KEEP, 0).unwrap().is_empty());
        assert_eq!(placed(&db), 0);
        submit(&db, 3, &job(3, JobState::Finished, None));
        assert_eq!(seq_of(&db, 3), 2);
        // An older hub's job, placed when the order is rebuilt.
        let txn = db.db.begin_write().unwrap();
        txn.delete_table(JOB_ORDER).unwrap();
        order_jobs(&txn).unwrap();
        txn.commit().unwrap();
        assert_eq!(seq_of(&db, 3), 2);
        assert_eq!(
            db.prune_jobs(10 + JOB_KEEP, 100).unwrap(),
            [id(3)],
            "expired, not skipped"
        );
    }

    /// One trim examines the excess and a bounded number of jobs past it; the next goes on.
    #[test]
    fn a_trim_reads_a_bounded_number_of_jobs() {
        let db = Db::open_memory().unwrap();
        for n in 1..=3 {
            submit(&db, n, &job(n, JobState::Running, None));
        }
        submit(&db, 4, &settled(4));
        assert!(db.prune_jobs_scanning(11, 1, 0).unwrap().is_empty());
        assert_eq!(placed(&db), 4);
        assert!(db.prune_jobs_scanning(11, 1, 1).unwrap().is_empty());
        assert_eq!(listed(&db), [3, 2, 1].map(id));
    }
}
