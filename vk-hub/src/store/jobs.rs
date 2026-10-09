//! Job records and redacted submission specs. Successful create requests are keyed by
//! `request_id` so retries reuse the first answer. Full specs contain tokens and secrets;
//! the hub keeps them only in memory until a node accepts the job ([`crate::jobs`]).
//! Output is stored in separate files beside the database.

use std::sync::atomic::Ordering;

use anyhow::{Context, Result};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use vk_hub_proto::client::{CancelMode, JobState, JobView, Placement};
use vk_hub_proto::job::JobResult;

use super::{Db, append_audit, decode, encode};

/// Key: job ID. Value: JSON [`JobRow`].
pub(super) const JOBS: TableDefinition<&str, &[u8]> = TableDefinition::new("jobs");
/// Key: job ID. Value: the job's spec as submitted, redacted, JSON.
pub(super) const JOB_SPECS: TableDefinition<&str, &[u8]> = TableDefinition::new("job_specs");
/// Key: `<key id>/<request_id>`. Value: JSON [`RequestRow`].
pub(super) const REQUESTS: TableDefinition<&str, &[u8]> = TableDefinition::new("requests");

/// How long a `request_id` keeps its answer.
pub const REQUEST_KEEP: u64 = 86_400;

/// How long a job's record is kept once it is settled, or finished and never settled.
const JOB_KEEP: u64 = 30 * 86_400;

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
    /// a later revision is already stored. Racing writes keep the newer revision.
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
            if stored.is_some_and(|s| s.revision > row.revision) {
                return Ok(false);
            }
            table.insert(id, encode(row)?.as_slice())?;
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
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            out.push((key.value().to_string(), decode::<JobRow>(value.value())?));
        }
        out.sort_by(|(a, x), (b, y)| (y.created_at, b).cmp(&(x.created_at, a)));
        out.truncate(limit);
        Ok(out)
    }

    /// Job `id`'s spec as submitted, redacted.
    #[cfg(test)]
    pub fn job_spec(&self, id: &str) -> Result<Option<Vec<u8>>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(JOB_SPECS)?;
        Ok(table.get(id)?.map(|g| g.value().to_vec()))
    }

    /// Drop the records of jobs finished more than [`JOB_KEEP`] before `now`, and their specs.
    /// The IDs dropped, whose output files go too.
    pub fn prune_jobs(&self, now: u64) -> Result<Vec<String>> {
        let txn = self.db.begin_write().context("starting a write")?;
        let gone = {
            let mut table = txn.open_table(JOBS)?;
            let mut gone = Vec::new();
            for entry in table.iter()? {
                let (key, value) = entry?;
                let row = decode::<JobRow>(value.value())?;
                let ended = row.settled_at.or(row.finished_at);
                if ended.is_some_and(|t| now.saturating_sub(t) > JOB_KEEP) {
                    gone.push(key.value().to_string());
                }
            }
            let mut specs = txn.open_table(JOB_SPECS)?;
            for id in &gone {
                table.remove(id.as_str())?;
                specs.remove(id.as_str())?;
            }
            gone
        };
        txn.commit().context("pruning jobs")?;
        Ok(gone)
    }
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
        assert!(db.prune_jobs(20 + JOB_KEEP).unwrap().is_empty());
        assert_eq!(
            db.prune_jobs(21 + JOB_KEEP).unwrap(),
            std::slice::from_ref(&id)
        );
        assert!(db.job(&id).unwrap().is_none());
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
}
