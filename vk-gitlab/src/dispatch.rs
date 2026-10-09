//! [`Dispatcher`] exposes the vk fleet hub's client API defined in `docs/gitlab-dispatch.md`.
//!
//! The poll loop follows the contract: wait for [capacity](Dispatcher::capacity) on the
//! runner's placement, [reserve](Dispatcher::reserve) an envelope, then ask GitLab for a
//! job while renewing the reservation. [Submit](Dispatcher::submit) the job on that
//! reservation and commit it to GitLab once the hub [reports](Dispatcher::job) node
//! acceptance. Copy its [output](Dispatcher::output) into the trace, report the result,
//! then [settle](Dispatcher::settle) it.
//!
//! The wire types are [`vk_hub_proto`]'s; [`crate::hub::HubClient`] implements the trait
//! over HTTP, and [`FakeDispatcher`] is an in-memory hub for tests.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

pub use vk_hub_proto::client::{CancelMode, Capacity, JobState as HubJobState, JobView, Placement};
pub use vk_hub_proto::job::{Envelope, FailureClass, JobResult, JobSpec};

/// An envelope set aside on a node, for one job request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    pub id: String,
    pub node: String,
    pub envelope: Envelope,
    /// The lease the node granted, counted from when the request was sent.
    pub lease: Duration,
}

/// A job handed to the hub. `Debug` shows which job it is, none of the spec's secrets.
#[derive(Clone)]
pub struct Submission {
    /// 32 hex digits for idempotent submission: reusing the ID after a restart returns
    /// the same job.
    pub request_id: String,
    pub placement: Placement,
    /// The reservation the job was requested under; `None` when it was lost meanwhile, and
    /// the hub then places the job afresh within `place_within`.
    pub reservation: Option<String>,
    pub place_within: Duration,
    /// GitLab's job ID, for logs.
    pub gitlab_job: i64,
    pub spec: JobSpec,
}

impl std::fmt::Debug for Submission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Submission")
            .field("request_id", &self.request_id)
            .field("gitlab_job", &self.gitlab_job)
            .field("placement", &self.placement)
            .field("reservation", &self.reservation)
            .finish_non_exhaustive()
    }
}

/// Output read from an offset (`GET /v1/jobs/<id>/output`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputChunk {
    /// The offset of `data`'s first byte.
    pub offset: u64,
    pub data: Bytes,
    /// The output's length so far.
    pub length: u64,
    /// The job has ended and `data` reaches the end of its output.
    pub complete: bool,
}

/// The hub's error codes, plus the ways a request can fail before one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Unauthorized,
    Forbidden,
    NotFound,
    Invalid,
    Conflict,
    NoCapacity,
    /// The reservation lapsed, was released, or its node was lost: reserve again.
    ReservationGone,
    TooLarge,
    Unavailable,
    Internal,
    /// An output offset past the end; `length` is the output's length.
    OutputRange {
        length: u64,
    },
    /// No answer: connection, TLS, timeout.
    Transport,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchError {
    pub kind: ErrorKind,
    pub message: String,
    /// The hub's `retry_after_secs`.
    pub retry_after: Option<Duration>,
}

impl DispatchError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            retry_after: None,
        }
    }
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for DispatchError {}

pub type DispatchResult<T> = Result<T, DispatchError>;

/// The hub's client API. Long polls (`wait`) return at most `wait` later, answering as a
/// plain request would. Implementations retry transport errors and retryable codes
/// themselves, as the contract describes; an error returned here is final for that call.
pub trait Dispatcher: Send + Sync + 'static {
    /// `POST /v1/capacity`: returns once the capacity's revision passes `after` (at once
    /// when `None`), or after `wait`.
    fn capacity(
        &self,
        placement: &Placement,
        after: Option<u64>,
        wait: Duration,
    ) -> impl Future<Output = DispatchResult<Capacity>> + Send;

    /// `POST /v1/reservations`: an envelope on a node, held for `lease`.
    fn reserve(
        &self,
        request_id: &str,
        placement: &Placement,
        lease: Duration,
        wait: Duration,
    ) -> impl Future<Output = DispatchResult<Reservation>> + Send;

    /// `POST /v1/reservations/<id>/renew`: extends the lease from now; answers the lease
    /// granted.
    fn renew(
        &self,
        reservation: &str,
        lease: Duration,
    ) -> impl Future<Output = DispatchResult<Duration>> + Send;

    /// `DELETE /v1/reservations/<id>`.
    fn release(&self, reservation: &str) -> impl Future<Output = DispatchResult<()>> + Send;

    /// `POST /v1/jobs`.
    fn submit(
        &self,
        submission: Submission,
    ) -> impl Future<Output = DispatchResult<JobView>> + Send;

    /// `GET /v1/jobs/<id>`: returns once the view's revision passes `after`, or after `wait`.
    fn job(
        &self,
        id: &str,
        after: Option<u64>,
        wait: Duration,
    ) -> impl Future<Output = DispatchResult<JobView>> + Send;

    /// `GET /v1/jobs/<id>/output`: bytes from `offset` (at most 1 MiB), waiting up to `wait`
    /// for some when there are none yet.
    fn output(
        &self,
        id: &str,
        offset: u64,
        wait: Duration,
    ) -> impl Future<Output = DispatchResult<OutputChunk>> + Send;

    /// `POST /v1/jobs/<id>/cancel`.
    fn cancel(
        &self,
        id: &str,
        mode: CancelMode,
    ) -> impl Future<Output = DispatchResult<JobView>> + Send;

    /// `POST /v1/jobs/<id>/settle`: the outcome reached GitLab; the hub may drop the output.
    fn settle(&self, id: &str) -> impl Future<Output = DispatchResult<()>> + Send;
}

pub use fake::{FakeCall, FakeDispatcher};

mod fake {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use tokio::sync::Notify;

    use super::*;

    /// A call the fake hub received, for tests to assert the order of.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum FakeCall {
        Reserve(String),
        Renew(String),
        Release(String),
        Submit {
            job: i64,
            reservation: Option<String>,
        },
        Cancel(String, CancelMode),
        Settle(String),
    }

    struct FakeJob {
        submission: Submission,
        view: JobView,
        output: Vec<u8>,
        settled: bool,
    }

    #[derive(Default)]
    struct Inner {
        slots: HashMap<String, u32>,
        capacity_revision: u64,
        /// Reservation ID → pool.
        reservations: HashMap<String, String>,
        next_id: u64,
        jobs: Vec<FakeJob>,
        calls: Vec<FakeCall>,
        refuse_submit: Option<DispatchError>,
        refuse_renew: Option<DispatchError>,
        /// Job ID → reads of its view (`GET /v1/jobs/<id>`) started.
        view_reads: HashMap<String, usize>,
    }

    impl Inner {
        fn fits(&self, pool: &str) -> u32 {
            let reserved = self.reservations.values().filter(|p| *p == pool).count();
            let running = self
                .jobs
                .iter()
                .filter(|j| {
                    j.submission.placement.pool == pool && j.view.state != HubJobState::Finished
                })
                .count();
            let used = u32::try_from(reserved + running).unwrap_or(u32::MAX);
            self.slots
                .get(pool)
                .copied()
                .unwrap_or(0)
                .saturating_sub(used)
        }

        fn job_mut(&mut self, id: &str) -> Option<&mut FakeJob> {
            self.jobs.iter_mut().find(|j| j.view.id == id)
        }
    }

    /// What the hub's idempotency compares: the submission as `POST /v1/jobs` carries it.
    fn body(s: &Submission) -> serde_json::Value {
        serde_json::json!([s.placement, s.reservation, s.place_within.as_secs(), s.spec])
    }

    fn not_found(id: &str) -> DispatchError {
        DispatchError::new(ErrorKind::NotFound, format!("no job {id}"))
    }

    /// An in-memory hub. The test sets each pool's slots, and plays the node: accepts a
    /// submitted job, appends its output, finishes it.
    #[derive(Clone, Default)]
    pub struct FakeDispatcher {
        inner: Arc<Mutex<Inner>>,
        changed: Arc<Notify>,
    }

    impl FakeDispatcher {
        pub fn new() -> Self {
            Self::default()
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
            self.inner.lock().unwrap_or_else(|p| p.into_inner())
        }

        /// Applies `f`, moves the capacity revision on and wakes the long polls.
        fn change<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
            let out = {
                let mut inner = self.lock();
                let out = f(&mut inner);
                inner.capacity_revision += 1;
                out
            };
            self.changed.notify_waiters();
            out
        }

        /// `f` until it gives a value; after `wait` (when given), `last` instead.
        async fn poll<T>(
            &self,
            wait: Option<Duration>,
            mut f: impl FnMut(&mut Inner) -> Option<T>,
            last: impl FnOnce(&mut Inner) -> T,
        ) -> T {
            let deadline = wait.map(|w| tokio::time::Instant::now() + w);
            loop {
                let notified = self.changed.notified();
                if let Some(v) = f(&mut self.lock()) {
                    return v;
                }
                match deadline {
                    Some(d) => {
                        if tokio::time::timeout_at(d, notified).await.is_err() {
                            return last(&mut self.lock());
                        }
                    }
                    None => notified.await,
                }
            }
        }

        /// How many envelopes `pool` has, reservations and unfinished jobs included.
        pub fn set_slots(&self, pool: &str, slots: u32) {
            self.change(|i| i.slots.insert(pool.to_owned(), slots));
        }

        /// Makes the next submissions fail with `err`.
        pub fn refuse_submit(&self, err: DispatchError) {
            self.lock().refuse_submit = Some(err);
        }

        /// Makes the next renewals fail with `err`, or succeed again with `None`.
        pub fn refuse_renew(&self, err: Option<DispatchError>) {
            self.lock().refuse_renew = err;
        }

        /// Cuts a job's output back to `len` bytes, as a hub that lost some of it would.
        pub fn truncate_output(&self, id: &str, len: usize) {
            self.change(|i| {
                if let Some(j) = i.job_mut(id) {
                    j.output.truncate(len);
                    j.view.output_len = j.output.len() as u64;
                }
            });
        }

        /// Ends a reservation, as a lapsed lease or a lost node does.
        pub fn drop_reservation(&self, id: &str) {
            self.change(|i| i.reservations.remove(id));
        }

        /// Number of view reads started for job `id`.
        pub fn view_reads(&self, id: &str) -> usize {
            self.lock().view_reads.get(id).copied().unwrap_or(0)
        }

        pub fn calls(&self) -> Vec<FakeCall> {
            self.lock().calls.clone()
        }

        pub fn reservations(&self) -> Vec<String> {
            self.lock().reservations.keys().cloned().collect()
        }

        /// Waits for the `n`th submitted job; returns its hub ID and submission.
        pub async fn wait_for_job(&self, n: usize) -> (String, Submission) {
            self.poll(
                None,
                |i| {
                    i.jobs
                        .get(n.saturating_sub(1))
                        .map(|j| (j.view.id.clone(), j.submission.clone()))
                },
                |_| unreachable!(),
            )
            .await
        }

        pub async fn wait_for_call(&self, call: FakeCall) {
            self.poll(None, |i| i.calls.contains(&call).then_some(()), |_| ())
                .await;
        }

        fn update(&self, id: &str, f: impl FnOnce(&mut FakeJob)) {
            self.change(|i| {
                if let Some(j) = i.job_mut(id) {
                    f(j);
                    j.view.revision += 1;
                }
            });
        }

        /// The node accepted the job.
        pub fn accept(&self, id: &str) {
            self.update(id, |j| {
                j.view.state = HubJobState::Running;
                j.view.node = Some("node-1".to_owned());
            });
        }

        /// Output from the node, appended.
        pub fn push_output(&self, id: &str, data: &[u8]) {
            self.change(|i| {
                if let Some(j) = i.job_mut(id) {
                    j.output.extend_from_slice(data);
                    j.view.output_len = j.output.len() as u64;
                }
            });
        }

        /// The job ended; `failure` `None` is success.
        pub fn finish(&self, id: &str, failure: Option<FailureClass>, exit_code: Option<i32>) {
            self.update(id, |j| {
                j.view.state = HubJobState::Finished;
                j.view.result = Some(JobResult {
                    failure,
                    exit_code,
                    message: None,
                    output_len: j.output.len() as u64,
                    artifacts: Vec::new(),
                    usage: None,
                });
            });
        }
    }

    impl Dispatcher for FakeDispatcher {
        async fn capacity(
            &self,
            placement: &Placement,
            after: Option<u64>,
            wait: Duration,
        ) -> DispatchResult<Capacity> {
            let pool = placement.pool.clone();
            let answer = |i: &mut Inner| Capacity {
                revision: i.capacity_revision,
                fits: i.fits(&pool),
            };
            Ok(self
                .poll(
                    Some(wait),
                    |i| {
                        after
                            .is_none_or(|a| i.capacity_revision > a)
                            .then(|| answer(i))
                    },
                    answer,
                )
                .await)
        }

        async fn reserve(
            &self,
            _request_id: &str,
            placement: &Placement,
            lease: Duration,
            _wait: Duration,
        ) -> DispatchResult<Reservation> {
            let id = self.change(|i| {
                if i.fits(&placement.pool) == 0 {
                    return None;
                }
                i.next_id += 1;
                let id = format!("{:032x}", i.next_id);
                i.reservations.insert(id.clone(), placement.pool.clone());
                i.calls.push(FakeCall::Reserve(id.clone()));
                Some(id)
            });
            match id {
                Some(id) => Ok(Reservation {
                    id,
                    node: "node-1".to_owned(),
                    envelope: placement.envelope,
                    lease,
                }),
                None => Err(DispatchError {
                    retry_after: Some(Duration::from_secs(1)),
                    ..DispatchError::new(ErrorKind::NoCapacity, "no node accepted in time")
                }),
            }
        }

        async fn renew(&self, reservation: &str, lease: Duration) -> DispatchResult<Duration> {
            let mut inner = self.lock();
            inner.calls.push(FakeCall::Renew(reservation.to_owned()));
            if let Some(err) = inner.refuse_renew.clone() {
                Err(err)
            } else if inner.reservations.contains_key(reservation) {
                Ok(lease)
            } else {
                Err(DispatchError::new(
                    ErrorKind::ReservationGone,
                    "reservation gone",
                ))
            }
        }

        async fn release(&self, reservation: &str) -> DispatchResult<()> {
            self.change(|i| {
                i.calls.push(FakeCall::Release(reservation.to_owned()));
                i.reservations.remove(reservation);
            });
            Ok(())
        }

        async fn submit(&self, submission: Submission) -> DispatchResult<JobView> {
            self.change(|i| {
                i.calls.push(FakeCall::Submit {
                    job: submission.gitlab_job,
                    reservation: submission.reservation.clone(),
                });
                if let Some(err) = i.refuse_submit.clone() {
                    return Err(err);
                }
                if let Some(j) = i
                    .jobs
                    .iter()
                    .find(|j| j.submission.request_id == submission.request_id)
                {
                    // Idempotent, as the hub: the same request_id and body answer the same
                    // job; another body is a conflict.
                    return if body(&j.submission) == body(&submission) {
                        Ok(j.view.clone())
                    } else {
                        Err(DispatchError::new(
                            ErrorKind::Conflict,
                            "this request_id was used before with another body",
                        ))
                    };
                }
                if let Some(r) = &submission.reservation {
                    i.reservations.remove(r);
                }
                i.next_id += 1;
                let view = JobView {
                    id: format!("{:032x}", i.next_id),
                    revision: 1,
                    state: HubJobState::Queued,
                    node: None,
                    stage: None,
                    output_len: 0,
                    cancel: None,
                    result: None,
                };
                i.jobs.push(FakeJob {
                    submission,
                    view: view.clone(),
                    output: Vec::new(),
                    settled: false,
                });
                Ok(view)
            })
        }

        async fn job(
            &self,
            id: &str,
            after: Option<u64>,
            wait: Duration,
        ) -> DispatchResult<JobView> {
            *self.lock().view_reads.entry(id.to_owned()).or_default() += 1;
            let current = |i: &mut Inner| i.job_mut(id).map(|j| j.view.clone());
            self.poll(
                Some(wait),
                |i| match current(i) {
                    Some(v) if after.is_none_or(|a| v.revision > a) => Some(Ok(v)),
                    Some(_) => None,
                    None => Some(Err(not_found(id))),
                },
                |i| current(i).ok_or_else(|| not_found(id)),
            )
            .await
        }

        async fn output(
            &self,
            id: &str,
            offset: u64,
            wait: Duration,
        ) -> DispatchResult<OutputChunk> {
            let read = |i: &mut Inner, block: bool| -> Option<DispatchResult<OutputChunk>> {
                let Some(j) = i.job_mut(id).filter(|j| !j.settled) else {
                    return Some(Err(not_found(id)));
                };
                let len = j.output.len() as u64;
                if offset > len {
                    return Some(Err(DispatchError::new(
                        ErrorKind::OutputRange { length: len },
                        "offset past the end",
                    )));
                }
                let finished = j.view.state == HubJobState::Finished;
                if offset == len && !finished && block {
                    return None;
                }
                let start = usize::try_from(offset).unwrap_or(usize::MAX);
                let end = j.output.len().min(start.saturating_add(1 << 20));
                Some(Ok(OutputChunk {
                    offset,
                    data: Bytes::copy_from_slice(&j.output[start..end]),
                    length: len,
                    complete: finished && end == j.output.len(),
                }))
            };
            self.poll(
                Some(wait),
                |i| read(i, true),
                |i| read(i, false).unwrap_or_else(|| Err(not_found(id))),
            )
            .await
        }

        async fn cancel(&self, id: &str, mode: CancelMode) -> DispatchResult<JobView> {
            self.lock()
                .calls
                .push(FakeCall::Cancel(id.to_owned(), mode));
            self.update(id, |j| {
                if j.view.state != HubJobState::Finished
                    && j.view.cancel != Some(CancelMode::Immediate)
                {
                    j.view.cancel = Some(mode);
                }
            });
            self.lock()
                .job_mut(id)
                .map(|j| j.view.clone())
                .ok_or_else(|| not_found(id))
        }

        async fn settle(&self, id: &str) -> DispatchResult<()> {
            self.change(|i| {
                i.calls.push(FakeCall::Settle(id.to_owned()));
                match i.job_mut(id) {
                    None => Err(not_found(id)),
                    Some(j) if j.view.state != HubJobState::Finished => Err(DispatchError::new(
                        ErrorKind::Conflict,
                        "the job has not finished",
                    )),
                    Some(j) => {
                        j.settled = true;
                        Ok(())
                    }
                }
            })
        }
    }
}
