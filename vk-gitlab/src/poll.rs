//! The poll loop: per configured runner, take jobs from GitLab only once the fleet has room
//! for them, hand them to the hub, and report their output and outcome back. The order is
//! virtkit's `docs/gitlab-dispatch.md`, "Job flow"; the GitLab side is a port of the
//! job-taking half of gitlab-runner's `commands/multi.go` and of
//! `commands/health_helper.go`.
//!
//! Each runner runs `request_concurrency` request loops. A loop waits for a free slot under
//! `concurrent` and the runner's `limit`, waits until the hub reports capacity on the
//! runner's placement, reserves an envelope on a node, takes the slot, and only then asks
//! GitLab for a job, renewing the reservation while the request is out; a request in flight
//! is never aborted. An empty answer gives the slot and the reservation back, so an idle
//! loop holds neither between requests. The loops of a runner start at most one request
//! per `check_interval` between them, as gitlab-runner feeds each runner once per interval
//! — except right after a job arrives (unless `strict_check_interval`).
//!
//! A job is submitted on its reservation and committed to GitLab (`state=running`, the
//! second phase of `two_phase_job_commit`) once a node accepted it; one that cannot be
//! placed is failed as `runner_system_failure` without being committed. Its output is
//! copied byte for byte from the hub into the trace — the node masks and cuts it — and its
//! result is mapped onto GitLab's failure reasons before the job is settled with the hub.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, watch};
use tokio::time::Instant;

use crate::api::{
    ClientOptions, GitLabClient, Info, JobCredentials, RetryPolicy, UpdateJobInfo, UpdateState,
};
use crate::backoff::{Backoff, hex, random_bytes};
use crate::config::{Config, RunnerConfig};
use crate::dispatch::{
    CancelMode, DispatchError, Dispatcher, ErrorKind, FailureClass, HubJobState, JobResult,
    JobView, Reservation, Submission,
};
use crate::failure::{FailureReason, FailureReasonMapper, JobState};
use crate::job::Job;
use crate::trace::{JobTrace, TraceSettings};

/// gitlab-runner's `ExitCodeUnsupportedOptions`.
const EXIT_CODE_UNSUPPORTED_OPTIONS: i32 = 3;
const UNHEALTHY_BACKOFF_INITIAL: Duration = Duration::from_secs(30);

const ANSI_BOLD_RED: &str = "\x1b[31;1m";
const ANSI_RESET: &str = "\x1b[0;m";

/// An error line as gitlab-runner's build logger writes one.
fn error_line(msg: &str) -> String {
    format!("{ANSI_BOLD_RED}ERROR: {msg}{ANSI_RESET}\n")
}

/// A hub `request_id`: 16 random bytes, hex.
fn new_request_id() -> String {
    hex(&random_bytes::<16>())
}

/// Stops the poll loop. Dropping it aborts the loop and its running jobs, as
/// [`abort`](Self::abort) does.
#[derive(Debug)]
pub struct ShutdownHandle {
    stop: watch::Sender<bool>,
    abort: watch::Sender<bool>,
}

/// What the loop and its jobs watch.
#[derive(Debug, Clone)]
pub struct Shutdown {
    stop: watch::Receiver<bool>,
    abort: watch::Receiver<bool>,
}

impl ShutdownHandle {
    pub fn new() -> (Self, Shutdown) {
        let (stop_tx, stop) = watch::channel(false);
        let (abort_tx, abort) = watch::channel(false);
        (
            Self {
                stop: stop_tx,
                abort: abort_tx,
            },
            Shutdown { stop, abort },
        )
    }

    /// Requests no more jobs; running jobs carry on.
    pub fn stop(&self) {
        self.stop.send_replace(true);
    }

    /// Requests no more jobs and aborts the running ones, reporting them as interrupted.
    pub fn abort(&self) {
        self.stop.send_replace(true);
        self.abort.send_replace(true);
    }
}

async fn wait_true(rx: &mut watch::Receiver<bool>) {
    // A dropped sender means the handle is gone: treat it as set.
    let _ = rx.wait_for(|v| *v).await;
}

impl Shutdown {
    fn stopping(&self) -> bool {
        *self.stop.borrow()
    }
}

/// The hub-side timings of virtkit's `docs/gitlab-dispatch.md`; the defaults are the
/// contract's.
#[derive(Debug, Clone)]
pub struct HubTimings {
    /// A reservation's lease, renewed every third of it while a job request is out.
    pub lease: Duration,
    /// The longest a capacity, reservation, job-view or output long poll is held.
    pub wait: Duration,
    /// How long the hub may take to place a job whose reservation was lost.
    pub place_within: Duration,
    /// The pause after a hub call failed without saying when to retry.
    pub retry_pause: Duration,
    /// How long a job aborted by GitLab, or by the runner's shutdown, is followed until the
    /// hub reports it ended.
    pub settle_wait: Duration,
}

impl Default for HubTimings {
    fn default() -> Self {
        Self {
            lease: Duration::from_secs(90),
            wait: Duration::from_secs(60),
            place_within: Duration::from_secs(300),
            retry_pause: Duration::from_secs(1),
            settle_wait: Duration::from_secs(300),
        }
    }
}

/// Settings of the loop that are not in the configuration file.
#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    /// Base timings of each job's log reporter; the runner's retry limit overrides its.
    pub trace: TraceSettings,
    pub retry: RetryPolicy,
    pub hub: HubTimings,
}

/// Port of gitlab-runner's `healthHelper`, for one runner.
struct Health {
    failures: u32,
    limit: u32,
    interval: Duration,
    backoff: Backoff,
    disabled_until: Option<Instant>,
}

impl Health {
    fn new(cfg: &RunnerConfig) -> Self {
        let interval = cfg.unhealthy_interval();
        Self {
            failures: 0,
            limit: cfg.unhealthy_requests_limit(),
            interval,
            backoff: Backoff::new(UNHEALTHY_BACKOFF_INITIAL, interval, 2.0, true),
            disabled_until: None,
        }
    }

    /// `None` when the runner may request now, else how long to wait.
    fn check(&mut self, runner: &str) -> Option<Duration> {
        if self.failures < self.limit || self.interval.is_zero() {
            return None;
        }
        if let Some(until) = self.disabled_until {
            let now = Instant::now();
            if now < until {
                return Some(until - now);
            }
        }
        log::warn!(
            runner = runner,
            unhealthy_requests = self.failures,
            unhealthy_requests_limit = self.limit,
            unhealthy_attempt = self.backoff.attempt();
            "Runner is not healthy, but check for a new job will be forced!"
        );
        self.failures = self.limit.saturating_sub(1);
        None
    }

    fn mark(&mut self, healthy: bool, runner: &str) {
        if healthy {
            self.failures = 0;
            self.backoff.reset();
            self.disabled_until = None;
            return;
        }
        self.failures = self.failures.saturating_add(1);
        let now = Instant::now();
        if self.failures < self.limit || self.disabled_until.is_some_and(|u| now < u) {
            return;
        }
        if self.interval.is_zero() {
            return;
        }
        let pause = self.backoff.next_delay();
        self.disabled_until = Some(now + pause);
        log::warn!(
            runner = runner,
            unhealthy_requests = self.failures,
            unhealthy_requests_limit = self.limit,
            disabled_for_s = pause.as_secs_f64();
            "Runner is not healthy and will be disabled for a while"
        );
    }
}

/// State shared by every runner.
struct Shared<D> {
    dispatcher: Arc<D>,
    concurrent: Arc<Semaphore>,
    /// Signalled when a job ends, freeing a slot.
    job_done: Notify,
    running_jobs: AtomicUsize,
    shutdown: Shutdown,
    options: RunOptions,
}

struct Runner {
    cfg: RunnerConfig,
    client: Arc<GitLabClient>,
    check_interval: Duration,
    limit: Option<Arc<Semaphore>>,
    health: Mutex<Health>,
    /// When the next request may start: the runner's share of `check_interval`.
    next_poll: Mutex<Instant>,
}

impl Runner {
    /// Claims the next request start; returns how long to wait for it.
    fn claim_poll(&self) -> Duration {
        let now = Instant::now();
        let Ok(mut next) = self.next_poll.lock() else {
            return self.check_interval;
        };
        let start = (*next).max(now);
        *next = start + self.check_interval;
        start - now
    }

    /// Lets the next request start at once.
    fn poll_now(&self) {
        if let Ok(mut next) = self.next_poll.lock() {
            *next = Instant::now();
        }
    }
}

/// The runner's identity as sent to GitLab.
pub fn runner_info() -> Info {
    Info::this_runner()
}

/// Builds the API client for one configured runner.
pub fn client_for(
    cfg: &RunnerConfig,
    system_id: &str,
    info: Info,
    retry: RetryPolicy,
) -> Result<GitLabClient> {
    GitLabClient::new(ClientOptions {
        url: cfg.url.clone(),
        token: cfg.token().clone(),
        tls_ca_file: cfg.tls_ca_file.clone(),
        tls_cert_file: cfg.tls_cert_file.clone(),
        tls_key_file: cfg.tls_key_file.clone(),
        system_id: system_id.to_owned(),
        info,
        retry,
    })
    .with_context(|| format!("runner {:?}", cfg.name))
}

/// Polls every configured runner until `shutdown` stops it and the running jobs end.
pub async fn run<D: Dispatcher>(
    config: &Config,
    system_id: &str,
    dispatcher: Arc<D>,
    options: RunOptions,
    shutdown: Shutdown,
) -> Result<()> {
    let shared = Arc::new(Shared {
        dispatcher,
        concurrent: Arc::new(Semaphore::new(config.concurrent)),
        job_done: Notify::new(),
        running_jobs: AtomicUsize::new(0),
        shutdown,
        options,
    });
    // Every runner is built before any loop starts: a bad one fails the whole run.
    let runners = config
        .runners
        .iter()
        .map(|cfg| {
            let client = client_for(cfg, system_id, runner_info(), shared.options.retry.clone())?;
            Ok(Arc::new(Runner {
                cfg: cfg.clone(),
                client: Arc::new(client),
                check_interval: config.runner_check_interval(cfg),
                limit: (cfg.limit > 0).then(|| Arc::new(Semaphore::new(cfg.limit))),
                health: Mutex::new(Health::new(cfg)),
                next_poll: Mutex::new(Instant::now()),
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut workers = tokio::task::JoinSet::new();
    for runner in runners {
        let cfg = &runner.cfg;
        log::info!(
            runner = cfg.name.as_str(),
            token = cfg.token().short().as_str(),
            pool = cfg.pool.as_str(),
            url = cfg.url.as_str(),
            request_concurrency = cfg.request_concurrency();
            "Starting runner"
        );
        for _ in 0..cfg.request_concurrency() {
            workers.spawn(request_loop(Arc::clone(&shared), Arc::clone(&runner)));
        }
    }
    while workers.join_next().await.is_some() {}
    log::info!(jobs = shared.running_jobs.load(Ordering::SeqCst); "Stopped requesting jobs; waiting for running jobs");
    loop {
        let done = shared.job_done.notified();
        if shared.running_jobs.load(Ordering::SeqCst) == 0 {
            break;
        }
        done.await;
    }
    Ok(())
}

/// The slots a job holds while it runs.
struct Slots {
    _concurrent: OwnedSemaphorePermit,
    _limit: Option<OwnedSemaphorePermit>,
}

/// Whether a slot is free now; [`acquire_slots`] decides.
fn slots_free<D>(shared: &Shared<D>, runner: &Runner) -> bool {
    shared.concurrent.available_permits() > 0
        && runner
            .limit
            .as_ref()
            .is_none_or(|sem| sem.available_permits() > 0)
}

/// A running job: its slots, and its count in `running_jobs`. Dropped when the job's task
/// ends, panicking or not, so shutdown never waits on a job that is gone.
struct RunningJob<D> {
    shared: Arc<Shared<D>>,
    _slots: Slots,
}

impl<D> RunningJob<D> {
    fn new(shared: Arc<Shared<D>>, slots: Slots) -> Self {
        shared.running_jobs.fetch_add(1, Ordering::SeqCst);
        Self {
            shared,
            _slots: slots,
        }
    }
}

impl<D> Drop for RunningJob<D> {
    fn drop(&mut self) {
        self.shared.running_jobs.fetch_sub(1, Ordering::SeqCst);
        self.shared.job_done.notify_waiters();
    }
}

fn acquire_slots<D>(shared: &Shared<D>, runner: &Runner) -> Option<Slots> {
    let limit = match &runner.limit {
        Some(sem) => Some(Arc::clone(sem).try_acquire_owned().ok()?),
        None => None,
    };
    let concurrent = Arc::clone(&shared.concurrent).try_acquire_owned().ok()?;
    Some(Slots {
        _concurrent: concurrent,
        _limit: limit,
    })
}

/// A reservation the loop holds, and when its lease was last (re)started — counted from
/// when the request was sent, so the loop always believes the lease ends before the node
/// does.
struct Held {
    reservation: Reservation,
    since: Instant,
    /// When to try again after a failed renewal; the lease still counts from `since`.
    retry_at: Option<Instant>,
}

impl Held {
    fn renew_at(&self) -> Instant {
        self.retry_at
            .unwrap_or(self.since + self.reservation.lease / 3)
    }

    fn expired(&self) -> bool {
        Instant::now() >= self.since + self.reservation.lease
    }
}

/// Runs `fut` to completion, renewing `held`'s lease every third of it meanwhile. A lease
/// the hub reports gone, or one that ran out, leaves `held` empty; `fut` is never cut short.
async fn keep_alive<D: Dispatcher, F: Future>(
    shared: &Shared<D>,
    runner: &str,
    held: &mut Option<Held>,
    fut: F,
) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    loop {
        let due = held.as_ref().map(Held::renew_at);
        tokio::select! {
            out = &mut fut => return out,
            () = sleep_until(due) => {
                let Some(h) = held.as_mut() else { continue };
                let sent = Instant::now();
                match shared.dispatcher.renew(&h.reservation.id, shared.options.hub.lease).await {
                    Ok(lease) => {
                        h.reservation.lease = lease;
                        h.since = sent;
                        h.retry_at = None;
                    }
                    Err(e) if e.kind == ErrorKind::ReservationGone => {
                        log::warn!(runner = runner, reservation = h.reservation.id.as_str(); "Reservation gone");
                        *held = None;
                    }
                    Err(e) => {
                        log::warn!(runner = runner, reservation = h.reservation.id.as_str(), error = e.to_string().as_str(); "Renewing the reservation failed");
                        if h.expired() {
                            *held = None;
                        } else {
                            let lease_end = h.since + h.reservation.lease;
                            h.retry_at =
                                Some((Instant::now() + shared.options.hub.retry_pause).min(lease_end));
                        }
                    }
                }
            }
        }
    }
}

async fn release<D: Dispatcher>(shared: &Shared<D>, held: Option<Held>) {
    if let Some(h) = held
        && let Err(e) = shared.dispatcher.release(&h.reservation.id).await
    {
        log::warn!(reservation = h.reservation.id.as_str(), error = e.to_string().as_str(); "Releasing the reservation failed");
    }
}

fn pause_for(e: &DispatchError, fallback: Duration) -> Duration {
    e.retry_after.unwrap_or(fallback)
}

async fn request_loop<D: Dispatcher>(shared: Arc<Shared<D>>, runner: Arc<Runner>) {
    let mut stop = shared.shutdown.stop.clone();
    let name = runner.cfg.name.clone();
    let placement = runner.cfg.placement();
    let hub = shared.options.hub.clone();
    let mut capacity_revision: Option<u64> = None;
    loop {
        if shared.shutdown.stopping() {
            return;
        }
        let health_wait = runner.health.lock().ok().and_then(|mut h| h.check(&name));
        if let Some(wait) = health_wait {
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = wait_true(&mut stop) => return,
            }
            continue;
        }
        // A free slot first: a loop waiting for one asks neither the hub nor GitLab.
        let job_done = shared.job_done.notified();
        if !slots_free(&shared, &runner) {
            log::debug!(runner = name.as_str(); "No free slot; not requesting a job");
            tokio::select! {
                () = tokio::time::sleep(runner.check_interval) => {}
                () = job_done => {}
                () = wait_true(&mut stop) => return,
            }
            continue;
        }
        drop(job_done);
        let pace = runner.claim_poll();
        if !pace.is_zero() {
            tokio::select! {
                () = tokio::time::sleep(pace) => {}
                () = wait_true(&mut stop) => return,
            }
        }
        // Then capacity: while the hub reports no room, GitLab is not asked, and the job
        // stays pending for another runner.
        let capacity = tokio::select! {
            c = shared.dispatcher.capacity(&placement, capacity_revision, hub.wait) => c,
            () = wait_true(&mut stop) => return,
        };
        match capacity {
            Ok(c) => {
                capacity_revision = Some(c.revision);
                if c.fits == 0 {
                    continue;
                }
            }
            Err(e) => {
                log::warn!(runner = name.as_str(), error = e.to_string().as_str(); "Asking the hub for capacity failed");
                capacity_revision = None;
                tokio::select! {
                    () = tokio::time::sleep(pause_for(&e, runner.check_interval)) => {}
                    () = wait_true(&mut stop) => return,
                }
                continue;
            }
        }
        // Then a reservation.
        let sent = Instant::now();
        let request_id = new_request_id();
        let reserved = tokio::select! {
            r = shared.dispatcher.reserve(&request_id, &placement, hub.lease, hub.wait) => r,
            () = wait_true(&mut stop) => return,
        };
        let mut held = match reserved {
            Ok(reservation) => {
                log::debug!(runner = name.as_str(), reservation = reservation.id.as_str(), node = reservation.node.as_str(); "Reserved an envelope");
                Some(Held {
                    reservation,
                    since: sent,
                    retry_at: None,
                })
            }
            Err(e) => {
                log::info!(runner = name.as_str(), error = e.to_string().as_str(); "No reservation");
                capacity_revision = None;
                tokio::select! {
                    () = tokio::time::sleep(pause_for(&e, runner.check_interval)) => {}
                    () = wait_true(&mut stop) => return,
                }
                continue;
            }
        };
        // Then the slot, which another loop may have taken meanwhile.
        let Some(slots) = acquire_slots(&shared, &runner) else {
            release(&shared, held).await;
            capacity_revision = None;
            continue;
        };
        if shared.shutdown.stopping() {
            release(&shared, held).await;
            return;
        }
        // Then the job request, under the reservation. Never aborted: GitLab may already
        // have assigned the job.
        let result = keep_alive(&shared, &name, &mut held, runner.client.request_job()).await;
        if let Ok(mut h) = runner.health.lock() {
            h.mark(result.healthy, &name);
        }
        capacity_revision = None;
        let Some(job) = result.job else {
            // Nothing to do: the slot and the reservation go back until the next request.
            drop(slots);
            release(&shared, held).await;
            continue;
        };
        let reservation = held
            .take()
            .filter(|h| !h.expired())
            .map(|h| h.reservation.id);
        let running = RunningJob::new(Arc::clone(&shared), slots);
        let runner2 = Arc::clone(&runner);
        tokio::spawn(async move {
            run_job(&running.shared, &runner2, job, reservation).await;
            drop(running);
        });
        if !runner.cfg.strict_check_interval {
            runner.poll_now();
        }
    }
}

/// Fails a job that was never committed: nothing ran, the trace holds only `msg`.
async fn fail_uncommitted(
    runner: &Runner,
    trace_settings: &TraceSettings,
    creds: &JobCredentials,
    mapper: FailureReasonMapper,
    msg: &str,
    reason: FailureReason,
    exit_code: i32,
) {
    log::error!(runner = runner.cfg.name.as_str(), job = creds.id, error = msg; "Failing the job");
    let trace = JobTrace::start(
        Arc::clone(&runner.client),
        creds.clone(),
        Some(mapper),
        trace_settings.clone(),
    );
    trace.write(error_line(msg).as_bytes());
    if let Err(e) = trace.fail(reason, exit_code).await {
        log::error!(job = creds.id, error = e.to_string().as_str(); "Could not report the job's final state");
    }
}

/// Why the job cannot run on the fleet, before it is submitted.
fn refusal(job: &Job) -> Option<(String, FailureReason, i32)> {
    if let Some(msg) = job.unsupported_options() {
        // gitlab-runner's own check and outcome for executor options it does not know.
        return Some((
            msg,
            FailureReason::runner_system_failure(),
            EXIT_CODE_UNSUPPORTED_OPTIONS,
        ));
    }
    let configuration = FailureReason::new(FailureReason::CONFIGURATION_ERROR);
    if !job.secrets.is_empty() {
        return Some((
            "Job failed: external secrets are not supported by this runner".to_owned(),
            configuration,
            0,
        ));
    }
    if job.run.is_some() {
        return Some((
            "Job failed: the `run` keyword (CI steps) is not supported by this runner".to_owned(),
            configuration,
            0,
        ));
    }
    None
}

/// What became of a submitted job once it is accepted or over.
enum Placed {
    Accepted(JobView),
    /// Ended before a node accepted it (not placed in time, or the hub lost it).
    Unplaced(JobView),
    Interrupted,
}

/// Follows a submitted job until a node accepts it or it ends. The hub ends a job it could
/// not place within `place_within`; a hub that says nothing for that long and one more
/// `wait` leaves the job unplaced.
async fn wait_until_placed<D: Dispatcher>(shared: &Shared<D>, mut view: JobView) -> Placed {
    let mut abort = shared.shutdown.abort.clone();
    let hub = &shared.options.hub;
    let deadline = Instant::now() + hub.place_within + hub.wait;
    loop {
        match view.state {
            HubJobState::Running => return Placed::Accepted(view),
            HubJobState::Finished => {
                // Without output or a result, nothing is known to have run.
                let ran = view.output_len > 0
                    || view.result.as_ref().is_some_and(|r| {
                        !matches!(
                            r.failure,
                            Some(FailureClass::NoCapacity | FailureClass::Lost)
                        )
                    });
                return if ran {
                    Placed::Accepted(view)
                } else {
                    Placed::Unplaced(view)
                };
            }
            HubJobState::Queued | HubJobState::Starting => {}
        }
        if Instant::now() >= deadline {
            log::error!(job = view.id.as_str(); "The hub did not report the job placed in time");
            let _ = shared
                .dispatcher
                .cancel(&view.id, CancelMode::Immediate)
                .await;
            view.state = HubJobState::Finished;
            view.result = Some(JobResult {
                failure: Some(FailureClass::Lost),
                exit_code: None,
                message: Some("the hub did not report it placed in time".to_owned()),
                output_len: 0,
            });
            continue;
        }
        let next = tokio::select! {
            v = shared.dispatcher.job(&view.id, Some(view.revision), hub.wait) => v,
            () = tokio::time::sleep_until(deadline) => continue,
            () = wait_true(&mut abort) => return Placed::Interrupted,
        };
        match next {
            Ok(v) => view = v,
            Err(e) if e.kind == ErrorKind::NotFound => {
                view.state = HubJobState::Finished;
                view.result = Some(JobResult {
                    failure: Some(FailureClass::Lost),
                    exit_code: None,
                    message: Some(e.message),
                    output_len: 0,
                });
            }
            Err(e) => {
                log::warn!(job = view.id.as_str(), error = e.to_string().as_str(); "Reading the job from the hub failed");
                tokio::select! {
                    () = tokio::time::sleep(pause_for(&e, hub.retry_pause)) => {}
                    () = wait_true(&mut abort) => return Placed::Interrupted,
                }
            }
        }
    }
}

/// Copies output from the hub into the trace until the hub reports it complete.
/// The read offset tracks the hub's output, even beyond the trace's ceiling.
async fn pump_output<D: Dispatcher>(
    shared: &Shared<D>,
    id: &str,
    trace: &JobTrace<GitLabClient>,
) -> Result<(), DispatchError> {
    let hub = &shared.options.hub;
    let mut offset = trace.len() as u64;
    loop {
        match shared.dispatcher.output(id, offset, hub.wait).await {
            Ok(chunk) => {
                if chunk.offset > offset {
                    return Err(DispatchError::new(
                        ErrorKind::Other,
                        format!("the output skipped from {offset} to {}", chunk.offset),
                    ));
                }
                let end = chunk.offset.saturating_add(chunk.data.len() as u64);
                if end < offset {
                    return Err(DispatchError::new(
                        ErrorKind::Other,
                        format!("the output ends at {end}, before {offset}"),
                    ));
                }
                // Bytes before our offset were copied already.
                let skip = usize::try_from(offset - chunk.offset).unwrap_or(usize::MAX);
                let new = chunk.data.get(skip..).unwrap_or_default();
                trace.write(new);
                offset = end;
                if chunk.complete {
                    return Ok(());
                }
            }
            // The output is shorter than what was copied: it cannot be followed any more.
            Err(e) if matches!(e.kind, ErrorKind::NotFound | ErrorKind::OutputRange { .. }) => {
                return Err(e);
            }
            Err(e) => {
                log::warn!(job = id, offset = offset, error = e.to_string().as_str(); "Reading the job's output failed");
                tokio::time::sleep(pause_for(&e, hub.retry_pause)).await;
            }
        }
    }
}

async fn settle<D: Dispatcher>(shared: &Shared<D>, id: &str) {
    if let Err(e) = shared.dispatcher.settle(id).await {
        log::warn!(job = id, error = e.to_string().as_str(); "Settling the job with the hub failed");
    }
}

/// Follows a job GitLab ended until the hub reports it over, then settles it.
async fn settle_when_over<D: Dispatcher>(shared: &Shared<D>, mut view: JobView) {
    let hub = &shared.options.hub;
    let deadline = Instant::now() + hub.settle_wait;
    while view.state != HubJobState::Finished && Instant::now() < deadline {
        match shared
            .dispatcher
            .job(&view.id, Some(view.revision), hub.wait)
            .await
        {
            Ok(v) => view = v,
            Err(e) if e.kind == ErrorKind::NotFound => return,
            Err(e) => tokio::time::sleep(pause_for(&e, hub.retry_pause)).await,
        }
    }
    settle(shared, &view.id).await;
}

/// Everything between receiving a job and settling it with the hub.
async fn run_job<D: Dispatcher>(
    shared: &Shared<D>,
    runner: &Runner,
    job: Box<Job>,
    reservation: Option<String>,
) {
    let job: Arc<Job> = Arc::from(job);
    let creds = JobCredentials {
        id: job.id,
        token: job.token.clone(),
    };
    let mapper = FailureReasonMapper::new(&job.features.failure_reasons);
    let trace_settings = TraceSettings {
        output_limit: runner.cfg.output_limit_bytes(),
        final_update_retry_limit: runner.cfg.final_update_retry_limit(),
        debug_trace: job.debug_mode_enabled(),
        ..shared.options.trace.clone()
    };
    log::info!(
        runner = runner.cfg.name.as_str(),
        runner_uuid = job.runner_info.uuid.as_str(),
        job = job.id,
        pipeline_id = job.job_info.pipeline_id,
        project = job.job_info.project_id,
        project_full_path = job.job_info.project_full_path.as_str(),
        repo_url = job.repo_clean_url().as_str(),
        time_in_queue_seconds = job.job_info.time_in_queue_seconds,
        reservation = reservation.as_deref().unwrap_or("");
        "Received a job"
    );

    if let Some((msg, reason, exit_code)) = refusal(&job) {
        if let Some(r) = &reservation {
            let _ = shared.dispatcher.release(r).await;
        }
        fail_uncommitted(
            runner,
            &trace_settings,
            &creds,
            mapper,
            &msg,
            reason,
            exit_code,
        )
        .await;
        return;
    }

    let submitted = shared
        .dispatcher
        .submit(Submission {
            request_id: new_request_id(),
            placement: runner.cfg.placement(),
            reservation: reservation.clone(),
            place_within: shared.options.hub.place_within,
            runner: runner.cfg.name.clone(),
            server_url: runner.cfg.url.clone(),
            job: Arc::clone(&job),
        })
        .await;
    let view = match submitted {
        Ok(v) => v,
        Err(e) => {
            if let Some(r) = &reservation {
                let _ = shared.dispatcher.release(r).await;
            }
            let msg = format!(
                "Job failed (system failure): the fleet did not take the job: {}",
                e.message
            );
            fail_uncommitted(
                runner,
                &trace_settings,
                &creds,
                mapper,
                &msg,
                FailureReason::runner_system_failure(),
                0,
            )
            .await;
            return;
        }
    };
    let hub_id = view.id.clone();

    let view = match wait_until_placed(shared, view).await {
        Placed::Accepted(v) => v,
        Placed::Unplaced(v) => {
            let why = v
                .result
                .as_ref()
                .and_then(|r| r.message.clone())
                .unwrap_or_else(|| "no node took it in time".to_owned());
            let msg =
                format!("Job failed (system failure): the fleet could not place the job: {why}");
            fail_uncommitted(
                runner,
                &trace_settings,
                &creds,
                mapper,
                &msg,
                FailureReason::runner_system_failure(),
                0,
            )
            .await;
            settle(shared, &hub_id).await;
            return;
        }
        Placed::Interrupted => {
            let _ = shared
                .dispatcher
                .cancel(&hub_id, CancelMode::Immediate)
                .await;
            fail_uncommitted(
                runner,
                &trace_settings,
                &creds,
                mapper,
                "Job failed: aborted: the runner is shutting down",
                FailureReason::new(FailureReason::RUNNER_INTERRUPTED),
                0,
            )
            .await;
            settle(shared, &hub_id).await;
            return;
        }
    };

    // The commit: the job is ours, and running.
    let update = runner
        .client
        .update_job(&creds, &UpdateJobInfo::new(job.id, JobState::Running))
        .await;
    if update.state == UpdateState::Abort {
        log::warn!(job = job.id, hub_job = hub_id.as_str(); "GitLab refused the job's commit; canceling it");
        let _ = shared
            .dispatcher
            .cancel(&hub_id, CancelMode::Immediate)
            .await;
        settle_when_over(shared, view).await;
        return;
    }
    let mut graceful_sent = false;
    if update.cancel_requested {
        graceful_sent = true;
        let _ = shared
            .dispatcher
            .cancel(&hub_id, CancelMode::Graceful)
            .await;
    }
    log::info!(job = job.id, hub_job = hub_id.as_str(), node = view.node.as_deref().unwrap_or(""); "Job committed");

    let trace = JobTrace::start(
        Arc::clone(&runner.client),
        creds.clone(),
        Some(mapper),
        trace_settings,
    );
    let mut remote = trace.remote_requests();
    let mut abort = shared.shutdown.abort.clone();
    let hub = shared.options.hub.clone();
    let mut view = view;
    let mut interrupted = false;
    let mut aborted_by_gitlab = false;
    let mut remote_open = true;
    let mut output_done = false;
    // When the job's view may be read again, after a failed read.
    let mut view_at = Instant::now();
    // Set on the runner's abort: how long the hub gets to report the job ended.
    let mut abort_deadline: Option<Instant> = None;
    let mut pump = std::pin::pin!(pump_output(shared, &hub_id, &trace));
    loop {
        if output_done && view.state == HubJobState::Finished {
            break;
        }
        tokio::select! {
            r = &mut pump, if !output_done => {
                output_done = true;
                if let Err(e) = r {
                    log::error!(job = job.id, error = e.to_string().as_str(); "The hub lost the job's output");
                    if view.state != HubJobState::Finished
                        && let Err(e) = shared.dispatcher.cancel(&hub_id, CancelMode::Immediate).await
                    {
                        log::warn!(job = job.id, hub_job = hub_id.as_str(), error = e.to_string().as_str(); "Canceling the job failed");
                    }
                    view.state = HubJobState::Finished;
                    view.result.get_or_insert(JobResult {
                        failure: Some(FailureClass::Lost),
                        exit_code: None,
                        message: Some(e.message),
                        output_len: trace.len() as u64,
                    });
                }
            }
            v = async {
                tokio::time::sleep_until(view_at).await;
                shared.dispatcher.job(&hub_id, Some(view.revision), hub.wait).await
            }, if view.state != HubJobState::Finished => {
                match v {
                    Ok(v) => view = v,
                    Err(e) => {
                        log::warn!(job = job.id, error = e.to_string().as_str(); "Reading the job from the hub failed");
                        view_at = Instant::now() + pause_for(&e, hub.retry_pause);
                    }
                }
            }
            changed = remote.changed(), if remote_open => {
                if changed.is_err() {
                    remote_open = false;
                    continue;
                }
                let r = *remote.borrow_and_update();
                if r.abort {
                    aborted_by_gitlab = true;
                    break;
                }
                if r.cancel && !graceful_sent {
                    graceful_sent = true;
                    log::info!(job = job.id; "GitLab requested the job to be canceled");
                    let _ = shared.dispatcher.cancel(&hub_id, CancelMode::Graceful).await;
                }
            }
            () = wait_true(&mut abort), if !interrupted => {
                interrupted = true;
                abort_deadline = Some(Instant::now() + hub.settle_wait);
                let _ = shared.dispatcher.cancel(&hub_id, CancelMode::Immediate).await;
            }
            () = sleep_until(abort_deadline) => {
                log::warn!(job = job.id, hub_job = hub_id.as_str(); "The hub did not report the aborted job ended; reporting it interrupted");
                break;
            }
        }
    }

    if aborted_by_gitlab {
        // GitLab ended the job: stop it now and write nothing more.
        log::warn!(job = job.id; "GitLab ended the job; canceling it");
        let _ = shared
            .dispatcher
            .cancel(&hub_id, CancelMode::Immediate)
            .await;
        trace.finish().await;
        settle_when_over(shared, view).await;
        return;
    }

    let result = view.result.clone().unwrap_or(JobResult {
        failure: Some(FailureClass::Lost),
        exit_code: None,
        message: None,
        output_len: trace.len() as u64,
    });
    let reported = if interrupted {
        trace
            .fail(FailureReason::new(FailureReason::RUNNER_INTERRUPTED), 0)
            .await
    } else {
        match result.failure {
            None => trace.success().await,
            Some(class) => {
                trace
                    .fail(class.gitlab_reason(), result.exit_code.unwrap_or(0))
                    .await
            }
        }
    };
    match reported {
        Ok(()) => settle(shared, &hub_id).await,
        // Not settled: the hub keeps the output for a retry by a restarted daemon.
        Err(e) => {
            log::error!(job = job.id, error = e.to_string().as_str(); "Could not report the job's final state");
        }
    }
    log::info!(job = job.id, runner = runner.cfg.name.as_str(); "Job finished");
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_lines_match_gitlab_runner() {
        assert_eq!(
            error_line("Job failed: exit code 1"),
            "\x1b[31;1mERROR: Job failed: exit code 1\x1b[0;m\n"
        );
    }

    // The behaviour of gitlab-runner's commands/health_helper.go: unhealthy after the
    // limit, a forced check once the pause is over.
    #[tokio::test(start_paused = true)]
    async fn health_disables_then_forces_a_check() {
        let cfg: RunnerConfig = {
            let c = Config::parse(
                "[[runners]]\nurl = \"https://g\"\ntoken = \"t\"\nunhealthy_interval = 120\n",
                std::path::Path::new("/"),
            )
            .unwrap();
            c.runners[0].clone()
        };
        let mut h = Health::new(&cfg);
        for _ in 0..2 {
            h.mark(false, "r");
            assert!(h.check("r").is_none());
        }
        h.mark(false, "r");
        let wait = h.check("r").expect("disabled after three failures");
        assert!(
            wait >= Duration::from_secs(30) && wait <= Duration::from_secs(120),
            "{wait:?}"
        );
        tokio::time::advance(wait).await;
        assert!(
            h.check("r").is_none(),
            "a check is forced once the pause is over"
        );
        assert_eq!(h.failures, 2);
        h.mark(true, "r");
        assert_eq!(h.failures, 0);
        assert!(h.disabled_until.is_none());
    }
}
