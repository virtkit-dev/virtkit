//! The poll loop: per configured runner, take jobs from GitLab only once the fleet has room
//! for them, hand them to the hub, and report their output and outcome back. The order is
//! `docs/gitlab-dispatch.md`, "Job flow"; the GitLab side is a port of the
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
//!
//! Each job is recorded in its runner's state file from the moment it is taken until it is
//! settled. On start, the recorded jobs of every runner resume before any runner requests a
//! job: they run whether or not `concurrent` and `limit` leave them a slot, and new requests
//! wait until they do.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
    JobSpec, JobView, Reservation, Submission,
};
use crate::failure::{FailureReason, FailureReasonMapper, JobState};
use crate::job::Job;
use crate::secret::Secret;
use crate::spec::{self, SpecContext};
use crate::state::{JobRecord, Phase, StateFile};
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

/// The hub-side timings of `docs/gitlab-dispatch.md`, as vk-gitlab sets them.
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
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// Base timings of each job's log reporter; the runner's retry limit overrides its.
    pub trace: TraceSettings,
    pub retry: RetryPolicy,
    pub hub: HubTimings,
    /// How often a running job's acknowledged trace offset is written to the state file at
    /// most; a resumed job whose offset lags is corrected by GitLab's 416.
    pub trace_offset_interval: Duration,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            trace: TraceSettings::default(),
            retry: RetryPolicy::default(),
            hub: HubTimings::default(),
            trace_offset_interval: Duration::from_secs(10),
        }
    }
}

/// The longest pause between retries of a hub call that keeps failing.
const HUB_ERROR_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Paces the retries of a hub call that keeps failing: the hub's `retry_after`, else a
/// backoff from `retry_pause` up to [`HUB_ERROR_BACKOFF_MAX`]. A refused API key is an
/// error, not a warning: nothing works until it is replaced.
struct HubErrors {
    backoff: Backoff,
}

impl HubErrors {
    fn new(hub: &HubTimings) -> Self {
        Self {
            backoff: Backoff::new(
                hub.retry_pause,
                HUB_ERROR_BACKOFF_MAX.max(hub.retry_pause),
                2.0,
                true,
            ),
        }
    }

    fn ok(&mut self) {
        self.backoff.reset();
    }

    /// Logs `e` and returns how long to wait before trying again.
    fn failed(&mut self, hub_job: &str, what: &str, e: &DispatchError) -> Duration {
        if matches!(e.kind, ErrorKind::Unauthorized | ErrorKind::Forbidden) {
            log::error!(hub_job = hub_job, error = e.to_string().as_str(); "{what} failed: the hub refuses the API key");
        } else {
            log::warn!(hub_job = hub_job, error = e.to_string().as_str(); "{what} failed");
        }
        e.retry_after.unwrap_or_else(|| self.backoff.next_delay())
    }
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

impl<D> Shared<D> {
    /// Runs a hub call to its end, or, once the runner aborts its jobs, for at most
    /// `settle_wait` more: a hub that does not answer must not hold the shutdown up.
    async fn bounded<T>(
        &self,
        call: impl Future<Output = Result<T, DispatchError>>,
    ) -> Result<T, DispatchError> {
        let mut call = std::pin::pin!(call);
        let mut abort = self.shutdown.abort.clone();
        tokio::select! {
            r = &mut call => return r,
            () = wait_true(&mut abort) => {}
        }
        tokio::time::timeout(self.options.hub.settle_wait, call)
            .await
            .unwrap_or_else(|_| {
                Err(DispatchError::new(
                    ErrorKind::Transport,
                    "the hub did not answer before the shutdown deadline",
                ))
            })
    }
}

struct Runner {
    cfg: RunnerConfig,
    client: Arc<GitLabClient>,
    check_interval: Duration,
    limit: Option<Arc<Semaphore>>,
    health: Mutex<Health>,
    /// When the next request may start: the runner's share of `check_interval`.
    next_poll: Mutex<Instant>,
    /// The jobs this runner has taken and not yet settled.
    state: Arc<StateFile>,
    /// The runner ID `/runners/verify` returned (the spec's `job.runner_id`).
    runner_id: AtomicU64,
    /// The CA bundle GitLab is verified against, passed to jobs (`CI_SERVER_TLS_CA_FILE`).
    server_ca_pem: Option<String>,
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

    /// Checks the token with GitLab (`/runners/verify`), recording the runner's ID and
    /// warning ahead of the token's expiry.
    async fn verify(&self) -> Verified {
        let name = self.cfg.name.as_str();
        match self.client.verify().await {
            Ok(Some(v)) => {
                self.runner_id
                    .store(u64::try_from(v.id).unwrap_or(0), Ordering::Relaxed);
                if let Some(at) = &v.token_expires_at {
                    warn_token_expiry(name, at, std::time::SystemTime::now());
                }
                Verified::Valid
            }
            Ok(None) => Verified::Refused,
            Err(e) => {
                log::warn!(runner = name, error = e.to_string().as_str(); "Verifying the runner failed; trying again with its next job");
                Verified::Unknown
            }
        }
    }

    /// The runner ID for a job's spec (`CI_RUNNER_ID`); verified again while unknown, and 0
    /// if it still is.
    async fn runner_id(&self) -> u64 {
        match self.runner_id.load(Ordering::Relaxed) {
            0 => {
                self.verify().await;
                self.runner_id.load(Ordering::Relaxed)
            }
            id => id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verified {
    Valid,
    Refused,
    Unknown,
}

/// How long ahead of a runner token's expiry vk-gitlab starts warning about it.
const TOKEN_EXPIRY_WARNING: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// How often a running runner's token is verified again, for the expiry warning.
const REVERIFY_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Verifies the runner's token every [`REVERIFY_INTERVAL`] until the loop stops.
async fn reverify<D>(shared: Arc<Shared<D>>, runner: Arc<Runner>) {
    let mut stop = shared.shutdown.stop.clone();
    loop {
        tokio::select! {
            () = tokio::time::sleep(REVERIFY_INTERVAL) => {}
            () = wait_true(&mut stop) => return,
        }
        if runner.verify().await == Verified::Refused {
            log::error!(runner = runner.cfg.name.as_str(); "GitLab refuses the runner's token");
        }
    }
}

/// Warns when the runner token expires within [`TOKEN_EXPIRY_WARNING`] or has expired:
/// vk-gitlab does not rotate tokens, and GitLab refuses an expired one. `at` is GitLab's
/// `token_expires_at` (RFC 3339, UTC); GitLab sends year 1 for a token that never expires.
fn warn_token_expiry(runner: &str, at: &str, now: std::time::SystemTime) {
    let Some(expires) = parse_utc(at) else {
        return;
    };
    let Ok(now) = now.duration_since(std::time::UNIX_EPOCH) else {
        return;
    };
    let now = now.as_secs() as i64;
    if expires <= now {
        log::error!(runner = runner, token_expires_at = at; "The runner token has expired; replace it");
    } else if expires - now <= TOKEN_EXPIRY_WARNING.as_secs() as i64 {
        log::warn!(runner = runner, token_expires_at = at; "The runner token expires soon; replace it before then");
    }
}

/// Seconds since the Unix epoch of an RFC 3339 UTC time (`2026-10-16T13:25:59Z`, fractions
/// ignored); `None` for anything else, and for year 1 and earlier.
fn parse_utc(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' {
        return None;
    }
    if b[16] != b':' || !s.ends_with('Z') {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hh, mm, ss) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if y <= 1 || !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // Howard Hinnant's days_from_civil.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
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
    let state_dir = config
        .state_dir
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from(crate::config::DEFAULT_STATE_DIR));
    let hub_key = config
        .hub
        .as_ref()
        .map(|h| crate::state::key_fingerprint(h.api_key().expose()));
    // Every runner is built before any loop starts: a bad one fails the whole run.
    let mut runners = Vec::with_capacity(config.runners.len());
    for cfg in &config.runners {
        let client = client_for(cfg, system_id, runner_info(), shared.options.retry.clone())?;
        let state = StateFile::open(&state_dir.join(format!("{}.json", cfg.name)))?;
        check_hub_key(&state, hub_key.as_deref())?;
        let server_ca_pem = match &cfg.tls_ca_file {
            Some(f) => Some(
                std::fs::read_to_string(f)
                    .with_context(|| format!("runner {:?}: reading {}", cfg.name, f.display()))?,
            ),
            None => None,
        };
        runners.push(Arc::new(Runner {
            cfg: cfg.clone(),
            client: Arc::new(client),
            check_interval: config.runner_check_interval(cfg),
            limit: (cfg.limit > 0).then(|| Arc::new(Semaphore::new(cfg.limit))),
            health: Mutex::new(Health::new(cfg)),
            next_poll: Mutex::new(Instant::now()),
            state: Arc::new(state),
            runner_id: AtomicU64::new(0),
            server_ca_pem,
        }));
    }
    warn_unowned_state_files(&state_dir, &config.runners);
    // Jobs from before a restart come first, every runner's: they are taken already, and
    // hold their slots ahead of any new request.
    let mut requesting = Vec::with_capacity(runners.len());
    for runner in runners {
        let name = runner.cfg.name.as_str();
        // A refused token stops the runner's requests; any other failure is retried with its
        // first job. Its recorded jobs resume either way: their job tokens are their own.
        let refused = runner.verify().await == Verified::Refused;
        if refused {
            log::error!(runner = name; "GitLab refuses the runner's token; the runner requests no jobs");
        }
        for rec in runner.state.records() {
            log::info!(runner = name, job = rec.gitlab_job, phase = format!("{:?}", rec.phase).as_str(); "Resuming a job from the state file");
            let mut running = RunningJob::new(Arc::clone(&shared), acquire_slots(&shared, &runner));
            let (shared2, runner2) = (Arc::clone(&shared), Arc::clone(&runner));
            tokio::spawn(async move {
                let resumed = drive(&shared2, &runner2, rec, true);
                running.hold_slots_while(&runner2, resumed).await;
            });
        }
        if !refused {
            requesting.push(runner);
        }
    }
    let mut workers = tokio::task::JoinSet::new();
    for runner in requesting {
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
        workers.spawn(reverify(Arc::clone(&shared), runner));
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

/// Refuses a state file whose jobs were submitted with another hub API key: the hub scopes
/// jobs to the key that submitted them, so this one could neither follow nor settle them.
/// Without jobs, or without a key recorded, the file takes this key.
fn check_hub_key(state: &StateFile, fingerprint: Option<&str>) -> Result<()> {
    let Some(fingerprint) = fingerprint else {
        return Ok(());
    };
    let jobs = state.records().len();
    match state.hub_key() {
        Some(k) if k == fingerprint => Ok(()),
        Some(_) if jobs > 0 => anyhow::bail!(
            "{}: {jobs} job(s) were submitted with another hub API key, which this one cannot \
             reach. Run with the previous key until they end (stop the daemon with SIGTERM and \
             let it drain), or remove the file to give them up: GitLab then times them out, \
             and their hub jobs stay unsettled",
            state.path().display()
        ),
        _ => state.set_hub_key(fingerprint.to_owned()),
    }
}

/// Warns about state files no configured runner owns: their jobs are not resumed. A runner
/// without a `name` is named after its token, so a new token orphans its file.
fn warn_unowned_state_files(dir: &std::path::Path, runners: &[RunnerConfig]) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let file = entry.file_name();
        let Some(name) = file.to_str().and_then(|f| f.strip_suffix(".json")) else {
            continue;
        };
        if name.starts_with('.') || runners.iter().any(|r| r.name == name) {
            continue;
        }
        log::warn!(state_file = entry.path().display().to_string().as_str(); "No configured runner owns this state file; its jobs are not resumed (a runner renamed, or named after a token that changed?)");
    }
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
    slots: Option<Slots>,
}

impl<D> RunningJob<D> {
    fn new(shared: Arc<Shared<D>>, slots: Option<Slots>) -> Self {
        shared.running_jobs.fetch_add(1, Ordering::SeqCst);
        Self { shared, slots }
    }

    /// Runs a resumed job immediately and acquires its slots when available. Pending
    /// acquisitions take priority over new requests, restoring `concurrent` and `limit`
    /// as jobs end.
    async fn hold_slots_while(&mut self, runner: &Runner, job: impl Future<Output = ()>) {
        let mut job = std::pin::pin!(job);
        if self.slots.is_none() {
            tokio::select! {
                () = &mut job => return,
                slots = wait_slots(&self.shared, runner) => self.slots = slots,
            }
        }
        job.await;
    }
}

impl<D> Drop for RunningJob<D> {
    fn drop(&mut self) {
        self.shared.running_jobs.fetch_sub(1, Ordering::SeqCst);
        self.shared.job_done.notify_waiters();
    }
}

/// Waits for a job's slots, in line with other waiters: a request loop's
/// [`acquire_slots`] gets none while one waits.
async fn wait_slots<D>(shared: &Shared<D>, runner: &Runner) -> Option<Slots> {
    let limit = match &runner.limit {
        Some(sem) => Some(Arc::clone(sem).acquire_owned().await.ok()?),
        None => None,
    };
    let concurrent = Arc::clone(&shared.concurrent).acquire_owned().await.ok()?;
    Some(Slots {
        _concurrent: concurrent,
        _limit: limit,
    })
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
/// the hub reports gone, or one that ran out, leaves `held` empty; `fut` is never cut short,
/// nor held up by a renewal.
async fn keep_alive<D: Dispatcher, F: Future>(
    shared: &Shared<D>,
    runner: &str,
    held: &mut Option<Held>,
    fut: F,
) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    loop {
        tokio::select! {
            out = &mut fut => return out,
            () = renew_when_due(shared, runner, held) => {}
        }
    }
}

/// Renews `held`'s lease once it is due; never returns while there is none.
async fn renew_when_due<D: Dispatcher>(shared: &Shared<D>, runner: &str, held: &mut Option<Held>) {
    let Some(h) = held.as_mut() else {
        return std::future::pending().await;
    };
    tokio::time::sleep_until(h.renew_at()).await;
    let sent = Instant::now();
    let gone = match shared
        .dispatcher
        .renew(&h.reservation.id, shared.options.hub.lease)
        .await
    {
        Ok(lease) => {
            h.reservation.lease = lease;
            h.since = sent;
            h.retry_at = None;
            false
        }
        Err(e) if e.kind == ErrorKind::ReservationGone => {
            log::warn!(runner = runner, reservation = h.reservation.id.as_str(); "Reservation gone");
            true
        }
        Err(e) => {
            log::warn!(runner = runner, reservation = h.reservation.id.as_str(), error = e.to_string().as_str(); "Renewing the reservation failed");
            let lease_end = h.since + h.reservation.lease;
            h.retry_at = Some((Instant::now() + shared.options.hub.retry_pause).min(lease_end));
            h.expired()
        }
    };
    if gone {
        *held = None;
    }
}

async fn release<D: Dispatcher>(shared: &Shared<D>, held: Option<Held>) {
    if let Some(h) = held
        && let Err(e) = shared
            .bounded(shared.dispatcher.release(&h.reservation.id))
            .await
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
        let running = RunningJob::new(Arc::clone(&shared), Some(slots));
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
    /// The runner aborted its jobs first; the job as last seen.
    Interrupted(JobView),
}

/// Follows a submitted job until a node accepts it or it ends. The hub ends a job it could
/// not place within `place_within`; a hub that says nothing for that long and one more
/// `wait` leaves the job unplaced.
async fn wait_until_placed<D: Dispatcher>(shared: &Shared<D>, mut view: JobView) -> Placed {
    let mut abort = shared.shutdown.abort.clone();
    let hub = &shared.options.hub;
    let deadline = Instant::now() + hub.place_within + hub.wait;
    let mut errors = HubErrors::new(hub);
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
            HubJobState::Queued | HubJobState::Starting | HubJobState::Other => {}
        }
        if Instant::now() >= deadline {
            log::error!(hub_job = view.id.as_str(); "The hub did not report the job placed in time");
            let _ = shared
                .bounded(shared.dispatcher.cancel(&view.id, CancelMode::Immediate))
                .await;
            view.state = HubJobState::Finished;
            view.result = Some(lost(
                "the hub did not report it placed in time".to_owned(),
                0,
            ));
            continue;
        }
        let next = tokio::select! {
            v = shared.dispatcher.job(&view.id, Some(view.revision), hub.wait) => v,
            () = tokio::time::sleep_until(deadline) => continue,
            () = wait_true(&mut abort) => return Placed::Interrupted(view),
        };
        match next {
            Ok(v) => {
                errors.ok();
                view = v;
            }
            Err(e) if e.kind == ErrorKind::NotFound => {
                view.state = HubJobState::Finished;
                view.result = Some(lost(e.message, 0));
            }
            Err(e) => {
                let pause = errors.failed(&view.id, "Reading the job from the hub", &e);
                tokio::select! {
                    () = tokio::time::sleep(pause) => {}
                    () = wait_true(&mut abort) => return Placed::Interrupted(view),
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
    let mut errors = HubErrors::new(hub);
    loop {
        match shared.dispatcher.output(id, offset, hub.wait).await {
            Ok(chunk) => {
                errors.ok();
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
                tokio::time::sleep(errors.failed(id, "Reading the job's output", &e)).await;
            }
        }
    }
}

/// Settles the job with the hub; true once it is settled, or the hub has it no more.
async fn settle<D: Dispatcher>(shared: &Shared<D>, id: &str) -> bool {
    match shared.bounded(shared.dispatcher.settle(id)).await {
        Ok(()) => true,
        Err(e) if e.kind == ErrorKind::NotFound => true,
        Err(e) => {
            log::warn!(hub_job = id, error = e.to_string().as_str(); "Settling the job with the hub failed; the next start settles it");
            false
        }
    }
}

/// Follows a job until the hub reports it over, for at most `settle_wait`, then settles it;
/// true once it is settled, or the hub has it no more.
async fn settle_when_over<D: Dispatcher>(shared: &Shared<D>, view: JobView) -> bool {
    let hub = &shared.options.hub;
    let id = view.id.clone();
    let over = tokio::time::timeout(hub.settle_wait, async {
        let mut view = view;
        let mut errors = HubErrors::new(hub);
        while view.state != HubJobState::Finished {
            match shared
                .dispatcher
                .job(&view.id, Some(view.revision), hub.wait)
                .await
            {
                Ok(v) => {
                    errors.ok();
                    view = v;
                }
                Err(e) if e.kind == ErrorKind::NotFound => return false,
                Err(e) => {
                    let pause = errors.failed(&view.id, "Reading the job from the hub", &e);
                    tokio::time::sleep(pause).await;
                }
            }
        }
        true
    })
    .await;
    // Over or not: a job the hub has not finished is refused, and settled on the next start.
    over == Ok(false) || settle(shared, &id).await
}

/// The job's outcome reached GitLab, or GitLab ended it: recorded as reported until the hub
/// settles it, which `settle` (once the job is over) does.
async fn report_then_settle(runner: &Runner, gitlab_job: i64, settle: impl Future<Output = bool>) {
    record(runner, "reported", move |s| {
        s.update(gitlab_job, |r| {
            r.phase = Phase::Reported;
            r.spec = None;
        })
    })
    .await;
    if settle.await {
        record(runner, "settled", move |s| s.remove(gitlab_job)).await;
    }
}

fn lost(message: String, output_len: u64) -> JobResult {
    JobResult {
        failure: Some(FailureClass::Lost),
        exit_code: None,
        message: Some(message),
        output_len,
        artifacts: Vec::new(),
    }
}

/// Writes a state change off the async workers (each write is synced), logging rather than
/// failing the job when the file cannot be written: the job carries on, only a restart
/// would lose it.
async fn record(
    runner: &Runner,
    what: &str,
    change: impl FnOnce(&StateFile) -> Result<()> + Send + 'static,
) {
    let state = Arc::clone(&runner.state);
    let result = tokio::task::spawn_blocking(move || change(&state))
        .await
        .unwrap_or_else(|e| Err(anyhow::anyhow!("{e}")));
    if let Err(e) = result {
        log::error!(runner = runner.cfg.name.as_str(), state_file = runner.state.path().display().to_string().as_str(), error = format!("{e:#}").as_str(); "Could not record the job ({what})");
    }
}

/// A received job: refused here, or recorded and handed to [`drive`].
async fn run_job<D: Dispatcher>(
    shared: &Shared<D>,
    runner: &Runner,
    job: Box<Job>,
    reservation: Option<String>,
) {
    let creds = JobCredentials {
        id: job.id,
        token: job.token.clone(),
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
            let _ = shared.bounded(shared.dispatcher.release(r)).await;
        }
        let mapper = FailureReasonMapper::new(&job.features.failure_reasons);
        let settings = trace_settings(shared, runner, job.debug_mode_enabled());
        fail_uncommitted(runner, &settings, &creds, mapper, &msg, reason, exit_code).await;
        return;
    }
    let translated = spec::translate(
        &job,
        &SpecContext {
            server_url: runner.cfg.url.clone(),
            server_ca_pem: runner.server_ca_pem.clone(),
            runner_id: runner.runner_id().await,
            output_limit: runner.cfg.output_limit_bytes() as u64,
            short_token: runner.cfg.token().short(),
        },
    );
    for w in &translated.warnings {
        log::warn!(job = job.id, warning = w.as_str(); "Translating the job");
    }
    let rec = JobRecord {
        gitlab_job: job.id,
        job_token: job.token.expose().to_owned(),
        request_id: new_request_id(),
        reservation,
        place_within_secs: u32::try_from(shared.options.hub.place_within.as_secs())
            .unwrap_or(u32::MAX),
        hub_job: None,
        phase: Phase::Taken,
        trace_offset: 0,
        failure_reasons: job
            .features
            .failure_reasons
            .iter()
            .map(|r| r.0.clone())
            .collect(),
        debug_trace: job.debug_mode_enabled(),
        placement: runner.cfg.placement(),
        spec: Some(JobSpec::GitlabCi(translated.job)),
    };
    let put = rec.clone();
    record(runner, "taken", move |s| s.put(put)).await;
    drive(shared, runner, rec, false).await;
}

fn trace_settings<D>(shared: &Shared<D>, runner: &Runner, debug_trace: bool) -> TraceSettings {
    TraceSettings {
        output_limit: runner.cfg.output_limit_bytes(),
        final_update_retry_limit: runner.cfg.final_update_retry_limit(),
        debug_trace,
        ..shared.options.trace.clone()
    }
}

/// Resubmits a recorded job with its original body: the same `request_id` returns the
/// same job only if the body matches. `Err(None)` means the runner aborted its jobs first.
async fn submit_recorded<D: Dispatcher>(
    shared: &Shared<D>,
    rec: &JobRecord,
    spec: JobSpec,
) -> Result<JobView, Option<DispatchError>> {
    let mut abort = shared.shutdown.abort.clone();
    let submission = Submission {
        request_id: rec.request_id.clone(),
        placement: rec.placement.clone(),
        reservation: rec.reservation.clone(),
        place_within: Duration::from_secs(u64::from(rec.place_within_secs)),
        gitlab_job: rec.gitlab_job,
        spec,
    };
    tokio::select! {
        r = shared.dispatcher.submit(submission) => r.map_err(Some),
        () = wait_true(&mut abort) => Err(None),
    }
}

/// Whether a failed submission may have reached the hub all the same.
fn outcome_unknown(e: &Option<DispatchError>) -> bool {
    e.as_ref().is_none_or(|e| {
        matches!(
            e.kind,
            ErrorKind::Transport | ErrorKind::Unavailable | ErrorKind::Internal
        )
    })
}

/// Drives a recorded job through submission, placement, commit, output, final state and
/// settlement, starting at its recorded phase. Also resumes jobs after a daemon restart.
async fn drive<D: Dispatcher>(
    shared: &Shared<D>,
    runner: &Runner,
    mut rec: JobRecord,
    resumed: bool,
) {
    let gitlab_job = rec.gitlab_job;
    let creds = JobCredentials {
        id: gitlab_job,
        token: Secret::new(rec.job_token.clone()),
    };
    let reasons: Vec<FailureReason> = rec
        .failure_reasons
        .iter()
        .map(|r| FailureReason::new(r.clone()))
        .collect();
    let mapper = FailureReasonMapper::new(&reasons);
    let settings = trace_settings(shared, runner, rec.debug_trace);
    let fail = |msg: String, reason: FailureReason| {
        let (mapper, settings, creds) = (mapper.clone(), settings.clone(), creds.clone());
        async move {
            fail_uncommitted(runner, &settings, &creds, mapper, &msg, reason, 0).await;
        }
    };
    let drop_record = |what: &'static str| record(runner, what, move |s| s.remove(gitlab_job));

    match rec.phase {
        Phase::Reported => {
            // Only the settle is left; a job the hub has not finished is canceled first.
            let Some(id) = rec.hub_job.clone() else {
                drop_record("settled").await;
                return;
            };
            match current_view(shared, &id).await {
                Err(Aborted) => {}
                Ok(None) => drop_record("settled").await,
                Ok(Some(v)) => {
                    if v.state != HubJobState::Finished {
                        let _ = shared
                            .bounded(shared.dispatcher.cancel(&id, CancelMode::Immediate))
                            .await;
                    }
                    if settle_when_over(shared, v).await {
                        drop_record("settled").await;
                    }
                }
            }
            return;
        }
        Phase::Abandoned => {
            // Failed in GitLab already: the submission again only learns the hub job, if
            // the first one made it, to cancel and settle it.
            let Some(spec) = rec.spec.take() else {
                drop_record("dropped").await;
                return;
            };
            match submit_recorded(shared, &rec, spec).await {
                Ok(v) => {
                    log::warn!(job = gitlab_job, hub_job = v.id.as_str(); "Canceling the hub job of a job failed in GitLab");
                    // Reported before the cancel: a restart from here cancels and settles
                    // the hub job instead of dropping a record without a spec.
                    rec.hub_job = Some(v.id.clone());
                    rec.phase = Phase::Reported;
                    let put = rec.clone();
                    record(runner, "reported", move |s| s.put(put)).await;
                    let _ = shared
                        .bounded(shared.dispatcher.cancel(&v.id, CancelMode::Immediate))
                        .await;
                    if settle_when_over(shared, v).await {
                        drop_record("settled").await;
                    }
                }
                Err(e) if outcome_unknown(&e) => {
                    log::warn!(job = gitlab_job; "The hub did not answer the submission again; the next start tries once more");
                }
                Err(_) => drop_record("dropped").await,
            }
            return;
        }
        Phase::Taken | Phase::Submitted | Phase::Committed => {}
    }

    // Submission: again, with the same request_id and body, after a restart.
    let view = if rec.phase == Phase::Taken {
        let Some(spec) = rec.spec.clone() else {
            fail(
                "Job failed (system failure): the job's spec was lost".to_owned(),
                FailureReason::runner_system_failure(),
            )
            .await;
            drop_record("dropped").await;
            return;
        };
        match submit_recorded(shared, &rec, spec).await {
            Ok(v) => {
                rec.hub_job = Some(v.id.clone());
                rec.phase = Phase::Submitted;
                rec.spec = None;
                let put = rec.clone();
                record(runner, "submitted", move |s| s.put(put)).await;
                v
            }
            Err(e) => {
                let unknown = outcome_unknown(&e);
                if unknown {
                    // The hub may have the job: kept, so the next start learns it and ends it.
                    rec.phase = Phase::Abandoned;
                    let put = rec.clone();
                    record(runner, "abandoned", move |s| s.put(put)).await;
                }
                if let Some(r) = &rec.reservation {
                    let _ = shared.bounded(shared.dispatcher.release(r)).await;
                }
                match e {
                    None => {
                        fail(
                            "Job failed: aborted: the runner is shutting down".to_owned(),
                            FailureReason::new(FailureReason::RUNNER_INTERRUPTED),
                        )
                        .await;
                    }
                    Some(e) => {
                        fail(
                            format!(
                                "Job failed (system failure): the fleet did not take the job: {}",
                                e.message
                            ),
                            FailureReason::runner_system_failure(),
                        )
                        .await;
                    }
                }
                if unknown {
                    log::warn!(job = gitlab_job; "The hub's answer to the submission is unknown; the next start cancels the job it may have");
                } else {
                    drop_record("dropped").await;
                }
                return;
            }
        }
    } else {
        let Some(id) = rec.hub_job.clone() else {
            drop_record("dropped").await;
            return;
        };
        match current_view(shared, &id).await {
            Ok(Some(v)) => v,
            Err(Aborted) => {
                // Still in the state file: the next start resumes it.
                log::warn!(job = gitlab_job, hub_job = id.as_str(); "Aborted before the hub answered; the job is left for the next start");
                return;
            }
            Ok(None) => {
                // The hub has no such job (any more): its outcome is unknown. GitLab
                // holds the trace sent so far; a 416 moves the offset past it.
                if rec.phase == Phase::Committed {
                    let trace = JobTrace::start(
                        Arc::clone(&runner.client),
                        creds.clone(),
                        Some(mapper.clone()),
                        settings.clone(),
                    );
                    if let Err(e) = trace.fail(FailureReason::from(FailureClass::Lost), 0).await {
                        log::error!(job = gitlab_job, error = e.to_string().as_str(); "Could not report the job's final state");
                    }
                } else {
                    fail(
                        "Job failed (system failure): the fleet lost the job".to_owned(),
                        FailureReason::runner_system_failure(),
                    )
                    .await;
                }
                drop_record("dropped").await;
                return;
            }
        }
    };
    let hub_id = view.id.clone();

    let mut graceful_sent = false;
    let view = if rec.phase == Phase::Committed {
        view
    } else {
        let view = match wait_until_placed(shared, view).await {
            Placed::Accepted(v) => v,
            Placed::Unplaced(v) => {
                let why = v
                    .result
                    .as_ref()
                    .and_then(|r| r.message.clone())
                    .unwrap_or_else(|| "no node took it in time".to_owned());
                fail(
                    format!(
                        "Job failed (system failure): the fleet could not place the job: {why}"
                    ),
                    FailureReason::runner_system_failure(),
                )
                .await;
                report_then_settle(runner, gitlab_job, settle(shared, &hub_id)).await;
                return;
            }
            Placed::Interrupted(v) => {
                let _ = shared
                    .bounded(shared.dispatcher.cancel(&hub_id, CancelMode::Immediate))
                    .await;
                fail(
                    "Job failed: aborted: the runner is shutting down".to_owned(),
                    FailureReason::new(FailureReason::RUNNER_INTERRUPTED),
                )
                .await;
                report_then_settle(runner, gitlab_job, settle_when_over(shared, v)).await;
                return;
            }
        };
        // The commit: the job is ours, and running.
        let update = runner
            .client
            .update_job(&creds, &UpdateJobInfo::new(gitlab_job, JobState::Running))
            .await;
        if update.state == UpdateState::Abort {
            log::warn!(job = gitlab_job, hub_job = hub_id.as_str(); "GitLab refused the job's commit; canceling it");
            let _ = shared
                .bounded(shared.dispatcher.cancel(&hub_id, CancelMode::Immediate))
                .await;
            report_then_settle(runner, gitlab_job, settle_when_over(shared, view)).await;
            return;
        }
        rec.phase = Phase::Committed;
        record(runner, "committed", move |s| {
            s.update(gitlab_job, |r| r.phase = Phase::Committed)
        })
        .await;
        if update.cancel_requested {
            graceful_sent = true;
            let _ = shared
                .bounded(shared.dispatcher.cancel(&hub_id, CancelMode::Graceful))
                .await;
        }
        log::info!(job = gitlab_job, hub_job = hub_id.as_str(), node = view.node.as_deref().unwrap_or(""); "Job committed");
        view
    };
    follow(shared, runner, rec, view, mapper, resumed, graceful_sent).await;
}

/// The runner aborted its jobs.
struct Aborted;

/// The hub's view of `id` now; `None` when the hub does not have it. Retried until the hub
/// answers or the runner aborts its jobs.
async fn current_view<D: Dispatcher>(
    shared: &Shared<D>,
    id: &str,
) -> Result<Option<JobView>, Aborted> {
    let mut abort = shared.shutdown.abort.clone();
    let mut errors = HubErrors::new(&shared.options.hub);
    loop {
        let read = tokio::select! {
            r = shared.dispatcher.job(id, None, Duration::ZERO) => r,
            () = wait_true(&mut abort) => return Err(Aborted),
        };
        match read {
            Ok(v) => return Ok(Some(v)),
            Err(e) if e.kind == ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                let pause = errors.failed(id, "Reading the job from the hub", &e);
                tokio::select! {
                    () = tokio::time::sleep(pause) => {}
                    () = wait_true(&mut abort) => return Err(Aborted),
                }
            }
        }
    }
}

/// Reads the hub's output from 0 up to `upto`: the part of the trace GitLab already holds,
/// which the checksum still covers.
async fn prefill<D: Dispatcher>(
    shared: &Shared<D>,
    id: &str,
    upto: u64,
) -> Result<Vec<u8>, DispatchError> {
    let mut out = Vec::new();
    while (out.len() as u64) < upto {
        let chunk = shared
            .dispatcher
            .output(id, out.len() as u64, Duration::ZERO)
            .await?;
        if chunk.data.is_empty() {
            break;
        }
        let room = usize::try_from(upto)
            .unwrap_or(usize::MAX)
            .saturating_sub(out.len());
        out.extend_from_slice(&chunk.data[..chunk.data.len().min(room)]);
    }
    Ok(out)
}

/// A committed job: its output copied into the trace, GitLab's cancel and abort relayed,
/// its outcome reported, and the job settled.
async fn follow<D: Dispatcher>(
    shared: &Shared<D>,
    runner: &Runner,
    mut rec: JobRecord,
    view: JobView,
    mapper: FailureReasonMapper,
    resumed: bool,
    mut graceful_sent: bool,
) {
    let gitlab_job = rec.gitlab_job;
    let hub_id = view.id.clone();
    let creds = JobCredentials {
        id: gitlab_job,
        token: Secret::new(rec.job_token.clone()),
    };
    // A resumed trace starts with what GitLab holds, and continues from GitLab's offset.
    let prefix = if resumed && rec.trace_offset > 0 {
        match prefill(shared, &hub_id, rec.trace_offset).await {
            Ok(p) => p,
            Err(e) => {
                log::warn!(job = gitlab_job, error = e.to_string().as_str(); "Could not read back the trace; sending it again");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let trace = JobTrace::resume(
        Arc::clone(&runner.client),
        creds,
        Some(mapper),
        trace_settings(shared, runner, rec.debug_trace),
        &prefix,
    );
    if resumed {
        log::info!(job = gitlab_job, hub_job = hub_id.as_str(), trace_offset = prefix.len(); "Resumed the job");
    }
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
    let mut view_errors = HubErrors::new(&hub);
    // Set on the runner's abort: how long the hub gets to report the job ended.
    let mut abort_deadline: Option<Instant> = None;
    // The trace offset is written at most every `trace_offset_interval`.
    let mut offset_saved = Instant::now();
    let save_offset = |sent: u64| {
        record(runner, "trace offset", move |s| {
            s.update(gitlab_job, |r| r.trace_offset = sent)
        })
    };
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut pump = std::pin::pin!(pump_output(shared, &hub_id, &trace));
    // The job view's long poll outlives the loop's other wake-ups (the tick, output, GitLab's
    // answers): made anew in each turn, it would be dropped mid-request every second, and
    // with it the connection it held. After a failed read it waits for `view_at` first.
    let (job_id, wait) = (&hub_id, hub.wait);
    let poll_view = |after: u64, at: Instant| async move {
        tokio::time::sleep_until(at).await;
        shared.dispatcher.job(job_id, Some(after), wait).await
    };
    // Boxed instead of `pin!` so the future can be dropped when the loop ends.
    let mut view_poll = Box::pin(poll_view(view.revision, view_at));
    loop {
        if output_done && view.state == HubJobState::Finished {
            break;
        }
        tokio::select! {
            r = &mut pump, if !output_done => {
                output_done = true;
                if let Err(e) = r {
                    log::error!(job = gitlab_job, error = e.to_string().as_str(); "The hub lost the job's output");
                    if view.state != HubJobState::Finished
                        && let Err(e) = shared.bounded(shared.dispatcher.cancel(&hub_id, CancelMode::Immediate)).await
                    {
                        log::warn!(job = gitlab_job, hub_job = hub_id.as_str(), error = e.to_string().as_str(); "Canceling the job failed");
                    }
                    view.state = HubJobState::Finished;
                    view.result.get_or_insert(lost(e.message, trace.len() as u64));
                }
            }
            v = &mut view_poll, if view.state != HubJobState::Finished => {
                match v {
                    Ok(v) => {
                        view_errors.ok();
                        view = v;
                    }
                    Err(e) if e.kind == ErrorKind::NotFound => {
                        view.state = HubJobState::Finished;
                        view.result = Some(lost(e.message, trace.len() as u64));
                    }
                    Err(e) => {
                        view_at = Instant::now() + view_errors.failed(&hub_id, "Reading the job from the hub", &e);
                    }
                }
                view_poll.set(poll_view(view.revision, view_at));
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
                    log::info!(job = gitlab_job; "GitLab requested the job to be canceled");
                    let _ = shared.bounded(shared.dispatcher.cancel(&hub_id, CancelMode::Graceful)).await;
                }
            }
            _ = tick.tick() => {
                let sent = trace.sent() as u64;
                if sent != rec.trace_offset && offset_saved.elapsed() >= shared.options.trace_offset_interval {
                    rec.trace_offset = sent;
                    offset_saved = Instant::now();
                    save_offset(sent).await;
                }
            }
            () = wait_true(&mut abort), if !interrupted => {
                interrupted = true;
                abort_deadline = Some(Instant::now() + hub.settle_wait);
                let _ = shared.bounded(shared.dispatcher.cancel(&hub_id, CancelMode::Immediate)).await;
            }
            () = sleep_until(abort_deadline) => {
                log::warn!(job = gitlab_job, hub_job = hub_id.as_str(); "The hub did not report the aborted job ended; reporting it interrupted");
                break;
            }
        }
    }
    // An in-flight read would otherwise hold its connection through the reporting below.
    drop(view_poll);

    if aborted_by_gitlab {
        // GitLab ended the job: stop it now and write nothing more.
        log::warn!(job = gitlab_job; "GitLab ended the job; canceling it");
        let _ = shared
            .bounded(shared.dispatcher.cancel(&hub_id, CancelMode::Immediate))
            .await;
        trace.finish().await;
        report_then_settle(runner, gitlab_job, settle_when_over(shared, view)).await;
        return;
    }

    let result = view
        .result
        .clone()
        .unwrap_or_else(|| lost("the hub gave no result".to_owned(), trace.len() as u64));
    let reported = if interrupted {
        trace
            .fail(FailureReason::new(FailureReason::RUNNER_INTERRUPTED), 0)
            .await
    } else {
        match result.failure {
            None => trace.success().await,
            Some(class) => {
                trace
                    .fail(FailureReason::from(class), result.exit_code.unwrap_or(0))
                    .await
            }
        }
    };
    match reported {
        Ok(()) => {
            // Unfinished only once the abort's deadline passed: the hub would refuse the
            // settle, which the next start makes.
            let settled =
                async { view.state == HubJobState::Finished && settle(shared, &hub_id).await };
            report_then_settle(runner, gitlab_job, settled).await;
        }
        // Not settled: the hub keeps the output, and a restarted daemon reports it again.
        Err(e) => {
            log::error!(job = gitlab_job, error = e.to_string().as_str(); "Could not report the job's final state");
            let sent = trace.sent() as u64;
            if sent != rec.trace_offset {
                save_offset(sent).await;
            }
        }
    }
    log::info!(job = gitlab_job, runner = runner.cfg.name.as_str(); "Job finished");
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
    fn token_expiry_times() {
        assert_eq!(parse_utc("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_utc("2000-02-29T23:59:59Z"), Some(951_868_799));
        assert_eq!(parse_utc("2026-10-09T12:00:00.123Z"), Some(1_791_547_200));
        assert_eq!(parse_utc("2684-10-16T13:25:59Z"), Some(22_556_669_159));
        // GitLab's "never expires".
        assert_eq!(parse_utc("0001-01-01T00:00:00Z"), None);
        assert_eq!(parse_utc("2026-10-09T12:00:00+02:00"), None);
        assert_eq!(parse_utc("2026-13-09T12:00:00Z"), None);
        assert_eq!(parse_utc(""), None);
    }

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
