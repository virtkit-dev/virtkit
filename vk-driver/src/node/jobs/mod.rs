//! Placed jobs (protocol version [`vk_hub_proto::JOBS`]): reservations the hub asks this node
//! to hold, the jobs it starts on them, their output and their results. See
//! `docs/gitlab-dispatch.md`.

pub mod artifacts;
pub mod cache;
pub mod driver;
pub mod env;
pub mod guest;
pub mod journal;
pub mod ledger;
pub mod mask;
pub mod script;
pub mod settings;
#[cfg(test)]
mod testkit;
pub mod trace;
pub mod transfer;
pub mod vars;

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;
use vk_core::addr::SocketAddr;
use vk_hub_proto::dispatch::{
    Held, HeldJob, HubJobMsg, JobStart, LeaseEnd, LeaseState, MAX_OUTPUT_CHUNK, NodeJobMsg,
    OUTPUT_WINDOW, OfferReply, Refusal, RunState,
};
use vk_hub_proto::job::{CiJob, FailureClass, JobResult, JobSpec, MAX_JOB_SPEC};

use crate::config::Config;
use journal::Meta;
use ledger::{Ledger, Limits};
use trace::Trace;
use vars::Vars;

/// What the cache and artifact stages need of a running job.
pub struct StageCtx<'a> {
    pub cfg: &'a Config,
    pub job: &'a CiJob,
    pub vars: &'a Vars,
    /// The job VM's exec channel.
    pub addr: SocketAddr,
    /// The guest user the job's steps run as; `None` for the image's own.
    pub user: Option<String>,
    /// `CI_PROJECT_DIR`, in the guest.
    pub project_dir: String,
    pub trace: &'a Trace,
    /// A private host directory of this job's, for archives in transit.
    pub scratch: &'a Path,
    /// Raised when the job is canceled or times out: a transfer under way stops.
    pub cancel: &'a CancellationToken,
}

impl StageCtx<'_> {
    /// `stage` run by `f` up to `attempts` times, as gitlab-runner retries a stage: each
    /// failure but the last a warning, none once the job is stopped.
    pub async fn attempted<F, Fut>(&self, stage: &str, attempts: u32, mut f: F) -> Result<()>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        let mut attempt = 1;
        loop {
            match f().await {
                Ok(()) => return Ok(()),
                Err(e) if attempt < attempts && !self.cancel.is_cancelled() => {
                    self.trace.warning(&format!("{e:#}"));
                    attempt += 1;
                    self.trace
                        .print(&format!("Retrying {stage}, attempt {attempt}"));
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// How often a result is repeated until the hub records it.
const RESULT_REPEAT: Duration = Duration::from_secs(15);

/// How long a driver may take to write its pid before a missing one means it is gone.
const DRIVER_START: Duration = Duration::from_secs(10);

/// A job the node holds, as the session follows it.
struct Track {
    dir: PathBuf,
    meta: Meta,
    /// The hub has stored the output up to here.
    acked: u64,
    /// Sent up to here this session.
    sent: u64,
    /// A job held across a reconnect waits for the hub's ack before it resends.
    awaiting_ack: bool,
    /// The hub canceled the job instead of acking it after a reconnect: it has ended the job
    /// or never knew it, and wants no output, only the result that lets the node drop it.
    disowned: bool,
    /// Raised once the node's cleanup after the job's lost driver has ended, when one was
    /// started: the result is written then.
    cleaning: Option<Arc<AtomicBool>>,
    /// The stage last told.
    told: Option<String>,
    result: Option<JobResult>,
    result_told: Option<Instant>,
    started: Instant,
}

struct State {
    ledger: Ledger,
    jobs: BTreeMap<String, Track>,
    /// Why the last offer was refused, logged when it changes; `None` once one is granted.
    refused: Option<(Refusal, Option<String>)>,
}

/// Every reservation and placed job this node holds, for the sessions of `vk node run`.
pub struct Jobs {
    /// `<state_dir>/node/jobs`.
    dir: PathBuf,
    cfg: Arc<Config>,
    state: Mutex<State>,
    /// Starts a job's driver: [`Jobs::spawn`], or a test's stand-in.
    spawner: Spawner,
    /// Cleans up after a job whose driver is gone: [`Jobs::clean_up`], or a test's stand-in.
    cleaner: Cleaner,
}

/// Starts the driver of the job journaled in a dir, handing it the job's ledger entry.
type Spawner = fn(&Jobs, &Path, Option<crate::admit::Reservation>) -> Result<()>;

/// Starts the executor's cleanup of the job journaled in a dir, raising the flag once it has
/// ended.
type Cleaner = fn(&Jobs, &Path, Arc<AtomicBool>) -> Result<()>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What the node admits a placed job's envelope against, from its configuration.
pub fn limits(cfg: &Config) -> Result<Limits> {
    let ctx_jobs = cfg.state_dir().join("jobs");
    let vm = &cfg.executor.vm;
    Ok(Limits {
        admit_dir: cfg.state_dir().join("admit"),
        jobs_dir: ctx_jobs,
        budget_mib: crate::vm::budget_mib(cfg).transpose()?,
        disk_admission: cfg.executor.schedule.disk_admission.unwrap_or(true),
        max_cpus: vm.max_cpus.unwrap_or(vm.cpus),
    })
}

impl Jobs {
    /// The jobs journaled under `node_dir/jobs`, as a restarted node finds them.
    pub fn open(node_dir: &Path, cfg: Arc<Config>) -> Result<Arc<Jobs>> {
        let limits = limits(&cfg)?;
        Ok(Self::open_with(
            node_dir,
            cfg,
            limits,
            Jobs::spawn,
            Jobs::clean_up,
        ))
    }

    fn open_with(
        node_dir: &Path,
        cfg: Arc<Config>,
        limits: Limits,
        spawner: Spawner,
        cleaner: Cleaner,
    ) -> Arc<Jobs> {
        let dir = node_dir.join("jobs");
        let mut jobs = BTreeMap::new();
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let Some(id) = entry.file_name().to_str().map(String::from) else {
                continue;
            };
            let path = entry.path();
            if !vk_hub_proto::valid_id(&id) {
                continue;
            }
            let Ok(meta) = journal::read_meta(&path) else {
                // Taken down before it was accepted: the hub never heard of it.
                let _ = std::fs::remove_dir_all(&path);
                continue;
            };
            jobs.insert(
                id,
                Track {
                    result: journal::read_result(&path),
                    dir: path,
                    meta,
                    acked: 0,
                    sent: 0,
                    awaiting_ack: true,
                    disowned: false,
                    cleaning: None,
                    told: None,
                    result_told: None,
                    started: Instant::now(),
                },
            );
        }
        Arc::new(Jobs {
            dir,
            cfg,
            state: Mutex::new(State {
                ledger: Ledger::new(limits),
                jobs,
                refused: None,
            }),
            spawner,
            cleaner,
        })
    }

    /// A session at [`vk_hub_proto::JOBS`] has started: everything held, for `held`. Output
    /// resumes from the offset the hub acks.
    pub fn held(&self, now: Instant) -> NodeJobMsg {
        let mut state = lock(&self.state);
        let reservations = state.ledger.held(now);
        let mut jobs = Vec::new();
        for (id, t) in &mut state.jobs {
            t.awaiting_ack = true;
            t.disowned = false;
            t.sent = t.acked;
            t.result_told = None;
            let stage = journal::read_stage(&t.dir);
            t.told = stage.clone();
            let finished = t.result.is_some();
            jobs.push(HeldJob {
                job: id.clone(),
                state: match (finished, stage) {
                    (true, _) => RunState::Finished,
                    (false, Some(stage)) => RunState::Running { stage },
                    (false, None) => RunState::Accepted,
                },
                output_len: journal::output_len(&t.dir),
                finished,
            });
        }
        NodeJobMsg::Held(Held { reservations, jobs })
    }

    /// The answers to a message from the hub. `ready`: the node takes new work.
    pub fn handle(&self, msg: HubJobMsg, ready: bool, now: Instant) -> Vec<NodeJobMsg> {
        let mut state = lock(&self.state);
        match msg {
            HubJobMsg::Offer {
                reservation,
                envelope,
                lease_secs,
            } => {
                let reply = state
                    .ledger
                    .offer(&reservation, envelope, lease_secs, ready, now);
                if let Some(line) = refusal_change(&mut state.refused, &reply) {
                    say!("{line}");
                }
                vec![NodeJobMsg::OfferReply { reservation, reply }]
            }
            HubJobMsg::Renew {
                reservation,
                lease_secs,
            } => {
                let state = state.ledger.renew(&reservation, lease_secs, now);
                vec![NodeJobMsg::Lease { reservation, state }]
            }
            HubJobMsg::Release { reservation } => {
                let state = state.ledger.release(&reservation);
                vec![NodeJobMsg::Lease { reservation, state }]
            }
            HubJobMsg::Start(start) => self.start(&mut state, *start, ready),
            HubJobMsg::OutputAck { job, offset } => {
                if let Some(t) = state.jobs.get_mut(&job) {
                    let len = journal::output_len(&t.dir);
                    let offset = offset.min(len);
                    if t.awaiting_ack || offset > t.sent {
                        t.sent = offset;
                    }
                    t.awaiting_ack = false;
                    t.acked = offset;
                }
                Vec::new()
            }
            HubJobMsg::Cancel { job, mode } => match state.jobs.get_mut(&job) {
                Some(t) => {
                    // The hub acks every job it knows before it cancels the rest.
                    if t.awaiting_ack {
                        t.disowned = true;
                    }
                    // Finished: its result follows, or already did.
                    if t.result.is_none()
                        && let Err(e) = journal::write_cancel(&t.dir, mode)
                    {
                        say!("canceling job {job}: {e:#}");
                    }
                    Vec::new()
                }
                None => vec![NodeJobMsg::Job {
                    job,
                    state: RunState::Refused {
                        reason: Refusal::Invalid,
                        message: Some("this node does not hold that job".into()),
                    },
                }],
            },
            HubJobMsg::Recorded { job } => {
                if let Some(t) = state.jobs.get(&job)
                    && t.result.is_some()
                {
                    let dir = t.dir.clone();
                    state.jobs.remove(&job);
                    if let Err(e) = std::fs::remove_dir_all(&dir) {
                        say!("removing {}: {e}", dir.display());
                    }
                }
                Vec::new()
            }
        }
    }

    fn start(&self, state: &mut State, start: JobStart, ready: bool) -> Vec<NodeJobMsg> {
        let job = start.job.clone();
        let refused = |reason: Refusal, message: String| {
            vec![NodeJobMsg::Job {
                job: job.clone(),
                state: RunState::Refused {
                    reason,
                    message: Some(message),
                },
            }]
        };
        if !vk_hub_proto::valid_id(&job) {
            return refused(Refusal::Invalid, "malformed job ID".into());
        }
        // Redelivered: answered from the journal, never run twice.
        if let Some(t) = state.jobs.get(&job) {
            let run = match (&t.result, journal::read_stage(&t.dir)) {
                (Some(_), _) => RunState::Finished,
                (None, Some(stage)) => RunState::Running { stage },
                (None, None) => RunState::Accepted,
            };
            return vec![NodeJobMsg::Job { job, state: run }];
        }
        let JobSpec::GitlabCi(spec) = &start.spec;
        let spec_len = serde_json::to_vec(&start.spec).map_or(usize::MAX, |b| b.len());
        if spec_len > MAX_JOB_SPEC {
            return refused(Refusal::Invalid, "the spec is over 512 KiB".into());
        }
        let gitlab_id = spec.job.id;
        if gitlab_id == 0 || env::place(&self.cfg, spec, &meta_for(0, 0, spec)).is_err() {
            return refused(Refusal::Invalid, "the spec names no runnable job".into());
        }
        let name = gitlab_id.to_string();
        // The ledger entry the job holds: its reservation's, renamed to the job, or a fresh
        // one for a job placed without one.
        let mut msgs = Vec::new();
        let taken = start
            .reservation
            .as_deref()
            .and_then(|r| state.ledger.take(r));
        let held = match taken {
            Some((_, held)) => {
                if let Some(r) = &start.reservation {
                    msgs.push(NodeJobMsg::Lease {
                        reservation: r.clone(),
                        state: LeaseState::Gone {
                            why: LeaseEnd::Started,
                        },
                    });
                }
                held
            }
            None if !ready => {
                return refused(Refusal::NotReady, "the node takes no new work".into());
            }
            None => match state.ledger.admit(&name, &start.envelope) {
                Ok(held) => held,
                Err((reason, message)) => {
                    let reason = match start.reservation {
                        Some(_) => Refusal::NoReservation,
                        None => reason,
                    };
                    return refused(reason, message);
                }
            },
        };
        // Past the take, a refusal goes out with the end of the reservation it consumed.
        let refused_after = |msgs: Vec<NodeJobMsg>, reason, message| {
            let mut out = refused(reason, message);
            out.extend(msgs.into_iter().map(|m| match m {
                NodeJobMsg::Lease { reservation, .. } => NodeJobMsg::Lease {
                    reservation,
                    state: LeaseState::Gone {
                        why: LeaseEnd::Released,
                    },
                },
                m => m,
            }));
            out
        };
        let held = match held.map(|r| match r.name() == name {
            true => Ok(r),
            false => r.rename(&state.ledger.limits().admit_dir, &name),
        }) {
            None => None,
            Some(Ok(r)) => Some(r),
            Some(Err(e)) => return refused_after(msgs, Refusal::Invalid, format!("{e:#}")),
        };
        let meta = self.slots(state, spec);
        let dir = self.dir.join(&job);
        match self.journal(&dir, &start, &meta) {
            Ok(()) => {}
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                return refused_after(msgs, Refusal::Other, format!("journaling the job: {e:#}"));
            }
        }
        if let Err(e) = (self.spawner)(self, &dir, held) {
            // Accepted all the same: the result says why it ended.
            say!("starting job {job}: {e:#}");
            let result = JobResult {
                failure: Some(FailureClass::System),
                exit_code: None,
                message: Some(format!("the node could not start the job: {e:#}")),
                output_len: journal::output_len(&dir),
                artifacts: Vec::new(),
                usage: None,
            };
            let _ = journal::write_json(&dir.join(journal::RESULT), &result);
        }
        state.jobs.insert(
            job.clone(),
            Track {
                result: journal::read_result(&dir),
                dir,
                meta,
                acked: 0,
                sent: 0,
                awaiting_ack: false,
                disowned: false,
                cleaning: None,
                told: None,
                result_told: None,
                started: Instant::now(),
            },
        );
        say!("job {job}: GitLab job {gitlab_id} accepted");
        msgs.insert(
            0,
            NodeJobMsg::Job {
                job,
                state: RunState::Accepted,
            },
        );
        msgs
    }

    /// The lowest slots free among the jobs this node runs: overall, and within the project.
    fn slots(&self, state: &State, spec: &CiJob) -> Meta {
        let running = || state.jobs.values().filter(|t| t.result.is_none());
        let free = |used: Vec<u32>| (0u32..).find(|n| !used.contains(n)).unwrap_or(0);
        let slot = free(running().map(|t| t.meta.slot).collect());
        let project_slot = free(
            running()
                .filter(|t| t.meta.project_id == spec.job.project_id)
                .map(|t| t.meta.project_slot)
                .collect(),
        );
        meta_for(slot, project_slot, spec)
    }

    fn journal(&self, dir: &Path, start: &JobStart, meta: &Meta) -> Result<()> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .with_context(|| format!("creating {}", self.dir.display()))?;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        journal::write_json(&dir.join(journal::START), start)?;
        let JobSpec::GitlabCi(spec) = &start.spec;
        journal::write_json(&dir.join(env::JOB_RESPONSE), &env::job_response(spec))?;
        // Last: a dir with its meta is a job the hub was told about.
        journal::write_json(&dir.join(journal::META), meta)
    }

    /// Start the job's driver, detached, with the ledger entry it holds. The driver computes
    /// the job's executor environment from the journal itself.
    fn spawn(&self, dir: &Path, held: Option<crate::admit::Reservation>) -> Result<()> {
        // The spelling [`journal::live_driver`] finds the driver by.
        let dir = &dir
            .canonicalize()
            .with_context(|| format!("resolving {}", dir.display()))?;
        let mut cmd = self.detached(dir)?;
        cmd.args(["node", "job"]).arg(dir);
        let ledger = held.map(crate::admit::Reservation::into_file);
        let fd = ledger.as_ref().map(|file| file.as_raw_fd());
        if let Some(fd) = fd {
            cmd.arg("--ledger-fd").arg(fd.to_string());
        }
        // SAFETY: setsid and fcntl on a descriptor this process owns, between fork and exec,
        // where only async-signal-safe calls are made.
        unsafe {
            cmd.pre_exec(move || {
                // Its own session: no controlling terminal, no signal sent to the node's group.
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if let Some(fd) = fd
                    && libc::fcntl(fd, libc::F_SETFD, 0) == -1
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().context("starting the job's driver")?;
        // The driver holds the ledger entry now; this process's copy goes.
        drop(ledger);
        if let Err(e) = vk_fs::write_atomic(
            &dir.join(journal::PID),
            child.id().to_string().as_bytes(),
            0o600,
        ) {
            // The node reports the job failed: no driver may run it meanwhile.
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
        reap(child);
        Ok(())
    }

    /// `vk gitlab cleanup` of a job whose driver is gone, with the environment the driver
    /// gave it, bounded as the driver bounds it: the job's VM and executor dir go. `done` is
    /// raised once it has ended.
    fn clean_up(&self, dir: &Path, done: Arc<AtomicBool>) -> Result<()> {
        let env = env::of_journal(&self.cfg, dir)?;
        let mut cmd = self.detached(dir)?;
        cmd.args(["gitlab", "cleanup"]);
        env::apply(&mut cmd, &env);
        // SAFETY: setsid between fork and exec, async-signal-safe.
        unsafe {
            cmd.pre_exec(|| match libc::setsid() {
                -1 => Err(std::io::Error::last_os_error()),
                _ => Ok(()),
            });
        }
        let mut child = cmd.spawn().context("starting `vk gitlab cleanup`")?;
        std::thread::spawn(move || {
            wait_bounded(&mut child, driver::CLEANUP_TIMEOUT);
            done.store(true, Ordering::Release);
        });
        Ok(())
    }

    /// `vk` with this node's configuration, its output appended to the job's driver log.
    fn detached(&self, dir: &Path) -> Result<std::process::Command> {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(dir.join(journal::DRIVER_LOG))
            .context("opening the driver log")?;
        let mut cmd = std::process::Command::new(crate::spawn::self_exe());
        if let Some(src) = &self.cfg.source {
            cmd.arg("--config").arg(src);
        }
        env::apply(&mut cmd, &[]);
        cmd.stdin(std::process::Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        Ok(cmd)
    }

    /// What the hub has yet to hear: lapsed leases, stages, output within the window, results.
    /// `quarantined` releases every reservation.
    pub fn poll(&self, now: Instant, quarantined: bool) -> Vec<NodeJobMsg> {
        let mut state = lock(&self.state);
        let mut msgs = Vec::new();
        let gone: Vec<(String, LeaseEnd)> = match quarantined {
            true => state
                .ledger
                .release_all()
                .into_iter()
                .map(|r| (r, LeaseEnd::Released))
                .collect(),
            false => state
                .ledger
                .expire(now)
                .into_iter()
                .map(|r| (r, LeaseEnd::Expired))
                .collect(),
        };
        for (reservation, why) in gone {
            msgs.push(NodeJobMsg::Lease {
                reservation,
                state: LeaseState::Gone { why },
            });
        }
        for (id, t) in &mut state.jobs {
            if t.result.is_none() {
                let result = journal::read_result(&t.dir).or_else(|| self.lost_driver(t, now));
                t.result = result;
                if let Some(stage) = journal::read_stage(&t.dir)
                    && t.told.as_ref() != Some(&stage)
                    && t.result.is_none()
                {
                    t.told = Some(stage.clone());
                    msgs.push(NodeJobMsg::Job {
                        job: id.clone(),
                        state: RunState::Running { stage },
                    });
                }
            }
            if t.awaiting_ack && !t.disowned {
                continue;
            }
            if !t.disowned {
                msgs.extend(output_chunks(id, t));
            }
            if let Some(result) = &t.result
                && (t.disowned || t.acked >= result.output_len)
                && t.result_told
                    .is_none_or(|at| now.duration_since(at) >= RESULT_REPEAT)
            {
                if t.result_told.is_none() {
                    msgs.push(NodeJobMsg::Job {
                        job: id.clone(),
                        state: RunState::Finished,
                    });
                }
                t.result_told = Some(now);
                msgs.push(NodeJobMsg::Result {
                    job: id.clone(),
                    result: result.clone(),
                });
            }
        }
        msgs
    }

    /// A result for a job whose driver is gone without writing one: the node or its host
    /// stopped under it. It is written, and so reported, once the node's cleanup of the
    /// job's VM and executor dir has ended, while the job's dir is still there for it.
    fn lost_driver(&self, t: &mut Track, now: Instant) -> Option<JobResult> {
        let Some(done) = &t.cleaning else {
            if now.duration_since(t.started) < DRIVER_START
                || journal::live_driver(&t.dir).is_some()
            {
                return None;
            }
            let done = Arc::new(AtomicBool::new(false));
            if let Err(e) = (self.cleaner)(self, &t.dir, done.clone()) {
                say!("cleaning up after job {}: {e:#}", t.dir.display());
                done.store(true, Ordering::Release);
            }
            t.cleaning = Some(done);
            return self.lost_driver(t, now);
        };
        if !done.load(Ordering::Acquire) {
            return None;
        }
        let result = JobResult {
            failure: Some(FailureClass::Interrupted),
            exit_code: None,
            message: Some("the job's driver ended without a result".into()),
            output_len: journal::output_len(&t.dir),
            artifacts: Vec::new(),
            usage: None,
        };
        // Written before it is reported, so the next node to read this journal agrees; tried
        // again at the next poll when it cannot be.
        journal::write_json(&t.dir.join(journal::RESULT), &result).ok()?;
        Some(result)
    }
}

fn meta_for(slot: u32, project_slot: u32, spec: &CiJob) -> Meta {
    Meta {
        gitlab_id: spec.job.id,
        slot,
        project_slot,
        project_id: spec.job.project_id,
    }
}

/// Wait for `child` up to `limit`, then stop it: SIGTERM, then SIGKILL after
/// [`driver::KILL_GRACE`].
fn wait_bounded(child: &mut std::process::Child, limit: Duration) {
    let poll = |until: Instant, child: &mut std::process::Child| {
        while Instant::now() < until {
            if !matches!(child.try_wait(), Ok(None)) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        false
    };
    if poll(Instant::now() + limit, child) {
        return;
    }
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: plain kill(2) on our own child, which has not been reaped.
        unsafe { libc::kill(pid, libc::SIGTERM) };
    }
    if !poll(Instant::now() + driver::KILL_GRACE, child) {
        // Already gone if this fails: nothing left to kill.
        let _ = child.kill();
    }
    let _ = child.wait();
}

/// Wait for `child` on a thread of its own, so it leaves no zombie behind.
fn reap(mut child: std::process::Child) {
    std::thread::spawn(move || {
        let _ = child.wait();
    });
}

/// The output past what was sent, within the window past the last ack.
fn output_chunks(id: &str, t: &mut Track) -> Vec<NodeJobMsg> {
    let len = journal::output_len(&t.dir);
    let until = len.min(t.acked.saturating_add(OUTPUT_WINDOW));
    if t.sent >= until {
        return Vec::new();
    }
    let Ok(mut file) = std::fs::File::open(t.dir.join(journal::OUTPUT)) else {
        return Vec::new();
    };
    let mut msgs = Vec::new();
    while t.sent < until {
        let want = usize::try_from(until - t.sent)
            .unwrap_or(usize::MAX)
            .min(MAX_OUTPUT_CHUNK);
        let mut buf = vec![0u8; want];
        let read = file
            .seek(SeekFrom::Start(t.sent))
            .and_then(|_| file.read(&mut buf));
        let n = match read {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        msgs.push(NodeJobMsg::Output {
            job: id.to_string(),
            offset: t.sent,
            data: vk_hub_proto::to_base64(buf.get(..n).unwrap_or_default()),
        });
        t.sent = t.sent.saturating_add(n as u64);
    }
    msgs
}

/// What to log of `reply` after the refusal `last`: why offers are refused once per change of
/// reason, not once per offer, as the hub offers again every few seconds while a reservation
/// waits.
fn refusal_change(
    last: &mut Option<(Refusal, Option<String>)>,
    reply: &OfferReply,
) -> Option<String> {
    let OfferReply::Refused { reason, message } = reply else {
        return last
            .take()
            .map(|_| "granting the hub's offers again".to_string());
    };
    let now = Some((*reason, message.clone()));
    if *last == now {
        return None;
    }
    *last = now;
    let why = match (reason, message) {
        (_, Some(m)) => m.as_str(),
        (Refusal::NotReady, None) => "the node takes no new work",
        (Refusal::Invalid, None) => "the offer is invalid",
        (Refusal::Memory, None) => "short of memory",
        (Refusal::Disk, None) => "short of disk",
        (Refusal::Cpus, None) => "short of CPUs",
        (Refusal::Policy, None) => "not allowed by the configuration",
        (Refusal::NoReservation, None) => "no such reservation",
        (Refusal::Other, None) => "for another reason",
    };
    Some(format!("refusing the hub's offers: {why}"))
}

/// The node's readiness for new work, from its steering state.
pub fn ready(state: vk_hub_proto::NodeState, acquiring: bool) -> bool {
    state == vk_hub_proto::NodeState::Ready && acquiring
}

/// A node's jobs for a test: admission against `budget_mib` in `node_dir`, and a driver that
/// writes its output and result at once.
#[cfg(test)]
pub(crate) fn for_test(node_dir: &Path, cfg: Config, budget_mib: Option<u64>) -> Arc<Jobs> {
    let limits = Limits {
        admit_dir: node_dir.join("admit"),
        jobs_dir: node_dir.join("vm-jobs"),
        budget_mib,
        disk_admission: false,
        max_cpus: 8,
    };
    Jobs::open_with(
        node_dir,
        Arc::new(cfg),
        limits,
        tests::fake_driver,
        tests::fake_cleanup,
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use vk_hub_proto::dispatch::CancelMode;
    use vk_hub_proto::job::Envelope;

    pub(crate) fn fake_driver(
        _: &Jobs,
        dir: &Path,
        held: Option<crate::admit::Reservation>,
    ) -> Result<()> {
        drop(held);
        let meta = journal::read_meta(dir)?;
        let output = format!("$ make\nGitLab job {} done\n", meta.gitlab_id);
        std::fs::write(dir.join(journal::OUTPUT), &output)?;
        std::fs::write(dir.join(journal::STAGE), "step_script")?;
        let result = JobResult {
            failure: None,
            exit_code: None,
            message: None,
            output_len: output.len() as u64,
            artifacts: Vec::new(),
            usage: None,
        };
        journal::write_json(&dir.join(journal::RESULT), &result)
    }

    /// Marks the job's dir as cleaned up, and ends at once.
    pub(crate) fn fake_cleanup(_: &Jobs, dir: &Path, done: Arc<AtomicBool>) -> Result<()> {
        std::fs::write(dir.join("cleaned"), "")?;
        done.store(true, Ordering::Release);
        Ok(())
    }

    pub(crate) fn spec(id: u64) -> JobSpec {
        let mut job = CiJob::default();
        job.job.id = id;
        job.job.project_id = 12;
        job.job.project_path = "acme/web".into();
        job.token = "glcbt-secret".into();
        job.timeout_secs = 60;
        job.sources.repo_url = "https://gitlab.example.com/acme/web.git".into();
        JobSpec::GitlabCi(job)
    }

    pub(crate) fn hex(c: &str) -> String {
        c.repeat(32)
    }

    pub(crate) fn envelope(mem_mib: u64) -> Envelope {
        Envelope {
            mem_mib,
            cpus: 2,
            disk_bytes: 0,
        }
    }

    fn jobs(tag: &str, budget: Option<u64>) -> (Arc<Jobs>, PathBuf) {
        let dir = std::env::temp_dir().join(format!("vk-node-jobs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg: Config =
            toml::from_str(&format!("state_dir = {:?}\n", dir.display().to_string())).unwrap();
        (for_test(&dir, cfg, budget), dir)
    }

    fn start(job: &str, reservation: Option<String>, id: u64) -> HubJobMsg {
        HubJobMsg::Start(Box::new(JobStart {
            job: job.into(),
            reservation,
            envelope: envelope(4096),
            spec: spec(id),
        }))
    }

    #[test]
    fn a_refusal_is_logged_once_per_reason() {
        let mut last = None;
        let refused = |reason, message: &str| OfferReply::Refused {
            reason,
            message: Some(message.into()),
        };
        let disk = refused(Refusal::Other, "reading the free space of /x");
        assert_eq!(
            refusal_change(&mut last, &disk).as_deref(),
            Some("refusing the hub's offers: reading the free space of /x")
        );
        assert_eq!(refusal_change(&mut last, &disk), None, "the same again");
        assert!(refusal_change(&mut last, &refused(Refusal::Memory, "short")).is_some());
        let granted = OfferReply::Accepted { lease_secs: 90 };
        assert!(refusal_change(&mut last, &granted).is_some());
        assert_eq!(refusal_change(&mut last, &granted), None);
        assert!(refusal_change(&mut last, &refused(Refusal::Memory, "short")).is_some());
    }

    #[test]
    fn a_job_runs_on_its_reservation_and_reports_until_recorded() {
        let (jobs, dir) = jobs("flow", Some(8192));
        let now = Instant::now();
        let offer = HubJobMsg::Offer {
            reservation: hex("a"),
            envelope: envelope(6144),
            lease_secs: 90,
        };
        assert_eq!(
            jobs.handle(offer, true, now),
            vec![NodeJobMsg::OfferReply {
                reservation: hex("a"),
                reply: OfferReply::Accepted { lease_secs: 90 }
            }]
        );
        let replies = jobs.handle(start(&hex("b"), Some(hex("a")), 4242), true, now);
        assert_eq!(
            replies,
            vec![
                NodeJobMsg::Job {
                    job: hex("b"),
                    state: RunState::Accepted
                },
                NodeJobMsg::Lease {
                    reservation: hex("a"),
                    state: LeaseState::Gone {
                        why: LeaseEnd::Started
                    }
                },
            ]
        );
        // The journal holds the spec and the GitLab job's identity, without its token.
        let job_dir = dir.join("jobs").join(hex("b"));
        assert!(journal::read_start(&job_dir).is_ok());
        let response = std::fs::read_to_string(job_dir.join(env::JOB_RESPONSE)).unwrap();
        assert!(response.contains("4242") && !response.contains("glcbt"));
        // A redelivered start is answered from the journal, not run again: this driver has
        // already finished.
        let again = jobs.handle(start(&hex("b"), Some(hex("a")), 4242), true, now);
        assert_eq!(
            again,
            vec![NodeJobMsg::Job {
                job: hex("b"),
                state: RunState::Finished
            }]
        );
        // Output first; the result only once every byte of it is acked.
        let msgs = jobs.poll(now, false);
        let Some(NodeJobMsg::Output {
            offset: 0, data, ..
        }) = msgs.iter().find(|m| matches!(m, NodeJobMsg::Output { .. }))
        else {
            panic!("no output in {msgs:?}");
        };
        let data = vk_hub_proto::from_base64(data).unwrap();
        assert_eq!(data, b"$ make\nGitLab job 4242 done\n");
        assert!(!msgs.iter().any(|m| matches!(m, NodeJobMsg::Result { .. })));
        jobs.handle(
            HubJobMsg::OutputAck {
                job: hex("b"),
                offset: data.len() as u64,
            },
            true,
            now,
        );
        let msgs = jobs.poll(now, false);
        assert!(msgs.contains(&NodeJobMsg::Job {
            job: hex("b"),
            state: RunState::Finished
        }));
        assert!(msgs.iter().any(|m| matches!(m, NodeJobMsg::Result { .. })));
        // Repeated until recorded, not at once.
        assert!(jobs.poll(now, false).is_empty());
        assert!(
            jobs.poll(now + RESULT_REPEAT, false)
                .iter()
                .any(|m| matches!(m, NodeJobMsg::Result { .. }))
        );
        jobs.handle(HubJobMsg::Recorded { job: hex("b") }, true, now);
        assert!(!job_dir.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_start_without_a_held_reservation_is_admitted_or_refused_at_once() {
        let (jobs, dir) = jobs("noresv", Some(2048));
        let now = Instant::now();
        let refused = jobs.handle(start(&hex("b"), Some(hex("a")), 1), true, now);
        assert!(matches!(
            refused.as_slice(),
            [NodeJobMsg::Job {
                state: RunState::Refused {
                    reason: Refusal::NoReservation,
                    ..
                },
                ..
            }]
        ));
        assert!(!dir.join("jobs").join(hex("b")).exists());
        let not_ready = jobs.handle(start(&hex("c"), None, 2), false, now);
        assert!(matches!(
            not_ready.as_slice(),
            [NodeJobMsg::Job {
                state: RunState::Refused {
                    reason: Refusal::NotReady,
                    ..
                },
                ..
            }]
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_reconnect_resends_from_the_hubs_ack_and_leases_lapse() {
        let (jobs, dir) = jobs("reconnect", None);
        let now = Instant::now();
        jobs.handle(
            HubJobMsg::Offer {
                reservation: hex("a"),
                envelope: envelope(1),
                lease_secs: 5,
            },
            true,
            now,
        );
        jobs.handle(start(&hex("b"), None, 7), true, now);
        assert!(!jobs.poll(now, false).is_empty());
        // A new session: held lists both, and output waits for the hub's offset.
        let NodeJobMsg::Held(held) = jobs.held(now) else {
            panic!("not held");
        };
        assert_eq!(held.reservations.len(), 1);
        assert_eq!(held.jobs.len(), 1);
        assert!(held.jobs[0].finished);
        let lapsed = jobs.poll(now + Duration::from_secs(5), false);
        assert_eq!(
            lapsed,
            vec![NodeJobMsg::Lease {
                reservation: hex("a"),
                state: LeaseState::Gone {
                    why: LeaseEnd::Expired
                }
            }]
        );
        jobs.handle(
            HubJobMsg::OutputAck {
                job: hex("b"),
                offset: 2,
            },
            true,
            now,
        );
        let msgs = jobs.poll(now, false);
        assert!(matches!(
            msgs.first(),
            Some(NodeJobMsg::Output { offset: 2, .. })
        ));
        // A cancel of a finished job changes nothing; one of an unknown job is refused.
        assert!(
            jobs.handle(
                HubJobMsg::Cancel {
                    job: hex("b"),
                    mode: CancelMode::Immediate
                },
                true,
                now
            )
            .is_empty()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_start_refused_after_its_reservation_was_taken_releases_it() {
        let (jobs, dir) = jobs("refused-taken", Some(8192));
        let now = Instant::now();
        jobs.handle(
            HubJobMsg::Offer {
                reservation: hex("a"),
                envelope: envelope(1024),
                lease_secs: 90,
            },
            true,
            now,
        );
        // Another holder has the GitLab job's ledger name: the reservation cannot become it.
        let ask = crate::admit::Ask {
            mem: Some(crate::admit::MemAsk {
                want_mib: 1024,
                budget_mib: 8192,
            }),
            disk: None,
        };
        let _other = crate::admit::try_acquire(&dir.join("admit"), "4242", &ask)
            .unwrap()
            .unwrap();
        let replies = jobs.handle(start(&hex("b"), Some(hex("a")), 4242), true, now);
        assert!(
            matches!(
                replies.as_slice(),
                [
                    NodeJobMsg::Job {
                        state: RunState::Refused { .. },
                        ..
                    },
                    NodeJobMsg::Lease {
                        state: LeaseState::Gone {
                            why: LeaseEnd::Released
                        },
                        ..
                    },
                ]
            ),
            "{replies:?}"
        );
        assert!(!dir.join("jobs").join(hex("b")).exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_node_side_cleanup_is_stopped_at_its_bound() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let started = Instant::now();
        wait_bounded(&mut child, Duration::from_millis(200));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(child.try_wait().unwrap().is_some(), "reaped");
    }

    /// A job journaled with its meta, as the session leaves one, and the dir it is in.
    fn journaled(dir: &Path, job: &str, id: u64) -> PathBuf {
        let job_dir = dir.join("jobs").join(job);
        std::fs::create_dir_all(&job_dir).unwrap();
        let HubJobMsg::Start(start) = start(job, None, id) else {
            unreachable!()
        };
        journal::write_json(&job_dir.join(journal::START), &*start).unwrap();
        journal::write_json(&job_dir.join(journal::META), &meta_for(0, 0, &spec_job(id))).unwrap();
        job_dir
    }

    /// The jobs of `dir`, as a restarted node opens them.
    fn reopen(dir: &Path) -> Arc<Jobs> {
        let cfg: Config =
            toml::from_str(&format!("state_dir = {:?}\n", dir.display().to_string())).unwrap();
        for_test(dir, cfg, None)
    }

    fn spec_job(id: u64) -> CiJob {
        let JobSpec::GitlabCi(job) = spec(id);
        job
    }

    fn interrupted() -> JobResult {
        JobResult {
            failure: Some(FailureClass::Interrupted),
            exit_code: None,
            message: None,
            output_len: 0,
            artifacts: Vec::new(),
            usage: None,
        }
    }

    #[test]
    fn a_restarted_node_finds_its_journaled_jobs() {
        let (_, dir) = jobs("open", None);
        // Taken down before it was accepted: no meta, never heard of by the hub.
        let unaccepted = dir.join("jobs").join(hex("a"));
        std::fs::create_dir_all(&unaccepted).unwrap();
        std::fs::write(unaccepted.join(journal::START), "{}").unwrap();
        let finished = journaled(&dir, &hex("b"), 2);
        journal::write_json(&finished.join(journal::RESULT), &interrupted()).unwrap();
        journaled(&dir, &hex("c"), 3);
        let jobs = reopen(&dir);
        assert!(!unaccepted.exists());
        let NodeJobMsg::Held(held) = jobs.held(Instant::now()) else {
            panic!("not held");
        };
        let state = |id: &str| {
            held.jobs
                .iter()
                .find(|j| j.job == id)
                .map(|j| (j.finished, j.state.clone()))
        };
        assert_eq!(state(&hex("a")), None);
        assert_eq!(state(&hex("b")), Some((true, RunState::Finished)));
        assert_eq!(state(&hex("c")), Some((false, RunState::Accepted)));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_job_whose_driver_is_gone_ends_interrupted_and_is_cleaned_up() {
        let (_, dir) = jobs("lost", None);
        let job_dir = journaled(&dir, &hex("b"), 2);
        let jobs = reopen(&dir);
        let now = Instant::now();
        jobs.held(now);
        jobs.handle(
            HubJobMsg::OutputAck {
                job: hex("b"),
                offset: 0,
            },
            true,
            now,
        );
        // A driver still starting has the benefit of the doubt.
        assert!(jobs.poll(now, false).is_empty());
        assert!(!job_dir.join("cleaned").exists());
        let msgs = jobs.poll(now + DRIVER_START, false);
        let Some(NodeJobMsg::Result { result, .. }) =
            msgs.iter().find(|m| matches!(m, NodeJobMsg::Result { .. }))
        else {
            panic!("no result in {msgs:?}");
        };
        assert_eq!(result.failure, Some(FailureClass::Interrupted));
        assert_eq!(journal::read_result(&job_dir).as_ref(), Some(result));
        assert!(job_dir.join("cleaned").exists(), "cleaned up");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The flag of the one cleanup [`slow_cleanup`] has started.
    static SLOW_CLEANUP: Mutex<Option<Arc<AtomicBool>>> = Mutex::new(None);

    fn slow_cleanup(_: &Jobs, _: &Path, done: Arc<AtomicBool>) -> Result<()> {
        *lock(&SLOW_CLEANUP) = Some(done);
        Ok(())
    }

    #[test]
    fn a_lost_drivers_result_waits_for_the_nodes_cleanup() {
        let (_, dir) = jobs("lost-slow", None);
        let job_dir = journaled(&dir, &hex("b"), 2);
        let cfg: Config =
            toml::from_str(&format!("state_dir = {:?}\n", dir.display().to_string())).unwrap();
        let limits = Limits {
            admit_dir: dir.join("admit"),
            jobs_dir: dir.join("vm-jobs"),
            budget_mib: None,
            disk_admission: false,
            max_cpus: 8,
        };
        let jobs = Jobs::open_with(&dir, Arc::new(cfg), limits, fake_driver, slow_cleanup);
        let now = Instant::now();
        jobs.held(now);
        jobs.handle(
            HubJobMsg::OutputAck {
                job: hex("b"),
                offset: 0,
            },
            true,
            now,
        );
        let later = now + DRIVER_START;
        assert!(jobs.poll(later, false).is_empty(), "cleaning up");
        assert!(jobs.poll(later, false).is_empty(), "still");
        assert!(journal::read_result(&job_dir).is_none());
        let done = lock(&SLOW_CLEANUP).take().expect("one cleanup started");
        done.store(true, Ordering::Release);
        let msgs = jobs.poll(later, false);
        assert!(
            msgs.iter().any(|m| matches!(m, NodeJobMsg::Result { .. })),
            "{msgs:?}"
        );
        assert!(journal::read_result(&job_dir).is_some());
        assert!(lock(&SLOW_CLEANUP).is_none(), "started once");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_cancel_reaches_the_driver_through_the_journal() {
        let (_, dir) = jobs("cancel", None);
        let job_dir = journaled(&dir, &hex("b"), 2);
        let jobs = reopen(&dir);
        let now = Instant::now();
        jobs.held(now);
        jobs.handle(
            HubJobMsg::OutputAck {
                job: hex("b"),
                offset: 0,
            },
            true,
            now,
        );
        let cancel = |mode| {
            jobs.handle(
                HubJobMsg::Cancel {
                    job: hex("b"),
                    mode,
                },
                true,
                now,
            )
        };
        assert!(cancel(CancelMode::Graceful).is_empty());
        assert_eq!(journal::read_cancel(&job_dir), Some(CancelMode::Graceful));
        assert!(cancel(CancelMode::Immediate).is_empty());
        assert_eq!(journal::read_cancel(&job_dir), Some(CancelMode::Immediate));
        let unknown = jobs.handle(
            HubJobMsg::Cancel {
                job: hex("c"),
                mode: CancelMode::Immediate,
            },
            true,
            now,
        );
        assert!(matches!(
            unknown.as_slice(),
            [NodeJobMsg::Job {
                state: RunState::Refused {
                    reason: Refusal::Invalid,
                    ..
                },
                ..
            }]
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_job_the_hub_disowns_reports_its_result_and_goes() {
        let (_, dir) = jobs("disowned", None);
        let job_dir = journaled(&dir, &hex("b"), 2);
        std::fs::write(job_dir.join(journal::OUTPUT), "some output").unwrap();
        let jobs = reopen(&dir);
        let now = Instant::now();
        jobs.held(now);
        // The hub does not know the job: a cancel, no ack.
        assert!(
            jobs.handle(
                HubJobMsg::Cancel {
                    job: hex("b"),
                    mode: CancelMode::Immediate
                },
                true,
                now
            )
            .is_empty()
        );
        assert_eq!(journal::read_cancel(&job_dir), Some(CancelMode::Immediate));
        // Nothing until the driver ends, and never its output.
        assert!(jobs.poll(now, false).is_empty());
        journal::write_json(&job_dir.join(journal::RESULT), &interrupted()).unwrap();
        let msgs = jobs.poll(now, false);
        assert!(!msgs.iter().any(|m| matches!(m, NodeJobMsg::Output { .. })));
        assert!(msgs.iter().any(|m| matches!(m, NodeJobMsg::Result { .. })));
        jobs.handle(HubJobMsg::Recorded { job: hex("b") }, true, now);
        assert!(!job_dir.exists());
        let NodeJobMsg::Held(held) = jobs.held(now) else {
            panic!("not held");
        };
        assert!(held.jobs.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}
