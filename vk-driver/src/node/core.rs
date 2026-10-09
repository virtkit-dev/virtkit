//! Shared state for `vk node run`: persisted state ([`Persisted`]), the last calculated
//! concurrency, drain progress, and managed runner process state. The session reads a
//! [`Report`] and applies hub messages; the runner supervisor follows [`Core::acquire`];
//! [`Core::control`] sets concurrency and completes drains once nothing remains running.
//!
//! Without a hub session, the node keeps applying its last desired state and persisted
//! drain or quarantine.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::watch;
use vk_hub_proto::{
    Acquisition, Command, CommandAck, Concurrency, DesiredState, DrainProgress, NodeState,
    Operation, PlacedIntake, Report, RunnerMode, RunnerState,
};

use super::state::{Abilities, Issuer, Persisted, Work};
use super::update::Binary;
use crate::config::Config;

/// The node's gitlab-runner, as `[node] runner` says.
pub enum Runner {
    /// Run by the node: its process, as its supervisor reports it.
    Managed(watch::Receiver<RunnerState>),
    /// Run by something else, which may take jobs whatever the node is told.
    External,
    /// None: the node runs only the hub's placed jobs, all of which it can stop.
    None,
}

pub struct Core {
    dir: PathBuf,
    mode: RunnerMode,
    /// A managed runner's process, as its supervisor reports it; `None` otherwise.
    runner: Option<watch::Receiver<RunnerState>>,
    persisted: Mutex<Persisted>,
    concurrency: Mutex<Option<Concurrency>>,
    /// Why the last attempt at setting the concurrency failed, if it did.
    concurrency_error: Mutex<Option<String>>,
    /// Why the last pass at a drain failed, if it did: logged when it changes.
    drain_error: Mutex<Option<String>>,
    /// Which of a drain's conditions held at the last pass, while draining.
    drain: Mutex<Option<DrainProgress>>,
    /// Since when, in seconds since the epoch, a reset's drain has waited only on jobs
    /// admitted but with no supervisor.
    preparing_since: Mutex<Option<u64>>,
    /// Whether the runner may take jobs, for a managed runner's supervisor to follow.
    acquire: watch::Sender<bool>,
    /// Bumped on every change to what the node tells the hub: its report or its unrecorded
    /// acks.
    changed: watch::Sender<u64>,
    /// Whether a session with the hub is up: what an update on trial waits for.
    connected: watch::Sender<bool>,
    /// How [`Core::leave`] executes a binary.
    exec: fn(&Binary, Option<u64>) -> anyhow::Error,
    /// Whether an update may install an older version than this one (`[node]
    /// allow_downgrade`).
    allow_downgrade: AtomicBool,
    /// What an update's release must be signed with (`[node] release_keys`).
    release_policy: Mutex<crate::release_key::Policy>,
    /// The node's configured intake of hub-placed jobs.
    placed: Mutex<PlacedIntake>,
}

impl Core {
    /// Load the state in `dir`, for `issuer` — the hub and node ID the node is enrolled as —
    /// for a node with `runner`.
    pub fn open(dir: &Path, issuer: Issuer, runner: Runner) -> Result<Arc<Core>> {
        let (mode, runner) = match runner {
            Runner::Managed(state) => (RunnerMode::Managed, Some(state)),
            Runner::External => (RunnerMode::External, None),
            Runner::None => (RunnerMode::None, None),
        };
        let mut persisted = Persisted::load(dir)?;
        let before = persisted.clone();
        if persisted.adopt_issuer(issuer) {
            say!(
                "the node state was kept for another enrollment; its desired state and command \
                 journal are dropped, its {:?} state is kept",
                persisted.state
            );
        }
        if persisted != before {
            persisted.save(dir)?;
        }
        if mode == RunnerMode::External && persisted.state == NodeState::Draining {
            say!("the node is draining with an external runner, which may still take jobs");
        }
        let (acquire, _) = watch::channel(!persisted.acquisition_stopped());
        let (changed, _) = watch::channel(0);
        Ok(Arc::new(Core {
            dir: dir.to_path_buf(),
            mode,
            runner,
            persisted: Mutex::new(persisted),
            concurrency: Mutex::new(None),
            concurrency_error: Mutex::new(None),
            drain_error: Mutex::new(None),
            drain: Mutex::new(None),
            preparing_since: Mutex::new(None),
            acquire,
            changed,
            connected: watch::Sender::new(false),
            exec: super::update::exec,
            allow_downgrade: AtomicBool::new(false),
            release_policy: Mutex::new(crate::release_key::Policy::default()),
            placed: Mutex::new(PlacedIntake::default()),
        }))
    }

    /// Whether the runner may take jobs: false while the hub has stopped acquisition and while
    /// the node is draining, drained or quarantined. A managed runner's supervisor follows it.
    pub fn acquire(&self) -> watch::Receiver<bool> {
        self.acquire.subscribe()
    }

    /// Apply `f` and save the result before publishing it to the rest of the node, so a
    /// command's journal entry is on disk before anything acts on it.
    fn update<R>(&self, f: impl FnOnce(&mut Persisted) -> R) -> Result<R> {
        let mut persisted = lock(&self.persisted);
        let mut next = persisted.clone();
        let out = f(&mut next);
        if next != *persisted {
            next.save(&self.dir)?;
            *persisted = next;
            // `send_replace`: kept whether or not a supervisor listens.
            self.acquire.send_replace(!persisted.acquisition_stopped());
            drop(persisted);
            self.bump();
        }
        Ok(out)
    }

    fn bump(&self) {
        self.changed.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// A receiver that sees every change to what the node tells the hub.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    pub fn apply_desired(&self, desired: DesiredState) -> Result<bool> {
        self.update(|p| p.apply_desired(desired))
    }

    /// Journal `command` and carry it out. An external runner cannot be stopped, so a reset is
    /// refused, and a drain or a quarantine leaves it running; an update is refused when the
    /// node could not install it, or may not. A node with no runner stops all it runs.
    pub fn command(&self, command: Command, now: u64) -> Result<CommandAck> {
        let update = match &command.op {
            // Looked at only for an update: it reads the filesystem.
            Operation::Update {
                version,
                sha256,
                signature,
                ..
            } => {
                let installed = lock(&self.persisted).installed.clone();
                super::update::can_replace(installed.as_deref(), &self.dir)
                    .and_then(|()| {
                        super::update::check_version(
                            env!("CARGO_PKG_VERSION"),
                            version,
                            self.allow_downgrade(),
                        )
                    })
                    .and_then(|()| {
                        self.release_policy()
                            .check(sha256, version, signature.as_deref())
                    })
            }
            _ => Ok(()),
        };
        let can = Abilities {
            drainable: self.mode != RunnerMode::External,
            update,
        };
        self.update(|p| p.command_as(command, now, &can))
    }

    /// Change the persisted state through `f` and execute `exe` in this process's place —
    /// with `alarm(2)` armed for the trial deadline `alarm_at` when given — holding the
    /// state's lock throughout: nothing this process does meanwhile, an ack recorded or a
    /// runner started for the state `f` leaves, can come between the change on disk and the
    /// binary that follows it. Returns only on failure, with the state on disk as it was
    /// before.
    pub fn leave(
        &self,
        f: impl FnOnce(&mut Persisted),
        exe: &Binary,
        alarm_at: Option<u64>,
    ) -> anyhow::Error {
        let persisted = lock(&self.persisted);
        let mut next = persisted.clone();
        f(&mut next);
        if let Err(e) = next.save(&self.dir) {
            return e;
        }
        let e = (self.exec)(exe, alarm_at);
        // Not executed: the change is undone on disk — it described a binary that is not
        // running.
        if let Err(undo) = persisted.save(&self.dir) {
            return e.context(format!("and restoring the node state failed: {undo:#}"));
        }
        e
    }

    /// Execute binaries through `exec` rather than for real.
    #[cfg(test)]
    pub fn set_exec(&mut self, exec: fn(&Binary, Option<u64>) -> anyhow::Error) {
        self.exec = exec;
    }

    /// Change the persisted state through `f`, as a command would: on disk first.
    pub fn change<R>(&self, f: impl FnOnce(&mut Persisted) -> R) -> Result<R> {
        self.update(f)
    }

    /// The persisted state as it stands.
    pub fn persisted(&self) -> Persisted {
        lock(&self.persisted).clone()
    }

    /// Let updates install older versions, as `[node] allow_downgrade` says.
    pub fn set_allow_downgrade(&self, allow: bool) {
        self.allow_downgrade.store(allow, Ordering::Relaxed);
    }

    pub fn allow_downgrade(&self) -> bool {
        self.allow_downgrade.load(Ordering::Relaxed)
    }

    /// Require what `policy` says of every update's release, as `[node] release_keys` and
    /// `require_signed` say.
    pub fn set_release_policy(&self, policy: crate::release_key::Policy) {
        *lock(&self.release_policy) = policy;
    }

    pub fn release_policy(&self) -> crate::release_key::Policy {
        lock(&self.release_policy).clone()
    }

    /// Set placed-job intake and log when the host's own runner prevents it.
    pub fn set_placed(&self, placed: PlacedIntake) {
        if let Some(why) = &placed.runner {
            say!("this host runs its own gitlab-runner ({why}): it takes no placed jobs");
        }
        self.set(&self.placed, placed);
    }

    /// The node's intake of hub-placed jobs.
    pub fn placed(&self) -> PlacedIntake {
        lock(&self.placed).clone()
    }

    /// The node dir.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Note whether a session with the hub is up.
    pub fn set_connected(&self, up: bool) {
        self.connected.send_replace(up);
    }

    /// Follows whether a session with the hub is up.
    pub fn connected(&self) -> watch::Receiver<bool> {
        self.connected.subscribe()
    }

    pub fn recorded(&self, ack: &CommandAck, now: u64) -> Result<()> {
        self.update(|p| {
            p.recorded(ack, now);
        })
    }

    pub fn unrecorded(&self) -> Vec<CommandAck> {
        lock(&self.persisted).unrecorded()
    }

    pub fn hub_ceiling(&self) -> Option<u32> {
        lock(&self.persisted).hub_ceiling()
    }

    pub fn state(&self) -> NodeState {
        lock(&self.persisted).state
    }

    /// Replace the value behind `m`, reporting a change.
    fn set<T: PartialEq>(&self, m: &Mutex<T>, value: T) {
        let mut slot = lock(m);
        if *slot != value {
            *slot = value;
            drop(slot);
            self.bump();
        }
    }

    /// The node's steering state as it would report it now; the session adds the workloads.
    pub fn report(&self) -> Report {
        let persisted = lock(&self.persisted).clone();
        let stopped = persisted.acquisition_stopped();
        let runner = self.runner.as_ref().map(|r| *r.borrow());
        let placed = self.placed();
        let mut unsupported = Vec::new();
        // A host with no runner of its own runs only the hub's jobs, which a stop stops.
        if stopped && self.mode == RunnerMode::External && placed.runner.is_some() {
            unsupported.push(
                "stopping acquisition: the runner is external ([node] runner = \"external\"), \
                 so it may still take jobs"
                    .to_string(),
            );
        }
        Report {
            applied: persisted.applied.clone(),
            unsupported,
            state: Some(persisted.state),
            // Stopped only once a managed runner has exited: until then it may be one that
            // never heard its signal. With no runner, the node takes no placed job at once.
            acquisition: Some(
                if stopped
                    && (self.mode == RunnerMode::None || runner == Some(RunnerState::Stopped))
                {
                    Acquisition::Stop
                } else {
                    Acquisition::Run
                },
            ),
            runner: Some(self.mode),
            runner_state: runner,
            concurrency: *lock(&self.concurrency),
            concurrency_error: lock(&self.concurrency_error).clone(),
            // Only while draining: the pass that finishes a drain clears it a moment later.
            drain: (persisted.state == NodeState::Draining)
                .then(|| *lock(&self.drain))
                .flatten(),
            update: persisted.update.clone(),
            tools: persisted.tools_progress.clone(),
            placed: Some(placed),
            ..Report::default()
        }
    }

    /// Set the runner's concurrency every `every`, and whenever the state or a managed runner
    /// changes; while draining, check whether the drain is complete. Runs until `stop`.
    ///
    /// Only the timer may raise the concurrency: the estimate climbs one step per pass, and
    /// passes a change sets off — every report bumps a change, this loop's own included —
    /// would otherwise take it up several steps at once. A change may lower it at once.
    pub async fn control(
        self: Arc<Self>,
        cfg: Arc<Config>,
        every: Duration,
        mut stop: watch::Receiver<bool>,
    ) {
        let mut changes = self.subscribe();
        let mut runner = self.runner.clone();
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let may_rise = tokio::select! {
                _ = tick.tick() => true,
                _ = changes.changed() => false,
                // The runner's state is in every report, and nothing else marks it changed.
                () = runner_changed(runner.as_mut()) => {
                    self.bump();
                    false
                }
                _ = stop.wait_for(|&s| s) => return,
            };
            let core = self.clone();
            let cfg = cfg.clone();
            // Off the runtime: it reads files and takes the ledger's lock.
            if let Err(e) = tokio::task::spawn_blocking(move || core.step(&cfg, may_rise)).await {
                say!("the concurrency loop failed: {e}");
            }
        }
    }

    /// Update concurrency, then drain progress, independently of either's failure. An invalid
    /// concurrency config must not block a drain. Concurrency errors are reported as well as
    /// logged; each error is logged when it changes, not at every pass.
    fn step(&self, cfg: &Config, may_rise: bool) {
        let concurrency =
            crate::schedule::decide_with(cfg, self.hub_ceiling(), may_rise).and_then(|decision| {
                crate::schedule::apply(cfg, &decision)?;
                Ok(decision)
            });
        match concurrency {
            Ok(decision) => {
                self.set(
                    &self.concurrency,
                    Some(Concurrency {
                        estimate: decision.estimate,
                        hub_ceiling: decision.hub_ceiling,
                        local_ceiling: decision.ceiling,
                        effective: decision.effective,
                    }),
                );
                self.set(&self.concurrency_error, None);
            }
            Err(e) => {
                let message = explain_denied(cfg, &e);
                if lock(&self.concurrency_error).as_deref() != Some(&message) {
                    say!("setting the runner's concurrency: {message}");
                }
                self.set(&self.concurrency_error, Some(message));
            }
        }
        let drained = self.drain_step(cfg);
        let message = drained.as_ref().err().map(|e| explain_denied(cfg, e));
        let mut last = lock(&self.drain_error);
        if let Some(message) = &message
            && last.as_ref() != Some(message)
        {
            say!("{message}");
        }
        *last = message;
    }

    /// While draining, read where the drain stands and finish it once complete.
    fn drain_step(&self, cfg: &Config) -> Result<()> {
        let now = super::session::now_secs();
        if self.update(|p| p.drain_expired(now))? {
            say!("the command the node drained for expired before the drain finished");
        }
        if self.state() != NodeState::Draining {
            self.set(&self.drain, None);
            *lock(&self.preparing_since) = None;
            return Ok(());
        }
        let held = crate::admit::committed(&cfg.state_dir().join("admit"))
            .context("reading the admission ledger for the drain")?;
        let jobs = crate::vm::live_job_supervisors(&cfg.state_dir().join("jobs"))
            .context("counting the jobs left for the drain")?;
        // Count placed jobs from acceptance to result, including before supervisor startup
        // and during cleanup after driver exit. Match supervisors by GitLab job ID alone: a
        // host taking placed jobs runs no runner whose jobs could share one, but while it is
        // moved over, a job its former runner left running can, and hides a placed job from
        // the count until either ends.
        let placed = super::jobs::journal::unfinished(&self.dir.join("jobs"))
            .context("counting the placed jobs left for the drain")?;
        let unsupervised = placed
            .iter()
            .filter(|id| {
                let name = id.to_string();
                !jobs
                    .iter()
                    .any(|(dir, _)| dir.file_name() == Some(name.as_ref()))
            })
            .count();
        let progress = DrainProgress {
            // With no runner, the placed jobs stand in for it: a reset, which waits for the
            // runner alone, then waits for each to have its result. A supervisor left past
            // its result, by a failed cleanup, is what the reset is for.
            runner_stopped: match self.mode {
                RunnerMode::Managed => {
                    self.runner.as_ref().map(|r| *r.borrow()) == Some(RunnerState::Stopped)
                }
                RunnerMode::External => false,
                RunnerMode::None => placed.is_empty(),
            },
            ledger_empty: held.granted == 0 && held.ahead == 0,
            active_jobs: u32::try_from(jobs.len().saturating_add(unsupervised)).unwrap_or(u32::MAX),
        };
        self.set(&self.drain, Some(progress));
        // Reset stops supervisors left by failed cleanup; waiting for them or the admission
        // entries they hold would block it. Drain waits for the runner, pending admissions,
        // and admitted jobs without supervisors: a `prepare` can outlive its runner, and reset
        // cannot stop it or safely remove its job dir. It must exit or hand off to a supervisor
        // within `PREPARE_WAIT`, or the reset fails.
        let for_reset = lock(&self.persisted)
            .job
            .as_ref()
            .is_some_and(|j| matches!(j.work, Work::Reset { .. }));
        let done = if for_reset {
            let preparing: Vec<_> = held
                .mem
                .iter()
                .filter(|(name, _)| {
                    !jobs
                        .iter()
                        .any(|(dir, _)| dir.file_name() == Some(name.as_os_str()))
                })
                .map(|(name, _)| name.to_string_lossy())
                .collect();
            let waited = {
                let mut since = lock(&self.preparing_since);
                if progress.runner_stopped && held.ahead == 0 && !preparing.is_empty() {
                    now.saturating_sub(*since.get_or_insert(now))
                } else {
                    *since = None;
                    0
                }
            };
            if waited >= PREPARE_WAIT.as_secs() {
                let message = format!(
                    "job(s) {} admitted with no live supervisor for {}s; a reset does not \
                     stop what holds them",
                    preparing.join(", "),
                    PREPARE_WAIT.as_secs()
                );
                if self.update(|p| p.reset_blocked(message.clone()))? {
                    say!("the reset failed: {message}");
                    self.set(&self.drain, None);
                    *lock(&self.preparing_since) = None;
                }
                return Ok(());
            }
            progress.runner_stopped && held.ahead == 0 && preparing.is_empty()
        } else {
            drained(&progress, self.mode == RunnerMode::Managed)
        };
        if done && self.update(|p| p.finish_drain(now))? {
            say!("drained");
            self.set(&self.drain, None);
        }
        Ok(())
    }
}

/// Explain a CI user mismatch, when found, for permission errors; otherwise return `e`.
/// Raw permission errors name the first entry encountered, so their wording can change
/// on every pass.
fn explain_denied(cfg: &Config, e: &anyhow::Error) -> String {
    let denied = e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
    });
    match denied.then(|| super::ci_user::this_node(cfg)).flatten() {
        Some(why) => why,
        None => format!("{e:#}"),
    }
}

/// How long a reset's drain waits on a job admitted but with no supervisor before it fails.
const PREPARE_WAIT: Duration = Duration::from_secs(600);

/// Whether a drain is complete: a `managed` runner has exited — which it does on `SIGQUIT`
/// only once its jobs, their cleanup stage included, are over — the ledger holds and awaits
/// nothing, and no job is left: no placed job without its result, and no job supervisor,
/// which catches a job whose cleanup failed and left its VM up. An external runner is not
/// waited for: it does not stop, and its jobs show in the ledger and as supervisors while they
/// run. Nor is there one to wait for on a node with none.
fn drained(p: &DrainProgress, managed: bool) -> bool {
    (p.runner_stopped || !managed) && p.ledger_empty && p.active_jobs == 0
}

/// Once a managed runner's state changes. Never for an external runner, nor once the
/// supervisor has gone: nothing is left to change it.
async fn runner_changed(runner: Option<&mut watch::Receiver<RunnerState>>) {
    if let Some(r) = runner
        && r.changed().await.is_ok()
    {
        return;
    }
    std::future::pending().await
}

/// A lock whose holder panicked still guards whole values — each is replaced in one
/// assignment — so poisoning is ignored.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vk_hub_proto::{Operation, Outcome};

    fn issuer() -> Issuer {
        Issuer {
            hub: "https://hub".into(),
            node_id: "ab".repeat(16),
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-node-core-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("state")).unwrap();
        dir
    }

    fn cfg(dir: &Path) -> Arc<Config> {
        Arc::new(
            toml::from_str(&format!(
                "state_dir = {:?}\n[executor.schedule]\nmax_concurrency = 3\n",
                dir.join("state").display().to_string()
            ))
            .unwrap(),
        )
    }

    /// A hub job ID, naming a placed job's journal.
    const PLACED: &str = "0123456789abcdef0123456789abcdef";

    /// A pass expected to go through: `step` logs a drain's failure rather than return it.
    fn step(core: &Core, cfg: &Config) {
        core.step(cfg, true);
        assert_eq!(*lock(&core.drain_error), None);
    }

    fn drain() -> Command {
        Command {
            id: "d".into(),
            expires_at: u64::MAX,
            op: Operation::Drain,
        }
    }

    #[test]
    fn a_drain_completes_only_when_every_condition_holds() {
        let all = DrainProgress {
            runner_stopped: true,
            ledger_empty: true,
            active_jobs: 0,
        };
        assert!(drained(&all, true));
        // An external runner never stops; the rest still binds.
        assert!(drained(
            &DrainProgress {
                runner_stopped: false,
                ..all
            },
            false
        ));
        for p in [
            DrainProgress {
                runner_stopped: false,
                ..all
            },
            DrainProgress {
                ledger_empty: false,
                ..all
            },
            DrainProgress {
                active_jobs: 1,
                ..all
            },
        ] {
            assert!(!drained(&p, true), "{p:?}");
        }
    }

    #[test]
    fn a_drain_waits_for_the_runner_then_finishes() {
        let dir = scratch("drain");
        let (runner_tx, runner) = watch::channel(RunnerState::Running);
        let core = Core::open(&dir, issuer(), Runner::Managed(runner)).unwrap();
        let allowed = core.acquire();
        let cfg = cfg(&dir);
        assert!(*allowed.borrow());
        let ack = core.command(drain(), 1).unwrap();
        assert_eq!(ack.outcome, Outcome::Accepted);
        // The runner is told to stop at once; the drain waits for it to have gone.
        assert!(!*allowed.borrow());
        step(&core, &cfg);
        assert_eq!(core.state(), NodeState::Draining);
        let progress = core.report().drain.unwrap();
        assert!(!progress.runner_stopped && progress.ledger_empty && progress.active_jobs == 0);
        // Quitting is still a runner: not drained, and acquisition not yet reported stopped.
        runner_tx.send(RunnerState::Quitting).unwrap();
        step(&core, &cfg);
        assert_eq!(core.state(), NodeState::Draining);
        assert_eq!(core.report().acquisition, Some(Acquisition::Run));
        runner_tx.send(RunnerState::Stopped).unwrap();
        step(&core, &cfg);
        assert_eq!(core.state(), NodeState::Drained);
        assert_eq!(core.unrecorded()[0].outcome, Outcome::Done);
        let report = core.report();
        assert_eq!(report.drain, None);
        assert_eq!(report.acquisition, Some(Acquisition::Stop));
        assert_eq!(report.runner, Some(RunnerMode::Managed));
        assert_eq!(report.concurrency.unwrap().effective, Some(3));
        // Persisted: a restarted node is still drained and still not taking jobs.
        let again = Core::open(
            &dir,
            issuer(),
            Runner::Managed(watch::channel(RunnerState::Stopped).1),
        )
        .unwrap();
        assert_eq!(again.state(), NodeState::Drained);
        assert!(!*again.acquire().borrow());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_hub_ceiling_binds_and_an_external_runner_says_what_it_cannot_do() {
        let dir = scratch("ceiling");
        let core = Core::open(&dir, issuer(), Runner::External).unwrap();
        let cfg = cfg(&dir);
        core.apply_desired(DesiredState {
            generation: 1,
            ceiling: Some(2),
            acquisition: Acquisition::Stop,
        })
        .unwrap();
        step(&core, &cfg);
        let report = core.report();
        assert_eq!(report.applied_generation(), Some(1));
        assert_eq!(report.concurrency.unwrap().effective, Some(2));
        assert_eq!(
            std::fs::read_to_string(crate::schedule::desired_file(&cfg)).unwrap(),
            "2\n"
        );
        // With no runner of its own, the host runs only the hub's jobs, which a stop stops.
        assert_eq!(report.acquisition, Some(Acquisition::Run));
        assert_eq!(report.runner, Some(RunnerMode::External));
        assert_eq!(report.runner_state, None);
        assert_eq!(report.unsupported, Vec::<String>::new());
        assert!(!*core.acquire().borrow());
        // An external runner goes on taking jobs, and the report says why.
        core.set_placed(PlacedIntake {
            runner: Some("gitlab-runner.service runs the vk custom executor".into()),
            ..PlacedIntake::default()
        });
        let report = core.report();
        assert_eq!(report.unsupported.len(), 1);
        assert!(
            report.unsupported[0].contains("may still take jobs"),
            "{:?}",
            report.unsupported
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Without a managed runner, a drain stops the jobs the hub places and completes once
    /// those and whatever holds the admission ledger are over.
    #[test]
    fn a_node_without_a_managed_runner_drains_once_its_jobs_and_the_ledger_are_done() {
        use crate::node::jobs::journal;
        let dir = scratch("external-drain");
        let core = Core::open(&dir, issuer(), Runner::External).unwrap();
        let cfg = cfg(&dir);
        // A placed job accepted, its supervisor not started yet.
        let placed = dir.join("jobs").join(PLACED);
        std::fs::create_dir_all(&placed).unwrap();
        std::fs::write(
            placed.join(journal::META),
            r#"{"gitlab_id":41,"slot":0,"project_slot":0,"project_id":7}"#,
        )
        .unwrap();
        // The admission it holds, by its GitLab job ID.
        let admit = dir.join("state").join("admit");
        std::fs::create_dir_all(&admit).unwrap();
        std::fs::write(admit.join("41"), "1024 1 granted\n").unwrap();
        let held = crate::admit::hold(&admit, "41").unwrap();
        let ack = core.command(drain(), 1).unwrap();
        assert_eq!(ack.outcome, Outcome::Accepted);
        assert!(!crate::node::jobs::ready(
            core.state(),
            *core.acquire().borrow()
        ));
        step(&core, &cfg);
        assert_eq!(core.state(), NodeState::Draining);
        let report = core.report();
        let progress = report.drain.unwrap();
        assert!(!progress.runner_stopped && !progress.ledger_empty);
        assert_eq!(progress.active_jobs, 1);
        assert_eq!(report.unsupported, Vec::<String>::new());
        // The placed job ends.
        std::fs::write(placed.join(journal::RESULT), "{}").unwrap();
        step(&core, &cfg);
        assert_eq!(core.state(), NodeState::Draining);
        assert_eq!(core.report().drain.unwrap().active_jobs, 0);
        // Then its driver, which held the admission until its cleanup was over.
        drop(held);
        // Retried: a test forking meanwhile can hold the dropped lock for an instant.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while core.state() == NodeState::Draining && std::time::Instant::now() < deadline {
            step(&core, &cfg);
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(core.state(), NodeState::Drained);
        assert_eq!(core.unrecorded()[0].outcome, Outcome::Done);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With no runner, everything that takes jobs on the host is the node's: a stop and a
    /// drain stop it with no runner to wait for, and a reset and an update without `--force`
    /// go through, where an external runner refuses them.
    #[test]
    fn a_node_with_no_runner_stops_what_it_runs_and_takes_resets_and_updates() {
        let dir = scratch("no-runner");
        let bin = scratch("no-runner-bin");
        let exe = bin.join("vk");
        std::fs::write(&exe, "").unwrap();
        let cfg = cfg(&dir);
        let command = |id: &str, op| Command {
            id: id.into(),
            expires_at: u64::MAX,
            op,
        };
        let update = || Operation::Update {
            version: "999.0.0".into(),
            sha256: "ab".repeat(vk_hub_proto::SHA256_LEN),
            size: 1,
            signature: None,
            within_secs: None,
            force: false,
        };
        let external = Core::open(&dir, issuer(), Runner::External).unwrap();
        external
            .change(|p| p.installed = Some(exe.clone()))
            .unwrap();
        for (id, op) in [("r0", Operation::Reset { images: false }), ("u0", update())] {
            let ack = external.command(command(id, op), 1).unwrap();
            assert!(matches!(ack.outcome, Outcome::Refused { .. }), "{ack:?}");
        }
        drop(external);
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::create_dir_all(dir.join("state")).unwrap();

        let core = Core::open(&dir, issuer(), Runner::None).unwrap();
        core.change(|p| p.installed = Some(exe.clone())).unwrap();
        core.apply_desired(DesiredState {
            generation: 1,
            ceiling: None,
            acquisition: Acquisition::Stop,
        })
        .unwrap();
        let report = core.report();
        assert_eq!(report.runner, Some(RunnerMode::None));
        assert_eq!(report.runner_state, None);
        assert_eq!(report.acquisition, Some(Acquisition::Stop));
        assert_eq!(report.unsupported, Vec::<String>::new());
        core.command(drain(), 1).unwrap();
        step(&core, &cfg);
        assert_eq!(core.state(), NodeState::Drained);
        core.command(command("u", Operation::Undrain), 1).unwrap();
        let ack = core
            .command(command("r", Operation::Reset { images: false }), 1)
            .unwrap();
        assert_eq!(ack.outcome, Outcome::Accepted);
        step(&core, &cfg);
        assert_eq!(core.state(), NodeState::Maintenance);
        core.change(|p| {
            p.end_job(Outcome::Done, vk_hub_proto::UpdatePhase::Done);
        })
        .unwrap();
        assert_eq!(core.state(), NodeState::Ready);
        // An update drains first, as with a managed runner.
        let ack = core.command(command("u1", update()), 1).unwrap();
        assert_eq!(ack.outcome, Outcome::Accepted);
        assert_eq!(core.state(), NodeState::Draining);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&bin);
    }

    #[test]
    fn a_drain_completes_while_the_concurrency_cannot_be_set() {
        let dir = scratch("broken");
        let cfg: Config = toml::from_str(&format!(
            "state_dir = {:?}\n[executor.vm]\nmem = \"lots\"\n[executor.schedule]\n\
             mem_budget = \"32G\"\n",
            dir.join("state").display().to_string()
        ))
        .unwrap();
        let core = Core::open(
            &dir,
            issuer(),
            Runner::Managed(watch::channel(RunnerState::Stopped).1),
        )
        .unwrap();
        core.command(drain(), 1).unwrap();
        step(&core, &cfg);
        assert_eq!(core.state(), NodeState::Drained);
        let report = core.report();
        assert!(
            report
                .concurrency_error
                .unwrap()
                .contains("[executor.vm] mem")
        );
        assert_eq!(report.concurrency, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A plain stop, with no drain to poll, still shows in the report as the runner quits and
    /// then exits.
    #[tokio::test(flavor = "multi_thread")]
    async fn every_runner_transition_changes_the_report() {
        let dir = scratch("transitions");
        let (runner_tx, runner) = watch::channel(RunnerState::Running);
        let core = Core::open(&dir, issuer(), Runner::Managed(runner)).unwrap();
        let (halt, stop) = watch::channel(false);
        let task = tokio::spawn(
            core.clone()
                .control(cfg(&dir), Duration::from_secs(3600), stop),
        );
        core.apply_desired(DesiredState {
            generation: 1,
            ceiling: None,
            acquisition: Acquisition::Stop,
        })
        .unwrap();
        assert!(!*core.acquire().borrow());
        // Let the loop's own passes, which change the report too, settle first.
        let mut changes = core.subscribe();
        for _ in 0..100 {
            if core.report().concurrency.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        for state in [RunnerState::Quitting, RunnerState::Stopped] {
            changes.borrow_and_update();
            runner_tx.send(state).unwrap();
            tokio::time::timeout(Duration::from_secs(10), changes.changed())
                .await
                .expect("the runner's transition was not reported")
                .unwrap();
            assert_eq!(core.report().runner_state, Some(state));
            let want = match state {
                RunnerState::Stopped => Acquisition::Stop,
                _ => Acquisition::Run,
            };
            assert_eq!(core.report().acquisition, Some(want));
        }
        halt.send(true).unwrap();
        task.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Passes set off by changes — reports, acks, this loop's own findings — may lower the
    /// concurrency but not raise it; only the timer does, a step at a time.
    #[tokio::test(flavor = "multi_thread")]
    async fn only_the_timer_raises_the_concurrency() {
        let dir = scratch("rise");
        let cfg: Arc<Config> = Arc::new(
            toml::from_str(&format!(
                "state_dir = {:?}\n[executor.schedule]\nmem_budget = \"1000G\"\n",
                dir.join("state").display().to_string()
            ))
            .unwrap(),
        );
        let path = crate::schedule::desired_file(&cfg);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "1\n").unwrap();
        let read = || -> u32 {
            std::fs::read_to_string(&path)
                .unwrap()
                .trim()
                .parse()
                .unwrap()
        };
        let core = Core::open(&dir, issuer(), Runner::External).unwrap();
        let (halt, stop) = watch::channel(false);
        let task = tokio::spawn(
            core.clone()
                .control(cfg.clone(), Duration::from_secs(3600), stop),
        );
        // The first tick: at most one step above where it was.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let after_tick = read();
        assert!(after_tick <= 2, "{after_tick}");
        // A burst of changes: no further climb.
        for generation in 1..=10 {
            core.apply_desired(DesiredState {
                generation,
                ceiling: None,
                acquisition: Acquisition::Run,
            })
            .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(read() <= after_tick, "{} after {after_tick}", read());
        halt.send(true).unwrap();
        task.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A reset is for the job a failed cleanup left running: its drain does not wait for it,
    /// nor for the admission it holds, but does wait for one still being asked for.
    #[test]
    fn a_reset_drains_past_a_leftover_supervisor() {
        let dir = scratch("reset-drain");
        let job = dir.join("state").join("jobs").join("77");
        std::fs::create_dir_all(&job).unwrap();
        // A live supervisor, as the drain recognizes one: its pid, with the job dir among its
        // arguments, and its admission entry held.
        let mut child = std::process::Command::new("sh")
            .args(["-c", "while :; do sleep 1; done", job.to_str().unwrap()])
            .spawn()
            .unwrap();
        std::fs::write(job.join("supervisor.pid"), child.id().to_string()).unwrap();
        let admit = dir.join("state").join("admit");
        std::fs::create_dir_all(&admit).unwrap();
        std::fs::write(admit.join("77"), "1024 1 granted\n").unwrap();
        let _granted = crate::admit::hold(&admit, "77").unwrap();
        std::fs::write(admit.join("78"), "1024 2 waiting\n").unwrap();
        let waiting = crate::admit::hold(&admit, "78").unwrap();
        // A job admitted whose supervisor has not taken over: a prepare under way.
        std::fs::create_dir_all(job.with_file_name("79")).unwrap();
        std::fs::write(admit.join("79"), "1024 3 granted\n").unwrap();
        let preparing = crate::admit::hold(&admit, "79").unwrap();
        let (_runner, runner) = watch::channel(RunnerState::Stopped);
        let core = Core::open(&dir, issuer(), Runner::Managed(runner)).unwrap();
        let cfg = cfg(&dir);
        let command = |id: &str, op| Command {
            id: id.into(),
            expires_at: u64::MAX,
            op,
        };
        core.command(drain(), 1).unwrap();
        step(&core, &cfg);
        // A plain drain waits for the job.
        assert_eq!(core.state(), NodeState::Draining);
        assert_eq!(core.report().drain.unwrap().active_jobs, 1);
        assert!(!core.report().drain.unwrap().ledger_empty);
        core.command(command("u", Operation::Undrain), 1).unwrap();
        core.command(command("r", Operation::Reset { images: false }), 1)
            .unwrap();
        // A job still asking to be admitted is waited for.
        step(&core, &cfg);
        assert_eq!(core.state(), NodeState::Draining);
        drop(waiting);
        // Retried: a test forking meanwhile can hold the dropped lock for an instant.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while crate::admit::committed(&admit).unwrap().ahead > 0
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        // So is a job admitted that no supervisor runs yet.
        step(&core, &cfg);
        assert_eq!(core.state(), NodeState::Draining);
        drop(preparing);
        while core.state() == NodeState::Draining && std::time::Instant::now() < deadline {
            step(&core, &cfg);
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(core.state(), NodeState::Maintenance);
        child.kill().unwrap();
        child.wait().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With no runner, a reset waits for every placed job's result, a live supervisor or not,
    /// and then goes past a supervisor left behind.
    #[test]
    fn a_reset_with_no_runner_waits_for_the_placed_jobs() {
        use crate::node::jobs::journal;
        let dir = scratch("reset-none");
        let placed = dir.join("jobs").join(PLACED);
        std::fs::create_dir_all(&placed).unwrap();
        std::fs::write(
            placed.join(journal::META),
            r#"{"gitlab_id":41,"slot":0,"project_slot":0,"project_id":7}"#,
        )
        .unwrap();
        let job = dir.join("state").join("jobs").join("41");
        std::fs::create_dir_all(&job).unwrap();
        /// The supervisor's stand-in, killed however the test ends.
        struct Killed(std::process::Child);
        impl Drop for Killed {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let child = Killed(
            std::process::Command::new("sh")
                .args(["-c", "while :; do sleep 1; done", job.to_str().unwrap()])
                .spawn()
                .unwrap(),
        );
        std::fs::write(job.join("supervisor.pid"), child.0.id().to_string()).unwrap();
        let core = Core::open(&dir, issuer(), Runner::None).unwrap();
        let cfg = cfg(&dir);
        let ack = core
            .command(
                Command {
                    id: "r".into(),
                    expires_at: u64::MAX,
                    op: Operation::Reset { images: false },
                },
                1,
            )
            .unwrap();
        assert_eq!(ack.outcome, Outcome::Accepted);
        step(&core, &cfg);
        assert_eq!(core.state(), NodeState::Draining);
        // Its result in, the supervisor still up: the reset goes on.
        std::fs::write(placed.join(journal::RESULT), "{}").unwrap();
        step(&core, &cfg);
        assert_eq!(core.state(), NodeState::Maintenance);
        drop(child);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_reset_waiting_too_long_on_a_job_being_prepared_fails_and_stays_drained() {
        let dir = scratch("reset-prepare");
        std::fs::create_dir_all(dir.join("state").join("jobs").join("79")).unwrap();
        let admit = dir.join("state").join("admit");
        std::fs::create_dir_all(&admit).unwrap();
        std::fs::write(admit.join("79"), "1024 1 granted\n").unwrap();
        let _preparing = crate::admit::hold(&admit, "79").unwrap();
        let (_runner, runner) = watch::channel(RunnerState::Stopped);
        let core = Core::open(&dir, issuer(), Runner::Managed(runner)).unwrap();
        let cfg = cfg(&dir);
        let reset = Command {
            id: "r".into(),
            expires_at: u64::MAX,
            op: Operation::Reset { images: false },
        };
        core.command(reset, 1).unwrap();
        step(&core, &cfg);
        assert_eq!(core.state(), NodeState::Draining);
        // As if the prepare had been at it since well before.
        let started = lock(&core.preparing_since).unwrap();
        *lock(&core.preparing_since) = Some(started - PREPARE_WAIT.as_secs());
        step(&core, &cfg);
        assert_eq!(core.state(), NodeState::Drained);
        let journal = core.persisted().journal;
        assert!(
            matches!(&journal[0].outcome, Outcome::Failed { message } if message.contains("79")),
            "{journal:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
