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
    Operation, Report, RunnerMode, RunnerState,
};

use super::state::{Abilities, Issuer, Persisted};
use super::update::Binary;
use crate::config::Config;

pub struct Core {
    dir: PathBuf,
    /// A managed runner's process, as its supervisor reports it; `None` for an external runner.
    runner: Option<watch::Receiver<RunnerState>>,
    persisted: Mutex<Persisted>,
    concurrency: Mutex<Option<Concurrency>>,
    /// Why the last attempt at setting the concurrency failed, if it did.
    concurrency_error: Mutex<Option<String>>,
    /// Which of a drain's conditions held at the last pass, while draining.
    drain: Mutex<Option<DrainProgress>>,
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
}

impl Core {
    /// Load the state in `dir`, for `issuer` — the hub and node ID the node is enrolled as.
    /// `runner` is a managed runner's state as its supervisor reports it, `None` for an
    /// external runner.
    pub fn open(
        dir: &Path,
        issuer: Issuer,
        runner: Option<watch::Receiver<RunnerState>>,
    ) -> Result<Arc<Core>> {
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
        if runner.is_none() && persisted.state == NodeState::Draining {
            say!(
                "the node is draining but its runner is external: the drain cannot complete \
                 until the hub undrains the node"
            );
        }
        let (acquire, _) = watch::channel(!persisted.acquisition_stopped());
        let (changed, _) = watch::channel(0);
        Ok(Arc::new(Core {
            dir: dir.to_path_buf(),
            runner,
            persisted: Mutex::new(persisted),
            concurrency: Mutex::new(None),
            concurrency_error: Mutex::new(None),
            drain: Mutex::new(None),
            acquire,
            changed,
            connected: watch::Sender::new(false),
            exec: super::update::exec,
            allow_downgrade: AtomicBool::new(false),
            release_policy: Mutex::new(crate::release_key::Policy::default()),
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

    /// Journal `command` and carry it out. An external runner cannot be stopped, so a drain or
    /// a quarantine is refused; an update is refused when the node could not install it, or
    /// may not.
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
            managed: self.runner.is_some(),
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
        let mut unsupported = Vec::new();
        if stopped && runner.is_none() {
            unsupported.push(
                "stopping acquisition: the runner is external ([node] runner = \"external\"), \
                 so only its concurrency is steered"
                    .to_string(),
            );
        }
        Report {
            applied: persisted.applied.clone(),
            unsupported,
            state: Some(persisted.state),
            // Stopped only once a managed runner has exited: until then it may be one that
            // never heard its signal.
            acquisition: Some(if stopped && runner == Some(RunnerState::Stopped) {
                Acquisition::Stop
            } else {
                Acquisition::Run
            }),
            runner: Some(match runner {
                Some(_) => RunnerMode::Managed,
                None => RunnerMode::External,
            }),
            runner_state: runner,
            concurrency: *lock(&self.concurrency),
            concurrency_error: lock(&self.concurrency_error).clone(),
            // Only while draining: the pass that finishes a drain clears it a moment later.
            drain: (persisted.state == NodeState::Draining)
                .then(|| *lock(&self.drain))
                .flatten(),
            update: persisted.update.clone(),
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
            match tokio::task::spawn_blocking(move || core.step(&cfg, may_rise)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => say!("{e:#}"),
                Err(e) => say!("the concurrency loop failed: {e}"),
            }
        }
    }

    /// Update concurrency, then drain progress, independently of either's failure. An invalid
    /// concurrency config must not block a drain. Concurrency errors are reported as well as
    /// logged.
    fn step(&self, cfg: &Config, may_rise: bool) -> Result<()> {
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
                let message = format!("{e:#}");
                if lock(&self.concurrency_error).as_deref() != Some(&message) {
                    say!("setting the runner's concurrency: {message}");
                }
                self.set(&self.concurrency_error, Some(message));
            }
        }
        self.drain_step(cfg)
    }

    /// While draining, read where the drain stands and finish it once complete.
    fn drain_step(&self, cfg: &Config) -> Result<()> {
        let now = super::session::now_secs();
        if self.update(|p| p.drain_expired(now))? {
            say!("the update's command expired before the drain finished");
        }
        if self.state() != NodeState::Draining {
            self.set(&self.drain, None);
            return Ok(());
        }
        let held = crate::admit::committed(&cfg.state_dir().join("admit"))
            .context("reading the admission ledger for the drain")?;
        let jobs = crate::vm::live_job_supervisors(&cfg.state_dir().join("jobs"))
            .context("counting the jobs left for the drain")?;
        let progress = DrainProgress {
            runner_stopped: self.runner.as_ref().map(|r| *r.borrow()) == Some(RunnerState::Stopped),
            ledger_empty: held.granted == 0 && held.ahead == 0,
            active_jobs: u32::try_from(jobs.len()).unwrap_or(u32::MAX),
        };
        self.set(&self.drain, Some(progress));
        if drained(&progress) && self.update(|p| p.finish_drain(now))? {
            say!("drained");
            self.set(&self.drain, None);
        }
        Ok(())
    }
}

/// Whether a drain is complete: the runner has exited — which it does on `SIGQUIT` only once
/// its jobs, their cleanup stage included, are over — the ledger holds and awaits nothing,
/// and no job supervisor is left, which catches a job whose cleanup failed and left its VM up.
fn drained(p: &DrainProgress) -> bool {
    p.runner_stopped && p.ledger_empty && p.active_jobs == 0
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
        assert!(drained(&all));
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
            assert!(!drained(&p), "{p:?}");
        }
    }

    #[test]
    fn a_drain_waits_for_the_runner_then_finishes() {
        let dir = scratch("drain");
        let (runner_tx, runner) = watch::channel(RunnerState::Running);
        let core = Core::open(&dir, issuer(), Some(runner)).unwrap();
        let allowed = core.acquire();
        let cfg = cfg(&dir);
        assert!(*allowed.borrow());
        let ack = core.command(drain(), 1).unwrap();
        assert_eq!(ack.outcome, Outcome::Accepted);
        // The runner is told to stop at once; the drain waits for it to have gone.
        assert!(!*allowed.borrow());
        core.step(&cfg, true).unwrap();
        assert_eq!(core.state(), NodeState::Draining);
        let progress = core.report().drain.unwrap();
        assert!(!progress.runner_stopped && progress.ledger_empty && progress.active_jobs == 0);
        // Quitting is still a runner: not drained, and acquisition not yet reported stopped.
        runner_tx.send(RunnerState::Quitting).unwrap();
        core.step(&cfg, true).unwrap();
        assert_eq!(core.state(), NodeState::Draining);
        assert_eq!(core.report().acquisition, Some(Acquisition::Run));
        runner_tx.send(RunnerState::Stopped).unwrap();
        core.step(&cfg, true).unwrap();
        assert_eq!(core.state(), NodeState::Drained);
        assert_eq!(core.unrecorded()[0].outcome, Outcome::Done);
        let report = core.report();
        assert_eq!(report.drain, None);
        assert_eq!(report.acquisition, Some(Acquisition::Stop));
        assert_eq!(report.runner, Some(RunnerMode::Managed));
        assert_eq!(report.concurrency.unwrap().effective, Some(3));
        // Persisted: a restarted node is still drained and still not taking jobs.
        let again =
            Core::open(&dir, issuer(), Some(watch::channel(RunnerState::Stopped).1)).unwrap();
        assert_eq!(again.state(), NodeState::Drained);
        assert!(!*again.acquire().borrow());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_hub_ceiling_binds_and_an_external_runner_says_what_it_cannot_do() {
        let dir = scratch("ceiling");
        let core = Core::open(&dir, issuer(), None).unwrap();
        let cfg = cfg(&dir);
        core.apply_desired(DesiredState {
            generation: 1,
            ceiling: Some(2),
            acquisition: Acquisition::Stop,
        })
        .unwrap();
        core.step(&cfg, true).unwrap();
        let report = core.report();
        assert_eq!(report.applied_generation(), Some(1));
        assert_eq!(report.concurrency.unwrap().effective, Some(2));
        assert_eq!(
            std::fs::read_to_string(crate::schedule::desired_file(&cfg)).unwrap(),
            "2\n"
        );
        // External: the runner goes on taking jobs, and the report says why.
        assert_eq!(report.acquisition, Some(Acquisition::Run));
        assert_eq!(report.runner, Some(RunnerMode::External));
        assert_eq!(report.runner_state, None);
        assert_eq!(report.unsupported.len(), 1);
        assert!(!*core.acquire().borrow());
        // Nor can it drain.
        let ack = core.command(drain(), 1).unwrap();
        assert!(matches!(ack.outcome, Outcome::Refused { .. }), "{ack:?}");
        assert_eq!(core.state(), NodeState::Ready);
        let _ = std::fs::remove_dir_all(&dir);
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
        let core =
            Core::open(&dir, issuer(), Some(watch::channel(RunnerState::Stopped).1)).unwrap();
        core.command(drain(), 1).unwrap();
        core.step(&cfg, true).unwrap();
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
        let core = Core::open(&dir, issuer(), Some(runner)).unwrap();
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
        let core = Core::open(&dir, issuer(), None).unwrap();
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
}
