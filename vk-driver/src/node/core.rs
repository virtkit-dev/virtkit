//! What `vk node run` keeps between its tasks: the persisted state ([`Persisted`]), the
//! concurrency its loop last worked out, a drain's progress, and the supervised runner's
//! process state. The session reads a [`Report`] out of it and feeds it what the hub sends;
//! the runner supervisor follows its `acquire` flag; the control loop ([`Core::control`]) sets
//! the runner's concurrency and finishes a drain once nothing is left running.
//!
//! None of it depends on the hub being there: a node that has lost its session keeps
//! applying the last desired state it took and whatever drain or quarantine it has persisted.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use anyhow::Result;
use tokio::sync::watch;
use vk_fleet_proto::{
    Acquisition, Command, CommandAck, Concurrency, DesiredState, DrainProgress, NodeState, Report,
    RunnerMode, RunnerState,
};

use super::state::{Abilities, Issuer, Persisted};
use crate::config::Config;

pub struct Core {
    dir: PathBuf,
    managed: bool,
    persisted: Mutex<Persisted>,
    concurrency: Mutex<Option<Concurrency>>,
    /// Why the last attempt at setting the concurrency failed, if it did.
    concurrency_error: Mutex<Option<String>>,
    drain: Mutex<Option<DrainProgress>>,
    runner: watch::Receiver<RunnerState>,
    /// Whether the runner may take jobs, for the supervisor to follow.
    acquire: watch::Sender<bool>,
    /// Bumped on every change a report would show.
    changed: watch::Sender<u64>,
    /// Whether a session with the hub is up: what an update on trial waits for.
    connected: watch::Sender<bool>,
    /// How [`Core::leave`] executes a binary.
    exec: fn(&Path) -> anyhow::Error,
    /// Whether an update may install an older version than this one (`[node]
    /// allow_downgrade`).
    allow_downgrade: std::sync::atomic::AtomicBool,
    /// What an update's release must be signed with; none required until set.
    release_policy: std::sync::OnceLock<crate::release_key::Policy>,
}

impl Core {
    /// Load the state in `dir`, for `issuer` — the hub and node ID the node is enrolled as.
    /// `runner` is the supervisor's report of its runner, for ever `Stopped` for an external
    /// one. Returns the flag the supervisor follows beside it.
    pub fn open(
        dir: &Path,
        managed: bool,
        issuer: Issuer,
        runner: watch::Receiver<RunnerState>,
    ) -> Result<(Arc<Core>, watch::Receiver<bool>)> {
        let mut persisted = Persisted::load(dir)?;
        let before = persisted.clone();
        if persisted.adopt_issuer(issuer) {
            eprintln!(
                "vk node: the node state was kept for another enrollment; its desired state and \
                 command journal are dropped, its {:?} state is kept",
                persisted.state
            );
        }
        if persisted != before {
            persisted.save(dir)?;
        }
        let (acquire, allowed) = watch::channel(!persisted.acquisition_stopped());
        let (changed, _) = watch::channel(0);
        let core = Core {
            dir: dir.to_path_buf(),
            managed,
            persisted: Mutex::new(persisted),
            concurrency: Mutex::new(None),
            concurrency_error: Mutex::new(None),
            drain: Mutex::new(None),
            runner,
            acquire,
            changed,
            connected: watch::Sender::new(false),
            exec: super::update::exec,
            allow_downgrade: std::sync::atomic::AtomicBool::new(false),
            release_policy: std::sync::OnceLock::new(),
        };
        Ok((Arc::new(core), allowed))
    }

    /// Change the persisted state through `f`: written to disk first, and only then made the
    /// state the rest of the node follows — the journal entry of a command is on disk before
    /// the runner hears of it.
    fn update<R>(&self, f: impl FnOnce(&mut Persisted) -> R) -> Result<R> {
        let mut persisted = lock(&self.persisted);
        let mut next = persisted.clone();
        let out = f(&mut next);
        if next != *persisted {
            next.save(&self.dir)?;
            *persisted = next;
            self.acquire.send_replace(!persisted.acquisition_stopped());
            drop(persisted);
            self.bump();
        }
        Ok(out)
    }

    fn bump(&self) {
        self.changed.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// A receiver that sees every change a report would show.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    pub fn apply_desired(&self, desired: DesiredState) -> Result<bool> {
        self.update(|p| p.apply_desired(desired))
    }

    pub fn command(&self, command: Command, now: u64) -> Result<CommandAck> {
        let can = Abilities {
            managed: self.managed,
            // Looked at only for an update: it reads the filesystem.
            update: match &command.op {
                vk_fleet_proto::Operation::Update {
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
            },
        };
        self.update(|p| p.command_as(command, now, &can))
    }

    /// Require what `policy` says of every release from now on.
    pub fn set_release_policy(&self, policy: crate::release_key::Policy) {
        // Set once, at start: a second call has nothing new to say.
        let _ = self.release_policy.set(policy);
    }

    /// What an update's release must be signed with.
    pub fn release_policy(&self) -> crate::release_key::Policy {
        self.release_policy.get().cloned().unwrap_or_default()
    }

    /// Change the persisted state through `f` and execute `exe` in this process's place,
    /// holding the state's lock throughout: nothing this process does meanwhile — an ack
    /// recorded, a runner started for the state `f` leaves — can come between the change on
    /// disk and the binary that follows it. Returns only on failure, with the change in force
    /// in this process too.
    pub fn leave(&self, f: impl FnOnce(&mut Persisted), exe: &Path) -> anyhow::Error {
        let persisted = lock(&self.persisted);
        let mut next = persisted.clone();
        f(&mut next);
        if let Err(e) = next.save_durable(&self.dir) {
            return e;
        }
        let e = (self.exec)(exe);
        // Not executed: the change goes back, on disk too — it described a binary that is
        // not running.
        if let Err(undo) = persisted.save_durable(&self.dir) {
            return e.context(format!("and restoring the node state failed: {undo:#}"));
        }
        e
    }

    /// Execute binaries through `exec` rather than for real.
    #[cfg(test)]
    pub fn set_exec(&mut self, exec: fn(&Path) -> anyhow::Error) {
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
        self.allow_downgrade
            .store(allow, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn allow_downgrade(&self) -> bool {
        self.allow_downgrade
            .load(std::sync::atomic::Ordering::Relaxed)
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

    /// The node as it would report itself now.
    pub fn report(&self) -> Report {
        let persisted = lock(&self.persisted).clone();
        let stopped = persisted.acquisition_stopped();
        let runner = *self.runner.borrow();
        let mut unsupported = Vec::new();
        if stopped && !self.managed {
            unsupported.push(
                "stopping acquisition: the runner is external ([node] runner = \"external\"), \
                 so only its concurrency is steered"
                    .to_string(),
            );
        }
        Report {
            applied_generation: persisted.applied.as_ref().map(|d| d.generation),
            unsupported,
            state: persisted.state,
            // What the runner is doing: stopped only once a managed runner has exited, since
            // until then it may be one that never heard its signal.
            acquisition: if stopped && self.managed && runner == RunnerState::Stopped {
                Acquisition::Stop
            } else {
                Acquisition::Run
            },
            runner: if self.managed {
                RunnerMode::Managed
            } else {
                RunnerMode::External
            },
            runner_state: self.managed.then_some(runner),
            concurrency: *lock(&self.concurrency),
            concurrency_error: lock(&self.concurrency_error).clone(),
            drain: *lock(&self.drain),
            update: persisted.update.clone(),
        }
    }

    /// Set the runner's concurrency every `every`, and whenever the state or the runner
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
                _ = runner.changed() => {
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
                Ok(Err(e)) => eprintln!("vk node: {e:#}"),
                Err(e) => eprintln!("vk node: the concurrency loop failed: {e}"),
            }
        }
    }

    /// One pass of the loop: the concurrency, then the drain. Each goes on whether or not the
    /// other failed — a config the concurrency cannot be worked out from must not hold a drain
    /// open — and the concurrency's failure is reported rather than only logged.
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
                        local_ceiling: decision.local_ceiling,
                        effective: decision.effective,
                    }),
                );
                self.set(&self.concurrency_error, None);
            }
            Err(e) => {
                let message = format!("{e:#}");
                if lock(&self.concurrency_error).as_deref() != Some(&message) {
                    eprintln!("vk node: setting the runner's concurrency: {message}");
                }
                self.set(&self.concurrency_error, Some(message));
            }
        }
        self.drain_step(cfg)
    }

    fn drain_step(&self, cfg: &Config) -> Result<()> {
        let now = super::session::now_secs();
        if self.update(|p| p.drain_expired(now))? {
            eprintln!("vk node: the update's command expired before the drain finished");
        }
        if self.state() != NodeState::Draining {
            self.set(&self.drain, None);
            return Ok(());
        }
        let held = crate::admit::committed(&cfg.state_dir().join("admit"))?;
        let progress = DrainProgress {
            runner_stopped: *self.runner.borrow() == RunnerState::Stopped,
            ledger_empty: held.granted == 0 && held.ahead == 0,
            active_jobs: u32::try_from(crate::vm::live_supervisors(&cfg.state_dir().join("jobs"))?)
                .unwrap_or(u32::MAX),
        };
        self.set(&self.drain, Some(progress));
        // A reset exists for the job a failed cleanup left running: its drain is over once
        // the runner is gone and nothing is admitted, and clearing stops the rest.
        let for_reset = lock(&self.persisted)
            .job
            .as_ref()
            .is_some_and(|j| matches!(j.work, super::state::Work::Reset { .. }));
        let done = if for_reset {
            progress.runner_stopped && progress.ledger_empty
        } else {
            drained(&progress)
        };
        if done && self.update(|p| p.finish_drain(now))? {
            eprintln!("vk node: drained");
            self.set(&self.drain, None);
        }
        Ok(())
    }
}

/// Whether a drain is complete: the runner has exited — which it does on `SIGQUIT` only once
/// its jobs, their cleanup stage included, are over — the ledger holds and awaits nothing,
/// and no job supervisor is left, which catches a job whose cleanup failed and left its VM up.
pub fn drained(p: &DrainProgress) -> bool {
    p.runner_stopped && p.ledger_empty && p.active_jobs == 0
}

/// A lock whose holder panicked still guards whole values — each is replaced in one
/// assignment — so poisoning is ignored.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vk_fleet_proto::{Operation, Outcome};

    fn issuer() -> Issuer {
        Issuer {
            hub: "https://hub".into(),
            node_id: "ab".repeat(16),
        }
    }

    fn stopped() -> watch::Receiver<RunnerState> {
        watch::channel(RunnerState::Stopped).1
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

    /// A job dir counts while the process its pidfile names still carries the job dir, and
    /// not once it is gone or for a dot-directory.
    #[test]
    fn only_a_job_with_a_live_supervisor_counts() {
        let dir = scratch("jobs");
        let jobs = dir.join("jobs");
        let job = jobs.join("123");
        std::fs::create_dir_all(&job).unwrap();
        std::fs::create_dir_all(jobs.join(".net")).unwrap();
        assert_eq!(crate::vm::live_supervisors(&jobs).unwrap(), 0);
        let mut child = std::process::Command::new("sh")
            // A loop, so the shell itself stays the process — a lone command it would exec
            // in its place, and the job dir would leave the argument list.
            .args(["-c", "while :; do sleep 1; done", job.to_str().unwrap()])
            .spawn()
            .unwrap();
        std::fs::write(job.join("supervisor.pid"), child.id().to_string()).unwrap();
        // Until the child has exec'd, its argument list is still this process's.
        let cmdline = format!("/proc/{}/cmdline", child.id());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !std::fs::read(&cmdline).is_ok_and(|c| {
            c.split(|&b| b == 0)
                .any(|a| a == job.as_os_str().as_encoded_bytes())
        }) && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(crate::vm::live_supervisors(&jobs).unwrap(), 1);
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(crate::vm::live_supervisors(&jobs).unwrap(), 0);
        assert_eq!(crate::vm::live_supervisors(&dir.join("none")).unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_drain_waits_for_the_runner_then_finishes() {
        let dir = scratch("drain");
        let (runner_tx, runner) = watch::channel(RunnerState::Running);
        let (core, allowed) = Core::open(&dir, true, issuer(), runner).unwrap();
        let cfg = cfg(&dir);
        let ack = core
            .command(
                Command {
                    id: "d".into(),
                    expires_at: u64::MAX,
                    op: Operation::Drain,
                },
                1,
            )
            .unwrap();
        assert_eq!(ack.outcome, Outcome::Accepted);
        // The runner is told to stop at once; the drain waits for it to have gone.
        assert!(!*allowed.borrow());
        core.step(&cfg, true).unwrap();
        assert_eq!(core.state(), NodeState::Draining);
        let drain = core.report().drain.unwrap();
        assert!(!drain.runner_stopped && drain.ledger_empty && drain.active_jobs == 0);
        // Quitting is still a runner: not drained, and acquisition not yet reported stopped.
        runner_tx.send(RunnerState::Quitting).unwrap();
        core.step(&cfg, true).unwrap();
        assert_eq!(core.state(), NodeState::Draining);
        assert_eq!(core.report().acquisition, Acquisition::Run);
        runner_tx.send(RunnerState::Stopped).unwrap();
        core.step(&cfg, true).unwrap();
        assert_eq!(core.state(), NodeState::Drained);
        assert_eq!(core.unrecorded()[0].outcome, Outcome::Done);
        assert_eq!(core.report().concurrency.unwrap().effective, Some(3));
        // Persisted: a restarted node is still drained and still not taking jobs.
        assert_eq!(core.report().acquisition, Acquisition::Stop);
        let (again, allowed) = Core::open(&dir, true, issuer(), stopped()).unwrap();
        assert_eq!(again.state(), NodeState::Drained);
        assert!(!*allowed.borrow());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_hub_ceiling_binds_and_an_external_runner_says_what_it_cannot_do() {
        let dir = scratch("ceiling");
        let (core, allowed) = Core::open(&dir, false, issuer(), stopped()).unwrap();
        let cfg = cfg(&dir);
        core.apply_desired(DesiredState {
            generation: 1,
            ceiling: Some(2),
            acquisition: Acquisition::Stop,
        })
        .unwrap();
        core.step(&cfg, true).unwrap();
        let report = core.report();
        assert_eq!(report.applied_generation, Some(1));
        assert_eq!(report.concurrency.unwrap().effective, Some(2));
        assert_eq!(
            std::fs::read_to_string(crate::schedule::desired_file(&cfg)).unwrap(),
            "2\n"
        );
        // External: the runner goes on taking jobs, and the report says why.
        assert_eq!(report.acquisition, Acquisition::Run);
        assert_eq!(report.runner_state, None);
        assert_eq!(report.unsupported.len(), 1);
        assert!(!*allowed.borrow());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_drain_completes_while_the_concurrency_cannot_be_set() {
        let dir = scratch("broken");
        let cfg: Arc<Config> = Arc::new(
            toml::from_str(&format!(
                "state_dir = {:?}\n[executor.vm]\nmem = \"lots\"\n[executor.schedule]\n\
                 mem_budget = \"32G\"\n",
                dir.join("state").display().to_string()
            ))
            .unwrap(),
        );
        let (core, _) = Core::open(&dir, true, issuer(), stopped()).unwrap();
        core.command(
            Command {
                id: "d".into(),
                expires_at: u64::MAX,
                op: Operation::Drain,
            },
            1,
        )
        .unwrap();
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

    /// A plain stop — no drain polling progress — still shows in the report as the runner
    /// quits and then exits.
    #[tokio::test(flavor = "multi_thread")]
    async fn every_runner_transition_changes_the_report() {
        let dir = scratch("transitions");
        let (runner_tx, runner) = watch::channel(RunnerState::Running);
        let (core, _) = Core::open(&dir, true, issuer(), runner).unwrap();
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
        let mut changes = core.subscribe();
        for state in [RunnerState::Quitting, RunnerState::Stopped] {
            changes.borrow_and_update();
            runner_tx.send(state).unwrap();
            tokio::time::timeout(Duration::from_secs(5), changes.changed())
                .await
                .expect("the runner's transition was not reported")
                .unwrap();
            let report = core.report();
            assert_eq!(report.runner_state, Some(state));
            let want = match state {
                RunnerState::Stopped => Acquisition::Stop,
                _ => Acquisition::Run,
            };
            assert_eq!(report.acquisition, want);
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
        let (core, _) = Core::open(&dir, false, issuer(), stopped()).unwrap();
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

    /// A reset is for the job a failed cleanup left running: its drain does not wait for it.
    #[test]
    fn a_reset_drains_past_a_leftover_supervisor() {
        let dir = scratch("reset-drain");
        let jobs = dir.join("state").join("jobs");
        let job = jobs.join("77");
        std::fs::create_dir_all(&job).unwrap();
        let mut child = std::process::Command::new("sh")
            .args(["-c", "while :; do sleep 1; done", job.to_str().unwrap()])
            .spawn()
            .unwrap();
        std::fs::write(job.join("supervisor.pid"), child.id().to_string()).unwrap();
        let (core, _) = Core::open(&dir, true, issuer(), stopped()).unwrap();
        let cfg = cfg(&dir);
        let drain = Command {
            id: "d".into(),
            expires_at: u64::MAX,
            op: Operation::Drain,
        };
        core.command(drain, 1).unwrap();
        core.step(&cfg, true).unwrap();
        // A plain drain waits for the job.
        assert_eq!(core.state(), NodeState::Draining);
        core.command(
            Command {
                id: "u".into(),
                expires_at: u64::MAX,
                op: Operation::Undrain,
            },
            1,
        )
        .unwrap();
        core.command(
            Command {
                id: "r".into(),
                expires_at: u64::MAX,
                op: Operation::Reset { images: false },
            },
            1,
        )
        .unwrap();
        core.step(&cfg, true).unwrap();
        assert_eq!(core.state(), NodeState::Maintenance);
        child.kill().unwrap();
        child.wait().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
