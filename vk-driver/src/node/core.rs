//! Shared state for `vk node run`: persisted state ([`Persisted`]) and the last calculated
//! concurrency. The session reads a [`Report`] and applies hub messages here;
//! [`Core::control`] sets the runner's concurrency.
//!
//! Without a hub session, the node keeps applying its last desired state.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use anyhow::Result;
use tokio::sync::watch;
use vk_hub_proto::{
    Acquisition, Command, CommandAck, Concurrency, DesiredState, Report, RunnerMode,
};

use super::state::{Issuer, Persisted};
use crate::config::Config;

pub struct Core {
    dir: PathBuf,
    persisted: Mutex<Persisted>,
    concurrency: Mutex<Option<Concurrency>>,
    /// Why the last attempt at setting the concurrency failed, if it did.
    concurrency_error: Mutex<Option<String>>,
    /// Bumped on every change to what the node tells the hub: its report or its unrecorded
    /// acks.
    changed: watch::Sender<u64>,
}

impl Core {
    /// Load the state in `dir`, for `issuer` — the hub and node ID the node is enrolled as.
    pub fn open(dir: &Path, issuer: Issuer) -> Result<Arc<Core>> {
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
        let (changed, _) = watch::channel(0);
        Ok(Arc::new(Core {
            dir: dir.to_path_buf(),
            persisted: Mutex::new(persisted),
            concurrency: Mutex::new(None),
            concurrency_error: Mutex::new(None),
            changed,
        }))
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

    /// Journal `command` and carry it out. This node runs no runner of its own, so it cannot
    /// stop one: a drain or a quarantine is refused.
    pub fn command(&self, command: Command, now: u64) -> Result<CommandAck> {
        self.update(|p| p.command(command, now))
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
        let mut unsupported = Vec::new();
        if persisted.acquisition_stopped() {
            unsupported.push(
                "stopping acquisition: the runner is external, so only its concurrency is steered"
                    .to_string(),
            );
        }
        Report {
            applied_generation: persisted.applied.as_ref().map(|d| d.generation),
            unsupported,
            state: Some(persisted.state),
            acquisition: Some(Acquisition::Run),
            runner: Some(RunnerMode::External),
            concurrency: *lock(&self.concurrency),
            concurrency_error: lock(&self.concurrency_error).clone(),
            ..Report::default()
        }
    }

    /// Set the runner's concurrency every `every`, and whenever the state changes. Runs until
    /// `stop`.
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
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let may_rise = tokio::select! {
                _ = tick.tick() => true,
                _ = changes.changed() => false,
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

    /// One pass of the loop. A failure is reported rather than only logged.
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
                let message = format!("{e:#}");
                if lock(&self.concurrency_error).as_deref() != Some(&message) {
                    say!("setting the runner's concurrency: {message}");
                }
                self.set(&self.concurrency_error, Some(message));
            }
        }
    }
}

/// A lock whose holder panicked still guards whole values — each is replaced in one
/// assignment — so poisoning is ignored.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn the_hub_ceiling_binds_and_an_external_runner_says_what_it_cannot_do() {
        let dir = scratch("ceiling");
        let core = Core::open(&dir, issuer()).unwrap();
        let cfg = cfg(&dir);
        core.apply_desired(DesiredState {
            generation: 1,
            ceiling: Some(2),
            acquisition: Acquisition::Stop,
        })
        .unwrap();
        core.step(&cfg, true);
        let report = core.report();
        assert_eq!(report.applied_generation, Some(1));
        assert_eq!(report.concurrency.unwrap().effective, Some(2));
        assert_eq!(
            std::fs::read_to_string(crate::schedule::desired_file(&cfg)).unwrap(),
            "2\n"
        );
        // External: the runner goes on taking jobs, and the report says why.
        assert_eq!(report.acquisition, Some(Acquisition::Run));
        assert_eq!(report.runner, Some(RunnerMode::External));
        assert_eq!(report.unsupported.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_concurrency_that_cannot_be_set_is_reported() {
        let dir = scratch("broken");
        let cfg: Config = toml::from_str(&format!(
            "state_dir = {:?}\n[executor.vm]\nmem = \"lots\"\n[executor.schedule]\n\
             mem_budget = \"32G\"\n",
            dir.join("state").display().to_string()
        ))
        .unwrap();
        let core = Core::open(&dir, issuer()).unwrap();
        core.step(&cfg, true);
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
        let core = Core::open(&dir, issuer()).unwrap();
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
