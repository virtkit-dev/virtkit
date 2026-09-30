//! What the node remembers of what its hub asked: the desired state it last applied, its own
//! [`NodeState`], and the journal of commands it received. One file, `state.json` under
//! `<state_dir>/node/`, rewritten whole on every change, so a restart — or a hub that is gone
//! — leaves the node exactly where it was.
//!
//! A command is journaled by its ID before anything acts on it: the entry and the state change
//! it makes are written together, and only then does the rest of the node (the runner, the
//! concurrency loop) follow the new state. A command delivered again after a reconnect finds
//! its entry and gets the recorded outcome back, not a second application. A desired-state
//! generation is applied at most once the same way: one not newer than the applied one is
//! ignored. Generations are numbered by one hub for one enrollment, so the state names the
//! pair it holds them for, and forgets the applied generation — not the node's own state —
//! when the node has since enrolled anew or with another hub.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use vk_fleet_proto::{Command, CommandAck, DesiredState, NodeState, Operation, Outcome};

const STATE_FILE: &str = "state.json";

/// The most journal entries kept, whatever their expiry. A settled entry is kept until its
/// command expires — until then the hub may redeliver it, and a node that had forgotten it
/// would run it twice; after that, a redelivery is refused as expired anyway. This bounds
/// what a hub issuing commands faster than they expire can make the file hold.
const JOURNAL_MAX: usize = 4096;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Persisted {
    /// The hub and node ID the applied generation and the journal belong to.
    #[serde(default)]
    pub issuer: Option<Issuer>,
    #[serde(default)]
    pub applied: Option<DesiredState>,
    #[serde(default)]
    pub state: NodeState,
    #[serde(default)]
    pub journal: Vec<Entry>,
}

/// Whose generations and commands these are.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issuer {
    pub hub: String,
    pub node_id: String,
}

/// One journaled command and what became of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub op: Operation,
    pub expires_at: u64,
    pub received_at: u64,
    pub outcome: Outcome,
    /// The outcome the hub last said it stored; the ack is repeated until this matches.
    #[serde(default)]
    pub recorded: Option<Outcome>,
}

impl Entry {
    fn ack(&self) -> CommandAck {
        CommandAck {
            id: self.id.clone(),
            outcome: self.outcome.clone(),
        }
    }
}

/// `<dir>/state.json`.
pub fn path(dir: &Path) -> PathBuf {
    dir.join(STATE_FILE)
}

impl Persisted {
    /// The state in `dir`, or the initial one — ready, nothing applied — when there is none.
    pub fn load(dir: &Path) -> Result<Self> {
        let path = path(dir);
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Persisted::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Write the state whole, `0600`, published by `rename`.
    pub fn save(&self, dir: &Path) -> Result<()> {
        let json = serde_json::to_vec_pretty(self).context("encoding the node state")?;
        let path = path(dir);
        vk_fs::write_atomic(&path, &json, 0o600)
            .with_context(|| format!("writing {}", path.display()))
    }

    /// Whether the runner is to take no jobs: the hub asked for that, or the node is not
    /// ready.
    pub fn acquisition_stopped(&self) -> bool {
        self.state != NodeState::Ready
            || self
                .applied
                .as_ref()
                .is_some_and(|d| d.acquisition == vk_fleet_proto::Acquisition::Stop)
    }

    /// The hub's concurrency ceiling, from the applied desired state.
    pub fn hub_ceiling(&self) -> Option<u32> {
        self.applied.as_ref().and_then(|d| d.ceiling)
    }

    /// Hold what follows for `issuer`. For another one than before — a re-enrollment, another
    /// hub — the applied generation and the journal go: they count and name things for the
    /// previous one. The node's own state stays: a drain or quarantine is the host's, whoever
    /// asked for it. Returns whether anything was forgotten.
    pub fn adopt_issuer(&mut self, issuer: Issuer) -> bool {
        if self.issuer.as_ref() == Some(&issuer) {
            return false;
        }
        let forgot = self.issuer.is_some() || self.applied.is_some() || !self.journal.is_empty();
        self.issuer = Some(issuer);
        self.applied = None;
        self.journal.clear();
        forgot
    }

    /// Take `desired` unless a generation at least as new is already applied. Returns whether
    /// it changed anything.
    pub fn apply_desired(&mut self, desired: DesiredState) -> bool {
        if self
            .applied
            .as_ref()
            .is_some_and(|a| a.generation >= desired.generation)
        {
            return false;
        }
        self.applied = Some(desired);
        true
    }

    /// Journal `command` and make the state change it asks for, answering with its outcome. A
    /// command already journaled is answered with what it came to then.
    pub fn command(&mut self, command: Command, now: u64) -> CommandAck {
        if let Some(entry) = self.journal.iter().find(|e| e.id == command.id) {
            return entry.ack();
        }
        let outcome = if now >= command.expires_at {
            Outcome::Expired
        } else {
            self.execute(&command.op)
        };
        let entry = Entry {
            id: command.id,
            op: command.op,
            expires_at: command.expires_at,
            received_at: now,
            outcome,
            recorded: None,
        };
        let ack = entry.ack();
        self.journal.push(entry);
        self.prune(now);
        ack
    }

    /// A drain and a quarantine stop the runner taking jobs, which this node cannot do to a
    /// runner it does not run; undrain and release have nothing to undo.
    fn execute(&mut self, op: &Operation) -> Outcome {
        let refused = |reason: &str| Outcome::Refused {
            reason: reason.to_string(),
        };
        match op {
            Operation::Drain | Operation::Quarantine => {
                refused("vk node cannot stop a runner it does not run")
            }
            Operation::Undrain | Operation::Release => Outcome::Done,
            Operation::Update { .. } | Operation::Reset => {
                refused("this vk does not run that operation yet")
            }
        }
    }

    /// Every ack whose current outcome the hub has not recorded.
    pub fn unrecorded(&self) -> Vec<CommandAck> {
        self.journal
            .iter()
            .filter(|e| e.recorded.as_ref() != Some(&e.outcome))
            .map(Entry::ack)
            .collect()
    }

    /// The hub stored `ack`. Returns whether that settled anything.
    pub fn recorded(&mut self, ack: &CommandAck, now: u64) -> bool {
        match self.journal.iter_mut().find(|e| e.id == ack.id) {
            Some(entry) if entry.recorded.as_ref() != Some(&ack.outcome) => {
                entry.recorded = Some(ack.outcome.clone());
                self.prune(now);
                true
            }
            _ => false,
        }
    }

    /// Drop settled entries whose commands have expired, and past [`JOURNAL_MAX`] the oldest
    /// settled ones. An entry the hub has not yet recorded, or one still under way, is never
    /// dropped.
    fn prune(&mut self, now: u64) {
        let settled =
            |e: &Entry| e.recorded.as_ref() == Some(&e.outcome) && e.outcome != Outcome::Accepted;
        self.journal
            .retain(|e| !(settled(e) && now >= e.expires_at));
        let mut excess = self
            .journal
            .iter()
            .filter(|e| settled(e))
            .count()
            .saturating_sub(JOURNAL_MAX);
        self.journal.retain(|e| {
            if excess > 0 && settled(e) {
                excess -= 1;
                false
            } else {
                true
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vk_fleet_proto::Acquisition;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-node-state-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn desired(generation: u64, ceiling: Option<u32>, acquisition: Acquisition) -> DesiredState {
        DesiredState {
            generation,
            ceiling,
            acquisition,
        }
    }

    fn command(id: &str, op: Operation) -> Command {
        Command {
            id: id.to_string(),
            expires_at: 1000,
            op,
        }
    }

    #[test]
    fn a_generation_is_applied_once_across_restarts() {
        let dir = scratch("apply");
        let mut p = Persisted::load(&dir).unwrap();
        assert_eq!(p, Persisted::default());
        assert!(p.apply_desired(desired(2, Some(4), Acquisition::Run)));
        p.save(&dir).unwrap();
        let mut p = Persisted::load(&dir).unwrap();
        assert_eq!(p.hub_ceiling(), Some(4));
        // The same generation again, or an older one, changes nothing.
        assert!(!p.apply_desired(desired(2, Some(9), Acquisition::Stop)));
        assert!(!p.apply_desired(desired(1, None, Acquisition::Stop)));
        assert_eq!(p.hub_ceiling(), Some(4));
        assert!(!p.acquisition_stopped());
        assert!(p.apply_desired(desired(3, None, Acquisition::Stop)));
        assert!(p.acquisition_stopped());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_redelivered_command_gets_its_recorded_outcome_not_a_second_run() {
        let dir = scratch("redeliver");
        let mut p = Persisted::default();
        let ack = p.command(command("a", Operation::Release), 10);
        assert_eq!(ack.outcome, Outcome::Done);
        p.save(&dir).unwrap();
        let mut p = Persisted::load(&dir).unwrap();
        let journal = p.journal.clone();
        let again = p.command(command("a", Operation::Release), 12);
        assert_eq!(again, ack);
        assert_eq!(p.journal, journal);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn acks_repeat_until_recorded_and_expired_commands_do_nothing() {
        let mut p = Persisted::default();
        p.command(command("a", Operation::Undrain), 10);
        assert_eq!(p.unrecorded().len(), 1);
        let first = p.unrecorded().remove(0);
        assert!(p.recorded(&first, 10));
        assert!(p.unrecorded().is_empty());
        let late = p.command(command("b", Operation::Undrain), 1000);
        assert_eq!(late.outcome, Outcome::Expired);
        assert_eq!(p.unrecorded(), [late]);
    }

    #[test]
    fn a_runner_this_node_does_not_run_is_neither_drained_nor_quarantined() {
        let mut p = Persisted::default();
        for op in [Operation::Drain, Operation::Quarantine, Operation::Reset] {
            let ack = p.command(command(&format!("{op:?}"), op), 1);
            assert!(matches!(ack.outcome, Outcome::Refused { .. }), "{ack:?}");
        }
        assert_eq!(p.state, NodeState::Ready);
    }

    #[test]
    fn a_settled_entry_is_kept_until_its_command_expires() {
        let mut p = Persisted::default();
        let ack = p.command(command("a", Operation::Release), 1);
        p.recorded(&ack, 2);
        // Settled but not expired: a redelivery must still find it.
        assert_eq!(p.journal.len(), 1);
        let open = p.command(command("b", Operation::Release), 999);
        assert_eq!(p.journal.len(), 2);
        // Past its expiry (1000) the settled one goes; the one the hub has not recorded stays.
        let c = p.command(command("c", Operation::Release), 1000);
        assert_eq!(c.outcome, Outcome::Expired);
        assert!(!p.journal.iter().any(|e| e.id == "a"));
        assert!(p.journal.iter().any(|e| e.id == open.id));
        // And past the cap, the oldest settled entries go first.
        let mut p = Persisted::default();
        for i in 0..JOURNAL_MAX + 3 {
            let mut c = command(&i.to_string(), Operation::Release);
            c.expires_at = u64::MAX;
            let ack = p.command(c, 1);
            p.recorded(&ack, 1);
        }
        assert_eq!(p.journal.len(), JOURNAL_MAX);
        assert!(!p.journal.iter().any(|e| e.id == "0"));
    }

    #[test]
    fn another_issuer_forgets_the_applied_generation_but_not_the_node_state() {
        let issuer = |hub: &str| Issuer {
            hub: hub.into(),
            node_id: "ab".repeat(16),
        };
        let mut p = Persisted::default();
        assert!(!p.adopt_issuer(issuer("https://a")));
        p.apply_desired(desired(7, Some(2), Acquisition::Run));
        p.command(command("u", Operation::Undrain), 1);
        p.state = NodeState::Drained;
        assert!(!p.adopt_issuer(issuer("https://a")));
        assert_eq!(p.hub_ceiling(), Some(2));
        // Re-enrolled, or another hub: generation 1 is new again, and the node's state holds.
        assert!(p.adopt_issuer(issuer("https://b")));
        assert_eq!(p.applied, None);
        assert!(p.journal.is_empty());
        assert_eq!(p.state, NodeState::Drained);
        assert!(p.apply_desired(desired(1, None, Acquisition::Run)));
    }
}
