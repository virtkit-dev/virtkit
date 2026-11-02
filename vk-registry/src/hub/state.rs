//! What a registry keeps of its hub's asks across restarts: the desired state it applied, a
//! journal of the commands it was sent — so a command redelivered after a reconnect is
//! answered with its outcome rather than run twice — the last gc it ran and the update in
//! progress. One JSON file, `<root>/hub/state.json`, written whole.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use vk_hub_proto::registry::{DesiredState, GcRun, Operation};
use vk_hub_proto::{CommandAck, Outcome, UpdatePhase, UpdateProgress};
use vk_peer::trial::{Event, Ledger};

pub use vk_peer::trial::Trial;

const STATE_FILE: &str = "state.json";

/// The most commands the journal keeps; past it, the oldest settled ones go.
const JOURNAL_MAX: usize = 256;

/// A command as the registry journaled it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub op: Operation,
    pub expires_at: u64,
    pub outcome: Outcome,
    /// The outcome the hub said it stored; the ack is repeated until it matches.
    #[serde(default)]
    pub recorded: Option<Outcome>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Persisted {
    /// The hub and registry ID these were asked under; a new enrollment forgets them.
    #[serde(default)]
    pub issuer: Option<(String, String)>,
    #[serde(default)]
    pub applied: Option<DesiredState>,
    #[serde(default)]
    pub journal: Vec<Entry>,
    #[serde(default)]
    pub last_gc: Option<GcRun>,
    /// When the scheduled gc last ran.
    #[serde(default)]
    pub scheduled_gc_at: Option<u64>,
    #[serde(default)]
    pub trial: Option<Trial>,
    #[serde(default)]
    pub update: Option<UpdateProgress>,
    /// The installed `vk-registry` an update replaces: the binary `serve` last started from
    /// outside `<root>/hub/`, since a confirmed release goes on running from `releases/`.
    #[serde(default)]
    pub installed: Option<PathBuf>,
}

impl Ledger for Persisted {
    const PROGRAM: &'static str = "vk-registry";
    const PEER: &'static str = "registry";
    const SUBCOMMAND: &'static str = "serve";

    fn load(dir: &Path) -> Result<Self> {
        Persisted::load(dir)
    }

    fn save(&self, dir: &Path) -> Result<()> {
        Persisted::save(self, dir)
    }

    fn trial(&mut self) -> &mut Option<Trial> {
        &mut self.trial
    }

    fn set_progress(&mut self, progress: UpdateProgress) {
        self.update = Some(progress);
    }

    fn set_outcome(&mut self, id: &str, outcome: Outcome) {
        Persisted::set_outcome(self, id, outcome);
    }

    fn log(event: Event<'_>) {
        match event {
            Event::Unreadable(e) | Event::Unwritable(e) => eprintln!("vk-registry: hub: {e:#}"),
            Event::Starting { version, attempt } => {
                eprintln!(
                    "vk-registry: hub: starting vk-registry {version} on trial (attempt {attempt})"
                )
            }
            Event::RolledBack { version, why } => {
                eprintln!("vk-registry: hub: update to {version} rolled back: {why}")
            }
            Event::ConfirmFailed(e) => eprintln!("vk-registry: hub: confirming the update: {e:#}"),
            Event::Installed { version, path } => eprintln!(
                "vk-registry: hub: vk-registry {version} installed at {}",
                path.display()
            ),
            Event::InstallFailed(e) => eprintln!("vk-registry: hub: installing the update: {e:#}"),
            Event::RunInstalledFailed(e) => {
                eprintln!("vk-registry: hub: starting the installed release: {e:#}")
            }
        }
    }
}

impl Persisted {
    /// The state in `dir`, empty when there is none.
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(STATE_FILE);
        match vk_peer::net::read_nofollow(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing {}", path.display())),
            Err(e) if vk_peer::net::is_not_found(&e) => Ok(Persisted::default()),
            Err(e) => Err(e),
        }
    }

    /// Write it whole and private, then sync its directory: confirmation must survive a
    /// crash before the release is installed.
    pub fn save(&self, dir: &Path) -> Result<()> {
        let path = dir.join(STATE_FILE);
        let bytes = serde_json::to_vec_pretty(self).context("encoding the hub state")?;
        vk_fs::write_atomic_durable(&path, &bytes, 0o600)
            .with_context(|| format!("writing {}", path.display()))
    }

    /// Forget requests from another hub or enrollment. Return whether state changed.
    pub fn adopt_issuer(&mut self, hub: &str, id: &str) -> bool {
        let issuer = (hub.to_string(), id.to_string());
        if self.issuer.as_ref() == Some(&issuer) {
            return false;
        }
        *self = Persisted {
            issuer: Some(issuer),
            installed: self.installed.take(),
            ..Persisted::default()
        };
        true
    }

    /// The journaled entry for command `id`.
    pub fn entry(&self, id: &str) -> Option<&Entry> {
        self.journal.iter().find(|e| e.id == id)
    }

    /// Journal a command's first outcome at `now`. Past [`JOURNAL_MAX`], drop the oldest
    /// ended entries the hub stored or that have expired. Pruned expired commands are
    /// refused as expired if redelivered.
    pub fn journal(
        &mut self,
        id: &str,
        op: Operation,
        expires_at: u64,
        outcome: Outcome,
        now: u64,
    ) {
        self.journal.push(Entry {
            id: id.to_string(),
            op,
            expires_at,
            outcome,
            recorded: None,
        });
        while self.journal.len() > JOURNAL_MAX {
            let settled = self.journal.iter().position(|e| {
                e.outcome != Outcome::Accepted
                    && (e.recorded.as_ref() == Some(&e.outcome) || e.expires_at <= now)
            });
            match settled {
                Some(i) => {
                    self.journal.remove(i);
                }
                None => break,
            }
        }
    }

    /// Record command `id`'s new outcome.
    pub fn set_outcome(&mut self, id: &str, outcome: Outcome) {
        if let Some(e) = self.journal.iter_mut().find(|e| e.id == id) {
            e.outcome = outcome;
        }
    }

    /// The acks the hub has not stored yet.
    pub fn unrecorded(&self) -> Vec<CommandAck> {
        self.journal
            .iter()
            .filter(|e| e.recorded.as_ref() != Some(&e.outcome))
            .map(|e| CommandAck {
                id: e.id.clone(),
                outcome: e.outcome.clone(),
            })
            .collect()
    }

    /// Whether an update command is under way: accepted and not ended.
    pub fn update_under_way(&self) -> bool {
        self.journal
            .iter()
            .any(|e| matches!(e.op, Operation::Update { .. }) && e.outcome == Outcome::Accepted)
    }

    /// Fail what a restart cut short: every accepted command but the update on trial, and
    /// the progress of an update that never reached its trial. Whether anything changed.
    pub fn fail_interrupted(&mut self) -> bool {
        const WHY: &str = "interrupted by a restart";
        let on_trial = self.trial.as_ref().map(|t| t.command.clone());
        let mut changed = false;
        for e in &mut self.journal {
            if e.outcome == Outcome::Accepted && on_trial.as_ref() != Some(&e.id) {
                e.outcome = Outcome::Failed {
                    message: WHY.to_string(),
                };
                changed = true;
            }
        }
        if let Some(u) = &mut self.update
            && matches!(u.phase, UpdatePhase::Downloading | UpdatePhase::Validating)
            && on_trial.as_ref() != Some(&u.command)
        {
            u.phase = UpdatePhase::Failed;
            u.message = Some(WHY.to_string());
            changed = true;
        }
        changed
    }

    /// The hub stored `ack`.
    pub fn recorded(&mut self, ack: &CommandAck) {
        if let Some(e) = self.journal.iter_mut().find(|e| e.id == ack.id) {
            e.recorded = Some(ack.outcome.clone());
        }
    }

    /// Whether recording `ack` would change state. False for an ack already stored or a
    /// command not journaled.
    pub fn records(&self, ack: &CommandAck) -> bool {
        self.entry(&ack.id)
            .is_some_and(|e| e.recorded.as_ref() != Some(&ack.outcome))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gc() -> Operation {
        Operation::Gc {
            retention_days: 30,
            grace_days: 1,
            dry_run: false,
        }
    }

    #[test]
    fn an_ack_is_repeated_until_the_hub_stores_it() {
        let mut p = Persisted::default();
        p.journal("a", gc(), 10, Outcome::Accepted, 0);
        assert_eq!(p.unrecorded().len(), 1);
        let ack = CommandAck {
            id: "a".into(),
            outcome: Outcome::Accepted,
        };
        assert!(p.records(&ack));
        p.recorded(&ack);
        assert!(p.unrecorded().is_empty());
        // Stored already, or never journaled: nothing to save.
        assert!(!p.records(&ack));
        assert!(!p.records(&CommandAck {
            id: "b".into(),
            outcome: Outcome::Done,
        }));
        p.set_outcome("a", Outcome::Done);
        assert_eq!(p.unrecorded()[0].outcome, Outcome::Done);
    }

    #[test]
    fn another_hub_s_asks_are_forgotten() {
        let mut p = Persisted::default();
        assert!(p.adopt_issuer("https://a", "1"));
        p.journal("x", gc(), 10, Outcome::Done, 0);
        assert!(!p.adopt_issuer("https://a", "1"));
        assert!(p.entry("x").is_some());
        assert!(p.adopt_issuer("https://b", "1"));
        assert!(p.entry("x").is_none());
    }

    /// Unrecorded entries are pruned only once expired; commands under way stay.
    #[test]
    fn the_journal_drops_expired_entries_the_hub_never_stored() {
        let mut p = Persisted::default();
        p.journal("accepted", gc(), 10, Outcome::Accepted, 0);
        p.journal("live", gc(), 1000, Outcome::Done, 0);
        for i in 0..JOURNAL_MAX {
            p.journal(&i.to_string(), gc(), 10, Outcome::Done, 100);
        }
        assert_eq!(p.journal.len(), JOURNAL_MAX);
        assert!(p.entry("accepted").is_some() && p.entry("live").is_some());
        assert!(p.entry("0").is_none() && p.entry("1").is_none());
    }

    #[test]
    fn the_journal_is_bounded_by_settled_entries() {
        let mut p = Persisted::default();
        for i in 0..JOURNAL_MAX + 10 {
            let id = i.to_string();
            p.journal(&id, gc(), 10, Outcome::Done, 0);
            p.recorded(&CommandAck {
                id,
                outcome: Outcome::Done,
            });
        }
        assert_eq!(p.journal.len(), JOURNAL_MAX);
        assert!(p.entry("0").is_none());
    }

    #[test]
    fn a_restart_fails_what_it_interrupted_but_the_trial() {
        let update = || Operation::Update {
            version: "9.9.9".into(),
            sha256: "0".repeat(64),
            size: 1,
            signature: None,
        };
        let progress = |command: &str| UpdateProgress {
            command: command.into(),
            version: "9.9.9".into(),
            sha256: "0".repeat(64),
            phase: UpdatePhase::Downloading,
            message: None,
        };
        let mut p = Persisted::default();
        p.journal("gc", gc(), 10, Outcome::Accepted, 0);
        p.journal("u", update(), 10, Outcome::Accepted, 0);
        p.journal("done", gc(), 10, Outcome::Done, 0);
        p.update = Some(progress("u"));
        assert!(p.update_under_way());
        assert!(p.fail_interrupted());
        for id in ["gc", "u"] {
            assert!(matches!(
                p.entry(id).unwrap().outcome,
                Outcome::Failed { .. }
            ));
        }
        assert_eq!(p.entry("done").unwrap().outcome, Outcome::Done);
        assert_eq!(p.update.as_ref().unwrap().phase, UpdatePhase::Failed);
        assert!(!p.update_under_way());
        assert!(!p.fail_interrupted());

        // The update on trial goes on: the release confirms or the previous binary ends it.
        p.journal("t", update(), 10, Outcome::Accepted, 0);
        p.update = Some(UpdateProgress {
            phase: UpdatePhase::Validating,
            ..progress("t")
        });
        p.trial = Some(Trial {
            command: "t".into(),
            version: "9.9.9".into(),
            sha256: "0".repeat(64),
            exe: PathBuf::from("/x"),
            exe_id: (0, 0),
            next: PathBuf::from("/y"),
            previous: "1".repeat(64),
            attempts: 1,
            deadline: 1,
            confirmed: false,
        });
        assert!(!p.fail_interrupted());
        assert_eq!(p.entry("t").unwrap().outcome, Outcome::Accepted);
        assert!(p.update_under_way());
    }
}
