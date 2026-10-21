//! Reservations the hub asks this node to hold: each decided at once against the admission
//! ledger (`crate::admit`) — granted or refused with the resource that is short, never queued
//! — and held there as an entry with no job behind it until its lease runs out on the node's
//! monotonic clock, the hub releases it, or a job takes it over.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use vk_hub_proto::dispatch::{
    HeldReservation, LeaseEnd, LeaseState, MAX_LEASE_SECS, OfferReply, Refusal,
};
use vk_hub_proto::job::Envelope;

use crate::admit::{self, Short};

/// What the node admits against.
#[derive(Clone)]
pub struct Limits {
    /// The ledger's directory.
    pub admit_dir: PathBuf,
    /// Where job dirs are made, which disk admission measures.
    pub jobs_dir: PathBuf,
    /// What a disk shortage evicts from; `None` keeps everything.
    pub reclaim: Option<Reclaimer>,
    /// `[executor.schedule] mem_budget`, MiB; `None` with memory admission off.
    pub budget_mib: Option<u64>,
    pub disk_admission: bool,
    /// The most vCPUs a job may have.
    pub max_cpus: u32,
}

/// Frees `need` more bytes of room on the job dirs' filesystem, keeping the bases it is given.
pub type Reclaimer = Arc<dyn Fn(u64, &[PathBuf]) -> admit::Reclaimed + Send + Sync>;

/// The node's [`Reclaimer`]: evict the cached images under `state_dir` nobody holds on the
/// filesystem of `jobs_dir`, all or nothing (see `image::evict_for_room`), giving a base just
/// resolved the grace `idle` (`image_cache_idle_secs`) bounds.
pub fn evicting(state_dir: PathBuf, idle: Duration, jobs_dir: PathBuf) -> Reclaimer {
    Arc::new(move |need, keep| {
        crate::image::evict_for_room(
            &state_dir,
            idle,
            &jobs_dir,
            need,
            keep,
            crate::image::EVICT_WAIT,
        )
        .reclaimed()
    })
}

impl Limits {
    /// Have the [`Reclaimer`] free `need` bytes, keeping `keep`. Slow next to an admission pass,
    /// so run outside the node's locks.
    pub fn reclaim(&self, need: u64, keep: &[PathBuf]) -> admit::Reclaimed {
        self.reclaim
            .as_ref()
            .map_or_else(admit::Reclaimed::default, |r| r(need, keep))
    }
}

/// An ask the ledger refused: why, in the hub's words, and where the disk alone kept it out
/// and this node evicts caches for room, the bytes [`Limits::reclaim`] would have to free for
/// it to fit.
#[derive(Debug)]
pub struct Refused {
    pub reason: Refusal,
    pub message: String,
    pub reclaim: Option<u64>,
}

/// What [`Ledger::offer`] answers, and where it refused for want of disk that eviction might
/// free, how much: for the caller to free outside its locks and offer again.
#[derive(Debug)]
pub struct Offered {
    pub reply: OfferReply,
    pub reclaim: Option<u64>,
}

struct Entry {
    envelope: Envelope,
    expires: Instant,
    /// The ledger entry; `None` where admission is off and there is nothing to hold.
    held: Option<admit::Reservation>,
}

/// Whether the node takes new placed work: a reservation, or a job not on one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    Open,
    /// The host runs a gitlab-runner of its own with the vk executor: it takes no placed work.
    Runner,
    /// Draining, drained, quarantined, in maintenance, or with acquisition stopped.
    NotReady,
    /// The node's placed jobs not finished and its reservations, `held` of them, reach the
    /// hub's concurrency ceiling.
    Ceiling {
        ceiling: u32,
        held: usize,
    },
    /// The same, at the node's own limit (`[executor.schedule] max_concurrency`), below the
    /// hub's ceiling if any.
    Concurrency {
        limit: u32,
        held: usize,
    },
}

impl Gate {
    /// Why a closed gate refuses, in the hub's words; `None` when it is open.
    pub fn refusal(self) -> Option<(Refusal, Option<String>)> {
        match self {
            Gate::Open => None,
            Gate::Runner => Some((
                Refusal::Runner,
                Some(
                    "this host runs its own gitlab-runner with the vk executor, and a host runs \
                     one or the other"
                        .into(),
                ),
            )),
            Gate::NotReady => Some((Refusal::NotReady, None)),
            Gate::Ceiling { ceiling, held } => Some((
                Refusal::Ceiling,
                Some(format!(
                    "{held} placed jobs and reservations reach the hub's ceiling of {ceiling}"
                )),
            )),
            Gate::Concurrency { limit, held } => Some((
                Refusal::Concurrency,
                Some(format!(
                    "{held} placed jobs and reservations reach [executor.schedule] \
                     max_concurrency = {limit}"
                )),
            )),
        }
    }
}

pub struct Ledger {
    limits: Limits,
    entries: BTreeMap<String, Entry>,
}

/// Why an ask does not fit, in the hub's words.
pub fn refusal(short: Short, ask: &Envelope, limits: &Limits) -> (Refusal, String) {
    match short {
        Short::Memory => (
            Refusal::Memory,
            format!(
                "{} MiB does not fit the node's memory budget of {} MiB",
                ask.mem_mib,
                limits.budget_mib.unwrap_or(0)
            ),
        ),
        Short::Disk { .. } => (
            Refusal::Disk,
            format!("{} bytes of job-dir disk do not fit", ask.disk_bytes),
        ),
        Short::Queue => (
            match limits.budget_mib {
                Some(_) => Refusal::Memory,
                None => Refusal::Disk,
            },
            "jobs on this node are waiting for room".into(),
        ),
    }
}

impl Ledger {
    pub fn new(limits: Limits) -> Ledger {
        Ledger {
            limits,
            entries: BTreeMap::new(),
        }
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Hold `envelope` under `name` in the admission ledger now, or say what is short. Evicts
    /// nothing itself: a refusal for disk says what [`Limits::reclaim`] would have to free.
    pub fn admit(
        &self,
        name: &str,
        envelope: &Envelope,
    ) -> Result<Option<admit::Reservation>, Refused> {
        if envelope.cpus > self.limits.max_cpus {
            return Err(Refused {
                reason: Refusal::Cpus,
                message: format!(
                    "{} vCPUs is more than this node gives a job ({})",
                    envelope.cpus, self.limits.max_cpus
                ),
                reclaim: None,
            });
        }
        let ask = admit::Ask {
            mem: self.limits.budget_mib.map(|budget_mib| admit::MemAsk {
                want_mib: envelope.mem_mib,
                budget_mib,
            }),
            disk: (self.limits.disk_admission && envelope.disk_bytes > 0).then(|| admit::DiskAsk {
                want: envelope.disk_bytes,
                jobs: &self.limits.jobs_dir,
                reclaim: None,
            }),
        };
        if ask.mem.is_none() && ask.disk.is_none() {
            return Ok(None);
        }
        match admit::try_acquire(&self.limits.admit_dir, name, &ask) {
            Ok(Ok(r)) => Ok(Some(r)),
            Ok(Err(short)) => {
                let (reason, message) = refusal(short, envelope, &self.limits);
                let reclaim = match short {
                    Short::Disk { need } if self.limits.reclaim.is_some() => need,
                    _ => None,
                };
                Err(Refused {
                    reason,
                    message,
                    reclaim,
                })
            }
            Err(e) => Err(Refused {
                reason: Refusal::Other,
                message: format!("{e:#}"),
                reclaim: None,
            }),
        }
    }

    /// How many reservations are held.
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// The hub's offer: granted for at most [`MAX_LEASE_SECS`], or refused. An offer of a
    /// reservation already held renews it, keeping the envelope it was granted with, whatever
    /// `gate` says of new work.
    pub fn offer(
        &mut self,
        id: &str,
        envelope: Envelope,
        lease_secs: u32,
        gate: Gate,
        now: Instant,
    ) -> Offered {
        let reply = |reply| Offered {
            reply,
            reclaim: None,
        };
        if !vk_hub_proto::valid_id(id) || lease_secs == 0 {
            return reply(OfferReply::Refused {
                reason: Refusal::Invalid,
                message: None,
            });
        }
        let lease = lease_secs.min(MAX_LEASE_SECS);
        if let Some(entry) = self.entries.get_mut(id) {
            entry.expires = now + Duration::from_secs(lease.into());
            return reply(OfferReply::Accepted { lease_secs: lease });
        }
        if let Some((reason, message)) = gate.refusal() {
            return reply(OfferReply::Refused { reason, message });
        }
        match self.admit(&ledger_name(id), &envelope) {
            Ok(held) => {
                self.entries.insert(
                    id.to_string(),
                    Entry {
                        envelope,
                        expires: now + Duration::from_secs(lease.into()),
                        held,
                    },
                );
                reply(OfferReply::Accepted { lease_secs: lease })
            }
            Err(refused) => Offered {
                reply: OfferReply::Refused {
                    reason: refused.reason,
                    message: Some(refused.message),
                },
                reclaim: refused.reclaim,
            },
        }
    }

    pub fn renew(&mut self, id: &str, lease_secs: u32, now: Instant) -> LeaseState {
        match self.entries.get_mut(id) {
            Some(entry) => {
                let lease = lease_secs.clamp(1, MAX_LEASE_SECS);
                entry.expires = now + Duration::from_secs(lease.into());
                LeaseState::Held {
                    remaining_secs: lease,
                }
            }
            None => LeaseState::Gone {
                why: LeaseEnd::Unknown,
            },
        }
    }

    /// Give a reservation back; one already gone answers `released` too.
    pub fn release(&mut self, id: &str) -> LeaseState {
        self.drop_entry(id);
        LeaseState::Gone {
            why: LeaseEnd::Released,
        }
    }

    /// Release every reservation, as a quarantine does: their IDs.
    pub fn release_all(&mut self) -> Vec<String> {
        let ids: Vec<String> = self.entries.keys().cloned().collect();
        for id in &ids {
            self.drop_entry(id);
        }
        ids
    }

    /// Drop reservation `id` and its ledger entry. The entry's file goes too: closing it is
    /// not enough, as a child forked meanwhile and not yet exec'd shares its lock, keeping
    /// it counted until then.
    fn drop_entry(&mut self, id: &str) {
        if let Some(Entry { held: Some(_), .. }) = self.entries.remove(id) {
            admit::release(&self.limits.admit_dir, &ledger_name(id));
        }
    }

    /// Drop the reservations whose lease ran out: their IDs.
    pub fn expire(&mut self, now: Instant) -> Vec<String> {
        let gone: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| e.expires <= now)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &gone {
            self.drop_entry(id);
        }
        gone
    }

    /// A job takes the reservation over: its envelope and ledger entry. `None` when it is not
    /// held.
    pub fn take(&mut self, id: &str) -> Option<(Envelope, Option<admit::Reservation>)> {
        self.entries.remove(id).map(|e| (e.envelope, e.held))
    }

    pub fn held(&self, now: Instant) -> Vec<HeldReservation> {
        self.entries
            .iter()
            .map(|(id, e)| HeldReservation {
                reservation: id.clone(),
                envelope: e.envelope,
                remaining_secs: u32::try_from(e.expires.saturating_duration_since(now).as_secs())
                    .unwrap_or(u32::MAX),
            })
            .collect()
    }
}

/// A reservation's ledger entry: named apart from any job's, whose entries are GitLab job IDs.
pub fn ledger_name(id: &str) -> String {
    format!("reservation-{id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(c: &str) -> String {
        c.repeat(32)
    }

    fn ledger(tag: &str, budget: Option<u64>) -> (Ledger, PathBuf) {
        let dir = std::env::temp_dir().join(format!("vk-ledger-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("jobs")).unwrap();
        let limits = Limits {
            admit_dir: dir.join("admit"),
            jobs_dir: dir.join("jobs"),
            reclaim: None,
            budget_mib: budget,
            disk_admission: false,
            max_cpus: 8,
        };
        (Ledger::new(limits), dir)
    }

    fn env(mem_mib: u64, cpus: u32) -> Envelope {
        Envelope {
            mem_mib,
            cpus,
            disk_bytes: 0,
        }
    }

    #[test]
    fn offers_are_decided_at_once_against_the_budget() {
        let (mut l, dir) = ledger("budget", Some(8192));
        let now = Instant::now();
        assert_eq!(
            l.offer(&id("a"), env(6144, 4), 90, Gate::Open, now).reply,
            OfferReply::Accepted { lease_secs: 90 }
        );
        // The first one's memory is held: a second does not fit, and says why.
        let OfferReply::Refused { reason, .. } =
            l.offer(&id("b"), env(4096, 4), 90, Gate::Open, now).reply
        else {
            panic!("a second offer over the budget was granted");
        };
        assert_eq!(reason, Refusal::Memory);
        // Released, its memory is free again.
        assert_eq!(
            l.release(&id("a")),
            LeaseState::Gone {
                why: LeaseEnd::Released
            }
        );
        assert!(matches!(
            l.offer(&id("b"), env(4096, 4), 90, Gate::Open, now).reply,
            OfferReply::Accepted { .. }
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn leases_are_capped_renewed_and_expire_on_the_nodes_clock() {
        let (mut l, dir) = ledger("lease", Some(8192));
        let now = Instant::now();
        assert_eq!(
            l.offer(&id("a"), env(1024, 1), 3600, Gate::Open, now).reply,
            OfferReply::Accepted {
                lease_secs: MAX_LEASE_SECS
            }
        );
        assert_eq!(
            l.renew(&id("a"), 30, now),
            LeaseState::Held { remaining_secs: 30 }
        );
        assert!(l.expire(now + Duration::from_secs(29)).is_empty());
        assert_eq!(l.expire(now + Duration::from_secs(30)), vec![id("a")]);
        assert_eq!(
            l.renew(&id("a"), 30, now),
            LeaseState::Gone {
                why: LeaseEnd::Unknown
            }
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_node_not_ready_or_short_of_cpus_refuses() {
        let (mut l, dir) = ledger("refuse", None);
        let now = Instant::now();
        assert_eq!(
            l.offer(&id("a"), env(1, 1), 90, Gate::NotReady, now).reply,
            OfferReply::Refused {
                reason: Refusal::NotReady,
                message: None
            }
        );
        assert!(matches!(
            l.offer(&id("a"), env(1, 9), 90, Gate::Open, now).reply,
            OfferReply::Refused {
                reason: Refusal::Cpus,
                ..
            }
        ));
        assert!(matches!(
            l.offer("not-an-id", env(1, 1), 90, Gate::Open, now).reply,
            OfferReply::Refused {
                reason: Refusal::Invalid,
                ..
            }
        ));
        // Without admission there is nothing to hold, and the offer is granted.
        assert!(matches!(
            l.offer(&id("a"), env(1 << 20, 1), 90, Gate::Open, now)
                .reply,
            OfferReply::Accepted { .. }
        ));
        let (envelope, held) = l.take(&id("a")).unwrap();
        assert_eq!(envelope.mem_mib, 1 << 20);
        assert!(held.is_none() && l.take(&id("a")).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A node enrolled before it ran any job has no job-dir directory yet: disk admission
    /// makes it rather than refusing every offer.
    #[test]
    fn a_node_with_no_job_dirs_yet_grants_a_disk_reservation() {
        let (mut l, dir) = ledger("fresh", None);
        std::fs::remove_dir(&l.limits.jobs_dir).unwrap();
        l.limits.disk_admission = true;
        let now = Instant::now();
        let ask = Envelope {
            disk_bytes: 1 << 20,
            ..env(1, 1)
        };
        assert_eq!(
            l.offer(&id("a"), ask, 90, Gate::Open, now).reply,
            OfferReply::Accepted { lease_secs: 90 }
        );
        assert!(l.limits.jobs_dir.is_dir());
        let (_, held) = l.take(&id("a")).unwrap();
        assert!(held.is_some(), "the disk claim is held in the ledger");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Short of disk, an offer evicts nothing itself: it says what eviction would have to free,
    /// where the node evicts for room at all, for its caller to free outside its locks. That
    /// eviction is all or nothing: a need the caches cannot cover takes nothing from them.
    #[test]
    fn a_disk_short_offer_says_what_eviction_must_free() {
        let (mut l, dir) = ledger("reclaim", None);
        l.limits.disk_admission = true;
        // Alone on the filesystem a claim on all of it is granted, leaving no room for another.
        let total = crate::usage::fs_space(&l.limits.jobs_dir).unwrap().total;
        let whole = admit::Ask {
            mem: None,
            disk: Some(admit::DiskAsk {
                want: total,
                jobs: &l.limits.jobs_dir,
                reclaim: None,
            }),
        };
        let blocker = admit::try_acquire(&l.limits.admit_dir, "blocker", &whole)
            .unwrap()
            .unwrap();
        let ask = Envelope {
            disk_bytes: 1 << 20,
            ..env(1, 1)
        };
        let now = Instant::now();
        let kept = l.offer(&id("a"), ask, 90, Gate::Open, now);
        assert!(matches!(
            kept.reply,
            OfferReply::Refused {
                reason: Refusal::Disk,
                ..
            }
        ));
        assert_eq!(
            kept.reclaim, None,
            "a node that keeps its caches asks nothing of them"
        );

        // An unused base, idle past the grace, in the build tier beside the job dirs.
        let state = dir.join("state");
        let base = state.join("build").join("old");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("runner.ext4"), vec![0x5a; 64 * 1024]).unwrap();
        crate::image::mark_used(&base);
        std::fs::File::open(base.join(".used"))
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(std::time::SystemTime::now() - Duration::from_secs(3600)),
            )
            .unwrap();
        l.limits.reclaim = Some(evicting(
            state,
            Duration::from_secs(4 * 3600),
            l.limits.jobs_dir.clone(),
        ));
        let short = l.offer(&id("a"), ask, 90, Gate::Open, now);
        assert!(matches!(short.reply, OfferReply::Refused { .. }));
        // At least the ask: the claim beside it already covers all there is free.
        let need = short.reclaim.expect("what eviction must free");
        assert!(need >= ask.disk_bytes, "{need}");
        // Beyond what the caches hold: nothing goes, and it says what could have.
        let beyond = l.limits.reclaim(need, &[]);
        assert_eq!(beyond.freed, 0);
        assert!(
            beyond.reach.is_some_and(|r| r > 0 && r < need),
            "{beyond:?}"
        );
        assert!(base.join("runner.ext4").exists());
        // Within it: the base goes, whatever its idle window, unless it is kept.
        assert_eq!(l.limits.reclaim(1, std::slice::from_ref(&base)).freed, 0);
        assert!(base.exists());
        assert!(crate::cachelock::reclaimed_eventually(|| {
            l.limits.reclaim(1, &[]).freed > 0
        }));
        assert!(!base.exists());
        drop(blocker);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A job taking a reservation over keeps its claim: it waits only for what it needs
    /// beyond it, and the room it needs no more goes back to the ledger.
    #[test]
    fn a_job_takes_its_reservation_over_in_the_ledger() {
        let (mut l, dir) = ledger("takeover", Some(8192));
        let now = Instant::now();
        assert!(matches!(
            l.offer(&id("a"), env(6144, 2), 90, Gate::Open, now).reply,
            OfferReply::Accepted { .. }
        ));
        let (_, held) = l.take(&id("a")).unwrap();
        let held = held.unwrap().rename(&l.limits.admit_dir, "4242").unwrap();
        // The job asks for less than it reserved: granted at once, in its place.
        let ask = admit::Ask {
            mem: Some(admit::MemAsk {
                want_mib: 2048,
                budget_mib: 8192,
            }),
            disk: None,
        };
        let own = admit::acquire(&l.limits.admit_dir, "4242", &ask, Duration::ZERO).unwrap();
        // What it gave back fits another.
        assert!(matches!(
            l.offer(&id("b"), env(6144, 2), 90, Gate::Open, now).reply,
            OfferReply::Accepted { .. }
        ));
        drop((own, held));
        let _ = std::fs::remove_dir_all(dir);
    }
}
