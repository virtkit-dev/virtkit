//! What the Rules tab and Observed traffic's list of projects read from the history
//! ([`super::rule_use`], [`super::rules::RecentScan`]), computed once for every page and stream
//! showing it: one pass over the latest [`super::rules::RECENT_SCAN`] jobs, a record decoded at
//! a time, and at most one computation runs at once, those asking meanwhile waiting for it.
//!
//! A computation stands for the rules' generation and the day it was made for;
//! past a change to the jobs' reports or the rows ([`Hub::egress_changed`]), for [`MIN_AGE`]
//! more, so however fast jobs end and however many pages follow, the history is read at most once
//! per [`MIN_AGE`]; and never past [`MAX_AGE`], as the recent jobs' window moves with the clock.
//! A page streamed may so show use [`MIN_AGE`] old until its next render.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;

use super::rule_use::{self, RuleUse};
use super::rules::{RECENT_SCAN, Recent, RecentScan, Rules};
use crate::server::Hub;

/// How long a computation stands past a change to the jobs' reports or the rows.
pub const MIN_AGE: Duration = Duration::from_secs(5);

/// How long a computation stands at most.
pub const MAX_AGE: Duration = Duration::from_secs(60);

/// What the Rules tab reads from the history.
#[derive(Debug)]
pub struct Aggregates {
    pub rule_use: RuleUse,
    pub recent: Recent,
}

/// What a computation was made for: a change to any of it makes another.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Key {
    rules: u64,
    today: u64,
}

impl Key {
    fn of(rules: &Rules, now: u64) -> Key {
        Key {
            rules: rules.generation,
            today: now / 86_400,
        }
    }
}

struct Held {
    key: Key,
    /// [`Hub::egress_generation`] before the history was read.
    generation: u64,
    at: Instant,
    value: Arc<Aggregates>,
}

impl Held {
    fn stands(&self, key: &Key, generation: u64, now: Instant) -> bool {
        let age = now.saturating_duration_since(self.at);
        self.key == *key && age < MAX_AGE && (self.generation == generation || age < MIN_AGE)
    }
}

/// The latest computation, shared by the Rules tab's pages and streams.
#[derive(Default)]
pub struct Cache {
    held: Mutex<Option<Held>>,
    /// Held by the computation under way.
    computing: Mutex<()>,
    /// How many computations were made.
    computed: AtomicU64,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A computation, replaced whole: nothing half-written for a panic to leave.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Cache {
    /// What the Rules tab reads for `rules` at `now` (seconds since the epoch): the latest
    /// computation while it stands, else a new one.
    pub fn get(&self, hub: &Hub, rules: &Rules, now: u64) -> Result<Arc<Aggregates>> {
        self.get_at(hub, rules, now, Instant::now())
    }

    fn get_at(&self, hub: &Hub, rules: &Rules, now: u64, at: Instant) -> Result<Arc<Aggregates>> {
        let key = Key::of(rules, now);
        let standing = |generation| {
            lock(&self.held)
                .as_ref()
                .filter(|h| h.stands(&key, generation, at))
                .map(|h| h.value.clone())
        };
        if let Some(v) = standing(hub.egress_generation()) {
            return Ok(v);
        }
        let _computing = lock(&self.computing);
        // Taken before the history is read, so a change made meanwhile computes it again.
        let generation = hub.egress_generation();
        // Made while this one waited.
        if let Some(v) = standing(generation) {
            return Ok(v);
        }
        let value = Arc::new(compute(hub, rules, now)?);
        self.computed.fetch_add(1, Ordering::Relaxed);
        *lock(&self.held) = Some(Held {
            key,
            generation,
            at,
            value: value.clone(),
        });
        Ok(value)
    }

    /// How many computations were made.
    #[cfg(test)]
    pub fn computed(&self) -> u64 {
        self.computed.load(Ordering::Relaxed)
    }
}

/// One computation: the rules' entries' use, and the recent jobs from one pass over the
/// history.
fn compute(hub: &Hub, rules: &Rules, now: u64) -> Result<Aggregates> {
    let today = now / 86_400;
    let mut recent = RecentScan::new(now);
    hub.db.visit_jobs(RECENT_SCAN, |_, j| recent.visit(j))?;
    Ok(Aggregates {
        rule_use: rule_use::rule_use(hub, &rules.rules, today)?,
        recent: recent.finish(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Db;

    /// Pages and streams asking within [`MIN_AGE`] of one another share one computation, a
    /// change to the jobs' reports past it makes another, as does a change to the rules at
    /// once, and nothing stands past [`MAX_AGE`].
    #[test]
    fn the_rules_tab_reads_the_history_once_for_every_page_showing_it() {
        let db = Arc::new(Db::open_memory().unwrap());
        let hub = Arc::new(Hub::new(db, None));
        let cache = Arc::new(Cache::default());
        let rules = super::super::rules::list(&hub).unwrap();
        let start = Instant::now();
        let get =
            |rules: &Rules, at: Duration| cache.get_at(&hub, rules, 1_000_000, start + at).unwrap();
        // Two streams and a page at once: one computation.
        std::thread::scope(|s| {
            for _ in 0..3 {
                s.spawn(|| get(&rules, Duration::ZERO));
            }
        });
        assert_eq!(cache.computed(), 1);
        // A job ended: the computation stands for MIN_AGE more.
        hub.egress_changed();
        get(&rules, Duration::from_secs(1));
        assert_eq!(cache.computed(), 1);
        get(&rules, MIN_AGE);
        assert_eq!(cache.computed(), 2);
        // No change: it stands until MAX_AGE.
        get(&rules, MAX_AGE - Duration::from_secs(1));
        assert_eq!(cache.computed(), 2);
        get(&rules, MAX_AGE + MIN_AGE);
        assert_eq!(cache.computed(), 3);
        // The rules changed: at once.
        let changed = Rules {
            generation: rules.generation + 1,
            ..rules.clone()
        };
        get(&changed, MAX_AGE + MIN_AGE);
        assert_eq!(cache.computed(), 4);
    }
}
