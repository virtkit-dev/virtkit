//! In-process leased build-once lock, the authority the `/lock/` HTTP API exposes.
//!
//! The single `vk-registry` process coordinates who builds a given content-key, so N
//! runners needing the same image build it once and the rest wait then pull. There is
//! no Redis and no cross-host flock: this one process holds the locks. Semantics mirror
//! the `task` fork's `redis.Locker` so it is a drop-in replacement for `cache.lock:
//! redis://` — name-keyed, a lease renewed by a client heartbeat, release-if-owner, a
//! long-poll on contention, and a served holder identity.
//!
//! A lease that lapses (the client stopped heartbeating — crashed, killed) frees the
//! lock, the same "holder dies ⇒ lock frees" guarantee the abstract-socket lock and the
//! Redis TTL give. Owner tokens are server-minted and opaque; only the holder that minted
//! one can renew or release.
//!
//! A manager serving a local store in-process is instead one of several on the host: each
//! process serving the store has its own. Those made by [`LockManager::host_shared`] act as
//! one authority by holding, for each name they lease, the store's [`hostlock`] of that
//! name.

use std::collections::{HashMap, HashSet};
use std::os::unix::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};

use vk_hub_proto::token::Claims;

use crate::{Body, body_of, hostlock};
use tokio::sync::Notify;

/// Default lease if the client sends no `?ttl=` (seconds).
const DEFAULT_TTL: u64 = 30;
/// Default contention wait if the client sends no `?wait=` (seconds).
const DEFAULT_WAIT: u64 = 3600;
/// Default failure-record ttl if the client sends no `?ttl=` on `/lock/fail` (seconds) —
/// generous, on the order of a slow pipeline's whole lifetime.
const DEFAULT_FAIL_TTL: u64 = 6 * 3600;
/// Longest a client may ask a failure record to live for — a memo blocks every build of
/// this key across the whole pipeline until it expires or the pipeline restarts, so an
/// unbounded `?ttl=` here has an outsized blast radius. Generous enough for any real
/// pipeline, not a cap meant to bind tightly.
const MAX_FAIL_TTL: u64 = 24 * 3600;
/// Longest lease `/lock/acquire` and `/lock/renew` grant, whatever `?ttl=` asks: a holder
/// heartbeats well inside it, so the cap never binds a real client. Unclamped, a huge ttl
/// parks a lock for decades, and one past what an `Instant` can hold panics while the lock
/// table's mutex is held — poisoning it, so every later lock request fails until restart.
const MAX_LEASE_TTL: Duration = Duration::from_secs(24 * 3600);
/// Longest `/lock/acquire` long-polls, whatever `?wait=` asks; past it the client gets the
/// blockers and asks again.
const MAX_WAIT: Duration = Duration::from_secs(24 * 3600);
/// Cap failure records by evicting the oldest, so fresh names and pipelines cannot grow
/// the table without bound within a ttl.
const MAX_FAIL_RECORDS: usize = 10_000;
/// `/lock/fail`'s reason body is free text for a log/error message, not a payload; cap it
/// well above anything reasonable so a client can't park an unbounded buffer server-side.
const MAX_FAIL_REASON: usize = 4096;

/// Most live locks one token principal (a token's `sub`, a job) may hold at once: far more than
/// a job's builds take together, and a bound on the table a job's token can grow, which every
/// acquisition scans. A request with no token is the registry's own credential's, unbounded.
pub const MAX_TOKEN_LOCKS: usize = 256;

/// Longest lease a host-shared manager grants. Nothing bounds who asks it, and a client that
/// dies keeps its names from every process sharing the store until its lease lapses.
pub const MAX_HOST_LEASE_TTL: Duration = Duration::from_secs(300);

/// Most live locks a host-shared manager holds at once: each one shared is a socket and a
/// thread of the process, and no token bounds what its clients take.
pub const MAX_HOST_LOCKS: usize = 256;

/// Longest an acquisition blocked by another process of the host sleeps before it tries
/// again: nothing tells it of a release there.
const HOST_POLL: Duration = Duration::from_millis(250);

/// What the holders of a `/lock/status` request's names in other processes are given,
/// together, to say who they are.
const STATUS_WAIT: Duration = Duration::from_secs(1);

/// What a holder in another process is called when it does not say.
const ANOTHER_PROCESS: &str = "another process";

/// Longest a single `acquire` call parks between contention re-checks — also the ceiling
/// on how late a lapsed lease is reclaimed if a release notification is missed.
const MAX_POLL: Duration = Duration::from_secs(5);

/// A currently-held lock.
struct Held {
    /// server-minted token; renew/release must present it
    owner: String,
    /// client-supplied identity, served verbatim on `POST /lock/status`
    holder: String,
    /// lease deadline; once passed the lock is free (the holder stopped heartbeating)
    expires: Instant,
    /// the token principal that took it, counted against [`MAX_TOKEN_LOCKS`]
    principal: Option<String>,
    /// The name's lock among the processes of the host, in host-shared mode. `None` there
    /// too when the name could not be shared: the lease then excludes this manager's
    /// clients only.
    _host: Option<hostlock::Held>,
}

/// The names of one local store's locks among the processes of the host: what a
/// host-shared [`LockManager`] holds for its leases, and what a process building into the
/// store without a server takes directly, so that the two exclude each other.
#[derive(Clone)]
pub struct HostLocks {
    /// The store's root, resolved.
    root: Vec<u8>,
}

impl HostLocks {
    /// The locks of the store at `root`, however its path is spelled. The root is created
    /// if it is not there yet: taken as spelled until it is, it would name other locks than
    /// the ones a later process resolves it to. An error when it can be neither made nor
    /// resolved.
    pub fn new(root: &Path) -> std::io::Result<Self> {
        use std::os::unix::ffi::OsStrExt;
        std::fs::create_dir_all(root)?;
        let root = std::fs::canonicalize(root)?;
        Ok(HostLocks {
            root: root.as_os_str().as_bytes().to_vec(),
        })
    }

    /// The [`hostlock`] address of lock `name`.
    pub fn addr(&self, name: &str) -> std::io::Result<SocketAddr> {
        let mut key = self.root.clone();
        key.push(0);
        key.extend_from_slice(name.as_bytes());
        hostlock::addr("virtkit-lock", &key)
    }
}

/// A manager's share in its store's host-wide locks.
struct Host {
    locks: HostLocks,
    reaper: Arc<Reaper>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// What wakes the thread that ends lapsed leases.
#[derive(Default)]
struct Reaper {
    state: Mutex<ReaperState>,
    wake: Condvar,
}

#[derive(Default)]
struct ReaperState {
    /// The manager is dropped.
    stop: bool,
    /// A lease was granted or renewed since the thread last looked at the table.
    changed: bool,
}

impl Drop for Host {
    fn drop(&mut self) {
        self.reaper
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stop = true;
        self.reaper.wake.notify_all();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Remove each lease of `held` as it lapses, waking the waiters on `freed`, until the
/// manager is dropped. Other processes wait on the leases' host locks, which only removing
/// a lease lets go: nothing else looks at the table when its clients are quiet.
fn reap(held: &Mutex<HashMap<String, Held>>, freed: &Notify, reaper: &Reaper) {
    loop {
        let next = {
            let mut map = held.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            let before = map.len();
            map.retain(|_, h| h.expires > now);
            if map.len() != before {
                freed.notify_waiters();
            }
            map.values().map(|h| h.expires).min()
        };
        let mut state = reaper.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if state.stop {
                return;
            }
            // A lease granted or renewed since may end before `next`.
            if std::mem::take(&mut state.changed) {
                break;
            }
            let left = next.map(|at| at.saturating_duration_since(Instant::now()));
            state = match left {
                Some(Duration::ZERO) => break,
                Some(left) => {
                    let (state, _) = reaper
                        .wake
                        .wait_timeout(state, left)
                        .unwrap_or_else(|e| e.into_inner());
                    state
                }
                None => reaper.wake.wait(state).unwrap_or_else(|e| e.into_inner()),
            };
        }
    }
}

/// A name in a batch acquire that a live lease already holds, with that holder's identity
/// — reported so a waiter can log who blocks it (like `ci-lock-mgr.sh`'s blocker list).
pub struct Blocker {
    pub name: String,
    pub holder: String,
}

/// Why an acquisition was not granted.
pub enum Refusal {
    /// Names a live lease holds, with their holders: the caller may wait for them. None
    /// when the names were free but `not_after` had passed.
    Held(Vec<Blocker>),
    /// The principal would hold more than [`MAX_TOKEN_LOCKS`] live locks: waiting does not help.
    TooMany,
    /// The table was handed to the release updating this registry ([`LockManager::hand_over`]):
    /// asking again reaches it.
    HandedOver,
    /// A host-shared manager would hold more than [`MAX_HOST_LOCKS`] live locks.
    Full,
}

/// Why [`LockManager::try_take_all`] took nothing.
enum Blocked {
    Refused(Refusal),
    /// No lease of this manager holds any of the names, but these are bound on the host,
    /// by another process or another manager of this one.
    Elsewhere(Vec<String>),
}

/// A recorded build failure for one content-key, scoped to the pipeline that hit it — see
/// [`LockManager::record_failure`].
struct FailRecord {
    /// Order of recording, for evicting the oldest past [`MAX_FAIL_RECORDS`].
    seq: u64,
    reason: String,
    recorded_at: Instant,
    ttl: Duration,
}

/// Failure memos keyed by name and pipeline so one pipeline's record never replaces
/// another's.
#[derive(Default)]
struct FailTable {
    records: HashMap<(String, String), FailRecord>,
    next_seq: u64,
}

/// A recent failure matching the querying pipeline, as reported to a caller.
pub struct FailInfo {
    pub reason: String,
    pub age: Duration,
}

/// The name→holder table plus a notifier that wakes waiters on release.
pub struct LockManager {
    held: Arc<Mutex<HashMap<String, Held>>>,
    /// notified on every release so parked `acquire` calls re-check promptly
    freed: Arc<Notify>,
    /// build-failure memos, independent of `held` — a domain-specific negative cache, not a
    /// mutual-exclusion primitive, so it never entangles with `task`'s reuse of `/lock/*` for
    /// its own (unrelated) locking. See [`LockManager::record_failure`].
    failed: Mutex<FailTable>,
    /// Set once the table is handed over, under both mutexes, and read under the one a change
    /// takes: from then on nothing here changes, and the release holds the locks.
    handed_over: AtomicBool,
    /// Set in host-shared mode ([`LockManager::host_shared`]).
    host: Option<Host>,
}

/// The lock table as one process hands it to the next ([`LockManager::hand_over`],
/// [`LockManager::restore`]): leases and failure records with what is left of them, as a
/// process's `Instant`s mean nothing to another. It holds the owner tokens, so it travels
/// only through a descriptor the release inherits, never a file.
///
/// No `Debug`, for the owner tokens.
#[derive(Default, Serialize, Deserialize)]
pub struct Snapshot {
    held: Vec<HeldEntry>,
    failed: Vec<FailEntry>,
}

#[derive(Serialize, Deserialize)]
struct HeldEntry {
    name: String,
    owner: String,
    holder: String,
    /// What is left of the lease.
    left_ms: u64,
    principal: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct FailEntry {
    name: String,
    pipeline: String,
    reason: String,
    age_ms: u64,
    ttl_ms: u64,
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

impl Default for LockManager {
    fn default() -> Self {
        Self::new()
    }
}

impl LockManager {
    /// How many locks are held now.
    pub fn held_count(&self) -> usize {
        self.held.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn new() -> Self {
        LockManager {
            held: Arc::new(Mutex::new(HashMap::new())),
            freed: Arc::new(Notify::new()),
            failed: Mutex::new(FailTable::default()),
            handed_over: AtomicBool::new(false),
            host: None,
        }
    }

    /// A manager for a server run in-process over the local store at `root`, sharing its
    /// locks with what else uses that store in this network namespace: the other managers
    /// made this way, and whatever takes the store's [`HostLocks`] directly. A name another
    /// of them holds is waited for like one held here, and named by `/lock/status`.
    ///
    /// The sharing is best-effort. A name bound by another user's process or by one that
    /// three queries in a row could not connect to, or that cannot be bound, is leased all
    /// the same and excludes this manager's own clients only. A holder that connects and
    /// names no one is waited for. A lease is let go for the other processes as soon as it
    /// lapses, lasts at most [`MAX_HOST_LEASE_TTL`], and at most [`MAX_HOST_LOCKS`] are
    /// live at once. Failure records stay this manager's, and [`LockManager::hand_over`]
    /// refuses the table. An error when `root` can be neither made nor resolved.
    pub fn host_shared(root: &Path) -> std::io::Result<Self> {
        let locks = HostLocks::new(root)?;
        let mut m = Self::new();
        let reaper = Arc::new(Reaper::default());
        let thread = {
            let (held, freed, reaper) = (m.held.clone(), m.freed.clone(), reaper.clone());
            std::thread::Builder::new()
                .name("vk-lock-reaper".into())
                .spawn(move || reap(&held, &freed, &reaper))?
        };
        m.host = Some(Host {
            locks,
            reaper,
            thread: Some(thread),
        });
        Ok(m)
    }

    /// The lease granted for an asked `ttl`: cut to [`MAX_LEASE_TTL`], or in host-shared
    /// mode to [`MAX_HOST_LEASE_TTL`].
    pub fn lease(&self, ttl: Duration) -> Duration {
        ttl.min(match self.host {
            Some(_) => MAX_HOST_LEASE_TTL,
            None => MAX_LEASE_TTL,
        })
    }

    /// End of a lease granted or renewed at `now`, with `ttl` capped by
    /// [`LockManager::lease`] and `not_after`.
    fn lease_end(&self, now: Instant, ttl: Duration, not_after: Option<Instant>) -> Instant {
        let end = now + self.lease(ttl);
        not_after.map_or(end, |n| end.min(n))
    }

    /// Whether the table was handed over: requests that would change it are for the release.
    pub fn is_handed_over(&self) -> bool {
        self.handed_over.load(Ordering::SeqCst)
    }

    /// Freeze and snapshot the table for the release taking over. Stop granting, renewing
    /// and releasing leases; answer waiting acquisitions as handed over so their clients
    /// retry against the release.
    ///
    /// An error, the table left as it is, in host-shared mode: a snapshot carries no host
    /// lock, so the leases restored from it would exclude no other process.
    pub fn hand_over(&self) -> Result<Snapshot> {
        if self.host.is_some() {
            anyhow::bail!("a lock table shared with the host cannot be handed over");
        }
        let now = Instant::now();
        let held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        let failed = self.failed.lock().unwrap_or_else(|e| e.into_inner());
        self.handed_over.store(true, Ordering::SeqCst);
        let snapshot = Snapshot {
            held: held
                .iter()
                .filter(|(_, h)| h.expires > now)
                .map(|(name, h)| HeldEntry {
                    name: name.clone(),
                    owner: h.owner.clone(),
                    holder: h.holder.clone(),
                    left_ms: millis(h.expires - now),
                    principal: h.principal.clone(),
                })
                .collect(),
            failed: failed
                .records
                .iter()
                .filter(|(_, r)| now.duration_since(r.recorded_at) < r.ttl)
                .map(|((name, pipeline), r)| FailEntry {
                    name: name.clone(),
                    pipeline: pipeline.clone(),
                    reason: r.reason.clone(),
                    age_ms: millis(now.duration_since(r.recorded_at)),
                    ttl_ms: millis(r.ttl),
                })
                .collect(),
        };
        drop((held, failed));
        self.freed.notify_waiters();
        Ok(snapshot)
    }

    /// Change the table again: the release it was handed to did not take over.
    pub fn take_back(&self) {
        self.handed_over.store(false, Ordering::SeqCst);
    }

    /// The table a previous process handed over `since` ago. Leases keep what was left of
    /// them then, less `since`, cut to [`MAX_LEASE_TTL`]; failure records their age, plus
    /// `since`, and their ttl, cut to [`MAX_FAIL_TTL`]; the youngest [`MAX_FAIL_RECORDS`] are
    /// kept. The snapshot comes from a previous process of this registry, which held the same
    /// caps, so the leases and reasons are not capped again.
    pub fn restore(snapshot: Snapshot, since: Duration) -> Self {
        let m = Self::new();
        let now = Instant::now();
        {
            let mut held = m.held.lock().unwrap_or_else(|e| e.into_inner());
            for h in snapshot.held {
                let left = Duration::from_millis(h.left_ms).saturating_sub(since);
                if left.is_zero() {
                    continue;
                }
                held.insert(
                    h.name,
                    Held {
                        owner: h.owner,
                        holder: h.holder,
                        expires: now + left.min(MAX_LEASE_TTL),
                        principal: h.principal,
                        _host: None,
                    },
                );
            }
        }
        let mut table = m.failed.lock().unwrap_or_else(|e| e.into_inner());
        let mut failed = snapshot.failed;
        // The youngest kept, then inserted oldest first, so the order of eviction survives.
        failed.sort_by_key(|f| f.age_ms);
        failed.truncate(MAX_FAIL_RECORDS);
        for f in failed.into_iter().rev() {
            let ttl = Duration::from_millis(f.ttl_ms).min(Duration::from_secs(MAX_FAIL_TTL));
            let age = Duration::from_millis(f.age_ms).saturating_add(since);
            let Some(recorded_at) = now.checked_sub(age).filter(|_| age < ttl) else {
                continue;
            };
            let seq = table.next_seq;
            table.next_seq += 1;
            table.records.insert(
                (f.name, f.pipeline),
                FailRecord {
                    seq,
                    reason: f.reason,
                    recorded_at,
                    ttl,
                },
            );
        }
        drop(table);
        m
    }

    /// Record that `name` (a build stage's content-key) just failed to build under
    /// `pipeline`'s watch, so a peer — another job in the same pipeline needing the same
    /// key, or this job's own runner-level retry — can fail fast instead of repeating a
    /// doomed, expensive build. Scoped to `pipeline`: a different pipeline id (a restart)
    /// always gets a fresh attempt, so there is no separate "clear" operation. Upserts (a
    /// later failure under the same pipeline replaces an earlier one; another pipeline's is
    /// left alone) and prunes every lapsed record while it's at it; past
    /// [`MAX_FAIL_RECORDS`] live ones, the oldest is evicted. Records nothing once the table is
    /// handed over.
    pub fn record_failure(&self, name: &str, pipeline: &str, reason: &str, ttl: Duration) {
        self.try_record_failure(name, pipeline, reason, ttl);
    }

    /// [`LockManager::record_failure`]: `false`, recording nothing, once the table is handed
    /// over.
    pub fn try_record_failure(
        &self,
        name: &str,
        pipeline: &str,
        reason: &str,
        ttl: Duration,
    ) -> bool {
        let mut table = self.failed.lock().unwrap();
        if self.is_handed_over() {
            return false;
        }
        let FailTable {
            records: map,
            next_seq,
        } = &mut *table;
        let now = Instant::now();
        map.retain(|_, r| now.duration_since(r.recorded_at) < r.ttl);
        let key = (name.to_string(), pipeline.to_string());
        if map.len() >= MAX_FAIL_RECORDS
            && !map.contains_key(&key)
            && let Some(oldest) = map
                .iter()
                .min_by_key(|(_, r)| r.seq)
                .map(|(k, _)| k.clone())
        {
            map.remove(&oldest);
        }
        let seq = *next_seq;
        *next_seq += 1;
        map.insert(
            key,
            FailRecord {
                seq,
                reason: reason.to_string(),
                recorded_at: now,
                ttl,
            },
        );
        true
    }

    /// A still-live failure record for `name` recorded under `pipeline`, `None` if there is
    /// none, it was recorded under a different pipeline, or its ttl has lapsed.
    pub fn recent_failure(&self, name: &str, pipeline: &str) -> Option<FailInfo> {
        let now = Instant::now();
        let key = (name.to_string(), pipeline.to_string());
        self.failed.lock().unwrap().records.get(&key).and_then(|r| {
            (now.duration_since(r.recorded_at) < r.ttl).then(|| FailInfo {
                reason: r.reason.clone(),
                age: now.duration_since(r.recorded_at),
            })
        })
    }

    /// The batch's owner token: the only proof renew and release ask for, so it must be
    /// unguessable — 128 random bits.
    fn mint_owner() -> String {
        crate::accounts::random_token(16)
    }

    /// Atomically take ALL `names`, each given once, for `ttl`, ending no later than
    /// `not_after`, or none (reaping lapsed leases first). Returns the shared batch owner
    /// token, or the live blockers if any name is held, or [`Refusal::TooMany`] if
    /// `principal` would then hold more than [`MAX_TOKEN_LOCKS`]. All-or-nothing under one
    /// lock, so acquiring a set never deadlocks against another batch regardless of order.
    /// Nothing is taken once `not_after` has passed: the refusal then has no blocker.
    ///
    /// In host-shared mode the names are then taken on the host too.
    /// [`Blocked::Elsewhere`] names the ones bound there, and nothing is taken, unless they
    /// are all in `unshared`: those are leased without their host lock, as is a name that
    /// fails to bind. The table holds at most [`MAX_HOST_LOCKS`] there.
    fn try_take_all(
        &self,
        names: &[String],
        ttl: Duration,
        holder: &str,
        not_after: Option<Instant>,
        principal: Option<&str>,
        unshared: &HashSet<String>,
    ) -> Result<String, Blocked> {
        let mut map = self.held.lock().unwrap();
        if self.is_handed_over() {
            return Err(Blocked::Refused(Refusal::HandedOver));
        }
        let now = Instant::now();
        // drop every lapsed lease so the table can't grow without bound from names whose
        // holder died and never reacquired (release is otherwise the only path that prunes).
        map.retain(|_, h| h.expires > now);
        // Each of `names` adds a lock once granted, and the principal's others stay: a batch past
        // the bound is refused at once, waiting for its blockers would not make it fit.
        if let Some(p) = principal {
            let others = map
                .iter()
                .filter(|(n, h)| h.principal.as_deref() == Some(p) && !names.contains(n))
                .count();
            if others.saturating_add(names.len()) > MAX_TOKEN_LOCKS {
                return Err(Blocked::Refused(Refusal::TooMany));
            }
        }
        if self.host.is_some() {
            let others = map.keys().filter(|n| !names.contains(n)).count();
            if others.saturating_add(names.len()) > MAX_HOST_LOCKS {
                return Err(Blocked::Refused(Refusal::Full));
            }
        }
        let blockers: Vec<Blocker> = names
            .iter()
            .filter_map(|n| {
                map.get(n).filter(|h| h.expires > now).map(|h| Blocker {
                    name: n.clone(),
                    holder: h.holder.clone(),
                })
            })
            .collect();
        if !blockers.is_empty() {
            return Err(Blocked::Refused(Refusal::Held(blockers)));
        }
        // Bound under the table's mutex, where no lease of this manager holds any of the
        // names: a lease let go has let its host lock go by the time the mutex is free.
        let mut shared: Vec<Option<hostlock::Held>> = Vec::with_capacity(names.len());
        if let Some(host) = &self.host {
            let mut elsewhere = Vec::new();
            for n in names {
                let bound = host
                    .locks
                    .addr(n)
                    .and_then(|addr| hostlock::try_acquire(&addr, holder));
                match bound {
                    // Also a name of `unshared`: what kept it bound has gone.
                    Ok(Some(lock)) => shared.push(Some(lock)),
                    Ok(None) if unshared.contains(n) => shared.push(None),
                    Ok(None) => elsewhere.push(n.clone()),
                    // Not to be bound at all, out of descriptors or threads say: the lease
                    // goes unshared rather than refused.
                    Err(_) => shared.push(None),
                }
            }
            if !elsewhere.is_empty() {
                // `shared` drops: what was bound of the batch is let go.
                return Err(Blocked::Elsewhere(elsewhere));
            }
        } else {
            shared.resize_with(names.len(), || None);
        }
        // The leases start now: binding the names took time, which a short one may not have.
        let now = Instant::now();
        if not_after.is_some_and(|end| end <= now) {
            return Err(Blocked::Refused(Refusal::Held(Vec::new())));
        }
        let owner = Self::mint_owner();
        for (n, host) in names.iter().zip(shared) {
            map.insert(
                n.clone(),
                Held {
                    owner: owner.clone(),
                    holder: holder.to_string(),
                    expires: self.lease_end(now, ttl, not_after),
                    principal: principal.map(str::to_string),
                    _host: host,
                },
            );
        }
        drop(map);
        self.wake_reaper();
        Ok(owner)
    }

    /// Have the reaper look at the table again: a lease may now end before the one it
    /// sleeps until.
    fn wake_reaper(&self) {
        if let Some(host) = &self.host {
            host.reaper
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .changed = true;
            host.reaper.wake.notify_all();
        }
    }

    /// Ask the holders of `names`, which are bound on the host, who they are: `Ok(None)`
    /// for one that could not be connected to, an error for a query that failed on this
    /// side. Off the runtime: each holder has a second to answer, and all of them until
    /// `deadline` ([`hostlock::answer_by`]), past which they go unnamed.
    async fn ask_holders(
        &self,
        names: Vec<String>,
        deadline: Instant,
    ) -> Vec<(String, std::io::Result<Option<hostlock::Holder>>)> {
        let Some(host) = &self.host else {
            return Vec::new();
        };
        let locks = host.locks.clone();
        let asked = names.clone();
        let ask = move || {
            let by = hostlock::answer_by(deadline);
            asked
                .into_iter()
                .map(|n| {
                    let holder = locks
                        .addr(&n)
                        .and_then(|addr| hostlock::query_holder_by(&addr, by));
                    (n, holder)
                })
                .collect()
        };
        match tokio::task::spawn_blocking(ask).await {
            Ok(answers) => answers,
            Err(e) => names
                .into_iter()
                .map(|n| (n, Err(std::io::Error::other(e.to_string()))))
                .collect(),
        }
    }

    /// Acquire ALL `names` atomically, long-polling until the whole set is free or
    /// `deadline`. On timeout nothing is taken and the current blockers are returned. The
    /// lease runs `ttl` from the grant, cut at `not_after`. The batch shares one owner
    /// token; renew/release act on the set. Wakes on a release, and at worst every
    /// [`MAX_POLL`] so a lapsed lease is reclaimed even if its release notification was
    /// missed. A `principal` past [`MAX_TOKEN_LOCKS`] is refused at once.
    ///
    /// A name given twice is taken once, and nothing is granted once `not_after` has
    /// passed.
    ///
    /// In host-shared mode a name bound on the host blocks the batch too, and is tried
    /// again after at most [`HOST_POLL`]. One bound by another user's process, or that
    /// three queries in a row could not connect to, is not waited for: the batch is granted
    /// without sharing it, if that still holds of the name once the others are free. Naming
    /// the holders can take the call up to 250 ms past `deadline`
    /// ([`hostlock::answer_by`]).
    pub async fn acquire_all(
        &self,
        names: &[String],
        ttl: Duration,
        holder: &str,
        deadline: Instant,
        not_after: Option<Instant>,
        principal: Option<&str>,
    ) -> Result<String, Refusal> {
        // A name bound twice on the host would block its own batch.
        let mut seen = HashSet::new();
        let names: Vec<String> = names
            .iter()
            .filter(|n| seen.insert(n.as_str()))
            .cloned()
            .collect();
        let names = names.as_slice();
        let deadline = not_after.map_or(deadline, |end| deadline.min(end));
        // Names the last queries found not worth waiting for. Good for the next try only:
        // after a sleep another process may hold them.
        let mut unshared = HashSet::new();
        // Queries in a row that could not connect to each name still bound on the host.
        let mut silent: HashMap<String, u32> = HashMap::new();
        loop {
            match self.try_take_all(names, ttl, holder, not_after, principal, &unshared) {
                Ok(owner) => return Ok(owner),
                Err(Blocked::Refused(Refusal::Held(blockers))) => {
                    unshared.clear();
                    silent.clear();
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(Refusal::Held(blockers));
                    }
                    // wake at the soonest blocker's lease expiry (clamped), so a lapsed
                    // lease is reclaimed even without a release notification.
                    let soonest = {
                        let map = self.held.lock().unwrap();
                        names
                            .iter()
                            .filter_map(|n| map.get(n).map(|h| h.expires))
                            .min()
                    };
                    let wake = soonest.unwrap_or(deadline).min(deadline);
                    let sleep = wake
                        .saturating_duration_since(now)
                        .min(MAX_POLL)
                        .max(Duration::from_millis(20));
                    let freed = self.freed.notified();
                    // Handed over since the try: the release has the table.
                    if self.is_handed_over() {
                        continue;
                    }
                    tokio::select! {
                        _ = freed => {}
                        _ = tokio::time::sleep(sleep) => {}
                    }
                }
                // Too many are refused at once. So is a waiter of a table handed over:
                // answered "held", a client would stop waiting and build without the lock;
                // asked again, the release grants or holds it.
                Err(Blocked::Refused(refusal)) => return Err(refusal),
                Err(Blocked::Elsewhere(elsewhere)) => {
                    silent.retain(|n, _| elsewhere.contains(n) || unshared.contains(n));
                    unshared.clear();
                    // SAFETY: geteuid(2) has no preconditions and cannot fail.
                    let me = unsafe { libc::geteuid() };
                    let mut blockers = Vec::new();
                    for (name, asked) in self.ask_holders(elsewhere, deadline).await {
                        match weigh(&asked, me, silent.entry(name.clone()).or_default()) {
                            // A name that could not be connected to yet may only just have
                            // been let go.
                            hostlock::Verdict::Wait => blockers.push(Blocker {
                                holder: asked
                                    .ok()
                                    .flatten()
                                    .and_then(|h| h.who)
                                    .unwrap_or_else(|| ANOTHER_PROCESS.to_string()),
                                name,
                            }),
                            hostlock::Verdict::Foreign(_) | hostlock::Verdict::Unanswering => {
                                unshared.insert(name);
                            }
                        }
                    }
                    if blockers.is_empty() {
                        // At once, while what was just learnt of the names holds.
                        continue;
                    }
                    unshared.clear();
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(Refusal::Held(blockers));
                    }
                    tokio::time::sleep(left.min(HOST_POLL)).await;
                }
            }
        }
    }

    /// Renew every name in the batch still held by `owner`, for `ttl` cut at `not_after`;
    /// returns the count renewed (a heartbeat treats fewer than the batch size as "lost the
    /// batch"); 0 once the table is handed over.
    pub fn renew_all(
        &self,
        names: &[String],
        owner: &str,
        ttl: Duration,
        not_after: Option<Instant>,
    ) -> usize {
        self.try_renew_all(names, owner, ttl, not_after)
            .unwrap_or(0)
    }

    /// [`LockManager::renew_all`]: `None`, renewing nothing, once the table is handed over.
    pub fn try_renew_all(
        &self,
        names: &[String],
        owner: &str,
        ttl: Duration,
        not_after: Option<Instant>,
    ) -> Option<usize> {
        let mut map = self.held.lock().unwrap();
        if self.is_handed_over() {
            return None;
        }
        let now = Instant::now();
        let mut n = 0;
        for name in names {
            if let Some(h) = map.get_mut(name)
                && crate::auth::constant_eq(h.owner.as_bytes(), owner.as_bytes())
                && h.expires > now
            {
                h.expires = self.lease_end(now, ttl, not_after);
                n += 1;
            }
        }
        drop(map);
        if n > 0 {
            // A renewal may end a lease sooner than it did.
            self.wake_reaper();
        }
        Some(n)
    }

    /// Release every name in the batch held by `owner`, waking waiters; returns the count, 0
    /// once the table is handed over.
    pub fn release_all(&self, names: &[String], owner: &str) -> usize {
        self.try_release_all(names, owner).unwrap_or(0)
    }

    /// [`LockManager::release_all`]: `None`, releasing nothing, once the table is handed over.
    pub fn try_release_all(&self, names: &[String], owner: &str) -> Option<usize> {
        let mut map = self.held.lock().unwrap();
        if self.is_handed_over() {
            return None;
        }
        let mut n = 0;
        for name in names {
            if map
                .get(name)
                .is_some_and(|h| crate::auth::constant_eq(h.owner.as_bytes(), owner.as_bytes()))
            {
                map.remove(name);
                n += 1;
            }
        }
        if n > 0 {
            drop(map);
            self.freed.notify_waiters();
        }
        Some(n)
    }

    // ---- single-lock convenience: a batch of one ----

    /// Acquire `name`, long-polling until free or `deadline`; `None` on timeout.
    pub async fn acquire(
        &self,
        name: &str,
        ttl: Duration,
        holder: &str,
        deadline: Instant,
    ) -> Option<String> {
        let names = [name.to_string()];
        self.acquire_all(&names, ttl, holder, deadline, None, None)
            .await
            .ok()
    }

    /// Extend the lease if `owner` still holds a live lease on `name`.
    pub fn renew(&self, name: &str, owner: &str, ttl: Duration) -> bool {
        self.renew_all(&[name.to_string()], owner, ttl, None) == 1
    }

    /// Release `name` if `owner` holds it. `false` if `owner` is not the current holder.
    pub fn release(&self, name: &str, owner: &str) -> bool {
        self.release_all(&[name.to_string()], owner) == 1
    }

    /// The live holder's identity, `None` if free (or the lease has lapsed).
    pub fn holder(&self, name: &str) -> Option<String> {
        let now = Instant::now();
        self.held
            .lock()
            .unwrap()
            .get(name)
            .filter(|h| h.expires > now)
            .map(|h| h.holder.clone())
    }

    /// [`LockManager::holders_on_host`] for one name.
    pub async fn holder_on_host(&self, name: &str) -> Option<String> {
        let held = self.holders_on_host(&[name.to_string()]).await;
        held.into_iter().next().map(|(_, holder)| holder)
    }

    /// Those of `names` that are held, each with [`LockManager::holder`], or in host-shared
    /// mode with what the process that keeps the name bound says it is. Those processes
    /// have [`STATUS_WAIT`] together to say so. A name bound by another user's process, or
    /// that could not be connected to or asked after, has no holder.
    pub async fn holders_on_host(&self, names: &[String]) -> Vec<(String, String)> {
        let mut held: Vec<(String, Option<String>)> =
            names.iter().map(|n| (n.clone(), self.holder(n))).collect();
        let free: Vec<String> = held
            .iter()
            .filter(|(_, holder)| holder.is_none())
            .map(|(n, _)| n.clone())
            .collect();
        if self.host.is_some() && !free.is_empty() {
            // SAFETY: geteuid(2) has no preconditions and cannot fail.
            let me = unsafe { libc::geteuid() };
            let asked: HashMap<String, String> = self
                .ask_holders(free, Instant::now() + STATUS_WAIT)
                .await
                .into_iter()
                .filter_map(|(n, asked)| {
                    let asked = asked.ok()??;
                    (hostlock::judge(Some(&asked), me, 0) == hostlock::Verdict::Wait)
                        .then(|| (n, asked.who.unwrap_or_else(|| ANOTHER_PROCESS.to_string())))
                })
                .collect();
            for (n, holder) in &mut held {
                if holder.is_none() {
                    *holder = asked.get(n).cloned();
                }
            }
        }
        held.into_iter()
            .filter_map(|(n, holder)| Some((n, holder?)))
            .collect()
    }
}

/// What an acquisition makes of the answer of a name bound on the host, counting in
/// `silent` the queries in a row that could not connect to it. A query that failed on this
/// side says nothing of the holder: the name is waited for and the count kept.
fn weigh(
    asked: &std::io::Result<Option<hostlock::Holder>>,
    me: u32,
    silent: &mut u32,
) -> hostlock::Verdict {
    let Ok(asked) = asked else {
        return hostlock::Verdict::Wait;
    };
    *silent = if asked.is_some() { 0 } else { *silent + 1 };
    hostlock::judge(asked.as_ref(), me, *silent)
}

/// Dispatch a `/lock/<action>` request. Every action is **POST**; names are repeated
/// `?name=` params (one name = single-lock, several = an atomic all-or-nothing batch —
/// the `ci-lock-mgr.sh` model, for a step that builds several images together). Acquire
/// returns an opaque owner token; renew/release present it back in `X-Vk-Lock-Owner`.
///
/// - `POST /lock/acquire?name=…&ttl=&wait=` (`X-Vk-Lock-Holder`) → 200 `{owner, names, ttl}`
///   | 409 `{blockers:[{name, holder}]}`
/// - `POST /lock/renew?name=…&ttl=`         (`X-Vk-Lock-Owner`)  → `{renewed, of, ttl}`
/// - `POST /lock/release?name=…`            (`X-Vk-Lock-Owner`)  → `{released}`
/// - `POST /lock/status?name=…`                                  → `{holders:[{name, holder}]}`
///
/// A second, independent pair — a build-failure memo, not a mutual-exclusion primitive, so
/// it never entangles with `task`'s reuse of the four locking endpoints above:
///
/// - `POST /lock/fail?name=…&ttl=` (`X-Vk-Lock-Pipeline`, body = reason text) → `{recorded:true}`
/// - `POST /lock/fail-status?name=…` (`X-Vk-Lock-Pipeline`) → `{failed:false}` |
///   `{failed:true, reason, age_secs}`
///
/// A request with a hub token (`token`) may name only locks its grants cover, acts as the
/// token's own pipeline, starts nothing that outlives the token, and holds at most
/// [`MAX_TOKEN_LOCKS`] locks at once with the other tokens of its `sub`: past that, acquire
/// answers 429. The caller refuses a
/// token past its `exp`, which [`Claims::live_at`]'s skew still lets through.
pub async fn route(
    mgr: &LockManager,
    req: Request<Incoming>,
    token: Option<&Claims>,
) -> Result<Response<Body>> {
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let owner = header(&req, "x-vk-lock-owner");
    let holder = header(&req, "x-vk-lock-holder").unwrap_or_default();
    let mut pipeline = header(&req, "x-vk-lock-pipeline");

    if req.method() != Method::POST {
        return Ok(json(
            StatusCode::METHOD_NOT_ALLOWED,
            r#"{"error":"use POST"}"#,
        ));
    }
    let names = names_param(&query);
    if names.is_empty() {
        return Ok(json(
            StatusCode::BAD_REQUEST,
            r#"{"error":"no lock names (use ?name=…)"}"#,
        ));
    }
    let mut limit = Limit::default();
    if let Some(claims) = token {
        if let Some(name) = names.iter().find(|n| !claims.allows_lock(n)) {
            let body = serde_json::json!({
                "error": "lock name outside the token's grants", "name": name,
            });
            return Ok(json(StatusCode::FORBIDDEN, &body.to_string()));
        }
        match (&pipeline, &claims.pipeline) {
            (Some(asked), Some(own)) if asked != own => {
                return Ok(json(
                    StatusCode::FORBIDDEN,
                    r#"{"error":"X-Vk-Lock-Pipeline is not the token's pipeline"}"#,
                ));
            }
            (_, Some(own)) => pipeline = Some(own.clone()),
            (_, None) if path.starts_with("/lock/fail") => {
                return Ok(json(
                    StatusCode::FORBIDDEN,
                    r#"{"error":"the token names no pipeline"}"#,
                ));
            }
            (_, None) => {}
        }
        let remaining = claims.exp.saturating_sub(vk_peer::now_secs());
        limit = Limit(Some(Instant::now() + Duration::from_secs(remaining)));
    }

    match path.as_str() {
        // acquire the whole set atomically (all-or-nothing), long-polling until free.
        "/lock/acquire" => {
            let ttl = Duration::from_secs(qparam(&query, "ttl").unwrap_or(DEFAULT_TTL));
            // A grant happens only before the deadline, and its lease ends by the token's
            // expiry however long it waited: a lock is never held on an expired token.
            let deadline = limit.deadline(acquire_deadline(&query));
            let principal = token.map(|c| c.sub.as_str());
            match mgr
                .acquire_all(&names, ttl, &holder, deadline, limit.0, principal)
                .await
            {
                Ok(owner) => {
                    let body = serde_json::json!({
                        "owner": owner, "names": names, "ttl": limit.cut(mgr.lease(ttl)).as_secs(),
                    });
                    Ok(json(StatusCode::OK, &body.to_string()))
                }
                Err(Refusal::TooMany) => {
                    let body = serde_json::json!({
                        "error": format!(
                            "the token's principal would hold more than {MAX_TOKEN_LOCKS} locks"
                        ),
                        "limit": MAX_TOKEN_LOCKS,
                    });
                    Ok(json(StatusCode::TOO_MANY_REQUESTS, &body.to_string()))
                }
                Err(Refusal::Full) => {
                    let body = serde_json::json!({
                        "error": format!("more than {MAX_HOST_LOCKS} locks would be held"),
                        "limit": MAX_HOST_LOCKS,
                    });
                    Ok(json(StatusCode::TOO_MANY_REQUESTS, &body.to_string()))
                }
                Err(Refusal::HandedOver) => Ok(handed_over()),
                Err(Refusal::Held(blockers)) => {
                    let blockers: Vec<_> = blockers
                        .iter()
                        .map(|b| serde_json::json!({"name": b.name, "holder": b.holder}))
                        .collect();
                    let body = serde_json::json!({"error": "locks held", "blockers": blockers});
                    Ok(json(StatusCode::CONFLICT, &body.to_string()))
                }
            }
        }
        // renew every name still owned; fewer than the whole set ⇒ the batch was partly lost.
        "/lock/renew" => {
            let ttl = Duration::from_secs(qparam(&query, "ttl").unwrap_or(DEFAULT_TTL));
            let Some(owner) = owner else {
                return Ok(json(
                    StatusCode::BAD_REQUEST,
                    r#"{"error":"missing owner"}"#,
                ));
            };
            let Some(n) = mgr.try_renew_all(&names, &owner, ttl, limit.0) else {
                return Ok(handed_over());
            };
            let body = serde_json::json!({
                "renewed": n, "of": names.len(), "ttl": limit.cut(mgr.lease(ttl)).as_secs(),
            });
            let status = if n == names.len() {
                StatusCode::OK
            } else {
                StatusCode::CONFLICT
            };
            Ok(json(status, &body.to_string()))
        }
        "/lock/release" => {
            let Some(owner) = owner else {
                return Ok(json(
                    StatusCode::BAD_REQUEST,
                    r#"{"error":"missing owner"}"#,
                ));
            };
            let Some(n) = mgr.try_release_all(&names, &owner) else {
                return Ok(handed_over());
            };
            Ok(json(
                StatusCode::OK,
                &serde_json::json!({"released": n}).to_string(),
            ))
        }
        // holder identity for each requested name that is currently held.
        "/lock/status" => {
            let holders: Vec<_> = mgr
                .holders_on_host(&names)
                .await
                .into_iter()
                .map(|(n, h)| serde_json::json!({"name": n, "holder": h}))
                .collect();
            Ok(json(
                StatusCode::OK,
                &serde_json::json!({"holders": holders}).to_string(),
            ))
        }
        // record that `names` (usually one key) just failed to build under `pipeline`'s
        // watch, so a peer sees it via `/lock/fail-status` and fails fast instead of
        // repeating the same doomed build.
        "/lock/fail" => {
            let Some(pipeline) = pipeline.filter(|p| !p.is_empty()) else {
                return Ok(json(
                    StatusCode::BAD_REQUEST,
                    r#"{"error":"missing X-Vk-Lock-Pipeline"}"#,
                ));
            };
            let reason = match read_body_capped(req.into_body(), MAX_FAIL_REASON).await {
                Ok(b) => String::from_utf8_lossy(&b).into_owned(),
                Err(e) => {
                    return Ok(json(
                        StatusCode::BAD_REQUEST,
                        &format!(r#"{{"error":"{e}"}}"#),
                    ));
                }
            };
            // Cut once the body is in, so a slow one cannot stretch it past the token.
            let ttl = limit.cut(fail_ttl(&query));
            for name in &names {
                if !mgr.try_record_failure(name, &pipeline, &reason, ttl) {
                    return Ok(handed_over());
                }
            }
            Ok(json(StatusCode::OK, r#"{"recorded":true}"#))
        }
        // a still-live failure record for `names[0]` under `pipeline`? Single-name only —
        // a batch has no natural all-or-nothing meaning for a query, so only the first
        // requested name is checked.
        "/lock/fail-status" => {
            let Some(pipeline) = pipeline.filter(|p| !p.is_empty()) else {
                return Ok(json(
                    StatusCode::BAD_REQUEST,
                    r#"{"error":"missing X-Vk-Lock-Pipeline"}"#,
                ));
            };
            match mgr.recent_failure(&names[0], &pipeline) {
                Some(f) => {
                    let body = serde_json::json!({
                        "failed": true, "reason": f.reason, "age_secs": f.age.as_secs(),
                    });
                    Ok(json(StatusCode::OK, &body.to_string()))
                }
                None => Ok(json(StatusCode::OK, r#"{"failed":false}"#)),
            }
        }
        _ => Ok(json(
            StatusCode::NOT_FOUND,
            r#"{"error":"unknown lock action"}"#,
        )),
    }
}

/// Read a body, capped at `cap` bytes (`/lock/fail`'s reason is a short log message, not a
/// payload — reject anything abusively large instead of buffering it). Reads frame-by-frame
/// and bails the moment the running total crosses `cap`, so an oversized body is never
/// fully buffered server-side first, unlike a `collect()`-then-check. Generic over the body
/// type (rather than `Request<Incoming>` directly) so a test can exercise it against a
/// synthetic streaming body without a real connection.
async fn read_body_capped<B>(mut body: B, cap: usize) -> Result<Bytes, &'static str>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
{
    if body.size_hint().lower() > cap as u64 {
        return Err("reason body too large");
    }
    let mut buf = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| "reading request body")?;
        let Some(data) = frame.data_ref() else {
            continue; // a trailers frame — no data to accumulate
        };
        if buf.len() + data.len() > cap {
            return Err("reason body too large");
        }
        buf.extend_from_slice(data);
    }
    Ok(Bytes::from(buf))
}

/// Collect the repeated `?name=` query params (percent-decoded), de-duplicated while
/// preserving order.
fn names_param(query: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (k, v) in query.split('&').filter_map(|p| p.split_once('=')) {
        if k == "name" {
            // Lock names may carry `:` and `/`, percent-encoded.
            let val = crate::percent_decode(v);
            if seen.insert(val.clone()) {
                out.push(val);
            }
        }
    }
    out
}

/// The request's expiry bound: the token's expiry, or none.
#[derive(Clone, Copy, Default)]
struct Limit(Option<Instant>);

impl Limit {
    /// `d` from now, cut at the limit.
    fn cut(self, d: Duration) -> Duration {
        self.0.map_or(d, |end| {
            d.min(end.saturating_duration_since(Instant::now()))
        })
    }

    fn deadline(self, deadline: Instant) -> Instant {
        self.0.map_or(deadline, |end| deadline.min(end))
    }
}

fn header(req: &Request<Incoming>, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Parse a `u64` query parameter (`?key=<n>`), `None` if absent or unparseable.
fn qparam(query: &str, key: &str) -> Option<u64> {
    query
        .split('&')
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| *k == key)
        .and_then(|(_, v)| v.parse().ok())
}

/// `/lock/acquire`'s long-poll deadline: now plus the client's `?wait=` (or
/// [`DEFAULT_WAIT`]), clamped to [`MAX_WAIT`] so a huge wait can't overflow the `Instant`.
fn acquire_deadline(query: &str) -> Instant {
    let wait = Duration::from_secs(qparam(query, "wait").unwrap_or(DEFAULT_WAIT));
    Instant::now() + wait.min(MAX_WAIT)
}

/// `/lock/fail`'s effective ttl: the client's `?ttl=` (or [`DEFAULT_FAIL_TTL`]), clamped to
/// [`MAX_FAIL_TTL`] — see that constant's doc for why.
fn fail_ttl(query: &str) -> Duration {
    Duration::from_secs(
        qparam(query, "ttl")
            .unwrap_or(DEFAULT_FAIL_TTL)
            .min(MAX_FAIL_TTL),
    )
}

/// The answer to a change asked of a table handed over: the release serves the next
/// connection, and `Connection: close` has the client make one.
fn handed_over() -> Response<Body> {
    crate::ask_again(json(
        StatusCode::SERVICE_UNAVAILABLE,
        r#"{"error":"this registry is updating; retry"}"#,
    ))
}

fn json(status: StatusCode, body: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body_of(Bytes::from(body.to_string())))
        .expect("building a lock response")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_plus(d: Duration) -> Instant {
        Instant::now() + d
    }

    /// Owner tokens are 32 hex digits (128 bits) and differ from one batch to the next.
    #[test]
    fn owner_tokens_are_128_random_bits() {
        let (a, b) = (LockManager::mint_owner(), LockManager::mint_owner());
        assert_ne!(a, b);
        assert_eq!(a.len(), 32, "128 bits, hex: {a}");
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()), "{a}");
    }

    /// A ttl past what an `Instant` can hold is clamped, not added: the addition would panic
    /// with the lock table's mutex held and poison it for every later request.
    #[tokio::test]
    async fn an_outsized_ttl_is_clamped_rather_than_poisoning_the_table() {
        let m = LockManager::new();
        let names = ["k".to_string()];
        let huge = Duration::from_secs(u64::MAX);
        let Ok(owner) = m
            .acquire_all(&names, huge, "a", now_plus(Duration::ZERO), None, None)
            .await
        else {
            panic!("a free name must be granted");
        };
        assert_eq!(m.renew_all(&names, &owner, huge, None), 1);
        assert_eq!(m.release_all(&names, &owner), 1);
        let again = m
            .acquire_all(
                &names,
                Duration::from_secs(30),
                "b",
                now_plus(Duration::ZERO),
                None,
                None,
            )
            .await;
        assert!(again.is_ok());
    }

    /// The client chooses these bytes: a `%` before a multi-byte character decodes literally
    /// instead of panicking the connection's task.
    #[test]
    fn names_decode_without_panicking_on_a_split_character() {
        assert_eq!(
            names_param("name=a%2Fb&name=%€&name=%a€&name=a%2Fb"),
            ["a/b", "%€", "%a€"]
        );
    }

    #[tokio::test]
    async fn acquire_excludes_then_release_admits() {
        let m = LockManager::new();
        let a = m
            .acquire(
                "k",
                Duration::from_secs(30),
                "runner-a",
                now_plus(Duration::from_secs(1)),
            )
            .await
            .expect("first acquire wins");
        // second acquirer must not get it while a live lease holds it.
        assert!(
            m.acquire(
                "k",
                Duration::from_secs(30),
                "runner-b",
                now_plus(Duration::from_millis(150))
            )
            .await
            .is_none(),
            "a held lock must block a second acquirer"
        );
        assert_eq!(m.holder("k").as_deref(), Some("runner-a"));
        assert!(m.release("k", &a), "owner releases");
        // now it is free.
        assert!(
            m.acquire(
                "k",
                Duration::from_secs(30),
                "runner-b",
                now_plus(Duration::from_secs(1))
            )
            .await
            .is_some(),
            "released lock must admit the next acquirer"
        );
    }

    #[tokio::test]
    async fn lapsed_lease_frees_the_lock() {
        let m = LockManager::new();
        let _a = m
            .acquire(
                "k",
                Duration::from_millis(60),
                "dead",
                now_plus(Duration::from_secs(1)),
            )
            .await
            .unwrap();
        // a waiter should get it once the short lease lapses without a heartbeat.
        let got = m
            .acquire(
                "k",
                Duration::from_secs(30),
                "b",
                now_plus(Duration::from_secs(2)),
            )
            .await;
        assert!(
            got.is_some(),
            "a lapsed lease must free the lock for a waiter"
        );
        assert_eq!(m.holder("k").as_deref(), Some("b"));
    }

    #[tokio::test]
    async fn renew_keeps_the_lease_alive() {
        let m = LockManager::new();
        let a = m
            .acquire(
                "k",
                Duration::from_millis(80),
                "a",
                now_plus(Duration::from_secs(1)),
            )
            .await
            .unwrap();
        // renew before expiry, then a would-be waiter with a short deadline must fail:
        // the lease is still live.
        assert!(m.renew("k", &a, Duration::from_secs(30)));
        assert!(
            m.acquire(
                "k",
                Duration::from_secs(30),
                "b",
                now_plus(Duration::from_millis(200))
            )
            .await
            .is_none(),
            "a renewed lease must keep blocking"
        );
        // a non-owner cannot renew or release.
        assert!(!m.renew("k", "not-owner", Duration::from_secs(30)));
        assert!(!m.release("k", "not-owner"));
        assert!(m.release("k", &a));
    }

    #[tokio::test]
    async fn contended_waiter_wakes_on_release() {
        let m = std::sync::Arc::new(LockManager::new());
        let a = m
            .acquire(
                "k",
                Duration::from_secs(30),
                "a",
                now_plus(Duration::from_secs(1)),
            )
            .await
            .unwrap();
        let m2 = m.clone();
        let waiter = tokio::spawn(async move {
            m2.acquire(
                "k",
                Duration::from_secs(30),
                "b",
                now_plus(Duration::from_secs(5)),
            )
            .await
        });
        // give the waiter a moment to park, then release — it should wake promptly.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(m.release("k", &a));
        let got = waiter.await.unwrap();
        assert!(
            got.is_some(),
            "the parked waiter must acquire after release"
        );
    }

    #[tokio::test]
    async fn renew_does_not_resurrect_a_reacquired_lock() {
        let m = LockManager::new();
        // A takes a short lease and lets it lapse without heartbeating.
        let a = m
            .acquire(
                "k",
                Duration::from_millis(60),
                "a",
                now_plus(Duration::from_secs(1)),
            )
            .await
            .unwrap();
        // B reacquires once the lease lapses; it mints a fresh owner token.
        let b = m
            .acquire(
                "k",
                Duration::from_secs(30),
                "b",
                now_plus(Duration::from_secs(2)),
            )
            .await
            .unwrap();
        assert_ne!(a, b, "each acquire mints a distinct owner token");
        // A's stale owner must not renew — and must not extend B's live lease.
        assert!(
            !m.renew("k", &a, Duration::from_secs(30)),
            "a stale owner cannot renew a reacquired lock"
        );
        assert_eq!(
            m.holder("k").as_deref(),
            Some("b"),
            "B still holds the lock"
        );
        assert!(!m.release("k", &a), "a stale owner cannot release B's lock");
        assert!(m.release("k", &b));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn batch_acquire_is_all_or_nothing_under_contention() {
        let m = std::sync::Arc::new(LockManager::new());
        // hold the shared name so both overlapping batches must fail on it.
        let h = m
            .acquire(
                "y",
                Duration::from_secs(30),
                "holder",
                now_plus(Duration::from_secs(1)),
            )
            .await
            .unwrap();

        let m1 = m.clone();
        let t1 = tokio::spawn(async move {
            m1.acquire_all(
                &["x".into(), "y".into()],
                Duration::from_secs(30),
                "a",
                now_plus(Duration::from_millis(150)),
                None,
                None,
            )
            .await
        });
        let m2 = m.clone();
        let t2 = tokio::spawn(async move {
            m2.acquire_all(
                &["y".into(), "z".into()],
                Duration::from_secs(30),
                "b",
                now_plus(Duration::from_millis(150)),
                None,
                None,
            )
            .await
        });
        assert!(t1.await.unwrap().is_err(), "a batch blocked on y must fail");
        assert!(t2.await.unwrap().is_err(), "a batch blocked on y must fail");
        // the free names in the failed batches must NOT have been taken (all-or-nothing).
        assert_eq!(m.holder("x"), None, "no partial acquisition of x");
        assert_eq!(m.holder("z"), None, "no partial acquisition of z");
        assert_eq!(m.holder("y").as_deref(), Some("holder"));
        assert!(m.release("y", &h));
    }

    #[test]
    fn recent_failure_matches_only_the_recording_pipeline() {
        let m = LockManager::new();
        assert!(m.recent_failure("k", "pipeline-1").is_none());
        m.record_failure("k", "pipeline-1", "ENOSPC", Duration::from_secs(60));
        let f = m
            .recent_failure("k", "pipeline-1")
            .expect("recorded under pipeline-1");
        assert_eq!(f.reason, "ENOSPC");
        // a different pipeline (e.g. a restart) must never see the old failure.
        assert!(m.recent_failure("k", "pipeline-2").is_none());
        // an unrelated key is unaffected.
        assert!(m.recent_failure("other", "pipeline-1").is_none());
    }

    #[test]
    fn recent_failure_expires_past_its_ttl() {
        let m = LockManager::new();
        m.record_failure("k", "p", "boom", Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            m.recent_failure("k", "p").is_none(),
            "a lapsed failure record must not block a retry"
        );
    }

    #[test]
    fn record_failure_overwrites_an_earlier_record_for_the_same_key() {
        let m = LockManager::new();
        m.record_failure("k", "p", "first reason", Duration::from_secs(60));
        m.record_failure("k", "p", "second reason", Duration::from_secs(60));
        assert_eq!(m.recent_failure("k", "p").unwrap().reason, "second reason");
    }

    /// Another pipeline's record for the same key neither replaces nor clears this one's.
    #[test]
    fn a_record_under_another_pipeline_leaves_this_ones() {
        let m = LockManager::new();
        m.record_failure("k", "a", "ENOSPC", Duration::from_secs(60));
        m.record_failure("k", "b", "other", Duration::from_secs(60));
        assert_eq!(m.recent_failure("k", "a").unwrap().reason, "ENOSPC");
        assert_eq!(m.recent_failure("k", "b").unwrap().reason, "other");
    }

    #[test]
    fn a_limit_cuts_durations_and_deadlines() {
        let none = Limit::default();
        assert_eq!(none.cut(Duration::from_secs(90)), Duration::from_secs(90));
        let far = now_plus(Duration::from_secs(3600));
        assert_eq!(none.deadline(far), far);
        let end = now_plus(Duration::from_secs(30));
        let some = Limit(Some(end));
        assert!(some.cut(Duration::from_secs(90)) <= Duration::from_secs(30));
        assert_eq!(some.cut(Duration::from_secs(10)), Duration::from_secs(10));
        assert_eq!(some.deadline(far), end);
    }

    /// A lease granted after a wait still ends at `not_after`, not a full ttl past the
    /// grant: a token's lock never outlives the token.
    #[tokio::test]
    async fn a_lease_granted_after_a_wait_ends_at_not_after() {
        let m = LockManager::new();
        let names = ["k".to_string()];
        let blocker = m
            .acquire_all(
                &names,
                Duration::from_millis(300),
                "a",
                now_plus(Duration::ZERO),
                None,
                None,
            )
            .await;
        assert!(blocker.is_ok());
        let not_after = now_plus(Duration::from_millis(700));
        let owner = m
            .acquire_all(
                &names,
                Duration::from_secs(30),
                "b",
                now_plus(Duration::from_secs(5)),
                Some(not_after),
                None,
            )
            .await
            .ok()
            .expect("granted once the blocker's lease lapses");
        assert_eq!(m.holder("k").as_deref(), Some("b"));
        // A renewal does not push it past `not_after` either.
        assert_eq!(
            m.renew_all(&names, &owner, Duration::from_secs(30), Some(not_after)),
            1
        );
        tokio::time::sleep(not_after.saturating_duration_since(Instant::now())).await;
        assert_eq!(m.holder("k"), None, "the lease ended at not_after");
    }

    /// A token principal holds at most [`MAX_TOKEN_LOCKS`] live locks, refused at once past
    /// them whatever the wait; another principal, a request with no token and the principal
    /// once it releases one are not.
    #[tokio::test]
    async fn a_token_principal_holds_at_most_max_token_locks() {
        let m = LockManager::new();
        let ttl = Duration::from_secs(30);
        let take = |name: String, principal: Option<&'static str>| {
            let m = &m;
            async move {
                m.acquire_all(
                    &[name],
                    ttl,
                    "h",
                    now_plus(Duration::from_secs(60)),
                    None,
                    principal,
                )
                .await
            }
        };
        let mut owners = Vec::new();
        for i in 0..MAX_TOKEN_LOCKS {
            let Ok(owner) = take(format!("k{i}"), Some("job:1")).await else {
                panic!("lock {i} is within the bound");
            };
            owners.push(owner);
        }
        assert!(matches!(
            take("over".into(), Some("job:1")).await,
            Err(Refusal::TooMany)
        ));
        assert!(take("other".into(), Some("job:2")).await.is_ok());
        assert!(take("over".into(), None).await.is_ok());
        // One released, a batch still counts every name it takes.
        assert!(m.release("k0", &owners[0]));
        let pair = ["x".to_string(), "y".to_string()];
        let far = now_plus(Duration::from_secs(60));
        assert!(matches!(
            m.acquire_all(&pair, ttl, "h", far, None, Some("job:1"))
                .await,
            Err(Refusal::TooMany)
        ));
        assert!(take("again".into(), Some("job:1")).await.is_ok());
        // A batch past the bound is refused at once, a held name in it or not.
        let mut big: Vec<String> = (0..MAX_TOKEN_LOCKS).map(|i| format!("b{i}")).collect();
        big.push("other".into());
        let started = Instant::now();
        assert!(matches!(
            m.acquire_all(&big, ttl, "h", far, None, Some("job:3"))
                .await,
            Err(Refusal::TooMany)
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// Past [`MAX_FAIL_RECORDS`] live records, the oldest gives way to the newest.
    #[test]
    fn the_failure_table_evicts_its_oldest_record_past_the_cap() {
        let m = LockManager::new();
        let ttl = Duration::from_secs(60);
        for i in 0..=MAX_FAIL_RECORDS {
            m.record_failure(&format!("k{i}"), "p", "r", ttl);
        }
        assert_eq!(m.failed.lock().unwrap().records.len(), MAX_FAIL_RECORDS);
        assert!(m.recent_failure("k0", "p").is_none(), "the oldest went");
        assert!(m.recent_failure("k1", "p").is_some());
        assert!(
            m.recent_failure(&format!("k{MAX_FAIL_RECORDS}"), "p")
                .is_some()
        );
        // Replacing a record already held evicts nothing.
        m.record_failure("k1", "p", "again", ttl);
        assert_eq!(m.failed.lock().unwrap().records.len(), MAX_FAIL_RECORDS);
        assert!(m.recent_failure("k2", "p").is_some());
    }

    #[test]
    fn fail_ttl_defaults_and_clamps_but_never_shrinks_a_sane_value() {
        assert_eq!(fail_ttl(""), Duration::from_secs(DEFAULT_FAIL_TTL));
        assert_eq!(fail_ttl("ttl=60"), Duration::from_secs(60));
        // an outsized client-requested ttl (a memo blocks every build of this key across
        // the whole pipeline) must be clamped, not honored verbatim.
        assert_eq!(
            fail_ttl("ttl=999999999"),
            Duration::from_secs(MAX_FAIL_TTL),
            "an oversized ttl must be clamped to MAX_FAIL_TTL"
        );
    }

    #[test]
    fn acquire_deadline_defaults_and_clamps_an_outsized_wait() {
        let before = Instant::now();
        let d = acquire_deadline("");
        assert!(d >= before + Duration::from_secs(DEFAULT_WAIT));
        assert!(d <= Instant::now() + Duration::from_secs(DEFAULT_WAIT));
        // u64::MAX seconds overflows `Instant + Duration`; clamped, it must not panic.
        let before = Instant::now();
        let d = acquire_deadline("wait=18446744073709551615");
        assert!(d >= before + MAX_WAIT);
        assert!(d <= Instant::now() + MAX_WAIT);
    }

    #[tokio::test]
    async fn read_body_capped_accepts_a_body_at_the_cap() {
        let body = body_of(Bytes::from(vec![b'x'; 8]));
        let got = read_body_capped(body, 8).await.unwrap();
        assert_eq!(got.len(), 8);
    }

    #[tokio::test]
    async fn read_body_capped_rejects_a_body_over_the_cap() {
        let body = body_of(Bytes::from(vec![b'x'; 9]));
        assert!(read_body_capped(body, 8).await.is_err());
    }

    // The whole point of reading frame-by-frame is to never fully buffer an oversized body
    // server-side first. Feed a streaming body whose total size is far over the cap but
    // whose individual frames are cap-sized, and assert the read stops as soon as the
    // running total crosses the cap — not after draining every frame the client sent.
    #[tokio::test]
    async fn read_body_capped_stops_reading_once_over_cap_without_draining_the_rest() {
        use futures::{StreamExt, stream};
        use http_body_util::StreamBody;
        use hyper::body::Frame;
        let cap = 8usize;
        let total_frames = 5usize; // 5 * cap is far over cap
        let polled = std::rc::Rc::new(std::cell::Cell::new(0usize));
        let counted = polled.clone();
        let frames = stream::iter(0..total_frames).map(move |_| {
            counted.set(counted.get() + 1);
            Ok::<_, std::io::Error>(Frame::data(Bytes::from(vec![b'x'; cap])))
        });
        let body = StreamBody::new(frames);
        let err = read_body_capped(body, cap)
            .await
            .expect_err("a body far over the cap must be rejected");
        assert_eq!(err, "reason body too large");
        assert!(
            polled.get() < total_frames,
            "must bail once over cap instead of draining every frame, polled {} of {total_frames}",
            polled.get()
        );
    }

    /// Handover refuses grants, renewals, releases and failure records, waking waiting
    /// acquisitions immediately to retry against the release. Restore preserves leases
    /// less elapsed time; taking the table back permits changes again.
    #[tokio::test]
    async fn a_table_handed_over_changes_no_more_and_restores_whole() {
        let m = std::sync::Arc::new(LockManager::new());
        let a = ["a".to_string()];
        let owner = m
            .acquire_all(
                &a,
                Duration::from_secs(30),
                "one",
                now_plus(Duration::ZERO),
                None,
                Some("job"),
            )
            .await
            .ok()
            .unwrap();
        m.record_failure("k", "p", "broke", Duration::from_secs(600));
        let waiting = {
            let m = m.clone();
            let a = a.clone();
            tokio::spawn(async move {
                m.acquire_all(
                    &a,
                    Duration::from_secs(30),
                    "two",
                    now_plus(Duration::from_secs(60)),
                    None,
                    None,
                )
                .await
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        let snapshot = m.hand_over().unwrap();
        match tokio::time::timeout(Duration::from_secs(5), waiting).await {
            Ok(Ok(Err(Refusal::HandedOver))) => {}
            _ => panic!("the acquisition waiting was not answered as handed over"),
        }
        let b = ["b".to_string()];
        assert!(matches!(
            m.acquire_all(
                &b,
                Duration::from_secs(30),
                "x",
                now_plus(Duration::ZERO),
                None,
                None
            )
            .await,
            Err(Refusal::HandedOver)
        ));
        assert_eq!(
            m.try_renew_all(&a, &owner, Duration::from_secs(30), None),
            None
        );
        assert_eq!(m.try_release_all(&a, &owner), None);
        assert!(!m.try_record_failure("k2", "p", "r", Duration::from_secs(60)));

        let restored = LockManager::restore(snapshot, Duration::from_secs(10));
        assert_eq!(restored.holder("a").as_deref(), Some("one"));
        {
            let held = restored.held.lock().unwrap();
            let left = held["a"].expires.saturating_duration_since(Instant::now());
            assert!(left <= Duration::from_secs(20), "{left:?}");
            assert_eq!(held["a"].principal.as_deref(), Some("job"));
        }
        let failure = restored.recent_failure("k", "p").unwrap();
        assert_eq!(failure.reason, "broke");
        assert!(failure.age >= Duration::from_secs(10));
        assert_eq!(
            restored.try_renew_all(&a, &owner, Duration::from_secs(30), None),
            Some(1)
        );

        m.take_back();
        assert_eq!(m.try_release_all(&a, &owner), Some(1));
    }

    /// A lease or failure record whose time ran out in between is not restored.
    #[test]
    fn what_lapsed_in_between_is_not_restored() {
        let m = LockManager::new();
        assert!(
            m.try_take_all(
                &["a".to_string()],
                Duration::from_secs(1),
                "h",
                None,
                None,
                &HashSet::new()
            )
            .is_ok()
        );
        m.record_failure("k", "p", "r", Duration::from_secs(1));
        let restored = LockManager::restore(m.hand_over().unwrap(), Duration::from_secs(5));
        assert_eq!(restored.holder("a"), None);
        assert!(restored.recent_failure("k", "p").is_none());
    }

    /// The root of a store of this test alone, in this run of the tests. Two managers over
    /// it stand for two processes: each binds its own sockets.
    fn host_root(what: &str) -> std::path::PathBuf {
        crate::testtmp::root().join(format!("hostlocks-{what}"))
    }

    /// Bind `addr` and never listen: every query of it is refused.
    fn squat(addr: &SocketAddr) -> std::os::fd::OwnedFd {
        use std::os::fd::FromRawFd;
        let (sa, len) = hostlock::abstract_sockaddr(addr).unwrap();
        // SAFETY: plain socket calls on a fresh descriptor, owned by the result; `sa` and
        // `len` describe exactly the address filled in.
        unsafe {
            let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            assert!(fd >= 0);
            assert_eq!(
                libc::bind(fd, (&raw const sa).cast(), len as libc::socklen_t),
                0
            );
            std::os::fd::OwnedFd::from_raw_fd(fd)
        }
    }

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    /// Take `names` from `m` as `holder` for 30 s, waiting up to `wait`.
    async fn take(
        m: &LockManager,
        names: &[String],
        holder: &str,
        wait: Duration,
    ) -> Result<String, Refusal> {
        m.acquire_all(
            names,
            Duration::from_secs(30),
            holder,
            now_plus(wait),
            None,
            None,
        )
        .await
    }

    /// The blockers of a refused acquisition, as `(name, holder)`.
    fn blockers(refused: Result<String, Refusal>) -> Vec<(String, String)> {
        match refused {
            Err(Refusal::Held(blockers)) => {
                blockers.into_iter().map(|b| (b.name, b.holder)).collect()
            }
            Ok(_) => panic!("granted"),
            Err(_) => panic!("refused, but not for its blockers"),
        }
    }

    const SOON: Duration = Duration::from_secs(10);

    /// Two managers over one store are one authority: a name leased by one blocks the
    /// other, which names its holder, until it is released.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn managers_sharing_a_store_exclude_each_other() {
        let root = host_root("exclude");
        let a = LockManager::host_shared(&root).unwrap();
        let b = LockManager::host_shared(&root).unwrap();
        let k = names(&["k"]);
        let owner = take(&a, &k, "job A", Duration::ZERO).await.ok().unwrap();
        assert_eq!(
            blockers(take(&b, &k, "job B", Duration::ZERO).await),
            [("k".to_string(), "job A".to_string())]
        );
        assert_eq!(b.holder("k"), None, "no lease of its own");
        assert_eq!(b.holder_on_host("k").await.as_deref(), Some("job A"));
        assert_eq!(b.holder_on_host("free").await, None);
        // Another store's lock of the same name, and a manager that shares nothing, are free.
        let other = LockManager::host_shared(&host_root("exclude-other")).unwrap();
        assert!(take(&other, &k, "job C", Duration::ZERO).await.is_ok());
        assert!(
            take(&LockManager::new(), &k, "job D", Duration::ZERO)
                .await
                .is_ok()
        );

        let waiter = tokio::spawn(async move {
            let granted = take(&b, &k, "job B", SOON).await.is_ok();
            (b, granted)
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter.is_finished(), "it waits for the other manager");
        assert!(a.release("k", &owner));
        let (b, granted) = waiter.await.unwrap();
        assert!(granted, "a release lets the other manager in");
        assert_eq!(a.holder_on_host("k").await.as_deref(), Some("job B"));
        drop(b);
    }

    /// A lease that lapses is let go for the other processes without anything more being
    /// asked of its manager, also one a renewal cut short.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lapsed_lease_frees_its_name_for_another_process() {
        let root = host_root("lapse");
        let a = LockManager::host_shared(&root).unwrap();
        let b = LockManager::host_shared(&root).unwrap();
        let k = names(&["k"]);
        a.acquire_all(
            &k,
            Duration::from_millis(300),
            "job A",
            Instant::now(),
            None,
            None,
        )
        .await
        .ok()
        .unwrap();
        assert!(take(&b, &k, "job B", Duration::ZERO).await.is_err());
        assert!(take(&b, &k, "job B", SOON).await.is_ok());
        // A renewed lease is kept past its first end.
        let owner = a
            .acquire_all(
                &names(&["r"]),
                Duration::from_millis(300),
                "job A",
                Instant::now(),
                None,
                None,
            )
            .await
            .ok()
            .unwrap();
        assert!(a.renew("r", &owner, Duration::from_secs(30)));
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(b.holder_on_host("r").await.as_deref(), Some("job A"));
        // Cut short, it ends then, not 30 s on.
        assert!(a.renew("r", &owner, Duration::from_millis(200)));
        assert!(take(&b, &names(&["r"]), "job B", SOON).await.is_ok());
    }

    /// A batch blocked by another process takes none of its names, here or on the host.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_batch_another_process_blocks_takes_nothing() {
        let root = host_root("batch");
        let a = LockManager::host_shared(&root).unwrap();
        let b = LockManager::host_shared(&root).unwrap();
        let c = LockManager::host_shared(&root).unwrap();
        take(&a, &names(&["y"]), "job A", Duration::ZERO)
            .await
            .ok()
            .unwrap();
        assert_eq!(
            blockers(take(&b, &names(&["x", "y", "z"]), "job B", Duration::ZERO).await),
            [("y".to_string(), "job A".to_string())]
        );
        assert_eq!(b.held_count(), 0);
        assert!(take(&c, &names(&["x", "z"]), "job C", SOON).await.is_ok());
        // A name leased here is not asked of the host: the batch waits for the lease.
        assert_eq!(
            blockers(take(&c, &names(&["w", "x"]), "job C2", Duration::ZERO).await),
            [("x".to_string(), "job C".to_string())]
        );
        assert!(take(&b, &names(&["w"]), "job B", SOON).await.is_ok());
    }

    /// A name three queries in a row cannot connect to is not waited for: the lease is
    /// granted, and excludes this manager's own clients.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_squatted_name_is_leased_unshared() {
        let root = host_root("squat");
        let m = LockManager::host_shared(&root).unwrap();
        let _squatter = squat(&HostLocks::new(&root).unwrap().addr("k").unwrap());
        let k = names(&["k"]);
        // Not at the first refusal: a holder may only just have gone.
        assert_eq!(
            blockers(take(&m, &k, "job A", Duration::ZERO).await),
            [("k".to_string(), ANOTHER_PROCESS.to_string())]
        );
        assert_eq!(m.holder_on_host("k").await, None);
        assert!(take(&m, &k, "job A", SOON).await.is_ok());
        assert_eq!(
            blockers(take(&m, &k, "job B", Duration::ZERO).await),
            [("k".to_string(), "job A".to_string())]
        );
    }

    /// A name given up on is asked after again before it is leased unshared: a process
    /// that answers may hold it by then.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_name_given_up_on_is_asked_after_again() {
        let root = host_root("stale");
        let a = LockManager::host_shared(&root).unwrap();
        let b = LockManager::host_shared(&root).unwrap();
        let m = LockManager::host_shared(&root).unwrap();
        let squatter = squat(&HostLocks::new(&root).unwrap().addr("k").unwrap());
        let w = names(&["w"]);
        let held = take(&a, &w, "job A", Duration::ZERO).await.ok().unwrap();
        let waiter = tokio::spawn(async move {
            // Room for a loaded machine to do all that follows before the wait runs out.
            let taken = take(&m, &names(&["k", "w"]), "job M", Duration::from_secs(6)).await;
            (m, taken)
        });
        // Long enough for `k` to be given up on, the batch still waiting for `w`.
        tokio::time::sleep(Duration::from_millis(900)).await;
        drop(squatter);
        assert!(take(&b, &names(&["k"]), "job B", SOON).await.is_ok());
        assert!(a.release("w", &held));
        let (m, taken) = waiter.await.unwrap();
        assert_eq!(blockers(taken), [("k".to_string(), "job B".to_string())]);
        assert_eq!(m.held_count(), 0);
    }

    /// A query that fails on this side is no sign of a holder that cannot be connected to.
    #[test]
    fn a_failed_query_is_not_held_against_the_holder() {
        use hostlock::Verdict;
        let failed = Err(std::io::Error::other("out of descriptors"));
        let mut silent = 2;
        for _ in 0..5 {
            assert_eq!(weigh(&failed, 1000, &mut silent), Verdict::Wait);
        }
        assert_eq!(silent, 2);
        assert_eq!(weigh(&Ok(None), 1000, &mut silent), Verdict::Unanswering);
        let ours = Ok(Some(hostlock::Holder {
            uid: Some(1000),
            who: None,
        }));
        assert_eq!(weigh(&ours, 1000, &mut silent), Verdict::Wait);
        assert_eq!(silent, 0);
    }

    /// Holders that connect and say nothing are waited for, but not past the deadline of
    /// what asks: a second each would be.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn holders_that_say_nothing_do_not_stretch_a_wait() {
        use std::os::unix::net::UnixListener;
        let root = host_root("mute");
        let m = LockManager::host_shared(&root).unwrap();
        let locks = HostLocks::new(&root).unwrap();
        let all = names(&["a", "b", "c", "d"]);
        // Listening, never accepting: a query connects and is told nothing.
        let _mute: Vec<UnixListener> = all
            .iter()
            .map(|n| UnixListener::bind_addr(&locks.addr(n).unwrap()).unwrap())
            .collect();
        let started = Instant::now();
        let refused = blockers(take(&m, &all, "job A", Duration::ZERO).await);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(refused.len(), 4);
        assert!(refused.iter().all(|(_, holder)| holder == ANOTHER_PROCESS));
        // Nor a status request, past its one second.
        let started = Instant::now();
        assert_eq!(m.holders_on_host(&all).await.len(), 4);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    /// A name given twice is taken once, and shared.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_name_given_twice_is_taken_once() {
        let root = host_root("twice");
        let a = LockManager::host_shared(&root).unwrap();
        let b = LockManager::host_shared(&root).unwrap();
        assert!(
            take(&a, &names(&["k", "k"]), "job A", Duration::ZERO)
                .await
                .is_ok()
        );
        assert_eq!(a.held_count(), 1);
        assert_eq!(
            blockers(take(&b, &names(&["k"]), "job B", Duration::ZERO).await),
            [("k".to_string(), "job A".to_string())]
        );
    }

    /// Nothing is granted once `not_after` has passed, whatever the wait.
    #[tokio::test]
    async fn nothing_is_granted_past_not_after() {
        let m = LockManager::new();
        let ttl = Duration::from_secs(30);
        let taken = m
            .acquire_all(
                &names(&["k"]),
                ttl,
                "h",
                now_plus(SOON),
                Some(Instant::now()),
                None,
            )
            .await;
        assert!(blockers(taken).is_empty());
        assert_eq!(m.held_count(), 0);
    }

    /// A store's locks go by one name however its root is spelled, also before it is there.
    #[test]
    fn a_stores_locks_do_not_depend_on_how_its_root_is_spelled() {
        use std::os::linux::net::SocketAddrExt;
        let base = host_root("alias");
        std::fs::create_dir_all(base.join("real")).unwrap();
        std::os::unix::fs::symlink(base.join("real"), base.join("link")).unwrap();
        let early = HostLocks::new(&base.join("link/store")).unwrap();
        let late = HostLocks::new(&base.join("real/store")).unwrap();
        assert_eq!(
            early.addr("k").unwrap().as_abstract_name(),
            late.addr("k").unwrap().as_abstract_name()
        );
        assert!(HostLocks::new(Path::new("/proc/self/status/store")).is_err());
        assert!(LockManager::host_shared(Path::new("/proc/self/status/store")).is_err());
    }

    /// A table shared with the host is not handed over, and goes on as it was.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_host_shared_table_is_not_handed_over() {
        let m = LockManager::host_shared(&host_root("handover")).unwrap();
        let k = names(&["k"]);
        let owner = take(&m, &k, "job A", Duration::ZERO).await.ok().unwrap();
        assert!(m.hand_over().is_err());
        assert!(!m.is_handed_over());
        assert!(m.release("k", &owner));
    }

    /// A host-shared manager grants short leases and a bounded number of them, whoever asks.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_host_shared_manager_bounds_its_leases() {
        let m = LockManager::host_shared(&host_root("bounds")).unwrap();
        assert_eq!(m.lease(Duration::from_secs(3600)), MAX_HOST_LEASE_TTL);
        assert_eq!(m.lease(Duration::from_secs(30)), Duration::from_secs(30));
        assert_eq!(
            LockManager::new().lease(Duration::from_secs(3600)),
            Duration::from_secs(3600)
        );

        let all: Vec<String> = (0..MAX_HOST_LOCKS).map(|i| format!("k{i}")).collect();
        let owner = take(&m, &all, "job A", Duration::ZERO).await.ok().unwrap();
        assert_eq!(m.held_count(), MAX_HOST_LOCKS);
        assert!(matches!(
            take(&m, &names(&["more"]), "job B", SOON).await,
            Err(Refusal::Full)
        ));
        // Not for a name it holds, which only waits.
        assert_eq!(
            blockers(take(&m, &names(&["k0"]), "job B", Duration::ZERO).await).len(),
            1
        );
        assert!(m.release("k0", &owner));
        assert!(take(&m, &names(&["more"]), "job B", SOON).await.is_ok());
    }
}
