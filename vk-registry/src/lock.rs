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

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};

use vk_hub_proto::token::Claims;

use crate::{Body, body_of};
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
}

/// A name in a batch acquire that a live lease already holds, with that holder's identity
/// — reported so a waiter can log who blocks it (like `ci-lock-mgr.sh`'s blocker list).
pub struct Blocker {
    pub name: String,
    pub holder: String,
}

/// Why an acquisition was not granted.
pub enum Refusal {
    /// Names a live lease holds, with their holders: the caller may wait for them.
    Held(Vec<Blocker>),
    /// The principal would hold more than [`MAX_TOKEN_LOCKS`] live locks: waiting does not help.
    TooMany,
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
    held: Mutex<HashMap<String, Held>>,
    /// notified on every release so parked `acquire` calls re-check promptly
    freed: Notify,
    /// build-failure memos, independent of `held` — a domain-specific negative cache, not a
    /// mutual-exclusion primitive, so it never entangles with `task`'s reuse of `/lock/*` for
    /// its own (unrelated) locking. See [`LockManager::record_failure`].
    failed: Mutex<FailTable>,
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
            held: Mutex::new(HashMap::new()),
            freed: Notify::new(),
            failed: Mutex::new(FailTable::default()),
        }
    }

    /// Record that `name` (a build stage's content-key) just failed to build under
    /// `pipeline`'s watch, so a peer — another job in the same pipeline needing the same
    /// key, or this job's own runner-level retry — can fail fast instead of repeating a
    /// doomed, expensive build. Scoped to `pipeline`: a different pipeline id (a restart)
    /// always gets a fresh attempt, so there is no separate "clear" operation. Upserts (a
    /// later failure under the same pipeline replaces an earlier one; another pipeline's is
    /// left alone) and prunes every lapsed record while it's at it; past
    /// [`MAX_FAIL_RECORDS`] live ones, the oldest is evicted.
    pub fn record_failure(&self, name: &str, pipeline: &str, reason: &str, ttl: Duration) {
        let mut table = self.failed.lock().unwrap();
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

    /// Atomically take ALL `names` for `ttl`, ending no later than `not_after`, or none
    /// (reaping lapsed leases first). Returns the shared batch owner token, or the live
    /// blockers if any name is held, or [`Refusal::TooMany`] if `principal` would then hold
    /// more than [`MAX_TOKEN_LOCKS`]. All-or-nothing under one lock, so acquiring a set never
    /// deadlocks against another batch regardless of order.
    fn try_take_all(
        &self,
        names: &[String],
        ttl: Duration,
        holder: &str,
        not_after: Option<Instant>,
        principal: Option<&str>,
    ) -> Result<String, Refusal> {
        let mut map = self.held.lock().unwrap();
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
                return Err(Refusal::TooMany);
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
            return Err(Refusal::Held(blockers));
        }
        let owner = Self::mint_owner();
        for n in names {
            map.insert(
                n.clone(),
                Held {
                    owner: owner.clone(),
                    holder: holder.to_string(),
                    expires: lease_end(now, ttl, not_after),
                    principal: principal.map(str::to_string),
                },
            );
        }
        Ok(owner)
    }

    /// Acquire ALL `names` atomically, long-polling until the whole set is free or
    /// `deadline`. On timeout nothing is taken and the current blockers are returned. The
    /// lease runs `ttl` from the grant, cut at `not_after`. The batch shares one owner
    /// token; renew/release act on the set. Wakes on a release, and at worst every
    /// [`MAX_POLL`] so a lapsed lease is reclaimed even if its release notification was
    /// missed. A `principal` past [`MAX_TOKEN_LOCKS`] is refused at once.
    pub async fn acquire_all(
        &self,
        names: &[String],
        ttl: Duration,
        holder: &str,
        deadline: Instant,
        not_after: Option<Instant>,
        principal: Option<&str>,
    ) -> Result<String, Refusal> {
        loop {
            match self.try_take_all(names, ttl, holder, not_after, principal) {
                Ok(owner) => return Ok(owner),
                Err(Refusal::TooMany) => return Err(Refusal::TooMany),
                Err(Refusal::Held(blockers)) => {
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
                    tokio::select! {
                        _ = self.freed.notified() => {}
                        _ = tokio::time::sleep(sleep) => {}
                    }
                }
            }
        }
    }

    /// Renew every name in the batch still held by `owner`, for `ttl` cut at `not_after`;
    /// returns the count renewed (a heartbeat treats fewer than the batch size as "lost the
    /// batch").
    pub fn renew_all(
        &self,
        names: &[String],
        owner: &str,
        ttl: Duration,
        not_after: Option<Instant>,
    ) -> usize {
        let mut map = self.held.lock().unwrap();
        let now = Instant::now();
        let mut n = 0;
        for name in names {
            if let Some(h) = map.get_mut(name)
                && crate::auth::constant_eq(h.owner.as_bytes(), owner.as_bytes())
                && h.expires > now
            {
                h.expires = lease_end(now, ttl, not_after);
                n += 1;
            }
        }
        n
    }

    /// Release every name in the batch held by `owner`, waking waiters; returns the count.
    pub fn release_all(&self, names: &[String], owner: &str) -> usize {
        let mut map = self.held.lock().unwrap();
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
        n
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
                        "owner": owner, "names": names, "ttl": limit.cut(lease(ttl)).as_secs(),
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
            let n = mgr.renew_all(&names, &owner, ttl, limit.0);
            let body = serde_json::json!({
                "renewed": n, "of": names.len(), "ttl": limit.cut(lease(ttl)).as_secs(),
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
            let n = mgr.release_all(&names, &owner);
            Ok(json(
                StatusCode::OK,
                &serde_json::json!({"released": n}).to_string(),
            ))
        }
        // holder identity for each requested name that is currently held.
        "/lock/status" => {
            let holders: Vec<_> = names
                .iter()
                .filter_map(|n| {
                    mgr.holder(n)
                        .map(|h| serde_json::json!({"name": n, "holder": h}))
                })
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
                mgr.record_failure(name, &pipeline, &reason, ttl);
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

/// Requested lease `ttl`, clamped to [`MAX_LEASE_TTL`].
fn lease(ttl: Duration) -> Duration {
    ttl.min(MAX_LEASE_TTL)
}

/// End of a lease granted or renewed at `now`, with `ttl` capped by [`lease`] and
/// `not_after`.
fn lease_end(now: Instant, ttl: Duration, not_after: Option<Instant>) -> Instant {
    let end = now + lease(ttl);
    not_after.map_or(end, |n| end.min(n))
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
}
