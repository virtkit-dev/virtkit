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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};

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
/// this key across the whole pipeline until it expires or the pipeline restarts, so unlike
/// `/lock/acquire`'s lease (30s default, reclaimed fast on a miss), an unbounded `?ttl=`
/// here has an outsized blast radius. Generous enough for any real pipeline, not a cap
/// meant to bind tightly.
const MAX_FAIL_TTL: u64 = 24 * 3600;
/// `/lock/fail`'s reason body is free text for a log/error message, not a payload; cap it
/// well above anything reasonable so a client can't park an unbounded buffer server-side.
const MAX_FAIL_REASON: usize = 4096;

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
}

/// A name in a batch acquire that a live lease already holds, with that holder's identity
/// — reported so a waiter can log who blocks it (like `ci-lock-mgr.sh`'s blocker list).
pub struct Blocker {
    pub name: String,
    pub holder: String,
}

/// A recorded build failure for one content-key, scoped to the pipeline that hit it — see
/// [`LockManager::record_failure`].
struct FailRecord {
    pipeline: String,
    reason: String,
    recorded_at: Instant,
    ttl: Duration,
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
    seq: AtomicU64,
    /// build-failure memos, independent of `held` — a domain-specific negative cache, not a
    /// mutual-exclusion primitive, so it never entangles with `task`'s reuse of `/lock/*` for
    /// its own (unrelated) locking. See [`LockManager::record_failure`].
    failed: Mutex<HashMap<String, FailRecord>>,
}

impl Default for LockManager {
    fn default() -> Self {
        Self::new()
    }
}

impl LockManager {
    pub fn new() -> Self {
        LockManager {
            held: Mutex::new(HashMap::new()),
            freed: Notify::new(),
            seq: AtomicU64::new(0),
            failed: Mutex::new(HashMap::new()),
        }
    }

    /// Record that `name` (a build stage's content-key) just failed to build under
    /// `pipeline`'s watch, so a peer — another job in the same pipeline needing the same
    /// key, or this job's own runner-level retry — can fail fast instead of repeating a
    /// doomed, expensive build. Scoped to `pipeline`: a different pipeline id (a restart)
    /// always gets a fresh attempt, so there is no separate "clear" operation. Upserts (a
    /// later failure replaces an earlier one) and prunes every lapsed record while it's at
    /// it, so the table can't grow without bound.
    pub fn record_failure(&self, name: &str, pipeline: &str, reason: &str, ttl: Duration) {
        let mut map = self.failed.lock().unwrap();
        let now = Instant::now();
        map.retain(|_, r| now.duration_since(r.recorded_at) < r.ttl);
        map.insert(
            name.to_string(),
            FailRecord {
                pipeline: pipeline.to_string(),
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
        self.failed.lock().unwrap().get(name).and_then(|r| {
            (r.pipeline == pipeline && now.duration_since(r.recorded_at) < r.ttl).then(|| {
                FailInfo {
                    reason: r.reason.clone(),
                    age: now.duration_since(r.recorded_at),
                }
            })
        })
    }

    /// Unique within this process — all the authority a single-process lock needs.
    fn mint_owner(&self) -> String {
        format!(
            "{}-{}",
            std::process::id(),
            self.seq.fetch_add(1, Ordering::Relaxed)
        )
    }

    /// Atomically take ALL `names` for `ttl`, or none (reaping lapsed leases first).
    /// Returns the shared batch owner token, or the live blockers if any name is held.
    /// All-or-nothing under one lock, so acquiring a set never deadlocks against another
    /// batch regardless of order.
    fn try_take_all(
        &self,
        names: &[String],
        ttl: Duration,
        holder: &str,
    ) -> Result<String, Vec<Blocker>> {
        let mut map = self.held.lock().unwrap();
        let now = Instant::now();
        // drop every lapsed lease so the table can't grow without bound from names whose
        // holder died and never reacquired (release is otherwise the only path that prunes).
        map.retain(|_, h| h.expires > now);
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
            return Err(blockers);
        }
        let owner = self.mint_owner();
        for n in names {
            map.insert(
                n.clone(),
                Held {
                    owner: owner.clone(),
                    holder: holder.to_string(),
                    expires: now + ttl,
                },
            );
        }
        Ok(owner)
    }

    /// Acquire ALL `names` atomically, long-polling until the whole set is free or
    /// `deadline`. On timeout nothing is taken and the current blockers are returned. The
    /// batch shares one owner token; renew/release act on the set. Wakes on a release, and
    /// at worst every [`MAX_POLL`] so a lapsed lease is reclaimed even if its release
    /// notification was missed.
    pub async fn acquire_all(
        &self,
        names: &[String],
        ttl: Duration,
        holder: &str,
        deadline: Instant,
    ) -> Result<String, Vec<Blocker>> {
        loop {
            match self.try_take_all(names, ttl, holder) {
                Ok(owner) => return Ok(owner),
                Err(blockers) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(blockers);
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

    /// Renew every name in the batch still held by `owner`; returns the count renewed
    /// (a heartbeat treats fewer than the batch size as "lost the batch").
    pub fn renew_all(&self, names: &[String], owner: &str, ttl: Duration) -> usize {
        let mut map = self.held.lock().unwrap();
        let now = Instant::now();
        let mut n = 0;
        for name in names {
            if let Some(h) = map.get_mut(name)
                && h.owner == owner
                && h.expires > now
            {
                h.expires = now + ttl;
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
            if map.get(name).is_some_and(|h| h.owner == owner) {
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
        self.acquire_all(&names, ttl, holder, deadline).await.ok()
    }

    /// Extend the lease if `owner` still holds a live lease on `name`.
    pub fn renew(&self, name: &str, owner: &str, ttl: Duration) -> bool {
        self.renew_all(&[name.to_string()], owner, ttl) == 1
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
/// - `POST /lock/renew?name=…&ttl=`         (`X-Vk-Lock-Owner`)  → `{renewed, of}`
/// - `POST /lock/release?name=…`            (`X-Vk-Lock-Owner`)  → `{released}`
/// - `POST /lock/status?name=…`                                  → `{holders:[{name, holder}]}`
///
/// A second, independent pair — a build-failure memo, not a mutual-exclusion primitive, so
/// it never entangles with `task`'s reuse of the four locking endpoints above:
///
/// - `POST /lock/fail?name=…&ttl=` (`X-Vk-Lock-Pipeline`, body = reason text) → `{recorded:true}`
/// - `POST /lock/fail-status?name=…` (`X-Vk-Lock-Pipeline`) → `{failed:false}` |
///   `{failed:true, reason, age_secs}`
pub async fn route(mgr: &LockManager, req: Request<Incoming>) -> Result<Response<Body>> {
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let owner = header(&req, "x-vk-lock-owner");
    let holder = header(&req, "x-vk-lock-holder").unwrap_or_default();
    let pipeline = header(&req, "x-vk-lock-pipeline");

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

    match path.as_str() {
        // acquire the whole set atomically (all-or-nothing), long-polling until free.
        "/lock/acquire" => {
            let ttl = Duration::from_secs(qparam(&query, "ttl").unwrap_or(DEFAULT_TTL));
            let wait = Duration::from_secs(qparam(&query, "wait").unwrap_or(DEFAULT_WAIT));
            let deadline = Instant::now() + wait;
            match mgr.acquire_all(&names, ttl, &holder, deadline).await {
                Ok(owner) => {
                    let body = serde_json::json!({
                        "owner": owner, "names": names, "ttl": ttl.as_secs(),
                    });
                    Ok(json(StatusCode::OK, &body.to_string()))
                }
                Err(blockers) => {
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
            let n = mgr.renew_all(&names, &owner, ttl);
            let body = serde_json::json!({"renewed": n, "of": names.len()});
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
            let ttl = fail_ttl(&query);
            let reason = match read_body_capped(req.into_body(), MAX_FAIL_REASON).await {
                Ok(b) => String::from_utf8_lossy(&b).into_owned(),
                Err(e) => {
                    return Ok(json(
                        StatusCode::BAD_REQUEST,
                        &format!(r#"{{"error":"{e}"}}"#),
                    ));
                }
            };
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
            let val = percent_decode(v);
            if seen.insert(val.clone()) {
                out.push(val);
            }
        }
    }
    out
}

/// Minimal `%XX` + `+` percent-decode for query values (lock names may carry `:`/`/`).
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 3 <= b.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(v) => {
                    out.push(v);
                    i += 3;
                }
                Err(_) => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
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

/// `/lock/fail`'s effective ttl: the client's `?ttl=` (or [`DEFAULT_FAIL_TTL`]), clamped to
/// [`MAX_FAIL_TTL`] — see that constant's doc for why this endpoint clamps where
/// `/lock/acquire`'s lease does not.
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
