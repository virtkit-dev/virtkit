//! Live updates: a page's fragment re-rendered and pushed as a server-sent event whenever
//! what it shows may have changed, for htmx's SSE extension to swap in.
//!
//! A fragment that is the same for every viewer — the nodes table, local mode's VMs — is
//! rendered once per change, by one task, and each page's stream only forwards it
//! ([`Source::Shared`]). A page of one thing — a node, a VM — renders its own fragment, woken
//! only by the changes it follows ([`Source::Own`]). Either way a fragment is rendered at most
//! once per [`DEBOUNCE`] however fast what it shows changes, and sent only when it differs
//! from the last one that stream sent; ages on the pages move in steps of a heartbeat, so a
//! page with nothing new to show is sent nothing but keep-alives.
//!
//! Streams hold connections, so there are at most [`MAX_STREAMS`] of them — the rest of the
//! UI's connections stay for pages and posts — and [`MAX_SESSION_STREAMS`] per session. A
//! stream whose browser stops reading drops its connection once the buffers between them
//! fill, hyper's and the socket's before its own: a quiet page can take long to, and holds
//! no more than its place under those caps until it does.
//! One past either is answered 429 or 503, and htmx's SSE extension retries it with its own
//! backoff, doubling from half a second to 64 seconds. A stream whose session ends sends a
//! fragment saying so and the `close` event the pages name in `sse-close`, on which the
//! extension closes its connection for good; a page asking for one after its session ended is
//! answered the same.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use hyper::header::{self, HeaderValue};
use hyper::{Response, StatusCode};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch};

use super::{Auth, Body, pages};
use crate::server::{HEARTBEAT, Hub};

/// The fewest seconds between two renders of one stream: a fleet's heartbeats arrive every
/// few seconds from every node, and a page need not follow each one.
const DEBOUNCE: Duration = Duration::from_secs(1);

/// How often a fragment is rendered with no change noted, for what moves on its own: ages,
/// and a node that goes quiet becomes unreachable without a message saying so. Also how
/// soon a stream notices its session has ended without being told.
const REFRESH: Duration = HEARTBEAT;

/// Streams at once, of the [`MAX_CONNECTIONS`](super::MAX_CONNECTIONS) the UI's listeners
/// share.
#[cfg(not(test))]
pub const MAX_STREAMS: usize = 96;
#[cfg(test)]
pub const MAX_STREAMS: usize = 8;

/// Streams at once for one session: a few tabs. Below the six connections a browser opens to
/// one host over HTTP/1.1, which every tab of its profile shares: at six, every one of them
/// would be held by a stream, and the next page or post would wait for one to close.
pub const MAX_SESSION_STREAMS: usize = 4;

/// A comment sent after this long with no event, so a proxy or the browser does not take a
/// quiet stream for a dead one.
const KEEP_ALIVE: Duration = Duration::from_secs(15);

/// How long a stream waits on a browser not reading before it gives up on it.
#[cfg(not(test))]
const SEND_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(test)]
const SEND_TIMEOUT: Duration = Duration::from_secs(1);

tokio::task_local! {
    /// Notified to drop the connection a request came in on, by a stream given up on its
    /// browser: hyper, waiting to write what the browser does not read, would hold it open
    /// for as long as the browser does, and never poll the body for an error that would end
    /// it. Set around each request by `serve_conn`.
    pub static GIVE_UP: Arc<Notify>;
}

/// One event: `event: <name>`, then `data` a line at a time, then the blank line that ends
/// it. Any line break in `data` starts a new `data:` line, which the browser joins back with
/// `\n`, so nothing in it can end the event early or start another.
pub fn event(name: &'static str, data: &str) -> Bytes {
    let mut out = format!("event: {name}\n");
    let normalized = data.replace("\r\n", "\n").replace('\r', "\n");
    for line in normalized.split('\n') {
        out.push_str("data: ");
        out.push_str(line);
        out.push('\n');
    }
    out.push('\n');
    Bytes::from(out)
}

const COMMENT: &[u8] = b": keep-alive\n\n";

/// The event on which a page's `sse-close` closes the stream for good.
pub const CLOSE: &str = "close";

/// The streams open, against [`MAX_STREAMS`] and [`MAX_SESSION_STREAMS`].
pub struct Streams {
    all: Arc<Semaphore>,
    by_session: Arc<Mutex<HashMap<String, usize>>>,
}

/// One stream's place, given back when it is dropped.
pub struct Slot {
    _all: OwnedSemaphorePermit,
    by_session: Arc<Mutex<HashMap<String, usize>>>,
    session: String,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut by_session = lock(&self.by_session);
        if let Some(n) = by_session.get_mut(&self.session) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                by_session.remove(&self.session);
            }
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A counter, updated whole: nothing half-written for a panic to leave behind.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Streams {
    pub fn new() -> Self {
        Streams {
            all: Arc::new(Semaphore::new(MAX_STREAMS)),
            by_session: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// A place for one more stream of `session`'s — its key, the hash of its secret, which
    /// unlike its ID no other session shares — or the status and reason there is none.
    pub fn take(&self, session: &str) -> Result<Slot, (StatusCode, &'static str)> {
        let mut by_session = lock(&self.by_session);
        let n = by_session.entry(session.to_string()).or_insert(0);
        if *n >= MAX_SESSION_STREAMS {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "Too many live pages open for this session; close some.",
            ));
        }
        let Ok(permit) = self.all.clone().try_acquire_owned() else {
            if *n == 0 {
                by_session.remove(session);
            }
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "Too many live pages open on this hub; try again later.",
            ));
        };
        *n += 1;
        Ok(Slot {
            _all: permit,
            by_session: self.by_session.clone(),
            session: session.to_string(),
        })
    }
}

/// How a fragment is rendered: called off the runtime, as it may read the database.
pub type Render = Arc<dyn Fn() -> anyhow::Result<String> + Send + Sync>;

/// Start a shared rendering task woken by `changes` and return its feed of framed `name`
/// events. Render only while the feed has subscribers.
pub fn feed(
    mut changes: watch::Receiver<u64>,
    name: &'static str,
    render_fn: Render,
) -> watch::Sender<Option<Bytes>> {
    let (feed, _) = watch::channel(None);
    let publish = feed.clone();
    tokio::spawn(async move {
        let mut refresh = refresh_interval();
        loop {
            tokio::select! {
                changed = changes.changed() => if changed.is_err() { return },
                _ = refresh.tick() => {}
            }
            if publish.receiver_count() == 0 {
                continue;
            }
            let f = render_fn.clone();
            // Publish even unchanged fragments: a new stream renders its first fragment
            // independently and may need this one to replace it. Each stream deduplicates
            // against its own last sent fragment.
            if let Some(html) = blocking(RENDERING, move || f()).await {
                publish.send_replace(Some(event(name, &html)));
            }
            tokio::time::sleep(DEBOUNCE).await;
        }
    });
    feed
}

const RENDERING: &str = "rendering a live update";

/// Run `f` off the runtime; on failure, log `what` and return `None`.
async fn blocking<T: Send + 'static>(
    what: &str,
    f: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
) -> Option<T> {
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(v)) => Some(v),
        Ok(Err(e)) => {
            eprintln!("vk-hub: ui: {what}: {e:#}");
            None
        }
        Err(e) => {
            eprintln!("vk-hub: ui: {what}: {e}");
            None
        }
    }
}

fn refresh_interval() -> tokio::time::Interval {
    let mut refresh = tokio::time::interval_at(tokio::time::Instant::now() + REFRESH, REFRESH);
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    refresh
}

/// What a stream follows.
pub enum Source {
    /// A fragment rendered once for everyone following it.
    Shared {
        name: &'static str,
        feed: watch::Receiver<Option<Bytes>>,
        render: Render,
    },
    /// A fragment of this page's own, rendered whenever `changes` says it may have changed.
    Own {
        name: &'static str,
        changes: watch::Receiver<u64>,
        render: Render,
    },
}

/// A stream for `auth`'s page of `source`, holding `slot` for as long as it lasts.
/// `sign_in` says how to sign in again once the session ends ([`pages::signed_out_fragment`]).
pub fn stream(
    hub: Arc<Hub>,
    auth: &Auth,
    source: Source,
    slot: Slot,
    sign_in: &'static str,
) -> Response<Body> {
    let (tx, rx) = mpsc::channel(4);
    let session = Session {
        changes: hub.subscribe_sessions(),
        hub,
        secret: auth.secret.clone(),
        expires_at: auth.session.expires_at,
        sign_in,
    };
    let give_up = GIVE_UP.try_with(Arc::clone).ok();
    debug_assert!(give_up.is_some(), "a stream outside a connection's scope");
    tokio::spawn(async move {
        let _slot = slot;
        if run(session, source, tx).await.is_err()
            && let Some(give_up) = give_up
        {
            give_up.notify_one();
        }
    });
    event_stream(Body::Stream(rx))
}

/// What a page's stream is answered with once its session has ended, its cookie still sent:
/// what an open stream ends with, so that the page stops asking rather than retry.
pub fn signed_out(name: &'static str, sign_in: &'static str) -> Response<Body> {
    let mut body = event(name, &pages::signed_out_fragment(sign_in).into_string()).to_vec();
    body.extend_from_slice(&event(CLOSE, ""));
    event_stream(Body::Full(Some(Bytes::from(body))))
}

fn event_stream(body: Body) -> Response<Body> {
    let mut resp = Response::new(body);
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    resp
}

/// The session a stream is for.
struct Session {
    hub: Arc<Hub>,
    secret: String,
    expires_at: u64,
    /// Woken when a session ends.
    changes: watch::Receiver<u64>,
    /// How to sign in again, for the page once it has ended.
    sign_in: &'static str,
}

impl Session {
    /// Check expiry every time; query the database if `recheck` is set or a session has
    /// ended since the last check. Log database failures and return `None`.
    async fn live(&mut self, recheck: bool) -> Option<bool> {
        if crate::now_secs() >= self.expires_at {
            return Some(false);
        }
        if !recheck && !self.changes.has_changed().unwrap_or(true) {
            return Some(true);
        }
        self.changes.borrow_and_update();
        let (hub, secret) = (self.hub.clone(), self.secret.clone());
        blocking("checking a live page's session", move || {
            Ok(hub.db.ui_session(&secret, crate::now_secs())?.is_some())
        })
        .await
    }
}

/// A browser that stopped reading, given up on.
struct Stalled;

/// A stream's life: its first fragment at once, then what changes, until the browser goes or
/// the session ends. Nothing is sent before the session is checked; a check that fails ends
/// the stream without the `close` event, for the page to open it again.
async fn run(mut session: Session, source: Source, tx: mpsc::Sender<Bytes>) -> Result<(), Stalled> {
    let (name, mut feed, mut own, render_fn) = match source {
        Source::Shared { name, feed, render } => (name, Some(feed), None, render),
        Source::Own {
            name,
            changes,
            render,
        } => (name, None, Some(changes), render),
    };
    let mut refresh = refresh_interval();
    let mut last_render = Instant::now();
    let mut last_sent = Instant::now();
    // Render the first fragment here: the feed may predate its current subscribers.
    if let Some(feed) = feed.as_mut() {
        feed.borrow_and_update();
    }
    let f = render_fn.clone();
    let Some(first) = blocking(RENDERING, move || f()).await else {
        return Ok(());
    };
    match session.live(false).await {
        Some(true) => {}
        Some(false) => return end(&tx, name, session.sign_in).await,
        None => return Ok(()),
    }
    let mut last_frame = event(name, &first);
    if !send(&tx, last_frame.clone()).await? {
        return Ok(());
    }
    loop {
        enum Wake {
            Feed,
            Own,
            Sessions,
            Tick,
        }
        // Sessions first: one ended is not sent another fragment, whatever else is ready.
        let wake = tokio::select! {
            biased;
            changed = session.changes.changed() => match changed {
                Ok(()) => Wake::Sessions,
                Err(_) => return Ok(()),
            },
            () = tx.closed() => return Ok(()),
            changed = changed(feed.as_mut()) => match changed {
                Ok(()) => Wake::Feed,
                Err(_) => return Ok(()),
            },
            changed = changed(own.as_mut()) => match changed {
                Ok(()) => Wake::Own,
                Err(_) => return Ok(()),
            },
            _ = refresh.tick() => Wake::Tick,
        };
        let mut frame = None;
        match wake {
            Wake::Feed => {
                frame = feed
                    .as_mut()
                    .and_then(|feed| feed.borrow_and_update().clone());
            }
            Wake::Own | Wake::Tick if own.is_some() => {
                tokio::time::sleep_until((last_render + DEBOUNCE).into()).await;
                if let Some(changes) = own.as_mut() {
                    changes.borrow_and_update();
                    last_render = Instant::now();
                    let f = render_fn.clone();
                    frame = blocking(RENDERING, move || f())
                        .await
                        .map(|html| event(name, &html));
                }
            }
            Wake::Own | Wake::Sessions | Wake::Tick => {}
        }
        match session
            .live(matches!(wake, Wake::Sessions | Wake::Tick))
            .await
        {
            Some(true) => {}
            Some(false) => return end(&tx, name, session.sign_in).await,
            None => return Ok(()),
        }
        let frame = match frame.filter(|frame| *frame != last_frame) {
            Some(frame) => {
                last_frame = frame.clone();
                Some(frame)
            }
            None if last_sent.elapsed() >= KEEP_ALIVE => Some(Bytes::from_static(COMMENT)),
            None => None,
        };
        if let Some(frame) = frame {
            if !send(&tx, frame).await? {
                return Ok(());
            }
            last_sent = Instant::now();
        }
    }
}

/// Show the session's end in the page's region, then close the stream for good.
/// Stop sending if the browser disconnects.
async fn end(
    tx: &mpsc::Sender<Bytes>,
    name: &'static str,
    sign_in: &'static str,
) -> Result<(), Stalled> {
    if send(
        tx,
        event(name, &pages::signed_out_fragment(sign_in).into_string()),
    )
    .await?
    {
        send(tx, event(CLOSE, "")).await?;
    }
    Ok(())
}

/// Wait for [`watch::Receiver::changed`], or remain pending if there is no receiver.
async fn changed<T>(rx: Option<&mut watch::Receiver<T>>) -> Result<(), watch::error::RecvError> {
    match rx {
        Some(rx) => rx.changed().await,
        None => std::future::pending().await,
    }
}

/// Send `frame`: whether the browser is still there to, or `Stalled` if it stopped reading.
async fn send(tx: &mpsc::Sender<Bytes>, frame: Bytes) -> Result<bool, Stalled> {
    match tokio::time::timeout(SEND_TIMEOUT, tx.send(frame)).await {
        Ok(Ok(())) => Ok(true),
        Ok(Err(_)) => Ok(false),
        Err(_) => Err(Stalled),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Db, Role};

    /// A hub, and a live session on it.
    fn signed_in() -> (Arc<Hub>, Auth) {
        let hub = Arc::new(Hub::new(
            Arc::new(Db::open_memory().unwrap()),
            Some("http://hub.example".into()),
        ));
        let now = crate::now_secs();
        let (token, _) = hub
            .db
            .create_login(Role::Viewer, Duration::from_secs(60), "uid 0", now)
            .unwrap();
        let (secret, session) = hub.db.redeem_login(&token, now).unwrap().unwrap();
        let auth = Auth {
            session,
            csrf: String::new(),
            secret,
        };
        (hub, auth)
    }

    /// A fragment that reads `shown`.
    fn showing(shown: &Arc<Mutex<String>>) -> Render {
        let shown = shown.clone();
        Arc::new(move || Ok(lock(&shown).clone()))
    }

    /// A new stream with a fresher initial fragment must receive the feed's next rendering,
    /// even if it matches the feed's previous value.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stream_follows_its_feed_back_to_what_it_showed_before() {
        let (hub, auth) = signed_in();
        let shown = Arc::new(Mutex::new("A".to_string()));
        let (changes, changes_rx) = watch::channel(0u64);
        let publish = feed(changes_rx, "t", showing(&shown));
        let mut published = publish.subscribe();
        changes.send_modify(|n| *n += 1);
        published.changed().await.unwrap();
        assert_eq!(*published.borrow(), Some(event("t", "A")));

        *lock(&shown) = "B".to_string();
        let source = Source::Shared {
            name: "t",
            feed: publish.subscribe(),
            render: showing(&shown),
        };
        let slot = Streams::new().take("s").unwrap();
        let mut resp = GIVE_UP
            .scope(Arc::new(Notify::new()), async {
                stream(hub, &auth, source, slot, "")
            })
            .await;
        let Body::Stream(rx) = resp.body_mut() else {
            panic!("not a stream");
        };
        assert_eq!(rx.recv().await.unwrap(), event("t", "B"));
        *lock(&shown) = "A".to_string();
        changes.send_modify(|n| *n += 1);
        let next = tokio::time::timeout(Duration::from_secs(10), rx.recv()).await;
        assert_eq!(next.unwrap().unwrap(), event("t", "A"));
    }

    /// A browser that stops reading has its connection dropped, not held.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stream_not_read_gives_up_its_connection() {
        let (hub, auth) = signed_in();
        let n = Arc::new(Mutex::new(0u64));
        // A new fragment at every refresh.
        let render: Render = Arc::new(move || {
            let mut n = lock(&n);
            *n += 1;
            Ok(n.to_string())
        });
        let source = Source::Own {
            name: "t",
            changes: hub.subscribe(),
            render,
        };
        let give_up = Arc::new(Notify::new());
        let slot = Streams::new().take("s").unwrap();
        let resp = GIVE_UP
            .scope(give_up.clone(), async {
                stream(hub, &auth, source, slot, "")
            })
            .await;
        tokio::time::timeout(Duration::from_secs(30), give_up.notified())
            .await
            .unwrap();
        drop(resp);
    }

    #[test]
    fn an_event_is_framed_so_its_data_cannot_break_out() {
        assert_eq!(
            event("nodes", "<table>"),
            Bytes::from_static(b"event: nodes\ndata: <table>\n\n")
        );
        // A blank line in the data would end the event; each break is its own data line.
        assert_eq!(
            event("node", "a\n\nevent: evil\r\nb\rc"),
            Bytes::from_static(
                b"event: node\ndata: a\ndata: \ndata: event: evil\ndata: b\ndata: c\n\n"
            )
        );
    }
}
