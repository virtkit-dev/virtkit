//! Live updates: a page's fragment re-rendered and pushed as a server-sent event whenever
//! what it shows may have changed, for htmx's SSE extension to swap in.
//!
//! A fragment that is the same for every viewer — the nodes table, local mode's VMs — is
//! rendered once per change, by one task, and each page's stream only forwards it
//! ([`Source::Shared`]). A page of one thing — a node, a VM — renders its own fragment, woken
//! only by the changes it follows ([`Source::Own`]). Either way a fragment is rendered at most
//! once per [`DEBOUNCE`] however fast what it shows changes, and sent only when it differs
//! from the last one; ages on the pages move in steps of a heartbeat, so a fleet with nothing
//! new to show sends nothing but keep-alives.
//!
//! Streams hold connections, so there are at most [`MAX_STREAMS`] of them — the rest of the
//! listener's connections stay for pages and posts — and [`MAX_SESSION_STREAMS`] per session.
//! One past either is answered 429 or 503, and htmx's SSE extension retries it with its own
//! backoff, doubling from half a second to a minute. A stream whose session ends sends a
//! fragment saying so and the `close` event the pages name in `sse-close`, on which the
//! extension closes its connection for good.

use std::collections::HashMap;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use hyper::body::{Frame, SizeHint};
use hyper::header::{self, HeaderValue};
use hyper::{Response, StatusCode};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};

use super::{Auth, pages};
use crate::server::{HEARTBEAT, Hub};

/// The fewest seconds between two renders of one stream: a fleet's heartbeats arrive every
/// few seconds from every node, and a page need not follow each one.
const DEBOUNCE: Duration = Duration::from_secs(1);

/// How often a fragment is rendered with no change noted, for what moves on its own: ages,
/// and a node that goes quiet becomes unreachable without a message saying so. Also how
/// soon a stream notices its session has expired.
const REFRESH: Duration = HEARTBEAT;

/// Streams at once, of the listener's 128 connections.
#[cfg(not(test))]
pub const MAX_STREAMS: usize = 96;
#[cfg(test)]
pub const MAX_STREAMS: usize = 8;

/// Streams at once for one session: a few tabs.
pub const MAX_SESSION_STREAMS: usize = 6;

/// A comment sent after this long with no event, so a proxy or the browser does not take a
/// quiet stream for a dead one.
const KEEP_ALIVE: Duration = Duration::from_secs(15);

/// How long a stream waits on a browser not reading before it gives up on it.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// Every UI response's body: whole, or a stream of events.
pub enum Body {
    Full(Option<Bytes>),
    Stream(mpsc::Receiver<Bytes>),
}

impl Default for Body {
    fn default() -> Self {
        Body::Full(None)
    }
}

impl From<String> for Body {
    fn from(s: String) -> Self {
        Body::Full(Some(Bytes::from(s)))
    }
}

impl From<&'static [u8]> for Body {
    fn from(b: &'static [u8]) -> Self {
        Body::Full(Some(Bytes::from_static(b)))
    }
}

impl hyper::body::Body for Body {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        match self.get_mut() {
            Body::Full(bytes) => Poll::Ready(bytes.take().map(|b| Ok(Frame::data(b)))),
            Body::Stream(rx) => rx.poll_recv(cx).map(|b| b.map(|b| Ok(Frame::data(b)))),
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self, Body::Full(None))
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Body::Full(None) => SizeHint::with_exact(0),
            Body::Full(Some(b)) => SizeHint::with_exact(b.len() as u64),
            Body::Stream(_) => SizeHint::default(),
        }
    }
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

    /// A place for one more stream of `session`'s, or the status and reason there is none.
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

/// Start the task that renders `render_fn`'s fragment for every stream following it, woken by
/// `changes`, and return where it publishes each new rendering, as a framed `name` event. It
/// renders only while someone follows it.
pub fn feed(
    mut changes: watch::Receiver<u64>,
    name: &'static str,
    render_fn: Render,
) -> watch::Sender<Option<Bytes>> {
    let (feed, _) = watch::channel(None);
    let publish = feed.clone();
    tokio::spawn(async move {
        let mut refresh = refresh_interval();
        let mut last: Option<String> = None;
        loop {
            tokio::select! {
                changed = changes.changed() => if changed.is_err() { return },
                _ = refresh.tick() => {}
            }
            if publish.receiver_count() == 0 {
                last = None;
                continue;
            }
            changes.borrow_and_update();
            let rendered = render(render_fn.clone()).await;
            if let Some(html) = rendered
                && last.as_deref() != Some(html.as_str())
            {
                publish.send_replace(Some(event(name, &html)));
                last = Some(html);
            }
            tokio::time::sleep(DEBOUNCE).await;
        }
    });
    feed
}

/// Run `f` off the runtime; `None`, logged, if it failed.
async fn render(f: Render) -> Option<String> {
    blocking(move || f()).await
}

/// Run `f` off the runtime; `None`, logged, if it failed.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
) -> Option<T> {
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(v)) => Some(v),
        Ok(Err(e)) => {
            eprintln!("vk-hub: ui: rendering a live update: {e:#}");
            None
        }
        Err(e) => {
            eprintln!("vk-hub: ui: rendering a live update: {e}");
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
pub fn stream(hub: Arc<Hub>, auth: &Auth, source: Source, slot: Slot) -> Response<Body> {
    let (tx, rx) = mpsc::channel(4);
    let secret = auth.secret.clone();
    tokio::spawn(async move {
        let _slot = slot;
        run(hub, secret, source, tx).await;
    });
    let mut resp = Response::new(Body::Stream(rx));
    *resp.status_mut() = StatusCode::OK;
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    // A buffering reverse proxy would hold events back until the stream ends.
    h.insert("x-accel-buffering", HeaderValue::from_static("no"));
    resp
}

/// A stream's life: its first fragment at once, then what changes, until the browser goes or
/// the session ends.
async fn run(hub: Arc<Hub>, secret: String, source: Source, tx: mpsc::Sender<Bytes>) {
    let (name, mut feed, mut own, render_fn) = match source {
        Source::Shared { name, feed, render } => (name, Some(feed), None, render),
        Source::Own {
            name,
            changes,
            render,
        } => (name, None, Some(changes), render),
    };
    let mut sessions = hub.subscribe_sessions();
    let mut refresh = refresh_interval();
    let mut last_render = Instant::now();
    let mut last_sent = Instant::now();
    // Rendered here once rather than taken from the feed, which may be from before anyone
    // followed it.
    if let Some(feed) = feed.as_mut() {
        feed.borrow_and_update();
    }
    let Some(first) = render(render_fn.clone()).await else {
        return;
    };
    if !send(&tx, event(name, &first)).await {
        return;
    }
    let mut last = Some(first);
    loop {
        enum Wake {
            Feed,
            Own,
            Sessions,
            Tick,
        }
        let wake = tokio::select! {
            () = tx.closed() => return,
            changed = changed(feed.as_mut()) => match changed { Ok(()) => Wake::Feed, Err(_) => return },
            changed = changed(own.as_mut()) => match changed {
                Ok(()) => Wake::Own,
                Err(_) => return,
            },
            changed = sessions.changed() => match changed { Ok(()) => Wake::Sessions, Err(_) => return },
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
                if matches!(wake, Wake::Own) {
                    tokio::time::sleep_until((last_render + DEBOUNCE).into()).await;
                }
                if let Some(changes) = own.as_mut() {
                    changes.borrow_and_update();
                    last_render = Instant::now();
                    if let Some(html) = render(render_fn.clone()).await
                        && last.as_deref() != Some(html.as_str())
                    {
                        frame = Some(event(name, &html));
                        last = Some(html);
                    }
                }
            }
            Wake::Own | Wake::Sessions | Wake::Tick => {}
        }
        if matches!(wake, Wake::Sessions | Wake::Tick) {
            let (hub, secret) = (hub.clone(), secret.clone());
            let live =
                blocking(move || Ok(hub.db.ui_session(&secret, crate::now_secs())?.is_some()))
                    .await;
            if live != Some(true) {
                // Said in the page's own region, then closed for good.
                let _ = send(
                    &tx,
                    event(name, &pages::signed_out_fragment().into_string()),
                )
                .await;
                let _ = send(&tx, event(CLOSE, "")).await;
                return;
            }
        }
        let frame = match frame {
            Some(frame) => Some(frame),
            None if last_sent.elapsed() >= KEEP_ALIVE => Some(Bytes::from_static(COMMENT)),
            None => None,
        };
        if let Some(frame) = frame {
            if !send(&tx, frame).await {
                return;
            }
            last_sent = Instant::now();
        }
    }
}

/// [`watch::Receiver::changed`] on a receiver there may not be; never, without one.
async fn changed<T>(rx: Option<&mut watch::Receiver<T>>) -> Result<(), watch::error::RecvError> {
    match rx {
        Some(rx) => rx.changed().await,
        None => std::future::pending().await,
    }
}

/// Send `frame`, unless the browser has gone or stopped reading.
async fn send(tx: &mpsc::Sender<Bytes>, frame: Bytes) -> bool {
    matches!(
        tokio::time::timeout(SEND_TIMEOUT, tx.send(frame)).await,
        Ok(Ok(()))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
