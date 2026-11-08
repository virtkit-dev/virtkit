//! Session transport: dial, upgrade, and hello → challenge → auth → welcome before each
//! peer exchanges its own messages.

use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use futures::{SinkExt, StreamExt};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use vk_hub_proto::gitlab;
use vk_hub_proto::{Channel, HubMsg, NodeMsg, TLS_EXPORTER_LEN, VersionRange};

use crate::identity::Identity;

/// The bound on TCP data the hub has not acknowledged, and the idle time before keepalives. At
/// the hub's 5s heartbeat both fall well inside the silence that ends a session, so the socket
/// fails first and says why.
const TCP_USER_TIMEOUT: Duration = Duration::from_secs(30);
const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(10);

/// The transport under the WebSocket: TCP, or TLS over it.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// The session's WebSocket.
pub type Ws = WebSocketStream<Box<dyn Io>>;

/// A refusal no redial can fix: the peer's enrollment is gone or not its own.
#[derive(Debug)]
pub struct Permanent(pub String);

impl std::fmt::Display for Permanent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Permanent {}

/// A newer session of this peer took over at the hub.
#[derive(Debug)]
pub struct Superseded(pub String);

impl std::fmt::Display for Superseded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Superseded {}

/// Dial the hub's session endpoint `path`: TCP, TLS for an `https` hub, then the WebSocket
/// upgrade. Returns the TLS keying material the auth is bound to, `None` on plain TCP.
pub async fn connect(
    hub: &str,
    tls: &Arc<rustls::ClientConfig>,
    path: &str,
) -> Result<(Ws, Option<[u8; TLS_EXPORTER_LEN]>)> {
    let Dialed {
        io,
        exported,
        authority,
        h2,
    } = dial(hub, tls).await?;
    if h2 {
        bail!("a session needs HTTP/1.1, and TLS negotiated HTTP/2");
    }
    let scheme = if exported.is_some() { "wss" } else { "ws" };
    let ws_url = format!("{scheme}://{authority}{path}");
    let (ws, _) = tokio_tungstenite::client_async_with_config(ws_url, io, Some(ws_config()))
        .await
        .map_err(|e| match e {
            // The hub's bound on handshakes in flight: transient by design.
            tokio_tungstenite::tungstenite::Error::Http(resp)
                if resp.status()
                    == tokio_tungstenite::tungstenite::http::StatusCode::SERVICE_UNAVAILABLE =>
            {
                anyhow!("{hub} is busy with other peers' handshakes (HTTP 503)")
            }
            e => anyhow!("opening the WebSocket to {hub}: {e}"),
        })?;
    Ok((ws, exported))
}

/// A session's WebSocket bounds: messages and frames of at most [`vk_hub_proto::MAX_MESSAGE`].
fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(vk_hub_proto::MAX_MESSAGE))
        .max_frame_size(Some(vk_hub_proto::MAX_MESSAGE))
}

/// A hub that cannot carry a relay's connection: it negotiated HTTP/1.1, or its HTTP/2 does
/// not take a WebSocket over CONNECT. Only an upgrade of the hub fixes it.
#[derive(Debug)]
pub struct Outdated(pub String);

impl std::fmt::Display for Outdated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Outdated {}

/// A relay's one connection to the hub: its session's WebSocket and the sender of its requests,
/// both on the same HTTP/2 connection, which a task of its own drives until it closes.
pub struct RelayConnection<B> {
    pub ws: Ws,
    /// Requests on the connection, served as the relay's once its session's handshake passed.
    pub sender: http2::SendRequest<B>,
    /// The TLS keying material the session's auth is bound to; `None` on plain TCP.
    pub exported: Option<[u8; TLS_EXPORTER_LEN]>,
    /// The `host:port` it reached, which a request's URI names.
    pub authority: String,
}

/// Dial the hub as a relay: TLS offering [`vk_hub_proto::gitlab::ALPN`] (or HTTP/2 with prior
/// knowledge on plain TCP), HTTP/2 through `h2`, and the session at `path` opened as a WebSocket
/// over the extended CONNECT (RFC 8441). A hub that answers HTTP/1.1, or whose HTTP/2 does
/// not enable the extended CONNECT, is [`Outdated`]. Nothing here is bounded in time: the
/// caller bounds the whole.
pub async fn connect_relay<B>(
    hub: &str,
    tls: &Arc<rustls::ClientConfig>,
    h2: &http2::Builder<TokioExecutor>,
    path: &str,
) -> Result<RelayConnection<B>>
where
    B: hyper::body::Body + Default + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let mut offer = (**tls).clone();
    offer.alpn_protocols = vec![gitlab::ALPN.to_vec(), b"http/1.1".to_vec()];
    let Dialed {
        io,
        exported,
        authority,
        h2: negotiated,
    } = dial(hub, &Arc::new(offer)).await?;
    if exported.is_some() && !negotiated {
        return Err(anyhow::Error::new(Outdated(format!(
            "{hub} speaks only HTTP/1.1 to relays: it needs an upgrade"
        ))));
    }
    // A plain WebSocket's CONNECT names `http` (RFC 8441, section 5).
    let scheme = if exported.is_some() { "https" } else { "http" };
    let (mut sender, mut conn) = h2
        .handshake::<_, B>(TokioIo::new(io))
        .await
        .map_err(|e| anyhow!("opening HTTP/2 to {hub}: {e}"))?;
    let mut req = hyper::Request::builder()
        .method(hyper::Method::CONNECT)
        .uri(format!("{scheme}://{authority}{path}"))
        .header(hyper::header::SEC_WEBSOCKET_VERSION, "13")
        .body(B::default())
        .context("building the session's CONNECT")?;
    req.extensions_mut()
        .insert(hyper::ext::Protocol::from_static("websocket"));
    // Drive the connection until the CONNECT is answered: the hub's SETTINGS, sent before any
    // answer, are read off it.
    let answered = tokio::select! {
        ended = &mut conn => {
            bail!("{hub} closed the connection before answering the session: {}", match ended {
                Ok(()) => "no error".to_string(),
                Err(e) => e.to_string(),
            })
        }
        answered = sender.send_request(req) => answered,
    };
    // A refused stream on a live connection whose SETTINGS lack the extended CONNECT is the
    // hub's answer; a connection that failed is not.
    let alive = futures::poll!(&mut conn).is_pending();
    if !conn.is_extended_connect_protocol_enabled() && (answered.is_ok() || alive) {
        return Err(anyhow::Error::new(Outdated(format!(
            "{hub} does not take a relay's session over HTTP/2: it needs an upgrade"
        ))));
    }
    let resp = answered.map_err(|e| anyhow!("opening the session with {hub}: {e}"))?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            log::debug!("The connection to the hub ended: {e}");
        }
    });
    match resp.status() {
        hyper::StatusCode::OK => {}
        // The hub's bound on handshakes in flight: transient by design.
        hyper::StatusCode::SERVICE_UNAVAILABLE => {
            bail!("{hub} is busy with other peers' handshakes (HTTP 503)")
        }
        status => bail!("{hub} refused the session's CONNECT with {status}"),
    }
    let upgraded = hyper::upgrade::on(resp)
        .await
        .map_err(|e| anyhow!("opening the session with {hub}: {e}"))?;
    let io: Box<dyn Io> = Box::new(TokioIo::new(upgraded));
    let ws = WebSocketStream::from_raw_socket(io, Role::Client, Some(ws_config())).await;
    Ok(RelayConnection {
        ws,
        sender,
        exported,
        authority,
    })
}

/// A connection [`dial`] made.
pub struct Dialed {
    /// TCP, wrapped in TLS for an `https` hub.
    pub io: Box<dyn Io>,
    /// TLS keying material binding the signature to this connection; `None` on plain TCP.
    pub exported: Option<[u8; TLS_EXPORTER_LEN]>,
    /// The `host:port` it reached.
    pub authority: String,
    /// Whether TLS negotiated HTTP/2: `h2`, or a relay's [`gitlab::ALPN`], when `tls` offers
    /// it.
    pub h2: bool,
}

/// A connection to the hub's listener: TCP, and TLS for an `https` hub.
pub async fn dial(hub: &str, tls: &Arc<rustls::ClientConfig>) -> Result<Dialed> {
    let url = reqwest::Url::parse(hub).with_context(|| format!("parsing the hub URL {hub:?}"))?;
    // Bracketed for an IPv6 literal, which is the form both the socket address and the
    // WebSocket URL want.
    let host = url.host_str().context("the hub URL has no host")?;
    let port = url
        .port_or_known_default()
        .context("the hub URL has no port")?;
    let authority = format!("{host}:{port}");
    let addrs = ADDRS
        .resolve(&authority, Instant::now(), |a| async move {
            tokio::net::lookup_host(a)
                .await
                .map(|addrs| addrs.collect())
        })
        .await
        .with_context(|| format!("resolving {authority}"))?;
    let tcp = connect_any(&addrs)
        .await
        .with_context(|| format!("connecting to {authority}"))?;
    // Heartbeats are small and latency is what a session is judged on.
    tcp.set_nodelay(true).context("setting TCP_NODELAY")?;
    keepalive(&tcp).context("setting TCP keepalives")?;
    let (io, exported, h2): (Box<dyn Io>, _, _) = match url.scheme() {
        "https" => {
            // An IP literal is verified against the certificate's IP addresses, a name
            // against its DNS names.
            let bare = host.trim_start_matches('[').trim_end_matches(']');
            let name = match bare.parse::<std::net::IpAddr>() {
                Ok(ip) => ip.into(),
                Err(_) => rustls::pki_types::ServerName::try_from(bare.to_string())
                    .with_context(|| format!("{bare:?} is not a valid TLS server name"))?,
            };
            let stream = tokio_rustls::TlsConnector::from(tls.clone())
                .connect(name, tcp)
                .await
                .with_context(|| format!("TLS handshake with {authority}"))?;
            let mut exported = [0u8; TLS_EXPORTER_LEN];
            stream
                .get_ref()
                .1
                .export_keying_material(&mut exported, vk_hub_proto::TLS_EXPORTER_LABEL, None)
                .context("exporting TLS keying material")?;
            let h2 = matches!(
                stream.get_ref().1.alpn_protocol(),
                Some(b"h2" | gitlab::ALPN)
            );
            (Box::new(stream), Some(exported), h2)
        }
        "http" => (Box::new(tcp), None, false),
        other => bail!("the hub URL has scheme {other:?}; expected https (or http on loopback)"),
    };
    Ok(Dialed {
        io,
        exported,
        authority,
        h2,
    })
}

/// How long a hub's resolved addresses are used before it is looked up again.
const RESOLVE_TTL: Duration = Duration::from_secs(60);

/// The addresses each hub authority resolved to, shared by every dial in the process.
static ADDRS: AddrCache = AddrCache::new(RESOLVE_TTL);

/// Resolved addresses per `host:port`, used for a TTL and kept past it for when the resolver
/// fails: a peer dialing the hub several times a second stays off DNS, and one whose resolver
/// stalls keeps reaching the hub at its last known addresses.
struct AddrCache {
    ttl: Duration,
    entries: std::sync::Mutex<std::collections::BTreeMap<String, Resolved>>,
}

struct Resolved {
    addrs: Vec<SocketAddr>,
    at: Instant,
    /// Whether the fallback to these addresses was logged since the last good lookup.
    warned: bool,
}

impl AddrCache {
    const fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    fn entries(&self) -> std::sync::MutexGuard<'_, std::collections::BTreeMap<String, Resolved>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// `authority`'s addresses: cached ones younger than the TTL, else what `lookup` finds,
    /// else, when it fails or finds none, the last ones it found.
    async fn resolve<F, Fut>(
        &self,
        authority: &str,
        now: Instant,
        lookup: F,
    ) -> std::io::Result<Vec<SocketAddr>>
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = std::io::Result<Vec<SocketAddr>>>,
    {
        if let Some(r) = self.entries().get(authority)
            && now.saturating_duration_since(r.at) < self.ttl
        {
            return Ok(r.addrs.clone());
        }
        let found = match lookup(authority.to_string()).await {
            Ok(addrs) if addrs.is_empty() => Err(std::io::Error::other("no addresses")),
            found => found,
        };
        let mut entries = self.entries();
        match found {
            Ok(addrs) => {
                entries.insert(
                    authority.to_string(),
                    Resolved {
                        addrs: addrs.clone(),
                        at: now,
                        warned: false,
                    },
                );
                Ok(addrs)
            }
            Err(e) => match entries.get_mut(authority) {
                Some(last) => {
                    if !last.warned {
                        last.warned = true;
                        log::warn!(
                            "Resolving {authority} failed ({e}); using its last known addresses"
                        );
                    }
                    Ok(last.addrs.clone())
                }
                None => Err(e),
            },
        }
    }
}

/// A TCP connection to the first of `addrs` that takes one, in order.
async fn connect_any(addrs: &[SocketAddr]) -> std::io::Result<tokio::net::TcpStream> {
    let mut last = None;
    for addr in addrs {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(tcp) => return Ok(tcp),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("no addresses")))
}

/// Keepalives on an idle socket and a bound on unacknowledged data on a busy one, so a hub
/// that disappeared behind a dead route is noticed by the kernel too.
fn keepalive(tcp: &tokio::net::TcpStream) -> std::io::Result<()> {
    let fd = tcp.as_raw_fd();
    let secs = |d: Duration| libc::c_int::try_from(d.as_secs()).unwrap_or(libc::c_int::MAX);
    let millis = libc::c_int::try_from(TCP_USER_TIMEOUT.as_millis()).unwrap_or(libc::c_int::MAX);
    for (level, name, value) in [
        (libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1),
        (
            libc::IPPROTO_TCP,
            libc::TCP_KEEPIDLE,
            secs(TCP_KEEPALIVE_IDLE),
        ),
        (
            libc::IPPROTO_TCP,
            libc::TCP_KEEPINTVL,
            secs(TCP_KEEPALIVE_IDLE),
        ),
        (libc::IPPROTO_TCP, libc::TCP_KEEPCNT, 2),
        (libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT, millis),
    ] {
        // SAFETY: `fd` is the live socket `tcp` owns; the option value is a c_int that outlives
        // the call, and its size is passed with it.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                (&raw const value).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Send `msg` as one text frame, within `within`.
pub async fn send(ws: &mut Ws, msg: &impl serde::Serialize, within: Duration) -> Result<()> {
    let text = serde_json::to_string(msg).context("encoding a message")?;
    tokio::time::timeout(within, ws.send(Message::text(text)))
        .await
        .map_err(|_| anyhow!("the hub has not taken a message for {}s", within.as_secs()))?
        .map_err(|e| anyhow!("sending to the hub: {e}"))
}

/// The next text frame, within `within`; pings and pongs are skipped.
pub async fn receive_text(ws: &mut Ws, within: Duration) -> Result<String> {
    tokio::time::timeout(within, async {
        loop {
            match ws.next().await {
                None => bail!("the hub closed the connection"),
                Some(Err(e)) => bail!("reading from the hub: {e}"),
                Some(Ok(Message::Text(text))) => return Ok(text.as_str().to_string()),
                Some(Ok(Message::Close(_))) => bail!("the hub closed the session"),
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .map_err(|_| anyhow!("the hub sent nothing for {within:?}"))?
}

/// A message from the hub, its parse error cut to what is safe to print.
pub fn parse<M: serde::de::DeserializeOwned>(text: &str) -> Result<M> {
    serde_json::from_str(text).map_err(|e| {
        anyhow!(
            "the hub sent a message this peer does not understand: {}",
            vk_hub_proto::display_safe(&e.to_string())
        )
    })
}

/// Who a peer says it is when it opens a session.
pub struct Hello<'a> {
    /// The protocol versions it speaks.
    pub versions: VersionRange,
    /// The ID the hub assigned it at enrollment, and its key.
    pub id: &'a str,
    pub identity: &'a Identity,
    /// Drawn afresh each time the peer's process starts.
    pub incarnation: &'a str,
    /// The peer program's own version.
    pub version: &'a str,
}

/// Hello → challenge → auth → welcome, each step within `within`. Returns the heartbeat
/// interval the hub asked for, in seconds, and the protocol version of the session. A
/// refusal becomes the error `refused` makes of it.
pub async fn handshake(
    ws: &mut Ws,
    hello: &Hello<'_>,
    exported: Option<&[u8; TLS_EXPORTER_LEN]>,
    within: Duration,
    refused: impl Fn(vk_hub_proto::RefusalCode, &str) -> anyhow::Error,
) -> Result<(u32, u32)> {
    send(
        ws,
        &NodeMsg::Hello {
            versions: hello.versions,
            node_id: hello.id.to_string(),
            incarnation: hello.incarnation.to_string(),
            vk_version: hello.version.to_string(),
        },
        within,
    )
    .await?;
    let (version, hub_versions, nonce) = match parse(&receive_text(ws, within).await?)? {
        HubMsg::Challenge {
            version,
            versions,
            nonce,
        } => {
            // The highest version both sides speak, and nothing else: a hub — or something
            // between the two — picking a lower one is refused, not followed.
            if !hello.versions.accepts_pick(versions, version) {
                bail!(
                    "the hub chose protocol version {version} of {}–{}, not the highest this peer \
                     ({}–{}) shares with it",
                    versions.min,
                    versions.max,
                    hello.versions.min,
                    hello.versions.max
                );
            }
            let nonce = vk_hub_proto::from_hex_lower::<{ vk_hub_proto::CHALLENGE_LEN }>(&nonce)
                .context("the hub's challenge is malformed")?;
            (version, versions, nonce)
        }
        HubMsg::Refused { code, reason } => return Err(refused(code, &reason)),
        other => bail!("the hub answered the hello with {}", kind(&other)),
    };
    let channel = match exported {
        Some(exported) => Channel::Tls(exported),
        None => Channel::Plaintext,
    };
    let signature = hello.identity.sign(&vk_hub_proto::auth_message(
        &nonce,
        hello.id,
        hello.incarnation,
        hello.versions,
        hub_versions,
        version,
        channel,
    ));
    send(ws, &NodeMsg::Auth { signature }, within).await?;
    match parse(&receive_text(ws, within).await?)? {
        HubMsg::Welcome { heartbeat_secs } => Ok((heartbeat_secs, version)),
        HubMsg::Refused { code, reason } => Err(refused(code, &reason)),
        other => bail!("the hub answered the auth with {}", kind(&other)),
    }
}

/// A hub message by kind, for an error that names one out of place.
pub fn kind(msg: &HubMsg) -> &'static str {
    match msg {
        HubMsg::Challenge { .. } => "a challenge",
        HubMsg::Welcome { .. } => "a welcome",
        HubMsg::Refused { .. } => "a refusal",
        HubMsg::Desired(_) => "desired state",
        HubMsg::Command(_) => "a command",
        HubMsg::Recorded(_) => "a record of an ack",
        HubMsg::Job(_) => "a job message",
        HubMsg::RegistryAccess { .. } => "registry access",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn addr(last: u8) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, last], 443))
    }

    /// A lookup that counts its calls and answers `answer`.
    fn lookup(
        calls: &AtomicUsize,
        answer: std::io::Result<Vec<SocketAddr>>,
    ) -> impl FnOnce(String) -> std::future::Ready<std::io::Result<Vec<SocketAddr>>> + '_ {
        move |authority| {
            assert_eq!(authority, "hub:443");
            calls.fetch_add(1, Ordering::Relaxed);
            std::future::ready(answer)
        }
    }

    #[tokio::test]
    async fn addresses_are_reused_within_the_ttl_and_looked_up_again_after() {
        let cache = AddrCache::new(Duration::from_secs(60));
        let calls = AtomicUsize::new(0);
        let t0 = Instant::now();
        let first = cache
            .resolve("hub:443", t0, lookup(&calls, Ok(vec![addr(1)])))
            .await
            .unwrap();
        assert_eq!(first, vec![addr(1)]);
        let cached = cache
            .resolve(
                "hub:443",
                t0 + Duration::from_secs(59),
                lookup(&calls, Ok(vec![addr(2)])),
            )
            .await
            .unwrap();
        assert_eq!((cached, calls.load(Ordering::Relaxed)), (vec![addr(1)], 1));
        let renewed = cache
            .resolve(
                "hub:443",
                t0 + Duration::from_secs(60),
                lookup(&calls, Ok(vec![addr(2)])),
            )
            .await
            .unwrap();
        assert_eq!((renewed, calls.load(Ordering::Relaxed)), (vec![addr(2)], 2));
    }

    #[tokio::test]
    async fn a_failed_lookup_falls_back_to_the_last_good_addresses() {
        let cache = AddrCache::new(Duration::from_secs(60));
        let calls = AtomicUsize::new(0);
        let t0 = Instant::now();
        let stall = || {
            Err(std::io::Error::other(
                "Temporary failure in name resolution",
            ))
        };
        // Nothing to fall back to yet.
        assert!(
            cache
                .resolve("hub:443", t0, lookup(&calls, stall()))
                .await
                .is_err()
        );
        cache
            .resolve("hub:443", t0, lookup(&calls, Ok(vec![addr(1)])))
            .await
            .unwrap();
        let later = t0 + Duration::from_secs(120);
        for answer in [stall(), Ok(vec![])] {
            let fallback = cache
                .resolve("hub:443", later, lookup(&calls, answer))
                .await
                .unwrap();
            assert_eq!(fallback, vec![addr(1)]);
        }
        // Looked up on each try past the TTL, and taken as soon as it answers.
        let back = cache
            .resolve("hub:443", later, lookup(&calls, Ok(vec![addr(3)])))
            .await
            .unwrap();
        assert_eq!((back, calls.load(Ordering::Relaxed)), (vec![addr(3)], 5));
        assert!(!cache.entries()["hub:443"].warned);
    }
}
