//! Session transport: dial, upgrade, and hello → challenge → auth → welcome before each
//! peer exchanges its own messages.

use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
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
    let (io, exported, authority) = dial(hub, tls).await?;
    let scheme = if exported.is_some() { "wss" } else { "ws" };
    let config = WebSocketConfig::default()
        .max_message_size(Some(vk_hub_proto::MAX_MESSAGE))
        .max_frame_size(Some(vk_hub_proto::MAX_MESSAGE));
    let ws_url = format!("{scheme}://{authority}{path}");
    let (ws, _) = tokio_tungstenite::client_async_with_config(ws_url, io, Some(config))
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

/// A connection to the hub's listener: TCP, and TLS for an `https` hub. Returns it
/// with the TLS keying material a signature on it is bound to — `None` on plain TCP — and
/// the `host:port` it reached.
pub async fn dial(
    hub: &str,
    tls: &Arc<rustls::ClientConfig>,
) -> Result<(Box<dyn Io>, Option<[u8; TLS_EXPORTER_LEN]>, String)> {
    let url = reqwest::Url::parse(hub).with_context(|| format!("parsing the hub URL {hub:?}"))?;
    // Bracketed for an IPv6 literal, which is the form both the socket address and the
    // WebSocket URL want.
    let host = url.host_str().context("the hub URL has no host")?;
    let port = url
        .port_or_known_default()
        .context("the hub URL has no port")?;
    let authority = format!("{host}:{port}");
    let tcp = tokio::net::TcpStream::connect(&authority)
        .await
        .with_context(|| format!("connecting to {authority}"))?;
    // Heartbeats are small and latency is what a session is judged on.
    tcp.set_nodelay(true).context("setting TCP_NODELAY")?;
    keepalive(&tcp).context("setting TCP keepalives")?;
    let (io, exported): (Box<dyn Io>, _) = match url.scheme() {
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
            (Box::new(stream), Some(exported))
        }
        "http" => (Box::new(tcp), None),
        other => bail!("the hub URL has scheme {other:?}; expected https (or http on loopback)"),
    };
    Ok((io, exported, authority))
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
    }
}
