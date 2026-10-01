//! What the hub's listeners share: its state, and the accept loop that holds every connection
//! to a bounded count — the shape of `vk-registry`'s server.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};

use crate::store::Db;

/// Accept backlog.
const LISTEN_BACKLOG: u32 = 1024;

/// How long a client has for each step before it has authenticated: its request headers, a
/// form's body. A browser needs milliseconds for any of them; a peer that holds a connection
/// open without finishing one is only holding it.
pub const PRE_AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// What every connection shares.
pub struct Hub {
    pub db: Arc<Db>,
    /// The web UI's origin, which its sign-in links start with.
    pub ui_url: String,
    /// Bumped whenever anything a page shows may have changed, for its live updates.
    changes: watch::Sender<u64>,
    /// Bumped when a web UI session ends.
    sessions: watch::Sender<u64>,
}

impl Hub {
    /// The hub keeping its state in `db`, with its web UI at `ui_url`.
    pub fn new(db: Arc<Db>, ui_url: String) -> Self {
        Hub {
            db,
            ui_url,
            changes: watch::Sender::new(0),
            sessions: watch::Sender::new(0),
        }
    }

    /// Note that something a page shows may have changed.
    pub(crate) fn touch(&self) {
        self.changes.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// Wake on the next [`Hub::touch`].
    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// Note that a web UI session ended.
    pub(crate) fn sessions_changed(&self) {
        self.sessions.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// Wake on the next [`Hub::sessions_changed`].
    pub(crate) fn subscribe_sessions(&self) -> watch::Receiver<u64> {
        self.sessions.subscribe()
    }
}

/// Bind `addr` with [`LISTEN_BACKLOG`].
pub fn listen(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(LISTEN_BACKLOG)
}

/// A connection's byte stream, as one type, so one accept loop serves every listener.
pub(crate) trait Stream:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send
{
}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Stream for T {}
pub(crate) type Io = TokioIo<Box<dyn Stream>>;

/// Accept on `listener` until the process ends and pass each connection to `conn`, holding
/// a permit for its lifetime. Close excess connections immediately.
pub(crate) async fn accept<F, Fut>(
    listener: TcpListener,
    permits: Arc<Semaphore>,
    conn: F,
) -> Result<()>
where
    F: Fn(Io, SocketAddr) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let conn = Arc::new(conn);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                // EMFILE and friends persist; a bare retry would spin.
                eprintln!("vk-hub: accept error: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        // Queuing excess connections would still consume resources.
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let conn = conn.clone();
        tokio::spawn(async move {
            let io: Box<dyn Stream> = Box::new(stream);
            conn(TokioIo::new(io), peer).await;
            drop(permit);
        });
    }
}
