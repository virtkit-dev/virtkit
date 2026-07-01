//! Generic byte forwarder.
//!
//! Accepts on a local listener and splices each connection to a target. The
//! payload is opaque (no virtkit-agent framing), so the same primitive serves both
//! ends of a host-mediated tunnel:
//!   - guest side: a guest-local TCP port -> the host over vsock
//!     (`forward --listen tcp://127.0.0.1:5000  --socket vsock://5000`)
//!   - host side:  the VMM's per-port unix socket -> an upstream TCP service
//!     (`forward --listen <vsock.sock>_5000      --socket tcp://127.0.0.1:<port>`)
//!
//! Pairing the two lets the host inject credentials at its edge (e.g. a registry
//! pull-through proxy), so the secret never crosses into the guest or the job.

use anyhow::{Context, Result};
use log::{debug, info, warn};

use crate::addr::SocketAddr;
use crate::net::{raw_connect, raw_listen};

/// Splice this process's stdin/stdout to `target`, returning once either side
/// closes. The stdio analogue of [`run_forward`]: the same opaque-bytes splice,
/// but the local end is the process's own stdin/stdout instead of a listener —
/// the shape an SSH `ProxyCommand` needs. ssh hands us its protocol stream on
/// stdio and we relay it to `target` (e.g. the guest sshd reached over the
/// hybrid vsock-mux), so VS Code Remote-SSH attaches to the microVM with no
/// guest network. Nothing may log to stdout while this runs — it is the SSH byte
/// stream.
pub async fn run_connect(target: &SocketAddr) -> Result<()> {
    let mut conn = raw_connect(target)
        .await
        .with_context(|| format!("connect: dialing {target}"))?;
    // stdin (read half) + stdout (write half) presented as one duplex stream.
    let mut stdio = tokio::io::join(tokio::io::stdin(), tokio::io::stdout());
    let (up, down) = tokio::io::copy_bidirectional(&mut stdio, &mut conn).await?;
    debug!("connect: closed ({up} up, {down} down)");
    Ok(())
}

/// Accept on `local` and splice every connection to `target` until cancelled.
/// Per-connection errors are logged and do not stop the listener.
pub async fn run_forward(local: &SocketAddr, target: &SocketAddr) -> Result<()> {
    let listener = raw_listen(local)
        .await
        .with_context(|| format!("forward: binding {local}"))?;
    info!("forward: {local} -> {target}");
    loop {
        let mut inbound = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!("forward: accept on {local}: {e}");
                continue;
            }
        };
        let target = target.clone();
        tokio::spawn(async move {
            match raw_connect(&target).await {
                Ok(mut outbound) => {
                    match tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await {
                        Ok((up, down)) => debug!("forward: closed ({up} up, {down} down)"),
                        Err(e) => debug!("forward: stream ended: {e}"),
                    }
                }
                Err(e) => warn!("forward: connecting to {target}: {e:#}"),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// End to end over loopback TCP: client -> forward -> echo backend. Proves
    /// the accept/connect/splice path is wired correctly and bytes flow both
    /// ways; the vsock/unix variants reuse the same RawConn splice.
    #[tokio::test]
    async fn forwards_bytes_both_ways() {
        // echo backend
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = backend.accept().await.unwrap();
            let mut buf = [0u8; 64];
            loop {
                let n = s.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                s.write_all(&buf[..n]).await.unwrap();
            }
        });

        // forward listening on its own ephemeral port -> the backend
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        drop(front); // free the port for run_forward to bind
        let listen: SocketAddr = format!("tcp://{front_addr}").parse().unwrap();
        let target: SocketAddr = format!("tcp://{backend_addr}").parse().unwrap();
        tokio::spawn(async move {
            let _ = run_forward(&listen, &target).await;
        });

        // give the forward a moment to bind, then round-trip a payload
        let mut client = loop {
            if let Ok(c) = TcpStream::connect(front_addr).await {
                break c;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }
}
