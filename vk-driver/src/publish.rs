//! Host side of `vk publish`: accept local connections and, for each one, ask a
//! running guest's agent (over its exec control channel) to dial an address on its
//! own network and splice raw bytes — reusing `vk_core::exec::client` the same way
//! `vk exec` does, so no dedicated vsock port needs to exist for the published port.

use anyhow::{Context, Result};
use log::{error, info, warn};
use vk_core::addr::SocketAddr;
use vk_core::exec::client::client_run_connect;
use vk_core::net::{connect, raw_listen};

/// Accept on `listen` and, per connection, dial `agent_addr`'s control channel and
/// ask it to reach `to`. Each connection gets its own session on the (already
/// multiplexing) control channel — no VM reboot, no new vsock port. Returns only on
/// a bind error; a per-connection failure is logged and does not stop the listener.
pub async fn run(agent_addr: &SocketAddr, listen: &SocketAddr, to: &SocketAddr) -> Result<()> {
    let listener = raw_listen(listen)
        .await
        .with_context(|| format!("publish: binding {listen}"))?;
    info!("publish: {listen} -> {to} (via {agent_addr})");
    loop {
        let local = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!("publish: accept on {listen}: {e}");
                continue;
            }
        };
        let agent_addr = agent_addr.clone();
        let target = to.to_string();
        tokio::spawn(async move {
            match connect(&agent_addr).await {
                Ok((stream, sink)) => {
                    if let Err(e) = client_run_connect(stream, sink, target, local).await {
                        error!("publish: session to {agent_addr}: {e}");
                    }
                }
                Err(e) => error!("publish: connecting to agent {agent_addr}: {e}"),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use vk_core::exec::server::run_server;

    /// A TCP echo server, standing in for a target reachable only from the guest's
    /// own network — the thing `vk publish` relays a local connection to.
    async fn echo_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut conn, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        match conn.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) if conn.write_all(&buf[..n]).await.is_err() => break,
                            Ok(_) => {}
                        }
                    }
                });
            }
        });
        addr
    }

    /// End to end through `run`'s own accept loop: a local TCP client -> `publish::run`
    /// -> a fake agent (a real `run_server`) -> an echo target on its "network". Proves
    /// the accept/dial/relay glue this module adds on top of `client_run_connect` (which
    /// `vk-core/tests/exec.rs` already covers directly) is wired correctly end to end.
    #[tokio::test]
    async fn relays_a_published_connection_to_the_target() {
        let agent_path = std::env::temp_dir().join(format!(
            "virtkit-publish-test-{}.socket",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&agent_path);
        let agent_addr = SocketAddr::Unix(agent_path.clone());
        let server_addr = agent_addr.clone();
        tokio::spawn(async move {
            run_server(&server_addr, Some(Duration::from_secs(60)), None, vec![])
                .await
                .unwrap();
        });
        while !agent_path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let echo_addr = echo_server().await;
        let target: SocketAddr = format!("tcp://{echo_addr}").parse().unwrap();

        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        drop(front); // free the port for `run` to bind
        let listen: SocketAddr = format!("tcp://{front_addr}").parse().unwrap();
        tokio::spawn(async move {
            let _ = run(&agent_addr, &listen, &target).await;
        });

        let mut client = loop {
            if let Ok(c) = TcpStream::connect(front_addr).await {
                break c;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }
}
