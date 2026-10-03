//! The qemu-ga channel of an agent-less guest (Windows): the guest agent reads and writes a
//! named virtio-console port, which the boot child bridges to a Unix socket on the host.
//!
//! The port is one end of a socketpair; [`serve`] relays the other end to whichever client is
//! connected to the socket, one at a time. What the guest writes with no client connected
//! stays in the socketpair and goes to the next client, and the agent's protocol carries no
//! session, so a client starts with `guest-sync-delimited` to discard what an earlier client
//! left in flight.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use anyhow::{Context, Result};

/// The port name qemu-ga opens (`\\.\Global\org.qemu.guest_agent.0` on Windows).
pub const PORT_NAME: &str = "org.qemu.guest_agent.0";

/// Bind `path` (replacing a stale socket from an earlier boot) and relay each client in turn
/// to `guest` on a thread of its own, for the life of the process.
pub fn serve(path: &Path, guest: UnixStream) -> Result<()> {
    let _ = std::fs::remove_file(path);
    let listener = vk_core::unixpath::bind(path)
        .with_context(|| format!("binding the guest agent socket {}", path.display()))?;
    std::thread::Builder::new()
        .name("vk-qga".into())
        .spawn(move || {
            for client in listener.incoming().flatten() {
                relay(&client, &guest);
            }
        })
        .context("spawning the guest agent relay")?;
    Ok(())
}

/// Copy bytes both ways between `client` and `guest` until the client goes away (or the
/// guest side fails).
fn relay(client: &UnixStream, guest: &UnixStream) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        let mut fds = [
            libc::pollfd {
                fd: client.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: guest.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: two valid pollfds on fds borrowed for the call.
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        let ready =
            |fd: &libc::pollfd| fd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0;
        if ready(&fds[0]) && !copy(client, guest, &mut buf) {
            return;
        }
        if ready(&fds[1]) && !copy(guest, client, &mut buf) {
            return;
        }
    }
}

/// Move ready bytes from `from` to `to`; false at end of stream or on error.
fn copy(mut from: &UnixStream, mut to: &UnixStream, buf: &mut [u8]) -> bool {
    match from.read(buf) {
        Ok(0) | Err(_) => false,
        Ok(n) => to.write_all(&buf[..n]).is_ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clients_take_turns_on_the_guest_port() {
        let dir = std::env::temp_dir().join(format!("vk-qga-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("qga.sock");
        let (mut port, host) = UnixStream::pair().unwrap();
        serve(&sock, host).unwrap();

        for round in 0..2 {
            let mut client = vk_core::unixpath::connect(&sock).unwrap();
            let request = format!("{{\"execute\":\"guest-ping\",\"id\":{round}}}\n");
            client.write_all(request.as_bytes()).unwrap();
            let mut got = vec![0u8; request.len()];
            port.read_exact(&mut got).unwrap();
            assert_eq!(got, request.as_bytes());

            port.write_all(b"{\"return\": {}}\n").unwrap();
            let mut reply = vec![0u8; 15];
            client.read_exact(&mut reply).unwrap();
            assert_eq!(reply, b"{\"return\": {}}\n");
            // The next round's client gets the port once this one hangs up.
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
