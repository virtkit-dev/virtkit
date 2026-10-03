//! The boot child relays a Unix socket to a socketpair whose other end the VMM holds.
//! This serves a UEFI guest's qemu-ga port ([`crate::qga`]) and COM1's input (`vk console`).

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use anyhow::{Context, Result};

/// Bind `path` (replacing a stale socket from an earlier boot) and relay its client to `guest`
/// on a thread named `thread`, for the life of the process.
///
/// One client at a time; the newest wins. A new connection drops the previous client so a
/// hung or abandoned client cannot lock the channel. A client that stops reading is dropped
/// after [`CLIENT_WRITE_TIMEOUT`]. Guest output with no connected client is dropped.
pub fn serve_socket(path: &Path, guest: UnixStream, thread: &str) -> Result<()> {
    let _ = std::fs::remove_file(path);
    let listener =
        vk_core::unixpath::bind(path).with_context(|| format!("binding {}", path.display()))?;
    std::thread::Builder::new()
        .name(thread.into())
        .spawn(move || relay(&listener, &guest))
        .context("spawning the socket relay")?;
    Ok(())
}

/// How long the relay waits on a client that does not read what the guest sends it.
const CLIENT_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

fn relay(listener: &std::os::unix::net::UnixListener, guest: &UnixStream) {
    let mut client: Option<UnixStream> = None;
    let mut buf = [0u8; 16 * 1024];
    let poll_in = |fd: i32| libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ready =
        |fd: &libc::pollfd| fd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0;
    loop {
        let mut fds = vec![poll_in(listener.as_raw_fd()), poll_in(guest.as_raw_fd())];
        if let Some(c) = &client {
            fds.push(poll_in(c.as_raw_fd()));
        }
        // SAFETY: valid pollfds on fds borrowed for the call.
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) } < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if fds.get(2).is_some_and(ready)
            && let Some(c) = &client
            && !copy(c, guest, &mut buf)
        {
            client = None;
        }
        if ready(&fds[1]) {
            match &client {
                Some(c) => {
                    if !copy(guest, c, &mut buf) {
                        client = None;
                    }
                }
                // Nobody to hand it to.
                None => {
                    if (&*guest).read(&mut buf).is_ok_and(|n| n == 0) {
                        return;
                    }
                }
            }
        }
        if ready(&fds[0])
            && let Ok((c, _)) = listener.accept()
            && c.set_write_timeout(Some(CLIENT_WRITE_TIMEOUT)).is_ok()
        {
            client = Some(c);
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
    fn clients_take_turns_on_the_port() {
        let dir = std::env::temp_dir().join(format!("vk-relay-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("relay.sock");
        let (mut port, host) = UnixStream::pair().unwrap();
        serve_socket(&sock, host, "vk-relay-test").unwrap();

        for round in 0..2 {
            let mut client = vk_core::unixpath::connect(&sock).unwrap();
            let request = format!("request {round}\n");
            client.write_all(request.as_bytes()).unwrap();
            let mut got = vec![0u8; request.len()];
            port.read_exact(&mut got).unwrap();
            assert_eq!(got, request.as_bytes());

            port.write_all(b"reply\n").unwrap();
            let mut reply = [0u8; 6];
            client.read_exact(&mut reply).unwrap();
            assert_eq!(&reply, b"reply\n");
            // The next round's client gets the port once this one hangs up.
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_client_that_stops_reading_is_dropped() {
        let dir = std::env::temp_dir().join(format!("vk-relay-stuck-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("relay.sock");
        let (mut port, host) = UnixStream::pair().unwrap();
        serve_socket(&sock, host, "vk-relay-test").unwrap();

        // A client that asks, then never reads the flood the guest answers with.
        let mut stuck = vk_core::unixpath::connect(&sock).unwrap();
        stuck.write_all(b"first\n").unwrap();
        let mut got = [0u8; 6];
        port.read_exact(&mut got).unwrap();
        // More than both socket buffers hold: only dropping the client lets it all through.
        port.write_all(&vec![b'x'; 8 << 20]).unwrap();
        port.write_all(b"\n").unwrap();

        let mut client = vk_core::unixpath::connect(&sock).unwrap();
        client.write_all(b"second\n").unwrap();
        let mut got = [0u8; 7];
        port.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"second\n");
        port.write_all(b"reply\n").unwrap();
        // Possibly behind the end of the flood.
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut reply = Vec::new();
        let mut byte = [0u8; 1];
        while !reply.ends_with(b"reply\n") {
            client.read_exact(&mut byte).unwrap();
            reply.push(byte[0]);
        }
        drop(stuck);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_client_takes_the_port_from_one_that_hangs() {
        let dir = std::env::temp_dir().join(format!("vk-relay-preempt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("relay.sock");
        let (mut port, host) = UnixStream::pair().unwrap();
        serve_socket(&sock, host, "vk-relay-test").unwrap();

        // A client that connects, asks, and then neither reads nor leaves.
        let mut stuck = vk_core::unixpath::connect(&sock).unwrap();
        stuck.write_all(b"first\n").unwrap();
        let mut got = [0u8; 6];
        port.read_exact(&mut got).unwrap();

        let mut client = vk_core::unixpath::connect(&sock).unwrap();
        client.write_all(b"second\n").unwrap();
        let mut got = [0u8; 7];
        port.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"second\n");
        port.write_all(b"reply\n").unwrap();
        let mut reply = [0u8; 6];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"reply\n");
        drop(stuck);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
