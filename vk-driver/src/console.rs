//! `vk console`: the serial console of a Windows (UEFI) guest, where Windows serves its
//! Special Administration Console (SAC, through EMS) on COM1 — the way in when qemu-ga does not
//! answer.
//!
//! What the guest writes to COM1 is already the run's `console.log`, so the console follows that
//! file; keystrokes go to the run's COM1 input socket ([`crate::uefi::CONSOLE_SOCKET`]), which
//! takes one client at a time, the newest winning. SAC reads the port slowly and drops what
//! arrives faster, so keystrokes are paced: [`BURST`] bytes every [`GAP`]. Ctrl-] leaves.
//!
//! A guest reboot restarts the VMM process, which rebinds that socket: the console reconnects
//! to it and keeps following the log, which the new boot appends to.

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// Bytes sent to COM1 at a time.
const BURST: usize = 3;
/// The pause between two bursts.
const GAP: Duration = Duration::from_millis(180);
/// Ctrl-]: leave the console.
const ESCAPE: u8 = 0x1d;
/// Console history shown on attachment, starting at its first full line.
const BACKLOG: u64 = 2048;
/// How long a hung-up console waits for a rebooting guest's VMM to rebind the socket.
const REBOOT_WAIT: Duration = Duration::from_secs(30);
/// An unchanged socket this long after a hang-up means a newer console took it; a reboot
/// rebinds it within milliseconds.
const REPLACED_AFTER: Duration = Duration::from_secs(3);

/// Keystrokes on their way to COM1.
#[derive(Default)]
struct Pacer {
    pending: VecDeque<u8>,
    /// when the last burst went
    sent: Option<Instant>,
    /// the keyboard (or pipe) has ended
    closed: bool,
}

impl Pacer {
    /// Queue what was typed since the last call; false on Ctrl-], which drops what is queued.
    fn take(&mut self, typed: &mpsc::Receiver<u8>) -> bool {
        loop {
            match typed.try_recv() {
                Ok(ESCAPE) => {
                    self.pending.clear();
                    return false;
                }
                Ok(byte) => self.pending.push_back(translate(byte)),
                Err(mpsc::TryRecvError::Empty) => return true,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.closed = true;
                    return true;
                }
            }
        }
    }

    /// The burst due at `now`, if any.
    fn next_burst(&mut self, now: Instant) -> Option<Vec<u8>> {
        let due = self
            .sent
            .is_none_or(|t| now.saturating_duration_since(t) >= GAP);
        if self.pending.is_empty() || !due {
            return None;
        }
        self.sent = Some(now);
        Some(
            self.pending
                .drain(..self.pending.len().min(BURST))
                .collect(),
        )
    }

    /// Requeue a failed burst ahead of pending input.
    fn requeue(&mut self, burst: Vec<u8>) {
        for byte in burst.into_iter().rev() {
            self.pending.push_front(byte);
        }
    }

    /// Piped input has ended and all of it has been sent.
    fn done(&self) -> bool {
        self.closed && self.pending.is_empty()
    }
}

/// Keystrokes as COM1 gets them: a newline from a pipe becomes the carriage return a terminal
/// sends for Enter.
fn translate(byte: u8) -> u8 {
    if byte == b'\n' { b'\r' } else { byte }
}

/// What a console the relay hung up on does next.
#[derive(Debug, PartialEq)]
enum Hangup {
    /// look again shortly
    Wait,
    /// the socket was rebound: a guest reboot
    Reconnect,
    /// a newer console took the socket
    Replaced,
    /// the VM is gone
    Stopped,
}

/// Which bind of the socket file this is: inode and ctime (seconds, nanoseconds). The inode
/// alone does not tell: ext4 hands the one an unlink freed to the next bind.
type SocketId = (u64, i64, i64);

fn socket_id(socket: &Path) -> Option<SocketId> {
    let m = std::fs::metadata(socket).ok()?;
    Some((m.ino(), m.ctime(), m.ctime_nsec()))
}

/// Decide from the socket's identity at connection (`ours`) and now (`now`, `None` if missing),
/// whether the VM still runs, and the time since hang-up.
fn after_hangup(ours: SocketId, now: Option<SocketId>, vm_alive: bool, waited: Duration) -> Hangup {
    if !vm_alive {
        return Hangup::Stopped;
    }
    match now {
        Some(id) if id != ours && waited < REBOOT_WAIT => Hangup::Reconnect,
        Some(id) if id == ours && waited >= REPLACED_AFTER => Hangup::Replaced,
        _ if waited >= REBOOT_WAIT => Hangup::Stopped,
        _ => Hangup::Wait,
    }
}

/// Connect to COM1's input socket and return its identity, which a reboot changes.
/// Read the identity first: a rebind in between costs at most a needless reconnect.
fn connect(socket: &Path) -> Result<(UnixStream, SocketId)> {
    let id =
        socket_id(socket).with_context(|| format!("no console input at {}", socket.display()))?;
    let com1 = vk_core::unixpath::connect(socket)
        .with_context(|| format!("connecting to the console input {}", socket.display()))?;
    // Nothing comes back on it: a read only tells when the relay has hung up.
    com1.set_nonblocking(true)?;
    Ok((com1, id))
}

/// Write a burst to the nonblocking COM1 socket, waiting briefly while the relay is behind.
fn send(com1: &mut UnixStream, mut burst: &[u8]) -> std::io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(1);
    while !burst.is_empty() {
        match com1.write(burst) {
            Ok(0) => return Err(ErrorKind::WriteZero.into()),
            Ok(n) => burst = &burst[n..],
            Err(e) if e.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Attach to the console of `vm`, a UEFI guest, until Ctrl-] (or the end of a piped input once
/// it is all sent).
pub fn run(vm: &crate::vms::VmEntry) -> Result<()> {
    let state_dir = &vm.state_dir;
    let log_path = state_dir.join(crate::run::CONSOLE_LOG);
    let socket = state_dir.join(crate::uefi::CONSOLE_SOCKET);
    let (mut com1, mut ours) = connect(&socket)?;
    let mut log = std::fs::File::open(&log_path)
        .with_context(|| format!("opening {}", log_path.display()))?;
    let start = log.metadata()?.len().saturating_sub(BACKLOG);
    log.seek(SeekFrom::Start(start))?;
    let mut backlog = Vec::new();
    (&mut log).take(BACKLOG).read_to_end(&mut backlog)?;
    if start > 0 {
        let first_line = backlog
            .iter()
            .position(|&b| b == b'\n')
            .map_or(0, |i| i + 1);
        backlog.drain(..first_line);
    }
    eprintln!(
        "virtkit: console of {} — Ctrl-] leaves\r",
        state_dir.display()
    );

    // Raw before the keyboard thread reads, so no keystroke goes through the line discipline.
    // A pipe has no termios: then neither applies.
    let saved = crate::term::current_termios(libc::STDIN_FILENO);
    let _raw = vk_core::pty::RawModeGuard::enable(libc::STDIN_FILENO).ok();
    if let Some(saved) = saved {
        crate::term::catch_terminating_signals(saved);
    }
    let (keys, typed) = mpsc::channel::<u8>();
    std::thread::Builder::new()
        .name("vk-console-in".into())
        .spawn(move || {
            let mut byte = [0u8; 1];
            while let Ok(1) = std::io::stdin().read(&mut byte) {
                if keys.send(byte[0]).is_err() {
                    break;
                }
            }
        })?;

    let mut out = std::io::stdout();
    out.write_all(&backlog)?;
    out.flush()?;
    let mut pacer = Pacer::default();
    let mut buf = [0u8; 16 * 1024];
    // When the relay hung up; keystrokes queue until the socket is rebound.
    let mut hung_up: Option<Instant> = None;
    loop {
        if !pacer.take(&typed) {
            out.write_all(b"\r\n")?;
            return Ok(());
        }
        if let Some(since) = hung_up {
            let why = match after_hangup(
                ours,
                socket_id(&socket),
                crate::vms::alive(vm),
                since.elapsed(),
            ) {
                Hangup::Reconnect => {
                    if let Ok(again) = connect(&socket) {
                        (com1, ours) = again;
                        hung_up = None;
                        eprintln!("\r\nvirtkit: reconnected after a guest reboot\r");
                    }
                    None
                }
                Hangup::Wait => None,
                Hangup::Replaced => Some("another vk console attached"),
                Hangup::Stopped => Some("the VM stopped"),
            };
            if let Some(why) = why {
                out.write_all(b"\r\n")?;
                bail!("console closed: {why}");
            }
        } else {
            if let Some(burst) = pacer.next_burst(Instant::now())
                && let Err(e) = send(&mut com1, &burst)
            {
                // A relay gone with a guest reboot: the read below sees it hang up, and the
                // burst goes to the next one.
                if e.kind() != ErrorKind::BrokenPipe {
                    return Err(e).context("writing to the console");
                }
                pacer.requeue(burst);
            }
            match com1.read(&mut buf) {
                Ok(0) => hung_up = Some(Instant::now()),
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(e).context("reading the console input"),
            }
        }
        let n = log.read(&mut buf)?;
        if n > 0 {
            out.write_all(&buf[..n])?;
            out.flush()?;
        } else if pacer.done() {
            // Piped input all sent: leave once the guest has had a moment to answer it.
            std::thread::sleep(Duration::from_secs(2));
            std::io::copy(&mut log, &mut out)?;
            out.flush()?;
            return Ok(());
        } else {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_piped_newline_reaches_com1_as_enter() {
        assert_eq!(translate(b'\n'), b'\r');
        assert_eq!(translate(b'a'), b'a');
        assert_eq!(translate(ESCAPE), ESCAPE);
    }

    #[test]
    fn keystrokes_go_in_bursts_of_three_a_gap_apart() {
        let (keys, typed) = mpsc::channel();
        b"dir\n".iter().for_each(|&b| keys.send(b).unwrap());
        let mut pacer = Pacer::default();
        assert!(pacer.take(&typed));
        let t0 = Instant::now();
        assert_eq!(pacer.next_burst(t0), Some(b"dir".to_vec()));
        assert_eq!(pacer.next_burst(t0 + GAP - Duration::from_millis(1)), None);
        assert_eq!(pacer.next_burst(t0 + GAP), Some(b"\r".to_vec()));
        assert_eq!(pacer.next_burst(t0 + 3 * GAP), None);
    }

    #[test]
    fn ctrl_close_bracket_leaves_and_drops_pending_input() {
        let (keys, typed) = mpsc::channel();
        b"abcdef".iter().for_each(|&b| keys.send(b).unwrap());
        keys.send(ESCAPE).unwrap();
        let mut pacer = Pacer::default();
        assert!(!pacer.take(&typed));
        assert_eq!(pacer.next_burst(Instant::now()), None);
    }

    #[test]
    fn a_hangup_reconnects_only_to_a_rebound_socket() {
        let soon = Duration::from_millis(100);
        let ours = (1, 100, 5);
        // ext4 reuses the freed inode: only the ctime tells the rebind.
        let rebound = (1, 107, 2);
        let check = |now, alive, waited| after_hangup(ours, now, alive, waited);
        assert_eq!(check(Some(ours), true, soon), Hangup::Wait);
        assert_eq!(check(None, true, soon), Hangup::Wait);
        assert_eq!(check(Some(rebound), true, soon), Hangup::Reconnect);
        assert_eq!(check(Some((2, 100, 5)), true, soon), Hangup::Reconnect);
        assert_eq!(check(Some((1, 100, 6)), true, soon), Hangup::Reconnect);
        assert_eq!(check(Some(ours), true, REPLACED_AFTER), Hangup::Replaced);
        assert_eq!(check(None, true, REPLACED_AFTER), Hangup::Wait);
        assert_eq!(check(None, true, REBOOT_WAIT), Hangup::Stopped);
        assert_eq!(check(Some(rebound), true, REBOOT_WAIT), Hangup::Stopped);
        assert_eq!(check(Some(rebound), false, soon), Hangup::Stopped);
        assert_eq!(check(Some(ours), false, soon), Hangup::Stopped);
    }

    #[test]
    fn a_burst_that_did_not_get_through_goes_first() {
        let (keys, typed) = mpsc::channel();
        b"dir\n".iter().for_each(|&b| keys.send(b).unwrap());
        let mut pacer = Pacer::default();
        assert!(pacer.take(&typed));
        let t0 = Instant::now();
        let burst = pacer.next_burst(t0).unwrap();
        pacer.requeue(burst);
        assert_eq!(pacer.next_burst(t0 + GAP), Some(b"dir".to_vec()));
        assert_eq!(pacer.next_burst(t0 + 2 * GAP), Some(b"\r".to_vec()));
    }

    #[test]
    fn piped_input_ends_once_all_of_it_is_sent() {
        let (keys, typed) = mpsc::channel();
        b"ab\n".iter().for_each(|&b| keys.send(b).unwrap());
        let mut pacer = Pacer::default();
        assert!(pacer.take(&typed));
        assert!(!pacer.done());
        drop(keys);
        assert!(pacer.take(&typed));
        assert!(!pacer.done());
        assert_eq!(pacer.next_burst(Instant::now()), Some(b"ab\r".to_vec()));
        assert!(pacer.done());
    }
}
