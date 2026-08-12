//! Exit records from the kernel's taskstats, over generic netlink.
//!
//! A `/proc` sweep only ever sees what is alive when it runs, so a job whose work is thousands
//! of short commands — a compile, a test suite forking per case — shows the sampler almost
//! nothing. The kernel will send a record for *every* task as it dies, carrying the whole life
//! of it: processor time, faults, peak resident size and the bytes it moved. This module
//! registers for those records and hands them to the sampler.
//!
//! Registration is `TASKSTATS_CMD_GET` with a cpumask over every processor, on a
//! `NETLINK_GENERIC` socket whose family id is resolved by name first (the family is dynamic,
//! so there is no constant to hard-code). Records then arrive unsolicited as tasks exit.
//!
//! **The `struct taskstats` field offsets below were taken from
//! `include/uapi/linux/taskstats.h` at `TASKSTATS_VERSION` 17 (Linux 6.18, the pinned guest
//! kernel).** They are safe to hard-code because that struct is append-only by its own
//! contract — new fields go on the end and the version counter is bumped — so a record from an
//! older kernel has the same layout, only shorter. Every read is bounds-checked against the
//! record actually received, and the two fields added after version 1 are taken only from a
//! record that claims to carry them.
//!
//! Nothing here is allowed to stop a job being recorded: a kernel without taskstats, a
//! rejected registration or a malformed message all end in the sampler carrying on with what
//! `/proc` gives it.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// `NETLINK_GENERIC`, and the fixed family id of the controller that resolves the others.
const NETLINK_GENERIC: libc::c_int = 16;
const GENL_ID_CTRL: u16 = 16;

/// The controller command that resolves a family by name, and the two attributes involved.
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

/// The taskstats family: its name, protocol version, the command that registers a listener and
/// the attribute carrying the processors to listen on.
const TASKSTATS_GENL_NAME: &str = "TASKSTATS";
const TASKSTATS_GENL_VERSION: u8 = 1;
const TASKSTATS_CMD_GET: u8 = 1;
const TASKSTATS_CMD_ATTR_REGISTER_CPUMASK: u16 = 3;

/// The attributes a record arrives in: a per-task or per-thread-group aggregate, each holding
/// the id it is about and the statistics themselves.
const TASKSTATS_TYPE_AGGR_PID: u16 = 4;
const TASKSTATS_TYPE_AGGR_TGID: u16 = 5;
const TASKSTATS_TYPE_PID: u16 = 1;
const TASKSTATS_TYPE_TGID: u16 = 2;
const TASKSTATS_TYPE_STATS: u16 = 3;

/// Netlink message types that are not data: an error reply, and the end of a multipart one.
const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;

/// Header sizes: `struct nlmsghdr`, `struct genlmsghdr`, `struct nlattr`.
const NLMSG_HDRLEN: usize = 16;
const GENL_HDRLEN: usize = 4;
const NLA_HDRLEN: usize = 4;

/// Offsets into `struct taskstats` of the fields a sample needs. Named rather than counted at
/// each use, so the one place they come from is the header they were read out of (see the
/// module note: version 17, append-only ABI).
mod field {
    pub const VERSION: usize = 0; // u16
    pub const EXITCODE: usize = 4; // u32
    pub const NICE: usize = 9; // u8
    pub const COMM: usize = 80; // char[32]
    pub const UID: usize = 120; // u32
    pub const GID: usize = 124; // u32
    pub const PID: usize = 128; // u32
    pub const PPID: usize = 132; // u32
    pub const BTIME: usize = 136; // u32, seconds since the epoch
    pub const ETIME: usize = 144; // u64, microseconds
    pub const UTIME: usize = 152; // u64, microseconds
    pub const STIME: usize = 160; // u64, microseconds
    pub const MINFLT: usize = 168; // u64
    pub const MAJFLT: usize = 176; // u64
    pub const HIWATER_RSS: usize = 200; // u64, KiB
    pub const READ_SYSCALLS: usize = 232; // u64
    pub const WRITE_SYSCALLS: usize = 240; // u64
    pub const READ_BYTES: usize = 248; // u64
    pub const WRITE_BYTES: usize = 256; // u64
    pub const CANCELLED_WRITE_BYTES: usize = 264; // u64
    /// Added in version 10 (a 32-bit begin time overflows in 2106).
    pub const BTIME64: usize = 344; // u64
    /// Added in version 12.
    pub const TGID: usize = 368; // u32
    /// The end of what is read above: a record shorter than this is from a kernel whose
    /// taskstats predates I/O accounting, and carries nothing worth reporting.
    pub const NEEDED: usize = CANCELLED_WRITE_BYTES + 8;
}

/// The version a record must claim before [`field::BTIME64`] and [`field::TGID`] are read.
const VERSION_BTIME64: u16 = 10;
const VERSION_TGID: u16 = 12;

/// How much room the kernel gets for records this sampler has not read yet. A burst of short
/// commands can exit thousands of tasks between two samples, and a receive buffer that
/// overflows loses them (the loss is reported, see [`Listener::drops`]).
const RCVBUF: libc::c_int = 8 * 1024 * 1024;

/// One task the kernel says has exited, with the whole of what it used.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Exit {
    pub pid: i32,
    pub tgid: i32,
    pub ppid: i32,
    pub uid: u32,
    pub gid: u32,
    /// The name of the command, as the kernel's own 16-byte task name — a task's full command
    /// line is gone by the time it exits, so this is all there is of it.
    pub comm: String,
    /// The raw exit code, in the form `wait` reports it.
    pub exitcode: u32,
    pub nice: i8,
    /// When it started, seconds since the epoch.
    pub btime: i64,
    /// How long it lived, and what it burned, in microseconds.
    pub etime_us: u64,
    pub utime_us: u64,
    pub stime_us: u64,
    pub minflt: u64,
    pub majflt: u64,
    /// The most resident memory it ever held, in KiB.
    pub hiwater_rss_kb: u64,
    /// The reads and writes it asked for, and the bytes those cost the block layer.
    pub read_syscalls: u64,
    pub write_syscalls: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub cancelled_write_bytes: u64,
}

/// A registered listener for exit records.
pub struct Listener {
    fd: OwnedFd,
    family: u16,
    /// Records the kernel had to drop because this listener was not reading fast enough.
    drops: u64,
    buf: Vec<u8>,
}

impl Listener {
    /// Open a socket, resolve the taskstats family and register for the exit records of every
    /// processor. Fails on a kernel built without taskstats (no such family) or one that will
    /// not have us (registration needs privilege) — either way the caller carries on without.
    pub fn open(cpus: usize) -> io::Result<Listener> {
        // SAFETY: a plain socket(2) with constant arguments.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                NETLINK_GENERIC,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh fd this call owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: a caller-owned sockaddr_nl of the length given.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const addr).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // Best effort: a smaller buffer only means records are dropped sooner, which is
        // reported rather than fatal.
        let size = RCVBUF;
        // SAFETY: SO_RCVBUF takes an int of the length given.
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&raw const size).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        let mut listener = Listener {
            fd,
            family: 0,
            drops: 0,
            buf: vec![0u8; 64 * 1024],
        };
        listener.family = listener.resolve_family()?;
        listener.register(cpus)?;
        Ok(listener)
    }

    /// The socket, for a caller waiting on it alongside its own clock.
    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// How many records the kernel dropped for want of room in this socket. A job whose churn
    /// outruns the sampler loses exits, which is worth saying rather than hiding.
    pub fn drops(&self) -> u64 {
        self.drops
    }

    /// Ask the controller for the taskstats family id, which is assigned at runtime.
    fn resolve_family(&mut self) -> io::Result<u16> {
        let mut name = TASKSTATS_GENL_NAME.as_bytes().to_vec();
        name.push(0); // the controller expects it NUL-terminated
        self.send(
            GENL_ID_CTRL,
            CTRL_CMD_GETFAMILY,
            1,
            CTRL_ATTR_FAMILY_NAME,
            &name,
        )?;
        let len = self.recv_reply()?;
        let reply = self
            .buf
            .get(..len)
            .ok_or_else(|| io::Error::other("short netlink reply"))?;
        family_id(reply).ok_or_else(|| io::Error::other("no taskstats family in the reply"))
    }

    /// Register for the exit records of every processor. The mask is a range because that is
    /// what the kernel parses here — a list of cpus, spelled as `0-N`.
    ///
    /// The terminator is part of the payload: the kernel copies one byte fewer than the
    /// attribute's length and terminates the string itself, so a mask sent without it arrives
    /// with its last character cut off and is rejected as a list it cannot parse.
    fn register(&mut self, cpus: usize) -> io::Result<()> {
        let mask = format!("0-{}\0", cpus.max(1).saturating_sub(1));
        self.send(
            self.family,
            TASKSTATS_CMD_GET,
            TASKSTATS_GENL_VERSION,
            TASKSTATS_CMD_ATTR_REGISTER_CPUMASK,
            mask.as_bytes(),
        )?;
        // The kernel answers a registration only when it refuses it, so a reply that does not
        // come is the success case: look once, briefly.
        if let Ok(len) = self.recv_reply()
            && let Some(errno) = error_in(self.buf.get(..len).unwrap_or_default())
        {
            return Err(io::Error::from_raw_os_error(errno));
        }
        Ok(())
    }

    /// One generic-netlink request with a single attribute.
    fn send(&self, family: u16, cmd: u8, version: u8, attr: u16, payload: &[u8]) -> io::Result<()> {
        let msg = request(family, cmd, version, attr, payload);
        // SAFETY: a caller-owned buffer of the length given, on a socket this struct owns.
        let sent = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                msg.as_ptr().cast(),
                msg.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        match sent < 0 {
            true => Err(io::Error::last_os_error()),
            false => Ok(()),
        }
    }

    /// Wait briefly for a reply to a request, and read it into the buffer.
    fn recv_reply(&mut self) -> io::Result<usize> {
        let mut poll = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one caller-owned pollfd, and the count matches.
        let ready = unsafe { libc::poll(&mut poll, 1, 1_000) };
        if ready <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no netlink reply within a second",
            ));
        }
        self.read()
    }

    /// Read one datagram, or report what stopped it.
    fn read(&mut self) -> io::Result<usize> {
        // SAFETY: this struct owns the buffer, and the length matches it.
        let n = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                self.buf.as_mut_ptr().cast(),
                self.buf.len(),
                0,
            )
        };
        match n < 0 {
            true => Err(io::Error::last_os_error()),
            false => Ok(n as usize),
        }
    }

    /// Take every record waiting on the socket, appending the exits to `out`. Returns when the
    /// socket is empty; a message that cannot be understood is skipped, and a buffer the kernel
    /// overflowed is counted and read on from.
    pub fn drain(&mut self, out: &mut Vec<Exit>) {
        loop {
            match self.read() {
                Ok(0) => return,
                Ok(len) => {
                    let buf = std::mem::take(&mut self.buf);
                    if let Some(msg) = buf.get(..len) {
                        parse_exits(msg, out);
                    }
                    self.buf = buf;
                }
                Err(e) => match after_error(e.raw_os_error()) {
                    Next::Done => return,
                    Next::Again => continue,
                    Next::Dropped => self.drops = self.drops.saturating_add(1),
                },
            }
        }
    }
}

/// What a failed read means for the drain loop.
#[derive(Debug, PartialEq, Eq)]
enum Next {
    /// The socket is empty, or unusable: stop reading it.
    Done,
    /// Try again.
    Again,
    /// The kernel had records and nowhere to put them. Count the loss and read on — what is
    /// gone is the exits of an interval too busy for this socket, and stopping here would lose
    /// every interval after it as well.
    Dropped,
}

fn after_error(errno: Option<i32>) -> Next {
    match errno {
        // Nothing left to read (EWOULDBLOCK is the same value on Linux).
        Some(libc::EAGAIN) => Next::Done,
        Some(libc::EINTR) => Next::Again,
        Some(libc::ENOBUFS) => Next::Dropped,
        // Anything else is this socket being unusable; stop rather than spin on it.
        _ => Next::Done,
    }
}

/// One netlink request: message header, generic header, one attribute.
fn request(family: u16, cmd: u8, version: u8, attr: u16, payload: &[u8]) -> Vec<u8> {
    let attr_len = NLA_HDRLEN + payload.len();
    let total = NLMSG_HDRLEN + GENL_HDRLEN + align4(attr_len);
    let mut msg = Vec::with_capacity(total);
    msg.extend_from_slice(&(total as u32).to_ne_bytes()); // nlmsg_len
    msg.extend_from_slice(&family.to_ne_bytes()); // nlmsg_type
    msg.extend_from_slice(&NLM_F_REQUEST.to_ne_bytes()); // nlmsg_flags
    msg.extend_from_slice(&1u32.to_ne_bytes()); // nlmsg_seq
    msg.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid: the kernel fills it in
    msg.push(cmd);
    msg.push(version);
    msg.extend_from_slice(&0u16.to_ne_bytes()); // genlmsghdr reserved
    msg.extend_from_slice(&(attr_len as u16).to_ne_bytes());
    msg.extend_from_slice(&attr.to_ne_bytes());
    msg.extend_from_slice(payload);
    while msg.len() < total {
        msg.push(0); // attributes are padded to four bytes
    }
    msg
}

/// Netlink rounds every length up to four bytes.
fn align4(len: usize) -> usize {
    len.saturating_add(3) & !3
}

/// The attributes of a message payload, as `(type, value)`. A truncated or nonsensical length
/// ends the walk rather than reading past the buffer.
fn attrs(payload: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    let mut at = 0usize;
    std::iter::from_fn(move || {
        let header = payload.get(at..at.checked_add(NLA_HDRLEN)?)?;
        let len = u16::from_ne_bytes([header[0], header[1]]) as usize;
        let kind = u16::from_ne_bytes([header[2], header[3]]);
        if len < NLA_HDRLEN {
            return None;
        }
        let value = payload.get(at + NLA_HDRLEN..at.checked_add(len)?)?;
        at = at.saturating_add(align4(len));
        Some((kind, value))
    })
}

/// The messages of a datagram, as `(type, payload after the generic header)`.
fn messages(buf: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    let mut at = 0usize;
    std::iter::from_fn(move || {
        let header = buf.get(at..at.checked_add(NLMSG_HDRLEN)?)?;
        let len = u32::from_ne_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let kind = u16::from_ne_bytes([header[4], header[5]]);
        if len < NLMSG_HDRLEN {
            return None;
        }
        let body = buf.get(at + NLMSG_HDRLEN..at.checked_add(len)?)?;
        at = at.saturating_add(align4(len));
        // An error or a done marker has no generic header to skip.
        let payload = match kind {
            NLMSG_ERROR | NLMSG_DONE | NLMSG_NOOP => body,
            _ => body.get(GENL_HDRLEN..)?,
        };
        Some((kind, payload))
    })
}

/// The family id in a controller reply, if it holds one.
fn family_id(buf: &[u8]) -> Option<u16> {
    for (kind, payload) in messages(buf) {
        if kind == NLMSG_ERROR || kind == NLMSG_DONE {
            continue;
        }
        for (attr, value) in attrs(payload) {
            if attr == CTRL_ATTR_FAMILY_ID {
                return Some(u16::from_ne_bytes([*value.first()?, *value.get(1)?]));
            }
        }
    }
    None
}

/// The errno an error message carries, or `None` when the buffer holds no error. Netlink's own
/// acknowledgement is an error message with errno 0.
fn error_in(buf: &[u8]) -> Option<i32> {
    for (kind, payload) in messages(buf) {
        if kind != NLMSG_ERROR {
            continue;
        }
        let raw = payload.get(..4)?;
        let errno = i32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]);
        if errno != 0 {
            return Some(-errno); // the kernel sends it negated
        }
    }
    None
}

/// Every exited task a datagram describes. A record that is not a whole process, or that this
/// reader cannot make sense of, is passed over.
fn parse_exits(buf: &[u8], out: &mut Vec<Exit>) {
    for (kind, payload) in messages(buf) {
        if matches!(kind, NLMSG_ERROR | NLMSG_DONE | NLMSG_NOOP) {
            continue;
        }
        for (attr, value) in attrs(payload) {
            if attr != TASKSTATS_TYPE_AGGR_PID && attr != TASKSTATS_TYPE_AGGR_TGID {
                continue; // an attribute this reader has no use for
            }
            for (inner, stats) in attrs(value) {
                match inner {
                    TASKSTATS_TYPE_STATS => {
                        if let Some(exit) = parse_stats(stats) {
                            out.push(exit);
                        }
                    }
                    // The id beside the statistics, which the statistics also carry.
                    TASKSTATS_TYPE_PID | TASKSTATS_TYPE_TGID => {}
                    _ => {}
                }
            }
        }
    }
}

/// One `struct taskstats` as an [`Exit`], or `None` when the record is too short to hold what a
/// sample reports, or is a thread rather than the process it belongs to — a thread exiting is
/// not a process ending, and its time is charged to the process's own record.
fn parse_stats(stats: &[u8]) -> Option<Exit> {
    let version = u16_at(stats, field::VERSION)?;
    if version == 0 || stats.len() < field::NEEDED {
        return None;
    }
    let pid = u32_at(stats, field::PID)? as i32;
    // The thread group is only in a record from version 12 on; before that a task is taken to
    // be its own group, which is what a single-threaded command is.
    let tgid = match version >= VERSION_TGID {
        true => u32_at(stats, field::TGID)? as i32,
        false => pid,
    };
    if pid != tgid {
        return None;
    }
    let btime = match version >= VERSION_BTIME64 {
        true => u64_at(stats, field::BTIME64)? as i64,
        false => i64::from(u32_at(stats, field::BTIME)?),
    };
    Some(Exit {
        pid,
        tgid,
        ppid: u32_at(stats, field::PPID)? as i32,
        uid: u32_at(stats, field::UID)?,
        gid: u32_at(stats, field::GID)?,
        comm: comm_at(stats, field::COMM)?,
        exitcode: u32_at(stats, field::EXITCODE)?,
        nice: *stats.get(field::NICE)? as i8,
        btime,
        etime_us: u64_at(stats, field::ETIME)?,
        utime_us: u64_at(stats, field::UTIME)?,
        stime_us: u64_at(stats, field::STIME)?,
        minflt: u64_at(stats, field::MINFLT)?,
        majflt: u64_at(stats, field::MAJFLT)?,
        hiwater_rss_kb: u64_at(stats, field::HIWATER_RSS)?,
        read_syscalls: u64_at(stats, field::READ_SYSCALLS)?,
        write_syscalls: u64_at(stats, field::WRITE_SYSCALLS)?,
        read_bytes: u64_at(stats, field::READ_BYTES)?,
        write_bytes: u64_at(stats, field::WRITE_BYTES)?,
        cancelled_write_bytes: u64_at(stats, field::CANCELLED_WRITE_BYTES)?,
    })
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(
        b.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        b.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(
        b.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

/// The task name: a fixed-width field the kernel NUL-terminates, whose bytes are whatever the
/// program was called.
fn comm_at(b: &[u8], at: usize) -> Option<String> {
    let raw = b.get(at..at.checked_add(32)?)?;
    let end = raw.iter().position(|c| *c == 0).unwrap_or(raw.len());
    Some(String::from_utf8_lossy(raw.get(..end)?).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `struct taskstats` blob with the fields this reader takes, at the offsets the header
    /// puts them — built here so the parser is tested against the layout it claims to read and
    /// not against itself.
    fn stats_blob(version: u16, pid: u32, tgid: u32, comm: &str) -> Vec<u8> {
        let mut b = vec![0u8; 688]; // sizeof(struct taskstats) at version 17
        let put16 =
            |b: &mut Vec<u8>, at: usize, v: u16| b[at..at + 2].copy_from_slice(&v.to_ne_bytes());
        let put32 =
            |b: &mut Vec<u8>, at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_ne_bytes());
        let put64 =
            |b: &mut Vec<u8>, at: usize, v: u64| b[at..at + 8].copy_from_slice(&v.to_ne_bytes());
        put16(&mut b, field::VERSION, version);
        put32(&mut b, field::EXITCODE, 0x0100); // exited with status 1
        b[field::NICE] = 5;
        b[field::COMM..field::COMM + comm.len()].copy_from_slice(comm.as_bytes());
        put32(&mut b, field::UID, 1000);
        put32(&mut b, field::GID, 100);
        put32(&mut b, field::PID, pid);
        put32(&mut b, field::PPID, 7);
        put32(&mut b, field::BTIME, 1_700_000_000);
        put64(&mut b, field::ETIME, 250_000); // a quarter of a second alive
        put64(&mut b, field::UTIME, 30_000);
        put64(&mut b, field::STIME, 20_000);
        put64(&mut b, field::MINFLT, 412);
        put64(&mut b, field::MAJFLT, 2);
        put64(&mut b, field::HIWATER_RSS, 3_200);
        put64(&mut b, field::READ_SYSCALLS, 11);
        put64(&mut b, field::WRITE_SYSCALLS, 4);
        put64(&mut b, field::READ_BYTES, 8_192);
        put64(&mut b, field::WRITE_BYTES, 4_096);
        put64(&mut b, field::CANCELLED_WRITE_BYTES, 512);
        put64(&mut b, field::BTIME64, 1_700_000_001);
        put32(&mut b, field::TGID, tgid);
        b
    }

    /// One attribute: header then value, padded as netlink pads.
    fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
        let len = NLA_HDRLEN + value.len();
        let mut out = Vec::with_capacity(align4(len));
        out.extend_from_slice(&(len as u16).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(value);
        while out.len() < align4(len) {
            out.push(0);
        }
        out
    }

    /// One netlink message carrying a generic-netlink payload.
    fn message(kind: u16, payload: &[u8]) -> Vec<u8> {
        let len = NLMSG_HDRLEN + GENL_HDRLEN + payload.len();
        let mut out = Vec::with_capacity(align4(len));
        out.extend_from_slice(&(len as u32).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(&0u16.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(&[3, TASKSTATS_GENL_VERSION, 0, 0]); // TASKSTATS_CMD_NEW
        out.extend_from_slice(payload);
        while out.len() < align4(len) {
            out.push(0);
        }
        out
    }

    fn exit_message(version: u16, pid: u32, tgid: u32, comm: &str) -> Vec<u8> {
        let stats = stats_blob(version, pid, tgid, comm);
        let mut aggr = attr(TASKSTATS_TYPE_PID, &pid.to_ne_bytes());
        aggr.extend_from_slice(&attr(TASKSTATS_TYPE_STATS, &stats));
        message(99, &attr(TASKSTATS_TYPE_AGGR_PID, &aggr))
    }

    /// A record the kernel sends for an exited task reads back as the life of it, at the
    /// offsets and in the units the header documents.
    #[test]
    fn an_exit_record_reads_back_as_the_task_that_died() {
        let mut out = Vec::new();
        parse_exits(&exit_message(17, 412, 412, "cc1plus"), &mut out);
        assert_eq!(out.len(), 1);
        let e = &out[0];
        assert_eq!(e.pid, 412);
        assert_eq!(e.tgid, 412);
        assert_eq!(e.ppid, 7);
        assert_eq!(e.comm, "cc1plus");
        assert_eq!((e.uid, e.gid), (1000, 100));
        assert_eq!(e.exitcode, 0x0100);
        assert_eq!(e.nice, 5);
        assert_eq!(
            e.btime, 1_700_000_001,
            "the 64-bit begin time of version 10 on"
        );
        assert_eq!(e.etime_us, 250_000);
        assert_eq!((e.utime_us, e.stime_us), (30_000, 20_000));
        assert_eq!((e.minflt, e.majflt), (412, 2));
        assert_eq!(e.hiwater_rss_kb, 3_200);
        assert_eq!((e.read_syscalls, e.write_syscalls), (11, 4));
        assert_eq!(
            (e.read_bytes, e.write_bytes, e.cancelled_write_bytes),
            (8_192, 4_096, 512)
        );
    }

    /// A record from a kernel whose taskstats predates the fields added since version 1 is
    /// still read — for what it does carry, and with the older begin time and the task's own
    /// id for its group.
    #[test]
    fn an_older_record_is_read_for_what_it_carries() {
        let mut out = Vec::new();
        // version 9: before the 64-bit begin time (10) and the thread group (12)
        parse_exits(&exit_message(9, 77, 0, "sh"), &mut out);
        assert_eq!(out.len(), 1, "a version 9 record still parses");
        assert_eq!(out[0].btime, 1_700_000_000, "the 32-bit begin time");
        assert_eq!(out[0].tgid, 77, "its own id stands in for the group");
        assert_eq!(out[0].comm, "sh");

        // A record too short to hold the I/O counters is not worth reporting.
        let stats = stats_blob(17, 5, 5, "old")[..field::HIWATER_RSS].to_vec();
        let mut aggr = attr(TASKSTATS_TYPE_PID, &5u32.to_ne_bytes());
        aggr.extend_from_slice(&attr(TASKSTATS_TYPE_STATS, &stats));
        let mut out = Vec::new();
        parse_exits(
            &message(99, &attr(TASKSTATS_TYPE_AGGR_PID, &aggr)),
            &mut out,
        );
        assert!(out.is_empty(), "a truncated record is skipped");
    }

    /// A thread exiting is not a process ending: its record names a group it does not lead, and
    /// what it used is charged to the process's own record.
    #[test]
    fn a_thread_exit_is_not_a_process_exit() {
        let mut out = Vec::new();
        parse_exits(&exit_message(17, 413, 412, "worker"), &mut out);
        assert!(out.is_empty(), "{out:?}");
    }

    /// The kernel's messages are whatever the kernel sends: an error, a done marker, an
    /// attribute this reader has no use for, several records in one datagram. None of it may
    /// panic, and the records among it must still come out.
    #[test]
    fn malformed_and_unknown_messages_are_skipped() {
        let mut out = Vec::new();
        // several records in one datagram, with an unknown attribute between them
        let mut buf = exit_message(17, 1, 1, "one");
        buf.extend_from_slice(&message(99, &attr(999, b"nothing to read here")));
        buf.extend_from_slice(&exit_message(17, 2, 2, "two"));
        parse_exits(&buf, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].comm, "one");
        assert_eq!(out[1].comm, "two");

        // an error message, and the errno read out of it
        let mut err = Vec::new();
        err.extend_from_slice(&(NLMSG_HDRLEN as u32 + 4).to_ne_bytes());
        err.extend_from_slice(&NLMSG_ERROR.to_ne_bytes());
        err.extend_from_slice(&0u16.to_ne_bytes());
        err.extend_from_slice(&0u32.to_ne_bytes());
        err.extend_from_slice(&0u32.to_ne_bytes());
        err.extend_from_slice(&(-libc::EPERM).to_ne_bytes());
        assert_eq!(error_in(&err), Some(libc::EPERM));
        let mut out = Vec::new();
        parse_exits(&err, &mut out);
        assert!(out.is_empty());

        // every truncation of a good message: none may panic, whatever it costs the record
        let whole = exit_message(17, 3, 3, "three");
        for cut in 0..whole.len() {
            let mut out = Vec::new();
            parse_exits(&whole[..cut], &mut out);
            assert!(out.len() <= 1);
        }
        // and lengths that claim more than the buffer holds
        let mut lying = whole.clone();
        lying[0..4].copy_from_slice(&u32::MAX.to_ne_bytes());
        let mut out = Vec::new();
        parse_exits(&lying, &mut out);
        assert!(out.is_empty());
        assert_eq!(error_in(&[]), None);
        assert_eq!(family_id(&[]), None);
    }

    /// A kernel with records and no room for them must not stop the reading: the loss is
    /// counted and the drain carries on, or one busy interval would cost every interval after
    /// it. (Provoking a real overflow needs privilege and tens of thousands of exits in one
    /// interval, so what is asserted here is the decision the drain makes.)
    #[test]
    fn a_dropped_record_does_not_stop_the_drain() {
        assert_eq!(after_error(Some(libc::ENOBUFS)), Next::Dropped);
        assert_eq!(after_error(Some(libc::EINTR)), Next::Again);
        assert_eq!(after_error(Some(libc::EAGAIN)), Next::Done);
        assert_eq!(after_error(Some(libc::EBADF)), Next::Done);
        assert_eq!(after_error(None), Next::Done);
    }

    /// Both strings this listener sends carry their terminator inside the attribute, because
    /// the kernel reads one byte fewer than the length it is given: a cpumask sent without it
    /// arrives as `0-` and is rejected, which is a whole feature lost to one byte.
    #[test]
    fn the_strings_sent_carry_their_terminator() {
        for payload in [format!("0-{}\0", 3), format!("{TASKSTATS_GENL_NAME}\0")] {
            let msg = request(1, TASKSTATS_CMD_GET, 1, 1, payload.as_bytes());
            let (_, value) = attrs(&msg[NLMSG_HDRLEN + GENL_HDRLEN..])
                .next()
                .expect("an attribute");
            assert_eq!(value.last(), Some(&0), "{payload:?} lost its terminator");
            assert_eq!(value.len(), payload.len());
        }
    }

    /// The requests this listener sends: a header the kernel will accept, and the attribute it
    /// asked about, padded as netlink requires.
    #[test]
    fn a_request_is_a_netlink_message() {
        let msg = request(
            GENL_ID_CTRL,
            CTRL_CMD_GETFAMILY,
            1,
            CTRL_ATTR_FAMILY_NAME,
            b"TASKSTATS\0",
        );
        assert_eq!(msg.len() % 4, 0, "netlink pads to four bytes");
        assert_eq!(
            u32::from_ne_bytes(msg[..4].try_into().unwrap()) as usize,
            msg.len(),
            "the length in the header is the length of the message"
        );
        assert_eq!(
            u16::from_ne_bytes(msg[4..6].try_into().unwrap()),
            GENL_ID_CTRL
        );
        assert_eq!(
            u16::from_ne_bytes(msg[6..8].try_into().unwrap()),
            NLM_F_REQUEST
        );
        assert_eq!(msg[16], CTRL_CMD_GETFAMILY);
        // the attribute: length, type, then the name
        let (kind, value) = attrs(&msg[NLMSG_HDRLEN + GENL_HDRLEN..])
            .next()
            .expect("an attribute");
        assert_eq!(kind, CTRL_ATTR_FAMILY_NAME);
        assert_eq!(value, b"TASKSTATS\0");

        // and the reply to it, read for the family id the kernel assigned
        let reply = message(
            GENL_ID_CTRL,
            &attr(CTRL_ATTR_FAMILY_ID, &27u16.to_ne_bytes()),
        );
        assert_eq!(family_id(&reply), Some(27));
    }
}
