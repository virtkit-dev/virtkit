//! Records guest kernel OOM kills for the host.
//!
//! A guest OOM kill otherwise appears to the host only as a command terminated by signal 9.
//! A PID 1 thread follows `/dev/kmsg`, stores OOM records in [`LOG`] on the agent's `/run`
//! tmpfs, and serves them through `vk-agent oomkills` over the exec channel. The host reads
//! them with [`crate::memmark`] data at stage end, after a CI job's final stage, after
//! `vk run`, and during `vk status`.
//!
//! The watcher is always enabled. It blocks on `/dev/kmsg` while idle, limits the log to
//! [`MAX_KILLS`] records, and limits console warnings to [`WARN_KILLS`]. These bounds prevent
//! repeated kills from exhausting the guest RAM backing `/run`.

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::Path;

use log::warn;
use vk_core::oomkills::{OOM_PREFIX, OOM_PREFIX_CGROUP};

pub(crate) use vk_core::oomkills::Kill;

/// OOM records on the agent-mounted `/run` tmpfs, outside the image.
const LOG: &str = "/run/vk-oomkills";

const KMSG: &str = "/dev/kmsg";

/// Maximum recorded kills, bounding the RAM consumed by a runaway guest.
const MAX_KILLS: usize = 64;

/// Maximum kills announced in the retained guest console log.
const WARN_KILLS: usize = 4;

/// A kmsg record's syslog priority is `facility * 8 + level`, and the kernel's own records
/// have facility 0. `/dev/kmsg` is writable, so a guest process could otherwise forge kills:
/// its writes get facility 1 (LOG_USER) and are rejected here.
const MAX_KERNEL_PRIO: u32 = 8;

/// Read buffer for `/dev/kmsg`. A record is at most `CONSOLE_EXT_LOG_MAX` (8 KiB) and
/// `devkmsg_read` fails with EINVAL when the buffer cannot hold one whole, so this is
/// deliberately larger than the default 8 KiB.
const KMSG_BUF: usize = 16 * 1024;

/// Parse a kmsg record (`prio,seq,uptime_us,flags;message`) into a [`Kill`] when the message
/// is an OOM kill announcement the kernel wrote; `None` for every other record.
///
/// The kernel's line (mm/oom_kill.c): `<prefix>: Killed process <pid> (<comm>) total-vm:<n>kB,
/// anon-rss:<n>kB, file-rss:<n>kB, shmem-rss:<n>kB, UID:<u> pgtables:<n>kB oom_score_adj:<n>`,
/// the prefix being [`OOM_PREFIX`] or [`OOM_PREFIX_CGROUP`].
fn parse_kmsg(record: &str) -> Option<Kill> {
    let (header, msg) = record.split_once(';')?;
    let mut fields = header.split(',');
    let prio: u32 = fields.next()?.trim().parse().ok()?;
    if prio >= MAX_KERNEL_PRIO {
        return None;
    }
    let uptime_us: u64 = fields.nth(1)?.trim().parse().ok()?;
    let (prefix, rest) = msg.split_once(": Killed process ")?;
    let cgroup = match prefix.trim() {
        OOM_PREFIX => false,
        OOM_PREFIX_CGROUP => true,
        _ => return None,
    };
    let (pid, rest) = rest.split_once(" (")?;
    let pid: u32 = pid.parse().ok()?;
    // The comm is the kernel's own, 15 bytes at most, but may hold ')' or spaces: cut at the
    // ") total-vm:" that always follows it rather than at the first ')'. A process can set
    // its comm to that marker and make the cut land early, leaving nothing — rejected here
    // so a victim cannot hide itself, and so the two sides accept exactly the same records.
    let (comm, rest) = rest.split_once(") total-vm:")?;
    if comm.is_empty() {
        return None;
    }
    let anon_rss_kb: u64 = rest
        .split(',')
        .map(str::trim)
        .find_map(|f| f.strip_prefix("anon-rss:"))?
        .strip_suffix("kB")?
        .parse()
        .ok()?;
    Some(Kill {
        uptime_us,
        pid,
        comm: comm.to_string(),
        anon_rss: anon_rss_kb.checked_mul(1024)?,
        cgroup,
    })
}

/// Append OOM kills from `kmsg` to `log`, stopping at [`MAX_KILLS`]. Return when the input
/// ends or fails; subsequent kills remain unrecorded. Generic inputs keep record handling
/// testable without a guest.
fn follow(kmsg: impl BufRead, mut log: impl Write) -> std::io::Result<()> {
    let mut kmsg = kmsg;
    let mut recorded = 0usize;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match kmsg.read_until(b'\n', &mut buf) {
            // A record overwritten while it was being read (EPIPE): the kernel tells us we
            // fell behind; the next read resumes at the oldest record still there.
            Err(e) if e.raw_os_error() == Some(libc::EPIPE) => continue,
            Err(e) => return Err(e),
            Ok(0) => return Ok(()),
            Ok(_) => {}
        }
        // Per record, not per stream: kmsg escapes non-ASCII, but a driver's record could
        // still arrive undecodable, and one bad record must not end the watch.
        let Some(kill) = std::str::from_utf8(&buf).ok().and_then(parse_kmsg) else {
            continue;
        };
        if recorded < WARN_KILLS {
            warn!(
                "vk-agent: guest OOM: kernel killed {} (pid {}, {} bytes anon-rss) at +{}s",
                kill.comm,
                kill.pid,
                kill.anon_rss,
                kill.uptime_us / 1_000_000
            );
        }
        log.write_all(kill.render().as_bytes())?;
        recorded = recorded.saturating_add(1);
        if recorded >= MAX_KILLS {
            warn!("vk-agent: guest OOM: {MAX_KILLS} kills recorded; no longer counting");
            return Ok(());
        }
    }
}

/// Start the watcher after PID 1's last fork, like [`crate::memmark::watch`], so children
/// cannot inherit locks held by vanished threads. Skip guests without the agent-mounted
/// `/run` tmpfs to avoid writing the log into the image.
pub(crate) fn watch() {
    if !crate::memmark::is_own_mount(Path::new("/run")) {
        return;
    }
    let kmsg = match File::open(KMSG) {
        Ok(f) => f,
        Err(e) => {
            warn!("vk-agent oomkills: opening {KMSG}: {e} — OOM kills will not be recorded");
            return;
        }
    };
    // Exclusive creation avoids appending to an image-provided file. Set the mode at creation
    // so a guest process cannot forge or erase records before a later chmod.
    use std::os::unix::fs::OpenOptionsExt;
    let log = match std::fs::OpenOptions::new()
        .append(true)
        .create_new(true)
        .mode(0o644)
        .open(LOG)
    {
        Ok(f) => f,
        Err(e) => {
            warn!("vk-agent oomkills: creating {LOG}: {e} — OOM kills will not be recorded");
            return;
        }
    };
    let started = std::thread::Builder::new()
        .name("oomkills".into())
        .spawn(move || {
            // Start after existing boot records. `run_init` has not launched commands yet;
            // `run_service` has already forked the entrypoint and can miss an immediate kill.
            let mut kmsg = kmsg;
            if let Err(e) = kmsg.seek(SeekFrom::End(0)) {
                warn!("vk-agent oomkills: seeking {KMSG}: {e}");
            }
            if let Err(e) = follow(BufReader::with_capacity(KMSG_BUF, kmsg), log) {
                // Remove an incomplete log so the host does not mistake it for a complete count.
                warn!("vk-agent oomkills: following {KMSG}: {e} — no longer recording");
                remove_log();
            }
        });
    if let Err(e) = started {
        warn!("vk-agent oomkills: starting the OOM watcher failed: {e}");
        remove_log();
    }
}

fn remove_log() {
    if let Err(e) = std::fs::remove_file(LOG) {
        warn!("vk-agent oomkills: removing {LOG}: {e}");
    }
}

/// `vk-agent oomkills`: print the recorded kills, one [`Kill::render`] line each, for the host.
/// Exit 1 when the guest was not watched (no log), so the host reports nothing rather than
/// "no kills"; an empty output with exit 0 is a watched guest that lost no process. A write
/// that fails also exits 1 — a truncated list would under-report.
pub fn main(args: &[String]) -> i32 {
    if !args.is_empty() {
        eprintln!("usage: vk-agent oomkills");
        return 2;
    }
    let text = match std::fs::read_to_string(LOG) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("oomkills: this guest's OOM kills were not recorded: {e}");
            return 1;
        }
    };
    let mut out = std::io::stdout().lock();
    for kill in Kill::parse_all(&text, MAX_KILLS) {
        if let Err(e) = out.write_all(kill.render().as_bytes()) {
            eprintln!("oomkills: writing the kills: {e}");
            return 1;
        }
    }
    match out.flush() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("oomkills: writing the kills: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORD: &str = "3,1302,48291057,-;Out of memory: Killed process 1234 (cc1plus) \
        total-vm:2216564kB, anon-rss:1998812kB, file-rss:1024kB, shmem-rss:0kB, UID:0 \
        pgtables:4100kB oom_score_adj:0\n";

    #[test]
    fn a_kernel_oom_record_parses_to_the_victim() {
        assert_eq!(
            parse_kmsg(RECORD).unwrap(),
            Kill {
                uptime_us: 48_291_057,
                pid: 1234,
                comm: "cc1plus".into(),
                anon_rss: 1_998_812 * 1024,
                cgroup: false,
            }
        );
    }

    #[test]
    fn a_cgroup_kill_is_marked_and_keeps_a_comm_with_spaces() {
        let cg = parse_kmsg(
            "3,9,100,-;Memory cgroup out of memory: Killed process 7 (a b) total-vm:1kB, \
             anon-rss:2kB, file-rss:0kB, shmem-rss:0kB, UID:0 pgtables:0kB oom_score_adj:0",
        )
        .unwrap();
        assert!(cg.cgroup && cg.comm == "a b" && cg.anon_rss == 2048);
    }

    #[test]
    fn other_records_are_not_kills() {
        for r in [
            "6,1,0,-;Linux version 6.18.49",
            "4,2,5,-;cc1plus invoked oom-killer: gfp_mask=0x140dca, order=0",
            "3,3,6,-;Out of memory: no killable process",
            "not a record",
            "",
        ] {
            assert_eq!(parse_kmsg(r), None, "{r:?}");
        }
    }

    #[test]
    fn a_record_a_guest_process_wrote_is_not_a_kill() {
        // /dev/kmsg is writable: a userspace write lands at facility 1 (prio >= 8), so a
        // process cannot invent victims for the host to report.
        let forged = RECORD.replacen("3,", "11,", 1);
        assert_eq!(parse_kmsg(&forged), None);
    }

    #[test]
    fn a_comm_shaped_like_the_end_marker_cannot_hide_its_kill() {
        // `prctl(PR_SET_NAME, ") total-vm:")` makes the cut land early; an empty comm is
        // rejected rather than written and then dropped by the host's parser.
        let evil = RECORD.replace("(cc1plus)", "() total-vm:)");
        assert_eq!(parse_kmsg(&evil), None);
    }

    #[test]
    fn an_anon_rss_too_large_to_scale_to_bytes_is_no_kill() {
        let huge = RECORD.replace("anon-rss:1998812kB", &format!("anon-rss:{}kB", u64::MAX));
        assert_eq!(parse_kmsg(&huge), None);
    }

    #[test]
    fn a_record_without_anon_rss_is_no_kill() {
        let no_rss = RECORD.replace("anon-rss:1998812kB, ", "");
        assert_eq!(parse_kmsg(&no_rss), None);
    }

    #[test]
    fn follow_records_kills_and_skips_everything_else() {
        let stream = format!("6,1,0,-;Linux version 6.18.49\n{RECORD}not a record\n");
        let mut log = Vec::new();
        follow(stream.as_bytes(), &mut log).unwrap();
        assert_eq!(
            Kill::parse_all(&String::from_utf8(log).unwrap(), 8).len(),
            1
        );
    }

    #[test]
    fn follow_survives_a_record_that_is_not_utf8() {
        // One undecodable record must not end the watch: the kill after it is still recorded.
        let mut stream = b"3,1,0,-;\xff\xfe bad\n".to_vec();
        stream.extend_from_slice(RECORD.as_bytes());
        let mut log = Vec::new();
        follow(&stream[..], &mut log).unwrap();
        assert_eq!(
            Kill::parse_all(&String::from_utf8(log).unwrap(), 8).len(),
            1
        );
    }

    #[test]
    fn follow_stops_recording_at_the_cap() {
        // A guest out of memory can kill without end; the tmpfs it writes to is its own RAM.
        let stream: String = std::iter::repeat_n(RECORD, MAX_KILLS + 20).collect();
        let mut log = Vec::new();
        follow(stream.as_bytes(), &mut log).unwrap();
        assert_eq!(
            Kill::parse_all(&String::from_utf8(log).unwrap(), usize::MAX).len(),
            MAX_KILLS
        );
    }

    #[test]
    fn follow_reports_a_log_it_cannot_append_to() {
        // A full tmpfs must surface, not be swallowed: the caller drops the log so the host
        // reports nothing rather than a count it cannot vouch for.
        struct Full;
        impl Write for Full {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::StorageFull))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(follow(RECORD.as_bytes(), Full).is_err());
    }
}
