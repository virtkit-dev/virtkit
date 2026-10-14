//! Unusual things a job's machinery logged while it ran: not why the job failed, but what an
//! operator should know about the machine. Today a virtio-fs request whose missing
//! notification the VMM's stall check detected and retried; in time a full disk, I/O or memory
//! errors. Read from the job directory before cleanup removes it, they go into the job trace,
//! the node's log and the hub's record of the job.

use std::ffi::OsStr;
use std::io::{BufRead, BufReader};
use std::path::Path;

use vk_hub_proto::job::{JobEvent, JobEventKind, MAX_JOB_EVENTS};

/// Set by the node's job driver for the executor commands it runs: the driver reports the job's
/// events itself, into the trace and to the hub, so the executor leaves them out. Without it —
/// a classic gitlab-runner custom executor — the executor writes them into the trace.
pub(crate) const FROM_NODE_ENV: &str = "VK_JOB_EVENTS_FROM_NODE";

/// What libkrun's virtio-fs stall check writes to the VMM log when it suspects a lost
/// notification (`third_party/libkrun/src/devices/src/virtio/fs/worker.rs`): at WARN the first
/// time per episode, at DEBUG while the same ring positions come back.
const STALL_MARKERS: [&[u8]; 2] = [b"suspected lost kick", b"suspected lost interrupt"];

/// The events a job's VMM log records, each kind once, counted, with its first occurrence. A
/// virtio-fs stall counts its warnings ([`JobEvent::count`]). An unreadable or missing log (a
/// VM that never started) has none.
pub(crate) fn from_vmm_log(path: &Path) -> Vec<JobEvent> {
    match std::fs::File::open(path) {
        Ok(file) => from_vmm_reader(BufReader::new(file)),
        Err(_) => Vec::new(),
    }
}

/// Line by line, in bytes: the log is large under `VIRTKIT_DEBUG`, and not always UTF-8.
fn from_vmm_reader(log: impl BufRead) -> Vec<JobEvent> {
    let mut stalls = 0u32;
    let mut first = None;
    for line in log.split(b'\n') {
        // Keep events already read if a later read fails.
        let Ok(line) = line else { break };
        let Some((b"WARN", message)) = split_prefix(&line) else {
            continue;
        };
        if STALL_MARKERS.iter().any(|marker| contains(message, marker)) {
            stalls = stalls.saturating_add(1);
            first.get_or_insert_with(|| String::from_utf8_lossy(message).into_owned());
        }
    }
    let mut events: Vec<JobEvent> = first
        .map(|first| JobEvent::new(JobEventKind::VirtioFsStall, stalls, &first))
        .into_iter()
        .collect();
    events.truncate(MAX_JOB_EVENTS);
    events
}

/// A log line's level and message, from env_logger's `[timestamp LEVEL target] ` prefix; `None`
/// for a line without one, such as a message's continuation. The VMM's logger ignores RUST_LOG
/// and RUST_LOG_STYLE (`libkrun_sys::boot`), so its WARN lines are all there, uncoloured.
fn split_prefix(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let rest = line.strip_prefix(b"[")?;
    let end = rest.windows(2).position(|w| w == b"] ")?;
    let level = rest[..end]
        .split(u8::is_ascii_whitespace)
        .filter(|word| !word.is_empty())
        .nth(1)?;
    Some((level, &rest[end + 2..]))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The events the executor writes into the trace, given [`FROM_NODE_ENV`]'s value: none under
/// a node's driver, which reports them itself.
pub(crate) fn for_executor(vmm_log: &Path, from_node: Option<&OsStr>) -> Vec<JobEvent> {
    match from_node {
        Some(_) => Vec::new(),
        None => from_vmm_log(vmm_log),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lost interrupt as the VMM warns of it the first time.
    const STALL: &str = "[2026-10-13T12:58:12.787949Z WARN  krun_devices::virtio::fs::worker] \
        virtio-fs /builds/git/wab: queue 1: 1 completion(s) past used_event for 10s \
        (used_event 185, next_used 186, avail_idx 186; msix enabled: v0 unmasked gsi 28 routed, \
        v1 unmasked gsi 29 routed; config vector 0, queue vectors 0x1; intx isr 0x0): \
        suspected lost interrupt, signalling again";

    /// A lost kick whose chain could not be popped, at WARN, then the same positions again, at
    /// DEBUG.
    const KICK: &str = "[2026-10-13T12:58:22.791002Z WARN  krun_devices::virtio::fs::worker] \
        virtio-fs /builds/git/wab: queue 1: 1 request(s) available and not popped for 10s \
        (avail_idx 190, next_avail 189, used_event 188, next_used 189; msix enabled: v0 unmasked \
        gsi 28 routed, v1 unmasked gsi 29 routed; config vector 0, queue vectors 0x1; intx isr \
        0x0): suspected lost kick, serving them\n\
        [2026-10-13T12:58:22.791101Z WARN  krun_devices::virtio::fs::worker] \
        virtio-fs /builds/git/wab: queue 1: the chain at next_avail 189 could not be popped\n\
        [2026-10-13T12:58:32.795310Z DEBUG krun_devices::virtio::fs::worker] \
        virtio-fs /builds/git/wab: queue 1: 1 request(s) available and not popped for 10s \
        (avail_idx 190, next_avail 189, used_event 188, next_used 189; msix enabled: v0 unmasked \
        gsi 28 routed, v1 unmasked gsi 29 routed; config vector 0, queue vectors 0x1; intx isr \
        0x0): suspected lost kick, serving them";

    #[test]
    fn a_vmm_log_s_stall_warnings_are_one_counted_event_with_the_first_of_them() {
        let log = format!(
            "[2026-10-13T12:58:00Z WARN  krun_devices::virtio::device] Received request for \
             unknown features page.\n{STALL}\n{KICK}\n"
        );
        let events = from_vmm_reader(log.as_bytes());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, JobEventKind::VirtioFsStall);
        assert_eq!(events[0].count, 2, "the DEBUG repeat is not counted");
        assert!(
            events[0]
                .detail
                .starts_with("virtio-fs /builds/git/wab: queue 1:")
        );
        assert!(
            events[0]
                .detail
                .ends_with("suspected lost interrupt, signalling again")
        );
        assert_eq!(
            events[0].to_string(),
            format!("virtio-fs stall (2 times): {}", events[0].detail)
        );
    }

    #[test]
    fn repeats_at_debug_alone_are_no_event() {
        let debug = STALL.replace("Z WARN  ", "Z DEBUG ");
        assert!(from_vmm_reader(debug.as_bytes()).is_empty());
    }

    #[test]
    fn a_log_that_is_not_utf8_is_read_and_its_detail_kept_lossily() {
        let mut stall = format!("{STALL}\n").into_bytes();
        stall[STALL.find("wab").unwrap() + 1] = 0xff;
        let mut log = b"[t INFO x] \xff\xfe\n".to_vec();
        log.extend_from_slice(&stall);
        let events = from_vmm_reader(&log[..]);
        assert_eq!(events.len(), 1);
        assert!(
            events[0]
                .detail
                .starts_with("virtio-fs /builds/git/w\u{fffd}b:")
        );
    }

    #[test]
    fn a_quiet_or_missing_vmm_log_has_no_events() {
        assert!(
            from_vmm_reader(&b"[t WARN x] Received request for unknown features page.\n"[..])
                .is_empty()
        );
        assert!(from_vmm_log(Path::new("/nonexistent/console.vmm.log")).is_empty());
    }

    #[test]
    fn the_executor_reports_events_only_outside_a_node() {
        let dir = std::env::temp_dir().join(format!("vk-jobevents-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("console.vmm.log");
        std::fs::write(&log, format!("{STALL}\n")).unwrap();
        let outside = for_executor(&log, None);
        let under = for_executor(&log, Some(OsStr::new("1")));
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(outside.len(), 1);
        assert!(under.is_empty());
    }
}
