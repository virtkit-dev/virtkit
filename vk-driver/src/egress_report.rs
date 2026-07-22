//! The switch's egress-denial channel, shared by the switch (writer) and the gitlab
//! executor (reader).
//!
//! The switch runs as a detached job child; the executor's `run` stages are separate,
//! short-lived processes. So a job that fails because the switch refused an egress cannot
//! see why — the refusal is in the switch's host-side log. Rather than scrape that human
//! log, the switch appends a typed record here per denial and each `run` stage drains the
//! ones added since the previous stage, reporting them into the job trace. This module
//! owns the (append-only, one-record-per-line) format so the two ends never drift.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// The kind of flow the switch refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
    Dns,
}

impl Proto {
    fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Dns => "dns",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        match s {
            "tcp" => Some(Proto::Tcp),
            "udp" => Some(Proto::Udp),
            "dns" => Some(Proto::Dns),
            _ => None,
        }
    }
}

/// One egress request the switch refused: its protocol and destination (an `ip:port` for
/// tcp/udp, a DNS name for dns).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    pub proto: Proto,
    pub target: String,
}

impl Denial {
    /// A human line for the job trace — the shape the switch also logs for operators.
    pub fn display(&self) -> String {
        format!("egress denied ({}) {}", self.proto.as_str(), self.target)
    }
}

/// Append a denial to `path` (create-or-append). A DNS `target` is guest-controlled, so
/// control characters — which would otherwise tear the one-record-per-line format or inject
/// forged lines into the job trace — are replaced with `U+FFFD`; the record is then one
/// unambiguous `proto\ttarget` line. Written in a single `write_all` so concurrent switch
/// tasks appending at once don't interleave fragments of a line. Best-effort: any IO error
/// is dropped — a lost denial notice must never disturb the job or the switch's forwarding.
pub fn append(path: &Path, proto: Proto, target: &str) {
    let target: String = target
        .chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect();
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(format!("{}\t{}\n", proto.as_str(), target).as_bytes());
    }
}

/// Read the denials appended to `path` since byte `offset`, returning them with the new
/// offset to persist. Only whole lines are consumed — a partial trailing line (the writer
/// mid-append) is left for next time, so a record is never torn. A file shorter than
/// `offset` was truncated (e.g. removed and recreated) and is re-read from the start; the
/// per-job log is otherwise append-only and never rotated. A missing file (the job had no
/// egress restriction, so the switch wrote none) yields no denials.
pub fn read_since(path: &Path, offset: u64) -> (Vec<Denial>, u64) {
    let Ok(mut f) = std::fs::File::open(path) else {
        return (Vec::new(), offset);
    };
    let mut start = offset;
    if f.metadata().map(|m| m.len()).unwrap_or(0) < start {
        start = 0;
    }
    if f.seek(SeekFrom::Start(start)).is_err() {
        return (Vec::new(), offset);
    }
    let mut buf = Vec::new();
    if f.read_to_end(&mut buf).is_err() {
        return (Vec::new(), start);
    }
    // Consume only through the last newline; a partial trailing line stays unread.
    let consumed = match buf.iter().rposition(|&b| b == b'\n') {
        Some(nl) => nl + 1,
        None => return (Vec::new(), start),
    };
    let mut out = Vec::new();
    for line in String::from_utf8_lossy(&buf[..consumed]).lines() {
        if let Some((p, target)) = line.split_once('\t')
            && let Some(proto) = Proto::parse(p)
        {
            out.push(Denial {
                proto,
                target: target.to_string(),
            });
        }
    }
    (out, start + consumed as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_resumes_from_offset() {
        let dir = std::env::temp_dir().join(format!("vk-egress-report-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("egress-denied.log");
        let _ = std::fs::remove_file(&path);

        append(&path, Proto::Dns, "wallix.com");
        append(&path, Proto::Tcp, "93.184.216.34:443");
        let (first, off) = read_since(&path, 0);
        assert_eq!(
            first,
            vec![
                Denial {
                    proto: Proto::Dns,
                    target: "wallix.com".into()
                },
                Denial {
                    proto: Proto::Tcp,
                    target: "93.184.216.34:443".into()
                },
            ]
        );

        // Nothing new since the recorded offset.
        assert_eq!(read_since(&path, off), (Vec::new(), off));

        // A later append is picked up from the offset alone.
        append(&path, Proto::Udp, "8.8.8.8:53");
        let (next, _) = read_since(&path, off);
        assert_eq!(
            next,
            vec![Denial {
                proto: Proto::Udp,
                target: "8.8.8.8:53".into()
            }]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn leaves_a_partial_trailing_line_unconsumed() {
        let dir = std::env::temp_dir().join(format!("vk-egress-partial-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("d.log");
        let _ = std::fs::remove_file(&path);
        // A complete record followed by a torn one (no newline yet).
        std::fs::write(&path, b"dns\ta.com\ntcp\t1.2.3.4:44").unwrap();
        let (got, off) = read_since(&path, 0);
        assert_eq!(
            got,
            vec![Denial {
                proto: Proto::Dns,
                target: "a.com".into()
            }]
        );
        // The torn line completes; the next read returns only it.
        std::fs::write(&path, b"dns\ta.com\ntcp\t1.2.3.4:443\n").unwrap();
        let (got, _) = read_since(&path, off);
        assert_eq!(
            got,
            vec![Denial {
                proto: Proto::Tcp,
                target: "1.2.3.4:443".into()
            }]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sanitizes_control_chars_in_a_guest_controlled_name() {
        let dir = std::env::temp_dir().join(format!("vk-egress-sanitize-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("d.log");
        let _ = std::fs::remove_file(&path);
        // A guest DNS query smuggling a newline + tab, trying to forge a second record and
        // tear the format. It must stay one record with the control chars neutralized.
        append(&path, Proto::Dns, "evil\ntcp\t10.0.0.1:22\tx.com");
        let (got, _) = read_since(&path, 0);
        assert_eq!(
            got,
            vec![Denial {
                proto: Proto::Dns,
                target: "evil\u{fffd}tcp\u{fffd}10.0.0.1:22\u{fffd}x.com".into()
            }]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
