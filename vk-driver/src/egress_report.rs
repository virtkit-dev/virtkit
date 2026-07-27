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

/// Append one audited external contact to the audit channel `path` (create-or-append). Audit
/// mode (see switch's `EgressGuard`) records both the allowed external names the guest resolves
/// (`kind = "name"`) and the external IPs it dials without a matching resolution (`kind = "ip"`),
/// interleaved in one channel; the readers below split them back apart by kind. Unlike the
/// denial channel this is drained once at the end of the job rather than per stage. `value` is
/// guest-controlled, so — like `append` — control characters are neutralized to `U+FFFD` (no
/// forged or torn lines in the summary) and the record is one `kind\tvalue` `write_all`, so
/// concurrent stage switches sharing a build's channel never interleave fragments. Best-effort:
/// IO errors are dropped, exactly like `append`.
fn append_audit(path: &Path, kind: &str, value: &str) {
    let value: String = value
        .chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect();
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(format!("{kind}\t{value}\n").as_bytes());
    }
}

/// Record one contacted external domain (see [`append_audit`]).
pub fn append_contact(path: &Path, name: &str) {
    append_audit(path, "name", name);
}

/// Record one external `ip:port` the guest dialed directly, i.e. without a resolution the
/// switch handed it — the domains summary would otherwise miss it (see [`append_audit`]).
pub fn append_ip_contact(path: &Path, ip_port: &str) {
    append_audit(path, "ip", ip_port);
}

/// Read the audit channel `path` and return each `kind` contact paired with its count, ordered
/// most-contacted first (ties broken by value) for a stable job-trace summary. A missing file
/// (audit off, or the switch recorded nothing) yields an empty list. Unlike the denial channel
/// there is no offset: the whole file is one job's contacts, read once.
fn read_audit(path: &Path, kind: &str) -> Vec<(String, usize)> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for value in text.lines().filter_map(|l| {
        l.split_once('\t')
            .filter(|(k, _)| *k == kind)
            .map(|(_, v)| v.trim())
            .filter(|v| !v.is_empty())
    }) {
        *counts.entry(value).or_default() += 1;
    }
    let mut counts: Vec<(String, usize)> = counts
        .into_iter()
        .map(|(n, c)| (n.to_string(), c))
        .collect();
    counts.sort_by(|(an, ac), (bn, bc)| bc.cmp(ac).then_with(|| an.cmp(bn)));
    counts
}

/// The contacted domains, most-contacted first (see [`read_audit`]).
pub fn read_contacts(path: &Path) -> Vec<(String, usize)> {
    read_audit(path, "name")
}

/// The directly-dialed external `ip:port`s, most-contacted first (see [`read_audit`]).
pub fn read_ip_contacts(path: &Path) -> Vec<(String, usize)> {
    read_audit(path, "ip")
}

/// Format `contacts` as a job-trace block: the line `virtkit: {header}:` followed by one
/// indented `value (xN)` line per contact, counts aligned, most-contacted first. `None` when
/// there is nothing to report, so the caller prints nothing.
fn summary(contacts: &[(String, usize)], header: &str) -> Option<String> {
    if contacts.is_empty() {
        return None;
    }
    // Char count, not byte length: the `{:<width$}` padding below measures in chars, so a
    // multibyte value (e.g. a sanitized `U+FFFD`) would misalign the count column otherwise.
    let width = contacts
        .iter()
        .map(|(n, _)| n.chars().count())
        .max()
        .unwrap_or(0);
    let mut s = format!("virtkit: {header}:");
    for (value, count) in contacts {
        s.push_str(&format!("\n  {value:<width$}  (x{count})"));
    }
    Some(s)
}

/// The "domains contacted" summary for a trace. `header` names the phase (e.g. `external
/// domains contacted (audit)`), letting a `vk run` that both builds and boots distinguish its
/// build-phase summary from the guest one. Shared by the gitlab executor, `vk run`, and
/// `vk build` so every surface reads identically.
pub fn contacts_summary(path: &Path, header: &str) -> Option<String> {
    summary(&read_contacts(path), header)
}

/// The "IPs/ports contacted" summary for a trace — the guest's direct-IP egress the domains
/// summary cannot show. Same shape and phase-header convention as [`contacts_summary`].
pub fn ip_contacts_summary(path: &Path, header: &str) -> Option<String> {
    summary(&read_ip_contacts(path), header)
}

/// The bytes the switch has forwarded, as it last published them: `(sent, received)` from
/// the guests' side. `None` when there is no file — no switch, or one that has not published
/// yet. Payload only, and egress only: the framing around it, the retransmits under it and
/// the vsock carrying it are the host's traffic, and what the guests send each other is
/// switched at layer 2 without ever being proxied.
pub fn read_net_bytes(path: &Path) -> Option<(u64, u64)> {
    let text = std::fs::read_to_string(path).ok()?;
    // Each line is one switch's traffic since it last wrote, so the total is their sum —
    // over every publish, and over every switch that shared the channel (a build's stages
    // each have their own LAN). One publish is one small `write_all` to an `O_APPEND` fd,
    // which the kernel does not split, so a reader never sees half a record — and a line
    // that does not hold two numbers is passed over rather than read as a figure.
    let total = text.lines().fold((0u64, 0u64), |(sent, received), line| {
        let mut fields = line.split_whitespace();
        match (
            fields.next().and_then(|f| f.parse::<u64>().ok()),
            fields.next().and_then(|f| f.parse::<u64>().ok()),
        ) {
            (Some(s), Some(r)) => (sent.saturating_add(s), received.saturating_add(r)),
            _ => (sent, received),
        }
    });
    Some(total)
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

    /// The byte channel is summed, not read: several switches append to one file, each
    /// writing only what it forwarded since its last line.
    #[test]
    fn network_bytes_are_summed_across_writers() {
        let dir = std::env::temp_dir().join(format!("vk-net-bytes-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("net.bytes");
        let _ = std::fs::remove_file(&path);

        // No channel: nothing forwarded, and nothing to say.
        assert_eq!(read_net_bytes(&path), None);

        // Two switches, publishing as they go.
        std::fs::write(&path, "100 2000\n50 0\n0 3000\n").unwrap();
        assert_eq!(read_net_bytes(&path), Some((150, 5000)));

        // A line torn by a switch killed mid-write counts for nothing rather than wrongly.
        std::fs::write(&path, "100 2000\n7").unwrap();
        assert_eq!(read_net_bytes(&path), Some((100, 2000)));
        let _ = std::fs::remove_dir_all(&dir);
    }

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
    fn contacts_are_counted_and_ranked() {
        let dir = std::env::temp_dir().join(format!("vk-egress-audit-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("egress-audit.log");
        let _ = std::fs::remove_file(&path);

        // Missing file: no contacts.
        assert_eq!(read_contacts(&path), Vec::<(String, usize)>::new());

        for name in [
            "crates.io",
            "github.com",
            "crates.io",
            "crates.io",
            "github.com",
        ] {
            append_contact(&path, name);
        }
        // Most-contacted first; equal counts fall back to name order.
        assert_eq!(
            read_contacts(&path),
            vec![("crates.io".into(), 3), ("github.com".into(), 2)]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn names_and_ips_share_the_channel_without_crossing() {
        let dir = std::env::temp_dir().join(format!("vk-egress-audit-ip-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("egress-audit.log");
        let _ = std::fs::remove_file(&path);

        append_contact(&path, "crates.io");
        append_ip_contact(&path, "93.184.216.34:443");
        append_ip_contact(&path, "93.184.216.34:443");
        append_contact(&path, "crates.io");

        // Each reader sees only its own kind, counted independently.
        assert_eq!(read_contacts(&path), vec![("crates.io".into(), 2)]);
        assert_eq!(
            read_ip_contacts(&path),
            vec![("93.184.216.34:443".into(), 2)]
        );

        let summary = ip_contacts_summary(&path, "external IPs/ports contacted (audit)").unwrap();
        let lines: Vec<&str> = summary.lines().collect();
        assert_eq!(lines[0], "virtkit: external IPs/ports contacted (audit):");
        assert!(lines[1].starts_with("  93.184.216.34:443") && lines[1].ends_with("(x2)"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_sanitizes_control_chars_and_formats_summary() {
        let dir = std::env::temp_dir().join(format!("vk-egress-audit-fmt-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("egress-audit.log");
        let _ = std::fs::remove_file(&path);

        // Missing file: no summary to print.
        assert_eq!(contacts_summary(&path, "domains contacted (audit)"), None);

        // A guest DNS name smuggling a newline, trying to forge a second summary line: the
        // control char must be neutralized so it stays one record.
        append_contact(&path, "evil\nforged.example.com");
        assert_eq!(
            read_contacts(&path),
            vec![("evil\u{fffd}forged.example.com".into(), 1)]
        );

        append_contact(&path, "crates.io");
        append_contact(&path, "crates.io");
        let summary = contacts_summary(&path, "domains contacted (audit)").unwrap();
        let lines: Vec<&str> = summary.lines().collect();
        // Header, then one line per domain, most-contacted first.
        assert_eq!(lines[0], "virtkit: domains contacted (audit):");
        assert!(lines[1].starts_with("  crates.io") && lines[1].ends_with("(x2)"));
        assert!(
            lines[2].starts_with("  evil\u{fffd}forged.example.com") && lines[2].ends_with("(x1)")
        );
        // The count column is aligned: both `(xN)` markers start at the same char offset.
        let marker_col = |l: &str| l.chars().count() - "(xN)".chars().count();
        assert_eq!(marker_col(lines[1]), marker_col(lines[2]));
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
