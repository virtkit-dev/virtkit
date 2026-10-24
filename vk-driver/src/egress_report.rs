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
use std::path::{Path, PathBuf};

use vk_hub_proto::egress::{
    EgressCoverage, EgressDestination, EgressEntry, EgressLayer, EgressOmitted, EgressOutcome,
    EgressPhase, EgressPhaseReport, EgressProtocol, EgressRefusal, EgressReport, EgressSource,
    MAX_EGRESS_CONTACTS, MAX_EGRESS_DENIALS,
};

/// A placed job's egress record ([`crate::jobctx::JobCtx::egress_record`]) keeps each of the
/// job's builds' channels in a dir of its own, named with this prefix, laid out as a build's
/// scratch lays them out.
pub const BUILD_PREFIX: &str = "build-";
/// A file in a placed job's egress record saying that one of its builds recorded nothing: a
/// Windows image's, whose build records no egress.
pub const UNRECORDED_BUILD: &str = "unrecorded-build";

/// A file in a placed job's egress record naming the caps one of its phase's VMs was held to:
/// `caps-<phase>-<fingerprint>`, created empty, once per caps ([`mark_caps`]).
pub const CAPS_PREFIX: &str = "caps-";

/// Note in `record` that a VM of `phase` is held to `caps`, the node's caps as the config of
/// the process enforcing them says them, which the node's inventory may not: it reads its config
/// once, an executor each time it starts. Its name says it whole, so it is never seen half
/// written. Best-effort like the channels: a phase with none is reported held to the caps its
/// job was placed under.
pub fn mark_caps(record: &Path, phase: EgressPhase, caps: &vk_hub_proto::egress::NodeEgressCaps) {
    let fingerprint = match caps {
        vk_hub_proto::egress::NodeEgressCaps::Listed(c) => c.fingerprint.as_str(),
        _ => vk_hub_proto::egress::UNKNOWN_CAPS,
    };
    let Some(phase) = caps_phase(phase) else {
        return;
    };
    let name = format!("{CAPS_PREFIX}{phase}-{fingerprint}");
    let _ = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(record.join(name));
}

/// A phase as a caps file names it.
fn caps_phase(phase: EgressPhase) -> Option<&'static str> {
    match phase {
        EgressPhase::Run => Some("run"),
        EgressPhase::Build => Some("build"),
        EgressPhase::Other => None,
    }
}

/// The egress declarations a placed job was refused at validation, in its egress record: one
/// JSON [`EgressRefusal`] per line.
pub const REFUSED: &str = "refused.jsonl";

/// Append `refusals` to `path` (create-or-append), each as one JSON line, in a single
/// `write_all`. Best-effort like the channels: the job fails with the refusal in its trace
/// either way.
pub fn append_refusals(path: &Path, refusals: &[EgressRefusal]) {
    let mut lines = String::new();
    for r in refusals {
        if let Ok(json) = serde_json::to_string(r) {
            lines.push_str(&json);
            lines.push('\n');
        }
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(lines.as_bytes());
    }
}

/// The kind of flow the switch refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
    Dns,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
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

/// Egress requests the switch refused: their protocol and destination (an `ip:port` for
/// tcp/udp, a DNS name for dns), and how many of them one record stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    pub proto: Proto,
    pub target: String,
    pub count: u64,
}

impl Denial {
    /// A human line for the job trace — the shape the switch also logs for operators.
    pub fn display(&self) -> String {
        format!("egress denied ({}) {}", self.proto.as_str(), self.target)
    }
}

/// How long a placed job's switches let each of its denial and audit channels grow, in bytes:
/// past it they only count what they would have recorded, as [`append_omitted`] writes it.
pub const RECORD_LIMIT: u64 = 8 << 20;

/// Append `n` attempts with `outcome` that a switch dropped past its record limit to `path`, as
/// an `omitted\toutcome\tn` record, which neither the trace's readers nor `vk egress-report`
/// read as a denial or a contact.
pub fn append_omitted(path: &Path, outcome: vk_hub_proto::egress::EgressOutcome, n: u64) {
    use vk_hub_proto::egress::EgressOutcome;
    let outcome = match outcome {
        EgressOutcome::Observed => "observed",
        EgressOutcome::WouldBlock => "would_block",
        EgressOutcome::Blocked | EgressOutcome::Other => "blocked",
    };
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(format!("omitted\t{outcome}\t{n}\n").as_bytes());
    }
}

/// What the switch knew of a record when it wrote it, beyond the record itself: written after
/// the record's own fields as tab-separated `key=value`s, which the trace's readers pass over.
/// A record without them — from an older switch — reads as all unknown.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attrs {
    /// The layer that decided a denial (see vk_hub_proto::egress).
    pub layer: Option<EgressLayer>,
    /// The service whose VM sent it; `None` for the job's own VM.
    pub vm: Option<String>,
    /// A denial a dry-run allowlist carried rather than refused.
    pub would_block: bool,
    /// The protocol of a contact by IP, which its record does not otherwise say.
    pub proto: Option<Proto>,
    /// When it happened, in milliseconds since the Unix epoch; for a count of repeats, the
    /// last of them.
    pub at_ms: Option<u64>,
    /// The hub's dry-run rule whose would-be denial it is.
    pub rule: Option<String>,
}

impl Attrs {
    /// The attributes as they follow a record: `\tkey=value` each, the VM's name sanitized.
    fn encode(&self) -> String {
        let mut s = String::new();
        if let Some(layer) = self.layer {
            s.push_str(&format!("\tlayer={}", layer.as_str()));
        }
        if let Some(vm) = &self.vm {
            s.push_str(&format!("\tvm={}", sanitize(vm)));
        }
        if self.would_block {
            s.push_str("\tdry=1");
        }
        if let Some(proto) = self.proto {
            s.push_str(&format!("\tp={}", proto.as_str()));
        }
        if let Some(at) = self.at_ms {
            s.push_str(&format!("\tt={at}"));
        }
        if let Some(rule) = &self.rule {
            s.push_str(&format!("\trule={}", sanitize(rule)));
        }
        s
    }

    /// The attributes in `fields`, the `key=value`s after a record's own. An unknown key, from
    /// a later switch, is passed over.
    fn decode<'a>(fields: impl Iterator<Item = &'a str>) -> Self {
        let mut attrs = Attrs::default();
        for (key, value) in fields.filter_map(|f| f.split_once('=')) {
            match key {
                "layer" => attrs.layer = Some(EgressLayer::parse(value)),
                "vm" => attrs.vm = Some(value.to_string()),
                "dry" => attrs.would_block = value == "1",
                "p" => attrs.proto = Proto::parse(value),
                "t" => attrs.at_ms = value.parse().ok(),
                "rule" => attrs.rule = Some(value.to_string()),
                _ => {}
            }
        }
        attrs
    }
}

/// Now, in milliseconds since the Unix epoch, as [`Attrs::at_ms`] says it.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// `s` with its control characters replaced with `U+FFFD`: a guest-controlled name holding one
/// would otherwise tear the one-record-per-line format, or forge lines into the job trace.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}

/// Append a denial to `path` (create-or-append). A DNS `target` is guest-controlled, so
/// control characters are replaced (see [`sanitize`]); the record is then one unambiguous
/// `proto\ttarget` line, followed by its `attrs`. Written in a single `write_all` so concurrent
/// switch tasks appending at once don't interleave fragments of a line. Best-effort: any IO
/// error is dropped — a lost denial notice must never disturb the job or the switch's
/// forwarding.
pub fn append(path: &Path, proto: Proto, target: &str, attrs: &Attrs) {
    append_repeats(path, proto, target, 1, attrs);
}

/// [`append`] for `count` refusals of the same target at once, as a `proto\ttarget\tcount`
/// record; the count is left off at one when no attributes follow. The sanitized target holds
/// no tab, so the count is unambiguous.
pub fn append_repeats(path: &Path, proto: Proto, target: &str, count: u64, attrs: &Attrs) {
    let target = sanitize(target);
    let attrs = attrs.encode();
    let line = match (count, attrs.is_empty()) {
        (1, true) => format!("{}\t{target}\n", proto.as_str()),
        (n, _) => format!("{}\t{target}\t{n}{attrs}\n", proto.as_str()),
    };
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(line.as_bytes());
    }
}

/// Append one external contact to the audit channel `path` (create-or-append). The switch
/// records both the allowed external names the guest resolves (`kind = "name"`) and the
/// external IPs it dials without a matching resolution (`kind = "ip"`), interleaved in one
/// channel; the readers below split them back apart by kind. Unlike the denial channel this is
/// drained once at the end of the job rather than per stage. `value` is guest-controlled, so —
/// like `append` — control characters are neutralized to `U+FFFD` (no forged or torn lines in
/// the summary) and the record is one `kind\tvalue` `write_all`, followed by its `attrs`, so
/// concurrent stage switches sharing a build's channel never interleave fragments.
/// Best-effort: IO errors are dropped, exactly like `append`.
fn append_audit(path: &Path, kind: &str, value: &str, attrs: &Attrs) {
    let value = sanitize(value);
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(format!("{kind}\t{value}{}\n", attrs.encode()).as_bytes());
    }
}

/// Record one contacted external domain (see [`append_audit`]).
pub fn append_contact(path: &Path, name: &str, attrs: &Attrs) {
    append_audit(path, "name", name, attrs);
}

/// Record one external `ip:port` the guest dialed directly, i.e. without a resolution the
/// switch handed it — the domains summary would otherwise miss it (see [`append_audit`]).
pub fn append_ip_contact(path: &Path, ip_port: &str, attrs: &Attrs) {
    append_audit(path, "ip", ip_port, attrs);
}

/// Read the audit channel `path` and return each `kind` contact paired with its count, ordered
/// most-contacted first (ties broken by value) for a stable job-trace summary. A missing file
/// (audit off, or the switch recorded nothing) yields an empty list. Unlike the denial channel
/// there is no offset: the whole file is one job's contacts, read once.
fn read_audit(path: &Path, kind: &str) -> Vec<(String, usize)> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    count_audit(&text, kind)
}

/// The `kind` contacts in the audit records `text`, counted and ranked as [`read_audit`] says.
fn count_audit(text: &str, kind: &str) -> Vec<(String, usize)> {
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for value in audit_records(text)
        .filter(|(k, _, _)| *k == kind)
        .map(|(_, v, _)| v)
    {
        *counts.entry(value).or_default() += 1;
    }
    let mut counts: Vec<(String, usize)> = counts
        .into_iter()
        .map(|(n, c)| (n.to_string(), c))
        .collect();
    counts.sort_by(|(an, ac), (bn, bc)| bc.cmp(ac).then_with(|| an.cmp(bn)));
    counts
}

/// Each `kind\tvalue[\tattrs…]` record in `text`, as its kind, its value and its [`Attrs`]; a
/// record with no value is passed over.
fn audit_records(text: &str) -> impl Iterator<Item = (&str, &str, Attrs)> {
    text.lines().filter_map(|l| {
        let mut fields = l.split('\t');
        let kind = fields.next()?;
        let value = fields.next().map(str::trim).filter(|v| !v.is_empty())?;
        Some((kind, value, Attrs::decode(fields)))
    })
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
/// indented `value (xN)` line per contact, counts aligned, in the order given. `None` when
/// there is nothing to report, so the caller prints nothing.
fn summary(contacts: &[(String, impl std::fmt::Display)], header: &str) -> Option<String> {
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

/// How much of the end of each channel [`report`] reads: a guest retrying in a loop fills
/// them with the same few lines, which their last MiB holds as well as the whole.
const REPORT_TAIL: u64 = 1 << 20;

/// Format unique denials in first-seen order for the job trace and [`report`]. Sum record
/// counts, including DNS repeats, and append `(xN)` when the total exceeds one, so a retry
/// loop against one host produces one line.
pub fn denial_lines(denials: &[Denial]) -> Vec<String> {
    let mut seen: Vec<(String, u64)> = Vec::new();
    let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for d in denials {
        let line = d.display();
        match index.get(&line) {
            Some(&i) => {
                if let Some((_, n)) = seen.get_mut(i) {
                    *n = n.saturating_add(d.count);
                }
            }
            None => {
                index.insert(line.clone(), seen.len());
                seen.push((line, d.count));
            }
        }
    }
    seen.into_iter()
        .map(|(msg, n)| match n {
            1 => msg,
            n => format!("{msg} (x{n})"),
        })
        .collect()
}

/// What `dir` — a CI job's dir, or a `vk run`'s state dir, where the switch keeps its channels
/// — recorded of its guest's egress, from the last [`REPORT_TAIL`] bytes of each channel: the
/// refusals as the job's trace lists them, then the domains and the IPs it reached, each
/// most-contacted first. A header says when a channel was longer. `None` when neither holds
/// anything. The dir does not record whether a job's allowlist was dry-run, so the refusals'
/// header names both cases.
pub fn report(dir: &Path) -> Option<String> {
    use crate::jobctx::JobCtx;
    let header = |what: &str, cut: bool| {
        if cut {
            format!("{what} (the log's last MiB)")
        } else {
            what.to_string()
        }
    };
    let (denied, denied_cut) = read_tail(&JobCtx::egress_denied_log_in(dir), REPORT_TAIL);
    let denials: Vec<Denial> = parse_records(&denied)
        .0
        .into_iter()
        .map(|(d, _)| d)
        .collect();
    let refused = denial_lines(&denials);
    let refused = (!refused.is_empty()).then(|| {
        let mut s = format!(
            "virtkit: {}:",
            header("egress refused, or flagged under dry-run", denied_cut)
        );
        for line in &refused {
            s.push_str(&format!("\n  {line}"));
        }
        s
    });
    let (audit, audit_cut) = read_tail(&JobCtx::egress_audit_log_in(dir), REPORT_TAIL);
    let audit = String::from_utf8_lossy(&audit);
    let blocks: Vec<String> = [
        refused,
        summary(
            &count_audit(&audit, "name"),
            &header("external domains contacted", audit_cut),
        ),
        summary(
            &count_audit(&audit, "ip"),
            &header("external IPs/ports contacted", audit_cut),
        ),
    ]
    .into_iter()
    .flatten()
    .collect();
    (!blocks.is_empty()).then(|| blocks.join("\n"))
}

/// The whole lines in the last `max` bytes of `path` as it was when opened, and whether that
/// left any out. Begun mid-file, the read starts a byte early and drops everything through the
/// first newline, so a line cut by the start is dropped whole — and one that begins exactly at
/// it is kept. A missing or unreadable file holds nothing.
fn read_tail(path: &Path, max: u64) -> (Vec<u8>, bool) {
    let Ok(mut f) = std::fs::File::open(path) else {
        return (Vec::new(), false);
    };
    let Ok(len) = f.metadata().map(|m| m.len()) else {
        return (Vec::new(), false);
    };
    let from = len.saturating_sub(max);
    let start = from.saturating_sub(1);
    let mut buf = Vec::new();
    // To the length stated, not past it into what was appended since.
    if f.seek(SeekFrom::Start(start)).is_err() || f.take(len - start).read_to_end(&mut buf).is_err()
    {
        return (Vec::new(), from > 0);
    }
    if from > 0 {
        let first = buf
            .iter()
            .position(|&b| b == b'\n')
            .map_or(buf.len(), |nl| nl + 1);
        buf.drain(..first);
    }
    (buf, from > 0)
}

/// The bytes the switch has forwarded, as it last published them: `(sent, received)` from
/// the guests' side. `None` when there is no file — no switch, or one that has not published
/// yet. Payload only, and egress only: the framing around it, the retransmits under it and
/// the vsock carrying it are the host's traffic, and what the guests send each other is
/// switched at layer 2 without ever being proxied.
pub fn read_net_bytes(path: &Path) -> Option<(u64, u64)> {
    let text = std::fs::read_to_string(path).ok()?;
    Some(sum_net_bytes(&text))
}

/// The traffic the byte channel's lines in `text` add up to, `(sent, received)`.
fn sum_net_bytes(text: &str) -> (u64, u64) {
    // Each line is one switch's traffic since it last wrote, so the total is their sum —
    // over every publish, and over every switch that shared the channel (a build's stages
    // each have their own LAN). One publish is one small `write_all` to an `O_APPEND` fd,
    // which the kernel does not split, so a reader never sees half a record — and a line
    // that does not hold two numbers is passed over rather than read as a figure.
    text.lines().fold((0u64, 0u64), |(sent, received), line| {
        let mut fields = line.split_whitespace();
        match (
            fields.next().and_then(|f| f.parse::<u64>().ok()),
            fields.next().and_then(|f| f.parse::<u64>().ok()),
        ) {
            (Some(s), Some(r)) => (sent.saturating_add(s), received.saturating_add(r)),
            _ => (sent, received),
        }
    })
}

/// Read the denials appended to `path` since byte `offset`, returning them with the new
/// offset to persist. Only whole lines are consumed — a partial trailing line (the writer
/// mid-append) is left for next time, so a record is never torn. A file shorter than
/// `offset` was truncated (e.g. removed and recreated) and is re-read from the start; the
/// per-job log is otherwise append-only and never rotated. A missing file (the job had no
/// egress restriction, so the switch wrote none) yields no denials.
#[cfg(test)]
pub fn read_since(path: &Path, offset: u64) -> (Vec<Denial>, u64) {
    let (records, offset) = read_records_since(path, offset);
    (records.into_iter().map(|(d, _)| d).collect(), offset)
}

/// Read the denials appended to `path` since byte `offset`, each with its [`Attrs`], as
/// [`read_since`] does.
pub fn read_records_since(path: &Path, offset: u64) -> (Vec<(Denial, Attrs)>, u64) {
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
    let (out, consumed) = parse_records(&buf);
    (out, start + consumed as u64)
}

/// Parse records through the last newline in `buf`, each with its [`Attrs`], and return the
/// number of bytes consumed. Ignore incomplete trailing lines and malformed records. A record
/// is `proto\ttarget[\tcount[\tattrs…]]`.
fn parse_records(buf: &[u8]) -> (Vec<(Denial, Attrs)>, usize) {
    let consumed = match buf.iter().rposition(|&b| b == b'\n') {
        Some(nl) => nl + 1,
        None => return (Vec::new(), 0),
    };
    let mut out = Vec::new();
    for line in String::from_utf8_lossy(&buf[..consumed]).lines() {
        let mut fields = line.split('\t');
        let (Some(proto), Some(target)) = (fields.next().and_then(Proto::parse), fields.next())
        else {
            continue;
        };
        let count = match fields.next().map(str::parse) {
            None => 1,
            Some(Ok(n)) => n,
            Some(Err(_)) => continue,
        };
        let denial = Denial {
            proto,
            target: target.to_string(),
            count,
        };
        out.push((denial, Attrs::decode(fields)));
    }
    (out, consumed)
}

/// The dir of a placed job's egress record its run phase's channels are kept in at cleanup,
/// laid out as the job dir lays them out ([`keep_run_channels`]).
pub const RUN_DIR: &str = "run";

/// The run phase's channels in the executor's `job_dir`, moved into the job's egress `record`
/// before cleanup removes the job dir: the switch is stopped by then, and has written out all
/// it counted. Best-effort: a channel that cannot be kept leaves the report without it.
pub fn keep_run_channels(job_dir: &Path, record: &Path) {
    use crate::jobctx::JobCtx;
    let run = record.join(RUN_DIR);
    if std::fs::create_dir_all(&run).is_err() {
        return;
    }
    for from in [
        JobCtx::egress_denied_log_in(job_dir),
        JobCtx::egress_audit_log_in(job_dir),
        job_dir.join(crate::run::NET_BYTES),
    ] {
        let Some(name) = from.file_name() else {
            continue;
        };
        let to = run.join(name);
        // A copy where the two are not on one filesystem; nothing at all where there is no
        // channel, as for a job whose guest had no switch.
        if std::fs::rename(&from, &to).is_err() && from.exists() {
            let _ = std::fs::copy(&from, &to);
        }
    }
}

/// How much of each channel a [`JobRecord`] reads, from its start: what a job's switch records
/// past it is left out, and the phase's coverage says so.
const JOB_REPORT_READ: u64 = 16 << 20;

/// How far one channel has been read: whole lines up to `offset`, and whether some of it was
/// left out.
#[derive(Default)]
struct Channel {
    offset: u64,
    cut: bool,
}

impl Channel {
    /// The whole lines `path` holds past the last read, within [`JOB_REPORT_READ`] of its start;
    /// a line still being written is read again, whole, the next time. `None` for a missing file,
    /// which holds nothing yet; one that cannot be read, holds more than the bound, or has lost
    /// lines read before, is cut.
    fn read(&mut self, path: &Path) -> Option<Vec<u8>> {
        let mut f = match std::fs::File::open(path) {
            Ok(f) => f,
            // Gone after lines were read from it: whatever followed them is left out.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.cut |= self.offset > 0;
                return None;
            }
            // There, but not to be read: whatever it holds is left out.
            Err(_) => {
                self.cut = true;
                return Some(Vec::new());
            }
        };
        // Shorter than what was read of it: not the file read, and what followed is left out.
        if f.metadata().is_ok_and(|m| m.len() < self.offset) {
            self.cut = true;
            return Some(Vec::new());
        }
        let room = JOB_REPORT_READ.saturating_sub(self.offset);
        let mut buf = Vec::new();
        let read = f.seek(SeekFrom::Start(self.offset)).and_then(|_| {
            f.take(room.saturating_add(1))
                .read_to_end(&mut buf)
                .map(|_| ())
        });
        if read.is_err() {
            self.cut = true;
            return Some(Vec::new());
        }
        if buf.len() as u64 > room {
            self.cut = true;
            buf.truncate(usize::try_from(room).unwrap_or(usize::MAX));
        }
        let whole = buf.iter().rposition(|&b| b == b'\n').map_or(0, |nl| nl + 1);
        buf.truncate(whole);
        self.offset = self.offset.saturating_add(whole as u64);
        Some(buf)
    }
}

/// How far a dir's channels have been read: its denials, its contacts and its bytes.
#[derive(Default)]
struct Channels {
    denied: Channel,
    audit: Channel,
    bytes: Channel,
}

impl Channels {
    fn cut(&self) -> bool {
        self.denied.cut || self.audit.cut || self.bytes.cut
    }
}

/// What a phase's channels counted beyond their entries.
#[derive(Default)]
struct PhaseCount {
    omitted: EgressOmitted,
    sent_bytes: Option<u64>,
    received_bytes: Option<u64>,
}

/// What a report entry is counted under: one destination, reached or refused one way, by one
/// VM in one phase, decided by one layer — or, for a would-be denial, by one hub dry-run rule.
type EntryKey = (
    EgressOutcome,
    EgressProtocol,
    EgressDestination,
    EgressPhase,
    EgressSource,
    Option<EgressLayer>,
    Option<String>,
);

/// A job's records counted into report entries as they are read, bounded as the report is: an
/// entry past [`MAX_EGRESS_DENIALS`] or [`MAX_EGRESS_CONTACTS`] is only counted, as omitted.
#[derive(Default)]
struct Tally {
    entries: Vec<EgressEntry>,
    index: std::collections::HashMap<EntryKey, usize>,
    denials: usize,
    contacts: usize,
}

impl Tally {
    /// Count `count` attempts under `key` at `at_ms`; past the bounds, into `omitted`.
    fn add(&mut self, key: EntryKey, count: u64, at_ms: Option<u64>, omitted: &mut EgressOmitted) {
        if let Some(e) = self.index.get(&key).and_then(|&i| self.entries.get_mut(i)) {
            e.count = e.count.saturating_add(count);
            if let Some(at) = at_ms {
                e.first_seen_ms = match e.first_seen_ms {
                    0 => at,
                    first => first.min(at),
                };
                e.last_seen_ms = e.last_seen_ms.max(at);
            }
            return;
        }
        let (outcome, protocol, destination, phase, source, layer, rule) = key.clone();
        let (kept, max) = match outcome.is_denial() {
            true => (&mut self.denials, MAX_EGRESS_DENIALS),
            false => (&mut self.contacts, MAX_EGRESS_CONTACTS),
        };
        if *kept >= max {
            omitted.add(outcome, count);
            return;
        }
        *kept += 1;
        self.index.insert(key, self.entries.len());
        self.entries.push(EgressEntry {
            outcome,
            protocol,
            destination,
            phase,
            source,
            layer,
            count,
            first_seen_ms: at_ms.unwrap_or(0),
            last_seen_ms: at_ms.unwrap_or(0),
            stage: None,
            rule,
        });
    }

    /// Count what the channels in `dir` hold past `read` into `phase`, its omissions and its
    /// bytes included.
    fn add_channels(
        &mut self,
        dir: &Path,
        read: &mut Channels,
        phase: EgressPhase,
        count: &mut PhaseCount,
    ) {
        use crate::jobctx::JobCtx;
        let source = |attrs: &Attrs| match &attrs.vm {
            Some(name) => EgressSource::Service { name: name.clone() },
            None => EgressSource::Job,
        };
        let denied = read
            .denied
            .read(&JobCtx::egress_denied_log_in(dir))
            .unwrap_or_default();
        for (outcome, n) in omitted_records(&denied) {
            count.omitted.add(outcome, n);
        }
        for (d, attrs) in parse_records(&denied).0 {
            let outcome = match attrs.would_block {
                true => EgressOutcome::WouldBlock,
                false => EgressOutcome::Blocked,
            };
            // The switch's count of the names it had no room to keep: attempts, not a place.
            if d.target == crate::switch::DNS_DENIED_MORE {
                count.omitted.add(outcome, d.count);
                continue;
            }
            let (protocol, destination) = match d.proto {
                Proto::Dns => (EgressProtocol::Dns, EgressDestination::domain(&d.target)),
                Proto::Tcp => (EgressProtocol::Tcp, EgressDestination::address(&d.target)),
                Proto::Udp => (EgressProtocol::Udp, EgressDestination::address(&d.target)),
            };
            let layer = Some(attrs.layer.unwrap_or(EgressLayer::Unknown));
            let rule = attrs.rule.clone().filter(|_| attrs.would_block);
            let key = (
                outcome,
                protocol,
                destination,
                phase,
                source(&attrs),
                layer,
                rule,
            );
            self.add(key, d.count, attrs.at_ms, &mut count.omitted);
        }
        let audit = read
            .audit
            .read(&JobCtx::egress_audit_log_in(dir))
            .unwrap_or_default();
        for (outcome, n) in omitted_records(&audit) {
            count.omitted.add(outcome, n);
        }
        let audit = String::from_utf8_lossy(&audit);
        for (kind, value, attrs) in audit_records(&audit) {
            let (protocol, destination) = match kind {
                "name" => (EgressProtocol::Dns, EgressDestination::domain(value)),
                "ip" => (
                    match attrs.proto {
                        Some(Proto::Tcp) => EgressProtocol::Tcp,
                        Some(Proto::Udp) => EgressProtocol::Udp,
                        _ => EgressProtocol::Other,
                    },
                    EgressDestination::address(value),
                ),
                _ => continue,
            };
            let key = (
                EgressOutcome::Observed,
                protocol,
                destination,
                phase,
                source(&attrs),
                None,
                None,
            );
            self.add(key, 1, attrs.at_ms, &mut count.omitted);
        }
        if let Some(bytes) = read.bytes.read(&dir.join(crate::run::NET_BYTES)) {
            let (sent, received) = sum_net_bytes(&String::from_utf8_lossy(&bytes));
            count.sent_bytes = Some(count.sent_bytes.unwrap_or(0).saturating_add(sent));
            count.received_bytes = Some(count.received_bytes.unwrap_or(0).saturating_add(received));
        }
    }
}

/// The attempts a switch dropped past its record limit, from the [`append_omitted`] records in
/// a channel's `text`.
fn omitted_records(text: &[u8]) -> Vec<(EgressOutcome, u64)> {
    String::from_utf8_lossy(text)
        .lines()
        .filter_map(|l| {
            let mut fields = l.strip_prefix("omitted\t")?.split('\t');
            let outcome = match fields.next()? {
                "observed" => EgressOutcome::Observed,
                "would_block" => EgressOutcome::WouldBlock,
                _ => EgressOutcome::Blocked,
            };
            Some((outcome, fields.next()?.parse().ok()?))
        })
        .collect()
}

/// A phase's account before anything is counted into it.
fn phase_report(phase: EgressPhase, coverage: EgressCoverage) -> EgressPhaseReport {
    EgressPhaseReport {
        phase,
        coverage,
        omitted: EgressOmitted::default(),
        sent_bytes: None,
        received_bytes: None,
        caps: None,
    }
}

/// A placed job's egress record, read as it grows: each read takes only what its channels
/// gained since the last, so that the report of a running job can be taken again and again at
/// the cost of what is new. Its builds' channels are in the record; its run phase's in
/// `run_dir`, the executor's job dir while the job runs and the record's [`RUN_DIR`] once
/// cleanup has kept them there, the same bytes either way.
pub struct JobRecord {
    record: PathBuf,
    run_dir: PathBuf,
    tally: Tally,
    /// Each build's channels, by dir.
    builds: std::collections::BTreeMap<PathBuf, Channels>,
    build: PhaseCount,
    run: Channels,
    run_count: PhaseCount,
    /// A run-phase switch was seen: it opens its byte channel as it starts.
    watched: bool,
    /// The hub's enforced rules the job runs under, which its report names.
    hub_rules: Vec<String>,
    /// The caps each phase's VMs were held to, by [`caps_phase`]: two at most, which says they
    /// were not one.
    caps: std::collections::BTreeMap<&'static str, std::collections::BTreeSet<String>>,
}

impl JobRecord {
    pub fn new(record: &Path, run_dir: &Path) -> Self {
        JobRecord {
            record: record.to_path_buf(),
            run_dir: run_dir.to_path_buf(),
            tally: Tally::default(),
            builds: Default::default(),
            build: PhaseCount::default(),
            run: Channels::default(),
            run_count: PhaseCount::default(),
            watched: false,
            hub_rules: Vec::new(),
            caps: Default::default(),
        }
    }

    /// The record of a job run under the hub's enforced `rules`.
    pub fn with_hub_rules(mut self, rules: &[String]) -> Self {
        self.hub_rules = rules.to_vec();
        self
    }

    /// Read the run phase's channels from `dir` from now on, where they read as far as before:
    /// cleanup keeps them in the record's [`RUN_DIR`].
    pub fn move_run(&mut self, dir: &Path) {
        self.run_dir = dir.to_path_buf();
    }

    /// Count what the channels gained since the last read, and the builds begun since.
    pub fn read(&mut self) {
        let found = std::fs::read_dir(&self.record).into_iter().flatten();
        for e in found.filter_map(|e| e.ok()) {
            let name = e.file_name();
            let held = name
                .to_str()
                .and_then(|n| n.strip_prefix(CAPS_PREFIX))
                .and_then(|n| n.split_once('-'));
            if let Some((phase, fingerprint)) = held
                && let Some(phase) = [EgressPhase::Run, EgressPhase::Build]
                    .into_iter()
                    .find_map(|p| caps_phase(p).filter(|k| *k == phase))
            {
                let seen = self.caps.entry(phase).or_default();
                if seen.len() < 2 {
                    seen.insert(fingerprint.to_string());
                }
                continue;
            }
            let build = name.as_encoded_bytes().starts_with(BUILD_PREFIX.as_bytes());
            if build && e.file_type().is_ok_and(|t| t.is_dir()) {
                self.builds.entry(e.path()).or_default();
            }
        }
        for (dir, read) in &mut self.builds {
            self.tally
                .add_channels(dir, read, EgressPhase::Build, &mut self.build);
        }
        let watched = self.run_dir.join(crate::run::NET_BYTES).exists();
        // A switch's byte channel seen, then gone: the run's channels were not all kept.
        self.run.bytes.cut |= self.watched && !watched;
        self.watched |= watched;
        self.tally.add_channels(
            &self.run_dir,
            &mut self.run,
            EgressPhase::Run,
            &mut self.run_count,
        );
    }

    /// The report of what has been read, as its node sends it the hub, with `revision`: the
    /// builds' and the run's denials and contacts, counted per destination, VM and layer, each
    /// with the stage of `stages` — `(stage, start in ms since the epoch)`, in order — it was
    /// first seen in; the refused declarations; and each phase the job ran, with its coverage
    /// and bytes. `run_reached` says the job got past preparing, so that a run phase with no
    /// channel is reported as unrecorded rather than left out. Bounded
    /// ([`EgressReport::bounded`]).
    pub fn report(
        &self,
        stages: &[(String, u64)],
        run_reached: bool,
        revision: u64,
    ) -> EgressReport {
        let mut phases = Vec::new();
        let unrecorded = self.record.join(UNRECORDED_BUILD).exists();
        if !self.builds.is_empty() || unrecorded {
            let mut coverage = match (self.builds.is_empty(), unrecorded) {
                (true, _) => EgressCoverage::Unavailable,
                (false, true) => EgressCoverage::Partial,
                (false, false) => EgressCoverage::Complete,
            };
            if self.builds.values().any(Channels::cut) && coverage == EgressCoverage::Complete {
                coverage = EgressCoverage::Partial;
            }
            phases.push(counted(EgressPhase::Build, coverage, &self.build));
        }
        if self.watched || run_reached {
            let coverage = match (self.watched, self.run.cut()) {
                (false, _) => EgressCoverage::Unavailable,
                (true, true) => EgressCoverage::Partial,
                (true, false) => EgressCoverage::Complete,
            };
            phases.push(counted(EgressPhase::Run, coverage, &self.run_count));
        }
        for p in &mut phases {
            if !p.omitted.is_empty() && p.coverage == EgressCoverage::Complete {
                p.coverage = EgressCoverage::Partial;
            }
            let held = caps_phase(p.phase).and_then(|k| self.caps.get(k));
            p.caps = match held.map(|h| h.iter().collect::<Vec<_>>()).as_deref() {
                None | Some([]) => None,
                Some([one]) => Some((*one).clone()),
                Some(_) => Some(vk_hub_proto::egress::UNKNOWN_CAPS.to_string()),
            };
        }

        let mut entries = self.tally.entries.clone();
        for e in &mut entries {
            e.stage = stages
                .iter()
                .take_while(|(_, start)| e.first_seen_ms != 0 && *start <= e.first_seen_ms)
                .last()
                .map(|(stage, _)| stage.clone());
        }
        // Denials first, then what was observed, each in the order first seen.
        entries.sort_by_key(|e| (!e.outcome.is_denial(), e.first_seen_ms));

        // A handful of lines at most: read whole each time.
        let refused = Channel::default()
            .read(&self.record.join(REFUSED))
            .unwrap_or_default();
        let refusals: Vec<EgressRefusal> = String::from_utf8_lossy(&refused)
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        EgressReport {
            revision,
            entries,
            refusals,
            refusals_omitted: 0,
            phases,
            hub_rules: self.hub_rules.clone(),
        }
        .bounded()
    }
}

/// Phase `phase`'s account, with `coverage` and what its channels counted.
fn counted(phase: EgressPhase, coverage: EgressCoverage, count: &PhaseCount) -> EgressPhaseReport {
    EgressPhaseReport {
        omitted: count.omitted,
        sent_bytes: count.sent_bytes,
        received_bytes: count.received_bytes,
        ..phase_report(phase, coverage)
    }
}

/// What a placed job's egress `record` holds, read whole, as the first report its node sends
/// the hub ([`JobRecord::report`]), its run phase's channels in the record's [`RUN_DIR`].
#[cfg(test)]
pub fn job_report(record: &Path, stages: &[(String, u64)], run_reached: bool) -> EgressReport {
    let mut read = JobRecord::new(record, &record.join(RUN_DIR));
    read.read();
    read.report(stages, run_reached, 1)
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
    fn a_dir_reports_its_refusals_and_contacts_or_nothing() {
        let dir = std::env::temp_dir().join(format!("vk-egress-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(report(&dir), None);
        append(
            &dir.join("egress-denied.log"),
            Proto::Dns,
            "evil.example",
            &Attrs::default(),
        );
        append(
            &dir.join("egress-denied.log"),
            Proto::Dns,
            "evil.example",
            &Attrs::default(),
        );
        // The switch's later count of the same name's repeats.
        append_repeats(
            &dir.join("egress-denied.log"),
            Proto::Dns,
            "evil.example",
            40,
            &Attrs::default(),
        );
        append_contact(
            &dir.join("egress-audit.log"),
            "crates.io",
            &Attrs::default(),
        );
        let text = report(&dir).unwrap();
        assert!(
            text.starts_with(
                "virtkit: egress refused, or flagged under dry-run:\n  \
                 egress denied (dns) evil.example (x42)\n"
            ),
            "{text}"
        );
        assert!(
            text.contains("external domains contacted:\n  crates.io  (x1)"),
            "{text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Only the log's end is read, the record its start cuts dropped whole, and repeats
    /// counted once.
    #[test]
    fn a_long_refusal_log_is_read_from_its_end() {
        let dir = std::env::temp_dir().join(format!("vk-egress-tail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("egress-denied.log");
        append(&path, Proto::Dns, "early.example", &Attrs::default());
        let (line, last) = ("tcp\t10.0.0.1:443\n", "udp\t10.0.0.2:5353\n");
        let tail = usize::try_from(REPORT_TAIL).unwrap() - last.len();
        // The tail starts inside a tcp record, which is not counted.
        assert_ne!(tail % line.len(), 0);
        let whole = tail / line.len();
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(line.repeat(whole + 2).as_bytes()).unwrap();
        f.write_all(last.as_bytes()).unwrap();
        drop(f);
        let text = report(&dir).unwrap();
        assert!(
            text.starts_with(
                "virtkit: egress refused, or flagged under dry-run (the log's last MiB):\n"
            ),
            "{text}"
        );
        assert!(!text.contains("early.example"), "{text}");
        // Refused once, it is listed with no count, as a job's trace lists it.
        assert!(
            text.lines()
                .any(|l| l == "  egress denied (udp) 10.0.0.2:5353"),
            "{text}"
        );
        let tcp = text.lines().find(|l| l.contains("(tcp)")).unwrap();
        assert!(tcp.ends_with(&format!("(x{whole})")), "{tcp} of {whole}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A tail that begins exactly at a line keeps it; one that begins a byte into it drops it.
    #[test]
    fn a_tail_keeps_the_line_it_begins_at() {
        let dir = std::env::temp_dir().join(format!("vk-egress-cut-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("d.log");
        std::fs::write(&path, b"dns\ta\ndns\tb\n").unwrap();
        assert_eq!(read_tail(&path, 6), (b"dns\tb\n".to_vec(), true));
        assert_eq!(read_tail(&path, 5), (Vec::new(), true));
        assert_eq!(read_tail(&path, 100), (b"dns\ta\ndns\tb\n".to_vec(), false));
        assert!(!read_tail(&path, 12).1);
        assert_eq!(read_tail(&dir.join("none"), 6), (Vec::new(), false));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A long audit log is read from its end too, its headers saying so.
    #[test]
    fn a_long_audit_log_is_read_from_its_end() {
        let dir = std::env::temp_dir().join(format!("vk-egress-audit-tail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("egress-audit.log");
        append_contact(&path, "early.example", &Attrs::default());
        let line = "name\tcrates.io\n";
        let n = usize::try_from(REPORT_TAIL).unwrap() / line.len() + 2;
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(line.repeat(n).as_bytes()).unwrap();
        drop(f);
        append_ip_contact(&path, "10.0.0.1:443", &Attrs::default());
        let text = report(&dir).unwrap();
        assert!(!text.contains("early.example"), "{text}");
        assert!(
            text.starts_with("virtkit: external domains contacted (the log's last MiB):\n"),
            "{text}"
        );
        assert!(
            text.contains(
                "virtkit: external IPs/ports contacted (the log's last MiB):\n  10.0.0.1:443  (x1)"
            ),
            "{text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Repeats are summed across records, a counted one included, in first-seen order, and a
    /// target refused once carries no count.
    #[test]
    fn denial_lines_sum_the_repeats_of_each_target() {
        let d = |proto, target: &str, count| Denial {
            proto,
            target: target.into(),
            count,
        };
        let denials = [
            d(Proto::Dns, "a.example", 1),
            d(Proto::Tcp, "10.0.0.1:443", 1),
            d(Proto::Dns, "b.example", 1),
            d(Proto::Tcp, "10.0.0.1:443", 1),
            d(Proto::Dns, "a.example", 40),
        ];
        assert_eq!(
            denial_lines(&denials),
            [
                "egress denied (dns) a.example (x41)",
                "egress denied (tcp) 10.0.0.1:443 (x2)",
                "egress denied (dns) b.example",
            ]
        );
    }

    /// A phase's report names the caps its VMs were held to, as the processes enforcing them
    /// marked them; held to more than one, they are not known.
    #[test]
    fn a_phase_names_the_caps_its_vms_were_held_to() {
        use vk_hub_proto::egress::{EgressCaps, HubPhase, NodeEgressCaps, UNKNOWN_CAPS};
        let dir = std::env::temp_dir().join(format!("vk-egress-caps-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(format!("{BUILD_PREFIX}1"))).unwrap();
        let caps = |fingerprint: &str| {
            let mut c =
                EgressCaps::normalized(HubPhase::Unrestricted, false, HubPhase::Unrestricted)
                    .unwrap();
            c.fingerprint = fingerprint.to_string();
            NodeEgressCaps::Listed(c)
        };
        let (a, b) = ("ab".repeat(32), "cd".repeat(32));
        mark_caps(&dir, EgressPhase::Build, &caps(&a));
        mark_caps(&dir, EgressPhase::Build, &caps(&a));
        mark_caps(&dir, EgressPhase::Run, &caps(&a));
        mark_caps(&dir, EgressPhase::Run, &caps(&b));
        let report = job_report(&dir, &[], true);
        let held = |phase| {
            report
                .phases
                .iter()
                .find(|p| p.phase == phase)
                .and_then(|p| p.caps.clone())
        };
        assert_eq!(held(EgressPhase::Build), Some(a.clone()));
        assert_eq!(held(EgressPhase::Run), Some(UNKNOWN_CAPS.to_string()));
        // Too large to report: not known either.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(format!("{BUILD_PREFIX}1"))).unwrap();
        mark_caps(&dir, EgressPhase::Build, &NodeEgressCaps::TooLarge);
        let report = job_report(&dir, &[], true);
        assert_eq!(
            report
                .phases
                .iter()
                .map(|p| p.caps.as_deref())
                .collect::<Vec<_>>(),
            [Some(UNKNOWN_CAPS), None]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn round_trips_and_resumes_from_offset() {
        let dir = std::env::temp_dir().join(format!("vk-egress-report-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("egress-denied.log");
        let _ = std::fs::remove_file(&path);

        append(&path, Proto::Dns, "wallix.com", &Attrs::default());
        append(&path, Proto::Tcp, "93.184.216.34:443", &Attrs::default());
        let (first, off) = read_since(&path, 0);
        assert_eq!(
            first,
            vec![
                Denial {
                    proto: Proto::Dns,
                    target: "wallix.com".into(),
                    count: 1,
                },
                Denial {
                    proto: Proto::Tcp,
                    target: "93.184.216.34:443".into(),
                    count: 1,
                },
            ]
        );

        // Nothing new since the recorded offset.
        assert_eq!(read_since(&path, off), (Vec::new(), off));

        // A later append is picked up from the offset alone, repeats with their count.
        append(&path, Proto::Udp, "8.8.8.8:53", &Attrs::default());
        append_repeats(&path, Proto::Dns, "wallix.com", 41, &Attrs::default());
        let (next, _) = read_since(&path, off);
        assert_eq!(
            next,
            vec![
                Denial {
                    proto: Proto::Udp,
                    target: "8.8.8.8:53".into(),
                    count: 1,
                },
                Denial {
                    proto: Proto::Dns,
                    target: "wallix.com".into(),
                    count: 41,
                },
            ]
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
            append_contact(&path, name, &Attrs::default());
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

        append_contact(&path, "crates.io", &Attrs::default());
        append_ip_contact(&path, "93.184.216.34:443", &Attrs::default());
        append_ip_contact(&path, "93.184.216.34:443", &Attrs::default());
        append_contact(&path, "crates.io", &Attrs::default());

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
        append_contact(&path, "evil\nforged.example.com", &Attrs::default());
        assert_eq!(
            read_contacts(&path),
            vec![("evil\u{fffd}forged.example.com".into(), 1)]
        );

        append_contact(&path, "crates.io", &Attrs::default());
        append_contact(&path, "crates.io", &Attrs::default());
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
                target: "a.com".into(),
                count: 1,
            }]
        );
        // The torn line completes; the next read returns only it.
        std::fs::write(&path, b"dns\ta.com\ntcp\t1.2.3.4:443\n").unwrap();
        let (got, _) = read_since(&path, off);
        assert_eq!(
            got,
            vec![Denial {
                proto: Proto::Tcp,
                target: "1.2.3.4:443".into(),
                count: 1,
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
        append(
            &path,
            Proto::Dns,
            "evil\ntcp\t10.0.0.1:22\tx.com",
            &Attrs::default(),
        );
        let (got, _) = read_since(&path, 0);
        assert_eq!(
            got,
            vec![Denial {
                proto: Proto::Dns,
                target: "evil\u{fffd}tcp\u{fffd}10.0.0.1:22\u{fffd}x.com".into(),
                count: 1,
            }]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What the switch knew of a record follows it, and the trace's readers see the record as
    /// they always did: an attributed denial shows and counts as a bare one, and an attributed
    /// contact under its value alone. A bare record, as an older switch wrote it, reads with no
    /// attributes.
    #[test]
    fn attributes_follow_a_record_and_the_trace_reads_past_them() {
        let dir = std::env::temp_dir().join(format!("vk-egress-attrs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let denied = dir.join("egress-denied.log");
        let attrs = Attrs {
            layer: Some(EgressLayer::Service),
            vm: Some("db\nforged".into()),
            would_block: true,
            proto: None,
            at_ms: Some(1_700_000_000_123),
            rule: None,
        };
        append(&denied, Proto::Tcp, "10.0.0.1:443", &attrs);
        append_repeats(&denied, Proto::Dns, "a.example", 3, &attrs);
        append(&denied, Proto::Dns, "a.example", &Attrs::default());
        let text = std::fs::read_to_string(&denied).unwrap();
        assert_eq!(
            text.lines().next(),
            Some(
                "tcp\t10.0.0.1:443\t1\tlayer=service\tvm=db\u{fffd}forged\tdry=1\tt=1700000000123"
            )
        );
        let sanitized = Attrs {
            vm: Some("db\u{fffd}forged".into()),
            ..attrs.clone()
        };
        let (records, _) = parse_records(text.as_bytes());
        assert_eq!(
            records.iter().map(|(_, a)| a.clone()).collect::<Vec<_>>(),
            [sanitized.clone(), sanitized, Attrs::default()]
        );
        assert_eq!(
            denial_lines(&read_since(&denied, 0).0),
            [
                "egress denied (tcp) 10.0.0.1:443",
                "egress denied (dns) a.example (x4)"
            ]
        );

        let audit = dir.join("egress-audit.log");
        let at = Attrs {
            at_ms: Some(5),
            ..Attrs::default()
        };
        append_contact(&audit, "crates.io", &at);
        append_contact(&audit, "crates.io", &Attrs::default());
        let by_ip = Attrs {
            proto: Some(Proto::Udp),
            ..at.clone()
        };
        append_ip_contact(&audit, "10.0.0.2:53", &by_ip);
        assert_eq!(read_contacts(&audit), vec![("crates.io".into(), 2)]);
        assert_eq!(read_ip_contacts(&audit), vec![("10.0.0.2:53".into(), 1)]);
        let text = std::fs::read_to_string(&audit).unwrap();
        let records: Vec<_> = audit_records(&text).collect();
        assert_eq!(
            records,
            [
                ("name", "crates.io", at),
                ("name", "crates.io", Attrs::default()),
                ("ip", "10.0.0.2:53", by_ip),
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A placed job's record read into its report: each destination counted per outcome, VM
    /// and layer, with its first and last times and the stage it was first seen in; the
    /// switch's overflow count as omitted attempts; malformed names kept as text; the refused
    /// declarations; and each phase with its coverage and bytes.
    #[test]
    fn a_job_record_reads_as_its_report() {
        use crate::jobctx::JobCtx;
        let record = std::env::temp_dir().join(format!("vk-egress-job-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&record);
        let (build, run) = (record.join("build-a"), record.join(RUN_DIR));
        std::fs::create_dir_all(&build).unwrap();
        std::fs::create_dir_all(&run).unwrap();
        let at = |ms, layer, vm: Option<&str>, would_block| Attrs {
            layer,
            vm: vm.map(str::to_string),
            would_block,
            proto: None,
            at_ms: Some(ms),
            rule: None,
        };
        let build_denied = JobCtx::egress_denied_log_in(&build);
        append(
            &build_denied,
            Proto::Dns,
            "Crates.io",
            &at(1_000, Some(EgressLayer::NodeCap), None, false),
        );
        append_repeats(
            &build_denied,
            Proto::Dns,
            "crates.io",
            4,
            &at(1_500, Some(EgressLayer::NodeCap), None, false),
        );
        std::fs::write(build.join(crate::run::NET_BYTES), "0 0\n10 20\n").unwrap();

        let run_denied = JobCtx::egress_denied_log_in(&run);
        append(
            &run_denied,
            Proto::Tcp,
            "10.0.0.1:443",
            &at(3_500, Some(EgressLayer::Service), Some("db"), true),
        );
        append(
            &run_denied,
            Proto::Dns,
            "evil\nname",
            &at(4_000, Some(EgressLayer::Job), None, false),
        );
        append_repeats(
            &run_denied,
            Proto::Dns,
            crate::switch::DNS_DENIED_MORE,
            7,
            &at(4_000, Some(EgressLayer::Job), None, false),
        );
        // What the switch dropped past its record limit.
        append_omitted(&run_denied, EgressOutcome::WouldBlock, 3);
        // From an older switch: nothing known but the record.
        append(&run_denied, Proto::Udp, "10.0.0.2:53", &Attrs::default());
        let run_audit = JobCtx::egress_audit_log_in(&run);
        append_contact(&run_audit, "debian.org", &at(3_000, None, None, false));
        append_contact(&run_audit, "debian.org", &at(5_000, None, None, false));
        let by_ip = Attrs {
            proto: Some(Proto::Udp),
            ..at(3_200, None, Some("db"), false)
        };
        append_ip_contact(&run_audit, "10.0.0.3:123", &by_ip);
        std::fs::write(run.join(crate::run::NET_BYTES), "0 0\n5 6\n").unwrap();

        let refusal = EgressRefusal {
            variable: "MICROVM_EGRESS_ALLOW_NAME".into(),
            entry: "evil.com".into(),
            dimension: vk_hub_proto::egress::EgressDimension::Name,
            phase: EgressPhase::Run,
            source: EgressSource::Job,
            layer: Some(EgressLayer::NodeCap),
            reason: vk_hub_proto::egress::RefusalReason::Unreachable,
        };
        append_refusals(&record.join(REFUSED), std::slice::from_ref(&refusal));

        let stages = [
            ("prepare_executor".to_string(), 500),
            ("step_script".to_string(), 3_100),
        ];
        let report = job_report(&record, &stages, true);
        let entry = |outcome,
                     protocol,
                     destination,
                     phase,
                     source,
                     layer,
                     count,
                     times: (u64, u64),
                     stage: Option<&str>| {
            EgressEntry {
                outcome,
                protocol,
                destination,
                phase,
                source,
                layer,
                count,
                first_seen_ms: times.0,
                last_seen_ms: times.1,
                stage: stage.map(str::to_string),
                rule: None,
            }
        };
        let db = || EgressSource::Service { name: "db".into() };
        assert_eq!(
            report.entries,
            [
                entry(
                    EgressOutcome::Blocked,
                    EgressProtocol::Udp,
                    EgressDestination::address("10.0.0.2:53"),
                    EgressPhase::Run,
                    EgressSource::Job,
                    Some(EgressLayer::Unknown),
                    1,
                    (0, 0),
                    None
                ),
                entry(
                    EgressOutcome::Blocked,
                    EgressProtocol::Dns,
                    EgressDestination::domain("crates.io"),
                    EgressPhase::Build,
                    EgressSource::Job,
                    Some(EgressLayer::NodeCap),
                    5,
                    (1_000, 1_500),
                    Some("prepare_executor")
                ),
                entry(
                    EgressOutcome::WouldBlock,
                    EgressProtocol::Tcp,
                    EgressDestination::address("10.0.0.1:443"),
                    EgressPhase::Run,
                    db(),
                    Some(EgressLayer::Service),
                    1,
                    (3_500, 3_500),
                    Some("step_script")
                ),
                entry(
                    EgressOutcome::Blocked,
                    EgressProtocol::Dns,
                    EgressDestination::Malformed {
                        text: "evil\u{fffd}name".into()
                    },
                    EgressPhase::Run,
                    EgressSource::Job,
                    Some(EgressLayer::Job),
                    1,
                    (4_000, 4_000),
                    Some("step_script")
                ),
                entry(
                    EgressOutcome::Observed,
                    EgressProtocol::Dns,
                    EgressDestination::domain("debian.org"),
                    EgressPhase::Run,
                    EgressSource::Job,
                    None,
                    2,
                    (3_000, 5_000),
                    Some("prepare_executor")
                ),
                entry(
                    EgressOutcome::Observed,
                    EgressProtocol::Udp,
                    EgressDestination::address("10.0.0.3:123"),
                    EgressPhase::Run,
                    db(),
                    None,
                    1,
                    (3_200, 3_200),
                    Some("step_script")
                ),
            ]
        );
        assert_eq!(report.refusals, [refusal]);
        assert_eq!(
            report.phases,
            [
                EgressPhaseReport {
                    sent_bytes: Some(10),
                    received_bytes: Some(20),
                    ..phase_report(EgressPhase::Build, EgressCoverage::Complete)
                },
                EgressPhaseReport {
                    omitted: EgressOmitted {
                        blocked: 7,
                        would_block: 3,
                        observed: 0,
                    },
                    sent_bytes: Some(5),
                    received_bytes: Some(6),
                    ..phase_report(EgressPhase::Run, EgressCoverage::Partial)
                },
            ]
        );
        assert_eq!(report.revision, 1);
        let _ = std::fs::remove_dir_all(&record);
    }

    /// A phase that ran with nothing recording it reads as unrecorded, not as quiet; one the
    /// job never reached is left out.
    #[test]
    fn an_unrecorded_phase_reads_as_unavailable() {
        let record = std::env::temp_dir().join(format!("vk-egress-none-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&record);
        std::fs::create_dir_all(&record).unwrap();
        assert_eq!(job_report(&record, &[], false).phases, []);
        std::fs::write(record.join(UNRECORDED_BUILD), b"").unwrap();
        assert_eq!(
            job_report(&record, &[], true).phases,
            [
                phase_report(EgressPhase::Build, EgressCoverage::Unavailable),
                phase_report(EgressPhase::Run, EgressCoverage::Unavailable),
            ]
        );
        let _ = std::fs::remove_dir_all(&record);
    }

    /// Past its bound a destination is counted, not listed, and the entries kept are the
    /// first seen.
    #[test]
    fn a_job_reports_the_denials_past_its_bound_as_omitted() {
        let record = std::env::temp_dir().join(format!("vk-egress-many-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&record);
        let run = record.join(RUN_DIR);
        std::fs::create_dir_all(&run).unwrap();
        std::fs::write(run.join(crate::run::NET_BYTES), "0 0\n").unwrap();
        let denied = crate::jobctx::JobCtx::egress_denied_log_in(&run);
        for i in 0..MAX_EGRESS_DENIALS + 5 {
            append_repeats(
                &denied,
                Proto::Dns,
                &format!("n{i}.example"),
                2,
                &Attrs::default(),
            );
        }
        let report = job_report(&record, &[], true);
        assert_eq!(report.entries.len(), MAX_EGRESS_DENIALS);
        assert_eq!(
            report.entries[0].destination,
            EgressDestination::domain("n0.example")
        );
        assert_eq!(report.phases[0].coverage, EgressCoverage::Partial);
        assert_eq!(report.phases[0].omitted.blocked, 10);
        let _ = std::fs::remove_dir_all(&record);
    }

    /// A record read as it grows — a line caught half-written, a build begun between reads,
    /// the run's channels kept in the record by cleanup — reports as it does read whole.
    #[test]
    fn a_job_record_read_as_it_grows_reads_as_it_does_whole() {
        use crate::jobctx::JobCtx;
        use std::io::Write;
        let tmp = std::env::temp_dir().join(format!("vk-egress-grow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let (job, record) = (tmp.join("job"), tmp.join("record"));
        std::fs::create_dir_all(&job).unwrap();
        std::fs::create_dir_all(&record).unwrap();
        let attrs = |ms| Attrs {
            layer: Some(EgressLayer::NodeCap),
            at_ms: Some(ms),
            ..Attrs::default()
        };
        let denied = JobCtx::egress_denied_log_in(&job);
        let mut live = JobRecord::new(&record, &job);
        live.read();
        std::fs::write(job.join(crate::run::NET_BYTES), "1 2\n").unwrap();
        append(&denied, Proto::Dns, "a.example", &attrs(1_000));
        live.read();
        assert_eq!(live.report(&[], true, 1).entries.len(), 1);
        // Half a line, then the rest.
        let mut f = OpenOptions::new().append(true).open(&denied).unwrap();
        f.write_all(b"dns\tb.exa").unwrap();
        live.read();
        assert_eq!(live.report(&[], true, 1).entries.len(), 1);
        f.write_all(b"mple\t1\tlayer=job\tt=2000\n").unwrap();
        append(&denied, Proto::Dns, "a.example", &attrs(3_000));
        let build = record.join("build-x");
        std::fs::create_dir_all(&build).unwrap();
        append(
            &JobCtx::egress_denied_log_in(&build),
            Proto::Tcp,
            "10.0.0.1:443",
            &attrs(2_500),
        );
        live.read();
        std::fs::write(job.join(crate::run::NET_BYTES), "1 2\n3 4\n").unwrap();
        keep_run_channels(&job, &record);
        live.move_run(&record.join(RUN_DIR));
        live.read();
        let stages = [("step_script".to_string(), 500)];
        let whole = job_report(&record, &stages, true);
        assert_eq!(live.report(&stages, true, 1), whole);
        assert_eq!(whole.entries.len(), 3);
        assert_eq!(whole.entries[0].count, 2);
        assert_eq!(whole.phases[1].sent_bytes, Some(4));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Channels gone, or shorter than what was read of them, have lost what followed: the phase
    /// reads as partial, with what was counted before.
    #[test]
    fn a_channel_lost_after_it_was_read_leaves_its_phase_partial() {
        let tmp = std::env::temp_dir().join(format!("vk-egress-lost-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let run = tmp.join(RUN_DIR);
        std::fs::create_dir_all(&run).unwrap();
        let denied = crate::jobctx::JobCtx::egress_denied_log_in(&run);
        let coverage = |live: &JobRecord| live.report(&[], true, 1).phases[0].coverage;
        for lose in [
            |run: &Path| std::fs::remove_dir_all(run).unwrap(),
            |run: &Path| {
                std::fs::write(crate::jobctx::JobCtx::egress_denied_log_in(run), "").unwrap()
            },
        ] {
            std::fs::create_dir_all(&run).unwrap();
            std::fs::write(run.join(crate::run::NET_BYTES), "1 2\n").unwrap();
            append(&denied, Proto::Dns, "a.example", &Attrs::default());
            let mut live = JobRecord::new(&tmp, &run);
            live.read();
            assert_eq!(coverage(&live), EgressCoverage::Complete);
            lose(&run);
            live.read();
            assert_eq!(coverage(&live), EgressCoverage::Partial);
            assert_eq!(live.report(&[], true, 1).entries.len(), 1);
            let _ = std::fs::remove_dir_all(&run);
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Cleanup keeps the run phase's channels, those there are, in the job's record.
    #[test]
    fn run_channels_are_kept_in_the_record() {
        let tmp = std::env::temp_dir().join(format!("vk-egress-keep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let (job, record) = (tmp.join("job"), tmp.join("record"));
        std::fs::create_dir_all(&job).unwrap();
        std::fs::create_dir_all(&record).unwrap();
        std::fs::write(job.join(crate::run::NET_BYTES), "0 0\n").unwrap();
        std::fs::write(job.join("egress-denied.log"), "dns\ta.example\n").unwrap();
        keep_run_channels(&job, &record);
        let run = record.join(RUN_DIR);
        assert_eq!(
            std::fs::read_to_string(run.join("egress-denied.log")).unwrap(),
            "dns\ta.example\n"
        );
        assert!(run.join(crate::run::NET_BYTES).exists());
        assert!(!run.join(crate::run::AUDIT_LOG).exists());
        assert!(!job.join("egress-denied.log").exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// A hub dry-run rule's would-be denial is an entry of its own, naming its rule, beside the
    /// same destination's denial by another layer; the trace reads it as any other record.
    #[test]
    fn a_dry_run_rules_denial_names_its_rule() {
        use crate::jobctx::JobCtx;
        let record = std::env::temp_dir().join(format!("vk-egress-rule-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&record);
        let run = record.join(RUN_DIR);
        std::fs::create_dir_all(&run).unwrap();
        let denied = JobCtx::egress_denied_log_in(&run);
        let by = |rule: Option<&str>| Attrs {
            layer: Some(EgressLayer::HubRule),
            would_block: true,
            at_ms: Some(1_000),
            rule: rule.map(str::to_string),
            ..Attrs::default()
        };
        append(&denied, Proto::Dns, "evil.example", &by(Some("trial")));
        append(&denied, Proto::Dns, "evil.example", &by(Some("trial")));
        append(&denied, Proto::Dns, "evil.example", &by(None));
        let text = std::fs::read_to_string(&denied).unwrap();
        assert!(
            text.starts_with("dns\tevil.example\t1\tlayer=hub_rule\tdry=1\tt=1000\trule=trial\n")
        );
        assert_eq!(read_since(&denied, 0).0.len(), 3);
        let report = job_report(&record, &[], true);
        let entries: Vec<_> = report
            .entries
            .iter()
            .map(|e| (e.outcome, e.layer, e.rule.as_deref(), e.count))
            .collect();
        assert_eq!(
            entries,
            [
                (
                    EgressOutcome::WouldBlock,
                    Some(EgressLayer::HubRule),
                    Some("trial"),
                    2
                ),
                (
                    EgressOutcome::WouldBlock,
                    Some(EgressLayer::HubRule),
                    None,
                    1
                ),
            ]
        );
        let _ = std::fs::remove_dir_all(&record);
    }
}
