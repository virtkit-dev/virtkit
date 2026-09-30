//! Read a guest's recorded samples from `atop.log` or a finished job's `atop.log.zst`.
//!
//! The guest writes what `atop -P` would print (the schema is `vk_core::atop`); this opens
//! that log and turns its text back into samples, so `vk atop` can account a job that
//! has already finished. What the format guarantees a reader, and what this therefore relies
//! on:
//!
//! * a sample is complete only once its `SEP` line is written, so everything after the
//!   last `SEP` is a sample still being written — or one whose VM died mid-write, since the
//!   guest writes each sample with a single write and abrupt teardown truncates the tail.
//!   [`Parsed::consumed`] is where the samples end, which is also where a follower resumes;
//! * a record's own arity is known from its label, so a record that does not have it — the
//!   torn line, or a command line whose parentheses do not balance — is dropped rather than
//!   read with its fields shifted;
//! * counter labels carry per-interval differences and the interval column is at least 1,
//!   so a rate is a division that cannot fail;
//! * the first sample is announced by `RESET` and covers the guest's whole boot, which is a
//!   window of its own: totals want it, rates do not (see [`Sample::boot`]);
//! * `-1` is "the kernel does not have this counter", never zero;
//! * a process's wait channels (`PRW`) are written only when they change, so the latest
//!   record stands for every sample after it — which is what [`Proc::wchans`] carries.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use vk_core::atop::{self, Label};

/// Maximum text size of the retained samples, or of any single line or sample. The guest
/// owns the log directory and can fill it, so retention must be bounded. Evict the oldest
/// samples as newer ones arrive to keep the end of a hung job.
pub(crate) const MAX_LOG: u64 = 256 * 1024 * 1024;

/// The most of a log one read goes through — read from a plain log, decoded from a compressed
/// one. The log is guest input, a sparse file or a zstd frame (which may sit under the plain
/// name, since a log is told by its magic) can stand for any size at all, and the job-end
/// report reads it synchronously: this bounds the CPU and I/O one read spends, far past any
/// real job's log. Memory is bounded apart from it, by what [`MAX_LOG`] of text parses to.
///
/// It is an upper bound, not a budget: a guest that fills its log can make the job-end report
/// parse up to this much before the job is done — a longer job end, accepted as the price of
/// reading a real log whole.
pub(crate) const MAX_READ: u64 = 8 * 1024 * 1024 * 1024;

/// How much of a log is read or decoded at a time.
const CHUNK: usize = 1024 * 1024;

/// The on-disk zstd magic identifies compressed recordings regardless of filename, so renamed
/// copies still read correctly.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// The largest zstd window a recording's decoder accepts, as a power of two: the `zstd` CLI's
/// own default limit (128 MiB), above what any level `vk` compresses at uses, and the most
/// memory a frame can make a reader allocate for its window.
const WINDOW_LOG_MAX: u32 = 27;

/// A line that closes a sample, with the newline ending the line before it: what a follower
/// that starts part-way into a log resynchronises on.
pub(crate) const SEP_LINE: &[u8] = b"\nSEP\n";

/// Every sample of a log, opened by [`open_log`] — or, for one whose samples span more than
/// [`MAX_LOG`], its last ones (see [`read_folding`]).
pub fn read(path: &Path) -> Result<Parsed> {
    read_folding(path, |_| {})
}

/// [`read`] on a log already opened by [`open_log`], plain or compressed.
pub fn read_opened(path: &Path, file: std::fs::File) -> Result<Parsed> {
    read_from(path, file, Limits::DEFAULT, &mut |_| {})
}

/// [`read`], passing evicted samples to `evicted` in order. Callers detecting stalls and
/// their start times feed these into the same state as the retained samples.
///
/// Parsing starts at the first byte regardless of log size, preserving boot-sample identity
/// and wait channels across evictions. Only retained samples stay in memory.
///
/// Read lossily on purpose: the guest maps a command's own control bytes to spaces as it
/// writes, so a byte that is not text means a damaged log — and reading what is still there is
/// exactly what a reader of a possibly-torn file is for. A compressed log that stops decoding
/// part-way likewise yields the samples before the damage, with a warning.
pub fn read_folding(path: &Path, mut evicted: impl FnMut(Sample)) -> Result<Parsed> {
    read_from(path, open_log(path)?.0, Limits::DEFAULT, &mut evicted)
}

/// [`read_folding`] with a `keep`-byte retention limit, so tests in other modules can
/// exercise eviction with small logs.
#[cfg(test)]
pub(crate) fn read_folding_keeping(
    path: &Path,
    keep: u64,
    mut evicted: impl FnMut(Sample),
) -> Result<Parsed> {
    let limits = Limits {
        keep,
        ..Limits::DEFAULT
    };
    read_from(path, open_log(path)?.0, limits, &mut evicted)
}

/// The bounds one read goes by: [`MAX_LOG`], [`MAX_READ`] and [`CHUNK`] outside tests.
#[derive(Clone, Copy)]
struct Limits {
    keep: u64,
    max_read: u64,
    chunk: usize,
}

impl Limits {
    const DEFAULT: Limits = Limits {
        keep: MAX_LOG,
        max_read: MAX_READ,
        chunk: CHUNK,
    };
}

fn read_from(
    path: &Path,
    file: std::fs::File,
    limits: Limits,
    evicted: &mut dyn FnMut(Sample),
) -> Result<Parsed> {
    use std::io::Read;
    let reading = || format!("reading {}", path.display());
    let compressed = is_compressed(&file).with_context(reading)?;
    let mut source: Box<dyn Read> = match compressed {
        true => Box::new(decoder(file).with_context(reading)?),
        false => Box::new(file),
    };
    let max = limits.max_read;
    let mut stream = Stream::new(limits.keep, evicted);
    let mut chunk = vec![0u8; limits.chunk.max(1)];
    let mut read = 0u64;
    loop {
        match source.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                // Strictly past the bound, so a log that decodes to exactly it is not cut.
                let room = usize::try_from(max - read).unwrap_or(usize::MAX);
                if n > room {
                    stream.feed(&chunk[..room]);
                    stream.unread = true;
                    eprintln!(
                        "virtkit: warning: {} holds more than {} — reading no further",
                        path.display(),
                        crate::usage::fmt_bytes(max)
                    );
                    break;
                }
                read += n as u64;
                stream.feed(&chunk[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if compressed && read > 0 => {
                eprintln!(
                    "virtkit: warning: {} stops decoding after {} ({e}) — reading the samples \
                     before it",
                    path.display(),
                    crate::usage::fmt_bytes(read)
                );
                break;
            }
            Err(e) => return Err(e).with_context(reading),
        }
    }
    let parsed = stream.finish();
    // Said out loud rather than silently reading a part of the job: anything totalled over
    // what comes back covers only that part.
    if parsed.evicted > 0 {
        eprintln!(
            "virtkit: warning: {} holds more than {} of samples — keeping its last ones, \
             leaving out the first {}",
            path.display(),
            crate::usage::fmt_bytes(limits.keep),
            crate::usage::fmt_bytes(parsed.evicted)
        );
    }
    if parsed.oversized > 0 {
        eprintln!(
            "virtkit: warning: {} holds samples over {}, the most one may span — leaving out \
             {} of them",
            path.display(),
            crate::usage::fmt_bytes(limits.keep),
            crate::usage::fmt_bytes(parsed.oversized)
        );
    }
    Ok(parsed)
}

/// A log parsed as its bytes arrive, holding the newest samples that fit in `keep` bytes of
/// text and handing the older ones to `evicted`. A line, or a sample, longer than `keep` is
/// dropped whole rather than held.
struct Stream<'a> {
    parser: Parser,
    keep: u64,
    evicted: &'a mut dyn FnMut(Sample),
    /// The line being assembled, and whether it has outgrown `keep` and is being dropped.
    line: Vec<u8>,
    overlong: bool,
    /// Bytes fed so far, and where the sample being read began (just past the last `SEP`).
    at: u64,
    sample_start: u64,
    /// The sample being read has outgrown `keep`: its records are skipped until its `SEP`.
    abandoned: bool,
    /// The samples kept, each with the bytes of text it spans, and their sum.
    kept: std::collections::VecDeque<(Sample, u64)>,
    kept_bytes: u64,
    consumed: u64,
    /// Bytes of the samples let go of at the front, and of those too long to hold.
    evicted_bytes: u64,
    oversized: u64,
    /// The read stopped at [`MAX_READ`].
    unread: bool,
}

impl<'a> Stream<'a> {
    fn new(keep: u64, evicted: &'a mut dyn FnMut(Sample)) -> Stream<'a> {
        Stream {
            parser: Parser::default(),
            keep,
            evicted,
            line: Vec::new(),
            overlong: false,
            at: 0,
            sample_start: 0,
            abandoned: false,
            kept: Default::default(),
            kept_bytes: 0,
            consumed: 0,
            evicted_bytes: 0,
            oversized: 0,
            unread: false,
        }
    }

    fn feed(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let (piece, rest, ends) = match bytes.iter().position(|b| *b == b'\n') {
                Some(nl) => (&bytes[..=nl], &bytes[nl + 1..], true),
                None => (bytes, &[][..], false),
            };
            bytes = rest;
            if !self.overlong && (self.line.len() + piece.len()) as u64 > self.keep {
                self.overlong = true;
                self.at += self.line.len() as u64;
                self.line = Vec::new();
            }
            match self.overlong {
                true => self.at += piece.len() as u64,
                false => self.line.extend_from_slice(piece),
            }
            if ends {
                self.end_line();
            }
        }
    }

    /// The line assembled so far is whole (or is the log's torn last one).
    fn end_line(&mut self) {
        if std::mem::take(&mut self.overlong) {
            self.parser.dropped = self.parser.dropped.saturating_add(1);
            self.line.clear();
            self.check_size();
            return;
        }
        let mut line = std::mem::take(&mut self.line);
        self.at += line.len() as u64;
        let text = String::from_utf8_lossy(&line);
        let text = text.trim_end_matches(['\n', '\r']);
        if text == atop::SEP {
            let sample = self.parser.sep();
            // With the SEP line itself: a sample whose records fit but whose SEP does not is
            // still too long to hold.
            let span = self.at - self.sample_start;
            match (
                std::mem::take(&mut self.abandoned) || span > self.keep,
                sample,
            ) {
                (true, _) => self.oversized += span,
                (false, Some(sample)) => self.keep_sample(sample, span),
                (false, None) => {}
            }
            self.consumed = self.at;
            self.sample_start = self.at;
        } else if !self.abandoned || text == atop::RESET {
            // A `RESET` is honoured even in a sample given up on: the wait channels recorded
            // before it no longer stand. The boot sample it announces is the one given up on.
            self.parser.record(text);
            self.check_size();
        }
        line.clear();
        self.line = line;
    }

    /// Give up on a sample that has outgrown `keep`, rather than build it.
    fn check_size(&mut self) {
        if !self.abandoned && self.at - self.sample_start > self.keep {
            self.parser.abandon();
            self.abandoned = true;
        }
    }

    fn keep_sample(&mut self, sample: Sample, span: u64) {
        self.kept.push_back((sample, span));
        self.kept_bytes += span;
        while self.kept_bytes > self.keep {
            let Some((old, span)) = self.kept.pop_front() else {
                break;
            };
            self.kept_bytes -= span;
            self.evicted_bytes += span;
            (self.evicted)(old);
        }
    }

    fn finish(mut self) -> Parsed {
        if !self.line.is_empty() || self.overlong {
            self.end_line();
        }
        if self.abandoned {
            self.oversized += self.at - self.sample_start;
        }
        let mut samples = Vec::with_capacity(self.kept.len());
        samples.extend(self.kept.into_iter().map(|(s, _)| s));
        Parsed {
            samples,
            consumed: usize::try_from(self.consumed).unwrap_or(usize::MAX),
            len: usize::try_from(self.at).unwrap_or(usize::MAX),
            dropped: self.parser.dropped,
            evicted: self.evicted_bytes,
            oversized: self.oversized,
            unread: self.unread,
        }
    }
}

/// Where a follower of a plain log starts, and whether that is a sample boundary: the first
/// boundary at or after `len − keep`, or — where the tail closes no sample — the last bytes a
/// [`SEP_LINE`] still to come may begin with, for the follower to resynchronise from as the
/// log grows ([`after_first_sep`]).
pub(crate) fn tail_start(file: &std::fs::File, keep: u64) -> std::io::Result<(u64, bool)> {
    tail_start_by(file, keep, 64 * 1024)
}

fn tail_start_by(file: &std::fs::File, keep: u64, chunk: usize) -> std::io::Result<(u64, bool)> {
    use std::os::unix::fs::FileExt;
    let len = file.metadata()?.len();
    if len <= keep {
        return Ok((0, true));
    }
    // From a pattern's length before the cut, so a `SEP` line ending exactly at the cut — or
    // one the cut lands in — is found; no match can end before the cut.
    let mut at = (len - keep).saturating_sub(SEP_LINE.len() as u64);
    let mut buf = vec![0u8; chunk.max(SEP_LINE.len())];
    loop {
        let n = file.read_at(&mut buf, at)?;
        if let Some(end) = after_first_sep(&buf[..n]) {
            return Ok((at + end as u64, true));
        }
        if n < SEP_LINE.len() {
            return Ok((len.saturating_sub(SEP_LINE.len() as u64 - 1), false));
        }
        // Overlapping by all but one byte of the pattern, so one that straddles two reads is
        // still found.
        at += (n - (SEP_LINE.len() - 1)) as u64;
    }
}

/// One past the first [`SEP_LINE`] in `bytes`.
pub(crate) fn after_first_sep(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(SEP_LINE.len())
        .position(|w| w == SEP_LINE)
        .map(|at| at + SEP_LINE.len())
}

/// Whether `file` is a zstd recording, from its first bytes. Read at an offset, so the
/// descriptor's own position is left where it was; a file shorter than the magic is plain.
pub fn is_compressed(file: &std::fs::File) -> std::io::Result<bool> {
    use std::os::unix::fs::FileExt;
    let mut head = [0u8; ZSTD_MAGIC.len()];
    let mut got = 0;
    while got < head.len() {
        match file.read_at(&mut head[got..], got as u64)? {
            0 => return Ok(false),
            n => got += n,
        }
    }
    Ok(head == ZSTD_MAGIC)
}

/// A decoder for a compressed recording, its window bounded by [`WINDOW_LOG_MAX`].
fn decoder(file: std::fs::File) -> std::io::Result<impl std::io::Read> {
    let mut decoder = zstd::stream::read::Decoder::new(file)?;
    decoder.window_log_max(WINDOW_LOG_MAX)?;
    Ok(decoder)
}

/// A recording, opened on the descriptor everything that reads it reads from, with its size.
///
/// Without following symlinks, and refusing anything but a regular file: the guest had this
/// directory read-write and can leave anything where its log goes, so the path is resolved
/// once, by the kernel, on the thing actually read — never checked as a path and then opened
/// as another. A symlink to a FIFO would otherwise block a reader forever.
pub fn open_log(path: &Path) -> Result<(std::fs::File, u64)> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let md = file
        .metadata()
        .with_context(|| format!("reading {}", path.display()))?;
    if !md.is_file() {
        bail!("{} is not a regular file; not a recording", path.display());
    }
    Ok((file, md.len()))
}

/// Every complete sample of a log, and how far into the text they reach.
pub struct Parsed {
    pub samples: Vec<Sample>,
    /// Bytes up to and including the last `SEP` — the end of the last complete sample — of
    /// what this was parsed from: the text [`parse`] was given, or the (decompressed) log
    /// [`read`] streamed. Not an offset into a file [`parse`] read lossily: each byte that is
    /// not text widens to three.
    pub consumed: usize,
    /// How much this was parsed from, so "is there an unfinished sample after the last
    /// complete one" is a question `Parsed` can answer by itself.
    pub len: usize,
    /// Records dropped for not carrying their label's fields: a torn tail, a command line
    /// this format cannot represent unambiguously, a record a guest mangled, or one whose
    /// label carries a different number of fields than this schema pins.
    pub dropped: usize,
    /// Bytes of the samples [`read`] let go of at the front of a log whose samples span more
    /// than [`MAX_LOG`]: every figure over `samples` covers only what followed them.
    pub evicted: u64,
    /// Bytes of the samples [`read`] left out anywhere for spanning more than [`MAX_LOG`] each.
    pub oversized: u64,
    /// [`read`] stopped at [`MAX_READ`]: nothing after that point is in `samples`, or in what
    /// was handed over as evicted.
    pub unread: bool,
}

impl Parsed {
    /// Whether the text holds an incomplete sample after the last complete one — a job
    /// still running, or a guest that died before finishing its final sample.
    pub fn ends_mid_sample(&self) -> bool {
        self.consumed < self.len
    }
}

/// One interval of a guest's life, as the log records it.
#[derive(Clone, Default, serde::Serialize)]
pub struct Sample {
    /// When the sample was taken (seconds since the epoch).
    pub epoch: i64,
    /// Seconds the sample covers; at least 1, and the divisor of every rate below.
    pub interval: u64,
    pub host: String,
    /// The first sample of a recording: its counters cover the guest's whole boot, so it
    /// belongs in a total but not in a rate beside the intervals around it.
    pub boot: bool,
    pub cpu: Option<Cpu>,
    pub cores: Vec<Cpu>,
    pub load: Option<Load>,
    pub mem: Option<Mem>,
    pub swap: Option<Swap>,
    pub paging: Option<Paging>,
    pub psi: Option<Psi>,
    pub disks: Vec<Disk>,
    pub net: Option<Net>,
    pub ifaces: Vec<Iface>,
    /// One entry per process, the four process labels of this sample merged by pid.
    pub procs: Vec<Proc>,
    /// Per-sample count and totals for unnamed exited tasks (pid 0). Their shared pid
    /// cannot distinguish them, so they stay out of `procs`. `None` if no such tasks occur.
    pub exited_unknown: Option<ExitedUnknown>,
}

/// Processor time over the interval, in ticks of `hertz`.
#[derive(Clone, Default, serde::Serialize)]
pub struct Cpu {
    /// Which processor, for a per-core record; `None` for the total across all of them.
    pub core: Option<u32>,
    pub hertz: u64,
    pub cpus: u32,
    pub system: u64,
    pub user: u64,
    pub nice: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}

impl Cpu {
    /// Every tick of the interval, idle included.
    pub fn total(&self) -> u64 {
        self.system
            .saturating_add(self.user)
            .saturating_add(self.nice)
            .saturating_add(self.idle)
            .saturating_add(self.iowait)
            .saturating_add(self.irq)
            .saturating_add(self.softirq)
            .saturating_add(self.steal)
    }

    /// The ticks spent on work: everything but idle and waiting for I/O. Guest time
    /// overlaps user time in this format and is deliberately not added again.
    pub fn busy(&self) -> u64 {
        self.total()
            .saturating_sub(self.idle)
            .saturating_sub(self.iowait)
    }

    /// A tick count as a share of the interval, 0.0–100.0. Zero where the record counted
    /// no ticks at all, which is a sample too short to have any.
    pub fn percent(&self, ticks: u64) -> f64 {
        match self.total() {
            0 => 0.0,
            total => 100.0 * ticks as f64 / total as f64,
        }
    }
}

#[derive(Clone, Default, serde::Serialize)]
pub struct Load {
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    /// Context switches over the interval.
    pub ctxsw: u64,
}

/// Memory as it stood, in pages of `pagesize`.
#[derive(Clone, Default, serde::Serialize)]
pub struct Mem {
    pub pagesize: u64,
    pub physmem: u64,
    pub freemem: u64,
    pub cachemem: u64,
    pub buffermem: u64,
    pub slabreclaim: u64,
}

impl Mem {
    /// Pages as bytes.
    pub fn bytes(&self, pages: u64) -> u64 {
        pages.saturating_mul(self.pagesize)
    }

    /// The memory something holds: everything but what is free and what the kernel could
    /// hand back on demand (the page and buffer caches, and the reclaimable half of slab).
    pub fn used(&self) -> u64 {
        self.physmem
            .saturating_sub(self.freemem)
            .saturating_sub(self.cachemem)
            .saturating_sub(self.buffermem)
            .saturating_sub(self.slabreclaim)
    }

    /// What the caches hold, which a job's own file traffic drives.
    pub fn cache(&self) -> u64 {
        self.cachemem.saturating_add(self.buffermem)
    }
}

#[derive(Clone, Default, serde::Serialize)]
pub struct Swap {
    pub pagesize: u64,
    pub total: u64,
    pub free: u64,
}

impl Swap {
    /// The swap something holds, in bytes.
    pub fn used_bytes(&self) -> u64 {
        self.total
            .saturating_sub(self.free)
            .saturating_mul(self.pagesize)
    }

    pub fn total_bytes(&self) -> u64 {
        self.total.saturating_mul(self.pagesize)
    }
}

/// The paging events that say a guest was short of memory, over the interval.
#[derive(Clone, Default, serde::Serialize)]
pub struct Paging {
    /// Allocations that had to wait for the kernel to reclaim.
    pub allocstalls: u64,
    pub swapins: u64,
    pub swapouts: u64,
    /// `None` on a kernel with no such counter, which the log writes as `-1`.
    pub oomkills: Option<u64>,
}

/// One pressure-stall resource: the averages as they stood, and the microseconds stalled
/// during the interval.
#[derive(Clone, Copy, Default, serde::Serialize)]
pub struct Stall {
    /// The share of the last ten seconds spent stalled, as the sample was taken.
    pub avg10: f64,
    pub total_us: u64,
}

#[derive(Clone, Default, serde::Serialize)]
pub struct Psi {
    /// Whether the guest kernel reports pressure at all (`psi=1` on its cmdline).
    pub supported: bool,
    pub cpu_some: Stall,
    pub mem_some: Stall,
    pub mem_full: Stall,
    pub io_some: Stall,
    pub io_full: Stall,
}

/// One disk over the interval. A device that did nothing has no record, so an absent disk
/// moved nothing rather than being unknown.
#[derive(Clone, Default, serde::Serialize)]
pub struct Disk {
    pub name: String,
    /// Milliseconds the device was busy over the interval.
    pub io_ms: u64,
    pub sectors_read: u64,
    pub sectors_written: u64,
}

/// The bytes a sector count stands for. Fixed at 512 in this format, whatever a device's
/// own block size is — the kernel's own diskstats unit.
pub const SECTOR: u64 = 512;

/// The protocol layers: connections held as they stand, segments resent over the interval.
#[derive(Clone, Default, serde::Serialize)]
pub struct Net {
    pub tcp_established: u64,
    pub tcp_retrans: u64,
}

/// One interface over the interval.
#[derive(Clone, Default, serde::Serialize)]
pub struct Iface {
    pub name: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// One process in one sample: identity as it stands, everything else over the interval.
#[derive(Clone, Default, serde::Serialize)]
pub struct Proc {
    pub pid: i32,
    pub name: String,
    pub cmdline: String,
    /// What the task was doing: the states `/proc` reports for a live one, and `E` for one the
    /// kernel reported the death of — which is the only way a task too short-lived to be swept
    /// appears at all.
    pub state: char,
    /// The status it exited with, as atop encodes it (a signal is its number plus 256). Only
    /// meaningful for an exited task; 0 while it lives.
    pub exitcode: u32,
    /// When the process started (seconds since the epoch), which tells a reused pid from
    /// the process that held it before.
    pub started: i64,
    pub hertz: u64,
    pub utime: u64,
    pub stime: u64,
    /// Resident size as it stands, in KiB. Named with its unit in the JSON: this figure is
    /// the one field whose scale is fixed rather than carried beside it.
    #[serde(rename = "rsize_kib")]
    pub rsize: u64,
    /// 512-byte sectors moved over the interval, and whether the kernel accounted them at
    /// all — without accounting the two counts are meaningless rather than zero.
    pub sectors_read: u64,
    pub sectors_written: u64,
    pub io_stats: bool,
    /// Threads in all, and how many of them were running as the sample was taken.
    pub threads: u64,
    pub threads_running: u64,
    /// Non-running threads by kernel wait channel, as last recorded. The guest writes this
    /// histogram only when it changes. `None` for a single-threaded process (whose wait
    /// channel is in PRC) or a log without these records.
    ///
    /// Carried across samples within one parse or read. A reader parsing pieces of a log, such
    /// as a follower, sees it only from the first record in each piece.
    ///
    /// Shared, not copied, from sample to sample: the histogram's size is the guest's to choose,
    /// and a copy in every later sample would multiply it by the length of the log.
    #[serde(serialize_with = "shared_wchans")]
    pub wchans: Option<Wchans>,
    /// When `wchans` was recorded (seconds since the epoch): it has stood unchanged since.
    pub wchans_since: Option<i64>,
    /// The kernel stack of each thread, in the one sample carrying the dump the guest writes
    /// once for a process it finds stalled (see `vk_core::atop::Stall`); empty in every
    /// other. A snapshot of that moment, not the process's current state.
    pub stacks: Vec<Stack>,
}

/// A process's threads by wait channel, shared by every sample it stands for.
pub type Wchans = Arc<BTreeMap<String, u32>>;

/// [`Proc::wchans`] as the map it shares.
fn shared_wchans<S: serde::Serializer>(wchans: &Option<Wchans>, out: S) -> Result<S::Ok, S::Error> {
    serde::Serialize::serialize(&wchans.as_deref(), out)
}

/// One thread's kernel stack.
#[derive(Clone, Default, serde::Serialize)]
pub struct Stack {
    pub tid: i32,
    /// `None` for a thread waiting in nothing.
    pub wchan: Option<String>,
    /// `function+offset/length`, innermost first; empty where the guest's kernel exposed none.
    pub frames: Vec<String>,
}

impl Proc {
    /// Whether this record is the death of a task rather than a look at a living one.
    pub fn exited(&self) -> bool {
        self.state == 'E'
    }

    /// Whether an exited task ended badly — the reason to look at a burst of them at all.
    pub fn failed(&self) -> bool {
        self.exited() && self.exitcode != 0
    }

    /// The processor time this sample charged to the process, in seconds.
    pub fn cpu_seconds(&self) -> f64 {
        match self.hertz {
            0 => 0.0,
            hz => self.utime.saturating_add(self.stime) as f64 / hz as f64,
        }
    }

    /// What to call the process: its command line, else the bare name a kernel thread has.
    pub fn command(&self) -> &str {
        match self.cmdline.is_empty() {
            true => &self.name,
            false => &self.cmdline,
        }
    }
}

/// atop's placeholder for tasks it caught exiting but could not identify — pid 0, no name,
/// state `E`, the leftover of a command too short-lived for the sweep to read from `/proc`.
/// A recording can hold many at once, all under the one pid; the four process labels of a
/// task cannot be matched up across them, so this is all a reader can honestly keep: how many
/// there were and the time they charged, summed.
#[derive(Clone, Default, serde::Serialize)]
pub struct ExitedUnknown {
    /// Tasks in this sample, counted once each on the CPU record.
    pub tasks: u64,
    pub hertz: u64,
    pub utime: u64,
    pub stime: u64,
    pub sectors_read: u64,
    pub sectors_written: u64,
    pub io_stats: bool,
}

impl ExitedUnknown {
    /// The processor time these tasks charged together, in seconds.
    pub fn cpu_seconds(&self) -> f64 {
        match self.hertz {
            0 => 0.0,
            hz => self.utime.saturating_add(self.stime) as f64 / hz as f64,
        }
    }
}

/// Parse every complete sample in `text`.
pub fn parse(text: &str) -> Parsed {
    let mut parser = Parser::default();
    let (mut samples, mut consumed, mut at) = (Vec::new(), 0usize, 0usize);
    for line in text.split_inclusive('\n') {
        at = at.saturating_add(line.len());
        let line = line.trim_end_matches(['\n', '\r']);
        if line == atop::SEP {
            samples.extend(parser.sep());
            consumed = at;
        } else {
            parser.record(line);
        }
    }
    Parsed {
        samples,
        consumed,
        len: text.len(),
        dropped: parser.dropped,
        evicted: 0,
        oversized: 0,
        unread: false,
    }
}

/// Samples assembled a line at a time — the one state [`parse`] and a [`Stream`] both build on,
/// so a log reads the same whichever reads it.
#[derive(Default)]
struct Parser {
    cur: Builder,
    dropped: usize,
}

impl Parser {
    /// A `SEP` line: the sample it closes, if it closes one. A sample is only complete at its
    /// `SEP`.
    fn sep(&mut self) -> Option<Sample> {
        self.cur.finish()
    }

    /// Any other line, without its line ending.
    fn record(&mut self, line: &str) {
        if line == atop::RESET {
            self.cur.boot = true;
            // The guest writes every process's wait channels afresh after one.
            self.cur.known.clear();
            return;
        }
        if line.is_empty() {
            return;
        }
        let cells = atop::cells(line);
        // virtkit's own labels, whose arity is their own to check.
        if cells.first() == Some(&atop::WCHANS) || cells.first() == Some(&atop::STACK) {
            if !self.cur.task_record(&cells) {
                self.dropped = self.dropped.saturating_add(1);
            }
            return;
        }
        let Some(label) = atop::label_of(&cells) else {
            return; // a label this version does not read is not an error
        };
        if cells.len() != label.arity() {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.cur.record(&Record { label, cells });
    }

    /// Drop the sample being built, keeping what carries across samples.
    fn abandon(&mut self) {
        self.cur.discard();
    }
}

/// Write every sample as one JSON object per line, which is what a pipeline reads: `jq` and
/// its like take a line at a time, and no JSON document is built for the whole log.
///
/// The objects carry the log's own units, so nothing is rounded on the way out: pages, with
/// their `pagesize` beside them; ticks, with their `hertz` beside them; 512-byte sectors; and
/// KiB for a process's resident size (`rsize_kib`). A counter the guest's kernel does not have
/// is `null`, never a zero — as is a scale the sample did not carry a record for, which is why
/// `hertz` and `pagesize` are worth checking before dividing by one.
///
/// These field names are the interface `--json` promises: renaming one breaks the scripts
/// reading it.
pub fn write_json(samples: &[Sample], out: &mut impl std::io::Write) -> std::io::Result<()> {
    for sample in samples {
        // Rendered whole before any of it is written, so a closed pipe cannot leave half an
        // object on a reader's stdin.
        let line = serde_json::to_string(sample).map_err(std::io::Error::other)?;
        out.write_all(line.as_bytes())?;
        out.write_all(b"\n")?;
    }
    Ok(())
}

/// One record, read by field name rather than by a counted-out position.
struct Record<'a> {
    label: &'static Label,
    cells: Vec<&'a str>,
}

impl Record<'_> {
    fn raw(&self, field: &str) -> &str {
        self.label
            .index_of(field)
            .and_then(|i| self.cells.get(i))
            .copied()
            .unwrap_or_default()
    }

    /// A numeric field, or the type's zero where the guest wrote something unparseable.
    fn num<T: std::str::FromStr + Default>(&self, field: &str) -> T {
        self.raw(field).parse().unwrap_or_default()
    }

    /// A `-1`-means-unknown counter.
    fn counter(&self, field: &str) -> Option<u64> {
        match self.raw(field).parse::<i64>() {
            Ok(n) if n >= 0 => Some(n as u64),
            _ => None,
        }
    }

    /// A real-valued field. A guest can write `nan` or `inf` and both parse: neither is a
    /// number JSON can name (each would serialize as `null`, which this format reserves for a
    /// counter the kernel does not have), and no average over one means anything — so a figure
    /// that is not finite reads as zero.
    fn real(&self, field: &str) -> f64 {
        let v: f64 = self.num(field);
        match v.is_finite() {
            true => v,
            false => 0.0,
        }
    }

    /// A parenthesised string field, unwrapped.
    fn text(&self, field: &str) -> String {
        let raw = self.raw(field);
        raw.strip_prefix('(')
            .and_then(|r| r.strip_suffix(')'))
            .unwrap_or(raw)
            .to_string()
    }

    fn flag(&self, field: &str) -> bool {
        self.raw(field) == "y"
    }

    fn char(&self, field: &str) -> char {
        self.raw(field).chars().next().unwrap_or('?')
    }
}

/// A sample under construction: records arrive one line at a time and the four process
/// labels have to be merged by pid.
#[derive(Default)]
struct Builder {
    boot: bool,
    sample: Sample,
    procs: BTreeMap<i32, Proc>,
    /// Sum unnamed exited tasks as records arrive: their shared pid 0 cannot identify
    /// separate entries in `procs`.
    exited_unknown: ExitedUnknown,
    any: bool,
    /// Whether the generic columns have been taken from a record yet — a flag rather than a
    /// sentinel epoch, since a guest whose clock is unset stamps 0 and means it.
    generic: bool,
    /// This sample's PRW and PRK records, by pid.
    wchans: BTreeMap<i32, BTreeMap<String, u32>>,
    stacks: BTreeMap<i32, Vec<Stack>>,
    /// The wait channels last recorded for each live multi-threaded process (pid, start time),
    /// and when — carried from sample to sample, since the guest does not repeat them. A
    /// histogram holds one entry per distinct channel, a handful, so a copy per sample costs
    /// about what the command line beside it does. Stacks are not carried: they are the
    /// largest record in a log, and stay in the one sample that holds them.
    known: HashMap<(i32, i64), (Wchans, i64)>,
}

impl Builder {
    /// The sample this builder holds, or `None` when the `SEP` closed nothing — a log that
    /// starts mid-sample, or two separators in a row.
    fn finish(&mut self) -> Option<Sample> {
        if !self.any {
            self.boot = false;
            self.wchans.clear();
            self.stacks.clear();
            return None;
        }
        let mut sample = std::mem::take(&mut self.sample);
        sample.boot = std::mem::take(&mut self.boot);
        sample.procs = std::mem::take(&mut self.procs).into_values().collect();
        self.carry(&mut sample);
        let unknown = std::mem::take(&mut self.exited_unknown);
        sample.exited_unknown = (unknown.tasks > 0).then_some(unknown);
        // At least 1, whatever the log says: this is the divisor of every rate a reader
        // computes, and the guest promises but does not enforce it.
        sample.interval = sample.interval.max(1);
        self.any = false;
        self.generic = false;
        Some(sample)
    }

    /// Drop the sample being built — its records, wait channels and stacks — and leave what
    /// carries across samples as it was.
    fn discard(&mut self) {
        self.sample = Sample::default();
        self.procs.clear();
        self.exited_unknown = ExitedUnknown::default();
        self.wchans.clear();
        self.stacks.clear();
        self.boot = false;
        self.any = false;
        self.generic = false;
    }

    /// Attach each process's last recorded wait channels and this sample's stacks. Carry
    /// the wait channels into the next sample, forgetting processes that are gone or now
    /// single-threaded.
    fn carry(&mut self, sample: &mut Sample) {
        let mut wchans = std::mem::take(&mut self.wchans);
        let mut stacks = std::mem::take(&mut self.stacks);
        let mut known = HashMap::new();
        for p in &mut sample.procs {
            let key = (p.pid, p.started);
            if p.threads <= 1 || p.exited() {
                continue;
            }
            p.stacks = stacks.remove(&p.pid).unwrap_or_default();
            let recorded = match wchans.remove(&p.pid) {
                Some(w) => Some((Arc::new(w), sample.epoch)),
                None => self.known.remove(&key),
            };
            if let Some((w, since)) = recorded {
                p.wchans = Some(Arc::clone(&w));
                p.wchans_since = Some(since);
                known.insert(key, (w, since));
            }
        }
        self.known = known;
    }

    /// Take a PRW or PRK record into this sample; `false` when it is malformed. A later
    /// record replaces an earlier one for the same process or thread: a torn sample (no
    /// `SEP`) runs into the next, which may carry the same records again.
    fn task_record(&mut self, cells: &[&str]) -> bool {
        if let Some(w) = atop::parse_wchans(cells) {
            let mut hist = BTreeMap::new();
            for (wchan, n) in w.counts {
                let slot: &mut u32 = hist.entry(wchan.to_string()).or_default();
                *slot = slot.saturating_add(n);
            }
            self.wchans.insert(w.pid, hist);
            return true;
        }
        if let Some(s) = atop::parse_stack(cells) {
            let stack = Stack {
                tid: s.tid,
                wchan: s.wchan.map(str::to_string),
                frames: s.frames.into_iter().map(str::to_string).collect(),
            };
            let stacks = self.stacks.entry(s.pid).or_default();
            match stacks.iter_mut().find(|t| t.tid == stack.tid) {
                Some(held) => *held = stack,
                None => stacks.push(stack),
            }
            return true;
        }
        false
    }

    fn record(&mut self, r: &Record) {
        self.any = true;
        // Every record of a sample repeats the generic columns; the first one to arrive
        // fixes them for the sample.
        if !self.generic {
            self.generic = true;
            self.sample.epoch = r
                .cells
                .get(atop::COL_EPOCH)
                .and_then(|c| c.parse().ok())
                .unwrap_or(0);
            self.sample.interval = r
                .cells
                .get(atop::COL_INTERVAL)
                .and_then(|c| c.parse().ok())
                .unwrap_or(1);
            self.sample.host = r
                .cells
                .get(atop::COL_HOST)
                .copied()
                .unwrap_or_default()
                .to_string();
        }
        match r.label.name {
            "CPU" => self.sample.cpu = Some(cpu(r, None)),
            "cpu" => {
                let core = r.num::<u32>("cpu");
                self.sample.cores.push(cpu(r, Some(core)));
            }
            "CPL" => {
                self.sample.load = Some(Load {
                    load1: r.real("load1"),
                    load5: r.real("load5"),
                    load15: r.real("load15"),
                    ctxsw: r.num("ctxsw"),
                })
            }
            "MEM" => {
                self.sample.mem = Some(Mem {
                    pagesize: r.num("pagesize"),
                    physmem: r.num("physmem"),
                    freemem: r.num("freemem"),
                    cachemem: r.num("cachemem"),
                    buffermem: r.num("buffermem"),
                    slabreclaim: r.num("slabreclaim"),
                })
            }
            "SWP" => {
                self.sample.swap = Some(Swap {
                    pagesize: r.num("pagesize"),
                    total: r.num("swaptotal"),
                    free: r.num("swapfree"),
                })
            }
            "PAG" => {
                self.sample.paging = Some(Paging {
                    allocstalls: r.num("allocstalls"),
                    swapins: r.num("swapins"),
                    swapouts: r.num("swapouts"),
                    oomkills: r.counter("oomkills"),
                })
            }
            "PSI" => {
                self.sample.psi = Some(Psi {
                    supported: r.flag("supported"),
                    cpu_some: stall(r, "cpusome"),
                    mem_some: stall(r, "memsome"),
                    mem_full: stall(r, "memfull"),
                    io_some: stall(r, "iosome"),
                    io_full: stall(r, "iofull"),
                })
            }
            "DSK" => self.sample.disks.push(Disk {
                name: r.raw("name").to_string(),
                io_ms: r.num("io-ms"),
                sectors_read: r.num("sectors-read"),
                sectors_written: r.num("sectors-written"),
            }),
            "NET" if r.raw("layer") == atop::NET_UPPER_LAYER => {
                self.sample.net = Some(Net {
                    tcp_established: r.num("tcp-established"),
                    tcp_retrans: r.num("tcp-retrans"),
                })
            }
            "NET" => self.sample.ifaces.push(Iface {
                name: r.raw("name").to_string(),
                bytes_in: r.num("bytes-in"),
                bytes_out: r.num("bytes-out"),
            }),
            // A process label carrying pid 0 is atop's exited-but-unnamed placeholder, never a
            // real process: it is summed rather than merged into a `procs` entry that 0 would
            // make no key for.
            "PRG" | "PRC" | "PRM" | "PRD" if r.num::<i32>("pid") == 0 => self.exited_unknown(r),
            "PRG" => {
                let p = self.proc(r);
                p.name = r.text("name");
                p.cmdline = r.text("cmdline");
                p.started = r.num("starttime");
                p.state = r.char("state");
                p.exitcode = r.num("exitcode");
                p.threads = r.num("threads");
                p.threads_running = r.num("threads-running");
            }
            "PRC" => {
                let p = self.proc(r);
                p.name = r.text("name");
                p.state = r.char("state");
                p.hertz = r.num("hertz");
                p.utime = r.num("utime");
                p.stime = r.num("stime");
            }
            "PRM" => {
                let p = self.proc(r);
                p.name = r.text("name");
                p.rsize = r.num("rsize");
            }
            "PRD" => {
                let p = self.proc(r);
                p.name = r.text("name");
                p.io_stats = r.flag("io-stats");
                p.sectors_read = r.num("sectors-read");
                p.sectors_written = r.num("sectors-written");
            }
            _ => {}
        }
    }

    /// Fold one pid-0 record into the sample's exited-but-unnamed total. The task is counted
    /// once, on its PRC record — the one that carries cpu, and the one atop writes per task;
    /// the other labels only add their own quarter, and PRG and PRM carry a name and a
    /// resident size an exited task no longer has.
    fn exited_unknown(&mut self, r: &Record) {
        let acc = &mut self.exited_unknown;
        match r.label.name {
            "PRC" => {
                acc.tasks = acc.tasks.saturating_add(1);
                acc.hertz = acc.hertz.max(r.num("hertz"));
                acc.utime = acc.utime.saturating_add(r.num("utime"));
                acc.stime = acc.stime.saturating_add(r.num("stime"));
            }
            "PRD" => {
                acc.io_stats |= r.flag("io-stats");
                acc.sectors_read = acc.sectors_read.saturating_add(r.num("sectors-read"));
                acc.sectors_written = acc.sectors_written.saturating_add(r.num("sectors-written"));
            }
            _ => {}
        }
    }

    /// The process this record is about, created on first sight: the four process labels
    /// each carry a quarter of it.
    fn proc(&mut self, r: &Record) -> &mut Proc {
        let pid = r.num("pid");
        self.procs.entry(pid).or_insert_with(|| Proc {
            pid,
            ..Default::default()
        })
    }
}

fn cpu(r: &Record, core: Option<u32>) -> Cpu {
    Cpu {
        core,
        hertz: r.num("hertz"),
        cpus: r.num("cpus"),
        system: r.num("system"),
        user: r.num("user"),
        nice: r.num("nice"),
        idle: r.num("idle"),
        iowait: r.num("iowait"),
        irq: r.num("irq"),
        softirq: r.num("softirq"),
        steal: r.num("steal"),
    }
}

fn stall(r: &Record, resource: &str) -> Stall {
    Stall {
        avg10: r.real(&format!("{resource}-avg10")),
        total_us: r.num(&format!("{resource}-total")),
    }
}

/// A log of `samples` samples for a test to write, compress and read back: each a CPU record
/// and a process whose command line varies from one sample to the next, so it compresses the
/// way a real log does — well, but not to nothing.
#[cfg(test)]
pub(crate) fn synthetic_log(samples: usize) -> String {
    use std::fmt::Write;
    let mut text = String::from("RESET\n");
    let mut seed: u64 = 42;
    for i in 0..samples {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let epoch = 1000 + 10 * i;
        let _ = write!(
            text,
            "CPU runner {epoch} 1970/01/01 00:16:40 10 100 2 {} 3 0 2991 0 0 0 0 0 0 100 0 0\n\
             PRG runner {epoch} 1970/01/01 00:16:40 10 7 (cc1) S 0 0 7 1 0 900 (cc1 -o {seed:x}.o) \
             1 1 0 0 0 0 0 0 0 0 0 y 0 0 - N ()\n\
             SEP\n",
            seed % 997
        );
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A whole sample as the guest writes one, trimmed to a couple of processes and one
    /// disk. Written out rather than generated so the parser is tested against the format
    /// as it appears on disk.
    const LOG: &str = "\
RESET
CPU runner 1000 1970/01/01 00:16:40 40 100 2 20 10 0 760 4 0 6 0 0 0 100 0 0
cpu runner 1000 1970/01/01 00:16:40 40 100 0 9 4 0 380 2 0 3 0 0 0 100 0 0
cpu runner 1000 1970/01/01 00:16:40 40 100 1 11 6 0 380 2 0 3 0 0 0 100 0 0
CPL runner 1000 1970/01/01 00:16:40 40 2 0.50 0.25 0.10 4242 909
MEM runner 1000 1970/01/01 00:16:40 40 4096 250000 200000 20000 500 3000 40 1500 0 700 0 0 2097152 0 0 0 0 0 0 0 250
SWP runner 1000 1970/01/01 00:16:40 40 4096 0 0 0 41026 126424 0 0 0
PAG runner 1000 1970/01/01 00:16:40 40 4096 0 0 0 0 0 -1 0 0 0 12 4
PSI runner 1000 1970/01/01 00:16:40 40 y 0.5 0.2 0.1 1000 0.0 0.0 0.0 0 0.0 0.0 0.0 0 1.5 0.4 0.2 4000 0.0 0.0 0.0 0
DSK runner 1000 1970/01/01 00:16:40 40 vda 200 10 80 5 40 -1 0 1 2.50
NET runner 1000 1970/01/01 00:16:40 40 upper 1 2 9 10 13 14 15 16 11 12 3 4 5 6 7 8
NET runner 1000 1970/01/01 00:16:40 40 eth0 100 20000 90 9000 10000 1
PRG runner 1000 1970/01/01 00:16:40 40 412 (sh) S 1000 100 412 3 0 900 (sh -c make test) 1 1 2 0 1000 100 1000 100 1000 100 0 y 0 0 - N ()
PRG runner 1000 1970/01/01 00:16:40 40 9 (php-fpm8.5) S 0 0 9 1 0 900 (php-fpm: master process (/etc/php/fpm.conf)) 1 0 1 0 0 0 0 0 0 0 0 y 0 0 - - ()
PRC runner 1000 1970/01/01 00:16:40 40 412 (sh) S 100 120 30 5 25 0 0 1 0 412 y 9000000 (do_wait) 7 -3 -3
PRC runner 1000 1970/01/01 00:16:40 40 9 (php-fpm8.5) S 100 4 2 0 20 0 0 0 0 9 y 0 (0) 0 -3 -3
PRM runner 1000 1970/01/01 00:16:40 40 412 (sh) S 4096 20000 8000 700 20000 8000 900 2 2400 1100 132 0 412 y 0 0 -3 -3 -3 -3
PRM runner 1000 1970/01/01 00:16:40 40 9 (php-fpm8.5) S 4096 30000 12000 700 0 0 10 0 2400 1100 132 0 9 y 0 0 -3 -3 -3 -3
PRD runner 1000 1970/01/01 00:16:40 40 412 (sh) S n y 11 176 4 64 8 412 n y
PRD runner 1000 1970/01/01 00:16:40 40 9 (php-fpm8.5) S n y 0 0 0 0 0 9 n y
SEP
CPU runner 1030 1970/01/01 00:17:10 30 100 2 6 3 0 2991 0 0 0 0 0 0 100 0 0
MEM runner 1030 1970/01/01 00:17:10 30 4096 250000 190000 22000 500 3000 40 1500 0 700 0 0 2097152 0 0 0 0 0 0 0 250
PRC runner 1030 1970/01/01 00:17:10 30 412 (sh) S 100 60 15 5 25 0 0 1 0 412 y 900 (do_wait) 0 -3 -3
SEP
";

    #[test]
    fn a_log_parses_into_its_samples() {
        let p = parse(LOG);
        assert_eq!(p.samples.len(), 2);
        assert_eq!(p.dropped, 0);
        assert!(!p.ends_mid_sample(), "the log ends on a SEP");

        let first = &p.samples[0];
        assert!(first.boot, "the RESET sample covers the boot");
        assert_eq!(first.epoch, 1000);
        assert_eq!(first.interval, 40);
        assert_eq!(first.host, "runner");

        let cpu = first.cpu.as_ref().expect("a CPU record");
        assert_eq!(cpu.cpus, 2);
        assert_eq!((cpu.user, cpu.system, cpu.idle), (10, 20, 760));
        assert_eq!(cpu.total(), 800);
        assert_eq!(cpu.busy(), 36, "everything but idle and iowait");
        assert_eq!(cpu.percent(cpu.busy()).round(), 5.0);
        assert_eq!(first.cores.len(), 2);
        assert_eq!(first.cores[1].core, Some(1));

        let load = first.load.as_ref().expect("a CPL record");
        assert_eq!((load.load1, load.load5, load.load15), (0.5, 0.25, 0.10));
        assert_eq!(load.ctxsw, 4242);

        let mem = first.mem.as_ref().expect("a MEM record");
        assert_eq!(mem.physmem, 250_000);
        assert_eq!(mem.bytes(mem.physmem), 250_000 * 4096);
        // used = physmem - free - cache - buffers - reclaimable slab
        assert_eq!(mem.used(), 250_000 - 200_000 - 20_000 - 500 - 1_500);
        assert_eq!(mem.cache(), 20_500);
        let swap = first.swap.as_ref().expect("a SWP record");
        assert_eq!((swap.used_bytes(), swap.total_bytes()), (0, 0));

        let pag = first.paging.as_ref().expect("a PAG record");
        assert_eq!(pag.oomkills, None, "-1 is unknown, not zero");
        assert_eq!((pag.allocstalls, pag.swapouts), (0, 0));

        let psi = first.psi.as_ref().expect("a PSI record");
        assert!(psi.supported);
        assert_eq!(psi.cpu_some.avg10, 0.5);
        assert_eq!(psi.io_some.total_us, 4000);
        assert_eq!(psi.io_full.total_us, 0);

        assert_eq!(first.disks.len(), 1);
        assert_eq!(first.disks[0].name, "vda");
        assert_eq!(first.disks[0].sectors_written, 40);
        assert_eq!(first.disks[0].io_ms, 200);
        let net = first.net.as_ref().expect("a NET upper record");
        assert_eq!((net.tcp_established, net.tcp_retrans), (5, 6));
        assert_eq!(
            first.ifaces.len(),
            1,
            "the upper record is not an interface"
        );
        assert_eq!(first.ifaces[0].bytes_in, 20_000);
    }

    /// The four process labels of a sample are one process each, and a command line with
    /// spaces — or parentheses of its own — survives being read back.
    #[test]
    fn the_process_labels_merge_by_pid() {
        let p = parse(LOG);
        let first = &p.samples[0];
        assert_eq!(first.procs.len(), 2);
        let sh = first.procs.iter().find(|p| p.pid == 412).expect("pid 412");
        assert_eq!(sh.name, "sh");
        assert_eq!(sh.cmdline, "sh -c make test");
        assert_eq!(sh.command(), "sh -c make test");
        assert_eq!(sh.started, 900);
        assert_eq!((sh.utime, sh.stime, sh.hertz), (120, 30, 100));
        assert_eq!(sh.cpu_seconds(), 1.5);
        assert_eq!(sh.rsize, 8000);
        assert!(sh.io_stats);
        assert_eq!((sh.sectors_read, sh.sectors_written), (176, 64));

        let php = first.procs.iter().find(|p| p.pid == 9).expect("pid 9");
        assert_eq!(php.name, "php-fpm8.5");
        assert_eq!(
            php.command(),
            "php-fpm: master process (/etc/php/fpm.conf)",
            "a command line holds its own parentheses"
        );

        // A sample that carries only some of the labels still yields what it has.
        let second = &p.samples[1];
        assert_eq!(second.procs.len(), 1);
        assert_eq!(second.procs[0].cpu_seconds(), 0.75);
        assert!(second.cpu.is_some() && second.psi.is_none());
        assert!(!second.boot);
    }

    /// Unnamed exited records share pid 0 within a sample. Sum them in `exited_unknown`
    /// instead of merging them into one process in `procs`.
    #[test]
    fn pid_zero_records_sum_into_exited_unknown() {
        let extra = "\
PRC runner 1000 1970/01/01 00:16:40 40 0 () E 100 100 50 0 0 0 0 -1 0 0 y 0 () 0 -3 -3
PRC runner 1000 1970/01/01 00:16:40 40 0 () E 100 20 10 0 0 0 0 -1 0 0 y 0 () 0 -3 -3
PRD runner 1000 1970/01/01 00:16:40 40 0 () E n y 2 8 1 4 0 0 n y
PRD runner 1000 1970/01/01 00:16:40 40 0 () E n y 2 8 1 4 0 0 n y
";
        let text = LOG.replacen("SEP\n", &format!("{extra}SEP\n"), 1);
        let first = &parse(&text).samples[0];
        // The two real processes are untouched; pid 0 never becomes one of them.
        assert_eq!(first.procs.len(), 2);
        assert!(first.procs.iter().all(|p| p.pid != 0));

        let u = first
            .exited_unknown
            .as_ref()
            .expect("an exited-unknown total");
        assert_eq!(u.tasks, 2, "one per PRC record, not clobbered");
        assert_eq!((u.utime, u.stime), (120, 60), "summed, not overwritten");
        assert_eq!(u.cpu_seconds(), 1.8);
        assert_eq!((u.sectors_read, u.sectors_written), (16, 8));
        assert!(u.io_stats);

        // A sample with no such records carries none.
        assert!(parse(LOG).samples[0].exited_unknown.is_none());
    }

    /// The crash guarantee: a guest killed mid-write leaves a truncated line, and the
    /// samples before it must still read. What is past the last `SEP` is not a sample.
    #[test]
    fn a_torn_tail_leaves_the_samples_before_it_readable() {
        let torn = format!(
            "{LOG}CPU runner 1060 1970/01/01 00:17:40 30 100 2 6 3 0 2991 0 0 0 0 0 0 100 0 0\n\
             PRC runner 1060 1970/01/01 00:17:40 30 412 (sh) S 100 60 15 5 25 0 0 1 0 41"
        );
        let p = parse(&torn);
        assert_eq!(p.samples.len(), 2, "only what a SEP closed");
        assert!(p.ends_mid_sample());
        assert_eq!(p.consumed, LOG.len(), "a follower resumes at the last SEP");
        assert_eq!(p.dropped, 1, "the torn record does not have its fields");

        // Reading the same text again from where it stopped yields the rest once the
        // interrupted sample is finished.
        let rest = format!("{}\nSEP\n", &torn[p.consumed..]);
        let more = parse(&rest);
        assert_eq!(more.samples.len(), 1);
        assert_eq!(more.samples[0].epoch, 1060);
    }

    /// A log whose first bytes are the middle of a sample (a reader that started late)
    /// yields nothing for that sample rather than a half of one.
    #[test]
    fn a_log_that_starts_mid_sample_drops_it() {
        let p = parse("MEM runner 1000 1970/01/01 00:16:40 40 4096 1 1\nSEP\nSEP\n");
        assert!(p.samples.is_empty(), "the MEM record was short, and a SEP");
        assert_eq!(p.dropped, 1);
        assert_eq!(parse("").samples.len(), 0);
        assert_eq!(parse("SEP\n").samples.len(), 0);
    }

    /// A task the kernel reported the death of: state `E`, an exit status, and the whole of
    /// what it used — the only way a command too short-lived to be swept appears at all.
    #[test]
    fn an_exited_task_reads_back_as_one() {
        let text = "\
CPU runner 1000 1970/01/01 00:16:40 30 100 2 6 3 0 2991 0 0 0 0 0 0 100 0 0
PRG runner 1000 1970/01/01 00:16:40 30 99 (cc1plus) E 0 0 99 1 265 990 (cc1plus) 412 0 0 0 0 0 0 0 0 0 40 y 0 0 - N ()
PRC runner 1000 1970/01/01 00:16:40 30 99 (cc1plus) E 100 30 10 0 0 0 0 -1 0 99 y 0 () 0 -3 -3
PRM runner 1000 1970/01/01 00:16:40 30 99 (cc1plus) E 4096 0 8192 0 0 0 120 3 0 0 0 0 99 y 0 0 -3 -3 -3 -3
PRD runner 1000 1970/01/01 00:16:40 30 99 (cc1plus) E n y 6 16 3 8 0 99 n y
PRG runner 1000 1970/01/01 00:16:40 30 412 (make) S 0 0 412 1 0 900 (make -j8) 1 1 0 0 0 0 0 0 0 0 0 y 0 0 - - ()
SEP
";
        let p = parse(text);
        assert_eq!(p.samples.len(), 1);
        let procs = &p.samples[0].procs;
        assert_eq!(procs.len(), 2);
        let dead = procs.iter().find(|p| p.pid == 99).expect("the exited task");
        assert!(dead.exited(), "state {}", dead.state);
        assert!(dead.failed(), "it was killed, which is a failure");
        assert_eq!(dead.exitcode, 265, "the signal that killed it, plus 256");
        assert_eq!(dead.command(), "cc1plus", "a dead task has only its name");
        assert_eq!(dead.cpu_seconds(), 0.4);
        assert_eq!(dead.rsize, 8192, "the most it ever held");
        assert_eq!((dead.sectors_read, dead.sectors_written), (16, 8));

        let live = procs.iter().find(|p| p.pid == 412).expect("the live one");
        assert!(!live.exited() && !live.failed());
        assert_eq!(live.state, 'S');
        assert_eq!(live.exitcode, 0);
        assert_eq!(live.command(), "make -j8");
    }

    /// Every sample is one line of JSON, carrying the log's own units and the scales that
    /// make sense of them, so a pipeline reads a sample at a time.
    #[test]
    fn samples_serialize_one_object_per_line() {
        let parsed = parse(LOG);
        let mut out: Vec<u8> = Vec::new();
        write_json(&parsed.samples, &mut out).expect("writing to a Vec cannot fail");
        let text = String::from_utf8(out).expect("json is text");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "one line per sample");

        let first: serde_json::Value = serde_json::from_str(lines[0]).expect("a JSON object");
        assert_eq!(first["epoch"], 1000);
        assert_eq!(first["interval"], 40);
        assert_eq!(first["host"], "runner");
        assert_eq!(first["boot"], true);
        // the scale beside the figures it applies to
        assert_eq!(first["cpu"]["hertz"], 100);
        assert_eq!(first["cpu"]["user"], 10);
        assert_eq!(first["mem"]["pagesize"], 4096);
        assert_eq!(first["mem"]["physmem"], 250_000);
        // a counter this kernel does not have is null, not zero
        assert_eq!(first["paging"]["oomkills"], serde_json::Value::Null);
        assert_eq!(first["psi"]["io_some"]["total_us"], 4000);
        assert_eq!(first["disks"][0]["name"], "vda");
        assert_eq!(first["ifaces"][0]["name"], "eth0");
        assert_eq!(first["cores"].as_array().expect("two cores").len(), 2);
        let procs = first["procs"].as_array().expect("processes");
        assert_eq!(procs.len(), 2);
        let sh = procs.iter().find(|p| p["pid"] == 412).expect("pid 412");
        assert_eq!(sh["cmdline"], "sh -c make test");
        assert_eq!(sh["utime"], 120);
        assert_eq!(
            sh["rsize_kib"], 8000,
            "named with its unit: the one fixed scale"
        );
        assert_eq!(sh["io_stats"], true);

        // A label a sample did not carry is null rather than missing, so every line has the
        // same shape whatever the guest recorded.
        let second: serde_json::Value = serde_json::from_str(lines[1]).expect("a JSON object");
        assert_eq!(second["boot"], false);
        assert_eq!(second["psi"], serde_json::Value::Null);
    }

    /// The log is text a hostile process chose: a command line can hold quotes, backslashes
    /// and bytes that are not text, and one line of JSON has to survive all of them.
    #[test]
    fn a_hostile_command_line_still_yields_one_valid_line() {
        let cmd = "sh -c echo \"a\\b\"\u{1}\u{fffd}\ttail";
        let log = format!(
            "PRG runner 1000 1970/01/01 00:16:40 40 412 (sh) S 1000 100 412 3 0 900 ({cmd}) \
             1 1 2 0 1000 100 1000 100 1000 100 0 y 0 0 - N ()\nSEP\n"
        );
        let mut out: Vec<u8> = Vec::new();
        write_json(&parse(&log).samples, &mut out).expect("writing to a Vec cannot fail");
        let text = String::from_utf8(out).expect("json is text");
        assert_eq!(
            text.lines().count(),
            1,
            "one line, whatever the command held"
        );
        let v: serde_json::Value = serde_json::from_str(text.trim_end()).expect("a JSON object");
        assert_eq!(v["procs"][0]["cmdline"], cmd, "escaped, and back again");
    }

    /// `nan` and `inf` parse as floats but are numbers JSON cannot name — and `null` here
    /// would read as a counter the guest's kernel does not have, which is a different thing.
    #[test]
    fn a_figure_that_is_not_finite_reads_as_zero() {
        let parsed = parse("CPL runner 1000 1970/01/01 00:16:40 40 2 nan inf -inf 4242 909\nSEP\n");
        let load = parsed.samples[0].load.as_ref().expect("a CPL record");
        assert_eq!((load.load1, load.load5, load.load15), (0.0, 0.0, 0.0));
        let mut out: Vec<u8> = Vec::new();
        write_json(&parsed.samples, &mut out).expect("writing to a Vec cannot fail");
        let text = String::from_utf8(out).expect("json is text");
        let v: serde_json::Value = serde_json::from_str(text.trim_end()).expect("a JSON object");
        assert_eq!(v["load"]["load1"], 0.0, "a number, not null");
    }

    /// A log with nothing complete in it writes nothing, so a pipeline reads an empty stream
    /// rather than half an object.
    #[test]
    fn a_log_with_no_complete_sample_writes_nothing() {
        for text in [
            "",
            "SEP\n",
            "CPU runner 1000 1970/01/01 00:16:40 40 100 2 20 10 0 760 4 0 6 0 0 0 100 0 0\n",
        ] {
            let mut out: Vec<u8> = Vec::new();
            write_json(&parse(text).samples, &mut out).expect("writing to a Vec cannot fail");
            assert!(out.is_empty(), "{text:?} holds no complete sample");
        }
    }

    /// A multi-threaded process's wait channels are written only when they change, so each
    /// sample carries the latest ones and when they were recorded — as does its JSON — while
    /// the stacks the guest dumped stay in the one sample that holds them. A process that
    /// turns single-threaded has none, and a malformed record is damage.
    #[test]
    fn wait_channels_carry_forward_until_they_change() {
        let sample = |epoch: i64, threads: u32, extra: &str| {
            let (date, time) = atop::date_time(epoch);
            let h = |label: &str| format!("{label} runner {epoch} {date} {time} 10");
            format!(
                "{} 412 (ruff) S 1000 100 412 {threads} 0 900 (ruff check .) 1 0 {threads} 0 \
                 1000 100 1000 100 1000 100 0 y 0 0 - - ()\n{extra}SEP\n",
                h("PRG")
            )
            .replace("{PRW}", &h("PRW"))
            .replace("{PRK}", &h("PRK"))
        };
        let text = [
            sample(1_000, 9, "{PRW} 412 (ruff) futex_do_wait:1 hrtimer_nanosleep:8\n"),
            sample(1_010, 9, ""),
            sample(
                1_020,
                9,
                "{PRW} 412 (ruff) futex_do_wait:1 hrtimer_nanosleep:7 request_wait_answer:1\n\
                 {PRK} 412 (ruff) 412 futex_do_wait futex_do_wait+0x4e/0x80;__futex_wait+0x8c/0x110\n\
                 {PRK} 412 (ruff) 415 request_wait_answer -\n",
            ),
            sample(1_030, 9, "{PRW} 412 (ruff) futex_do_wait:x\n"),
            sample(1_040, 1, ""),
        ]
        .concat();
        let p = parse(&text);
        assert_eq!(p.samples.len(), 5);
        assert_eq!(p.dropped, 1, "the PRW whose count is no number");
        let ruff = |i: usize| &p.samples[i].procs[0];
        assert_eq!((ruff(0).threads, ruff(0).threads_running), (9, 0));
        let first = ruff(0).wchans.clone().expect("recorded");
        assert_eq!(first.get("hrtimer_nanosleep"), Some(&8));
        assert_eq!(ruff(1).wchans.as_ref(), Some(&first), "carried");
        assert_eq!(ruff(1).wchans_since, Some(1_000));
        assert!(ruff(1).stacks.is_empty());
        assert_eq!(ruff(2).wchans_since, Some(1_020));
        assert_eq!(ruff(2).wchans.as_ref().map(|w| w.len()), Some(3));
        assert_eq!(ruff(2).stacks.len(), 2);
        assert_eq!(
            ruff(2).stacks[1].wchan.as_deref(),
            Some("request_wait_answer")
        );
        assert!(ruff(2).stacks[1].frames.is_empty());
        assert_eq!(
            ruff(3).wchans_since,
            Some(1_020),
            "the damaged record changed nothing"
        );
        assert!(
            ruff(3).stacks.is_empty(),
            "stacks stay in the sample that holds them"
        );
        assert!(ruff(4).wchans.is_none() && ruff(4).stacks.is_empty());

        let mut out: Vec<u8> = Vec::new();
        write_json(&p.samples, &mut out).expect("writing to a Vec cannot fail");
        let text = String::from_utf8(out).expect("json is text");
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).expect("a JSON object"))
            .collect();
        let proc = &lines[2]["procs"][0];
        assert_eq!(proc["threads"], 9);
        assert_eq!(proc["threads_running"], 0);
        assert_eq!(lines[3]["procs"][0]["wchans"]["request_wait_answer"], 1);
        assert_eq!(lines[3]["procs"][0]["wchans_since"], 1_020);
        assert_eq!(lines[3]["procs"][0]["stacks"], serde_json::json!([]));
        assert_eq!(proc["stacks"][0]["tid"], 412);
        assert_eq!(proc["stacks"][0]["frames"][1], "__futex_wait+0x8c/0x110");
        assert_eq!(proc["stacks"][1]["wchan"], "request_wait_answer");
        assert_eq!(lines[4]["procs"][0]["wchans"], serde_json::Value::Null);
    }

    /// A multi-threaded process's PRG line, the wait-channel and stack records given, and a
    /// `SEP` when `sep` — one guest sample at `epoch`.
    fn threaded_sample(epoch: i64, extra: &str, sep: bool) -> String {
        let (date, time) = atop::date_time(epoch);
        let h = |label: &str| format!("{label} runner {epoch} {date} {time} 10");
        format!(
            "{} 412 (ruff) S 1000 100 412 9 0 900 (ruff check .) 1 0 9 0 \
             1000 100 1000 100 1000 100 0 y 0 0 - - ()\n{}{}",
            h("PRG"),
            extra
                .replace("{PRW}", &h("PRW"))
                .replace("{PRK}", &h("PRK")),
            match sep {
                true => "SEP\n",
                false => "",
            }
        )
    }

    /// A torn sample — no `SEP` — runs into the next one, which carries the same records
    /// again: the later ones replace the earlier, so no count doubles and no thread has two
    /// stacks.
    #[test]
    fn a_torn_sample_does_not_double_its_task_records() {
        let records = "{PRW} 412 (ruff) futex_do_wait:1 hrtimer_nanosleep:8\n\
                       {PRK} 412 (ruff) 412 futex_do_wait futex_do_wait+0x4e/0x80\n\
                       {PRK} 412 (ruff) 413 hrtimer_nanosleep -\n";
        let text = [
            threaded_sample(1_000, records, false),
            threaded_sample(1_010, records, true),
        ]
        .concat();
        let p = parse(&text);
        assert_eq!(p.samples.len(), 1);
        let ruff = &p.samples[0].procs[0];
        assert_eq!(
            ruff.wchans.as_deref(),
            Some(&BTreeMap::from([
                ("futex_do_wait".to_string(), 1),
                ("hrtimer_nanosleep".to_string(), 8),
            ]))
        );
        let tids: Vec<i32> = ruff.stacks.iter().map(|s| s.tid).collect();
        assert_eq!(tids, [412, 413]);
    }

    /// A `RESET` mid-log is a guest that restarted its sampler: the wait channels recorded
    /// before it no longer stand, so a sample after it without a PRW has none.
    #[test]
    fn a_reset_forgets_the_wait_channels_before_it() {
        let text = [
            threaded_sample(1_000, "{PRW} 412 (ruff) futex_do_wait:9\n", true),
            threaded_sample(1_010, "", true),
            "RESET\n".to_string(),
            threaded_sample(1_020, "", true),
        ]
        .concat();
        let p = parse(&text);
        assert_eq!(p.samples.len(), 3);
        assert!(p.samples[1].procs[0].wchans.is_some(), "carried");
        assert!(p.samples[2].boot);
        assert_eq!(p.samples[2].procs[0].wchans, None);
        assert_eq!(p.samples[2].procs[0].wchans_since, None);
    }

    /// A label this version does not know is skipped, not counted as damage: the guest may
    /// record more than this reader was written for.
    #[test]
    fn an_unknown_label_is_not_damage() {
        let text = "GPU runner 1000 1970/01/01 00:16:40 40 0 busid nvidia 1 2\n\
                    CPU runner 1000 1970/01/01 00:16:40 40 100 1 1 1 0 8 0 0 0 0 0 0 100 0 0\n\
                    SEP\n";
        let p = parse(text);
        assert_eq!(p.samples.len(), 1);
        assert_eq!(p.dropped, 0);
        assert!(p.samples[0].cpu.is_some());
    }

    fn json(samples: &[Sample]) -> Vec<u8> {
        let mut out = Vec::new();
        write_json(samples, &mut out).unwrap();
        out
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-atoplog-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// `text` written plain and compressed, for a test that reads each the same way.
    fn both(dir: &Path, text: &str) -> [std::path::PathBuf; 2] {
        let plain = dir.join("atop.log");
        std::fs::write(&plain, text).unwrap();
        let packed = dir.join("atop.log.zst");
        std::fs::write(&packed, zstd::encode_all(text.as_bytes(), 9).unwrap()).unwrap();
        [plain, packed]
    }

    fn read_with(path: &Path, limits: Limits, evicted: &mut dyn FnMut(Sample)) -> Parsed {
        read_from(path, open_log(path).unwrap().0, limits, evicted).unwrap()
    }

    /// A compressed recording reads back as the samples of the text it was made from, told
    /// apart by its content rather than its name; a file too short to hold the magic is plain.
    #[test]
    fn a_compressed_log_reads_back_as_its_samples() {
        let dir = scratch("zst");
        let text = synthetic_log(50);
        let named_anything = dir.join("copy");
        std::fs::write(
            &named_anything,
            zstd::encode_all(text.as_bytes(), 9).unwrap(),
        )
        .unwrap();
        let got = read(&named_anything).unwrap();
        assert_eq!(json(&got.samples), json(&parse(&text).samples));
        assert_eq!(
            (got.len, got.consumed, got.evicted + got.oversized),
            (text.len(), text.len(), 0)
        );
        let short = dir.join("short");
        std::fs::write(&short, b"SE").unwrap();
        let got = read(&short).unwrap();
        assert!(got.samples.is_empty() && got.ends_mid_sample());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A compressed log cut short — a full disk, a crash — yields the samples that decoded
    /// before the cut, never a panic and never an error that loses them all.
    #[test]
    fn a_truncated_compressed_log_yields_the_samples_before_the_cut() {
        let dir = scratch("cut");
        let text = synthetic_log(20_000);
        let whole = parse(&text).samples;
        let packed = zstd::encode_all(text.as_bytes(), 9).unwrap();
        let path = dir.join("atop.log.zst");
        std::fs::write(&path, &packed[..packed.len() / 2]).unwrap();

        let got = read(&path).expect("the part before the cut").samples;
        assert!(!got.is_empty() && got.len() < whole.len(), "{}", got.len());
        assert!(
            got.iter().zip(&whole).all(|(a, b)| a.epoch == b.epoch),
            "a prefix of the job, in order"
        );
        // Cut inside the frame header: nothing decodes, which is an error rather than an
        // empty recording.
        std::fs::write(&path, &packed[..5]).unwrap();
        assert!(read(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A frame that expands without limit is decoded only as far as the bound, and held no
    /// larger than `keep`; one that decodes to exactly the bound is not cut; one asking for a
    /// window past [`WINDOW_LOG_MAX`] is refused before anything is allocated for it.
    #[test]
    fn decompression_is_bounded() {
        let dir = scratch("bomb");
        let bomb = dir.join("bomb");
        std::fs::write(
            &bomb,
            zstd::encode_all(&vec![b'x'; 8 << 20][..], 19).unwrap(),
        )
        .unwrap();
        let limits = Limits {
            keep: 64 * 1024,
            max_read: 1024 * 1024,
            chunk: CHUNK,
        };
        let got = read_with(&bomb, limits, &mut |_| {});
        assert!(got.samples.is_empty());
        assert_eq!(
            got.len as u64, limits.max_read,
            "decoded to the bound, no further"
        );
        assert_eq!(got.oversized, limits.max_read, "a line too long to hold");
        assert!(got.unread);

        let text = synthetic_log(50);
        let [_, packed] = both(&dir, &text);
        let exact = Limits {
            max_read: text.len() as u64,
            ..Limits::DEFAULT
        };
        let got = read_with(&packed, exact, &mut |_| {});
        assert_eq!(
            (got.samples.len(), got.evicted + got.oversized),
            (50, 0),
            "exactly the bound is whole"
        );

        let wide = dir.join("wide");
        let mut enc = zstd::stream::write::Encoder::new(Vec::new(), 3).unwrap();
        enc.window_log(WINDOW_LOG_MAX + 1).unwrap();
        std::io::Write::write_all(&mut enc, b"SEP\n").unwrap();
        std::fs::write(&wide, enc.finish().unwrap()).unwrap();
        assert!(read(&wide).is_err(), "a window past the limit");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The bytes of text each sample of `text` spans: from just past the previous `SEP` to
    /// the end of its own.
    fn spans(text: &str) -> Vec<u64> {
        let mut out = Vec::new();
        let mut from = 0;
        for (at, _) in text.match_indices("SEP\n") {
            out.push((at + 4 - from) as u64);
            from = at + 4;
        }
        out
    }

    /// A log whose samples span more than `keep` keeps the newest that fit, whole — plain or
    /// compressed, however the reads split its lines — hands the older ones over in order,
    /// and does not take the first one kept for the boot sample the log started with.
    #[test]
    fn an_oversized_log_keeps_its_newest_samples_whole() {
        let dir = scratch("tail");
        let text = synthetic_log(500);
        let whole = parse(&text).samples;
        assert!(whole[0].boot);
        let spans = spans(&text);
        for keep in [16 * 1024, 16 * 1024 + 1, spans[499] + spans[498]] {
            // The newest samples whose spans fit.
            let mut fit = 0;
            let mut sum = 0;
            while fit < spans.len() && sum + spans[spans.len() - 1 - fit] <= keep {
                sum += spans[spans.len() - 1 - fit];
                fit += 1;
            }
            for chunk in [7, 4096, CHUNK] {
                for path in both(&dir, &text) {
                    let limits = Limits {
                        keep,
                        max_read: u64::MAX,
                        chunk,
                    };
                    let mut evicted = Vec::new();
                    let got = read_with(&path, limits, &mut |s| evicted.push(s.epoch));
                    let tail = &whole[whole.len() - fit..];
                    assert_eq!(json(&got.samples), json(tail), "{keep} {chunk} {path:?}");
                    assert_eq!(got.evicted, text.len() as u64 - sum);
                    assert!(
                        !got.samples[0].boot,
                        "the first kept sample is not the boot's"
                    );
                    let front: Vec<i64> =
                        whole[..whole.len() - fit].iter().map(|s| s.epoch).collect();
                    assert_eq!(evicted, front, "the rest, handed over in order");
                }
            }
        }
        // A log that fits is read whole, boot sample and all.
        let got = read_with(&dir.join("atop.log"), Limits::DEFAULT, &mut |_| {});
        assert_eq!((got.samples.len(), got.evicted), (500, 0));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A sample longer than `keep` is dropped whole, and the samples either side of it still
    /// read; a log holding nothing but such a sample has no sample to read, and says what it
    /// left out rather than passing for an empty log.
    #[test]
    fn a_sample_too_long_to_hold_is_left_out_whole() {
        let dir = scratch("huge");
        let text = synthetic_log(3);
        let seps: Vec<usize> = text.match_indices("SEP\n").map(|(at, _)| at + 4).collect();
        let filler = format!(
            "CPU runner 1015 1970/01/01 00:16:55 10 100 2 {} 3\n",
            "9".repeat(3000)
        )
        .repeat(4);
        let huge = format!("{}{filler}SEP\n{}", &text[..seps[1]], &text[seps[1]..]);
        let limits = Limits {
            keep: 8 * 1024,
            max_read: u64::MAX,
            chunk: 1000,
        };
        for path in both(&dir, &huge) {
            let got = read_with(&path, limits, &mut |_| {});
            let epochs: Vec<i64> = got.samples.iter().map(|s| s.epoch).collect();
            assert_eq!(epochs, [1000, 1010, 1020], "{path:?}");
            assert_eq!(got.oversized, (filler.len() + 4) as u64);
        }
        for path in both(&dir, &format!("{filler}SEP\n")) {
            let got = read_with(&path, limits, &mut |_| {});
            assert!(got.samples.is_empty());
            assert!(got.oversized > 0, "{path:?}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// ruff's sample at `epoch`, preceded by `before`.
    fn ruff_sample(epoch: i64, before: &str, extra: &str) -> String {
        format!("{before}{}", threaded_sample(epoch, extra, true))
    }

    /// A `RESET` inside a sample given up on still forgets the wait channels before it, and
    /// the sample after is not taken for the boot sample it announced.
    #[test]
    fn a_reset_in_an_abandoned_sample_still_forgets_the_wait_channels() {
        let dir = scratch("abandonedreset");
        let text = [
            threaded_sample(1_000, "{PRW} 412 (ruff) futex_do_wait:9\n", true),
            // Torn: the guest restarted its sampler mid-write, and the two run together past
            // what a sample may span.
            threaded_sample(1_010, &"filler\n".repeat(400), false),
            "RESET\n".to_string(),
            threaded_sample(1_020, "", true),
            threaded_sample(1_030, "", true),
        ]
        .concat();
        let limits = Limits {
            keep: 2048,
            max_read: u64::MAX,
            chunk: 256,
        };
        for path in both(&dir, &text) {
            let got = read_with(&path, limits, &mut |_| {});
            let epochs: Vec<i64> = got.samples.iter().map(|s| s.epoch).collect();
            assert_eq!(epochs, [1_000, 1_030], "{path:?}");
            assert!(got.samples[0].procs[0].wchans.is_some());
            assert!(!got.samples[1].boot, "{path:?}");
            assert_eq!(got.samples[1].procs[0].wchans, None, "{path:?}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A line too long to hold, in the middle of a log, costs its own sample and nothing else:
    /// the samples after it read, the wait channels recorded before it still carry through it
    /// — ruff's records come after the long line, in the sample that is dropped — and what was
    /// left out is counted as oversized, not as a front let go of.
    #[test]
    fn an_overlong_line_mid_log_costs_only_its_sample() {
        let dir = scratch("overlong");
        let long = format!("{}\n", "x".repeat(9000));
        let text = [
            ruff_sample(
                1_000,
                "",
                "{PRW} 412 (ruff) futex_do_wait:1 hrtimer_nanosleep:8\n",
            ),
            ruff_sample(1_010, &long, ""),
            ruff_sample(1_020, "", ""),
        ]
        .concat();
        let limits = Limits {
            keep: 8 * 1024,
            max_read: u64::MAX,
            chunk: 1000,
        };
        for path in both(&dir, &text) {
            let got = read_with(&path, limits, &mut |_| {});
            let epochs: Vec<i64> = got.samples.iter().map(|s| s.epoch).collect();
            assert_eq!(epochs, [1_000, 1_020], "{path:?}");
            let last = &got.samples[1].procs[0];
            assert_eq!(
                last.wchans, got.samples[0].procs[0].wchans,
                "carried through"
            );
            assert_eq!(last.wchans_since, Some(1_000));
            assert_eq!(got.evicted, 0);
            let dropped = ruff_sample(1_010, &long, "").len() as u64;
            assert_eq!(got.oversized, dropped);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A sample whose records fit in `keep` but whose `SEP` line does not is too long to hold
    /// like any other, and is counted as such — not kept, and not let go of as the front.
    #[test]
    fn a_sample_over_keep_only_by_its_sep_is_left_out() {
        let dir = scratch("sepedge");
        let big = ruff_sample(
            1_000,
            "",
            "{PRW} 412 (ruff) futex_do_wait:1 hrtimer_nanosleep:8\n",
        );
        let small = ruff_sample(1_010, "", "");
        let text = format!("{big}{small}");
        for keep in [big.len() - 1, big.len() - 2, big.len() - 4] {
            let limits = Limits {
                keep: keep as u64,
                max_read: u64::MAX,
                chunk: 64,
            };
            for path in both(&dir, &text) {
                let got = read_with(&path, limits, &mut |_| {});
                let epochs: Vec<i64> = got.samples.iter().map(|s| s.epoch).collect();
                assert_eq!(epochs, [1_010], "{keep} {path:?}");
                assert_eq!((got.evicted, got.oversized), (0, big.len() as u64));
            }
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A read stops at its bound, plain or compressed, keeping the samples before it and
    /// saying it stopped.
    #[test]
    fn a_read_stops_at_its_bound() {
        let dir = scratch("readbound");
        let text = synthetic_log(50);
        let limits = Limits {
            max_read: (text.len() / 2) as u64,
            ..Limits::DEFAULT
        };
        let whole = parse(&text).samples;
        for path in both(&dir, &text) {
            let got = read_with(&path, limits, &mut |_| {});
            assert!(got.unread, "{path:?}");
            assert_eq!(got.len as u64, limits.max_read);
            assert!(!got.samples.is_empty() && got.samples.len() < whole.len());
            assert_eq!(json(&got.samples), json(&whole[..got.samples.len()]));
        }
        let got = read_with(&dir.join("atop.log"), Limits::DEFAULT, &mut |_| {});
        assert!(!got.unread);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Where a follower starts in a log too large to read whole: past the first `SEP` line in
    /// its last `keep` bytes — found when the line straddles two reads, when the cut lands on
    /// the newline before it, on its `S`, inside it, or just past it — or, with none there, the
    /// last bytes a `SEP` line still to come may begin with, marked as not a boundary.
    #[test]
    fn a_follower_starts_on_the_first_boundary_past_the_cut() {
        let dir = scratch("start");
        let text = synthetic_log(40);
        let path = dir.join("atop.log");
        std::fs::write(&path, &text).unwrap();
        let file = open_log(&path).unwrap().0;
        let len = text.len() as u64;
        let ends: Vec<u64> = text
            .match_indices("\nSEP\n")
            .map(|(at, _)| (at + 5) as u64)
            .collect();
        let sep = ends[30] - 4; // the `S` of a SEP line
        assert_eq!(
            tail_start_by(&file, len, 8).unwrap(),
            (0, true),
            "a log that fits"
        );
        for chunk in [5, 8, 13, 64 * 1024] {
            for (cut, want) in [
                (sep - 1, ends[30]),
                (sep, ends[30]),
                (sep + 1, ends[30]),
                (sep + 2, ends[30]),
                (sep + 3, ends[30]),
                (sep + 4, ends[30]),
                (sep + 5, ends[31]),
            ] {
                let got = tail_start_by(&file, len - cut, chunk).unwrap();
                assert_eq!(got, (want, true), "cut at {cut}, reading {chunk} at a time");
            }
            // The last SEP line ends the file: that is a boundary, with nothing after it yet.
            assert_eq!(tail_start_by(&file, 3, chunk).unwrap(), (len, true));
        }
        // Past the last SEP line, mid-sample: no boundary to start on.
        let torn = format!("{text}CPU runner 1400 1970/01/01 00:23:20 10 100 2");
        std::fs::write(&path, &torn).unwrap();
        let file = open_log(&path).unwrap().0;
        let len = torn.len() as u64;
        assert_eq!(tail_start_by(&file, 20, 8).unwrap(), (len - 4, false));
        // Torn inside a SEP line: the follower starts early enough to see the whole of it
        // once the rest arrives.
        let torn = format!("{torn}\nSE");
        std::fs::write(&path, &torn).unwrap();
        let file = open_log(&path).unwrap().0;
        let len = torn.len() as u64;
        let (start, boundary) = tail_start_by(&file, 20, 8).unwrap();
        assert!(!boundary);
        let grown = format!("{torn}P\n");
        assert_eq!(
            after_first_sep(&grown.as_bytes()[start as usize..]).map(|at| start + at as u64),
            Some(len + 2)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
