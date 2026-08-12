//! Reading a recorded job back: the samples in a guest's `atop.log`.
//!
//! The guest writes what `atop -P` would print (the schema is `vk_core::atop`); this opens
//! that log and turns its text back into samples, so `vk gitlab atop` can account a job that
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
//! * `-1` is "the kernel does not have this counter", never zero.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use vk_core::atop::{self, Label};

/// The most of a log this reads. The guest owns the directory its log is in and can fill it;
/// reading one is not worth an unbounded allocation.
const MAX_LOG: u64 = 256 * 1024 * 1024;

/// A whole log as text, opened by [`open_log`] and capped at [`MAX_LOG`].
///
/// Read lossily on purpose: the guest maps a command's own control bytes to spaces as it
/// writes, so a byte that is not text means a damaged log — and reading what is still there is
/// exactly what a reader of a possibly-torn file is for.
pub fn read(path: &Path) -> Result<String> {
    use std::io::Read;
    let (file, len) = open_log(path)?;
    if len > MAX_LOG {
        // Said out loud rather than silently reading a fraction of the job: anything totalled
        // over what comes back would cover only the part that was read.
        eprintln!(
            "virtkit: warning: {} is {} — reading its first {}",
            path.display(),
            crate::usage::fmt_bytes(len),
            crate::usage::fmt_bytes(MAX_LOG)
        );
    }
    let mut bytes = Vec::new();
    file.take(MAX_LOG)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
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
    /// Bytes of the *decoded text* up to and including the last `SEP` — the end of the last
    /// complete sample. Not a file offset: a log holding a byte that is not text is decoded
    /// lossily, and each such byte widens to three.
    pub consumed: usize,
    /// How much decoded text this was parsed from, so "is there an unfinished sample after
    /// the last complete one" is a question `Parsed` can answer by itself.
    pub len: usize,
    /// Records dropped for not carrying their label's fields: a torn tail, a command line
    /// this format cannot represent unambiguously, a record a guest mangled, or one whose
    /// label carries a different number of fields than this schema pins.
    pub dropped: usize,
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

/// Parse every complete sample in `text`.
pub fn parse(text: &str) -> Parsed {
    let mut out = Parsed {
        samples: Vec::new(),
        consumed: 0,
        len: text.len(),
        dropped: 0,
    };
    let mut cur = Builder::default();
    let mut at = 0usize;
    for line in text.split_inclusive('\n') {
        at = at.saturating_add(line.len());
        let line = line.trim_end_matches(['\n', '\r']);
        // A sample is only complete at its SEP, and only a whole line is a record: a
        // truncated tail (no newline) never reaches either.
        if line == atop::SEP {
            if let Some(sample) = cur.finish() {
                out.samples.push(sample);
            }
            out.consumed = at;
            continue;
        }
        if line == atop::RESET {
            cur.boot = true;
            continue;
        }
        if line.is_empty() {
            continue;
        }
        let cells = atop::cells(line);
        let Some(label) = atop::label_of(&cells) else {
            continue; // a label this version does not read is not an error
        };
        if cells.len() != label.arity() {
            out.dropped = out.dropped.saturating_add(1);
            continue;
        }
        cur.record(&Record { label, cells });
    }
    out
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
    any: bool,
    /// Whether the generic columns have been taken from a record yet — a flag rather than a
    /// sentinel epoch, since a guest whose clock is unset stamps 0 and means it.
    generic: bool,
}

impl Builder {
    /// The sample this builder holds, or `None` when the `SEP` closed nothing — a log that
    /// starts mid-sample, or two separators in a row.
    fn finish(&mut self) -> Option<Sample> {
        if !self.any {
            self.boot = false;
            return None;
        }
        let mut sample = std::mem::take(&mut self.sample);
        sample.boot = std::mem::take(&mut self.boot);
        sample.procs = std::mem::take(&mut self.procs).into_values().collect();
        // At least 1, whatever the log says: this is the divisor of every rate a reader
        // computes, and the guest promises but does not enforce it.
        sample.interval = sample.interval.max(1);
        self.any = false;
        self.generic = false;
        Some(sample)
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
            "PRG" => {
                let p = self.proc(r);
                p.name = r.text("name");
                p.cmdline = r.text("cmdline");
                p.started = r.num("starttime");
                p.state = r.char("state");
                p.exitcode = r.num("exitcode");
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
}
