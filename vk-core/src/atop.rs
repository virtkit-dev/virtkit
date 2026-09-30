//! The statistics log the guest writes and the host reads: atop's parseable (`atop -P`)
//! text schema, pinned to atop 2.8.1 — the release Debian 12 ships.
//!
//! A CI job's guest samples its own `/proc` and appends one sample per interval to
//! `atop.log` on a share the host provides — the agent's `atop` module writes it and the
//! host reads it back. Everything the two sides have to agree on lives here: where
//! the share is mounted and how the guest is asked to record, the log's name, the
//! columns every line starts with, and each label's own fields in printed order.
//!
//! Every line is one record:
//!
//! ```text
//! <label> <host> <epoch> <YYYY/MM/DD> <HH:MM:SS> <interval> <label's own fields...>
//! ```
//!
//! A `SEP` line closes each sample — the point at which it is complete — and a `RESET`
//! line precedes the first, whose counters cover the guest's whole boot. Counter labels
//! carry per-interval differences, size labels the value as it stood, and the interval
//! column is the divisor for any rate computed from them.
//!
//! A string field is parenthesised and may hold spaces — a command line is one of them —
//! so a record is split into cells by [`cells`] rather than on whitespace.
//!
//! Two labels are virtkit's own, not atop's: [`WCHANS`] and [`STACK`], which say what a
//! multi-threaded process's threads wait in.

/// The virtio-fs tag of the archive share. The host's `FsShare` and the cmdline knob
/// must name the same tag: the guest mounts whatever the cmdline says.
pub const TAG: &str = "vkatop";

/// Where the guest mounts that share.
pub const GUEST_MOUNT: &str = "/run/virtkit-atop";

/// The guest path the agent leaves its sampler's pid in, so the host can signal it for a
/// final sample at the end of the job. Beside the mountpoint, never inside it: everything
/// under the mountpoint is the host's archive.
pub const PID_FILE: &str = "/run/virtkit-atop.pid";

/// The log itself, inside the share.
pub const LOG_NAME: &str = "atop.log";

/// The line announcing that the sample after it covers the guest's whole boot.
pub const RESET: &str = "RESET";

/// The line closing a sample. A sample is complete only once this is written.
pub const SEP: &str = "SEP";

/// The columns every record starts with, in order.
pub const HEADER: &[&str] = &["label", "host", "epoch", "date", "time", "interval"];

/// How many columns [`HEADER`] describes, i.e. where a label's own fields begin.
pub const HEADER_COLS: usize = HEADER.len();

/// Column of the recording guest's hostname.
pub const COL_HOST: usize = 1;
/// Column of the sample time, in seconds since the epoch.
pub const COL_EPOCH: usize = 2;
/// Column of the seconds the sample covers — at least 1, and the divisor of every rate.
pub const COL_INTERVAL: usize = 5;

/// The cmdline fragment asking a guest to record: the share to mount, where, and how
/// often to sample. `psi=1` rides along because the guest kernel is built with pressure
/// stall information available but off, and the PSI label is worth having.
pub fn cmdline_knob(interval_secs: u64) -> String {
    format!(" VIRTKIT_ATOP={TAG}:{GUEST_MOUNT}:{interval_secs} psi=1")
}

/// Parse the `VIRTKIT_ATOP` cmdline value `<tag>:<mountpoint>:<interval_secs>` written by
/// [`cmdline_knob`], into its three parts. `None` when it is malformed: an empty tag, a
/// relative mountpoint, a zero or unparseable interval, or extra fields.
pub fn parse_knob(spec: &str) -> Option<(&str, &str, u64)> {
    let mut parts = spec.split(':');
    let tag = parts.next()?;
    let mount = parts.next()?;
    let interval: u64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || tag.is_empty() || !mount.starts_with('/') || interval == 0 {
        return None;
    }
    Some((tag, mount, interval))
}

/// One record's cells, with each parenthesised field kept whole however many spaces it
/// holds — the only way to read this format, since a command line is a field.
///
/// A parenthesised field ends at the parenthesis matching the one that opened it, because
/// its content is a command line and can hold its own (`php-fpm: master process (…conf)`).
/// Content whose parentheses do not balance — a command that prints a lone `)` — has no
/// unambiguous reading, and atop's own format has none either: the field is then taken to
/// the last `)` of the record, which recovers every field after it. Checking the result
/// against the label's [`Label::arity`] is what tells a reader it got a whole record.
pub fn cells(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = line;
    while !rest.is_empty() {
        rest = rest.trim_start();
        if rest.starts_with('(') {
            let end = match_paren(rest)
                .unwrap_or_else(|| rest.rfind(')').unwrap_or(rest.len().saturating_sub(1)));
            let (cell, after) = rest.split_at((end + 1).min(rest.len()));
            out.push(cell);
            rest = after;
            continue;
        }
        let (cell, after) = match rest.find(char::is_whitespace) {
            Some(at) => rest.split_at(at),
            None => (rest, ""),
        };
        if !cell.is_empty() {
            out.push(cell);
        }
        rest = after;
    }
    out
}

/// The index of the parenthesis closing the one `s` starts with, or `None` when the
/// parentheses in it never balance.
fn match_paren(s: &str) -> Option<usize> {
    // Checked throughout: the content is a command line a guest chose, so the parentheses
    // in it are as arbitrary as any other byte.
    let mut depth = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth = depth.checked_add(1)?,
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// One label's own fields, in the order they are printed after the [`HEADER`] columns.
///
/// The names are this codebase's, for indexing a record by meaning rather than by a
/// counted-out position; the *order* is atop 2.8.1's and cannot be changed without
/// breaking every reader of the format.
#[derive(Debug)]
pub struct Label {
    /// The label as it appears in the first column.
    pub name: &'static str,
    /// This label's own fields, in the order they are printed after the [`HEADER`] columns.
    pub fields: &'static [&'static str],
}

impl Label {
    /// How many whitespace-separated cells a whole record of this label has.
    pub fn arity(&self) -> usize {
        HEADER_COLS + self.fields.len()
    }

    /// Which cell of a whole record holds `field`.
    pub fn index_of(&self, field: &str) -> Option<usize> {
        self.fields
            .iter()
            .position(|f| *f == field)
            .map(|i| HEADER_COLS + i)
    }
}

/// Totals across all processors: the tick counters of `/proc/stat`, the clock rate they
/// are counted in, and the frequency and performance counters a guest cannot source.
pub static CPU: Label = Label {
    name: "CPU",
    fields: &[
        "hertz",
        "cpus",
        "system",
        "user",
        "nice",
        "idle",
        "iowait",
        "irq",
        "softirq",
        "steal",
        "guest",
        "freq",
        "freqperc",
        "instructions",
        "cycles",
    ],
};

/// One processor's share of [`CPU`], with its number where the total has a count.
pub static CPU_ONE: Label = Label {
    name: "cpu",
    fields: &[
        "hertz",
        "cpu",
        "system",
        "user",
        "nice",
        "idle",
        "iowait",
        "irq",
        "softirq",
        "steal",
        "guest",
        "freq",
        "freqperc",
        "instructions",
        "cycles",
    ],
};

/// Load: the three averages, plus context switches and interrupts over the interval.
pub static CPL: Label = Label {
    name: "CPL",
    fields: &["cpus", "load1", "load5", "load15", "ctxsw", "interrupts"],
};

/// Memory as it stands, in pages of the `pagesize` field (huge pages are counted whole,
/// and the two huge-page sizes are bytes).
pub static MEM: Label = Label {
    name: "MEM",
    fields: &[
        "pagesize",
        "physmem",
        "freemem",
        "cachemem",
        "buffermem",
        "slabmem",
        "dirty",
        "slabreclaim",
        "balloon",
        "shmem",
        "shmrss",
        "shmswap",
        "hugepagesize",
        "hugepages",
        "hugepagesfree",
        "zfsarc",
        "ksmsharing",
        "ksmshared",
        "tcpsock",
        "udpsock",
        "pagetables",
    ],
};

/// Swap as it stands. atop prints the swap cache twice; the repeat is part of the format,
/// so it is named rather than dropped.
pub static SWP: Label = Label {
    name: "SWP",
    fields: &[
        "pagesize",
        "swaptotal",
        "swapfree",
        "swapcache",
        "committed",
        "commitlimit",
        "swapcache-again",
        "zswapstored",
        "zswappool",
    ],
};

/// Paging and swapping events over the interval. `reserved` is atop's own placeholder,
/// and `oomkills` is `-1` on a kernel that has no such counter.
pub static PAG: Label = Label {
    name: "PAG",
    fields: &[
        "pagesize",
        "pgscans",
        "allocstalls",
        "reserved",
        "swapins",
        "swapouts",
        "oomkills",
        "compactstalls",
        "pgmigrated",
        "numamigrated",
        "pgin",
        "pgout",
    ],
};

/// Pressure stall information: `supported` is `y` or `n`, each average is a percentage as
/// it stands, and each total is the microseconds stalled during the interval.
pub static PSI: Label = Label {
    name: "PSI",
    fields: &[
        "supported",
        "cpusome-avg10",
        "cpusome-avg60",
        "cpusome-avg300",
        "cpusome-total",
        "memsome-avg10",
        "memsome-avg60",
        "memsome-avg300",
        "memsome-total",
        "memfull-avg10",
        "memfull-avg60",
        "memfull-avg300",
        "memfull-total",
        "iosome-avg10",
        "iosome-avg60",
        "iosome-avg300",
        "iosome-total",
        "iofull-avg10",
        "iofull-avg60",
        "iofull-avg300",
        "iofull-total",
    ],
};

/// One disk over the interval. Sizes are 512-byte sectors, `discards` is `-1` where the
/// kernel's diskstats have no discard columns, and a device that moved nothing and holds
/// nothing gets no record at all.
pub static DSK: Label = Label {
    name: "DSK",
    fields: &[
        "name",
        "io-ms",
        "reads",
        "sectors-read",
        "writes",
        "sectors-written",
        "discards",
        "sectors-discarded",
        "inflight",
        "avque",
    ],
};

/// The protocol layers over the interval, on the record whose first field is `upper`.
pub static NET_UPPER: Label = Label {
    name: "NET",
    fields: &[
        "layer",
        "tcp-in",
        "tcp-out",
        "udp-in",
        "udp-out",
        "ip-in",
        "ip-out",
        "ip-delivered",
        "ip-forwarded",
        "udp-inerrors",
        "udp-noports",
        "tcp-activeopens",
        "tcp-passiveopens",
        "tcp-established",
        "tcp-retrans",
        "tcp-inerrors",
        "tcp-outresets",
    ],
};

/// One network interface over the interval; `speed` is Mbit/s (0 where the link does not
/// report one) and `duplex` is 1 for full.
pub static NET_IF: Label = Label {
    name: "NET",
    fields: &[
        "name",
        "packets-in",
        "bytes-in",
        "packets-out",
        "bytes-out",
        "speed",
        "duplex",
    ],
};

/// The field distinguishing the two shapes of a `NET` record: the protocol-layer one
/// names this layer where a per-interface record names the interface.
pub const NET_UPPER_LAYER: &str = "upper";

/// A process in general: identity, ownership, thread counts, and whether it started
/// during the interval (`new` = `N`). A live task's exit code and elapsed time are 0.
pub static PRG: Label = Label {
    name: "PRG",
    fields: &[
        "pid",
        "name",
        "state",
        "ruid",
        "rgid",
        "tgid",
        "threads",
        "exitcode",
        "starttime",
        "cmdline",
        "ppid",
        "threads-running",
        "threads-sleeping",
        "threads-uninterruptible",
        "euid",
        "egid",
        "suid",
        "sgid",
        "fsuid",
        "fsgid",
        "elapsed",
        "isproc",
        "vpid",
        "ctid",
        "container",
        "new",
        "cgroup",
    ],
};

/// A process's CPU over the interval: user and system ticks (of `hertz`), scheduling, and
/// the delays it waited out. The cgroup columns are `-3` — no cgroup v2 accounting.
pub static PRC: Label = Label {
    name: "PRC",
    fields: &[
        "pid",
        "name",
        "state",
        "hertz",
        "utime",
        "stime",
        "nice",
        "prio",
        "rtprio",
        "policy",
        "curcpu",
        "sleepavg",
        "tgid",
        "isproc",
        "rundelay",
        "wchan",
        "blkdelay",
        "cgroup-cpumax",
        "cgroup-cpumax-strictest",
    ],
};

/// A process's memory: sizes in KiB as they stand, growth and faults over the interval.
/// `pss` is 0 (atop measures it only when asked to) and the cgroup columns are `-3`.
pub static PRM: Label = Label {
    name: "PRM",
    fields: &[
        "pid",
        "name",
        "state",
        "pagesize",
        "vsize",
        "rsize",
        "tsize",
        "vgrow",
        "rgrow",
        "minflt",
        "majflt",
        "vlibs",
        "vdata",
        "vstack",
        "vswap",
        "tgid",
        "isproc",
        "pss",
        "vlock",
        "cgroup-memmax",
        "cgroup-memmax-strictest",
        "cgroup-swapmax",
        "cgroup-swapmax-strictest",
    ],
};

/// A process's disk over the interval: read and write syscalls, and the 512-byte sectors
/// they moved. `io-stats` says whether the sizes could be read at all; the two `obsolete`
/// fields are atop's own dead columns.
pub static PRD: Label = Label {
    name: "PRD",
    fields: &[
        "pid",
        "name",
        "state",
        "obsolete-patch",
        "io-stats",
        "reads",
        "sectors-read",
        "writes",
        "sectors-written",
        "sectors-cancelled",
        "tgid",
        "obsolete",
        "isproc",
    ],
};

/// Every label a virtkit guest records, in the order one sample prints them (atop's own
/// label order, skipping what a microVM guest has nothing to say about).
pub const LABELS: &[&Label] = &[
    &CPU, &CPU_ONE, &CPL, &MEM, &SWP, &PAG, &PSI, &DSK, &NET_UPPER, &NET_IF, &PRG, &PRC, &PRM, &PRD,
];

/// The label a record belongs to, from its first cell — and, for the two shapes of a
/// `NET` record, from the field that tells them apart.
pub fn label_of(cells: &[&str]) -> Option<&'static Label> {
    let name = *cells.first()?;
    if name == NET_UPPER.name {
        let layer = cells.get(HEADER_COLS).copied();
        return Some(match layer == Some(NET_UPPER_LAYER) {
            true => &NET_UPPER,
            false => &NET_IF,
        });
    }
    LABELS.iter().copied().find(|l| l.name == name)
}

/// The vk-specific label for a multi-threaded process's wait channels: after the [`HEADER`]
/// columns, `<pid> (<name>)`, then one `<wchan>:<threads>` cell per kernel function its
/// non-running threads wait in, sorted by name. A running thread has no wait channel and is
/// counted in PRG's `threads-running` instead, so a process whose threads all run has no cell.
///
/// The guest writes one only when the histogram differs from the one it last wrote for the
/// same task, and for every multi-threaded process in the sample after `RESET`: the latest
/// record stands until the next one, or until PRG reports the process single-threaded. Its
/// arity varies, so it is not a [`Label`] and not in [`LABELS`]; [`label_of`] does not know
/// it, which is how an atop-format reader that does not read it skips it.
pub const WCHANS: &str = "PRW";

/// The vk-specific label for one thread's kernel stack, written once per task when its
/// process meets the [`Stall`] test in the guest: after the [`HEADER`] columns, `<pid>
/// (<name>) <tid> <wchan> <frames>`. `<wchan>` is `-` for a thread with none; `<frames>` is
/// the stack innermost first, joined by `;`, each frame `function+offset/length` as
/// `/proc/<pid>/task/<tid>/stack` prints it, or `-` where the kernel exposes no stack.
pub const STACK: &str = "PRK";

/// How long a multi-threaded process must stand [`idle`] before it counts as stalled.
///
/// Five minutes: the waits of a CI step that is making progress usually change which channels
/// its threads wait in within seconds, while a hang that runs into a job's timeout (an hour and
/// up) is caught long before its VM is torn down. A process that waits longer than this on a
/// lock or a network-only transfer is reported by design.
pub const STALL_SECS: u64 = 300;

/// The most processor time an [`idle`] process spends over an interval, in percent of one
/// processor: threads polling a stuck worker cost a hung process 1–3%, real progress far more.
pub const IDLE_CPU_PERCENT: u64 = 10;

/// Minimum idle samples per stall, preventing a verdict from one or two widely spaced samples.
pub const STALL_MIN_SAMPLES: u32 = 3;

/// Whether a multi-threaded process is idle since its previous sample: unchanged wait-channel
/// set ([`same_channels`]), no disk sectors moved, and CPU use below [`IDLE_CPU_PERCENT`]
/// percent of one processor, measured as `ticks` at `hertz` over `interval_secs`.
///
/// The set, not the counts, and not whether a thread runs: a poller caught running, or between
/// two states, drops out of the counts for a sample, and a hung process with pollers flickers
/// between histograms every few samples while its set stands still. An unknown tick rate or
/// interval (0) never counts as idle.
pub fn idle(same_channels: bool, ticks: u64, hertz: u64, interval_secs: u64, sectors: u64) -> bool {
    let budget = IDLE_CPU_PERCENT
        .saturating_mul(hertz)
        .saturating_mul(interval_secs);
    same_channels && sectors == 0 && ticks.saturating_mul(100) < budget
}

/// Whether two wait-channel histograms name the same channels, whatever their counts.
pub fn same_channels<K: Ord, V>(
    a: &std::collections::BTreeMap<K, V>,
    b: &std::collections::BTreeMap<K, V>,
) -> bool {
    a.keys().eq(b.keys())
}

/// Whether one sample's processor ticks and 512-byte sectors, both over its interval, show a
/// process doing work.
pub fn worked(ticks: u64, sectors: u64) -> bool {
    ticks > 0 || sectors > 0
}

/// One multi-threaded process's progress towards a stall. Guest and host each keep one per
/// task (pid and start time) and feed it the same figures from each sample on disk, so the
/// stacks the guest writes ([`STACK`]) and the stalls the host reports are the same ones.
///
/// A stall is a stretch of [`idle`] samples lasting [`STALL_SECS`] and [`STALL_MIN_SAMPLES`],
/// by a process that [`worked`] in a sample up to the one the stretch starts at. That sample
/// counts because its figures cover the interval before the stretch; work inside the stretch
/// is its own idle threads polling. The boot-covering first sample is not work of the job's,
/// so a daemon that has done nothing since the guest booted never stalls — though one that
/// worked and then idles in a fixed set of wait channels does.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stall {
    seen: bool,
    from: i64,
    unchanged: u32,
    worked: bool,
}

impl Stall {
    /// Observe a sample and return whether the process is stalled. `idle` is [`idle`] against
    /// the previous sample (false for the first); `worked` is [`worked`] over this sample's
    /// interval (false for the boot-covering sample).
    pub fn observe(&mut self, epoch: i64, idle: bool, worked: bool) -> bool {
        match idle && self.seen {
            true => self.unchanged = self.unchanged.saturating_add(1),
            false => {
                self.from = epoch;
                self.unchanged = 0;
                self.worked |= worked;
            }
        }
        self.seen = true;
        let secs = epoch.saturating_sub(self.from).max(0) as u64;
        self.worked && secs >= STALL_SECS && self.unchanged >= STALL_MIN_SAMPLES
    }

    /// When the current stretch began (seconds since the epoch).
    pub fn from(&self) -> i64 {
        self.from
    }
}

/// A [`WCHANS`] record, read.
#[derive(Debug, PartialEq, Eq)]
pub struct Wchans<'a> {
    pub pid: i32,
    pub name: &'a str,
    /// `(wchan, threads)`, in the order the record lists them.
    pub counts: Vec<(&'a str, u32)>,
}

/// A [`WCHANS`] record's own fields, or `None` when `cells` is not one or is malformed: a
/// pid that is no number, a name that is not parenthesised, or a cell that is not
/// `<wchan>:<count>`. A wchan is a kernel symbol and holds no `:`, but the count is taken
/// after the last one regardless.
pub fn parse_wchans<'a>(cells: &[&'a str]) -> Option<Wchans<'a>> {
    let (pid, name, rest) = task_cells(cells, WCHANS)?;
    let counts = rest
        .iter()
        .map(|cell| match cell.rsplit_once(':') {
            Some((wchan, count)) if !wchan.is_empty() => Some((wchan, count.parse().ok()?)),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    Some(Wchans { pid, name, counts })
}

/// A [`STACK`] record, read.
#[derive(Debug, PartialEq, Eq)]
pub struct Stack<'a> {
    pub pid: i32,
    pub name: &'a str,
    pub tid: i32,
    /// `None` for a thread with no wait channel (written `-`).
    pub wchan: Option<&'a str>,
    /// Innermost first; empty where the kernel exposed no stack (written `-`).
    pub frames: Vec<&'a str>,
}

/// A [`STACK`] record's own fields, or `None` when `cells` is not one or does not carry
/// exactly its five.
pub fn parse_stack<'a>(cells: &[&'a str]) -> Option<Stack<'a>> {
    let (pid, name, rest) = task_cells(cells, STACK)?;
    let [tid, wchan, frames] = rest else {
        return None;
    };
    let dash = |cell: &'a str| (cell != "-").then_some(cell);
    Some(Stack {
        pid,
        name,
        tid: tid.parse().ok()?,
        wchan: dash(wchan),
        frames: dash(frames)
            .map(|f| f.split(';').filter(|f| !f.is_empty()).collect())
            .unwrap_or_default(),
    })
}

/// The pid and unparenthesised name that open a vk-specific process record of `label`, and
/// the cells after them.
fn task_cells<'c, 'a>(cells: &'c [&'a str], label: &str) -> Option<(i32, &'a str, &'c [&'a str])> {
    if cells.first() != Some(&label) {
        return None;
    }
    let [pid, name, rest @ ..] = cells.get(HEADER_COLS..)? else {
        return None;
    };
    let name = name.strip_prefix('(')?.strip_suffix(')')?;
    Some((pid.parse().ok()?, name, rest))
}

/// Now, in seconds since the epoch: the `epoch` column of a record, and the day a job is
/// filed under. Both sides stamp their own clock, so both read it here.
pub fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The `date` and `time` columns of a record, in UTC — the timezone a job guest records
/// in, having none of its own. The `epoch` column beside them reads the same anywhere.
pub fn date_time(epoch: i64) -> (String, String) {
    let (y, m, d) = civil_from_days(day_of(epoch));
    let secs = epoch.rem_euclid(86_400);
    (
        format!("{y:04}/{m:02}/{d:02}"),
        format!(
            "{:02}:{:02}:{:02}",
            secs / 3600,
            (secs / 60) % 60,
            secs % 60
        ),
    )
}

/// Whole days since 1970-01-01, UTC — what a day of the archive is keyed on, and what the
/// retention window is counted in.
pub fn day_of(epoch: i64) -> i64 {
    epoch.div_euclid(86_400)
}

/// The archive directory name for the day `epoch` falls in, `YYYY-MM-DD`.
pub fn date_dir(epoch: i64) -> String {
    date_dir_of_day(day_of(epoch))
}

/// The archive directory name of a day number.
fn date_dir_of_day(day: i64) -> String {
    let (y, m, d) = civil_from_days(day);
    format!("{y:04}-{m:02}-{d:02}")
}

/// The day an archive directory name stands for, or `None` when the name is not one of the
/// days this archive writes — so a sweep can leave everything else in it alone.
///
/// Only the canonical `YYYY-MM-DD` of a real date reads back, which the round trip through
/// [`date_dir_of_day`] is what settles: `2026-02-31` names no day rather than March the 3rd,
/// and the fixed-width fields keep a year out of the arithmetic below that it could not hold.
pub fn parse_date_dir(name: &str) -> Option<i64> {
    let field = |part: Option<&str>, width: usize| -> Option<i64> {
        let s = part?;
        (s.len() == width && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse().ok())
            .flatten()
    };
    let mut parts = name.split('-');
    let y = field(parts.next(), 4)?;
    let m = field(parts.next(), 2)?;
    let d = field(parts.next(), 2)?;
    if parts.next().is_some() {
        return None;
    }
    let day = days_from_civil(y, m, d);
    (date_dir_of_day(day) == name).then_some(day)
}

/// The Gregorian date `days` after 1970-01-01. Counting from a March-based year puts the
/// leap day last, so the month lengths follow one formula with no table and no leap-year
/// branch.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468; // days since 0000-03-01
    let era = z.div_euclid(146_097); // one 400-year cycle
    let doe = z.rem_euclid(146_097); // day of era
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // year of era
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of the March-based year
    let mp = (5 * doy + 2) / 153; // month, 0 = March
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (era * 400 + yoe + i64::from(month <= 2), month, day)
}

/// The day number of a Gregorian date, the inverse of [`civil_from_days`].
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y }; // the March-based year the day falls in
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 }; // month, 0 = March
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The schema is indexed by field name, so a repeated name inside one label would
    /// silently answer for the wrong column — atop prints the swap cache twice, which is
    /// exactly the trap.
    #[test]
    fn every_label_names_its_fields_once() {
        // The generic columns are read by position, so the constants and the header they
        // describe must not drift apart.
        assert_eq!(HEADER[COL_HOST], "host");
        assert_eq!(HEADER[COL_EPOCH], "epoch");
        assert_eq!(HEADER[COL_INTERVAL], "interval");
        assert_eq!(HEADER_COLS, COL_INTERVAL + 1);

        for label in LABELS {
            for (i, field) in label.fields.iter().enumerate() {
                assert!(!field.is_empty(), "{} has an empty field name", label.name);
                assert_eq!(
                    label.fields.iter().position(|f| f == field),
                    Some(i),
                    "{} names {field} twice",
                    label.name
                );
                assert_eq!(label.index_of(field), Some(HEADER_COLS + i));
            }
            assert_eq!(label.arity(), HEADER_COLS + label.fields.len());
            assert_eq!(label.index_of("nosuchfield"), None);
        }
    }

    /// The arities of atop 2.8.1, counted out of its `parseable.c` print functions. A
    /// change here is a change to the format itself, which every reader would have to be
    /// told about — so they are written down as literals rather than derived.
    #[test]
    fn the_arities_are_the_pinned_ones() {
        for (label, own) in [
            (&CPU, 15),
            (&CPU_ONE, 15),
            (&CPL, 6),
            (&MEM, 21),
            (&SWP, 9),
            (&PAG, 12),
            (&PSI, 21),
            (&DSK, 10),
            (&NET_UPPER, 17),
            (&NET_IF, 7),
            (&PRG, 27),
            (&PRC, 19),
            (&PRM, 23),
            (&PRD, 13),
        ] {
            assert_eq!(label.fields.len(), own, "{}", label.name);
            assert_eq!(label.arity(), 6 + own, "{}", label.name);
        }
    }

    /// A record's string fields are parenthesised and hold spaces — a command line is one
    /// of them — so they are read as the single cells they are, parentheses of their own
    /// included. Getting this wrong shifts every field after the command line.
    #[test]
    fn a_parenthesised_field_is_one_cell() {
        assert_eq!(cells("CPU h 100 30 5"), ["CPU", "h", "100", "30", "5"]);
        assert_eq!(
            cells("PRG 7 (sh) S (sh -c make test) 1 ()"),
            ["PRG", "7", "(sh)", "S", "(sh -c make test)", "1", "()"]
        );
        // A command line with balanced parentheses of its own.
        assert_eq!(
            cells("PRG 9 (php-fpm8.5) S (php-fpm: master process (/etc/php/fpm.conf)) 1 ()"),
            [
                "PRG",
                "9",
                "(php-fpm8.5)",
                "S",
                "(php-fpm: master process (/etc/php/fpm.conf))",
                "1",
                "()"
            ]
        );
        // An unclosed `(` in the content never balances: the field is read to the record's
        // last `)`, which puts every field after it back where it belongs.
        assert_eq!(
            cells("PRG 9 (sh) S (sh -c echo ( tail) 1 ()"),
            ["PRG", "9", "(sh)", "S", "(sh -c echo ( tail) 1 ()"]
        );
        // The ambiguity the format cannot resolve: a lone `)` in the content closes the
        // field early, and the cells after it shift. Reading them back against the label's
        // arity is what tells a reader this record cannot be trusted.
        assert_eq!(
            cells("PRG 9 (sh) S (sh -c echo ) tail) 1 ()"),
            ["PRG", "9", "(sh)", "S", "(sh -c echo )", "tail)", "1", "()"]
        );
        // Repeated whitespace and a trailing newline leave no empty cells behind.
        assert_eq!(cells("CPU  h \t100\n"), ["CPU", "h", "100"]);
        assert!(cells("").is_empty());
    }

    /// A record names its own label, and the two shapes of a NET record are told apart by
    /// the field the protocol-layer one puts the word `upper` in.
    #[test]
    fn a_record_resolves_to_its_label() {
        fn cells(line: &str) -> Vec<&str> {
            line.split(' ').collect()
        }
        assert_eq!(
            label_of(&cells("CPU h 100 1970/01/01 00:01:40 30 100 2")).map(|l| l.name),
            Some("CPU")
        );
        assert!(std::ptr::eq(
            label_of(&cells("NET h 100 1970/01/01 00:01:40 30 upper 1 2")).unwrap(),
            &NET_UPPER
        ));
        assert!(std::ptr::eq(
            label_of(&cells("NET h 100 1970/01/01 00:01:40 30 eth0 1 2")).unwrap(),
            &NET_IF
        ));
        // A short NET record (nothing where the shape is decided) reads as per-interface,
        // which is the shape that carries a name there.
        assert!(std::ptr::eq(
            label_of(&cells("NET h 100")).unwrap(),
            &NET_IF
        ));
        assert!(label_of(&cells("SEP")).is_none());
        assert!(label_of(&cells("RESET")).is_none());
        assert!(label_of(&[]).is_none());
    }

    /// The wait-channel record reads back as its pid, name and counts; a record whose cells
    /// are not all `<wchan>:<count>` is refused whole rather than read in part. Neither
    /// vk-specific label is one [`label_of`] knows, so a positional reader skips both.
    #[test]
    fn a_wait_channel_record_reads_back() {
        let h = "PRW h 100 1970/01/01 00:01:40 30";
        let line = format!("{h} 412 (ruff check) futex_do_wait:1 hrtimer_nanosleep:7");
        let c = cells(&line);
        assert!(label_of(&c).is_none());
        assert_eq!(
            parse_wchans(&c),
            Some(Wchans {
                pid: 412,
                name: "ruff check",
                counts: vec![("futex_do_wait", 1), ("hrtimer_nanosleep", 7)],
            })
        );
        // Every thread running: no cell after the name.
        let all_running = format!("{h} 412 (ruff)");
        let w = parse_wchans(&cells(&all_running)).expect("a record with no channels");
        assert!(w.counts.is_empty());
        for bad in [
            format!("{h} 412 (ruff) futex_do_wait"),
            format!("{h} 412 (ruff) futex_do_wait:x"),
            format!("{h} 412 (ruff) :3"),
            format!("{h} x (ruff) futex_do_wait:1"),
            format!("{h} 412 ruff futex_do_wait:1"),
            format!("{h} 412"),
            "PRW h 100".to_string(),
            format!("PRK{} 412 (ruff) futex_do_wait:1", &h[3..]),
        ] {
            assert_eq!(parse_wchans(&cells(&bad)), None, "{bad}");
        }
    }

    /// The stack record: a thread's wait channel and frames, `-` standing for either being
    /// absent — a thread with no wait channel, a kernel that exposes no stacks.
    #[test]
    fn a_stack_record_reads_back() {
        let h = "PRK h 100 1970/01/01 00:01:40 30";
        let line = format!(
            "{h} 412 (ruff) 415 request_wait_answer \
             request_wait_answer+0x7c/0x1e0;fuse_simple_request+0x1a0/0x2d0"
        );
        let c = cells(&line);
        assert!(label_of(&c).is_none());
        assert_eq!(
            parse_stack(&c),
            Some(Stack {
                pid: 412,
                name: "ruff",
                tid: 415,
                wchan: Some("request_wait_answer"),
                frames: vec![
                    "request_wait_answer+0x7c/0x1e0",
                    "fuse_simple_request+0x1a0/0x2d0"
                ],
            })
        );
        let bare = format!("{h} 412 (ruff) 413 - -");
        let s = parse_stack(&cells(&bare)).expect("a record with nothing to show");
        assert_eq!((s.wchan, s.frames.len()), (None, 0));
        for bad in [
            format!("{h} 412 (ruff) 413 -"),
            format!("{h} 412 (ruff) 413 - - extra"),
            format!("{h} 412 (ruff) tid - -"),
        ] {
            assert_eq!(parse_stack(&cells(&bad)), None, "{bad}");
        }
    }

    /// A stall needs work before it, then five minutes and three samples of standing still.
    /// A sample that moves starts the stretch over, and its own work counts; work inside the
    /// stretch does not, and neither does the boot sample's.
    #[test]
    fn a_stall_takes_work_then_time_and_samples() {
        assert_eq!(
            STALL_MIN_SAMPLES, 3,
            "the samples below are counted out for three"
        );
        let secs = STALL_SECS as i64;
        // Worked in the sample the stretch starts at.
        let mut s = Stall::default();
        assert!(!s.observe(0, false, true));
        assert!(!s.observe(secs - 1, true, false), "not five minutes yet");
        assert!(!s.observe(secs, true, false), "two samples");
        assert!(s.observe(secs + 10, true, false));
        assert_eq!(s.from(), 0);
        // A coarse interval reaches five minutes before three samples.
        let mut s = Stall::default();
        s.observe(0, false, true);
        assert!(!s.observe(secs * 10, true, false));
        assert!(!s.observe(secs * 11, true, false));
        assert!(s.observe(secs * 12, true, false));
        // Idle since the boot sample, polling ticks inside the stretch notwithstanding.
        let mut s = Stall::default();
        s.observe(0, false, false);
        for i in 1..100 {
            assert!(!s.observe(i * 10, true, true));
        }
        // A sample that moves restarts the stretch there.
        let mut s = Stall::default();
        s.observe(0, false, true);
        s.observe(10, true, false);
        s.observe(20, false, false);
        assert_eq!(s.from(), 20);
        assert!(!s.observe(secs + 10, true, false));
        assert!(!s.observe(secs + 20, true, false));
        assert!(s.observe(secs + 30, true, false));
        // Under a tenth of a processor, 100 Hz over 10 s: 99 ticks is idle, 100 is not.
        assert!(idle(true, 99, 100, 10, 0) && !idle(true, 100, 100, 10, 0));
        assert!(!idle(false, 0, 100, 10, 0) && !idle(true, 0, 100, 10, 1));
        assert!(!idle(true, 0, 0, 10, 0) && !idle(true, 0, 100, 0, 0));
        let hist = |pairs: &[(&str, u32)]| -> std::collections::BTreeMap<String, u32> {
            pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
        };
        let flicker = hist(&[("__futex_wait", 2), ("hrtimer_nanosleep", 7)]);
        assert!(same_channels(
            &flicker,
            &hist(&[("__futex_wait", 2), ("hrtimer_nanosleep", 5)])
        ));
        assert!(!same_channels(&flicker, &hist(&[("__futex_wait", 9)])));
        assert!(worked(1, 0) && worked(0, 1) && !worked(0, 0));
    }

    /// The knob the host writes is the knob the guest parses — the two sides agree on
    /// nothing else.
    #[test]
    fn the_cmdline_knob_round_trips() {
        assert_eq!(
            cmdline_knob(30),
            " VIRTKIT_ATOP=vkatop:/run/virtkit-atop:30 psi=1"
        );
        let value = cmdline_knob(30)
            .split_whitespace()
            .find_map(|t| t.strip_prefix("VIRTKIT_ATOP="))
            .map(str::to_string)
            .expect("the knob carries the parameter");
        assert_eq!(parse_knob(&value), Some((TAG, GUEST_MOUNT, 30)));
        for bad in [
            "vkatop:/run/virtkit-atop",       // no interval
            "vkatop:/run/virtkit-atop:0",     // a zero interval would spin
            "vkatop:/run/virtkit-atop:x",     // unparseable
            ":/run/virtkit-atop:30",          // no tag
            "vkatop:run/virtkit-atop:30",     // relative mountpoint
            "vkatop:/run/virtkit-atop:30:40", // trailing field
        ] {
            assert_eq!(parse_knob(bad), None, "{bad}");
        }
    }

    /// The date and time columns, and the archive day they are filed under.
    #[test]
    fn dates_and_times_are_the_utc_day() {
        assert_eq!(
            date_time(0),
            ("1970/01/01".to_string(), "00:00:00".to_string())
        );
        assert_eq!(
            date_time(1_767_225_600),
            ("2026/01/01".to_string(), "00:00:00".to_string())
        );
        // a leap day, and its last second
        assert_eq!(
            date_time(1_709_251_199),
            ("2024/02/29".to_string(), "23:59:59".to_string())
        );
        assert_eq!(date_dir(1_709_251_199), "2024-02-29");
        assert_eq!(date_dir(0), "1970-01-01");
        // The day boundary the archive is cut on: the last second of a day and the first
        // second of the next belong to different directories.
        assert_eq!(date_dir(1_709_251_200), "2024-03-01");
        // A clock before the epoch still names a day rather than dividing towards zero.
        assert_eq!(date_dir(-1), "1969-12-31");
    }

    /// The clock both sides stamp their records with, read as the day the archive files it
    /// under: whatever the calendar does, the two agree.
    #[test]
    fn the_epoch_now_is_the_day_it_is_filed_under() {
        let now = now_epoch();
        assert!(now > 1_767_225_600, "the clock is set: {now}");
        assert_eq!(date_dir(now), date_dir_of_day(day_of(now)));
        assert_eq!(day_of(now) - day_of(now - 86_400), 1);
    }

    /// A day number and its directory name convert both ways, whatever the calendar does
    /// around them: the retention sweep compares those numbers, so an edge getting them
    /// wrong would drop a day early or keep one forever.
    #[test]
    fn a_date_directory_name_reads_back_as_its_day() {
        for name in [
            "1970-01-01",
            "2024-02-29",
            "2024-03-01",
            "2026-08-11",
            "2026-12-31",
        ] {
            let day = parse_date_dir(name).unwrap_or_else(|| panic!("{name} is a date"));
            assert_eq!(date_dir_of_day(day), name);
        }
        assert_eq!(
            parse_date_dir("2024-03-01").unwrap() - parse_date_dir("2024-02-29").unwrap(),
            1
        );
        // Anything that is not a day of recordings has no day number, so a sweep leaves it
        // where the operator put it — including names that are nearly one, since a name the
        // archive would never write is a name somebody else chose.
        for bad in [
            "atop.log",
            "2026-08",
            "2026-08-11.bak",
            "2026-13-01",
            "2026-08-32",
            "2026-02-31", // in range, but no such day
            "2023-02-29", // a leap day of a common year
            "2026-1-1",   // not the width the archive writes
            "2026-08-011",
            "+2026-01-01",
            "9223372036854775807-01-01", // a year the day arithmetic could not hold
            "yesterday",
            "",
        ] {
            assert_eq!(parse_date_dir(bad), None, "{bad}");
        }
    }
}
