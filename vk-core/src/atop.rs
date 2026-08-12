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

/// Whole days since 1970-01-01, UTC — what a day of the archive is keyed on.
fn day_of(epoch: i64) -> i64 {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The schema is indexed by field name, so a repeated name inside one label would
    /// silently answer for the wrong column — atop prints the swap cache twice, which is
    /// exactly the trap.
    #[test]
    fn every_label_names_its_fields_once() {
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
}
