//! What a recorded job did, from its samples: the report `vk atop --summary` prints.
//!
//! A log is a few hundred lines per interval and nobody reads that; this is the account of
//! it — how long the guest ran, what it did with its processors and memory, what it moved,
//! where it stalled, and which of its processes the time went to.
//!
//! Two properties of the format shape every figure here. Counter labels carry per-interval
//! differences, so a *total* is a sum over samples and a *rate* is one sample divided by its
//! interval. And the first sample covers the guest's whole boot (`RESET`), which is a window
//! of a different size: it counts towards totals, and is left out of anything computed *over*
//! an interval — the percentages, the rates, the sparklines — where it would otherwise flatten
//! everything after it into one bar. A figure that was simply the reading at a moment (the
//! load, the memory held, a pressure average) is taken from every sample, the first included:
//! a peak the guest really reached is not less true for having happened during boot.
//!
//! The log itself is written by the job's own guest, on a directory it had read-write (see
//! [`crate::atop`]), so everything here reads it as text a hostile process chose: a figure
//! that cannot be represented is dropped rather than trusted, and no arithmetic over one may
//! panic.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use anyhow::{Context, Result};

use crate::atoplog::{Parsed, Proc, SECTOR, Sample, Stall};
use crate::usage::{fmt_bytes, fmt_cpu};

/// The bars a sparkline is drawn with, lightest first.
const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// How many processes the "what ran" table lists.
const TOP_PROCS: usize = 10;

/// Seconds as a duration, saturating. A guest writes both its tick counters and the `hertz`
/// they are counted in, so the quotient can be a number no `Duration` names — and a report is
/// not the place to panic over one.
pub(crate) fn secs_of(v: f64) -> std::time::Duration {
    std::time::Duration::try_from_secs_f64(v).unwrap_or(std::time::Duration::MAX)
}

/// Read a recorded log and account it: the whole of `--summary`.
pub fn summarize(path: &Path) -> Result<String> {
    summarize_as(path, None)
}

/// The same account, headed with `named` instead of the recording's directory — for a log
/// whose directory is not a job's. A live attach lays one down in `<state dir>/atop/`, which
/// names the archive rather than the VM the samples came from.
pub fn summarize_as(path: &Path, named: Option<&str>) -> Result<String> {
    let text = crate::atoplog::read(path)?;
    let parsed = crate::atoplog::parse(&text);
    summary(path, named, &parsed).with_context(|| {
        format!(
            "{} holds no complete sample yet (a job records its first one an interval in)",
            path.display()
        )
    })
}

/// The same account, without the line that says whose it is — for the job trace, where the
/// section holding it is already headed with the job's name. `None` where there is nothing to
/// account, which is a job whose guest died before it finished a sample.
pub(crate) fn trace_body(path: &Path) -> Option<String> {
    let text = crate::atoplog::read(path).ok()?;
    body(&crate::atoplog::parse(&text))
}

/// The report for one recorded job, or `None` when the log holds no complete sample — a
/// guest that died before finishing its first one.
fn summary(path: &Path, named: Option<&str>, parsed: &Parsed) -> Option<String> {
    let job = named.map(str::to_string).unwrap_or_else(|| {
        path.parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.display().to_string())
    });
    Some(format!(
        "virtkit: {job} — what its guest did:\n{}",
        body(parsed)?
    ))
}

/// The account itself: everything but the line naming the job it belongs to.
fn body(parsed: &Parsed) -> Option<String> {
    let samples = parsed.samples.as_slice();
    let (first, last) = (samples.first()?, samples.last()?);
    // Rates come from the samples that cover one interval each; the boot sample covers
    // however long the guest had been up, which is not a comparable window.
    let paced: Vec<&Sample> = samples.iter().filter(|s| !s.boot).collect();

    let mut out = String::new();
    out.push_str(&keyed(
        "recorded",
        &span(first, last, &paced, samples.len()),
    ));
    if let Some(line) = hardware(samples) {
        out.push_str(&keyed("guest", &line));
    }
    if let Some(line) = cpu_line(samples, &paced) {
        out.push_str(&keyed("cpu", &line));
    }
    if let Some(line) = load_line(samples, &paced) {
        out.push_str(&keyed("load", &line));
    }
    if let Some(line) = memory_line(samples) {
        out.push_str(&keyed("memory", &line));
    }
    if let Some(line) = pressure_line(samples) {
        out.push_str(&keyed("pressure", &line));
    }
    if let Some(line) = disk_line(samples) {
        out.push_str(&keyed("disk", &line));
    }
    if let Some(line) = network_line(samples) {
        out.push_str(&keyed("network", &line));
    }
    // The shape of the job over time, one bar per sample: which end of it the work was at
    // is the question a total cannot answer.
    if paced.len() > 1 {
        if let Some(bars) = sparkline(&paced, |s| {
            s.cpu.as_ref().map(|c| c.percent(c.busy()) / 100.0)
        }) {
            out.push_str(&keyed("cpu over time", &bars));
        }
        if let Some(bars) = sparkline(&paced, |s| {
            s.mem
                .as_ref()
                .filter(|m| m.physmem > 0)
                .map(|m| m.used() as f64 / m.physmem as f64)
        }) {
            out.push_str(&keyed("memory over time", &bars));
        }
    }
    if parsed.ends_mid_sample() {
        out.push_str(&keyed(
            "incomplete",
            "the log ends mid-sample — the guest was still running, or died writing it",
        ));
    }
    // A record the format could not carry, or one a damaged log cut short: the figures above
    // are missing whatever it held, which is worth a line rather than silence.
    if parsed.dropped > 0 {
        out.push_str(&keyed(
            "damaged",
            &format!(
                "{} {} did not carry their label's fields and were left out",
                parsed.dropped,
                plural(parsed.dropped as u64, "record")
            ),
        ));
    }
    out.push_str(&processes(samples));
    Some(out)
}

/// How wide the labels of the overview block are: the longest of them and a space, so every
/// value starts at the same column and a new label cannot silently misalign the rest.
const LABEL_WIDTH: usize = "memory over time".len() + 1;

/// One `label   value` line of the overview block. The labels read down the left edge, wide
/// enough for the longest of them, so the values line up as a column.
fn keyed(label: &str, value: &str) -> String {
    format!("  {label:<LABEL_WIDTH$}{value}\n")
}

/// When the recording ran, and at what resolution.
fn span(first: &Sample, last: &Sample, paced: &[&Sample], samples: usize) -> String {
    let (date, from) = vk_core::atop::date_time(first.epoch);
    let (_, to) = vk_core::atop::date_time(last.epoch);
    let covered = last.epoch.saturating_sub(first.epoch).max(0) as u64;
    // The interval every paced sample shares, and only where they all agree — a job recorded
    // at one resolution is the normal case, and saying "1s" beats saying nothing. Read off the
    // paced samples alone: the boot sample's interval column is the guest's uptime, not a pace.
    let pace = match paced.first().map(|s| s.interval) {
        Some(secs) if paced.iter().all(|s| s.interval == secs) => format!(" at {secs}s"),
        _ => String::new(),
    };
    // Say which samples the percentages below rest on: the first covers the guest's boot,
    // so it is in the totals and out of the rates, and a reader comparing the two needs to
    // know that the busiest moment of the boot is not among them.
    let boot = match first.boot {
        true => ", the first covering the guest's boot (counted in the totals, not the rates)",
        false => "",
    };
    format!(
        "{date} {from} → {to} UTC ({}), {samples} {}{pace}{boot}",
        fmt_secs(covered),
        plural(samples as u64, "sample")
    )
}

/// What the guest had to work with: a job's VM does not change size, so this is the newest
/// sample that carries each record rather than only the last — a guest that died partway
/// through writing its final sample still said what it was working with earlier.
fn hardware(samples: &[Sample]) -> Option<String> {
    let last = samples.last()?;
    let newest = |f: fn(&Sample) -> bool| samples.iter().rev().find(|s| f(s));
    let cpu = newest(|s| s.cpu.is_some())?.cpu.as_ref()?;
    let mem = newest(|s| s.mem.is_some())?.mem.as_ref()?;
    let swap = match newest(|s| s.swap.is_some())
        .and_then(|s| s.swap.as_ref())
        .map(|s| s.total_bytes())
        .unwrap_or(0)
    {
        0 => "no swap".to_string(),
        total => format!("{} swap", fmt_bytes(total)),
    };
    Some(format!(
        "{} on {} {}, {} memory, {swap}",
        last.host,
        cpu.cpus,
        plural(cpu.cpus as u64, "cpu"),
        fmt_bytes(mem.bytes(mem.physmem))
    ))
}

/// What the processors did: the whole job's cpu time, then how hard they were driven and
/// where that time went.
fn cpu_line(samples: &[Sample], paced: &[&Sample]) -> Option<String> {
    let mut ticks = Total::default();
    for s in samples.iter().filter_map(|s| s.cpu.as_ref()) {
        // Saturating throughout: a guest writes its own tick counters, and a sum of two it
        // chose must report a wrong-looking total rather than wrap into a plausible one.
        ticks.busy = ticks.busy.saturating_add(s.busy());
        ticks.user = ticks.user.saturating_add(s.user).saturating_add(s.nice);
        ticks.system = ticks
            .system
            .saturating_add(s.system)
            .saturating_add(s.irq)
            .saturating_add(s.softirq);
        ticks.iowait = ticks.iowait.saturating_add(s.iowait);
        ticks.steal = ticks.steal.saturating_add(s.steal);
        ticks.hertz = s.hertz.max(ticks.hertz);
    }
    let hertz = match ticks.hertz {
        0 => return None,
        hz => hz as f64,
    };
    let cpu_time = |t: u64| fmt_cpu(secs_of(t as f64 / hertz));
    let busy: Vec<f64> = paced
        .iter()
        .filter_map(|s| s.cpu.as_ref())
        .map(|c| c.percent(c.busy()))
        .collect();
    let mut line = format!(
        "{} of cpu time — {} user, {} system",
        cpu_time(ticks.busy),
        cpu_time(ticks.user),
        cpu_time(ticks.system),
    );
    // Stolen time is part of the cpu time above (a processor was taken while the guest was
    // runnable); waiting for a disk is not cpu time at all, so it sits beside it rather than
    // inside the list, which would otherwise not add up to the figure it breaks down.
    if ticks.steal > 0 {
        line.push_str(&format!(", {} stolen by the host", cpu_time(ticks.steal)));
    }
    if ticks.iowait > 0 {
        line.push_str(&format!("; {} waiting for disk", cpu_time(ticks.iowait)));
    }
    if let (Some(peak), Some(avg)) = (max(&busy), mean(&busy)) {
        line.push_str(&format!("; {peak:.0}% busy at peak, {avg:.0}% on average"));
    }
    // Which core carried it: a job that drove one processor flat while the others idled is
    // single-threaded, which no total across them can show.
    if let Some((core, share)) = busiest_core(paced) {
        line.push_str(&format!(
            ", cpu {core} busiest at {share:.0}% of its own time"
        ));
    }
    Some(line)
}

/// The processor that spent the largest share of the whole recording on work, and that share
/// of its own time. `None` where the log has no per-core records, or only one core to choose
/// between.
///
/// Summed over the paced samples rather than picked from the best single one: the question is
/// which processor carried the work, and at a one-second resolution one spike is not that.
fn busiest_core(paced: &[&Sample]) -> Option<(u32, f64)> {
    let mut by_core: BTreeMap<u32, (u64, u64)> = BTreeMap::new();
    for c in paced.iter().flat_map(|s| s.cores.iter()) {
        let Some(core) = c.core else {
            continue; // a per-core record with no core number names no processor
        };
        let (busy, total) = by_core.entry(core).or_default();
        *busy = busy.saturating_add(c.busy());
        *total = total.saturating_add(c.total());
    }
    if by_core.len() < 2 {
        return None; // nothing to choose between
    }
    by_core
        .into_iter()
        .filter(|(_, (_, total))| *total > 0)
        .map(|(core, (busy, total))| (core, 100.0 * busy as f64 / total as f64))
        .max_by(|a, b| a.1.total_cmp(&b.1))
}

/// Ticks of the whole job, by where they went.
#[derive(Default)]
struct Total {
    busy: u64,
    user: u64,
    system: u64,
    iowait: u64,
    steal: u64,
    hertz: u64,
}

/// What the run queue looked like: the peak one-minute average, where it stood at the end,
/// and how much context switching the job cost — a job whose work is many short commands
/// switches far more than one long compile.
fn load_line(samples: &[Sample], paced: &[&Sample]) -> Option<String> {
    let last = samples.iter().filter_map(|s| s.load.as_ref()).next_back()?;
    // The load average is the reading at a moment, not a figure computed over an interval, so
    // it is taken from every sample: a queue the guest really had during boot is not less real.
    let peak = samples
        .iter()
        .filter_map(|s| s.load.as_ref())
        .map(|l| l.load1)
        .reduce(f64::max)
        .unwrap_or(0.0);
    // A rate, so only the paced samples: the interval column is already clamped to at least 1
    // when a sample is built, which is what makes this division safe.
    let switches = paced
        .iter()
        .filter_map(|s| s.load.as_ref().map(|l| l.ctxsw / s.interval))
        .max();
    Some(format!(
        "{peak:.2} at peak, {:.2} / {:.2} / {:.2} at the end (1m / 5m / 15m); \
         {} context switches a second at peak",
        last.load1,
        last.load5,
        last.load15,
        // No paced sample means no interval to divide by — not zero switching.
        match switches {
            Some(n) => n.to_string(),
            None => "-".to_string(),
        }
    ))
}

/// The most memory the guest held, and what it did when it ran short.
///
/// Every sample, the boot one included: memory held is the reading at a moment rather than a
/// figure computed over an interval, so a peak the guest reached while booting is a peak it
/// reached. (Which is why this figure can exceed the `memory over time` sparkline's own peak,
/// drawn from the paced samples alone.)
fn memory_line(samples: &[Sample]) -> Option<String> {
    let mems: Vec<&crate::atoplog::Mem> = samples.iter().filter_map(|s| s.mem.as_ref()).collect();
    let peak = mems.iter().map(|m| m.bytes(m.used())).max()?;
    let total = mems.last().map(|m| m.bytes(m.physmem)).unwrap_or(0);
    let cache = mems.iter().map(|m| m.bytes(m.cache())).max().unwrap_or(0);
    let share = match total {
        0 => String::new(),
        total => format!(" ({:.0}% of the VM)", 100.0 * peak as f64 / total as f64),
    };
    let mut line = format!(
        "{} held at peak{share}, {} of cache at peak",
        fmt_bytes(peak),
        fmt_bytes(cache)
    );
    let swapped = samples
        .iter()
        .filter_map(|s| s.swap.as_ref())
        .map(|s| s.used_bytes())
        .max()
        .unwrap_or(0);
    if swapped > 0 {
        line.push_str(&format!(", {} swapped out", fmt_bytes(swapped)));
    }
    // Reclaim stalls, swapping and OOM kills are what "short of memory" looks like from
    // inside the guest — worth saying only when the guest hit them.
    let mut stalls = 0u64;
    let mut swapio = 0u64;
    let mut oomkills = None;
    for p in samples.iter().filter_map(|s| s.paging.as_ref()) {
        stalls = stalls.saturating_add(p.allocstalls);
        swapio = swapio.saturating_add(p.swapins).saturating_add(p.swapouts);
        if let Some(n) = p.oomkills {
            oomkills = Some(oomkills.unwrap_or(0u64).saturating_add(n));
        }
    }
    if stalls > 0 || swapio > 0 || oomkills.is_some_and(|n| n > 0) {
        line.push_str(&format!(
            "; {stalls} allocation {}, {swapio} pages swapped, {} oom {}",
            plural(stalls, "stall"),
            match oomkills {
                Some(n) => n.to_string(),
                None => "-".to_string(),
            },
            plural(oomkills.unwrap_or(0), "kill"),
        ));
    }
    Some(line)
}

/// Where the guest was stalled waiting for a resource, worst moment first. Pressure is the
/// one figure that says a job was *held up* rather than merely busy.
///
/// The totals are over every sample; the worst average is the reading at a moment, so it too
/// comes from every sample rather than the paced ones alone.
fn pressure_line(samples: &[Sample]) -> Option<String> {
    let psis: Vec<&crate::atoplog::Psi> = samples.iter().filter_map(|s| s.psi.as_ref()).collect();
    if psis.is_empty() {
        // Nothing in the log says anything about pressure either way, so this says nothing
        // about the guest's kernel — which the "not recorded" line below would.
        return None;
    }
    if !psis.iter().any(|p| p.supported) {
        return Some(
            "not recorded — this guest's kernel was booted without pressure stall information"
                .to_string(),
        );
    }
    let mut parts: Vec<String> = Vec::new();
    type Pick = fn(&crate::atoplog::Psi) -> Stall;
    let resources: [(&str, Pick); 5] = [
        ("cpu", |p| p.cpu_some),
        ("memory", |p| p.mem_some),
        ("memory full", |p| p.mem_full),
        ("io", |p| p.io_some),
        ("io full", |p| p.io_full),
    ];
    for (name, pick) in resources {
        // Total stalled time first: it is the figure that adds up over a job, where the
        // averages are only ever a moment's reading.
        let stalled: u64 = samples
            .iter()
            .filter_map(|s| s.psi.as_ref())
            .map(|p| pick(p).total_us)
            .fold(0, u64::saturating_add);
        if stalled == 0 {
            continue;
        }
        let worst = samples
            .iter()
            .filter_map(|s| s.psi.as_ref().map(|p| (pick(p).avg10, s.epoch)))
            .fold((0.0f64, 0i64), |a, b| if b.0 > a.0 { b } else { a });
        let at = match worst.0 > 0.0 {
            true => format!(
                ", {:.1}% at {}",
                worst.0,
                vk_core::atop::date_time(worst.1).1
            ),
            false => String::new(),
        };
        parts.push(format!("{name} {}{at}", fmt_micros(stalled)));
    }
    match parts.is_empty() {
        true => Some("nothing waited on a resource".to_string()),
        false => Some(parts.join("; ")),
    }
}

/// What the guest's disks moved, and which one carried it.
fn disk_line(samples: &[Sample]) -> Option<String> {
    let mut read = 0u64;
    let mut written = 0u64;
    let mut busiest: Option<(&str, u64)> = None;
    let mut by_device: Vec<(&str, u64)> = Vec::new();
    for d in samples.iter().flat_map(|s| s.disks.iter()) {
        read = read.saturating_add(d.sectors_read.saturating_mul(SECTOR));
        written = written.saturating_add(d.sectors_written.saturating_mul(SECTOR));
        match by_device.iter_mut().find(|(name, _)| *name == d.name) {
            Some((_, ms)) => *ms = ms.saturating_add(d.io_ms),
            None => by_device.push((&d.name, d.io_ms)),
        }
    }
    if by_device.is_empty() {
        return None; // no disk did anything: the guest worked entirely in memory
    }
    for (name, ms) in &by_device {
        if busiest.is_none_or(|(_, most)| *ms > most) {
            busiest = Some((name, *ms));
        }
    }
    let mut line = format!("{} read, {} written", fmt_bytes(read), fmt_bytes(written));
    if let Some((name, ms)) = busiest {
        line.push_str(&format!(" — {name} busiest, {} busy", fmt_millis(ms)));
    }
    Some(line)
}

/// What crossed the guest's interfaces. Loopback is left out of the totals: traffic a guest
/// sends itself never leaves it, and counting it would double every local round-trip.
fn network_line(samples: &[Sample]) -> Option<String> {
    let mut ifaces: Vec<(&str, u64, u64)> = Vec::new();
    for i in samples
        .iter()
        .flat_map(|s| s.ifaces.iter())
        .filter(|i| i.name != "lo")
    {
        match ifaces.iter_mut().find(|(name, _, _)| *name == i.name) {
            Some((_, in_, out)) => {
                *in_ = in_.saturating_add(i.bytes_in);
                *out = out.saturating_add(i.bytes_out);
            }
            None => ifaces.push((&i.name, i.bytes_in, i.bytes_out)),
        }
    }
    ifaces.retain(|(_, in_, out)| *in_ > 0 || *out > 0);
    if ifaces.is_empty() {
        return None; // nothing crossed the network
    }
    ifaces.sort_by_key(|(_, in_, out)| std::cmp::Reverse(in_.saturating_add(*out)));
    let mut line = ifaces
        .iter()
        .map(|(name, in_, out)| {
            format!(
                "{name} received {}, sent {}",
                fmt_bytes(*in_),
                fmt_bytes(*out)
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    let retrans: u64 = samples
        .iter()
        .filter_map(|s| s.net.as_ref())
        .map(|n| n.tcp_retrans)
        .fold(0, u64::saturating_add);
    let established = samples
        .iter()
        .filter_map(|s| s.net.as_ref())
        .map(|n| n.tcp_established)
        .max()
        .unwrap_or(0);
    if established > 0 || retrans > 0 {
        line.push_str(&format!(
            "; {established} tcp connections at peak, {retrans} segments resent"
        ));
    }
    Some(line)
}

/// The whole job's processes, the ones that used the most processor time first: a job's own
/// account of where its time went, which nothing outside the guest can give.
fn processes(samples: &[Sample]) -> String {
    let mut totals = Totals::over(samples);
    if totals.is_empty() {
        return String::new();
    }
    // The pid last, so the order does not depend on how the map happened to iterate.
    totals.sort_by(|a, b| {
        b.cpu
            .total_cmp(&a.cpu)
            .then(b.rss_peak_kib.cmp(&a.rss_peak_kib))
            .then(a.pid.cmp(&b.pid))
    });
    let listed = totals.len().min(TOP_PROCS);
    let rows: Vec<Cells> = totals.iter().take(listed).map(Totals::row).collect();
    let widths = widths(&rows);
    // How much of the job was commands too short-lived for a sweep to catch. A burst of them
    // can be most of what a job did and still sort below the top of this table — a thousand
    // processes that each ran for a millisecond — so the count is said whatever it ranks.
    let churn: u64 = totals
        .iter()
        .filter(|t| t.burst)
        .map(|t| t.runs)
        .fold(0, u64::saturating_add);
    let mut out = format!(
        "\n  what ran{}{}\n",
        match totals.len() > listed {
            true => format!(" — the {listed} of {} that used the most cpu", totals.len()),
            false => String::new(),
        },
        match churn {
            0 => String::new(),
            n => format!("; {n} short-lived {} came and went", plural(n, "task")),
        }
    );
    out.push_str(&line(&head(), &widths));
    for row in &rows {
        out.push_str(&line(row, &widths));
    }
    out
}

/// One process across every sample it appears in — what the whole job charged to it. Shared
/// with the panel, whose `a` key asks the same question of the samples it has read.
pub(crate) struct Totals {
    pid: i32,
    command: String,
    cpu: f64,
    rss_peak_kib: u64,
    read: u64,
    written: u64,
    /// Whether any sample could account this process's disk traffic at all.
    io_stats: bool,
    /// How many runs this row stands for: one, unless it is a command the job ran over and over
    /// and the kernel reported each death (see [`Totals::over`]).
    runs: u64,
    /// The kernel reported this task's death, and no sweep ever saw it alive — the shape of a
    /// command too short-lived for the sampler to catch any other way.
    burst: bool,
    /// The task ended while the job was recorded, however it was seen.
    exited: bool,
    /// How many of those runs ended with a non-zero status.
    failures: u64,
}

impl Totals {
    /// Every process of a recording, one entry each. Keyed on the pid *and* when it started:
    /// a guest that runs thousands of short commands reuses pids, and two processes that
    /// shared one must not merge into a third that ran for as long as both.
    pub(crate) fn over(samples: &[Sample]) -> Vec<Totals> {
        // A map rather than a scan: a long job holds tens of thousands of distinct processes,
        // and finding each one linearly in every sample is quadratic in exactly the case this
        // exists for. A start time has one-second resolution, so two processes that reused a
        // pid inside one second do still merge.
        let mut by_proc: HashMap<(i32, i64), Totals> = HashMap::new();
        for s in samples {
            for p in &s.procs {
                by_proc
                    .entry((p.pid, p.started))
                    .or_insert_with(|| Totals::new(p))
                    .add(p);
            }
        }
        burst_rows(by_proc.into_values().collect())
    }

    pub(crate) fn pid(&self) -> i32 {
        self.pid
    }

    /// What to call this row: the command, and how many runs of it there were where it stands
    /// for a burst of them.
    pub(crate) fn command(&self) -> String {
        let mut out = self.command.clone();
        if self.runs > 1 {
            out.push_str(&format!(" ×{}", self.runs));
        }
        if self.failures > 0 {
            out.push_str(&format!(" ({} failed)", self.failures));
        }
        out
    }

    /// The processor time the whole job charged to the process. A `Duration` rather than the
    /// quotient it came from: a guest writes both its tick counters and the `hertz` they are
    /// counted in, so the figure can be one no `Duration` names.
    pub(crate) fn cpu_time(&self) -> std::time::Duration {
        secs_of(self.cpu)
    }

    /// The state a panel shows for this row: `E` for a task that ended while the job ran, as
    /// atop marks an exited one, and `-` for a process the recording only ever saw alive.
    pub(crate) fn state(&self) -> char {
        match self.exited {
            true => 'E',
            false => '-',
        }
    }

    pub(crate) fn peak_rss_bytes(&self) -> u64 {
        self.rss_peak_kib.saturating_mul(1024)
    }

    /// Everything the process moved, read and written together — the panel sorts on one
    /// figure where the report has room for both. `None` where no sample could account its
    /// traffic at all, which is not the same as having moved nothing.
    pub(crate) fn disk_bytes(&self) -> Option<u64> {
        self.io_stats
            .then(|| self.read.saturating_add(self.written))
    }

    fn new(p: &Proc) -> Totals {
        Totals {
            pid: p.pid,
            command: plain(p.command()),
            cpu: 0.0,
            rss_peak_kib: 0,
            read: 0,
            written: 0,
            io_stats: false,
            runs: 1,
            burst: p.exited(),
            exited: p.exited(),
            failures: 0,
        }
    }

    fn add(&mut self, p: &Proc) {
        // A record of a death is the last word on a task; a sweep that saw it alive means this
        // row is a process the sampler watched, not one it only ever heard about.
        match p.exited() {
            true => {
                self.exited = true;
                self.failures = self.failures.saturating_add(u64::from(p.failed()));
            }
            false => self.burst = false,
        }
        self.cpu += p.cpu_seconds();
        self.rss_peak_kib = self.rss_peak_kib.max(p.rsize);
        self.read = self
            .read
            .saturating_add(p.sectors_read.saturating_mul(SECTOR));
        self.written = self
            .written
            .saturating_add(p.sectors_written.saturating_mul(SECTOR));
        self.io_stats |= p.io_stats;
        // The command line is only in PRG, so a process first seen through another label
        // has its bare name until one arrives.
        if !p.cmdline.is_empty() || self.command.is_empty() {
            self.command = plain(p.command());
        }
    }

    fn row(&self) -> Cells {
        let disk = |bytes: u64| match self.io_stats {
            true => fmt_bytes(bytes),
            false => "-".to_string(),
        };
        [
            truncated(&self.command(), COMMAND_WIDTH),
            match self.runs > 1 {
                // A row standing for many runs has no one pid to name.
                true => "-".to_string(),
                false => self.pid.to_string(),
            },
            fmt_cpu(self.cpu_time()),
            fmt_bytes(self.peak_rss_bytes()),
            disk(self.read),
            disk(self.written),
        ]
    }
}

/// Fold the commands a job ran over and over into one row each.
///
/// A task the sampler only ever heard the death of is one of a burst — a compile forking a
/// thousand `cc1`, a test suite a process per case — and a thousand rows of one run each say
/// far less than one row of a thousand runs. A process a sweep did see stays its own row: it
/// ran long enough to be worth naming on its own, and merging it into its namesakes would hide
/// how long.
fn burst_rows(totals: Vec<Totals>) -> Vec<Totals> {
    let mut out: Vec<Totals> = Vec::new();
    // The row each burst command has folded into so far. A map rather than a scan over `out`:
    // the commands are a guest's own, and one that writes thirty thousand distinct ones must
    // not cost thirty thousand comparisons apiece. The order does not matter — the caller
    // sorts.
    let mut folded: HashMap<String, usize> = HashMap::new();
    for t in totals {
        let merged = t.burst
            && folded
                .get(&t.command)
                .and_then(|at| out.get_mut(*at))
                .map(|o| {
                    o.runs = o.runs.saturating_add(1);
                    o.exited = true;
                    o.failures = o.failures.saturating_add(t.failures);
                    o.cpu += t.cpu;
                    o.rss_peak_kib = o.rss_peak_kib.max(t.rss_peak_kib);
                    o.read = o.read.saturating_add(t.read);
                    o.written = o.written.saturating_add(t.written);
                    o.io_stats |= t.io_stats;
                })
                .is_some();
        if !merged {
            if t.burst {
                folded.insert(t.command.clone(), out.len());
            }
            out.push(t);
        }
    }
    out
}

/// One row of the process table, headings included: a fixed width so `head`, `row`, `widths`
/// and `line` cannot drift into a table whose columns do not line up.
const COLS: usize = 6;
type Cells = [String; COLS];

fn head() -> Cells {
    ["command", "pid", "cpu", "peak rss", "read", "written"].map(str::to_string)
}

/// A guest's own text, as a report or a panel may write it: one cell per character, and nothing
/// a terminal reads as an instruction. The log is written on a directory the job's guest had
/// read-write (see [`crate::atop`]), so a command line can hold an escape sequence — and one
/// drawn into a full-screen panel would move the cursor rather than name a process.
///
/// Applied where the text enters a row, not where the row is drawn: what this module adds
/// afterwards (`×1184`, `(2 failed)`) is its own and must survive.
pub(crate) fn plain(s: &str) -> String {
    s.chars()
        .map(|c| match c.is_ascii_graphic() || c == ' ' {
            true => c,
            false => '.',
        })
        .collect()
}

/// How wide the command column may get. A build's own command lines run to hundreds of
/// characters — and a guest can write one of any length at all — so one of them must not push
/// every figure beside it off the screen.
const COMMAND_WIDTH: usize = 60;

/// `s` cut to `width` characters, the last of them an ellipsis where anything was dropped.
/// Counted in characters rather than display columns, so a command holding double-width text
/// still lines up only approximately.
fn truncated(s: &str, width: usize) -> String {
    match s.chars().count() > width {
        true => s
            .chars()
            .take(width.saturating_sub(1))
            .chain(['…'])
            .collect(),
        false => s.to_string(),
    }
}

/// Each column wide enough for the widest cell in it, headings included.
fn widths(rows: &[Cells]) -> [usize; COLS] {
    let head = head();
    std::array::from_fn(|col| {
        rows.iter()
            .map(|r| &r[col])
            .chain([&head[col]])
            .map(|cell| cell.chars().count())
            .max()
            .unwrap_or(0)
    })
}

/// One rendered line: the command reads down the left edge, figures line up on the right
/// where a column of mixed units can be compared at a glance.
fn line(cells: &Cells, widths: &[usize; COLS]) -> String {
    let mut out = String::from("  ");
    for (col, (cell, width)) in cells.iter().zip(widths).enumerate() {
        match col {
            0 => out.push_str(&format!("{cell:<width$}  ")),
            _ => out.push_str(&format!("{cell:>width$}  ")),
        }
    }
    while out.ends_with(' ') {
        out.pop();
    }
    out.push('\n');
    out
}

/// One bar per sample of a series scaled 0.0–1.0, or `None` where no sample carried the
/// figure. The scale is absolute, not stretched to the series: a job that never troubled
/// its guest should look flat, not busy.
fn sparkline(samples: &[&Sample], pick: impl Fn(&Sample) -> Option<f64>) -> Option<String> {
    let values: Vec<f64> = samples.iter().filter_map(|s| pick(s)).collect();
    if values.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(values.len().saturating_mul(4));
    for v in &values {
        let scaled = (v * BARS.len() as f64).ceil() as usize;
        let bar = BARS
            .get(scaled.clamp(1, BARS.len()).saturating_sub(1))
            .copied()
            .unwrap_or(BARS[0]);
        out.push(bar);
    }
    let peak = max(&values).unwrap_or(0.0);
    Some(format!("{out}  (peak {:.0}%)", peak * 100.0))
}

fn max(values: &[f64]) -> Option<f64> {
    values.iter().copied().reduce(f64::max)
}

fn mean(values: &[f64]) -> Option<f64> {
    match values.len() {
        0 => None,
        n => Some(values.iter().sum::<f64>() / n as f64),
    }
}

/// A duration at job scale, from the seconds a log counts in.
fn fmt_secs(secs: u64) -> String {
    match secs {
        0 => "under a second".to_string(),
        s if s < 60 => format!("{s}s"),
        // A minute or more reads as a job's own timings do, from the one place that renders
        // them (`usage::fmt_cpu`).
        s => fmt_cpu(std::time::Duration::from_secs(s)),
    }
}

/// A sub-second unit rendered as seconds once it reaches one — the arm `fmt_millis` and
/// `fmt_micros` share, where a bare figure in the small unit stops being readable.
fn fmt_as_secs(n: u64, per_sec: u64) -> String {
    format!("{:.1}s", n as f64 / per_sec as f64)
}

/// Time a device spent busy, which diskstats counts in milliseconds.
fn fmt_millis(ms: u64) -> String {
    match ms {
        ms if ms < 1_000 => format!("{ms}ms"),
        ms => fmt_as_secs(ms, 1_000),
    }
}

/// Stalled time, which pressure counts in microseconds and a reader thinks of in seconds.
fn fmt_micros(us: u64) -> String {
    match us {
        us if us < 1_000 => format!("{us}µs"),
        us if us < 1_000_000 => format!("{}ms", us / 1_000),
        us => fmt_as_secs(us, 1_000_000),
    }
}

fn plural(n: u64, word: &str) -> String {
    match n {
        1 => word.to_string(),
        _ => format!("{word}s"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Two samples of a guest that burned a little cpu, wrote to its disk, moved some
    /// bytes over eth0 and stalled briefly on io — enough for every line of the report.
    fn log() -> String {
        let mut s = String::from("RESET\n");
        for (epoch, interval, idle, used_pages, sectors, bytes, utime) in [
            (1_000i64, 40u64, 760u64, 30_000u64, 40u64, 20_000u64, 120u64),
            (1_030, 30, 2_900, 50_000, 400, 5_000, 60),
            (1_060, 30, 1_500, 40_000, 0, 0, 20),
        ] {
            let h = |label: &str| {
                let (d, t) = vk_core::atop::date_time(epoch);
                format!("{label} runner {epoch} {d} {t} {interval}")
            };
            s.push_str(&format!(
                "{} 100 2 20 {utime} 0 {idle} 4 0 6 2 0 0 100 0 0\n",
                h("CPU")
            ));
            s.push_str(&format!(
                "{} 100 0 10 60 0 {idle} 2 0 3 1 0 0 100 0 0\n",
                h("cpu")
            ));
            s.push_str(&format!(
                "{} 100 1 10 {} 0 {} 2 0 3 1 0 0 100 0 0\n",
                h("cpu"),
                utime / 2,
                idle + utime / 2
            ));
            s.push_str(&format!("{} 2 0.50 0.25 0.10 4242 909\n", h("CPL")));
            s.push_str(&format!(
                "{} 4096 250000 {} 20000 500 3000 40 1500 0 700 0 0 2097152 0 0 0 0 0 0 0 250\n",
                h("MEM"),
                250_000 - used_pages - 22_000
            ));
            s.push_str(&format!("{} 4096 0 0 0 41026 126424 0 0 0\n", h("SWP")));
            s.push_str(&format!("{} 4096 0 3 0 0 1 -1 0 0 0 12 4\n", h("PAG")));
            s.push_str(&format!(
                "{} y 0.5 0.2 0.1 1000 0.0 0.0 0.0 0 0.0 0.0 0.0 0 1.5 0.4 0.2 4000 0.0 0.0 0.0 0\n",
                h("PSI")
            ));
            if sectors > 0 {
                s.push_str(&format!(
                    "{} vda 200 10 {sectors} 5 {sectors} -1 0 1 2.50\n",
                    h("DSK")
                ));
            }
            s.push_str(&format!(
                "{} upper 1 2 9 10 13 14 15 16 11 12 3 4 5 6 7 8\n",
                h("NET")
            ));
            s.push_str(&format!(
                "{} eth0 100 {bytes} 90 {bytes} 10000 1\n",
                h("NET")
            ));
            s.push_str(&format!("{} lo 4 4096 4 4096 0 0\n", h("NET")));
            s.push_str(&format!(
                "{} 412 (sh) S 1000 100 412 3 0 900 (sh -c make test) 1 1 2 0 1000 100 1000 100 1000 100 0 y 0 0 - N ()\n",
                h("PRG")
            ));
            s.push_str(&format!(
                "{} 412 (sh) S 100 {utime} 30 5 25 0 0 1 0 412 y 900 (do_wait) 0 -3 -3\n",
                h("PRC")
            ));
            s.push_str(&format!(
                "{} 412 (sh) S 4096 20000 {} 700 0 0 900 2 2400 1100 132 0 412 y 0 0 -3 -3 -3 -3\n",
                h("PRM"),
                used_pages / 2
            ));
            s.push_str(&format!(
                "{} 412 (sh) S n y 11 {sectors} 4 {sectors} 8 412 n y\n",
                h("PRD")
            ));
            s.push_str("SEP\n");
        }
        s
    }

    fn report(text: &str) -> String {
        let parsed = crate::atoplog::parse(text);
        summary(
            &PathBuf::from("/var/lib/virtkit/atop/2026-08-12/42137-acme-web-test_unit/atop.log"),
            None,
            &parsed,
        )
        .expect("a report for a log with samples")
    }

    /// The report is what an operator reads instead of the log, so every figure in it is
    /// checked against the samples behind it — and the table lines up.
    #[test]
    fn the_report_accounts_the_whole_job() {
        let text = log();
        let out = report(&text);
        println!("{out}");

        assert!(out.starts_with("virtkit: 42137-acme-web-test_unit — what its guest did:\n"));
        // 1970-01-01, three samples 30s apart, the last two paced at 30s.
        assert!(
            out.contains(
                "1970/01/01 00:16:40 → 00:17:40 UTC (1m00s), 3 samples at 30s, the first \
                 covering the guest's boot"
            ),
            "{out}"
        );
        assert!(
            out.contains("runner on 2 cpus, 977 MiB memory, no swap"),
            "{out}"
        );

        // cpu: busy ticks are everything but idle and iowait, summed over all three
        // samples — (20+120+0+4+0+6+2) + (20+60+…) + … at 100 Hz.
        assert!(out.contains("of cpu time"), "{out}");
        assert!(out.contains("user"), "{out}");
        assert!(
            out.contains("stolen by the host"),
            "steal was 2 ticks: {out}"
        );
        assert!(
            out.contains("waiting for disk"),
            "iowait was 6 ticks: {out}"
        );
        assert!(out.contains("% busy at peak"), "{out}");
        assert!(
            out.contains("cpu 0 busiest at"),
            "the first core did the work: {out}"
        );

        // memory: the peak of used pages, 50_000 * 4 KiB, and the cache beside it.
        assert!(
            out.contains("195 MiB held at peak (20% of the VM)"),
            "{out}"
        );
        assert!(out.contains("80 MiB of cache at peak"), "{out}");
        // Waiting for a disk is not one of the components of the cpu time above, so it sits
        // after them rather than inside the list that must add up to the headline figure.
        assert!(
            out.contains("stolen by the host; 0.1s waiting for disk"),
            "{out}"
        );
        // paging: three allocation stalls and one page swapped per sample, oom unknown.
        assert!(
            out.contains("9 allocation stalls, 3 pages swapped, - oom kills"),
            "{out}"
        );

        // pressure: 4ms of io stall per sample, worst avg10 1.5% — and cpu 1ms per sample.
        assert!(out.contains("cpu 3ms"), "{out}");
        // Equal readings across samples resolve to the first, which is when it started.
        assert!(out.contains("io 12ms, 1.5% at 00:16:40"), "{out}");

        // disk: 440 sectors read and written, of 512 bytes each, on vda.
        assert!(out.contains("220 KiB read, 220 KiB written"), "{out}");
        // two samples moved sectors, 200ms of io each; the third recorded no device
        assert!(out.contains("vda busiest, 400ms busy"), "{out}");
        // network: eth0 only — loopback is not the guest's traffic.
        assert!(out.contains("eth0 received 24 KiB, sent 24 KiB"), "{out}");
        assert!(!out.contains(" lo "), "loopback is left out: {out}");
        assert!(
            out.contains("5 tcp connections at peak, 18 segments resent"),
            "{out}"
        );

        // the shape of the job: one bar per paced sample
        let bars: Vec<&str> = out
            .lines()
            .filter_map(|l| l.trim().strip_prefix("cpu over time"))
            .collect();
        assert_eq!(bars.len(), 1, "{out}");
        assert_eq!(
            bars[0]
                .trim()
                .chars()
                .take_while(|c| BARS.contains(c))
                .count(),
            2,
            "two paced samples, two bars: {out}"
        );

        // the process table: one process, its whole-job cpu time and peak rss
        let table: Vec<&str> = out.lines().skip_while(|l| !l.contains("command")).collect();
        assert_eq!(table.len(), 2, "a heading and one process: {out}");
        assert!(table[0].contains("command") && table[0].contains("peak rss"));
        assert!(table[1].contains("sh -c make test"), "{table:?}");
        assert!(table[1].contains("412"), "{table:?}");
        // 30 ticks of system plus 200 of user over three samples, at 100 Hz
        assert!(table[1].contains("2.9s"), "{table:?}");
        // peak rss is the largest of 15000, 25000 and 20000 KiB
        assert!(table[1].contains("24 MiB"), "{table:?}");
        for line in &table {
            assert!(!line.ends_with(' '), "trailing whitespace: {line:?}");
        }
    }

    /// A burst of short-lived commands is one row of many runs, not many rows of one — which is
    /// the whole reason the kernel's exit records are read at all. A process a sweep did see
    /// keeps its own row, however many namesakes died around it.
    #[test]
    fn a_burst_of_short_commands_is_one_row() {
        let mut text = log();
        let sep = text.rfind("SEP\n").expect("a sample to add to");
        let mut burst = String::new();
        for pid in 500..515 {
            let h = |label: &str| format!("{label} runner 1060 1970/01/01 00:17:40 30");
            // twelve that returned, three that failed
            let status = match pid % 5 {
                0 => 2,
                _ => 0,
            };
            burst.push_str(&format!(
                "{} {pid} (cc1) E 0 0 {pid} 1 {status} 1059 (cc1) 412 0 0 0 0 0 0 0 0 0 10 y 0 0 - N ()\n",
                h("PRG")
            ));
            burst.push_str(&format!(
                "{} {pid} (cc1) E 100 10 5 0 0 0 0 -1 0 {pid} y 0 () 0 -3 -3\n",
                h("PRC")
            ));
            burst.push_str(&format!(
                "{} {pid} (cc1) E 4096 0 4096 0 0 0 30 0 0 0 0 0 {pid} y 0 0 -3 -3 -3 -3\n",
                h("PRM")
            ));
            burst.push_str(&format!(
                "{} {pid} (cc1) E n y 2 8 1 4 0 {pid} n y\n",
                h("PRD")
            ));
        }
        text.insert_str(sep, &burst);
        let out = report(&text);
        println!("{out}");

        let row = out
            .lines()
            .find(|l| l.contains("cc1"))
            .unwrap_or_default()
            .to_string();
        assert!(row.contains("cc1 ×15"), "one row for fifteen runs: {out}");
        assert!(
            out.contains("15 short-lived tasks came and went"),
            "the churn is reported whatever it ranks: {out}"
        );
        assert!(
            row.contains("(3 failed)"),
            "and the ones that failed: {row}"
        );
        assert!(row.contains(" - "), "a burst has no one pid to name: {row}");
        // fifteen runs of 15 ticks each at 100 Hz, and the peak of one of them
        assert!(row.contains("2.2s"), "their cpu time together: {row}");
        assert!(
            row.contains("4 MiB"),
            "the most any one of them held: {row}"
        );
        // fifteen runs of 8 sectors read and 4 written, at 512 bytes a sector
        assert!(
            row.contains("60 KiB") && row.contains("30 KiB"),
            "what they moved: {row}"
        );
        // The long-lived process is still its own row, not folded into anything.
        assert_eq!(
            out.lines()
                .filter(|l| l.contains("sh -c make test"))
                .count(),
            1,
            "{out}"
        );
        assert!(out.lines().any(|l| l.contains("cc1 ×15")), "{out}");
    }

    /// A log torn off mid-sample still reports what it has, and says that it was torn.
    #[test]
    fn a_torn_log_is_reported_as_far_as_it_goes() {
        let text = format!("{}CPU runner 1090 1970/01/01 00:18:10 30 100 2 1", log());
        let out = report(&text);
        assert!(out.contains("3 samples"), "{out}");
        assert!(out.contains("the log ends mid-sample"), "{out}");
    }

    /// A guest whose kernel has no pressure stall information says so rather than
    /// reporting an unpressured job.
    #[test]
    fn a_guest_without_pressure_says_so() {
        let text = log().replace(
            "y 0.5 0.2 0.1 1000 0.0 0.0 0.0 0 0.0 0.0 0.0 0 1.5 0.4 0.2 4000 0.0 0.0 0.0 0",
            "n 0.0 0.0 0.0 0 0.0 0.0 0.0 0 0.0 0.0 0.0 0 0.0 0.0 0.0 0 0.0 0.0 0.0 0",
        );
        let out = report(&text);
        assert!(out.contains("without pressure stall information"), "{out}");
    }

    /// A process whose disk traffic the kernel never accounted reports `-`, not zero: the
    /// two mean different things and a column of zeros would hide which.
    #[test]
    fn unaccounted_disk_traffic_reads_as_unmeasured() {
        let text = log().replace("(sh) S n y 11", "(sh) S n n 11");
        let out = report(&text);
        let row = out
            .lines()
            .find(|l| l.contains("sh -c make test"))
            .unwrap_or_default();
        assert!(row.ends_with('-'), "{row:?}");
    }

    /// A log with nothing complete in it has nothing to report — the caller says so rather
    /// than printing an empty account.
    #[test]
    fn a_log_with_no_whole_sample_has_no_report() {
        let text = "RESET\nCPU runner 1000 1970/01/01 00:16:40 40 100 2 1\n";
        let parsed = crate::atoplog::parse(text);
        assert!(summary(&PathBuf::from("atop.log"), None, &parsed).is_none());
    }

    /// The whole of `--summary` against a file on disk — and against the two things a job's
    /// own guest can leave where its log goes, since it had that directory read-write.
    #[test]
    fn summarize_reads_a_real_log_and_refuses_what_is_not_one() {
        let dir = std::env::temp_dir().join(format!("vk-atop-summarize-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("atop.log");
        std::fs::write(&path, log()).unwrap();
        let out = summarize(&path).expect("a report for a recorded job");
        assert!(out.contains("what its guest did"), "{out}");

        // A byte that is not text is damage, not a reason to refuse the whole account.
        let mut raw = log().into_bytes();
        raw.extend_from_slice(b"CPU runner 1090 1970/01/01 00:18:10 30 \xff\xfe 2 1\nSEP\n");
        std::fs::write(&path, &raw).unwrap();
        assert!(summarize(&path).is_ok(), "a damaged log still reports");

        // A symlink where the log goes is not opened, however readable its target: the path
        // is resolved by the kernel on the descriptor, not checked and re-opened.
        let elsewhere = dir.join("elsewhere.log");
        std::fs::write(&elsewhere, log()).unwrap();
        let planted = dir.join("planted.log");
        std::os::unix::fs::symlink(&elsewhere, &planted).unwrap();
        let e = summarize(&planted).expect_err("a symlink is not a recording");
        assert!(
            format!("{e:#}").contains(&planted.display().to_string()),
            "{e:#}"
        );
        // A directory is not one either.
        assert!(summarize(&dir).is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A guest writes its own tick counters and the `hertz` they are counted in, so the
    /// quotient can be a number no duration names. A report says something rather than
    /// panicking on one.
    #[test]
    fn an_absurd_tick_count_reports_rather_than_panics() {
        let huge = u64::MAX;
        let text = format!(
            "RESET\n\
             CPU runner 1000 1970/01/01 00:16:40 30 1 1 {huge} {huge} 0 0 0 0 0 0 0 0 100 0 0\n\
             PRG runner 1000 1970/01/01 00:16:40 30 7 (sh) S 0 0 7 1 0 900 (sh) 1 1 0 0 \
             0 0 0 0 0 0 0 y 0 0 - N ()\n\
             PRC runner 1000 1970/01/01 00:16:40 30 7 (sh) S 1 {huge} {huge} 0 20 0 0 0 0 7 \
             y 0 (-) 0 -3 -3\n\
             SEP\n\
             CPU runner 1030 1970/01/01 00:17:10 30 1 1 {huge} {huge} 0 0 0 0 0 0 0 0 100 0 0\n\
             SEP\n"
        );
        let parsed = crate::atoplog::parse(&text);
        let out = summary(&PathBuf::from("atop.log"), None, &parsed).expect("a report");
        assert!(out.contains("of cpu time"), "{out}");
    }

    /// A log with no pressure records at all says nothing about pressure — where a guest
    /// whose kernel reported "unsupported" says so, and the two must not be confused.
    #[test]
    fn a_log_with_no_pressure_records_says_nothing_about_it() {
        let text: String = log()
            .lines()
            .filter(|l| !l.starts_with("PSI "))
            .map(|l| format!("{l}\n"))
            .collect();
        let out = report(&text);
        assert!(!out.contains("pressure"), "{out}");
    }

    /// A log recorded once has no pace to report: the boot sample's interval column is the
    /// guest's uptime, so claiming it as the resolution would be a number nobody set.
    #[test]
    fn a_single_sample_log_claims_no_pace() {
        let text: String = log().split_inclusive("SEP\n").take(1).collect::<String>();
        let out = report(&text);
        assert!(
            out.contains("1 sample,"),
            "one sample, not '1 samples': {out}"
        );
        assert!(
            !out.contains(" at 40s"),
            "the boot interval is not a pace: {out}"
        );
    }

    /// More processes than the table lists: the heading says how many were left out, and the
    /// ones listed are the ones that used the most processor time.
    #[test]
    fn the_table_lists_the_busiest_processes_and_says_how_many_it_left_out() {
        let mut text = String::from("RESET\n");
        let (d, t) = vk_core::atop::date_time(1_000);
        for pid in 1..=TOP_PROCS + 5 {
            text.push_str(&format!(
                "PRC runner 1000 {d} {t} 30 {pid} (cmd{pid}) S 100 {pid} 0 0 20 0 0 0 0 {pid} \
                 y 0 (-) 0 -3 -3\n"
            ));
        }
        text.push_str("SEP\n");
        let out = report(&text);
        assert!(
            out.contains(&format!(
                "the {TOP_PROCS} of {} that used the most cpu",
                TOP_PROCS + 5
            )),
            "{out}"
        );
        // Ordered by cpu time, so the largest pid (the most ticks here) leads and the five
        // smallest are the ones left out.
        let listed: Vec<&str> = out
            .lines()
            .skip_while(|l| !l.contains("command"))
            .skip(1)
            .collect();
        assert_eq!(listed.len(), TOP_PROCS, "{out}");
        assert!(
            listed[0].contains(&format!("cmd{}", TOP_PROCS + 5)),
            "{out}"
        );
        assert!(!out.contains("cmd1 "), "the least busy are left out: {out}");
    }

    /// A command line long enough to push every figure off the screen is cut, so one process
    /// cannot destroy the table it is a row of.
    #[test]
    fn an_enormous_command_line_is_cut_to_the_column() {
        let long = "x".repeat(500);
        let text = log().replace("(sh -c make test)", &format!("(sh {long})"));
        let out = report(&text);
        let row = out
            .lines()
            .find(|l| l.contains("sh xxx"))
            .expect("the process row");
        assert!(row.contains('…'), "cut, and said to be: {row}");
        assert!(row.chars().count() < 200, "{}", row.chars().count());
    }

    /// The unit boundaries of each formatter, which every figure in the report goes through.
    #[test]
    fn the_formatters_turn_over_at_their_units() {
        assert_eq!(fmt_secs(0), "under a second");
        assert_eq!(fmt_secs(59), "59s");
        assert_eq!(fmt_secs(60), "1m00s");
        assert_eq!(fmt_secs(3_599), "59m59s");
        assert_eq!(fmt_secs(3_600), "1h00m");
        assert_eq!(fmt_millis(0), "0ms");
        assert_eq!(fmt_millis(999), "999ms");
        assert_eq!(fmt_millis(1_000), "1.0s");
        assert_eq!(fmt_micros(999), "999µs");
        assert_eq!(fmt_micros(1_000), "1ms");
        assert_eq!(fmt_micros(999_999), "999ms");
        assert_eq!(fmt_micros(1_000_000), "1.0s");
        assert_eq!(plural(1, "sample"), "sample");
        assert_eq!(plural(0, "sample"), "samples");
        assert_eq!(truncated("short", 10), "short");
        assert_eq!(truncated("abcdef", 4), "abc…");
    }
}
