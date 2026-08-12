//! Guest statistics in atop's parseable (`atop -P`) text format.
//!
//! The GitLab executor boots one microVM per CI job, so the guest *is* the job:
//! sampling `/proc` from inside it attributes every tick, page and byte to that one
//! job. `init` forks this sampler when the kernel cmdline carries
//! `VIRTKIT_ATOP=<tag>:<mountpoint>:<interval_secs>`; every interval it appends one
//! sample to `<mountpoint>/atop.log`, a read-write virtio-fs share landing in the
//! host's per-job archive. SIGUSR2 (atop's own kill signal) writes one last sample
//! and exits.
//!
//! **Every label's field order below is pinned to atop 2.8.1** — the release Debian 12
//! ships — and was derived from that version's `parseable.c` print functions. Each
//! emitter lists its fields in printed order, and `vk_core::atop` names the same fields
//! for the host that reads them back. A field a microVM guest cannot source
//! carries the value atop itself prints when it has no answer (CPU frequency 0 at
//! 100%, `-3` for cgroup-v2 maxima, `0` for the VMware balloon and PSS), never a
//! missing column: the format is positional and has no room for one.
//!
//! Each line starts with the six generic columns `<label> <host> <epoch> <YYYY/MM/DD>
//! <HH:MM:SS> <interval>`; a `SEP` line closes every sample, and a `RESET` line
//! precedes the first one — whose counters cover boot→now. Counter labels carry
//! per-interval differences, size labels the value as it stands.
//!
//! Emitted labels: CPU, cpu, CPL, MEM, SWP, PAG, PSI, DSK, NET (upper + per
//! interface), PRG, PRC, PRM, PRD. Not emitted: PRN (per-process network needs
//! netatop even for real atop), PRE/GPU, the NFS/InfiniBand/NUMA/LLC/LVM/MDD labels,
//! and exited processes (real atop takes those from process accounting; a `/proc`
//! sweep misses a task that starts and exits inside one interval).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use vk_core::atop::{LOG_NAME, PID_FILE, RESET, SEP, date_time, now_epoch};

/// Set by the SIGUSR2 handler: write one final sample, then exit.
static STOP: AtomicBool = AtomicBool::new(false);

/// The subcommand `init` forks and the host asks for a final sample through, as it appears
/// in the sampler's own argv — which is how a pid is confirmed to be the sampler.
const SUBCOMMAND: &str = "atop";

/// How `init` execs the sampler (see `fork_agent`), i.e. the sampler's own `argv[0]`.
const SELF_EXE: &str = "/proc/self/exe";

extern "C" fn handle_usr2(_sig: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

/// CLI entry for the sampler `init` forks (`vk-agent atop <dir> <interval_secs>`) and for
/// the host's end-of-job request for a final sample (`vk-agent atop --stop`). Errors go to
/// the console: a guest that cannot record stats still runs its job.
pub fn main(args: &[String]) -> i32 {
    if matches!(args, [flag] if flag == "--stop") {
        return stop();
    }
    let [dir, interval] = args else {
        eprintln!("usage: vk-agent atop <dir> <interval_secs> | vk-agent atop --stop");
        return 2;
    };
    let Some(interval) = interval.parse::<u64>().ok().filter(|i| *i > 0) else {
        eprintln!("vk-agent atop: interval {interval:?} is not a positive number of seconds");
        return 2;
    };
    let code = match run(Path::new(dir), Duration::from_secs(interval)) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("vk-agent atop: {e:#}");
            1
        }
    };
    // The pid file is this sampler's liveness, so it goes when the sampler does: nothing
    // left to signal, and no recycled pid to mistake for one that is still recording.
    let _ = std::fs::remove_file(PID_FILE);
    code
}

/// How long `--stop` waits for the final sample, and how often it looks. The host is
/// holding a job's last stage open for this, so it is short and it always ends.
const STOP_WAIT: Duration = Duration::from_secs(2);
const STOP_POLL: Duration = Duration::from_millis(50);

/// Ask the sampler for one last sample and wait for it to write it — what the host runs in
/// the guest at the end of a job, while the guest is still alive, so the log covers the job
/// to its end rather than to the last interval boundary before teardown.
///
/// Exits 0 whatever happens: a guest with no sampler running has nothing to stop, and no
/// part of this is worth failing a job's last stage over.
fn stop() -> i32 {
    let Some(pid) = sampler_pid() else {
        return 0;
    };
    // SAFETY: kill(2) only signals; a pid that has exited since it was confirmed fails
    // harmlessly, and the pid cannot be a process group (checked in `sampler_pid`).
    unsafe { libc::kill(pid, libc::SIGUSR2) };
    // The sampler unlinks its pid file after writing the final sample, so its absence is
    // the sample being on disk — not merely the process being gone.
    let deadline = Instant::now() + STOP_WAIT;
    while std::fs::exists(PID_FILE).unwrap_or(false) && Instant::now() < deadline {
        std::thread::sleep(STOP_POLL);
    }
    0
}

/// The running sampler's pid, or `None` when there is none to signal.
///
/// The pid comes from a file in a guest the job has had root over, so it is read as a
/// number and confirmed to belong to this agent's own sampler before anything is signalled:
/// a `-1` left in that file would otherwise send SIGUSR2 to every process in the guest.
fn sampler_pid() -> Option<libc::pid_t> {
    let pid: libc::pid_t = std::fs::read_to_string(PID_FILE)
        .ok()?
        .trim()
        .parse()
        .ok()?;
    // > 1: never a process group (`0`, `-1`, a negative pid), never init.
    if pid <= 1 {
        return None;
    }
    is_sampler(pid).then_some(pid)
}

/// Whether `pid` is this agent running as the sampler, from the argv the kernel keeps for
/// it: `/proc/self/exe atop <dir> <interval_secs>`.
fn is_sampler(pid: libc::pid_t) -> bool {
    let Ok(argv) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let mut argv = argv.split(|b| *b == 0);
    argv.next() == Some(SELF_EXE.as_bytes()) && argv.next() == Some(SUBCOMMAND.as_bytes())
}

/// Sample `/proc` every `interval` and append each sample to `<dir>/atop.log` until
/// SIGUSR2 asks for a final one.
fn run(dir: &Path, interval: Duration) -> Result<()> {
    let log = dir.join(LOG_NAME);
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
        .with_context(|| format!("opening {}", log.display()))?;
    // SAFETY: the handler only stores into an atomic (async-signal-safe).
    unsafe {
        libc::signal(
            libc::SIGUSR2,
            handle_usr2 as *const () as libc::sighandler_t,
        );
    }
    let env = Env::probe();
    eprintln!(
        "vk-agent atop: sampling every {}s -> {}",
        interval.as_secs(),
        log.display()
    );

    let mut prev: Option<Sys> = None;
    let mut failures: u64 = 0;
    // An absolute cadence: sleeping a whole interval *after* each collection would walk the
    // samples away from the wall clock the host's own atop keeps, and the two logs are read
    // side by side.
    let mut next = Instant::now() + interval;
    loop {
        let cur = snapshot(&env);
        let covered = match &prev {
            Some(p) => covered_secs(cur.epoch, p.epoch),
            None => uptime_secs().max(1),
        };
        // One buffer per sample: a VM torn down mid-write then truncates the tail of
        // one sample instead of interleaving two, and the file stays line-parseable.
        let text = sample_text(&env, &cur, prev.as_ref(), covered);
        match file.write_all(text.as_bytes()) {
            // `prev` advances only for a sample that reached the log, so a write that failed
            // leaves its interval to be covered by the next one that lands — counters and
            // `interval` column together — rather than dropping it. It also keeps `RESET`
            // owed until the first sample is actually on disk.
            Ok(()) => prev = Some(cur),
            Err(e) => {
                // Reported once. A share that cannot be written stays that way, and a line
                // per interval would crowd out the rest of a long job's console log.
                if failures == 0 {
                    eprintln!("vk-agent atop: writing {}: {e}", log.display());
                }
                failures += 1;
            }
        }
        if STOP.load(Ordering::Relaxed) {
            break; // the sample just written is the final one
        }
        // A collection that ran past its own interval skips ahead to the next one rather
        // than firing the samples it missed back to back.
        let now = Instant::now();
        while next <= now {
            next += interval;
        }
        wait_until(next);
    }
    if failures > 1 {
        eprintln!(
            "vk-agent atop: {failures} samples could not be written to {}",
            log.display()
        );
    }
    Ok(())
}

/// One sample as it goes to the log: the `RESET` line when there is nothing to deviate
/// from — its counters cover the guest's whole boot — the records themselves, then the
/// `SEP` line that marks the sample complete.
fn sample_text(env: &Env, cur: &Sys, prev: Option<&Sys>, covered: u64) -> String {
    let mut buf = String::with_capacity(64 * 1024);
    if prev.is_none() {
        buf.push_str(RESET);
        buf.push('\n');
    }
    write_sample(&mut buf, env, &deviate(cur, prev), covered);
    buf.push_str(SEP);
    buf.push('\n');
    buf
}

/// The seconds a sample covers (atop's `numsecs`), from the two sample times. Never zero,
/// however soon after the last sample a final one is asked for: this column is the divisor
/// of every rate a reader computes from the counters beside it.
fn covered_secs(now: i64, before: i64) -> u64 {
    (now.saturating_sub(before).max(0) as u64).max(1)
}

/// How long one sleep runs before the stop flag is read again. SIGUSR2 that lands between
/// the flag check and the sleep interrupts nothing — the handler has already run — so the
/// wait is sliced, which bounds that miss to one slice instead of one whole interval. The
/// host waits seconds for the final sample, so a slice this size is never noticed.
const SLEEP_SLICE: Duration = Duration::from_millis(250);

/// Sleep until `deadline`, returning early once SIGUSR2 has been seen.
fn wait_until(deadline: Instant) {
    while !STOP.load(Ordering::Relaxed) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        nap(left.min(SLEEP_SLICE));
    }
}

/// Sleep `dur`. A signal that cuts it short is not resumed: the caller sleeps towards a
/// deadline, so an early return costs one flag check and nothing else.
fn nap(dur: Duration) {
    let req = libc::timespec {
        // clamped so the cast holds on every target's timespec, which no sampling
        // interval comes near anyway
        tv_sec: dur.as_secs().min(i32::MAX as u64) as _,
        tv_nsec: dur.subsec_nanos() as _,
    };
    // SAFETY: the request is valid and caller-owned; nanosleep accepts a null remainder.
    unsafe { libc::nanosleep(&req, std::ptr::null_mut()) };
}

/// What every sample repeats: the reporting host and the two system constants the
/// counters are scaled by.
struct Env {
    host: String,
    hertz: u64,
    pagesize: u64,
    /// Whether `/proc/<pid>/io` can be read — atop's IOSTAT support flag, which the
    /// PRD label carries because its counters mean nothing without it.
    io_stats: bool,
}

impl Env {
    fn probe() -> Env {
        Env {
            // The first whitespace-delimited token: this goes into a record unparenthesised,
            // so a hostname holding a space would add a cell and break the record's arity.
            host: std::fs::read_to_string("/proc/sys/kernel/hostname")
                .ok()
                .and_then(|h| h.split_whitespace().next().map(str::to_string))
                .unwrap_or_else(|| "localhost".into()),
            hertz: sysconf(libc::_SC_CLK_TCK, 100),
            pagesize: sysconf(libc::_SC_PAGESIZE, 4096),
            io_stats: std::fs::read_to_string("/proc/self/io").is_ok(),
        }
    }
}

fn sysconf(name: libc::c_int, fallback: u64) -> u64 {
    // SAFETY: sysconf only reads a static system parameter.
    let v = unsafe { libc::sysconf(name) };
    if v > 0 { v as u64 } else { fallback }
}

// ---------------------------------------------------------------------------
// The snapshot: everything one sample prints, plus what the next sample's
// differences are computed against.
// ---------------------------------------------------------------------------

/// One CPU's tick counters, named as atop names them (`/proc/stat` order differs from
/// the printed order).
#[derive(Clone, Default)]
struct Cpu {
    /// The processor's own number, not its position in `/proc/stat` — which leaves an
    /// offline processor out, so the two part company as soon as one goes down.
    id: usize,
    utime: u64,
    ntime: u64,
    stime: u64,
    itime: u64,
    wtime: u64,
    irq: u64,
    softirq: u64,
    steal: u64,
    guest: u64,
}

/// Memory sizes, in pages except where noted — the unit atop's MEM/SWP labels print
/// (the page size is a column of each).
#[derive(Clone, Default)]
struct Mem {
    physmem: u64,
    freemem: u64,
    cachemem: u64,
    buffermem: u64,
    slabmem: u64,
    cachedrt: u64,
    slabreclaim: u64,
    shmem: u64,
    pagetables: u64,
    tcpsock: u64,
    udpsock: u64,
    /// bytes
    hugepagesz: u64,
    /// huge pages, not pages
    tothugepage: u64,
    freehugepage: u64,
    totswap: u64,
    freeswap: u64,
    swapcached: u64,
    committed: u64,
    commitlim: u64,
    zswstored: u64,
    zswtotpool: u64,
}

/// Paging/swap event counters (`/proc/vmstat`), all per-interval differences.
#[derive(Clone, Default)]
struct Pag {
    pgscans: u64,
    allocstall: u64,
    swins: u64,
    swouts: u64,
    /// `-1` where the kernel has no counter, which atop prints as such
    oomkills: i64,
    compactstall: u64,
    pgmigrate: u64,
    numamigrate: u64,
    pgins: u64,
    pgouts: u64,
}

/// One pressure-stall line: three averages as they stand, plus a total whose
/// difference is the microseconds stalled during the interval.
#[derive(Clone, Default)]
struct PsiLine {
    avg10: f64,
    avg60: f64,
    avg300: f64,
    total: u64,
}

#[derive(Clone, Default)]
struct Psi {
    present: bool,
    cpusome: PsiLine,
    memsome: PsiLine,
    memfull: PsiLine,
    iosome: PsiLine,
    iofull: PsiLine,
}

/// One whole disk (`/proc/diskstats`); counters are per-interval differences,
/// `inflight` the queue as it stands.
#[derive(Clone, Default)]
struct Disk {
    name: String,
    io_ms: u64,
    nread: u64,
    nrsect: u64,
    nwrite: u64,
    nwsect: u64,
    /// `-1` on a kernel whose diskstats have no discard columns
    ndisc: i64,
    ndsect: u64,
    inflight: u64,
    /// weighted time in the queue, the numerator of the printed average depth
    avque: u64,
}

impl Disk {
    /// Whether this device did anything over the interval, or has a request outstanding.
    fn busy(&self) -> bool {
        self.nread != 0
            || self.nwrite != 0
            || self.ndsect != 0
            || self.io_ms != 0
            || self.inflight != 0
    }
}

#[derive(Clone, Default)]
struct Iface {
    name: String,
    rpack: u64,
    rbyte: u64,
    spack: u64,
    sbyte: u64,
    speed: i64,
    duplex: i32,
}

/// The upper-layer protocol counters of NET, summed over IPv4 and IPv6 as atop sums
/// them. All differences but `tcp_currestab`, which is a current count.
#[derive(Clone, Default)]
struct NetProto {
    tcp_insegs: u64,
    tcp_outsegs: u64,
    tcp_activeopens: u64,
    tcp_passiveopens: u64,
    tcp_currestab: u64,
    tcp_retranssegs: u64,
    tcp_inerrs: u64,
    tcp_outrsts: u64,
    udp_indatagrams: u64,
    udp_outdatagrams: u64,
    udp_inerrors: u64,
    udp_noports: u64,
    ip_inreceives: u64,
    ip_outrequests: u64,
    ip_indelivers: u64,
    ip_forwdatagrams: u64,
}

/// One process. Task-level counters (CPU time, faults, delays, disk) are
/// per-interval differences; sizes and identity are as they stand.
#[derive(Clone, Default)]
struct Proc {
    pid: i32,
    tgid: i32,
    ppid: i32,
    name: String,
    state: char,
    cmdline: String,
    /// real, effective, saved and filesystem ids, in `/proc/<pid>/status` order
    uids: [u32; 4],
    gids: [u32; 4],
    nthr: u64,
    nthrrun: u64,
    nthrslpi: u64,
    nthrslpu: u64,
    /// start time (epoch seconds)
    btime: i64,
    /// absent from the previous snapshot — atop's 'N' marker
    is_new: bool,
    utime: u64,
    stime: u64,
    nice: i64,
    prio: i64,
    rtprio: u64,
    policy: u64,
    curcpu: i64,
    /// runqueue wait, nanoseconds
    rundelay: u64,
    /// block I/O delay, clock ticks
    blkdelay: u64,
    wchan: String,
    // memory, KiB
    vmem: u64,
    rmem: u64,
    vexec: u64,
    vlibs: u64,
    vdata: u64,
    vstack: u64,
    vswap: u64,
    vlock: u64,
    vgrow: i64,
    rgrow: i64,
    minflt: u64,
    majflt: u64,
    // disk: syscall counts and 512-byte sectors
    rio: u64,
    rsz: u64,
    wio: u64,
    wsz: u64,
    cwsz: u64,
}

#[derive(Clone, Default)]
struct Sys {
    epoch: i64,
    cpu: Cpu,
    cpus: Vec<Cpu>,
    csw: u64,
    devint: u64,
    lavg: [f64; 3],
    mem: Mem,
    pag: Pag,
    psi: Psi,
    disks: Vec<Disk>,
    ifaces: Vec<Iface>,
    net: NetProto,
    procs: Vec<Proc>,
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

/// Read every source one sample needs. Best effort throughout: a source this kernel
/// does not carry leaves its fields at the value atop prints for "no answer", so a
/// sample is always complete.
fn snapshot(env: &Env) -> Sys {
    let mut s = Sys {
        epoch: now_epoch(),
        ..Default::default()
    };
    let boot = parse_stat(&read("/proc/stat"), &mut s);
    parse_loadavg(&read("/proc/loadavg"), &mut s);
    parse_meminfo(&read("/proc/meminfo"), &mut s, env.pagesize);
    parse_sockstat(&read("/proc/net/sockstat"), &mut s);
    parse_vmstat(&read("/proc/vmstat"), &mut s);
    s.psi = parse_psi(
        &read("/proc/pressure/cpu"),
        &read("/proc/pressure/memory"),
        &read("/proc/pressure/io"),
    );
    // A name in `/proc/diskstats` is a whole disk when `/sys/block` carries it; a partition
    // is under its own disk there and so is not counted twice.
    parse_diskstats(&read("/proc/diskstats"), &mut s, |name| {
        Path::new("/sys/block").join(name).exists()
    });
    // A virtual NIC reports neither, so both come from sysfs where they exist at all.
    parse_netdev(&read("/proc/net/dev"), &mut s, |name| {
        let at = |file: &str| read_trim(format!("/sys/class/net/{name}/{file}"));
        (
            at("speed").parse().unwrap_or(0).max(0),
            match at("duplex").as_str() {
                "full" => 1,
                _ => 0,
            },
        )
    });
    s.net = parse_snmp(&read("/proc/net/snmp"), &read("/proc/net/snmp6"));
    s.procs = read_procs(env, boot);
    s
}

/// Seconds since boot, which is what the first sample covers.
fn uptime_secs() -> u64 {
    read("/proc/uptime")
        .split_whitespace()
        .next()
        .and_then(|s| s.split('.').next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn read(path: impl AsRef<Path>) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// A `/proc` or `/sys` file holding one value on one line.
fn read_trim(path: impl AsRef<Path>) -> String {
    read(path).trim().to_string()
}

/// A `/proc` file carrying bytes the kernel took from userspace — a task's `comm` or its
/// command line — read with those bytes replaced rather than refused: a process whose name
/// is not UTF-8 must appear in the sample, not disappear from it.
fn read_lossy(path: impl AsRef<Path>) -> Option<String> {
    Some(String::from_utf8_lossy(&std::fs::read(path).ok()?).into_owned())
}

fn num<T: std::str::FromStr + Default>(v: Option<&str>) -> T {
    v.and_then(|v| v.parse().ok()).unwrap_or_default()
}

/// `/proc/stat`: the CPU tick counters, context switches and device interrupts.
/// Returns the boot time, from which a task's start time becomes an epoch.
fn parse_stat(text: &str, s: &mut Sys) -> i64 {
    let mut boot = 0;
    for line in text.lines() {
        let mut f = line.split_whitespace();
        let Some(key) = f.next() else {
            continue;
        };
        match key {
            "cpu" => s.cpu = cpu_ticks(f),
            "ctxt" => s.csw = num(f.next()),
            "btime" => boot = num(f.next()),
            // the first value is the total across all interrupt sources
            "intr" => s.devint = num(f.next()),
            // `cpuN`, carrying the processor's own number: an offline processor has no line
            // here at all, so counting the lines off would misname every one after it.
            k => {
                if let Some(id) = k.strip_prefix("cpu").and_then(|n| n.parse().ok()) {
                    s.cpus.push(Cpu { id, ..cpu_ticks(f) });
                }
            }
        }
    }
    boot
}

/// The nine counters atop reads from a `/proc/stat` cpu line, in that file's order. The
/// processor number is the caller's: the `cpu` total line has none.
fn cpu_ticks<'a>(mut f: impl Iterator<Item = &'a str>) -> Cpu {
    Cpu {
        id: 0,
        utime: num(f.next()),
        ntime: num(f.next()),
        stime: num(f.next()),
        itime: num(f.next()),
        wtime: num(f.next()),
        irq: num(f.next()),
        softirq: num(f.next()),
        steal: num(f.next()),
        guest: num(f.next()),
    }
}

fn parse_loadavg(text: &str, s: &mut Sys) {
    let mut f = text.split_whitespace();
    s.lavg = [num(f.next()), num(f.next()), num(f.next())];
}

/// `/proc/meminfo`, whose kB sizes become the pages MEM and SWP print.
fn parse_meminfo(text: &str, s: &mut Sys, pagesize: u64) {
    let mut kb: HashMap<&str, u64> = HashMap::new();
    for line in text.lines() {
        if let Some((key, rest)) = line.split_once(':') {
            kb.insert(key, num(rest.split_whitespace().next()));
        }
    }
    let pages = |key: &str| kb.get(key).copied().unwrap_or(0) * 1024 / pagesize.max(1);
    let count = |key: &str| kb.get(key).copied().unwrap_or(0);
    s.mem = Mem {
        physmem: pages("MemTotal"),
        freemem: pages("MemFree"),
        cachemem: pages("Cached"),
        buffermem: pages("Buffers"),
        slabmem: pages("Slab"),
        cachedrt: pages("Dirty"),
        slabreclaim: pages("SReclaimable"),
        shmem: pages("Shmem"),
        pagetables: pages("PageTables"),
        // filled from /proc/net/sockstat, which counts them in pages already
        tcpsock: 0,
        udpsock: 0,
        hugepagesz: count("Hugepagesize") * 1024,
        tothugepage: count("HugePages_Total"),
        freehugepage: count("HugePages_Free"),
        totswap: pages("SwapTotal"),
        freeswap: pages("SwapFree"),
        swapcached: pages("SwapCached"),
        committed: pages("Committed_AS"),
        commitlim: pages("CommitLimit"),
        zswstored: pages("Zswapped"),
        zswtotpool: pages("Zswap"),
    };
}

/// `/proc/net/sockstat`: the socket memory MEM reports, already counted in pages.
fn parse_sockstat(text: &str, s: &mut Sys) {
    for line in text.lines() {
        let mut f = line.split_whitespace();
        let proto = f.next();
        if !matches!(proto, Some("TCP:") | Some("UDP:")) {
            continue;
        }
        // `mem <pages>` among the line's key/value pairs
        let mut mem = 0;
        while let Some(key) = f.next() {
            if key == "mem" {
                mem = num(f.next());
                break;
            }
        }
        match proto {
            Some("TCP:") => s.mem.tcpsock = mem,
            _ => s.mem.udpsock = mem,
        }
    }
}

/// `/proc/vmstat`: the PAG counters. The scan and stall counters are per-zone or
/// per-reclaim-path families, so they are summed over their whole prefix.
fn parse_vmstat(text: &str, s: &mut Sys) {
    let mut v: HashMap<&str, u64> = HashMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(' ') {
            v.insert(key, num(Some(value.trim())));
        }
    }
    let get = |key: &str| v.get(key).copied().unwrap_or(0);
    let sum = |prefix: &str| -> u64 {
        v.iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(_, n)| *n)
            .sum()
    };
    s.pag = Pag {
        // `pgscan_direct_throttle` shares the prefix but counts throttling events rather
        // than pages, so it is not one of the family that sums into a page count.
        pgscans: (sum("pgscan_kswapd") + sum("pgscan_direct"))
            .saturating_sub(get("pgscan_direct_throttle")),
        allocstall: sum("allocstall"),
        swins: get("pswpin"),
        swouts: get("pswpout"),
        oomkills: match v.get("oom_kill") {
            Some(n) => *n as i64,
            None => -1,
        },
        compactstall: get("compact_stall"),
        pgmigrate: get("pgmigrate_success"),
        numamigrate: get("numa_pages_migrated"),
        pgins: get("pgpgin"),
        pgouts: get("pgpgout"),
    };
}

/// `/proc/pressure/*`. Absent (a kernel without `psi=1`) leaves the label's
/// "present" column at `n` and every figure zero — the form atop prints on such a
/// host.
fn parse_psi(cpu: &str, mem: &str, io: &str) -> Psi {
    if cpu.is_empty() {
        return Psi::default();
    }
    Psi {
        present: true,
        cpusome: psi_line(cpu, "some"),
        memsome: psi_line(mem, "some"),
        memfull: psi_line(mem, "full"),
        iosome: psi_line(io, "some"),
        iofull: psi_line(io, "full"),
    }
}

/// One `some`/`full` line of a pressure file: `some avg10=0.00 avg60=0.00
/// avg300=0.00 total=0`.
fn psi_line(text: &str, kind: &str) -> PsiLine {
    let Some(line) = text.lines().find(|l| l.starts_with(kind)) else {
        return PsiLine::default();
    };
    let mut p = PsiLine::default();
    for field in line.split_whitespace().skip(1) {
        let Some((key, value)) = field.split_once('=') else {
            continue;
        };
        match key {
            "avg10" => p.avg10 = num(Some(value)),
            "avg60" => p.avg60 = num(Some(value)),
            "avg300" => p.avg300 = num(Some(value)),
            "total" => p.total = num(Some(value)),
            _ => {}
        }
    }
    p
}

/// `/proc/diskstats`, whole disks only — `is_disk` decides which names those are (an entry
/// under `/sys/block` on a live kernel, a fixture's own list in a test). A partition, or a
/// name that is no plain path component, is not one.
fn parse_diskstats(text: &str, s: &mut Sys, is_disk: impl Fn(&str) -> bool) {
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        // major minor name, then the per-request counters
        let Some(name) = f.get(2) else {
            continue;
        };
        if name.contains('/') || !is_disk(name) {
            continue;
        }
        let at = |i: usize| -> u64 { num(f.get(i).copied()) };
        s.disks.push(Disk {
            name: (*name).to_string(),
            nread: at(3),
            nrsect: at(5),
            nwrite: at(7),
            nwsect: at(9),
            inflight: at(11),
            io_ms: at(12),
            avque: at(13),
            // discards were added later; a kernel without them has no such columns
            ndisc: match f.get(14) {
                Some(v) => num(Some(*v)),
                None => -1,
            },
            ndsect: at(16),
        });
    }
}

/// `/proc/net/dev` for the per-interface counters; `link` answers with the interface's
/// speed in Mbit/s and whether it is full duplex, which the file itself does not carry.
fn parse_netdev(text: &str, s: &mut Sys, link: impl Fn(&str) -> (i64, i32)) {
    for line in text.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue; // the two header lines
        };
        let name = name.trim();
        if name.is_empty() || name.contains('/') {
            continue;
        }
        let f: Vec<&str> = rest.split_whitespace().collect();
        let at = |i: usize| -> u64 { num(f.get(i).copied()) };
        let (speed, duplex) = link(name);
        s.ifaces.push(Iface {
            name: name.to_string(),
            rbyte: at(0),
            rpack: at(1),
            sbyte: at(8),
            spack: at(9),
            speed,
            duplex,
        });
    }
}

/// `/proc/net/snmp` (+ `snmp6`): the IP/TCP/UDP counters NET's `upper` line carries,
/// IPv4 and IPv6 summed as atop sums them.
fn parse_snmp(snmp: &str, snmp6: &str) -> NetProto {
    let v4 = snmp_counters(snmp);
    let v6 = snmp6_counters(snmp6);
    let g4 = |proto: &str, name: &str| v4.get(&(proto, name)).copied().unwrap_or(0);
    let g6 = |name: &str| v6.get(name).copied().unwrap_or(0);
    NetProto {
        tcp_insegs: g4("Tcp", "InSegs"),
        tcp_outsegs: g4("Tcp", "OutSegs"),
        tcp_activeopens: g4("Tcp", "ActiveOpens"),
        tcp_passiveopens: g4("Tcp", "PassiveOpens"),
        tcp_currestab: g4("Tcp", "CurrEstab"),
        tcp_retranssegs: g4("Tcp", "RetransSegs"),
        tcp_inerrs: g4("Tcp", "InErrs"),
        tcp_outrsts: g4("Tcp", "OutRsts"),
        udp_indatagrams: g4("Udp", "InDatagrams") + g6("Udp6InDatagrams"),
        udp_outdatagrams: g4("Udp", "OutDatagrams") + g6("Udp6OutDatagrams"),
        udp_inerrors: g4("Udp", "InErrors") + g6("Udp6InErrors"),
        udp_noports: g4("Udp", "NoPorts") + g6("Udp6NoPorts"),
        ip_inreceives: g4("Ip", "InReceives") + g6("Ip6InReceives"),
        ip_outrequests: g4("Ip", "OutRequests") + g6("Ip6OutRequests"),
        ip_indelivers: g4("Ip", "InDelivers") + g6("Ip6InDelivers"),
        ip_forwdatagrams: g4("Ip", "ForwDatagrams") + g6("Ip6OutForwDatagrams"),
    }
}

/// `/proc/net/snmp`, keyed by protocol and counter name. Each protocol comes as a header
/// line of names followed by a line of values, both starting with the protocol's own name —
/// which is what the two are paired on. Taking the lines two at a time instead would let a
/// single unexpected line shift every counter after it onto the wrong name.
fn snmp_counters(text: &str) -> HashMap<(&str, &str), u64> {
    let mut out = HashMap::new();
    let mut pending: HashMap<&str, Vec<&str>> = HashMap::new();
    for line in text.lines() {
        let Some((proto, rest)) = line.split_once(':') else {
            continue;
        };
        match pending.remove(proto) {
            // The names this protocol announced, in the order its values arrive.
            Some(names) => {
                for (name, value) in names.into_iter().zip(rest.split_whitespace()) {
                    out.insert((proto, name), num(Some(value)));
                }
            }
            None => {
                pending.insert(proto, rest.split_whitespace().collect());
            }
        }
    }
    out
}

/// `/proc/net/snmp6`, one `<name> <value>` per line — the counter names already carry the
/// protocol, so there is nothing to pair.
fn snmp6_counters(text: &str) -> HashMap<&str, u64> {
    text.lines()
        .filter_map(|line| {
            let mut f = line.split_whitespace();
            Some((f.next()?, num(f.next())))
        })
        .collect()
}

/// Every process in `/proc` (processes, not threads: a thread's counters are already
/// in its process's). A task that exits while being read is skipped.
fn read_procs(env: &Env, boot: i64) -> Vec<Proc> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut procs = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<i32>().ok())
        else {
            continue;
        };
        if let Some(p) = read_proc(&entry.path(), pid, env, boot) {
            procs.push(p);
        }
    }
    procs.sort_by_key(|p| p.pid);
    procs
}

fn read_proc(dir: &Path, pid: i32, env: &Env, boot: i64) -> Option<Proc> {
    let mut p = parse_proc_stat(&read_lossy(dir.join("stat"))?, pid, env, boot)?;
    p.cmdline = cmdline(dir);
    p.wchan = read_trim(dir.join("wchan"));
    if let Some(status) = read_lossy(dir.join("status")) {
        parse_proc_status(&status, &mut p);
    }
    read_proc_threads(dir, &mut p);
    p.rundelay = parse_schedstat(&read(dir.join("schedstat")));
    parse_proc_io(&read(dir.join("io")), &mut p);
    Some(p)
}

/// Which cell of a `/proc/<pid>/stat` tail is which. The tail begins after the command,
/// i.e. at field 3 (state) of the file's own numbering, so field N is at N - [`FIRST`].
const FIRST: usize = 3;

/// `/proc/<pid>/stat`: identity, scheduling and the sizes and counters the file carries.
/// `None` when the line is not a stat line at all (no command in parentheses).
fn parse_proc_stat(stat: &str, pid: i32, env: &Env, boot: i64) -> Option<Proc> {
    // The command holds anything, parentheses and spaces included, so the fields
    // after it are read from beyond its closing parenthesis.
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let name = stat.get(open + 1..close)?.to_string();
    let f: Vec<&str> = stat.get(close + 1..)?.split_whitespace().collect();
    let at = |field: usize| -> u64 { num(f.get(field.saturating_sub(FIRST)).copied()) };
    let signed = |field: usize| -> i64 { num(f.get(field.saturating_sub(FIRST)).copied()) };
    Some(Proc {
        pid,
        name,
        state: f.first().and_then(|s| s.chars().next()).unwrap_or('?'),
        ppid: signed(4) as i32,
        minflt: at(10),
        majflt: at(12),
        utime: at(14),
        stime: at(15),
        prio: signed(18),
        nice: signed(19),
        nthr: at(20),
        btime: boot.saturating_add((at(22) / env.hertz.max(1)) as i64),
        vmem: at(23) / 1024,
        rmem: at(24) * env.pagesize / 1024,
        curcpu: signed(39),
        rtprio: at(40),
        policy: at(41),
        blkdelay: at(42),
        ..Default::default()
    })
}

/// The command line as one string; a kernel thread has none, which atop prints as an
/// empty field.
fn cmdline(dir: &Path) -> String {
    let Some(text) = read_lossy(dir.join("cmdline")) else {
        return String::new();
    };
    let text: String = text
        .chars()
        .map(|c| if c == '\0' { ' ' } else { c })
        .collect();
    text.trim().to_string()
}

/// `/proc/<pid>/status`: the four ids of each kind, the thread group, and the memory
/// sizes `stat` does not carry.
fn parse_proc_status(text: &str, p: &mut Proc) {
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let mut f = rest.split_whitespace();
        let first = || -> u64 { num(rest.split_whitespace().next()) };
        match key {
            "Tgid" => p.tgid = first() as i32,
            "Uid" => {
                for slot in p.uids.iter_mut() {
                    *slot = num(f.next());
                }
            }
            "Gid" => {
                for slot in p.gids.iter_mut() {
                    *slot = num(f.next());
                }
            }
            "VmExe" => p.vexec = first(),
            "VmLib" => p.vlibs = first(),
            "VmData" => p.vdata = first(),
            "VmStk" => p.vstack = first(),
            "VmSwap" => p.vswap = first(),
            "VmLck" => p.vlock = first(),
            _ => {}
        }
    }
}

/// The per-state thread counts PRG reports, from the states of the process's own
/// tasks (`/proc/<pid>/task/*/stat`). atop counts running, interruptible-sleeping and
/// uninterruptible-sleeping threads; any other state is in the total only.
fn read_proc_threads(dir: &Path, p: &mut Proc) {
    let Ok(tasks) = std::fs::read_dir(dir.join("task")) else {
        return;
    };
    for task in tasks.flatten() {
        let Ok(stat) = std::fs::read_to_string(task.path().join("stat")) else {
            continue;
        };
        let state = stat
            .rfind(')')
            .and_then(|close| stat.get(close + 1..))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|s| s.chars().next());
        match state {
            Some('R') => p.nthrrun += 1,
            Some('S') => p.nthrslpi += 1,
            Some('D') => p.nthrslpu += 1,
            _ => {}
        }
    }
}

/// `/proc/<pid>/schedstat`: `<runtime> <waittime> <timeslices>`, whose wait time is
/// the runqueue delay PRC reports.
fn parse_schedstat(text: &str) -> u64 {
    num(text.split_whitespace().nth(1))
}

/// `/proc/<pid>/io`: the syscall counts and byte totals PRD reports as reads, writes
/// and sectors. Absent (or unreadable) leaves them zero, which the label's own
/// "standard io statistics" column already says to disregard.
fn parse_proc_io(text: &str, p: &mut Proc) {
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let n: u64 = num(value.split_whitespace().next());
        match key {
            "syscr" => p.rio = n,
            "syscw" => p.wio = n,
            "read_bytes" => p.rsz = n / 512,
            "write_bytes" => p.wsz = n / 512,
            "cancelled_write_bytes" => p.cwsz = n / 512,
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Differences
// ---------------------------------------------------------------------------

/// What one sample prints: `cur` where atop reports a value as it stands (memory
/// sizes, load average, PSI averages, established connections, queue depth), and
/// `cur - prev` where it reports a per-interval difference. Without a previous
/// snapshot every counter already covers boot→now, which is the sample the `RESET`
/// line announces.
fn deviate(cur: &Sys, prev: Option<&Sys>) -> Sys {
    let mut d = cur.clone();
    let Some(p) = prev else {
        for proc in &mut d.procs {
            proc.is_new = true;
            proc.vgrow = proc.vmem as i64;
            proc.rgrow = proc.rmem as i64;
        }
        return d;
    };
    d.cpu = cpu_delta(&cur.cpu, &p.cpu);
    // Paired by processor number: a processor that went offline between the two samples
    // leaves the file, and pairing by position would deviate every one after it against
    // its neighbour's counters. A processor with nothing to pair against came online during
    // the interval, and its counters run from the guest's boot — reported as one interval's
    // worth they would be a spike it never had, so it starts from nothing instead.
    for c in d.cpus.iter_mut() {
        *c = match p.cpus.iter().find(|q| q.id == c.id) {
            Some(q) => cpu_delta(c, q),
            None => Cpu {
                id: c.id,
                ..Default::default()
            },
        };
    }
    d.csw = sub(cur.csw, p.csw);
    d.devint = sub(cur.devint, p.devint);
    d.pag = Pag {
        pgscans: sub(cur.pag.pgscans, p.pag.pgscans),
        allocstall: sub(cur.pag.allocstall, p.pag.allocstall),
        swins: sub(cur.pag.swins, p.pag.swins),
        swouts: sub(cur.pag.swouts, p.pag.swouts),
        oomkills: match (cur.pag.oomkills, p.pag.oomkills) {
            (c, q) if c < 0 || q < 0 => -1,
            (c, q) => c.saturating_sub(q),
        },
        compactstall: sub(cur.pag.compactstall, p.pag.compactstall),
        pgmigrate: sub(cur.pag.pgmigrate, p.pag.pgmigrate),
        numamigrate: sub(cur.pag.numamigrate, p.pag.numamigrate),
        pgins: sub(cur.pag.pgins, p.pag.pgins),
        pgouts: sub(cur.pag.pgouts, p.pag.pgouts),
    };
    d.psi.cpusome.total = sub(cur.psi.cpusome.total, p.psi.cpusome.total);
    d.psi.memsome.total = sub(cur.psi.memsome.total, p.psi.memsome.total);
    d.psi.memfull.total = sub(cur.psi.memfull.total, p.psi.memfull.total);
    d.psi.iosome.total = sub(cur.psi.iosome.total, p.psi.iosome.total);
    d.psi.iofull.total = sub(cur.psi.iofull.total, p.psi.iofull.total);
    for disk in &mut d.disks {
        let Some(q) = p.disks.iter().find(|q| q.name == disk.name) else {
            continue;
        };
        disk.io_ms = sub(disk.io_ms, q.io_ms);
        disk.nread = sub(disk.nread, q.nread);
        disk.nrsect = sub(disk.nrsect, q.nrsect);
        disk.nwrite = sub(disk.nwrite, q.nwrite);
        disk.nwsect = sub(disk.nwsect, q.nwsect);
        disk.ndsect = sub(disk.ndsect, q.ndsect);
        disk.avque = sub(disk.avque, q.avque);
        if disk.ndisc >= 0 && q.ndisc >= 0 {
            disk.ndisc = disk.ndisc.saturating_sub(q.ndisc);
        }
    }
    for iface in &mut d.ifaces {
        let Some(q) = p.ifaces.iter().find(|q| q.name == iface.name) else {
            continue;
        };
        iface.rpack = sub(iface.rpack, q.rpack);
        iface.rbyte = sub(iface.rbyte, q.rbyte);
        iface.spack = sub(iface.spack, q.spack);
        iface.sbyte = sub(iface.sbyte, q.sbyte);
    }
    let n = &cur.net;
    let q = &p.net;
    d.net = NetProto {
        tcp_insegs: sub(n.tcp_insegs, q.tcp_insegs),
        tcp_outsegs: sub(n.tcp_outsegs, q.tcp_outsegs),
        tcp_activeopens: sub(n.tcp_activeopens, q.tcp_activeopens),
        tcp_passiveopens: sub(n.tcp_passiveopens, q.tcp_passiveopens),
        tcp_currestab: n.tcp_currestab,
        tcp_retranssegs: sub(n.tcp_retranssegs, q.tcp_retranssegs),
        tcp_inerrs: sub(n.tcp_inerrs, q.tcp_inerrs),
        tcp_outrsts: sub(n.tcp_outrsts, q.tcp_outrsts),
        udp_indatagrams: sub(n.udp_indatagrams, q.udp_indatagrams),
        udp_outdatagrams: sub(n.udp_outdatagrams, q.udp_outdatagrams),
        udp_inerrors: sub(n.udp_inerrors, q.udp_inerrors),
        udp_noports: sub(n.udp_noports, q.udp_noports),
        ip_inreceives: sub(n.ip_inreceives, q.ip_inreceives),
        ip_outrequests: sub(n.ip_outrequests, q.ip_outrequests),
        ip_indelivers: sub(n.ip_indelivers, q.ip_indelivers),
        ip_forwdatagrams: sub(n.ip_forwdatagrams, q.ip_forwdatagrams),
    };
    // A pid the previous snapshot did not hold — or held for a task that has since
    // been replaced, which its start time reveals — is new this interval: its
    // counters and its growth are what it has done since it started.
    let before: HashMap<i32, &Proc> = p.procs.iter().map(|q| (q.pid, q)).collect();
    for proc in &mut d.procs {
        match before.get(&proc.pid).filter(|q| q.btime == proc.btime) {
            Some(q) => {
                proc.is_new = false;
                proc.vgrow = proc.vmem as i64 - q.vmem as i64;
                proc.rgrow = proc.rmem as i64 - q.rmem as i64;
                proc.utime = sub(proc.utime, q.utime);
                proc.stime = sub(proc.stime, q.stime);
                proc.minflt = sub(proc.minflt, q.minflt);
                proc.majflt = sub(proc.majflt, q.majflt);
                proc.rundelay = sub(proc.rundelay, q.rundelay);
                proc.blkdelay = sub(proc.blkdelay, q.blkdelay);
                proc.rio = sub(proc.rio, q.rio);
                proc.rsz = sub(proc.rsz, q.rsz);
                proc.wio = sub(proc.wio, q.wio);
                proc.wsz = sub(proc.wsz, q.wsz);
                proc.cwsz = sub(proc.cwsz, q.cwsz);
            }
            None => {
                proc.is_new = true;
                proc.vgrow = proc.vmem as i64;
                proc.rgrow = proc.rmem as i64;
            }
        }
    }
    d
}

/// A counter difference. Saturating: a counter that was reset (an interface renewed,
/// a task replaced) must read as no activity rather than wrap.
fn sub(cur: u64, prev: u64) -> u64 {
    cur.saturating_sub(prev)
}

fn cpu_delta(cur: &Cpu, prev: &Cpu) -> Cpu {
    Cpu {
        id: cur.id,
        utime: sub(cur.utime, prev.utime),
        ntime: sub(cur.ntime, prev.ntime),
        stime: sub(cur.stime, prev.stime),
        itime: sub(cur.itime, prev.itime),
        wtime: sub(cur.wtime, prev.wtime),
        irq: sub(cur.irq, prev.irq),
        softirq: sub(cur.softirq, prev.softirq),
        steal: sub(cur.steal, prev.steal),
        guest: sub(cur.guest, prev.guest),
    }
}

// ---------------------------------------------------------------------------
// Formatting (atop 2.8.1 parseable.c field order)
//
// Every emitter writes into a String, where a formatting write cannot fail, so the
// `write!` results are discarded.
// ---------------------------------------------------------------------------

/// A CPU frequency atop could not read: its own fallback is 0 MHz reported at 100%
/// of an unknown maximum (`calc_freqscale`). A microVM guest has no cpufreq.
const NO_FREQ: (u64, u64) = (0, 100);

/// Performance counters atop reports only where it can read them; 0 is its own value
/// for "not available", and a guest has no perf events.
const NO_PERF: (u64, u64) = (0, 0);

/// cgroup v2 columns: `-3` is what atop prints for every one of them when it has no
/// cgroup v2 support, which is the honest report for a sampler that reads none.
const NO_CGROUP: i64 = -3;

fn write_sample(out: &mut String, env: &Env, s: &Sys, interval: u64) {
    let h = |label: &str| header(label, env, s.epoch, interval);
    print_cpu(out, &h("CPU"), env, s);
    print_cpus(out, &h("cpu"), env, s);
    print_cpl(out, &h("CPL"), s);
    print_mem(out, &h("MEM"), env, s);
    print_swp(out, &h("SWP"), env, s);
    print_pag(out, &h("PAG"), env, s);
    print_psi(out, &h("PSI"), s);
    print_dsk(out, &h("DSK"), s);
    print_net(out, &h("NET"), s);
    print_prg(out, &h("PRG"), s);
    print_prc(out, &h("PRC"), env, s);
    print_prm(out, &h("PRM"), env, s);
    print_prd(out, &h("PRD"), env, s);
}

/// The six generic columns every line starts with: label, host, epoch, date, time and
/// the seconds the sample covers.
fn header(label: &str, env: &Env, epoch: i64, interval: u64) -> String {
    let (date, time) = date_time(epoch);
    format!("{label} {} {epoch} {date} {time} {interval}", env.host)
}

/// atop's `spaceformat` in its default form: a string field is parenthesised, spaces
/// and all. Control characters become spaces — a command line may hold a newline, and
/// one record has to stay one line.
///
/// A field ends at the parenthesis matching its opener, so content whose own parentheses do
/// not balance would shift every cell after it (see [`vk_core::atop::cells`], which has to
/// guess at such a record). Real atop lives with that; this sampler is the writer and does
/// not have to. Balanced content is kept as it is — `php-fpm: master process (…conf)` reads
/// as itself — and unbalanced content gives up its parentheses rather than the record's shape.
fn paren(s: &str) -> String {
    let text: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if !balanced(&text) {
        return format!("({})", text.replace(['(', ')'], " "));
    }
    format!("({text})")
}

/// Whether every `(` in `s` is closed, and no `)` comes before its opener.
fn balanced(s: &str) -> bool {
    let mut depth = 0usize;
    for c in s.chars() {
        match c {
            '(' => depth += 1,
            ')' if depth == 0 => return false,
            ')' => depth -= 1,
            _ => {}
        }
    }
    depth == 0
}

fn yn(b: bool) -> char {
    if b { 'y' } else { 'n' }
}

/// CPU: hertz, cpus, then the tick counters in atop's order (system, user, nice,
/// idle, iowait, irq, softirq, steal, guest), frequency, frequency percentage,
/// instructions and cycles.
fn print_cpu(out: &mut String, h: &str, env: &Env, s: &Sys) {
    let c = &s.cpu;
    let _ = writeln!(
        out,
        "{h} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
        env.hertz,
        s.cpus.len(),
        c.stime,
        c.utime,
        c.ntime,
        c.itime,
        c.wtime,
        c.irq,
        c.softirq,
        c.steal,
        c.guest,
        NO_FREQ.0,
        NO_FREQ.1,
        NO_PERF.0,
        NO_PERF.1
    );
}

/// cpu: one line per processor — the CPU fields with the processor number in place of
/// the processor count.
fn print_cpus(out: &mut String, h: &str, env: &Env, s: &Sys) {
    for c in &s.cpus {
        let _ = writeln!(
            out,
            "{h} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
            env.hertz,
            c.id,
            c.stime,
            c.utime,
            c.ntime,
            c.itime,
            c.wtime,
            c.irq,
            c.softirq,
            c.steal,
            c.guest,
            NO_FREQ.0,
            NO_FREQ.1,
            NO_PERF.0,
            NO_PERF.1
        );
    }
}

/// CPL: processors, the three load averages, context switches, device interrupts.
fn print_cpl(out: &mut String, h: &str, s: &Sys) {
    let _ = writeln!(
        out,
        "{h} {} {:.2} {:.2} {:.2} {} {}",
        s.cpus.len(),
        s.lavg[0],
        s.lavg[1],
        s.lavg[2],
        s.csw,
        s.devint
    );
}

/// MEM: page size, then the memory sizes in pages — physical, free, page cache,
/// buffer cache, slab, dirty, reclaimable slab, VMware balloon, shared memory
/// (total, resident, swapped), huge page size and huge page counts, ZFS ARC, the two
/// KSM figures, TCP and UDP socket memory, page tables.
fn print_mem(out: &mut String, h: &str, env: &Env, s: &Sys) {
    let m = &s.mem;
    let _ = writeln!(
        out,
        "{h} {} {} {} {} {} {} {} {} 0 {} 0 0 {} {} {} 0 0 0 {} {} {}",
        env.pagesize,
        m.physmem,
        m.freemem,
        m.cachemem,
        m.buffermem,
        m.slabmem,
        m.cachedrt,
        m.slabreclaim,
        m.shmem,
        m.hugepagesz,
        m.tothugepage,
        m.freehugepage,
        m.tcpsock,
        m.udpsock,
        m.pagetables
    );
}

/// SWP: page size, swap total and free, swap cache, committed space and its limit,
/// the swap cache again (atop prints it twice), the two zswap sizes.
fn print_swp(out: &mut String, h: &str, env: &Env, s: &Sys) {
    let m = &s.mem;
    let _ = writeln!(
        out,
        "{h} {} {} {} {} {} {} {} {} {}",
        env.pagesize,
        m.totswap,
        m.freeswap,
        m.swapcached,
        m.committed,
        m.commitlim,
        m.swapcached,
        m.zswstored,
        m.zswtotpool
    );
}

/// PAG: page size, page scans, allocation stalls, a reserved zero, swap ins and outs,
/// OOM kills, compaction stalls, migrated pages, NUMA migrations, pages read from and
/// written to block devices.
fn print_pag(out: &mut String, h: &str, env: &Env, s: &Sys) {
    let p = &s.pag;
    let _ = writeln!(
        out,
        "{h} {} {} {} 0 {} {} {} {} {} {} {} {}",
        env.pagesize,
        p.pgscans,
        p.allocstall,
        p.swins,
        p.swouts,
        p.oomkills,
        p.compactstall,
        p.pgmigrate,
        p.numamigrate,
        p.pgins,
        p.pgouts
    );
}

/// PSI: whether pressure stall information is present, then for CPU-some,
/// memory-some, memory-full, io-some and io-full the three averages and the
/// microseconds stalled during the interval.
fn print_psi(out: &mut String, h: &str, s: &Sys) {
    let p = &s.psi;
    let _ = write!(out, "{h} {}", yn(p.present));
    for l in [&p.cpusome, &p.memsome, &p.memfull, &p.iosome, &p.iofull] {
        let _ = write!(
            out,
            " {:.1} {:.1} {:.1} {}",
            l.avg10, l.avg60, l.avg300, l.total
        );
    }
    out.push('\n');
}

/// DSK: one line per disk — name, milliseconds of I/O, reads, sectors read, writes,
/// sectors written, discards, sectors discarded, requests in flight, and the average
/// queue depth while the disk was busy.
///
/// A device that moved nothing and holds nothing is left out: this guest's kernel carries
/// sixteen ramdisks and eight loop devices that never see a sector, and a line each per
/// sample would be most of the log.
fn print_dsk(out: &mut String, h: &str, s: &Sys) {
    for d in s.disks.iter().filter(|d| d.busy()) {
        let avque = match d.io_ms {
            0 => 0.0,
            io_ms => d.avque as f64 / io_ms as f64,
        };
        let _ = writeln!(
            out,
            "{h} {} {} {} {} {} {} {} {} {} {avque:.2}",
            d.name, d.io_ms, d.nread, d.nrsect, d.nwrite, d.nwsect, d.ndisc, d.ndsect, d.inflight
        );
    }
}

/// NET: the `upper` line for the protocol layers — TCP segments in and out, UDP
/// datagrams in and out, IP packets received, transmitted, delivered and forwarded,
/// UDP input and noport errors, TCP opens (active, passive), connections
/// established, retransmits, input errors and output resets — then one line per
/// interface with its packets and bytes, speed and duplex.
fn print_net(out: &mut String, h: &str, s: &Sys) {
    let n = &s.net;
    let _ = writeln!(
        out,
        "{h} upper {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
        n.tcp_insegs,
        n.tcp_outsegs,
        n.udp_indatagrams,
        n.udp_outdatagrams,
        n.ip_inreceives,
        n.ip_outrequests,
        n.ip_indelivers,
        n.ip_forwdatagrams,
        n.udp_inerrors,
        n.udp_noports,
        n.tcp_activeopens,
        n.tcp_passiveopens,
        n.tcp_currestab,
        n.tcp_retranssegs,
        n.tcp_inerrs,
        n.tcp_outrsts
    );
    for i in &s.ifaces {
        let _ = writeln!(
            out,
            "{h} {} {} {} {} {} {} {}",
            i.name, i.rpack, i.rbyte, i.spack, i.sbyte, i.speed, i.duplex
        );
    }
}

/// PRG: pid, name, state, real uid and gid, thread group, threads, exit code, start
/// time, command line, parent, the three thread-state counts, effective, saved and
/// filesystem ids, the elapsed time of an exited process, whether this is a process,
/// the two OpenVZ ids, the container id, whether the task is new this interval, and
/// its cgroup v2 path.
///
/// A live task has no exit code and no elapsed time (0), and this sampler reports no
/// OpenVZ ids (0), no container (`-`) and no cgroup path — all of them atop's own
/// values where it has nothing to report.
fn print_prg(out: &mut String, h: &str, s: &Sys) {
    for p in &s.procs {
        let _ = writeln!(
            out,
            "{h} {} {} {} {} {} {} {} 0 {} {} {} {} {} {} {} {} {} {} {} {} 0 y 0 0 - {} ()",
            p.pid,
            paren(&p.name),
            p.state,
            p.uids[0],
            p.gids[0],
            p.tgid,
            p.nthr,
            p.btime,
            paren(&p.cmdline),
            p.ppid,
            p.nthrrun,
            p.nthrslpi,
            p.nthrslpu,
            p.uids[1],
            p.gids[1],
            p.uids[2],
            p.gids[2],
            p.uids[3],
            p.gids[3],
            if p.is_new { 'N' } else { '-' }
        );
    }
}

/// PRC: pid, name, state, hertz, user and system time, nice, priority, realtime
/// priority, scheduling policy, current CPU, sleep average, thread group, whether
/// this is a process, runqueue delay, wait channel, block I/O delay, and the two
/// cgroup v2 cpu.max columns.
fn print_prc(out: &mut String, h: &str, env: &Env, s: &Sys) {
    for p in &s.procs {
        let _ = writeln!(
            out,
            "{h} {} {} {} {} {} {} {} {} {} {} {} 0 {} y {} {} {} {NO_CGROUP} {NO_CGROUP}",
            p.pid,
            paren(&p.name),
            p.state,
            env.hertz,
            p.utime,
            p.stime,
            p.nice,
            p.prio,
            p.rtprio,
            p.policy,
            p.curcpu,
            p.tgid,
            p.rundelay,
            paren(&p.wchan),
            p.blkdelay
        );
    }
}

/// PRM: pid, name, state, page size, virtual and resident size, shared text, virtual
/// and resident growth, minor and major faults, library, data and stack size, swap
/// used, thread group, whether this is a process, proportional set size, locked
/// memory, and the four cgroup v2 memory columns. The proportional set size is 0,
/// which is what atop prints unless asked to measure it.
fn print_prm(out: &mut String, h: &str, env: &Env, s: &Sys) {
    for p in &s.procs {
        let _ = writeln!(
            out,
            "{h} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} y 0 {} \
             {NO_CGROUP} {NO_CGROUP} {NO_CGROUP} {NO_CGROUP}",
            p.pid,
            paren(&p.name),
            p.state,
            env.pagesize,
            p.vmem,
            p.rmem,
            p.vexec,
            p.vgrow,
            p.rgrow,
            p.minflt,
            p.majflt,
            p.vlibs,
            p.vdata,
            p.vstack,
            p.vswap,
            p.tgid,
            p.vlock
        );
    }
}

/// PRD: pid, name, state, the obsolete kernel-patch column, whether standard io
/// statistics are used, reads, sectors read, writes, sectors written, cancelled
/// sectors, thread group, another obsolete column, and whether this is a process.
fn print_prd(out: &mut String, h: &str, env: &Env, s: &Sys) {
    for p in &s.procs {
        let _ = writeln!(
            out,
            "{h} {} {} {} n {} {} {} {} {} {} {} n y",
            p.pid,
            paren(&p.name),
            p.state,
            yn(env.io_stats),
            p.rio,
            p.rsz,
            p.wio,
            p.wsz,
            p.cwsz,
            p.tgid
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed header, so the golden lines below assert field order and values rather
    /// than the clock — atop builds the same six columns for every label.
    const H: &str = "LBL runner 1767225600 2026/01/01 00:00:00 30";

    fn env() -> Env {
        Env {
            host: "runner".into(),
            hertz: 100,
            pagesize: 4096,
            io_stats: true,
        }
    }

    /// `/proc/stat`: the counters, the boot time a task's start time is anchored on, and
    /// the per-processor lines — whose *number* is the processor's own, since an offline
    /// processor is missing from the file and counting the lines off would rename the rest.
    #[test]
    fn proc_stat_reads_its_counters_and_each_processors_own_number() {
        let mut s = Sys::default();
        let boot = parse_stat(
            "cpu  100 2 30 400 5 6 7 8 9 0\n\
             cpu0 40 1 10 200 2 3 4 5 6 0\n\
             cpu3 60 1 20 200 3 3 3 3 3 0\n\
             intr 1234 5 6\n\
             ctxt 98765\n\
             btime 1767225000\n\
             processes 4242\n\
             softirq 1 2 3\n",
            &mut s,
        );
        assert_eq!(boot, 1_767_225_000);
        assert_eq!(s.csw, 98_765);
        assert_eq!(s.devint, 1_234, "the total across all sources");
        // /proc/stat order: user nice system idle iowait irq softirq steal guest
        assert_eq!((s.cpu.utime, s.cpu.ntime, s.cpu.stime), (100, 2, 30));
        assert_eq!((s.cpu.itime, s.cpu.wtime), (400, 5));
        assert_eq!((s.cpu.irq, s.cpu.softirq, s.cpu.steal), (6, 7, 8));
        assert_eq!(s.cpu.guest, 9);
        // cpu1 and cpu2 are offline: the two lines present keep their own numbers.
        assert_eq!(s.cpus.len(), 2);
        assert_eq!((s.cpus[0].id, s.cpus[0].utime), (0, 40));
        assert_eq!((s.cpus[1].id, s.cpus[1].utime), (3, 60));
        // `softirq` and `processes` start with neither `cpu` nor a known key: not processors.
        let mut out = String::new();
        print_cpus(&mut out, H, &env(), &s);
        assert!(
            out.lines()
                .nth(1)
                .unwrap()
                .starts_with(&format!("{H} 100 3 "))
        );
    }

    /// `/proc/loadavg`: the three averages, in the order the file prints them — the counts
    /// after them are not atop's to report.
    #[test]
    fn proc_loadavg_reads_the_three_averages() {
        let mut s = Sys::default();
        parse_loadavg("0.52 1.25 2.00 3/412 4242\n", &mut s);
        assert_eq!(s.lavg, [0.52, 1.25, 2.00]);
        let mut none = Sys::default();
        parse_loadavg("", &mut none);
        assert_eq!(none.lavg, [0.0, 0.0, 0.0]);
    }

    /// `/proc/meminfo`: kB into pages of the running page size, and the two huge-page
    /// figures that are counts and bytes rather than pages.
    #[test]
    fn proc_meminfo_converts_kilobytes_into_pages() {
        let mut s = Sys::default();
        parse_meminfo(
            "MemTotal:        4096 kB\n\
             MemFree:         1024 kB\n\
             Cached:           512 kB\n\
             Buffers:            8 kB\n\
             Slab:              64 kB\n\
             SReclaimable:      32 kB\n\
             Dirty:              4 kB\n\
             Shmem:             16 kB\n\
             PageTables:        12 kB\n\
             SwapTotal:       2048 kB\n\
             SwapFree:        2040 kB\n\
             SwapCached:         4 kB\n\
             Committed_AS:    8192 kB\n\
             CommitLimit:     6144 kB\n\
             Zswap:              8 kB\n\
             Zswapped:          20 kB\n\
             HugePages_Total:    3\n\
             HugePages_Free:     1\n\
             Hugepagesize:    2048 kB\n",
            &mut s,
            4096,
        );
        assert_eq!(s.mem.physmem, 1_024, "4096 kB is 1024 pages of 4 KiB");
        assert_eq!(s.mem.freemem, 256);
        assert_eq!(s.mem.cachemem, 128);
        assert_eq!(s.mem.buffermem, 2);
        assert_eq!((s.mem.slabmem, s.mem.slabreclaim), (16, 8));
        assert_eq!(s.mem.cachedrt, 1);
        assert_eq!((s.mem.shmem, s.mem.pagetables), (4, 3));
        assert_eq!((s.mem.totswap, s.mem.freeswap), (512, 510));
        assert_eq!(s.mem.swapcached, 1);
        assert_eq!((s.mem.committed, s.mem.commitlim), (2048, 1536));
        assert_eq!((s.mem.zswstored, s.mem.zswtotpool), (5, 2));
        // A huge page is counted whole, and its size is bytes rather than pages.
        assert_eq!(s.mem.hugepagesz, 2 * 1024 * 1024);
        assert_eq!((s.mem.tothugepage, s.mem.freehugepage), (3, 1));
        // A key this kernel does not carry reads as zero, not as the line beside it.
        assert_eq!(s.mem.zswstored, 5);
        let mut bare = Sys::default();
        parse_meminfo("MemTotal: 8192 kB\n", &mut bare, 4096);
        assert_eq!((bare.mem.physmem, bare.mem.freemem), (2_048, 0));
    }

    /// `/proc/net/sockstat`: socket memory, already counted in pages by the kernel, read
    /// out of a line of key/value pairs rather than by position.
    #[test]
    fn proc_sockstat_reads_the_socket_memory_pages() {
        let mut s = Sys::default();
        parse_sockstat(
            "sockets: used 210\n\
             TCP: inuse 4 orphan 0 tw 1 alloc 9 mem 12\n\
             UDP: inuse 2 mem 3\n\
             UDPLITE: inuse 0\n\
             RAW: inuse 0\n",
            &mut s,
        );
        assert_eq!((s.mem.tcpsock, s.mem.udpsock), (12, 3));
        // A protocol line with no `mem` pair at all leaves the figure at zero.
        let mut none = Sys::default();
        parse_sockstat("TCP: inuse 4 orphan 0\n", &mut none);
        assert_eq!(none.mem.tcpsock, 0);
    }

    /// `/proc/vmstat`: the counters whose kernel names are per-zone or per-reclaim-path
    /// families, which atop reports as one figure — so they are summed over the family.
    #[test]
    fn proc_vmstat_sums_the_counter_families() {
        let mut s = Sys::default();
        parse_vmstat(
            "pgpgin 100\n\
             pgpgout 200\n\
             pswpin 3\n\
             pswpout 4\n\
             pgscan_kswapd_dma 10\n\
             pgscan_kswapd_normal 20\n\
             pgscan_direct_normal 5\n\
             pgscan_direct_throttle 4\n\
             pgscan_anon 999\n\
             allocstall_dma 1\n\
             allocstall_normal 2\n\
             compact_stall 7\n\
             pgmigrate_success 8\n\
             numa_pages_migrated 9\n\
             oom_kill 2\n",
            &mut s,
        );
        assert_eq!((s.pag.pgins, s.pag.pgouts), (100, 200));
        assert_eq!((s.pag.swins, s.pag.swouts), (3, 4));
        assert_eq!(
            s.pag.pgscans, 35,
            "the kswapd and direct families summed, less the throttle count that shares the \
             prefix but counts events rather than pages"
        );
        assert_eq!(s.pag.allocstall, 3);
        assert_eq!(s.pag.compactstall, 7);
        assert_eq!((s.pag.pgmigrate, s.pag.numamigrate), (8, 9));
        assert_eq!(s.pag.oomkills, 2);
        // A kernel with no OOM counter reports -1, which is what atop prints for it —
        // never 0, which would read as "no job was killed".
        let mut old = Sys::default();
        parse_vmstat("pgpgin 1\n", &mut old);
        assert_eq!(old.pag.oomkills, -1);
    }

    /// `/proc/pressure/*`: the three averages and the stall total of each line.
    #[test]
    fn proc_pressure_reads_each_line_of_each_resource() {
        let psi = parse_psi(
            "some avg10=1.25 avg60=0.50 avg300=0.00 total=1234\n",
            "some avg10=2.00 avg60=1.00 avg300=0.10 total=5678\n\
             full avg10=0.50 avg60=0.25 avg300=0.00 total=90\n",
            "some avg10=9.99 avg60=0.00 avg300=0.00 total=42\n\
             full avg10=0.01 avg60=0.00 avg300=0.00 total=7\n",
        );
        assert!(psi.present);
        assert_eq!(
            (
                psi.cpusome.avg10,
                psi.cpusome.avg60,
                psi.cpusome.avg300,
                psi.cpusome.total
            ),
            (1.25, 0.50, 0.00, 1234)
        );
        assert_eq!((psi.memsome.avg10, psi.memsome.total), (2.00, 5678));
        assert_eq!((psi.memfull.avg10, psi.memfull.total), (0.50, 90));
        assert_eq!((psi.iosome.avg10, psi.iosome.total), (9.99, 42));
        assert_eq!((psi.iofull.avg10, psi.iofull.total), (0.01, 7));
        // A kernel booted without `psi=1` has no such files: absent, not zeroed.
        let none = parse_psi("", "", "");
        assert!(!none.present);
        assert_eq!(none.cpusome.total, 0);
        // The cpu file has no `full` line; asking for one yields zeroes rather than the
        // `some` line beside it.
        assert_eq!(
            psi_line("some avg10=1.0 avg60=0.0 avg300=0.0 total=1", "full").total,
            0
        );
    }

    /// `/proc/diskstats`, column by column — an offset wrong here is a log that parses
    /// cleanly and reports the wrong device activity forever.
    #[test]
    fn proc_diskstats_reads_every_column_of_a_whole_disk() {
        let mut s = Sys::default();
        // major minor name reads rmerged rsect rms writes wmerged wsect wms inflight ioms
        // weighted discards dmerged dsect dms
        parse_diskstats(
            " 254  0 vda 10 1 80 15 5 2 40 12 1 200 500 3 0 24 6\n\
             \x20254  1 vda1 9 0 70 14 4 0 30 10 0 150 400 0 0 0 0\n\
             \x20  7  0 loop0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
            &mut s,
            |name| name == "vda",
        );
        // The partition and the loop device are not whole disks: one record only.
        assert_eq!(s.disks.len(), 1);
        let d = &s.disks[0];
        assert_eq!(d.name, "vda");
        assert_eq!((d.nread, d.nrsect), (10, 80));
        assert_eq!((d.nwrite, d.nwsect), (5, 40));
        assert_eq!(d.inflight, 1);
        assert_eq!(d.io_ms, 200);
        assert_eq!(d.avque, 500);
        assert_eq!((d.ndisc, d.ndsect), (3, 24));

        // A pre-discard kernel's line stops at the weighted time: discards are reported as
        // `-1` (atop's own "no such counter"), never as zero discards.
        let mut old = Sys::default();
        parse_diskstats(" 254 0 vdb 1 0 8 2 1 0 8 2 0 16 32\n", &mut old, |_| true);
        assert_eq!(old.disks[0].ndisc, -1);
        assert_eq!(old.disks[0].ndsect, 0);
        // A name that is no plain path component never reaches the `is_disk` probe.
        let mut odd = Sys::default();
        parse_diskstats(" 254 0 ../vda 1 0 8 2 1 0 8 2 0 16 32\n", &mut odd, |_| {
            panic!("probed a name that is not one component")
        });
        assert!(odd.disks.is_empty());
    }

    /// `/proc/net/dev`: bytes and packets, received and transmitted — four columns out of
    /// sixteen, and the two the file does not carry come from the link probe.
    #[test]
    fn proc_net_dev_reads_the_four_counters_and_the_link() {
        let mut s = Sys::default();
        parse_netdev(
            "Inter-|   Receive                                                |  Transmit\n\
             \x20face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n\
             \x20   lo:    1000      10    0    0    0     0          0         0     1000      10    0    0    0     0       0          0\n\
             \x20 eth0:   20000     100    0    0    0     0          0         0     9000      90    0    0    0     0       0          0\n",
            &mut s,
            |name| match name {
                "eth0" => (1000, 1),
                _ => (0, 0),
            },
        );
        assert_eq!(s.ifaces.len(), 2, "the two header lines are not interfaces");
        assert_eq!(s.ifaces[0].name, "lo");
        let eth = &s.ifaces[1];
        assert_eq!(eth.name, "eth0");
        assert_eq!((eth.rbyte, eth.rpack), (20_000, 100));
        assert_eq!((eth.sbyte, eth.spack), (9_000, 90));
        assert_eq!((eth.speed, eth.duplex), (1000, 1));
    }

    /// `/proc/net/snmp`: read by name out of the header line each protocol announces, and
    /// summed with the IPv6 counters of the same meaning as atop sums them.
    #[test]
    fn proc_net_snmp_pairs_each_protocol_with_its_own_values() {
        let net = parse_snmp(
            "Ip: Forwarding InReceives ForwDatagrams InDelivers OutRequests\n\
             Ip: 2 13 16 15 14\n\
             Icmp: InMsgs OutMsgs\n\
             Icmp: 1 2\n\
             Tcp: ActiveOpens PassiveOpens CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts\n\
             Tcp: 3 4 5 1 2 6 7 8\n\
             Udp: InDatagrams NoPorts InErrors OutDatagrams\n\
             Udp: 9 12 11 10\n",
            "Ip6InReceives                     100\n\
             Ip6OutRequests                    200\n\
             Ip6InDelivers                     300\n\
             Ip6OutForwDatagrams               400\n\
             Udp6InDatagrams                   500\n\
             Udp6OutDatagrams                  600\n\
             Udp6InErrors                      700\n\
             Udp6NoPorts                       800\n",
        );
        // The counters are read by name, so a protocol declaring them in another order —
        // as Udp does here — still lands each value on its own field.
        assert_eq!((net.tcp_insegs, net.tcp_outsegs), (1, 2));
        assert_eq!((net.tcp_activeopens, net.tcp_passiveopens), (3, 4));
        assert_eq!(net.tcp_currestab, 5);
        assert_eq!(net.tcp_retranssegs, 6);
        assert_eq!((net.tcp_inerrs, net.tcp_outrsts), (7, 8));
        // v4 + v6, each pair summed.
        assert_eq!(net.udp_indatagrams, 9 + 500);
        assert_eq!(net.udp_outdatagrams, 10 + 600);
        assert_eq!(net.udp_inerrors, 11 + 700);
        assert_eq!(net.udp_noports, 12 + 800);
        assert_eq!(net.ip_inreceives, 13 + 100);
        assert_eq!(net.ip_outrequests, 14 + 200);
        assert_eq!(net.ip_indelivers, 15 + 300);
        assert_eq!(net.ip_forwdatagrams, 16 + 400);

        // A stray line between a header and its values must not shift every counter after
        // it onto the wrong name — which is what reading the file two lines at a time does.
        let shifted = parse_snmp(
            "Tcp: InSegs OutSegs\n\
             something the kernel added\n\
             Tcp: 1 2\n\
             Udp: InDatagrams\n\
             Udp: 9\n",
            "",
        );
        assert_eq!((shifted.tcp_insegs, shifted.tcp_outsegs), (1, 2));
        assert_eq!(shifted.udp_indatagrams, 9);
    }

    /// `/proc/<pid>/stat`, field by field. The command sits in parentheses and holds
    /// anything at all — spaces, parentheses of its own — so every field after it is read
    /// from beyond its *last* `)`, and getting that wrong misreads the whole record.
    #[test]
    fn proc_pid_stat_reads_every_field_past_the_command() {
        // fields 1..=42, the command holding both a space and nested parentheses
        let stat = "412 (sh (x) y) S 1 412 412 0 -1 4194560 900 0 2 0 120 30 0 0 25 5 3 0 \
                    170000 20480000 2000 18446744073709551615 1 2 3 4 5 6 7 8 9 10 11 12 13 \
                    3 2 1 77\n";
        let p = parse_proc_stat(stat, 412, &env(), 1_767_225_000).expect("a stat line");
        assert_eq!(p.pid, 412);
        assert_eq!(p.name, "sh (x) y", "the command, its own parentheses kept");
        assert_eq!(p.state, 'S');
        assert_eq!(p.ppid, 1);
        assert_eq!((p.minflt, p.majflt), (900, 2));
        assert_eq!((p.utime, p.stime), (120, 30));
        assert_eq!((p.prio, p.nice), (25, 5));
        assert_eq!(p.nthr, 3);
        // starttime is in clock ticks since boot; the log carries an epoch instead.
        assert_eq!(p.btime, 1_767_225_000 + 1_700);
        assert_eq!(p.vmem, 20_000, "vsize is bytes, the log is KiB");
        assert_eq!(p.rmem, 8_000, "rss is pages, the log is KiB");
        assert_eq!(p.curcpu, 3);
        assert_eq!((p.rtprio, p.policy), (2, 1));
        assert_eq!(p.blkdelay, 77);
        // A line with no command in parentheses is not a stat line.
        assert!(parse_proc_stat("412 sh S 1", 412, &env(), 0).is_none());
        // A truncated line leaves the fields it does not reach at zero rather than
        // panicking or shifting: a task can exit while it is being read.
        let short = parse_proc_stat("412 (sh) R 1 412", 412, &env(), 0).expect("a stat line");
        assert_eq!((short.state, short.ppid), ('R', 1));
        assert_eq!((short.utime, short.blkdelay), (0, 0));
    }

    /// `/proc/<pid>/status`: the four ids of each kind in the order the file lists them,
    /// and the sizes `stat` has no field for.
    #[test]
    fn proc_pid_status_reads_the_four_ids_and_the_sizes() {
        let mut p = Proc::default();
        parse_proc_status(
            "Name:\tsh\n\
             Tgid:\t412\n\
             Uid:\t1000\t1001\t1002\t1003\n\
             Gid:\t100\t101\t102\t103\n\
             VmExe:\t     700 kB\n\
             VmLib:\t    2400 kB\n\
             VmData:\t    1100 kB\n\
             VmStk:\t     132 kB\n\
             VmSwap:\t      64 kB\n\
             VmLck:\t       8 kB\n",
            &mut p,
        );
        assert_eq!(p.tgid, 412);
        assert_eq!(
            p.uids,
            [1000, 1001, 1002, 1003],
            "real, effective, saved, fs"
        );
        assert_eq!(p.gids, [100, 101, 102, 103]);
        assert_eq!((p.vexec, p.vlibs, p.vdata), (700, 2400, 1100));
        assert_eq!((p.vstack, p.vswap, p.vlock), (132, 64, 8));
    }

    /// `/proc/<pid>/schedstat` and `/proc/<pid>/io`: the runqueue wait, and the syscall
    /// counts and byte totals that become 512-byte sectors.
    #[test]
    fn proc_pid_schedstat_and_io_read_the_delay_and_the_bytes() {
        // <runtime> <waittime> <timeslices>: the middle figure is the runqueue delay
        assert_eq!(parse_schedstat("1234567 9000000 42\n"), 9_000_000);
        assert_eq!(parse_schedstat(""), 0);

        let mut p = Proc::default();
        parse_proc_io(
            "rchar: 999\n\
             wchar: 888\n\
             syscr: 11\n\
             syscw: 4\n\
             read_bytes: 90112\n\
             write_bytes: 32768\n\
             cancelled_write_bytes: 4096\n",
            &mut p,
        );
        assert_eq!((p.rio, p.wio), (11, 4));
        assert_eq!(p.rsz, 176, "90112 bytes is 176 sectors of 512");
        assert_eq!(p.wsz, 64);
        assert_eq!(p.cwsz, 8);
        // A kernel without per-process io accounting leaves them at zero, which the PRD
        // label's own "standard io statistics" column tells a reader to disregard.
        let mut none = Proc::default();
        parse_proc_io("", &mut none);
        assert_eq!((none.rio, none.rsz), (0, 0));
    }

    /// The interval column is what a reader divides the counters by, so it is never zero —
    /// the final sample SIGUSR2 asks for can land in the same second as the one before it.
    #[test]
    fn the_interval_a_sample_covers_is_never_zero() {
        assert_eq!(covered_secs(1_000, 970), 30);
        assert_eq!(covered_secs(1_000, 1_000), 1, "a sample within the second");
        assert_eq!(covered_secs(1_000, 1_100), 1, "a clock that stepped back");
    }

    /// The six generic columns every record starts with.
    #[test]
    fn the_generic_columns_lead_every_line() {
        assert_eq!(
            header("CPU", &env(), 1_767_225_600, 30),
            "CPU runner 1767225600 2026/01/01 00:00:00 30"
        );
    }

    #[test]
    fn cpu_and_cpl_lines_match_the_pinned_field_order() {
        let s = Sys {
            cpu: Cpu {
                id: 0, // the total across all processors carries no processor number
                utime: 10,
                ntime: 1,
                stime: 20,
                itime: 300,
                wtime: 4,
                irq: 5,
                softirq: 6,
                steal: 7,
                guest: 8,
            },
            cpus: vec![
                Cpu {
                    id: 0,
                    utime: 4,
                    stime: 9,
                    itime: 150,
                    ..Default::default()
                },
                Cpu {
                    id: 1,
                    utime: 6,
                    stime: 11,
                    itime: 150,
                    ..Default::default()
                },
            ],
            csw: 4242,
            devint: 909,
            lavg: [0.5, 1.25, 2.0],
            ..Default::default()
        };
        let mut out = String::new();
        print_cpu(&mut out, H, &env(), &s);
        print_cpus(&mut out, H, &env(), &s);
        print_cpl(&mut out, H, &s);
        assert_eq!(
            out,
            format!(
                "{H} 100 2 20 10 1 300 4 5 6 7 8 0 100 0 0\n\
                 {H} 100 0 9 4 0 150 0 0 0 0 0 0 100 0 0\n\
                 {H} 100 1 11 6 0 150 0 0 0 0 0 0 100 0 0\n\
                 {H} 2 0.50 1.25 2.00 4242 909\n"
            )
        );
    }

    #[test]
    fn memory_lines_match_the_pinned_field_order() {
        let s = Sys {
            mem: Mem {
                physmem: 500_000,
                freemem: 100_000,
                cachemem: 50_000,
                buffermem: 2_000,
                slabmem: 3_000,
                cachedrt: 40,
                slabreclaim: 1_500,
                shmem: 700,
                pagetables: 250,
                tcpsock: 12,
                udpsock: 3,
                hugepagesz: 2 * 1024 * 1024,
                tothugepage: 0,
                freehugepage: 0,
                totswap: 1_000,
                freeswap: 900,
                swapcached: 20,
                committed: 30_000,
                commitlim: 400_000,
                zswstored: 5,
                zswtotpool: 6,
            },
            pag: Pag {
                pgscans: 11,
                allocstall: 12,
                swins: 13,
                swouts: 14,
                oomkills: 0,
                compactstall: 15,
                pgmigrate: 16,
                numamigrate: 17,
                pgins: 18,
                pgouts: 19,
            },
            ..Default::default()
        };
        let mut out = String::new();
        print_mem(&mut out, H, &env(), &s);
        print_swp(&mut out, H, &env(), &s);
        print_pag(&mut out, H, &env(), &s);
        assert_eq!(
            out,
            format!(
                // pagesize, sizes in pages, the VMware balloon / shared-memory
                // residency / ZFS ARC / KSM columns atop fills with 0 here
                "{H} 4096 500000 100000 50000 2000 3000 40 1500 0 700 0 0 2097152 0 0 0 0 0 12 3 250\n\
                 {H} 4096 1000 900 20 30000 400000 20 5 6\n\
                 {H} 4096 11 12 0 13 14 0 15 16 17 18 19\n"
            )
        );
    }

    /// A kernel booted without `psi=1` has no /proc/pressure: the label still carries
    /// all 21 of its fields, with the `n` atop prints for a host without it.
    #[test]
    fn psi_reports_its_unsupported_form_when_the_kernel_has_none() {
        let mut out = String::new();
        print_psi(&mut out, H, &Sys::default());
        assert_eq!(
            out,
            format!(
                "{H} n 0.0 0.0 0.0 0 0.0 0.0 0.0 0 0.0 0.0 0.0 0 0.0 0.0 0.0 0 0.0 0.0 0.0 0\n"
            )
        );

        let s = Sys {
            psi: Psi {
                present: true,
                cpusome: PsiLine {
                    avg10: 1.25,
                    avg60: 0.5,
                    avg300: 0.0,
                    total: 1_000,
                },
                iofull: PsiLine {
                    avg10: 9.99,
                    avg60: 0.0,
                    avg300: 0.0,
                    total: 42,
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let mut out = String::new();
        print_psi(&mut out, H, &s);
        assert_eq!(
            out,
            format!(
                "{H} y 1.2 0.5 0.0 1000 0.0 0.0 0.0 0 0.0 0.0 0.0 0 0.0 0.0 0.0 0 10.0 0.0 0.0 42\n"
            )
        );
    }

    #[test]
    fn disk_and_network_lines_match_the_pinned_field_order() {
        let s = Sys {
            disks: vec![Disk {
                name: "vda".into(),
                io_ms: 200,
                nread: 10,
                nrsect: 80,
                nwrite: 5,
                nwsect: 40,
                ndisc: -1,
                ndsect: 0,
                inflight: 1,
                avque: 500,
            }],
            ifaces: vec![Iface {
                name: "eth0".into(),
                rpack: 100,
                rbyte: 20_000,
                spack: 90,
                sbyte: 9_000,
                speed: 0,
                duplex: 0,
            }],
            net: NetProto {
                tcp_insegs: 1,
                tcp_outsegs: 2,
                tcp_activeopens: 3,
                tcp_passiveopens: 4,
                tcp_currestab: 5,
                tcp_retranssegs: 6,
                tcp_inerrs: 7,
                tcp_outrsts: 8,
                udp_indatagrams: 9,
                udp_outdatagrams: 10,
                udp_inerrors: 11,
                udp_noports: 12,
                ip_inreceives: 13,
                ip_outrequests: 14,
                ip_indelivers: 15,
                ip_forwdatagrams: 16,
            },
            ..Default::default()
        };
        let mut out = String::new();
        print_dsk(&mut out, H, &s);
        print_net(&mut out, H, &s);
        assert_eq!(
            out,
            format!(
                // the queue depth is the weighted time over the busy time
                "{H} vda 200 10 80 5 40 -1 0 1 2.50\n\
                 {H} upper 1 2 9 10 13 14 15 16 11 12 3 4 5 6 7 8\n\
                 {H} eth0 100 20000 90 9000 0 0\n"
            )
        );
    }

    /// The guest kernel's ramdisks and loop devices never move a sector, and a line each
    /// per sample would be most of the log — so a device that did nothing is not recorded,
    /// while one with a request still outstanding is.
    #[test]
    fn a_device_that_did_nothing_is_not_recorded() {
        let idle = |name: &str| Disk {
            name: name.into(),
            ndisc: -1,
            ..Default::default()
        };
        let s = Sys {
            disks: vec![
                idle("ram0"),
                Disk {
                    inflight: 1,
                    ..idle("vdb")
                },
                Disk {
                    nwrite: 3,
                    nwsect: 24,
                    io_ms: 8,
                    avque: 8,
                    ..idle("vda")
                },
            ],
            ..Default::default()
        };
        let mut out = String::new();
        print_dsk(&mut out, H, &s);
        assert_eq!(
            out,
            format!(
                "{H} vdb 0 0 0 0 0 -1 0 1 0.00\n\
                 {H} vda 8 0 0 3 24 -1 0 0 1.00\n"
            )
        );
    }

    fn proc_fixture() -> Proc {
        Proc {
            pid: 412,
            tgid: 412,
            ppid: 1,
            name: "sh".into(),
            state: 'S',
            cmdline: "/bin/sh -c make test".into(),
            uids: [1000, 1000, 1000, 1000],
            gids: [100, 100, 100, 100],
            nthr: 3,
            nthrrun: 1,
            nthrslpi: 2,
            nthrslpu: 0,
            btime: 1_767_225_000,
            is_new: true,
            utime: 120,
            stime: 30,
            nice: 5,
            prio: 25,
            rtprio: 0,
            policy: 0,
            curcpu: 1,
            rundelay: 9_000_000,
            blkdelay: 7,
            wchan: "do_wait".into(),
            vmem: 20_000,
            rmem: 8_000,
            vexec: 700,
            vlibs: 2_400,
            vdata: 1_100,
            vstack: 132,
            vswap: 0,
            vlock: 0,
            vgrow: 20_000,
            rgrow: 8_000,
            minflt: 900,
            majflt: 2,
            rio: 11,
            rsz: 176,
            wio: 4,
            wsz: 64,
            cwsz: 8,
        }
    }

    #[test]
    fn process_lines_match_the_pinned_field_order() {
        let s = Sys {
            procs: vec![proc_fixture()],
            ..Default::default()
        };
        let mut out = String::new();
        print_prg(&mut out, H, &s);
        print_prc(&mut out, H, &env(), &s);
        print_prm(&mut out, H, &env(), &s);
        print_prd(&mut out, H, &env(), &s);
        assert_eq!(
            out,
            format!(
                // PRG: the exit code, elapsed time, OpenVZ ids, container and cgroup
                // path a live task in a plain guest has nothing to report for
                "{H} 412 (sh) S 1000 100 412 3 0 1767225000 (/bin/sh -c make test) 1 1 2 0 \
                 1000 100 1000 100 1000 100 0 y 0 0 - N ()\n\
                 {H} 412 (sh) S 100 120 30 5 25 0 0 1 0 412 y 9000000 (do_wait) 7 -3 -3\n\
                 {H} 412 (sh) S 4096 20000 8000 700 20000 8000 900 2 2400 1100 132 0 412 y 0 0 \
                 -3 -3 -3 -3\n\
                 {H} 412 (sh) S n y 11 176 4 64 8 412 n y\n"
            )
        );
    }

    /// A command that holds a newline must not break the one-record-per-line format
    /// the whole schema rests on.
    #[test]
    fn a_control_character_in_a_command_stays_inside_its_field() {
        let mut p = proc_fixture();
        p.cmdline = "sh -c echo\nSEP".into();
        let s = Sys {
            procs: vec![p],
            ..Default::default()
        };
        let mut out = String::new();
        print_prg(&mut out, H, &s);
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(out.contains("(sh -c echo SEP)"), "{out}");
    }

    /// A string field ends at the parenthesis matching its opener, so a command whose own
    /// parentheses do not balance would shift every cell after it and leave the record
    /// unreadable. This sampler is the writer, so it does not emit such a record at all.
    #[test]
    fn a_command_that_cannot_be_read_back_gives_up_its_parentheses() {
        let record = |cmdline: &str| {
            let mut p = proc_fixture();
            p.cmdline = cmdline.into();
            let s = Sys {
                procs: vec![p],
                ..Default::default()
            };
            let mut out = String::new();
            print_prg(&mut out, H, &s);
            out
        };

        // Balanced parentheses of its own are the common case and are kept verbatim.
        let out = record("php-fpm: master process (/etc/php/fpm.conf)");
        assert!(
            out.contains("(php-fpm: master process (/etc/php/fpm.conf))"),
            "{out}"
        );
        assert_eq!(
            vk_core::atop::cells(out.trim_end()).len(),
            vk_core::atop::PRG.arity()
        );

        // A lone `)` would close the field early; a lone `(` would swallow the rest of the
        // record. Either way the parentheses go and the record still reads back whole.
        for cmdline in ["sh -c echo ) tail", "sh -c echo ( tail", "sh -c )("] {
            let out = record(cmdline);
            let line = out.trim_end();
            assert_eq!(
                vk_core::atop::cells(line).len(),
                vk_core::atop::PRG.arity(),
                "{cmdline:?} -> {line}"
            );
            assert!(!line.contains(") tail"), "{line}");
        }
    }

    /// A sample is framed by the lines a reader finds it with: `RESET` before the first one
    /// only — its counters cover the whole boot — and `SEP` after every one, which is the
    /// point at which the sample is complete.
    #[test]
    fn a_sample_is_framed_by_reset_and_sep() {
        let s = Sys {
            cpus: vec![Cpu::default()],
            procs: vec![proc_fixture()],
            ..Default::default()
        };
        let first = sample_text(&env(), &s, None, 30);
        assert!(first.starts_with("RESET\n"), "{first}");
        assert!(first.ends_with("SEP\n"));
        assert_eq!(first.matches("RESET\n").count(), 1);

        let next = sample_text(&env(), &s, Some(&s), 30);
        assert!(
            !next.contains("RESET"),
            "only the first sample announces one"
        );
        assert!(next.ends_with("SEP\n"));
        // The framing is not the only thing that turns on there being a previous sample:
        // a task the sample before it already held is no longer marked new.
        let prg = |text: &str| {
            text.lines()
                .find(|l| l.starts_with("PRG "))
                .expect("a process record")
                .to_string()
        };
        assert!(prg(&first).ends_with(" N ()"), "{}", prg(&first));
        assert!(prg(&next).ends_with(" - ()"), "{}", prg(&next));

        // Between the two framing lines, each label appears exactly where atop's own label
        // table puts it — the order every positional reader of the format walks.
        let labels: Vec<&str> = first
            .lines()
            .map(|l| l.split_whitespace().next().unwrap_or(""))
            .collect();
        assert_eq!(
            labels,
            vec![
                "RESET", "CPU", "cpu", "CPL", "MEM", "SWP", "PAG", "PSI", "NET", "PRG", "PRC",
                "PRM", "PRD", "SEP"
            ]
        );
    }

    /// The counters atop reports per interval are differences against the previous
    /// snapshot, while sizes and averages are the values as they stand — and a first
    /// sample, having nothing to compare against, reports everything since boot.
    #[test]
    fn counters_are_per_interval_differences() {
        let first = Sys {
            epoch: 1_000,
            cpu: Cpu {
                utime: 100,
                stime: 50,
                ..Default::default()
            },
            csw: 1_000,
            devint: 500,
            mem: Mem {
                freemem: 900,
                ..Default::default()
            },
            pag: Pag {
                pgins: 10,
                oomkills: 0,
                ..Default::default()
            },
            psi: Psi {
                present: true,
                cpusome: PsiLine {
                    avg10: 1.0,
                    total: 700,
                    ..Default::default()
                },
                ..Default::default()
            },
            disks: vec![Disk {
                name: "vda".into(),
                nread: 7,
                inflight: 3,
                ..Default::default()
            }],
            ifaces: vec![Iface {
                name: "eth0".into(),
                rbyte: 4_000,
                ..Default::default()
            }],
            net: NetProto {
                tcp_insegs: 40,
                tcp_currestab: 6,
                ..Default::default()
            },
            procs: vec![proc_fixture()],
            ..Default::default()
        };
        // Nothing to deviate from: the raw counters already cover boot→now.
        let d = deviate(&first, None);
        assert_eq!(d.cpu.utime, 100);
        assert_eq!(d.procs[0].utime, 120);
        assert!(d.procs[0].is_new);

        let mut second = first.clone();
        second.epoch = 1_030;
        second.cpu.utime = 175;
        second.csw = 1_600;
        second.mem.freemem = 800;
        second.pag.pgins = 12;
        second.psi.cpusome.total = 900;
        second.psi.cpusome.avg10 = 2.5;
        second.disks[0].nread = 19;
        second.disks[0].inflight = 1;
        second.ifaces[0].rbyte = 4_500;
        second.net.tcp_insegs = 60;
        second.net.tcp_currestab = 9;
        second.procs[0].utime = 200;
        second.procs[0].vmem = 22_000;
        second.procs[0].rio = 15;

        let d = deviate(&second, Some(&first));
        assert_eq!(d.cpu.utime, 75);
        assert_eq!(d.csw, 600);
        assert_eq!(d.pag.pgins, 2);
        assert_eq!(d.psi.cpusome.total, 200, "the stall total is a difference");
        assert_eq!(d.psi.cpusome.avg10, 2.5, "the averages are current");
        assert_eq!(d.mem.freemem, 800, "memory sizes are current");
        assert_eq!(d.disks[0].nread, 12);
        assert_eq!(d.disks[0].inflight, 1, "the queue is current");
        assert_eq!(d.ifaces[0].rbyte, 500);
        assert_eq!(d.net.tcp_insegs, 20);
        assert_eq!(
            d.net.tcp_currestab, 9,
            "established connections are a current count"
        );
        assert_eq!(d.procs[0].utime, 80);
        assert_eq!(d.procs[0].rio, 4);
        assert_eq!(d.procs[0].vgrow, 2_000, "growth over the interval");
        assert!(!d.procs[0].is_new, "the task was there before");

        // A pid reused by another task is not the same task: its counters start over.
        let mut reused = second.clone();
        reused.procs[0].btime += 5;
        reused.procs[0].utime = 20;
        let d = deviate(&reused, Some(&first));
        assert!(d.procs[0].is_new);
        assert_eq!(d.procs[0].utime, 20);
    }

    /// Per-processor counters are deviated against the same processor, by its number — a
    /// processor that goes offline mid-job leaves `/proc/stat`, and pairing the lines off by
    /// position would deviate every processor after it against its neighbour.
    #[test]
    fn a_processor_is_deviated_against_itself_not_against_its_position() {
        let cpu = |id: usize, utime: u64| Cpu {
            id,
            utime,
            ..Default::default()
        };
        let before = Sys {
            epoch: 1_000,
            cpus: vec![cpu(0, 100), cpu(1, 200), cpu(2, 300)],
            ..Default::default()
        };
        // cpu1 went offline: what is left is cpu0 and cpu2, in that order.
        let after = Sys {
            epoch: 1_030,
            cpus: vec![cpu(0, 150), cpu(2, 340)],
            ..Default::default()
        };
        let d = deviate(&after, Some(&before));
        assert_eq!((d.cpus[0].id, d.cpus[0].utime), (0, 50));
        assert_eq!(
            (d.cpus[1].id, d.cpus[1].utime),
            (2, 40),
            "cpu2 against cpu2, not against cpu1"
        );
        // A processor that comes back reports what it has done since, not since boot.
        let back = Sys {
            epoch: 1_060,
            cpus: vec![cpu(0, 160), cpu(1, 210), cpu(2, 350)],
            ..Default::default()
        };
        let d = deviate(&back, Some(&after));
        assert_eq!(
            (d.cpus[1].id, d.cpus[1].utime),
            (1, 0),
            "nothing to pair against: its since-boot ticks are not one interval's"
        );
        assert_eq!((d.cpus[2].id, d.cpus[2].utime), (2, 10));
    }

    /// The emitters against the real /proc of the machine running the tests: every record
    /// must carry exactly the fields the shared schema declares for its label, which is
    /// what a positional reader reads it by. A record's string fields are parenthesised
    /// and may hold spaces, so those are counted as the one cell they are.
    #[test]
    fn a_sample_of_the_live_proc_filesystem_has_every_field() {
        let env = env();
        let s = snapshot(&env);
        assert!(!s.cpus.is_empty(), "at least one processor");
        assert!(s.mem.physmem > 0, "physical memory");
        assert!(!s.procs.is_empty(), "at least this test process");
        let mut out = String::new();
        write_sample(&mut out, &env, &deviate(&s, None), 30);
        let mut seen: Vec<&str> = Vec::new();
        for line in out.lines() {
            let cells = vk_core::atop::cells(line);
            let label = vk_core::atop::label_of(&cells)
                .unwrap_or_else(|| panic!("no schema for this record: {line}"));
            assert_eq!(cells.len(), label.arity(), "{line}");
            seen.push(label.name);
        }
        for label in vk_core::atop::LABELS {
            // DSK is the one label a sample may legitimately lack: a device that moved
            // nothing gets no record (see print_dsk), and a machine can be that quiet.
            if std::ptr::eq(*label, &vk_core::atop::DSK) && !s.disks.iter().any(Disk::busy) {
                continue;
            }
            assert!(seen.contains(&label.name), "no {} record", label.name);
        }
        // The live sample must name this very process, with its own command line.
        let me = format!(" {} (", std::process::id());
        assert!(
            out.lines()
                .any(|l| l.starts_with("PRG ") && l.contains(&me)),
            "no PRG line for pid {}",
            std::process::id()
        );
    }
}
