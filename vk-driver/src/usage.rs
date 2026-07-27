//! What work cost the host: the CPU time and peak memory it consumed, for the line each
//! phase reports when it ends.
//!
//! Each phase is measured the way its own processes allow:
//!
//! - a **job's** microVM ([`tree`]) is a live process tree — the VMM, the service VMs, the
//!   switch, the virtiofsds, the forwards, all tied children of the job supervisor — read
//!   from `/proc` while it runs. The supervisor is detached and no `run` stage waits for
//!   it, so there is no `rusage` to collect; by the time it is reaped (cleanup) the job
//!   trace is already closed.
//! - a **build** ([`Meter`]) is the opposite: its stage guests are this process's own
//!   children, and every one is gone before the build ends. Its CPU therefore comes from
//!   `getrusage`, which has already added the reaped children up — but how much memory
//!   several guests held *together* exists only while they are alive, so a sampler tracks
//!   it as the build runs.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// The host resources some work used.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    /// User + system CPU time, guest execution included: KVM accounts the time a vCPU
    /// thread spends running the guest into the VMM process's user time.
    pub cpu: Duration,
    /// The most resident memory the work held at one time, in bytes. A high-water mark, not
    /// the memory left at the end: a guest hands freed RAM straight back to the host (free
    /// page reporting), so the live figure says little about the demand it passed through.
    /// How closely the mark is known depends on how it was taken — see [`tree`] and
    /// [`Meter::read`].
    pub peak_rss: u64,
    /// The most any one process in the work was seen to hold — the per-guest figure next to
    /// the whole-phase `peak_rss`, so a build says whether to raise the memory each stage
    /// guest gets or to run fewer at once. A maximum over measurements rather than any single
    /// process's own peak: one that peaked while a larger sibling was resident never shows.
    /// `None` where nothing tracked it.
    pub largest_rss: Option<u64>,
}

impl Usage {
    /// The trace line for `phase` (`job`, `build`):
    /// `virtkit: build resource usage: cpu 2m14s, peak memory 1.6 GiB (largest process 900 MiB)`.
    pub fn summary(&self, phase: &str) -> String {
        let total = fmt_bytes(self.peak_rss);
        // The largest process is worth a clause only where it says something the total does
        // not: one guest holding everything reads the same either way.
        let largest = match self.largest_rss.map(fmt_bytes) {
            Some(one) if one != total => format!(" (largest process {one})"),
            _ => String::new(),
        };
        format!(
            "virtkit: {phase} resource usage: cpu {}, peak memory {total}{largest}",
            fmt_cpu(self.cpu),
        )
    }
}

/// How often the sampler adds up what a phase is holding. Two orders of magnitude under the
/// seconds a guest takes to fault its memory in, so it lands on the plateau rather than
/// between two of them.
const SAMPLE: Duration = Duration::from_millis(100);

/// Meters ever started in this process (high half) and running right now (low half). Both of
/// a meter's sources are process-wide — `getrusage` counts every child this process reaped,
/// and the sampler walks everything under its pid — so two phases running at once cannot be
/// told apart, and the manager does run two on-demand service builds at once. A meter that
/// shared the process with another reports nothing rather than charging it for the other's
/// guests. Packed into one word so a single `fetch_add` claims a place in the sequence and
/// reads how many were already running: taken apart, two meters starting at once could each
/// find the other's half unwritten and both believe they were alone.
static METERS: AtomicU64 = AtomicU64::new(0);
const ONE_STARTED: u64 = 1 << 32;
const RUNNING_MASK: u64 = u32::MAX as u64;

/// Measures a phase this process runs in guests of its own — a build's stage guests.
/// Started before the phase, read after it.
pub struct Meter {
    cpu_before: Duration,
    /// This meter's place in the process's sequence of meters, and whether any other was
    /// already running when it began — together they say whether it had the process to
    /// itself for its whole life (see [`Meter::read`]).
    seq: u64,
    alone_at_start: bool,
    /// The largest total the sampler has seen this process's tree hold.
    peak: Arc<AtomicU64>,
    /// The largest any one process in it reached, from the same samples.
    largest: Arc<AtomicU64>,
    /// Raised when the phase ends. A condvar rather than a flag the sampler polls: teardown
    /// runs on the thread that ran the phase — a tokio worker, for a `vk run` — and must not
    /// block there for whatever is left of a backoff.
    stop: Arc<(Mutex<bool>, Condvar)>,
    sampler: Option<std::thread::JoinHandle<()>>,
}

/// The stop flag, taken past a poisoning: a panic while it was held says only that some
/// thread died, and the flag it guards is a plain bool that is never left half-written.
fn stop_flag(stop: &(Mutex<bool>, Condvar)) -> std::sync::MutexGuard<'_, bool> {
    stop.0.lock().unwrap_or_else(|e| e.into_inner())
}

impl Meter {
    pub fn start() -> Meter {
        let root = std::process::id() as i32;
        let claimed = METERS.fetch_add(ONE_STARTED | 1, Ordering::Relaxed);
        let seq = (claimed >> 32) + 1;
        let alone_at_start = claimed & RUNNING_MASK == 0;
        // Whatever already runs under this process came from before this phase — a service VM
        // the manager booted, say. Recorded now and left out of every sample, so the phase is
        // charged for its own guests alone.
        let mut before: HashSet<i32> = descendants(root, &HashSet::new()).into_iter().collect();
        before.remove(&root);

        let peak = Arc::new(AtomicU64::new(0));
        let largest = Arc::new(AtomicU64::new(0));
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        // Named and fallibly spawned: a host too short on threads to take one must not lose
        // the build over a figure it only reports. Without the sampler the phase keeps no
        // memory marks, and `read` reports nothing at all.
        let sampler = std::thread::Builder::new()
            .name("vk-usage-sampler".into())
            .spawn({
                let (peak, largest, stop) =
                    (Arc::clone(&peak), Arc::clone(&largest), Arc::clone(&stop));
                move || {
                    while !*stop_flag(&stop) {
                        let swept = Instant::now();
                        let (held, biggest) = sweep(root, &before);
                        // Total first, largest second and released — `read` takes them the
                        // other way round, so a largest it picks up is never newer than the
                        // total it already holds. Publishing them in the same order a reader
                        // consumes them would let a growing tree hand back a largest process
                        // bigger than the whole phase.
                        peak.fetch_max(held, Ordering::Relaxed);
                        largest.fetch_max(biggest, Ordering::Release);
                        // Back off from an expensive sweep so the measurement never costs more
                        // than ~2% of a core: reading the tree from the kernel's child lists is
                        // orders of magnitude cheaper than the ppid-scan fallback, which walks
                        // all of `/proc`. Waited on the stop condvar, so the end of the phase
                        // cuts the backoff short.
                        let backoff = SAMPLE.max(swept.elapsed() * 50);
                        // Whether it woke on the signal or the timeout makes no difference:
                        // the loop reads the flag again either way, so the wait's own result
                        // (a poisoning included) has nothing left to say.
                        let _ = stop
                            .1
                            .wait_timeout_while(stop_flag(&stop), backoff, |s| !*s);
                    }
                }
            })
            .ok();
        Meter {
            cpu_before: rusage_cpu(),
            seq,
            alone_at_start,
            peak,
            largest,
            stop,
            sampler,
        }
    }

    /// The usage since [`Meter::start`], or `None` for a phase whose figures cannot be
    /// attributed to it: one that shared the process with another meter, one whose sampler
    /// never started, and one the sampler never got to sweep at all.
    ///
    /// `cpu` is the whole delta, the driver's own work (assembling an image, pushing to the
    /// cache) counted alongside the guests'. Unlike the memory samples it has no counterpart
    /// to the `before` set, since `getrusage` reports one running total rather than a tree:
    /// it also absorbs whatever unrelated work this process did in the window, and the whole
    /// lifetime of any process that predated the phase and was reaped inside it — a service
    /// VM torn down during an on-demand service build charges its entire run to that build.
    ///
    /// The memory marks are the sampler's, not `getrusage`'s: `ru_maxrss` would be exact but
    /// covers this process's whole life, so a build inside a supervisor already running
    /// service VMs would report their peak as its own, and it tracks only the largest single
    /// child — never what several guests held together.
    pub fn read(&self) -> Option<Usage> {
        // Alone for the whole phase, not merely at its start: a meter that began and ended
        // inside this one's window would leave the counter back where it was.
        let alone = self.alone_at_start && METERS.load(Ordering::Relaxed) >> 32 == self.seq;
        // Largest before the total, against the order the sampler publishes them in: `read`
        // can run while it still sweeps, and taking them the same way round would let a
        // growing tree yield a largest process bigger than the phase that held it.
        let largest = self.largest.load(Ordering::Acquire);
        let peak = self.peak.load(Ordering::Relaxed);
        // A sweep always covers at least this process, so a zero largest means none ever
        // landed — a phase shorter than the sampler took to start. Omitted rather than
        // reported as having held no memory. Gated on the mark read first: a largest above
        // zero already implies a total at least as big, where a nonzero total says nothing
        // about a largest read before it.
        (alone && self.sampler.is_some() && largest > 0).then(|| Usage {
            cpu: rusage_cpu().saturating_sub(self.cpu_before),
            peak_rss: peak,
            largest_rss: Some(largest),
        })
    }
}

impl Drop for Meter {
    fn drop(&mut self) {
        *stop_flag(&self.stop) = true;
        self.stop.1.notify_all();
        METERS.fetch_sub(1, Ordering::Relaxed);
        if let Some(sampler) = self.sampler.take() {
            // A panicked sampler leaves the marks at their last good value, which is all
            // `read` needs; there is nothing to do about it here but let the phase end.
            let _ = sampler.join();
        }
    }
}

/// One pass over the tree under `root`: `(what it holds altogether, the most any one process
/// in it holds)`. Both from the same reads, so the total always covers the process that set
/// the second figure — the two marks a [`Meter`] keeps are each a maximum over these, and so
/// can come from different passes, but neither can ever exceed a total this one measured.
///
/// Resident size, where [`tree`] takes the kernel's own `VmHWM` high-water mark. A sampler
/// wants what the tree holds *right now*: the maximum over passes is then the high-water mark
/// of the total, which per-process marks summed could never give — they never coincided.
fn sweep(root: i32, skip: &HashSet<i32>) -> (u64, u64) {
    let mut held = 0;
    let mut biggest = 0;
    for rss in descendants(root, skip)
        .into_iter()
        .filter_map(|pid| Some(mem(pid)?.0))
    {
        held += rss;
        biggest = biggest.max(rss);
    }
    (held, biggest)
}

/// This process's CPU time plus that of every child it has reaped.
fn rusage_cpu() -> Duration {
    [libc::RUSAGE_SELF, libc::RUSAGE_CHILDREN]
        .into_iter()
        .filter_map(rusage)
        .map(|ru| timeval(ru.ru_utime) + timeval(ru.ru_stime))
        .sum()
}

fn rusage(who: libc::c_int) -> Option<libc::rusage> {
    let mut ru = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage fills the whole struct through the pointer, and only on success.
    unsafe { (libc::getrusage(who, ru.as_mut_ptr()) == 0).then(|| ru.assume_init()) }
}

fn timeval(t: libc::timeval) -> Duration {
    Duration::new(t.tv_sec.max(0) as u64, t.tv_usec.max(0) as u32 * 1000)
}

/// The usage of `root` and every process descending from it, summed — including their peak
/// memory, so two that never peaked together read as an upper bound on what the tree held at
/// once. Unlike a build, a job's VM cannot be sampled: the reader is a short-lived stage in
/// another process. `None` when `root` is gone: a job whose supervisor already died reports
/// nothing rather than a partial figure.
pub fn tree(root: i32) -> Option<Usage> {
    let pids = descendants(root, &HashSet::new());
    if pids.is_empty() {
        return None;
    }
    let hz = clock_ticks();
    let mut usage = Usage::default();
    for pid in pids {
        if let Some((_, ticks)) = stat(pid) {
            usage.cpu += ticks_to_duration(ticks, hz);
        }
        usage.peak_rss += mem(pid).map_or(0, |(_, peak)| peak);
    }
    Some(usage)
}

/// `root` and every process descending from it, in no particular order. A pid in `skip` is
/// left out along with everything under it — nothing descends through a process the caller
/// has disowned, which is how a [`Meter`] ignores what was already running. Empty when
/// `root` itself is gone.
fn descendants(root: i32, skip: &HashSet<i32>) -> Vec<i32> {
    if skip.contains(&root) || stat(root).is_none() {
        return Vec::new();
    }
    // Without the kernel's child lists the links have to come from every process's ppid:
    // derive them once for the whole host rather than per process visited.
    let scanned = (!kernel_lists_children()).then(ppid_links);
    let mut out = vec![root];
    let mut next = 0;
    while next < out.len() {
        let pid = out[next];
        next += 1;
        let children = match &scanned {
            Some(links) => links.get(&pid).cloned().unwrap_or_default(),
            None => kernel_children(pid),
        };
        for child in children {
            // `out.contains` keeps a pid the kernel reports twice — or a link that a mid-walk
            // pid reuse turned into a cycle — from being visited again.
            if !skip.contains(&child) && !out.contains(&child) {
                out.push(child);
            }
        }
    }
    out
}

/// One process's direct children, from the kernel's own lists. A child is recorded under the
/// thread that forked it, so this reads one small file per thread — a handful of reads against
/// the whole-of-`/proc` scan [`ppid_links`] needs to derive the same links, which is what makes
/// sampling a running build affordable.
fn kernel_children(pid: i32) -> Vec<i32> {
    let Ok(threads) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return Vec::new(); // the process exited mid-walk
    };
    threads
        .flatten()
        .filter_map(|t| std::fs::read_to_string(t.path().join("children")).ok())
        .flat_map(|list| {
            list.split_whitespace()
                .filter_map(|child| child.parse().ok())
                .collect::<Vec<i32>>()
        })
        .collect()
}

/// Whether this kernel publishes per-thread child lists (`CONFIG_PROC_CHILDREN`). Probed
/// once: the answer cannot change while we run, and the fallback costs a scan of every
/// process on the host.
fn kernel_lists_children() -> bool {
    static PRESENT: OnceLock<bool> = OnceLock::new();
    *PRESENT.get_or_init(|| {
        std::fs::read_dir("/proc/self/task").is_ok_and(|mut threads| {
            threads.any(|entry| entry.is_ok_and(|t| t.path().join("children").exists()))
        })
    })
}

/// Parent → children over every process on the host, from their `stat` ppid. The stand-in
/// for [`kernel_children`] on a kernel that publishes no child lists.
fn ppid_links() -> HashMap<i32, Vec<i32>> {
    let mut links: HashMap<i32, Vec<i32>> = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return links;
    };
    for pid in entries.flatten().filter_map(|e| {
        e.file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
    }) {
        // A process exiting mid-scan just drops out: it is no longer part of anything held.
        if let Some((ppid, _)) = stat(pid) {
            links.entry(ppid).or_default().push(pid);
        }
    }
    links
}

/// `(ppid, CPU ticks)` for `pid`. Fields are counted from the last `)`: before it sits the
/// comm field, a process name that may hold spaces and parentheses — the ppid scan reads
/// every process on the host, and vk's own VMM name comes from a `--vm-name` template — so
/// splitting from the front would misalign everything after it.
fn stat(pid: i32) -> Option<(i32, u64)> {
    parse_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

fn parse_stat(line: &str) -> Option<(i32, u64)> {
    let fields: Vec<&str> = line
        .get(line.rfind(')')? + 1..)?
        .split_whitespace()
        .collect();
    // The first field after comm is state (3), so field N is at index N - 3: ppid is 4,
    // utime 14, stime 15, cutime 16, cstime 17.
    let ppid = fields.get(1)?.parse().ok()?;
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    // cutime/cstime hold the time of children this process has already reaped — the only
    // record left of a helper that came and went before the tree was read, such as the build
    // microVMs of a service the supervisor had to build itself. A live descendant has not
    // been waited for, so it is in nobody's cutime and cannot be counted twice. Defaulted
    // rather than `?` so a line that stops before these two still yields the ppid and the
    // process's own time.
    let reaped = |i: usize| -> u64 { fields.get(i).and_then(|f| f.parse().ok()).unwrap_or(0) };
    Some((ppid, utime + stime + reaped(13) + reaped(14)))
}

/// `(resident, peak resident)` for `pid` in bytes — what it holds now and its high-water
/// mark. `None` for a process that reports neither (it has gone, or has no memory of its
/// own); a process reporting only one of the two still counts for that one.
fn mem(pid: i32) -> Option<(u64, u64)> {
    parse_mem(&std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?)
}

fn parse_mem(status: &str) -> Option<(u64, u64)> {
    let field = |name: &str| {
        status.lines().find_map(|l| {
            let kb: u64 = l
                .strip_prefix(name)?
                .split_whitespace()
                .next()?
                .parse()
                .ok()?;
            Some(kb * 1024)
        })
    };
    let (rss, peak) = (field("VmRSS:"), field("VmHWM:"));
    // Looked up independently, so a status missing one field does not zero the other.
    (rss.is_some() || peak.is_some()).then(|| (rss.unwrap_or(0), peak.unwrap_or(0)))
}

/// The kernel's CPU-time unit — `stat` counts in these. Falls back to the near-universal
/// 100 Hz if the sysconf query fails, so a usage line is still roughly right.
fn clock_ticks() -> u64 {
    // SAFETY: sysconf reads a constant of the running libc; it takes no pointer and cannot
    // fail other than by returning -1, which the guard below turns into the fallback.
    match unsafe { libc::sysconf(libc::_SC_CLK_TCK) } {
        hz if hz > 0 => hz as u64,
        _ => 100,
    }
}

/// Clock ticks as a `Duration`. Whole seconds first, so scaling the remainder to nanoseconds
/// cannot overflow whatever the tick count. `hz` comes from [`clock_ticks`], which never
/// yields zero.
fn ticks_to_duration(ticks: u64, hz: u64) -> Duration {
    debug_assert!(hz > 0, "a zero tick rate would divide by zero");
    Duration::new(ticks / hz, ((ticks % hz) * 1_000_000_000 / hz) as u32)
}

/// CPU time at job scale: `12.3s` under a minute, then `2m14s`, then `1h04m`.
fn fmt_cpu(d: Duration) -> String {
    // Rounded, not truncated: branching on 59 while the sub-minute arm prints the rounded
    // 60.0 would render 59.97s as "60.0s" instead of "1m00s".
    let secs = d.as_secs_f64().round() as u64;
    if secs < 60 {
        format!("{:.1}s", d.as_secs_f64())
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Memory as a sizing figure — `1.6 GiB`, `842 MiB` — never finer than a MiB.
fn fmt_bytes(bytes: u64) -> String {
    let mib = bytes as f64 / (1024.0 * 1024.0);
    // Rounded for the same reason as fmt_cpu: 1023.7 MiB reads "1.0 GiB", never "1024 MiB".
    if mib.round() >= 1024.0 {
        format!("{:.1} GiB", mib / 1024.0)
    } else {
        format!("{mib:.0} MiB")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A child that holds `mib` of memory until it is killed.
    fn hog(mib: usize) -> Reap {
        // Written in shell so the test needs no helper binary: a string the child holds
        // until it is killed. Read in one go rather than doubled up to size — the doubling
        // copies megabytes over and over, which on a loaded host takes long enough that the
        // test waiting for the child gives up on it.
        let script = format!(
            "s=$(head -c {} /dev/zero | tr '\\0' x); while true; do sleep 1; done",
            mib * 1024 * 1024
        );
        Reap(
            std::process::Command::new("sh")
                .args(["-c", &script])
                .spawn()
                .expect("spawning a memory-holding child"),
        )
    }

    /// A spawned child, killed however the test ends. These children loop forever, so an
    /// assert firing mid-poll would otherwise leave one holding its memory on the runner.
    struct Reap(std::process::Child);

    impl Reap {
        fn pid(&self) -> i32 {
            self.0.id() as i32
        }
    }

    impl Drop for Reap {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn parses_a_stat_line_whose_comm_holds_spaces_and_parens() {
        // A real line, with a process name that would break front-to-back field splitting.
        let line = "42 (vk:my (odd) vm) S 7 42 42 0 -1 4194560 900 0 0 0 130 27 0 0 20 0 9 0 \
                    123456 2 3 4";
        assert_eq!(parse_stat(line), Some((7, 157)));
        // Children this process reaped count too, or a helper that came and went before the
        // reading — a service's build microVMs, say — would go unbilled.
        let reaped = line.replace(" 130 27 0 0 20 ", " 130 27 40 3 20 ");
        assert_eq!(parse_stat(&reaped), Some((7, 200)));
        // A truncated line yields nothing rather than a wrong figure.
        assert_eq!(parse_stat("42 (vk) S 7"), None);
        assert_eq!(parse_stat("no parens here"), None);
    }

    #[test]
    fn converts_clock_ticks_at_any_hz_without_overflowing() {
        assert_eq!(ticks_to_duration(157, 100), Duration::from_millis(1570));
        assert_eq!(ticks_to_duration(0, 100), Duration::ZERO);
        assert_eq!(ticks_to_duration(3, 1000), Duration::from_millis(3));
        // A tick count that scaling to nanoseconds up front would overflow.
        assert_eq!(
            ticks_to_duration(u64::MAX / 2, 100).as_secs(),
            u64::MAX / 200
        );
    }

    #[test]
    fn reads_live_and_peak_memory_in_bytes() {
        let status = "Name:\tvk\nVmRSS:\t    7064 kB\nVmHWM:\t  375372 kB\nThreads:\t8\n";
        assert_eq!(parse_mem(status), Some((7064 * 1024, 375372 * 1024)));
        // Either field alone still counts: one missing must not zero the other.
        assert_eq!(
            parse_mem("Name:\tvk\nVmHWM:\t  375372 kB\n"),
            Some((0, 375372 * 1024))
        );
        // A process with no mm of its own reports neither.
        assert_eq!(parse_mem("Name:\tkthread\nThreads:\t1\n"), None);
    }

    /// Both routes to a process's children — the kernel's lists and the ppid scan that
    /// stands in for them — must find a child this process spawned, `skip` must hide it, and the
    /// walk must carry on past that first level: a job's deeper helpers are why it descends
    /// at all.
    #[test]
    fn both_child_lookups_find_a_spawned_child() {
        let me = std::process::id() as i32;
        // `sleep` under a shell that waits on it: the shell is the child, the sleep the
        // grandchild, and both outlive the assertions.
        let child = Reap(
            std::process::Command::new("sh")
                .args(["-c", "sleep 30 & wait"])
                .spawn()
                .expect("spawning a child"),
        );
        let pid = child.pid();

        if kernel_lists_children() {
            assert!(kernel_children(me).contains(&pid), "kernel child list");
        }
        assert!(
            ppid_links().get(&me).is_some_and(|c| c.contains(&pid)),
            "ppid scan"
        );
        assert!(descendants(me, &HashSet::new()).contains(&pid));
        assert!(!descendants(me, &HashSet::from([pid])).contains(&pid));

        // The grandchild appears once the shell has forked it, which is not instant.
        let forked = std::time::Instant::now();
        let grandchild = loop {
            if let Some(&g) = descendants(pid, &HashSet::new())
                .iter()
                .find(|&&p| p != pid)
            {
                break g;
            }
            assert!(
                forked.elapsed() < Duration::from_secs(30),
                "the child never forked"
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(
            descendants(me, &HashSet::new()).contains(&grandchild),
            "the walk must descend past the root's own children"
        );
        // Skipping the child prunes what is under it, so the grandchild goes too.
        assert!(!descendants(me, &HashSet::from([pid])).contains(&grandchild));
        // Reap only kills the shell, and SIGKILL leaves it no chance to take its own child
        // with it: without this the grandchild lingers on the runner, reparented to init.
        unsafe { libc::kill(grandchild, libc::SIGKILL) };

        // pid 0 is never a process: nothing to walk.
        assert!(descendants(0, &HashSet::new()).is_empty());
    }

    #[test]
    fn tree_sums_the_peaks_of_a_root_and_its_children() {
        let me = std::process::id() as i32;
        let alone = tree(me).expect("this process is running");
        assert!(alone.peak_rss > 0, "the test process has resident memory");

        // Waited on through the child's own `/proc` entry: a total measured against `alone`
        // would be at the mercy of the sibling tests' children, whose peaks join the tree and
        // leave it as they come and go, and a rise this one has to clear can vanish with them.
        let child = hog(64);
        let grown = std::time::Instant::now();
        while mem(child.pid()).is_none_or(|(_, peak)| peak < 32 * 1024 * 1024) {
            assert!(
                grown.elapsed() < Duration::from_secs(30),
                "child never grew"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        // The child's peak is in the total beside this process's own. Both are members of the
        // tree and a peak never falls, so the sum covers the pair whatever else runs alongside
        // — where a tree that did not descend would carry this process alone.
        let (mine, theirs) = (mem(me).unwrap().1, mem(child.pid()).unwrap().1);
        assert!(
            tree(me).unwrap().peak_rss >= mine + theirs,
            "the total must cover this process and its child"
        );
        drop(child);

        // A root that is gone reports nothing rather than a partial figure.
        assert_eq!(tree(0), None);
    }

    /// A meter reports only when it had the process to itself, so the tests that build one
    /// must not run at the same time — the harness runs them as threads of one process.
    /// Poisoning is ignored: a failing test has already reported, and the counters it leaves
    /// behind are exactly what the next test would see anyway.
    static METER_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A meter's first reading. Until the sampler lands a sweep there is nothing to attribute
    /// and the meter says so, so a test that wants a baseline has to wait for one.
    fn first_reading(meter: &Meter) -> Usage {
        let started = std::time::Instant::now();
        loop {
            if let Some(usage) = meter.read() {
                return usage;
            }
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "the sampler never landed a sweep"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn meter_counts_a_child_that_burns_cpu_and_one_that_holds_memory() {
        let _alone = METER_TEST.lock().unwrap_or_else(|e| e.into_inner());
        let me = std::process::id() as i32;
        let meter = Meter::start();
        // A mark only ever rises, so once the first sweep has landed every later read reports.
        let idle = first_reading(&meter);
        let read = || meter.read().expect("the only meter in this process");

        // CPU: a child burning a measurable slice, waited for — its time lands in this
        // process's children rusage, which is how a build's stage guests are accounted.
        let status = std::process::Command::new("sh")
            .args(["-c", "i=0; while [ $i -lt 400000 ]; do i=$((i+1)); done"])
            .status()
            .expect("running a child");
        assert!(status.success());
        assert!(
            read().cpu > idle.cpu,
            "the child's cpu must show up: {:?} vs {idle:?}",
            read()
        );

        // Memory: a child holding ~64 MiB while it lives is only visible to the sampler,
        // since it is killed — like a stage guest — before the meter is read.
        //
        // Both waits are on absolute marks, and the first reads the child's own `/proc` entry
        // rather than the meter. A threshold measured off `idle` would be at the mercy of what
        // the sampler happened to see in it: a sweep covers this test binary and every sibling
        // test's children too, so an `idle` that caught their hogs resident would put a
        // 64 MiB child's rise out of reach — and a mark never falls, so it would stay there.
        const GREW: u64 = 32 * 1024 * 1024;
        let child = hog(64);
        let held = std::time::Instant::now();
        while mem(child.pid()).is_none_or(|(rss, _)| rss < GREW) {
            assert!(held.elapsed() < Duration::from_secs(60), "child never grew");
            std::thread::sleep(Duration::from_millis(50));
        }
        // And a sweep has since totalled it up with this process, which is the whole point of
        // sampling a tree: no per-process reading gives what two held together. Both are tree
        // members and a mark never falls, so one sweep covering the pair is enough. (A sibling
        // test's own hog can only carry the total further, never hold it back.)
        // Recomputed each turn rather than frozen: the shell overshoots while it reads its
        // string in and then falls back, so a target caught at that spike could sit above
        // anything a later sweep sees.
        while read().peak_rss < mem(me).unwrap().0 + mem(child.pid()).unwrap().0 {
            assert!(
                held.elapsed() < Duration::from_secs(60),
                "no sweep ever covered this process and its child together"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        drop(child);

        // Each mark is a maximum over sweeps and the two can come from different ones, so
        // only their ordering is guaranteed here — what a single sweep totals is the
        // business of the test below.
        let after = read();
        assert!(
            after.peak_rss >= after.largest_rss.unwrap(),
            "a total can never be under the largest process in it: {after:?}"
        );
    }

    /// `getrusage` and the process tree are both process-wide, so two phases running at once
    /// cannot be told apart — each must report nothing rather than the other's guests.
    #[test]
    fn overlapping_meters_report_nothing() {
        let _alone = METER_TEST.lock().unwrap_or_else(|e| e.into_inner());
        let first = Meter::start();
        {
            let second = Meter::start();
            // The one that found the process already metered knows immediately.
            assert!(second.read().is_none(), "started inside another meter");
        }
        // And the one that was there first, even though the other has since gone: it was
        // charged for that meter's guests for as long as they overlapped.
        assert!(first.read().is_none(), "another meter ran inside this one");

        // A meter that follows a finished one, rather than overlapping it, reports again.
        drop(first);
        let third = Meter::start();
        first_reading(&third);
    }

    /// The whole point of sweeping: what several processes hold *together*, which no
    /// per-process maximum can give.
    #[test]
    fn a_sweep_totals_every_process_and_names_the_largest() {
        let me = std::process::id() as i32;
        let (one, two) = (hog(64), hog(64));
        let (pid_one, pid_two) = (one.pid(), two.pid());

        // Both children resident *and* settled before measuring. A shell doubling its string
        // holds the old copy alongside the new one, so its RSS overshoots and falls back —
        // comparing one sweep against per-process reads is only meaningful once neither is
        // moving, or the two land on opposite sides of a spike.
        let rss_of = |pid: i32| mem(pid).map_or(0, |(rss, _)| rss);
        let grown = std::time::Instant::now();
        let mut last = [0, 0];
        loop {
            let now = [rss_of(pid_one), rss_of(pid_two)];
            let settled = now
                .iter()
                .zip(&last)
                .all(|(n, l): (&u64, &u64)| *n >= 60 * 1024 * 1024 && n.abs_diff(*l) < 1024 * 1024);
            if settled {
                break;
            }
            assert!(
                grown.elapsed() < Duration::from_secs(60),
                "children never settled: {now:?}"
            );
            last = now;
            std::thread::sleep(Duration::from_millis(100));
        }

        // One pass, so the figures are comparable: the total holds both children at once,
        // where the largest process — this test process, or either child — holds one.
        let (held, biggest) = sweep(me, &HashSet::new());
        let (rss_one, rss_two) = (rss_of(pid_one), rss_of(pid_two));
        assert!(held >= rss_one + rss_two, "both children counted: {held}");
        assert!(biggest >= rss_one.max(rss_two), "largest: {biggest}");
        assert!(
            held >= biggest + rss_one.min(rss_two),
            "the total must exceed its largest process by the other child: {held} vs {biggest}"
        );

        // A skipped pid leaves the total, so a phase is charged for its own processes alone.
        let (without_one, _) = sweep(me, &HashSet::from([pid_one]));
        assert!(without_one < held, "{without_one} vs {held}");
    }

    #[test]
    fn formats_cpu_and_memory_across_the_unit_boundaries() {
        assert_eq!(fmt_cpu(Duration::from_millis(1230)), "1.2s");
        assert_eq!(fmt_cpu(Duration::from_secs(59)), "59.0s");
        assert_eq!(fmt_cpu(Duration::from_secs(134)), "2m14s");
        assert_eq!(fmt_cpu(Duration::from_secs(3600)), "1h00m");
        assert_eq!(fmt_cpu(Duration::from_secs(3840)), "1h04m");
        // Just short of a minute crosses into the minutes form rather than printing "60.0s".
        assert_eq!(fmt_cpu(Duration::from_millis(59_970)), "1m00s");
        // The hour boundary rounds the same way, and never reads "59m60s".
        assert_eq!(fmt_cpu(Duration::from_millis(3_599_700)), "1h00m");

        assert_eq!(fmt_bytes(0), "0 MiB");
        // The first byte count to take the GiB branch still reads as a whole GiB.
        assert_eq!(fmt_bytes(1023 * 1024 * 1024 + 512 * 1024), "1.0 GiB");
        assert_eq!(fmt_bytes(842 * 1024 * 1024), "842 MiB");
        assert_eq!(fmt_bytes(1024 * 1024 * 1024), "1.0 GiB");
        assert_eq!(fmt_bytes(1717986918), "1.6 GiB");
        // Just short of a GiB likewise, rather than printing "1024 MiB".
        assert_eq!(fmt_bytes(1024 * 1024 * 1024 - 1), "1.0 GiB");

        // A job reports one figure; a build adds the largest single process.
        let usage = Usage {
            cpu: Duration::from_secs(134),
            peak_rss: 1717986918,
            largest_rss: None,
        };
        assert_eq!(
            usage.summary("job"),
            "virtkit: job resource usage: cpu 2m14s, peak memory 1.6 GiB"
        );
        assert_eq!(
            Usage {
                largest_rss: Some(900 * 1024 * 1024),
                ..usage
            }
            .summary("build"),
            "virtkit: build resource usage: cpu 2m14s, peak memory 1.6 GiB \
             (largest process 900 MiB)"
        );
        // One guest holding the whole total: the clause would only repeat the figure.
        assert_eq!(
            Usage {
                largest_rss: Some(1717986918),
                ..usage
            }
            .summary("build"),
            "virtkit: build resource usage: cpu 2m14s, peak memory 1.6 GiB"
        );
    }
}
