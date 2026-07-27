//! What a job cost the runner: the CPU time and peak memory its microVM and the host
//! helpers around it consumed, read from `/proc` for the end-of-job trace line.
//!
//! The job's **run** phase is exactly the supervisor's tree — the VMM, the service VMs,
//! the switch, the virtiofsds, the forwards are all its tied children — so descending
//! from the supervisor pid covers that phase and nothing outside it. What the job cost the
//! host before the supervisor existed (prepare's checkout and image build) and the stage
//! driver reading this out are outside the tree and go uncounted. The tree is read live,
//! from a `run` stage: the supervisor is detached and no stage waits for it, so there is
//! no `rusage` to collect, and by the time it is reaped (cleanup) the job trace is
//! already closed.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

/// The host resources some work used.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    /// User + system CPU time, guest execution included: KVM accounts the time a vCPU
    /// thread spends running the guest into the VMM process's user time.
    pub cpu: Duration,
    /// The most resident memory the work held at one time, in bytes. A high-water mark, not
    /// the memory left at the end: a guest hands freed RAM straight back to the host (free
    /// page reporting), so the live figure says little about the demand it passed through.
    /// How closely the mark is known depends on how it was taken — see [`tree`].
    pub peak_rss: u64,
}

impl Usage {
    /// The job-trace line: `virtkit: job resource usage: cpu 2m14s, peak memory 1.6 GiB`.
    pub fn summary(&self) -> String {
        format!(
            "virtkit: job resource usage: cpu {}, peak memory {}",
            fmt_cpu(self.cpu),
            fmt_bytes(self.peak_rss),
        )
    }
}

/// The usage of `root` and every process descending from it, summed — including their peak
/// memory, so two that never peaked together read as an upper bound on what the tree held at
/// once. `None` when `root` is gone: a job whose supervisor already died reports nothing
/// rather than a partial figure.
pub fn tree(root: i32) -> Option<Usage> {
    let pids = descendants(root);
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

/// `root` and every process descending from it, in no particular order. Empty when `root`
/// itself is gone.
fn descendants(root: i32) -> Vec<i32> {
    if stat(root).is_none() {
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
            if !out.contains(&child) {
                out.push(child);
            }
        }
    }
    out
}

/// One process's direct children, from the kernel's own lists. A child is recorded under the
/// thread that forked it, so this reads one small file per thread — a handful of reads against
/// the whole-of-`/proc` scan [`ppid_links`] needs to derive the same links.
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
    /// stands in for them — must find a child this process spawned, and the walk must carry
    /// on past that first level: a job's deeper helpers are why it descends at all.
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
        assert!(descendants(me).contains(&pid));

        // The grandchild appears once the shell has forked it, which is not instant.
        let forked = std::time::Instant::now();
        let grandchild = loop {
            if let Some(&g) = descendants(pid).iter().find(|&&p| p != pid) {
                break g;
            }
            assert!(
                forked.elapsed() < Duration::from_secs(30),
                "the child never forked"
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(
            descendants(me).contains(&grandchild),
            "the walk must descend past the root's own children"
        );
        // Reap only kills the shell, and SIGKILL leaves it no chance to take its own child
        // with it: without this the grandchild lingers on the runner, reparented to init.
        unsafe { libc::kill(grandchild, libc::SIGKILL) };

        // pid 0 is never a process: nothing to walk.
        assert!(descendants(0).is_empty());
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

        assert_eq!(
            Usage {
                cpu: Duration::from_secs(134),
                peak_rss: 1717986918,
            }
            .summary(),
            "virtkit: job resource usage: cpu 2m14s, peak memory 1.6 GiB"
        );
    }
}
