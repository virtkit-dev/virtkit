//! Idle page-cache trimming, the guest half (see `vk_core::reclaim` for the contract).
//!
//! `init` forks `vk-agent reclaim <spec>` when the kernel cmdline carries `VIRTKIT_RECLAIM`.
//! Two ways to decide what goes, both gated on the guest's memory pressure being low:
//!
//! - **By age** (`auto`, when the kernel exposes the multi-gen LRU's `lru_gen` control file):
//!   every aging interval the loop evicts the oldest generation of file pages, then opens a
//!   new generation. The kernel tracks access itself: mapped pages move up as page-table
//!   scans find them used, and pages read through file descriptors more than once are
//!   protected at eviction time (the multi-gen LRU's tiers), while a page read once sits in
//!   the oldest generation from the start. So a compile's hot headers stay, and what was read
//!   once and not again within an interval drains; there is no amount to guess.
//! - **By floor** (an explicit size or share, or `auto` on a kernel without `lru_gen`): while
//!   the file cache sits above the floor, ask the root cgroup's `memory.reclaim` for a bounded
//!   slice per tick, so a big trim spreads over a minute rather than stalling the guest.
//!
//! Freed pages reach the host through the balloon's free-page reporting, which only looks at
//! free runs of 2 MiB by default — reclaimed pages are scattered, and at that order almost none
//! of them would ever be reported. The loop drops the reporting order to single pages for the
//! ticks right after memory came free (a trim, or a process exiting) and puts it back
//! otherwise, so a busy guest's allocator churn does not pay for re-faulting reported pages.
//!
//! Pressure is `/proc/pressure/memory`'s `some avg10`: the share of the last ten seconds in
//! which some task waited on memory. A guest re-reading what the loop just dropped shows up
//! there and the loop backs off until it stops. The host asks for PSI (`psi=1`) alongside
//! every reclaim knob, so the file is there on the pinned kernel; a `--kernel image` guest
//! whose kernel was built without `CONFIG_PSI` falls back to a `MemAvailable` gate rather
//! than trimming ungated.

use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use log::{debug, info, warn};

const TICK: Duration = Duration::from_secs(10);

/// Ticks between two agings in the by-age mode: how long a page read once has to be read again
/// before it goes. Mapped pages and pages re-read since get two to three of these.
const AGING_TICKS: u32 = 6;

/// `some avg10` above this (percent) is a guest fighting for memory: hold off.
const PRESSURE_MAX: f64 = 1.0;

/// Without PSI, a guest is taken to be fighting for memory once `MemAvailable` drops below
/// this share of its RAM. Far coarser than PSI — most of `MemAvailable` is the very cache the
/// loop is trimming, so it only trips once the guest is already short — but it is a gate.
const AVAILABLE_MIN_PCT: u64 = 10;

/// The most a floor-mode tick reclaims: a sixteenth of the guest's RAM, and at least this much.
const MIN_STEP_MIB: u64 = 64;

/// The most an age-mode eviction takes in one go: a quarter of RAM. What is left of the
/// generation stays the oldest and goes on the next round.
const EVICT_DIVISOR: u64 = 4;

/// Free memory growing by at least this much in a tick is worth reporting page by page.
const REPORT_FREED_MIB: u64 = 32;

/// How long after memory came free single-page reporting stays on.
const REPORT_WINDOW: Duration = Duration::from_secs(30);

/// The root cgroup's reclaim knob on [`Cgroup2`]'s detached mount.
const MEMORY_RECLAIM: &CStr = c"memory.reclaim";

const PRESSURE_FILE: &str = "/proc/pressure/memory";

/// The multi-gen LRU: its switch, and the debugfs control file this loop mounts debugfs for.
const LRU_GEN_ENABLED: &str = "/sys/kernel/mm/lru_gen/enabled";
const LRU_GEN: &str = "/sys/kernel/debug/lru_gen";
const DEBUGFS: &str = "/sys/kernel/debug";

/// The balloon's reporting granularity (`log2` pages): everything, or whatever the kernel
/// booted with (a pageblock, 2 MiB on x86_64 — read at startup rather than assumed, so a
/// different page size or an image kernel gets its own value back).
const REPORT_ORDER_FILE: &str = "/sys/module/page_reporting/parameters/page_reporting_order";
const REPORT_ALL: u32 = 0;
/// The pageblock order to fall back on when the knob cannot be read: x86_64's 2 MiB.
const REPORT_PAGEBLOCKS: u32 = 9;

/// Aging rounds between two cumulative log lines: one an hour, so a guest that runs for days
/// leaves a readable console rather than a line a minute.
const SUMMARY_ROUNDS: u32 = 60;

/// The kernel keeps at most this many multi-gen LRU generations (`MAX_NR_GENS`).
const MAX_GENS: usize = 4;

/// The flag that keeps the trimmer's debugfs mount out of the guest's view.
pub const PRIVATE_MOUNTS: &str = "--private-mounts";

/// Init forks `vk-agent reclaim [--private-mounts] <spec>` with the kernel cmdline value.
/// Errors go to the guest console and boot continues.
pub fn main(args: &[String]) -> i32 {
    let (private, spec) = match args {
        [flag, spec] if flag == PRIVATE_MOUNTS => (true, spec),
        [spec] => (false, spec),
        _ => {
            eprintln!("usage: vk-agent reclaim [{PRIVATE_MOUNTS}] [auto:]<floor_mib>");
            return 2;
        }
    };
    let Some(req) = vk_core::reclaim::parse_cmdline_value(spec) else {
        eprintln!("vk-agent reclaim: {spec:?} is not [auto:]<floor_mib>");
        return 2;
    };
    if private && let Err(e) = private_mount_ns() {
        eprintln!("vk-agent reclaim: {e:#}");
        return 1;
    }
    match run(req) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("vk-agent reclaim: {e:#}");
            1
        }
    }
}

/// The memory figures one tick decides on, in MiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Meminfo {
    total: u64,
    free: u64,
    /// `MemAvailable`: what the kernel thinks a new allocation could get without swapping.
    available: u64,
    /// File cache the kernel could drop: `Cached` + `Buffers` less `Shmem` (tmpfs and shared
    /// memory count as cached but have nowhere to go without swap).
    reclaimable: u64,
}

impl Meminfo {
    fn parse(text: &str) -> Option<Self> {
        let field = |name: &str| -> Option<u64> {
            text.lines()
                .find_map(|l| l.strip_prefix(name))
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|n| n.parse::<u64>().ok())
                .map(|kib| kib / 1024)
        };
        let total = field("MemTotal:")?;
        let free = field("MemFree:")?;
        let available = field("MemAvailable:").unwrap_or(free);
        let cached = field("Cached:")?;
        let buffers = field("Buffers:").unwrap_or(0);
        let shmem = field("Shmem:").unwrap_or(0);
        Some(Meminfo {
            total,
            free,
            available,
            reclaimable: cached.saturating_add(buffers).saturating_sub(shmem),
        })
    }

    fn read() -> Option<Self> {
        std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|t| Self::parse(&t))
    }
}

/// What a floor-mode tick does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Nothing above the floor.
    Idle,
    /// Ask the kernel to drop this many MiB.
    Reclaim(u64),
}

/// The floor-mode decision, kept free of I/O so it can be checked. `reclaimable` counts mapped
/// file pages, which are a running process's working set, and `some avg10` is an average that
/// lags several ticks — so a guest that starts touching what it caches can lose a few steps'
/// worth before the gate trips. The by-age mode has no such exposure and is what the pinned
/// kernel takes; this is the fallback for a kernel without the multi-gen LRU.
fn plan(m: Meminfo, floor_mib: u64) -> Step {
    let excess = m.reclaimable.saturating_sub(floor_mib);
    if excess == 0 {
        return Step::Idle;
    }
    let step = (m.total / 16).max(MIN_STEP_MIB);
    Step::Reclaim(excess.min(step))
}

/// `some avg10` of `/proc/pressure/memory`, in percent. `None` when the kernel has no PSI, or
/// has it compiled out.
fn pressure_some_avg10(text: &str) -> Option<f64> {
    text.lines()
        .find_map(|l| l.strip_prefix("some "))?
        .split_whitespace()
        .find_map(|kv| kv.strip_prefix("avg10="))?
        .parse()
        .ok()
}

/// Memory-pressure gate, selected at startup. Kernels without PSI use the availability
/// fallback so trimming remains gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gate {
    /// `/proc/pressure/memory`, what `psi=1` on the cmdline is for.
    Psi,
    /// No PSI in this kernel: `MemAvailable` against [`AVAILABLE_MIN_PCT`].
    Available,
}

impl Gate {
    fn detect() -> Self {
        match std::fs::read_to_string(PRESSURE_FILE) {
            Ok(t) if pressure_some_avg10(&t).is_some() => Gate::Psi,
            _ => {
                warn!(
                    "vk-agent reclaim: no {PRESSURE_FILE} (kernel built without PSI?); \
                     holding off on MemAvailable instead, which only sees a guest already short"
                );
                Gate::Available
            }
        }
    }

    /// Whether the guest is fighting for memory, so this tick holds off.
    fn pressured(self, m: Meminfo) -> bool {
        match self {
            // Treat a failed read after startup as no pressure; retry in ten seconds.
            Gate::Psi => std::fs::read_to_string(PRESSURE_FILE)
                .ok()
                .and_then(|t| pressure_some_avg10(&t))
                .is_some_and(|p| p > PRESSURE_MAX),
            Gate::Available => m.available < m.total * AVAILABLE_MIN_PCT / 100,
        }
    }
}

/// One generation of an lruvec, as `lru_gen` lists it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Gen {
    seq: u64,
    age_ms: u64,
    /// Pages.
    anon: u64,
    file: u64,
}

/// An `lru_gen` command addresses one memcg on one node. File pages stay charged to the
/// memcg that brought them into cache. A systemd slice or container can therefore hold
/// generations of file pages that eviction from the root lruvec cannot reach.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Lruvec {
    memcg: u32,
    node: u32,
    /// The cgroup path, `/` for the root and empty when memcgs are compiled out.
    path: String,
    /// A removed cgroup, such as a finished systemd unit, can still hold charged pages.
    /// Once listed with id 0, it can be reached through ancestor reclaim but has no
    /// usable `lru_gen` id.
    dying: bool,
    /// Oldest first.
    gens: Vec<Gen>,
}

/// The multi-gen LRU control handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Mglru;

impl Mglru {
    /// Mount debugfs, enable the multi-gen LRU and require a usable lruvec listing.
    /// On failure the caller tries floor-based reclaim.
    fn open() -> Result<Self> {
        // The mount below is the real check: a directory that is already there is fine.
        let _ = std::fs::create_dir_all(DEBUGFS);
        match mount(DEBUGFS, "debugfs") {
            Ok(()) => {}
            // EBUSY: already mounted (the image, or an earlier trimmer). What is wanted.
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {}
            Err(e) => return Err(e).context("mounting debugfs"),
        }
        // `y` is every capability bit, not just the core one: the pinned kernel has none set
        // (no CONFIG_LRU_GEN_ENABLED), and on a distro kernel the wider set is what makes the
        // page-table scan in `age` read accessed bits rather than guess them.
        std::fs::write(LRU_GEN_ENABLED, "y")
            .with_context(|| format!("enabling the multi-gen LRU ({LRU_GEN_ENABLED})"))?;
        if Mglru.lruvecs()?.is_empty() {
            bail!("no usable lruvec in {LRU_GEN}");
        }
        Ok(Mglru)
    }

    /// Read the current lruvecs each round. Services and containers come and go, and
    /// their memcg ids can be reused.
    fn lruvecs(self) -> Result<Vec<Lruvec>> {
        let text =
            std::fs::read_to_string(LRU_GEN).with_context(|| format!("reading {LRU_GEN}"))?;
        Ok(parse_lruvecs(&text))
    }

    fn command(self, cmd: &str) -> io::Result<()> {
        std::fs::write(LRU_GEN, cmd)
    }

    /// Request eviction of the oldest eligible file pages (see [`evict_target`]).
    /// Return the requested page count, or zero if no request was made.
    fn evict_oldest(self, v: &Lruvec, budget: u64) -> io::Result<u64> {
        let Some((seq, pages)) = evict_target(&v.gens, budget) else {
            return Ok(0);
        };
        self.command(&evict_cmd(v.memcg, v.node, seq, pages))?;
        Ok(pages)
    }

    /// Open a generation in `v` for mapped pages the scan finds accessed. Everything
    /// else is one interval older. `force_scan` walks every page table so the accessed bits
    /// are read rather than guessed.
    fn age(self, v: &Lruvec) -> io::Result<()> {
        let Some(newest) = v.gens.last() else {
            return Ok(());
        };
        match self.command(&age_cmd(v.memcg, v.node, newest.seq)) {
            // EEXIST: the kernel aged on its own since we looked. Same outcome.
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
            other => other,
        }
    }
}

/// Target the oldest generation with file pages, up to `budget` pages. The kernel
/// evicts through the named generation, so naming an earlier one reaches no file pages.
/// The two youngest generations are ineligible.
fn evict_target(gens: &[Gen], budget: u64) -> Option<(u64, u64)> {
    let newest = gens.last()?;
    let target = gens.iter().find(|g| g.file > 0)?;
    let pages = target.file.min(budget);
    (target.seq.saturating_add(2) <= newest.seq && pages > 0).then_some((target.seq, pages))
}

/// `- memcg node min_seq swappiness nr_to_reclaim`: evict at most `cap_pages` of generation
/// `seq`. Swappiness 0 is file pages only — the guest has no swap anyway.
fn evict_cmd(memcg: u32, node: u32, seq: u64, cap_pages: u64) -> String {
    format!("- {memcg} {node} {seq} 0 {cap_pages}")
}

/// `+ memcg node max_seq can_swap force_scan`: open a generation past `seq`. `force_scan`
/// walks the page tables, so accessed bits are read rather than guessed.
fn age_cmd(memcg: u32, node: u32, seq: u64) -> String {
    format!("+ {memcg} {node} {seq} 0 1")
}

/// Whether a generation listing is the one to four contiguous sequence numbers the kernel
/// keeps. An empty listing is also accepted and gives the trimmer no target.
fn is_contiguous(gens: &[Gen]) -> bool {
    gens.len() <= MAX_GENS
        && gens
            .windows(2)
            .all(|w| w[1].seq == w[0].seq.saturating_add(1))
}

/// Parse each `memcg <id> <path>` / `node <n>` block. Its `seq age_ms anon file` rows
/// run oldest first. Discard blocks with malformed rows or invalid sequences. Skipping
/// an unreadable oldest row could select a younger, still-warm generation for eviction.
fn parse_lruvecs(text: &str) -> Vec<Lruvec> {
    // The flag records whether every generation row in the block parsed.
    let mut out: Vec<(Lruvec, bool)> = Vec::new();
    // `memcg` holds the enclosing id and path. Either header ends the previous node
    // block so rows after a malformed header cannot attach to it.
    let mut memcg: Option<(u32, &str)> = None;
    let mut in_block = false;
    for line in text.lines() {
        let mut it = line.split_whitespace();
        match it.next() {
            Some("memcg") => {
                in_block = false;
                memcg = it.next().and_then(|s| s.parse::<u32>().ok()).map(|id| {
                    // The path runs to the end of the line; a cgroup name may hold spaces.
                    let rest = line.trim_start().strip_prefix("memcg").unwrap_or("");
                    let path = rest.trim_start().split_once(char::is_whitespace);
                    (id, path.map_or("", |(_, p)| p.trim()))
                });
            }
            Some("node") => {
                in_block = false;
                if let (Some((memcg, path)), Some(node)) =
                    (memcg, it.next().and_then(|s| s.parse::<u32>().ok()))
                {
                    let lruvec = Lruvec {
                        memcg,
                        node,
                        path: path.to_owned(),
                        dying: memcg == 0 && !path.is_empty() && path != "/",
                        gens: Vec::new(),
                    };
                    out.push((lruvec, true));
                    in_block = true;
                }
            }
            Some(seq) => {
                let Some((v, ok)) = out.last_mut().filter(|_| in_block) else {
                    continue;
                };
                let mut nums = std::iter::once(seq)
                    .chain(it)
                    .map(|s| s.parse::<u64>().ok());
                match (nums.next(), nums.next(), nums.next(), nums.next()) {
                    (Some(Some(seq)), Some(Some(age_ms)), Some(Some(anon)), Some(Some(file))) => {
                        v.gens.push(Gen {
                            seq,
                            age_ms,
                            anon,
                            file,
                        })
                    }
                    _ => *ok = false,
                }
            }
            None => {}
        }
    }
    out.into_iter()
        .filter(|(v, ok)| *ok && is_contiguous(&v.gens))
        .map(|(v, _)| v)
        .collect()
}

/// Mount a kernel filesystem using its type as the source and the common mount flags.
fn mount(target: &str, fstype: &str) -> io::Result<()> {
    crate::init::mount(
        fstype,
        target,
        fstype,
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
    )
}

/// Isolate [`run`]'s mounts so the trimmer and image init can each mount `/sys/kernel/debug`.
/// Init attempts to mount `/proc` and `/sys` before forking. The new namespace inherits
/// those mounts if present.
fn private_mount_ns() -> Result<()> {
    // SAFETY: The trimmer is single-threaded and unshare takes only flags.
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        return Err(io::Error::last_os_error()).context("unshare(CLONE_NEWNS)");
    }
    // A copy of a shared mount would still propagate both ways.
    let root = c"/";
    // SAFETY: valid NUL-terminated path; null source/type/data are allowed for a
    // propagation change.
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error()).context("making / private");
    }
    Ok(())
}

/// A detached cgroup2 mount (`fsopen` and `fsmount`) leaves `/sys/fs/cgroup` unchanged for
/// the guest's init and container runtimes.
struct Cgroup2 {
    /// The mount's root directory, which is the hierarchy's root.
    root: OwnedFd,
    /// The root cgroup's open `memory.reclaim` covers the whole hierarchy, including dying
    /// memcgs.
    reclaim: std::fs::File,
    /// Try `swappiness=` (Linux 6.11 and later) until a write returns `EINVAL`.
    swappiness: std::cell::Cell<bool>,
}

impl Cgroup2 {
    /// Mount in a new cgroup namespace. In the initial namespace, omitting `nsdelegate` or
    /// `memory_recursiveprot` would clear those options for the whole hierarchy.
    /// The new namespace starts at the caller's cgroup, so verify it is the hierarchy root.
    /// Returns `Err` without memcg or the mount API introduced in Linux 5.2.
    fn open() -> Result<Self> {
        const FSOPEN_CLOEXEC: libc::c_long = 1;
        const FSCONFIG_CMD_CREATE: libc::c_long = 6;
        const FSMOUNT_CLOEXEC: libc::c_long = 1;
        let fd = |rc: libc::c_long, what: &str| -> Result<OwnedFd> {
            if rc < 0 {
                return Err(io::Error::last_os_error()).context(what.to_owned());
            }
            let rc = libc::c_int::try_from(rc).context("descriptor out of range")?;
            // SAFETY: a fresh descriptor the kernel just returned, owned by nobody else.
            Ok(unsafe { OwnedFd::from_raw_fd(rc) })
        };
        // SAFETY: plain syscall on a single-threaded process.
        if unsafe { libc::unshare(libc::CLONE_NEWCGROUP) } != 0 {
            return Err(io::Error::last_os_error()).context("unshare(CLONE_NEWCGROUP)");
        }
        // SAFETY: the filesystem name is a NUL-terminated string literal.
        let fsfd = fd(
            unsafe { libc::syscall(libc::SYS_fsopen, c"cgroup2".as_ptr(), FSOPEN_CLOEXEC) },
            "fsopen(cgroup2)",
        )?;
        let null = std::ptr::null::<libc::c_char>();
        // SAFETY: FSCONFIG_CMD_CREATE requires a null key and value.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_fsconfig,
                fsfd.as_raw_fd(),
                FSCONFIG_CMD_CREATE,
                null,
                null,
                0,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error())
                .context("fsconfig(cgroup2, FSCONFIG_CMD_CREATE)");
        }
        // SAFETY: fsfd owns the configured filesystem context. The flags are scalar arguments.
        let root = fd(
            unsafe { libc::syscall(libc::SYS_fsmount, fsfd.as_raw_fd(), FSMOUNT_CLOEXEC, 0) },
            "fsmount(cgroup2)",
        )?;
        // Only the real root cgroup lacks `cgroup.type`.
        match openat(&root, c"cgroup.type", libc::O_RDONLY) {
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
            Ok(_) => bail!("this process is not in the root cgroup"),
            Err(e) => return Err(e).context("probing cgroup.type"),
        }
        let reclaim = openat(&root, MEMORY_RECLAIM, libc::O_WRONLY)
            .context("opening the root cgroup's memory.reclaim (no memcg?)")?;
        Ok(Cgroup2 {
            root,
            reclaim: reclaim.into(),
            swappiness: std::cell::Cell::new(true),
        })
    }

    /// Ask the root cgroup to trim `mib` MiB of file cache. `swappiness=0` spares anonymous
    /// pages in guests with swap. If the kernel rejects the key, retry with the byte count
    /// alone and use that form for later requests. Treat `EAGAIN` as success because the
    /// kernel may have reclaimed some pages even though it fell short of the target.
    fn reclaim(&self, mib: u64) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        let bytes = mib.saturating_mul(1024 * 1024);
        loop {
            let swappiness = self.swappiness.get();
            let req = if swappiness {
                format!("{bytes} swappiness=0")
            } else {
                bytes.to_string()
            };
            return match self.reclaim.write_at(req.as_bytes(), 0) {
                Err(e) if swappiness && e.raw_os_error() == Some(libc::EINVAL) => {
                    self.swappiness.set(false);
                    continue;
                }
                Err(e) if e.raw_os_error() != Some(libc::EAGAIN) => Err(e),
                _ => Ok(()),
            };
        }
    }

    /// Debugfs eviction bypasses the kernel's `memory.min` and `memory.low` checks. Leave
    /// a cgroup to kernel reclaim if either setting reads nonzero there or in an ancestor.
    /// Subtrees without a memory controller lack these files. Skip missing or unreadable
    /// settings and continue checking the others.
    fn protected(&self, path: &str) -> bool {
        let mut dir = String::new();
        for part in path.split('/').filter(|p| !p.is_empty()) {
            if !dir.is_empty() {
                dir.push('/');
            }
            dir.push_str(part);
            for knob in ["memory.min", "memory.low"] {
                let Ok(rel) = CString::new(format!("{dir}/{knob}")) else {
                    return true;
                };
                let Ok(f) = openat(&self.root, &rel, libc::O_RDONLY) else {
                    continue;
                };
                let mut text = String::new();
                if io::Read::read_to_string(&mut std::fs::File::from(f), &mut text).is_ok()
                    && text.trim() != "0"
                {
                    return true;
                }
            }
        }
        false
    }
}

/// `openat` below `dir`, close-on-exec.
fn openat(dir: &OwnedFd, rel: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: a valid directory fd and a NUL-terminated relative path.
    let rc = unsafe { libc::openat(dir.as_raw_fd(), rel.as_ptr(), flags | libc::O_CLOEXEC) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh descriptor the kernel just returned, owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(rc) })
}

enum Mode {
    /// Without the cgroup2 handle, age live file cache without checking memory
    /// protections or reclaiming cache from removed cgroups.
    Age(Mglru, Option<Cgroup2>),
    Floor(u64, Cgroup2),
}

fn run(req: vk_core::reclaim::Request) -> Result<()> {
    let mglru = if req.by_age {
        match Mglru::open() {
            Ok(m) => {
                info!(
                    "vk-agent reclaim: evicting file cache not re-read within {}s (multi-gen LRU)",
                    u64::from(AGING_TICKS) * TICK.as_secs()
                );
                Some(m)
            }
            Err(e) => {
                warn!(
                    "vk-agent reclaim: no multi-gen LRU control ({e:#}); trimming to a {} MiB floor",
                    req.floor_mib
                );
                None
            }
        }
    } else {
        info!(
            "vk-agent reclaim: trimming file cache above {} MiB when idle",
            req.floor_mib
        );
        None
    };
    let mode = match (mglru, Cgroup2::open()) {
        (Some(m), Ok(cg)) => Mode::Age(m, Some(cg)),
        (Some(m), Err(e)) => {
            warn!(
                "vk-agent reclaim: {e:#}; aging file cache without checking cgroup protections \
                 or reclaiming cache from removed cgroups"
            );
            Mode::Age(m, None)
        }
        (None, cg) => Mode::Floor(req.floor_mib, cg?),
    };
    // Paths seen dying in the previous round (see `drainable_pages`).
    let mut dying = HashSet::new();

    let gate = Gate::detect();
    let mut reporter = Reporter::new();
    let mut rounds: u32 = 0;
    let mut cumulative: u64 = 0;
    let mut tick: u32 = 0;
    let mut last_free = Meminfo::read().map(|m| m.free);
    loop {
        std::thread::sleep(TICK);
        tick = tick.wrapping_add(1);
        let Some(before) = Meminfo::read() else {
            continue;
        };
        let hold = gate.pressured(before);
        // Memory that came free since the last look — a process exiting, say — is worth
        // reporting page by page even when the loop itself frees nothing this tick.
        let grew = before.free.saturating_sub(last_free.unwrap_or(before.free));
        if grew >= REPORT_FREED_MIB {
            reporter.freed(grew);
        }

        let mut freed = 0;
        if hold {
            debug!(
                "vk-agent reclaim: holding (memory pressure), {} MiB cached",
                before.reclaimable
            );
        } else {
            match &mode {
                Mode::Age(mglru, cg) if tick.is_multiple_of(AGING_TICKS) => {
                    freed = age_round(*mglru, cg.as_ref(), before, &mut dying);
                    rounds += 1;
                    cumulative += freed;
                    if rounds.is_multiple_of(SUMMARY_ROUNDS) {
                        info!(
                            "vk-agent reclaim: {cumulative} MiB given back over {rounds} rounds, \
                             {} MiB cached",
                            before.reclaimable.saturating_sub(freed)
                        );
                    }
                }
                Mode::Age(..) => {}
                Mode::Floor(floor_mib, cg) => {
                    if let Step::Reclaim(mib) = plan(before, *floor_mib) {
                        debug!("vk-agent reclaim: asking for {mib} MiB");
                        match cg.reclaim(mib) {
                            Ok(()) => freed = freed_since(before),
                            Err(e) => warn!(
                                "vk-agent reclaim: {}: {e}",
                                MEMORY_RECLAIM.to_string_lossy()
                            ),
                        }
                    }
                }
            }
        }
        if freed > 0 {
            reporter.freed(freed);
        }
        reporter.apply(hold);
        last_free = Meminfo::read().map(|m| m.free);
    }
}

/// MiB of free memory gained since `before` was read.
fn freed_since(before: Meminfo) -> u64 {
    Meminfo::read()
        .map(|m| m.free.saturating_sub(before.free))
        .unwrap_or(0)
}

/// Evict old file pages and age eligible live lruvecs. Use the remaining budget for
/// root reclaim based on removed paths seen in consecutive rounds. Return the observed
/// increase in free MiB after a successful request.
fn age_round(
    mglru: Mglru,
    cg: Option<&Cgroup2>,
    before: Meminfo,
    dying: &mut HashSet<String>,
) -> u64 {
    let lruvecs = match mglru.lruvecs() {
        Ok(v) => v,
        Err(e) => {
            warn!("vk-agent reclaim: {e:#}");
            return 0;
        }
    };
    // The round's budget across every lruvec, MiB → 4 KiB pages.
    let mut budget = (before.total / EVICT_DIVISOR).max(MIN_STEP_MIB) * 256;
    let started = Instant::now();
    let mut evicted = false;
    let live = lruvecs
        .iter()
        .filter(|v| !v.dying && v.gens.iter().any(|g| g.file > 0))
        .filter(|v| !cg.is_some_and(|cg| cg.protected(&v.path)));
    for v in live {
        // A memcg removed after the listing can return `EINVAL`.
        match mglru.evict_oldest(v, budget) {
            Ok(asked) => {
                budget -= asked;
                evicted |= asked > 0;
            }
            Err(e) => debug!("vk-agent reclaim: evicting from memcg {}: {e}", v.memcg),
        }
        if let Err(e) = mglru.age(v) {
            debug!("vk-agent reclaim: aging memcg {}: {e}", v.memcg);
        }
    }
    // Neither interface can target dying memcgs alone. The eviction above skips them, and
    // the kernel demotes offlined memcgs, so root reclaim tends to reach them early. Its
    // scan starts in a random bin and can take old pages from live memcgs too. Eligible
    // dying pages and the remaining budget cap the request. Pressure suspends the round.
    let dying_mib = drainable_pages(&lruvecs, dying).min(budget) / 256;
    if let Some(cg) = cg
        && dying_mib > 0
    {
        match cg.reclaim(dying_mib) {
            Ok(()) => evicted = true,
            Err(e) => warn!(
                "vk-agent reclaim: {}: {e}",
                MEMORY_RECLAIM.to_string_lossy()
            ),
        }
    }
    let freed = if evicted { freed_since(before) } else { 0 };
    debug!(
        "vk-agent reclaim: free memory gained {freed} MiB, {} lruvecs listed ({dying_mib} MiB \
         eligible for root reclaim) in {}ms, estimated {} MiB cached",
        lruvecs.len(),
        started.elapsed().as_millis(),
        before.reclaimable.saturating_sub(freed)
    );
    freed
}

/// Count file pages at dying paths seen in both rounds, then replace `prev` with this
/// round's paths. Dying memcgs lack a usable id. Waiting a round before counting a new
/// path gives another cgroup time to read its cache again.
fn drainable_pages(lruvecs: &[Lruvec], prev: &mut HashSet<String>) -> u64 {
    let now: HashSet<String> = lruvecs
        .iter()
        .filter(|v| v.dying)
        .map(|v| v.path.clone())
        .collect();
    let pages = lruvecs
        .iter()
        .filter(|v| v.dying && prev.contains(&v.path))
        .flat_map(|v| &v.gens)
        .map(|g| g.file)
        .sum();
    *prev = now;
    pages
}

/// The free-page reporting order: single pages for a while after memory came free, whole
/// pageblocks otherwise (and whenever the guest is under pressure).
struct Reporter {
    all_until: Option<Instant>,
    current: Option<u32>,
    /// Restore the kernel's startup pageblock order for its page size, without assuming
    /// x86_64.
    default_order: u32,
    warned: bool,
}

impl Reporter {
    fn new() -> Self {
        let default_order = std::fs::read_to_string(REPORT_ORDER_FILE)
            .ok()
            .and_then(|t| t.trim().parse().ok())
            .unwrap_or(REPORT_PAGEBLOCKS);
        Reporter {
            all_until: None,
            current: None,
            default_order,
            warned: false,
        }
    }

    fn freed(&mut self, mib: u64) {
        debug!("vk-agent reclaim: {mib} MiB came free, reporting single pages");
        self.all_until = Some(Instant::now() + REPORT_WINDOW);
    }

    fn apply(&mut self, hold: bool) {
        let want = match self.all_until {
            Some(until) if !hold && Instant::now() < until => REPORT_ALL,
            _ => self.default_order,
        };
        if self.current == Some(want) {
            return;
        }
        // Write only when the order changes; warn once if the kernel lacks the knob.
        match std::fs::write(REPORT_ORDER_FILE, want.to_string()) {
            Ok(()) => self.current = Some(want),
            Err(e) if !self.warned => {
                warn!("vk-agent reclaim: setting {REPORT_ORDER_FILE}: {e}");
                self.warned = true;
            }
            Err(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MEMINFO: &str = "MemTotal:        8157864 kB\n\
                           MemFree:         2891452 kB\n\
                           MemAvailable:    7967248 kB\n\
                           Buffers:           12428 kB\n\
                           Cached:          5139428 kB\n\
                           Shmem:              7068 kB\n";

    /// What the 6.18 kernel prints: `memcg %5hu %s`, ` node %5d`, then per generation
    /// ` %10lu %10u %10lu%c %10lu%c` (seq, age ms, anon pages, file pages). This is a guest
    /// with memcgs on, so the whole-guest root is `memcg 1 /` and a service slice follows it.
    const LRU_GEN: &str = "memcg     1 /\n\
                           \x20node     0\n\
                           \x20        12     183042        512     262144 \n\
                           \x20        13     122031       1024      65536 \n\
                           \x20        14      61020       2048       8192 \n\
                           \x20        15         10       4096        128 \n\
                           memcg    27 /system.slice/foo\n\
                           \x20node     0\n\
                           \x20         2       9000          1          2 \n\
                           \x20         3       1000          3          4 \n";

    /// The other shape: memcgs compiled out, so the kernel prints the one id-0 entry with an
    /// empty path. A guest can be listed as one or the other, never as both.
    const LRU_GEN_NO_MEMCG: &str = "memcg     0 \n\
                                    \x20node     0\n\
                                    \x20        12     183042        512     262144 \n\
                                    \x20        13         10       4096        128 \n";

    #[test]
    fn meminfo_counts_droppable_file_cache() {
        let m = Meminfo::parse(MEMINFO).unwrap();
        assert_eq!(m.total, 7966);
        assert_eq!(m.free, 2823);
        assert_eq!(m.available, 7780);
        // Cached + Buffers - Shmem, in MiB.
        assert_eq!(m.reclaimable, 5018 + 12 - 6);
        assert_eq!(Meminfo::parse("MemFree: 1 kB\n"), None);
        // A kernel too old for MemAvailable: MemFree is the honest floor for it.
        let no_avail = MEMINFO.replace("MemAvailable:    7967248 kB\n", "");
        assert_eq!(Meminfo::parse(&no_avail).unwrap().available, 2823);
    }

    #[test]
    fn the_memavailable_gate_only_trips_on_a_guest_already_short() {
        let m = |available| Meminfo {
            total: 8192,
            free: available,
            available,
            reclaimable: 0,
        };
        assert!(Gate::Available.pressured(m(800)));
        assert!(!Gate::Available.pressured(m(820)));
        assert!(!Gate::Available.pressured(m(4096)));
    }

    #[test]
    fn pressure_reads_some_avg10() {
        let psi = "some avg10=0.35 avg60=0.10 avg300=0.02 total=123456\n\
                   full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
        assert_eq!(pressure_some_avg10(psi), Some(0.35));
        assert_eq!(pressure_some_avg10(""), None);
        // A kernel with PSI compiled out has no `some` line at all, which is what picks the
        // MemAvailable gate rather than trimming ungated.
        assert_eq!(pressure_some_avg10("full avg10=0.00\n"), None);
    }

    #[test]
    fn a_floor_tick_trims_a_bounded_slice_of_the_excess() {
        let m = Meminfo {
            total: 8192,
            free: 100,
            available: 5100,
            reclaimable: 5000,
        };
        // A sixteenth of RAM per tick, never the whole excess at once.
        assert_eq!(plan(m, 512), Step::Reclaim(512));
        // The last slice is whatever is left above the floor.
        let near = Meminfo {
            total: 8192,
            free: 100,
            available: 700,
            reclaimable: 600,
        };
        assert_eq!(plan(near, 512), Step::Reclaim(88));
        assert_eq!(plan(near, 600), Step::Idle);
        assert_eq!(plan(near, 1024), Step::Idle);
        // Small guests still make progress.
        let small = Meminfo {
            total: 512,
            free: 100,
            available: 500,
            reclaimable: 400,
        };
        assert_eq!(plan(small, 64), Step::Reclaim(64));
    }

    #[test]
    fn lru_gen_lists_every_memcg_and_node_oldest_first() {
        // A systemd slice can hold file cache outside the root's generations.
        let v = parse_lruvecs(LRU_GEN);
        assert_eq!(
            v.iter().map(|v| (v.memcg, v.node)).collect::<Vec<_>>(),
            [(1, 0), (27, 0)]
        );
        assert_eq!(v[0].gens.len(), 4);
        assert_eq!(
            v[0].gens[0],
            Gen {
                seq: 12,
                age_ms: 183042,
                anon: 512,
                file: 262144
            }
        );
        assert_eq!(v[0].gens[3].seq, 15);
        assert_eq!(v[1].gens.len(), 2);
        // The memcg-less shape reads the same way, under id 0.
        let v = parse_lruvecs(LRU_GEN_NO_MEMCG);
        assert_eq!((v[0].memcg, v[0].node, v[0].gens.len()), (0, 0, 2));
        assert!(parse_lruvecs("nothing here\n").is_empty());
        assert!(!parse_lruvecs(LRU_GEN).iter().any(|v| v.dying));
        assert!(!parse_lruvecs(LRU_GEN_NO_MEMCG)[0].dying);
    }

    #[test]
    fn a_removed_cgroup_is_drained_once_it_has_been_dying_for_a_round() {
        // A finished oneshot unit: its id is gone, its pages are not.
        let readbig = "memcg     0 /system.slice/readbig.service\n\
                       \x20node     0\n\
                       \x20         1     312728          0     153601 \n";
        let v = parse_lruvecs(&format!("{LRU_GEN}{readbig}"));
        assert_eq!(
            v.iter()
                .map(|v| (v.memcg, v.path.as_str(), v.dying))
                .collect::<Vec<_>>(),
            [
                (1, "/", false),
                (27, "/system.slice/foo", false),
                (0, "/system.slice/readbig.service", true)
            ]
        );
        let mut prev = HashSet::new();
        // First sighting starts the grace period.
        assert_eq!(drainable_pages(&v, &mut prev), 0);
        // A second sighting makes those pages eligible.
        assert_eq!(drainable_pages(&v, &mut prev), 153601);
        // A different path starts a new grace period.
        let other = readbig.replace("readbig", "other");
        let v2 = parse_lruvecs(&format!("{LRU_GEN}{other}"));
        assert_eq!(drainable_pages(&v2, &mut prev), 0);
        assert_eq!(drainable_pages(&parse_lruvecs(LRU_GEN), &mut prev), 0);
    }

    #[test]
    fn a_header_that_does_not_read_takes_its_rows_with_it() {
        // Rows after a malformed header could corrupt the preceding sequence.
        // Here row 14 would silently extend memcg 0's rows 12 and 13.
        let text = format!(
            "{LRU_GEN_NO_MEMCG}memcg     x /broken\n\
                            \x20node     0\n\
                            \x20        14         10          0         64 \n"
        );
        let v = parse_lruvecs(&text);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].gens.len(), 2);
        let text = format!(
            "{LRU_GEN_NO_MEMCG}\x20node     z\n\
                            \x20        14         10          0         64 \n"
        );
        assert_eq!(parse_lruvecs(&text)[0].gens.len(), 2);
    }

    #[test]
    fn eviction_targets_the_oldest_generation_holding_file_pages() {
        let gens = |files: &[u64]| -> Vec<Gen> {
            files
                .iter()
                .zip(10..)
                .map(|(&file, seq)| Gen {
                    seq,
                    age_ms: 0,
                    anon: 1,
                    file,
                })
                .collect()
        };
        assert_eq!(
            evict_target(&gens(&[100, 50, 10, 1]), 1000),
            Some((10, 100))
        );
        // An anon-only oldest generation: naming it would evict nothing.
        assert_eq!(evict_target(&gens(&[0, 50, 10, 1]), 1000), Some((11, 50)));
        assert_eq!(evict_target(&gens(&[100, 50, 10, 1]), 30), Some((10, 30)));
        assert_eq!(evict_target(&gens(&[100, 50, 10, 1]), 0), None);
        // The two youngest are never old enough.
        assert_eq!(evict_target(&gens(&[0, 0, 10, 1]), 1000), None);
        assert_eq!(evict_target(&gens(&[5, 1]), 1000), None);
        assert_eq!(evict_target(&[], 1000), None);
    }

    #[test]
    fn a_gappy_generation_listing_is_refused() {
        let seqs = |seqs: &[u64]| -> Vec<Gen> {
            seqs.iter()
                .map(|&seq| Gen {
                    seq,
                    age_ms: 0,
                    anon: 0,
                    file: 0,
                })
                .collect()
        };
        assert!(is_contiguous(&[]));
        assert!(is_contiguous(&seqs(&[12, 13, 14, 15])));
        // A line the parser could not read leaves a hole: `first()` would no longer be the
        // oldest generation, and evicting it would take pages that are still warm.
        assert!(!is_contiguous(&seqs(&[12, 14])));
        // More generations than the kernel keeps means we are not reading what we think.
        assert!(!is_contiguous(&seqs(&[12, 13, 14, 15, 16])));
        // An unreadable first row invalidates only its block, even when the remaining
        // rows are contiguous.
        let bad = LRU_GEN.replace("        12     183042", "        zz     183042");
        let v = parse_lruvecs(&bad);
        assert_eq!(v.iter().map(|v| v.memcg).collect::<Vec<_>>(), [27]);
    }

    #[test]
    fn lru_gen_commands_are_the_format_the_kernel_parses() {
        // `- memcg node min_seq swappiness nr_to_reclaim`, swappiness 0 = file pages only.
        assert_eq!(evict_cmd(1, 0, 12, 262144), "- 1 0 12 0 262144");
        // `+ memcg node max_seq can_swap force_scan`.
        assert_eq!(age_cmd(1, 0, 15), "+ 1 0 15 0 1");
    }
}
