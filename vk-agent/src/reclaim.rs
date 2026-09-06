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

use std::io;
use std::path::Path;
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

/// The cgroup2 hierarchy the floor mode's reclaim knob lives in. Mounted only for that mode:
/// an `auto` guest on the pinned kernel never takes this path, and mounting cgroup2 in every
/// guest would change what an in-guest container runtime finds under `/sys/fs/cgroup`.
const CGROUP2: &str = "/sys/fs/cgroup";
const MEMORY_RECLAIM: &str = "/sys/fs/cgroup/memory.reclaim";

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

/// CLI entry for the loop `init` forks (`vk-agent reclaim <spec>`, the cmdline value). Errors
/// go to the console: a guest that cannot trim still runs.
pub fn main(args: &[String]) -> i32 {
    let [spec] = args else {
        eprintln!("usage: vk-agent reclaim [auto:]<floor_mib>");
        return 2;
    };
    let Some(req) = vk_core::reclaim::parse_cmdline_value(spec) else {
        eprintln!("vk-agent reclaim: {spec:?} is not [auto:]<floor_mib>");
        return 2;
    };
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

/// One generation of the root memcg's LRU, as `lru_gen` lists it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Gen {
    seq: u64,
    age_ms: u64,
    /// Pages.
    anon: u64,
    file: u64,
}

/// The multi-gen LRU control handle: the root memcg and node the commands address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Mglru {
    memcg: u32,
    node: u32,
}

impl Mglru {
    /// Mount debugfs, switch the multi-gen LRU on and find the root memcg. `Err` on a kernel
    /// without any of it — the caller falls back to the floor.
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
        let text =
            std::fs::read_to_string(LRU_GEN).with_context(|| format!("reading {LRU_GEN}"))?;
        let (memcg, node) = parse_root(&text).context("no root memcg in lru_gen")?;
        Ok(Mglru { memcg, node })
    }

    /// The root memcg's generations on our node, oldest first. A listing that does not come
    /// back as the kernel's one-to-four contiguous sequence numbers is refused rather than
    /// acted on: a line dropped by [`parse_gens`] would leave `first()` a generation younger
    /// than the oldest, and `evict_oldest` would then evict pages that are still warm.
    fn gens(&self) -> Result<Vec<Gen>> {
        let text =
            std::fs::read_to_string(LRU_GEN).with_context(|| format!("reading {LRU_GEN}"))?;
        let gens = parse_gens(&text, self.memcg, self.node);
        if !is_contiguous(&gens) {
            bail!(
                "unreadable {LRU_GEN} listing for memcg {} node {}",
                self.memcg,
                self.node
            );
        }
        Ok(gens)
    }

    fn command(&self, cmd: &str) -> io::Result<()> {
        std::fs::write(LRU_GEN, cmd)
    }

    /// Evict the oldest generation of file pages, at most `cap_pages` of it. The kernel keeps
    /// the two youngest generations whatever is asked; with fewer than three there is
    /// nothing old enough to evict yet. `Ok(false)` when nothing was asked for.
    fn evict_oldest(&self, gens: &[Gen], cap_pages: u64) -> io::Result<bool> {
        let (Some(oldest), Some(newest)) = (gens.first(), gens.last()) else {
            return Ok(false);
        };
        if oldest.seq.saturating_add(2) > newest.seq {
            return Ok(false);
        }
        self.command(&evict_cmd(self.memcg, self.node, oldest.seq, cap_pages))?;
        Ok(true)
    }

    /// Open a new generation: the pages accessed from now on land in it, and everything
    /// else is one interval older. `force_scan` walks every page table so the accessed bits
    /// are read rather than guessed.
    fn age(&self, gens: &[Gen]) -> io::Result<()> {
        let Some(newest) = gens.last() else {
            return Ok(());
        };
        match self.command(&age_cmd(self.memcg, self.node, newest.seq)) {
            // EEXIST: the kernel aged on its own since we looked. Same outcome.
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
            other => other,
        }
    }
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
/// keeps. Empty is fine: a guest that has not faulted anything in yet.
fn is_contiguous(gens: &[Gen]) -> bool {
    gens.len() <= MAX_GENS
        && gens
            .windows(2)
            .all(|w| w[1].seq == w[0].seq.saturating_add(1))
}

/// The `memcg <id> <path>` line of the root cgroup (path `/`, or the lone id-0 entry when
/// memcgs are off) and the first `node <n>` under it.
fn parse_root(text: &str) -> Option<(u32, u32)> {
    let mut lines = text.lines();
    let memcg = lines.by_ref().find_map(|l| {
        let mut it = l.split_whitespace();
        if it.next()? != "memcg" {
            return None;
        }
        let id: u32 = it.next()?.parse().ok()?;
        let path = it.next().unwrap_or("");
        (path == "/" || path.is_empty()).then_some(id)
    })?;
    let node = lines.find_map(|l| {
        let mut it = l.split_whitespace();
        (it.next()? == "node").then(|| it.next()?.parse().ok())?
    })?;
    Some((memcg, node))
}

/// The generation lines under `memcg <id>` / `node <n>`: `seq age_ms anon file`, in the order
/// the kernel prints them (oldest first).
fn parse_gens(text: &str, memcg: u32, node: u32) -> Vec<Gen> {
    let mut out = Vec::new();
    let (mut in_memcg, mut in_node) = (false, false);
    for line in text.lines() {
        let mut it = line.split_whitespace();
        match it.next() {
            Some("memcg") => {
                in_memcg = it.next().and_then(|s| s.parse::<u32>().ok()) == Some(memcg);
                in_node = false;
            }
            Some("node") => {
                in_node = in_memcg && it.next().and_then(|s| s.parse::<u32>().ok()) == Some(node);
            }
            Some(seq) if in_node => {
                let mut nums = std::iter::once(seq)
                    .chain(it)
                    .map(|s| s.parse::<u64>().ok());
                if let (Some(Some(seq)), Some(Some(age_ms)), Some(Some(anon)), Some(Some(file))) =
                    (nums.next(), nums.next(), nums.next(), nums.next())
                {
                    out.push(Gen {
                        seq,
                        age_ms,
                        anon,
                        file,
                    });
                }
            }
            _ => {}
        }
    }
    out
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

/// Mount cgroup2 for floor-mode reclaim; accept an existing mount from the image or a prior
/// trimmer.
fn mount_cgroup2() -> io::Result<()> {
    std::fs::create_dir_all(CGROUP2)?;
    match mount(CGROUP2, "cgroup2") {
        Err(e) if e.raw_os_error() == Some(libc::EBUSY) => Ok(()),
        other => other,
    }
}

enum Mode {
    Age(Mglru),
    Floor(u64),
}

fn run(req: vk_core::reclaim::Request) -> Result<()> {
    let mode = if req.by_age {
        match Mglru::open() {
            Ok(m) => {
                info!(
                    "vk-agent reclaim: evicting file cache not re-read within {}s (multi-gen LRU)",
                    u64::from(AGING_TICKS) * TICK.as_secs()
                );
                Mode::Age(m)
            }
            Err(e) => {
                warn!(
                    "vk-agent reclaim: no multi-gen LRU control ({e:#}); trimming to a {} MiB floor",
                    req.floor_mib
                );
                Mode::Floor(req.floor_mib)
            }
        }
    } else {
        info!(
            "vk-agent reclaim: trimming file cache above {} MiB when idle",
            req.floor_mib
        );
        Mode::Floor(req.floor_mib)
    };
    if matches!(mode, Mode::Floor(_)) {
        mount_cgroup2().context("mounting cgroup2 for the floor mode's memory.reclaim")?;
        if !Path::new(MEMORY_RECLAIM).exists() {
            bail!("{MEMORY_RECLAIM} is missing (no memcg in this kernel)");
        }
    }

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
                Mode::Age(mglru) if tick.is_multiple_of(AGING_TICKS) => {
                    freed = age_round(mglru, before);
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
                Mode::Age(_) => {}
                Mode::Floor(floor_mib) => {
                    if let Step::Reclaim(mib) = plan(before, *floor_mib) {
                        debug!("vk-agent reclaim: asking for {mib} MiB");
                        match reclaim(mib) {
                            Ok(()) => freed = freed_since(before),
                            Err(e) => warn!("vk-agent reclaim: {MEMORY_RECLAIM}: {e}"),
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

/// One by-age round: evict the oldest generation (bounded), then open a new one. Returns the
/// MiB that came free.
fn age_round(mglru: &Mglru, before: Meminfo) -> u64 {
    let gens = match mglru.gens() {
        Ok(g) => g,
        Err(e) => {
            warn!("vk-agent reclaim: {e:#}");
            return 0;
        }
    };
    // MiB → 4 KiB pages.
    let cap_pages = (before.total / EVICT_DIVISOR).max(MIN_STEP_MIB) * 256;
    let started = Instant::now();
    let evicted = match mglru.evict_oldest(&gens, cap_pages) {
        Ok(asked) => asked,
        Err(e) => {
            warn!("vk-agent reclaim: evicting the oldest generation: {e}");
            false
        }
    };
    let freed = if evicted { freed_since(before) } else { 0 };
    if let Err(e) = mglru.age(&gens) {
        warn!("vk-agent reclaim: aging: {e}");
    }
    let oldest_s = gens.first().map(|g| g.age_ms / 1000).unwrap_or(0);
    debug!(
        "vk-agent reclaim: evicted {freed} MiB from the {oldest_s}s-old generation in {}ms, \
         {} MiB cached",
        started.elapsed().as_millis(),
        before.reclaimable.saturating_sub(freed)
    );
    freed
}

/// Ask the root cgroup to reclaim `mib`. The kernel answers `EAGAIN` when it fell short of the
/// amount (what it did reclaim is gone all the same), so that is not an error here.
fn reclaim(mib: u64) -> io::Result<()> {
    let bytes = mib.saturating_mul(1024 * 1024);
    match std::fs::write(MEMORY_RECLAIM, bytes.to_string()) {
        Err(e) if e.raw_os_error() != Some(libc::EAGAIN) => Err(e),
        _ => Ok(()),
    }
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
    fn lru_gen_root_is_the_first_root_like_memcg() {
        // Either shape is the whole guest: a `/` path with memcgs on, an empty one without.
        // A slice like /system.slice/foo is neither, so it is never taken for the root.
        assert_eq!(parse_root(LRU_GEN), Some((1, 0)));
        assert_eq!(parse_root(LRU_GEN_NO_MEMCG), Some((0, 0)));
        assert_eq!(
            parse_root("memcg    27 /system.slice/foo\n node     0\n"),
            None
        );
        assert_eq!(parse_root("nothing here\n"), None);
    }

    #[test]
    fn lru_gen_generations_are_read_oldest_first_for_the_addressed_memcg() {
        let gens = parse_gens(LRU_GEN, 1, 0);
        assert_eq!(gens.len(), 4);
        assert_eq!(
            gens[0],
            Gen {
                seq: 12,
                age_ms: 183042,
                anon: 512,
                file: 262144
            }
        );
        assert_eq!(gens[3].seq, 15);
        // Another memcg's lines are not ours, nor another node's.
        assert_eq!(parse_gens(LRU_GEN, 27, 0).len(), 2);
        assert!(parse_gens(LRU_GEN, 1, 1).is_empty());
        // The memcg-less shape reads the same way, under id 0.
        assert_eq!(parse_gens(LRU_GEN_NO_MEMCG, 0, 0).len(), 2);
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
    }

    #[test]
    fn lru_gen_commands_are_the_format_the_kernel_parses() {
        // `- memcg node min_seq swappiness nr_to_reclaim`, swappiness 0 = file pages only.
        assert_eq!(evict_cmd(1, 0, 12, 262144), "- 1 0 12 0 262144");
        // `+ memcg node max_seq can_swap force_scan`.
        assert_eq!(age_cmd(1, 0, 15), "+ 1 0 15 0 1");
    }
}
