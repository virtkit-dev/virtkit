//! Admission for CI jobs: a host-wide ledger that keeps a runner from committing more guest
//! RAM than it can back, or more disk than the filesystem holding its job dirs has room for.
//!
//! Without it a runner takes every job its `concurrent` limit allows and the host's OOM
//! killer arbitrates — it takes a VMM, and that job dies mid-stage. So a job reserves what
//! it is about to boot before it boots it, and waits when the host is full.
//!
//! Each job has a ledger file under `<state_dir>/admit/` with its reservation, request time,
//! and the memory node chosen by the supervisor. Later jobs use that placement to account
//! for the node's load ([`Reservation::place`]).
//!
//! A reservation counts only while someone holds a shared `flock` on it:
//! `prepare` takes one while it waits and keeps it until it exits, and the supervisor takes
//! its own for the job's life, so the two overlap and the reservation never lapses between
//! them — and a job killed at any point has its reservation freed by the kernel. Admission
//! reads and writes the ledger under one exclusive lock on the directory, so concurrent
//! `prepare`s (a runner runs several, and a host may run several runners) admit one at a
//! time. The supervisor's [`hold`] and cleanup's [`release`] need no such lock: neither
//! consults the ledger, and both act only on this job's own entry.
//!
//! Admission is against the ledger, never against the host's free memory: a guest faults
//! its RAM in gradually, so a VM that just booted leaves `MemAvailable` looking roomy and
//! the next job in would be admitted against memory the previous one has not touched yet.
//!
//! The same entry can also claim room on the filesystem holding the job dirs ([`DiskAsk`]),
//! which fills the same way: a job's rootfs overlay grows as its guest writes. There the
//! filesystem's own free space counts too, so anything else on it is seen. A job fits when
//! that covers its own expected growth plus what each admitted job has yet to write (its
//! expectation less what its dir already holds), or when no other job holds a claim there: a
//! job that could not run alone never could. Its own test is cut to what could ever come
//! free, but its ledger claim is its full expectation: the room it cannot have yet is room it
//! will want.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// The directory lock, taken for every ledger read and write.
const LOCK: &str = ".lock";
/// How often a waiting job re-checks the ledger.
const POLL: Duration = Duration::from_secs(2);

/// A job's granted reservation: the open, shared-locked ledger file. Dropping it (or the
/// process exiting) releases the lock, which is what makes the reservation stop counting —
/// the file itself stays for the next holder, and is removed by [`release`] at cleanup or
/// reclaimed by the next admission that finds it unlocked.
///
/// Keep the writable handle and job name so [`Reservation::place`] can record the node
/// through the locked descriptor without resolving the entry's path again.
#[derive(Debug)]
pub struct Reservation {
    file: File,
    job_id: String,
}

/// What a job asks the ledger for: its guest RAM against the host's budget, room for its job
/// dir to grow into, or both — each `None` where that admission is off.
#[derive(Clone, Copy)]
pub struct Ask<'a> {
    pub mem: Option<MemAsk>,
    pub disk: Option<DiskAsk<'a>>,
}

/// `want_mib` of guest RAM out of a `budget_mib` the whole host shares.
#[derive(Clone, Copy)]
pub struct MemAsk {
    pub want_mib: u64,
    pub budget_mib: u64,
}

/// Room for `want` more bytes on the filesystem holding `jobs`, the directory every job's dir
/// is made in. A job dir is named by its job id, as its ledger entry is: that is how admission
/// finds what each admitted job has written so far.
#[derive(Clone, Copy)]
pub struct DiskAsk<'a> {
    pub want: u64,
    pub jobs: &'a Path,
}

/// Reserve what `ask` names for `job_id`, waiting up to `timeout` for room. Prints its wait to
/// stdout — this runs in `prepare`, whose output the job trace keeps, so a job that starts late
/// says why.
///
/// Jobs are admitted oldest-request-first: a big job would otherwise wait behind an endless
/// stream of small ones that each fit. Erring the other way, a small job can queue behind a
/// big one it would have fit alongside — predictable beats optimal here.
pub fn acquire(dir: &Path, job_id: &str, ask: &Ask, timeout: Duration) -> Result<Reservation> {
    if let Some(MemAsk {
        want_mib,
        budget_mib,
    }) = ask.mem
        && want_mib > budget_mib
    {
        // A per-job MICROVM_MEM is clamped to the budget before it reaches here, so a size
        // that still exceeds it came from the host's own `[executor.vm] mem` default: name both, or the
        // message sends the reader after a job variable that is not the cause.
        bail!(
            "this job's {want_mib} MiB of guest memory exceeds the host's whole {budget_mib} MiB \
             budget ([executor.schedule] mem_budget vs [executor.vm] mem) — it can never be admitted"
        );
    }
    if let Some(DiskAsk { want, jobs }) = ask.disk {
        let total = crate::usage::fs_space(jobs)
            .with_context(|| format!("reading the free space of {}", jobs.display()))?
            .total;
        // An expectation from history is capped at the filesystem before it reaches here, as is
        // the built-in default, so one that still exceeds it is a `disk_default` set larger
        // than the filesystem.
        if want > total {
            bail!(
                "this job is expected to write {} into {}, more than its whole filesystem holds \
                 ({}) — it can never be admitted ([executor.schedule] disk_default)",
                crate::usage::fmt_bytes(want),
                jobs.display(),
                crate::usage::fmt_bytes(total)
            );
        }
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    // 0700 on create AND reuse, as `vk run`'s pinned state dir does: this ledger is the host's
    // memory guard, and an entry another local user could plant in it — locked, claiming the
    // whole budget — would stall every job on the box. A pre-existing looser mode is the case
    // worth covering, so the mode is asserted and not merely requested at creation.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("restricting {} to 0700", dir.display()))?;
    let path = dir.join(job_id);
    let mut entry = Entry {
        want_mib: ask.mem.map_or(0, |m| m.want_mib),
        asked: now_nanos(),
        granted: false,
        // Decided later, by the supervisor that boots the VM: prepare does not know the
        // topology matters until there is a VM to place.
        node: None,
        disk: ask.disk.map(|d| d.want),
    };
    // Held from here on: while waiting it marks a live request other jobs must queue behind,
    // and once granted it is the reservation itself. Created under the directory lock, which
    // is what [`tally`] reaps dead entries under: an entry that exists unlocked for even the
    // instant between its creation and its lock would be taken for abandoned and removed,
    // leaving this job writing to an unlinked file that no later scan can see — its memory
    // then counted by nobody, which is the one thing this ledger exists to prevent.
    let file = {
        let _dir_lock = lock_dir(dir)?;
        let file = open_shared(&path)?;
        // Written before the lock drops, not on the next pass: an entry that exists but is
        // still empty parses as nothing, so a scan catching it in that state would report a
        // ledger anomaly against a job that is merely starting up — and leave its request out
        // of the queue order for that pass.
        entry.write(&file, &path)?;
        file
    };
    let deadline = Instant::now() + timeout;
    let mut waited_since = None;
    // What held the job back on the last pass that did, which is what it ended up waiting for.
    let mut waited_for = Blocker::Queue;
    loop {
        // Both are composed under the directory lock and reported outside it: prepare's stdout
        // is a pipe gitlab-runner drains, and a stalled reader blocking on `write` must not
        // block every other runner's admission on the host-wide lock.
        let mut wait_note = None;
        let mut anomalies = Vec::new();
        // The block yields what held the job back, if anything, and nothing more, so no
        // reporting can sit inside the critical section even by accident.
        let refused = {
            let _dir_lock = lock_dir(dir)?;
            let held = tally(dir, job_id, entry.asked, &mut anomalies)?;
            let mut pass = Pass {
                ask: *ask,
                used_mib: held.granted_mib,
                ahead: held.ahead,
                room: None,
            };
            // Walking every admitted job's dir is the costly part of a pass, under the lock
            // every other admission waits on: skipped while memory keeps the job out anyway.
            if !pass.mem_short() {
                pass.room = ask
                    .disk
                    .map(|d| DiskRoom::of(d.jobs, &held.disk))
                    .transpose()?;
            }
            match pass.blocker() {
                None => {
                    // The entry keeps the full expectation `ask` put in it, not the claim this
                    // pass cut to fit: the cut is what a full filesystem could offer now, and
                    // recorded, it would go on under-charging this job once space frees up.
                    entry.granted = true;
                    entry.write(&file, &path)?;
                    None
                }
                Some(blocker) => {
                    if waited_since.is_none() {
                        waited_since = Some(Instant::now());
                        wait_note = Some(pass.note());
                    }
                    waited_for = blocker;
                    Some(pass)
                }
            }
        };
        report(&anomalies);
        let Some(pass) = refused else {
            if let Some(since) = waited_since {
                println!(
                    "virtkit: admitted after waiting {:.0}s for {}",
                    Instant::now().duration_since(since).as_secs_f64(),
                    waited_for.what()
                );
            }
            return Ok(Reservation {
                file,
                job_id: job_id.to_string(),
            });
        };
        if let Some(note) = wait_note {
            println!("{note}");
        }
        if Instant::now() >= deadline {
            // Best-effort: the entry stops counting the moment this process drops its lock,
            // and a scan that got there first has already removed it.
            let _ = std::fs::remove_file(&path);
            bail!("{}", pass.refusal(timeout));
        }
        std::thread::sleep(POLL);
    }
}

/// What one admission pass found, kept to say why the job has to wait.
struct Pass<'a> {
    ask: Ask<'a>,
    /// The memory the other jobs hold.
    used_mib: u64,
    /// How many jobs asked first and are still waiting.
    ahead: usize,
    /// The job dirs' filesystem, where disk is asked for.
    room: Option<DiskRoom>,
}

/// What kept a job out on a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Blocker {
    Memory,
    Disk,
    /// Nothing but the jobs that asked first.
    Queue,
}

impl Blocker {
    fn what(self) -> &'static str {
        match self {
            Blocker::Memory => "memory",
            Blocker::Disk => "disk space",
            Blocker::Queue => "the jobs that asked first",
        }
    }
}

impl<'a> Pass<'a> {
    // Saturating, like the totals they compare: a corrupt entry must not add up to apparent
    // room.
    fn mem_short(&self) -> bool {
        self.ask
            .mem
            .is_some_and(|m| self.used_mib.saturating_add(m.want_mib) > m.budget_mib)
    }

    /// The disk this job's own admission test asks for: what it expects, cut to what the
    /// filesystem could ever give it — what is free now plus what the other jobs' dirs hold,
    /// which comes free as they end. A job that last filled the filesystem expects more than
    /// that, and would otherwise wait for room that cannot appear. Its claim on the ledger stays
    /// its full expectation.
    fn disk_claim(&self) -> Option<u64> {
        let want = self.ask.disk?.want;
        Some(match self.room {
            Some(room) => want.min(room.avail.saturating_add(room.held)),
            None => want,
        })
    }

    fn disk_short(&self) -> bool {
        match (self.disk_claim(), self.room) {
            // Alone on the filesystem it goes in whatever it expects: nothing it waited for
            // could make more room than it has now.
            (Some(_), Some(room)) if room.claims == 0 => false,
            (Some(want), Some(room)) => room.pending.saturating_add(want) > room.avail,
            _ => false,
        }
    }

    /// What keeps the job out, or `None` when it is admitted. Memory before disk where both
    /// are short: it is the figure a job's trace sizes it by.
    fn blocker(&self) -> Option<Blocker> {
        if self.mem_short() {
            Some(Blocker::Memory)
        } else if self.disk_short() {
            Some(Blocker::Disk)
        } else if self.ahead > 0 {
            Some(Blocker::Queue)
        } else {
            None
        }
    }

    /// The line a job prints when it starts to wait: the resource it is short of, or for a job
    /// held only by the queue, the one it asked for — memory where it asked for both.
    fn note(&self) -> String {
        let ahead = self.ahead;
        let on_disk = match self.blocker() {
            Some(Blocker::Disk) => true,
            Some(Blocker::Queue) => self.ask.mem.is_none(),
            _ => false,
        };
        match (on_disk, self.ask.mem, self.ask.disk, self.room) {
            (true, _, Some(disk), Some(room)) => format!(
                "virtkit: waiting for {} of room in {} ({} free, {} still to be written by the \
                 jobs admitted there, {ahead} job(s) asked first)",
                crate::usage::fmt_bytes(self.disk_claim().unwrap_or(disk.want)),
                disk.jobs.display(),
                crate::usage::fmt_bytes(room.avail),
                crate::usage::fmt_bytes(room.pending)
            ),
            (
                false,
                Some(MemAsk {
                    want_mib,
                    budget_mib,
                }),
                _,
                _,
            ) => format!(
                "virtkit: waiting for {want_mib} MiB of the host's {budget_mib} MiB memory \
                 budget ({} MiB reserved, {ahead} job(s) asked first)",
                self.used_mib
            ),
            _ => format!("virtkit: waiting behind {ahead} job(s) that asked first"),
        }
    }

    /// Why the job gave up, from the last pass it made.
    fn refusal(&self, timeout: Duration) -> String {
        let secs = timeout.as_secs();
        let knob = "([executor.schedule] wait_timeout_secs)";
        match (self.blocker(), self.ask.mem, self.ask.disk) {
            (Some(Blocker::Disk), _, Some(disk)) => format!(
                "no room in {} for the {} this job is expected to write within {secs}s {knob}",
                disk.jobs.display(),
                crate::usage::fmt_bytes(self.disk_claim().unwrap_or(disk.want))
            ),
            (
                Some(Blocker::Memory),
                Some(MemAsk {
                    want_mib,
                    budget_mib,
                }),
                _,
            ) => format!(
                "no room in the host's {budget_mib} MiB memory budget for this job's \
                 {want_mib} MiB within {secs}s {knob}"
            ),
            _ => format!(
                "not admitted within {secs}s: {} job(s) that asked first are still waiting {knob}",
                self.ahead
            ),
        }
    }
}

/// The job dirs' filesystem as one pass found it: what is free, how much of that the jobs
/// already admitted there are still expected to write, what their dirs hold now, and how many
/// of them hold a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DiskRoom {
    avail: u64,
    pending: u64,
    held: u64,
    claims: usize,
}

impl DiskRoom {
    /// Each admitted job's claim counts for what its dir has yet to grow by — its expectation
    /// less what the dir already holds, which is out of `avail` already and would otherwise be
    /// counted twice. A dir that cannot be read counts as empty, charging its whole claim.
    ///
    /// Walks every admitted job's dir, under the ledger lock its callers hold: a few dozen files
    /// a job, and a pass every [`POLL`] per waiting job, against a lock that is otherwise only
    /// held for the length of a directory scan.
    fn of(jobs: &Path, claims: &[(OsString, u64)]) -> Result<DiskRoom> {
        let mut room = DiskRoom {
            avail: 0,
            pending: 0,
            held: 0,
            claims: claims.len(),
        };
        for (job, want) in claims {
            let written = crate::usage::allocated_bytes(&jobs.join(job)).unwrap_or(0);
            room.held = room.held.saturating_add(written);
            room.pending = room.pending.saturating_add(want.saturating_sub(written));
        }
        // Free space read after the walk, not before: a byte written in between is then out of
        // `avail` and still in `pending`, counted twice against the job rather than not at all.
        room.avail = crate::usage::fs_space(jobs)
            .with_context(|| format!("reading the free space of {}", jobs.display()))?
            .avail;
        Ok(room)
    }
}

/// Re-open the reservation `prepare` was granted and hold it for this process's life — the
/// supervisor's half of the handoff. `None` when the job has no reservation (admission off),
/// which is not an error: a job has an entry only where memory or disk admission is on.
///
/// Needs no directory lock, unlike [`acquire`]: prepare holds its own lock on this entry
/// until the guest answers, which is long after this runs, so no scan can take it for
/// abandoned in between.
pub fn hold(dir: &Path, job_id: &str) -> Option<Reservation> {
    let path = dir.join(job_id);
    // One open, and never creating. Testing for the file and then opening it would be two
    // resolutions of the same path: an entry removed in between — by a racing cleanup, or by
    // the scan that reaps abandoned ones — would be re-created here as an empty file, which no
    // scan can parse and none can reclaim while this process holds it locked. What the job
    // claimed would then count for nobody for the whole of its life.
    match open_locked_shared(&path) {
        Ok(file) => Some(Reservation {
            file,
            job_id: job_id.to_string(),
        }),
        // admission is off — prepare never made an entry
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        // An entry that exists but cannot be re-locked is not the same as no entry at all:
        // what this job claimed stops counting for the rest of its life, so say so in the
        // supervisor log rather than degrading the host's guard in silence.
        Err(e) => {
            eprintln!(
                "virtkit: holding this job's admission reservation ({}): {e}",
                path.display()
            );
            None
        }
    }
}

impl Reservation {
    /// Choose the memory node this job's VM boots on, and record it in the ledger so the jobs
    /// placed after it know the node is taken.
    ///
    /// Against the ledger rather than the host's live per-node memory, for the reason
    /// admission itself is: a guest faults its RAM in over minutes, so a node carrying a VM
    /// that booted a moment ago still looks empty. What a node may carry is its share of the
    /// host's `mem_budget` — the budget is a whole-host figure, and a node with a quarter of
    /// the host's memory can back a quarter of it. `host_total_mib` unreadable leaves each
    /// node capped at its own memory, which is the most it could ever back anyway.
    ///
    /// The reserved size is read back out of this job's own entry rather than passed in, so a
    /// `from_history` reservation is placed against the figure it actually holds.
    pub fn place(
        &self,
        dir: &Path,
        topology: &crate::numa::Topology,
        budget_mib: u64,
        host_total_mib: Option<u64>,
        cpus: u32,
    ) -> Result<crate::numa::Placement> {
        let mut anomalies = Vec::new();
        // Collect anomalies under the host-wide directory lock and report them after
        // releasing it, as admission does, so logging does not block other runners.
        let out = {
            let _dir_lock = lock_dir(dir)?;
            self.place_locked(
                dir,
                topology,
                budget_mib,
                host_total_mib,
                cpus,
                &mut anomalies,
            )
        };
        report(&anomalies);
        out
    }

    fn place_locked(
        &self,
        dir: &Path,
        topology: &crate::numa::Topology,
        budget_mib: u64,
        host_total_mib: Option<u64>,
        cpus: u32,
        anomalies: &mut Vec<String>,
    ) -> Result<crate::numa::Placement> {
        // `u128::MAX`: nothing is queued behind this job — it is already admitted — so every
        // other entry counts and none of them is "ahead".
        let held = tally(dir, &self.job_id, u128::MAX, anomalies)?;
        let path = dir.join(&self.job_id);
        let mut entry =
            Entry::read(&self.file).with_context(|| format!("re-reading {}", path.display()))?;
        let mut load = held.per_node;
        // Charge interleaved jobs equally to every node; omitting them would make occupied
        // nodes look empty, especially on hosts where most jobs interleave.
        let share = held
            .spread
            .granted_mib
            .checked_div(u64::try_from(topology.nodes.len()).unwrap_or(1))
            .unwrap_or(0);
        for node in &topology.nodes {
            let carried = load.entry(node.id).or_default();
            carried.granted_mib = carried.granted_mib.saturating_add(share);
            carried.jobs = carried.jobs.saturating_add(held.spread.jobs);
        }
        let placement = crate::numa::pick(
            topology,
            &load,
            |node| node_budget_mib(node, budget_mib, host_total_mib),
            entry.want_mib,
            cpus,
        );
        entry.node = Some(match &placement {
            crate::numa::Placement::Bind { node, .. } => Place::Node(*node),
            crate::numa::Placement::Interleave { .. } => Place::Spread,
        });
        entry.write(&self.file, &path)?;
        Ok(placement)
    }
}

/// Scale the host's memory budget by this node's share of host memory. If the host total
/// is unreadable, use the node's full memory; this cap only guides placement.
fn node_budget_mib(node: &crate::numa::Node, budget_mib: u64, host_total_mib: Option<u64>) -> u64 {
    match host_total_mib {
        Some(total) => node
            .mem_total_mib
            .saturating_mul(budget_mib)
            .checked_div(total)
            .unwrap_or(node.mem_total_mib),
        None => node.mem_total_mib,
    }
}

/// How far back a job's own runs are believed. Measured in days rather than runs, because
/// what changes a job's appetite — a dependency, a fixture, the code — changes on calendar
/// time, while the same count of runs can span half an hour on a busy merge queue and most
/// of a year on a release job.
const WINDOW: Duration = Duration::from_secs(14 * 24 * 60 * 60);
/// However quiet a job is, its last few runs always count: a job that runs monthly would
/// otherwise have no history at all and be admitted on its declared size forever.
const MIN_RUNS: usize = 5;
/// The most lines a job's history keeps; past it the oldest fall off the front. The only bound
/// on the file — the window narrows what a read believes, not what is stored — so this is what
/// keeps a job running every few minutes from growing one without end. A thousand recent runs
/// make as good a maximum as ten thousand.
const TRIM_AT: usize = 1000;
/// Headroom over what a job has been seen to use, as a percentage: the next run is not the
/// last one, and a reservation that is a little too big only costs throughput.
const HEADROOM_PCT: u64 = 25;
/// No reservation smaller than this, however little a job has been seen to use — the page
/// cache behind the rootfs is not in the measured peak, and a job that has only ever run
/// trivially may not next time.
const FLOOR_MIB: u64 = 512;
/// Bytes to a MiB, for the boundary between a history in bytes and the reservation
/// arithmetic in MiB — which is the unit the ledger, `[executor.vm] mem` and `MICROVM_MEM` all use.
const MIB: u64 = 1024 * 1024;

/// One remembered run: when it ended, the peak it reached, the ceiling it ran under, how full
/// it filled its writable layer, and the disk and network traffic it moved. The ceiling matters
/// because a peak is only evidence of what a job needs while the job was free to need it — a
/// run held to 4 GiB says nothing about the same job given 16.
///
/// Every figure is in **bytes**. Memory alone would read fine in MiB — it is what the
/// reservation arithmetic and `MICROVM_MEM` are in — but the traffic beside it routinely
/// runs to hundreds of kilobytes, and a megabyte unit rounds a real fetch to nothing.
#[derive(Clone, Copy)]
struct Sample {
    at_secs: u64,
    peak: u64,
    ceiling: u64,
    /// What the run moved to and from the disk. `None` where the figure was never
    /// measurable — a kernel that accounts no block I/O, or a run remembered before it was
    /// recorded. Kept apart from a measured zero on purpose: "moved nothing" is a fact about
    /// the job, "nobody could tell" one about the host, and a maximum that mixed them would
    /// report the second as the first for a fortnight.
    disk: Option<(u64, u64)>,
    /// What its guests sent and received between them and the outside, under the same rule:
    /// `None` where no switch counted — a `net.mode = "tap"` run, whose traffic goes nowhere
    /// near one.
    network: Option<(u64, u64)>,
    /// How full its writable layer got, as `(the high-water mark, the capacity)`, under the
    /// same rule again: `None` where the run had no in-guest overlay to measure. The capacity
    /// is remembered beside the mark because it follows the VM's memory rather than the
    /// ceiling exactly, so the mark alone could not say how near the wall a run came.
    overlay: Option<(u64, u64)>,
    /// What its job dir held on the host by the end — the rootfs overlay its guest wrote,
    /// the checkout packed for the guest, the logs — which is what disk admission expects the
    /// next run to need. `None` where the dir could not be read.
    footprint: Option<u64>,
}

/// What one run of a job cost, as its history remembers it, in bytes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    pub peak: u64,
    pub ceiling: u64,
    /// What it moved to and from the disk, or `None` where the host could not measure.
    pub disk: Option<(u64, u64)>,
    /// What its guests sent and received outside, or `None` where nothing counted it.
    pub network: Option<(u64, u64)>,
    /// How full it filled its writable layer and how much that layer held, or `None` where it
    /// had no in-guest overlay to fill.
    pub overlay: Option<(u64, u64)>,
    /// What its job dir held on the host, or `None` where it could not be read.
    pub footprint: Option<u64>,
}

/// The most a job has needed lately, in bytes, and over how many runs. Memory is what a
/// reservation is made of; the traffic figures ride along because a job that reads 40 GiB or
/// pulls 8 GiB over the network every run is a fact about the host worth knowing, even though
/// nothing reserves against either. Each figure is its own maximum over the window, so they
/// need not come from the same run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Recent {
    most: u64,
    /// The heaviest disk of the runs that measured it, or `None` where none did.
    most_disk: Option<(u64, u64)>,
    /// The same for the network.
    most_network: Option<(u64, u64)>,
    /// The fullest its writable layer got, and what that layer held, over the runs that had
    /// one. Unlike the traffic beside it this is a ceiling a job can *fail* against, so it is
    /// the figure to read when a job dies of `ENOSPC` with every host disk empty.
    most_overlay: Option<(u64, u64)>,
    /// The most its job dir held on the host, over the runs that measured it.
    most_footprint: Option<u64>,
    runs: usize,
}

/// Note what a job of this kind actually used, and the ceiling it used it under, for the
/// next one to be admitted against. One `<unix seconds> <peak> <ceiling> <read> <written>
/// <sent> <received> <overlay> <capacity> <footprint>` line per run, every figure in bytes and
/// an unmeasured one written `-`, appended whole so runs finishing together cannot tear each
/// other's; best-effort, since a lost sample only costs accuracy on the next admission.
///
/// A line short of any field is dropped rather than read short, since a reader loose enough
/// to accept it could not tell a torn append from a whole one. The one exception is the
/// footprint, the last field and the latest added: a line that ends before it is a run
/// recorded before it existed, and reads as one whose job dir nobody measured. A torn append
/// is therefore never left for a reader to judge: the next append cuts it off first.
pub fn remember(dir: &Path, key: &Path, run: Run) {
    remember_at(dir, key, run, now_secs())
}

fn remember_at(dir: &Path, key: &Path, run: Run, now: u64) {
    let Some(path) = under(dir, key) else {
        return; // a key that would write outside the history is no key at all
    };
    // The key is `<project>/<job>`, so the project's own directory has to exist first — and
    // making it makes the history root the lock below lives in. 0700 like the ledger's, on
    // create and on reuse: what a job is admitted against decides how much of the host it is
    // charged for, so an entry another local user could plant or edit would let one job's
    // guest be reserved a fraction of what it boots.
    let Some(parent) = path.parent() else {
        return;
    };
    if std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .is_err()
    {
        return;
    }
    for private in [dir, parent] {
        if std::fs::set_permissions(private, std::fs::Permissions::from_mode(0o700)).is_err() {
            return;
        }
    }
    // Held across the append and the trim under it, the way the ledger holds its own: the
    // trim rewrites the file whole, so a run appended between its read and its write would
    // be erased rather than merely delayed. A history dir has its own lock, so this never
    // contends with admission.
    let Ok(_dir_lock) = lock_dir(dir) else {
        return; // no lock, no safe write — a lost sample only costs the next admission
    };
    if let Ok(mut file) = File::options()
        .read(true)
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)
    {
        // An append torn short of its newline — a full filesystem, most likely, since it is
        // usually the job dirs' — is cut back off before this one goes on. Glued on, this
        // line would fuse with it; merely ended, a line torn inside its last figures would
        // read as a run with a figure far smaller than the one it lost — and the run that
        // filled the disk is the one most likely to be torn.
        let mut text = Vec::new();
        if (&file).read_to_end(&mut text).is_ok() && text.last().is_some_and(|b| *b != b'\n') {
            let whole = text
                .iter()
                .rposition(|b| *b == b'\n')
                .map_or(0, |at| at + 1);
            // Best-effort, as the doc says: a run that goes unrecorded costs the next
            // admission a little accuracy and nothing else.
            let _ = file.set_len(whole as u64);
        }
        let _ = file.write_all(
            sample_line(&Sample {
                at_secs: now,
                peak: run.peak,
                ceiling: run.ceiling,
                disk: run.disk,
                network: run.network,
                overlay: run.overlay,
                footprint: run.footprint,
            })
            .as_bytes(),
        );
    }
    // Keep the file from growing without bound: the newest runs, capped.
    if let Ok(text) = std::fs::read_to_string(&path) {
        if text.lines().count() <= TRIM_AT {
            return;
        }
        // Written back from the samples rather than from the lines they came from: the two
        // line up only while every line parses, so a line that does not is dropped here
        // instead of being carried forever.
        //
        // Trimmed by count alone and never by age. The window already ignores what is too old
        // to believe, at read time and per ceiling — deleting it here would instead take every
        // other ceiling's runs with it, since the window is ceiling-blind and floors at
        // [`MIN_RUNS`]: one run after an idle fortnight would cut a thousand-line history to
        // five lines, and a job whose ceiling went back to what it was would find nothing.
        let samples = parse(&text);
        let keep = samples.len().min(TRIM_AT);
        let kept: String = samples[samples.len() - keep..]
            .iter()
            .map(sample_line)
            .collect();
        // Swapped in whole rather than truncated in place: a reader takes no lock, and
        // truncate-then-write leaves it a prefix — the *oldest* runs, a smaller history that
        // still parses, which is the unsafe way to be wrong. A failed write leaves the previous
        // file untouched.
        //
        // The staged name appends to the whole filename rather than replacing an extension, so
        // it stays one-to-one with the history it belongs to: `with_extension` would turn
        // `my.job-<digest>` into `my.trim`, losing the digest and colliding with every other
        // `my.*` job. Created 0600 like the append path's, since the rename makes this inode
        // the history and so its mode the history's mode; `create_new` after removing any
        // staged file a crashed trim left rejects a symlink planted in its place.
        let mut staged = path.clone().into_os_string();
        staged.push(".trim");
        let staged = PathBuf::from(staged);
        let _ = std::fs::remove_file(&staged);
        let written = File::options()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staged)
            .and_then(|mut f| f.write_all(kept.as_bytes()));
        if written.is_ok() {
            let _ = std::fs::rename(&staged, &path);
        } else {
            let _ = std::fs::remove_file(&staged);
        }
    }
}

/// The most a job of this kind has used lately under `ceiling` bytes, and over how many runs.
/// `None` when it has none — a job whose ceiling has just changed is in the same position as
/// one that has never run: what it did under the old ceiling is not evidence about the new.
///
/// The largest of the window, not an average: a job that peaks 6 GiB one run in five needs
/// 6 GiB reserved, and averaging would admit it into a host that cannot hold it.
fn most_recent(dir: &Path, key: &Path, ceiling: u64) -> Option<Recent> {
    most_recent_at(dir, key, ceiling, now_secs())
}

fn most_recent_at(dir: &Path, key: &Path, ceiling: u64, now: u64) -> Option<Recent> {
    let samples = under_ceiling(&read(dir, key), ceiling);
    let window = window_of(&samples, now);
    // An empty window is a job with no history to answer from, so it is the whole answer.
    let peak = window.iter().map(|s| s.peak).max()?;
    Some(Recent {
        most: peak,
        // Only the runs that measured it vote: one that could not is left out rather than
        // dragging the maximum down to zero.
        most_disk: heaviest(window, |s| s.disk),
        most_network: heaviest(window, |s| s.network),
        most_overlay: heaviest(window, |s| s.overlay),
        most_footprint: window.iter().filter_map(|s| s.footprint).max(),
        runs: window.len(),
    })
}

/// The largest each half of a pair reached, over the runs that measured it. `None` where
/// none did: a window in which nobody could take the figure has no maximum to report, which
/// is not the same as one whose runs all moved nothing.
fn heaviest(window: &[Sample], of: fn(&Sample) -> Option<(u64, u64)>) -> Option<(u64, u64)> {
    window
        .iter()
        .filter_map(of)
        .reduce(|(a, b), (c, d)| (a.max(c), b.max(d)))
}

/// The runs taken under `ceiling` bytes, in order. A run held to a lower ceiling may have been
/// squeezed by it; one given a higher ceiling had room this job no longer has. Either way the
/// number it reached says nothing about what it would reach now, so raising or lowering a
/// job's `MICROVM_MEM` starts its history again — and putting it back finds the old runs still
/// there, until [`TRIM_AT`] newer ones have pushed them off the front.
fn under_ceiling(samples: &[Sample], ceiling: u64) -> Vec<Sample> {
    samples
        .iter()
        .copied()
        .filter(|s| s.ceiling == ceiling)
        .collect()
}

/// What to reserve for a job of this kind: the most it has used lately plus headroom, never
/// below the floor and never above what the job declares. `None` when it has no history —
/// the first run of a job is admitted against its declared size.
pub fn expect_mib(dir: &Path, key: &Path, declared_mib: u64) -> Option<u64> {
    // A declared size too large to express in bytes has no history to match it: the ceiling
    // every run was stamped with went through the same conversion.
    let recent = most_recent(dir, key, declared_mib.checked_mul(MIB)?)?;
    Some(reserve_mib(recent.most / MIB, declared_mib))
}

/// What a job of this kind is expected to write into its job dir, in bytes: the most its dir
/// has held lately plus headroom, never above `cap` — the size of the filesystem it would fill,
/// which headroom must not price a job out of. Read against the same ceiling as its memory, and
/// `None` in the same cases, or where no run in the window measured its dir.
pub fn expect_disk(dir: &Path, key: &Path, declared_mib: u64, cap: u64) -> Option<u64> {
    // Read against the memory ceiling because that is what a history's window is cut by, not
    // because disk follows memory: a new MICROVM_MEM restarts the disk estimate too, costing a
    // run against `disk_default` — cheaper than a second window to keep in step.
    let recent = most_recent(dir, key, declared_mib.checked_mul(MIB)?)?;
    let most = recent.most_footprint?;
    Some(
        most.saturating_add(most.saturating_mul(HEADROOM_PCT) / 100)
            .min(cap),
    )
}

/// What every job this host remembers would reserve if it ran now, each read against the
/// ceiling it last ran under — the scheduler sizing a typical job, which knows no job's
/// ceiling. Histories are two deep (`<project>/<job>`), and only directories are descended,
/// so the root's own lock file is passed over.
pub fn all_expected(root: &Path) -> Vec<u64> {
    let Ok(projects) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut expected = Vec::new();
    for project in projects.flatten().filter(|p| p.path().is_dir()) {
        let Ok(jobs) = std::fs::read_dir(project.path()) else {
            continue; // removed under us, or not ours to read
        };
        for job in jobs.flatten() {
            let key = PathBuf::from(project.file_name()).join(job.file_name());
            expected.extend(expect_last_mib(root, &key));
        }
    }
    expected
}

/// The same for a caller that does not know a job's ceiling — the scheduler asking what a
/// typical job on this host reserves. Read against the ceiling the job last ran under, which
/// is the one it would run under now.
pub fn expect_last_mib(dir: &Path, key: &Path) -> Option<u64> {
    let ceiling = read(dir, key).last()?.ceiling;
    expect_mib(dir, key, ceiling / MIB)
}

fn reserve_mib(most_mib: u64, declared_mib: u64) -> u64 {
    // Saturating: the headroom is applied to a figure read off disk, and a wrapped total
    // would reserve less than the run it came from. The cap makes the ceiling the real bound.
    most_mib
        .saturating_add(most_mib.saturating_mul(HEADROOM_PCT) / 100)
        .max(FLOOR_MIB)
        .min(declared_mib)
}

/// The runs the estimate rests on: those inside the window, and always at least the last
/// [`MIN_RUNS`] however old they are.
///
/// Counted from the newest backwards, so a sample stamped out of order — a host whose clock
/// stepped between two runs — ends the window early rather than reordering history. The
/// minimum then covers what that dropped.
fn window_of(samples: &[Sample], now: u64) -> &[Sample] {
    let fresh = samples
        .iter()
        .rev()
        .take_while(|s| now.saturating_sub(s.at_secs) <= WINDOW.as_secs())
        .count();
    let take = fresh.max(MIN_RUNS).min(samples.len());
    &samples[samples.len() - take..]
}

/// `dir/key`, or `None` for a key that would not stay under `dir`. Every key comes from
/// [`crate::jobctx::JobCtx::usage_key`], which builds it out of sanitised components — but
/// `Path::join` drops the base entirely for an absolute key, so nothing here takes that on
/// trust from a caller two modules away. Shared with [`crate::sites`], which keys its own
/// per-job store the same way: one guard, so a fix to it cannot reach one store and not the
/// other.
pub(crate) fn under(dir: &Path, key: &Path) -> Option<PathBuf> {
    let mut parts = key.components().peekable();
    parts.peek()?; // an empty key would name the history root itself
    parts
        .all(|c| matches!(c, Component::Normal(_)))
        .then(|| dir.join(key))
}

/// Read without the directory lock, unlike the ledger beside it: the trim swaps a whole file in
/// by rename, so a reader sees one complete history or the one before it and never a prefix of
/// either. Taking the lock on every read would serialise the scheduler against every job on the
/// host finishing, to close a race the rename has already closed.
fn read(dir: &Path, key: &Path) -> Vec<Sample> {
    let Some(path) = under(dir, key) else {
        return Vec::new();
    };
    std::fs::read_to_string(path)
        .map(|text| parse(&text))
        .unwrap_or_default()
}

/// Read a history file, oldest first. A line that does not parse whole is dropped: a torn
/// append costs the next admission one sample, where half-reading it would invent a run.
/// `-` is a figure the host could not take, which is not a figure of zero.
fn parse(text: &str) -> Vec<Sample> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let unmeasurable_or = |f: &str| -> Option<Option<u64>> {
                match f {
                    "-" => Some(None),
                    n => n.parse().ok().map(Some),
                }
            };
            let at_secs = fields.next()?.parse().ok()?;
            let peak = fields.next()?.parse().ok()?;
            let ceiling = fields.next()?.parse().ok()?;
            // Both halves or neither: a pair with one figure missing reads as unmeasured,
            // and a field that is neither a number nor `-` drops the line.
            let mut pair = || -> Option<Option<(u64, u64)>> {
                let one = unmeasurable_or(fields.next()?)?;
                let other = unmeasurable_or(fields.next()?)?;
                Some(one.zip(other))
            };
            let (disk, network, overlay) = (pair()?, pair()?, pair()?);
            Some(Sample {
                at_secs,
                peak,
                ceiling,
                disk,
                network,
                overlay,
                // Absent on the lines written before the figure was: unmeasured, as `-` is.
                footprint: match fields.next() {
                    Some(f) => unmeasurable_or(f)?,
                    None => None,
                },
            })
        })
        .collect()
}

/// One history line, the only place the on-disk shape is written. A figure nobody could take
/// is written `-`, so reading it back cannot mistake it for zero.
fn sample_line(s: &Sample) -> String {
    let pair = |p: Option<(u64, u64)>| match p {
        Some((one, other)) => format!("{one} {other}"),
        None => "- -".to_string(),
    };
    let footprint = s
        .footprint
        .map_or_else(|| "-".to_string(), |bytes| bytes.to_string());
    format!(
        "{} {} {} {} {} {} {footprint}\n",
        s.at_secs,
        s.peak,
        s.ceiling,
        pair(s.disk),
        pair(s.network),
        pair(s.overlay)
    )
}

/// The line a job trace ends with when the host has seen this job before: what it has been
/// using lately under the ceiling it is running at now, and — where the host reserves from
/// history — what that makes the next run claim. `None` for a job with no history yet, which
/// includes one whose ceiling has just changed.
pub fn history_summary(
    dir: &Path,
    key: &Path,
    declared_mib: u64,
    from_history: bool,
) -> Option<String> {
    history_summary_at(dir, key, declared_mib, from_history, now_secs())
}

fn history_summary_at(
    dir: &Path,
    key: &Path,
    declared_mib: u64,
    from_history: bool,
    now: u64,
) -> Option<String> {
    // Checked, like `expect_mib`'s: a declared size too large to express in bytes has no
    // history that could match it, since every stored ceiling went through this conversion.
    let recent = most_recent_at(dir, key, declared_mib.checked_mul(MIB)?, now)?;
    let runs = recent.runs;
    let plural = if runs == 1 { "run" } else { "runs" };
    let reserves = match from_history {
        true => format!(
            "; the next run reserves {}",
            fmt_mib(reserve_mib(recent.most / MIB, declared_mib))
        ),
        false => String::new(),
    };
    // "lately" rather than the window's own length: [`window_of`] floors at [`MIN_RUNS`], so a
    // job too quiet to have a fortnight's runs is answered from its last few however old they
    // are — and a line reading "37 runs in 14 days" would then be a statement of throughput
    // that is simply untrue. The guide gives the exact rule.
    let overlay = filled(recent.most_overlay);
    let job_dir = recent
        .most_footprint
        .map(|bytes| format!(", job dir {}", crate::usage::fmt_bytes(bytes)))
        .unwrap_or_default();
    let disk = moved("read", "written", recent.most_disk);
    let net = moved("sent", "received", recent.most_network);
    let most = crate::usage::fmt_bytes(recent.most);
    Some(format!(
        "virtkit: most this job has used lately: memory {most}{overlay}{job_dir}{disk}{net} \
         over {runs} {plural}{reserves}"
    ))
}

/// What every job of a project has been using, as a table for an operator sizing a host:
/// one row per job, heaviest first, and a closing line saying what the lot would reserve if
/// they all ran at once — the figure `[executor.schedule] mem_budget` has to cover.
///
/// `project` narrows it to the projects whose directory (`<id>-<slug>`) contains it, so the
/// slug alone will do; empty reports every project this host remembers. `None` when nothing
/// matched, which the caller distinguishes from a host that has run nothing.
pub fn project_report(
    root: &Path,
    project: &str,
    budget_mib: Option<Result<u64, String>>,
    from_history: bool,
) -> Option<String> {
    // An empty fragment is in every name, so the whole host reports without a special case.
    report_where(root, budget_mib, from_history, |name| {
        name.contains(project)
    })
}

/// The report for one named project and no other, for the trace of a job that asked for it.
/// Exact where [`project_report`] takes a fragment: a directory name is `<id>-<slug>`, so one
/// project's whole name can sit inside another's — `4-acme` is a substring of `14-acme-web` —
/// and a job must not be handed the history of a project whose pipelines it cannot even see.
pub fn own_project_report(
    root: &Path,
    project: &str,
    budget_mib: Option<Result<u64, String>>,
    from_history: bool,
) -> Option<String> {
    report_where(root, budget_mib, from_history, |name| name == project)
}

/// One job's row in the report: what it has been using, and the ceiling it last ran under —
/// which is the one it would run under now, and so what its next reservation is read against.
struct JobUsage {
    job: String,
    /// The digest the directory name carries, kept so two jobs whose readable names collide
    /// can still be told apart on the report (see [`label_rows`]).
    digest: String,
    recent: Recent,
    ceiling_mib: u64,
}

impl JobUsage {
    /// What this job's next run would reserve, in MiB — the figure the report is ordered by and
    /// the one its closing total adds up. Which is the size it declares unless the host reserves
    /// from history: the report has to say what *this* host does, not what another one would.
    fn reserves(&self, from_history: bool) -> u64 {
        match from_history {
            true => reserve_mib(self.recent.most / MIB, self.ceiling_mib),
            false => self.ceiling_mib,
        }
    }
}

fn report_where(
    root: &Path,
    budget_mib: Option<Result<u64, String>>,
    from_history: bool,
    keep: impl Fn(&str) -> bool,
) -> Option<String> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return None; // nothing has run on this host yet, or the store is not ours to read
    };
    let mut projects: Vec<PathBuf> = entries
        .flatten()
        .map(|p| p.path())
        .filter(|p| p.is_dir() && p.file_name().and_then(|n| n.to_str()).is_some_and(&keep))
        .collect();
    projects.sort();

    let mut blocks: Vec<(String, Vec<JobUsage>)> = Vec::new();
    for dir in projects {
        let Some(name) = dir.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let mut jobs = jobs_of(root, &dir, name);
        if jobs.is_empty() {
            continue; // a project directory with no history left under it to read
        }
        label_rows(&mut jobs);
        // Ordered by what each would reserve, which is the column the budget line below
        // totals — not by the peak behind it, since a job pressed against a low ceiling
        // reserves less than a lighter one given room.
        jobs.sort_by(|a, b| {
            b.reserves(from_history)
                .cmp(&a.reserves(from_history))
                .then(a.job.cmp(&b.job))
        });
        blocks.push((name.to_string(), jobs));
    }
    if blocks.is_empty() {
        return None;
    }
    // One set of column widths for the whole report, so a host's projects read as one table
    // in several pieces rather than as several tables that happen to be printed together.
    let rows: Vec<Cells> = blocks
        .iter()
        .flat_map(|(_, jobs)| jobs)
        .map(|job| row(job, from_history))
        .collect();
    let widths = widths(&rows);
    let mut report = String::new();
    for (name, jobs) in &blocks {
        if !report.is_empty() {
            report.push('\n');
        }
        // "lately", not the window's own length: [`window_of`] floors at [`MIN_RUNS`], so a
        // quiet job is answered from its last few runs however old they are — the same reason
        // the per-job line says it that way.
        report.push_str(&format!(
            "virtkit: {name} — what its jobs have been using lately:\n"
        ));
        report.push_str(&line(&head(), &widths));
        for job in jobs {
            report.push_str(&line(&row(job, from_history), &widths));
        }
    }
    // Set apart where it closes several projects, since it covers them all; kept tight
    // against the table of a single one, which is what a job's own trace prints.
    if blocks.len() > 1 {
        report.push('\n');
    }
    let all: Vec<&JobUsage> = blocks.iter().flat_map(|(_, jobs)| jobs).collect();
    report.push_str(&together(&all, budget_mib, from_history));
    Some(report)
}

/// One report row, headings included: a fixed width so `head`, `row`, `widths` and `line`
/// cannot drift apart into a table whose columns do not line up.
const COLS: usize = 11;
type Cells = [String; COLS];

/// What the columns are called, in the order [`row`] fills them.
fn head() -> Cells {
    [
        "job", "memory", "overlay", "job dir", "ceiling", "reserves", "runs", "read", "written",
        "sent", "received",
    ]
    .map(str::to_string)
}

/// One job's cells. A figure no run could measure is `-`, not a zero: the two mean different
/// things, and a column of zeros would hide which host cannot measure.
fn row(job: &JobUsage, from_history: bool) -> Cells {
    let pair = |p: Option<(u64, u64)>| match p {
        Some((a, b)) => [crate::usage::fmt_bytes(a), crate::usage::fmt_bytes(b)],
        None => ["-".to_string(), "-".to_string()],
    };
    let [read, written] = pair(job.recent.most_disk);
    let [sent, received] = pair(job.recent.most_network);
    [
        job.job.clone(),
        crate::usage::fmt_bytes(job.recent.most),
        // Both figures in one cell, where every other column holds one: the mark is only
        // legible against the layer that held it, and a job pressed against its capacity is
        // the row an operator is reading the table to find.
        overlay_cell(job.recent.most_overlay),
        job.recent
            .most_footprint
            .map_or_else(|| "-".to_string(), crate::usage::fmt_bytes),
        fmt_mib(job.ceiling_mib),
        fmt_mib(job.reserves(from_history)),
        job.recent.runs.to_string(),
        read,
        written,
        sent,
        received,
    ]
}

/// The overlay column's cell: the mark and the capacity it was reached against, or `-` for a
/// job with no writable layer to fill (one whose checkout is mounted read-write, or that never
/// had a checkout at all).
fn overlay_cell(overlay: Option<(u64, u64)>) -> String {
    match overlay {
        Some((used, cap)) => format!(
            "{} / {}",
            crate::usage::fmt_bytes(used),
            crate::usage::fmt_bytes(cap)
        ),
        None => "-".to_string(),
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

/// One rendered line. Names read down the left edge; figures line up on the right, where a
/// column of mixed units (`812 MiB` over `3.4 GiB`) can be compared at a glance.
fn line(cells: &Cells, widths: &[usize; COLS]) -> String {
    let mut out = String::from("  ");
    for (col, (cell, width)) in cells.iter().zip(widths).enumerate() {
        match col {
            0 => out.push_str(&format!("{cell:<width$}  ")),
            _ => out.push_str(&format!("{cell:>width$}  ")),
        }
    }
    // The padding after the last column is trailing whitespace nobody wants in a trace.
    while out.ends_with(' ') {
        out.pop();
    }
    out.push('\n');
    out
}

/// The closing line: what the reported jobs would reserve if every one of them ran at once,
/// against the budget the host admits within. That comparison is the report's point — a host
/// whose jobs cannot all fit is not misconfigured, it is one where jobs queue.
fn together(
    jobs: &[&JobUsage],
    budget_mib: Option<Result<u64, String>>,
    from_history: bool,
) -> String {
    // Saturating, like `reserve_mib`'s own arithmetic: these are figures read off disk.
    let total: u64 = jobs
        .iter()
        .map(|j| j.reserves(from_history))
        .fold(0u64, u64::saturating_add);
    let plural = if jobs.len() == 1 { "job" } else { "jobs" };
    let budget = match budget_mib {
        Some(Ok(mib)) => format!(", against a budget of {}", fmt_mib(mib)),
        // A budget this host cannot read is not the absence of one: every job's prepare is
        // already failing on it, and saying "no budget" would send the reader the wrong way.
        Some(Err(why)) => {
            format!(", against a [executor.schedule] mem_budget this host cannot read ({why})")
        }
        // Nothing to compare against, and saying so beats an unqualified total: without
        // `[executor.schedule] mem_budget` nothing is held back whatever the figure says.
        None => ", with no [executor.schedule] mem_budget to hold them back".to_string(),
    };
    format!(
        "virtkit: {} {plural}; all at once they would reserve {}{budget}\n",
        jobs.len(),
        fmt_mib(total),
    )
}

/// Every job remembered under one project directory, each read against the ceiling it last
/// ran under — and, as every reader of a history does, over its last few runs however old
/// they are, so a job too quiet for the window is still reported rather than dropped. Left
/// out only where there is no history left to read.
fn jobs_of(root: &Path, dir: &Path, project: &str) -> Vec<JobUsage> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new(); // removed under us, or not ours to read
    };
    let mut jobs = Vec::new();
    for entry in entries.flatten() {
        let key = Path::new(project).join(entry.file_name());
        // Named the way the project above it is: anything this host wrote is ASCII by
        // construction, so a name that will not read back as one is not a history of ours.
        let Some((name, digest)) = entry.file_name().to_str().map(readable_job) else {
            continue;
        };
        let Some(ceiling) = read(root, &key).last().map(|s| s.ceiling) else {
            continue;
        };
        let Some(recent) = most_recent(root, &key, ceiling) else {
            continue;
        };
        jobs.push(JobUsage {
            job: name,
            digest,
            recent,
            ceiling_mib: ceiling / MIB,
        });
    }
    jobs
}

/// A job directory's readable half and the digest that follows it: two job names can reduce
/// to the same readable half — `deploy:prod` and `deploy prod` both key on `deploy_prod` —
/// and it is the digest that keeps their histories apart, so a report showing one row per
/// name has to be able to tell them apart too.
pub(crate) fn readable_job(component: &str) -> (String, String) {
    match component.rsplit_once('-') {
        Some((name, digest))
            if digest.len() == crate::jobctx::JOB_DIGEST_HEX
                && digest.chars().all(|c| c.is_ascii_hexdigit()) =>
        {
            (name.to_string(), digest.to_string())
        }
        _ => (component.to_string(), String::new()),
    }
}

/// Give every row a label of its own: a readable name that only one job in this block wears
/// is that name, and one that two wear carries enough of each digest to be told from the
/// other — the alternative is two rows labelled alike with different figures behind them.
fn label_rows(jobs: &mut [JobUsage]) {
    let mut seen: HashMap<&str, usize> = HashMap::new();
    for j in jobs.iter() {
        *seen.entry(j.job.as_str()).or_default() += 1;
    }
    let repeated: HashSet<String> = seen
        .into_iter()
        .filter(|(_, n)| *n > 1)
        .map(|(name, _)| name.to_string())
        .collect();
    for j in jobs.iter_mut() {
        if repeated.contains(&j.job) && !j.digest.is_empty() {
            // The whole digest, not a prefix: a prefix separates two entries only as well as
            // its own length, and these are names someone chose to have read alike.
            j.job = format!("{} ({})", j.job, j.digest);
        }
    }
}

fn fmt_mib(mib: u64) -> String {
    // Saturating: a `[executor.schedule] mem_budget` absurd enough to survive its own `checked_mul` is
    // still a figure this has to print rather than wrap on.
    crate::usage::fmt_bytes(mib.saturating_mul(MIB))
}

/// A pair of figures for a trace line, or nothing at all where no run in the window could
/// measure them. A measured zero is printed: "moved nothing" is a fact about the job worth
/// stating, where the same row of zeros from a host that accounts no block I/O would state
/// that fact falsely.
fn moved(one: &str, other: &str, pair: Option<(u64, u64)>) -> String {
    match pair {
        Some((a, b)) => format!(
            ", {one} {}, {other} {}",
            crate::usage::fmt_bytes(a),
            crate::usage::fmt_bytes(b)
        ),
        None => String::new(),
    }
}

/// The writable layer for a trace line, the mark against what the layer held — the pair, not
/// the mark alone, because a job reads this to learn whether it has room left. Nothing at all
/// where no run in the window had a layer to fill.
fn filled(overlay: Option<(u64, u64)>) -> String {
    match overlay {
        Some((used, cap)) => format!(
            ", overlay {} of {}",
            crate::usage::fmt_bytes(used),
            crate::usage::fmt_bytes(cap)
        ),
        None => String::new(),
    }
}

/// Drop a job's reservation at cleanup. Best-effort: a reservation left behind stops
/// counting the moment its holders die, and the next admission removes the file.
pub fn release(dir: &Path, job_id: &str) {
    let _ = std::fs::remove_file(dir.join(job_id));
}

/// Report what a scan found odd. Called once the directory lock is gone: stderr is the
/// supervisor log or the runner's own, and blocking on it under the lock would stall every
/// admission on the host.
fn report(anomalies: &[String]) {
    for note in anomalies {
        eprintln!("{note}");
    }
}

/// What the ledger is holding: the memory granted and how many jobs hold it, plus how many
/// asked before `asked` and are still waiting. Ignores `job_id` (the caller's own entry).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Held {
    pub granted_mib: u64,
    pub granted: usize,
    pub ahead: usize,
    /// Granted memory by node, used to place the next job. Entries without a placement,
    /// including older virtkit entries and jobs on hosts with placement disabled, appear in
    /// neither this map nor `spread`. Their sum never exceeds `granted_mib`; a host with
    /// placement disabled has an empty breakdown.
    pub per_node: HashMap<u32, crate::numa::NodeLoad>,
    /// What the interleaved jobs hold, which is a share of every node rather than any one.
    pub spread: crate::numa::NodeLoad,
    /// What each granted job claimed on the job dirs' filesystem, in bytes, by entry name —
    /// which is its job id, and so the name of its job dir. Only the jobs that asked for disk.
    pub disk: Vec<(OsString, u64)>,
}

/// What this host has committed right now, for a caller with no entry of its own — the
/// scheduler reading the ledger to decide how much work the runner should accept.
///
/// A ledger that is not there yet holds nothing — no job on this host has ever been admitted,
/// which is the honest answer on a fresh host and not a failure. A ledger that exists and
/// cannot be read is an error, though: a scheduler told nothing is committed would offer the
/// whole budget again, which is the one answer that overcommits the host.
pub fn committed(dir: &Path) -> Result<Held> {
    // Not `Path::exists()`: that answers false for a stat that failed for any reason — a
    // permission error on a parent included — which is exactly the reading this must refuse.
    match std::fs::metadata(dir) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Held::default()),
        Err(e) => return Err(e).with_context(|| format!("statting {}", dir.display())),
    }
    let mut anomalies = Vec::new();
    let out = {
        let _lock = lock_dir(dir)?;
        tally(dir, "", u128::MAX, &mut anomalies)
    };
    report(&anomalies);
    out
}

/// What the live ledger holds, ignoring `job_id` (the caller's own entry), with how many jobs
/// asked before `asked` and are still waiting. Entries nobody holds a lock on are dead — their
/// job is gone — and are removed as they are found. Callers hold the directory lock.
///
/// An unreadable ledger is an error, never an empty one: reporting nothing reserved would
/// admit every job on the host against a guard that has stopped working. Anything odd but
/// survivable is pushed onto `anomalies` for the caller to report once it has let the lock go.
fn tally(dir: &Path, job_id: &str, asked: u128, anomalies: &mut Vec<String>) -> Result<Held> {
    let mut out = Held::default();
    let entries = std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    for entry in entries {
        let path = entry
            .with_context(|| format!("reading {}", dir.display()))?
            .path();
        // Compared as an OsStr, never defaulted to "": `committed` passes "" for "no entry of
        // my own", and a name that is not UTF-8 must not match it and go uncounted.
        let name = path.file_name().unwrap_or_default();
        if name == std::ffi::OsStr::new(LOCK) || name == std::ffi::OsStr::new(job_id) {
            continue;
        }
        let file = match File::open(&path) {
            Ok(file) => file,
            // Removed under us by another admission. Any other failure — no descriptors
            // left, say — would silently shrink the guard, so it is an error.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("opening {}", path.display())),
        };
        if !locked(&file) {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        let Some(entry) = Entry::read(&file) else {
            // Every write happens under this lock and an entry is written as it is created,
            // so only a holder killed mid-write leaves a partial line. It would go on not
            // counting, so say so rather than letting the guard quietly shrink.
            anomalies.push(format!(
                "virtkit: ledger entry {} unreadable — not counted this pass",
                path.display()
            ));
            continue;
        };
        // Saturating: these are numbers parsed out of a file, and a wrapped total would read
        // as room where there is none.
        if entry.granted {
            out.granted_mib = out.granted_mib.saturating_add(entry.want_mib);
            out.granted = out.granted.saturating_add(1);
            let placed = match entry.node {
                Some(Place::Node(id)) => Some(out.per_node.entry(id).or_default()),
                Some(Place::Spread) => Some(&mut out.spread),
                None => None,
            };
            if let Some(node) = placed {
                node.granted_mib = node.granted_mib.saturating_add(entry.want_mib);
                node.jobs = node.jobs.saturating_add(1);
            }
            if let Some(bytes) = entry.disk {
                out.disk.push((name.to_os_string(), bytes));
            }
        } else if entry.asked < asked {
            out.ahead = out.ahead.saturating_add(1);
        }
    }
    Ok(out)
}

/// One ledger entry: what the job wants, when it first asked (its place in the queue),
/// whether it holds that memory yet, and which memory node it took.
struct Entry {
    want_mib: u64,
    asked: u128,
    granted: bool,
    node: Option<Place>,
    /// The bytes it expects to write into its job dir, where disk admission is on.
    disk: Option<u64>,
}

/// Where a job's guest RAM went, as the ledger records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    /// All of it on one node.
    Node(u32),
    /// Interleaved over every node — the VM did not fit one.
    Spread,
}

impl Place {
    fn parse(field: &str) -> Option<Place> {
        match field {
            "spread" => Some(Place::Spread),
            _ => Some(Place::Node(field.strip_prefix("node=")?.parse().ok()?)),
        }
    }
}

impl Entry {
    /// `<mib> <asked> <granted|waiting> [node=<n>|spread] [disk=<bytes>]`, rewritten whole
    /// each time so a reader either sees the previous line or the new one, never a splice of
    /// both. The node is absent until one is chosen, and absent for good on a host that places
    /// nothing — so a three-field line, all this ledger ever held before, still reads. The disk
    /// claim goes last, where a reader that knows only the node passes over it.
    fn write(&self, mut file: &File, path: &Path) -> Result<()> {
        let state = if self.granted { "granted" } else { "waiting" };
        let node = match self.node {
            Some(Place::Node(id)) => format!(" node={id}"),
            Some(Place::Spread) => " spread".to_string(),
            None => String::new(),
        };
        let disk = match self.disk {
            Some(bytes) => format!(" disk={bytes}"),
            None => String::new(),
        };
        let line = format!("{} {} {state}{node}{disk}\n", self.want_mib, self.asked);
        file.set_len(0)
            .and_then(|()| file.seek(SeekFrom::Start(0)))
            .and_then(|_| file.write_all(line.as_bytes()))
            .and_then(|()| file.flush())
            .with_context(|| format!("writing {}", path.display()))
    }

    fn read(mut file: &File) -> Option<Entry> {
        // Rewind because [`Reservation::place`] reads through the handle that wrote the entry.
        file.seek(SeekFrom::Start(0)).ok()?;
        let mut text = String::new();
        file.read_to_string(&mut text).ok()?;
        let mut fields = text.split_whitespace();
        let mut entry = Entry {
            want_mib: fields.next()?.parse().ok()?,
            asked: fields.next()?.parse().ok()?,
            granted: fields.next()? == "granted",
            node: None,
            disk: None,
        };
        for field in fields {
            match field.strip_prefix("disk=") {
                // A claim that does not parse makes the entry unreadable, not claimless: it is
                // reported as a ledger anomaly rather than silently read as claiming no room.
                Some(bytes) => entry.disk = Some(bytes.parse().ok()?),
                // A field this version does not know leaves the node as it was.
                None => {
                    if let Some(place) = Place::parse(field) {
                        entry.node = Some(place);
                    }
                }
            }
        }
        Some(entry)
    }
}

/// Open (creating) `path` and take a shared lock on it — the mark of a live reservation.
/// Shared, so `prepare` and the supervisor can hold the same one across the handoff.
fn open_shared(path: &Path) -> Result<File> {
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    lock_shared(&file).with_context(|| format!("locking {}", path.display()))?;
    Ok(file)
}

/// Open an existing `path` writable and take a shared lock, without creating it.
/// [`Reservation::place`] needs write access to record the job's NUMA placement. Return the
/// original `io::Error` so callers can distinguish a missing entry from a lock failure.
fn open_locked_shared(path: &Path) -> std::io::Result<File> {
    let file = File::options().read(true).write(true).open(path)?;
    lock_shared(&file)?;
    Ok(file)
}

fn lock_shared(file: &File) -> std::io::Result<()> {
    // SAFETY: the fd is owned by `file`, which outlives the call; flock returns 0 or -1.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Whether anyone holds `file`'s reservation, probed by trying to take it exclusively.
///
/// A lock lives until the last copy of the descriptor holding it closes, so a process that
/// forks while a reservation is being released keeps it alive for the instant before the
/// child execs. Erring that way is the right way round — a reservation read as live for one
/// poll costs a job two seconds, where reclaiming a live one would overcommit the host.
fn locked(file: &File) -> bool {
    // SAFETY: same as open_shared; LOCK_NB never blocks.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return true;
    }
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    false
}

/// Take the directory's exclusive lock, held until the returned file drops. Blocking: the
/// critical section is a directory scan, and a waiter is better than a spuriously refused job.
pub(crate) fn lock_dir(dir: &Path) -> Result<File> {
    let path = dir.join(LOCK);
    let file = File::options()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    // SAFETY: the fd is owned by `file`, which outlives the call; flock returns 0 or -1.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("locking {}", path.display()));
    }
    Ok(file)
}

/// Wall-clock seconds, for ageing a job's history: what makes a run old is calendar time,
/// which outlives the boots the queue's monotonic clock is scoped to.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A request's place in the queue: nanoseconds since boot. Monotonic rather than wall clock,
/// which the whole oldest-first rule rests on — an NTP step backwards would otherwise stamp a
/// request that arrived later with an earlier time and let it cut in front of one already
/// waiting. Comparable across the processes sharing this ledger because they share a boot,
/// and entries never outlive one: nothing holds their locks afterwards, so the first scan
/// after a reboot reclaims them.
fn now_nanos() -> u128 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime only writes the timespec we own, and only on success.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        // Unreachable for CLOCK_MONOTONIC on Linux. Queue behind everyone rather than
        // ahead of them: waiting a turn too long beats taking someone else's.
        return u128::MAX;
    }
    ts.tv_sec as u128 * 1_000_000_000 + ts.tv_nsec as u128
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-admit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Read the live ledger the way production does. `tally` reaps entries it finds unlocked,
    /// so it must only ever run under the directory lock: an unlocked reader can unlink an
    /// entry a concurrent `acquire` is still between opening and locking, leaving that job's
    /// memory uncounted — which would mask the very over-admission these tests look for.
    fn live_mib(dir: &Path) -> u64 {
        live(dir).0
    }

    /// The reserved total, and how many entries the scan could not parse. A scan racing an
    /// `acquire` must see none of the latter: an entry is created and written in one critical
    /// section, so it is never observable empty.
    fn live(dir: &Path) -> (u64, usize) {
        let mut anomalies = Vec::new();
        let _dir_lock = lock_dir(dir).unwrap();
        let used = tally(dir, "nobody", u128::MAX, &mut anomalies)
            .unwrap()
            .granted_mib;
        (used, anomalies.len())
    }

    /// Wait for the live ledger to fall to `mib`. Releasing is not instant when something
    /// else in the process forks at the wrong moment (see [`locked`]), and the rest of this
    /// binary's tests spawn children constantly.
    fn until_ledger_is(dir: &Path, mib: u64) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while live_mib(dir) != mib {
            assert!(
                Instant::now() < deadline,
                "ledger stuck at {} MiB, expected {mib}",
                live_mib(dir)
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// One run of a job at `ceiling_mib`, for the tests that are not about disk. The history
    /// is in bytes; these tests read better in the megabytes a person would say, so they
    /// convert here.
    fn run(peak_mib: u64, ceiling_mib: u64) -> Run {
        Run {
            peak: peak_mib * MIB,
            ceiling: ceiling(ceiling_mib),
            ..Run::default()
        }
    }

    /// A ceiling as the history stores it, from the megabytes a test states it in.
    fn ceiling(mib: u64) -> u64 {
        mib * MIB
    }

    /// An append torn short of its newline is cut off before the next run's line goes on, so
    /// that line reads whole and the torn one is not read as a run with its figures cut short.
    #[test]
    fn a_run_appended_after_a_torn_line_reads_whole() {
        let dir = std::env::temp_dir().join(format!("vk-hist-torn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let now = 1_700_000_000;
        remember_at(&dir, key("torn"), run(500, 8192), now - 60);
        let path = under(&dir, key("torn")).unwrap();
        let whole = std::fs::read_to_string(&path).unwrap();
        // Cut inside the last field, as a full filesystem would leave it.
        std::fs::write(&path, &whole[..whole.len() - 2]).unwrap();
        remember_at(&dir, key("torn"), run(700, 8192), now);
        let samples = parse(&std::fs::read_to_string(&path).unwrap());
        let last = samples.last().expect("the new run");
        assert_eq!((last.at_secs, last.peak), (now, 700 * MIB));
        assert_eq!(samples.len(), 1, "the torn line is gone, not read short");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What a window of runs that moved no disk reads back as.
    fn recent(most_mib: u64, runs: usize) -> Option<Recent> {
        Some(Recent {
            most: most_mib * MIB,
            runs,
            ..Recent::default()
        })
    }

    /// A history key. Real ones are `<project>/<job>`; a single component exercises the same
    /// paths and keeps the assertions readable.
    fn key(name: &str) -> &Path {
        Path::new(name)
    }

    /// Memory admission alone, as every test not about disk asks for.
    fn acquire_mem(
        dir: &Path,
        job: &str,
        want_mib: u64,
        budget_mib: u64,
        timeout: Duration,
    ) -> Result<Reservation> {
        let mem = Some(MemAsk {
            want_mib,
            budget_mib,
        });
        acquire(dir, job, &Ask { mem, disk: None }, timeout)
    }

    /// A reservation held by this test, as another job's would be.
    fn held(dir: &Path, job: &str, want_mib: u64, asked: u128, granted: bool) -> File {
        held_on(dir, job, want_mib, asked, granted, None)
    }

    /// The same, placed on a node.
    fn held_on(
        dir: &Path,
        job: &str,
        want_mib: u64,
        asked: u128,
        granted: bool,
        node: Option<Place>,
    ) -> File {
        let file = open_shared(&dir.join(job)).unwrap();
        Entry {
            want_mib,
            asked,
            granted,
            node,
            disk: None,
        }
        .write(&file, &dir.join(job))
        .unwrap();
        file
    }

    #[test]
    fn admits_within_the_budget_and_refuses_beyond_it() {
        let dir = tmpdir("fits");
        let held_by_others = held(&dir, "other", 4096, 1, true);

        // 4 GiB reserved of an 8 GiB budget: a 4 GiB job still fits.
        let res = acquire_mem(&dir, "mine", 4096, 8192, Duration::from_secs(0)).unwrap();
        assert_eq!(live_mib(&dir), 8192, "both counted");

        // The budget is now full: the next job waits, then gives up.
        let err = acquire_mem(&dir, "third", 4096, 8192, Duration::from_secs(0)).unwrap_err();
        assert!(err.to_string().contains("no room"), "{err}");
        // A refused job leaves nothing behind.
        assert!(!dir.join("third").exists());

        // Releasing frees the room for the next one.
        drop(res);
        crate::admit::release(&dir, "mine");
        drop(held_by_others);
        crate::admit::release(&dir, "other");
        until_ledger_is(&dir, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_job_larger_than_the_budget_fails_at_once() {
        let dir = tmpdir("too-big");
        let err = acquire_mem(&dir, "huge", 16384, 8192, Duration::from_secs(60)).unwrap_err();
        assert!(err.to_string().contains("never be admitted"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_older_waiter_is_served_first() {
        let dir = tmpdir("fifo");
        // A big job that asked first and is still waiting, with the budget full.
        let _big = held(&dir, "big", 8192, 1, false);
        let _full = held(&dir, "running", 8192, 1, true);

        // A small job that would fit the moment the running one ends must not jump the queue.
        let err = acquire_mem(&dir, "small", 512, 8192, Duration::from_secs(0)).unwrap_err();
        assert!(err.to_string().contains("no room"), "{err}");

        // Once the older waiter is gone, the same job is admitted.
        drop(_big);
        crate::admit::release(&dir, "big");
        drop(_full);
        crate::admit::release(&dir, "running");
        acquire_mem(&dir, "small", 512, 8192, Duration::from_secs(0)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_reservation_nobody_holds_is_reclaimed() {
        let dir = tmpdir("stale");
        // A job that died: its file is left behind, but no one holds its lock.
        let dead = held(&dir, "dead", 8192, 1, true);
        drop(dead);

        // It neither counts against the budget nor survives the scan that found it.
        until_ledger_is(&dir, 0);
        assert!(!dir.join("dead").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The wait itself: a job that does not fit sits in the poll loop and is admitted once
    /// the reservation in its way goes, rather than being refused or granted on the spot.
    #[test]
    fn a_waiting_job_is_admitted_once_there_is_room() {
        let dir = tmpdir("waits");
        let blocker = held(&dir, "running", 8192, 1, true);

        let freed = std::thread::spawn({
            let dir = dir.clone();
            move || {
                // Only once the waiter has registered, so admission really does come from a
                // later pass of the loop and not from the first one.
                let deadline = Instant::now() + Duration::from_secs(30);
                while !dir.join("waiter").exists() {
                    assert!(Instant::now() < deadline, "the waiter never registered");
                    std::thread::sleep(Duration::from_millis(20));
                }
                std::thread::sleep(POLL);
                drop(blocker);
                release(&dir, "running");
            }
        });

        let asked_at = Instant::now();
        let res = acquire_mem(&dir, "waiter", 8192, 8192, Duration::from_secs(120)).unwrap();
        assert!(asked_at.elapsed() >= POLL, "admitted without ever waiting");
        freed.join().unwrap();

        drop(res);
        release(&dir, "waiter");
        until_ledger_is(&dir, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The point of the directory lock: real concurrent admissions, of a size that only one
    /// can hold at a time, must never both be granted.
    #[test]
    fn concurrent_admissions_never_exceed_the_budget() {
        const BUDGET: u64 = 4096;
        const WANT: u64 = 3072; // two of these do not fit together
        let dir = tmpdir("contended");

        let watching = Arc::new(AtomicBool::new(true));
        let over = Arc::new(AtomicU64::new(0));
        let unparseable = Arc::new(AtomicU64::new(0));
        let watcher = std::thread::spawn({
            let (dir, watching, over, unparseable) = (
                dir.clone(),
                Arc::clone(&watching),
                Arc::clone(&over),
                Arc::clone(&unparseable),
            );
            move || {
                while watching.load(Ordering::Relaxed) {
                    let (used, odd) = live(&dir);
                    over.fetch_max(used, Ordering::Relaxed);
                    unparseable.fetch_add(odd as u64, Ordering::Relaxed);
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        });

        // Stops the watcher however this test ends: a racer that panics unwinds past the
        // explicit stop below, and the watcher's poll loop has no deadline of its own.
        struct StopOnDrop(Arc<AtomicBool>);
        impl Drop for StopOnDrop {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Relaxed);
            }
        }
        let _stop = StopOnDrop(Arc::clone(&watching));

        let racers: Vec<_> = (0..4)
            .map(|i| {
                let dir = dir.clone();
                std::thread::spawn(move || {
                    let job = format!("job{i}");
                    let res = acquire_mem(&dir, &job, WANT, BUDGET, Duration::from_secs(120))
                        .unwrap_or_else(|e| panic!("{job} was never admitted: {e}"));
                    std::thread::sleep(Duration::from_millis(50));
                    drop(res);
                    release(&dir, &job);
                })
            })
            .collect();
        for r in racers {
            r.join().unwrap();
        }
        watching.store(false, Ordering::Relaxed);
        watcher.join().unwrap();

        assert!(
            over.load(Ordering::Relaxed) <= BUDGET,
            "the ledger held {} MiB of a {BUDGET} MiB budget",
            over.load(Ordering::Relaxed)
        );
        assert_eq!(
            unparseable.load(Ordering::Relaxed),
            0,
            "a scan caught an entry between its creation and its first write"
        );
        until_ledger_is(&dir, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The ceiling every history test that is not about ceilings runs under.
    const CEIL: u64 = 8192;

    #[test]
    fn a_reservation_follows_what_the_job_has_been_using() {
        let dir = tmpdir("history");
        let now = 1_700_000_000;
        let day = 24 * 60 * 60;
        // No history: the caller falls back to the declared size.
        assert_eq!(expect_mib(&dir, key("proj-test"), 8192), None);

        // The largest run in the window plus headroom, not the average — a job that peaks
        // once needs room for that run.
        for (age, peak) in [(3 * day, 1000), (2 * day, 4000), (day, 1200)] {
            remember_at(&dir, key("proj-test"), run(peak, CEIL), now - age);
        }
        assert_eq!(
            most_recent_at(&dir, key("proj-test"), ceiling(CEIL), now),
            recent(4000, 3)
        );
        assert_eq!(reserve_mib(4000, 8192), 5000);

        // Never above what the job declares: reserving memory it cannot use would only
        // idle the host. And never under the floor, however light the job has been.
        assert_eq!(reserve_mib(4000, 4096), 4096);
        assert_eq!(reserve_mib(4, 8192), FLOOR_MIB);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The point of measuring the window in days: a spike stops being believed once it is
    /// old, however few runs have happened since.
    #[test]
    fn an_old_spike_leaves_the_window_on_its_own() {
        let dir = tmpdir("ages");
        let now = 1_700_000_000;
        let day = 24 * 60 * 60;

        remember_at(&dir, key("job"), run(8000, CEIL), now - 30 * day); // a month ago
        for age in [3 * day, 2 * day, day, day / 2, 60] {
            remember_at(&dir, key("job"), run(900, CEIL), now - age);
        }
        // Six runs, but only the five inside the window count — the old spike is not one of
        // them, and MIN_RUNS is satisfied without it.
        assert_eq!(
            most_recent_at(&dir, key("job"), ceiling(CEIL), now),
            recent(900, 5)
        );

        // While it was fresh, that same spike was the whole answer — age demoted it, not
        // the runs since.
        remember_at(&dir, key("spike-only"), run(8000, CEIL), now - day);
        assert_eq!(
            most_recent_at(&dir, key("spike-only"), ceiling(CEIL), now),
            recent(8000, 1)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A job that runs monthly has nothing inside the window, and must still be estimated
    /// from what it did rather than from its declared size.
    #[test]
    fn a_rare_job_keeps_its_last_few_runs_however_old() {
        let dir = tmpdir("rare");
        let now = 1_700_000_000;
        let year = 365 * 24 * 60 * 60;
        // Oldest first, as an append-only history has them: eight monthly runs, the earlier
        // ones the heaviest.
        for months in (1..=8).rev() {
            remember_at(
                &dir,
                key("release"),
                run(2000 + months * 10, CEIL),
                now - months * year / 12,
            );
        }
        // Nothing is inside the window, so the last MIN_RUNS carry the estimate: the largest
        // of those five (five months ago), not the heavier ones from further back.
        let recent = most_recent_at(&dir, key("release"), ceiling(CEIL), now).unwrap();
        assert_eq!(recent.runs, MIN_RUNS);
        assert_eq!(
            recent.most / MIB,
            2050,
            "the largest of the last five, not of all eight"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_long_history_is_trimmed_to_the_cap_and_no_further() {
        let dir = tmpdir("trim");
        let now = 1_700_000_000;
        let day = 24 * 60 * 60;
        // A job run more times in a fortnight than the cap allows: the cap bounds the file.
        for i in 0..=TRIM_AT as u64 {
            remember_at(&dir, key("busy"), run(500, CEIL), now - day + i);
        }
        let kept = std::fs::read_to_string(dir.join("busy")).unwrap();
        assert_eq!(kept.lines().count(), TRIM_AT);
        // The trim swaps a new file in, so from here on it is the trim that decides the mode.
        let mode = std::fs::metadata(dir.join("busy"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the trim kept the history private");

        // Ageing out does not shrink it further. The window already ignores what is too old
        // to believe, per ceiling and at read time; trimming by age here would be blind to
        // the ceiling and would take a thousand runs down to MIN_RUNS on the strength of one
        // quiet fortnight — losing every other ceiling's runs with them.
        remember_at(&dir, key("busy"), run(500, CEIL), now + 60 * day);
        assert_eq!(
            std::fs::read_to_string(dir.join("busy"))
                .unwrap()
                .lines()
                .count(),
            TRIM_AT
        );
        assert_eq!(
            most_recent_at(&dir, key("busy"), ceiling(CEIL), now + 60 * day),
            recent(500, MIN_RUNS),
            "the read still narrows to what the window reaches"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What a job is admitted against decides how much of the host it is charged for, so the
    /// history is as private as the ledger: a planted or edited file would have a job's guest
    /// reserved a fraction of what it boots.
    #[test]
    fn the_history_is_created_private() {
        let dir = std::env::temp_dir().join(format!("vk-hist-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // The two-component key production uses, so the project directory is made here too.
        remember(&dir, key("42-proj/build-abc"), run(500, CEIL));

        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700, "history root");
        assert_eq!(mode(&dir.join("42-proj")), 0o700, "the project's directory");
        assert_eq!(
            mode(&dir.join("42-proj/build-abc")),
            0o600,
            "a job's history"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The reason the trim is by count and not by age: one file holds runs from every ceiling
    /// the job has had, and a job that goes back to an earlier `MICROVM_MEM` has to find them —
    /// for as long as the cap has not pushed them out behind the newer ceiling's runs, which is
    /// the bound this test stays inside.
    #[test]
    fn a_trim_keeps_an_earlier_ceilings_runs_inside_the_cap() {
        let dir = tmpdir("trim-ceilings");
        let now = 1_700_000_000;
        let day = 24 * 60 * 60;
        // Runs under 2G, then enough under 8G to push the file past the cap — but not so many
        // that the newest TRIM_AT are all 8G, which would evict the older ceiling fairly.
        for i in 0..300 {
            remember_at(&dir, key("moved"), run(900, 2048), now - 40 * day + i);
        }
        for i in 0..800 {
            remember_at(&dir, key("moved"), run(3000, 8192), now - day + i);
        }
        assert_eq!(
            std::fs::read_to_string(dir.join("moved"))
                .unwrap()
                .lines()
                .count(),
            TRIM_AT
        );

        // The newest ceiling answers from its own runs...
        assert_eq!(
            most_recent_at(&dir, key("moved"), ceiling(8192), now).map(|r| r.most / MIB),
            Some(3000)
        );
        // ...and going back to the old one still finds runs there, rather than falling back
        // to the declared size as it would if the trim had dropped them.
        let earlier = most_recent_at(&dir, key("moved"), ceiling(2048), now)
            .expect("the earlier ceiling's runs survived the trim");
        assert_eq!(earlier.most / MIB, 900);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The line a job trace ends with: what a person reads to size the host by.
    #[test]
    fn the_trace_line_says_what_the_job_uses_and_what_it_will_reserve() {
        let dir = tmpdir("summary");
        let now = 1_700_000_000;
        let day = 24 * 60 * 60;
        // Read at the same `now` the samples are written at: reading against the wall clock
        // would age every one of them out and answer from the MIN_RUNS floor instead, which
        // gives the same numbers here and so would assert nothing about the window.
        assert_eq!(history_summary_at(&dir, key("none"), 8192, true, now), None);

        remember_at(&dir, key("job"), run(1600, CEIL), now);
        let line = history_summary_at(&dir, key("job"), 8192, true, now).unwrap();
        assert_eq!(
            line,
            "virtkit: most this job has used lately: memory 1.6 GiB over 1 run; \
             the next run reserves 2.0 GiB"
        );
        // With the host still reserving declared sizes, the figure is worth showing — it is
        // how an operator decides to turn that on — but there is no reservation to promise.
        remember_at(&dir, key("job"), run(1600, CEIL), now);
        let line = history_summary_at(&dir, key("job"), 8192, false, now).unwrap();
        assert_eq!(
            line,
            "virtkit: most this job has used lately: memory 1.6 GiB over 2 runs"
        );
        // A run that moved disk and pulled traffic puts both on the line beside the memory —
        // as the two runs above, which measured neither, left them off rather than reading as
        // zero.
        remember_at(
            &dir,
            key("job"),
            Run {
                peak: 1600 * MIB,
                ceiling: ceiling(CEIL),
                disk: Some((3482 * MIB, 812 * MIB)),
                network: Some((3 * MIB, 941 * MIB)),
                ..Run::default()
            },
            now,
        );
        assert_eq!(
            history_summary_at(&dir, key("job"), 8192, false, now).unwrap(),
            "virtkit: most this job has used lately: memory 1.6 GiB, read 3.4 GiB, \
             written 812 MiB, sent 3 MiB, received 941 MiB over 3 runs"
        );

        // The writable layer reads beside the memory and before the traffic, as the pair it is:
        // the mark alone would not say this job came within a hair of failing on space. What
        // its job dir held on the host follows it.
        remember_at(
            &dir,
            key("filled"),
            Run {
                peak: 15_800 * MIB,
                ceiling: ceiling(CEIL),
                overlay: Some((9_950 * MIB, 10_240 * MIB)),
                footprint: Some(6_554 * MIB),
                ..Run::default()
            },
            now,
        );
        assert_eq!(
            history_summary_at(&dir, key("filled"), 8192, false, now).unwrap(),
            "virtkit: most this job has used lately: memory 15.4 GiB, \
             overlay 9.7 GiB of 10.0 GiB, job dir 6.4 GiB over 1 run"
        );

        // Read against the ceiling the job is running at now, so widening MICROVM_MEM leaves
        // the same job with nothing to report until it has run there.
        assert_eq!(history_summary_at(&dir, key("job"), 16384, true, now), None);

        // A run that measured zero says so, exactly as the per-run line does — the clause goes
        // missing only where nobody could take the figure at all.
        remember_at(
            &dir,
            key("zero"),
            Run {
                peak: 900 * MIB,
                ceiling: ceiling(CEIL),
                disk: Some((0, 0)),
                ..Run::default()
            },
            now,
        );
        assert_eq!(
            history_summary_at(&dir, key("zero"), 8192, false, now).unwrap(),
            "virtkit: most this job has used lately: memory 900 MiB, read 0 B, \
             written 0 B over 1 run"
        );

        // The largest run in the window, not the one that just ended.
        remember_at(&dir, key("peaky"), run(3000, CEIL), now - day);
        remember_at(&dir, key("peaky"), run(900, CEIL), now);
        assert_eq!(
            history_summary_at(&dir, key("peaky"), 8192, false, now).unwrap(),
            "virtkit: most this job has used lately: memory 2.9 GiB over 2 runs"
        );

        // Past MIN_RUNS the window really does decide: a spike a month old leaves both the
        // figure and the count.
        remember_at(&dir, key("aged"), run(8000, CEIL), now - 30 * day);
        for age in [3 * day, 2 * day, day, day / 2, 60] {
            remember_at(&dir, key("aged"), run(900, CEIL), now - age);
        }
        assert_eq!(
            history_summary_at(&dir, key("aged"), 8192, false, now).unwrap(),
            "virtkit: most this job has used lately: memory 900 MiB over 5 runs"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_changed_ceiling_starts_the_history_again() {
        let dir = tmpdir("ceiling");
        let now = 1_700_000_000;
        for peak in [3900, 4000, 3950] {
            remember_at(&dir, key("job"), run(peak, 4096), now - 60);
        }
        assert_eq!(
            most_recent_at(&dir, key("job"), ceiling(4096), now),
            recent(4000, 3)
        );

        // Given four times the room, the job is unknown again rather than predicted from
        // runs that were pressed against the old ceiling.
        assert_eq!(most_recent_at(&dir, key("job"), ceiling(16384), now), None);
        assert_eq!(expect_mib(&dir, key("job"), 16384), None);

        // Its first run at the new ceiling is what it is then read against.
        remember_at(&dir, key("job"), run(11000, 16384), now);
        assert_eq!(
            most_recent_at(&dir, key("job"), ceiling(16384), now),
            recent(11000, 1)
        );

        // And putting the ceiling back finds the earlier runs still there — nothing was
        // thrown away, only set aside.
        assert_eq!(
            most_recent_at(&dir, key("job"), ceiling(4096), now),
            recent(4000, 3)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The history is written by every job on the host, and the trim rewrites the whole file
    /// — so concurrent writers must not erase each other's runs.
    #[test]
    fn concurrent_writers_do_not_lose_each_others_runs() {
        const THREADS: u64 = 4;
        // Past TRIM_AT, but by less than one thread's share: the trim drops the oldest
        // THREADS * EACH - TRIM_AT runs, so every thread's own last run — written no earlier
        // than its EACH'th of the total — is still there however the threads interleaved.
        const EACH: u64 = 300;
        let dir = tmpdir("shared-history");
        let now = 1_700_000_000;

        let writers: Vec<_> = (0..THREADS)
            .map(|t| {
                let dir = dir.clone();
                std::thread::spawn(move || {
                    for i in 0..EACH {
                        // Distinct peaks, so a lost run is a missing value and not a
                        // duplicate of someone else's.
                        remember_at(
                            &dir,
                            key("shared"),
                            run(1000 + t * EACH + i, CEIL),
                            now - 60,
                        );
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().unwrap();
        }

        // Every line still parses, and the file is trimmed to the cap rather than to
        // whatever one racing writer happened to hold in memory.
        let text = std::fs::read_to_string(dir.join("shared")).unwrap();
        let samples = parse(&text);
        assert_eq!(samples.len(), text.lines().count(), "a torn line");
        assert_eq!(samples.len(), TRIM_AT);

        // Nothing was dropped but by the trim: each writer's last run is still there, where
        // an unlocked rewrite would have erased whatever landed during its read.
        let kept: HashSet<u64> = samples.iter().map(|s| s.peak / MIB).collect();
        assert_eq!(kept.len(), samples.len(), "a run was written twice");
        for t in 0..THREADS {
            let last = 1000 + t * EACH + EACH - 1;
            assert!(
                kept.contains(&last),
                "writer {t} lost its last run ({last})"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A key names a history inside the directory, or it names nothing. `usage_key` already
    /// sanitises every component, but these functions take a bare path and `Path::join`
    /// throws the base away for an absolute one, so the guard lives here too.
    #[test]
    fn a_key_that_would_leave_the_directory_is_refused() {
        let dir = tmpdir("escape");
        let now = 1_700_000_000;

        // Put to `under` itself rather than to a write against one of these paths: it is the
        // one place the guard lives, and asking it directly cannot touch a file outside `dir`
        // however the code around it changes.
        for escape in ["/etc/passwd", "../outside", "", "/"] {
            assert_eq!(under(&dir, key(escape)), None, "{escape:?} was let through");
        }

        // A real two-component key is written and read as usual.
        let real = Path::new("42-proj").join("build-abc123");
        assert_eq!(under(&dir, &real), Some(dir.join(&real)));
        remember_at(&dir, &real, run(1600, CEIL), now);
        assert_eq!(
            most_recent_at(&dir, &real, ceiling(CEIL), now),
            recent(1600, 1)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The scheduler asks what a typical job reserves without knowing any job's ceiling, so
    /// each history answers for the one it last ran under.
    #[test]
    fn a_job_is_read_against_the_ceiling_it_last_ran_under() {
        let dir = tmpdir("last-ceiling");
        let now = 1_700_000_000;
        remember_at(&dir, key("job"), run(3900, 4096), now - 120);
        remember_at(&dir, key("job"), run(9000, 16384), now - 60);
        // The 16 GiB run is the current one, so the estimate follows it and is capped there.
        assert_eq!(
            expect_last_mib(&dir, key("job")),
            Some(reserve_mib(9000, 16384))
        );

        // Nothing recorded, nothing to read against.
        assert_eq!(expect_last_mib(&dir, key("never-run")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What the scheduler reads off the ledger: how much is granted, by how many jobs, and
    /// how many are still queued behind them.
    #[test]
    fn the_ledger_reports_what_it_currently_holds() {
        let dir = tmpdir("committed");
        // Nothing there yet — not even the directory. A ledger that has never existed holds
        // nothing; only one that exists and cannot be read is an error.
        let empty = committed(&dir.join("missing")).expect("a fresh host holds nothing");
        assert_eq!((empty.granted_mib, empty.granted, empty.ahead), (0, 0, 0));

        let _running = held(&dir, "one", 2048, 1, true);
        let _also = held(&dir, "two", 1024, 2, true);
        let _queued = held(&dir, "three", 4096, 3, false);
        let now = committed(&dir).unwrap();
        assert_eq!(now.granted_mib, 3072, "only the granted count against it");
        assert_eq!(now.granted, 2);
        assert_eq!(now.ahead, 1, "the waiter is counted but not charged");

        // The lock file the directory keeps is not a project, so nothing is read out of it.
        assert!(dir.join(LOCK).exists(), "committed took the lock");
        assert!(all_expected(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The report an operator sizes a host from: every job of a project, heaviest first, with
    /// the figures lined up under one set of columns and a closing line saying what the lot
    /// would reserve at once.
    #[test]
    fn a_project_report_lists_each_job_against_the_host_budget() {
        let dir = tmpdir("report");
        let now = 1_700_000_000;
        let digest = "0123456789abcdef0123456789abcdef"; // as `job_component` appends one
        let put = |project: &str, job: &str, run: Run| {
            let key = Path::new(project).join(format!("{job}-{digest}"));
            remember_at(&dir, &key, run, now);
        };
        put("42-acme", "build", run(6000, CEIL));
        put(
            "42-acme",
            "test_unit",
            Run {
                peak: 500 * MIB,
                ceiling: ceiling(2048),
                disk: Some((10 * MIB, 20 * MIB)),
                // An overlaid checkout it nearly filled, beside a job that had no layer at all:
                // the column has to tell those two apart.
                overlay: Some((900 * MIB, 1024 * MIB)),
                footprint: Some(1536 * MIB),
                ..Run::default()
            },
        );
        put("77-other", "lint", run(300, 2048));

        // Narrowed by any part of the directory name — the slug is what an operator knows.
        let report = project_report(&dir, "acme", Some(Ok(16384)), true).expect("acme has run");
        // Written out at the left margin, as the table it is: a column that stops lining up is
        // the whole failure, and an expectation wrapped to fit an indent could not show it.
        let want = "\
virtkit: 42-acme — what its jobs have been using lately:
  job         memory            overlay  job dir  ceiling  reserves  runs    read  written  sent  received
  build      5.9 GiB                  -        -  8.0 GiB   7.3 GiB     1       -        -     -         -
  test_unit  500 MiB  900 MiB / 1.0 GiB  1.5 GiB  2.0 GiB   625 MiB     1  10 MiB   20 MiB     -         -
virtkit: 2 jobs; all at once they would reserve 7.9 GiB, against a budget of 16.0 GiB
";
        assert_eq!(report, want);
        assert!(!report.contains(digest), "the digest is not for reading");

        // No project named reports the whole host, one table's worth of columns throughout.
        let all = project_report(&dir, "", None, true).expect("something has run");
        assert!(all.contains("42-acme") && all.contains("77-other"), "{all}");
        assert!(
            all.ends_with(
                "virtkit: 3 jobs; all at once they would reserve 8.4 GiB, \
                 with no [executor.schedule] mem_budget to hold them back\n"
            ),
            "{all}"
        );
        // And a project nothing answers to reports nothing, as does an empty history.
        assert_eq!(project_report(&dir, "no-such-project", None, true), None);
        assert_eq!(project_report(&dir.join("missing"), "", None, true), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A project's whole directory name can sit inside another's, so the report a job asks for
    /// is matched exactly: it goes into a trace anyone who can see that job can read, and the
    /// other project's pipelines may be none of their business.
    #[test]
    fn the_report_a_job_asks_for_covers_its_own_project_only() {
        let dir = tmpdir("own");
        let now = 1_700_000_000;
        let put = |project: &str| {
            remember_at(
                &dir,
                &Path::new(project).join("build-0123456789abcdef0123456789abcdef"),
                run(1000, CEIL),
                now,
            );
        };
        put("4-acme");
        put("14-acme-web");

        let report = own_project_report(&dir, "4-acme", None, true).expect("4-acme has run");
        assert!(report.contains("4-acme"), "{report}");
        assert!(!report.contains("14-acme-web"), "{report}");
        assert!(
            report.contains("1 job;"),
            "one project's jobs, not both: {report}"
        );
        // A job of a project this host has never run reports nothing at all.
        assert_eq!(own_project_report(&dir, "9-elsewhere", None, true), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A figure the host could not take is remembered as unmeasurable and stays out of the
    /// maximum, rather than being written as a zero that then reads as a fact about the job.
    /// The two pairs are independent: a `net.mode = "tap"` job on a kernel that accounts
    /// block I/O measures its disk and not its network.
    #[test]
    fn an_unmeasurable_figure_is_not_remembered_as_zero() {
        let dir = tmpdir("unmeasurable");
        let now = 1_700_000_000;
        let ceil = ceiling(CEIL);
        let measured = Run {
            peak: 900 * MIB,
            ceiling: ceil,
            disk: Some((10 * MIB, 20 * MIB)),
            ..Run::default()
        };
        remember_at(&dir, key("job"), measured, now);
        remember_at(
            &dir,
            key("job"),
            Run {
                peak: 800 * MIB,
                disk: None,
                ..measured
            },
            now,
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("job")).unwrap(),
            format!(
                "{now} {} {ceil} {} {} - - - - -\n{now} {} {ceil} - - - - - - -\n",
                900 * MIB,
                10 * MIB,
                20 * MIB,
                800 * MIB
            ),
            "an unmeasurable figure is written as one, not as zero"
        );
        assert_eq!(
            most_recent_at(&dir, key("job"), ceil, now),
            Some(Recent {
                most: 900 * MIB,
                // The run that could measure carries the disk; the network neither run saw
                // has no maximum at all, which is what keeps it off the trace line — as does
                // the writable layer neither run had, and the job dir neither run measured.
                most_disk: Some((10 * MIB, 20 * MIB)),
                most_network: None,
                most_overlay: None,
                most_footprint: None,
                runs: 2,
            })
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two job names can reduce to the same readable half, and the digest is what keeps
    /// their histories apart — so the report has to keep their rows apart too, or an
    /// operator reads two different jobs as one.
    #[test]
    fn two_jobs_that_read_alike_get_rows_of_their_own() {
        let dir = tmpdir("collide");
        let now = 1_700_000_000;
        // What `job_component` writes for two names that `path_component` reduces alike.
        for digest in [
            "0123456789abcdef0123456789abcdef",
            "fedcba9876543210fedcba9876543210",
        ] {
            let key = Path::new("42-acme").join(format!("deploy_prod-{digest}"));
            remember_at(&dir, &key, run(1000, CEIL), now);
        }
        let report = project_report(&dir, "acme", None, true).expect("acme has run");
        assert_eq!(
            report.matches("deploy_prod").count(),
            2,
            "both jobs are on the report: {report}"
        );
        // The whole digest, not a prefix: these are names chosen to read alike, so a prefix
        // would separate them only as well as its own length.
        assert!(
            report.contains("deploy_prod (0123456789abcdef0123456789abcdef)"),
            "{report}"
        );
        assert!(
            report.contains("deploy_prod (fedcba9876543210fedcba9876543210)"),
            "{report}"
        );

        // A name only one job wears is left as it is — the suffix is for collisions alone.
        let lone = Path::new("42-acme").join("lint-0123456789abcdef0123456789abcdef");
        remember_at(&dir, &lone, run(500, CEIL), now);
        let report = project_report(&dir, "acme", None, true).expect("acme has run");
        assert!(report.contains(" lint "), "{report}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A torn or truncated append is dropped whole rather than read as a run that never
    /// happened.
    #[test]
    fn a_half_written_run_is_not_read_as_a_run() {
        let dir = tmpdir("torn");
        let now = 1_700_000_000;
        std::fs::create_dir_all(&dir).unwrap();
        let ceil = ceiling(CEIL);
        let (peak, read, written) = (900 * MIB, 10 * MIB, 20 * MIB);
        let (sent, received) = (2 * MIB, 400 * MIB);
        let (mark, cap) = (600 * MIB, 1024 * MIB);
        let footprint = 3000 * MIB;
        let (torn, lesser, narrower) = (4000 * MIB, 700 * MIB, 5000 * MIB);
        // Two pairs where three are due: short of a field older lines have.
        std::fs::write(
            dir.join("job"),
            format!(
                "{now} {peak} {ceil} {read} {written} {sent} {received} {mark} {cap} {footprint}\n\
                 {now} {torn} {ceil} 30 30 30\n\
                 nonsense\n\
                 {now} {narrower} {ceil} 5 5 5 5\n\
                 {now} {lesser} {ceil} 5 5 5 5 5 5 5\n"
            ),
        )
        .unwrap();
        // The two whole lines, neither the one cut short mid-append, nor the unparseable one,
        // nor the one a field short — so the 4000 and 5000 MiB peaks and the 30 bytes the torn
        // line claims to have read are all left out.
        assert_eq!(
            most_recent_at(&dir, key("job"), ceil, now),
            Some(Recent {
                most: peak,
                most_disk: Some((read, written)),
                most_network: Some((sent, received)),
                most_overlay: Some((mark, cap)),
                most_footprint: Some(footprint),
                runs: 2,
            })
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_supervisor_picks_up_the_reservation_prepare_took() {
        let dir = tmpdir("handoff");
        let prepared = acquire_mem(&dir, "job", 2048, 8192, Duration::from_secs(0)).unwrap();
        // The supervisor takes its own lock on the same entry, then prepare exits.
        let supervised = hold(&dir, "job").expect("the entry prepare left");
        drop(prepared);

        // The reservation still counts, held by the supervisor alone.
        assert_eq!(live_mib(&dir), 2048);
        drop(supervised);
        until_ledger_is(&dir, 0);

        // A job with no reservation (admission off) has nothing to hold.
        assert!(hold(&dir, "unknown").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `hold` must never re-create an entry that has already gone: the file it made would be
    /// empty, so no scan could parse it, and none could reclaim it while this process held it
    /// locked — the job's memory would count for nobody for the whole of its life.
    #[test]
    fn hold_does_not_resurrect_an_entry_that_has_been_released() {
        let dir = tmpdir("hold-gone");
        let prepared = acquire_mem(&dir, "job", 2048, 8192, Duration::from_secs(0)).unwrap();
        drop(prepared);
        release(&dir, "job");

        assert!(hold(&dir, "job").is_none(), "nothing left to hold");
        assert!(!dir.join("job").exists(), "hold must not have created it");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Nothing a scan can see is ever half-written. An entry is created and written in one
    /// critical section, so a scanner — which must hold the directory lock, as this probe does
    /// — can only ever observe it complete. Were the write deferred to the next pass of the
    /// admission loop, a scan landing in between would fail to parse the entry: it would then
    /// report a ledger anomaly against a job that is merely starting up, and leave that job's
    /// request out of the queue order for the pass.
    ///
    /// The probe scans as fast as it can take the lock, against churn from admissions that
    /// never wait, so the window is sampled thousands of times rather than a handful.
    #[test]
    fn a_scan_never_observes_a_half_written_entry() {
        let dir = tmpdir("half-written");
        let watching = Arc::new(AtomicBool::new(true));
        let odd = Arc::new(AtomicU64::new(0));
        let scans = Arc::new(AtomicU64::new(0));
        let watcher = std::thread::spawn({
            let (dir, watching, odd, scans) = (
                dir.clone(),
                Arc::clone(&watching),
                Arc::clone(&odd),
                Arc::clone(&scans),
            );
            move || {
                while watching.load(Ordering::Relaxed) {
                    odd.fetch_add(live(&dir).1 as u64, Ordering::Relaxed);
                    scans.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        struct StopOnDrop(Arc<AtomicBool>);
        impl Drop for StopOnDrop {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Relaxed);
            }
        }
        let _stop = StopOnDrop(Arc::clone(&watching));

        // Four jobs that all fit together, so every acquire is granted on its first pass and
        // the churn is pure create-and-release.
        for _ in 0..50 {
            let held: Vec<_> = (0..4)
                .map(|i| {
                    let job = format!("job{i}");
                    (
                        acquire_mem(&dir, &job, 512, 8192, Duration::from_secs(0)).unwrap(),
                        job,
                    )
                })
                .collect();
            for (res, job) in held {
                drop(res);
                release(&dir, &job);
            }
        }
        watching.store(false, Ordering::Relaxed);
        watcher.join().unwrap();

        assert!(scans.load(Ordering::Relaxed) > 100, "the probe barely ran");
        assert_eq!(
            odd.load(Ordering::Relaxed),
            0,
            "a scan could not parse an entry — it is not written where it is created"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The ledger is the host's memory guard: an entry another local user could plant in it
    /// would stall every job on the box, so it must not inherit a permissive umask.
    #[test]
    fn the_ledger_is_created_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("vk-admit-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let res = acquire_mem(&dir, "job", 2048, 8192, Duration::from_secs(0)).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700, "ledger directory");
        assert_eq!(mode(&dir.join("job")), 0o600, "ledger entry");
        assert_eq!(mode(&dir.join(LOCK)), 0o600, "directory lock");

        drop(res);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A locked entry nobody can parse — a holder killed mid-write — must not count as room.
    /// It stays until its lock goes, so the budget it stood for is neither freed nor doubled.
    #[test]
    fn an_unparseable_entry_is_kept_but_uncounted() {
        let dir = tmpdir("garbled");
        let garbled = open_shared(&dir.join("mid-write")).unwrap();

        assert_eq!(live_mib(&dir), 0, "an empty entry reserves nothing");
        assert!(dir.join("mid-write").exists(), "but is not reclaimed");

        // Once it finishes writing it counts, without having been reclaimed in between.
        Entry {
            want_mib: 2048,
            asked: 1,
            granted: true,
            node: None,
            disk: None,
        }
        .write(&garbled, &dir.join("mid-write"))
        .unwrap();
        assert_eq!(live_mib(&dir), 2048);

        drop(garbled);
        release(&dir, "mid-write");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A non-zero timeout really is waited out, and the wait ends in a refusal rather than
    /// hanging — every other timeout case here passes zero.
    #[test]
    fn a_non_zero_timeout_expires_and_refuses() {
        let dir = tmpdir("expires");
        let _full = held(&dir, "running", 8192, 1, true);

        let asked_at = Instant::now();
        let err = acquire_mem(&dir, "waiter", 8192, 8192, POLL + POLL / 2).unwrap_err();
        assert!(err.to_string().contains("no room"), "{err}");
        assert!(
            asked_at.elapsed() >= POLL,
            "gave up before the timeout it was given"
        );
        assert!(!dir.join("waiter").exists(), "a refused job leaves nothing");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The node a job was placed on survives a round trip through the ledger, and an entry
    /// written before placement existed still reads as one that was never placed.
    #[test]
    fn an_entry_remembers_the_node_it_was_placed_on() {
        let dir = tmpdir("entry-node");

        let bound = held_on(&dir, "bound", 2048, 1, true, Some(Place::Node(3)));
        assert_eq!(
            std::fs::read_to_string(dir.join("bound")).unwrap(),
            "2048 1 granted node=3\n"
        );
        assert_eq!(Entry::read(&bound).unwrap().node, Some(Place::Node(3)));

        let spread = held_on(&dir, "spread", 1024, 2, true, Some(Place::Spread));
        assert_eq!(
            std::fs::read_to_string(dir.join("spread")).unwrap(),
            "1024 2 granted spread\n"
        );
        assert_eq!(Entry::read(&spread).unwrap().node, Some(Place::Spread));

        // Three fields: every entry this ledger held before placement, and every entry on a
        // host that places nothing.
        let old = open_shared(&dir.join("old")).unwrap();
        (&old).write_all(b"512 7 granted\n").unwrap();
        let entry = Entry::read(&old).unwrap();
        assert_eq!((entry.want_mib, entry.asked, entry.granted), (512, 7, true));
        assert_eq!(entry.node, None);

        // An unplaced entry counts against the budget as it always did, and against no node:
        // neither the per-node breakdown nor the interleaved share knows anything about it.
        let held = committed(&dir).unwrap();
        assert_eq!(held.granted_mib, 2048 + 1024 + 512);
        assert_eq!(held.per_node.len(), 1);
        assert_eq!(
            held.per_node.get(&3).copied(),
            Some(crate::numa::NodeLoad {
                granted_mib: 2048,
                jobs: 1,
            })
        );
        assert_eq!(
            held.spread,
            crate::numa::NodeLoad {
                granted_mib: 1024,
                jobs: 1,
            }
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A job lands on the node the ledger says is emptiest, its entry says so afterwards, and
    /// one that fits on no node is spread instead.
    #[test]
    fn a_job_is_placed_on_the_emptiest_node_the_ledger_knows() {
        let dir = tmpdir("place");
        let topology = crate::numa::Topology::of(vec![
            crate::numa::Node {
                id: 0,
                cpus: (0..4).collect(),
                mem_total_mib: 16384,
            },
            crate::numa::Node {
                id: 1,
                cpus: (4..8).collect(),
                mem_total_mib: 16384,
            },
        ]);
        // Another job already holds half of node 0.
        let _other = held_on(&dir, "other", 8192, 1, true, Some(Place::Node(0)));

        let mine = acquire_mem(&dir, "mine", 4096, 32768, Duration::from_secs(0)).unwrap();
        let placement = mine.place(&dir, &topology, 32768, Some(32768), 2).unwrap();
        assert_eq!(
            placement,
            crate::numa::Placement::Bind {
                node: 1,
                cpus: vec![4, 5, 6, 7],
                nodes_total: 2,
            }
        );
        let line = std::fs::read_to_string(dir.join("mine")).unwrap();
        assert!(
            line.starts_with("4096 ") && line.ends_with(" granted node=1\n"),
            "{line}"
        );

        let held = committed(&dir).unwrap();
        assert_eq!(held.granted_mib, 12288);
        assert_eq!(
            held.per_node.get(&0).copied(),
            Some(crate::numa::NodeLoad {
                granted_mib: 8192,
                jobs: 1,
            })
        );
        assert_eq!(
            held.per_node.get(&1).copied(),
            Some(crate::numa::NodeLoad {
                granted_mib: 4096,
                jobs: 1,
            })
        );

        // A job larger than either node's share of the budget is interleaved, and the ledger
        // records that rather than a node.
        let big = acquire_mem(&dir, "big", 20480, 32768, Duration::from_secs(0)).unwrap();
        assert_eq!(
            big.place(&dir, &topology, 32768, Some(32768), 2).unwrap(),
            crate::numa::Placement::Interleave { nodes: vec![0, 1] }
        );
        assert!(
            std::fs::read_to_string(dir.join("big"))
                .unwrap()
                .ends_with(" granted spread\n")
        );
        assert_eq!(
            committed(&dir).unwrap().spread,
            crate::numa::NodeLoad {
                granted_mib: 20480,
                jobs: 1,
            }
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    const GIB: u64 = 1 << 30;

    /// A pass that asks for `want` GiB of disk in `/jobs`, with `avail` GiB free of which the
    /// one other job holding a claim there has `pending` GiB yet to write, and with memory
    /// asked for or not.
    fn disk_pass(want: u64, avail: u64, pending: u64, mem: Option<MemAsk>) -> Pass<'static> {
        Pass {
            ask: Ask {
                mem,
                disk: Some(DiskAsk {
                    want: want * GIB,
                    jobs: Path::new("/jobs"),
                }),
            },
            used_mib: 0,
            ahead: 0,
            room: Some(DiskRoom {
                avail: avail * GIB,
                pending: pending * GIB,
                held: 0,
                claims: 1,
            }),
        }
    }

    /// Bytes no filesystem can compress or deduplicate away, so a size test measures blocks
    /// really allocated.
    fn noise(len: usize) -> Vec<u8> {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    /// A job fits on disk when what is free covers what the admitted jobs have yet to write
    /// plus its own expectation — and not a byte less.
    #[test]
    fn disk_admission_charges_what_admitted_jobs_have_yet_to_write() {
        assert_eq!(disk_pass(50, 100, 50, None).blocker(), None, "exactly fits");
        let short = disk_pass(51, 100, 50, None);
        assert_eq!(short.blocker(), Some(Blocker::Disk));
        assert_eq!(
            short.note(),
            "virtkit: waiting for 51.0 GiB of room in /jobs (100.0 GiB free, 50.0 GiB still to \
             be written by the jobs admitted there, 0 job(s) asked first)"
        );
        assert_eq!(
            short.refusal(Duration::from_secs(600)),
            "no room in /jobs for the 51.0 GiB this job is expected to write within 600s \
             ([executor.schedule] wait_timeout_secs)"
        );
        // A job that fits waits its turn all the same, and says it is the queue it waited on.
        let queued = Pass {
            ahead: 2,
            ..disk_pass(1, 100, 0, None)
        };
        assert_eq!(queued.blocker(), Some(Blocker::Queue));
        assert!(
            queued.note().contains("of room in /jobs"),
            "{}",
            queued.note()
        );
        assert_eq!(
            queued.refusal(Duration::from_secs(5)),
            "not admitted within 5s: 2 job(s) that asked first are still waiting \
             ([executor.schedule] wait_timeout_secs)"
        );
        assert_eq!(Blocker::Queue.what(), "the jobs that asked first");

        // With memory asked for too, the wait is told as one for whichever is short — memory
        // where both are, since that is the figure a job is sized by.
        let mem = |want_mib| {
            Some(MemAsk {
                want_mib,
                budget_mib: 8192,
            })
        };
        let with_mem = |want, want_mib| Pass {
            used_mib: 4096,
            ..disk_pass(want, 100, 50, mem(want_mib))
        };
        assert_eq!(with_mem(51, 4096).blocker(), Some(Blocker::Disk));
        let both = with_mem(51, 8192);
        assert_eq!(both.blocker(), Some(Blocker::Memory));
        assert!(both.note().contains("MiB memory budget"), "{}", both.note());
        let mem_only = with_mem(1, 8192);
        assert_eq!(mem_only.blocker(), Some(Blocker::Memory));
        assert!(
            mem_only
                .refusal(Duration::from_secs(1))
                .starts_with("no room in the host's 8192 MiB memory budget"),
            "{}",
            mem_only.refusal(Duration::from_secs(1))
        );
        assert_eq!(with_mem(1, 4096).blocker(), None);
        // A pass memory keeps out never reads the filesystem, and still says it is memory.
        let unread = Pass {
            room: None,
            ..with_mem(51, 8192)
        };
        assert_eq!(unread.blocker(), Some(Blocker::Memory));
        assert_eq!(unread.note(), both.note());
        assert_eq!(
            unread.refusal(Duration::from_secs(1)),
            both.refusal(Duration::from_secs(1))
        );

        // Totals read off disk saturate rather than wrap into apparent room.
        let wrapped = Pass {
            room: Some(DiskRoom {
                avail: 100 * GIB,
                pending: u64::MAX,
                held: 0,
                claims: 1,
            }),
            ..disk_pass(1, 0, 0, None)
        };
        assert_eq!(wrapped.blocker(), Some(Blocker::Disk));
    }

    /// A claim no filesystem state could ever satisfy must not lock the job out: alone on the
    /// filesystem a job goes in whatever it expects, and beside others its own test asks for at
    /// most what could come free — what is free now plus what their dirs hold.
    #[test]
    fn a_claim_the_filesystem_cannot_meet_is_cut_to_what_it_can() {
        let room = |avail, held, claims| {
            Some(DiskRoom {
                avail: avail * GIB,
                pending: 0,
                held: held * GIB,
                claims,
            })
        };
        // As big as the whole filesystem, of which some is always reserved: never free, and
        // admitted the moment nobody else holds a claim.
        let alone = Pass {
            room: room(120, 0, 0),
            ..disk_pass(128, 0, 0, None)
        };
        assert_eq!(alone.blocker(), None);
        assert_eq!(alone.disk_claim(), Some(120 * GIB));
        // Beside another job, more than could ever come free is cut to what could: it waits
        // for that much, and is admitted once it is there.
        let beside = Pass {
            room: room(20, 30, 1),
            ..disk_pass(128, 0, 0, None)
        };
        assert_eq!(beside.disk_claim(), Some(50 * GIB));
        assert_eq!(beside.blocker(), Some(Blocker::Disk));
        assert!(
            beside.note().starts_with("virtkit: waiting for 50.0 GiB"),
            "{}",
            beside.note()
        );
        let freed = Pass {
            room: room(50, 0, 1),
            ..disk_pass(128, 0, 0, None)
        };
        assert_eq!(freed.blocker(), None);
    }

    /// What an admitted job still counts for is its claim less what its dir already holds:
    /// what it has written is already out of the free space, and a job past its claim counts
    /// for nothing more.
    #[test]
    fn disk_room_nets_each_claim_against_its_job_dir() {
        let jobs = tmpdir("disk-room");
        for job in ["partway", "past"] {
            std::fs::create_dir_all(jobs.join(job)).unwrap();
            std::fs::write(jobs.join(job).join("overlay.qcow2"), noise(1 << 20)).unwrap();
        }
        let written = crate::usage::allocated_bytes(&jobs.join("partway")).unwrap();
        let past = crate::usage::allocated_bytes(&jobs.join("past")).unwrap();
        assert!(written >= 1 << 20);

        let claims = [
            (OsString::from("partway"), 10 * MIB),
            (OsString::from("past"), 1024),
            // No dir to read: charged its whole claim.
            (OsString::from("unseen"), 5 * MIB),
        ];
        let room = DiskRoom::of(&jobs, &claims).unwrap();
        assert_eq!(room.pending, 10 * MIB - written + 5 * MIB);
        assert_eq!(room.held, written + past);
        assert_eq!(room.claims, 3);
        let _ = std::fs::remove_dir_all(&jobs);
    }

    /// The ledger end to end: a disk claim is recorded in the entry, counts against the next
    /// job for as long as it is held, a claim of the whole filesystem goes in alone and is
    /// recorded whole — so it holds the next job back — and one larger than the whole
    /// filesystem is refused outright rather than left to wait.
    #[test]
    fn a_disk_claim_holds_the_next_job_back_until_it_goes() {
        let dir = tmpdir("disk-ledger");
        let jobs = tmpdir("disk-ledger-jobs");
        let ask = |want| Ask {
            mem: None,
            disk: Some(DiskAsk { want, jobs: &jobs }),
        };
        // A job already admitted that has yet to write more than the filesystem has free.
        let blocker = open_shared(&dir.join("running")).unwrap();
        Entry {
            want_mib: 0,
            asked: 1,
            granted: true,
            node: None,
            disk: Some(u64::MAX / 2),
        }
        .write(&blocker, &dir.join("running"))
        .unwrap();
        assert_eq!(
            committed(&dir).unwrap().disk,
            vec![(OsString::from("running"), u64::MAX / 2)]
        );

        let err = acquire(&dir, "next", &ask(1), Duration::from_secs(0)).unwrap_err();
        let jobs_shown = jobs.display().to_string();
        assert!(
            err.to_string()
                .starts_with(&format!("no room in {jobs_shown} for the 1 B")),
            "{err}"
        );
        assert!(!dir.join("next").exists(), "a refused job leaves nothing");

        drop(blocker);
        release(&dir, "running");
        let res = acquire(&dir, "next", &ask(1), Duration::from_secs(0)).unwrap();
        assert_eq!(
            Entry::read(&res.file).unwrap().disk,
            Some(1),
            "the claim is in the entry"
        );

        drop(res);
        release(&dir, "next");

        // A claim of the whole filesystem, of which never all is free, goes in alone. Its own
        // test was cut to what was free, but the ledger keeps the whole claim: recorded cut, it
        // would let the next job in the moment space came free.
        let total = crate::usage::fs_space(&jobs).unwrap().total;
        let whole = acquire(&dir, "whole", &ask(total), Duration::from_secs(0)).unwrap();
        assert_eq!(Entry::read(&whole.file).unwrap().disk, Some(total));
        let err = acquire(&dir, "after", &ask(1), Duration::from_secs(0)).unwrap_err();
        assert!(err.to_string().starts_with("no room in"), "{err}");
        drop(whole);
        release(&dir, "whole");

        let err = acquire(&dir, "huge", &ask(total + 1), Duration::from_secs(60)).unwrap_err();
        assert!(err.to_string().contains("never be admitted"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&jobs);
    }

    /// The disk claim rides after the node, where a reader that knows only the node passes over
    /// it, and a claim that does not parse makes the entry unreadable rather than claimless.
    #[test]
    fn an_entry_remembers_its_disk_claim() {
        let dir = tmpdir("entry-disk");
        let placed = held_on(&dir, "placed", 2048, 1, true, Some(Place::Node(3)));
        let mut entry = Entry::read(&placed).unwrap();
        entry.disk = Some(12345);
        entry.write(&placed, &dir.join("placed")).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("placed")).unwrap(),
            "2048 1 granted node=3 disk=12345\n"
        );
        let back = Entry::read(&placed).unwrap();
        assert_eq!((back.node, back.disk), (Some(Place::Node(3)), Some(12345)));

        // A field a later version adds is passed over without costing the node.
        let later = open_shared(&dir.join("later")).unwrap();
        (&later)
            .write_all(b"0 1 granted node=2 disk=7 extra=1\n")
            .unwrap();
        let back = Entry::read(&later).unwrap();
        assert_eq!((back.node, back.disk), (Some(Place::Node(2)), Some(7)));

        let garbled = open_shared(&dir.join("garbled")).unwrap();
        (&garbled).write_all(b"0 1 granted disk=12x\n").unwrap();
        assert!(Entry::read(&garbled).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What a job's dir is expected to grow to: the most it has held lately plus headroom,
    /// capped at the filesystem, and nothing where no run measured it.
    #[test]
    fn a_disk_expectation_follows_what_the_job_dir_has_held() {
        let dir = tmpdir("disk-history");
        assert_eq!(expect_disk(&dir, key("job"), CEIL, u64::MAX), None);
        // A run that could not read its dir is no evidence either way.
        remember(&dir, key("job"), run(1000, CEIL));
        assert_eq!(expect_disk(&dir, key("job"), CEIL, u64::MAX), None);

        for footprint in [8 * GIB, 16 * GIB, 4 * GIB] {
            let measured = Run {
                footprint: Some(footprint),
                ..run(1000, CEIL)
            };
            remember(&dir, key("job"), measured);
        }
        assert_eq!(
            expect_disk(&dir, key("job"), CEIL, u64::MAX),
            Some(20 * GIB)
        );
        // Headroom never asks for more than the filesystem has.
        assert_eq!(
            expect_disk(&dir, key("job"), CEIL, 18 * GIB),
            Some(18 * GIB)
        );
        // Read against the ceiling, as memory is: another MICROVM_MEM starts again.
        assert_eq!(expect_disk(&dir, key("job"), 2 * CEIL, u64::MAX), None);
        assert!(
            history_summary(&dir, key("job"), CEIL, false)
                .unwrap()
                .contains("memory 1000 MiB, job dir 16.0 GiB over 4 runs"),
            "{:?}",
            history_summary(&dir, key("job"), CEIL, false)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A run recorded before the job dir figure existed ends one field short: its memory and
    /// the rest still count, and its job dir reads as unmeasured rather than dropping the run.
    #[test]
    fn a_run_recorded_before_the_job_dir_figure_still_counts() {
        let dir = tmpdir("pre-footprint");
        let now = 1_700_000_000;
        std::fs::create_dir_all(&dir).unwrap();
        let ceil = ceiling(CEIL);
        let peak = 900 * MIB;
        std::fs::write(
            dir.join("job"),
            format!("{now} {peak} {ceil} 10 20 - - 600 1024\n"),
        )
        .unwrap();
        assert_eq!(
            most_recent_at(&dir, key("job"), ceil, now),
            Some(Recent {
                most: peak,
                most_disk: Some((10, 20)),
                most_network: None,
                most_overlay: Some((600, 1024)),
                most_footprint: None,
                runs: 1,
            })
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
