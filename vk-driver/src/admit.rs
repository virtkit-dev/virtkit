//! Memory admission for CI jobs: a host-wide ledger that keeps a runner from committing
//! more guest RAM than it can back.
//!
//! Without it a runner takes every job its `concurrent` limit allows and the host's OOM
//! killer arbitrates — it takes a VMM, and that job dies mid-stage. So a job reserves what
//! it is about to boot before it boots it, and waits when the host is full.
//!
//! The ledger is one file per job under `<state_dir>/admit/`, holding what the job reserved
//! and when it asked. A reservation counts only while someone holds a shared `flock` on it:
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
#[derive(Debug)]
pub struct Reservation {
    _file: File,
}

/// Reserve `want_mib` for `job_id` against `budget_mib`, waiting up to `timeout` for room.
/// Prints its wait to stdout — this runs in `prepare`, whose output the job trace keeps, so
/// a job that starts late says why.
///
/// Jobs are admitted oldest-request-first: a big job would otherwise wait behind an endless
/// stream of small ones that each fit. Erring the other way, a small job can queue behind a
/// big one it would have fit alongside — predictable beats optimal here.
pub fn acquire(
    dir: &Path,
    job_id: &str,
    want_mib: u64,
    budget_mib: u64,
    timeout: Duration,
) -> Result<Reservation> {
    if want_mib > budget_mib {
        // A per-job MICROVM_MEM is clamped to the budget before it reaches here, so a size
        // that still exceeds it came from the host's own `[vm] mem` default: name both, or the
        // message sends the reader after a job variable that is not the cause.
        bail!(
            "this job's {want_mib} MiB of guest memory exceeds the host's whole {budget_mib} MiB \
             budget ([schedule] mem_budget vs [vm] mem) — it can never be admitted"
        );
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
        want_mib,
        asked: now_nanos(),
        granted: false,
    };
    // Held from here on: while waiting it marks a live request other jobs must queue behind,
    // and once granted it is the reservation itself. Created under the directory lock, which
    // is what [`scan`] reaps dead entries under: an entry that exists unlocked for even the
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
    loop {
        // Both are composed under the directory lock and reported outside it: prepare's stdout
        // is a pipe gitlab-runner drains, and a stalled reader blocking on `write` must not
        // block every other runner's admission on the host-wide lock.
        let mut wait_note = None;
        let mut anomalies = Vec::new();
        // The block yields whether we got in and nothing more, so no reporting can sit inside
        // the critical section even by accident.
        let admitted = {
            let _dir_lock = lock_dir(dir)?;
            let (used_mib, ahead) = scan(dir, job_id, entry.asked, &mut anomalies)?;
            // Saturating, like the totals it compares: a corrupt entry must not add up to
            // apparent room.
            if ahead == 0 && used_mib.saturating_add(want_mib) <= budget_mib {
                entry.granted = true;
                entry.write(&file, &path)?;
                true
            } else {
                if waited_since.is_none() {
                    waited_since = Some(Instant::now());
                    wait_note = Some(format!(
                        "virtkit: waiting for {want_mib} MiB of the host's {budget_mib} MiB \
                         memory budget ({used_mib} MiB reserved, {ahead} job(s) asked first)"
                    ));
                }
                false
            }
        };
        report(&anomalies);
        if admitted {
            if let Some(since) = waited_since {
                println!(
                    "virtkit: admitted after waiting {:.0}s for memory",
                    Instant::now().duration_since(since).as_secs_f64()
                );
            }
            return Ok(Reservation { _file: file });
        }
        if let Some(note) = wait_note {
            println!("{note}");
        }
        if Instant::now() >= deadline {
            // Best-effort: the entry stops counting the moment this process drops its lock,
            // and a scan that got there first has already removed it.
            let _ = std::fs::remove_file(&path);
            bail!(
                "no room in the host's {budget_mib} MiB memory budget for this job's \
                 {want_mib} MiB within {}s ([schedule] wait_timeout_secs)",
                timeout.as_secs()
            );
        }
        std::thread::sleep(POLL);
    }
}

/// Re-open the reservation `prepare` was granted and hold it for this process's life — the
/// supervisor's half of the handoff. `None` when the job has no reservation (admission off),
/// which is not an error: the ledger only exists when a budget is configured.
///
/// Needs no directory lock, unlike [`acquire`]: prepare holds its own lock on this entry
/// until the guest answers, which is long after this runs, so no scan can take it for
/// abandoned in between.
pub fn hold(dir: &Path, job_id: &str) -> Option<Reservation> {
    let path = dir.join(job_id);
    // One open, and never creating. Testing for the file and then opening it would be two
    // resolutions of the same path: an entry removed in between — by a racing cleanup, or by
    // the scan that reaps abandoned ones — would be re-created here as an empty file, which no
    // scan can parse and none can reclaim while this process holds it locked. The job's memory
    // would then count for nobody for the whole of its life.
    match open_locked_shared(&path) {
        Ok(file) => Some(Reservation { _file: file }),
        // admission is off — prepare never made an entry
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        // An entry that exists but cannot be re-locked is not the same as no entry at all:
        // this job's memory stops counting against the budget for the rest of its life, so
        // say so in the supervisor log rather than degrading the host's guard in silence.
        Err(e) => {
            eprintln!(
                "virtkit: holding this job's memory reservation ({}): {e}",
                path.display()
            );
            None
        }
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
/// arithmetic in MiB — which is the unit the ledger, `[vm] mem` and `MICROVM_MEM` all use.
const MIB: u64 = 1024 * 1024;

/// One remembered run: when it ended, the peak it reached, the ceiling it ran under, and the
/// disk and network traffic it moved. The ceiling matters because a peak is only evidence of
/// what a job needs while the job was free to need it — a run held to 4 GiB says nothing
/// about the same job given 16.
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
    runs: usize,
}

/// Note what a job of this kind actually used, and the ceiling it used it under, for the
/// next one to be admitted against. One
/// `<unix seconds> <peak> <ceiling> <read> <written> <sent> <received>` line per run, every
/// figure in bytes and an unmeasured pair written `-`, appended whole so runs finishing
/// together cannot tear each other's; best-effort, since a lost sample only costs accuracy
/// on the next admission.
///
/// Widening the line retires the histories written before it: a run without the new fields
/// is dropped rather than read short, since a reader loose enough to accept it could not
/// tell a torn append from a whole one. A host loses a fortnight of estimates once.
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
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)
    {
        // Best-effort, as the doc says: a run that goes unrecorded costs the next admission
        // a little accuracy and nothing else.
        let _ = file.write_all(
            sample_line(&Sample {
                at_secs: now,
                peak: run.peak,
                ceiling: run.ceiling,
                disk: run.disk,
                network: run.network,
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
            Some(Sample {
                at_secs,
                peak,
                ceiling,
                disk: pair()?,
                network: pair()?,
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
    format!(
        "{} {} {} {} {}\n",
        s.at_secs,
        s.peak,
        s.ceiling,
        pair(s.disk),
        pair(s.network)
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
    let disk = moved("read", "written", recent.most_disk);
    let net = moved("sent", "received", recent.most_network);
    let most = crate::usage::fmt_bytes(recent.most);
    Some(format!(
        "virtkit: most this job has used lately: memory {most}{disk}{net} \
         over {runs} {plural}{reserves}"
    ))
}

fn fmt_mib(mib: u64) -> String {
    crate::usage::fmt_bytes(mib * MIB)
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

/// What the live ledger holds, ignoring `job_id` (the caller's own entry): the granted MiB,
/// and how many jobs asked before `asked` and are still waiting. Entries nobody holds a lock
/// on are dead — their job is gone — and are removed as they are found. Callers hold the
/// directory lock.
///
/// An unreadable ledger is an error, never an empty one: reporting nothing reserved would
/// admit every job on the host against a guard that has stopped working. Anything odd but
/// survivable is pushed onto `anomalies` for the caller to report once it has let the lock go.
fn scan(
    dir: &Path,
    job_id: &str,
    asked: u128,
    anomalies: &mut Vec<String>,
) -> Result<(u64, usize)> {
    let held = tally(dir, job_id, asked, anomalies)?;
    Ok((held.granted_mib, held.ahead))
}

/// What the ledger is holding: the memory granted and how many jobs hold it, plus how many
/// asked before `asked` and are still waiting. Ignores `job_id` (the caller's own entry).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Held {
    pub granted_mib: u64,
    pub granted: usize,
    pub ahead: usize,
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
        } else if entry.asked < asked {
            out.ahead = out.ahead.saturating_add(1);
        }
    }
    Ok(out)
}

/// One ledger entry: what the job wants, when it first asked (its place in the queue), and
/// whether it holds that memory yet.
struct Entry {
    want_mib: u64,
    asked: u128,
    granted: bool,
}

impl Entry {
    /// `<mib> <asked> <granted|waiting>`, rewritten whole each time so a reader either sees
    /// the previous line or the new one, never a splice of both.
    fn write(&self, mut file: &File, path: &Path) -> Result<()> {
        let state = if self.granted { "granted" } else { "waiting" };
        let line = format!("{} {} {state}\n", self.want_mib, self.asked);
        file.set_len(0)
            .and_then(|()| file.seek(SeekFrom::Start(0)))
            .and_then(|_| file.write_all(line.as_bytes()))
            .and_then(|()| file.flush())
            .with_context(|| format!("writing {}", path.display()))
    }

    fn read(mut file: &File) -> Option<Entry> {
        let mut text = String::new();
        file.read_to_string(&mut text).ok()?;
        let mut fields = text.split_whitespace();
        Some(Entry {
            want_mib: fields.next()?.parse().ok()?,
            asked: fields.next()?.parse().ok()?,
            granted: fields.next()? == "granted",
        })
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

/// Open an existing `path` and take a shared lock on it, without creating. The `io::Error` is
/// returned unwrapped so a caller can tell a missing entry from one it could not lock.
fn open_locked_shared(path: &Path) -> std::io::Result<File> {
    let file = File::options().read(true).open(path)?;
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

    /// Read the live ledger the way production does. `scan` reaps entries it finds unlocked,
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
        let used = scan(dir, "nobody", u128::MAX, &mut anomalies).unwrap().0;
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

    /// A reservation held by this test, as another job's would be.
    fn held(dir: &Path, job: &str, want_mib: u64, asked: u128, granted: bool) -> File {
        let file = open_shared(&dir.join(job)).unwrap();
        Entry {
            want_mib,
            asked,
            granted,
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
        let res = acquire(&dir, "mine", 4096, 8192, Duration::from_secs(0)).unwrap();
        assert_eq!(live_mib(&dir), 8192, "both counted");

        // The budget is now full: the next job waits, then gives up.
        let err = acquire(&dir, "third", 4096, 8192, Duration::from_secs(0)).unwrap_err();
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
        let err = acquire(&dir, "huge", 16384, 8192, Duration::from_secs(60)).unwrap_err();
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
        let err = acquire(&dir, "small", 512, 8192, Duration::from_secs(0)).unwrap_err();
        assert!(err.to_string().contains("no room"), "{err}");

        // Once the older waiter is gone, the same job is admitted.
        drop(_big);
        crate::admit::release(&dir, "big");
        drop(_full);
        crate::admit::release(&dir, "running");
        acquire(&dir, "small", 512, 8192, Duration::from_secs(0)).unwrap();
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
        let res = acquire(&dir, "waiter", 8192, 8192, Duration::from_secs(120)).unwrap();
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
                    let res = acquire(&dir, &job, WANT, BUDGET, Duration::from_secs(120))
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
            },
            now,
        );
        assert_eq!(
            history_summary_at(&dir, key("job"), 8192, false, now).unwrap(),
            "virtkit: most this job has used lately: memory 1.6 GiB, read 3.4 GiB, \
             written 812 MiB, sent 3 MiB, received 941 MiB over 3 runs"
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
                network: None,
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
            network: None,
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
                "{now} {} {ceil} {} {} - -\n{now} {} {ceil} - - - -\n",
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
                // has no maximum at all, which is what keeps it off the trace line.
                most_disk: Some((10 * MIB, 20 * MIB)),
                most_network: None,
                runs: 2,
            })
        );
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
        let (torn, lesser) = (4000 * MIB, 700 * MIB);
        std::fs::write(
            dir.join("job"),
            format!(
                "{now} {peak} {ceil} {read} {written} {sent} {received}\n\
                 {now} {torn} {ceil} 30 30 30\n\
                 nonsense\n\
                 {now} {lesser} {ceil} 5 5 5 5\n"
            ),
        )
        .unwrap();
        // The two whole lines, neither the one cut short mid-append nor the unparseable one —
        // so the 4000 MiB peak and the 30 bytes it claims to have read are both left out.
        assert_eq!(
            most_recent_at(&dir, key("job"), ceil, now),
            Some(Recent {
                most: peak,
                most_disk: Some((read, written)),
                most_network: Some((sent, received)),
                runs: 2,
            })
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_supervisor_picks_up_the_reservation_prepare_took() {
        let dir = tmpdir("handoff");
        let prepared = acquire(&dir, "job", 2048, 8192, Duration::from_secs(0)).unwrap();
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
        let prepared = acquire(&dir, "job", 2048, 8192, Duration::from_secs(0)).unwrap();
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
                        acquire(&dir, &job, 512, 8192, Duration::from_secs(0)).unwrap(),
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

        let res = acquire(&dir, "job", 2048, 8192, Duration::from_secs(0)).unwrap();
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
        let err = acquire(&dir, "waiter", 8192, 8192, POLL + POLL / 2).unwrap_err();
        assert!(err.to_string().contains("no room"), "{err}");
        assert!(
            asked_at.elapsed() >= POLL,
            "gave up before the timeout it was given"
        );
        assert!(!dir.join("waiter").exists(), "a refused job leaves nothing");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
