//! Keeping gitlab-runner's appetite in step with the host: works out how many jobs this
//! runner should be accepting and leaves that number where `vk-runnerctl` can apply it.
//!
//! The admission gate ([`crate::admit`]) is what keeps the host safe — it never lets more
//! memory be committed than the budget allows. But a job it makes wait has already been
//! assigned by GitLab: it holds one of the runner's slots and its own timeout runs while it
//! queues. The fix is to stop the work arriving, which means the runner's `concurrent`, and
//! that lives in a file only root can write. So this side only measures and writes a number;
//! the privileged side clamps it into a range an administrator set and edits the config.
//!
//! Being wrong here is cheap by construction: this decides how many jobs the runner
//! *accepts*, never how much memory is committed. Too high and the gate makes the extra
//! jobs queue as before; too low and the host idles until the next run. That is what makes
//! a crude control law the right one.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::config::Config;

/// The share of `MemTotal` kept outside new work. Guest RAM is only part of what a runner's
/// box holds — the VMMs themselves, a tmpfs-backed checkout, whatever else the machine runs —
/// so the ledger looking roomy is not on its own a reason to take more work.
const RESERVE_PCT: u64 = 15;

/// Where `vk` leaves the concurrency it would like, for the root-side setter to pick up.
/// Named in `vk-runnerctl`'s own config too — the two have to agree, and the guide gives
/// the pair.
pub fn desired_file(cfg: &Config) -> PathBuf {
    cfg.state_dir().join("schedule").join("desired-concurrency")
}

/// Measure the host and write what the runner's concurrency should be. Meant to run every
/// half minute or so from a user timer; each run stands alone, reading its own previous
/// answer back out of the file it writes.
pub fn tune(cfg: &Config) -> Result<()> {
    let Some(budget) = cfg.schedule.mem_budget.as_deref() else {
        bail!(
            "[schedule] mem_budget is unset: there is no budget to schedule against \
             (see the GitLab CI guide)"
        );
    };
    let budget_mib = crate::vm::parse_gib(budget)
        .context("invalid [schedule] mem_budget")?
        .checked_mul(1024)
        .context("[schedule] mem_budget is absurdly large")?;
    // Propagated, not defaulted: a reading of "nothing committed" would offer the whole
    // budget again, which is the one answer that overcommits the host.
    let held = crate::admit::committed(&cfg.state_dir().join("admit"))?;
    let declared_mib = crate::vm::parse_gib(&cfg.vm.mem)
        .context("invalid [vm] mem")?
        .checked_mul(1024)
        .context("[vm] mem is absurdly large")?;
    let typical = typical_job_mib(cfg, declared_mib);

    let path = desired_file(cfg);
    let previous = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| t.trim().parse::<u32>().ok());
    // Read once: the figures the decision rests on are the ones reported below it.
    let host = host_memory();
    let want = concurrency(Inputs {
        budget_mib,
        granted_mib: held.granted_mib,
        running: held.granted as u64,
        typical_mib: typical,
        host,
        previous,
    });

    if let Some(parent) = path.parent() {
        // 0700 like the ledger's, and for the same reason: a root process reads what is left
        // here, so no other local user may plant or rewrite it.
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting {} to 0700", parent.display()))?;
    }
    // Written whole and renamed: the reader runs as root on its own schedule and must never
    // catch half a number. Created exclusively, as the root side creates its own temporaries —
    // whatever a killed run left is cleared first, and `create_new` then refuses to follow a
    // symlink put at this predictable name in its place — and named per process, so two
    // overlapping runs cannot each unlink the other's staged file and rename an inode the
    // other has not finished writing.
    let tmp = path.with_extension(format!("new.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut file = std::fs::File::options()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    file.write_all(format!("{want}\n").as_bytes())
        .with_context(|| format!("writing {}", tmp.display()))?;
    drop(file);
    std::fs::rename(&tmp, &path).with_context(|| format!("installing {}", path.display()))?;
    println!(
        "virtkit: runner concurrency {want} ({} of {budget_mib} MiB committed by {} job(s), \
         typical job {typical} MiB, {})",
        held.granted_mib,
        held.granted,
        match host {
            Some(h) => format!(
                "{} of {} MiB host memory available",
                h.available_mib, h.total_mib
            ),
            None => "host memory unreadable".to_string(),
        },
    );
    Ok(())
}

/// What this host's `/proc/meminfo` says, in MiB.
#[derive(Clone, Copy)]
pub struct HostMemory {
    pub available_mib: u64,
    pub total_mib: u64,
}

/// Everything the decision rests on, so the rule itself can be read — and tested — without
/// a host to measure.
pub struct Inputs {
    pub budget_mib: u64,
    pub granted_mib: u64,
    pub running: u64,
    pub typical_mib: u64,
    /// `None` when `/proc/meminfo` cannot be read: the host brake is then off and the ledger
    /// is the only gate, which is what it was before this brake existed.
    pub host: Option<HostMemory>,
    pub previous: Option<u32>,
}

/// How many jobs the runner should be accepting: the ones already running, plus as many
/// more of a typical size as the budget and the host still have room for.
///
/// The movement is deliberately lopsided. Falling is immediate — the host is under pressure
/// now, and a slot not taken costs nothing. Rising is one step per run, because every job
/// that starts takes a while to reach its real size, and a controller that believed an empty
/// ledger would let a whole pipeline in at once.
pub fn concurrency(i: Inputs) -> u32 {
    let budget_headroom = i.budget_mib.saturating_sub(i.granted_mib);
    // `MemAvailable` discounts what the host cannot hand out — a tmpfs-backed checkout or
    // build tree, a co-located service — none of which the guest ledger sees. Keep RESERVE_PCT
    // of the physical host outside new work, then let whichever headroom is smaller, ledger or
    // host, decide how many more typical jobs fit. That charges a large checkout its real
    // allocated size instead of a guessed per-repository reserve. Reclaimable page cache is not
    // charged at all, since `MemAvailable` already counts it as available.
    let headroom = match i.host {
        Some(h) => {
            let reserve = h.total_mib.saturating_mul(RESERVE_PCT) / 100;
            budget_headroom.min(h.available_mib.saturating_sub(reserve))
        }
        None => budget_headroom,
    };
    let want = i.running + headroom / i.typical_mib.max(1);
    // Never below one, even then: `concurrent = 0` is not a throttle gitlab-runner has, and a
    // runner that stops taking work entirely never recovers on its own. An idle host under
    // memory pressure therefore still offers the one slot.
    let want = want.clamp(1, u32::MAX as u64) as u32;
    match i.previous {
        Some(prev) if want > prev => prev + 1,
        _ => want,
    }
}

/// What a job on this host typically reserves. With `from_history` on, the median of what
/// each kind of job would be admitted against today — each read against the ceiling it last
/// ran under, since jobs do not share one — so the count and the gate agree on what a job
/// costs. Otherwise every job reserves what it declares, and the default declared size is
/// the answer.
fn typical_job_mib(cfg: &Config, declared_mib: u64) -> u64 {
    if !cfg.schedule.from_history {
        return declared_mib;
    }
    let mut seen = crate::admit::all_expected(&cfg.state_dir().join("history"));
    if seen.is_empty() {
        return declared_mib;
    }
    seen.sort_unstable();
    seen[seen.len() / 2]
}

/// This host's memory, from `/proc/meminfo`. `None` — a host whose memory cannot be read — is
/// treated as roomy: the ledger is the real guard, and this is only the brake for what the
/// ledger cannot see.
fn host_memory() -> Option<HostMemory> {
    let (available_kib, total_kib) = meminfo(Path::new("/proc/meminfo"))?;
    Some(HostMemory {
        available_mib: available_kib / 1024,
        total_mib: total_kib / 1024,
    })
}

/// `(MemAvailable, MemTotal)` in kB.
fn meminfo(path: &Path) -> Option<(u64, u64)> {
    let text = std::fs::read_to_string(path).ok()?;
    let field = |name: &str| {
        text.lines().find_map(|l| {
            l.strip_prefix(name)?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        })
    };
    Some((field("MemAvailable:")?, field("MemTotal:")?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> Inputs {
        Inputs {
            budget_mib: 32768,
            granted_mib: 0,
            running: 0,
            typical_mib: 4096,
            host: Some(HostMemory {
                available_mib: 65536,
                total_mib: 65536,
            }),
            previous: None,
        }
    }

    /// An `available_mib` on a 64 GiB host, for a case whose subject is host pressure.
    fn available(mib: u64) -> Option<HostMemory> {
        Some(HostMemory {
            available_mib: mib,
            total_mib: 65536,
        })
    }

    /// The file this writes is read by a *root* process, which accepts a regular file of at
    /// most 16 bytes parsing as a `u32` and nothing else. Both halves of that contract are
    /// checked here, since the two live in different binaries and nothing else ties them
    /// together — and the file must be no more readable than the ledger beside it.
    #[test]
    fn the_request_is_what_the_privileged_reader_accepts() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("vk-tune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = Config {
            state_dir: Some(dir.clone()),
            schedule: crate::config::Schedule {
                mem_budget: Some("32G".into()),
                ..Default::default()
            },
            ..Config::default()
        };

        tune(&cfg).unwrap();
        let path = desired_file(&cfg);
        let meta = std::fs::metadata(&path).unwrap();
        assert!(meta.is_file(), "a fifo or a directory is not a request");
        assert!(meta.len() <= 16, "the reader takes 16 bytes at most");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        // Parsed the way the reader parses it, and at least one slot is always offered.
        let text = std::fs::read_to_string(&path).unwrap();
        let n: u32 = text.trim().parse().expect("a plain number, as written");
        assert!(
            n >= 1,
            "a runner accepting nothing would never pick up again"
        );

        // A second run reads its own answer back rather than starting over, and leaves no
        // staging file behind.
        tune(&cfg).unwrap();
        let again: u32 = std::fs::read_to_string(&path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(again >= 1);
        let left: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, ["desired-concurrency"].map(std::ffi::OsString::from));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_idle_host_offers_a_slot_per_typical_job() {
        // 32 GiB of budget, 4 GiB a job: eight.
        assert_eq!(concurrency(inputs()), 8);
        // Half committed by two jobs: those two, plus what is left over.
        assert_eq!(
            concurrency(Inputs {
                granted_mib: 16384,
                running: 2,
                ..inputs()
            }),
            6
        );
        // Full: the runner should take nothing new, but never drops below one — a runner at
        // zero would stop asking GitLab for work at all.
        assert_eq!(
            concurrency(Inputs {
                granted_mib: 32768,
                running: 8,
                ..inputs()
            }),
            8
        );
        assert_eq!(
            concurrency(Inputs {
                granted_mib: 32768,
                running: 0,
                ..inputs()
            }),
            1
        );
    }

    #[test]
    fn it_falls_at_once_and_climbs_a_step_at_a_time() {
        // Room for eight, but it was at two: one more this run.
        assert_eq!(
            concurrency(Inputs {
                previous: Some(2),
                ..inputs()
            }),
            3
        );
        // Room for two while it was at eight: straight down, no easing.
        assert_eq!(
            concurrency(Inputs {
                granted_mib: 24576,
                running: 6,
                previous: Some(8),
                ..inputs()
            }),
            8
        );
        assert_eq!(
            concurrency(Inputs {
                granted_mib: 28672,
                running: 1,
                previous: Some(8),
                ..inputs()
            }),
            2
        );
    }

    #[test]
    fn a_host_short_of_memory_takes_no_new_work() {
        // The ledger says there is room; the host has less available than the 15% it keeps in
        // reserve. The host wins, and the jobs already running are left alone.
        let tight = Inputs {
            host: available(2621),
            running: 3,
            // It was offering eight; a host-driven fall is immediate, not one step at a time.
            previous: Some(8),
            ..inputs()
        };
        assert_eq!(concurrency(tight), 3);
        // Even with nothing running it keeps the floor of one rather than stalling the runner.
        assert_eq!(
            concurrency(Inputs {
                host: available(2621),
                running: 0,
                ..inputs()
            }),
            1
        );
    }

    #[test]
    fn host_memory_in_use_lowers_the_slots_before_the_reserve_is_gone() {
        // The ledger has room for eight 4 GiB jobs. With only 24 GiB available on a 64 GiB
        // host, keeping 15% (9.6 GiB) of it free leaves 14.4 GiB, so three more jobs fit. What
        // holds the missing memory does not matter — a tmpfs checkout or a co-located service
        // both leave `MemAvailable` this low.
        assert_eq!(
            concurrency(Inputs {
                host: available(24576),
                ..inputs()
            }),
            3
        );
    }

    #[test]
    fn an_unreadable_meminfo_leaves_the_ledger_as_the_only_gate() {
        // The brake needs a measurement to apply. Without one the answer is the budget's alone,
        // which is what it was before the host was consulted at all.
        assert_eq!(
            concurrency(Inputs {
                host: None,
                ..inputs()
            }),
            8
        );
        // And a host it cannot measure never blocks work the ledger has room for.
        assert_eq!(
            concurrency(Inputs {
                host: None,
                granted_mib: 16384,
                running: 4,
                previous: Some(8),
                ..inputs()
            }),
            8
        );
    }

    #[test]
    fn a_typical_job_larger_than_the_budget_still_yields_a_runner() {
        assert_eq!(
            concurrency(Inputs {
                typical_mib: 65536,
                ..inputs()
            }),
            1
        );
        // And a nonsense typical size cannot divide by zero.
        assert!(
            concurrency(Inputs {
                typical_mib: 0,
                ..inputs()
            }) > 0
        );
    }

    /// What a typical job reserves: the middle of what each remembered job would be admitted
    /// against, not the mean and not the largest.
    #[test]
    fn the_typical_job_is_the_median_of_the_histories() {
        let dir = std::env::temp_dir().join(format!("vk-schedule-typical-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let history = dir.join("history");
        std::fs::create_dir_all(&history).unwrap();

        let cfg = Config {
            state_dir: Some(dir.clone()),
            schedule: crate::config::Schedule {
                from_history: true,
                ..Default::default()
            },
            ..Default::default()
        };

        // Off, or with nothing remembered, the declared size is the answer.
        assert_eq!(typical_job_mib(&Config::default(), 2048), 2048);
        assert_eq!(typical_job_mib(&cfg, 2048), 2048);

        // Three jobs of very different appetites, keyed `<project>/<job>` as a real one is —
        // two of them under the same project, so the walk has to descend rather than read the
        // project directories themselves. The middle job is the answer, so one heavy outlier
        // cannot drag the host's whole count down.
        let key = |project: &str, job: &str| Path::new(project).join(job);
        for (project, job, peak) in [
            ("proj-a", "small", 200),
            ("proj-a", "middling", 1000),
            ("proj-b", "heavy", 6000),
        ] {
            crate::admit::remember(
                &history,
                &key(project, job),
                crate::admit::Run {
                    peak: peak * 1024 * 1024,
                    ceiling: 8192 * 1024 * 1024,
                    ..Default::default()
                },
            );
        }
        let typical = typical_job_mib(&cfg, 8192);
        let middling = crate::admit::expect_last_mib(&history, &key("proj-a", "middling")).unwrap();
        assert_eq!(typical, middling, "the median history, not the mean");

        // The directory's own lock file is not a project, and a stray file at either level is
        // not a job: all are passed over rather than counted as a history of nothing.
        std::fs::write(history.join("not-a-project"), "gibberish\n").unwrap();
        std::fs::write(history.join("proj-a").join("not-a-history"), "gibberish\n").unwrap();
        assert_eq!(typical_job_mib(&cfg, 8192), typical);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reads_the_two_meminfo_fields_it_needs() {
        let dir = std::env::temp_dir().join(format!("vk-meminfo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("meminfo");
        std::fs::write(
            &path,
            "MemTotal:       65790616 kB\nMemFree:  123 kB\nMemAvailable:   32895308 kB\n",
        )
        .unwrap();
        assert_eq!(meminfo(&path), Some((32895308, 65790616)));
        assert_eq!(meminfo(Path::new("/nonexistent")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
