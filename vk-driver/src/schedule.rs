//! Keeping gitlab-runner's appetite in step with the host: works out how many jobs this
//! runner should be accepting and leaves that number where `vk-runnerctl` can apply it, or
//! sets it in a runner config this user owns.
//!
//! This is the one place the number is decided: `effective = min(estimate, hub ceiling,
//! ceiling)` ([`decide`]), whether `vk tune` asks or `vk node run`'s own loop does, holding
//! it to its previous answer between periods — and while `vk node run` is up, only its loop
//! asks ([`tune`]).
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
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
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

/// The runner's concurrency and what it was worked out from:
/// `effective = min(estimate, hub ceiling, ceiling)`, each term optional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Decision {
    /// What the host can take, by [`concurrency`]; `None` without a memory budget to measure
    /// against.
    pub estimate: Option<u32>,
    /// The cap a fleet hub set, as the node last persisted it; `None` off a fleet.
    pub hub_ceiling: Option<u32>,
    /// `[executor.schedule] max_concurrency`.
    pub ceiling: Option<u32>,
    /// The smallest term, never below one, and held to the previous answer when it may not
    /// rise; `None` when no term applies, which leaves the runner's `concurrent` alone.
    pub effective: Option<u32>,
    /// The figures the estimate rests on, for the report line.
    basis: Option<Basis>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Basis {
    budget_mib: u64,
    granted_mib: u64,
    running: usize,
    typical_mib: u64,
    host: Option<(u64, u64)>,
}

/// The smallest of the terms that apply, never below one: `concurrent = 0` is not a throttle
/// gitlab-runner has, and a runner that accepts nothing never picks up again. The config
/// refuses a zero ceiling already, and a hub's ceiling of zero means one: stopping acquisition
/// is a state of its own, not a number.
pub(crate) fn effective(
    estimate: Option<u32>,
    hub_ceiling: Option<u32>,
    ceiling: Option<u32>,
) -> Option<u32> {
    [estimate, hub_ceiling, ceiling]
        .into_iter()
        .flatten()
        .min()
        .map(|n| n.max(1))
}

/// Decide concurrency from the host, ledger, `hub_ceiling` and local ceiling. The estimate
/// rises from the previous *effective* answer, one step at a time when a ceiling is lifted.
pub(crate) fn decide(cfg: &Config, hub_ceiling: Option<u32>) -> Result<Decision> {
    decide_with(cfg, hub_ceiling, true)
}

/// Like [`decide`], but let the effective answer rise above the previous one only when
/// `may_rise`. Pass false for changes between periods, so concurrency can fall at once but
/// rises at most once per period, whichever term lifted.
pub(crate) fn decide_with(
    cfg: &Config,
    hub_ceiling: Option<u32>,
    may_rise: bool,
) -> Result<Decision> {
    let ceiling = cfg
        .executor
        .schedule
        .max_concurrency
        .map(std::num::NonZeroU32::get);
    let previous = std::fs::read_to_string(desired_file(cfg))
        .ok()
        .and_then(|t| t.trim().parse::<u32>().ok());
    let (estimate, basis) = match crate::vm::budget_mib(cfg) {
        None => (None, None),
        Some(budget) => {
            let budget_mib = budget?;
            // Propagated, not defaulted: a reading of "nothing committed" would offer the whole
            // budget again, which is the one answer that overcommits the host.
            let held = crate::admit::committed(&cfg.state_dir().join("admit"))?;
            let declared_mib = crate::vm::parse_gib(&cfg.executor.vm.mem)
                .context("invalid [executor.vm] mem")?
                .checked_mul(1024)
                .context("[executor.vm] mem is absurdly large")?;
            let typical = typical_job_mib(cfg, declared_mib);
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
            let basis = Basis {
                budget_mib,
                granted_mib: held.granted_mib,
                running: held.granted,
                typical_mib: typical,
                host: host.map(|h| (h.available_mib, h.total_mib)),
            };
            (Some(want), Some(basis))
        }
    };
    Ok(Decision {
        estimate,
        hub_ceiling,
        ceiling,
        effective: effective(estimate, hub_ceiling, ceiling)
            .map(|want| held_below(want, previous, may_rise).max(1)),
        basis,
    })
}

/// `want`, or no more than `previous` unless it `may_rise`.
fn held_below(want: u32, previous: Option<u32>, may_rise: bool) -> u32 {
    match previous {
        Some(prev) if !may_rise => want.min(prev),
        _ => want,
    }
}

/// Write `decision` to the desired-concurrency file: it records this host's request and
/// feeds `vk-runnerctl` for a root-managed runner. Also set `concurrent` directly when
/// [`runner_config`] names a config this user owns.
pub(crate) fn apply(cfg: &Config, decision: &Decision) -> Result<()> {
    let Some(want) = decision.effective else {
        return Ok(());
    };
    write_desired(cfg, want)?;
    if let Some(path) = runner_config(cfg) {
        set_runner_concurrent(&path, want)?;
    }
    Ok(())
}

/// The gitlab-runner config this user owns and `vk` edits directly, if any: `[node]
/// runner_config`, which a managed runner defaults to `~/.gitlab-runner/config.toml`.
/// Otherwise the runner is root's, reached through `vk-runnerctl`.
pub fn runner_config(cfg: &Config) -> Option<PathBuf> {
    runner_config_in(cfg, std::env::var_os("HOME").as_deref())
}

/// [`runner_config`], with `home` for `$HOME`.
pub fn runner_config_in(cfg: &Config, home: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    match (&cfg.node.runner_config, cfg.node.runner) {
        (Some(path), _) => Some(path.clone()),
        (None, vk_hub_proto::RunnerMode::Managed) => home
            .filter(|h| !h.is_empty())
            .map(|h| Path::new(h).join(".gitlab-runner/config.toml")),
        (None, vk_hub_proto::RunnerMode::External) => None,
    }
}

/// Measure the host and write what the runner's concurrency should be. Meant to run every
/// half minute or so from a user timer; each run stands alone, reading its own previous
/// answer back out of the file it writes.
///
/// On a fleet node the node's own loop is the one writer: while `vk node run` holds the
/// state dir this does nothing, rather than step the concurrency up twice as fast. Otherwise
/// it applies the hub ceiling the node last persisted, so both give the same answer.
pub fn tune(cfg: &Config) -> Result<()> {
    // Held until this pass is done, so no `vk node run` starts writing in the middle of it.
    let Some(_claim) = crate::node::claim_tuning(cfg)? else {
        println!("virtkit: `vk node run` sets this runner's concurrency; nothing to do");
        return Ok(());
    };
    let decision = decide(cfg, crate::node::hub_ceiling(cfg)?)?;
    if decision.effective.is_none() {
        bail!(
            "neither [executor.schedule] mem_budget nor max_concurrency is set: nothing to \
             schedule against (see the GitLab CI guide)"
        );
    }
    apply(cfg, &decision)?;
    println!("virtkit: {}", describe(&decision));
    Ok(())
}

/// One line saying what the concurrency is and which term set it.
pub(crate) fn describe(d: &Decision) -> String {
    let Some(want) = d.effective else {
        return "runner concurrency left alone: no budget and no ceiling".to_string();
    };
    let term = |n: Option<u32>| n.map_or_else(|| "none".to_string(), |n| n.to_string());
    // The hub's term only on a node that has one.
    let hub = d
        .hub_ceiling
        .map_or_else(String::new, |n| format!(", hub ceiling {n}"));
    let mut line = format!(
        "runner concurrency {want} (estimate {}{hub}, ceiling {})",
        term(d.estimate),
        term(d.ceiling)
    );
    if let Some(b) = &d.basis {
        line.push_str(&format!(
            "; {} of {} MiB committed by {} job(s), typical job {} MiB, {}",
            b.granted_mib,
            b.budget_mib,
            b.running,
            b.typical_mib,
            match b.host {
                Some((available, total)) =>
                    format!("{available} of {total} MiB host memory available"),
                None => "host memory unreadable".to_string(),
            },
        ));
    }
    line
}

fn write_desired(cfg: &Config, want: u32) -> Result<()> {
    let path = desired_file(cfg);
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
    std::fs::rename(&tmp, &path).with_context(|| format!("installing {}", path.display()))
}

/// Set `concurrent` in the gitlab-runner config at `path`, which this user must own, with
/// `vk-runnerctl`'s editor: the one line rewritten, and the result proven to differ from the
/// original at that key alone before it replaces it. gitlab-runner notices the change itself.
/// Returns whether the file changed: a file that already says `value` is not rewritten, and
/// one another edit holds locked is left to it.
///
/// gitlab-runner saves this file itself too — rewriting it in place, `os.WriteFile`, when it
/// rotates a runner's token — so the file is read again just before the edit replaces it:
/// the same inode and contents it was read with, or the edit starts over from what is there
/// now. An empty file is taken for one caught between that rewrite's truncate and its write.
/// Every step works relative to the directory, opened once, so the name checked is the name
/// replaced. What remains is the instant between that check and the rename.
pub fn set_runner_concurrent(path: &Path, value: u32) -> Result<bool> {
    set_runner_concurrent_checked(path, value, || {})
}

/// How many times an edit starts over on a config that changed under it.
const EDIT_ATTEMPTS: u32 = 5;

/// Like [`set_runner_concurrent`], with a `before_publish` callback between staging and
/// rechecking the file so tests can simulate a concurrent write.
fn set_runner_concurrent_checked(
    path: &Path,
    value: u32,
    mut before_publish: impl FnMut(),
) -> Result<bool> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    let name = path
        .file_name()
        .with_context(|| format!("{} names no file", path.display()))?;
    let c_name = CString::new(name.as_bytes()).context("a runner config path with a NUL")?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = vk_fs::open_dir(parent.unwrap_or(Path::new(".")))?;
    let mut staged_name = b".".to_vec();
    staged_name.extend_from_slice(name.as_bytes());
    staged_name.extend_from_slice(format!(".vk-{}", std::process::id()).as_bytes());
    let staged = CString::new(staged_name).context("a runner config name with a NUL")?;
    // SAFETY (both helpers): the directory descriptor is live, the names are NUL-terminated
    // and outlive each call, and a descriptor a call returns is handed straight to `OwnedFd`.
    let open_at = |cname: &CString, flags: libc::c_int, mode: libc::c_uint| {
        let fd = unsafe { libc::openat(dir.as_raw_fd(), cname.as_ptr(), flags, mode) };
        if fd < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
        }
    };
    let unlink_staged = || unsafe { libc::unlinkat(dir.as_raw_fd(), staged.as_ptr(), 0) };
    // Non-blocking, so a FIFO in the config's place is opened and refused rather than waited
    // on; reading an ordinary file is unaffected.
    let read_flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    let read_config = || -> Result<(std::fs::File, std::fs::Metadata, String)> {
        let mut file = open_at(&c_name, read_flags, 0)
            .with_context(|| format!("opening {}", path.display()))?;
        let meta = file
            .metadata()
            .with_context(|| format!("statting {}", path.display()))?;
        if !meta.is_file() {
            bail!(
                "{} is not an ordinary file — refusing to replace it",
                path.display()
            );
        }
        let mut text = String::new();
        std::io::Read::read_to_string(&mut file, &mut text)
            .with_context(|| format!("reading {}", path.display()))?;
        Ok((file, meta, text))
    };

    // An attempt that starts over on the same file keeps the lock it took. Retaken through a
    // new descriptor, it could find itself still held: a fork elsewhere in this process
    // copies the old descriptor into its child, which holds it until it execs.
    let mut locked: Option<(std::fs::File, u64, u64)> = None;
    for _ in 0..EDIT_ATTEMPTS {
        let (file, meta, text) = read_config()?;
        // SAFETY: geteuid takes no arguments and cannot fail.
        let uid = unsafe { libc::geteuid() };
        if meta.uid() != uid {
            bail!(
                "{} belongs to uid {}, not this user: a runner config vk does not own is set \
                 through vk-runnerctl",
                path.display(),
                meta.uid()
            );
        }
        // One edit at a time: two that both pass the recheck would each rename over the
        // other, the last undoing the first. The edit holding the lock is the current one.
        let held =
            matches!(&locked, Some((_, dev, ino)) if (*dev, *ino) == (meta.dev(), meta.ino()));
        if !held {
            // SAFETY: the fd is owned by `file`, which outlives the call; flock returns 0 or -1.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::EWOULDBLOCK) {
                    return Err(e).with_context(|| format!("locking {}", path.display()));
                }
                return Ok(false);
            }
            locked = Some((file, meta.dev(), meta.ino()));
        }
        if text.is_empty() {
            // Most likely mid-rewrite: give the writer a moment to finish.
            std::thread::sleep(std::time::Duration::from_millis(20));
            continue;
        }
        if vk_runnerctl::edit::current_concurrent(&text) == Some(value) {
            return Ok(false);
        }
        let edited = vk_runnerctl::edit::set_concurrent(&text, value)
            .with_context(|| format!("editing {}", path.display()))?;
        vk_runnerctl::edit::verify(&text, &edited, value)
            .with_context(|| format!("editing {}", path.display()))?;

        // Per-process, so a leftover from a killed run can never be a live run's file, and
        // this process's own leftover is cleared first. Created private and exclusively, then
        // given the config's mode and group through the descriptor, before anyone can open it
        // by name.
        unlink_staged();
        let mut out = open_at(
            &staged,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
        .with_context(|| format!("staging the edit of {}", path.display()))?;
        let written = out
            .write_all(edited.as_bytes())
            // Permission bits only: a config has no business carrying setuid, setgid or sticky.
            .and_then(|()| {
                out.set_permissions(std::fs::Permissions::from_mode(meta.mode() & 0o777))
            })
            .and_then(|()| out.sync_all());
        if let Err(e) = written {
            unlink_staged();
            return Err(e).with_context(|| format!("staging the edit of {}", path.display()));
        }
        // A new file takes this process's group, not the config's.
        // SAFETY: the fd is owned by `out`, which outlives the call; fchown returns 0 or -1.
        if unsafe { libc::fchown(out.as_raw_fd(), libc::uid_t::MAX, meta.gid()) } != 0 {
            let e = std::io::Error::last_os_error();
            unlink_staged();
            return Err(e).with_context(|| format!("restoring the group of {}", path.display()));
        }
        drop(out);

        before_publish();
        let unchanged = match read_config() {
            Ok((_, now, now_text)) => {
                now.dev() == meta.dev() && now.ino() == meta.ino() && now_text == text
            }
            Err(e) => {
                unlink_staged();
                return Err(e);
            }
        };
        if !unchanged {
            unlink_staged();
            continue;
        }
        // SAFETY: as above.
        let rc = unsafe {
            libc::renameat(
                dir.as_raw_fd(),
                staged.as_ptr(),
                dir.as_raw_fd(),
                c_name.as_ptr(),
            )
        };
        if rc != 0 {
            let e = std::io::Error::last_os_error();
            unlink_staged();
            return Err(e).with_context(|| format!("installing {}", path.display()));
        }
        return Ok(true);
    }
    bail!(
        "{} stayed empty or kept changing while its `concurrent` was being set; left for the \
         next pass",
        path.display()
    )
}

/// What this host's `/proc/meminfo` says, in MiB.
#[derive(Clone, Copy)]
pub struct HostMemory {
    pub available_mib: u64,
    pub total_mib: u64,
    /// tmpfs and other shared pages. They sit on the file LRU, so `MemAvailable` counts them
    /// as reclaimable although they can only leave for swap — a reader that must not
    /// over-count what the host can hand out subtracts them again (see
    /// `crate::build::foreign_used_mib`). `0` on a kernel that does not report it.
    pub shmem_mib: u64,
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
    if !cfg.executor.schedule.from_history {
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
pub(crate) fn host_memory() -> Option<HostMemory> {
    let (available_kib, total_kib, shmem_kib) = meminfo(Path::new("/proc/meminfo"))?;
    Some(HostMemory {
        available_mib: available_kib / 1024,
        total_mib: total_kib / 1024,
        shmem_mib: shmem_kib / 1024,
    })
}

/// This host's `MemTotal` in MiB — what a percentage `[executor.schedule] mem_budget` is a share of,
/// and what a build fits its stages' declared sizes into to pick an auto `[build] jobs`
/// (`build::resolve_build_jobs`), and measures against to admit them. `None` on a host whose
/// memory cannot be read, which each caller answers its own way: the budget is a share that
/// cannot be resolved, the build falls back to a modest assumed size.
pub(crate) fn host_total_mib() -> Option<u64> {
    total_mib(Path::new("/proc/meminfo"))
}

/// `MemTotal` in MiB, on its own: a caller that wants only the size of the host must not be
/// denied it by a `/proc/meminfo` that happens to omit `MemAvailable`.
fn total_mib(path: &Path) -> Option<u64> {
    Some(meminfo_field(&std::fs::read_to_string(path).ok()?, "MemTotal:")? / 1024)
}

/// `(MemAvailable, MemTotal, Shmem)` in kB. The first two are required — a `/proc/meminfo`
/// without them is not one this can read — while `Shmem` reads as 0 when absent, which is
/// what a kernel that does not report it effectively means.
fn meminfo(path: &Path) -> Option<(u64, u64, u64)> {
    let text = std::fs::read_to_string(path).ok()?;
    Some((
        meminfo_field(&text, "MemAvailable:")?,
        meminfo_field(&text, "MemTotal:")?,
        meminfo_field(&text, "Shmem:").unwrap_or(0),
    ))
}

/// One `/proc/meminfo` field in kB, by its `Name:` prefix. `None` when it is absent or
/// unparsable.
fn meminfo_field(text: &str, name: &str) -> Option<u64> {
    text.lines().find_map(|l| {
        l.strip_prefix(name)?
            .split_whitespace()
            .next()?
            .parse::<u64>()
            .ok()
    })
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
                shmem_mib: 0,
            }),
            previous: None,
        }
    }

    /// An `available_mib` on a 64 GiB host, for a case whose subject is host pressure.
    fn available(mib: u64) -> Option<HostMemory> {
        Some(HostMemory {
            available_mib: mib,
            total_mib: 65536,
            shmem_mib: 0,
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
            executor: crate::config::Executor {
                schedule: crate::config::Schedule {
                    mem_budget: Some("32G".into()),
                    ..Default::default()
                },
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
    fn the_smallest_term_binds_and_one_is_the_floor() {
        // Each term binds when it is the smallest.
        assert_eq!(effective(Some(3), Some(8), Some(6)), Some(3));
        assert_eq!(effective(Some(9), Some(4), Some(6)), Some(4));
        assert_eq!(effective(Some(9), Some(8), Some(2)), Some(2));
        // Absent terms do not bind; a ceiling applies without a budget to estimate from.
        assert_eq!(effective(None, Some(5), None), Some(5));
        assert_eq!(effective(None, None, Some(5)), Some(5));
        assert_eq!(effective(Some(7), None, None), Some(7));
        assert_eq!(effective(None, None, None), None);
        // Zero is not a throttle gitlab-runner has.
        assert_eq!(effective(Some(4), None, Some(0)), Some(1));
        assert_eq!(effective(None, None, Some(0)), Some(1));
        assert_eq!(effective(Some(4), Some(0), None), Some(1));
    }

    fn scratch_cfg(tag: &str, schedule: crate::config::Schedule) -> (Config, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("vk-tune-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = Config {
            state_dir: Some(dir.clone()),
            executor: crate::config::Executor {
                schedule,
                ..Default::default()
            },
            ..Config::default()
        };
        (cfg, dir)
    }

    #[test]
    fn a_decision_combines_the_estimate_with_the_ceiling() {
        let (cfg, dir) = scratch_cfg(
            "decide",
            crate::config::Schedule {
                mem_budget: Some("32G".into()),
                max_concurrency: std::num::NonZeroU32::new(3),
                ..Default::default()
            },
        );
        // The estimate is this host's own reading, so only its relation to the rest is fixed.
        let d = decide(&cfg, Some(2)).unwrap();
        assert_eq!((d.hub_ceiling, d.ceiling), (Some(2), Some(3)));
        assert!(d.estimate.is_some());
        assert_eq!(d.effective, effective(d.estimate, Some(2), Some(3)));
        assert!(d.effective <= Some(2));
        assert!(
            describe(&d).contains("hub ceiling 2, ceiling 3"),
            "{}",
            describe(&d)
        );
        let d = decide(&cfg, None).unwrap();
        assert_eq!(d.effective, Some(d.estimate.unwrap().min(3)));
        assert!(describe(&d).contains("ceiling 3"), "{}", describe(&d));
        assert!(!describe(&d).contains("hub"), "{}", describe(&d));
        // No budget: the ceiling alone decides, and the report has no figures to give.
        let (cfg, dir2) = scratch_cfg(
            "decide-nobudget",
            crate::config::Schedule {
                max_concurrency: std::num::NonZeroU32::new(5),
                ..Default::default()
            },
        );
        let d = decide(&cfg, None).unwrap();
        assert_eq!((d.estimate, d.effective), (None, Some(5)));
        assert_eq!(
            describe(&d),
            "runner concurrency 5 (estimate none, ceiling 5)"
        );
        apply(&cfg, &d).unwrap();
        assert_eq!(std::fs::read_to_string(desired_file(&cfg)).unwrap(), "5\n");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    /// Between periods a lifted hub ceiling is held to the previous answer even with no
    /// estimate to step it, and a lowered one applies at once.
    #[test]
    fn a_lifted_hub_ceiling_waits_for_the_period() {
        let (cfg, dir) = scratch_cfg(
            "decide-hold",
            crate::config::Schedule {
                max_concurrency: std::num::NonZeroU32::new(8),
                ..Default::default()
            },
        );
        apply(&cfg, &decide_with(&cfg, Some(2), true).unwrap()).unwrap();
        let d = decide_with(&cfg, Some(6), false).unwrap();
        assert_eq!((d.hub_ceiling, d.effective), (Some(6), Some(2)));
        assert_eq!(
            decide_with(&cfg, Some(1), false).unwrap().effective,
            Some(1)
        );
        assert_eq!(decide_with(&cfg, Some(6), true).unwrap().effective, Some(6));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tune_refuses_with_nothing_to_schedule_against() {
        let (cfg, dir) = scratch_cfg("tune-nothing", crate::config::Schedule::default());
        let d = decide(&cfg, None).unwrap();
        assert_eq!(d.effective, None);
        assert_eq!(
            describe(&d),
            "runner concurrency left alone: no budget and no ceiling"
        );
        let err = tune(&cfg).unwrap_err().to_string();
        assert!(
            err.contains("mem_budget") && err.contains("max_concurrency"),
            "{err}"
        );
        assert!(!desired_file(&cfg).exists(), "nothing was written");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_runner_config_this_user_owns_is_edited_in_place() {
        use std::os::unix::fs::PermissionsExt;
        let (mut cfg, dir) = scratch_cfg(
            "edit",
            crate::config::Schedule {
                max_concurrency: std::num::NonZeroU32::new(4),
                ..Default::default()
            },
        );
        let path = dir.join("config.toml");
        let original =
            "# ops\nconcurrent = 9  # keep\n\n[[runners]]\n  name = \"a\"\n  token = \"glrt-x\"\n";
        std::fs::write(&path, original).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        cfg.node.runner_config = Some(path.clone());
        apply(&cfg, &decide(&cfg, None).unwrap()).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, original.replace("concurrent = 9", "concurrent = 4"));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(std::fs::read_to_string(desired_file(&cfg)).unwrap(), "4\n");
        // Nothing to change is not a rewrite.
        assert!(!set_runner_concurrent(&path, 4).unwrap());
        // A link in the config's place is not followed.
        let link = dir.join("link.toml");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(set_runner_concurrent(&link, 5).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// gitlab-runner rewrites its config in place when it saves a rotated token. One that
    /// does so between the edit's read and its rename is not overwritten: the edit starts
    /// again from what is there.
    #[test]
    fn a_config_rewritten_during_the_edit_is_edited_afresh() {
        let dir = std::env::temp_dir().join(format!("vk-tune-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "concurrent = 9\n\n[[runners]]\n  token = \"old\"\n").unwrap();
        let mut rewrites = 0;
        let changed = set_runner_concurrent_checked(&path, 3, || {
            if rewrites == 0 {
                // In place, as `os.WriteFile` does: same inode, new contents.
                std::fs::write(
                    &path,
                    "concurrent = 9\n\n[[runners]]\n  token = \"rotated\"\n",
                )
                .unwrap();
            }
            rewrites += 1;
        })
        .unwrap();
        assert!(changed);
        assert_eq!(rewrites, 2);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "concurrent = 3\n\n[[runners]]\n  token = \"rotated\"\n"
        );
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, ["config.toml"].map(std::ffi::OsString::from));
        // One that never stops changing is left alone, with nothing staged left behind.
        let err = set_runner_concurrent_checked(&path, 5, || {
            std::fs::write(&path, format!("concurrent = 3\n# {}\n", next_suffix())).unwrap();
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("kept changing"), "{err:#}");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        // An empty file is one caught mid-rewrite, never edited. A new file, as the lock the
        // last edit took on this one may live on in a concurrent test's forked child.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "").unwrap();
        let err = set_runner_concurrent(&path, 5).unwrap_err();
        assert!(format!("{err:#}").contains("stayed empty"), "{err:#}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A different number each call, so each rewrite changes the file.
    fn next_suffix() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        N.fetch_add(1, Ordering::Relaxed)
    }

    /// A FIFO or a directory in the config's place is refused, not waited on or replaced.
    #[test]
    fn a_runner_config_that_is_not_an_ordinary_file_is_refused() {
        use std::os::unix::ffi::OsStrExt;
        let dir = std::env::temp_dir().join(format!("vk-tune-odd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("fifo.toml");
        let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: a NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let sub = dir.join("dir.toml");
        std::fs::create_dir(&sub).unwrap();
        for path in [&fifo, &sub] {
            let err = set_runner_concurrent(path, 3).unwrap_err();
            assert!(
                format!("{err:#}").contains("not an ordinary file"),
                "{err:#}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn between_periods_concurrency_can_fall_but_not_climb() {
        assert_eq!(held_below(5, Some(3), false), 3);
        assert_eq!(held_below(2, Some(3), false), 2);
        assert_eq!(held_below(5, Some(3), true), 5);
        // Nothing written yet: nothing to hold it to.
        assert_eq!(held_below(5, None, false), 5);
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
            executor: crate::config::Executor {
                schedule: crate::config::Schedule {
                    from_history: true,
                    ..Default::default()
                },
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
    fn reads_the_meminfo_fields_each_caller_needs() {
        let dir = std::env::temp_dir().join(format!("vk-meminfo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("meminfo");
        std::fs::write(
            &path,
            "MemTotal:       65790616 kB\nMemFree:  123 kB\nMemAvailable:   32895308 kB\n\
             Shmem:           1048576 kB\n",
        )
        .unwrap();
        assert_eq!(meminfo(&path), Some((32895308, 65790616, 1048576)));
        // A kernel that reports no Shmem reads as none held, not as an unreadable host.
        let no_shmem = dir.join("meminfo-no-shmem");
        std::fs::write(&no_shmem, "MemTotal: 100 kB\nMemAvailable: 50 kB\n").unwrap();
        assert_eq!(meminfo(&no_shmem), Some((50, 100, 0)));
        assert_eq!(meminfo(Path::new("/nonexistent")), None);
        assert_eq!(total_mib(&path), Some(64248));

        // A size question is answered from `MemTotal` alone. A kernel that reports no
        // `MemAvailable` still has a size, and a caller asking only for it gets an answer.
        std::fs::write(&path, "MemTotal:       65790616 kB\nMemFree:  123 kB\n").unwrap();
        assert_eq!(total_mib(&path), Some(64248));
        assert_eq!(meminfo(&path), None);
        assert_eq!(total_mib(Path::new("/nonexistent")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
