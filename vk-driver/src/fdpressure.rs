//! Trims guest caches under virtio-fs descriptor pressure.
//!
//! The VMM holds a descriptor for each shared inode until the guest forgets it. Without
//! memory pressure, cached inodes can accumulate until the VMM reaches `RLIMIT_NOFILE`
//! and further opens fail with "Too many open files".
//!
//! [`watch`] polls the held-inode count. At half the limit, it asks the guest agent to drop
//! unused dentries and inodes (`vk-agent drop-caches`), which later lookups must rebuild.
//! Cached pages can keep inodes resident, so a trim that leaves the count high is followed
//! by one that drops the page cache too.
//!
//! Trimming is not a ceiling: open files stay held, lookups can outpace reclamation, and
//! guests without a reachable agent cannot be trimmed.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use vk_core::addr::SocketAddr;
use vk_core::messages::Fd;

use crate::executor::{GUEST_ROOT, OutputSink, exec_script};
use crate::run::GUEST_AGENT;

const POLL: Duration = Duration::from_secs(1);

/// Wait for a trim to affect the count before paying for another.
const COOLDOWN: Duration = Duration::from_secs(30);

/// At [`Limits::urgent`], allow time for forgets before trimming again.
/// Retry and backoff delays take precedence.
const SETTLE: Duration = Duration::from_secs(5);

/// Delay after a full trim leaves the count high, or retries keep failing.
const BACKOFF: Duration = Duration::from_secs(300);

/// Retry delay for a failed trim: the guest may be paused or its agent not ready.
const RETRY: Duration = Duration::from_secs(10);

/// Retries before [`BACKOFF`] limits repeated requests and failure logs.
const RETRIES: u32 = 3;

/// How long the guest gets to drop its caches; a paused or wedged guest must not hold the
/// watcher.
const TRIM_TIMEOUT: Duration = Duration::from_secs(120);

/// The first bytes of the agent's stderr, which an error quotes from.
const MAX_STDERR: usize = 4096;

/// What the guest is asked to drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Trim {
    /// Unused dentries and inodes.
    Dentries,
    /// Those and the page cache, which pins the inodes it belongs to.
    All,
}

impl Trim {
    fn arg(self) -> &'static str {
        match self {
            Trim::Dentries => "dentries",
            Trim::All => "all",
        }
    }
}

/// Held-inode thresholds derived from the process's descriptor limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Limits {
    /// Below this count, the next trim drops only dentries and inodes.
    low: u64,
    /// Start trimming here, reserving half the limit for uncounted descriptors:
    /// open file and directory handles, and the VMM's own descriptors.
    high: u64,
    /// Use [`SETTLE`] instead of [`COOLDOWN`], unless retrying or backing off.
    urgent: u64,
}

impl Limits {
    fn of(nofile: u64) -> Self {
        Limits {
            low: nofile / 20 * 7,
            high: nofile / 2,
            urgent: nofile / 4 * 3,
        }
    }
}

/// When to trim, and how hard.
#[derive(Debug, Default)]
struct Policy {
    /// When the last trim ended.
    last: Option<Instant>,
    /// Consecutive failed trims.
    failed: u32,
    /// Trims the guest carried out since the count was last under [`Limits::low`].
    tried: u32,
}

impl Policy {
    /// The trim to ask for now, if any. The caller reports how it went with [`Policy::done`].
    fn next(&mut self, held: u64, limits: Limits, now: Instant) -> Option<Trim> {
        if held < limits.low {
            self.tried = 0;
        }
        if held < limits.high {
            return None;
        }
        let wait = if self.failed > RETRIES {
            BACKOFF
        } else if self.failed > 0 {
            RETRY
        } else if self.tried >= 2 {
            BACKOFF
        } else if held >= limits.urgent {
            SETTLE
        } else {
            COOLDOWN
        };
        if self
            .last
            .is_some_and(|last| now.duration_since(last) < wait)
        {
            return None;
        }
        Some(if self.tried == 0 {
            Trim::Dentries
        } else {
            Trim::All
        })
    }

    /// Record completion at `now`. Failed trims are retried without escalation.
    fn done(&mut self, ok: bool, now: Instant) {
        self.last = Some(now);
        if ok {
            self.failed = 0;
            self.tried = self.tried.saturating_add(1);
        } else {
            self.failed = self.failed.saturating_add(1);
        }
    }
}

/// The process's soft `RLIMIT_NOFILE`, or `None` if unlimited or unreadable.
fn nofile() -> Option<u64> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes only the `rlimit` passed to it.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return None;
    }
    (lim.rlim_cur != libc::RLIM_INFINITY).then_some(lim.rlim_cur)
}

/// The last nonblank stderr line, escaped for logging because the guest controls its bytes.
/// Agent errors already identify their source.
fn last_line(complaints: &str) -> Option<String> {
    let line = complaints.lines().rev().find(|l| !l.trim().is_empty())?;
    Some(line.trim().escape_debug().to_string())
}

async fn trim(agent: &SocketAddr, trim: Trim) -> Result<()> {
    let cmd = [GUEST_AGENT, "drop-caches", trim.arg()].map(String::from);
    // Its stdout is dropped; its stderr, bounded, becomes the error below.
    let complaints = Arc::new(Mutex::new(Vec::new()));
    let sink = {
        let complaints = Arc::clone(&complaints);
        OutputSink::Routed(Arc::new(move |fd, bytes: &[u8]| {
            if matches!(fd, Fd::Stderr)
                && let Ok(mut buf) = complaints.lock()
            {
                let room = MAX_STDERR.saturating_sub(buf.len());
                buf.extend_from_slice(&bytes[..bytes.len().min(room)]);
            }
        }))
    };
    let run = exec_script(
        agent,
        &cmd,
        Vec::new(),
        Some(GUEST_ROOT.into()),
        &sink,
        None,
    );
    let result = tokio::time::timeout(TRIM_TIMEOUT, run)
        .await
        .context("the guest did not answer")??;
    let ended = match (result.code, result.signal) {
        (Some(0), _) => return Ok(()),
        (Some(code), _) => format!("exit code {code}"),
        (None, Some(signal)) => format!("killed by signal {signal}"),
        (None, None) => "ended without a status".to_owned(),
    };
    // A poisoned buffer only loses the quote.
    let complaints = complaints.lock().map(|buf| buf.clone()).unwrap_or_default();
    match last_line(&String::from_utf8_lossy(&complaints)) {
        Some(said) => bail!("{ended}: {said}"),
        None => bail!("vk-agent drop-caches: {ended}"),
    }
}

/// Watch held inodes on a dedicated thread for the process's lifetime.
/// `agent` is the host socket of the guest's exec channel.
pub(crate) fn watch(agent: &Path) -> Result<()> {
    let Some(limits) = nofile().map(Limits::of) else {
        return Ok(());
    };
    let agent = SocketAddr::Unix(PathBuf::from(agent));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building the share watcher's runtime")?;
    std::thread::Builder::new()
        .name("vk-fd-pressure".into())
        .spawn(move || {
            let mut policy = Policy::default();
            loop {
                std::thread::sleep(POLL);
                let held = krun::fs_held_inodes();
                let Some(what) = policy.next(held, limits, Instant::now()) else {
                    continue;
                };
                let outcome = rt.block_on(trim(&agent, what));
                policy.done(outcome.is_ok(), Instant::now());
                match outcome {
                    Ok(()) => eprintln!(
                        "virtkit: the guest's shares held {held} files open on the host: \
                         had it drop its {}",
                        match what {
                            Trim::Dentries => "cached directory entries",
                            Trim::All => "page cache",
                        }
                    ),
                    Err(e) => eprintln!(
                        "virtkit: the guest's shares hold {held} files open on the host, and \
                         it could not be made to drop its caches: {e:#}"
                    ),
                }
            }
        })
        .context("spawning the share watcher")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: Limits = Limits {
        low: 350,
        high: 500,
        urgent: 750,
    };

    /// Simulate successful or failed trims with zero elapsed time.
    struct Guest {
        policy: Policy,
        ok: bool,
    }

    impl Guest {
        fn new(ok: bool) -> Self {
            Guest {
                policy: Policy::default(),
                ok,
            }
        }

        fn next(&mut self, held: u64, now: Instant) -> Option<Trim> {
            let trim = self.policy.next(held, LIMITS, now);
            if trim.is_some() {
                self.policy.done(self.ok, now);
            }
            trim
        }
    }

    #[test]
    fn limits_are_shares_of_the_descriptor_limit() {
        assert_eq!(Limits::of(1000), LIMITS);
        let big = Limits::of(524_288);
        assert!(big.low < big.high && big.high < big.urgent && big.urgent < 524_288);
        // Neither end of the range overflows or inverts the order.
        for nofile in [0, 1, 19, u64::MAX] {
            let l = Limits::of(nofile);
            assert!(
                l.low <= l.high && l.high <= l.urgent && l.urgent <= nofile,
                "{l:?}"
            );
        }
    }

    #[test]
    fn a_guest_under_the_threshold_is_left_alone() {
        let mut guest = Guest::new(true);
        let t0 = Instant::now();
        for (i, held) in [0, 349, 350, 499].into_iter().enumerate() {
            let now = t0 + POLL * i as u32;
            assert_eq!(guest.next(held, now), None, "{held}");
        }
    }

    #[test]
    fn a_trim_that_worked_is_gentle_again_next_time() {
        let mut guest = Guest::new(true);
        let t0 = Instant::now();
        assert_eq!(guest.next(500, t0), Some(Trim::Dentries));
        assert_eq!(guest.next(100, t0 + POLL), None);
        // The count having been low in between does not shorten the cooldown.
        assert_eq!(guest.next(500, t0 + POLL * 2), None);
        assert_eq!(guest.next(500, t0 + COOLDOWN), Some(Trim::Dentries));
    }

    #[test]
    fn a_trim_that_did_not_help_escalates_then_backs_off() {
        let mut guest = Guest::new(true);
        let t0 = Instant::now();
        assert_eq!(guest.next(600, t0), Some(Trim::Dentries));
        // Not under `low`, so the next one drops everything, after the cooldown.
        assert_eq!(guest.next(400, t0 + POLL), None);
        assert_eq!(guest.next(600, t0 + COOLDOWN - POLL), None);
        let t1 = t0 + COOLDOWN;
        assert_eq!(guest.next(600, t1), Some(Trim::All));
        // Back off when the count stays high, even above the urgent threshold.
        assert_eq!(guest.next(600, t1 + COOLDOWN), None);
        assert_eq!(guest.next(900, t1 + COOLDOWN), None);
        assert_eq!(guest.next(600, t1 + BACKOFF), Some(Trim::All));
    }

    #[test]
    fn a_count_left_between_the_thresholds_keeps_the_next_trim_hard() {
        let mut guest = Guest::new(true);
        let t0 = Instant::now();
        assert_eq!(guest.next(600, t0), Some(Trim::Dentries));
        assert_eq!(guest.next(400, t0 + COOLDOWN), None);
        assert_eq!(guest.next(500, t0 + COOLDOWN * 2), Some(Trim::All));
    }

    #[test]
    fn an_urgent_count_does_not_wait_for_the_cooldown() {
        let mut guest = Guest::new(true);
        let t0 = Instant::now();
        assert_eq!(guest.next(800, t0), Some(Trim::Dentries));
        assert_eq!(guest.next(800, t0 + POLL), None);
        assert_eq!(guest.next(800, t0 + SETTLE), Some(Trim::All));
    }

    #[test]
    fn a_failed_trim_is_retried_without_escalating() {
        let mut guest = Guest::new(false);
        let t0 = Instant::now();
        assert_eq!(guest.next(600, t0), Some(Trim::Dentries));
        assert_eq!(guest.next(600, t0 + RETRY - POLL), None);
        assert_eq!(guest.next(600, t0 + RETRY), Some(Trim::Dentries));
        assert_eq!(guest.next(900, t0 + RETRY * 2), Some(Trim::Dentries));
        guest.ok = true;
        assert_eq!(guest.next(600, t0 + RETRY * 3), Some(Trim::Dentries));
        assert_eq!(guest.next(600, t0 + RETRY * 4), None);
        assert_eq!(guest.next(600, t0 + RETRY * 3 + COOLDOWN), Some(Trim::All));
    }

    #[test]
    fn a_trim_that_keeps_failing_backs_off_without_escalating() {
        let mut guest = Guest::new(false);
        let t0 = Instant::now();
        for i in 0..=RETRIES {
            assert_eq!(guest.next(600, t0 + RETRY * i), Some(Trim::Dentries));
        }
        let t1 = t0 + RETRY * RETRIES;
        assert_eq!(guest.next(900, t1 + RETRY), None);
        assert_eq!(guest.next(600, t1 + BACKOFF - POLL), None);
        assert_eq!(guest.next(600, t1 + BACKOFF), Some(Trim::Dentries));
        // One that works ends the streak.
        guest.ok = true;
        let t2 = t1 + BACKOFF * 2;
        assert_eq!(guest.next(600, t2), Some(Trim::Dentries));
        assert_eq!(guest.next(600, t2 + COOLDOWN), Some(Trim::All));
    }

    #[test]
    fn the_agents_last_complaint_fits_one_line() {
        assert_eq!(last_line(""), None);
        assert_eq!(last_line(" \n\n"), None);
        assert_eq!(
            last_line("warning\ndrop-caches: writing x: denied\n\n").as_deref(),
            Some("drop-caches: writing x: denied")
        );
        assert_eq!(last_line("a\x1b[0mb").as_deref(), Some("a\\u{1b}[0mb"));
    }

    #[test]
    fn the_cooldown_counts_from_the_trims_end() {
        let mut policy = Policy::default();
        let t0 = Instant::now();
        assert_eq!(policy.next(600, LIMITS, t0), Some(Trim::Dentries));
        let ended = t0 + COOLDOWN * 2;
        policy.done(true, ended);
        assert_eq!(policy.next(600, LIMITS, ended + POLL), None);
        assert_eq!(policy.next(600, LIMITS, ended + COOLDOWN), Some(Trim::All));
    }
}
