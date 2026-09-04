//! Fetches and summarizes guest kernel OOM kills.
//!
//! [`fetch`] reads the agent's records over the exec channel. [`summary`] formats them for
//! build-stage output, CI traces, `vk run`, and `vk status`, including the setting that raises
//! the memory limit.

use std::time::Duration;

use tokio_util::sync::CancellationToken;
use vk_core::addr::SocketAddr;

pub(crate) use vk_core::oomkills::Kill;

/// Maximum time to wait for a guest that may be unresponsive under memory pressure.
const BUDGET: Duration = Duration::from_secs(5);

/// Maximum kills parsed from untrusted guest output; the agent applies the same limit.
const MAX: usize = 64;

/// Fetch recorded OOM kills from the live guest at `addr`, stopping at [`BUDGET`] or when
/// `cancel` fires. Return `None` when no reliable answer is available, allowing callers to
/// distinguish that case from a watched guest with no kills.
pub(crate) async fn fetch(
    addr: &SocketAddr,
    cancel: Option<&CancellationToken>,
) -> Option<Vec<Kill>> {
    let (out, sink) = crate::executor::stdout_capture();
    let argv = [crate::run::GUEST_AGENT.to_string(), "oomkills".to_string()];
    let asked = tokio::time::timeout(
        BUDGET,
        crate::executor::exec_script(addr, &argv, Vec::new(), None, &sink, cancel),
    )
    .await;
    if !matches!(asked, Ok(Ok(r)) if r.code == Some(0)) {
        return None;
    }
    let buf = out.lock().ok()?;
    Some(Kill::parse_all(std::str::from_utf8(&buf).ok()?, MAX))
}

/// Format fetched kills, or return `None` when no report is available.
pub(crate) fn line(kills: Option<&[Kill]>, hint: &str) -> Option<String> {
    summary(kills?, hint)
}

/// Summarize `kills` on one line, or return `None` when empty. Sizes are anonymous RSS,
/// times are guest uptime, and `hint` is appended as parenthesized advice such as
/// `raise --mem`.
pub(crate) fn summary(kills: &[Kill], hint: &str) -> Option<String> {
    if kills.is_empty() {
        return None;
    }
    // Name the first few victims, then summarize the remainder as a count.
    const LISTED: usize = 4;
    let mut who: Vec<String> = kills
        .iter()
        .take(LISTED)
        .map(|k| {
            format!(
                "{} (pid {}, {} RSS) at +{}s{}",
                k.comm,
                k.pid,
                crate::usage::fmt_bytes(k.anon_rss),
                k.uptime_us / 1_000_000,
                if k.cgroup { " [cgroup limit]" } else { "" }
            )
        })
        .collect();
    if kills.len() > LISTED {
        who.push(format!("and {} more", kills.len() - LISTED));
    }
    Some(format!(
        "guest OOM: the kernel killed {} ({hint})",
        who.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kill(comm: &str, mib: u64, secs: u64, cgroup: bool) -> Kill {
        Kill {
            uptime_us: secs * 1_000_000,
            pid: 7,
            comm: comm.into(),
            anon_rss: mib * 1024 * 1024,
            cgroup,
        }
    }

    #[test]
    fn summary_names_the_victims_and_the_knob() {
        assert_eq!(
            summary(
                &[kill("cc1plus", 1946, 48, false), kill("ld", 700, 52, true)],
                "raise --mem"
            )
            .as_deref(),
            Some(
                "guest OOM: the kernel killed cc1plus (pid 7, 1.9 GiB RSS) at +48s, \
                 ld (pid 7, 700 MiB RSS) at +52s [cgroup limit] (raise --mem)"
            )
        );
    }

    #[test]
    fn summary_counts_the_victims_it_does_not_list() {
        let many: Vec<Kill> = (0..6).map(|i| kill("w", 10, i, false)).collect();
        let s = summary(&many, "x").unwrap();
        assert!(s.ends_with("and 2 more (x)"), "{s}");
        assert_eq!(s.matches("w (pid 7, 10 MiB RSS)").count(), 4);
    }

    #[test]
    fn a_guest_with_nothing_to_report_produces_no_line() {
        // No kills and "the guest could not say" both print nothing, so neither can be
        // mistaken for the other by a reader of the output.
        assert_eq!(summary(&[], "raise --mem"), None);
        assert_eq!(line(None, "raise --mem"), None);
        assert_eq!(line(Some(&[]), "raise --mem"), None);
    }
}
