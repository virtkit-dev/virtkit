//! How long a Windows image built from evaluation media keeps working, as Windows reports it.
//!
//! Microsoft's evaluation terms: a Windows Server evaluation must be activated online within 10
//! days and then runs 180 days from activation; Windows 11 Enterprise's evaluation runs 90 days.
//! A generalized (sysprep) image restarts the 10-day activation grace at every machine's first
//! boot, so it carries no clock. A non-generalized one does: its machines inherit whatever its
//! build left, activation (and the 180 days counted from it) included. `vk build` records that
//! in the bundle, and runs of the bundle warn as its end nears. Only Windows on an evaluation
//! (`TIMEBASED_EVAL`) channel ends once activated; retail, volume and KMS activations do not.

use std::io::Write;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::qga::Client;

const DAY: u64 = 24 * 60 * 60;

/// How long before an evaluation ends a run starts warning.
const EVAL_WARN_BEFORE: u64 = 30 * DAY;

/// How long before an unactivated image's grace period ends a run starts warning.
const ACTIVATE_WARN_BEFORE: u64 = 3 * DAY;

/// Windows' licensing state, the minutes left of its grace or evaluation period and its
/// channel (`Description`, e.g. `Windows(R) Operating System, TIMEBASED_EVAL channel`), from
/// the Windows product (its application ID) that has a key. Without progress records:
/// powershell.exe writes them to stderr as CLIXML, after the answer.
const QUERY_PS1: &str = r#"$ProgressPreference = 'SilentlyContinue'; Get-CimInstance SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" | % { "$($_.LicenseStatus) $($_.GracePeriodRemaining) $($_.Description)" }"#;

/// How long [`query`] waits for Windows' answer.
const QUERY_TIMEOUT: Duration = Duration::from_secs(3 * 60);

/// `SoftwareLicensingProduct.LicenseStatus` of an activated Windows.
const LICENSED: u32 = 1;

/// Tell that Windows could not be asked, and why.
pub(crate) fn warn_unread(e: &anyhow::Error) {
    eprintln!(
        "virtkit: warning: could not read Windows' licensing ({e:#}); \
         the bundle records no evaluation end"
    );
}

/// When an image's Windows stops working unless something is done, in seconds since the epoch;
/// recorded in a bundle's layer record. Empty for a generalized image, one activated for good
/// (retail, volume, KMS), or when Windows could not be asked.
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Evaluation {
    /// An activated evaluation: when it ends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eval_expires: Option<u64>,
    /// Not activated: when its activation grace period ends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activate_by: Option<u64>,
}

impl Evaluation {
    /// What a licensing `status` with `grace_minutes` left at `now` comes to, on a `timebased`
    /// (evaluation) channel or another.
    fn of(status: u32, grace_minutes: u64, timebased: bool, now: u64) -> Evaluation {
        let end = Some(now.saturating_add(grace_minutes.saturating_mul(60)));
        match status {
            LICENSED if timebased && grace_minutes > 0 => Evaluation {
                eval_expires: end,
                activate_by: None,
            },
            // Activated for good.
            LICENSED => Evaluation::default(),
            _ => Evaluation {
                eval_expires: None,
                activate_by: end,
            },
        }
    }

    /// The warning a run of the image gives at `now`, if any.
    pub(crate) fn warning(&self, now: u64) -> Option<String> {
        if let Some(end) = self.eval_expires
            && end < now.saturating_add(EVAL_WARN_BEFORE)
        {
            let expires = if end <= now { "expired" } else { "expires" };
            return Some(format!(
                "this image's evaluation {expires} on {}; rebuild it from the ISO \
                 (`vk build --reinstall`)",
                date(end)
            ));
        }
        let end = self
            .activate_by
            .filter(|end| *end < now.saturating_add(ACTIVATE_WARN_BEFORE))?;
        let ends = if end <= now { "ended" } else { "ends" };
        Some(format!(
            "this image was never activated and its activation grace period {ends} on {}; \
             activate it (`slmgr /ato`, with a network) or rebuild it from the ISO \
             (`vk build --reinstall`)",
            date(end)
        ))
    }
}

/// The UTC day of `secs` since the epoch, `YYYY-MM-DD` (the format atop names its archive
/// directories in).
fn date(secs: u64) -> String {
    vk_core::atop::date_dir(i64::try_from(secs).unwrap_or(i64::MAX))
}

/// Ask Windows behind `ga` how long it keeps working, within [`QUERY_TIMEOUT`]. On failure,
/// warn and return None: the image records nothing.
pub(crate) fn query(ga: &mut Client) -> Option<Evaluation> {
    match ask(ga) {
        Ok(evaluation) => Some(evaluation),
        Err(e) => {
            warn_unread(&e);
            None
        }
    }
}

/// [`query`], failing when Windows does not tell.
fn ask(ga: &mut Client) -> Result<Evaluation> {
    let mut out = Bounded {
        out: Vec::new(),
        deadline: Instant::now() + QUERY_TIMEOUT,
    };
    let code = crate::winexec::powershell_output(ga, QUERY_PS1, &mut out)?;
    let out = String::from_utf8_lossy(&out.out);
    if code != 0 {
        bail!("exit {code}: {out}");
    }
    let (status, grace_minutes, timebased) =
        parse(&out).with_context(|| format!("unexpected answer {out:?}"))?;
    Ok(Evaluation::of(
        status,
        grace_minutes,
        timebased,
        crate::vms::unix_now(),
    ))
}

/// [`QUERY_PS1`]'s output, refused once `deadline` has passed: the command's output is flushed
/// at each poll of it, so a query that hangs fails there.
struct Bounded {
    out: Vec<u8>,
    deadline: Instant,
}

impl Bounded {
    fn check(&self) -> std::io::Result<()> {
        if Instant::now() < self.deadline {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("no answer within {}s", QUERY_TIMEOUT.as_secs()),
            ))
        }
    }
}

impl Write for Bounded {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.check()?;
        self.out.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.check()
    }
}

/// [`QUERY_PS1`]'s answer, `<LicenseStatus> <GracePeriodRemaining> <Description>`, from its
/// last line that is one (stderr, CLIXML included, is merged in): the status, the minutes, and
/// whether the channel is an evaluation's.
fn parse(out: &str) -> Option<(u32, u64, bool)> {
    out.lines().rev().find_map(|line| {
        let mut words = line.trim().splitn(3, ' ');
        let status = words.next()?.parse().ok()?;
        let grace_minutes = words.next()?.parse().ok()?;
        let timebased = words.next().is_some_and(|d| d.contains("TIMEBASED_EVAL"));
        Some((status, grace_minutes, timebased))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVAL: &str = "Windows(R) Operating System, TIMEBASED_EVAL channel";

    #[test]
    fn the_answer_is_status_minutes_and_channel_on_the_last_line_that_is_one() {
        assert_eq!(
            parse(&format!("1 259200 {EVAL}\r\n")),
            Some((1, 259200, true))
        );
        assert_eq!(
            parse(
                "a warning\r\n2 14400 Windows(R) Operating System, VOLUME_KMSCLIENT channel\r\n\r\n"
            ),
            Some((2, 14400, false))
        );
        assert_eq!(parse("1 0\r\n"), Some((1, 0, false)));
        // powershell.exe's progress records, on stderr after the answer.
        assert_eq!(
            parse(&format!(
                "#< CLIXML\r\n1 259174 {EVAL}\r\n<Objs Version=\"1.1.0.1\" \
                 xmlns=\"http://schemas.microsoft.com/powershell/2004/04\"><Obj S=\"progress\">\
                 </Obj></Objs>"
            )),
            Some((1, 259174, true))
        );
        assert_eq!(parse(""), None);
        assert_eq!(parse("1\r\n"), None);
        assert_eq!(parse("1 -5\r\n"), None);
    }

    #[test]
    fn only_activated_evaluations_expire_and_unactivated_windows_must_activate() {
        let now = 1_000_000_000;
        // Windows Server evaluation after `slmgr /ato`: 180 days from now.
        assert_eq!(
            Evaluation::of(1, 259200, true, now),
            Evaluation {
                eval_expires: Some(now + 180 * DAY),
                activate_by: None,
            }
        );
        // Not activated: its 10-day grace, whatever the channel.
        let unactivated = Evaluation {
            eval_expires: None,
            activate_by: Some(now + 10 * DAY),
        };
        assert_eq!(Evaluation::of(2, 14400, true, now), unactivated);
        assert_eq!(Evaluation::of(2, 14400, false, now), unactivated);
        // Activated for good: an evaluation with no time left reported, or a KMS, volume or
        // retail activation, whatever grace it reports.
        assert_eq!(Evaluation::of(1, 0, true, now), Evaluation::default());
        assert_eq!(Evaluation::of(1, 259200, false, now), Evaluation::default());
    }

    #[test]
    fn a_run_warns_near_and_past_the_end_only() {
        let end = 1_000_000_000;
        let expiring = Evaluation {
            eval_expires: Some(end),
            activate_by: None,
        };
        assert_eq!(expiring.warning(end - 31 * DAY), None);
        let near = expiring.warning(end - 29 * DAY).unwrap();
        assert!(near.contains("evaluation expires on 2001-09-09"), "{near}");
        let past = expiring.warning(end + DAY).unwrap();
        assert!(past.contains("evaluation expired on 2001-09-09"), "{past}");

        let unactivated = Evaluation {
            eval_expires: None,
            activate_by: Some(end),
        };
        assert_eq!(unactivated.warning(end - 4 * DAY), None);
        let near = unactivated.warning(end - 2 * DAY).unwrap();
        assert!(near.contains("grace period ends on 2001-09-09"), "{near}");
        let past = unactivated.warning(end + DAY).unwrap();
        assert!(past.contains("grace period ended on 2001-09-09"), "{past}");

        // Nothing recorded: nothing to tell.
        assert_eq!(Evaluation::default().warning(end), None);
    }

    #[test]
    fn the_query_output_refuses_writes_after_its_deadline() {
        let mut out = Bounded {
            out: Vec::new(),
            deadline: Instant::now() + Duration::from_secs(60),
        };
        out.write_all(b"1 0").unwrap();
        out.flush().unwrap();
        out.deadline = Instant::now();
        let e = out.flush().unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::TimedOut);
        assert!(out.write_all(b"x").is_err());
        assert_eq!(out.out, b"1 0");
    }
}
